//! Terminal-based interactive approval backend for supervisor IPC
//!
//! Prompts the user at the terminal when the sandboxed child requests
//! additional filesystem access. This is the default approval backend
//! for `nono run --supervised`.

use nono::{AccessMode, ApprovalBackend, ApprovalDecision, CapabilityRequest, NonoError, Result};
use std::io::{BufRead, IsTerminal, Write};

/// Interactive terminal approval backend.
///
/// Prints capability expansion requests to stderr and reads the user's
/// response from `/dev/tty` (not stdin, which belongs to the sandboxed child).
///
/// Returns `Denied` automatically if no terminal is available.
pub struct TerminalApproval;

impl ApprovalBackend for TerminalApproval {
    fn request_capability(&self, request: &CapabilityRequest) -> Result<ApprovalDecision> {
        let stderr = std::io::stderr();
        if !stderr.is_terminal() {
            return Ok(ApprovalDecision::Denied {
                reason: "No terminal available for interactive approval".to_string(),
            });
        }

        // Display the request (sanitize untrusted fields from the sandboxed child)
        eprintln!();
        eprintln!("[nono] The sandboxed process is requesting additional access:");
        eprintln!(
            "[nono]   Path:   {}",
            sanitize_for_terminal(&request.path.display().to_string())
        );
        eprintln!("[nono]   Access: {}", format_access_mode(&request.access));
        if let Some(ref reason) = request.reason {
            eprintln!("[nono]   Reason: {}", sanitize_for_terminal(reason));
        }
        eprintln!("[nono]");
        eprint!("[nono] Grant access? [y/N] ");
        let _ = std::io::stderr().flush();

        // Read from /dev/tty, not stdin (which belongs to the sandboxed child)
        let tty = std::fs::File::open("/dev/tty").map_err(|e| {
            NonoError::SandboxInit(format!("Failed to open /dev/tty for approval prompt: {e}"))
        })?;
        let mut reader = std::io::BufReader::new(tty);
        let mut input = String::new();
        reader.read_line(&mut input).map_err(|e| {
            NonoError::SandboxInit(format!("Failed to read approval response: {e}"))
        })?;

        let input = input.trim().to_lowercase();
        if input == "y" || input == "yes" {
            eprintln!("[nono] Access granted.");
            Ok(ApprovalDecision::Granted)
        } else {
            eprintln!("[nono] Access denied.");
            Ok(ApprovalDecision::Denied {
                reason: "User denied the request".to_string(),
            })
        }
    }

    fn backend_name(&self) -> &str {
        "terminal"
    }
}

/// Strip control characters and ANSI escape sequences from untrusted input
/// before displaying on the terminal.
///
/// Replaces bytes 0x00-0x1F (except tab/newline, replaced with space), 0x7F,
/// and ANSI CSI/OSC escape sequences with a replacement character.
fn sanitize_for_terminal(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip ANSI escape sequence: ESC [ ... final_byte  or  ESC ] ... ST
            if let Some(&next) = chars.peek() {
                if next == '[' {
                    // CSI sequence: consume until 0x40-0x7E
                    chars.next();
                    for seq_c in chars.by_ref() {
                        if ('\x40'..='\x7e').contains(&seq_c) {
                            break;
                        }
                    }
                } else if next == ']' {
                    // OSC sequence: consume until ST (ESC \) or BEL
                    chars.next();
                    let mut prev = '\0';
                    for seq_c in chars.by_ref() {
                        if seq_c == '\x07' || (prev == '\x1b' && seq_c == '\\') {
                            break;
                        }
                        prev = seq_c;
                    }
                }
                // Other ESC sequences: just drop the ESC
            }
            continue;
        }

        if c.is_control() {
            // Replace all control chars (CR, LF, tab, null, etc.) with space
            result.push(' ');
        } else {
            result.push(c);
        }
    }

    result
}

/// Format an access mode for human-readable display.
fn format_access_mode(access: &AccessMode) -> &'static str {
    match access {
        AccessMode::Read => "read-only",
        AccessMode::Write => "write-only",
        AccessMode::ReadWrite => "read+write",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terminal_approval_backend_name() {
        let backend = TerminalApproval;
        assert_eq!(backend.backend_name(), "terminal");
    }

    #[test]
    fn test_format_access_mode() {
        assert_eq!(format_access_mode(&AccessMode::Read), "read-only");
        assert_eq!(format_access_mode(&AccessMode::Write), "write-only");
        assert_eq!(format_access_mode(&AccessMode::ReadWrite), "read+write");
    }

    #[test]
    fn test_sanitize_clean_input() {
        assert_eq!(sanitize_for_terminal("/tmp/harmless"), "/tmp/harmless");
    }

    #[test]
    fn test_sanitize_carriage_return_overwrite() {
        // An attacker could use \r to overwrite the displayed path
        let malicious = "/etc/shadow\r/tmp/harmless";
        let sanitized = sanitize_for_terminal(malicious);
        assert!(!sanitized.contains('\r'));
        assert!(sanitized.contains("/etc/shadow"));
        assert!(sanitized.contains("/tmp/harmless"));
    }

    #[test]
    fn test_sanitize_ansi_escape_csi() {
        // ANSI CSI sequence to change colors / move cursor
        let malicious = "/tmp/\x1b[2K\x1b[1A/etc/shadow";
        let sanitized = sanitize_for_terminal(malicious);
        assert!(!sanitized.contains('\x1b'));
        assert!(sanitized.contains("/tmp/"));
    }

    #[test]
    fn test_sanitize_ansi_escape_osc() {
        // OSC sequence (e.g., change terminal title)
        let malicious = "/tmp/\x1b]0;evil\x07path";
        let sanitized = sanitize_for_terminal(malicious);
        assert!(!sanitized.contains('\x1b'));
        assert!(!sanitized.contains('\x07'));
    }

    #[test]
    fn test_sanitize_null_bytes() {
        let malicious = "/tmp/\0evil";
        let sanitized = sanitize_for_terminal(malicious);
        assert!(!sanitized.contains('\0'));
    }

    #[test]
    fn test_sanitize_all_control_chars_replaced() {
        for byte in 0x00u8..=0x1f {
            let input = format!("/tmp/{}evil", byte as char);
            let sanitized = sanitize_for_terminal(&input);
            assert!(
                !sanitized.chars().any(|c| c == byte as char),
                "Control byte 0x{:02x} should be stripped",
                byte
            );
        }
        // DEL (0x7F) is handled as control too
        let del_input = "/tmp/\x7Fevil";
        let sanitized = sanitize_for_terminal(del_input);
        assert!(!sanitized.contains('\x7F'));
    }
}
