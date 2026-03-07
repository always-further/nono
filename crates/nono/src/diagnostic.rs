//! Diagnostic output formatter for sandbox policy.
//!
//! This module provides human and agent-readable diagnostic output
//! when sandboxed commands fail. The output helps identify whether
//! the failure was due to sandbox restrictions.
//!
//! # Design Principles
//!
//! - **Unmistakable prefix**: All lines start with `[nono]` so agents
//!   immediately recognize the source
//! - **May vs was**: Phrased as "may be due to" not "was caused by"
//!   because the non-zero exit could be unrelated to the sandbox
//! - **Actionable**: Provides specific flags to grant additional access
//! - **Mode-aware**: Different guidance for supervised vs standard mode
//! - **Library code**: No process management, no CLI assumptions

use crate::capability::{AccessMode, CapabilitySet, CapabilitySource};
use std::path::PathBuf;

/// Why a path access was denied during a supervised session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenialReason {
    /// Path is permanently blocked by security policy (never_grant)
    PolicyBlocked,
    /// User declined the interactive approval prompt
    UserDenied,
    /// Request was rate limited (too many requests)
    RateLimited,
    /// Approval backend returned an error
    BackendError,
}

/// Record of a denied access attempt during a supervised session.
#[derive(Debug, Clone)]
pub struct DenialRecord {
    /// The path that was denied
    pub path: PathBuf,
    /// Access mode requested
    pub access: AccessMode,
    /// Why it was denied
    pub reason: DenialReason,
}

/// Execution mode for diagnostic context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticMode {
    /// Standard mode: suggest --allow flags for re-run
    Standard,
    /// Supervised mode: interactive expansion available, show denials
    Supervised,
}

/// Context about the command that was executed.
///
/// Used to generate more specific diagnostic messages when a
/// sandboxed command fails.
#[derive(Debug, Clone)]
pub struct CommandContext {
    /// The program name as the user typed it (e.g. "ps", "./script.sh")
    pub program: String,
    /// The resolved absolute path to the binary
    pub resolved_path: PathBuf,
}

/// Formats diagnostic information about sandbox policy.
///
/// This is library code that can be used by any parent process
/// that wants to explain sandbox denials to users or AI agents.
pub struct DiagnosticFormatter<'a> {
    caps: &'a CapabilitySet,
    mode: DiagnosticMode,
    denials: &'a [DenialRecord],
    /// Paths that are write-protected due to trust verification
    protected_paths: &'a [PathBuf],
    /// Name of a protected file that was detected in the error output
    blocked_protected_file: Option<String>,
    /// Command that was executed (for context-aware diagnostics)
    command: Option<CommandContext>,
}

impl<'a> DiagnosticFormatter<'a> {
    /// Create a new formatter for the given capability set.
    #[must_use]
    pub fn new(caps: &'a CapabilitySet) -> Self {
        Self {
            caps,
            mode: DiagnosticMode::Standard,
            denials: &[],
            protected_paths: &[],
            blocked_protected_file: None,
            command: None,
        }
    }

    /// Set the diagnostic mode (standard or supervised).
    #[must_use]
    pub fn with_mode(mut self, mode: DiagnosticMode) -> Self {
        self.mode = mode;
        self
    }

    /// Add denial records from a supervised session.
    #[must_use]
    pub fn with_denials(mut self, denials: &'a [DenialRecord]) -> Self {
        self.denials = denials;
        self
    }

    /// Add paths that are write-protected due to trust verification.
    ///
    /// These are signed instruction files that the sandbox protects from
    /// modification even when the parent directory has write access.
    #[must_use]
    pub fn with_protected_paths(mut self, paths: &'a [PathBuf]) -> Self {
        self.protected_paths = paths;
        self
    }

    /// Set the name of a protected file that was detected in the error output.
    ///
    /// When set, the diagnostic will highlight that a write to a signed
    /// instruction file was blocked.
    #[must_use]
    pub fn with_blocked_protected_file(mut self, name: Option<String>) -> Self {
        self.blocked_protected_file = name;
        self
    }

    /// Set command context for more specific diagnostics.
    #[must_use]
    pub fn with_command(mut self, command: CommandContext) -> Self {
        self.command = Some(command);
        self
    }

    /// Check if an error line mentions any protected file and return the filename.
    ///
    /// This is used by the output processor to detect when a permission error
    /// is specifically due to a signed instruction file being write-protected.
    #[must_use]
    pub fn detect_protected_file_in_error(&self, error_line: &str) -> Option<String> {
        for path in self.protected_paths {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if error_line.contains(name) {
                    return Some(name.to_string());
                }
            }
        }
        None
    }

    /// Format the diagnostic footer for a failed command.
    ///
    /// Returns a multi-line string with `[nono]` prefix on each line.
    /// The output is designed to be printed to stderr.
    #[must_use]
    pub fn format_footer(&self, exit_code: i32) -> String {
        match self.mode {
            DiagnosticMode::Standard => self.format_standard_footer(exit_code),
            DiagnosticMode::Supervised => self.format_supervised_footer(exit_code),
        }
    }

    /// Check whether the resolved binary path falls under any allowed read path.
    fn is_binary_path_readable(&self) -> bool {
        let cmd = match &self.command {
            Some(c) => c,
            None => return true, // no context, assume readable
        };
        let binary_path = &cmd.resolved_path;
        for cap in self.caps.fs_capabilities() {
            if cap.access == AccessMode::Read || cap.access == AccessMode::ReadWrite {
                if binary_path.starts_with(&cap.resolved) {
                    return true;
                }
                if cap.is_file && *binary_path == cap.resolved {
                    return true;
                }
            }
        }
        false
    }

    /// Check whether the binary's parent directory is readable in the sandbox.
    fn is_binary_dir_readable(&self) -> bool {
        let cmd = match &self.command {
            Some(c) => c,
            None => return true,
        };
        let binary_dir = match cmd.resolved_path.parent() {
            Some(d) => d,
            None => return false,
        };
        for cap in self.caps.fs_capabilities() {
            if (cap.access == AccessMode::Read || cap.access == AccessMode::ReadWrite)
                && (binary_dir.starts_with(&cap.resolved) || cap.resolved == binary_dir)
            {
                return true;
            }
        }
        false
    }

    /// Format context-aware explanation for the exit code.
    ///
    /// Returns a vec of `[nono]`-prefixed lines explaining what likely
    /// happened and what the user can do about it.
    fn format_exit_explanation(&self, exit_code: i32) -> Vec<String> {
        let mut lines = Vec::new();

        match exit_code {
            127 => {
                // 127 = command not found (shell convention) or execve failed
                lines.push(
                    "[nono] Command not found (exit code 127).".to_string(),
                );
                lines.push("[nono]".to_string());

                if let Some(ref cmd) = self.command {
                    if !self.is_binary_path_readable() {
                        // The binary exists (we resolved it) but the sandbox
                        // can't read it.
                        lines.push(format!(
                            "[nono] The binary '{}' was found at:",
                            cmd.program,
                        ));
                        lines.push(format!(
                            "[nono]   {}",
                            cmd.resolved_path.display(),
                        ));
                        lines.push(
                            "[nono] but its directory is not readable inside the sandbox."
                                .to_string(),
                        );
                        lines.push("[nono]".to_string());

                        if let Some(parent) = cmd.resolved_path.parent() {
                            lines.push("[nono] Fix: grant read access to the binary's directory:".to_string());
                            lines.push(format!(
                                "[nono]   nono run --read {} ...",
                                parent.display(),
                            ));
                        }
                    } else if !self.is_binary_dir_readable() {
                        // Binary itself is allowed but its directory isn't
                        // (unlikely but possible with file-level grants)
                        lines.push(format!(
                            "[nono] '{}' resolved to {} but the directory",
                            cmd.program,
                            cmd.resolved_path.display(),
                        ));
                        lines.push(
                            "[nono] may not be accessible. The sandbox needs read access to"
                                .to_string(),
                        );
                        lines.push(
                            "[nono] the directory containing the binary.".to_string(),
                        );
                    } else {
                        // Binary path is readable — the command may depend on
                        // a dynamic linker, shared libraries, or shell that
                        // isn't accessible.
                        lines.push(format!(
                            "[nono] '{}' resolved to {} which is readable,",
                            cmd.program,
                            cmd.resolved_path.display(),
                        ));
                        lines.push(
                            "[nono] but the command still failed to execute. Common causes:"
                                .to_string(),
                        );
                        lines.push(
                            "[nono]   - A shared library or dynamic linker path is not accessible"
                                .to_string(),
                        );
                        lines.push(
                            "[nono]   - The binary is a script whose interpreter is not accessible"
                                .to_string(),
                        );
                        lines.push(
                            "[nono]   - The binary depends on a path not in the sandbox"
                                .to_string(),
                        );
                        lines.push("[nono]".to_string());
                        lines.push(
                            "[nono] Run with -v to see all allowed paths and check if"
                                .to_string(),
                        );
                        lines.push(
                            "[nono] required system directories are included.".to_string(),
                        );
                    }
                } else {
                    lines.push(
                        "[nono] The command binary could not be found or executed inside"
                            .to_string(),
                    );
                    lines.push(
                        "[nono] the sandbox. Ensure the binary's directory is readable."
                            .to_string(),
                    );
                }
            }
            126 => {
                // 126 = command found but not executable
                lines.push(
                    "[nono] Permission denied (exit code 126).".to_string(),
                );
                lines.push("[nono]".to_string());

                if let Some(ref cmd) = self.command {
                    lines.push(format!(
                        "[nono] '{}' was found at {} but could not be executed.",
                        cmd.program,
                        cmd.resolved_path.display(),
                    ));
                    lines.push(
                        "[nono] The file may not have execute permission, or the sandbox"
                            .to_string(),
                    );
                    lines.push(
                        "[nono] may be blocking execution of binaries in that directory."
                            .to_string(),
                    );
                } else {
                    lines.push(
                        "[nono] The command was found but could not be executed.".to_string(),
                    );
                    lines.push(
                        "[nono] Check file permissions and sandbox access to the binary's directory."
                            .to_string(),
                    );
                }
            }
            1 => {
                // Generic error - could be anything
                lines.push(format!(
                    "[nono] Command exited with code {}. This may be due to sandbox restrictions.",
                    exit_code,
                ));
            }
            code if (129..=192).contains(&code) => {
                // Signal-based exit: 128 + signal number
                let sig = code - 128;
                // SIGSYS is platform-dependent: 31 on Linux, 12 on macOS
                let sigsys: i32 = libc::SIGSYS;
                let sig_name = match sig {
                    1 => "SIGHUP",
                    2 => "SIGINT",
                    4 => "SIGILL",
                    6 => "SIGABRT",
                    9 => "SIGKILL",
                    11 => "SIGSEGV",
                    13 => "SIGPIPE",
                    15 => "SIGTERM",
                    s if s == sigsys => "SIGSYS",
                    _ => "",
                };

                if sig == sigsys {
                    // SIGSYS = seccomp/sandbox killed it
                    lines.push(format!(
                        "[nono] Command killed by {} (exit code {}).",
                        sig_name, code,
                    ));
                    lines.push("[nono]".to_string());
                    lines.push(
                        "[nono] SIGSYS typically means a blocked system call. The command tried"
                            .to_string(),
                    );
                    lines.push(
                        "[nono] an operation that the sandbox does not permit."
                            .to_string(),
                    );
                } else if sig == 9 {
                    lines.push(format!(
                        "[nono] Command killed by {} (exit code {}).",
                        sig_name, code,
                    ));
                    lines.push("[nono]".to_string());
                    lines.push(
                        "[nono] The process was forcefully terminated. This is usually not"
                            .to_string(),
                    );
                    lines.push(
                        "[nono] caused by sandbox restrictions.".to_string(),
                    );
                } else if !sig_name.is_empty() {
                    lines.push(format!(
                        "[nono] Command killed by signal {} / {} (exit code {}).",
                        sig, sig_name, code,
                    ));
                } else {
                    lines.push(format!(
                        "[nono] Command killed by signal {} (exit code {}).",
                        sig, code,
                    ));
                }
            }
            code => {
                lines.push(format!(
                    "[nono] Command exited with code {}. This may be due to sandbox restrictions.",
                    code,
                ));
            }
        }

        lines
    }

    /// Standard mode footer: concise policy summary with --allow suggestions.
    fn format_standard_footer(&self, exit_code: i32) -> String {
        let mut lines = Vec::new();

        // Check if this was a protected file write attempt
        if let Some(ref blocked_file) = self.blocked_protected_file {
            lines.push(format!(
                "[nono] Write to '{}' blocked: file is a signed instruction file.",
                blocked_file
            ));
            lines.push(
                "[nono] Signed instruction files are write-protected to prevent tampering."
                    .to_string(),
            );
            lines.push("[nono]".to_string());
            lines.push(format!("[nono] Command exited with code {}.", exit_code));
        } else {
            lines.extend(self.format_exit_explanation(exit_code));
        }
        lines.push("[nono]".to_string());

        // Concise policy summary: show user paths, summarize system/group paths
        lines.push("[nono] Sandbox policy:".to_string());
        self.format_allowed_paths_concise(&mut lines);
        self.format_network_status(&mut lines);
        self.format_protected_paths(&mut lines);

        // Help section (skip if the failure was specifically due to protected file)
        if self.blocked_protected_file.is_none() {
            lines.push("[nono]".to_string());
            lines.push("[nono] To grant additional access, re-run with:".to_string());
            lines.push("[nono]   --allow <path>     read+write access to directory".to_string());
            lines.push("[nono]   --read <path>      read-only access to directory".to_string());
            lines.push("[nono]   --write <path>     write-only access to directory".to_string());

            if self.caps.is_network_blocked() {
                lines.push(
                    "[nono]   --net-allow        unrestricted network for this session".to_string(),
                );
            }
        }

        lines.join("\n")
    }

    /// Supervised mode footer: show denials and mode-specific guidance.
    fn format_supervised_footer(&self, exit_code: i32) -> String {
        let mut lines = Vec::new();

        lines.extend(self.format_exit_explanation(exit_code));
        lines.push("[nono]".to_string());

        if self.denials.is_empty() && !self.caps.extensions_enabled() {
            // No denials and no capability expansion (macOS supervised mode).
            // Seatbelt blocks at the kernel level without notifying the supervisor,
            // so we fall back to the standard policy summary with re-run suggestions.
            lines.push("[nono] Sandbox policy:".to_string());
            self.format_allowed_paths_concise(&mut lines);
            self.format_network_status(&mut lines);
            self.format_protected_paths(&mut lines);
            lines.push("[nono]".to_string());
            lines.push("[nono] To grant additional access, re-run with:".to_string());
            lines.push("[nono]   --allow <path>     read+write access to directory".to_string());
            lines.push("[nono]   --read <path>      read-only access to directory".to_string());
            lines.push("[nono]   --write <path>     write-only access to directory".to_string());
            if self.caps.is_network_blocked() {
                lines.push(
                    "[nono]   --net-allow        unrestricted network for this session".to_string(),
                );
            }
            return lines.join("\n");
        } else if self.denials.is_empty() {
            // No denials but expansion is active (Linux supervised mode).
            // seccomp-notify would have caught any denial, so this is genuine.
            lines.push("[nono] No access requests were denied during this session.".to_string());
            lines.push("[nono] The failure may be unrelated to sandbox restrictions.".to_string());
        } else {
            // Show denied paths grouped by reason
            let policy_blocked: Vec<_> = self
                .denials
                .iter()
                .filter(|d| d.reason == DenialReason::PolicyBlocked)
                .collect();
            let user_denied: Vec<_> = self
                .denials
                .iter()
                .filter(|d| d.reason == DenialReason::UserDenied)
                .collect();
            let other_denied: Vec<_> = self
                .denials
                .iter()
                .filter(|d| {
                    d.reason != DenialReason::PolicyBlocked && d.reason != DenialReason::UserDenied
                })
                .collect();

            lines.push("[nono] Denied paths during this session:".to_string());

            // Deduplicate paths within each category (same path may be attempted
            // multiple times)
            if !policy_blocked.is_empty() {
                let mut seen = std::collections::HashSet::new();
                for d in &policy_blocked {
                    if seen.insert(&d.path) {
                        lines.push(format!(
                            "[nono]   {} ({}) - permanently restricted by security policy",
                            d.path.display(),
                            access_str(d.access),
                        ));
                    }
                }
            }
            if !user_denied.is_empty() {
                let mut seen = std::collections::HashSet::new();
                for d in &user_denied {
                    if seen.insert(&d.path) {
                        lines.push(format!(
                            "[nono]   {} ({}) - access declined by user",
                            d.path.display(),
                            access_str(d.access),
                        ));
                    }
                }
            }
            if !other_denied.is_empty() {
                let mut seen = std::collections::HashSet::new();
                for d in &other_denied {
                    if seen.insert(&d.path) {
                        lines.push(format!(
                            "[nono]   {} ({}) - denied",
                            d.path.display(),
                            access_str(d.access),
                        ));
                    }
                }
            }
        }

        // Supervised-mode guidance
        lines.push("[nono]".to_string());
        let has_policy_blocked = self
            .denials
            .iter()
            .any(|d| d.reason == DenialReason::PolicyBlocked);
        let has_user_denied = self
            .denials
            .iter()
            .any(|d| d.reason == DenialReason::UserDenied);

        if has_policy_blocked && !has_user_denied {
            lines.push(
                "[nono] Some paths are permanently restricted and cannot be granted.".to_string(),
            );
        } else if has_user_denied && !has_policy_blocked {
            lines.push(
                "[nono] Re-run the command and approve the access prompt to grant access."
                    .to_string(),
            );
        } else if has_policy_blocked && has_user_denied {
            lines.push(
                "[nono] Some paths are permanently restricted. Others can be granted by approving the prompt."
                    .to_string(),
            );
        }

        lines.join("\n")
    }

    /// Format allowed paths concisely: show user/profile paths explicitly,
    /// summarize group/system paths with a count.
    fn format_allowed_paths_concise(&self, lines: &mut Vec<String>) {
        let caps = self.caps.fs_capabilities();
        if caps.is_empty() {
            lines.push("[nono]   Allowed paths: (none)".to_string());
            return;
        }

        let mut user_paths = Vec::new();
        let mut group_count: usize = 0;

        for cap in caps {
            match &cap.source {
                CapabilitySource::User | CapabilitySource::Profile => {
                    let kind = if cap.is_file { "file" } else { "dir" };
                    user_paths.push(format!(
                        "[nono]     {} ({}, {})",
                        cap.resolved.display(),
                        access_str(cap.access),
                        kind,
                    ));
                }
                CapabilitySource::Group(_) | CapabilitySource::System => {
                    group_count += 1;
                }
            }
        }

        if user_paths.is_empty() && group_count == 0 {
            lines.push("[nono]   Allowed paths: (none)".to_string());
        } else {
            lines.push("[nono]   Allowed paths:".to_string());
            for p in &user_paths {
                lines.push(p.clone());
            }
            if group_count > 0 {
                lines.push(format!(
                    "[nono]     + {} system/profile path(s)",
                    group_count
                ));
            }
        }
    }

    /// Format the network status.
    fn format_network_status(&self, lines: &mut Vec<String>) {
        use crate::NetworkMode;
        match self.caps.network_mode() {
            NetworkMode::Blocked => {
                lines.push("[nono]   Network: blocked".to_string());
            }
            NetworkMode::ProxyOnly { port, bind_ports } => {
                if bind_ports.is_empty() {
                    lines.push(format!("[nono]   Network: proxy (localhost:{})", port));
                } else {
                    let ports_str: Vec<String> = bind_ports.iter().map(|p| p.to_string()).collect();
                    lines.push(format!(
                        "[nono]   Network: proxy (localhost:{}), bind: {}",
                        port,
                        ports_str.join(", ")
                    ));
                }
            }
            NetworkMode::AllowAll => {
                lines.push("[nono]   Network: allowed".to_string());
            }
        }
    }

    /// Format write-protected paths (signed instruction files).
    fn format_protected_paths(&self, lines: &mut Vec<String>) {
        if self.protected_paths.is_empty() {
            return;
        }

        lines.push("[nono]   Write-protected (signed instruction files):".to_string());
        for path in self.protected_paths {
            // Show just the filename for brevity
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| path.display().to_string());
            lines.push(format!("[nono]     {}", name));
        }
    }

    /// Format a concise single-line summary of the policy.
    ///
    /// Useful for logging or brief status messages.
    #[must_use]
    pub fn format_summary(&self) -> String {
        let path_count = self.caps.fs_capabilities().len();
        let network_status = if self.caps.is_network_blocked() {
            "blocked"
        } else {
            "allowed"
        };

        format!(
            "[nono] Policy: {} path(s), network {}",
            path_count, network_status
        )
    }
}

fn access_str(access: AccessMode) -> &'static str {
    match access {
        AccessMode::Read => "read",
        AccessMode::Write => "write",
        AccessMode::ReadWrite => "read+write",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{CapabilitySource, FsCapability};

    fn make_test_caps() -> CapabilitySet {
        let mut caps = CapabilitySet::new().block_network();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/test/project"),
            resolved: PathBuf::from("/test/project"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });
        caps
    }

    fn make_mixed_caps() -> CapabilitySet {
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/home/user/project"),
            resolved: PathBuf::from("/home/user/project"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });
        caps.add_fs(FsCapability {
            original: PathBuf::from("/usr/bin"),
            resolved: PathBuf::from("/usr/bin"),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::Group("base_read".to_string()),
        });
        caps.add_fs(FsCapability {
            original: PathBuf::from("/usr/lib"),
            resolved: PathBuf::from("/usr/lib"),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::Group("base_read".to_string()),
        });
        caps.add_fs(FsCapability {
            original: PathBuf::from("/tmp"),
            resolved: PathBuf::from("/tmp"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::System,
        });
        caps
    }

    // --- Standard mode tests ---

    #[test]
    fn test_standard_footer_contains_exit_code() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("exited with code 1"));
    }

    #[test]
    fn test_standard_footer_uses_may_not_was() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("may be due to"));
        assert!(!output.contains("was caused by"));
    }

    #[test]
    fn test_standard_footer_has_nono_prefix() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        for line in output.lines() {
            if !line.is_empty() {
                assert!(line.starts_with("[nono]"), "Line missing prefix: {}", line);
            }
        }
    }

    #[test]
    fn test_standard_footer_shows_user_paths() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("/test/project"));
        assert!(output.contains("read+write"));
    }

    #[test]
    fn test_standard_footer_summarizes_group_paths() {
        let caps = make_mixed_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        // User path shown explicitly
        assert!(output.contains("/home/user/project"));
        // Group/system paths summarized, not listed individually
        assert!(output.contains("3 system/profile path(s)"));
        assert!(!output.contains("/usr/bin"));
        assert!(!output.contains("/usr/lib"));
    }

    #[test]
    fn test_standard_footer_shows_network_blocked() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("Network: blocked"));
    }

    #[test]
    fn test_standard_footer_shows_network_allowed() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/test/project"),
            resolved: PathBuf::from("/test/project"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("Network: allowed"));
    }

    #[test]
    fn test_standard_footer_shows_network_proxy() {
        use crate::NetworkMode;
        let mut caps = CapabilitySet::new().block_network();
        caps.set_network_mode_mut(NetworkMode::ProxyOnly {
            port: 12345,
            bind_ports: vec![],
        });
        caps.add_fs(FsCapability {
            original: PathBuf::from("/test/project"),
            resolved: PathBuf::from("/test/project"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("Network: proxy (localhost:12345)"));
    }

    #[test]
    fn test_standard_footer_shows_help() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("--allow <path>"));
        assert!(output.contains("--read <path>"));
        assert!(output.contains("--write <path>"));
    }

    #[test]
    fn test_standard_footer_shows_network_help_when_blocked() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("--net-allow"));
    }

    #[test]
    fn test_standard_footer_no_network_help_when_allowed() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/test/project"),
            resolved: PathBuf::from("/test/project"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(!output.contains("--net-allow"));
    }

    #[test]
    fn test_standard_footer_empty_caps() {
        let caps = CapabilitySet::new();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("(none)"));
    }

    #[test]
    fn test_standard_footer_file_vs_dir() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/test/file.txt"),
            resolved: PathBuf::from("/test/file.txt"),
            access: AccessMode::Read,
            is_file: true,
            source: CapabilitySource::User,
        });
        caps.add_fs(FsCapability {
            original: PathBuf::from("/test/dir"),
            resolved: PathBuf::from("/test/dir"),
            access: AccessMode::Write,
            is_file: false,
            source: CapabilitySource::User,
        });

        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("file.txt (read, file)"));
        assert!(output.contains("dir (write, dir)"));
    }

    #[test]
    fn test_format_summary() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let summary = formatter.format_summary();

        assert!(summary.contains("1 path(s)"));
        assert!(summary.contains("network blocked"));
    }

    // --- Supervised mode tests ---

    #[test]
    fn test_supervised_no_denials_no_extensions() {
        // macOS supervised mode: no capability expansion, Seatbelt blocks silently.
        // Should fall back to policy summary + --allow suggestions.
        let caps = make_test_caps(); // extensions_enabled defaults to false
        let formatter = DiagnosticFormatter::new(&caps).with_mode(DiagnosticMode::Supervised);
        let output = formatter.format_footer(1);

        assert!(output.contains("Sandbox policy:"));
        assert!(output.contains("--allow <path>"));
        assert!(!output.contains("No access requests were denied"));
    }

    #[test]
    fn test_supervised_no_denials_extensions_active() {
        // Linux supervised mode: seccomp-notify is active, empty denials means
        // nothing was actually blocked.
        let mut caps = make_test_caps();
        caps.set_extensions_enabled(true);
        let formatter = DiagnosticFormatter::new(&caps).with_mode(DiagnosticMode::Supervised);
        let output = formatter.format_footer(1);

        assert!(output.contains("No access requests were denied"));
        assert!(output.contains("may be unrelated"));
        assert!(!output.contains("--allow <path>"));
    }

    #[test]
    fn test_supervised_policy_blocked_denial() {
        let caps = make_test_caps();
        let denials = vec![DenialRecord {
            path: PathBuf::from("/etc/shadow"),
            access: AccessMode::Read,
            reason: DenialReason::PolicyBlocked,
        }];
        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_denials(&denials);
        let output = formatter.format_footer(1);

        assert!(output.contains("/etc/shadow"));
        assert!(output.contains("permanently restricted"));
        assert!(!output.contains("--allow <path>"));
    }

    #[test]
    fn test_supervised_user_denied() {
        let caps = make_test_caps();
        let denials = vec![DenialRecord {
            path: PathBuf::from("/home/user/secret.txt"),
            access: AccessMode::Read,
            reason: DenialReason::UserDenied,
        }];
        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_denials(&denials);
        let output = formatter.format_footer(1);

        assert!(output.contains("/home/user/secret.txt"));
        assert!(output.contains("declined by user"));
        assert!(output.contains("Re-run the command and approve"));
        assert!(!output.contains("--allow <path>"));
    }

    #[test]
    fn test_supervised_mixed_denials() {
        let caps = make_test_caps();
        let denials = vec![
            DenialRecord {
                path: PathBuf::from("/etc/shadow"),
                access: AccessMode::Read,
                reason: DenialReason::PolicyBlocked,
            },
            DenialRecord {
                path: PathBuf::from("/home/user/data.txt"),
                access: AccessMode::Read,
                reason: DenialReason::UserDenied,
            },
        ];
        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_denials(&denials);
        let output = formatter.format_footer(1);

        assert!(output.contains("/etc/shadow"));
        assert!(output.contains("/home/user/data.txt"));
        assert!(output.contains("permanently restricted"));
        assert!(output.contains("approving the prompt"));
    }

    #[test]
    fn test_supervised_deduplicates_paths() {
        let caps = make_test_caps();
        let denials = vec![
            DenialRecord {
                path: PathBuf::from("/etc/shadow"),
                access: AccessMode::Read,
                reason: DenialReason::PolicyBlocked,
            },
            DenialRecord {
                path: PathBuf::from("/etc/shadow"),
                access: AccessMode::Read,
                reason: DenialReason::PolicyBlocked,
            },
        ];
        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_denials(&denials);
        let output = formatter.format_footer(1);

        // Should only appear once
        let count = output.matches("/etc/shadow").count();
        assert_eq!(count, 1, "Path should be deduplicated");
    }

    #[test]
    fn test_supervised_has_nono_prefix() {
        let caps = make_test_caps();
        let denials = vec![DenialRecord {
            path: PathBuf::from("/etc/shadow"),
            access: AccessMode::Read,
            reason: DenialReason::PolicyBlocked,
        }];
        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_denials(&denials);
        let output = formatter.format_footer(1);

        for line in output.lines() {
            if !line.is_empty() {
                assert!(line.starts_with("[nono]"), "Line missing prefix: {}", line);
            }
        }
    }

    #[test]
    fn test_supervised_rate_limited_denial() {
        let caps = make_test_caps();
        let denials = vec![DenialRecord {
            path: PathBuf::from("/tmp/flood"),
            access: AccessMode::Read,
            reason: DenialReason::RateLimited,
        }];
        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_denials(&denials);
        let output = formatter.format_footer(1);

        assert!(output.contains("/tmp/flood"));
        assert!(output.contains("denied"));
    }

    // --- Protected paths tests ---

    #[test]
    fn test_protected_paths_shown_in_footer() {
        let caps = make_test_caps();
        let protected = vec![
            PathBuf::from("/project/SKILLS.md"),
            PathBuf::from("/project/helper.py"),
        ];
        let formatter = DiagnosticFormatter::new(&caps).with_protected_paths(&protected);
        let output = formatter.format_footer(1);

        assert!(output.contains("Write-protected"));
        assert!(output.contains("SKILLS.md"));
        assert!(output.contains("helper.py"));
    }

    #[test]
    fn test_protected_paths_empty_no_section() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps).with_protected_paths(&[]);
        let output = formatter.format_footer(1);

        assert!(!output.contains("Write-protected"));
    }

    #[test]
    fn test_protected_paths_shown_in_supervised_macos_fallback() {
        // macOS supervised mode (no extensions) falls back to standard policy format
        let caps = make_test_caps(); // extensions_enabled defaults to false
        let protected = vec![PathBuf::from("/project/config.json")];
        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_protected_paths(&protected);
        let output = formatter.format_footer(1);

        assert!(output.contains("Write-protected"));
        assert!(output.contains("config.json"));
    }

    // --- Exit code explanation tests ---

    fn make_command_context(program: &str, path: &str) -> CommandContext {
        CommandContext {
            program: program.to_string(),
            resolved_path: PathBuf::from(path),
        }
    }

    #[test]
    fn test_exit_127_binary_not_readable() {
        // Binary resolved to /opt/bin/foo but sandbox has no read access there
        let caps = make_test_caps(); // only /test/project
        let cmd = make_command_context("foo", "/opt/bin/foo");
        let formatter = DiagnosticFormatter::new(&caps).with_command(cmd);
        let output = formatter.format_footer(127);

        assert!(output.contains("Command not found (exit code 127)"));
        assert!(output.contains("'foo' was found at:"));
        assert!(output.contains("/opt/bin/foo"));
        assert!(output.contains("not readable inside the sandbox"));
        assert!(output.contains("nono run --read /opt/bin"));
    }

    #[test]
    fn test_exit_127_binary_readable_but_exec_fails() {
        // Binary at /usr/bin/ps, sandbox has /usr/bin readable
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/usr/bin"),
            resolved: PathBuf::from("/usr/bin"),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::Group("system_read".to_string()),
        });
        let cmd = make_command_context("ps", "/usr/bin/ps");
        let formatter = DiagnosticFormatter::new(&caps).with_command(cmd);
        let output = formatter.format_footer(127);

        assert!(output.contains("'ps' resolved to /usr/bin/ps which is readable"));
        assert!(output.contains("Common causes:"));
        assert!(output.contains("shared library"));
        assert!(output.contains("Run with -v"));
    }

    #[test]
    fn test_exit_127_file_level_grant_dir_not_readable() {
        // Binary granted as a file-level read, but parent dir not readable
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/opt/custom/mybin"),
            resolved: PathBuf::from("/opt/custom/mybin"),
            access: AccessMode::Read,
            is_file: true,
            source: CapabilitySource::User,
        });
        let cmd = make_command_context("mybin", "/opt/custom/mybin");
        let formatter = DiagnosticFormatter::new(&caps).with_command(cmd);
        let output = formatter.format_footer(127);

        // is_binary_path_readable returns true (file-level match)
        // is_binary_dir_readable returns false (/opt/custom not granted)
        assert!(output.contains("'mybin' resolved to /opt/custom/mybin but the directory"));
        assert!(output.contains("read access to"));
    }

    #[test]
    fn test_exit_127_no_command_context() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(127);

        assert!(output.contains("Command not found (exit code 127)"));
        assert!(output.contains("could not be found or executed"));
    }

    #[test]
    fn test_exit_126_permission_denied() {
        let caps = make_test_caps();
        let cmd = make_command_context("script.sh", "/test/project/script.sh");
        let formatter = DiagnosticFormatter::new(&caps).with_command(cmd);
        let output = formatter.format_footer(126);

        assert!(output.contains("Permission denied (exit code 126)"));
        assert!(output.contains("'script.sh' was found at /test/project/script.sh"));
        assert!(output.contains("execute permission"));
    }

    #[test]
    fn test_exit_126_no_command_context() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(126);

        assert!(output.contains("Permission denied (exit code 126)"));
        assert!(output.contains("found but could not be executed"));
    }

    #[test]
    fn test_exit_1_generic() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("exited with code 1"));
        assert!(output.contains("may be due to sandbox restrictions"));
    }

    #[test]
    fn test_exit_sigkill() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(128 + 9);

        assert!(output.contains("SIGKILL"));
        assert!(output.contains("forcefully terminated"));
        assert!(output.contains("usually not"));
    }

    #[test]
    fn test_exit_sigsys_platform_correct() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(128 + libc::SIGSYS);

        assert!(output.contains("SIGSYS"));
        assert!(output.contains("blocked system call"));
    }

    #[test]
    fn test_exit_sigterm() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(128 + 15);

        assert!(output.contains("SIGTERM"));
        // SIGTERM gets the generic signal line, not a special explanation
        assert!(!output.contains("blocked system call"));
        assert!(!output.contains("forcefully terminated"));
    }

    #[test]
    fn test_exit_unknown_signal() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(128 + 33);

        assert!(output.contains("killed by signal 33"));
        assert!(!output.contains("SIGKILL"));
        assert!(!output.contains("SIGSYS"));
    }

    #[test]
    fn test_exit_other_code() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(42);

        assert!(output.contains("exited with code 42"));
        assert!(output.contains("may be due to sandbox restrictions"));
    }
}
