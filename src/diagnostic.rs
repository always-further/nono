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
//! - **Library code**: No process management, no CLI assumptions

use crate::capability::{CapabilitySet, FsAccess};

/// Formats diagnostic information about sandbox policy.
///
/// This is library code that can be used by any parent process
/// that wants to explain sandbox denials to users or AI agents.
pub struct DiagnosticFormatter<'a> {
    caps: &'a CapabilitySet,
}

impl<'a> DiagnosticFormatter<'a> {
    /// Create a new formatter for the given capability set.
    #[must_use]
    pub fn new(caps: &'a CapabilitySet) -> Self {
        Self { caps }
    }

    /// Format the diagnostic footer for a failed command.
    ///
    /// Returns a multi-line string with `[nono]` prefix on each line.
    /// The output is designed to be printed to stderr.
    #[must_use]
    pub fn format_footer(&self, exit_code: i32) -> String {
        let mut lines = Vec::new();

        // Header
        lines.push(format!(
            "[nono] Command exited with code {}. This may be due to sandbox restrictions.",
            exit_code
        ));
        lines.push("[nono]".to_string());

        // Policy summary
        lines.push("[nono] Sandbox policy:".to_string());
        self.format_allowed_paths(&mut lines);
        self.format_network_status(&mut lines);

        // Help section
        lines.push("[nono]".to_string());
        lines.push("[nono] To grant additional access, re-run with:".to_string());
        lines.push("[nono]   --allow <path>     read+write access to directory".to_string());
        lines.push("[nono]   --read <path>      read-only access to directory".to_string());
        lines.push("[nono]   --write <path>     write-only access to directory".to_string());

        if self.caps.net_block {
            lines.push(
                "[nono]   --allow-net        network access (remove --net-block)".to_string(),
            );
        }

        lines.join("\n")
    }

    /// Format the list of allowed paths.
    fn format_allowed_paths(&self, lines: &mut Vec<String>) {
        lines.push("[nono]   Allowed paths:".to_string());

        if self.caps.fs.is_empty() {
            lines.push("[nono]     (none)".to_string());
        } else {
            for cap in &self.caps.fs {
                let access_str = match cap.access {
                    FsAccess::Read => "read",
                    FsAccess::Write => "write",
                    FsAccess::ReadWrite => "read+write",
                };
                let kind = if cap.is_file { "file" } else { "dir" };
                lines.push(format!(
                    "[nono]     {} ({}, {})",
                    cap.resolved.display(),
                    access_str,
                    kind
                ));
            }
        }
    }

    /// Format the network status.
    fn format_network_status(&self, lines: &mut Vec<String>) {
        if self.caps.net_block {
            lines.push("[nono]   Network: blocked".to_string());
        } else {
            lines.push("[nono]   Network: allowed".to_string());
        }
    }

    /// Format a concise single-line summary of the policy.
    ///
    /// Useful for logging or brief status messages.
    #[must_use]
    #[allow(dead_code)]
    pub fn format_summary(&self) -> String {
        let path_count = self.caps.fs.len();
        let network_status = if self.caps.net_block {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::FsCapability;
    use std::path::PathBuf;

    fn make_test_caps() -> CapabilitySet {
        let mut caps = CapabilitySet::default();
        caps.fs.push(FsCapability {
            original: PathBuf::from("/test/project"),
            resolved: PathBuf::from("/test/project"),
            access: FsAccess::ReadWrite,
            is_file: false,
        });
        caps.net_block = true;
        caps
    }

    #[test]
    fn test_format_footer_contains_exit_code() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("exited with code 1"));
    }

    #[test]
    fn test_format_footer_uses_may_not_was() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        // Must say "may be due to" not "was caused by"
        assert!(output.contains("may be due to"));
        assert!(!output.contains("was caused by"));
    }

    #[test]
    fn test_format_footer_has_nono_prefix() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        // Every non-empty line must start with [nono]
        for line in output.lines() {
            if !line.is_empty() {
                assert!(line.starts_with("[nono]"), "Line missing prefix: {}", line);
            }
        }
    }

    #[test]
    fn test_format_footer_shows_allowed_paths() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("/test/project"));
        assert!(output.contains("read+write"));
    }

    #[test]
    fn test_format_footer_shows_network_blocked() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("Network: blocked"));
    }

    #[test]
    fn test_format_footer_shows_network_allowed() {
        let mut caps = make_test_caps();
        caps.net_block = false;
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("Network: allowed"));
    }

    #[test]
    fn test_format_footer_shows_help() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("--allow <path>"));
        assert!(output.contains("--read <path>"));
        assert!(output.contains("--write <path>"));
    }

    #[test]
    fn test_format_footer_shows_network_help_when_blocked() {
        let mut caps = make_test_caps();
        caps.net_block = true;
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("--allow-net"));
    }

    #[test]
    fn test_format_footer_no_network_help_when_allowed() {
        let mut caps = make_test_caps();
        caps.net_block = false;
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        // Should not suggest --allow-net if network already allowed
        assert!(!output.contains("--allow-net"));
    }

    #[test]
    fn test_format_footer_empty_caps() {
        let caps = CapabilitySet::default();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("(none)"));
    }

    #[test]
    fn test_format_summary() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let summary = formatter.format_summary();

        assert!(summary.contains("1 path(s)"));
        assert!(summary.contains("network blocked"));
    }

    #[test]
    fn test_format_footer_file_vs_dir() {
        let mut caps = CapabilitySet::default();
        caps.fs.push(FsCapability {
            original: PathBuf::from("/test/file.txt"),
            resolved: PathBuf::from("/test/file.txt"),
            access: FsAccess::Read,
            is_file: true,
        });
        caps.fs.push(FsCapability {
            original: PathBuf::from("/test/dir"),
            resolved: PathBuf::from("/test/dir"),
            access: FsAccess::Write,
            is_file: false,
        });

        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("file.txt (read, file)"));
        assert!(output.contains("dir (write, dir)"));
    }
}
