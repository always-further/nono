//! Configuration module for nono CLI
//!
//! This module handles loading and merging configuration from multiple sources:
//! - Embedded policy.json (composable security groups, single source of truth)
//! - User-level config at ~/.config/nono/ (overrides with acknowledgment)
//! - CLI flags (highest precedence)

pub mod embedded;
pub mod user;
pub mod version;

use crate::policy;
use nono::{NonoError, Result};
use std::path::{Path, PathBuf};

// ============================================================================
// Environment variable validation
// ============================================================================

/// Validate and return the HOME environment variable.
///
/// Returns an error if HOME is not set or is not an absolute path.
/// This prevents attacks where a malicious parent process sets
/// HOME to a relative or attacker-controlled path, which would
/// cause deny rules and sensitive path checks to target wrong locations.
pub fn validated_home() -> Result<String> {
    let home = std::env::var("HOME").map_err(|_| NonoError::EnvVarValidation {
        var: "HOME".to_string(),
        reason: "not set".to_string(),
    })?;

    if !Path::new(&home).is_absolute() {
        return Err(NonoError::EnvVarValidation {
            var: "HOME".to_string(),
            reason: format!("must be an absolute path, got: {}", home),
        });
    }

    Ok(home)
}

/// Validate and return the TMPDIR environment variable, falling back to /tmp.
///
/// Returns an error if TMPDIR is set but is not an absolute path.
pub fn validated_tmpdir() -> Result<String> {
    match std::env::var("TMPDIR") {
        Ok(tmpdir) => {
            if !Path::new(&tmpdir).is_absolute() {
                return Err(NonoError::EnvVarValidation {
                    var: "TMPDIR".to_string(),
                    reason: format!("must be an absolute path, got: {}", tmpdir),
                });
            }
            Ok(tmpdir)
        }
        Err(_) => Ok("/tmp".to_string()),
    }
}

/// Get the user config directory path
#[allow(dead_code)]
pub fn user_config_dir() -> Option<PathBuf> {
    dirs::config_dir().map(|p| p.join("nono"))
}

/// Get the user state directory path (for version tracking)
#[allow(dead_code)]
pub fn user_state_dir() -> Option<PathBuf> {
    dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .map(|p| p.join("nono"))
}

// ============================================================================
// Helper functions for main.rs compatibility
// These provide access to embedded config data without requiring full config loading
// ============================================================================

/// Check if a command is blocked by the default dangerous commands list
/// Returns Some(command_name) if blocked, None if allowed
pub fn check_blocked_command(
    cmd: impl AsRef<std::ffi::OsStr>,
    allowed_commands: &[String],
    extra_blocked: &[String],
) -> Result<Option<String>> {
    use std::ffi::OsStr;
    use std::path::Path;

    let cmd = cmd.as_ref();

    // Extract just the binary name (handle paths like /bin/rm)
    let binary_os = Path::new(cmd).file_name().unwrap_or(cmd);

    // Check if explicitly allowed (overrides default blocklist)
    if allowed_commands.iter().any(|a| OsStr::new(a) == binary_os) {
        return Ok(None);
    }

    // Check extra blocked commands first
    if extra_blocked.iter().any(|b| OsStr::new(b) == binary_os) {
        return Ok(Some(binary_os.to_string_lossy().into_owned()));
    }

    // Check default dangerous commands list from policy.json
    let loaded_policy = policy::load_embedded_policy()?;
    let dangerous = policy::get_dangerous_commands(&loaded_policy);
    let binary_str = binary_os.to_string_lossy();
    if dangerous.contains(binary_str.as_ref()) {
        return Ok(Some(binary_str.into_owned()));
    }

    Ok(None)
}

/// Check if a path is in the sensitive paths list (for `nono why` command)
/// Returns Some(category_description) if blocked, None if not in list
///
/// Uses `Path::starts_with()` for component-wise comparison, preventing
/// bypass attacks like `~/.sshevil` matching `~/.ssh`.
pub fn check_sensitive_path(path_str: &str) -> Result<Option<String>> {
    let home = validated_home()?;
    let expanded_path = policy::expand_home_path(path_str, &home);

    let loaded_policy = policy::load_embedded_policy()?;
    let sensitive = policy::get_sensitive_paths_with_home(&loaded_policy, &home)?;

    for (sensitive_expanded, description) in &sensitive {
        let sensitive_path = Path::new(sensitive_expanded);

        if expanded_path == sensitive_path || expanded_path.starts_with(sensitive_path) {
            return Ok(Some(description.clone()));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_blocked_command_basic() {
        assert!(check_blocked_command("rm", &[], &[])
            .expect("should not fail")
            .is_some());
        assert!(check_blocked_command("dd", &[], &[])
            .expect("should not fail")
            .is_some());
        assert!(check_blocked_command("echo", &[], &[])
            .expect("should not fail")
            .is_none());
        assert!(check_blocked_command("ls", &[], &[])
            .expect("should not fail")
            .is_none());
    }

    #[test]
    fn test_check_blocked_command_with_path() {
        assert!(check_blocked_command("/bin/rm", &[], &[])
            .expect("should not fail")
            .is_some());
        assert!(check_blocked_command("/usr/bin/dd", &[], &[])
            .expect("should not fail")
            .is_some());
    }

    #[test]
    fn test_check_blocked_command_with_override() {
        let allowed = vec!["rm".to_string()];
        assert!(check_blocked_command("rm", &allowed, &[])
            .expect("should not fail")
            .is_none());
        assert!(check_blocked_command("dd", &allowed, &[])
            .expect("should not fail")
            .is_some());
    }

    #[test]
    fn test_check_blocked_command_extra_blocked() {
        let extra = vec!["custom-dangerous".to_string()];
        assert!(check_blocked_command("custom-dangerous", &[], &extra)
            .expect("should not fail")
            .is_some());
        assert!(check_blocked_command("rm", &[], &extra)
            .expect("should not fail")
            .is_some());
    }

    #[test]
    fn test_check_sensitive_path() {
        assert!(check_sensitive_path("~/.ssh")
            .expect("should not fail")
            .is_some());
        assert!(check_sensitive_path("~/.aws")
            .expect("should not fail")
            .is_some());
        assert!(check_sensitive_path("~/.config/gcloud")
            .expect("should not fail")
            .is_some());
        // /tmp is a system path, not sensitive
        assert!(check_sensitive_path("/tmp")
            .expect("should not fail")
            .is_none());
        // ~/Documents is not sensitive
        assert!(check_sensitive_path("~/Documents")
            .expect("should not fail")
            .is_none());
    }

    #[test]
    fn test_check_sensitive_path_component_wise() {
        // ~/.sshevil must NOT match ~/.ssh (component-wise comparison)
        let home = validated_home().expect("HOME must be set");
        let evil_path = format!("{}/.sshevil", home);
        assert!(check_sensitive_path(&evil_path)
            .expect("should not fail")
            .is_none());

        // But ~/.ssh/id_rsa should match ~/.ssh
        assert!(check_sensitive_path("~/.ssh/id_rsa")
            .expect("should not fail")
            .is_some());
    }
}
