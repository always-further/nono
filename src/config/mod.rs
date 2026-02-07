//! Configuration module for nono
//!
//! This module handles loading and merging configuration from multiple sources:
//! - Embedded author-signed security lists (highest trust)
//! - System-level config at /etc/nono/ (admin-signed, additive only)
//! - User-level config at ~/.config/nono/ (overrides with acknowledgment)
//! - CLI flags (highest precedence)

pub mod embedded;
pub mod security_lists;
pub mod user;
pub mod verify;
pub mod version;

use crate::error::Result;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use tracing::warn;

// ============================================================================
// Phase 4 infrastructure: Override system (implemented, not yet integrated)
// These types and functions are used for the full override system which
// will be integrated in a future PR. For now, allow dead_code.
// ============================================================================

/// Effective configuration after merging all sources
#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct EffectiveConfig {
    /// All sensitive paths that should be blocked
    pub sensitive_paths: HashSet<String>,

    /// Sensitive paths that have been explicitly allowed (with reason)
    pub allowed_sensitive: HashMap<String, OverrideInfo>,

    /// All dangerous commands that should be blocked
    pub dangerous_commands: HashSet<String>,

    /// Commands that have been explicitly allowed (with reason)
    pub allowed_commands: HashMap<String, OverrideInfo>,

    /// System read paths for the current platform
    pub system_read_paths: Vec<String>,

    /// Version information for downgrade protection
    pub security_lists_version: u64,
}

/// Information about an override (for audit trail)
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct OverrideInfo {
    /// Reason provided by user for the override
    pub reason: String,
    /// When the override was acknowledged (if from config file)
    pub acknowledged: Option<String>,
    /// Source of the override
    pub source: OverrideSource,
    /// Access level for path overrides (read, write, or both)
    pub access: Option<String>,
}

/// Source of an override for audit purposes
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum OverrideSource {
    /// Override came from CLI flag (single session)
    CliFlag,
    /// Override came from user config file (persistent)
    UserConfig,
}

impl OverrideInfo {
    /// Create an override from a CLI flag
    #[allow(dead_code)]
    pub fn from_cli(reason: &str) -> Self {
        Self {
            reason: reason.to_string(),
            acknowledged: None,
            source: OverrideSource::CliFlag,
            access: None,
        }
    }
}

/// Load effective configuration by merging all sources
///
/// Precedence (highest to lowest):
/// 1. CLI flags
/// 2. User config (~/.config/nono/config.toml)
/// 3. System config (/etc/nono/) - additive only
/// 4. Embedded defaults
#[allow(dead_code)]
pub fn load_effective_config() -> Result<EffectiveConfig> {
    // Start with embedded security lists
    let security_lists = embedded::load_security_lists()?;

    let mut config = EffectiveConfig {
        sensitive_paths: security_lists.all_sensitive_paths(),
        dangerous_commands: security_lists.all_dangerous_commands(),
        system_read_paths: security_lists.system_paths_for_platform(),
        security_lists_version: security_lists.meta.version,
        ..Default::default()
    };

    // Load user config if it exists (optional)
    if let Some(user_config) = user::load_user_config()? {
        // Apply user extensions (additions to blocklists)
        for path in user_config.extensions.sensitive_paths.values().flatten() {
            config.sensitive_paths.insert(path.clone());
        }

        for cmd in user_config.extensions.dangerous_commands.values().flatten() {
            config.dangerous_commands.insert(cmd.clone());
        }

        // Apply user overrides (acknowledged exceptions)
        for (path, override_info) in user_config.overrides.sensitive_paths {
            if override_info.acknowledged.is_some() {
                config.allowed_sensitive.insert(
                    path,
                    OverrideInfo {
                        reason: override_info.reason,
                        acknowledged: override_info.acknowledged,
                        source: OverrideSource::UserConfig,
                        access: override_info.access,
                    },
                );
            }
        }

        for (cmd, override_info) in user_config.overrides.commands {
            if override_info.acknowledged.is_some() {
                config.allowed_commands.insert(
                    cmd,
                    OverrideInfo {
                        reason: override_info.reason,
                        acknowledged: override_info.acknowledged,
                        source: OverrideSource::UserConfig,
                        access: None,
                    },
                );
            }
        }
    }

    Ok(config)
}

/// Check if a path is in the sensitive paths list
#[allow(dead_code)]
pub fn is_sensitive_path(path: &str, config: &EffectiveConfig) -> bool {
    let home = std::env::var("HOME").unwrap_or_default();
    let expanded = path.replace('~', &home);

    for sensitive in &config.sensitive_paths {
        let expanded_sensitive = sensitive.replace('~', &home);
        if expanded == expanded_sensitive
            || expanded.starts_with(&format!("{}/", expanded_sensitive))
        {
            // Check if explicitly allowed
            if config.allowed_sensitive.contains_key(sensitive) {
                return false;
            }
            return true;
        }
    }
    false
}

/// Check if a command is in the dangerous commands list
#[allow(dead_code)]
pub fn is_dangerous_command(cmd: &str, config: &EffectiveConfig) -> bool {
    use std::ffi::OsStr;
    use std::path::Path;

    // Extract just the binary name (handle paths like /bin/rm)
    let binary_os = Path::new(cmd)
        .file_name()
        .unwrap_or_else(|| OsStr::new(cmd));
    let binary = binary_os.to_string_lossy();

    // Check if explicitly allowed
    if config.allowed_commands.contains_key(binary.as_ref()) {
        return false;
    }

    config.dangerous_commands.contains(binary.as_ref())
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

/// Get all sensitive paths from embedded config
pub fn get_sensitive_paths() -> Vec<String> {
    match embedded::load_security_lists() {
        Ok(lists) => lists.all_sensitive_paths().into_iter().collect(),
        Err(err) => {
            warn!(
                "Failed to load embedded security lists for sensitive paths: {}",
                err
            );
            Vec::new()
        }
    }
}

/// Get all dangerous commands from embedded config
pub fn get_dangerous_commands() -> HashSet<String> {
    match embedded::load_security_lists() {
        Ok(lists) => lists.all_dangerous_commands(),
        Err(err) => {
            warn!(
                "Failed to load embedded security lists for dangerous commands: {}",
                err
            );
            HashSet::new()
        }
    }
}

/// Get system read paths for the current platform
#[allow(dead_code)]
pub fn get_system_read_paths() -> Vec<String> {
    match embedded::load_security_lists() {
        Ok(lists) => lists.system_paths_for_platform(),
        Err(err) => {
            warn!(
                "Failed to load embedded security lists for system read paths: {}",
                err
            );
            Vec::new()
        }
    }
}

/// Check if a command is blocked by the default dangerous commands list
/// Returns Some(command_name) if blocked, None if allowed
pub fn check_blocked_command(
    cmd: impl AsRef<std::ffi::OsStr>,
    allowed_commands: &[String],
    extra_blocked: &[String],
) -> Option<String> {
    use std::ffi::OsStr;
    use std::path::Path;

    let cmd = cmd.as_ref();

    // Extract just the binary name (handle paths like /bin/rm)
    let binary_os = Path::new(cmd).file_name().unwrap_or(cmd);

    // Check if explicitly allowed (overrides default blocklist)
    if allowed_commands.iter().any(|a| OsStr::new(a) == binary_os) {
        return None;
    }

    // Check extra blocked commands first
    if extra_blocked.iter().any(|b| OsStr::new(b) == binary_os) {
        return Some(binary_os.to_string_lossy().into_owned());
    }

    // Check default dangerous commands list from config
    let dangerous = get_dangerous_commands();
    let binary_str = binary_os.to_string_lossy();
    if dangerous.contains(binary_str.as_ref()) {
        return Some(binary_str.into_owned());
    }

    None
}

/// Check if a path is in the sensitive paths list (for `nono why` command)
/// Returns Some(reason) if blocked, None if not in list
pub fn check_sensitive_path(path_str: &str) -> Option<&'static str> {
    use security_lists::sensitive_paths_by_category;

    let home = std::env::var("HOME").unwrap_or_default();
    let expanded = if path_str.starts_with("~/") {
        path_str.replacen("~", &home, 1)
    } else if path_str == "~" {
        home.clone()
    } else {
        path_str.to_string()
    };

    // Load security lists and get paths organized by category
    let lists = match embedded::load_security_lists() {
        Ok(l) => l,
        Err(err) => {
            warn!(
                "Failed to load embedded security lists while checking sensitive path: {}",
                err
            );
            return None;
        }
    };

    let categories = sensitive_paths_by_category(&lists);

    // Check each category's paths
    for (category_name, paths) in categories {
        for sensitive in paths {
            let expanded_sensitive = sensitive.replace('~', &home);

            if expanded == expanded_sensitive
                || expanded.starts_with(&format!("{}/", expanded_sensitive))
            {
                return Some(category_name);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_override_info_from_cli() {
        let info = OverrideInfo::from_cli("test reason");
        assert_eq!(info.reason, "test reason");
        assert_eq!(info.source, OverrideSource::CliFlag);
        assert!(info.acknowledged.is_none());
    }

    #[test]
    fn test_is_dangerous_command() {
        let mut config = EffectiveConfig::default();
        config.dangerous_commands.insert("rm".to_string());
        config.dangerous_commands.insert("dd".to_string());

        assert!(is_dangerous_command("rm", &config));
        assert!(is_dangerous_command("/bin/rm", &config));
        assert!(is_dangerous_command("dd", &config));
        assert!(!is_dangerous_command("ls", &config));
        assert!(!is_dangerous_command("echo", &config));
    }

    #[test]
    fn test_is_dangerous_command_with_override() {
        let mut config = EffectiveConfig::default();
        config.dangerous_commands.insert("pip".to_string());
        config.allowed_commands.insert(
            "pip".to_string(),
            OverrideInfo::from_cli("needed for development"),
        );

        // Should not be considered dangerous when explicitly allowed
        assert!(!is_dangerous_command("pip", &config));
    }
}
