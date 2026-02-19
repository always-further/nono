//! User configuration loading
//!
//! Loads user-level configuration from ~/.config/nono/config.toml

#![allow(dead_code)]

use nono::{NonoError, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

/// User configuration file name
const USER_CONFIG_FILE: &str = "config.toml";

/// Root structure for user config
#[derive(Debug, Default, Deserialize)]
pub struct UserConfig {
    #[serde(default)]
    pub meta: UserConfigMeta,
    #[serde(default)]
    pub overrides: UserOverrides,
    #[serde(default)]
    pub extensions: UserExtensions,
    #[serde(default)]
    pub trusted_keys: HashMap<String, TrustedKeyInfo>,
    #[serde(default, alias = "undo")]
    pub rollback: RollbackSettings,
}

/// Metadata for user config
#[derive(Debug, Default, Deserialize)]
pub struct UserConfigMeta {
    #[serde(default)]
    pub version: u64,
}

/// User overrides (exceptions to default blocking)
#[derive(Debug, Default, Deserialize)]
pub struct UserOverrides {
    /// Overrides for sensitive paths
    /// Format: path = { reason = "...", acknowledged = "YYYY-MM-DD", access = "read" }
    #[serde(default)]
    pub sensitive_paths: HashMap<String, PathOverrideInfo>,

    /// Overrides for dangerous commands
    /// Format: command = { reason = "...", acknowledged = "YYYY-MM-DD" }
    #[serde(default)]
    pub commands: HashMap<String, CommandOverrideInfo>,
}

/// Override information for a sensitive path
#[derive(Debug, Clone, Deserialize)]
pub struct PathOverrideInfo {
    /// User-provided reason for the override
    pub reason: String,
    /// Date when user acknowledged the risk (required for override to be active)
    pub acknowledged: Option<String>,
    /// Access level: "read", "write", or "both" (default: "both")
    #[serde(default)]
    pub access: Option<String>,
}

/// Override information for a dangerous command
#[derive(Debug, Clone, Deserialize)]
pub struct CommandOverrideInfo {
    /// User-provided reason for the override
    pub reason: String,
    /// Date when user acknowledged the risk (required for override to be active)
    pub acknowledged: Option<String>,
}

/// User extensions (additions to blocklists)
#[derive(Debug, Default, Deserialize)]
pub struct UserExtensions {
    /// Additional sensitive paths to block
    #[serde(default)]
    pub sensitive_paths: HashMap<String, Vec<String>>,

    /// Additional dangerous commands to block
    #[serde(default)]
    pub dangerous_commands: HashMap<String, Vec<String>>,
}

/// Information about a trusted third-party signing key
#[derive(Debug, Clone, Deserialize)]
pub struct TrustedKeyInfo {
    /// Human-readable name for the key owner
    pub name: String,
    /// Key fingerprint for verification
    #[serde(default)]
    pub fingerprint: Option<String>,
}

/// Rollback system settings
#[derive(Debug, Clone, Deserialize)]
pub struct RollbackSettings {
    /// Maximum number of sessions to retain
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
    /// Maximum total storage in gigabytes
    #[serde(default = "default_max_storage_gb")]
    pub max_storage_gb: f64,
    /// Maximum snapshots per session
    #[serde(default = "default_max_snapshots")]
    pub max_snapshots: u32,
    /// Hours to keep stale sessions (ended is None, PID dead) before cleanup
    #[serde(default = "default_stale_grace_hours")]
    pub stale_grace_hours: u64,
}

fn default_max_sessions() -> usize {
    10
}
fn default_max_storage_gb() -> f64 {
    5.0
}
fn default_max_snapshots() -> u32 {
    100
}
fn default_stale_grace_hours() -> u64 {
    24
}

impl Default for RollbackSettings {
    fn default() -> Self {
        Self {
            max_sessions: default_max_sessions(),
            max_storage_gb: default_max_storage_gb(),
            max_snapshots: default_max_snapshots(),
            stale_grace_hours: default_stale_grace_hours(),
        }
    }
}

/// Load user configuration from ~/.config/nono/config.toml
///
/// Returns None if the config file doesn't exist.
/// Returns Err if the file exists but is malformed.
pub fn load_user_config() -> Result<Option<UserConfig>> {
    let config_path = user_config_path()?;

    if !config_path.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(&config_path).map_err(|e| NonoError::ConfigRead {
        path: config_path.clone(),
        source: e,
    })?;

    let config: UserConfig = toml::from_str(&content)
        .map_err(|e| NonoError::ConfigParse(format!("Failed to parse user config: {}", e)))?;

    Ok(Some(config))
}

/// Get the path to user config file
pub fn user_config_path() -> Result<PathBuf> {
    let config_dir = super::user_config_dir().ok_or_else(|| {
        NonoError::ConfigParse("Could not determine user config directory".to_string())
    })?;

    Ok(config_dir.join(USER_CONFIG_FILE))
}

/// Get the path to user profiles directory
pub fn user_profiles_dir() -> Result<PathBuf> {
    let config_dir = super::user_config_dir().ok_or_else(|| {
        NonoError::ConfigParse("Could not determine user config directory".to_string())
    })?;

    Ok(config_dir.join("profiles"))
}

/// Get the path to user trusted keys directory
pub fn user_trusted_keys_dir() -> Result<PathBuf> {
    let config_dir = super::user_config_dir().ok_or_else(|| {
        NonoError::ConfigParse("Could not determine user config directory".to_string())
    })?;

    Ok(config_dir.join("trusted-keys"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_user_config() {
        let toml = r#"
[meta]
version = 1

[overrides.sensitive_paths]
"~/.ssh/id_rsa.pub" = { reason = "Public key for git", acknowledged = "2025-01-15", access = "read" }

[overrides.commands]
pip = { reason = "Python development", acknowledged = "2025-01-15" }

[extensions.sensitive_paths]
custom = ["~/work/secrets"]

[extensions.dangerous_commands]
custom = ["my-dangerous-tool"]

[trusted_keys]
alice = { name = "Alice", fingerprint = "abc123" }
"#;

        let config: UserConfig = toml::from_str(toml).expect("Failed to parse");

        assert_eq!(config.meta.version, 1);

        // Check overrides
        assert!(config
            .overrides
            .sensitive_paths
            .contains_key("~/.ssh/id_rsa.pub"));
        let ssh_override = &config.overrides.sensitive_paths["~/.ssh/id_rsa.pub"];
        assert_eq!(ssh_override.reason, "Public key for git");
        assert_eq!(ssh_override.access.as_deref(), Some("read"));

        assert!(config.overrides.commands.contains_key("pip"));

        // Check extensions
        assert!(config.extensions.sensitive_paths.contains_key("custom"));
        assert!(config.extensions.dangerous_commands.contains_key("custom"));

        // Check trusted keys
        assert!(config.trusted_keys.contains_key("alice"));
    }

    #[test]
    fn test_empty_user_config() {
        let toml = "";
        let config: UserConfig = toml::from_str(toml).expect("Failed to parse empty config");

        assert!(config.overrides.sensitive_paths.is_empty());
        assert!(config.overrides.commands.is_empty());
    }

    #[test]
    fn test_rollback_settings_defaults() {
        let toml = "";
        let config: UserConfig = toml::from_str(toml).expect("Failed to parse");
        assert_eq!(config.rollback.max_sessions, 10);
        assert!((config.rollback.max_storage_gb - 5.0).abs() < f64::EPSILON);
        assert_eq!(config.rollback.max_snapshots, 100);
        assert_eq!(config.rollback.stale_grace_hours, 24);
    }

    #[test]
    fn test_rollback_settings_custom() {
        let toml = r#"
[rollback]
max_sessions = 20
max_storage_gb = 10.0
max_snapshots = 50
stale_grace_hours = 48
"#;
        let config: UserConfig = toml::from_str(toml).expect("Failed to parse");
        assert_eq!(config.rollback.max_sessions, 20);
        assert!((config.rollback.max_storage_gb - 10.0).abs() < f64::EPSILON);
        assert_eq!(config.rollback.max_snapshots, 50);
        assert_eq!(config.rollback.stale_grace_hours, 48);
    }
}
