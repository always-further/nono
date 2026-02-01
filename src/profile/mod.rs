//! Profile system for pre-configured capability sets
//!
//! Profiles provide named configurations for common applications like
//! claude-code, openclaw, and opencode. They can be built-in (compiled
//! into the binary) or user-defined (in ~/.config/nono/profiles/).

mod builtin;

use crate::error::{NonoError, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Profile metadata
#[derive(Debug, Clone, Default, Deserialize)]
#[allow(dead_code)]
pub struct ProfileMeta {
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
    /// Minisign signature (Phase 2)
    #[serde(default)]
    pub signature: Option<String>,
}

/// Filesystem configuration in a profile
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FilesystemConfig {
    /// Directories with read+write access
    #[serde(default)]
    pub allow: Vec<String>,
    /// Directories with read-only access
    #[serde(default)]
    pub read: Vec<String>,
    /// Directories with write-only access
    #[serde(default)]
    pub write: Vec<String>,
    /// Single files with read+write access
    #[serde(default)]
    pub allow_file: Vec<String>,
    /// Single files with read-only access
    #[serde(default)]
    pub read_file: Vec<String>,
    /// Single files with write-only access
    #[serde(default)]
    pub write_file: Vec<String>,
}

/// Network configuration in a profile
#[derive(Debug, Clone, Default, Deserialize)]
pub struct NetworkConfig {
    /// Block network access (network allowed by default; true = blocked)
    #[serde(default)]
    pub block: bool,
    // Future: dns_only, proxy_allow
}

/// Secrets configuration in a profile
///
/// Maps keystore account names to environment variable names.
/// Secrets are loaded from the system keystore (macOS Keychain / Linux Secret Service)
/// under the service name "nono".
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SecretsConfig {
    /// Map of keystore account name -> environment variable name
    /// Example: { "openai_api_key" = "OPENAI_API_KEY" }
    #[serde(flatten)]
    pub mappings: HashMap<String, String>,
}

/// A complete profile definition
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Profile {
    #[serde(default)]
    pub meta: ProfileMeta,
    #[serde(default)]
    pub filesystem: FilesystemConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub secrets: SecretsConfig,
}

impl Profile {
    /// Check if this profile has a signature
    pub fn is_signed(&self) -> bool {
        self.meta.signature.is_some()
    }
}

/// Load a profile by name
///
/// Loading precedence:
/// 1. User profiles from ~/.config/nono/profiles/<name>.toml (allows customization)
/// 2. Built-in profiles (compiled into binary, fallback)
///
/// User profiles require --trust-unsigned unless signed (Phase 2).
pub fn load_profile(name: &str, trust_unsigned: bool) -> Result<Profile> {
    // Validate profile name (alphanumeric + hyphen only)
    if !is_valid_profile_name(name) {
        return Err(NonoError::ProfileParse(format!(
            "Invalid profile name '{}': must be alphanumeric with hyphens only",
            name
        )));
    }

    // 1. Check user profiles first (allows overriding built-ins)
    let profile_path = get_user_profile_path(name)?;
    if profile_path.exists() {
        tracing::info!("Loading user profile from: {}", profile_path.display());
        let profile = load_from_file(&profile_path)?;

        // Require --trust-unsigned for unsigned user profiles
        if !profile.is_signed() && !trust_unsigned {
            return Err(NonoError::UnsignedProfile(name.to_string()));
        }

        return Ok(profile);
    }

    // 2. Fall back to built-in profiles
    if let Some(profile) = builtin::get_builtin(name) {
        tracing::info!("Using built-in profile: {}", name);
        return Ok(profile);
    }

    Err(NonoError::ProfileNotFound(name.to_string()))
}

/// Load a profile from a TOML file
fn load_from_file(path: &Path) -> Result<Profile> {
    let content = fs::read_to_string(path).map_err(|e| NonoError::ProfileRead {
        path: path.to_path_buf(),
        source: e,
    })?;

    toml::from_str(&content).map_err(|e| NonoError::ProfileParse(e.to_string()))
}

/// Get the path to a user profile
fn get_user_profile_path(name: &str) -> Result<PathBuf> {
    let config_dir = match std::env::var("XDG_CONFIG_HOME") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => home_dir()?.join(".config"),
    };

    Ok(config_dir
        .join("nono")
        .join("profiles")
        .join(format!("{}.toml", name)))
}

/// Get home directory path using xdg-home
fn home_dir() -> Result<PathBuf> {
    xdg_home::home_dir().ok_or(NonoError::HomeNotFound)
}

/// Validate profile name (alphanumeric + hyphen only, no path traversal)
fn is_valid_profile_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

/// Expand environment variables in a path string
///
/// Supported variables:
/// - $WORKDIR: Working directory (--workdir or cwd)
/// - $HOME: User's home directory
/// - $XDG_CONFIG_HOME: XDG config directory
/// - $XDG_DATA_HOME: XDG data directory
///
/// If $HOME cannot be determined and the path uses $HOME, $XDG_CONFIG_HOME, or $XDG_DATA_HOME,
/// the unexpanded variable is left in place (which will cause the path to not exist).
pub fn expand_vars(path: &str, workdir: &Path) -> PathBuf {
    let home = xdg_home::home_dir().map(|p| p.to_string_lossy().to_string());

    let expanded = path.replace("$WORKDIR", &workdir.to_string_lossy());

    let expanded = if let Some(ref h) = home {
        let xdg_config = std::env::var("XDG_CONFIG_HOME")
            .unwrap_or_else(|_| format!("{}", PathBuf::from(h).join(".config").display()));
        let xdg_data = std::env::var("XDG_DATA_HOME").unwrap_or_else(|_| {
            format!(
                "{}",
                PathBuf::from(h).join(".local").join("share").display()
            )
        });

        expanded
            .replace("$HOME", h)
            .replace("$XDG_CONFIG_HOME", &xdg_config)
            .replace("$XDG_DATA_HOME", &xdg_data)
    } else {
        // If home is not available, leave $HOME variables unexpanded
        // This will cause the path to not exist, which is handled gracefully
        tracing::warn!("Could not determine home directory for variable expansion");
        expanded
    };

    PathBuf::from(expanded)
}

/// List available profiles (built-in + user)
#[allow(dead_code)]
pub fn list_profiles() -> Vec<String> {
    let mut profiles = builtin::list_builtin();

    // Add user profiles (if home directory is available)
    if let Ok(profile_path) = get_user_profile_path("") {
        if let Some(dir) = profile_path.parent() {
            if dir.exists() {
                if let Ok(entries) = fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        if let Some(name) = entry.path().file_stem() {
                            let name_str = name.to_string_lossy().to_string();
                            if !profiles.contains(&name_str) {
                                profiles.push(name_str);
                            }
                        }
                    }
                }
            }
        }
    }

    profiles.sort();
    profiles
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_valid_profile_names() {
        assert!(is_valid_profile_name("claude-code"));
        assert!(is_valid_profile_name("openclaw"));
        assert!(is_valid_profile_name("my-app-2"));
        assert!(!is_valid_profile_name(""));
        assert!(!is_valid_profile_name("-invalid"));
        assert!(!is_valid_profile_name("invalid-"));
        assert!(!is_valid_profile_name("../escape"));
        assert!(!is_valid_profile_name("path/traversal"));
    }

    #[test]
    fn test_expand_vars() {
        let workdir = PathBuf::from("/projects/myapp");
        env::set_var("HOME", "/home/user");

        let expanded = expand_vars("$WORKDIR/src", &workdir);
        assert_eq!(expanded, PathBuf::from("/projects/myapp/src"));

        let expanded = expand_vars("$HOME/.config", &workdir);
        assert_eq!(expanded, PathBuf::from("/home/user/.config"));
    }

    #[test]
    fn test_load_builtin_profile() {
        let profile = load_profile("claude-code", false).unwrap();
        assert_eq!(profile.meta.name, "claude-code");
        assert!(!profile.network.block); // network allowed by default
    }

    #[test]
    fn test_load_nonexistent_profile() {
        let result = load_profile("nonexistent-profile-12345", false);
        assert!(matches!(result, Err(NonoError::ProfileNotFound(_))));
    }

    #[test]
    fn test_list_profiles() {
        let profiles = list_profiles();
        assert!(profiles.contains(&"claude-code".to_string()));
        assert!(profiles.contains(&"openclaw".to_string()));
        assert!(profiles.contains(&"opencode".to_string()));
    }

    #[test]
    fn test_secrets_config_parsing() {
        let toml_str = r#"
            [meta]
            name = "test-profile"

            [secrets]
            openai_api_key = "OPENAI_API_KEY"
            anthropic_api_key = "ANTHROPIC_API_KEY"
        "#;

        let profile: Profile = toml::from_str(toml_str).unwrap();
        assert_eq!(profile.secrets.mappings.len(), 2);
        assert_eq!(
            profile.secrets.mappings.get("openai_api_key"),
            Some(&"OPENAI_API_KEY".to_string())
        );
        assert_eq!(
            profile.secrets.mappings.get("anthropic_api_key"),
            Some(&"ANTHROPIC_API_KEY".to_string())
        );
    }

    #[test]
    fn test_empty_secrets_config() {
        let toml_str = r#"
            [meta]
            name = "test-profile"
        "#;

        let profile: Profile = toml::from_str(toml_str).unwrap();
        assert!(profile.secrets.mappings.is_empty());
    }
}
