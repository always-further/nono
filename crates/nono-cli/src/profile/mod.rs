//! Profile system for pre-configured capability sets
//!
//! Profiles provide named configurations for common applications like
//! claude-code, openclaw, and opencode. They can be built-in (compiled
//! into the binary) or user-defined (in ~/.config/nono/profiles/).

mod builtin;

use nono::{NonoError, Result};
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

/// Custom credential route definition for reverse proxy.
///
/// Allows users to define their own credential services in profiles,
/// enabling `--proxy-credential` to work with any API without requiring
/// changes to the built-in `network-policy.json`.
#[derive(Debug, Clone, Deserialize)]
pub struct CustomCredentialDef {
    /// Upstream URL to proxy requests to (e.g., "https://api.telegram.org")
    pub upstream: String,
    /// Keystore account name for the credential (e.g., "telegram_bot_token")
    pub credential_key: String,
    /// HTTP header to inject the credential into (default: "Authorization")
    #[serde(default = "default_inject_header")]
    pub inject_header: String,
    /// Format string for the credential value (default: "Bearer {}")
    /// Use {} as placeholder for the credential value.
    #[serde(default = "default_credential_format")]
    pub credential_format: String,
}

fn default_inject_header() -> String {
    "Authorization".to_string()
}

fn default_credential_format() -> String {
    "Bearer {}".to_string()
}

/// Check if a character is a valid HTTP token character per RFC 7230.
fn is_http_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '!' | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '.'
                | '^'
                | '_'
                | '`'
                | '|'
                | '~'
        )
}

/// Validate a custom credential definition for security issues.
///
/// Checks:
/// - `inject_header` must be a valid HTTP token (RFC 7230)
/// - `credential_format` must not contain CRLF sequences
/// - `credential_key` must be alphanumeric + underscores only
/// - `upstream` must be HTTPS (or HTTP for loopback only)
fn validate_custom_credential(name: &str, cred: &CustomCredentialDef) -> Result<()> {
    // Validate inject_header (RFC 7230 token)
    if cred.inject_header.is_empty() {
        return Err(NonoError::ProfileParse(format!(
            "inject_header for custom credential '{}' cannot be empty",
            name
        )));
    }
    if !cred.inject_header.chars().all(is_http_token_char) {
        return Err(NonoError::ProfileParse(format!(
            "inject_header '{}' for custom credential '{}' contains invalid characters; \
             header names must be valid HTTP tokens (alphanumeric and !#$%&'*+-.^_`|~)",
            cred.inject_header, name
        )));
    }

    // Validate credential_format (no CRLF injection)
    if cred.credential_format.contains('\r') || cred.credential_format.contains('\n') {
        return Err(NonoError::ProfileParse(format!(
            "credential_format for custom credential '{}' contains invalid CRLF characters; \
             this could enable header injection attacks",
            name
        )));
    }

    // Validate credential_key (alphanumeric + underscore)
    if cred.credential_key.is_empty() {
        return Err(NonoError::ProfileParse(format!(
            "credential_key for custom credential '{}' cannot be empty",
            name
        )));
    }
    if !cred
        .credential_key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(NonoError::ProfileParse(format!(
            "credential_key '{}' for custom credential '{}' must contain only \
             alphanumeric characters and underscores",
            cred.credential_key, name
        )));
    }

    // Validate upstream URL (HTTPS required, HTTP only for loopback)
    validate_upstream_url(&cred.upstream, name)?;

    Ok(())
}

/// Validate an upstream URL for security.
///
/// HTTP is only allowed for loopback addresses:
/// - `localhost` (hostname)
/// - `127.0.0.0/8` (IPv4 loopback range)
/// - `::1` (IPv6 loopback)
/// - `0.0.0.0` (unspecified IPv4, binds to all interfaces)
/// - `::` (unspecified IPv6)
fn validate_upstream_url(url: &str, service_name: &str) -> Result<()> {
    let parsed = url::Url::parse(url).map_err(|e| {
        NonoError::ProfileParse(format!(
            "Invalid upstream URL for custom credential '{}': {}",
            service_name, e
        ))
    })?;

    match parsed.scheme() {
        "https" => Ok(()),
        "http" => {
            // For IPv6 addresses, url::Url returns the address in host()
            // but host_str() may include brackets. We need to handle both cases.
            let is_loopback = match parsed.host() {
                Some(url::Host::Ipv4(ip)) => ip.is_loopback() || ip.is_unspecified(),
                Some(url::Host::Ipv6(ip)) => ip.is_loopback() || ip.is_unspecified(),
                Some(url::Host::Domain(domain)) => domain == "localhost",
                None => false,
            };

            if is_loopback {
                Ok(())
            } else {
                Err(NonoError::ProfileParse(format!(
                    "Upstream URL for custom credential '{}' must use HTTPS \
                     (HTTP only allowed for loopback addresses): {}",
                    service_name, url
                )))
            }
        }
        scheme => Err(NonoError::ProfileParse(format!(
            "Upstream URL for custom credential '{}' must use HTTPS, got scheme '{}': {}",
            service_name, scheme, url
        ))),
    }
}

/// Validate all custom credentials in a profile.
fn validate_profile_custom_credentials(profile: &Profile) -> Result<()> {
    for (name, cred) in &profile.network.custom_credentials {
        validate_custom_credential(name, cred)?;
    }
    Ok(())
}

/// Network configuration in a profile
#[derive(Debug, Clone, Default, Deserialize)]
pub struct NetworkConfig {
    /// Block network access (network allowed by default; true = blocked)
    #[serde(default)]
    pub block: bool,
    /// Network proxy profile name (from network-policy.json).
    /// When set, outbound traffic is filtered through the proxy.
    #[serde(default)]
    pub network_profile: Option<String>,
    /// Additional hosts to allow through the proxy (on top of profile hosts)
    #[serde(default)]
    pub proxy_allow: Vec<String>,
    /// Credential services to enable via reverse proxy
    #[serde(default)]
    pub proxy_credentials: Vec<String>,
    /// Custom credential definitions for services not in network-policy.json.
    /// Keys are service names (used with --proxy-credential), values define
    /// how to route and inject credentials for that service.
    #[serde(default)]
    pub custom_credentials: HashMap<String, CustomCredentialDef>,
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

/// Hook configuration for an agent
///
/// Defines hooks that nono will install for the target application.
/// For example, Claude Code hooks are installed to ~/.claude/hooks/
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HookConfig {
    /// Event that triggers the hook (e.g., "PostToolUseFailure")
    pub event: String,
    /// Regex pattern to match tool names (e.g., "Read|Write|Edit|Bash")
    pub matcher: String,
    /// Script filename from data/hooks/ to install
    pub script: String,
}

/// Hooks configuration in a profile
///
/// Maps target application names to their hook configurations.
/// Example: [hooks.claude-code] for Claude Code hooks
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HooksConfig {
    /// Map of target application -> hook configuration
    #[serde(flatten)]
    pub hooks: HashMap<String, HookConfig>,
}

/// Working directory access level for profiles
///
/// Controls whether and how the current working directory is automatically
/// shared with the sandboxed process. This is profile-driven so each
/// application can declare its own CWD requirements.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkdirAccess {
    /// No automatic CWD access
    #[default]
    None,
    /// Read-only access to CWD
    Read,
    /// Write-only access to CWD
    Write,
    /// Full read+write access to CWD
    ReadWrite,
}

/// Working directory configuration in a profile
#[derive(Debug, Clone, Default, Deserialize)]
pub struct WorkdirConfig {
    /// Access level for the current working directory
    #[serde(default)]
    pub access: WorkdirAccess,
}

/// Security configuration referencing policy.json groups
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SecurityConfig {
    /// Policy group names to resolve (from policy.json)
    #[serde(default)]
    pub groups: Vec<String>,
    /// Base groups to exclude for this profile (overrides base policy).
    /// Populated during deserialization; read by `ProfileDef::to_profile()` in the
    /// policy resolver. Will also be consumed by `--trust-group` CLI flag handling.
    #[serde(default)]
    #[allow(dead_code)]
    pub trust_groups: Vec<String>,
}

/// Rollback snapshot configuration in a profile
///
/// Controls which files are excluded from rollback snapshots. Patterns are
/// matched against path components (exact match) or, if they contain `/`,
/// as substrings of the full path. Glob patterns are matched against
/// the filename (last path component).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RollbackConfig {
    /// Patterns to exclude from rollback snapshots.
    /// Added on top of the CLI's base exclusion list.
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
    /// Glob patterns to exclude from rollback snapshots.
    /// Matched against the filename using standard glob syntax.
    #[serde(default)]
    pub exclude_globs: Vec<String>,
}

/// A complete profile definition
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Profile {
    #[serde(default)]
    pub meta: ProfileMeta,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub filesystem: FilesystemConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default, alias = "secrets")]
    pub env_credentials: SecretsConfig,
    #[serde(default)]
    pub workdir: WorkdirConfig,
    #[serde(default)]
    pub hooks: HooksConfig,
    #[serde(default, alias = "undo")]
    pub rollback: RollbackConfig,
    /// App has interactive UI that needs TTY preserved (implies --exec mode)
    #[serde(default)]
    pub interactive: bool,
}

/// Load a profile by name or file path
///
/// If `name_or_path` contains a path separator or ends with `.json`, it is
/// treated as a direct file path. Otherwise it is resolved as a profile name.
///
/// Name loading precedence:
/// 1. User profiles from ~/.config/nono/profiles/<name>.json (allows customization)
/// 2. Built-in profiles (compiled into binary, fallback)
pub fn load_profile(name_or_path: &str) -> Result<Profile> {
    // Direct file path: contains separator or ends with .json
    if name_or_path.contains('/') || name_or_path.ends_with(".json") {
        return load_profile_from_path(Path::new(name_or_path));
    }

    // Validate profile name (alphanumeric + hyphen only)
    if !is_valid_profile_name(name_or_path) {
        return Err(NonoError::ProfileParse(format!(
            "Invalid profile name '{}': must be alphanumeric with hyphens only",
            name_or_path
        )));
    }

    // 1. Check user profiles first (allows overriding built-ins)
    let profile_path = get_user_profile_path(name_or_path)?;
    if profile_path.exists() {
        tracing::info!("Loading user profile from: {}", profile_path.display());
        let mut profile = load_from_file(&profile_path)?;
        merge_base_groups(&mut profile)?;
        return Ok(profile);
    }

    // 2. Fall back to built-in profiles
    if let Some(profile) = builtin::get_builtin(name_or_path) {
        tracing::info!("Using built-in profile: {}", name_or_path);
        return Ok(profile);
    }

    Err(NonoError::ProfileNotFound(name_or_path.to_string()))
}

/// Load a profile from a direct file path.
///
/// The path must exist and point to a valid JSON profile file.
/// Base groups are merged automatically.
pub fn load_profile_from_path(path: &Path) -> Result<Profile> {
    if !path.exists() {
        return Err(NonoError::ProfileRead {
            path: path.to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "profile file not found"),
        });
    }

    tracing::info!("Loading profile from path: {}", path.display());
    let mut profile = load_from_file(path)?;
    merge_base_groups(&mut profile)?;
    Ok(profile)
}

/// Merge base_groups from policy.json into a user profile.
///
/// User profiles loaded from file only declare their own groups in
/// `security.groups`. Built-in profiles get base_groups merged by
/// `ProfileDef::to_profile()`, but user profiles bypass that path.
/// This function applies the same merge: `(base_groups - trust_groups) + profile.groups`.
fn merge_base_groups(profile: &mut Profile) -> Result<()> {
    let policy = crate::policy::load_embedded_policy()?;
    crate::policy::validate_trust_groups(&policy, &profile.security.trust_groups)?;

    let base = policy.base_groups;
    let mut merged: Vec<String> = base
        .into_iter()
        .filter(|g| !profile.security.trust_groups.contains(g))
        .collect();
    // Append profile-specific groups (avoiding duplicates)
    let mut seen: std::collections::HashSet<String> = merged.iter().cloned().collect();
    for g in &profile.security.groups {
        if seen.insert(g.clone()) {
            merged.push(g.clone());
        }
    }
    profile.security.groups = merged;
    Ok(())
}

/// Load a profile from a JSON file
fn load_from_file(path: &Path) -> Result<Profile> {
    let content = fs::read_to_string(path).map_err(|e| NonoError::ProfileRead {
        path: path.to_path_buf(),
        source: e,
    })?;

    let profile: Profile =
        serde_json::from_str(&content).map_err(|e| NonoError::ProfileParse(e.to_string()))?;

    // Validate custom credentials for security issues
    validate_profile_custom_credentials(&profile)?;

    Ok(profile)
}

/// Get the path to a user profile
fn get_user_profile_path(name: &str) -> Result<PathBuf> {
    let config_dir = resolve_user_config_dir()?;

    Ok(config_dir
        .join("nono")
        .join("profiles")
        .join(format!("{}.json", name)))
}

/// Resolve the user config directory with secure validation.
///
/// Security behavior:
/// - If `XDG_CONFIG_HOME` is set, it must be absolute.
/// - If absolute, we canonicalize it to avoid path confusion through symlinks.
/// - If invalid (relative or cannot be canonicalized), we fall back to `$HOME/.config`.
fn resolve_user_config_dir() -> Result<PathBuf> {
    if let Ok(raw) = std::env::var("XDG_CONFIG_HOME") {
        let path = PathBuf::from(&raw);
        if path.is_absolute() {
            match path.canonicalize() {
                Ok(canonical) => return Ok(canonical),
                Err(e) => {
                    tracing::warn!(
                        "Ignoring invalid XDG_CONFIG_HOME='{}' (canonicalize failed: {}), falling back to $HOME/.config",
                        raw,
                        e
                    );
                }
            }
        } else {
            tracing::warn!(
                "Ignoring invalid XDG_CONFIG_HOME='{}' (must be absolute), falling back to $HOME/.config",
                raw
            );
        }
    }

    // Fallback: use HOME/.config. Canonicalize HOME when possible, but do not
    // fail hard if HOME currently points to a non-existent path.
    let home = home_dir()?;
    let home_base = match home.canonicalize() {
        Ok(canonical) => canonical,
        Err(e) => {
            tracing::warn!(
                "Failed to canonicalize HOME='{}' ({}), using raw HOME path for fallback",
                home.display(),
                e
            );
            home
        }
    };
    Ok(home_base.join(".config"))
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
/// - $TMPDIR: System temporary directory
/// - $UID: Current user ID
///
/// If $HOME cannot be determined and the path uses $HOME, $XDG_CONFIG_HOME, or $XDG_DATA_HOME,
/// the unexpanded variable is left in place (which will cause the path to not exist).
pub fn expand_vars(path: &str, workdir: &Path) -> Result<PathBuf> {
    use crate::config;

    let home = config::validated_home()?;

    let expanded = path.replace("$WORKDIR", &workdir.to_string_lossy());

    // Expand $TMPDIR and $UID
    let tmpdir = config::validated_tmpdir()?;
    let uid = nix::unistd::getuid().to_string();
    let expanded = expanded
        .replace("$TMPDIR", tmpdir.trim_end_matches('/'))
        .replace("$UID", &uid);

    let xdg_config = std::env::var("XDG_CONFIG_HOME")
        .unwrap_or_else(|_| format!("{}", PathBuf::from(&home).join(".config").display()));
    let xdg_data = std::env::var("XDG_DATA_HOME").unwrap_or_else(|_| {
        format!(
            "{}",
            PathBuf::from(&home).join(".local").join("share").display()
        )
    });

    // Validate XDG paths are absolute
    if !Path::new(&xdg_config).is_absolute() {
        return Err(NonoError::EnvVarValidation {
            var: "XDG_CONFIG_HOME".to_string(),
            reason: format!("must be an absolute path, got: {}", xdg_config),
        });
    }
    if !Path::new(&xdg_data).is_absolute() {
        return Err(NonoError::EnvVarValidation {
            var: "XDG_DATA_HOME".to_string(),
            reason: format!("must be an absolute path, got: {}", xdg_data),
        });
    }

    let expanded = expanded
        .replace("$HOME", &home)
        .replace("$XDG_CONFIG_HOME", &xdg_config)
        .replace("$XDG_DATA_HOME", &xdg_data);

    Ok(PathBuf::from(expanded))
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
    use tempfile::tempdir;

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
        // Save original HOME to restore after test (avoid polluting other parallel tests)
        let original_home = env::var("HOME").ok();

        let workdir = PathBuf::from("/projects/myapp");
        env::set_var("HOME", "/home/user");

        let expanded = expand_vars("$WORKDIR/src", &workdir).expect("valid env");
        assert_eq!(expanded, PathBuf::from("/projects/myapp/src"));

        let expanded = expand_vars("$HOME/.config", &workdir).expect("valid env");
        assert_eq!(expanded, PathBuf::from("/home/user/.config"));

        // Restore original HOME
        if let Some(home) = original_home {
            env::set_var("HOME", home);
        }
    }

    #[test]
    fn test_resolve_user_config_dir_uses_valid_absolute_xdg() {
        let tmp = tempdir().expect("tmpdir");
        env::set_var("XDG_CONFIG_HOME", tmp.path());
        let resolved = resolve_user_config_dir().expect("resolve user config dir");
        assert_eq!(
            resolved,
            tmp.path().canonicalize().expect("canonicalize tmp")
        );
        env::remove_var("XDG_CONFIG_HOME");
    }

    #[test]
    fn test_resolve_user_config_dir_falls_back_on_relative_xdg() {
        let expected_home = home_dir().expect("home dir");
        env::set_var("XDG_CONFIG_HOME", "relative/path");

        let resolved = resolve_user_config_dir().expect("resolve with fallback");
        assert_eq!(resolved, expected_home.join(".config"));

        env::remove_var("XDG_CONFIG_HOME");
    }

    #[test]
    fn test_load_builtin_profile() {
        let profile = load_profile("claude-code").expect("Failed to load profile");
        assert_eq!(profile.meta.name, "claude-code");
        assert!(!profile.network.block); // network allowed by default
    }

    #[test]
    fn test_load_nonexistent_profile() {
        let result = load_profile("nonexistent-profile-12345");
        assert!(matches!(result, Err(NonoError::ProfileNotFound(_))));
    }

    #[test]
    fn test_load_profile_from_file_path() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("custom.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "custom-test" },
                "security": { "groups": ["node_runtime"] },
                "network": { "block": true }
            }"#,
        )
        .expect("write profile");

        let profile =
            load_profile(profile_path.to_str().expect("valid utf8")).expect("load from path");
        assert_eq!(profile.meta.name, "custom-test");
        assert!(profile.network.block);
        // base_groups should be merged in
        assert!(profile
            .security
            .groups
            .contains(&"deny_credentials".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"node_runtime".to_string()));
    }

    #[test]
    fn test_load_profile_from_nonexistent_path() {
        let result = load_profile("/tmp/does-not-exist-nono-test.json");
        assert!(result.is_err());
    }

    #[test]
    fn test_list_profiles() {
        let profiles = list_profiles();
        assert!(profiles.contains(&"claude-code".to_string()));
        assert!(profiles.contains(&"openclaw".to_string()));
        assert!(profiles.contains(&"opencode".to_string()));
    }

    #[test]
    fn test_env_credentials_config_parsing() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "env_credentials": {
                "openai_api_key": "OPENAI_API_KEY",
                "anthropic_api_key": "ANTHROPIC_API_KEY"
            }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert_eq!(profile.env_credentials.mappings.len(), 2);
        assert_eq!(
            profile.env_credentials.mappings.get("openai_api_key"),
            Some(&"OPENAI_API_KEY".to_string())
        );
        assert_eq!(
            profile.env_credentials.mappings.get("anthropic_api_key"),
            Some(&"ANTHROPIC_API_KEY".to_string())
        );
    }

    #[test]
    fn test_secrets_alias_backward_compat() {
        // "secrets" should still work as an alias for "env_credentials"
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "secrets": {
                "openai_api_key": "OPENAI_API_KEY"
            }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert_eq!(profile.env_credentials.mappings.len(), 1);
        assert_eq!(
            profile.env_credentials.mappings.get("openai_api_key"),
            Some(&"OPENAI_API_KEY".to_string())
        );
    }

    #[test]
    fn test_empty_env_credentials_config() {
        let json_str = r#"{ "meta": { "name": "test-profile" } }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert!(profile.env_credentials.mappings.is_empty());
    }

    #[test]
    fn test_merge_base_groups_into_user_profile() {
        let mut profile = Profile {
            security: SecurityConfig {
                groups: vec!["node_runtime".to_string()],
                trust_groups: vec![],
            },
            ..Default::default()
        };

        merge_base_groups(&mut profile).expect("merge should succeed");

        // Should contain base groups
        assert!(
            profile
                .security
                .groups
                .contains(&"deny_credentials".to_string()),
            "Expected base group 'deny_credentials'"
        );
        assert!(
            profile
                .security
                .groups
                .contains(&"system_read_macos".to_string())
                || profile
                    .security
                    .groups
                    .contains(&"system_read_linux".to_string()),
            "Expected platform system_read group"
        );

        // Should still contain the profile's own group
        assert!(
            profile
                .security
                .groups
                .contains(&"node_runtime".to_string()),
            "Expected profile group 'node_runtime'"
        );

        // No duplicates
        let unique: std::collections::HashSet<_> = profile.security.groups.iter().collect();
        assert_eq!(
            unique.len(),
            profile.security.groups.len(),
            "Groups should have no duplicates"
        );
    }

    #[test]
    fn test_merge_base_groups_respects_trust_groups() {
        let mut profile = Profile {
            security: SecurityConfig {
                groups: vec!["node_runtime".to_string()],
                trust_groups: vec!["dangerous_commands".to_string()],
            },
            ..Default::default()
        };

        merge_base_groups(&mut profile).expect("merge should succeed");

        // trust_groups should be excluded
        assert!(
            !profile
                .security
                .groups
                .contains(&"dangerous_commands".to_string()),
            "trusted group 'dangerous_commands' should be excluded"
        );
    }

    #[test]
    fn test_merge_base_groups_rejects_required_trust_group() {
        let mut profile = Profile {
            security: SecurityConfig {
                groups: vec![],
                trust_groups: vec!["deny_credentials".to_string()],
            },
            ..Default::default()
        };

        let result = merge_base_groups(&mut profile);
        assert!(
            result.is_err(),
            "Trusting a required group must be rejected"
        );
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("deny_credentials"),
            "Error should name the required group"
        );
    }

    #[test]
    fn test_workdir_config_readwrite() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "workdir": { "access": "readwrite" }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert_eq!(profile.workdir.access, WorkdirAccess::ReadWrite);
    }

    #[test]
    fn test_workdir_config_read() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "workdir": { "access": "read" }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert_eq!(profile.workdir.access, WorkdirAccess::Read);
    }

    #[test]
    fn test_workdir_config_none() {
        let json_str = r#"{
            "meta": { "name": "test-profile" },
            "workdir": { "access": "none" }
        }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert_eq!(profile.workdir.access, WorkdirAccess::None);
    }

    #[test]
    fn test_workdir_config_default() {
        let json_str = r#"{ "meta": { "name": "test-profile" } }"#;

        let profile: Profile = serde_json::from_str(json_str).expect("Failed to parse profile");
        assert_eq!(profile.workdir.access, WorkdirAccess::None);
    }

    // ============================================================================
    // is_http_token_char tests (RFC 7230)
    // ============================================================================

    #[test]
    fn test_http_token_char_alphanumeric() {
        assert!(is_http_token_char('a'));
        assert!(is_http_token_char('Z'));
        assert!(is_http_token_char('0'));
        assert!(is_http_token_char('9'));
    }

    #[test]
    fn test_http_token_char_special_chars() {
        // RFC 7230 tchar: !#$%&'*+-.^_`|~
        for c in "!#$%&'*+-.^_`|~".chars() {
            assert!(is_http_token_char(c), "Expected '{}' to be valid tchar", c);
        }
    }

    #[test]
    fn test_http_token_char_rejects_invalid() {
        // Control chars, space, colon, parentheses should be rejected
        assert!(!is_http_token_char(' '));
        assert!(!is_http_token_char(':'));
        assert!(!is_http_token_char('('));
        assert!(!is_http_token_char(')'));
        assert!(!is_http_token_char('\r'));
        assert!(!is_http_token_char('\n'));
    }

    // ============================================================================
    // Custom credential validation integration tests
    //
    // These test the full validation chain including:
    // - inject_header (RFC 7230 token validation)
    // - credential_format (CRLF injection prevention)
    // - credential_key (alphanumeric + underscore)
    // - upstream URL (HTTPS required, HTTP only for loopback)
    // ============================================================================

    #[test]
    fn test_validate_custom_credential_valid() {
        let cred = CustomCredentialDef {
            upstream: "https://api.example.com".to_string(),
            credential_key: "api_key".to_string(),
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
        };
        assert!(validate_custom_credential("test", &cred).is_ok());
    }

    #[test]
    fn test_validate_custom_credential_http_loopback_allowed() {
        let cred = CustomCredentialDef {
            upstream: "http://127.0.0.1:8080/api".to_string(),
            credential_key: "local_key".to_string(),
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
        };
        assert!(validate_custom_credential("local", &cred).is_ok());
    }

    #[test]
    fn test_validate_custom_credential_http_remote_rejected() {
        let cred = CustomCredentialDef {
            upstream: "http://api.example.com".to_string(),
            credential_key: "api_key".to_string(),
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
        };
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("HTTP to remote should be rejected");
        assert!(err.to_string().contains("HTTPS"));
    }

    #[test]
    fn test_validate_custom_credential_invalid_header_rejected() {
        let cred = CustomCredentialDef {
            upstream: "https://api.example.com".to_string(),
            credential_key: "api_key".to_string(),
            inject_header: "X-Header\r\nEvil: injected".to_string(),
            credential_format: "Bearer {}".to_string(),
        };
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("CRLF in header should be rejected");
        assert!(err.to_string().contains("invalid characters"));
    }

    #[test]
    fn test_validate_custom_credential_invalid_format_rejected() {
        let cred = CustomCredentialDef {
            upstream: "https://api.example.com".to_string(),
            credential_key: "api_key".to_string(),
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}\r\nEvil: header".to_string(),
        };
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("CRLF in format should be rejected");
        assert!(err.to_string().contains("CRLF"));
    }

    #[test]
    fn test_validate_custom_credential_invalid_key_rejected() {
        let cred = CustomCredentialDef {
            upstream: "https://api.example.com".to_string(),
            credential_key: "api-key".to_string(), // hyphens not allowed
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
        };
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("hyphen in key should be rejected");
        assert!(err.to_string().contains("alphanumeric"));
    }

    #[test]
    fn test_validate_custom_credential_empty_header_rejected() {
        let cred = CustomCredentialDef {
            upstream: "https://api.example.com".to_string(),
            credential_key: "api_key".to_string(),
            inject_header: "".to_string(),
            credential_format: "Bearer {}".to_string(),
        };
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("empty header should be rejected");
        assert!(err.to_string().contains("cannot be empty"));
    }

    #[test]
    fn test_validate_custom_credential_header_with_space_rejected() {
        let cred = CustomCredentialDef {
            upstream: "https://api.example.com".to_string(),
            credential_key: "api_key".to_string(),
            inject_header: "X Header".to_string(),
            credential_format: "Bearer {}".to_string(),
        };
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("space in header should be rejected");
        assert!(err.to_string().contains("invalid characters"));
    }

    #[test]
    fn test_validate_custom_credential_header_with_colon_rejected() {
        let cred = CustomCredentialDef {
            upstream: "https://api.example.com".to_string(),
            credential_key: "api_key".to_string(),
            inject_header: "X-Header:".to_string(),
            credential_format: "Bearer {}".to_string(),
        };
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("colon in header should be rejected");
        assert!(err.to_string().contains("invalid characters"));
    }

    #[test]
    fn test_validate_custom_credential_valid_special_header_chars() {
        // RFC 7230 tchar special chars should be allowed in header names
        let cred = CustomCredentialDef {
            upstream: "https://api.example.com".to_string(),
            credential_key: "api_key".to_string(),
            inject_header: "X-Header!".to_string(), // ! is valid tchar
            credential_format: "Bearer {}".to_string(),
        };
        assert!(validate_custom_credential("test", &cred).is_ok());
    }

    #[test]
    fn test_validate_custom_credential_format_with_cr_rejected() {
        let cred = CustomCredentialDef {
            upstream: "https://api.example.com".to_string(),
            credential_key: "api_key".to_string(),
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}\rEvil: header".to_string(),
        };
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("CR in format should be rejected");
        assert!(err.to_string().contains("CRLF"));
    }

    #[test]
    fn test_validate_custom_credential_format_with_lf_rejected() {
        let cred = CustomCredentialDef {
            upstream: "https://api.example.com".to_string(),
            credential_key: "api_key".to_string(),
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}\nEvil: header".to_string(),
        };
        let result = validate_custom_credential("test", &cred);
        let err = result.expect_err("LF in format should be rejected");
        assert!(err.to_string().contains("CRLF"));
    }

    #[test]
    fn test_validate_custom_credential_various_valid_formats() {
        for format in ["Bearer {}", "Token {}", "{}", "Basic {}", "ApiKey={}"] {
            let cred = CustomCredentialDef {
                upstream: "https://api.example.com".to_string(),
                credential_key: "api_key".to_string(),
                inject_header: "Authorization".to_string(),
                credential_format: format.to_string(),
            };
            assert!(
                validate_custom_credential("test", &cred).is_ok(),
                "Expected format '{}' to be valid",
                format
            );
        }
    }

    #[test]
    fn test_validate_custom_credential_http_localhost_allowed() {
        let cred = CustomCredentialDef {
            upstream: "http://localhost:3000/api".to_string(),
            credential_key: "local_key".to_string(),
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
        };
        assert!(validate_custom_credential("local", &cred).is_ok());
    }

    #[test]
    fn test_validate_custom_credential_http_ipv6_loopback_allowed() {
        let cred = CustomCredentialDef {
            upstream: "http://[::1]:8080/api".to_string(),
            credential_key: "local_key".to_string(),
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
        };
        assert!(validate_custom_credential("local", &cred).is_ok());
    }

    #[test]
    fn test_validate_custom_credential_http_0_0_0_0_allowed() {
        let cred = CustomCredentialDef {
            upstream: "http://0.0.0.0:3000/api".to_string(),
            credential_key: "local_key".to_string(),
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
        };
        assert!(validate_custom_credential("local", &cred).is_ok());
    }
}
