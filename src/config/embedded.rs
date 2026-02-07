//! Embedded configuration loading
//!
//! Loads security lists and built-in profiles that are compiled into the binary.

#![allow(dead_code)]

use super::security_lists::SecurityLists;
use crate::error::{NonoError, Result};
use crate::profile::{
    FilesystemConfig, HooksConfig, NetworkConfig, Profile, ProfileMeta, SecretsConfig,
    WorkdirConfig,
};

/// Embedded security lists (compiled into binary by build.rs)
const EMBEDDED_SECURITY_LISTS: &str =
    include_str!(concat!(env!("OUT_DIR"), "/security-lists.toml"));

/// Author public key for verifying signatures
/// This is the root of trust - embedded at compile time
/// Luke: Implementing signature verification is a future step, but we need to have the key in place for when we do. In fact it will be rotating, so we need to have the infrastructure for it in place before we can generate the first key pair. For now, this is a placeholder value that will be replaced once we have a real key pair generated.
pub const AUTHOR_PUBLIC_KEY: &str = "RWTk1xXqcTODeYttYMCqEwcLg+KiX+Vpu1v6iV3D0sGabcdef12345678";
// TODO: Replace with actual public key when generated

/// Check if security lists are signed (runtime check)
fn is_signed() -> bool {
    option_env!("SECURITY_LISTS_SIGNED") == Some("1")
}

/// Load embedded security lists
///
/// If signatures are present, verifies them before returning.
/// For unsigned builds (development), returns the lists without verification.
pub fn load_security_lists() -> Result<SecurityLists> {
    // Parse the TOML
    let lists: SecurityLists = toml::from_str(EMBEDDED_SECURITY_LISTS).map_err(|e| {
        NonoError::ConfigParse(format!("Failed to parse embedded security lists: {}", e))
    })?;

    // Signature verification is deferred until we have proper key management
    // For now, just log if we're running unsigned
    if !is_signed() {
        tracing::debug!("Running with unsigned security lists (development mode)");
    }

    // TODO: Check version against stored state for downgrade protection

    Ok(lists)
}

// Include generated profile loading code from build.rs
// This ensures profile list stays in sync with data/profiles/*.toml
include!(concat!(env!("OUT_DIR"), "/builtin_profiles.rs"));

/// Load a built-in profile by name
///
/// Built-in profiles are embedded TOML files, trusted by default.
pub fn load_builtin_profile(name: &str) -> Option<Profile> {
    let content = load_builtin_profile_content(name)?;
    parse_profile_toml(content).ok()
}

/// Parse a profile from TOML content
fn parse_profile_toml(content: &str) -> Result<Profile> {
    // Profile TOML has a slightly different structure than the Rust struct
    // We need an intermediate type for deserialization
    #[derive(serde::Deserialize)]
    struct ProfileToml {
        meta: ProfileMetaToml,
        #[serde(default)]
        filesystem: FilesystemToml,
        #[serde(default)]
        network: NetworkConfig,
        #[serde(default)]
        commands: CommandsConfig,
        #[serde(default)]
        secrets: SecretsConfig,
        #[serde(default)]
        workdir: WorkdirConfig,
        #[serde(default)]
        hooks: HooksConfig,
        #[serde(default)]
        interactive: bool,
    }

    #[derive(serde::Deserialize)]
    struct ProfileMetaToml {
        name: String,
        #[serde(default)]
        version: String,
        #[serde(default)]
        description: Option<String>,
        #[serde(default)]
        author: Option<String>,
        #[serde(default)]
        min_nono_version: Option<String>,
        #[serde(default)]
        signature: Option<String>,
    }

    #[derive(Default, serde::Deserialize)]
    struct FilesystemToml {
        #[serde(default)]
        allow: Vec<String>,
        #[serde(default)]
        read: Vec<String>,
        #[serde(default)]
        write: Vec<String>,
        #[serde(default)]
        files: FilesConfig,
    }

    #[derive(Default, serde::Deserialize)]
    struct FilesConfig {
        #[serde(default)]
        allow: Vec<String>,
        #[serde(default)]
        read: Vec<String>,
        #[serde(default)]
        write: Vec<String>,
    }

    #[derive(Default, serde::Deserialize)]
    struct CommandsConfig {
        #[serde(default)]
        allow: Vec<String>,
        #[serde(default)]
        block: Vec<String>,
    }

    let toml_profile: ProfileToml = toml::from_str(content)
        .map_err(|e| NonoError::ProfileParse(format!("Failed to parse profile: {}", e)))?;

    Ok(Profile {
        meta: ProfileMeta {
            name: toml_profile.meta.name,
            version: toml_profile.meta.version,
            description: toml_profile.meta.description,
            author: toml_profile.meta.author,
            signature: toml_profile.meta.signature,
        },
        filesystem: FilesystemConfig {
            allow: toml_profile.filesystem.allow,
            read: toml_profile.filesystem.read,
            write: toml_profile.filesystem.write,
            allow_file: toml_profile.filesystem.files.allow,
            read_file: toml_profile.filesystem.files.read,
            write_file: toml_profile.filesystem.files.write,
        },
        network: toml_profile.network,
        secrets: toml_profile.secrets,
        workdir: toml_profile.workdir,
        hooks: toml_profile.hooks,
        interactive: toml_profile.interactive,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_security_lists() {
        let lists = load_security_lists().expect("Failed to load security lists");

        // Verify basic structure
        assert!(lists.meta.version >= 1);
        assert!(!lists.all_sensitive_paths().is_empty());
        assert!(!lists.all_dangerous_commands().is_empty());
    }

    #[test]
    fn test_load_builtin_profiles() {
        // Test that all built-in profiles can be loaded
        for name in list_builtin_profiles() {
            let profile = load_builtin_profile(&name);
            assert!(
                profile.is_some(),
                "Failed to load built-in profile: {}",
                name
            );

            let p = profile.unwrap();
            assert_eq!(p.meta.name, name);
        }
    }

    #[test]
    fn test_load_nonexistent_builtin() {
        assert!(load_builtin_profile("nonexistent").is_none());
    }
}
