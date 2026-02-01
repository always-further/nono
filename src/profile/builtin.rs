//! Built-in profiles compiled into the nono binary
//!
//! These profiles are trusted by default and don't require --trust-unsigned.

use super::{FilesystemConfig, NetworkConfig, Profile, ProfileMeta, SecretsConfig};

/// Get a built-in profile by name
pub fn get_builtin(name: &str) -> Option<Profile> {
    match name {
        "claude-code" => Some(claude_code()),
        "openclaw" => Some(openclaw()),
        "opencode" => Some(opencode()),
        "cargo-build" => Some(cargo_build()),
        _ => None,
    }
}

/// List all built-in profile names
#[allow(dead_code)]
pub fn list_builtin() -> Vec<String> {
    vec![
        "claude-code".to_string(),
        "openclaw".to_string(),
        "opencode".to_string(),
        "cargo-build".to_string(),
    ]
}

/// Anthropic Claude Code CLI agent
fn claude_code() -> Profile {
    Profile {
        meta: ProfileMeta {
            name: "claude-code".to_string(),
            version: "1.0.0".to_string(),
            description: Some("Anthropic Claude Code CLI agent".to_string()),
            author: Some("nono-project".to_string()),
            signature: None,
        },
        filesystem: FilesystemConfig {
            // WORKDIR: where the agent works on code
            // ~/.claude: agent state, debug logs, projects, etc.
            allow: vec!["$WORKDIR".to_string(), "$HOME/.claude".to_string()],
            read: vec!["$HOME/.config/claude-code".to_string()],
            write: vec![],
            // ~/.claude.json: agent writes settings/state here
            allow_file: vec!["$HOME/.claude.json".to_string()],
            read_file: vec![],
            write_file: vec![],
        },
        network: NetworkConfig { block: false },
        secrets: SecretsConfig::default(),
    }
}

/// OpenClaw messaging gateway
fn openclaw() -> Profile {
    Profile {
        meta: ProfileMeta {
            name: "openclaw".to_string(),
            version: "1.0.0".to_string(),
            description: Some("OpenClaw messaging gateway".to_string()),
            author: Some("nono-project".to_string()),
            signature: None,
        },
        filesystem: FilesystemConfig {
            allow: vec![
                "$HOME/.openclaw".to_string(),
                "$HOME/.config/openclaw".to_string(),
            ],
            read: vec![],
            write: vec![],
            allow_file: vec![],
            read_file: vec![],
            write_file: vec![],
        },
        network: NetworkConfig { block: false },
        secrets: SecretsConfig::default(),
    }
}

/// OpenCode AI coding assistant
fn opencode() -> Profile {
    Profile {
        meta: ProfileMeta {
            name: "opencode".to_string(),
            version: "1.0.0".to_string(),
            description: Some("OpenCode AI coding assistant".to_string()),
            author: Some("nono-project".to_string()),
            signature: None,
        },
        filesystem: FilesystemConfig {
            allow: vec!["$WORKDIR".to_string()],
            read: vec!["$HOME/.opencode".to_string()],
            write: vec![],
            allow_file: vec![],
            read_file: vec![],
            write_file: vec![],
        },
        network: NetworkConfig { block: false },
        secrets: SecretsConfig::default(),
    }
}

/// Rust cargo build (no network)
fn cargo_build() -> Profile {
    Profile {
        meta: ProfileMeta {
            name: "cargo-build".to_string(),
            version: "1.0.0".to_string(),
            description: Some("Rust cargo build (no network)".to_string()),
            author: Some("nono-project".to_string()),
            signature: None,
        },
        filesystem: FilesystemConfig {
            allow: vec!["$WORKDIR".to_string()],
            read: vec!["$HOME/.cargo".to_string(), "$HOME/.rustup".to_string()],
            write: vec![],
            allow_file: vec![],
            read_file: vec![],
            write_file: vec![],
        },
        network: NetworkConfig { block: true },
        secrets: SecretsConfig::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_builtin_claude_code() {
        let profile = get_builtin("claude-code").unwrap();
        assert_eq!(profile.meta.name, "claude-code");
        assert!(!profile.network.block); // network allowed
        assert!(profile.filesystem.allow.contains(&"$WORKDIR".to_string()));
    }

    #[test]
    fn test_get_builtin_openclaw() {
        let profile = get_builtin("openclaw").unwrap();
        assert_eq!(profile.meta.name, "openclaw");
        assert!(!profile.network.block); // network allowed
        assert!(profile
            .filesystem
            .allow
            .contains(&"$HOME/.openclaw".to_string()));
    }

    #[test]
    fn test_get_builtin_cargo_build() {
        let profile = get_builtin("cargo-build").unwrap();
        assert_eq!(profile.meta.name, "cargo-build");
        assert!(profile.network.block); // Network blocked for cargo-build
    }

    #[test]
    fn test_get_builtin_nonexistent() {
        assert!(get_builtin("nonexistent").is_none());
    }

    #[test]
    fn test_list_builtin() {
        let profiles = list_builtin();
        assert!(profiles.contains(&"claude-code".to_string()));
        assert!(profiles.contains(&"openclaw".to_string()));
        assert!(profiles.contains(&"opencode".to_string()));
        assert!(profiles.contains(&"cargo-build".to_string()));
    }
}
