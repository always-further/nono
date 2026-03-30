//! Built-in profiles compiled into the nono binary
//!
//! Profiles are defined declaratively in `policy.json` under the `profiles` key.
//! This module delegates to the policy resolver for loading and listing.

use super::Profile;

/// Get a built-in profile by name
pub fn get_builtin(name: &str) -> Option<Profile> {
    crate::policy::get_policy_profile(name).ok().flatten()
}

/// List all built-in profile names
pub fn list_builtin() -> Vec<String> {
    crate::policy::list_policy_profiles().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::WorkdirAccess;

    #[test]
    fn test_get_builtin_claude_code() {
        let profile = get_builtin("claude-code").expect("Profile not found");
        assert_eq!(profile.meta.name, "claude-code");
        assert!(!profile.network.block); // network allowed
        assert_eq!(profile.workdir.access, WorkdirAccess::ReadWrite);
        assert!(!profile.security.groups.is_empty());
        assert!(profile
            .security
            .groups
            .contains(&"deny_credentials".to_string()));
    }

    #[test]
    fn test_get_builtin_default() {
        let profile = get_builtin("default").expect("Profile not found");
        assert_eq!(profile.meta.name, "default");
        assert_eq!(profile.workdir.access, WorkdirAccess::None);
        assert!(!profile.interactive);
        assert!(!profile.network.block);
    }

    #[test]
    fn test_get_builtin_claude_code_uses_platform_groups_for_os_paths() {
        let profile = get_builtin("claude-code").expect("Profile not found");
        assert!(profile
            .security
            .groups
            .contains(&"claude_code_macos".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"claude_code_linux".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"vscode_macos".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"vscode_linux".to_string()));
        assert!(!profile
            .filesystem
            .read
            .contains(&"$HOME/.local/share/claude".to_string()));
        assert!(!profile
            .filesystem
            .read_file
            .contains(&"$HOME/Library/Keychains/login.keychain-db".to_string()));
    }

    #[test]
    fn test_get_builtin_openclaw() {
        let profile = get_builtin("openclaw").expect("Profile not found");
        assert_eq!(profile.meta.name, "openclaw");
        assert!(!profile.network.block); // network allowed
        assert!(profile
            .filesystem
            .allow
            .contains(&"$HOME/.openclaw".to_string()));
    }

    #[test]
    fn test_get_builtin_codex() {
        let profile = get_builtin("codex").expect("Profile not found");
        assert_eq!(profile.meta.name, "codex");
        assert_eq!(profile.workdir.access, WorkdirAccess::ReadWrite);
        assert!(profile.interactive);
        assert!(profile
            .filesystem
            .allow
            .contains(&"$HOME/.codex".to_string()));
        assert!(profile.security.groups.contains(&"codex_macos".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"node_runtime".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"rust_runtime".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"python_runtime".to_string()));
        assert!(profile.security.groups.contains(&"nix_runtime".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"unlink_protection".to_string()));
    }

    #[test]
    fn test_get_builtin_opencode() {
        let profile = get_builtin("opencode").expect("Profile not found");
        assert_eq!(profile.meta.name, "opencode");
        assert_eq!(profile.workdir.access, WorkdirAccess::ReadWrite);
        assert!(profile.interactive);
        assert!(profile
            .filesystem
            .allow
            .contains(&"$HOME/.opencode".to_string()));
        assert!(profile
            .filesystem
            .allow
            .contains(&"$HOME/.local/share/opentui".to_string()));
    }

    #[test]
    fn test_get_builtin_swival() {
        let profile = get_builtin("swival").expect("Profile not found");
        assert_eq!(profile.meta.name, "swival");
        assert_eq!(profile.workdir.access, WorkdirAccess::ReadWrite);
        assert!(profile.interactive);
        assert!(!profile.network.block);
        assert!(profile
            .filesystem
            .allow
            .contains(&"$HOME/.config/swival".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"python_runtime".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"unlink_protection".to_string()));
    }

    #[test]
    fn test_get_builtin_nonexistent() {
        assert!(get_builtin("nonexistent").is_none());
    }

    #[test]
    fn test_list_builtin() {
        let profiles = list_builtin();
        assert!(profiles.contains(&"default".to_string()));
        assert!(profiles.contains(&"claude-code".to_string()));
        assert!(profiles.contains(&"codex".to_string()));
        assert!(profiles.contains(&"openclaw".to_string()));
        assert!(profiles.contains(&"opencode".to_string()));
        assert!(profiles.contains(&"swival".to_string()));
    }

    #[test]
    fn test_profile_group_merging() {
        let profile = get_builtin("claude-code").expect("Profile not found");
        // Should have default profile groups
        assert!(profile
            .security
            .groups
            .contains(&"deny_credentials".to_string()));
        // Should have profile-specific groups
        assert!(profile
            .security
            .groups
            .contains(&"node_runtime".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"rust_runtime".to_string()));
        assert!(profile
            .security
            .groups
            .contains(&"unlink_protection".to_string()));
    }

    #[test]
    fn test_profile_exclusion_mechanism() {
        // Verify that built-in profiles resolve exclusions through the shared
        // group-exclusion path. Current embedded profiles do not exclude any.
        let profile = get_builtin("openclaw").expect("Profile not found");
        let default = get_builtin("default").expect("default profile");
        // All default groups should be present since embedded exclusions are empty.
        for group in &default.security.groups {
            assert!(
                profile.security.groups.contains(group),
                "openclaw should contain default profile group '{}'",
                group
            );
        }
    }

    #[test]
    fn test_default_profile_group_set_is_explicit() {
        let profile = get_builtin("default").expect("default profile");
        let mut expected = vec![
            "dangerous_commands".to_string(),
            "dangerous_commands_linux".to_string(),
            "dangerous_commands_macos".to_string(),
            "deny_browser_data_linux".to_string(),
            "deny_browser_data_macos".to_string(),
            "deny_credentials".to_string(),
            "deny_keychains_linux".to_string(),
            "deny_keychains_macos".to_string(),
            "deny_macos_private".to_string(),
            "deny_shell_configs".to_string(),
            "deny_shell_history".to_string(),
            "homebrew".to_string(),
            "system_read_linux".to_string(),
            "system_read_macos".to_string(),
            "system_read_windows".to_string(),
            "system_write_linux".to_string(),
            "system_write_macos".to_string(),
            "user_tools".to_string(),
        ];
        let mut actual = profile.security.groups.clone();
        expected.sort();
        actual.sort();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_embedded_profiles_extend_default() {
        let policy = crate::policy::load_embedded_policy().expect("load embedded policy");
        for (name, def) in &policy.profiles {
            if name == "default" {
                continue;
            }
            assert_eq!(
                def.extends.as_deref(),
                Some("default"),
                "embedded profile '{}' should extend default",
                name
            );
        }
    }
}
