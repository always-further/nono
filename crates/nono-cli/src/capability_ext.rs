//! CLI-specific extensions for CapabilitySet
//!
//! This module provides methods to construct a CapabilitySet from CLI arguments
//! or profiles. These are CLI-specific and not part of the core library.

use crate::cli::SandboxArgs;
use crate::policy;
use crate::profile::{expand_vars, Profile};
use nono::{AccessMode, CapabilitySet, CapabilitySource, FsCapability, NonoError, Result};
use std::path::Path;
use tracing::{debug, warn};

/// Try to create a directory capability, warning and skipping on PathNotFound.
/// Propagates all other errors.
fn try_new_dir(path: &Path, access: AccessMode, label: &str) -> Result<Option<FsCapability>> {
    match FsCapability::new_dir(path, access) {
        Ok(cap) => Ok(Some(cap)),
        Err(NonoError::PathNotFound(_)) => {
            warn!("{}: {}", label, path.display());
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// Try to create a file capability, warning and skipping on PathNotFound.
/// Propagates all other errors.
fn try_new_file(path: &Path, access: AccessMode, label: &str) -> Result<Option<FsCapability>> {
    match FsCapability::new_file(path, access) {
        Ok(cap) => Ok(Some(cap)),
        Err(NonoError::PathNotFound(_)) => {
            warn!("{}: {}", label, path.display());
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// Extension trait for CapabilitySet to add CLI-specific construction methods.
///
/// Both methods return `(CapabilitySet, bool)` where the bool indicates whether
/// `policy::apply_unlink_overrides()` must be called after all writable paths
/// are finalized (including CWD). The caller is responsible for calling it.
pub trait CapabilitySetExt {
    /// Create a capability set from CLI sandbox arguments.
    /// Returns `(caps, needs_unlink_overrides)`.
    fn from_args(args: &SandboxArgs) -> Result<(CapabilitySet, bool)>;

    /// Create a capability set from a profile with CLI overrides.
    /// Returns `(caps, needs_unlink_overrides)`.
    fn from_profile(
        profile: &Profile,
        workdir: &Path,
        args: &SandboxArgs,
    ) -> Result<(CapabilitySet, bool)>;
}

impl CapabilitySetExt for CapabilitySet {
    fn from_args(args: &SandboxArgs) -> Result<(CapabilitySet, bool)> {
        let mut caps = CapabilitySet::new();

        // Resolve base policy groups (system paths, deny rules, dangerous commands)
        let loaded_policy = policy::load_embedded_policy()?;
        let base = policy::base_groups()?;
        let resolved = policy::resolve_groups(&loaded_policy, &base, &mut caps)?;
        let needs_unlink_overrides = resolved.needs_unlink_overrides;

        // Directory permissions (canonicalize handles existence check atomically)
        for path in &args.allow {
            if let Some(cap) =
                try_new_dir(path, AccessMode::ReadWrite, "Skipping non-existent path")?
            {
                caps.add_fs(cap);
            }
        }

        for path in &args.read {
            if let Some(cap) = try_new_dir(path, AccessMode::Read, "Skipping non-existent path")? {
                caps.add_fs(cap);
            }
        }

        for path in &args.write {
            if let Some(cap) = try_new_dir(path, AccessMode::Write, "Skipping non-existent path")? {
                caps.add_fs(cap);
            }
        }

        // Single file permissions
        for path in &args.allow_file {
            if let Some(cap) =
                try_new_file(path, AccessMode::ReadWrite, "Skipping non-existent file")?
            {
                caps.add_fs(cap);
            }
        }

        for path in &args.read_file {
            if let Some(cap) = try_new_file(path, AccessMode::Read, "Skipping non-existent file")? {
                caps.add_fs(cap);
            }
        }

        for path in &args.write_file {
            if let Some(cap) = try_new_file(path, AccessMode::Write, "Skipping non-existent file")?
            {
                caps.add_fs(cap);
            }
        }

        // Network blocking
        if args.net_block {
            caps.set_network_blocked(true);
        }

        // Command allow/block lists
        for cmd in &args.allow_command {
            caps.add_allowed_command(cmd.clone());
        }

        for cmd in &args.block_command {
            caps.add_blocked_command(cmd.clone());
        }

        // Validate deny/allow overlaps (hard-fail on Linux where Landlock cannot enforce denies)
        policy::validate_deny_overlaps(&resolved.deny_paths, &caps)?;

        // Keep broad keychain deny groups active, but allow explicit
        // login.keychain-db read grants (profile/CLI) on macOS.
        policy::apply_macos_login_keychain_exception(&mut caps);

        // Deduplicate capabilities
        caps.deduplicate();

        // Caller must call apply_unlink_overrides() after CWD and any other
        // writable paths are added, if needs_unlink_overrides is true.
        Ok((caps, needs_unlink_overrides))
    }

    fn from_profile(
        profile: &Profile,
        workdir: &Path,
        args: &SandboxArgs,
    ) -> Result<(CapabilitySet, bool)> {
        let mut caps = CapabilitySet::new();

        // Resolve policy groups from profile
        // All profiles must have groups; if empty, use base_groups() as fallback
        let loaded_policy = policy::load_embedded_policy()?;
        let groups = if profile.security.groups.is_empty() {
            policy::base_groups()?
        } else {
            profile.security.groups.clone()
        };
        let resolved = policy::resolve_groups(&loaded_policy, &groups, &mut caps)?;
        let needs_unlink_overrides = resolved.needs_unlink_overrides;
        debug!("Resolved {} policy groups", resolved.names.len());

        // Process profile filesystem config (profile-specific paths on top of groups).
        // These are marked as CapabilitySource::Profile so they are displayed in
        // the banner but NOT tracked for rollback snapshots (only User-sourced paths
        // representing the project workspace are tracked).
        let fs = &profile.filesystem;

        // Directories with read+write access
        for path_template in &fs.allow {
            let path = expand_vars(path_template, workdir)?;
            let label = format!("Profile path '{}' does not exist, skipping", path_template);
            if let Some(mut cap) = try_new_dir(&path, AccessMode::ReadWrite, &label)? {
                cap.source = CapabilitySource::Profile;
                caps.add_fs(cap);
            }
        }

        // Directories with read-only access
        for path_template in &fs.read {
            let path = expand_vars(path_template, workdir)?;
            let label = format!("Profile path '{}' does not exist, skipping", path_template);
            if let Some(mut cap) = try_new_dir(&path, AccessMode::Read, &label)? {
                cap.source = CapabilitySource::Profile;
                caps.add_fs(cap);
            }
        }

        // Directories with write-only access
        for path_template in &fs.write {
            let path = expand_vars(path_template, workdir)?;
            let label = format!("Profile path '{}' does not exist, skipping", path_template);
            if let Some(mut cap) = try_new_dir(&path, AccessMode::Write, &label)? {
                cap.source = CapabilitySource::Profile;
                caps.add_fs(cap);
            }
        }

        // Single files with read+write access
        for path_template in &fs.allow_file {
            let path = expand_vars(path_template, workdir)?;
            let label = format!("Profile file '{}' does not exist, skipping", path_template);
            if let Some(mut cap) = try_new_file(&path, AccessMode::ReadWrite, &label)? {
                cap.source = CapabilitySource::Profile;
                caps.add_fs(cap);
            }
        }

        // Single files with read-only access
        for path_template in &fs.read_file {
            let path = expand_vars(path_template, workdir)?;
            let label = format!("Profile file '{}' does not exist, skipping", path_template);
            if let Some(mut cap) = try_new_file(&path, AccessMode::Read, &label)? {
                cap.source = CapabilitySource::Profile;
                caps.add_fs(cap);
            }
        }

        // Single files with write-only access
        for path_template in &fs.write_file {
            let path = expand_vars(path_template, workdir)?;
            let label = format!("Profile file '{}' does not exist, skipping", path_template);
            if let Some(mut cap) = try_new_file(&path, AccessMode::Write, &label)? {
                cap.source = CapabilitySource::Profile;
                caps.add_fs(cap);
            }
        }

        // Network blocking from profile
        if profile.network.block {
            caps.set_network_blocked(true);
        }

        // Apply CLI overrides (CLI args take precedence)
        add_cli_overrides(&mut caps, args)?;

        // Validate deny/allow overlaps (hard-fail on Linux where Landlock cannot enforce denies)
        policy::validate_deny_overlaps(&resolved.deny_paths, &caps)?;

        // Keep broad keychain deny groups active, but allow explicit
        // login.keychain-db read grants (profile/CLI) on macOS.
        policy::apply_macos_login_keychain_exception(&mut caps);

        // Deduplicate capabilities
        caps.deduplicate();

        // Caller must call apply_unlink_overrides() after CWD and any other
        // writable paths are added, if needs_unlink_overrides is true.
        Ok((caps, needs_unlink_overrides))
    }
}

/// Apply CLI argument overrides on top of existing capabilities
fn add_cli_overrides(caps: &mut CapabilitySet, args: &SandboxArgs) -> Result<()> {
    // Additional directories from CLI
    for path in &args.allow {
        if !caps.path_covered(path) {
            if let Some(cap) =
                try_new_dir(path, AccessMode::ReadWrite, "Skipping non-existent path")?
            {
                caps.add_fs(cap);
            }
        }
    }

    for path in &args.read {
        if !caps.path_covered(path) {
            if let Some(cap) = try_new_dir(path, AccessMode::Read, "Skipping non-existent path")? {
                caps.add_fs(cap);
            }
        }
    }

    for path in &args.write {
        if !caps.path_covered(path) {
            if let Some(cap) = try_new_dir(path, AccessMode::Write, "Skipping non-existent path")? {
                caps.add_fs(cap);
            }
        }
    }

    // Additional files from CLI
    for path in &args.allow_file {
        if let Some(cap) = try_new_file(path, AccessMode::ReadWrite, "Skipping non-existent file")?
        {
            caps.add_fs(cap);
        }
    }

    for path in &args.read_file {
        if let Some(cap) = try_new_file(path, AccessMode::Read, "Skipping non-existent file")? {
            caps.add_fs(cap);
        }
    }

    for path in &args.write_file {
        if let Some(cap) = try_new_file(path, AccessMode::Write, "Skipping non-existent file")? {
            caps.add_fs(cap);
        }
    }

    // CLI network blocking overrides profile
    if args.net_block {
        caps.set_network_blocked(true);
    }

    // Command allow/block from CLI
    for cmd in &args.allow_command {
        caps.add_allowed_command(cmd.clone());
    }

    for cmd in &args.block_command {
        caps.add_blocked_command(cmd.clone());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_from_args_basic() {
        let dir = tempdir().expect("Failed to create temp dir");

        let args = SandboxArgs {
            allow: vec![dir.path().to_path_buf()],
            read: vec![],
            write: vec![],
            allow_file: vec![],
            read_file: vec![],
            write_file: vec![],
            net_block: false,
            allow_command: vec![],
            block_command: vec![],
            secrets: None,
            profile: None,
            allow_cwd: false,
            workdir: None,
            config: None,
            verbose: 0,
            dry_run: false,
        };

        let (caps, _) = CapabilitySet::from_args(&args).expect("Failed to build caps");
        assert!(caps.has_fs());
        assert!(!caps.is_network_blocked());
    }

    #[test]
    fn test_from_args_network_blocked() {
        let args = SandboxArgs {
            allow: vec![],
            read: vec![],
            write: vec![],
            allow_file: vec![],
            read_file: vec![],
            write_file: vec![],
            net_block: true,
            allow_command: vec![],
            block_command: vec![],
            secrets: None,
            profile: None,
            allow_cwd: false,
            workdir: None,
            config: None,
            verbose: 0,
            dry_run: false,
        };

        let (caps, _) = CapabilitySet::from_args(&args).expect("Failed to build caps");
        assert!(caps.is_network_blocked());
    }

    #[test]
    fn test_from_args_with_commands() {
        let args = SandboxArgs {
            allow: vec![],
            read: vec![],
            write: vec![],
            allow_file: vec![],
            read_file: vec![],
            write_file: vec![],
            net_block: false,
            allow_command: vec!["rm".to_string()],
            block_command: vec!["custom".to_string()],
            secrets: None,
            profile: None,
            allow_cwd: false,
            workdir: None,
            config: None,
            verbose: 0,
            dry_run: false,
        };

        let (caps, _) = CapabilitySet::from_args(&args).expect("Failed to build caps");
        assert!(caps.allowed_commands().contains(&"rm".to_string()));
        assert!(caps.blocked_commands().contains(&"custom".to_string()));
    }

    #[test]
    fn test_from_profile_with_groups() {
        let profile = crate::profile::load_profile("claude-code")
            .expect("Failed to load claude-code profile");

        let workdir = tempdir().expect("Failed to create temp dir");
        let args = SandboxArgs {
            allow: vec![],
            read: vec![],
            write: vec![],
            allow_file: vec![],
            read_file: vec![],
            write_file: vec![],
            net_block: false,
            allow_command: vec![],
            block_command: vec![],
            secrets: None,
            profile: None,
            allow_cwd: false,
            workdir: None,
            config: None,
            verbose: 0,
            dry_run: false,
        };

        let (mut caps, needs_unlink_overrides) =
            CapabilitySet::from_profile(&profile, workdir.path(), &args).expect("Failed to build");

        // Simulate what main.rs does: apply unlink overrides after all paths finalized
        if needs_unlink_overrides {
            policy::apply_unlink_overrides(&mut caps);
        }

        // Groups should have populated filesystem capabilities
        assert!(caps.has_fs());

        if cfg!(target_os = "macos") {
            // On macOS: deny groups generate Seatbelt platform rules
            assert!(!caps.platform_rules().is_empty());

            let rules = caps.platform_rules().join("\n");
            assert!(rules.contains("deny file-read-data"));
            assert!(rules.contains("deny file-write*"));

            // Unlink protection should be present
            assert!(rules.contains("deny file-write-unlink"));

            // Unlink overrides must exist for writable paths (including ~/.claude from
            // the profile [filesystem] section, which is added AFTER group resolution).
            assert!(
                rules.contains("allow file-write-unlink"),
                "Expected unlink overrides for writable paths, got:\n{}",
                rules
            );
        }
        // On Linux: deny/unlink rules are not generated (Landlock has no deny semantics),
        // but deny_paths are collected for overlap validation.

        // Dangerous commands should be blocked (cross-platform)
        assert!(caps.blocked_commands().contains(&"rm".to_string()));
        assert!(caps.blocked_commands().contains(&"dd".to_string()));
    }
}
