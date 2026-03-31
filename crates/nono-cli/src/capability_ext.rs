//! CLI-specific extensions for CapabilitySet
//!
//! This module provides methods to construct a CapabilitySet from CLI arguments
//! or profiles. These are CLI-specific and not part of the core library.

use crate::cli::SandboxArgs;
use crate::policy;
use crate::profile::{expand_vars, Profile};
use crate::protected_paths::{self, ProtectedRoots};
use nono::{AccessMode, CapabilitySet, CapabilitySource, FsCapability, NonoError, Result};
use std::path::{Path, PathBuf};
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

fn apply_profile_dir_allows(
    path_templates: &[String],
    access: AccessMode,
    workdir: &Path,
    protected_roots: &ProtectedRoots,
    caps: &mut CapabilitySet,
    label_prefix: &str,
) -> Result<()> {
    for path_template in path_templates {
        let path = expand_vars(path_template, workdir)?;
        validate_requested_dir(&path, "Profile", protected_roots)?;
        let label = format!(
            "{label_prefix} '{}' does not exist, skipping",
            path_template
        );
        if let Some(mut cap) = try_new_dir(&path, access, &label)? {
            cap.source = CapabilitySource::Profile;
            caps.add_fs(cap);
        }
    }
    Ok(())
}

fn validate_requested_dir(
    path: &Path,
    source: &str,
    protected_roots: &ProtectedRoots,
) -> Result<()> {
    protected_paths::validate_requested_path_against_protected_roots(
        path,
        false,
        source,
        protected_roots.as_paths(),
    )
}

fn validate_requested_file(
    path: &Path,
    source: &str,
    protected_roots: &ProtectedRoots,
) -> Result<()> {
    protected_paths::validate_requested_path_against_protected_roots(
        path,
        true,
        source,
        protected_roots.as_paths(),
    )
}

pub(crate) fn default_profile_groups() -> Result<Vec<String>> {
    let profile = crate::policy::get_policy_profile("default")?
        .ok_or_else(|| NonoError::ProfileNotFound("default".to_string()))?;
    Ok(profile.security.groups)
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
        let protected_roots = ProtectedRoots::from_defaults()?;

        // Resolve base policy groups (system paths, deny rules, dangerous commands)
        let loaded_policy = policy::load_embedded_policy()?;
        let default_groups = default_profile_groups()?;
        let mut resolved = policy::resolve_groups(&loaded_policy, &default_groups, &mut caps)?;

        // Directory permissions (canonicalize handles existence check atomically)
        for path in &args.allow {
            validate_requested_dir(path, "CLI", &protected_roots)?;
            if let Some(cap) =
                try_new_dir(path, AccessMode::ReadWrite, "Skipping non-existent path")?
            {
                caps.add_fs(cap);
            }
        }

        for path in &args.read {
            validate_requested_dir(path, "CLI", &protected_roots)?;
            if let Some(cap) = try_new_dir(path, AccessMode::Read, "Skipping non-existent path")? {
                caps.add_fs(cap);
            }
        }

        for path in &args.write {
            validate_requested_dir(path, "CLI", &protected_roots)?;
            if let Some(cap) = try_new_dir(path, AccessMode::Write, "Skipping non-existent path")? {
                caps.add_fs(cap);
            }
        }

        // Single file permissions
        for path in &args.allow_file {
            validate_requested_file(path, "CLI", &protected_roots)?;
            if let Some(cap) =
                try_new_file(path, AccessMode::ReadWrite, "Skipping non-existent file")?
            {
                caps.add_fs(cap);
            }
        }

        for path in &args.read_file {
            validate_requested_file(path, "CLI", &protected_roots)?;
            if let Some(cap) = try_new_file(path, AccessMode::Read, "Skipping non-existent file")? {
                caps.add_fs(cap);
            }
        }

        for path in &args.write_file {
            validate_requested_file(path, "CLI", &protected_roots)?;
            if let Some(cap) = try_new_file(path, AccessMode::Write, "Skipping non-existent file")?
            {
                caps.add_fs(cap);
            }
        }

        apply_cli_network_mode(&mut caps, args);

        // Localhost IPC ports
        for port in &args.allow_port {
            caps.add_localhost_port(*port);
        }

        // Command allow/block lists
        for cmd in &args.allow_command {
            caps.add_allowed_command(cmd.clone());
        }

        for cmd in &args.block_command {
            caps.add_blocked_command(cmd);
        }

        finalize_caps(&mut caps, &mut resolved, &loaded_policy, args, &[])?;

        Ok((caps, resolved.needs_unlink_overrides))
    }

    fn from_profile(
        profile: &Profile,
        workdir: &Path,
        args: &SandboxArgs,
    ) -> Result<(CapabilitySet, bool)> {
        let mut caps = CapabilitySet::new();
        let protected_roots = ProtectedRoots::from_defaults()?;

        // Resolve policy groups from the already-finalized profile.
        let loaded_policy = policy::load_embedded_policy()?;
        let groups = profile.security.groups.clone();
        let mut resolved = policy::resolve_groups(&loaded_policy, &groups, &mut caps)?;
        debug!("Resolved {} policy groups", resolved.names.len());

        // Process profile filesystem config (profile-specific paths on top of groups).
        // These are marked as CapabilitySource::Profile so they are displayed in
        // the banner but NOT tracked for rollback snapshots (only User-sourced paths
        // representing the project workspace are tracked).
        let fs = &profile.filesystem;

        // Directories with read+write access
        for path_template in &fs.allow {
            let path = expand_vars(path_template, workdir)?;
            validate_requested_dir(&path, "Profile", &protected_roots)?;
            let label = format!("Profile path '{}' does not exist, skipping", path_template);
            if let Some(mut cap) = try_new_dir(&path, AccessMode::ReadWrite, &label)? {
                cap.source = CapabilitySource::Profile;
                caps.add_fs(cap);
            }
        }

        // Directories with read-only access
        for path_template in &fs.read {
            let path = expand_vars(path_template, workdir)?;
            validate_requested_dir(&path, "Profile", &protected_roots)?;
            let label = format!("Profile path '{}' does not exist, skipping", path_template);
            if let Some(mut cap) = try_new_dir(&path, AccessMode::Read, &label)? {
                cap.source = CapabilitySource::Profile;
                caps.add_fs(cap);
            }
        }

        // Directories with write-only access
        for path_template in &fs.write {
            let path = expand_vars(path_template, workdir)?;
            validate_requested_dir(&path, "Profile", &protected_roots)?;
            let label = format!("Profile path '{}' does not exist, skipping", path_template);
            if let Some(mut cap) = try_new_dir(&path, AccessMode::Write, &label)? {
                cap.source = CapabilitySource::Profile;
                caps.add_fs(cap);
            }
        }

        // Single files with read+write access
        for path_template in &fs.allow_file {
            let path = expand_vars(path_template, workdir)?;
            validate_requested_file(&path, "Profile", &protected_roots)?;
            let label = format!("Profile file '{}' does not exist, skipping", path_template);
            if let Some(mut cap) = try_new_file(&path, AccessMode::ReadWrite, &label)? {
                cap.source = CapabilitySource::Profile;
                caps.add_fs(cap);
            }
        }

        // Single files with read-only access
        for path_template in &fs.read_file {
            let path = expand_vars(path_template, workdir)?;
            validate_requested_file(&path, "Profile", &protected_roots)?;
            let label = format!("Profile file '{}' does not exist, skipping", path_template);
            if let Some(mut cap) = try_new_file(&path, AccessMode::Read, &label)? {
                cap.source = CapabilitySource::Profile;
                caps.add_fs(cap);
            }
        }

        // Single files with write-only access
        for path_template in &fs.write_file {
            let path = expand_vars(path_template, workdir)?;
            validate_requested_file(&path, "Profile", &protected_roots)?;
            let label = format!("Profile file '{}' does not exist, skipping", path_template);
            if let Some(mut cap) = try_new_file(&path, AccessMode::Write, &label)? {
                cap.source = CapabilitySource::Profile;
                caps.add_fs(cap);
            }
        }

        // Policy patch additions
        apply_profile_dir_allows(
            &profile.policy.add_allow_readwrite,
            AccessMode::ReadWrite,
            workdir,
            &protected_roots,
            &mut caps,
            "Profile policy path",
        )?;
        apply_profile_dir_allows(
            &profile.policy.add_allow_read,
            AccessMode::Read,
            workdir,
            &protected_roots,
            &mut caps,
            "Profile policy path",
        )?;
        apply_profile_dir_allows(
            &profile.policy.add_allow_write,
            AccessMode::Write,
            workdir,
            &protected_roots,
            &mut caps,
            "Profile policy path",
        )?;

        for path_template in &profile.policy.add_deny_access {
            let path = expand_vars(path_template, workdir)?;
            let path_str = path.to_str().ok_or_else(|| {
                NonoError::ConfigParse(format!(
                    "Profile policy deny path contains non-UTF-8 bytes: {}",
                    path.display()
                ))
            })?;
            policy::add_deny_access_rules(path_str, &mut caps, &mut resolved.deny_paths)?;
        }

        for cmd in &profile.policy.add_deny_commands {
            caps.add_blocked_command(cmd);
        }

        // Network blocking or proxy mode from profile
        if profile.network.block {
            caps.set_network_blocked(true);
        } else if profile.network.has_proxy_flags() {
            let bind_ports =
                crate::merge_dedup_ports(&profile.network.listen_port, &args.allow_bind);
            // Profile requests proxy mode; port 0 is a placeholder.
            // bind_ports come from profile listen_port plus CLI --listen-port.
            caps = caps.set_network_mode(nono::NetworkMode::ProxyOnly {
                port: 0,
                bind_ports,
            });
        }

        // Localhost IPC ports from profile
        for port in &profile.network.open_port {
            caps.add_localhost_port(*port);
        }

        // Apply allowed commands from profile
        for cmd in &profile.security.allowed_commands {
            caps.add_allowed_command(cmd.as_str());
        }

        // Apply signal mode from profile (None defaults to Isolated)
        let mode = profile
            .security
            .signal_mode
            .map(nono::SignalMode::from)
            .unwrap_or_default();
        caps = caps.set_signal_mode(mode);

        // Apply process inspection mode from profile (None defaults to Isolated)
        let process_info_mode = profile
            .security
            .process_info_mode
            .map(nono::ProcessInfoMode::from)
            .unwrap_or_default();
        caps.set_process_info_mode_mut(process_info_mode);

        // Apply IPC mode from profile (None defaults to SharedMemoryOnly)
        let ipc_mode = profile
            .security
            .ipc_mode
            .map(nono::IpcMode::from)
            .unwrap_or_default();
        caps.set_ipc_mode_mut(ipc_mode);

        // Apply CLI overrides (CLI args take precedence)
        add_cli_overrides(&mut caps, args)?;

        // Expand profile-level override_deny paths for finalize_caps
        let mut profile_overrides = Vec::with_capacity(profile.policy.override_deny.len());
        for path_template in &profile.policy.override_deny {
            let path = expand_vars(path_template, workdir)?;
            profile_overrides.push(path);
        }

        finalize_caps(
            &mut caps,
            &mut resolved,
            &loaded_policy,
            args,
            &profile_overrides,
        )?;

        Ok((caps, resolved.needs_unlink_overrides))
    }
}

/// Shared finalization: deny overrides, overlap validation, keychain exception, dedup.
///
/// Called by both `from_args()` and `from_profile()` after all grants are added.
/// Caller must still call `apply_unlink_overrides()` after CWD and any other
/// writable paths are added, if `resolved.needs_unlink_overrides` is true.
fn finalize_caps(
    caps: &mut CapabilitySet,
    resolved: &mut policy::ResolvedGroups,
    _loaded_policy: &policy::Policy,
    args: &SandboxArgs,
    profile_override_deny: &[PathBuf],
) -> Result<()> {
    // Apply profile-level deny overrides first, then CLI overrides.
    // Profile overrides come from `policy.override_deny` in the profile JSON.
    // CLI `--override-deny` flags are applied on top.
    policy::apply_deny_overrides(profile_override_deny, &mut resolved.deny_paths, caps)?;
    policy::apply_deny_overrides(&args.override_deny, &mut resolved.deny_paths, caps)?;

    // Remove exact file grants for the deny paths that remain after overrides.
    // This lets profile deny patches override inherited file capabilities while
    // preserving `--override-deny` validation against the original grant set.
    caps.remove_exact_file_caps_for_paths(&resolved.deny_paths);

    // Validate deny/allow overlaps (hard-fail on Linux where Landlock cannot enforce denies)
    policy::validate_deny_overlaps(&resolved.deny_paths, caps)?;

    // Keep broad keychain deny groups active, but allow explicit
    // login.keychain-db read grants (profile/CLI) on macOS.
    policy::apply_macos_login_keychain_exception(caps);

    // Deduplicate capabilities
    caps.deduplicate();

    Ok(())
}

fn apply_cli_network_mode(caps: &mut CapabilitySet, args: &SandboxArgs) {
    if args.block_net {
        caps.set_network_blocked(true);
    } else if args.allow_net {
        caps.set_network_mode_mut(nono::NetworkMode::AllowAll);
    } else if args.has_proxy_flags() {
        // Proxy mode: port 0 is a placeholder, updated when proxy starts.
        // bind_ports are passed through allow_bind CLI flag.
        caps.set_network_mode_mut(nono::NetworkMode::ProxyOnly {
            port: 0,
            bind_ports: args.allow_bind.clone(),
        });
    }
}

/// Apply CLI argument overrides on top of existing capabilities.
///
/// CLI directory args are always added, even if the path is already covered by
/// a profile or group capability. The subsequent `deduplicate()` call resolves
/// conflicts using source priority (User wins over Group/System) and merges
/// complementary access modes (Read + Write = ReadWrite).
fn add_cli_overrides(caps: &mut CapabilitySet, args: &SandboxArgs) -> Result<()> {
    let protected_roots = ProtectedRoots::from_defaults()?;

    // Additional directories from CLI
    for path in &args.allow {
        validate_requested_dir(path, "CLI", &protected_roots)?;
        if let Some(cap) = try_new_dir(path, AccessMode::ReadWrite, "Skipping non-existent path")? {
            caps.add_fs(cap);
        }
    }

    for path in &args.read {
        validate_requested_dir(path, "CLI", &protected_roots)?;
        if let Some(cap) = try_new_dir(path, AccessMode::Read, "Skipping non-existent path")? {
            caps.add_fs(cap);
        }
    }

    for path in &args.write {
        validate_requested_dir(path, "CLI", &protected_roots)?;
        if let Some(cap) = try_new_dir(path, AccessMode::Write, "Skipping non-existent path")? {
            caps.add_fs(cap);
        }
    }

    // Additional files from CLI
    for path in &args.allow_file {
        validate_requested_file(path, "CLI", &protected_roots)?;
        if let Some(cap) = try_new_file(path, AccessMode::ReadWrite, "Skipping non-existent file")?
        {
            caps.add_fs(cap);
        }
    }

    for path in &args.read_file {
        validate_requested_file(path, "CLI", &protected_roots)?;
        if let Some(cap) = try_new_file(path, AccessMode::Read, "Skipping non-existent file")? {
            caps.add_fs(cap);
        }
    }

    for path in &args.write_file {
        validate_requested_file(path, "CLI", &protected_roots)?;
        if let Some(cap) = try_new_file(path, AccessMode::Write, "Skipping non-existent file")? {
            caps.add_fs(cap);
        }
    }

    // CLI network flags override profile network settings.
    apply_cli_network_mode(caps, args);

    // Localhost IPC ports from CLI
    for port in &args.allow_port {
        caps.add_localhost_port(*port);
    }

    // Command allow/block from CLI
    for cmd in &args.allow_command {
        caps.add_allowed_command(cmd.clone());
    }

    for cmd in &args.block_command {
        caps.add_blocked_command(cmd);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sandbox_args() -> SandboxArgs {
        SandboxArgs::default()
    }

    #[test]
    fn test_from_args_basic() {
        let dir = tempdir().expect("Failed to create temp dir");

        let args = SandboxArgs {
            allow: vec![dir.path().to_path_buf()],
            ..sandbox_args()
        };

        let (caps, _) = CapabilitySet::from_args(&args).expect("Failed to build caps");
        assert!(caps.has_fs());
        assert!(!caps.is_network_blocked());
    }

    #[test]
    fn test_from_args_network_blocked() {
        let args = SandboxArgs {
            block_net: true,
            ..sandbox_args()
        };

        let (caps, _) = CapabilitySet::from_args(&args).expect("Failed to build caps");
        assert!(caps.is_network_blocked());
    }

    #[test]
    fn test_from_args_with_commands() {
        let args = SandboxArgs {
            override_deny: vec![],
            allow_command: vec!["rm".to_string()],
            block_command: vec!["custom".to_string()],
            ..sandbox_args()
        };

        let (caps, _) = CapabilitySet::from_args(&args).expect("Failed to build caps");
        assert!(caps.allowed_commands().contains(&"rm".to_string()));
        assert!(caps.blocked_commands().contains(&"custom".to_string()));
    }

    #[test]
    fn test_from_args_rejects_protected_state_subtree() {
        let protected_subtree = ProtectedRoots::from_defaults()
            .expect("protected roots")
            .as_paths()
            .first()
            .expect("at least one protected root")
            .join("rollbacks");

        let args = SandboxArgs {
            allow: vec![protected_subtree],
            ..sandbox_args()
        };

        let err = CapabilitySet::from_args(&args).expect_err("must reject protected state path");
        assert!(
            err.to_string()
                .contains("overlaps protected nono state root"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn test_from_args_uses_default_profile_groups_for_runtime_policy() {
        let args = sandbox_args();
        let (caps, _) = CapabilitySet::from_args(&args).expect("build caps from args");

        let policy = crate::policy::load_embedded_policy().expect("load embedded policy");
        let default_groups = default_profile_groups().expect("get default profile groups");
        let deny_paths = crate::policy::resolve_deny_paths_for_groups(&policy, &default_groups)
            .expect("resolve deny paths");

        crate::policy::validate_deny_overlaps(&deny_paths, &caps)
            .expect("from_args caps should match default profile deny policy");
    }

    #[test]
    fn test_from_profile_allowed_commands() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("rm-test.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "rm-test" },
                "filesystem": { "allow": ["/tmp"] },
                "security": { "allowed_commands": ["rm", "shred"] }
            }"#,
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let (caps, _) =
            CapabilitySet::from_profile(&profile, workdir.path(), &args).expect("build caps");
        assert!(
            caps.allowed_commands().contains(&"rm".to_string()),
            "profile allowed_commands should include 'rm'"
        );
        assert!(
            caps.allowed_commands().contains(&"shred".to_string()),
            "profile allowed_commands should include 'shred'"
        );
    }

    #[test]
    fn test_from_profile_policy_exclude_groups_removes_non_required_group() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("exclude-groups.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "exclude-groups" },
                "filesystem": { "allow": ["/tmp"] },
                "policy": {
                    "exclude_groups": ["dangerous_commands", "dangerous_commands_linux"]
                }
            }"#,
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let (caps, _) =
            CapabilitySet::from_profile(&profile, workdir.path(), &args).expect("build caps");
        assert!(
            !caps.blocked_commands().contains(&"rm".to_string()),
            "excluded dangerous_commands should remove rm from blocked commands"
        );
        assert!(
            !caps.blocked_commands().contains(&"shred".to_string()),
            "excluded dangerous_commands_linux should remove shred from blocked commands"
        );
    }

    #[test]
    fn test_from_loaded_profile_extends_default_respects_excluded_blocked_commands() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("no-dangerous-commands.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "no-dangerous-commands", "version": "1.0.0" },
                "extends": "default",
                "policy": {
                    "exclude_groups": [
                        "dangerous_commands",
                        "dangerous_commands_linux",
                        "dangerous_commands_macos"
                    ]
                },
                "workdir": { "access": "readwrite" }
            }"#,
        )
        .expect("write profile");

        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");
        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();
        let (caps, _) =
            CapabilitySet::from_profile(&profile, workdir.path(), &args).expect("build caps");

        assert!(
            !caps.blocked_commands().contains(&"rm".to_string()),
            "excluded dangerous_commands should remove rm from blocked commands"
        );
        assert!(
            !caps.blocked_commands().contains(&"shred".to_string()),
            "excluded dangerous_commands_linux should remove shred from blocked commands"
        );
    }

    #[test]
    fn test_from_profile_policy_add_allow_paths_add_capabilities() {
        let dir = tempdir().expect("tmpdir");
        let read_dir = dir.path().join("read-dir");
        let write_dir = dir.path().join("write-dir");
        let rw_dir = dir.path().join("rw-dir");
        std::fs::create_dir_all(&read_dir).expect("mkdir read");
        std::fs::create_dir_all(&write_dir).expect("mkdir write");
        std::fs::create_dir_all(&rw_dir).expect("mkdir rw");

        let profile_path = dir.path().join("policy-adds.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                    "meta": {{ "name": "policy-adds" }},
                    "policy": {{
                        "add_allow_read": ["{}"],
                        "add_allow_write": ["{}"],
                        "add_allow_readwrite": ["{}"]
                    }}
                }}"#,
                read_dir.display(),
                write_dir.display(),
                rw_dir.display()
            ),
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let (caps, _) =
            CapabilitySet::from_profile(&profile, workdir.path(), &args).expect("build caps");

        let read_canonical = read_dir.canonicalize().expect("canonicalize read");
        let write_canonical = write_dir.canonicalize().expect("canonicalize write");
        let rw_canonical = rw_dir.canonicalize().expect("canonicalize rw");

        let read_cap = caps
            .fs_capabilities()
            .iter()
            .find(|c| c.resolved == read_canonical)
            .expect("read dir cap");
        let write_cap = caps
            .fs_capabilities()
            .iter()
            .find(|c| c.resolved == write_canonical)
            .expect("write dir cap");
        let rw_cap = caps
            .fs_capabilities()
            .iter()
            .find(|c| c.resolved == rw_canonical)
            .expect("rw dir cap");

        assert_eq!(read_cap.access, AccessMode::Read);
        assert_eq!(write_cap.access, AccessMode::Write);
        assert_eq!(rw_cap.access, AccessMode::ReadWrite);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_from_profile_policy_add_deny_access_participates_in_overlap_validation() {
        let dir = tempdir().expect("tmpdir");
        let allowed = dir.path().join("allowed");
        let denied = allowed.join("child");
        std::fs::create_dir_all(&denied).expect("mkdir denied child");

        let profile_path = dir.path().join("policy-deny.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                    "meta": {{ "name": "policy-deny" }},
                    "policy": {{
                        "add_allow_readwrite": ["{}"],
                        "add_deny_access": ["{}"]
                    }}
                }}"#,
                allowed.display(),
                denied.display()
            ),
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let err = CapabilitySet::from_profile(&profile, workdir.path(), &args)
            .expect_err("profile deny overlap should fail on linux");
        assert!(
            err.to_string().contains("Landlock deny-overlap"),
            "unexpected error: {err}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_from_profile_policy_add_deny_access_tracks_symlink_target_for_overlap_validation() {
        let dir = tempdir().expect("tmpdir");
        let target_dir = dir.path().join("target");
        let denied_target = target_dir.join("child");
        std::fs::create_dir_all(&denied_target).expect("mkdir denied target");

        let symlink_dir = dir.path().join("symlinked");
        std::os::unix::fs::symlink(&denied_target, &symlink_dir).expect("create symlink");

        let profile_path = dir.path().join("policy-deny-symlink.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                    "meta": {{ "name": "policy-deny-symlink" }},
                    "policy": {{
                        "add_allow_readwrite": ["{}"],
                        "add_deny_access": ["{}"]
                    }}
                }}"#,
                target_dir.display(),
                symlink_dir.display()
            ),
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let err = CapabilitySet::from_profile(&profile, workdir.path(), &args)
            .expect_err("symlinked deny overlap should fail on linux");
        assert!(
            err.to_string().contains("Landlock deny-overlap"),
            "unexpected error: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_from_profile_policy_add_deny_access_removes_symlinked_file_grant() {
        let dir = tempdir().expect("tmpdir");
        let target = dir.path().join("real_gitconfig");
        std::fs::write(&target, "[user]\n").expect("write target");
        let target_canonical = target.canonicalize().expect("canonicalize target");
        let link = dir.path().join(".gitconfig");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        let profile_path = dir.path().join("policy-deny-file-symlink.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                    "meta": {{ "name": "policy-deny-file-symlink" }},
                    "filesystem": {{
                        "read_file": ["{}"]
                    }},
                    "policy": {{
                        "add_deny_access": ["{}"]
                    }}
                }}"#,
                target.display(),
                link.display()
            ),
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let (caps, _) =
            CapabilitySet::from_profile(&profile, workdir.path(), &args).expect("build caps");

        assert!(
            !caps
                .fs_capabilities()
                .iter()
                .any(|cap| cap.is_file && cap.resolved == target_canonical),
            "deny patch should remove the inherited file grant for the symlink target"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_from_profile_policy_add_deny_access_respects_override_deny_for_symlinked_file() {
        let dir = tempdir().expect("tmpdir");
        let target = dir.path().join("real_gitconfig");
        std::fs::write(&target, "[user]\n").expect("write target");
        let target_canonical = target.canonicalize().expect("canonicalize target");
        let link = dir.path().join(".gitconfig");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        let profile_path = dir.path().join("policy-deny-file-symlink-override.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                    "meta": {{ "name": "policy-deny-file-symlink-override" }},
                    "filesystem": {{
                        "read_file": ["{}"]
                    }},
                    "policy": {{
                        "add_deny_access": ["{}"]
                    }}
                }}"#,
                target.display(),
                link.display()
            ),
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let mut args = sandbox_args();
        args.override_deny = vec![target.clone()];

        let (caps, _) =
            CapabilitySet::from_profile(&profile, workdir.path(), &args).expect("build caps");

        assert!(
            caps.fs_capabilities()
                .iter()
                .any(|cap| cap.is_file && cap.resolved == target_canonical),
            "override should preserve the inherited file grant for the denied symlink target"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_from_profile_policy_override_deny_via_symlink_path() {
        let dir = tempdir().expect("tmpdir");
        let target = dir.path().join("real_gitconfig");
        std::fs::write(&target, "[user]\n").expect("write target");
        let target_canonical = target.canonicalize().expect("canonicalize target");
        let link = dir.path().join(".gitconfig");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        // Override via the symlink path (not the canonical target)
        let profile_path = dir.path().join("override-deny-symlink.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                    "meta": {{ "name": "override-deny-symlink" }},
                    "filesystem": {{
                        "read_file": ["{target}"]
                    }},
                    "policy": {{
                        "add_deny_access": ["{link}"],
                        "override_deny": ["{link}"]
                    }}
                }}"#,
                target = target.display(),
                link = link.display()
            ),
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let (caps, _) =
            CapabilitySet::from_profile(&profile, workdir.path(), &args).expect("build caps");

        assert!(
            caps.fs_capabilities()
                .iter()
                .any(|cap| cap.is_file && cap.resolved == target_canonical),
            "override via symlink path should preserve the file grant for the canonical target"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_from_profile_workdir_deny_env_extends_claude_code() {
        let workdir = tempdir().expect("workdir");
        std::fs::write(workdir.path().join(".env"), "SECRET=test").expect("write .env");

        let profile_path = workdir.path().join("deny-env.json");
        std::fs::write(
            &profile_path,
            r#"{
                "extends": "claude-code",
                "meta": { "name": "claude-code-deny-env" },
                "policy": {
                    "add_deny_access": ["$WORKDIR/.env"]
                }
            }"#,
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let args = sandbox_args();
        let (caps, _) =
            CapabilitySet::from_profile(&profile, workdir.path(), &args).expect("build caps");

        let rules = caps.platform_rules().join("\n");
        // On macOS, tempdir is under /var/folders which is a symlink to /private/var/folders.
        // The deny rule must use the canonical path so it matches the kernel-resolved path
        // that Seatbelt sees at runtime.
        let env_path = workdir.path().join(".env");
        let env_canonical = env_path.canonicalize().expect("canonicalize .env");

        // Check: does the deny rule use the canonical path?
        let has_canonical_deny = rules.contains(&format!(
            "deny file-read-data (literal \"{}\")",
            env_canonical.display()
        ));
        // Check: does the deny rule use the original (possibly non-canonical) path?
        let has_original_deny = rules.contains(&format!(
            "deny file-read-data (literal \"{}\")",
            env_path.display()
        ));

        // The deny must cover the canonical path, otherwise Seatbelt won't enforce it
        assert!(
            has_canonical_deny,
            "deny rule must use canonical path {}.\n\
             Has original path deny: {}\n\
             Original path: {}\n\
             Canonical path: {}\n\
             All platform rules:\n{}",
            env_canonical.display(),
            has_original_deny,
            env_path.display(),
            env_canonical.display(),
            rules
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_from_profile_policy_add_deny_access_emits_seatbelt_rules() {
        let dir = tempdir().expect("tmpdir");
        let denied = dir.path().join("denied");
        std::fs::create_dir_all(&denied).expect("mkdir denied");

        let profile_path = dir.path().join("policy-deny-macos.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                    "meta": {{ "name": "policy-deny-macos" }},
                    "policy": {{
                        "add_deny_access": ["{}"]
                    }}
                }}"#,
                denied.display()
            ),
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let (caps, _) =
            CapabilitySet::from_profile(&profile, workdir.path(), &args).expect("build caps");

        let rules = caps.platform_rules().join("\n");
        assert!(
            rules.contains("deny file-read-data"),
            "expected macOS deny read rule, got:\n{}",
            rules
        );
        assert!(
            rules.contains("deny file-write*"),
            "expected macOS deny write rule, got:\n{}",
            rules
        );
    }

    #[test]
    fn test_from_profile_policy_override_deny_punches_through_deny_group() {
        let dir = tempdir().expect("tmpdir");
        let denied = dir.path().join("denied_dir");
        std::fs::create_dir_all(&denied).expect("mkdir denied");

        let profile_path = dir.path().join("override-deny-profile.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                    "meta": {{ "name": "override-deny-test" }},
                    "policy": {{
                        "add_allow_readwrite": ["{path}"],
                        "add_deny_access": ["{path}"],
                        "override_deny": ["{path}"]
                    }}
                }}"#,
                path = denied.display()
            ),
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let (caps, _) =
            CapabilitySet::from_profile(&profile, workdir.path(), &args).expect("build caps");

        // The allow should survive because override_deny punches through the deny
        let canonical = denied.canonicalize().expect("canonicalize");
        assert!(
            caps.fs_capabilities()
                .iter()
                .any(|cap| !cap.is_file && cap.resolved == canonical),
            "override_deny should preserve the directory grant despite deny group"
        );
    }

    #[test]
    fn test_from_profile_policy_override_deny_requires_matching_grant() {
        // Override path is under temp dir which is covered by system groups,
        // but the grant check requires user-intent sources (User/Profile),
        // so group coverage is not sufficient.
        let dir = tempdir().expect("tmpdir");
        let denied = dir.path().join("denied_no_grant");
        std::fs::create_dir_all(&denied).expect("mkdir denied");

        let profile_path = dir.path().join("override-deny-no-grant.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                    "meta": {{ "name": "override-deny-no-grant" }},
                    "policy": {{
                        "add_deny_access": ["{path}"],
                        "override_deny": ["{path}"]
                    }}
                }}"#,
                path = denied.display()
            ),
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = sandbox_args();

        let err = CapabilitySet::from_profile(&profile, workdir.path(), &args)
            .expect_err("override_deny without user-intent grant should fail");
        assert!(
            err.to_string().contains("no matching grant"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_from_profile_with_groups() {
        let profile = crate::profile::load_profile("claude-code")
            .expect("Failed to load claude-code profile");

        let workdir = tempdir().expect("Failed to create temp dir");
        let args = sandbox_args();

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

    #[test]
    fn test_cli_allow_upgrades_profile_read_path() {
        // Regression test: a profile sets a path as read-only, and --allow on
        // the CLI should upgrade it to ReadWrite. Previously, path_covered()
        // in add_cli_overrides() silently dropped the CLI entry because it
        // only checked path containment, not access mode.
        let dir = tempdir().expect("tmpdir");
        let target = dir.path().join("readonly_dir");
        std::fs::create_dir(&target).expect("create target dir");

        let profile_path = dir.path().join("test-profile.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                    "meta": {{ "name": "test-upgrade" }},
                    "filesystem": {{ "read": ["{}"] }}
                }}"#,
                target.display()
            ),
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = SandboxArgs {
            allow: vec![target.clone()],
            ..sandbox_args()
        };

        let (caps, _) =
            CapabilitySet::from_profile(&profile, workdir.path(), &args).expect("build caps");

        let canonical = target.canonicalize().expect("canonicalize target");
        let cap = caps
            .fs_capabilities()
            .iter()
            .find(|c| c.resolved == canonical)
            .expect("target path should be in capabilities");

        assert_eq!(
            cap.access,
            AccessMode::ReadWrite,
            "CLI --allow should upgrade profile read-only path to ReadWrite, got {:?}",
            cap.access,
        );
    }

    #[test]
    fn test_cli_write_merges_with_profile_read_path() {
        // Same regression but with --write instead of --allow.
        // Profile read + CLI write should merge to ReadWrite.
        let dir = tempdir().expect("tmpdir");
        let target = dir.path().join("readonly_dir");
        std::fs::create_dir(&target).expect("create target dir");

        let profile_path = dir.path().join("test-profile.json");
        std::fs::write(
            &profile_path,
            format!(
                r#"{{
                    "meta": {{ "name": "test-merge" }},
                    "filesystem": {{ "read": ["{}"] }}
                }}"#,
                target.display()
            ),
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = SandboxArgs {
            write: vec![target.clone()],
            ..sandbox_args()
        };

        let (caps, _) =
            CapabilitySet::from_profile(&profile, workdir.path(), &args).expect("build caps");

        let canonical = target.canonicalize().expect("canonicalize target");
        let cap = caps
            .fs_capabilities()
            .iter()
            .find(|c| c.resolved == canonical)
            .expect("target path should be in capabilities");

        assert_eq!(
            cap.access,
            AccessMode::ReadWrite,
            "CLI --write + profile read should merge to ReadWrite, got {:?}",
            cap.access,
        );
    }

    #[test]
    fn test_from_profile_allow_net_overrides_proxy_mode() {
        let profile = crate::profile::load_profile("claude-code")
            .expect("Failed to load claude-code profile");
        let workdir = tempdir().expect("workdir");
        let args = SandboxArgs {
            allow_net: true,
            ..sandbox_args()
        };

        let (caps, _) =
            CapabilitySet::from_profile(&profile, workdir.path(), &args).expect("build caps");

        assert_eq!(*caps.network_mode(), nono::NetworkMode::AllowAll);
    }

    #[test]
    fn test_from_profile_allow_net_overrides_blocked_network() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("blocked.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "blocked" },
                "filesystem": { "allow": ["/tmp"] },
                "network": { "block": true }
            }"#,
        )
        .expect("write profile");
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");

        let workdir = tempdir().expect("workdir");
        let args = SandboxArgs {
            allow_net: true,
            ..sandbox_args()
        };

        let (caps, _) =
            CapabilitySet::from_profile(&profile, workdir.path(), &args).expect("build caps");

        assert_eq!(*caps.network_mode(), nono::NetworkMode::AllowAll);
    }

    #[test]
    fn test_from_profile_process_info_mode_same_sandbox() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("pim-test.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "pim-test" },
                "filesystem": { "allow": ["/tmp"] },
                "security": { "process_info_mode": "allow_same_sandbox" }
            }"#,
        )
        .expect("write profile");
        let workdir = tempdir().expect("tmpdir");
        let args = sandbox_args();
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");
        let (caps, _) =
            CapabilitySet::from_profile(&profile, workdir.path(), &args).expect("build caps");
        assert_eq!(
            caps.process_info_mode(),
            nono::ProcessInfoMode::AllowSameSandbox,
            "profile process_info_mode should propagate to CapabilitySet"
        );
    }

    #[test]
    fn test_from_profile_ipc_mode_full() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("ipc-test.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "ipc-test" },
                "filesystem": { "allow": ["/tmp"] },
                "security": { "ipc_mode": "full" }
            }"#,
        )
        .expect("write profile");
        let workdir = tempdir().expect("tmpdir");
        let args = sandbox_args();
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");
        let (caps, _) =
            CapabilitySet::from_profile(&profile, workdir.path(), &args).expect("build caps");
        assert_eq!(
            caps.ipc_mode(),
            nono::IpcMode::Full,
            "profile ipc_mode should propagate to CapabilitySet"
        );
    }

    #[test]
    fn test_from_profile_ipc_mode_shared_memory_only() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("ipc-test-shm.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "ipc-test-shm" },
                "filesystem": { "allow": ["/tmp"] },
                "security": { "ipc_mode": "shared_memory_only" }
            }"#,
        )
        .expect("write profile");
        let workdir = tempdir().expect("tmpdir");
        let args = sandbox_args();
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");
        let (caps, _) =
            CapabilitySet::from_profile(&profile, workdir.path(), &args).expect("build caps");
        assert_eq!(
            caps.ipc_mode(),
            nono::IpcMode::SharedMemoryOnly,
            "profile ipc_mode: shared_memory_only should propagate to CapabilitySet"
        );
    }

    #[test]
    fn test_from_profile_ipc_mode_default() {
        let dir = tempdir().expect("tmpdir");
        let profile_path = dir.path().join("ipc-test-default.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "ipc-test-default" },
                "filesystem": { "allow": ["/tmp"] },
                "security": {}
            }"#,
        )
        .expect("write profile");
        let workdir = tempdir().expect("tmpdir");
        let args = sandbox_args();
        let profile = crate::profile::load_profile_from_path(&profile_path).expect("load profile");
        let (caps, _) =
            CapabilitySet::from_profile(&profile, workdir.path(), &args).expect("build caps");
        assert_eq!(
            caps.ipc_mode(),
            nono::IpcMode::SharedMemoryOnly,
            "absent profile ipc_mode should default to SharedMemoryOnly"
        );
    }
}
