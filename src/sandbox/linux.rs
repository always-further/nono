use crate::capability::{CapabilitySet, FsAccess};
use crate::config;
use crate::error::{NonoError, Result};
use landlock::{
    Access, AccessFs, AccessNet, BitFlags, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, ABI,
};
use std::fs;
use std::path::Path;
use tracing::{debug, info, warn};

/// The target ABI version we support (highest we know about)
const TARGET_ABI: ABI = ABI::V5;

/// Check if Landlock is supported on this system
pub fn is_supported() -> bool {
    // Try to create a minimal ruleset to check if Landlock is available
    Ruleset::default()
        .handle_access(AccessFs::from_all(TARGET_ABI))
        .and_then(|r| r.create())
        .is_ok()
}

/// Get information about Landlock support
pub fn support_info() -> String {
    // Try to create a ruleset and check the status
    match Ruleset::default()
        .handle_access(AccessFs::from_all(TARGET_ABI))
        .and_then(|r| r.create())
    {
        Ok(_) => format!("Landlock available (targeting ABI v{:?})", TARGET_ABI),
        Err(_) => {
            "Landlock not available. Requires Linux kernel 5.13+ with Landlock enabled.".to_string()
        }
    }
}

/// Convert FsAccess to Landlock AccessFs flags
/// RemoveFile, RemoveDir, Truncate, and Refer are included to support atomic writes
/// (write to .tmp → rename to target), which is the standard pattern used by
/// most applications for safe config updates.
fn access_to_landlock(access: FsAccess, _abi: ABI) -> BitFlags<AccessFs> {
    match access {
        FsAccess::Read => AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute,
        FsAccess::Write => {
            // Write access includes all operations needed for normal file manipulation:
            // - WriteFile: modify file contents
            // - MakeReg/MakeDir/etc: create new files/directories
            // - RemoveFile: delete files (required for rename() for atomic writes)
            // - RemoveDir: delete directories (required for rename() directories for atomic writes)
            // - Refer: rename/hard link operations (required for atomic writes)
            // - Truncate: change file size (common write operation, ABI v3+)
            //
            // Rationale: When a user grants --write to a directory, they expect
            // the sandboxed process to be able to create, modify, AND delete files
            // and directories within that directory. Atomic writes (writes to .tmp -> rename to
            // target) require RemoveFile and RemoveDir (for files and directories respectively).
            AccessFs::WriteFile
                | AccessFs::MakeChar
                | AccessFs::MakeDir
                | AccessFs::MakeReg
                | AccessFs::MakeSock
                | AccessFs::MakeFifo
                | AccessFs::MakeBlock
                | AccessFs::MakeSym
                | AccessFs::RemoveFile
                | AccessFs::RemoveDir
                | AccessFs::Refer
                | AccessFs::Truncate
        }
        FsAccess::ReadWrite => {
            access_to_landlock(FsAccess::Read, _abi) | access_to_landlock(FsAccess::Write, _abi)
        }
    }
}

/// Apply Landlock sandbox with the given capabilities
pub fn apply(caps: &CapabilitySet) -> Result<()> {
    info!("Using Landlock ABI {:?}", TARGET_ABI);

    // Determine which access rights to handle based on ABI
    let handled_fs = AccessFs::from_all(TARGET_ABI);

    debug!("Handling filesystem access: {:?}", handled_fs);

    // Create the ruleset (Ruleset::default() auto-probes kernel support)
    // Start with filesystem access
    let ruleset_builder = Ruleset::default()
        .handle_access(handled_fs)
        .map_err(|e| NonoError::SandboxInit(format!("Failed to handle fs access: {}", e)))?;

    // Add network access handling if blocking network (ABI V4+ required)
    let ruleset_builder = if caps.net_block {
        let handled_net = AccessNet::from_all(TARGET_ABI);
        if !handled_net.is_empty() {
            debug!("Handling network access (blocking): {:?}", handled_net);
            ruleset_builder.handle_access(handled_net).map_err(|e| {
                NonoError::SandboxInit(format!("Failed to handle net access: {}", e))
            })?
        } else {
            warn!("Network blocking requested but kernel ABI doesn't support it (requires V4+)");
            ruleset_builder
        }
    } else {
        ruleset_builder
    };

    let mut ruleset = ruleset_builder
        .create()
        .map_err(|e| NonoError::SandboxInit(format!("Failed to create ruleset: {}", e)))?;

    // Add read+execute access to system paths needed for executables to run
    // These paths are loaded from the embedded security-lists.toml
    let read_access = access_to_landlock(FsAccess::Read, TARGET_ABI);
    let system_paths = config::get_system_read_paths();
    for path_str in &system_paths {
        let path = Path::new(path_str);
        if !path.exists() {
            debug!("Skipping system path {} (does not exist)", path_str);
            continue;
        }

        // Some distro device aliases (notably /dev/stdin|stdout|stderr) are symlinks
        // to ephemeral procfs FDs (e.g. /proc/self/fd/1), which can fail Landlock
        // rule insertion with EBADFD on some kernels. Skip symlink aliases and rely
        // on stable paths like /dev/fd and /dev/pts already in the system path list.
        if let Ok(meta) = fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() {
                warn!("Skipping system path {} (symlink alias)", path_str);
                continue;
            }
        }

        let path_fd = match PathFd::new(path) {
            Ok(fd) => fd,
            Err(e) => {
                warn!("Skipping system path {} (cannot open: {})", path_str, e);
                continue;
            }
        };

        debug!("Adding system read rule: {}", path_str);
        ruleset = ruleset
            .add_rule(PathBeneath::new(path_fd, read_access))
            .map_err(|e| {
                NonoError::SandboxInit(format!(
                    "Cannot add Landlock rule for system path {}: {}",
                    path_str, e
                ))
            })?;
    }

    // Add rules for each user-specified filesystem capability
    // These MUST succeed - user explicitly requested these capabilities
    // Failing silently would violate the principle of least surprise and fail-secure design
    for cap in &caps.fs {
        let access = access_to_landlock(cap.access, TARGET_ABI);

        debug!(
            "Adding rule: {} with access {:?}",
            cap.resolved.display(),
            access
        );

        let path_fd = PathFd::new(&cap.resolved)?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(path_fd, access))
            .map_err(|e| {
                NonoError::SandboxInit(format!(
                    "Cannot add Landlock rule for {}: {} (filesystem may not support Landlock)",
                    cap.resolved.display(),
                    e
                ))
            })?;
    }

    // Apply the ruleset - THIS IS IRREVERSIBLE
    let status = ruleset
        .restrict_self()
        .map_err(|e| NonoError::SandboxInit(format!("Failed to restrict self: {}", e)))?;

    match status.ruleset {
        landlock::RulesetStatus::FullyEnforced => {
            info!("Landlock sandbox fully enforced");
        }
        landlock::RulesetStatus::PartiallyEnforced => {
            // This is normal - the kernel supports a subset of features we requested.
            // The sandbox is still active and enforcing restrictions.
            debug!("Landlock sandbox enforced in best-effort mode");
        }
        landlock::RulesetStatus::NotEnforced => {
            return Err(NonoError::SandboxInit(
                "Landlock sandbox was not enforced".to_string(),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_supported() {
        // This test will pass or fail depending on kernel version
        // Just verify it doesn't panic
        let _ = is_supported();
    }

    #[test]
    fn test_support_info() {
        let info = support_info();
        assert!(!info.is_empty());
    }

    #[test]
    fn test_access_conversion() {
        let abi = ABI::V3;

        let read = access_to_landlock(FsAccess::Read, abi);
        assert!(read.contains(AccessFs::ReadFile));
        assert!(!read.contains(AccessFs::WriteFile));

        let write = access_to_landlock(FsAccess::Write, abi);
        assert!(write.contains(AccessFs::WriteFile));
        assert!(!write.contains(AccessFs::ReadFile));
        // Verify atomic write operations ARE included (RemoveFile, RemoveDir, Refer, Truncate)
        assert!(write.contains(AccessFs::RemoveFile));
        assert!(write.contains(AccessFs::RemoveDir));
        assert!(write.contains(AccessFs::Refer));
        assert!(write.contains(AccessFs::Truncate));

        let rw = access_to_landlock(FsAccess::ReadWrite, abi);
        assert!(rw.contains(AccessFs::ReadFile));
        assert!(rw.contains(AccessFs::WriteFile));
        // Verify atomic write operations ARE included in ReadWrite too
        assert!(rw.contains(AccessFs::RemoveFile));
        assert!(rw.contains(AccessFs::RemoveDir));
        assert!(rw.contains(AccessFs::Refer));
        assert!(rw.contains(AccessFs::Truncate));
    }
}
