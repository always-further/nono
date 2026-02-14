//! Linux sandbox implementation using Landlock LSM

use crate::capability::{AccessMode, CapabilitySet};
use crate::error::{NonoError, Result};
use crate::sandbox::SupportInfo;
use landlock::{
    Access, AccessFs, AccessNet, BitFlags, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, ABI,
};
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
pub fn support_info() -> SupportInfo {
    // Try to create a ruleset and check the status
    match Ruleset::default()
        .handle_access(AccessFs::from_all(TARGET_ABI))
        .and_then(|r| r.create())
    {
        Ok(_) => SupportInfo {
            is_supported: true,
            platform: "linux",
            details: format!("Landlock available (targeting ABI v{:?})", TARGET_ABI),
        },
        Err(_) => SupportInfo {
            is_supported: false,
            platform: "linux",
            details: "Landlock not available. Requires Linux kernel 5.13+ with Landlock enabled."
                .to_string(),
        },
    }
}

/// Convert AccessMode to Landlock AccessFs flags
///
/// Note: RemoveDir is intentionally excluded to prevent directory deletion.
/// RemoveFile, Truncate, and Refer are included to support atomic writes
/// (write to .tmp → rename to target), which is the standard pattern used by
/// most applications for safe config updates.
fn access_to_landlock(access: AccessMode, _abi: ABI) -> BitFlags<AccessFs> {
    match access {
        AccessMode::Read => AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute,
        AccessMode::Write => {
            // Write access includes all operations needed for normal file manipulation:
            // - WriteFile: modify file contents
            // - MakeReg/MakeDir/etc: create new files/directories
            // - RemoveFile: delete files (required for rename() in atomic writes)
            // - Refer: rename/hard link operations (required for atomic writes)
            // - Truncate: change file size (common write operation, ABI v3+)
            //
            // Still excluded:
            // - RemoveDir: directory deletion (more dangerous than file deletion)
            AccessFs::WriteFile
                | AccessFs::MakeChar
                | AccessFs::MakeDir
                | AccessFs::MakeReg
                | AccessFs::MakeSock
                | AccessFs::MakeFifo
                | AccessFs::MakeBlock
                | AccessFs::MakeSym
                | AccessFs::RemoveFile
                | AccessFs::Refer
                | AccessFs::Truncate
        }
        AccessMode::ReadWrite => {
            access_to_landlock(AccessMode::Read, _abi) | access_to_landlock(AccessMode::Write, _abi)
        }
    }
}

/// Apply Landlock sandbox with the given capabilities
///
/// This is a pure primitive - it applies ONLY the capabilities provided.
/// The caller is responsible for including all necessary paths (including
/// system paths like /usr, /lib, /bin if executables need to run).
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
    let ruleset_builder = if caps.is_network_blocked() {
        let handled_net = AccessNet::from_all(TARGET_ABI);
        if !handled_net.is_empty() {
            debug!("Handling network access (blocking): {:?}", handled_net);
            ruleset_builder.handle_access(handled_net).map_err(|e| {
                NonoError::SandboxInit(format!("Failed to handle net access: {}", e))
            })?
        } else {
            warn!("Network blocking requested but kernel ABI doesn't support it (requires V4+)");
            eprintln!("WARNING: Network blocking requested but kernel Landlock ABI doesn't support it (requires V4+). Network access will NOT be restricted.");
            ruleset_builder
        }
    } else {
        ruleset_builder
    };

    let mut ruleset = ruleset_builder
        .create()
        .map_err(|e| NonoError::SandboxInit(format!("Failed to create ruleset: {}", e)))?;

    // Add rules for each filesystem capability
    // These MUST succeed - caller explicitly requested these capabilities
    // Failing silently would violate the principle of least surprise and fail-secure design
    for cap in caps.fs_capabilities() {
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
        assert!(!info.details.is_empty());
    }

    #[test]
    fn test_access_conversion() {
        let abi = ABI::V3;

        let read = access_to_landlock(AccessMode::Read, abi);
        assert!(read.contains(AccessFs::ReadFile));
        assert!(!read.contains(AccessFs::WriteFile));

        let write = access_to_landlock(AccessMode::Write, abi);
        assert!(write.contains(AccessFs::WriteFile));
        assert!(!write.contains(AccessFs::ReadFile));
        // Verify atomic write operations ARE included (RemoveFile, Refer, Truncate)
        assert!(write.contains(AccessFs::RemoveFile));
        assert!(write.contains(AccessFs::Refer));
        assert!(write.contains(AccessFs::Truncate));
        // Verify directory removal is still NOT included (defense in depth)
        assert!(!write.contains(AccessFs::RemoveDir));

        let rw = access_to_landlock(AccessMode::ReadWrite, abi);
        assert!(rw.contains(AccessFs::ReadFile));
        assert!(rw.contains(AccessFs::WriteFile));
        // Verify atomic write operations ARE included in ReadWrite too
        assert!(rw.contains(AccessFs::RemoveFile));
        assert!(rw.contains(AccessFs::Refer));
        assert!(rw.contains(AccessFs::Truncate));
        // Verify directory removal is still NOT included
        assert!(!rw.contains(AccessFs::RemoveDir));
    }
}
