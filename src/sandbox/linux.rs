use crate::capability::{CapabilitySet, FsAccess};
use crate::error::{NonoError, Result};
use landlock::{
    Access, AccessFs, AccessNet, BitFlags, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, ABI,
};
use std::path::Path;
use tracing::{debug, info, warn};

/// The target ABI version we support (highest we know about)
const TARGET_ABI: ABI = ABI::V5;

/// System paths that need read+execute access for executables to run
const SYSTEM_READ_PATHS: &[&str] = &[
    // Executables
    "/bin",
    "/usr/bin",
    "/usr/local/bin",
    "/sbin",
    "/usr/sbin",
    // Shared libraries
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
    "/usr/local/lib",
    "/usr/local/lib64",
    // Dynamic linker configuration
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    // System configuration commonly needed by programs
    "/etc/passwd",
    "/etc/group",
    "/etc/nsswitch.conf",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/machine-id",
    // Locale and timezone data
    "/usr/share/locale",
    "/usr/share/zoneinfo",
    "/etc/localtime",
    "/etc/timezone",
    // SSL certificates
    "/etc/ssl",
    "/etc/pki",
    "/usr/share/ca-certificates",
    // Terminfo for terminal apps
    "/usr/share/terminfo",
    "/lib/terminfo",
    "/etc/terminfo",
    // Device files - only safe, commonly needed devices
    // (NOT /dev as a whole, which would expose /dev/sda, /dev/mem, etc.)
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
    "/dev/full",
    "/dev/tty",
    "/dev/console",
    "/dev/stdin",
    "/dev/stdout",
    "/dev/stderr",
    "/dev/fd",
    "/dev/pts",
    // Proc filesystem (needed for many operations)
    "/proc",
    // Sys filesystem (some tools need it)
    "/sys",
    // Run directory (for runtime data)
    "/run",
    "/var/run",
];

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
/// Note: RemoveFile, RemoveDir, and Truncate are intentionally excluded
/// to prevent destructive operations even in allowed directories.
/// This is a defense-in-depth measure against accidental or malicious deletion.
fn access_to_landlock(access: FsAccess, _abi: ABI) -> BitFlags<AccessFs> {
    match access {
        FsAccess::Read => AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute,
        FsAccess::Write => {
            // Write access allows creating and modifying files, but NOT deleting or truncating.
            // This prevents destructive operations like `rm -rf` or truncating files to zero bytes.
            // Excluded operations:
            //   - RemoveFile: unlink syscall (file deletion)
            //   - RemoveDir: rmdir syscall (directory deletion)
            //   - Truncate: truncate/ftruncate syscalls (can zero out files)
            AccessFs::WriteFile
                | AccessFs::MakeChar
                | AccessFs::MakeDir
                | AccessFs::MakeReg
                | AccessFs::MakeSock
                | AccessFs::MakeFifo
                | AccessFs::MakeBlock
                | AccessFs::MakeSym
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
    let read_access = access_to_landlock(FsAccess::Read, TARGET_ABI);
    for path_str in SYSTEM_READ_PATHS {
        let path = Path::new(path_str);
        if path.exists() {
            match PathFd::new(path) {
                Ok(path_fd) => {
                    debug!("Adding system read rule: {}", path_str);
                    ruleset = ruleset.add_rule(PathBeneath::new(path_fd, read_access))?;
                }
                Err(e) => {
                    debug!("Skipping system path {} (cannot open: {})", path_str, e);
                }
            }
        } else {
            debug!("Skipping system path {} (does not exist)", path_str);
        }
    }

    // Add rules for each user-specified filesystem capability
    for cap in &caps.fs {
        let access = access_to_landlock(cap.access, TARGET_ABI);

        debug!(
            "Adding rule: {} with access {:?}",
            cap.resolved.display(),
            access
        );

        let path_fd = PathFd::new(&cap.resolved)?;
        ruleset = ruleset.add_rule(PathBeneath::new(path_fd, access))?;
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
        // Verify destructive operations are NOT included
        assert!(!write.contains(AccessFs::RemoveFile));
        assert!(!write.contains(AccessFs::RemoveDir));

        let rw = access_to_landlock(FsAccess::ReadWrite, abi);
        assert!(rw.contains(AccessFs::ReadFile));
        assert!(rw.contains(AccessFs::WriteFile));
        // Verify destructive operations are NOT included in ReadWrite either
        assert!(!rw.contains(AccessFs::RemoveFile));
        assert!(!rw.contains(AccessFs::RemoveDir));
    }
}
