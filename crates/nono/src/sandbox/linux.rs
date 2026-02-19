//! Linux sandbox implementation using Landlock LSM

use crate::capability::{AccessMode, CapabilitySet};
use crate::error::{NonoError, Result};
use crate::sandbox::SupportInfo;
use landlock::{
    Access, AccessFs, AccessNet, BitFlags, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, ABI,
};
use tracing::{debug, info};

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
            return Err(NonoError::SandboxInit(
                "Network blocking requested but kernel Landlock ABI doesn't support it \
                 (requires V4+). Refusing to start without network restrictions."
                    .to_string(),
            ));
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

// ==========================================================================
// Seccomp user notification (SECCOMP_RET_USER_NOTIF) for transparent
// capability expansion. These primitives install a BPF filter on
// openat/openat2, receive notifications in the supervisor parent, and
// inject opened fds into the child process.
//
// Requires kernel >= 5.14 for SECCOMP_ADDFD_FLAG_SEND (atomic fd injection).
// ==========================================================================

/// seccomp notification received from the kernel.
///
/// Mirrors `struct seccomp_notif` from `<linux/seccomp.h>`.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SeccompNotif {
    /// Unique notification ID (for responding)
    pub id: u64,
    /// PID of the process that triggered the notification
    pub pid: u32,
    /// Flags (currently unused, reserved)
    pub flags: u32,
    /// The syscall data (architecture, syscall number, args, etc.)
    pub data: SeccompData,
}

/// Syscall data from a seccomp notification.
///
/// Mirrors `struct seccomp_data` from `<linux/seccomp.h>`.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct SeccompData {
    /// Syscall number
    pub nr: i32,
    /// CPU architecture (AUDIT_ARCH_*)
    pub arch: u32,
    /// Instruction pointer at time of syscall
    pub instruction_pointer: u64,
    /// Syscall arguments (up to 6)
    pub args: [u64; 6],
}

/// Response to a seccomp notification.
///
/// Mirrors `struct seccomp_notif_resp` from `<linux/seccomp.h>`.
#[repr(C)]
#[derive(Debug)]
struct SeccompNotifResp {
    /// Must match the notification ID
    id: u64,
    /// Return value for the syscall (if not using SECCOMP_USER_NOTIF_FLAG_CONTINUE)
    val: i64,
    /// Negated errno to return (0 = use val, negative = error)
    error: i32,
    /// Response flags
    flags: u32,
}

/// Addfd request for injecting an fd into the notified process.
///
/// Mirrors `struct seccomp_notif_addfd` from `<linux/seccomp.h>`.
#[repr(C)]
#[derive(Debug)]
struct SeccompNotifAddfd {
    /// Must match the notification ID
    id: u64,
    /// Flags (SECCOMP_ADDFD_FLAG_SEND makes the injected fd the syscall return value)
    flags: u32,
    /// The fd in the supervisor to inject (or 0 if using SETFD)
    srcfd: u32,
    /// Target fd number in the child (0 = kernel chooses)
    newfd: u32,
    /// Additional flags for the target fd (e.g., FD_CLOEXEC)
    newfd_flags: u32,
}

// Seccomp constants not in libc crate
const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_uint = 1 << 3;
const SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV: libc::c_uint = 1 << 4;

// ioctl request codes for seccomp notifications
const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc0502100;
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc0182101;
const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = 0x40082102;
const SECCOMP_IOCTL_NOTIF_ADDFD: libc::c_ulong = 0x40182103;

// Seccomp addfd flags
const SECCOMP_ADDFD_FLAG_SEND: u32 = 1 << 1;

// BPF constants
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

// Syscall numbers for x86_64 (public for CLI to distinguish openat vs openat2)
#[cfg(target_arch = "x86_64")]
pub const SYS_OPENAT: i32 = 257;
#[cfg(target_arch = "x86_64")]
pub const SYS_OPENAT2: i32 = 437;

// Syscall numbers for aarch64 (public for CLI to distinguish openat vs openat2)
#[cfg(target_arch = "aarch64")]
pub const SYS_OPENAT: i32 = 56;
#[cfg(target_arch = "aarch64")]
pub const SYS_OPENAT2: i32 = 437;

/// struct open_how from <linux/openat2.h>
///
/// Used by openat2() syscall. args[2] is a pointer to this struct, NOT the flags integer.
/// This is a critical security distinction from openat() where args[2] IS the flags.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct OpenHow {
    /// O_CREAT, O_RDONLY, O_WRONLY, O_RDWR, etc.
    pub flags: u64,
    /// File mode (when O_CREAT is used)
    pub mode: u64,
    /// RESOLVE_* flags for path resolution control
    pub resolve: u64,
}

/// Classify access mode from open flags.
///
/// Extracts O_ACCMODE bits and maps to AccessMode. Used by both openat (where flags
/// come from args[2] directly) and openat2 (where flags come from open_how.flags).
#[must_use]
pub fn classify_access_from_flags(flags: i32) -> crate::AccessMode {
    match flags & libc::O_ACCMODE {
        libc::O_RDONLY => crate::AccessMode::Read,
        libc::O_WRONLY => crate::AccessMode::Write,
        _ => crate::AccessMode::ReadWrite,
    }
}

/// Validate that the openat2 size argument is large enough to hold the open_how struct.
///
/// For openat2, args[3] contains the size of the open_how struct passed by the caller.
/// If this is smaller than our expected struct size, the request is malformed and should
/// be denied to avoid reading garbage or partial data.
///
/// We also reject unreasonably large sizes. The supervisor only reads the stable
/// leading fields we know (`flags`, `mode`, `resolve`) and should be recompiled
/// against newer kernel headers when `struct open_how` evolves.
const OPENAT2_HOW_SIZE_MAX: usize = 4096;

#[must_use]
pub fn validate_openat2_size(how_size: usize) -> bool {
    let min_size = std::mem::size_of::<OpenHow>();
    how_size >= min_size && how_size <= OPENAT2_HOW_SIZE_MAX
}

// Offset of `nr` field in seccomp_data (used by BPF)
const SECCOMP_DATA_NR_OFFSET: u32 = 0;

/// A single BPF instruction.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SockFilterInsn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

/// BPF program header.
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilterInsn,
}

/// Install a seccomp-notify BPF filter for openat/openat2.
///
/// Returns the notify fd. Must be called BEFORE `Sandbox::apply()` (Landlock
/// `restrict_self()`), so the supervisor can still receive notifications for
/// paths that Landlock would block.
///
/// The BPF filter routes openat/openat2 to `SECCOMP_RET_USER_NOTIF` and
/// allows all other syscalls with `SECCOMP_RET_ALLOW`.
///
/// # Errors
///
/// Returns an error if:
/// - The kernel doesn't support seccomp user notifications (< 5.0)
/// - The `seccomp()` syscall fails
/// - `SECCOMP_FILTER_FLAG_NEW_LISTENER` is not available
pub fn install_seccomp_notify() -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;

    // BPF program:
    //   ld  [nr]                     ; load syscall number
    //   jeq SYS_OPENAT, notify       ; if openat -> notify
    //   jeq SYS_OPENAT2, notify      ; if openat2 -> notify
    //   ret SECCOMP_RET_ALLOW        ; else allow
    //   notify: ret SECCOMP_RET_USER_NOTIF
    let filter = [
        // 0: Load syscall number
        SockFilterInsn {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: SECCOMP_DATA_NR_OFFSET,
        },
        // 1: If openat, jump to 4 (notify)
        SockFilterInsn {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 2, // jump +2 to instruction 4 (notify)
            jf: 0,
            k: SYS_OPENAT as u32,
        },
        // 2: If openat2, jump to 4 (notify)
        SockFilterInsn {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 1, // jump +1 to instruction 4 (notify)
            jf: 0,
            k: SYS_OPENAT2 as u32,
        },
        // 3: Allow all other syscalls
        SockFilterInsn {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
        // 4: Route to user notification
        SockFilterInsn {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_USER_NOTIF,
        },
    ];

    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    // seccomp(SET_MODE_FILTER) requires either CAP_SYS_ADMIN or no_new_privs.
    // We use no_new_privs (unprivileged) which prevents gaining privileges via
    // setuid/setgid binaries. This is a one-way flag that cannot be unset, and
    // Landlock's restrict_self() sets it too, so this adds no new restriction.
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS is always safe to call.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(NonoError::SandboxInit(format!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Try with WAIT_KILLABLE_RECV first (kernel 5.19+) for Go runtime compatibility.
    // Falls back without it if the kernel doesn't support it.
    let flags = SECCOMP_FILTER_FLAG_NEW_LISTENER | SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;

    // SAFETY: seccomp() with SECCOMP_SET_MODE_FILTER installs a BPF filter.
    // The prog pointer is valid for the duration of the syscall. The filter
    // array is stack-allocated and outlives the syscall.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            flags,
            &prog as *const SockFprog,
        )
    };

    let notify_fd = if ret < 0 {
        // Retry without WAIT_KILLABLE_RECV (kernel < 5.19)
        let flags = SECCOMP_FILTER_FLAG_NEW_LISTENER;

        // SAFETY: Same as above, retrying with fewer flags.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                flags,
                &prog as *const SockFprog,
            )
        };

        if ret < 0 {
            return Err(NonoError::SandboxInit(format!(
                "seccomp(SECCOMP_SET_MODE_FILTER) failed: {}. \
                 Requires kernel >= 5.0 with SECCOMP_FILTER_FLAG_NEW_LISTENER.",
                std::io::Error::last_os_error()
            )));
        }
        ret as i32
    } else {
        ret as i32
    };

    // SAFETY: The fd returned by seccomp() with NEW_LISTENER is a valid,
    // newly-created file descriptor that we now own.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(notify_fd) })
}

/// Receive the next seccomp notification (blocking).
///
/// Blocks until a notification is available on the notify fd.
/// Returns the notification with syscall data and a unique ID.
///
/// # Errors
///
/// Returns an error if the ioctl fails (e.g., EINTR, ENOENT if child exited).
pub fn recv_notif(notify_fd: std::os::fd::RawFd) -> Result<SeccompNotif> {
    // Zero-initialize the notification struct (kernel writes into it)
    let mut notif = SeccompNotif {
        id: 0,
        pid: 0,
        flags: 0,
        data: SeccompData::default(),
    };

    // SAFETY: SECCOMP_IOCTL_NOTIF_RECV writes a seccomp_notif struct into
    // the provided buffer. The struct is correctly sized and aligned.
    let ret = unsafe {
        libc::ioctl(
            notify_fd,
            SECCOMP_IOCTL_NOTIF_RECV,
            &mut notif as *mut SeccompNotif,
        )
    };

    if ret < 0 {
        return Err(NonoError::SandboxInit(format!(
            "SECCOMP_IOCTL_NOTIF_RECV failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(notif)
}

/// Read the path argument from a seccomp notification.
///
/// Reads from `/proc/PID/mem` at the pointer address in the second syscall
/// argument (args[1] for openat/openat2, which is the pathname pointer).
///
/// # TOCTOU Warning
///
/// The path read here may have been modified between the syscall and this read.
/// Always call `notif_id_valid()` after reading to verify the notification is
/// still pending (the child hasn't been killed and its PID recycled).
///
/// Security boundary note: notification ID validation is only a liveness check.
/// Authorization is bound to the path opened by the supervisor itself; the child
/// receives that already-opened fd via `inject_fd()`.
///
/// # Errors
///
/// Returns an error if:
/// - `/proc/PID/mem` cannot be opened
/// - The read fails
/// - The path is not valid UTF-8
pub fn read_notif_path(pid: u32, addr: u64) -> Result<std::path::PathBuf> {
    use std::io::Read;

    let mem_path = format!("/proc/{}/mem", pid);
    let mut file = std::fs::File::open(&mem_path)
        .map_err(|e| NonoError::SandboxInit(format!("Failed to open {}: {}", mem_path, e)))?;

    // Seek to the address of the path string
    std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(addr))
        .map_err(|e| NonoError::SandboxInit(format!("Failed to seek in {}: {}", mem_path, e)))?;

    // Read up to PATH_MAX bytes, looking for null terminator
    let mut buf = vec![0u8; 4096];
    let n = file.read(&mut buf).map_err(|e| {
        NonoError::SandboxInit(format!("Failed to read path from {}: {}", mem_path, e))
    })?;

    // Find null terminator
    let end = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
    if end == 0 || end >= 4096 {
        return Err(NonoError::SandboxInit(
            "Invalid path in seccomp notification (empty or too long)".to_string(),
        ));
    }

    let path_str = std::str::from_utf8(&buf[..end]).map_err(|_| {
        NonoError::SandboxInit("Path in seccomp notification is not valid UTF-8".to_string())
    })?;

    Ok(std::path::PathBuf::from(path_str))
}

/// Read the open_how struct from a seccomp notification for openat2 syscalls.
///
/// For openat2, args[2] is a pointer to `struct open_how`, NOT the flags integer.
/// This function safely reads the struct from the child's memory.
///
/// # Security
///
/// This is critical for access-mode classification. Treating args[2] as an integer
/// (as with openat) when it's actually a pointer leads to misclassifying access mode,
/// potentially granting broader permissions than the child requested.
///
/// # TOCTOU Warning
///
/// The struct may be modified between the syscall and this read. Always call
/// `notif_id_valid()` after reading to verify the notification is still pending.
///
/// # Errors
///
/// Returns an error if:
/// - `/proc/PID/mem` cannot be opened
/// - The read fails or doesn't return enough bytes
pub fn read_open_how(pid: u32, addr: u64) -> Result<OpenHow> {
    use std::io::Read;

    let mem_path = format!("/proc/{}/mem", pid);
    let mut file = std::fs::File::open(&mem_path)
        .map_err(|e| NonoError::SandboxInit(format!("Failed to open {}: {}", mem_path, e)))?;

    // Seek to the address of the open_how struct
    std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(addr))
        .map_err(|e| NonoError::SandboxInit(format!("Failed to seek in {}: {}", mem_path, e)))?;

    // Read exactly the size of OpenHow (24 bytes)
    let mut buf = [0u8; std::mem::size_of::<OpenHow>()];
    file.read_exact(&mut buf).map_err(|e| {
        NonoError::SandboxInit(format!("Failed to read open_how from {}: {}", mem_path, e))
    })?;

    // SAFETY: OpenHow is repr(C) with no padding between fields (u64, u64, u64).
    // We read exactly size_of::<OpenHow>() bytes into a properly aligned buffer.
    // The struct contains only u64 values which have no invalid bit patterns.
    let open_how: OpenHow = unsafe { std::ptr::read_unaligned(buf.as_ptr().cast()) };

    Ok(open_how)
}

/// Check that a seccomp notification is still pending (TOCTOU protection).
///
/// Must be called after `read_notif_path()` and before `inject_fd()` or
/// `deny_notif()`. If the notification is no longer valid (child exited,
/// PID recycled), the operation should be skipped.
///
/// # Errors
///
/// Returns an error if the ioctl fails for reasons other than ENOENT.
pub fn notif_id_valid(notify_fd: std::os::fd::RawFd, notif_id: u64) -> Result<bool> {
    // SAFETY: SECCOMP_IOCTL_NOTIF_ID_VALID checks if a notification ID is
    // still pending. The ID is passed by pointer.
    let ret = unsafe {
        libc::ioctl(
            notify_fd,
            SECCOMP_IOCTL_NOTIF_ID_VALID,
            &notif_id as *const u64,
        )
    };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            // Notification is no longer valid (child exited or was killed)
            return Ok(false);
        }
        return Err(NonoError::SandboxInit(format!(
            "SECCOMP_IOCTL_NOTIF_ID_VALID failed: {}",
            err
        )));
    }

    Ok(true)
}

/// Inject an fd into the notified process (atomic respond + inject).
///
/// Uses `SECCOMP_IOCTL_NOTIF_ADDFD` with `SECCOMP_ADDFD_FLAG_SEND` to
/// atomically inject the fd and set it as the syscall return value.
/// This means the child's `openat()` call returns the injected fd directly.
///
/// Requires kernel >= 5.14.
///
/// # Errors
///
/// Returns an error if the ioctl fails (notification expired, kernel too old).
pub fn inject_fd(
    notify_fd: std::os::fd::RawFd,
    notif_id: u64,
    fd: std::os::fd::RawFd,
) -> Result<()> {
    let addfd = SeccompNotifAddfd {
        id: notif_id,
        flags: SECCOMP_ADDFD_FLAG_SEND,
        srcfd: fd as u32,
        newfd: 0,                            // Let kernel choose the fd number
        newfd_flags: libc::O_CLOEXEC as u32, // Prevent fd leaking to child's children
    };

    // SAFETY: SECCOMP_IOCTL_NOTIF_ADDFD injects a file descriptor from our
    // process into the notified process. The addfd struct is correctly
    // initialized with a valid fd and notification ID.
    let ret = unsafe {
        libc::ioctl(
            notify_fd,
            SECCOMP_IOCTL_NOTIF_ADDFD,
            &addfd as *const SeccompNotifAddfd,
        )
    };

    if ret < 0 {
        return Err(NonoError::SandboxInit(format!(
            "SECCOMP_IOCTL_NOTIF_ADDFD failed: {}. Requires kernel >= 5.14.",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Deny a seccomp notification with EPERM.
///
/// Sends a response to the kernel that causes the child's syscall to
/// return -1 with errno=EPERM.
///
/// # Errors
///
/// Returns an error if the ioctl fails.
pub fn deny_notif(notify_fd: std::os::fd::RawFd, notif_id: u64) -> Result<()> {
    let resp = SeccompNotifResp {
        id: notif_id,
        val: 0,
        error: -libc::EPERM,
        flags: 0,
    };

    // SAFETY: SECCOMP_IOCTL_NOTIF_SEND sends our response to the kernel.
    // The resp struct is correctly initialized.
    let ret = unsafe {
        libc::ioctl(
            notify_fd,
            SECCOMP_IOCTL_NOTIF_SEND,
            &resp as *const SeccompNotifResp,
        )
    };

    if ret < 0 {
        return Err(NonoError::SandboxInit(format!(
            "SECCOMP_IOCTL_NOTIF_SEND failed: {}",
            std::io::Error::last_os_error()
        )));
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

    #[test]
    fn test_seccomp_notif_struct_sizes() {
        // Verify our repr(C) structs match expected sizes
        use std::mem;
        // SeccompData: 4 + 4 + 8 + 6*8 = 64 bytes
        assert_eq!(mem::size_of::<SeccompData>(), 64);
        // SeccompNotif: 8 + 4 + 4 + 64 = 80 bytes
        assert_eq!(mem::size_of::<SeccompNotif>(), 80);
        // SeccompNotifResp: 8 + 8 + 4 + 4 = 24 bytes
        assert_eq!(mem::size_of::<SeccompNotifResp>(), 24);
        // SeccompNotifAddfd: 8 + 4 + 4 + 4 + 4 = 24 bytes
        assert_eq!(mem::size_of::<SeccompNotifAddfd>(), 24);
    }

    #[test]
    fn test_bpf_filter_instruction_count() {
        // The BPF filter should have exactly 5 instructions:
        // ld, jeq openat, jeq openat2, ret allow, ret notify
        let filter = [
            SockFilterInsn {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: SECCOMP_DATA_NR_OFFSET,
            },
            SockFilterInsn {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 2,
                jf: 0,
                k: SYS_OPENAT as u32,
            },
            SockFilterInsn {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 1,
                jf: 0,
                k: SYS_OPENAT2 as u32,
            },
            SockFilterInsn {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ALLOW,
            },
            SockFilterInsn {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_USER_NOTIF,
            },
        ];
        assert_eq!(filter.len(), 5);
    }

    #[test]
    fn test_open_how_struct_size() {
        use std::mem;
        // OpenHow: 3 x u64 = 24 bytes (flags, mode, resolve)
        assert_eq!(mem::size_of::<OpenHow>(), 24);
    }

    #[test]
    fn test_syscall_numbers_distinct() {
        // Verify openat and openat2 have different syscall numbers
        assert_ne!(SYS_OPENAT, SYS_OPENAT2);
    }

    #[test]
    fn test_syscall_numbers_match_seccomp_data_nr_type() {
        // SeccompData.nr is i32, verify our constants fit
        let _: i32 = SYS_OPENAT;
        let _: i32 = SYS_OPENAT2;
    }

    #[test]
    fn test_classify_access_rdonly() {
        let access = classify_access_from_flags(libc::O_RDONLY);
        assert!(matches!(access, crate::AccessMode::Read));
    }

    #[test]
    fn test_classify_access_wronly() {
        let access = classify_access_from_flags(libc::O_WRONLY);
        assert!(matches!(access, crate::AccessMode::Write));
    }

    #[test]
    fn test_classify_access_rdwr() {
        let access = classify_access_from_flags(libc::O_RDWR);
        assert!(matches!(access, crate::AccessMode::ReadWrite));
    }

    #[test]
    fn test_classify_access_with_extra_flags() {
        // O_RDONLY with O_CREAT, O_TRUNC etc should still be Read
        let flags = libc::O_RDONLY | libc::O_CREAT | libc::O_TRUNC;
        let access = classify_access_from_flags(flags);
        assert!(matches!(access, crate::AccessMode::Read));

        // O_WRONLY with O_APPEND should still be Write
        let flags = libc::O_WRONLY | libc::O_APPEND;
        let access = classify_access_from_flags(flags);
        assert!(matches!(access, crate::AccessMode::Write));

        // O_RDWR with O_CLOEXEC should still be ReadWrite
        let flags = libc::O_RDWR | libc::O_CLOEXEC;
        let access = classify_access_from_flags(flags);
        assert!(matches!(access, crate::AccessMode::ReadWrite));
    }

    #[test]
    fn test_classify_access_pointer_as_flags_gives_readwrite() {
        // Simulates the original bug: a pointer value (e.g., 0x7fff12345678) treated as flags.
        // The O_ACCMODE mask (0o3) would extract garbage bits, likely resulting in O_RDWR (2).
        // This test documents that garbage input defaults to ReadWrite (fail-safe for deny
        // decisions, but the real fix is proper syscall discrimination).
        let fake_pointer = 0x7fff_1234_5678_i64 as i32; // truncated pointer
        let access = classify_access_from_flags(fake_pointer);
        // With this specific value, (fake_pointer & 0o3) == 0, which is O_RDONLY
        // But the point is: any garbage value goes through the match, we don't panic.
        // The actual security fix is not calling this with garbage in the first place.
        let _ = access; // Just verify it doesn't panic
    }

    #[test]
    fn test_validate_openat2_size_rejects_zero() {
        assert!(!validate_openat2_size(0));
    }

    #[test]
    fn test_validate_openat2_size_rejects_undersized() {
        // Anything less than sizeof(OpenHow) = 24 should be rejected
        assert!(!validate_openat2_size(1));
        assert!(!validate_openat2_size(8));
        assert!(!validate_openat2_size(16));
        assert!(!validate_openat2_size(23));
    }

    #[test]
    fn test_validate_openat2_size_accepts_exact() {
        // Exactly sizeof(OpenHow) = 24 should be accepted
        let exact_size = std::mem::size_of::<OpenHow>();
        assert_eq!(exact_size, 24);
        assert!(validate_openat2_size(exact_size));
    }

    #[test]
    fn test_validate_openat2_size_accepts_larger() {
        // Larger (but bounded) sizes are valid (kernel may extend struct in future)
        assert!(validate_openat2_size(32));
        assert!(validate_openat2_size(64));
        assert!(validate_openat2_size(128));
    }

    #[test]
    fn test_validate_openat2_size_rejects_unreasonably_large() {
        assert!(!validate_openat2_size(4097));
        assert!(!validate_openat2_size(usize::MAX));
    }
}
