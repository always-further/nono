//! Execution strategy for sandboxed commands.
//!
//! This module defines how nono executes commands within the sandbox.
//! The strategy determines the process model and what features are available.
//!
//! # Async-Signal-Safety
//!
//! The Monitor strategy uses `fork()` to create a child process. After fork in a
//! multi-threaded program, the child can only safely call async-signal-safe functions
//! until `exec()`. This module carefully prepares all data in the parent (where
//! allocation is safe) and uses only raw libc calls in the child.

mod env_sanitization;
#[cfg(target_os = "linux")]
mod supervisor_linux;

use nix::libc;
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};
use nono::supervisor::{ApprovalDecision, SupervisorMessage, SupervisorResponse};
use nono::{
    ApprovalBackend, CapabilitySet, DenialReason, DenialRecord, DiagnosticFormatter,
    DiagnosticMode, NeverGrantChecker, NonoError, Result, Sandbox, SupervisorSocket,
};
use std::ffi::CString;
use std::io::{BufRead, BufReader, Write};
use std::mem::ManuallyDrop;
#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{debug, info, warn};

pub(crate) use env_sanitization::is_dangerous_env_var;
use env_sanitization::should_skip_env_var;

/// Resolve a program name to its absolute path.
///
/// This should be called BEFORE the sandbox is applied to ensure the program
/// can be found even if its directory is not in the sandbox's allowed paths.
///
/// # Errors
/// Returns an error if the program cannot be found in PATH or as a valid path.
pub fn resolve_program(program: &str) -> Result<PathBuf> {
    which::which(program).map_err(|e| {
        NonoError::CommandExecution(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{}: {}", program, e),
        ))
    })
}

/// Maximum threads allowed when keyring backend is active.
/// Main thread (1) + up to 3 keyring threads for D-Bus/Security.framework.
const MAX_KEYRING_THREADS: usize = 4;

/// Threading context for fork safety validation.
///
/// After loading secrets from the system keystore, the keyring crate may leave
/// background threads running (for D-Bus/Security.framework communication).
/// These threads are benign for our fork+exec pattern because:
/// - They don't hold locks that the main thread or child process needs
/// - The child immediately calls exec(), clearing all thread state
/// - The parent's keyring threads continue independently
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThreadingContext {
    /// Enforce single-threaded execution (default).
    /// Fork will fail if thread count > 1.
    #[default]
    Strict,

    /// Allow elevated thread count for known-safe keyring backends.
    /// Fork proceeds if thread count <= MAX_KEYRING_THREADS.
    KeyringExpected,
}

/// Execution strategy for running sandboxed commands.
///
/// Each strategy provides different trade-offs between security,
/// functionality, and complexity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExecStrategy {
    /// Direct exec: apply sandbox, then exec into command.
    /// nono ceases to exist after exec.
    ///
    /// - Minimal attack surface (no persistent parent)
    /// - No diagnostic footer on error
    /// - No rollback support
    /// - For backward compatibility and scripts
    Direct,

    /// Monitor mode: apply sandbox, fork, wait, diagnose on error.
    /// Both parent and child are sandboxed.
    ///
    /// - Small attack surface (parent sandboxed too)
    /// - Diagnostic footer on non-zero exit
    /// - No rollback support (parent can't write to ~/.nono/rollbacks)
    /// - Default for interactive use
    #[default]
    Monitor,

    /// Supervised mode: fork first, sandbox only child.
    /// Parent is unsandboxed.
    ///
    /// - Larger attack surface (requires hardening)
    /// - Diagnostic footer on non-zero exit
    /// - Undo support (parent can write snapshots)
    /// - Future: IPC for capability expansion
    Supervised,
}

/// Configuration for command execution.
pub struct ExecConfig<'a> {
    /// The command to execute (program + args).
    pub command: &'a [String],
    /// Pre-resolved absolute path to the program.
    /// This is resolved BEFORE the sandbox is applied to ensure the program
    /// can be found even if its directory is not in the sandbox's allowed paths.
    pub resolved_program: &'a std::path::Path,
    /// Capabilities for the sandbox.
    pub caps: &'a CapabilitySet,
    /// Environment variables to set.
    pub env_vars: Vec<(&'a str, &'a str)>,
    /// Path to the capability state file.
    pub cap_file: &'a std::path::Path,
    /// Whether to suppress diagnostic output.
    pub no_diagnostics: bool,
    /// Threading context for fork safety validation.
    pub threading: ThreadingContext,
}

/// Configuration for supervisor IPC in supervised execution mode.
///
/// When provided to [`execute_supervised()`], the supervisor creates a Unix
/// socket pair before fork, passes the child end to the child process via
/// the `NONO_SUPERVISOR_FD` environment variable, and runs an IPC event loop
/// in the parent that handles capability expansion requests from the
/// sandboxed child.
pub struct SupervisorConfig<'a> {
    /// Checker for permanently blocked paths (from policy.json `never_grant`)
    pub never_grant: &'a NeverGrantChecker,
    /// Backend for approval decisions (terminal prompt, webhook, policy engine)
    pub approval_backend: &'a dyn ApprovalBackend,
}

/// Execute a command using the Direct strategy (exec, nono disappears).
///
/// This is the original behavior: apply sandbox, then exec into the command.
/// nono ceases to exist after exec() succeeds.
pub fn execute_direct(config: &ExecConfig<'_>) -> Result<()> {
    let cmd_args = &config.command[1..];

    info!(
        "Executing (direct): {} {:?}",
        config.resolved_program.display(),
        cmd_args
    );

    let mut cmd = Command::new(config.resolved_program);
    cmd.env_clear();

    for (key, value) in std::env::vars() {
        if !should_skip_env_var(&key, &config.env_vars, &["NONO_CAP_FILE"]) {
            cmd.env(&key, &value);
        }
    }

    cmd.args(cmd_args).env("NONO_CAP_FILE", config.cap_file);

    for (key, value) in &config.env_vars {
        cmd.env(key, value);
    }

    let err = cmd.exec();

    // exec() only returns if there's an error
    Err(NonoError::CommandExecution(err))
}

/// Execute a command using the Monitor strategy (fork+wait, both sandboxed).
///
/// The sandbox is applied BEFORE forking, so both parent and child are
/// equally restricted. This minimizes attack surface while enabling
/// diagnostic output on failure.
///
/// # Security Properties
///
/// - Both parent and child are sandboxed with identical restrictions
/// - Even if child compromises parent via ptrace, parent has no additional privileges
/// - Platform-specific ptrace hardening is applied:
///   - Linux: PR_SET_DUMPABLE(0) prevents core dumps and ptrace attachment
///   - macOS: PT_DENY_ATTACH prevents debugger attachment (Seatbelt also blocks process-info)
///
/// # Stderr Interception
///
/// In Monitor mode, nono intercepts the child's stderr and watches for permission
/// error patterns. When detected, it immediately injects a diagnostic footer so
/// AI agents can understand the sandbox restrictions without checking env vars.
///
/// # Concurrency Limitations
///
/// This function is **not reentrant** and requires single-threaded execution:
/// - Uses process-global state for signal forwarding (Unix signal handlers cannot
///   access thread-local state)
/// - Calls `fork()` which is unsafe in multi-threaded programs
/// - Returns an error if called with multiple threads active
///
/// This is CLI-only code. Library consumers should use `Sandbox::apply()` directly
/// and implement their own process management if needed.
///
/// # Process Flow
///
/// 1. Program path already resolved by caller (before sandbox applied)
/// 2. Sandbox is already applied (caller's responsibility)
/// 3. Prepare all data for exec in parent (CString conversion)
/// 4. Apply platform-specific ptrace hardening
/// 5. Verify threading context allows fork
/// 6. Create pipes for output interception
/// 7. Fork into parent and child
/// 8. Child: close FDs, redirect output to pipes, exec using prepared data
/// 9. Parent: read pipes, inject diagnostic on permission errors, wait for exit
///
/// # Async-Signal-Safety
///
/// After fork() in a potentially multi-threaded process, the child can only safely
/// call async-signal-safe functions until exec(). This implementation:
/// - Uses the pre-resolved program path from ExecConfig
/// - Converts all strings to CString in the parent
/// - Uses only raw libc calls in the child (no Rust allocations)
/// - Exits with `libc::_exit()` on error (not `std::process::exit()` or panic)
pub fn execute_monitor(config: &ExecConfig<'_>) -> Result<i32> {
    let program = &config.command[0];
    let cmd_args = &config.command[1..];

    info!("Executing (monitor): {} {:?}", program, cmd_args);

    // Use pre-resolved program path (resolved before sandbox was applied)
    // This ensures the program can be found even if its directory is not
    // in the sandbox's allowed paths.
    let program_path = config.resolved_program;

    // Convert program path to CString for execve
    let program_c = CString::new(program_path.to_string_lossy().as_bytes())
        .map_err(|_| NonoError::SandboxInit("Program path contains null byte".to_string()))?;

    // Build argv: [program, args..., NULL]
    let mut argv_c: Vec<CString> = Vec::with_capacity(1 + cmd_args.len());
    argv_c.push(program_c.clone());
    for arg in cmd_args {
        argv_c.push(CString::new(arg.as_bytes()).map_err(|_| {
            NonoError::SandboxInit(format!("Argument contains null byte: {}", arg))
        })?);
    }

    // Build environment: inherit current env + add our vars
    let mut env_c: Vec<CString> = Vec::new();

    // Copy current environment, filtering dangerous and overridden vars
    for (key, value) in std::env::vars_os() {
        if let (Some(k), Some(v)) = (key.to_str(), value.to_str()) {
            let should_skip = should_skip_env_var(k, &config.env_vars, &["NONO_CAP_FILE"]);
            if !should_skip {
                if let Ok(cstr) = CString::new(format!("{}={}", k, v)) {
                    env_c.push(cstr);
                }
            }
        }
    }

    // Add NONO_CAP_FILE
    if let Some(cap_file_str) = config.cap_file.to_str() {
        if let Ok(cstr) = CString::new(format!("NONO_CAP_FILE={}", cap_file_str)) {
            env_c.push(cstr);
        }
    }

    // Add user-specified environment variables (secrets, etc.)
    // Pre-allocate with room for the null terminator to prevent CString::new
    // from reallocating, which would leave a non-zeroized copy of secret values.
    for (key, value) in &config.env_vars {
        let mut kv = Vec::with_capacity(key.len() + 1 + value.len() + 1);
        kv.extend_from_slice(key.as_bytes());
        kv.push(b'=');
        kv.extend_from_slice(value.as_bytes());
        if let Ok(cstr) = CString::new(kv) {
            env_c.push(cstr);
        }
    }

    // Create null-terminated pointer arrays for execve
    let argv_ptrs: Vec<*const libc::c_char> = argv_c
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    let envp_ptrs: Vec<*const libc::c_char> = env_c
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    // Platform-specific ptrace hardening
    #[cfg(target_os = "linux")]
    {
        use nix::sys::prctl;
        if let Err(e) = prctl::set_dumpable(false) {
            warn!("Failed to set PR_SET_DUMPABLE(0): {}", e);
        }
    }

    #[cfg(target_os = "macos")]
    {
        const PT_DENY_ATTACH: libc::c_int = 31;
        let result =
            unsafe { libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut::<libc::c_char>(), 0) };
        if result != 0 {
            warn!(
                "Failed to set PT_DENY_ATTACH: {} (errno: {})",
                result,
                std::io::Error::last_os_error()
            );
        }
    }

    // Validate threading context before fork
    let thread_count = get_thread_count();
    match (config.threading, thread_count) {
        (_, 1) => {}
        (ThreadingContext::KeyringExpected, n) if n <= MAX_KEYRING_THREADS => {
            debug!(
                "Proceeding with fork despite {} threads (keyring backend threads expected)",
                n
            );
        }
        (ThreadingContext::Strict, n) => {
            return Err(NonoError::SandboxInit(format!(
                "Cannot fork: process has {} threads (expected 1). \
                 This is a bug - fork() requires single-threaded execution.",
                n
            )));
        }
        (ThreadingContext::KeyringExpected, n) => {
            return Err(NonoError::SandboxInit(format!(
                "Cannot fork: process has {} threads (max {} with keyring). \
                 Unexpected threading detected.",
                n, MAX_KEYRING_THREADS
            )));
        }
    }

    // Create pipes for stdout and stderr interception
    let (stdout_read, stdout_write): (OwnedFd, OwnedFd) = nix::unistd::pipe()
        .map_err(|e| NonoError::SandboxInit(format!("pipe() for stdout failed: {}", e)))?;
    let (stderr_read, stderr_write): (OwnedFd, OwnedFd) = nix::unistd::pipe()
        .map_err(|e| NonoError::SandboxInit(format!("pipe() for stderr failed: {}", e)))?;

    // Extract raw FDs before fork
    let stdout_write_fd = stdout_write.as_raw_fd();
    let stderr_write_fd = stderr_write.as_raw_fd();
    let stdout_read_fd = stdout_read.as_raw_fd();
    let stderr_read_fd = stderr_read.as_raw_fd();

    // Wrap in ManuallyDrop to prevent Drop from running in child
    // (Drop may allocate, which is unsafe after fork)
    let stdout_read = ManuallyDrop::new(stdout_read);
    let stdout_write = ManuallyDrop::new(stdout_write);
    let stderr_read = ManuallyDrop::new(stderr_read);
    let stderr_write = ManuallyDrop::new(stderr_write);

    // Compute max FD in parent (get_max_fd may allocate on Linux)
    let max_fd = get_max_fd();

    // SAFETY: fork() is safe here because we validated threading context
    // and child will only use async-signal-safe functions until exec()
    let fork_result = unsafe { fork() };

    match fork_result {
        Ok(ForkResult::Child) => {
            // CHILD: No allocations allowed from here until exec()

            // Prevent /proc/pid/environ from being readable during the
            // fork-to-exec window (secrets may be in the environment).
            // prctl() is async-signal-safe so this is safe after fork.
            // Note: execve() resets dumpable to 1, so this only protects
            // the interval between fork and exec.
            #[cfg(target_os = "linux")]
            unsafe {
                libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
            }

            // Close read ends of pipes
            unsafe {
                libc::close(stdout_read_fd);
                libc::close(stderr_read_fd);
            }

            // Close inherited FDs from keyring/other sources
            close_inherited_fds(max_fd, &[stdout_write_fd, stderr_write_fd]);

            // Redirect stdout to pipe
            unsafe {
                if stdout_write_fd != libc::STDOUT_FILENO {
                    libc::dup2(stdout_write_fd, libc::STDOUT_FILENO);
                    libc::close(stdout_write_fd);
                }
            }

            // Redirect stderr to pipe
            unsafe {
                if stderr_write_fd != libc::STDERR_FILENO {
                    libc::dup2(stderr_write_fd, libc::STDERR_FILENO);
                    libc::close(stderr_write_fd);
                }
            }

            // Execute using pre-prepared CStrings (no allocation)
            unsafe {
                libc::execve(program_c.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
            }

            // execve only returns on error - exit without cleanup
            unsafe { libc::_exit(127) }
        }
        Ok(ForkResult::Parent { child }) => {
            // PARENT: Close write ends, read from pipes, wait for child
            unsafe {
                ManuallyDrop::drop(&mut { stdout_write });
                ManuallyDrop::drop(&mut { stderr_write });
            }

            let stdout_read = ManuallyDrop::into_inner(stdout_read);
            let stderr_read = ManuallyDrop::into_inner(stderr_read);

            let stdout_file = std::fs::File::from(stdout_read);
            let stderr_file = std::fs::File::from(stderr_read);

            execute_parent_monitor(child, config, stdout_file, stderr_file)
        }
        Err(e) => {
            unsafe {
                ManuallyDrop::drop(&mut { stdout_read });
                ManuallyDrop::drop(&mut { stdout_write });
                ManuallyDrop::drop(&mut { stderr_read });
                ManuallyDrop::drop(&mut { stderr_write });
            }
            Err(NonoError::SandboxInit(format!("fork() failed: {}", e)))
        }
    }
}

/// Execute a command using the Supervised strategy (fork first, sandbox only child).
///
/// Unlike Monitor mode where the sandbox is applied before forking (both processes
/// sandboxed), Supervised mode forks first and applies the sandbox only in the child.
/// The parent remains unsandboxed, enabling rollback snapshots and IPC capability
/// expansion.
///
/// # Security Properties
///
/// - Child is sandboxed with full restrictions (identical to Monitor's child)
/// - Parent is NOT sandboxed - requires additional hardening:
///   - Linux: PR_SET_DUMPABLE(0) applied BEFORE fork (inherited by both processes,
///     closes TOCTOU window). Failure is fatal.
///   - macOS: PT_DENY_ATTACH applied in parent immediately after fork (not inherited
///     across fork on macOS). Failure is fatal - child is killed and error returned.
/// - Parent attack surface is larger than Monitor (unsandboxed parent)
/// - Keyring secrets (--secrets) are NOT supported with Supervised mode to prevent
///   deadlock from keyring threads holding allocator locks at fork time
///
/// # Sandbox Application in Child
///
/// The child calls `Sandbox::apply()` after fork, which allocates memory (generating
/// Seatbelt profile strings on macOS, opening Landlock PathFds on Linux). This is safe
/// because we validate single-threaded execution before fork, giving the child a clean
/// copy of the parent's heap with no contended locks.
///
/// # Process Flow
///
/// 1. Prepare all data for exec in parent (CString conversion)
/// 2. Reject keyring threading context (deadlock risk)
/// 3. Verify single-threaded execution
/// 4. Fork into parent and child
/// 5. Child: apply Landlock, install seccomp-notify, close inherited FDs, exec
/// 6. Parent: apply PR_SET_DUMPABLE(0) + PT_DENY_ATTACH, receive seccomp fd, run supervisor loop
///
/// Unlike Monitor mode, Supervised mode does NOT pipe stdout/stderr. The child
/// inherits the parent's terminal directly, preserving TTY semantics for
/// interactive programs (e.g., Claude Code, vim). Diagnostic injection is not
/// needed because the parent is alive after the child exits and can print
/// diagnostics and rollback UI directly.
pub fn execute_supervised(
    config: &ExecConfig<'_>,
    supervisor: Option<&SupervisorConfig<'_>>,
) -> Result<i32> {
    let program = &config.command[0];
    let cmd_args = &config.command[1..];

    info!("Executing (supervised): {} {:?}", program, cmd_args);

    // Use pre-resolved program path (resolved before fork)
    let program_path = config.resolved_program;

    // Convert program path to CString for execve
    let program_c = CString::new(program_path.to_string_lossy().as_bytes())
        .map_err(|_| NonoError::SandboxInit("Program path contains null byte".to_string()))?;

    // Build argv: [program, args..., NULL]
    let mut argv_c: Vec<CString> = Vec::with_capacity(1 + cmd_args.len());
    argv_c.push(program_c.clone());
    for arg in cmd_args {
        argv_c.push(CString::new(arg.as_bytes()).map_err(|_| {
            NonoError::SandboxInit(format!("Argument contains null byte: {}", arg))
        })?);
    }

    // Create supervisor socket pair if IPC is enabled.
    // Must be done before building envp so we can add NONO_SUPERVISOR_FD.
    let socket_pair = if supervisor.is_some() {
        Some(SupervisorSocket::pair()?)
    } else {
        None
    };
    let child_sock_fd: Option<i32> = socket_pair.as_ref().map(|(_, c)| c.as_raw_fd());

    // Build environment: inherit current env + add our vars
    let mut env_c: Vec<CString> = Vec::new();

    // Copy current environment, filtering dangerous and overridden vars
    for (key, value) in std::env::vars_os() {
        if let (Some(k), Some(v)) = (key.to_str(), value.to_str()) {
            let should_skip = should_skip_env_var(
                k,
                &config.env_vars,
                &["NONO_CAP_FILE", "NONO_SUPERVISOR_FD"],
            );
            if !should_skip {
                if let Ok(cstr) = CString::new(format!("{}={}", k, v)) {
                    env_c.push(cstr);
                }
            }
        }
    }

    // Add NONO_CAP_FILE
    if let Some(cap_file_str) = config.cap_file.to_str() {
        if let Ok(cstr) = CString::new(format!("NONO_CAP_FILE={}", cap_file_str)) {
            env_c.push(cstr);
        }
    }

    // Add user-specified environment variables (secrets, etc.)
    for (key, value) in &config.env_vars {
        let mut kv = Vec::with_capacity(key.len() + 1 + value.len() + 1);
        kv.extend_from_slice(key.as_bytes());
        kv.push(b'=');
        kv.extend_from_slice(value.as_bytes());
        if let Ok(cstr) = CString::new(kv) {
            env_c.push(cstr);
        }
    }

    // Add NONO_SUPERVISOR_FD if supervisor IPC is enabled
    if let Some(fd) = child_sock_fd {
        if let Ok(cstr) = CString::new(format!("NONO_SUPERVISOR_FD={fd}")) {
            env_c.push(cstr);
        }
    }

    // Create null-terminated pointer arrays for execve
    let argv_ptrs: Vec<*const libc::c_char> = argv_c
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    let envp_ptrs: Vec<*const libc::c_char> = env_c
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    // Supervised mode REQUIRES single-threaded execution (Strict context).
    // Unlike Monitor mode (where sandbox is applied before fork and keyring
    // threads are tolerable), Supervised mode calls Sandbox::apply() in the
    // child after fork. If keyring threads hold allocator locks at fork time,
    // the child's Sandbox::apply() will deadlock when it tries to allocate.
    if matches!(config.threading, ThreadingContext::KeyringExpected) {
        return Err(NonoError::SandboxInit(
            "Supervised mode is incompatible with keyring secrets. \
             Keyring threads may hold allocator locks at fork time, causing \
             deadlock when the child applies the sandbox. Use Monitor mode \
             (remove --supervised) or avoid --secrets with --supervised."
                .to_string(),
        ));
    }

    // Validate single-threaded execution before fork.
    // Supervised mode applies sandbox in child (allocates), so extra threads
    // would risk deadlock from contended allocator locks.
    let thread_count = get_thread_count();
    if thread_count != 1 {
        return Err(NonoError::SandboxInit(format!(
            "Cannot fork in supervised mode: process has {} threads (expected 1). \
             Supervised mode requires single-threaded execution because the child \
             calls Sandbox::apply() after fork, which allocates.",
            thread_count
        )));
    }

    // NOTE: In supervised mode with IPC (--supervised), we do NOT set
    // PR_SET_DUMPABLE(0) before fork. The child must remain dumpable so
    // the parent can read /proc/CHILD/mem for seccomp-notify path extraction.
    // In rollback-only mode (no IPC), the child is made non-dumpable after
    // sandbox apply (see child branch below).
    // The parent sets itself non-dumpable immediately after fork.

    // Compute child's FD keep list: supervisor socket fd if IPC is enabled
    let child_keep_fds: Vec<i32> = child_sock_fd.into_iter().collect();

    let effective_caps: &CapabilitySet = config.caps;

    // Compute max FD in parent (get_max_fd may allocate on Linux)
    let max_fd = get_max_fd();

    // SAFETY: fork() is safe here because we validated threading context.
    // Child will call Sandbox::apply() which allocates, but this is safe
    // because the child is single-threaded (validated above).
    let fork_result = unsafe { fork() };

    match fork_result {
        Ok(ForkResult::Child) => {
            // CHILD: Apply sandbox, then exec.
            //
            // Unlike Monitor mode, the child must apply the sandbox itself.
            // Sandbox::apply() allocates (Seatbelt profile generation, Landlock
            // PathFd opens) but this is safe because we validated single-threaded
            // execution before fork, giving us a clean heap.
            //
            // The child inherits the parent's stdin/stdout/stderr directly
            // (no pipe redirection). This preserves TTY semantics for
            // interactive programs like Claude Code.

            // Apply Landlock FIRST. Landlock's restrict_self() opens path fds
            // for rule creation, so it must run before seccomp-notify is installed.
            // (seccomp-notify traps ALL openat/openat2 syscalls, which would
            // intercept Landlock's own path opens and deadlock.)
            if let Err(e) = Sandbox::apply(effective_caps) {
                let detail = format!("nono: failed to apply sandbox in supervised child: {}\n", e);
                let msg = detail.as_bytes();
                unsafe {
                    libc::write(
                        libc::STDERR_FILENO,
                        msg.as_ptr().cast::<libc::c_void>(),
                        msg.len(),
                    );
                    libc::_exit(126);
                }
            }

            // On Linux with supervisor enabled: install seccomp-notify filter
            // AFTER Landlock. The kernel evaluates seccomp before LSM hooks
            // regardless of installation order, so the security properties are
            // identical. All openat/openat2 from exec'd child are routed to
            // the supervisor, which can inject fds for approved paths.
            #[cfg(target_os = "linux")]
            {
                if let Some(fd) = child_sock_fd {
                    match nono::sandbox::install_seccomp_notify() {
                        Ok(notify_fd) => {
                            // Send the notify fd to the parent via SCM_RIGHTS
                            // SAFETY: We own the child socket end and the notify fd
                            // is valid. from_stream is safe with our inherited fd.
                            let child_sock =
                                unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
                            let tmp_sock = SupervisorSocket::from_stream(child_sock);
                            if let Err(_e) = tmp_sock.send_fd(notify_fd.as_raw_fd()) {
                                let msg = b"nono: failed to send seccomp notify fd to supervisor\n";
                                unsafe {
                                    libc::write(
                                        libc::STDERR_FILENO,
                                        msg.as_ptr().cast::<libc::c_void>(),
                                        msg.len(),
                                    );
                                }
                            }
                            // Leak the socket wrapper so it doesn't close the fd
                            // (the fd is still needed for supervisor IPC)
                            std::mem::forget(tmp_sock);
                        }
                        Err(e) => {
                            // seccomp not available -- proceed without transparent expansion
                            let detail = format!(
                                "nono: seccomp-notify not available, expansion disabled: {}\n",
                                e
                            );
                            let msg = detail.as_bytes();
                            unsafe {
                                libc::write(
                                    libc::STDERR_FILENO,
                                    msg.as_ptr().cast::<libc::c_void>(),
                                    msg.len(),
                                );
                            }
                        }
                    }
                }
            }

            // In rollback-only mode (no supervisor IPC), make the child
            // non-dumpable to prevent ptrace attachment from same-UID
            // processes. When supervisor IPC is active, the child must stay
            // dumpable so the parent can read /proc/CHILD/mem for
            // seccomp-notify path extraction.
            #[cfg(target_os = "linux")]
            {
                if child_sock_fd.is_none() {
                    // No supervisor IPC — safe to drop dumpable
                    unsafe {
                        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
                    }
                }
            }

            #[cfg(target_os = "macos")]
            {
                const PT_DENY_ATTACH: libc::c_int = 31;
                unsafe {
                    libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut::<libc::c_char>(), 0);
                }
            }

            // Close inherited FDs (but keep stdin/stdout/stderr and supervisor socket)
            close_inherited_fds(max_fd, &child_keep_fds);

            // Execute using pre-prepared CStrings (no allocation)
            unsafe {
                libc::execve(program_c.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
            }

            // execve only returns on error - exit without cleanup
            unsafe { libc::_exit(127) }
        }
        Ok(ForkResult::Parent { child }) => {
            // Destructure socket pair: close child's end, keep supervisor's end
            let supervisor_sock = if let Some((sup, child_end)) = socket_pair {
                drop(child_end);
                Some(sup)
            } else {
                None
            };

            // PARENT: Apply ptrace hardening immediately. This is CRITICAL
            // because the parent is unsandboxed in Supervised mode.
            // Failure to harden is fatal - we kill the child and abort.

            // On Linux, set PR_SET_DUMPABLE(0) on the parent to prevent
            // ptrace attachment. The child stays dumpable only when
            // supervisor IPC is active (for /proc/CHILD/mem path extraction).
            #[cfg(target_os = "linux")]
            {
                use nix::sys::prctl;
                if let Err(e) = prctl::set_dumpable(false) {
                    let _ = signal::kill(child, Signal::SIGKILL);
                    let _ = waitpid(child, None);
                    return Err(NonoError::SandboxInit(format!(
                        "Failed to verify PR_SET_DUMPABLE(0) on supervised parent: {}. \
                         Aborting: unsandboxed parent must not be ptrace-attachable.",
                        e
                    )));
                }
            }

            #[cfg(target_os = "macos")]
            {
                const PT_DENY_ATTACH: libc::c_int = 31;
                let result = unsafe {
                    libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut::<libc::c_char>(), 0)
                };
                if result != 0 {
                    let err = std::io::Error::last_os_error();
                    let _ = signal::kill(child, Signal::SIGKILL);
                    let _ = waitpid(child, None);
                    return Err(NonoError::SandboxInit(format!(
                        "Failed to set PT_DENY_ATTACH on supervised parent: {} (errno: {}). \
                         Aborting: unsandboxed parent must not be debugger-attachable.",
                        result, err
                    )));
                }
            }

            // On Linux with supervisor enabled: receive the seccomp notify fd
            // from the child. The child installed a seccomp-notify filter and
            // sent the fd via SCM_RIGHTS on the supervisor socket.
            #[cfg(target_os = "linux")]
            let seccomp_notify_fd: Option<OwnedFd> = if supervisor.is_some() {
                if let Some(ref sup_sock) = supervisor_sock {
                    match sup_sock.recv_fd() {
                        Ok(fd) => {
                            debug!("Received seccomp notify fd from child");
                            Some(fd)
                        }
                        Err(e) => {
                            warn!("Failed to receive seccomp notify fd: {}", e);
                            None
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            };

            // Set up signal forwarding.
            // No output piping needed - child inherits the terminal directly.
            setup_signal_forwarding(child);

            // NOTE: peer_pid() is NOT called here. For socketpair() created
            // before fork, LOCAL_PEERPID/SO_PEERCRED return the parent's own PID
            // (credentials are captured at creation time, not updated after fork).
            // Socketpairs are inherently secure: anonymous (no filesystem path),
            // only our forked child has the other end. peer_pid() is useful for
            // named sockets (bind/connect), not socketpair+fork.

            // Build initial-set path lookup for seccomp fast-path (Linux)
            // Stores (resolved_path, is_file) to distinguish file vs directory semantics:
            // - File capabilities: exact match only (no subpath access)
            // - Directory capabilities: subpath access allowed via starts_with
            #[cfg(target_os = "linux")]
            let initial_caps: Vec<(std::path::PathBuf, bool)> = config
                .caps
                .fs_capabilities()
                .iter()
                .map(|cap| (cap.resolved.clone(), cap.is_file))
                .collect();

            // Run IPC event loop if supervisor is configured, otherwise just wait
            let (status, denials) =
                if let (Some(sup_cfg), Some(mut sup_sock)) = (supervisor, supervisor_sock) {
                    #[cfg(target_os = "linux")]
                    {
                        run_supervisor_loop(
                            child,
                            &mut sup_sock,
                            sup_cfg,
                            seccomp_notify_fd.as_ref(),
                            &initial_caps,
                        )?
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        run_supervisor_loop(child, &mut sup_sock, sup_cfg)?
                    }
                } else {
                    let status = wait_for_child(child)?;
                    (status, Vec::new())
                };

            let exit_code = match status {
                WaitStatus::Exited(_, code) => {
                    debug!("Supervised child exited with code {}", code);
                    code
                }
                WaitStatus::Signaled(_, sig, _) => {
                    debug!("Supervised child killed by signal {}", sig);
                    128 + sig as i32
                }
                other => {
                    warn!("Unexpected wait status: {:?}", other);
                    1
                }
            };

            // Print diagnostic footer on non-zero exit.
            // Unlike Monitor mode (which intercepts stderr for inline injection),
            // Supervised mode inherits the terminal directly, so the footer is
            // only printed here after the child exits.
            if exit_code != 0 && !config.no_diagnostics {
                let mode = if supervisor.is_some() {
                    DiagnosticMode::Supervised
                } else {
                    DiagnosticMode::Standard
                };
                let formatter = DiagnosticFormatter::new(config.caps)
                    .with_mode(mode)
                    .with_denials(&denials);
                let footer = formatter.format_footer(exit_code);
                eprintln!("\n{}", footer);
            }

            Ok(exit_code)
        }
        Err(e) => Err(NonoError::SandboxInit(format!("fork() failed: {}", e))),
    }
}

/// Close inherited file descriptors, keeping stdin/stdout/stderr and specified FDs.
///
/// `max_fd` must be computed in the parent before fork (get_max_fd may allocate).
fn close_inherited_fds(max_fd: i32, keep_fds: &[i32]) {
    for fd in 3..=max_fd {
        if !keep_fds.contains(&fd) {
            unsafe { libc::close(fd) };
        }
    }
}

/// Get the maximum file descriptor number to iterate over.
fn get_max_fd() -> i32 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
            let max = entries
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()))
                .max()
                .unwrap_or(1024);
            return max;
        }
    }

    let max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    if max > 0 {
        std::cmp::min(max as i32, 65536)
    } else {
        1024
    }
}

/// Patterns that indicate a permission error from sandbox restrictions.
/// These are checked case-insensitively against stderr output.
const PERMISSION_ERROR_PATTERNS: &[&str] = &[
    "eperm",
    "eacces",
    "permission denied",
    "operation not permitted",
    "sandbox",
];

/// Minimum time between diagnostic injections (debounce).
const DIAGNOSTIC_DEBOUNCE_MS: u128 = 2000;

/// Parent process in Monitor mode: intercept stdout/stderr, inject diagnostics, wait for child.
fn execute_parent_monitor(
    child: Pid,
    config: &ExecConfig<'_>,
    stdout_pipe: std::fs::File,
    stderr_pipe: std::fs::File,
) -> Result<i32> {
    debug!("Parent waiting for child pid {}", child);

    // Set up signal forwarding
    setup_signal_forwarding(child);

    // Shared flag to track if we've injected diagnostics recently
    // This allows debouncing across both stdout and stderr
    let diagnostic_injected = Arc::new(AtomicBool::new(false));

    // Spawn threads to read stdout and stderr
    // We need threads because we must read from both pipes while also waiting for the child
    let caps_stdout = config.caps.clone();
    let caps_stderr = config.caps.clone();
    let no_diagnostics = config.no_diagnostics;
    let diag_flag_stdout = Arc::clone(&diagnostic_injected);
    let diag_flag_stderr = Arc::clone(&diagnostic_injected);

    let stdout_handle = std::thread::spawn(move || {
        process_output(
            stdout_pipe,
            &caps_stdout,
            no_diagnostics,
            false,
            diag_flag_stdout,
        );
    });

    let stderr_handle = std::thread::spawn(move || {
        process_output(
            stderr_pipe,
            &caps_stderr,
            no_diagnostics,
            true,
            diag_flag_stderr,
        );
    });

    // Wait for child to exit
    let status = wait_for_child(child)?;

    // Wait for output threads to finish (they will exit when pipes close)
    if let Err(e) = stdout_handle.join() {
        warn!("stdout processing thread panicked: {:?}", e);
    }
    if let Err(e) = stderr_handle.join() {
        warn!("stderr processing thread panicked: {:?}", e);
    }

    // Determine exit code
    let exit_code = match status {
        WaitStatus::Exited(_, code) => {
            debug!("Child exited with code {}", code);
            code
        }
        WaitStatus::Signaled(_, signal, _) => {
            debug!("Child killed by signal {:?}", signal);
            // Exit code convention: 128 + signal number
            128 + signal as i32
        }
        other => {
            warn!("Unexpected wait status: {:?}", other);
            1
        }
    };

    // Print diagnostic footer on non-zero exit if not already injected
    if exit_code != 0
        && !config.no_diagnostics
        && diagnostic_injected
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    {
        let formatter = DiagnosticFormatter::new(config.caps);
        let footer = formatter.format_footer(exit_code);
        eprintln!("\n{}", footer);
    }

    Ok(exit_code)
}

/// Process output from the child (stdout or stderr), forwarding and injecting diagnostics.
///
/// When a permission error is detected on either stream, the diagnostic is written to stdout.
/// This ensures AI agents like Claude Code see the diagnostic since they typically capture
/// and re-render subprocess output through their TUI.
fn process_output(
    pipe: std::fs::File,
    caps: &CapabilitySet,
    no_diagnostics: bool,
    is_stderr: bool,
    diagnostic_injected: Arc<AtomicBool>,
) {
    let reader = BufReader::new(pipe);
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    let stream_name = if is_stderr { "stderr" } else { "stdout" };

    for line_result in reader.lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                debug!("Error reading {}: {}", stream_name, e);
                break;
            }
        };

        // Forward line to the appropriate real output
        if is_stderr {
            if writeln!(stderr, "{}", line).is_err() {
                debug!("Failed to write to stderr");
            }
        } else if writeln!(stdout, "{}", line).is_err() {
            debug!("Failed to write to stdout");
        }

        // Check for permission error patterns (skip if diagnostics disabled)
        if no_diagnostics {
            continue;
        }

        let line_lower = line.to_lowercase();
        let is_permission_error = PERMISSION_ERROR_PATTERNS
            .iter()
            .any(|pattern| line_lower.contains(pattern));

        if is_permission_error {
            // Use compare_exchange to ensure only one thread injects diagnostics
            // This prevents duplicate diagnostics when errors appear on both streams
            if diagnostic_injected
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                // We won the race - inject diagnostic to stdout only
                // Writing to stdout ensures AI agents (like Claude Code) see the diagnostic
                // since they may capture and re-render subprocess output through their TUI
                let formatter = DiagnosticFormatter::new(caps);
                let footer = formatter.format_footer(1);

                // Write to stdout (for agents that capture stdout)
                for footer_line in footer.lines() {
                    let _ = writeln!(stdout, "{}", footer_line);
                }
                let _ = stdout.flush();

                // Reset the flag after debounce period in a background thread
                let flag = Arc::clone(&diagnostic_injected);
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(
                        DIAGNOSTIC_DEBOUNCE_MS as u64,
                    ));
                    flag.store(false, Ordering::SeqCst);
                });
            }
        }
    }
}

/// Wait for child process, handling EINTR from signals.
fn wait_for_child(child: Pid) -> Result<WaitStatus> {
    loop {
        match waitpid(child, Some(WaitPidFlag::empty())) {
            Ok(status) => return Ok(status),
            Err(nix::errno::Errno::EINTR) => {
                // Interrupted by signal, retry
                continue;
            }
            Err(e) => {
                return Err(NonoError::SandboxInit(format!("waitpid() failed: {}", e)));
            }
        }
    }
}

/// Set up signal forwarding from parent to child.
///
/// Signals received by the parent are forwarded to the child process.
/// This ensures Ctrl+C, SIGTERM, etc. properly reach the sandboxed command.
///
/// # Process-Global State
///
/// This function uses process-global static storage for the child PID because
/// Unix signal handlers cannot access thread-local or instance-specific state.
/// This means:
///
/// - Only one `execute_monitor` invocation can be active at a time
/// - Concurrent calls from different threads would corrupt the child PID
/// - This is enforced by the single-threaded check in `execute_monitor`
///
/// This is acceptable because:
/// 1. `execute_monitor` is CLI code, not library code (per DESIGN-supervisor.md)
/// 2. The fork+wait model inherently requires single-threaded execution
/// 3. Library consumers would use `Sandbox::apply()` directly, not the fork machinery
fn setup_signal_forwarding(child: Pid) {
    // ==================== SAFETY INVARIANT ====================
    // This static variable is ONLY safe because execute_monitor()
    // verifies single-threaded execution BEFORE calling this function.
    //
    // DO NOT call this function without first verifying:
    //   get_thread_count() == 1
    //
    // If threading is ever introduced before this point, this code
    // becomes a race condition where signals could be forwarded to
    // the wrong process (or a non-existent one).
    // ===========================================================
    //
    // Why this design:
    // - Unix signal handlers cannot access thread-local storage
    // - Unix signal handlers cannot access instance data
    // - The only safe option is process-global static storage
    // - AtomicI32 ensures atomic reads/writes
    static CHILD_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
    CHILD_PID.store(child.as_raw(), std::sync::atomic::Ordering::SeqCst);

    extern "C" fn forward_signal(sig: libc::c_int) {
        let child_raw = CHILD_PID.load(std::sync::atomic::Ordering::SeqCst);
        if child_raw > 0 {
            // Forward signal to child
            // SAFETY: kill() is async-signal-safe
            unsafe {
                libc::kill(child_raw, sig);
            }
        }
    }

    // Install signal handlers for common signals
    // SAFETY: signal handlers are async-signal-safe (only call kill())
    unsafe {
        for sig in &[
            Signal::SIGINT,
            Signal::SIGTERM,
            Signal::SIGHUP,
            Signal::SIGQUIT,
        ] {
            if let Err(e) = signal::signal(*sig, signal::SigHandler::Handler(forward_signal)) {
                debug!("Failed to install handler for {:?}: {}", sig, e);
            }
        }
    }
}
/// Get the current thread count for the process.
///
/// Used to verify single-threaded execution before fork().
/// Returns 1 if the count cannot be determined (conservative assumption).
fn get_thread_count() -> usize {
    #[cfg(target_os = "linux")]
    {
        // On Linux, read /proc/self/status for accurate thread count
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(count_str) = line.strip_prefix("Threads:") {
                    if let Ok(count) = count_str.trim().parse::<usize>() {
                        return count;
                    }
                }
            }
        }
        // Fallback: assume single-threaded if we can't read /proc
        1
    }

    #[cfg(target_os = "macos")]
    {
        // On macOS, use mach APIs to get thread count
        // SAFETY: These are read-only queries about our own process
        #[allow(deprecated)] // libc recommends mach2 crate, but this is a simple defensive check
        unsafe {
            let task = libc::mach_task_self();
            let mut thread_list: libc::thread_act_array_t = std::ptr::null_mut();
            let mut thread_count: libc::mach_msg_type_number_t = 0;

            // task_threads returns all threads in the task
            let result = libc::task_threads(task, &mut thread_list, &mut thread_count);

            if result == libc::KERN_SUCCESS && !thread_list.is_null() {
                // Deallocate the thread list (required by mach API contract)
                let list_size = thread_count as usize * std::mem::size_of::<libc::thread_act_t>();
                libc::vm_deallocate(task, thread_list as libc::vm_address_t, list_size);
                return thread_count as usize;
            }
        }
        // Fallback: assume single-threaded if mach call fails
        1
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        // On other platforms, assume single-threaded (conservative)
        1
    }
}

/// Supervisor IPC event loop (non-Linux).
///
/// Polls the supervisor socket for messages from the sandboxed child.
/// Uses `poll(2)` with a 200ms timeout to periodically check child status.
/// Returns the child's wait status and any denial records collected.
#[cfg(not(target_os = "linux"))]
fn run_supervisor_loop(
    child: Pid,
    sock: &mut SupervisorSocket,
    config: &SupervisorConfig<'_>,
) -> Result<(WaitStatus, Vec<DenialRecord>)> {
    let sock_fd = sock.as_raw_fd();
    let mut denials = Vec::new();

    loop {
        let mut pfd = libc::pollfd {
            fd: sock_fd,
            events: libc::POLLIN,
            revents: 0,
        };

        // SAFETY: pfd is a valid pollfd struct on the stack, nfds=1 is correct.
        let ret = unsafe { libc::poll(&mut pfd, 1, 200) };

        if ret > 0 {
            if pfd.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                debug!("Supervisor socket closed by child");
                break;
            }
            if pfd.revents & libc::POLLIN != 0 {
                match sock.recv_message() {
                    Ok(msg) => {
                        if let Err(e) = handle_supervisor_message(sock, msg, config, &mut denials) {
                            warn!("Error handling supervisor message: {}", e);
                        }
                    }
                    Err(e) => {
                        debug!("Error receiving supervisor message: {}", e);
                        break;
                    }
                }
            }
        } else if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                warn!("poll() error in supervisor loop: {}", err);
                break;
            }
        }

        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => continue,
            Ok(status) => return Ok((status, denials)),
            Err(nix::errno::Errno::EINTR) => continue,
            Err(nix::errno::Errno::ECHILD) => {
                warn!("Child already reaped in supervisor loop");
                return Ok((WaitStatus::Exited(child, 1), denials));
            }
            Err(e) => {
                return Err(NonoError::SandboxInit(format!(
                    "waitpid() failed in supervisor loop: {}",
                    e
                )));
            }
        }
    }

    let status = wait_for_child(child)?;
    Ok((status, denials))
}

/// Supervisor IPC event loop for capability expansion (Linux).
///
/// Multiplexes between:
/// - seccomp notify fd (openat/openat2 interceptions from the child)
/// - supervisor socket (explicit capability requests from SDK clients)
/// - child process exit via non-blocking `waitpid()`
///
/// Seccomp notifications for paths in the initial capability set are handled
/// immediately (fast-path). Other paths go through the approval backend.
///
/// The initial_caps parameter contains (path, is_file) tuples:
/// - For files (is_file=true): only exact path matches are allowed
/// - For directories (is_file=false): subpath matches via starts_with are allowed
///
/// Returns the child's wait status and any denial records collected.
#[cfg(target_os = "linux")]
fn run_supervisor_loop(
    child: Pid,
    sock: &mut SupervisorSocket,
    config: &SupervisorConfig<'_>,
    seccomp_fd: Option<&OwnedFd>,
    initial_caps: &[(std::path::PathBuf, bool)],
) -> Result<(WaitStatus, Vec<DenialRecord>)> {
    let sock_fd = sock.as_raw_fd();
    let notify_raw_fd = seccomp_fd.map(|fd| fd.as_raw_fd());
    let mut rate_limiter = supervisor_linux::RateLimiter::new(10, 5);
    let mut denials = Vec::new();
    // Track whether the supervisor socket is still alive. After exec,
    // CLOEXEC closes the child's socket end, causing POLLHUP. We stop
    // polling the dead socket but continue handling seccomp notifications.
    let mut sock_fd_active = true;

    loop {
        // Build poll array: supervisor socket (if alive) + seccomp fd (if present)
        let mut pfds: Vec<libc::pollfd> = vec![libc::pollfd {
            // poll ignores negative fds, so set to -1 when socket is dead
            fd: if sock_fd_active { sock_fd } else { -1 },
            events: libc::POLLIN,
            revents: 0,
        }];
        if let Some(nfd) = notify_raw_fd {
            pfds.push(libc::pollfd {
                fd: nfd,
                events: libc::POLLIN,
                revents: 0,
            });
        }

        // SAFETY: pfds is a valid array of pollfd structs on the stack.
        let ret = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, 200) };

        if ret > 0 {
            // Check supervisor socket (only if still active)
            if sock_fd_active && pfds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                // Supervisor socket closed (CLOEXEC closes child's end after exec).
                // If we have a seccomp notify fd, keep looping to handle
                // seccomp notifications -- just stop polling the dead socket.
                if notify_raw_fd.is_some() {
                    debug!("Supervisor socket closed, continuing for seccomp notifications");
                    sock_fd_active = false;
                } else {
                    debug!("Supervisor socket closed by child");
                    break;
                }
            }
            if sock_fd_active && pfds[0].revents & libc::POLLIN != 0 {
                match sock.recv_message() {
                    Ok(msg) => {
                        if let Err(e) = handle_supervisor_message(sock, msg, config, &mut denials) {
                            warn!("Error handling supervisor message: {}", e);
                        }
                    }
                    Err(e) => {
                        debug!("Error receiving supervisor message: {}", e);
                        if notify_raw_fd.is_none() {
                            break;
                        }
                        sock_fd_active = false;
                    }
                }
            }

            // Check seccomp notify fd (if present)
            if pfds.len() > 1 && pfds[1].revents & libc::POLLIN != 0 {
                if let Some(nfd) = notify_raw_fd {
                    if let Err(e) = supervisor_linux::handle_seccomp_notification(
                        nfd,
                        child,
                        config,
                        initial_caps,
                        &mut rate_limiter,
                        &mut denials,
                    ) {
                        debug!("Error handling seccomp notification: {}", e);
                    }
                }
            }
        } else if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                warn!("poll() error in supervisor loop: {}", err);
                break;
            }
        }

        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => continue,
            Ok(status) => return Ok((status, denials)),
            Err(nix::errno::Errno::EINTR) => continue,
            Err(nix::errno::Errno::ECHILD) => {
                warn!("Child already reaped in supervisor loop");
                return Ok((WaitStatus::Exited(child, 1), denials));
            }
            Err(e) => {
                return Err(NonoError::SandboxInit(format!(
                    "waitpid() failed in supervisor loop: {}",
                    e
                )));
            }
        }
    }

    let status = wait_for_child(child)?;
    Ok((status, denials))
}

/// Handle a single supervisor IPC message.
///
/// Flow:
/// 1. Check `never_grant` - permanently blocked paths are rejected immediately
/// 2. Delegate to `ApprovalBackend` for the decision
/// 3. If granted, open the path and send the fd via `SCM_RIGHTS`
/// 4. Send the decision response
/// 5. Record denials for diagnostic footer
fn handle_supervisor_message(
    sock: &mut SupervisorSocket,
    msg: SupervisorMessage,
    config: &SupervisorConfig<'_>,
    denials: &mut Vec<DenialRecord>,
) -> Result<()> {
    match msg {
        SupervisorMessage::Request(request) => {
            // 1. Check never_grant list first (before consulting the backend)
            let never_grant_check = config.never_grant.check(&request.path);

            let decision = if never_grant_check.is_blocked() {
                debug!(
                    "Supervisor: path {} blocked by never_grant",
                    request.path.display()
                );
                denials.push(DenialRecord {
                    path: request.path.clone(),
                    access: request.access,
                    reason: DenialReason::PolicyBlocked,
                });
                ApprovalDecision::Denied {
                    reason: format!(
                        "Path is permanently blocked by never_grant policy: {}",
                        request.path.display()
                    ),
                }
            } else {
                // 2. Delegate to approval backend
                match config.approval_backend.request_capability(&request) {
                    Ok(d) => {
                        if d.is_denied() {
                            denials.push(DenialRecord {
                                path: request.path.clone(),
                                access: request.access,
                                reason: DenialReason::UserDenied,
                            });
                        }
                        d
                    }
                    Err(e) => {
                        warn!("Approval backend error: {}", e);
                        denials.push(DenialRecord {
                            path: request.path.clone(),
                            access: request.access,
                            reason: DenialReason::BackendError,
                        });
                        ApprovalDecision::Denied {
                            reason: format!("Approval backend error: {e}"),
                        }
                    }
                }
            };

            // 3. If granted, open the path and send fd before the response
            if decision.is_granted() {
                match open_path_for_access(&request.path, &request.access, config.never_grant) {
                    Ok(file) => {
                        if let Err(e) = sock.send_fd(file.as_raw_fd()) {
                            warn!("Failed to send fd: {}", e);
                            let response = SupervisorResponse::Decision {
                                request_id: request.request_id,
                                decision: ApprovalDecision::Denied {
                                    reason: format!("Failed to send file descriptor: {e}"),
                                },
                            };
                            return sock.send_response(&response);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to open path: {}", e);
                        let response = SupervisorResponse::Decision {
                            request_id: request.request_id,
                            decision: ApprovalDecision::Denied {
                                reason: format!("Supervisor failed to open path: {e}"),
                            },
                        };
                        return sock.send_response(&response);
                    }
                }
            }

            // 4. Send decision response
            let response = SupervisorResponse::Decision {
                request_id: request.request_id,
                decision,
            };
            sock.send_response(&response)?;
        }
    }

    Ok(())
}

/// Generate a unique request ID from timestamp + random component.
///
/// Uses nanosecond timestamp for ordering plus random bytes for
/// uniqueness under concurrency. Not cryptographically significant --
/// used for audit correlation and replay detection, not security.
#[cfg(target_os = "linux")]
fn unique_request_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0) as u64;
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);

    // Combine timestamp with monotonic counter for uniqueness
    format!("{:x}-{:x}", nanos, seq)
}

/// Open a filesystem path with the requested access mode.
///
/// Used by the supervisor to open files on behalf of the sandboxed child
/// before passing the fd via `SCM_RIGHTS` or seccomp fd injection.
///
/// # Security
///
/// This function canonicalizes the path and re-checks it against the
/// `never_grant` list AFTER resolution. This prevents symlink-based
/// bypasses where a child creates `/tmp/innocent -> /etc/shadow` and
/// requests access to `/tmp/innocent`.
///
/// File creation is intentionally disabled (`create(false)`) -- the
/// supervisor only grants access to existing files. File creation should
/// go through the initial capability set, not capability expansion.
fn open_path_for_access(
    path: &std::path::Path,
    access: &nono::AccessMode,
    never_grant: &NeverGrantChecker,
) -> Result<std::fs::File> {
    use std::fs::OpenOptions;

    // Canonicalize to resolve symlinks before opening. This ensures
    // we check and open the real target, not a symlink alias.
    let canonical = std::fs::canonicalize(path).map_err(|e| {
        NonoError::SandboxInit(format!(
            "Failed to canonicalize {} for access: {}",
            path.display(),
            e
        ))
    })?;

    // Re-check never_grant on the resolved path. A symlink could point
    // from an innocuous path to a never_grant target.
    let check = never_grant.check(&canonical);
    if check.is_blocked() {
        return Err(NonoError::SandboxInit(format!(
            "Path {} resolves to {} which is blocked by never_grant policy",
            path.display(),
            canonical.display(),
        )));
    }

    let result = match access {
        nono::AccessMode::Read => OpenOptions::new().read(true).open(&canonical),
        nono::AccessMode::Write => OpenOptions::new()
            .write(true)
            .truncate(false)
            .open(&canonical),
        nono::AccessMode::ReadWrite => OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(false)
            .open(&canonical),
    };

    result.map_err(|e| {
        NonoError::SandboxInit(format!(
            "Failed to open {} for {:?} access: {}",
            canonical.display(),
            access,
            e
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exec_strategy_default_is_monitor() {
        assert_eq!(ExecStrategy::default(), ExecStrategy::Monitor);
    }

    #[test]
    fn test_exec_strategy_variants() {
        // Just verify all variants exist and are distinct
        assert_ne!(ExecStrategy::Direct, ExecStrategy::Monitor);
        assert_ne!(ExecStrategy::Monitor, ExecStrategy::Supervised);
        assert_ne!(ExecStrategy::Direct, ExecStrategy::Supervised);
    }

    #[test]
    fn test_dangerous_env_vars_linker_injection() {
        assert!(is_dangerous_env_var("LD_PRELOAD"));
        assert!(is_dangerous_env_var("LD_LIBRARY_PATH"));
        assert!(is_dangerous_env_var("LD_AUDIT"));
        assert!(is_dangerous_env_var("DYLD_INSERT_LIBRARIES"));
        assert!(is_dangerous_env_var("DYLD_LIBRARY_PATH"));
        assert!(is_dangerous_env_var("DYLD_FRAMEWORK_PATH"));
    }

    #[test]
    fn test_dangerous_env_vars_shell_injection() {
        assert!(is_dangerous_env_var("BASH_ENV"));
        assert!(is_dangerous_env_var("ENV"));
        assert!(is_dangerous_env_var("CDPATH"));
        assert!(is_dangerous_env_var("GLOBIGNORE"));
        assert!(is_dangerous_env_var("BASH_FUNC_foo%%"));
        assert!(is_dangerous_env_var("PROMPT_COMMAND"));
    }

    #[test]
    fn test_dangerous_env_vars_interpreter_injection() {
        assert!(is_dangerous_env_var("PYTHONSTARTUP"));
        assert!(is_dangerous_env_var("PYTHONPATH"));
        assert!(is_dangerous_env_var("NODE_OPTIONS"));
        assert!(is_dangerous_env_var("NODE_PATH"));
        assert!(is_dangerous_env_var("PERL5OPT"));
        assert!(is_dangerous_env_var("PERL5LIB"));
        assert!(is_dangerous_env_var("RUBYOPT"));
        assert!(is_dangerous_env_var("RUBYLIB"));
        assert!(is_dangerous_env_var("GEM_PATH"));
        assert!(is_dangerous_env_var("GEM_HOME"));
    }

    #[test]
    fn test_dangerous_env_vars_jvm_dotnet_go() {
        assert!(is_dangerous_env_var("JAVA_TOOL_OPTIONS"));
        assert!(is_dangerous_env_var("_JAVA_OPTIONS"));
        assert!(is_dangerous_env_var("DOTNET_STARTUP_HOOKS"));
        assert!(is_dangerous_env_var("GOFLAGS"));
    }

    #[test]
    fn test_dangerous_env_vars_shell_ifs() {
        assert!(is_dangerous_env_var("IFS"));
    }

    #[test]
    fn test_exec_strategy_supervised_selection() {
        // Verify the strategy selection logic from main.rs:
        // interactive || direct_exec -> Direct
        // supervised -> Supervised
        // else -> Monitor
        let strategy = ExecStrategy::Supervised;
        assert_eq!(strategy, ExecStrategy::Supervised);

        // Supervised is distinct from both Monitor and Direct
        assert_ne!(ExecStrategy::Supervised, ExecStrategy::Direct);
        assert_ne!(ExecStrategy::Supervised, ExecStrategy::Monitor);
    }

    #[test]
    fn test_safe_env_vars_allowed() {
        assert!(!is_dangerous_env_var("HOME"));
        assert!(!is_dangerous_env_var("PATH"));
        assert!(!is_dangerous_env_var("SHELL"));
        assert!(!is_dangerous_env_var("TERM"));
        assert!(!is_dangerous_env_var("LANG"));
        assert!(!is_dangerous_env_var("USER"));
        assert!(!is_dangerous_env_var("TMPDIR"));
        assert!(!is_dangerous_env_var("EDITOR"));
        assert!(!is_dangerous_env_var("XDG_CONFIG_HOME"));
        assert!(!is_dangerous_env_var("CARGO_HOME"));
        assert!(!is_dangerous_env_var("RUST_LOG"));
        assert!(!is_dangerous_env_var("SSH_AUTH_SOCK"));
    }
}
