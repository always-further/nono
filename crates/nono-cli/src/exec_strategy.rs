//! Execution strategy for sandboxed commands.
//!
//! This module defines how nono executes commands within the sandbox.
//! The strategy determines the process model and what features are available.
//!
//! # Async-Signal-Safety
//!
//! The Supervised strategy uses `fork()` to create a child process. After fork in a
//! multi-threaded program, the child can only safely call async-signal-safe functions
//! until `exec()`. This module carefully prepares all data in the parent (where
//! allocation is safe) and uses only raw libc calls in the child.

mod env_sanitization;
mod pty_mux;
#[cfg(target_os = "linux")]
mod supervisor_linux;

use nix::libc;
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};
use nono::supervisor::{ApprovalDecision, SupervisorMessage, SupervisorResponse};
use nono::{
    ApprovalBackend, CapabilitySet, DenialReason, DenialRecord, DiagnosticFormatter,
    DiagnosticMode, NonoError, Result, Sandbox, SupervisorSocket,
};
use std::collections::HashSet;
use std::ffi::{CString, OsStr};
use std::os::fd::FromRawFd;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
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
/// Maximum threads allowed when crypto library thread pool is active.
/// Main thread (1) + tokio proxy workers (2) + aws-lc-rs ECDSA pool (4).
/// When --network-profile is used with trust scanning, both the proxy runtime
/// and crypto verification threads may be active simultaneously.
const MAX_CRYPTO_THREADS: usize = 7;
/// Hard cap on retained denial records to prevent memory exhaustion.
const MAX_DENIAL_RECORDS: usize = 1000;
/// Hard cap on request IDs tracked for replay detection.
const MAX_TRACKED_REQUEST_IDS: usize = 4096;

/// Linux procfs context for resolving child-relative procfs paths in the supervisor.
///
/// `/proc/self/...` must refer to the sandboxed child process, not the unsandboxed
/// supervisor. For seccomp interceptions we may also know the calling TID, which
/// lets us resolve `/proc/thread-self/...` accurately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcfsAccessContext {
    process_pid: u32,
    thread_pid: Option<u32>,
}

impl ProcfsAccessContext {
    fn new(process_pid: u32, thread_pid: Option<u32>) -> Self {
        Self {
            process_pid,
            thread_pid,
        }
    }
}

/// PTY relay state passed to supervisor loops.
///
/// The supervisor poll loop uses these fds to relay I/O between the real
/// terminal and the PTY master (which is connected to the child's PTY slave).
struct PtyRelay<'a> {
    /// PTY master fd (connected to child's stdin/stdout/stderr)
    master_fd: std::os::fd::RawFd,
    /// Real terminal fd (/dev/tty)
    real_tty_fd: std::os::fd::RawFd,
    /// Real terminal state (for save/restore during prompts)
    real_term: &'a pty_mux::RealTerminal,
}

/// Threading context for fork safety validation.
///
/// After loading secrets from the system keystore, the keyring crate may leave
/// background threads running (for D-Bus/Security.framework communication).
/// Similarly, cryptographic verification (aws-lc-rs ECDSA) spawns idle thread
/// pool workers. These threads are benign for our fork+exec pattern because:
/// - They don't hold locks that the main thread or child process needs
/// - The child immediately calls exec(), clearing all thread state
/// - The parent's threads continue independently
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThreadingContext {
    /// Enforce single-threaded execution (default).
    /// Fork will fail if thread count > 1.
    #[default]
    Strict,

    /// Allow elevated thread count for known-safe keyring backends.
    /// Fork proceeds if thread count <= MAX_KEYRING_THREADS.
    /// Keyring threads are idle XPC dispatch workers (macOS) or D-Bus workers
    /// (Linux) after the synchronous keyring call completes — parked, not
    /// holding allocator locks. Safe for Supervised mode's post-fork
    /// Sandbox::apply() allocation.
    KeyringExpected,

    /// Allow elevated thread count for crypto library thread pools.
    /// Spawned by trust scan's ECDSA verification (aws-lc-rs) and keystore
    /// public key lookup. These are idle pool workers parked on condvars,
    /// NOT holding allocator locks — safe for supervised mode's post-fork
    /// Sandbox::apply() allocation.
    CryptoExpected,
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
    /// - Used by `nono wrap` for scripts and embedding
    Direct,

    /// Supervised mode: fork first, sandbox only child.
    /// Parent is unsandboxed.
    ///
    /// - Larger attack surface (requires hardening)
    /// - Diagnostic footer on non-zero exit
    /// - Undo support (parent can write snapshots)
    /// - IPC for capability expansion
    /// - Default for `nono shell`
    /// - Used by `nono run` when a parent process is required
    #[default]
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
    /// Directory the child process should start in.
    pub current_dir: &'a std::path::Path,
    /// Whether to suppress diagnostic output.
    pub no_diagnostics: bool,
    /// Threading context for fork safety validation.
    pub threading: ThreadingContext,
    /// Paths that are write-protected (signed instruction files).
    pub protected_paths: &'a [std::path::PathBuf],
    /// Whether runtime capability elevation is enabled.
    /// When true, the child installs seccomp-notify and the parent sets up
    /// a PTY mux for terminal isolation during approval prompts.
    /// When false, the child runs with static capabilities only.
    pub capability_elevation: bool,
}

/// Configuration for supervisor IPC in supervised execution mode.
///
/// When provided to [`execute_supervised()`], the supervisor creates a Unix
/// socket pair before fork, passes the child end to the child process via
/// the `NONO_SUPERVISOR_FD` environment variable, and runs an IPC event loop
/// in the parent that handles capability expansion requests from the
/// sandboxed child.
pub struct SupervisorConfig<'a> {
    /// Protected nono state roots that must never be granted dynamically.
    pub protected_roots: &'a [std::path::PathBuf],
    /// Deny paths that must be rejected before any approval prompt.
    pub deny_paths: &'a [std::path::PathBuf],
    /// Backend for approval decisions (terminal prompt, webhook, policy engine)
    pub approval_backend: &'a dyn ApprovalBackend,
    /// Session identifier used for audit correlation.
    pub session_id: &'a str,
    /// Allowed URL origins for supervisor-delegated browser opens (from profile).
    /// Empty means no URLs are allowed.
    pub open_url_origins: &'a [String],
    /// Whether to allow http://localhost and http://127.0.0.1 URLs.
    pub open_url_allow_localhost: bool,
    /// Whether direct LaunchServices opening is enabled for this session.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub allow_launch_services_active: bool,
}

fn canonicalize_for_deny_check(path: &Path) -> PathBuf {
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }

    if let Some(parent) = path.parent() {
        if let Ok(parent_canonical) = parent.canonicalize() {
            return parent_canonical.join(path.file_name().unwrap_or_default());
        }
    }

    path.to_path_buf()
}

#[cfg(target_os = "macos")]
fn should_install_macos_open_shim(supervisor: Option<&SupervisorConfig<'_>>) -> bool {
    supervisor.is_some_and(|cfg| !cfg.allow_launch_services_active)
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
    cmd.current_dir(config.current_dir);

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

/// Execute a command using the Supervised strategy (fork first, sandbox only child).
///
/// Forks first and applies the sandbox only in the child. The parent remains
/// unsandboxed, enabling rollback snapshots and IPC capability expansion.
///
/// # Security Properties
///
/// - Child is sandboxed with full restrictions
/// - Parent is NOT sandboxed - requires additional hardening:
///   - Linux: PR_SET_DUMPABLE(0) applied BEFORE fork (inherited by both processes,
///     closes TOCTOU window). Failure is fatal.
///   - macOS: PT_DENY_ATTACH applied in parent immediately after fork (not inherited
///     across fork on macOS). Failure is fatal - child is killed and error returned.
///
/// # Sandbox Application in Child
///
/// The child calls `Sandbox::apply()` after fork, which allocates memory (generating
/// Seatbelt profile strings on macOS, opening Landlock PathFds on Linux). This is safe
/// because we validate threading context before fork — known-safe thread contexts
/// (keyring workers, crypto pool) are idle and not holding allocator locks.
///
/// # Process Flow
///
/// 1. Prepare all data for exec in parent (CString conversion)
/// 2. Verify threading context allows fork
/// 3. Fork into parent and child
/// 4. Child: apply Landlock, install seccomp-notify, close inherited FDs, exec
/// 5. Parent: apply PR_SET_DUMPABLE(0) + PT_DENY_ATTACH, receive seccomp fd, run supervisor loop
///
/// Does NOT pipe stdout/stderr. The child inherits the parent's terminal directly,
/// preserving TTY semantics for interactive programs (e.g., Claude Code, vim).
/// The parent prints diagnostics and rollback UI after the child exits.
pub fn execute_supervised(
    config: &ExecConfig<'_>,
    supervisor: Option<&SupervisorConfig<'_>>,
    trust_interceptor: Option<crate::trust_intercept::TrustInterceptor>,
) -> Result<i32> {
    let program = &config.command[0];
    let cmd_args = &config.command[1..];

    info!("Executing (supervised): {} {:?}", program, cmd_args);

    // Use pre-resolved program path (resolved before fork)
    let program_path = config.resolved_program;

    // Convert program path to CString for execve
    let program_c = CString::new(program_path.to_string_lossy().as_bytes())
        .map_err(|_| NonoError::SandboxInit("Program path contains null byte".to_string()))?;
    let current_dir_c = CString::new(config.current_dir.as_os_str().as_bytes())
        .map_err(|_| NonoError::SandboxInit("Working directory contains null byte".to_string()))?;

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

    #[cfg(target_os = "macos")]
    let mut open_shim: Option<OpenShim> = None;

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

    // Delegate URL opens to the unsandboxed supervisor.
    //
    // On Linux, child processes inherit Landlock restrictions so the browser
    // can't access its own config directories. xdg-open and the Node.js `open`
    // package respect the BROWSER env var, so we set it to our helper.
    //
    // On macOS, the Node.js `open` package ignores BROWSER and always spawns
    // `/usr/bin/open`. Seatbelt blocks that from launching URLs. Instead, we
    // create a shim script named `open` in a temp directory and prepend it to
    // PATH so the npm `open` package hits our shim first.
    if supervisor.is_some() {
        if let Ok(nono_exe) = std::env::current_exe() {
            #[cfg(target_os = "linux")]
            {
                let exe_str = nono_exe.display().to_string();
                let quoted_exe = shell_quote(&exe_str);
                let browser_cmd = format!("BROWSER={quoted_exe} open-url-helper");
                if let Ok(cstr) = CString::new(browser_cmd) {
                    env_c.push(cstr);
                }
            }

            #[cfg(target_os = "macos")]
            {
                if should_install_macos_open_shim(supervisor) {
                    // Create a shim `open` script that delegates to nono open-url-helper.
                    // The npm `open` package spawns `open <url>` on macOS; by placing our
                    // shim earlier in PATH, we intercept the call.
                    if let Some(shim) = create_open_shim(&nono_exe) {
                        // Prepend shim dir to PATH and also set BROWSER for any tool
                        // that does respect it.
                        let current_path = std::env::var("PATH").unwrap_or_default();
                        let new_path = format!("PATH={}:{current_path}", shim.dir.path().display());
                        if let Ok(cstr) = CString::new(new_path) {
                            // Remove existing PATH from env_c, then add our modified one
                            env_c.retain(|c| !c.as_bytes().starts_with(b"PATH="));
                            env_c.push(cstr);
                        }
                        let quoted_helper = shell_quote(&shim.helper_exe.display().to_string());
                        let browser_cmd = format!("BROWSER={quoted_helper} open-url-helper");
                        if let Ok(cstr) = CString::new(browser_cmd) {
                            env_c.push(cstr);
                        }
                        open_shim = Some(shim);
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    let _keep_open_shim_alive = open_shim;

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

    // Validate threading before fork.
    // Supervised mode applies sandbox in child (allocates), so threads holding
    // allocator locks would cause deadlock. Both KeyringExpected and CryptoExpected
    // threads are safe: keyring threads are idle XPC dispatch workers (macOS) or
    // D-Bus workers (Linux) parked after the synchronous call completes; crypto
    // threads are idle aws-lc-rs pool workers parked on condvars. Neither holds
    // allocator locks.
    let thread_count = get_thread_count()?;
    match (config.threading, thread_count) {
        (_, 1) => {}
        (ThreadingContext::KeyringExpected, n) if n <= MAX_KEYRING_THREADS => {
            debug!(
                "Supervised fork with {} threads (keyring workers, idle after sync call)",
                n
            );
        }
        (ThreadingContext::CryptoExpected, n) if n <= MAX_CRYPTO_THREADS => {
            debug!(
                "Supervised fork with {} threads (crypto pool workers, idle on condvar)",
                n
            );
        }
        (ThreadingContext::Strict, n) => {
            return Err(NonoError::SandboxInit(format!(
                "Cannot fork in supervised mode: process has {} threads (expected 1). \
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
        (ThreadingContext::CryptoExpected, n) => {
            return Err(NonoError::SandboxInit(format!(
                "Cannot fork: process has {} threads (max {} with crypto pool). \
                 Unexpected threading detected.",
                n, MAX_CRYPTO_THREADS
            )));
        }
    }

    // NOTE: In supervised mode with IPC, we do NOT set
    // PR_SET_DUMPABLE(0) before fork. The child must remain dumpable so
    // the parent can read /proc/CHILD/mem for seccomp-notify path extraction.
    // In rollback-only mode (no IPC), the child is made non-dumpable after
    // sandbox apply (see child branch below).
    // The parent sets itself non-dumpable immediately after fork.

    // Create PTY pair for terminal isolation, only when capability elevation
    // is enabled. The PTY gives the child its own terminal so TUI apps can set
    // raw mode without affecting the supervisor's approval prompts.
    // Without elevation there are no prompts, so the child inherits the parent's
    // terminal directly (simpler, avoids PTY relay complexity).
    let pty_pair = if config.capability_elevation {
        Some(pty_mux::create_pty_pair()?)
    } else {
        None
    };
    let pty_slave_fd = pty_pair.as_ref().map(|p| p.slave.as_raw_fd());

    // Compute child's FD keep list: PTY slave (if elevation) + supervisor socket fd
    let mut child_keep_fds: Vec<i32> = Vec::new();
    if let Some(fd) = pty_slave_fd {
        child_keep_fds.push(fd);
    }
    if let Some(fd) = child_sock_fd {
        child_keep_fds.push(fd);
    }

    let effective_caps: &CapabilitySet = config.caps;

    // Compute max FD in parent (get_max_fd may allocate on Linux)
    let max_fd = get_max_fd();

    // Clear any stale forwarding target before forking.
    clear_signal_forwarding_target();

    // SAFETY: fork() is safe here because we validated threading context.
    // Child will call Sandbox::apply() which allocates, but this is safe
    // because the child is single-threaded (validated above).
    let fork_result = unsafe { fork() };

    match fork_result {
        Ok(ForkResult::Child) => {
            // CHILD: Set up PTY, apply sandbox, then exec.
            //
            // The child applies the sandbox itself before exec.
            // Sandbox::apply() allocates (Seatbelt profile generation, Landlock
            // PathFd opens) but this is safe because we validated single-threaded
            // execution before fork, giving us a clean heap.

            // The supervisor socket must survive exec into the sandboxed command,
            // and later into any helper (`open-url-helper`) that needs to speak
            // IPC back to the unsandboxed parent. `UnixStream::pair()` creates
            // fds with close-on-exec set, so clear it on the child end here.
            if let Some(fd) = child_sock_fd {
                if let Err(e) = clear_close_on_exec(fd) {
                    let detail = format!(
                        "nono: failed to clear close-on-exec on supervisor socket: {}\n",
                        e
                    );
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
            }

            // Set up PTY slave as the child's controlling terminal (elevation only).
            // This gives the child its own terminal so TUI apps can freely
            // change terminal modes without affecting the supervisor.
            // SAFETY: We are in the child after fork, slave_fd is valid.
            if let Some(slave_fd) = pty_slave_fd {
                unsafe { pty_mux::setup_child_pty(slave_fd) };
            }

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

            // On Linux with capability elevation: install seccomp-notify filter
            // AFTER Landlock. The kernel evaluates seccomp before LSM hooks
            // regardless of installation order, so the security properties are
            // identical. All openat/openat2 from exec'd child are routed to
            // the supervisor, which can inject fds for approved paths.
            // Without elevation, seccomp is not installed — the child runs
            // with static Landlock capabilities only.
            #[cfg(target_os = "linux")]
            {
                if config.capability_elevation {
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
                                    let msg =
                                        b"nono: failed to send seccomp notify fd to supervisor\n";
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
            }

            // When capability elevation is off, make the child non-dumpable
            // to prevent ptrace attachment from same-UID processes. When
            // elevation is active, the child must stay dumpable so the parent
            // can read /proc/CHILD/mem for seccomp-notify path extraction.
            #[cfg(target_os = "linux")]
            {
                if !config.capability_elevation {
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

            // SAFETY: `current_dir_c` was prepared before fork and remains valid
            // for the lifetime of the child. `chdir` is async-signal-safe.
            let chdir_result = unsafe { libc::chdir(current_dir_c.as_ptr()) };
            if chdir_result != 0 {
                const MSG: &[u8] = b"nono: failed to enter child working directory\n";
                // SAFETY: `write` and `_exit` are async-signal-safe and we're in
                // the post-fork child path where higher-level Rust APIs are unsafe.
                unsafe {
                    libc::write(
                        libc::STDERR_FILENO,
                        MSG.as_ptr().cast::<libc::c_void>(),
                        MSG.len(),
                    );
                    libc::_exit(126);
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
            // Close the PTY slave in the parent (only the child uses it).
            // The master stays open for relay. Destructure to take ownership
            // of master and drop slave.
            let pty_master = pty_pair.map(|p| {
                drop(p.slave);
                p.master
            });

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

            // On Linux with capability elevation: receive the seccomp notify fd
            // from the child. The child installed a seccomp-notify filter and
            // sent the fd via SCM_RIGHTS on the supervisor socket.
            // Only attempt recv when elevation is active (child sends the fd).
            #[cfg(target_os = "linux")]
            let seccomp_notify_fd: Option<OwnedFd> = if config.capability_elevation {
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
            setup_signal_forwarding(child);
            let _signal_forwarding_guard = SignalForwardingGuard;

            // Set up PTY relay when capability elevation is enabled.
            // The real terminal is put into raw mode so keystrokes pass through
            // to the child transparently. When the supervisor needs to prompt,
            // it restores the terminal, prompts, then re-enters raw mode.
            // Without elevation, the child inherits the parent's terminal directly.
            let real_term = if pty_master.is_some() {
                Some(pty_mux::RealTerminal::open()?)
            } else {
                None
            };
            let pty_master_fd = pty_master.as_ref().map(|m| m.as_raw_fd());
            let real_tty_fd = real_term.as_ref().map(|t| t.as_raw_fd());

            if let (Some(master_fd), Some(tty_fd)) = (pty_master_fd, real_tty_fd) {
                pty_mux::set_nonblocking(master_fd)?;
                pty_mux::setup_sigwinch_forwarding(tty_fd, master_fd);
                if let Some(ref rt) = real_term {
                    rt.enter_raw_mode()?;
                }
            }

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

            // Build optional PTY relay (only when capability elevation allocates a PTY).
            let relay = if let (Some(mfd), Some(tfd), Some(ref rt)) =
                (pty_master_fd, real_tty_fd, &real_term)
            {
                Some(PtyRelay {
                    master_fd: mfd,
                    real_tty_fd: tfd,
                    real_term: rt,
                })
            } else {
                None
            };

            // Run supervisor IPC loop when configured, with or without PTY relay.
            // Trust interception runs over the IPC socket regardless of
            // capability_elevation. The PTY relay is only present when
            // elevation is active (seccomp-notify + interactive prompts).
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
                            trust_interceptor,
                            relay.as_ref(),
                        )?
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        run_supervisor_loop(
                            child,
                            &mut sup_sock,
                            sup_cfg,
                            trust_interceptor,
                            relay.as_ref(),
                        )?
                    }
                } else if let Some(ref r) = relay {
                    // PTY relay active but no supervisor — just relay I/O.
                    let status = wait_for_child_with_relay(child, r)?;
                    (status, Vec::new())
                } else {
                    // No supervisor, no PTY — simple wait.
                    let status = wait_for_child(child)?;
                    (status, Vec::new())
                };

            // Restore real terminal and clean up PTY state
            if real_term.is_some() {
                pty_mux::clear_sigwinch_forwarding();
            }
            if let Some(ref rt) = real_term {
                let _ = rt.restore();
            }
            // Drop PTY master to send EOF to child (if still alive)
            drop(pty_master);

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
            if exit_code != 0 && !config.no_diagnostics {
                let mode = if supervisor.is_some() {
                    DiagnosticMode::Supervised
                } else {
                    DiagnosticMode::Standard
                };
                let mut formatter = DiagnosticFormatter::new(config.caps)
                    .with_mode(mode)
                    .with_denials(&denials)
                    .with_protected_paths(config.protected_paths);
                if let Some(program) = config.command.first() {
                    formatter = formatter.with_command(nono::diagnostic::CommandContext {
                        program: program.clone(),
                        resolved_path: config.resolved_program.to_path_buf(),
                    });
                }
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

/// Wait for child process while relaying PTY I/O.
///
/// Used when no supervisor IPC is configured but we still need to relay
/// the PTY for terminal isolation.
fn wait_for_child_with_relay(child: Pid, relay: &PtyRelay<'_>) -> Result<WaitStatus> {
    loop {
        // Poll: real_tty (user input) + pty_master (child output)
        let mut pfds = [
            libc::pollfd {
                fd: relay.real_tty_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: relay.master_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        // SAFETY: pfds is a valid array on the stack
        let ret = unsafe { libc::poll(pfds.as_mut_ptr(), 2, 200) };

        if ret > 0 {
            // User input -> PTY master (child's stdin)
            if pfds[0].revents & libc::POLLIN != 0 {
                pty_mux::relay_bytes(relay.real_tty_fd, relay.master_fd);
            }
            // Child output -> real terminal
            if pfds[1].revents & libc::POLLIN != 0 {
                pty_mux::relay_bytes(relay.master_fd, relay.real_tty_fd);
            }
        }

        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => continue,
            Ok(status) => {
                // Drain any remaining output from PTY master
                loop {
                    if pty_mux::relay_bytes(relay.master_fd, relay.real_tty_fd) == 0 {
                        break;
                    }
                }
                return Ok(status);
            }
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => {
                return Err(NonoError::SandboxInit(format!("waitpid() failed: {}", e)));
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
/// - Only one `execute_supervised` invocation can be active at a time
/// - Concurrent calls from different threads would corrupt the child PID
/// - This is enforced by the thread count check in `execute_supervised`
///
/// This is acceptable because:
/// 1. `execute_supervised` is CLI code, not library code (per DESIGN-supervisor.md)
/// 2. The fork+wait model inherently requires single-threaded execution
/// 3. Library consumers would use `Sandbox::apply()` directly, not the fork machinery
fn setup_signal_forwarding(child: Pid) {
    // ==================== SAFETY INVARIANT ====================
    // This static variable is ONLY safe because execute_supervised()
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
    CHILD_PID.store(child.as_raw(), std::sync::atomic::Ordering::SeqCst);

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

static CHILD_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

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

fn clear_signal_forwarding_target() {
    CHILD_PID.store(0, std::sync::atomic::Ordering::SeqCst);
}

struct SignalForwardingGuard;

impl Drop for SignalForwardingGuard {
    fn drop(&mut self) {
        clear_signal_forwarding_target();
    }
}
/// Get the current thread count for the process.
///
/// Used to verify single-threaded execution before fork().
/// Returns an error if the count cannot be determined, since fork()
/// safety depends on knowing the exact thread count.
fn get_thread_count() -> Result<usize> {
    #[cfg(target_os = "linux")]
    {
        // On Linux, read /proc/self/status for accurate thread count
        let status = std::fs::read_to_string("/proc/self/status").map_err(|e| {
            NonoError::SandboxInit(format!(
                "Cannot read /proc/self/status for thread count: {e}"
            ))
        })?;
        for line in status.lines() {
            if let Some(count_str) = line.strip_prefix("Threads:") {
                return count_str.trim().parse::<usize>().map_err(|e| {
                    NonoError::SandboxInit(format!("Cannot parse thread count: {e}"))
                });
            }
        }
        Err(NonoError::SandboxInit(
            "Thread count not found in /proc/self/status".to_string(),
        ))
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
                return Ok(thread_count as usize);
            }
        }
        Err(NonoError::SandboxInit(
            "Cannot determine thread count via mach task_threads API".to_string(),
        ))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(NonoError::SandboxInit(
            "Cannot determine thread count on this platform".to_string(),
        ))
    }
}

/// Supervisor IPC event loop (non-Linux).
///
/// Polls the supervisor socket and PTY relay fds for activity.
/// Uses `poll(2)` with a 200ms timeout to periodically check child status.
/// Returns the child's wait status and any denial records collected.
#[cfg(not(target_os = "linux"))]
fn run_supervisor_loop(
    child: Pid,
    sock: &mut SupervisorSocket,
    config: &SupervisorConfig<'_>,
    mut trust_interceptor: Option<crate::trust_intercept::TrustInterceptor>,
    relay: Option<&PtyRelay<'_>>,
) -> Result<(WaitStatus, Vec<DenialRecord>)> {
    let _ = config.session_id;
    let sock_fd = sock.as_raw_fd();
    let mut denials = Vec::new();
    let mut seen_request_ids = HashSet::new();

    // PTY relay fds: -1 when no relay (supervisor-only mode, no PTY mux)
    let relay_tty_fd = relay.map_or(-1, |r| r.real_tty_fd);
    let relay_master_fd = relay.map_or(-1, |r| r.master_fd);

    loop {
        // Poll: [0] supervisor socket, [1] real_tty (user input), [2] pty_master (child output)
        let mut pfds = [
            libc::pollfd {
                fd: sock_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: relay_tty_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: relay_master_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        // SAFETY: pfds is a valid array on the stack
        let ret = unsafe { libc::poll(pfds.as_mut_ptr(), 3, 200) };

        if ret > 0 {
            // Supervisor socket
            if pfds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                debug!("Supervisor socket closed by child");
                break;
            }
            if pfds[0].revents & libc::POLLIN != 0 {
                // Pause relay if active: restore terminal for interactive prompt
                if let Some(r) = relay {
                    let _ = r.real_term.restore();
                }
                match sock.recv_message() {
                    Ok(msg) => {
                        if let Err(e) = handle_supervisor_message(
                            sock,
                            msg,
                            child,
                            config,
                            &mut denials,
                            &mut seen_request_ids,
                            trust_interceptor.as_mut(),
                        ) {
                            warn!("Error handling supervisor message: {}", e);
                        }
                    }
                    Err(e) => {
                        debug!("Error receiving supervisor message: {}", e);
                        break;
                    }
                }
                // Resume relay if active: re-enter raw mode
                if let Some(r) = relay {
                    let _ = r.real_term.enter_raw_mode();
                }
            }

            // PTY relay: user input -> child
            if relay.is_some() && pfds[1].revents & libc::POLLIN != 0 {
                pty_mux::relay_bytes(relay_tty_fd, relay_master_fd);
            }
            // PTY relay: child output -> user
            if relay.is_some() && pfds[2].revents & libc::POLLIN != 0 {
                pty_mux::relay_bytes(relay_master_fd, relay_tty_fd);
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
            Ok(status) => {
                // Drain remaining child output
                if relay.is_some() {
                    loop {
                        if pty_mux::relay_bytes(relay_master_fd, relay_tty_fd) == 0 {
                            break;
                        }
                    }
                }
                return Ok((status, denials));
            }
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
/// - PTY relay (real terminal <-> PTY master), when present
/// - child process exit via non-blocking `waitpid()`
///
/// When a seccomp notification requires interactive approval, the relay is
/// paused (terminal restored to canonical mode) so the user can type a response.
/// After the prompt, raw mode is re-entered and relay resumes.
///
/// The relay is optional: when `capability_elevation` is off, no PTY is
/// allocated but the supervisor loop still runs for trust interception over
/// the IPC socket.
///
/// Returns the child's wait status and any denial records collected.
#[cfg(target_os = "linux")]
fn run_supervisor_loop(
    child: Pid,
    sock: &mut SupervisorSocket,
    config: &SupervisorConfig<'_>,
    seccomp_fd: Option<&OwnedFd>,
    initial_caps: &[(std::path::PathBuf, bool)],
    mut trust_interceptor: Option<crate::trust_intercept::TrustInterceptor>,
    relay: Option<&PtyRelay<'_>>,
) -> Result<(WaitStatus, Vec<DenialRecord>)> {
    let sock_fd = sock.as_raw_fd();
    let notify_raw_fd = seccomp_fd.map(|fd| fd.as_raw_fd());
    let mut rate_limiter = supervisor_linux::RateLimiter::new(10, 5);
    let mut denials = Vec::new();
    let mut seen_request_ids = HashSet::new();
    let mut sock_fd_active = true;

    // PTY relay fds: -1 when no relay (supervisor-only mode, no PTY mux)
    let relay_tty_fd = relay.map_or(-1, |r| r.real_tty_fd);
    let relay_master_fd = relay.map_or(-1, |r| r.master_fd);

    loop {
        // Build poll array:
        // [0] supervisor socket (or -1 if dead)
        // [1] seccomp notify fd (or -1 if absent)
        // [2] real_tty (user input for relay, or -1 if no relay)
        // [3] pty_master (child output for relay, or -1 if no relay)
        let mut pfds = [
            libc::pollfd {
                fd: if sock_fd_active { sock_fd } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: notify_raw_fd.unwrap_or(-1),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: relay_tty_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: relay_master_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        // SAFETY: pfds is a valid array on the stack
        let ret = unsafe { libc::poll(pfds.as_mut_ptr(), 4, 200) };

        match ret.cmp(&0) {
            std::cmp::Ordering::Greater => {
                // [0] Supervisor socket
                if sock_fd_active && pfds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                    if notify_raw_fd.is_some() {
                        debug!("Supervisor socket closed, continuing for seccomp notifications");
                        sock_fd_active = false;
                    } else {
                        debug!("Supervisor socket closed by child");
                        break;
                    }
                }
                if sock_fd_active && pfds[0].revents & libc::POLLIN != 0 {
                    // Pause relay if active: restore terminal for interactive prompt
                    if let Some(r) = relay {
                        let _ = r.real_term.restore();
                    }
                    match sock.recv_message() {
                        Ok(msg) => {
                            if let Err(e) = handle_supervisor_message(
                                sock,
                                msg,
                                child,
                                config,
                                &mut denials,
                                &mut seen_request_ids,
                                trust_interceptor.as_mut(),
                            ) {
                                warn!("Error handling supervisor message: {}", e);
                            }
                        }
                        Err(e) => {
                            debug!("Error receiving supervisor message: {}", e);
                            if notify_raw_fd.is_none() {
                                if let Some(r) = relay {
                                    let _ = r.real_term.enter_raw_mode();
                                }
                                break;
                            }
                            sock_fd_active = false;
                        }
                    }
                    // Resume relay if active
                    if let Some(r) = relay {
                        let _ = r.real_term.enter_raw_mode();
                    }
                }

                // [1] Seccomp notify fd
                if pfds[1].revents & libc::POLLIN != 0 {
                    if let Some(nfd) = notify_raw_fd {
                        if let Some(r) = relay {
                            if let Err(e) = r.real_term.restore() {
                                warn!("Failed to restore terminal before seccomp prompt: {}", e);
                            }
                        }
                        if let Err(e) = supervisor_linux::handle_seccomp_notification(
                            nfd,
                            child,
                            config,
                            initial_caps,
                            &mut rate_limiter,
                            &mut denials,
                            trust_interceptor.as_mut(),
                        ) {
                            debug!("Error handling seccomp notification: {}", e);
                        }
                        if let Some(r) = relay {
                            let _ = r.real_term.enter_raw_mode();
                        }
                    }
                }

                // [2] PTY relay: user input -> child
                if relay.is_some() && pfds[2].revents & libc::POLLIN != 0 {
                    pty_mux::relay_bytes(relay_tty_fd, relay_master_fd);
                }
                // [3] PTY relay: child output -> user
                if relay.is_some() && pfds[3].revents & libc::POLLIN != 0 {
                    pty_mux::relay_bytes(relay_master_fd, relay_tty_fd);
                }
            }
            std::cmp::Ordering::Less => {
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::Interrupted {
                    warn!("poll() error in supervisor loop: {}", err);
                    break;
                }
            }
            std::cmp::Ordering::Equal => {}
        }

        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => continue,
            Ok(status) => {
                // Drain remaining child output
                if relay.is_some() {
                    loop {
                        if pty_mux::relay_bytes(relay_master_fd, relay_tty_fd) == 0 {
                            break;
                        }
                    }
                }
                return Ok((status, denials));
            }
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
/// 1. Check protected nono state roots - those paths are rejected immediately
/// 2. Delegate to `ApprovalBackend` for the decision
/// 3. If granted, open the path and send the fd via `SCM_RIGHTS`
/// 4. Send the decision response
/// 5. Record denials for diagnostic footer
fn handle_supervisor_message(
    sock: &mut SupervisorSocket,
    msg: SupervisorMessage,
    child: Pid,
    config: &SupervisorConfig<'_>,
    denials: &mut Vec<DenialRecord>,
    seen_request_ids: &mut HashSet<String>,
    mut trust_interceptor: Option<&mut crate::trust_intercept::TrustInterceptor>,
) -> Result<()> {
    match msg {
        SupervisorMessage::Request(request) => {
            // Replay detection and bounded request-id cache.
            let replay_denial_reason = if seen_request_ids.contains(&request.request_id) {
                Some("Duplicate request_id rejected (replay detected)")
            } else if seen_request_ids.len() >= MAX_TRACKED_REQUEST_IDS {
                Some("Request replay cache is full; refusing request")
            } else {
                None
            };

            if let Some(reason) = replay_denial_reason {
                record_denial(
                    denials,
                    DenialRecord {
                        path: request.path.clone(),
                        access: request.access,
                        reason: DenialReason::PolicyBlocked,
                    },
                );
                let response = SupervisorResponse::Decision {
                    request_id: request.request_id,
                    decision: ApprovalDecision::Denied {
                        reason: reason.to_string(),
                    },
                };
                return sock.send_response(&response);
            }
            seen_request_ids.insert(request.request_id.clone());

            // Digest from trust verification, used for TOCTOU re-check at open time.
            // Set by the trust interceptor branch when an instruction file is verified.
            let mut verified_digest: Option<String> = None;

            let canonical_request_path = canonicalize_for_deny_check(&request.path);

            let decision = if let Some(protected_root) =
                crate::protected_paths::overlapping_protected_root(
                    &request.path,
                    false,
                    config.protected_roots,
                ) {
                debug!(
                    "Supervisor: path {} blocked by protected root {}",
                    request.path.display(),
                    protected_root.display()
                );
                record_denial(
                    denials,
                    DenialRecord {
                        path: request.path.clone(),
                        access: request.access,
                        reason: DenialReason::PolicyBlocked,
                    },
                );
                ApprovalDecision::Denied {
                    reason: format!(
                        "Path overlaps protected nono state root '{}': {}",
                        protected_root.display(),
                        request.path.display()
                    ),
                }
            } else if let Some(deny_path) =
                crate::policy::matching_deny_path(&canonical_request_path, config.deny_paths)
            {
                debug!(
                    "Supervisor: path {} blocked by deny path {}",
                    canonical_request_path.display(),
                    deny_path.display()
                );
                record_denial(
                    denials,
                    DenialRecord {
                        path: request.path.clone(),
                        access: request.access,
                        reason: DenialReason::PolicyBlocked,
                    },
                );
                ApprovalDecision::Denied {
                    reason: format!(
                        "Path is denied by active sandbox policy '{}': {}",
                        deny_path.display(),
                        request.path.display()
                    ),
                }
            } else if let Some(trust_result) = trust_interceptor
                .as_mut()
                .and_then(|ti| ti.check_path(&request.path))
            {
                // 2. Trust verification for instruction files
                match trust_result {
                    Ok(verified) => {
                        debug!(
                            "Supervisor: instruction file {} verified (publisher: {})",
                            request.path.display(),
                            verified.publisher,
                        );
                        // Stash the verified digest for TOCTOU re-check at open time
                        verified_digest = Some(verified.digest);
                        // Instruction file verified — proceed to approval backend
                        match config.approval_backend.request_capability(&request) {
                            Ok(d) => {
                                if d.is_denied() {
                                    record_denial(
                                        denials,
                                        DenialRecord {
                                            path: request.path.clone(),
                                            access: request.access,
                                            reason: DenialReason::UserDenied,
                                        },
                                    );
                                }
                                d
                            }
                            Err(e) => {
                                warn!("Approval backend error: {}", e);
                                record_denial(
                                    denials,
                                    DenialRecord {
                                        path: request.path.clone(),
                                        access: request.access,
                                        reason: DenialReason::BackendError,
                                    },
                                );
                                ApprovalDecision::Denied {
                                    reason: format!("Approval backend error: {e}"),
                                }
                            }
                        }
                    }
                    Err(reason) => {
                        // Instruction file failed trust verification — auto-deny
                        debug!(
                            "Supervisor: instruction file {} failed trust verification: {}",
                            request.path.display(),
                            reason
                        );
                        record_denial(
                            denials,
                            DenialRecord {
                                path: request.path.clone(),
                                access: request.access,
                                reason: DenialReason::PolicyBlocked,
                            },
                        );
                        ApprovalDecision::Denied {
                            reason: format!("Instruction file failed trust verification: {reason}"),
                        }
                    }
                }
            } else {
                // 3. Delegate to approval backend (non-instruction files)
                match config.approval_backend.request_capability(&request) {
                    Ok(d) => {
                        if d.is_denied() {
                            record_denial(
                                denials,
                                DenialRecord {
                                    path: request.path.clone(),
                                    access: request.access,
                                    reason: DenialReason::UserDenied,
                                },
                            );
                        }
                        d
                    }
                    Err(e) => {
                        warn!("Approval backend error: {}", e);
                        record_denial(
                            denials,
                            DenialRecord {
                                path: request.path.clone(),
                                access: request.access,
                                reason: DenialReason::BackendError,
                            },
                        );
                        ApprovalDecision::Denied {
                            reason: format!("Approval backend error: {e}"),
                        }
                    }
                }
            };

            // 3. If granted, open the path and send fd before the response
            if decision.is_granted() {
                match open_path_for_access(
                    &request.path,
                    &request.access,
                    config.protected_roots,
                    verified_digest.as_deref(),
                    Some(ProcfsAccessContext::new(child.as_raw() as u32, None)),
                ) {
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
        SupervisorMessage::OpenUrl(url_request) => {
            let request_id = url_request.request_id.clone();

            match validate_and_open_url(&url_request.url, config) {
                Ok(()) => {
                    info!("Supervisor: opened URL {} for child", url_request.url);
                    let response = SupervisorResponse::UrlOpened {
                        request_id,
                        success: true,
                        error: None,
                    };
                    sock.send_response(&response)?;
                }
                Err(reason) => {
                    warn!(
                        "Supervisor: URL open denied for {}: {}",
                        url_request.url, reason
                    );
                    let response = SupervisorResponse::UrlOpened {
                        request_id,
                        success: false,
                        error: Some(reason),
                    };
                    sock.send_response(&response)?;
                }
            }
        }
    }

    Ok(())
}

/// Maximum URL length to prevent abuse via oversized URLs.
const MAX_URL_LENGTH: usize = 8192;

/// Validate a URL against the profile's allowed origins, then open it in the user's browser.
///
/// The supervisor (unsandboxed parent) performs this operation so the browser
/// launches outside the sandbox with full access to its own config files.
fn validate_and_open_url(
    url: &str,
    config: &SupervisorConfig<'_>,
) -> std::result::Result<(), String> {
    validate_url(url, config)?;
    open_url_in_browser(url)
}

/// Validate a URL against the profile's allowed origins and scheme rules.
///
/// Returns `Ok(())` if the URL passes all checks. Does not open the browser.
fn validate_url(url: &str, config: &SupervisorConfig<'_>) -> std::result::Result<(), String> {
    // Length check
    if url.len() > MAX_URL_LENGTH {
        return Err(format!(
            "URL exceeds maximum length ({} > {})",
            url.len(),
            MAX_URL_LENGTH
        ));
    }

    // Parse URL to extract origin
    let parsed = url::Url::parse(url).map_err(|e| format!("Invalid URL: {e}"))?;

    let scheme = parsed.scheme();
    let host = parsed.host_str().unwrap_or("");

    // Check localhost first
    let is_localhost = host == "localhost" || host == "127.0.0.1" || host == "::1";
    if is_localhost {
        if scheme != "http" && scheme != "https" {
            return Err(format!(
                "Localhost URL must use http or https scheme, got: {scheme}"
            ));
        }
        if !config.open_url_allow_localhost {
            return Err("Localhost URLs are not allowed by this profile".to_string());
        }
    } else {
        // Non-localhost: must be https
        if scheme != "https" {
            return Err(format!(
                "Only https:// URLs are allowed (got {scheme}://). \
                 file://, javascript:, data:, and other schemes are blocked."
            ));
        }

        // Check against allowed origins
        let url_origin = parsed.origin().unicode_serialization();
        let origin_allowed = config.open_url_origins.contains(&url_origin);

        if !origin_allowed {
            return Err(format!(
                "Origin {url_origin} is not in the profile's open_urls.allow_origins list"
            ));
        }
    }

    Ok(())
}

/// Open a URL in the user's default browser.
///
/// Uses `open` on macOS and `xdg-open` on Linux. Runs in the unsandboxed
/// parent process so the browser has full system access.
fn open_url_in_browser(url: &str) -> std::result::Result<(), String> {
    #[cfg(target_os = "macos")]
    let result = std::process::Command::new("open")
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    #[cfg(target_os = "linux")]
    let result = std::process::Command::new("xdg-open")
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let result: std::result::Result<std::process::ExitStatus, std::io::Error> =
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "URL opening not supported on this platform",
        ));

    match result {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!("Browser opener exited with status: {status}")),
        Err(e) => Err(format!("Failed to launch browser: {e}")),
    }
}

/// Clear `FD_CLOEXEC` on a file descriptor so it survives `execve()`.
fn clear_close_on_exec(fd: i32) -> Result<()> {
    // SAFETY: `fcntl` is called with a valid fd owned by this process.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(NonoError::SandboxInit(format!(
            "fcntl(F_GETFD) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    let new_flags = flags & !libc::FD_CLOEXEC;
    if new_flags != flags {
        // SAFETY: `fcntl` is called with a valid fd and descriptor flags.
        let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, new_flags) };
        if rc < 0 {
            return Err(NonoError::SandboxInit(format!(
                "fcntl(F_SETFD) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
    }

    Ok(())
}

pub(super) fn record_denial(denials: &mut Vec<DenialRecord>, record: DenialRecord) {
    if denials.len() < MAX_DENIAL_RECORDS {
        denials.push(record);
    }
}

/// Create a temporary directory containing an `open` shim script on macOS.
///
/// The shim intercepts calls to `open` (which the Node.js `open` package
/// uses on macOS) and routes URL arguments through `nono open-url-helper`.
/// Non-URL arguments are passed through to `/usr/bin/open` so that
/// non-browser `open` invocations (e.g. opening files) still work.
///
/// Returns the path to the shim directory, or `None` on failure.
#[cfg(target_os = "macos")]
struct OpenShim {
    dir: tempfile::TempDir,
    helper_exe: std::path::PathBuf,
}

#[cfg(target_os = "macos")]
fn create_open_shim(nono_exe: &std::path::Path) -> Option<OpenShim> {
    use std::os::unix::fs::PermissionsExt;

    let shim_dir = tempfile::Builder::new()
        .prefix("nono-shim-")
        .tempdir()
        .ok()?;
    let shim_dir_path = shim_dir.path();

    // Keep the helper inside the shim directory so it is always readable and
    // executable under the sandbox's temp-dir allowlist, regardless of where
    // the original `nono` binary was launched from.
    let helper_path = shim_dir_path.join("nono-open-url-helper");
    if std::fs::copy(nono_exe, &helper_path).is_err() {
        return None;
    }
    if std::fs::set_permissions(&helper_path, std::fs::Permissions::from_mode(0o755)).is_err() {
        return None;
    }

    let shim_path = shim_dir_path.join("open");
    let quoted_helper = shell_quote(&helper_path.display().to_string());

    // The shim script scans all arguments for the first URL-like value. If one
    // is present, delegate to nono open-url-helper. Otherwise fall through to
    // /usr/bin/open for non-URL uses (opening files, apps, etc.).
    let script = format!(
        r#"#!/bin/sh
# nono URL open shim — intercepts `open` calls for browser URL delegation
url_arg=""
for arg in "$@"; do
    case "$arg" in
        http://*|https://*)
            url_arg="$arg"
            break
            ;;
    esac
done

if [ -n "$url_arg" ]; then
    exec {quoted_helper} open-url-helper "$url_arg"
else
    exec /usr/bin/open "$@"
fi
"#
    );

    if std::fs::write(&shim_path, script).is_err() {
        return None;
    }
    if std::fs::set_permissions(&shim_path, std::fs::Permissions::from_mode(0o755)).is_err() {
        return None;
    }

    Some(OpenShim {
        dir: shim_dir,
        helper_exe: helper_path,
    })
}

/// Shell-quote a string for safe embedding in `sh -c` commands.
/// If the string contains no special characters, returns it unchanged.
/// Otherwise wraps it in single quotes, escaping embedded single quotes.
fn shell_quote(s: &str) -> String {
    // If the string is safe as-is, skip quoting
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b))
    {
        return s.to_string();
    }
    // Single-quote the string, replacing ' with '\'' (end quote, escaped quote, start quote)
    let mut quoted = String::with_capacity(s.len() + 2);
    quoted.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

/// Generate a unique request ID from timestamp + monotonic counter.
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

/// Resolve `/proc/self` and `/proc/thread-self` against the sandboxed child.
///
/// Without this rewrite, canonicalizing `/proc/self/...` in the supervisor would
/// resolve to the supervisor's procfs view instead of the child's.
fn resolve_procfs_path_for_child(
    path: &Path,
    procfs_context: Option<ProcfsAccessContext>,
) -> Result<PathBuf> {
    let Some(procfs_context) = procfs_context else {
        return Ok(path.to_path_buf());
    };

    let mut components = path.components();
    if components.next() != Some(Component::RootDir)
        || components.next() != Some(Component::Normal(OsStr::new("proc")))
    {
        return Ok(path.to_path_buf());
    }

    let Some(proc_component) = components.next() else {
        return Ok(path.to_path_buf());
    };

    let mut rewritten = PathBuf::from("/proc");
    match proc_component {
        Component::Normal(part) if part == OsStr::new("self") => {
            rewritten.push(procfs_context.process_pid.to_string());
        }
        Component::Normal(part) if part == OsStr::new("thread-self") => {
            let thread_pid = procfs_context.thread_pid.ok_or_else(|| {
                NonoError::SandboxInit(
                    "Cannot resolve /proc/thread-self without a requesting thread ID".to_string(),
                )
            })?;
            rewritten.push(procfs_context.process_pid.to_string());
            rewritten.push("task");
            rewritten.push(thread_pid.to_string());
        }
        _ => return Ok(path.to_path_buf()),
    }

    for component in components {
        match component {
            Component::Normal(part) => rewritten.push(part),
            Component::CurDir => rewritten.push("."),
            Component::ParentDir => rewritten.push(".."),
            Component::RootDir | Component::Prefix(_) => {}
        }
    }

    Ok(rewritten)
}

/// Enforce the supervisor's sensitive procfs deny rules.
///
/// Same-process procfs access is allowed after `/proc/self` rewriting. Foreign
/// process reads stay blocked.
fn validate_procfs_access(
    canonical: &Path,
    procfs_context: Option<ProcfsAccessContext>,
) -> std::result::Result<(), OpenPathError> {
    const SENSITIVE_PROC_FILES: &[&str] =
        &["mem", "environ", "maps", "syscall", "stack", "cmdline"];

    let Some(suffix) = canonical.to_str().and_then(|s| s.strip_prefix("/proc/")) else {
        return Ok(());
    };

    let allowed_pid = procfs_context.map(|ctx| ctx.process_pid.to_string());
    let components: Vec<&str> = suffix.split('/').collect();

    if components.len() == 2
        && components[0].chars().all(|c| c.is_ascii_digit())
        && SENSITIVE_PROC_FILES.contains(&components[1])
    {
        if allowed_pid.as_deref() == Some(components[0]) {
            return Ok(());
        }
        return Err(OpenPathError::policy_blocked(format!(
            "Access to /proc/{}/{} is blocked by policy",
            components[0], components[1],
        )));
    }

    if components.len() == 4
        && components[0].chars().all(|c| c.is_ascii_digit())
        && components[1] == "task"
        && components[2].chars().all(|c| c.is_ascii_digit())
        && SENSITIVE_PROC_FILES.contains(&components[3])
    {
        if allowed_pid.as_deref() == Some(components[0]) {
            return Ok(());
        }
        return Err(OpenPathError::policy_blocked(format!(
            "Access to /proc/{}/task/{}/{} is blocked by policy",
            components[0], components[2], components[3],
        )));
    }

    Ok(())
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug)]
struct OpenPathError {
    errno: i32,
    message: String,
    policy_blocked: bool,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl OpenPathError {
    fn policy_blocked(message: String) -> Self {
        Self {
            errno: libc::EPERM,
            message,
            policy_blocked: true,
        }
    }

    fn io(message: String, source: &std::io::Error) -> Self {
        Self {
            errno: source.raw_os_error().unwrap_or(libc::EIO),
            message,
            policy_blocked: false,
        }
    }

    fn internal(message: String) -> Self {
        Self {
            errno: libc::EIO,
            message,
            policy_blocked: false,
        }
    }

    fn errno(&self) -> i32 {
        self.errno
    }

    fn is_policy_blocked(&self) -> bool {
        self.policy_blocked
    }
}

impl std::fmt::Display for OpenPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for OpenPathError {}

/// Open a filesystem path with the requested access mode.
///
/// Used by the supervisor to open files on behalf of the sandboxed child
/// before passing the fd via `SCM_RIGHTS` or seccomp fd injection.
///
/// # Security
///
/// This function canonicalizes the path and re-checks it against protected
/// nono state roots AFTER resolution. This prevents symlink-based bypasses
/// where a child creates `/tmp/innocent -> ~/.nono` and requests access to the
/// innocuous alias.
///
/// File creation is intentionally disabled (`create(false)`) -- the
/// supervisor only grants access to existing files. File creation should
/// go through the initial capability set, not capability expansion.
fn open_path_for_access(
    path: &Path,
    access: &nono::AccessMode,
    protected_roots: &[PathBuf],
    trust_digest: Option<&str>,
    procfs_context: Option<ProcfsAccessContext>,
) -> std::result::Result<std::fs::File, OpenPathError> {
    let resolved_path = resolve_procfs_path_for_child(path, procfs_context)
        .map_err(|e| OpenPathError::internal(e.to_string()))?;

    // Canonicalize to resolve symlinks before opening. This ensures
    // we check and open the real target, not a symlink alias.
    let canonical = std::fs::canonicalize(&resolved_path).map_err(|e| {
        OpenPathError::io(
            format!(
                "Failed to canonicalize {} for access: {}",
                path.display(),
                e
            ),
            &e,
        )
    })?;

    if let Some(protected_root) =
        crate::protected_paths::overlapping_protected_root(&canonical, false, protected_roots)
    {
        return Err(OpenPathError::policy_blocked(format!(
            "Path {} resolves to {} which overlaps protected nono state root '{}'",
            path.display(),
            canonical.display(),
            protected_root.display(),
        )));
    }

    validate_procfs_access(&canonical, procfs_context)?;

    let file = open_canonical_path_no_symlinks(&canonical, access).map_err(|e| {
        OpenPathError::io(
            format!(
                "Failed to open {} for {:?} access: {}",
                canonical.display(),
                access,
                e
            ),
            &e,
        )
    })?;

    // TOCTOU re-verification: if this file was trust-verified, re-compute the
    // digest from the opened fd and compare against the verification-time digest.
    // This closes the window between check_path() (which reads the file by path)
    // and open (which opens a potentially different file if an attacker performed
    // an atomic rename between the two operations).
    if let Some(expected_digest) = trust_digest {
        use sha2::Digest as _;
        use std::io::{Read, Seek};
        let mut hasher = sha2::Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = (&file).read(&mut buf).map_err(|e| {
                OpenPathError::io(
                    format!(
                        "Failed to read {} for digest re-check: {}",
                        canonical.display(),
                        e,
                    ),
                    &e,
                )
            })?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let hash = hasher.finalize();
        let actual_digest: String = hash
            .iter()
            .flat_map(|b| {
                [
                    char::from_digit((u32::from(*b) >> 4) & 0xF, 16).unwrap_or('0'),
                    char::from_digit(u32::from(*b) & 0xF, 16).unwrap_or('0'),
                ]
            })
            .collect();
        if actual_digest != expected_digest {
            return Err(OpenPathError::policy_blocked(format!(
                "Instruction file {} was modified between trust verification and open \
                 (expected digest {}, got {}). Possible TOCTOU attack.",
                path.display(),
                expected_digest,
                actual_digest,
            )));
        }
        // Seek back to start so the child reads from the beginning
        (&file).seek(std::io::SeekFrom::Start(0)).map_err(|e| {
            OpenPathError::io(
                format!(
                    "Failed to seek {} after digest re-check: {}",
                    canonical.display(),
                    e,
                ),
                &e,
            )
        })?;
    }

    Ok(file)
}

/// Open a canonical absolute path by traversing path components using `openat`.
///
/// Every component is opened with `O_NOFOLLOW` to prevent symlink substitution
/// between canonicalization and open time (TOCTOU).
fn open_canonical_path_no_symlinks(
    canonical: &std::path::Path,
    access: &nono::AccessMode,
) -> std::io::Result<std::fs::File> {
    use std::os::unix::ffi::OsStrExt;

    if !canonical.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "canonical path must be absolute",
        ));
    }

    let components: Vec<_> = canonical
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(part) => Some(part),
            _ => None,
        })
        .collect();

    if components.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "cannot open root path",
        ));
    }

    // Start resolution from the real root directory.
    let root = CString::new("/")
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid path"))?;
    let root_fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut dir_fd = unsafe { OwnedFd::from_raw_fd(root_fd) };

    for part in &components[..components.len() - 1] {
        let c_part = CString::new(part.as_bytes())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid path"))?;
        let next_fd = unsafe {
            libc::openat(
                dir_fd.as_raw_fd(),
                c_part.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if next_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        dir_fd = unsafe { OwnedFd::from_raw_fd(next_fd) };
    }

    let flags = match access {
        nono::AccessMode::Read => libc::O_RDONLY,
        nono::AccessMode::Write => libc::O_WRONLY,
        nono::AccessMode::ReadWrite => libc::O_RDWR,
    } | libc::O_NOFOLLOW
        | libc::O_CLOEXEC;

    let leaf = CString::new(components[components.len() - 1].as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid path"))?;
    let file_fd = unsafe { libc::openat(dir_fd.as_raw_fd(), leaf.as_ptr(), flags) };
    if file_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let file_fd = unsafe { OwnedFd::from_raw_fd(file_fd) };
    Ok(std::fs::File::from(file_fd))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exec_strategy_default_is_supervised() {
        assert_eq!(ExecStrategy::default(), ExecStrategy::Supervised);
    }

    #[test]
    fn test_exec_strategy_variants() {
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
        let strategy = ExecStrategy::Supervised;
        assert_eq!(strategy, ExecStrategy::Supervised);
        assert_ne!(ExecStrategy::Supervised, ExecStrategy::Direct);
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

    #[test]
    fn test_record_denial_is_capped() {
        let mut denials = Vec::new();
        for _ in 0..(MAX_DENIAL_RECORDS + 10) {
            record_denial(
                &mut denials,
                DenialRecord {
                    path: "/tmp/test".into(),
                    access: nono::AccessMode::Read,
                    reason: DenialReason::PolicyBlocked,
                },
            );
        }
        assert_eq!(denials.len(), MAX_DENIAL_RECORDS);
    }

    #[test]
    fn test_resolve_procfs_self_for_child() {
        let path = resolve_procfs_path_for_child(
            Path::new("/proc/self/maps"),
            Some(ProcfsAccessContext::new(4242, Some(4343))),
        );
        assert_eq!(path.ok(), Some(PathBuf::from("/proc/4242/maps")));
    }

    #[test]
    fn test_resolve_procfs_thread_self_for_child() {
        let path = resolve_procfs_path_for_child(
            Path::new("/proc/thread-self/maps"),
            Some(ProcfsAccessContext::new(4242, Some(4343))),
        );
        assert_eq!(path.ok(), Some(PathBuf::from("/proc/4242/task/4343/maps")));
    }

    #[test]
    fn test_resolve_procfs_thread_self_requires_thread_context() {
        let result = resolve_procfs_path_for_child(
            Path::new("/proc/thread-self/maps"),
            Some(ProcfsAccessContext::new(4242, None)),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_procfs_access_allows_child_sensitive_proc_path() {
        let result = validate_procfs_access(
            Path::new("/proc/4242/maps"),
            Some(ProcfsAccessContext::new(4242, Some(4343))),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_procfs_access_blocks_foreign_sensitive_proc_path() {
        let result = validate_procfs_access(
            Path::new("/proc/1/maps"),
            Some(ProcfsAccessContext::new(4242, Some(4343))),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_procfs_access_allows_child_task_sensitive_proc_path() {
        let result = validate_procfs_access(
            Path::new("/proc/4242/task/9999/maps"),
            Some(ProcfsAccessContext::new(4242, Some(4343))),
        );
        assert!(result.is_ok());
    }

    /// Verify that the supervisor loop runs and exits cleanly without a PTY relay.
    ///
    /// This tests the `capability_elevation = false` code path where no PTY is
    /// allocated but the supervisor loop must still service the IPC socket for
    /// trust interception. The child fork closes its socket end and exits,
    /// causing the loop to see POLLHUP and return.
    #[test]
    fn test_supervisor_loop_runs_without_pty_relay() {
        use std::os::unix::net::UnixStream;

        struct DenyAll;
        impl ApprovalBackend for DenyAll {
            fn request_capability(
                &self,
                _req: &nono::supervisor::CapabilityRequest,
            ) -> nono::Result<ApprovalDecision> {
                Ok(ApprovalDecision::Denied {
                    reason: "test".to_string(),
                })
            }
            fn backend_name(&self) -> &str {
                "deny-all-test"
            }
        }

        let (parent_stream, child_stream) = UnixStream::pair()
            .map_err(|e| format!("socketpair: {e}"))
            .expect("socketpair failed in test");

        let backend = DenyAll;
        let sup_cfg = SupervisorConfig {
            protected_roots: &[],
            deny_paths: &[],
            approval_backend: &backend,
            session_id: "test-session",
            open_url_origins: &[],
            open_url_allow_localhost: false,
            allow_launch_services_active: false,
        };

        // Fork a child that closes its socket end and exits immediately.
        // SAFETY: We are in a test; the child does minimal work and _exit()s.
        match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                drop(child_stream);
                drop(parent_stream);
                unsafe { libc::_exit(42) };
            }
            Ok(ForkResult::Parent { child }) => {
                drop(child_stream);
                let mut sock = SupervisorSocket::from_stream(parent_stream);

                // Run supervisor loop with relay: None (the capability_elevation=false path).
                // It should poll the socket, see POLLHUP when child exits, and return.
                #[cfg(target_os = "linux")]
                let result = run_supervisor_loop(
                    child,
                    &mut sock,
                    &sup_cfg,
                    None, // no seccomp
                    &[],  // no initial caps
                    None, // no trust interceptor
                    None, // no PTY relay — this is what we're testing
                );

                #[cfg(not(target_os = "linux"))]
                let result = run_supervisor_loop(
                    child, &mut sock, &sup_cfg, None, // no trust interceptor
                    None, // no PTY relay
                );

                let (status, denials) = result
                    .map_err(|e| format!("supervisor loop: {e}"))
                    .expect("supervisor loop failed");
                assert!(denials.is_empty(), "no denials expected");

                // Child exited with code 42
                match status {
                    WaitStatus::Exited(_, code) => assert_eq!(code, 42),
                    other => panic!("unexpected wait status: {other:?}"),
                }
            }
            Err(e) => panic!("fork failed: {e}"),
        }
    }

    #[test]
    fn test_handle_supervisor_message_denied_path_skips_prompt() {
        use std::os::unix::net::UnixStream;
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        struct CountingBackend {
            calls: Arc<AtomicUsize>,
        }

        impl ApprovalBackend for CountingBackend {
            fn request_capability(
                &self,
                _req: &nono::supervisor::CapabilityRequest,
            ) -> nono::Result<ApprovalDecision> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(ApprovalDecision::Granted)
            }

            fn backend_name(&self) -> &str {
                "counting-backend"
            }
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let denied = dir.path().join("appsettings.json");
        std::fs::write(&denied, "{}").expect("write denied");
        let denied_canonical = denied.canonicalize().expect("canonicalize denied");
        let deny_paths = if denied_canonical == denied {
            vec![denied.clone()]
        } else {
            vec![denied.clone(), denied_canonical]
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let backend = CountingBackend {
            calls: Arc::clone(&calls),
        };
        let config = SupervisorConfig {
            protected_roots: &[],
            deny_paths: &deny_paths,
            approval_backend: &backend,
            session_id: "test-session",
            open_url_origins: &[],
            open_url_allow_localhost: false,
            allow_launch_services_active: false,
        };
        let (stream_a, _stream_b) = UnixStream::pair().expect("socketpair");
        let mut sock = SupervisorSocket::from_stream(stream_a);
        let mut denials = Vec::new();
        let mut seen = HashSet::new();
        let request = nono::CapabilityRequest {
            request_id: "req-1".to_string(),
            path: denied.clone(),
            access: nono::AccessMode::Read,
            reason: Some("test".to_string()),
            child_pid: std::process::id(),
            session_id: "sess-1".to_string(),
        };

        handle_supervisor_message(
            &mut sock,
            SupervisorMessage::Request(request),
            Pid::from_raw(std::process::id() as i32),
            &config,
            &mut denials,
            &mut seen,
            None,
        )
        .expect("handle request");

        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "deny path should be rejected before approval backend is invoked"
        );
        assert!(denials
            .iter()
            .any(|d| d.reason == DenialReason::PolicyBlocked));
    }

    struct TestDenyBackend;
    impl ApprovalBackend for TestDenyBackend {
        fn request_capability(
            &self,
            _req: &nono::supervisor::CapabilityRequest,
        ) -> nono::Result<ApprovalDecision> {
            Ok(ApprovalDecision::Denied {
                reason: "test".to_string(),
            })
        }
        fn backend_name(&self) -> &str {
            "test-deny"
        }
    }

    #[test]
    fn test_validate_url_allowed_origin() {
        let backend = TestDenyBackend;
        let origins = vec!["https://claude.ai".to_string()];
        let config = SupervisorConfig {
            protected_roots: &[],
            deny_paths: &[],
            approval_backend: &backend,
            session_id: "test",
            open_url_origins: &origins,
            open_url_allow_localhost: false,
            allow_launch_services_active: false,
        };

        // Allowed origin: validation passes
        let result = validate_url("https://claude.ai/oauth/authorize?state=xyz", &config);
        assert!(result.is_ok(), "Expected validation to pass: {result:?}");

        // Disallowed origin: must fail validation
        let result = validate_url("https://evil.example.com/phishing", &config);
        assert!(result.is_err());
        assert!(result
            .as_ref()
            .err()
            .map(|e| e.contains("not in the profile"))
            .unwrap_or(false));
    }

    #[test]
    fn test_validate_url_blocks_non_https() {
        let backend = TestDenyBackend;
        let config = SupervisorConfig {
            protected_roots: &[],
            deny_paths: &[],
            approval_backend: &backend,
            session_id: "test",
            open_url_origins: &[],
            open_url_allow_localhost: false,
            allow_launch_services_active: false,
        };

        let result = validate_url("file:///etc/passwd", &config);
        assert!(result.is_err());
        assert!(result
            .as_ref()
            .err()
            .map(|e| e.contains("Only https://"))
            .unwrap_or(false));

        let result = validate_url("javascript:alert(1)", &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_url_localhost() {
        let backend = TestDenyBackend;
        let config_allow = SupervisorConfig {
            protected_roots: &[],
            deny_paths: &[],
            approval_backend: &backend,
            session_id: "test",
            open_url_origins: &[],
            open_url_allow_localhost: true,
            allow_launch_services_active: false,
        };
        let config_deny = SupervisorConfig {
            protected_roots: &[],
            deny_paths: &[],
            approval_backend: &backend,
            session_id: "test",
            open_url_origins: &[],
            open_url_allow_localhost: false,
            allow_launch_services_active: false,
        };

        // Localhost denied when not allowed
        let result = validate_url("http://localhost:8080/callback", &config_deny);
        assert!(result.is_err());
        assert!(result
            .as_ref()
            .err()
            .map(|e| e.contains("not allowed"))
            .unwrap_or(false));

        // Localhost allowed when configured
        let result = validate_url("http://localhost:8080/callback", &config_allow);
        assert!(
            result.is_ok(),
            "Expected localhost validation to pass: {result:?}"
        );
    }

    #[test]
    fn test_validate_url_max_length() {
        let backend = TestDenyBackend;
        let config = SupervisorConfig {
            protected_roots: &[],
            deny_paths: &[],
            approval_backend: &backend,
            session_id: "test",
            open_url_origins: &[],
            open_url_allow_localhost: false,
            allow_launch_services_active: false,
        };

        let long_url = format!("https://example.com/{}", "a".repeat(MAX_URL_LENGTH));
        let result = validate_url(&long_url, &config);
        assert!(result.is_err());
        assert!(result
            .as_ref()
            .err()
            .map(|e| e.contains("maximum length"))
            .unwrap_or(false));
    }

    #[test]
    fn test_shell_quote_simple_path() {
        assert_eq!(shell_quote("/usr/bin/nono"), "/usr/bin/nono");
    }

    #[test]
    fn test_shell_quote_path_with_spaces() {
        assert_eq!(shell_quote("/opt/my app/nono"), "'/opt/my app/nono'");
    }

    #[test]
    fn test_shell_quote_path_with_single_quote() {
        assert_eq!(shell_quote("/opt/it's/nono"), "'/opt/it'\\''s/nono'");
    }

    #[test]
    fn test_shell_quote_empty_string() {
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn test_clear_close_on_exec_clears_flag() {
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;

        let (a, _b) = UnixStream::pair().expect("socketpair");
        let fd = a.as_raw_fd();

        let before = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(before >= 0, "F_GETFD before failed");
        assert_ne!(before & libc::FD_CLOEXEC, 0, "fd should start CLOEXEC");

        clear_close_on_exec(fd).expect("clear cloexec");

        let after = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(after >= 0, "F_GETFD after failed");
        assert_eq!(after & libc::FD_CLOEXEC, 0, "fd should not be CLOEXEC");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_create_open_shim_installs_helper_in_shim_dir() {
        let exe = std::env::current_exe().expect("current_exe");
        let shim = create_open_shim(&exe).expect("create shim");

        assert!(
            shim.dir.path().join("open").exists(),
            "open shim should exist"
        );
        assert!(shim.helper_exe.exists(), "helper copy should exist");
        assert_eq!(
            shim.helper_exe.parent(),
            Some(shim.dir.path()),
            "helper should live inside shim dir"
        );

        let script = std::fs::read_to_string(shim.dir.path().join("open")).expect("read shim");
        let helper = shell_quote(&shim.helper_exe.display().to_string());
        assert!(
            script.contains("for arg in \"$@\"; do"),
            "shim should scan all arguments for a URL"
        );
        assert!(
            script.contains(&format!("exec {helper} open-url-helper \"$url_arg\"")),
            "shim should exec the copied helper"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_should_install_macos_open_shim_respects_launch_services_flag() {
        struct TestBackend;
        impl ApprovalBackend for TestBackend {
            fn request_capability(
                &self,
                _req: &nono::supervisor::CapabilityRequest,
            ) -> nono::Result<ApprovalDecision> {
                Ok(ApprovalDecision::Denied {
                    reason: "test".to_string(),
                })
            }
            fn backend_name(&self) -> &str {
                "test"
            }
        }

        let backend = TestBackend;
        let config = SupervisorConfig {
            protected_roots: &[],
            deny_paths: &[],
            approval_backend: &backend,
            session_id: "test",
            open_url_origins: &[],
            open_url_allow_localhost: false,
            allow_launch_services_active: true,
        };

        assert!(
            !should_install_macos_open_shim(Some(&config)),
            "launch services sessions should skip the macOS open shim"
        );
        assert!(
            !should_install_macos_open_shim(None),
            "without supervisor config, the helper should not install the macOS open shim"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_open_shim_drop_cleans_up_directory() {
        let exe = std::env::current_exe().expect("current_exe");
        let shim = create_open_shim(&exe).expect("create shim");
        let dir = shim.dir.path().to_path_buf();

        assert!(dir.exists(), "shim dir should exist before drop");
        drop(shim);
        assert!(!dir.exists(), "shim dir should be removed on drop");
    }
}
