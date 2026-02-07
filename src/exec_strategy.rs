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

use crate::capability::CapabilitySet;
use crate::diagnostic::DiagnosticFormatter;
use crate::error::{NonoError, Result};
use nix::libc;
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};
use std::ffi::CString;
use std::io::{BufRead, BufReader, Write};
use std::mem::ManuallyDrop;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{debug, info, warn};

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
    /// - No undo support
    /// - For backward compatibility and scripts
    Direct,

    /// Monitor mode: apply sandbox, fork, wait, diagnose on error.
    /// Both parent and child are sandboxed.
    ///
    /// - Small attack surface (parent sandboxed too)
    /// - Diagnostic footer on non-zero exit
    /// - No undo support (parent can't write to ~/.nono/undo)
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
    #[allow(dead_code)]
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

    // Copy current environment, skipping vars we'll override
    for (key, value) in std::env::vars_os() {
        if let (Some(k), Some(v)) = (key.to_str(), value.to_str()) {
            let should_skip =
                config.env_vars.iter().any(|(ek, _)| *ek == k) || k == "NONO_CAP_FILE";
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
        if let Ok(cstr) = CString::new(format!("{}={}", key, value)) {
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
/// 1. `execute_monitor` is CLI code, not library code (per DESIGN-diagnostic-and-supervisor.md)
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
}
