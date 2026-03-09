//! PTY multiplexer for supervised mode.
//!
//! Gives the sandboxed child its own PTY so that TUI programs (Claude Code, vim, etc.)
//! can set raw mode without interfering with the supervisor's terminal prompts.
//!
//! Layout:
//! ```text
//! ┌─────────────┐         ┌──────────────┐         ┌──────────────┐
//! │ Real TTY    │ <-----> │  Supervisor   │ <-----> │ PTY master   │
//! │ (user sees) │         │  (relay loop) │         │              │
//! └─────────────┘         └──────────────┘         └──────┬───────┘
//!                                                         │ kernel
//!                                                  ┌──────┴───────┐
//!                                                  │ PTY slave    │
//!                                                  │ (child's     │
//!                                                  │  stdin/out/  │
//!                                                  │  err)        │
//!                                                  └──────────────┘
//! ```
//!
//! The relay loop copies bytes between the real terminal and the PTY master.
//! When the supervisor needs to display a prompt (seccomp approval, IPC message),
//! it pauses the relay, interacts directly with the real terminal, then resumes.

use nix::libc;
use nix::pty::openpty;
use nix::sys::termios;
use nono::{NonoError, Result};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use tracing::debug;

/// PTY pair for supervised mode.
///
/// `master` stays with the supervisor (parent).
/// `slave` is dup2'd onto the child's stdin/stdout/stderr after fork.
pub(crate) struct PtyPair {
    pub master: OwnedFd,
    pub slave: OwnedFd,
}

/// State for the real terminal, saved before entering relay mode.
pub(crate) struct RealTerminal {
    /// File descriptor for /dev/tty (the real controlling terminal)
    tty_fd: OwnedFd,
    /// Original termios settings, restored on drop
    original_termios: termios::Termios,
}

impl RealTerminal {
    /// Open the real terminal and save its settings.
    pub fn open() -> Result<Self> {
        let tty = std::fs::File::open("/dev/tty").map_err(|e| {
            NonoError::SandboxInit(format!("Failed to open /dev/tty for PTY relay: {e}"))
        })?;
        let tty_fd: OwnedFd = tty.into();
        let original_termios = termios::tcgetattr(&tty_fd).map_err(|e| {
            NonoError::SandboxInit(format!("Failed to get terminal attributes: {e}"))
        })?;
        Ok(Self {
            tty_fd,
            original_termios,
        })
    }

    /// Put the real terminal into raw mode for transparent relay.
    ///
    /// Raw mode disables line buffering and echo so that every keystroke
    /// is forwarded immediately to the PTY master (and thus to the child).
    pub fn enter_raw_mode(&self) -> Result<()> {
        let mut raw = self.original_termios.clone();
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(&self.tty_fd, termios::SetArg::TCSADRAIN, &raw).map_err(|e| {
            NonoError::SandboxInit(format!("Failed to set raw mode on real terminal: {e}"))
        })?;
        Ok(())
    }

    /// Restore the real terminal to its original (canonical) mode.
    ///
    /// Called when the supervisor needs to display a prompt, and on exit.
    /// Explicitly ensures ICANON, ECHO, ISIG, and ICRNL are set so that
    /// line-buffered input works correctly for the approval prompt.
    pub fn restore(&self) -> Result<()> {
        let mut restored = self.original_termios.clone();
        // Ensure canonical mode flags are set even if the original termios
        // was somehow missing them (defensive)
        restored.local_flags |=
            termios::LocalFlags::ICANON | termios::LocalFlags::ECHO | termios::LocalFlags::ISIG;
        restored.input_flags |= termios::InputFlags::ICRNL;
        termios::tcsetattr(&self.tty_fd, termios::SetArg::TCSADRAIN, &restored).map_err(|e| {
            NonoError::SandboxInit(format!("Failed to restore terminal attributes: {e}"))
        })?;
        Ok(())
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.tty_fd.as_raw_fd()
    }
}

impl Drop for RealTerminal {
    fn drop(&mut self) {
        // Best-effort restore on drop
        let _ = termios::tcsetattr(
            &self.tty_fd,
            termios::SetArg::TCSADRAIN,
            &self.original_termios,
        );
    }
}

/// Create a PTY pair, copying the real terminal's size to the slave.
pub(crate) fn create_pty_pair() -> Result<PtyPair> {
    let result = openpty(None, None)
        .map_err(|e| NonoError::SandboxInit(format!("openpty() failed: {e}")))?;

    let master = result.master;
    let slave = result.slave;

    // Copy terminal size from real terminal to PTY slave
    if let Ok(tty) = std::fs::File::open("/dev/tty") {
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        // SAFETY: ioctl TIOCGWINSZ reads terminal size into ws, valid pointer
        let ret = unsafe { libc::ioctl(tty.as_raw_fd(), libc::TIOCGWINSZ, &mut ws) };
        if ret == 0 {
            // SAFETY: ioctl TIOCSWINSZ sets terminal size from ws, valid pointer
            unsafe { libc::ioctl(slave.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
        }
    }

    debug!(
        "Created PTY pair: master={}, slave={}",
        master.as_raw_fd(),
        slave.as_raw_fd()
    );

    Ok(PtyPair { master, slave })
}

/// Set up the PTY slave as the child's controlling terminal.
///
/// Must be called in the child process after fork, before exec.
/// This is async-signal-safe (only raw libc calls).
///
/// # Safety
/// Must be called after fork() in the child process only.
/// `slave_fd` must be a valid open file descriptor for the PTY slave.
pub(crate) unsafe fn setup_child_pty(slave_fd: RawFd) {
    // Create a new session so the child gets its own controlling terminal.
    // setsid() detaches from the parent's controlling terminal.
    libc::setsid();

    // Make the PTY slave the controlling terminal for this session.
    // TIOCSCTTY with arg 0 means "make this my controlling terminal".
    libc::ioctl(slave_fd, libc::TIOCSCTTY as libc::c_ulong, 0i32);

    // Redirect stdin/stdout/stderr to the PTY slave
    libc::dup2(slave_fd, libc::STDIN_FILENO);
    libc::dup2(slave_fd, libc::STDOUT_FILENO);
    libc::dup2(slave_fd, libc::STDERR_FILENO);

    // Close the original slave fd if it's not one of 0/1/2
    if slave_fd > 2 {
        libc::close(slave_fd);
    }
}

/// Forward the current terminal window size to the PTY master.
///
/// Called from the SIGWINCH handler to keep the child's terminal size in sync.
pub(crate) fn forward_winsize(real_tty_fd: RawFd, master_fd: RawFd) {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: ioctl reads/writes winsize struct, both fds are valid
    unsafe {
        if libc::ioctl(real_tty_fd, libc::TIOCGWINSZ, &mut ws) == 0 {
            libc::ioctl(master_fd, libc::TIOCSWINSZ, &ws);
        }
    }
}

/// Relay bytes between the real terminal and the PTY master.
///
/// Reads from `src_fd` and writes to `dst_fd`. Returns the number of bytes
/// relayed, or 0 on EOF/EAGAIN.
///
/// This is a non-blocking single-pass relay (call within a poll loop).
pub(crate) fn relay_bytes(src_fd: RawFd, dst_fd: RawFd) -> usize {
    let mut buf = [0u8; 4096];
    // SAFETY: read on valid fd with valid buffer
    let n = loop {
        let res = unsafe { libc::read(src_fd, buf.as_mut_ptr().cast(), buf.len()) };
        if res < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return 0;
        }
        break res as usize;
    };

    if n == 0 {
        return 0;
    }

    let mut written = 0;
    while written < n {
        // SAFETY: write on valid fd with valid buffer slice
        let w = unsafe { libc::write(dst_fd, buf[written..n].as_ptr().cast(), n - written) };
        if w < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            // EAGAIN/EWOULDBLOCK or fatal write error — return what we wrote.
            // The caller's poll loop will retry when the fd is writable.
            break;
        }
        if w == 0 {
            break;
        }
        written += w as usize;
    }
    written
}

/// Set a file descriptor to non-blocking mode.
pub(crate) fn set_nonblocking(fd: RawFd) -> Result<()> {
    // SAFETY: fcntl on valid fd
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(NonoError::SandboxInit(format!(
            "fcntl(F_GETFL) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if ret < 0 {
        return Err(NonoError::SandboxInit(format!(
            "fcntl(F_SETFL, O_NONBLOCK) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

// Global storage for SIGWINCH forwarding (same pattern as CHILD_PID)
static REAL_TTY_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
static PTY_MASTER_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

/// Install SIGWINCH handler that forwards window size changes to the PTY.
pub(crate) fn setup_sigwinch_forwarding(real_tty_fd: RawFd, master_fd: RawFd) {
    REAL_TTY_FD.store(real_tty_fd, std::sync::atomic::Ordering::SeqCst);
    PTY_MASTER_FD.store(master_fd, std::sync::atomic::Ordering::SeqCst);

    // SAFETY: signal handler only calls async-signal-safe ioctl()
    unsafe {
        let _ = nix::sys::signal::signal(
            nix::sys::signal::Signal::SIGWINCH,
            nix::sys::signal::SigHandler::Handler(handle_sigwinch),
        );
    }
}

extern "C" fn handle_sigwinch(_sig: libc::c_int) {
    let tty = REAL_TTY_FD.load(std::sync::atomic::Ordering::SeqCst);
    let master = PTY_MASTER_FD.load(std::sync::atomic::Ordering::SeqCst);
    if tty >= 0 && master >= 0 {
        forward_winsize(tty, master);
    }
}

/// Clear SIGWINCH forwarding state.
pub(crate) fn clear_sigwinch_forwarding() {
    REAL_TTY_FD.store(-1, std::sync::atomic::Ordering::SeqCst);
    PTY_MASTER_FD.store(-1, std::sync::atomic::Ordering::SeqCst);
}
