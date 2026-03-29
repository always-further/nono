//! PTY proxy for detachable sandboxed sessions.
//!
//! The supervisor interposes a PTY between the real terminal and the sandboxed
//! child process. This enables:
//! - `nono detach`: detach from the terminal while the child keeps running
//! - `nono attach`: reattach from any terminal
//!
//! Architecture:
//! ```text
//!   real terminal <---> supervisor (PTY proxy) <---> PTY master/slave <---> child
//!                       |
//!                       +--- attach socket (~/.nono/sessions/{id}.sock)
//! ```
//!
//! The attach socket allows `nono attach` to connect from a different terminal.
//! The supervisor proxies I/O between whoever is connected and the PTY master.

use nix::libc;
use nix::pty::{openpty, OpenptyResult, Winsize};
use nono::{NonoError, Result};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{debug, warn};

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, PermissionsExt};

const ATTACH_HANDSHAKE_MAGIC: [u8; 4] = *b"NNOA";
const ATTACH_HANDSHAKE_LEN: usize = 8;
const RESIZE_MESSAGE_LEN: usize = 4;
const SCROLLBACK_LIMIT_BYTES: usize = 8 * 1024 * 1024;
const VT_SCROLLBACK_ROWS: usize = 10_000;
const DEFAULT_DETACH_SEQUENCE: [u8; 2] = [0x1d, b'd'];
const ATTACH_ACK_OK: u8 = 0;
const ATTACH_ACK_BUSY: u8 = 1;
const ATTACH_ACK_DENIED: u8 = 2;
const ATTACH_SCREEN_ENTER_ESCAPE: &[u8] =
    b"\x1b[0m\x1b(B\x1b)B\x0f\x1b[r\x1b[?6l\x1b[?1049h\x1b[?25h\x1b[2J\x1b[H";
const TERMINAL_RESTORE_ESCAPE: &[u8] = b"\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?1015l\x1b[?1004l\x1b[?2004l\x1b[?1049l\x1b[?25h";
const TERMINAL_RESTORE_AND_CLEAR_ESCAPE: &[u8] =
    b"\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?1015l\x1b[?1004l\x1b[?2004l\x1b[?1l\x1b>\x1b[?1049l\x1b[?25h\x1b[2J\x1b[H";

/// PTY pair with the attach socket path.
pub struct PtyPair {
    /// Master side — held by the supervisor for I/O proxying.
    pub master: OwnedFd,
    /// Slave side — becomes the child's stdin/stdout/stderr.
    pub slave: OwnedFd,
}

/// State for a connected terminal client (the real terminal or an attach connection).
enum AttachedClient {
    /// Initial terminal attached to the current process.
    Terminal { read_fd: RawFd, write_fd: RawFd },
    /// Reattached client over the session Unix socket.
    Socket(OwnedFd),
}

impl AttachedClient {
    fn terminal(read_fd: RawFd, write_fd: RawFd) -> Self {
        Self::Terminal { read_fd, write_fd }
    }

    fn socket(socket: OwnedFd) -> Self {
        Self::Socket(socket)
    }

    fn read_fd(&self) -> RawFd {
        match self {
            Self::Terminal { read_fd, .. } => *read_fd,
            Self::Socket(socket) => socket.as_raw_fd(),
        }
    }

    fn write_fd(&self) -> RawFd {
        match self {
            Self::Terminal { write_fd, .. } => *write_fd,
            Self::Socket(socket) => socket.as_raw_fd(),
        }
    }

    fn is_terminal(&self) -> bool {
        matches!(self, Self::Terminal { .. })
    }
}

struct ScreenState {
    parser: vt100::Parser,
}

impl ScreenState {
    fn new(rows: usize, cols: usize) -> Self {
        let rows = rows.max(1).min(u16::MAX as usize) as u16;
        let cols = cols.max(1).min(u16::MAX as usize) as u16;
        Self {
            parser: vt100::Parser::new(rows, cols, VT_SCROLLBACK_ROWS),
        }
    }

    fn resize(&mut self, rows: usize, cols: usize) {
        let rows = rows.max(1).min(u16::MAX as usize) as u16;
        let cols = cols.max(1).min(u16::MAX as usize) as u16;
        self.parser.screen_mut().set_size(rows, cols);
    }

    fn apply_bytes(&mut self, bytes: &[u8]) {
        self.parser.process(bytes);
    }

    fn render(&self) -> Vec<u8> {
        self.parser.screen().state_formatted()
    }

    fn render_plaintext(&self) -> String {
        self.parser.screen().contents()
    }

    fn size(&self) -> (u16, u16) {
        self.parser.screen().size()
    }

    fn cursor_position(&self) -> (u16, u16) {
        self.parser.screen().cursor_position()
    }

    fn alternate_screen_active(&self) -> bool {
        self.parser.screen().alternate_screen()
    }
}

/// The running PTY proxy state managed by the supervisor.
pub struct PtyProxy {
    /// PTY master fd
    master: OwnedFd,
    /// Session identifier for updating registry state on detach.
    session_id: String,
    /// Attach socket for `nono attach`
    attach_listener: UnixListener,
    /// Path to the attach socket (for cleanup)
    attach_path: PathBuf,
    /// Currently attached client (None when detached)
    client: Option<AttachedClient>,
    /// Resize updates from a reattached terminal client.
    resize_notifier: Option<UnixDatagram>,
    /// Saved terminal settings (restored on detach)
    saved_termios: Option<nix::sys::termios::Termios>,
    /// Recent PTY output replayed to newly attached clients.
    scrollback: VecDeque<u8>,
    /// Last visible screen state for attach restoration.
    screen: ScreenState,
    /// Configured in-band detach byte sequence.
    detach_sequence: Vec<u8>,
    /// Number of bytes currently matched against `detach_sequence`.
    pending_detach_match_len: usize,
    /// In-band detach requested from the attached client.
    detach_requested: bool,
}

/// Open a PTY pair, inheriting the current terminal's window size.
pub fn open_pty() -> Result<PtyPair> {
    // Get current terminal window size if available
    let winsize = get_terminal_winsize();

    let OpenptyResult { master, slave } = openpty(winsize.as_ref(), None)
        .map_err(|e| NonoError::SandboxInit(format!("openpty() failed: {}", e)))?;

    Ok(PtyPair { master, slave })
}

/// Set up the slave PTY as the child's controlling terminal.
///
/// Must be called in the child after fork, before exec.
/// This is async-signal-safe (only uses raw libc calls).
///
/// # Safety
/// Must be called in the child process after fork. The slave_fd must be valid.
pub unsafe fn setup_child_pty(slave_fd: RawFd) {
    // Create a new session so the child can acquire a controlling terminal.
    libc::setsid();

    // Set the slave as the controlling terminal (TIOCSCTTY).
    // The arg 0 means "don't steal if another process has it".
    libc::ioctl(slave_fd, libc::TIOCSCTTY as libc::c_ulong, 0);

    // Redirect stdin/stdout/stderr to the slave PTY
    libc::dup2(slave_fd, libc::STDIN_FILENO);
    libc::dup2(slave_fd, libc::STDOUT_FILENO);
    libc::dup2(slave_fd, libc::STDERR_FILENO);

    // Close the original slave fd if it's not one of 0/1/2
    if slave_fd > 2 {
        libc::close(slave_fd);
    }
}

/// Get the current terminal window size, if available.
fn get_terminal_winsize() -> Option<Winsize> {
    let mut ws: Winsize = unsafe { std::mem::zeroed() };
    // SAFETY: ioctl with TIOCGWINSZ reads window size into ws
    let ret = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
    if ret == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
        Some(ws)
    } else {
        None
    }
}

impl PtyProxy {
    /// Create a new PTY proxy with an attach socket.
    pub fn new(
        master: OwnedFd,
        session_id: &str,
        attach_initial_client: bool,
        detach_sequence: Option<&[u8]>,
    ) -> Result<Self> {
        let attach_path = crate::session::session_socket_path(session_id)?;
        remove_stale_attach_socket(&attach_path)?;
        let attach_listener = bind_attach_listener(&attach_path)?;
        attach_listener.set_nonblocking(true).map_err(|e| {
            NonoError::SandboxInit(format!("Failed to set attach socket nonblocking: {}", e))
        })?;

        let winsize = current_winsize(master.as_raw_fd()).unwrap_or(Winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        });

        let (saved_termios, client) = if attach_initial_client {
            (
                set_terminal_raw(),
                Some(AttachedClient::terminal(
                    libc::STDIN_FILENO,
                    libc::STDOUT_FILENO,
                )),
            )
        } else {
            (None, None)
        };

        Ok(Self {
            master,
            session_id: session_id.to_string(),
            attach_listener,
            attach_path,
            client,
            resize_notifier: None,
            saved_termios,
            scrollback: VecDeque::with_capacity(SCROLLBACK_LIMIT_BYTES.min(64 * 1024)),
            screen: ScreenState::new(winsize.ws_row as usize, winsize.ws_col as usize),
            detach_sequence: detach_sequence
                .filter(|sequence| !sequence.is_empty())
                .map_or_else(|| DEFAULT_DETACH_SEQUENCE.to_vec(), ToOwned::to_owned),
            pending_detach_match_len: 0,
            detach_requested: false,
        })
    }

    /// Detach the current client.
    ///
    /// Restores terminal settings and drops the client connection.
    pub fn detach(&mut self) -> bool {
        let mut detached_terminal = false;
        if let Some(client) = self.client.take() {
            if client.is_terminal() {
                detached_terminal = true;
                self.restore_terminal();
            }
        }
        self.resize_notifier = None;
        self.pending_detach_match_len = 0;
        self.persist_attachment_state(crate::session::SessionAttachment::Detached);
        debug!("PTY proxy detached");
        detached_terminal
    }

    /// Accept an attach connection.
    ///
    /// Returns true if a client was attached.
    pub fn try_accept(&mut self) -> bool {
        match self.attach_listener.accept() {
            Ok((mut stream, _addr)) => {
                if self.client.is_some() {
                    let _ = stream.write_all(&[ATTACH_ACK_BUSY]);
                    debug!("PTY proxy: rejected attach while another client is active");
                    return false;
                }

                if let Err(e) = authenticate_attach_peer(stream.as_raw_fd()) {
                    warn!(
                        "PTY proxy: rejected unauthorized attach for {}: {}",
                        self.session_id, e
                    );
                    let _ = stream.write_all(&[ATTACH_ACK_DENIED]);
                    return false;
                }

                let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                let mut handshake = [0u8; ATTACH_HANDSHAKE_LEN];
                match stream.read_exact(&mut handshake) {
                    Ok(()) => {
                        if let Some(winsize) = decode_attach_handshake(&handshake) {
                            let _ = self.apply_winsize(&winsize);
                        } else {
                            debug!("PTY proxy: invalid attach handshake");
                            let _ = stream.write_all(&[ATTACH_ACK_DENIED]);
                            return false;
                        }
                    }
                    Err(e) => {
                        debug!("PTY proxy: failed to read attach handshake: {}", e);
                        let _ = stream.write_all(&[ATTACH_ACK_DENIED]);
                        return false;
                    }
                }
                let _ = stream.set_read_timeout(None);

                let (supervisor_resize, client_resize) = match UnixDatagram::pair() {
                    Ok(pair) => pair,
                    Err(e) => {
                        debug!("PTY proxy: failed to create resize channel: {}", e);
                        let _ = stream.write_all(&[ATTACH_ACK_DENIED]);
                        return false;
                    }
                };
                if !set_nonblocking(supervisor_resize.as_raw_fd()) {
                    debug!("PTY proxy: failed to set resize channel nonblocking");
                    let _ = stream.write_all(&[ATTACH_ACK_DENIED]);
                    return false;
                }

                // Acknowledge the attach first so the client can proceed into
                // its proxy loop, then pass the resize channel fd, then replay
                // buffered PTY output to rebuild the terminal view before live
                // traffic resumes.
                let _ = stream.write_all(&[ATTACH_ACK_OK]);
                if send_fd_over_stream(&stream, client_resize.as_raw_fd()).is_err() {
                    debug!("PTY proxy: failed to send resize fd to attached client");
                    let _ = stream.write_all(&[ATTACH_ACK_DENIED]);
                    return false;
                }
                self.write_debug_capture();
                let replay = self.attach_replay_bytes();
                if !replay.is_empty() && stream.write_all(&replay).is_err() {
                    debug!("PTY proxy: failed to replay scrollback to attached client");
                }

                let socket_fd = stream.into_raw_fd();
                // SAFETY: `socket_fd` came from `UnixStream::into_raw_fd`, so
                // ownership is transferred exactly once into `OwnedFd`.
                let socket = unsafe { OwnedFd::from_raw_fd(socket_fd) };
                self.client = Some(AttachedClient::socket(socket));
                self.resize_notifier = Some(supervisor_resize);
                self.persist_attachment_state(crate::session::SessionAttachment::Attached);
                debug!("PTY proxy: client attached via socket");
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => false,
            Err(e) => {
                debug!("PTY proxy: accept error: {}", e);
                false
            }
        }
    }

    /// Get poll fds for the supervisor loop.
    ///
    /// Returns (master_fd, client_read_fd, attach_listener_fd, resize_fd).
    /// client_read_fd is -1 if no client is attached.
    pub fn poll_fds(&self) -> (RawFd, RawFd, RawFd, RawFd) {
        let client_fd = self.client.as_ref().map_or(-1, AttachedClient::read_fd);
        let resize_fd = self.resize_notifier.as_ref().map_or(-1, AsRawFd::as_raw_fd);
        (
            self.master.as_raw_fd(),
            client_fd,
            self.attach_listener.as_raw_fd(),
            resize_fd,
        )
    }

    /// Proxy data from the PTY master to the attached client (child → user).
    ///
    /// Returns false if the client disconnected.
    pub fn proxy_master_to_client(&mut self) -> bool {
        let client = self
            .client
            .as_ref()
            .map(|c| (c.write_fd(), c.is_terminal()));

        let mut buf = [0u8; 4096];
        let n = unsafe {
            libc::read(
                self.master.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };

        if n <= 0 {
            return n == -1
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted;
        }

        self.record_output(&buf[..n as usize]);

        if let Some((write_fd, is_terminal)) = client {
            if write_all_fd(write_fd, &buf[..n as usize]).is_err() && !is_terminal {
                // Socket client disconnected
                self.detach();
                return true;
            }
        }

        true
    }

    /// Proxy data from the attached client to the PTY master (user → child).
    ///
    /// Returns false if the client disconnected.
    pub fn proxy_client_to_master(&mut self) -> bool {
        let client = match self.client.as_ref() {
            Some(c) => (c.read_fd(), c.is_terminal()),
            None => return true,
        };

        let mut buf = [0u8; 4096];
        let n = unsafe { libc::read(client.0, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };

        if n <= 0 {
            if n == 0 && !client.1 {
                // Socket client disconnected
                self.detach();
                return true;
            }
            return n == -1
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted;
        }

        let forwarded = self.filter_client_input(&buf[..n as usize]);
        if !forwarded.is_empty() && write_all_fd(self.master.as_raw_fd(), &forwarded).is_err() {
            return false;
        }

        true
    }

    /// Returns true once for each in-band detach request.
    pub fn take_detach_request(&mut self) -> bool {
        std::mem::take(&mut self.detach_requested)
    }

    /// Restore terminal settings.
    fn restore_terminal(&mut self) {
        if let Some(ref termios) = self.saved_termios {
            let _ = nix::sys::termios::tcsetattr(
                std::io::stdin(),
                nix::sys::termios::SetArg::TCSANOW,
                termios,
            );
            self.saved_termios = None;
        }
    }

    pub fn sync_current_terminal_winsize(&mut self) {
        if self
            .client
            .as_ref()
            .is_some_and(AttachedClient::is_terminal)
        {
            if let Some(winsize) = get_terminal_winsize() {
                let _ = self.apply_winsize(&winsize);
            }
        }
    }

    pub fn apply_resize_update(&mut self) {
        if self.resize_notifier.is_none() {
            return;
        }

        let mut buf = [0u8; RESIZE_MESSAGE_LEN];
        loop {
            let recv_result = match self.resize_notifier.as_ref() {
                Some(notifier) => notifier.recv(&mut buf),
                None => return,
            };
            match recv_result {
                Ok(RESIZE_MESSAGE_LEN) => {
                    if let Some(winsize) = decode_resize_message(&buf) {
                        let _ = self.apply_winsize(&winsize);
                    }
                }
                Ok(_) => continue,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.resize_notifier = None;
                    break;
                }
            }
        }
    }

    fn apply_winsize(&mut self, winsize: &Winsize) -> bool {
        if winsize.ws_row == 0 || winsize.ws_col == 0 {
            return false;
        }

        let target_rows = winsize.ws_row.max(1);
        let target_cols = winsize.ws_col.max(1);
        let (current_rows, current_cols) = self.screen.size();
        if current_rows == target_rows && current_cols == target_cols {
            return false;
        }

        unsafe {
            let _ = libc::ioctl(
                self.master.as_raw_fd(),
                libc::TIOCSWINSZ as libc::c_ulong,
                winsize as *const Winsize,
            );
        }
        self.screen
            .resize(target_rows as usize, target_cols as usize);
        true
    }

    fn persist_attachment_state(&self, attachment: crate::session::SessionAttachment) {
        if let Err(e) = crate::session::update_session_attachment(&self.session_id, attachment) {
            warn!(
                "Failed to update session {} attachment state: {}",
                self.session_id, e
            );
        }
    }

    fn record_output(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }

        self.screen.apply_bytes(bytes);

        if bytes.len() >= SCROLLBACK_LIMIT_BYTES {
            self.scrollback.clear();
            self.scrollback.extend(
                bytes[bytes.len() - SCROLLBACK_LIMIT_BYTES..]
                    .iter()
                    .copied(),
            );
            return;
        }

        let overflow = self
            .scrollback
            .len()
            .saturating_add(bytes.len())
            .saturating_sub(SCROLLBACK_LIMIT_BYTES);
        for _ in 0..overflow {
            let _ = self.scrollback.pop_front();
        }
        self.scrollback.extend(bytes.iter().copied());
    }

    fn scrollback_snapshot(&self) -> Vec<u8> {
        self.screen.render()
    }

    /// Return the current screen content as plain text for diagnostic analysis.
    ///
    /// Called after the child exits so the supervisor can search for
    /// sandbox-related error messages in the terminal output.
    pub fn screen_plaintext(&self) -> String {
        self.screen.render_plaintext()
    }

    fn attach_replay_bytes(&self) -> Vec<u8> {
        select_attach_replay_bytes(
            self.screen.alternate_screen_active(),
            self.scrollback.iter().copied().collect(),
            self.scrollback_snapshot(),
        )
    }

    fn write_debug_capture(&self) {
        let Some(dir) = std::env::var_os("NONO_PTY_DEBUG_DIR").map(PathBuf::from) else {
            return;
        };

        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }

        let prefix = format!(
            "{}-{}",
            self.session_id,
            chrono::Utc::now().timestamp_millis()
        );
        let scrollback_path = dir.join(format!("{prefix}-scrollback.bin"));
        let snapshot_path = dir.join(format!("{prefix}-snapshot.bin"));
        let plaintext_path = dir.join(format!("{prefix}-screen.txt"));
        let metadata_path = dir.join(format!("{prefix}-meta.txt"));

        let scrollback: Vec<u8> = self.scrollback.iter().copied().collect();
        let snapshot = self.scrollback_snapshot();
        let plaintext = self.screen.render_plaintext();
        let (rows, cols) = self.screen.size();
        let (cursor_row, cursor_col) = self.screen.cursor_position();
        let metadata = format!(
            "session_id={}\nrows={}\ncols={}\ncursor_row={}\ncursor_col={}\nalternate_screen_active={}\nscrollback_len={}\n",
            self.session_id,
            rows,
            cols,
            cursor_row,
            cursor_col,
            self.screen.alternate_screen_active(),
            self.scrollback.len()
        );

        let _ = std::fs::write(scrollback_path, scrollback);
        let _ = std::fs::write(snapshot_path, snapshot);
        let _ = std::fs::write(plaintext_path, plaintext);
        let _ = std::fs::write(metadata_path, metadata);
    }
    fn filter_client_input(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut forwarded = Vec::with_capacity(bytes.len());
        let sequence = self.detach_sequence.as_slice();
        for &byte in bytes {
            if sequence.is_empty() {
                forwarded.push(byte);
                continue;
            }

            if byte == sequence[self.pending_detach_match_len] {
                self.pending_detach_match_len += 1;
                if self.pending_detach_match_len == sequence.len() {
                    self.detach_requested = true;
                    self.pending_detach_match_len = 0;
                }
                continue;
            }

            if self.pending_detach_match_len > 0 {
                forwarded.extend_from_slice(&sequence[..self.pending_detach_match_len]);
                self.pending_detach_match_len = 0;
                if byte == sequence[0] {
                    self.pending_detach_match_len = 1;
                    continue;
                }
            }

            forwarded.push(byte);
        }
        forwarded
    }
}

fn select_attach_replay_bytes(
    alternate_screen_active: bool,
    raw_scrollback: Vec<u8>,
    rendered_snapshot: Vec<u8>,
) -> Vec<u8> {
    if alternate_screen_active {
        if rendered_snapshot.is_empty() {
            raw_scrollback
        } else {
            rendered_snapshot
        }
    } else {
        rendered_snapshot
    }
}

fn current_winsize(fd: RawFd) -> Option<Winsize> {
    let mut ws: Winsize = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) };
    if ret == 0 && ws.ws_row > 0 && ws.ws_col > 0 {
        Some(ws)
    } else {
        None
    }
}

fn remove_stale_attach_socket(attach_path: &Path) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(attach_path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(NonoError::ConfigWrite {
                path: attach_path.to_path_buf(),
                source: e,
            });
        }
    };

    if !metadata.file_type().is_socket() {
        return Err(NonoError::ConfigParse(format!(
            "Refusing to replace non-socket attach path {}",
            attach_path.display()
        )));
    }

    std::fs::remove_file(attach_path).map_err(|e| NonoError::ConfigWrite {
        path: attach_path.to_path_buf(),
        source: e,
    })
}

fn bind_attach_listener(attach_path: &Path) -> Result<UnixListener> {
    struct UmaskGuard(libc::mode_t);

    impl Drop for UmaskGuard {
        fn drop(&mut self) {
            unsafe {
                libc::umask(self.0);
            }
        }
    }

    let _umask_guard = UmaskGuard(unsafe { libc::umask(0o177) });
    let listener = UnixListener::bind(attach_path).map_err(|e| NonoError::ConfigWrite {
        path: attach_path.to_path_buf(),
        source: e,
    })?;

    #[cfg(unix)]
    {
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(attach_path, perms).map_err(|e| NonoError::ConfigWrite {
            path: attach_path.to_path_buf(),
            source: e,
        })?;
    }

    Ok(listener)
}

fn authenticate_attach_peer(sock_fd: RawFd) -> Result<()> {
    let current_uid = unsafe { libc::geteuid() };
    let peer_uid = peer_uid(sock_fd)?;
    if peer_uid == current_uid {
        Ok(())
    } else {
        Err(NonoError::ConfigParse(format!(
            "attach peer uid {} does not match current uid {}",
            peer_uid, current_uid
        )))
    }
}

#[cfg(target_os = "linux")]
fn peer_uid(sock_fd: RawFd) -> Result<libc::uid_t> {
    let mut peer_cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            sock_fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut peer_cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if ret != 0 {
        return Err(NonoError::SandboxInit(format!(
            "Failed to read attach peer credentials: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(peer_cred.uid)
}

#[cfg(target_os = "macos")]
fn peer_uid(sock_fd: RawFd) -> Result<libc::uid_t> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let ret = unsafe { libc::getpeereid(sock_fd, &mut uid, &mut gid) };
    if ret != 0 {
        return Err(NonoError::SandboxInit(format!(
            "Failed to read attach peer credentials: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(uid)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn peer_uid(_sock_fd: RawFd) -> Result<libc::uid_t> {
    Err(NonoError::SandboxInit(
        "Attach peer credential checks are unsupported on this platform".to_string(),
    ))
}

impl Drop for PtyProxy {
    fn drop(&mut self) {
        if self
            .client
            .as_ref()
            .is_some_and(AttachedClient::is_terminal)
        {
            write_detach_terminal_reset(libc::STDOUT_FILENO);
        }
        self.restore_terminal();
        // Clean up the attach socket
        let _ = std::fs::remove_file(&self.attach_path);
    }
}

/// Put the terminal into raw mode, returning the saved settings.
fn set_terminal_raw() -> Option<nix::sys::termios::Termios> {
    use nix::sys::termios;

    let stdin_fd = std::io::stdin();

    let original = match termios::tcgetattr(&stdin_fd) {
        Ok(t) => t,
        Err(_) => return None, // Not a terminal
    };

    let mut raw = original.clone();
    termios::cfmakeraw(&mut raw);

    if let Err(e) = termios::tcsetattr(&stdin_fd, termios::SetArg::TCSANOW, &raw) {
        warn!("Failed to set raw terminal mode: {}", e);
        return None;
    }

    Some(original)
}

fn get_fd_flags(fd: RawFd) -> Option<libc::c_int> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return None;
    }
    Some(flags)
}

fn set_fd_flags(fd: RawFd, flags: libc::c_int) -> bool {
    unsafe { libc::fcntl(fd, libc::F_SETFL, flags) == 0 }
}

fn set_nonblocking(fd: RawFd) -> bool {
    let Some(flags) = get_fd_flags(fd) else {
        return false;
    };
    set_fd_flags(fd, flags | libc::O_NONBLOCK)
}

fn drain_socket_replay(sock_fd: RawFd) {
    let original_flags = match get_fd_flags(sock_fd) {
        Some(flags) => flags,
        None => return,
    };

    let needs_restore = original_flags & libc::O_NONBLOCK == 0;
    if needs_restore && !set_fd_flags(sock_fd, original_flags | libc::O_NONBLOCK) {
        return;
    }

    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe { libc::read(sock_fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };

        if n > 0 {
            if write_all_fd(libc::STDOUT_FILENO, &buf[..n as usize]).is_err() {
                break;
            }
            continue;
        }

        if n == 0 {
            break;
        }

        let err = std::io::Error::last_os_error();
        match err.kind() {
            std::io::ErrorKind::Interrupted => continue,
            std::io::ErrorKind::WouldBlock => break,
            _ => break,
        }
    }

    if needs_restore {
        let _ = set_fd_flags(sock_fd, original_flags);
    }
}

fn encode_attach_handshake(winsize: Option<Winsize>) -> [u8; ATTACH_HANDSHAKE_LEN] {
    let ws = winsize.unwrap_or(Winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    });

    let mut buf = [0u8; ATTACH_HANDSHAKE_LEN];
    buf[..4].copy_from_slice(&ATTACH_HANDSHAKE_MAGIC);
    buf[4..6].copy_from_slice(&ws.ws_row.to_be_bytes());
    buf[6..8].copy_from_slice(&ws.ws_col.to_be_bytes());
    buf
}

fn decode_attach_handshake(buf: &[u8; ATTACH_HANDSHAKE_LEN]) -> Option<Winsize> {
    if buf[..4] != ATTACH_HANDSHAKE_MAGIC {
        return None;
    }

    Some(Winsize {
        ws_row: u16::from_be_bytes([buf[4], buf[5]]),
        ws_col: u16::from_be_bytes([buf[6], buf[7]]),
        ws_xpixel: 0,
        ws_ypixel: 0,
    })
}

fn encode_resize_message(winsize: Winsize) -> [u8; RESIZE_MESSAGE_LEN] {
    let mut buf = [0u8; RESIZE_MESSAGE_LEN];
    buf[..2].copy_from_slice(&winsize.ws_row.to_be_bytes());
    buf[2..4].copy_from_slice(&winsize.ws_col.to_be_bytes());
    buf
}

fn decode_resize_message(buf: &[u8; RESIZE_MESSAGE_LEN]) -> Option<Winsize> {
    let ws_row = u16::from_be_bytes([buf[0], buf[1]]);
    let ws_col = u16::from_be_bytes([buf[2], buf[3]]);
    if ws_row == 0 || ws_col == 0 {
        return None;
    }
    Some(Winsize {
        ws_row,
        ws_col,
        ws_xpixel: 0,
        ws_ypixel: 0,
    })
}

fn send_attach_handshake(stream: &mut UnixStream) -> Result<()> {
    let handshake = encode_attach_handshake(get_terminal_winsize());
    stream
        .write_all(&handshake)
        .map_err(|e| NonoError::ConfigParse(format!("Failed to send attach handshake: {}", e)))
}

fn send_attach_resize(socket: &UnixDatagram, winsize: Winsize) -> Result<()> {
    let msg = encode_resize_message(winsize);
    socket.send(&msg).map_err(|e| {
        NonoError::SandboxInit(format!("Failed to send attach resize update: {}", e))
    })?;
    Ok(())
}

fn recv_fd_over_stream(stream: &UnixStream) -> Result<OwnedFd> {
    use libc::{
        c_void, iovec, msghdr, recvmsg, CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN, CMSG_NXTHDR, CMSG_SPACE,
    };

    let mut data = [0u8; 1];
    let mut iov = iovec {
        iov_base: data.as_mut_ptr().cast::<c_void>(),
        iov_len: 1,
    };
    let cmsg_space = unsafe { CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];
    let mut msg: msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov as *mut iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast::<c_void>();
    msg.msg_controllen = cmsg_space as _;

    let received = unsafe { recvmsg(stream.as_raw_fd(), &mut msg, 0) };
    if received <= 0 {
        return Err(NonoError::SandboxInit(format!(
            "Failed to receive attach control fd: {}",
            std::io::Error::last_os_error()
        )));
    }
    if (msg.msg_flags & libc::MSG_CTRUNC) != 0 {
        return Err(NonoError::SandboxInit(
            "Attach control fd ancillary data was truncated".to_string(),
        ));
    }

    let expected_len = unsafe { CMSG_LEN(std::mem::size_of::<RawFd>() as u32) } as usize;
    let mut cmsg = unsafe { CMSG_FIRSTHDR(&msg as *const msghdr as *mut msghdr) };
    while !cmsg.is_null() {
        let header = unsafe { &*cmsg };
        if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
            if (header.cmsg_len as usize) < expected_len {
                return Err(NonoError::SandboxInit(
                    "Attach control fd ancillary data too small".to_string(),
                ));
            }
            let mut fd: RawFd = -1;
            unsafe {
                std::ptr::copy_nonoverlapping(
                    CMSG_DATA(cmsg),
                    (&mut fd as *mut RawFd).cast::<u8>(),
                    std::mem::size_of::<RawFd>(),
                );
            }
            if fd < 0 {
                return Err(NonoError::SandboxInit(
                    "Received invalid attach control fd".to_string(),
                ));
            }
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        cmsg = unsafe { CMSG_NXTHDR(&msg as *const msghdr as *mut msghdr, cmsg) };
    }

    Err(NonoError::SandboxInit(
        "No attach control fd received".to_string(),
    ))
}

fn send_fd_over_stream(stream: &UnixStream, fd: RawFd) -> Result<()> {
    use libc::{c_void, cmsghdr, iovec, msghdr, sendmsg, CMSG_DATA, CMSG_LEN, CMSG_SPACE};

    let data = [0u8; 1];
    let iov = iovec {
        iov_base: data.as_ptr().cast::<c_void>() as *mut c_void,
        iov_len: 1,
    };
    let cmsg_space = unsafe { CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];
    let mut msg: msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = (&iov as *const iovec).cast_mut();
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast::<c_void>();
    msg.msg_controllen = cmsg_space as _;

    let cmsg: &mut cmsghdr = unsafe { &mut *(cmsg_buf.as_mut_ptr().cast::<cmsghdr>()) };
    cmsg.cmsg_level = libc::SOL_SOCKET;
    cmsg.cmsg_type = libc::SCM_RIGHTS;
    cmsg.cmsg_len = unsafe { CMSG_LEN(std::mem::size_of::<RawFd>() as u32) } as _;
    unsafe {
        std::ptr::copy_nonoverlapping(
            (&fd as *const RawFd).cast::<u8>(),
            CMSG_DATA(cmsg),
            std::mem::size_of::<RawFd>(),
        );
    }

    let sent = unsafe { sendmsg(stream.as_raw_fd(), &msg, 0) };
    if sent < 0 {
        return Err(NonoError::SandboxInit(format!(
            "Failed to send attach control fd: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

fn recv_attach_resize_socket(stream: &UnixStream) -> Result<Option<UnixDatagram>> {
    let fd = recv_fd_over_stream(stream)?;
    let raw_fd = fd.into_raw_fd();
    let socket = unsafe { UnixDatagram::from_raw_fd(raw_fd) };
    if !set_nonblocking(socket.as_raw_fd()) {
        return Err(NonoError::SandboxInit(
            "Failed to set attach resize socket nonblocking".to_string(),
        ));
    }
    Ok(Some(socket))
}

fn enter_attach_screen() {
    unsafe {
        libc::write(
            libc::STDOUT_FILENO,
            ATTACH_SCREEN_ENTER_ESCAPE.as_ptr().cast(),
            ATTACH_SCREEN_ENTER_ESCAPE.len(),
        );
    }
}

fn leave_attach_screen() {
    let esc = terminal_restore_escape(false);
    let _ = write_all_fd(libc::STDOUT_FILENO, esc);
}

pub(crate) fn write_detach_terminal_reset(fd: RawFd) {
    let esc = terminal_restore_escape(true);
    unsafe {
        libc::write(fd, esc.as_ptr().cast(), esc.len());
    }
}

pub(crate) fn terminal_restore_escape(clear_screen: bool) -> &'static [u8] {
    if clear_screen {
        TERMINAL_RESTORE_AND_CLEAR_ESCAPE
    } else {
        TERMINAL_RESTORE_ESCAPE
    }
}

fn write_all_fd(fd: RawFd, mut bytes: &[u8]) -> std::io::Result<()> {
    while !bytes.is_empty() {
        let written =
            unsafe { libc::write(fd, bytes.as_ptr().cast::<libc::c_void>(), bytes.len()) };
        if written > 0 {
            bytes = &bytes[written as usize..];
            continue;
        }

        let err = std::io::Error::last_os_error();
        match err.kind() {
            std::io::ErrorKind::Interrupted => continue,
            _ => return Err(err),
        }
    }

    Ok(())
}

/// Connect to a running session's attach socket.
///
/// Used by `nono attach` to connect to the supervisor's PTY proxy.
pub fn connect_to_session(session_id: &str) -> Result<UnixStream> {
    let sock_path = crate::session::session_socket_path(session_id)?;

    if !sock_path.exists() {
        return Err(NonoError::ConfigParse(format!(
            "Session {} has no attach socket (not a PTY session or already exited)",
            session_id
        )));
    }

    let mut stream = UnixStream::connect(&sock_path).map_err(|e| {
        NonoError::ConfigParse(format!(
            "Failed to connect to session {} attach socket: {}",
            session_id, e
        ))
    })?;

    send_attach_handshake(&mut stream)?;
    Ok(stream)
}

/// Wait for the supervisor to accept an attach socket.
pub fn wait_for_attach_ready(sock_fd: RawFd, timeout_ms: i32) -> Result<()> {
    let mut pfd = libc::pollfd {
        fd: sock_fd,
        events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
        revents: 0,
    };

    let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if ret < 0 {
        return Err(NonoError::SandboxInit(format!(
            "poll() error waiting for attach readiness: {}",
            std::io::Error::last_os_error()
        )));
    }
    if ret == 0 {
        return Err(NonoError::ConfigParse(
            "Timed out waiting for session attach".to_string(),
        ));
    }
    let mut ack = [0u8; 1];
    let n = unsafe { libc::read(sock_fd, ack.as_mut_ptr().cast::<libc::c_void>(), ack.len()) };
    if n != 1 {
        if pfd.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            return Err(NonoError::ConfigParse(
                "Session attach socket closed before attach completed".to_string(),
            ));
        }
        return Err(NonoError::ConfigParse(
            "Failed to confirm session attach readiness".to_string(),
        ));
    }

    match ack[0] {
        ATTACH_ACK_OK => Ok(()),
        ATTACH_ACK_BUSY => Err(NonoError::ConfigParse(
            "Session already has an active attached client".to_string(),
        )),
        ATTACH_ACK_DENIED => Err(NonoError::ConfigParse(
            "Session attach was rejected by supervisor".to_string(),
        )),
        _ => Err(NonoError::ConfigParse(
            "Received invalid attach acknowledgement from supervisor".to_string(),
        )),
    }
}

/// Attach to an already connected session socket.
pub fn attach_to_stream(stream: UnixStream) -> Result<()> {
    let resize_socket = recv_attach_resize_socket(&stream)?;
    attach_to_stream_with_init(stream, resize_socket, || Ok(()))
}

/// Attach to an already connected session socket after running an init hook.
///
/// The init hook runs after the local terminal has entered raw mode but before
/// the attach loop starts, which is important for TUIs that probe the terminal
/// immediately when they are resumed.
pub fn attach_to_stream_with_init<F>(
    stream: UnixStream,
    resize_socket: Option<UnixDatagram>,
    init: F,
) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    let sock_fd = stream.as_raw_fd();

    // Put our terminal in raw mode
    let saved_termios = set_terminal_raw();
    enter_attach_screen();

    // Render any queued replay bytes before the child is resumed. This keeps
    // the restored screen and cursor state coherent before new live output
    // starts arriving from the PTY.
    drain_socket_replay(sock_fd);

    let init_result = init();

    // Proxy I/O between our terminal and the socket
    let result = match init_result {
        Ok(()) => run_attach_loop(
            sock_fd,
            resize_socket.as_ref(),
            Some(Duration::from_millis(250)),
        ),
        Err(e) => Err(e),
    };

    // Restore terminal
    leave_attach_screen();
    if let Some(ref termios) = saved_termios {
        let _ = nix::sys::termios::tcsetattr(
            std::io::stdin(),
            nix::sys::termios::SetArg::TCSANOW,
            termios,
        );
    }

    // Keep stream alive until we're done
    drop(stream);

    result
}

/// Connect to a running session's attach socket and proxy I/O.
pub fn attach_to_session(session_id: &str) -> Result<()> {
    let stream = connect_to_session(session_id)?;
    wait_for_attach_ready(stream.as_raw_fd(), 1000)?;
    attach_to_stream(stream)
}

/// Run the attach client I/O loop.
fn run_attach_loop(
    sock_fd: RawFd,
    resize_socket: Option<&UnixDatagram>,
    stdin_delay: Option<Duration>,
) -> Result<()> {
    let mut pfds = [
        libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: sock_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    let mut buf = [0u8; 4096];
    let stdin_deadline = stdin_delay.and_then(|delay| std::time::Instant::now().checked_add(delay));
    let mut last_winsize = get_terminal_winsize();

    loop {
        if let Some(socket) = resize_socket {
            if let Some(winsize) = get_terminal_winsize() {
                let changed = last_winsize
                    .map(|last| last.ws_row != winsize.ws_row || last.ws_col != winsize.ws_col)
                    .unwrap_or(true);
                if changed {
                    let _ = send_attach_resize(socket, winsize);
                    last_winsize = Some(winsize);
                }
            }
        }

        if let Some(deadline) = stdin_deadline {
            if std::time::Instant::now() < deadline {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
                let mut warmup_pfd = libc::pollfd {
                    fd: sock_fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let ret = unsafe { libc::poll(&mut warmup_pfd, 1, timeout_ms) };
                if ret < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(NonoError::SandboxInit(format!(
                        "poll() error in attach warm-up: {}",
                        err
                    )));
                }
                if warmup_pfd.revents & libc::POLLIN != 0 {
                    let n = unsafe {
                        libc::read(sock_fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len())
                    };
                    if n <= 0 {
                        break;
                    }
                    if write_all_fd(libc::STDOUT_FILENO, &buf[..n as usize]).is_err() {
                        break;
                    }
                }
                if warmup_pfd.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                    break;
                }
                continue;
            }
        }

        // SAFETY: pfds is a valid array on the stack
        let ret = unsafe { libc::poll(pfds.as_mut_ptr(), 2, 250) };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(NonoError::SandboxInit(format!(
                "poll() error in attach loop: {}",
                err
            )));
        }

        // stdin → socket (user input)
        if pfds[0].revents & libc::POLLIN != 0 {
            let n = unsafe {
                libc::read(
                    libc::STDIN_FILENO,
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                )
            };
            if n <= 0 {
                break;
            }
            if write_all_fd(sock_fd, &buf[..n as usize]).is_err() {
                break;
            }
        }

        // socket → stdout (child output)
        if pfds[1].revents & libc::POLLIN != 0 {
            let n =
                unsafe { libc::read(sock_fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
            if n <= 0 {
                break;
            }
            if write_all_fd(libc::STDOUT_FILENO, &buf[..n as usize]).is_err() {
                break;
            }
        }

        // Connection closed
        if pfds[1].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            break;
        }
    }

    eprintln!("\n[nono] Detached from session.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        select_attach_replay_bytes, terminal_restore_escape, PtyProxy, ScreenState,
        DEFAULT_DETACH_SEQUENCE,
    };
    use nix::libc;
    use std::collections::VecDeque;
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::net::UnixListener;

    fn build_test_proxy(sequence: &[u8]) -> PtyProxy {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let attach_path = temp_dir.path().join("attach.sock");
        let attach_listener = UnixListener::bind(&attach_path).expect("bind attach socket");
        let dup_fd = unsafe { libc::dup(libc::STDIN_FILENO) };
        assert!(dup_fd >= 0);
        let master = unsafe { OwnedFd::from_raw_fd(dup_fd) };

        PtyProxy {
            master,
            session_id: "test-session".to_string(),
            attach_listener,
            attach_path,
            client: None,
            resize_notifier: None,
            saved_termios: None,
            scrollback: VecDeque::new(),
            screen: ScreenState::new(24, 80),
            detach_sequence: sequence.to_vec(),
            pending_detach_match_len: 0,
            detach_requested: false,
        }
    }

    #[test]
    fn terminal_restore_escape_disables_mouse_modes() {
        let esc = std::str::from_utf8(terminal_restore_escape(false)).unwrap_or("");
        for mode in ["1000", "1002", "1003", "1005", "1006", "1015"] {
            assert!(esc.contains(&format!("\u{1b}[?{mode}l")));
        }
        assert!(esc.contains("\u{1b}[?1049l"));
    }

    #[test]
    fn terminal_restore_escape_can_clear_screen() {
        let esc = std::str::from_utf8(terminal_restore_escape(true)).unwrap_or("");
        assert!(esc.ends_with("\u{1b}[2J\u{1b}[H"));
    }

    #[test]
    fn attach_replay_uses_rendered_snapshot_for_alternate_screen() {
        let replay = select_attach_replay_bytes(true, b"raw".to_vec(), b"rendered".to_vec());
        assert_eq!(replay, b"rendered");
    }

    #[test]
    fn attach_replay_uses_rendered_snapshot_for_normal_screen() {
        let replay = select_attach_replay_bytes(false, b"raw".to_vec(), b"rendered".to_vec());
        assert_eq!(replay, b"rendered");
    }

    #[test]
    fn attach_replay_falls_back_to_raw_if_alternate_snapshot_is_empty() {
        let replay = select_attach_replay_bytes(true, b"raw".to_vec(), Vec::new());
        assert_eq!(replay, b"raw");
    }

    #[test]
    fn apply_winsize_is_noop_when_dimensions_are_unchanged() {
        let mut proxy = build_test_proxy(&DEFAULT_DETACH_SEQUENCE);
        proxy.screen.apply_bytes(b"\x1b[?1049h\x1b[2J\x1b[Hhello");

        let before = proxy.screen.render();
        let changed = proxy.apply_winsize(&nix::pty::Winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        });
        let after = proxy.screen.render();

        assert!(!changed);
        assert_eq!(before, after);
    }

    #[test]
    fn apply_winsize_ignores_zero_dimensions() {
        let mut proxy = build_test_proxy(&DEFAULT_DETACH_SEQUENCE);
        let before = proxy.screen.size();
        let changed = proxy.apply_winsize(&nix::pty::Winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        });

        assert!(!changed);
        assert_eq!(before, proxy.screen.size());
    }

    #[test]
    fn detach_clears_partial_detach_sequence_state() {
        let mut proxy = build_test_proxy(&DEFAULT_DETACH_SEQUENCE);
        let forwarded = proxy.filter_client_input(&[DEFAULT_DETACH_SEQUENCE[0]]);
        assert!(forwarded.is_empty());
        assert_eq!(proxy.pending_detach_match_len, 1);

        let _ = proxy.detach();

        assert_eq!(proxy.pending_detach_match_len, 0);
        let forwarded = proxy.filter_client_input(b"x");
        assert_eq!(forwarded, b"x");
        assert!(!proxy.take_detach_request());
    }

    #[test]
    fn filter_client_input_detaches_on_default_sequence() {
        let mut proxy = build_test_proxy(&DEFAULT_DETACH_SEQUENCE);
        let forwarded = proxy.filter_client_input(&DEFAULT_DETACH_SEQUENCE);
        assert!(forwarded.is_empty());
        assert!(proxy.take_detach_request());
    }

    #[test]
    fn filter_client_input_detaches_on_custom_sequence() {
        let mut proxy = build_test_proxy(&[0x01, b'x']);
        let forwarded = proxy.filter_client_input(&[0x01, b'x']);
        assert!(forwarded.is_empty());
        assert!(proxy.take_detach_request());
    }

    #[test]
    fn filter_client_input_forwards_partial_mismatch() {
        let mut proxy = build_test_proxy(&DEFAULT_DETACH_SEQUENCE);
        let forwarded = proxy.filter_client_input(&[0x1d, b'x']);
        assert_eq!(forwarded, vec![0x1d, b'x']);
        assert!(!proxy.take_detach_request());
    }
}
