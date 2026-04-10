//! Windows named-pipe IPC for supervisor-child communication.
//!
//! Windows does not support Unix domain sockets or `SCM_RIGHTS`. The initial
//! supervisor scaffold uses a per-session duplex named pipe as the control
//! channel. Approved resource transfer uses explicit handle brokering metadata
//! plus `DuplicateHandle` into the child process.

use crate::error::{NonoError, Result};
use crate::supervisor::types::{ResourceGrant, SupervisorMessage, SupervisorResponse};
use getrandom::fill as random_fill;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::{
    DuplicateHandle, DUPLICATE_SAME_ACCESS, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY,
    ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, CreatePipe, DisconnectNamedPipe,
    GetNamedPipeServerProcessId, WaitNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

/// Length prefix size: 4 bytes (u32 big-endian)
const LENGTH_PREFIX_SIZE: usize = 4;

/// Maximum message size: 64 KiB (prevents memory exhaustion from malicious messages)
const MAX_MESSAGE_SIZE: u32 = 64 * 1024;

/// Default wait for pipe availability during startup.
const PIPE_CONNECT_TIMEOUT_MS: u32 = 5_000;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PipeRendezvousInfo {
    pipe_name: String,
    server_pid: u32,
}

/// A Windows named pipe used for supervisor IPC.
#[derive(Debug)]
pub struct SupervisorSocket {
    reader: File,
    writer: File,
    transport_name: String,
    disconnect_on_drop: bool,
    cleanup_rendezvous_path: Option<PathBuf>,
}

/// Windows process target for brokered handle duplication.
#[derive(Debug, Clone, Copy)]
pub struct BrokerTargetProcess {
    handle: HANDLE,
}

impl SupervisorSocket {
    /// Create a connected Windows pipe pair for supervisor-child IPC.
    #[must_use = "both pipe ends must be used"]
    pub fn pair() -> Result<(Self, Self)> {
        // `pair()` is a local already-connected helper used by tests and
        // in-process setup. The production Windows supervisor transport still
        // uses duplex named pipes through `bind()` / `connect()`.
        let (parent_reader, child_writer) = create_anonymous_pipe()?;
        let (child_reader, parent_writer) = create_anonymous_pipe()?;
        let transport_name = unique_pair_name()?;

        Ok((
            Self {
                reader: parent_reader,
                writer: parent_writer,
                transport_name: transport_name.clone(),
                disconnect_on_drop: false,
                cleanup_rendezvous_path: None,
            },
            Self {
                reader: child_reader,
                writer: child_writer,
                transport_name,
                disconnect_on_drop: false,
                cleanup_rendezvous_path: None,
            },
        ))
    }

    /// Bind a named pipe for the provided rendezvous path and wait for a client.
    pub fn bind(path: &Path) -> Result<Self> {
        let (pipe_name, cleanup_rendezvous_path) = prepare_bind_pipe_name(path)?;
        let server_handle = create_named_pipe(&pipe_name, false)?;
        if let Err(err) = write_pipe_rendezvous(path, &pipe_name) {
            // SAFETY: `server_handle` is an owned handle created above and must
            // be reclaimed if rendezvous publication fails before conversion.
            drop(unsafe { OwnedHandle::from_raw_handle(server_handle) });
            return Err(err);
        }
        let server_file = finalize_server_connection(server_handle, &pipe_name)?;
        Ok(Self {
            reader: server_file
                .try_clone()
                .map_err(|e| NonoError::SandboxInit(format!("Failed to clone pipe handle: {e}")))?,
            writer: server_file,
            transport_name: pipe_name,
            disconnect_on_drop: true,
            cleanup_rendezvous_path,
        })
    }

    /// Connect to a named pipe published for the provided rendezvous path.
    pub fn connect(path: &Path) -> Result<Self> {
        let rendezvous = resolve_connect_pipe_name(path)?;
        let file = connect_named_pipe(&rendezvous)?;
        Ok(Self {
            reader: file
                .try_clone()
                .map_err(|e| NonoError::SandboxInit(format!("Failed to clone pipe handle: {e}")))?,
            writer: file,
            transport_name: rendezvous.pipe_name,
            disconnect_on_drop: false,
            cleanup_rendezvous_path: None,
        })
    }

    /// Send a message from child to supervisor.
    pub fn send_message(&mut self, msg: &SupervisorMessage) -> Result<()> {
        let payload = serde_json::to_vec(msg).map_err(|e| {
            NonoError::SandboxInit(format!("Failed to serialize supervisor message: {e}"))
        })?;
        self.write_frame(&payload)
    }

    /// Receive a message from child (supervisor side).
    pub fn recv_message(&mut self) -> Result<SupervisorMessage> {
        let payload = self.read_frame()?;
        serde_json::from_slice(&payload).map_err(|e| {
            NonoError::SandboxInit(format!("Failed to deserialize supervisor message: {e}"))
        })
    }

    /// Send a response from supervisor to child.
    pub fn send_response(&mut self, resp: &SupervisorResponse) -> Result<()> {
        let payload = serde_json::to_vec(resp).map_err(|e| {
            NonoError::SandboxInit(format!("Failed to serialize supervisor response: {e}"))
        })?;
        self.write_frame(&payload)
    }

    /// Receive a response from supervisor (child side).
    pub fn recv_response(&mut self) -> Result<SupervisorResponse> {
        let payload = self.read_frame()?;
        serde_json::from_slice(&payload).map_err(|e| {
            NonoError::SandboxInit(format!("Failed to deserialize supervisor response: {e}"))
        })
    }

    /// Returns the Windows transport name used by this connection.
    #[must_use]
    pub fn transport_name(&self) -> &str {
        &self.transport_name
    }

    fn write_frame(&mut self, payload: &[u8]) -> Result<()> {
        let len = payload.len();
        if len > MAX_MESSAGE_SIZE as usize {
            return Err(NonoError::SandboxInit(format!(
                "Supervisor message too large: {len} bytes (max: {MAX_MESSAGE_SIZE})"
            )));
        }

        let len_bytes = (len as u32).to_be_bytes();
        self.writer
            .write_all(&len_bytes)
            .map_err(|e| NonoError::SandboxInit(format!("Failed to write message length: {e}")))?;
        self.writer
            .write_all(payload)
            .map_err(|e| NonoError::SandboxInit(format!("Failed to write message payload: {e}")))?;
        self.writer
            .flush()
            .map_err(|e| NonoError::SandboxInit(format!("Failed to flush pipe payload: {e}")))?;
        Ok(())
    }

    fn read_frame(&mut self) -> Result<Vec<u8>> {
        let mut len_bytes = [0u8; LENGTH_PREFIX_SIZE];
        self.reader
            .read_exact(&mut len_bytes)
            .map_err(|e| NonoError::SandboxInit(format!("Failed to read message length: {e}")))?;

        let len = u32::from_be_bytes(len_bytes);
        if len > MAX_MESSAGE_SIZE {
            return Err(NonoError::SandboxInit(format!(
                "Supervisor message too large: {len} bytes (max: {MAX_MESSAGE_SIZE})"
            )));
        }

        let mut payload = vec![0u8; len as usize];
        self.reader
            .read_exact(&mut payload)
            .map_err(|e| NonoError::SandboxInit(format!("Failed to read message payload: {e}")))?;
        Ok(payload)
    }
}

impl BrokerTargetProcess {
    /// Use the current process as the duplication target.
    #[must_use]
    pub fn current() -> Self {
        Self {
            handle: unsafe {
                // SAFETY: `GetCurrentProcess` returns a valid pseudo-handle for
                // the current process and requires no explicit cleanup.
                GetCurrentProcess()
            },
        }
    }

    /// Construct a target wrapper from an existing live process handle.
    ///
    /// # Safety
    ///
    /// The caller must ensure the handle refers to a live process and remains
    /// valid for the duration of the brokering call.
    #[must_use]
    pub unsafe fn from_raw_handle(handle: HANDLE) -> Self {
        Self { handle }
    }

    fn raw(self) -> HANDLE {
        self.handle
    }
}

/// Duplicate an opened file handle into the target process and describe it in
/// the supervisor response contract.
pub fn broker_file_handle_to_process(
    file: &File,
    target_process: BrokerTargetProcess,
    access: crate::capability::AccessMode,
) -> Result<ResourceGrant> {
    let mut duplicated: HANDLE = std::ptr::null_mut();
    let source_handle = file.as_raw_handle() as HANDLE;

    // SAFETY: `source_handle` comes from a live `File`, the current process is
    // the source process, `target_process` was wrapped by the caller from a
    // live process handle, and `duplicated` points to writable storage.
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            source_handle,
            target_process.raw(),
            &mut duplicated,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if ok == 0 || duplicated.is_null() {
        return Err(NonoError::SandboxInit(format!(
            "Failed to duplicate Windows handle into supervised child: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(ResourceGrant::duplicated_windows_file_handle(
        duplicated as usize as u64,
        access,
    ))
}

impl Drop for SupervisorSocket {
    fn drop(&mut self) {
        if self.disconnect_on_drop {
            let raw = self.writer.as_raw_handle();
            if !raw.is_null() {
                // SAFETY: The handle comes from this `File` and remains valid for
                // the duration of `drop`. Disconnecting the server end is the
                // Windows-equivalent cleanup for a bound named pipe instance.
                unsafe {
                    let _ = DisconnectNamedPipe(raw as HANDLE);
                }
            }
        }
        if let Some(path) = self.cleanup_rendezvous_path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn unique_pair_name() -> Result<String> {
    let mut nonce = [0u8; 16];
    random_fill(&mut nonce)
        .map_err(|e| NonoError::SandboxInit(format!("Failed to generate pipe nonce: {e}")))?;
    let suffix = nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!(
        "windows-supervisor-anon-{}-{suffix}",
        std::process::id()
    ))
}

fn explicit_pipe_name(path: &Path) -> Option<String> {
    let display = path.to_string_lossy();
    if display.starts_with(r"\\.\pipe\") {
        Some(display.into_owned())
    } else {
        None
    }
}

fn create_nonce_hex() -> Result<String> {
    let mut nonce = [0u8; 16];
    random_fill(&mut nonce)
        .map_err(|e| NonoError::SandboxInit(format!("Failed to generate pipe nonce: {e}")))?;
    Ok(nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>())
}

fn pipe_name_from_rendezvous_path(path: &Path, nonce_hex: &str) -> String {
    let mut hasher = Sha256::new();
    let display = path.to_string_lossy();
    hasher.update(display.as_bytes());
    let digest = hasher.finalize();
    let short_hash = digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    let leaf = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("supervisor");
    let safe_leaf = leaf
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();

    format!(r"\\.\pipe\nono-{}-{short_hash}-{nonce_hex}", safe_leaf)
}

fn prepare_bind_pipe_name(path: &Path) -> Result<(String, Option<PathBuf>)> {
    if let Some(pipe_name) = explicit_pipe_name(path) {
        return Ok((pipe_name, None));
    }

    let nonce_hex = create_nonce_hex()?;
    Ok((
        pipe_name_from_rendezvous_path(path, &nonce_hex),
        Some(path.to_path_buf()),
    ))
}

fn resolve_connect_pipe_name(path: &Path) -> Result<PipeRendezvousInfo> {
    if let Some(pipe_name) = explicit_pipe_name(path) {
        return Ok(PipeRendezvousInfo {
            pipe_name,
            server_pid: 0,
        });
    }

    read_pipe_rendezvous(path)
}

fn write_pipe_rendezvous(path: &Path, pipe_name: &str) -> Result<()> {
    if explicit_pipe_name(path).is_some() {
        return Ok(());
    }

    let parent = path.parent().ok_or_else(|| {
        NonoError::SandboxInit(format!(
            "Windows supervisor rendezvous path {} has no parent directory",
            path.display()
        ))
    })?;
    std::fs::create_dir_all(parent).map_err(|e| {
        NonoError::SandboxInit(format!(
            "Failed to create Windows supervisor rendezvous directory {}: {e}",
            parent.display()
        ))
    })?;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| {
            NonoError::SandboxInit(format!(
                "Failed to publish Windows supervisor rendezvous {}: {e}",
                path.display()
            ))
        })?;
    let payload = format!("{pipe_name}\n{}", std::process::id());
    file.write_all(payload.as_bytes()).map_err(|e| {
        NonoError::SandboxInit(format!(
            "Failed to write Windows supervisor rendezvous {}: {e}",
            path.display()
        ))
    })?;
    file.flush().map_err(|e| {
        NonoError::SandboxInit(format!(
            "Failed to flush Windows supervisor rendezvous {}: {e}",
            path.display()
        ))
    })?;
    Ok(())
}

fn read_pipe_rendezvous(path: &Path) -> Result<PipeRendezvousInfo> {
    let contents = std::fs::read_to_string(path).map_err(|e| {
        NonoError::SandboxInit(format!(
            "Failed to read Windows supervisor pipe rendezvous {}: {e}. \
Ensure the supervisor created the control channel before launching the child.",
            path.display()
        ))
    })?;
    let mut lines = contents.lines();
    let pipe_name = lines.next().unwrap_or_default().trim();
    if !pipe_name.starts_with(r"\\.\pipe\") {
        return Err(NonoError::SandboxInit(format!(
            "Windows supervisor pipe rendezvous {} did not contain a valid pipe name",
            path.display()
        )));
    }
    let server_pid = lines
        .next()
        .ok_or_else(|| {
            NonoError::SandboxInit(format!(
                "Windows supervisor pipe rendezvous {} did not include a server PID",
                path.display()
            ))
        })?
        .trim()
        .parse::<u32>()
        .map_err(|e| {
            NonoError::SandboxInit(format!(
                "Windows supervisor pipe rendezvous {} contained an invalid server PID: {e}",
                path.display()
            ))
        })?;
    Ok(PipeRendezvousInfo {
        pipe_name: pipe_name.to_string(),
        server_pid,
    })
}

fn create_named_pipe(pipe_name: &str, first_instance: bool) -> Result<HANDLE> {
    let mut open_mode = PIPE_ACCESS_DUPLEX;
    if first_instance {
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    let wide_name = to_wide(pipe_name);

    // SAFETY: `wide_name` is a valid null-terminated UTF-16 string. We request a
    // single duplex byte-mode instance with no external pointers.
    let handle = unsafe {
        CreateNamedPipeW(
            wide_name.as_ptr(),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            MAX_MESSAGE_SIZE,
            MAX_MESSAGE_SIZE,
            PIPE_CONNECT_TIMEOUT_MS,
            std::ptr::null(),
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        return Err(NonoError::SandboxInit(format!(
            "Failed to create Windows supervisor pipe {pipe_name}: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(handle)
}

fn finalize_server_connection(server_handle: HANDLE, pipe_name: &str) -> Result<File> {
    // SAFETY: `server_handle` was returned by `CreateNamedPipeW` and is still
    // owned by this function until converted into `OwnedHandle`.
    let connected = unsafe { ConnectNamedPipe(server_handle, std::ptr::null_mut()) };
    if connected == 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(ERROR_PIPE_CONNECTED as i32) {
            // SAFETY: `server_handle` is a live handle that must be reclaimed on error.
            drop(unsafe { OwnedHandle::from_raw_handle(server_handle) });
            return Err(NonoError::SandboxInit(format!(
                "Failed to accept Windows supervisor pipe connection on {pipe_name}: {err}. \
Ensure the child process received the correct pipe name and startup token."
            )));
        }
    }

    Ok(file_from_handle(server_handle))
}

fn connect_named_pipe(rendezvous: &PipeRendezvousInfo) -> Result<File> {
    let wide_name = to_wide(&rendezvous.pipe_name);
    let mut last_error: Option<std::io::Error> = None;

    for _ in 0..3 {
        // SAFETY: `wide_name` is a valid null-terminated UTF-16 string. We open
        // the pipe for duplex access and receive an owned OS handle on success.
        let handle = unsafe {
            CreateFileW(
                wide_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };

        if handle != INVALID_HANDLE_VALUE {
            let file = file_from_handle(handle);
            if rendezvous.server_pid != 0 {
                verify_connected_server_pid(file.as_raw_handle() as HANDLE, rendezvous)?;
            }
            return Ok(file);
        }

        let err = std::io::Error::last_os_error();
        if matches!(
            err.raw_os_error(),
            Some(code) if code == ERROR_PIPE_BUSY as i32 || code == ERROR_FILE_NOT_FOUND as i32
        ) {
            // SAFETY: `wide_name` remains valid for the duration of the call.
            let waited = unsafe { WaitNamedPipeW(wide_name.as_ptr(), PIPE_CONNECT_TIMEOUT_MS) };
            if waited != 0 {
                continue;
            }
            last_error = Some(std::io::Error::last_os_error());
            continue;
        }

        return Err(NonoError::SandboxInit(format!(
            "Failed to connect to Windows supervisor pipe {}: {err}. \
Ensure the supervisor created the control channel before launching the child.",
            rendezvous.pipe_name
        )));
    }

    let err = last_error.unwrap_or_else(std::io::Error::last_os_error);
    Err(NonoError::SandboxInit(format!(
        "Timed out waiting for Windows supervisor pipe {}: {err}. \
Ensure the parent process is listening before the child attempts to connect.",
        rendezvous.pipe_name
    )))
}

fn verify_connected_server_pid(handle: HANDLE, rendezvous: &PipeRendezvousInfo) -> Result<()> {
    let mut actual_server_pid = 0u32;
    let ok = unsafe {
        // SAFETY: `handle` is a live pipe handle returned by `CreateFileW` and
        // `actual_server_pid` points to writable storage for the queried PID.
        GetNamedPipeServerProcessId(handle, &mut actual_server_pid)
    };
    if ok == 0 {
        return Err(NonoError::SandboxInit(format!(
            "Failed to verify Windows supervisor pipe server PID for {}: {}",
            rendezvous.pipe_name,
            std::io::Error::last_os_error()
        )));
    }
    if actual_server_pid != rendezvous.server_pid {
        return Err(NonoError::SandboxInit(format!(
            "Windows supervisor pipe peer validation failed for {}: expected server PID {}, got {}",
            rendezvous.pipe_name, rendezvous.server_pid, actual_server_pid
        )));
    }
    Ok(())
}

fn file_from_handle(handle: HANDLE) -> File {
    // SAFETY: `handle` is a valid owned Windows handle returned by a Win32 API
    // in this module. Converting it into `OwnedHandle` transfers ownership to Rust.
    let owned = unsafe { OwnedHandle::from_raw_handle(handle) };
    File::from(owned)
}

fn create_anonymous_pipe() -> Result<(File, File)> {
    let mut read_handle: HANDLE = std::ptr::null_mut();
    let mut write_handle: HANDLE = std::ptr::null_mut();

    // SAFETY: We pass valid out-pointers for the read and write handles and do
    // not request inherited handles yet. On success, both handles are owned by
    // this function and immediately wrapped in `File`.
    let created = unsafe { CreatePipe(&mut read_handle, &mut write_handle, std::ptr::null(), 0) };
    if created == 0 {
        return Err(NonoError::SandboxInit(format!(
            "Failed to create Windows anonymous pipe pair: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok((
        file_from_handle(read_handle),
        file_from_handle(write_handle),
    ))
}

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::AccessMode;
    use crate::supervisor::types::{
        ApprovalDecision, CapabilityRequest, ResourceTransferKind, SupervisorMessage,
        SupervisorResponse,
    };
    use std::path::PathBuf;
    #[test]
    fn test_pipe_pair_roundtrip() {
        let (mut supervisor, mut child) =
            SupervisorSocket::pair().expect("Failed to create named pipe pair");

        let request = CapabilityRequest {
            request_id: "req-001".to_string(),
            path: r"C:\tmp\test.txt".into(),
            access: AccessMode::Read,
            reason: Some("test access".to_string()),
            child_pid: 12345,
            session_id: "sess-001".to_string(),
        };

        child
            .send_message(&SupervisorMessage::Request(request.clone()))
            .expect("Failed to send request");

        let msg = supervisor
            .recv_message()
            .expect("Failed to receive request");
        match msg {
            SupervisorMessage::Request(req) => {
                assert_eq!(req.request_id, "req-001");
                assert_eq!(req.path, PathBuf::from(r"C:\tmp\test.txt"));
                assert_eq!(req.child_pid, 12345);
            }
            other => panic!("Expected Request, got {other:?}"),
        }

        supervisor
            .send_response(&SupervisorResponse::Decision {
                request_id: "req-001".to_string(),
                decision: ApprovalDecision::Granted,
                grant: Some(ResourceGrant::duplicated_windows_file_handle(
                    0x1234,
                    AccessMode::Read,
                )),
            })
            .expect("Failed to send response");

        let resp = child.recv_response().expect("Failed to receive response");
        match resp {
            SupervisorResponse::Decision {
                request_id,
                decision,
                grant,
            } => {
                assert_eq!(request_id, "req-001");
                assert!(decision.is_granted());
                let grant = grant.expect("grant metadata should be present");
                assert_eq!(
                    grant.transfer,
                    ResourceTransferKind::DuplicatedWindowsHandle
                );
                assert_eq!(grant.raw_handle, Some(0x1234));
            }
            other => panic!("Expected Decision, got {other:?}"),
        }
    }

    #[test]
    fn test_message_too_large() {
        let (mut supervisor, _child) =
            SupervisorSocket::pair().expect("Failed to create named pipe pair");

        let large_payload = vec![0u8; (MAX_MESSAGE_SIZE as usize) + 1];
        let result = supervisor.write_frame(&large_payload);
        assert!(result.is_err());
    }

    #[test]
    fn test_connect_missing_pipe_returns_actionable_diagnostic() {
        let path = PathBuf::from(format!(
            r"C:\tmp\nono-win-missing-{}-{}",
            std::process::id(),
            1
        ));
        let err = SupervisorSocket::connect(&path).expect_err("Connect should fail");
        let message = err.to_string();
        assert!(message.contains("Windows supervisor pipe"));
        assert!(
            message.contains("Ensure the supervisor created the control channel")
                || message.contains("Ensure the parent process is listening")
                || message.contains("Timed out waiting for Windows supervisor pipe")
        );
    }

    #[test]
    fn test_rendezvous_paths_publish_nonce_backed_pipe_names() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rendezvous = dir.path().join("supervisor.pipe");

        let (pipe_name_one, cleanup_one) =
            prepare_bind_pipe_name(&rendezvous).expect("prepare first pipe");
        let (pipe_name_two, cleanup_two) =
            prepare_bind_pipe_name(&rendezvous).expect("prepare second pipe");

        assert_ne!(pipe_name_one, pipe_name_two);
        assert_eq!(cleanup_one.as_deref(), Some(rendezvous.as_path()));
        assert_eq!(cleanup_two.as_deref(), Some(rendezvous.as_path()));
        assert!(pipe_name_one.starts_with(r"\\.\pipe\nono-"));
        assert!(pipe_name_two.starts_with(r"\\.\pipe\nono-"));
    }

    #[test]
    fn test_explicit_pipe_paths_are_preserved() {
        let explicit = PathBuf::from(r"\\.\pipe\nono-explicit");
        let (pipe_name, cleanup_path) =
            prepare_bind_pipe_name(&explicit).expect("prepare explicit pipe");

        assert_eq!(pipe_name, r"\\.\pipe\nono-explicit");
        assert!(cleanup_path.is_none());
    }

    #[test]
    fn test_rendezvous_roundtrip_uses_published_pipe_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rendezvous = dir.path().join("socket.info");
        let pipe_name = r"\\.\pipe\nono-test-roundtrip";

        write_pipe_rendezvous(&rendezvous, pipe_name).expect("write rendezvous");
        let resolved = resolve_connect_pipe_name(&rendezvous).expect("resolve rendezvous");

        assert_eq!(resolved.pipe_name, pipe_name);
        assert_eq!(resolved.server_pid, std::process::id());
    }

    #[test]
    fn test_explicit_pipe_path_skips_server_pid_expectation() {
        let explicit = PathBuf::from(r"\\.\pipe\nono-explicit-connect");
        let resolved = resolve_connect_pipe_name(&explicit).expect("resolve explicit");

        assert_eq!(resolved.pipe_name, r"\\.\pipe\nono-explicit-connect");
        assert_eq!(resolved.server_pid, 0);
    }

    #[test]
    fn test_read_pipe_rendezvous_rejects_missing_server_pid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rendezvous = dir.path().join("socket.info");
        std::fs::write(&rendezvous, r"\\.\pipe\nono-test-only").expect("write rendezvous");

        let err = read_pipe_rendezvous(&rendezvous).expect_err("missing pid should fail");
        assert!(err.to_string().contains("did not include a server PID"));
    }

    #[test]
    fn test_broker_file_handle_to_process_duplicates_handle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("broker.txt");
        std::fs::write(&path, b"hello").expect("write file");
        let file = File::open(&path).expect("open file");

        let grant =
            broker_file_handle_to_process(&file, BrokerTargetProcess::current(), AccessMode::Read)
                .expect("duplicate handle into current process");
        assert_eq!(
            grant.transfer,
            ResourceTransferKind::DuplicatedWindowsHandle
        );
        let raw_handle = grant.raw_handle.expect("raw handle");
        assert_ne!(raw_handle, 0);

        unsafe {
            // SAFETY: The duplicated handle value came from `DuplicateHandle`
            // above and has not been wrapped or closed yet.
            windows_sys::Win32::Foundation::CloseHandle(raw_handle as usize as HANDLE);
        }
    }
}
