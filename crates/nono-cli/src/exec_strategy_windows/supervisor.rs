use super::*;
use std::io::{Read, Write};
use std::mem::ManuallyDrop;
use std::os::windows::io::FromRawHandle;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use windows_sys::Win32::Foundation::{GetLastError, LocalFree, BOOL, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::Console::{
    GetConsoleScreenBufferInfo, GetStdHandle, ResizePseudoConsole, SetConsoleCtrlHandler,
    CONSOLE_SCREEN_BUFFER_INFO, COORD, CTRL_C_EVENT, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, TerminateProcess, WaitForSingleObject,
};

const SDDL_REVISION_1: u32 = 1;

const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT_CODE: u32 = 0x0000_0102;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SendableHandle(pub HANDLE);

unsafe impl Send for SendableHandle {}
unsafe impl Sync for SendableHandle {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WindowsSupervisorLifecycleState {
    Initializing,
    ControlChannelReady,
    LaunchingChild,
    WaitingForChild,
    ShuttingDown,
    Completed,
}

impl WindowsSupervisorLifecycleState {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Initializing => "initializing",
            Self::ControlChannelReady => "control-channel-ready",
            Self::LaunchingChild => "launching-child",
            Self::WaitingForChild => "waiting-for-child",
            Self::ShuttingDown => "shutting-down",
            Self::Completed => "completed",
        }
    }
}

#[derive(Debug)]
pub(super) enum WindowsSupervisedChild {
    Native {
        process: OwnedHandle,
        _thread: OwnedHandle,
    },
}

impl WindowsSupervisedChild {
    fn process_handle(&self) -> HANDLE {
        match self {
            Self::Native { process, .. } => process.0,
        }
    }

    fn wait_for_exit(&self, timeout: u32) -> Result<Option<i32>> {
        let wait_result = unsafe {
            // SAFETY: `process_handle()` returns a valid process handle owned by this child wrapper.
            WaitForSingleObject(self.process_handle(), timeout)
        };
        match wait_result {
            WAIT_OBJECT_0 => {
                let mut exit_code = 0u32;
                let ok = unsafe {
                    // SAFETY: Handle remains valid and `exit_code` is writable.
                    GetExitCodeProcess(self.process_handle(), &mut exit_code)
                };
                if ok == 0 {
                    return Err(NonoError::SandboxInit(
                        "Failed to query Windows supervised child exit code".to_string(),
                    ));
                }
                Ok(Some(exit_code as i32))
            }
            WAIT_TIMEOUT_CODE => Ok(None),
            _ => Err(NonoError::SandboxInit(format!(
                "Windows supervisor failed while waiting for child process state: {}",
                std::io::Error::last_os_error()
            ))),
        }
    }

    pub(super) fn poll_exit_code(&mut self) -> Result<Option<i32>> {
        match self {
            Self::Native { .. } => self.wait_for_exit(0),
        }
    }

    pub(super) fn terminate(&self) -> Result<()> {
        let ok = unsafe {
            // SAFETY: `process_handle()` is a valid process handle with `PROCESS_TERMINATE` access.
            TerminateProcess(self.process_handle(), 1)
        };
        if ok == 0 {
            let err = std::io::Error::last_os_error();
            // If it already exited, that's fine
            if err.raw_os_error()
                != Some(windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED as i32)
            {
                return Err(NonoError::CommandExecution(err));
            }
        }
        Ok(())
    }
}

fn create_secure_pipe(name: &str) -> Result<HANDLE> {
    let name_u16 = to_u16_null_terminated(name);
    // SDDL: D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)
    // SY: Local System
    // BA: Built-in Administrators
    // OW: Owner Rights
    let sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)";
    let sddl_u16 = to_u16_null_terminated(sddl);

    let mut security_descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 0,
    };

    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_u16.as_ptr(),
            SDDL_REVISION_1,
            &mut security_descriptor,
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(NonoError::Setup(format!(
                "Failed to convert SDDL: {}",
                std::io::Error::last_os_error()
            )));
        }
        sa.lpSecurityDescriptor = security_descriptor;

        let h_pipe = CreateNamedPipeW(
            name_u16.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            1024,
            1024,
            0,
            &sa,
        );

        LocalFree(security_descriptor as _);

        if h_pipe == INVALID_HANDLE_VALUE {
            return Err(NonoError::Setup(format!(
                "Failed to create named pipe {}: {}",
                name,
                std::io::Error::last_os_error()
            )));
        }

        Ok(h_pipe)
    }
}

#[derive(Debug)]
pub(super) struct WindowsSupervisorRuntime {
    session_id: String,
    requested_features: Vec<String>,
    transport_name: String,
    _parent_control: nono::SupervisorSocket,
    child_control: Option<nono::SupervisorSocket>,
    started_at: Instant,
    pub(super) state: WindowsSupervisorLifecycleState,
    audit_log: Vec<AuditEntry>,
    terminate_requested: Arc<AtomicBool>,
    pty: Option<crate::pty_proxy::PtyPair>,
    active_attachment: Arc<Mutex<Option<SendableHandle>>>,
    interactive_shell: bool,
}

impl WindowsSupervisorRuntime {
    pub(super) fn initialize(
        supervisor: &SupervisorConfig<'_>,
        pty: Option<crate::pty_proxy::PtyPair>,
    ) -> Result<Self> {
        let started_at = Instant::now();
        let (parent_control, child_control) = initialize_supervisor_control_channel()?;
        let transport_name = parent_control.transport_name().to_string();
        let terminate_requested = Arc::new(AtomicBool::new(false));
        let active_attachment = Arc::new(Mutex::new(None));

        let mut runtime = Self {
            session_id: supervisor.session_id.to_string(),
            requested_features: supervisor
                .requested_features
                .iter()
                .map(|feature| (*feature).to_string())
                .collect(),
            transport_name,
            _parent_control: parent_control,
            child_control: Some(child_control),
            started_at,
            state: WindowsSupervisorLifecycleState::Initializing,
            audit_log: Vec::new(),
            terminate_requested,
            pty,
            active_attachment,
            interactive_shell: supervisor.interactive_shell,
        };

        runtime.start_control_pipe_server()?;
        if runtime.interactive_shell {
            runtime.start_interactive_terminal_io()?;
        } else {
            runtime.start_logging()?;
            runtime.start_data_pipe_server()?;
        }

        runtime.state = WindowsSupervisorLifecycleState::ControlChannelReady;
        Ok(runtime)
    }

    fn start_logging(&self) -> Result<()> {
        let session_id = self.session_id.clone();
        let pty_output_read = self
            .pty
            .as_ref()
            .map(|p| p.output_read as usize)
            .unwrap_or(0);
        let active_attachment = self.active_attachment.clone();

        if pty_output_read == 0 {
            return Ok(());
        }

        std::thread::spawn(move || {
            let log_path = match crate::session::session_log_path(&session_id) {
                Ok(path) => path,
                Err(e) => {
                    tracing::error!(
                        "Failed to resolve log path for session {}: {}",
                        session_id,
                        e
                    );
                    return;
                }
            };

            let mut log_file = match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
            {
                Ok(file) => file,
                Err(e) => {
                    tracing::error!("Failed to open log file {}: {}", log_path.display(), e);
                    return;
                }
            };

            let mut pty_file =
                ManuallyDrop::new(unsafe { std::fs::File::from_raw_handle(pty_output_read as _) });

            let mut buf = [0u8; 4096];
            while let Ok(n) = pty_file.read(&mut buf) {
                if n == 0 {
                    break;
                }

                // Write to log file
                let _ = log_file.write_all(&buf[..n]);
                let _ = log_file.flush();

                // On Windows, writing to a named pipe that has no listener will block
                // if we try to write to it directly. We use a shared handle for the active attachment.
                let attachment_handle = {
                    let lock = active_attachment.lock().unwrap_or_else(|p| p.into_inner());
                    *lock
                };

                if let Some(sendable) = attachment_handle {
                    let mut written = 0;
                    // SAFETY: sendable.0 is a valid named pipe handle while it's in active_attachment.
                    // We use the raw Win32 WriteFile to avoid taking ownership or blocking too long.
                    unsafe {
                        windows_sys::Win32::Storage::FileSystem::WriteFile(
                            sendable.0,
                            buf.as_ptr(),
                            n as u32,
                            &mut written,
                            std::ptr::null_mut(),
                        );
                    }
                }
            }
        });

        Ok(())
    }

    fn start_control_pipe_server(&self) -> Result<()> {
        let session_id = self.session_id.clone();
        let terminate_requested = self.terminate_requested.clone();
        let active_attachment = self.active_attachment.clone();

        std::thread::spawn(move || {
            let pipe_name = format!("\\\\.\\pipe\\nono-session-{}", session_id);
            let h_pipe = match create_secure_pipe(&pipe_name) {
                Ok(h) => h,
                Err(e) => {
                    tracing::error!("Failed to create supervisor control pipe: {}", e);
                    return;
                }
            };

            loop {
                let connected = unsafe { ConnectNamedPipe(h_pipe, std::ptr::null_mut()) };
                if connected != 0
                    || unsafe { GetLastError() }
                        == windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED
                {
                    // Use a synchronous file wrapper for simplicity in the background thread
                    let mut file = unsafe { std::fs::File::from_raw_handle(h_pipe as _) };

                    // Simple length-prefixed JSON reader (same as nono::SupervisorSocket)
                    let mut len_buf = [0u8; 4];
                    if file.read_exact(&mut len_buf).is_ok() {
                        let len = u32::from_be_bytes(len_buf);
                        if len < 4096 {
                            let mut body = vec![0u8; len as usize];
                            if file.read_exact(&mut body).is_ok() {
                                if let Ok(msg) = serde_json::from_slice::<
                                    nono::supervisor::SupervisorMessage,
                                >(&body)
                                {
                                    match msg {
                                        nono::supervisor::SupervisorMessage::Terminate {
                                            session_id: msg_session_id,
                                        } => {
                                            if msg_session_id == session_id {
                                                tracing::info!("Terminate requested via control pipe for session {}", session_id);
                                                terminate_requested.store(true, Ordering::SeqCst);
                                                break;
                                            }
                                        }
                                        nono::supervisor::SupervisorMessage::Detach {
                                            session_id: msg_session_id,
                                        } => {
                                            if msg_session_id == session_id {
                                                tracing::info!("Detach requested via control pipe for session {}", session_id);
                                                let mut lock = active_attachment
                                                    .lock()
                                                    .unwrap_or_else(|p| p.into_inner());
                                                if let Some(sendable) = lock.take() {
                                                    unsafe {
                                                        DisconnectNamedPipe(sendable.0);
                                                    }
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }

                    unsafe { DisconnectNamedPipe(h_pipe) };
                    // If we're terminating, exit the loop
                    if terminate_requested.load(Ordering::SeqCst) {
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    fn start_interactive_terminal_io(&self) -> Result<()> {
        let pty = self.pty.as_ref().ok_or_else(|| {
            NonoError::SandboxInit(
                "interactive_shell requires a PTY pair but none was provided".to_string(),
            )
        })?;

        let session_id = self.session_id.clone();
        let output_read = pty.output_read as usize;
        let input_write = pty.input_write as usize;
        let hpcon = pty.hpcon;

        unsafe extern "system" fn ctrl_handler(ctrl_type: u32) -> BOOL {
            if ctrl_type == CTRL_C_EVENT {
                1
            } else {
                0
            }
        }

        unsafe {
            // SAFETY: `ctrl_handler` has the correct ABI and remains valid for
            // the process lifetime.
            SetConsoleCtrlHandler(Some(ctrl_handler), 1);
        }

        {
            let output_session_id = session_id.clone();
            std::thread::spawn(move || {
                let log_path = crate::session::session_log_path(&output_session_id).ok();
                let mut log_file = log_path.and_then(|path| {
                    std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(path)
                        .ok()
                });

                let mut pty_out = ManuallyDrop::new(unsafe {
                    // SAFETY: `output_read` is owned by the PTY pair; ManuallyDrop
                    // avoids double-closing the handle.
                    std::fs::File::from_raw_handle(output_read as _)
                });
                let mut stdout = std::io::stdout();
                let mut buf = [0u8; 4096];

                while let Ok(n) = pty_out.read(&mut buf) {
                    if n == 0 {
                        break;
                    }

                    let _ = stdout.write_all(&buf[..n]);
                    let _ = stdout.flush();
                    if let Some(ref mut file) = log_file {
                        let _ = file.write_all(&buf[..n]);
                    }
                }
            });
        }

        {
            std::thread::spawn(move || {
                let mut pty_in = ManuallyDrop::new(unsafe {
                    // SAFETY: `input_write` is owned by the PTY pair; ManuallyDrop
                    // avoids double-closing the handle.
                    std::fs::File::from_raw_handle(input_write as _)
                });
                let mut stdin = std::io::stdin();
                let mut buf = [0u8; 4096];

                loop {
                    match stdin.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if pty_in.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }

        {
            std::thread::spawn(move || {
                let h_stdout = unsafe {
                    // SAFETY: GetStdHandle returns either a valid handle or an
                    // invalid sentinel, which we check before use.
                    GetStdHandle(STD_OUTPUT_HANDLE)
                };
                if h_stdout.is_null() || h_stdout == INVALID_HANDLE_VALUE {
                    return;
                }

                let mut last_size = COORD { X: 0, Y: 0 };

                loop {
                    std::thread::sleep(std::time::Duration::from_millis(100));

                    let mut info: CONSOLE_SCREEN_BUFFER_INFO = unsafe {
                        // SAFETY: CONSOLE_SCREEN_BUFFER_INFO is a plain Win32 FFI
                        // struct; zero-init is valid.
                        std::mem::zeroed()
                    };
                    let ok = unsafe {
                        // SAFETY: `h_stdout` is a live console handle after the
                        // sentinel checks above.
                        GetConsoleScreenBufferInfo(h_stdout, &mut info)
                    };
                    if ok == 0 {
                        break;
                    }

                    let cols = info.srWindow.Right - info.srWindow.Left + 1;
                    let rows = info.srWindow.Bottom - info.srWindow.Top + 1;
                    let new_size = COORD { X: cols, Y: rows };

                    if new_size.X != last_size.X || new_size.Y != last_size.Y {
                        last_size = new_size;
                        unsafe {
                            // SAFETY: `hpcon` belongs to the live PTY pair and
                            // remains valid for the lifetime of this thread.
                            let _ = ResizePseudoConsole(hpcon, new_size);
                        }
                    }
                }
            });
        }

        Ok(())
    }

    fn start_data_pipe_server(&self) -> Result<()> {
        let session_id = self.session_id.clone();
        let pty_output_read = self
            .pty
            .as_ref()
            .map(|p| p.output_read as usize)
            .unwrap_or(0);
        let pty_input_write = self
            .pty
            .as_ref()
            .map(|p| p.input_write as usize)
            .unwrap_or(0);
        let active_attachment = self.active_attachment.clone();

        if pty_output_read == 0 || pty_input_write == 0 {
            return Ok(());
        }

        std::thread::spawn(move || {
            let pipe_name = format!("\\\\.\\pipe\\nono-data-{}", session_id);
            let h_pipe = match create_secure_pipe(&pipe_name) {
                Ok(h) => h,
                Err(e) => {
                    tracing::error!("Failed to create supervisor data pipe: {}", e);
                    return;
                }
            };

            loop {
                let connected = unsafe { ConnectNamedPipe(h_pipe, std::ptr::null_mut()) };
                if connected != 0
                    || unsafe { GetLastError() }
                        == windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED
                {
                    {
                        let mut lock = active_attachment.lock().unwrap_or_else(|p| p.into_inner());
                        *lock = Some(SendableHandle(h_pipe));
                    }

                    // For input, we read from the pipe and write to PTY input.
                    // This thread will block on pipe reading while the client is attached.
                    let mut file = unsafe { std::fs::File::from_raw_handle(h_pipe as _) };
                    let mut pty_input = ManuallyDrop::new(unsafe {
                        std::fs::File::from_raw_handle(pty_input_write as _)
                    });

                    let mut buf = [0u8; 4096];
                    while let Ok(n) = file.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        if pty_input.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }

                    {
                        let mut lock = active_attachment.lock().unwrap_or_else(|p| p.into_inner());
                        if let Some(sendable) = *lock {
                            if sendable.0 == h_pipe {
                                *lock = None;
                            }
                        }
                    }
                    unsafe { DisconnectNamedPipe(h_pipe) };
                }
            }
        });

        Ok(())
    }

    pub(super) fn transport_name(&self) -> &str {
        self.transport_name.as_str()
    }

    pub(super) fn run_child_event_loop(
        &mut self,
        child: &mut WindowsSupervisedChild,
    ) -> Result<i32> {
        self.state = WindowsSupervisorLifecycleState::WaitingForChild;
        tracing::debug!(
            "Windows supervisor event loop entering wait phase (session: {}, transport: {}, state: {}, features: {})",
            self.session_id,
            self.transport_name,
            self.state.label(),
            if self.requested_features.is_empty() {
                "none".to_string()
            } else {
                self.requested_features.join(", ")
            }
        );

        loop {
            if self.terminate_requested.load(Ordering::SeqCst) {
                tracing::info!(
                    "Windows supervisor received termination request, stopping child..."
                );
                child.terminate()?;
                return Ok(-1);
            }

            if let Some(exit_code) = child.wait_for_exit(100)? {
                self.state = WindowsSupervisorLifecycleState::ShuttingDown;
                self.shutdown();
                self.state = WindowsSupervisorLifecycleState::Completed;
                tracing::debug!(
                    "Windows supervisor event loop completed (session: {}, transport: {}, exit_code: {}, elapsed_ms: {})",
                    self.session_id,
                    self.transport_name,
                    exit_code,
                    self.started_at.elapsed().as_millis()
                );
                return Ok(exit_code);
            }
        }
    }

    pub(super) fn startup_failure(&mut self, message: String) -> NonoError {
        self.shutdown();
        NonoError::SandboxInit(format!(
            "Windows supervised execution failed during {} (session: {}, transport: {}, supervisor_audit_entries: {}): {}",
            self.state.label(),
            self.session_id,
            self.transport_name,
            self.audit_log.len(),
            message
        ))
    }

    pub(super) fn command_failure(&mut self, message: String) -> NonoError {
        self.shutdown();
        NonoError::CommandExecution(std::io::Error::other(format!(
            "Windows supervised execution failed during {} (session: {}, transport: {}, supervisor_audit_entries: {}): {}",
            self.state.label(),
            self.session_id,
            self.transport_name,
            self.audit_log.len(),
            message
        )))
    }

    pub(super) fn shutdown(&mut self) {
        let _ = self.child_control.take();
        self.state = WindowsSupervisorLifecycleState::ShuttingDown;
    }

    pub(super) fn pty(&self) -> Option<&crate::pty_proxy::PtyPair> {
        self.pty.as_ref()
    }
}

impl Drop for WindowsSupervisorRuntime {
    fn drop(&mut self) {
        if self.state != WindowsSupervisorLifecycleState::Completed {
            self.shutdown();
        }
    }
}

pub(super) fn initialize_supervisor_control_channel(
) -> Result<(nono::SupervisorSocket, nono::SupervisorSocket)> {
    nono::SupervisorSocket::pair().map_err(|e| {
        NonoError::SandboxInit(format!(
            "Failed to initialize Windows supervisor control channel: {e}"
        ))
    })
}

#[cfg(test)]
pub(super) fn open_windows_supervisor_path(
    path: &Path,
    access: &nono::AccessMode,
) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    match access {
        nono::AccessMode::Read => {
            options.read(true);
        }
        nono::AccessMode::Write => {
            options.write(true);
        }
        nono::AccessMode::ReadWrite => {
            options.read(true).write(true);
        }
    }

    options.open(path).map_err(|e| {
        NonoError::SandboxInit(format!(
            "Windows supervisor failed to open approved path {}: {}",
            path.display(),
            e
        ))
    })
}

#[cfg(test)]
pub(super) fn handle_windows_supervisor_message(
    sock: &mut nono::SupervisorSocket,
    msg: nono::supervisor::SupervisorMessage,
    approval_backend: &dyn ApprovalBackend,
    target_process: nono::BrokerTargetProcess,
    seen_request_ids: &mut HashSet<String>,
    audit_log: &mut Vec<AuditEntry>,
) -> Result<()> {
    match msg {
        nono::supervisor::SupervisorMessage::Request(request) => {
            let started_at = Instant::now();
            if seen_request_ids.contains(&request.request_id) {
                let decision = nono::ApprovalDecision::Denied {
                    reason: "Duplicate request_id rejected (replay detected)".to_string(),
                };
                audit_log.push(AuditEntry {
                    timestamp: SystemTime::now(),
                    request: request.clone(),
                    decision: decision.clone(),
                    backend: approval_backend.backend_name().to_string(),
                    duration_ms: started_at.elapsed().as_millis() as u64,
                });
                return sock.send_response(&nono::supervisor::SupervisorResponse::Decision {
                    request_id: request.request_id,
                    decision,
                    grant: None,
                });
            }
            seen_request_ids.insert(request.request_id.clone());

            let decision = approval_backend
                .request_capability(&request)
                .unwrap_or_else(|e| nono::ApprovalDecision::Denied {
                    reason: format!("Approval backend error: {e}"),
                });

            let grant = if decision.is_granted() {
                let file = open_windows_supervisor_path(&request.path, &request.access)?;
                Some(nono::supervisor::socket::broker_file_handle_to_process(
                    &file,
                    target_process,
                    request.access,
                )?)
            } else {
                None
            };

            audit_log.push(AuditEntry {
                timestamp: SystemTime::now(),
                request: request.clone(),
                decision: decision.clone(),
                backend: approval_backend.backend_name().to_string(),
                duration_ms: started_at.elapsed().as_millis() as u64,
            });

            sock.send_response(&nono::supervisor::SupervisorResponse::Decision {
                request_id: request.request_id,
                decision,
                grant,
            })
        }
        nono::supervisor::SupervisorMessage::OpenUrl(url_request) => sock
            .send_response(&nono::supervisor::SupervisorResponse::UrlOpened {
            request_id: url_request.request_id,
            success: false,
            error: Some(
                "Windows delegated browser-open flows are not available yet. Windows supervised child processes do not have an attached supervisor control channel for open-url requests."
                    .to_string(),
            ),
        }),
        nono::supervisor::SupervisorMessage::Terminate { .. } => {
            // CLI-to-supervisor termination is handled via the background control pipe thread,
            // not via the child-to-supervisor socket. We ignore it here.
            Ok(())
        }
        nono::supervisor::SupervisorMessage::Detach { .. } => {
            // Detach is handled via the background control pipe thread, not here.
            Ok(())
        }
    }
}
