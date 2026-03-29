use crate::cli::OpenUrlHelperArgs;
use nono::supervisor::types::{SupervisorMessage, SupervisorResponse};
use nono::supervisor::{SupervisorSocket, UrlOpenRequest};
use nono::{NonoError, Result};
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;

/// Internal helper invoked via BROWSER env var (Linux) or PATH shim (macOS).
///
/// Reads the supervisor socket fd from `NONO_SUPERVISOR_FD`, sends an
/// `OpenUrl` IPC message, waits for the response, and exits with the
/// appropriate exit code.
pub(crate) fn run_open_url_helper(args: OpenUrlHelperArgs) -> Result<()> {
    let fd_str = std::env::var("NONO_SUPERVISOR_FD").map_err(|_| {
        NonoError::SandboxInit(
            "NONO_SUPERVISOR_FD not set. open-url-helper must be invoked inside a nono sandbox."
                .to_string(),
        )
    })?;

    let fd: i32 = fd_str.parse().map_err(|_| {
        NonoError::SandboxInit(format!("Invalid NONO_SUPERVISOR_FD value: {fd_str}"))
    })?;

    // SAFETY: The fd was inherited from the parent process via fork+exec.
    // It is a valid Unix domain socket created by the supervisor.
    let stream = unsafe { UnixStream::from(std::os::unix::io::OwnedFd::from_raw_fd(fd)) };
    let mut socket = SupervisorSocket::from_stream(stream);

    let request = UrlOpenRequest {
        request_id: format!("url-{}", std::process::id()),
        url: args.url.clone(),
        child_pid: std::process::id(),
        session_id: String::new(),
    };

    socket.send_message(&SupervisorMessage::OpenUrl(request))?;

    let response = socket.recv_response()?;
    match response {
        SupervisorResponse::UrlOpened { success: true, .. } => Ok(()),
        SupervisorResponse::UrlOpened {
            success: false,
            error,
            ..
        } => {
            let msg = error.unwrap_or_else(|| "Unknown error".to_string());
            Err(NonoError::SandboxInit(format!(
                "Supervisor denied URL open: {msg}"
            )))
        }
        other => Err(NonoError::SandboxInit(format!(
            "Unexpected supervisor response: {other:?}"
        ))),
    }
}
