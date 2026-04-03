#![allow(dead_code)]

use nono::{NonoError, Result};
use std::path::Path;

pub struct PtyPair;

pub struct PtyProxy;

impl PtyProxy {
    pub fn poll_fds(&self) -> (i32, i32) {
        (-1, -1)
    }
}

pub fn open_pty() -> Result<PtyPair> {
    Err(NonoError::UnsupportedPlatform(
        "Windows PTY detach/attach sessions are not available yet.".to_string(),
    ))
}

pub fn setup_child_pty(_slave_fd: i32) {}

pub fn write_detach_terminal_reset(_fd: i32) {}

pub fn write_detach_notice(_fd: i32) {}

pub fn request_session_detach(_session_id: &str) -> Result<()> {
    Err(NonoError::UnsupportedPlatform(
        "Windows detached runtime sessions are not available yet.".to_string(),
    ))
}

pub fn attach_to_session(_session_id: &str) -> Result<()> {
    Err(NonoError::UnsupportedPlatform(
        "Windows detached runtime sessions are not available yet.".to_string(),
    ))
}

pub fn connect_to_session(_session_id: &str) -> Result<()> {
    Err(NonoError::UnsupportedPlatform(
        "Windows detached runtime sessions are not available yet.".to_string(),
    ))
}

pub fn wait_for_attach_ready(_sock_fd: i32, _timeout_ms: i32) -> Result<()> {
    Err(NonoError::UnsupportedPlatform(
        "Windows detached runtime sessions are not available yet.".to_string(),
    ))
}

pub fn attach_to_stream<T>(_stream: T) -> Result<()> {
    Err(NonoError::UnsupportedPlatform(
        "Windows detached runtime sessions are not available yet.".to_string(),
    ))
}

pub fn remove_stale_attach_socket(_attach_path: &Path) -> Result<()> {
    Ok(())
}
