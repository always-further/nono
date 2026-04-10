#![allow(dead_code)]

use nono::{NonoError, Result};
use std::path::Path;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::Console::{ClosePseudoConsole, CreatePseudoConsole, COORD, HPCON};
use windows_sys::Win32::System::Pipes::CreatePipe;

#[derive(Debug)]
pub struct PtyPair {
    pub hpcon: HPCON,
    pub input_write: HANDLE,
    pub output_read: HANDLE,
}

impl Drop for PtyPair {
    fn drop(&mut self) {
        unsafe {
            if self.hpcon != 0 {
                ClosePseudoConsole(self.hpcon);
            }
            if self.input_write != INVALID_HANDLE_VALUE {
                CloseHandle(self.input_write);
            }
            if self.output_read != INVALID_HANDLE_VALUE {
                CloseHandle(self.output_read);
            }
        }
    }
}

pub struct PtyProxy;

impl PtyProxy {
    pub fn poll_fds(&self) -> (i32, i32) {
        (-1, -1)
    }
}

pub fn open_pty() -> Result<PtyPair> {
    let mut h_input_read: HANDLE = INVALID_HANDLE_VALUE;
    let mut h_input_write: HANDLE = INVALID_HANDLE_VALUE;
    let mut h_output_read: HANDLE = INVALID_HANDLE_VALUE;
    let mut h_output_write: HANDLE = INVALID_HANDLE_VALUE;

    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 0, // Do NOT inherit
    };

    unsafe {
        if CreatePipe(&mut h_input_read, &mut h_input_write, &sa, 0) == 0 {
            return Err(NonoError::Setup("Failed to create input pipe".to_string()));
        }
        if CreatePipe(&mut h_output_read, &mut h_output_write, &sa, 0) == 0 {
            CloseHandle(h_input_read);
            CloseHandle(h_input_write);
            return Err(NonoError::Setup("Failed to create output pipe".to_string()));
        }

        let mut hpcon: HPCON = 0;
        let size = COORD { X: 80, Y: 24 };
        let hr = CreatePseudoConsole(size, h_input_read, h_output_write, 0, &mut hpcon);

        // After CreatePseudoConsole returns, the caller may close the handles passed to it
        // as the PseudoConsole maintains its own references.
        CloseHandle(h_input_read);
        CloseHandle(h_output_write);

        if hr != 0 {
            CloseHandle(h_input_write);
            CloseHandle(h_output_read);
            return Err(NonoError::Setup(format!(
                "CreatePseudoConsole failed with HRESULT 0x{:X}",
                hr
            )));
        }

        Ok(PtyPair {
            hpcon,
            input_write: h_input_write,
            output_read: h_output_read,
        })
    }
}

pub fn close_pseudo_console(hpcon: HPCON) {
    unsafe {
        ClosePseudoConsole(hpcon);
    }
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
