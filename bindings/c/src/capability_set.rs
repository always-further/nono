//! FFI wrapper for `nono::CapabilitySet`.

use std::os::raw::c_char;

use crate::types::{validate_access_mode, NonoErrorCode};
use crate::{c_str_to_str, map_error, rust_string_to_c, set_last_error};

/// Opaque handle to a capability set.
///
/// Created with `nono_capability_set_new()`.
/// Freed with `nono_capability_set_free()`.
pub struct NonoCapabilitySet {
    pub(crate) inner: nono::CapabilitySet,
}

impl Default for NonoCapabilitySet {
    fn default() -> Self {
        Self {
            inner: nono::CapabilitySet::new(),
        }
    }
}

/// Create a new empty capability set.
///
/// The returned pointer is never NULL. Caller must free with
/// `nono_capability_set_free()`.
#[no_mangle]
pub extern "C" fn nono_capability_set_new() -> *mut NonoCapabilitySet {
    Box::into_raw(Box::new(NonoCapabilitySet::default()))
}

/// Free a capability set.
///
/// NULL-safe (no-op on NULL).
///
/// # Safety
///
/// `caps` must be NULL or a pointer previously returned by
/// `nono_capability_set_new()` or a factory function.
#[no_mangle]
pub unsafe extern "C" fn nono_capability_set_free(caps: *mut NonoCapabilitySet) {
    if !caps.is_null() {
        // SAFETY: The pointer was created by Box::into_raw() in
        // nono_capability_set_new() or a factory function in this library.
        unsafe {
            drop(Box::from_raw(caps));
        }
    }
}

/// Add directory access permission.
///
/// The path is validated and canonicalized. Returns `Ok` on success.
/// On failure, returns a negative error code; call `nono_last_error()`
/// for the detailed message.
///
/// # Safety
///
/// - `caps` must be a valid pointer from `nono_capability_set_new()`.
/// - `path` must be a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn nono_capability_set_allow_path(
    caps: *mut NonoCapabilitySet,
    path: *const c_char,
    mode: u32,
) -> NonoErrorCode {
    if caps.is_null() {
        set_last_error("caps pointer is NULL");
        return NonoErrorCode::ErrInvalidArg;
    }

    let access = match validate_access_mode(mode) {
        Some(m) => m,
        None => {
            set_last_error(&format!("invalid access mode: {mode}"));
            return NonoErrorCode::ErrInvalidArg;
        }
    };

    // SAFETY: caller guarantees caps is valid.
    let caps = unsafe { &mut *caps };

    let path_str = match unsafe { c_str_to_str(path) } {
        Some(s) => s,
        None => {
            set_last_error("path is NULL or invalid UTF-8");
            return NonoErrorCode::ErrInvalidArg;
        }
    };

    match nono::FsCapability::new_dir(path_str, access) {
        Ok(cap) => {
            caps.inner.add_fs(cap);
            NonoErrorCode::Ok
        }
        Err(e) => map_error(&e),
    }
}

/// Add single-file access permission.
///
/// The path is validated and canonicalized. Returns `Ok` on success.
///
/// # Safety
///
/// - `caps` must be a valid pointer from `nono_capability_set_new()`.
/// - `path` must be a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn nono_capability_set_allow_file(
    caps: *mut NonoCapabilitySet,
    path: *const c_char,
    mode: u32,
) -> NonoErrorCode {
    if caps.is_null() {
        set_last_error("caps pointer is NULL");
        return NonoErrorCode::ErrInvalidArg;
    }

    let access = match validate_access_mode(mode) {
        Some(m) => m,
        None => {
            set_last_error(&format!("invalid access mode: {mode}"));
            return NonoErrorCode::ErrInvalidArg;
        }
    };

    let caps = unsafe { &mut *caps };

    let path_str = match unsafe { c_str_to_str(path) } {
        Some(s) => s,
        None => {
            set_last_error("path is NULL or invalid UTF-8");
            return NonoErrorCode::ErrInvalidArg;
        }
    };

    match nono::FsCapability::new_file(path_str, access) {
        Ok(cap) => {
            caps.inner.add_fs(cap);
            NonoErrorCode::Ok
        }
        Err(e) => map_error(&e),
    }
}

/// Set whether outbound network access is blocked.
///
/// # Safety
///
/// `caps` must be a valid pointer from `nono_capability_set_new()`.
#[no_mangle]
pub unsafe extern "C" fn nono_capability_set_set_network_blocked(
    caps: *mut NonoCapabilitySet,
    blocked: bool,
) {
    if caps.is_null() {
        return;
    }
    let caps = unsafe { &mut *caps };
    caps.inner.set_network_blocked(blocked);
}

/// Add a command to the allow list (overrides block lists).
///
/// # Safety
///
/// - `caps` must be a valid pointer.
/// - `cmd` must be a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn nono_capability_set_allow_command(
    caps: *mut NonoCapabilitySet,
    cmd: *const c_char,
) -> NonoErrorCode {
    if caps.is_null() {
        set_last_error("caps pointer is NULL");
        return NonoErrorCode::ErrInvalidArg;
    }
    let caps = unsafe { &mut *caps };

    let cmd_str = match unsafe { c_str_to_str(cmd) } {
        Some(s) => s,
        None => {
            set_last_error("cmd is NULL or invalid UTF-8");
            return NonoErrorCode::ErrInvalidArg;
        }
    };

    caps.inner.add_allowed_command(cmd_str);
    NonoErrorCode::Ok
}

/// Add a command to the block list.
///
/// # Safety
///
/// - `caps` must be a valid pointer.
/// - `cmd` must be a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn nono_capability_set_block_command(
    caps: *mut NonoCapabilitySet,
    cmd: *const c_char,
) -> NonoErrorCode {
    if caps.is_null() {
        set_last_error("caps pointer is NULL");
        return NonoErrorCode::ErrInvalidArg;
    }
    let caps = unsafe { &mut *caps };

    let cmd_str = match unsafe { c_str_to_str(cmd) } {
        Some(s) => s,
        None => {
            set_last_error("cmd is NULL or invalid UTF-8");
            return NonoErrorCode::ErrInvalidArg;
        }
    };

    caps.inner.add_blocked_command(cmd_str);
    NonoErrorCode::Ok
}

/// Add a raw platform-specific sandbox rule.
///
/// On macOS this is a Seatbelt S-expression. On Linux it is ignored.
/// Returns `Ok` on success or a negative error code if the rule is
/// malformed or grants root-level access.
///
/// # Safety
///
/// - `caps` must be a valid pointer.
/// - `rule` must be a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn nono_capability_set_add_platform_rule(
    caps: *mut NonoCapabilitySet,
    rule: *const c_char,
) -> NonoErrorCode {
    if caps.is_null() {
        set_last_error("caps pointer is NULL");
        return NonoErrorCode::ErrInvalidArg;
    }
    let caps = unsafe { &mut *caps };

    let rule_str = match unsafe { c_str_to_str(rule) } {
        Some(s) => s,
        None => {
            set_last_error("rule is NULL or invalid UTF-8");
            return NonoErrorCode::ErrInvalidArg;
        }
    };

    match caps.inner.add_platform_rule(rule_str) {
        Ok(()) => NonoErrorCode::Ok,
        Err(e) => map_error(&e),
    }
}

/// Deduplicate filesystem capabilities, keeping the highest access level.
///
/// # Safety
///
/// `caps` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn nono_capability_set_deduplicate(caps: *mut NonoCapabilitySet) {
    if caps.is_null() {
        return;
    }
    let caps = unsafe { &mut *caps };
    caps.inner.deduplicate();
}

/// Check if a path is covered by an existing directory capability.
///
/// Returns `false` if `caps` or `path` is NULL.
///
/// # Safety
///
/// - `caps` must be a valid pointer or NULL.
/// - `path` must be a valid null-terminated UTF-8 string or NULL.
#[no_mangle]
pub unsafe extern "C" fn nono_capability_set_path_covered(
    caps: *const NonoCapabilitySet,
    path: *const c_char,
) -> bool {
    if caps.is_null() {
        return false;
    }
    let caps = unsafe { &*caps };

    let path_str = match unsafe { c_str_to_str(path) } {
        Some(s) => s,
        None => return false,
    };

    caps.inner.path_covered(std::path::Path::new(path_str))
}

/// Check if outbound network access is blocked.
///
/// Returns `false` if `caps` is NULL.
///
/// # Safety
///
/// `caps` must be a valid pointer or NULL.
#[no_mangle]
pub unsafe extern "C" fn nono_capability_set_is_network_blocked(
    caps: *const NonoCapabilitySet,
) -> bool {
    if caps.is_null() {
        return false;
    }
    let caps = unsafe { &*caps };
    caps.inner.is_network_blocked()
}

/// Get a plain-text summary of the capability set.
///
/// Caller must free the returned string with `nono_string_free()`.
/// Returns NULL if `caps` is NULL.
///
/// # Safety
///
/// `caps` must be a valid pointer or NULL.
#[no_mangle]
pub unsafe extern "C" fn nono_capability_set_summary(
    caps: *const NonoCapabilitySet,
) -> *mut c_char {
    if caps.is_null() {
        return std::ptr::null_mut();
    }
    let caps = unsafe { &*caps };
    rust_string_to_c(caps.inner.summary())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_capability_set_lifecycle() {
        let caps = nono_capability_set_new();
        assert!(!caps.is_null());
        // SAFETY: caps was just created.
        unsafe { nono_capability_set_free(caps) };
    }

    #[test]
    fn test_free_null_safe() {
        // SAFETY: deliberate NULL.
        unsafe { nono_capability_set_free(std::ptr::null_mut()) };
    }

    #[test]
    fn test_network_blocking() {
        let caps = nono_capability_set_new();
        // SAFETY: caps is valid.
        unsafe {
            assert!(!nono_capability_set_is_network_blocked(caps));
            nono_capability_set_set_network_blocked(caps, true);
            assert!(nono_capability_set_is_network_blocked(caps));
            nono_capability_set_set_network_blocked(caps, false);
            assert!(!nono_capability_set_is_network_blocked(caps));
            nono_capability_set_free(caps);
        }
    }

    #[test]
    fn test_allow_path_valid() {
        let caps = nono_capability_set_new();
        let path = CString::new("/tmp").unwrap_or_default();
        // SAFETY: caps and path are valid.
        unsafe {
            let rc = nono_capability_set_allow_path(
                caps,
                path.as_ptr(),
                crate::types::NONO_ACCESS_MODE_READ,
            );
            assert_eq!(rc, NonoErrorCode::Ok);
            nono_capability_set_free(caps);
        }
    }

    #[test]
    fn test_allow_path_nonexistent() {
        let caps = nono_capability_set_new();
        let path = CString::new("/nonexistent_path_abc123_xyz").unwrap_or_default();
        // SAFETY: caps and path are valid.
        unsafe {
            let rc = nono_capability_set_allow_path(
                caps,
                path.as_ptr(),
                crate::types::NONO_ACCESS_MODE_READ,
            );
            assert_ne!(rc, NonoErrorCode::Ok);

            let err = crate::nono_last_error();
            assert!(!err.is_null());
            crate::nono_string_free(err);
            nono_capability_set_free(caps);
        }
    }

    #[test]
    fn test_allow_path_null_caps() {
        let path = CString::new("/tmp").unwrap_or_default();
        // SAFETY: deliberately passing NULL.
        unsafe {
            let rc = nono_capability_set_allow_path(
                std::ptr::null_mut(),
                path.as_ptr(),
                crate::types::NONO_ACCESS_MODE_READ,
            );
            assert_eq!(rc, NonoErrorCode::ErrInvalidArg);
        }
    }

    #[test]
    fn test_allow_path_null_path() {
        let caps = nono_capability_set_new();
        // SAFETY: caps is valid, path is NULL.
        unsafe {
            let rc = nono_capability_set_allow_path(
                caps,
                std::ptr::null(),
                crate::types::NONO_ACCESS_MODE_READ,
            );
            assert_eq!(rc, NonoErrorCode::ErrInvalidArg);
            nono_capability_set_free(caps);
        }
    }

    #[test]
    fn test_allow_path_invalid_mode() {
        let caps = nono_capability_set_new();
        let path = CString::new("/tmp").unwrap_or_default();
        // SAFETY: caps and path are valid, mode is intentionally invalid.
        unsafe {
            let rc = nono_capability_set_allow_path(caps, path.as_ptr(), 42);
            assert_eq!(rc, NonoErrorCode::ErrInvalidArg);
            nono_capability_set_free(caps);
        }
    }

    #[test]
    fn test_summary() {
        let caps = nono_capability_set_new();
        // SAFETY: caps is valid.
        unsafe {
            let summary = nono_capability_set_summary(caps);
            assert!(!summary.is_null());
            crate::nono_string_free(summary);
            nono_capability_set_free(caps);
        }
    }

    #[test]
    fn test_summary_null_safe() {
        // SAFETY: deliberately passing NULL.
        unsafe {
            let summary = nono_capability_set_summary(std::ptr::null());
            assert!(summary.is_null());
        }
    }

    #[test]
    fn test_commands() {
        let caps = nono_capability_set_new();
        let cmd = CString::new("rm").unwrap_or_default();
        // SAFETY: caps and cmd are valid.
        unsafe {
            let rc = nono_capability_set_block_command(caps, cmd.as_ptr());
            assert_eq!(rc, NonoErrorCode::Ok);
            let rc = nono_capability_set_allow_command(caps, cmd.as_ptr());
            assert_eq!(rc, NonoErrorCode::Ok);
            nono_capability_set_free(caps);
        }
    }
}
