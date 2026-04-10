use super::*;
use uuid::Uuid;
use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
use windows_sys::Win32::Security::{
    CreateRestrictedToken, SID_AND_ATTRIBUTES, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY,
};

pub(super) struct RestrictedToken {
    pub h_token: HANDLE,
}

impl Drop for RestrictedToken {
    fn drop(&mut self) {
        if !self.h_token.is_null() {
            unsafe { CloseHandle(self.h_token) };
        }
    }
}

pub(crate) fn generate_session_sid() -> String {
    let u = Uuid::new_v4();
    let fields = u.as_fields();
    // Use a custom sub-authority format: S-1-5-117-{D1}-{D2}-{D3}-{D4}
    format!(
        "S-1-5-117-{}-{}-{}-{}",
        fields.0,
        fields.1,
        fields.2,
        u.as_u128() as u32
    )
}

pub(super) fn create_restricted_token_with_sid(session_sid_str: &str) -> Result<RestrictedToken> {
    let mut h_current_token: HANDLE = std::ptr::null_mut();
    let ok = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
            &mut h_current_token,
        )
    };
    if ok == 0 {
        return Err(NonoError::Setup(format!(
            "Failed to open process token: {}",
            unsafe { GetLastError() }
        )));
    }
    let current_token = OwnedHandle(h_current_token);

    let mut sid_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
    let sid_str_u16 = to_u16_null_terminated(session_sid_str);
    let ok = unsafe {
        windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW(
            sid_str_u16.as_ptr(),
            &mut sid_ptr,
        )
    };
    if ok == 0 {
        return Err(NonoError::Setup(format!(
            "Failed to convert SID string {}: {}",
            session_sid_str,
            unsafe { GetLastError() }
        )));
    }

    let sid_restrict = SID_AND_ATTRIBUTES {
        Sid: sid_ptr,
        Attributes: 0,
    };

    let mut h_restricted: HANDLE = std::ptr::null_mut();
    let ok = unsafe {
        CreateRestrictedToken(
            current_token.0,
            0,
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            1,
            &sid_restrict,
            &mut h_restricted,
        )
    };

    unsafe { LocalFree(sid_ptr as _) };

    if ok == 0 {
        return Err(NonoError::Setup(format!(
            "Failed to create restricted token: {}",
            unsafe { GetLastError() }
        )));
    }

    Ok(RestrictedToken {
        h_token: h_restricted,
    })
}
