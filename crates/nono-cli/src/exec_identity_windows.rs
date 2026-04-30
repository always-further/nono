//! Windows Authenticode exec-identity recording (REQ-AUD-03 acceptance #2/#3).
//!
//! Plan 22-05b Task 4 — fork-only addition per CONTEXT § Integration Points
//! line 248 (D-17 ALLOWED). FFI style mirrors Phase 21's
//! `crates/nono/src/sandbox/windows.rs::try_set_mandatory_label`:
//! `encode_wide` UTF-16 conversion, `unsafe { ... }` blocks paired with
//! `// SAFETY:` doc comments, RAII close guard for `WTD_STATEACTION_CLOSE`,
//! `GetLastError` -> typed `NonoError`.
//!
//! Sibling field on the audit envelope per RESEARCH Contradiction #2:
//! `AuthenticodeStatus` does NOT mutate upstream's `ExecutableIdentity`
//! struct shape; SHA-256 capture stays independent and always happens.
//!
//! On any FFI failure (helpers absent / runtime error / unsigned binary),
//! the caller falls back to the SHA-256-only audit path captured by
//! `exec_identity::compute`.
//!
//! ## REQ-AUDC-03 fail-closed contract (v2.3, Phase 28)
//!
//! Phase 28 enables the chain walker by adding the
//! `Win32_Security_Cryptography_Catalog` + `Win32_Security_Cryptography_Sip`
//! features to `windows-sys` 0.59. With those gates in place,
//! `WTHelperProvDataFromStateData` and `WTHelperGetProvSignerFromChain`
//! become reachable, and `parse_signer_subject` / `parse_thumbprint`
//! return live extraction results instead of the v2.2 Decision 4 sentinel.
//!
//! On `WinVerifyTrust = Valid` (HRESULT 0): both `signer_subject` and
//! `thumbprint` MUST be populated (REQ-AUDC-03 acceptance #2). Any
//! chain-walk failure (NULL prov-data, empty cert chain, NULL leaf
//! CERT_CONTEXT, `CertGetNameStringW` returning empty,
//! `CertGetCertificateContextProperty` returning false) causes
//! `query_authenticode_status` to return `Err(NonoError::SandboxInit(..))`
//! carrying the failure cause and the original `WinVerifyTrust` HRESULT —
//! NEVER a silent `<unknown>` fallback.
//!
//! `Unsigned` (`HRESULT == TRUST_E_NOSIGNATURE`) and `InvalidSignature`
//! (`HRESULT != 0 && != TRUST_E_NOSIGNATURE`) paths are unchanged — chain
//! walk is NOT attempted; the discriminant alone is recorded.
//!
//! Behavior change vs v2.2: callers previously seeing
//! `AuthenticodeStatus::Valid { signer_subject: "<unknown>", thumbprint: "" }`
//! now see either `AuthenticodeStatus::Valid { signer_subject: <RDN>,
//! thumbprint: <40-char-hex> }` (success) or `Err(NonoError::SandboxInit)`
//! (chain-walk failure on Valid signature). This is intentional per
//! REQ-AUDC-03 acceptance #2 (fail-closed audit-recording).

#![cfg(target_os = "windows")]

use nono::{NonoError, Result};
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Security::Cryptography::{
    CertGetCertificateContextProperty, CertGetNameStringW, CERT_CONTEXT, CERT_HASH_PROP_ID,
    CERT_NAME_RDN_TYPE, CERT_X500_NAME_STR,
};
use windows_sys::Win32::Security::WinTrust::{
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
    CRYPT_PROVIDER_CERT, CRYPT_PROVIDER_DATA, CRYPT_PROVIDER_SGNR,
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};

/// Authenticode status for an executable.
///
/// Sibling field on the audit envelope (RESEARCH Contradiction #2 — does
/// NOT mutate upstream's `ExecutableIdentity` struct shape; SHA-256 capture
/// stays independent and always happens).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticodeStatus {
    /// Signature valid; chain validated to a trusted root by `WinVerifyTrust`.
    ///
    /// Both `signer_subject` and `thumbprint` are guaranteed populated when
    /// this variant is constructed (REQ-AUDC-03 acceptance #2 fail-closed
    /// contract). If chain walking fails to extract either field on a
    /// `WinVerifyTrust=Valid` result, `query_authenticode_status` returns
    /// `Err(NonoError::SandboxInit(..))` carrying the chain-walk failure
    /// cause — it does NOT produce this variant with sentinel values.
    Valid {
        /// Signer subject (leaf-cert RDN, e.g.
        /// `"CN=Microsoft Windows, O=Microsoft Corporation, ..."`)
        /// extracted via `CertGetNameStringW(CERT_NAME_RDN_TYPE)` and
        /// sanitized to strip control characters via `sanitize_for_terminal`
        /// (defense-in-depth against attacker-controlled cert subjects
        /// containing terminal escape sequences — T-28-01 mitigation).
        signer_subject: String,
        /// SHA-1 thumbprint of the leaf signing cert as a 40-character
        /// UPPERCASE hex string, extracted via
        /// `CertGetCertificateContextProperty(CERT_HASH_PROP_ID)`.
        thumbprint: String,
    },
    /// File present but unsigned (`TRUST_E_NOSIGNATURE`).
    Unsigned,
    /// File signed but signature invalid / chain rejected. The `hresult`
    /// field carries the raw `WinVerifyTrust` return value for forensics.
    InvalidSignature { hresult: i32 },
    /// Signature query itself failed (e.g. file missing). Caller falls back
    /// to SHA-256-only audit envelope per AUD-03 acceptance #3.
    QueryFailed { reason: String },
}

/// `TRUST_E_NOSIGNATURE` — well-known WinTrust HRESULT for "file is not
/// signed". Surfaced verbatim in the audit ledger for forensic clarity.
const TRUST_E_NOSIGNATURE: u32 = 0x800B0100;

/// Record exec-identity Authenticode status for `path`.
///
/// Calls `WinVerifyTrust` with `WTD_REVOKE_NONE` (best-effort signature
/// query without CRL/OCSP latency per T-22-05b-02 mitigation; SHA-256
/// fallback ensures audit completes even on Authenticode failure). Always
/// pairs the `WTD_STATEACTION_VERIFY` call with a `WTD_STATEACTION_CLOSE`
/// call on Drop via `WinTrustCloseGuard` (T-22-05b-05 mitigation).
///
/// Returns `Ok(AuthenticodeStatus::QueryFailed { .. })` for path-conversion
/// failures rather than `Err(..)` so the caller's "fall through to SHA-256"
/// branch is exercised uniformly.
#[must_use = "ignoring the AuthenticodeStatus drops audit evidence"]
pub fn query_authenticode_status(path: &Path) -> Result<AuthenticodeStatus> {
    // UTF-16 path conversion (mirrors sandbox/windows.rs::try_set_mandatory_label).
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Heuristic: if `path` is empty post-conversion, the path conversion
    // produced nothing valid. Surface as QueryFailed so the caller falls
    // through to SHA-256.
    if wide.len() < 2 {
        return Ok(AuthenticodeStatus::QueryFailed {
            reason: format!("empty UTF-16 path conversion for {}", path.display()),
        });
    }

    let file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide.as_ptr(),
        hFile: std::ptr::null_mut(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    let mut wtd = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        // Best-effort signature query without CRL/OCSP latency
        // (T-22-05b-02 mitigation; AUD-03 acceptance allows
        // "Signature failures do not prevent session start").
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &file_info as *const _ as *mut WINTRUST_FILE_INFO,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: std::ptr::null_mut(),
        pwszURLReference: std::ptr::null_mut(),
        dwProvFlags: 0,
        dwUIContext: 0,
        pSignatureSettings: std::ptr::null_mut(),
    };

    // SAFETY: `WINTRUST_ACTION_GENERIC_VERIFY_V2` is a static GUID exported
    // by windows-sys; `&mut wtd` points to a valid stack-allocated
    // WINTRUST_DATA pre-populated above. `hWnd = NULL` is the documented
    // headless-verify shape. The first call requests verification; the
    // matching `WTD_STATEACTION_CLOSE` second call is guaranteed by the
    // RAII `WinTrustCloseGuard` constructed below (Drop fires even on
    // early return / panic). `wtd.hWVTStateData` is mutated by Windows
    // and read back in `parse_signer_subject` / `parse_thumbprint`.
    let verify_result: i32 = unsafe {
        WinVerifyTrust(
            std::ptr::null_mut(),
            &WINTRUST_ACTION_GENERIC_VERIFY_V2 as *const _ as *mut _,
            &mut wtd as *mut _ as *mut c_void,
        )
    };

    // RAII close guard MUST be constructed BEFORE we read `wtd.hWVTStateData`
    // so any early-return path (including panic propagation) still runs
    // the matching `WTD_STATEACTION_CLOSE` call. Mirrors Phase 21's
    // `_sd_guard` pattern (T-22-05b-05 mitigation).
    let _close_guard = WinTrustCloseGuard {
        wtd: &mut wtd as *mut WINTRUST_DATA,
    };

    let status = if verify_result == 0 {
        // Per REQ-AUDC-03 fail-closed contract: chain-walk failure on a
        // Valid signature returns Err(NonoError::SandboxInit) — NEVER a
        // silent <unknown> fallback. The `_close_guard` constructed above
        // dominates this branch, so its RAII Drop fires on the early-Err
        // path (T-22-05b-05 mitigation preserved; Drop runs the matching
        // WTD_STATEACTION_CLOSE call even on `?` propagation).
        let signer_subject = parse_signer_subject(&wtd)?;
        let thumbprint = parse_thumbprint(&wtd)?;
        AuthenticodeStatus::Valid {
            signer_subject,
            thumbprint,
        }
    } else if (verify_result as u32) == TRUST_E_NOSIGNATURE {
        AuthenticodeStatus::Unsigned
    } else {
        AuthenticodeStatus::InvalidSignature {
            hresult: verify_result,
        }
    };

    Ok(status)
}

/// RAII close-guard for the second `WinVerifyTrust` call with
/// `WTD_STATEACTION_CLOSE`. Mirrors Phase 21's `_sd_guard` pattern in
/// `sandbox/windows.rs`. ALWAYS runs the close call to release the
/// state allocated by the first verify call (T-22-05b-05 mitigation:
/// state-leak via mis-ordered close).
struct WinTrustCloseGuard {
    wtd: *mut WINTRUST_DATA,
}

impl Drop for WinTrustCloseGuard {
    fn drop(&mut self) {
        // SAFETY: `self.wtd` points to the same stack-allocated WINTRUST_DATA
        // referenced by the matching VERIFY call above. Setting
        // `dwStateAction = WTD_STATEACTION_CLOSE` and re-invoking
        // WinVerifyTrust with the same hWVTStateData is the documented
        // close-pair pattern. Errors from the close call are best-effort
        // (we are in Drop and cannot propagate); they do not affect audit
        // correctness because the state being leaked is verify-side only.
        unsafe {
            (*self.wtd).dwStateAction = WTD_STATEACTION_CLOSE;
            let _ = WinVerifyTrust(
                std::ptr::null_mut(),
                &WINTRUST_ACTION_GENERIC_VERIFY_V2 as *const _ as *mut _,
                self.wtd as *mut c_void,
            );
        }
    }
}

/// Walk the WinVerifyTrust state data to the leaf signing certificate and
/// extract the RDN-formatted subject string via `CertGetNameStringW`.
///
/// Per REQ-AUDC-03 fail-closed contract: returns `Err(NonoError::SandboxInit)`
/// if any step in the chain fails. The caller MUST propagate via `?` —
/// `query_authenticode_status` is responsible for ensuring the
/// `WinTrustCloseGuard` is alive on the failure path (RAII Drop fires
/// even on early-Err return).
fn parse_signer_subject(wtd: &WINTRUST_DATA) -> Result<String> {
    let leaf_cert = leaf_cert_from(wtd)?;

    // For CERT_NAME_RDN_TYPE, `pvTypePara` is treated as a `*const DWORD`
    // pointing to a CERT_STRING_TYPE flag controlling the RDN serialization
    // format. CERT_X500_NAME_STR (= 3) yields the keyed RDN format
    // "CN=..., O=..., C=..." (the format REQ-AUDC-01 must-haves expect for
    // the CN= substring assertion). Without this flag, the default behavior
    // emits a comma-separated value-only string with no attribute keys.
    let str_type_flag: u32 = CERT_X500_NAME_STR;
    let str_type_ptr = &str_type_flag as *const u32 as *mut c_void;

    // First call: query the required UTF-16 buffer length (returns
    // wide-char count INCLUDING the null terminator).
    // SAFETY: `leaf_cert` is a non-NULL CERT_CONTEXT pointer obtained from
    // `leaf_cert_from` (which returns Err on NULL). `str_type_ptr` points
    // to a stack-local DWORD live for the duration of this function.
    // Passing NULL/0 for pszNameString/cchNameString returns the required
    // size in wide chars including the null terminator.
    let cch_required = unsafe {
        CertGetNameStringW(
            leaf_cert,
            CERT_NAME_RDN_TYPE,
            0,
            str_type_ptr,
            std::ptr::null_mut(),
            0,
        )
    };
    if cch_required <= 1 {
        // Returns 1 on failure (just the null terminator); 0 should not
        // occur per Microsoft docs but defensively treat as fail-closed.
        return Err(authenticode_chain_walk_error(format!(
            "CertGetNameStringW(RDN_TYPE) sizing call returned {cch_required} (no subject available)"
        )));
    }

    // Second call: actually read the wide string.
    // SAFETY: buffer is sized to `cch_required` u16 elements per the
    // first-call result; `CertGetNameStringW` writes UP TO `cch_required`
    // wide chars including the null terminator. `str_type_ptr` is the
    // same valid stack pointer as the first call.
    let mut buf: Vec<u16> = vec![0u16; cch_required as usize];
    let written = unsafe {
        CertGetNameStringW(
            leaf_cert,
            CERT_NAME_RDN_TYPE,
            0,
            str_type_ptr,
            buf.as_mut_ptr(),
            cch_required,
        )
    };
    if written <= 1 {
        return Err(authenticode_chain_walk_error(
            "CertGetNameStringW(RDN_TYPE) read call returned empty subject".to_string(),
        ));
    }

    // Strip the trailing null and decode UTF-16. Use saturating_sub for
    // CLAUDE.md § Coding Standards "Arithmetic" compliance.
    let truncated_len = written.saturating_sub(1) as usize;
    let raw = String::from_utf16_lossy(&buf[..truncated_len]);
    Ok(sanitize_for_terminal(&raw))
}

/// Walk the WinVerifyTrust state data to the leaf signing certificate and
/// extract the SHA-1 thumbprint via
/// `CertGetCertificateContextProperty(CERT_HASH_PROP_ID)`. Renders the
/// 20-byte hash as a 40-character UPPERCASE hex string.
///
/// Per REQ-AUDC-03 fail-closed contract: returns `Err(NonoError::SandboxInit)`
/// on any chain-walk failure. The caller MUST propagate via `?`.
fn parse_thumbprint(wtd: &WINTRUST_DATA) -> Result<String> {
    let leaf_cert = leaf_cert_from(wtd)?;

    // First call: query required byte length of the SHA-1 hash (always 20
    // for CERT_HASH_PROP_ID, but Microsoft pattern is to ask twice).
    let mut cb_required: u32 = 0;
    // SAFETY: `leaf_cert` is non-NULL per the helper's contract; NULL
    // pvData + zero pcbData populates `cb_required` with the needed byte
    // count. `CertGetCertificateContextProperty` returns BOOL (0 = fail).
    let ok = unsafe {
        CertGetCertificateContextProperty(
            leaf_cert,
            CERT_HASH_PROP_ID,
            std::ptr::null_mut(),
            &mut cb_required,
        )
    };
    if ok == 0 || cb_required == 0 || cb_required > 64 {
        // SHA-1 is 20 bytes; refuse implausible sizes (defense-in-depth
        // against malformed cert state — T-28-04 acceptance bound).
        return Err(authenticode_chain_walk_error(format!(
            "CertGetCertificateContextProperty(CERT_HASH_PROP_ID) sizing call failed (ok={ok}, cb_required={cb_required})"
        )));
    }

    // Second call: read the bytes.
    let mut buf: Vec<u8> = vec![0u8; cb_required as usize];
    // SAFETY: `buf` is sized per the first-call result; `cb_required` is
    // updated to the actual bytes-written count by Windows.
    let ok = unsafe {
        CertGetCertificateContextProperty(
            leaf_cert,
            CERT_HASH_PROP_ID,
            buf.as_mut_ptr() as *mut c_void,
            &mut cb_required,
        )
    };
    if ok == 0 {
        return Err(authenticode_chain_walk_error(
            "CertGetCertificateContextProperty(CERT_HASH_PROP_ID) read call failed".to_string(),
        ));
    }

    // Render as 40-char UPPERCASE hex (per must-haves.truths regex anchor
    // ^[0-9A-F]{40}$).
    let hex: String = buf
        .iter()
        .take(cb_required as usize)
        .map(|b| format!("{:02X}", b))
        .collect();
    Ok(hex)
}

/// Walk `WTHelperProvDataFromStateData → WTHelperGetProvSignerFromChain`
/// down to the leaf `CERT_CONTEXT` pointer. Shared between
/// `parse_signer_subject` and `parse_thumbprint` to avoid duplicating the
/// null-check ladder.
///
/// The returned pointer is owned by the WinTrust state data (which is in
/// turn owned by the caller's `WinTrustCloseGuard` RAII binding). The
/// caller MUST NOT free it. Lifetime is bounded by the close-guard.
fn leaf_cert_from(wtd: &WINTRUST_DATA) -> Result<*const CERT_CONTEXT> {
    // SAFETY: `wtd.hWVTStateData` was populated by the matching
    // `WinVerifyTrust(... WTD_STATEACTION_VERIFY ...)` call in
    // `query_authenticode_status` and is owned by the live
    // `WinTrustCloseGuard`. `WTHelperProvDataFromStateData` accepts a
    // state-data handle and returns either a non-NULL
    // `*mut CRYPT_PROVIDER_DATA` whose lifetime is tied to the state data
    // (do NOT free), or NULL on failure.
    let prov_data: *mut CRYPT_PROVIDER_DATA =
        unsafe { WTHelperProvDataFromStateData(wtd.hWVTStateData) };
    if prov_data.is_null() {
        return Err(authenticode_chain_walk_error(
            "WTHelperProvDataFromStateData returned NULL".to_string(),
        ));
    }

    // SAFETY: `prov_data` is non-NULL per the check above. The 0/0 indices
    // request the primary signer (idxSigner=0) and the leaf cert chain
    // (fCounterSigner=FALSE / idxCounterSigner=0). Returns NULL if the
    // signer index is out of range (treat as fail-closed).
    let signer: *mut CRYPT_PROVIDER_SGNR =
        unsafe { WTHelperGetProvSignerFromChain(prov_data, 0, 0, 0) };
    if signer.is_null() {
        return Err(authenticode_chain_walk_error(
            "WTHelperGetProvSignerFromChain returned NULL — no primary signer".to_string(),
        ));
    }

    // SAFETY: `signer` is non-NULL per the check above. The `pasCertChain`
    // field is a non-owning pointer to an array of `csCertChain`
    // CRYPT_PROVIDER_CERT entries. The leaf cert is the LAST entry
    // (index `csCertChain - 1`) per the Microsoft Authenticode chain
    // ordering convention (root at index 0, leaf at the end).
    let (cert_chain, chain_len): (*mut CRYPT_PROVIDER_CERT, u32) =
        unsafe { ((*signer).pasCertChain, (*signer).csCertChain) };
    if cert_chain.is_null() || chain_len == 0 {
        return Err(authenticode_chain_walk_error(format!(
            "Authenticode signer carries empty cert chain (chain_len={chain_len})"
        )));
    }

    // SAFETY: leaf is at `chain_len - 1`. We checked chain_len > 0 above
    // (so the saturating_sub never underflows even though it cannot here).
    // `pCert` is a `*const CERT_CONTEXT` (PCCERT_CONTEXT) owned by the
    // WinTrust state data.
    let leaf_cert: *const CERT_CONTEXT = unsafe {
        let leaf_idx = chain_len.saturating_sub(1) as usize;
        let leaf_entry: *mut CRYPT_PROVIDER_CERT = cert_chain.add(leaf_idx);
        (*leaf_entry).pCert
    };
    if leaf_cert.is_null() {
        return Err(authenticode_chain_walk_error(
            "Authenticode leaf CERT_CONTEXT is NULL".to_string(),
        ));
    }

    Ok(leaf_cert)
}

/// Build a fail-closed `NonoError` carrying the chain-walk failure cause.
///
/// REQ-AUDC-03 acceptance #2: chain-walk failure on a `WinVerifyTrust=Valid`
/// signature is an audit-integrity failure (we cannot record the binary's
/// identity). Phase 28 routes this through `NonoError::SandboxInit`
/// because the existing `NonoError` taxonomy in `crates/nono/src/error.rs`
/// does not have an `AuditIntegrity` variant; `SandboxInit` is the
/// established Phase 21 + Phase 22 sink for Windows-FFI-adjacent failures
/// (see `capability_ext.rs`, `execution_runtime.rs`, `exec_strategy.rs`
/// for prior usage). The "authenticode chain-walk failed" prefix makes
/// the cause unambiguous in logs.
fn authenticode_chain_walk_error(hint: String) -> NonoError {
    NonoError::SandboxInit(format!(
        "authenticode chain-walk failed (REQ-AUDC-03 fail-closed): {hint}"
    ))
}

/// Strip control characters and ANSI escape sequences from a chain-extracted
/// subject string before recording it in the audit ledger.
///
/// Defense-in-depth (T-28-01 mitigation): a malicious cert subject containing
/// terminal escape sequences must not be able to reflow the operator's TTY
/// when `nono audit show <id>` renders the audit ledger. Mirrors the
/// `sanitize_for_terminal` helper in `audit_commands.rs` /
/// `terminal_approval.rs`. Inlined here (rather than re-exported) because
/// those functions are private to their respective modules and Phase 28's
/// scope is intentionally tight.
fn sanitize_for_terminal(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // ESC: consume CSI/OSC/DCS/APC/PM/SOS sequences without emitting.
            if let Some(&next) = chars.peek() {
                if next == '[' {
                    // CSI: consume until final byte 0x40-0x7E.
                    chars.next();
                    for seq_c in chars.by_ref() {
                        if ('\x40'..='\x7e').contains(&seq_c) {
                            break;
                        }
                    }
                } else if matches!(next, ']' | 'P' | '_' | '^' | 'X') {
                    // OSC/DCS/APC/PM/SOS: consume until ST (ESC \) or BEL.
                    chars.next();
                    let mut prev = '\0';
                    for seq_c in chars.by_ref() {
                        if seq_c == '\x07' || (prev == '\x1b' && seq_c == '\\') {
                            break;
                        }
                        prev = seq_c;
                    }
                } else {
                    // Lone ESC followed by non-CSI: drop ESC, keep next.
                    chars.next();
                }
            }
        } else if c.is_control() && c != '\t' {
            // Drop other control chars (newlines, CR, BS, etc. should not
            // appear in a cert RDN subject; if they do, attacker-controlled).
        } else {
            result.push(c);
        }
    }
    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Microsoft-signed system binary fixture. Probed via the
    /// `_probe_embedded_signed_candidates` test below on a Windows 11 host:
    /// `C:\Windows\explorer.exe` is **EMBEDDED-signed** (not catalog-signed).
    /// `notepad.exe`, `cmd.exe`, and `powershell.exe` are catalog-signed on
    /// modern Windows 10/11 builds (their signatures live in `.cat` files,
    /// not in the PE itself), so `WinVerifyTrust(WTD_CHOICE_FILE)` returns
    /// `TRUST_E_NOSIGNATURE` for them — that's why we use `explorer.exe`
    /// here. `taskmgr.exe`, `dllhost.exe`, `svchost.exe`, `wuauclt.exe`,
    /// `wermgr.exe` are also reliable embedded-signed fallbacks if a future
    /// Windows SKU drops `explorer.exe`.
    const FIXTURE_PATH: &str = r"C:\Windows\explorer.exe";

    /// Substring expected in the leaf-cert RDN for the FIXTURE_PATH binary.
    /// Lowercased for case-insensitive comparison via `to_lowercase()`.
    const EXPECTED_SUBJECT_SUBSTRING: &str = "microsoft";

    // REQ-AUDC-03 fail-closed contract: structurally enforced via
    // ?-propagation in query_authenticode_status (Task 4 wiring); no
    // programmable test fixture exists for "Valid + chain-walk-fails"
    // because constructing one requires FFI mocking. Code review of the
    // two `?` operators is the authoritative evidence.

    #[test]
    fn unsigned_temp_file_returns_unsigned_or_invalid() {
        // A short tempfile that LOOKS like a PE start but has no signature.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unsigned.exe");
        std::fs::write(&path, b"MZ\x90\x00\x03\x00\x00\x00").unwrap();
        let status = query_authenticode_status(&path).unwrap();
        // Either Unsigned (most likely) or InvalidSignature is acceptable —
        // both signal "fall back to SHA-256". The unit test refuses to
        // require Valid for a tempfile.
        assert!(
            matches!(
                status,
                AuthenticodeStatus::Unsigned | AuthenticodeStatus::InvalidSignature { .. }
            ),
            "expected Unsigned or InvalidSignature, got: {status:?}"
        );
    }

    #[test]
    fn missing_path_returns_invalid_or_query_failed() {
        let path = Path::new(r"C:\nonexistent\path\that\should\not\exist.exe");
        let result = query_authenticode_status(path);
        match result {
            Ok(AuthenticodeStatus::QueryFailed { .. })
            | Ok(AuthenticodeStatus::InvalidSignature { .. })
            | Ok(AuthenticodeStatus::Unsigned)
            | Err(_) => (),
            other => panic!(
                "expected QueryFailed/InvalidSignature/Unsigned/Err for missing path, got: {other:?}"
            ),
        }
    }

    /// REQ-AUDC-01 acceptance: chain walker extracts a populated, RDN-shaped
    /// subject from a known-Microsoft-signed system binary. Replaces the
    /// v2.2 "<unknown>" sentinel with a real CN= prefix.
    #[test]
    fn signed_system_binary_extracts_cn_subject() {
        let path = Path::new(FIXTURE_PATH);
        if !path.exists() {
            // Defense-in-depth: graceful skip on unusual Windows SKUs.
            eprintln!("Skipping: fixture {FIXTURE_PATH} not present on this host.");
            return;
        }

        let status = query_authenticode_status(path)
            .expect("query_authenticode_status must succeed on a Microsoft-signed system binary");

        match status {
            AuthenticodeStatus::Valid {
                signer_subject, ..
            } => {
                assert!(
                    !signer_subject.is_empty(),
                    "signer_subject must be non-empty on Valid signature; got: {signer_subject:?}"
                );
                assert!(
                    signer_subject.to_lowercase().contains("cn="),
                    "signer_subject should be RDN-formatted with a CN= component; got: {signer_subject:?}"
                );
                assert!(
                    signer_subject
                        .to_lowercase()
                        .contains(EXPECTED_SUBJECT_SUBSTRING),
                    "signer_subject should contain '{EXPECTED_SUBJECT_SUBSTRING}' for fixture {FIXTURE_PATH}; got: {signer_subject:?}"
                );
            }
            other => panic!(
                "expected AuthenticodeStatus::Valid for Microsoft-signed fixture {FIXTURE_PATH}, got: {other:?}"
            ),
        }
    }

    /// REQ-AUDC-01 acceptance: chain walker extracts a 40-character UPPERCASE
    /// hex thumbprint from a known-Microsoft-signed system binary. Replaces
    /// the v2.2 empty-string sentinel with the SHA-1 of the leaf signing cert.
    #[test]
    fn signed_system_binary_extracts_40_char_hex_thumbprint() {
        let path = Path::new(FIXTURE_PATH);
        if !path.exists() {
            eprintln!("Skipping: fixture {FIXTURE_PATH} not present on this host.");
            return;
        }

        let status = query_authenticode_status(path).expect("query Authenticode");
        match status {
            AuthenticodeStatus::Valid { thumbprint, .. } => {
                assert_eq!(
                    thumbprint.len(),
                    40,
                    "SHA-1 thumbprint must be exactly 40 hex chars; got {} chars: {thumbprint:?}",
                    thumbprint.len()
                );
                assert!(
                    thumbprint
                        .chars()
                        .all(|c| c.is_ascii_hexdigit()
                            && (c.is_ascii_digit() || c.is_ascii_uppercase())),
                    "thumbprint must be UPPERCASE hex (REQ-AUDC-01 must-haves.truths anchor); got: {thumbprint:?}"
                );
            }
            other => panic!("expected Valid for fixture {FIXTURE_PATH}, got: {other:?}"),
        }
    }

    /// REQ-AUDC-02 acceptance #1 (re-enabled in Phase 28 Plan 28-01 from the
    /// v2.2 Plan 22-05b deferral). Substring-matches a known-signed
    /// Windows-shipped binary's signer subject. Relocated inline here from
    /// `crates/nono-cli/tests/exec_identity_windows.rs` (PATH-4 per
    /// 28-CONTEXT.md): the integration-test target previously couldn't reach
    /// the bin's `query_authenticode_status` directly, so the test has been
    /// moved to live alongside the unit tests that exercise the same surface.
    /// The integration test file retains the `nono --version` linkage probe.
    #[test]
    fn authenticode_signed_records_subject() {
        let path = Path::new(FIXTURE_PATH);
        if !path.exists() {
            // Graceful skip on hosts where the fixture is missing
            // (e.g., Windows Nano server, ARM64 dev images).
            eprintln!("Skipping: fixture {FIXTURE_PATH} not present on this host.");
            return;
        }
        let status = query_authenticode_status(path)
            .expect("query_authenticode_status against signed system binary should succeed");
        match status {
            AuthenticodeStatus::Valid { signer_subject, .. } => {
                assert!(
                    signer_subject.to_lowercase().contains("microsoft"),
                    "expected signer subject to contain 'microsoft'; got: {signer_subject}"
                );
            }
            other => panic!("expected Valid status; got {other:?}"),
        }
    }

    #[test]
    fn sanitize_for_terminal_strips_ansi_escape_sequences() {
        // T-28-01 mitigation: a malicious cert subject with an ANSI escape
        // sequence must not survive into the audit ledger.
        let attacker_input = "CN=Evil\x1b[2JCorp, O=Evil";
        let cleaned = sanitize_for_terminal(attacker_input);
        assert!(
            !cleaned.contains('\x1b'),
            "ESC byte must be stripped; got: {cleaned:?}"
        );
        assert!(
            cleaned.contains("CN=Evil"),
            "non-control text must survive; got: {cleaned:?}"
        );
        assert!(
            cleaned.contains("Corp"),
            "post-escape text must survive (escape sequence consumed); got: {cleaned:?}"
        );
    }
}
