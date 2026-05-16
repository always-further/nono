//! Executable identity capture for the audit trail.
//!
//! Computes a cross-platform `ExecutableIdentity` (canonical path + SHA-256
//! hash of the launched binary) before sandbox apply so the audit ledger
//! commits to exactly the bytes the supervisor handed off to the kernel.
//!
//! AUD-03 SHA-256 portion (Plan 22-05a Task 4 — manual port replay of upstream
//! `02ee0bd1` per D-02 fallback gate; the full upstream commit also included
//! `MerkleScheme::DomainSeparatedV3`, `audit_ledger.rs` flock changes, and
//! cross-file refactors that breached D-02 thresholds for cherry-pick).
//!
//! Plan 22-05b Task 4 (fork-only D-17 ALLOWED): Windows Authenticode
//! signer-trust verification lands as a SIBLING `AuthenticodeStatus`
//! field on the audit envelope per RESEARCH Contradiction #2 — upstream's
//! `ExecutableIdentity` is SHA-256 only and stays unchanged. The
//! `platform_authenticode` dispatch below routes to
//! `exec_identity_windows::query_authenticode_status` on Windows and
//! returns `None` on other platforms (SHA-256-only audit envelope).

use nono::undo::{ContentHash, ExecutableIdentity};
use nono::{NonoError, Result};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[cfg(target_os = "windows")]
pub use crate::exec_identity_windows::AuthenticodeStatus;

/// Cross-platform `AuthenticodeStatus` placeholder for non-Windows hosts.
/// Construction is impossible (uninhabited type); the
/// `platform_authenticode` dispatch on non-Windows returns `None` so
/// downstream encoders skip the field cleanly.
#[cfg(not(target_os = "windows"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticodeStatus {}

/// Sibling field on the audit envelope per RESEARCH Contradiction #2.
/// Does NOT mutate upstream's `ExecutableIdentity { resolved_path, sha256 }`.
///
/// On Windows: delegates to `exec_identity_windows::query_authenticode_status`.
/// On any FFI failure: returns `None` so the SHA-256-only audit envelope
/// (captured by `compute()`) is the recorded ground truth (AUD-03
/// acceptance #3 fallback path).
#[cfg(target_os = "windows")]
#[allow(dead_code)]
pub(crate) fn platform_authenticode(path: &Path) -> Option<AuthenticodeStatus> {
    match crate::exec_identity_windows::query_authenticode_status(path) {
        Ok(status) => Some(status),
        Err(e) => {
            tracing::debug!(
                "Authenticode query failed for {}: {e} — falling back to SHA-256",
                path.display()
            );
            None
        }
    }
}

/// Non-Windows: SHA-256-only audit envelope (no Authenticode concept).
#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub(crate) fn platform_authenticode(_path: &Path) -> Option<AuthenticodeStatus> {
    None
}

/// Compute the canonical path + SHA-256 hash of the launched executable.
///
/// Canonicalizes the resolved program path then streams its bytes through
/// SHA-256 in 8 KiB chunks. Returns `NonoError::CommandExecution` if either
/// canonicalization, file open, or read fails.
pub(crate) fn compute(resolved_program: &Path) -> Result<ExecutableIdentity> {
    let canonical_path = resolved_program.canonicalize().map_err(|e| {
        NonoError::CommandExecution(std::io::Error::new(
            e.kind(),
            format!(
                "Failed to canonicalize executable {}: {e}",
                resolved_program.display()
            ),
        ))
    })?;
    let mut file = File::open(&canonical_path).map_err(|e| {
        NonoError::CommandExecution(std::io::Error::new(
            e.kind(),
            format!(
                "Failed to open executable {}: {e}",
                canonical_path.display()
            ),
        ))
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file.read(&mut buffer).map_err(|e| {
            NonoError::CommandExecution(std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to read executable {}: {e}",
                    canonical_path.display()
                ),
            ))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(ExecutableIdentity {
        resolved_path: canonical_path,
        sha256: ContentHash::from_bytes(hasher.finalize().into()),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs;

    #[test]
    fn compute_hashes_canonical_binary_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("tool");
        fs::write(&binary, b"#!/bin/sh\necho hello\n").unwrap();

        let identity = compute(&binary).unwrap();
        let expected = Sha256::digest(b"#!/bin/sh\necho hello\n");

        assert_eq!(identity.resolved_path, binary.canonicalize().unwrap());
        assert_eq!(identity.sha256.as_bytes(), &<[u8; 32]>::from(expected));
    }

    #[test]
    fn compute_propagates_canonicalize_errors() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");

        let err = compute(&missing).unwrap_err();
        assert!(matches!(err, NonoError::CommandExecution(_)));
    }
}
