// Phase 50 Plan 02 Task 1 finding: ureq 3.3.0 Body API
// - read_to_vec(): EXISTS at ureq-3.3.0/src/body/mod.rs:329
//     `pub fn read_to_vec(&mut self) -> Result<Vec<u8>, Error>`
// - into_reader(): EXISTS at ureq-3.3.0/src/body/mod.rs:264
// - Chosen API for Task 2: `Body::read_to_vec(&mut self)` (Option A per plan).
//   No `use std::io::Read;` needed; the closure body is:
//     let mut resp = agent.get(&url_str).call()?;
//     resp.body_mut().read_to_vec()
// This scratch note is overwritten by Task 2's full file rewrite.

//! Nono-local TUF chain-walk for refreshing the Sigstore trusted root
//! against `https://tuf-repo-cdn.sigstore.dev` using an HTTP transport
//! that consults the OS certificate store (`ureq` + `platform-verifier`).
//!
//! This module replaces the single call to the upstream production-trust-root
//! helper previously used by `crate::setup::SetupRunner::refresh_trust_root_step`.
//! The motivation is corp-network resilience: `reqwest 0.12.28` (pulled
//! transitively by `sigstore-trust-root 0.7.0`) uses `webpki-roots` (Mozilla
//! CA bundle) and cannot see enterprise CAs deployed via GPO/MDM, causing
//! `nono setup --refresh-trust-root` to fail on TLS-inspecting corporate
//! networks. See `.planning/debug/resolved/sigstore-tuf-fetch-transport.md`
//! and `.planning/phases/50-corp-network-tuf-refresh-via-os-root-store-replace-or-wrap-t/`.
//!
//! Phase 50 D-50-01: This module lives in `nono-cli`, not in `crates/nono`,
//! to preserve the P32-CHK-002 / D-32-15 invariant that `crates/nono` has
//! zero HTTP transport dependencies.
//!
//! Phase 50 D-50-02: The public surface is a single free function that
//! returns the same `TrustedRoot` value the upstream call would have
//! produced — swap-in replacement, byte-identical cache output.
//!
//! Phase 50 (RESEARCH.md A4 correction): This function is `async fn`
//! because `tough::RepositoryLoader::load`, `Repository::read_target`, and
//! `IntoVec::into_vec` are all async. The CONTEXT.md statement that
//! "tough + ureq are sync, no tokio runtime needed" is WRONG; the caller
//! (`refresh_trust_root_step`) MUST preserve the
//! `tokio::runtime::Builder::new_current_thread()` block.

use nono::trust::TrustedRoot;
use nono::{NonoError, Result};

/// Refresh the Sigstore production trusted root by walking the TUF chain
/// from the embedded v14 anchor (`sigstore_trust_root::PRODUCTION_TUF_ROOT`)
/// to the current head at `https://tuf-repo-cdn.sigstore.dev/`, using an
/// HTTP transport that consults the OS certificate store.
///
/// Returns the same `TrustedRoot` value the upstream production helper
/// would have produced; the call site (`crate::setup::SetupRunner::refresh_trust_root_step`)
/// serializes via the SAME `serde_json::to_string_pretty` call so the cache
/// file at `<nono_home>/.nono/trust-root/trusted_root.json` is byte-identical
/// to what the upstream call would have written.
///
/// # Errors
///
/// `NonoError::Setup` for all TUF / transport / parse failures. Best-effort
/// cleanup of the TUF datastore at `<nono_home>/.nono/trust-root/tuf-cache/`
/// is performed on any failure path (D-49-B2 / D-50-07).
///
/// # Skeleton Notice
///
/// This is the Wave 0 skeleton. The real chain-walk implementation lands
/// in Plan 50-02; the call-site swap in `setup.rs` lands in Plan 50-03.
// Phase 50 Wave 0 skeleton: this function is intentionally not called by
// any existing code path — Plan 50-03 swaps `setup.rs::refresh_trust_root_step`
// to call it once Plan 50-02 lands the real implementation. The
// `#[allow(dead_code)]` is removed at that point.
#[allow(dead_code)]
pub async fn refresh_production_trusted_root() -> Result<TrustedRoot> {
    Err(NonoError::Setup(
        "trust_refresh::refresh_production_trusted_root not yet implemented \
         (Wave 0 skeleton; real impl lands in Plan 50-02)"
            .to_string(),
    ))
}
