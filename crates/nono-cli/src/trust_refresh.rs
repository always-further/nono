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
//! Phase 50 (RESEARCH.md A4 correction): The public function is `async fn`
//! because `tough::RepositoryLoader::load`, `Repository::read_target`, and
//! `IntoVec::into_vec` are all async. The CONTEXT.md statement that
//! "tough + ureq are sync, no tokio runtime needed" is WRONG; the caller
//! (`refresh_trust_root_step`) MUST preserve the
//! `tokio::runtime::Builder::new_current_thread()` block.
//!
//! Implementation note (Phase 50 Plan 02): This is a verbatim port of
//! `sigstore-trust-root-0.7.0/src/tuf.rs::TufClient::load_repository`
//! (lines 349-407) with TWO substitutions: (1) `tough::HttpTransport`
//! -> `UreqTransport(ureq::Agent)` so the OS root store is honored;
//! (2) sigstore-rs's `directories`-based cache path -> nono's
//! `nono_home_dir()` + `.nono/trust-root/tuf-cache/`. Signature math
//! stays in `tough` (D-50-04, SPEC Req 3).
//!
//! Phase 50 (Codex R-50-05): D-50-07 cleanup applies to ALL failures
//! after `tokio::fs::create_dir_all` succeeds — not just
//! `RepositoryLoader::load()` failure. The chain-walk body is wrapped in
//! a single inner helper whose `Result` is captured once; cleanup runs
//! once on `Err(_)`. Read-target / IntoVec / UTF-8 / TrustedRoot::from_json
//! failures all trigger the cleanup path now.

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream;
use nono::trust::TrustedRoot;
use nono::{NonoError, Result};
use sigstore_trust_root::{DEFAULT_TUF_URL, PRODUCTION_TUF_ROOT, TRUSTED_ROOT_TARGET};
use std::path::PathBuf;
use std::time::Duration;
use tough::{
    IntoVec, RepositoryLoader, TargetName, Transport, TransportError, TransportErrorKind,
    TransportStream,
};
use ureq::tls::{RootCerts, TlsConfig};
use ureq::Agent;
use url::Url;

/// HTTP transport for `tough::RepositoryLoader` that uses a `ureq` agent
/// configured with the `platform-verifier` feature, so the OS certificate
/// store is consulted on every TLS handshake (Windows: Crypt32, macOS:
/// Security, Linux: ca-certificates).
///
/// Bridges sync `ureq::Agent::get(...).call()` into the async
/// `tough::Transport::fetch` trait method via `tokio::task::spawn_blocking`.
#[derive(Debug, Clone)]
struct UreqTransport {
    agent: Agent,
}

#[async_trait]
impl Transport for UreqTransport {
    async fn fetch(&self, url: Url) -> std::result::Result<TransportStream, TransportError> {
        let agent = self.agent.clone();
        let url_str = url.to_string();

        // Bridge: ureq is sync; tough::Transport::fetch is async.
        // spawn_blocking runs the sync ureq call on a tokio blocking thread.
        let join_result = tokio::task::spawn_blocking(move || {
            let mut resp = agent.get(&url_str).call()?;
            // Task 1 finding: ureq 3.3.0 exposes `Body::read_to_vec(&mut self)`
            // at src/body/mod.rs:329 → Option A in the plan; no `std::io::Read`
            // import needed.
            resp.body_mut().read_to_vec()
        })
        .await;

        let result = match join_result {
            Ok(r) => r,
            Err(e) => {
                return Err(TransportError::new_with_cause(
                    TransportErrorKind::Other,
                    url.as_str(),
                    e,
                ));
            }
        };

        match result {
            Ok(bytes) => {
                // Emit as a single-chunk stream (tough collects via IntoVec).
                let s = stream::iter(std::iter::once(Ok::<Bytes, TransportError>(Bytes::from(
                    bytes,
                ))));
                Ok(Box::pin(s))
            }
            // tough treats 403/404/410 as FileNotFound so the chain walk
            // can terminate cleanly when the next N+1.root.json doesn't
            // exist. Source: tough-0.22.0/src/http.rs:126-130.
            //
            // NOTE (Codex R-50-10): a corp-proxy returning HTTP 403 for
            // policy-deny reasons is normalized to FileNotFound here, which
            // tough then surfaces as a TUF "target not found" error. That
            // can misdirect debugging (looks like a missing root file
            // when really the proxy is denying access). The HUMAN-UAT
            // residual-risk section in Plan 05 documents this; we cannot
            // distinguish "missing root" from "proxy 403" without an
            // additional discriminator tough does not expose.
            Err(ureq::Error::StatusCode(code)) if code == 403 || code == 404 || code == 410 => {
                Err(TransportError::new(
                    TransportErrorKind::FileNotFound,
                    url.as_str(),
                ))
            }
            Err(e) => Err(TransportError::new_with_cause(
                TransportErrorKind::Other,
                url.as_str(),
                e,
            )),
        }
    }
}

/// Build the `ureq::Agent` used by `UreqTransport`.
///
/// `RootCerts::PlatformVerifier` is the discriminator that triggers the
/// `rustls-platform-verifier` path (gated by the `platform-verifier`
/// feature flag declared in `crates/nono-cli/Cargo.toml`).
///
/// Timeouts match `tough::HttpTransport`'s defaults
/// (`tough-0.22.0/src/http.rs:55-64`): 30s total, 10s connect.
fn build_corp_friendly_agent() -> Agent {
    Agent::config_builder()
        .tls_config(
            TlsConfig::builder()
                .root_certs(RootCerts::PlatformVerifier)
                .build(),
        )
        .timeout_global(Some(Duration::from_secs(30)))
        .timeout_connect(Some(Duration::from_secs(10)))
        .build()
        .new_agent()
}

/// Inner helper: everything that runs AFTER the datastore directory has
/// been created. Used by `refresh_trusted_root_with_transport` so we have
/// a single `Result` to match against for the broadened cleanup path
/// (Codex R-50-05 / D-50-07 literal semantics).
///
/// Phase 50 Plan 04 (Task 1): generalized to take `embedded_root: &[u8]`
/// and an arbitrary `Transport` impl so the test seam can substitute the
/// fixture's `1.root.json` and an in-memory `StaticMapTransport` while
/// driving the SAME chain-walk body production uses (D-50-08).
///
/// Returns `Result<TrustedRoot>` — the caller is responsible for cleanup.
async fn do_refresh_after_datastore_create_with_root(
    metadata_url: Url,
    targets_url: Url,
    datastore_dir: PathBuf,
    transport: impl Transport + 'static,
    embedded_root: &[u8],
) -> Result<TrustedRoot> {
    let repo = RepositoryLoader::new(&embedded_root, metadata_url, targets_url)
        .transport(transport)
        .datastore(datastore_dir)
        .load()
        .await
        .map_err(|e| NonoError::Setup(format!("Sigstore TUF refresh failed: {e}")))?;

    let target_name = TargetName::new(TRUSTED_ROOT_TARGET)
        .map_err(|e| NonoError::Setup(format!("invalid target name: {e}")))?;
    let stream = repo
        .read_target(&target_name)
        .await
        .map_err(|e| NonoError::Setup(format!("read trusted_root target: {e}")))?
        .ok_or_else(|| {
            NonoError::Setup(format!(
                "Sigstore target not found in TUF repo: {TRUSTED_ROOT_TARGET}"
            ))
        })?;

    let bytes = stream
        .into_vec()
        .await
        .map_err(|e| NonoError::Setup(format!("collect trusted_root bytes: {e}")))?;

    let json = std::str::from_utf8(&bytes)
        .map_err(|e| NonoError::Setup(format!("trusted_root.json is not UTF-8: {e}")))?;
    TrustedRoot::from_json(json)
        .map_err(|e| NonoError::Setup(format!("parse trusted_root.json: {e}")))
}

/// Phase 50 Plan 04 Task 1: wider injectable seam.
///
/// Wraps `do_refresh_after_datastore_create_with_root` with the
/// datastore-creation + broadened-cleanup pattern (R-50-05). Public to
/// the crate so the colocated test module (`mod tests`) can drive the
/// SAME chain-walk logic production uses, just with a swapped transport,
/// URLs, datastore, and embedded root anchor.
///
/// Production callers go through `refresh_production_trusted_root` which
/// composes the production values; tests construct each parameter
/// explicitly so the chain-walk is exercised hermetically.
///
/// # Errors
///
/// `NonoError::Setup` for all TUF / transport / parse failures. Best-effort
/// cleanup of `datastore_dir` is performed on ANY failure path after
/// `create_dir_all` succeeds.
pub(crate) async fn refresh_trusted_root_with_transport(
    transport: impl Transport + 'static,
    metadata_url: Url,
    targets_url: Url,
    datastore_dir: PathBuf,
    embedded_root: &[u8],
) -> Result<TrustedRoot> {
    // TUF datastore dir (D-50-07). tough requires this to exist BEFORE
    // .load() is called (Pitfall 2; tough-0.22.0/src/lib.rs:228-231).
    tokio::fs::create_dir_all(&datastore_dir)
        .await
        .map_err(|e| {
            NonoError::Setup(format!(
                "create tuf-cache dir {}: {e}",
                datastore_dir.display()
            ))
        })?;

    // Drive the TUF chain walk + signature verification (all in tough),
    // then fetch + parse the trusted_root.json target. ALL of this is
    // inside the inner helper so we have a single Result to capture for
    // the broadened cleanup path (Codex R-50-05).
    let datastore_for_cleanup = datastore_dir.clone();
    let result = do_refresh_after_datastore_create_with_root(
        metadata_url,
        targets_url,
        datastore_dir,
        transport,
        embedded_root,
    )
    .await;

    // Broadened cleanup (D-50-07 + Codex R-50-05): on ANY error from the
    // inner helper — TUF load, read_target, IntoVec, UTF-8, or
    // TrustedRoot::from_json — best-effort remove the datastore so we
    // don't leave partial state on disk. Cleanup result is ignored;
    // the primary error is what surfaces to the user.
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&datastore_for_cleanup);
    }
    result
}

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
/// is performed on ANY failure path after `create_dir_all` succeeds
/// (D-49-B2 / D-50-07 — broadened per Codex R-50-05).
// Phase 50 Wave 1: this function is still not invoked from any production
// code path; Plan 50-03 swaps `setup.rs::refresh_trust_root_step` to call
// it. The `#[allow(dead_code)]` is removed at that point.
#[allow(dead_code)]
pub async fn refresh_production_trusted_root() -> Result<TrustedRoot> {
    // Phase 50 Plan 04 Task 1 (Codex R-50-07): test-only env-seam.
    //
    // When `NONO_TEST_TUF_FIXTURE` is set in `#[cfg(test)]` builds, redirect
    // to a hermetic StaticMapTransport wired against the named fixture so
    // tests can exercise THIS public wrapper (not just the internal helper).
    // This validates URL composition, agent type, datastore resolution, and
    // delegation to `refresh_trusted_root_with_transport` at the integration
    // boundary — the gap R-50-07 flagged.
    //
    // The entire `if let Ok(...)` block is stripped from release builds by
    // `#[cfg(test)]`, so the env var is unreadable in production and there
    // is zero runtime overhead in `cargo build --release`.
    #[cfg(test)]
    if let Ok(fixture_name) = std::env::var("NONO_TEST_TUF_FIXTURE") {
        return tests::refresh_via_fixture_env_seam(&fixture_name).await;
    }

    // 1. URL setup (mirror sigstore-trust-root tuf.rs:350-354).
    let base_url = Url::parse(DEFAULT_TUF_URL)
        .map_err(|e| NonoError::Setup(format!("invalid Sigstore TUF URL: {e}")))?;
    let metadata_url = base_url.clone();
    let targets_url = base_url
        .join("targets/")
        .map_err(|e| NonoError::Setup(format!("invalid Sigstore targets URL: {e}")))?;

    // 2. TUF datastore dir (D-50-07).
    let datastore_dir = crate::config::nono_home_dir()
        .map_err(|e| NonoError::Setup(format!("resolve nono home dir: {e}")))?
        .join(".nono")
        .join("trust-root")
        .join("tuf-cache");

    // 3. Build agent + transport.
    let agent = build_corp_friendly_agent();
    let transport = UreqTransport { agent };

    // 4. Delegate to the wider seam (Plan 04 Task 1). Production passes the
    //    embedded `PRODUCTION_TUF_ROOT` const as the anchor; tests pass a
    //    fixture's `1.root.json`. The seam owns datastore creation + the
    //    R-50-05 broadened cleanup path.
    refresh_trusted_root_with_transport(
        transport,
        metadata_url,
        targets_url,
        datastore_dir,
        PRODUCTION_TUF_ROOT,
    )
    .await
}
