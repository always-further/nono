---
phase: 50-corp-network-tuf-refresh
reviewed: 2026-05-22T00:00:00Z
depth: standard
files_reviewed: 10
files_reviewed_list:
  - Cross.toml
  - crates/nono-cli/Cargo.toml
  - crates/nono-cli/src/exec_strategy.rs
  - crates/nono-cli/src/exec_strategy/supervisor_linux.rs
  - crates/nono-cli/src/learn.rs
  - crates/nono-cli/src/main.rs
  - crates/nono-cli/src/session_commands.rs
  - crates/nono-cli/src/setup.rs
  - crates/nono-cli/src/trust_refresh.rs
  - docs/cli/development/windows-poc-handoff.mdx
findings:
  critical: 0
  warning: 5
  info: 4
  total: 9
status: issues_found
---

# Phase 50: Code Review Report

**Reviewed:** 2026-05-22
**Depth:** standard
**Files Reviewed:** 10
**Status:** issues_found

## Summary

Phase 50 replaces `reqwest + webpki-roots` (Mozilla bundle) with
`ureq + platform-verifier` (OS root store) for the Sigstore TUF
trusted-root refresh, fixing the failure mode on TLS-inspecting corp
networks.

The net-new code in `crates/nono-cli/src/trust_refresh.rs` is a
near-verbatim port of the upstream `sigstore-trust-root` chain-walk
with a swapped transport and a deliberate cleanup-on-failure pattern
(D-50-07 broadened per R-50-05). The implementation correctly preserves
the tokio runtime (RESEARCH A4 correction) and threads a wider seam
through `refresh_trusted_root_with_transport` so hermetic tests can
swap transport + URLs + datastore + anchor root.

**Adversarial review surfaced no BLOCKER findings.** The security-
critical surfaces (TLS root-store policy, 403/404/410 normalization,
cleanup path) are documented intentional choices that survive scrutiny:
`RootCerts::PlatformVerifier` does not weaken trust-chain validation
(it delegates to the OS verifier, which still enforces self-signed
rejection), the 403 mis-classification risk is acknowledged in Plan 05
HUMAN-UAT, and the cleanup helper properly wraps the entire post-
`create_dir_all` path.

Five WARNINGS surface:
1. WR-01 — Path A (network refresh) skips the freshness gate that Path
   B (`--from-file`) enforces.
2. WR-02 — `refresh_trusted_root_with_transport` wipes the persistent
   TUF datastore cache on transient failures, defeating tough's
   incremental-update optimization.
3. WR-03 — Sync `std::fs::remove_dir_all` is called inside an `async fn`
   without `tokio::fs::remove_dir_all` or `spawn_blocking`, blocking
   the executor thread.
4. WR-04 — `refresh_trust_root_phase_index()` returns the same index
   for both `--refresh-trust-root` and `--from-file`, but they are
   distinct steps that print different banners. Clap `conflicts_with`
   prevents misuse today but the shared helper is a footgun if the
   mutual exclusion is ever relaxed.
5. WR-05 — `UreqTransport::fetch` returns `TransportErrorKind::Other`
   for tokio `JoinError` (panic in blocking task), which `tough`
   surfaces as a generic chain-walk failure rather than an internal
   bug indicator.

Four INFO items track minor maintainability concerns.

## Warnings

### WR-01: Path A skips the trusted_root freshness gate that Path B enforces

**File:** `crates/nono-cli/src/setup.rs:849-872`
**Issue:**
`refresh_trust_root_step` writes the freshly-fetched `TrustedRoot` to
disk via `serde_json::to_string_pretty` + `std::fs::write`, but does
**not** call `nono::trust::bundle::check_trusted_root_freshness` on the
result. The sibling `from_file_step` (lines 918-925) **does** call this
gate. The asymmetry means a network-fetched `trusted_root.json` whose
embedded tlog `validFor.end` has expired will be cached anyway, while
the same JSON loaded via `--from-file` would be rejected.

The realistic exposure is low (a fresh upstream fetch ought to ship a
non-expired tlog), but the gate exists in `from_file_step` precisely
because the supply-chain risk is not zero — Sigstore root rotations
have happened, and the embedded TUF anchor in `sigstore-trust-root`
0.7.0 can ship a soon-to-expire payload. Path A and Path B should
enforce the same validity contract.

**Fix:**
```rust
let trusted_root = rt
    .block_on(crate::trust_refresh::refresh_production_trusted_root())
    .map_err(|e| { /* ... */ })?;

let cache_path = cache_dir.join("trusted_root.json");

// Mirror from_file_step: enforce freshness on Path A too.
nono::trust::bundle::check_trusted_root_freshness(&trusted_root, &cache_path)
    .map_err(|e| {
        NonoError::Setup(format!(
            "fetched Sigstore trusted root failed freshness check: {e}"
        ))
    })?;

let json = serde_json::to_string_pretty(&trusted_root)
    .map_err(|e| NonoError::Setup(format!("serialize trusted root: {e}")))?;
std::fs::write(&cache_path, &json).map_err(NonoError::Io)?;
```

### WR-02: Datastore cleanup on transient failures defeats TUF incremental caching

**File:** `crates/nono-cli/src/trust_refresh.rs:258-260`
**Issue:**
The R-50-05 broadened cleanup unconditionally calls
`std::fs::remove_dir_all(&datastore_for_cleanup)` on ANY error from
`do_refresh_after_datastore_create_with_root`. The datastore lives at
`<nono_home>/.nono/trust-root/tuf-cache/` and is meant to be persistent
across invocations — `tough` uses it to incrementally update from the
last-known root version, avoiding a full N-root chain walk on every
refresh.

Wiping it on every error (including transient network glitches,
proxy 403s misclassified as FileNotFound, momentary `ureq` timeouts)
means the user pays the full chain-walk cost again on the next
attempt, AND any partially-validated state that survived the failure
(e.g. a fresh `2.root.json` from before a downstream `3.root.json`
fetch failed) is lost.

The original D-50-07 intent — "don't leave partial state on disk" —
applies to a **brand-new** datastore created in the same invocation,
not to a long-lived cache. Distinguishing the two cases would let us
keep the cleanup safety for first-run failures while preserving the
cache for subsequent runs.

**Fix:** Track whether `tokio::fs::create_dir_all` created the
directory fresh vs found it existing, and only clean up if it was
freshly created:

```rust
let datastore_existed = tokio::fs::metadata(&datastore_dir).await.is_ok();
tokio::fs::create_dir_all(&datastore_dir).await.map_err(/* ... */)?;

// ... do_refresh_after_datastore_create_with_root ...

// Only wipe on failure if we created the directory in this invocation —
// preserve any pre-existing incremental TUF cache so the next refresh
// can resume from the last-known good root.
if result.is_err() && !datastore_existed {
    let _ = tokio::fs::remove_dir_all(&datastore_for_cleanup).await;
}
```

If the broadened cleanup is intentionally aggressive (fail-clean for
security), document the trade-off explicitly in the module docstring
so the cache-wipe behavior is auditable.

### WR-03: Sync remove_dir_all in async context blocks the tokio executor

**File:** `crates/nono-cli/src/trust_refresh.rs:259`
**Issue:**
The cleanup line uses `std::fs::remove_dir_all`, a blocking call,
inside an `async fn` (`refresh_trusted_root_with_transport`).
Everything else in the same function uses `tokio::fs::create_dir_all`
(line 230). The mix is inconsistent and, depending on directory
contents, can stall the current-thread runtime for a measurable
period — the `tuf-cache` directory can contain dozens of cached
root metadata files.

In production this matters less because `refresh_trust_root_step`
runs on a `new_current_thread()` runtime where blocking is the
norm. But the function is `pub(crate)` and is reused from tests via
the env-seam; future callers on multi-threaded runtimes (e.g. if a
GUI / TUI ever wraps the trust commands) would feel this.

**Fix:**
```rust
if result.is_err() {
    let _ = tokio::fs::remove_dir_all(&datastore_for_cleanup).await;
}
```

(Combine with WR-02's conditional cleanup for full effect.)

### WR-04: `refresh_trust_root_phase_index` is shared by two distinct steps

**File:** `crates/nono-cli/src/setup.rs:803-818, 836, 901`
**Issue:**
`refresh_trust_root_phase_index()` returns a single value that is
reused as the phase index for both `refresh_trust_root_step` (line
836) and `from_file_step` (line 901), printing banners like
`[3/N] Refreshing Sigstore trusted root...` vs
`[3/N] Loading Sigstore trusted root from file...`.

This is correct **only because** clap declares
`conflicts_with = "refresh_trust_root"` on `from_file` (cli.rs:2382),
making them mutually exclusive at parse time. If that clap constraint
is ever loosened — and `total_phases()` already uses `||` so it
wouldn't tip the failure into a panic — the two steps would silently
share the same phase number, producing UX like:
```
[3/5] Refreshing Sigstore trusted root...
[3/5] Loading Sigstore trusted root from file...
```

The fragility lives in the implicit assumption that two execution
arms are mutually exclusive based on a clap declaration in a
different file. The defense is structural, not logical.

**Fix:** Either rename `refresh_trust_root_phase_index()` to
`trust_root_provisioning_phase_index()` and add a `debug_assert!(
self.refresh_trust_root ^ self.from_file.is_some()
|| !(self.refresh_trust_root || self.from_file.is_some()))`, or split
into two helper methods that each route through the same body. The
goal is to make the mutual-exclusion contract visible in `setup.rs`
itself, not buried in a clap attribute.

### WR-05: tokio JoinError surfaces as opaque `TransportErrorKind::Other`

**File:** `crates/nono-cli/src/trust_refresh.rs:88-98`
**Issue:**
When `tokio::task::spawn_blocking` returns `Err(JoinError)` — caused
by a panic inside the blocking task — the code maps it to
`TransportError::new_with_cause(TransportErrorKind::Other, ...)`. The
problem is that `tough` does not distinguish "Other" from "actual
network failure", so a panic inside the `ureq` agent (or a
cancellation, also represented as `JoinError`) surfaces in the
user-visible error as `"Sigstore TUF refresh failed: ..."` rather
than as an internal-bug indicator.

For corp-network debugging this matters: an operator reading the
v0.53.x+ caveats in `windows-poc-handoff.mdx` will look at a
JoinError-derived message and reasonably (but wrongly) conclude
their proxy is the problem.

**Fix:**
```rust
Err(e) => {
    // tokio JoinError is either a panic in the blocking task or a
    // cancellation — both are internal nono bugs, not transport
    // failures. Log loudly and surface as a SandboxInit-equivalent
    // signal that gets the user to a bug report, not a corp-network
    // troubleshooting page.
    tracing::error!("internal bug: ureq blocking task did not complete: {e}");
    return Err(TransportError::new_with_cause(
        TransportErrorKind::Other,
        url.as_str(),
        std::io::Error::other(format!("internal: spawn_blocking failed: {e}"))
    ));
}
```

Better still, propagate a panic by re-panicking on the supervisor
thread so the panic hook fires (this is the standard
`tokio::task::spawn_blocking` pattern when the spawned task is
trusted code):

```rust
let result = join_result.unwrap_or_else(|e| {
    if e.is_panic() {
        std::panic::resume_unwind(e.into_panic())
    }
    // Cancellation — surface a typed error.
    panic!("ureq blocking task cancelled unexpectedly: {e}");
});
```

(This is the only place in the file where panic-vs-error
discrimination matters; the rest of the chain walk has well-typed
error paths.)

## Info

### IN-01: `refresh_trust_root_phase_index` returns a hardcoded 3 on non-Windows

**File:** `crates/nono-cli/src/setup.rs:817`
**Issue:**
The non-Windows arm `3` is opaque. It happens to be correct because
on Linux/macOS the phase ordering is fixed (Install check 1, Sandbox
test 2, then trust-root step 3 if requested), but a future addition of
a non-Windows step between sandbox-test and trust-root would silently
shift the displayed index without the compiler catching the drift.

**Fix:** Either compute it from `protection_phase_index() - 1` (the
trust-root step prints immediately before protection summary), or
introduce a small `const PHASE_BEFORE_TRUST_ROOT: usize = 2;` so the
intent is grep-able.

### IN-02: `do_refresh_after_datastore_create_with_root` takes &[u8] but is bound to `'static` via `+ 'static` on transport

**File:** `crates/nono-cli/src/trust_refresh.rs:167-202`
**Issue:**
The helper signature is:
```rust
async fn do_refresh_after_datastore_create_with_root(
    metadata_url: Url,
    targets_url: Url,
    datastore_dir: PathBuf,
    transport: impl Transport + 'static,
    embedded_root: &[u8],
) -> Result<TrustedRoot> {
```

Note `transport: impl Transport + 'static` but `embedded_root: &[u8]`
without an explicit lifetime tied to the future. This compiles
because `RepositoryLoader::new(&embedded_root, ...)` consumes it
synchronously before any `.await`, but the call site
`RepositoryLoader::new(&embedded_root, metadata_url, targets_url)`
takes a `&&[u8]`. If `tough` ever changes `RepositoryLoader::new` to
hold the root bytes across an `.await`, this breaks in a non-obvious
way.

**Fix:** Take `embedded_root: Vec<u8>` (owned) so the lifetime is
unambiguous, or document that the byte slice MUST be consumed before
the first `.await`.

### IN-03: Hardcoded timeout values duplicate tough's defaults silently

**File:** `crates/nono-cli/src/trust_refresh.rs:150-151`
**Issue:**
The timeouts `30s` and `10s` are hardcoded as literal `Duration::from_secs(30)` /
`Duration::from_secs(10)` to "match tough's defaults". If tough bumps its
defaults (it's a minor-version-bumpable change), nono's behavior silently
drifts from the upstream contract.

**Fix:** Either expose these as `const TUF_TIMEOUT_GLOBAL: Duration` /
`const TUF_TIMEOUT_CONNECT: Duration` at the top of the module with a
comment naming the tough version they mirror, OR pull them from a
public tough constant if one exists.

### IN-04: Test 6 holds `ENV_LOCK` across an `.await` boundary (explicitly waived but coupling-prone)

**File:** `crates/nono-cli/src/trust_refresh.rs:692-712`
**Issue:**
The test acquires `ENV_LOCK` (a sync `Mutex<()>`) before setting
`NONO_TEST_TUF_FIXTURE`, then `.await`s the public wrapper. The
`#[allow(clippy::await_holding_lock)]` annotation acknowledges this,
and the rationale (the env var MUST stay set across the await) is
sound — but it bakes in a per-test serialization that scales with the
number of tests sharing `ENV_LOCK` plus their longest hermetic
chain-walk. Today that's milliseconds; if the suite ever adds
expensive trust-root tests, the serialized awaiting becomes the
bottleneck for parallel test execution.

The cited tracking issue (`always-further/nono#567`) is about
eliminating env var mutation from tests entirely, which is the
right long-term direction. No immediate fix needed; flagging so the
coupling is visible if the test suite grows.

---

_Reviewed: 2026-05-22_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
