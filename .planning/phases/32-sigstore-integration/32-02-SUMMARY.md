---
phase: 32
plan: "02"
subsystem: trust
tags: [sigstore, tuf, cache, fail-closed, library-api-change, offline-verify]
dependency_graph:
  requires: ["32-01"]
  provides: ["load_production_trusted_root-sync", "nono-setup-refresh-trust-root", "verify-is-offline-invariant"]
  affects: ["trust_cmd.rs", "trust_intercept.rs", "trust_scan.rs", "package_cmd.rs", "setup.rs"]
tech_stack:
  added: []
  patterns:
    - "Cache-then-verify pattern: nono setup writes cache, nono trust verify reads it (offline)"
    - "Howard Hinnant civil-from-days algorithm for ISO-8601 dates without chrono (D-19 compliance)"
    - "TestHomeGuard RAII guard for parallel-safe env var mutation in unit tests"
    - "Print_trust_root_status: cross-platform --check-only trust cache reporter"
key_files:
  created: []
  modified:
    - crates/nono/src/trust/bundle.rs
    - crates/nono-cli/src/setup.rs
    - crates/nono-cli/src/cli.rs
    - crates/nono-cli/src/trust_cmd.rs
    - crates/nono-cli/src/trust_intercept.rs
    - crates/nono-cli/src/trust_scan.rs
    - crates/nono-cli/src/package_cmd.rs
    - crates/nono-cli/tests/setup_trust_root.rs
    - crates/nono-cli/tests/keyless_offline_invariant.rs
    - tests/integration/test_upstream_drift.sh
decisions:
  - "sync cache-read replaces async TrustedRoot::production() in verify path (D-32-01)"
  - "home_dir_from_env() uses std::env only: no dirs dep in crates/nono (P32-CHK-002 / D-32-15)"
  - "expiry detection: any_active logic treats None end as no-expiry (Pitfall 3 from RESEARCH)"
  - "string-prefix comparison for ISO-8601 dates is fail-closed-correct (T-32-02-07 accepted)"
  - "refresh_trust_root_step uses ONE-SHOT tokio runtime; no admin check per Pitfall 7"
metrics:
  duration: "~120 minutes (two sessions due to context continuity)"
  completed: "2026-05-10"
  tasks_completed: 2
  files_modified: 16
---

# Phase 32 Plan 02: TUF Cache Rewrite + Setup Subcommand Summary

Sync cache-read replaces async TUF network call in verify path; `nono setup --refresh-trust-root` hydrates the cache; verify-is-offline invariant tested structurally and dynamically.

## Tasks Completed

| Task | Description | Commit |
|------|-------------|--------|
| Task 1 | Rewrite load_production_trusted_root as sync cache read; migrate 2 failing tests; drop 6 rt.block_on callers | ee1ae16c |
| Task 2 | Add nono setup --refresh-trust-root subcommand; fill in 2 integration test scaffolds | 0a8a206f |

## Task 1 Details

### Originally-Failing Tests — Now Passing

Both tests previously failed because `TrustedRoot::production().await` hit TUF network with stale bundled metadata ("0 valid signatures of required 3"):

```
test trust::bundle::tests::load_production_trusted_root_succeeds ... ok  (was: FAILED)
test trust::bundle::tests::verify_bundle_with_invalid_digest ... ok       (was: FAILED)
```

Migrated to use `crate::trust::load_test_trusted_root()` (Phase 32 Plan 01's frozen fixture).

### load_production_trusted_root Rewrite

`pub async fn` → `pub fn` (signature change, D-32-15 deliberate fork enumeration).

New implementation reads from `<nono_home_dir()>/.nono/trust-root/trusted_root.json` synchronously:

- **D-32-05**: missing cache → `TrustPolicy("Sigstore trusted root not initialized; run nono setup --refresh-trust-root")`
- **D-32-03**: all-expired tlogs → `TrustVerification { reason: "Sigstore trusted root expired ...; run nono setup --refresh-trust-root" }`
- Fresh cache → `Ok(TrustedRoot)`

`home_dir_from_env()` resolves home directory using `std::env` only (Windows: USERPROFILE / HOMEDRIVE+HOMEPATH; Unix: HOME). No `dirs` dep added to `crates/nono` (P32-CHK-002 / D-32-15 enforcement).

`current_date_iso_prefix_for_secs(secs: u64) -> String` uses Howard Hinnant civil-from-days algorithm (avoids `chrono`, preserves D-19).

### P32-CHK-013: Epoch Regression Guard

Pinned 4 known epoch seconds → expected ISO-8601 dates (all correct):
- `1_778_284_800` → `"2026-05-09"` (day of planning, verified via Python)
- `1_704_067_200` → `"2024-01-01"`
- `951_782_400` → `"2000-02-29"` (leap year sentinel)
- `0` → `"1970-01-01"` (epoch sentinel)

Note: Plan source listed `1_778_544_000` as "2026-05-09" — this was incorrect (actual = 2026-05-12). Correct value `1_778_284_800` was computed and used.

### The 6 Caller Sites Updated (Drop rt.block_on)

| File | Line range (approx) | Function |
|------|---------------------|----------|
| `crates/nono-cli/src/trust_cmd.rs` | ~907-913 | `verify_multi_subject_file` keyless arm |
| `crates/nono-cli/src/trust_cmd.rs` | ~1027-1033 | `verify_single_file` keyless arm |
| `crates/nono-cli/src/trust_intercept.rs` | ~371-376 | keyless arm |
| `crates/nono-cli/src/trust_scan.rs` | ~247-255 | `verify_keyless_policy_bundle` |
| `crates/nono-cli/src/trust_scan.rs` | ~753-760 | `verify_keyless_crypto` |
| `crates/nono-cli/src/package_cmd.rs` | ~446-452 | package verification |

Pattern before: `let rt = tokio::runtime::Builder::new_current_thread()...; let trusted_root = rt.block_on(trust::load_production_trusted_root())...`

Pattern after: `let trusted_root = trust::load_production_trusted_root()...`

Orphaned runtime variables and imports removed where the runtime existed solely for this call.

### Upstream-Drift Sentinel Annotated

`tests/integration/test_upstream_drift.sh` line 257 annotated:
```sh
'load_production_trusted_root'  # intentional fork: Phase 32 D-32-01
```

### New Unit Tests Added (bundle.rs)

5 new unit tests added to the test module:
- `cache_round_trip` — D-32-01: write frozen fixture to temp cache, read back via load_production_trusted_root
- `missing_cache_fails_closed` — D-32-05: TrustPolicy error when no cache
- `expired_cache_fails_closed_with_recovery_hint` — D-32-03: TrustVerification error when all tlogs expired
- `load_test_trusted_root_smoke` — D-32-06: frozen fixture helper smoke test
- `current_date_iso_prefix_pins_known_dates` — P32-CHK-013: epoch regression guard

All 5 use `TestHomeGuard` RAII (acquires `static ENV_LOCK: Mutex<()>` before `set_var`) for parallel-safe env isolation per CLAUDE.md.

## Task 2 Details

### nono setup --refresh-trust-root Subcommand

- `SetupArgs.refresh_trust_root: bool` added to `cli.rs`
- `SetupRunner.refresh_trust_root: bool` added to `setup.rs`
- `refresh_trust_root_step()` method: ONE-SHOT tokio runtime calls `nono::trust::TrustedRoot::production()` (full TUF verification, T-32-02-01), serializes to JSON, writes to `<nono_home_dir()>/.nono/trust-root/trusted_root.json`
- Dispatch in `run()`: NOT wrapped in `#[cfg(target_os = "windows")]` (cross-platform per D-32-01), NOT gated on `is_admin_process()` (per-user, Pitfall 7)
- `total_phases()`, `protection_phase_index()`, `profiles_phase_index()` updated to count the trust-root step

### --check-only Trust Root Status

`print_trust_root_status(prefix: &str)` function added (cross-platform):
- NOT INITIALIZED → `"Trust root cache: NOT INITIALIZED (run \`nono setup --refresh-trust-root\`)"`
- STALE (expired) → `"Trust root cache: STALE — {library_error_message}"` (contains literal `"nono setup --refresh-trust-root"` per D-32-03 wording)
- OK → `"Trust root cache: OK (/path/to/trusted_root.json)"`

Called from both Windows and non-Windows `print_check_only_summary()` paths.

### Integration Tests

**`crates/nono-cli/tests/setup_trust_root.rs`** (3 tests):
- `setup_check_only_reports_uninitialized_cache` — hermetic, asserts "NOT INITIALIZED" substring
- `setup_check_only_reports_stale_cache_with_recovery_hint` — hermetic, writes expired root, asserts "STALE" and "nono setup --refresh-trust-root"
- `setup_refresh_trust_root_writes_cache` — `#[ignore]`, requires network (D-32-07 hermetic CI policy)

**`crates/nono-cli/tests/keyless_offline_invariant.rs`** (1 test):
`verify_path_uses_no_async_network_io` — P32-CHK-004 fix:
1. Structural: source-greps `bundle.rs::verify_bundle` and `bundle.rs::verify_bundle_with_digest` bodies for `.await`, `reqwest::`, `hyper::`, `tokio::net`, `Runtime::new`, `.block_on(`, `ureq::` — asserts zero hits
2. Structural: greps `trust_cmd.rs` Keyless match arms for same tokens — asserts 2+ arms found, all clean
3. Dynamic: spawns `std::thread` without tokio runtime, calls `verify_bundle_with_digest` on stub bundle, asserts no panic on "no reactor running"

## VALIDATION.md Row Transitions

| Decision | Status Before | Status After |
|----------|--------------|--------------|
| D-32-01 (sync cache-read) | pending | green — load_production_trusted_root is sync, reads from cache |
| D-32-02 (frozen fixture migration) | pending | green — 2 originally-failing tests now pass |
| D-32-03 (expiry gate) | pending | green — expired_cache_fails_closed_with_recovery_hint passes |
| D-32-05 (missing cache) | pending | green — missing_cache_fails_closed passes |
| D-32-06 (test seam smoke) | pending | green — load_test_trusted_root_smoke passes |
| D-32-15 (no dirs dep, sync signature) | pending | green — home_dir_from_env + fmt change |
| P32-CHK-002 (no dirs in nono/Cargo.toml) | pending | green — verified 0 matches |
| P32-CHK-004 (verify-is-offline) | pending | green — structural+dynamic test |
| P32-CHK-012 (STALE surfaces recovery cmd) | pending | green — integration test asserts literal |
| P32-CHK-013 (epoch regression guard) | pending | green — 4 epoch values pinned |

## Deviations from Plan

### Auto-fixed Issues (Rule 3: Blocking Issues)

**1. [Rule 3 - Blocking] Pre-existing clippy errors in nono-cli test targets**
- **Found during:** Task 1 verification
- **Issue:** Multiple `doc list item without indentation` errors in `labels_guard.rs`, `supervisor.rs`, `registry_client.rs`; `collapsible_match` in `manifest.rs` and `supervisor.rs`; `useless_vec` in `audit_commands.rs`; redundant import in `audit_session.rs`
- **Fix:** Restructured doc comments to avoid `+` and em-dash list markers, collapsed match guards, fixed vec to array, removed redundant import. Applied `cargo fmt --all` to normalize formatting across touched files.
- **Files modified:** `exec_strategy_windows/labels_guard.rs`, `exec_strategy_windows/supervisor.rs`, `registry_client.rs`, `manifest.rs`, `audit_commands.rs`, `audit_session.rs`, `exec_strategy_windows/launch.rs`, `rollback_runtime.rs`, `tests/adr_aipc_unix_futures.rs`, `tests/audit_attestation.rs`
- **Commit:** ee1ae16c (included in Task 1 commit)

**2. [Rule 1 - Bug] Wrong epoch value in P32-CHK-013 test**
- **Found during:** Task 1 implementation
- **Issue:** Plan source stated `1_778_544_000` = 2026-05-09, but actual = 2026-05-12. Python-verified correct: `1_778_284_800` = 2026-05-09.
- **Fix:** Used correct epoch value. All 4 pinned dates now verified correct.
- **Commit:** ee1ae16c

**3. [Rule 1 - Bug] Invalid base64 key in expired-cache test fixture**
- **Found during:** Task 1 implementation
- **Issue:** Fake `rawBytes` in the expired trusted-root JSON caused `TrustedRoot::from_file` to fail with "Invalid symbol 61, offset 60" (base64 decode error), preventing the expiry test from reaching the freshness check.
- **Fix:** Replaced fake key with real ECDSA P-256 DER-encoded key from the frozen fixture.
- **Commit:** ee1ae16c

**4. [Rule 1 - Bug] TransparencyLogInstance.public_key field is PublicKey (NOT Option<PublicKey>)**
- **Found during:** Task 1 implementation
- **Issue:** Plan pseudocode showed `.as_ref()` on `public_key` as if it were `Option<PublicKey>`, but the sigstore-trust-root-0.6.5 struct has `public_key: PublicKey` (non-optional). The `valid_for: Option<ValidityPeriod>` IS optional.
- **Fix:** Wrote `check_trusted_root_freshness` without the `as_ref()` on `public_key`, going directly to `.valid_for.as_ref()`.
- **Commit:** ee1ae16c

**5. [Rule 3 - Blocking] nono-cli test struct initializer missing refresh_trust_root field**
- **Found during:** Task 2 verification (clippy --tests)
- **Issue:** Existing test in `setup.rs::tests` initialized `SetupRunner { ... }` struct literal, which became a compile error after adding the new field.
- **Fix:** Added `refresh_trust_root: false` to the test's struct literal.
- **Commit:** 0a8a206f

**6. [Rule 2 - Missing functionality] sigstore_verify not a direct nono-cli dependency**
- **Found during:** Task 2 implementation
- **Issue:** Plan showed `sigstore_verify::trust_root::TrustedRoot::production()` but `sigstore-verify` is not a direct dep of `nono-cli` — it's a dep of `nono` crate only. Using it directly would require adding a dep.
- **Fix:** Used `nono::trust::TrustedRoot::production()` instead, since `TrustedRoot` is re-exported from `nono::trust` and carries the `production()` async method.
- **Commit:** 0a8a206f

## Known Stubs

None. All integration test assertions are load-bearing. The network-only test `setup_refresh_trust_root_writes_cache` is `#[ignore]`d per D-32-07 (hermetic CI policy); it is an intentional stub preserved for manual operator verification.

## Self-Check

### Created/Modified File Existence

- `crates/nono/src/trust/bundle.rs` — FOUND (modified)
- `crates/nono-cli/src/setup.rs` — FOUND (modified)
- `crates/nono-cli/src/cli.rs` — FOUND (modified)
- `crates/nono-cli/tests/setup_trust_root.rs` — FOUND (replaced)
- `crates/nono-cli/tests/keyless_offline_invariant.rs` — FOUND (replaced)

### Commits Verified

- `ee1ae16c` — FOUND (Task 1: load_production_trusted_root rewrite)
- `0a8a206f` — FOUND (Task 2: setup --refresh-trust-root subcommand)

## Self-Check: PASSED
