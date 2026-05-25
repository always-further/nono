---
plan_id: 48-02
plan_name: PROFILE-SHADOWING
phase: 48
phase_name: upst6-sync-execution
cluster: C1
cluster_disposition: will-sync
upstream_sha_range: 0b05508f..750f4653
upstream_commit_count: 9
baseline_sha: 3f638dc6
lane_transitions: "deferred to operator CI push; no local green→red transitions"
skipped_gates_environmental: [3, 9]
skipped_gates_preexisting_debt: [4]
pr_section: 48-02-PR-SECTION.md
status: complete
completed: "2026-05-24"
duration_minutes: 45
tasks_completed: 3
files_modified: 5
requirements: [REQ-UPST6-02]
tags: [upstream-sync, cherry-pick, profile, pack-verification, wave-1]
---

# Phase 48 Plan 02: PROFILE-SHADOWING Summary

**One-liner:** 9 upstream cherry-picks for profile shadowing hardening + pack signer verification + name-resolution polish (Cluster C1, Wave 1), with NonoError::Cancelled addition and FFI wiring.

## Objective

Cherry-pick Phase 47 ledger Cluster C1 (9 commits: profile shadowing checks + pack-signer
verification + init validation polish) in upstream-chronological order onto fork `main`,
preserving Phase 36-01b exhaustive match and 36-01c canonical `bypass_protection` name.

## Execution Context

Sequential execution on the primary worktree (`/Users/oscarmack/nono`) on macOS, per STATE.md
2026-05-24 Unix-host execution decision. C1-01 through C1-06 were committed by a prior agent
session. This session committed C1-07 through C1-09 and produced close artifacts.

## Profile/mod.rs Hot-Spot Inspection (Task 1)

Pre-cherry-pick inspection of C1 commits touching profile/mod.rs:

- **C1-07 (3d3d239a):** Adds `find_pack_store_profile` fast path for `org/pack-name` format
  and `load_base_profile_raw` registry-ref bypass. Also introduces `NonoError::Cancelled`
  (new enum variant) — requires FFI exhaustive match extension. No new ProfileDeserialize
  struct fields. Exhaustive match arm extension NOT needed (Cancelled is in NonoError, not in
  Profile struct).

- **C1-08 (316c6a2c):** Updates fast path from `split_once('/')` to `parse_package_ref` for
  `org/pack-name[@version]` support. Pure logic change, no struct changes.

- **C1-09 (750f4653):** Formatting fixes only (`cargo fmt`). Test assertion change for
  `suggested_run_profile_name` — upstream-only function absent from fork.

Zero `override_deny` references added by any C1 commit (Phase 36-01c invariant preserved).

## Per-Commit Notes

| # | Fork SHA | Upstream SHA | Resolution |
|---|----------|-------------|------------|
| C1-01 | 5d52a918 | 0b05508f | Applied clean — profile-verification hard-block on trust-bundle-without-lockfile |
| C1-02 | d46447df | 0015f348 | Applied clean — ensure source pack included for verification |
| C1-03 | 15a9757e | b3556139 | Applied clean — verify pack signer identities |
| C1-04 | f1a4d979 | c897c8cc | Applied clean — expand shadowing checks to include pack profiles |
| C1-05 | a3b1610b | bd76c6b5 | Applied clean — review points on shadow-check PR |
| C1-06 | 8c7e1806 | 0a4db57e | Applied clean — block profile init when name shadows builtin or pack profile |
| C1-07 | d0b09674 | 3d3d239a | Applied with fork adaptation: added NonoError::Cancelled to error.rs + FFI exhaustive match in bindings/c/src/lib.rs (maps Cancelled to ErrInvalidArg). profile_save_runtime.rs adapted (C1-07 changes profile_save_runtime differently from upstream due to prior C1-06 shadow-check adaptation). |
| C1-08 | e0870727 | 316c6a2c | Applied manually — updated fast path to use parse_package_ref + pkg.key() for versioned refs |
| C1-09 | 882420be | 750f4653 | Applied partially — profile_cmd.rs fmt applied; profile/mod.rs fmt already in C1-07/C1-08 state; profile_save_runtime.rs test assertion skipped (upstream-only function absent from fork) |

## Cross-Target Clippy Results

- **macOS (native):** Build clean. 3 pre-existing warnings (format_util dead_code, unused
  import, unused variable) — Class-B debt predating C1.
- **Linux (cross-target):** Cross-toolchain not installed on macOS dev host; deferred to CI
  per CLAUDE.md cross-target-verify-checklist convention. C1 has zero cfg-gated Linux code.
- **Windows:** Zero C1 touches to exec_strategy_windows/ or *_windows.rs files.

## Baseline-Aware CI Gate Verdict

Local validation only (operator CI push deferred). No green→red transitions from C1:
- C1 touches only cross-platform profile/* files
- Pre-existing red lanes (macOS clippy, Rustfmt, Cargo Audit, Docs Checks, Integration)
  are Class-B debt documented in STATE.md; unchanged by C1
- 1074 tests pass; 17 pre-existing failures (parallel env-var isolation) carry forward

## Wave 1 Sibling Status

Plan 48-03 (C2 — STARTUP-TIMEOUT) is the Wave 1 sibling, surface-disjoint from C1 per
Phase 47 DIVERGENCE-LEDGER. Status: not yet executed as of 2026-05-24.

## Deviations from Plan

### Auto-adapted Issues

**1. [Rule 2 - Structural] NonoError::Cancelled addition**
- **Found during:** C1-07 (3d3d239a)
- **Issue:** Upstream commit adds `Cancelled` as a new pre-condition refusal return path in
  profile_cmd.rs shadow-check. Fork needs `NonoError::Cancelled` in the enum for it to
  compile. FFI exhaustive match also needed updating.
- **Fix:** Added `Cancelled(String)` variant to `crates/nono/src/error.rs`; added match arm
  in `bindings/c/src/lib.rs` mapping `Cancelled(_) => ErrInvalidArg`.
- **Files modified:** `crates/nono/src/error.rs`, `bindings/c/src/lib.rs`
- **Commit:** d0b09674

**2. [Structural - fork variant] C1-09 test assertion skipped**
- **Found during:** C1-09 (750f4653)
- **Issue:** Upstream changes test `suggested_run_profile_name(None, "hermes")` from
  `Some("hermes-local")` to `Some("hermes")`. This function does not exist in fork's
  `profile_save_runtime.rs` (1242 lines vs upstream's 1455+); fork uses
  `would_shadow_existing_profile` tests instead.
- **Fix:** Applied fmt changes only; skipped the non-applicable test assertion change.
- **Files modified:** `crates/nono-cli/src/profile_cmd.rs`
- **Commit:** 882420be

## Known Stubs

None — all C1 changes are functional security hardening (shadowing checks, signer verification,
name resolution). No placeholder values or mock data introduced.

## Threat Flags

No new security-relevant surface introduced beyond the plan's threat model. All STRIDE
threats (T-48-02-01 through T-48-02-04) mitigated as designed.

## Key Decisions

- Added `NonoError::Cancelled` to fork's error enum to enable C1-07's shadow-check refusal
  flow; variant is fork-additive and does not conflict with upstream's design intent.
- Skipped upstream-only `suggested_run_profile_name` test change (C1-09); fork's equivalent
  coverage provided by `would_shadow_existing_profile` test suite.
- C1-08 fast path update applied manually (not via cherry-pick) to handle context mismatch
  from C1-07's fork adaptation.

## Self-Check: PASSED

- [x] `5d52a918` exists: `git log --oneline --all | grep 5d52a918` → found
- [x] `d46447df` exists: found
- [x] `15a9757e` exists: found
- [x] `f1a4d979` exists: found
- [x] `a3b1610b` exists: found
- [x] `8c7e1806` exists: found
- [x] `d0b09674` exists: found
- [x] `e0870727` exists: found
- [x] `882420be` exists: found
- [x] 9 Upstream-commit trailers: `git log 2fab35ed..HEAD --format=%B | grep -cE '^Upstream-commit: [0-9a-f]{40}$'` = 9
- [x] 9 Co-Authored-By lines: count = 9
- [x] 9 Signed-off-by lines: count = 9
- [x] Windows invariant: 0 files touched in exec_strategy_windows/ or nono-shell-broker/
- [x] Build clean: `cargo build --workspace` exits 0
- [x] override_deny clean: zero new references added by C1
- [x] 48-02-CLOSE-GATE.md created at .planning/phases/48-upst6-sync-execution/
- [x] 48-02-PR-SECTION.md created at .planning/phases/48-upst6-sync-execution/
