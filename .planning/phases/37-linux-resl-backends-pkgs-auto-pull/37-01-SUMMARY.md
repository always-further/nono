---
phase: 37-linux-resl-backends-pkgs-auto-pull
plan: 01
subsystem: error-types
tags: [error-variant, ffi, cgroup-v2, linux, fail-closed, abi-stable]

requires:
  - phase: 25-cross-platform-resl-aipc-unix-design
    provides: CgroupSession + cgroup-v2 detect_from_str / detect / new lifecycle in supervisor_linux.rs (the 5 detection sites this plan touches)
  - phase: 25-cross-platform-resl-aipc-unix-design
    provides: NotSupportedOnPlatform struct-variant precedent + FFI exhaustive-match convention (mirrored 1:1 by Plan 37-01)

provides:
  - NonoError::UnsupportedKernelFeature { feature, hint } typed error variant for kernel-misconfigured hosts (distinct from UnsupportedPlatform + NotSupportedOnPlatform)
  - 4 of 5 cgroup-v2 detection sites in supervisor_linux.rs now emit the typed variant carrying the LOCKED `cgroup_no_v1=all` boot-flag hint (Phase 37 D-07)
  - 1 of 5 cgroup-v2 detection sites (path-traversal guard) intentionally preserved as UnsupportedPlatform with explicit Phase 37 D-07 KEEP comment
  - FFI exhaustive-match arm UnsupportedKernelFeature -> ErrUnsupportedPlatform (Phase 37 D-06; ABI stable — NO new NonoErrorCode entry)
  - Closes silent-no-op security regression on cgroup-v1 hosts (REQ-RESL-NIX-01 / 02 / 03 acceptance #3): `--memory` / `--cpu-percent` / `--max-processes` now fail closed with a typed actionable hint

affects: [37-02, 37-03, 37-04, nono-py, nono-ts]

tech-stack:
  added: []
  patterns:
    - "Typed kernel-feature error: struct variant `UnsupportedKernelFeature { feature: String, hint: String }` whose Display string starts with the LOCKED `Kernel feature not supported:` prefix and embeds the LOCKED boot-flag hint"
    - "FFI ABI stability via error-code reuse: net-new Rust variant maps to an EXISTING `NonoErrorCode` (no new enum entry) — FFI consumers read the typed feature+hint via `nono_last_error()` Display"
    - "Site-by-site disposition: 4 sites swapped to typed variant; 1 site explicitly kept as `UnsupportedPlatform` with inline `Phase 37 D-07: KEEP` comment documenting why the boot-flag hint would mislead (kernel fine; /proc tampering)"
    - "Test convention: 4 new Linux-gated unit tests in a dedicated `unsupported_kernel_feature_swap_tests` module, plus 3 pre-existing tests updated to assert the new typed variant (the old `UnsupportedPlatform` assertions would have silently re-masked the silent-no-op vulnerability)"

key-files:
  created:
    - .planning/phases/37-linux-resl-backends-pkgs-auto-pull/37-01-SUMMARY.md
    - .planning/phases/37-linux-resl-backends-pkgs-auto-pull/deferred-items.md
  modified:
    - crates/nono/src/error.rs
    - bindings/c/src/lib.rs
    - crates/nono-cli/src/exec_strategy/supervisor_linux.rs
    - crates/nono-cli/src/exec_strategy.rs
    - crates/nono-cli/src/launch_runtime.rs

key-decisions:
  - "D-05 implemented: net-new `NonoError::UnsupportedKernelFeature { feature: String, hint: String }` variant added (distinct from existing UnsupportedPlatform and NotSupportedOnPlatform). Display format LOCKED as `Kernel feature not supported: {feature} ({hint})`."
  - "D-06 implemented: FFI `map_error` reuses `NonoErrorCode::ErrUnsupportedPlatform` for the new variant — NO new FFI error code is added (ABI stability). FFI consumers read the typed feature+hint via the Display string from `nono_last_error()`."
  - "D-07 implemented: 4 of 5 cgroup-v2 detection sites (sites 1+2+3+5a+5b+5c) now emit `UnsupportedKernelFeature` carrying the LOCKED hint `cgroup v2 required; boot with systemd.unified_cgroup_hierarchy=1 or cgroup_no_v1=all`. Site 4 (path-traversal guard) deliberately preserved as `UnsupportedPlatform` with explicit `Phase 37 D-07: KEEP` comment — kernel is fine, /proc is tampered, boot-flag would mislead."
  - "D-08 honored implicitly: the swapped sites fire only when `cgroup::detect()` is called (i.e., when the supervisor is about to apply resource limits in `apply_resource_limits_unix`). User must have passed `--memory` / `--cpu-percent` / `--max-processes` for detect() to run, matching the D-08 'detection at sandbox setup, pre-fork, per resource flag' clause."
  - "Pre-existing tests at lines 1308-1335 of supervisor_linux.rs (`detect_from_str_cgroup_v1_rejected`, `detect_from_str_hybrid_rejected`, `detect_from_str_empty_rejected`) UPDATED to assert the new typed variant. Leaving them on `UnsupportedPlatform` would have silently re-masked the silent-no-op vulnerability — these are in-scope changes, not deviations."
  - "Doc comments referring to `UnsupportedPlatform(\"cgroup_v2: ...\")` in supervisor_linux.rs (CgroupSession header), exec_strategy.rs (apply_resource_limits_unix), and launch_runtime.rs (resource-limits architecture comment) updated to advertise the new typed variant. These are documentation-of-behavior updates, not behavior changes."

patterns-established:
  - "Three-surface touch for a typed Rust error variant: (1) library variant + tests, (2) FFI exhaustive arm + test (compiler-enforced via non-exhaustive-patterns error), (3) production call-site swap + new behavioral test + updated old behavioral tests. Mirrors Phase 25-01 NotSupportedOnPlatform precedent."
  - "Partial-disposition convention: when N-of-M call sites switch to a new variant and M-N sites stay, the staying sites carry an explicit `// Phase XX D-YY: KEEP as <OldVariant>` comment so future readers see the disposition rationale inline rather than having to git-blame back to the plan."

requirements-completed: [REQ-RESL-NIX-01, REQ-RESL-NIX-02, REQ-RESL-NIX-03]

duration: ~60min
completed: 2026-05-19
---

# Phase 37 Plan 01: Typed UnsupportedKernelFeature Variant + 4-of-5 cgroup-v2 Detection Swap Summary

**Three-surface touch — `NonoError::UnsupportedKernelFeature { feature, hint }` variant + FFI map_error exhaustive arm + 4 of 5 cgroup-v2 detection-site swaps in `supervisor_linux.rs` — closes the cgroup-v1 silent-no-op security regression flagged in REQ-RESL-NIX-01 / 02 / 03 acceptance #3 by routing `--memory` / `--cpu-percent` / `--max-processes` on misconfigured kernels to a typed error whose Display string carries the LOCKED `cgroup_no_v1=all` boot-flag hint.**

## Performance

- **Duration:** ~60 min
- **Started:** 2026-05-19T15:30:00Z
- **Completed:** 2026-05-19T16:18:06Z
- **Tasks:** 3
- **Files modified:** 7 (5 source files modified, 2 planning files created)

## Accomplishments

### Task 1 — Library variant (commit `202c1844`)

Added `NonoError::UnsupportedKernelFeature { feature: String, hint: String }` to `crates/nono/src/error.rs` immediately after the existing `NotSupportedOnPlatform` variant (mirroring the Phase 25-01 precedent location and doc-comment style). The variant carries:

- `feature` — stable machine-readable identifier (locked as `"cgroup_v2"` for the only current call sites).
- `hint` — human-actionable remediation pointer.

`Display` is LOCKED as `Kernel feature not supported: {feature} ({hint})` via `#[error(...)]`.

Added 3 unit tests in a new `unsupported_kernel_feature_tests` module:

| Test                                                              | Asserts                                                      |
| ----------------------------------------------------------------- | ------------------------------------------------------------ |
| `unsupported_kernel_feature_display_contains_cgroup_no_v1_hint`   | Display starts with `Kernel feature not supported:` prefix, contains `cgroup_v2`, contains LOCKED `cgroup_no_v1=all` substring |
| `unsupported_kernel_feature_is_pattern_matchable`                 | `matches!(err, NonoError::UnsupportedKernelFeature { .. })` |
| `unsupported_kernel_feature_is_debug`                             | `format!("{err:?}")` does not panic                          |

All 3 pass. `cargo check -p nono` exits 0. No new `#[allow(dead_code)]` introduced (CLAUDE.md compliance).

### Task 2 — FFI exhaustive arm (commit `8f5fdf09`)

Added the exhaustive `match` arm in `bindings/c/src/lib.rs::map_error`:

```rust
// Phase 37 D-06: kernel feature missing because the OS is misconfigured
// (cgroup v1 instead of v2). Reuses ErrUnsupportedPlatform per D-06; the
// FFI consumer reads the typed feature+hint via nono_last_error() Display
// string. NO new NonoErrorCode is added (ABI-stable).
nono::NonoError::UnsupportedKernelFeature { .. } => NonoErrorCode::ErrUnsupportedPlatform,
```

RED gate confirmed: without this arm, `cargo check -p nono-ffi` failed with `non-exhaustive patterns: NonoError::UnsupportedKernelFeature { .. } not covered` after Task 1. This proves the compiler-enforced ABI guard locked by `NonoError`'s non-`#[non_exhaustive]` shape + the explicit `match` instead of `_ => ErrUnknown`.

Added 1 unit test `map_error_unsupported_kernel_feature_returns_err_unsupported_platform` locking the D-06 mapping against regression. Passes.

**ABI stability assertion (D-06):** no new `NonoErrorCode` variant introduced — `grep ErrUnsupportedKernel bindings/c/src/lib.rs` returns 0. Binding repos that read the error code value continue to see `ErrUnsupportedPlatform` (no change).

### Task 3 — 4-of-5 cgroup-v2 detection-site swap (commit `8f408c02`)

Swapped 4 of 5 detection sites in `crates/nono-cli/src/exec_strategy/supervisor_linux.rs::cgroup` from `NonoError::UnsupportedPlatform("cgroup_v2: ...".into())` to the new typed `NonoError::UnsupportedKernelFeature { feature: "cgroup_v2", hint: <LOCKED> }`:

| Site | Function                                | Line (post-swap) | Trigger                                                    | New variant                         |
| ---- | --------------------------------------- | ---------------- | ---------------------------------------------------------- | ----------------------------------- |
| 1    | `CgroupSession::detect_from_str`        | 886-889          | empty `/proc/self/cgroup`                                  | `UnsupportedKernelFeature`          |
| 2    | `CgroupSession::detect_from_str`        | 896-899          | multi-line content (cgroup v1 / hybrid)                    | `UnsupportedKernelFeature`          |
| 3    | `CgroupSession::detect_from_str`        | 905-908          | missing `0::` prefix                                       | `UnsupportedKernelFeature`          |
| 4    | `CgroupSession::detect_from_str`        | 942-945 **KEEP** | path-traversal guard (`0::/../../etc`)                     | `UnsupportedPlatform` **PRESERVED** |
| 5a   | `CgroupSession::detect`                 | 974-978          | `read_to_string("/proc/self/cgroup")` failure              | `UnsupportedKernelFeature`          |
| 5b   | `CgroupSession::detect`                 | 987-990          | resolved path exists but is not a directory                | `UnsupportedKernelFeature`          |
| 5c   | `CgroupSession::detect`                 | 991-994          | `metadata()` failure                                       | `UnsupportedKernelFeature`          |

(Site 5 in the plan spec is implemented as 3 constructions inside the same `detect()` block — 5a/5b/5c — collectively the "4th of 5 sites" the plan refers to. Total typed-variant constructions in production code: 6.)

**LOCKED hint string** (carried by every swapped site, verbatim from CONTEXT.md D-07 and REQUIREMENTS.md REQ-RESL-NIX-01 acceptance #3):

```
cgroup v2 required; boot with systemd.unified_cgroup_hierarchy=1 or cgroup_no_v1=all
```

**Site 4 PRESERVED disposition (Phase 37 D-07):** the path-traversal guard at line 942-945 INTENTIONALLY remains `NonoError::UnsupportedPlatform(...)`. An explicit `// Phase 37 D-07: KEEP as UnsupportedPlatform — /proc tampering, not kernel misconfig.` comment documents the disposition inline. Rationale: the kernel is fine — `/proc/self/cgroup` content is malformed/malicious — and the `cgroup_no_v1=all` boot-flag hint would mislead an operator into thinking they need to reconfigure the kernel when the actual fault is `/proc` content tampering.

### Tests

- **4 new Linux-gated unit tests** in a dedicated `unsupported_kernel_feature_swap_tests` module at the bottom of the `cgroup` submodule, covering each of sites 1/2/3 (positive: typed variant emitted) and site 4 (negative: typed variant NOT emitted; old `UnsupportedPlatform` preserved). Test code uses `CgroupSession::detect_from_str(...)` (the established convention in the existing `mod tests` block).
- **3 pre-existing tests UPDATED** to expect the new typed variant: `detect_from_str_cgroup_v1_rejected`, `detect_from_str_hybrid_rejected`, `detect_from_str_empty_rejected`. These are in-scope updates, not deviations — they previously asserted the pre-Phase-37 `UnsupportedPlatform` behavior, which is the very behavior this plan removes. Leaving them unchanged would have silently re-masked the silent-no-op vulnerability (they'd fail loudly, masking the real swap).
- **Async-signal-safety regression test `resl_nix_async_signal_safety` still passes (5/5):** all swapped sites are pre-fork parent-path code in `detect_from_str` / `detect`; none touch `place_self_in_cgroup_raw` or any code between the `CR-01-CHILD-ARM-START` / `CR-01-CHILD-ARM-END` sentinels. The CR-01 invariant (no `format!()` in child arm) is undisturbed because all new `format!`-free typed variants are constructed before fork.

### Doc-comment updates (Rule 2 — keep documentation honest)

Updated outdated `UnsupportedPlatform("cgroup_v2: ...")` references in three doc-comment locations:

| File                                                            | Location                                | Updated to advertise                                            |
| --------------------------------------------------------------- | --------------------------------------- | --------------------------------------------------------------- |
| `crates/nono-cli/src/exec_strategy/supervisor_linux.rs`         | `mod cgroup` header (line ~830) + `detect_from_str` rustdoc + `detect` rustdoc + `CgroupSession::new` rustdoc | Typed variant for fail-fast cases; UnsupportedPlatform only for the path-traversal guard |
| `crates/nono-cli/src/exec_strategy.rs`                          | `apply_resource_limits_unix` rustdoc    | Typed variant + hint pointer                                    |
| `crates/nono-cli/src/launch_runtime.rs`                         | resource-limits architecture rustdoc    | Typed variant + hint pointer                                    |

## REQUIRED callout: external binding-repo verification (Manual)

**Out-of-tree manual verification needed in `nono-py` and `nono-ts` external binding repos.** Plan 37-01 D-06 reuses the existing `ErrUnsupportedPlatform` FFI error code (no ABI change), but the new variant's Display string starts with `"Kernel feature not supported:"`, **NOT** `"Platform not supported:"`. Any binding code that string-matches on the old prefix to gate user-facing behavior may need an update.

Commands to run:

```bash
cd ../nono-py && rg 'Platform not supported'
cd ../nono-ts && rg 'Platform not supported'
```

If matches are found in either repo, decide per-match whether to:

1. Extend the matcher to accept both prefixes (`Platform not supported|Kernel feature not supported`), or
2. Keep matching `Platform not supported` only and let cgroup-v1 hosts surface as a generic unsupported-platform error to FFI consumers (downgrade UX — not recommended).

This is tracked as a `VALIDATION.md` Manual-Only Verification row.

## Cross-target verification status

| Verification                                                         | Status     | Notes                                                                                                            |
| -------------------------------------------------------------------- | ---------- | ---------------------------------------------------------------------------------------------------------------- |
| `cargo check --workspace` (Windows host)                             | PASS       | exit 0                                                                                                           |
| `cargo clippy --workspace -- -D warnings -D clippy::unwrap_used` (Windows host) | PASS       | exit 0                                                                                                           |
| `cargo test -p nono --lib` (Windows host)                            | PASS (692/692) | One pre-existing Windows broker smoke-test flake on first run; passes on retry. Logged to `deferred-items.md`. |
| `cargo test -p nono-ffi --lib` (Windows host)                        | PASS (42/42) | Includes the new `map_error_unsupported_kernel_feature_returns_err_unsupported_platform`                         |
| `cargo test -p nono-cli --test resl_nix_async_signal_safety` (Windows host) | PASS (5/5) | CR-01 regression invariant preserved                                                                             |
| `cargo test -p nono --lib unsupported_kernel_feature` (Windows host) | PASS (3/3) | New variant unit tests                                                                                           |
| `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` | **PARTIAL — deferred to CI** | The `cc-rs` build dependency requires `x86_64-linux-gnu-gcc`, which is not installed on the Windows dev host. Per CLAUDE.md cross-target rule, deferred to live CI per `.planning/templates/cross-target-verify-checklist.md`. |
| `cargo test -p nono-cli --bin nono --target x86_64-unknown-linux-gnu unsupported_kernel_feature_swap_tests` | **PARTIAL — deferred to CI** | Same `cc-rs`/linux-gnu-gcc reason. Plan 37-04 covers Linux-runner verification.                                  |
| `cargo clippy --workspace --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used`              | **PARTIAL — deferred to CI** | `cc-rs` apple-darwin host SDK unavailable on the Windows dev host. Plan 37-04 covers macOS-runner verification.  |

The Linux + macOS cross-target gates are tracked in `.planning/phases/37-linux-resl-backends-pkgs-auto-pull/deferred-items.md`. The structural prerequisites for those gates (no `.unwrap()`, no new warnings, typed-variant exhaustive matches) are all satisfied by the Windows-host clippy run.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 — Bug] Updated 3 pre-existing tests that asserted the pre-Phase-37 `UnsupportedPlatform` behavior**

- **Found during:** Task 3 (after running compile-and-test on Windows host the swap was visible to compilers but the existing tests in `mod tests` still asserted `UnsupportedPlatform`; the test would have failed on Linux).
- **Issue:** `detect_from_str_cgroup_v1_rejected`, `detect_from_str_hybrid_rejected`, `detect_from_str_empty_rejected` all assert `matches!(err, NonoError::UnsupportedPlatform(_))` — which is the very behavior the plan removes.
- **Fix:** Updated each to `matches!(err, NonoError::UnsupportedKernelFeature { .. })` with a Phase 37 D-05 / D-07 explanatory comment. The path-traversal regression tests (`cgroup_path_rejects_parent_dir_traversal`, `cgroup_path_rejects_encoded_traversal`) at lines 1346-1367 INTENTIONALLY remain on `UnsupportedPlatform` — they assert the site 4 KEEP disposition.
- **Files modified:** `crates/nono-cli/src/exec_strategy/supervisor_linux.rs` (3 tests).
- **Commit:** `8f408c02`

**2. [Rule 2 — Documentation drift] Updated 4 stale doc comments referencing the pre-Phase-37 error type**

- **Found during:** Post-Task 3 self-check grep for `UnsupportedPlatform.*cgroup_v2`.
- **Issue:** Module-level rustdoc in `supervisor_linux.rs` mod cgroup header (line 831), `detect_from_str` rustdoc, `detect` rustdoc, `CgroupSession::new` rustdoc, plus `exec_strategy.rs::apply_resource_limits_unix` rustdoc and `launch_runtime.rs` resource-limits architecture comment all advertised the old `UnsupportedPlatform("cgroup_v2: ...")` shape. Leaving them would mislead future readers about the actual fail-fast contract.
- **Fix:** Updated each rustdoc to advertise the new `UnsupportedKernelFeature { feature: "cgroup_v2", hint }` shape, with explicit note that the path-traversal guard remains on `UnsupportedPlatform` per D-07.
- **Files modified:** `supervisor_linux.rs`, `exec_strategy.rs`, `launch_runtime.rs`.
- **Commit:** `8f408c02`

### Deferred Issues

**1. Pre-existing Windows broker smoke-test flake**

- **Test:** `supervisor::aipc_sdk::tests::windows_real_broker_smoke_tests::sdk_request_job_object_round_trips_through_real_broker`
- **Observation:** Failed once in 4 full-suite runs; passes on isolated re-run. Pre-existing Windows broker timing flake unrelated to Phase 37's error-variant work.
- **Disposition:** Logged to `.planning/phases/37-linux-resl-backends-pkgs-auto-pull/deferred-items.md`; recommended follow-up under Phase 41 CI-cleanup series.

**2. Cross-target Linux clippy + Linux-only unit-test runs**

- **Reason:** Windows-host `cargo` invocations targeting `x86_64-unknown-linux-gnu` (and `x86_64-apple-darwin`) require cross C compilers that are not installed locally. CLAUDE.md cross-target verification rule explicitly allows deferral to live CI in this case.
- **Coverage:** Plan 37-04 (CI-Linux verification) runs the Linux-target clippy gate and the new `unsupported_kernel_feature_swap_tests` module on a real cgroup-v2 runner.

## Verification Trace

| Plan requirement                                                                                                    | Result                                                                                                                                  |
| ------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Task 1 grep: `UnsupportedKernelFeature \{ feature: String, hint: String \}` in `error.rs`                           | 1 match (line 68) ✓                                                                                                                     |
| Task 1 grep: LOCKED `#[error(...)]` macro                                                                            | 1 match (line 67) ✓                                                                                                                     |
| Task 1 grep: `cgroup_no_v1=all` in `error.rs`                                                                       | 3 matches (test module) ≥1 ✓                                                                                                            |
| Task 1: `cargo test -p nono --lib unsupported_kernel_feature` reports 3 passed                                      | 3 passed ✓                                                                                                                              |
| Task 1: no new `#[allow(dead_code)]`                                                                                | 0 matches (baseline preserved) ✓                                                                                                        |
| Task 1: `cargo check -p nono` exits 0                                                                               | exit 0 ✓                                                                                                                                |
| Task 2 grep: `UnsupportedKernelFeature { .. } => NonoErrorCode::ErrUnsupportedPlatform` in `bindings/c/src/lib.rs`  | 1 match (line 147) ✓                                                                                                                    |
| Task 2 grep: `Phase 37 D-06` in `bindings/c/src/lib.rs`                                                             | 3 matches (justifier comment + test + variant) ≥1 ✓                                                                                     |
| Task 2 grep: `ErrUnsupportedKernel` in `bindings/c/src/lib.rs` (no new FFI code)                                    | 0 matches ✓                                                                                                                             |
| Task 2: `cargo check --workspace` exits 0                                                                           | exit 0 ✓                                                                                                                                |
| Task 2: `cargo test -p nono-ffi map_error_unsupported_kernel_feature` reports 1 passed                              | 1 passed ✓                                                                                                                              |
| Task 3 grep: `NonoError::UnsupportedKernelFeature {` in `supervisor_linux.rs` ≥ 5                                    | 14 matches (6 production constructions + 8 test references + doc-comment) ✓                                                             |
| Task 3 grep (multiline): `NonoError::UnsupportedPlatform\(format!\(.*"cgroup_v2:` in `supervisor_linux.rs` == 1     | 1 match (Site 4, line 942-945) ✓                                                                                                        |
| Task 3 grep: `Phase 37 D-07: KEEP as UnsupportedPlatform` in `supervisor_linux.rs` == 1                             | 1 match (line 938) ✓                                                                                                                    |
| Task 3 grep: `cgroup_no_v1=all` in `supervisor_linux.rs` ≥ 4                                                        | 11 matches (per-site LOCKED hint + test substring const) ≥4 ✓                                                                           |
| Task 3: `cargo build -p nono-cli --target x86_64-unknown-linux-gnu` exits 0                                         | **DEFERRED — see deferred-items.md** (linux-gnu-gcc not installed; CLAUDE.md cross-target rule)                                          |
| Task 3: Linux-target unit tests report 4 passed                                                                     | **DEFERRED — see deferred-items.md** (same reason; Plan 37-04 covers)                                                                   |
| Task 3: `cargo test -p nono-cli --test resl_nix_async_signal_safety` exits 0                                        | exit 0 (5/5 passed on Windows host) ✓                                                                                                   |
| Task 3: cross-target clippy clean                                                                                   | **DEFERRED — see deferred-items.md** (Windows-host `cargo clippy --workspace` clean — structural prerequisites satisfied)               |

## Self-Check: PASSED

- All 3 task commit hashes resolvable in `git log`: `202c1844`, `8f5fdf09`, `8f408c02` ✓
- All 5 modified source files present on disk + at expected line counts ✓
- `.planning/phases/37-linux-resl-backends-pkgs-auto-pull/deferred-items.md` present ✓
- No `STATE.md` / `ROADMAP.md` modifications (worktree-mode discipline) ✓
- DCO sign-off on all 3 commits ✓ (each commit was created with `git commit -s`)
