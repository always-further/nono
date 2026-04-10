---
phase: 06-wfp-enforcement-activation
plan: 02
subsystem: testing
tags: [windows, wfp, network-enforcement, testing, mock-pipe, snapshot-test, _with_runner]

# Dependency graph
requires:
  - phase: 06-wfp-enforcement-activation
    plan: 01
    provides: install_wfp_network_backend, build_wfp_target_activation_request with session_sid param, ExecConfig.session_sid

provides:
  - install_wfp_network_backend_with_runner generic function with probe_fn and run_probe closures
  - install_wfp_network_backend delegates to _with_runner (filesystem-independent testability)
  - 4 unit tests covering activation path success, prerequisites-missing failure, and request serialization

affects: [integration-tests-windows]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Dual-closure _with_runner pattern: probe_fn injects WfpProbeStatus without filesystem, run_probe injects IPC response"
    - "Test module at end of Windows-only submodule with #[cfg(test)] #[allow(clippy::unwrap_used)] before mod tests"

key-files:
  created: []
  modified:
    - crates/nono-cli/src/exec_strategy_windows/network.rs

key-decisions:
  - "Two closures required (not one): probe_wfp_backend_status_with_config checks filesystem even in test-force-ready branch, so probe_fn injection is needed to return WfpProbeStatus::Ready without nono-wfp-service.exe being present"
  - "prerequisites-missing maps to Err(NonoError::UnsupportedPlatform) directly via parse_wfp_runtime_probe_status, not through the NotImplemented arm in install_wfp_network_backend_with_runner"
  - "#[allow(clippy::unwrap_used)] placed on the mod tests block (not as a use attribute) to satisfy clippy"
  - "Test module placed before prepare_network_enforcement to avoid 'items after a test module' clippy warning"

patterns-established:
  - "_with_runner functions accept both a probe closure and a runner closure for full testability without filesystem or service dependencies"

requirements-completed: [NETW-01, NETW-03]

# Metrics
duration: 10min
completed: 2026-04-06
---

# Phase 06 Plan 02: WFP Test Coverage Summary

**Testable install_wfp_network_backend_with_runner extracted with dual-closure injection: 4 unit tests cover mock-pipe activation success/failure and request serialization with/without session SID, all without admin elevation or filesystem dependency**

## Performance

- **Duration:** 10 min
- **Started:** 2026-04-06T01:29:00Z
- **Completed:** 2026-04-06T01:39:35Z
- **Tasks:** 1
- **Files modified:** 1

## Accomplishments

- Extracted `install_wfp_network_backend_with_runner<P, R>` with a `probe_fn: P` closure (bypasses filesystem probe) and a `run_probe: R` closure (injects IPC response)
- `install_wfp_network_backend` now delegates to `_with_runner`, passing the real `probe_wfp_backend_status_with_config` and `run_wfp_runtime_probe_with_request` implementations
- Added `install_wfp_network_backend_returns_guard_on_enforced_pending_cleanup`: mock probe returns Ready, mock runner returns "enforced-pending-cleanup", asserts `WfpServiceManaged` guard is returned
- Added `install_wfp_network_backend_returns_error_on_prerequisites_missing`: mock probe returns Ready, mock runner returns "prerequisites-missing", asserts `UnsupportedPlatform` error
- Added `build_wfp_target_activation_request_populates_session_sid`: asserts session_sid, rule names, network_mode, request_kind, and target_program_path are all populated correctly
- Added `build_wfp_target_activation_request_leaves_session_sid_none_for_appid_fallback`: asserts session_sid is None when None is passed

## Task Commits

Each task was committed atomically:

1. **Task 1: Extract install_wfp_network_backend_with_runner and add mock pipe + snapshot tests** - `8f13d19` (feat)

**Plan metadata:** (docs commit follows)

## Files Created/Modified

- `crates/nono-cli/src/exec_strategy_windows/network.rs` - Added `install_wfp_network_backend_with_runner<P, R>`, updated `install_wfp_network_backend` to delegate, added `#[cfg(test)] mod tests` with 4 test functions

## Decisions Made

- Two closures are required because `probe_wfp_backend_status_with_config` checks `config.backend_binary_path.exists()` even in the `windows_wfp_test_force_ready()` branch. On CI where `nono-wfp-service.exe` is absent, the probe returns `BackendBinaryMissing` before the activation request is built, making the run_probe closure unreachable. The `probe_fn` closure sidesteps this by returning `WfpProbeStatus::Ready` directly.
- `prerequisites-missing` is handled by `parse_wfp_runtime_probe_status` which returns `Err(NonoError::UnsupportedPlatform(...))` directly — not by the `NotImplemented` match arm in `install_wfp_network_backend_with_runner`. Test assertion uses `UnsupportedPlatform`.
- Test module placed before `prepare_network_enforcement` (not after it) to avoid the `items after a test module` clippy warning.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed clippy::unwrap_used attribute placement and test module ordering**
- **Found during:** Task 1 (initial implementation)
- **Issue:** `#[allow(clippy::unwrap_used)]` was placed as a `use` attribute (invalid); test module was placed after `prepare_network_enforcement` triggering "items after a test module" clippy warning
- **Fix:** Moved `#[allow(clippy::unwrap_used)]` to the `mod tests` block; moved test module before `prepare_network_enforcement` and removed the duplicate function at end of file
- **Files modified:** `crates/nono-cli/src/exec_strategy_windows/network.rs`
- **Verification:** `cargo clippy --all-targets -- -D warnings -D clippy::unwrap_used` passes cleanly
- **Committed in:** 8f13d19 (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 bug)
**Impact on plan:** Clippy enforcement fix only. No scope creep. Tests and logic are exactly as specified.

## Issues Encountered

- Pre-existing test failure in `query_ext::tests::test_query_path_sensitive_policy_includes_policy_source` — confirmed pre-existing before this plan's changes, documented as out-of-scope per CLAUDE.md scope boundary policy.
- Pre-existing `cargo fmt` diffs in `snapshot.rs`, `types.rs`, `nono-wfp-service.rs`, `supervised_runtime.rs` — confirmed pre-existing, out of scope per CLAUDE.md scope boundary policy.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Plan 06-02 is complete: `install_wfp_network_backend_with_runner` extracted, 4 tests passing without admin elevation
- Phase 06 is now complete — both plans done
- Pre-existing test failure (`test_query_path_sensitive_policy_includes_policy_source`) should be investigated in a separate session

---
*Phase: 06-wfp-enforcement-activation*
*Completed: 2026-04-06*
