---
phase: 05-windows-detach-readiness-fix
plan: 01
subsystem: windows-supervisor
tags: [windows, named-pipe, WaitNamedPipeW, detach, supervisor, startup_runtime]

# Dependency graph
requires:
  - phase: 04-state-integrity-deployment
    provides: Windows supervisor infrastructure with named pipe server in supervisor.rs
provides:
  - Platform-guarded readiness check in run_detached_launch() using WaitNamedPipeW
  - Fail-closed WaitNamedPipeW error handling (unexpected errors => SandboxInit)
affects: [attach, detach, ps, session-commands-windows]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "#[cfg(target_os = \"windows\")] block with inline use statements for platform-specific Windows API calls"
    - "WaitNamedPipeW(50ms) polling per iteration within existing deadline loop"
    - "unwrap_or_else(|p| p.into_inner()) for mutex poison recovery in background threads"

key-files:
  created: []
  modified:
    - crates/nono-cli/src/startup_runtime.rs
    - crates/nono/src/keystore.rs
    - crates/nono-cli/src/exec_strategy_windows/mod.rs
    - crates/nono-cli/src/exec_strategy_windows/network.rs
    - crates/nono-cli/src/exec_strategy_windows/supervisor.rs
    - crates/nono-cli/src/supervised_runtime.rs
    - crates/nono-cli/src/setup.rs
    - crates/nono-cli/src/bin/nono-wfp-service.rs

key-decisions:
  - "WaitNamedPipeW with 50ms timeout per iteration within existing 2-second deadline loop (D-01)"
  - "result != 0 means pipe available; no handle opened (D-02)"
  - "ERROR_FILE_NOT_FOUND and ERROR_SEM_TIMEOUT are retry conditions; any other error is fatal (D-03)"
  - "Inline #[cfg(target_os = \"windows\")] block with local use statements to avoid unused-import on Unix (D-04)"
  - "Only attach_path.exists() replaced; session_path.exists() check remains shared across platforms (D-05)"
  - "Pipe name format \\\\.\\\\ pipe\\nono-session-{session_id} matching supervisor.rs:297 (D-06)"

patterns-established:
  - "Platform-gated readiness: #[cfg(not(target_os = \"windows\"))] for Unix path, #[cfg(target_os = \"windows\")] block for Windows path"
  - "Windows API use statements scoped inside cfg block to prevent unused-import warnings on Unix"

requirements-completed:
  - SUPV-01
  - SUPV-02

# Metrics
duration: 25min
completed: 2026-04-05
---

# Phase 05 Plan 01: Windows Detach Readiness Fix Summary

**WaitNamedPipeW-based Named Pipe readiness probe replaces .sock file check in run_detached_launch() for Windows detach/attach flow correctness**

## Performance

- **Duration:** ~25 min
- **Started:** 2026-04-05T00:00:00Z
- **Completed:** 2026-04-05T00:25:00Z
- **Tasks:** 1
- **Files modified:** 8

## Accomplishments

- `run_detached_launch()` now polls Named Pipe readiness via `WaitNamedPipeW` on Windows instead of checking for `.sock` file that never exists
- Non-Windows code path is unchanged — `attach_path.exists()` still used on Unix
- Fail-closed: unexpected `WaitNamedPipeW` errors return `Err(NonoError::SandboxInit(...))`
- Clippy passes clean with `-D warnings -D clippy::unwrap_used` on this platform

## Task Commits

1. **Task 1: Add WaitNamedPipeW readiness probe to run_detached_launch()** - `84f5743` (feat)

## Files Created/Modified

- `crates/nono-cli/src/startup_runtime.rs` - Platform-guarded readiness check: WaitNamedPipeW (Windows) / attach_path.exists() (Unix)
- `crates/nono/src/keystore.rs` - Pre-existing clippy fix: map_err -> inspect_err
- `crates/nono-cli/src/exec_strategy_windows/mod.rs` - Remove unused Write/Stdio imports
- `crates/nono-cli/src/exec_strategy_windows/network.rs` - Rename session_id -> _session_id in trait impls
- `crates/nono-cli/src/exec_strategy_windows/supervisor.rs` - unwrap() -> unwrap_or_else() on mutex locks
- `crates/nono-cli/src/supervised_runtime.rs` - Remove unused RollbackRuntimeState import
- `crates/nono-cli/src/setup.rs` - Remove let _ = on unit-value call
- `crates/nono-cli/src/bin/nono-wfp-service.rs` - Add #[allow(clippy::unwrap_used)] to test module

## Decisions Made

- `WaitNamedPipeW` with 50ms timeout per iteration (matching thread sleep interval) within the existing 2-second deadline
- `ERROR_FILE_NOT_FOUND` and `ERROR_SEM_TIMEOUT` are expected "not yet ready" conditions (pipe not created yet or timeout elapsed) — treated as retry
- Any other WaitNamedPipeW error is unexpected and treated as fail-closed (returns `Err(NonoError::SandboxInit(...))`)
- `session_path.exists()` (JSON session file) preserved as shared readiness gate on all platforms

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Pre-existing clippy errors prevented verification (7 fixes across 7 files)**
- **Found during:** Task 1 verification (cargo clippy)
- **Issue:** `cargo clippy --all-targets -p nono-cli -- -D warnings -D clippy::unwrap_used` failed with 10 errors in files not modified by this task (confirmed pre-existing via git stash test)
- **Fix:** Fixed all 10 pre-existing errors: map_err->inspect_err, unused imports, unused variables, unwrap->unwrap_or_else, let_unit_value, allow in tests
- **Files modified:** keystore.rs, exec_strategy_windows/mod.rs, exec_strategy_windows/network.rs, exec_strategy_windows/supervisor.rs, supervised_runtime.rs, setup.rs, bin/nono-wfp-service.rs
- **Verification:** `cargo clippy --all-targets -p nono-cli -- -D warnings -D clippy::unwrap_used` exits 0
- **Committed in:** 84f5743 (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (Rule 3 — blocking verification)
**Impact on plan:** All fixes necessary for clippy gate to pass. No scope creep; all issues were pre-existing, not introduced by this task.

## Issues Encountered

- Confirmed pre-existing clippy failures by using `git stash` before proceeding. All 7 affected files had failures independent of this plan's change.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Windows detach/attach flow is now structurally correct: `nono run --detach` on Windows will probe the Named Pipe via WaitNamedPipeW rather than waiting for a Unix socket that never appears
- Phase 05 has 1 plan, now complete
- SUPV-01 and SUPV-02 requirements satisfied

---
*Phase: 05-windows-detach-readiness-fix*
*Completed: 2026-04-05*
