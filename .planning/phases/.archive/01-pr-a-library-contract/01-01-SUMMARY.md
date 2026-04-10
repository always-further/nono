---
phase: 01-pr-a-library-contract
plan: "01"
subsystem: testing
tags: [rust, windows, sandbox, tdd, contract-tests]

# Dependency graph
requires: []
provides:
  - "9 named RED contract tests for Windows Sandbox::apply() promotion (LIBCON-01 through LIBCON-04)"
  - "Replaced support_info_reports_consistent_partial_status with promoted-contract test"
  - "IpcMode imported into windows.rs test module"
affects:
  - 01-02-pr-a-library-contract  # Plan 02 must make all 9 tests pass (GREEN)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "TDD RED phase: tests written against current stub to establish executable contract specification"
    - "Contract tests call apply(), is_supported(), support_info() together in one test to assert consistency"

key-files:
  created: []
  modified:
    - "crates/nono/src/sandbox/windows.rs"

key-decisions:
  - "Tests assert exact behavior plan 02 must deliver — no stub-friendly assertions"
  - "support_info test asserts all three functions agree (apply, is_supported, support_info) simultaneously"
  - "apply_error_message_remains_explicit test asserts both old stub absence AND named feature presence"

patterns-established:
  - "Windows contract test pattern: use tempdir() + allow_path() for directory-read acceptance tests"
  - "Windows rejection test pattern: add_fs(FsCapability::new_file) to trigger single-file rejection"

requirements-completed:
  - LIBCON-01
  - LIBCON-02
  - LIBCON-03
  - LIBCON-04

# Metrics
duration: 15min
completed: 2026-04-03
---

# Phase 01 Plan 01: PR-A Library Contract TDD RED Summary

**9 named contract tests for Windows Sandbox::apply() promotion written and confirmed RED against the current UnsupportedPlatform stub**

## Performance

- **Duration:** ~15 min
- **Started:** 2026-04-03T21:02:02Z
- **Completed:** 2026-04-03T21:17:00Z
- **Tasks:** 1
- **Files modified:** 1

## Accomplishments

- Replaced the old `support_info_reports_consistent_partial_status` test (which asserted the partial/unsupported state) with 9 contract tests that assert the promoted state
- Added `IpcMode` to the test module import line to support the non-default IPC mode rejection test
- All 9 tests compile cleanly (`cargo test -p nono --no-run --lib` passes, `cargo clippy -p nono --lib -- -D warnings` passes)
- All 9 tests FAIL (RED) against the current stub `apply()` that does `let _ = caps; Err(UnsupportedPlatform(...))` — this is the expected outcome for the TDD RED phase
- Plan 02 will flip the constant and implement the validate-and-signal body to turn these RED tests GREEN

## Task Commits

Each task was committed atomically:

1. **Task 1: Write 9 RED contract tests and replace old support_info test** - `185aa22` (test)

**Plan metadata:** (pending — created as part of this summary)

## Files Created/Modified

- `crates/nono/src/sandbox/windows.rs` - Added 9 contract tests, updated imports, removed old partial-status test

## Decisions Made

- No deviations from plan specification required; test skeletons from RESEARCH.md were used as specified
- `apply_error_message_remains_explicit_for_unsupported_subset` asserts both the OLD stub string is absent AND a named feature string is present — this is a stronger assertion than the skeleton draft

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None — file compiled on first attempt, all 9 tests fail in RED as expected.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- RED phase complete: all 9 LIBCON-04 contract tests exist, compile, and fail
- Plan 02 can proceed immediately: implement the validate-and-signal `apply()` body, flip `WINDOWS_PREVIEW_SUPPORTED` to `true`, update `support_info()` to return `SupportStatus::Supported`, activate the rejection classification in `compile_filesystem_policy`, and update the two existing tests that will break
- No blockers; no outstanding concerns for Plan 02

## Self-Check: PASSED

- FOUND: `crates/nono/src/sandbox/windows.rs`
- FOUND: commit `185aa22`

---
*Phase: 01-pr-a-library-contract*
*Completed: 2026-04-03*
