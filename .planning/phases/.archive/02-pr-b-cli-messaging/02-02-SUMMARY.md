---
phase: 02-pr-b-cli-messaging
plan: 02
subsystem: testing
tags: [windows, sandbox, cli-messaging, integration-tests, env_vars]

# Dependency graph
requires:
  - phase: 02-pr-b-cli-messaging
    plan: 01
    provides: "Unified 'Support status:' line; dead !is_supported branches removed from output.rs, setup.rs, execution_runtime.rs, command_runtime.rs"
provides:
  - "env_vars.rs Windows integration tests encode promoted CLI contract (no preview language, no CLI/library split labels)"
  - "Dry-run test asserts 'sandbox would be applied with above capabilities' (cross-platform string)"
  - "Live-run tests assert text.contains('active') instead of old restricted-execution surface messaging"
  - "Setup check-only tests assert 'Support status: supported' unified line, absence of CLI/library split lines"
affects: [03-pr-c-ci-promotion, 04-pr-d-docs-flip]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Test assertions encode the promoted contract boundary: check for new wording, check absence of old wording"
    - "Negative guards updated from 'must not claim parity' to 'must not use old preview wording'"

key-files:
  created: []
  modified:
    - crates/nono-cli/tests/env_vars.rs

key-decisions:
  - "Each old assertion replaced with a new one — no assertion blocks deleted wholesale per D-15/D-16"
  - "Negative guards retained but refactored: check absence of old dead-branch wording rather than old parity claims"

patterns-established:
  - "Test contract encoding: when production code drops a string, the test negative guard pivots to assert that old string is absent"

requirements-completed: [CLIMSG-04]

# Metrics
duration: 2min
completed: 2026-04-03
---

# Phase 02 Plan 02: Windows Integration Test Assertion Promotion Summary

**Surgically replaced eight stale Windows integration test assertions in env_vars.rs to match the promoted CLI contract from Plan 01 — dry-run, live-run, and setup check-only tests now encode the cross-platform unified messaging**

## Performance

- **Duration:** ~2 min
- **Started:** 2026-04-03T22:39:29Z
- **Completed:** 2026-04-03T22:41:30Z
- **Tasks:** 2
- **Files modified:** 1

## Accomplishments
- Renamed `windows_dry_run_reports_preview_validation_without_enforcement_claims` to `windows_dry_run_reports_sandbox_validation`; replaced old "current Windows command surface without claiming full parity" assertion with "sandbox would be applied with above capabilities"
- Updated `windows_run_executes_basic_command` and `windows_run_allows_supported_directory_allowlist_in_live_run` (renamed from preview variant) to assert `text.contains("active")` and check absence of "Windows restricted execution" instead of old surface-messaging and first-class-supported negative guards
- Renamed `windows_setup_check_only_reports_partial_support_without_first_class_claim` to `windows_setup_check_only_reports_unified_support_status`; replaced CLI/library split assertions with single "Support status: supported" assertion and absence checks for split labels
- Updated `windows_setup_check_only_reports_live_profile_subset` to assert "Support status: supported" and check absence of separate "Library support status:" line

## Task Commits

Each task was committed atomically:

1. **Task 1: Update windows_dry_run and windows_run test assertions** - `b619553` (feat)
2. **Task 2: Update windows_setup_check_only test assertions** - `7f22b67` (feat)

**Plan metadata:** (committed with final docs commit)

## Files Created/Modified
- `crates/nono-cli/tests/env_vars.rs` - Four test functions updated: renamed, assertions replaced per D-15/D-16; no blocks deleted wholesale

## Decisions Made
- Each assertion block replaced individually (not deleted wholesale) per D-15/D-16: old positive assertions replaced with new positive assertions, old negative guards replaced with absence checks for the old dead-branch wording
- The remaining `!text.contains("first-class supported")` guards at lines 2327, 2354, 2385, 2435, 3004, 3054 are in different test functions outside this plan's scope — left untouched

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

**Pre-existing test failure (out of scope):** `query_ext::tests::test_query_path_sensitive_policy_includes_policy_source` fails with `left: "path_not_granted" right: "sensitive_path"` — confirmed pre-existing before any changes in this plan (git stash verified). This is in `query_ext.rs`, not `env_vars.rs`. Logged to deferred items; not caused by this plan.

## Known Stubs
None — test assertions now directly encode the promoted production contract strings.

## Next Phase Readiness
- Plan 02-02 is complete; both PR-B plans are done
- Phase 02 (PR-B) is fully complete: production CLI code cleaned up (Plan 01) and tests updated to match (Plan 02)
- Phase 03 (PR-C: CI promotion) can proceed — the promoted Windows contract is now honest in both code and tests
- Pre-existing `query_ext` unit test failure should be addressed before or during Phase 03

---
*Phase: 02-pr-b-cli-messaging*
*Completed: 2026-04-03*
