---
phase: 03-pr-c-ci-verification
plan: 02
subsystem: testing
tags: [windows, ci, wfp, powershell, github-actions]

# Dependency graph
requires:
  - phase: 02-pr-b-cli-messaging
    provides: unified support status test (windows_setup_check_only_reports_unified_support_status) added in Phase 2
provides:
  - Dead regression entry removed from harness
  - WFP privilege gate in security suite (NONO_CI_HAS_WFP env var)
  - Unified support status test added to smoke suite
  - CI YAML windows-security job sets NONO_CI_HAS_WFP=true
affects:
  - 03-pr-c-ci-verification (03-01 companion plan — both together complete CIVER-01 and CIVER-02)
  - 04-pr-d-docs-flip (final phase, reads harness and CI as evidence of promoted support)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "WFP privilege gate: filter $securityTests at call site using $wfpFilters array; $securityTests declaration unchanged"
    - "Job-level env block in CI YAML for privilege-scoped env vars"
    - "Skip message via Tee-Object when NONO_CI_HAS_WFP is absent (no non-zero exit under $ErrorActionPreference=Stop)"

key-files:
  created: []
  modified:
    - scripts/windows-test-harness.ps1
    - .github/workflows/ci.yml

key-decisions:
  - "Gate WFP tests at the call site only — $securityTests array stays unchanged so entries remain discoverable"
  - "NONO_CI_HAS_WFP hardcoded true in CI YAML because windows-latest runners are always Administrator; no secrets or expressions needed"
  - "Add windows_setup_check_only_reports_unified_support_status to smoke suite alongside existing live_profile_subset test (complementary, not redundant)"

patterns-established:
  - "Privilege-gated test suites: maintain full array declarations, gate at invocation with named filter sets"

requirements-completed:
  - CIVER-01
  - CIVER-02

# Metrics
duration: 2min
completed: 2026-04-03
---

# Phase 3 Plan 02: Windows Test Harness CI Verification Summary

**WFP privilege gate added to security suite, dead regression entry removed, and unified support status smoke test wired — harness and CI YAML aligned to promoted Windows contract**

## Performance

- **Duration:** 2 min
- **Started:** 2026-04-03T23:27:35Z
- **Completed:** 2026-04-03T23:29:39Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments
- Removed dead `test_validate_windows_preview_direct_execution_allows_override_deny_when_policy_is_supported` entry from `$regressionTests` (function deleted in Phase 2; harness entry was a dead reference per D-06)
- Added `windows_setup_check_only_reports_unified_support_status` to `$smokeTests` alongside existing `live_profile_subset` entry (both tests are complementary: unified checks single status line + absence of old labels, live_profile_subset checks verbose subset content)
- Gated WFP integration tests on `NONO_CI_HAS_WFP` env var in the security switch case — non-WFP tests run unconditionally, WFP tests run when `NONO_CI_HAS_WFP=true`, skip message logged otherwise (no non-zero exit)
- Added job-level `env: NONO_CI_HAS_WFP: true` block to `windows-security` CI job (windows-latest runners are always Administrator)

## Task Commits

Each task was committed atomically:

1. **Task 1: Remove dead regression entry, add unified smoke test** - `21dc800` (feat)
2. **Task 2: Add WFP privilege gate in harness and CI YAML** - `fc60e25` (feat)

**Plan metadata:** (docs commit follows)

## Files Created/Modified
- `scripts/windows-test-harness.ps1` - Removed dead regression entry, added unified smoke test, added WFP gate in security case
- `.github/workflows/ci.yml` - Added `env: NONO_CI_HAS_WFP: true` block to windows-security job

## Decisions Made
- Gate WFP tests at the call site with a `$wfpFilters` array — the `$securityTests` array declaration is unchanged so both WFP entries remain fully discoverable
- `NONO_CI_HAS_WFP: true` hardcoded (not via secret or expression) because windows-latest GitHub Actions runners are unconditionally Administrator
- Both smoke tests kept: `live_profile_subset` covers verbose subset content, `unified_support_status` covers the single-line output with absence guards for split labels

## Deviations from Plan

None - plan executed exactly as written.

Note: Acceptance criterion "grep -c windows_run_block_net_blocks_probe_connection returns 1" was written pre-gate. After the WFP gate code was added, the filter name appears twice (once in `$securityTests`, once in `$wfpFilters`). This is correct: the entry is still in `$securityTests` (discoverable), and the gate references it by name. The spirit of the criterion (entry not removed) is satisfied.

## Issues Encountered
None

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- CIVER-01 and CIVER-02 complete: harness is clean and privilege-aware
- Combined with 03-01 (which validates the library contract surface in tests), phase 03 is ready for final CI verification sign-off
- Phase 04 (PR-D docs flip) can proceed once phase 03 CI gates show green

## Self-Check: PASSED

- scripts/windows-test-harness.ps1: FOUND
- .github/workflows/ci.yml: FOUND
- 03-02-SUMMARY.md: FOUND
- Commit 21dc800: FOUND
- Commit fc60e25: FOUND

---
*Phase: 03-pr-c-ci-verification*
*Completed: 2026-04-03*
