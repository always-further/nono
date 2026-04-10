---
phase: 07-quick-wins
plan: 01
subsystem: cli
tags: [windows, wrap, job-objects, wfp, session-commands, execution-strategy]

# Dependency graph
requires:
  - phase: 06-wfp-promotion
    provides: Windows WFP + Job Object enforcement backend wired end-to-end
provides:
  - Direct strategy Windows return path with process::exit(exit_code)
  - Anonymous Job Object (None session_id) for nono wrap invocations
  - Updated setup help text reflecting wrap availability on Windows
  - Confirmed session commands (logs, inspect, prune) compile and dispatch unconditionally on Windows
affects: [08-conpty-shell, 09-wfp-network-policy]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Windows Direct strategy exits via std::process::exit(exit_code) after cleanup, matching Supervised pattern"
    - "Anonymous Job Object (None) used for wrap invocations — no named session tracking needed"

key-files:
  created: []
  modified:
    - crates/nono-cli/src/execution_runtime.rs
    - crates/nono-cli/src/setup.rs

key-decisions:
  - "Pass None (anonymous Job Object) to execute_direct for wrap: wrap has no detach/ps integration and an empty session_id would produce malformed Job Object name Local\\nono-session-"
  - "Wrap availability documented in setup help text with (no exec-replace, unlike Unix) qualifier per WRAP-01"

patterns-established:
  - "Direct strategy Windows block: capture exit_code, cleanup cap file, call std::process::exit — mirrors Supervised strategy cleanup pattern"

requirements-completed: [WRAP-01, SESS-01, SESS-02, SESS-03]

# Metrics
duration: 15min
completed: 2026-04-08
---

# Phase 07 Plan 01: Quick Wins — wrap and Session Commands Summary

**`nono wrap` enabled on Windows via Direct strategy with anonymous Job Object + WFP enforcement; session commands (logs, inspect, prune) confirmed unconditionally available on Windows**

## Performance

- **Duration:** ~15 min
- **Started:** 2026-04-08T00:00:00Z
- **Completed:** 2026-04-08T00:15:00Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Fixed the `nono wrap` Windows return path: the Direct strategy now captures the child exit code and calls `std::process::exit(exit_code)` after cleanup, preventing the `unreachable!()` panic that previously blocked wrap on Windows (WRAP-01)
- Changed the Direct strategy to pass `None` (anonymous Job Object) instead of the session ID string, which would have produced a malformed Job Object name (`Local\nono-session-`) since wrap has no detach/ps integration
- Updated `setup.rs` help text: wrap is now correctly documented as available on Windows with Job Object + WFP enforcement (with the "no exec-replace, unlike Unix" qualifier); the stale "remain intentionally unavailable" claim is removed
- Confirmed `run_logs`, `run_inspect`, `run_prune` are all public, dispatch unconditionally (zero `#[cfg]` gates), and `run_prune` has the `reject_if_sandboxed` guard — SESS-01, SESS-02, SESS-03 satisfied by existing code

## Task Commits

Each task was committed atomically:

1. **Task 1: Fix Direct strategy Windows return path and update setup help text** - `e6035c9` (feat)
2. **Task 1 fmt fix: apply rustfmt formatting to setup.rs shell println** - `14e838e` (fix)
3. **Task 2: Verify session commands compile and dispatch on Windows, run CI checks** — verification-only, no code changes; covered by Task 1 commits

## Files Created/Modified

- `crates/nono-cli/src/execution_runtime.rs` — Direct strategy Windows arm: captures exit_code, calls cleanup_capability_state_file, exits with std::process::exit(exit_code); passes None for anonymous Job Object
- `crates/nono-cli/src/setup.rs` — Updated Windows help text: wrap available (no exec-replace, unlike Unix); shell (ConPTY) not yet available

## Decisions Made

- **Anonymous Job Object for wrap:** `None` passed to `execute_direct` because wrap invocations have no session tracking need; `SessionLaunchOptions::default()` gives empty string which would produce malformed named Job Object `Local\nono-session-`. Safety of `create_process_containment(None)` was pre-verified in plan context.
- **No code changes for session commands:** Pre-verified facts confirmed SESS-01/02/03 already satisfied. Grep verification + CI confirmation sufficient.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed rustfmt formatting violation in setup.rs**
- **Found during:** Task 2 (CI checks — `cargo fmt --all -- --check`)
- **Issue:** The new `println!` for the shell message exceeded line width; fmt wanted multi-line form
- **Fix:** Rewrapped `println!` to multi-line format matching rustfmt style
- **Files modified:** `crates/nono-cli/src/setup.rs`
- **Verification:** `cargo fmt --all -- --check` exits 0
- **Committed in:** `14e838e` (separate fix commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 — formatting)
**Impact on plan:** Trivial formatting fix, no behavioral change. No scope creep.

## Issues Encountered

Two pre-existing test failures were found (confirmed pre-existing by testing against HEAD~1):

1. `profile::builtin::tests::test_all_profiles_signal_mode_resolves` — `XDG_CONFIG_HOME` set to Unix path, fails on Windows; env var not restored per CLAUDE.md save/restore pattern
2. `query_ext::tests::test_query_path_sensitive_policy_includes_policy_source` — sensitive path detection returns `path_not_granted` instead of `sensitive_path` on Windows

Both are logged in `deferred-items.md` and are out of scope for this plan (CLAUDE.md scope boundary: only auto-fix issues directly caused by current task's changes).

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- `nono wrap` is now functional on Windows with Job Object + WFP enforcement; ready for end-to-end manual testing
- Session commands (logs, inspect, prune) are available on Windows — ready for use with any existing Windows sessions
- Phase 08 (ConPTY shell) can proceed; `nono shell` is the remaining unavailable command documented in setup help text

---
*Phase: 07-quick-wins*
*Completed: 2026-04-08*
