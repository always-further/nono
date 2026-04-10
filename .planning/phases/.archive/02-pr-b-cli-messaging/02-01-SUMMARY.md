---
phase: 02-pr-b-cli-messaging
plan: 01
subsystem: cli
tags: [windows, sandbox, cli-messaging, dead-code, is_supported]

# Dependency graph
requires:
  - phase: 01-pr-a-library-contract
    provides: "is_supported=true on Windows; apply() routes real backend path; status_label() returns 'supported'"
provides:
  - "Unified 'Support status:' line in setup.rs using info.status_label() only"
  - "No dead !is_supported branches in execution_runtime.rs, command_runtime.rs, output.rs"
  - "shell/wrap rejection fires unconditionally on Windows (security fix)"
  - "validate_windows_preview_direct_execution deleted (was always Ok after PR-A)"
affects: [02-02, 03-pr-c-ci-promotion, 04-pr-d-docs-flip]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Library contract as single source of truth: info.status_label() replaces CLI-owned labels"
    - "Unconditional Windows entry-point validation: no is_supported guard before shell/wrap rejection"

key-files:
  created: []
  modified:
    - crates/nono-cli/src/setup.rs
    - crates/nono-cli/src/execution_runtime.rs
    - crates/nono-cli/src/command_runtime.rs
    - crates/nono-cli/src/output.rs

key-decisions:
  - "info.status_label() from the library is the single source of truth for Windows support status in all CLI output"
  - "shell/wrap validation fires unconditionally on Windows — the is_supported guard was the bug, not the guard itself"

patterns-established:
  - "No separate CLI support label: the library contract dictates what the CLI displays"
  - "Dead cfg branches removed rather than kept with allow(dead_code)"

requirements-completed: [CLIMSG-01, CLIMSG-02, CLIMSG-03]

# Metrics
duration: 12min
completed: 2026-04-03
---

# Phase 02 Plan 01: PR-B CLI Messaging Cleanup Summary

**Deleted CLI/library support split and dead !is_supported branches from setup.rs, execution_runtime.rs, command_runtime.rs, and output.rs; shell/wrap rejection on Windows now fires unconditionally**

## Performance

- **Duration:** ~12 min
- **Started:** 2026-04-03T22:35:00Z
- **Completed:** 2026-04-03T22:37:10Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments
- Collapsed two-line CLI/library status split into single `Support status: {}` using `info.status_label()` in both `test_windows_support` and `print_check_only_summary` in setup.rs
- Deleted `windows_cli_support_status_label()` function — library contract is now the sole source of truth
- Removed dead `!is_supported` cfg block from `apply_pre_fork_sandbox` in execution_runtime.rs; removed unused `current_dir: &Path` parameter that was only used inside that dead block
- Deleted `validate_windows_preview_direct_execution` (always returned `Ok(())` after PR-A) and its call site
- Removed `!Sandbox::support_info().is_supported` guards from `run_shell` and `run_wrap` in command_runtime.rs — `validate_windows_preview_entry_point` now fires unconditionally on Windows for both shell and wrap (security fix: the guard was letting these through when is_supported was true)
- Removed dead Windows `!is_supported` blocks from `print_banner`, `print_supervised_info`, and `dry_run_summary` in output.rs

## Task Commits

Each task was committed atomically:

1. **Task 1: Remove dead code from setup.rs and collapse unified status line** - `1795a73` (feat)
2. **Task 2: Remove dead branches from execution_runtime.rs, command_runtime.rs, and output.rs** - `4b93d0a` (feat)

**Plan metadata:** (committed with final docs commit)

## Files Created/Modified
- `crates/nono-cli/src/setup.rs` - Unified support status line; deleted windows_cli_support_status_label
- `crates/nono-cli/src/execution_runtime.rs` - Removed dead Windows cfg block, current_dir param, validate_windows_preview_direct_execution
- `crates/nono-cli/src/command_runtime.rs` - Unconditional shell/wrap rejection on Windows
- `crates/nono-cli/src/output.rs` - Removed dead !is_supported blocks from banner, supervised info, dry-run summary

## Decisions Made
- The `if !support.is_supported` guard before `validate_windows_preview_entry_point` in command_runtime.rs was a security defect introduced when `is_supported` was false on Windows — with PR-A making it true, the guard was silently bypassing the validation. The fix is to make the call unconditional inside the `#[cfg(target_os = "windows")]` block.
- `_support` parameter retained in `dry_run_summary` signature to avoid breaking callers even though the body now ignores it (clippy satisfied with `_` prefix).

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None.

## Known Stubs
None — all output now routes through the library's `status_label()` and the dead Windows-specific messaging is fully removed.

## Next Phase Readiness
- Plan 02-02 (tests encoding promoted Windows contract) can now proceed: the CLI runtime messaging is clean and honest
- No remaining `!is_supported` dead branches in production CLI code
- `cargo clippy -p nono-cli -- -D warnings -D clippy::unwrap_used` passes clean

---
*Phase: 02-pr-b-cli-messaging*
*Completed: 2026-04-03*

## Self-Check: PASSED
