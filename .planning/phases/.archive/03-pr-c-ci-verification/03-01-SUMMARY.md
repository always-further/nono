---
phase: 03-pr-c-ci-verification
plan: "01"
subsystem: nono-cli
tags: [windows, cli, help-strings, promoted-contract]
dependency_graph:
  requires: [02-pr-b-cli-messaging]
  provides: [CIVER-01]
  affects: [crates/nono-cli/src/cli.rs]
tech_stack:
  added: []
  patterns: [cfg-target-os-windows, clap-after-help, clap-about]
key_files:
  created: []
  modified:
    - crates/nono-cli/src/cli.rs
decisions:
  - "Drop Windows qualifier from CLI_ABOUT entirely — after promotion, root description must not single out Windows"
  - "ROOT_HELP_TEMPLATE shell/wrap lines updated to say 'intentionally unavailable' to match SHELL/WRAP_AFTER_HELP wording (aligns root template with subcommand help)"
  - "Single assertion covers both shell and wrap limitations since 'intentionally unavailable on Windows' appears in both after-help consts and the root template"
metrics:
  duration: "4min"
  completed: "2026-04-03T23:32:10Z"
  tasks_completed: 2
  files_modified: 1
---

# Phase 03 Plan 01: CLI Help String Windows Promotion Summary

**One-liner:** Updated CLI_ABOUT, 7 AFTER_HELP consts, ROOT_HELP_TEMPLATE, and root help test to remove all "preview surface" and "Windows restricted execution" language, replacing with promoted contract wording.

## What Was Done

Aligned `crates/nono-cli/src/cli.rs` Windows help strings with the promoted Windows support contract from PR-A/B. The file had two categories of stale language:

1. **CLI_ABOUT** (Windows cfg variant): Said "Windows restricted execution plus explicit command-surface limitations" — removed the Windows qualifier entirely. Root description now says "OS-enforced isolation" on all platforms.

2. **7 AFTER_HELP consts** (PS, STOP, DETACH, ATTACH, LOGS, INSPECT, PRUNE): Each contained "not implemented for the current Windows preview surface" or "on the current Windows preview surface" — replaced with "not available on Windows" or "on Windows" as appropriate.

3. **ROOT_HELP_TEMPLATE** shell/wrap lines: Said "live shell is unsupported on Windows" / "live wrap is unsupported on Windows" — updated to "intentionally unavailable on Windows" to match the SHELL_AFTER_HELP / WRAP_AFTER_HELP wording (deviation fix, see below).

4. **test_root_help_mentions_windows_restricted_execution_surface**: Updated two assertions and removed one:
   - `"Windows restricted execution..."` → `"OS-enforced isolation"`
   - `"live shell is unsupported on Windows"` + `"live wrap is unsupported on Windows"` → single `"intentionally unavailable on Windows"`

## Tasks

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Update CLI_ABOUT and 7 AFTER_HELP preview-surface strings | caa35d0 | crates/nono-cli/src/cli.rs |
| 2 | Update root help test assertions | f7689eb | crates/nono-cli/src/cli.rs |

## Verification Results

- `grep -c "preview surface" crates/nono-cli/src/cli.rs` → **0** (was 7)
- `grep -c "Windows restricted execution" crates/nono-cli/src/cli.rs` → **0** (was 1)
- `grep -c "OS-enforced isolation" crates/nono-cli/src/cli.rs` → **3** (const + 2 test assertion lines)
- `cargo test -p nono-cli --bin nono test_root_help_mentions_windows_restricted_execution_surface` → **1 passed, 0 failed**
- `cargo clippy -p nono-cli -- -D warnings -D clippy::unwrap_used` → **clean**
- `cargo build -p nono-cli` → **Finished**

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] ROOT_HELP_TEMPLATE shell/wrap lines updated to "intentionally unavailable"**
- **Found during:** Task 2
- **Issue:** Plan said to update test assertion from `"live shell is unsupported on Windows"` to `"intentionally unavailable on Windows"`. But `write_long_help` renders the ROOT_HELP_TEMPLATE, which contained "live shell is unsupported on Windows" — not the SHELL_AFTER_HELP text. The new assertion would always fail unless the root template was also updated.
- **Fix:** Updated ROOT_HELP_TEMPLATE lines 89-90 from "unsupported on Windows" to "intentionally unavailable on Windows", aligning the root template with the subcommand after-help wording. The test now correctly passes.
- **Files modified:** `crates/nono-cli/src/cli.rs` (lines 89-90)
- **Commit:** f7689eb

## Known Stubs

None. All help string changes are wired to real clap constants consumed at render time.

## Self-Check: PASSED

- cli.rs: FOUND
- SUMMARY.md: FOUND
- Commit caa35d0 (Task 1): FOUND
- Commit f7689eb (Task 2): FOUND
