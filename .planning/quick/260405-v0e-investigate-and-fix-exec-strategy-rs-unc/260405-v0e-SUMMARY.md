---
quick_id: 260405-v0e
status: completed
date: 2026-04-06
---

# Summary: Fix exec_strategy.rs Unix/Windows Parity Bugs

## What Was Found

Two classes of bugs in `crates/nono-cli/src/exec_strategy.rs` (Unix-only file, not checked by `cargo check` on Windows):

### Bug 1: Missing `rollback_status` parameter (critical)

The Unix `execute_supervised` was missing `rollback_status: nono::undo::RollbackStatus` between `rollback_state` and `proxy_handle`. The Windows version (`exec_strategy_windows/mod.rs`) correctly has this parameter, and `supervised_runtime.rs` passes it from both `#[cfg(not(target_os = "windows"))]` and `#[cfg(target_os = "windows")]` call sites. On Linux/macOS this would fail to compile — the caller passes 14 args to a 13-param function.

Additionally, the `RollbackExitContext { ... }` construction was missing the `rollback_status` field, which `finalize_supervised_exit` requires.

### Bug 2: Incomplete startup_timeout removal (would fail to compile on Unix)

The diff removed `print_terminal_safe_stderr` and `prompt_startup_termination` function definitions and `ExecConfig.startup_timeout` field, but left call sites intact in:
- `wait_for_child_with_pty` (calls `prompt_startup_termination`)
- `wait_for_child_with_startup_timeout` (calls `prompt_startup_termination`)
- `run_supervisor_loop` non-Linux (calls `prompt_startup_termination`)
- `run_supervisor_loop` Linux (calls `prompt_startup_termination`)
- `execution_runtime.rs` ExecConfig construction (sets `startup_timeout` field that no longer exists)

## What Was Fixed

**exec_strategy.rs:**
- Added `rollback_status: nono::undo::RollbackStatus` param to `execute_supervised`
- Added `rollback_status` to `RollbackExitContext { ... }` construction
- Removed `StartupTimeoutConfig` struct
- Removed `startup_timeout` param from `wait_for_child_with_pty`, simplified to call `wait_for_child()` for the no-pty case
- Removed `wait_for_child_with_startup_timeout` function
- Removed startup_deadline/startup_prompted logic and `prompt_startup_termination` calls from both `run_supervisor_loop` variants
- Removed `startup_timeout` param from both `run_supervisor_loop` function signatures
- Updated all 5 `run_supervisor_loop` call sites (2 production + 3 test)
- Removed unused `use std::time::{Duration, Instant}`

**execution_runtime.rs:**
- Removed `PROFILE_HINT_STARTUP_TIMEOUT` constant
- Removed `should_apply_startup_timeout` function
- Removed `startup_timeout: ...` field from Unix `ExecConfig` construction
- Removed `use super::should_apply_startup_timeout` test import
- Removed `startup_timeout_applies_only_to_bare_interactive_profiled_tools` test

## Verification

- `cargo check -p nono-cli` passes on Windows (platform used for development)
- No remaining references to: `StartupTimeoutConfig`, `startup_timeout`, `should_apply_startup_timeout`, `PROFILE_HINT_STARTUP_TIMEOUT`, `prompt_startup_termination`, `print_terminal_safe_stderr`
