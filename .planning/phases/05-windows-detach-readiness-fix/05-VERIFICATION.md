---
phase: 05-windows-detach-readiness-fix
verified: 2026-04-05T21:00:00Z
status: passed
score: 5/5 must-haves verified
re_verification: false
---

# Phase 05: Windows Detach Readiness Fix — Verification Report

**Phase Goal:** Fix the readiness check in `startup_runtime.rs` so `nono run --detach` works on Windows by probing the Named Pipe instead of a `.sock` file.
**Verified:** 2026-04-05T21:00:00Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | `nono run --detach` on Windows detects Named Pipe readiness via `WaitNamedPipeW` instead of `.sock` file existence | VERIFIED | `startup_runtime.rs` lines 74-94: `#[cfg(target_os = "windows")]` block calls `WaitNamedPipeW(pipe_name_u16.as_ptr(), 50)` |
| 2 | Returns `Ok` when supervisor pipe becomes available within 2 seconds | VERIFIED | Line 96-100: `if session_path.exists() && attach_ready { ... return Ok(()) }` — deadline variable (line 69) unchanged at 2 seconds |
| 3 | Returns `Err(SandboxInit)` with descriptive message on unexpected `WaitNamedPipeW` errors (fail-closed) | VERIFIED | Lines 88-93: `return Err(NonoError::SandboxInit(format!("Named pipe readiness probe failed with error {err}")))` for any error other than `ERROR_FILE_NOT_FOUND` or `ERROR_SEM_TIMEOUT` |
| 4 | Non-Windows builds are unchanged — `attach_path.exists()` still used | VERIFIED | Lines 67-68: `#[cfg(not(target_os = "windows"))] let attach_path = ...`; lines 71-72: `#[cfg(not(target_os = "windows"))] let attach_ready = attach_path.exists()` |
| 5 | No compiler warnings on any platform (`clippy -D warnings` passes) | VERIFIED | `cargo clippy --all-targets -p nono-cli -- -D warnings -D clippy::unwrap_used` exits 0 with no output |

**Score:** 5/5 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/nono-cli/src/startup_runtime.rs` | Platform-guarded readiness check in `run_detached_launch()` | VERIFIED | Contains `WaitNamedPipeW`, `#[cfg(target_os = "windows")]` block, `#[cfg(not(target_os = "windows"))]` guard on `attach_path`, and `attach_ready` variable replacing old `attach_path.exists()` check |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `startup_runtime.rs` | `exec_strategy_windows/supervisor.rs` | Pipe name format `\\.\pipe\nono-session-{session_id}` | VERIFIED | `startup_runtime.rs` line 79 matches `supervisor.rs` line 297 exactly: `format!("\\\\.\\pipe\\nono-session-{}", session_id)` |
| `startup_runtime.rs` | `exec_strategy_windows/mod.rs` | `crate::exec_strategy::to_u16_null_terminated` | VERIFIED | `exec_strategy_windows/mod.rs` exports `to_u16_null_terminated` at line 59 as `pub(crate)`. On Windows, `main.rs` maps `mod exec_strategy` to `exec_strategy_windows/mod.rs` (lines 15-17), so `crate::exec_strategy::to_u16_null_terminated` resolves correctly. |

### Data-Flow Trace (Level 4)

Not applicable — `startup_runtime.rs` contains control-flow logic (OS readiness probe), not a rendering component with dynamic data display.

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| `startup_runtime` unit tests pass unchanged | `cargo test -p nono-cli --bin nono startup_runtime` | 6 passed, 0 failed | PASS |
| `nono-cli` compiles clean | `cargo build -p nono-cli` | Finished in 6.15s, no errors | PASS |
| Strict clippy passes | `cargo clippy --all-targets -p nono-cli -- -D warnings -D clippy::unwrap_used` | Finished, no warnings | PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| SUPV-01 | 05-01-PLAN.md | User can detach from a running Windows agent using `nono run --detach` | SATISFIED | `run_detached_launch()` now correctly probes Named Pipe readiness on Windows; the detach flow is no longer blocked waiting for a `.sock` file that never appears |
| SUPV-02 | 05-01-PLAN.md | User can re-attach to a running Windows agent session via Named Pipe IPC | SATISFIED | The readiness gate now confirms the Named Pipe is listening before returning `Ok`, ensuring attach commands will find a live pipe |

No orphaned requirements — REQUIREMENTS.md maps only SUPV-01 and SUPV-02 to Phase 5, both covered by 05-01-PLAN.md.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| — | — | None | — | — |

No TODOs, FIXMEs, stubs, empty implementations, or hardcoded empty data found in `startup_runtime.rs`.

### Human Verification Required

#### 1. Windows End-to-End Detach/Attach Flow

**Test:** On a Windows 10/11 machine, run `nono run --detach -- <some-long-running-command>`, then run `nono attach <session-id>`.
**Expected:** `nono run --detach` exits with a "Started detached session" banner within ~2 seconds. `nono attach` successfully connects to the running session via Named Pipe.
**Why human:** Cannot start a live Windows supervisor process in this environment to verify that `WaitNamedPipeW` returns non-zero when the Named Pipe server in `supervisor.rs` is actually listening.

#### 2. Fail-Closed Path Under Error

**Test:** On Windows, force `WaitNamedPipeW` to return an unexpected error code (e.g., by simulating an error other than `ERROR_FILE_NOT_FOUND`/`ERROR_SEM_TIMEOUT`).
**Expected:** `nono run --detach` returns a `SandboxInit` error with "Named pipe readiness probe failed with error N".
**Why human:** Triggering a specific Windows API error code in a live test requires process manipulation or a debug build with injected failure.

### Gaps Summary

No gaps. All 5 must-have truths are verified, both key links are wired, both requirements are satisfied, and the build and tests pass clean. Two items are flagged for human verification as they require live Windows process execution, but all automated checks pass.

---

_Verified: 2026-04-05T21:00:00Z_
_Verifier: Claude (gsd-verifier)_
