# Phase 5: Windows Detach Readiness Fix - Context

**Gathered:** 2026-04-05
**Status:** Ready for planning

<domain>
## Phase Boundary

Fix the readiness check in `startup_runtime.rs` so `nono run --detach` works on Windows. The current check probes for a `.sock` file (Unix only); Windows uses Named Pipes which are not filesystem paths. Scope: modify the readiness polling loop in `run_detached_launch()` to use a Windows-appropriate probe. Does NOT change the supervisor, IPC protocol, attach flow, or any other caller.

</domain>

<decisions>
## Implementation Decisions

### Pipe probe method
- **D-01:** Use `WaitNamedPipe` with a short per-iteration timeout (~50ms) to detect Named Pipe readiness.
- **D-02:** `WaitNamedPipe` returns `TRUE` when a pipe instance is available — no handle opened, no cleanup required.
- **D-03:** A return value of `FALSE` with `GetLastError() == ERROR_FILE_NOT_FOUND` means not ready yet — retry. Any other error is a hard failure (fail-closed, consistent with Phase 1 decisions).

### Platform guard placement
- **D-04:** Add an inline `#[cfg(target_os = "windows")]` block directly in `run_detached_launch()` in `startup_runtime.rs`. No new helpers, no changes to `session.rs`.
- **D-05:** The Windows branch replaces the `attach_path.exists()` check. The `session_path.exists()` (`.json` file) check remains shared — the supervisor must still write the session record.
- **D-06:** Pipe name format: `\\.\pipe\nono-session-{session_id}` — consistent with `exec_strategy_windows/supervisor.rs:297`.

### Startup timeout
- **D-07:** Keep the 2-second deadline on Windows (same as Unix). No platform-specific timeout constant.

### Claude's Discretion
- Exact `windows_sys` imports needed for `WaitNamedPipe`.
- Whether to inline the pipe name format or reference a constant.
- Sleep duration between poll iterations on Windows (existing 50ms loop is fine).

</decisions>

<specifics>
## Specific Ideas

- The fix is surgical: only `run_detached_launch()` in `startup_runtime.rs` changes. The broken line is `startup_runtime.rs:70` where `attach_path.exists()` will never be true on Windows.
- `WaitNamedPipe` API: `WaitNamedPipe(lpNamedPipeName: PCWSTR, nTimeOut: u32) -> BOOL` — available in `windows_sys::Win32::System::Pipes`.
- The supervisor creates the control pipe early in its lifecycle (`exec_strategy_windows/supervisor.rs:297`), so 2 seconds is more than sufficient.

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Files to modify
- `crates/nono-cli/src/startup_runtime.rs` — Contains `run_detached_launch()`, the broken readiness check is at line ~67-70

### Reference implementations (read-only)
- `crates/nono-cli/src/exec_strategy_windows/supervisor.rs` — Lines ~295-310: how the supervisor creates `\\.\pipe\nono-session-{session_id}`. The pipe name format here must match the probe in `startup_runtime.rs`.
- `crates/nono-cli/src/session.rs` — Lines 729-737: `session_file_path()` and `session_socket_path()` — understand what the Unix readiness check uses so the Windows branch is a parallel, not a replacement.

### Design docs
- `proj/DESIGN-supervisor.md` — Process model, execution strategies, named pipe IPC protocol

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `windows_sys::Win32::System::Pipes` — Already a dependency in `nono-cli/Cargo.toml`; `WaitNamedPipe` is in this module.
- `std::os::windows::process::CommandExt` — Already imported in `startup_runtime.rs` for the `creation_flags` call; Windows API pattern is established in this file.

### Established Patterns
- Fail-closed: All Windows API calls in this codebase check return values and return `Err(NonoError::SandboxInit(...))` on failure. The `WaitNamedPipe` branch must follow the same pattern.
- `#[cfg(target_os = "windows")]` blocks are used throughout `startup_runtime.rs` — the new block is consistent with existing style.

### Integration Points
- `run_detached_launch()` is the only caller of `session_socket_path()` in the startup flow. The fix is entirely self-contained within that function.

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 05-windows-detach-readiness-fix*
*Context gathered: 2026-04-05*
