# Phase 5: Windows Detach Readiness Fix - Research

**Researched:** 2026-04-05
**Domain:** Windows Named Pipe readiness probing in Rust (windows-sys 0.59)
**Confidence:** HIGH

## Summary

Phase 5 is a surgical, single-function fix. The root cause is that `run_detached_launch()` in `startup_runtime.rs` waits for both `session_path.exists()` (the `.json` session record) and `attach_path.exists()` (the `.sock` file). On Windows the supervisor never creates a `.sock` file — it creates a Named Pipe (`\\.\pipe\nono-session-{session_id}`). The `.exists()` probe will never return `true` on a Named Pipe path because Named Pipes are not filesystem objects visible to `std::path::Path::exists()`. The result is that `nono run --detach` always hits the 2-second timeout and returns `SandboxInit` error on Windows.

The fix adds a `#[cfg(target_os = "windows")]` block inside the polling loop that replaces the `attach_path.exists()` check with a `WaitNamedPipeW` probe. All surrounding infrastructure — the timeout, the sleep interval, the session JSON file check, the child-process death check, the error path — is shared and unchanged. No new files, no helper functions, no changes to session.rs or the supervisor.

`WaitNamedPipeW` is already present in the codebase (`crates/nono/src/supervisor/socket_windows.rs:544` and `crates/nono-cli/src/session_commands_windows.rs:138/225/282`) and the `Win32_System_Pipes` feature is already enabled in `nono-cli/Cargo.toml`. The pipe name format `\\.\pipe\nono-session-{session_id}` is authoritative in `exec_strategy_windows/supervisor.rs:297`.

**Primary recommendation:** Add a single `#[cfg(target_os = "windows")]` block replacing `attach_path.exists()` with a `WaitNamedPipeW` probe that treats `TRUE` as ready and `FALSE/ERROR_FILE_NOT_FOUND` as not-yet-ready; any other `FALSE` case is a hard failure.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Use `WaitNamedPipe` with a short per-iteration timeout (~50ms) to detect Named Pipe readiness.
- **D-02:** `WaitNamedPipe` returns `TRUE` when a pipe instance is available — no handle opened, no cleanup required.
- **D-03:** A return value of `FALSE` with `GetLastError() == ERROR_FILE_NOT_FOUND` means not ready yet — retry. Any other error is a hard failure (fail-closed, consistent with Phase 1 decisions).
- **D-04:** Add an inline `#[cfg(target_os = "windows")]` block directly in `run_detached_launch()` in `startup_runtime.rs`. No new helpers, no changes to `session.rs`.
- **D-05:** The Windows branch replaces the `attach_path.exists()` check. The `session_path.exists()` (`.json` file) check remains shared — the supervisor must still write the session record.
- **D-06:** Pipe name format: `\\.\pipe\nono-session-{session_id}` — consistent with `exec_strategy_windows/supervisor.rs:297`.
- **D-07:** Keep the 2-second deadline on Windows (same as Unix). No platform-specific timeout constant.

### Claude's Discretion

- Exact `windows_sys` imports needed for `WaitNamedPipe`.
- Whether to inline the pipe name format or reference a constant.
- Sleep duration between poll iterations on Windows (existing 50ms loop is fine).

### Deferred Ideas (OUT OF SCOPE)

None — discussion stayed within phase scope.
</user_constraints>

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `windows-sys` | 0.59 | Low-level Windows API FFI bindings | Already in `nono-cli/Cargo.toml`; `Win32_System_Pipes` feature already enabled |

`WaitNamedPipeW` is in `windows_sys::Win32::System::Pipes`. No new dependencies.

**Installation:** No new packages. Dependency is already present.

### Existing Pattern Reference

`session_commands_windows.rs` already calls `WaitNamedPipeW`:

```rust
use windows_sys::Win32::System::Pipes::WaitNamedPipeW;
// ...
let pipe_name_u16 = to_u16_null_terminated(&pipe_name);
unsafe {
    WaitNamedPipeW(pipe_name_u16.as_ptr(), 500);
}
```

The `to_u16_null_terminated` helper is defined at `exec_strategy_windows/mod.rs:60` with `pub(crate)` visibility, so it is accessible as `crate::exec_strategy::to_u16_null_terminated` from `startup_runtime.rs` (on Windows, `exec_strategy` maps to `exec_strategy_windows/mod.rs` via the `#[path]` attribute in `main.rs`).

## Architecture Patterns

### Existing `#[cfg(target_os = "windows")]` Pattern in startup_runtime.rs

The file already uses platform guards in exactly the shape needed. Lines 39-50 demonstrate the pattern:

```rust
#[cfg(target_os = "windows")]
{
    use windows_sys::Win32::System::Threading::{...};
    use std::os::windows::process::CommandExt as _;
    child.creation_flags(...);
}
```

The new block must mirror this structure inside the `while` loop, replacing one condition in the readiness check.

### Readiness Check Structure (Current, Broken)

```
while now < deadline {
    if session_path.exists() && attach_path.exists() {  // line 70: BROKEN on Windows
        return Ok(());
    }
    // child death check
    // sleep 50ms
}
```

### Readiness Check Structure (Target, Fixed)

```
while now < deadline {
    let attach_ready = {
        #[cfg(target_os = "windows")]
        {
            // WaitNamedPipeW probe — see Code Examples
        }
        #[cfg(not(target_os = "windows"))]
        {
            attach_path.exists()
        }
    };

    if session_path.exists() && attach_ready {
        return Ok(());
    }
    // child death check (unchanged)
    // sleep 50ms (unchanged)
}
```

Alternatively — and more surgical — keep `attach_path.exists()` on non-Windows, and gate the entire `if` condition:

```rust
#[cfg(not(target_os = "windows"))]
let attach_ready = attach_path.exists();

#[cfg(target_os = "windows")]
let attach_ready: Result<bool> = { /* WaitNamedPipeW probe */ };
```

The cleanest form may be a `bool`-returning inline expression so the `if` line stays unchanged. The planner should pick the form that minimizes diff size while remaining readable.

### Anti-Patterns to Avoid

- **Opening a handle to verify existence:** Do not use `CreateFile` to probe the pipe. `WaitNamedPipeW` is the correct API for "does a pipe instance exist right now without consuming it."
- **String path for pipe existence:** Do not call `attach_path.exists()` on Windows. `Path::exists()` uses `GetFileAttributesW` which returns `INVALID_FILE_ATTRIBUTES` for Named Pipe paths — it does not probe the Named Pipe server.
- **Reusing the `.sock` path as pipe name:** The pipe name is `\\.\pipe\nono-session-{session_id}`, not a filesystem path. Constructing the pipe name must use the session_id directly, not the `attach_path` value.
- **Ignoring `GetLastError` after FALSE:** `WaitNamedPipeW` returning `FALSE` can mean either "pipe not found yet" (safe to retry) or "some other error" (fail-closed). Only `ERROR_FILE_NOT_FOUND` (2) and `ERROR_SEM_TIMEOUT` (121) are safe retries. All other errors must propagate as `NonoError::SandboxInit`.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Wide-string conversion | Custom UTF-16 encoder | `to_u16_null_terminated` from `crate::exec_strategy` | Already `pub(crate)`, handles null terminator correctly |
| Pipe existence probe | `std::fs::metadata()` or `CreateFile` | `WaitNamedPipeW` | Designed exactly for this; no handle leak risk |
| Error code lookup | Manual constant literals | `windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND` | Typed constants from the same crate already in use |

## Common Pitfalls

### Pitfall 1: `ERROR_SEM_TIMEOUT` vs `ERROR_FILE_NOT_FOUND`

**What goes wrong:** `WaitNamedPipeW` with a 50ms timeout returns `FALSE` for two distinct reasons: (a) the pipe server doesn't exist yet (`ERROR_FILE_NOT_FOUND = 2`) and (b) the pipe exists but all instances are busy for the full timeout (`ERROR_SEM_TIMEOUT = 121`). In the readiness polling context `ERROR_SEM_TIMEOUT` is also a "not ready" condition (the server has not yet started `ConnectNamedPipe`) and should be treated as retry-safe.

**How to avoid:** Treat both `ERROR_FILE_NOT_FOUND` and `ERROR_SEM_TIMEOUT` as "retry" conditions. Treat everything else as a hard failure.

**Reference:** `socket_windows.rs:541` treats `ERROR_FILE_NOT_FOUND` and `ERROR_PIPE_BUSY` as retry conditions in a similar connect loop.

### Pitfall 2: Using `attach_path` to construct the pipe name

**What goes wrong:** `session_socket_path()` returns a path like `~/.nono/sessions/{id}.sock`. On Windows this path is used by Unix for socket files but it is not the Named Pipe path. If you call `WaitNamedPipeW` with this path it will fail unconditionally.

**How to avoid:** Construct the pipe name inline as `format!("\\\\.\\pipe\\nono-session-{}", session_id)` (consistent with D-06 and `supervisor.rs:297`). Do not transform `attach_path`.

### Pitfall 3: `attach_path` variable unused on Windows causing compiler warning

**What goes wrong:** The `attach_path` binding on line 67 is used only in the non-Windows branch. If `#[cfg(not(target_os = "windows"))]` is not applied to the binding, Clippy will emit a dead code warning on Windows builds (which is CI-fatal due to `-D warnings`).

**How to avoid:** Either gate the `attach_path` binding with `#[cfg(not(target_os = "windows"))]`, or use `let _attach_path = ...` and only use it in the non-Windows block. The cleanest approach is to cfg-gate the variable itself.

### Pitfall 4: Import scope for `WaitNamedPipeW` and `GetLastError`

**What goes wrong:** `WaitNamedPipeW` is in `windows_sys::Win32::System::Pipes`; `GetLastError` is in `windows_sys::Win32::Foundation`. Both must be imported inside the `#[cfg(target_os = "windows")]` block. Importing outside the cfg guard causes "unused import" warnings on non-Windows builds.

**How to avoid:** Place all Windows-specific `use` statements inside the `#[cfg(target_os = "windows")]` block, following the pattern already used on lines 40-44 of `startup_runtime.rs`.

## Code Examples

### Authoritative Pipe Name Construction (from supervisor.rs:297)

```rust
// Source: crates/nono-cli/src/exec_strategy_windows/supervisor.rs:297
let pipe_name = format!("\\\\.\\pipe\\nono-session-{}", session_id);
```

### WaitNamedPipeW Probe Pattern (from session_commands_windows.rs:134-139)

```rust
// Source: crates/nono-cli/src/session_commands_windows.rs:134-139
let pipe_name = format!("\\\\.\\pipe\\nono-session-{}", session.session_id);
let pipe_name_u16 = to_u16_null_terminated(&pipe_name);
unsafe {
    windows_sys::Win32::System::Pipes::WaitNamedPipeW(pipe_name_u16.as_ptr(), 500);
}
```

### Fail-Closed Error Handling for WaitNamedPipeW (adapted from socket_windows.rs)

```rust
// Source: crates/nono/src/supervisor/socket_windows.rs:538-550
use windows_sys::Win32::Foundation::{GetLastError, ERROR_FILE_NOT_FOUND, ERROR_SEM_TIMEOUT};
use windows_sys::Win32::System::Pipes::WaitNamedPipeW;

let result = unsafe { WaitNamedPipeW(pipe_name_u16.as_ptr(), 50) };
if result != 0 {
    // Pipe instance available — server is ready
    true  // attach_ready = true
} else {
    let err = unsafe { GetLastError() };
    if err == ERROR_FILE_NOT_FOUND || err == ERROR_SEM_TIMEOUT {
        // Server not ready yet — safe to retry
        false  // attach_ready = false, loop continues
    } else {
        // Unexpected error — fail closed
        return Err(NonoError::SandboxInit(format!(
            "Named pipe readiness probe failed (error {})", err
        )));
    }
}
```

### Full Readiness Block Sketch

```rust
// In run_detached_launch(), inside the while loop:

#[cfg(not(target_os = "windows"))]
let attach_path = session::session_socket_path(&session_id)?;

// ...

while std::time::Instant::now() < deadline {
    #[cfg(not(target_os = "windows"))]
    let attach_ready = attach_path.exists();

    #[cfg(target_os = "windows")]
    let attach_ready = {
        use windows_sys::Win32::Foundation::{GetLastError, ERROR_FILE_NOT_FOUND, ERROR_SEM_TIMEOUT};
        use windows_sys::Win32::System::Pipes::WaitNamedPipeW;
        let pipe_name = format!("\\\\.\\pipe\\nono-session-{}", session_id);
        let pipe_name_u16 = crate::exec_strategy::to_u16_null_terminated(&pipe_name);
        let result = unsafe { WaitNamedPipeW(pipe_name_u16.as_ptr(), 50) };
        if result != 0 {
            true
        } else {
            let err = unsafe { GetLastError() };
            if err == ERROR_FILE_NOT_FOUND || err == ERROR_SEM_TIMEOUT {
                false
            } else {
                return Err(NonoError::SandboxInit(format!(
                    "Named pipe readiness probe failed with error {err}"
                )));
            }
        }
    };

    if session_path.exists() && attach_ready {
        cleanup_startup_log(&startup_log_path);
        print_detached_launch_banner(&session_id, args.name.as_deref(), silent);
        return Ok(());
    }

    // ... child death check and sleep unchanged ...
}
```

Note: Moving `attach_path` computation out of the loop (guarded by `#[cfg(not(target_os = "windows"))]`) is one way to handle the unused variable. The planner may also keep it inside the loop gated the same way. Either form is correct as long as clippy is clean.

## Environment Availability

Step 2.6: SKIPPED — This phase is a pure code change within the existing Rust workspace. No external tools, services, or CLIs beyond the Rust toolchain are required, and the Rust toolchain is already established.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `.sock` path existence check (Unix) | `.sock` exists for Unix; `WaitNamedPipeW` probe for Windows | This phase | Unblocks `nono run --detach` on Windows |

**Broken behavior (pre-fix):**
- `attach_path.exists()` on Windows: `Path::exists()` resolves to `GetFileAttributesW`; Named Pipe paths (`\\.\pipe\...`) return `INVALID_FILE_ATTRIBUTES` — exists() returns `false` unconditionally regardless of pipe server state.

## Open Questions

1. **Pipe name inlining vs constant**
   - What we know: D-06 specifies the format string `\\.\pipe\nono-session-{session_id}`. A constant cannot embed the runtime session_id.
   - What's unclear: Whether the planner wants a module-level named format string constant (e.g., `CONTROL_PIPE_PREFIX`) or full inline. Both are correct.
   - Recommendation: Inline the `format!` call with a comment referencing `supervisor.rs:297`. Avoids a constant that is only used in one place.

2. **`attach_path` binding fate**
   - What we know: Line 67 creates `attach_path` from `session_socket_path()`. On Windows this is dead code post-fix.
   - What's unclear: Whether to remove the binding entirely on Windows (cfg-gate it) or keep it with `#[allow(unused_variables)]`.
   - Recommendation: Cfg-gate the binding — consistent with project's strict clippy settings and the `#[allow(dead_code)]` avoidance policy in CLAUDE.md.

## Sources

### Primary (HIGH confidence)

- Direct source read: `crates/nono-cli/src/startup_runtime.rs` — confirmed exact broken line (70), surrounding structure, existing `#[cfg(target_os = "windows")]` pattern
- Direct source read: `crates/nono-cli/src/exec_strategy_windows/supervisor.rs:297` — authoritative pipe name format
- Direct source read: `crates/nono-cli/src/session_commands_windows.rs:134-139` — `WaitNamedPipeW` call pattern already established in codebase
- Direct source read: `crates/nono/src/supervisor/socket_windows.rs:538-550` — fail-closed error handling for `WaitNamedPipeW`
- Direct source read: `crates/nono-cli/Cargo.toml:90` — confirms `Win32_System_Pipes` feature already enabled

### Secondary (MEDIUM confidence)

- Windows API semantics for `WaitNamedPipe`: Confirmed by multiple existing call sites in codebase. `ERROR_FILE_NOT_FOUND` = not-yet-ready; `TRUE` = available. Consistent with Windows SDK documentation.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — `windows-sys` and `Win32_System_Pipes` already enabled; `WaitNamedPipeW` already used in 3 places in the codebase
- Architecture: HIGH — single-function change, existing platform guard pattern already used in the same function
- Pitfalls: HIGH — all pitfalls derived from direct code reading and existing codebase patterns

**Research date:** 2026-04-05
**Valid until:** 2026-05-05 (stable Windows API, no expiry risk)
