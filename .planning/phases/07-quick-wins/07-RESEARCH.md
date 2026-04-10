# Phase 7: Quick Wins - Research

**Researched:** 2026-04-07
**Domain:** Windows CLI surface — `nono wrap` Direct strategy, session log commands
**Confidence:** HIGH

## Summary

Phase 7 closes four Windows CLI gaps: enabling `nono wrap` to run the Direct execution strategy on Windows with Job Object + WFP enforcement, and verifying that `nono logs`, `nono inspect`, and `nono prune` work without Unix-specific dependencies. Research confirms the session commands (`run_logs`, `run_inspect`, `run_prune`) are already implemented in `session_commands_windows.rs` and use only cross-platform I/O, but they likely have a compile-time or runtime guard blocking execution on Windows that must be identified and removed. The primary bug for `nono wrap` is a `unreachable!()` macro at `execution_runtime.rs:282` that panics when `execute_direct` returns `Ok(i32)` on Windows, plus a stale help string in `setup.rs` that says wrap "remains intentionally unavailable."

**Primary recommendation:** Fix the Direct-strategy return path in `execution_runtime.rs` so Windows calls `std::process::exit(exit_code)` after `execute_direct` returns, remove the stale "unavailable" message from `setup.rs`, and confirm the session commands compile cleanly on Windows with no runtime guards.

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| WRAP-01 | User can run `nono wrap <cmd>` on Windows using Direct strategy with Job Object + WFP enforcement; help text documents supervisor stays alive as Job Object owner (no exec-replace, unlike Unix). | The code path exists; `execute_direct` handles Job Object + WFP already. The only blockers are a `unreachable!()` panic bug and a stale "unavailable" note in `setup.rs`. The help text for Windows wrap already exists and is correct. |
| SESS-01 | User can view logs for a Windows session using `nono logs <session>`. | `run_logs` is implemented in `session_commands_windows.rs`. Dispatched via `app_runtime.rs`. Need to verify no PTY dependency or Unix-only `cfg` guard prevents it from working on Windows. |
| SESS-02 | User can inspect a Windows session record in JSON format using `nono inspect <session>`. | `run_inspect` is implemented in `session_commands_windows.rs`. Same verification needed. |
| SESS-03 | User can prune stale Windows session records using `nono prune`. | `run_prune` is implemented in `session_commands_windows.rs` with a `reject_if_sandboxed` guard that checks `NONO_CAP_FILE` env var — this matches the Unix behavior. Same verification needed. |
</phase_requirements>

## Standard Stack

Phase 7 adds no new dependencies. All changes are within existing code.

### Core
| Component | Location | Purpose |
|-----------|----------|---------|
| `exec_strategy_windows/mod.rs::execute_direct` | `crates/nono-cli/src/` | Spawns child in Job Object, polls exit, returns `Result<i32>` |
| `execution_runtime.rs::execute_sandboxed` | `crates/nono-cli/src/` | Routes between Direct and Supervised strategies |
| `session_commands_windows.rs` | `crates/nono-cli/src/` | Implements `run_logs`, `run_inspect`, `run_prune` |
| `session.rs` | `crates/nono-cli/src/` | Cross-platform session file I/O; uses `#[cfg(unix)]` for permission checks only |
| `sandbox/windows.rs::validate_preview_entry_point` | `crates/nono/src/` | Entry-point guard that allows Wrap when caps are advisory-only |
| `setup.rs` | `crates/nono-cli/src/` | Contains stale string saying wrap is "unavailable" — must be updated |

## Architecture Patterns

### How `nono wrap` Flows on Windows (Current State)

```
nono wrap --allow . -- cmd /c echo hi
  → run_wrap() [command_runtime.rs]
      → prepare_sandbox()
      → Sandbox::validate_windows_preview_entry_point(Wrap, caps, dir, ctx)
          → preview_runtime_status()  [returns AdvisoryOnly for basic caps]
          → Ok(())  [no error, execution continues]
      → execute_sandboxed(LaunchPlan { strategy: Direct, ... })
          → exec_strategy::execute_direct(&config, Some(session_id))?
              → returns Ok(exit_code)   ← Windows returns, Unix never returns
          → unreachable!("execute_direct only returns on error")  ← PANIC HERE
```

On Unix, `execute_direct` calls `execvp()` which replaces the process — it never returns on success. On Windows, `execute_direct` polls a Job Object child and returns `Ok(i32)`. The `unreachable!()` at `execution_runtime.rs:282` is inside an unconditional block, so it panics immediately after `execute_direct` succeeds.

### The Fix Pattern

```rust
// execution_runtime.rs — Direct strategy arm:
exec_strategy::ExecStrategy::Direct => {
    #[cfg(target_os = "windows")]
    {
        let exit_code = exec_strategy::execute_direct(
            &config,
            Some(flags.session.session_id.as_str()),
        )?;
        cleanup_capability_state_file(&cap_file_path);
        std::process::exit(exit_code);
    }
    #[cfg(not(target_os = "windows"))]
    {
        exec_strategy::execute_direct(&config)?;
    }
    unreachable!("execute_direct only returns on error");
}
```

The `unreachable!()` remains valid for non-Windows because Unix `execute_direct` calls `execvp()` and only returns on error (the `?` propagates it).

### Session Commands — Architecture is Already Correct

`session_commands_windows.rs` implements:
- `run_logs` — reads `.events.ndjson` via `session_events_path()`, cross-platform I/O only
- `run_inspect` — reads session JSON via `session::load_session()`, cross-platform
- `run_prune` — removes `.json` and `.events.ndjson` files, cross-platform; calls `reject_if_sandboxed("prune")` which checks `NONO_CAP_FILE` env var — matches Unix behavior exactly

`session.rs` uses `#[cfg(unix)]` only for permission enforcement (mode bits, UID checks). The file I/O itself is cross-platform. The `sessions_dir()` function uses `dirs::home_dir().join(".nono").join("sessions")` which resolves to `%USERPROFILE%\.nono\sessions` on Windows.

`app_runtime.rs` dispatches all three commands unconditionally (no `cfg` gate):
```rust
Commands::Logs(args) => { session_commands::run_logs(&args) }
Commands::Inspect(args) => { session_commands::run_inspect(&args) }
Commands::Prune(args) => { session_commands::run_prune(&args) }
```

### Help Text — Already Correct for `wrap`

`cli.rs` already has a Windows-specific `WRAP_AFTER_HELP` constant (lines 40–49):
```
WINDOWS BEHAVIOR
  On Windows, `nono wrap` uses Job Object + WFP enforcement.
  The supervisor process stays alive as the Job Object owner and does NOT
  exec-replace the CLI process, unlike on Unix where nono disappears after exec.
  Proxy filtering is not supported with wrap.
```

This satisfies WRAP-01's help text requirement. No change needed here.

### Stale String in `setup.rs`

`setup.rs:834` prints:
```
Live 'nono shell' and 'nono wrap' remain intentionally unavailable on Windows; use their --dry-run forms to inspect policy.
```

This must be updated when Phase 7 ships. The `nono shell` part stays (Phase 8), so the string should be split: wrap is now available, shell is still pending until Phase 8.

### `preview_runtime_status` — Wrap Entry Point Already Works

`validate_preview_entry_point(Wrap, ...)` calls `preview_runtime_status()`. For the common case (allow-listed directory caps, no proxy, no extensions), it returns `AdvisoryOnly` — meaning `Ok(())` is returned and `run_wrap` continues. The entry-point guard is already correct and is tested in `validate_preview_entry_point_allows_wrap_with_empty_caps`.

### `session_id` in Direct Strategy

`run_wrap` builds a `LaunchPlan` via `ExecutionFlags::defaults()`. The `defaults()` method initializes `session.session_id` as an empty string via `SessionLaunchOptions::default()`. The call to `execute_direct(&config, Some(flags.session.session_id.as_str()))` would pass an empty string as session ID. This is used to create a named Job Object (`Local\nono-session-{}`). An empty session ID may produce a malformed Job Object name. The planner must decide whether to generate a session ID for wrap or pass `None`.

Looking at `execute_direct` signature: `pub fn execute_direct(config: &ExecConfig<'_>, session_id: Option<&str>) -> Result<i32>` — `None` is valid. The Job Object name logic should be checked.

Looking at `create_process_containment` in `launch.rs`:

```rust
pub(super) fn create_process_containment(session_id: Option<&str>) -> Result<ProcessContainment>
```

If `session_id` is `None`, the Job Object is likely created without a name (anonymous). This is acceptable for `nono wrap` since wrap does not need a persistent/named Job Object (no detach, no `nono ps` integration). The planner should pass `None` or generate a fresh random session ID for wrap.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Job Object cleanup on exit | Custom cleanup logic | `ProcessContainment` RAII drop (existing pattern) | Already handles this via `OwnedHandle` drop |
| Cross-platform file I/O | Platform-specific wrappers | `std::fs` + existing `session.rs` | Session module already abstracts this |
| Session ID generation | Custom ID logic | `session::generate_session_id()` | Already exists and is tested |

## Common Pitfalls

### Pitfall 1: `unreachable!()` Placement
**What goes wrong:** The `unreachable!()` macro at `execution_runtime.rs:282` is after both `#[cfg(target_os = "windows")]` and `#[cfg(not(target_os = "windows"))]` blocks. It compiles on all platforms but panics at runtime on Windows when `execute_direct` returns successfully.
**Why it happens:** On Unix, `execute_direct` calls `execvp()` (process replacement) — it only returns on `Err`. The `unreachable!()` is valid for Unix. On Windows, `execute_direct` polls a Job Object and returns `Ok(i32)`.
**How to avoid:** The Windows-specific block must call `std::process::exit(exit_code)` before falling through to `unreachable!()`.
**Warning signs:** Any test or CI run that invokes `nono wrap` on Windows will panic with "internal error: entered unreachable code".

### Pitfall 2: Empty Session ID for Job Object Name
**What goes wrong:** `LaunchPlan` from `run_wrap` uses `ExecutionFlags::defaults()`, which sets `session.session_id = String::new()` (default). Passing `Some("")` as session ID may produce a Job Object name of `Local\nono-session-`.
**Why it happens:** `run_wrap` does not set a session ID because wrap is Direct strategy and historically has no session tracking on non-Windows platforms.
**How to avoid:** Pass `None` as session_id in the Direct strategy path for wrap, or generate a fresh session ID using `session::generate_session_id()` before the call. Check `create_process_containment`'s handling of `None`.
**Warning signs:** Job Object creation fails or succeeds with an unexpected name.

### Pitfall 3: `setup.rs` Help Text Out of Sync
**What goes wrong:** After enabling wrap on Windows, `nono setup --check-only` still prints "Live 'nono shell' and 'nono wrap' remain intentionally unavailable on Windows."
**Why it happens:** The string was accurate before Phase 7 and was not updated.
**How to avoid:** Update the string to split wrap (now available) from shell (still Phase 8).
**Warning signs:** User confusion after Phase 7 ships.

### Pitfall 4: Session Commands Compile on Windows but Have Silent Gaps
**What goes wrong:** The session commands in `session_commands_windows.rs` may compile but fail at runtime if `session_events_path()` or `session_log_path()` invoke `ensure_sessions_dir()`, which on Windows uses `dirs::home_dir()` — if HOME is not set on some Windows configurations, this fails.
**Why it happens:** `dirs::home_dir()` on Windows reads `USERPROFILE` or `FOLDERID_Profile`. On most Windows 10/11 installs this is set, but it should be verified.
**How to avoid:** The existing error handling in `sessions_dir()` returns `NonoError::ConfigParse` if home dir is unavailable — this is a proper error, not a silent failure. No special handling needed.

### Pitfall 5: `reject_if_sandboxed` Guard Parity
**What goes wrong:** `run_prune` already has `reject_if_sandboxed("prune")?` at the top. This checks `NONO_CAP_FILE` env var. The requirement says this should match the Unix reject-if-sandboxed guard. Verification: `NONO_CAP_FILE` is set by `execution_runtime.rs::write_capability_state_file()` on all platforms and passed as the env file path. If this env var is present, the process is sandboxed.
**Status:** Already correct — no change needed.

## Code Examples

### Pattern: Direct Strategy Windows Return Value
```rust
// execution_runtime.rs — corrected Direct arm
exec_strategy::ExecStrategy::Direct => {
    #[cfg(target_os = "windows")]
    {
        let exit_code = exec_strategy::execute_direct(
            &config,
            Some(flags.session.session_id.as_str()),
        )?;
        cleanup_capability_state_file(&cap_file_path);
        std::process::exit(exit_code);
    }
    #[cfg(not(target_os = "windows"))]
    {
        exec_strategy::execute_direct(&config)?;
    }
    #[allow(unreachable_code)]
    {
        unreachable!("execute_direct only returns on error on non-Windows");
    }
}
```

Note: The `unreachable!()` after the `#[cfg(not(target_os = "windows"))]` block is genuinely unreachable on Windows because `std::process::exit` diverges. On Unix, it remains unreachable because `execute_direct` does not return on success. The `#[allow(unreachable_code)]` annotation may be needed if the compiler warns about it.

### Pattern: Session ID for Wrap Direct Strategy
```rust
// Two options — planner should choose one:

// Option A: Anonymous Job Object (pass None)
exec_strategy::execute_direct(&config, None)?;

// Option B: Random session ID (named Job Object, no session tracking)
let wrap_session_id = session::generate_session_id();
exec_strategy::execute_direct(&config, Some(wrap_session_id.as_str()))?;
```

Option A (anonymous) is simpler and correct for `nono wrap` since the process exits synchronously and no persistent session record is created by `run_wrap`.

### Pattern: Updated `setup.rs` Help String
```rust
// Before (stale):
println!("Live 'nono shell' and 'nono wrap' remain intentionally unavailable on Windows; use their --dry-run forms to inspect policy.");

// After (Phase 7 ships):
println!("'nono wrap' is available on Windows with Job Object + WFP enforcement (supervisor stays alive as Job Object owner).");
println!("'nono shell' (ConPTY) is not yet available on Windows; use --dry-run to inspect policy.");
```

## State of the Art

| Old State | Phase 7 State | Notes |
|-----------|--------------|-------|
| `nono wrap` panics on Windows (unreachable!) | Returns correct exit code | One-line fix in `execution_runtime.rs` |
| `setup.rs` says wrap unavailable | Updated to reflect availability | Cosmetic change |
| Session commands compiled but untested on Windows | Verified working | `session_commands_windows.rs` already implemented |

## Open Questions

1. **Session ID for Direct/Wrap on Windows**
   - What we know: `run_wrap` uses `ExecutionFlags::defaults()` which gives `session_id = ""`. Passing `Some("")` to `execute_direct` may produce a malformed Job Object name.
   - What's unclear: Whether `create_process_containment(Some(""))` produces an error or a valid anonymous-ish Job Object. Need to read `launch.rs::create_process_containment`.
   - Recommendation: Planner should read `launch.rs::create_process_containment` and decide between Option A (None) or Option B (generate_session_id). Safest: pass `None` for wrap since no session record is written.

2. **Compile-time correctness of session commands on Windows**
   - What we know: `session_commands_windows.rs` implements `run_logs`, `run_inspect`, `run_prune`. Dispatch is in `app_runtime.rs` without any `cfg` gate.
   - What's unclear: Whether the codebase currently compiles and the commands run without error on a real Windows 10/11 machine. The git status shows `session_commands_windows.rs` has unstaged changes — planner should inspect those diffs.
   - Recommendation: The planner should check what changed in `session_commands_windows.rs` per the git status and ensure the changes do not break the three session commands.

## Environment Availability

Step 2.6: SKIPPED (no external dependencies — all changes are within existing Rust source; no new CLI tools, databases, or external services required).

## Sources

### Primary (HIGH confidence)
- Direct code inspection of `crates/nono-cli/src/execution_runtime.rs` — confirms `unreachable!()` bug
- Direct code inspection of `crates/nono-cli/src/command_runtime.rs` — confirms `run_wrap` flow
- Direct code inspection of `crates/nono-cli/src/session_commands_windows.rs` — confirms all three session commands are implemented
- Direct code inspection of `crates/nono/src/sandbox/windows.rs` — confirms `Wrap` entry point passes with advisory caps
- Direct code inspection of `crates/nono-cli/src/setup.rs:834` — confirms stale "unavailable" string
- Direct code inspection of `crates/nono-cli/src/cli.rs` — confirms Windows `WRAP_AFTER_HELP` already documents correct behavior
- Direct code inspection of `crates/nono-cli/src/session.rs` — confirms `sessions_dir()` uses `dirs::home_dir()` (cross-platform)

## Metadata

**Confidence breakdown:**
- `nono wrap` fix (unreachable! bug): HIGH — root cause is visible in source; fix pattern is clear
- Session commands: HIGH — implementations exist in `session_commands_windows.rs`; only compile verification needed
- Help text: HIGH — stale string is visible; correct fix is clear

**Research date:** 2026-04-07
**Valid until:** Until Phase 7 code lands (stable analysis, no external API changes involved)
