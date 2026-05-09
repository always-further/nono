---
phase: 31-broker-process-architecture-shell-01
reviewed: 2026-05-09T00:00:00Z
depth: standard
files_reviewed: 12
files_reviewed_list:
  - crates/nono/src/sandbox/windows.rs
  - crates/nono/src/lib.rs
  - crates/nono/src/error.rs
  - crates/nono-cli/src/exec_strategy_windows/launch.rs
  - crates/nono-cli/src/exec_strategy_windows/mod.rs
  - crates/nono-shell-broker/Cargo.toml
  - crates/nono-shell-broker/src/main.rs
  - bindings/c/src/lib.rs
  - Cargo.toml
  - .github/workflows/release.yml
  - scripts/build-windows-msi.ps1
  - scripts/test-windows-shell-write-deny.ps1
findings:
  critical: 4
  warning: 14
  info: 6
  total: 24
status: issues_found
---

# Phase 31: Code Review Report

**Reviewed:** 2026-05-09
**Depth:** standard
**Files Reviewed:** 12
**Status:** issues_found

## Summary

Phase 31 ships a Windows broker-process architecture: `nono.exe` spawns `nono-shell-broker.exe` (Medium-IL, caller's identity) which lowers its own duplicated token to Low-IL and spawns the actual sandboxed PowerShell child via `CreateProcessAsUserW(EXTENDED_STARTUPINFO_PRESENT)` with `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`. The implementation is broadly faithful to the validated 2026-05-08 PoC, the lifted `nono::create_low_integrity_primary_token` is well-encapsulated, and `// SAFETY:` discipline is largely maintained across the 16 unsafe blocks in the broker plus the broker-dispatch path in `launch.rs`.

However, this review found **four BLOCKER-class defects** that materially affect the security envelope or correctness of the shipping artifact:

1. The **FFI `BrokerNotFound` mapping** is semantically wrong (`ErrPathNotFound` instead of `ErrSandboxInit`), and will mislead C-API consumers into reporting "user supplied bad path" when the install is structurally broken.
2. The **broker accepts `--inherit-handle 0x0` (null HANDLE)** without validation, allowing a malformed argv to plant a null entry into `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` — Win32 behavior with null-in-handle-list is undefined; the kernel may treat it as INVALID_HANDLE_VALUE / current-process pseudo-handle (`-1` ≡ pseudo-handle for current process).
3. The **empty `--inherit-handle` list path** (key-decision in plan 31-02) is structurally broken: `UpdateProcThreadAttribute(HANDLE_LIST, cbSize=0)` is documented to fail with `ERROR_BAD_LENGTH`. The plan's claim of "most-restrictive shape" is wishful; this path will not work at runtime.
4. The **`broker_launch_assigns_child_to_job_object` test does NOT have `#[ignore]`** despite the Plan 31-03 SUMMARY explicitly claiming it does and deferring its "lift" to Plan 31-05. This is a documentation-vs-code mismatch; the test currently runs in `cargo test -p nono-cli` on Windows and silently skips when the broker artifact is missing — meaning Plan 31-05's "lift the ignore" task is a no-op.

Additional WARNINGs cover defense-in-depth gaps (broker arm fall-through if pty=None, broker_path not canonicalized, error misclassification, no validation that handles in `--inherit-handle` are actually inheritable in the broker), one PowerShell harness robustness issue, and one potential Win32 quoting bug in the broker's command-line builder for shell-args containing backslash sequences.

The CLAUDE.md `// SAFETY:` discipline IS observed (every unsafe block has an annotation). No `.unwrap()` / `.expect()` exists in non-test broker code. The signing pipeline correctly extends signing + verification to `nono-shell-broker.exe` with the same key (D-05 carry).

## Critical Issues

### CR-01: FFI mapping `BrokerNotFound -> ErrPathNotFound` is semantically wrong

**File:** `bindings/c/src/lib.rs:128-134`
**Issue:** The `map_error` arm maps `nono::NonoError::BrokerNotFound { .. } => NonoErrorCode::ErrPathNotFound`. The inline comment justifies this as "structurally a path-resolution failure." This is wrong from a C-API consumer's perspective. `ErrPathNotFound` is the code for *user-supplied* paths that don't exist on disk (canonical use: `--allow-path /nonexistent`). `BrokerNotFound` is a runtime-environment / install defect — the user did NOT supply this path; nono's runtime did. A C consumer seeing `ErrPathNotFound` will diagnose "the user gave me a bad path" and try to ask the user for a different path. The correct mapping is `ErrSandboxInit` (the broker's absence prevents sandbox initialization on Windows). The variant docstring (`crates/nono/src/error.rs:45-52`) makes the install-defect framing explicit ("not found as sibling of the running `nono.exe`") — the FFI should preserve that semantic.
**Fix:**
```rust
// Phase 31 D-07: BrokerNotFound is a Windows install / runtime-environment
// defect (the broker.exe sibling that nono.exe expected to exist next to
// itself is missing). Map to ErrSandboxInit because sandbox initialization
// cannot proceed; the user did NOT supply this path so ErrPathNotFound would
// mislead C-API consumers into a user-input-validation failure mode.
nono::NonoError::BrokerNotFound { .. } => NonoErrorCode::ErrSandboxInit,
```

### CR-02: Broker accepts `--inherit-handle 0x0` (null HANDLE) without validation

**File:** `crates/nono-shell-broker/src/main.rs:87-99`
**Issue:** The `--inherit-handle` parser strips `0x` prefix and calls `usize::from_str_radix(stripped, 16)` then casts the result to `HANDLE` (a raw pointer). There is NO validation that the parsed value is non-null or non-`INVALID_HANDLE_VALUE` (`0xFFFFFFFFFFFFFFFF`). The resulting `inherit_handles: Vec<HANDLE>` is then passed verbatim to `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`. If an attacker (or a future bug in nono.exe's argv emitter, or a stray test invocation) passes `--inherit-handle 0x0`, a null HANDLE enters the inheritance list. Per Win32 semantics, `0` is sometimes treated as a null handle (CloseHandle no-op), but Microsoft has historically reserved null/`-1`/`-2` as pseudo-handle values. Kernel behavior on null-in-HANDLE_LIST is undocumented and version-dependent. Worst case: pseudo-handle `-1` is "current process" — inheriting it would let the child duplicate any handle in the broker's handle table.
**Fix:**
```rust
let raw_value = usize::from_str_radix(stripped, 16).map_err(|e| {
    NonoError::SandboxInit(format!(
        "--inherit-handle parse error for '{hex_str}': {e}"
    ))
})?;
// Reject null HANDLE (0) and INVALID_HANDLE_VALUE (-1 / usize::MAX) up-front;
// these have special-case Win32 semantics (pseudo-handles) and must never
// appear in PROC_THREAD_ATTRIBUTE_HANDLE_LIST.
if raw_value == 0 || raw_value == usize::MAX {
    return Err(NonoError::SandboxInit(format!(
        "--inherit-handle rejected sentinel value {hex_str}: must be a real \
         inheritable HANDLE in the broker's handle table"
    )));
}
inherit_handles.push(raw_value as HANDLE);
```

### CR-03: Empty `--inherit-handle` list path likely fails at runtime

**File:** `crates/nono-shell-broker/src/main.rs:200-226` (and Plan 31-02 SUMMARY key-decision claim)
**Issue:** The Plan 31-02 SUMMARY states "Empty inherit-handle list permitted at parse time. ... HANDLE_LIST is initialized with a zero-sized handle array — most-restrictive: no handles inherit." The code computes `let handles_byte_size = std::mem::size_of_val(handles_array.as_slice());` which yields `0` for an empty slice, then calls `UpdateProcThreadAttribute(... PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles_array.as_ptr() as *mut _, 0, ...)`. Per MSDN `UpdateProcThreadAttribute` documentation, `cbSize` for `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` "must be the size of the array of inheritable handles". A zero-byte array fails with `ERROR_BAD_LENGTH` on real Windows — `bInheritHandles=1` requires at least one valid handle to satisfy the contract. The "most-restrictive empty list" pattern is a documentation myth; you cannot use HANDLE_LIST to mean "no handles." The correct way to inherit zero handles is to set `bInheritHandles=0` and skip the attribute entirely. The current path, if exercised by a test harness or a future direct-spawn invocation that emits zero `--inherit-handle` flags, will surface a confusing `UpdateProcThreadAttribute(HANDLE_LIST) failed` error.
**Fix:** Either (a) require at least one `--inherit-handle` at parse time (fail-fast `NonoError::SandboxInit("--inherit-handle requires at least one value")`), or (b) when the list is empty, skip the `UpdateProcThreadAttribute(HANDLE_LIST)` call entirely AND set `bInheritHandles=0` on the subsequent `CreateProcessAsUserW`. Option (a) is simpler and matches the production callsite (which always passes 2 handles).

### CR-04: `broker_launch_assigns_child_to_job_object` test is NOT `#[ignore]`'d as Plan 31-03 SUMMARY claims

**File:** `crates/nono-cli/src/exec_strategy_windows/launch.rs:2246-2247`
**Issue:** The Plan 31-03 SUMMARY repeatedly states this test is `#[ignore]`'d, with the lift deferred to Plan 31-05 ("the `#[ignore]`'d `broker_launch_assigns_child_to_job_object` test embeds the `IsProcessInJob` import and references the lift plan", "broker_dispatch_tests: 1 passed + 1 ignored"). The actual code at line 2246 has only `#[test]` — no `#[ignore]`. The test runs in any `cargo test -p nono-cli` invocation on Windows, where it conditionally `eprintln!("SKIP: ...")` and early-returns if the broker artifact is missing. Three concrete consequences: (1) Plan 31-05's "lift the ignore" task is a no-op — the test is already live; (2) on a CI box without the broker artifact, the test silently SKIPs (printed but exit 0), which is a false-PASS class — the test reports green when it didn't actually verify anything; (3) on a CI box WITH the broker artifact but where the broker fails to spawn (e.g., the runner can't construct a Low-IL token), `panic!("CreateProcessW(broker) failed; ...")` will fire and cause real test failures that look like Phase 31 broke `nono-cli` test suite. This is documentation-vs-code drift that hides a test that should either be ignored or made fully self-contained.
**Fix:** Either (a) add `#[ignore]` to match the SUMMARY's documented intent (Plan 31-05 then lifts it), OR (b) update the SUMMARY to reflect the test's actual always-on-with-skip-fallback shape. If option (a), also add a doc-comment to the SKIP eprintln explaining that "skip is treated as PASS only because Plan 31-05 owns the runtime acceptance — do not rely on this for CI signal."
```rust
#[test]
#[ignore = "Plan 31-05 lifts: requires production broker artifact built via \
            cargo build -p nono-shell-broker --release --target x86_64-pc-windows-msvc"]
fn broker_launch_assigns_child_to_job_object() {
    // ... existing body ...
}
```

## Warnings

### WR-01: `BrokerLaunch` arm has no defense-in-depth gate against pty=None

**File:** `crates/nono-cli/src/exec_strategy_windows/launch.rs:1198-1210` and `1245-1438`
**Issue:** `select_windows_token_arm` returns `BrokerLaunch` only when `has_pty=true`, but the dispatch at `spawn_windows_child` is a two-step decision: the match arm at lines 1198-1210 sets `h_token = null` regardless, then the `if let Some(pty_pair) = pty { if matches!(arm, BrokerLaunch) {...} }` block at line 1245 dispatches to the broker. If a future refactor (or test misconfiguration) reaches `arm = BrokerLaunch` with `pty = None`, control falls through to the non-PTY `else` branch at line 1547, which calls `CreateProcessW(application_name=launch_program, ...)` with `h_token=null` — i.e., spawns the SHELL DIRECTLY at Medium IL with no broker, no Low-IL token, no sandbox. The cascade structure depends on the invariant `BrokerLaunch ↔ pty.is_some()` but does not enforce it.
**Fix:** Add a fail-secure assertion at the top of `spawn_windows_child` after `arm` is computed:
```rust
if matches!(arm, WindowsTokenArm::BrokerLaunch) && pty.is_none() {
    return Err(NonoError::SandboxInit(
        "internal: BrokerLaunch requires PTY; cascade invariant violated".into(),
    ));
}
```

### WR-02: `broker_path` is not canonicalized before `CreateProcessW`

**File:** `crates/nono-cli/src/exec_strategy_windows/launch.rs:1251-1264`
**Issue:** The broker path is built as `current_exe.parent().join("nono-shell-broker.exe")`, then `.exists()` is checked, then the raw path is passed to `CreateProcessW` as the executable. Per CLAUDE.md § Path Handling: "Validate and canonicalize all paths before applying capabilities." If the install dir contains a junction or symlink (e.g., `D:\nono-link` symlinks to `C:\Program Files\nono`), `current_exe()` may return the link path; downstream `CreateProcessW` follows the link at execution time — TOCTOU window between `.exists()` check and `CreateProcessW`. While T-31-16 was accepted, canonicalization (`std::fs::canonicalize`) costs nothing and closes the symlink-swap class.
**Fix:**
```rust
let broker_path = exe_dir.join("nono-shell-broker.exe");
let broker_path = std::fs::canonicalize(&broker_path).map_err(|_| {
    NonoError::BrokerNotFound { path: broker_path }
})?;
```

### WR-03: `broker_path.exists()` swallows IO errors → misclassified as `BrokerNotFound`

**File:** `crates/nono-cli/src/exec_strategy_windows/launch.rs:1263-1265`
**Issue:** `Path::exists()` returns `false` for both "file does not exist" AND "I/O error reading parent dir" (e.g., permission denied, network share offline). Both surface as `BrokerNotFound` — the operator sees "broker missing" when in fact they have a permissions problem. Per CLAUDE.md § Fail Secure: "Never silently degrade to a less secure state" — here we silently degrade to a less *informative* state.
**Fix:** Use `try_exists()` and propagate IO errors distinctly:
```rust
match broker_path.try_exists() {
    Ok(true) => { /* proceed */ }
    Ok(false) => return Err(NonoError::BrokerNotFound { path: broker_path }),
    Err(e) => return Err(NonoError::SandboxInit(format!(
        "Failed to probe broker path {}: {e}", broker_path.display()
    ))),
}
```

### WR-04: Broker `attr_size` from probe call is not validated > 0

**File:** `crates/nono-shell-broker/src/main.rs:173-179`
**Issue:** The probe call `InitializeProcThreadAttributeList(null, 1, 0, &mut attr_size)` is documented to fail and write the required size to `attr_size`. The code does NOT check the return value (correct — failure is expected) AND does NOT validate `attr_size > 0` before the subsequent `vec![0u8; attr_size]`. If for any reason the kernel does not write the size (kernel bug, memory corruption), `attr_size` remains `0`, the buffer is zero-sized but `as_mut_ptr()` returns a non-null dangling pointer (per Vec layout guarantees), and the second `Initialize...` call operates on a zero-sized buffer that may corrupt adjacent stack/heap memory.
**Fix:**
```rust
let mut attr_size: usize = 0;
unsafe {
    InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut attr_size);
}
if attr_size == 0 {
    return Err(NonoError::SandboxInit(
        "InitializeProcThreadAttributeList probe did not return required size".into(),
    ));
}
let mut attr_buf = vec![0u8; attr_size];
```
Identical fix needed at `crates/nono-cli/src/exec_strategy_windows/launch.rs:1308-1314`.

### WR-05: `AllocConsole` failure is logged but not validated against D-01 contract

**File:** `crates/nono-shell-broker/src/main.rs:160-164`
**Issue:** `AllocConsole` is called unconditionally and the rc is logged as "console attach probe". The comment says "rc=0 means console inherited (expected when spawned by nono.exe); rc != 0 means new console (when broker invoked standalone for testing)." This conflates two failure modes: (a) AllocConsole returns 0 because broker is already attached to nono.exe's inherited console (D-01 invariant — GOOD), or (b) AllocConsole returns 0 for any other reason (resource exhaustion, sandbox-already-restricting, etc.). More importantly, `rc != 0` ("new console allocated") DEFEATS D-01: it means the broker just opened a separate console and the Low-IL child will inherit THAT console, re-triggering the CSRSS attach race that Phase 31 is designed to avoid. If nono.exe is launched from a non-console context (Windows service, SSH redirected, scheduled task), `AllocConsole` may succeed (rc != 0) and silently violate D-01.
**Fix:** After AllocConsole, validate the broker's actual console state via `GetConsoleWindow()` or `GetStdHandle(STD_INPUT_HANDLE)`. If a NEW console was allocated (not inherited), fail-secure with `NonoError::SandboxInit("broker spawned without inherited console; D-01 invariant violated")`. At minimum, make the SUMMARY claim "rc=0 means console inherited" rigorous by checking the prior-attached state.

### WR-06: Misleading error message in broker spawn failure

**File:** `crates/nono-cli/src/exec_strategy_windows/launch.rs:1621-1626`
**Issue:** When `CreateProcessW(broker, ...)` fails in the BrokerLaunch arm, the resulting error message is `"Failed to launch Windows child process (error={})"`. This message is reused from the legacy non-broker spawn path; in the BrokerLaunch arm, the failed process is the BROKER, not the child. Operator diagnostics that grep for "Failed to launch" will misattribute the failure.
**Fix:** Branch the error message on the arm:
```rust
if created == 0 {
    let last = unsafe { GetLastError() };
    let target = if matches!(arm, WindowsTokenArm::BrokerLaunch) {
        "nono-shell-broker.exe"
    } else {
        "Windows child process"
    };
    return Err(NonoError::SandboxInit(format!(
        "Failed to launch {target} (error={last})"
    )));
}
```

### WR-07: Broker quote doubling breaks for shell-args with backslash sequences

**File:** `crates/nono-shell-broker/src/main.rs:129-146`
**Issue:** `build_command_line` quotes args containing space or `"` by wrapping in `"..."` and replacing embedded `"` with `""`. This handles the PowerShell convention but does NOT handle backslashes. Per Win32 `CommandLineToArgvW` rules, `\\"` parses as `\"` (literal escaped quote), `\\\\` parses as `\\\\`, etc. The broker's quoting function emits raw backslashes inside the quoted region. For typical shell args containing Windows paths (e.g., `--shell-arg "C:\path with space\file.txt"`), the path has both backslash and space — the current code emits `"C:\path with space\file.txt"` which CommandLineToArgvW correctly parses as one arg. BUT for an arg ending in a backslash followed by a quote (`C:\path\"`), the doubling produces `"C:\path\"""` which CommandLineToArgvW parses as `C:\path"` followed by... ambiguous. The `nono-cli` side uses `quote_windows_arg` which DOES handle backslash-quote interactions correctly (lines 955-980 in launch.rs). The broker's helper diverges.
**Fix:** Lift `quote_windows_arg` from `nono-cli` to a shared helper in `nono` (or reimplement it identically in the broker), and replace the broker's `build_command_line` quoting block.

### WR-08: Broker passes inherited handles to HANDLE_LIST without verifying inheritability

**File:** `crates/nono-shell-broker/src/main.rs:200-213`
**Issue:** The handles received via `--inherit-handle` are passed verbatim to `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`. Win32 requires that handles in this list are already marked `HANDLE_FLAG_INHERIT` in the broker's handle table. While nono.exe DOES set this flag before spawning the broker (and the kernel duplicates the inheritable state into the broker), the broker has no defense-in-depth check that the handles it was told to pass on are in fact inheritable. If a future direct-spawn caller invokes the broker with non-inheritable handles, `CreateProcessAsUserW` returns `ERROR_INVALID_PARAMETER` with no diagnostic value.
**Fix:** Add a `GetHandleInformation` probe loop before `UpdateProcThreadAttribute`:
```rust
for h in &handles_array {
    let mut flags: u32 = 0;
    let probed = unsafe { GetHandleInformation(*h, &mut flags) };
    if probed == 0 || (flags & HANDLE_FLAG_INHERIT) == 0 {
        return Err(NonoError::SandboxInit(format!(
            "--inherit-handle 0x{:x} is not marked HANDLE_FLAG_INHERIT in broker's handle table", *h as usize
        )));
    }
}
```

### WR-09: `OwnedHandle.0` is `pub` — invites external double-close

**File:** `crates/nono/src/sandbox/windows.rs:489`
**Issue:** `pub struct OwnedHandle(pub HANDLE)` — the inner HANDLE is publicly accessible. The Plan 31-01 SUMMARY justifies this as "5+ callsites in nono-cli access it directly via `.0` field reads." But exposing the HANDLE invites consumers to manually `CloseHandle(owned.0)` then drop owned, causing a double-close. The wrapper's whole point is to centralize the close. The pre-lift use was internal to `nono-cli`; lifting the type to `nono` (a public library) made the pub field a wider attack surface for downstream consumers. There are no compile-time tests preventing the double-close anti-pattern.
**Fix:** Keep `pub struct OwnedHandle(HANDLE)` (private field) and add a `pub fn into_raw(self) -> HANDLE` for ownership transfer + a `pub fn raw(&self) -> HANDLE` (already present) for borrow access. Update the 5+ nono-cli callsites to use `.raw()`. This is a one-time migration cost vs. an open-ended FFI-misuse risk.

### WR-10: `test-windows-shell-write-deny.ps1` lacks `Set-StrictMode -Version Latest`

**File:** `scripts/test-windows-shell-write-deny.ps1:51-53`
**Issue:** Sibling scripts `build-windows-msi.ps1` and `sign-windows-artifacts.ps1` both set `Set-StrictMode -Version Latest`, which catches typos and uninitialized variable accesses at parse/runtime. The harness script does NOT enable strict mode — a typo in `$shellExit` vs `$shellexit` (PowerShell is case-insensitive but doesn't catch undefined-variable use without strict mode) would silently use `$null` and cause false PASS / FAIL.
**Fix:**
```powershell
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'  # keep existing
```

### WR-11: Test harness path interpolation doesn't escape single quotes in USERPROFILE

**File:** `scripts/test-windows-shell-write-deny.ps1:144-151`
**Issue:** The injected one-shot script uses `Set-Content -Path '$targetFile'` where `$targetFile` is interpolated into a PowerShell here-string. Single-quote wrapping protects against most special characters BUT NOT single quotes themselves. If `$env:USERPROFILE` ever contains a `'` (legal in Windows usernames), the inner script becomes `Set-Content -Path 'C:\Users\some'name\Desktop\nono-acceptance3.txt' ...` — a parse error. The catch handler runs, file doesn't exist, `exit 42` fires — FALSE PASS, exactly the bug class Plan 31-01 just fixed.
**Fix:** Escape single quotes in `$targetFile` before interpolation:
```powershell
$escapedTargetFile = $targetFile.Replace("'", "''")
$injected = @"
try {
  Set-Content -Path '$escapedTargetFile' -Value 'phase 31 write-deny test' -ErrorAction Stop
} catch { ... }
if (Test-Path '$escapedTargetFile') { exit 1 } else { exit 42 }
"@
```

### WR-12: Broker logs child PID via `tracing::info!`

**File:** `crates/nono-shell-broker/src/main.rs:289-292`
**Issue:** `tracing::info!(child_pid = process_info.dwProcessId, "broker: spawned Low-IL child");` logs the spawned PID at INFO level. PIDs are not strictly secret but are operational metadata that, in shared CI logs or attestation traces, can leak process-identity info. Phase 23 audit-ledger emissions (D-10) are explicitly out of scope, but the broker's info-level log is operator-visible. Consider DEBUG.
**Fix:** Demote to `tracing::debug!` for child PID and exit code (lines 289 and 324).

### WR-13: `nono-shell-broker/Cargo.toml` hardcodes `nono = "0.37.1"` instead of workspace pinning

**File:** `crates/nono-shell-broker/Cargo.toml:19`
**Issue:** `nono = { version = "0.37.1", path = "../nono" }` hardcodes the version. The workspace doesn't expose `nono` in `[workspace.dependencies]`, so a workspace-level bump (e.g., to 0.38.0) requires editing this file separately. Forgetting to bump this file would silently keep the broker on the old version (until cargo's path-dep semantics override). Plan 31-02's auto-correlation between `nono` and `nono-shell-broker` versions has no enforcement.
**Fix:** Either expose `nono = { version = "0.37.1", path = "crates/nono" }` in workspace.dependencies and use `nono.workspace = true` here, OR drop the `version` field and rely solely on `path = "../nono"` (cargo will use the path-resolved version automatically; release builds are workspace-uniform).

### WR-14: Broker doesn't honor `NONO_LOG` env var for tracing

**File:** `crates/nono-shell-broker/src/main.rs:338-341`
**Issue:** The broker uses `tracing_subscriber::EnvFilter::try_from_default_env()` which reads `RUST_LOG`. CLAUDE.md / project conventions list `NONO_LOG` as the canonical env var (alongside `NONO_NO_UPDATE_CHECK`, etc.). Operators inspecting broker behavior will set `NONO_LOG` based on familiarity with nono-cli's flag and see no effect.
**Fix:** Read `NONO_LOG` first, then fall back to `RUST_LOG`:
```rust
let env_filter = std::env::var("NONO_LOG").ok()
    .and_then(|v| tracing_subscriber::EnvFilter::try_new(v).ok())
    .or_else(|| tracing_subscriber::EnvFilter::try_from_default_env().ok())
    .unwrap_or_else(|| tracing_subscriber::EnvFilter::new("info"));
```
(Note: the `unwrap_or_else` is fine here — it constructs a new `EnvFilter` synchronously and infallibly. The CLAUDE.md `clippy::unwrap_used` rule targets `Option::unwrap` and `Result::unwrap`, not `unwrap_or_else` with closure-pure-construction.)

## Info

### IN-01: Broker `BrokerArgs` struct fields are `pub` but only consumed within `mod broker`

**File:** `crates/nono-shell-broker/src/main.rs:53-59`
**Issue:** `pub struct BrokerArgs { pub shell_path: PathBuf, ... }` exposes fields publicly even though the struct is constructed by `parse_args` and consumed by `run` — both within the private `mod broker`. No external consumer accesses these fields.
**Fix:** Drop `pub` on fields and on the struct itself (or keep struct-level pub if a future `--smoke` self-test wants to construct it externally).

### IN-02: Broker has zero unit tests for argv parsing

**File:** `crates/nono-shell-broker/src/main.rs:64-123`
**Issue:** Plan 31-02 SUMMARY explicitly states "No unit tests were added in Plan 31-02 because the broker's logic is structural plumbing." Argv parsing is exactly the failure-prone code that benefits from unit tests: empty `--shell-arg ""`, repeated `--shell` (current code silently overwrites), missing flag at end-of-argv, malformed hex in `--inherit-handle`. The broker's correctness is hand-validated via the PoC; regression coverage is nil.
**Fix:** Add a `#[cfg(test)] mod tests` with at minimum: (a) round-trip parse of a well-formed argv, (b) reject `--unknown-flag`, (c) reject missing required `--shell` / `--cwd`, (d) reject malformed `--inherit-handle 0xZZZZ`, (e) accept multiple `--shell-arg` in order. ~50 LOC.

### IN-03: `OsStr` import in broker is necessary but `OsString` redundant after parse

**File:** `crates/nono-shell-broker/src/main.rs:36`
**Issue:** `use std::ffi::{OsStr, OsString};` — `OsString` is only used in the `parse_args` signature to receive `&[OsString]` from `main()`'s `args_os().collect()`. After parsing into `BrokerArgs`, only `OsStr` is used. Minor.
**Fix:** None needed; cosmetic.

### IN-04: Release workflow `Build broker (Windows)` could be merged into main `Build` step

**File:** `.github/workflows/release.yml:73-79`
**Issue:** Steps 73-75 (`Build`) and 77-79 (`Build broker (Windows)`) are separate cargo invocations. Two cold-cache compilations. Could be `cargo build --release --target ${{ matrix.target }} -p nono-cli -p nono-shell-broker` in one step (Windows-only). Cosmetic.
**Fix:**
```yaml
- name: Build (Windows — nono-cli + nono-shell-broker)
  if: runner.os == 'Windows'
  run: cargo build --release --target ${{ matrix.target }} -p nono-cli -p nono-shell-broker

- name: Build (non-Windows — nono-cli only)
  if: runner.os != 'Windows' && matrix.target != 'aarch64-unknown-linux-gnu'
  run: cargo build --release --target ${{ matrix.target }} -p nono-cli
```

### IN-05: Verify-zip-signatures loop iterates over hardcoded names; brittle to artifact rename

**File:** `.github/workflows/release.yml:239`
**Issue:** `foreach ($name in @("${{ matrix.artifact }}", "nono-shell-broker.exe"))` — hardcodes `nono-shell-broker.exe` while using `${{ matrix.artifact }}` for the main binary. If the broker binary is ever renamed (e.g., `nono-broker.exe`), this loop silently passes the verify even if the broker is missing.
**Fix:** Either parameterize via a matrix var or grep the zip contents:
```pwsh
$expected = @("${{ matrix.artifact }}", "nono-shell-broker.exe")
$found = Get-ChildItem -Path $extractRoot -File | ForEach-Object { $_.Name }
foreach ($name in $expected) {
    if ($name -notin $found) {
        Write-Error "Expected $name in zip; found: $($found -join ', ')"
        exit 1
    }
}
foreach ($name in $found) { ... verify ... }
```

### IN-06: `release.yml` env block evaluates `RELEASE_TAG` once at workflow start

**File:** `.github/workflows/release.yml:17-20`
**Issue:** `RELEASE_TAG: ${{ github.event.inputs.tag || github.ref_name }}` is correct. Worth documenting that this is workflow-scoped and consistent across jobs (some workflows accidentally re-evaluate per-job env). No fix needed; observation only.
**Fix:** None; mentioned for review completeness.

---

_Reviewed: 2026-05-09_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
