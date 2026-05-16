---
phase: 41-ci-cleanup-v24-broker-code-review-closure
reviewed: 2026-05-16T00:00:00Z
depth: standard
files_reviewed: 23
files_reviewed_list:
  - .github/workflows/ci.yml
  - bindings/c/include/nono.h
  - bindings/c/src/lib.rs
  - bindings/c/src/types.rs
  - crates/nono-cli/Cargo.toml
  - crates/nono-cli/src/audit_integrity.rs
  - crates/nono-cli/src/cli.rs
  - crates/nono-cli/src/command_runtime.rs
  - crates/nono-cli/src/exec_identity.rs
  - crates/nono-cli/src/exec_strategy.rs
  - crates/nono-cli/src/exec_strategy/supervisor_linux.rs
  - crates/nono-cli/src/exec_strategy_windows/launch.rs
  - crates/nono-cli/src/exec_strategy_windows/mod.rs
  - crates/nono-cli/src/main.rs
  - crates/nono-cli/src/profile_runtime.rs
  - crates/nono-cli/src/protected_paths.rs
  - crates/nono-cli/src/pty_proxy.rs
  - crates/nono-cli/src/rollback_session.rs
  - crates/nono-cli/src/session.rs
  - crates/nono-cli/tests/common/mod.rs
  - crates/nono-cli/tests/common/test_env.rs
  - crates/nono-cli/tests/env_vars.rs
  - crates/nono-shell-broker/src/main.rs
  - scripts/validate-windows-msi-contract.ps1
findings:
  blocker: 1
  warning: 7
  total: 8
status: issues_found
---

# Phase 41: Code Review Report

**Reviewed:** 2026-05-16T00:00:00Z
**Depth:** standard
**Files Reviewed:** 23
**Status:** issues_found

## Summary

Phase 41 closes CI cleanup and v2.4 broker code-review items. The principal targets — FFI error mapping for `BrokerNotFound` (CR-01), null/INVALID handle rejection in the broker argv parser (CR-02), empty-list rejection (CR-03), Job Object containment (CR-04), and the `--dangerous-force-wfp-ready` runtime guard via `NONO_TEST_HARNESS` — are correctly implemented and well-tested. The Cargo.toml dev-dependency on `nono-shell-broker` is correctly scoped to Windows. The `EnvVarGuard` integration-test mirror is a reasonable workaround for the binary-crate visibility boundary. Authenticode self-trust-anchor verification on the broker spawn path is well-structured.

One BLOCKER was found: the build suite in `scripts/windows-test-harness.ps1` still calls `validate-windows-msi-contract.ps1` without the newly-mandatory `-BrokerPath` parameter. The CI `windows-build` job invokes this suite and will fail at PowerShell parameter binding — the exact failure mode that Plan 41-03's comment in the validator script warns about. The validator fix was applied but the upstream consumer in the test harness was not updated in lockstep.

The remaining WARNINGS cover: `--dangerous-force-wfp-ready` only wired into `nono run` (silently ignored on `shell`/`wrap`), broker `build_command_line` not rejecting NUL bytes or 32-bit `INVALID_HANDLE_VALUE`, FFI `NoCapabilities`/`NoCommand` conflation, FFI `HashMismatch`/`SessionNotFound` mapped to generic `ErrIo`, drift risk from duplicated `validate_env_var_patterns_local`, dev-dependency build profile mismatch with broker test, and the missing integration-test mirror of `lock_env()` / `EnvVarGuard::remove()`.

## Blockers

### CR-01: Windows test harness build suite invokes MSI validator without mandatory `-BrokerPath`

**File:** `scripts/windows-test-harness.ps1:146-148`
**Issue:** Phase 41 Plan 03 made `-BrokerPath` a mandatory parameter on `validate-windows-msi-contract.ps1` (line 8 of the validator). The CI `windows-build` job in `.github/workflows/ci.yml:151-153` invokes `.\scripts\windows-test-harness.ps1 -Suite build`, which executes:

```powershell
& (Join-Path $PWD "scripts\validate-windows-msi-contract.ps1") -BinaryPath (Join-Path $PWD "target\debug\nono.exe")
```

This call is missing the `-BrokerPath` argument. PowerShell will reject parameter binding at the validator's `[Parameter(Mandatory = $true)] [string]$BrokerPath` declaration with: "Cannot process command because of one or more missing mandatory parameters: BrokerPath." This is the exact failure mode that the comment at `scripts/validate-windows-msi-contract.ps1:5-7` warns about. CI will fail every run of the `windows-build` job once Phase 41 lands.

The Phase 41 fix updated the validator and the `windows-packaging` CI job site (which now passes all three paths), but missed this second consumer. Phase 41 RESEARCH/PATTERNS files only reference `validate-windows-msi-contract.ps1` and `ci.yml:343`; `windows-test-harness.ps1:147` was not part of the fix surface.

**Fix:** Update the call site in the build suite to pass `-BrokerPath` pointing at the workspace's debug-built broker artifact (the build suite runs `cargo build --workspace`, so `target/debug/nono-shell-broker.exe` is the natural sibling):

```powershell
Invoke-LoggedCommand -LogFile "windows-build.log" -Label "validate windows msi contract" -Command {
    & (Join-Path $PWD "scripts\validate-windows-msi-contract.ps1") `
        -BinaryPath (Join-Path $PWD "target\debug\nono.exe") `
        -BrokerPath (Join-Path $PWD "target\debug\nono-shell-broker.exe")
}
```

If the build suite is expected to validate without a built broker (e.g., minimal smoke), an alternative is to make `-BrokerPath` validation explicit `Test-Path -LiteralPath` (already in place at validator line 117) so the call site can pass a stub or omit the broker assertion via a separate switch — but the current state is "validator demands, caller omits → CI breaks."

## Warnings

### WR-01: `--dangerous-force-wfp-ready` silently ignored on `shell` and `wrap` subcommands

**File:** `crates/nono-cli/src/command_runtime.rs:26-29`
**Issue:** The wiring `if args.dangerous_force_wfp_ready { exec_strategy::set_windows_wfp_test_force_ready(true); }` exists only in `run_sandbox` (the `run` subcommand). `SandboxArgs` is shared with `nono shell` (via `ShellArgs.sandbox`) and `nono wrap` (via `WrapArgs.sandbox`), and clap will accept `--dangerous-force-wfp-ready` on either subcommand without error — but the flag will be parsed and discarded with no effect on the global `WINDOWS_WFP_TEST_FORCE_READY` atomic. A future test that exercises `nono shell` against the WFP backend would silently fail to flip the atomic and would observe real WFP-readiness checks instead of the test-force path, with no diagnostic.

**Fix:** Move the wiring into a shared helper called from all three command runtimes (`run_sandbox`, `run_shell`, `run_wrap`), or move it into the CLI bootstrap immediately after `Cli::parse()` so the flag's behavior is independent of subcommand. Example:

```rust
// crates/nono-cli/src/cli_bootstrap.rs (or a new sandbox_args helper)
#[cfg(target_os = "windows")]
pub(crate) fn apply_dangerous_test_flags(args: &crate::cli::SandboxArgs) {
    if args.dangerous_force_wfp_ready {
        crate::exec_strategy::set_windows_wfp_test_force_ready(true);
    }
}
```
Call from each of `run_sandbox`, `run_shell`, `run_wrap` immediately after extracting `args`. Alternative: reject the flag on subcommands where it has no effect, so the silent-drop becomes a hard error.

### WR-02: Broker `build_command_line` accepts interior NUL bytes in argv values

**File:** `crates/nono-shell-broker/src/main.rs:150-167`
**Issue:** `build_command_line` encodes each `shell_args` entry as UTF-16 via `OsStr::new(&cmd).encode_wide().chain(Some(0)).collect()`. If a `--shell-arg` value contains an interior NUL (e.g. an attacker-controlled arg piped through `nono.exe` that contains a U+0000 codepoint), `encode_wide` emits a `0u16` in the middle of the string, and `CreateProcessAsUserW` will truncate the command-line buffer at that NUL. Subsequent args, the `--cwd` value, and the HANDLE_LIST handles serialized into the buffer are silently lost. The broker would proceed to spawn the shell with a truncated argv but a HANDLE_LIST that no longer maps to the documented argv positions — a wire-protocol corruption with no visible error.

Because the broker trusts its parent (`nono.exe`), this is not directly exploitable, but it is a hardening gap: the broker docstring claims minimal-attack-surface, yet silently mis-tokenizes input.

**Fix:** Reject any argv value (and the broker/shell paths) containing a NUL byte in `parse_args` before they reach `build_command_line`. Example:

```rust
if v.encode_wide().any(|w| w == 0) {
    return Err(NonoError::SandboxInit(
        "argv value contains interior NUL byte; reject".into(),
    ));
}
```

Apply to `--shell`, `--shell-arg`, and `--cwd` values.

### WR-03: Broker INVALID_HANDLE_VALUE check uses `usize::MAX` (host pointer width) but accepts the 32-bit sentinel literally on 64-bit hosts

**File:** `crates/nono-shell-broker/src/main.rs:98-107`
**Issue:** The rejection guard `if raw_value == 0 || raw_value == usize::MAX` correctly handles the host's native `INVALID_HANDLE_VALUE` (`(HANDLE)-1`). However, the 32-bit `INVALID_HANDLE_VALUE` literal `0xFFFFFFFF` is NOT rejected on a 64-bit Windows host (where `usize::MAX = 0xFFFFFFFFFFFFFFFF`). An operator or test writing `--inherit-handle 0xFFFFFFFF` on a 64-bit broker would have that value passed to `UpdateProcThreadAttribute(HANDLE_LIST)`. Windows handle values are pointer-sized; `0xFFFFFFFF` is theoretically a valid 64-bit handle though unusually small. Defense-in-depth would also reject this and other small sentinel values.

The test `parse_args_invalid_handle_value_inherit_handle_returns_error` covers only the native-width sentinel.

**Fix:** Extend the guard to reject the 32-bit sentinel as well:

```rust
if raw_value == 0 || raw_value == usize::MAX || raw_value == 0xFFFFFFFF {
    return Err(NonoError::SandboxInit(format!(
        "--inherit-handle value '{hex_str}' is null or INVALID_HANDLE_VALUE; reject"
    )));
}
```

Add a companion test for the 32-bit sentinel.

### WR-04: FFI `map_error` conflates `NoCommand` with `NoCapabilities`

**File:** `bindings/c/src/lib.rs:80-82`
**Issue:** `NoCapabilities | NoCommand => ErrNoCapabilities`. The two `NonoError` variants are semantically distinct: `NoCommand` means "the user invoked `nono run` with no `--` command", while `NoCapabilities` means "the capability set is empty". A C consumer receiving `ErrNoCapabilities` cannot distinguish the two cases without parsing the error string, defeating the structured-error contract. Phase 41 D-09 (CR-01) explicitly chose `BrokerNotFound → ErrSandboxInit` to keep the structural distinction; the same discipline should apply here.

**Fix:** Either:
1. Introduce a new error code `ErrNoCommand` and route `NoCommand` to it (the cleaner fix), OR
2. Map `NoCommand → ErrInvalidArg` (closer to the user-input semantic — the "argument missing" intent matches existing `ErrInvalidArg` usage at `CwdPromptRequired` and `EnvVarValidation`).

### WR-05: FFI `map_error` lumps `HashMismatch` and `SessionNotFound` under generic `ErrIo`

**File:** `bindings/c/src/lib.rs:116-119`
**Issue:** `ObjectStore | Snapshot | HashMismatch { .. } | SessionNotFound(_) => ErrIo`. `HashMismatch` is a content-integrity verification failure (Merkle-tree corruption, tampered snapshot), which semantically belongs with `TrustVerification` errors at line 120-125. `SessionNotFound` is a lookup miss, semantically closer to `PathNotFound` than to I/O. Conflating these with generic I/O means C consumers cannot route tamper detection (security-critical) versus benign I/O issues (e.g., disk-full).

**Fix:** Route `HashMismatch` to `ErrTrustVerification` and `SessionNotFound` to `ErrPathNotFound`:

```rust
nono::NonoError::ObjectStore(_) | nono::NonoError::Snapshot(_) => NonoErrorCode::ErrIo,
nono::NonoError::HashMismatch { .. } => NonoErrorCode::ErrTrustVerification,
nono::NonoError::SessionNotFound(_) => NonoErrorCode::ErrPathNotFound,
```

Add unit tests pinning each mapping, following the pattern of `broker_not_found_maps_to_err_sandbox_init` (lib.rs:279).

### WR-06: Duplicated `validate_env_var_patterns_local` introduces drift risk

**File:** `crates/nono-cli/src/profile_runtime.rs:289-306`
**Issue:** The body of `validate_env_var_patterns_local` is byte-identical to `validate_env_var_patterns` in `crates/nono-cli/src/exec_strategy/env_sanitization.rs:127-143`. The duplication is documented (line 254-260 of profile_runtime.rs) as a workaround for the `exec_strategy_windows` module-boundary invariant from Plan 34. However, no test asserts that the two implementations stay in lock-step. A future patch to either copy will silently diverge — a profile pattern accepted by one validator and rejected by the other becomes a security inconsistency (a deny-list with `*FOO*` would be rejected by one path but accepted by the other, depending on which call site fires first).

**Fix:** Add an assertion test in `profile_runtime.rs` tests module that calls both functions against the same fuzz-style inputs and asserts byte-identical results:

```rust
#[test]
fn env_var_pattern_validators_stay_in_lockstep() {
    use crate::exec_strategy::env_sanitization::validate_env_var_patterns;
    for case in [vec![], vec!["*".into()], vec!["FOO_*".into()], vec!["*FOO".into()],
                 vec!["FOO*BAR".into()], vec!["*FOO*".into()]] {
        assert_eq!(
            super::validate_env_var_patterns_local(&case, "allow_vars"),
            validate_env_var_patterns(&case, "allow_vars"),
            "validators must agree on input {:?}", case,
        );
    }
}
```

Alternative (preferred): expose the canonical helper through a non-`exec_strategy_windows` module path so `profile_runtime` can import it directly — but that requires touching the D-34-E1 boundary, which is presumably out of scope.

### WR-07: Dev-dependency on `nono-shell-broker` builds DEBUG; broker test only looks in RELEASE directories

**File:** `crates/nono-cli/Cargo.toml:109-115` and `crates/nono-cli/src/exec_strategy_windows/launch.rs:2436-2459`
**Issue:** The Cargo.toml comment states: "Declaring it as a dev-dependency makes cargo build the broker artifact before running nono-cli tests — eliminating the manual `cargo build -p nono-shell-broker` step." This is misleading. Cargo dev-dependencies build into `target/<profile>/` where `<profile>` defaults to `debug` for `cargo test`. The test `broker_launch_assigns_child_to_job_object` only inspects:

```rust
target/x86_64-pc-windows-msvc/release/nono-shell-broker.exe
target/release/nono-shell-broker.exe
```

Neither path is populated by a dev-dependency build under `cargo test`. The test will panic in any dev workflow that runs `cargo test -p nono-cli` without a prior `cargo build -p nono-shell-broker --release`. The Phase 41 CR-04 disposition replaced silent-SKIP with PANIC, but the rationale for the Cargo.toml dev-dep — "eliminating the manual step" — is incorrect.

**Fix:** Either:
1. Also check `target/debug/nono-shell-broker.exe` as a fallback before panicking (acceptable because the Job Object containment assertion does not depend on release-mode optimization), OR
2. Update the Cargo.toml comment to truthfully say the dev-dep exists for compile-time link safety only, and the test still requires an explicit pre-build (the test's panic message already states this — line 2451-2455).

The cleanest fix is option 1: extend candidate_default checks to include `target/debug/nono-shell-broker.exe`:

```rust
let candidate_debug = workspace_root.join("target").join("debug").join("nono-shell-broker.exe");
let broker_path = if candidate_triple.exists() { candidate_triple }
    else if candidate_default.exists() { candidate_default }
    else if candidate_debug.exists() { candidate_debug }
    else { panic!(...) };
```

This aligns the test with the dev-dependency it now declares.

### WR-08: Integration `EnvVarGuard` mirror omits `lock_env()` and `EnvVarGuard::remove()`

**File:** `crates/nono-cli/tests/common/test_env.rs:1-50`
**Issue:** The integration-test copy of `EnvVarGuard` (introduced as the Phase 41-05 fix per the source comment) is missing two public surfaces present in the canonical `crates/nono-cli/src/test_env.rs`:
1. `pub fn lock_env() -> MutexGuard<'static, ()>` for process-global env-mutation serialization
2. `EnvVarGuard::remove(&self, key: &str)` for mid-test env-var removal

The comment claims "This file mirrors the canonical abstraction verbatim." It does not — it mirrors only `set_all` + Drop. Integration tests that ever need to remove a var mid-test or serialize against other env-mutating tests have no recourse; existing `audit_attestation.rs:261-283` defined its own `ScopedEnvVar` rather than use this mirror, suggesting the mirror surface is already known-insufficient.

Note: integration tests run as separate processes (file header comment line 3-4 of env_vars.rs), so `lock_env()` is arguably unnecessary at that boundary. But `remove()` is still useful within a single test, and the misleading docstring will mislead future contributors.

**Fix:** Either add the missing methods (preferred — keeps the "verbatim mirror" claim true), or amend the file header to accurately describe the subset:

```rust
//! Integration-test SUBSET of the `EnvVarGuard` RAII primitive.
//!
//! Mirrors only `set_all` + Drop. The full primitive in
//! `crates/nono-cli/src/test_env.rs` also exposes `lock_env()` and
//! `EnvVarGuard::remove()`; those are unused at the integration-test
//! boundary today (integration tests are separate processes; no
//! mid-test env removal is needed). Add them here if a future test
//! grows that requirement.
```

The latter is the minimal-touch fix; the former is the lint-against-drift fix.

---

_Reviewed: 2026-05-16T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
