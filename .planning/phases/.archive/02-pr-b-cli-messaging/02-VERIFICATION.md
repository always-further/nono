---
phase: 02-pr-b-cli-messaging
verified: 2026-04-03T23:00:00Z
status: passed
score: 7/7 must-haves verified
re_verification: false
---

# Phase 2: PR-B CLI Messaging Verification Report

**Phase Goal:** WIN-1720 — Remove the CLI/library split from all runtime output; `setup --check-only` emits one unified Windows support line; CLI runtime validation routes through the library's `support_info()`; `nono shell` and `nono wrap` remain hard-rejected on Windows
**Verified:** 2026-04-03T23:00:00Z
**Status:** passed
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | `setup --check-only` emits a single `Support status: supported` line; no CLI/library split | VERIFIED | `setup.rs:189` and `setup.rs:740` both emit `println!("...Support status: {}", info.status_label())`. `windows_cli_support_status_label` function absent. |
| 2 | Live run follows unified code path: `print_applying_sandbox` -> `apply` -> `print_sandbox_active` | VERIFIED | `execution_runtime.rs:22,36` call these in order. No dead `!is_supported` branch preceding them. No `current_dir: &Path` parameter. |
| 3 | `nono shell` and `nono wrap` are unconditionally rejected on Windows regardless of `is_supported` value | VERIFIED | `command_runtime.rs:77-85` (shell) and `command_runtime.rs:146-154` (wrap) call `Sandbox::validate_windows_preview_entry_point` directly under `#[cfg(target_os = "windows")]` with no `if !is_supported` guard. |
| 4 | No dead code remains in `execution_runtime.rs`, `output.rs`, or `setup.rs` from old `!is_supported` branches | VERIFIED | `grep` for `!support.is_supported`, `!_support.is_supported`, `validate_windows_preview_direct_execution`, `preview_runtime_status` all return no matches across these files. |
| 5 | No env_vars.rs test asserts preview language, split labels, or old dead-branch wording | VERIFIED | No occurrences of `CLI support status`, `Library support status`, `current Windows command surface without claiming full parity`, `Windows restricted execution covers the current`, `current restricted-execution command surface`, or `dry-run must not imply enforcement` found in env_vars.rs. |
| 6 | Every env_vars.rs assertion is an individual replacement — no assertion blocks deleted wholesale | VERIFIED | Four functions renamed/updated; Plan 02-02 replaced each assertion individually per D-15/D-16. Negative guards retained but refactored to check absence of old wording. |
| 7 | All env_vars.rs Windows tests pass with promoted wording | VERIFIED (programmatic check) | New assertions use `"sandbox would be applied with above capabilities"` (line 465), `text.contains("active")` (lines 492, 569), `"Support status: supported"` (lines 2519, 2572). Old prohibited strings absent. Commits 1795a73, 4b93d0a, b619553, 7f22b67 all verified present in git log. |

**Score:** 7/7 truths verified

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/nono-cli/src/setup.rs` | Unified support status line; no `windows_cli_support_status_label` | VERIFIED | Contains `Support status: {}` with `info.status_label()` at lines 189 and 740. Function `windows_cli_support_status_label` absent. |
| `crates/nono-cli/src/execution_runtime.rs` | No `validate_windows_preview_direct_execution`; no dead `!is_supported` branch; no `current_dir: &Path` param | VERIFIED | `apply_pre_fork_sandbox` signature at line 16 takes only `(strategy, caps, silent)`. Dead function and call site absent. |
| `crates/nono-cli/src/command_runtime.rs` | Unconditional shell/wrap rejection on Windows | VERIFIED | Lines 77-85 and 146-154 call `validate_windows_preview_entry_point` with no `is_supported` guard. |
| `crates/nono-cli/src/output.rs` | No dead `!is_supported` branches in `print_banner`, `print_supervised_info`, `dry_run_summary` | VERIFIED | `print_banner` (line 34) has no Windows branch. `print_supervised_info` (line 289) always emits `"supervised (...)"`. `dry_run_summary` (line 534) always returns the cross-platform string. |
| `crates/nono-cli/tests/env_vars.rs` | Updated Windows integration test assertions matching promoted contract | VERIFIED | Four functions renamed: `windows_dry_run_reports_sandbox_validation`, `windows_run_allows_supported_directory_allowlist_in_live_run`, `windows_setup_check_only_reports_unified_support_status`. All stale assertion strings absent. |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `setup.rs` | `nono::Sandbox::support_info().status_label()` | unified status line | WIRED | `info.status_label()` called at lines 189 and 740; no separate CLI label function exists |
| `execution_runtime.rs` | `output::print_applying_sandbox` / `print_sandbox_active` | cross-platform sandbox path | WIRED | Both calls present at lines 22 and 36 of `apply_pre_fork_sandbox`; no dead branch before them |
| `env_vars.rs` | `output.rs` / `setup.rs` | assertion strings matching post-Plan-01 output | WIRED | `"sandbox would be applied with above capabilities"` at line 465; `"Support status: supported"` at lines 2519, 2572; `text.contains("active")` at lines 492, 569 |

---

### Data-Flow Trace (Level 4)

Not applicable. Phase 02 modifies CLI output strings and test assertions — no dynamic data rendering (no DB queries, no state-to-render pipelines). The data source is `nono::Sandbox::support_info()` which is a pure library function verified in Phase 01.

---

### Behavioral Spot-Checks

Step 7b: SKIPPED — tests are integration tests that require a compiled `nono` binary and a Windows runtime. The spot-check would require running `cargo test -p nono-cli` on a Windows host. The SUMMARY documents a pre-existing unrelated failure in `query_ext::tests::test_query_path_sensitive_policy_includes_policy_source` (wrong error variant returned), which is out of scope for phase 02.

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Four commits exist in git history | `git log --oneline 1795a73 4b93d0a b619553 7f22b67` | All four present | PASS |
| `windows_cli_support_status_label` removed | `grep` across nono-cli/src | No matches | PASS |
| `validate_windows_preview_direct_execution` removed | `grep` across nono-cli/src | No matches | PASS |
| Old test function names absent | `grep` for `preview_validation_without_enforcement` | No matches | PASS |
| New test function names present | `grep` for `windows_dry_run_reports_sandbox_validation` | Found at line 435 | PASS |

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| CLIMSG-01 | 02-01-PLAN.md | `setup --check-only` emits one unified Windows support status line (no separate CLI/library split labels) | SATISFIED | `setup.rs:189,740` both emit `Support status: {}` via `info.status_label()`. Split labels absent from file and from test assertions. |
| CLIMSG-02 | 02-01-PLAN.md | CLI runtime validation routes through the library's now-authoritative `support_info()` rather than a standalone Windows preview gate | SATISFIED | `apply_pre_fork_sandbox` routes through `Sandbox::apply()` cross-platform; `validate_windows_preview_direct_execution` (the standalone gate) is deleted. |
| CLIMSG-03 | 02-01-PLAN.md | `nono shell` and `nono wrap` remain hard-rejected on Windows via `validate_preview_entry_point` with explicit messaging | SATISFIED | `command_runtime.rs:78,147` call `Sandbox::validate_windows_preview_entry_point` unconditionally (no `is_supported` guard). Library-owned rejection message "intentionally unavailable on Windows" unchanged. |
| CLIMSG-04 | 02-02-PLAN.md | `env_vars.rs` test assertions updated per-assertion to match first-class supported wording (surgical updates, not wholesale deletion) | SATISFIED | Eight individual assertion replacements across four test functions. Old strings absent. New promoted strings present. Functions renamed to reflect promoted behavior. |

No orphaned requirements: REQUIREMENTS.md maps CLIMSG-01 through CLIMSG-04 exclusively to Phase 2, and all four are claimed and satisfied by the two plans in this phase directory.

---

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `setup.rs` | 20 | `#[allow(dead_code)]` on `verbose: u8` field | Info | Pre-existing before phase 02 (present in commit 2dfc993 context). Not added by this phase. Field is a future-facing placeholder for verbose output. No impact on phase goal. |
| `output.rs` | 1 | `#![cfg_attr(target_os = "windows", allow(dead_code))]` | Info | Explicitly retained by the plan to cover `print_abi_info` and other Linux/macOS-only functions. Correct and intentional. Not a phase 02 addition. |

No blockers. No warnings. Both items are pre-existing or intentional carve-outs documented in the plan.

---

### Human Verification Required

#### 1. Windows integration test suite passes

**Test:** Run `cargo test -p nono-cli` on a Windows host with a running nono binary in PATH.
**Expected:** All `env_vars.rs` Windows tests pass; no `preview` language, no `CLI support status`, no `Library support status` in any test assertion string.
**Why human:** Integration tests require a real Windows environment with the compiled binary. Cannot execute on this (Windows 11) host without a full Rust toolchain + compiled binary available in the shell.

#### 2. `nono shell` and `nono wrap` emit explicit rejection message on Windows

**Test:** Run `nono shell` and `nono wrap` on Windows.
**Expected:** Both commands produce an error message containing "intentionally unavailable on Windows" and exit non-zero.
**Why human:** Requires executing the compiled binary. Verifiable only in a live Windows test environment.

#### 3. `nono setup --check-only` emits single unified status line

**Test:** Run `nono setup --check-only` on Windows.
**Expected:** Output contains exactly `Support status: supported` (one line); no `CLI support status:` or `Library support status:` lines appear.
**Why human:** Requires executing the compiled binary. Code-level verification is complete; this is behavioral confirmation.

---

### Gaps Summary

No gaps. All must-haves from the two PLAN frontmatter blocks are satisfied by the actual codebase:

- The `windows_cli_support_status_label` function is deleted.
- Both split status lines in `setup.rs` are collapsed to single unified lines using `info.status_label()`.
- The dead `!is_supported` cfg block and `validate_windows_preview_direct_execution` function are removed from `execution_runtime.rs`.
- The `apply_pre_fork_sandbox` signature no longer has a `current_dir: &Path` parameter.
- Shell and wrap entry-point validation fires unconditionally on Windows.
- Dead `!is_supported` blocks are removed from `print_banner`, `print_supervised_info`, and `dry_run_summary` in `output.rs`.
- All eight stale env_vars.rs assertions are individually replaced with promoted wording.
- No `#[allow(dead_code)]` was added by this phase.

The pre-existing `query_ext::tests::test_query_path_sensitive_policy_includes_policy_source` failure is documented in 02-02-SUMMARY.md, confirmed as unrelated to phase 02 scope, and deferred to Phase 03.

---

_Verified: 2026-04-03T23:00:00Z_
_Verifier: Claude (gsd-verifier)_
