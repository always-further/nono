---
status: partial
phase: 41-ci-cleanup-v24-broker-code-review-closure
source: [41-VERIFICATION.md]
started: 2026-05-16T19:30:00Z
updated: 2026-05-16T23:15:00Z
---

## Current Test

[awaiting human testing]

## Tests

### 1. NEW: CI run on HEAD `b78dba87` (or successor) — Rustfmt + Linux Clippy + macOS Build/Clippy lanes GREEN after Plan 41-10 (supersedes prior #1 + prior #3)
expected: GH Actions Linux Clippy + macOS Clippy + macOS Build lanes on `b78dba87` (or its successor) all PASS. None of these strings appear in lane logs: `cargo fmt --all -- --check` diff output for `exec_strategy.rs:2636` / `profile_runtime.rs:311` / `main.rs:547`; `clippy::zombie_processes` or `clippy::unwrap_used` on `supervisor_linux.rs`; `private function path_to_utf8` / `private function escape_seatbelt_path`; `error[E0599]: no associated item named 'RLIMIT_NPROC' found for enum 'Resource'`; `cannot find type NonoError in this scope`.
result: [pending]

### 2. All 8 GH Actions CI lanes status on Phase 41 close SHA (post-Plan-41-10 head `b78dba87` or successor) — with documented Class E deferral caveat
expected: Linux Clippy + Linux Test + macOS Clippy + macOS Build + Windows Build + Windows Security + Windows Packaging PASS. CAVEAT (documented disposition, NOT a Phase 41 blocker): Windows Integration + Windows Regression are EXPECTED to fail with `windows_run_redirects_{profile_state,temp}_vars_into_writable_allowlist` (Plan 41-05 env_vars parallel flake, HUMAN-UAT #4 territory; deferred to v2.5 cargo-nextest per Plan 41-10 Task 4 E.1+E.2 disposition). Linux Test should now report `run_allow_cwd_with_profile_deny_under_workdir_fails_closed` as `ignored` (not failed) per Plan 41-10 Task 4 Class D disposition.
result: [pending]

### 3. windows-build CI lane no longer fails at PowerShell parameter binding (Plan 41-08 carry-forward)
expected: ci-logs/windows-build.log contains NO "Cannot process command because of one or more missing mandatory parameters: BrokerPath" line; build suite progresses past "validate windows msi contract" label; cargo build -p nono-shell-broker step appears and succeeds.
result: [pending]

### 4. env_vars parallel flake on real Windows host (Plan 41-05) — 10x runs
expected: cargo test -p nono-cli --test env_vars windows_run_redirects_profile_state_vars_into_writable_allowlist run 10x in parallel — 0 failures across 10 runs.
result: [pending]

### 5. Block-net probe tests on elevated Windows runner with NONO_CI_HAS_WFP=true
expected: windows_run_block_net_blocks_probe_connection + windows_run_block_net_blocks_probe_through_cmd_host both PASS with "connect failed" or "exit code 42" markers in stderr.
result: [pending]

### 6. Cross-binding nono-py / nono-ts D-10 FFI remap audit
expected: No integer-mapping of -1 (ErrPathNotFound) as broker-discovery-failure in downstream bindings — or follow-up todo filed for lockstep.
result: [pending]

## Summary

total: 6
passed: 0
issues: 0
pending: 6
skipped: 0
blocked: 0

## Gaps
