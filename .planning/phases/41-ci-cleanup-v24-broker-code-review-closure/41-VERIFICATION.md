---
phase: 41-ci-cleanup-v24-broker-code-review-closure
verified: 2026-05-16T21:48:17Z
status: human_needed
score: 5/5 must-haves verified
overrides_applied: 0
re_verification:
  previous_status: gaps_found
  previous_score: 4/5
  previous_verified: 2026-05-16T20:30:00Z
  trigger: "Plan 41-09 landed 5 commits (05065209, 389c0fae, e97b596e, 0699c6f4, 47d55905) closing the 6 cross-target dead-code / clippy::manual_inspect gaps surfaced by CI run 25972316892 (Linux Test, Linux Clippy, macOS Clippy lanes). Codebase-level re-verification required."
  gaps_closed:
    - "Gap 1: crates/nono-cli/src/exec_strategy/env_sanitization.rs:127 validate_env_var_patterns orphan — closed by wiring profile_runtime.rs to delegate (commit 05065209). WR-06 closed simultaneously."
    - "Gap 2: crates/nono-cli/src/launch_runtime.rs interactive_shell field — closed by #[cfg_attr(not(target_os = \"windows\"), allow(dead_code))] (commit e97b596e)."
    - "Gap 3: crates/nono-cli/src/setup.rs:14-23 5 WFP fields — closed by #[cfg(target_os = \"windows\")] per-field gates (commit 389c0fae)."
    - "Gap 4: crates/nono-cli/src/setup.rs:748-793 6 phase_index methods — closed by #[cfg(target_os = \"windows\")] per-method gates (commit 389c0fae)."
    - "Gap 5: crates/nono-cli/tests/common/test_env.rs EnvVarGuard::set_all mirror — closed by module-inner #![cfg(target_os = \"windows\")] gate (commit e97b596e)."
    - "Gap 6: crates/nono/src/keystore.rs:1074-1078 map_err side-effect-only pattern — closed by replacement with .inspect_err(|_| {...}) (commit 0699c6f4)."
  gaps_remaining: []
  regressions: []
must_haves:
  truths:
    - "REQ-CI-01: cross-target Linux clippy clean; no new raw #[allow(dead_code)]; orphans deleted or cfg-gated"
    - "REQ-CI-02: 5 Windows CI jobs (Build, Integration, Regression, Security, Packaging) green; MSI validator -BrokerPath mismatch resolved; no unjustified #[ignored]"
    - "REQ-CI-03: baseline-aware CI gate baseline SHA + skipped-gates convention + STATE.md ## Deferred Items cleanup"
    - "REQ-BROKER-CR-01..03: BrokerNotFound FFI remap + broker null/INVALID + empty-list rejects"
    - "REQ-BROKER-CR-04: Job-object test silent-SKIP→FAIL resolved; STATE.md v24 CR-A entries cleared"
human_verification:
  - test: "Verify CI run after pushing 41-09 commits (05065209..47d55905) lands no -Dwarnings dead-code errors on Linux/macOS lanes"
    expected: "GitHub Actions Linux Test, Linux Clippy, macOS Clippy lanes on the SHA carrying 47d55905 (or its successor) all PASS. No occurrence of 'function `validate_env_var_patterns` is never used', 'field `interactive_shell` is never read', 'fields `register_wfp_service`', 'methods `register_phase_index`', 'associated function `set_all` is never used', or 'using `map_err` over `inspect_err`' in lane logs."
    why_human: "Live CI signal; not reproducible locally without cross-toolchain for Linux/macOS clippy from this Windows dev host (load-bearing per memory feedback_clippy_cross_target). NEW item for Plan 41-09 closure verification."
  - test: "Verify windows-build CI lane no longer fails at PowerShell parameter binding on next PR push (Plan 41-08 fix)"
    expected: "ci-logs/windows-build.log contains NO 'Cannot process command because of one or more missing mandatory parameters: BrokerPath' line; the build suite progresses past 'validate windows msi contract' label; cargo build -p nono-shell-broker step appears and succeeds."
    why_human: "Plan 41-08 closed the gap at codebase level (verified by grep + PowerShell syntax check), but decisive live signal — GH Actions windows-build job green on PR head SHA — lives in CI. Carried forward."
  - test: "Verify all 8 GH Actions CI lanes green on Phase 41 close SHA (post-41-09 head)"
    expected: "Linux Clippy + Linux Test + macOS Clippy + Windows Build + Windows Integration + Windows Regression + Windows Security + Windows Packaging all PASS on the same head commit."
    why_human: "Lives in GitHub Actions; not reproducible locally. REQ-CI-01 SC#3 + REQ-CI-02 SC#1+2 require GH Actions green on Phase 41 close SHA. Carried forward."
  - test: "Verify env_vars parallel flake fix (Plan 41-05) on Windows host — 10x parallel runs"
    expected: "0 failures across 10 parallel runs of `cargo test -p nono-cli --test env_vars windows_run_redirects_profile_state_vars_into_writable_allowlist`."
    why_human: "Plan 41-05 used Windows-host-only verification; current dev host did not execute the flake check (10x runs). CI Integration job covers this on Windows-latest. Carried forward."
  - test: "Verify block-net probe tests pass on Windows host with NONO_CI_HAS_WFP=true (elevated, WFP service installed)"
    expected: "windows_run_block_net_blocks_probe_connection + windows_run_block_net_blocks_probe_through_cmd_host both PASS with 'connect failed' or 'exit code 42' markers in stderr."
    why_human: "Plan 41-04 short-circuits on non-elevated dev hosts; full probe path runs only on elevated CI runner. Carried forward."
  - test: "Verify cross-binding nono-py / nono-ts impact of CR-01 FFI remap (D-10 deferred)"
    expected: "No integer-mapping of -1 (ErrPathNotFound) as broker-discovery-failure in downstream bindings — or follow-up todo filed for lockstep."
    why_human: "../nono-py/ and ../nono-ts/ are sibling repositories not present in this working directory. Carried forward."
---

# Phase 41: CI cleanup + v24 broker code-review closure Verification Report

**Phase Goal:** Reset every CI lane to green and clear the v24 Windows broker code-review backlog so Phases 42 + 43 inherit a clean baseline.

**Verified:** 2026-05-16T21:48:17Z (re-verification after Plan 41-09 cross-target gap closure)
**Status:** human_needed
**Re-verification:** Yes — supersedes 2026-05-16T20:30:00Z verification

## Re-verification Summary

The prior verification (2026-05-16T20:30:00Z, post-CI-run 25972316892) returned `status: gaps_found` with 4/5 must-haves VERIFIED at the codebase level. REQ-CI-01 had regressed from VERIFIED to PARTIAL because CI run 25972316892 surfaced 6 `-Dwarnings` dead-code / `clippy::manual_inspect` errors on Linux Test, Linux Clippy, and macOS Clippy lanes — errors that the Windows-host local verification could not catch because cross-target clippy was load-bearing-but-SKIPPED.

Plan 41-09 (commits `05065209`, `389c0fae`, `e97b596e`, `0699c6f4`, `47d55905`) landed 4 task commits + 1 docs commit between `a03f13cf` (prior verification SHA) and HEAD (`47d55905`). All 6 gaps + WR-06 have been closed via cfg-gating, delegate wiring, or one-line combinator swap. Cargo workspace check is clean on the Windows host post-commit.

**REQ-CI-01 flips back from PARTIAL to VERIFIED** at the codebase level. Status transitions: `gaps_found` (4/5) → `human_needed` (5/5).

The status is `human_needed` (NOT `passed`) because the 6 carried-forward human verification items remain: the same 5 from the prior verification PLUS one NEW item specific to Plan 41-09 (live CI confirmation that Linux Test + Linux Clippy + macOS Clippy lanes flip RED → GREEN on the post-push head SHA). The codebase-level fix is complete; the decisive GH Actions signal is pending the next PR push.

## Codebase Evidence — Plan 41-09 Gap Closure

Verified against HEAD (`47d55905`) on Windows dev host using greppable evidence from the planning trigger's verification block.

### Gap 1: `validate_env_var_patterns` orphan (REQ-CI-01 SC#1 + #4, simultaneous WR-06 close)

| Check | Expected | Actual | Result |
|-------|----------|--------|--------|
| `grep -c "validate_env_var_patterns_local" crates/nono-cli/src/profile_runtime.rs` | `0` | `0` | PASS |
| `grep -cE "crate::exec_strategy::validate_env_var_patterns\|exec_strategy::validate_env_var_patterns" crates/nono-cli/src/profile_runtime.rs` | `>= 2` | `3` (1 comment self-mention + 2 callsites; documented as deviation in 41-09-SUMMARY) | PASS |
| `grep -n "validate_env_var_patterns" crates/nono-cli/src/exec_strategy_windows/mod.rs` | 1 re-export at line 76 | `76:pub(crate) use env_sanitization::{is_dangerous_env_var, validate_env_var_patterns};` | PASS |
| `grep -n "validate_env_var_patterns" crates/nono-cli/src/exec_strategy.rs` | 1 non-Windows re-export at line 50 (untouched) | `50:pub(crate) use env_sanitization::validate_env_var_patterns;` | PASS |

The byte-identical local copy in `profile_runtime.rs` is gone; the canonical fn at `exec_strategy/env_sanitization.rs:127` is reached via `crate::exec_strategy::validate_env_var_patterns` from both call closures (`allowed_env_vars`, `denied_env_vars`). The Windows re-export tuple now mirrors the non-Windows precedent so the canonical fn resolves on all targets. **WR-06 simultaneously closed** — the drift-risk duplication is eliminated by deletion, not by lockstep test.

### Gap 2: `interactive_shell` field never read on Linux/macOS (REQ-CI-01 SC#1 + #4)

| Check | Expected | Actual | Result |
|-------|----------|--------|--------|
| `grep -B 1 'pub(crate) interactive_shell' crates/nono-cli/src/launch_runtime.rs \| grep -c 'cfg_attr(not(target_os = "windows"), allow(dead_code))'` | `1` | `1` | PASS |

Field at `launch_runtime.rs:179` (line shifted from prior :170 due to added doc comment block at lines 175-178 explaining the inverse direction). Cfg-attr applied per Plan 41-09 Task 3 — the inverse direction (`not(target_os = "windows")`) is required because the field is read by Windows-only code paths (`execution_runtime.rs:411`, `exec_strategy_windows/mod.rs:669,743`, `exec_strategy_windows/supervisor.rs:373,434`) and set on every platform in `ExecutionFlags::defaults`. The `cfg_attr` conditional gate is explicitly permitted per REQ-CI-01 SC#4 (which forbids unconditional bulk `#[allow(dead_code)]`, not conditional `cfg_attr`).

### Gap 3: 5 WFP `SetupRunner` fields never read on Linux/macOS (REQ-CI-01 SC#1 + #4)

| Check | Expected | Actual | Result |
|-------|----------|--------|--------|
| `crates/nono-cli/src/setup.rs:14-23` 5 WFP field declarations all carry `#[cfg(target_os = "windows")]` | 5 | 5 (`register_wfp_service` line 15, `install_wfp_service` line 17, `install_wfp_driver` line 19, `start_wfp_service` line 21, `start_wfp_driver` line 23 — each prefixed with cfg gate on the line above) | PASS |
| Constructor initializers at lines 33-42 all carry `#[cfg(target_os = "windows")]` on the prefix | 5 | 5 (verified by inspection) | PASS |
| Test fixture struct-literal entries at lines 1219-1223 carry matching cfg gates | 5 | 5 (verified by `cargo check -p nono-cli --tests` succeeding) | PASS |

Reader sites at lines 62-82, 660-680 are themselves already inside `#[cfg(target_os = "windows")]` blocks (verified by inspection of the surrounding `if !self.check_only { ... }` blocks in `run()` — see SUMMARY Task 2 note). On Linux/macOS the 5 fields no longer exist on the struct, so the dead-code lint cannot fire.

### Gap 4: 6 `phase_index` methods never used on Linux/macOS (REQ-CI-01 SC#1 + #4)

| Check | Expected | Actual | Result |
|-------|----------|--------|--------|
| Phase_index method declarations cfg-gated | 6 | 6 (`register_phase_index:748`, `install_phase_index:753`, `start_phase_index:758`, `install_driver_phase_index:766`, `start_driver_phase_index:771`, `recheck_wfp_phase_index:787` — each prefixed with `#[cfg(target_os = "windows")]`) | PASS |
| `any_windows_wfp_action_requested` (the 7th method in cluster) cfg gate preserved untouched | 1 | 1 (line 777-784, already cfg-gated before Plan 41-09) | PASS |

All 6 methods compile out on Linux/macOS, so the call sites at lines 152, 172, 192, 212, 232, 277 (themselves inside Windows-only WFP flows) reference symbols that no longer exist on non-Windows targets.

### Gap 5: `EnvVarGuard::set_all` mirror never used on Linux/macOS (REQ-CI-01 SC#1 + #4)

| Check | Expected | Actual | Result |
|-------|----------|--------|--------|
| `grep -cE '^#!\[cfg\(target_os = "windows"\)\]' crates/nono-cli/tests/common/test_env.rs` | `1` | `1` (at line 19, after the doc-comment block) | PASS |

Module-inner attribute gates the entire compilation unit. On Linux/macOS the `tests/common/test_env.rs` module compiles out, taking `EnvVarGuard::set_all` (and all sibling helpers) with it. The sole caller (`tests/env_vars.rs:1047` inside `windows_run_redirects_profile_state_vars_into_writable_allowlist` at line 1039) is already `#[cfg(target_os = "windows")]`, so the gate is reachability-correct.

### Gap 6: `map_err` clippy::manual_inspect lint on macOS (REQ-CI-01 SC#1)

| Check | Expected | Actual | Result |
|-------|----------|--------|--------|
| `sed -n '1068,1080p' crates/nono/src/keystore.rs \| grep -c 'map_err'` | `0` | `0` | PASS |
| `sed -n '1068,1080p' crates/nono/src/keystore.rs \| grep -c 'inspect_err'` | `1` | `1` | PASS |

The Gap-6 line range now contains `.inspect_err(|_| { let _ = child.kill(); let _ = child.wait(); })?;` (lines 1074-1078). The remaining `map_err` at line 1085 is the legitimate `String::from_utf8(output.stdout).map_err(|_| { NonoError::KeystoreAccess(...) })` — a true transformation that returns a NEW error, NOT a side-effect-only closure returning the input. That `map_err` is correctly out of scope for `clippy::manual_inspect`.

### REQ-CI-01 SC#4 Compliance Audit

| Check | Expected | Actual | Result |
|-------|----------|--------|--------|
| `git diff a03f13cf..HEAD -- 'crates/**/*.rs' \| grep -cE '^\+.*#\[allow\(dead_code\)\]'` (raw, unconditional) | `0` | `0` | PASS |
| `git diff a03f13cf..HEAD -- 'crates/**/*.rs' \| grep -cE '^\+.*cfg_attr.*allow\(dead_code\)'` (conditional, allowed) | `1` (Gap 2 interactive_shell) | `1` | PASS |

REQ-CI-01 SC#4 ("No `#[allow(dead_code)]` added — orphans either deleted or wired") is honored. The one conditional `cfg_attr(not(target_os = "windows"), allow(dead_code))` on the `interactive_shell` field is the explicitly-permitted form (per the established precedent at `launch_runtime.rs:189` + `:194` which use the inverse-direction `cfg_attr(target_os = "windows", allow(dead_code))` for Unix-read-only fields). The SC#4 spirit — no bulk silencing of dead-code — is preserved.

### Local Cargo Verification (Windows Host)

| Command | Expected | Actual | Result |
|---------|----------|--------|--------|
| `cargo check --workspace` | clean | `Finished dev profile [unoptimized + debuginfo] target(s) in 10.14s` | PASS |
| `cargo test -p nono-cli --bin nono profile_runtime` (per Plan 41-09 SUMMARY) | 2/2 passed | 2/2 passed (per SUMMARY) | PASS |
| `cargo test -p nono --lib keystore` (per Plan 41-09 SUMMARY) | 126/126 passed | 126/126 passed (per SUMMARY) | PASS |

The Windows-host cargo signal is clean, but the decisive cross-target Linux/macOS clippy signal lives in GH Actions and is captured in human verification item #1.

## Goal Achievement

### Observable Truths (Roadmap Success Criteria)

| # | Truth (Success Criterion) | Status | Evidence |
|---|---------------------------|--------|----------|
| 1 | REQ-CI-01 SC: cross-target Linux clippy clean from Windows host + GH Actions Linux/macOS Clippy green; no `#[allow(dead_code)]` added — every orphan deleted or wired | **VERIFIED** (codebase level; CI green = human-verify #1) | All 6 cross-target gaps from prior verification are closed (see § Codebase Evidence). SC#4 audit clean (0 raw `#[allow(dead_code)]` in diff). The API migration, audit_ledger deletion, and Phase 41-02 cfg-gates from prior plans remain intact. Live CI signal is the decisive confirmation — pending next push. |
| 2 | REQ-CI-02 SC: All 5 Windows CI jobs green; MSI validator -BrokerPath mismatch resolved; no [ignored] markers | VERIFIED (code-level; CI green = human-verify #2) | Unchanged from prior verification. Plan 41-08's `scripts/windows-test-harness.ps1:158-170` fix landed and intact (`-BrokerPath $brokerPath` argument present). Live CI confirmation pending. |
| 3 | REQ-CI-03 SC: Baseline SHA in upstream-sync-quick.md updated to Phase 41 close SHA; SUMMARY frontmatter convention documented; STATE.md ## Deferred Items cleared of v24 CR-A | VERIFIED | Unchanged. `.planning/templates/upstream-sync-quick.md` baseline SHA `13cc0628` (line 102); `41-SUMMARY.md` `skipped_gates_convention` frontmatter present (line 4); STATE.md v24 CR-A row cleared. |
| 4 | REQ-BROKER-CR-01..03 SC: BrokerNotFound→ErrSandboxInit FFI remap; broker argv rejects null/INVALID/empty handle inputs | VERIFIED | Unchanged. `bindings/c/src/lib.rs:138` BrokerNotFound→ErrSandboxInit mapping intact; `crates/nono-shell-broker/src/main.rs:127-134` empty-handle reject; CR-02 null-handle guard at :103-107 intact (verified by Plan 41-06 SUMMARY + spot-check). |
| 5 | REQ-BROKER-CR-04 SC: Job-object test silent-SKIP→FAIL resolved with explicit decision; STATE.md ## Deferred Items cleared of v24 CR-A | VERIFIED | Unchanged. `crates/nono-cli/src/exec_strategy_windows/launch.rs:2450-2458` panic! intact (Plan 41-07); Cargo.toml cfg-windows dev-dep intact; STATE.md updated. |

**Score:** 5/5 truths verified at codebase level (was 4/5; REQ-CI-01 promoted from PARTIAL to VERIFIED via Plan 41-09 gap closure).

### Required Artifacts

All previously failed artifact rows from the prior verification are now resolved by Plan 41-09 (see § Codebase Evidence above). The previously-verified artifacts from Plans 41-01..41-08 remain unchanged:

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/nono-cli/src/profile_runtime.rs` | Delegates to canonical `exec_strategy::validate_env_var_patterns`; no local copy | VERIFIED | Plan 41-09 Task 1 — 2 delegate call-sites, 0 local-copy references |
| `crates/nono-cli/src/exec_strategy_windows/mod.rs` | Re-exports `validate_env_var_patterns` alongside `is_dangerous_env_var` | VERIFIED | Plan 41-09 Task 1 — line 76 |
| `crates/nono-cli/src/launch_runtime.rs` | `interactive_shell` field cfg-attr-gated | VERIFIED | Plan 41-09 Task 3 — line 178-179 |
| `crates/nono-cli/src/setup.rs` | 5 WFP fields + 6 phase_index methods cfg-gated to Windows | VERIFIED | Plan 41-09 Task 2 — lines 14-23, 33-42, 748-793, 1219-1223 |
| `crates/nono-cli/tests/common/test_env.rs` | Module-inner `#![cfg(target_os = "windows")]` gate | VERIFIED | Plan 41-09 Task 3 — line 19 |
| `crates/nono/src/keystore.rs` | `inspect_err` for side-effect-only error cleanup in Apple Passwords path | VERIFIED | Plan 41-09 Task 4 — lines 1074-1078 |
| `crates/nono-cli/src/exec_strategy.rs` | `request_path()` helper + `HandleTarget` import path | VERIFIED | Plan 41-01 + Quick 260516-mxw — line 2633, `use nono::supervisor::HandleTarget` |
| `scripts/windows-test-harness.ps1` | `-BrokerPath $brokerPath` argument on validator invocation | VERIFIED | Plan 41-08 — lines 158-170 |
| `bindings/c/src/lib.rs` | `BrokerNotFound`→`ErrSandboxInit` FFI mapping | VERIFIED | Plan 41-06 — line 138 |
| `crates/nono-shell-broker/src/main.rs` | Empty-handle-list reject + null/INVALID guards | VERIFIED | Plan 41-06 — lines 127-134, 103-107 |
| `crates/nono-cli/src/exec_strategy_windows/launch.rs` | Job-object test panic! on SKIP path | VERIFIED | Plan 41-07 — lines 2450-2458 |
| `.planning/templates/upstream-sync-quick.md` | Baseline SHA reset to `13cc0628` | VERIFIED | Plan 41-07 — line 102 |
| `.planning/phases/41-.../41-SUMMARY.md` | `skipped_gates_convention` frontmatter | VERIFIED | Plan 41-07 — line 4 |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `profile_runtime.rs` (allowed_env_vars, denied_env_vars closures) | `exec_strategy/env_sanitization.rs:127` (`validate_env_var_patterns`) | `crate::exec_strategy::validate_env_var_patterns` re-export | WIRED | Plan 41-09 Task 1 |
| `exec_strategy.rs:50` (non-Windows re-export) | `env_sanitization::validate_env_var_patterns` | direct `pub(crate) use` | WIRED | Pre-existing, untouched |
| `exec_strategy_windows/mod.rs:76` (Windows re-export) | `env_sanitization::validate_env_var_patterns` | direct `pub(crate) use` (mirror tuple) | WIRED | Plan 41-09 Task 1 added |
| `setup.rs::SetupRunner::new` (Windows constructor branch) | 5 WFP boolean fields on struct | cfg-matched field initializers | WIRED on Windows only | Plan 41-09 Task 2 |
| `setup.rs::run` (Windows WFP flow) | 6 phase_index methods | cfg-matched method dispatch | WIRED on Windows only | Plan 41-09 Task 2 |

No key links broken by the gap closure. The deletion of `validate_env_var_patterns_local` shortened the call chain by one hop without breaking the wiring contract.

### Data-Flow Trace (Level 4)

Not applicable for this re-verification — Plan 41-09 is a dead-code cleanup + idiom swap pass. No artifacts render dynamic data; the changes are purely structural. Plan 41-09 Task 4 (`map_err` → `inspect_err`) preserves the cleanup-on-error data flow verbatim (best-effort `child.kill()` + `child.wait()` still runs when `wait_with_timeout` errs; original error still propagates via `?`).

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Workspace cargo check clean on Windows host | `cargo check --workspace` | `Finished dev profile target(s) in 10.14s` | PASS |
| Gap 1 local-copy removed | `grep -c "validate_env_var_patterns_local" crates/nono-cli/src/profile_runtime.rs` | `0` | PASS |
| Gap 1 Windows re-export | `grep -nE "validate_env_var_patterns" crates/nono-cli/src/exec_strategy_windows/mod.rs` | `76:pub(crate) use env_sanitization::{is_dangerous_env_var, validate_env_var_patterns};` | PASS |
| Gap 2 interactive_shell cfg-attr | `grep -B 1 'pub(crate) interactive_shell' crates/nono-cli/src/launch_runtime.rs` | shows `cfg_attr(not(target_os = "windows"), allow(dead_code))` at line 178 | PASS |
| Gap 3 WFP fields cfg-gated | `grep -nE 'register_wfp_service\|install_wfp_service\|install_wfp_driver\|start_wfp_service\|start_wfp_driver' crates/nono-cli/src/setup.rs` | shows 5 field decls + 5 initializers + 10 reader sites (all in Windows-only WFP branches) | PASS |
| Gap 4 phase_index cfg-gated | `grep -nE 'fn register_phase_index\|fn install_phase_index\|fn start_phase_index\|fn install_driver_phase_index\|fn start_driver_phase_index\|fn recheck_wfp_phase_index' crates/nono-cli/src/setup.rs` | 6 method decls each preceded by `#[cfg(target_os = "windows")]` | PASS |
| Gap 5 test_env module gate | `grep -nE '^#!\[cfg\(target_os = "windows"\)\]' crates/nono-cli/tests/common/test_env.rs` | `19:#![cfg(target_os = "windows")]` | PASS |
| Gap 6 keystore map_err absent | `sed -n '1068,1080p' crates/nono/src/keystore.rs \| grep -c 'map_err'` | `0` | PASS |
| Gap 6 keystore inspect_err present | `sed -n '1068,1080p' crates/nono/src/keystore.rs \| grep -c 'inspect_err'` | `1` | PASS |
| REQ-CI-01 SC#4 raw allow(dead_code) audit | `git diff a03f13cf..HEAD -- 'crates/**/*.rs' \| grep -cE '^\+.*#\[allow\(dead_code\)\]'` | `0` | PASS |
| REQ-CI-01 SC#4 conditional cfg_attr audit | `git diff a03f13cf..HEAD -- 'crates/**/*.rs' \| grep -cE '^\+.*cfg_attr.*allow\(dead_code\)'` | `1` (Gap 2 only, permitted) | PASS |
| Cross-target Linux/macOS clippy from Windows host | NOT runnable without cross-toolchain (load-bearing per memory `feedback_clippy_cross_target`) | SKIPPED — escalated to human verification item #1 | SKIP (decisive signal in CI) |
| Plan 41-01 request_path helper intact | `grep -nE 'request_path\|HandleTarget' crates/nono-cli/src/exec_strategy.rs` | line 2633 `fn request_path`, line 2634 `use nono::supervisor::HandleTarget`, plus 7 callsites | PASS |
| Plan 41-08 BrokerPath fix intact | `grep -nE 'BrokerPath' scripts/windows-test-harness.ps1` | lines 158-170 contain the parameter binding + comment block | PASS |
| Plan 41-06 BrokerNotFound→ErrSandboxInit intact | `grep -nE 'BrokerNotFound\|ErrSandboxInit' bindings/c/src/lib.rs` | line 138 mapping + lines 274-286 test | PASS |
| Plan 41-06 broker null + empty-list guards intact | `grep -nE 'INVALID_HANDLE\|inherit-handle list is empty' crates/nono-shell-broker/src/main.rs` | lines 127-134 empty-list reject; CR-02 null guard at :103-107 | PASS |
| Plan 41-07 baseline SHA + skipped_gates_convention intact | `grep -nE 'baseline_sha\|13cc0628\|skipped_gates_convention' .planning/templates/upstream-sync-quick.md .planning/phases/41-ci-cleanup-v24-broker-code-review-closure/41-SUMMARY.md` | upstream-sync-quick.md:102 `13cc0628`; 41-SUMMARY.md:4 `skipped_gates_convention:` | PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| REQ-CI-01 | 41-01, 41-02, 41-09 | Linux/macOS Clippy lints resolved | SATISFIED (codebase-level); GH Actions green = human-verify #1 | API migration + audit_ledger deletion + cfg-gates from prior plans intact; Plan 41-09 closed the 6 cross-target gaps from prior verification. SC#4 audit clean. |
| REQ-CI-02 | 41-03, 41-04, 41-05, 41-08 | Windows CI jobs green (5 jobs) | SATISFIED (code-level); GH Actions green = human-verify #2 | Plan 41-08's PowerShell BrokerPath fix landed and intact (lines 158-170). |
| REQ-CI-03 | 41-07 | Baseline-aware gate reset + skipped-gates convention + STATE.md cleanup | SATISFIED | Three D-16 commits intact. |
| REQ-BROKER-CR-01 | 41-06 | BrokerNotFound FFI not-found mapping | SATISFIED | `bindings/c/src/lib.rs:138` |
| REQ-BROKER-CR-02 | 41-06 | Broker null-handle validation | SATISFIED | `crates/nono-shell-broker/src/main.rs:103-107` + 2 tests |
| REQ-BROKER-CR-03 | 41-06 | Broker empty-handle-list path | SATISFIED | `crates/nono-shell-broker/src/main.rs:127-134` + flipped test |
| REQ-BROKER-CR-04 | 41-07 | Job-object test skip policy | SATISFIED | `launch.rs:2450-2458` panic! + Cargo.toml dev-dep |

### Anti-Patterns Found

The 6 BLOCKER-class CI-surfaced findings from the prior verification are now resolved by Plan 41-09 (rows 1-5 in the prior table, plus the macOS keystore::map_err row). The 7 deferred WARNINGS minus WR-06 (which Plan 41-09 Task 1 closed) remain in the backlog.

| File | Line | Pattern | Severity | Status |
|------|------|---------|----------|--------|
| `crates/nono-cli/src/profile_runtime.rs` | (former :290 line) | `validate_env_var_patterns_local` byte-identical duplicate | (was WR-06 WARNING + CI-surfaced BLOCKER row 1) | **CLOSED** by Plan 41-09 Task 1 (deletion + delegation) |
| `crates/nono-cli/src/exec_strategy/env_sanitization.rs` | 127 | `pub(crate) fn` never used on Linux/macOS | (was 🛑 BLOCKER) | **CLOSED** by Plan 41-09 Task 1 (wired via delegate from profile_runtime.rs) |
| `crates/nono-cli/src/launch_runtime.rs` | 179 | `ExecutionFlags.interactive_shell` field never read on Linux/macOS | (was 🛑 BLOCKER) | **CLOSED** by Plan 41-09 Task 3 (`cfg_attr(not(target_os = "windows"), allow(dead_code))`) |
| `crates/nono-cli/src/setup.rs` | 14-23, 748-793 | WFP setup surface never exercised on Linux/macOS | (was 🛑 BLOCKER) | **CLOSED** by Plan 41-09 Task 2 (per-item `#[cfg(target_os = "windows")]` gates on 5 fields + 6 methods + initializers + fixtures) |
| `crates/nono-cli/tests/common/test_env.rs` | 23-37 | `EnvVarGuard::set_all` mirror orphan on Linux/macOS | (was 🛑 BLOCKER) | **CLOSED** by Plan 41-09 Task 3 (module-inner `#![cfg(target_os = "windows")]`) |
| `crates/nono/src/keystore.rs` | 1074-1078 | `map_err(\|e\| {...; e})` clippy::manual_inspect on macOS | (was 🛑 BLOCKER) | **CLOSED** by Plan 41-09 Task 4 (one-line swap to `.inspect_err(\|_\| {...})`) |
| `crates/nono-cli/Cargo.toml` | 109-115 | Dev-dep builds DEBUG but test only checks RELEASE | ⚠️ WARNING (WR-07) | DEFERRED — backlog |
| `crates/nono-cli/tests/common/test_env.rs` | 5-10 | Doc-comment claims "verbatim mirror" but omits `lock_env()` and `EnvVarGuard::remove()` | ⚠️ WARNING (WR-08) | DEFERRED — backlog |
| `crates/nono-cli/src/command_runtime.rs` | 26-29 | `--dangerous-force-wfp-ready` silently dropped on `nono shell`/`nono wrap` | ⚠️ WARNING (WR-01) | DEFERRED — backlog |
| `crates/nono-shell-broker/src/main.rs` | 103-107 | INVALID_HANDLE_VALUE guard misses 32-bit `0xFFFFFFFF` sentinel | ⚠️ WARNING (WR-03) | DEFERRED — backlog |
| `crates/nono-shell-broker/src/main.rs` | 150-167 | `build_command_line` does not reject argv values with interior NUL bytes | ⚠️ WARNING (WR-02) | DEFERRED — backlog |
| `bindings/c/src/lib.rs` | 80-82 | `NoCapabilities \| NoCommand => ErrNoCapabilities` conflates distinct semantics | ⚠️ WARNING (WR-04) | DEFERRED — backlog |
| `bindings/c/src/lib.rs` | 116-119 | `HashMismatch` → `ErrIo` (should be `ErrTrustVerification`); `SessionNotFound` → `ErrIo` (should be `ErrPathNotFound`) | ⚠️ WARNING (WR-05) | DEFERRED — backlog |

## Deferred (Backlog)

The 7 WARNINGS deferred per the prior verification minus WR-06 (which Plan 41-09 Task 1 closed) remain in the backlog. Per user "Blocker only" scope discipline across Plan 41-08 + 41-09. **v2.5 milestone or future hardening phase candidate.**

| Item | File | Brief | Disposition |
|------|------|-------|-------------|
| WR-01 | crates/nono-cli/src/command_runtime.rs:26-29 | `--dangerous-force-wfp-ready` silently dropped on `nono shell`/`nono wrap` | Backlog — defense-in-depth UX hardening |
| WR-02 | crates/nono-shell-broker/src/main.rs:150-167 | `build_command_line` does not reject argv values with interior NUL bytes | Backlog — minimal-attack-surface |
| WR-03 | crates/nono-shell-broker/src/main.rs:103-107 | INVALID_HANDLE_VALUE guard misses 32-bit sentinel `0xFFFFFFFF` | Backlog — defense-in-depth |
| WR-04 | bindings/c/src/lib.rs:80-82 | `NoCapabilities \| NoCommand` conflates distinct semantics | Backlog — FFI error precision |
| WR-05 | bindings/c/src/lib.rs:116-119 | `HashMismatch`/`SessionNotFound` routed to `ErrIo` instead of precise codes | Backlog — FFI error routing |
| ~~WR-06~~ | ~~crates/nono-cli/src/profile_runtime.rs~~ | ~~byte-identical local copy of `validate_env_var_patterns`~~ | **CLOSED** by Plan 41-09 Task 1 (deletion + delegate) |
| WR-07 | crates/nono-cli/Cargo.toml:109-115 | Dev-dep builds DEBUG but test only checks RELEASE | Backlog — dev-loop UX |
| WR-08 | crates/nono-cli/tests/common/test_env.rs:5-10 | Mirror omits `lock_env()`/`EnvVarGuard::remove()` | Backlog — doc freshness |

## Human Verification Required

#### 1. NEW: Verify CI run after pushing 41-09 commits (`05065209..47d55905`) lands no `-Dwarnings` dead-code errors on Linux/macOS lanes

**Test:** After Phase 41 commits push (or after the next gap-closure commit if any), inspect GH Actions runs for Linux Test, Linux Clippy, and macOS Clippy lanes on the head SHA carrying `47d55905`.
**Expected:** All three lanes PASS. None of the following strings appear in lane logs:
- `function \`validate_env_var_patterns\` is never used`
- `field \`interactive_shell\` is never read`
- `fields \`register_wfp_service\``
- `methods \`register_phase_index\``
- `associated function \`set_all\` is never used`
- `using \`map_err\` over \`inspect_err\``
**Why human:** Live CI signal; not reproducible locally without cross-toolchain for Linux/macOS clippy from this Windows dev host (load-bearing per memory `feedback_clippy_cross_target`). NEW for this Plan 41-09 closure re-verification.

#### 2. windows-build CI lane no longer fails at PowerShell parameter binding after Plan 41-08 lands

**Test:** On the next push to the Phase 41 PR branch, inspect the GH Actions `windows-build` job's `Run Windows build harness` step output.
**Expected:** NO line matching `Cannot process command because of one or more missing mandatory parameters: BrokerPath`; the new `==> build nono-shell-broker` label appears followed by a successful `cargo build -p nono-shell-broker`; the `==> validate windows msi contract` label is followed by NO Test-Path failure.
**Why human:** Decisive live signal lives in GH Actions; not reproducible locally. Carried forward from prior verification.

#### 3. All 8 GH Actions CI lanes green on Phase 41 close SHA

**Test:** Open / refresh the Phase 41 PR and inspect CI status for all lanes (Linux Clippy, Linux Test, macOS Clippy, Windows Build, Windows Integration, Windows Regression, Windows Security, Windows Packaging) on the head SHA after Plan 41-09 lands.
**Expected:** All lanes PASS on the same head commit.
**Why human:** REQ-CI-01 SC#3 + REQ-CI-02 SC#1+2 require GH Actions green on Phase 41 close SHA; not reproducible locally. Carried forward.

#### 4. env_vars parallel flake fix (Plan 41-05) on Windows host

**Test:** On a Windows host, run `cargo test -p nono-cli --test env_vars windows_run_redirects_profile_state_vars_into_writable_allowlist` 10 times back-to-back in parallel mode.
**Expected:** 0 failures across 10 runs.
**Why human:** Plan 41-05 did not execute the 10x verification on the current dev host. Carried forward.

#### 5. Block-net probe tests on elevated Windows CI runner

**Test:** Verify `windows_run_block_net_blocks_probe_connection` + `windows_run_block_net_blocks_probe_through_cmd_host` pass on a Windows runner with `NONO_CI_HAS_WFP=true` and WFP service installed.
**Expected:** Both tests pass with "connect failed" or "exit code 42" markers in stderr.
**Why human:** Local dev host short-circuits the probe path. Carried forward.

#### 6. Cross-binding (nono-py / nono-ts) D-10 verification of CR-01 FFI remap

**Test:** `grep -rn 'ErrPathNotFound\|errorCode.*-1' ../nono-py/ ../nono-ts/` from a workspace with both sibling repos checked out.
**Expected:** No integer-mapping of `-1` (ErrPathNotFound) as broker-discovery-failure semantics.
**Why human:** Sibling repos not present in this working directory. Carried forward.

## Lesson Reinforced

**Cross-target clippy is load-bearing for the close-gate verifier.** Phase 41 required TWO rounds of gap closure (41-08 BlockerPath + 41-09 cross-target) because the original Phase 41 close-gate verifier accepted Windows-host grep evidence alone for REQ-CI-01 SC#1 + SC#3. The prior verifier honestly documented cross-target Linux clippy as SKIPPED with the load-bearing risk noted — but still flipped REQ-CI-01 to VERIFIED at the codebase level on Windows-host signal. CI run 25972316892 then surfaced 6 dead-code errors that were structurally invisible to Windows-host verification.

**Future close-gate verifiers MUST:** for any plan that touches cfg-gated Unix code paths (i.e. files containing `#[cfg(target_os = "linux"|"macos")]` blocks or files re-exported via Unix-side modules), either (a) run `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings` from the dev host (requires `x86_64-unknown-linux-gnu` toolchain installed via `rustup target add`), or (b) wait for GH Actions Linux Test + Linux Clippy + macOS Clippy lanes to PASS on the head SHA before flipping the related SC to VERIFIED. The Windows-host `cargo check` signal is necessary but not sufficient.

This re-verification respects that lesson: REQ-CI-01 is flipped to VERIFIED only at the **codebase level**, with the live CI signal explicitly preserved as human verification item #1. Status is `human_needed`, not `passed`, because the CI signal is the decisive gate per REQ-CI-01 SC#3.

This lesson generalizes beyond Phase 41 to every future plan touching platform-conditional symbols. It complements memory `feedback_clippy_cross_target` (Phase 25 CR-A regression lesson) by extending the rule from PLAN-time verification to CLOSE-GATE verification.

## Gaps Summary

**No gaps remaining at the codebase level.** Plan 41-09 closed all 6 cross-target findings from CI run 25972316892:

1. `validate_env_var_patterns` orphan + WR-06 — closed by delegate wiring (`profile_runtime.rs` → `exec_strategy::validate_env_var_patterns`)
2. `interactive_shell` field — closed by `cfg_attr(not(target_os = "windows"), allow(dead_code))`
3. 5 `SetupRunner` WFP fields — closed by per-field `#[cfg(target_os = "windows")]`
4. 6 `phase_index` methods — closed by per-method `#[cfg(target_os = "windows")]`
5. `EnvVarGuard::set_all` mirror — closed by module-inner `#![cfg(target_os = "windows")]`
6. `keystore.rs` Apple Passwords `map_err` — closed by one-line swap to `.inspect_err(|_| {...})`

REQ-CI-01 flips from PARTIAL back to VERIFIED at the codebase level. Score: 5/5 truths verified.

Status is `human_needed` (NOT `passed`) because the 6 carried-forward human verification items remain pending live CI signal (the prior 5 + 1 NEW for this plan's specific Linux Test + Linux Clippy + macOS Clippy lane green confirmation). The codebase-level fix is complete; the GH Actions signal is the decisive gate.

---

_Verified: 2026-05-16T21:48:17Z_
_Verifier: Claude (gsd-verifier)_
_Re-verification supersedes: 2026-05-16T20:30:00Z (post-CI-run-25972316892 verification, status: gaps_found, score 4/5)_
_Closure trigger: Plan 41-09 commits 05065209, 389c0fae, e97b596e, 0699c6f4, 47d55905 — 5 commits closing 6 cross-target gaps + WR-06_
