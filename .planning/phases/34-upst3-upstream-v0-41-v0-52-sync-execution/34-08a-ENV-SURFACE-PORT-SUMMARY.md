---
phase: 34-upst3-upstream-v0-41-v0-52-sync-execution
plan_number: 34-08a
plan: 08a
slug: env-surface-port
cluster_id: C12-env-surface
parent_plan: 34-08 (archived)
type: execute
status: complete
outcome: success
wave: 2
subsystem: env-sanitization
tags: [upst3, c12-env-surface, env-sanitization, deny-vars, fork-preserve, manual-replay, d-20, wave-2, split-from-34-08]
requirements: [C12-env-surface]
metrics:
  duration_minutes: ~120
  completed_date: 2026-05-12
  commits_landed: 5
  upstream_commit_trailers: 4
  manual_replay_trailers: 1
  signed_off_by_lines: 10
  windows_file_touches: 0
  learn_windows_sha_pre: aa4d33dc801b631883ba9c5fc7917e0e194342a4
  learn_windows_sha_post: aa4d33dc801b631883ba9c5fc7917e0e194342a4
  workspace_lib_tests: 857
  env_sanitization_tests: 29
  profile_tests: 199
  profile_runtime_tests: 2
dependency_graph:
  requires:
    - 34-04
    - 34-04b (canonical-schema baseline)
    - 34-01
    - 34-02
    - 34-05
    - 34-07
  provides:
    - EnvironmentConfig struct + Profile.environment field (v0.37.0 1b412a7 surface)
    - is_env_var_allowed + is_env_var_denied + validate_env_var_patterns helpers
    - deny_vars feature (v0.52.0 3657c935; operator-controlled denylist)
    - empty-allow fail-closed security invariant (v0.52.0 780965d7)
    - matches_env_var_patterns shared helper (v0.52.0 a022e5c7 refactor)
    - PreparedSandbox + ExecutionFlags + ExecConfig env-filter plumbing (Unix path)
  blocks:
    - 34-08b (non-env subset of cluster C12; unblocked by this close)
tech_stack:
  added: [EnvironmentConfig, EnvironmentConfig.allow_vars, EnvironmentConfig.deny_vars, is_env_var_allowed, is_env_var_denied, validate_env_var_patterns, matches_env_var_patterns, ExecConfig.allowed_env_vars, ExecConfig.denied_env_vars]
  patterns: [D-20 manual-replay, D-19 cherry-pick trailer, fork-preserve-manual-replay-split, env-filter-precedence (dangerous > deny > allow), fail-closed-on-empty-allow]
key_files:
  created: []
  modified:
    - crates/nono-cli/src/profile/mod.rs (EnvironmentConfig + merge + 8 new tests)
    - crates/nono-cli/src/exec_strategy/env_sanitization.rs (is_env_var_allowed + is_env_var_denied + matches_env_var_patterns + validate_env_var_patterns + 19 new tests)
    - crates/nono-cli/src/exec_strategy.rs (ExecConfig.allowed_env_vars + .denied_env_vars + filter wiring in execute_direct + execute_supervised)
    - crates/nono-cli/src/profile_runtime.rs (PreparedProfile.allowed_env_vars + .denied_env_vars + validate_env_var_patterns_local + 2 new regression tests)
    - crates/nono-cli/src/sandbox_prepare.rs (PreparedSandbox.allowed_env_vars + .denied_env_vars plumbing)
    - crates/nono-cli/src/launch_runtime.rs (ExecutionFlags.allowed_env_vars + .denied_env_vars)
    - crates/nono-cli/src/command_runtime.rs (run_shell + run_wrap ExecutionFlags wiring)
    - crates/nono-cli/src/execution_runtime.rs (ExecConfig construction wiring on non-Windows)
    - crates/nono-cli/src/main.rs (PreparedSandbox test fixtures)
    - crates/nono-cli/src/policy.rs (ProfileDef::to_raw_profile environment: None)
decisions:
  - D-34-08a-DEFERRAL-01 - Closed Phase 20-03 b4762e63 partial-port deferral via D-20 manual replay of v0.37.0 1b412a7 base (EnvironmentConfig + helpers + 6+ runtime call-sites)
  - D-34-08a-SPLIT-01 - Confirmed 34-08 -> 34-08a + 34-08b mid-plan split (Phase 22-05a/22-05b + 34-04/34-04b precedent within Phase 34); env-touching subset (5 artifacts) landed here; non-env subset (5 commits) deferred to 34-08b
  - D-34-08a-FORK-01 - All fork-defense baselines preserved at or above pre-plan values (capabilities.aipc/loaded_profile 17, ProfileDeserialize 4, bypass_protection 17, never_grant+apply_deny_overrides 21, validate_path_within 9, find_denied_user_grants 7, Phase 20-03 cli.rs env-surface 60)
  - D-34-08a-CHERRY-PICK-ESCALATION - 3657c935 disposition escalated from straight cherry-pick to D-20 manual-replay-by-escalation per Plan 34-08a Task 4 Step 2b rule (10 conflicting files; well above D-02 >2-file threshold). 780965d7 + a022e5c7 + 31f2fc27 also applied by hand because fork's local validate_env_var_patterns_local copy + denied_env_vars presence + CLAUDE.md no-unwrap policy diverge from upstream. All 4 commits carry the D-19 Upstream-commit: trailer per plan acceptance criteria; bodies document the escalation.
  - D-34-08a-WINDOWS-DEFER - Windows execution path (exec_strategy_windows/) env-filter wiring NOT included in this plan (P34-DEFER-08a-1). ExecConfig in exec_strategy_windows/mod.rs is unchanged. Linux/macOS gets full env-filter; Windows retains existing should_skip_env_var-only behaviour. Justification: D-34-E1 invariant (no *_windows.rs / exec_strategy_windows/ touches); Windows env-filter parity tracked for a future plan.
---

# Phase 34 Plan 08a: C12-env-surface Manual Replay (v0.37.0) + 4 v0.52.0 Cherry-Picks Summary

## One-liner

D-20 manual replay of v0.37.0 env-filter surface (Phase 20-03 deferral closure) + 4 v0.52.0 env-touching cherry-picks (deny_vars + empty-allow fail-closed + refactor + clippy-lint fix) — 5 commits landed on main; env-filter surface now at v0.52.0 parity on Linux/macOS; Windows wiring deferred (P34-DEFER-08a-1).

## Outcome

Plan 34-08a closes the env-touching subset of cluster C12 (v0.52.0). The archived parent plan 34-08 attempted all 10 v0.52.0 C12 commits as a single autonomous cherry-pick chain and hit a wall at commit 1/10 (`3657c935`) because the fork had only a PARTIAL Phase 20-03 env-filter surface port — CLI flag-parsing landed in Phase 20-03 (`b4762e63`) but `EnvironmentConfig` + runtime wiring + `env_sanitization.rs` helpers were deferred.

34-08a lands:

1. **D-20 manual replay** of upstream `1b412a7` v0.37.0 — the deferred env-filter surface base (`EnvironmentConfig` struct, `Profile.environment` + `ProfileDeserialize.environment` fields, `is_env_var_allowed` + `validate_env_var_patterns` helpers, runtime call-site wiring across command_runtime, execution_runtime, launch_runtime, profile_runtime, sandbox_prepare, exec_strategy).
2. **D-19 → D-20 manual-replay-by-escalation** of `3657c935` v0.52.0 — operator-controlled `deny_vars` feature with deny-wins-over-allow precedence (security-critical).
3. **D-19** (applied by hand due to fork shape) of `780965d7` v0.52.0 — empty-allow fail-closed security regression fix; locked down with two new regression tests in `profile_runtime::tests`.
4. **D-19** (applied by hand) of `a022e5c7` v0.52.0 — refactor: extract `matches_env_var_patterns` shared helper.
5. **D-19** (applied by hand) of `31f2fc27` v0.52.0 — clippy lint fix: replace `unwrap()` with `is_some_and()` in a test (test-only).

34-08b (the non-env cluster C12 subset: 5 commits — `1d491b4d` macOS learn, `b5f0a3ab` interactive, `b34c2af6` learn deprecation, `bbdf7b85` escaped quotes, `5d15b50e` release v0.52.0) is **UNBLOCKED** and can proceed.

## Pre-Plan-34-08a HEAD

`9d1bf137167c2bdebe85af51af02c70174a4d360` (post-split-commit, 2026-05-12 baseline)

## Plan-34-08a HEAD

`e9ce06a1ae5dadb9a1d218054253c21bb43a7b62`

## Commits Table

| # | Upstream SHA | Upstream Tag | Disposition | Landed Fork SHA | Trailer Type | Notes |
|---|--------------|--------------|-------------|-----------------|--------------|-------|
| 1 | `1b412a7` | v0.37.0 | D-20 manual replay | `fd73700e` | Manual-replay: | EnvironmentConfig + helpers + 6+ runtime call-sites (Phase 20-03 deferral closed) |
| 2 | `3657c935` | v0.52.0 | D-20 manual-replay-by-escalation | `9ec9365b` | Upstream-commit: | deny_vars feature; cherry-pick produced 10-file conflict, escalated per Task 4 Step 2b |
| 3 | `780965d7` | v0.52.0 | hand-applied (D-19 trailer) | `1676fe24` | Upstream-commit: | empty-allow fail-closed regression fix; 2 new regression tests added |
| 4 | `a022e5c7` | v0.52.0 | hand-applied (D-19 trailer) | `a80e6344` | Upstream-commit: | refactor: extract matches_env_var_patterns helper; docs/cli/features/environment.mdx skipped (fork doesn't carry that doc) |
| 5 | `31f2fc27` | v0.52.0 | hand-applied (D-19 trailer) | `e9ce06a1` | Upstream-commit: | clippy lint fix (unwrap -> is_some_and) in test |

NOTE on commit 5 misidentification: The plan body and orchestrator-prompt disposition table labeled `31f2fc27` as "chore: release v0.52.0 — CHANGELOG only, Cargo bumps dropped". The actual upstream commit is `fix(lint): replace unwrap() with is_some_and() in test` — a 6-line test-only clippy fix with no Cargo.toml/Cargo.lock changes. Treated as a straight (hand-applied) cherry-pick per Task 7 with no version-bump-dropping required. Disposition file `/tmp/34-08a-disposition.txt` documents this discovery.

## Verification

| Gate | Result | Evidence |
|------|--------|----------|
| Gate 1: `cargo test --workspace --lib` (Windows host) | PASS | 670 + 39 + 148 = 857 tests pass. Known carry-forward flake: `supervisor::aipc_sdk` parallel-execution env-var race (P34-DEFER-01-1); passes cleanly with `--test-threads=1`. |
| Gate 2: Windows clippy `-D warnings -D clippy::unwrap_used` | PASS | exit 0 |
| Gate 3: Linux cross-target clippy | DOCUMENTED-SKIPPED | deferred to CI per dev-host limitation (user accepted same posture at 34-04 + 34-04b close) |
| Gate 4: macOS cross-target clippy | DOCUMENTED-SKIPPED | deferred to CI per dev-host limitation (user accepted same posture at 34-04 + 34-04b close) |
| Gate 5: `cargo fmt --all -- --check` | PASS | exit 0 |
| Gate 6: Phase 15 5-row detached-console smoke | DOCUMENTED-SKIPPED | requires admin-elevated session; not exercised on dev host |
| Gate 7: `wfp_port_integration --ignored` | DOCUMENTED-SKIPPED | requires admin + nono-wfp-service installed; not exercised on dev host |
| Gate 8: `learn_windows_integration` | DOCUMENTED-SKIPPED | requires elevated session + ETW provider; not exercised on dev host. **NOTE:** 34-08a does NOT touch the learn deprecation commit `b34c2af6` (that ships in 34-08b); learn_windows.rs SHA UNCHANGED across 34-08a chain (D-34-B2 invariant). |

## D-34-E1 Windows-only File Invariant

**PASS** — 0 hits on `*_windows.rs` / `exec_strategy_windows/` across all 5 commits, individually AND across the chain.

Per-commit check across the 34-08a range:

```bash
for sha in $(git log --format='%H' 9d1bf137..e9ce06a1); do
  git diff --stat $sha^..$sha -- crates/ | grep -v '^#' | grep -cE '_windows|exec_strategy_windows'
done
# All zero.
```

## D-34-B2 learn_windows.rs Byte-Identity

**PASS** — `learn_windows.rs` SHA `aa4d33dc801b631883ba9c5fc7917e0e194342a4` UNCHANGED across the entire 34-08a chain.

## Fork-Defense Invariants Final Sentinels

| Surface | File | Baseline | Final | Status |
|---------|------|----------|-------|--------|
| Plan 18.1-03 `capabilities.aipc` / `loaded_profile` | profile/mod.rs | 17 | 17 | PASS |
| Phase 22-01 `ProfileDeserialize` | profile/mod.rs | 1+ | 4 | PASS |
| Plan 34-04b `bypass_protection` canonical-schema | profile/mod.rs | 1+ | 17 | PASS |
| Phase 19 v2.1 `never_grant` / `apply_deny_overrides` | policy.rs | 21 | 21 | PASS |
| Phase 22-03 PKG-04 `validate_path_within` | package_cmd.rs | 9 | 9 | PASS |
| 34-04 `find_denied_user_grants` helper | policy.rs | 1+ | 7 | PASS |
| Phase 20-03 cli.rs env-surface | cli.rs | 4+ | 60 | PASS |

## NEW Surface Sentinels

| Item | File | Required | Actual | Status |
|------|------|----------|--------|--------|
| EnvironmentConfig + environment field | profile/mod.rs | >= 3 | 10 | PASS |
| is_env_var_allowed + validate_env_var_patterns | env_sanitization.rs | >= 2 | 30+ | PASS |
| deny_vars | env_sanitization.rs | >= 1 | 5 | PASS |
| deny_vars | profile/mod.rs | >= 1 | 20 | PASS |
| Empty-allow fail-closed regression test | profile_runtime.rs | >= 1 | 1 (`empty_allow_vars_fails_closed`) | PASS |
| deny_vars precedence regression test | env_sanitization.rs | >= 1 | 1 (`test_env_var_denied_overrides_allowed`) | PASS |

## Deviations from Plan

### Auto-fixed Issues (Rule 1-3)

**1. [Rule 3 - Blocking] `31f2fc27` misidentified as v0.52.0 release commit**
- **Found during:** Task 1 (after upstream-meta capture)
- **Issue:** Plan body + orchestrator prompt disposition table labeled `31f2fc27` as "chore: release v0.52.0; drop Cargo.toml + Cargo.lock version-bumps". Actual upstream commit is `fix(lint): replace unwrap() with is_some_and() in test` (6-line test refactor).
- **Fix:** Task 7 applied the actual commit's intent. No Cargo version bumps to drop because upstream commit has none. Documented in `/tmp/34-08a-disposition.txt` and Commits table NOTE.
- **Files modified:** /tmp/34-08a-disposition.txt + Task 7 commit body
- **Commit:** `e9ce06a1`

**2. [Rule 3 - Blocking] `3657c935` cherry-pick escalated to D-20 manual-replay**
- **Found during:** Task 4 (cherry-pick attempt)
- **Issue:** `git cherry-pick 3657c935` produced 10 conflicting files (well above D-02 threshold of >2 files) because fork's Task 3 manual-replay base diverges from upstream's profile/mod.rs + 6+ runtime-call-site shape.
- **Fix:** Aborted cherry-pick; applied upstream's intent by hand against the fork's Task 3 base. Per Plan 34-08a Task 4 Step 2b escalation rule and the orchestrator prompt's "≥10 conflicted files OR ≥3K-line delta escalates to D-20 manual replay" rule.
- **Files modified:** 9 files (matches upstream's file inventory)
- **Commit:** `9ec9365b` (D-19 `Upstream-commit:` trailer retained per plan acceptance criteria; body documents the escalation explicitly)

**3. [Rule 1 - Bug] Task 3 commit body false-positive on plan-close smoke grep**
- **Found during:** Task 3 per-commit verification
- **Issue:** Commit body contained prose "Upstream-commit: per the convention." which `grep -c '^Upstream-commit: '` would count as a 5th `Upstream-commit:` trailer at plan close (the plan-close smoke check expects exactly 4).
- **Fix:** Amended Task 3 commit body to phrase the same idea without a `^Upstream-commit: ` prose line.
- **Files modified:** None (commit body only)
- **Commit:** `fd73700e` (amend of `e96c4188`)

**4. [Rule 3 - Blocking] Windows-side `validate_allow_vars_pattern` re-export missing**
- **Found during:** Task 3 build
- **Issue:** Adding `pub(crate) use env_sanitization::validate_allow_vars_pattern;` to `exec_strategy.rs` resolves only on Linux/macOS because `crate::exec_strategy` is rewired to `exec_strategy_windows/mod.rs` on Windows. The Windows mod.rs has its own `mod env_sanitization;` (private) — no equivalent re-export.
- **Fix:** Avoided crossing the D-34-E1 invariant boundary by duplicating the small `validate_env_var_patterns` function (12 lines) inline in `profile_runtime.rs` as `validate_env_var_patterns_local`. Two copies kept in lock-step via tests in `env_sanitization.rs`. Documented in Task 3 commit body + tracked as a deferral if Windows env-filter wiring is ever needed.
- **Files modified:** crates/nono-cli/src/profile_runtime.rs (Task 3 + Task 4 evolution)
- **Commit:** `fd73700e` (Task 3) + `9ec9365b` (Task 4)

### Deferred Items

**P34-DEFER-08a-1: Windows env-filter wiring**
- **Description:** ExecConfig in `exec_strategy_windows/mod.rs` is unchanged; the new `allowed_env_vars` / `denied_env_vars` fields are wired only into the Unix `ExecConfig` in `exec_strategy.rs`. `ExecutionFlags.allowed_env_vars` / `.denied_env_vars` are forwarded cross-platform but the Windows execution path doesn't consume them yet (`#[cfg_attr(target_os = "windows", allow(dead_code))]`).
- **Justification:** D-34-E1 invariant strictly forbids touching `*_windows.rs` / `exec_strategy_windows/` files in this plan. Linux/macOS get full env-filter; Windows retains the existing `should_skip_env_var`-only behaviour (the same posture as before this plan).
- **Tracker:** Add to `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md` (or analogue) if/when Windows env-filter parity becomes required.

## Known Stubs

None.

## Authentication Gates

None.

## Self-Check: PASSED

**Files verified exist:**
- crates/nono-cli/src/profile/mod.rs (modified): present
- crates/nono-cli/src/exec_strategy/env_sanitization.rs (modified): present
- crates/nono-cli/src/exec_strategy.rs (modified): present
- crates/nono-cli/src/profile_runtime.rs (modified): present
- crates/nono-cli/src/sandbox_prepare.rs (modified): present
- crates/nono-cli/src/launch_runtime.rs (modified): present
- crates/nono-cli/src/command_runtime.rs (modified): present
- crates/nono-cli/src/execution_runtime.rs (modified): present
- crates/nono-cli/src/main.rs (modified): present
- crates/nono-cli/src/policy.rs (modified): present

**Commits verified in git log:**
- fd73700e (Task 3, Manual-replay: 1b412a7): present
- 9ec9365b (Task 4, Upstream-commit: 3657c935): present
- 1676fe24 (Task 5, Upstream-commit: 780965d7): present
- a80e6344 (Task 6, Upstream-commit: a022e5c7): present
- e9ce06a1 (Task 7, Upstream-commit: 31f2fc27): present

**Invariants verified:**
- D-34-E1: 0 Windows-file hits across all 5 commits — PASS
- D-34-B2: learn_windows.rs SHA `aa4d33dc801b631883ba9c5fc7917e0e194342a4` UNCHANGED — PASS
- Plan-close smoke: 4 Upstream-commit + 1 Manual-replay + 0 Upstream-Author + 10 Signed-off-by — PASS
- Fork-defense baselines: all at or above pre-plan values — PASS

**Split-precedent cited correctly:**
- Phase 22-05a/22-05b (AUD-CORE + AUD-RENAME split) — referenced
- Phase 34-04/34-04b (PATH-CANON-SCHEMA + FP-CANONICAL-SCHEMA split, within Phase 34) — referenced
- Plan 34-08 archived parent (`34-08-ENV-DENY-PLAN.archive.md`) — referenced

## Next Steps

- **34-08b (sibling plan)**: UNBLOCKED. 5 non-env-touching v0.52.0 cluster-C12 commits: `1d491b4d` (style: cargo fmt), `b5f0a3ab` (feat(cli): enhance macos learn and run diagnostics), `b34c2af6` (feat(cli): deprecate `nono learn`), `bbdf7b85` (fix(diagnostic): escaped quotes), `5d15b50e` (chore: release v0.52.0 — CHANGELOG entry, Cargo bumps to be dropped per partial-cherry-pick precedent). `b34c2af6` is the D-34-B2 surgical-posture commit; 34-08b assumes responsibility for learn_windows.rs byte-identity invariant on the ETW path.
- **34-09 / 34-10 (Wave 3 manual replays)**: on track.
- **P34-DEFER-08a-1**: Windows env-filter wiring deferred; track if needed.
