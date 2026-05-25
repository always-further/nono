---
plan_id: 48-03
phase: 48
artifact: summary
status: shipped
plan_scope: "Plan 48-03 only (Wave 1, Cluster C2). Phase 48 = 9 plans total; this closes 1 of 9."
cluster: C2
cluster_disposition: will-sync
requirement: REQ-UPST6-02 (C2 acceptance criterion #1)
upstream_sha_range: 2bed3565..50272a03
upstream_tag: v0.56.0
upstream_commit_count: 7
fork_side_cleanup_commits: 1
baseline_sha: 3f638dc6
fork_branch: worktree-agent-a80ac1f5bcde7c2bd
wave: 1
depends_on: 48-01
pr_section: 48-03-PR-SECTION.md
lane_transitions: "deferred to live CI (cross-target clippy PARTIAL); test suite: 16 carry-forward failures (all pre-date C2 cherry-picks)"
skipped_gates_environmental: "Gate 7 (Linux cross-toolchain unavailable on macOS dev host), Gate 8 (pre-existing clippy errors in files not touched by C2)"
generated: 2026-05-25
---

# Plan 48-03 — Final Summary (Cluster C2: Startup Timeout + Dead Infrastructure Cleanup)

Cherry-picks the **7-commit Cluster C2** (process startup timeout configuration +
`startup_prompt` dead infrastructure removal) from upstream `always-further/nono`
`v0.56.0` into the fork on the Wave 1 worktree branch off baseline `3f638dc6`.
Runs in parallel with Plan 48-02 (Cluster C1). Satisfies REQ-UPST6-02 acceptance
criterion #1 for C2.

**One-liner:** `--startup-timeout` flag added across run/shell subcommands; SIGTERM→SIGKILL
bug fixed in IPC supervisor loop; `startup_prompt` dead infrastructure removed (193→54-line
refactor); fork-side D-48-D3 cleanup commit precedes `4e0e127a` cherry-pick.

## Fork-side startup_prompt reference inventory (Task 1 pre-flight grep)

Per D-48-D3 mandatory pre-flight, `grep -rn 'startup_prompt' crates/ | grep -v target/`
produced the following before the cleanup commit:

| File | Line | Reference type |
|------|------|----------------|
| `crates/nono-cli/src/main.rs` | 82 | `mod startup_prompt;` (module declaration) |
| `crates/nono-cli/src/exec_strategy.rs` | 22 | `use crate::startup_prompt::{print_terminal_safe_stderr, prompt_startup_termination_for_child};` |
| `crates/nono-cli/src/exec_strategy.rs` | 1862 | `let mut startup_prompted = false;` (site 1) |
| `crates/nono-cli/src/exec_strategy.rs` | 1920–1921 | `!startup_prompted` + `startup_prompted = true;` (site 1 body) |
| `crates/nono-cli/src/exec_strategy.rs` | 1963 | `let mut startup_prompted = false;` (site 2) |
| `crates/nono-cli/src/exec_strategy.rs` | 1969–1970 | `!startup_prompted` + `startup_prompted = true;` (site 2 body) |
| `crates/nono-cli/src/exec_strategy.rs` | 2301 | `let mut startup_prompted = false;` (site 3) |
| `crates/nono-cli/src/exec_strategy.rs` | 2401–2403 | `!startup_prompted` + `startup_prompted = true;` (site 3 body) |
| `crates/nono-cli/src/exec_strategy.rs` | 2490 | `let mut startup_prompted = false;` (site 4) |
| `crates/nono-cli/src/exec_strategy.rs` | 2656–2658 | `!startup_prompted` + `startup_prompted = true;` (site 4 body) |
| `crates/nono-cli/src/exec_strategy.rs` | 3719 | `fn test_configure_startup_prompt_termios_restores_cooked_input` (test name — tests `profile_save_runtime::configure_prompt_termios`, NOT removed) |
| `crates/nono-cli/src/startup_prompt.rs` | entire file | `prompt_startup_termination_for_child`, `StartupPromptTerminalGuard`, etc. |

Zero references found in `exec_strategy_windows/` or `nono-shell-broker/` — D-48-D3 carve-out
for Windows files was NOT needed.

## D-48-D3 cleanup commit shape + rationale (Task 2)

**Fork SHA:** `062b3aa7`
**Subject:** `cleanup(48-03): remove dead startup_prompt references ahead of upstream 4e0e127a absorption`
**Has D-19 trailer:** NO (fork-authored cleanup, not upstream cherry-pick; no upstream author to attribute per D-48-D3)
**Has Co-Authored-By:** NO (same reason)
**Has Signed-off-by DCO:** YES (`Signed-off-by: Oscar Mack Jr <oscar.mack.jr@gmail.com>`)

The cleanup does NOT delete `startup_prompt.rs`. Upstream `4e0e127a` does NOT delete the file
either — it refactors it from 193 to 54 lines, renaming `prompt_startup_termination_for_child`
to `notify_startup_termination_for_child` (return type `bool` → `void`, removes `child: Pid`
param, eliminates `StartupPromptTerminalGuard`, `pause_without_pty`, `prompt_startup_termination`).

Cleanup changes:
- `startup_prompt.rs`: rewrote to match the `4e0e127a` final state (54 lines: `notify_startup_termination_for_child` + `notify_startup_termination` + `print_terminal_safe_stderr`)
- `exec_strategy.rs`: updated import to `notify_startup_termination_for_child`; removed all 4 `startup_prompted` variables; replaced all 4 `prompt_startup_termination_for_child` call sites with `notify_startup_termination_for_child` (no return-value check needed); fixed SIGTERM→SIGKILL in IPC supervisor loop (bug from upstream's comment about the fix in `4e0e127a`)
- `pty_proxy.rs`: removed `resume_terminal_after_prompt` method (dead since no `terminate=false` path exists post-cleanup); updated `pause_terminal_for_prompt` doc comment

After cleanup: `mod startup_prompt;` in `main.rs` is retained (file still exists with new API).

## Cherry-pick manifest (upstream → fork)

| # | Upstream SHA | Fork SHA | Subject | Conflict resolution |
|---|-------------|----------|---------|---------------------|
| D-48-D3 | (fork-authored) | `062b3aa7` | cleanup(48-03): remove dead startup_prompt references | Fork-authored; no trailer |
| 1 | `2bed3565` | `b2d77713` | feat(cli): add option to configure process startup timeout | 4 files conflicted: launch_runtime (kept resource_limits + added startup_timeout_secs), command_runtime (kept Windows cfg path + added startup_timeout_secs to run_shell), execution_runtime (removed startup_timeout_profile heuristic; added explicit secs→Duration wiring; updated tests), exec_strategy (let-chain→nested if-let) |
| 2 | `a8646d26` | `153ed870` | feat(cli): expand startup timeout interactive detection | 1 file conflicted: docs/cli/usage/flags.mdx (kept both --no-auto-pull and --startup-timeout rows) |
| 3 | `8628fd6d` | `85e0ce44` | refactor(cli): require alt-screen for startup timeout | Auto-merged cleanly |
| 4 | `468d3813` | `17ae8901` | docs(cli): clarify startup timeout definition of interactive | Auto-merged cleanly |
| 5 | `4e0e127a` | `8b4f3341` | fix(startup): use SIGKILL consistently and remove dead prompt infrastructure | 2 files conflicted: exec_strategy (kept rollback_runtime import + cfg(windows) gated imports; let-chain→nested if-let), pty_proxy (auto-merged) |
| 6 | `1be97978` | `31ed52c3` | refactor(cli-exec-strategy): simplify startup timeout checks | Empty commit: upstream uses let-chain (Ed.2024); nested if-let form already present |
| 7 | `50272a03` | `5a434d3d` | refactor(cli): simplify startup timeout check | Empty commit: same — let-chain→nested if-let already present |

## Cross-target clippy results

| Target | Result | Notes |
|--------|--------|-------|
| macOS (x86_64-apple-darwin) | PARTIAL | 8 pre-existing errors from commit `2823ec29` (May 10); zero errors in files touched by C2 |
| Linux (x86_64-unknown-linux-gnu) | PARTIAL | Cross-toolchain not installed on macOS dev host |

Per CLAUDE.md: "If the cross-toolchain is not installed, the related verification REQ MUST be
marked PARTIAL and deferred to live CI." Both partial; deferred to Task 5 (push to pre-merge).

## Build and test summary

- `cargo build --workspace`: PASS (zero errors; 3 pre-existing warnings unrelated to C2)
- `cargo test --workspace`: 1070 passed / 16 failed
  - 16 failures: all pre-date C2 cherry-picks (macOS platform limitations, Wave-0 protected_paths regression from Plan 48-01, parallel env flakiness)
  - `cargo test -p nono-cli --test resl_nix_async_signal_safety`: 5/5 PASS (CR-01 invariant intact)

## Baseline-aware CI verdict

Deferred to live CI (Task 5). Baseline is `3f638dc6`. Zero green→red lane transitions permitted.
Pre-existing red lanes documented in Plan 48-01 SUMMARY (macOS Clippy/Test, Rustfmt, Cargo Audit,
Docs Checks, Integration) carry forward.

## Wave 1 sibling status

Plan 48-02 (Cluster C1) runs in parallel on a separate worktree branch. Surface-disjoint:
C2 touches `cli.rs` / `exec_strategy.rs` / `startup_prompt.rs` / `pty_proxy.rs` / `output.rs` /
`launch_runtime.rs` / `command_runtime.rs`. C1 touches the profile shadowing surface. No
shared files.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Spurious `ignored_denial_paths` field in ExecConfig construction**
- **Found during:** C2-01 (2bed3565) conflict resolution
- **Issue:** `ignored_denial_paths: &flags.ignored_denial_paths` added to `ExecConfig { ... }` during manual conflict merge; `ExecConfig` struct has no such field
- **Fix:** Removed the spurious line; build error `E0560` caught it immediately
- **Files modified:** `crates/nono-cli/src/execution_runtime.rs`

**2. [Rule 1 - Bug] Rust 2024 let-chain syntax incompatible with Edition 2021**
- **Found during:** C2-01, C2-05, C2-06, C2-07 cherry-picks
- **Issue:** Upstream uses `if let Some(x) = foo && condition { }` (Edition 2024 feature); fork targets Edition 2021
- **Fix:** Converted all 4 occurrences to nested `if let { if condition { } }` form; C2-06 + C2-07 were empty commits since nested form was already present
- **Files modified:** `crates/nono-cli/src/exec_strategy.rs`

**3. [Rule 2 - Missing functionality] SIGTERM→SIGKILL bug in IPC supervisor loop**
- **Found during:** D-48-D3 cleanup (pre-flight of 4e0e127a)
- **Issue:** IPC supervisor loop used SIGTERM on startup timeout; all other paths (PTY, no-PTY, macOS supervisor) use SIGKILL; upstream 4e0e127a's commit message explicitly states this as a bug fix
- **Fix:** Changed `Signal::SIGTERM` → `Signal::SIGKILL` in the IPC supervisor loop during D-48-D3 cleanup
- **Files modified:** `crates/nono-cli/src/exec_strategy.rs`

### D-48-D3 Scope Refinement

The plan stated "remove all startup_prompt references." Upstream `4e0e127a` does NOT delete
`startup_prompt.rs` — it refactors it from 193→54 lines. Cleanup commit matches actual upstream
intent: retain the file with the new `notify_startup_termination_for_child` API.
`mod startup_prompt;` in `main.rs` is retained. This is not a deviation from D-48-D3's spirit —
the pre-flight cleanup enabled `4e0e127a` to cherry-pick cleanly, which was the goal.

## Decisions Made

- D-48-D3 cleanup precedes 4e0e127a (mandatory per plan); cleanup commit carries NO D-19 trailer + NO Co-Authored-By (fork-authored, no upstream author to attribute)
- Edition 2021 let-chain incompatibility treated as Rule 1 auto-fix (4 occurrences)
- SIGTERM→SIGKILL treated as Rule 2 missing-correctness fix (applied in cleanup commit)
- Empty commits used for C2-06 + C2-07 to preserve upstream attribution metadata while acknowledging net-zero code change on Edition 2021

## Known Stubs

None. All upstream functionality is wired:
- `--startup-timeout` flag: wired in RunArgs + ShellArgs (removed from WrapArgs per C2-02)
- `notify_startup_termination_for_child`: wired in all 4 timeout sites in exec_strategy.rs
- PTY interactive detection: wired in pty_proxy.rs (alt-screen + visible output heuristics)

## Threat Flags

No new network endpoints, auth paths, file access patterns, or schema changes introduced.
C2 is purely a CLI UX feature (timeout flag) + dead code removal. No threat surface expansion.
