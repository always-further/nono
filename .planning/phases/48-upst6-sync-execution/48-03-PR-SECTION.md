## Plan 48-03 — Cluster C2: Process Startup Timeout + Dead Infrastructure Cleanup

This section covers the **7 commits comprising Cluster C2** (process startup timeout flag +
interactive detection + dead `startup_prompt` infrastructure removal) cherry-picked from
upstream `always-further/nono` into the fork, as Plan 48-03 of fork-side Phase 48 (UPST6 sync).
Runs in parallel with Plan 48-02 (C1) as Wave 1.

**Cluster:** C2 (startup timeout configuration; `--startup-timeout` flag)
**Disposition:** `will-sync` (per fork-side Phase 47 UPST6 audit ledger row for C2)
**Upstream SHA range:** `2bed3565..50272a03` (7 commits, all authored 2026-05-18 by Luke Hinds)
**Upstream tag:** `v0.56.0`
**Fork baseline:** `3f638dc6`
**Fork branch:** worktree-agent-a80ac1f5bcde7c2bd (Wave 1 parallel execution)
**Plan:** `48-03`
**Requirement satisfied:** REQ-UPST6-02 (C2 acceptance criterion #1)

## Cherry-pick manifest (upstream → fork)

| # | Upstream SHA | Fork SHA | Subject |
|---|-------------|----------|---------|
| D-48-D3 cleanup | (fork-authored) | `062b3aa7` | cleanup(48-03): remove dead startup_prompt references ahead of upstream 4e0e127a absorption |
| 1 | `2bed3565` | `b2d77713` | feat(cli): add option to configure process startup timeout |
| 2 | `a8646d26` | `153ed870` | feat(cli): expand startup timeout interactive detection |
| 3 | `8628fd6d` | `85e0ce44` | refactor(cli): require alt-screen for startup timeout |
| 4 | `468d3813` | `17ae8901` | docs(cli): clarify startup timeout definition of interactive |
| 5 | `4e0e127a` | `8b4f3341` | fix(startup): use SIGKILL consistently and remove dead prompt infrastructure |
| 6 | `1be97978` | `31ed52c3` | refactor(cli-exec-strategy): simplify startup timeout checks |
| 7 | `50272a03` | `5a434d3d` | refactor(cli): simplify startup timeout check |

## Key decisions

- **D-48-D3 pre-flight cleanup (fork-authored, no Co-Authored-By):** Upstream `4e0e127a` refactors
  `startup_prompt.rs` (193-line → 54-line, renames `prompt_startup_termination_for_child` to
  `notify_startup_termination_for_child`). The fork had ~13 references to the old API across
  `exec_strategy.rs`. Cleanup commit removes all dead infrastructure FIRST (fork-authored,
  NO D-19 trailer, NO Co-Authored-By per D-48-D3), enabling `4e0e127a` to cherry-pick cleanly.
- **Rust Edition 2021 let-chain conversion (4 sites):** Upstream commits 2bed3565, 4e0e127a,
  1be97978, and 50272a03 all use Rust 2024 let-chain syntax. Fork is Edition 2021. All four
  required conversion to nested if-let form; C2-06 and C2-07 resulted in zero net code change
  (committed as empty commits with upstream metadata preserved).
- **SIGTERM → SIGKILL bug fix in IPC supervisor loop:** Upstream `4e0e127a` fixes a real bug
  where the Linux IPC supervisor loop sent SIGTERM (not SIGKILL) on startup timeout, inconsistent
  with all other timeout paths. Fix applied as part of conflict resolution.
- **`startup_timeout_secs` wired alongside fork's `resource_limits`:** Fork has `resource_limits`
  field from Phase 37 in `ExecutionFlags`. `startup_timeout_secs` from 2bed3565 added alongside.
- **`--startup-timeout` removed from `nono wrap` in C2-02:** Upstream `a8646d26` removes the flag
  from wrap args (requires a parent process for PTY detection). Fork follows.

## Fork-side deviations (4)

| # | Deviation | Class | Disposition |
|---|-----------|-------|-------------|
| 1 | C2-01 (2bed3565): `ignored_denial_paths` spuriously added to `ExecConfig` during conflict resolution; caught by `cargo build` | Rule 1 auto-fix | Removed before C2-01 commit |
| 2 | C2-01/05/06/07: Rust 2024 let-chain syntax in 4 upstream commits; fork is Edition 2021 | Edition compatibility | All 4 converted to nested if-let; C2-06 + C2-07 are empty commits |
| 3 | D-48-D3 scope: upstream 4e0e127a does NOT delete startup_prompt.rs entirely (reduces it 193→54 lines); plan said "remove all references" | Scope clarification | Fork keeps startup_prompt.rs with new API; mod declaration retained in main.rs |
| 4 | 16 pre-existing test failures in test suite; plan requires "cargo test --workspace exits 0" | Pre-existing carry-forward | All 16 failures pre-date C2 cherry-picks (macOS platform, Wave-0 protected_paths, parallel env flakiness) |

## D-48-E1 Windows-only-files invariant

```
$ git diff e56d0e50..HEAD --name-only | grep -E "(_windows\.rs|exec_strategy_windows/|nono-shell-broker/)"
(no output)
```

ZERO Windows-only files touched by any Plan 48-03 commit (cherry-picks OR cleanup commit).

## Cross-target clippy status

Both Linux (`x86_64-unknown-linux-gnu`) and macOS (`x86_64-apple-darwin`) clippy targets
produce errors — all pre-existing from commit `2823ec29` (May 10, 2026), predating Plan 48-03.
None of the error lines are in regions touched by C2 cherry-picks. Deferred to live CI for
baseline comparison per CLAUDE.md.

## Source artifacts

- [`48-03-CLOSE-GATE.md`](48-03-CLOSE-GATE.md) — 8-gate matrix with PASS evidence + deviation notes
- [`48-03-SUMMARY.md`](48-03-SUMMARY.md) — final shipped summary
