---
plan_id: 48-01
phase: 48
status: awaiting_ci
state: cherry_picks_complete
baseline_sha: 3f638dc6
cherry_picks_landed: 9
cherry_picks_remaining: 0
landed_shas:
  - upstream: c2c6f2caacafb198330d3f0c6c599d85aff49c02
    fork: caab9967
    notes: 3 trivial import-merge conflicts resolved (lib.rs, sandbox/mod.rs, why_runtime.rs); per-commit smoke build PASS
  - upstream: b8a320069b8885a9c99f7f510e8c091342d24623
    fork: a93b2bed
    notes: clean auto-merge
  - upstream: 858ad0096cbd335324095eea758bac694227bc22
    fork: 8a4bb02f
    notes: 6 semantic conflicts resolved (capability_ext.rs Phase-36-01b rename preserved; profile/mod.rs + capability.rs structural blocks)
  - upstream: bbc652a0c31ff863c0fcad6f4ca1bb6922ab03d4
    fork: 605eae2b
    notes: clean auto-merge (CHANGELOG.md + SocketScope enum)
  - upstream: 1e9385a748bc1f8b991f2534dcaf21519be26ef8
    fork: ffac4e89
    notes: supervisor_linux.rs structure preserved (cgroup module outside tests)
  - upstream: 98f8cb182d1ff9b2adfbb8a47d791d4b692160ed
    fork: 08637446
    notes: clean auto-merge (1-line test addition)
  - upstream: d146001ba3d169ffb02100dd687858fe2d51c70a
    fork: 14e5149c
    notes: clean apply on top of ffac4e89
  - upstream: a0222be24e1db32efa2738233fc1e83c33e9dc0e
    fork: b6a88fea
    notes: HIGH complexity; RollbackExitContext struct refactor; T-36-01-CANONICAL extended; Arc/Mutex typing preserved; exec_strategy_windows/mod.rs updated for struct compat
  - upstream: 863bbfd342fe7b5a14a5db91e31f617a7e5d2040
    fork: e7da4998
    notes: let-chain (Rust 2024) converted to nested if-let; CR-01 violation fixed (format!() replaced with const MSG_* byte strings); amended before gate
tasks_completed: [0, 1, 2, 3]
tasks_remaining: [4, 5, 6, 7]
gate_status: PASS (see 48-01-CLOSE-GATE.md)
generated: 2026-05-24
---

# Plan 48-01 — Progress Summary (Session 2 Complete)

## What landed

- All 9 C4 cherry-picks committed on branch `phase-48-01-landlock-v6-af-unix`
- All D-19 trailers present; DCO sign-off on every commit
- `48-01-CLOSE-GATE.md` produced (Task 3) — 8 gates, all PASS
- `cargo build --workspace` clean (zero warnings after cfg fixup folded into cp8)
- `cargo test --workspace` clean (43 suites, 0 failures)
- CR-01 async-signal safety tests all passing (5/5)
- Fork invariants preserved: T-36-01-CANONICAL, Phase-36-01b rename, Arc/Mutex pattern, finalize_supervised_exit location

## Deviations from Plan 48-01

1. **CR-01 violation in cp9's initial commit** — `format!()` in post-fork child block. Caught by
   `resl_nix_async_signal_safety` tests. Fixed by amending cp9. Rule 1 auto-fix.

2. **Rust 2024 let-chain in cp9** — Upstream used edition 2024 syntax. Converted to nested
   if-let in cp9 amendment.

3. **exec_strategy_windows/mod.rs touched by cp8** — Audit predicted 0 Windows files touched.
   Upstream a0222be2 changed `RollbackExitContext` types; Windows call site needed compat update.
   9 lines; no new Windows functionality.

4. **Unused variable warning from cp8** — `supervisor_network_audit_events` lacked cfg gate.
   Added `#[cfg(not(target_os = "windows"))]`; folded into cp8 via fixup+autosquash rebase.

## Tasks remaining (Plan 48-01)

- Task 4 (human-gated): Push to fork's `pre-merge` branch + baseline-aware CI gate vs `3f638dc6`
- Task 5: Open upstream umbrella PR (`gh pr create --repo always-further/nono ...`)
- Task 6: Author `48-01-SUMMARY.md` + `48-01-PR-SECTION.md` + STATE.md update
- Task 7: DCO-signed close-doc commit batching all planning artifacts

## STOP point

Branch is ready for Task 4 (human-initiated push to `pre-merge`).
Cross-target clippy must run in live CI — not available on Windows dev host.
