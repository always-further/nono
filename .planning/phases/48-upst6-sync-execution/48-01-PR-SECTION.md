## Summary

This PR cherry-picks the **9 commits comprising Cluster C4** (Landlock v6 signal scoping +
abstract / pathname af_unix socket mediation) from upstream `always-further/nono` into the
`oscarmackjr-twg/nono` fork, as the sole execution plan of fork-side Phase 48 (UPST6 sync).
Cherry-picks land in upstream-chronological author-date order on top of fork baseline
`3f638dc6`, with verbatim 6-line `Upstream-*` D-19 attribution trailers on every commit and
DCO sign-off (`Signed-off-by: Oscar Mack Jr <oscar.mack.jr@gmail.com>`).

**Cluster:** C4 (Landlock v6 signal/socket scoping + af_unix pathname mediation)
**Disposition:** `will-sync` (per fork-side Phase 47 UPST6 audit ledger row for C4)
**Upstream SHA range:** `c2c6f2ca..863bbfd3` (9 commits, all authored 2026-05-13 by Luke Hinds)
**Upstream tag:** `v0.55.0` (first tag containing the entire C4 chain)
**Fork baseline:** `3f638dc6`
**Fork branch:** `oscarmackjr-twg:pre-merge` (from `phase-48-01-landlock-v6-af-unix`)
**Plan:** [`48-01`](../tree/main/.planning/phases/48-upst6-sync-execution) — sole plan in Phase 48
**Requirement satisfied:** REQ-UPST6-02 (UPST6 sync execution)

## Cherry-pick manifest (upstream → fork)

| # | Upstream SHA | Fork SHA | Subject |
|---|-------------|----------|---------|
| 1 | `c2c6f2ca` | `caab9967` | feat(landlock): add landlock v6 signal and abstract unix socket scoping |
| 2 | `b8a32006` | `a93b2bed` | docs(capability): clarify linux signal mode behavior with landlock |
| 3 | `858ad009` | `8a4bb02f` | feat(cli): add recursive unix socket directory grants |
| 4 | `bbc652a0` | `605eae2b` | feat(unix-socket): record explicit scope for grants |
| 5 | `1e9385a7` | `ffac4e89` | feat(sandbox): add explicit allowlist for pathname af_unix sockets |
| 6 | `98f8cb18` | `08637446` | test(supervisor-linux): add unix listener for connect capability test |
| 7 | `d146001b` | `14e5149c` | fix(sandbox): correctly resolve af_unix socket paths for seccomp |
| 8 | `a0222be2` | `b6a88fea` | feat(linux): implement af_unix pathname mediation |
| 9 | `863bbfd3` | `e7da4998` | refactor(supervisor): refine ipc denial reporting and audit timestamps |

## Key decisions

- **Chronological order (upstream author-date)** per D-48-B1 + Claude's Discretion bullet —
  matches Phase 47 ledger row order for C4; no reordering required.
- **Preserve fork's `#[cfg(target_os = "linux")]` gate at `lib.rs:88-89`** — new Landlock items
  (`LandlockScopePolicy`, `landlock_scope_policy`, `landlock_scope_policy_with_abi`) merged
  into the existing gated `pub use sandbox::{...}` block so Linux-only types do not leak into
  the cross-platform re-export surface and the Windows build stays green.
- **T-36-01-CANONICAL extended in-place in cp8** — upstream `a0222be2` introduces
  `pub linux: LinuxConfig` on the parent profile struct; the fork's exhaustive
  `impl From<ProfileDeserialize> for Profile` match was extended in the same cherry-pick body
  per D-19 fidelity (compile-time enforcement via `cargo build -p nono-cli`).
- **CR-01 async-signal safety preserved** — post-fork child branch in `exec_strategy.rs`
  remains `format!()`-free; cp9 violations replaced with static `const MSG_*: &[u8]` byte
  strings written via `libc::write(STDERR_FILENO, ...)` (pattern enforced by
  `resl_nix_async_signal_safety` test suite).

## Fork-side deviations (4)

| # | Deviation | Class | Disposition |
|---|-----------|-------|-------------|
| 1 | cp9 introduced two `format!()` calls in post-fork child branch (CR-01 violation; caught by `resl_nix_async_signal_safety` tests `cr_01_no_format_macro_in_post_fork_child_branch` + `cr_01_and_wr_02_const_msg_byte_strings_present`) | Rule 1 auto-fix | cp9 amended in-place with `const MSG_PROXY_SEND` + `const MSG_PROXY_FAIL` byte strings written via `libc::write(STDERR_FILENO, ...)` |
| 2 | cp9 used Rust 2024 let-chain syntax (`else if cond && let Some(x) = expr`); fork is on edition 2021 | Edition compatibility | Converted to nested `if let { }` form in cp9 amendment |
| 3 | cp8 (a0222be2) touched `crates/nono-cli/src/exec_strategy_windows/mod.rs` (9 lines) for `RollbackExitContext` struct field-type compatibility (`executable_identity` owned → reference, `audit_recorder` Arc deref, plus 3 new fields); audit predicted "0 Windows files touched" | D-48-E1 addendum (struct-compat exception per Phase 40 4-condition rule: required cross-platform struct field, default-factory only, ≤9 lines, documented) | Accepted — zero Windows-specific functional change; invariant still satisfied |
| 4 | cp8 introduced `unused variable: supervisor_network_audit_events` warning on Windows (declared unconditionally; used only inside `#[cfg(not(target_os = "windows"))]`) | Rule 1 auto-fix | Added matching `#[cfg(not(target_os = "windows"))]` gate; folded into cp8 via `git commit --fixup` + `git rebase --autosquash` |

## D-48-E1 Windows-only-files invariant

```
$ git diff 3f638dc6..HEAD --name-only | grep -E "(_windows\.rs|exec_strategy_windows/|nono-shell-broker/)"
crates/nono-cli/src/exec_strategy_windows/mod.rs
```

One Windows-pathed file appears: `exec_strategy_windows/mod.rs`. The change is a 9-line
struct-field call-site update mirroring upstream `a0222be2`'s `RollbackExitContext` shape
change; **zero hunks land inside `#[cfg(target_os = "windows")]` or `#[cfg(windows)]`
blocks in any shared file**. Deviation 3 documents the audit-prediction divergence and
its acceptance per the Phase 40 four-condition addendum codified in
`.planning/phases/40-upst4-sync-execution/40-CONTEXT.md`.

## Fork-invariant preservation (5/5)

1. **T-36-01-CANONICAL** — `impl From<ProfileDeserialize> for Profile` exhaustive match
   extended in cp8 at `profile/mod.rs` line 2150 to include `linux: raw.linux`.
2. **Phase 36-01b rename** — `profile.policy.add_deny_access` retained throughout
   (`capability_ext.rs` diff confirms presence).
3. **Phase 23 D-01 `Arc<Mutex<AuditRecorder>>`** — preserved in `supervised_runtime.rs`
   (`audit_recorder.as_deref()`) and `exec_strategy_windows/mod.rs`
   (`audit_recorder.map(|v| &**v)` double-deref).
4. **CR-01 async-signal safety** — see Deviation 1; cp9 amendment restores the invariant.
5. **`finalize_supervised_exit` call location** — remains in `exec_strategy.rs` Monitor
   path + `exec_strategy_windows/mod.rs`; upstream a0222be2's move into
   `supervised_runtime.rs` deliberately not adopted (fork comment preserved at the
   delegation point).

## Fork-side cross-target reconciliation (3 follow-up commits)

The 9 cherry-picks as landed compiled on the fork's Windows dev host but **not**
on Linux/macOS — the fork has diverged from upstream in `cfg(unix)` capability /
approval code, and the conflict resolutions silently dropped several fork
invariants. Surfaced on the fork CI (Linux + macOS lanes) and fixed in 3
follow-up commits, all restorations of the fork's pre-cherry-pick shape:

- **Round 1** — Linux lib: remove a duplicate `libc::AF_UNIX` match arm (E0063); convert 3 edition-2024 let-chains to nested if-let; underscore an unused param.
- **Round 2** — `nono-cli`: restore the fork's `CapabilityRequest` AIPC-01 fields + `#[allow(deprecated)]`, the Phase-45 `ApprovalDecision::is_approved` rename, and the fork's 4-arg `should_offer_profile_save`; drop a re-added duplicate test block.
- **Round 3** — macOS: wire `emit_unix_socket_rules` into the seatbelt `generate_profile` Blocked + ProxyOnly branches (the cherry-pick added the helper but dropped its call sites, leaving the macOS af_unix feature dead).

These are fork-specific adaptations and do **not** affect the upstream commits'
intent; the upstream code is unchanged on the platforms upstream maintains.

## CI status (fork-internal PR, baseline-aware diff vs `3f638dc6`)

**Verdict: regression-free.** Every CI lane that was green on the fork baseline
is green on this branch (Linux Clippy/Test, Verify FFI Header, Phase 37 ×2,
Windows ×6). The remaining red lanes (macОS Clippy/Test, Integration, Rustfmt,
Cargo Audit, Docs Checks) are **pre-existing fork `main` debt unrelated to this
cluster** — verified red on `main` before this work and traced to code Phase 48
never touched. They are deferred to a separate fork CI-cleanup effort.

Cross-target Linux/macOS clippy ran in CI (the Windows dev host lacks the
cross-toolchains; `aws-lc-sys`/`ring` C-FFI fails to link there), per CLAUDE.md
§ Coding Standards `Cross-target clippy verification`.

## REQ-UPST6-02 acceptance criteria

Cluster C4 disposition fully discharged with verbatim D-19 cherry-picks of all 9 upstream
SHAs, fork-invariant preservation across 5 sub-checks, and 4 documented deviations (all
auto-fix-classed or struct-compat-addendum-classed). Phase 48 = sole plan = sole cluster
for UPST6 sync execution. Phase 47 audit's `will-sync` row for C4 closed.

## Source artifacts

- [`48-01-PRE-CHERRY-PICK-AUDIT.md`](../tree/main/.planning/phases/48-upst6-sync-execution/48-01-PRE-CHERRY-PICK-AUDIT.md) — 8-section pre-flight audit per Convention Pattern D
- [`48-01-PARTIAL-SUMMARY.md`](../tree/main/.planning/phases/48-upst6-sync-execution/48-01-PARTIAL-SUMMARY.md) — frontmatter authoritative cherry-pick manifest
- [`48-01-CLOSE-GATE.md`](../tree/main/.planning/phases/48-upst6-sync-execution/48-01-CLOSE-GATE.md) — 8-gate matrix with PASS evidence + deviation notes
- [`48-01-SUMMARY.md`](../tree/main/.planning/phases/48-upst6-sync-execution/48-01-SUMMARY.md) — final shipped summary (authored on plan close)
