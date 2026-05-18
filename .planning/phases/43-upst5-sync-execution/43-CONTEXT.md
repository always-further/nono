---
phase: 43
phase_name: upst5-sync-execution
gathered: 2026-05-17
status: Ready for planning
requirements_locked_via: REQUIREMENTS.md § REQ-UPST5-02 (no SPEC.md — execution phase mirrors Phase 34 + 40 shape)
---

# Phase 43: UPST5 sync execution - Context

**Gathered:** 2026-05-17
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 43 executes the 6 syncable cluster dispositions from Phase 42's `DIVERGENCE-LEDGER.md` (4 will-sync + 2 fork-preserve) against 15 cross-platform commits in upstream `v0.53.0..v0.54.0`. Mirror Phase 34 + 40 execution shape: per-commit cherry-pick of will-sync clusters with verbatim D-19 trailer block; D-20 manual replay for fork-preserve clusters (with diff-inspection upgrade authority for Clusters 4 + 5 per Phase 40 D-40-B1 precedent). Cluster 6 macOS lint = won't-sync, documented inline in 43-SUMMARY per Phase 40 D-40-D1 (pointer-only rationale).

**First UPST sync cycle where the `windows-touch: yes` column requires real fork-side review:** 3 commits flagged (`0748cced` + `5d821c12` + `ce06bd59`) across Cluster 4 + Cluster 5; both clusters default to fork-preserve per D-42-C3 conservative default, with explicit Phase 43 plan-phase diff-inspection upgrade authority.

**Foundation wrinkle:** Cluster 2 is the Rust 2024 edition migration (single commit `8b888a1c`, 86 files, +2,234 / -1,470) and requires MSRV bump 1.77 → 1.85+. Fork is currently `edition = "2021"`, `rust-version = "1.77"` (workspace-wide). The MSRV bump + edition migration land atomically with Cluster 2 in Wave 0a — every downstream cluster's cherry-pick rebases on top of the edition-2024 baseline.

**In scope:**
- Per-commit cherry-pick of 4 `will-sync` clusters with `Upstream-commit:` D-19 trailer block (verbatim 6-line shape with lowercase `Upstream-author:` per Phase 40 standardization).
- Manual replay (or diff-inspection-upgraded cherry-pick) of 2 `fork-preserve` clusters per D-20 / D-42-C3 (Cluster 4 Windows registry parsing 2 commits + Cluster 5 platform.rs + WhenPredicate foundation 1 commit).
- Atomic MSRV bump (1.77 → 1.85+) bundled with Cluster 2 edition-2024 cherry-pick in Plan 43-01 (D-43-B1).
- Diff-inspection-first plans for Clusters 4 + 5 (Phase 40 D-40-B1 pattern): plan opens with structured "compare upstream `platform.rs` + `profile/mod.rs` `WhenPredicate` against fork's `profile/mod.rs::From<ProfileDeserialize>`" task. If zero fork-only-line conflicts AND identical surface semantics → upgrade disposition to `will-sync` (D-19 trailer cherry-pick). Otherwise stay D-20 manual replay. Decision documented in PLAN.md.
- Inline `## Won't-sync clusters from Phase 42 ledger` section in 43-SUMMARY.md documenting Cluster 6 (macOS lint) won't-sync disposition with pointer-only rationale (cite Phase 42 ledger row + Phase 40 D-40-D1 precedent).
- Baseline-aware CI gate vs Phase 41 close SHA `13cc0628` (all Linux/macOS Clippy + 5 Windows CI lanes green at baseline). Zero `success → failure` transitions allowed on every Wave 1+ head commit.
- PR umbrella to upstream: new branch per plan feeds into a fresh upstream PR (Phase 43 opens its own umbrella; PR #922 was the Phase 40 umbrella and is closed at v2.4 ship). Per memory `project_cross_fork_pr_pattern`: GitHub's one-PR-per-branch-pair rule means per-plan upstream PRs require per-plan feature branches; the umbrella aggregates plan-section bodies into one PR.

**Out of scope (route elsewhere or explicitly defer):**
- **Re-litigation of Phase 42 dispositions** — Phase 42 hand-off explicitly forbids: "Phase 43 must honor [Phase 42 dispositions] without re-relitigating the call". Phase 43 plan-phase has upgrade-from-fork-preserve authority for Clusters 4 + 5 (per D-43-C1), but cannot downgrade will-sync clusters or change cluster boundaries.
- **`## ADR review` re-litigation** — Phase 42 outcome (a) confirm Option A `continue` is the locked verdict; Phase 43 may produce a follow-on ADR amendment ONLY if Cluster 4 + 5 manual-replay labor surfaces a structural pattern worth codifying (plan-phase discretion, not Phase 43 verdict by default).
- **Post-v0.54.0 commits** (UPST6 absorbs per D-42-A4 silent-on-post-range rule) — 2 known post-v0.54.0 commits at audit time: `fc965ccc chore(deps): bump tokio`, `089cf6a0 chore(deps): bump cosign-installer`. UPST6 cadence trigger already met (`v0.55.0` tag fetched 2026-05-17 during Phase 42 audit-open).
- **Defense-in-depth wiring of newly-absorbed cross-platform features into fork-only Windows surface** — D-34-B2 surgical-retrofit posture inherits unchanged. No opportunistic Windows composition during cherry-pick.
- **Closure or replay of fork-only Windows seams** (`crates/nono-shell-broker/`, `WindowsTokenArm::BrokerLaunch`, Phase 28 chain-walker, Phase 32 TUF cached-root + broker self-trust-anchor, NONO_TEST_HOME seam) — D-17 / D-34-E1 / D-40-E1 / D-42-E7 cross-phase invariant; these stay byte-identical.
- **Cluster 6 macOS lint absorption** — won't-sync by default; only upgrade individual commits to `will-sync` if a specific diagnostic surfaces in fork's CI between Phase 42 audit close and Phase 43 sync execution (Phase 42 ledger note). Default action: skip the cluster; pointer-only inline SUMMARY entry.

</domain>

<decisions>
## Implementation Decisions

### Wave structure & plan slicing (Area A — discussed)

- **D-43-A1: Wave 0a = Cluster 2 solo (single-plan sequential gate).** Cluster 2 lands alone as Wave 0a (Plan 43-01-EDITION-2024-FOUNDATION) per Phase 34 D-34-A2 'C7 first' single-cluster sequential gate pattern. The 86-file edition-2024 migration cannot run parallel with any other cluster because every downstream cluster's cherry-pick rebases on top of the edition-2024 + MSRV bump baseline. Cherry-pick conflicts contained to one sequencing decision. **User explicitly chose** option (a) over (b) "Wave 0 = Cluster 2 + Cluster 7 sequential" and (c) "inline pre-flight" — sequential-gate is the cleanest blast-radius bound.

- **D-43-A2: Wave 1 = Cluster 1 + Cluster 3 parallel will-sync (one plan per cluster).** Plan 43-03-PACK-MGMT (Cluster 1, 8 commits, `crates/nono-cli/src/` pack/CLI surface) and Plan 43-04-RELEASE-RIDE (Cluster 3, 2 commits, CHANGELOG + nix dep bump) run in parallel as Wave 1. Surface-disjoint per Phase 42 ledger (Cluster 1 = `pack_update_hint.rs` + `package*.rs` + `cli.rs` + `app_runtime.rs` + `cli_bootstrap.rs` + `main.rs` + `sandbox_prepare.rs` + `registry_client.rs`; Cluster 3 = `Cargo.toml` CHANGELOG + nix dep). Mirrors Phase 40 D-40-A1 'one plan per cluster' + Phase 40 D-40-A2 parallel-foundation pattern. **User explicitly chose** option (a) over (b) "sequential Cluster 3 → Cluster 1" and (c) "fold Cluster 3 into Cluster 1 plan".

- **D-43-A3: Wave 2a = Cluster 5, Wave 2b = Cluster 4 (sequential fork-preserve).** Plan 43-05-PLATFORM-DETECTION-FOUNDATION (Cluster 5, 1 commit introducing `platform.rs` 659 lines + `WhenPredicate` deserialization in `profile/mod.rs` 217 lines + `wiring.rs` 126 lines + `policy.rs` 28 lines) lands first; Plan 43-06-PLATFORM-DETECTION-WINDOWS (Cluster 4, 2 commits: `0748cced` Windows registry queries 66 net + `5d821c12` REG_DWORD parse fix 26 net) lands sequentially after. Per Phase 42 ledger Cluster 4 wave-hint: "depends-on cluster-5 disposition — the two commits build on `ce06bd59`'s `platform.rs` foundation". Mirrors Phase 40 Wave 2 sequential fork-preserve pattern.

- **D-43-A4: Wave 0b = Cluster 7 sequential (between Wave 0a and Wave 1).** Plan 43-02-SNAPSHOT-SYMLINK-FIX (Cluster 7, 1 commit `66c69f86 fix(snapshot): validate restore targets against symlinks` on `crates/nono/src/undo/snapshot.rs`) lands sequentially after Plan 43-01 closes and before Wave 1 starts. Security-flavored fix closes the symlink-redirect race condition (an attacker creating a symlink between snapshot-taken and restore-invoked could redirect the restore write outside the tracked directory). Phase 42 ledger explicit recommendation: "the security flavor argues for sequencing this cluster early in the wave structure to close the symlink-race window in the fork too". Single-commit cherry-pick — minimal delay to Wave 1 start. **User explicitly chose** option (a) over (b) "Wave 1 parallel with Cluster 1 + Cluster 3" and (c) "Wave 0a before Cluster 2" — security urgency outranks parallelization speed, but post-edition-2024 baseline ordering avoids needing a follow-up edit if snapshot.rs surfaces edition-2024 adjustments.

### MSRV bump strategy (Area B — discussed)

- **D-43-B1: MSRV bump atomic with Cluster 2 cherry-pick.** Fork's `rust-version = "1.77"` and `edition = "2021"` (workspace-wide via `Cargo.toml`) bumps to whatever MSRV upstream `8b888a1c` chose (likely 1.85; planner verifies at cherry-pick time by reading upstream's `Cargo.toml` workspace section) in a single atomic commit (or paired commits in the same Plan 43-01). Upstream's `8b888a1c` bumps MSRV implicitly via edition; fork follows the same shape. Clean traceability — the edition decision and its prerequisite move together. CI catches any 1.77-only paths atomically. **User explicitly chose** option (a) "atomic with Cluster 2 cherry-pick" over (b) "separate prep plan before Cluster 2" and (c) "bump MSRV to latest stable (1.86+)". The pinned `windows-sys 0.59` already requires recent rustc (the v2.4 Phase 04 plan 02 bumped MSRV 1.74 → 1.77 specifically to support this); the v0.54.0 → edition-2024 bump is the next natural step.

- **D-43-B2 (implicit, follow-up from D-43-B1):** Fork MSRV = whatever upstream `8b888a1c` chose. Planner verifies at cherry-pick time. If upstream chose 1.85, fork pins 1.85; if upstream chose a higher value, fork follows. Fork does NOT diverge from upstream's MSRV in this cycle — the parity rationale is the entire point of Option A `continue`.

### Cluster 4 + 5 fork-preserve disposition pathway (Area C — discussed)

- **D-43-C1: Plan-open diff-inspection authority for both Cluster 4 + Cluster 5 (Phase 40 D-40-B1 pattern).** Each fork-preserve cluster's plan opens with a structured diff-inspection task: "compare upstream `platform.rs` + `profile/mod.rs::WhenPredicate` deserialization against fork's `profile/mod.rs::From<ProfileDeserialize>` exhaustive match (extended in Phase 36-01b for `CommandsConfig`)". If zero fork-only-line conflicts AND identical surface semantics → upgrade disposition to `will-sync` (D-19 trailer cherry-pick). Otherwise stay D-20 manual replay. Decision documented in PLAN.md. **User explicitly chose** option (a) over (b) "commit to manual-replay regardless" and (c) "only Cluster 5 gets diff-inspection authority".

- **D-43-C2: Two sequential plans (Cluster 5 → Cluster 4), not one combined plan.** Plan 43-05-PLATFORM-DETECTION-FOUNDATION covers Cluster 5 (the foundation feature introducing `platform.rs` + `WhenPredicate`); Plan 43-06-PLATFORM-DETECTION-WINDOWS covers Cluster 4 (the Windows registry parsing + REG_DWORD fix that builds on Cluster 5's module). Maximum per-cluster traceability; reviewer attention concentrates per cluster; avoids the mixed-disposition risk if Cluster 5 upgrades to will-sync but Cluster 4 stays manual-replay. Mirrors Phase 40 D-40-A1 + Phase 40 Wave 2 sequential fork-preserve pattern. **User explicitly chose** option (a) over (b) "one combined plan".

### Carry-Forward From Phase 22 / 33 / 34 / 39 / 40 / 41 / 42 (binding — locked, not for re-discussion)

- **D-43-E1 (= Phase 22 D-17 / Phase 34 D-34-E1 / Phase 40 D-40-E1 / Phase 42 D-42-E7):** Windows-only files structurally invariant. Phase 43 cherry-picks MUST NOT touch `*_windows.rs`, `crates/nono-cli/src/exec_strategy_windows/`, or `crates/nono-shell-broker/` UNLESS the 4-condition addendum applies: (1) required cross-platform struct field; (2) cross-platform default factory only; (3) ≤5 lines; (4) documented in SUMMARY + STATE.
- **D-43-E2 (= Phase 22 D-19 / Phase 34 D-19 / Phase 40):** Cherry-pick trailer block. Every cherry-picked commit carries the verbatim 6-line trailer:
  ```
  Upstream-commit: <40-char sha>
  Upstream-author: <name> <email>
  Upstream-date: <iso-8601>
  Upstream-subject: <verbatim upstream subject>
  Upstream-tag: <upstream tag containing this commit>
  Upstream-categories: <drift-tool categories from JSON>
  ```
  Lowercase `Upstream-author:` per Phase 40 standardization (was capitalized in earlier phases; Phase 40 lowercase convention is canonical).
- **D-43-E3 (= Phase 41 close-gate):** Baseline-aware CI gate baseline SHA = `13cc0628` per `.planning/templates/upstream-sync-quick.md:102`. All Linux/macOS Clippy + 5 Windows CI lanes (Build, Integration, Regression, Security, Packaging) green at baseline. Phase 43 plans MUST gate vs `13cc0628`; zero `success → failure` transitions on every Wave 1+ head commit. Lane transitions categorized: green→green=PASS; green→red=FAIL (real regression); red→red=PASS (carry-forward); red→green=PASS+IMPROVEMENT.
- **D-43-E4 (= memory `feedback_clippy_cross_target` / Phase 41 Wave 5):** Cross-target clippy required for cfg-gated Unix code from Windows host. Every Phase 43 plan touching `#[cfg(target_os = "linux"|"macos")]` code MUST run `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` AND `--target x86_64-apple-darwin` per `.planning/templates/cross-target-verify-checklist.md`. Windows-host workspace clippy alone is insufficient.
- **D-43-E5 (= memory `project_workspace_crates`):** nono workspace has 5 crates (not 3 — CLAUDE.md is stale). Workspace-touching commits (Cluster 2 + Cluster 5) MUST update all 5 `Cargo.toml` files (root + 4 member crates: nono, nono-cli, nono-proxy, nono-shell-broker, bindings/c) + internal path-dep `version` pins as needed.
- **D-43-E6 (= memory `project_cross_fork_pr_pattern`):** Single upstream PR umbrella per phase. Phase 43 opens a new umbrella PR (Phase 40 PR #922 closed at v2.4 ship). GitHub's one-PR-per-branch-pair rule means per-plan upstream contribution sections require per-plan feature branches feeding into the umbrella PR body. Plan-section bodies aggregate into the PR description.
- **D-43-E7 (= Phase 42 ADR review outcome (a)):** Phase 33 ADR Option A `continue` upstream-parity strategy stays `Accepted`. Phase 43 does NOT supersede or amend by default. Plan-phase MAY produce a follow-on ADR amendment if Cluster 4 + 5 manual-replay labor surfaces a structural pattern worth codifying (e.g., "windows-touch:yes platform-detection commits default to D-20 manual-replay until fork has its own platform.rs"); this is plan-phase discretion, not Phase 43 verdict.
- **D-43-E8 (= Phase 42 dispositions locked):** Cluster boundaries + dispositions from Phase 42 ledger are IMMUTABLE per D-39-B3 / D-42-B3. Phase 43 plan-phase has upgrade-from-fork-preserve authority for Clusters 4 + 5 (per D-43-C1) but cannot:
  - downgrade will-sync clusters to fork-preserve or won't-sync
  - merge or split cluster boundaries
  - change `windows-touch` column entries
  - re-relitigate per-commit dispositions for `0748cced` + `5d821c12` + `ce06bd59`
- **D-43-E9 (= Phase 34 D-34-D2 / Phase 40):** Per-plan close gate verbatim from Phase 34's 8-check format (cargo test + 4-platform clippy + fmt + Phase 15 smoke + wfp_port_integration + learn_windows_integration). Adjustments allowed only if a specific check is structurally inapplicable (e.g., Plan 43-04 release-ride is CHANGELOG-only and may skip wfp_port_integration with explicit `skipped_gates_load_bearing` vs `_environmental` categorization per Phase 40 anti-pattern #3).
- **D-43-E10 (= Phase 34 + 40 release-ride convention; precedent commit `64b231a7`):** For Cluster 3's `6b00932f chore: release v0.54.0` commit: fork DROPS upstream's `Cargo.toml` + `Cargo.lock` version bumps; absorbs only `CHANGELOG.md` entries. Fork tracks its own version separately. Each release-commit body documents the reverted hunks explicitly.

### Won't-sync handling (carry-forward from Phase 40 D-40-D1)

- **D-43-D1: Cluster 6 (macOS lint) handled inline in 43-SUMMARY.md, no plan.** Three small commits (`548bb800`, `021074c9`, `ff2d8b84`), each titled `fix: macos lint`, close `cargo clippy --target=apple-darwin` warnings that upstream's clippy ruleset surfaces but fork's does not (fork is green on baseline `13cc0628` per Phase 41 close-gate). Default action: skip the cluster; document divergence as intentional ("fork's clippy ruleset diverges from upstream's at v0.54.0; absorb selectively if fork CI surfaces matching diagnostics"). Pointer-only rationale in 43-SUMMARY § Won't-sync clusters from Phase 42 ledger. **Phase 43 plan-phase MAY upgrade individual commits to will-sync** if a specific diagnostic surfaces in fork's CI between Phase 42 audit close and Phase 43 sync execution; in that case, cherry-pick only the relevant subset, NOT the whole cluster.

### Claude's Discretion

- **Plan numbering finalization.** Plans 43-01..43-06 follow `{padded_phase}-{NN}-{CLUSTER-THEME}` convention. Suggested names captured above (43-01-EDITION-2024-FOUNDATION, 43-02-SNAPSHOT-SYMLINK-FIX, 43-03-PACK-MGMT, 43-04-RELEASE-RIDE, 43-05-PLATFORM-DETECTION-FOUNDATION, 43-06-PLATFORM-DETECTION-WINDOWS). Planner may refine naming for clarity.
- **Per-plan close-gate composition.** D-43-E9 inherits Phase 34 D-34-D2's 8-check verbatim; planner may add/skip individual checks per plan with explicit `skipped_gates_load_bearing` / `_environmental` categorization (Phase 40 anti-pattern #3). For example, Plan 43-04-RELEASE-RIDE is CHANGELOG-only and trivially passes most code-quality gates.
- **PR umbrella body assembly.** Each plan appends its contribution section to the umbrella PR body at plan close. Planner specifies the section template (subject + sha range + cluster disposition + key decisions) per Phase 40 D-40-A1 + memory `project_cross_fork_pr_pattern`.
- **Cluster 4/5 diff-inspection task structure.** D-43-C1 mandates plan-open diff-inspection; planner decides whether it's a separate task (Phase 40 D-40-B1 explicit task) or inlined at plan-open (less ceremony). Recommendation: separate task with explicit upgrade-or-not decision recorded.
- **MSRV verification sequencing in Plan 43-01.** D-43-B1 locks atomic MSRV bump; planner decides whether to verify upstream's exact MSRV by reading the upstream Cargo.toml at plan-open (recommended), or to assume 1.85 and rely on `cargo check` failure to catch mismatch.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase 43 scope sources
- `.planning/REQUIREMENTS.md` § REQ-UPST5-02 — Acceptance criteria (every will-sync cluster has a plan with cherry-picks + D-19 trailers; every fork-preserve cluster has a documented rationale; `windows-touch` cluster handled per audit disposition; baseline-aware CI gate zero `success → failure`; PR umbrella holds all phase contribution sections).
- `.planning/ROADMAP.md` § Phase 43 (lines 86–94) — Goal, depends-on Phase 41 (clean baseline) + Phase 42 (audit dispositions), success criteria (5 items), reference list.
- `.planning/PROJECT.md` § v2.5 Backlog Drain + UPST5 — milestone context, key decisions.

### Phase 42 audit ledger (BINDING IMMUTABLE INPUT — every plan reads this)
- `.planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md` — Cluster Summary table (7 clusters / 18 commits), per-cluster dispositions (4 will-sync + 2 fork-preserve + 1 won't-sync), `windows-touch` column firing for 3 commits, ADR review outcome (a) confirm, empirical cross-check methodology. **Phase 43 plans MUST cite specific ledger rows and dispositions; cannot re-relitigate.**
- `.planning/phases/42-upst5-audit/42-CONTEXT.md` — D-42-A1..D-42-E10 audit-shape decision IDs Phase 43 inherits (especially D-42-A1 range, D-42-A3 lock SHA, D-42-C1/C2/C3 windows-touch methodology, D-42-E7 Windows-only-files invariant).
- `.planning/phases/42-upst5-audit/42-01-SUMMARY.md` § Hand-off to Phase 43 — explicit hand-off contract; Phase 43 must honor cluster dispositions without re-relitigation.

### Phase 40 execution-shape template (PRIMARY reference — Phase 43 mirrors verbatim with Cluster 2 foundation wrinkle + windows-touch:yes Wave 2)
- `.planning/phases/40-upst4-sync-execution/40-CONTEXT.md` — D-40-A1..E5 decision IDs. Phase 43 D-43-A1..A4 inherit D-40-A1 (one plan per cluster) + D-40-A2 (parallel-foundation pattern); D-43-B1 atomic-MSRV strategy is new (Phase 40 had no MSRV bump); D-43-C1 diff-inspection upgrade authority inherits D-40-B1 verbatim and extends to BOTH Cluster 4 + 5 (Phase 40 only Cluster 4); D-43-D1 won't-sync inline SUMMARY inherits D-40-D1; D-43-E1..E10 are the cross-phase invariants.
- `.planning/phases/40-upst4-sync-execution/40-01-PROXY-HARDENING-SUMMARY.md` — Phase 40 Plan 40-01 worked example with cherry-pick chain + D-19 trailer block + CR-A regression handling. Phase 43 Plan 43-03-PACK-MGMT mirrors structure.
- `.planning/phases/40-upst4-sync-execution/40-04-RELEASE-RIDE-SUMMARY.md` — Phase 40 release-ride convention (precedent commit `64b231a7`); fork drops upstream Cargo.toml + Cargo.lock version bumps, absorbs only CHANGELOG. Phase 43 Plan 43-04-RELEASE-RIDE mirrors verbatim.
- `.planning/phases/40-upst4-sync-execution/40-05-FP-PROFILE-SAVE-SUMMARY.md` + `40-06-FP-PROXY-TLS-SUMMARY.md` — Phase 40 fork-preserve manual-replay examples. Phase 43 Plans 43-05 + 43-06 follow the diff-inspection-first pattern.

### Phase 34 execution-shape template root (Phase 43 inherits D-34-A1..D-34-E5 transitively via Phase 40)
- `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md` — D-34-A1..E5 decision IDs; per-cluster plan slicing, foundation gate, fork-preserve handling, per-plan close gate (D-34-D2 8-check format).

### Strategic ADR (LOCKED — Phase 43 inherits Phase 33 + Phase 42 verdict outcome (a))
- `docs/architecture/upstream-parity-strategy.md` — Phase 33 strategic ADR `Status: Accepted` 2026-05-11, re-confirmed at v2.4 close (Phase 39 D-39-C4), re-confirmed at v0.53.0..v0.54.0 audit close (Phase 42 D-42-C4 outcome (a)). Option A `continue` is the operative strategy. Phase 43 does NOT supersede or amend by default.

### Sync execution mechanics (MANDATORY)
- `.planning/templates/upstream-sync-quick.md` — MANDATORY scaffold for every Phase 43 plan; D-19 cherry-pick trailer block (verbatim 6-line shape with lowercase `Upstream-author:`); baseline SHA `13cc0628` per Phase 41 close (line 102); lane transition categorization rules (green→green PASS, green→red FAIL, etc.).
- `.planning/templates/cross-target-verify-checklist.md` — Phase 41 Class F template (`feedback_clippy_cross_target`); MANDATORY for every Phase 43 plan touching cfg-gated Unix code. Cross-target Linux + macOS clippy from Windows host.

### Drift-tool infrastructure (Phase 24; Phase 43 does not run drift tool but inherits audit output)
- `scripts/check-upstream-drift.sh` + `scripts/check-upstream-drift.ps1` — Drift-tool twin scripts (sha `0834aa66`); Phase 42 produced the ledger via these; Phase 43 references the ledger, doesn't re-run the tool.
- `.planning/phases/24-parity-drift-prevention/24-CONTEXT.md` § D-11 — fork-only Windows filter (`*_windows.rs` + `exec_strategy_windows/` excluded). Phase 43 cherry-picks MUST honor D-11 + D-42-C1/C2/C3 windows-touch detection.

### Phase 41 close-gate context (Phase 43 inherits clean baseline)
- `.planning/phases/41-ci-cleanup-v24-broker-code-review-closure/41-CONTEXT.md` — Phase 41 wave structure + close-gate semantics; D-41-* decisions Phase 43 inherits via D-43-E3 (baseline reset) and D-43-E4 (cross-target clippy).
- `.planning/phases/41-ci-cleanup-v24-broker-code-review-closure/41-SUMMARY.md` — Phase 41 close gate; baseline-aware CI gate reset to `13cc0628`, all CI lanes green, broker CR-01..04 closed, HandleTarget API migration at 14 sites complete.
- `.planning/phases/41-ci-cleanup-v24-broker-code-review-closure/41-VERIFICATION.md` — verifier confirming Phase 41 close-gate semantics. Phase 43 inherits this as the "clean baseline" precondition.

### Phase 36 canonical-sections context (binding for Cluster 5 diff-inspection)
- `.planning/phases/36-upst3-deep-closure/36-01b-CANONICAL-PROFILE-SECTIONS-SUMMARY.md` — Phase 36-01b extended `From<ProfileDeserialize> for Profile` exhaustively for new `CommandsConfig`. Cluster 5's upstream `WhenPredicate` deserialization touches this same impl — diff-inspection MUST verify no exhaustive-match collision.
- `.planning/phases/36-upst3-deep-closure/36-01c-OVERRIDE-DENY-RENAME-SUMMARY.md` — Phase 36-01c `override_deny → bypass_protection` atomic rename. Cluster 5 cherry-pick MUST honor the canonical name.

### Coding & security standards (CLAUDE.md)
- `CLAUDE.md` § Coding Standards — no `.unwrap()`, DCO sign-off (`Signed-off-by:` lines), `#[must_use]` on critical Results, env-var save/restore in tests. Every Phase 43 cherry-pick + manual-replay observes.
- `CLAUDE.md` § Security Considerations — path component comparison, fail-secure on any unsupported shape. Cluster 7 snapshot symlink fix is directly in scope.
- `CLAUDE.md` § Cross-target clippy verification — Phase 41 close-gate codifies; Phase 43 D-43-E4 inherits.

### Upstream source (git-resolvable from `upstream` remote at `https://github.com/always-further/nono.git`)
- Tag `v0.53.0` (`c4b25b82`) — Phase 40 UPST4 sync point; Phase 43 baseline fork-side.
- Tag `v0.54.0` (`6b00932f`) — Phase 43 upper bound; Phase 42 audit lock SHA `94fc4c6aa2f3d328c5f222c10c9c14352b179ddb` is the post-fetch HEAD.
- Tag `v0.55.0` (fetched 2026-05-17 during Phase 42 audit-open) — UPST6 cadence trigger met; Phase 43 does NOT absorb v0.55.0+ commits (UPST6 absorbs per D-42-A4).

### v2.5 milestone context
- `.planning/STATE.md` § Key Decisions (v2.5) — Phase 42 Plan 42-01 close entry captures the audit outcome Phase 43 inherits.
- `.planning/phases/41-*/` — Phase 41 close context (clean baseline precondition).
- `.planning/phases/42-upst5-audit/` — Phase 42 close context (binding audit input).

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets

- **`.planning/templates/upstream-sync-quick.md`** — MANDATORY scaffold. D-19 cherry-pick trailer block; baseline SHA `13cc0628`; lane transition categorization rules. Phase 43 plans inherit verbatim.
- **`.planning/templates/cross-target-verify-checklist.md`** — Phase 41 Class F template. Every Phase 43 plan touching cfg-gated Unix code uses this.
- **Phase 40 + 34 cherry-pick + manual-replay precedents** — `.planning/phases/40-upst4-sync-execution/` (4 will-sync plans + 2 fork-preserve plans) and `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/` (10 plans across waves) as worked examples.
- **PR umbrella body assembly pattern (Phase 40)** — each plan close appends contribution section to umbrella PR body; per-plan branch feeds into umbrella PR.
- **Phase 41 close-gate baseline `13cc0628`** — all CI lanes green; Phase 43 baseline-aware CI gate gates against this SHA per D-43-E3.

### Established Patterns

- **`upstream` git remote** at `https://github.com/always-further/nono.git`; tags v0.40.1..v0.55.0 fetched locally (verified 2026-05-17 during Phase 42 audit-open). Phase 43 cherry-picks from `upstream/main` history at `v0.53.0..v0.54.0`.
- **One plan per cluster (Phase 40 D-40-A1 / Phase 34 D-34-A1).** Cluster-themed plan names; maximum per-cluster traceability.
- **Surface-disjoint parallel waves (Phase 40 D-40-A2).** Waves group surface-disjoint plans for parallel execution; same-surface plans serialize.
- **Diff-inspection-first for fork-preserve (Phase 40 D-40-B1).** Plan opens with structured upstream-vs-fork diff inspection; upgrade-to-will-sync authority granted if surfaces compose cleanly.
- **Release-ride convention (Phase 40 D-40-E10; precedent commit `64b231a7`).** Fork drops upstream Cargo.toml + Cargo.lock version bumps; absorbs only CHANGELOG; each release-commit body documents reverted hunks.
- **Baseline-aware CI gate (Phase 40 anti-pattern #3 / Phase 41 close).** Categorize gate transitions: green→green PASS, green→red FAIL, red→red PASS (carry-forward), red→green PASS+IMPROVEMENT. `skipped_gates_load_bearing` vs `_environmental` documented in plan SUMMARY frontmatter.
- **D-19 6-line trailer block (Phase 22).** Verbatim shape with lowercase `Upstream-author:` per Phase 40 standardization. Falsifiable via `git log --format=%B | grep -c "^Upstream-commit:"`.

### Integration Points

- **`.planning/phases/43-upst5-sync-execution/` directory** — NEW phase dir Phase 43 creates. Plans land as `43-NN-CLUSTER-THEME-PLAN.md` + SUMMARY.md pairs.
- **`Cargo.toml` workspace root** — Cluster 2 edition + MSRV bump touches this atomically with Plan 43-01. Per memory `project_workspace_crates`, all 5 crate Cargo.toml files inherit via `edition.workspace = true` + `rust-version.workspace = true`.
- **`crates/nono/src/undo/snapshot.rs`** — Cluster 7 single-commit cherry-pick (Plan 43-02).
- **`crates/nono-cli/src/platform.rs`** — NEW file Cluster 5 introduces (Plan 43-05). 659 lines if cherry-picked verbatim; manual replay if D-43-C1 diff-inspection finds fork-only conflict.
- **`crates/nono-cli/src/profile/mod.rs`** — Cluster 5 extends `From<ProfileDeserialize> for Profile` with `WhenPredicate`; collision check against Phase 36-01b's `CommandsConfig` extension MANDATORY at Plan 43-05 diff-inspection.
- **`crates/nono-cli/src/wiring.rs`** — Cluster 5 extends `WiringDirective` with conditional evaluation (126 lines).
- **`crates/nono-cli/src/policy.rs`** — Cluster 5 extends built-in profile conditional inclusion (28 lines).
- **Upstream PR umbrella (new for Phase 43)** — Phase 40 used PR #922; Phase 43 opens a new umbrella PR. Per-plan branches feed into the umbrella body.

### Phase 43 wave structure (final)

```
Wave 0a: Plan 43-01-EDITION-2024-FOUNDATION (Cluster 2)
              │  - sequential gate per D-43-A1
              │  - atomic MSRV bump 1.77 → 1.85+ per D-43-B1
              │  - 86-file commit / +2,234 / -1,470 / single SHA 8b888a1c
              │  - workspace deps centralized (nix/landlock/url/getrandom)
              ↓
Wave 0b: Plan 43-02-SNAPSHOT-SYMLINK-FIX (Cluster 7)
              │  - sequential per D-43-A4
              │  - security-flavored; closes symlink-race window
              │  - single SHA 66c69f86 on crates/nono/src/undo/snapshot.rs
              ↓
Wave 1 (parallel): Plan 43-03-PACK-MGMT (Cluster 1)     Plan 43-04-RELEASE-RIDE (Cluster 3)
              │       - 8 commits / pack/CLI surface         - 2 commits / CHANGELOG + nix
              │       - cherry-pick chain                    - release-ride drops Cargo.toml
              │       - per D-43-A2 parallel                 - per D-43-A2 parallel
              ↓                                              ↓
Wave 2a: Plan 43-05-PLATFORM-DETECTION-FOUNDATION (Cluster 5)
              │  - fork-preserve default per D-42-C3
              │  - diff-inspection-first per D-43-C1 (upgrade authority)
              │  - single SHA ce06bd59 introduces platform.rs (659 lines)
              │  - extends profile/mod.rs WhenPredicate + wiring.rs + policy.rs
              ↓
Wave 2b: Plan 43-06-PLATFORM-DETECTION-WINDOWS (Cluster 4)
              │  - fork-preserve default per D-42-C3
              │  - diff-inspection-first per D-43-C1 (upgrade authority)
              │  - 2 commits: 0748cced (registry queries) + 5d821c12 (REG_DWORD fix)
              │  - builds on Cluster 5's platform.rs
              ↓
Phase close: 43-SUMMARY.md
              - § Won't-sync clusters: Cluster 6 macOS lint (pointer-only per D-43-D1)
              - § Hand-off to UPST6 (v0.54.0..+ audit absorbing v0.55.0+ accumulation)
              - PR umbrella body assembled from per-plan contribution sections
```

</code_context>

<specifics>
## Specific Ideas

- **Cluster 2 = Wave 0a solo sequential gate** (D-43-A1) — user explicitly chose over "Wave 0 = Cluster 2 + Cluster 7 sequential" or "inline pre-flight" shapes. Sequential-gate is the cleanest blast-radius bound for a 86-file commit that gates every downstream cherry-pick.
- **Atomic MSRV bump with Cluster 2** (D-43-B1) — user explicitly chose over "separate prep plan" or "bump to latest stable (1.86+)". Fork inherits whatever MSRV upstream `8b888a1c` chose; planner verifies at cherry-pick time. Single-commit atomicity preserves clean traceability.
- **Diff-inspection-first for BOTH Cluster 4 + Cluster 5** (D-43-C1) — user explicitly chose over "commit to manual-replay" or "only Cluster 5 gets diff-inspection authority". Both clusters' plans open with structured diff-inspection task; upgrade-to-will-sync authority granted if surfaces compose cleanly. Mirrors Phase 40 D-40-B1 pattern.
- **Two sequential plans for Cluster 4 + 5 (Cluster 5 → Cluster 4)** (D-43-C2) — user explicitly chose over "one combined platform-detection plan". Maximum per-cluster traceability; avoids mixed-disposition risk if Cluster 5 upgrades to will-sync but Cluster 4 stays manual-replay.
- **Wave 0b for Cluster 7 security fix** (D-43-A4) — user explicitly chose over "Wave 1 parallel" or "Wave 0a before Cluster 2". Honors Phase 42 ledger's "sequence security-flavored fixes early" recommendation while avoiding the follow-up-edit risk of pre-edition-2024 cherry-pick.

</specifics>

<deferred>
## Deferred Ideas

- **Post-v0.54.0 commit absorption** — UPST6 absorbs per D-42-A4 silent-on-post-range rule. UPST6 cadence trigger met (v0.55.0 fetched 2026-05-17); v0.55.0+ commits queued for UPST6 audit when scope is locked.
- **Follow-on ADR amendment after Cluster 4/5 manual-replay labor** — D-43-E7 allows but does not require. If Phase 43 plan-phase or execution surfaces a structural pattern (e.g., "windows-touch:yes platform-detection commits default to D-20 manual-replay until fork has its own platform.rs"), an ADR amendment can ship in a follow-up phase. Phase 43 does NOT supersede or amend by default.
- **Cluster 6 macOS lint selective absorption** — D-43-D1 default is skip. Phase 43 plan-phase MAY upgrade individual commits to will-sync if a specific diagnostic surfaces in fork's CI between Phase 42 audit close and Phase 43 sync execution.
- **Defense-in-depth wiring of newly-absorbed cross-platform features into fork-only Windows surface** — D-34-B2 surgical-retrofit posture inherits unchanged. No opportunistic Windows composition during cherry-pick. Future phase if/when needed.
- **Latest-stable MSRV (1.86+)** — D-43-B1 user-explicitly-rejected. Fork tracks upstream MSRV in this cycle; future phase may bump independently if needed.

</deferred>

---

*Phase: 43-upst5-sync-execution*
*Context gathered: 2026-05-17*
