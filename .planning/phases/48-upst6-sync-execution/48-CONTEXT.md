---
phase: 48
phase_name: upst6-sync-execution
gathered: 2026-05-24
status: Ready for planning
requirements_locked_via: REQUIREMENTS.md § REQ-UPST6-02 (no SPEC.md — execution phase mirrors Phase 34 + 40 + 43 sync-execution shape; binding input is Phase 47 DIVERGENCE-LEDGER.md immutable)
---

# Phase 48: UPST6 sync execution - Context

**Gathered:** 2026-05-24
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 48 executes the 9-cluster disposition set from Phase 47's `DIVERGENCE-LEDGER.md` (8 will-sync + 1 fork-preserve) against 42 cross-platform commits in upstream `v0.54.0..v0.57.0`. Mirror Phase 34 + 40 + 43 execution shape: per-commit cherry-pick of will-sync clusters with verbatim D-19 trailer block; D-20 manual replay for the fork-preserve cluster (with diff-inspection upgrade authority per Phase 43 D-43-C1 precedent). Single requirement: REQ-UPST6-02.

**Structurally cleaner than Phase 43:** zero `windows-touch:yes` (Phase 43 had 3 fires), zero cross-cluster re-export deps (Phase 43 had Cluster 2 split), one fork-preserve cluster (Phase 43 had two), no foundation wrinkle (Phase 43 had MSRV bump + Edition 2024 migration in Cluster 2). The Phase 47 D-47-D1..D4 re-export hardening closed the `feedback_cluster_isolation_invalid` lesson preventively — Phase 48 inherits a Cluster-2-style-surprise-free cherry-pick surface.

**Plan slicing locked: one plan per cluster (9 plans total).** Naming convention `48-NN-{CLUSTER-THEME}-PLAN.md` mirrors Phase 40 D-40-A1 + Phase 43 D-43-A2. Per-cluster traceability; rollback granularity = one cluster.

**Wave structure locked: 4 waves.**
- **Wave 0:** Plan 48-01-LANDLOCK-V6-AF-UNIX (Cluster C4 solo, foundation gate per D-48-A2).
- **Wave 1:** Plan 48-02-PROFILE-SHADOWING (Cluster C1) || Plan 48-03-STARTUP-TIMEOUT (Cluster C2) parallel after Wave 0 closes. Both gate on C4 (profile/mod.rs + cli.rs shared with C4); surface-disjoint from each other per Phase 47 § Empirical cross-check.
- **Wave 2:** Plan 48-04-LINUX-POLICY-POLISH (C5) || Plan 48-05-MACOS-GRANT-RESTORE (C6) || Plan 48-06-PTY-MUSL-PORTABILITY (C7) || Plan 48-07-PROXY-CRED-FORMAT (C8) || Plan 48-08-PACKAGE-MANIFEST (C9, fork-preserve with upgrade authority) parallel polish wave; all surfaces disjoint per Phase 47 audit.
- **Wave 3:** Plan 48-09-RELEASE-RIDE (Cluster C3 solo, structurally last per Phase 34/40/43 release-ride convention).

**ZERO backfill cherry-picks from Phase 47 Plan 47-02.** The v0.41-v0.43 backfill ledger concluded with `absorbed-via:` distribution 7 phase-34 + 4 intentionally-skipped + 0 unmatched. Phase 48 has zero backfill candidates to absorb alongside UPST6 work.

**In scope:**
- Per-commit cherry-pick of 8 `will-sync` clusters (7 will-sync + 1 fork-preserve-upgrade-candidate) with `Upstream-commit:` D-19 trailer block (verbatim 6-line shape with lowercase `Upstream-author:` per Phase 40 standardization).
- Pre-flight diff-inspection task at Plan 48-01 open captured in separate `48-01-PRE-CHERRY-PICK-AUDIT.md` artifact (extends Phase 43 D-43-C1 pattern from fork-preserve to will-sync-with-high-conflict-potential because C4 touches ~29+ fork-shared files cumulatively including supervisor.rs Windows-arm intersection).
- Mid-plan escalation pathway for Plan 48-01 if pre-flight surfaces irreconcilable conflicts: split into 48-01a (cleanly-resolvable commits) + 48-01b (deferred / D-20 manual-replay commits) per Phase 43 Plan 43-01 → 43-01b precedent.
- Plan 48-08 (Cluster C9, fork-preserve default) opens with diff-inspection against fork's Phase 35 + 45 trust-bundle work captured in `48-08-DISPOSITION-RESOLUTION.md` artifact (Phase 43 D-43-C1 naming convention). If no D-32-15 offline-verify invariant collision detected → upgrade to will-sync (D-19 trailer cherry-pick + D-47-D2 re-export scan); else stay D-20 manual-replay (`Upstream-replayed-from:` trailer per Phase 43 convention).
- Plan 48-08 close-gate ships a mandatory fork-side regression test exercising D-32-15 offline-verify with the upstream-extended `.nono-trust.bundle` schema (`installed_path` + `sha256_digest` fields per artifact) regardless of upgrade-or-not decision — defense-in-depth for security-critical surface.
- Plan 48-03 (Cluster C2) opens with grep-for-`startup_prompt` task across fork tree (especially `crates/nono-cli/src/exec_strategy_windows/` + `crates/nono-shell-broker/`); if references found, fork-side cleanup commit lands BEFORE cherry-picking `4e0e127a` (the 193-line dead-infra-removal commit). Cleanup commit carries no D-19 trailer; documented in plan SUMMARY.
- Plan 48-07 (Cluster C8) verifies existing fork-side schema-validator coverage (`crates/nono-cli/tests/` + `tests/integration/` grep) for the extended `credential_format` field shape (Option<String>: omitted vs explicit `'Bearer {}'` vs explicit bare token). If coverage gap detected → add focused fork-side regression test; else rely on existing schema-validator coverage.
- Plan 48-06 (Cluster C7) close-gate adds `cargo check --target x86_64-unknown-linux-musl` invocation; mark PARTIAL with explicit `_environmental` skipped-gate categorization per Phase 40 anti-pattern #3 if musl-cross-toolchain unavailable on Windows dev host. Defers to live CI per `.planning/templates/cross-target-verify-checklist.md` shape.
- Plan 48-09 (Cluster C3) ships ONE consolidated CHANGELOG-only commit `chore(48-09): absorb upstream v0.55.0..v0.57.0 CHANGELOG entries` with THREE stacked `Upstream-commit:` D-19 trailer blocks (one per upstream release). Fork's `crates/nono/Cargo.toml` + `Cargo.lock` version bumps DROPPED per release-ride convention (Phase 34/40/43 precedent commit `64b231a7`). Fork-side `crates/nono/CHANGELOG.md` (or wherever fork tracks CHANGELOG) gains all 3 upstream CHANGELOG sections in chronological order.
- Upstream PR umbrella opens AFTER Wave 0 (Plan 48-01) close — substantive content from day one; per-plan contribution sections from Waves 1–3 append. Mirrors Phase 43 umbrella cadence.
- Baseline-aware CI gate vs Phase 46 post-merge baseline SHA `3f638dc6` per `.planning/templates/upstream-sync-quick.md:102`. Zero `success → failure` transitions allowed on every Wave 1+ head commit. Lane transitions categorized per Phase 40 anti-pattern #3 (`skipped_gates_load_bearing` vs `_environmental`).
- 48-SUMMARY.md `## Hand-off to UPST7` section records C9 final disposition + rationale (Phase 47 ledger stays as-shipped — audit-of-record immutability); UPST7 auditor discovers C9 resolution at Plan 48-08 artifacts.
- Cross-target clippy verification per CLAUDE.md MUST/NEVER on every plan touching cfg-gated Unix code (C4, C5, C6, C7 all qualify); `.planning/templates/cross-target-verify-checklist.md` shape; PARTIAL acceptable only if cross-toolchain unavailable on Windows dev host.

**Out of scope (route elsewhere or explicitly defer):**
- **Re-litigation of Phase 47 dispositions** — Phase 47 hand-off explicitly forbids re-relitigating cluster boundaries, cluster dispositions, or per-commit disposition decisions. Plan 48-08 has upgrade-from-fork-preserve authority for C9 (per D-48-C1), but cannot downgrade will-sync clusters or change cluster boundaries.
- **`## ADR review` re-litigation** — Phase 47 outcome (a) confirm Option A `continue` is the locked verdict; Phase 48 may produce a follow-on ADR amendment ONLY if Plan 48-01 pre-flight surfaces a structural pattern worth codifying (plan-phase discretion, not Phase 48 verdict by default).
- **Post-v0.57.0 commits** (19 known at Phase 47 close, accumulating) — UPST7 absorbs per D-47-A4 silent-on-post-range rule. UPST7 cadence trigger partially met; will fire when next upstream release ships OR maintainer decides accumulated cherry-pick labor warrants firing.
- **v0.41-v0.43 backfill cherry-picks** — Phase 47 Plan 47-02 backfill ledger concluded zero unmatched commits. No Phase 48 backfill absorption.
- **Defense-in-depth wiring of newly-absorbed cross-platform features into fork-only Windows surface** — D-34-B2 surgical-retrofit posture inherits unchanged. No opportunistic Windows composition during cherry-pick.
- **Closure or replay of fork-only Windows seams** (`crates/nono-shell-broker/`, `WindowsTokenArm::BrokerLaunch`, Phase 28 chain-walker, Phase 32 TUF cached-root + broker self-trust-anchor, NONO_TEST_HOME seam, Phase 49 `--from-file` flag, Phase 50 sigstore TUF refresh) — D-17 / D-34-E1 / D-40-E1 / D-43-E1 / D-47-E5 cross-phase invariant; these stay byte-identical.
- **Phase 47 ledger retroactive amendment** — Phase 47 DIVERGENCE-LEDGER.md stays as-shipped (audit-of-record immutability). C9 disposition resolution lives in Plan 48-08 artifacts + 48-SUMMARY hand-off, not as inline annotation on Phase 47 ledger.
- **Phase 49 + 50 surface changes** — these phases shipped at v2.6 (Phase 49 2026-05-21; Phase 50 most recent close before Phase 48). Phase 48 inherits their state; no Plan touches `crates/nono-cli/src/setup.rs::trust_refresh` or `--from-file` paths.

</domain>

<decisions>
## Implementation Decisions

### Wave structure & plan slicing (Area A — discussed)

- **D-48-A1: One plan per cluster (9 plans total).** Mirrors Phase 40 D-40-A1 + Phase 43 D-43-A2 'one plan per cluster' precedent. Max per-cluster traceability; rollback granularity = one cluster. Plan naming convention `48-NN-{CLUSTER-THEME}-PLAN.md`. Suggested names (planner may refine):
  - 48-01-LANDLOCK-V6-AF-UNIX (C4, 9 commits)
  - 48-02-PROFILE-SHADOWING (C1, 9 commits)
  - 48-03-STARTUP-TIMEOUT (C2, 7 commits)
  - 48-04-LINUX-POLICY-POLISH (C5, 3 commits)
  - 48-05-MACOS-GRANT-RESTORE (C6, 3 commits)
  - 48-06-PTY-MUSL-PORTABILITY (C7, 4 commits)
  - 48-07-PROXY-CRED-FORMAT (C8, 2 commits)
  - 48-08-PACKAGE-MANIFEST (C9, 2 commits, fork-preserve with upgrade authority)
  - 48-09-RELEASE-RIDE (C3, 3 commits consolidated to 1 fork-side commit)
  **User explicitly rejected** option (b) "consolidate small polish clusters (6 plans, merge C5+C6+C7 into POLISH-BATCH)" and (c) "aggressive consolidation (4-5 plans by wave)".

- **D-48-A2: 4-wave structure — foundation → sequenced → parallel polish → release.**
  - **Wave 0:** Plan 48-01 (C4) solo — foundation gate; largest cluster (9 commits incl. a0222be2 18-file af_unix mediation); shared file dependencies with C1 (profile/mod.rs) + C2 (cli.rs) per Phase 47 § Empirical cross-check.
  - **Wave 1:** Plan 48-02 (C1) || Plan 48-03 (C2) parallel after Wave 0 closes. Both gate on C4; surface-disjoint from each other (C1 = `profile/*`, C2 = `cli.rs` + runtime/strategy files).
  - **Wave 2:** Plans 48-04 (C5) || 48-05 (C6) || 48-06 (C7) || 48-07 (C8) || 48-08 (C9) parallel polish wave. All surfaces disjoint per Phase 47 audit. C9 fork-preserve plan runs alongside polish (no separate Wave 2b; surface disjoint from C5/C6/C7/C8).
  - **Wave 3:** Plan 48-09 (C3) solo — structurally last per release-ride convention.
  **User explicitly rejected** option (b) "5 waves with sub-divided polish wave (Wave 2a Unix-side + Wave 2b proxy + fork-preserve)" and (c) "3 waves: foundation + parallel-all-non-conflicting + release".

- **D-48-A3: Wave 1 C1 and C2 parallel (not sequential).** C1 + C2 are surface-disjoint from each other (per Phase 47 § Empirical cross-check File #4: C1 touches `crates/nono-cli/src/profile/mod.rs`; per File #5: C2 touches `crates/nono-cli/src/cli.rs` + 7 other runtime/strategy files; intersection set is empty). Both wait for Wave 0 (C4) plan close (foundation gate), then run concurrently. Mirrors Phase 43 D-43-A2 'parallel will-sync when surface-disjoint' pattern. Halves Wave 1 elapsed time. **User explicitly rejected** option (b) "sequential C1 then C2" and (c) "sequential C2 then C1".

- **D-48-A4: PR umbrella opens after Wave 0 (C4) close.** Substantive content from day one; per-plan contribution sections from Waves 1–3 append. Mirrors Phase 43 umbrella cadence where the umbrella opened once foundation work landed. **User explicitly rejected** option (b) "at Phase 48 open (before any plan executes)" and (c) "at Phase 48 close (after all 9 plans land)".

### Cluster C4 internal sequencing (Area B — discussed)

- **D-48-B1: Single Plan 48-01 with 9 sequential cherry-picks.** Preserves cluster atomicity per Phase 47 ledger; close-gate runs once at plan close. Mirrors Phase 43 Plan 43-01 single-plan-86-files pattern at smaller scale. Cherry-pick order = upstream-chronological (c2c6f2ca → b8a32006 → 858ad009 → bbc652a0 → 1e9385a7 → 98f8cb18 → d146001b → a0222be2 → 863bbfd3; planner verifies exact order against `git log v0.54.0..v0.57.0 -- crates/nono/src/sandbox/linux.rs crates/nono/src/sandbox/mod.rs crates/nono-cli/src/cli.rs` at plan-open). **User explicitly rejected** option (b) "split into 2 plans by feature (Landlock-v6-scoping vs af-unix-mediation)" and (c) "split a0222be2 to its own plan (size-based)".

- **D-48-B2: Pre-flight diff-inspection task at Plan 48-01 open; output in separate `48-01-PRE-CHERRY-PICK-AUDIT.md` artifact.** Extends Phase 43 D-43-C1 pre-flight pattern from fork-preserve to will-sync-with-high-conflict-potential because C4 touches ~29+ fork-shared files cumulatively (lib.rs re-exports, capability.rs, supervisor.rs touched by 863bbfd3 which is shared with WindowsTokenArm/supervisor_windows). Artifact captures: per-commit conflict-prediction table, per-file diff inspection (esp. fork-only Windows arms in supervisor.rs / lib.rs / sandbox/linux.rs surfaces), chosen resolution strategy per commit. Plan body cites artifact at pre-flight task; subsequent cherry-pick tasks reference resolution strategy per commit. Mirrors Phase 43 Plan 43-02 `43-02-PRE-CHERRY-PICK-AUDIT.md` + Plan 43-03 `43-03-PER-SHA-AUDIT.md` naming precedent. **User explicitly rejected** option (b) "inline in 48-01-PLAN.md Pre-flight section" and (c) "first commit on the branch `docs(48-01): pre-flight diff-inspection results`".

- **D-48-B3: Escalation if irreconcilable conflict surfaces in C4 cherry-pick → split Plan 48-01 into 48-01a + 48-01b.** Mirrors Phase 43 Plan 43-01 → 43-01b precedent (Cluster 2 mid-flight split). 48-01a lands cleanly-resolvable commits with close-gate pass; 48-01b takes deferred commits with explicit per-commit resolution strategy (fork-authored partial-advancement per D-43-E1 4-condition addendum + D-20 manual-replay carrying `Upstream-replayed-from:` trailer per Phase 43 convention). Preserves cluster atomicity at the cluster level while allowing per-commit recovery. Phase 47 cluster dispositions remain IMMUTABLE — split is execution-level granularity refinement, not disposition change. **User explicitly rejected** option (b) "hand-fix on the cherry-pick branch + continue (fork-side hunks ride inside upstream cherry-pick commit, breaks D-19 trailer fidelity)" and (c) "D-20 manual-replay the problematic commit only (less aggressive than full split)".

### Cluster C9 fork-preserve disposition pathway (Area C — discussed)

- **D-48-C1: Diff-inspection-first with upgrade authority for Plan 48-08.** Mirror Phase 43 D-43-C1 pattern: Plan 48-08 opens with structured 'compare upstream 5f1c9c73 against fork's `crates/nono-cli/src/package_cmd.rs` + `crates/nono/src/trust/policy.rs` + `crates/nono/src/manifest.rs` (Phase 35 / 45 trust-bundle work)' task. Compatibility criteria: (1) no schema collision detected in fork's `.nono-trust.bundle` field set vs upstream's `installed_path` + `sha256_digest` extension; (2) D-32-15 offline-verify invariant preserved (cached `trusted_root.json` is read via plain JSON deserialization, not TUF re-verification; new schema fields MUST NOT break offline verify path). If both criteria pass → UPGRADE to will-sync (D-19 trailer cherry-pick + D-47-D2 re-export scan); else stay D-20 manual-replay (`Upstream-replayed-from: 5f1c9c73`/`8d774753` trailers per Phase 43 convention). Decision documented in PLAN.md + `48-08-DISPOSITION-RESOLUTION.md`. **User explicitly rejected** option (b) "commit upfront to D-20 manual-replay" and (c) "commit upfront to will-sync (skip the conservative default)".

- **D-48-C2: `48-08-DISPOSITION-RESOLUTION.md` separate artifact.** Mirrors Phase 43 D-43-C1 artifact convention (`43-05-DISPOSITION-RESOLUTION.md` + `43-06-DISPOSITION-RESOLUTION.md`). Captures: diff-inspection methodology, per-file comparison findings (fork's package_cmd.rs / trust/policy.rs / manifest.rs vs upstream's 5f1c9c73), D-32-15 offline-verify invariant check, and the upgrade-or-not decision with rationale. Plan body cites artifact at first task. If upgrade → subsequent tasks are cherry-pick with D-19 trailer; if no-upgrade → subsequent tasks are D-20 manual-replay with `Upstream-replayed-from:` trailer. **User explicitly rejected** option (b) "inline in 48-08-PLAN.md Decision section" and (c) "fold into shared `48-FORK-PRESERVE-RESOLUTION.md`".

- **D-48-C3: Mandatory fork-side regression test for D-32-15 offline-verify-with-extended-schema.** Plan 48-08 close-gate adds a fork-side integration test (`tests/integration/offline_verify_extended_trust_bundle.rs` or similar) that proves D-32-15 offline-verify holds when the bundle carries the new `installed_path` + `sha256_digest` fields. Belt-and-suspenders for a security-critical surface; codifies the invariant against future drift. Test must pass regardless of upgrade-or-not decision (if upgrade: tests cherry-picked behavior; if no-upgrade: tests that fork's preserved schema still validates against the extended-schema bundle shape that real upstream consumers may produce). Adds ~30–60 min plan scope. **User explicitly rejected** option (b) "only if diff-inspection surfaces concrete risk" and (c) "no, standard close-gate is sufficient".

- **D-48-C4: C9 resolution recorded in `48-08-DISPOSITION-RESOLUTION.md` + `48-SUMMARY.md` hand-off; Phase 47 DIVERGENCE-LEDGER.md stays as-shipped.** Resolution lives in Plan 48-08 artifacts (audit trail) + Phase 48 SUMMARY hand-off (`## Hand-off to UPST7` section explicitly states C9 final disposition + rationale). Phase 47 ledger preserves audit-of-record immutability; UPST7 auditor discovers C9 resolution at Plan 48-08 artifacts. Matches Phase 47's own pattern (Cluster 2 split→closed follow-on annotated in Phase 47 ledger Headline, not retroactive Phase 42 amendment). **User explicitly rejected** option (b) "amend Phase 47 DIVERGENCE-LEDGER.md C9 row in-place (breaks immutability convention)" and (c) "both — plan artifacts + ledger annotation (redundant)".

### Release-ride + schema/musl test specifics (Area D — discussed)

- **D-48-D1: C3 single consolidated CHANGELOG commit with 3 stacked D-19 trailers.** Plan 48-09 ships ONE commit `chore(48-09): absorb upstream v0.55.0..v0.57.0 CHANGELOG entries`; commit body carries 3 stacked `Upstream-commit:` D-19 trailer blocks (one per upstream release sha `35f9fea2` v0.55.0 + `b251c72f` v0.56.0 + `10cec984` v0.57.0). Fork's CHANGELOG.md (path `crates/nono/CHANGELOG.md` per upstream commit file walk) gains all 3 upstream CHANGELOG sections in chronological order. Fork's `crates/nono/Cargo.toml` + `Cargo.lock` version bumps DROPPED per release-ride convention (Phase 34/40/43 precedent commit `64b231a7`; fork tracks its own version separately). Minimum commit count; preserves provenance via stacked trailers; matches Phase 47 ledger consolidation invitation. **User explicitly rejected** option (b) "three separate release-ride commits (one per upstream release)" and (c) "single consolidated commit with 1 aggregate trailer (breaks D-19 per-sha convention)".

- **D-48-D2: C8 schema regression test — verify existing coverage first, add only if gap.** Plan 48-07 includes a sub-task: grep fork-side tests for jsonschema validation against `crates/nono-cli/data/nono-profile.schema.json` (likely under `crates/nono-cli/tests/` or `tests/integration/`). If existing coverage exercises the new `credential_format` field shape across all 3 cases (omitted → default-resolution, explicit `'Bearer {}'`, explicit bare token) → no new test. If gap → add a focused test for omitted-vs-explicit-Bearer-vs-bare-token resolution. Adaptive; smallest scope-increase that's still defensive. **User explicitly rejected** option (b) "yes, mandatory regression test (unconditional)" and (c) "no, rely on standard close-gate".

- **D-48-D3: C2 dead-infra removal handling — pre-flight grep + cleanup task before cherry-pick of 4e0e127a.** Plan 48-03 opens with grep for `startup_prompt` across fork tree (especially `crates/nono-cli/src/exec_strategy_windows/`, `crates/nono-shell-broker/`, fork-only test fixtures). If references found → plan-includes a fork-side cleanup commit (no D-19 trailer, documented in plan SUMMARY) BEFORE cherry-picking `4e0e127a`. Safe path; preserves cherry-pick atomicity for `4e0e127a`; mirrors Phase 43 D-43-C1 pre-flight pattern. **User explicitly rejected** option (b) "cherry-pick 4e0e127a; let cargo build fail; hand-fix in-place (breaks D-19 trailer fidelity)" and (c) "split 4e0e127a: D-20 manual-replay just the SIGKILL change (fork diverges from upstream cleanup; flagged in future UPST audits)".

- **D-48-D4: C7 musl-target verification — `cargo check --target x86_64-unknown-linux-musl` if cross-toolchain available; PARTIAL with `_environmental` skipped-gate categorization if not.** Plan 48-06 close-gate adds the cargo check invocation. Mirrors `.planning/templates/cross-target-verify-checklist.md` cross-target pattern: try the verification, mark PARTIAL with explicit `skipped_gates_environmental` per Phase 40 anti-pattern #3 if musl-cross unavailable, defer to live CI. Lowest-cost defense-in-depth; gates on what's actually verifiable from the Windows dev host. **User explicitly rejected** option (b) "add musl-target CI lane explicitly (substantial CI setup scope creep)" and (c) "no musl verification — standard close-gate sufficient".

### Carry-Forward From Phase 22 / 33 / 34 / 39 / 40 / 41 / 42 / 43 / 47 (binding — locked, not for re-discussion)

- **D-48-E1 (= Phase 22 D-17 / Phase 34 D-34-E1 / Phase 40 D-40-E1 / Phase 43 D-43-E1 / Phase 47 D-47-E5):** Windows-only files structurally invariant. Phase 48 cherry-picks MUST NOT touch `*_windows.rs`, `crates/nono-cli/src/exec_strategy_windows/`, or `crates/nono-shell-broker/` UNLESS the 4-condition addendum applies: (1) required cross-platform struct field; (2) cross-platform default factory only; (3) ≤5 lines; (4) documented in SUMMARY + STATE. Zero `windows-touch:yes` in Phase 47 audit means trivially honored for cherry-pick verbatim; D-48-D3 fork-side cleanup commit MAY touch fork-only Windows files (e.g., remove `startup_prompt` references from `exec_strategy_windows/`) — that's allowed under "fork-side cleanup" rather than upstream-sync invariant; documented in plan SUMMARY.

- **D-48-E2 (= Phase 22 D-19 / Phase 34 / Phase 40 / Phase 43 D-43-E2):** Cherry-pick trailer block. Every cherry-picked commit carries the verbatim 6-line trailer:
  ```
  Upstream-commit: <40-char sha>
  Upstream-author: <name> <email>
  Upstream-date: <iso-8601>
  Upstream-subject: <verbatim upstream subject>
  Upstream-tag: <upstream tag containing this commit>
  Upstream-categories: <drift-tool categories from JSON>
  ```
  Lowercase `Upstream-author:` per Phase 40 standardization (was capitalized in earlier phases; Phase 40 lowercase convention is canonical). D-20 manual-replay commits carry `Upstream-replayed-from: <sha>` trailer per Phase 43 convention.

- **D-48-E3 (= Phase 46 close-gate / `.planning/templates/upstream-sync-quick.md:102`):** Baseline-aware CI gate baseline SHA = `3f638dc6` per Phase 46 post-merge baseline. All Linux/macOS Clippy + 5 Windows CI lanes (Build, Integration, Regression, Security, Packaging) green at baseline. Phase 48 plans MUST gate vs `3f638dc6`; zero `success → failure` transitions on every Wave 1+ head commit. Lane transitions categorized: green→green=PASS; green→red=FAIL (real regression); red→red=PASS (carry-forward); red→green=PASS+IMPROVEMENT. Load-bearing skips (cross-target clippy gates 3+4 absent `aws-lc-sys`/`ring` cross-compilers on Windows host) categorized correctly per Phase 40 anti-pattern #3.

- **D-48-E4 (= memory `feedback_clippy_cross_target` / Phase 41 Wave 5 / CLAUDE.md MUST/NEVER bullet):** Cross-target clippy required for cfg-gated Unix code from Windows host. Every Phase 48 plan touching `#[cfg(target_os = "linux"|"macos")]` code MUST run `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` AND `--target x86_64-apple-darwin` per `.planning/templates/cross-target-verify-checklist.md`. Windows-host workspace clippy alone is insufficient. Plans C4 / C5 / C6 / C7 all qualify. PARTIAL allowed only if cross-toolchain unavailable on Windows dev host.

- **D-48-E5 (= memory `project_workspace_crates`):** nono workspace has 5 crates (not 3 — CLAUDE.md is stale). Workspace-touching commits MUST update all 5 `Cargo.toml` files (root + nono, nono-cli, nono-proxy, nono-shell-broker, bindings/c) + internal path-dep `version` pins as needed. Phase 47 audit surfaces no workspace-edit cluster this cycle (Cluster 2 closed in Phase 43 + 45); D-48-E5 trivially honored.

- **D-48-E6 (= memory `project_cross_fork_pr_pattern`):** Single upstream PR umbrella per phase. Phase 48 opens a new umbrella PR after Wave 0 close (per D-48-A4). GitHub's one-PR-per-branch-pair rule means per-plan upstream contribution sections require per-plan feature branches feeding into the umbrella PR body. Plan-section bodies aggregate into the PR description.

- **D-48-E7 (= Phase 47 ADR review outcome (a) / Phase 33 ADR `Status: Accepted`):** Phase 33 ADR Option A `continue` upstream-parity strategy stays `Accepted`. Phase 47 verdict shape `(H, H, M, M, M)` identical to Phase 42's; ~42-commit evidence base does not surface amend candidates. Phase 48 does NOT supersede or amend by default. Plan-phase MAY produce a follow-on ADR amendment ONLY if Plan 48-01 pre-flight surfaces a structural pattern worth codifying (e.g., "will-sync-with-high-conflict-potential clusters require pre-flight diff-inspection by default"); this is plan-phase discretion, not Phase 48 verdict by default.

- **D-48-E8 (= Phase 47 dispositions locked / Phase 43 D-43-E8 inheritance):** Cluster boundaries + dispositions from Phase 47 ledger are IMMUTABLE per D-39-B3 / D-42-B3 / D-47-B3 inheritance. Phase 48 plan-phase has upgrade-from-fork-preserve authority for C9 (per D-48-C1) and split-execution authority for C4 if pre-flight surfaces conflict (per D-48-B3), but cannot:
  - downgrade will-sync clusters to fork-preserve or won't-sync
  - merge or split cluster boundaries (per D-48-B3 'split' is execution-level granularity refinement, not disposition or cluster change)
  - change `windows-touch` column entries (Phase 47 audit confirmed zero fires; immutable)
  - re-relitigate per-commit dispositions within a cluster (each commit in a will-sync cluster gets cherry-picked unless pre-flight + escalation per D-48-B3 splits the plan)

- **D-48-E9 (= Phase 34 D-34-D2 / Phase 40 / Phase 43 D-43-E9):** Per-plan close gate verbatim from Phase 34's 8-check format (cargo test + 4-platform clippy + fmt + Phase 15 smoke + wfp_port_integration + learn_windows_integration). Adjustments allowed only if a specific check is structurally inapplicable (e.g., Plan 48-09 release-ride is CHANGELOG-only and may skip wfp_port_integration with explicit `skipped_gates_environmental` categorization per Phase 40 anti-pattern #3). Plan 48-08 close-gate ADDS the D-48-C3 mandatory regression test; Plan 48-07 MAY add D-48-D2 schema test if coverage gap; Plan 48-06 ADDS D-48-D4 musl-target verification; Plan 48-03 ADDS D-48-D3 fork-side cleanup task (not gate per se but plan-task).

- **D-48-E10 (= Phase 34 + 40 + 43 release-ride convention; precedent commit `64b231a7`):** For Cluster C3's 3 release commits: fork DROPS upstream's `crates/nono/Cargo.toml` + `Cargo.lock` version bumps; absorbs only CHANGELOG.md entries (per D-48-D1 consolidated into a single CHANGELOG-only commit with 3 stacked D-19 trailers). Fork tracks its own version separately. Plan 48-09 SUMMARY documents the reverted hunks explicitly.

- **D-48-E11 (= Phase 47 Plan 47-02 close):** ZERO backfill candidates from v0.41.0..v0.43.0 ledger. Phase 47 Plan 47-02 concluded with `absorbed-via:` distribution 7 phase-34 + 4 intentionally-skipped + 0 unmatched + 0 fork-divergence + 0 ambiguous. Phase 48 has zero backfill absorption work; closes v2.3 scope-lock 2026-04-29 REQ-DRIFT-INGEST-01 deferral structurally.

- **D-48-E12 (= Phase 47 D-47-D1..D4 closure):** ZERO cross-cluster re-export deps detected this cycle. Phase 47 audit confirmed only intra-cluster re-export surface in C4 lead commit `c2c6f2ca` (`LandlockScopePolicy`, `DetectedAbi`, `landlock_scope_policy`, `detect_abi`, `is_wsl2` all introduced in the same commit). No D-47-D4 split-flip required; Phase 48 inherits a Cluster-2-style-surprise-free cherry-pick surface. Plan 48-08 upgrade-to-will-sync path MUST still perform the D-47-D2 re-export scan on `5f1c9c73` + `8d774753` lead commits before cherry-pick (deferred from Phase 47 because C9 was fork-preserve at audit time).

- **D-48-E13 (= Phase 47 audit windows-touch:yes count = 0):** ZERO windows-touch this cycle. No new fork-side windows-conditional rework needed. The Phase 43 + 45 absorption of Cluster 5 (`0748cced` + `5d821c12` Windows platform-detection) + Cluster 2 (`8b888a1c` Edition 2024 source migration via Phase 45 Plan 45-01 `f640528a..d21399e3`) closed the v2.5 risk surface; Phase 47 verified no upstream regression. Cluster C4 (Linux-only Landlock v6) is `#[cfg(target_os = "linux")]`-gated; Windows structurally unaffected. D-48-E1 trivially honored at cherry-pick level for all 9 clusters.

### Folded Todos

[None — `cross_reference_todos` step matched 2 todos at score 0.6 (44-class-d-validator-preflight-investigation + 44-validate-restore-target-fd-relative-hardening), but both were explicitly out-of-scope per their own metadata (Phase 44 follow-up tagged for Phase 46+47 batch / explicit post-v2.6 deferral). User chose "neither — review only". See `<deferred>` § Reviewed Todos (not folded).]

### Claude's Discretion

- **Plan numbering finalization.** Plans 48-01..48-09 follow `{padded_phase}-{NN}-{CLUSTER-THEME}` convention. Suggested names captured in D-48-A1; planner may refine naming for clarity.
- **Per-plan close-gate composition.** D-48-E9 inherits Phase 34 D-34-D2's 8-check verbatim; planner may add/skip individual checks per plan with explicit `skipped_gates_load_bearing` / `_environmental` categorization (Phase 40 anti-pattern #3). For example, Plan 48-09 release-ride is CHANGELOG-only and trivially passes most code-quality gates; Plan 48-08 close-gate ADDS the D-48-C3 mandatory regression test.
- **PR umbrella body assembly.** Each plan appends its contribution section to the umbrella PR body at plan close. Planner specifies the section template (subject + sha range + cluster disposition + key decisions) per Phase 40 D-40-A1 + Phase 43 D-43-E6.
- **C4 cherry-pick chronological order verification.** D-48-B1 locks upstream-chronological cherry-pick order; planner verifies at Plan 48-01 open by running `git log v0.54.0..v0.57.0 -- crates/nono/src/sandbox/linux.rs crates/nono/src/sandbox/mod.rs crates/nono-cli/src/cli.rs` and recording the canonical order in `48-01-PRE-CHERRY-PICK-AUDIT.md`. If the chronological order differs from the Phase 47 ledger's row-order (which is grouped semantically, not chronologically), planner uses chronological order.
- **C4 commit b8a32006 (docs-only) sequencing.** Per upstream chronology; lands wherever its sha falls in the date ordering. No special handling.
- **Plan 48-08 upgrade decision artifact name.** D-48-C2 locks `48-08-DISPOSITION-RESOLUTION.md`; planner may add suffix (e.g., `-UPGRADED` or `-DEFERRED`) at plan close to reflect outcome, or leave the bare name.
- **48-SUMMARY.md hand-off section structure.** D-48-C4 mandates a `## Hand-off to UPST7` section with C9 final disposition. Planner decides whether to also include `## Wave 3 close summary` / `## Plan-level retrospective` / `## Deferred items` sections per Phase 43 43-SUMMARY shape.
- **Cluster C5 / C6 / C7 close-gate adjustments.** D-48-E9 8-check format inherits; planner may streamline for small-cluster polish plans (3-4 commits each, all Unix-side). For example, Plan 48-05 (macOS grant restore) may mark `wfp_port_integration` + `learn_windows_integration` as `_environmental` (Windows-only tests irrelevant to macOS-only changes).
- **Plan 48-08 re-export scan execution.** D-47-D2 + D-48-E12 require re-export scan on `5f1c9c73` + `8d774753` lead commits IF Plan 48-08 upgrades to will-sync. Scan output captured in `48-08-DISPOSITION-RESOLUTION.md` § Re-export check subsection. If no upgrade (D-20 manual-replay path), scan is N/A.
- **PR umbrella title + body initial state.** D-48-A4 opens umbrella after Wave 0 close; planner decides initial title (e.g., `nono: upstream v0.55.0..v0.57.0 sync (Phase 48)` mirrors Phase 43 umbrella shape).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase 48 scope sources
- `.planning/REQUIREMENTS.md` § REQ-UPST6-02 — Acceptance criteria (D-19 cherry-picks + D-20 manual replays per UPST6 audit dispositions; D-19 trailer convention + Windows-only-files invariant inherited from Phase 22+34+43; baseline-aware CI gate verified).
- `.planning/ROADMAP.md` § Phase 48 — Goal, depends-on Phase 47 (audit dispositions) + implicitly Phase 46 (clean post-merge baseline anchor), success criteria (5 items), reference list.
- `.planning/PROJECT.md` § v2.6 UPST6 + v2.5 Drain — milestone context, key decisions.

### Phase 47 audit ledger (BINDING IMMUTABLE INPUT — every Phase 48 plan reads this)
- `.planning/phases/47-upst6-audit-v0-41-v0-43-drift-ingestion/DIVERGENCE-LEDGER.md` — Cluster Summary table (9 clusters / 42 commits), per-cluster dispositions (8 will-sync + 1 fork-preserve), `windows-touch` column ZERO fires, ADR review outcome (a) confirm (H,H,M,M,M), empirical cross-check 5 fork-shared files, re-export scan ZERO cross-cluster deps. **Phase 48 plans MUST cite specific ledger rows and dispositions; cannot re-relitigate.**
- `.planning/phases/47-upst6-audit-v0-41-v0-43-drift-ingestion/DIVERGENCE-LEDGER-v041-v043-backfill.md` — v0.41-v0.43 backfill ledger; concluded zero unmatched commits; Phase 48 has zero backfill absorption work.
- `.planning/phases/47-upst6-audit-v0-41-v0-43-drift-ingestion/47-CONTEXT.md` — D-47-A1..D-47-E12 audit-shape decision IDs Phase 48 inherits (especially D-47-A1 range `v0.54.0..v0.57.0`, D-47-A3 lock SHA at first commit of audit plan, D-47-A5 windows-touch heuristic, D-47-D1..D4 re-export hardening, D-47-E7 baseline SHA `3f638dc6` inheritance).
- `.planning/phases/47-upst6-audit-v0-41-v0-43-drift-ingestion/47-01-SUMMARY.md` — Phase 47 Plan 47-01 close hand-off; per-cluster wave-hints for Phase 48 (C4 foundation candidate, C1 after C4 due to profile/mod.rs shared, C2 after C4 due to cli.rs shared, C3 release ride last, C9 plan-phase upgrade authority).
- `.planning/phases/47-upst6-audit-v0-41-v0-43-drift-ingestion/47-02-SUMMARY.md` — Phase 47 Plan 47-02 close hand-off; v0.41-v0.43 backfill resolution (zero unmatched); REQ-DRIFT-INGEST-01 closed.

### Phase 43 execution-shape template (PRIMARY reference — Phase 48 mirrors verbatim with no foundation wrinkle + zero windows-touch + zero cross-cluster re-export)
- `.planning/phases/43-upst5-sync-execution/43-CONTEXT.md` — D-43-A1..E10 decision IDs. Phase 48 D-48-A1..A4 inherit D-43-A1 (cluster solo foundation) + D-43-A2 (parallel will-sync when surface-disjoint) + D-43-A3/A4 (sequential fork-preserve wave); D-48-B1..B3 are net-new (single-plan 9-commit + pre-flight extension + split escalation); D-48-C1..C4 extend Phase 43 D-43-C1 fork-preserve pattern; D-48-D1 mirrors Phase 43 D-43-D1 release-ride consolidation invitation; D-48-D2/D3/D4 are net-new per-cluster regression-test/cleanup decisions; D-48-E1..E13 are the cross-phase invariants.
- `.planning/phases/43-upst5-sync-execution/43-01-EDITION-2024-FOUNDATION-SUMMARY.md` — Cluster 2 mid-flight split precedent; D-48-B3 escalation path directly references this artifact.
- `.planning/phases/43-upst5-sync-execution/43-01b-EDITION-WORKSPACE-ONLY-SUMMARY.md` — `split` disposition execution mechanism; mechanically-resolvable portion delivered fork-authored; template for D-48-B3 split-escalation pattern.
- `.planning/phases/43-upst5-sync-execution/43-02-PRE-CHERRY-PICK-AUDIT.md` — Pre-flight diff-inspection artifact precedent; D-48-B2 artifact naming convention directly mirrors this.
- `.planning/phases/43-upst5-sync-execution/43-03-PER-SHA-AUDIT.md` — Per-sha audit precedent; secondary template for D-48-B2.
- `.planning/phases/43-upst5-sync-execution/43-04-RELEASE-RIDE-SUMMARY.md` — Release-ride convention worked example; precedent commit `64b231a7`; D-48-D1 + D-48-E10 directly inherit shape.
- `.planning/phases/43-upst5-sync-execution/43-05-DISPOSITION-RESOLUTION.md` + `43-06-DISPOSITION-RESOLUTION.md` — Fork-preserve disposition resolution artifact precedents; D-48-C2 artifact naming convention directly mirrors these.
- `.planning/phases/43-upst5-sync-execution/43-05-PLATFORM-DETECTION-FOUNDATION-SUMMARY.md` + `43-06-PLATFORM-DETECTION-WINDOWS-SUMMARY.md` — Fork-preserve manual-replay worked examples; D-48-C1 diff-inspection-first pattern.

### Phase 40 + 34 execution-shape template ROOTS (Phase 48 inherits transitively via Phase 43)
- `.planning/phases/40-upst4-sync-execution/40-CONTEXT.md` — D-40-A1..E5 (one plan per cluster, surface-disjoint parallel waves, diff-inspection-first for fork-preserve, baseline-aware CI gate, Windows-only-files invariant + 4-condition addendum rule, anti-pattern #3 skipped-gate categorization).
- `.planning/phases/40-upst4-sync-execution/40-04-RELEASE-RIDE-SUMMARY.md` — Phase 40 release-ride convention precedent commit `64b231a7`; fork drops upstream Cargo.toml + Cargo.lock version bumps, absorbs only CHANGELOG. D-48-D1 directly inherits.
- `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md` — D-34-A1..E5 (per-cluster plan slicing, foundation gate, fork-preserve handling, per-plan close gate D-34-D2 8-check format).

### Strategic ADR (LOCKED — Phase 48 inherits Phase 33 + Phase 42 + Phase 47 verdict outcome (a))
- `docs/architecture/upstream-parity-strategy.md` — Phase 33 strategic ADR `Status: Accepted` 2026-05-11, re-confirmed at v2.4 close (Phase 39 D-39-C4), re-confirmed at v0.53.0..v0.54.0 audit close (Phase 42 D-42-C4 outcome (a)), re-confirmed at v0.54.0..v0.57.0 audit close (Phase 47 verdict (H,H,M,M,M) outcome (a)). Option A `continue` is the operative strategy. Phase 48 does NOT supersede or amend by default.

### Sync execution mechanics (MANDATORY)
- `.planning/templates/upstream-sync-quick.md` — MANDATORY scaffold for every Phase 48 plan; D-19 cherry-pick trailer block (verbatim 6-line shape with lowercase `Upstream-author:`); baseline SHA `3f638dc6` per Phase 46 close (line 102); lane transition categorization rules (green→green PASS, green→red FAIL, etc.).
- `.planning/templates/cross-target-verify-checklist.md` — Phase 41 Class F template (`feedback_clippy_cross_target`); MANDATORY for every Phase 48 plan touching cfg-gated Unix code (C4, C5, C6, C7). Cross-target Linux + macOS clippy from Windows host.

### Drift-tool infrastructure (Phase 24; Phase 48 does not run drift tool but inherits audit output)
- `scripts/check-upstream-drift.sh` + `scripts/check-upstream-drift.ps1` — Drift-tool twin scripts (sha `0834aa664fbaf4c5e41af5debece292992211559`); Phase 47 produced both ledgers via these; Phase 48 references the ledger, doesn't re-run the tool.
- `.planning/phases/24-parity-drift-prevention/24-CONTEXT.md` § D-11 — fork-only Windows filter (`*_windows.rs` + `exec_strategy_windows/` excluded). Phase 48 cherry-picks MUST honor D-11 + D-47-A5 windows-touch detection (zero fires this cycle).

### Phase 46 close-gate context (Phase 48 inherits clean post-merge baseline)
- `.planning/phases/46-windows-squash-merge-post-merge-ci-verifications-uat-backlog/46-VERIFICATION.md` — Phase 46 close gate; baseline-aware CI gate reset, baseline registry updated to `3f638dc6`, all 8 lanes diff vs `13cc0628` with zero load-bearing success→failure. Phase 48 inherits this as "clean baseline" precondition.
- `.planning/phases/46-windows-squash-merge-post-merge-ci-verifications-uat-backlog/46-CONTEXT.md` — D-46-A1..C3 windows-squash merge + post-merge CI + UAT backlog dispositions.

### Phase 41 close-gate context (transitively inherited via Phase 46 baseline reset)
- `.planning/phases/41-ci-cleanup-v24-broker-code-review-closure/41-CONTEXT.md` — Phase 41 wave structure + close-gate semantics; cross-target clippy enforcement promoted to MUST/NEVER.

### Phase 36 canonical-sections context (binding for C1 + C4 profile/mod.rs collision check)
- `.planning/phases/36-upst3-deep-closure/36-01b-CANONICAL-PROFILE-SECTIONS-SUMMARY.md` — Phase 36-01b extended `From<ProfileDeserialize> for Profile` exhaustively for new `CommandsConfig`. C1 commits touching `profile/mod.rs` (5 commits: 750f4653, 316c6a2c, 3d3d239a, b3556139, 0015f348, 0a4db57e, bd76c6b5, c897c8cc) MUST diff-inspect against fork's exhaustive match. C4 a0222be2 also touches `profile/mod.rs` — Plan 48-01 + Plan 48-02 diff-inspection MUST verify no exhaustive-match collision.
- `.planning/phases/36-upst3-deep-closure/36-01c-OVERRIDE-DENY-RENAME-SUMMARY.md` — Phase 36-01c `override_deny → bypass_protection` atomic rename. C1 + C4 cherry-picks MUST honor the canonical name if profile fields are touched.

### Phase 35 + 45 trust-bundle context (binding for C9 fork-preserve diff-inspection)
- `.planning/phases/35-source-migration-aipc-g04-resl-nix/45-CONTEXT.md` (or `.planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-CONTEXT.md`) — Phase 45 trust-bundle handling work; D-48-C1 diff-inspection MUST compare upstream's `5f1c9c73` `installed_path` + `sha256_digest` extension against fork's Phase 35 + 45 schema.
- `crates/nono/src/trust/policy.rs` — Fork's trust-bundle schema. D-48-C1 reads this at diff-inspection time.
- `crates/nono/src/manifest.rs` — Fork's manifest module. D-48-C1 reads this at diff-inspection time.
- `crates/nono-cli/src/package_cmd.rs` — Fork's package command surface. D-48-C1 reads this at diff-inspection time.

### Phase 49 + 50 surface awareness (Phase 48 inherits state; no source-tree intersection)
- `.planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-CONTEXT.md` — Phase 49 shipped 2026-05-21 with `--from-file` flag, release-asset bundling, fixture refresh cadence template. Phase 48 does not touch `crates/nono-cli/src/setup.rs::trust_refresh` or `--from-file` paths.
- `.planning/phases/50-corp-network-tuf-refresh-via-os-root-store-replace-or-wrap-t/50-CONTEXT.md` — Phase 50 nono-local TUF chain-walk shipped via ureq + tough. Phase 48 does not touch the trust_refresh module.

### Phase 32 verify-is-offline invariant (binding for C9 D-48-C3 regression test)
- D-32-15 verify-is-offline invariant — cached `trusted_root.json` is read via plain JSON deserialization, not TUF re-verification. New `.nono-trust.bundle` schema fields from C9 (`installed_path` + `sha256_digest`) MUST NOT break the offline verify path. D-48-C3 mandatory regression test codifies this against future drift.

### Coding & security standards (CLAUDE.md)
- `CLAUDE.md` § Coding Standards — no `.unwrap()`, DCO sign-off (`Signed-off-by:` lines), `#[must_use]` on critical Results, env-var save/restore in tests. Every Phase 48 cherry-pick + manual-replay observes.
- `CLAUDE.md` § Security Considerations — path component comparison, fail-secure on any unsupported shape. C9 (`validate_bundle_relative_path` defense-in-depth) is directly in scope; C4 (af_unix pathname mediation) and C7 (PTY proxy + musl) intersect with path-handling primitives.
- `CLAUDE.md` § Cross-target clippy verification — Phase 41 close-gate codifies; D-48-E4 inherits MUST/NEVER.

### Operative memory entries (load-bearing for Phase 48)
- Memory `feedback_clippy_cross_target` — cross-target clippy enforced via CLAUDE.md MUST/NEVER. D-48-E4 inheritance.
- Memory `project_workspace_crates` — nono workspace has 5 crates (not 3). D-48-E5 trivially honored (no workspace-edit clusters this cycle).
- Memory `project_cross_fork_pr_pattern` — fork uses ONE umbrella PR to upstream (Phase 22+34+40+43 pattern). D-48-A4 + D-48-E6 inheritance.
- Memory `feedback_cluster_isolation_invalid` — DIVERGENCE-LEDGER cluster isolation can be empirically false; Phase 47 D-47-D1..D4 structurally closed this lesson; Phase 48 inherits zero cross-cluster re-export deps per D-48-E12.
- Memory `feedback_windows_worktree_cwd` — Windows worktree CWD divergence; after every wave-merge, `cd /c/Users/OMack/Nono` and verify pwd + branch before next bash. Phase 48 wave-merges (Wave 0 → Wave 1 → Wave 2 → Wave 3) MUST observe this.

### Upstream source (git-resolvable from `upstream` remote at `https://github.com/always-further/nono.git`)
- Tag `v0.54.0` (`6b00932f`) — Phase 47 audit lower bound + Phase 43+45 absorption sync point + Phase 48 fork-side baseline.
- Tag `v0.55.0` (`35f9fea2`) — Phase 47 audit intermediate; C3 release commit #1.
- Tag `v0.56.0` (`b251c72f`) — Phase 47 audit intermediate; C3 release commit #2.
- Tag `v0.57.0` (`10cec984`) — Phase 47 audit upper bound; C3 release commit #3.
- Upstream HEAD at Phase 47 audit-open: `807fca38` (2026-05-23; 19 post-v0.57.0 commits visible). Strictly silent per D-47-A4; UPST7 absorbs.

### v2.6 milestone context
- `.planning/STATE.md` — current milestone v2.6 status; Phase 48 follows Phase 47 close; Phase 49 + 50 already shipped.
- `.planning/PROJECT.md` § v2.6 UPST6 + v2.5 Drain — milestone scope, key decisions.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets

- **`.planning/templates/upstream-sync-quick.md`** — MANDATORY scaffold. D-19 cherry-pick trailer block; baseline SHA `3f638dc6`; lane transition categorization rules. Phase 48 plans inherit verbatim.
- **`.planning/templates/cross-target-verify-checklist.md`** — Phase 41 Class F template. Every Phase 48 plan touching cfg-gated Unix code (C4, C5, C6, C7) uses this.
- **Phase 43 cherry-pick + manual-replay precedents** — `.planning/phases/43-upst5-sync-execution/` (4 will-sync plans + 2 fork-preserve plans + 1 release-ride) as worked examples. Phase 48 D-48-A1..A4 + D-48-B1..B3 + D-48-C1..C4 + D-48-D1 directly inherit shape.
- **Phase 40 + 34 cherry-pick + manual-replay precedents** — `.planning/phases/40-upst4-sync-execution/` + `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/` as transitive references.
- **PR umbrella body assembly pattern (Phase 40 + 43)** — each plan close appends contribution section to umbrella PR body; per-plan branch feeds into umbrella PR.
- **Phase 46 close-gate baseline `3f638dc6`** — all CI lanes green at baseline; Phase 48 baseline-aware CI gate gates against this SHA per D-48-E3.
- **Phase 47 ledger DIVERGENCE-LEDGER.md** — IMMUTABLE INPUT; defines all 9 cluster boundaries + dispositions + per-commit row data + windows-touch column (zero fires) + ADR review verdict (a) confirm + empirical cross-check 5 files + re-export scan zero cross-cluster deps. Phase 48 plans MUST cite specific ledger rows.

### Established Patterns

- **`upstream` git remote** at `https://github.com/always-further/nono.git`; tags v0.40.1..v0.57.0+ fetched locally (verified at Phase 47 audit-open 2026-05-23). Phase 48 cherry-picks from `upstream/main` history at `v0.54.0..v0.57.0`.
- **One plan per cluster (Phase 40 D-40-A1 / Phase 43 D-43-A2 / Phase 48 D-48-A1).** Cluster-themed plan names; maximum per-cluster traceability.
- **Surface-disjoint parallel waves (Phase 40 D-40-A2 / Phase 43 D-43-A2 / Phase 48 D-48-A2/A3).** Waves group surface-disjoint plans for parallel execution; same-surface plans serialize.
- **Diff-inspection-first for fork-preserve (Phase 40 D-40-B1 / Phase 43 D-43-C1 / Phase 48 D-48-C1).** Plan opens with structured upstream-vs-fork diff inspection; upgrade-to-will-sync authority granted if surfaces compose cleanly. **Phase 48 D-48-B2 extends pattern to will-sync-with-high-conflict-potential (Plan 48-01 / C4).**
- **Pre-flight artifact convention (Phase 43 D-43-C1 / Phase 48 D-48-B2 + D-48-C2).** Separate artifacts `48-01-PRE-CHERRY-PICK-AUDIT.md` (C4) + `48-08-DISPOSITION-RESOLUTION.md` (C9). Plan body cites artifact at first task.
- **Mid-plan escalation via split (Phase 43 Plan 43-01 → 43-01b / Phase 48 D-48-B3).** Cluster atomicity preserved at cluster level; per-commit recovery via plan split.
- **Release-ride convention (Phase 40 D-40-E10 / Phase 43 D-43-D1 / Phase 48 D-48-D1 + D-48-E10; precedent commit `64b231a7`).** Fork drops upstream Cargo.toml + Cargo.lock version bumps; absorbs only CHANGELOG. Phase 48 D-48-D1 consolidates 3 releases into 1 commit with stacked trailers.
- **Baseline-aware CI gate (Phase 40 anti-pattern #3 / Phase 41 close / Phase 46 close / Phase 48 D-48-E3).** Categorize gate transitions: green→green PASS, green→red FAIL, red→red PASS (carry-forward), red→green PASS+IMPROVEMENT. `skipped_gates_load_bearing` vs `_environmental` documented in plan SUMMARY frontmatter.
- **D-19 6-line trailer block (Phase 22).** Verbatim shape with lowercase `Upstream-author:` per Phase 40 standardization. Falsifiable via `git log --format=%B | grep -c "^Upstream-commit:"`. D-20 manual-replay carries `Upstream-replayed-from:` per Phase 43 convention.

### Integration Points

- **`.planning/phases/48-upst6-sync-execution/` directory** — NEW phase dir Phase 48 creates. Plans land as `48-NN-CLUSTER-THEME-PLAN.md` + SUMMARY.md pairs. Pre-flight + disposition-resolution artifacts under `48-01-PRE-CHERRY-PICK-AUDIT.md` + `48-08-DISPOSITION-RESOLUTION.md`.
- **`crates/nono/src/sandbox/linux.rs`** — C4 a0222be2 + c2c6f2ca touch. Linux-only; `#[cfg(target_os = "linux")]`-gated.
- **`crates/nono/src/sandbox/mod.rs`** — C4 c2c6f2ca re-exports `DetectedAbi` + `LandlockScopePolicy` + `landlock_scope_policy` from linux module.
- **`crates/nono/src/lib.rs`** — C4 c2c6f2ca re-exports same symbols at top-level. Re-export check passed in Phase 47 audit (intra-cluster origin); no D-47-D4 split-flip required.
- **`crates/nono/src/capability.rs`** — C4 touches (cfg-gated additions).
- **`crates/nono-cli/src/cli.rs`** — Touched by C2 (4 commits: a8646d26, 2bed3565, 468d3813, 4e0e127a) + C4 (3 commits: c2c6f2ca, bbc652a0, 858ad009). Wave 1 (C1) and Wave 1 (C2) both gate on C4 closing first.
- **`crates/nono-cli/src/profile/mod.rs`** — Touched by C1 (5 commits: 750f4653, 316c6a2c, 3d3d239a, c897c8cc, b3556139, 0015f348) + C4 (1 commit: a0222be2 — af_unix mediation profile config) + C6 (1 commit: abca959a — macOS localhost outbound). Fork-side intersection: Phase 36-01b / 36-01c canonical-sections work. Plan 48-01 + Plan 48-02 diff-inspection MUST verify no exhaustive-match collision in `From<ProfileDeserialize> for Profile`.
- **`crates/nono-cli/src/policy.rs`** — Touched by C5 (2 commits: e6215f8b, 4fa9f6a6 — Linux deny-overlap diagnostic quieting) + C4 (1 commit: a0222be2). Fork's Phase 41 Class D Linux deny-overlap regression test (REQ-TEST-HYG-01 closed via Phase 44 Plan 44-02 drain) composes additively.
- **`crates/nono-cli/src/package_cmd.rs` + `crates/nono/src/trust/policy.rs` + `crates/nono/src/manifest.rs`** — C9 5f1c9c73 + 8d774753 touch. Plan 48-08 diff-inspection target (D-48-C1).
- **`crates/nono-cli/data/nono-profile.schema.json`** — C8 57005737 + 530306ee touch. Fork-shared schema; Plan 48-07 D-48-D2 verifies fork-side validator coverage.
- **`crates/nono/src/undo/snapshot.rs`** — Phase 43 absorbed `66c69f86` symlink fix; Phase 48 has no upstream commits touching this file (verified Phase 47 audit walk).
- **`crates/nono-cli/src/exec_strategy.rs`** — C7 3d0ff87f musl Ioctl fix touches. Cross-platform; Linux musl-target verification per D-48-D4.
- **`crates/nono-cli/src/exec_strategy_windows/` + `crates/nono-shell-broker/`** — Fork-only Windows surface; D-48-E1 invariant. Phase 48 cherry-picks DO NOT touch these directly. D-48-D3 fork-side cleanup MAY touch (remove `startup_prompt` references) under "fork-side cleanup" carve-out.
- **`crates/nono/CHANGELOG.md`** — C3 release-ride commits absorb 3 upstream CHANGELOG sections into this file (or wherever fork tracks CHANGELOG; planner verifies at Plan 48-09 open).
- **Upstream PR umbrella (NEW for Phase 48)** — Phase 43 umbrella closed at v2.5 ship. Phase 48 opens a new umbrella after Wave 0 (Plan 48-01) close per D-48-A4. Per-plan branches feed into the umbrella body.

### Phase 48 wave structure (final, locked by D-48-A2)

```
Wave 0 (foundation gate, sequential):
  Plan 48-01-LANDLOCK-V6-AF-UNIX (Cluster C4, 9 commits)
              │  - pre-flight diff-inspection at 48-01-PRE-CHERRY-PICK-AUDIT.md (D-48-B2)
              │  - upstream-chronological cherry-pick order (D-48-B1)
              │  - escalation: split to 48-01a + 48-01b if irreconcilable (D-48-B3)
              │  - PR umbrella opens after this plan closes (D-48-A4)
              ↓
Wave 1 (parallel after Wave 0 closes):
  Plan 48-02-PROFILE-SHADOWING (C1, 9 commits)   ||   Plan 48-03-STARTUP-TIMEOUT (C2, 7 commits)
              │  - profile/mod.rs after C4              │  - cli.rs + runtime files after C4
              │  - Phase 36 canonical-sections check    │  - pre-flight grep startup_prompt (D-48-D3)
              │                                         │  - fork-side cleanup before 4e0e127a
              ↓                                         ↓
Wave 2 (parallel polish + fork-preserve, 5-way):
  Plan 48-04-LINUX-POLICY-POLISH (C5, 3 commits)
  Plan 48-05-MACOS-GRANT-RESTORE (C6, 3 commits)
  Plan 48-06-PTY-MUSL-PORTABILITY (C7, 4 commits)
              │  - cargo check --target x86_64-unknown-linux-musl (D-48-D4)
  Plan 48-07-PROXY-CRED-FORMAT (C8, 2 commits)
              │  - verify schema-validator coverage first (D-48-D2)
  Plan 48-08-PACKAGE-MANIFEST (C9, 2 commits, fork-preserve with upgrade authority)
              │  - 48-08-DISPOSITION-RESOLUTION.md (D-48-C2)
              │  - mandatory D-32-15 offline-verify regression test (D-48-C3)
              ↓
Wave 3 (release ride, sequential after Wave 2):
  Plan 48-09-RELEASE-RIDE (C3, 3 upstream commits → 1 fork-side commit)
              │  - single consolidated CHANGELOG commit with 3 stacked D-19 trailers (D-48-D1)
              │  - fork drops upstream Cargo.toml + Cargo.lock version bumps (D-48-E10)
              ↓
Phase close: 48-SUMMARY.md
              - § Won't-sync clusters: none this cycle (Phase 47 ledger: 0 won't-sync)
              - § Hand-off to UPST7 (D-48-C4 records C9 final disposition)
              - PR umbrella body assembled from per-plan contribution sections (9 sections)
              - Baseline-aware CI gate verdict vs 3f638dc6 (D-48-E3)
```

</code_context>

<specifics>
## Specific Ideas

- **One plan per cluster (9 plans)** (D-48-A1) — user explicitly chose over "consolidate small polish clusters (6 plans)" or "aggressive consolidation (4-5 plans by wave)". Mirrors Phase 40 D-40-A1 + Phase 43 D-43-A2 maximum per-cluster traceability.
- **4-wave structure** (D-48-A2) — user explicitly chose over "5 waves with sub-divided polish" or "3 waves: foundation + parallel-all-non-conflicting + release". Wave 0 = C4 solo; Wave 1 = C1 || C2 parallel; Wave 2 = C5/C6/C7/C8/C9 parallel; Wave 3 = C3 release-ride solo.
- **C1 || C2 parallel in Wave 1** (D-48-A3) — user explicitly chose over "sequential C1 then C2" or "sequential C2 then C1". Surface-disjoint per Phase 47 § Empirical cross-check; halves Wave 1 elapsed time.
- **PR umbrella opens after Wave 0 close** (D-48-A4) — user explicitly chose over "Phase 48 open" or "Phase 48 close". Substantive content from day one; mirrors Phase 43 cadence.
- **Single 9-commit sequential plan for C4** (D-48-B1) — user explicitly chose over "split by feature (Landlock-v6 vs af-unix)" or "split a0222be2 by size". Preserves cluster atomicity; close-gate runs once at plan close.
- **Pre-flight diff-inspection separate artifact `48-01-PRE-CHERRY-PICK-AUDIT.md`** (D-48-B2) — user explicitly chose over "inline in PLAN.md" or "first commit on the branch". Mirrors Phase 43 D-43-C1 artifact convention.
- **Plan 48-01 split escalation if irreconcilable conflict** (D-48-B3) — user explicitly chose over "hand-fix on the cherry-pick branch + continue" or "D-20 manual-replay the problematic commit only". Mirrors Phase 43 Plan 43-01 → 43-01b precedent.
- **Diff-inspection-first with upgrade authority for C9** (D-48-C1) — user explicitly chose over "commit upfront to D-20 manual-replay" or "commit upfront to will-sync". Mirrors Phase 43 D-43-C1 fork-preserve pattern.
- **`48-08-DISPOSITION-RESOLUTION.md` separate artifact** (D-48-C2) — user explicitly chose over "inline in PLAN.md" or "shared fork-preserve resolution doc". Mirrors Phase 43 D-43-C1 artifact convention.
- **Mandatory D-32-15 offline-verify regression test for C9** (D-48-C3) — user explicitly chose over "only if diff-inspection surfaces concrete risk" or "no, standard close-gate sufficient". Belt-and-suspenders for security-critical surface.
- **C9 resolution recorded in plan artifacts + 48-SUMMARY hand-off; Phase 47 ledger stays as-shipped** (D-48-C4) — user explicitly chose over "amend Phase 47 ledger C9 row in-place" or "both". Preserves audit-of-record immutability.
- **C3 single consolidated CHANGELOG commit with 3 stacked D-19 trailers** (D-48-D1) — user explicitly chose over "three separate release-ride commits" or "single commit with 1 aggregate trailer". Matches Phase 47 ledger consolidation invitation; preserves provenance via stacked trailers.
- **C8 schema test: verify existing coverage first, add only if gap** (D-48-D2) — user explicitly chose over "yes, mandatory" or "no, standard close-gate". Adaptive; smallest scope-increase that's still defensive.
- **C2 dead-infra pre-flight grep + cleanup before cherry-pick of 4e0e127a** (D-48-D3) — user explicitly chose over "cherry-pick + hand-fix in-place" or "D-20 manual-replay just SIGKILL". Safe path; preserves cherry-pick atomicity for 4e0e127a.
- **C7 musl: cargo check + PARTIAL if cross-toolchain unavailable** (D-48-D4) — user explicitly chose over "add musl-target CI lane" or "no musl verification". Mirrors `.planning/templates/cross-target-verify-checklist.md` shape.

</specifics>

<deferred>
## Deferred Ideas

- **Post-v0.57.0 commit absorption** — UPST7 absorbs per D-47-A4 silent-on-post-range rule. UPST7 cadence trigger already accumulating: 19 post-v0.57.0 commits visible at Phase 47 audit-open (2026-05-23); will continue accumulating before UPST7 fires. UPST7 fires when next upstream release ships OR maintainer decides accumulated cherry-pick labor warrants firing.
- **Follow-on ADR amendment** — D-48-E7 allows but does not require. If Plan 48-01 pre-flight surfaces a structural pattern (e.g., "will-sync-with-high-conflict-potential clusters require pre-flight diff-inspection by default"), an ADR amendment can ship in a follow-up phase. Phase 48 does NOT supersede or amend by default.
- **C9 partial absorption (one commit cherry-pick, one D-20 manual-replay)** — Not discussed explicitly; if Plan 48-08 diff-inspection surfaces 5f1c9c73-compatible-but-8d774753-incompatible (or vice versa), the per-commit disposition decision becomes a Plan 48-08 internal call. Default = whole-cluster decision per D-48-C1 (upgrade-or-no-upgrade applies to both commits).
- **Defense-in-depth wiring of newly-absorbed cross-platform features into fork-only Windows surface** — D-34-B2 surgical-retrofit posture inherits unchanged. No opportunistic Windows composition during cherry-pick. Future phase if/when needed (e.g., extending C4 LandlockScopePolicy concept to Windows AppContainer? — out of scope for Phase 48; v2.7+ candidate).
- **Cross-binding lockstep updates for nono-py / nono-ts** — Phase 44 v24-broker CR-01/02 pattern. Phase 48 surfaces no broker-touching commits this cycle; cross-binding lockstep N/A. If C9 upgrade-to-will-sync introduces new public Rust API (`installed_artifact_relative_path`, `validate_bundle_relative_path`), language bindings may need lockstep updates — defer to post-Phase-48 review if surfaced.

### Reviewed Todos (not folded)

- **`44-class-d-validator-preflight-investigation`** — Phase 44 follow-up tagged for "Phase 46+47 batch" (already past). Linux Landlock policy.rs validator investigation. Out of scope for Phase 48 cherry-pick execution; reviewed but not folded per user decision.
- **`44-validate-restore-target-fd-relative-hardening`** — Substantial 2-3 week cross-platform fd-relative TOCTOU refactor. Explicitly tagged "post-v2.6" by its own metadata. Out of scope for Phase 48 cherry-pick execution; reviewed but not folded per user decision.

</deferred>

---

*Phase: 48-upst6-sync-execution*
*Context gathered: 2026-05-24*
