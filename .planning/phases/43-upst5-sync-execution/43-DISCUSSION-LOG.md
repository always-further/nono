# Phase 43: UPST5 sync execution - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-17
**Phase:** 43-upst5-sync-execution
**Areas discussed:** Wave structure + Cluster 2 foundation sequencing, MSRV bump strategy, Cluster 4 + 5 fork-preserve disposition pathway, Cluster 7 wave placement

---

## Area A — Wave structure + Cluster 2 foundation sequencing

### Sub-decision A.1 — Cluster 2 sequencing

| Option | Description | Selected |
|--------|-------------|----------|
| Wave 0 = Cluster 2 solo (sequential gate) | Cluster 2 lands alone as Wave 0 (single-plan sequential gate). All downstream waves rebase on top of edition 2024. Mirrors Phase 34 D-34-A2 'C7 first' single-cluster sequential gate. Cherry-pick conflicts contained to one sequencing decision. | ✓ |
| Wave 0 = Cluster 2 (sequential) + Cluster 7 (security) | Cluster 2 lands solo first, then Cluster 7 (security) lands second in Wave 0 before any other will-sync work. Hoists the security fix early; Cluster 7's surface (snapshot.rs) is disjoint from Cluster 2's edition touches. | |
| Treat Cluster 2 as inline pre-flight (not its own wave) | Bundle MSRV bump + edition migration as an inline pre-flight step in the first plan, then proceed with normal wave structure. Less ceremony but harder to roll back if edition migration surfaces unexpected issues. | |

**User's choice:** Wave 0 = Cluster 2 solo (sequential gate)
**Notes:** Captured as D-43-A1. Sequential-gate cleanest blast-radius bound for an 86-file commit.

### Sub-decision A.2 — Wave 1 shape (Cluster 1 + Cluster 3)

| Option | Description | Selected |
|--------|-------------|----------|
| Parallel will-sync (1 plan per cluster) | Cluster 1 (pack mgmt) + Cluster 3 (release-ride) run in parallel as Wave 1. Surface-disjoint (Cluster 1 = nono-cli pack/CLI surface; Cluster 3 = CHANGELOG + nix dep bump). Mirrors Phase 40 D-40-A1 'one plan per cluster' + Phase 40 D-40-A2 parallel-foundation pattern. | ✓ |
| Sequential: Cluster 3 first, then Cluster 1 | Land the small Cluster 3 (release-ride + nix bump) first as a sanity check that edition-2024 baseline holds, then tackle Cluster 1's 8-commit cherry-pick chain. Slower but lower blast-radius if edition migration surfaces an issue. | |
| Fold Cluster 3 into Cluster 1 plan | Combine the 2 release-ride commits into the Cluster 1 plan since both touch CLI surface area. Cluster 1 already pulls 8 commits; adding 2 makes 10. Mirrors Phase 40 D-40-A2 paired-cluster approach. Risk: bloats one plan. | |

**User's choice:** Parallel will-sync (1 plan per cluster)
**Notes:** Captured as D-43-A2. Surface-disjoint; mirrors Phase 40 D-40-A1/A2 verbatim.

---

## Area B — MSRV bump strategy for Cluster 2 (Rust 2024)

| Option | Description | Selected |
|--------|-------------|----------|
| Atomic with Cluster 2 cherry-pick | MSRV bump + edition migration land in a single atomic commit (or paired commits in the same plan). Upstream's 8b888a1c bumps MSRV implicitly via edition; fork follows the same shape. Clean traceability — the edition decision and its prerequisite move together. CI catches any 1.77-only paths atomically. | ✓ |
| Separate prep plan BEFORE Cluster 2 | Wave 0a = standalone fork commit bumping rust-version 1.77 → 1.85; Wave 0b = Cluster 2 cherry-pick. Surfaces any MSRV-only breakage (e.g., deprecated APIs that 1.85 lints differently) before the edition migration noise. More ceremony but smaller individual blast radius. | |
| Bump MSRV to latest stable (e.g., 1.86+) | Same as option 1/2 but pick latest stable Rust instead of the minimum required by edition 2024. Gives the fork headroom for future upstream commits without immediate MSRV pressure. Tightly couples fork release cadence to rustc release cadence. | |

**User's choice:** Atomic with Cluster 2 cherry-pick
**Notes:** Captured as D-43-B1. Fork inherits whatever MSRV upstream `8b888a1c` chose (likely 1.85; planner verifies). Implicit D-43-B2: fork MSRV matches upstream's choice; does not diverge in this cycle (preserves Option A `continue` parity rationale).

---

## Area C — Cluster 4 + 5 fork-preserve disposition pathway

### Sub-decision C.1 — Diff-inspection upgrade authority

| Option | Description | Selected |
|--------|-------------|----------|
| Yes — diff-inspection-first (Phase 40 D-40-B1 pattern) | Each fork-preserve cluster's plan opens with a structured diff-inspection task. If zero fork-only-line conflicts AND identical surface semantics → upgrade disposition to will-sync (D-19 trailer cherry-pick). Otherwise stay D-20 manual replay. Decision documented in PLAN.md. | ✓ |
| No — commit to manual-replay (D-20) | Both clusters stay D-20 manual replay regardless of diff-inspection outcome. Replay the *intent* without the *form*. Safer; preserves Phase 36 canonical-sections design integrity. No upgrade authority used. | |
| Only Cluster 5 gets diff-inspection authority | Cluster 5 (the foundation feature) gets diff-inspection authority. Cluster 4 stays straight cherry-pick once Cluster 5 lands (disposition follows). Mirrors ledger's wave-hint dependency note. | |

**User's choice:** Yes — diff-inspection-first (Phase 40 D-40-B1 pattern)
**Notes:** Captured as D-43-C1. Extends Phase 40 D-40-B1 to BOTH clusters (Phase 40 only granted authority to Cluster 4).

### Sub-decision C.2 — Plan slicing for Cluster 4 + 5

| Option | Description | Selected |
|--------|-------------|----------|
| Two sequential plans (Cluster 5 → Cluster 4) | Plan 43-04-PLATFORM-DETECTION-FOUNDATION (Cluster 5; 1 commit + 659 lines) lands first; then Plan 43-05-PLATFORM-DETECTION-WINDOWS (Cluster 4; 2 commits) builds on top. Mirrors Phase 40 D-40-A1 'one plan per cluster' + Phase 40 Wave 2 sequential fork-preserve pattern. Maximum per-cluster traceability. | ✓ |
| One combined plan (platform-detection feature) | Single plan covers all 3 commits. Tightly coupled: Cluster 4 builds on Cluster 5's platform.rs. Plan covers cluster-5 diff-inspection FIRST, then cluster-4 work depends on that outcome. Reduces plan count from 5 to 4. Risk: mixed dispositions inside one plan get muddier. | |

**User's choice:** Two sequential plans (Cluster 5 → Cluster 4)
**Notes:** Captured as D-43-C2. Plan numbering finalized as 43-05 (foundation) and 43-06 (Windows).

---

## Area D — Cluster 7 (snapshot security fix) wave placement

| Option | Description | Selected |
|--------|-------------|----------|
| Wave 0b (right after Cluster 2 lands, before Wave 1) | Close the symlink-race window as soon as the edition-2024 baseline holds. Plan 43-02 lands sequentially after Plan 43-01 (Cluster 2) and before Wave 1. Single-commit cherry-pick — minimal delay. Honors ledger recommendation. | ✓ |
| Wave 1 (parallel with Cluster 1 + Cluster 3) | Cluster 7 joins Wave 1 as a third parallel will-sync plan. Surface-disjoint. Faster total wall-clock; security fix lands at same time as pack management + release ride. Acceptable if security urgency is low. | |
| Wave 0a (before Cluster 2) | Hoist Cluster 7 to land even before Cluster 2 because security flavor outranks foundation. Risk: snapshot.rs may need edition-2024 adjustments after Cluster 2 lands; the pre-Cluster-2 cherry-pick may need a follow-up edit. | |

**User's choice:** Wave 0b (right after Cluster 2 lands, before Wave 1)
**Notes:** Captured as D-43-A4. Honors Phase 42 ledger's "sequence security-flavored fixes early" recommendation while avoiding follow-up-edit risk.

---

## Wrap-up question — anything else to lock down?

| Option | Description | Selected |
|--------|-------------|----------|
| No — write CONTEXT.md now | Decisions captured for: wave structure, MSRV strategy, Cluster 4/5 diff-inspection, Cluster 7 placement. Other concerns (Cluster 6 won't-sync handling, PR umbrella pattern, baseline SHA, D-19 trailer, Windows-only-files invariant) are locked by precedent. | ✓ |
| Cluster 6 (macOS lint) — CI-diagnostic check | Phase 42 ledger says 'absorb selectively if fork CI surfaces matching diagnostics'. Should Phase 43 include an explicit CI-diagnostic check task? | |
| Phase 43 PR umbrella strategy | Phase 40 used branch-per-plan feeding into PR #922 umbrella. Should we discuss whether to open a new PR or reuse PR #922's pattern with a new branch? | |
| Close-gate per-plan checks (D-34-D2 verbatim?) | Phase 40 inherited Phase 34 D-34-D2's 8-check close gate. Should Phase 43 inherit verbatim or adjust given new MSRV requirement? | |

**User's choice:** No — write CONTEXT.md now
**Notes:** Cluster 6, PR umbrella, and close-gate inherit Phase 40 + 42 precedent verbatim (captured in CONTEXT.md as D-43-D1, D-43-E6, D-43-E9 respectively).

---

## Claude's Discretion

Items deferred to planner judgment (captured in CONTEXT.md § Claude's Discretion):

- Plan numbering finalization (suggested names 43-01-EDITION-2024-FOUNDATION..43-06-PLATFORM-DETECTION-WINDOWS)
- Per-plan close-gate composition (D-43-E9 inherits Phase 34 D-34-D2's 8-check verbatim; planner may skip individual checks per plan with explicit `_load_bearing` vs `_environmental` categorization)
- PR umbrella body assembly section templates per plan
- Cluster 4/5 diff-inspection task structure (separate task vs inlined at plan-open)
- MSRV verification sequencing in Plan 43-01 (read upstream Cargo.toml at plan-open vs rely on `cargo check` failure)

## Deferred Ideas

- Post-v0.54.0 commit absorption (UPST6; cadence trigger met 2026-05-17)
- Follow-on ADR amendment after Cluster 4/5 manual-replay labor (D-43-E7 allows but does not require)
- Cluster 6 macOS lint selective absorption (D-43-D1 default skip; may upgrade if specific diagnostic surfaces)
- Defense-in-depth wiring of newly-absorbed features into fork-only Windows surface (D-34-B2 surgical-retrofit; future phase if needed)
- Latest-stable MSRV (1.86+) — user explicitly rejected for this cycle
