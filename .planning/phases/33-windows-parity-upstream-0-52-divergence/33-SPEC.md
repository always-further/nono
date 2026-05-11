# Phase 33: Windows parity with upstream 0.52 features and divergence decision — Specification

**Created:** 2026-05-10
**Ambiguity score:** 0.13 (gate: ≤ 0.20)
**Requirements:** 5 locked

## Goal

Produce an audited inventory of every fork-vs-upstream divergence between v0.41 and v0.52 (`DIVERGENCE-LEDGER.md`) and a scored strategic decision ADR (`docs/architecture/upstream-parity-strategy.md`) recording whether continued parity in this repo is sustainable, or whether the Windows-only surface warrants splitting off from `always-further/nono`. The actual cherry-pick / manual-replay work implied by the decision (UPST3-sync) is OUT of this phase by construction.

## Background

The fork's last upstream sync was Phase 22 UPST2 (v0.38–v0.40, shipped 2026-04-28). Upstream `always-further/nono` is at v0.52 and has accumulated 12 minor releases of feature divergence we have not absorbed.

Phase 25's HUMAN-UAT (2026-05-10) surfaced **Gap G-25-DRIFT-01**: all four RESL flags (`--memory`, `--cpu-percent`, `--max-processes`, `--timeout`) shipped by Phase 25 are deprecated or renamed in upstream v0.52. Phase 25's source-level closure is INTACT (the cgroup v2 / setrlimit backends correctly enforce against the values they receive — backend correctness is independent of flag naming), but the user-facing CLI surface diverges from upstream documentation. All 6 of Phase 25's HUMAN-UAT tests are blocked pending the sync.

RESL flags are the only confirmed surface so far. v0.41–v0.52 spans ~12 minor versions and almost certainly contains additional renames, removals, and new features the fork hasn't absorbed. The Phase 24 DRIFT tooling (`make check-upstream-drift` + the 260428-rsu-style quick-task template) is in place but has never been run against the v0.52 baseline.

Beyond the parity gap, this phase is also the natural decision point for a strategic question that's been growing since v2.1: **the fork has accumulated significant Windows-only surface area** — broker-process architecture (Phase 31), WFP service + filtering (Phases 6/9), ConPTY shell (Phase 8/30), Authenticode chain-walker (Phase 28), Sigstore broker self-trust-anchor (Phase 32), NONO_TEST_HOME seam (Phase 27.1) — none of which has an upstream analog. Every upstream sync from here on will hit fork-only files. The question is whether continued bidirectional parity is sustainable, or whether the Windows-specific work belongs in a separate downstream that periodically pulls from upstream rather than chasing parity.

The primary deliverable that does NOT exist yet: a falsifiable audit of v0.41–v0.52 divergence AND a scored, accepted ADR resolving the parity-strategy question.

## Requirements

1. **Drift audit against v0.52**: Run `make check-upstream-drift` against the v0.52 upstream tag and produce a complete divergence inventory.
   - Current: Phase 24 shipped `check-upstream-drift` (DRIFT-01) + the 260428-rsu quick-task template (DRIFT-02). Neither has been run against v0.52. `DIVERGENCE-LEDGER.md` does not exist for v0.41–v0.52 scope.
   - Target: `DIVERGENCE-LEDGER.md` exists at the phase root (or repo-level location chosen at plan-phase); every divergence surfaced by `make check-upstream-drift` against v0.52 has one of three explicit dispositions: `will-sync` (queued for UPST3-sync follow-up), `fork-preserve` (D-19/D-20 pattern — keep fork verbatim, recorded), `won't-sync` (intentional non-port with rationale).
   - Acceptance: `make check-upstream-drift` against v0.52 baseline exits 0 after ledger is written; `DIVERGENCE-LEDGER.md` row count ≥ count of items the tool surfaced; every row has a non-empty disposition field from the three-value enum and a one-line rationale.

2. **Strategic decision ADR**: Score and decide between three named parity-strategy options.
   - Current: No ADR exists. ROADMAP Phase 33 narrative implies the decision but assigns no shape. PROJECT.md key-decisions table has no row.
   - Target: `docs/architecture/upstream-parity-strategy.md` exists with frontmatter `status: accepted` and a scoring matrix evaluating three options — (A) continue bidirectional parity in this repo, (B) split Windows-only surface into a separate downstream (`always-further/nono-windows` or equivalent) that periodically pulls from upstream, (C) freeze fork at v0.52 baseline and stop chasing upstream — on at least 4 weighted criteria (maintenance cost, security posture, user clarity, contributor velocity); picks one option with rationale.
   - Acceptance: ADR file exists at the named path; frontmatter contains `status: accepted` (not `proposed` or `draft`); the scoring matrix has all three options scored on the same criteria; the chosen option has a "Decision" section with rationale; alternatives are recorded with the reason they were rejected. Falsifiable: a reader can re-audit the scoring matrix without re-reading the rationale.

3. **PROJECT.md key-decisions row**: Surface the decision so it's discoverable from the project root.
   - Current: PROJECT.md key-decisions table has no row for upstream-parity-strategy.
   - Target: PROJECT.md key-decisions table gains one row referencing the ADR (date, decision name, chosen option, one-line summary, ADR link). Same shape as existing rows for REQ-WRU-01 / SHELL-01.
   - Acceptance: PROJECT.md grep finds the row; row's ADR link resolves to the file written under REQ-2.

4. **G-25-DRIFT-01 cross-reference**: Phase 25's open gap row is updated to reference this phase's output.
   - Current: G-25-DRIFT-01 in `.planning/phases/25-cross-platform-resl-aipc-unix-design/25-HUMAN-UAT.md` is `status: open` with `Recommended follow-up: UPST3 — Upstream v0.41–v0.52 Parity Sync`. No back-link to Phase 33.
   - Target: G-25-DRIFT-01 row updated to add: (a) reference to `DIVERGENCE-LEDGER.md` entry covering the 4 RESL flag renames, (b) reference to the parity-strategy ADR, (c) note that the gap stays open until the UPST3-sync follow-up phase lands the actual flag renames (Phase 33 does NOT close G-25-DRIFT-01 by itself).
   - Acceptance: Grep for `G-25-DRIFT-01` in Phase 25's HUMAN-UAT finds the cross-references; gap status remains `open`; closure handoff to the follow-up phase is explicit.

5. **Sync deferral plan**: The UPST3-sync follow-up phase is queued in ROADMAP with audit-driven scope.
   - Current: ROADMAP has only Phase 33; no UPST3-sync placeholder. Audit findings would otherwise sit in the ledger with no execution owner.
   - Target: ROADMAP.md gains a new placeholder phase entry (Phase 34 or next available number, exact slot decided at plan-phase) titled `UPST3 — Upstream v0.41–v0.52 Sync Execution` with `Goal: [To be planned] — execute the cherry-picks and manual replays catalogued in Phase 33's DIVERGENCE-LEDGER.md per the parity-strategy ADR`. Plans count = 0. Marked as `Depends on: Phase 33`. If the ADR picks option (B) or (C), the placeholder is replaced with the corresponding work (split-execution or freeze-bookkeeping).
   - Acceptance: ROADMAP.md grep finds the new placeholder phase; its "Depends on" line references Phase 33; the ledger entries with disposition `will-sync` are explicitly assigned to that phase.

## Boundaries

**In scope:**
- Run `make check-upstream-drift` against the v0.52 upstream tag and produce `DIVERGENCE-LEDGER.md` with full coverage of flagged items.
- Write `docs/architecture/upstream-parity-strategy.md` with scored options, picked option, rationale, and `status: accepted`.
- Add the PROJECT.md key-decisions row.
- Cross-reference Phase 25's G-25-DRIFT-01 gap entry to point at this phase's outputs.
- Queue the UPST3-sync follow-up phase placeholder in ROADMAP.md.

**Out of scope:**
- **Any actual cherry-picks, manual replays, or code changes that close divergences.** — Phase 33 is audit + decision only; execution work is always a separate phase per the gate decided in interview round 3. The reasoning: keeps Phase 33 reviewable in one PR, lets the ADR be reviewed without bundled implementation, and protects against scope creep if the audit surfaces more divergence than expected.
- Closing G-25-DRIFT-01. — The RESL flag renames are the most visible part of the divergence but they're sync work, not audit work. G-25-DRIFT-01 closes when the UPST3-sync follow-up phase lands the actual renames.
- Phase 25 HUMAN-UAT re-validation. — Same reasoning as G-25-DRIFT-01. The blocked UAT tests stay blocked until the sync executes.
- Cross-platform parity sweep beyond the audit. — Linux/macOS-specific upstream changes not affecting Windows are inventoried but not pre-prioritized over Windows-affecting changes within this phase.
- Decisions on whether specific divergences should be `fork-preserve` vs `will-sync` at the individual-row level. — Plan-phase / execute-phase handles per-row dispositions during the audit walk; SPEC.md only requires that EVERY row gets ONE of the three valid dispositions.
- Mock-Fulcio fixture work / Phase 32 carry-forward items. — Tracked in `.planning/quick/` and v2.4 deferreds; Phase 33 doesn't touch them.

## Constraints

- **`crates/nono/` byte-identical (D-19 invariant) continues.** No library changes ride along with the audit/decision artifacts.
- **D-19/D-20 fork-preserve pattern locked for sync follow-up.** Where the ledger marks `fork-preserve`, the rationale must reference D-19 (no library change) or D-20 (manual replay because cherry-pick would delete fork-only code, per Phase 26 Plan 26-01 PKGS-02 precedent).
- **No interactive merges in this phase.** Audit is read-only against upstream tags; no `git pull --no-commit` or merge commits land. The drift tool already operates this way.
- **`make check-upstream-drift` is the source of truth for "what diverged."** Hand-audits supplement but do not replace tool output. If the tool misses something, that's a tool fix (potentially folded into the UPST3-sync follow-up), not a Phase 33 scope expansion.
- **ADR uses the existing ADR convention.** Mirrors `docs/architecture/aipc-unix-futures.md` (Phase 25 Plan 25-02), `docs/architecture/audit-bundle-target.md` (Phase 27.2 Plan 27.2-03), `docs/architecture/broker-trust-anchor.md` (Phase 32 Plan 32-05): frontmatter with `status:`, problem statement, options, decision, consequences, alternatives.
- **No new clippy/test failures.** Standard project gate: `make ci` passes after the phase's commits land. Since the phase ships only docs + ledger + ROADMAP edits, this should be uneventful but is non-negotiable.

## Acceptance Criteria

- [ ] `make check-upstream-drift` against the v0.52 upstream tag exits 0 after the phase's final commit lands.
- [ ] `DIVERGENCE-LEDGER.md` exists at the path locked in plan-phase; every row carries a disposition from the enum {`will-sync`, `fork-preserve`, `won't-sync`} and a one-line rationale; row count ≥ count of items the drift tool flagged.
- [ ] `docs/architecture/upstream-parity-strategy.md` exists with frontmatter `status: accepted`.
- [ ] The ADR scoring matrix evaluates all three named options (continue / split-windows / freeze-at-v0.52) on the same ≥4 weighted criteria.
- [ ] The ADR has a "Decision" section naming the chosen option and a "Consequences" section.
- [ ] PROJECT.md key-decisions table has a new row referencing the ADR (grep-discoverable).
- [ ] Phase 25's `25-HUMAN-UAT.md` G-25-DRIFT-01 entry cross-references both `DIVERGENCE-LEDGER.md` and the strategy ADR; gap status remains `open` with explicit handoff to the UPST3-sync follow-up phase.
- [ ] ROADMAP.md has a new placeholder phase entry for UPST3-sync (or the corresponding work if the ADR picks option B/C) with `Depends on: Phase 33`.
- [ ] `make ci` passes (clippy + fmt + tests) after the final commit.

## Ambiguity Report

| Dimension          | Score | Min  | Status | Notes                                                            |
|--------------------|-------|------|--------|------------------------------------------------------------------|
| Goal Clarity       | 0.92  | 0.75 | ✓      | Audit + decision must-ship; sync always deferred                 |
| Boundary Clarity   | 0.92  | 0.70 | ✓      | "Always defer sync" locks boundary cleanly                       |
| Constraint Clarity | 0.72  | 0.65 | ✓      | D-19/D-20 preserve pattern; drift tool = source of truth         |
| Acceptance Criteria| 0.85  | 0.70 | ✓      | Tool exit + dispositioned ledger + ADR accepted + key-decisions row |
| **Ambiguity**      | 0.13  | ≤0.20| ✓      | Gate passed after Round 3                                        |

Status: ✓ = met minimum, ⚠ = below minimum (planner treats as assumption)

## Interview Log

| Round | Perspective       | Question summary                          | Decision locked                                                                                                          |
|-------|-------------------|-------------------------------------------|--------------------------------------------------------------------------------------------------------------------------|
| 1     | Researcher        | Primary deliverable: sync vs decision?    | Both — coupled in one phase, two waves                                                                                   |
| 1     | Researcher        | Audit scope: RESL-only or full v0.41–v0.52? | Full v0.41–v0.52 audit via `make check-upstream-drift`                                                                   |
| 1     | Researcher        | Policy for fork-vs-upstream conflicts?    | Preserve fork (D-19/D-20 pattern); record in DIVERGENCE-LEDGER.md                                                       |
| 2     | Researcher        | Wave ordering?                            | Audit → Decide → Sync (data-driven decision)                                                                             |
| 2     | Simplifier        | Decision artifact shape?                  | Scored ADR with 3 named options (continue / split-windows / freeze-at-v0.52) on ≥4 weighted criteria; picks one         |
| 2     | Simplifier        | Minimum viable if 50% cut?                | Audit + decision only; cherry-picks deferrable                                                                           |
| 3     | Boundary Keeper   | Audit done-check?                         | `make check-upstream-drift` exits 0 + DIVERGENCE-LEDGER.md disposition-complete (3-value enum: will-sync/fork-preserve/won't-sync) |
| 3     | Boundary Keeper   | Sync gating: in-phase or always-defer?    | **Always defer sync** — Phase 33 = audit + decision only; sync is always a separate follow-up phase                     |
| 3     | Boundary Keeper   | "Decision is locked" definition?          | ADR file `status: accepted` + PROJECT.md key-decisions row, both in phase's commit chain                                |

---

*Phase: 33-windows-parity-upstream-0-52-divergence*
*Spec created: 2026-05-10*
*Next step: /gsd-discuss-phase 33 — implementation decisions (drift-tool invocation specifics, ADR scoring weights, ledger location, UPST3-sync follow-up phase numbering)*
