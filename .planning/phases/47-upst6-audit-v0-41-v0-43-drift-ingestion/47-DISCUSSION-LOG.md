# Phase 47: UPST6 audit + v0.41–v0.43 drift ingestion - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-23
**Phase:** 47-upst6-audit-v0-41-v0-43-drift-ingestion
**Areas discussed:** Audit upper bound (UPST6), Ledger layout & plan slicing, v0.41–v0.43 backfill scope/purpose, Cross-cluster re-export hardening

---

## Area Selection

**Question:** Which gray areas do you want to discuss for Phase 47?

| Option | Description | Selected |
|--------|-------------|----------|
| Audit upper bound (UPST6) | v0.55.0 vs v0.57.0 vs HEAD-anchor vs hybrid (with explicit upstream_head_at_audit aux). 19 post-v0.57.0 unreleased commits at upstream HEAD 807fca38. | ✓ |
| Ledger layout & plan slicing | One ledger with two range sections vs two separate ledgers + single plan vs two plans. | ✓ |
| v0.41–v0.43 backfill scope/purpose | Pure paper-trail / active surface for cherry-picks Phase 34 missed / tool-validation only. | ✓ |
| Cross-cluster re-export hardening | Phase 47 SC#3 closes the cluster-isolation-invalid lesson. Bump file count only vs add explicit re-export surface diff. | ✓ |

**User's choice:** ALL FOUR areas selected (multi-select).

---

## Audit upper bound (UPST6) — 4 questions

### Q1: What's the UPST6 audit upper bound?

| Option | Description | Selected |
|--------|-------------|----------|
| v0.57.0 (~75 cmts, +19 deferred) | Clean tag boundary; matches Phase 42 D-42-A1 reproducibility discipline. 19 commits past v0.57.0 deferred to UPST7. | ✓ |
| v0.55.0 (narrow; ROADMAP literal) | Strict literal of ROADMAP "v0.54.0..v0.55.0+" — but 0.55 shipped months ago. ~30 cmts. v0.56.0 + v0.57.0 + post (~63 cmts) deferred. | |
| upstream/main HEAD 807fca38 | Full-snapshot HEAD-anchor. Captures post-v0.57.0 churn. Breaks Phase 33/39/42 reproducibility-against-tag-pair convention. | |
| v0.56.0 (mid; ~55 cmts) | Intermediate tag boundary. v0.57.0 (~20 cmts) + post-v0.57.0 deferred. | |

**User's choice:** v0.57.0
**Notes:** Range = `v0.54.0..v0.57.0`, ~75 cross-platform non-merge commits across 3 minor releases.

### Q2: Frontmatter shape — capture v0.57.0 boundary plus auxiliary HEAD anchor?

| Option | Description | Selected |
|--------|-------------|----------|
| Both: range + upstream_head_at_audit | Inherits Phase 42 D-42-A2 verbatim. range: v0.54.0..v0.57.0; upstream_head_at_audit: <40-char sha at first commit of audit plan>. Latter is the historical signal that lets UPST7 reconstruct what was punted. | ✓ |
| Range only (drop the HEAD aux) | Pure tag-pair audit. Cleaner frontmatter; loses post-tag deferral signal. | |
| Range + 19-commit post-v0.57.0 list inline | Capture the 19 post-v0.57.0 commits explicitly in a deferred-to-UPST7 ledger subsection. More work, more signal. | |

**User's choice:** Both: range + upstream_head_at_audit
**Notes:** Locked → D-47-A2.

### Q3: Anchor lock timing (when do we capture upstream_head_at_audit)?

| Option | Description | Selected |
|--------|-------------|----------|
| First commit of UPST6 audit plan | Inherits Phase 42 D-42-A3 verbatim. Auditor runs `git fetch upstream --tags` then captures `upstream/main` SHA as FIRST act of the plan. New upstream commits during audit week → UPST7. | ✓ |
| Phase 47 open / CONTEXT-commit | Lock at this CONTEXT.md commit (would be 807fca38). Loses in-plan auditable-act discipline. | |
| Plan-phase open | Capture at /gsd-plan-phase 47 start. Earlier than D-42-A3 — less likely to drift but no explicit git-fetch-tags act. | |

**User's choice:** First commit of UPST6 audit plan
**Notes:** Locked → D-47-A3. Backfill ledger uses same lock timing at Plan 47-02 first commit.

### Q4: Post-v0.57.0 commits handling — strictly silent (Phase 42 D-42-A4 inheritance) or audit-watch addendum?

| Option | Description | Selected |
|--------|-------------|----------|
| Strictly silent (D-42-A4 inheritance) | Ledger does NOT mention the 19 post-v0.57.0 commits. UPST7 absorbs. Preserves audit-boundary discipline; matches Phase 42/39/33 cadence. | ✓ |
| Audit-watch addendum at bottom of ledger | Add a `## Post-v0.57.0 audit-watch` section listing the 19 commits as informational UPST7 prioritization signal. Slightly muddies the boundary. | |
| Silent on ledger, but list in CONTEXT.md deferred section | Compromise: ledger stays clean, but CONTEXT.md `<deferred>` section enumerates the 19. | |

**User's choice:** Strictly silent (D-42-A4 inheritance)
**Notes:** Locked → D-47-A4. UPST7 absorbs the inventory on the next cycle.

---

## Ledger layout & plan slicing — 4 questions

### Q1: Ledger artifact layout for the two audit ranges?

| Option | Description | Selected |
|--------|-------------|----------|
| TWO separate ledgers | DIVERGENCE-LEDGER.md (UPST6, v0.54.0..v0.57.0) + DIVERGENCE-LEDGER-v041-v043-backfill.md. Each ledger has its own frontmatter, own range, own ADR review / empirical cross-check. | ✓ |
| ONE ledger, two range sections | Single DIVERGENCE-LEDGER.md with `## Range A: v0.54.0..v0.57.0 (UPST6)` and `## Range B: v0.41.0..v0.43.0 (backfill cleanup)` sections. One frontmatter with two ranges. | |
| ONE primary ledger + backfill subsection | Primary DIVERGENCE-LEDGER.md for UPST6; `## Appendix: v0.41–v0.43 drift backfill` subsection. | |

**User's choice:** TWO separate ledgers
**Notes:** Locked → D-47-B1. Cleanest separation; each ledger has distinct framing (parity-sync vs backfill-cleanup).

### Q2: Plan slicing — single plan or two?

| Option | Description | Selected |
|--------|-------------|----------|
| Two plans (one per ledger) | Plan 47-01-UPST6-AUDIT (v0.54.0..v0.57.0; ~75 commits) + Plan 47-02-V041-V043-BACKFILL (~19 commits). Each ledger has its own SUMMARY.md disposition record. | ✓ |
| Single plan covering both ledgers | Plan 47-01-DIVERGENCE-AUDIT writes both ledgers. Inherits Phase 42 D-42-B1 default verbatim. Tighter context. | |
| Three plans (UPST6 audit + backfill audit + ADR review consolidation) | Adds Plan 47-03 for cross-cutting ADR review verdict if both audits produce conflicting evidence. | |

**User's choice:** Two plans (one per ledger)
**Notes:** Locked → D-47-B2.

### Q3: Plan ordering / parallelism — sequential or parallel?

| Option | Description | Selected |
|--------|-------------|----------|
| Sequential: UPST6 first, then backfill | Plan 47-01-UPST6-AUDIT runs first (load-bearing for Phase 48); Plan 47-02-BACKFILL runs after. Backfill is paper-trail — can wait. | ✓ |
| Parallel — both plans concurrent | Both audits read upstream tags independently; no shared state besides drift-tool sha. Faster wall-clock; mixes framings in working memory. | |
| Sequential: backfill first, then UPST6 | Run backfill first as DRIFT-tool warmup / validation against known-absorbed range. Unusual ordering. | |

**User's choice:** Sequential: UPST6 first, then backfill
**Notes:** Locked → D-47-B3. UPST6 is the load-bearing artifact for Phase 48; sequence it first.

### Q4: Phase 47 close-gate — both ledgers must close, or load-bearing UPST6 only?

| Option | Description | Selected |
|--------|-------------|----------|
| BOTH ledgers must close (strict) | Phase 47 close-gate requires UPST6 ledger AND backfill ledger fully dispositioned. REQ-UPST6-01 + REQ-DRIFT-INGEST-01 both satisfied at phase close. | ✓ |
| UPST6 strict, backfill best-effort | UPST6 ledger close is load-bearing for Phase 48; backfill ledger close is best-effort with deferral to UPST7 if anything surfaces. | |
| Stage-gate: UPST6 ledger close → Phase 48 unblocked; backfill close at Phase 48 sync time | Decouple gates. UPST6 audit close unblocks Phase 48 plan-phase; backfill close becomes Phase 48's parallel audit task. | |

**User's choice:** BOTH ledgers must close (strict)
**Notes:** Locked → D-47-B4. REQ-DRIFT-INGEST-01 already deferred at v2.3 scope-lock 2026-04-29 — second slip unacceptable.

---

## v0.41–v0.43 backfill scope/purpose — 4 questions

### Q1: What's the primary purpose of the v0.41–v0.43 backfill audit?

| Option | Description | Selected |
|--------|-------------|----------|
| Paper-trail + surface missed cherry-picks | Document the historical absorption via DRIFT-01/02 tooling AND surface any commits Phase 34 missed. Any missed-surface flagged for Phase 48 absorption. Maps to ROADMAP SC#4. | ✓ |
| Pure paper-trail (no Phase 48 hand-off) | Document via DRIFT tooling for compliance/REQ closure. Treat Phase 34 absorption as authoritative; no missed-surface check. | |
| Tool-validation exercise primarily | Goal is to exercise DRIFT-01/02 against a known-absorbed range to catch any tool bugs. Findings drive `.planning/quick/` spawns. | |

**User's choice:** Paper-trail + surface missed cherry-picks
**Notes:** Locked → D-47-C1.

### Q2: Missed-cherry-pick detection methodology — how do we identify what Phase 34 absorbed?

| Option | Description | Selected |
|--------|-------------|----------|
| Subject-line + diff fingerprint match against fork main | For each upstream commit in v0.41.0..v0.43.0, search fork main for matching subject OR diff fingerprint. Manual judgment for ambiguous matches. Robust against trailer-less pre-D-19 absorption. | ✓ |
| Strict trailer match only | Only commits with `Upstream-commit: <sha>` trailers count as absorbed. | |
| Phase 22/34 SUMMARY.md cross-reference | Read Phase 22 + 34 plan SUMMARYs to enumerate what they claimed to absorb; compare to v0.41-v0.43 commit set. | |
| Hybrid: trailer match + diff fingerprint fallback | Trailer match for the 11 known D-19 trailers; diff fingerprint match for the rest. | |

**User's choice:** Subject-line + diff fingerprint match against fork main
**Notes:** Locked → D-47-C2. Only 11 unique Upstream-commit: trailers in fork main; most Phase 22/34 absorptions are trailer-less.

### Q3: Backfill ledger disposition vocabulary — same as UPST6 or backfill-specific?

| Option | Description | Selected |
|--------|-------------|----------|
| Same vocab: will-sync / fork-preserve / won't-sync / split | Use the standard 4-disposition vocabulary. `will-sync` semantics disambiguated in rationale + `absorbed-via:` column. | ✓ |
| Backfill-specific vocab | Introduce `already-absorbed` / `missed-absorb` / `intentionally-skipped` / `not-applicable` to make backfill framing explicit. | |
| Standard vocab + `absorbed-via:` column | Keep 4-disposition vocab AND add an `absorbed-via:` column to commit-row tables. Belt-and-suspenders. | |

**User's choice:** Same vocab: will-sync / fork-preserve / won't-sync / split
**Notes:** Locked → D-47-C3. Note: D-47-C3 ALSO incorporates the `absorbed-via:` column (combines the chosen option with the column from the rejected belt-and-suspenders option — auditor's judgment during write-context).

### Q4: Backfill ledger — needs `## ADR review` + empirical cross-check sections too?

| Option | Description | Selected |
|--------|-------------|----------|
| ADR review NO, empirical cross-check YES | Backfill is paper-trail — skip ADR review verdict. Keep empirical cross-check ≥4 files to satisfy SC#3 closure. | ✓ |
| Both sections required (matches UPST6 shape) | Backfill ledger gets BOTH ADR review with per-cell L/M/H verdicts AND empirical cross-check ≥4 files. | |
| Neither — backfill is pure tabular paper-trail | Drop both sections; backfill ledger is just frontmatter + cluster summary + commit-row tables. | |

**User's choice:** ADR review NO, empirical cross-check YES
**Notes:** Locked → D-47-C4.

---

## Cross-cluster re-export hardening — 4 questions

### Q1: How should the cluster-isolation-invalid closure manifest in the UPST6 ledger?

| Option | Description | Selected |
|--------|-------------|----------|
| File walk ≥4 + explicit re-export surface diff | Empirical cross-check picks ≥4 fork-shared files AND for each `will-sync` cluster's lead commit, run `git diff --name-only` PLUS scan for `pub use` / `pub mod` / `extern` declarations that re-export symbols from OUTSIDE the cluster's files. Surface any cross-cluster re-export deps inline. | ✓ |
| File walk ≥4 only (matches Phase 47 SC#3 literal) | Bump empirical cross-check from ≥3 (Phase 42) to ≥4 (Phase 47 SC#3). No explicit re-export diff pass. | |
| File walk ≥4 + re-export scan + cross-cluster dependency graph | Full upgrade: file walk + re-export scan PLUS produce a cluster-dependency graph (Mermaid or table) showing which clusters import/re-export symbols from which other clusters. | |
| File walk ≥4 + targeted re-export scan only on multi-file clusters | Bump to ≥4 files + run re-export scan only on clusters with >5 files OR involving `crates/nono/src/trust/`. | |

**User's choice:** File walk ≥4 + explicit re-export surface diff
**Notes:** Locked → D-47-D1. Directly closes `feedback_cluster_isolation_invalid` memory lesson.

### Q2: Re-export diff trigger — every `will-sync` cluster, or selectively?

| Option | Description | Selected |
|--------|-------------|----------|
| Every `will-sync` cluster's lead commit | Run re-export surface scan against EVERY `will-sync` cluster's lead commit. Uniform discipline; catches the next Cluster-2-style surprise in any cluster. | ✓ |
| Only foundation-candidate / wave-hint clusters | Run scan only on clusters tagged `wave-hint: foundation` or with >50 files touched. | |
| Every cluster regardless of disposition | Run scan against EVERY cluster's lead commit including `fork-preserve` / `won't-sync` / `split` clusters. | |
| Lead commit of every cluster + any commit touching `crates/nono/src/trust/` | `will-sync` lead commits + any commit touching trust/. | |

**User's choice:** Every `will-sync` cluster's lead commit
**Notes:** Locked → D-47-D2.

### Q3: Where do re-export findings live in the ledger?

| Option | Description | Selected |
|--------|-------------|----------|
| Inline in each cluster section + summarized in `## Empirical cross-check` | Per-cluster findings appear in the cluster's body. Empirical cross-check section consolidates with a `cross-cluster re-export deps detected` summary. | ✓ |
| All findings in `## Empirical cross-check` only | Cluster sections stay clean of re-export details; all live in dedicated empirical-cross-check section. | |
| New `## Cross-cluster dependency surface` section | Dedicated top-level section enumerating every detected re-export edge between clusters. | |

**User's choice:** Inline in each cluster section + summarized in `## Empirical cross-check`
**Notes:** Locked → D-47-D3. Preserves Phase 33/39/42 audit-shape template uniformity.

### Q4: If re-export scan surfaces a cross-cluster dep, what's the default disposition response?

| Option | Description | Selected |
|--------|-------------|----------|
| Flip to `split` with explicit prerequisite enumeration | If cluster X's lead commit re-exports a symbol from cluster Y, default disposition flips to `split`: mechanically-resolvable portion delivered fork-authored; cross-cluster source migration deferred until Y is absorbed. Mirrors Phase 43 Cluster 2 precedent exactly. | ✓ |
| Stay `will-sync` with `wave-hint: depends-on cluster-Y` | Keep `will-sync` but tag the wave-hint with cluster-Y as foundation. | |
| Auditor judgment per case (no default) | Document the dep inline; let auditor judge `split` vs `will-sync-with-wave-hint` per case. | |
| Flip to `fork-preserve` until prereq cluster absorbed | Conservative: treat cross-cluster re-export deps as fork-preserve until the prereq cluster lands. | |

**User's choice:** Flip to `split` with explicit prerequisite enumeration
**Notes:** Locked → D-47-D4. `split` is the codified-at-v2.5-close vocab precisely for this empirical-prerequisite-discovery class.

---

## Claude's Discretion

Areas where auditor has discretion at audit-walk time (per CONTEXT.md `<decisions>` § Claude's Discretion):

- **Cluster grouping heuristic** — cluster boundaries during audit-walk.
- **Per-cluster `wave-hint` granularity** — whether to tag clusters with wave-hints for Phase 48 planner.
- **UPST7 stub title wording** — `… sync audit` vs `… sync execution` at Phase 47 close.
- **Whether to capture a `Fork-only surface area` delta section since Phase 42.**
- **Empirical cross-check file selection** for both UPST6 and backfill ledgers (≥4 each; recommendations in D-47-E12).
- **`make ci` re-run cadence** — once at plan close OR per-commit.
- **ADR review verdict outcome (UPST6 ledger)** — auditor judges (a) confirm / (b) amend / (c) flag future-supersede based on ~75-commit evidence base.
- **Plan 47-02 backfill plan slicing** — default = single plan; multi-plan if audit-walk surfaces wave-shape concern.
- **`absorbed-via:` column value format for ambiguous matches** on backfill ledger.

## Deferred Ideas

(Captured in CONTEXT.md `<deferred>` section)

- 19 post-v0.57.0 upstream unreleased commits → UPST7 cycle.
- Drift-tool fixes surfaced mid-audit → `.planning/quick/YYMMDD-xxx-upstream-drift-tool-fix/` quick-task per D-47-E10.
- Full wave-map for Phase 48 — Phase 47 ships foundation flag + dependency hints only.
- Fork-only surface area delta enumeration since Phase 42 — auditor's discretion.
- Superseding ADR — Phase-NN ADR if Phase 47 surfaces evidence Option A `continue` is no longer right.
- UPST7 scope — Phase 47 close picks title + queues stub.
- `Upstream-commit:` trailer backfill on already-absorbed Phase 22/34 commits — not Phase 47 scope.
- Phase 48 cherry-pick selection for backfill `unmatched` rows.
