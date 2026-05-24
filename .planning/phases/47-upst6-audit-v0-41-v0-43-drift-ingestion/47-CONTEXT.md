---
phase: 47
phase_name: upst6-audit-v0-41-v0-43-drift-ingestion
gathered: 2026-05-23
status: Ready for planning
requirements_locked_via: REQUIREMENTS.md § REQ-UPST6-01 + REQ-DRIFT-INGEST-01 (no SPEC.md — audit-only phase mirrors Phase 33 + 39 + 42 audit-shape template, extended with the v0.41–v0.43 backfill second-ledger pattern unique to this phase)
---

# Phase 47: UPST6 audit + v0.41–v0.43 drift ingestion - Context

**Gathered:** 2026-05-23
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 47 ships TWO artifacts (per D-47-B1 two-ledger layout):

1. **`.planning/phases/47-upst6-audit-v0-41-v0-43-drift-ingestion/DIVERGENCE-LEDGER.md`** — UPST6 cycle audit covering upstream `v0.54.0..v0.57.0` (~75 cross-platform non-merge commits across 3 minor releases: v0.55.0 `35f9fea2`, v0.56.0 `b251c72f`, v0.57.0 `10cec984`). Mirrors Phase 33 + 39 + 42 audit-shape verbatim, with the Phase 47 SC#3 cluster-isolation-invalid closure mechanism layered on top (D-47-D1..D4 below). Includes `## ADR review` per-cell L/M/H verdicts on the 5 Phase 33 ADR dimensions (security/windows/maintenance/divergence/contributor) and `## Empirical cross-check` ≥4 fork-shared files. This ledger is the binding input for Phase 48's cherry-pick selection.

2. **`.planning/phases/47-upst6-audit-v0-41-v0-43-drift-ingestion/DIVERGENCE-LEDGER-v041-v043-backfill.md`** — Long-deferred v0.41.0..v0.43.0 drift backfill (~19 cross-platform commits). First real load of the v2.2 Phase 24 DRIFT-01/02 tooling on this range (deferred at v2.3 scope-lock 2026-04-29). Framed as "backfill-cleanup, not parity-sync" per ROADMAP. Per-commit `absorbed-via` status against the historical Phase 22 + 34 absorption record (pre-D-19 trailer convention era — only 11 unique `Upstream-commit:` trailers exist in fork main). Surfaces any cherry-picks Phase 34 missed for Phase 48 absorption alongside UPST6 work. Includes `## Empirical cross-check` ≥4 files (D-47-C4); SKIPS `## ADR review` (D-47-C4 — retroactive paper-trail does not warrant fresh Option A `continue` verdict).

Phase 47 ships ZERO `crates/` / `bindings/` / `scripts/` source edits (audit-only output; D-39-E5 / D-42-E7 Windows-only-files invariant trivially honored — Phase 47 touches only `.planning/` artifacts).

**Foundation context for UPST6 audit-walk (informational; auditor confirms during walk):** ~75 commits is substantially larger than Phase 42's 18 (v0.53.0..v0.54.0). Drift-tool category preview suggests likely cluster themes will include continued pack-management evolution (v0.55+ extends v0.54.0's `nono update` + pinning/outdated surface), additional platform-detection / registry / `platform.rs` deltas (Phase 43 absorbed `0748cced` + `5d821c12` + Cluster 2 source migration via Phase 45 Plans `f640528a..d21399e3`; v0.55+ may iterate further on the absorbed surface), and the 3 release commits (v0.55.0/v0.56.0/v0.57.0) per the Phase 34/40 release-ride convention. Phase 47 auditor produces the authoritative cluster grouping.

**In scope:**
- Run `make check-upstream-drift ARGS="--from v0.54.0 --to v0.57.0 --format json"` at phase-start (Plan 47-01 first commit) and curate themed clusters with per-cluster disposition + rationale.
- Run `make check-upstream-drift ARGS="--from v0.41.0 --to v0.43.0 --format json"` for the backfill ledger (Plan 47-02 first commit). Windows-host dispatch via `bash scripts/check-upstream-drift.sh` per Phase 33/42 precedent if `make` is not on PATH.
- Write `DIVERGENCE-LEDGER.md` (UPST6) mirroring Phase 42 two-tier schema (cluster headers + nested commit-row tables) with `windows-touch: yes/no` column (D-42-C1 inherited as D-47-A5).
- Write `DIVERGENCE-LEDGER-v041-v043-backfill.md` (backfill) using the SAME 4-disposition vocab (`will-sync` / `fork-preserve` / `won't-sync` / `split`) and the same two-tier schema (D-47-C3). Backfill ledger adds an `absorbed-via:` column to commit-row tables (per-commit status from the historical Phase 22 + 34 record).
- Apply D-42-C3 conservative-default fork-preserve to UPST6 `windows-touch: yes` clusters unless empty fork-side.
- **Explicit `## ADR review` section on UPST6 ledger with per-cell L/M/H verdict on Phase 33 ADR Option A `continue`.** ~75 commits is a substantial evidence base; auditor verdicts (a) confirm, (b) amend with carve-outs, or (c) flag a future-supersede trigger per the Phase 42 D-42-C4 outcome menu.
- **Empirical cross-check ≥4 fork-shared files PLUS explicit re-export surface diff on every `will-sync` cluster's lead commit (D-47-D1/D2/D3/D4).** Closes the `feedback_cluster_isolation_invalid` lesson hardened at v2.5 close. Findings appear inline in each cluster section + summarized in `## Empirical cross-check`.
- Both ledgers' close-gate satisfied at Phase 47 close (D-47-B4 — strict). REQ-UPST6-01 and REQ-DRIFT-INGEST-01 both closed at the same close-event.
- Sequential plan ordering: Plan 47-01 (UPST6) runs first; Plan 47-02 (backfill) runs after Plan 47-01 closes (D-47-B3).
- Update `.planning/STATE.md` at phase close.
- Queue a UPST7 placeholder phase entry in `ROADMAP.md` per D-42-B4 inheritance (auditor's call at plan-phase between v2.6 backlog vs v2.6 § Future Cycles holding section; recommendation: v2.6 § Future Cycles since v2.6 is the active milestone).

**Out of scope (route elsewhere or explicitly defer):**
- **Any actual cherry-picks, manual replays, or code changes** — Phase 48 is the execution phase by construction; Phase 47 is audit-only.
- **Post-v0.57.0 upstream commits** — 19 unreleased commits between v0.57.0 `10cec984` and upstream/main HEAD `807fca38` at context-capture time. Strictly silent per D-47-A4 (inherits D-42-A4). UPST7 absorbs.
- **Strategic ADR rewrite** — Phase 33 ADR Option A `continue` stays Accepted until explicitly superseded. Phase 47 UPST6 ledger verdicts (confirm or amend) but does NOT supersede.
- **Backfill `## ADR review` section** — backfill is retroactive paper-trail on a 2-year-old range; fresh ADR verdict on it adds no signal beyond the UPST6 verdict (D-47-C4).
- **Drift-tool fixes surfaced mid-audit** — documented inline + spawn `.planning/quick/` follow-up task per D-42-D3 inheritance (carried forward); Phase 47 itself stays untouched to preserve `drift_tool_sh_sha` reproducibility.
- **Full wave-map for Phase 48** — Phase 47 ledger ships foundation flag + dependency hints only (D-42-B3 inherited as D-47-B5); Phase 48 planner decides full Wave 0/1/2/... mapping.
- **`Upstream-commit:` trailer backfill on already-absorbed Phase 22/34 commits** — backfill ledger reports the `absorbed-via:` status as historical paper-trail; it does NOT rewrite fork-main commits to add D-19 trailers retroactively (that would require interactive rebase on long-published history; unacceptable).
- **Baseline-aware CI gate work** — done by Phase 46 (REQ-CI-FU-03 closed; baseline SHA `3f638dc6` per `.planning/templates/upstream-sync-quick.md:102`). Phase 48 inherits this baseline; Phase 47 has no CI concern (zero source edits).

</domain>

<decisions>
## Implementation Decisions

### Audit invocation, scope, and reproducibility (Area A — discussed)

- **D-47-A1:** **UPST6 upper bound = `v0.57.0` clean tag boundary, not upstream HEAD.** Audit range = `v0.54.0..v0.57.0` (sha `10cec984`, ~75 non-merge cross-platform commits; 3 minor releases — v0.55.0 `35f9fea2`, v0.56.0 `b251c72f`, v0.57.0 `10cec984`). Inherits Phase 33 + 39 + 42 pattern: clean reproducibility against tag pair. ~75 commits is substantially larger than Phase 42's 18 but still tractable in one audit cycle. Post-v0.57.0 commits (19 known at context-capture time, between `10cec984` and upstream/main HEAD `807fca38`) roll into UPST7. **User explicitly rejected** narrow `v0.55.0` (stale ROADMAP wording; misses ~63 commits), mid `v0.56.0` (defers ~20 commits unnecessarily), and HEAD-anchor `807fca38` (breaks tag-pair reproducibility convention).

- **D-47-A2:** **Frontmatter captures BOTH `range` AND `upstream_head_at_audit`.** Inherits D-42-A2 verbatim:
  - `range: v0.54.0..v0.57.0`
  - `upstream_head_at_audit: <40-char sha captured at first commit of Plan 47-01>`
  - `drift_tool_sh_sha: 0834aa664fbaf4c5e41af5debece292992211559` (Phase 24 ship sha; unchanged through Phase 33 + 39 + 42)
  - `drift_tool_ps1_sha: 0834aa664fbaf4c5e41af5debece292992211559`
  - `drift_tool_invocation: 'make check-upstream-drift ARGS="--from v0.54.0 --to v0.57.0 --format json"'`
  - `fork_baseline: v0.54.0 (Phase 43 + 45 UPST5 sync point — Cluster 5 0748cced/5d821c12 + Cluster 2 8b888a1c source migration absorbed 2026-05-18..2026-05-20)`
  - `date: 2026-MM-DD`
  Raw drift JSON is NOT committed (D-33-A2 inherited; output redirects to `ci-logs-local/drift/` per `.gitignore`); the ledger is the canonical artifact. The auxiliary `upstream_head_at_audit` is the historical signal that lets UPST7 reconstruct what was punted (19 commits at context-capture; will likely grow before Plan 47-01 first commit). **User explicitly rejected** `range only` and `range + 19-commit post-v0.57.0 list inline` (the latter would muddy D-47-A4 strictly-silent boundary; UPST7 absorbs the inventory).

- **D-47-A3:** **Lock at first commit of Plan 47-01.** Auditor runs `git fetch upstream --tags` then captures `upstream/main` sha into UPST6 ledger frontmatter (`upstream_head_at_audit`) as the FIRST act of Plan 47-01. Range = `v0.54.0..v0.57.0`; the lock records post-fetch HEAD for reproducibility against the historical fetch state. Matches Phase 33 D-33-A1+A2 / Phase 39 D-39-D1 / Phase 42 D-42-A3 cadence verbatim. New upstream commits landing during the audit week are ignored; they roll into UPST7. **Backfill ledger lock timing identical:** auditor captures `upstream_head_at_audit` (re-runs `git rev-parse upstream/main`) as the FIRST act of Plan 47-02. For the backfill, the HEAD-anchor is informational (range `v0.41.0..v0.43.0` is fully historical), but the field stays in frontmatter for schema uniformity with UPST6. **User explicitly rejected** earlier lock points (CONTEXT-commit, plan-phase-open) — first-commit-of-plan preserves the discipline of fetching tags as an explicit auditable act in the plan's commit history.

- **D-47-A4:** **Strictly silent on post-v0.57.0 commits.** UPST6 ledger covers `v0.54.0..v0.57.0` only. Anything past `10cec984` is UPST7's problem; mentioning it would muddy the audit boundary. Inherits D-39-A3 / D-42-A4 verbatim. The cadence rule is structural — each audit closes a defined range, next audit picks up where this one left off. **User explicitly rejected** the `audit-watch addendum` shape and the `CONTEXT-only deferred enumeration` shape. UPST7 absorbs the 19 known post-v0.57.0 commits on the next cycle.

- **D-47-A5 (= Phase 33/39/42 inheritance D-33-B3 / D-39-E4 / D-42-E6):** **Standard row schema = `sha + subject + upstream-tag + categories + files-changed-count + windows-touch`.** Disposition + rationale live at the CLUSTER level, not per-row. Backfill ledger appends an `absorbed-via:` column to commit-row tables (D-47-C3); UPST6 ledger uses the base schema (no `absorbed-via:` since UPST6 commits are by definition not-yet-absorbed pending Phase 48 selection).

### Ledger layout, plan slicing, and close-gate (Area B — discussed)

- **D-47-B1:** **TWO separate ledgers (UPST6 + v0.41–v0.43 backfill).** UPST6 cycle ships `DIVERGENCE-LEDGER.md` in the phase dir; backfill ships `DIVERGENCE-LEDGER-v041-v043-backfill.md` alongside. Each ledger has its own frontmatter, own range, own cluster summary table, own empirical cross-check. UPST6 ledger has `## ADR review`; backfill ledger does NOT (D-47-C4). Cleanest separation between the two framings (parity-sync vs backfill-cleanup); UPST6 ledger feeds Phase 48 cherry-pick selection; backfill ledger documents cleanup with optional missed-cherry-pick surface for Phase 48. **User explicitly rejected** single-ledger-two-sections (mixes two framings in one artifact) and primary-ledger-with-appendix (treats backfill as satellite — but it's its own deferred requirement REQ-DRIFT-INGEST-01, not a UPST6 subordinate).

- **D-47-B2:** **TWO plans (one per ledger).** Plan 47-01-UPST6-AUDIT writes `DIVERGENCE-LEDGER.md` (v0.54.0..v0.57.0). Plan 47-02-V041-V043-BACKFILL writes `DIVERGENCE-LEDGER-v041-v043-backfill.md`. Each plan has its own SUMMARY.md disposition record. Diverges from Phase 42 D-42-B1 single-plan default — but Phase 42 had ONE ledger; Phase 47 has TWO with distinct framings. Plan slicing tracks artifact slicing. **User explicitly rejected** single-plan-covering-both (mixes two framings in one plan's working memory) and three-plans-with-ADR-consolidation (over-sliced; defer to multi-plan only if audit-walk surfaces conflict between the two audits' evidence).

- **D-47-B3:** **Sequential plan ordering: UPST6 first, then backfill.** Plan 47-01-UPST6-AUDIT runs first (load-bearing for Phase 48 cherry-pick selection). Plan 47-02-V041-V043-BACKFILL runs after Plan 47-01 closes. Cleaner blast radius; backfill is paper-trail with optional missed-cherry-pick surface — it can wait. Each plan keeps full context-window for its own framing (parity-sync vs backfill-cleanup) without interleaving. **User explicitly rejected** parallel-concurrent (mixes two framings in working memory) and backfill-first-as-tool-validation (unusual ordering; UPST6 is the load-bearing artifact for Phase 48 — sequence it first).

- **D-47-B4:** **Phase 47 close-gate = BOTH ledgers must fully disposition.** REQ-UPST6-01 AND REQ-DRIFT-INGEST-01 both satisfied at phase close (strict gate). Cleanest gate; matches Phase 42 D-42-B2 8-check shape adapted for two ledgers:
  1. `make check-upstream-drift ARGS="--from v0.54.0 --to v0.57.0 --format json"` exits 0 AND `make check-upstream-drift ARGS="--from v0.41.0 --to v0.43.0 --format json"` exits 0 (both drift-tool invocations reproduce against locked ranges).
  2. UPST6 ledger row count ≥ drift-tool `total_unique_commits` for v0.54.0..v0.57.0; backfill ledger row count ≥ drift-tool `total_unique_commits` for v0.41.0..v0.43.0 (exact coverage, zero gap).
  3. Every cluster in BOTH ledgers has disposition (`will-sync` / `fork-preserve` / `won't-sync` / `split`) + one-line rationale.
  4. **UPST6 ledger `## ADR review` section present AND verdicts with per-cell L/M/H** — ~75-commit evidence base; verdict is (a) confirm, (b) amend with carve-outs, or (c) flag future-supersede trigger. Falsifiable via grep for the section header + per-cell verdict format. **Backfill ledger does NOT require this section** (D-47-C4).
  5. **Empirical cross-check ≥4 fork-shared files on BOTH ledgers** (D-47-D1 raises ≥3 → ≥4 per Phase 47 SC#3). UPST6 ledger ALSO requires explicit re-export surface diff on every `will-sync` cluster's lead commit (D-47-D2); backfill ledger requires file walk only (no re-export diff since backfill commits are historical, not load-bearing for Phase 48 wave structure).
  6. ROADMAP UPST7 stub committed (per D-42-B4 inheritance — auditor's call between v2.6 backlog vs v2.6 § Future Cycles holding section).
  7. STATE.md updated.
  8. `make ci` substitute: `git diff --name-only HEAD~N..HEAD -- crates/ bindings/ scripts/ | wc -l` == 0 (Phase 47 ships zero source-tree edits — structurally zero clippy/fmt/test risk; D-42-E7 invariant trivially honored).
  No cross-target clippy gate needed (Phase 25 CR-A lesson) — Phase 47 touches zero `.rs` files.
  **User explicitly rejected** load-bearing-UPST6-only (risks REQ-DRIFT-INGEST-01 slipping again — already deferred at v2.3 scope-lock 2026-04-29; second slip unacceptable) and stage-gate-UPST6-close-unblocks-Phase-48-and-backfill-becomes-Phase-48-task (breaks REQ-DRIFT-INGEST-01 → Phase 47 mapping in ROADMAP).

- **D-47-B5 (= Phase 42 D-42-B3 inheritance):** **Disposition-complete at Phase 47 close + foundation/dependency hints.** Every cluster's disposition is locked at Phase 47 close — Phase 48 inherits immutable input. UPST6 ledger MAY tag the largest/most-foundational cluster as `wave-hint: foundation`; Phase 47 planner may flag cluster dependencies inline (e.g., `wave-hint: depends-on cluster-N final state`). Phase 48 planner has full discretion to refine wave membership; Phase 47 hints are advisory, not prescriptive. Backfill ledger's missed-cherry-pick candidates (if any) are flagged for Phase 48 absorption alongside UPST6 work; backfill `wave-hint` not required.

### v0.41–v0.43 backfill scope and methodology (Area C — discussed)

- **D-47-C1:** **Backfill purpose = paper-trail + surface missed cherry-picks.** Document the historical absorption via DRIFT-01/02 tooling AND surface any commits Phase 34 missed (since Phase 34 pre-dated D-19 `Upstream-commit:` trailer convention — only 11 unique trailers exist in fork main vs the much-larger Phase 22 + 34 absorption scope). Any missed-cherry-pick candidates flagged for Phase 48 absorption alongside UPST6 work, per ROADMAP SC#4: "resolves the deferral by confirming no fork-side action needed OR flags any cherry-picks worth absorbing in Phase 48". **User explicitly rejected** pure-paper-trail-no-Phase-48-handoff (treats Phase 34 absorption as authoritative without verification; weaker confidence — Phase 22/34 plan-claim drift could have left commits unabsorbed) and tool-validation-only (drift-tool has been re-run successfully on 3+ ranges since Phase 24 ship; tool-validation byproduct not the primary aim).

- **D-47-C2:** **Missed-cherry-pick detection = subject-line + diff fingerprint match against fork main.** For each upstream commit in v0.41.0..v0.43.0, search fork main for a commit with matching subject line OR matching diff fingerprint. Manual auditor judgment for ambiguous matches (e.g., upstream subject reworded fork-side, diff partially absorbed, etc.). Robust against trailer-less pre-D-19 absorption (most of Phase 22/34 absorbed commits will have no `Upstream-commit:` trailer). **User explicitly rejected** strict-trailer-match-only (would show ~all 19 commits as unmatched since pre-D-19 era — excessive false-positive cherry-pick candidates for Phase 48), Phase-22/34-SUMMARY.md-cross-reference-only (authoritative-by-doc; vulnerable to scope drift between plan-claim and actual absorbed-commit), and hybrid-trailer-plus-fingerprint (over-engineered; the subject+fingerprint walk subsumes the trailer match — trailers fall out as a bonus when present).

- **D-47-C3:** **Backfill ledger disposition vocabulary = SAME as UPST6: `will-sync` / `fork-preserve` / `won't-sync` / `split`.** Standard 4-disposition vocab (the 4th `split` codified at v2.5 close per memory `feedback_cluster_isolation_invalid`). For backfill, `will-sync` semantics is disambiguated in per-commit rationale + `absorbed-via:` column on commit-row tables:
  - `absorbed-via: phase-22-plan-XX-commit-XXXXXXXX` → already-absorbed, paper-trail confirms (`will-sync` retroactive)
  - `absorbed-via: phase-34-plan-XX-commit-XXXXXXXX` → already-absorbed via Phase 34 UPST3
  - `absorbed-via: unmatched` → missed by Phase 22/34; Phase 48 absorbs as new cherry-pick (`will-sync` forward-looking)
  - `absorbed-via: intentionally-skipped` → never absorbed by design (e.g., upstream-only macOS lint fix) (`won't-sync`)
  - `absorbed-via: fork-divergence` → fork chose different implementation; `fork-preserve` with rationale
  Keeps the audit-shape template uniform across all 4 audit phases (33/39/42/47). **User explicitly rejected** backfill-specific-vocab (introduces `already-absorbed` / `missed-absorb` / `intentionally-skipped` as first-class dispositions — diverges from Phase 33/39/42 template; harder to read across audits) and standard-vocab-without-`absorbed-via:`-column (loses per-commit traceability against Phase 22/34 historical record).

- **D-47-C4:** **Backfill ledger has `## Empirical cross-check` YES, `## ADR review` NO.** Backfill is retroactive paper-trail on a 2-year-old range (Phase 22 ship 2026-01-XX, Phase 34 ship 2026-04-XX); fresh ADR verdict on it adds no signal beyond the UPST6 verdict. Phase 33 ADR Option A `continue` decision was rationale-based on the cherry-pick cadence; the backfill range was already absorbed by the older Phase 22+34 pre-D-19 mechanism — retroactively re-verdicting that absorption against the ADR adds nothing. Empirical cross-check ≥4 files stays YES (D-47-D1) to satisfy Phase 47 SC#3 closure across BOTH ledgers (cluster-isolation-invalid lesson applies retroactively too — Phase 34 may have hit re-export deps it didn't recognize). **User explicitly rejected** both-sections-required (wasted prose; ADR verdict on retroactive look-back is unlikely to differ from UPST6 verdict) and neither-section (drops empirical cross-check; loses cluster-isolation-invalid closure signal — REGRESSES Phase 47 SC#3).

### Cross-cluster re-export hardening (Area D — discussed)

- **D-47-D1:** **Closure mechanism = file walk ≥4 fork-shared files PLUS explicit re-export surface diff on every `will-sync` cluster's lead commit (UPST6 ledger).** Closes the `feedback_cluster_isolation_invalid` lesson hardened at v2.5 close into `split` as a valid fourth audit-cluster disposition. The empirical cross-check section MUST contain BOTH:
  - (a) The Phase 42-style ≥4 fork-shared file walk (Phase 47 SC#3 raises ≥3 → ≥4; bumps Phase 42 D-42-E1).
  - (b) For each `will-sync` cluster's lead commit, run `git diff --name-only` PLUS scan for `pub use` / `pub mod` / `extern crate` / `pub(crate)` declarations that re-export symbols from OUTSIDE the cluster's files. Surface any cross-cluster re-export deps inline in the cluster section.
  Audit-walk discovers the same shape Phase 43 hit empirically with Cluster 2 (`8b888a1c` re-exporting `public_key_id_hex` + `sign_statement_bundle` in `crates/nono/src/trust/mod.rs` from prerequisite upstream commits the fork hadn't absorbed). **User explicitly rejected** file-walk-≥4-only (ROADMAP-literal; weaker structural prevention against another Cluster-2-style empirical surprise), file-walk-plus-full-cluster-dependency-graph (heaviest audit-walk overhead; Mermaid/table format adds maintenance burden for marginal additional signal beyond inline-per-cluster + summary), and targeted-re-export-scan-on-multi-file-clusters-only (misses smaller cluster surprises — `8b888a1c` was a single commit but with foundation-class scope; size-threshold heuristic doesn't generalize).

- **D-47-D2:** **Re-export scan runs on EVERY `will-sync` cluster's lead commit.** Uniform discipline; catches the next Cluster-2-style surprise in any cluster regardless of size or foundation-status. ~75 commits in v0.54.0..v0.57.0 likely yields 7-10 clusters; scanning each `will-sync` cluster's lead commit is bounded audit-walk overhead. **User explicitly rejected** foundation-only (misses non-foundation surprises; Cluster 2 size was empirically discovered AFTER the cluster was already designated foundation candidate — pre-classification heuristic doesn't generalize), every-cluster-regardless-of-disposition (redundant for `fork-preserve` / `won't-sync` / `split` clusters we won't cherry-pick), and lead-commit-plus-anything-touching-trust/ (special-cases the Phase 43 hot zone but Cluster 2 the next time may touch a different module — hot-zone enumeration doesn't generalize).

- **D-47-D3:** **Re-export findings live inline in each cluster section + summarized in `## Empirical cross-check`.** Per-cluster findings appear in the cluster's body (under the disposition + rationale block, before the commit-row table) as a `**Cross-cluster re-export check:**` subsection naming any detected re-export deps + the prereq cluster(s). Empirical cross-check section consolidates with a `## Cross-cluster re-export deps detected` summary subsection listing all detected edges (source cluster → prereq cluster + symbol). Reader sees strategic disposition + empirical dep graph at the cluster level. **User explicitly rejected** all-findings-in-empirical-cross-check-only (cleaner cluster headers but forces reader to jump back-and-forth to correlate cluster disposition with re-export status) and dedicated-top-level-Cross-cluster-dependency-surface-section (highest signal density but biggest deviation from Phase 33/39/42 audit-shape template — uniformity preferred).

- **D-47-D4:** **If re-export scan surfaces a cross-cluster dep, default disposition response = flip to `split` with explicit prerequisite enumeration.** If cluster X's lead commit re-exports a symbol from cluster Y (where cluster X and cluster Y are both within the v0.54.0..v0.57.0 range), disposition flips from `will-sync` (or whatever was the initial mechanical assignment) to `split`. Mechanically-resolvable portion (workspace edits, trivial absorbable surface) delivered fork-authored; cross-cluster source migration deferred until cluster Y is absorbed (typically via a subsequent UPST cycle). Mirrors Phase 43 Cluster 2 precedent exactly (workspace-only edits via Plan 43-01b; source migration deferred to Phase 45 once prerequisite upstream commits became available). Rationale recorded in cluster section as `**Prerequisite enumeration:**` line listing cluster Y's lead commit + the re-exported symbol(s). **User explicitly rejected** stay-will-sync-with-wave-hint-depends-on-cluster-Y (Phase 43 abort scenario — the dep was discovered AT cherry-pick time, not pre-flight; risks repeating the abort), auditor-judgment-per-case-no-default (most flexible; weakest structural prevention — same as not having a default), and flip-to-fork-preserve-until-prereq-cluster-absorbed (conservative but over-defers; `split` is the codified-at-v2.5-close vocabulary precisely for this empirical-prerequisite-discovery class).

### Carry-Forward From Phase 33 + 39 + 42 (still binding)

- **D-47-E1 (= Phase 33 D-33-A1/A2 / Phase 39 D-39-E1 / Phase 42 D-42-E3):** Drift-tool invocation in ledger frontmatter is the audit-of-record; raw JSON not committed; reproducible against tag pair + drift-tool sha.
- **D-47-E2 (= Phase 33 D-33-B1 / Phase 39 D-39-E2 / Phase 42 D-42-E4):** Phase-local ledger location. UPST6 ledger AND backfill ledger both in `.planning/phases/47-upst6-audit-v0-41-v0-43-drift-ingestion/`. No cross-phase append.
- **D-47-E3 (= Phase 33 D-33-B2 / Phase 39 D-39-E3 / Phase 42 D-42-E5):** Two-tier structure (cluster headers + nested commit-row tables); reader sees strategic disposition at a glance via cluster headers; commit-level audit trail in nested tables. Applies to BOTH ledgers.
- **D-47-E4 (= D-47-A5 / Phase 42 D-42-E6):** Row schema documented in D-47-A5 above (backfill adds `absorbed-via:` column per D-47-C3).
- **D-47-E5 (= Phase 22 D-17 / Phase 34 D-34-E1 / Phase 39 D-39-E5 / Phase 42 D-42-E7):** Windows-only files structurally invariant. Phase 47 does not edit `*_windows.rs` or `exec_strategy_windows/`. Trivially honored (Phase 47 ships only docs + ROADMAP edits).
- **D-47-E6 (= Phase 33 ADR cadence rule / Phase 39 D-39-E6 / Phase 42 D-42-E8):** "Per upstream release, lazily-evaluated" — Phase 47 closes when v0.54.0..v0.57.0 (UPST6) AND v0.41.0..v0.43.0 (backfill) are fully dispositioned; UPST7 fires when next upstream release ships or maintainer decides cherry-pick labor warrants absorbing accumulated post-v0.57.0 commits (19 known at context-capture).
- **D-47-E7 (= Phase 46 close-gate baseline):** Baseline-aware CI gate baseline SHA = `3f638dc6` per `.planning/templates/upstream-sync-quick.md:102`. Phase 48 (NOT Phase 47 — Phase 47 ships zero source edits) inherits this as the gate reference for `success → failure` regression detection.
- **D-47-E8 (= Phase 33 D-33-C4 ADR review section convention / Phase 39 D-39-C4 / Phase 42 D-42-C4 / D-42-E10):** Explicit `## ADR review` section in UPST6 ledger MANDATORY with per-cell L/M/H verdicts. Per-cell L/M/H verdict on each of the 5 dimensions (security / windows / maintenance / divergence / contributor). Backfill ledger SKIPS this section (D-47-C4). ~75-commit evidence base is substantially larger than Phase 42's 18; auditor verdict (a) confirm, (b) amend with carve-outs, or (c) flag future-supersede.
- **D-47-E9 (= Phase 42 D-42-D2 / Phase 39 D-39-D2):** Post-lock upstream commits → UPST7 absorbs them. If a security-relevant upstream commit lands between Phase 47 close and Phase 48 start, Phase 47 ledgers stay frozen. Phase 48 plan-phase may re-run `make check-upstream-drift` if urgency demands faster turnaround — that's a Phase 48 scope re-evaluation, NOT a Phase 47 retroactive edit. Default: UPST7 is the absorption vehicle.
- **D-47-E10 (= Phase 42 D-42-D3 / Phase 39 D-39-D3):** Drift-tool bugs documented inline + spawn `.planning/quick/` follow-up task. If the auditor discovers a drift-tool bug mid-phase (category miscategorized, file filter misses a cross-platform path, etc.), the audit ledger documents the bug inline AND the auditor creates a quick-task entry under `.planning/quick/YYMMDD-xxx-upstream-drift-tool-fix/`. Phase 47 stays untouched to preserve `drift_tool_sh_sha` reproducibility. **Backfill ledger is the most likely source of drift-tool feedback** — first real load on a long-deferred range is exactly the scenario where tool gaps surface; auditor should be alert to category miscategorizations or file-filter blind spots on the v0.41-v0.43 inventory.
- **D-47-E11 (= Phase 42 D-42-B4):** UPST7 ROADMAP queue location TBD — auditor decides at plan-phase. Recommendation: v2.6 § Future Cycles holding section (v2.6 is the active milestone; UPST7 is structurally a v2.7+ cycle but the cadence trigger reference belongs in the current milestone's ROADMAP). Stub shape inherits Phase 42 D-42-B4:
  - Title: `UPST7 — Upstream v0.57.0… sync audit` (or `… sync execution` if next cycle's commit set is small enough to skip a dedicated audit; auditor's call at Phase 47 close)
  - `Depends on: Phase 48`
  - `Plans: 0 / TBD`
  - Cross-reference to `docs/architecture/upstream-parity-strategy.md` § Future audit cadence
- **D-47-E12 (= Phase 42 D-42-E2 / Phase 41 delta surface awareness):** **Phase 43 + 45 delta surface awareness.** Phase 43 + 45 landed substantial fork-side changes since Phase 42's audit boundary:
  - Cluster 5 absorption: `0748cced feat(platform): implement robust windows platform detection` + `5d821c12 fix(platform): correctly parse windows registry dword values` + `ce06bd59 feat(profile): add platform-conditional profile fields` (introducing `crates/nono-cli/src/platform.rs`)
  - Cluster 2 absorption (split closure): Phase 45 Plan 45-01 commits `f640528a..d21399e3` (workspace edits via Phase 43 Plan 43-01b + source migration via Phase 45 Plan 45-01; cluster fully synchronized with upstream `79715aa5`)
  - AIPC G-04 wire-protocol tightening (Phase 45 Plan 45-02 REQ-AIPC-G04-01)
  - Linux/macOS RESL native re-validation (Phase 45 REQ-RESL-NIX-04)
  - Phase 46 windows-squash merge (REQ-MERGE-01) → post-merge baseline `3f638dc6`
  Empirical cross-check + re-export scan should preferentially sample files in `crates/nono-cli/src/platform.rs`, `crates/nono/src/trust/`, and AIPC schema files since those are the highest-risk surfaces for further upstream drift.

### Folded Todos

[None — `cross_reference_todos` step skipped. Phase 47 is an audit-only phase; no implementation todos pending.]

### Claude's Discretion

- **Cluster grouping heuristic.** D-47-E3 says cluster related commits; cluster boundaries are the auditor's judgment call during the audit walk. Likely clusters in v0.54.0..v0.57.0 will be auditor-confirmed at audit-walk; the audit-walk produces the authoritative cluster grouping.
- **Per-cluster `wave-hint` granularity.** D-47-B5 allows but does not require wave hints on every cluster. Auditor decides whether a cluster's wave shape is interesting enough to flag.
- **UPST7 stub title wording.** D-47-E11 names two candidate titles (`… sync audit` vs `… sync execution`). Auditor picks at Phase 47 close based on UPST6 ledger shape — if dispositions are simple and the next cycle could be a single-plan execution phase without a separate audit, title flips to `… sync execution`. Otherwise default to `… audit`.
- **Whether to capture a `Fork-only surface area` delta section.** Phase 33 enumerated 6+ fork-only Windows seams; Phase 39 + 42 referenced unchanged. Phase 47 may add a § Delta-since-Phase-42 fork-only surface section IF Phase 43 + 45 + 46 introduced meaningful new fork-only Windows surface affecting audit interpretation. Auditor judges at audit walk.
- **Empirical cross-check file selection (UPST6 ledger).** D-47-D1 requires ≥4 fork-shared files; auditor picks which. Recommendation in D-47-E12 to preferentially sample `crates/nono-cli/src/platform.rs`, `crates/nono/src/trust/`, AIPC schema files, and files touched by Phase 45 Plan 45-01 source-migration commits.
- **Empirical cross-check file selection (backfill ledger).** D-47-C4 requires ≥4 fork-shared files for the backfill ledger too. Recommendation: preferentially sample files most-likely-to-have-been-touched-by-Phase-22/34 absorption (e.g., `crates/nono/src/policy.rs`, `crates/nono/src/audit.rs`, `crates/nono-cli/src/profile/`, depending on Phase 22/34 SUMMARY scope).
- **`make ci` re-run cadence.** Standard project gate (D-47-B4 step 8) — auditor may run the `git diff --name-only` substitute once at plan close OR per-commit if curation surfaces any tooling change concerns. Either is acceptable.
- **ADR review verdict outcome (UPST6 ledger).** D-47-E8 offers three outcomes ((a) confirm, (b) amend with carve-outs, (c) flag future-supersede). Auditor judges based on ~75-commit evidence base. **Provisional expectation (auditor confirms or revises):** (a) confirm with updated per-cell verdicts reflecting empirical evidence that the absorbed Cluster 2 + Cluster 5 (Phase 43 + 45) closed the v2.5 windows-platform-detection risk. Larger evidence base may surface new amend candidates.
- **Plan 47-02 backfill plan slicing.** D-47-B2 ships Plan 47-02 as single plan; planner may override to multi-plan only if audit-walk surfaces a wave-shape concern. Default = single plan.
- **`absorbed-via:` column value format for ambiguous matches.** D-47-C3 lists 5 standard values; auditor uses `absorbed-via: ambiguous-see-cluster-rationale` for cases where subject-line matched but diff fingerprint partially differs (e.g., Phase 22/34 absorbed the commit with a fork-side rework). Per-commit rationale block captures the disambiguation.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase 47 scope sources
- `.planning/REQUIREMENTS.md` § REQ-UPST6-01 — Acceptance criteria (DIVERGENCE-LEDGER.md inventory for `v0.54.0..v0.55.0+` with per-cluster dispositions + `## ADR review` per-cell L/M/H verdict table on 5 dimensions; outcome confirms or revises Phase 33 ADR Option A `continue` strategy). Phase 47 D-47-A1 refines `<anchor>` to `v0.57.0` clean tag boundary.
- `.planning/REQUIREMENTS.md` § REQ-DRIFT-INGEST-01 — Acceptance criteria (Upstream `v0.41`–`v0.43` ingestion executed via DRIFT-01/02 tooling; backfill cleanup not parity-sync; inventory + per-cluster dispositions recorded). First real load of v2.2 DRIFT tooling.
- `.planning/ROADMAP.md` § Phase 47 — Goal, depends-on Phase 46, success criteria (5 items including SC#3 empirical cross-check ≥4 fork-shared files closing the `feedback_cluster_isolation_invalid` lesson), reference list.
- `.planning/PROJECT.md` § v2.6 milestone scope.

### Phase 42 audit-shape template (PRIMARY reference — Phase 47 mirrors verbatim with two-ledger extension + D-47-D1..D4 re-export hardening)
- `.planning/phases/42-upst5-audit/42-CONTEXT.md` — D-42-A1..D-42-E10 decision IDs. Phase 47 D-47-A1..A5 inherit D-42-A1..A4 + D-42-E6 (with D-47-A1 range refinement and D-47-A2 fork_baseline update to v0.54.0 post-Phase-43+45); D-47-B1..B5 are net-new (two-ledger / two-plan / sequential / strict-both-close / disposition-complete hints); D-47-C1..C4 are net-new (backfill-specific); D-47-D1..D4 raise Phase 42 D-42-E1 + close the cluster-isolation-invalid lesson; D-47-E1..E12 inherit Phase 42 carry-forwards verbatim except E11 (UPST7 stub location refined).
- `.planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md` — **the worked example.** 18 commits / 7 clusters / `windows-touch:yes` first-fire cycle / `## ADR review` per-cell L/M/H verdicts / `## Empirical cross-check` ≥3 fork-shared files / Cluster 2 marked `split` with Phase 43+45 disposition resolution amendment. Phase 47 UPST6 ledger mirrors this shape with raised empirical-cross-check ≥4 files + re-export surface diff layered on top.
- `.planning/phases/42-upst5-audit/42-01-PLAN.md` — single-plan structure (Phase 47 diverges to two-plan per D-47-B2).
- `.planning/phases/42-upst5-audit/42-01-SUMMARY.md` — Phase 42 close-gate verification methodology (drift-tool re-run idempotence, ledger row count == drift-tool total_unique_commits, ADR review grep-confirmable, ROADMAP UPST6 stub committed, STATE.md updated).

### Phase 43 split disposition precedent (LOAD-BEARING for D-47-D4)
- `.planning/phases/43-upst5-sync-execution/43-CONTEXT.md` — Cluster 2 foundation wrinkle context; D-43-A1..A4 wave structure; D-43-B1 atomic-MSRV bump-with-edition.
- `.planning/phases/43-upst5-sync-execution/43-01-EDITION-2024-FOUNDATION-SUMMARY.md` — **BLOCKED — Rule 4 architectural checkpoint** status; the empirical discovery that proved Phase 42 cluster isolation invalid (`8b888a1c` re-exports `public_key_id_hex` + `sign_statement_bundle` from prerequisite upstream commits the fork hadn't absorbed; 98 files touched vs 86 estimated; 87 conflict markers across 40 source files; 10 fork-deleted-by-us / upstream-modified files). This summary is the canonical artifact of the lesson Phase 47 D-47-D1..D4 closes.
- `.planning/phases/43-upst5-sync-execution/43-01b-EDITION-WORKSPACE-ONLY-SUMMARY.md` — `split` disposition execution mechanism: mechanically-resolvable portion (workspace `Cargo.toml` MSRV bump + `[workspace.dependencies]` centralization + per-crate `.workspace = true` switches) delivered fork-authored; source migration deferred. Template for D-47-D4 `split` flip-to default.
- `.planning/phases/45-source-migration-aipc-g04-resl-nix/45-CONTEXT.md` (or equivalent Phase 45 artifact) — closure: source-file edition-2024 migration absorbed via Phase 45 Plan 45-01 commits `f640528a..d21399e3`. Cluster 2 fully synchronized with upstream `79715aa5`. (Read at audit-walk to confirm absorbed-fork-state baseline.)

### Phase 33 + 39 audit-shape template ROOTS (Phase 47 inherits transitively via Phase 42)
- `.planning/phases/33-windows-parity-upstream-0-52-divergence/33-SPEC.md` — 5 requirements + acceptance criteria for the audit-shape template; Phase 47 mirrors REQ-1 inheritance.
- `.planning/phases/33-windows-parity-upstream-0-52-divergence/33-CONTEXT.md` — D-33-A1..D-33-D2 decision IDs.
- `.planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md` — 300-line ledger with frontmatter + Headline + Reproduction + Cluster Summary table + 12 cluster sections + Fork-only surface area section + `## ADR review` section.
- `.planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md` — 22-commit precedent with `windows-touch` column zero-fire reference shape.

### Phase 40 + 34 execution-shape templates (inform Phase 48 disposition decisions; Phase 47 ledger feeds these)
- `.planning/phases/40-upst4-sync-execution/40-CONTEXT.md` — D-40-A1..E5 (wave structure, baseline-aware CI gate, Windows-only-files invariant + 4-condition addendum exception rule). Phase 47's dispositions feed Phase 48's wave structure.
- `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md` — D-34-A1..E5 (per-cluster plan slicing, foundation gate, fork-preserve handling). **Phase 34 is the historical absorption record for v0.41–v0.43 backfill range** — auditor reads Phase 34 SUMMARYs (Plans 34-01..34-XX) to enumerate what was claimed-absorbed and reconcile with the drift-tool inventory.

### v0.41–v0.43 backfill historical absorption record (Phase 22 + 34)
- `.planning/phases/22-upst2-upstream-v038-v040-parity-sync/` — Phase 22 UPST2 absorbed v0.38..v0.40; some v0.41 commits may have been absorbed here if Phase 22 scope spilled forward (auditor verifies).
- `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/` — Phase 34 UPST3 absorbed v0.41..v0.52 explicitly. All v0.41-v0.43 commits in scope for Phase 34's absorption. Auditor reads each Plan 34-XX SUMMARY to enumerate the historical absorption.
- **Note on D-19 trailer convention era:** Phase 22 + 34 pre-dated the D-19 `Upstream-commit:` trailer convention (introduced Phase 34/40 era; only 11 unique trailers exist in fork main currently). Subject-line + diff-fingerprint match (D-47-C2) is the load-bearing detection methodology for the backfill ledger's `absorbed-via:` column.

### Strategic ADR (LOCKED — Phase 47 UPST6 ledger MUST verdict but NOT supersede)
- `docs/architecture/upstream-parity-strategy.md` — **Phase 33 strategic ADR, `Status: Accepted` 2026-05-11, re-confirmed at v2.4 close per D-39-C4, re-confirmed at v2.5 close per D-42-C4 verdict.** Option A `continue` chosen. § Future audit cadence defines the "per upstream release, lazily-evaluated" rule. Phase 47 UPST6 ledger's § ADR review section MUST verdict with per-cell L/M/H (D-47-E8); ~75-commit evidence base is the largest yet — auditor judges (a) confirm / (b) amend / (c) flag future-supersede.

### Drift-tool infrastructure (Phase 24)
- `scripts/check-upstream-drift.sh` + `scripts/check-upstream-drift.ps1` — Drift-tool twin scripts. Sha `0834aa664fbaf4c5e41af5debece292992211559` (Phase 24 ship sha; unchanged since 2026-04-29 through Phase 33 + 39 + 42). Phase 47 invokes via `make check-upstream-drift` or `bash scripts/check-upstream-drift.sh` if `make` is not on PATH (Phase 33/39/42 precedent).
- `Makefile` § `check-upstream-drift` target — dispatches platform-appropriate script.
- `.planning/phases/24-parity-drift-prevention/24-CONTEXT.md` — D-04..D-19 drift-tool decisions (categorization D-05, range auto-detect D-08, fork-only filter D-11, JSON schema D-07). D-11 path filter on `*_windows.rs` + `exec_strategy_windows/` is the key invariant Phase 47 honors; D-42-C1/C2/C3 windows-touch detection layered on top.
- `docs/cli/development/upstream-drift.mdx` — long-form runbook.

### Sync execution mechanics (referenced by Phase 48; Phase 47 references for context)
- `.planning/templates/upstream-sync-quick.md` — MANDATORY scaffold for every Phase 48 plan; D-19 cherry-pick trailer block (verbatim 6-line shape with lowercase `Upstream-author:`); **baseline SHA `3f638dc6` per Phase 46 close** (line 102). Phase 47 does NOT use this directly (no cherry-picks); Phase 48 plans inherit it from the Phase 34 + 40 + 43 pattern.
- `.planning/templates/cross-target-verify-checklist.md` — Phase 41 Class F template; Phase 48 plan-phase references for cross-target clippy verification.

### Phase 46 close-gate context (Phase 47 inherits clean post-merge baseline; Phase 48 uses it as CI gate reference)
- `.planning/phases/46-windows-squash-merge-post-merge-ci-verifications-uat-backlog/46-VERIFICATION.md` — Phase 46 close gate; baseline-aware CI gate reset, baseline registry updated to `3f638dc6`, all 8 lanes diff vs `13cc0628` with zero load-bearing success→failure. Phase 47 inherits this as "clean baseline" precondition.
- `.planning/phases/46-windows-squash-merge-post-merge-ci-verifications-uat-backlog/46-CONTEXT.md` — D-46-A1..C3 windows-squash merge + post-merge CI + UAT backlog dispositions.

### Operative memory entries (load-bearing for Phase 47)
- Memory `feedback_cluster_isolation_invalid` — **DIVERGENCE-LEDGER cluster isolation can be empirically false; lesson hardened at v2.5 close into `split` as a valid fourth audit-cluster disposition. UPST plan-phase must diff-inspect re-export surfaces, not just `--name-only`.** Directly closed by D-47-D1..D4.
- Memory `project_workspace_crates` — nono workspace has 5 crates (not 3); CLAUDE.md is stale. Workspace-touching upstream commits (likely a v0.54.0..v0.57.0 cluster) MUST be analyzed against all 5 `Cargo.toml` files. Auditor applies this lens during audit-walk.
- Memory `project_cross_fork_pr_pattern` — fork uses ONE umbrella PR to upstream (Phase 22+34+40+43 pattern). Phase 48 will inherit this; Phase 47 audit-walk should preserve cluster boundaries that map cleanly to a single Phase 48 umbrella PR's contribution sections.
- Memory `feedback_clippy_cross_target` — cross-target clippy enforced via CLAUDE.md MUST/NEVER. Phase 47 trivially honors (zero `.rs` edits); Phase 48 must observe per cluster's `windows-touch` column.

### Coding & security standards
- `CLAUDE.md` § Coding Standards — no `.unwrap()`, DCO sign-off (`Signed-off-by:` lines), `#[must_use]` on critical Results, env-var save/restore in tests. Phase 47 ships only docs; trivially honored.
- `CLAUDE.md` § Security Considerations — path component comparison, fail-secure on any unsupported shape. Phase 47's audit interpretation lens for any cluster that touches path canonicalization, trust scanning, or symlink validation (e.g., upstream's `66c69f86 fix(snapshot): validate restore targets against symlinks` absorbed by Phase 43 Plan 43-02; v0.55+ may iterate on this surface).
- `CLAUDE.md` § Cross-target clippy verification — Phase 41 close-gate codifies; Phase 47 trivially honors (zero `.rs` edits), Phase 48 must observe.

### Upstream source (git-resolvable from `upstream` remote at `https://github.com/always-further/nono.git`)
- Tag `v0.54.0` (`6b00932f`) — Phase 47 UPST6 lower bound + Phase 43+45 absorption sync point.
- Tag `v0.55.0` (`35f9fea2`) — UPST6 intermediate.
- Tag `v0.56.0` (`b251c72f`) — UPST6 intermediate.
- Tag `v0.57.0` (`10cec984`) — Phase 47 UPST6 upper bound.
- Tag `v0.41.0` — Phase 47 backfill lower bound (sha resolved at Plan 47-02 first commit).
- Tag `v0.43.0` — Phase 47 backfill upper bound (sha resolved at Plan 47-02 first commit).
- Upstream HEAD at context-capture time: `807fca38` (2026-05-23; 19 post-v0.57.0 commits visible). Phase 47 Plan 47-01 locks `upstream_head_at_audit` at first commit of Plan 47-01 (D-47-A3) — may shift from this value if upstream commits land before Plan 47-01 starts. Range stays `v0.54.0..v0.57.0` regardless.

### v2.6 milestone context
- `.planning/STATE.md` — current milestone v2.6 status; Phase 47 follows Phase 46 close.
- `.planning/PROJECT.md` § v2.6 — milestone scope, key decisions.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets

- **`make check-upstream-drift` tooling (Phase 24)** — `scripts/check-upstream-drift.{sh,ps1}` (sha `0834aa66`, unchanged since Phase 24 ship 2026-04-29 through Phase 33 + 39 + 42). Phase 47 invokes TWICE: once for UPST6 (Plan 47-01) at `--from v0.54.0 --to v0.57.0`, once for backfill (Plan 47-02) at `--from v0.41.0 --to v0.43.0`. Each invocation captured verbatim in respective ledger frontmatter.
- **Phase 42 DIVERGENCE-LEDGER.md as the closest worked template for UPST6 ledger.** Phase 47 UPST6 ledger replicates the shape with raised empirical-cross-check ≥4 files + re-export surface diff (D-47-D1..D4). Likely ~250-350 lines for ~75 commits / 7-10 clusters (vs Phase 42's ~150-200 for 18 commits / 7 clusters).
- **Phase 43 Cluster 2 split precedent + Phase 45 Plan 45-01 closure** — the canonical worked example of the `split` disposition execution mechanism. Workspace edits via Plan 43-01b; source migration via Phase 45 Plan 45-01 `f640528a..d21399e3`. D-47-D4 flip-to-`split` default applies this pattern preemptively when re-export scan surfaces cross-cluster deps.
- **Phase 33 ADR `docs/architecture/upstream-parity-strategy.md`** — locked Accepted, re-confirmed at v2.4 + v2.5 close. § Future audit cadence defines the cadence rule. Phase 47 UPST6 ledger § ADR review MUST verdict with per-cell L/M/H (D-47-E8); ~75-commit evidence base is largest yet.
- **Phase 46 close-gate baseline `3f638dc6`** — Phase 47 inherits clean post-merge baseline (no Phase 47 CI concern; Phase 48 uses as gate reference).
- **Phase 42 + 43 + 45 ledger amendment pattern (Cluster 2 split→closed update)** — example of how disposition can evolve post-audit-close when execution surfaces empirical evidence. D-47-D4 builds on this pattern proactively (pre-flight re-export scan) rather than reactively (post-cherry-pick discovery).

### Established Patterns

- **`upstream` git remote** at `https://github.com/always-further/nono.git`; tags v0.5.0..v0.57.0 fetched locally (verified 2026-05-23). No setup work.
- **Phase-local ledger convention (D-33-B1 / D-39-E2 / D-42-E4 / D-47-E2).** Each audit phase owns its ledger artifact(s) in its phase dir. Phase 47 owns TWO ledgers in one dir; no cross-phase append.
- **D-11 fork-only Windows filter (Phase 24 D-08).** Drift tool excludes `*_windows.rs` and `crates/nono-cli/src/exec_strategy_windows/`. Phase 47 must STILL detect upstream commits adding NEW Windows code outside D-11 filter (D-42-C1/C2 inherited). Phase 42 was first cycle this mattered (`0748cced` + `5d821c12` + `ce06bd59`); Phase 47 may surface further fires depending on v0.55+ platform/registry work.
- **Two-tier ledger structure (D-33-B2 / D-39-E3 / D-42-E5 / D-47-E3).** Cluster headers carry strategic disposition; nested commit-row tables carry audit trail. Phase 33 worked example shipped in 300 lines for 97 commits / 12 clusters; Phase 39 in ~150-200 lines for 22 commits / 7 clusters; Phase 42 in ~200 lines for 18 commits / 7 clusters; Phase 47 UPST6 ledger expects ~250-350 lines for ~75 commits / 7-10 clusters; backfill ledger expects ~120-180 lines for 19 commits / 4-6 clusters.
- **Lazily-evaluated cadence (D-39-E6 / D-42-E8 / D-47-E6).** ADR § Future audit cadence rule fires per upstream release; Phase 47 absorbs 3 minor releases (v0.55.0/v0.56.0/v0.57.0) in one cycle. UPST7 fires when next upstream release ships or maintainer decides accumulated cherry-pick labor warrants firing.
- **Pre-D-19 absorption record (Phase 22 + 34 era).** Only 11 unique `Upstream-commit:` trailers in fork main (most absorptions pre-D-19). Backfill ledger's `absorbed-via:` column (D-47-C3) uses subject-line + diff fingerprint match (D-47-C2) to reconstruct against the historical Phase 22 + 34 record.

### Integration Points

- `.planning/phases/47-upst6-audit-v0-41-v0-43-drift-ingestion/DIVERGENCE-LEDGER.md` — NEW file Phase 47 creates via Plan 47-01. Phase 48 reads this as its immutable input.
- `.planning/phases/47-upst6-audit-v0-41-v0-43-drift-ingestion/DIVERGENCE-LEDGER-v041-v043-backfill.md` — NEW file Phase 47 creates via Plan 47-02. Phase 48 reads any `unmatched` rows for absorption candidates.
- `.planning/ROADMAP.md` — Phase 47 appends a UPST7 placeholder phase entry (D-47-E11; location per auditor's call at plan-phase between v2.6 backlog vs v2.6 § Future Cycles holding section).
- `.planning/STATE.md` — Phase 47 plan-close appends a "Last activity" log entry.
- `.planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md` — READ-ONLY reference. Phase 47 does NOT modify Phase 42's ledger.
- `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-XX-SUMMARY.md` (multiple) — READ-ONLY reference for backfill ledger `absorbed-via:` column reconstruction.
- `docs/architecture/upstream-parity-strategy.md` — READ-ONLY reference. Phase 47 verdicts but does NOT supersede this ADR.

### Drift signal preview (informational, NOT a disposition pre-commit)

UPST6 range `v0.54.0..v0.57.0` — auditor confirms during audit-walk:
- ~75 cross-platform non-merge commits across 3 minor releases (v0.55.0, v0.56.0, v0.57.0).
- 3 release commits (v0.55.0 `35f9fea2`, v0.56.0 `b251c72f`, v0.57.0 `10cec984`) — Phase 34/40 release-ride convention (CHANGELOG-only absorption; drop Cargo.toml + Cargo.lock version bumps).
- Likely cluster themes (auditor confirms during audit-walk):
  - Continued pack-management evolution (v0.55+ extends `nono update` + pinning/outdated from v0.54.0).
  - Additional platform-detection / registry / `platform.rs` deltas (Phase 43 + 45 absorbed v0.54.0's introduction; v0.55+ may iterate).
  - AIPC schema evolution (Phase 45 absorbed REQ-AIPC-G04-01 wire-protocol tightening; v0.55+ may introduce further schema changes).
  - Trust / signing / sigstore-verify dep bumps (recurring per memory `project_v26_opened` Phase 49 reference).
  - Snapshot symlink / restore validation iteration (Phase 43 Plan 43-02 absorbed `66c69f86`; v0.55+ may iterate).
  - Standard dep bumps (nix, tokio, cosign-installer, etc.) — Phase 42 D-42-A4-style drop-or-absorb per cluster.
  - macOS lint fixes (Phase 42 Cluster 6 `won't-sync` precedent; Phase 47 inherits unless fork's CI now surfaces matching diagnostics).
- **Cross-cluster re-export deps (D-47-D2 mandatory scan):** With ~75 commits spanning 3 releases, the likelihood of cross-cluster re-export deps (Phase 43 Cluster 2 class) is substantially higher than Phase 42. Auditor should be alert during audit-walk; D-47-D4 default flip-to-`split` applies on detection.

Backfill range `v0.41.0..v0.43.0` — auditor confirms during audit-walk:
- 19 cross-platform non-merge commits across 3 minor releases (v0.41.0, v0.42.0, v0.43.0).
- Auditor walks each Phase 34 plan SUMMARY to enumerate the historical claimed-absorption + reconcile against drift-tool inventory.
- Most-likely outcome (per ROADMAP SC#4): "resolves the deferral by confirming no fork-side action needed". Auditor may surface 0..few missed cherry-picks for Phase 48.
- Standard 4-disposition vocab applies; `absorbed-via:` column carries per-commit Phase 22/34 traceability.

These are **informational only** — the audit walk produces the authoritative cluster grouping + disposition per the methodology in D-47-A1..D-47-D4. Phase 47 plan-phase or research-phase may refine.

</code_context>

<specifics>
## Specific Ideas

- **v0.57.0 clean tag boundary** (D-47-A1) — user explicitly chose over v0.55.0 (narrow ROADMAP literal), v0.56.0 (mid), and HEAD-anchor `807fca38`. Mirrors Phase 42 D-42-A1 reproducibility-against-tag-pair discipline.
- **Frontmatter captures both range AND upstream_head_at_audit** (D-47-A2) — user explicitly rejected range-only and range+19-commit-inline-list shapes. The HEAD aux is the historical signal that lets UPST7 reconstruct what was punted.
- **First-commit-of-Plan-47-01 / Plan-47-02 lock timing** (D-47-A3) — user chose over CONTEXT-commit and plan-phase-open. Preserves discipline of `git fetch upstream --tags` as an explicit auditable act in each plan's commit history.
- **Strictly silent on post-v0.57.0 commits** (D-47-A4) — user explicitly rejected audit-watch-addendum and CONTEXT-only-deferred-enumeration shapes. UPST7 absorbs the 19 known post-v0.57.0 commits.
- **TWO ledgers, TWO plans, sequential UPST6→backfill, strict-both-must-close** (D-47-B1..B4) — user explicitly chose over single-ledger-two-sections, primary-with-appendix, single-plan, parallel-concurrent, backfill-first, and load-bearing-UPST6-only. Cleanest separation of the two distinct framings (parity-sync vs backfill-cleanup); REQ-DRIFT-INGEST-01 was already deferred at v2.3 scope-lock — second slip unacceptable.
- **Backfill purpose = paper-trail + missed-cherry-pick surface** (D-47-C1) — user explicitly chose over pure-paper-trail (weaker confidence) and tool-validation-only (drift-tool already proven on 3 ranges). Maps to ROADMAP SC#4 "confirm no fork-side action OR flag cherry-picks worth absorbing in Phase 48".
- **Subject-line + diff fingerprint match for `absorbed-via:` column** (D-47-C2) — user explicitly chose over strict-trailer-match (would over-flag pre-D-19 absorbed commits as unmatched), SUMMARY.md-cross-reference-only (vulnerable to plan-claim drift), and hybrid (over-engineered; fingerprint-walk subsumes trailer match).
- **Standard 4-disposition vocab + `absorbed-via:` column on backfill** (D-47-C3) — user explicitly chose over backfill-specific-vocab (diverges from template) and standard-vocab-no-column (loses per-commit Phase 22/34 traceability).
- **Backfill has empirical cross-check YES, ADR review NO** (D-47-C4) — user explicitly chose over both-sections-required (wasted prose on retroactive verdict) and neither-section (loses Phase 47 SC#3 cluster-isolation-invalid closure on backfill).
- **File walk ≥4 + explicit re-export surface diff on every `will-sync` cluster's lead commit (UPST6)** (D-47-D1) — user explicitly chose over file-walk-only (ROADMAP-literal; weaker structural prevention), file-walk-plus-full-dep-graph (heaviest overhead), and targeted-on-multi-file-clusters-only (size threshold doesn't generalize). Directly closes `feedback_cluster_isolation_invalid`.
- **Re-export scan runs on EVERY `will-sync` cluster's lead commit** (D-47-D2) — user explicitly chose over foundation-only (Cluster 2 was discovered foundation-class AFTER classification — heuristic doesn't generalize), every-cluster-regardless-of-disposition (redundant on non-cherry-pick clusters), and lead-commit-plus-trust/-special-case (hot-zone enumeration doesn't generalize).
- **Re-export findings inline in cluster sections + summarized in ## Empirical cross-check** (D-47-D3) — user explicitly chose over all-findings-in-empirical-only (forces back-and-forth correlation) and dedicated-Cross-cluster-dependency-surface-section (biggest deviation from audit-shape template).
- **Default response on detected cross-cluster dep = flip to `split` with explicit prerequisite enumeration** (D-47-D4) — user explicitly chose over stay-will-sync-with-wave-hint (repeats Phase 43 abort scenario), auditor-judgment-no-default (weakest prevention), and flip-to-fork-preserve-until-prereq-cluster-absorbed (over-defers; `split` is the codified-at-v2.5-close vocab for this class).

</specifics>

<deferred>
## Deferred Ideas

- **19 post-v0.57.0 upstream unreleased commits** (between v0.57.0 `10cec984` and upstream/main HEAD `807fca38` at context-capture 2026-05-23) → UPST7 cycle absorbs per the lazily-evaluated cadence rule (D-47-E6) when next upstream release ships or maintainer decides accumulated cherry-pick labor warrants firing. Inventory NOT enumerated in CONTEXT (per D-47-A4 strictly-silent invariant); auditor sees full inventory at Plan 47-01 first-commit lock time.
- **Drift-tool fixes surfaced mid-audit** — if Phase 47 audit-walk (especially the backfill ledger, which is first real load on a long-deferred range) reveals a drift-tool category miscategorization or file-filter gap, the fix lands as a `.planning/quick/YYMMDD-xxx-upstream-drift-tool-fix/` quick-task (D-47-E10), NOT folded into Phase 47.
- **Full wave-map for Phase 48** — D-47-B5 ships foundation flag + dependency hints only; Phase 48 planner decides full Wave 0/1/2/... mapping.
- **Fork-only surface area delta enumeration since Phase 42** — Phase 33 enumerated 6+ fork-only Windows seams; Phase 39 + 42 referenced unchanged. Phase 47 may add a § Delta-since-Phase-42 fork-only surface section IF Phase 43 + 45 + 46 introduced meaningful new fork-only Windows surface affecting audit interpretation. Auditor's discretion at audit walk.
- **Superseding ADR** — if Phase 47 UPST6 ledger's `## ADR review` section surfaces evidence that Option A `continue` is no longer the right call (e.g., per-cell L/M/H verdicts shift dramatically given ~75-commit evidence base), that's a Phase-NN superseding ADR, NOT a Phase 47 inline edit. Phase 33 ADR stays `Accepted` until explicitly superseded. D-47-E8 outcome (c) "flag a future-supersede trigger" is the deferral path.
- **UPST7 scope** — UPST7 audit/sync execution; auditor at Phase 47 close picks title (`audit` vs `sync execution` per D-47-E11) and queues in v2.6 backlog OR v2.6 § Future Cycles holding section (recommended). UPST7 depends on Phase 48.
- **`Upstream-commit:` trailer backfill on already-absorbed Phase 22/34 commits** — backfill ledger reports `absorbed-via:` status as historical paper-trail; does NOT rewrite fork-main commits to add D-19 trailers retroactively (interactive rebase on long-published history unacceptable). Trailer-backfill on individual commits could be a future exploratory task if specific commits warrant traceability bookkeeping, but not Phase 47 scope.
- **Phase 48 cherry-pick selection for backfill `unmatched` rows** — if Phase 47 backfill ledger surfaces any `absorbed-via: unmatched` rows, those are flagged for Phase 48 absorption alongside UPST6 work. Phase 48 plan-phase decides whether to fold into UPST6 plans or spawn dedicated backfill-absorption plans.

### Reviewed Todos (not folded)

[None — `cross_reference_todos` step skipped. Phase 47 is an audit-only phase; no implementation todos pending.]

</deferred>

---

*Phase: 47-upst6-audit-v0-41-v0-43-drift-ingestion*
*Context gathered: 2026-05-23*
