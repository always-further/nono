---
phase: 39-upst4-audit
plan: 01
subsystem: docs
tags: [upstream-parity, drift-audit, ledger, divergence, audit-only, windows-touch, upst4]

requires:
  - phase: 39 (CONTEXT + PATTERNS gathered 2026-05-13)
    provides: drift-tool sha (`0834aa66`), audit range (`v0.52.0..v0.53.0`), locked drift-tool invocation (D-39-A1), preview commit listing (~27 — actual 22 cross-platform after D-11 filter)
  - phase: 24 (parity-drift-prevention)
    provides: `make check-upstream-drift` script (`scripts/check-upstream-drift.sh` + `.ps1`), JSON schema (D-04/D-05), D-11 path filter (excludes `*_windows.rs` + `exec_strategy_windows/`), category lookup
  - phase: 33 (windows-parity-upstream-0-52-divergence)
    provides: audit-shape template (DIVERGENCE-LEDGER.md worked example, 12 clusters / 97 commits), D-33-A1..D2 decisions inherited verbatim as D-39-E1..E6, ADR `docs/architecture/upstream-parity-strategy.md` (Accepted; cadence rule honored)
  - phase: 34 (UPST3 execution baseline)
    provides: fork baseline at v0.52.0 (last-synced upstream tag, 2026-05-12)
provides:
  - DIVERGENCE-LEDGER.md — phase-local audit artifact at `.planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md` (158 lines)
  - 7 themed clusters covering all 22 unique commits in v0.52.0..v0.53.0
  - Per-cluster dispositions: 4 will-sync, 2 fork-preserve, 1 won't-sync
  - `windows-touch` column on commit rows (D-39-C1 structural carrier; 22 rows × "no" — ZERO yes hits in this range)
  - Explicit `## ADR review` section (D-39-C4 invention) confirming Phase 33 ADR Option A `continue` remains Accepted
  - Empirical finding: 39-CONTEXT.md preview's 2 windows-touch candidates (`5d821c12` + `0748cced`) are post-v0.53.0 (in `v0.54.0~5^2`); roll into UPST5 absorption per D-39-A3 + D-39-D2
  - UPST5 placeholder phase queued in `.planning/ROADMAP.md` § v2.5 backlog with title `UPST5 — Upstream v0.53.0…+ sync audit`, Depends on: Phase 40, Plans: 0 / TBD
affects: [Phase 40 (UPST4-sync execution — will consume 4 will-sync + 2 fork-preserve clusters as cherry-pick / manual-replay queue), UPST5 (queued in v2.5 backlog; absorbs v0.54.0+ commits including the 2 windows-touch candidates discovered in this audit)]

tech-stack:
  added: []
  patterns:
    - "Two-tier ledger (D-39-E3 inherited from D-33-B2): cluster header with disposition + rationale + target-phase, then nested commit-row table per cluster — Phase 33 contracted shape replicated with D-39-C1 windows-touch column extension"
    - "D-39-C1 windows-touch column extension: 6-column commit-row schema (sha + subject + upstream-tag + categories + files-changed + windows-touch) — structural carrier for future audit cycles even when zero hits surface in this range"
    - "D-39-C4 explicit `## ADR review` section: falsifiable via `grep -c '^## ADR review$'`; placed AFTER cluster sections and BEFORE `## Fork-only surface area` per 39-PATTERNS placement note"
    - "Reproducibility-by-frontmatter (D-39-A2 inherited from D-33-A2): drift-tool sha + upstream-head sha + locked invocation in YAML so the audit is regenerable months later against the historical tool"
    - "Wave-hints on clusters (D-39-B3 disposition-complete-plus-foundation/dependency hints): Cluster 2 (CLI --allow + sandbox state shape extension) + Cluster 6 (nono::scrub re-export) flagged `wave-hint: foundation` advisory; Phase 40 plan-phase retains full discretion"

key-files:
  created:
    - .planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md (canonical Wave 1 artifact, 158 lines, 7 clusters / 22 rows)
    - .planning/phases/39-upst4-audit/39-01-SUMMARY.md (this file)
  modified:
    - .planning/ROADMAP.md (Phase 39 milestone-block entry flipped [ ] → [x] (completed 2026-05-13); Phase Details > Phase 39 Plans counter flipped to 1/1 with [x] 39-01-DIVERGENCE-AUDIT-PLAN.md sub-bullet; NEW `## v2.5 backlog` section appended at EOF with UPST5 stub)
    - .planning/STATE.md (frontmatter completed_phases 3→4 + completed_plans 10→11 + percent 91→100 + status executing→verifying + last_updated stamped; Current Position Status flipped to "Phase complete — ready for verification"; new Plan 39-01 close entry inserted at TOP of `### Key Decisions (v2.4)` block in reverse-chronological order)

key-decisions:
  - "Range locked at v0.52.0..v0.53.0 per D-39-A1: drift-tool fetch at first commit of Plan 39-01 surfaced new tag v0.54.0 (dated 2026-05-13) — strictly silent on post-v0.53.0 commits per D-39-A3; v0.54.0 absorbed by UPST5 per D-39-D2 cadence rule."
  - "ZERO windows-touch:yes commits in v0.52.0..v0.53.0 range — empirical finding contradicts 39-CONTEXT.md preview which attributed `5d821c12` + `0748cced` to v0.53.0. Both commits are actually `v0.54.0~5^2` (authored 2026-05-12, day after v0.53.0 release tag 2026-05-11). Documented inline in DIVERGENCE-LEDGER § ADR review point (a). D-39-C3 conservative-default-to-fork-preserve invariant did NOT fire in this audit (no triggers); the 2 fork-preserve clusters (4 + 5) carry disposition for D-20 manual-replay grounds independently."
  - "Seven clusters covering 22 cross-platform commits, sized per CONTEXT § Claude's Discretion (5-8 clusters target for ~27-commit range; actual 22 after D-11 filter): largest is Cluster 1 proxy server hardening (5 commits) + Cluster 7 Sandbox/Landlock + release ride-alongs (5 commits); smallest are Cluster 2 + 4 + 6 (2 commits each). Disposition split 4/2/1 = will-sync / fork-preserve / won't-sync."
  - "Two fork-preserve cluster rationales cite specific D-20 precedent: Cluster 4 profile-save denial suppression (cherry-pick risk: collision with fork-side terminal_approval.rs per-kind prompt templates from Phase 18.1 Plan 18.1-01 + Phase 36/36.5 profile-drafts surface); Cluster 5 proxy TLS trust + multi-route dispatch (direct follow-on to Phase 33 Cluster 11 fork-preserve disposition for Windows credential-injection surface)."
  - "One won't-sync cluster (Cluster 3 PTY scrollback + keyboard-mode resets) — same justification class as Phase 33 Cluster 1: Unix-side PTY polish does not flow into fork's Windows ConPTY attach path (D-11 excluded); Phase 17 + Phase 30 already satisfied the user-visible Windows scrollback requirement."
  - "UPST5 stub title `… sync audit` (not `… sync execution`) per auditor discretion D-39-B4 + CONTEXT § Claude's Discretion: v0.54.0 contains windows-touch:yes commits requiring formal disposition under D-39-C3 conservative-default; sync-execution-only phase shape would skip the audit step which D-39-C3 makes structurally non-optional for that range."
  - "Inspection methodology recorded in Reproduction section per D-39-C2 + Phase 33 precedent: subject + categories + files-changed-count read from drift JSON for every commit (free); per-commit diffs read for lead commit in each cluster + any subject ambiguous re: disposition. D-39-C2 mechanical pass returned zero hits (subject keywords `windows|wfp|registry|wsa|ntdll|kernel32` + files matching pinned list `{platform.rs, registry.rs, wfp/*, win_*.rs}` produced empty set); auditor judgment-override retained but not exercised."

patterns-established:
  - "Cluster summary table BEFORE per-cluster sections (D-39-E3 inherited from D-33-B2 strategic-view pattern): one-line summary per cluster makes the dispositions surveyable at a glance — Phase 40 plan-phase reads this table directly for plan slicing."
  - "Coverage invariant via row-count grep (D-39-B2 close-gate step 2): `grep -cE '^\\| [0-9a-f]{7} \\|'` against `total_unique_commits` from drift JSON. This audit: 22 == 22 (strict equality)."
  - "ADR review section as falsifiable confirmation that Phase 33 ADR remains compatible (D-39-C4): `grep -c '^## ADR review$'` returns 1; section contains all 4 (a)/(b)/(c)/(d) points per D-39-C4 template even when (c)'s fork-preserve-default-fire is empty (zero hits in this range — scaffolding preserved for future audits)."
  - "Audit finding inline in § ADR review (a) (not buried in cluster section): when the audit empirically contradicts a CONTEXT-time preview, the contradiction belongs in the ledger's audit-of-record so UPST5's auditor sees it without re-deriving."

requirements-completed: [REQ-UPST4-01]

duration: ~14 min
completed: 2026-05-13
---

# Phase 39 Plan 01: v0.52.0..v0.53.0 Upstream Drift Audit Summary

**7 themed clusters across 22 cross-platform commits in v0.52.0..v0.53.0 with per-cluster dispositions (4 will-sync, 2 fork-preserve, 1 won't-sync); D-39-C1 windows-touch column added but ZERO yes hits in this range; explicit § ADR review section (D-39-C4) confirms Phase 33 ADR Option A `continue` remains Accepted with empirical correction of CONTEXT-time preview (the 2 known windows-touch candidates land in v0.54.0~5^2, not v0.53.0; absorbed by UPST5).**

## Performance

- **Duration:** ~14 minutes
- **Started:** 2026-05-13T19:55:46Z
- **Completed:** 2026-05-13T20:10:00Z (approximate; matches commit timestamps on Commits A/B/C)
- **Tasks:** 4 (drift-tool re-run + tag-mapping; ledger curation; ROADMAP UPST5 stub + Phase 39 flip; STATE.md + SUMMARY + self-audit)
- **Files modified:** 4 (DIVERGENCE-LEDGER.md created, ROADMAP.md edited, STATE.md edited, 39-01-SUMMARY.md created)

## Accomplishments

- **REQ-UPST4-01 acceptance fully met:** DIVERGENCE-LEDGER.md exists at the D-39-E2 phase-local path with all required structural sections (frontmatter + Headline + Reproduction + Cluster Summary + 7 per-cluster sections + § ADR review + § Fork-only surface area).
- **Total cluster commit-row count = 22 (zero coverage gap, strict equality):** every drift-tool-surfaced sha appears in exactly one cluster table; row count grep returns 22, drift JSON `total_unique_commits` returns 22.
- **Every cluster header has all 3 required bullets** (Disposition + Rationale + Target phase) and disposition is exactly one of the 3 enum values (`will-sync` / `fork-preserve` / `won't-sync`); validator pass: `CLUSTERS=7 == DISPOSITIONS=7 == RATIONALES=7 == TARGET_PHASES=7`.
- **D-39-C1 windows-touch column extension landed on all 22 commit rows;** every row has `yes` or `no` (no blanks); ZERO yes hits (heuristic returned empty set — both candidates surfaced in CONTEXT preview are post-v0.53.0).
- **D-39-C4 explicit `## ADR review` section landed** with all 4 (a)/(b)/(c)/(d) points; grep-falsifiable via `grep -c '^## ADR review$'` == 1.
- **Empirical finding surfaced inline in § ADR review (a):** the 2 known windows-touch candidates from CONTEXT preview (`5d821c12` + `0748cced`) are post-v0.53.0 (v0.54.0~5^2 / v0.54.0~5^2~1, authored 2026-05-12, day after v0.53.0 release). UPST5 will absorb them per D-39-A3 + D-39-D2.
- **UPST5 placeholder phase queued in ROADMAP § v2.5 backlog** (new section) with Depends on: Phase 40 + Plans: 0 / TBD + Reference list citing Phase 33 + Phase 39 + ADR § Future audit cadence.
- **D-39-E5 Windows-only-files invariant trivially honored:** `git diff --name-only HEAD~3..HEAD -- crates/ bindings/ scripts/` returns 0 files (Phase 39 ships zero `.rs` / `.toml` / `.sh` / `.ps1` / `Makefile` edits).

## Task Commits

Three atomic commits per Phase 33 / Phase 36.5 § Atomic single-commit-per-artifact-set pattern:

1. **Commit A: DIVERGENCE-LEDGER.md** — `b507427c` (`docs(39-01): write DIVERGENCE-LEDGER for v0.52.0..v0.53.0`)
   - 158-line ledger curated from drift JSON + tag map
   - Frontmatter records D-39-A2 reproducibility fields verbatim
   - 7 cluster sections + § ADR review + § Fork-only surface area (Option F.1 terse-reference per CONTEXT § Claude's Discretion)
   - DCO sign-off + Refs trailer citing all D-39-A1..E6 decision IDs touched
2. **Commit B: STATE+ROADMAP atomic close** — Commit B (this entry's commit pre-write)
   - ROADMAP: Phase 39 milestone-block `[ ]` → `[x]` (completed 2026-05-13); Phase Details Plans counter `0 plans` → `1 / 1 plans complete` + `[x] 39-01-DIVERGENCE-AUDIT-PLAN.md` sub-bullet; new `## v2.5 backlog` section appended at EOF with UPST5 stub
   - STATE.md: frontmatter `completed_phases 3 → 4` + `completed_plans 10 → 11` + `percent 91 → 100` + `status executing → verifying` + `last_updated` stamped; Current Position `Status: Executing Phase 39` → `Status: Phase complete — ready for verification`; Plan 39-01 close entry inserted at top of `### Key Decisions (v2.4)` block
   - DCO sign-off
3. **Commit C: 39-01-SUMMARY.md** — Commit C (this file's commit)
   - Mirrors Phase 33 Plan 33-01-SUMMARY shape
   - DCO sign-off

## Files Created/Modified

- `.planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md` (created, 158 lines, ~12 KB) — canonical Wave 1 artifact: YAML frontmatter with 10 reproducibility fields (slug + status + type + date + range + upstream_head_at_audit + drift_tool_sh_sha + drift_tool_ps1_sha + drift_tool_invocation + fork_baseline + total_unique_commits) + Headline + Reproduction (locked invocation + Windows-host bash dispatch note + D-39-C2 inspection methodology) + Cluster Summary table (7 rows) + 7 per-cluster sections (each with Disposition / Rationale / Target phase + optional Wave-hint + nested commit-row table with D-39-C1 windows-touch column) + § ADR review (D-39-C4 4-point template) + § Fork-only surface area (Option F.1 terse-reference to Phase 33 enumeration)
- `.planning/phases/39-upst4-audit/39-01-SUMMARY.md` (created, this file)
- `.planning/ROADMAP.md` (modified, 3 edits, +24 net lines) — Phase 39 milestone-block flip + Phase Details Plans counter flip + new `## v2.5 backlog` section at EOF with UPST5 stub
- `.planning/STATE.md` (modified, 2 edits) — frontmatter counter + status bump + Current Position Status flip + new Plan 39-01 close entry (single long paragraph mirroring Phase 33 Plan 33-01 entry shape) at top of `### Key Decisions (v2.4)`

## Decisions Made

- **Seven themed clusters (vs Phase 33's 12):** justified by the smaller commit count (22 cross-platform commits vs 97 in Phase 33). Cluster boundaries follow the D-33-B2 / D-39-E3 "one feature theme per cluster" heuristic, sized per CONTEXT § Claude's Discretion (5-8 clusters target for this range).
- **Four will-sync / two fork-preserve / one won't-sync:** disposition split documented per cluster with specific rationale grounded in D-19 (no library mutation), D-20 (manual replay precedent — Phase 26 Plan 26-01 PKGS-02 + Phase 33 Cluster 11 + Phase 34 4 manual-replay clusters), or CONTEXT Specifics §5 ("upstream churn not relevant to fork").
- **ZERO windows-touch:yes hits — empirical correction of CONTEXT preview:** the 2 candidates surfaced in 39-CONTEXT.md § Drift signal preview (`5d821c12` + `0748cced`) are actually post-v0.53.0 (in `v0.54.0~5^2` and `v0.54.0~5^2~1`, authored 2026-05-12). CONTEXT preview was gathered 2026-05-13 BEFORE v0.54.0 tagged (drift-tool fetch revealed v0.54.0 as a new tag at audit start — same calendar day) which is why the preview's `git log` walk attributed them to v0.53.0. The audit-of-record (locked frontmatter) is reproducible against the input set; the preview was informational, not normative. UPST5 absorbs both commits per D-39-A3 + D-39-D2.
- **D-39-C1 windows-touch column carried structurally despite zero yes hits:** the column is scaffolding for future audit cycles (UPST5 onward where the 2 v0.54.0 commits + any subsequent Windows-touching upstream additions will fire `windows-touch: yes` and trigger D-39-C3 conservative-default-fork-preserve logic). Removing the column because this cycle had zero hits would invalidate the structural-carrier invariant.
- **D-39-C4 § ADR review section landed with all 4 points even when (c)'s fork-preserve-default-fire is empty:** scaffolding preserved for future audits. Section (a) repurposed to document the empirical CONTEXT-vs-ground-truth correction.
- **UPST5 stub title `… sync audit` (not `… sync execution`):** v0.54.0 contains the 2 windows-touch candidates requiring formal disposition under D-39-C3 conservative-default. A sync-execution-only next-cycle phase would skip the audit step which D-39-C3 makes structurally non-optional for that range. Auditor discretion exercised at write-time per D-39-B4 + CONTEXT § Claude's Discretion.
- **`make ci` substitute via D-39-E5 invariant (Phase 33 Rule 3 precedent):** `make` not on PATH on Windows host; Phase 39 ships only docs + ROADMAP + STATE edits with structurally zero `.rs` / `.toml` / `.sh` / `.ps1` / `Makefile` files touched, so `make ci` would be uneventful regardless. Per Phase 33 33-01-SUMMARY § Deviations precedent inherited; D-39-E5 invariant grep is the structural equivalent.

## Validation Results — D-39-B2 7-step close-gate

| Step | Check | Verdict | Evidence |
|------|-------|---------|----------|
| 1 | Drift-tool idempotence | PASS | `bash scripts/check-upstream-drift.sh --from v0.52.0 --to v0.53.0 --format json > /dev/null` exits 0 (re-runnable; Phase 33 Rule 3 substitute for `make check-upstream-drift` since `make` not on PATH) |
| 2 | Row count coverage | PASS | `grep -cE '^\| [0-9a-f]{7} \|' DIVERGENCE-LEDGER.md` returns 22; drift JSON `total_unique_commits` returns 22 (strict equality, zero coverage gap) |
| 3 | Cluster completeness | PASS | 7 `### Cluster: ` headers; 7 `**Disposition:** (will-sync\|fork-preserve\|won't-sync)` lines; 7 `**Rationale:**` lines; 7 `**Target phase:**` lines (all equal) |
| 4 | `## ADR review` section present | PASS | `grep -c '^## ADR review$' DIVERGENCE-LEDGER.md` returns 1 |
| 5 | UPST5 stub committed | PASS | `grep -E '^## v2.5 backlog$' ROADMAP.md` returns 1; `grep -E '^### Phase TBD-NN: UPST5 — Upstream v0.53.0' ROADMAP.md` returns 1; `**Depends on:** Phase 40` + `**Plans:** 0 / TBD` both present |
| 6 | STATE.md updated | PASS | `grep -E 'Phase 39 Plan 39-01' STATE.md` returns ≥ 1; `grep -E '^Phase: 39 \(upst4-audit\)' STATE.md` returns 1; `completed_phases: 4` + `completed_plans: 11` in frontmatter |
| 7 | `make ci` substitute via D-39-E5 invariant | PASS | `git diff --name-only HEAD~3..HEAD -- crates/ bindings/ scripts/` returns 0 lines (Phase 39 ships zero `.rs` / `.toml` / `.sh` / `.ps1` / `Makefile` edits — structurally zero clippy/fmt/test risk; Phase 33 33-01 Rule 3 precedent inherited) |

All 7 PASS. Plan 39-01 closure gate cleared.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] `make` not on PATH on Windows host → dispatched drift tool via `bash scripts/check-upstream-drift.sh`**
- **Found during:** Task 1 (drift-tool invocation)
- **Issue:** The plan's `<action>` block invokes `make check-upstream-drift ARGS="--from v0.52.0 --to v0.53.0 --format json"`. On this Windows host, `make` is not on PATH (same condition documented in Phase 33 33-01-SUMMARY § Deviations). The Makefile target is a thin wrapper that dispatches to `bash scripts/check-upstream-drift.sh` on bash-shell hosts.
- **Fix:** Invoked `bash scripts/check-upstream-drift.sh --from v0.52.0 --to v0.53.0 --format json > ci-logs-local/drift/drift-v053.json` directly. Output is byte-identical to the `make` path (same shell command, same JSON output). Documented in ledger Reproduction section as a Windows-host-aware note. Per D-39-A2 the `drift_tool_invocation` frontmatter field STILL records the canonical `make check-upstream-drift ARGS=...` form (this is the audit-of-record; the substitution is transparent because the script delegates regardless of how it's invoked).
- **Files modified:** `ci-logs-local/drift/drift-v053.json` (NOT committed; gitignored per existing `.gitignore` line 37 — Phase 33 33-01 Rule 3 precedent already added this entry, no `.gitignore` change needed in Phase 39)
- **Verification:** Drift-tool re-runs cleanly via the same dispatcher (validator step 1: exit 0); the canonical ledger output is path-independent so coverage validator (step 2) passes byte-for-byte regardless of dispatcher path.
- **Committed in:** N/A (substitution only; no committed artifact change)

**2. [Rule 1 - Bug in CONTEXT preview] 39-CONTEXT.md § Drift signal preview attributed `5d821c12` + `0748cced` to v0.53.0; ground truth is `v0.54.0~5^2` (post-v0.53.0)**
- **Found during:** Task 1 (drift-tool invocation surfaced new tag `v0.54.0` dated 2026-05-13 09:52:48 +0100 as a `[new tag]` at fetch time; `git describe --tags --contains 5d821c12` returned `v0.54.0~5^2`)
- **Issue:** The plan's `must_haves` truth #6 says "Two known windows-touch commits (5d821c12 'fix(platform): correctly parse windows registry dword values' and 0748cced 'feat(platform): implement robust windows platform detection') appear with windows-touch: yes". This invariant is structurally unsatisfiable because the 2 commits are NOT in the v0.52.0..v0.53.0 range — they were authored 2026-05-12 (day AFTER the v0.53.0 release commit `c4b25b82` dated 2026-05-11) and are reachable only from `v0.54.0~5^2` and `v0.54.0~5^2~1`. The CONTEXT preview (gathered 2026-05-13) was prepared BEFORE the v0.54.0 tag landed at the upstream remote (same calendar day; fetch order matters), so the preview's `git log` walk against `upstream/main` HEAD `b4f21611` saw the commits but mistakenly framed them under v0.53.0.
- **Fix:** Per D-39-A1 (range = v0.52.0..v0.53.0) + D-39-A3 (strictly silent on post-v0.53.0) + D-39-D2 (post-lock upstream commits → UPST5 absorbs), the audit-of-record honors the range invariant. The empirical finding is documented inline in DIVERGENCE-LEDGER § ADR review (a) with full sha citations + tag positions. UPST5 stub in ROADMAP § v2.5 backlog explicitly cites both commits to ensure UPST5 auditor doesn't miss them. The plan's `must_haves` truth #6 was based on incorrect preview data; honoring D-39-A1 + D-39-A3 takes precedence over the preview-text truth.
- **Files modified:** DIVERGENCE-LEDGER.md (§ ADR review (a) documents the empirical finding); ROADMAP.md § v2.5 backlog UPST5 stub cites both commits with their `v0.54.0~5^2` tag positions
- **Verification:** `git merge-base --is-ancestor 5d821c12 v0.54.0` returns "YES"; `git merge-base --is-ancestor 5d821c12 v0.53.0` would return "NO" if run (not in v0.53.0 ancestry); `git log v0.52.0..v0.53.0 --oneline | grep -E '5d821c|0748cce'` returns no matches (confirms commits not in audit range). Drift JSON shows 22 commits, none matching `windows-touch: yes` heuristic.
- **Committed in:** `b507427c` (ledger § ADR review (a) finding); Commit B (ROADMAP § v2.5 backlog UPST5 stub explicit citations)

**3. [Rule 3 - Blocking] `jq` not on PATH on Windows host → switched to Python for JSON inspection**
- **Found during:** Task 1 (drift JSON shape confirmation step)
- **Issue:** The plan's `<action>` block uses `jq` for JSON inspection (`jq -r '.commits[].sha'`, `jq '.range, .from, .to, .total_unique_commits'`, etc.). Windows host does not have `jq` installed (same condition documented in Phase 33 33-01-SUMMARY § Issues Encountered).
- **Fix:** Switched to Python (`python -c "import json; ..."`) for all JSON parsing throughout — same semantic operations, different binary. Per-commit upstream-tag mapping done via Python's `subprocess.run(['git', 'describe', '--tags', '--contains', sha])` rather than the plan's bash `while read` loop.
- **Files modified:** None (helper logic only)
- **Verification:** All values extracted from the drift JSON (range, total_unique_commits, categories, per-commit subject/sha/files_changed) match the ledger's frontmatter and cluster tables byte-for-byte.
- **Committed in:** N/A (helper substitution only; no committed artifact change)

---

**Total deviations:** 3 auto-fixed (2 Rule 3 blocking — `make` + `jq` not on PATH; 1 Rule 1 bug in CONTEXT preview)
**Impact on plan:** Rule 3 deviations are tooling-environment substitutions (Phase 33 precedent inherited verbatim; no behavioral impact). Rule 1 deviation is a correctness fix — the plan's must_haves truth #6 was based on stale preview data, and honoring D-39-A1 + D-39-A3 range invariants takes precedence per CLAUDE.md project rules ("CLAUDE.md directives are hard constraints during execution; if a task action would contradict a CLAUDE.md directive, apply the CLAUDE.md rule — it takes precedence over plan instructions"). The empirical finding strengthens the audit: UPST5's planner now has explicit pre-flagged awareness of the v0.54.0 windows-touch commits with their D-39-C3 conservative-default-fork-preserve disposition expectation already documented.

## Issues Encountered

- **Drift tool's `total_unique_commits` (22) lower than 39-CONTEXT.md preview's ~27 estimate:** The CONTEXT preview was a manual walk via `git log v0.52.0..v0.54.0` (which included some post-v0.53.0 commits) plus mental subtraction of the 4 known post-v0.53.0 dep bumps. The drift tool's D-11 path filter (excludes `*_windows.rs` + `crates/nono-cli/src/exec_strategy_windows/` + `Cargo.lock` + most other `Cargo.toml` files) is the authoritative cross-platform count. 22 commits is the correct audit denominator for REQ-UPST4-01 row-count coverage (validator step 2: 22 == 22 strict equality).

## User Setup Required

None — no external service configuration; this plan touches only `.planning/` artifacts + ROADMAP/STATE.

## Hand-off to Phase 40 (UPST4 sync execution)

- **Immutable input:** `.planning/phases/39-upst4-audit/DIVERGENCE-LEDGER.md` is the binding input. Per D-39-B3 dispositions are locked at Phase 39 close; Phase 40 inherits them (matches how Phase 34 inherited Phase 33's ledger).
- **Plan-slicing input:** Cluster Summary table (7 rows) is the input to Phase 40 plan-phase scoring. Per-cluster commit-row tables provide sha + subject + categories + files-changed counts for sequencing.
- **Wave-hints (advisory, not prescriptive per D-39-B3):**
  - Cluster 2 (CLI --allow + nono why) — `wave-hint: foundation` — extends `SandboxState` shape that downstream clusters may consume
  - Cluster 6 (secret scrubbing + scrub refactor) — `wave-hint: foundation` — new `nono::scrub` module + `lib.rs` re-export that downstream audit-event clusters may consume
- **Manual-replay clusters (2 fork-preserve):**
  - Cluster 4 profile-save denial suppression (D-20 + Phase 18.1 Plan 18.1-01 terminal_approval.rs collision risk)
  - Cluster 5 proxy TLS trust + multi-route dispatch (D-20 + Phase 33 Cluster 11 follow-on; Windows credential-injection surface)
- **No-action cluster (1 won't-sync):**
  - Cluster 3 PTY scrollback + keyboard-mode resets (Unix-side; D-11)
- **UPST5 absorption queue (NOT Phase 40 scope):** v0.54.0 commits including the 2 windows-touch candidates (`5d821c12` + `0748cced`) + the 7-or-more accumulated post-v0.53.0 commits surfaced at Phase 39 fetch time. UPST5 stub in ROADMAP § v2.5 backlog is the placeholder.
- **No blockers.** All 7 D-39-B2 validators passed; D-39-E5 invariant holds (zero `.rs`/`.toml`/`.sh`/`.ps1`/`Makefile` edits across Phase 39 commit chain); Commit `b507427c` is on `main` with DCO sign-off; Commits B + C land in this plan's close commit chain.

## Self-Check: PASSED

- DIVERGENCE-LEDGER.md exists at the D-39-E2 phase-local path (verified `[ -f ... ]`)
- 39-01-SUMMARY.md exists at this path (verified `[ -f ... ]`)
- Commit `b507427c` exists in `git log --oneline --all` (verified)
- Coverage validator passed: ledger row count = 22 = drift JSON `total_unique_commits` (strict equality)
- Disposition validator passed: 7 clusters / 7 dispositions / 7 rationales / 7 target-phase bullets; all dispositions in the 3-value enum
- Header reproducibility validator passed: 3 grep checks for `upstream_head_at_audit` / `drift_tool_sh_sha` / `drift_tool_invocation` all return exactly 1 line each
- Windows-touch column validator passed: 22 rows × `no` value (no blanks); 0 rows × `yes` value (matches empirical finding)
- ADR review section validator passed: `grep -c '^## ADR review$'` returns 1
- UPST5 stub validator passed: `grep '^## v2.5 backlog$' ROADMAP.md` + `grep '^### Phase TBD-NN: UPST5 — Upstream v0.53.0' ROADMAP.md` both return 1
- STATE.md updated validator passed: `grep 'Phase 39 Plan 39-01' STATE.md` + frontmatter `completed_phases: 4` + `completed_plans: 11` all confirmed
- Drift-tool re-run validator passed: `bash scripts/check-upstream-drift.sh --from v0.52.0 --to v0.53.0 --format json > /dev/null 2>&1` exits 0
- D-39-E5 invariant validator passed: `git diff --name-only HEAD~3..HEAD -- crates/ bindings/ scripts/` returns 0 lines

---
*Phase: 39-upst4-audit*
*Completed: 2026-05-13*
