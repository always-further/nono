# Phase 40: UPST4 sync execution - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-13
**Phase:** 40-UPST4 sync execution
**Areas discussed:** Plan slicing & wave shape, fork-preserve auditor authority, PR / branch posture, Won't-sync documentation shape for Cluster 3

---

## Plan slicing & wave shape

### Q1: How many plans should Phase 40 ship?

| Option | Description | Selected |
|--------|-------------|----------|
| One plan per cluster (6 plans) — Phase 34 D-34-A1 shape | Six plans: 4 will-sync (Clusters 1, 2, 6, 7) + 2 fork-preserve (Clusters 4, 5). Maximum per-cluster traceability; reviewer attention concentrates per cluster. | ✓ |
| Bundle small will-sync clusters (4-5 plans) | Merge Cluster 2 + Cluster 6 into one foundation plan, or bundle Cluster 1 + Cluster 7. Fewer plans, easier sequencing, but loses per-cluster review focus. | |
| Mega-plan (1-2 plans total) | All will-sync in one plan + fork-preserve in another. Lightest planning overhead; harder reviewer attention; mid-plan STOP-trigger risk. | |

**User's choice:** One plan per cluster (6 plans) — Phase 34 D-34-A1 shape (Recommended)
**Notes:** Cluster-traceability for reviewer attention is the deciding factor; D-34-A1 verbatim.

### Q2: Wave shape — Cluster 2 + Cluster 6 'wave-hint: foundation' sequencing

| Option | Description | Selected |
|--------|-------------|----------|
| Both run parallel as a single Wave 0 | Cluster 2 + Cluster 6 are surface-disjoint (CLI/sandbox_state vs new crates/nono/src/scrub.rs). Run parallel; downstream rebases on top. | ✓ |
| Sequential gate: Cluster 6 first, then Cluster 2 | Mirror Phase 34 D-34-A2 single-cluster sequential gate. Higher upfront serialization; zero rebase risk. | |
| No special wave structure — chronological by upstream tag | Plans land in upstream-chronological order. No wave-parallelization; simplest sequencing. | |

**User's choice:** Both run parallel as a single Wave 0 (Recommended)
**Notes:** Phase 40's foundation clusters are 2 commits each on disjoint surfaces; parallel justified vs Phase 34's 23-commit C7 schema gate.

### Q3: Plan numbering convention

| Option | Description | Selected |
|--------|-------------|----------|
| Cluster-theme names matching Phase 34 | E.g., 40-01-PROXY-HARDENING, 40-03-SCRUB-MODULE, 40-05-FP-PROFILE-SAVE. Mirrors Phase 34 readability. | ✓ |
| Upstream-tag chronological numbering | Plan numbers follow upstream-tag chronology (v0.52.1 first, etc.). Easier release-by-release walkthrough. | |
| Wave-order numbering | Plan numbers follow wave order. Easier PLAN.md execution-order reading; harder upstream-tag mapping. | |

**User's choice:** Cluster-theme names matching Phase 34 (Recommended)
**Notes:** Naming follows wave order (40-02/40-03 Wave 0, 40-01/40-04 Wave 1, 40-05/40-06 Wave 2) with cluster-theme suffix; diverges from upstream-tag chronology to keep execution-order readable.

### Q4: Phase-prep plan (40-00-style)?

| Option | Description | Selected |
|--------|-------------|----------|
| No 40-00 prep plan — jump straight to cluster plans | No G-25-DRIFT-01 analog; UPST5 already queued; no PROJECT.md row to update. Plan 40-02 is the first to land. | ✓ |
| Lightweight 40-00 prep plan | STATE.md status flip, optional PROJECT.md row noting Phase 40 inherits Phase 34 invariants. | |
| Phase-start drift-tool re-run as 40-00 | Re-runs `make check-upstream-drift` to confirm 22-commit set unchanged. Audit-correctness paranoia. | |

**User's choice:** No 40-00 prep plan — jump straight to cluster plans (Recommended)
**Notes:** Phase 39 audit-of-record locked the inputs; no pre-execution validation needed.

---

## fork-preserve auditor authority

### Q1: Cluster 4 (profile-save denial suppression) disposition

| Option | Description | Selected |
|--------|-------------|----------|
| Plan-phase runs diff inspection; upgrade to will-sync if safe | Plan 40-05 begins with upstream-vs-fork diff inspection. If no collision → upgrade to D-19 cherry-pick; else D-20 manual replay. | ✓ |
| Keep conservative D-20 manual replay regardless | Honor D-39-B3 dispositions-locked invariant strictly; no re-audit. Saves diff-inspection step. | |
| Auditor authority via standalone Plan 40-00-AUDIT-INSPECT | Front-load diff inspection as no-code prep plan producing audit memo. Heaviest but most auditable. | |

**User's choice:** Plan-phase runs diff inspection; upgrade to will-sync if safe (Recommended)
**Notes:** Ledger explicitly invited the upgrade; user wants to absorb upstream cleanly if no collision.

### Q2: Cluster 5 (proxy TLS trust + multi-route + credential matching) posture

| Option | Description | Selected |
|--------|-------------|----------|
| Keep conservative D-20 manual replay; no upgrade attempt | Phase 33 Cluster 11 follow-on; fork's credential-injection rewrite makes collision likely. Mirror Phase 34 D-34-B1. | ✓ |
| Allow diff-inspection upgrade attempt | Same posture as Cluster 4 — try diff inspection. Higher upside if upstream doesn't touch rewritten path; precedent says collision is likely. | |
| Manual replay BUT scope only what's defense-in-depth-useful | Skip wholesale replay; replay only audit/policy semantics that strengthen fork. Most surgical. | |

**User's choice:** Keep conservative D-20 manual replay; no upgrade attempt (Recommended)
**Notes:** Phase 33 Cluster 11 precedent + fork's credential-injection rewrite makes the conservative choice the right one; selective-scope retained as planner discretion (D-40-B2 commit body documents what was replayed vs skipped).

### Q3: Upgrade rule criteria if Cluster 4 diff inspection clears

| Option | Description | Selected |
|--------|-------------|----------|
| Upgrade requires zero fork-only-line conflicts AND identical surface semantics | Strict rule: cherry-pick must apply without touching `#[cfg(target_os = "windows")]` arms AND upstream semantics match fork's enforcement. | ✓ |
| Upgrade allowed if cherry-pick applies without merge conflict | Looser rule: clean `git cherry-pick` is sufficient. Faster but misses semantic drift. | |
| Upgrade is a planner judgment call (no fixed rule) | Trust plan-phase author; document rationale in PLAN.md. Most flexible; relies on planner discipline. | |

**User's choice:** Upgrade requires zero fork-only-line conflicts AND identical surface semantics (Recommended)
**Notes:** Strict rule prevents silent semantic drift; documented in PLAN.md § Disposition resolution.

### Q4: Manual-replay commit-body discipline

| Option | Description | Selected |
|--------|-------------|----------|
| Single commit per replayed semantic change, body documents what+why | Mirrors Phase 26 Plan 26-01 PKGS-02 + Phase 34 Plan 34-10. No D-19 trailer (not a cherry-pick); structured body sections. | ✓ |
| Squash all replayed changes per cluster into one commit | Single commit per cluster. Cleaner git log; harder bisect. | |
| Use D-19 trailer ANYWAY with 'replayed-from' instead of 'cherry-pick' | Custom trailer `Upstream-replayed-from:`. Maintains provenance; new convention to document. | |

**User's choice:** Single commit per replayed semantic change, body documents what+why (Recommended)
**Notes:** Bisect support + per-semantic granularity; optional `Upstream-replayed-from:` trailer for provenance without polluting the D-19 `^Upstream-commit: ` grep smoke check.

---

## PR / branch posture

### Q1: PR shape

| Option | Description | Selected |
|--------|-------------|----------|
| One PR per plan, direct-on-main (6 PRs) | Mirror Phase 34 D-34-D1 verbatim. Per-cluster reviewer attention; PR ordering follows wave structure. | ✓ |
| Bundle into 3 PRs: Wave 0, will-sync rest, fork-preserve | Fewer PRs; preserves disposition-class boundary; larger blast radius per PR. | |
| Single Phase 40 PR | Lightest PR overhead; biggest blast radius. Phase 22 + Phase 34 both rejected this shape. | |
| One PR per disposition-class (2 PRs) | Mid-ground; will-sync in one PR, fork-preserve in another. | |

**User's choice:** One PR per plan, direct-on-main (6 PRs) (Recommended)
**Notes:** Phase 34 D-34-D1 verbatim; reviewer attention per cluster.

### Q2: Per-plan close gate

| Option | Description | Selected |
|--------|-------------|----------|
| D-34-D2 verbatim (all 8 checks per plan close) | Cargo test + 4-platform clippy + fmt + Phase 15 smoke + wfp_port_integration + learn_windows_integration. Cross-target clippy non-negotiable per Phase 25 CR-A lesson. | ✓ |
| Drop wfp_port_integration + learn_windows_integration unless plan touches them | Lighter gate for unrelated plans; risk of late-stage breakage. | |
| Cross-target clippy as PR-level gate not per-plan | Per-plan Windows-host only; cross-target at PR-merge. Faster per-plan; late discovery risk. | |

**User's choice:** D-34-D2 verbatim (all 8 checks per plan close) (Recommended)
**Notes:** Phase 25 CR-A cross-target lesson (memory `feedback_clippy_cross_target`) makes steps 3+4 non-negotiable.

### Q3: STOP-trigger behavior mid-plan

| Option | Description | Selected |
|--------|-------------|----------|
| Any D-34-D2 gate failure freezes the plan | Mirror Phase 34 verbatim: freeze on gate failure; split (Phase 22-05a/05b precedent) or roll back to last clean state. | ✓ |
| Per-cluster split allowed if fork-divergence exceeds estimate | Plan can split into 40-NN-a (clean) + 40-NN-b (manual ports). Phase 22-05a/05b precedent. | |
| Soft STOP — ask user before split-or-rollback | Surface to user with recommendation; user chooses. More interactive; loses automaticity. | |

**User's choice:** Any D-34-D2 gate failure freezes the plan (Recommended)
**Notes:** Strict freeze + Phase 22-05a/05b split-allowed precedent both inherited (D-40-C3 explicitly allows per-cluster split as the recovery shape).

### Q4: DCO sign-off + Co-Authored-By trailer convention

| Option | Description | Selected |
|--------|-------------|----------|
| Phase 22 D-19 verbatim: 2 Signed-off-by lines + Co-Authored-By per cherry-pick | 6-line D-19 trailer block. Manual-replay: 1 Co-Authored-By + DCO Signed-off-by. | ✓ |
| Strip Co-Authored-By for cherry-picks (just preserve upstream-author) | Trailer Upstream-author is sufficient provenance; Co-Authored-By bot-clutters log. | |
| Single Signed-off-by (CLAUDE.md DCO convention) | One Signed-off-by; skip second + Co-Authored-By. Deviates from Phase 22 D-19. | |

**User's choice:** Phase 22 D-19 verbatim: 2 Signed-off-by lines + Co-Authored-By per cherry-pick (Recommended)
**Notes:** Verbatim 6-line shape from `.planning/templates/upstream-sync-quick.md`; smoke check `grep -c '^Upstream-commit: '` equals cluster commit count at plan close.

---

## Won't-sync documentation shape for Cluster 3

### Q1: Where should Cluster 3 (PTY scrollback) be documented?

| Option | Description | Selected |
|--------|-------------|----------|
| Inline section in 40-SUMMARY.md | Smallest footprint: `## Won't-sync clusters from Phase 39 ledger` section in close-out SUMMARY. No new file. | ✓ |
| Inline addendum to Phase 39 DIVERGENCE-LEDGER.md (Phase 34 D-34-A3 default) | Append `## Phase 40 won't-sync closure` to Phase 39 ledger. Single source of truth across audit + execution. | |
| Dedicated 40-PHASE-OUTCOMES.md file | Phase 34 alternative shape. 1-row file is overkill for single won't-sync cluster. | |

**User's choice:** Inline section in 40-SUMMARY.md (Recommended)
**Notes:** Smallest footprint; Phase 39 ledger has full rationale and is the single source of truth.

### Q2: Rationale depth for Cluster 3 won't-sync

| Option | Description | Selected |
|--------|-------------|----------|
| Pointer-only: cite Phase 39 ledger row + Phase 33 Cluster 1 precedent | One-line note. Phase 39 ledger has full rationale; Phase 40 doesn't duplicate. | ✓ |
| Full rationale copied from Phase 39 ledger | Self-contained Phase 40 SUMMARY; duplicates content. | |
| Empirical re-validation: at Phase 40 close, re-confirm Cluster 3 is still won't-sync | Walk the 3 commits one more time against fork's pty_proxy_windows.rs. Phase 34 D-34-A3 did NOT do this. | |

**User's choice:** Pointer-only: cite Phase 39 ledger row + Phase 33 Cluster 1 precedent (Recommended)
**Notes:** Trust Phase 39 audit-of-record; no re-litigation.

### Q3: Re-confirm Phase 39 § Fork-only surface area at Phase 40 close?

| Option | Description | Selected |
|--------|-------------|----------|
| No re-confirmation needed | Phase 40 only touches cross-platform files (D-11 invariant); fork-only surface structurally untouched. | ✓ |
| Add a one-line grep validator at Phase 40 close | `git ls-files | grep -E '_windows\.rs$' | wc -l` matches Phase 39 audit-time count. Cheap defense-in-depth. | |
| Full audit-walk of any new Phase 36.5+ surface | Walk recent SUMMARYs to confirm no new fork-only Windows surface. Heavier. | |

**User's choice:** No re-confirmation needed (Recommended)
**Notes:** D-11 invariant + D-40-E1 close-gate make this structurally unnecessary.

### Q4: Phase 39 § ADR review closure note?

| Option | Description | Selected |
|--------|-------------|----------|
| No closure note — Phase 39 audit closed the ADR review | Phase 39 point (d) already says ADR remains Accepted. Phase 40 is execution-only. | ✓ |
| Phase 40 SUMMARY notes 'ADR Option A continue execution complete' | Light pointer back to docs/architecture/upstream-parity-strategy.md. | |
| Append a 'Phase 40 execution outcome' subsection to the ADR | Edit ADR with execution outcome. Heavier; ADR is strategic not execution-log. | |

**User's choice:** No closure note — Phase 39 audit closed the ADR review (Recommended)
**Notes:** ADR closure structurally complete via Phase 39 § ADR review point (d).

---

## Claude's Discretion

- Exact wave membership beyond D-40-A2 (Wave 1 grouping refined by planner based on surface conflict probing).
- Plan 40-04-RELEASE-RIDE handling: whether the 3 release commits (`21bbb82` v0.52.1, `e8bf014` v0.52.2, `c4b25b8` v0.53.0) ride along with each cluster's chain or are bundled into a release-bumps-only plan.
- Whether Plan 40-05-FP-PROFILE-SAVE PLAN.md is written assuming the diff-inspection upgrade WILL fire or WON'T fire (either is acceptable as long as diff inspection is first task + disposition decision documented before any commit).
- Push-to-origin/main batching within a wave (push at each plan-close is the default; planner may batch).

## Deferred Ideas

- `nono why --host` Windows-side composition with Phase 09 WFP state (D-40-E6 watch item from Cluster 2) — new phase if user demand materializes.
- Windows-specific scrub rules in `nono::scrub` module (D-40-E6 watch item from Cluster 6) — separate scope.
- UPST5 audit phase (v0.54.0+) — already queued in ROADMAP § v2.5 backlog; explicit citation of windows-touch candidates `5d821c12` + `0748cced`.
- Plan 40-06 partial-replay scope: "what's defense-in-depth-useful vs skip" boundary in Cluster 5 manual replay — planner discretion at Plan 40-06.
- Push-to-origin batching policy within a wave.

### Reviewed Todos (not folded)

- `v24-cr-01-broker-not-found-ffi-mapping.md` — Phase 31 broker FFI error mapping. Out of scope (FFI surface, not upstream-sync).
- `v24-cr-02-broker-null-handle-validation.md` — Phase 31 broker argv parser. Out of scope.
- `v24-cr-03-broker-empty-handle-list-path.md` — Phase 31 broker empty-handle-list path. Out of scope.
- `v24-cr-04-job-object-test-skip-policy.md` — Phase 31 broker Job Object test skip policy. Out of scope.

All four matched `gsd-sdk query todo.match-phase 40` at score 0.6 due to false-positive `phase / planning / phases` keyword matches; surface is `bindings/c/` and `crates/nono-shell-broker/`, neither of which Phase 40 touches.
