# Phase 45: Source migration + AIPC G-04 + RESL native re-validation - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-21
**Phase:** 45-source-migration-aipc-g-04-resl-native-re-validation
**Areas discussed:** Plan slicing & parallelism, Edition 2024 disposition, AIPC G-04 migration shape, RESL native re-validation host strategy

---

## Plan slicing & parallelism

### Question 1 — How should Phase 45 be sliced into plans?

| Option | Description | Selected |
|--------|-------------|----------|
| 3 plans, parallel-safe | 45-01 Edition 2024, 45-02 AIPC G-04, 45-03 RESL re-validation. Disjoint surfaces; clean per-plan SUMMARY + per-plan REQ closure. RESL plan has different exec semantics (host-blocked) but same plan shape. | ✓ |
| 2 plans (Edition 2024 vs AIPC+RESL bundled) | 45-01 Edition 2024 mechanical, 45-02 bundles AIPC G-04 + RESL re-validation. Fewer plans but mixes wire-type compile-time tightening with a tactical native-host confirmation. | |
| 1 mega-plan covering all three sub-streams | Single PLAN.md with three sections. Loses per-sub-stream commit-boundary clarity. Matches Phase 44 D-44-A1 option (b) which user rejected then. | |

**User's choice:** 3 plans, parallel-safe (Recommended)
**Notes:** Aligns with Phase 44 D-44-A1 + Phase 43 D-43-A2 parallel-wave precedent. Each plan closes exactly one requirement: PORT-CLOSURE-08, AIPC-G04-01, RESL-NIX-04.

### Question 2 — Commit slicing for Plan 45-01 (39 mechanical rewrites across 6 files)

| Option | Description | Selected |
|--------|-------------|----------|
| One commit per file (6 commits) | Each of capability_set.rs (16), lib.rs (4), fs_capability.rs (7), sandbox.rs (3), state.rs (5), query.rs (4) gets its own commit. Matches Phase 41/44 "one commit per class" pattern. | ✓ |
| Single atomic mechanical commit | All 39 rewrites in one commit. Simpler PR diff but loses per-file bisect granularity. | |
| One commit per pub-surface category (3 commits) | Slice by FFI category: capability_set + fs_capability, sandbox + state, query + lib. | |

**User's choice:** One commit per file (6 commits) (Recommended)
**Notes:** Easiest review-per-file; clean bisect on any FFI regression.

---

## Edition 2024 disposition

### Question 1 — How should Plan 45-01 land the Edition 2024 source rewrites originally from upstream `79715aa5`?

| Option | Description | Selected |
|--------|-------------|----------|
| D-20 manual replay, no upstream PR | `chore(45-01):` commits with `Replay-of: 79715aa5 (Phase 43 Plan 43-01b DEC-3 split-disposition close)` annotation. No `Upstream-commit:` D-19 trailer. No upstream PR — the change already exists in upstream main; this is fork catching up. | ✓ |
| D-19 cherry-pick with path-filtered cherry-pick of 79715aa5 | `git cherry-pick -n 79715aa5 && git checkout -- <non-bindings paths>` then six per-file commits with `Upstream-commit: 79715aa5` trailer blocks. | |
| Fork-internal `chore(45-01)` with no upstream attribution | Pure mechanical rewrite; no upstream reference. Cleanest history but loses audit trail back to upstream lineage. | |

**User's choice:** D-20 manual replay, no upstream PR (Recommended)
**Notes:** Mirrors Phase 40 D-20 pattern. The Edition 2024 syntax change already exists in upstream main; Phase 45 catches the fork up. `Replay-of:` annotation preserves lineage without overloading D-19 trailer semantics.

### Question 2 — When does DIVERGENCE-LEDGER get amended to flip Cluster 2 `split → closed`?

| Option | Description | Selected |
|--------|-------------|----------|
| At Plan 45-01 close | One commit at end of Plan 45-01 amends DIVERGENCE-LEDGER to flip Cluster 2 `split → closed` with back-reference to commit `79715aa5` and the Phase 45 commit range. Plan SUMMARY records the amendment SHA. | ✓ |
| At Phase 45 close (single ledger commit) | All three plans complete, then a single phase-close commit amends the ledger. | |
| Per-commit (inline in each of the 6 file commits) | Every file commit includes a DIVERGENCE-LEDGER edit fragment. Verbose; lossy if commit ordering changes. | |

**User's choice:** At Plan 45-01 close (Recommended)
**Notes:** Mirrors Phase 43 mid-flight amendment pattern at commit `79715aa5`.

### Question 3 — How should Plan 45-01 disposition non-mechanical surprises?

| Option | Description | Selected |
|--------|-------------|----------|
| Absorb into per-file commit + verify cbindgen header byte-identical | Fold non-mech into the file's commit with inline explanation. After all 6 commits, regenerate `nono.h` and assert byte-identical to pre-phase. If header diffs, surface as deviation, do not auto-close. | ✓ |
| Treat non-mechanical changes as out-of-scope; defer to follow-up phase | Plan 45-01 is mechanical-only. Files with non-mech requirements left at pre-Edition 2024 syntax. REQ-PORT-CLOSURE-08 closes as PARTIAL. | |
| Absorb non-mech changes silently; no header verification | No distinction; skip cbindgen byte-identical gate. Could mask FFI ABI break. | |

**User's choice:** Absorb into per-file commit + verify cbindgen header byte-identical (Recommended)
**Notes:** Edition 2024 syntax changes should not change C header output; the byte-identical gate is the canonical correctness anchor.

---

## AIPC G-04 migration shape

### Question 1 — How should Plan 45-02 slice the AIPC G-04 wire-protocol migration?

| Option | Description | Selected |
|--------|-------------|----------|
| Single atomic commit (wire + sdk + 23 tests in one) | All changes land together. SC#2's compile-time guarantee requires atomicity — partial migration is a build break. Body lists touched test files; AUD-05 regression test called out as verified-pass. | ✓ |
| Two-commit pipeline (wire + sdk in commit 1, tests in commit 2) | Would require feature flag or cfg gating to keep commit 1 build-green; more complex than the atomic shape. | |
| Test-first prep + atomic flip (2 commits with helper) | Introduce a temporary helper that constructs either shape, then flip. Build green at every commit but more churn (helper introduced then removed). | |

**User's choice:** Single atomic commit (wire + sdk + 23 tests in one) (Recommended)
**Notes:** Tag `feat(45-02):`, not `chore:` — real production wire-type change.

### Question 2 — Wire-format backward compat for the AIPC G-04 flip

| Option | Description | Selected |
|--------|-------------|----------|
| Accept the break; old ledgers no longer re-verifiable | Pre-v2.6 audit-event ledgers cannot be re-verified after Phase 45. Document in CHANGELOG (BREAKING) + ADR amendment in `docs/architecture/audit-bundle-target.md`. AUD-02 fresh-session invariant preserved. | ✓ |
| Custom Deserialize accepting both shapes for one milestone | ~30 LOC of bridging + 2 tests; complicates wire-type invariant story; tagged removal at v2.7. | |
| Write a one-time migration tool | `nono audit migrate <session-id>` rewrites pre-v2.6 NDJSON in place. ~100 LOC + new subcommand; integrity rewrites Merkle root concern. | |

**User's choice:** Accept the break; old ledgers no longer re-verifiable (Recommended)
**Notes:** Audit-attestation is session-fresh by design; replay of pre-upgrade ledgers is a documented limitation, not a security regression.

### Question 3 — Should Plan 45-02 rename the variant `Granted → Approved`?

| Option | Description | Selected |
|--------|-------------|----------|
| Rename `Granted` → `Approved` in the atomic commit | Matches SC#2 wording, Phase 23 D-01 comments, audit_commands.rs:867 fixture, conventional security terminology. Folded into the single atomic commit; ~10 extra LOC; prevents future code-vs-wire drift. | ✓ |
| Keep `Granted`; inline `ResourceGrant` only | Smaller diff (no renames). SC#2 wording becomes colloquial slip; locks in naming drift permanently. | |

**User's choice:** Rename `Granted` → `Approved` in the atomic commit (Recommended)
**Notes:** PROJECT.md's v2.1 PROF-01..04 / AUD-01..05 sections use "Approved" throughout; supervisor.rs comments at 1995, 2000, 3580 also use "Approved" — rename closes the drift.

---

## RESL native re-validation host strategy

### Question 1 — How should Plan 45-03 handle the host-blocked execution?

| Option | Description | Selected |
|--------|-------------|----------|
| Author `.github/workflows/phase-45-resl-native-host.yml`; CI runs on ubuntu-24.04 + macos-latest; defer live run to Phase 46 | Workflow + protocol doc + REQ-RESL-NIX-04 STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN. Mirrors Phase 37 / Phase 44 cross-target-clippy carry-forward pattern. | ✓ |
| Close REQ-RESL-NIX-04 as PARTIAL with documented deferral; no new artifacts | Smallest blast radius; rely on Phase 27.2 transitive closure as sufficient. Lose the workflow artifact. | |
| Run live via GitHub Actions during this phase (push branch + monitor) | User-initiated push + CI wait. Real verification; longest wall-clock. | |

**User's choice:** Author workflow; defer live run to Phase 46 (Recommended)
**Notes:** Creates a real, reusable verification artifact that Phase 46 orchestrator invokes explicitly. REQ-RESL-NIX-04 closes as STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN per `.planning/templates/cross-target-verify-checklist.md` semantics.

### Question 2 — What trigger shape should `phase-45-resl-native-host.yml` use?

| Option | Description | Selected |
|--------|-------------|----------|
| `workflow_dispatch` only (manual trigger, tactical one-off) | Phase 46 orchestrator runs once with `gh workflow run`. Doesn't burn CI minutes on every PR. Deletable in v2.7 once verdict recorded. Includes `gh_runner_os: { choice [ubuntu-24.04, macos-latest, both], default: both }` input. | ✓ |
| Always-on (pull_request + push to main), like phase-37-linux-resl.yml | Permanent CI lane catches future regressions. Higher CI-minute cost. | |
| `workflow_dispatch` + scheduled weekly | Manual trigger + weekly cron. Compromise; modest CI-minute cost. | |

**User's choice:** `workflow_dispatch` only (Recommended)
**Notes:** SC#3 explicitly says "tactical confirmation pass only — does not block phase close if no gap is found". Permanent always-on lane is over-engineering for the tactical scope.

---

## Claude's Discretion

The following sub-decisions are explicitly left to planner discretion in CONTEXT.md § Implementation Decisions § Claude's Discretion:

- **Exact path for `aipc_sdk.rs`** — planner locates at plan-open via `grep -rln "aipc_sdk" crates/`.
- **23 pre-existing test inventory** — planner inventories at plan-open via `grep -rn "ApprovalDecision::Granted\|grant: Option\|(Granted, grant=None)" crates/ bindings/`; surface as deviation if count differs from 23 by more than ±2.
- **CHANGELOG.md entry placement + exact wording** — must include BREAKING marker, wire shape change, fresh-session vs replay distinction, ADR back-reference.
- **`docs/architecture/audit-bundle-target.md` ADR amendment shape** — planner picks heading level + amendment number (likely 45-A or 45-1).
- **`is_granted()` / `is_denied()` impl method renames** — planner discretion on whether to rename in-place or retain ergonomic alias.
- **`.github/workflows/phase-45-resl-native-host.yml` matrix specifics** — planner picks exact `runs-on` strings, `continue-on-error: true` per-OS shape, cache + setup-action choices.
- **`45-03-NATIVE-RESL-PROTOCOL.md` content depth** — planner picks the depth; minimum required: SC#3 decision tree, expected `cargo test` output shape, Phase 46 hand-off instructions.
- **cbindgen header byte-identical gate mechanics** — planner picks pre-phase capture + diff mechanism (tempfile + diff vs `git diff bindings/c/nono.h`).
- **Plan numbering / suggested slugs** — 45-01-EDITION-2024-MIGRATION, 45-02-AIPC-G04-TIGHTENING, 45-03-RESL-NATIVE-REVALIDATION. Planner may refine.

## Deferred Ideas

- **`is_granted()` → `is_approved()` impl method rename ergonomics** — planner discretion at plan-open.
- **Project-wide `Granted` → `Approved` comment / docstring sweep beyond Plan 45-02 atomic commit** — planner-discretion sweep; otherwise file follow-up todo for v2.7 cleanup.
- **One-time `nono audit migrate` tool for legacy ledger forward-port** — rejected at D-45-C2; revisit in v2.7+ if user demand surfaces.
- **Permanent always-on CI lane for audit-attestation native-host coverage** — if post-Phase-45 experience shows audit-attestation is regression-prone, promote workflow to always-on.
- **Sibling-binding cascade verification for the wire-format break** — planner verifies `../nono-py/` + `../nono-ts/` FFI consumers at plan-open; Phase 44 D-44-D1 lockstep precedent available.
- **Cluster 2 DIVERGENCE-LEDGER amendment exact ledger location** — planner verifies canonical path at plan-open.

### Reviewed Todos (not folded)

- **`44-class-d-validator-preflight-investigation.md`** (score 0.6) — Phase 44 D-44-C3 follow-up; explicitly tagged for future Linux-host phase per Phase 44 CONTEXT § Deferred Ideas. Keyword match reflects generic vocabulary, not topical fit.
- **`44-validate-restore-target-fd-relative-hardening.md`** (score 0.6) — Phase 44 D-44-B4 follow-up; substantial cross-platform refactor requiring own security-scoped phase per Phase 44 CONTEXT § Deferred Ideas.

Both stay in `.planning/todos/pending/` for the appropriate future phase.
