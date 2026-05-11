# Phase 34: UPST3 — Upstream v0.41–v0.52 Sync Execution - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-11
**Phase:** 34-upst3-upstream-v0-41-v0-52-sync-execution
**Areas discussed:** Plan slicing & wave shape, fork-preserve handling + Win retrofit depth, G-25-DRIFT-01 closure shape, PR shape / branch landing / STOP triggers

---

## Plan slicing & wave shape

### Sub-question 1: How to chunk 8 will-sync + 2 fork-preserve into plans

| Option | Description | Selected |
|--------|-------------|----------|
| One plan per cluster (10 plans) | 8 will-sync + 2 fork-preserve as dedicated plans, named by cluster theme. Maximum traceability; heavier management. | ✓ |
| Themed grouping (4-5 plans) | Group clusters by theme (CLI surface / security hardening / dev-env / fork-preserve). Fewer ceremony boundaries; less wave-parallelizable. | |
| Hybrid: themed for small, dedicated for large (6 plans) | C7 + C12 standalone; rest themed. Balances Phase 22 5-plan precedent against C7's outsized risk. | |

**User's choice:** One plan per cluster (10 plans)
**Notes:** Maps directly to Phase 33 DIVERGENCE-LEDGER.md cluster IDs; reviewer attention concentrates per cluster.

### Sub-question 2: Where C7 (path canon + JSON schema, 23 commits) lands in the wave order

| Option | Description | Selected |
|--------|-------------|----------|
| First — foundation wave | C7 alone as Wave 0. Other profile-touching clusters fork off the post-schema state. Higher upfront risk; de-risks every downstream plan. | ✓ |
| Middle — after small surgical wins | Small isolated clusters prove cherry-pick mechanics, then C7 alone, then remaining clusters. Lower mechanical-failure risk; later structural discovery. | |
| Last among will-sync | All small clusters first, then C7, then fork-preserve. Maximum small-cluster stability; risk of rework in already-landed plans. | |

**User's choice:** First — foundation wave
**Notes:** Locks the canonical JSON schema state before any other profile-touching plan starts. Matches Phase 22 D-09 PROF-as-gate pattern.

---

## fork-preserve handling + Win retrofit depth

### Sub-question 1: How to handle the 2 fork-preserve clusters

| Option | Description | Selected |
|--------|-------------|----------|
| Both in Phase 34 (C6 packs + C11 proxy-TLS as manual replays) | Dedicated plans (34-09 + 34-10) for both manual replays. Phase scope wider; ledger fully closes. | ✓ |
| C6 in scope, C11 deferred to its own phase | Carve C11 (proxy TLS, 21-file upstream change) to a separate phase. Phase 34 ledger row notes "C11 scheduled to Phase 35". | |
| Audit-context replay only; full proxy-TLS deferred | Replay only `9300de9` from C11. Skip TLS-interception entirely. 9 plans instead of 10. | |

**User's choice:** Both in Phase 34 (C6 packs + C11 proxy-TLS as manual replays)
**Notes:** Closes the disposition-complete ledger in one phase; no carry-over to UPST3.5.

### Sub-question 2: Depth of Windows retrofit for cross-platform features

| Option | Description | Selected |
|--------|-------------|----------|
| Surgical — inherit upstream, no fork-side wiring | C4 `--allow-connect-port` proxy-only (no WFP composition); C8 `nono completion` no MSI integration (user-runs-manually); C12 `nono learn` deprecation cli.rs-only (ETW path untouched). Smallest retrofit. | ✓ |
| Defense-in-depth — route through both WFP and proxy | C4 WFP + proxy composition; C8 MSI `$PROFILE.d` shim; C12 ETW docstring deprecation note. | |
| Mixed — case-by-case decisions | Each feature gets independent retrofit depth. Compromise; recorded per-decision. | |

**User's choice:** Surgical — inherit upstream, no fork-side wiring
**Notes:** "Every retrofit becomes load-bearing surface the fork owns forever." Phase 34's job is to absorb upstream, not grow Windows composition.

---

## G-25-DRIFT-01 closure shape

| Option | Description | Selected |
|--------|-------------|----------|
| Close as `no-divergence` at phase-start with audit citation | Plan 34-00 flips status before any sync work; cites DIVERGENCE-LEDGER.md Headline finding + upstream HEAD sha. Removes stale open gap up front. | ✓ |
| Close at phase-end after no-op confirmation pass | Verification re-runs `make check-upstream-drift` at phase close; ceremony but redundant given Phase 33 evidence. | |
| Close as `closed: superseded-by-watch`; create UPST4-watch trigger | Forward reference to next upstream release; defends against rename actually landing in v0.53+. Most defensive; adds tracking overhead. | |

**User's choice:** Close as `no-divergence` at phase-start with audit citation
**Notes:** Removes stale state before piling new on top. Audit empirically resolved the question.

---

## PR shape, branch landing & STOP triggers

### Sub-question 1: Branch + PR shape for 97-commit chain

| Option | Description | Selected |
|--------|-------------|----------|
| Direct-on-main, one Phase-34 PR at close (Phase 22 pattern) | All 10 plans land directly on `main`; single PR at phase close. Simplest; matches Phase 22 D-05/D-07 verbatim. Single large PR. | |
| Direct-on-main, one PR per plan (10 PRs) | Direct-on-main commits; PR-per-plan at plan close. Reviewer attention per-cluster. Heavier PR ceremony; smaller review surfaces. | ✓ |
| Integration branch `v2.4-upst3`, single PR at close | Stage on integration branch; single merge PR at close. Trivial revert-all; diverges from Phase 22/33 direct-on-main precedent. | |

**User's choice:** Direct-on-main, one PR per plan (10 PRs)
**Notes:** Per-cluster reviewer attention deemed worth the PR-ceremony overhead.

### Sub-question 2: Per-plan close gate (acceptance + STOP triggers)

| Option | Description | Selected |
|--------|-------------|----------|
| Phase 22 D-18 baseline + cross-target clippy (Linux + macOS) | Windows cargo test + Windows clippy + Linux-target clippy + macOS-target clippy + Phase 15 smoke + wfp_port_integration + learn_windows_integration. Same as Phase 22 plus two cross-target clippy invocations. | ✓ |
| Phase 22 baseline + Linux cross-target only | Same as above without macOS clippy. Faster gate, slightly looser. | |
| Full triple-target build + test on per-plan close | Add `cargo build` on Linux/macOS targets beyond clippy. Most defensive; slowest. | |

**User's choice:** Phase 22 D-18 baseline + cross-target clippy (Linux + macOS)
**Notes:** Phase 25 CR-A lesson directly motivates the cross-target clippy gate; symmetric macOS coverage adds defense without significant time cost.

---

## Claude's Discretion

- **Exact wave membership beyond D-34-A2** — planner refines Wave 1/2/3 cluster groupings based on actual surface conflict probing.
- **Plan numbering scheme** — by cluster theme (chronological by upstream tag) vs by wave order. Either acceptable as long as PLAN.md frontmatter records both.
- **`nono learn` deprecation message release-window timing** — v2.4 immediate emit vs delayed; default to immediate.
- **Plan 34-00 PR bundling** — separate tiny PR vs bundled with Plan 34-04 (Wave 0). Both acceptable.
- **PHASE-OUTCOMES.md vs DIVERGENCE-LEDGER.md amendment** for D-34-A3 won't-sync documentation.

## Deferred Ideas

- `nono completion` MSI installer integration — separate phase if user demand materializes.
- `--allow-connect-port` ↔ Phase 09 WFP defense-in-depth — separate phase if kernel-enforced port allowlisting wanted.
- `nono learn` Windows ETW deprecation routing — separate phase if active gating wanted.
- UPST4 (v0.53+) ingestion — fires per cadence rule when v0.53.0 ships.
- PHASE-OUTCOMES.md vs DIVERGENCE-LEDGER.md amendment shape for won't-sync rows.
