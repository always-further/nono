---
slug: gap-v039-linux-poc-vs-windows-fork-tip
created: 2026-04-29
completed: 2026-04-29
status: complete
type: research-only
---

# Quick task SUMMARY: Gap matrix — upstream v0.39.0 (Linux POC) vs fork tip

**Status:** ✅ Complete (research-only deliverable; no code changes).

**Deliverable:** `PLAN.md` — gap matrix in three buckets, demo-strategy recommendation, and proposed v2.3 remediation phase.

## Outcome

Categorized 191 commits in the `v0.39.0..HEAD` range across `crates/`:

- **Bucket A (8 cross-platform clusters)** — fork tip has, v0.39 binary lacks. AUD-01..04, PROF-01..04, POLY-01..03, PKG-01..04 partial, OAUTH-01..03. All demo-able 🟢 on fork-Linux-build except AUD-03 Authenticode discriminant which is Windows-only (silent omission on Linux 🟡).
- **Bucket B (7 Windows-only clusters)** — AIPC handle brokering, WSFG mandatory labels, Job Object RESL enforcement, Authenticode discriminant, AUD-05 ledger emissions. Linux behavior ranges from compile-error (WSFG) to silent no-op-with-warning (RESL) to immediate `UnsupportedPlatform` runtime error (AIPC).
- **Bucket C (2 demo-blockers)** — AIPC client SDK (compiles cross-platform; runtime-fails on Linux without broker) and RESL silent no-ops on Linux/macOS.

## Demo-strategy recommendation

Hybrid: fork-Linux-build with managed expectations (option C). Demo Bucket A as marquee wins; convert Bucket B/C into "Windows-first / Linux-equivalent shipping in v2.3" roadmap statements rather than visible failures. Concrete 6-step demo script in PLAN.md § Demo-strategy recommendation.

## Proposed v2.3 phase

**Phase 25 — Cross-Platform RESL + AIPC Unix Design** (1 phase, 2 plans):
- **Plan 25-01** — Cross-platform RESL Unix backends (cgroup v2 on Linux + `setrlimit` on macOS). 3–4 days. Subsumes the existing v2.3 backlog row in PROJECT.md verbatim.
- **Plan 25-02** — AIPC Unix futures design sketch. 1–2 days exploratory. ADR-level decision on which AIPC HandleKinds admit Unix analogs (Socket/Pipe via SCM_RIGHTS) vs which are inherently Windows-only (JobObject/Event/Mutex).

**Why short:** Zero protocol changes, no compile-time tightening, reuses v2.1 Phase 16 acceptance criteria. Hard part is honest scoping (25-02), not implementation (25-01).

## Tag boundary verified

- Upstream v0.39.0: 2026-04-21 (`6a284447`)
- Fork HEAD post-v2.2: 2026-04-29 (`b9963323`)
- 191 commits in `crates/` between the two — Phase 22 (UPST2) cherry-picks for AUD/PROF/POLY/PKG/OAUTH + Windows-native phases 16–23 (RESL/ATCH/AIPC/WSFG/AUD-05).

## What this is NOT

- Not a /gsd-new-milestone scope-lock. The proposed Phase 25 is a candidate for v2.3 when the user runs `/gsd-new-milestone` next.
- Not a code change. Read-only research.
- Not a replacement for the existing v2.3 backlog. Plan 25-01 explicitly subsumes the "Cross-platform RESL Unix backends" backlog row; everything else in the v2.3 backlog (PKG streaming, audit-attestation hardening, Authenticode chain-walker, WR-01 unification, AIPC G-04 wire tightening) is independent of this phase.

## STATE.md update

Append row to STATE.md "Quick Tasks Completed" table referencing this directory.
