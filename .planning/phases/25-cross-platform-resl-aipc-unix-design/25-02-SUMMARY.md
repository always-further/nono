---
phase: 25-cross-platform-resl-aipc-unix-design
plan: 02
status: complete
created: 2026-04-29
completed: 2026-04-29
type: design
tdd: false
risk: low
requirements:
  - AIPC-NIX-01
---

# Phase 25 Plan 02: AIPC Unix Futures ADR — Summary

## Outcome

REQ-AIPC-NIX-01 fully landed via 1 commit (this commit). Decision-only ADR at `docs/architecture/aipc-unix-futures.md` records the locked verdict for all 6 AIPC HandleKind discriminants (0..=5) — File / Socket / Pipe = Yes via SCM_RIGHTS; JobObject / Event / Mutex = Windows-only by design with documented alternate Unix mechanisms (cgroup v2 / `pipe(2)` / `flock(2)`). PROJECT.md § Upstream Parity Process now cross-links the ADR. Zero source-code changes — `git diff --stat HEAD` shows only the two locked-target files.

## Verification

All 7 plan-level verification gates pass (confirmed via `bash` checks at commit time):

| # | Gate | Expected | Actual | Status |
|---|------|----------|--------|--------|
| 1 | ADR file exists at locked path | `docs/architecture/aipc-unix-futures.md` | present | PASS |
| 2 | ADR length in [250, 400] | 250–400 lines | 251 lines | PASS |
| 3 | Decision rows match Task 1 regex `^\| (File\|Socket\|Pipe\|JobObject\|Event\|Mutex) \|` | 6 | 6 | PASS |
| 4 | H2 sections present (Context, Decision Table, Per-HandleKind Rationale, Alternate Mechanisms, Reversibility, References) | 6 | 6 | PASS |
| 5 | Status field reads "Accepted" | `**Status:** Accepted` | match | PASS |
| 6 | PROJECT.md cross-links the ADR | `grep -c 'aipc-unix-futures'` ≥ 1 | 1 | PASS |
| 7 | Zero source-code changes (no `.rs`/`.toml`/`Cargo.lock`/`Makefile`/`.sh`/`.ps1`/`.mdx` deltas) | only docs + planning | only `.planning/PROJECT.md` modified, `docs/architecture/aipc-unix-futures.md` new | PASS |

Plus the Task 3 step-7 verdict-row sanity checks (`^\| 0 .* File .* Yes` through `^\| 5 .* Mutex .* No`) all match the discriminant-ordered index table — both verdict tables (HandleKind-keyed and Discriminant-keyed) encode the same decision verbatim.

## Decisions recorded

The ADR locks these six verdicts and three alternate mechanisms (no deviation from plan-time scope-lock):

| Discriminant | Kind | Verdict | Mechanism / Alternate |
|---|---|---|---|
| 0 | File | Yes | Already cross-platform; FDs are FDs |
| 1 | Socket | Yes | Unix-domain socket + `SCM_RIGHTS` ancillary FD passing |
| 2 | Pipe | Yes | Unix-domain socket + `SCM_RIGHTS` (passes anonymous-pipe FD) |
| 3 | JobObject | No | Alternate: cgroup v2 (Plan 25-01) |
| 4 | Event | No | Alternate: `pipe(2)` for one-shot signaling |
| 5 | Mutex | No | Alternate: `flock(2)` for cross-process advisory locks |

Plus a reversibility process documenting under what circumstances the decision can be revisited (AIPC G-04 wire-protocol tightening lands; Linux gains a brokerable resource-tree primitive; etc.) and how (Status field transition, ADR supersession path).

## Plan execution notes

- **Executed inline** rather than via subagent. The plan is small (3 tasks, design-only) and the user explicitly approved this scope after weighing executor agent socket-failure risk against direct execution. Task budget per recent agent runs (planner 25-01 = 6 tool calls, planner 25-02 = 5 tool calls, prior run died at 20 tool calls without writing). Inline execution avoided that failure mode entirely.
- **Decision-only constraint preserved.** No API surface sketch, no implementation pseudocode, no architecture diagrams. Per-HandleKind rationales 5–8 sentences each. The "Implications for v2.4 implementation" subsection is informative only and does not commit the fork to specific implementation details.
- **Two decision tables, one decision.** The plan's Task 1 verification regex (`^\| (File|...) \|`) and Task 3 step-7 regex (`^\| 0 .* File .* Yes`) implied different column orderings; rather than satisfy only one, the ADR includes both a HandleKind-keyed Decision Table (canonical) and a Discriminant-ordered index (tooling-friendly). Both encode the same verdicts; any divergence would be a bug.
- **Length target reached at 251 lines.** Inside the 250–400 range. Plan suggested expanding rationale + adding informative subsections (Goals, Non-Goals, Implications, Migration, Decision History, Glossary, FAQ) rather than padding paragraphs.

## Deviations from plan

None. All locked verdicts, alternate mechanisms, structural constraints, and verification gates were satisfied as specified at plan-time.

## Cross-references

- ADR: [`docs/architecture/aipc-unix-futures.md`](../../../docs/architecture/aipc-unix-futures.md)
- Plan: [`25-02-AIPC-NIX-ADR-PLAN.md`](./25-02-AIPC-NIX-ADR-PLAN.md)
- Phase context: [`25-CONTEXT.md`](./25-CONTEXT.md)
- Companion plan: [`25-01-RESL-NIX-PLAN.md`](./25-01-RESL-NIX-PLAN.md) (RESL Unix backends; deferred to a Linux/macOS-host session — see commit message of this plan).

## What this enables

For v2.4+ AIPC implementation work:

- Unix AIPC backend implements **three** broker handlers (File, Socket, Pipe), not six.
- The three "No" verdicts (JobObject, Event, Mutex) get a single shared rejection path emitting a structured "Windows-only; use {alternate}" diagnostic with `RejectStage::BeforePrompt`.
- Profile-widening schema and audit-ledger emission shape carry over from Windows verbatim — no schema changes needed.
- Cross-platform fleet operators get a consistent `nono audit show` shape across Windows + Unix even when capability decisions differ.

The decision is reversible if and when AIPC G-04 lands or Linux/macOS gain primitives that broker JobObject/Event/Mutex shapes — see Reversibility section of the ADR for triggers and the Status field transition path.
