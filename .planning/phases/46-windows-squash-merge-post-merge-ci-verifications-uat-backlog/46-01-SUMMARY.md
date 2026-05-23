---
phase: 46-windows-squash-merge-post-merge-ci-verifications-uat-backlog
plan: "01"
closed: 2026-05-23
requirements_closed: [REQ-MERGE-01]
status: complete
commits: 20cbfadc
files_created:
  - .planning/architecture/v2.6-upstream-merge-deferral-ADR.md
  - .planning/phases/46-windows-squash-merge-post-merge-ci-verifications-uat-backlog/46-01-SUMMARY.md
files_modified:
  - .planning/quick/260428-rsu-refresh-stack-onto-upstream-tip/260428-rsu-SUMMARY.md
  - .planning/REQUIREMENTS.md
---

# Phase 46 Plan 01: v2.6 Upstream Merge Deferral ADR + REQ-MERGE-01 Close Summary

## Outcome

REQ-MERGE-01 is closed via the SC#1 "feature-flag-equivalent rollout with the gate-state explicitly documented" alternative path per D-46-A1. A new ADR landed at `.planning/architecture/v2.6-upstream-merge-deferral-ADR.md` capturing three alternative paths considered (feature-flag-equivalent rollout, re-poll maintainer, resume 260428-rsu force-rebase), the chosen path's reasoning, the maintainer-response revival trigger set (D-46-A3), and the per-phase umbrella PR pattern as the fork's go-forward upstream-contribution mode (D-46-A4). The `260428-rsu-SUMMARY.md` status was flipped from `re-deferred` to `closed-via-v2.6-rollout` with an ADR back-reference (D-46-A2). REQUIREMENTS.md REQ-MERGE-01 checkbox flipped `[ ]` → `[x]`; Traceability table updated `Pending` → `Complete`.

PRs 725 and 726 remain OPEN; the 2026-04-29 outreach remains the canonical communication with the upstream maintainer. Revival on maintainer response only — no fork-side calendar trigger.

## Decisions Honored

| Decision ID | Decision | How Implemented |
|-------------|----------|-----------------|
| D-46-A1 | Close REQ-MERGE-01 via SC#1 feature-flag-equivalent rollout alternative path | ADR created at `.planning/architecture/v2.6-upstream-merge-deferral-ADR.md`; REQUIREMENTS.md checkbox flipped `[ ]` → `[x]` |
| D-46-A2 | Land new ADR + flip 260428-rsu status `re-deferred → closed-via-v2.6-rollout` with back-reference | ADR created; `260428-rsu-SUMMARY.md` frontmatter updated with `status: closed-via-v2.6-rollout`, `closed: 2026-05-23`, `adr:` field, `closure_disposition:` field; body amendment blockquote inserted |
| D-46-A3 | Codify maintainer-response-only revival triggers; no fork-side calendar trigger | ADR `### Revival triggers (maintainer-response only)` subsection enumerates 4-bullet trigger set; explicitly notes calendar + drift-quantification triggers as NOT triggers |
| D-46-A4 | Codify per-phase umbrella PR as go-forward upstream-contribution mode; cite Phase 22/33/39/42/43 + PR 922 precedent | ADR `### Go-forward upstream-contribution mode (per-phase umbrella PR)` subsection cites `project_cross_fork_pr_pattern` memory, Phases 22/33/39/42/43, PR 922 (Phase 40) as live exemplar, and GitHub's one-PR-per-branch-pair rule |

## Artifacts

- **`.planning/architecture/v2.6-upstream-merge-deferral-ADR.md`** (NEW) — Architecture decision record capturing D-46-A1 through D-46-A4: three-option decision table with 5 criteria × L/M/H/Verdict scoring, 8 H2 sections (Context, Goals, Non-goals, Decision Table, Decision, Consequences, Alternatives Considered, References), 4 H3 subsections in Consequences (Positive, Negative, Revival triggers, Go-forward mode).
- **`.planning/quick/260428-rsu-refresh-stack-onto-upstream-tip/260428-rsu-SUMMARY.md`** (MODIFIED) — Status flipped `re-deferred → closed-via-v2.6-rollout`; `closed: 2026-05-23`, `closure_disposition:`, and `adr:` fields added to frontmatter; body amendment blockquote inserted before existing H1.
- **`.planning/REQUIREMENTS.md`** (MODIFIED) — REQ-MERGE-01 checkbox `[ ]` → `[x]`; Traceability table row `Pending` → `Complete`.
- **`.planning/phases/46-windows-squash-merge-post-merge-ci-verifications-uat-backlog/46-01-SUMMARY.md`** (NEW) — This file; Plan 46-01 close disposition.

## Revival Trigger Set

Copied verbatim from ADR `### Revival triggers (maintainer-response only)`:

Resume scope determined at trigger time. ANY of:

1. Maintainer comments on PR 725 or 726 with directional guidance (rebase, close-and-restage, alternate approach).
2. Maintainer takes substantive action on either PR (review submitted, label change, close, merge).
3. Maintainer requests a different approach via issue, discussion, or direct communication.
4. (Explicitly NOT a trigger: v3.0 milestone calendar, drift-quantification threshold — per D-46-A3 these were considered and rejected. Fork-side calendar triggers are not set; no drift level automatically re-opens REQ-MERGE-01.)

## Cross-References

- [v2.6 Upstream Merge Deferral ADR](.././.planning/architecture/v2.6-upstream-merge-deferral-ADR.md) — authoritative decision record for D-46-A1 through D-46-A4; per-option decision table; revival trigger set; go-forward upstream-contribution mode.
- [260428-rsu-SUMMARY.md](../../quick/260428-rsu-refresh-stack-onto-upstream-tip/260428-rsu-SUMMARY.md) — abandoned-path runbook disposition; 504-commit / 77-conflict scope quantification; 2026-04-29 outreach links; status flipped to `closed-via-v2.6-rollout` by this plan.
- [REQUIREMENTS.md § REQ-MERGE-01](../../REQUIREMENTS.md) — line 42; acceptance criteria: "feature-flag-equivalent rollout documented"; checkbox flipped `[x]` by this plan.
- [ROADMAP.md § Phase 46 SC#1](../../ROADMAP.md) — "feature-flag-equivalent rollout with the gate-state explicitly documented" — the verbatim alternative path language that authorizes this plan's closure mechanism.
