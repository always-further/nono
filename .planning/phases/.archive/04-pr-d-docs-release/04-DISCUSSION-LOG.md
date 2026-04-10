# Phase 4: PR-D Docs & Release - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-03
**Phase:** 04-pr-d-docs-release
**Areas discussed:** WIN-1706 closeout evidence (area 4)

---

## WIN-1706 Closeout Evidence (DOCSREL-03)

| Option | Description | Selected |
|--------|-------------|----------|
| A — Pinned run URL | Link to specific GitHub Actions run that passed after Phase 3 | ✓ |
| B — CI badge | Always-current badge showing latest workflow status | ✓ |
| C — Statement only | Text reference to date/commit, no live URL | |
| New closeout file | Standalone `windows-win-1706-closeout.mdx` | |
| Git tag annotation | Closeout evidence in tag notes only | |

**User's choice:** Both A and B — pinned run URL (proof of moment) plus CI badge (ongoing green status). Both land in a `## Milestone Closed: WIN-1706` section appended to `windows-promotion-criteria.mdx`.

**Notes:** The user confirmed "Can we do A and B?" — both are complementary. The pinned URL proves the specific passing moment; the badge shows it has stayed green. Standard closeout pattern.

---

## README Paragraph Surgery (area 1 — not discussed, default applied)

**Default applied:** README line 88 removed entirely; line 46 loses only the "partial on Windows" sentence.

---

## `security-model.mdx` Scope (area 2 — not discussed, default applied)

**Default applied:** Remove only the split paragraph (lines 373–378). Section header and structural limitations (deny-within-allow, preflight mediation) remain — they are still accurate.

---

## `windows-promotion-criteria.mdx` Fate (area 3 — not discussed, default applied)

**Default applied:** Update in-place. Stale split language updated; closeout section appended.

---

## Claude's Discretion

- Badge markdown syntax
- Ordering of badge vs pinned URL in closeout section
- Whether `windows-win-1706-decision-package.mdx` reference at the bottom of the criteria file is updated
- Whether the "In progress" REL-01 CI gate gets a note referencing Phase 3's completion commit

## Deferred Ideas

None.
