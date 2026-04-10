---
phase: 04-pr-d-docs-release
verified: 2026-04-03T00:00:00Z
status: gaps_found
score: 2/3 must-haves verified
gaps:
  - truth: "windows-promotion-criteria.mdx and security-model.mdx contain no CLI/library split language; Windows support told through a single aligned contract"
    status: partial
    reason: "Two gate table rows in windows-promotion-criteria.mdx carry stale WIN-1705-era language that contradicts the aligned-contract narrative stated in the intro paragraph. Line 14: 'distinguishes CLI support from library partial status' implies the split still exists. Line 16: 'without overstating library parity' was the WIN-1705 framing (library was the subordinate concern); post-WIN-1706 the library is co-equal and this reads as a residual qualifier. Neither row was updated when the intro and detail sections were rewritten."
    artifacts:
      - path: "docs/cli/development/windows-promotion-criteria.mdx"
        issue: "Gate table row 1 (line 14) still reads 'distinguishes CLI support from library partial status' — the split it describes is the thing WIN-1706 eliminated. Gate table row 3 (line 16) still reads 'without overstating library parity' — the WIN-1705 framing where library parity was an asterisk."
    missing:
      - "Update line 14 gate description to: 'Runtime output is free of misleading preview language; CLI and library described under the same aligned contract'"
      - "Update line 16 gate description to: 'Windows listed as supported platform in README and release artifacts under the aligned contract'"
  - truth: "WIN-1706 closeout documented with a pointer to green CI run evidence; maintainers can point to one place"
    status: partial
    reason: "The closeout section exists, the CI badge is present and correct, and the closeout paragraph is complete. However, the pinned run URL is a placeholder ('PENDING — fetch manually via: gh run list ...') rather than a real GitHub Actions run URL. The section is 95% correct but the one concrete evidentiary pointer a maintainer would click is missing. Per the known deviation note, this is a pre-merge fix, not a blocking gap — but it does prevent the milestone from being closeable as-is."
    artifacts:
      - path: "docs/cli/development/windows-promotion-criteria.mdx"
        issue: "Line 94: pinned run URL is 'PENDING — fetch manually via: gh run list --workflow=ci.yml --branch=main --status=success --limit=1' — a placeholder, not a real run URL. The badge (line 92) is present and links to the correct workflow."
    missing:
      - "Fetch run ID: gh run list --workflow=ci.yml --branch=main --status=success --limit=1 --json databaseId"
      - "Replace placeholder with: https://github.com/always-further/nono/actions/runs/{databaseId}"
human_verification: []
---

# Phase 4: PR-D Docs & Release — Verification Report

**Phase Goal:** WIN-1740 — Public docs describe Windows as first-class supported without CLI/library qualification; `shell` and `wrap` documented as intentional product boundaries; WIN-1706 closeout backed by green CI evidence
**Verified:** 2026-04-03
**Status:** GAPS FOUND
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | README describes Windows as first-class supported; no "CLI supported, library partial" qualification anywhere in README or docs; `nono shell` / `nono wrap` limitations documented as intentional product decisions | VERIFIED | README line 46 states "Windows native builds support a real restricted-execution command surface"; "Live `nono shell` and `nono wrap` remain intentionally unavailable on Windows" — no split language present; grep confirms zero matches for "library partial", "library contract remains partial", "CLI supported, library partial" in README |
| 2 | `windows-promotion-criteria.mdx` and `security-model.mdx` contain no "CLI supported, library partial" language; Windows support story told through a single aligned contract | PARTIAL | `security-model.mdx` is clean. The intro paragraph and detail sections of `windows-promotion-criteria.mdx` are fully updated. Two gate table rows retain stale WIN-1705 language that contradicts the aligned-contract narrative (see Gaps section). |
| 3 | WIN-1706 closeout documented with a pointer to green CI run evidence; maintainers can point to one place | PARTIAL | `## Milestone Closed: WIN-1706` section exists with correct CI badge and complete closeout paragraph. The pinned run URL is a `PENDING` placeholder — the concrete evidentiary run link a maintainer would share is missing. |

**Score:** 1/3 truths fully verified (Truth 1); 2/3 truths partially verified (Truths 2 and 3)

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `README.md` | No "library partial" / split language; `shell`/`wrap` framed as intentional | VERIFIED | Both target removals confirmed present (commits 11e4296). No split language in file. Line 46 correctly describes the aligned Windows contract. |
| `docs/cli/internals/security-model.mdx` | No "support-contract split" paragraph | VERIFIED | Commit b46e7d3 removed the 7-line block. File scanned — no "CLI supported, library partial", no "support-contract split" language present. Windows Model section ends at structural limitations; Summary follows directly. |
| `docs/cli/development/windows-promotion-criteria.mdx` | No split language; all gates Met; `## Milestone Closed: WIN-1706` section with badge + run URL + paragraph | PARTIAL | Intro paragraph, detail bullets, and Current Audit Result are fully updated (commit 5d3f613). Gate table rows 1 and 3 retain stale WIN-1705 descriptions. Closeout section has correct badge and paragraph but placeholder run URL. |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `windows-promotion-criteria.mdx` closeout section | GitHub Actions CI run | Pinned run URL | PARTIAL | Badge link is correct (`https://github.com/always-further/nono/actions/workflows/ci.yml`). Pinned run URL is `PENDING` placeholder — not a real `actions/runs/{id}` URL. |
| `windows-promotion-criteria.mdx` | Aligned contract claim | Intro paragraph + Current Audit Result | VERIFIED | Line 8: "Windows is supported as a first-class platform under the full aligned contract: `Sandbox::apply()` is real on Windows, the CLI/library split is closed". Current Audit Result: WIN-1706 closeout paragraph present. |
| Gate table | Aligned contract | Row descriptions | PARTIAL | Rows 2, 4, 5, 6 correctly reflect the aligned contract. Row 1 ("distinguishes CLI support from library partial status") and Row 3 ("without overstating library parity") are stale WIN-1705 descriptions. |

---

### Data-Flow Trace (Level 4)

Not applicable — this is a documentation-only phase with no code that renders dynamic data.

---

### Behavioral Spot-Checks

Step 7b SKIPPED — documentation-only phase, no runnable entry points introduced.

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| DOCSREL-01 | 04-01-PLAN.md | README describes Windows as first-class supported; no split qualification; `shell`/`wrap` as intentional | SATISFIED | README line 46 verified clean; both stale sentences removed (commits 11e4296); grep confirms no split language |
| DOCSREL-02 | 04-01-PLAN.md, 04-02-PLAN.md | `windows-promotion-criteria.mdx` and `security-model.mdx` updated; no "CLI supported, library partial" language remaining | PARTIAL | `security-model.mdx` is clean. `windows-promotion-criteria.mdx` main content is updated but two gate table row descriptions retain stale WIN-1705 language that contradicts the aligned-contract narrative. No "CLI supported, library partial" verbatim phrase appears, but the split framing is embedded in the gate descriptions. |
| DOCSREL-03 | 04-02-PLAN.md | WIN-1706 closeout documented with verification evidence (green CI, not intent); maintainers can point to single Windows support contract | PARTIAL | Closeout section structure complete with badge. Pinned run URL is a placeholder; the concrete evidentiary pointer is missing. The milestone is documentable but not fully closeable without the run URL. |

---

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `docs/cli/development/windows-promotion-criteria.mdx` | 14 | Gate table row: "distinguishes CLI support from library partial status" | Warning | Contradicts the aligned-contract narrative in line 8; a reader of the gate table alone would infer the CLI/library split is the current contract |
| `docs/cli/development/windows-promotion-criteria.mdx` | 16 | Gate table row: "without overstating library parity" | Warning | WIN-1705 framing — implies library parity is an asterisk on the Windows claim, when post-WIN-1706 the library is fully co-equal |
| `docs/cli/development/windows-promotion-criteria.mdx` | 94 | `PENDING — fetch manually via: gh run list...` as the pinned run URL | Warning | The evidentiary link is missing; the section reads as unfinished to a reviewer |

No blockers. All three findings are warning-level: they reduce clarity and leave a residual impression of the old contract, but none of them assert a false claim as a positive statement.

---

### Gaps Summary

Two gaps, both in `docs/cli/development/windows-promotion-criteria.mdx`:

**Gap 1 — Stale gate table descriptions (DOCSREL-02 partial).**
The intro paragraph (line 8) and the detail sections correctly state the aligned contract. However, the Gate Summary table at lines 14 and 16 still carries WIN-1705-era descriptions:

- Line 14 says the gate is "Runtime output is free of misleading preview language and **distinguishes CLI support from library partial status**". The distinguishing is what WIN-1706 ended — the gate description implies the split is the contract.
- Line 16 says "Windows listed as supported CLI platform in README and release artifacts, **without overstating library parity**". This reads as though library parity is still a qualifier to hedge against.

A maintainer reviewing the gate table alone would not be able to conclude the split is closed. The fix is two short description updates — approximately one sentence each.

**Gap 2 — Placeholder CI run URL (DOCSREL-03 partial).**
The `## Milestone Closed: WIN-1706` section at the bottom of `windows-promotion-criteria.mdx` contains a well-written closeout paragraph and a correct CI badge. However, the pinned run URL — which is the "pointer to green CI run evidence" required by Success Criterion 3 — is the literal text `PENDING — fetch manually via: gh run list --workflow=ci.yml --branch=main --status=success --limit=1` instead of an actual `https://github.com/always-further/nono/actions/runs/{id}` link.

The badge provides an always-current signal. The pinned run URL was intended to provide a frozen, point-in-time record of the specific run that passed after Phase 3 landed — the evidentiary anchor for "green CI backs the claim". Without it, a reviewer cannot verify which run the claim is based on, only that the current state of the badge is green.

Per the known deviation, this is a pre-merge maintainer fix, not a fundamental content failure. The section is correct in every other respect. The gap is: one URL substitution.

**Combined impact:** Truth 2 is partially satisfied (gate table language is inconsistent with the narrative it frames). Truth 3 is partially satisfied (closeout structure complete, evidentiary link absent). Truth 1 is fully satisfied. The phase is not ready to merge as a closed milestone without the two gate description updates and the pinned run URL.

---

_Verified: 2026-04-03_
_Verifier: Claude (gsd-verifier)_
