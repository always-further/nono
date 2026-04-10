---
phase: 04-pr-d-docs-release
plan: "01"
subsystem: docs
tags: [windows, readme, security-model, cli-library-split, win-1706]

# Dependency graph
requires:
  - phase: 03-pr-c-ci-verification
    provides: Aligned CI and code contract — prerequisite for honest docs flip
provides:
  - README.md platform support paragraph and Library section without stale CLI/library split claims
  - security-model.mdx Windows Model section without stale support-contract split paragraph
affects: [04-pr-d-docs-release]

# Tech tracking
tech-stack:
  added: []
  patterns: []

key-files:
  created: []
  modified:
    - README.md
    - docs/cli/internals/security-model.mdx

key-decisions:
  - "No new decisions — pure removal of stale content after PR-A/B/C completed the alignment"

patterns-established: []

requirements-completed:
  - DOCSREL-01
  - DOCSREL-02

# Metrics
duration: 8min
completed: 2026-04-04
---

# Phase 4 Plan 01: Remove Stale CLI/Library Split Language from README and security-model.mdx Summary

**Surgical removal of two stale README sentences and one security-model.mdx paragraph that described the now-gone CLI/library support split — leaving surrounding content untouched.**

## Performance

- **Duration:** 8 min
- **Started:** 2026-04-04T00:20:00Z
- **Completed:** 2026-04-04T00:28:45Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Removed "The embedded library `Sandbox::apply()` contract remains partial on Windows for now." from README.md platform support paragraph (line 46 region)
- Removed standalone Windows CLI/library split paragraph from README.md Library section (line 88 region)
- Removed 6-line support-contract split block from security-model.mdx Windows Model section (former lines 373-378), leaving Windows Model structural limitations and Summary section intact

## Task Commits

Each task was committed atomically:

1. **Task 1: Remove stale sentence from README.md line 46 and stale paragraph from README.md line 88** - `11e4296` (docs)
2. **Task 2: Remove support-contract split paragraph from security-model.mdx** - `b46e7d3` (docs)

## Files Created/Modified

- `README.md` - Platform support paragraph and Library section now free of stale split claims
- `docs/cli/internals/security-model.mdx` - Windows Model section ends at structural limitations; Summary follows directly

## Decisions Made

None - pure content removal per plan specification. No new decisions required.

## Deviations from Plan

None - plan executed exactly as written.

The README.md base diff showed the file had been modified previously on the branch, but both target strings were present and both removals were executed correctly. All acceptance criteria verified with grep.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Both stale passages eliminated; public docs now accurately reflect the aligned Windows contract established in PR-A/B/C
- Ready for remaining phase 04 plans (windows-feature-gap-matrix, windows-promotion-criteria updates, WIN-1742 closeout)

---
*Phase: 04-pr-d-docs-release*
*Completed: 2026-04-04*
