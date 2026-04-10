# nono WIN-1706 — State as of 2026-04-03

## What this is

WIN-1706 Option 1: Windows Library/Runtime Alignment. Closes the honesty gap between the Windows CLI runtime (already enforcing via WFP and low-integrity process tokens) and `Sandbox::apply()` (which unconditionally returned `UnsupportedPlatform` on Windows). Four sequential PRs.

**Branch:** `pr/windows-epic12-clean-v2`

---

## Phase Status

| Phase | Goal | Status | Key commits |
|-------|------|--------|-------------|
| 1 — PR-A Library Contract | `Sandbox::apply()` validates real capability shapes, returns `Ok(())` for supported subset | Complete (2026-04-03) | TDD RED + GREEN |
| 2 — PR-B CLI Messaging | Remove CLI/library split from all runtime output; route through `support_info()` | Complete (2026-04-03) | Dead branch removal + test assertion updates |
| 3 — PR-C CI Verification | Windows CI lanes assert aligned contract; WFP tests gated on privilege | Complete (2026-04-03) | Help strings + harness cleanup + CI YAML |
| 4 — PR-D Docs & Release | Flip public docs to first-class Windows support; WIN-1706 closeout | **Executed — one pre-merge step remaining** | See below |

All 8 plans (2 per phase) are complete.

---

## Phase 4 Detail

### Commits landed

| Commit | What |
|--------|------|
| `11e4296` | Remove stale CLI/library split sentence from README line 46 |
| `b46e7d3` | Remove support-contract split paragraph from security-model.mdx (lines 373–378) |
| `5d3f613` | Update windows-promotion-criteria.mdx: aligned contract language, gates "Met", WIN-1706 closeout section |
| `1256fc6` | Plan 04-01 metadata |
| `dfc36ab` | Plan 04-02 metadata |
| `981ac48` | Remove stale split framing from gate table row descriptions (verifier gap fix) |

### What changed

**README.md** — Two removals:
- Line 46: deleted "The embedded library `Sandbox::apply()` contract remains partial on Windows for now."
- Line 88: deleted entire paragraph "On Windows, the CLI support contract is broader than the current embedded library contract: ..."

**docs/cli/internals/security-model.mdx** — One removal:
- Lines 373–378: deleted the "There is also a current support-contract split to keep in mind:" block

**docs/cli/development/windows-promotion-criteria.mdx** — Multiple updates:
- Intro paragraph rewritten to aligned-contract language
- Gate rows REL-01 and REL-04 flipped from "In progress" to "Met"
- Gate table descriptions updated (stale split framing removed)
- REL-01 detail bullet updated
- Current Audit Result bullets updated
- "Deliberate boundary" block replaced with aligned-contract statement
- `## Milestone Closed: WIN-1706` section appended (CI badge + closeout paragraph)

---

## One Remaining Pre-Merge Step

The `## Milestone Closed: WIN-1706` section in `windows-promotion-criteria.mdx` contains a placeholder for the pinned CI run URL (`gh` CLI was unavailable at execution time).

**Fix before merging:**

```bash
gh run list --workflow=ci.yml --branch=main --status=success --limit=1 --json databaseId
```

Then in `docs/cli/development/windows-promotion-criteria.mdx`, replace:

```
PENDING — fetch manually via: gh run list --workflow=ci.yml --branch=main --status=success --limit=1
```

with:

```
https://github.com/always-further/nono/actions/runs/{databaseId}
```

---

## Key Decisions Made

- Option 1 (alignment) adopted over Option 2 (perpetual split) — library and CLI describe the same contract
- `shell` / `wrap` remain hard-rejected on Windows throughout all phases — intentional product decisions, not gaps
- `Sandbox::apply()` validates capability sets and returns `Ok(())` for the supported Windows subset (directory-read + `network_mode: Blocked`); single-file grants and other unsupported shapes fail closed with explicit `UnsupportedPlatform`
- `is_supported()`, `support_info()`, and `apply()` describe the same contract — they cannot disagree
- `shell`/`wrap` validation fires unconditionally on Windows (the old `is_supported` guard was a security defect, now removed)
- NONO_CI_HAS_WFP hardcoded `true` in CI YAML — `windows-latest` runners are unconditionally Administrator
- Gate descriptions no longer reference the old split framing

---

## Verification Result

GAPS FOUND (both addressed):
1. Stale gate table descriptions — fixed in `981ac48`
2. Placeholder CI run URL — pre-merge manual step (documented above)

All three success criteria are met modulo the run URL placeholder.

---

## Planning Artifacts

```
.planning/
├── PROJECT.md
├── REQUIREMENTS.md        (14 requirements: LIBCON-*, CLIMSG-*, CIVER-*, DOCSREL-*)
├── ROADMAP.md
├── STATE.md
└── phases/
    ├── 01-pr-a-library-contract/   (VERIFICATION.md: apply() is real)
    ├── 02-pr-b-cli-messaging/      (VERIFICATION.md: split gone from CLI output)
    ├── 03-pr-c-ci-verification/    (VERIFICATION.md: CI lanes green)
    └── 04-pr-d-docs-release/       (VERIFICATION.md: docs aligned, one gap placeholder)
```
