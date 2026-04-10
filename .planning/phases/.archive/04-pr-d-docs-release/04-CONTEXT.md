# Phase 4: PR-D Docs & Release - Context

**Gathered:** 2026-04-03
**Status:** Ready for planning

<domain>
## Phase Boundary

Update public-facing documentation to reflect the aligned Windows support contract now that PR-A/B/C have delivered it. Three files change: `README.md`, `docs/cli/development/windows-promotion-criteria.mdx`, and `docs/cli/internals/security-model.mdx`. Document WIN-1706 closeout with green CI evidence. No code changes — this phase is docs only.

</domain>

<decisions>
## Implementation Decisions

### README surgery (DOCSREL-01)

- **D-01:** README line 88 — remove the entire paragraph ("On Windows, the CLI support contract is broader than the current embedded library contract...") entirely. This paragraph exists only to explain the now-gone CLI/library split. No replacement sentence needed — the library section stands on its own.
- **D-02:** README line 46 — remove the single sentence "The embedded library `Sandbox::apply()` contract remains partial on Windows for now." from the platform support paragraph. The surrounding sentences (`nono shell` / `nono wrap` limitations, link to Installation Guide) remain and are still accurate.
- **D-03:** No other README changes in scope. The platform support line, the kernel sandbox feature table, and all other content are correct as-is.

### `security-model.mdx` Windows section (DOCSREL-02)

- **D-04:** Remove only the "current support-contract split" paragraph (lines 373–378 — the block beginning "There is also a current support-contract split to keep in mind:"). This paragraph described the old CLI/library split and is now false post-PR-A.
- **D-05:** The section header ("Windows currently uses a narrower restricted-execution command surface than Linux or macOS") and the structural limitations paragraph (deny-within-allow not available, preflight mediation still applies) are still accurate — leave them unchanged.
- **D-06:** No rewrite of the Windows section framing beyond removing the split paragraph. The real structural limitations (deny-within-allow, launch-time mediation) are not fixed by WIN-1706 and must remain documented.

### `windows-promotion-criteria.mdx` update (DOCSREL-02)

- **D-07:** Update in-place. Update or remove lines that still describe the old "CLI supported, library partial" split as the adopted contract (currently lines 8, 28, 63–64, 68–71). The gate checklist entries that are already "Met" remain; "In progress" gates are updated to "Met" where Phase 3 completed them.
- **D-08:** Append a `## Milestone Closed: WIN-1706` section at the bottom of the file. This is the primary home for DOCSREL-03 closeout evidence.

### WIN-1706 closeout artifact (DOCSREL-03)

- **D-09:** The `## Milestone Closed: WIN-1706` section in `windows-promotion-criteria.mdx` contains:
  1. A CI status badge (always-current, links to the `windows-security` workflow)
  2. A pinned GitHub Actions run URL — the executor pulls the most recent successful `windows-security` run from the GitHub API at execution time (the specific run that passed after Phase 3 landed)
  3. A one-paragraph summary: WIN-1706 closed under the full aligned contract (library + CLI + CI + docs), not just the CLI-surface contract; `Sandbox::apply()` is real on Windows; the CLI/library split is gone
- **D-10:** The pinned run URL format: `https://github.com/{owner}/{repo}/actions/runs/{run_id}` — executor fetches via `gh run list --workflow=ci.yml --branch=main --status=success --limit=1 --json databaseId` or equivalent
- **D-11:** No new file for closeout — everything lives in `windows-promotion-criteria.mdx`. The workstream doc (`windows-win-1706-option-1-workstream.mdx`) is not modified.

### Claude's Discretion
- Exact badge markdown syntax (use GitHub's standard `[![CI](badge-url)](workflow-url)` pattern)
- Whether to update the `windows-win-1706-decision-package.mdx` reference at the bottom of `windows-promotion-criteria.mdx` — fine to leave it as a historical link
- Ordering of badge vs pinned run URL in the closeout section
- Whether the "In progress" REL-01 gate entry (CI lanes treat Windows identically) gets a note referencing Phase 3's completion commit

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase requirements
- `.planning/REQUIREMENTS.md` — DOCSREL-01, DOCSREL-02, DOCSREL-03 (what each requires)
- `.planning/ROADMAP.md` §Phase 4 — Success criteria (3 criteria, each independently verifiable)

### Files being modified
- `README.md` — Lines 46 and 88 are the only stale passages; read the full file before editing to avoid breaking surrounding context
- `docs/cli/development/windows-promotion-criteria.mdx` — All 93 lines; the split language is scattered through lines 8, 14–15, 28–29, 63–64, 68–71; closeout section goes at the bottom
- `docs/cli/internals/security-model.mdx` — Lines 373–378 are the only removal target; read lines 355–380 for context before editing

### Prior phase context (for understanding what's now true)
- `.planning/phases/01-pr-a-library-contract/01-VERIFICATION.md` — Confirms `Sandbox::apply()` is real on Windows (the fact that makes the split language false)
- `.planning/phases/03-pr-c-ci-verification/03-VERIFICATION.md` — Confirms CI lanes are green under the aligned contract

### Docs navigation (read-only — understand the doc landscape)
- `docs/cli/development/windows-win-1706-decision-package.mdx` — Referenced from promotion-criteria; historical, not modified
- `docs/cli/development/windows-win-1706-option-1-workstream.mdx` — Historical workstream doc; not modified in this phase

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- None — this is a pure docs phase, no code files modified

### Established Patterns
- Existing badge syntax in the repo follows GitHub's standard `[![label](badge-url)](link-url)` pattern — match it
- MDX files in `docs/cli/` use standard Markdown; no JSX components needed for the closeout section

### Integration Points
- The executor needs `gh` CLI access to fetch the pinned run URL via `gh run list`
- All three files are already committed and tracked; no new files created

</code_context>

<specifics>
## Specific Ideas

- The pinned CI run URL is fetched at execution time, not hardcoded here — executor uses `gh run list --workflow=ci.yml --branch=main --status=success --limit=5 --json databaseId,headBranch,conclusion` and picks the most recent successful run on main after Phase 3 landed
- README line 88 is a full standalone paragraph — deleting it leaves no orphaned context; the Library section reads cleanly without it
- `windows-promotion-criteria.mdx` lines 68–71 contain the old claim that `WIN-1706` is complete "under the adopted CLI-surface support contract" — this needs to be updated to reflect the stronger aligned contract WIN-1706 actually delivered

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 04-pr-d-docs-release*
*Context gathered: 2026-04-03*
