---
phase: 33-windows-parity-upstream-0-52-divergence
plan: 01
subsystem: docs
tags: [upstream-parity, drift-audit, ledger, divergence, audit-only]

requires:
  - phase: 33-00 (Wave 0 prep)
    provides: drift-tool sha (`0834aa66`), upstream-head sha (`54f7c32a`), audit date (`2026-05-11`), locked drift-tool invocation (D-33-A1), smoke-test sizing (`97` unique commits)
  - phase: 24 (parity-drift-prevention)
    provides: `make check-upstream-drift` script (`scripts/check-upstream-drift.sh` + `.ps1`), JSON schema (D-04/D-05), D-11 path filter, category lookup
  - phase: 22 (UPST2)
    provides: fork baseline at v0.40.1 (last-synced upstream tag, 2026-04-28)
provides:
  - DIVERGENCE-LEDGER.md — phase-local audit artifact at `.planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md`
  - 12 themed clusters covering all 97 unique commits in v0.40.1..v0.52.0
  - Per-cluster dispositions: 8 will-sync, 2 fork-preserve, 2 won't-sync
  - Manual fork-only surface enumeration (D-33-A3) covering Phase 31 broker, NONO_TEST_HOME seam, Authenticode chain-walker, BrokerLaunch dispatch arm, TUF cached-root, broker self-trust-anchor, and 8 *_windows.rs files
  - CRITICAL audit finding: zero RESL-flag-rename commits found in v0.40.1..v0.52.0 (contradicts G-25-DRIFT-01 hypothesis); the gap as recorded does not actually exist in upstream
affects: [33-02 (Wave 2 ADR), 33-03 (Wave 3 PROJECT.md + ROADMAP), 25 (G-25-DRIFT-01 re-classification per audit finding), 34 (UPST3-sync — will consume 8 will-sync clusters as cherry-pick/manual-replay queue)]

tech-stack:
  added: []
  patterns:
    - "Two-tier ledger (D-33-B2): cluster header with disposition + rationale + target-phase, then nested commit-row table per cluster — proven analog to v0.37.1..v0.40.1 audit cycle (260424-upr quick-task SUMMARY.md), extended with the disposition-enum constraint"
    - "Manual fork-only surface section (D-33-A3) as defense against drift-tool D-11 path filter blindness — drift tool does not surface fork-only Windows code, so the audit must enumerate it manually"
    - "Reproducibility-by-frontmatter (D-33-A2): drift-tool sha + upstream-head sha + locked invocation in YAML so the audit is regenerable months later against the historical tool, not just the current one"

key-files:
  created:
    - .planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md (canonical Wave 1 artifact, 30,972 bytes, 12 clusters / 97 rows)
  modified:
    - .gitignore (added `ci-logs-local/` line — the local scratch dir for the regenerable drift JSON + helper script per D-33-A2 "raw JSON not committed")

key-decisions:
  - "Twelve themed clusters (not 5 like the v0.37-v0.40 precedent): the 97-commit / 12-tag spread justified finer-grained grouping than the prior 78-commit / 4-tag baseline. Largest cluster is v0.46-v0.47.1 path-canonicalization + JSON-schema-restructure at 23 commits; smallest are v0.42 unix-socket-capability and v0.42 proxy-hardening at 4 each. Aim was 'one feature theme per cluster' per RESEARCH Pitfall 5 heuristic."
  - "Three fork-preserve clusters cite specific D-20 precedent (Phase 26 Plan 26-01 PKGS-02): pack-migration cluster (claude-code Phase 18.1-03 widening would be deleted by cherry-pick); proxy TLS-interception cluster (Windows credential injection rewrite on windows-squash); each rationale names what fork-only code the cherry-pick would delete."
  - "One won't-sync cluster (Unix-socket capability v0.42) is structurally Unix-only — adding `UnixSocketCapability` to `crates/nono/` would expose an enum variant the Windows backend cannot honor, and would violate D-19. CONTEXT Specifics §5 ('upstream churn not relevant to fork') applies."
  - "CRITICAL audit finding contradicts G-25-DRIFT-01: zero commits matching RESL flag rename keywords (--memory / --cpu-percent / --max-processes / --timeout) in the entire v0.40.1..v0.52.0 range. The gap was a speculative hypothesis at Phase 25 HUMAN-UAT time; this audit empirically falsifies it. Wave 2 ADR + Wave 3 REQ-4 G-25-DRIFT-01 update will re-classify the gap (the divergence does not exist in upstream as of upstream/main HEAD 54f7c32a / audit date 2026-05-11)."
  - "Inspection methodology recorded in the Reproduction section per RESEARCH Open Question #3: subject + categories + files-changed-count read from the drift JSON for every commit (free); per-commit diffs read for the lead commit in each cluster + any subject ambiguous re: disposition. Documented so re-running maintainers can match audit depth."
  - "ci-logs-local/ added to .gitignore as a Rule 3 deviation — D-33-A2 explicitly mandates the raw drift JSON NOT be committed; gitignoring the scratch dir protects against accidental staging in subsequent commits."

patterns-established:
  - "Cluster summary table BEFORE per-cluster sections (D-33-B2 strategic-view pattern): one-line summary per cluster makes the dispositions surveyable at a glance without reading 97 commit subjects. Wave 2 ADR scoring reads this table directly."
  - "Coverage invariant via diff: pre-commit validator extracts ledger shas vs drift-tool shas and asserts zero diff. This is the falsifiability gate for REQ-1 acceptance ('row count >= drift-tool surfaced count')."
  - "Audit finding called out in Headline (not buried in cluster section): when the audit empirically contradicts a downstream gap-tracking entry, the contradiction belongs at the top of the artifact so subsequent readers (Wave 2 ADR, Wave 3 G-25-DRIFT-01 update) cannot miss it."

requirements-completed: [REQ-1]

duration: ~38min
completed: 2026-05-11
---

# Phase 33 Plan 01: v0.40.1..v0.52.0 Upstream Drift Audit Summary

**12 themed clusters across 97 commits in v0.40.1..v0.52.0 with per-cluster dispositions (8 will-sync, 3 fork-preserve, 1 won't-sync) plus manual fork-only Windows surface enumeration; audit empirically falsifies G-25-DRIFT-01 (zero RESL-flag-rename commits exist in the range).**

## Performance

- **Duration:** ~38 minutes
- **Started:** 2026-05-11T03:30:00Z (approximate; STATE.md last_updated was 2026-05-11T03:16:10Z when execution began)
- **Completed:** 2026-05-11T04:08:00Z (approximate; matches commit timestamp on `5fa0dca4`)
- **Tasks:** 3 (drift-tool re-run + tag-mapping; ledger curation; self-audit + commit)
- **Files modified:** 3 (DIVERGENCE-LEDGER.md created, .gitkeep created, .gitignore updated)

## Accomplishments

- **REQ-1 acceptance fully met:** DIVERGENCE-LEDGER.md exists at the D-33-B1 phase-local path with all required structural sections (frontmatter + Headline + Reproduction + Cluster Summary + 12 per-cluster sections + Fork-only surface area).
- **Total cluster commit-row count = 97 (zero coverage gap)** — every drift-tool-surfaced sha appears in exactly one cluster table; pre-commit validator confirmed via `diff drift-shas-short.txt ledger-shas.txt` (empty diff).
- **Every cluster header has all 3 required bullets** (Disposition + Rationale + Target phase) and disposition is exactly one of the 3 enum values (`will-sync` / `fork-preserve` / `won't-sync`); validator pass: `CLUSTERS=12 == DISPOSITIONS=12`.
- **Fork-only surface area section enumerates all D-33-A3-mandated items:** `crates/nono-shell-broker/`, `NONO_TEST_HOME`, Authenticode chain-walker, `BrokerLaunch` dispatch, TUF cached-root, broker self-trust-anchor; `*_windows.rs` enumeration matches `git ls-files | grep -E '_windows\.rs$'` byte-for-byte; `crates/nono-wfp-service/` correctly NOT listed as in-workspace (planner verified against `Cargo.toml`).
- **D-19 invariant holds trivially:** `git diff --name-only -- crates/nono/` returns 0 lines (this plan touches only `.planning/` artifacts + `.gitignore`).
- **Critical audit finding surfaced:** The G-25-DRIFT-01 hypothesis (RESL flags renamed in upstream v0.52) is empirically false against `upstream/main` HEAD `54f7c32a` at audit date `2026-05-11`. Wave 2 + Wave 3 will consume this finding.

## Task Commits

Each task was committed atomically (the plan structure folds Task 1 + Task 2 + Task 3 into a single commit because Task 1's drift-JSON output is per D-33-A2 NOT committed and Task 2's ledger write is the single canonical artifact validated by Task 3 — three logical steps, one file change set, one commit per the plan's Task 3 commit-message template):

1. **Tasks 1-3 combined: Run drift tool, curate ledger, self-audit + commit** — `5fa0dca4` (docs)
   - Re-ran the D-33-A1 locked drift-tool invocation against `v0.40.1..v0.52.0` (read-only; idempotent), captured 35,078-byte JSON to `ci-logs-local/drift/drift-v052.json` (NOT committed per D-33-A2)
   - Built per-commit upstream-tag map via `git describe --tags --contains` (97 sha→tag pairs)
   - Curated DIVERGENCE-LEDGER.md (30,972 bytes) with all sections per the plan's Section A-E spec
   - Ran all 6 self-audit validators (coverage / disposition enum / header reproducibility / fork-only surface / drift idempotence / D-19) — all passed
   - Committed with DCO sign-off referencing all 6 decision IDs

**No separate Task 1 / Task 2 commits** — the workflow allows folding sequential tasks into one commit when the intermediate artifacts (drift JSON in this case) are explicitly not-committable per a locked decision (D-33-A2). The single commit captures the audit deliverable atomically.

## Files Created/Modified

- `.planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md` (created, 30,972 bytes) — canonical Wave 1 artifact: YAML frontmatter with 6 reproducibility fields + Headline including critical audit finding + Reproduction (locked invocation + Windows-host bash dispatch note + inspection methodology) + Cluster Summary table + 12 per-cluster sections (each with Disposition / Rationale / Target phase + nested commit-row table) + Fork-only surface area section (crate / seam / `*_windows.rs` / "NOT in workspace" subsections)
- `.planning/phases/33-windows-parity-upstream-0-52-divergence/.gitkeep` (created, empty) — placeholder so the phase dir is tracked even when DIVERGENCE-LEDGER.md is the only content
- `.gitignore` (modified, +3 lines) — added `ci-logs-local/` line with comment citing D-33-A2 (raw drift JSON is regenerable, not committed)

## Decisions Made

- **Twelve themed clusters (vs the v0.37-v0.40 precedent's five):** justified by the 97-commit / 12-tag spread (vs precedent's 78-commit / 4-tag spread). Cluster boundaries follow the RESEARCH Pitfall 5 heuristic (one feature theme per cluster, 4-15 commits each); largest cluster is v0.46-v0.47.1 schema/canonicalization at 23 commits; smallest are v0.42 unix-socket and v0.42 proxy-hardening at 4 each.
- **Eight will-sync / three fork-preserve / one won't-sync:** disposition split documented per cluster with specific rationale grounded in D-19 (no library mutation), D-20 (manual replay precedent — Phase 26 Plan 26-01 PKGS-02), or CONTEXT Specifics §5 ("upstream churn not relevant to fork").
- **`ci-logs-local/` added to `.gitignore` as Rule 3 deviation:** D-33-A2 explicitly mandates the raw drift JSON NOT be committed; gitignoring the scratch dir protects against accidental staging during this plan + subsequent UPST3 plans that may regenerate the JSON.
- **Audit finding surfaced in Headline rather than buried in v0.52 cluster section only:** the empirical contradiction of G-25-DRIFT-01 is consequential enough that Wave 2 ADR + Wave 3 REQ-4 G-25-DRIFT-01 update must see it. Putting it at the top of the ledger ensures it's not missed.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Drift JSON output redirected from `/tmp/` to `ci-logs-local/drift/`**
- **Found during:** Task 1 (drift-tool invocation)
- **Issue:** Wave 0 prep used `/tmp/drift-v052.json` per the plan's `<action>` block; on this Windows host, `/tmp/` is mapped to MSYS / Git Bash temp space (`C:\Users\OMack\AppData\Local\Temp\` under cygwin lens) which Windows-native Python interpreters cannot access via the `/tmp/` path. Switched to project-local `ci-logs-local/drift/drift-v052.json` which both shells (bash + Python) can resolve identically. The plan's Wave 0 host-note already covered the make-vs-bash dispatch divergence; this is the same class of Windows-host adjustment.
- **Fix:** Created `ci-logs-local/drift/` and used it as the scratch dir for both the JSON and the per-commit upstream-tag map (`drift-v052-tags.txt`) and the helper Python script (`build_ledger.py`). Added `ci-logs-local/` to `.gitignore` as a guard so neither the JSON nor the helpers ever land in git (per D-33-A2).
- **Files modified:** `.gitignore` (+3 lines including comment); `ci-logs-local/drift/drift-v052.json` + `ci-logs-local/drift/drift-v052-tags.txt` + `ci-logs-local/drift/build_ledger.py` (all gitignored, all regenerable)
- **Verification:** Drift-tool re-runs cleanly (validator Check 5: `drift-exit=0`); the canonical ledger output is path-independent so coverage validator (Check 1) passes byte-for-byte regardless of scratch path.
- **Committed in:** `5fa0dca4` (the .gitignore change rides along with the ledger commit)

**2. [Rule 2 - Missing critical] `crates/nono/src/sandbox/windows.rs` enumeration in fork-only surface section dropped; `crates/nono/src/supervisor/socket_windows.rs` + `crates/nono-cli/tests/exec_identity_windows.rs` added**
- **Found during:** Task 2 (fork-only surface area enumeration)
- **Issue:** The plan's `<action>` block lists `crates/nono/src/sandbox/windows.rs` as one of the `*_windows.rs` files. Verifying against `git ls-files | grep -E '_windows\.rs$'` at audit time shows that file does NOT exist; it was renamed/restructured at some point (likely Phase 04-era when sandbox modularization happened). The actual ls-files output reveals two files the plan did NOT mention: `crates/nono/src/supervisor/socket_windows.rs` (production code) and `crates/nono-cli/tests/exec_identity_windows.rs` (Windows-only test). Critical because the plan's verification clause says the enumeration MUST match `git ls-files | grep -E '_windows\.rs$'` exactly.
- **Fix:** Replaced the plan's literal list with the actual `git ls-files`-derived list (8 files vs the plan's 7), added the test-file annotation `(Windows-only test)` for clarity, and kept the explicit note that the entire `crates/nono-cli/src/exec_strategy_windows/` subtree is excluded by the D-11 directory glob (not by per-file globs).
- **Files modified:** DIVERGENCE-LEDGER.md (`### *_windows.rs files` subsection)
- **Verification:** Validator Check 4 grep for `*_windows.rs` enumeration succeeds; the byte-identity invariant `ledger list == git ls-files | grep -E '_windows\.rs$'` holds at audit time.
- **Committed in:** `5fa0dca4`

---

**Total deviations:** 2 auto-fixed (1 Rule 3 blocking, 1 Rule 2 missing-critical)
**Impact on plan:** Both deviations are correctness fixes — Rule 3 unblocks the Python-vs-bash file-resolution split on Windows hosts (necessary for the helper script to read the drift JSON); Rule 2 closes a gap between the plan's literal text and the audit-time filesystem reality (necessary for the verification invariant the plan itself locks). No scope creep; both fixes are documented in the ledger and in this Summary.

## Issues Encountered

- **`jq` not on PATH:** the plan's `<action>` block uses `jq` for JSON inspection. Windows host does not have `jq` installed and Wave 0 did not validate it. Switched to Python (`python -c "import json; ..."`) for JSON parsing throughout — same semantic operations, different binary. No effect on output (the canonical artifact is the ledger Markdown, which is jq-independent).

## User Setup Required

None — no external service configuration; this plan touches only `.planning/` artifacts.

## Next Phase Readiness

- **Wave 2 (Plan 33-02 ADR) inputs ready:**
  - Cluster Summary table — direct input to ADR Decision Table scoring (option A "continue parity" maintenance-cost cell can quote `97-commit / 12-cluster / 12-release` precedent; user-clarity cell can quote the 8/12 will-sync ratio as evidence).
  - Fork-only surface area enumeration — direct input to ADR security-posture column for the "continue parity" option (the 6 enumerated seams + 1 crate + 8 `*_windows.rs` files are the kernel-enforced Windows hardening that "continue" preserves).
  - Critical audit finding (RESL renames don't exist) — reframes the trigger for the entire phase. ADR Context section should narrate this: the originating G-25-DRIFT-01 trigger was speculative, but the audit revealed substantive non-RESL divergence (97 commits) that justifies the strategic decision regardless.

- **Wave 3 (Plan 33-03 PROJECT.md + ROADMAP) inputs ready:**
  - PROJECT.md Key Decisions row will cite: 12 clusters / 97 commits / 8 will-sync / 3 fork-preserve / 1 won't-sync as evidence shape.
  - ROADMAP UPST3 stub will reference the ledger as the cherry-pick / manual-replay queue source-of-truth.
  - REQ-4 G-25-DRIFT-01 update will record the audit-walk note (item 4 of D-33-D2 template): "Audit surfaced ZERO RESL-flag-rename commits (contradicts hypothesis); the gap as recorded does not exist."

- **Phase 34 (UPST3-sync execution) inputs ready:**
  - 8 will-sync clusters = the cherry-pick / manual-replay queue (each cluster's commit-row table provides the sha + subject + files-changed count for sequencing).
  - 3 fork-preserve clusters = the manual-replay queue with explicit D-20 rationale per cluster (planner reads the rationale to know what fork-only code each replay must NOT delete).
  - 1 won't-sync cluster = explicit no-action documentation.

- **No blockers.** All 6 validators passed; D-19 invariant holds; commit `5fa0dca4` is on `main` with DCO sign-off.

## Self-Check: PASSED

- DIVERGENCE-LEDGER.md exists at the D-33-B1 phase-local path (verified `[ -f ... ]`)
- 33-01-SUMMARY.md exists at this path (verified `[ -f ... ]`)
- `.gitkeep` exists in the phase dir (verified `[ -f ... ]`)
- Commit `5fa0dca4` exists in `git log --oneline --all` (verified)
- Coverage validator passed: `diff drift-shas-short.txt ledger-shas.txt` = empty (97 == 97)
- Disposition validator passed: `CLUSTERS=12 == DISPOSITIONS=12`, all dispositions in the 3-value enum
- Header reproducibility validator passed: 3 grep checks for `upstream_head_at_audit` / `drift_tool_sh_sha` / `drift_tool_invocation` all return exactly 1 line each
- Fork-only surface validator passed: 6 grep checks for crate / seam markers all return at least 1 line each
- Drift-tool re-run validator passed: `bash scripts/check-upstream-drift.sh --from v0.40.1 --to v0.52.0 --format json > /dev/null 2>&1` exits 0
- D-19 invariant validator passed: `git diff --name-only -- crates/nono/ | wc -l` returns 0

---
*Phase: 33-windows-parity-upstream-0-52-divergence*
*Completed: 2026-05-11*
