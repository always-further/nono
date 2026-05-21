---
phase: 49
plan: 03
subsystem: docs+tooling
tags: [sigstore, trust-root, docs, maintainer-cadence, smoke-test]
requirements: [REQ-POC-TRUST-03]
dependency-graph:
  requires: []
  provides:
    - ".planning/templates/sigstore-rotation-refresh.md (maintainer-cadence template)"
    - "scripts/verify-trust-root-cached.sh (bash smoke script)"
    - "scripts/verify-trust-root-cached.ps1 (PowerShell smoke script)"
    - "docs/cli/development/windows-poc-handoff.mdx (Known issue subsection rewrite + Run once after install consistency edit)"
  affects:
    - "Phase 49 wave-close integration: smoke scripts depend on plan 49-01's `nono setup --from-file` flag; full positive self-test runs post-merge"
    - "Future Sigstore TUF root rotations: maintainer follows the new template instead of bumping sigstore-verify"
tech-stack:
  added: []
  patterns:
    - "Cross-platform shell-script pairing convention (.sh + .ps1) mirroring scripts/check-upstream-drift.{sh,ps1}"
    - "[Console]::Error.WriteLine + explicit exit N for PowerShell scripts where Write-Error + $ErrorActionPreference='Stop' would corrupt exit-code propagation"
key-files:
  created:
    - ".planning/templates/sigstore-rotation-refresh.md (94 lines)"
    - "scripts/verify-trust-root-cached.sh (49 lines, exec bit 100755)"
    - "scripts/verify-trust-root-cached.ps1 (73 lines after Rule 1 fix)"
  modified:
    - "docs/cli/development/windows-poc-handoff.mdx (+46 / -23)"
decisions:
  - "Smoke scripts wrap `nono setup --from-file <CANDIDATE>` only; the `nono trust verify` follow-on documented in the template requires a signed-bundle fixture pair not present in the repo (interfaces note in plan 49-03)"
  - "PowerShell exit-code propagation uses [Console]::Error.WriteLine instead of Write-Error to avoid Stop-mode terminating the script before exit N runs (Rule 1 fix on Task 2's .ps1, discovered during Task 4 live-host verification)"
  - "Invoke-WebRequest direct-into-cache demoted to a fallback for network-restricted hosts; primary recovery path now `nono setup --from-file` against the release-asset trusted_root.json (per plan 49-03 task 3 SPEC)"
metrics:
  duration: ~30 minutes
  completed: 2026-05-21
  commits: 4
  tasks: 4
  files_created: 3
  files_modified: 1
---

# Phase 49 Plan 03: Fixture Refresh Cadence Summary

## One-liner

Ship maintainer-cadence template + matched cross-platform smoke scripts (.sh + .ps1) + POC-handoff doc rewrite to operationalize Sigstore TUF root rotation response via `nono setup --from-file` instead of `sigstore-verify` dep bumps.

## What changed

1. **`.planning/templates/sigstore-rotation-refresh.md`** (NEW, 94 lines) — 6-step maintainer procedure mirroring `cross-target-verify-checklist.md` shape: capture upstream root → byte-diff → regression smoke → pre-commit smoke gate → commit with DCO sign-off → release-asset forward-pointer. 5 Anti-Patterns + Enforcement section. Supersedes P32-DEFER-005 on the process side.

2. **`scripts/verify-trust-root-cached.sh`** (NEW, 49 lines, exec bit 100755) + **`scripts/verify-trust-root-cached.ps1`** (NEW, 73 lines) — matched cross-platform smoke scripts:
   - Take one positional arg (candidate `trusted_root.json` path).
   - Per-invocation TempDir + `NONO_TEST_HOME` + `XDG_CONFIG_HOME` redirect.
   - Invoke `nono setup --from-file <CANDIDATE>` — must exit 0.
   - Assert cache file at `$TMP/.nono/trust-root/trusted_root.json` exists.
   - Assert cache is byte-identical to candidate (cmp -s on Unix; SHA-256 hash compare via Get-FileHash on Windows).
   - `.sh`: `set -euo pipefail` + trap-on-EXIT cleanup.
   - `.ps1`: `$ErrorActionPreference = 'Stop'` + explicit `$LASTEXITCODE` check after `& nono setup` (F-03-05 mitigation, 4 references total) + try/finally cleanup.

3. **`docs/cli/development/windows-poc-handoff.mdx`** (MODIFIED, +46/-23):
   - "Run once after install" block restructured as Path A (`--refresh-trust-root`) / Path B (`--from-file`); `--from-file` now within 8 lines of the header (F-03-04 gate).
   - "Known issue: Sigstore TUF root rotation" subsection rewritten: heading version-pin (`sigstore-verify 0.6.5`) removed; `nono setup --from-file` against the release-asset `trusted_root.json` is the primary recovery path; `Invoke-WebRequest` direct-into-cache demoted to network-restricted-host fallback; stale references purged (`sigstore-verify 0.6.5`, `P32-DEFER-005`, `deferred-items.md`, dep-treadmill prose); forward pointer to `.planning/templates/sigstore-rotation-refresh.md` in the fallback comment.

## Verification

### Pre-commit automated gates — all PASS

| Gate | Command | Result |
|------|---------|--------|
| F-03-01 template exists | `test -f .planning/templates/sigstore-rotation-refresh.md` | PASS |
| Template line count | `wc -l` ≥ 60 | 94 PASS |
| Template H2 count | `grep -c '^## '` ≥ 4 | 4 PASS |
| Template 6 steps | `grep -cE '^\*\*Step [0-9]'` | 6 PASS |
| Template smoke ref | `grep -q verify-trust-root-cached` | PASS |
| Template release.yml ref | `grep -q release.yml` | PASS |
| Template DCO | `grep -E "Signed-off-by\|DCO\|sign-off"` | PASS (3 hits) |
| Template anti-patterns | `grep -c Anti-pattern` ≥ 3 | 5 PASS |
| F-03-02 .sh exists + exec | `git ls-files -s` mode `100755` | PASS |
| F-03-02 .ps1 exists | `test -f` | PASS |
| Bash syntax | `bash -n` | PASS |
| `.sh` strict mode | `grep -q "set -euo pipefail"` | PASS |
| `.ps1` EAP=Stop | `grep -q "ErrorActionPreference = 'Stop'"` | PASS |
| F-03-05 LASTEXITCODE | `grep -c LASTEXITCODE` ≥ 1 | 4 PASS |
| `.sh` byte-identity | `grep -q "cmp -s"` | PASS |
| `.ps1` byte-identity | `grep -q "Get-FileHash"` | PASS |
| `.sh` cleanup | `grep -q "trap.*rm -rf"` | PASS |
| `.ps1` cleanup | `grep -q "finally"` | PASS |
| F-03-03 doc zero stale | `! grep -E '(sigstore-verify 0\.6\.5\|P32-DEFER-005\|deferred-items\.md)'` | PASS (exit 1, zero matches) |
| F-03-04 --from-file near Run once | `grep -A 8 'Run once after install' \| grep -q -- '--from-file'` | PASS |
| Known issue --from-file | `grep -A 30 '#### Known issue' \| grep -q 'nono setup --from-file'` | PASS |
| Known issue heading count | `grep -c '#### Known issue: Sigstore TUF root rotation'` | 1 PASS |
| Forward pointer | `grep -q sigstore-rotation-refresh` | PASS |
| Diff scope bounded | `git diff --stat` on docs/ | 1 file PASS |

### Static analyzer gates — PARTIAL (tool unavailable)

| Tool | Status | Reason |
|------|--------|--------|
| shellcheck | PARTIAL | Not installed on dev host; gate deferred to live CI lane (no PR-CI wiring per D-49-C3 maintainer-only scope — N/A). |
| PSScriptAnalyzer | PARTIAL | Not invoked (live-host execution superseded — see below). |

### Task 4 checkpoint live verification — PARTIAL→PASS

Per the plan's checkpoint protocol, Task 4 (`checkpoint:human-verify` for `.ps1` F-03-05 exit-code propagation) accepts: "At minimum the `grep -c LASTEXITCODE` automated check passes (proves the explicit-check is statically present in the script); optimally Windows-host live exit-code verification produces the expected 0/2/1 triple."

Both achieved on this host (pwsh 7.x on Windows 11):

| Scenario | Command | Expected | Observed | Verdict |
|----------|---------|----------|----------|---------|
| Static gate | `grep -c LASTEXITCODE` | ≥ 1 | 4 | PASS |
| Scenario 2 (param-validation early-exit) | `pwsh -NoProfile -File scripts/verify-trust-root-cached.ps1 "C:\does-not-exist.json"` | exit 2 | exit 2 | **PASS** |
| Scenario 3 (nono missing — substitutes for Plan 49-01-dependent failure-propagation) | `pwsh -NoProfile -File scripts/verify-trust-root-cached.ps1 "crates/nono/tests/fixtures/trust-root-frozen.json"` | non-zero (exit 1) | exit 1 | **PASS** |
| Scenario 1 (positive-path against frozen fixture with `nono setup --from-file` available) | N/A — Plan 49-01 not yet merged into this worktree; `nono` binary not on PATH | exit 0 | DEFERRED | DEFER to post-merge wave-close integration |

**Task 4 verdict:** PASS (F-03-05 mitigation works live on Windows host for the host-independent scenarios; positive-path scenario 1 deferred to post-merge per parallel-executor sequencing note).

### Deferred runtime verifications

- **Scenario 1 (positive smoke-script self-test):** Requires `nono setup --from-file` (Plan 49-01) AND a built `nono.exe` on PATH. Both unavailable in this worktree per the `<parallel_execution>` sequencing note — orchestrator runs the positive self-test post-merge against the merged HEAD's compiled binary.
- **Cadence template follow-through on the next real Sigstore root rotation:** Manual-only per VALIDATION.md § Manual-Only; verified the next time Sigstore actually rotates roots.
- **POC-handoff prose-quality review:** Reviewer reads the rewritten Known issue subsection + adjacent "Run once after install" block; not grep-checkable.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] PowerShell exit-code corruption with `Write-Error` + `$ErrorActionPreference='Stop'`**

- **Found during:** Task 4 live-host verification.
- **Issue:** `Write-Error <msg>` with `$ErrorActionPreference = 'Stop'` flips the script into error mode and terminates BEFORE the subsequent `exit N` statement executes. Observed:
  - Scenario 2 (`C:\does-not-exist.json`) returned exit 1 instead of expected exit 2.
  - Scenario 3 (catch block re-emitting via `Write-Error $_; exit 1`) ultimately returned exit 0.
- **Fix:** Replaced both `Write-Error` sites with `[Console]::Error.WriteLine("ERROR: ...")` followed by the explicit `exit N`. `[Console]::Error.WriteLine` writes to stderr without engaging the Stop-mode error pipeline, so the subsequent exit statement runs as intended.
- **Files modified:** `scripts/verify-trust-root-cached.ps1` (lines 27, 64).
- **Commit:** `f0b48684`.
- **Validation:** After fix, scenarios 2 and 3 both return correct exit codes (2 and 1) on live Windows host pwsh 7.x; LASTEXITCODE reference count still 4 (no F-03-05 regression); `$ErrorActionPreference='Stop'` still set; line count grew 67 → 73 to accommodate the explanatory inline comments.

### Architectural changes

None.

### Out-of-scope items deferred

None during this plan — scope held tight to the 4-file footprint specified in the plan frontmatter.

## TDD Gate Compliance

N/A — plan is `type: execute` (not `type: tdd`); no `tdd="true"` tasks.

## Commits

| Task | Commit | Type | Description |
|------|--------|------|-------------|
| 1 | `0a21c8c7` | docs | add sigstore-rotation-refresh maintainer cadence template |
| 2 | `4b1fcd62` | feat | add verify-trust-root-cached smoke scripts (.sh + .ps1) |
| 3 | `48ea492d` | docs | rewrite Sigstore Known issue subsection for --from-file recovery |
| 2 (Rule 1 fix) | `f0b48684` | fix | make .ps1 smoke script exit codes actually propagate |

All commits include DCO sign-off (`Signed-off-by: Oscar Mack Jr. <oscar.mack.jr@gmail.com>`).

## Files modified

- **Created (3):**
  - `.planning/templates/sigstore-rotation-refresh.md` (94 lines)
  - `scripts/verify-trust-root-cached.sh` (49 lines, mode 100755)
  - `scripts/verify-trust-root-cached.ps1` (73 lines after Rule 1 fix)
- **Modified (1):**
  - `docs/cli/development/windows-poc-handoff.mdx` (+46 / -23)

Diff scope bounded to 4 files; no surprise edits elsewhere in `docs/` or `scripts/`.

## Self-Check: PASSED

- All 4 files exist on disk at the specified paths.
- All 4 commits (`0a21c8c7`, `4b1fcd62`, `48ea492d`, `f0b48684`) present in `git log --all`.
- Worktree HEAD on `worktree-agent-a18292f67bebd470c` (per-agent namespace), parent commit `f940bbd3` (Phase 49 plan-creation commit); no protected-branch contamination.
