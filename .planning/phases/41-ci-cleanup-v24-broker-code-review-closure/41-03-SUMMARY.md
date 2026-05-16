---
phase: 41-ci-cleanup-v24-broker-code-review-closure
plan: 03
subsystem: infra
tags: [powershell, msi, windows, ci, broker, packaging]

requires:
  - phase: 31-windows-supervisor
    provides: "Made -BrokerPath mandatory on scripts/build-windows-msi.ps1 (Phase 31 Plan 04, 2026-05-09)"

provides:
  - "scripts/validate-windows-msi-contract.ps1 accepts mandatory -BrokerPath parameter and threads it unconditionally to build-windows-msi.ps1 via Get-WixDocumentForScope"
  - "CI windows-packaging job builds nono-shell-broker and passes -BrokerPath to the validator"

affects:
  - 41-ci-cleanup-v24-broker-code-review-closure
  - windows-packaging-jobs

tech-stack:
  added: []
  patterns:
    - "Mandatory parameter thread-through in PowerShell: top-level param -> function param -> $buildArgs hashtable -> call site, mirroring the $ServiceBinary optional pattern but unconditional"

key-files:
  created: []
  modified:
    - scripts/validate-windows-msi-contract.ps1
    - .github/workflows/ci.yml

key-decisions:
  - "Used Pattern (1) — thread the param from caller — not Pattern (2) which would compute a default broker path inside the validator. Keeps the validator honest: if the CI caller doesn't know where the broker is, it fails closed."
  - "Marked BrokerBinary mandatory (not optional with default '') in Get-WixDocumentForScope because build-windows-msi.ps1 has it mandatory; making it optional in the function would create a silent failure path that bypasses the mandatory check."
  - "Added nono-shell-broker build step to CI windows-packaging job to ensure the artifact exists before the validator is invoked; mirrors release.yml's existing pattern."

patterns-established:
  - "Mandatory param thread-through: when a callee adds a Mandatory param, the entire call chain must propagate it unconditionally — no optional defaults that would bypass the Mandatory enforcement at the callee."

requirements-completed:
  - REQ-CI-02

duration: 10min
completed: 2026-05-15
---

# Phase 41 Plan 03: MSI Validator BrokerPath Threading Summary

**Mandatory `-BrokerPath` parameter threaded from CI invocation through `validate-windows-msi-contract.ps1` to `build-windows-msi.ps1`, closing the PowerShell parameter-binding failure that blocked Windows Packaging CI since Phase 31 Plan 04 (2026-05-09).**

## Performance

- **Duration:** ~10 min
- **Started:** 2026-05-15T00:00:00Z
- **Completed:** 2026-05-15T00:10:00Z
- **Tasks:** 1 of 1
- **Files modified:** 2

## Accomplishments

- Added `[Parameter(Mandatory = $true)] [string]$BrokerPath` to the top-level `param(...)` block of `validate-windows-msi-contract.ps1` with a Phase 41 / REQ-CI-02 comment referencing the Phase 31 Plan 04 origin
- Added `[Parameter(Mandatory = $true)] [string]$BrokerBinary` to `Get-WixDocumentForScope`'s param block; assigned unconditionally via `$buildArgs["BrokerPath"] = $BrokerBinary` in the splat hashtable
- Added `Test-Path` guard + `Resolve-Path` canonicalization for `$BrokerPath` immediately after the existing `$binaryFullPath` resolution block (mirroring the `$ServiceBinaryPath` pattern)
- Updated both `Get-WixDocumentForScope` call sites to pass `-BrokerBinary $brokerFullPath`
- Updated `.github/workflows/ci.yml` `windows-packaging` job to build `nono-shell-broker` alongside `nono-cli` and pass `-BrokerPath .\target\release\nono-shell-broker.exe` to the validator

## Task Commits

1. **Task 1: Thread mandatory -BrokerPath through MSI contract validator + CI** - `258a6294` (fix)

**Plan metadata commit:** (follows immediately after this SUMMARY commit)

## Files Created/Modified

- `scripts/validate-windows-msi-contract.ps1` - Added top-level `$BrokerPath` param, `Get-WixDocumentForScope` `$BrokerBinary` param, `$buildArgs["BrokerPath"]` assignment, `Resolve-Path` block, and both call sites updated
- `.github/workflows/ci.yml` - `windows-packaging` job: added `nono-shell-broker` build, added `-BrokerPath` to validator invocation

## Decisions Made

- Used Pattern (1) (thread the param) not Pattern (2) (compute a default inside the validator). A validator that silently falls back to a computed broker path would mask invocation errors in CI — fail-closed is the correct behavior per CLAUDE.md.
- Made `$BrokerBinary` mandatory in `Get-WixDocumentForScope` matching `build-windows-msi.ps1`'s Mandatory declaration. An optional function param would create a code path that invokes the builder without `BrokerPath`, which would fail at the builder anyway — better to fail at the function boundary with a clear parameter-binding error.
- Added `nono-shell-broker` build step to the CI `windows-packaging` job; the artifact must exist before `Resolve-Path` is called on it. Pattern from `release.yml` which already builds the broker before packaging.

## Deviations from Plan

None - plan executed exactly as written. The five edits from 41-PATTERNS.md were applied in order. The CI workflow update was included in the same commit as specified in the plan's "CI follow-up reminder" note.

## Dryrun Verification

PowerShell AST parse check passed (0 errors):
```
pwsh -NoProfile -Command "
  $errors = $null; $tokens = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseFile(
      (Resolve-Path .\scripts\validate-windows-msi-contract.ps1).Path,
      [ref]$tokens, [ref]$errors)
  if ($errors.Count -gt 0) { exit 1 } else { Write-Host 'Syntax OK: 0 parse errors'; exit 0 }
"
```
Result: `Syntax OK: 0 parse errors`

A live end-to-end dryrun with real binary paths requires a Windows host with `nono.exe`, `nono-shell-broker.exe`, and WiX tooling — not available in this execution environment. The parameter-binding fix is verified structurally via:
- Acceptance criterion grep counts all pass
- PowerShell parser reports 0 syntax errors
- CI will provide the first live verification when the PR runs `windows-packaging`

## CI Workflow Confirmation

`.github/workflows/ci.yml` `windows-packaging` job now passes `-BrokerPath` to the validator. The `Validate Windows MSI contract` step reads:

```yaml
- name: Build Windows release binaries
  shell: pwsh
  run: |
    cargo build --release -p nono-cli
    cargo build --release -p nono-shell-broker

- name: Validate Windows MSI contract
  shell: pwsh
  run: |
    .\scripts\validate-windows-msi-contract.ps1 `
      -BinaryPath .\target\release\nono.exe `
      -BrokerPath .\target\release\nono-shell-broker.exe `
      -ServiceBinaryPath .\target\release\nono-wfp-service.exe
```

## Issues Encountered

None.

## Next Phase Readiness

- REQ-CI-02 SC#1 + SC#2 resolved for the MSI validator mismatch class
- REQ-CI-02 SC#3 honored: no `[ignored]` markers used
- Windows Build and Windows Packaging CI jobs will proceed past PowerShell parameter binding on the next PR run
- Remaining REQ-CI-02 causes (other CI failure root causes) addressed by other plans in Phase 41 wave

---
*Phase: 41-ci-cleanup-v24-broker-code-review-closure*
*Completed: 2026-05-15*
