---
phase: 31-broker-process-architecture-shell-01
plan: 04
subsystem: release-pipeline
tags: [windows, broker, ci, release-pipeline, signing, msi, authenticode, wix]

# Dependency graph
requires:
  - phase: 31-broker-process-architecture-shell-01
    plan: 02
    provides: "nono-shell-broker workspace member crate; cargo build -p nono-shell-broker --release --target x86_64-pc-windows-msvc produces a 770KB nono-shell-broker.exe artifact (D-05 broker workspace-member discipline)"
  - phase: 31-broker-process-architecture-shell-01
    plan: 03
    provides: "WindowsTokenArm::BrokerLaunch dispatch in spawn_windows_child resolves broker via current_exe.parent().join('nono-shell-broker.exe') (D-07 sibling resolution; install-time deployment must land broker in the same dir as nono.exe for the cascade arm to find it)"
provides:
  - "release.yml build step: cargo build -p nono-shell-broker --release --target x86_64-pc-windows-msvc (Windows-only matrix entry)"
  - "release.yml sign step: ArtifactPaths array extended to include broker.exe alongside nono.exe + machine MSI + user MSI (single Authenticode key per Phase 28 chain-walker requirement)"
  - "release.yml verify step: Get-AuthenticodeSignature foreach loop extended to include broker.exe (D-13 fail-closed: signing or verification failure aborts release before upload)"
  - "release.yml zip step: Compress-Archive -LiteralPath @($binary, $broker) bundles both binaries into nono-${tag}-${target}.zip"
  - "release.yml zip-payload verification step: extracted-zip foreach loop validates both binaries' Authenticode signatures (D-13 belt-and-suspenders)"
  - "release.yml prepare-upload step: stages broker.exe into artifact_staging\\ alongside nono.exe and the zip so the broker ships as a standalone signed artifact"
  - "build-windows-msi.ps1 -BrokerPath mandatory parameter: validated via Test-Path (fail-closed throw on missing path); resolves to $brokerFullPath; threaded into the WiX manifest as <Component Id='cmpNonoShellBrokerExe'> inside the always-present ProductComponents ComponentGroup so both machine-scope and user-scope MSIs ship the broker"
affects:
  - 31-05-field-test
  - 31-06-docs-flip

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "D-05 broker artifact in release pipeline: workspace-member crate built on Windows runners only via -p nono-shell-broker; Linux/macOS targets skip the broker build entirely (the cargo workspace's #[cfg(not(windows))] stub from Plan 31-02 keeps the workspace green for cross-compile parity but is not shipped)"
    - "D-07 sibling resolution at install time: WiX <Component Id='cmpNonoShellBrokerExe'> lives in the ProductComponents ComponentGroup under Directory='INSTALLFOLDER' — the same dir cmpNonoExe lives in. Both machine MSI (Program Files\\nono\\) and user MSI (LocalAppData\\Programs\\nono\\) deploy the broker to current_exe().parent() at runtime. No scope guard required because the ComponentGroup uses ComponentGroupRef in the Feature."
    - "D-13 fail-closed Authenticode pipeline extended: the broker.exe joins the existing 4-stage gate — (1) signtool sign + signtool verify inside sign-windows-artifacts.ps1 (script unchanged; only the -ArtifactPaths array extends), (2) Get-AuthenticodeSignature secondary verification on the raw .exe, (3) Get-AuthenticodeSignature on the extracted-zip payload, (4) Test-Path before staging into artifact_staging\\. Any failure on any stage exits 1 before the actions/upload-artifact step runs."
    - "Pattern: append-only mandatory parameter discipline. -BrokerPath mirrors $BinaryPath's [Parameter(Mandatory = $true)] shape so release.yml's caller cannot accidentally omit it. PowerShell parser enforces the mandatory check at invocation time before any script body executes ('Cannot process command because of one or more missing mandatory parameters: BrokerPath')."

key-files:
  created:
    - ".planning/phases/31-broker-process-architecture-shell-01/31-04-SUMMARY.md (this file)"
  modified:
    - ".github/workflows/release.yml (+47 / -19; new 'Build broker (Windows)' step + Package step extended with -BrokerPath + Sign step's ArtifactPaths extended + Verify step's foreach extended + zip step uses Compress-Archive -LiteralPath @($binary, $broker) + zip-verification foreach extended + prepare-upload stages broker)"
    - "scripts/build-windows-msi.ps1 (+26 / -0; new mandatory -BrokerPath parameter + Test-Path validation + $brokerFullPath resolution + new <Component Id='cmpNonoShellBrokerExe'> inside ProductComponents ComponentGroup)"

key-decisions:
  - "release.yml broker build as a SEPARATE step (`Build broker (Windows)`) rather than appended to the existing `Build` step. Rationale: keeps the existing nono-cli build cache hit independent; the broker builds against the same workspace + lockfile, so adding it as a sibling step costs only the broker's own cold-cache time (~3min per Plan 31-02 measurement). Conditioning on `if: runner.os == 'Windows'` keeps Linux/macOS targets skipping the broker entirely (cross-compile parity preserved by construction)."
  - "build-windows-msi.ps1 -BrokerPath as MANDATORY parameter (not optional). Rationale: v2.3 SHELL-01 enforcement requires the broker; making it optional would let release.yml silently ship MSIs without the broker if the YAML invocation accidentally omits the flag. Mandatory enforces fail-closed at the parameter level — PowerShell's argument-binding gate fires before any script body runs."
  - "broker <Component> inserted inside the always-present ProductComponents ComponentGroup (between cmpNonoExe and cmpReadme), NOT in a scope-conditional branch. Rationale: the broker must ship in BOTH machine-scope MSI (Program Files\\nono\\) and user-scope MSI (LocalAppData\\Programs\\nono\\). The Feature uses <ComponentGroupRef Id='ProductComponents' /> (line 232), so all components inside the group are auto-referenced — no Feature-level <ComponentRef> edit needed. The existing $serviceComponentXml/$eventLogComponentXml gating on 'machine' scope confirms this pattern is the correct shape for unconditional components."
  - "ArtifactPaths array extended to @($binary, $broker, $machineMsi, $userMsi) — broker placed BETWEEN $binary and the MSIs to keep the .exe pair grouped. Rationale: scripts/sign-windows-artifacts.ps1 iterates the array verbatim (sign each, then verify each); ordering only affects readability of CI log output. Grouping the .exe artifacts together makes log scanning easier when debugging signing failures."
  - "Zip bundle Compress-Archive switched to -LiteralPath @($binary, $broker) (was @($binary)). Rationale: the zip is the install-method-of-last-resort for users who don't run the MSI; without the broker in the zip, those users would hit NonoError::BrokerNotFound at runtime. The zip-verification step's foreach loop is the matching belt-and-suspenders gate."
  - "scripts/sign-windows-artifacts.ps1 NOT modified. Rationale: the script's signtool primitive is byte-identical for any .exe / .msi input. The script accepts -ArtifactPaths as [string[]]; passing a 4-element array (binary, broker, machineMsi, userMsi) instead of 3 (binary, machineMsi, userMsi) requires zero script changes. D-12 (DigiCert + SHA-256) and D-14 (signtool only) invariants preserved unchanged."
  - "YAML structural validation via PyYAML's safe_load (passed locally) rather than actionlint (not installed on this runner). actionlint is the strongest option but the plan's Step 9 mode (b) explicitly defers to CI's built-in workflow validation if actionlint is unavailable. PyYAML's safe_load is a stricter check than the plan required (catches structural YAML errors that the plan's grep-based criteria would miss). Both pwsh and powershell parsers also accept the modified build-windows-msi.ps1 cleanly."

patterns-established:
  - "Pattern: extending sign-windows-artifacts.ps1's calling shape (the ArtifactPaths array) without modifying the script itself. Future broker-style sibling artifacts (e.g. nono-wfp-service.exe, nono-attest.exe) just append to the array; the script's foreach iterator handles them transparently."
  - "Pattern: WiX <Component> insertion inside ProductComponents ComponentGroup (with ComponentGroupRef in the Feature) for unconditional sibling binaries. The component's KeyPath='yes' on the <File> matches the existing cmpNonoExe shape — both binaries get their own GUID per build (Guid='*') so MajorUpgrade tracks them as distinct atoms."

requirements-completed: []

# Metrics
duration: ~30min
completed: 2026-05-09
---

# Phase 31 Plan 04: Release Pipeline + MSI Bundle Extensions Summary

**Extended the Windows release pipeline to build, sign, verify, package, and upload `nono-shell-broker.exe` alongside `nono.exe` on every tag-triggered or workflow_dispatch release run.** The broker ships as: (a) a standalone signed `.exe` artifact, (b) inside the `nono-${tag}-${target}.zip` bundle as a sibling of `nono.exe`, and (c) inside both machine-scope and user-scope MSI installers as a sibling component under `INSTALLFOLDER`. D-13 fail-closed Authenticode semantics extend to the broker — any signing or verification failure aborts the release before upload, with the same single Authenticode key as `nono.exe` (Phase 28 `parse_signer_subject` chain-walker requirement). Plan 31-05's field test on a fresh install (or zip extraction) sees `nono-shell-broker.exe` as a sibling of `nono.exe`, satisfying D-07 (`current_exe().parent()` resolves the broker), unblocking the runtime cascade arm wired by Plan 31-03.

## Performance

- **Duration:** ~30 min
- **Started:** 2026-05-09T03:18Z (after worktree HEAD assertion + reset to base 27a1bf88)
- **Completed:** 2026-05-09T03:48Z
- **Tasks:** 2
- **Files modified:** 2 (`.github/workflows/release.yml`, `scripts/build-windows-msi.ps1`)
- **Lines added:** +73 (release.yml +47 / build-windows-msi.ps1 +26)
- **Lines removed:** -19 (release.yml -19 / build-windows-msi.ps1 -0)

## Accomplishments

- **`Build broker (Windows)` step** added between the existing `Build` step and `Build (cross aarch64-unknown-linux-gnu)` step. Conditioned on `runner.os == 'Windows'`; runs `cargo build --release --target ${{ matrix.target }} -p nono-shell-broker` to produce `target/x86_64-pc-windows-msvc/release/nono-shell-broker.exe`. Linux/macOS targets skip this step entirely.
- **`Package (Windows)` step** extended to pass `-BrokerPath $broker` to both `build-windows-msi.ps1` invocations (machine + user scope). New `Test-Path $broker` guard fails the step early if the broker binary is missing from the build output.
- **`Sign Windows artifacts` step** extended `ArtifactPaths` from `@($binary, $machineMsi, $userMsi)` to `@($binary, $broker, $machineMsi, $userMsi)`. `scripts/sign-windows-artifacts.ps1` is unchanged — its `[string[]] $ArtifactPaths` parameter accepts the 4-element array verbatim; signtool sign + signtool verify now run on all 4 artifacts.
- **`Verify Authenticode signatures (Windows)` step** extended its `foreach ($artifact in @(...))` loop to include `$broker`. D-13 fail-closed semantics (exit 1 on any `Status -ne "Valid"`) now cover all 4 artifacts.
- **`Create zip from signed binary (Windows)` step** switched from `Compress-Archive -LiteralPath $binary` to `Compress-Archive -LiteralPath @($binary, $broker)`. The zip now contains BOTH binaries.
- **`Verify signed binaries inside zip (Windows)` step** (renamed from `Verify signed binary inside zip (Windows)`) now extracts the zip and runs `Get-AuthenticodeSignature` on both extracted binaries via a `foreach ($name in @("${{ matrix.artifact }}", "nono-shell-broker.exe"))` loop. Any failure exits 1.
- **`Prepare upload (Windows)` step** stages `$broker` into `artifact_staging\` alongside `$binary` and `$zipName`. The pre-existing `Test-Path` guards for `$binary` and `$zipName` were unified into a `foreach ($f in @($binary, $broker, $zipName))` loop covering all 3 paths.
- **`build-windows-msi.ps1` -BrokerPath parameter** added as `[Parameter(Mandatory = $true)] [string]$BrokerPath` immediately after `$BinaryPath` in the param block. PowerShell's argument-binding gate enforces the mandatory check before any script body executes (verified: running with no args produces `Cannot process command because of one or more missing mandatory parameters: BrokerPath`).
- **`build-windows-msi.ps1` broker validation block** added after `$binaryFullPath` resolution: `if (-not (Test-Path -LiteralPath $BrokerPath)) { throw "BrokerPath does not exist: '$BrokerPath'." }` then `$brokerFullPath = (Resolve-Path -LiteralPath $BrokerPath).Path`. Mirrors the existing `$ServiceBinaryPath` validation pattern (fail-closed throw on missing path).
- **`build-windows-msi.ps1` WiX `<Component Id="cmpNonoShellBrokerExe">` block** inserted inside the `<ComponentGroup Id="ProductComponents">` here-string, immediately after `cmpNonoExe`. The component's `<File Source="$brokerFullPath" KeyPath="yes" />` mirrors `cmpNonoExe`'s shape exactly. The component lives under `Directory="INSTALLFOLDER"` (the ComponentGroup's directory), so both binaries install to the same dir at runtime — `current_exe().parent()` resolution per D-07 is satisfied for both machine scope (`Program Files\nono\`) and user scope (`LocalAppData\Programs\nono\`). No Feature-level `<ComponentRef>` edit is needed because the Feature uses `<ComponentGroupRef Id="ProductComponents" />` (line 232).
- **YAML structurally valid** (`python -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"` exits 0). PowerShell parser accepts `build-windows-msi.ps1` cleanly (`pwsh -NoProfile [System.Management.Automation.Language.Parser]::ParseFile(...)` exits 0).
- **scripts/sign-windows-artifacts.ps1 unchanged** — only the calling shape (the `-ArtifactPaths` array passed by `release.yml`) extends. D-12 (DigiCert + SHA-256) and D-14 (signtool only) invariants preserved.

## Task Commits

Each task committed atomically on `worktree-agent-adda70c6368f4146c`:

1. **Task 1: Extend release.yml — build, sign, verify, zip, upload nono-shell-broker.exe alongside nono.exe** — `54abb3f7` (feat). 1 file changed, +47 / -19.
2. **Task 2: Extend build-windows-msi.ps1 with mandatory -BrokerPath parameter** — `390870aa` (feat). 1 file changed, +26 / -0.

_STATE.md / ROADMAP.md untouched in worktree mode (per the orchestrator's parallel-execution contract; the Wave 3 orchestrator owns those writes after this worktree merges)._

## Files Created/Modified

- **`.github/workflows/release.yml`** — Added `Build broker (Windows)` step (Windows-only conditional, `cargo build -p nono-shell-broker --release --target ${{ matrix.target }}`); extended `Package (Windows)` step to resolve `$broker` and pass `-BrokerPath $broker` to both `build-windows-msi.ps1` invocations; extended `Sign Windows artifacts` step's `ArtifactPaths` array to include `$broker`; extended `Verify Authenticode signatures (Windows)` step's `foreach` loop to include `$broker`; extended `Create zip from signed binary (Windows)` step to use `Compress-Archive -LiteralPath @($binary, $broker)`; renamed `Verify signed binary inside zip (Windows)` → `Verify signed binaries inside zip (Windows)` with a `foreach ($name in @(...))` loop validating both extracted binaries; extended `Prepare upload (Windows)` step to stage `$broker` into `artifact_staging\` (consolidated the existing `Test-Path` guards into a `foreach` loop for symmetry).
- **`scripts/build-windows-msi.ps1`** — Added new mandatory `-BrokerPath` parameter at the top of the param block (immediately after `-BinaryPath`); added new `Test-Path -LiteralPath $BrokerPath` validation + `Resolve-Path` block immediately after the existing `$binaryFullPath` resolution (mirrors the `$ServiceBinaryPath` validation pattern); inserted new `<Component Id="cmpNonoShellBrokerExe" Guid="*">` block inside the `<ComponentGroup Id="ProductComponents">` here-string, immediately after `cmpNonoExe`. The component's `<File Id="filNonoShellBrokerExe" Source="$brokerFullPath" KeyPath="yes" />` mirrors `cmpNonoExe`'s shape.

## Decisions Made

See `key-decisions` in the frontmatter. Notable items:

- **Separate `Build broker (Windows)` step** rather than appended to existing `Build` step: keeps `nono-cli` build cache independent; broker is conditional on `runner.os == 'Windows'` so Linux/macOS targets skip entirely.
- **`-BrokerPath` mandatory, not optional**: v2.3 SHELL-01 enforcement requires the broker; mandatory enforces fail-closed at the parameter level (PowerShell's argument binder catches missing arg before script body runs).
- **Broker `<Component>` in always-present ProductComponents ComponentGroup**: ships in BOTH machine and user MSI; no scope guard needed because the Feature uses `<ComponentGroupRef Id="ProductComponents" />` and all components inside auto-reference.
- **`scripts/sign-windows-artifacts.ps1` NOT modified**: the script's signtool primitive is byte-identical for any `.exe`/`.msi` input; only the calling shape (the `-ArtifactPaths` array) extends. D-12/D-14 invariants preserved.

## Threat-Model Coverage (per plan `<threat_model>`)

| Threat ID | Disposition | Status |
|-----------|-------------|--------|
| T-31-22 (unsigned broker uploaded if D-13 not extended) | mitigate | The Verify step lists the broker in `foreach ($artifact in @($binary, $broker, $machineMsi, $userMsi))` — `Get-AuthenticodeSignature` failure exits 1 BEFORE the upload step runs. The Sign step's `signtool sign + signtool verify` (inside `sign-windows-artifacts.ps1`) also runs on the broker. Both checks must pass. ✓ |
| T-31-23 (signing cert leakage via build logs) | accept | `sign-windows-artifacts.ps1` is unchanged in this plan. The new `ArtifactPaths` array contains only file paths, not secrets. Risk unchanged from baseline. ✓ |
| T-31-24 (MSI install-dir DACL allows non-admin write to broker) | mitigate | The MSI installs to `Program Files\nono\` (machine scope) or `LocalAppData\nono\` (user scope). Both DACLs match the existing `nono.exe` install — broker inherits the same protection. ✓ |
| T-31-25 (unsigned broker passes Phase 28 chain-walker) | mitigate | The broker is signed with the SAME Authenticode key as `nono.exe` (sign step's `ArtifactPaths` array). Single signing identity for both processes. ✓ |
| T-31-26 (TOCTOU between MSI install and first invocation) | accept | Same threat surface as `nono.exe` itself; install-dir DACL is the boundary. Documented; accepted. ✓ |

## Verification

After both tasks land, the plan's verification line items resolve as follows:

1. **YAML structural validation** — `actionlint` not installed on this runner; per plan Step 9 mode (b), CI's built-in workflow validation catches any structural error. Strongest local check: `python -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"` exits 0 (PyYAML is available on this runner). PowerShell parser accepts `build-windows-msi.ps1` cleanly via `[System.Management.Automation.Language.Parser]::ParseFile(...)`.
2. **Grep checks** — `nono-shell-broker` count: 9 in `release.yml` (>= 8 required), 2 in `build-windows-msi.ps1` (>= 1 required); `BrokerPath` count: 2 in `release.yml` (>= 1 required), 4 in `build-windows-msi.ps1` (>= 4 required); `--no-verify` count: 0 in `release.yml` (no shortcuts that bypass signing/verification).
3. **`-BrokerPath` mandatory enforcement** — `powershell -Command "& '...\build-windows-msi.ps1' -VersionTag 'v0.0.0-test' -BinaryPath 'C:\Windows\System32\notepad.exe'"` fails with the message `Cannot process command because of one or more missing mandatory parameters: BrokerPath`. ✓
4. **Manual workflow_dispatch on a Windows release tag** — deferred to actual tag-triggered run. Plan 31-05's field-test will exercise the produced artifacts.

## Cross-Compile Parity

This plan modifies CI/script files only. Zero Rust source files touched (`git diff --name-only 27a1bf88..HEAD | grep '\.rs$'` returns empty). The cross-compile parity invariant ("`cargo build --workspace` builds clean on Linux and macOS via the broker's `#[cfg(not(windows))]` stub") was already validated by Plan 31-02; this plan does not regress it.

## Deviations from Plan

None. Tasks 1 and 2 executed exactly as specified by the plan. The verification grep counts match or exceed all plan-spec'd minimums.

## Issues Encountered

- **Edit/Write went to main checkout instead of worktree on first round of release.yml edits.** Same root-cause as 31-02 and 31-03 SUMMARYs documented: the `Read` tool was given an absolute path under `C:\Users\OMack\Nono\` (the main checkout) rather than the worktree path, and the subsequent `Edit` tool calls preserved that path. Detected at the pre-commit `git status --short` step (worktree showed `M` on no files; the main checkout had the changes). Remediated by `cp` of the modified `release.yml` from the main checkout to the worktree, then `git checkout --` of the main checkout's copy. No commits landed on the wrong branch; no work was lost. Task 2's build-windows-msi.ps1 edits used the worktree-absolute path explicitly to avoid the same trap.

## User Setup Required

None — no external service configuration required. The workflow definition changes take effect on the next tag-triggered or workflow_dispatch release run; signing secrets (`WINDOWS_SIGNING_CERT`, `WINDOWS_SIGNING_CERT_PASSWORD`) are already configured per v2.0 / v2.2 release infrastructure.

## Next Phase Readiness

- **Plan 31-05 (field-test):** the broker artifact will ship into both MSIs and the zip on the next release run. Plan 31-05's field-test on a fresh install (or zip extraction) will see `nono-shell-broker.exe` as a sibling of `nono.exe`, unblocking the `WindowsTokenArm::BrokerLaunch` cascade arm wired by Plan 31-03 (which currently fails fast with `NonoError::BrokerNotFound { path }` at any `nono shell` invocation on a Windows host).
- **Plan 31-06 (docs flip):** the cookbook's `nono shell --profile claude-code` v3.0-deferral text can flip to "supported on Windows v2.3+" once Plan 31-05 confirms field-test pass.
- **No blockers.** Worktree branch `worktree-agent-adda70c6368f4146c` is ready for the orchestrator's post-Wave-3 merge.

## TDD Gate Compliance

Both tasks were tagged `tdd="false"` per plan frontmatter. Workflow YAML and PowerShell script changes do not lend themselves to unit-test guards inside the Rust workspace; the structural acceptance criteria (grep-based literal-string checks + PowerShell parser + PyYAML safe_load) are the appropriate verification surface. Plan 31-05's field-test is the runtime acceptance event — it exercises the actual signed artifact + actual MSI install + actual broker spawn end-to-end.

## Self-Check: PASSED

All 2 files claimed in this SUMMARY exist on disk:

```
$ ls .github/workflows/release.yml scripts/build-windows-msi.ps1
.github/workflows/release.yml
scripts/build-windows-msi.ps1
```

Both commit hashes (`54abb3f7`, `390870aa`) are reachable in `git log --oneline`:

```
$ git log --oneline 27a1bf88..HEAD
390870aa feat(31-04): extend build-windows-msi.ps1 with mandatory -BrokerPath parameter
54abb3f7 feat(31-04): extend release.yml to build, sign, verify, zip, and upload nono-shell-broker.exe
```

All literal-string acceptance criteria from both tasks pass:

```
$ grep -c "nono-shell-broker" .github/workflows/release.yml
9
$ grep -c "p nono-shell-broker" .github/workflows/release.yml
1
$ grep -c "BrokerPath" .github/workflows/release.yml
2
$ grep -c '@($binary, $broker, $machineMsi, $userMsi)' .github/workflows/release.yml
2
$ grep -c '"nono-shell-broker.exe"' .github/workflows/release.yml
1
$ grep -c 'Copy-Item $broker artifact_staging' .github/workflows/release.yml
1
$ grep -c -- '--no-verify' .github/workflows/release.yml
0
$ grep -c "BrokerPath" scripts/build-windows-msi.ps1
4
$ grep -c "nono-shell-broker" scripts/build-windows-msi.ps1
2
$ grep -c 'Test-Path -LiteralPath $BrokerPath' scripts/build-windows-msi.ps1
1
```

PowerShell parser + PyYAML safe_load both accept the modified files; mandatory-parameter enforcement on `-BrokerPath` verified via runtime invocation.

---
*Phase: 31-broker-process-architecture-shell-01*
*Wave: 3 (depends on Plan 31-02 + Plan 31-03)*
*Completed: 2026-05-09*
