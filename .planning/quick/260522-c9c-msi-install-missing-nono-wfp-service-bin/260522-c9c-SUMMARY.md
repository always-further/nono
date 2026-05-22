---
phase: 260522-c9c
plan: 01
subsystem: windows-msi-packaging
tags: [windows, msi, wfp, packaging, ci]
requires:
  - dist/windows/nono-machine.wxs (existing reference manifest from d3adef81 baseline)
  - dist/windows/nono-user.wxs (existing reference manifest from d3adef81 baseline)
  - crates/nono-cli/data/windows/nono-wfp-driver.sys (checked-in pre-signed kernel driver)
  - scripts/build-windows-msi.ps1 (existing WiX generator)
  - scripts/validate-windows-msi-contract.ps1 (existing CI validator wrapper)
  - .github/workflows/release.yml (existing release pipeline)
  - .github/workflows/ci.yml (existing CI MSI emit-only step)
provides:
  - machine-scope MSI now bundles nono-wfp-service.exe AND nono-wfp-driver.sys at INSTALLFOLDER
  - scope-coherence guards in build-windows-msi.ps1 (fail-closed on incoherent flag combos)
  - new -DriverBinaryPath parameter on both build-windows-msi.ps1 and validate-windows-msi-contract.ps1
  - cmpWfpDriverSys contract assertions in CI validator (regression detection)
  - explanatory XML comment in dist/windows/nono-user.wxs documenting WFP exclusion
affects:
  - .github/workflows/release.yml (Package (Windows) step)
  - .github/workflows/ci.yml (Validate Windows MSI contract step)
  - dist/windows/nono-machine.wxs (reference manifest extended with WFP components)
  - dist/windows/nono-user.wxs (added explanatory comment)
  - scripts/build-windows-msi.ps1 (new param + scope guards + driver component emission)
  - scripts/validate-windows-msi-contract.ps1 (new param + driver assertions)
tech-stack:
  added: []
  patterns:
    - "Scope-coherence guards (fail-closed on incoherent CLI flag combinations)"
    - "Two-tier MSI verification (build generator + validator wrapper) with new -DriverBinaryPath threaded through both layers"
key-files:
  created: []
  modified:
    - scripts/build-windows-msi.ps1
    - scripts/validate-windows-msi-contract.ps1
    - .github/workflows/release.yml
    - .github/workflows/ci.yml
    - dist/windows/nono-machine.wxs
    - dist/windows/nono-user.wxs
decisions:
  - "Driver source = checked-in pre-signed copy under crates/nono-cli/data/windows/nono-wfp-driver.sys (NOT the dev build artifact under target/x86_64-pc-windows-msvc/release/). The checked-in copy is the canonical WHQL-signed distribution; the target/ artifact is a dev convenience that is not WHQL-signed."
  - "User-scope MSI deliberately omits the WFP backend (no cmpWfpServiceExe, no cmpWfpDriverSys). Kernel driver cannot load from per-user LocalAppData and the LocalSystem service cannot run from there either; refusing to ship them is more honest than producing an MSI that fails at runtime."
  - "Kernel driver registration (sc create ... type=kernel / SERVICE_KERNEL_DRIVER) is handled post-install by the existing CLI command `nono setup install-wfp-driver`, NOT by WiX. WiX's <ServiceInstall> only models user-mode services and cannot represent kernel drivers; the MSI's responsibility is solely to land the .sys file at a well-known sibling path."
  - "Both scope-coherence guards in build-windows-msi.ps1 fail closed (PowerShell `throw`): (a) user scope + service/driver flags throws; (b) machine scope must receive BOTH -ServiceBinaryPath and -DriverBinaryPath, or NEITHER (xor check). Half-installed WFP backend is worse than none."
metrics:
  duration: ~25 minutes
  completed: 2026-05-22
---

# Quick Task 260522-c9c: MSI Install Missing nono-wfp-service Binary Summary

Fixed the Windows MSI installers so the machine-scope MSI now bundles both the
WFP user-mode service binary (`nono-wfp-service.exe`) AND the pre-signed kernel
driver (`nono-wfp-driver.sys`) at `INSTALLFOLDER`, closing the
`BackendBinaryMissing` startup failure for POC users.

## What Was Built

### Task 1 — MSI generator + reference manifest updates (commit `169c56d7`)

**`scripts/build-windows-msi.ps1`:**
- Added optional `-DriverBinaryPath` parameter with `Test-Path` validation
  (fail-closed if path resolves but file missing).
- Added two scope-coherence guards before WiX content generation:
  - `user` scope + any of `-ServiceBinaryPath`/`-DriverBinaryPath` → throws.
    Kernel driver + LocalSystem service cannot run from per-user LocalAppData.
  - `machine` scope + service path XOR driver path → throws. Half-installed
    WFP backend is worse than none.
- Added `$driverComponentXml` parallel to `$serviceComponentXml`; emits
  `<Component Id="cmpWfpDriverSys">` containing `<File Source="$driverBinaryFullPath" Name="nono-wfp-driver.sys" />`.
  Deliberately omits any `<ServiceInstall>` because WiX cannot represent
  `SERVICE_KERNEL_DRIVER`.
- Updated the `</ComponentGroup>` interpolation line to splice the new driver
  component between the service component and the event-log component.

**`dist/windows/nono-machine.wxs`** (reference manifest baselined in `d3adef81`):
- Inserted `cmpWfpServiceExe` (with `<ServiceInstall>` + `<ServiceControl>`),
  `cmpWfpDriverSys`, and `cmpEventLogSource` between `cmpPath` and
  `</ComponentGroup>`. This matches what
  `build-windows-msi.ps1 -Scope machine -ServiceBinaryPath ... -DriverBinaryPath ...`
  emits at CI time.
- Driver `Source` attribute points to
  `C:\Users\OMack\Nono\crates\nono-cli\data\windows\nono-wfp-driver.sys` (the
  checked-in pre-signed copy), NOT the dev build artifact under `target/`.

**`dist/windows/nono-user.wxs`:**
- Casing fix (`nono` → `Nono` on Windows local paths) preserved from
  `d3adef81` baseline.
- Added a multi-line XML comment immediately after the opening
  `<ComponentGroup>` documenting why the user-scope MSI deliberately omits
  `cmpWfpServiceExe` and `cmpWfpDriverSys`, with a forward reference to the
  runtime probe in `exec_strategy_windows::network::probe_wfp_runtime`.

### Task 2 — CI/release pipeline wiring (commit `5c457929`)

**`.github/workflows/release.yml` (Package (Windows) step):**
- Added `$service` and `$driver` path resolution + `Test-Path` guards
  (matching the existing pattern for `$binary` and `$broker`).
- Machine-scope invocation now passes BOTH `-ServiceBinaryPath $service` AND
  `-DriverBinaryPath $driver`.
- User-scope invocation deliberately unchanged — passes neither.
  `build-windows-msi.ps1`'s new scope-coherence guard would throw on the
  combination.

**`.github/workflows/ci.yml` (Validate Windows MSI contract step):**
- Added `$driver` path resolution + `Test-Path` guard for the checked-in
  pre-signed copy under `crates/nono-cli/data/windows/`.
- Existing `validate-windows-msi-contract.ps1` invocation now passes
  `-DriverBinaryPath $driver`.

**`scripts/validate-windows-msi-contract.ps1`:**
- Extended with `-DriverBinaryPath` parameter that threads through to
  `build-windows-msi.ps1` via the existing `$buildArgs` hash.
- `Get-WixDocumentForScope` helper extended with a `$DriverBinary` parameter.
- Added a new assertion block (gated on `$driverBinaryFullPath -ne ""`) that
  validates the machine MSI contains a `<File Name="nono-wfp-driver.sys" />`
  inside a `Component Id="cmpWfpDriverSys"`, contains no `<ServiceInstall>`
  inside that component, and that the user MSI does NOT carry the driver
  file.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing critical functionality] Extended `validate-windows-msi-contract.ps1` with `-DriverBinaryPath`**
- **Found during:** Task 2 design review (running the new generator's coherence guard against the existing ci.yml invocation chain)
- **Issue:** The plan instructed me to add `-DriverBinaryPath` to ci.yml's
  invocation, but ci.yml actually invokes `validate-windows-msi-contract.ps1`
  (a wrapper), not `build-windows-msi.ps1` directly. Without threading the
  flag through the wrapper, the new scope-coherence guard in
  `build-windows-msi.ps1` would cause ci.yml to throw fail-closed on every
  PR (machine scope + service-only triggers the xor guard). Confirmed
  empirically: ran the wrapper without the new flag and observed the throw.
- **Fix:** Added `-DriverBinaryPath` param to the wrapper, plumbed it into
  `Get-WixDocumentForScope` and the `$buildArgs` hash, and added explicit
  contract assertions for `cmpWfpDriverSys` (regression detection layer:
  ensures future PRs cannot delete the driver component without breaking
  CI).
- **Files modified:** `scripts/validate-windows-msi-contract.ps1`
- **Commit:** `5c457929`
- **Why this counts as Rule 2:** Without this fix, the new flag in
  `build-windows-msi.ps1` would have shipped to main but ci.yml would have
  been broken on the very next PR — a build-time regression with no
  intervening surface to catch it. CI is the regression-detection layer
  the plan explicitly called out as needing the new plumbing.

## Authentication Gates

None — this task is purely about static MSI manifest generation and CI
pipeline plumbing.

## Verification Results

All seven invariants from the plan's `<verify>` block passed when executed
locally against fixture binaries (real `target/` binaries aren't built in
this worktree, so the test used stub `nono.exe`, `nono-shell-broker.exe`,
and `nono-wfp-service.exe` files plus the real checked-in
`nono-wfp-driver.sys`):

1. Machine scope + both flags → emits `cmpWfpServiceExe`, `cmpWfpDriverSys`,
   `cmpEventLogSource`, `ServiceInstall`, and `nono-wfp-driver.sys` Name
   attribute. **PASS**
2. User scope without flags → user `.wxs` does NOT contain
   `cmpWfpServiceExe` or `cmpWfpDriverSys`. **PASS**
3. User scope + `-DriverBinaryPath` → throws with explicit message
   "WFP service/driver binaries are machine-scope only." **PASS**
4. Machine scope + `-ServiceBinaryPath` only (no driver) → throws with
   "Machine-scope MSI requires both -ServiceBinaryPath and -DriverBinaryPath, or neither." **PASS**
5. Machine scope + `-DriverBinaryPath` only (no service) → throws (same
   message as #4). **PASS**
6. User scope + `-ServiceBinaryPath` → throws (same as #3). **PASS**
7. User scope baseline emits `cmpNonoExe` + `cmpNonoShellBrokerExe`. **PASS**

Additional checks that passed:

- `xml.etree.ElementTree` parses both `.wxs` files as well-formed XML;
  machine has 8 `<Component>` elements (5 baseline + 3 WFP), user has 5.
- `yaml.safe_load` parses both workflow files as valid YAML.
- PowerShell parser (`[System.Management.Automation.Language.Parser]::ParseFile`)
  reports zero errors on both modified `.ps1` files.
- `validate-windows-msi-contract.ps1 -DriverBinaryPath ...` succeeds
  end-to-end against fixtures and the real driver file.
- `validate-windows-msi-contract.ps1 -ServiceBinaryPath ...` (without
  driver) correctly throws via the new scope-coherence guard — confirms
  the regression-detection layer is wired.

### End-to-end manual smoke check (DEFERRED)

The plan documents a 9-step manual smoke check requiring clean Windows
VMs (install MSI, run `nono setup --check-only`, verify
`BackendBinaryMissing` no longer fires, etc.). This cannot be executed in
this environment because it requires Administrator on a clean Windows VM
plus the WiX v7 toolset to actually build the `.msi`. The live release
pipeline (post-merge) is the gate that verifies this end-to-end.

## Decision Matrix

| Decision | Choice | Rationale |
| --- | --- | --- |
| Driver source | `crates/nono-cli/data/windows/nono-wfp-driver.sys` (checked-in) | The checked-in copy is the WHQL-signed distribution artifact; `target/.../release/nono-wfp-driver.sys` is a dev convenience that is NOT WHQL-signed. Shipping the dev artifact would break driver load on customer machines (Windows refuses to load unsigned kernel drivers in production). |
| User-scope WFP backend | Omitted entirely (not just disabled) | Kernel driver cannot load from per-user LocalAppData; LocalSystem service requires admin install. Shipping either to user scope would produce an MSI that installs successfully but fails at runtime. The runtime probe already fail-closes with a directive message, so users get clear feedback. |
| Kernel driver registration | Post-install via `nono setup install-wfp-driver` (existing CLI command) | WiX's `<ServiceInstall>` only models user-mode services (`ownProcess`, `shareProcess`, etc.) — it cannot represent `SERVICE_KERNEL_DRIVER`. The CLI command uses `sc.exe` / `CreateService` with the kernel driver type. The MSI's responsibility is solely to land the `.sys` file at a well-known path. |
| Coherence guard semantics | Fail closed (`throw`) on any incoherent flag combination | CLAUDE.md security principle: "Fail Secure: On any error, deny access. Never silently degrade to a less secure state." A silently-broken WFP backend would be a security regression because the agent might believe network filtering is active when it isn't. |
| Where to add CI assertions | `validate-windows-msi-contract.ps1` (the wrapper, not ci.yml inline) | The wrapper is the existing regression-detection layer; adding driver-specific assertions there means any future PR that strips the driver component will fail CI before merge. Inline checks in ci.yml are harder to maintain and reuse across other validation entry points. |

## Follow-ups for Future Phases

These are deferrals, not blockers for closing the runtime
`BackendBinaryMissing` bug:

- **MSI custom action to auto-run `nono setup install-wfp-driver` on first
  install.** Currently the MSI just lands the `.sys` file; the user (or an
  enterprise deployment script) must run the CLI command separately to
  register the kernel driver. A WiX `CustomAction` invoking the CLI
  command at `InstallFinalize` would close the gap. Risk: custom actions
  that invoke external processes are a known source of MSI fragility; if
  the CLI command fails, the install rolls back. Worth doing only after
  the runtime path is empirically stable.
- **Cross-arch driver harvesting.** This task hardcodes `x86_64` paths.
  When/if nono ships an ARM64 Windows build, the driver path resolution
  in `release.yml` and `ci.yml` will need a matrix-aware expansion.
- **Reference `.wxs` drift detection.** `dist/windows/nono-machine.wxs`
  is hand-edited to match what `build-windows-msi.ps1` emits at CI time;
  these can drift. A future CI step could diff the static reference
  against a fresh generator run with placeholder paths to catch drift.

## Known Stubs

None — all changes are real (no placeholders, no TODOs, no hardcoded
empty values that flow to runtime).

## Threat Flags

None — the changes are purely about correctly bundling existing signed
binaries into the MSI. No new network endpoints, no new auth paths, no
new trust boundaries. The driver source is the canonical pre-signed copy
(checked in as a binary artifact, signed upstream of this commit); the
service is signed as part of the existing release pipeline alongside
`nono.exe` and the broker.

## Commits

| Commit | Type | Description |
| --- | --- | --- |
| `169c56d7` | feat | Bundle nono-wfp-driver.sys in machine-scope MSI (build-windows-msi.ps1 + both `.wxs` reference manifests) |
| `5c457929` | ci | Wire -DriverBinaryPath through release + CI MSI pipelines (release.yml + ci.yml + validate-windows-msi-contract.ps1) |

## Self-Check: PASSED

- [x] `scripts/build-windows-msi.ps1` contains `DriverBinaryPath` (verified
  via Grep)
- [x] `dist/windows/nono-machine.wxs` contains `cmpWfpDriverSys` (verified
  via Grep)
- [x] `dist/windows/nono-user.wxs` contains the 260522-c9c explanatory
  comment (verified via Grep)
- [x] `.github/workflows/release.yml` machine invocation passes
  `-DriverBinaryPath` and user invocation does not (verified via
  block-aware Python parser)
- [x] `.github/workflows/ci.yml` validator invocation passes
  `-DriverBinaryPath` (verified via Grep)
- [x] `scripts/validate-windows-msi-contract.ps1` contains
  `DriverBinaryPath` and asserts `cmpWfpDriverSys` (verified via Grep)
- [x] Commits `169c56d7` and `5c457929` exist on
  `worktree-agent-a0a871f5e9acd407f` (verified via `git log`)
- [x] Both `.wxs` files parse as well-formed XML (`xml.etree.ElementTree`)
- [x] Both workflow files parse as valid YAML (`yaml.safe_load`)
- [x] Both modified `.ps1` files parse without errors
  (`[System.Management.Automation.Language.Parser]::ParseFile`)
- [x] `validate-windows-msi-contract.ps1 -DriverBinaryPath ...` succeeds
  end-to-end against fixture binaries plus the real driver file
- [x] `validate-windows-msi-contract.ps1 -ServiceBinaryPath ...` (without
  driver) correctly throws via the new scope-coherence guard
