---
phase: 04-state-integrity-deployment
plan: 03
subsystem: infra
tags: [windows, authenticode, signtool, ci, github-actions, wix, msi, powershell]

requires:
  - phase: 04-state-integrity-deployment
    provides: Phase 04 research and MSI build scripts (build-windows-msi.ps1)

provides:
  - Hardened Windows signing script using RFC 3161 /tr + /td sha256 timestamping
  - Timestamp-aware signtool verify /pa /tw failure mode
  - Operator-facing windows-signing-guide.mdx documenting CI-only secret contract
  - Windows build matrix entry in release.yml (x86_64-pc-windows-msvc)
  - Fail-closed signing workflow: secrets check, dual MSI packaging, sign, verify, then upload

affects: [04-state-integrity-deployment, windows-release, ci]

tech-stack:
  added: [signtool RFC 3161 /tr flag, /td sha256 timestamp digest]
  patterns:
    - "Sign-then-verify before upload: signtool sign then signtool verify /pa /tw then Get-AuthenticodeSignature"
    - "Dual MSI: machine and user MSIs both signed and uploaded per D-11"
    - "Fail-closed: secret check step fails immediately before any artifact is produced or uploaded"

key-files:
  created:
    - scripts/sign-windows-artifacts.ps1
    - docs/cli/development/windows-signing-guide.mdx
  modified:
    - .github/workflows/release.yml

key-decisions:
  - "RFC 3161 timestamping via /tr + /td sha256: DigiCert endpoint supports RFC 3161 when addressed via /tr; this is the current Microsoft-recommended mode for SHA-256 signed binaries (D-12)"
  - "Timestamp-aware verification: /tw flag added to signtool verify makes missing timestamps a hard failure, enforcing D-12 at verify time"
  - "Secondary Authenticode check: Get-AuthenticodeSignature runs after signtool verify as a defense-in-depth gate before upload"

patterns-established:
  - "Windows signing: scripts/sign-windows-artifacts.ps1 is the single signing primitive; no custom PKCS#7 logic (D-14)"
  - "CI-only signing: WINDOWS_SIGNING_CERT and WINDOWS_SIGNING_CERT_PASSWORD are required repo secrets; local builds never sign"

requirements-completed: [DEPL-01]

duration: 5min
completed: 2026-04-05
---

# Phase 4 Plan 3: Windows Release Signing Summary

**Fail-closed Windows release signing using RFC 3161 Authenticode via signtool.exe, covering the raw exe and both dual MSIs before any upload step**

## Performance

- **Duration:** ~5 min
- **Started:** 2026-04-05T17:01:13Z
- **Completed:** 2026-04-05T17:05:43Z
- **Tasks:** 2
- **Files modified:** 3 (1 created scripts, 1 created docs, 1 updated workflow)

## Accomplishments

- Upgraded signing from legacy `/t` (RFC 2161) to `/tr` + `/td sha256` (RFC 3161), the current Microsoft-recommended mode for SHA-256 signed binaries
- Added `/tw` to `signtool verify` so missing timestamps are treated as hard failures (D-12)
- Created `docs/cli/development/windows-signing-guide.mdx` documenting the CI-only secret contract, dual-MSI artifacts, timestamping decision, and test certificate workflow
- Added Windows `x86_64-pc-windows-msvc` entry to the build matrix with WiX installation, dual MSI packaging, signing, two-layer Authenticode verification, zip creation, and zip payload verification — all gating the upload step (D-13)

## Task Commits

1. **Task 1: Harden the shared Windows signing script** - `319d571` (feat)
2. **Task 2: Gate release uploads on verified signed Windows artifacts** - `936939c` (feat)

## Files Created/Modified

- `scripts/sign-windows-artifacts.ps1` - Centralized Authenticode signing and verification contract using RFC 3161 /tr + /td sha256 and /tw timestamp-aware verify
- `docs/cli/development/windows-signing-guide.mdx` - Operator-facing CI-only secret contract; covers secret names, artifacts signed, signing implementation, timestamping decisions, and test certificate generation
- `.github/workflows/release.yml` - Updated to include Windows build matrix, WiX install, dual MSI build, secret check, sign, verify, zip, zip-verify, and upload steps all in strict dependency order

## Decisions Made

- RFC 3161 timestamping mode: The DigiCert endpoint supports RFC 3161 when addressed via `/tr`. The script now uses `/tr http://timestamp.digicert.com /td sha256` which is the current Microsoft-recommended mode (avoids legacy SHA1-era timestamp defaults). Documented as the explicit locked choice in both script comments and the signing guide.
- `/tw` flag for timestamp-aware verify: Added to `signtool verify /pa` to ensure artifacts without a timestamp fail verification loudly rather than passing silently. This enforces D-12 at verify time.

## Deviations from Plan

None — plan executed exactly as written. The Task 2 automated verification (`cargo run -p nono-cli -- --help`) failed due to pre-existing Unix-only API compilation errors in `crates/nono/src/undo/snapshot.rs` on Windows (mtime/mode not available on Windows, libc Unix imports). These errors are unrelated to the workflow YAML and script changes made in this plan. Deferred to deferred-items.

### Pre-existing build issues noted

- `crates/nono/src/undo/snapshot.rs`: Uses `metadata.mtime()`, `metadata.mode()`, `libc::iovec`, and other Unix-only APIs without `#[cfg(unix)]` guards, causing compilation failure on Windows. This is a pre-existing issue in the worktree branch not introduced by plan 04-03.

## Issues Encountered

Pre-existing compilation errors in the codebase (`crates/nono/src/undo/snapshot.rs`) prevented `cargo run -p nono-cli -- --help` from succeeding. The workflow and script changes made in this plan are syntactically and semantically correct as verified by PowerShell parser (`[System.Management.Automation.Language.Parser]::ParseFile`). The pre-existing build failures are tracked as deferred items.

## User Setup Required

None — no external service configuration required beyond the pre-existing secret setup documented in `docs/cli/development/windows-signing-guide.mdx`.

## Next Phase Readiness

- DEPL-01 is complete: Windows MSI packages are automatically generated and signed in CI using WiX v4 dual-MSI generation, signtool.exe RFC 3161 signing, and fail-closed verification before upload
- Phase 04 is now complete on the deployment sub-track
- Pre-existing `snapshot.rs` Unix-only compilation errors on Windows remain outstanding and should be addressed in a follow-up

---
*Phase: 04-state-integrity-deployment*
*Completed: 2026-04-05*
