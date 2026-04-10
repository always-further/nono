# Phase 4: State Integrity & Deployment - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-04
**Phase:** 04-state-integrity-deployment
**Areas discussed:** Scope, Filesystem Snapshot Strategy, MSI Signing Pipeline, WFP Handle Leakage Cleanup

---

## Scope

| Option | Description | Selected |
|--------|-------------|----------|
| Discuss Phase 4 filesystem strategy (VSS vs Merkle Trees) | Core requirement for STAT-01/STAT-02 | ✓ |
| Finalize .msi signing pipeline in GitHub Actions | Core requirement for DEPL-01 | ✓ |
| Investigate WFP Handle leakage during sudden process exits | Leftover from Phase 3, affects reliability | ✓ |
| Confirm Rust MSRV requirement for windows-wfp crate | Leftover from Phase 3, affects build compatibility | ✓ |

**User's choice:** All options selected.
**Notes:** Folded all 4 todos into Phase 4 implementation scope.

---

## Filesystem Snapshot Strategy

| Option | Description | Selected |
|--------|-------------|----------|
| Merkle Trees (Recommended) | Calculate hashes and only copy changed blocks. Consistent with existing Unix implementations but CPU heavy. | ✓ |
| Windows VSS | Use Windows Volume Shadow Copy service. OS-native but requires elevation/service orchestration. | |
| Manual Copy | Simple recursive copy of the target directory to a temp folder. Slowest but easiest to implement. | |

**User's choice:** Merkle Trees (Recommended)
**Notes:** None

| Option | Description | Selected |
|--------|-------------|----------|
| Project Root Only | Only snapshot files within the current working directory. Ignore external allowed paths. | |
| All Granted Paths | Attempt to snapshot all granted file paths, even if they are scattered across the drive. | ✓ |

**User's choice:** All Granted Paths
**Notes:** None

| Option | Description | Selected |
|--------|-------------|----------|
| Strict Limits | If snapshot takes longer than 5 seconds or exceeds 500MB, abort the run. | |
| Soft Limits | Best effort. Warn the user if it's taking a long time, but don't abort. | ✓ |
| No Limits | Let it run as long as it takes, even for gigabytes of data. | |

**User's choice:** Soft Limits
**Notes:** None

| Option | Description | Selected |
|--------|-------------|----------|
| Abort Execution | If snapshot fails, abort the execution entirely (Fail Closed). | |
| Proceed with Warning | If snapshot fails, log a warning but proceed with execution without rollback capability. | ✓ |

**User's choice:** Proceed with Warning
**Notes:** None

---

## MSI Signing Pipeline

| Option | Description | Selected |
|--------|-------------|----------|
| GitHub Secrets (Recommended) | Store the .pfx file as a base64 encoded GitHub Secret. Simple and contained entirely in GitHub. | ✓ |
| Azure Key Vault | Use Azure Key Vault and signtool.exe /csp. More secure, but requires Azure setup and credentials. | |

**User's choice:** GitHub Secrets (Recommended)
**Notes:** None

| Option | Description | Selected |
|--------|-------------|----------|
| Tag/Release Only (Recommended) | Only sign artifacts when a semantic version tag (e.g., v1.0.0) is pushed. | ✓ |
| Every Main Commit | Sign every successful build on the main branch. Uses more timestamp quotas. | |

**User's choice:** Tag/Release Only (Recommended)
**Notes:** None

| Option | Description | Selected |
|--------|-------------|----------|
| Self-Signed Cert | Provide a script to generate and trust a local self-signed cert for testing the signed MSI flow. | |
| Skip Locally (Recommended) | Skip signing entirely for local builds and tests. | ✓ |

**User's choice:** Skip Locally (Recommended)
**Notes:** None

| Option | Description | Selected |
|--------|-------------|----------|
| Maintain Separate MSIs (Recommended) | Keep generating two separate MSIs (`-user` and `-machine`). This matches the existing contract validation tests. | ✓ |
| Single Dual-Purpose MSI | Attempt to combine them into a single MSI that asks for elevation if needed. | |

**User's choice:** Maintain Separate MSIs (Recommended)
**Notes:** None

| Option | Description | Selected |
|--------|-------------|----------|
| DigiCert (Recommended) | Use the standard DigiCert timestamp server (http://timestamp.digicert.com). Highly reliable. | ✓ |
| Microsoft/Comodo | Use Microsoft's Authenticode timestamp server (http://timestamp.comodoca.com/authenticode). | |

**User's choice:** DigiCert (Recommended)
**Notes:** None

| Option | Description | Selected |
|--------|-------------|----------|
| SHA256 Only (Recommended) | Use SHA256. Windows 10/11 fully supports it, and SHA1 is deprecated. | ✓ |
| Dual Sign | Dual sign with SHA1 and SHA256 for maximum backward compatibility (Windows 7/8). | |

**User's choice:** SHA256 Only (Recommended)
**Notes:** None

| Option | Description | Selected |
|--------|-------------|----------|
| Fail CI Run (Recommended) | If signtool fails, the entire CI release run fails. We never ship unsigned release artifacts. | ✓ |
| Upload Unsigned | If signing fails, warn in the logs but proceed to upload unsigned release artifacts as a fallback. | |

**User's choice:** Fail CI Run (Recommended)
**Notes:** None

| Option | Description | Selected |
|--------|-------------|----------|
| signtool.exe (Recommended) | Use the native `signtool.exe` from the Windows SDK. Requires Windows runner. | ✓ |
| osslsigncode | Use `osslsigncode` so we can potentially sign Windows binaries from Linux runners in the future. | |

**User's choice:** signtool.exe (Recommended)
**Notes:** None

---

## WFP Handle Leakage Cleanup

| Option | Description | Selected |
|--------|-------------|----------|
| Dynamic Sessions (Recommended) | Tie WFP filters to a dynamic WFP Session. When the process/session dies, the OS automatically drops the filters. | ✓ |
| Active Tracking | Implement a heartbeat or active tracking system to manually delete filters if a process stops responding. | |

**User's choice:** Dynamic Sessions (Recommended)
**Notes:** None

| Option | Description | Selected |
|--------|-------------|----------|
| Startup Sweep (Recommended) | On `nono-wfp-service` startup, sweep and delete any filters matching our provider GUID that belong to dead PIDs. | ✓ |
| No Sweeping | No active sweeps. Rely entirely on the OS and assume no long-term leakage. | |

**User's choice:** Startup Sweep (Recommended)
**Notes:** None

| Option | Description | Selected |
|--------|-------------|----------|
| Windows Event Log (Recommended) | Write leakage and cleanup events to the Windows Event Log so administrators can audit them. | ✓ |
| Local App Log | Write to a standard local text file in the nono logs directory. | |

**User's choice:** Windows Event Log (Recommended)
**Notes:** None

| Option | Description | Selected |
|--------|-------------|----------|
| Bump MSRV (Recommended) | Bump the Minimum Supported Rust Version (MSRV) if needed to use the latest `windows` crate which has better safe Handle types. | ✓ |
| Manual FFI Patch | Maintain current MSRV and manually implement `Drop` traits for raw FFI `HANDLE`s to fix the leak. | |

**User's choice:** Bump MSRV (Recommended)
**Notes:** None

---

## Claude's Discretion
None

## Deferred Ideas
None
