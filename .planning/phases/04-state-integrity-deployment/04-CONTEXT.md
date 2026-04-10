# Phase 4: State Integrity & Deployment - Context

**Gathered:** 2026-04-04
**Status:** Ready for planning

<domain>
## Phase Boundary

Finalize filesystem protection (snapshots/rollback) for Windows workspaces and finalize automated release pipelines for Windows MSI deployment.
</domain>

<decisions>
## Implementation Decisions

### Filesystem Snapshot Strategy
- **Mechanism:** Merkle Trees (Calculate hashes and only copy changed blocks).
- **Scope:** All Granted Paths (Attempt to snapshot all granted file paths, not just project root).
- **Performance:** Soft Limits (Best effort; warn the user if taking a long time, but don't abort).
- **Failures:** Proceed with Warning (If snapshot fails, log a warning but proceed with execution without rollback capability).

### MSI Signing Pipeline
- **Cert Storage:** GitHub Secrets (Store the `.pfx` file as a base64 encoded secret).
- **Promotion:** Tag/Release Only (Only sign artifacts when a semantic version tag is pushed).
- **Local Dev:** Skip Locally (Skip signing entirely for local builds and tests).
- **Dual MSI:** Maintain Separate MSIs (Keep generating separate `-user` and `-machine` MSIs to match the existing release contract).
- **Timestamping:** DigiCert (Use standard DigiCert timestamp server `http://timestamp.digicert.com`).
- **Algorithm:** SHA256 Only (Use SHA256 for the file digest).
- **Failures:** Fail CI Run (If signing fails, fail the entire CI run; never upload unsigned release artifacts).
- **Tooling:** `signtool.exe` (Use native Windows SDK tooling).

### WFP Handle Leakage Cleanup
- **Cleanup Trigger:** Dynamic Sessions (Tie WFP filters to a dynamic OS session for automatic teardown).
- **Orphan Sweeps:** Startup Sweep (On `nono-wfp-service` startup, sweep and delete any filters matching our provider GUID that belong to dead PIDs).
- **Logging:** Windows Event Log (Write leakage and cleanup events to the Windows Event Log).
- **MSRV Impact:** Bump MSRV (Bump the Minimum Supported Rust Version to use the latest `windows` crate for safer handle types).

### Folded Todos
- **Discuss Phase 4 filesystem strategy (VSS vs Merkle Trees):** Addressed in Filesystem Snapshot Strategy section.
- **Finalize .msi signing pipeline in GitHub Actions:** Addressed in MSI Signing Pipeline section.
- **Investigate WFP Handle leakage during sudden process exits:** Addressed in WFP Handle Leakage Cleanup section.
- **Confirm Rust MSRV requirement for windows-wfp crate:** Addressed in WFP Handle Leakage Cleanup section.
</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements
- `.planning/REQUIREMENTS.md` § STAT-01, STAT-02, DEPL-01 — Core requirements for filesystem snapshots, rollbacks, and MSI generation on Windows.
- `.planning/ROADMAP.md` § Phase 4 Details — Goal and success criteria.

### Project Context
- `.planning/PROJECT.md` — Core value and high-level goals.

### Code Constraints
- `scripts/build-windows-msi.ps1` — The script managing the current MSI building sequence.
- `scripts/sign-windows-artifacts.ps1` — The script providing Authenticode signing workflows.
- `scripts/validate-windows-msi-contract.ps1` — The script outlining strict structural tests that both MSI artifacts must pass.
</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `nono::undo::SnapshotManager`: Core snapshot management struct available in `crates/nono-cli/src/rollback_runtime.rs`.
- `build-windows-msi.ps1`: Established packaging steps utilizing WiX Toolset.
- `sign-windows-artifacts.ps1`: Contains utility functions to import certs and invoke `signtool.exe`.

### Established Patterns
- **MSI Contract Validation:** The project heavily tests the output MSIs to ensure they conform to strict scope requirements (e.g. UpgradeCodes, ARPNOMODIFY values, explicit target directories). Changes to packaging must pass `validate-windows-msi-contract.ps1`.
- **WFP Service Daemonization:** Pointers from Phase 3 structure the `nono-wfp-service` to run detached in the background, reinforcing the need for Event Log output and automated garbage collection.

### Integration Points
- **CLI Rollback Pipeline:** Connect Merkle Tree snapshot logic directly into `crates/nono-cli/src/rollback_runtime.rs`.
- **CI Workflows:** Append `.pfx` decoding and signtool execution into `.github/workflows/release.yml`.
</code_context>

<specifics>
## Specific Ideas
No specific requirements — open to standard approaches aligned with the decisions above.
</specifics>

<deferred>
## Deferred Ideas
None — discussion stayed within phase scope.
</deferred>

---
*Phase: 04-state-integrity-deployment*
*Context gathered: 2026-04-04*
