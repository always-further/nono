# Phase 04: State Integrity Deployment - Research

**Researched:** 2026-04-05
**Domain:** Windows filesystem rollback, WFP lifecycle cleanup, and MSI signing/release automation
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
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

### Claude's Discretion
## Specific Ideas
No specific requirements — open to standard approaches aligned with the decisions above.

### Deferred Ideas (OUT OF SCOPE)
## Deferred Ideas
None — discussion stayed within phase scope.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| STAT-01 | User can create a filesystem snapshot of a Windows workspace before execution. | Reuse the existing Merkle/content-addressable snapshot stack, keep scope at granted write paths, and retain soft walk budgets plus warning-only failure behavior. |
| STAT-02 | User can rollback Windows filesystem changes to a previous snapshot using `nono rollback`. | Restore with same-directory temp file plus atomic replace semantics, preserve ACL/metadata expectations, and surface locked-file partial-failure handling. |
| DEPL-01 | Windows MSI packages (machine and user) are automatically generated and signed in CI. | Keep WiX v4 dual-MSI generation, sign only on tag/release workflows with `signtool.exe`, verify signatures before upload, and fail closed on any signing or contract-validation error. |
</phase_requirements>

## Summary

Phase 04 should not introduce a second Windows-only rollback engine. The repo already has the right core shape: a content-addressable object store, Merkle manifests, tracked-path scoping, and same-directory temp-file replacement. Current Microsoft guidance also points away from Transactional NTFS and toward application-level atomic replacement for document-style updates, which matches the existing `SnapshotManager` design far better than VSS or TxF.

For WFP cleanup, the established Windows pattern is: open a dynamic filtering session, attach filters to your provider/sublayer, and let BFE delete session-owned objects when the session ends. Dynamic sessions handle the normal case; a startup sweep still matters for abnormal exits, version drift, or objects previously created outside the dynamic session contract. That sweep should enumerate sessions and filters by provider GUID and deterministically remove anything owned by dead processes, with each cleanup result written to Windows Event Log.

For deployment, the standard path is already the correct one: WiX v4 to author two MSIs, `signtool.exe` from the Windows SDK for Authenticode, and CI-only signing from a PFX stored in GitHub secrets. The main gap is tightening the signing invocation to current SignTool expectations and explicitly treating unsigned or unverified artifacts as release blockers.

**Primary recommendation:** Keep the existing Merkle snapshot architecture, wrap WFP objects in dynamic sessions plus provider-guided startup sweeps, and harden the current WiX/`signtool.exe` release workflow rather than introducing VSS, TxF, or custom signing logic.

## Project Constraints (from CLAUDE.md)

- Use the repo's GSD workflow; do not make direct repo edits outside it unless explicitly bypassed.
- Use `make build`, `make test`, `make check`, and `make ci` as the standard verification entry points when available.
- Never use `.unwrap()` or `.expect()` in production code; `clippy::unwrap_used` is enforced.
- Libraries should almost never panic; use `Result` and `NonoError`.
- Apply `#[must_use]` to critical `Result`-returning functions.
- Canonicalize paths at enforcement boundaries.
- Use `Path::components()` or `Path::starts_with()` for path checks; never string-prefix matching.
- Consider symlink TOCTOU risks.
- Use `zeroize` for sensitive data in memory.
- Use checked or saturating arithmetic for security-sensitive math.
- Restrict `unsafe` to FFI modules; every `unsafe` block requires a `// SAFETY:` explanation.
- Follow least privilege and fail-secure behavior; never silently degrade security.
- Keep library policy-free; Windows policy belongs in `nono-cli`.

## Standard Stack

### Core
| Library / Tool | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Existing `nono::undo` stack | repo current | Snapshot manifests, Merkle roots, deduped object storage, restore flow | Already matches Microsoft’s recommended app-level atomic replace model better than VSS/TxF for workspace rollback. |
| `windows` crate | 0.62.2 (2025-10-06) | Safer Win32/WFP/Event Log bindings for new Windows work | Current `windows-rs` primary crate; aligns with the locked MSRV bump decision. |
| `windows-service` | 0.8.0 | Service entrypoint, control handling, status transitions | Standard Rust service host crate; already used in `nono-wfp-service`. |
| WiX Toolset CLI | 4.0.6 | Build machine and user MSIs | Already wired into repo scripts and release workflow; standard Windows MSI authoring path. |
| `signtool.exe` | Windows SDK tool | Authenticode signing and verification | Microsoft-supported signing tool; should remain the only signing primitive in CI. |

### Supporting
| Library / Tool | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `windows-sys` | repo pinned 0.59.0; latest 0.61.2 (2025-10-06) | Lowest-level FFI bindings | Keep only where zero-overhead raw bindings are already in place and wrapper migration is too disruptive. |
| Windows Event Log classic API (`RegisterEventSourceW` / `ReportEventW`) | OS API | Low-volume admin/service events into Application log | Good fit if Phase 04 wants Windows Event Log now without adding ETW manifest compilation to the MSI pipeline. |
| Manifest-based ETW / Windows Event Log provider | OS API | Structured modern Windows Event Log integration | Use if the phase can absorb provider manifest installation and message resources; this is the longer-term SOTA direction. |
| PowerShell `Get-AuthenticodeSignature` | OS tool | Secondary signature verification in CI | Good as a second verifier after `signtool verify /pa`. |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Existing Merkle snapshots | VSS requester flow | VSS is built for backup applications and volume shadow copies; it adds requester/writer/provider complexity and admin/volume scope the phase does not need. |
| Existing Merkle snapshots + atomic replace | Transactional NTFS | Microsoft recommends alternatives and explicitly points developers away from new TxF dependencies. |
| `signtool.exe` | Azure Trusted Signing / cloud-sign services | Viable later, but contradicts the locked `signtool.exe` decision for this phase. |
| Classic Event Log source | Manifest-based ETW provider | More modern, but heavier install-time tooling and message-manifest work. |

**Installation / version verification**

Current workspace availability:

- `cargo 1.94.1`
- `rustc 1.94.1`
- `.NET SDK 9.0.201`
- `wix 4.0.6+73c89738`
- `signtool.exe` not present on this machine's `PATH`
- `make` not present on this machine

Implication:

- Local Windows MSI authoring is available.
- Local Authenticode signing is not currently runnable here without the Windows SDK path setup.
- CI remains the canonical signing environment.

## Architecture Patterns

### Recommended Project Structure
```text
crates/nono/src/undo/              # Cross-platform snapshot/object-store/Merkle primitives
crates/nono-cli/src/rollback_*.rs  # CLI orchestration, UX, policy, and Windows-specific warnings
crates/nono-cli/src/bin/nono-wfp-service.rs
scripts/build-windows-msi.ps1
scripts/sign-windows-artifacts.ps1
scripts/validate-windows-msi-contract.ps1
.github/workflows/release.yml
packaging/windows/                 # Recommended new home for Event Log manifests / MSI fragments
```

### Pattern 1: User-Mode Snapshot + Atomic Restore
**What:** Snapshot all granted write paths into the existing content-addressable store, then restore each target with a temp file in the same directory followed by atomic replacement.

**When to use:** For STAT-01 and STAT-02. This is the Windows-specific execution of the existing `SnapshotManager` contract.

**Why:** Microsoft’s TxF guidance explicitly recommends application-level write-new-then-replace flows for single-file atomicity. The repo already implements this with `MoveFileExW(MOVEFILE_REPLACE_EXISTING)`; moving to VSS or TxF would add complexity without improving the workspace rollback contract.

**Implementation guidance:**

- Keep snapshot scope at write-capable user-granted paths only.
- Keep the baseline/incremental manifest split already present in [`snapshot.rs`](/C:/Users/omack/Nono/crates/nono/src/undo/snapshot.rs).
- Treat locked files on restore as a surfaced partial failure, not silent success.
- Add Windows-specific diagnostics around ACL-preservation or lock contention, but do not weaken restore path validation.
- Preserve the current warning-only behavior when pre-execution snapshot capture fails; execution may proceed, but session metadata must clearly record that rollback is unavailable.

### Pattern 2: Dynamic WFP Session + Deterministic Orphan Sweep
**What:** Open the filtering engine with `FWPM_SESSION_FLAG_DYNAMIC`, add provider/sublayer/filter objects in that session, and on service startup enumerate sessions/filters to delete stale objects matching the nono provider GUID and dead owners.

**When to use:** For WFP cleanup and leakage handling folded into Phase 04 planning.

**Why:** Microsoft documents that objects added in a dynamic session are deleted automatically when the session ends. That gives the normal cleanup path for detach/attach and most crash exits. The startup sweep covers the abnormal cases that escape that guarantee.

**Implementation guidance:**

- Keep deterministic filter keys for explicit cleanup and diagnostics.
- Add a provider GUID and service association so the cleanup surface is enumerable and auditable.
- Record enough metadata to correlate stale filters with PID/session SID before deletion.
- Run the sweep before accepting new runtime activation requests in `nono-wfp-service`.
- Log every sweep action to Windows Event Log with outcome, PID, session key if known, and provider GUID.

### Pattern 3: MSI as the Service Registration Boundary
**What:** Put service registration, Event Log source/provider registration, and binary placement inside WiX-authored machine MSI components; keep user MSI service-free.

**When to use:** For DEPL-01 and the WFP service/event-log install surface.

**Why:** WiX/Windows Installer already own install, upgrade, and uninstall sequencing. The current repo contract correctly keeps `nono-wfp-service` in the machine MSI only.

**Implementation guidance:**

- Keep separate machine and user MSIs with distinct UpgradeCodes.
- Register or install Event Log source/provider during machine MSI install, not at first process launch.
- Keep `ServiceInstall`/`ServiceControl` in the machine MSI only.
- If adding advanced service hardening, prefer WiX/MSI tables over ad hoc post-install scripts.

### Pattern 4: Sign After Packaging, Verify Before Upload
**What:** Build unsigned artifacts, sign the `.exe` and both `.msi` files with `signtool.exe`, then verify signatures before artifact upload.

**When to use:** Always in release/tag CI; never for local developer builds.

**Why:** Signing before zipping preserves the embedded signature on the executable and makes MSI verification straightforward. Failing before upload guarantees the repo never publishes unsigned release assets.

**Implementation guidance:**

- Keep signing restricted to tag/release workflows.
- Sign the raw `.exe` and both MSIs, then build the `.zip` from the already-signed `.exe`.
- Add `signtool verify /pa /tw` in addition to PowerShell verification so missing timestamps fail loudly.
- Prefer RFC 3161 mode (`/tr` + `/td sha256`) if the DigiCert endpoint supports it; if the phase retains `/t`, document that this is a locked compatibility choice rather than the current preferred SignTool mode.

### Anti-Patterns to Avoid
- **VSS as workspace rollback engine:** VSS is for backup requesters coordinating writers across volumes; it is too coarse and operationally heavy for per-session workspace undo.
- **TxF resurrection:** Microsoft recommends alternatives and warns against building new dependencies on TxF.
- **Best-effort signing:** Any branch that uploads unsigned Windows assets violates the locked fail-closed release decision.
- **Logging only to stdout/stderr:** Service cleanup events need durable Windows-native observability.
- **Per-file ad hoc cleanup rules:** Tie WFP ownership to provider GUID, session key, and deterministic filter keys instead of string-matched names alone.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| MSI authoring and service lifecycle | Custom installer EXE or bespoke registry/service scripts | WiX v4 `Package`, `ServiceInstall`, `ServiceControl` | Windows Installer already handles upgrade/uninstall sequencing and rollback semantics. |
| Authenticode signing | Custom PKCS#7 logic or homegrown signing wrappers | `signtool.exe` + SDK certificate store integration | Microsoft-supported toolchain, proper timestamping, and straightforward verification. |
| WFP object ownership cleanup | Name-based filter scavenger only | Dynamic WFP sessions + provider-guided enumeration and explicit deletion | Session lifecycle is what BFE understands; names are diagnostics, not ownership. |
| Filesystem rollback transactions | TxF-like multi-file transaction layer | Existing Merkle/object-store snapshots plus atomic per-file replace | TxF is deprecated for new work; application-level replace is the documented alternative. |
| Event log persistence format | Custom JSON file as the primary audit sink | Windows Event Log source/provider | Operators expect service failures and cleanup activity in Event Viewer. |

**Key insight:** Windows already has authoritative mechanisms for install sequencing, signing, event persistence, and WFP object lifecycle. Phase 04 should compose those mechanisms around the repo’s existing Merkle snapshot core, not replace them.

## Common Pitfalls

### Pitfall 1: Assuming VSS is a drop-in rollback primitive
**What goes wrong:** Planning drifts into requester/writer/provider orchestration, volume snapshots, and privilege requirements that do not map cleanly to per-session workspace rollback.
**Why it happens:** VSS sounds like “Windows snapshots,” but it is designed for backup applications and live-volume shadow copies.
**How to avoid:** Keep rollback at file-manifest scope and reuse `SnapshotManager`.
**Warning signs:** Design docs start talking about writer metadata, volume selection, or backup components documents.

### Pitfall 2: Using `MoveFileEx` as if it were a perfect transaction
**What goes wrong:** Restore can still fail on locked files, cross-volume cases, or metadata/ACL surprises, producing partial rollback.
**Why it happens:** Atomic replacement is per-target, not a full multi-file transaction.
**How to avoid:** Restore from same-directory temp files only, surface per-file failures, and never claim all-or-nothing rollback for the entire tree.
**Warning signs:** Plans describe rollback as “transactional” rather than “best-effort per file with explicit errors.”

### Pitfall 3: Relying only on dynamic WFP session teardown
**What goes wrong:** Objects created outside the expected session or left behind by abnormal states survive and confuse later launches.
**Why it happens:** Dynamic sessions solve the normal lifecycle, not every historical or mismatched object.
**How to avoid:** Keep the startup sweep and key it off provider GUID plus dead-owner inspection.
**Warning signs:** Repeated “already exists” failures or stale filters after service restarts.

### Pitfall 4: Treating Event Log as just `ReportEventW` with no install story
**What goes wrong:** Events show up without message text, or not at all, because the source/provider was never registered.
**Why it happens:** Windows Event Viewer needs source metadata or provider metadata to render event IDs correctly.
**How to avoid:** Install the source/provider during the machine MSI and test rendering on a clean machine.
**Warning signs:** Event Viewer shows generic “description cannot be found” messages.

### Pitfall 5: Signing pipeline passes locally but fails on hosted runners
**What goes wrong:** Release jobs fail because `signtool.exe` is not on `PATH`, `/td` is omitted, or timestamping is misconfigured.
**Why it happens:** Local environments differ from GitHub runners and current SignTool versions are stricter.
**How to avoid:** Keep CI as the source of truth, validate SDK path assumptions, and include explicit digest/timestamp flags.
**Warning signs:** SignTool warnings on `/fd` or `/td`, or artifacts that verify locally only through one tool.

### Pitfall 6: Uploading before signature verification
**What goes wrong:** Unsigned or invalid artifacts can be published if the upload step runs before verification.
**Why it happens:** Build/publish stages are often composed before security gates.
**How to avoid:** Verify raw artifacts before staging/upload and keep signing failures fatal.
**Warning signs:** Workflow structure allows `upload-artifact` or release creation after a non-fatal signing step.

### Pitfall 7: Forgetting Windows path-length and lock behavior in rollback tests
**What goes wrong:** Restore logic appears correct in unit tests but fails against real Windows paths or open handles.
**Why it happens:** Temp-dir tests rarely exercise long paths, AV interference, or held file handles.
**How to avoid:** Add Windows-specific tests for locked targets, same-directory temp replacement, and path canonicalization.
**Warning signs:** Restore code has no tests for “file in use” or long/UNC-style paths.

## Code Examples

Verified patterns from official docs and current repo shape:

### Dynamic WFP session open
```rust
// Source: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC, FwpmEngineOpen0,
};

fn open_dynamic_session() -> windows::core::Result<isize> {
    let mut session = FWPM_SESSION0::default();
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    let mut engine = 0isize;
    unsafe { FwpmEngineOpen0(None, 0, None, Some(&session), &mut engine) }.ok()?;
    Ok(engine)
}
```

### Classic Event Log source write for low-volume service events
```rust
// Source: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-reporteventw
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::EventLog::{
    DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_WARNING_TYPE,
};
use windows::core::w;

fn write_cleanup_warning(message: &str) -> windows::core::Result<()> {
    let source: HANDLE = unsafe { RegisterEventSourceW(None, w!("nono-wfp-service")) };
    let text: Vec<u16> = message.encode_utf16().chain(Some(0)).collect();
    let strings = [windows::core::PCWSTR(text.as_ptr())];
    unsafe {
        ReportEventW(source, EVENTLOG_WARNING_TYPE, 0, 0x1001, None, &strings, None).ok()?;
        DeregisterEventSource(source).ok()?;
    }
    Ok(())
}
```

### Atomic replace-oriented restore flow
```rust
// Source: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilea
// Repo reference: /C:/Users/omack/Nono/crates/nono/src/undo/object_store.rs
fn restore_one(target: &Path, object_bytes: &[u8]) -> nono::Result<()> {
    let tmp = target.with_extension("nono.tmp");
    std::fs::write(&tmp, object_bytes)?;
    nono::undo::object_store::replace_file(&tmp, target)?;
    Ok(())
}
```

### WiX machine MSI service ownership
```xml
<!-- Source: https://docs.firegiant.com/wix/schema/wxs/serviceinstall/ -->
<!-- Source: https://docs.firegiant.com/wix/schema/wxs/servicecontrol/ -->
<Component Id="cmpWfpServiceExe" Guid="*">
  <File Id="filWfpServiceExe" Source="$(var.ServiceBinary)" KeyPath="yes" />
  <ServiceInstall
      Id="svcWfpService"
      Name="nono-wfp-service"
      Type="ownProcess"
      Start="demand"
      Account="LocalSystem"
      ErrorControl="normal" />
  <ServiceControl
      Id="svcCtrlWfpService"
      Name="nono-wfp-service"
      Start="install"
      Stop="both"
      Remove="uninstall"
      Wait="yes" />
</Component>
```

### Hardened SignTool invocation
```powershell
# Source: https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool
signtool.exe sign `
  /fd sha256 `
  /sha1 $Thumbprint `
  /tr http://timestamp.digicert.com `
  /td sha256 `
  $ArtifactPath

signtool.exe verify /pa /tw $ArtifactPath
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Transactional NTFS for atomic file operations | Application-level write-new-then-`ReplaceFile` / atomic replace | Microsoft guidance updated by 2021 docs | Favors the repo’s current snapshot/restore design over new TxF work. |
| VSS as a generic “snapshot” answer | VSS reserved for backup/requester scenarios; app rollback stays app-managed | Stable current guidance | Avoids over-scoping Phase 04 into writer/requester/provider orchestration. |
| Classic Event Logging API as default for new apps | Windows Event Log / manifest-based ETW supersedes old Event Logging on Vista+ | Vista era onward; still current | If the team wants the most future-proof Windows-native logging, provider manifests are the long-term target. |
| SHA1-era or legacy timestamp defaults | Explicit SHA256 digest selection and RFC 3161 timestamping | Current SignTool behavior | Current CI should explicitly include digest flags and preferably `/tr` + `/td sha256`. |

**Deprecated/outdated:**

- **TxF for new design work:** Microsoft recommends alternatives and warns the API may not be available in future Windows versions.
- **Unsigned “best-effort” Windows release assets:** Outdated for this repo; locked phase decision is fail closed.
- **Event log source created lazily by the service:** Operationally weak; MSI install should own registration.

## Open Questions

1. **Should Phase 04 land classic Event Log source registration or jump straight to manifest-based ETW?**
   - What we know: Modern Windows guidance favors Windows Event Log/ETW; classic `ReportEventW` is still simple and adequate for Application log writes.
   - What's unclear: Whether the phase budget can absorb message compiler and manifest-install work.
   - Recommendation: Plan Phase 04 around classic Event Log source registration unless the planner can explicitly allocate MSI/provider-manifest tasks.

2. **Should the signing script stay on `/t` or move to `/tr` + `/td sha256`?**
   - What we know: Current SignTool docs require explicit `/fd` and `/td`, and RFC 3161 uses `/tr`.
   - What's unclear: Whether `http://timestamp.digicert.com` is being used here as a legacy Authenticode endpoint or an RFC 3161 endpoint.
   - Recommendation: Verify the DigiCert endpoint behavior early in implementation; if it supports RFC 3161, migrate the script.

3. **How much of the WFP sweep should rely on session enumeration versus deterministic filter keys?**
   - What we know: Dynamic sessions are the primary cleanup mechanism; deterministic keys already exist in the service code.
   - What's unclear: Whether Phase 03 left any provider/sublayer registration gaps that limit precise stale-object attribution.
   - Recommendation: Use both. Session enumeration identifies dead owners; deterministic keys make explicit deletion and diagnostics reliable.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| `cargo` | Rust builds/tests | Yes | 1.94.1 | — |
| `rustc` | Windows crate / CLI build | Yes | 1.94.1 | — |
| `.NET SDK` | WiX tool installation/use | Yes | 9.0.201 | — |
| `wix` | MSI generation | Yes | 4.0.6 | — |
| `signtool.exe` | Authenticode signing | No (local) | — | CI on `windows-latest` with Windows SDK |
| `make` | Repo high-level workflows | No (local) | — | Direct `cargo build`, `cargo test`, `cargo clippy`, `cargo fmt --check` |
| GitHub Actions | Tag/release signing pipeline | Yes (repo workflow present) | `.github/workflows/release.yml` | — |

**Missing dependencies with no fallback:**

- None for planning. Local Authenticode signing is unavailable here, but the phase already intends CI-only signing.

**Missing dependencies with fallback:**

- `signtool.exe` locally: use the hosted Windows release runner as the signing environment.
- `make` locally: use direct Cargo commands.

## Sources

### Primary (HIGH confidence)
- Microsoft Learn, `FWPM_SESSION0`: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0
- Microsoft Learn, `FwpmSessionEnum0`: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmsessionenum0
- Microsoft Learn, `FWPM_FILTER0`: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
- Microsoft Learn, `FWPM_PROVIDER0`: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_provider0
- Microsoft Learn, SignTool: https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool
- Microsoft Learn, `ReplaceFile`: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilea
- Microsoft Learn, Alternatives to using Transactional NTFS: https://learn.microsoft.com/en-us/windows/win32/fileio/deprecation-of-txf
- Microsoft Learn, Volume Shadow Copy Service Overview: https://learn.microsoft.com/en-us/windows/win32/vss/volume-shadow-copy-service-overview
- Microsoft Learn, Requesters: https://learn.microsoft.com/en-us/windows/win32/vss/requestors
- Microsoft Learn, Writers: https://learn.microsoft.com/en-us/windows/win32/vss/writers
- Microsoft Learn, Event Sources: https://learn.microsoft.com/en-us/windows/win32/eventlog/event-sources
- Microsoft Learn, ReportEventW: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-reporteventw
- Microsoft Learn, Windows Event Log overview: https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log
- Microsoft Learn, Windows Events / TraceLogging guidance: https://learn.microsoft.com/en-us/windows/win32/events/windows-events
- FireGiant WiX docs, `ServiceInstall`: https://docs.firegiant.com/wix/schema/wxs/serviceinstall/
- FireGiant WiX docs, `ServiceControl`: https://docs.firegiant.com/wix/schema/wxs/servicecontrol/
- Docs.rs, `windows` crate: https://docs.rs/crate/windows/latest
- Docs.rs, `windows-service` crate: https://docs.rs/windows-service/latest/windows_service/
- Docs.rs, `windows-sys` crate: https://docs.rs/crate/windows-sys/latest
- Repo source, rollback runtime: [/C:/Users/omack/Nono/crates/nono-cli/src/rollback_runtime.rs](/C:/Users/omack/Nono/crates/nono-cli/src/rollback_runtime.rs)
- Repo source, snapshot manager: [/C:/Users/omack/Nono/crates/nono/src/undo/snapshot.rs](/C:/Users/omack/Nono/crates/nono/src/undo/snapshot.rs)
- Repo source, object store: [/C:/Users/omack/Nono/crates/nono/src/undo/object_store.rs](/C:/Users/omack/Nono/crates/nono/src/undo/object_store.rs)
- Repo source, Merkle tree: [/C:/Users/omack/Nono/crates/nono/src/undo/merkle.rs](/C:/Users/omack/Nono/crates/nono/src/undo/merkle.rs)
- Repo source, WFP service: [/C:/Users/omack/Nono/crates/nono-cli/src/bin/nono-wfp-service.rs](/C:/Users/omack/Nono/crates/nono-cli/src/bin/nono-wfp-service.rs)
- Repo source, release workflow: [/C:/Users/omack/Nono/.github/workflows/release.yml](/C:/Users/omack/Nono/.github/workflows/release.yml)
- Repo source, MSI build script: [/C:/Users/omack/Nono/scripts/build-windows-msi.ps1](/C:/Users/omack/Nono/scripts/build-windows-msi.ps1)
- Repo source, signing script: [/C:/Users/omack/Nono/scripts/sign-windows-artifacts.ps1](/C:/Users/omack/Nono/scripts/sign-windows-artifacts.ps1)
- Repo source, MSI contract validator: [/C:/Users/omack/Nono/scripts/validate-windows-msi-contract.ps1](/C:/Users/omack/Nono/scripts/validate-windows-msi-contract.ps1)

### Secondary (MEDIUM confidence)
- Repo doc, Windows signing guide: [/C:/Users/omack/Nono/docs/cli/development/windows-signing-guide.mdx](/C:/Users/omack/Nono/docs/cli/development/windows-signing-guide.mdx)

### Tertiary (LOW confidence)
- None.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - Core recommendations are supported by Microsoft docs, current crate docs, and existing repo wiring.
- Architecture: HIGH - The repo already implements the critical undo primitives, and Microsoft guidance clearly rejects the main tempting alternatives.
- Pitfalls: HIGH - Derived from Microsoft docs, hosted-runner/tooling constraints, and current repo script/workflow structure.

**Research date:** 2026-04-05
**Valid until:** 2026-05-05
