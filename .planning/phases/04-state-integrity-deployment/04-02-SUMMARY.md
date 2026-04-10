---
phase: 04-state-integrity-deployment
plan: 02
subsystem: windows-wfp-service
tags: [windows, wfp, event-log, msi, msrv, startup-sweep]
dependency_graph:
  requires: []
  provides:
    - wfp-startup-orphan-sweep
    - event-log-reporting
    - machine-msi-event-log-registration
    - msrv-1.77
  affects:
    - crates/nono-cli/src/bin/nono-wfp-service.rs
    - scripts/build-windows-msi.ps1
    - scripts/validate-windows-msi-contract.ps1
    - Cargo.toml
    - CLAUDE.md
    - .planning/codebase/STACK.md
tech_stack:
  added:
    - Win32_System_EventLog feature in windows-sys 0.59
  patterns:
    - TDD (red-green for startup sweep and Event Log helpers)
    - RAII for WFP engine and transaction lifetime
    - Deterministic filter keys via SHA-256
    - Dual-output logging (stderr + Windows Event Log)
key_files:
  created: []
  modified:
    - crates/nono-cli/src/bin/nono-wfp-service.rs
    - crates/nono-cli/Cargo.toml
    - scripts/build-windows-msi.ps1
    - scripts/validate-windows-msi-contract.ps1
    - Cargo.toml
    - CLAUDE.md
    - .planning/codebase/STACK.md
decisions:
  - "D-05 preserved: FWPM_SESSION_FLAG_DYNAMIC remains the normal filter cleanup path"
  - "D-06 implemented: startup sweep enumerates NONO_SUBLAYER_GUID filters and removes stale ones"
  - "D-07 implemented: write_event_log() + log_sweep_event() dual-output to stderr and Windows Event Log"
  - "D-08 applied: MSRV bumped from 1.74 to 1.77 for Windows service/WFP handle binding safety"
  - "Machine MSI owns EventLog source registration; user MSI is service-free"
metrics:
  duration: ~25 minutes
  completed: 2026-04-05T17:11:34Z
  tasks_completed: 3
  tasks_total: 3
  files_changed: 7
---

# Phase 04 Plan 02: Windows WFP Service Lifecycle Hardening Summary

WFP startup orphan sweep with Windows Event Log reporting, machine MSI Event Log source registration, and MSRV bump to 1.77.

## What Was Built

### Task 1: WFP Startup Sweep and Event Log Reporting

Added provider-guided orphan sweep to `nono-wfp-service` that runs before the named-pipe server accepts any new activation requests:

- `SweepOutcome` enum (Removed / Skipped / Failed) with deterministic message formatting via `format_sweep_outcome()`
- `EventLogLevel` enum (Information / Warning) for structured log classification
- Event ID constants: `EVENT_ID_SWEEP_COMPLETE` (1001), `EVENT_ID_SWEEP_REMOVED` (1002), `EVENT_ID_SWEEP_SKIPPED` (1003), `EVENT_ID_SWEEP_FAILED` (1004)
- `build_sweep_summary()` produces "removed=N skipped=N failed=N" summaries from outcome slices
- `build_event_log_message()` formats structured body strings including source name and event ID
- `write_event_log()` (Windows-only): registers event source and calls `ReportEventW`; falls back to stderr if source is not yet registered
- `log_sweep_event()` always writes to stderr for pipeline capture, and on Windows also calls `write_event_log()`
- `run_startup_sweep()` (Windows): opens WFP engine, checks for `NONO_SUBLAYER_GUID`, creates filter enum handle, iterates batches of 64 filters, skips zero-key filters (fail-secure), deletes owned filters, logs outcomes, emits sweep summary to Event Log
- Non-Windows stub: returns empty vec
- Wired into `run_named_pipe_server()` before `open_wfp_engine()` and before the named-pipe accept loop

TDD approach: wrote 7 failing tests first (RED), then implemented all helper functions (GREEN). All 18 tests pass.

Added `Win32_System_EventLog` to windows-sys features in `crates/nono-cli/Cargo.toml`.

Fixed pre-existing `clippy::io_other_error` warning in tokio runtime error construction.

### Task 2: Machine MSI Owns Event Log Registration

Updated `scripts/build-windows-msi.ps1`:
- Added `$eventLogComponentXml` variable, populated only when `$Scope -eq "machine"` and a service binary path is provided
- Registers `SYSTEM\CurrentControlSet\Services\EventLog\Application\nono-wfp-service` with `EventMessageFile` (pointing to `[INSTALLFOLDER]nono-wfp-service.exe`) and `TypesSupported = 7` (Information + Warning + Error)
- Component included in the WXS output alongside the service component

Updated `scripts/validate-windows-msi-contract.ps1`:
- Added assertions that machine MSI contains a `RegistryKey` for the EventLog path
- Validates `EventMessageFile` and `TypesSupported` values are present
- Asserts user MSI contains no `EventLog` registry keys (D-07 scope boundary enforcement)

### Task 3: MSRV Bump to 1.77

Updated `workspace.package.rust-version` in `Cargo.toml` from `1.74` to `1.77`.
Updated CLAUDE.md language and runtime sections.
Updated `.planning/codebase/STACK.md` runtime section.

Rationale (D-08): aligns documented MSRV with windows-sys 0.59 and the Event Log + WFP filter enumeration APIs introduced in this plan. All code compiles and all 18 tests pass under the new MSRV.

## Decisions Made

1. **Fail-secure zero-key skip**: Filters with all-zero GUIDs are skipped during the sweep and logged as `Skipped`. Zero-key filters are system-assigned and deleting them could corrupt WFP state.
2. **`FWP_E_FILTER_NOT_FOUND` treated as Removed**: If the API returns not-found during deletion, the filter is already gone — counted as a successful implicit removal rather than a failure.
3. **Best-effort Event Log**: `RegisterEventSourceW` can fail if the source is not yet registered (e.g., development, service binary run manually before machine MSI install). In that case, `write_event_log` falls back to stderr-only output without blocking startup.
4. **MSRV 1.77 not 1.80+**: A minimal bump was chosen. No features requiring 1.78+ are used. The bump documents the Windows service work boundary without imposing unnecessary constraints on Unix targets.
5. **`EventLogLevel::Error` removed**: Per CLAUDE.md dead-code policy, the variant was removed since no code path emits Error-level events in this plan. Can be added when needed.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed `FWP_FILTER_ENUM_TEMPLATE0` field name**
- **Found during:** Task 1 GREEN phase
- **Issue:** Plan referenced filtering by `subLayerKey` in the enum template, but `FWPM_FILTER_ENUM_TEMPLATE0` has no `subLayerKey` field — only `providerKey`. Scoping by sublayer requires post-enumeration filtering.
- **Fix:** Used zeroed/wildcard template (all filters) and filtered by `filter.subLayerKey == NONO_SUBLAYER_GUID` during the iteration loop.
- **Files modified:** `crates/nono-cli/src/bin/nono-wfp-service.rs`
- **Commit:** 216eec2

**2. [Rule 2 - Missing] Added `Win32_System_EventLog` feature flag**
- **Found during:** Task 1 GREEN phase
- **Issue:** `windows-sys::Win32::System::EventLog` was feature-gated and the feature was absent from `Cargo.toml`.
- **Fix:** Added `Win32_System_EventLog` to the `windows-sys` features list.
- **Files modified:** `crates/nono-cli/Cargo.toml`
- **Commit:** 216eec2

**3. [Rule 1 - Bug] Fixed pre-existing `clippy::io_other_error`**
- **Found during:** Task 1 clippy pass
- **Issue:** `std::io::Error::new(std::io::ErrorKind::Other, ...)` triggers the `io_other_error` clippy lint; should use `std::io::Error::other(...)`.
- **Fix:** Replaced with `std::io::Error::other(format!(...))`.
- **Files modified:** `crates/nono-cli/src/bin/nono-wfp-service.rs`
- **Commit:** 216eec2

**4. [Rule 2 - Missing] Added missing `session_sid` field in test structs**
- **Found during:** Task 1 RED compilation
- **Issue:** `WfpRuntimeActivationRequest` has a `session_sid` field but pre-existing test constructors omitted it (struct completeness regression from Phase 03).
- **Fix:** Added `session_sid: None` to `sample_request()` and the inline test struct.
- **Files modified:** `crates/nono-cli/src/bin/nono-wfp-service.rs`
- **Commit:** 216eec2

**5. [Rule 2 - Missing] Added `Debug` impl for `WfpSecurityDescriptor`**
- **Found during:** Task 1 RED compilation
- **Issue:** `Result::unwrap_err()` requires `T: Debug` for the `Ok` type; `WfpSecurityDescriptor` wraps a raw pointer and cannot auto-derive `Debug`.
- **Fix:** Added manual `Debug` impl printing the pointer address.
- **Files modified:** `crates/nono-cli/src/bin/nono-wfp-service.rs`
- **Commit:** 216eec2

## Self-Check: PASSED

Files verified:
- FOUND: `crates/nono-cli/src/bin/nono-wfp-service.rs`
- FOUND: `crates/nono-cli/Cargo.toml`
- FOUND: `scripts/build-windows-msi.ps1`
- FOUND: `scripts/validate-windows-msi-contract.ps1`
- FOUND: `Cargo.toml`
- FOUND: `CLAUDE.md`
- FOUND: `.planning/codebase/STACK.md`
- FOUND: `.planning/phases/04-state-integrity-deployment/04-02-SUMMARY.md`

Commits verified:
- FOUND: 216eec2 (feat: WFP startup sweep and Event Log reporting)
- FOUND: 3952e64 (feat: machine MSI Event Log source registration)
- FOUND: 7ee0d28 (chore: MSRV bump to 1.77)

Tests: 18/18 passing (cargo test -p nono-cli --bin nono-wfp-service)
