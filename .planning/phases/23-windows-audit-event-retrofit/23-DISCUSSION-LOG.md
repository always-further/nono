# Phase 23: Windows Audit-Event Retrofit - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-28
**Phase:** 23-windows-audit-event-retrofit
**Areas discussed:** Wiring locus, Reject-stage encoding, OpenUrl scope, Test approach

---

## Wiring locus

| Option | Description | Selected |
|--------|-------------|----------|
| Single-site at 5 push points (Recommended) | Thread `Option<&Mutex<AuditRecorder>>` as a parameter on `handle_windows_supervisor_message`. At each existing `audit_log.push` site, also call `recorder.record_capability_decision(entry.clone())`. Five touch points, all in one function. Per-kind helpers stay audit-unaware. | ✓ |
| Push into each handle_*_request helper | Pass recorder + request context into each per-kind helper. More granular but requires changing 5 helper signatures and the call site has to construct Approved entries differently from Denied entries. | |
| Tee wrapper around audit_log Vec | Replace `audit_log: &mut Vec<AuditEntry>` with a thin `AuditSink` type that fans out push to Vec + Option<recorder>. Zero call-site diff at the 5 push points; new ~30 LOC type. Trade: adds an abstraction for one consumer. | |

**User's choice:** Single-site at 5 push points (Recommended)
**Notes:** Aligns with G-04's single-site `(decision, grant)` tuple discipline; 5 push sites already exist as the funnel.

---

## Reject-stage encoding

| Option | Description | Selected |
|--------|-------------|----------|
| Field on the ledger payload only (Recommended) | Add `reject_stage: Option<RejectStage> { BeforePrompt, AfterPrompt }` to `AuditEventPayload` in audit_integrity.rs. Set at the 5 push sites based on which gate produced the decision. Cross-platform `AuditEntry` untouched. nono audit show surfaces it. None for Approved entries. | ✓ |
| New field on cross-platform AuditEntry | Add `reject_stage` to `nono::supervisor::AuditEntry`. Cleaner data model but breaks D-19 byte-identical guarantee on cross-platform code. | |
| Structured prefix in reason string | Encode as `before-prompt:` / `after-prompt:` prefix. Zero schema change. Trade: free-form parsing; collides with G-04's `broker failed:` prefix. | |

**User's choice:** Field on the ledger payload only (Recommended)
**Notes:** Preserves D-19 invariant on cross-platform AuditEntry. Localizes Windows-AIPC concept to the ledger-payload layer.

---

## OpenUrl scope

| Option | Description | Selected |
|--------|-------------|----------|
| Skip — defer with rest of OpenUrl (Recommended) | OpenUrl on Windows is a stub returning 'not available yet' — no broker decision made. Don't emit a Denied event for a feature that doesn't exist yet. Document the deferral; pick it up when Windows OpenUrl actually has a broker. | ✓ |
| Emit a Denied 'not-implemented' event | Record a Denied event with reason 'OpenUrl not available on Windows'. Slightly broader audit surface; risks normalizing 'feature unavailable' as a security decision. | |
| Out of scope — strip OpenUrl mention from AUD-05 | Update REQUIREMENTS.md AUD-05 'What' line to remove URL-open language. | |

**User's choice:** Skip — defer with rest of OpenUrl (Recommended)
**Notes:** AUD-05 'URL-open events from any existing URL-handling surfaces' is vacuously satisfied — there is no existing URL surface on Windows. REQUIREMENTS.md NOT updated; deferral noted in Plan 23-01 SUMMARY.

---

## Test approach

| Option | Description | Selected |
|--------|-------------|----------|
| Dispatcher unit tests + extend aipc_handle_brokering_integration (Recommended) | Extend `capability_handler_tests` in supervisor.rs to assert recorder receives `record_capability_decision` per request. Plus extend `aipc_handle_brokering_integration` (already shells aipc-demo.exe) to assert audit-events.ndjson contains expected events. Two layers, both already in CI. | ✓ |
| Dispatcher unit tests only + HUMAN-UAT for E2E | Unit tests cover wiring; HUMAN-UAT covers live aipc-demo.exe → nono audit show round-trip. Lighter test code, but E2E claim depends on manual run. | |
| Full E2E only (cargo test runs aipc-demo.exe) | Single integration test shells aipc-demo.exe under --audit-integrity. Strong proof; slow; brittle. | |

**User's choice:** Dispatcher unit tests + extend aipc_handle_brokering_integration (Recommended)
**Notes:** Reuses Phase 18.1 `capability_handler_tests` and `aipc_handle_brokering_integration` patterns. No new HUMAN-UAT entry.

---

## Claude's Discretion

- Exact name + serde encoding of `RejectStage` enum (planner picks against existing AuditEventPayload conventions).
- Whether to bind the recorder mutex once at the top of the dispatcher or per-push-site.
- Error handling when `record_capability_decision` returns Err: log + continue, do not fail-close (per 22-05a SUMMARY pattern).
- Test fixture sharing vs duplication.

## Deferred Ideas

- Windows OpenUrl audit emission (no broker exists yet).
- Cross-platform `RejectStage` field on `nono::supervisor::AuditEntry` (breaks D-19).
- `nono audit show --stage` filtering UX.
- Stage-aware retention/compaction policy.
- AuditEventPayload schema versioning policy precedent.
