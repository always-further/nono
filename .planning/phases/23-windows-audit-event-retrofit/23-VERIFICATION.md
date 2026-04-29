---
phase: 23-windows-audit-event-retrofit
verified: 2026-04-29T00:00:00Z
status: passed
score: 8/8 must-haves verified
requirements: [AUD-05]
must_haves_total: 8
must_haves_verified: 8
tests_total: 60
tests_passed: 60
overrides_applied: 0
---

# Phase 23: Windows Audit-Event Retrofit Verification Report

**Phase Goal:** A Windows user who inspects an audit session via `nono audit show <id>` sees supervisor decisions for every AIPC broker path recorded with the same structured shape macOS uses for its equivalent capability events.

**Verified:** 2026-04-29
**Status:** passed
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths (from PLAN frontmatter must_haves.truths)

| #   | Truth                                                                                                                                                                          | Status     | Evidence                                                                                                                                                                                              |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Windows user running `aipc-demo.exe` under `--audit-integrity` then `nono audit show <id>` sees one capability_decision event per brokered handle (Event/Mutex/Pipe/Socket/JobObject) | ✓ VERIFIED | `audit_integrity_records_5_handle_kinds_in_ledger` test passes (supervisor.rs:5083); `cmd_show` emits "Capability Decisions: N" counter (audit_commands.rs:438) and JSON `capability_decisions` array (line 589). Layer-2 E2E deferred per documented Step-7 fallback. |
| 2   | Privileged-port Socket request produces Denied event in ledger with reason containing 'broker failed:' AND 'privileged port'                                                  | ✓ VERIFIED | `wr01_socket_*` test asserts on-disk reject_stage = "after-prompt" + reason substring match (5 wr01_ tests pass).                                                                                      |
| 3   | Every wr01_* dispatcher test still passes; ledger entries carry reject_stage matching WR-01 verdict matrix                                                                    | ✓ VERIFIED | `cargo test capability_handler_tests::wr01_` → 5 passed. Matrix: BeforePrompt for mask-gate kinds (Event/Mutex/JobObject), AfterPrompt for Pipe/Socket G-04 flips. Encoded in supervisor.rs:1978, 2094. |
| 4   | AppliedLabelsGuard Drop ordering invariant survives — `audit_flush_before_drop` test passes                                                                                    | ✓ VERIFIED | `cargo test audit_flush_before_drop` → 1 passed (`test exec_strategy::labels_guard::tests::audit_flush_before_drop ... ok`).                                                                          |
| 5   | D-19 invariant: `git diff --stat` against locked cross-platform paths is empty                                                                                                | ✓ VERIFIED | `git diff --stat 1b98a174 HEAD -- crates/nono/src/ crates/nono-cli/src/terminal_approval.rs crates/nono-cli/src/profile/ crates/nono-cli/data/` → empty output.                                       |
| 6   | D-21 invariant: non-Windows builds compile clean; cross-platform files have no behavioral change                                                                              | ✓ VERIFIED | `grep -c "RejectStage"` on `exec_strategy.rs`, `supervised_runtime.rs`, `rollback_runtime.rs` → all `:0`. Type-only Arc-wrapping change verified by 23-REVIEW.md.                                       |
| 7   | OpenUrl branch (supervisor.rs ~2118) NOT touched and emits no ledger event (D-03)                                                                                              | ✓ VERIFIED | `git diff 1b98a174 HEAD -- supervisor.rs \| grep -A20 "SupervisorMessage::OpenUrl" \| grep -E "emit_to_ledger\|record_capability_decision"` → no matches. Verified by full-diff inspection. |
| 8   | No credential material (raw session_token bytes) appears in NDJSON ledger; token redaction via `audit_entry_with_redacted_token` is the single AuditEntry construction path    | ✓ VERIFIED | `recorded_ledger_redacts_session_token` test passes; sensitive token "TOPSECRET_TOKEN_DO_NOT_LEAK_42" at supervisor.rs:5026 asserted absent from on-disk ledger.                                       |

**Score:** 8/8 truths verified

---

### Required Artifacts

| Artifact                                                       | Expected                                                                                  | Status     | Details                                                                                                                                                                  |
| -------------------------------------------------------------- | ----------------------------------------------------------------------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `crates/nono-cli/src/audit_integrity.rs`                       | RejectStage enum + reject_stage field on AuditEventPayload::CapabilityDecision           | ✓ VERIFIED | Line 49: `pub(crate) enum RejectStage`; line 79: `reject_stage: Option<RejectStage>` with `#[serde(default, skip_serializing_if = "Option::is_none")]`.                  |
| `crates/nono-cli/src/exec_strategy_windows/supervisor.rs`      | 5 emit-to-ledger call sites; record_capability_decision call routed                       | ✓ VERIFIED | `grep "emit_to_ledger("` → 5 sites at lines 1869, 1894, 1927, 1975, 2109. The helper closure at 1828 routes to `recorder.record_capability_decision(entry, reject_stage)`. |
| `crates/nono-cli/src/exec_strategy_windows/mod.rs`             | audit_recorder threaded into handle_windows_supervisor_message call site                  | ✓ VERIFIED | Line 695-697: `audit_recorder: Option<&Arc<Mutex<AuditRecorder>>>`; passed at lines 744 + 817.                                                                            |
| `crates/nono-cli/src/audit_commands.rs`                        | Capability Decisions counter rendering + JSON capability_decisions field in cmd_show     | ✓ VERIFIED | Line 320: `read_capability_decisions_from_ledger`; line 438: text counter; line 589: JSON array.                                                                          |
| `crates/nono-cli/tests/aipc_handle_brokering_integration.rs`   | Layer-2 E2E test: 5 HandleKinds → 5 ledger entries                                       | ⚠ DEFERRED | File unchanged in Phase 23. Layer-2 test deferred per documented authorized fallback (handle_windows_supervisor_message is `pub(super)`, cannot be called from `tests/`); compensating layer-1 multi-kind E2E lives in supervisor.rs:5083 (`audit_integrity_records_5_handle_kinds_in_ledger`). 5 pre-existing integration tests still pass. |

---

### Key Link Verification

| From                                                          | To                                                          | Via                                                                                          | Status |
| ------------------------------------------------------------- | ----------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ------ |
| `handle_windows_supervisor_message`                           | `AuditRecorder::record_capability_decision`                 | `recorder_mutex.lock()` → `record_capability_decision(entry.clone(), reject_stage)` (l.1836) | WIRED  |
| capability-pipe handler closure (mod.rs)                      | `handle_windows_supervisor_message`                         | `audit_recorder.as_ref()` threaded as `Option<&Arc<Mutex<AuditRecorder>>>`                   | WIRED  |
| `AuditEventPayload::CapabilityDecision`                       | NDJSON wire format                                          | `#[serde(default, skip_serializing_if = "Option::is_none")]` on reject_stage (line 78)        | WIRED  |
| WR-01 verdict matrix (supervisor.rs ~2155 docstring)          | ledger reject_stage encoding                                | site 4 → BeforePrompt (l.1978); site 5 G-04 flip on Pipe\|Socket → AfterPrompt (l.2094)      | WIRED  |

---

### Behavioral Spot-Checks (cargo test on Windows target)

| Behavior                                                                       | Command                                                                                                                                | Result            | Status |
| ------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | ------ |
| Workspace builds clean for Windows                                             | `cargo build --workspace --target x86_64-pc-windows-msvc`                                                                              | finished in 0.60s | ✓ PASS |
| WR-01 verdict matrix tests                                                     | `cargo test --package nono-cli --target x86_64-pc-windows-msvc capability_handler_tests::wr01_`                                        | 5 passed          | ✓ PASS |
| Recorder TDD tests (T-23-03 lock-poison + emission-optional + happy-path)      | `cargo test --package nono-cli --target x86_64-pc-windows-msvc capability_handler_tests::recorder_`                                    | 3 passed          | ✓ PASS |
| Token-redaction regression (T-23-01)                                           | `cargo test ... capability_handler_tests::recorded_ledger_redacts_session_token`                                                       | 1 passed          | ✓ PASS |
| AUD-05 acceptance #1 multi-kind E2E (layer-1 compensating fallback)           | `cargo test ... capability_handler_tests::audit_integrity_records_5_handle_kinds_in_ledger`                                            | 1 passed          | ✓ PASS |
| audit_integrity tests (Task 1 surface)                                         | `cargo test --package nono-cli --target x86_64-pc-windows-msvc audit_integrity::`                                                      | 8 passed          | ✓ PASS |
| audit_commands tests (Task 3 surface)                                          | `cargo test --package nono-cli --target x86_64-pc-windows-msvc audit_commands::`                                                       | 5 passed          | ✓ PASS |
| Phase 22-05b invariant (`audit_flush_before_drop`)                             | `cargo test --package nono-cli --target x86_64-pc-windows-msvc audit_flush_before_drop`                                                | 1 passed          | ✓ PASS |
| AIPC handle-brokering integration (5 pre-existing layer-2 tests, unchanged)    | `cargo test --package nono-cli --target x86_64-pc-windows-msvc --test aipc_handle_brokering_integration`                                | 5 passed          | ✓ PASS |
| capability_handler_tests overall (regression bound for Phase 18 + Phase 23)    | `cargo test --package nono-cli --target x86_64-pc-windows-msvc capability_handler_tests::`                                             | 41 passed         | ✓ PASS |

**Total: 60 tests passing across the affected surfaces** (SUMMARY claimed 54; actual is 60 across all listed surfaces).

---

### Invariance Gates

| Gate                                                          | Command                                                                                                                          | Result    | Status |
| ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | --------- | ------ |
| D-19 (cross-platform code untouched)                          | `git diff --stat 1b98a174 HEAD -- crates/nono/src/ crates/nono-cli/src/terminal_approval.rs crates/nono-cli/src/profile/ crates/nono-cli/data/` | empty     | ✓ HOLD |
| D-21 (RejectStage stays nono-cli-windows-local)              | `grep -c "RejectStage" exec_strategy.rs supervised_runtime.rs rollback_runtime.rs`                                              | all `:0`  | ✓ HOLD |
| D-03 (OpenUrl arm untouched)                                 | `git diff ... supervisor.rs \| grep -A20 "SupervisorMessage::OpenUrl" \| grep -E "emit_to_ledger\|record_capability_decision"` | no match  | ✓ HOLD |
| 5 emit_to_ledger call sites                                  | `grep -nE "emit_to_ledger\(" supervisor.rs`                                                                                     | 5 sites   | ✓ HOLD |
| record_capability_decision is live (no dead-code suppression) | `grep -B5 "fn record_capability_decision" audit_integrity.rs \| grep -c "#\[allow(dead_code)\]"`                              | 0         | ✓ HOLD |
| Token-redaction regression test exists                        | `grep "TOPSECRET_TOKEN_DO_NOT_LEAK" supervisor.rs`                                                                              | line 5026 | ✓ HOLD |
| RejectStage absent from `crates/nono/src/`                    | `grep -rn "reject_stage\|RejectStage" crates/nono/src/`                                                                         | no match  | ✓ HOLD |

All 7 invariance gates hold.

---

### Requirements Coverage

| Requirement | Source Plan | Description                                                                          | Status      | Evidence                                                                                                                                                                                              |
| ----------- | ----------- | ------------------------------------------------------------------------------------ | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| AUD-05      | 23-01       | Windows supervisor emits ledger events for AIPC broker decisions (5 HandleKinds + WR-01 stage encoding) | ✓ SATISFIED | All 3 acceptance criteria met. AC#1: 5 HandleKinds → 5 ledger entries (`audit_integrity_records_5_handle_kinds_in_ledger`). AC#2: privileged-port Socket Denied with "broker failed: ... privileged port" (wr01_socket test). AC#3: wr01_* matrix preserved + ledger reflects reject_stage. URL-open branch vacuously satisfied per CONTEXT D-03 (no Windows OpenUrl broker exists yet). |

REQUIREMENTS.md line 329 records AUD-05 as Complete (2026-04-29; commits 427e1283, a9307802, 263795a9) — matches phase frontmatter.

---

### Anti-Patterns Found

| File                                       | Line       | Pattern                              | Severity | Impact                                                                                                                                                                                                              |
| ------------------------------------------ | ---------- | ------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `crates/nono/src/manifest.rs`              | 95, 103    | `clippy::collapsible_match`          | ℹ Info   | **Pre-existing on `main` BEFORE Phase 23.** Tracked in `deferred-items.md`. Last touched commit (`cf5a60a1`) predates Phase 22. Phase 23 is constitutionally barred from touching `crates/nono/` (D-19 invariant).   |
| `crates/nono-cli/src/audit_attestation.rs` | 281, 418, 447, 471 | rustfmt drift (single-line vs multi-line tuple) | ℹ Info   | **Pre-existing on `main` BEFORE Phase 23.** Tracked in `deferred-items.md`. `git diff --stat 1b98a174 HEAD -- crates/nono-cli/src/audit_attestation.rs` returns empty — Phase 23 commits did NOT touch the file.   |

Phase 23-touched files alone pass `rustfmt --check` cleanly (verified via `rustfmt --check` on the 7 modified files individually).

No new anti-patterns introduced by Phase 23. Both items are explicitly out of scope per CLAUDE.md "fix only issues caused by current task" and the plan's `<scope_guardrails>`.

---

### Human Verification Required

None. Per CONTEXT.md D-04, the dispatcher unit tests + the layer-1 multi-kind E2E test (`audit_integrity_records_5_handle_kinds_in_ledger`) cover the AUD-05 acceptance shape without requiring a live `aipc-demo.exe` HUMAN-UAT. The plan explicitly states "Avoid: Adding a new HUMAN-UAT entry for AUD-05 (Phase 22's UAT was the last one for v2.2's audit-integrity surface)." All AC#1/#2/#3 are exercised in cargo tests.

---

### Documented Deviations (accepted)

1. **Layer-2 integration test deferral (authorized by plan Step 7 fallback).** `tests/aipc_handle_brokering_integration.rs` was listed as a layer-2 target in the plan frontmatter, but `handle_windows_supervisor_message` is `pub(super)` and cannot be reached from the `tests/` directory without violating CLAUDE.md "library is policy-free." The plan's Step 7 explicitly authorizes redirecting layer-2 work to `capability_handler_tests` mod when the surface is not exposed. The compensating layer-1 multi-kind E2E test (`audit_integrity_records_5_handle_kinds_in_ledger`, supervisor.rs:5083) dispatches one request per HandleKind through a shared recorder and asserts the ledger contains 5 capability_decision entries covering {Event, Mutex, Pipe, Socket, JobObject}. AUD-05 acceptance #1 is fully met by the layer-1 test.

2. **Pre-existing clippy + fmt drift (out of scope per CLAUDE.md).** Two `clippy::collapsible_match` errors in `crates/nono/src/manifest.rs:95+103` and four rustfmt drift hunks in `crates/nono-cli/src/audit_attestation.rs:281,418,447,471` exist on `main` BEFORE Phase 23. Both are tracked in `.planning/phases/23-windows-audit-event-retrofit/deferred-items.md`. Phase 23 commits did NOT touch either file (verified via `git diff --stat`). Future cleanup quick task will address them.

---

### Gaps Summary

No gaps. All 8 must-haves verified. All 60 tests pass. All 7 invariance gates hold. AUD-05 fully satisfied by Phase 23 commits 427e1283, a9307802, 263795a9. The 3 INFO notes from `23-REVIEW.md` are documentation hygiene (stale doc-comment line numbers + intentional best-effort error swallowing in `read_capability_decisions_from_ledger`) and do not affect runtime correctness, security, or audit-integrity invariants. Both pre-existing anti-patterns (clippy::collapsible_match, rustfmt drift) are out of scope per documented policy and tracked in `deferred-items.md`.

**v2.2 milestone is now ready for `/gsd-complete-milestone v2.2`.**

---

_Verified: 2026-04-29_
_Verifier: Claude (gsd-verifier)_
