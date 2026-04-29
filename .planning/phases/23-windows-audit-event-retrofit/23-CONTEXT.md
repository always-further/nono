# Phase 23: Windows Audit-Event Retrofit - Context

**Gathered:** 2026-04-28
**Status:** Ready for planning

<domain>
## Phase Boundary

Wire the existing `AuditRecorder` (landed in Phase 22-05a) into the AIPC capability-decision dispatch in `crates/nono-cli/src/exec_strategy_windows/supervisor.rs::handle_windows_supervisor_message` so that every Windows supervisor decision (Approved / Denied) for the 5 AIPC HandleKinds (Event, Mutex, Pipe, Socket, JobObject) plus the legacy File path is appended to the persistent `audit-events.ndjson` ledger and surfaced through `nono audit show <id>`. Reject-stage asymmetry (BEFORE-prompt vs AFTER-prompt, locked by Phase 18.1 G-05 verdict matrix) is preserved AND recorded explicitly per event.

Closes REQ-AUD-05. The single plan in this phase is 23-01 (per ROADMAP.md).

</domain>

<decisions>
## Implementation Decisions

### Wiring locus (D-01)
- **D-01:** Plumb `audit_recorder: Option<&Mutex<AuditRecorder>>` as a new parameter on `handle_windows_supervisor_message`. At each of the 5 existing `audit_log.push(audit_entry_with_redacted_token(...))` sites in that function (supervisor.rs:1795 duplicate-replay, :1818 invalid-token, :1849 unknown-kind, :1891 mask-gate-deny, :1997 final-decision), also call `recorder.lock().record_capability_decision(entry.clone())` when recorder is `Some`. Per-kind helpers (`handle_event_request`, `handle_mutex_request`, `handle_pipe_request`, `handle_socket_request`, `handle_job_object_request`) stay audit-unaware — their signature does not change.
- **Rejected alternatives:** Push into per-kind helpers (5 signature changes, awkward Approved-vs-Denied entry construction split); tee wrapper around `Vec<AuditEntry>` (new abstraction for one consumer).
- **Why:** Five existing push sites are already the funnel for every Decision response that goes back on the wire. Single-site discipline matches the G-04 fix (Phase 18.1) which already constructs `(decision, grant)` at one place. Keeps 22-05a's D-19 / D-21 byte-identical-preservation invariants on cross-platform code in force.

### Reject-stage encoding (D-02)
- **D-02:** Add a `reject_stage: Option<RejectStage>` field to `AuditEventPayload` in `crates/nono-cli/src/audit_integrity.rs` only — do NOT touch the cross-platform `nono::supervisor::AuditEntry` struct. Variants: `BeforePrompt`, `AfterPrompt`. Field is `None` for `Approved` decisions and for the duplicate-replay / invalid-token / unknown-kind early rejections (which fire before any stage gate).
- **Stage assignment at the 5 push sites:**
  - Site 1 (duplicate replay, :1795) → `None` (pre-stage)
  - Site 2 (invalid token, :1818) → `None` (pre-stage)
  - Site 3 (unknown HandleKind, :1849) → `None` (pre-stage)
  - Site 4 (mask gate deny for Event/Mutex/JobObject, :1891) → `Some(BeforePrompt)`
  - Site 5 (final decision, :1997):
    - For Event/Mutex/JobObject Approved → `None`; Denied path is unreachable here for these kinds (already gated at site 4)
    - For Pipe/Socket Denied via `broker failed: …` (G-04 flip from helper Err) → `Some(AfterPrompt)`
    - For File / any Approved → `None`
- **Why:** Keeps cross-platform `AuditEntry` structurally identical (D-19 invariant), localizes the Windows-AIPC-specific concept to the ledger-payload layer where `nono audit show` already surfaces it, and gives downstream tooling a typed enum rather than free-form string parsing.

### OpenUrl scope (D-03)
- **D-03:** OpenUrl branch (`SupervisorMessage::OpenUrl` arm at supervisor.rs:2010) is **out of scope** for Phase 23. The current Windows OpenUrl handler returns `success: false` with `"Windows delegated browser-open flows are not available yet"` — there is no broker decision to record. Do NOT emit a Denied "not-implemented" event for it. Leave the arm untouched.
- **Why:** Recording a Denied event for a feature that doesn't exist conflates "the supervisor refused this" with "the supervisor doesn't implement this," and pollutes `nono audit show` output. The OpenUrl audit story lands when Windows OpenUrl actually grows a broker. AUD-05's "URL-open events from any existing URL-handling surfaces" — there is no existing URL-handling surface on Windows, so the requirement is vacuously satisfied.
- **Scope clarification for planner:** REQUIREMENTS.md REQ-AUD-05 "What" mentions URL-open events; do NOT update REQUIREMENTS.md as part of this phase — leave it as-is so the requirement remains on file for the future Windows OpenUrl phase. Note the deferral in the Plan 23-01 SUMMARY's "Out of scope" section instead.

### Test approach (D-04)
- **D-04:** Two-layer coverage:
  1. **Dispatcher unit tests (Windows-gated, in `capability_handler_tests` mod inside supervisor.rs):** Extend the existing per-kind tests (e.g. `handle_brokers_event_with_default_mask`, `handle_denies_event_with_mask_outside_allowlist`, the 5 G-04 broker-failure tests, the 5 `wr01_*` reject-stage tests) to construct an `AuditRecorder` over a `tempfile::TempDir`, pass `Some(&Mutex::new(recorder))` to `handle_windows_supervisor_message`, and assert (a) `audit-events.ndjson` exists, (b) it contains exactly N entries (1 per request), (c) the `reject_stage` field on each entry matches the WR-01 verdict matrix, (d) no credential material appears in payload (sanitization regression).
  2. **E2E integration extension:** Extend the existing `aipc_handle_brokering_integration` test (Windows-gated, already shells `aipc-demo.exe`) to run under `--audit-integrity` and parse `audit-events.ndjson` for the 5 expected `HandleKind` ledger events.
- **Reject test from acceptance criterion 2:** Add a dispatcher-level test that constructs a privileged-port (port < 1024) Socket request, asserts the resulting ledger entry has `decision=Denied`, `reason` contains `"broker failed:"` AND `"privileged port"` (substring match — exact wording lives in `handle_socket_request`), and `reject_stage = Some(AfterPrompt)`.
- **Why:** Layer 1 is fast, deterministic, runs on every CI and exercises every push site. Layer 2 proves the full process chain (sandbox apply → child broker request → supervisor record → ledger flush) end-to-end without relying on HUMAN-UAT.
- **Avoid:** Adding a new HUMAN-UAT entry for AUD-05 (Phase 22's UAT was the last one for v2.2's audit-integrity surface; the dispatcher + integration tests collectively prove the acceptance shape).

### Claude's Discretion
- Exact name of the `RejectStage` enum and its serde tag/discriminant in NDJSON (suggested: kebab-case `"before-prompt"` / `"after-prompt"` to match the ledger's existing snake-case-with-hyphen convention if any; planner verifies against AuditEventPayload's existing field encoding).
- Whether to bind the recorder mutex once at the top of `handle_windows_supervisor_message` (single lock, drop after the function returns) or per-push-site lock-and-drop. Trade: re-entrancy vs. lock-hold-duration. Either is acceptable as long as it survives the AppliedLabelsGuard Drop flush.
- Error handling when `record_capability_decision` itself returns `Err`: per the 22-05a SUMMARY pattern, log via `tracing::warn!` and continue — do NOT abort the supervisor. The wire response goes out regardless. Phase 23 must NOT introduce a new fail-closed surface in the dispatcher.
- Test fixture: whether to share an `AuditRecorder` constructor helper across the existing tests or duplicate the construction in each test. Either works; planner picks.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirement and roadmap (locked)
- `.planning/REQUIREMENTS.md` § REQ-AUD-05 — What/Enforcement/Security/Acceptance for Windows AIPC broker audit emissions.
- `.planning/ROADMAP.md` § "Phase 23: Windows Audit-Event Retrofit" (lines 102–122) — Goal, success criteria, Plan 23-01 description, rationale for not collapsing into 22-05.

### Audit infrastructure (already shipped, do not modify boundary)
- `crates/nono-cli/src/audit_integrity.rs` — `AuditRecorder` struct, `record_capability_decision(entry: AuditEntry) -> Result<()>` API, `AuditEventPayload` struct (this is where D-02 adds the `reject_stage` field).
- `crates/nono-cli/src/exec_strategy_windows/labels_guard.rs` § `audit_flush_before_drop` test (lines 495+) — locks the AppliedLabelsGuard ↔ AuditRecorder Drop ordering invariant. Phase 23 must not regress this; planner should verify the dispatcher recorder calls land BEFORE the guard's Drop runs.
- `crates/nono/src/undo/types.rs` — `AuditEntry` cross-platform struct (D-19 invariant: do NOT modify in this phase).

### Surface to wire
- `crates/nono-cli/src/exec_strategy_windows/supervisor.rs` lines 1776–2009 — `handle_windows_supervisor_message`, the dispatcher with the 5 `audit_log.push` sites that D-01 extends.
- `crates/nono-cli/src/exec_strategy_windows/mod.rs:695` — `audit_recorder: Option<&Mutex<AuditRecorder>>` is already a parameter on the supervisor entrypoint; needs threading down into `handle_windows_supervisor_message`.
- `crates/nono-cli/src/exec_strategy_windows/supervisor.rs::audit_entry_with_redacted_token` (line 1279) — token-redacting `AuditEntry` builder; reused unchanged.

### WR-01 verdict matrix (locked, must be reflected in ledger)
- `crates/nono-cli/src/exec_strategy_windows/supervisor.rs` § `capability_handler_tests` module docs (lines 2034–2076) — the BEFORE/AFTER prompt verdict matrix that D-02's `reject_stage` encodes per event.
- `wr01_*` regression tests in the same module — must continue to pass, and the ledger entries those tests now write must carry `reject_stage` matching the matrix.

### G-04 broker-failure flip (must coexist)
- `crates/nono-cli/src/exec_strategy_windows/supervisor.rs:1925` — the `(decision, grant) = if decision.is_granted() { … broker helper … }` block that rewrites `Approved → Denied { reason: "broker failed: …" }` on per-kind helper Err. D-01 ledger emission at site 5 must observe the post-flip decision (this is automatic with the recommended wiring — `audit_log.push` runs after the flip).

### Phase 22-05a deferrals (this phase delivers some)
- `.planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-05a-AUD-CORE-SUMMARY.md` § "Deferred to 22-05b" — confirms the capability-decision hook was explicitly deferred from 22-05a's minimal AuditRecorder lifecycle. Phase 23 lands that hook for Windows AIPC paths.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`AuditRecorder.record_capability_decision(entry: AuditEntry) -> Result<()>`** (audit_integrity.rs:145): the exact API D-01 calls into. Already integrated with `session_started` / `session_ended` hooks in the supervisor lifecycle. Locks via the surrounding `Mutex<AuditRecorder>` that supervised_runtime constructs.
- **`audit_entry_with_redacted_token`** (supervisor.rs:1279): builds a token-redacted `AuditEntry` from a `CapabilityRequest` + `ApprovalDecision`. Reuse without modification — it's the entry that gets cloned to feed the recorder.
- **`sanitize_for_terminal`** (terminal_approval.rs): already used by the prompt path; AUD-05 says "event payload sanitized via `sanitize_for_terminal` before write." Whether it's needed at the recorder boundary depends on whether `audit_entry_with_redacted_token` already produces sanitized output — planner verifies. (Token redaction is the load-bearing scrub; `sanitize_for_terminal` is for stripping ANSI / control bytes.)
- **`capability_handler_tests` mod** (supervisor.rs:2031+): existing Windows-gated unit-test fixture with `MockApprovalBackend`, request builders for every `HandleKind`, and the WR-01 + G-04 regression coverage. D-04 layer-1 tests extend this, not greenfield.
- **`aipc_handle_brokering_integration` test** (Phase 18 regression guard, Windows-gated, shells `aipc-demo.exe`): D-04 layer-2 tests extend this to add `--audit-integrity` + ledger parsing.
- **`tempfile::TempDir`** (already a dev-dep workspace-wide): test fixture for AuditRecorder session-dir construction.

### Established Patterns
- **D-19 byte-identical preservation invariants** (Phase 22-05a): pre/post structural-grep diffs on cross-platform files (`crates/nono/src/`, `crates/nono-cli/src/terminal_approval.rs`, `crates/nono-cli/src/profile/`, `crates/nono-cli/data/`) MUST be EMPTY across this phase's commits. The planner should add the same grep gate to plan 23-01's task structure.
- **D-21 Windows-invariance preservation**: changes belong in `exec_strategy_windows/` and `audit_integrity.rs`. Cross-platform files (`exec_strategy.rs`, `supervised_runtime.rs`, `rollback_runtime.rs`) get the new parameter passed through but NO behavioral change for non-Windows. Use the `let _ = &audit_recorder;` silencer pattern from Phase 18.1 if the binding is unused on non-Windows compile paths.
- **Boundary deny-list grep gates** (Phase 22-05a §11 commits): planner pre-bakes the grep-must-be-empty gates at the bottom of each plan task — `git diff --stat` against locked files, `grep -nE` for forbidden patterns. Phase 23 should keep this discipline.
- **G-04 single-site decision tuple** (Phase 18.1): `(decision, grant)` is constructed at exactly one site so audit + wire stay in lockstep. D-01 preserves this — the recorder call piggybacks on the existing `audit_log.push`, both reading the same final `decision` value.
- **AppliedLabelsGuard Drop ↔ AuditRecorder flush ordering** (Phase 22-05b § labels_guard.rs:495+): `audit_flush_before_drop` test locks the invariant. D-04 tests must not regress it; the new dispatcher recorder calls land in the supervisor body, which is upstream of the guard's Drop on the call stack — should be naturally safe.

### Integration Points
- `handle_windows_supervisor_message` parameter list grows by one (`audit_recorder: Option<&Mutex<AuditRecorder>>`). The single caller is `exec_strategy_windows/mod.rs` near line 811, which already has the recorder in scope.
- `AuditEventPayload` schema gains one optional field. Planner verifies serde compatibility (the field defaulting to `None` should make it backward-compatible with existing audit-events.ndjson files written by Phase 22; if not, gate behind a schema version bump and document it).
- `audit show` rendering (audit_commands.rs `cmd_show` and JSON output around line 511): planner decides whether to surface the new `reject_stage` field in human-readable output (probably yes), JSON only, or both. Current `audit_event_count` rendering can be the model.

</code_context>

<specifics>
## Specific Ideas

- The 5 push sites in `handle_windows_supervisor_message` map cleanly to a 5-element ledger event sequence per request lifecycle (most paths short-circuit at site 1–4; the happy path lands at site 5). Mirror that mental model in test fixture comments.
- `RejectStage::AfterPrompt` is currently observable for exactly two HandleKinds: Pipe (direction allowlist post-approval) and Socket (privileged port + role allowlist post-approval). Document this as a Windows-AIPC quirk in the new field's doc-comment so future readers don't assume it's a generalized concept.
- Acceptance criterion 3 ("ledger reflects each kind's reject stage … BEFORE-prompt kinds carry zero-backend-call markers") suggests the test should ALSO assert `backend.calls() == 0` on the BEFORE-prompt path and `== 1` on the AFTER-prompt path — same shape Phase 18.1 G-05 already locks. Reuse `MockApprovalBackend.calls()` from those tests.

</specifics>

<deferred>
## Deferred Ideas

- **Windows OpenUrl audit emission** — deferred until Windows actually has a delegated-browser broker (no existing surface to emit from; see D-03).
- **Cross-platform `RejectStage` field on `nono::supervisor::AuditEntry`** — kept Windows-AIPC-local to preserve D-19 invariant. If macOS/Linux ever grow analogous staged rejection paths, revisit.
- **`audit show` filtering by `reject_stage`** — `nono audit show <id> --stage before-prompt` would be useful for triage but is a UX add; not required by AUD-05. Add to v2.3 backlog if asked.
- **Stage-aware ledger compaction / retention policy** — out of scope; would belong with audit-cleanup work (AUD-04 already shipped via Phase 22-05b).
- **`AuditEventPayload` schema versioning policy** — if the new optional field requires a schema bump, define the bump policy as a separate decision (not Phase 23's job to set the precedent). Default behavior: serde optional field with `#[serde(default)]` is backward-compatible by construction.

</deferred>

---

*Phase: 23-windows-audit-event-retrofit*
*Context gathered: 2026-04-28*
