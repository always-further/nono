---
phase: 23-windows-audit-event-retrofit
reviewed: 2026-04-29T13:46:40Z
depth: standard
files_reviewed: 7
files_reviewed_list:
  - crates/nono-cli/src/audit_integrity.rs
  - crates/nono-cli/src/audit_commands.rs
  - crates/nono-cli/src/exec_strategy_windows/supervisor.rs
  - crates/nono-cli/src/exec_strategy_windows/mod.rs
  - crates/nono-cli/src/supervised_runtime.rs
  - crates/nono-cli/src/exec_strategy.rs
  - crates/nono-cli/src/rollback_runtime.rs
findings:
  critical: 0
  warning: 0
  info: 3
  total: 3
status: clean
---

# Phase 23: Code Review Report

**Reviewed:** 2026-04-29T13:46:40Z
**Depth:** standard
**Files Reviewed:** 7
**Status:** clean (3 informational notes)

## Summary

Phase 23 wires the existing `AuditRecorder` into the Windows AIPC capability
dispatcher across three commits (`427e1283`, `a9307802`, `263795a9`). The
review covered the full diff against base `1b98a174`, with explicit checks
for the security-critical, concurrency, cross-platform, and Rust-quality
invariants spelled out in the prompt.

All critical invariants hold:

- **Token redaction.** Every one of the 5 push sites in
  `handle_windows_supervisor_message` constructs the `AuditEntry` via
  `audit_entry_with_redacted_token` BEFORE handing it to `emit_to_ledger`
  (supervisor.rs:1863, 1888, 1921, 1965, 2103). The regression-guard test
  `recorded_ledger_redacts_session_token` (supervisor.rs ~5023-5052) writes a
  sensitive token through the dispatcher and asserts
  `!ledger.contains(sensitive_token)`. No raw-token leak path exists.
- **Lock-poison handling.** The `emit_to_ledger` closure
  (supervisor.rs:1828-1854) uses `match recorder_mutex.lock()` with both
  `Ok` and `Err` arms; the `Err` arm warns and continues. No `?`
  propagation. The dispatcher returns `Ok(())` on poisoned mutex, locked
  by the `recorder_does_not_abort_dispatcher_on_lock_poison` test.
- **Lock scope vs wire response.** The recorder mutex guard goes out of
  scope at the end of the closure invocation, BEFORE
  `sock.send_response(...)` is called. The lock IS held across the
  ledger-line `file.write_all + flush`, but that is single-writer ledger
  semantics by design and is not held across the wire response.
- **Cross-platform invariance (D-21, D-19, D-03).**
  `crates/nono/` (the core library) is byte-identical to pre-Phase-23
  (verified via `git diff --name-only`).
  `exec_strategy.rs`, `supervised_runtime.rs`, and `rollback_runtime.rs`
  contain ONLY type-level changes (Arc-wrapping the existing
  `Mutex<AuditRecorder>`); no `RejectStage` or `record_capability_decision`
  references appear in those files (verified via Grep over the whole
  `crates/nono-cli/src/` tree — only `audit_integrity.rs` and
  `exec_strategy_windows/supervisor.rs` reference those identifiers).
- **`OpenUrl` arm untouched.** `git diff` over the `OpenUrl` arm
  (supervisor.rs:2118-2126) shows zero changes; no `emit_to_ledger` /
  `record_capability_decision` calls were introduced in that arm.
- **Closure capture shape.** `emit_to_ledger` captures the
  `Option<&Arc<...>>` parameter `audit_recorder` by reference (no `move`,
  and `Option<&T>` is `Copy` regardless). The capability-pipe thread
  closure clones the Arc exactly once at thread spawn (supervisor.rs:487),
  then passes `audit_recorder_for_thread.as_ref()` per-message
  (supervisor.rs:565) — no per-call-site Arc clone.
- **Serde back-compat.** `RejectStage` is `pub(crate)` with
  `#[serde(rename_all = "kebab-case")]` (audit_integrity.rs:48) and the
  `reject_stage` field on `CapabilityDecision` carries
  `#[serde(default, skip_serializing_if = "Option::is_none")]`
  (audit_integrity.rs:78). The
  `reject_stage_deserializes_old_records_as_none` test
  (audit_integrity.rs:543-566) confirms Phase-22-shaped NDJSON records
  parse cleanly with `reject_stage = None`.
- **No new `.unwrap()` / `.expect()` outside `#[cfg(test)]`.** The diff
  scan for newly introduced `.unwrap()` / `.expect()` returns matches
  only inside `mod tests { ... }` blocks (allowed by the project's
  `clippy::unwrap_used` policy).

The three informational notes below are documentation hygiene — they do not
affect runtime correctness, security, or the audit-integrity invariants.

## Info

### IN-01 (Task 1): Stale supervisor.rs line numbers in `RejectStage` doc comments

**File:** `crates/nono-cli/src/audit_integrity.rs:34, 37, 73, 75, 46`
**Issue:** The `RejectStage` enum doc comment and the `reject_stage` field
doc comment cite specific line numbers in `supervisor.rs` that were already
stale after the `a9307802` feat commit added ~80 lines to the dispatcher:

| Doc reference                | Cited line | Actual line | Drift  |
|------------------------------|-----------:|------------:|--------|
| "mask gate at supervisor.rs" |       1891 |        1958 | +67    |
| "G-04 broker-failure flip"   |       1997 |        2080 | +83    |
| "verdict matrix module docstring lines" | 2034-2076 | ~2155-2176 | +120  |

The plan (per the prompt) accepts hardcoded line numbers as a known
constraint of the codebase, so this is **not a blocker**. The references
are useful breadcrumbs but will continue to drift. If a follow-up wants
to harden them, the conventional fix is replacing them with anchor
markers (e.g. `// PHASE-23-MASK-GATE` near the site, with grep-able
references in the doc comment).

**Fix (optional, not required for v2.2):** Either refresh the line
numbers or replace with stable anchors:
```rust
/// mask gate (search `// PHASE-23-MASK-GATE` in supervisor.rs)
```

---

### IN-02 (Task 3): Stale supervisor.rs line number in test docstring

**File:** `crates/nono-cli/src/exec_strategy_windows/supervisor.rs:5014`
**Issue:** The `recorded_ledger_redacts_session_token` test docstring
says "the in-memory `audit_entry_with_redacted_token` (supervisor.rs:1279)
is the load-bearing scrub". The actual function lives at line 1307 in
the post-Phase-23 file (28-line drift). Same caveat as IN-01: the plan
accepts this constraint.

**Fix (optional):** Refresh to `(supervisor.rs:1307)` or use a doc-anchor.

---

### IN-03 (Task 3): `read_capability_decisions_from_ledger` swallows per-line parse errors silently

**File:** `crates/nono-cli/src/audit_commands.rs:320-348`
**Issue:** The helper uses `let Ok(line) = line_result else { continue }`
and `let Ok(record) = serde_json::from_str::<serde_json::Value>(&line)
else { continue }` to skip unreadable / unparseable NDJSON lines. A
genuinely corrupted ledger that happens to have ALL its
`capability_decision` lines malformed would silently render
`capability_decisions: null` in `audit show --json` and "0 capability
decisions" in the human output, with no warning to the user.

This is **intentional per the function's docstring**:
> Best-effort: on file-missing or per-line parse error, returns
> `Ok(vec![])` (empty list) rather than failing the audit-show command.
> The integrity summary path (already-rendered by `cmd_show`) is the
> load-bearing failure surface; this function is a UX add and must
> degrade gracefully.

The fail-closed surface is `nono audit verify`, which uses
`audit_integrity::verify_audit_log` (a separate parser that DOES return
`Err` on malformed lines — see audit_integrity.rs:346-351). So a
corrupted ledger will still be caught at verify time. No security
regression, but operators inspecting only `audit show --json` could be
misled if they don't also run `audit verify`.

**Fix (optional, follow-up backlog):** Consider emitting a single
`tracing::warn!` per malformed line (deduped) so operators get a hint
to run `audit verify`. Not required for v2.2 acceptance.

---

_Reviewed: 2026-04-29T13:46:40Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
