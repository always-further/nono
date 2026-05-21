---
phase: 45-source-migration-aipc-g-04-resl-native-re-validation
plan: 02
type: execute
wave: 1
depends_on: []
files_modified:
  - crates/nono/src/supervisor/types.rs
  - crates/nono/src/supervisor/aipc_sdk.rs
  - crates/nono/src/supervisor/mod.rs
  - crates/nono/src/supervisor/socket.rs
  - crates/nono/src/supervisor/socket_windows.rs
  - crates/nono-cli/src/exec_strategy.rs
  - crates/nono-cli/src/exec_strategy_windows/supervisor.rs
  - crates/nono-cli/src/terminal_approval.rs
  - crates/nono-cli/src/audit_integrity.rs
  - crates/nono-cli/src/audit_commands.rs
  - CHANGELOG.md
  - docs/architecture/audit-bundle-target.md
  - .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-02-CLIPPY-CROSS-TARGET.md
autonomous: true
requirements:
  - REQ-AIPC-G04-01
requirements_addressed:
  - REQ-AIPC-G04-01
must_haves:
  truths:
    - "`ApprovalDecision::Granted` no longer exists in the source tree — renamed to `ApprovalDecision::Approved(ResourceGrant)` with the `ResourceGrant` payload inlined (D-45-C1 + D-45-C3 + ROADMAP SC#2)"
    - "`SupervisorResponse::Decision` no longer carries a `grant: Option<ResourceGrant>` field — the payload is exclusively carried by the inlined `Approved(ResourceGrant)` variant (D-45-C1)"
    - "`(Approved, grant=None)` is structurally unrepresentable — this IS the SC#2 compile-time guarantee; the `ok_or_else(\"supervisor granted but returned no ResourceGrant\")` defense-in-depth branch at `aipc_sdk.rs:~417` no longer exists in the source tree (Open Question #2: leave dispatcher pair-binding intact as defense in depth at supervisor.rs:1875-1950, but the demultiplexer branch is gone)"
    - "AUD-05 token-redaction regression `recorded_ledger_redacts_session_token` at `crates/nono-cli/src/exec_strategy_windows/supervisor.rs:5033` passes verbatim post-cascade (D-45-C1 commit-body callout)"
    - "All 23±2 pre-existing tests that depended on the `(Granted, grant=None)` shape are updated atomically in the same commit (D-45-C1)"
    - "CHANGELOG.md carries a v2.6 / Phase 45 BREAKING entry covering: wire-shape change before/after; fresh-session vs replay distinction; ADR back-reference; v2.5-binary-pin mitigation (D-45-C2)"
    - "`docs/architecture/audit-bundle-target.md` has an appended ADR amendment 45-X (planner-chosen heading) documenting the BREAKING wire-format change (D-45-C2)"
    - "`audit_entry_with_redacted_token` at `supervisor.rs:1303-1318` is preserved verbatim — the load-bearing token scrub is NOT touched (Pitfall 3)"
    - "`audit_integrity.rs:83-93` docstring referring to `reject_stage` is NOT edited (Pitfall 4 — distinct from the dropped `grant` field)"
    - "`audit_commands.rs:867` already reads `\"decision\":{\"Approved\":null}` (pre-aligned per Pitfall 2) — only edit IF the typed-deserialization path now requires a structurally-complete `ResourceGrant` payload"
    - "All 22 `SupervisorResponse::Decision { ... grant: None }` construction sites in `crates/nono-cli/src/exec_strategy_windows/supervisor.rs` drop the `grant:` field; Windows-only-files invariant honored per CONTEXT.md cross-phase invariants (this is wire-type cascade, NOT new Windows-only code)"
    - "The single atomic commit `feat(45-02):` lands wire + sdk + all consumers + all tests + audit_commands fixture comment + CHANGELOG + ADR amendment together — D-45-C1 (a partial migration is by design a build break)"
    - "Every commit carries DCO `Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>` trailer — CLAUDE.md § Coding Standards"
    - "Cross-target Linux + macOS clippy attempted from Windows dev host AND documented in `45-02-CLIPPY-CROSS-TARGET.md` per cross-target-verify-checklist.md (PARTIAL acceptable when C cross-linker absent) — D-44-E2 carry-forward"
    - "No `.unwrap()` / `.expect()` introduced; no `#[allow(dead_code)]` to silence removed surface — CLAUDE.md § Unwrap Policy + § Lazy use of dead code"
    - "Library vs CLI boundary preserved: the (Approved ⟹ grant Some) invariant is enforced at the `nono` library wire-type tier (crates/nono/src/supervisor/types.rs); CLI consumers (crates/nono-cli/src/) obey the type without introducing CLI-policy concepts into the library — CLAUDE.md § Library vs CLI Boundary"
  artifacts:
    # phase: post-execution — all `contains`/`must_not_contain` assertions describe the expected post-execution state of each artifact (the wire-format invariants the executor produces by end of plan, NOT pre-state).
    - path: "crates/nono/src/supervisor/types.rs"
      provides: "ApprovalDecision::Approved(ResourceGrant) inlined variant + SupervisorResponse::Decision without grant field + is_approved() #[must_use] helper"
      contains: "Approved(ResourceGrant)"
      must_not_contain: "grant: Option<ResourceGrant>"
    - path: "crates/nono/src/supervisor/aipc_sdk.rs"
      provides: "Demultiplexer match arm `ApprovalDecision::Approved(grant) => Ok(grant)` (the ok_or_else defense-in-depth branch is now structurally unreachable and removed)"
      contains: "ApprovalDecision::Approved(grant) => Ok(grant)"
      must_not_contain: "supervisor granted but returned no ResourceGrant"
    - path: "crates/nono-cli/src/exec_strategy_windows/supervisor.rs"
      provides: "22 SupervisorResponse::Decision construction sites updated to drop the grant field; AUD-05 regression test preserved verbatim at :5033; audit_entry_with_redacted_token preserved verbatim at :1303-1318"
      contains: "recorded_ledger_redacts_session_token"
      must_not_contain: "grant: None"
    - path: "crates/nono-cli/src/terminal_approval.rs"
      provides: "Terminal-prompt approval path constructs ApprovalDecision::Approved(ResourceGrant::sideband_file_descriptor(access)) explicitly (or planner-chosen factory)"
      contains: "ApprovalDecision::Approved"
    - path: "CHANGELOG.md"
      provides: "v2.6 / Phase 45 BREAKING wire-format entry"
      contains: "BREAKING"
    - path: "docs/architecture/audit-bundle-target.md"
      provides: "ADR amendment 45-X documenting the Approved(ResourceGrant) inlining + replay limitation for pre-v2.6 ledgers"
      contains: "45-"
    - path: ".planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-02-CLIPPY-CROSS-TARGET.md"
      provides: "Cross-target Linux + macOS clippy verification artifact (PARTIAL when C cross-linker absent)"
      contains: "PARTIAL"
  key_links:
    - from: "crates/nono/src/supervisor/types.rs (ApprovalDecision::Approved(ResourceGrant))"
      to: "crates/nono/src/supervisor/aipc_sdk.rs (demultiplexer match at :~417)"
      via: "deserialization via serde Deserialize derive on the renamed wire enum"
      pattern: "ApprovalDecision::Approved(grant)"
    - from: "crates/nono-cli/src/exec_strategy_windows/supervisor.rs (22 Decision construction sites)"
      to: "crates/nono/src/supervisor/types.rs (SupervisorResponse::Decision without `grant:` field)"
      via: "nono::supervisor::SupervisorResponse::Decision { request_id, decision } construction"
      pattern: "SupervisorResponse::Decision"
    - from: "crates/nono-cli/src/exec_strategy_windows/supervisor.rs::audit_entry_with_redacted_token (preserved verbatim)"
      to: "AUD-05 regression test recorded_ledger_redacts_session_token at :5033"
      via: "AuditEntry { decision: decision.clone() } flows transparently through serde derive on renamed enum"
      pattern: "audit_entry_with_redacted_token"
---

<objective>
Inline `ResourceGrant` into the `ApprovalDecision::Granted` variant AND rename `Granted → Approved`, producing the wire shape `ApprovalDecision::Approved(ResourceGrant)`. Drop the redundant `grant: Option<ResourceGrant>` field from `SupervisorResponse::Decision`. Cascade through the demultiplexer (`aipc_sdk.rs`), 22 Windows-supervisor construction sites, all Unix + cross-platform consumers, every dependent test (23±2 per CONTEXT.md inventory), the `audit_commands.rs:867` fixture, CHANGELOG.md (BREAKING entry), and `docs/architecture/audit-bundle-target.md` (ADR amendment 45-X) — all in a single atomic `feat(45-02):` commit per D-45-C1. The post-commit invariant: `(Approved, grant=None)` is structurally unrepresentable; the demultiplexer's `ok_or_else("supervisor granted but returned no ResourceGrant")` defense-in-depth branch is gone — this elimination IS the SC#2 compile-time guarantee.

Purpose: REQ-AIPC-G04-01 closure. Elevates the Phase 18.1-02 G-04 flow-control invariant (`Approved ⟹ grant Some`) from runtime defense to type-level enforcement. Eliminates an entire class of dispatcher-bypass spoofing vulnerabilities. Aligns with CLAUDE.md § Security Considerations "Explicit Over Implicit" and § Library vs CLI Boundary (wire-type invariant lives in `nono` library; CLI consumers cascade). AUD-05 token-redaction regression remains intact (load-bearing scrub at `supervisor.rs:1303-1318` is preserved verbatim; the test at `:5033` asserts the session token never appears on disk and flows transparently through the renamed wire shape via serde derive).

Output: ONE atomic `feat(45-02):` commit on a Phase 45 feature branch carrying:
- Wire-type rename + inlining + `is_approved()` `#[must_use]` helper rename in `crates/nono/src/supervisor/types.rs`
- Demultiplexer rewrite in `crates/nono/src/supervisor/aipc_sdk.rs:~404-433`
- Cross-platform consumer cascade in `crates/nono/src/supervisor/{mod,socket,socket_windows}.rs` + `crates/nono-cli/src/{exec_strategy,terminal_approval}.rs`
- Windows-supervisor 22-site cascade in `crates/nono-cli/src/exec_strategy_windows/supervisor.rs` (wire-type cascade, NOT new Windows-only code — D-34-E1 / D-40-E1 honored per CONTEXT.md cross-phase invariants)
- All dependent tests updated atomically
- `audit_commands.rs:867` fixture (touchup only IF typed deserialization affected — Pitfall 2)
- CHANGELOG.md v2.6 / Phase 45 BREAKING entry per D-45-C2
- `docs/architecture/audit-bundle-target.md` ADR amendment 45-X per D-45-C2
- AUD-05 regression `recorded_ledger_redacts_session_token` called out as verified-pass in commit body per D-45-C1

Plan-close artifact: `45-02-CLIPPY-CROSS-TARGET.md` per cross-target-verify-checklist.md § Enforcement (PARTIAL disposition; live GH Actions Linux + macOS Clippy on Phase 45 head SHA decisive).
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/ROADMAP.md
@.planning/STATE.md
@.planning/REQUIREMENTS.md
@.planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-CONTEXT.md
@.planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-RESEARCH.md
@.planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-PATTERNS.md
@.planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-VALIDATION.md
@.planning/templates/cross-target-verify-checklist.md
@docs/architecture/audit-bundle-target.md
@CHANGELOG.md
@CLAUDE.md

<interfaces>
<!-- The exact wire-type definitions, demultiplexer, and load-bearing helpers that the executor MUST work against. -->
<!-- Source-of-truth excerpts from PATTERNS.md (Plan 45-02 § Analog 1/2/3/4/5) + RESEARCH.md (§ Plan 45-02 Cascade Map). -->

Current `crates/nono/src/supervisor/types.rs:198-211` (enum) + `:474-495` (envelope) — the rename targets:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApprovalDecision {
    /// Access was granted. Resource-transfer details, if any, are carried by
    /// [`SupervisorResponse::Decision`].
    Granted,
    /// Access was denied with a reason.
    Denied { reason: String },
    /// The approval request timed out without a decision.
    Timeout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SupervisorResponse {
    Decision {
        request_id: String,
        decision: ApprovalDecision,
        grant: Option<ResourceGrant>,   // ← DROPPED in this plan
    },
    UrlOpened { /* unchanged */ },
}
```

Target post-rewrite (verbatim from PATTERNS.md § Target wire type):
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApprovalDecision {
    /// Access was approved. The resource-transfer metadata is carried inline.
    Approved(ResourceGrant),
    /// Access was denied with a reason.
    Denied { reason: String },
    /// The approval request timed out without a decision.
    Timeout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SupervisorResponse {
    Decision {
        request_id: String,
        decision: ApprovalDecision,
        // grant field removed; payload now carried by Approved(ResourceGrant)
    },
    UrlOpened { /* unchanged */ },
}

impl ApprovalDecision {
    /// Returns true if access was approved (carries an inlined ResourceGrant).
    #[must_use]
    pub fn is_approved(&self) -> bool {
        matches!(self, ApprovalDecision::Approved(_))
    }

    #[must_use]
    pub fn is_denied(&self) -> bool {
        matches!(self, ApprovalDecision::Denied { .. })
    }
}
```

`ResourceGrant` payload (DO NOT change — already canonical at `types.rs:243-261`):
```rust
// Reused as-is. Plan 45-02 inlines this into Approved(ResourceGrant); no field changes.
pub struct ResourceGrant { /* existing fields */ }

impl ResourceGrant {
    pub fn sideband_file_descriptor(access: AccessMode) -> Self { /* ... */ }
    // ← Use this factory in terminal_approval.rs:84 per Cascade Map row.
}
```

Current demultiplexer at `crates/nono/src/supervisor/aipc_sdk.rs:404-433` (the `:417` defense-in-depth branch becomes unreachable):
```rust
match cap_pipe.recv_response()? {
    SupervisorResponse::Decision { request_id: resp_id, decision, grant } => {
        if resp_id != request_id { /* mismatch error — preserve */ }
        match decision {
            ApprovalDecision::Granted => grant.ok_or_else(|| {
                NonoError::SandboxInit(
                    "supervisor granted but returned no ResourceGrant".to_string(),
                )
            }),
            ApprovalDecision::Denied { reason } => Err(/* ... */),
            ApprovalDecision::Timeout => Err(/* ... */),
        }
    }
    other => Err(/* ... */),
}
```

Target demultiplexer (verbatim from PATTERNS.md § Target demultiplexer):
```rust
match cap_pipe.recv_response()? {
    SupervisorResponse::Decision { request_id: resp_id, decision } => {
        if resp_id != request_id { /* mismatch error — preserve verbatim */ }
        match decision {
            ApprovalDecision::Approved(grant) => Ok(grant),
            ApprovalDecision::Denied { reason } => Err(/* ... */),
            ApprovalDecision::Timeout => Err(/* ... */),
        }
    }
    other => Err(/* ... */),
}
```

Construction-site cascade pattern (denial path; representative — `supervisor.rs:1867-1872, 1892-1896, 1925-1929, 1981` and 18 more sites):
```rust
// Before:
return sock.send_response(&nono::supervisor::SupervisorResponse::Decision {
    request_id: request.request_id,
    decision,
    grant: None,    // ← DROP across all 22 sites
});

// After:
return sock.send_response(&nono::supervisor::SupervisorResponse::Decision {
    request_id: request.request_id,
    decision,
});
```

Approval path (representative — wherever `decision: ApprovalDecision::Granted, grant: Some(resource_grant)` appears):
```rust
// Before:
SupervisorResponse::Decision {
    request_id,
    decision: ApprovalDecision::Granted,
    grant: Some(resource_grant),
}

// After:
SupervisorResponse::Decision {
    request_id,
    decision: ApprovalDecision::Approved(resource_grant),
}
```

LOAD-BEARING redactor at `supervisor.rs:1303-1318` (DO NOT TOUCH the helper body; the call signature unchanged):
```rust
fn audit_entry_with_redacted_token(
    request: &nono::CapabilityRequest,
    decision: &nono::ApprovalDecision,
    backend_name: &str,
    started_at: Instant,
) -> AuditEntry {
    let mut redacted = request.clone();
    redacted.session_token.clear();
    AuditEntry {
        timestamp: SystemTime::now(),
        request: redacted,
        decision: decision.clone(),        // ← flows through serde unchanged
        backend: backend_name.to_string(),
        duration_ms: started_at.elapsed().as_millis() as u64,
    }
}
```

AUD-05 regression test at `crates/nono-cli/src/exec_strategy_windows/supervisor.rs:5033` (DO NOT TOUCH — preserved verbatim):
```rust
// Phase 23 Task 3 Step 6: ledger-side sanitization regression.
// Verification command (per D-45-C1 commit body callout):
//   cargo test --bin nono recorded_ledger_redacts_session_token -- --exact
#[test]
fn recorded_ledger_redacts_session_token() { /* ... unchanged ... */ }
```

Pitfall 4 — `crates/nono-cli/src/audit_integrity.rs:83-93` docstring (DO NOT EDIT — refers to `reject_stage`, NOT to the dropped `grant` field):
```rust
CapabilityDecision {
    entry: AuditEntry,
    /// Windows-AIPC-specific reject-stage marker (Phase 23 D-02).
    /// `None` for Approved decisions, for non-Windows ledger entries,
    /// and for the three pre-stage rejections...
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reject_stage: Option<RejectStage>,    // ← UNCHANGED
},
```

Pitfall 2 — `crates/nono-cli/src/audit_commands.rs:867` already pre-aligned:
```rust
// Lines 863-868 hand-rolled serde_json::Value fixture; line 867 already reads:
r#"{"sequence":3,...,"event":{...,"entry":{...,"decision":{"Approved":null},"backend":"t","duration_ms":0}}}"#,
// Edit ONLY if typed-deserialization path requires a structurally-complete ResourceGrant payload
// post-rename (planner traces read_capability_decisions_from_ledger to decide).
```

Phase 45 Cross-Target Posture (RESEARCH.md):
- Rust targets installed: `x86_64-unknown-linux-gnu`, `x86_64-apple-darwin`, `x86_64-pc-windows-msvc`.
- C cross-linkers absent: PARTIAL disposition per 3-precedent (Phase 41 + 43-01b + 44).
- Decisive close signal: GH Actions Linux Clippy + macOS Clippy lanes on Phase 45 head SHA.
</interfaces>
</context>

<tasks>

<task type="auto" tdd="false">
  <name>Task 1: Plan-open inventory grep + cascade-site verification (sequence-of-record)</name>
  <files>(read-only — no file mutations)</files>
  <read_first>
    - .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-RESEARCH.md § Plan 45-02 Cascade Map (lines 504-526 — exact line numbers + counts per file)
    - .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-CONTEXT.md § Claude's Discretion (23-test inventory + sibling-binding deferral) + § cross-phase invariants (Windows-only-files exception scope)
    - crates/nono/src/supervisor/types.rs (full read of lines 195-220, 245-275, 400-420, 470-500)
    - crates/nono/src/supervisor/aipc_sdk.rs (lines 400-440 — the demultiplexer block + the surrounding 7 construction sites at :730, :801, :967, :1033, :1078, :1141, :1212; and `grant: None` at :769, :841)
    - crates/nono-cli/src/exec_strategy_windows/supervisor.rs (lines 1300-1340 — preserve the redactor verbatim; lines 1860-1990 — the 4 `grant: None` denial-path sites; lines 5020-5085 — the AUD-05 test)
    - crates/nono-cli/src/audit_commands.rs (lines 855-875 — Pitfall 2 fixture pre-alignment)
    - crates/nono-cli/src/audit_integrity.rs (lines 75-105 — Pitfall 4 docstring distinguishability)
  </read_first>
  <action>
This task does NOT mutate source. It establishes the sequence-of-record inventory required by CONTEXT.md § Claude's Discretion before the atomic-commit task runs, and surfaces any deviation > ±2 on the "23 pre-existing tests" figure for explicit confirmation.

1. **Run the canonical inventory grep:**
   ```
   grep -rn 'ApprovalDecision::Granted\|grant: Option<ResourceGrant>\|grant: None\|grant: Some' crates/ bindings/
   ```
   Capture the full output to a scratch file (`.planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/.task1-inventory.txt` — git-ignored or deleted at task end). Count per file and compare against the Cascade Map in RESEARCH.md § Plan 45-02 Cascade Map (lines 508-520):

   Expected per RESEARCH.md:
   - `crates/nono/src/supervisor/types.rs`: 1 variant use + 1 impl use (enum def + `is_granted` impl)
   - `crates/nono/src/supervisor/aipc_sdk.rs`: 8 variant uses (1 match + 7 construction sites at :730, :801, :967, :1033, :1078, :1141, :1212) + 2 `grant: None` (:769, :841) + 7 `grant: Some` + 10 Decision-construction blocks
   - `crates/nono/src/supervisor/mod.rs`: 2 variant uses (:148, :202) + 0 grant manipulations
   - `crates/nono/src/supervisor/socket.rs`: 1 fully-qualified variant use (:572) + 2 Decision construction sites
   - `crates/nono/src/supervisor/socket_windows.rs`: 2 variant uses (:1484, :1621) + 1 `grant: None` (:1622) + 1 `grant: Some` + 4 Decision construction sites
   - `crates/nono-cli/src/exec_strategy.rs`: 1 `matches!` arm (:2862) + 3 `grant: None` sites (:2691, :2842, :2854) + 4 Decision construction sites
   - `crates/nono-cli/src/exec_strategy_windows/supervisor.rs`: 2 variant uses (:2253, :2670) + 4 `grant: None` sites (:1870, :1895, :1928, :1981) + 22 Decision construction sites
   - `crates/nono-cli/src/terminal_approval.rs`: 1 variant use (:84) — needs explicit `ResourceGrant::sideband_file_descriptor(access)` construction
   - `crates/nono-cli/src/audit_integrity.rs`: 0 direct `Granted` references (flows through serde)
   - `crates/nono-cli/src/audit_commands.rs`: 0 direct `Granted` references (only the fixture string at :867 which is pre-aligned to `"Approved"`)

   Totals to verify:
   - `ApprovalDecision::Granted` source-tree occurrences: 25 (target — RESEARCH.md § Summary)
   - `SupervisorResponse::Decision { ... }` construction sites: 42
   - `grant: None` callsites that disappear: ~10
   - `grant: Some(...)` callsites that reshape into `Approved(...)`: ~8

   If actual counts deviate from RESEARCH.md by ≤ ±2 per category: proceed silently with the updated counts. If deviation > ±2 OR new files surface that RESEARCH.md does not list: STOP and surface a deviation report to user before proceeding to Task 2.

2. **Inventory the dependent test count (CONTEXT.md "23 pre-existing tests"):**
   ```
   grep -rln 'ApprovalDecision::Granted\|grant: Option\|(Granted, grant=None)' crates/ bindings/ | xargs -I {} grep -l '#\[test\]\|#\[cfg(test)\]\|#\[tokio::test\]' {}
   ```
   For each test file, count the `#[test]` (or `#[tokio::test]`) functions that reference `Granted` or the `(Granted, None)` shape. Record the per-file count. CONTEXT.md allows ±2 deviation; if delta > 2, surface as deviation for explicit user confirmation before Task 2 starts the atomic rewrite.

3. **Sibling-repo cascade check (CONTEXT.md § Deferred Ideas — Plan-open verification only):**
   Check whether `../nono-py/` and `../nono-ts/` are present at the working-tree-parent level. If either exists:
   ```
   grep -rln 'ApprovalDecision\|approval_decision\|"Granted"\|"Approved"' ../nono-py/src/ ../nono-py/python/ ../nono-ts/src/ 2>/dev/null
   ```
   If matches surface (either repo has code that JSON-deserializes the wire shape), surface as deviation per CONTEXT.md § Deferred Ideas — invoke the Phase 44 D-44-D1 cross-binding lockstep precedent. If both repos absent OR neither contains matches, record "no sibling cascade" in the inventory and proceed.

4. **Pitfall checks (read-only confirmations):**
   - Pitfall 2: `grep -n '"Approved":null' crates/nono-cli/src/audit_commands.rs` returns at least line 867 — confirms fixture pre-alignment. Pre-Task-2 ACTION: trace `read_capability_decisions_from_ledger` (in `crates/nono-cli/src/audit_commands.rs`) deserialization path. If the path uses `serde_json::from_str::<AuditEntry>` (typed deserialization) on the fixture, the line WILL need a structurally-complete `ResourceGrant` payload post-Plan-45-02 because tuple-variant `Approved(...)` with `null` payload fails type-checked deserialization. If the path uses `serde_json::Value` and matches structurally on "Approved" string presence only, the fixture is OK as-is. Record the verdict in the inventory.
   - Pitfall 3: `grep -n 'fn audit_entry_with_redacted_token' crates/nono-cli/src/exec_strategy_windows/supervisor.rs` returns line ~1303 — confirms redactor location. Pre-Task-2 ACTION: this function MUST NOT be edited by Task 2; signature `(&CapabilityRequest, &ApprovalDecision, &str, Instant) -> AuditEntry` and body unchanged.
   - Pitfall 4: `grep -n 'reject_stage' crates/nono-cli/src/audit_integrity.rs | head -5` returns docstring + field. Pre-Task-2 ACTION: the docstring at `:83-93` referring to "`None` for Approved decisions" refers to `reject_stage`, NOT to `grant`. MUST NOT be edited by Task 2.

5. **Record the verified inventory** as a short note appended to PLAN-EXECUTION-LOG.md (or scratch context — Task 2 reads it). Required fields: per-file `Granted` count, per-file `Decision { ... }` count, test-file inventory + per-test-file count, Pitfall 2 fixture verdict (edit needed yes/no), sibling-repo cascade verdict (lockstep needed yes/no).
  </action>
  <verify>
    <automated>(cd C:/Users/OMack/Nono && grep -rcn 'ApprovalDecision::Granted' crates/ bindings/) && (cd C:/Users/OMack/Nono && grep -rcn 'grant: Option<ResourceGrant>' crates/ bindings/) && (cd C:/Users/OMack/Nono && grep -n '"Approved":null' crates/nono-cli/src/audit_commands.rs) && (cd C:/Users/OMack/Nono && grep -n 'fn audit_entry_with_redacted_token' crates/nono-cli/src/exec_strategy_windows/supervisor.rs)</automated>
  </verify>
  <acceptance_criteria>
    - **Inventory matches RESEARCH.md ±2 per category** (maps to VALIDATION row REQ-AIPC-G04-01 inventory pre-check):
      - `grep -rc 'ApprovalDecision::Granted' crates/ bindings/ | awk -F: '{s+=$2} END {print s}'` ≥ 17 AND ≤ 28 (empirically verified baseline: 18 construction/match sites at plan-open per checker B1; RESEARCH.md historical figure 25 includes the bare variant declaration at types.rs:203 + matches! arm at types.rs:409 + comments — those are NOT in scope for the test-file rewrite inventory which keys off construction sites and match arms)
      - `grep -rc 'grant: Option<ResourceGrant>' crates/ bindings/ | awk -F: '{s+=$2} END {print s}'` = 1 (only the definition at types.rs)
      - `grep -rc 'grant: None' crates/ bindings/ | awk -F: '{s+=$2} END {print s}'` ≥ 8 AND ≤ 12 (RESEARCH.md target: ~10)
    - **Pitfall confirmations:**
      - `grep -n '"decision":{"Approved":null}' crates/nono-cli/src/audit_commands.rs` returns line 867 (fixture pre-alignment confirmed — Pitfall 2)
      - `grep -n 'fn audit_entry_with_redacted_token' crates/nono-cli/src/exec_strategy_windows/supervisor.rs` returns one line in range 1300-1320 (redactor verbatim-preserve target — Pitfall 3)
      - `grep -c 'reject_stage' crates/nono-cli/src/audit_integrity.rs` ≥ 2 (field + docstring; Pitfall 4 distinct from `grant` field — DO NOT edit)
    - **Test inventory recorded:** scratch inventory note exists with per-test-file count; total within 23±2 of RESEARCH.md guidance (if > 25, deviation surfaced explicitly).
    - **Sibling-repo cascade verdict recorded:** explicit "no sibling cascade" or "lockstep needed per D-44-D1" entry in inventory.
    - **No mutations:** `git status --porcelain` returns empty (Task 1 is read-only).
  </acceptance_criteria>
  <done>
    Inventory grep run; per-file + per-test-file counts match RESEARCH.md within ±2 OR deviation explicitly surfaced; Pitfall 2/3/4 confirmations recorded; sibling-repo cascade verdict recorded; no source mutations from this task.
  </done>
</task>

<task type="auto" tdd="false">
  <name>Task 2: Single atomic feat(45-02) commit — wire-type rename + ResourceGrant inlining + full consumer cascade + tests + CHANGELOG + ADR amendment + AUD-05 pass verification</name>
  <files>crates/nono/src/supervisor/types.rs, crates/nono/src/supervisor/aipc_sdk.rs, crates/nono/src/supervisor/mod.rs, crates/nono/src/supervisor/socket.rs, crates/nono/src/supervisor/socket_windows.rs, crates/nono-cli/src/exec_strategy.rs, crates/nono-cli/src/exec_strategy_windows/supervisor.rs, crates/nono-cli/src/terminal_approval.rs, crates/nono-cli/src/audit_integrity.rs, crates/nono-cli/src/audit_commands.rs, CHANGELOG.md, docs/architecture/audit-bundle-target.md, (23±2 test files as inventoried by Task 1)</files>
  <read_first>
    - .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-PATTERNS.md § Plan 45-02 (full section, especially the Single-commit cascade order at lines 490-503 and Analog 1-8 code blocks)
    - .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-CONTEXT.md § D-45-C1 + D-45-C2 + D-45-C3 (decisions)
    - .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-RESEARCH.md § Pitfall 1-5 + § Plan 45-02 Cascade Map
    - Task 1 inventory note (per-file counts + sibling-repo verdict + Pitfall 2 fixture verdict)
    - crates/nono/src/supervisor/types.rs:198-211 + :243-261 + :405-417 + :474-495 (the rename targets + ResourceGrant payload + impl helpers)
    - crates/nono/src/supervisor/aipc_sdk.rs:400-440 (demultiplexer block)
    - crates/nono-cli/src/exec_strategy_windows/supervisor.rs:1300-1340 (redactor verbatim preserve), :1860-1990 (4 denial-path construction sites + Phase 18.1-02 dispatcher pair-binding), :5020-5085 (AUD-05 test verbatim preserve)
    - crates/nono-cli/src/terminal_approval.rs:80-95 (the approval-path site needing explicit ResourceGrant construction)
    - CHANGELOG.md (existing structure — extract heading conventions)
    - docs/architecture/audit-bundle-target.md (existing structure — extract ADR amendment heading conventions, especially v2.5-FU-1 / v2.5-FU-2 if present)
  </read_first>
  <action>
**Land ALL of the following in ONE atomic commit (D-45-C1).** Sub-steps run in this order; commit ONLY after every sub-step passes a local `cargo check`. Do NOT split into multiple commits — a partial migration breaks the build by design and that IS the SC#2 compile-time guarantee.

**Sub-step A — Wire-type definitions in `crates/nono/src/supervisor/types.rs`:**

1. At `:198-211`, replace the `ApprovalDecision` enum:
   ```rust
   #[derive(Debug, Clone, Serialize, Deserialize)]
   pub enum ApprovalDecision {
       /// Access was approved. The resource-transfer metadata is carried inline.
       Approved(ResourceGrant),
       /// Access was denied with a reason.
       Denied {
           /// Why the request was denied
           reason: String,
       },
       /// The approval request timed out without a decision.
       Timeout,
   }
   ```

2. At `:474-495` (the `SupervisorResponse::Decision` variant), drop the `grant: Option<ResourceGrant>` field (line :484). Final shape:
   ```rust
   #[derive(Debug, Clone, Serialize, Deserialize)]
   pub enum SupervisorResponse {
       Decision {
           request_id: String,
           decision: ApprovalDecision,
           // grant field removed; payload now carried by Approved(ResourceGrant)
       },
       UrlOpened { /* unchanged */ },
       // ... other unchanged variants ...
   }
   ```

3. At `:405-417` (the `impl ApprovalDecision`), rename `is_granted()` → `is_approved()` and update the body. Keep `is_denied()` unchanged. Both methods MUST carry `#[must_use]` per CLAUDE.md § Coding Standards (Pattern S2):
   ```rust
   impl ApprovalDecision {
       /// Returns true if access was approved (carries an inlined ResourceGrant).
       #[must_use]
       pub fn is_approved(&self) -> bool {
           matches!(self, ApprovalDecision::Approved(_))
       }

       /// Returns true if access was denied.
       #[must_use]
       pub fn is_denied(&self) -> bool {
           matches!(self, ApprovalDecision::Denied { .. })
       }
   }
   ```

**Sub-step B — Demultiplexer rewrite in `crates/nono/src/supervisor/aipc_sdk.rs`:**

1. At `:404-433`, replace the demultiplexer match block. The new shape removes the `grant` field destructuring AND the `ok_or_else(...)` defense-in-depth branch (because `Approved(grant) => Ok(grant)` is now total — this elimination IS the SC#2 deliverable):
   ```rust
   match cap_pipe.recv_response()? {
       SupervisorResponse::Decision {
           request_id: resp_id,
           decision,
       } => {
           if resp_id != request_id {
               return Err(NonoError::SandboxInit(format!(
                   "supervisor response request_id mismatch: expected {request_id}, got {resp_id}"
               )));
           }
           match decision {
               ApprovalDecision::Approved(grant) => Ok(grant),
               ApprovalDecision::Denied { reason } => Err(NonoError::SandboxInit(format!(
                   "supervisor denied capability: {reason}"
               ))),
               ApprovalDecision::Timeout => Err(NonoError::SandboxInit(
                   "supervisor approval timed out".to_string(),
               )),
           }
       }
       other => Err(NonoError::SandboxInit(format!(
           "expected Decision response, got {other:?}"
       ))),
   }
   ```

2. Update the 7 construction sites at `:730, :801, :967, :1033, :1078, :1141, :1212`:
   - Approval path: `decision: ApprovalDecision::Granted, grant: Some(rg)` → `decision: ApprovalDecision::Approved(rg)`
   - Denial path: drop the `grant: None` / `grant: <value>` field entirely; the `SupervisorResponse::Decision` envelope no longer has the field.

3. Remove the 2 standalone `grant: None,` lines at `:769, :841` (denial-path construction blocks).

**Sub-step C — Cross-platform consumer cascade:**

1. `crates/nono/src/supervisor/mod.rs` at `:148, :202`: rename `ApprovalDecision::Granted` → `ApprovalDecision::Approved(...)`; supply an appropriate `ResourceGrant` payload where the original constructed a granted decision. If `:148` is a re-export only, no value-construction needed — verify by reading the line and adjacent context first.

2. `crates/nono/src/supervisor/socket.rs:572`: fully-qualified site `crate::supervisor::types::ApprovalDecision::Granted` → `crate::supervisor::types::ApprovalDecision::Approved(<grant>)`. Update the 2 surrounding `SupervisorResponse::Decision { ... }` blocks to drop the `grant:` field.

3. `crates/nono/src/supervisor/socket_windows.rs` at `:1484, :1621, :1622`: rename + drop `grant:` field across 4 Decision construction sites. Per CONTEXT.md cross-phase invariants, this Windows-only file touch is a wire-type cascade (NOT new Windows-only code) and is permitted.

4. `crates/nono-cli/src/exec_strategy.rs` at `:2691, :2842, :2854` (3 `grant: None` sites — drop the field) + `:2862` (`matches!(decision, ApprovalDecision::Granted)` → `matches!(decision, ApprovalDecision::Approved(_))`) + 4 Decision construction sites (drop `grant:` field).

5. `crates/nono-cli/src/exec_strategy_windows/supervisor.rs` — the largest cascade surface (22 Decision construction sites):
   - At `:1300-1340`: **DO NOT TOUCH** `audit_entry_with_redacted_token` (Pitfall 3 — load-bearing scrub preserved verbatim).
   - At `:1860-1990` (the Phase 18.1-02 G-04 dispatcher pair-binding pattern `let (decision, grant) = if ... { ... }`): **leave the pair-binding INTACT as defense in depth** per Open Question #2 recommendation in RESEARCH.md. The pair-binding is now redundant at type level but a free runtime check. Add a comment immediately above the `let (decision, grant) = if ...` line:
     ```rust
     // Phase 45 Plan 45-02 elevated the (Approved, grant Some) invariant to type level;
     // this dispatcher fold is now defense in depth, not load-bearing.
     ```
     Then update each arm: the `grant` half of the pair becomes vestigial. Inside each arm, when constructing `ApprovalDecision::Granted`, change to `ApprovalDecision::Approved(grant_value)` and drop the standalone `grant: Some(...)` / `grant: None` line from the subsequent `SupervisorResponse::Decision { ... }` block. If preserving the pair-binding causes a build error (the inner `grant` becomes unused), bind it as `_grant` to silence the unused-variable lint WITHOUT introducing `#[allow(dead_code)]`.
   - At `:2253, :2670` (variant uses outside the dispatcher): rename to `Approved(...)`.
   - At all 22 `SupervisorResponse::Decision { ... grant: ... }` construction sites: drop the `grant:` field. The `decision:` field carries the payload.
   - At `:5020-5085` (AUD-05 regression test `recorded_ledger_redacts_session_token`): **DO NOT TOUCH** the test body. The test asserts `!ledger.contains(sensitive_token)` and the renamed wire shape flows through serde transparently.

6. `crates/nono-cli/src/terminal_approval.rs:84` — RESOLVED literal (B4 pre-resolution, executor MUST use this exact form):

   <rationale>
   The function `request_capability` at `terminal_approval.rs:27-91` receives `request: &CapabilityRequest` (line 28). `CapabilityRequest` at `crates/nono/src/supervisor/types.rs:153-168` has a public `access: AccessMode` field at `:166`. Therefore `request.access` IS in scope at line :84. The appropriate factory is `ResourceGrant::sideband_file_descriptor(access: AccessMode) -> Self` at `types.rs:263-275` — terminal approval gates filesystem access requests (the request's path/access pair is the `HandleTarget::FilePath` case), which is exactly the sideband-FD transfer kind.
   </rationale>

   Edit (literal substitution at `:84`):
   ```rust
   // Before:
   Ok(ApprovalDecision::Granted)

   // After:
   Ok(ApprovalDecision::Approved(ResourceGrant::sideband_file_descriptor(request.access)))
   ```

   Required ancillary edit (import line `:9`): add `ResourceGrant` to the `use nono::{...}` import block. The current line :9 reads:
   ```rust
   use nono::{AccessMode, ApprovalBackend, ApprovalDecision, CapabilityRequest, NonoError, Result};
   ```
   becomes:
   ```rust
   use nono::{AccessMode, ApprovalBackend, ApprovalDecision, CapabilityRequest, NonoError, ResourceGrant, Result};
   ```

   D-45-C1 atomic-commit contract is honored: NO fallback deferral path, NO "surface as deviation" — the literal is pre-resolved here. If during execution the executor finds that the codebase has drifted (e.g., `CapabilityRequest::access` was renamed) the executor MUST stop and surface to the user as a real deviation (drift from this plan's verified pre-resolution), NOT silently substitute.

**Sub-step D — Audit-recorder consumers (transparent through serde — verify only):**

1. `crates/nono-cli/src/audit_integrity.rs`: zero direct `Granted` references; the wire shape flows through `AuditEntry::decision` via serde derive on the renamed enum. Verify no edits needed (Task 1 inventory confirms this). Pitfall 4: docstring at `:83-93` referring to `reject_stage` is UNCHANGED.

2. `crates/nono-cli/src/audit_commands.rs:867`: fixture line per Task 1 verdict. If Task 1's typed-deserialization trace says "fixture OK as-is" (the path uses `serde_json::Value`), make NO edits to line 867 itself; optionally touch up the surrounding comment to remove "workaround" framing if any such comment exists. If Task 1's trace says "typed deserialization requires structurally-complete ResourceGrant payload", update line 867 to a structurally-complete fixture: replace `"decision":{"Approved":null}` with `"decision":{"Approved":{<full ResourceGrant JSON>}}`. The exact ResourceGrant JSON depends on the struct definition at `types.rs:243-261`; planner constructs a minimal valid instance.

**Sub-step E — Dependent tests (23±2 per Task 1 inventory):**

For each test file flagged by Task 1's inventory:
1. Read the file (or the specific test function).
2. Replace every `ApprovalDecision::Granted` → `ApprovalDecision::Approved(<grant>)` with an appropriate `ResourceGrant` value (use the existing test helper or `ResourceGrant::sideband_file_descriptor(access)` factory; preserve original test intent).
3. Replace every `(Granted, grant=None)` pattern destructure or pattern match → `Approved(_)` (or `Approved(grant)` if `grant` is needed in the test body).
4. Drop every `grant: None` / `grant: Some(...)` field from `SupervisorResponse::Decision { ... }` literals in tests.
5. Replace every `decision.is_granted()` call → `decision.is_approved()`.
6. If any test depended on the `ok_or_else("supervisor granted but returned no ResourceGrant")` error path being reachable (RESEARCH.md flags `aipc_sdk.rs:417` as the structurally-unreachable branch), that test must be DELETED or REPLACED with a compile-time-property test (e.g., a `compile_fail` doc test asserting the new shape rejects `Approved` without a grant). Document the deletion/replacement in the commit body.

**Sub-step F — CHANGELOG.md entry (D-45-C2):**

Append a BREAKING entry under a v2.6 / Phase 45 marker (planner picks heading level — typical pattern: `## [Unreleased]` → `### Breaking` subsection or a new `## v2.6 (Phase 45)` section). Required content:
- BREAKING marker prominently visible (e.g., `**BREAKING:** Audit wire format change`).
- Wire shape before/after: `{"decision":{"Granted":null},"grant":{...}}` → `{"decision":{"Approved":{...ResourceGrant...}}}` (or accurate serde-derived JSON forms).
- Fresh-session vs replay distinction: "Sessions started under v2.6+ produce the new wire shape; pre-v2.6 `audit-events.ndjson` ledgers cannot be re-verified by `nono audit verify` after upgrade."
- ADR back-reference: pointer to `docs/architecture/audit-bundle-target.md` § amendment 45-X.
- Mitigation guidance: "Users with pre-v2.6 ledgers needing re-verification can pin to v2.5 binary; no `nono audit migrate` subcommand is provided (rejected at CONTEXT.md D-45-C2)."

**Sub-step G — ADR amendment in `docs/architecture/audit-bundle-target.md` (D-45-C2):**

Append a new dated subsection (planner picks heading — typical: `### 45-A (2026-05-21): Approved(ResourceGrant) wire-type inlining`). Required content:
- Date + Phase 45 Plan 45-02 reference.
- Decision: inline `ResourceGrant` into `ApprovalDecision::Approved` at the wire type.
- Rationale: elevates the Phase 18.1-02 G-04 invariant (`Approved ⟹ grant Some`) from runtime to type level; eliminates dispatcher-bypass spoofing class per RESEARCH.md § Security Domain.
- Consequences: BREAKING wire-format change for pre-v2.6 ledgers; CHANGELOG entry pointer.
- Cross-references: Phase 18.1-02 SUMMARY, Phase 23 D-01, Phase 27.2 audit-attestation closure, AUD-05 token-redaction regression at `supervisor.rs:5033`.

**Sub-step H — Compile gates + AUD-05 verification (must pass before committing):**

1. `cargo check --workspace --all-features` exits 0.
2. `cargo build --workspace --all-features` exits 0.
3. `cargo test --workspace --all-features` exits 0 (full suite green; expected ≥ 2197 passes per Phase 43-01b baseline).
4. **AUD-05 targeted verification (D-45-C1 commit-body callout):**
   ```
   cargo test --bin nono recorded_ledger_redacts_session_token -- --exact
   ```
   MUST exit 0. Manually spot-check the on-disk ledger NDJSON (under the test's tempdir if printed via `--nocapture`) to confirm the new wire shape contains a properly-formed `Approved({...ResourceGrant...})` payload AND the session token is still scrubbed (Pitfall 3 dual-assertion check).

5. **Compile-time error verification (SC#2 gate):**
   - `grep -rn 'ApprovalDecision::Granted' crates/ bindings/` returns 0 results.
   - `grep -rn 'grant: Option<ResourceGrant>' crates/ bindings/` returns 0 results.
   - `grep -rn 'grant: None' crates/ bindings/` returns 0 results.
   - `grep -rn 'supervisor granted but returned no ResourceGrant' crates/` returns 0 results (the structurally-unreachable branch is gone).

**Sub-step I — Stage + single atomic commit:**

Stage every modified file (the 10 source files + CHANGELOG.md + audit-bundle-target.md + the 23±2 test files):
```
git add crates/nono/src/supervisor/types.rs \
        crates/nono/src/supervisor/aipc_sdk.rs \
        crates/nono/src/supervisor/mod.rs \
        crates/nono/src/supervisor/socket.rs \
        crates/nono/src/supervisor/socket_windows.rs \
        crates/nono-cli/src/exec_strategy.rs \
        crates/nono-cli/src/exec_strategy_windows/supervisor.rs \
        crates/nono-cli/src/terminal_approval.rs \
        crates/nono-cli/src/audit_integrity.rs \
        crates/nono-cli/src/audit_commands.rs \
        CHANGELOG.md \
        docs/architecture/audit-bundle-target.md \
        <23±2 test files per Task 1 inventory>
```

Verify nothing else is staged: `git status --short` shows only the expected files; `git diff --cached --stat` matches the cascade map.

Commit with this message body:
```
feat(45-02): inline ApprovalDecision::Approved(ResourceGrant) — type-level (Approved ⟹ grant Some) invariant

Closes the AIPC G-04 deferral from v2.1 Plan 18.1-02 (reaffirmed at v2.3, v2.4,
v2.5 scope-locks). Renames `ApprovalDecision::Granted` to `Approved(ResourceGrant)`,
inlining the resource-transfer payload at the wire type; drops the redundant
`grant: Option<ResourceGrant>` field from `SupervisorResponse::Decision`. Cascades
through the demultiplexer (aipc_sdk.rs:404-433), 22 Decision construction sites
in exec_strategy_windows/supervisor.rs, all cross-platform + Unix consumers, and
every dependent test.

SC#2 compile-time guarantee: `(Approved, grant=None)` is now structurally
unrepresentable. The aipc_sdk.rs:417 `ok_or_else("supervisor granted but
returned no ResourceGrant")` defense-in-depth branch is gone — its absence IS
the deliverable. The Phase 18.1-02 dispatcher pair-binding at supervisor.rs:1875-1950
is preserved as defense in depth (no longer load-bearing).

BREAKING (D-45-C2): pre-v2.6 audit-events.ndjson ledgers with the old
`{"decision":{"Granted":null},"grant":{...}}` shape cannot be re-verified by
`nono audit verify` after upgrade. CHANGELOG.md updated; ADR amendment 45-X
appended to docs/architecture/audit-bundle-target.md. No migration tool
provided (rejected at D-45-C2). Audit-attestation is session-fresh by design
(Phase 27.2 ADR); fresh sessions produce the new wire shape and AUD-02 Merkle
integrity remains valid.

AUD-05 regression (`recorded_ledger_redacts_session_token` at
crates/nono-cli/src/exec_strategy_windows/supervisor.rs:5033): verified-pass
via `cargo test --bin nono recorded_ledger_redacts_session_token -- --exact`.
The load-bearing scrub `audit_entry_with_redacted_token` at
supervisor.rs:1303-1318 is preserved verbatim; serde derive flows the renamed
enum transparently through the AuditEntry persisting path; on-disk ledger spot-
check confirms session token never appears in the NDJSON.

Windows-only-files invariant (D-34-E1 / D-40-E1 / D-43-E1): the 22-site cascade
in exec_strategy_windows/supervisor.rs is a wire-type cascade unavoidable from
the cross-platform rename; per CONTEXT.md § cross-phase invariants this is
permitted as "wire-type cascade, NOT new Windows-only code." No codified
addendum exception required.

Test inventory: <N> pre-existing tests across <M> files updated to the new
shape (Task 1 inventory recorded in 45-02-SUMMARY.md § Test Inventory).

Closes: REQ-AIPC-G04-01

Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```

After `git commit`, run `git log --pretty=format:'%b' -1 | grep -c '^Signed-off-by: oscarmackjr-twg'` and confirm it returns 1.
  </action>
  <verify>
    <automated>(cd C:/Users/OMack/Nono && cargo build --workspace --all-features) && (cd C:/Users/OMack/Nono && cargo test --workspace --all-features) && (cd C:/Users/OMack/Nono && cargo test --bin nono recorded_ledger_redacts_session_token -- --exact) && (cd C:/Users/OMack/Nono && grep -rn 'ApprovalDecision::Granted' crates/ bindings/) ; (cd C:/Users/OMack/Nono && grep -rn 'grant: Option<ResourceGrant>' crates/ bindings/) ; (cd C:/Users/OMack/Nono && grep -rn 'supervisor granted but returned no ResourceGrant' crates/)</automated>
  </verify>
  <acceptance_criteria>
    - **Wire-type inlined (maps to VALIDATION row REQ-AIPC-G04-01 "Approved(ResourceGrant) inlined; (Approved, grant=None) is compile-time error"):**
      - `grep -rn 'ApprovalDecision::Granted' crates/ bindings/` returns 0 results
      - `grep -rn 'grant: Option<ResourceGrant>' crates/ bindings/` returns 0 results
      - `grep -rn 'grant: None' crates/ bindings/` returns 0 results
      - `grep -c 'Approved(ResourceGrant)' crates/nono/src/supervisor/types.rs` ≥ 1
    - **Demultiplexer branch removed (maps to VALIDATION row "aipc_sdk.rs:417 `ok_or_else` defense-in-depth branch removed"):** `grep -rn 'supervisor granted but returned no ResourceGrant' crates/` returns 0 results.
    - **Build + full test suite green (maps to VALIDATION row "All 23+ pre-existing tests updated; full workspace green"):** `cargo build --workspace --all-features` exits 0 AND `cargo test --workspace --all-features` exits 0 AND total passing ≥ 2197 (Phase 43-01b baseline).
    - **AUD-05 regression verified (maps to VALIDATION row "AUD-05 token-redaction regression `recorded_ledger_redacts_session_token` passes"):** `cargo test --bin nono recorded_ledger_redacts_session_token -- --exact` exits 0.
    - **Helper rename + #[must_use] preserved:**
      - `grep -c 'fn is_approved' crates/nono/src/supervisor/types.rs` = 1
      - `grep -c 'fn is_granted' crates/nono/src/supervisor/types.rs` = 0
      - `grep -B 1 'fn is_approved' crates/nono/src/supervisor/types.rs | grep -c '#\[must_use\]'` = 1
    - **Pitfalls observed (verbatim preserves):**
      - `grep -c 'fn audit_entry_with_redacted_token' crates/nono-cli/src/exec_strategy_windows/supervisor.rs` = 1 (Pitfall 3 — redactor preserved)
      - `git diff main..HEAD -- crates/nono-cli/src/exec_strategy_windows/supervisor.rs | grep -c '^- fn audit_entry_with_redacted_token\|^- redacted.session_token.clear'` = 0 (redactor body NOT touched)
      - `git diff main..HEAD -- crates/nono-cli/src/exec_strategy_windows/supervisor.rs | grep -c '^- fn recorded_ledger_redacts_session_token'` = 0 (AUD-05 test body NOT touched)
      - `grep -c 'reject_stage' crates/nono-cli/src/audit_integrity.rs` ≥ 2 (Pitfall 4 — docstring + field unchanged)
    - **Per-test-file post-edit gate (B2 fix — Sub-step E inventory loop):** For each test file recorded in Task 1's inventory, ALL three of these must hold post-Sub-step-E:
      - `grep -c 'ApprovalDecision::Granted' <test_file>` = 0 (no surviving Granted occurrences)
      - `grep -cE 'grant: None|grant: Some' <test_file>` = 0 (no surviving grant-field occurrences in test-literal `SupervisorResponse::Decision { ... }` blocks)
      - `<test_file>` still appears in `cargo test --workspace --all-features --list` output (test was edited, NOT accidentally deleted — unless explicitly justified per Sub-step E item 6's compile_fail replacement, in which case the commit body documents the deletion)
    - **Cross-target pre-commit cargo check (B2 fix — Linux/macOS-gated test syntax surfacing on Windows host):** Before staging the atomic commit, BOTH of these must exit 0:
      - `cargo check --workspace --all-features --target x86_64-unknown-linux-gnu` exits 0 (Rust target installed per RESEARCH.md § Phase 45 Cross-Target Posture; `cargo check` does NOT require the C cross-linker — it only runs the typechecker, surfacing Linux-cfg-gated test syntax errors pre-commit)
      - `cargo check --workspace --all-features --target x86_64-apple-darwin` exits 0 (same — Rust target installed; cargo check works without Darwin SDK; surfaces macOS-cfg-gated test syntax errors)
      - Note: clippy STILL requires the C linker and remains PARTIAL per `.planning/templates/cross-target-verify-checklist.md` PARTIAL disposition; cargo check is NOT a clippy substitute (Anti-pattern 3) — it is a tighter typecheck-only gate that pre-empts the most common Linux/macOS-gated build break (test file uses cfg-gated import unavailable on Windows). If either `cargo check --target` errors, STOP and fix before atomic-commit.
    - **CHANGELOG + ADR (B3 fix — per-element D-45-C2 gate, tightened from soft greps):**
      - **CHANGELOG.md** must contain ALL FIVE D-45-C2 elements:
        - (a) Old wire shape literal: `grep -cE 'Granted.*null|Granted\{\}' CHANGELOG.md` ≥ 1
        - (b) New wire shape literal: `grep -cE 'Approved.*ResourceGrant|Approved\(ResourceGrant\)' CHANGELOG.md` ≥ 1
        - (c) Fresh-session vs replay distinction: `grep -ciE 'fresh session|session-fresh|re-verify' CHANGELOG.md` ≥ 1
        - (d) v2.5-binary-pin mitigation: `grep -c 'v2.5' CHANGELOG.md` ≥ 1 AND `grep -ciE 'binary|pin' CHANGELOG.md` ≥ 1
        - (e) ADR back-reference: `grep -c 'audit-bundle-target' CHANGELOG.md` ≥ 1
      - **docs/architecture/audit-bundle-target.md** ADR amendment must contain ALL THREE elements:
        - (a) New wire-type literal: `grep -c 'Approved(ResourceGrant)' docs/architecture/audit-bundle-target.md` ≥ 1
        - (b) Phase 45 / Plan 45-02 attribution: `grep -cE 'Phase 45|45-02' docs/architecture/audit-bundle-target.md` ≥ 1
        - (c) BREAKING marker: `grep -ciE 'breaking|wire-format break' docs/architecture/audit-bundle-target.md` ≥ 1
      - **Diff-anchored guards (carry-forward):** `grep -ci 'BREAKING' CHANGELOG.md` ≥ 1 AND `git diff main..HEAD -- docs/architecture/audit-bundle-target.md | grep -cE '^\+.*45-(A|02|X)'` ≥ 1.
    - **Single atomic commit (D-45-C1):** `git log --pretty=format:'%s' main..HEAD -- crates/nono/src/supervisor/types.rs | wc -l` = 1 (the wire-type file was touched exactly once on this branch by this task; combined with Plan 45-01's untouched range this is the single Plan 45-02 commit).
    - **DCO sign-off:** `git log --pretty=format:'%b' -1 | grep -c '^Signed-off-by: oscarmackjr-twg'` = 1.
    - **Commit subject shape:** `git log --pretty=format:'%s' -1` returns exactly: `feat(45-02): inline ApprovalDecision::Approved(ResourceGrant) — type-level (Approved ⟹ grant Some) invariant`
    - **No silenced lints:** `git diff main..HEAD -- crates/ | grep -c '#\[allow(clippy::unwrap_used)\]\|#\[allow(dead_code)\]'` = 0.
    - **Windows-only-files invariant (per CONTEXT.md cross-phase invariants):** `git diff --stat main..HEAD -- 'crates/nono-shell-broker/**' 'crates/nono-cli/src/exec_strategy_windows/' | grep -v 'supervisor.rs'` is empty (only the supervisor.rs cascade — documented as wire-type cascade in commit body — touches Windows-only path).
  </acceptance_criteria>
  <done>
    Single atomic `feat(45-02):` commit landed. Wire type at `crates/nono/src/supervisor/types.rs` has `ApprovalDecision::Approved(ResourceGrant)` + `SupervisorResponse::Decision` without `grant:` field + `is_approved()` `#[must_use]` helper. Demultiplexer rewritten; structurally-unreachable `ok_or_else` branch removed. All 22 Windows-supervisor sites + cross-platform + Unix consumers cascaded. AUD-05 token-redaction regression passes via `cargo test --bin nono recorded_ledger_redacts_session_token -- --exact`. CHANGELOG.md has BREAKING entry; `docs/architecture/audit-bundle-target.md` has ADR amendment 45-X. Full workspace test suite green (≥ 2197 passes). Pitfall 3 redactor + Pitfall 4 docstring + AUD-05 test body all verbatim preserved. Single DCO-signed commit; no `#[allow(...)]` introductions.
  </done>
</task>

<task type="auto" tdd="false">
  <name>Task 3: Cross-target clippy verification + 45-02-CLIPPY-CROSS-TARGET.md artifact (plan-close gate)</name>
  <files>.planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-02-CLIPPY-CROSS-TARGET.md</files>
  <read_first>
    - .planning/templates/cross-target-verify-checklist.md (full file — PARTIAL Disposition + Anti-patterns + Enforcement)
    - .planning/phases/44-review-polish-test-hygiene-drain/44-01-CLIPPY-CROSS-TARGET.md (layout precedent)
    - .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-RESEARCH.md § Phase 45 Cross-Target Posture (decisive disposition for Plan 45-02 specifically — RESEARCH.md lines 530-541)
    - .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-01-CLIPPY-CROSS-TARGET.md (mirror layout — Plan 45-01 should land this on same Phase 45 head SHA)
  </read_first>
  <action>
This task produces the close-gate artifact for cross-target clippy verification scoped to Plan 45-02's surface (Windows + Unix cfg-gated files). Same PARTIAL protocol as Plan 45-01 Task 2 Sub-step B, but the file scope is different (Plan 45-02 touches cross-platform `crates/nono/src/supervisor/` AND Windows-cfg-gated `exec_strategy_windows/supervisor.rs` AND cross-platform Unix-relevant consumers in `crates/nono-cli/src/exec_strategy.rs` and `terminal_approval.rs`).

1. Run Windows-host clippy first:
   ```
   cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used
   ```
   MUST exit 0. Capture full output.

2. Attempt cross-target Linux clippy:
   ```
   cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used
   ```
   Per RESEARCH.md § Phase 45 Cross-Target Posture: expected toolchain-missing failure (Rust target installed, C cross-linker absent). Capture exit code + stderr.

3. Attempt cross-target macOS clippy:
   ```
   cargo clippy --workspace --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used
   ```
   Expected: same toolchain-missing failure. Capture exit code + stderr.

4. Author `.planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-02-CLIPPY-CROSS-TARGET.md` mirroring the Phase 44 + Plan 45-01 layout. Required sections:
   - **YAML frontmatter:** `phase: 45`, `plan: 02`, `req: REQ-AIPC-G04-01`, `disposition: PARTIAL`, `created: <today>`, `verifier: oscarmackjr-twg`.
   - **§ Scope** — explicit statement that Plan 45-02 touched `crates/nono/src/supervisor/{types,aipc_sdk,mod,socket,socket_windows}.rs` (cross-platform + Unix + Windows cfg-gated), `crates/nono-cli/src/exec_strategy_windows/supervisor.rs` (Windows-only — wire-type cascade per CONTEXT.md cross-phase invariants), `crates/nono-cli/src/{exec_strategy,terminal_approval,audit_integrity,audit_commands}.rs` (cross-platform Unix-relevant). Cite cross-target-verify-checklist.md § Scope.
   - **§ Decision Tree Walkthrough** — Q1: touches in-scope files YES (Unix-cfg-gated + Windows-cfg-gated + cross-platform); Q2: Linux cross-target clippy: toolchain-missing (capture EXACT stderr); Q3: macOS: toolchain-missing.
   - **§ Local Evidence** — Windows-host clippy command + exit-0 confirmation; captured stderr from cross-target attempts; explicit acknowledgement that `cargo check` was NOT substituted (Anti-pattern 3 confirmation).
   - **§ Codebase Evidence** — VERBATIM prose from cross-target-verify-checklist.md § PARTIAL Disposition step 4:
     > Cross-target clippy gate SKIPPED on Windows dev host due to missing toolchain (x86_64-unknown-linux-gnu C linker; Darwin SDK absent). The live GH Actions Linux Clippy and macOS Clippy lanes on the Phase 45 head SHA are the decisive signal per .planning/templates/cross-target-verify-checklist.md. REQ-AIPC-G04-01 marked PARTIAL pending CI confirmation.
   - **§ Anti-pattern audit** — explicit verification statements:
     - Anti-pattern 1: REQ-AIPC-G04-01 NOT flipped to VERIFIED locally; remains PARTIAL until CI confirms.
     - Anti-pattern 2: zero `#[allow(clippy::unwrap_used)]` and zero `#[allow(dead_code)]` introduced (verified via `git diff main..HEAD -- crates/ | grep -c '#\[allow(...)\]'` = 0).
     - Anti-pattern 3: `cargo check` was NOT substituted for clippy on Windows host.
     - Anti-pattern 4: Windows-host workspace clippy was NOT alone treated as sufficient — cross-target attempts were run AND documented even when they failed.
   - **§ Closure path** — Phase 46 orchestrator records the GH Actions Linux Clippy + macOS Clippy lane verdicts on the Phase 45 head SHA; flips REQ-AIPC-G04-01 from PARTIAL to VERIFIED upon green capture.
   - **§ Windows-only-files invariant cross-reference** — explicit note that `exec_strategy_windows/supervisor.rs` 22-site cascade is wire-type cascade NOT new Windows-only code, per CONTEXT.md cross-phase invariants; documented in 45-02-SUMMARY § Cross-Phase Invariants.

5. Stage + commit the new artifact:
   ```
   git add .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-02-CLIPPY-CROSS-TARGET.md
   git commit -m "$(cat <<'EOF'
   docs(45-02): cross-target clippy verification artifact (PARTIAL)

   Document cross-target Linux + macOS clippy attempt outcomes for Plan 45-02
   per .planning/templates/cross-target-verify-checklist.md § Enforcement.
   Windows-host workspace clippy exits 0; cross-target Linux clippy SKIPPED
   (x86_64-linux-gnu C linker absent on Windows dev host); cross-target macOS
   clippy SKIPPED (Darwin SDK absent). REQ-AIPC-G04-01 marked PARTIAL; live
   GH Actions Linux Clippy + macOS Clippy lanes on Phase 45 head SHA are the
   decisive close signal per the 3-precedent pattern at Phase 41 + 43-01b + 44.

   Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
   EOF
   )"
   ```
  </action>
  <verify>
    <automated>(cd C:/Users/OMack/Nono && cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used) && (cd C:/Users/OMack/Nono && test -f .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-02-CLIPPY-CROSS-TARGET.md) && (cd C:/Users/OMack/Nono && grep -c 'PARTIAL' .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-02-CLIPPY-CROSS-TARGET.md)</automated>
  </verify>
  <acceptance_criteria>
    - **Windows-host clippy clean (maps to VALIDATION row REQ-AIPC-G04-01 "cargo clippy clean on Windows host"):** `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` exits 0.
    - **Artifact exists with PARTIAL disposition (maps to VALIDATION manual-only rows for cross-target Linux + macOS):** `test -f .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-02-CLIPPY-CROSS-TARGET.md` exits 0 AND `grep -c 'PARTIAL' <file>` ≥ 1.
    - **Verbatim PARTIAL prose present:** `grep -c 'Cross-target clippy gate SKIPPED on Windows dev host' .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-02-CLIPPY-CROSS-TARGET.md` = 1.
    - **All 4 anti-patterns acknowledged in artifact:** `grep -ciE 'Anti-pattern (1|2|3|4)' .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-02-CLIPPY-CROSS-TARGET.md` ≥ 4.
    - **Live-CI deferral path documented:** `grep -c 'live GH Actions' .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-02-CLIPPY-CROSS-TARGET.md` ≥ 1 AND `grep -c 'Phase 46' .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-02-CLIPPY-CROSS-TARGET.md` ≥ 1.
    - **Windows-only-files invariant cross-reference present:** `grep -c 'wire-type cascade' .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-02-CLIPPY-CROSS-TARGET.md` ≥ 1.
    - **DCO-signed commit:** `git log --pretty=format:'%s' -1` = `docs(45-02): cross-target clippy verification artifact (PARTIAL)` AND `git log --pretty=format:'%b' -1 | grep -c '^Signed-off-by: oscarmackjr-twg'` = 1.
  </acceptance_criteria>
  <done>
    `45-02-CLIPPY-CROSS-TARGET.md` committed with PARTIAL disposition, verbatim cross-target-verify-checklist.md PARTIAL prose, all 4 anti-pattern acknowledgements, Windows-only-files-invariant cross-reference, and Phase 46 orchestrator hand-off documentation. Windows-host workspace clippy exits 0.
  </done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Parent ⇄ Child supervisor (AIPC) | `SupervisorResponse::Decision` flows over named pipes (Windows) / Unix sockets (Linux/macOS); the wire shape is the cross-process boundary that Plan 45-02 is hardening. |
| Persistent ledger ⇄ verifier (audit-attestation) | `AuditEntry::decision` (containing the renamed `ApprovalDecision`) is serialized into `audit-events.ndjson` and later verified by `nono audit verify`. Pre-v2.6 ledgers become non-re-verifiable post-migration (accepted BREAKING per D-45-C2). |
| In-memory `CapabilityRequest` ⇄ persistent NDJSON | The `audit_entry_with_redacted_token` scrub at `supervisor.rs:1303-1318` is the load-bearing token-redaction boundary; AUD-05 regression test at `:5033` asserts the boundary holds. |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-45-02-01 | Tampering / Spoofing | Illegal IPC wire state `(Approved, grant=None)` — a malicious or buggy supervisor could send a "granted" decision without a `ResourceGrant`, causing the child to proceed with no resource handle. | mitigate | Plan 45-02 inlines `ResourceGrant` into `ApprovalDecision::Approved(ResourceGrant)`; `(Approved, grant=None)` is now structurally unrepresentable at the type level. The `aipc_sdk.rs:417` `ok_or_else("supervisor granted but returned no ResourceGrant")` runtime defense becomes structurally unreachable — its elimination IS the SC#2 deliverable. Elevates the Phase 18.1-02 G-04 invariant from flow-control to type-level. |
| T-45-02-02 | Spoofing | Pre-existing dispatcher flow-control bug at `exec_strategy_windows/supervisor.rs:1875-1950` — the Phase 18.1-02 G-04 fix (`let (decision, grant) = if ... { ... }`) elevated `decision` to `Denied { reason: "broker failed: {e}" }` on broker failure. | mitigate (defense-in-depth) | Plan 45-02 PRESERVES the dispatcher pair-binding intact per Open Question #2 recommendation — defense in depth at no cost. The type-level invariant is now load-bearing; the runtime pair-binding is redundant but still correct. Comment added: `// Phase 45 Plan 45-02 elevated the (Approved, grant Some) invariant to type level; this dispatcher fold is now defense in depth, not load-bearing.` |
| T-45-02-03 | Information Disclosure | Session-token leakage in persistent NDJSON ledger — if the rename inadvertently bypasses `audit_entry_with_redacted_token` at `supervisor.rs:1303-1318`, raw session tokens could persist on disk. | mitigate | Plan 45-02 PRESERVES the redactor verbatim (Pitfall 3): function body untouched, signature `(&CapabilityRequest, &ApprovalDecision, &str, Instant) -> AuditEntry` unchanged. AUD-05 regression test `recorded_ledger_redacts_session_token` at `:5033` is preserved verbatim AND explicitly verified via `cargo test --bin nono recorded_ledger_redacts_session_token -- --exact` per D-45-C1 commit-body callout. On-disk ledger spot-check confirms the new `Approved({ResourceGrant})` payload contains no session token. |
| T-45-02-04 | Tampering | Pre-v2.6 ledger replay forgery — an attacker who possessed a v2.5 ledger could attempt to forge "Approved" entries by manipulating the old `{"decision":{"Granted":null},"grant":{...}}` shape if the post-v2.6 verifier silently accepted both forms. | mitigate | Plan 45-02 accepts the BREAKING wire-format change per D-45-C2; pre-v2.6 ledgers fail typed deserialization against the new shape (no `Deserialize` accepting both forms). Phase 22 Merkle integrity still applies to v2.6+ ledgers. Documented in CHANGELOG.md BREAKING entry + ADR amendment 45-X. Mitigation guidance: pin v2.5 binary for legacy ledger re-verification (no `nono audit migrate` tool; rejected at D-45-C2). |
| T-45-02-05 | Repudiation | Loss of audit trail across the v2.5 → v2.6 wire-format boundary — if the BREAKING change is not documented prominently, users could mistake the failure-to-verify as a security regression. | mitigate | Plan 45-02 lands CHANGELOG.md BREAKING entry + ADR amendment 45-X in `docs/architecture/audit-bundle-target.md` as part of the same atomic commit. Both artifacts include: before/after wire shape, fresh-session vs replay distinction, v2.5-binary-pin mitigation, ADR cross-reference. |
| T-45-02-06 | Tampering / Repudiation | Cross-target Linux + macOS clippy drift on the cascade's `socket.rs` (Unix) and `exec_strategy.rs` (cross-platform Unix-relevant) sites could hide cfg-gated bugs (Phase 41 twice-mis-verified precedent). | mitigate | Plan 45-02 Task 3 authors `45-02-CLIPPY-CROSS-TARGET.md` with PARTIAL disposition; live GH Actions Linux Clippy + macOS Clippy lanes on Phase 45 head SHA are the decisive close signal per 3-precedent pattern (Phase 41 + 43-01b + 44). All 4 anti-patterns from cross-target-verify-checklist.md acknowledged. |
| T-45-02-07 | Elevation of Privilege | Silenced lints (`#[allow(clippy::unwrap_used)]` or `#[allow(dead_code)]`) introduced to suppress cascade-related warnings would violate CLAUDE.md § Unwrap Policy + § Lazy use of dead code AND cross-target-verify-checklist.md Anti-pattern 2. | accept | Task 2 + Task 3 acceptance criteria explicitly grep for `#[allow(...)]` introductions and require count = 0. Removed surface (`grant: Option<ResourceGrant>` field) must be DELETED, not silenced — per CLAUDE.md § Lazy use of dead code. |
| T-45-02-08 | Tampering | Library vs CLI boundary violation — Plan 45-02 touches both `nono` library (wire-type definition) and `nono-cli` (22+ consumer sites). The library is the policy authority; CLI consumers obey. | accept | The wire-type invariant (`Approved ⟹ grant Some`) lives in `crates/nono/src/supervisor/types.rs` per CLAUDE.md § Library vs CLI Boundary; CLI consumers cascade per the type. No CLI-policy concepts are introduced into the library; no library types depend on CLI configuration. The `nono` library tier remains policy-free. |
| T-45-02-09 | Spoofing | Windows-only-files invariant violation (D-34-E1 / D-40-E1 / D-43-E1) — Plan 45-02 touches `exec_strategy_windows/supervisor.rs` at 22 cross-platform wire-type cascade sites. | accept | Per CONTEXT.md § cross-phase invariants, this is permitted as "wire-type cascade, NOT new Windows-only code; existing Windows-only callsite updates." No codified addendum exception required. Task 2 commit body explicitly documents the touch scope; Task 3 cross-target artifact cross-references the invariant. Plan 45-02-SUMMARY § Cross-Phase Invariants restates the disposition. |
</threat_model>

<verification>
**Plan-close gate (run before flipping plan status to complete):**
1. `cargo build --workspace --all-features` exits 0 — workspace builds with the new wire shape.
2. `cargo test --workspace --all-features` exits 0 — full test suite green (expected ≥ 2197 per Phase 43-01b baseline; the 23±2 dependent tests are updated atomically).
3. `cargo test --bin nono recorded_ledger_redacts_session_token -- --exact` exits 0 — AUD-05 token-redaction regression verified.
4. `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` exits 0 — Windows-host strict clippy clean.
5. `grep -rn 'ApprovalDecision::Granted' crates/ bindings/` returns 0 results — rename complete.
6. `grep -rn 'grant: Option<ResourceGrant>' crates/ bindings/` returns 0 results — field dropped.
7. `grep -rn 'grant: None' crates/ bindings/` returns 0 results — `grant: None` callsites gone.
8. `grep -rn 'supervisor granted but returned no ResourceGrant' crates/` returns 0 results — defense-in-depth branch structurally unreachable.
9. `grep -c 'BREAKING' CHANGELOG.md` ≥ 1 AND CHANGELOG diff includes wire-shape before/after + ADR back-reference.
10. `git diff main..HEAD -- docs/architecture/audit-bundle-target.md | grep -c '^+.*45-'` ≥ 1 — ADR amendment 45-X present.
11. `test -f .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-02-CLIPPY-CROSS-TARGET.md` AND `grep -c 'PARTIAL' <file>` ≥ 1 — cross-target artifact in place.
12. `git log --pretty=format:'%s' main..HEAD | grep -c '^feat(45-02): inline ApprovalDecision::Approved'` = 1 — single atomic commit landed (plus the docs(45-02) artifact commit = 2 commits total on this plan).
13. `git log --pretty=format:'%b' main..HEAD | grep -c '^Signed-off-by: oscarmackjr-twg'` ≥ 2 — every commit DCO-signed.
14. `git diff main..HEAD -- crates/ | grep -c '#\[allow(clippy::unwrap_used)\]\|#\[allow(dead_code)\]'` = 0 — no silenced lints.
15. Windows-only-files invariant honored: `git diff --name-only main..HEAD -- 'crates/nono-shell-broker/**' 'crates/nono-cli/src/exec_strategy_windows/'` lists ONLY `crates/nono-cli/src/exec_strategy_windows/supervisor.rs` (the documented wire-type cascade).
</verification>

<success_criteria>
Plan 45-02 satisfies REQ-AIPC-G04-01 when ALL of these are true:
- `ApprovalDecision::Approved(ResourceGrant)` is the wire shape; `Granted` is gone from the source tree; `grant: Option<ResourceGrant>` is dropped from `SupervisorResponse::Decision` — REQ-AIPC-G04-01 acceptance line 1 + ROADMAP SC#2.
- `(Approved, grant=None)` is structurally unrepresentable (compile-time error if attempted); the `aipc_sdk.rs` `ok_or_else("supervisor granted but returned no ResourceGrant")` defense-in-depth branch is gone — SC#2 compile-time guarantee.
- All 23±2 pre-existing tests updated atomically in the same commit; full workspace test suite green (`cargo test --workspace --all-features` ≥ 2197 passes) — REQ-AIPC-G04-01 acceptance line 2.
- AUD-05 token-redaction regression `recorded_ledger_redacts_session_token` at `supervisor.rs:5033` passes verbatim post-cascade (`cargo test --bin nono recorded_ledger_redacts_session_token -- --exact` exits 0) — REQ-AIPC-G04-01 acceptance line 3 + D-45-C1 commit-body callout.
- `audit_entry_with_redacted_token` at `supervisor.rs:1303-1318` is preserved verbatim (Pitfall 3); `audit_integrity.rs:83-93` docstring is preserved (Pitfall 4); `audit_commands.rs:867` fixture handled per Task 1 verdict (Pitfall 2).
- CHANGELOG.md has a v2.6 / Phase 45 BREAKING entry covering: wire-shape before/after, fresh-session vs replay distinction, ADR back-reference, v2.5-binary-pin mitigation — D-45-C2.
- `docs/architecture/audit-bundle-target.md` has an ADR amendment 45-X documenting the wire-type inlining decision + consequences — D-45-C2.
- Single atomic `feat(45-02):` commit covers all source + tests + docs (a separate `docs(45-02):` commit lands only the cross-target artifact) — D-45-C1.
- `45-02-CLIPPY-CROSS-TARGET.md` exists with PARTIAL disposition + all 4 anti-pattern acknowledgements + Phase 46 orchestrator hand-off — cross-target-verify-checklist.md § Enforcement.
- Windows-only-files invariant honored: `exec_strategy_windows/supervisor.rs` 22-site cascade documented in commit body as wire-type cascade (NOT new Windows-only code) per CONTEXT.md § cross-phase invariants — ROADMAP SC#4 at plan scope.
- No `#[allow(clippy::unwrap_used)]` or `#[allow(dead_code)]` introductions; no `.unwrap()` / `.expect()` added — CLAUDE.md § Coding Standards.
</success_criteria>

<output>
After completion, create `.planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-02-SUMMARY.md` with:
- Frontmatter: `phase`, `plan`, `req: REQ-AIPC-G04-01`, `commits: 2` (the atomic `feat(45-02):` + the `docs(45-02):` artifact), `status: complete` (or `partial` if cross-target lanes pending live CI).
- § Closure Disposition — REQ-AIPC-G04-01 status (CLOSED if PARTIAL gate cleared via captured GH Actions verdict, else STRUCTURALLY-COMPLETE-PENDING-CROSS-TARGET-CI).
- § Commit Manifest — `feat(45-02):` SHA + subject + brief body summary; `docs(45-02):` SHA + subject.
- § Test Inventory — final per-file count of updated tests; cross-reference to Task 1 inventory note; AUD-05 verification output verbatim.
- § BREAKING Change Documentation — CHANGELOG.md diff snippet + ADR amendment 45-X heading; explicit fresh-session-only guarantee statement.
- § Pitfall Audit — explicit confirmations: Pitfall 2 (fixture verdict + edit/no-edit), Pitfall 3 (redactor preserved verbatim), Pitfall 4 (docstring preserved), Pitfall 5 (cross-target lane scoped at phase head).
- § Windows-only-files invariant — explicit documentation of `exec_strategy_windows/supervisor.rs` 22-site cascade as wire-type cascade per CONTEXT.md § cross-phase invariants.
- § Sibling-repo cascade — explicit "no cascade needed" OR "lockstep filed for v2.7" per Task 1 verdict.
- § Cross-Target Posture — pointer to `45-02-CLIPPY-CROSS-TARGET.md` + Phase 46 orchestrator hand-off note.
- § Anti-pattern Audit — explicit confirmation that no `#[allow(...)]` was introduced; no `cargo check` substitution; no defense-in-depth silencing.
</output>
