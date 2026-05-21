# Phase 45: Source migration + AIPC G-04 + RESL native re-validation — Pattern Map

**Mapped:** 2026-05-21
**Files analyzed:** 18 (source) + 2 (NEW artifacts) + 2 (planning/doc) = 22
**Analogs found:** 22 / 22 (100% — all surfaces have in-repo analog files)

---

## File Classification

### Plan 45-01 — Edition 2024 source migration (bindings/c FFI tier)

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `bindings/c/src/capability_set.rs` (16 sites) | FFI export — library tier | request-response (sync C ABI) | **self** (existing file, mechanical rewrite) — sibling pattern: any other `bindings/c/src/*.rs` already in repo | exact (self) |
| `bindings/c/src/lib.rs` (4 sites) | FFI export — library tier (root + helpers) | request-response | **self** | exact (self) |
| `bindings/c/src/fs_capability.rs` (7 sites) | FFI export — library tier | request-response | **self** | exact (self) |
| `bindings/c/src/sandbox.rs` (3 sites) | FFI export — library tier | request-response | **self** | exact (self) |
| `bindings/c/src/state.rs` (5 sites) | FFI export — library tier | request-response | **self** | exact (self) |
| `bindings/c/src/query.rs` (4 sites) | FFI export — library tier | request-response | **self** | exact (self) |
| `.planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md` (Cluster 2 line 76 flip) | planning artifact — audit trail | transform (status flip) | **self** (existing ledger; in-place amendment) | exact (self) |
| `bindings/c/include/nono.h` (read-only gate target) | FFI generated artifact — byte-identical gate | transform (cbindgen output) | `bindings/c/build.rs` + `bindings/c/cbindgen.toml` invocation | exact (existing infra; no edit) |

### Plan 45-02 — AIPC G-04 wire-protocol cascade

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `crates/nono/src/supervisor/types.rs` (wire type def `:200-211, :476-495`; impl `:405-417`) | library wire-type — definition tier | producer (defines wire shape) | **self** (in-place rename + variant restructure) — sibling pattern in same file: `GrantedResourceKind` enum `:213-228` (variant-with-data pattern) | exact (self; in-place edit of canonical enum) |
| `crates/nono/src/supervisor/aipc_sdk.rs` (7 construction sites + match-arm `:417`) | child SDK demultiplexer — library consumer | consumer (deserializes wire, dispatches) | **self** (in-place; the `:404-433` match block is the canonical demultiplexer) | exact (self; pattern is the rewrite target itself) |
| `crates/nono/src/supervisor/mod.rs` (2 sites `:148, :202`) | library re-export + example | producer (constructor) | self (in-place rename only) | exact (self) |
| `crates/nono/src/supervisor/socket.rs` (1 site `:572`) | cross-platform socket dispatch | producer (constructs Decision) | sibling `socket_windows.rs:1484, :1621` (Windows counterpart) | exact (sibling) |
| `crates/nono/src/supervisor/socket_windows.rs` (2 sites + 4 Decision constructions) | Windows socket dispatch | producer | sibling `socket.rs:572` (Unix counterpart) | exact (sibling) |
| `crates/nono-cli/src/exec_strategy.rs` (1 matches! + 3 `grant: None` sites + 4 Decision constructions) | CLI cross-platform exec dispatch | consumer | sibling `exec_strategy_windows/supervisor.rs` (Windows counterpart) | exact (sibling) |
| `crates/nono-cli/src/exec_strategy_windows/supervisor.rs` (22 Decision sites; AUD-05 test `:5033`; redactor `:1303-1318`) | CLI Windows supervisor — load-bearing consumer | producer (constructs Decision responses) + recorder | **self** (in-place; supervisor.rs is the canonical analog) — dispatcher pair-binding pattern `:1875-1950` documents the flow-control invariant Plan 45-02 elevates to type level | exact (self; supersedes own pre-Phase-45 dispatcher fold) |
| `crates/nono-cli/src/audit_integrity.rs` (no `Granted` refs; transparent through `AuditEntry::decision`) | CLI audit-recorder tier | transform (serde derive flows through) | self (docstring at `:83-93` mentions stale "Approved decisions" wording but refers to **`reject_stage`** not `grant` — Pitfall 4) | exact (self; verify only) |
| `crates/nono-cli/src/audit_commands.rs:867` | CLI verify tier — test fixture | consumer (NDJSON line-by-line reader) | self (`:863-868` hand-rolled `serde_json::Value` fixture already uses `"Approved":null`) | exact (self; pre-aligned, no edit needed for line itself; surrounding comment touchup only) |
| `crates/nono-cli/src/terminal_approval.rs` (1 site `:84`) | CLI terminal prompt path | producer (constructs decision) | **self** — but this site needs explicit `ResourceGrant` construction; analog: `ResourceGrant::sideband_file_descriptor(access)` factory at `types.rs:266-275` | exact (sibling factory) |
| 23+ test files across `crates/nono-cli/tests/`, `crates/nono/tests/` (planner runs plan-open grep) | test tier | consumer | `crates/nono-cli/tests/adr_aipc_unix_futures.rs` (named in CONTEXT § canonical refs) | partial (same test shape; per-file inventory at plan-open) |
| `CHANGELOG.md` (BREAKING entry) | project doc — change log | producer | self (existing changelog entries) | role-match |
| `docs/architecture/audit-bundle-target.md` (ADR amendment 45-X) | project doc — ADR | producer (append-only amendment) | self (existing Phase 27.2 follow-ups v2.5-FU-1, v2.5-FU-2 are the append-pattern precedent) | role-match |

### Plan 45-03 — RESL native re-validation (CI + planning tier)

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `.github/workflows/phase-45-resl-native-host.yml` (NEW) | CI workflow — tactical verification | event-driven (workflow_dispatch) | **`.github/workflows/phase-37-linux-resl.yml`** (Phase 37 always-on precedent — scale DOWN to `workflow_dispatch`-only per D-45-D2) | exact (role) / scaled (trigger) |
| `.planning/phases/45-.../45-03-NATIVE-RESL-PROTOCOL.md` (NEW) | planning artifact — verification protocol | producer (decision tree + Phase 46 hand-off) | `.planning/phases/27.2-audit-attestation-test-re-enablement/27.2-04-SUMMARY.md` (verification-protocol shape, but SUMMARY not protocol-spec); no existing pure-protocol doc analog | role-match (no exact analog — Phase 45 introduces the pattern) |

---

## Pattern Assignments

### Plan 45-01 — `bindings/c/src/*.rs` Edition 2024 rewrite

**Analog:** the same file pre-rewrite (mechanical sweep). Representative: `bindings/c/src/capability_set.rs` (16 sites) and `bindings/c/src/sandbox.rs` (3 sites).

#### Imports pattern (canonical at `bindings/c/src/capability_set.rs:1-6`)

```rust
//! FFI wrapper for `nono::CapabilitySet`.

use std::os::raw::c_char;

use crate::types::{validate_access_mode, NonoErrorCode};
use crate::{c_str_to_str, map_error, rust_string_to_c, set_last_error};
```

**No imports change** in Plan 45-01 — pure attribute syntax sweep.

#### Pre-rewrite `#[no_mangle]` (current, at `capability_set.rs:28-31`)

```rust
/// Create a new empty capability set.
///
/// The returned pointer is never NULL. Caller must free with
/// `nono_capability_set_free()`.
#[no_mangle]
pub extern "C" fn nono_capability_set_new() -> *mut NonoCapabilitySet {
    Box::into_raw(Box::new(NonoCapabilitySet::default()))
}
```

#### `#[no_mangle]` on `unsafe extern "C" fn` (canonical at `capability_set.rs:41-50`)

```rust
/// # Safety
///
/// `caps` must be NULL or a pointer previously returned by
/// `nono_capability_set_new()` or a factory function.
#[no_mangle]
pub unsafe extern "C" fn nono_capability_set_free(caps: *mut NonoCapabilitySet) {
    if !caps.is_null() {
        // SAFETY: The pointer was created by Box::into_raw() in
        // nono_capability_set_new() or a factory function in this library.
        unsafe {
            drop(Box::from_raw(caps));
        }
    }
}
```

#### Post-rewrite (target, Edition 2024 conformant)

```rust
#[unsafe(no_mangle)]
pub extern "C" fn nono_capability_set_new() -> *mut NonoCapabilitySet {
    Box::into_raw(Box::new(NonoCapabilitySet::default()))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn nono_capability_set_free(caps: *mut NonoCapabilitySet) {
    // body unchanged
}
```

**Rewrite rule:** literal substitution `#[no_mangle]` → `#[unsafe(no_mangle)]`. No body changes, no `unsafe` block additions, no signature changes. Verify with `git diff --stat`: every diff line should be one of the 39 sites; nothing else.

**Cross-file site counts (verified via Grep):**
- `state.rs`: 5
- `lib.rs`: 4
- `capability_set.rs`: 16
- `fs_capability.rs`: 7
- `query.rs`: 4
- `sandbox.rs`: 3
- **Total: 39** (matches CONTEXT.md + RESEARCH.md)

#### Commit body template (D-45-B1 D-20 manual replay)

```text
chore(45-01): bindings/c capability_set.rs Edition 2024 no_mangle (16 sites)

Sweep 16 #[no_mangle] sites to #[unsafe(no_mangle)] per Rust Edition 2024
semantics. No behavior change; no signature change; cbindgen output remains
byte-identical (verified at Plan 45-01 close).

Replay-of: 79715aa5 (Phase 43 Plan 43-01b DEC-3 split-disposition close)
Cluster: 2 (Rust edition 2024 + workspace dependency centralization)
DIVERGENCE-LEDGER: see .planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md
                   § "Cluster: Rust edition 2024" — disposition split → closed
                   at Plan 45-01 close.

Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```

#### DIVERGENCE-LEDGER amendment (final Plan 45-01 commit)

**Target line at `.planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md:76`:**

```markdown
- **Disposition:** split — workspace edits in Phase 43 Plan 43-01b, source migration deferred to v2.6 / UPST6
```

**Append (recommended; preserves "Original disposition" line at :77 for audit traceability):**

```markdown
- **Final disposition:** closed (Phase 45 Plan 45-01 commits <range>, ledger amended at SHA <amend-sha>). Source migration absorbed; cluster fully synchronized with upstream `79715aa5`.
```

---

### Plan 45-02 — wire-type cascade

**Analog 1 (canonical wire type):** `crates/nono/src/supervisor/types.rs:198-211` (current enum) + `:476-495` (current SupervisorResponse) + `:243-261` (ResourceGrant struct to inline).

#### Current wire type (`types.rs:198-211`)

```rust
/// The supervisor's response to a [`CapabilityRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApprovalDecision {
    /// Access was granted. Resource-transfer details, if any, are carried by
    /// [`SupervisorResponse::Decision`].
    Granted,
    /// Access was denied with a reason.
    Denied {
        /// Why the request was denied
        reason: String,
    },
    /// The approval request timed out without a decision.
    Timeout,
}
```

#### Current SupervisorResponse (`types.rs:474-495`)

```rust
/// IPC message envelope sent from supervisor to child.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SupervisorResponse {
    /// Response to a capability request
    Decision {
        /// The request_id this responds to
        request_id: String,
        /// The approval decision
        decision: ApprovalDecision,
        /// Resource-transfer metadata when the supervisor granted access.
        grant: Option<ResourceGrant>,   // ← DROP in Plan 45-02
    },
    /// Response to a URL open request
    UrlOpened {
        // unchanged
    },
}
```

#### Current `impl ApprovalDecision` `#[must_use]` pattern (`types.rs:405-417`)

```rust
impl ApprovalDecision {
    /// Returns true if access was granted.
    #[must_use]
    pub fn is_granted(&self) -> bool {
        matches!(self, ApprovalDecision::Granted)
    }

    /// Returns true if access was denied.
    #[must_use]
    pub fn is_denied(&self) -> bool {
        matches!(self, ApprovalDecision::Denied { .. })
    }
}
```

**Key pattern to preserve:** `#[must_use]` on every helper. The renamed `is_approved()` MUST carry `#[must_use]` (CLAUDE.md § Coding Standards `#[must_use]` rule).

#### Target wire type (post-Plan-45-02)

```rust
/// The supervisor's response to a [`CapabilityRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApprovalDecision {
    /// Access was approved. The resource-transfer metadata is carried inline.
    Approved(ResourceGrant),
    /// Access was denied with a reason.
    Denied {
        reason: String,
    },
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

**Analog 2 (demultiplexer rewrite):** `crates/nono/src/supervisor/aipc_sdk.rs:404-433`.

#### Current demultiplexer (the structural defense-in-depth becomes unreachable)

```rust
match cap_pipe.recv_response()? {
    SupervisorResponse::Decision {
        request_id: resp_id,
        decision,
        grant,
    } => {
        if resp_id != request_id {
            return Err(NonoError::SandboxInit(format!(
                "supervisor response request_id mismatch: expected {request_id}, got {resp_id}"
            )));
        }
        match decision {
            ApprovalDecision::Granted => grant.ok_or_else(|| {
                NonoError::SandboxInit(
                    "supervisor granted but returned no ResourceGrant".to_string(),
                )
            }),
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

#### Target demultiplexer (post-rewrite — SC#2 compile-time guarantee)

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

**Note:** the `grant.ok_or_else(... "supervisor granted but returned no ResourceGrant" ...)` defense-in-depth branch becomes structurally unreachable. **This deletion IS the SC#2 deliverable.**

**Analog 3 (supervisor.rs construction-site cascade):** `crates/nono-cli/src/exec_strategy_windows/supervisor.rs:1867-1872, 1892-1896, 1925-1929` — 22 sites of the same shape.

#### Current construction pattern (representative, supervisor.rs:1867-1872)

```rust
return sock.send_response(&nono::supervisor::SupervisorResponse::Decision {
    request_id: request.request_id,
    decision,
    grant: None,    // ← DROP across all 22 sites in Plan 45-02
});
```

#### Target construction (post-rewrite, denial path)

```rust
return sock.send_response(&nono::supervisor::SupervisorResponse::Decision {
    request_id: request.request_id,
    decision,    // already-built ApprovalDecision::Denied { reason }
});
```

#### Target construction (post-rewrite, approval path — Decision now carries inline grant via `decision`)

```rust
// Where current code is: SupervisorResponse::Decision { request_id, decision: ApprovalDecision::Granted, grant: Some(resource_grant) }
// Becomes:
return sock.send_response(&nono::supervisor::SupervisorResponse::Decision {
    request_id: request.request_id,
    decision: ApprovalDecision::Approved(resource_grant),
});
```

**Analog 4 (load-bearing redactor — DO NOT TOUCH the helper, only its call):** `crates/nono-cli/src/exec_strategy_windows/supervisor.rs:1300-1318`.

#### Redactor (unchanged across Plan 45-02 — preserved verbatim)

```rust
/// Build an `AuditEntry` for a `CapabilityRequest` while redacting the
/// `session_token` field. Never embed the raw request directly — always go
/// through this helper so the token cannot leak via audit serialization.
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
        decision: decision.clone(),
        backend: backend_name.to_string(),
        duration_ms: started_at.elapsed().as_millis() as u64,
    }
}
```

The redactor takes `&nono::ApprovalDecision` — flows through unchanged. AUD-05 invariant is preserved by serde re-deriving the new wire shape.

**Analog 5 (AUD-05 regression test — must pass post-cascade):** `crates/nono-cli/src/exec_strategy_windows/supervisor.rs:5025-5081`.

#### Test pattern (preserved verbatim across Plan 45-02 — assert structure unchanged)

```rust
/// Phase 23 Task 3 Step 6: ledger-side sanitization regression. The
/// in-memory `audit_entry_with_redacted_token` (supervisor.rs:1279)
/// is the load-bearing scrub; this test reads the persistent NDJSON
/// ledger and asserts the raw session token never appears on disk
#[test]
fn recorded_ledger_redacts_session_token() {
    let backend = CountingGrantBackend::new();
    let (mut supervisor, mut child) = new_pair();
    let mut seen = HashSet::new();
    let mut audit_log = Vec::new();
    let sensitive_token = "TOPSECRET_TOKEN_DO_NOT_LEAK_42";

    let dir = tempfile::tempdir().expect("tempdir");
    let recorder_arc = std::sync::Arc::new(std::sync::Mutex::new(
        crate::audit_integrity::AuditRecorder::new(dir.path().to_path_buf()).expect("recorder"),
    ));

    // ... dispatch one Event request, read ledger from disk ...

    let ledger = std::fs::read_to_string(
        dir.path()
            .join(crate::audit_integrity::AUDIT_EVENTS_FILENAME),
    )
    .expect("ledger file");
    assert!(
        !ledger.contains(sensitive_token),
        "Phase 23 sanitization invariant: NDJSON ledger MUST NOT contain \
         raw session token. Ledger:\n{ledger}",
    );
}
```

**Verification command (cite in commit body per D-45-C1):**

```bash
cargo test --bin nono recorded_ledger_redacts_session_token -- --exact
```

**Analog 6 (dispatcher pair-binding — defense-in-depth at supervisor.rs:1875-1950):** the Phase 18.1-02 G-04 fix `let (decision, grant) = if ... { ... }` pattern is now redundant at type level but **leave it intact** per Open Question 2 recommendation (defense in depth at no cost; add Phase 45 transition comment).

#### Construction-site denial cascade (representative — supervisor.rs:1881-1896, repeats 4× in 1875-1950 block)

```rust
let decision = nono::ApprovalDecision::Denied {
    reason: "Invalid session token".to_string(),
};
let entry = audit_entry_with_redacted_token(
    &request,
    &decision,
    approval_backend.backend_name(),
    started_at,
);
emit_to_ledger(&entry, &request.request_id, None);
audit_log.push(entry);
return sock.send_response(&nono::supervisor::SupervisorResponse::Decision {
    request_id: request.request_id,
    decision,
    grant: None,    // ← DROP only this line in Plan 45-02; rest is preserved
});
```

**Analog 7 (audit_commands.rs:867 fixture — pre-aligned, comment touchup only):** `crates/nono-cli/src/audit_commands.rs:855-870`.

#### Current fixture (lines 863-868 already use type-checked spelling)

```rust
let lines = [
    r#"{"sequence":0,...,"event":{"type":"session_started",...}}"#,
    r#"{"sequence":1,...,"event":{"type":"capability_decision","entry":{...,"decision":{"Denied":{"reason":"x"}},"backend":"t","duration_ms":0},"reject_stage":"before-prompt"}}"#,
    r#"{"sequence":2,...,"event":{"type":"capability_decision","entry":{...,"decision":{"Denied":{"reason":"y"}},"backend":"t","duration_ms":0},"reject_stage":"after-prompt"}}"#,
    r#"{"sequence":3,...,"event":{"type":"capability_decision","entry":{...,"decision":{"Approved":null},"backend":"t","duration_ms":0}}}"#,
    r#"{"sequence":4,...,"event":{"type":"session_ended",...}}"#,
];
```

**Action in Plan 45-02:**
- Line 867 already reads `"decision":{"Approved":null}` (predicts post-rename shape). **The literal `null` is OK because this is hand-rolled `serde_json::Value` for a read-only test path that does not deserialize to the typed shape.** Pitfall 2 — do NOT double-edit.
- The line **may need updating** post-rename: with the new `Approved(ResourceGrant)` variant, the wire shape becomes `{"Approved":{"transfer":...,"resource_kind":...,"access":...,...}}` (non-null tuple-variant payload). If this fixture is read by code that NOW typed-deserializes against `ApprovalDecision`, the line WILL need a structurally-complete `ResourceGrant` value. **Planner verifies at plan-open** by tracing `read_capability_decisions_from_ledger` deserialization path.

**Analog 8 (audit_integrity.rs docstring at :83-93 — Pitfall 4):** the `None` for Approved decisions wording refers to `reject_stage`, NOT to `grant`. The `grant` field is dropped from a **different** type (`SupervisorResponse::Decision`); `reject_stage: Option<RejectStage>` here is UNCHANGED.

```rust
CapabilityDecision {
    entry: AuditEntry,
    /// Windows-AIPC-specific reject-stage marker (Phase 23 D-02).
    /// `None` for Approved decisions, for non-Windows ledger entries,
    /// and for the three pre-stage rejections...
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reject_stage: Option<RejectStage>,    // ← UNCHANGED; do not edit
},
```

#### Single-commit cascade order (D-45-C1)

1. Rewrite `types.rs` enum + `SupervisorResponse::Decision` + impl rename.
2. Rewrite `aipc_sdk.rs` demultiplexer + all 7 construction sites + `:769, :841` `grant: None` removals.
3. Rewrite `socket.rs`, `socket_windows.rs`, `mod.rs` construction + match sites.
4. Rewrite `exec_strategy_windows/supervisor.rs` 22 Decision sites + 4 `grant: None` removals (preserve `audit_entry_with_redacted_token` + AUD-05 test verbatim).
5. Rewrite `exec_strategy.rs` 4 Decision sites + `matches!` arm.
6. Rewrite `terminal_approval.rs:84` with explicit `ResourceGrant::sideband_file_descriptor(access)` construction.
7. Update 23+ pre-existing tests (planner inventories at plan-open).
8. Touch up `audit_commands.rs` fixture (only if typed deserialization path is affected).
9. Append CHANGELOG.md BREAKING entry.
10. Append `docs/architecture/audit-bundle-target.md` ADR amendment 45-X.
11. Run `cargo test --bin nono recorded_ledger_redacts_session_token -- --exact`; call out pass in commit body.

---

### Plan 45-03 — RESL native re-validation

**Analog (workflow):** `.github/workflows/phase-37-linux-resl.yml` (full file). Pattern: matrix runner + RUSTFLAGS + actions/setup-rust + actions/cache + cargo test invocation.

#### Workflow header pattern (from phase-37-linux-resl.yml:1-26)

```yaml
# Phase 37 — Linux RESL backends + PKGS auto-pull verification
#
# Verifies REQ-RESL-NIX-01/02/03 + REQ-PKGS-04 acceptance #4 on a real
# Ubuntu 24.04 runner...
# Required check on PRs to main per D-03. Always-on trigger (no path-filter
# per CONTEXT.md Claude's Discretion + research recommendation; CI minute
# budget acceptable for the two-job-per-PR cost).

name: Phase 37 Linux RESL

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: -Dwarnings

permissions:
  contents: read
```

**Plan 45-03 deviation (per D-45-D2):** replace `pull_request` + `push` triggers with `workflow_dispatch` only:

```yaml
name: Phase 45 RESL Native Host Re-validation

on:
  workflow_dispatch:
    inputs:
      gh_runner_os:
        description: Which OS matrix to run
        type: choice
        options: [ubuntu-24.04, macos-latest, both]
        default: both

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: -Dwarnings

permissions:
  contents: read
```

#### Action SHA pins to REUSE (from phase-37-linux-resl.yml:35-48)

```yaml
- name: Checkout
  uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6

- name: Install Rust toolchain
  uses: dtolnay/rust-toolchain@631a55b12751854ce901bb631d5902ceb48146f7 # stable
  with:
    toolchain: stable

- name: Cache cargo registry + target
  uses: actions/cache@668228422ae6a00e4ad889ee87cd7109ec5666a7 # v5
  with:
    path: |
      ~/.cargo/registry
      ~/.cargo/git
      target
    key: ${{ runner.os }}-phase45-resl-${{ hashFiles('**/Cargo.lock') }}
    restore-keys: |
      ${{ runner.os }}-phase45-resl-
```

**REUSE policy (per Open Question 4 recommendation):** lift these SHAs verbatim from `phase-37-linux-resl.yml`. Minimizes audit-trail divergence; the workflow is tactical (deletable in v2.7 once verdict recorded).

#### Job matrix pattern (per-OS, with `if:` gate on `inputs.gh_runner_os`)

```yaml
jobs:
  resl-nix:
    if: ${{ inputs.gh_runner_os == 'ubuntu-24.04' || inputs.gh_runner_os == 'both' }}
    name: Phase 45 RESL native (Linux)
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    continue-on-error: true   # SC#3: one or both per host availability
    steps:
      - name: Checkout
        uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6
      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@631a55b12751854ce901bb631d5902ceb48146f7 # stable
        with:
          toolchain: stable
      - name: Cache cargo registry + target
        uses: actions/cache@668228422ae6a00e4ad889ee87cd7109ec5666a7 # v5
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-phase45-resl-${{ hashFiles('**/Cargo.lock') }}
      - name: Build workspace
        run: cargo build --workspace --release --verbose
      - name: Run audit-attestation regression
        run: cargo test -p nono-cli --test audit_attestation -- --include-ignored

  resl-darwin:
    if: ${{ inputs.gh_runner_os == 'macos-latest' || inputs.gh_runner_os == 'both' }}
    name: Phase 45 RESL native (macOS)
    runs-on: macos-latest
    timeout-minutes: 30
    continue-on-error: true
    steps:
      # mirror Linux job; same cargo test invocation
```

#### Cargo test invocation (canonical — derived from Phase 27.2 closure)

```bash
cargo test -p nono-cli --test audit_attestation -- --include-ignored
# Expected:
# running 2 tests
# test audit_verify_reports_signed_attestation_with_pinned_public_key ... ok
# test rollback_signed_session_verifies_from_audit_dir_bundle ... ok
# test result: ok. 2 passed; 0 failed; 0 ignored
```

**Protocol doc analog:** No prior phase has a pure-protocol artifact. Closest precedent for shape: `.planning/phases/27.2-audit-attestation-test-re-enablement/27.2-04-SUMMARY.md` (verification narrative with expected output + Performance + Tasks). Plan 45-03 introduces a new pattern. Minimum content per CONTEXT.md § Claude's Discretion:

1. SC#3 decision tree: (a) coverage matches → close; (b) gap surfaced → file follow-up.
2. Expected `cargo test` output (verbatim from above).
3. Phase 46 hand-off instructions: `gh workflow run phase-45-resl-native-host.yml -f gh_runner_os=both` then capture run-ID + verdict + record in 45-VERIFICATION.md or 46-VERIFICATION.md.
4. Optional: Phase 27.2 transitive-closure mapping (since Phase 38 was originally a "Phase 27 reopen").

---

## Shared Patterns

### Pattern S1 — DCO sign-off on every commit

**Source:** CLAUDE.md § Coding Standards.
**Apply to:** Every commit in Plans 45-01, 45-02, 45-03.

```text
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```

### Pattern S2 — `#[must_use]` on helper methods returning `bool` (where critical)

**Source:** `crates/nono/src/supervisor/types.rs:407` + CLAUDE.md § Coding Standards "Attributes".
**Apply to:** Renamed `is_approved()` impl method in Plan 45-02.

```rust
impl ApprovalDecision {
    #[must_use]
    pub fn is_approved(&self) -> bool {
        matches!(self, ApprovalDecision::Approved(_))
    }
}
```

### Pattern S3 — Cross-target clippy verification (cfg-gated Unix code)

**Source:** `.planning/templates/cross-target-verify-checklist.md` § Decision Tree + CLAUDE.md § Coding Standards "Cross-target clippy verification".
**Apply to:** Plan 45-01 (`bindings/c/src/*` is cross-platform FFI consumed by Unix runtimes) + Plan 45-02 (`crates/nono/src/supervisor/socket.rs` is Unix; `exec_strategy_windows/supervisor.rs` is Windows cfg-gated).

```bash
# MUST/NEVER (from CLAUDE.md):
cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used
cargo clippy --workspace --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used
```

**Disposition on this Windows host (per RESEARCH.md § Phase 45 Cross-Target Posture):** PARTIAL (Rust targets installed; C cross-linkers absent — 3-precedent pattern at Phase 41, 43-01b, 44). Mark REQs PARTIAL per checklist § PARTIAL Disposition; GH Actions Linux Clippy + macOS Clippy lanes on Phase 45 head SHA are the decisive close signal.

**Required artifact:** `45-01-CLIPPY-CROSS-TARGET.md` (Plan 45-01 close) + `45-02-CLIPPY-CROSS-TARGET.md` (Plan 45-02 close) per cross-target-verify-checklist.md § Enforcement.

### Pattern S4 — Unwrap policy (`.unwrap()` / `.expect()` forbidden in source)

**Source:** CLAUDE.md § Coding Standards + workspace `[workspace.lints.clippy] unwrap_used = "deny"` (Phase 43 Plan 43-01b).
**Apply to:** All Plan 45-01 and Plan 45-02 source. Note that test modules are exempt — the existing `.expect("tempdir")` in supervisor.rs:5040 is in `#[cfg(test)]` scope.

### Pattern S5 — Library vs CLI boundary preserved

**Source:** CLAUDE.md § Library vs CLI Boundary + § Project Overview.
**Apply to:**
- Plan 45-01 (`bindings/c/src/*` is library FFI — Edition 2024 syntax conformance must NOT introduce CLI-policy concepts).
- Plan 45-02 (`crates/nono/src/supervisor/types.rs` is library wire type; consumers in `crates/nono-cli/` cascade. Wire-type invariant elevation lives at the library; CLI consumers obey.)

### Pattern S6 — Windows-only-files invariant (D-34-E1 / D-40-E1 / D-43-E1)

**Source:** ROADMAP.md § Cross-Phase Invariants + CONTEXT.md § canonical refs.
**Apply to:** Plan 45-02 only — `exec_strategy_windows/supervisor.rs` is touched at 22 Decision sites, but each is an **unavoidable cascade** from the cross-platform wire-type rename. **NOT new Windows-only code; existing Windows-only callsite updates.** No codified addendum exception required; SUMMARY documents the touch scope.

### Pattern S7 — Environment variable save/restore in tests

**Source:** CLAUDE.md § Coding Standards + Phase 27.2 RAII pattern at `crates/nono-cli/tests/audit_attestation.rs::ScopedEnvVar`.
**Apply to:** Plan 45-02 test additions if env vars are modified; Plan 45-03 does not add tests, so N/A there.

### Pattern S8 — BREAKING wire-format change documentation

**Source:** D-45-C2 + existing AUD-02 wire-format documented in `docs/architecture/audit-bundle-target.md`.
**Apply to:** Plan 45-02.
- CHANGELOG.md: BREAKING entry under v2.6 / Phase 45 marker. Must include: wire shape change before/after; fresh-session vs replay distinction; ADR back-reference; mitigation guidance (pin to v2.5 binary for legacy ledger re-verify).
- `docs/architecture/audit-bundle-target.md`: append ADR amendment 45-X (planner picks heading: append-as-new-subsection vs sibling-ADR).

### Pattern S9 — D-20 manual replay with `Replay-of:` annotation (NOT `Upstream-commit:` D-19 trailer)

**Source:** D-45-B1 + Phase 40 D-20 + Phase 43 split-disposition convention.
**Apply to:** All 6 per-file commits in Plan 45-01.

```text
Replay-of: 79715aa5 (Phase 43 Plan 43-01b DEC-3 split-disposition close)
Cluster: 2 (Rust edition 2024 + workspace dependency centralization)
```

**NOT a `Upstream-commit:` trailer block** — Plan 45-01 is closing a previously-split upstream commit, not a fresh upstream cherry-pick.

### Pattern S10 — Baseline-aware CI gate (Phase 44 quiet-baseline anchor)

**Source:** `.planning/templates/upstream-sync-quick.md:102` + D-44-E1 carry-forward.
**Apply to:** Plan 45-01 + Plan 45-02 commit gating. Gate against Phase 44 close head SHA `aa510098` (or whichever is the canonical "Phase 44 + 44.1 close" tip at plan-open; planner verifies via `git log --oneline -10`). No `success → failure` transitions in CI lanes.

---

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `.planning/phases/45-.../45-03-NATIVE-RESL-PROTOCOL.md` | planning artifact — verification protocol spec | producer | **No existing phase has a pure-protocol-spec doc.** Closest shape-precedent is `.planning/phases/27.2-.../27.2-04-SUMMARY.md` (which is a SUMMARY, not a forward-looking protocol). Plan 45-03 introduces a new pattern: the planner can structure freely per CONTEXT.md § Claude's Discretion. Recommended minimum: SC#3 decision tree + expected `cargo test` output + Phase 46 hand-off instructions + (optional) Phase 27.2 transitive-closure mapping. |

---

## Metadata

**Analog search scope:**
- `bindings/c/src/` (6 files, all read)
- `crates/nono/src/supervisor/` (types.rs, aipc_sdk.rs spot-reads; mod.rs/socket.rs/socket_windows.rs verified via Grep counts in RESEARCH.md)
- `crates/nono-cli/src/exec_strategy_windows/supervisor.rs` (3 targeted reads: redactor block, dispatcher cascade, AUD-05 test)
- `crates/nono-cli/src/audit_integrity.rs` (lines 75-103 read)
- `crates/nono-cli/src/audit_commands.rs` (lines 855-870 read)
- `.github/workflows/` (all 9 workflows listed; phase-37-linux-resl.yml fully read)
- `.planning/templates/cross-target-verify-checklist.md` (lines 1-60 read)
- `.planning/phases/27.2-.../27.2-04-SUMMARY.md` (lines 1-60 read for protocol-doc shape reference)
- `.planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md` (lines 70-89 read for amendment target)

**Files scanned:** 22

**Pattern extraction date:** 2026-05-21

**Empirical confirmations:**
- 39 `#[no_mangle]` sites in `bindings/c/src/` (Grep count: 5+4+16+7+4+3 = 39). Matches CONTEXT.md + RESEARCH.md.
- `ApprovalDecision::Granted` variant + `is_granted()` `#[must_use]` helper at types.rs:200 + :407 verified via direct read.
- `audit_commands.rs:867` already reads `"decision":{"Approved":null}` (Pitfall 2 — pre-aligned, no edit for the line itself).
- `audit_entry_with_redacted_token` at supervisor.rs:1303-1318 (Pitfall 3 — load-bearing scrub, preserved verbatim across Plan 45-02).
- AUD-05 test `recorded_ledger_redacts_session_token` at supervisor.rs:5033 (Pitfall 3 — variant rename does not affect token-leak assertion).
- DIVERGENCE-LEDGER line 76 = current `split` disposition (Plan 45-01 ledger-flip target verified).
- `.github/workflows/phase-37-linux-resl.yml` exists at expected path (Plan 45-03 analog confirmed).

**Cross-checked against:**
- CONTEXT.md (45-CONTEXT.md) — every D-45-* item honored.
- RESEARCH.md (45-RESEARCH.md) — Plan 45-02 Cascade Map at § lines 504-526 cross-referenced; 23 ±2 test count flagged at planner discretion.
- CLAUDE.md § Coding Standards, § Library vs CLI Boundary, § Security Considerations — all applicable directives surfaced in § Shared Patterns.
