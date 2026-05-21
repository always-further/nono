---
phase: 45
phase_name: source-migration-aipc-g-04-resl-native-re-validation
gathered: 2026-05-21
status: Ready for planning
requirements_locked_via: REQUIREMENTS.md § REQ-PORT-CLOSURE-08 + REQ-AIPC-G04-01 + REQ-RESL-NIX-04 (no SPEC.md — phase has explicit success criteria in ROADMAP.md)
---

# Phase 45: Source migration + AIPC G-04 + RESL native re-validation - Context

**Gathered:** 2026-05-21
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 45 closes three Rule-4 architectural items deferred for multiple milestones. All three are independent surface-touch operations bundled into a single phase to avoid three single-purpose phases. Surfaces are disjoint, so the three plans run as a single parallel wave.

1. **REQ-PORT-CLOSURE-08 — Cluster 2 Edition 2024 source migration (Plan 45-01).** Replay the 39 `#[unsafe(no_mangle)]` rewrites from upstream commit `79715aa5` across `bindings/c/src/` (6 files: `capability_set.rs` ×16, `fs_capability.rs` ×7, `state.rs` ×5, `lib.rs` ×4, `query.rs` ×4, `sandbox.rs` ×3). Deferred from Phase 43 Plan 43-01b DEC-3 per the `split` disposition recorded at DIVERGENCE-LEDGER commit `79715aa5` — workspace edits (MSRV 1.95, nix/landlock/getrandom workspace deps) landed in v2.5; this closes the source-file portion. Plan 45-01 close flips Cluster 2 disposition `split → closed`.

2. **REQ-AIPC-G04-01 — AIPC G-04 wire-protocol compile-time tightening (Plan 45-02).** Inline `ResourceGrant` into `ApprovalDecision::Granted` and rename `Granted → Approved`, producing the wire shape `ApprovalDecision::Approved(ResourceGrant)`. Drop the now-redundant `grant: Option<ResourceGrant>` field from `SupervisorResponse::Decision`. The cascade touches: the wire type in `crates/nono/src/supervisor/types.rs`, the `aipc_sdk.rs` child SDK demultiplexer at 5 push sites, 23 pre-existing tests that depended on the `(Granted, grant=None)` shape, the audit_commands.rs:867 test fixture, and the AUD-05 token-redaction regression (`recorded_ledger_redacts_session_token`) which must still pass. Deferred from v2.1 Plan 18.1-02; reaffirmed at v2.3, v2.4, v2.5 scope-locks.

3. **REQ-RESL-NIX-04 — Phase 38 REQ-AAHX-HOST-01 native re-validation (Plan 45-03).** Tactical confirmation pass: verify the audit-attestation transitive coverage shipped in Phase 27.2 holds on a native Linux + macOS host. Host-blocked from this Windows dev host since v2.4 close. Plan 45-03 authors `.github/workflows/phase-45-resl-native-host.yml` (`workflow_dispatch`-only matrix on `ubuntu-24.04` + `macos-latest`) plus the verification protocol doc; the live CI run is deferred to the Phase 46 orchestrator action that already coordinates the post-merge CI verifications (REQ-CI-FU-01/02/03). SC#3 explicitly says this requirement does not block phase close if no gap is found.

**Three plans, parallel-safe (per D-45-A1):**

- **Plan 45-01** — `chore(45-01): bindings/c/src/ Edition 2024 source migration` — touches `bindings/c/src/{capability_set,fs_capability,lib,query,sandbox,state}.rs` + `.planning/upstream/DIVERGENCE-LEDGER.md` (or equivalent ledger location) + cbindgen-generated `nono.h` (byte-identical gate).
- **Plan 45-02** — `feat(45-02): inline Approved(ResourceGrant) in CapabilityDecision wire type` — touches `crates/nono/src/supervisor/types.rs` (wire), `crates/nono/src/supervisor/mod.rs` (re-exports), `crates/nono-cli/src/exec_strategy_windows/supervisor.rs` (5 push sites + dispatcher), `crates/nono-cli/src/audit_integrity.rs`, `crates/nono-cli/src/audit_commands.rs` (fixture line 867), `crates/nono-cli/tests/adr_aipc_unix_futures.rs`, `aipc_sdk.rs` (child SDK demultiplexer; planner locates the canonical path), the 23 pre-existing tests (planner inventories at plan-open via `grep -rn "ApprovalDecision::Granted\|grant: Option\|(Granted, grant=None)" crates/ bindings/`), CHANGELOG.md (BREAKING entry), `docs/architecture/audit-bundle-target.md` (ADR amendment).
- **Plan 45-03** — `feat(45-03): phase-45 RESL native re-validation workflow + protocol` — adds `.github/workflows/phase-45-resl-native-host.yml` (NEW) + `.planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-03-NATIVE-RESL-PROTOCOL.md` (NEW). REQ-RESL-NIX-04 closes as STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN; 45-VERIFICATION.md records the live-run hand-off to Phase 46.

**Phase 44 ⇄ Phase 45 sequencing:** ROADMAP declares Phase 44 + 45 parallel-safe. Phase 44 shipped (commits `aa510098` REVIEW polish + `dde9f3e1` health-check audit + `98315791` test hygiene + Phase 44.1 OIDC remediation closed at HEAD). Phase 45 inherits Phase 44 close SHA `aa510098` as the v2.6 quiet-baseline anchor for the baseline-aware CI gate (per D-44-E1).

**In scope:**
- All 39 `#[unsafe(no_mangle)]` rewrites in `bindings/c/src/` per D-45-B1/B2/B3.
- The atomic `ApprovalDecision::Granted → Approved(ResourceGrant)` flip per D-45-C1/C2/C3, including all 23 dependent tests, the `aipc_sdk.rs` demultiplexer, the audit_commands.rs:867 fixture, CHANGELOG BREAKING entry, ADR amendment.
- `.github/workflows/phase-45-resl-native-host.yml` + `45-03-NATIVE-RESL-PROTOCOL.md` per D-45-D1/D2.
- DIVERGENCE-LEDGER amendment at Plan 45-01 close per D-45-B2.
- REQUIREMENTS.md checkbox flips: `[ ] → [x]` for REQ-PORT-CLOSURE-08, REQ-AIPC-G04-01, REQ-RESL-NIX-04 (the latter as PARTIAL — STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN).
- Cross-target clippy verification on Linux + macOS targets for any Plan 45-01 / 45-02 commit touching cfg-gated code (per D-44-E2 carry-forward).

**Out of scope (route elsewhere or explicitly defer):**
- **Phase 46 surfaces** — `windows-squash` → `main` merge, post-merge CI verifications (REQ-CI-FU-01/02/03), Phase 35+36 human-UAT backlog (REQ-UAT-BL-01/02), the live run of Plan 45-03's workflow. Sequential after Phase 45 close.
- **Phase 47 / 48 surfaces** — UPST6 audit + sync execution + v0.41–v0.43 drift ingestion. Sequential after Phase 46.
- **Custom `Deserialize` for legacy ledger backward compat (rejected at D-45-C2).** Pre-v2.6 `audit-events.ndjson` files become non-re-verifiable after Phase 45 — accepted as a documented BREAKING change per the AUD-02 fresh-session invariant. No `nono audit migrate` subcommand. No `serde(untagged)` bridging.
- **`is_granted()` → `is_approved()` method rename on the `ApprovalDecision` impl.** Folded into Plan 45-02 atomic commit per D-45-C3 spirit (planner discretion on exact spelling — the impl in `crates/nono/src/supervisor/types.rs:405-417` currently has `is_granted()` + `is_denied()`; rename only if a callsite blocks compile, otherwise planner discretion).
- **Phase 44 follow-up todos (`44-class-d-validator-preflight-investigation.md`, `44-validate-restore-target-fd-relative-hardening.md`).** Both surfaced by `todo.match-phase 45` with low confidence (0.6 score, keyword-only). Tagged for Phase 46+ Linux-host phase per Phase 44 CONTEXT § Deferred Ideas. Not folded.
- **Variant-naming drift cleanup elsewhere in the codebase** (e.g., supervisor.rs comments at 1995, 2000, 3580 use "Approved" while the enum is `Granted` until Plan 45-02). Plan 45-02's rename closes this drift at the wire and the comments may need touch-ups; planner sweeps as discovered.
- **Project-wide `is_granted()` ergonomic alias retention.** If the rename causes meaningful test churn beyond the 23 known sites, planner may surface as a deviation; default disposition: rename in-place.

</domain>

<decisions>
## Implementation Decisions

### Plan slicing & parallelism (Area A — discussed)

- **D-45-A1: Three plans, parallel-safe.** 45-01 Edition 2024 source migration (REQ-PORT-CLOSURE-08), 45-02 AIPC G-04 wire-protocol tightening (REQ-AIPC-G04-01), 45-03 RESL native re-validation (REQ-RESL-NIX-04). Surfaces disjoint; each plan owns exactly one requirement; per-plan SUMMARY + per-plan REQ closure. Plan 45-03 has different execution semantics (host-blocked, workflow-only artifacts) but same plan shape. Mirrors Phase 44 D-44-A1 pattern scaled to three sub-streams. **User explicitly chose** option (a) "3 plans parallel-safe" over (b) "2 plans (Edition 2024 + bundled AIPC/RESL)" and (c) "1 mega-plan covering all three sub-streams" — the rejected mega-plan option matches Phase 44 D-44-A1 option (b) which the user rejected then too, confirming the slicing preference.

- **D-45-A2: Plan 45-01 commits = one per file (6 commits).** One commit per `bindings/c/src/` file: `capability_set.rs` (16 sites), `lib.rs` (4 sites), `fs_capability.rs` (7 sites), `sandbox.rs` (3 sites), `state.rs` (5 sites), `query.rs` (4 sites). Easiest review-per-file; clean bisect on any FFI regression; matches Phase 41/44 "one commit per class" pattern. **User explicitly chose** option (a) over (b) "single atomic mechanical commit" and (c) "one commit per pub-surface category (3 commits)".

### Edition 2024 disposition (Area B — discussed)

- **D-45-B1: D-20 manual replay, no upstream PR.** Each commit is `chore(45-01):` with a free-form `Replay-of: 79715aa5 (Phase 43 Plan 43-01b DEC-3 split-disposition close)` annotation in the commit body (NOT a `Upstream-commit:` D-19 trailer block — Plan 45-01 is closing a previously-split upstream commit, not a fresh upstream cherry-pick). The Edition 2024 syntax change already exists in upstream main; Phase 45 catches the fork up. No upstream PR umbrella because there's nothing to contribute upstream — this is fork-side syntax conformance. Mirrors Phase 40 D-20 pattern. **User explicitly chose** option (a) over (b) "D-19 cherry-pick with path-filtered cherry-pick of 79715aa5" and (c) "fork-internal chore(45-01) with no upstream attribution".

- **D-45-B2: DIVERGENCE-LEDGER amended at Plan 45-01 close (single commit).** A final Plan 45-01 commit amends the ledger to flip Cluster 2 disposition `split → closed` with back-reference to commit `79715aa5` AND to the Phase 45 commit range. Plan 45-01 SUMMARY records the amendment SHA. Mirrors the Phase 43 mid-flight amendment pattern (the `79715aa5` ledger commit). **User explicitly chose** option (a) over (b) "at Phase 45 close (single ledger commit)" and (c) "per-commit (inline in each of the 6 file commits)".

- **D-45-B3: Non-mechanical surprises absorbed in per-file commits + cbindgen `nono.h` byte-identical gate.** Edition 2024 may surface non-mechanical requirements (e.g., `unsafe extern "C"` block wrapping for declarations, new `unsafe fn` body-elision rules, `cbindgen`-regenerated `nono.h` differences). If a file's rewrite surfaces a non-mechanical change, fold it into that file's commit body with an inline explanation. After all 6 commits, regenerate `nono.h` via `cargo build -p nono-ffi` (or workspace build) and assert byte-identical to the pre-phase `nono.h` — Edition 2024 syntax changes should not change C header output. If the header diffs, that is a Plan 45-01 deviation — surface to user, do not auto-close. **User explicitly chose** option (a) over (b) "treat non-mechanical changes as out-of-scope; defer to follow-up phase" and (c) "absorb non-mech changes silently; no header verification".

### AIPC G-04 migration shape (Area C — discussed)

- **D-45-C1: Single atomic commit for the AIPC G-04 cascade.** All changes land together — wire type, `aipc_sdk.rs` demultiplexer, all 23 tests, audit_commands.rs:867 fixture, AUD-05 verification. Single commit because SC#2's compile-time guarantee requires the cascade to be atomic — a partial migration is by design a build break. Commit message body lists touched test files; the AUD-05 regression test (`recorded_ledger_redacts_session_token`) is called out as verified-pass. Tag: `feat(45-02):`, not `chore:` — real production wire-type change. **User explicitly chose** option (a) over (b) "two-commit pipeline (wire + sdk in commit 1, tests in commit 2)" (which would break build at commit 1) and (c) "test-first prep + atomic flip (2 commits with helper)" (more code churn for marginal bisect benefit).

- **D-45-C2: Accept the wire-format break; old ledgers no longer re-verifiable.** Pre-Phase-45 `audit-events.ndjson` files with the old `{"decision":{"Granted":null},"grant":{...}}` shape cannot be re-verified by `nono audit verify` after upgrade. Document in CHANGELOG.md (v2.6 / Phase 45 BREAKING entry) and append an ADR amendment to `docs/architecture/audit-bundle-target.md`. AUD-05 token-redaction regression-tests on FRESH sessions; the Phase 22 AUD-02 invariant (`audit verify` reproduces the Merkle root) remains valid for v2.6+ sessions. Audit-attestation is session-fresh by design — replay of pre-upgrade ledgers is a documented limitation, not a security regression. Rejected: custom `Deserialize` accepting both shapes (would lock in deserializer-level-but-not-wire-level invariant for one milestone — adds 30 LOC + tests + tagged removal at v2.7); rejected: `nono audit migrate` one-time tool (~100 LOC + new subcommand + integrity-rewrites-Merkle-root concern). **User explicitly chose** option (a) over (b) "custom Deserialize accepting both shapes for one milestone" and (c) "write a one-time migration tool".

- **D-45-C3: Rename `Granted → Approved` in the atomic commit.** The current Rust enum is `ApprovalDecision::Granted` (no serde rename, wire JSON literally serializes as `{"Granted":...}`); SC#2 wording, Phase 23 D-01 comments, the audit_commands.rs:867 fixture line, and the conventional security terminology all use "Approved". The rename is folded into Plan 45-02's atomic commit per D-45-C1. The wire-format break is already happening; folding the rename in costs ~10 extra LOC and prevents future code-vs-wire drift. PROJECT.md's v2.1 PROF-01..04 / AUD-01..05 sections also use "Approved" throughout. **User explicitly chose** option (a) over (b) "keep `Granted`; inline `ResourceGrant` only" (which would lock in the naming drift permanently).

### RESL native re-validation host strategy (Area D — discussed)

- **D-45-D1: Author `.github/workflows/phase-45-resl-native-host.yml` + protocol doc; defer live run to Phase 46.** Plan 45-03 produces: (1) new GHA workflow invoking `cargo test --workspace --test audit_attestation -- --include-ignored` on a matrix of `ubuntu-24.04` + `macos-latest`; (2) `45-03-NATIVE-RESL-PROTOCOL.md` documenting the verification protocol + expected outputs + SC#3 option (a)/(b) decision tree (coverage matches OR gap surfaced with documented follow-up); (3) `workflow_dispatch`-triggered invocation. REQ-RESL-NIX-04 closes as STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN per `.planning/templates/cross-target-verify-checklist.md` semantics. Phase 46 orchestrator action invokes the workflow live and records the verdict in 45-VERIFICATION.md or 46-VERIFICATION.md. Mirrors Phase 37's `phase-37-linux-resl.yml` pattern, scaled down to manual trigger because the verification is tactical/one-time, not permanent CI lane. **User explicitly chose** option (a) over (b) "close REQ-RESL-NIX-04 as PARTIAL with documented deferral; no new artifacts" and (c) "run live via GitHub Actions during this phase (push branch + monitor)".

- **D-45-D2: `workflow_dispatch`-only trigger with `gh_runner_os` matrix input.** Workflow exposes `workflow_dispatch` with an input `gh_runner_os: { type: choice, options: [ubuntu-24.04, macos-latest, both], default: both }`. Doesn't burn CI minutes on every PR; Phase 46 orchestrator runs once with `gh workflow run phase-45-resl-native-host.yml -f gh_runner_os=both` to record the verdict. Workflow may be deleted in v2.7 once the verdict is recorded — explicit tactical artifact, not a permanent CI lane. **User explicitly chose** option (a) over (b) "always-on (pull_request + push to main), like phase-37-linux-resl.yml" and (c) "workflow_dispatch + scheduled weekly".

### Claude's Discretion

- **Exact paths for `aipc_sdk.rs`.** Plan 45-02 D-45-C1 names `aipc_sdk.rs` as the child SDK demultiplexer location; planner locates the canonical path at plan-open via `grep -rln "aipc_sdk" crates/`. Two files are known to contain references: `crates/nono-cli/tests/adr_aipc_unix_futures.rs` and `crates/nono/src/supervisor/mod.rs`.

- **23 pre-existing test inventory.** Plan 45-02 D-45-C1 references "23 pre-existing tests"; planner inventories at plan-open via `grep -rn "ApprovalDecision::Granted\|grant: Option\|(Granted, grant=None)" crates/ bindings/`. Inline the count + file list in the PLAN.md task table; if inventory differs from 23 by more than ±2, surface as a deviation to confirm scope.

- **CHANGELOG.md entry placement + exact wording.** D-45-C2 mandates a BREAKING entry; planner picks the heading level + exact wording (the preview shown in discussion is illustrative not binding). Must include: the BREAKING marker, the affected wire shape change, the fresh-session vs replay distinction, the ADR back-reference.

- **`docs/architecture/audit-bundle-target.md` ADR amendment shape.** D-45-C2 says "append ADR amendment 45-X"; planner picks whether to add a new ADR section, append to existing Phase 27.2 follow-ups (v2.5-FU-1, v2.5-FU-2), or land a new sibling ADR. Default: append as a new dated subsection with the amendment number Phase 45 picks (likely 45-A or 45-1).

- **`is_granted()` / `is_denied()` impl method renames.** `ApprovalDecision` has `impl` methods `is_granted()` and `is_denied()` at `crates/nono/src/supervisor/types.rs:405-417`. D-45-C3 spirit is to align with `Approved` terminology; planner picks whether `is_granted()` becomes `is_approved()` (recommended) or stays for callsite ergonomics. If renamed, sweep callsites; if kept, add a `// Renamed Granted → Approved at Phase 45; method name retained for ergonomics` comment.

- **`.github/workflows/phase-45-resl-native-host.yml` matrix specifics.** D-45-D1 names ubuntu-24.04 + macos-latest; planner picks the exact `runs-on` strings, the `continue-on-error: true` per-OS shape (so one OS green is sufficient per SC#3 "one or both per host availability"), and the cache + setup-action choices (default: mirror Phase 37 workflow's actions/setup-rust + actions/cache shape).

- **`45-03-NATIVE-RESL-PROTOCOL.md` content depth.** D-45-D1 names the file; planner picks the depth — minimum: SC#3 decision tree, expected `cargo test` output shape, Phase 46 hand-off instructions. Could optionally include comparison-to-Phase-27.2 transitive-closure mapping (since Phase 38 was originally a "Phase 27 reopen").

- **cbindgen header byte-identical gate mechanics.** D-45-B3 says "regenerate `nono.h` via `cargo build -p nono-ffi`"; planner picks whether to capture the pre-phase `nono.h` to a temporary location and `diff` post-phase, or use `git diff bindings/c/nono.h` after the build. Either is acceptable.

- **Plan numbering.** Plans 45-01 + 45-02 + 45-03 follow the `{padded_phase}-{NN}-{theme}` convention. Suggested slugs: 45-01-EDITION-2024-MIGRATION, 45-02-AIPC-G04-TIGHTENING, 45-03-RESL-NATIVE-REVALIDATION. Planner may refine.

### Folded Todos

No todos folded in Phase 45. The two matches surfaced by `todo.match-phase 45` (both score 0.6, keyword-only) are reviewed below as deferred.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase 45 scope sources
- `.planning/REQUIREMENTS.md` § REQ-PORT-CLOSURE-08, REQ-AIPC-G04-01, REQ-RESL-NIX-04 — Acceptance criteria for the 3 in-phase requirements.
- `.planning/ROADMAP.md` § Phase 45 — Goal + dependencies + 5 success criteria + Cross-Phase Invariants section.
- `.planning/PROJECT.md` § v2.6 UPST6 + v2.5 Drain — milestone context, target features, deferred items.
- `.planning/MILESTONES.md` — v2.5 archive context (Phase 43 split-disposition origin for Cluster 2).

### Edition 2024 migration sources (Plan 45-01)
- **Upstream commit `79715aa5`** — original source of the 39 `#[unsafe(no_mangle)]` rewrites. Workspace edits (MSRV 1.95, nix/landlock/getrandom workspace deps) landed in v2.5; `bindings/c/src/` source migration is the deferred portion Plan 45-01 closes.
- `.planning/phases/43-upst5-sync-execution/43-01b-SUMMARY.md` — Phase 43 Plan 43-01b DEC-3 split-disposition decision and `windows-squash`/`main` mid-flight reclassification (commit `79715aa5` ledger amendment); the source-file migration deferral notes are in DEC-3.
- `.planning/phases/43-upst5-sync-execution/43-CONTEXT.md` § DIVERGENCE-LEDGER cluster isolation — Cluster 2 `will-sync → split` reclassification rationale (memory `feedback_cluster_isolation_invalid` empirical lesson; codified at v2.5 close).
- `.planning/upstream/DIVERGENCE-LEDGER.md` (or equivalent ledger location — planner verifies at plan-open) — Cluster 2 row to amend `split → closed` per D-45-B2.

### AIPC G-04 migration sources (Plan 45-02)
- `crates/nono/src/supervisor/types.rs:198-211` — current `ApprovalDecision` enum (the rename target); `:474-495` — current `SupervisorResponse::Decision` with the to-be-deleted `grant: Option<ResourceGrant>` field; `:243-261` — `ResourceGrant` struct definition (the to-be-inlined payload).
- `crates/nono-cli/src/audit_integrity.rs:80-94` — `AuditEventPayload::CapabilityDecision { entry, reject_stage }` — the indirect site (does not change but its serialized form changes through `AuditEntry::decision`).
- `crates/nono-cli/src/audit_integrity.rs:208-227` — `record_capability_decision` recorder (audit ledger write site; AUD-05 verifies token redaction here).
- `crates/nono-cli/src/exec_strategy_windows/supervisor.rs:1995-2010,2594,3580,3562` — comments documenting the `(Approved, grant=None)` invariant that becomes structurally unreachable post-Phase 45.
- `crates/nono-cli/src/audit_commands.rs:867` — test fixture line currently using `"decision":{"Approved":null}` via `serde_json::Value` workaround; post-rename, this becomes the type-checked shape.
- **v2.1 Phase 18.1 — original AIPC G-04 deferral context:**
  - `.planning/phases/18.1-extended-ipc-gaps/18.1-02-SUMMARY.md` — original deferral; G-04 cited as "compile-time tightening cascades into 23 tests".
  - `.planning/phases/18-extended-ipc/18-04-SUMMARY.md`, `18-03-SUMMARY.md`, `18-02-SUMMARY.md`, `18-01-SUMMARY.md` — Phase 18 AIPC-01 baseline shape that G-04 closes the structural gap of.
- **Phase 23 — Windows audit-event retrofit (CapabilityDecision recorder ancestor):**
  - `.planning/phases/23-windows-audit-event-retrofit/23-01-SUMMARY.md` — Phase 23 D-01 (audit recorder threading) + D-02 (RejectStage discriminator); the `(Approved, grant=None)` flip at supervisor.rs:1997 documented in this phase. AUD-05 originated here.
- **Phase 29 — WR-01 reject-stage unification (locks Approved ⟹ grant=Some invariant as design property):**
  - `.planning/phases/29-wr01-reject-stage-unification/29-01-SUMMARY.md` — D-29 lock that `is_granted ⟹ grant=Some`; Phase 45 is the structural enforcement of this invariant at the wire type.
- **AUD-05 token-redaction regression:** Phase 22 Plan 22-05a closure; canonical test `recorded_ledger_redacts_session_token` in `crates/nono-cli/src/audit_integrity.rs` tests module.
- `docs/architecture/audit-bundle-target.md` — existing AUD ADR; Plan 45-02 appends amendment 45-X per D-45-C2.
- `CHANGELOG.md` — Plan 45-02 adds a BREAKING entry per D-45-C2.

### RESL native re-validation sources (Plan 45-03)
- **Phase 38 / Phase 27 reopen origin:**
  - `.planning/PROJECT.md` § Active (v2.3) → REQ-AAHX-01..03 close — Phase 27.2 transitive closure that Plan 45-03 re-validates.
  - `.planning/PROJECT.md` § v2.4 archive → Phase 37/38 Theme 2 carry-forward; Phase 38 was "Phase 27 reopen — REQ-AAH-01 native re-validation".
- **Phase 27.2 audit-attestation closure (transitive close for REQ-AAH-01 + REQ-NTH-03):**
  - `.planning/phases/27.2-audit-attestation-test-re-enablement/27.2-VERIFICATION.md` — 16/16 must-haves verified; baseline for "(a) coverage matches" verdict per SC#3.
- **Phase 37 workflow precedent (`.github/workflows/phase-37-linux-resl.yml`):**
  - The pattern Plan 45-03 mirrors: matrix runner, `cargo test` invocation, `RUSTFLAGS: -Dwarnings`, baseline-aware CI gate. Plan 45-03 scales DOWN to `workflow_dispatch` per D-45-D2; otherwise mirrors layout.
- `.planning/templates/cross-target-verify-checklist.md` — STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN closure semantics for REQ-RESL-NIX-04 per D-45-D1.
- **Audit-attestation test surface:**
  - `crates/nono-cli/tests/audit_attestation.rs` (Phase 27.2 re-enabled tests); the `cargo test --workspace --test audit_attestation -- --include-ignored` invocation Plan 45-03 wires into the workflow. Planner verifies path at plan-open.

### Phase 44 carry-forward context (binding — locked, not for re-discussion)
- `.planning/phases/44-review-polish-test-hygiene-drain/44-CONTEXT.md` § Carry-forward from Phase 41 / 43 — D-44-E1 through D-44-E7. Phase 45 inherits these.
- `.planning/phases/44-review-polish-test-hygiene-drain/44-01-SUMMARY.md` + `44-02-SUMMARY.md` — Phase 44 close artifacts.
- `.planning/phases/44.1-oidc-fail-closed-remediation-req-review-fu-01-t-44-01-cr-01/44.1-01-oidc-fail-closed-remediation-SUMMARY.md` — Phase 44.1 head SHA reset closure (T-44-01 CLOSED).
- **v2.6 quiet-baseline anchor SHA: `aa510098`** (Phase 44 close commit `docs(phase-44.1): add validation strategy (retroactive Nyquist audit)` — or whichever is the canonical "Phase 44 + 44.1 close" tip at plan-open; planner verifies via `git log --oneline -10`). Baseline-aware CI gate inherits per D-44-E1.

### Cross-phase invariants (inherited from ROADMAP § Cross-Phase Invariants)
- `.planning/ROADMAP.md` § Cross-Phase Invariants:
  - **D-19 trailer convention** — NOT applicable to Plan 45-01 (D-20 manual replay per D-45-B1) or Plan 45-02 (fork-internal architectural decision) or Plan 45-03 (verification, not contribution).
  - **D-34-E1 / D-40-E1 / D-43-E1 Windows-only-files invariant** — Plan 45-01 touches `bindings/c/src/` (cross-platform, NOT Windows-only). Plan 45-02 touches `exec_strategy_windows/supervisor.rs` BUT only at the wire-type usage sites that are unavoidable for the rename + inline cascade (NOT new Windows-only code; existing Windows-only callsite updates). Plan 45-03 touches `.github/workflows/` (CI infra). No codified addendum exceptions required.
  - **CLAUDE.md "lazy use of dead code"** — Plan 45-02 removes the `grant: Option<ResourceGrant>` field; planner verifies no `#[allow(dead_code)]` is required on removed surface.
  - **Cross-target clippy verification protocol** — Plan 45-02 touches `exec_strategy_windows/supervisor.rs` (Windows cfg-gated) and `crates/nono/src/supervisor/types.rs` (cross-platform); cross-target clippy MUST run on `x86_64-unknown-linux-gnu` AND `x86_64-apple-darwin` from the Windows dev host. If cross-toolchain unavailable, mark related verification REQ as PARTIAL per `.planning/templates/cross-target-verify-checklist.md`.
  - **DIVERGENCE-LEDGER cluster isolation** — relevant to Plan 45-01 only (Cluster 2 `split → closed` per D-45-B2).
- `.planning/templates/upstream-sync-quick.md:102` — Baseline-aware CI gate SHA (currently Phase 41 close `13cc0628`; Phase 45 inherits the Phase 44 quiet-baseline anchor `aa510098`). Plan 45-01 + 45-02 gate against this until Phase 46 post-merge moves it.
- `.planning/templates/cross-target-verify-checklist.md` — MANDATORY for any Plan 45-01 / 45-02 commit touching cfg-gated Unix or Windows code per D-44-E2 carry-forward.

### Coding & security standards (CLAUDE.md)
- `CLAUDE.md` § Coding Standards — no `.unwrap()`/`.expect()`; `#[must_use]` on critical Results; DCO sign-off (`Signed-off-by:` lines on every commit); cross-target clippy MUST/NEVER rule for cfg-gated Unix code; env-var save/restore in tests.
- `CLAUDE.md` § Security Considerations — fail secure on any unsupported shape; explicit over implicit. Plan 45-02 specifically: `Approved(ResourceGrant)` enforces "Approved ⟹ grant is Some" structurally — this IS a defense-in-depth security property elevation.
- `CLAUDE.md` § Library vs CLI Boundary — `bindings/c/src/` is library-FFI surface; Plan 45-01 syntax conformance must not introduce CLI-policy concepts into the FFI layer.
- `CLAUDE.md` § Platform-Specific Notes — Edition 2024 + `#[unsafe(no_mangle)]` is a cross-platform requirement; Plan 45-01 must not break either Landlock (Linux) or Seatbelt (macOS) builds.

### Memory anchors
- Memory `feedback_clippy_cross_target` — Cross-target Linux + macOS clippy from Windows host (MUST for Plan 45-01 + 45-02 per D-44-E2 carry-forward).
- Memory `project_workspace_crates` — Workspace has 5 crates, not 3. Plan 45-01 likely does NOT touch any workspace Cargo.toml (mechanical source rewrite only). Plan 45-02 may need to verify the wire-type change cascades through all 5 crate `Cargo.toml` version pins if a workspace `version` bump is warranted by the BREAKING change; planner discretion at plan-open.
- Memory `feedback_cluster_isolation_invalid` — Phase 43 lesson hardened at v2.5 close that `split` is a valid fourth audit-cluster disposition. Plan 45-01's `split → closed` flip is the natural follow-up that closes the split lineage.
- Memory `project_cross_fork_pr_pattern` — Fork uses ONE umbrella PR to upstream per phase. NOT applicable to Phase 45 (D-45-B1 says no upstream PR; Plan 45-02 is fork-internal; Plan 45-03 is verification artifacts).
- Memory `gh_available` — `gh` command usable for Phase 46 orchestrator `gh workflow run phase-45-resl-native-host.yml` invocation per D-45-D2.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets

- **`bindings/c/build.rs` + `bindings/c/cbindgen.toml`** — existing cbindgen header generator. Plan 45-01 D-45-B3 byte-identical gate uses this build step to regenerate `nono.h` post-migration and assert no diff.
- **`crates/nono/src/supervisor/types.rs:243-261` `ResourceGrant` struct** — already canonical wire shape; Plan 45-02 inlines it into `ApprovalDecision::Approved(ResourceGrant)` without changes to the struct itself.
- **`crates/nono/src/supervisor/types.rs:405-417` `impl ApprovalDecision`** — `is_granted()` + `is_denied()` helpers; planner discretion on rename per D-45-C3 spirit.
- **`crates/nono-cli/src/audit_integrity.rs` `AuditRecorder` + `record_capability_decision`** — existing recorder, no shape change needed; the `AuditEntry::decision` field carries the new variant transparently via serde.
- **`crates/nono-cli/src/audit_integrity.rs` `recorded_ledger_redacts_session_token` (AUD-05 regression test)** — must pass post-migration per Plan 45-02 acceptance.
- **`.github/workflows/phase-37-linux-resl.yml`** — workflow precedent for Plan 45-03; mirrors layout (matrix, RUSTFLAGS, actions/setup, cargo cache) but scales DOWN to `workflow_dispatch`.
- **`.planning/templates/cross-target-verify-checklist.md`** — STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN closure semantics for Plan 45-03 REQ-RESL-NIX-04 status.
- **`.planning/templates/upstream-sync-quick.md`** — baseline-aware CI gate SHA registry; Phase 45 inherits Phase 44 quiet-baseline anchor `aa510098`.
- **`crates/nono-cli/src/audit_commands.rs::read_capability_decisions_from_ledger`** — existing best-effort line-by-line ledger reader; the wire-format break per D-45-C2 means pre-Phase-45 ledger lines will fail to deserialize through this reader.

### Established Patterns

- **One commit per file boundary in mechanical sweeps (D-44-A4 / D-45-A2).** Plan 45-01's 6 commits follow this pattern.
- **Single atomic commit when wire-type changes are compile-coupled (D-45-C1).** Plan 45-02 commit shape mirrors Phase 32 D-32-15 single-atomic precedent for the TUF cached-root rewrite.
- **D-20 manual replay with `Replay-of:` annotation, no `Upstream-commit:` trailer (D-45-B1).** New pattern derived from Phase 40 D-20 + Phase 43 split-disposition convention; Plan 45-01 codifies the spelling.
- **DIVERGENCE-LEDGER amendment at plan-close commit (D-45-B2).** Mirrors Phase 43 mid-flight amendment at commit `79715aa5`.
- **STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN requirement-closure pattern (D-45-D1).** Inherits the Phase 37 / Phase 44 cross-target clippy precedent: ship the workflow + protocol, defer the live run to orchestrator-coordinated phases.
- **`workflow_dispatch`-only tactical workflow (D-45-D2).** New pattern; Plan 45-03 is the first phase to use this shape (Phase 37 was always-on; Phase 41 work was also always-on). Deletable in v2.7 once verdict is recorded.
- **BREAKING wire-format changes documented in CHANGELOG + ADR amendment (D-45-C2).** Existing pattern: AUD-02 wire format documented in `docs/architecture/audit-bundle-target.md`; Plan 45-02 appends amendment.
- **Cross-target clippy required for cfg-gated Unix code (D-44-E2 / CLAUDE.md MUST/NEVER).** Inherits to Plan 45-01 (`bindings/c/src/` cross-platform) and Plan 45-02 (`exec_strategy_windows/supervisor.rs` Windows cfg-gated).
- **Fork-internal feature branch + merge-to-main (D-44-E7 spirit).** Plan 45-01 + 45-02 + 45-03 all fork-internal; no upstream PR umbrella, no D-19 trailer.

### Integration Points

- **Phase 44 → Phase 45 (quiet-baseline inheritance).** Phase 44 + 44.1 close (head SHA at the Phase 45 plan-open time, currently `aa510098` per `git log -1` on `main`) becomes the v2.6 quiet-baseline anchor. Plan 45-01 + 45-02 commits gate against this baseline (no `success → failure` transitions); Plan 45-03 inherits transitively (no source-code changes that affect CI lanes).
- **Phase 45 → Phase 46 (CI verification deferral).** REQ-RESL-NIX-04 closes as STRUCTURALLY-COMPLETE-PENDING-LIVE-RUN per D-45-D1; the live workflow run is part of Phase 46's orchestrator coordination alongside REQ-CI-FU-01/02/03. Phase 46 deferred items inherit the explicit `gh workflow run phase-45-resl-native-host.yml -f gh_runner_os=both` action.
- **Phase 45 → Phase 47 (UPST6 audit baseline).** Plan 45-01 closes Cluster 2 disposition; Phase 47 UPST6 audit (upstream `v0.54.0..v0.55.0+` divergence) starts from the post-Phase-45 DIVERGENCE-LEDGER state where Cluster 2 is `closed`. No backward dependency.
- **Plan 45-01 ⇄ Plan 45-02 ⇄ Plan 45-03 (parallel, no inter-plan dependencies).** Surfaces fully disjoint:
  - 45-01 surface: `bindings/c/src/*.rs` (6 files) + `bindings/c/nono.h` (generated, byte-identical gate).
  - 45-02 surface: `crates/nono/src/supervisor/types.rs` + `crates/nono-cli/src/{exec_strategy_windows/supervisor.rs,audit_integrity.rs,audit_commands.rs}` + 23 test sites + `CHANGELOG.md` + `docs/architecture/audit-bundle-target.md`.
  - 45-03 surface: `.github/workflows/phase-45-resl-native-host.yml` (NEW) + `.planning/phases/45-.../45-03-NATIVE-RESL-PROTOCOL.md` (NEW).
- **Cross-binding cascade for the wire-format break (Plan 45-02).** Sibling repos `../nono-py/` + `../nono-ts/` use the FFI surface from `bindings/c/`; the wire-format change might surface there. Planner verifies at plan-open by checking sibling repo FFI consumers for `ApprovalDecision::Granted` / `Approved` references; if affected, surfaces as a deviation. Phase 44 D-44-D1 lockstep pattern remains available as a precedent.

### Phase 45 plan + commit map (final)

```
Plan 45-01 (Edition 2024 source migration)          Plan 45-02 (AIPC G-04 wire tightening)         Plan 45-03 (RESL native re-validation)
   │  7 commits: 6 per-file + 1 ledger flip            │  1 atomic commit (wire + sdk + 23 tests        │  2 commits: workflow + protocol doc
   │                                                   │                  + audit_commands fixture       │
   │                                                   │                  + CHANGELOG + ADR)            │
   │                                                   │                                                 │
   ├─ chore(45-01): bindings/c capability_set.rs       ├─ feat(45-02): inline Approved(ResourceGrant)    ├─ feat(45-03): workflow phase-45-resl
   │     Edition 2024 no_mangle  (16 sites)            │     in CapabilityDecision wire type            │     -native-host.yml (workflow_dispatch
   ├─ chore(45-01): bindings/c lib.rs                  │     - rename Granted → Approved                │      matrix on ubuntu-24.04 + macos-latest)
   │     Edition 2024 no_mangle  (4 sites)             │     - drop grant: Option<ResourceGrant>        └─ docs(45-03): 45-03-NATIVE-RESL-PROTOCOL.md
   ├─ chore(45-01): bindings/c fs_capability.rs        │     - update aipc_sdk.rs demultiplexer (5            (verification protocol + SC#3 decision tree)
   │     Edition 2024 no_mangle  (7 sites)             │       push sites)
   ├─ chore(45-01): bindings/c sandbox.rs              │     - update 23 pre-existing tests
   │     Edition 2024 no_mangle  (3 sites)             │     - update audit_commands.rs:867 fixture
   ├─ chore(45-01): bindings/c state.rs                │     - CHANGELOG.md BREAKING entry
   │     Edition 2024 no_mangle  (5 sites)             │     - docs/architecture/audit-bundle-target.md
   ├─ chore(45-01): bindings/c query.rs                │       ADR amendment 45-X
   │     Edition 2024 no_mangle  (4 sites)             │     - AUD-05 verified pass
   └─ chore(45-01): DIVERGENCE-LEDGER Cluster 2        │     Closes: REQ-AIPC-G04-01
         split → closed (79715aa5 close)

  Plan close: cbindgen nono.h byte-identical gate
  Closes: REQ-PORT-CLOSURE-08

Three plans land on a Phase 45 feature branch → merge to main per
the team's existing pattern (no upstream PR umbrella per D-45-B1 + Plan 45-02 fork-internal + Plan 45-03 verification artifacts).
```

</code_context>

<specifics>
## Specific Ideas

- **D-45-B1 chose D-20 manual replay over D-19 cherry-pick.** Rationale: the upstream commit `79715aa5` already exists in upstream main; Plan 45-01 is closing a previously-split disposition, not initiating a fresh cherry-pick. The `Replay-of:` annotation captures the lineage without overloading the `Upstream-commit:` trailer that signals fresh contributions.

- **D-45-C2 chose accept-the-break over backward-compat shenanigans.** Rationale: audit-attestation is session-fresh by design (Phase 27.2 ADR). Replay of pre-v2.6 ledgers is a documented limitation, not a security regression. The CHANGELOG BREAKING entry + ADR amendment make the contract explicit; users with v2.5 ledgers needing re-verification can pin to v2.5 binary.

- **D-45-C3 chose rename `Granted → Approved` in the atomic commit.** Rationale: the SC#2 wording, Phase 23 D-01 comments, the audit_commands.rs:867 fixture, and the conventional security terminology all use "Approved". The wire-format break is happening regardless; folding the rename in costs ~10 LOC and prevents future drift. SC#2's repeated use of "Approved" is interpreted as a rename mandate, not colloquial.

- **D-45-D1 chose author-workflow-defer-live-run over close-PARTIAL.** Rationale: producing the workflow artifact creates a real, reusable verification mechanism that Phase 46 can invoke explicitly. Closing PARTIAL with no artifact would lose the work; running live in this phase would require user-initiated push + CI wait (longer wall-clock; less orchestrable).

- **D-45-D2 chose workflow_dispatch-only over always-on.** Rationale: RESL re-validation is tactical confirmation, not a permanent CI lane. SC#3 explicitly says "tactical confirmation pass only — does not block phase close if no gap is found". Doesn't burn CI minutes; deletable in v2.7 once verdict is recorded.

</specifics>

<deferred>
## Deferred Ideas

- **`is_granted()` → `is_approved()` impl method rename ergonomics.** Plan 45-02 D-45-C3 spirit suggests renaming; planner discretion at plan-open. If kept as `is_granted()`, callsites stay ergonomic but introduce a new naming drift opposite the one Phase 45 closes. Default: rename for consistency unless callsite churn is substantial.

- **Project-wide `Granted` → `Approved` comment / docstring sweep beyond the Plan 45-02 atomic commit.** Several supervisor.rs comments (1995, 2000, 3580) currently say "Approved" while the enum was `Granted`; post-rename, the comments are correct. Other docstrings or comments may still use the inconsistent "approved" / "granted" terminology — planner-discretion sweep within Plan 45-02 boundaries; otherwise file follow-up todo for v2.7 cleanup.

- **One-time `nono audit migrate` tool for legacy ledger forward-port.** Rejected at D-45-C2 (~100 LOC + integrity rewrites Merkle root concern). Could be revisited in v2.7+ if user demand surfaces; tracked as a deferred follow-up.

- **Permanent always-on CI lane for audit-attestation native-host coverage.** Plan 45-03's workflow is tactical (workflow_dispatch only per D-45-D2). If post-Phase-45 experience shows audit-attestation is regression-prone on native hosts, a follow-up phase could promote the workflow to always-on (mirroring Phase 37 `phase-37-linux-resl.yml`).

- **Sibling-binding cascade verification for the wire-format break.** Plan 45-02's wire-type change might affect `../nono-py/` + `../nono-ts/` FFI consumers if either binding re-serializes `ApprovalDecision`. Planner verifies at plan-open; if affected, the Phase 44 D-44-D1 cross-binding lockstep pattern remains available as a precedent.

- **Cluster 2 DIVERGENCE-LEDGER amendment exact ledger location.** D-45-B2 says "amend the ledger"; planner verifies the canonical ledger path at plan-open (`.planning/upstream/DIVERGENCE-LEDGER.md` vs `.planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md` vs other location). Phase 42 + 43 historical refs should make this unambiguous.

### Reviewed Todos (not folded)

Two todos surfaced by `todo.match-phase 45` (both score 0.6, keyword-only matches):

- **`44-class-d-validator-preflight-investigation.md`** — Phase 44 D-44-C3 follow-up about `validate_deny_overlaps` pre-flight in `crates/nono-cli/src/policy.rs:1032-1088`. Not folded — Phase 44 CONTEXT § Deferred Ideas explicitly tags this for "a future Linux-host phase (Phase 46 or beyond)". Score-0.6 keyword match (`phase, plan, req, test, follow`) reflects the generic vocabulary of follow-up todos, not topical fit.
- **`44-validate-restore-target-fd-relative-hardening.md`** — Phase 44 D-44-B4 follow-up about TOCTOU hardening in `crates/nono/src/undo/snapshot.rs::validate_restore_target`. Not folded — Phase 44 CONTEXT § Deferred Ideas explicitly tags this as a "substantial cross-platform refactor: Linux + macOS + Windows have different fd-relative semantics" requiring its own security-scoped phase. Score-0.6 keyword match reflects the same generic vocabulary.

Both stay in `.planning/todos/pending/` for the appropriate future phase.

</deferred>

---

*Phase: 45-source-migration-aipc-g-04-resl-native-re-validation*
*Context gathered: 2026-05-21*
