---
phase: 26-pkg-streaming-followup
created: 2026-05-01
type: phase-context
---

# Phase 26 Context — PKG Streaming Follow-Up

## Two-plan split

Phase 26 closes the four PKGS reqs deferred from v2.2 Plan 22-03. The phase is split into two plans by execution-host requirement:

| Plan | Reqs | Host | Size | Risk |
|------|------|------|------|------|
| 26-01 — PKGS fork-arch | PKGS-02, PKGS-03 | Windows-OK | 875 lines, 6 tasks | low |
| 26-02 — PKGS streaming + auto-pull | PKGS-01, PKGS-04 | Linux/macOS preferred | 1054 lines, 8 tasks | medium |

**Plan 26-01 is the prerequisite for Plan 26-02** (`depends_on: [26-01]` in 26-02 frontmatter). 26-02's streaming refactor dispatches per-`ArtifactType` variant including `Plugin` (added by 26-01); landing 26-02 before 26-01 produces compile errors.

## Host preference rationale

**Plan 26-01 is Windows-OK** because it tests fork-architectural decisions (path validation + enum variant) entirely via unit tests. No `run_nono` integration tests; no real registry server; no streaming.

**Plan 26-02 prefers Linux/macOS host** for two reasons:

1. **Streaming RSS measurement is Linux-specific.** `proc_self_status` is the cleanest portable proxy for "memory profile peaks at ~10MB during a 200MB download." The plan's `streaming_200mb_artifact_under_50mb_rss` test is `#[cfg(target_os = "linux")]`-gated; macOS would need a different API or a portable proxy.
2. **Auto-pull e2e tests use `run_nono`** which hits the Phase 27 `dirs::home_dir()` Windows blocker (the harness ignores `USERPROFILE`). Plan 26-02's `auto_pull_loads_registry_pack_extends` test will fail on Windows for the same reason Phase 27's tests did.

**Workaround if Windows execution is required:** the v2.4 candidate "Windows test-harness HOME redirection" phase (proposed during Phase 27 close) lands a `NONO_TEST_HOME` production-code seam to `dirs::home_dir()` callsites. Once that ships, Plan 26-02 executes cleanly on Windows. Until then, queue Plan 26-02 execution for a Linux/macOS host alongside Plan 25-01 (RESL Unix) and Phase 27 resumption.

## Corrections from plan-time investigation

Both plans surfaced corrections to the v2.3 REQUIREMENTS.md / v2.2 backlog assumptions. These are recorded in the plans' `<interfaces>` blocks but flagged here for cross-plan visibility:

1. **`ArtifactType` enum has 6 variants today, not 5** (Plan 26-01 finding). The variants are Profile, Hook, Instruction, TrustPolicy, Groups, **Script**. Plan 26-01's PKGS-03 adds `Plugin` as the 7th variant (not 6th as the original v2.3 REQUIREMENTS.md implied). All match-arm sites need to gain a Plugin arm.

2. **`bundle_json` is currently a local variable, not a struct field** (both plans). At `crates/nono-cli/src/package_cmd.rs:425`, `bundle_json` is declared inline during artifact handling. Plan 26-02's PKGS-01 streaming refactor includes promoting it to a `pub bundle_json: Option<String>` field on `DownloadedArtifact`. Plan 26-01 explicitly defers this — Plan 26-01's PKGS-03 ArtifactType::Plugin work doesn't touch `bundle_json`.

3. **`tempfile` is already a runtime dependency** (Plan 26-02 finding). The original v2.3 REQUIREMENTS.md backlog mentioned "+ `tempfile::TempDir`" implying it would be added; verified that `tempfile = "3"` is at line 73 of `crates/nono-cli/Cargo.toml` already. Plan 26-02 Task 2 only adds `semver`; `tempfile` promotion is a no-op.

4. **The fork uses `ureq 3`, not `hyper`** (Plan 26-02 finding). The original v2.3 REQUIREMENTS.md REQ-PKGS-01 mentioned "streaming HTTP (chunked) through `hyper`". Verified that the fork's `crates/nono-cli/src/registry_client.rs` uses `ureq 3` (a different HTTP client crate). Plan 26-02 D-20 manual replay translates upstream's hyper streaming patterns to ureq 3 API (`into_body().into_reader()` or `body_mut().as_reader()` — exact API resolved at execute time).

5. **`NonoError::ArtifactTooLarge` placement is a Rule-4 architectural decision** (Plan 26-02 finding). Adding it to `crates/nono/src/error.rs` would break D-19 byte-identical preservation of the nono crate. Plan 26-02 Task 3 documents two paths:
   - **Path A (accept the D-19 break):** add `ArtifactTooLarge { actual: u64, max: u64 }` variant to `NonoError` with explicit `Upstream-commit:` provenance trailer. Recorded as a deviation.
   - **Path B (refactor to RegistryError payload):** keep `NonoError` byte-identical; add a new `RegistryError` enum in `nono-cli` that wraps the size-limit error with downcast to a String message at the supervisor boundary.
   - Decision deferred to executor; rationale capture required in 26-02 SUMMARY.

## Cross-plan invariants

- **D-19 cross-phase byte-identical preservation** of `crates/nono/` is non-negotiable for Plan 26-01. For Plan 26-02, D-19 may be relaxed if the executor chooses Path A on the `ArtifactTooLarge` decision (in which case the deviation must be explicitly documented).
- **Cherry-pick provenance via `Upstream-commit:` trailer** is required for both plans where cherry-picks land. Both plans default to chronological cherry-pick chain with D-20 manual-replay fallback per task.
- **Feature-first style** (`tdd: false`) for both plans. Match Phase 28 + Phase 29 default.

## Execution sequencing

The sequence: **Plan 26-01 → Plan 26-02 → Phase 26 SUMMARY**.

- Plan 26-01 can ship on Windows now (no host blockers).
- Plan 26-02 ships on Linux/macOS (or after `NONO_TEST_HOME` seam).
- Phase 26 closes when both plans have SUMMARY-recorded closure.

If Plan 26-02 is deferred indefinitely to v2.4 (e.g., the milestone-level decision is to ship v2.3 with Phase 26 partial), update Phase 26's status in ROADMAP.md to PARTIAL and surface in PROJECT.md key-decisions table. The Phase 26 closure record should explicitly note the partial-close shape.

## Out of scope (re-confirmed at scope-time)

- Multi-tenant registry features (pure upstream parity port; v2.x doesn't have multi-tenancy).
- Registry server implementation (client-side streaming only).
- Cross-platform RSS measurement on Windows (`proc_self_status` is Linux-specific; macOS uses different API; Plan 26-02 gates the RSS test `#[cfg(target_os = "linux")]`).
- The v2.2 backlog row "WR-01 reject-stage unification" (closed in v2.3 Phase 29 as design property; not v2.4 backlog anymore).
