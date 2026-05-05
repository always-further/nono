---
milestone: v2.3
milestone_name: Linux POC Unblock + Deferreds Closure
status: active
created: 2026-04-29
---

# Requirements — v2.3 Linux POC Unblock + Deferreds Closure

**Defined:** 2026-04-29
**Core Value:** A Linux user running fork-Linux-build sees real enforcement (not silent no-ops) for resource limits, and v2.2's deferred items (PKG streaming, audit-attestation hardening, Authenticode chain-walker) ship as production-ready surfaces.

**Context:** v2.2 closed the upstream-v0.38–v0.40 cross-platform feature gap on Windows + installed a parity-drift prevention process. Three requirement clusters remained partially-deferred (PKG-01 streaming, AUD-03 Windows Authenticode chain-walker, audit-attestation fixture re-enablement). Plus the gap analysis at `.planning/quick/260429-gap-v039-linux-poc-vs-windows-fork-tip/PLAN.md` surfaced that fork-Linux-build's `--memory` / `--cpu-percent` / `--timeout` / `--max-processes` flags are silent no-ops with stderr warnings — a credibility issue for a Linux POC. v2.3 closes those + lands the WR-01 product decision that's been deferred since v2.1.

**Scope shape:** 6 phases (25–29 + 27.1 inserted 2026-05-04), 17 requirements across 7 categories (RESL-NIX, AIPC-NIX, PKGS, AAH, AUDC, WRU, NTH). Cross-platform-first by construction. Mostly small/medium plans; longest is Phase 26 PKG streaming.

**Out of scope (explicit deferrals to v2.4 backlog):**
- Upstream v0.41–v0.43 ingestion (DRIFT tooling stays warm; first real load deferred one cycle).
- AIPC G-04 wire-protocol compile-time tightening (cascades into 23 tests + child SDK demultiplexer).
- `windows-squash` → `main` merge (gated on PR-583 maintainer response per quick-260428-rsu).
- Cross-platform drift QA (full Linux/macOS test-suite pass against fork tip).
- Docs pass (bring `docs/cli/*` current with v2.2+v2.3 surfaces).

---

## RESL-NIX — Cross-Platform RESL Unix Backends

Context: v2.1 Phase 16 shipped Job Object resource limits on Windows (CPU %, memory, wall-clock timeout, process count). The same flags were left as silent no-ops with stderr warnings on Linux/macOS — a deliberate scope cap at the time, but a Linux POC trips on the warnings and reads them as feature breakage. v2.3 lands real enforcement.

### REQ-RESL-NIX-01 — Linux cgroup v2 backends for memory / CPU / process count

- **What:** `--memory <bytes>` enforces via cgroup v2 `memory.max`; `--cpu-percent <0-100>` enforces via cgroup v2 `cpu.max` (`<quota> <period>` with period = 100000); `--max-processes <N>` enforces via cgroup v2 `pids.max`. Supervisor places the child PID into a fresh cgroup at launch time and writes the limits before `execve`. Removes the four "not enforced on linux" stderr warnings emitted today by `exec_strategy.rs:54-96`.
- **Enforcement:** Linux fork-Linux-build only. Requires cgroup v2 (mount at `/sys/fs/cgroup` with `cgroup2` filesystem). Supervisor verifies cgroup v2 availability at startup; fail-closed with clear error if cgroup v1 detected (no silent fallback).
- **Security:** Enforcement is kernel-level. Cgroup hierarchy created under `/sys/fs/cgroup/nono/<session-id>/`; cleaned up on session exit. Sandboxed agent cannot escape cgroup via fork (cgroup v2 propagates to descendants).
- **Acceptance:**
  1. `nono run --memory 256m -- bash -c "tail -c 1G </dev/urandom"` on Linux is killed by OOM (memory.max enforced); `nono inspect <id>` shows `memory_kill: true`.
  2. `nono run --cpu-percent 50 -- bash -c "yes >/dev/null"` on Linux pegs at ~50% CPU (cpu.max enforced); measurable via `top` or `/proc/<pid>/stat` time delta.
  3. `nono run --max-processes 10 -- bash -c "for i in {1..20}; do sleep 60 & done; wait"` on Linux fails after 10 forks (pids.max enforced); error contains `pids.max`.
  4. None of the four stderr warnings emit on Linux for these flags after this requirement lands.
  5. cgroup v1 system fails fast with `NonoError::UnsupportedPlatform` referencing cgroup v2.
- **Maps to:** v2.3 backlog "Cross-platform RESL Unix backends" (subsumed verbatim from PROJECT.md § Next Milestone).

### REQ-RESL-NIX-02 — Linux wall-clock timeout via supervisor + cgroup kill

- **What:** `--timeout <duration>` enforces wall-clock (not CPU-time) via supervisor-side `Instant` deadline + `cgroup.kill` on the cgroup tree at expiry. Mirrors v2.1 Phase 16 RESL-03 semantics on Windows (`TerminateJobObject`).
- **Enforcement:** Supervisor side, Linux only. Uses cgroup v2's `cgroup.kill` write to atomically SIGKILL all descendant processes.
- **Security:** No race window between deadline and kill — `cgroup.kill` is atomic. Sandboxed agent cannot race past the deadline by fork-storming.
- **Acceptance:**
  1. `nono run --timeout 5s -- sleep 60` on Linux exits with the documented timeout exit code at ~5s; `nono inspect <id>` shows `timeout_kill: true`.
  2. `nono run --timeout 5s -- bash -c "for i in {1..100}; do sleep 60 & done; wait"` on Linux kills all 100 child processes atomically at 5s.
- **Maps to:** v2.1 Phase 16 RESL-03 (Linux extension).

### REQ-RESL-NIX-03 — macOS `setrlimit` equivalents

- **What:** `--memory <bytes>` enforces via `RLIMIT_AS`; `--cpu-percent` *not supported on macOS* (no per-process CPU-quota equivalent; emit a clear NotSupportedOnPlatform error rather than silent no-op); `--max-processes <N>` enforces via `RLIMIT_NPROC`; `--timeout` enforces via supervisor `Instant` deadline + SIGKILL (no native wall-clock rlimit). Document the wall-clock-vs-CPU-time gap per RLIMIT_CPU semantics.
- **Enforcement:** macOS fork-macOS-build only. `setrlimit` called in pre-exec hook of fork.
- **Security:** Same kernel-level guarantees as Linux for the supported subset. `RLIMIT_AS` enforces address-space limit, not RSS — document the difference.
- **Acceptance:**
  1. `nono run --memory 256m -- bash -c "exec >/dev/null; <large alloc>"` on macOS aborts via `RLIMIT_AS` mmap failure.
  2. `nono run --max-processes 10 -- bash -c "for i in {1..20}; do sleep 60 & done; wait"` on macOS fails after 10 forks with `EAGAIN`.
  3. `nono run --cpu-percent 50 -- ...` on macOS fails fast with `NonoError::NotSupportedOnPlatform { feature: "cpu_percent_macos" }` — no silent degradation.
  4. `nono run --timeout 5s -- sleep 60` on macOS exits at ~5s via supervisor SIGKILL.
- **Maps to:** v2.1 Phase 16 RESL-01..04 (macOS extension; CPU-percent intentionally excluded).

---

## AIPC-NIX — AIPC Unix Futures Design

Context: AIPC handle brokering (Phase 18 + 18.1) is Windows-only by construction — Job Objects, Events, and Mutexes have no direct Unix analog. Sockets and Pipes plausibly admit Unix-domain socket + `SCM_RIGHTS` file-descriptor passing equivalents. The user-facing question for v2.4+ planning is which HandleKinds get Unix backends and which are documented as Windows-only by design. v2.3 produces an ADR-level decision document; no implementation.

### REQ-AIPC-NIX-01 — AIPC Unix futures ADR

- **What:** Design document at `docs/architecture/aipc-unix-futures.md` (or equivalent ADR location) documenting Decision D-NN: "AIPC HandleKinds 0–2 (File / Socket / Pipe) admit Unix backends via Unix-domain socket + `SCM_RIGHTS` file-descriptor passing; HandleKinds 3–5 (JobObject / Event / Mutex) are Windows-only by design — Linux equivalents (cgroup, eventfd, pthread mutex) don't broker the same way."
- **Enforcement:** Design-only; no code. ADR cross-linked from PROJECT.md and CONTEXT D-04 footnote.
- **Security:** N/A (documentation).
- **Acceptance:**
  1. ADR file committed; structure mirrors existing fork ADRs.
  2. PROJECT.md cross-links the ADR.
  3. Decision is falsifiable: each HandleKind has a yes/no verdict + 1-2 sentence rationale + (for "no") explicit alternate-mechanism note for users who need that primitive.
- **Maps to:** Derived from v2.2 close gap analysis (`.planning/quick/260429-gap-v039-linux-poc-vs-windows-fork-tip/PLAN.md`).

---

## PKGS — Package Manager Streaming Follow-Up

Context: v2.2 Phase 22 Plan 22-03 landed 6/8 cherry-picks of upstream's package management cluster. 2 cherry-picks were deferred because they required Rule-4 architectural decisions exceeding cherry-pick scope: `ArtifactType::Plugin` enum variant, `bundle_json` field, `validate_path_within` belt-and-suspenders alongside upstream's `validate_relative_path`. v2.3 closes those decisions + lands the streaming refactor.

### REQ-PKGS-01 — Streaming `bytes`→`PathBuf` refactor with size limits + HTTP timeouts + `semver` dep

- **What:** Port upstream `9ebad89a` — `nono package pull` streams artifact bytes directly to a `tempfile::TempDir` `PathBuf` rather than buffering full bytes in memory. Adds size limits enforced during stream (reject artifacts > configured cap), HTTP timeouts on `hyper` client (connect + idle), and a `semver` dep for version comparison in registry queries.
- **Enforcement:** Cross-platform (`hyper` + `rustls` are already in the workspace). Size cap default 500MB; configurable via `nono package pull --max-size <bytes>`.
- **Security:** Streaming verification (per existing PKG-04 acceptance) runs on streamed bytes; no full-buffer attack window. Tampered artifact rejected before install. HTTP timeouts prevent hung-connection DoS.
- **Acceptance:**
  1. `nono package pull <large-artifact>` of 200MB succeeds via streaming (memory profile peaks at ~10MB, not 200MB).
  2. Tampered mid-stream artifact rejected with clear error before install_dir placement.
  3. Artifact > `--max-size` cap rejected mid-stream with `NonoError::ArtifactTooLarge { actual, max }`.
  4. Connect timeout / idle timeout fires with clear error after configured threshold.
- **Maps to:** Upstream `9ebad89a refactor(pkg): stream package artifact downloads`. Deferred from v2.2 Plan 22-03.

### REQ-PKGS-02 — `validate_relative_path` belt-and-suspenders alongside fork's `validate_path_within`

- **What:** Port upstream `58b5a24e refactor(cli): improve artifact path validation`. Fork retains its existing `validate_path_within` (canonicalize-and-component-compare) as defense-in-depth alongside upstream's `validate_relative_path` (input-string pre-check). Both fire on every artifact path used in install_dir placement.
- **Enforcement:** Cross-platform. Order: input-string pre-check first (cheap rejection of obviously-bad shapes), canonicalize-and-component-compare second (definitive answer post-symlink-resolution).
- **Security:** Defense-in-depth. Fork's stance is stricter than upstream's verbatim pattern, matching CLAUDE.md § Path Handling guidance.
- **Acceptance:**
  1. Pack manifest with `..` traversal in path rejected by `validate_relative_path` input-string pre-check before any filesystem syscall.
  2. Pack manifest with symlink-traversal still rejected by `validate_path_within` canonicalize-and-compare path (post-symlink-resolution).
  3. Existing fork regression tests for `validate_path_within` still pass.
- **Maps to:** Upstream `58b5a24e`. Deferred from v2.2 Plan 22-03 pending Rule-4 architectural decision (kept fork's stricter check; recommended in v2.2 backlog).

### REQ-PKGS-03 — `ArtifactType::Plugin` enum variant + plumbing

- **What:** Add `Plugin` variant to `ArtifactType` enum (currently `Profile` + others); plumb through `package_cmd.rs`, `registry_client.rs`, manifest deserialization, install/remove paths. Closes the deferred-divergence comment at `crates/nono-cli/src/package_cmd.rs:631-643` introduced in v2.2 Plan 22-03's `73e1e3b8`.
- **Enforcement:** Cross-platform schema change; `#[serde(rename_all = "kebab-case")]` consistent with existing variants.
- **Security:** Plugin artifacts go through the same signed-artifact verification path as Profile. No new trust path introduced.
- **Acceptance:**
  1. `nono pull <plugin-pack>` deserializes the manifest's `artifact_type: plugin` field, places artifacts under `install_dir`, and registers any associated hooks.
  2. Round-trip serialization: `serde_json` produces `"plugin"` for the variant.
  3. Schema-validation rejects unknown `artifact_type` values fail-closed.
- **Maps to:** Deferred-divergence comment at `package_cmd.rs:631-643`. Required by REQ-PKGS-01 streaming work (the streaming path needs to know the artifact type to choose the install handler).

### REQ-PKGS-04 — `load_registry_profile` auto-pull

- **What:** Port upstream `115b5cfa feat(profile): load profiles from registry packs`. When a profile's `extends` chain references a registry-pack profile, `Profile::resolve` auto-pulls the pack via `nono package pull` (idempotent if already present locally) before resolving the extension.
- **Enforcement:** Cross-platform. Auto-pull triggers only when the referenced pack is absent locally; double-pull is a no-op (matches existing PKG-03 hook idempotency).
- **Security:** Auto-pull goes through the same signed-artifact verification path. No silent unauth'd network call — a profile resolve that requires registry access fails closed if registry credentials are missing.
- **Acceptance:**
  1. Profile with `extends: ["registry://vendor/pack@1.2.3"]` and pack absent locally triggers auto-pull, completes resolve.
  2. Profile resolve with no network access (and pack absent) fails with clear error pointing at the missing pack.
  3. Auto-pull respects the size limit + HTTP timeouts from REQ-PKGS-01.
- **Maps to:** Upstream `115b5cfa`. Deferred from v2.2 Plan 22-01's empty provenance commit `3bde347c`.

---

## AAH — Audit-Attestation Hardening

Context: v2.2 Plan 22-05a landed cryptographic DSSE bundle verification (HG-01-H, commit `cffb43b1`) but had to mark 2 fixture-driven tests `#[ignore]` because sigstore-rs 0.6.4 doesn't expose `KeyPair::from_pkcs8`. Required before publishing v2.2 attestation as production-ready.

### REQ-AAH-01 — Re-enable fixture-driven attestation tests

- **What:** Re-enable `#[ignore]`'d tests in `crates/nono-cli/tests/audit_attestation.rs`. Resolves the Rule-4 architectural decision: either upgrade sigstore-rs (may cascade through other crates) OR add a fork-internal pkcs8 parser (adds parsing surface, but contained scope). Plan-phase research documents both paths' cascade impact; chooses one with explicit rationale.
- **Enforcement:** Cross-platform. Either path delivers `KeyPair` reconstruction from a fixture-stored PKCS8-encoded key.
- **Security:** PKCS8 parsing must reject malformed input fail-closed. Whichever path chosen, the parsing surface is subjected to the same fuzz-test discipline as the rest of the trust path.
- **Acceptance:**
  1. Both `#[ignore]`'d tests in `audit_attestation.rs` run (no `#[ignore]` attribute) and pass.
  2. Whichever path is chosen, the architectural decision is documented in CONTEXT.md with the cascade impact for future readers.
  3. `cargo test -p nono-cli --test audit_attestation` exits 0 with no ignored tests.
  4. Threat model entry covers the new parsing surface (if path b) or the upgrade's known-issue ingestion (if path a).
- **Maps to:** v2.2 backlog "Audit-attestation D-13 fixtures re-enablement" (subsumed verbatim from PROJECT.md § Next Milestone).
- **Cross-link:** Phase 27 Plan 01 surfaced 3 Windows-host blockers and was re-deferred to v2.4. **Phase 27.1 (REQ-NTH-01..03, inserted 2026-05-04) lands the production-code `NONO_TEST_HOME` seam that closes those blockers** and re-enables the deferred tests via REQ-NTH-03. REQ-AAH-01 is closed transitively when Phase 27.1 Plan 03 verification passes on the Windows host.

---

## NTH — NONO_TEST_HOME Test-Harness Seam (INSERTED 2026-05-04)

Context: Phase 27 (REQ-AAH-01) attempted Path B fixture redesign on a Windows host on 2026-04-29 and surfaced 3 systemic Windows-host test-harness blockers documented in `.planning/phases/27-audit-attestation-hardening/27-01-SUMMARY.md`:
1. `dirs::home_dir()` on Windows ignores `USERPROFILE` env override (uses `SHGetKnownFolderPath` directly).
2. `LOCALAPPDATA`/`USERPROFILE` path-mismatch under partial env redirection causes audit/rollback co-location bugs.
3. (Independent) audit-integrity exit-cleanup `Session not found` on Windows.

The cleanest cross-platform unblock — explicitly proposed at Phase 27 SUMMARY § "v2.4 Resumption Path" item 2 — is a production-code `NONO_TEST_HOME` env-var seam that overrides home-dir resolution at a single chokepoint in `crates/nono-cli/src/`. v2.3 promotes this from v2.4 backlog into Phase 27.1 (inserted between Phases 27 and 28) so the deferred tests can re-enable in v2.3.

### REQ-NTH-01 — `nono_home_dir()` helper with `NONO_TEST_HOME` validation

- **What:** Add `pub fn nono_home_dir() -> Result<PathBuf>` to `crates/nono-cli/src/config/mod.rs` that honors `NONO_TEST_HOME` (when set, validates it is absolute; on miss, falls through to `dirs::home_dir()`). Always-on production seam (no `#[cfg(test)]` gating per CONTEXT D-27.1-08). Migrates all 15 home-dir callsites in `crates/nono-cli/src/` (10 `dirs::home_dir()` + 5 `xdg_home::home_dir()`) per CONTEXT D-27.1-02.
- **Enforcement:** Cross-platform. Validation matches existing `validated_home()` pattern: non-absolute `NONO_TEST_HOME` returns `NonoError::EnvVarValidation { var: "NONO_TEST_HOME", reason: "must be an absolute path, got: ..." }`. Fail-closed; no silent fallthrough (CONTEXT D-27.1-10). On first override resolution, emits exactly one `tracing::warn!("NONO_TEST_HOME override active: {path}")` per process via `OnceLock<()>` guard (CONTEXT D-27.1-09).
- **Security:** Mirrors `validated_home()`'s threat model. The override is structurally equivalent to existing `HOME`/`USERPROFILE` env-var trust (always-on in production, env-var validation is the security boundary). `tracing::warn!` provides forensic mark in logs without changing the security model. Production path behavior is byte-identical to status quo when `NONO_TEST_HOME` is unset (ROADMAP.md Phase 27.1 success criterion #3).
- **Acceptance:**
  1. `pub fn nono_home_dir() -> Result<PathBuf>` exists in `crates/nono-cli/src/config/mod.rs` and validates `NONO_TEST_HOME` per D-27.1-10.
  2. All 15 callsites in `crates/nono-cli/src/` route through the helper (10 `dirs::home_dir().ok_or(NonoError::HomeNotFound)?` swaps + 5 `xdg_home::home_dir().ok_or(...)` swaps + 5 deviation-shape sites covered per CONTEXT D-27.1-02 / PATTERNS.md migration table).
  3. `tracing::warn!` fires exactly once per process on override use (`OnceLock` guard).
  4. 4 dedicated unit tests (`nono_home_dir_returns_override_when_set`, `nono_home_dir_rejects_non_absolute_override`, `nono_home_dir_falls_through_when_unset`, plus Windows-only `user_state_dir_honors_nono_test_home`) pass under `cargo test -p nono-cli --bin nono config::tests` (CONTEXT D-27.1-15; `nono-cli` is binary-only, so `--bin nono` is required, not `--lib`).
  5. `crates/nono/` byte-identical (D-19 cross-phase invariant; satisfied because `NonoError::EnvVarValidation` and `NonoError::HomeNotFound` both already exist).
  6. `xdg-home` workspace dependency removed from `crates/nono-cli/Cargo.toml` once all 5 `xdg_home` callsites migrate (CONTEXT D-27.1-04 housekeeping; verified pre-flight that no other crate depends on it).
- **Maps to:** Phase 27 SUMMARY § "v2.4 Resumption Path" item 2 (verbatim proposal, promoted from v2.4 backlog into v2.3 Phase 27.1).

### REQ-NTH-02 — `user_state_dir()` Windows redirection under `NONO_TEST_HOME`

- **What:** Extend `pub fn user_state_dir() -> Option<PathBuf>` in `crates/nono-cli/src/config/mod.rs` so that when `NONO_TEST_HOME` is set, it returns `Some(<NONO_TEST_HOME>/.nono)` (CONTEXT D-27.1-05, D-27.1-06). Closes Phase 27 Blocker 2 (`audit_root()` and `rollback_root()` path mismatch on Windows under partial env redirection) by ensuring both roots co-locate under the same parent when the override is active.
- **Enforcement:** Cross-platform code path (the `NONO_TEST_HOME` short-circuit fires on all platforms); the practical effect is most pronounced on Windows where `user_state_dir()` and `dirs::home_dir()` previously diverged. Layout under override mirrors production (`.nono/audit` + `.nono/rollbacks`), NOT a new test-only hierarchy (D-27.1-06).
- **Security:** Signature stays `Option<PathBuf>` (callers expect `None`-semantics for missing platform — D-27.1-05 invariant b). When `NONO_TEST_HOME` is unset, behavior is byte-identical to the status quo.
- **Acceptance:**
  1. With `NONO_TEST_HOME=<abs>` set on Windows, `crate::config::user_state_dir()` returns `Some(PathBuf::from(<abs>).join(".nono"))`.
  2. With `NONO_TEST_HOME` unset, behavior matches status quo (`dirs::state_dir().or_else(dirs::data_local_dir).map(|p| p.join("nono"))`).
  3. `crates/nono-cli/src/rollback_session.rs::rollback_root()` Windows branch lands at `<NONO_TEST_HOME>/.nono/rollbacks` when override is active; `crates/nono-cli/src/audit_session.rs::audit_root()` lands at `<NONO_TEST_HOME>/.nono/audit` (co-located).
  4. Windows-only unit test `user_state_dir_honors_nono_test_home` passes.
- **Maps to:** Phase 27 Blocker 2 (closure of audit/rollback path-mismatch); CONTEXT D-27.1-05.

### REQ-NTH-03 — Phase 27 audit-attestation tests re-enabled and adapted

- **What:** Remove the 2 `#[ignore]` attributes from `crates/nono-cli/tests/audit_attestation.rs` (currently at lines 290 and 456 — `audit_verify_reports_signed_attestation_with_pinned_public_key` and `rollback_signed_session_verifies_from_audit_dir_bundle`) and adapt the bodies to use `NONO_TEST_HOME`-driven isolation instead of the Windows set-difference workaround (Phase 27 commit `16bae9ca` body preserved verbatim except for the workaround swap). Modify the `run_nono` helper at lines 12-43 to pass `NONO_TEST_HOME=<home>` to the spawned subprocess (CONTEXT D-27.1-12, D-27.1-13).
- **Enforcement:** Windows host verification (the original Phase 27 attempt happened on Windows; success on Windows closes the gap end-to-end). Linux/macOS execution is also expected to pass since the seam is cross-platform.
- **Security:** No new security surface — the seam already covered by REQ-NTH-01's threat model. Test mutation of parent-process env vars at lines 310/330 (for `env://` keystore URI seeding) uses a per-invocation `{pid}_{nanos}` suffix to avoid collisions across parallel test runs (Phase 27 D-AAH-01 pattern preserved).
- **Acceptance:**
  1. Both `#[ignore]` attributes removed from `crates/nono-cli/tests/audit_attestation.rs` (lines 290 and 456).
  2. `cargo test -p nono-cli --test audit_attestation` exits 0 with `2 passed; 0 failed; 0 ignored` on Windows host.
  3. Test 1 uses `only_audit_session_id(&home)` (the simple production-layout helper) instead of the Windows set-difference workaround (`audit_root_for_supervisor` + `new_session_id_after_run`).
  4. Test 2 uses `run_command_args()` (cross-platform) instead of `/bin/pwd` (Unix-only).
  5. **Blocker 3 contingency (D-27.1-14):** If audit-integrity exit-cleanup `Session not found` resurfaces with the seam in place, the failure is handled per the contingency tree: small localized fix in scope, larger investigation re-`#[ignore]`'d with Phase 27.1-Blocker-3 note + surfaced as v2.4 follow-up. Partial closure (1 test passing + 1 re-deferred) is acceptable for REQ-NTH-03 if Blocker 3 proves architecturally non-trivial — the seam landing is the deliverable; tests are the proof.
- **Maps to:** Phase 27 REQ-AAH-01 (closes by proxy through Phase 27.1); ROADMAP.md Phase 27.1 success criterion #2.

---

## AAHX — Audit-Attestation Test Re-Enablement (Phase 27.2)

Context: Phase 27.1 invoked the D-27.1-14 large-fix branch when both audit-attestation tests failed verification despite the `NONO_TEST_HOME` seam reaching the supervisor. Two distinct production-code gaps were surfaced:
- **FU-1:** `crates/nono-cli/src/audit_commands.rs:12` uses `rollback_session::load_session` to resolve audit verification targets, which can't find audit-only sessions (the audit-aware `audit_session::load_session` already exists with correct dual-root semantics but is gated behind `#[allow(dead_code)]`).
- **FU-2:** `--rollback`-active sessions write the bundle to `<rollback_root>/<id>/audit-attestation.bundle`, but Test 2 asserts the bundle lives at `<audit_root>/<id>/audit-attestation.bundle`. Either the production code mirrors to audit_dir, or it signs to session_dir and `audit verify` learns to look in both, or the test's expected path changes — this is a design decision, not a missed callsite.

Both follow-ups are documented in `.planning/phases/27.1-nono-test-home-seam/deferred-items.md` (v2.4-FU-1, v2.4-FU-2) and surfaced in `.planning/phases/27.1-nono-test-home-seam/27.1-03-SUMMARY.md`. Phase 27.2 closes them in v2.3.

### REQ-AAHX-01 — `cmd_verify` audit-loader correctness for audit-only sessions

- **What:** Swap the loader call in `crates/nono-cli/src/audit_commands.rs::cmd_verify` (line 12 region) from `rollback_session::load_session(...)` to `audit_session::load_session(...)` when the session was created with `--audit-integrity` but without `--rollback` (or with `--rollback` if the bundle-target decision in REQ-AAHX-02 says audit-loader should be the primary). Preserve correctness for rollback-only and dual-target sessions per the chosen architecture.
- **Enforcement:** Cross-platform — both `audit_session::load_session` and `rollback_session::load_session` already honor `nono_home_dir()` post-Phase-27.1.
- **Security:** Loader chosen must NOT widen the path-resolution surface beyond what `nono_home_dir()` already validates. Fail-closed on missing session: surface the canonical `Session not found` error rather than silently falling back to a different root (avoids confused-deputy across the audit/rollback discriminator).
- **Acceptance:**
  1. `audit_commands::cmd_verify` resolves audit-only sessions correctly (no `Session not found` for sessions written by `nono run --audit-integrity --audit-sign-key <key> -- <cmd>`).
  2. Rollback-only and dual-target sessions retain their existing verification correctness (no regressions in any pre-existing rollback verify path).
  3. `#[allow(dead_code)]` removed from `audit_session::load_session` once it has live consumers (mirrors Phase 27.1 Plan 02 D-19 pattern of removing the attr when migration consumers land).
- **Maps to:** Phase 27.1 D-27.1-14 v2.4-FU-1; closes the Test 1 path of REQ-NTH-03 acceptance #2 once the loader swap lands.

### REQ-AAHX-02 — Bundle-target architecture decision (ADR + implementation)

- **What:** Pick one of three bundle-target architectures and record the decision as an ADR (e.g. `docs/architecture/audit-bundle-target.md`):
  - **Option A:** Mirror to `<audit_root>/<id>/audit-attestation.bundle` regardless of `--rollback` flag (production code change in the supervisor sign-target routing).
  - **Option B:** Sign to `<rollback_root>/<id>/audit-attestation.bundle` only when `--rollback` is set, sign to `<audit_root>/<id>/...` otherwise; `audit verify` learns dual-root lookup.
  - **Option C:** Test rewrite — the test (Test 2) accepts the production behavior of writing to `<rollback_root>/<id>/...` when `--rollback` is set. Production unchanged.
- **Enforcement:** Cross-platform; relevant on every host where `nono run --audit-integrity --audit-sign-key <key> --rollback -- <cmd>` produces a bundle.
- **Security:** Audit logs and rollback artifacts are co-tenant on the same filesystem under `<NONO_TEST_HOME>/.nono/` (Phase 27.1 REQ-NTH-02). Whichever option is chosen must not weaken existing access-mode separation between `audit_root()` (append-mostly) and `rollback_root()` (mutable). If Option A or B introduces cross-root access, the access patterns must be SECURITY-reviewed in Phase 27.2 secure-phase.
- **Acceptance:**
  1. ADR file exists at the chosen path documenting the decision, alternatives considered, and rationale (matches Phase 25-02 AIPC ADR convention).
  2. Implementation matches the ADR's chosen path; `--audit-integrity --audit-sign-key` (with and without `--rollback`) produces a verifiable bundle at the documented canonical location.
  3. Test 2 (`rollback_signed_session_verifies_from_audit_dir_bundle`) asserts the canonical path per the ADR; no conditional `#[cfg]` shapes.
- **Maps to:** Phase 27.1 D-27.1-14 v2.4-FU-2.

### REQ-AAHX-03 — Audit-attestation tests re-enabled and passing on Windows host

- **What:** Remove the two `#[ignore]` attributes in `crates/nono-cli/tests/audit_attestation.rs` (currently re-`#[ignore]`'d per Phase 27.1 D-27.1-14). Both `audit_verify_reports_signed_attestation_with_pinned_public_key` and `rollback_signed_session_verifies_from_audit_dir_bundle` must pass on Windows host with `NONO_TEST_HOME` set. Includes converting the bare `std::env::set_var`/`remove_var` calls (Phase 27.1 REVIEW WR-05) to a RAII guard so a panic in `run_nono` doesn't leak the env var.
- **Enforcement:** Windows host verification (matches Phase 27 + 27.1 enforcement pattern). Linux/macOS pass is also expected since the seam is cross-platform.
- **Security:** No new security surface. RAII env-var guard reduces test-side flakiness only.
- **Acceptance:**
  1. Both `#[ignore]` attributes removed from `crates/nono-cli/tests/audit_attestation.rs`.
  2. `cargo test -p nono-cli --test audit_attestation` exits 0 with `2 passed; 0 failed; 0 ignored` on Windows host.
  3. Test 1's JSON-shape assertion at `tests/audit_attestation.rs:534-538` (Phase 27.1 REVIEW WR-04) either matches `cmd_verify`'s actual output, OR `cmd_verify` is updated to emit the nested `attestation` object the test expects — whichever is more consistent with the REQ-AAHX-02 ADR.
  4. Phase 27.1 `27.1-HUMAN-UAT.md` Test 1 (`Windows-host audit-attestation tests with v2.4-FU-1 + v2.4-FU-2 production fixes applied`) marks `result: passed` on `/gsd-verify-work 27.1` after Phase 27.2 closes.
- **Maps to:** Phase 27 REQ-AAH-01 (closes fully on Windows host); Phase 27.1 REQ-NTH-03 (full closure replacing the partial closure D-27.1-14 contingency outcome).

---

## AUDC — Authenticode Chain-Walker Subject Extraction

Context: v2.2 Plan 22-05b ports `WinVerifyTrust` discriminant-only on Windows because `windows-sys 0.59` does not expose `WTHelperProvDataFromStateData` / `WTHelperGetProvSignerFromChain` without `Win32_Security_Cryptography_Catalog` + `Win32_Security_Cryptography_Sip` features (`CRYPT_PROVIDER_DATA` shape is gated). Records `Valid` / `Unsigned` / `InvalidSignature{hresult}` only, sets `signer_subject = "<unknown>"` and empty thumbprint on Valid signatures. v2.3 lights up the chain walker.

### REQ-AUDC-01 — Add windows-sys feature gates + chain-walker implementation

- **What:** Add `Win32_Security_Cryptography_Catalog` + `Win32_Security_Cryptography_Sip` features to `windows-sys` in workspace `Cargo.toml`. Implement `parse_signer_subject` + `parse_thumbprint` in `crates/nono-cli/src/exec_identity_windows.rs` using `WTHelperProvDataFromStateData` + `WTHelperGetProvSignerFromChain`.
- **Enforcement:** Windows-only (gated `#[cfg(target_os = "windows")]`). Linux/macOS paths unchanged.
- **Security:** Subject + thumbprint extraction adds parsing surface. Validate all extracted strings via existing `sanitize_for_terminal` before write into session metadata. SAFETY comments on every `unsafe` block.
- **Acceptance:**
  1. `nono audit show <id>` on Windows for a signed binary shows populated `signer_subject` (e.g., "CN=Anthropic Inc., ...") and non-empty SHA-1 thumbprint.
  2. `nono audit show <id>` on Windows for an unsigned binary still shows `Unsigned` discriminant (existing v2.2 behavior preserved); subject + thumbprint absent.
  3. `cargo build --workspace` on Windows succeeds with the new features enabled.
- **Maps to:** v2.2 backlog "Authenticode chain-walker subject extraction" (subsumed verbatim from PROJECT.md § Next Milestone).

### REQ-AUDC-02 — Re-enable `authenticode_signed_records_subject` substring assertion test

- **What:** Remove `#[ignore]` attribute from `authenticode_signed_records_subject` test in v2.2 Plan 22-05b. Test asserts `signer_subject` contains a non-empty CN substring on a signed test binary.
- **Enforcement:** Windows-only (test gated `#[cfg(target_os = "windows")]`).
- **Security:** N/A.
- **Acceptance:**
  1. Test runs (no `#[ignore]`) and passes against a fixture signed binary.
  2. `cargo test -p nono-cli --test authenticode_*` on Windows exits 0 with no ignored tests in this file.
- **Maps to:** Companion to REQ-AUDC-01.

### REQ-AUDC-03 — Update AUD-03 acceptance: populated `signer_subject` + thumbprint on Valid

- **What:** Update REQ-AUD-03 acceptance criteria 2 (in v2.2-REQUIREMENTS.md archive — informational; v2.3 adds an active criterion enforced by tests): on `Valid` Authenticode discriminant, `signer_subject` MUST be populated (non-empty after sanitization) and `thumbprint` MUST be non-empty (40-char hex SHA-1).
- **Enforcement:** Windows-only. Tested by REQ-AUDC-02 + new regression test asserting both fields populated.
- **Security:** Forces fail-closed: if chain walk fails to extract subject/thumbprint on a signature that `WinVerifyTrust` returned `Valid` for, audit recording fails-closed (not silently records "<unknown>").
- **Acceptance:**
  1. Signed binary: both fields populated; verified via `nono audit show <id> --json`.
  2. Chain-walk failure on Valid signature → audit-recording fail-closed with clear error (not silent "<unknown>").
  3. Unsigned binary: existing v2.2 behavior preserved (Unsigned discriminant; no subject/thumbprint extraction attempted).
- **Maps to:** Upgrade of v2.2 REQ-AUD-03 acceptance (Windows portion). Cross-references v2.2-REQUIREMENTS.md archive.

---

## WRU — WR-01 Reject-Stage Unification

Context: AIPC HandleKinds Event/Mutex/JobObject reject BEFORE the user prompt (mask gate); Pipe/Socket reject AFTER the user prompt (G-04 broker-failure flip). This asymmetry was locked by `wr01_*` regression tests in v2.1 Phase 18.1 and explicitly mirrored on the audit-ledger wire by Phase 23's `RejectStage` discriminator. v2.3 makes the product decision: align all 5 on a single stage OR lock the asymmetry as a permanent design property with explicit rationale.

### REQ-WRU-01 — Product decision on canonical reject stage

- **What:** Decision document at CONTEXT D-14 (or equivalent) recording one of:
  - **(a) Unify on BeforePrompt** — Pipe/Socket pre-checks move ahead of the prompt; G-04 broker-failure flip becomes unreachable for these kinds. Cleaner mental model; small refactor in Pipe/Socket helpers.
  - **(b) Unify on AfterPrompt** — Event/Mutex/JobObject mask-gate moves behind the prompt. User sees prompts they cannot approve; questionable UX.
  - **(c) Lock asymmetry as permanent** — accept that 3 kinds reject before, 2 reject after, with explicit rationale grounded in resource cost (mask-gate is cheap; broker-failure isn't). Update WR-01 docstring to call this a design property, not a bug.
- **Enforcement:** Decision-only at REQ level; REQ-WRU-02 lands implementation.
- **Security:** Whichever option chosen, no silent fallback. Audit ledger continues to record `reject_stage` per event (v2.2 Phase 23 invariant preserved).
- **Acceptance:**
  1. CONTEXT D-14 (or equivalent ADR) updated with the chosen option + 1-paragraph rationale.
  2. PROJECT.md key-decisions table updated with the outcome.
  3. Phase plan 29-NN cites the decision verbatim before implementation begins.
- **Maps to:** v2.1 Phase 18.1 deferred decision (CONTEXT D-14); v2.2 Phase 23 wire-protocol locking (PROJECT.md key-decisions).

### REQ-WRU-02 — Update `wr01_*` regression tests + ledger emission per chosen verdict matrix

- **What:** Whichever option from REQ-WRU-01 is chosen, update the 5 `wr01_*` regression tests in `capability_handler_tests` to reflect the new verdict matrix. Update the dispatcher's `RejectStage` emission at the 5 push sites in `handle_windows_supervisor_message` to match. Update Phase 23's `nono audit show <id>` rendering counter logic if the asymmetry shape changes (today: "M before-prompt, K after-prompt rejections").
- **Enforcement:** Cross-platform code path (RejectStage enum is on `AuditEventPayload`); Windows-only emission site.
- **Security:** No new security surface. Audit ledger contract preserved (events still emitted at all 5 push sites; only the stage classification changes).
- **Acceptance:**
  1. All 5 `wr01_*` tests pass with their assertions matching the chosen matrix.
  2. `audit_integrity_records_5_handle_kinds_in_ledger` (Phase 23 multi-kind E2E) still passes; ledger reflects the chosen matrix.
  3. `nono audit show <id>` counter line wording matches the chosen matrix (e.g., if option (a) Unify-on-BeforePrompt: counter shows only "M before-prompt rejections" with after-prompt count omitted entirely).
  4. CONTEXT.md D-14 updated with the implementation outcome.
- **Maps to:** Companion to REQ-WRU-01.

---

## Out of Scope (Explicit Deferrals to v2.4 backlog)

| Item | Reason | Destination |
|------|--------|-------------|
| Upstream v0.41–v0.43 ingestion | DRIFT-01/02 tooling (v2.2 Phase 24) stays warm; first real load deferred one cycle to keep v2.3 shippable in 2 weeks | v2.4 first phase |
| AIPC G-04 wire-protocol compile-time tightening (`Approved(ResourceGrant)`) | Cascades into 23 pre-existing tests + child SDK demultiplexer (`aipc_sdk.rs`); too large for v2.3 | v2.4+ |
| `windows-squash` → `main` merge | Gated on PR-583 maintainer response per quick-260428-rsu (re-deferred 2026-04-29) | When PR-583 unblocks |
| Cross-platform RESL drift QA (full test-suite pass on Linux/macOS) | New v2.3 RESL backends will surface flakes; QA after lands as v2.4 work | v2.4 |
| Docs pass (`docs/cli/*` for v2.2 + v2.3) | Mintlify doc surface maintenance is ongoing; bundle into v2.4 with the v0.41+ ingestion | v2.4 |
| WR-02 EDR HUMAN-UAT | Requires EDR-instrumented runner; no host available | v3.0 |

---

## Traceability

To be filled by gsd-roadmapper at v2.3 phase scope-lock (currently at REQUIREMENTS-write stage; phase mapping below is the planned shape).

| Requirement | Planned Phase | Status |
|-------------|---------------|--------|
| RESL-NIX-01 | Phase 25 (Plan 25-01) | Active |
| RESL-NIX-02 | Phase 25 (Plan 25-01) | Active |
| RESL-NIX-03 | Phase 25 (Plan 25-01) | Active |
| AIPC-NIX-01 | Phase 25 (Plan 25-02) | Active |
| PKGS-01 | Phase 26 (Plan 26-02) | Active — plan + CONTEXT committed (commit 86efcdeb); execution queued for Linux/macOS host (streaming RSS measurement + run_nono e2e tests hit Phase 27 dirs::home_dir() Windows blocker) |
| PKGS-02 | Phase 26 (Plan 26-01) | Complete (2026-05-01; commits e5e1f2d7/8ff89923) — D-20 manual replay of upstream `58b5a24e` (cherry-pick would have deleted fork's `validate_path_within`, a security regression); both validators preserved as defense-in-depth; 2 unit tests (`validate_relative_path_rejects_traversal` + `validate_relative_path_rejects_absolute_path`) pass |
| PKGS-03 | Phase 26 (Plan 26-01) | Complete (2026-05-01; commits dd7b28b3/797f3295/8ff89923) — `ArtifactType::Plugin` added as 7th variant (Script was missed in v2.3 REQUIREMENTS.md scope-lock; Plugin is 7th not 6th); plumbed via 1 match-arm site (cargo build cascade-driven); deferred-divergence comment removed atomically with the variant addition; 2 unit tests (`artifact_type_plugin_round_trips` + `artifact_type_unknown_fails_closed`) pass |
| PKGS-04 | Phase 26 (Plan 26-02) | Active — plan + CONTEXT committed (commit 86efcdeb); execution queued for Linux/macOS host (auto-pull e2e tests hit Phase 27 Windows blocker) |
| AAH-01 | Phase 27 (PARTIAL) → re-routed via Phase 27.1 (Plans 27.1-01..03) | PROMOTED 2026-05-04 — closure rerouted through Phase 27.1 NONO_TEST_HOME seam (REQ-NTH-01..03). Phase 27 Plan 01 production code stays byte-identical; Phase 27.1 Plan 03 re-enables both deferred tests via the seam. Status will flip to Complete when Plan 27.1-03 verification passes on Windows host (D-27.1-14 contingency may yield partial closure). See `.planning/phases/27.1-nono-test-home-seam/27.1-CONTEXT.md`. |
| NTH-01 | Phase 27.1 (Plan 27.1-01) | Active — plan committed 2026-05-04; helper `nono_home_dir()` + `user_state_dir()` extension + 4 unit tests; foundation for Plan 27.1-02 callsite migration |
| NTH-02 | Phase 27.1 (Plan 27.1-01) | Active — plan committed 2026-05-04; bundled with REQ-NTH-01 in Plan 27.1-01 (`user_state_dir()` extension closes Phase 27 Blocker 2) |
| NTH-03 | Phase 27.1 (Plan 27.1-03) | Active — plan committed 2026-05-04; re-enables Phase 27 audit-attestation tests via the seam; closes REQ-AAH-01 transitively when Plan 27.1-03 verification passes on Windows host |
| AUDC-01 | Phase 28 (Plan 28-01) | Complete (2026-04-30; commits 67ba4a99/70593110/5a4a8443) — chain walker live; `parse_signer_subject` returns CERT_X500_NAME_STR keyed-RDN; `parse_thumbprint` returns 40-char UPPERCASE hex SHA-1 |
| AUDC-02 | Phase 28 (Plan 28-01) | Complete (2026-04-30; commit 279c1b86) — `authenticode_signed_records_subject` test relocated inline (PATH-4 per CONTEXT override) and re-enabled; #[ignore] count → 0 |
| AUDC-03 | Phase 28 (Plan 28-01) | Complete (2026-04-30; commit 70593110) — fail-closed `?` propagation in `query_authenticode_status` Valid branch; `<unknown>` sentinel fallback removed; reuses `NonoError::SandboxInit` (D-AUDC-02 deviation: `AuditIntegrity` variant doesn't exist on fork) |
| WRU-01 | Phase 29 (Plan 29-01) | Complete (2026-04-30; commit a3734bb3) — locked as permanent design property (Option c). Mask-gate is O(1) profile lookup; broker-failure flip is O(syscall) post-approval; asymmetry not unifiable without security or UX regression. |
| WRU-02 | Phase 29 (Plan 29-01) | Complete (2026-04-30; commit 9fcdf123) — chosen verdict matrix is the EXISTING matrix; all 5 `wr01_*` regression tests pass with assertions UNCHANGED; Phase 23 `RejectStage` wire shape preserved verbatim. |

**Coverage target:**
- v2.3 requirements: 17 total (14 original + 3 NTH inserted 2026-05-04)
- Mapped to phases: 17
- Unmapped: 0

---
*Requirements defined: 2026-04-29.*
*Scope-lock: 2026-04-29 at v2.3 milestone start (option Scope A from /gsd-new-milestone).*
*Phase 27.1 NTH category inserted: 2026-05-04 (3 reqs added; total 17). Promoted from v2.4 backlog per Phase 27 SUMMARY § "v2.4 Resumption Path" item 2.*
