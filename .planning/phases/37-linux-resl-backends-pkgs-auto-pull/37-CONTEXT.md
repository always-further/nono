# Phase 37: Linux RESL backends + PKGS auto-pull - Context

**Gathered:** 2026-05-19
**Status:** Ready for planning

<domain>
## Phase Boundary

Take 4 host-blocked v2.3 requirements (REQ-RESL-NIX-01/02/03 + REQ-PKGS-04) from "code-written-on-Windows but never verified on a real Linux host" to "kernel-enforced on Linux cgroup v2 + green on GitHub Actions Linux runners". The bulk of `crates/nono-cli/src/exec_strategy/supervisor_linux.rs::cgroup` and `profile/mod.rs::load_registry_profile` already exists from v2.3 Phase 25-01 + 26-02 — this phase verifies it end-to-end on Ubuntu 24.04 (cgroup v2 default + systemd-user-session), fixes whatever surfaces, and ships two missing micro-features explicitly called out in v2.5 acceptance criteria: a typed `NonoError::UnsupportedKernelFeature` variant and a `--no-auto-pull` CLI flag.

**In scope:**
- New CI workflow `phase-37-linux-resl.yml` on `ubuntu-24.04` with two jobs (RESL-NIX integration + PKGS-04 auto-pull e2e); required check on PRs to main; sets up `loginctl enable-linger` + `machinectl shell` so the `require_cgroup_v2!`-gated tests run under a real systemd-user-session.
- New `NonoError::UnsupportedKernelFeature { feature: String, hint: String }` variant in `crates/nono/src/error.rs`; FFI maps to existing `ErrUnsupportedPlatform`; pre-fork detection per resource flag; hint text `"cgroup v2 required; boot with systemd.unified_cgroup_hierarchy=1 or cgroup_no_v1=all"`.
- New `--no-auto-pull` flag + `NONO_NO_AUTO_PULL=1` env var threaded through a new `ProfileResolverArgs` struct shared by `nono run` + `nono wrap`; falls back to the existing `profile not found` error with a `DiagnosticFormatter` footer noting the flag is set.
- New `crates/nono-cli/tests/auto_pull_e2e_linux.rs` integration test that uses the std-only TCP server pattern from `registry_client::tests` (Phase 26-02) to mock the registry, signs an ephemeral pack at CI time via sigstore-sign keyless (GitHub OIDC), and verifies against the **production** Sigstore trust root with GitHub-Actions OIDC issuer pin.
- Whatever cgroup-v2 / auto-pull bugs surface when the existing v2.3 code actually executes against a real Linux host.

**Out of scope (deferred):**
- macOS `setrlimit` portion of v2.3 Plan 25-01 — REQUIREMENTS.md explicit (`macOS deprioritized this milestone`). Existing `supervisor_macos.rs` code is *kept as-is*, not stripped.
- `nono inspect` Limits-block format string drift (success criteria #1–3 strings) — included if pre-existing emission already matches; deferred to a follow-up plan if not.
- Auto-pull from real `registry.nono.sh` — not how acceptance #5 will be verified; ephemeral CI-generated pack instead.

</domain>

<decisions>
## Implementation Decisions

### CI workflow shape (D-01..D-04)
- **D-01:** New dedicated `.github/workflows/phase-37-linux-resl.yml` workflow file (NOT bolted onto `ci.yml`). Pins `runs-on: ubuntu-24.04` per REQ-RESL-NIX-01..03 acceptance #4 (current `ci.yml` jobs use `ubuntu-latest`). Cleanest blast-radius isolation; allows independent re-runs.
- **D-02:** cgroup-v2 user-delegation is set up via `loginctl enable-linger <runner-user>` + `machinectl shell <runner-user>@.host` so the tests run under a real systemd-user-session, exercising the unprivileged user-delegated cgroup code path. **Not** running tests as root (would mask delegation bugs and bypass the actual production code path).
- **D-03:** Workflow is a **required check on PRs to main** (blocking merge on red). Matches REQ-RESL-NIX-01 acceptance #4 + the v2.5 baseline-aware gate posture inherited from Phase 41 close.
- **D-04:** Two-job split, **not** matrix-per-backend: `resl-nix` job runs `cargo test -p nono-cli --test resl_nix_linux --test resl_nix_async_signal_safety`; `pkgs-auto-pull` job runs the new `auto_pull_e2e_linux` integration test. Reflects the two distinct REQ families (RESL-NIX vs PKGS) and isolates the signed-artifact fixture path from the cgroup path.

### UnsupportedKernelFeature error (D-05..D-08)
- **D-05:** **Net-new variant** `NonoError::UnsupportedKernelFeature { feature: String, hint: String }` added to `crates/nono/src/error.rs`. Distinct from existing `UnsupportedPlatform(String)` (whole-platform missing) and `NotSupportedOnPlatform { feature }` (feature missing on this OS); new variant is for "this OS supports the feature, but the kernel is misconfigured". Matches REQ-RESL-NIX-01 acceptance #3 verbatim.
- **D-06:** FFI mapping: `UnsupportedKernelFeature { .. } => NonoErrorCode::ErrUnsupportedPlatform` in `bindings/c/src/lib.rs` (reuses the existing FFI code; FFI consumers distinguish via `nono_last_error()` message string). Mirrors the Phase 25-01 precedent for `NotSupportedOnPlatform`. **No new FFI error code** added.
- **D-07:** Hint text on cgroup-v1 host (single line, minimal): `"cgroup v2 required; boot with systemd.unified_cgroup_hierarchy=1 or cgroup_no_v1=all"`. No docs link; no diagnostic shell-command sub-line; intentionally short to fit one terminal row of `nono`'s diagnostic-footer output.
- **D-08:** Detection point: **at sandbox setup, pre-fork, per resource flag**. Only fire `UnsupportedKernelFeature` when the user actually passes `--memory` / `--cpu-percent` / `--max-processes` on a cgroup-v1 host. Other `nono` invocations on a v1 host still work (e.g., pure `--allow` grants without resource limits). Matches v2.3 Plan 25-01 fail-fast precedent (the existing `UnsupportedPlatform("cgroup_v2: ...")` site is the replacement target).

### --no-auto-pull flag semantics (D-09..D-12)
- **D-09:** Scope: only `nono run` + `nono wrap`. These are the two subcommands where profile resolution happens implicitly during user execution. `nono pull` (direct install) intentionally does **not** get the flag — it's an explicit-install command where opt-out makes no sense.
- **D-10:** Env var counterpart: `NONO_NO_AUTO_PULL=1` is honored. CLI flag takes precedence over env var (clap default behavior). Mirrors the existing `NONO_LOG` / `NONO_NO_UPDATE_CHECK` / `NONO_UPDATE_URL` convention (per CLAUDE.md § Configuration).
- **D-11:** Fallback behavior: existing `profile not found` error string verbatim (matches REQ-PKGS-04 acceptance #4 literal wording), **plus** a `DiagnosticFormatter` footer line indicating `--no-auto-pull` is set so users can self-diagnose without a separate error variant.
- **D-12:** Structural placement: new `ProfileResolverArgs` struct in `cli.rs` with `no_auto_pull: bool`, flattened into both `RunArgs` and `WrapArgs` via `#[clap(flatten)]`. Threaded into `profile/mod.rs::load_profile` via a new `ResolveContext` parameter (not a thread-local, not a global). Sets up future profile-resolver options to slot in without re-plumbing the same path.

### Auto-pull e2e fixture strategy (D-13..D-16)
- **D-13:** Signed fixture pack is **generated + signed at CI time** using `sigstore-sign` keyless with the GitHub Actions OIDC token (the same flow Phase 32 sigstore-integration shipped). Hermetic; tests verify the same crypto path real users hit. Avoids check-in TTL / Rekor staleness problems.
- **D-14:** HTTP surface uses the **std-only single-shot TCP server pattern** Phase 26-02 already established in `registry_client::tests` (50 LOC, no new dev-deps). Extended to serve a multi-endpoint mock registry (bundle.json + manifest.json + artifact). NO `mockito` dev-dep (Phase 26-02 deliberately avoided it under portable-subset; Phase 37 holds the line).
- **D-15:** Trust root: **production Sigstore trust root** + GitHub Actions OIDC issuer pin (`https://token.actions.githubusercontent.com`). Most realistic; exercises the same verification path production users hit. **Prerequisite:** the 2 pre-existing `load_production_trusted_root_succeeds` / `verify_bundle_with_invalid_digest` TUF flakes documented in Plan 26-02 SUMMARY must be addressed (or confirmed environmental + not blocking) before this test can be green; researcher should investigate and plan accordingly.
- **D-16:** Test placement: new `crates/nono-cli/tests/auto_pull_e2e_linux.rs` integration test (Linux-gated via `#[cfg(target_os = "linux")]`). Mirrors the existing `resl_nix_linux.rs` pattern. Invokes the `nono` binary via the integration-test harness; covers REQ-PKGS-04 acceptance #1 (happy path), #2 (unknown-name fail-closed), #3 (signature-failure abort), #4 (`--no-auto-pull` fallback).

### Claude's Discretion
- Researcher decides whether the 2 pre-existing TUF-trust-root test flakes need their own sub-plan or can be absorbed as a Phase 37 fix-pass commit (see D-15 prerequisite).
- Planner decides whether `nono inspect` Limits-block string drift (success criteria #1–3 exact strings) gets a Phase 37 plan or a follow-up — depends on what the existing code emits today.
- Researcher confirms whether Ubuntu 24.04's default systemd-user-session provides cgroup-v2 delegation out-of-the-box such that `loginctl enable-linger` is sufficient, or whether additional cgroup-delegation config is required (D-02 implementation detail).
- Planner decides whether the `phase-37-linux-resl.yml` workflow gets a path-filter so it only fires on Linux-touching PRs, or always runs. Memory `feedback_clippy_cross_target` argues for always-on; CI minute budget may argue for path-filter.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### v2.3 carry-forward design + execution summaries (PRIMARY)
- `.planning/phases/25-cross-platform-resl-aipc-unix-design/25-01-RESL-NIX-SUMMARY.md` — v2.3 Plan 25-01 execution summary. Documents the `CgroupSession` RAII struct, async-signal-safe `place_self_in_cgroup_raw`, `MacosResourceLimits` pre_exec applier, `apply_resource_limits_unix` dispatch helper, integration test coverage shape (`resl_nix_linux.rs` 5 tests + `resl_nix_macos.rs` 4 tests), and the `NonoError::NotSupportedOnPlatform` variant that Phase 37 will sit alongside.
- `.planning/phases/26-pkg-streaming-followup/26-02-PKGS-STREAMING-SUMMARY.md` — v2.3 Plan 26-02 execution summary. Documents `download_artifact_to_path` streaming + `VerifiedDownloads` wrapper + `load_registry_profile` + `is_registry_ref` auto-pull plumbing, the std-only TCP server fixture pattern Phase 37 inherits (D-14), and the explicit deferral of the e2e auto-pull suite that Phase 37 now closes.
- `.planning/phases/26-pkg-streaming-followup/26-02-PKGS-STREAMING-PLAN.md` *(if present)* — Plan 26-02's original PLAN.md if it survived; contains the mockito-vs-portable-subset trade-off context.

### v2.5 milestone planning
- `.planning/ROADMAP.md` § Phase 37 — phase goal + 6 success criteria. Acceptance strings for `nono inspect` Limits-block format are LOCKED here.
- `.planning/REQUIREMENTS.md` § RESL-NIX + § PKGS — REQ-RESL-NIX-01/02/03 + REQ-PKGS-04 with full acceptance criteria. REQ-RESL-NIX-01 acceptance #3 names the `cgroup_no_v1` boot-flag hint text Phase 37 must emit (D-07).
- `.planning/PROJECT.md` § Current Milestone — v2.5 scope context; macOS-deprioritized rationale.

### Code surfaces touched
- `crates/nono/src/error.rs` — `NonoError` enum; D-05 adds `UnsupportedKernelFeature` variant here.
- `bindings/c/src/lib.rs` — `NonoError → NonoErrorCode` FFI match; D-06 adds the new variant arm.
- `crates/nono-cli/src/exec_strategy/supervisor_linux.rs` — existing `cgroup` submodule from Phase 25-01; D-08 detection point lives here (the existing `UnsupportedPlatform("cgroup_v2: ...")` site is the replacement target).
- `crates/nono-cli/src/exec_strategy/supervisor_macos.rs` — existing macOS code kept as-is (out of scope but not stripped).
- `crates/nono-cli/src/profile/mod.rs:2179–2233` — `is_registry_ref` + `load_registry_profile` auto-pull dispatch; D-12 threads `ResolveContext` here.
- `crates/nono-cli/src/cli.rs` — D-12 adds `ProfileResolverArgs` struct flattened into `RunArgs` + `WrapArgs`.
- `crates/nono-cli/src/registry_client.rs:13` — `DEFAULT_REGISTRY_URL = https://registry.nono.sh` + `NONO_REGISTRY` env override; D-14 mock-server test points `NONO_REGISTRY` at `127.0.0.1:<ephemeral>`.
- `crates/nono-cli/tests/resl_nix_linux.rs` + `resl_nix_async_signal_safety.rs` — existing Linux RESL integration tests Phase 37 will execute on CI for the first time.
- `crates/nono-cli/tests/auto_pull_e2e_linux.rs` *(new)* — D-16 creates this file.

### CI + workflow infrastructure
- `.github/workflows/ci.yml` — existing CI workflow; Phase 37 adds a sibling, does not modify this file.
- `.github/workflows/phase-37-linux-resl.yml` *(new)* — D-01 creates this file.

### Cross-cutting invariants + patterns
- `CLAUDE.md` § Cross-target clippy verification — Phase 37 MUST run `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` before close (per memory `feedback_clippy_cross_target`; ROADMAP Cross-Phase Invariants reiterates).
- `CLAUDE.md` § Coding Standards — `clippy::unwrap_used` strict; tests that touch `HOME`/`TMPDIR` must save/restore env; `NonoError` propagation via `?`.
- `.planning/codebase/STRUCTURE.md` — workspace layout (5 crates per memory `project_workspace_crates`).

### Related but not direct dependencies
- `docs/architecture/upstream-parity-strategy.md` — Phase 33 ADR. NOT load-bearing for Phase 37 since this is not an UPST phase; D-19 cross-platform byte-identity invariant does NOT gate this phase.
- `.planning/phases/35-upst3-closure-quick-wins/35-02-*-SUMMARY.md` *(if present)* — Landlock profiles-dir fix; reference pattern for "Linux code coded on Windows host + verified on GitHub Actions Linux runner" workflow. Mentioned in ROADMAP Phase 37 goal as the precedent.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`crates/nono-cli/src/exec_strategy/supervisor_linux.rs::cgroup` submodule** — `CgroupSession` (detect, new, apply_limits, install_pre_exec, place_self_in_cgroup_raw, kill_all, disarm, Drop). Already wired into Direct + Supervised execution strategies. Phase 37 reuses verbatim; the only modification expected is replacing `NonoError::UnsupportedPlatform("cgroup_v2: ...")` with `NonoError::UnsupportedKernelFeature { feature, hint }` (D-08).
- **`crates/nono-cli/tests/resl_nix_linux.rs`** — 5 integration tests (memory OOM kill, pids.max, timeout, atomic grandchild kill, no-warning assertion) all gated on `require_cgroup_v2!` macro. Compile-skip on Windows host; will execute for the first time under Phase 37's new CI workflow.
- **`crates/nono-cli/tests/resl_nix_async_signal_safety.rs`** — additional Phase 25-01 child-process safety tests; Phase 37 CI runs these too.
- **Phase 26-02 std-only TCP server in `registry_client::tests::spawn_one_shot_server`** — ~50 LOC single-shot HTTP fixture. D-14 extends this pattern into a multi-endpoint mock registry server for the new e2e test.
- **`profile/mod.rs::is_registry_ref` + `load_registry_profile`** — already shipped in Phase 26-02. Auto-pull plumbing is in place; Phase 37 only adds the `ResolveContext` parameter (D-12) to honor `--no-auto-pull`.
- **`NONO_REGISTRY` env override in `registry_client.rs:311`** — the test harness uses this to point nono at the mock TCP server instead of `https://registry.nono.sh`.

### Established Patterns
- **Linux code coded on Windows + verified on GitHub Actions Linux runner** — per ROADMAP Phase 37 goal: "same pattern that landed Phase 35-02 Landlock profiles-dir fix". Phase 37 inherits this workflow shape.
- **Cross-target clippy from Windows host** — `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` is mandatory before close (memory `feedback_clippy_cross_target`).
- **`NonoError` cross-cutting variant additions touch 3 surfaces** — Phase 25-01's `NotSupportedOnPlatform` precedent: add to `crates/nono/src/error.rs`; update `bindings/c/src/lib.rs` FFI match (otherwise workspace cargo check fails non-exhaustive); update language bindings if their match is exhaustive too (typically they go via the FFI code, so not always needed).
- **Async-signal-safe child placement** — `place_self_in_cgroup_raw` uses only raw `libc::write()` post-fork; the Phase 25-01 pattern continues to hold.
- **RAII cgroup lifecycle** — `CgroupSession` creates in parent, `Drop` removes after child reaped.

### Integration Points
- **Phase 41 surface drift** — Phase 41 closed 2026-05-16/17 and touched `exec_strategy.rs` (the same file Phase 25-01 wrote into). Phase 37 may need to confirm the `CapabilityRequest::path` → `HandleTarget::FilePath` API migration (Phase 41) is consistent with how the cgroup pre_exec setup hands paths around. Memory `project_phase41_open_gaps` notes 3 open CI gap classes (macOS pre-existing compile errors, Linux clippy zombie_processes+.unwrap(), 1 Linux test failure) — researcher should confirm none of these intersect Phase 37's CI lanes before lock-in.
- **FFI ABI** — D-06 reuses `ErrUnsupportedPlatform`, so `bindings/c/include/nono.h` doesn't change shape, but `nono-py` + `nono-ts` may have a code path that strings on "Platform not supported" prefix; the new variant's `Display` format starts differently (`"Kernel feature not supported: {feature} ({hint})"` vs `"Platform not supported: {0}"`). External binding test impact: low-but-non-zero; researcher to confirm.
- **NONO_TEST_HOME seam (Phase 27.1)** — D-15 production-trust-root posture means we do NOT use NONO_TEST_HOME for the auto-pull test; the test runs against the real production trust root. If D-15 prerequisite (TUF flakes) blocks, the fallback is to flip to NONO_TEST_HOME-based test-only trust root.

</code_context>

<specifics>
## Specific Ideas

- **REQ-RESL-NIX-01 acceptance #2** specifies the exact `nono inspect` Limits-block string: `memory: 100M (cgroup v2 memory.max)`. Same shape for `cpu_percent: 25 (cgroup v2 cpu.max 25000 100000)` and `max_processes: 5 (cgroup v2 pids.max)`. These strings are LOCKED — researcher must check whether the current `nono inspect` emission matches verbatim, and if not, planner adds a string-fix sub-plan.
- **D-07 hint text** (cgroup-v1) is LOCKED at: `"cgroup v2 required; boot with systemd.unified_cgroup_hierarchy=1 or cgroup_no_v1=all"`. Single line, no trailing period needed; will be rendered via `DiagnosticFormatter`.
- **D-15 prerequisite** — the 2 pre-existing TUF-trust-root test flakes (`nono::trust::bundle::tests::load_production_trusted_root_succeeds`, `verify_bundle_with_invalid_digest`) carried in Plan 26-02 SUMMARY's "Deferred Items". Phase 37 cannot ship a green CI close gate while these are red on the same Linux runner. Researcher should determine whether they're truly environmental (data-freshness) or load-bearing.
- **Ubuntu 24.04 + `loginctl enable-linger` + `machinectl shell`** — the specific incantation for systemd-user-session + cgroup-v2 user delegation on GitHub Actions runners. Researcher should confirm whether the runner image ships systemd as PID 1 (it does on modern Ubuntu runners) or whether additional `sudo systemctl start systemd-logind` setup is needed.

</specifics>

<deferred>
## Deferred Ideas

- **macOS `setrlimit` portion of Plan 25-01** — Already deferred at v2.5 scoping (REQUIREMENTS.md explicit). Existing `supervisor_macos.rs` code is kept on disk; macOS host UAT belongs in v2.6+.
- **Phase 38 REQ-AAHX-HOST-01 native re-validation** — Depends on Phase 37 native UAT; pre-deferred to v2.6 per REQUIREMENTS.md.
- **Mockito dev-dep** — Phase 26-02 deliberately avoided; D-14 holds the line. If a future phase needs richer HTTP mocking (e.g., partial-response simulation), revisit then.
- **Net-new FFI error code `ErrUnsupportedKernel`** — D-06 chose to reuse `ErrUnsupportedPlatform`. If language-binding consumers (`nono-py`, `nono-ts`) later demand programmatic kernel-vs-platform distinction, a future phase can add the code without breaking ABI (new variant at the end of the enum).
- **Real registry.nono.sh as e2e source** — D-13 chose ephemeral CI-signed pack instead. A separate "registry uptime smoke test" could be added in v2.6 if production-registry monitoring becomes a concern.
- **Path-filtered workflow trigger** — D-01 didn't lock whether `phase-37-linux-resl.yml` always runs or path-filters to Linux-touching PRs. Planner decides; either is acceptable.

</deferred>

---

*Phase: 37-linux-resl-backends-pkgs-auto-pull*
*Context gathered: 2026-05-19*
