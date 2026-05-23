---
phase: quick-260523-kzd
plan: "01"
subsystem: ci-workflow
tags: [bugfix, compile-error, sigstore, cgroup, workflow]
dependency_graph:
  requires: []
  provides: [REQ-CI-FU-01-precondition]
  affects: [.github/workflows/phase-37-linux-resl.yml, crates/nono-cli/src/exec_strategy/supervisor_linux.rs, tools/sign-fixture]
tech_stack:
  added: [tools/sign-fixture (new workspace member)]
  patterns: [workspace member for CI tooling, std::result::Result disambiguation]
key_files:
  created:
    - tools/sign-fixture/Cargo.toml
    - tools/sign-fixture/src/main.rs
  modified:
    - Cargo.toml (workspace members)
    - .github/workflows/phase-37-linux-resl.yml (PKGS-04 job)
    - crates/nono-cli/src/exec_strategy/supervisor_linux.rs (3 test fn signatures)
decisions:
  - "Use tools/sign-fixture workspace member instead of cargo example to expose sigstore-sign with tokio+chrono as regular deps (dev-dep workaround)"
  - "Qualify std::result::Result in test fns only; leave nono::Result import at line 859 unchanged"
metrics:
  duration: "~8 minutes"
  completed: "2026-05-23"
  tasks_completed: 3
  files_changed: 5
---

# Phase quick-260523-kzd Plan 01: Fix Phase 37 RESL Workflow Compile Bugs Summary

Two independent compile-time bugs prevented both jobs in `phase-37-linux-resl.yml` from reaching
their integration tests. BUG-1 (PKGS-04 job): created `tools/sign-fixture/` workspace crate with
`tokio`+`chrono` as regular deps to replace the broken `sigstore-sign --example sign_blob` invocation.
BUG-2 (RESL-NIX job): fully-qualified `std::result::Result` in three test fn signatures shadowed
by `use nono::Result`.

## What Was Built

### BUG-1 Fix: tools/sign-fixture workspace member

Created `tools/sign-fixture/` as a new Cargo workspace member that ports the `sigstore-sign 0.7.0`
`sign_blob` example into a standalone binary. The example's `tokio` and `chrono` dependencies are
declared as regular `[dependencies]` instead of dev-dependencies, which allows Cargo to resolve them
when building from a consumer workspace (Cargo does not fetch external crates' dev-deps).

The new binary preserves the full CLI interface of the original example:
- Positional `<ARTIFACT>` argument
- `-o`/`--output`, `-t`/`--token`, `--staging`, `--v2`, `-h`/`--help` flags
- GitHub Actions ambient OIDC detection via `IdentityToken::detect_ambient()`

The workflow's PKGS-04 job (`phase-37-linux-resl.yml`) was updated to use:
- `cargo build --release -p sign-fixture` (was: `cargo build --release -p sigstore-sign --example sign_blob`)
- `cargo run --release -p sign-fixture -- artifact.tar.gz -o artifact.tar.gz.sigstore.json` (was: `cargo run --release -p sigstore-sign --example sign_blob -- ...`)

All OIDC token flow and signing semantics are preserved.

### BUG-2 Fix: supervisor_linux.rs test fn signatures

The `cgroup` test module at line 859 contains `use nono::{NonoError, Result, CGROUP_V2_HINT}`.
`nono::Result<T>` is a single-argument alias. Three test functions declared the two-argument form
`-> Result<(), Box<dyn std::error::Error>>`, which is only valid for `std::result::Result`.
The compiler emits E0107 + E0277 for each function on Linux.

Fixed by fully-qualifying the return type on the three affected test fns only:
- `fn cgroup_session_apply_limits() -> std::result::Result<(), Box<dyn std::error::Error>>`
- `fn cgroup_session_pre_exec_places_pid() -> std::result::Result<(), Box<dyn std::error::Error>>`
- `fn cgroup_kill_terminates_grandchildren() -> std::result::Result<(), Box<dyn std::error::Error>>`

Line 859 (`use nono::{NonoError, Result, CGROUP_V2_HINT}`) was NOT touched — the non-test module
code uses `nono::Result` correctly with the single-argument form.

## Verification Results

### Windows host (cargo check)
- `cargo check -p sign-fixture`: PASSED
- `cargo check --workspace`: PASSED
- `cargo fmt --all -- --check` for files modified in this task: PASSED
  (Pre-existing format issues in `crates/nono/src/error.rs`, `crates/nono/src/sandbox/windows.rs`,
  `crates/nono/src/supervisor/mod.rs`, and `crates/nono/src/supervisor/socket_windows.rs` are
  out of scope for this quick task.)

### Acceptance criteria verification
- `grep -c "sign_blob" .github/workflows/phase-37-linux-resl.yml` = 0 (PASSED)
- `grep -c "sign-fixture" .github/workflows/phase-37-linux-resl.yml` = 5 (2 executable invocations + 3 comments; executable-only count = 2, PASSED)
- `SIGSTORE_ID_TOKEN_AUDIENCE: sigstore` env var remains on signing step (VERIFIED)
- `grep -c "std::result::Result" crates/nono-cli/src/exec_strategy/supervisor_linux.rs` = 3 (PASSED)
- Line 859 `use nono::{NonoError, Result, CGROUP_V2_HINT}` unchanged (VERIFIED)

## Cross-Target Clippy Status: PARTIAL

Per CLAUDE.md § Coding Standards "Cross-target clippy verification" and `.planning/templates/cross-target-verify-checklist.md`:

The modified file `crates/nono-cli/src/exec_strategy/supervisor_linux.rs` is under `exec_strategy/`
and contains `#[cfg(target_os = "linux")]` blocks. Windows-host `cargo check` does NOT exercise
cfg-gated Linux branches. Cross-target clippy requires:

```bash
cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used
```

The `x86_64-unknown-linux-gnu` cross-toolchain is NOT installed on this dev host (Windows 11).

**Deferred to:** Live `gh workflow run phase-37-linux-resl.yml` after push. The RESL-NIX job
includes a dedicated "Cross-target clippy gate (Linux from Linux)" step that runs exactly this
command.

## Commits

| Task | Commit | Subject |
|------|--------|---------|
| 1 (BUG-1 crate) | c8b3eacf | feat(quick-260523-kzd): add tools/sign-fixture workspace member (BUG-1) |
| 2 (BUG-1 wiring) | 166100cc | fix(quick-260523-kzd): update PKGS-04 job to use sign-fixture binary (BUG-1) |
| 3 (BUG-2 fix) | (see below) | fix(quick-260523-kzd): std-qualify Result in 3 test fn signatures (BUG-2) |

## Deviations from Plan

None. All three tasks executed exactly as planned. The only minor deviation was removing
`sign_blob` references from comments (not just executable lines) to satisfy the `grep -c "sign_blob" = 0`
acceptance criterion — this is a documentation improvement, not a behavioral change.

## unwrap Policy Note

The `tools/sign-fixture/src/main.rs` binary uses `process::exit(1)` for error paths (ported
verbatim from the upstream `sign_blob` example). There are no `.unwrap()` or `.expect()` calls
added. The only use of `unwrap_or_else` is in the output path default construction
(`output.unwrap_or_else(|| format!(...))`) which cannot fail. This is consistent with CLAUDE.md
§ Coding Standards: "Libraries should almost never panic" — `sign-fixture` is CI tooling, not
part of the security-critical library surface.

## Next Steps for Operator

1. `git push origin main` (merge worktree commits to main first via the orchestrator)
2. `gh workflow run .github/workflows/phase-37-linux-resl.yml` or wait for push-triggered run
3. `gh run watch <run-id>` to monitor both jobs
4. Confirm both `resl-nix` and `pkgs-auto-pull` jobs report `conclusion=success`
5. On green: mark REQ-CI-FU-01 as satisfied in Plan 46-02 tracking

## Threat Flags

No new threat surface introduced. The `sign-fixture` binary is `publish = false` CI tooling that
ports existing upstream signing logic verbatim. The OIDC token flow is identical to the original
`sign_blob` example; no new network endpoints, auth paths, or trust boundaries were introduced.

## Self-Check: PASSED

- `tools/sign-fixture/Cargo.toml`: FOUND
- `tools/sign-fixture/src/main.rs`: FOUND
- `Cargo.toml` members includes `tools/sign-fixture`: FOUND
- `.github/workflows/phase-37-linux-resl.yml` updated: VERIFIED (sign_blob=0, sign-fixture in build+run steps)
- `supervisor_linux.rs` 3 std-qualified signatures: VERIFIED
- `supervisor_linux.rs` line 859 unchanged: VERIFIED
- Task 1 commit c8b3eacf: FOUND
- Task 2 commit 166100cc: FOUND
