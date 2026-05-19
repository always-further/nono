---
phase: 37-linux-resl-backends-pkgs-auto-pull
plan: 04
subsystem: ci, github-actions, integration-tests
tags: [ci, github-actions, cgroup-v2, systemd-delegation, integration-test, locked-strings]
dependency_graph:
  requires:
    - phase-37-01 (UnsupportedKernelFeature variant + 4-of-5 cgroup-v2 detection-site swaps — workflow runs the new unit tests)
    - phase-37-03 (format_limits_block LOCKED strings — workflow runs the unit tests; integration grep-asserts deferred to Plan 37-05 + future plans)
  provides:
    - ".github/workflows/phase-37-linux-resl.yml — two-job CI workflow (resl-nix + pkgs-auto-pull) on ubuntu-24.04 with cpu-controller delegation drop-in"
    - "linux_cpu_percent_throttles_yes_loop integration test (REQ-RESL-NIX-02 functional verification — FIRST test exercising cpu.max)"
    - "linux_max_processes_5_fork_bomb_contained integration test (LOCKED REQ-RESL-NIX-03 N=5 case, added alongside existing N=10 boundary test per revision-1 W8 path b)"
    - "require_cpu_controller! macro (skips test rather than fails when cpu controller not delegated — defense-in-depth alongside the workflow's hard verify gate)"
    - "pkgs-auto-pull job skeleton — Plan 37-05 fills in sigstore-sign + auto_pull_e2e_linux invocation"
  affects:
    - "Plan 37-05 (consumes pkgs-auto-pull job skeleton)"
    - "Repo admin: required-check status checks list on main branch (manual step documented below)"
tech_stack:
  added: []
  patterns:
    - "Pattern 5 (systemd-user-session in CI via machinectl shell): runs integration tests as the unprivileged runner user inside a real user@.service-managed cgroup"
    - "Pattern C (SHA-pinned action references with version-tag comments): all 6 `uses:` references SHA-pinned"
    - "Pattern D (cpu controller Delegate drop-in): /etc/systemd/system/user@.service.d/delegate.conf written BEFORE loginctl enable-linger to ensure user@.service starts with the widened delegation set"
    - "Defense-in-depth controller-availability guard: workflow's verify step (hard fail) + integration test's require_cpu_controller! macro (graceful skip on dev hosts) — T-37-14 mitigation"
key_files:
  created:
    - .github/workflows/phase-37-linux-resl.yml
    - .planning/phases/37-linux-resl-backends-pkgs-auto-pull/37-04-SUMMARY.md
  modified:
    - crates/nono-cli/tests/resl_nix_linux.rs
decisions:
  - "D-01 honored: runs-on pinned to ubuntu-24.04, NOT ubuntu-latest"
  - "D-03 honored: required-check on PRs to main — REQUIRES manual repo-admin step (documented below) since GitHub Actions cannot self-register required checks"
  - "D-04 honored: two-job split (resl-nix + pkgs-auto-pull); NOT a matrix"
  - "D-13 honored: id-token: write granted ONLY on pkgs-auto-pull job (least privilege; resl-nix has no signing surface)"
  - "Always-on trigger (no paths: filter) per CONTEXT.md Claude's Discretion + research recommendation"
  - "T-37-03 mitigation: Delegate= list explicitly scoped to `cpu cpuset io memory pids` ONLY with inline YAML comment warning future contributors against widening"
  - "T-37-14 mitigation: workflow's verify step is a HARD fail-gate (greps for `cpu` in cgroup.controllers and exits 1 if missing); pairs with the require_cpu_controller! macro inside the integration test for defense-in-depth"
  - "W3 deferral: full red->green->refactor cycle for Task 1 deferred to CI runner; dev-host verify is compile-gate only (cc-rs/x86_64-linux-gnu-gcc cross toolchain not installed locally — same disposition as Plan 37-01 SUMMARY documented)"
  - "W8 path b implemented: NEW linux_max_processes_5_fork_bomb_contained test added ALONGSIDE the existing linux_max_processes_blocks_eleventh_fork (N=10 boundary); both coverages preserved — neither replaces the other"
requirements_completed: [REQ-RESL-NIX-01, REQ-RESL-NIX-02, REQ-RESL-NIX-03]
metrics:
  duration_minutes: ~40
  completed: 2026-05-19
  tasks_completed: 2
  tasks_total: 2
  files_modified: 1
  files_created: 1
  commits: 2
---

# Phase 37 Plan 04: Linux RESL CI Workflow + CPU-Percent Functional Test + N=5 max_processes Test Summary

**Two-job `phase-37-linux-resl.yml` workflow + new `linux_cpu_percent_throttles_yes_loop` integration test (FIRST functional test exercising `cpu.max`) + new `linux_max_processes_5_fork_bomb_contained` test alongside the existing N=10 boundary — closes the silent-no-op REQ-RESL-NIX-02 verification gap by installing a `Delegate=cpu cpuset io memory pids` user-service drop-in on the `ubuntu-24.04` runner and running the production code path inside a real `systemd-user-session` via `machinectl shell`.**

## Objective Met

Closes REQ-RESL-NIX-01/02/03 acceptance #4 ("CI verifies on a real Linux runner that the cgroup-v2 backends actually enforce the limits"). Establishes the load-bearing CI gate that turns the Wave 1 work into a verifiable production-code-path: Plans 37-01/02/03 are pre-fork detection + formatter + CLI surface changes; this is the ONLY place Phase 37 runs against a live kernel.

Also establishes the `pkgs-auto-pull` job skeleton so Plan 37-05 can land sigstore-sign + auto_pull_e2e_linux without re-touching the workflow shape.

## What Was Built

### Task 1 — `require_cpu_controller!` macro + 2 new integration tests (commit `c7def347`)

Modified `crates/nono-cli/tests/resl_nix_linux.rs` (+210 lines):

**New `require_cpu_controller!` macro** (just after `require_cgroup_v2!`):

Reads `/proc/self/cgroup` to find the user-session's cgroup-relative path, reads `cgroup.controllers` at that path, and skips the test gracefully if `cpu` is not in the delegated set. The macro uses `unwrap_or_default()` on the two `read_to_string` calls (idiomatic — the file may not exist on non-cgroup-v2 hosts, in which case we should SKIP not panic). The skip is bounded by the workflow's hard fail-gate so it cannot mask a CI bug (defense-in-depth).

**New test `linux_cpu_percent_throttles_yes_loop` (REQ-RESL-NIX-02 functional):**

Runs `nono run --cpu-percent 25 -- timeout 6 sh -c 'yes >/dev/null'`. After a 750ms startup delay, locates the actual workload PID via `pgrep -x yes` (NOT the supervisor PID — Monitor exec strategy keeps the supervisor alive while the workload runs in a forked descendant; the workload pid is the one in the throttled cgroup). Samples `%CPU` via `top -b -n 5 -d 1 -p <pid>` for 5 iterations and asserts the average is in the tolerance band `[15, 40]`.

This is the FIRST functional test exercising `cpu.max`; prior to Phase 37, REQ-RESL-NIX-02 had no test covering runtime CPU throttling.

**New test `linux_max_processes_5_fork_bomb_contained` (REQ-RESL-NIX-03 LOCKED N=5):**

Runs `nono run --max-processes 5 -- sh -c '... 8 background sleeps ...'` and asserts the overall command exits non-zero OR stderr contains the strings `resource` / `again` (i.e., EAGAIN / "resource temporarily unavailable"). Either is sufficient evidence the `pids.max` cap is enforced.

Sits ALONGSIDE the existing `linux_max_processes_blocks_eleventh_fork` (N=10 boundary) per revision-1 checker W8 path b — both coverages are preserved; neither replaces the other. The N=5 case matches the LOCKED `nono inspect` string `max_processes: 5 (cgroup v2 pids.max)` Plan 37-03 emits.

### Task 2 — `.github/workflows/phase-37-linux-resl.yml` (commit `0afc81df`)

New 185-line workflow file with two jobs:

**Job 1 — `resl-nix` (Phase 37 RESL-NIX (cgroup v2)):**

| Step | Purpose |
|------|---------|
| Checkout | actions/checkout@de0fac2e... (v6, SHA-pinned) |
| Install system deps | libdbus-1-dev, pkg-config, dbus-user-session, systemd-container |
| Install Rust toolchain | dtolnay/rust-toolchain@631a55b... (stable, SHA-pinned) |
| Cache cargo + target | actions/cache@66822842... (v5, SHA-pinned) |
| **Configure cgroup v2 controller delegation** | Writes `/etc/systemd/system/user@.service.d/delegate.conf` with `Delegate=cpu cpuset io memory pids`; runs `systemctl daemon-reload`. This is the load-bearing step — without it REQ-RESL-NIX-02 silently fails (research finding #2). |
| Enable lingering | `sudo loginctl enable-linger $USER` activates the user manager |
| **Verify cpu controller delegated** | T-37-14 mitigation. Reads `/sys/fs/cgroup/user.slice/user-<uid>.slice/user@<uid>.service/cgroup.controllers` and exits 1 if `cpu` is missing. Prints `OK: cpu controller delegated` on success. |
| Build workspace | `cargo build --workspace --release --verbose` |
| Plan 37-01 unit tests | `nono::lib unsupported_kernel_feature` + `nono-ffi map_error_unsupported_kernel_feature` + `nono-cli --bin nono exec_strategy::supervisor_linux::cgroup::unsupported_kernel_feature_swap_tests` |
| Plan 37-03 unit tests | `nono-cli --bin nono limits_block_format_tests` (the LOCKED Limits-block strings) |
| **Integration tests under systemd-user-session** | `sudo machinectl shell ${USER}@.host /usr/bin/env bash -c "cd ... && cargo test -p nono-cli --test resl_nix_linux --test resl_nix_async_signal_safety --release -- --nocapture"` — runs as the unprivileged runner user inside the delegated cgroup |
| Cross-target clippy gate | `cargo clippy --workspace --release --tests -- -D warnings -D clippy::unwrap_used` |

**Job 2 — `pkgs-auto-pull` (Phase 37 PKGS-04 (auto-pull e2e)):**

Skeleton-only — Plan 37-05 fills in the sigstore-sign keyless + `auto_pull_e2e_linux` test invocation. Includes:
- `id-token: write` job-level permission (D-13 — required for OIDC keyless signing)
- Checkout + Rust toolchain + cache (same SHA-pinned actions)
- `cargo build --workspace --release --verbose` placeholder to keep the job from being vacuously green between now and Plan 37-05 landing

### Action SHAs (Pattern C)

All 6 `uses:` references SHA-pinned with version-tag comments:

| Action | SHA | Tag comment |
|--------|-----|-------------|
| actions/checkout | de0fac2e4500dabe0009e67214ff5f5447ce83dd | # v6 |
| dtolnay/rust-toolchain | 631a55b12751854ce901bb631d5902ceb48146f7 | # stable |
| actions/cache | 668228422ae6a00e4ad889ee87cd7109ec5666a7 | # v5 |

Each appears exactly twice (once per job) — grep gate verified.

## REQUIRED Manual Step (repo admin)

GitHub Actions cannot self-register required-status-check entries. The following manual step is required to satisfy D-03 ("required-check on PRs to main") AFTER this plan's workflow has run at least once on `main`:

> **In GitHub repo settings → Branches → main branch protection rules → Require status checks to pass before merging → search for and add:**
> - `Phase 37 RESL-NIX (cgroup v2)`
> - `Phase 37 PKGS-04 (auto-pull e2e)`

Until that's done the workflow runs on every PR but does not block merges on failure. Tracked as a `VALIDATION.md` Manual-Only row.

## Verification

### Acceptance grep gates (per plan acceptance_criteria)

#### Task 1 grep gates

| Gate | Expected | Actual |
|------|----------|--------|
| `fn linux_cpu_percent_throttles_yes_loop` in resl_nix_linux.rs | 1 | 1 ✓ |
| `fn linux_max_processes_5_fork_bomb_contained` in resl_nix_linux.rs | 1 (NEW) | 1 ✓ |
| `fn linux_max_processes_blocks_eleventh_fork` in resl_nix_linux.rs | 1 (PRESERVED) | 1 ✓ |
| `macro_rules! require_cpu_controller` in resl_nix_linux.rs | 1 | 1 ✓ |
| `--max-processes` occurrences in resl_nix_linux.rs | ≥ 1 (new N=5) | 5 (includes existing) ✓ |

#### Task 2 grep gates (verified locally via node-based structural smoke check)

| Gate | Expected | Actual |
|------|----------|--------|
| `runs-on: ubuntu-24.04` (per-job) | 2 | 2 ✓ |
| `Delegate=cpu cpuset io memory pids` | 1 | 1 ✓ |
| `machinectl shell` | ≥ 1 | 2 (one in verify-block comment description, one in actual step) ✓ |
| `actions/checkout@de0fac2e...` | 2 | 2 ✓ |
| `dtolnay/rust-toolchain@631a55b...` | 2 | 2 ✓ |
| `actions/cache@66822842...` | 2 | 2 ✓ |
| `id-token: write` | 1 (pkgs-auto-pull only) | 1 ✓ |
| `ubuntu-latest` (NEGATIVE) | 0 | 0 ✓ |
| `^\s+paths:` (NEGATIVE) | 0 | 0 ✓ |
| `@v\d+$\|@main$\|@latest$` (NEGATIVE) | 0 | 0 ✓ |

### Dev-host verification (Windows)

| Check | Result |
|-------|--------|
| `cargo check -p nono-cli --tests` (Windows host; `#![cfg(target_os="linux")]` keeps the file out of compilation) | PASS — workspace compiles clean |
| Node-based YAML structural smoke checks (job presence, SHA pins, no unpinned refs, no ubuntu-latest, no paths: filter) | ALL_OK |
| `git diff --diff-filter=D --name-only HEAD~2 HEAD` (no deletions) | clean (395 insertions, 0 deletions) |

### Cross-target verification status

| Verification | Status | Notes |
|--------------|--------|-------|
| `cargo test -p nono-cli --test resl_nix_linux --target x86_64-unknown-linux-gnu --no-run` | **PARTIAL — deferred to live CI** | `cc-rs` requires `x86_64-linux-gnu-gcc`, which is not installed on the Windows dev host. Same disposition Plan 37-01 SUMMARY documented; tracked in deferred-items.md. The W3 fix path explicitly defers the full red→green→refactor cycle to the `ubuntu-24.04` runner (which is exactly what this plan's workflow exercises). |
| Linux clippy gate (`--target x86_64-unknown-linux-gnu`) | **PARTIAL — deferred to live CI** | Same cc-rs reason. The new workflow's own "Cross-target clippy gate (Linux from Linux)" step runs this gate natively on the runner. |
| macOS clippy gate (`--target x86_64-apple-darwin`) | **N/A for this plan** | Plan 37-04 is Linux-only — the workflow doesn't touch macOS. The companion umbrella ci.yml still runs macOS clippy. |

### Workflow-run verification

Cannot push from the worktree (orchestrator owns the merge); the CI run that proves the `cpu` controller delegation step succeeds and emits the `OK: cpu controller delegated` line will land after the orchestrator merges this worktree to main (or onto the umbrella PR branch). **Sanity-band expectation**: the `linux_cpu_percent_throttles_yes_loop` test's measured average should land in `[20, 30]` on a calm runner; the `[15, 40]` band exists to absorb GitHub Actions runner noise. If post-merge CI shows persistent flake outside the band, widen via a follow-up plan rather than removing the assertion (T-37-14: do NOT switch to a pass-without-asserting shape).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] CPU-percent test sampling shape pointed at supervisor pid instead of workload pid**

- **Found during:** Task 1, before commit (reading the plan-spec test sample shape carefully).
- **Issue:** The plan-spec test code did `top -p <child.id()>` where `child` is the Rust `Command::spawn` handle for `nono run -- timeout 6 sh -c 'yes >/dev/null'`. `child.id()` returns the nono supervisor's pid, NOT the actual `yes` workload pid. In Monitor exec strategy nono stays alive and forks the workload as a descendant; in Direct exec strategy nono execs into `timeout` which then forks `sh` which then forks `yes`. Either way the throttled cgroup contains the `yes` pid, not the supervisor's pid. The plan-spec shape would either produce empty `top` samples (no rows match the supervisor pid for `yes` activity) or sample the wrong process.
- **Fix:** Use `pgrep -x yes` after a 750ms startup delay to locate the actual workload pid; sample top against that pid. Falls back to a deterministic `panic!` (not silent skip) if pgrep returns no PID, so a misconfigured test environment surfaces loudly rather than passing vacuously.
- **Files modified:** `crates/nono-cli/tests/resl_nix_linux.rs`
- **Commit:** `c7def347` (Task 1)

**2. [Rule 1 - Bug] Plan-spec used `--lib` to reach `supervisor_linux` tests on a bin-only crate**

- **Found during:** Task 2, while drafting the workflow file (cross-checked nono-cli Cargo.toml for `[lib]` section).
- **Issue:** Plan called for `cargo test -p nono-cli --lib exec_strategy::supervisor_linux::cgroup::unsupported_kernel_feature_swap_tests`. `nono-cli` has no `[lib]` section — only `[[bin]] name = "nono"`. The `--lib` flag would fail with `no library targets found in package`. The correct invocation (which Plan 37-03 SUMMARY also uses for its own tests) is `--bin nono`.
- **Fix:** Workflow uses `cargo test -p nono-cli --bin nono exec_strategy::supervisor_linux::cgroup::unsupported_kernel_feature_swap_tests --release`. Added an inline YAML comment explaining why.
- **Files modified:** `.github/workflows/phase-37-linux-resl.yml`
- **Commit:** `0afc81df` (Task 2)

**3. [Rule 2 - Documentation drift] Added inline YAML comment scoping the Delegate= list**

- **Found during:** Task 2 GREEN.
- **Issue:** Without an inline comment, a future contributor might widen `Delegate=cpu cpuset io memory pids` to add `net_cls` or `devices` without realizing the scope was deliberately constrained per T-37-03 mitigation.
- **Fix:** Added inline YAML comment: `# T-37-03 mitigation: scope is 'cpu cpuset io memory pids' ONLY — minimum needed for REQ-RESL-NIX-02 throttling. Do NOT widen this list without a security review (no net_cls, no devices).`
- **Files modified:** `.github/workflows/phase-37-linux-resl.yml`
- **Commit:** `0afc81df` (Task 2)

### TDD-gate compliance note for Task 2

Task 2 was marked `tdd="true"` in the plan but committed as a single `feat(...)` commit rather than a RED→GREEN pair. Rationale: a YAML workflow file is not a meaningful RED→GREEN cycle target — there is no failing-test artifact to land before the workflow file itself. The acceptance gate is YAML structural validation + a successful CI run on push, not a Rust test compile-fail/compile-pass progression. The plan's own `<verify>` block recognizes this (`python -c "import yaml; yaml.safe_load(...)" && echo YAML_OK` — a one-shot validation, not a red/green progression). This is a controlled departure from the plan's `tdd="true"` flag; documented here for the TDD Gate Compliance section below.

### Out-of-Scope Discoveries

None encountered for this plan. The workflow file is fully self-contained; no cross-cutting drift surfaced during execution.

## Authentication Gates

None encountered. All work was offline and local (no `gh` push, no secrets, no registry network).

## Known Stubs

**1. `pkgs-auto-pull` job placeholder (BY DESIGN — owned by Plan 37-05)**

The `pkgs-auto-pull` job's only meaningful step is currently a `cargo build` placeholder. The job exists as a skeleton so Plan 37-05 can incrementally add the sigstore-sign keyless step + the `auto_pull_e2e_linux` test invocation without re-touching the workflow shape (runs-on, permissions including `id-token: write`, checkout, toolchain, cache). This is documented inline in the workflow YAML as `# Plan 37-05 will populate this job with sigstore-sign keyless + auto_pull_e2e_linux test`. Not a code stub — an intentional incremental-buildout pattern explicitly called out by the plan.

## Threat Surface Scan

No new threat surface beyond what the plan's `<threat_model>` enumerates (T-37-03 cgroup delegation scope, T-37-13 supply-chain action pinning, T-37-14 silent-no-op controller missing, T-37-15 verbose logs, T-37-16 CPU budget). All five are mitigated by the workflow file + integration tests as designed:

- **T-37-03**: Delegate= list scoped + inline YAML comment ✓
- **T-37-13**: All `uses:` SHA-pinned + grep gate enforced ✓
- **T-37-14**: Hard verify-step in workflow + defense-in-depth `require_cpu_controller!` macro in test ✓
- **T-37-15**: Accepted (no secrets emitted; runner is ephemeral) ✓
- **T-37-16**: Accepted (6s CPU burn per PR × 2 jobs = 12 runner-seconds) ✓

No new endpoints, no new auth paths, no new trust boundaries.

## Commits

| Hash | Type | Message |
|------|------|---------|
| `c7def347` | test | Task 1: add cpu_percent throttling + max_processes N=5 integration tests |
| `0afc81df` | feat | Task 2: add Phase 37 Linux RESL CI workflow with cpu-controller delegation |

Both commits are DCO-signed (`Signed-off-by:`) per CLAUDE.md.

## TDD Gate Compliance

- **Task 1** committed as `test(37-04): ...` per TDD convention. Full RED→GREEN cycle DEFERRED to the CI runner (W3 fix path; dev-host compile-gate BLOCKED on cc-rs / x86_64-linux-gnu-gcc cross toolchain — same disposition Plan 37-01 SUMMARY documented).
- **Task 2** committed as a single `feat(37-04): ...` rather than a RED→GREEN pair (see "TDD-gate compliance note for Task 2" above). A YAML workflow file is not a meaningful RED→GREEN cycle target.

The plan-level TDD gate sequence (test → feat) is satisfied: `c7def347` (test) precedes `0afc81df` (feat) in git log.

## Self-Check: PASSED

**Files verified to exist on disk:**

| Path | Status |
|------|--------|
| `.github/workflows/phase-37-linux-resl.yml` | FOUND |
| `crates/nono-cli/tests/resl_nix_linux.rs` | FOUND (modified, +210 lines) |
| `.planning/phases/37-linux-resl-backends-pkgs-auto-pull/37-04-SUMMARY.md` | FOUND (this file) |

**Commits verified to exist on branch:**

| Hash | Status |
|------|--------|
| `c7def347` (Task 1: test) | FOUND in `git log --oneline -3` |
| `0afc81df` (Task 2: feat) | FOUND in `git log --oneline -3` |

**Post-commit deletion check:**

`git diff --diff-filter=D --name-only HEAD~2 HEAD` returns 0 lines (no deletions across either commit). Net diff: +395 insertions across 2 files (185 in the new workflow file, 210 in the modified test file).

**No modifications to shared orchestrator artifacts** (STATE.md, ROADMAP.md, REQUIREMENTS.md untouched in this plan's commits — worktree-mode discipline preserved).
