---
phase: 46-windows-squash-merge-post-merge-ci-verifications-uat-backlog
reviewed: 2026-05-23T00:00:00Z
depth: standard
files_reviewed: 2
files_reviewed_list:
  - .github/workflows/phase-46-uat-backlog.yml
  - crates/nono-cli/src/exec_strategy/supervisor_macos.rs
findings:
  critical: 0
  warning: 3
  info: 5
  total: 8
status: issues_found
---

# Phase 46: Code Review Report

**Reviewed:** 2026-05-23
**Depth:** standard
**Files Reviewed:** 2
**Status:** issues_found

## Summary

Phase 46 was scoped as a doc/orchestrator phase but produced two source-code touches under plan 46-03: a new GitHub Actions workflow `phase-46-uat-backlog.yml` and a single-line `#[derive(Debug)]` addition to `MacosResourceLimits` in `supervisor_macos.rs`.

The `#[derive(Debug)]` addition is a minimal, correct fix for the macOS test compile failure described in commit `f6a6d97d`. No defects in that change.

The workflow file is the primary source of findings. The most significant concerns are:

1. **Dropped `RUSTFLAGS: -Dwarnings` parity (BLOCKER-adjacent quality regression):** Every other native-platform workflow in the repo (`ci.yml`, `phase-37-linux-resl.yml`, `phase-45-resl-native-host.yml`) sets `RUSTFLAGS: -Dwarnings`. Phase 46 silently drops it. Combined with the `#[derive(Debug)]` addition being motivated by a build failure, this raises the legitimate question of whether the workflow is silently swallowing warnings that would otherwise be fatal on the supposedly-stricter sibling workflows. The risk is that future drift (unused imports, dead code, missing `Debug` derives, deprecated API usage) lands on main unseen because this workflow won't catch it, and the next operator who tries to run the same tests under `-Dwarnings` (e.g., locally or via the broader CI lane) is the one who pays the cost. **Classified as WARNING** because Phase 46 itself is workflow_dispatch-only and `continue-on-error: true` at the job level — but the precedent matters.

2. **Double-layered `continue-on-error` masks failures from `gh run watch`:** Both jobs carry `continue-on-error: true` at the job level (lines 47, 124) AND step-level `continue-on-error: true` (lines 83, 90, 96, 104, 110, 116, 153, 158, 165, 170, 175). With job-level CoE, the whole workflow returns "success" to `gh run watch` even when every test step in both jobs fails. Operators looking at `gh run list` will see green and skip log inspection. The header comment at line 17 explicitly acknowledges and endorses this — and the design intent (per-item waiver in `46-03-SUMMARY.md`) is documented. **Classified as WARNING** because the operational gap exists even with that documentation: an orchestrator that wires "wait for green tick" expecting a true verdict gets misled.

3. **Two redundant cfg gates inside the macOS-only module:** `supervisor_macos.rs` is itself included via `#[cfg(target_os = "macos")] mod supervisor_macos;` in `exec_strategy.rs:16-17`. The `#[cfg(target_os = "macos")]` block on lines 116-135 (inside `install_pre_exec`), the corresponding `#[cfg(not(target_os = "macos"))]` else branch on lines 136-139, and the `#[cfg(target_os = "macos")]` on `spawn_macos_timeout_watchdog` (line 170) are all redundant inside a module that only compiles on macOS. **Classified as INFO** — pre-existing in this file (not introduced by phase 46) and harmless, but worth surfacing for cleanup.

Five additional INFO items document minor inconsistencies in test invocation flags and one missed parity concern.

## Warnings

### WR-01: `RUSTFLAGS: -Dwarnings` dropped relative to sibling workflows

**File:** `.github/workflows/phase-46-uat-backlog.yml:35-36`
**Issue:** This is the only workflow in the repo's `.github/workflows/` directory that runs cargo build/test on Linux + macOS and does NOT set `RUSTFLAGS: -Dwarnings`. Confirmed via grep:
- `ci.yml:14` — sets `-Dwarnings`
- `phase-45-resl-native-host.yml:35` — sets `-Dwarnings`
- `phase-37-linux-resl.yml:23` — sets `-Dwarnings`
- `phase-46-uat-backlog.yml` — does NOT set `-Dwarnings`

The phase-45 workflow is explicitly cited as the layout this workflow mirrors (line 6: "Mirrors `.github/workflows/phase-45-resl-native-host.yml` layout"), but only the structure is mirrored — the strictness flag was dropped. Per the scope rationale, this drop appears to have been a reaction to a build failure that was independently fixed by adding `#[derive(Debug)]` to `MacosResourceLimits`. With the Debug derive landed, the original justification for dropping `-Dwarnings` is gone.

The functional impact is that this workflow can silently accept warnings (unused imports, dead code, deprecated API usage, missing Debug derives on other test-formatted types) that would be caught on the standard CI lane. Drift detected here, but masked.

**Fix:**
```yaml
env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: -Dwarnings
```

If a specific warning class is too noisy for a UAT re-execution workflow, allow only that class (e.g., `RUSTFLAGS: -Dwarnings -A dead_code`) rather than dropping the floor entirely. Document the rationale in the workflow header.

### WR-02: Double-layered `continue-on-error` causes `gh run watch` to report success even on total failure

**File:** `.github/workflows/phase-46-uat-backlog.yml:47, 124` (job-level CoE) and lines 83/90/96/104/110/116/153/158/165/170/175 (step-level CoE)
**Issue:** Both per-OS jobs carry `continue-on-error: true` at the JOB level. This is distinct from the step-level CoE flags. Job-level CoE means the job's outcome does not contribute to the workflow's overall status, so the workflow run is reported "success" to the orchestrator even if every test step on both runners fails.

The header comment (lines 17-19) describes the step-level CoE intent ("items that fail because the test fixture is intrinsically unavailable get a `no-test-fixture` waiver"), but does not justify the job-level CoE. Step-level CoE alone would satisfy the documented intent — letting subsequent steps run despite earlier step failure — without hiding the overall verdict.

The risk: per `46-03-SUMMARY.md`, this workflow is the *evidence vehicle* for closing REQ-UAT-BL-01/02. An operator who runs `gh workflow run` + `gh run watch` and trusts the exit code to mean "all tests passed or were waived" will be misled. They must instead open each step's log individually.

**Fix:** Drop the job-level `continue-on-error: true` (lines 47 and 124). Keep step-level CoE on the individual test steps so subsequent steps in the same job still run. The job summary will then accurately reflect whether any step failed, while waiver-eligible failures are still captured per-step.

```yaml
jobs:
  uat-backlog-linux:
    if: ${{ inputs.gh_runner_os == 'ubuntu-24.04' || inputs.gh_runner_os == 'both' }}
    name: Phase 46 UAT backlog (Linux)
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    # continue-on-error: true   <-- REMOVE this line

    steps:
      - name: Checkout
      ...
      - name: Run Phase 35 UAT — ...
        continue-on-error: true   # <-- KEEP step-level CoE
        run: cargo test -p nono-cli -- ...
```

If the deliberate intent was that the workflow must NEVER fail (e.g., to avoid red x'es on the Actions tab during the v2.6 close), document that explicitly in the header so the next maintainer understands the trade-off.

### WR-03: macOS job omits `Install system dependencies` step; relies on macos-latest preinstalled toolchain implicitly

**File:** `.github/workflows/phase-46-uat-backlog.yml:127-147` (macOS job, between Checkout and Build workspace)
**Issue:** The Linux job has a dedicated `Install system dependencies (libdbus-1-dev required by keyring crate)` step (lines 69-72). The macOS job has no equivalent step. Compared to `Cargo.toml` (the `keyring` dep feature-gates `apple-native` for macOS, which uses `Security.framework` — preinstalled), the omission is technically correct for the keyring path.

However, the macOS runner does NOT install `pkg-config` (which IS installed on Linux). Several crates in the dependency tree (`openssl-sys`, `libgit2-sys`, etc., depending on cargo feature resolution) probe `pkg-config` during build. macos-latest images currently ship pkg-config preinstalled via Homebrew bottles, but this is an undocumented dependency on runner-image internals. If a future macos-latest image (or a future cargo dep resolution) drops pkg-config from PATH, this workflow will fail with an opaque link error. The Linux job protects against this by explicit install; the macOS job does not.

**Fix:** Either add an explicit `Install build prerequisites` step on macOS to mirror the Linux job's defensive posture:

```yaml
      - name: Install build prerequisites (pkg-config for keyring/openssl chains)
        run: brew install pkg-config || true
```

Or add a header comment to the macOS job explicitly documenting "macos-latest preinstalled toolchain provides pkg-config + apple-native keyring backend; no extra deps needed", so the next maintainer doesn't add one unnecessarily.

## Info

### IN-01: Redundant `#[cfg(target_os = "macos")]` gates inside macOS-only module

**File:** `crates/nono-cli/src/exec_strategy/supervisor_macos.rs:116, 136, 170`
**Issue:** The whole module is included via `#[cfg(target_os = "macos")] mod supervisor_macos;` in `exec_strategy.rs:16-17`. Therefore:
- Line 116 `#[cfg(target_os = "macos")]` (inside `install_pre_exec`'s pre_exec closure) — always true, redundant
- Lines 136-139 `#[cfg(not(target_os = "macos"))]` else branch — always false, dead code
- Line 170 `#[cfg(target_os = "macos")]` on `spawn_macos_timeout_watchdog` — always true, redundant
- Line 189 `#[cfg(all(test, target_os = "macos"))]` on tests mod — the `target_os = "macos"` half is redundant

Pre-existing in the file (not introduced by Phase 46), but the file is now in scope for review.

**Fix:** Strip the redundant cfg gates. The `let _ = (memory_bytes, max_processes);` dead branch on lines 136-139 can be removed entirely:

```rust
        unsafe {
            cmd.pre_exec(move || -> std::io::Result<()> {
                use nix::sys::resource::{setrlimit, Resource};
                if let Some(bytes) = memory_bytes {
                    let limit = bytes.try_into().unwrap_or(nix::libc::rlim_t::MAX);
                    setrlimit(Resource::RLIMIT_AS, limit, limit)
                        .map_err(std::io::Error::from)?;
                }
                if let Some(_n) = max_processes {
                    tracing::warn!(
                        "--max-processes is not enforced on macOS \
                         (RLIMIT_NPROC unavailable in nix v0.31's macOS subset)"
                    );
                }
                Ok(())
            });
        }
```

### IN-02: `--include-ignored` is extraneous on a non-`#[ignore]`d test

**File:** `.github/workflows/phase-46-uat-backlog.yml:84`
**Issue:** Step "Run Phase 35 UAT — Linux Landlock profiles-dir idempotency" invokes:
```
cargo test -p nono-cli -- test_pre_create_landlock_profiles_dir_idempotent --include-ignored
```
The target test (`profile_runtime.rs:364`) is NOT decorated with `#[ignore]`. `--include-ignored` is therefore a no-op here. Harmless, but suggests the workflow was copy-pasted from a different test invocation pattern and not pruned. Removes noise / mild confusion for the next maintainer wondering "why is this one ignored?"

**Fix:** Drop the `--include-ignored` flag:
```yaml
        run: cargo test -p nono-cli -- test_pre_create_landlock_profiles_dir_idempotent
```

### IN-03: Cache key omits OS-suffix nuance present in phase-45

**File:** `.github/workflows/phase-46-uat-backlog.yml:65, 142`
**Issue:** Both jobs use cache key prefix `${{ runner.os }}-phase46-uat-backlog-`. Since both jobs (`uat-backlog-linux` and `uat-backlog-macos`) hash the same `Cargo.lock` and use the same prefix mod `runner.os`, they will share a cache namespace BUT segregated by `runner.os` (Linux vs macOS). That's correct.

However, neither job differentiates cache by `--release` build mode. If a future CI lane on the same runner (`runner.os = Linux`) caches a debug-built target/ dir under the same prefix, the release build here will pull a debug cache and rebuild. Not a correctness bug — just slightly worse cache locality.

**Fix:** Append a build-mode discriminator to the cache key prefix:
```yaml
          key: ${{ runner.os }}-phase46-uat-backlog-release-${{ hashFiles('**/Cargo.lock') }}
          restore-keys: |
            ${{ runner.os }}-phase46-uat-backlog-release-
```

### IN-04: `cargo build --workspace --release --verbose` produces noisy CI logs without observable benefit

**File:** `.github/workflows/phase-46-uat-backlog.yml:75, 147`
**Issue:** The `--verbose` flag on `cargo build` produces several MB of full rustc command lines per crate. This is useful for debugging linker-flag issues on a misconfigured runner, but otherwise creates log scroll-spam that obscures the test output the workflow is actually trying to surface.

Phase 45's sibling workflow uses the same pattern (`cargo build --workspace --release --verbose`), so this is consistent with precedent. Calling out as INFO because it slows log review for an evidence-gathering workflow.

**Fix:** Either drop `--verbose` from both Phase 46 jobs (and consider doing the same in Phase 45 for consistency), or leave as-is for consistency with precedent. No action required if precedent is the stronger constraint.

### IN-05: Header `gh_runner_os=both` example invocation does not match the choice input's positional semantics

**File:** `.github/workflows/phase-46-uat-backlog.yml:14`
**Issue:** The header comment says:
```
#   gh workflow run phase-46-uat-backlog.yml -f gh_runner_os=both
```
This is correct (`-f` passes input by name). But the workflow's `inputs.gh_runner_os.default: both` already runs both OSs without any `-f` flag, so the example invocation is functionally identical to just `gh workflow run phase-46-uat-backlog.yml`. Minor: the example could instead demonstrate the non-default cases (`-f gh_runner_os=ubuntu-24.04` or `-f gh_runner_os=macos-latest`) that the operator actually needs to know about.

**Fix:**
```
# Invocation (Phase 46 orchestrator action):
#   gh workflow run phase-46-uat-backlog.yml                              # both (default)
#   gh workflow run phase-46-uat-backlog.yml -f gh_runner_os=ubuntu-24.04  # Linux only
#   gh workflow run phase-46-uat-backlog.yml -f gh_runner_os=macos-latest  # macOS only
#   gh run watch
```

---

_Reviewed: 2026-05-23_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
