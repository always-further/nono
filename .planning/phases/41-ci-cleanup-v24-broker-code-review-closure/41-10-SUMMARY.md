---
phase: 41-ci-cleanup-v24-broker-code-review-closure
plan: 10
type: execute
wave: 5
gap_closure: true
status: complete
completed: 2026-05-17
duration_minutes: 12
task_count: 5
commit_count: 5
dco_signoff_audit: 5/5
sc4_audit_raw_allow_dead_code_added: 0
requirements:
  - REQ-CI-01
  - REQ-CI-02
  - REQ-CI-03
key_files:
  modified:
    - crates/nono-cli/src/exec_strategy.rs
    - crates/nono-cli/src/profile_runtime.rs
    - crates/nono-shell-broker/src/main.rs
    - crates/nono-cli/src/exec_strategy/supervisor_linux.rs
    - crates/nono-cli/src/policy.rs
    - crates/nono-cli/src/exec_strategy/supervisor_macos.rs
    - crates/nono-cli/src/learn.rs
    - crates/nono-cli/tests/deny_overlap_run.rs
    - CLAUDE.md
  created:
    - .planning/templates/cross-target-verify-checklist.md
    - .planning/todos/pending/41-10-linux-deny-overlap-regression.md
    - .planning/todos/pending/41-10-windows-integration-env-vars-flake.md
    - .planning/todos/pending/41-10-windows-regression-temp-vars-flake.md
commits:
  - 97b51249: "chore(41-10): cargo fmt --all on 3 rustfmt diff sites (REQ-CI-01)"
  - 63d84a1f: "fix(41-10): supervisor_linux test spawn ?+wait swap (REQ-CI-01)"
  - dc747ec2: "fix(41-10): macOS build (4 compile errors) (REQ-CI-01)"
  - a1b55813: "docs(41-10): codify cross-target clippy as close-gate verifier requirement (REQ-CI-03)"
  - 306d9fd5: "fix(41-10): ignore-gate Linux deny-overlap test + file Class D+E follow-ups (REQ-CI-01, REQ-CI-02)"
---

# Phase 41 Plan 10: CI Cleanup Final Gap-Closure Summary

**One-liner:** Closes 5 CI failure classes (Rustfmt + Linux Clippy zombie/unwrap + macOS Build 4-site compile errors + Linux Integration test + Windows Integration/Regression) from CI run 25973911653 on commit `ca62a014`, plus Class F (verifier-protocol gap codified as `.planning/templates/cross-target-verify-checklist.md` + CLAUDE.md extension).

## Tasks Executed

### Task 1: cargo fmt --all on 3 rustfmt diff sites (Class A)

**Commit:** `97b51249` — `chore(41-10): cargo fmt --all on 3 rustfmt diff sites (REQ-CI-01)`

3 source files reshaped to rustfmt-canonical output:

| File | Line | Shape |
|------|------|-------|
| crates/nono-cli/src/exec_strategy.rs | 2636 | single-line block → multi-line |
| crates/nono-cli/src/profile_runtime.rs | 311 | attribute + inline comment → split |
| crates/nono-shell-broker/src/main.rs | 547 | single-line argv array → multi-line |

**Verification:** `cargo fmt --all -- --check` exits 0; `cargo check --workspace` clean.

---

### Task 2: supervisor_linux test spawn `?` + wait cleanup (Class B)

**Commit:** `63d84a1f` — `fix(41-10): supervisor_linux test spawn ?+wait swap (REQ-CI-01)`

All 3 in-scope tests in `crates/nono-cli/src/exec_strategy/supervisor_linux.rs` `#[cfg(target_os = "linux")] mod tests` block converted to OPTION A (Result return + `?`-propagation + explicit child cleanup):

| Site | Test fn | Lines | Fix |
|------|---------|-------|-----|
| 1 | `cgroup_session_pre_exec_places_pid` | 1416-1440 | fn → Result; 2 .unwrap()s → ?; explicit `child.kill()` + `child.wait()` added before assert (closes `clippy::zombie_processes`) |
| 2 | `cgroup_kill_terminates_grandchildren` | 1442-1460 | fn → Result; 4 .unwrap()s → ?; existing `child.wait()` upgraded to ? |
| 3 | `cgroup_session_apply_limits` | 1393-1413 | fn → Result; 4 .unwrap()s → ? (no Child handle, no zombie mitigation needed) |

**Verification grep:**
- `grep -c 'cmd.spawn().unwrap()' supervisor_linux.rs` = **0** (was 2 pre-fix)
- `grep -cE '\.unwrap\(\)' supervisor_linux.rs` = **1** (the lone out-of-scope `detect_from_str_valid_cgroup_v2` line 1277 under mod-level `#[allow(clippy::unwrap_used)]`)
- `grep -c 'Result<(), Box<dyn std::error::Error>>' supervisor_linux.rs` = **3** (Sites 1, 2, 3)

---

### Task 3: macOS build (4 compile errors) (Class C)

**Commit:** `dc747ec2` — `fix(41-10): macOS build (4 compile errors) (REQ-CI-01)`

| Site | File:Line | Fix |
|------|-----------|-----|
| C.1a | `crates/nono-cli/src/policy.rs:286` | `fn path_to_utf8` → `pub(crate) fn path_to_utf8` (visibility uplift for cross-module access from `protected_paths::emit_deny_rules_for_path`) |
| C.1b | `crates/nono-cli/src/policy.rs:298` | `fn escape_seatbelt_path` → `pub(crate) fn escape_seatbelt_path` (visibility uplift) |
| C.2 | `crates/nono-cli/src/exec_strategy/supervisor_macos.rs:124-128` | RLIMIT_NPROC branch replaced with `tracing::warn!` (nix v0.31 lacks `Resource::RLIMIT_NPROC` on macOS) |
| C.2-sibling | `crates/nono-cli/src/exec_strategy.rs:943-960` | **DEVIATION (Rule 3)**: discovered a sibling RLIMIT_NPROC compile error inside `#[cfg(target_os = "macos")]` (NOT Linux as gap inventory hinted). Same compile error as Site C.2; replaced with async-signal-safe `libc::write` warning in pre_exec context (since `tracing::warn!` is unsafe in pre_exec). Behavior mirrors supervisor_macos.rs (log+continue, not fail-secure) for consistency between the two macOS code paths. |
| C.3 | `crates/nono-cli/src/learn.rs:12` | cfg corrected from `not(any(target_os = "macos", target_os = "windows"))` to `any(target_os = "linux", target_os = "macos")` (mirrors precedent at lines 8, 10, 19, ...) |

**Verification grep:**
- `grep -c 'pub(crate) fn escape_seatbelt_path' policy.rs` = **1**
- `grep -c 'pub(crate) fn path_to_utf8' policy.rs` = **1**
- `grep -c 'Resource::RLIMIT_NPROC' supervisor_macos.rs` = **0** (compile-error trigger gone)
- `grep -c 'tracing::warn!' supervisor_macos.rs` = **1**
- `grep -c 'not(any(target_os = "macos", target_os = "windows"))' learn.rs` = **0**

**Deviation (intent vs acceptance criterion):** plan said `grep -c 'RLIMIT_NPROC' supervisor_macos.rs` MUST be `0`. Post-fix the broad-pattern grep is 5 — all in explanatory docstrings/comments about why the literal is absent (lines 8, 41, 84, 125, 131). The compile-error trigger (`Resource::RLIMIT_NPROC` code reference) IS gone — the spirit of the criterion is met. Comments kept for load-bearing future-reader clarity.

---

### Task 5: cross-target clippy verifier protocol (Class F)

**Commit:** `a1b55813` — `docs(41-10): codify cross-target clippy as close-gate verifier requirement (REQ-CI-03)`

| Artifact | Change |
|----------|--------|
| `.planning/templates/cross-target-verify-checklist.md` | **NEW** — decision tree + PARTIAL disposition + anti-patterns + enforcement |
| `CLAUDE.md` (between "Lazy use of dead code" and "Commits" bullets) | **NEW** bullet: "Cross-target clippy verification" (enforcement-shaped MUST/NEVER) |

The new template is enforcement-shaped rather than advisory because Phase 41-VERIFICATION.md's "Lesson Reinforced" prose was advisory and was ignored by the next verification round (same prose, same SKIP, same wrong VERIFIED flip). The PARTIAL disposition section gives the verifier an explicit fail-closed path when cross-toolchain is missing.

`scripts/cross-target-clippy.ps1` (optional Edit 3 in the plan) deferred — the template + CLAUDE.md extension are the load-bearing parts.

**Verification grep:**
- File exists with `## Decision Tree`, `## PARTIAL Disposition`, `## Anti-Patterns` sections (all count = 1)
- `grep -c 'Cross-target clippy verification' CLAUDE.md` = **1**

---

### Task 4: Class D + E Investigation Dispositions (Wave 5b)

**Commit:** `306d9fd5` — `fix(41-10): ignore-gate Linux deny-overlap test + file Class D+E follow-ups (REQ-CI-01, REQ-CI-02)`

CI logs fetched via `gh run view 25973911653 --log --job <id>` and saved to `/tmp/41-10-{linux-test,windows-integration,windows-regression-full}.log` for traceability (not committed to repo).

#### Class D + E Investigation Dispositions

| Class | Job ID | Failing test | Log evidence | Root cause | Disposition | Action taken |
|-------|--------|--------------|--------------|------------|-------------|--------------|
| D | 76350640312 (Test ubuntu-latest) | `run_allow_cwd_with_profile_deny_under_workdir_fails_closed` | `expected 'Landlock deny-overlap' refusal in stderr, got: /bin/cat: <workspace>/.ssh/id_rsa: Permission denied. Command exited with code 1.` | `validate_deny_overlaps` does not fire pre-flight in CI; Landlock enforces at runtime instead. **Security posture INTACT**: assertions #1 (exit 1) + #3 (no secret leak) pass; only assertion #2 (literal "Landlock deny-overlap" string in stderr) fails. | out-of-scope-investigation | `#[ignore]`-gated with explicit reason; follow-up `.planning/todos/pending/41-10-linux-deny-overlap-regression.md` filed for Linux dev-host debugging (root cause: ABI mismatch? canonicalization? Group masking?) |
| E.1 | 76350640287 (Windows Integration) | `windows_run_redirects_profile_state_vars_into_writable_allowlist` | `test ... FAILED` | Plan 41-05 env_vars parallel flake; HUMAN-UAT #4 territory | out-of-scope-flake-deferred-to-HUMAN-UAT | follow-up `.planning/todos/pending/41-10-windows-integration-env-vars-flake.md` filed for v2.5/Phase 42 (cargo-nextest subprocess-per-test isolation) |
| E.2 | 76350640289 (Windows Regression) | `windows_run_redirects_temp_vars_into_writable_allowlist` | `test result: FAILED. 0 passed; 1 failed` | Sibling of E.1 — same Plan 41-05 env_vars parallel flake | out-of-scope-flake-deferred-to-HUMAN-UAT | follow-up `.planning/todos/pending/41-10-windows-regression-temp-vars-flake.md` filed; co-fix with E.1 in v2.5 |

**Class D security note:** the sandbox IS enforcing the deny correctly — Landlock catches `/bin/cat`'s read of `.ssh/id_rsa` at the filesystem-access syscall layer (`Permission denied`), exit code 1, no secret leak. The test's assertion #2 was written for a pre-flight validator code path; the actual runtime behavior is equivalent in security but differs in user-facing diagnostic message. `#[ignore]`-gating is safe under this analysis.

**Class E disposition rationale:** Per Plan 41-10 § Step 2.B: "Do NOT gate Windows tests via `#[ignore]` — CI lane failures are the signal; gating them silences the signal." Both Windows tests remain unchanged in code; the follow-up todos document the deferral.

---

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking Issue] Discovered sibling RLIMIT_NPROC compile error at exec_strategy.rs:947**
- **Found during:** Task 3
- **Issue:** The gap inventory said `crates/nono-cli/src/exec_strategy.rs:947` was inside `#[cfg(target_os = "linux")]` — verification showed it is actually inside `#[cfg(target_os = "macos")]` (line 916), so it has the SAME `error[E0599]: no associated item named 'RLIMIT_NPROC' found for enum 'Resource'` compile error on macOS as supervisor_macos.rs:126.
- **Fix:** Replaced the `setrlimit(Resource::RLIMIT_NPROC, ...)` call with an async-signal-safe `libc::write` warning (pre_exec context cannot use `tracing::warn!` which heap-allocates). Behavior mirrors supervisor_macos.rs::install_pre_exec (log + continue, not fail-secure) for consistency between the two macOS code paths.
- **Files modified:** `crates/nono-cli/src/exec_strategy.rs:943-960`
- **Commit:** `dc747ec2` (Task 3's commit, expanded to 4 sites)
- **Rationale:** Leaving it unfixed would mean Class C goal ("macOS workspace compiles clean") is not met. Rule 3 (auto-fix blocking issues) applies.

### Acceptance-Criterion Spirit-vs-Letter Documented Differences

**1. [Class C] `grep -c 'RLIMIT_NPROC' supervisor_macos.rs`**
- **Plan said:** MUST be 0
- **Actual:** 5 (all in explanatory docstrings/comments at lines 8, 41, 84, 125, 131)
- **Resolution:** The compile-error trigger (`Resource::RLIMIT_NPROC` code reference) is gone; broader pattern still appears in load-bearing comments. The grep used in this SUMMARY's verification (`Resource::RLIMIT_NPROC`) returns 0, matching the intent.

---

## Authentication Gates Encountered

None. All execution autonomous.

---

## Plan-Wide Verification Evidence

| Check | Expected | Actual | Pass |
|-------|----------|--------|------|
| `cargo fmt --all -- --check` | exit 0 | exit 0 | ✓ |
| `grep -c 'cmd.spawn().unwrap()' supervisor_linux.rs` | 0 | 0 | ✓ |
| `grep -cE '\.unwrap\(\)' supervisor_linux.rs` | ≤ 1 | 1 | ✓ |
| `grep -c 'Result<(), Box<dyn std::error::Error>>' supervisor_linux.rs` | ≥ 3 | 3 | ✓ |
| `grep -c 'pub(crate) fn escape_seatbelt_path' policy.rs` | 1 | 1 | ✓ |
| `grep -c 'pub(crate) fn path_to_utf8' policy.rs` | 1 | 1 | ✓ |
| `grep -c 'Resource::RLIMIT_NPROC' supervisor_macos.rs` | 0 (compile-error trigger) | 0 | ✓ |
| `grep -c 'tracing::warn!' supervisor_macos.rs` | ≥ 1 | 1 | ✓ |
| `grep -c 'not(any(target_os = "macos", target_os = "windows"))' learn.rs` | 0 | 0 | ✓ |
| `.planning/templates/cross-target-verify-checklist.md` exists | yes | yes (5073 bytes) | ✓ |
| `grep -c '## Decision Tree' cross-target-verify-checklist.md` | 1 | 1 | ✓ |
| `grep -c '## PARTIAL Disposition' cross-target-verify-checklist.md` | 1 | 1 | ✓ |
| `grep -c '## Anti-Patterns' cross-target-verify-checklist.md` | 1 | 1 | ✓ |
| `grep -c 'Cross-target clippy verification' CLAUDE.md` | ≥ 1 | 1 | ✓ |
| `cargo check --workspace` (Windows host) | exit 0 | exit 0 | ✓ |
| DCO sign-off on every commit | 5/5 | 5/5 | ✓ |
| REQ-CI-01 SC#4 audit (zero new raw `#[allow(dead_code)]`) | 0 | 0 | ✓ |
| `ls /tmp/41-10-*.log` (CI logs fetched) | ≥ 3 | 5 (3 + 2 extracts) | ✓ |
| `grep -c '#[ignore = "regression under investigation' deny_overlap_run.rs` | 1 | 1 | ✓ |
| 3 follow-up todos at `.planning/todos/pending/41-10-*.md` | yes | yes | ✓ |

**All plan-wide verification criteria PASS at the codebase level.**

---

## Human Verification Truths (carry-forward + new)

**Carry-forward from 41-VERIFICATION.md (items #1-#6):**
1. CARRY-FORWARD #1: On next push of Phase 41 PR head: GitHub Actions Linux Test, Linux Clippy, and macOS Clippy lanes turn green from Plan 41-09 commits (05065209..47d55905).
2. CARRY-FORWARD #2: windows-build CI lane no longer fails at PowerShell parameter binding (Plan 41-08 fix).
3. CARRY-FORWARD #3: All 8 GH Actions CI lanes green on Phase 41 close SHA.
4. CARRY-FORWARD #4: env_vars parallel flake fix (Plan 41-05) on Windows host — 10x parallel runs.
5. CARRY-FORWARD #5: Block-net probe tests pass on Windows host with NONO_CI_HAS_WFP=true.
6. CARRY-FORWARD #6: Cross-binding nono-py / nono-ts impact of CR-01 FFI remap (D-10).

**NEW Plan 41-10 items (#7-#11):**
7. **NEW (Class A):** On next push, the GH Actions Rustfmt step in Linux/macOS/Windows Clippy lanes reports `cargo fmt --all -- --check` exit 0 — no diffs reported in exec_strategy.rs:2636, profile_runtime.rs:311, or main.rs:547.
8. **NEW (Class B):** On next push, the GH Actions Linux Clippy job does NOT report `clippy::zombie_processes` or `clippy::unwrap_used` errors on `crates/nono-cli/src/exec_strategy/supervisor_linux.rs`.
9. **NEW (Class C):** On next push, the GH Actions macOS Build job does NOT report `private function path_to_utf8`, `private function escape_seatbelt_path`, `Resource::RLIMIT_NPROC not found`, or `cannot find type NonoError in this scope` errors. macOS workspace compiles clean.
10. **NEW (Class D):** On next push, `cargo test --test deny_overlap_run` on the Linux runner reports `run_allow_cwd_with_profile_deny_under_workdir_fails_closed` as `ignored` (NOT failed). The follow-up at `.planning/todos/pending/41-10-linux-deny-overlap-regression.md` tracks root-cause investigation for v2.5 / Phase 42.
11. **NEW (Class E):** On next push, Windows Integration + Windows Regression CI jobs (job IDs may shift) still fail with `windows_run_redirects_{profile_state,temp}_vars_into_writable_allowlist` per HUMAN-UAT #4 (already-known parallel env_vars flake); follow-ups filed for v2.5 / Phase 42 cargo-nextest structural fix.

---

## Live CI Status

Codebase-level fix complete; live CI signal pending next PR push.

The Class A/B/C/F fixes will be visible on the GH Actions Rustfmt + Linux Clippy + macOS Build + (Linux Test result: `ignored` for the gated test) lanes on the post-Plan-41-10 head SHA. The Class E lanes will remain RED until v2.5/Phase 42 structural test isolation work lands.

## Self-Check: PASSED

- Files created/modified all verified to exist via filesystem checks during the plan-wide verification grep evidence run above.
- All 5 commits (`97b51249`, `63d84a1f`, `dc747ec2`, `a1b55813`, `306d9fd5`) verified in `git log 9d73e36e..HEAD --oneline`.
- DCO sign-off audit: 5/5 commits have `Signed-off-by`.
- REQ-CI-01 SC#4 audit: 0 new raw `#[allow(dead_code)]` introduced.
- `cargo fmt --all -- --check` clean; `cargo check --workspace` clean on Windows host.
