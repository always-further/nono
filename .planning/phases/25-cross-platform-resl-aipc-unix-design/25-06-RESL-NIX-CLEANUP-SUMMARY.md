---
phase: 25-cross-platform-resl-aipc-unix-design
plan: 06
subsystem: resilience-cleanup-dead-code
tags: [timeout-watchdog, atomicbool-dead-store, cgroup-v2, drop-cleanup, dead-code-removal, claude-md-compliance, wr-c, wr-d]

# Dependency graph
requires:
  - phase: 25-cross-platform-resl-aipc-unix-design (plan 03)
    provides: "Original timeout watchdog implementations (spawn_linux_timeout_watchdog with cgroup.kill, spawn_macos_timeout_watchdog with kill(-pgrp, SIGKILL)) and the CgroupSession RAII wrapper with armed flag + disarm method"
  - phase: 25-cross-platform-resl-aipc-unix-design (plan 04)
    provides: "Code-review identifying WR-C (timeout_fired AtomicBool dead store across both watchdog paths) and WR-D (CgroupSession::disarm + armed field dead-code violating CLAUDE.md § Lazy use of dead code)"
  - phase: 25-cross-platform-resl-aipc-unix-design (plan 05)
    provides: "Sentinel comments around the post-fork child arm (// CR-01-CHILD-ARM-START / END) and clear_close_on_exec returning std::io::Result<()> — both untouched by this plan"
provides:
  - "spawn_linux_timeout_watchdog with two-parameter signature (deadline, cgroup_path) — timeout_fired Arc<AtomicBool> parameter removed end-to-end, no .store() call, doc comment now describes the cgroup v2 atomic-multi-process-kill primitive accurately"
  - "spawn_macos_timeout_watchdog with two-parameter signature (deadline, child_pgrp) — same surface removal as Linux variant; doc comment now describes the kill(-pgrp, SIGKILL) primitive without the false 'inspect data' claim"
  - "Simplified CgroupSession with no armed: bool field, no disarm() method, no #[allow(dead_code)] annotation; Drop unconditionally runs the cgroup-procs scan + remove_dir cleanup (preserving the only state ever actually constructed)"
affects: [phase-25-verification, future-resl-aipc-windows-inspect-data-plumbing (deferred per CONTEXT.md Q1)]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Pure deletion as the lower-blast-radius response to dead-store / dead-code warnings (path b in 25-VERIFICATION.md): when no consumer exists for a stored signal AND no in-scope plumbing requirement exists, delete the producer rather than wire a fictitious consumer"
    - "Single-state RAII Drop: when an 'armed' guard flag exists but is never disarmed in any code path, simplify Drop to unconditionally run the cleanup body — the conditional was always reducible to true"
    - "Doc-comment honesty: when a doc comment claims a downstream consumer that does not exist, deleting both the producer and the comment is the correct fix; updating only the comment leaves a misleading dead store"

key-files:
  created: []
  modified:
    - "crates/nono-cli/src/exec_strategy.rs"
    - "crates/nono-cli/src/exec_strategy/supervisor_linux.rs"
    - "crates/nono-cli/src/exec_strategy/supervisor_macos.rs"

key-decisions:
  - "Selected path (b) DELETE over path (a) wiring for WR-C, per 25-VERIFICATION.md guidance and 25-CONTEXT.md Q1 scope-out posture for inspect-data plumbing. Path (a) would have introduced new SessionRecord/SandboxState fields (memory_kill, timeout_kill) and supervisor footer reporting — explicitly out-of-scope for Phase 25."
  - "Deleted CgroupSession::armed and disarm together rather than just suppressing the warning — CLAUDE.md § 'Lazy use of dead code' rule explicitly forbids #[allow(dead_code)] as the response to unused code; the rule applies even when the surrounding doc comment claimed the field gated cleanup."
  - "Preserved the WR-04 'no PID fallback on getpgid failure' fix structure verbatim through Task 1's macOS spawn-site edit. Only the `, fired` argument was removed from the Ok arm; the Err arm warn! and 'no PID fallback' rationale comment block are byte-identical."

patterns-established:
  - "Threshold for 'just delete it': when grep -rn confirms zero consumers workspace-wide AND CONTEXT.md scopes the would-be consumer plumbing as deferred, deletion is correct — wiring would expand plan scope without delivering current-cycle value."
  - "Drop simplification when the gate flag is constant-true: if every constructor sets the flag to true and no method ever sets it to false, the flag and its early-return are dead by inspection — collapse to the always-on cleanup body, preserving behavior bit-for-bit."

requirements-completed: [REQ-RESL-NIX-02, REQ-RESL-NIX-03]

# Metrics
duration: ~7min
completed: 2026-05-10
---

# Phase 25 Plan 06: WR-C + WR-D Cleanup Summary

**Removed the timeout_fired AtomicBool dead store across both Linux and macOS supervisor watchdogs, deleted CgroupSession::disarm + armed field dead code (closing the CLAUDE.md § "Lazy use of dead code" violation), and preserved every behavior path bit-for-bit including the WR-04 no-PID-fallback rationale.**

## Performance

- **Duration:** ~7 min
- **Started:** 2026-05-10T21:49:13Z
- **Completed:** 2026-05-10T21:56:23Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- **WR-C closed (path b — DELETE).** `timeout_fired: Arc<AtomicBool>` removed end-to-end across the supervisor pipeline: declaration deleted at `exec_strategy.rs`, both `.clone()` capture sites at the post-fork spawn path deleted, both watchdog function signatures simplified from three parameters to two, both `.store(true, ...)` calls deleted, and the misleading "the parent's wait loop reads it for `timeout_kill: true` in inspect data" doc claims at exec_strategy.rs:108-109 and supervisor_macos.rs:152-153 removed. The `inspect_data` plumbing referenced in those doc comments does not exist and is explicitly out of scope per 25-CONTEXT.md Q1. Doc comments now accurately describe the actual primitives: cgroup v2 `cgroup.kill` atomic-multi-process kill (Linux) and `kill(-pgrp, SIGKILL)` process-group SIGKILL (macOS).
- **WR-D closed.** `CgroupSession::disarm` method deleted in full (including its `#[allow(dead_code)]` attribute and 4-line doc comment); `armed: bool` field deleted from struct + constructor; Drop's `if !self.armed { return; }` early-return + `self.armed = false;` write deleted. Drop now unconditionally runs the procs-scan + remove_dir cleanup — preserving the only state ever actually constructed (workspace-wide grep confirms `disarm` had zero callers). Doc comment in `new()` updated from "Stores the path, limits, and armed flag" to "Stores the path and limits". The CLAUDE.md § "Lazy use of dead code" violation is closed without bypassing the rule.
- **WR-04 fix preserved verbatim.** The `match getpgid(...)` arm at exec_strategy.rs:1358 retains the entire "no PID fallback to avoid wrong-pgrp kill under PID reuse" rationale block byte-identical; only the `, fired` argument was removed from the Ok arm. `grep -c "match getpgid(" exec_strategy.rs` returns exactly 1.
- **D-19/D-21 byte-identical Windows preservation invariant satisfied.** No files under `crates/nono-cli/src/exec_strategy_windows/` or `crates/nono/src/sandbox/windows.rs` were touched across either commit (`git diff --stat HEAD~2 HEAD -- ...` is empty).
- **Net code reduction:** -27 lines across 3 files (Task 1: 9 ins / 22 del across 2 files; Task 2: 1 ins / 15 del in 1 file). Zero new abstractions, zero new dependencies, zero new `#[allow(...)]` annotations.

## Task Commits

Each task was committed atomically with a DCO sign-off:

1. **Task 1: Remove timeout_fired AtomicBool — declaration, both clone captures, both watchdog signatures, both store calls, both doc comments (WR-C)** — `134de02a` (fix)
2. **Task 2: Delete CgroupSession::disarm method, armed field, and Drop's armed early-return (WR-D)** — `28ce03e8` (fix)

**Plan metadata:** committed separately by orchestrator after this SUMMARY.md is written.

## Files Created/Modified

- `crates/nono-cli/src/exec_strategy.rs` — Task 1: removed `timeout_fired` Arc declaration (line 832-833), both `.clone()` capture sites at the post-fork Linux/macOS spawn paths, the `, fired` argument from both watchdog calls; replaced `spawn_linux_timeout_watchdog` doc comment to describe `cgroup.kill` accurately and removed the third parameter; collapsed the macOS Ok arm from a 4-line block-with-let to an inline `Some(spawn_macos_timeout_watchdog(deadline, child_pgrp))` expression. (-13 net lines.)
- `crates/nono-cli/src/exec_strategy/supervisor_macos.rs` — Task 1: removed step 3 of the Watchdog-behaviour doc list, removed the `timeout_fired` parameter from `spawn_macos_timeout_watchdog`, removed the `// Set the flag BEFORE sending SIGKILL ...` comment and the `.store(true, ...)` line. Doc step 2 expanded slightly to reference `kill(-pgrp, SIGKILL)` explicitly so the function summary is self-contained. (-7 net lines.)
- `crates/nono-cli/src/exec_strategy/supervisor_linux.rs` — Task 2: deleted `armed: bool` struct field + its doc comment, the `armed: true,` constructor initializer, the entire `disarm` method (6 lines including doc + `#[allow(dead_code)]`), and the `if !self.armed { return; }` + `self.armed = false;` lines from Drop. Updated `new()` doc step 4 from "Stores the path, limits, and armed flag for later use" to "Stores the path and limits for later use". (-14 net lines.)

## Decisions Made

- **Path (b) DELETE selected over path (a) WIRING for WR-C.** 25-VERIFICATION.md flagged both options. Path (a) — wiring `timeout_fired` into supervisor footer reporting — would have required adding `memory_kill` / `timeout_kill` fields to SessionRecord / SandboxState and threading them through the inspect-data path. 25-CONTEXT.md Q1 explicitly scopes that plumbing as "optional follow-up, NOT part of Phase 25 deliverables", with the additional constraint "If the field plumbing meaningfully expands plan scope (>2 file additions), surface as a deviation during execution rather than expanding upfront." Path (b) deletion has zero file-additions impact and matches the scope-lock posture exactly. Recorded as the lead must_have in the plan frontmatter and adopted as-written.
- **Two surfaces removed per task, not bundled across tasks.** The plan defined Task 1 (WR-C, two files) and Task 2 (WR-D, one file). Even though all three files are co-located and could have been bundled into a single commit, the plan's task split was preserved to keep each WR closure independently revertable. This also matches the `atomic commits per task` rule from the orchestrator prompt.
- **No use of `#[allow(...)]` substitution.** WR-D could in principle be closed by leaving `disarm` in place and either suppressing the warning differently or adding a test that exercises it. CLAUDE.md § "Lazy use of dead code" forbids `#[allow(dead_code)]` and says "either remove it or write tests that use it". Since `disarm` had no behavior to test (it was a one-line setter on a flag with no consumers), removal is the only correct choice.

## Deviations from Plan

None — plan executed exactly as written.

The plan included a sub-step under EDIT 6 in Task 1's `<action>` block warning that other unrelated `timeout_kill` references might need surfacing as a deviation. Workspace grep returned two such matches in the test files (`linux_timeout_kills_at_deadline`, `macos_timeout_kills_at_deadline`) — these are test-function names referring to the *behavior* being tested ("timeout kills the child") and have no relationship to the deleted `timeout_fired` AtomicBool. They are correctly out of scope and were left untouched. The plan's anticipatory note was satisfied by inspection without code changes.

## Issues Encountered

- **Pre-existing untracked artifacts in working tree.** `git status --short` showed pre-existing untracked items in `.planning/phases/01-*`, `.planning/phases/02-*`, `.planning/phases/03-*`, `.planning/phases/27.1-*`, `.planning/phases/27.2-*`, `.planning/phases/31-*`, plus `ci-logs-local/`, `dist/`, and three `pr555-*.log` files. None are related to this plan; all were left untouched. Each task commit explicitly named only the files modified (`git add <path1> <path2>`), never `git add .` or `git add -A`, so no pre-existing artifacts were swept into either commit.

## Verification Results

All verification commands from the plan's `<verification>` block:

```text
[1] timeout_fired workspace-wide:                              0 matches  (expected: 0)
[2] spawn_linux_timeout_watchdog signature: 2 params (deadline, cgroup_path)
[3] spawn_macos_timeout_watchdog signature: 2 params (deadline, child_pgrp)
[4] WR-04 match getpgid arm count:                             1          (expected: 1)
[5] armed (whole word) in supervisor_linux.rs:                 0          (expected: 0)
[6] disarm in supervisor_linux.rs:                             0          (expected: 0)
[7] disarm workspace-wide:                                     0          (expected: 0)
[8] #[allow(dead_code)] count in supervisor_linux.rs:          0          (was 1, removed in Task 2)
[9] Drop body head: starts with `// Check for surviving processes` (no `if !self.armed`)
[10] D-19/D-21 plan-level diff: empty (no Windows-side files touched)

cargo build --workspace                                        : clean
cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used : clean
cargo fmt --check --all                                        : clean (exit 0)
cargo test --package nono-cli --bins                           : 18 passed; 0 failed
cargo test --package nono-cli --test resl_nix_async_signal_safety : 5 passed; 0 failed
```

### Host-environment notes

- **Windows host caveat.** This plan's modifications live entirely under `#[cfg(target_os = "linux")]` and `#[cfg(target_os = "macos")]` gates (the `spawn_*_timeout_watchdog` functions, the post-fork spawn block within `execute_supervised`, and the cgroup_v2 module). On the Windows host, those code paths are not compiled; verification relied on `cargo build --workspace` (which compiles the cross-platform shell with `#[cfg(any(linux, macos))]` watchdog-spawn statements stripped out) plus `cargo clippy --workspace --all-targets`. Both pass clean.
- **Linux/macOS-specific tests.** The cgroup_v2 unit tests in `supervisor_linux.rs` (e.g. `detect_from_str_valid_cgroup_v2`) and the macOS-side `new_rejects_cpu_percent` test are `#[cfg(all(test, target_os = "linux"))]` / `#[cfg(all(test, target_os = "macos"))]`-gated and will run on Linux/macOS CI as part of the standard `cargo test` invocation.
- **Static-analysis tests run on Windows.** All 5 tests in `tests/resl_nix_async_signal_safety.rs` (introduced by Plan 25-03 and strengthened by Plan 25-05) read source as text and pass on this Windows host, including `wr_04_no_pid_fallback_on_getpgid_failure` which is the witness that this plan did not regress the WR-04 fix structure.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- **WR-C + WR-D gap-closure:** complete. Phase 25 verifier can now re-run `25-VERIFICATION.md`. Combined with the Plan 25-05 closure of CR-01-RESIDUAL + WR-A/B, the gap-closure cycle is complete; no warnings remain from the original 25-REVIEW-GAPS.md scope.
- **Out of scope (deferred per 25-CONTEXT.md Q1, NOT a blocker for plan or phase completion):** `memory_kill` / `timeout_kill` field plumbing on `SessionRecord` / `SandboxState`. The watchdogs themselves continue to fire correctly — they perform `cgroup.kill` write / `kill(-pgrp, SIGKILL)` atomically. Inspect-data surfacing of "did the watchdog fire" remains a v2.4-or-later backlog candidate. Deletion of `timeout_fired` does NOT preclude future addition; if/when path (a) is revived, the future implementer should add a fresh signal-and-consumer pair together rather than reviving the orphan flag.
- **Phase 25 reverification:** ready to be re-run on Linux/macOS CI to confirm the cgroup_v2 unit tests still compile cleanly against the simplified `CgroupSession` struct (no `armed` field, no `disarm` method) and that the `armed`/`disarm` removal does not break any test that this Windows host was unable to exercise.
- **Plan 25-06 closes the gap-closure cycle.** The orchestrator's `docs(25): plan gap-closure cycle 25-05 + 25-06` commit (ef405bd6) anticipated both plans; both are now landed. Phase 25 is at 6/6 plans complete pending the orchestrator's STATE.md / ROADMAP.md updates.

## TDD Gate Compliance

This plan is `type: execute` (not `type: tdd`), so plan-level TDD gate enforcement does not apply. Both tasks carry `tdd="true"` markers, but per each task's `<behavior>` section, the GREEN-phase guarantor is the existing test infrastructure rather than new tests:

- **Task 1 GREEN:** `cargo test --package nono-cli --test resl_nix_async_signal_safety` (5 tests) is the GREEN-phase verifier — it includes `wr_04_no_pid_fallback_on_getpgid_failure` which asserts the WR-04 match-arm structure remains intact through Task 1's signature simplification. All 5 tests pass.
- **Task 2 GREEN:** the `cgroup_v2` unit tests in `supervisor_linux.rs` (Linux-only) are the GREEN-phase verifier — they construct `CgroupSession` instances and rely on Drop running. With `armed` removed and Drop unconditional, those tests' construction-and-drop sequences continue to work because `armed=true` was the only constructed state; deleting the gate is behavior-preserving by definition. Will be exercised on Linux CI.

No additional TDD compliance commits required.

## Self-Check

Verification of claims before state updates:

```text
[ -f crates/nono-cli/src/exec_strategy.rs ]                              FOUND
[ -f crates/nono-cli/src/exec_strategy/supervisor_linux.rs ]             FOUND
[ -f crates/nono-cli/src/exec_strategy/supervisor_macos.rs ]             FOUND
git log --oneline | grep 134de02a (Task 1 — WR-C)                         FOUND
git log --oneline | grep 28ce03e8 (Task 2 — WR-D)                         FOUND
grep -rn "timeout_fired" crates/                                          0 matches  (expected: 0)
grep -n "fn spawn_linux_timeout_watchdog" exec_strategy.rs                1 match (2-param signature)
grep -n "fn spawn_macos_timeout_watchdog" supervisor_macos.rs             1 match (2-param signature)
grep -c "match getpgid(" exec_strategy.rs                                 1          (expected: 1)
grep -cw "armed" supervisor_linux.rs                                      0          (expected: 0)
grep -c "disarm" supervisor_linux.rs                                      0          (expected: 0)
grep -rn "disarm" crates/                                                 0 matches  (expected: 0)
grep -c "#\[allow(dead_code)\]" supervisor_linux.rs                       0          (expected: 0; was 1, removed in Task 2)
Drop body head: `// Check for surviving processes` (not `if !self.armed`) CONFIRMED
git diff --stat HEAD~2 HEAD -- exec_strategy_windows/ sandbox/windows.rs  empty (D-19/D-21 invariant)
cargo build --workspace                                                   clean
cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used  clean
cargo fmt --check --all                                                   clean
cargo test --package nono-cli --bins                                      18/18 passed
cargo test --package nono-cli --test resl_nix_async_signal_safety         5/5 passed
```

## Self-Check: PASSED

---
*Phase: 25-cross-platform-resl-aipc-unix-design*
*Plan: 06*
*Completed: 2026-05-10*
