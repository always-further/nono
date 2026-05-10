---
phase: 25-cross-platform-resl-aipc-unix-design
verified: 2026-05-10T22:00:00Z
status: human_needed
score: 4/6 must-haves verified (2 host-blocked)
overrides_applied: 0
human_verification:
  - test: "Linux OOM enforcement: run `nono run --memory 256m -- bash -c 'tail -c 1G </dev/urandom'` on Linux 5.13+ with cgroup v2 systemd delegation"
    expected: "Child is OOM-killed by cgroup v2 memory.max; exit code 137. `nono inspect <id>` behavior is TBD — the inspect-side `memory_kill` field was not wired in this phase (PLAN scoped it as optional follow-up). Accept: child exits non-zero within a few seconds."
    why_human: "Requires Linux host with cgroup v2 delegation. This Windows host cannot execute the test."
  - test: "Linux fork limit: run `nono run --max-processes 10 -- bash -c 'for i in {1..20}; do sleep 60 & done; wait'` on Linux 5.13+ with cgroup v2"
    expected: "Child fails after the 10th fork due to pids.max enforcement; nono exits non-zero."
    why_human: "Requires Linux host with cgroup v2 delegation."
  - test: "macOS RLIMIT_AS enforcement: run `nono run --memory 256m -- bash -c '<large alloc>'` on macOS"
    expected: "Child aborts via RLIMIT_AS mmap failure; exits non-zero."
    why_human: "Requires macOS host. Windows host cannot build or run macOS-target binary."
  - test: "macOS cpu-percent parse rejection: build nono for macOS target and run `nono run --cpu-percent 50 -- ls`"
    expected: "Command exits non-zero at clap parse time with stderr containing 'not supported on macOS' or 'cpu_percent_macos'. No child spawned."
    why_human: "Requires macOS build. Source verification passed (parse_cpu_percent is #[cfg(target_os = 'macos')]-gated)."
  - test: "Linux no-warning assertion: run `nono run --memory 4g --cpu-percent 50 --max-processes 1000 --timeout 60s -- echo hi` on Linux and inspect stderr"
    expected: "Stderr contains zero occurrences of 'is not enforced on linux' or 'is not enforced on macos'. Source grep already confirmed zero matches, but runtime confirmation on Linux needed."
    why_human: "Linux host required for runtime binary test. Source-level grep confirms zero matches; this is a belt-and-suspenders runtime check."
---

# Phase 25: Cross-Platform RESL + AIPC Unix Design — Verification Report

**Phase Goal:** Convert silent-no-op RESL flags on Linux/macOS into kernel-level enforcement (cgroup v2 / setrlimit), and ship an ADR documenting which AIPC HandleKinds admit Unix backends.
**Verified:** 2026-05-10T22:00:00Z
**Status:** human_needed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | ADR `docs/architecture/aipc-unix-futures.md` exists with 6 HandleKind rows, Status=Accepted, 251 lines (250-400 range), 6 H2 sections | VERIFIED | File present; `wc -l` = 251; `grep -c "^## "` = 6; `grep "^\*\*Status:\*\*"` = "Accepted"; 6 HandleKind rows confirmed |
| 2 | ADR records the locked decision: HandleKinds 0-2 = Yes (SCM_RIGHTS), 3-5 = No (Windows-only) with alternates | VERIFIED | Decision table rows confirmed; each No verdict names alternate (cgroup v2 / pipe(2) / flock(2)); Reversibility section references AIPC G-04 |
| 3 | PROJECT.md cross-links the ADR via `aipc-unix-futures` | VERIFIED | `grep -n 'aipc-unix-futures' .planning/PROJECT.md` returns line 196 with AIPC Unix futures bullet under Upstream Parity Process |
| 4 | The four "is not enforced on linux/macos" stderr warnings are removed from `collect_unix_resource_limit_warnings` | VERIFIED | `grep -nE "is not enforced on (linux\|macos)" crates/nono-cli/src/` returns zero matches; functions `warn_unix_resource_limits` + `collect_unix_resource_limit_warnings` removed entirely (commit 2823ec29) |
| 5 | Linux runtime: child OOM-killed by cgroup v2 memory.max; Linux fork limit via pids.max; wall-clock timeout via cgroup.kill | UNCERTAIN (host-blocked) | Implementation exists in `supervisor_linux.rs` (CgroupSession with memory.max, cpu.max, pids.max, cgroup.kill); commit 2823ec29 verified. Cannot execute on Windows host. |
| 6 | macOS runtime: child aborted via RLIMIT_AS; cpu-percent rejected at clap parse time; RLIMIT_NPROC enforced | UNCERTAIN (host-blocked) | Implementation exists in `supervisor_macos.rs` (MacosResourceLimits, spawn_macos_timeout_watchdog); `parse_cpu_percent` is #[cfg(target_os = "macos")]-gated in `cli.rs`. Cannot execute on Windows host. |

**Score:** 4/6 truths verified (2 uncertain — host-blocked, require Linux/macOS execution)

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `docs/architecture/aipc-unix-futures.md` | AIPC Unix Futures ADR (6-row table, 6 H2 sections, 250-400 lines, Status=Accepted) | VERIFIED | Present; 251 lines; all 6 H2 sections (Context, Decision Table, Per-HandleKind Rationale, Alternate Mechanisms, Reversibility, References); Status=Accepted |
| `.planning/PROJECT.md` | Cross-link to ADR via `aipc-unix-futures` | VERIFIED | Line 196: "AIPC Unix futures — see [docs/architecture/aipc-unix-futures.md]..." under Upstream Parity Process |
| `crates/nono-cli/src/exec_strategy/supervisor_linux.rs` | CgroupSession RAII struct with detect, apply_limits, place_self_in_cgroup_raw, cgroup.kill, Drop cleanup | VERIFIED | CgroupSession present; detect_from_str, new, apply_limits, place_self_in_cgroup_raw, kill_all, Drop all present |
| `crates/nono-cli/src/exec_strategy/supervisor_macos.rs` | MacosResourceLimits + spawn_macos_timeout_watchdog; setrlimit RLIMIT_AS/RLIMIT_NPROC in pre_exec | VERIFIED | File exists (NEW); MacosResourceLimits struct; install_pre_exec with setrlimit calls inside unsafe pre_exec; spawn_macos_timeout_watchdog present |
| `crates/nono-cli/src/exec_strategy.rs` | Removal of 4 "not enforced" branches; UnixResourceLimitGuard enum; apply_resource_limits_unix dispatch | VERIFIED | warn_unix_resource_limits and collect_unix_resource_limit_warnings removed; UnixResourceLimitGuard{Noop, Linux, Macos}; apply_resource_limits_unix dispatches to CgroupSession or MacosResourceLimits |
| `crates/nono-cli/src/cli.rs` | parse_cpu_percent with macOS #[cfg]-gated rejection | VERIFIED | parse_cpu_percent at line 99 with #[cfg(target_os = "macos")] returning Err containing "not supported on macOS" and "cpu_percent_macos" |
| `crates/nono/src/error.rs` | NotSupportedOnPlatform { feature: String } variant | VERIFIED | Line 52: `NotSupportedOnPlatform { feature: String }` present alongside existing UnsupportedPlatform |
| `crates/nono-cli/tests/resl_nix_linux.rs` | 5 integration tests gated on cgroup v2 (require_cgroup_v2! macro) | VERIFIED | 5 tests: linux_memory_limit_oom_kills_child, linux_max_processes_blocks_eleventh_fork, linux_timeout_kills_at_deadline, linux_no_warnings_on_resource_flags, linux_timeout_atomic_kill_grandchildren |
| `crates/nono-cli/tests/resl_nix_macos.rs` | 4 integration tests (#[cfg(target_os = "macos")]) | VERIFIED | 4 tests: macos_cpu_percent_rejected_at_clap_parse, macos_timeout_kills_at_deadline, macos_no_warnings_on_resource_flags, macos_max_processes_blocks_on_rlimit_nproc |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| ResourceLimits.memory_bytes / cpu_percent / max_processes / timeout | CgroupSession::new in supervisor_linux.rs | exec_strategy::apply_resource_limits_unix → CgroupSession::new(session_id, limits) | VERIFIED | Lines 81-94 in exec_strategy.rs: apply_resource_limits_unix calls CgroupSession::new; CgroupSession::apply_limits writes memory.max / cpu.max / pids.max |
| ResourceLimits | MacosResourceLimits::install_pre_exec in supervisor_macos.rs | exec_strategy::apply_resource_limits_unix → MacosResourceLimits::new + install_pre_exec | VERIFIED | Lines 96-101 in exec_strategy.rs: MacosResourceLimits::new(limits) + install_pre_exec(&mut cmd) |
| Linux supervisor Instant deadline | atomic kill of cgroup descendant tree | spawn_linux_timeout_watchdog writes "1\n" to cgroup.kill | VERIFIED | spawn_linux_timeout_watchdog at exec_strategy.rs:114; cgroup_path.join("cgroup.kill") at line 125 |
| macOS supervisor Instant deadline | SIGKILL to child process group | nix::sys::signal::kill(Pid::from_raw(-child_pgrp), Signal::SIGKILL) | VERIFIED | spawn_macos_timeout_watchdog in supervisor_macos.rs:159; kill with -child_pgrp at line 174 |
| cgroup v1 / no-delegation at startup | fail-fast NonoError::UnsupportedPlatform("cgroup_v2: ...") | CgroupSession::detect_from_str returning Err before child spawn | VERIFIED | detect_from_str validates 0:: prefix; returns UnsupportedPlatform("cgroup_v2: ...") on v1 or empty input |
| cli.rs --cpu-percent | NotSupportedOnPlatform { feature: "cpu_percent_macos" } at clap parse time | parse_cpu_percent #[cfg(target_os = "macos")] returns Err at parse time | VERIFIED | cli.rs:99-109; value_parser = parse_cpu_percent at line 1961 |
| PROJECT.md Upstream Parity Process | docs/architecture/aipc-unix-futures.md | Markdown link at line 196 | VERIFIED | Link text: `[docs/architecture/aipc-unix-futures.md](../docs/architecture/aipc-unix-futures.md)` |
| ADR References section | PROJECT.md (AIPC HandleKind discriminator entry) | `.planning/PROJECT.md` § Key Decisions back-reference | VERIFIED | ADR lines 216-217 reference PROJECT.md § Key Decisions and § Upstream Parity Process |
| ADR References section | Phase 23 RejectStage discussion | "Phase 23" back-reference in Context, Per-HandleKind Rationale, and References | VERIFIED | Phase 23 referenced at ADR lines 10, 34, 78, 84, 134, 226; RejectStage taxonomy motivation present |

### Data-Flow Trace (Level 4)

These are enforcement paths, not rendering-of-data paths; Level 4 is not applicable for the ADR (documentation-only). For the RESL enforcement paths:

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| `supervisor_linux.rs` CgroupSession::apply_limits | memory.max / cpu.max / pids.max writes | ResourceLimits from RunArgs via exec_strategy | Real fs writes to /sys/fs/cgroup (kernel-level) | WIRED — host-blocked for runtime verification |
| `supervisor_macos.rs` MacosResourceLimits::install_pre_exec | setrlimit(RLIMIT_AS, RLIMIT_NPROC) in child pre_exec | ResourceLimits from RunArgs via exec_strategy | Real syscall in child | WIRED — host-blocked for runtime verification |
| `exec_strategy.rs` spawn_linux_timeout_watchdog | "1\n" write to cgroup.kill | Instant deadline from resource_limits.timeout | Real fs write to kernel cgroup interface | WIRED — host-blocked for runtime verification |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| ADR file exists and has correct shape | `wc -l docs/architecture/aipc-unix-futures.md` | 251 lines | PASS |
| ADR has 6 HandleKind rows | `grep -cE "^\| (File\|Socket\|Pipe\|JobObject\|Event\|Mutex) \|" docs/architecture/aipc-unix-futures.md` | 6 | PASS |
| ADR Status is Accepted | `grep "^\*\*Status:\*\*" docs/architecture/aipc-unix-futures.md` | `**Status:** Accepted` | PASS |
| ADR has 6 H2 sections | `grep -c "^## " docs/architecture/aipc-unix-futures.md` | 6 | PASS |
| PROJECT.md cross-link present | `grep -c "aipc-unix-futures" .planning/PROJECT.md` | 1 | PASS |
| Zero "not enforced" warnings in source | `grep -rE "is not enforced on (linux\|macos)" crates/nono-cli/src/` | 0 matches | PASS |
| NotSupportedOnPlatform variant in error.rs | `grep -n "NotSupportedOnPlatform" crates/nono/src/error.rs` | Line 52 present | PASS |
| Commit 2823ec29 exists (RESL implementation) | `git log --oneline --all \| grep 2823ec29` | Found: "feat(25-01): implement Linux cgroup v2 + macOS setrlimit resource enforcement" | PASS |
| Commit 30d6fdb1 exists (ADR) | `git log --oneline --all \| grep 30d6fdb1` | Found: "docs(25-02): land AIPC Unix Futures ADR (REQ-AIPC-NIX-01)" | PASS |
| Linux runtime OOM kill | Requires Linux host | SKIP — host-blocked |
| macOS RLIMIT_AS abort | Requires macOS host | SKIP — host-blocked |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| REQ-RESL-NIX-01 | Plan 25-01 | Linux cgroup v2 backends for memory / CPU / process count | PARTIAL — source verified; runtime host-blocked | CgroupSession in supervisor_linux.rs; memory.max / cpu.max / pids.max writes; 4 "not enforced" warnings removed; acceptance criteria 1-3 require Linux host |
| REQ-RESL-NIX-02 | Plan 25-01 | Linux wall-clock timeout via supervisor + cgroup.kill | PARTIAL — source verified; runtime host-blocked | spawn_linux_timeout_watchdog writes to cgroup.kill; acceptance criteria 1-2 require Linux host |
| REQ-RESL-NIX-03 | Plan 25-01 | macOS setrlimit equivalents; cpu-percent rejected at parse time | PARTIAL — source verified; runtime host-blocked | MacosResourceLimits in supervisor_macos.rs; parse_cpu_percent #[cfg(macos)] gating in cli.rs; acceptance criteria 1-4 require macOS host |
| REQ-AIPC-NIX-01 | Plan 25-02 | AIPC Unix futures ADR | SATISFIED | ADR at docs/architecture/aipc-unix-futures.md; 6 HandleKind verdicts; PROJECT.md cross-link; design-only; REQ-AIPC-NIX-01 acceptance criteria 1-3 all met |

**Orphaned requirements:** None. All 4 phase requirements are claimed by plans and verified above.

**ROADMAP success criterion note:** Criterion 5 says "each of 5 HandleKinds" — this is a typo in the ROADMAP; the ADR, PLAN, and REQUIREMENTS.md all say 6 HandleKinds (0..5). The ADR correctly covers 6. No action needed.

**`memory_kill` / `timeout_kill` inspect fields:** ROADMAP criterion 1 references `nono inspect <id>` showing `memory_kill: true`. These fields do not exist in `inspect_cmd.rs` or `sandbox_state.rs`. The PLAN explicitly scoped this as optional follow-up ("If absent, that lands as a follow-up; this plan focuses on enforcement and uses existing exit-code reporting"). This is a known gap documented by the implementer, not a surprise. The enforcement path itself (cgroup OOM kill, exit code 137) works without the field. Classifying as human_needed follow-up, not a blocker.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `crates/nono-cli/src/exec_strategy/supervisor_linux.rs` | 905-906 | Cgroup path from `/proc/self/cgroup` constructed via string ops without `Path::starts_with("/sys/fs/cgroup")` post-check (WR-03 from code review) | WARNING | A compromised container runtime could craft a malicious `/proc/self/cgroup` entry with `..` components to redirect cgroup directory creation. `PathBuf::join` does not resolve `..` at the type level. Mitigation: add `if !abs_path.starts_with("/sys/fs/cgroup") { return Err(...) }` after line 906. This matches CLAUDE.md § Path Handling requirement. Does not prevent OOM/pids/cpu enforcement on normal hosts. |
| `crates/nono-cli/src/exec_strategy/supervisor_linux.rs` | 31 | `lines[0].starts_with("0::/")` in `cgroup_v2_available()` test helper is string comparison on a path-like string (WR-01 from code review) | INFO | Test skip logic may diverge from production `detect_from_str`. Low risk on well-formed systems; does not affect enforcement correctness. |
| `crates/nono-cli/src/exec_strategy/supervisor_macos.rs` | 114, 119 | `e as i32` cast on `nix::errno::Errno` instead of `std::io::Error::from(e)` (WR-05 from code review) | WARNING | Relies on nix's `#[repr(i32)]` which could change. Does not affect current behavior; idiomatic fix is `map_err(std::io::Error::from)?`. |
| `crates/nono-cli/src/exec_strategy.rs` | 53 | `#[allow(dead_code)]` on `UnixResourceLimitGuard` enum (IN-01 from code review) | INFO | CLAUDE.md § Lazy use of dead code says avoid this attribute. The Macos variant is dead code on Linux builds and vice versa. Should use `#[cfg(target_os = "...")]` per-variant instead. |

**Code review blockers (CR-01, CR-02):** The code review found 2 blockers:

- **CR-01:** `format!()` macro calls inside the post-fork child branch of `execute_supervised` allocate heap memory, potentially deadlocking if the allocator lock was held at `fork()`. This is a correctness issue in the supervised execution path on Linux. The async-signal-safe cgroup placement path correctly avoids `format!()`, but other child-branch error paths use it.

- **CR-02:** The Linux timeout watchdog is only spawned when `unix_resource_guard.is_some()`. If `--timeout` is the only resource limit, the cgroup is created (correctly) but the re-read confirms that `resource_limits.is_empty()` checks all four fields — timeout alone makes `is_empty()` false, so a cgroup is created and the watchdog fires correctly. The actual blocker scenario from the code review (watchdog-not-spawned when guard is None) does not apply when timeout alone is set. The `execute_direct` mode silently ignores `--timeout` with no user-visible warning (WR-07).

CR-01 is a correctness concern for the supervised-fork post-fork child branch. It does not prevent cgroup enforcement from working in the normal case (the cgroup placement path IS async-signal-safe). In the failure case (allocator deadlock), the child would hang rather than proceed unsandboxed — the fail-secure behavior is maintained. This is a WARNING for this verification, not a goal-blocking BLOCKER, because:
1. The cgroup enforcement path (memory.max, cpu.max, pids.max, cgroup.kill) operates correctly on the parent side.
2. The async-signal-safe risk is in the error-reporting path within the child branch, not the enforcement path.
3. Behavioral acceptance criteria can only be verified on Linux host anyway.

These code review findings are surfaced as advisory. The REVIEW.md at `.planning/phases/25-cross-platform-resl-aipc-unix-design/25-REVIEW.md` documents them in detail.

### Human Verification Required

The following items require Linux or macOS host execution. They cannot be verified on the current Windows host.

#### 1. Linux OOM Kill via cgroup v2 memory.max (REQ-RESL-NIX-01 criterion 1)

**Test:** On Linux 5.13+ with systemd cgroup v2 delegation:
```
nono run --memory 256m -- bash -c 'tail -c 1G </dev/urandom'
```
**Expected:** Child exits non-zero (SIGKILL, exit code 137). Cgroup OOM kill triggered by memory.max.
**Note:** `nono inspect <id>` showing `memory_kill: true` is NOT expected — this field was not wired in Phase 25 (PLAN scoped as optional follow-up). Accept any non-zero exit code.
**Why human:** Requires Linux kernel with cgroup v2 delegation (/sys/fs/cgroup cgroup2 mount).

#### 2. Linux Fork Limit via pids.max (REQ-RESL-NIX-01 criterion 3)

**Test:** On Linux with cgroup v2:
```
nono run --max-processes 10 -- bash -c 'for i in {1..20}; do sleep 60 & done; wait'
```
**Expected:** Child fails after the 10th fork (pids.max violation). nono exits non-zero.
**Why human:** Requires Linux host.

#### 3. Linux Timeout via cgroup.kill (REQ-RESL-NIX-02 criterion 1)

**Test:** On Linux with cgroup v2:
```
nono run --timeout 5s -- sleep 60
```
**Expected:** nono exits non-zero at approximately 5 seconds (cgroup.kill fires). Wall time 3–10s.
**Why human:** Requires Linux host.

#### 4. Linux No-Warning Assertion (REQ-RESL-NIX-01 criterion 4, runtime)

**Test:** On Linux:
```
nono run --memory 4g --cpu-percent 50 --max-processes 1000 --timeout 60s -- echo hi
```
**Expected:** stderr contains zero occurrences of "is not enforced on linux" or "is not enforced on macos". (Source grep already confirmed zero — this is belt-and-suspenders runtime check.)
**Why human:** Runtime binary test requires Linux host. Source evidence is sufficient for PASS if human test cannot be run promptly.

#### 5. macOS RLIMIT_AS Enforcement (REQ-RESL-NIX-03 criterion 1)

**Test:** On macOS:
```
nono run --memory 256m -- bash -c 'python3 -c "import ctypes; buf = ctypes.create_string_buffer(1024*1024*1024)"'
```
**Expected:** Child aborts via RLIMIT_AS mmap failure; exits non-zero.
**Why human:** Requires macOS host and macOS-target build.

#### 6. macOS cpu-percent Clap-Time Rejection (REQ-RESL-NIX-03 criterion 3)

**Test:** On macOS (or with macOS-target cross-compile):
```
nono run --cpu-percent 50 -- ls
```
**Expected:** Exit code non-zero; stderr contains "not supported on macOS" or "cpu_percent_macos"; no child spawned (ls output absent).
**Why human:** Requires macOS-target binary. Source verification confirms `parse_cpu_percent` is `#[cfg(target_os = "macos")]`-gated with correct error message.

### Code Review Findings to Track

The code review (`25-REVIEW.md`) identified 2 blockers and 7 warnings. These are advisory for this verification. They do not block goal achievement (which requires Linux/macOS host for final acceptance) but SHOULD be addressed before the RESL-NIX work is considered production-ready:

| Finding | File | Severity | Description | Recommendation |
|---------|------|----------|-------------|----------------|
| CR-01 | exec_strategy.rs:862-863 et al | Critical | `format!()` in post-fork child branch (async-signal-unsafe heap alloc) | Replace format! with static `const MSG: &[u8]` in child branch error paths |
| CR-02 | exec_strategy.rs:1280-1291 | Critical | `--timeout` in Direct mode silently not enforced; no user warning | Add `warn!()` when timeout is set in Direct strategy mode |
| WR-03 | supervisor_linux.rs:905-906 | Warning | Cgroup path constructed without `Path::starts_with("/sys/fs/cgroup")` post-check | Add `if !abs_path.starts_with("/sys/fs/cgroup") { return Err(...) }` after path join |
| WR-04 | exec_strategy.rs:1296 | Warning | `getpgid` failure falls back to child PID, risking wrong-pgrp kill | Match on getpgid result; skip kill on Err instead of falling back |

### Gaps Summary

No hard FAILED truths are identified from static verification. The 2 uncertain truths are host-blocked and represent implementation that structurally exists in the codebase but cannot be executed on this Windows host.

**The phase goal's two objectives are structurally achieved:**
1. **RESL Unix backends** — kernel-level enforcement code is in the codebase (CgroupSession, MacosResourceLimits, dispatch wiring); the 4 no-op warnings are removed; cli.rs rejects --cpu-percent on macOS at parse time. Runtime verification is host-blocked.
2. **AIPC ADR** — `docs/architecture/aipc-unix-futures.md` exists, is correctly shaped, and is cross-linked from PROJECT.md. REQ-AIPC-NIX-01 is fully satisfied.

**Open items (not goal blockers, but should be tracked):**
- `memory_kill` / `timeout_kill` fields not wired into `nono inspect` output (PLAN scoped as optional; accept existing exit-code reporting)

### Gaps to Close (user-selected 2026-05-10 from 25-REVIEW.md)

User reviewed VERIFICATION.md `human_needed` status and selected 4 code-review findings to address before phase completion. The host-gated runtime acceptance items (HUMAN-UAT.md tests 1–6) are kept separate, to be closed via `/gsd-verify-work 25` on Linux/macOS host.

| # | ID | Severity | File | Description | Acceptance |
|---|----|----------|------|-------------|------------|
| 1 | CR-01 | blocker | crates/nono-cli/src/exec_strategy.rs:862-863, 899, 933, 951, 994, 1011, 1054, 1071, 1093 | `format!()` calls in post-fork child branch of `execute_supervised` — heap allocation in async-signal-unsafe context risks allocator-mutex deadlock when parent holds it at `fork()` time. | Replace each `format!()` in child branch with `const MSG: &[u8]` static byte strings, or write via `write_all` with pre-formatted parent-side messages. Child branch must contain zero `format!`/`println!`/`eprintln!`/`String` calls between `fork()` and `exec()`. |
| 2 | CR-02 | blocker | crates/nono-cli/src/exec_strategy.rs:1280-1291 | `--timeout` is silently not enforced in Direct strategy mode; user gets no warning. | Emit a `warn!()` log line (and visible stderr line on `-v` or always) when `--timeout` is set AND strategy resolves to Direct. Message names the limitation and suggests `--strategy supervised`. |
| 3 | WR-03 | warning | crates/nono-cli/src/exec_strategy/supervisor_linux.rs:905-906 (around `CgroupSession::detect_from_str`) | Cgroup path constructed via `.join(cgroup_rel.trim_start_matches('/'))` without `Path::starts_with("/sys/fs/cgroup")` post-check. Per CLAUDE.md §Path Handling, this is a flagged security footgun if `/proc/self/cgroup` content is ever attacker-controlled. | Canonicalize the joined path, assert `canon.starts_with("/sys/fs/cgroup")` after construction, return `NonoError` on mismatch. Add a regression test that feeds a malicious cgroup-relative path with `..` components. |
| 4 | WR-02/04/05 | warning (group) | crates/nono-cli/src/exec_strategy/supervisor_macos.rs | (a) WR-02: `let _ = setrlimit(...)` silently discards errors in supervised-child branch — sandbox may run without requested `--max-processes` enforcement if hard limit is below request. (b) WR-04: `getpgid(Some(child)).unwrap_or(child)` falls back to child PID as pgrp if `getpgid` fails; under PID reuse, `kill(-pgrp, SIGKILL)` could target the wrong process group. (c) WR-05: `e as i32` cast on `nix::errno::Errno` relies on internal repr. | (a) WR-02: surface setrlimit failure as `NonoError::ResourceLimitApply { feature, errno }` and fail closed instead of swallowing. (b) WR-04: match on `Result` from `getpgid`; on `Err`, log and skip the kill — do NOT fall back. (c) WR-05: use `std::io::Error::from(e)` to extract the raw errno via the public API. |

### Out of Scope for This Gap Closure

- HUMAN-UAT.md tests 1–6 (host-gated runtime acceptance) — remain pending in `25-HUMAN-UAT.md`, closed via `/gsd-verify-work 25` on Linux/macOS host.
- WR-01 (cgroup detection duplication in test), WR-06 (`select_exec_strategy` always returns Supervised), WR-07 (Direct mode timeout no-warn — subsumed by CR-02), and 3 info items — deferred until production-hardening pass.

---

_Verified: 2026-05-10T22:00:00Z_
_Verifier: Claude (gsd-verifier)_
