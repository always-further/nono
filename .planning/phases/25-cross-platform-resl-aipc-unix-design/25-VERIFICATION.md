---
phase: 25-cross-platform-resl-aipc-unix-design
verified: 2026-05-10T23:30:00Z
status: gaps_found
score: 4/6 must-haves verified (2 host-blocked) — gap-closure plans 25-03 + 25-04 landed; new CR-01-RESIDUAL surfaced from gap-closure code review
overrides_applied: 0
re_verification:
  previous_status: human_needed
  previous_score: 4/6
  gaps_closed:
    - "CR-01: 9 format!() calls in lexical post-fork child branch replaced with const &[u8] static byte strings (commit 45ef4f3f)"
    - "CR-02: --timeout in Direct strategy mode now emits warn!() + eprintln!() user-visible warning (commit a069d6b3)"
    - "WR-02: macOS setrlimit failures fail-closed via _exit(126) with static MSG_RLIMIT_*_FAIL (commit 28df5c50)"
    - "WR-03: CgroupSession::detect_from_str rejects Component::ParentDir + verifies Path::starts_with(/sys/fs/cgroup) (commit 7dcd9fe8)"
    - "WR-04: getpgid PID fallback removed; safe match arm skips watchdog on Err (commit abeda8e7)"
    - "WR-05: install_pre_exec uses idiomatic map_err(std::io::Error::from) instead of e as i32 cast (commit f13ba84f)"
  gaps_remaining:
    - "Six Linux/macOS host-gated runtime UAT items (HUMAN-UAT.md tests 1–6) — unchanged; cannot be executed on Windows host"
  regressions:
    - "CR-01-RESIDUAL: clear_close_on_exec() (lines 2759–2782) still calls format!() on its fcntl error paths and is reachable from the post-fork child branch at line 950. The static-analysis test cr_01_no_format_macro_in_post_fork_child_branch only inspects the lexical region of Ok(ForkResult::Child) => { and does not recursively scan called functions, so it reports green while the underlying allocator-deadlock primitive remains exploitable. Surfaced by 25-REVIEW-GAPS.md."
gaps:
  - truth: "No format!() / println!() / eprintln!() / String calls inside the post-fork child branch of execute_supervised between fork() and exec()"
    status: partial
    reason: "Lexical region of the child arm is clean (CR-01 fixed in commit 45ef4f3f), but clear_close_on_exec() — invoked from line 950 inside the child arm — still calls format!() on both fcntl error paths (lines 2763 and 2774). The static-analysis test does not catch this because it only scans the lexical region of the arm, not the call graph. This re-opens the original CR-01 allocator-deadlock risk along the fcntl-failure code path. The internal consistency concern raised by 25-REVIEW-GAPS.md (Sandbox::apply, seccomp helpers also allocate) needs an explicit decision: either harden every callee (strict reading of CR-01) or document the threading-context contract as the security boundary and retract CR-01's zero-allocation goal."
    artifacts:
      - path: "crates/nono-cli/src/exec_strategy.rs"
        issue: "clear_close_on_exec at line 2759 returns Err(NonoError::SandboxInit(format!(...))) on both fcntl(F_GETFD) and fcntl(F_SETFD) failure. Called from post-fork child at line 950."
      - path: "crates/nono-cli/tests/resl_nix_async_signal_safety.rs"
        issue: "cr_01_no_format_macro_in_post_fork_child_branch (lines 95–128) only inspects the lexical region [start_line..=end_line] of the first Ok(ForkResult::Child) => { match arm. It does not recursively scan called functions or check helpers like clear_close_on_exec, Sandbox::apply, install_seccomp_notify, send_fd_via_socket. False-green primitive."
    missing:
      - "Convert clear_close_on_exec to return std::io::Result<()> using std::io::Error::last_os_error() (which captures errno into a stack-resident io::Error::Repr without heap allocation). Update the call site at line 950 to use the new signature."
      - "Strengthen cr_01_no_format_macro_in_post_fork_child_branch to also scan reachable helpers — at minimum assert that clear_close_on_exec body contains zero format!() calls. Or annotate the production child arm with sentinel comments (// CR-01-CHILD-ARM-START / // CR-01-CHILD-ARM-END) and have the test scope by sentinel rather than brace counting."
      - "Decide and document the threading-context contract for Sandbox::apply, install_seccomp_notify, send_fd_via_socket, install_seccomp_proxy_filter, set_dumpable: either (a) audit + harden every helper to ensure no heap allocation on any path reachable from the child arm, OR (b) formalize the threading-context contract as the security boundary, retract CR-01's zero-allocation goal, update 25-03-SUMMARY accordingly. Internal consistency between 'these helpers may allocate by design' and 'the lexical child arm must not allocate' must be reconciled in 25-03-SUMMARY § 'Auto-fixed Issues' or a new ADR."
deferred:
  - truth: "Linux runtime: child OOM-killed by cgroup v2 memory.max; Linux fork limit via pids.max; wall-clock timeout via cgroup.kill"
    addressed_in: "Phase 25 HUMAN-UAT (host-gated)"
    evidence: "HUMAN-UAT.md tests 1–4 require Linux 5.13+ host with cgroup v2 systemd delegation. Implementation structurally exists in supervisor_linux.rs (CgroupSession). To be closed via /gsd-verify-work 25 on Linux CI."
  - truth: "macOS runtime: child aborted via RLIMIT_AS; cpu-percent rejected at clap parse time; RLIMIT_NPROC enforced"
    addressed_in: "Phase 25 HUMAN-UAT (host-gated)"
    evidence: "HUMAN-UAT.md tests 5–6 require macOS host. Implementation structurally exists in supervisor_macos.rs (MacosResourceLimits, install_pre_exec, spawn_macos_timeout_watchdog). To be closed via /gsd-verify-work 25 on macOS CI."
human_verification:
  - test: "Linux OOM kill via cgroup v2 memory.max"
    expected: "`nono run --memory 256m -- bash -c 'tail -c 1G </dev/urandom'` exits non-zero (SIGKILL/137). memory_kill inspect field NOT expected (scoped as optional follow-up by Plan 25-01). Accept any non-zero exit code."
    why_human: "Requires Linux 5.13+ with cgroup v2 systemd delegation. Windows host cannot execute."
  - test: "Linux fork limit via pids.max"
    expected: "`nono run --max-processes 10 -- bash -c 'for i in {1..20}; do sleep 60 & done; wait'` fails after the 10th fork; nono exits non-zero."
    why_human: "Requires Linux host with cgroup v2 delegation."
  - test: "Linux timeout via cgroup.kill"
    expected: "`nono run --timeout 5s -- sleep 60` exits non-zero at approximately 5 seconds (cgroup.kill fires). Wall time 3–10s."
    why_human: "Requires Linux host."
  - test: "Linux no-warning assertion (runtime)"
    expected: "`nono run --memory 4g --cpu-percent 50 --max-processes 1000 --timeout 60s -- echo hi` stderr contains zero occurrences of 'is not enforced on linux' or 'is not enforced on macos'. Source grep already confirms zero — this is belt-and-suspenders runtime check."
    why_human: "Runtime binary test requires Linux host."
  - test: "macOS RLIMIT_AS enforcement"
    expected: "`nono run --memory 256m -- bash -c '<large alloc>'` aborts via RLIMIT_AS mmap failure; exits non-zero."
    why_human: "Requires macOS host and macOS-target build."
  - test: "macOS cpu-percent clap-time rejection"
    expected: "`nono run --cpu-percent 50 -- ls` exit code non-zero; stderr contains 'not supported on macOS' or 'cpu_percent_macos'; no child spawned (ls output absent)."
    why_human: "Requires macOS-target binary. Source verification confirms parse_cpu_percent is #[cfg(target_os = 'macos')]-gated with correct error message."
overrides: []
---

# Phase 25: Cross-Platform RESL + AIPC Unix Design — Verification Report (Re-Verification)

**Phase Goal:** Convert silent-no-op RESL flags on Linux/macOS into kernel-level enforcement (cgroup v2 / setrlimit), and ship an ADR documenting which AIPC HandleKinds admit Unix backends.
**Verified:** 2026-05-10T23:30:00Z
**Status:** gaps_found
**Re-verification:** Yes — second pass after gap-closure plans 25-03 + 25-04 landed.

## Re-Verification Summary

The previous verification (2026-05-10T22:00:00Z) returned `human_needed` with 4/6 truths verified and 2 host-blocked. The user selected 6 code-review findings (CR-01, CR-02, WR-02, WR-03, WR-04, WR-05) for closure before phase completion. Plans 25-03 and 25-04 executed those fixes and the gap-closure code review (`25-REVIEW-GAPS.md`) inspected the result.

**All 6 originally selected findings are technically fixed at the call sites named in 25-REVIEW.md.** Source-level verification confirms each transformation:

| Finding | Site | Pre-fix | Post-fix | Commit |
|---------|------|---------|----------|--------|
| CR-01 | exec_strategy.rs lexical child arm | 9× `format!()` | 9× `const MSG_*: &[u8]` + `libc::write` + `libc::_exit(126)` | `45ef4f3f` |
| CR-02 | execute_direct (lines 455–470) | silent timeout in Direct mode | `warn!()` + `eprintln!()` dual emission | `a069d6b3` |
| WR-02 | execute_supervised macOS child branch | `let _ = setrlimit(...)` (silent) | `if .is_err() { write(MSG_RLIMIT_*_FAIL); _exit(126); }` | `28df5c50` |
| WR-03 | supervisor_linux.rs detect_from_str | bare `PathBuf::join` | `Path::starts_with("/sys/fs/cgroup")` + `Component::ParentDir` scan | `7dcd9fe8` |
| WR-04 | exec_strategy.rs macOS watchdog spawn | `getpgid(...).unwrap_or(child)` | `match getpgid(...) { Ok => spawn, Err => warn + None }` | `abeda8e7` |
| WR-05 | supervisor_macos.rs install_pre_exec | `e as i32` cast on Errno | `map_err(std::io::Error::from)` (public From impl) | `f13ba84f` |

**However, a new critical was surfaced by the gap-closure review** (25-REVIEW-GAPS.md CR-01-RESIDUAL): the CR-01 fix only purged `format!()` calls in the *lexical* region of `Ok(ForkResult::Child) => {`, but a function called from inside that arm — `clear_close_on_exec` (line 2759, called at line 950) — still uses `format!()` on its fcntl error paths. The static-analysis test reports GREEN because it only inspects the lexical region of the arm, not the call graph. The original allocator-deadlock primitive remains reachable along the fcntl-failure code path.

This is explicitly worse than the original CR-01: the test now passes a regression check while the defect is still exploitable. The phase cannot be marked passed until this is resolved.

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | ADR `docs/architecture/aipc-unix-futures.md` exists with 6 HandleKind rows, Status=Accepted, 251 lines, 6 H2 sections | VERIFIED | Confirmed in initial verification (2026-05-10T22:00:00Z); unchanged. Commit 30d6fdb1 |
| 2 | ADR records the locked decision: HandleKinds 0–2 = Yes (SCM_RIGHTS), 3–5 = No (Windows-only) with alternates | VERIFIED | Confirmed in initial verification; unchanged |
| 3 | PROJECT.md cross-links the ADR via `aipc-unix-futures` | VERIFIED | Confirmed in initial verification; unchanged |
| 4 | The four "is not enforced on linux/macos" stderr warnings are removed from collect_unix_resource_limit_warnings | VERIFIED | Confirmed in initial verification (commit 2823ec29); unchanged |
| 5 | Linux runtime: child OOM-killed by cgroup v2 memory.max; pids.max enforcement; cgroup.kill timeout | UNCERTAIN (host-blocked) | Implementation structurally present in supervisor_linux.rs; cannot execute on Windows. Deferred to HUMAN-UAT. |
| 6 | macOS runtime: RLIMIT_AS abort; --cpu-percent clap rejection; RLIMIT_NPROC enforcement | UNCERTAIN (host-blocked) | Implementation structurally present in supervisor_macos.rs; cannot execute on Windows. Deferred to HUMAN-UAT. |

**Score:** 4/6 truths verified (unchanged); 2 host-blocked deferred to HUMAN-UAT.

### Gap-Closure Verification (Plans 25-03 + 25-04)

Each must-have from the gap-closure plans verified against source:

| Gap-closure must-have | Status | Evidence |
|-----------------------|--------|----------|
| No format!() / println!() / eprintln!() / String calls inside the lexical post-fork child branch of execute_supervised | PARTIAL | Lexical region clean. **CR-01-RESIDUAL**: clear_close_on_exec (line 2759, called at line 950) still uses format!() — reachable from child arm. Test does not catch this. |
| --timeout in Direct strategy mode emits warn!() naming the limitation and suggesting --strategy supervised | VERIFIED | exec_strategy.rs:462–469 — both warn!() and eprintln!() present; #[cfg(any(linux, macos))]-gated. Test cr_02_direct_mode_timeout_emits_warn_macro asserts both invocations. |
| setrlimit failures in execute_supervised macOS child branch cause _exit(126) with static message, not silent discard | VERIFIED | exec_strategy.rs:911 (MSG_RLIMIT_AS_FAIL) and 930 (MSG_RLIMIT_NPROC_FAIL) confirmed. Zero `let _ = setrlimit` matches in file. Test wr_02_no_silent_setrlimit_discards passes. |
| getpgid failure in macOS watchdog spawn logs warning and returns None — no PID fallback, no SIGKILL to wrong group | VERIFIED | exec_strategy.rs:1353–1369 — match arm with Ok(spawn)/Err(warn + None). Zero `unwrap_or(child)` matches. Test wr_04_no_pid_fallback_on_getpgid_failure passes. |
| CgroupSession::detect_from_str rejects cgroup-relative paths containing .. components | VERIFIED | supervisor_linux.rs:928–937 — `Path::starts_with("/sys/fs/cgroup")` AND `components().any(\|c\| matches!(c, Component::ParentDir))` — strengthened beyond plan's literal text per Rule 1 deviation in 25-04-SUMMARY (the bare `Path::starts_with` fix the plan proposed would have failed the test, since `/sys/fs/cgroup/../../etc` does start with `/sys/fs/cgroup` at the component level). |
| nix::errno::Errno-to-io::Error conversion in supervisor_macos.rs uses std::io::Error::from(e) not e as i32 | VERIFIED | supervisor_macos.rs:122 and 127 — both `map_err(std::io::Error::from)`. Zero `from_raw_os_error` matches. SAFETY doc comment at lines 89–98 updated to reference From<Errno> impl. |

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `docs/architecture/aipc-unix-futures.md` | AIPC Unix Futures ADR | VERIFIED | Unchanged from initial verification. |
| `.planning/PROJECT.md` | Cross-link to ADR | VERIFIED | Unchanged. |
| `crates/nono-cli/src/exec_strategy/supervisor_linux.rs` | CgroupSession + detect_from_str + WR-03 traversal guard | VERIFIED | All present. WR-03 guard at lines 928–937. Three regression tests in `#[cfg(all(test, target_os = "linux"))]` module: cgroup_path_rejects_parent_dir_traversal, cgroup_path_rejects_encoded_traversal, cgroup_path_accepts_normal_path. |
| `crates/nono-cli/src/exec_strategy/supervisor_macos.rs` | MacosResourceLimits + spawn_macos_timeout_watchdog + WR-05 idiomatic conversion | VERIFIED | install_pre_exec uses map_err(std::io::Error::from); SAFETY doc comment updated. |
| `crates/nono-cli/src/exec_strategy.rs` | const MSG_* static byte strings; CR-02 warning; WR-02 fail-closed; WR-04 safe match | VERIFIED (with CR-01-RESIDUAL caveat) | 11 const MSG_* declarations present (9 CR-01 + 2 WR-02). Lexical child arm has zero format!(). **clear_close_on_exec at line 2759 still uses format!() on fcntl error paths — reachable from child arm at line 950.** |
| `crates/nono-cli/tests/resl_nix_async_signal_safety.rs` | 5 static-analysis regression tests | VERIFIED (with WR-A/WR-B caveat — see Anti-Patterns) | All 5 tests present. find_child_branch_lines uses src.find() which returns first occurrence (line 844 — production); two test-helper child arms at lines 3551 and 3647 not covered. |
| `crates/nono-cli/tests/resl_nix_linux.rs` | 5 integration tests gated on cgroup v2 | VERIFIED | Unchanged from initial verification. |
| `crates/nono-cli/tests/resl_nix_macos.rs` | 4 integration tests (#[cfg(target_os = "macos")]) | VERIFIED | Unchanged from initial verification. |

### Key Link Verification

All key links from the original plan + gap-closure plans verified. New links from gap-closure:

| From | To | Via | Status |
|------|----|----|--------|
| execute_direct + resource_limits.timeout.is_some() | warn!() + eprintln!() to stderr | exec_strategy.rs:455–470 #[cfg(any(linux, macos))] block | VERIFIED |
| execute_supervised macOS child setrlimit | libc::_exit(126) on failure | is_err() guards at lines 910 and 929 | VERIFIED |
| spawn_macos_timeout_watchdog caller | skip kill on getpgid Err | match getpgid at line 1353; returns None on Err | VERIFIED |
| CgroupSession::detect_from_str | NonoError::UnsupportedPlatform on traversal | abs_path.starts_with + Component::ParentDir scan at lines 928–937 | VERIFIED |
| MacosResourceLimits::install_pre_exec setrlimit | std::io::Error via From<Errno> | map_err(std::io::Error::from) at lines 122, 127 | VERIFIED |
| **execute_supervised child branch line 950** | **clear_close_on_exec at line 2759** | **direct call** | **NOT_WIRED FOR ASYNC-SIGNAL-SAFETY — clear_close_on_exec uses format!() on fcntl error paths (lines 2763, 2774). The child arm's allocator-deadlock primitive is reachable through this call.** |

### Behavioral Spot-Checks (Source-Level)

Behavioral runtime checks for Linux/macOS enforcement are host-gated. Source-level static checks performed:

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Lexical child arm has zero format!() | `awk 'NR>=844 && NR<=1196' exec_strategy.rs \| grep -c format!` | 0 | PASS |
| 11+ const MSG_* declarations present | `grep -c "const MSG_" exec_strategy.rs` | 11 | PASS |
| CR-02 warn!() invocation present | grep `warn!.*timeout.*not enforced` exec_strategy.rs | line 462 | PASS |
| CR-02 eprintln!() invocation present | grep `eprintln!.*--strategy supervised` exec_strategy.rs | line 466 | PASS |
| WR-02 zero `let _ = setrlimit` discards | `grep -c "let _ = setrlimit" exec_strategy.rs` | 0 | PASS |
| WR-04 zero `unwrap_or(child)` PID fallbacks | `grep -c "unwrap_or(child)" exec_strategy.rs` | 0 | PASS |
| WR-04 match getpgid arm present | `grep "match getpgid(" exec_strategy.rs` | line 1353 | PASS |
| WR-03 cgroup path traversal guard present | `grep "starts_with.*sys/fs/cgroup" supervisor_linux.rs` | lines 912, 928, 1335, 1370 | PASS |
| WR-05 from_raw_os_error gone | `grep -c "from_raw_os_error" supervisor_macos.rs` | 0 | PASS |
| WR-05 idiomatic conversion present | `grep -c "map_err(std::io::Error::from)" supervisor_macos.rs` | 2 | PASS |
| Gap-closure commits exist | `git log --oneline 45ef4f3f a069d6b3 28df5c50 abeda8e7 7dcd9fe8 f13ba84f 115b548d` | all found | PASS |
| **CR-01-RESIDUAL: clear_close_on_exec uses format!()** | grep `format!` exec_strategy.rs:2759..2782 | **2 matches at lines 2763, 2774 (fcntl error paths)** | **FAIL — reachable from child arm at line 950** |
| **clear_close_on_exec called from post-fork child** | grep `clear_close_on_exec` exec_strategy.rs | **line 950 (in child arm), line 2759 (definition), line 3901 (test)** | **CONFIRMED reachable from child arm** |
| Linux runtime OOM kill | requires Linux host | SKIP — host-blocked |
| macOS RLIMIT_AS abort | requires macOS host | SKIP — host-blocked |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| REQ-RESL-NIX-01 | 25-01, 25-03, 25-04 | Linux cgroup v2 backends + traversal guard hardening | PARTIAL — source verified; runtime host-blocked; CR-01-RESIDUAL surfaces async-signal-safety gap in supervised path | CgroupSession + WR-03 guard verified; 4 "not enforced" warnings removed; runtime acceptance criteria 1–3 host-gated. The CR-01-RESIDUAL affects supervised execution path's child-error reporting, not the cgroup enforcement primitives themselves — kernel-level enforcement still works on the success path. |
| REQ-RESL-NIX-02 | 25-01, 25-03 | Linux wall-clock timeout via supervisor + cgroup.kill | PARTIAL — source verified; runtime host-blocked | spawn_linux_timeout_watchdog at exec_strategy.rs:114 writes "1\n" to cgroup.kill. Note: timeout_fired AtomicBool is set but never .load()'d (WR-C in 25-REVIEW-GAPS) — UX hole around the WR-04 watchdog-skip case. |
| REQ-RESL-NIX-03 | 25-01, 25-03, 25-04 | macOS setrlimit + cpu-percent rejected at parse + idiomatic errno + safe getpgid | PARTIAL — source verified; runtime host-blocked | MacosResourceLimits + parse_cpu_percent + WR-02 fail-closed + WR-04 safe match + WR-05 idiomatic conversion all verified. |
| REQ-AIPC-NIX-01 | 25-02 | AIPC Unix futures ADR | SATISFIED (unchanged) | Unchanged from initial verification. |

**Orphaned requirements:** None. All 4 phase requirements are claimed by plans and tracked above.

### Anti-Patterns Found (Updated from 25-REVIEW-GAPS.md)

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `crates/nono-cli/src/exec_strategy.rs` | 2759, 2763, 2774 | **CR-01-RESIDUAL**: clear_close_on_exec uses format!() on both fcntl error paths; reachable from post-fork child at line 950 | **BLOCKER** | The CR-01 fix's "zero allocation in child arm" goal is not actually achieved. The static-analysis test passes but the underlying allocator-mutex-deadlock primitive remains reachable. This is worse than the original CR-01 because a regression test now reports green over the defect. |
| `crates/nono-cli/tests/resl_nix_async_signal_safety.rs` | 47–79 | **WR-A**: find_child_branch_lines uses src.find() returning first match; two test-helper child arms at lines 3551 and 3647 are not statically guaranteed to remain trivial | WARNING | Fragile assumption — a future refactor that reorders or adds child branches before line 844 could silently start checking the wrong code region. |
| `crates/nono-cli/tests/resl_nix_async_signal_safety.rs` | 55–70 | **WR-B**: brace counting in find_child_branch_lines ignores string literals, char literals, raw strings, block comments | WARNING | Hypothetical today (verified that lines 844–1196 have no braces inside literals/comments) but one careless string-literal addition away from silently checking the wrong region. |
| `crates/nono-cli/src/exec_strategy.rs` and `supervisor_macos.rs` | exec_strategy.rs:833,1336,1355; supervisor_macos.rs:179 | **WR-C**: timeout_fired AtomicBool stored but never .load()'d; "inspect data" plumbing referenced in doc comments doesn't exist | WARNING | The user has no way to distinguish "child exited normally just before deadline" from "watchdog SIGKILL'd". Combined with WR-04 (watchdog skipped on getpgid failure), the user is silently told nothing. Pre-existing (predates 25-03/25-04), but the WR-04 fix makes it more visible. |
| `crates/nono-cli/src/exec_strategy/supervisor_linux.rs` | 1049–1052 | **WR-D**: `#[allow(dead_code)]` on `CgroupSession::disarm` violates CLAUDE.md "no dead code" rule. `disarm` is unreferenced anywhere in the workspace. | WARNING | CLAUDE.md § Lazy use of dead code: "Avoid `#[allow(dead_code)]`. If code is unused, either remove it or write tests that use it." Pre-existing (predates 25-03), but gap-closure work touched the same module — natural opportunity to address. |
| `crates/nono-cli/src/exec_strategy/supervisor_linux.rs` | ~1204–1212 | **IN-A**: place_self_in_cgroup_raw reads errno after libc::close() may have clobbered it | INFO | Minor diagnostic bug. Caller in post-fork child only checks is_err() and writes static MSG anyway. |
| `crates/nono-cli/tests/resl_nix_async_signal_safety.rs` | 147 | **IN-B**: cr_01_and_wr_02_const_msg_byte_strings_present asserts `count >= 11` but does not enforce per-name presence | INFO | Loose lower bound; a future commit removing one specific MSG_* would still pass if any 11 remain. |
| `crates/nono-cli/src/exec_strategy/supervisor_linux.rs` | 933–936 | **IN-C**: WR-03 traversal error message includes full abs_path via {abs_path:?}; standard advice is to log verbose path at debug level only | INFO | Diagnostic-cleanliness concern; attacker cannot exfiltrate anything new (they wrote /proc/self/cgroup themselves by hypothesis). |

### Human Verification Required (Unchanged from Initial Verification)

The following items remain pending — they require Linux or macOS host execution and cannot be verified on the current Windows host. They are tracked in `25-HUMAN-UAT.md` and will be closed via `/gsd-verify-work 25` on the appropriate host.

(See `human_verification:` section in frontmatter for the structured list — same six tests as the initial verification: Linux OOM kill, Linux fork limit, Linux timeout, Linux no-warning runtime check, macOS RLIMIT_AS, macOS cpu-percent clap rejection.)

### Gaps Summary

**One new gap surfaced by the gap-closure code review:**

- **CR-01-RESIDUAL**: The CR-01 fix is incomplete. The lexical region of `Ok(ForkResult::Child) => {` is now allocation-free, but `clear_close_on_exec` (called from line 950 inside the child arm) uses `format!()` on its fcntl error paths (lines 2763, 2774). The static-analysis regression test only inspects the lexical region, not the call graph, so it reports GREEN while the defect is reachable. This re-opens the original CR-01 allocator-mutex-deadlock primitive along the fcntl-failure code path.

  The deeper architectural inconsistency raised by 25-REVIEW-GAPS.md: the team accepted the threading-context argument for `Sandbox::apply()` (which DOES allocate by design) but rejected it for the original 9 `format!()` sites in the lexical region. Either the threading argument holds (and CR-01 was over-stated; the static MSG_* strings exist only as belt-and-suspenders diagnostic visibility) or it does not (and many more callees need hardening — including `clear_close_on_exec`). The current state is internally inconsistent; this needs an explicit decision documented in 25-03-SUMMARY.

**Bare-minimum fix to close CR-01-RESIDUAL without re-litigating the architectural question:**

Convert `clear_close_on_exec` to return `std::io::Result<()>` using `std::io::Error::last_os_error()` (which captures errno into a stack-resident `io::Error::Repr` for raw OS errors — does not allocate). This is the one helper that is reachable from the child error path *outside* the documented "Sandbox::apply allocates by design" exception (per 25-REVIEW-GAPS author's reading).

Strengthen `cr_01_no_format_macro_in_post_fork_child_branch` to either:
- (a) recursively scan the call graph from the child arm, OR
- (b) use sentinel comments (`// CR-01-CHILD-ARM-START` / `// CR-01-CHILD-ARM-END`) to scope the test region instead of brace counting, AND add a separate assertion that `clear_close_on_exec` body contains zero `format!()` calls.

**Six host-gated runtime UAT items remain pending** (unchanged from initial verification) — these are deferred to Linux/macOS CI, not goal-blocking gaps.

**Three pre-existing warnings (WR-A/WR-B/WR-C/WR-D)** surface fragility in the test scaffolding and a UX hole around the timeout_fired flag. Each is documented in Anti-Patterns above and should be addressed before the RESL-NIX work is considered production-ready, but none independently blocks goal achievement.

### Status Decision Rationale

- **Not `passed`**: A new BLOCKER (CR-01-RESIDUAL) was surfaced by the gap-closure code review. The async-signal-safety contract that CR-01 was supposed to establish is not actually met along the fcntl-failure code path.
- **Not `human_needed`** (alone): Even if no new criticals existed, the 6 host-gated UAT items would push status to `human_needed`. With a new BLOCKER on top, the more-restrictive `gaps_found` applies.
- **`gaps_found`**: Per Step 9 decision tree — any failed truth, missing artifact, or blocker anti-pattern → `gaps_found`. CR-01-RESIDUAL is a blocker.

The next gap-closure cycle should target CR-01-RESIDUAL (and ideally also resolve the architectural inconsistency about `Sandbox::apply` and other allocating helpers in the child arm). The 6 HUMAN-UAT items remain pending separately and continue to be tracked via `25-HUMAN-UAT.md`.

---

_Re-verified: 2026-05-10T23:30:00Z_
_Verifier: Claude (gsd-verifier)_
_Diff base: 70f06904 (post 25-03 + 25-04 + 25-REVIEW-GAPS landing)_
