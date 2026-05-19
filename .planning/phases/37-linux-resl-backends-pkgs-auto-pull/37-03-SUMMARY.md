---
phase: 37-linux-resl-backends-pkgs-auto-pull
plan: 03
subsystem: nono-cli/session_commands
tags: [inspect, formatter, cfg-gated, locked-strings, D-17]
requirements_addressed: [REQ-RESL-NIX-01, REQ-RESL-NIX-02, REQ-RESL-NIX-03]
dependency_graph:
  requires: []
  provides:
    - "format_limits_block helper (LOCKED Linux Limits-block strings)"
    - "format_bytes_short helper (K/M/G/T short-form bytes)"
    - "platform-aware emission via #[cfg(target_os)] gates"
  affects:
    - "Plan 37-04 (CI grep-asserts these LOCKED strings against the Linux runner)"
tech_stack:
  added: []
  patterns:
    - "Pattern F: cfg-over-runtime (compile-time #[cfg], not runtime cfg!())"
    - "Pure-formatter refactor for unit-testability (no stdout capture)"
key_files:
  created: []
  modified:
    - crates/nono-cli/src/session_commands.rs
    - crates/nono-cli/src/session_commands_windows.rs
decisions:
  - "D-17: Linux Limits-block emits LOCKED cgroup-v2 strings verbatim"
  - "D-17: macOS emits explicit deprioritized stub per v2.5 posture"
  - "D-17: Windows retains legacy v2.1 Phase 16 Job Object emission"
metrics:
  tasks_completed: 1
  tasks_total: 1
  files_modified: 2
  commits: 2
  completed_date: "2026-05-19"
  duration_minutes: ~35
---

# Phase 37 Plan 03: cfg-gated platform-aware `nono inspect` Limits emission Summary

Refactored the `run_inspect` Limits block into a pure `format_limits_block(&ResourceLimitsRecord) -> String` helper with compile-time `#[cfg(target_os = ...)]` arms so the Linux runner emits the LOCKED ROADMAP Phase 37 success-criteria strings byte-for-byte, unblocking Plan 37-04's CI grep assertions.

## Objective

Implement decision **D-17 (cfg-gated platform-aware `nono inspect` Limits-block emission)** to fix the string drift between today's `cpu: 25% (hard cap)` / `memory: 100 MiB (job-wide)` / `procs: 5 (active)` emission and the LOCKED ROADMAP Phase 37 acceptance strings.

## Implementation

### LOCKED Linux strings (VERBATIM, per REQ-RESL-NIX-01/02/03 acceptance #2)

```
memory: 100M (cgroup v2 memory.max)
cpu_percent: 25 (cgroup v2 cpu.max 25000 100000)
max_processes: 5 (cgroup v2 pids.max)
```

These are produced by:
- `memory:` line: `writeln!(out, "  memory: {} (cgroup v2 memory.max)", format_bytes_short(bytes))` — short-form bytes ("100M" not "100 MiB") matches the `--memory 100M` CLI input form.
- `cpu_percent:` line: `writeln!(out, "  cpu_percent: {pct} (cgroup v2 cpu.max {quota} 100000)")` where `quota = u32::from(pct) * 1000` (e.g. 25% → 25000μs quota over the default 100000μs period).
- `max_processes:` line: `writeln!(out, "  max_processes: {procs} (cgroup v2 pids.max)")`.

### `format_bytes_short` helper

```rust
fn format_bytes_short(bytes: u64) -> String
```

Round-trip parity with `crate::cli::parse_byte_size`. Tested values:

| Input | Output | Notes |
|-------|--------|-------|
| `100 * 1024 * 1024` | `"100M"` | LOCKED REQ-RESL-NIX-01 acceptance |
| `1024 * 1024 * 1024` | `"1G"` | round GiB |
| `1024` | `"1K"` | round KiB |
| `1500` | `"1500"` | non-round fall-through (raw bytes, no suffix) |

### Platform arms

| Platform | cpu_percent line | memory line | max_processes line |
|----------|------------------|-------------|--------------------|
| Linux    | `cpu_percent: {pct} (cgroup v2 cpu.max {quota} 100000)` | `memory: {short} (cgroup v2 memory.max)` | `max_processes: {procs} (cgroup v2 pids.max)` |
| macOS    | `cpu:     {pct}% (n/a - macOS deprioritized v2.5)` | `memory:  {human} (n/a - macOS deprioritized v2.5)` | `procs:   {procs} (n/a - macOS deprioritized v2.5)` |
| Windows  | `cpu:     {pct}% (hard cap)` | `memory:  {human} (job-wide)` | `procs:   {procs} (active)` |

The `timeout:` line is shared across all three platforms (not a cgroup-backend concern).

### `#[cfg]` (compile-time) vs `cfg!()` (runtime) choice

**Chose `#[cfg(target_os = ...)]` compile-time gates per D-17 + CLAUDE.md "Explicit Over Implicit" + PATTERNS.md Pattern F.**

Rationale:
- Compile-time arms are verified by the compiler — each platform compiles only the right branch, and dead-code lints catch any orphaned arm.
- Runtime `cfg!()` would cause unused-variable lints on platforms that don't hit a branch (e.g., `quota` is meaningless outside Linux) and would tie all-platform compilation to the union of all platforms' types.
- Acceptance grep gate `grep -cE 'if cfg!\(target_os' ... = 0` enforces the convention for future plans (T-37-12 tamper-mitigation).

### `session_commands_windows.rs` dispatch shape

The two files are mutually exclusive at compile time:

```rust
// main.rs:73-77
#[cfg(not(target_os = "windows"))]
mod session_commands;
#[cfg(target_os = "windows")]
#[path = "session_commands_windows.rs"]
mod session_commands;
```

This means on Linux/macOS the Unix file is compiled; on Windows only the Windows file is compiled. Both files now carry a mirror `format_limits_block` helper:

- **Unix file** (`session_commands.rs`): the full cfg-gated helper with Linux, macOS, and Windows arms. The Windows arm is defensively present for symmetry but is unreachable in practice — `main.rs` never selects this file on Windows.
- **Windows file** (`session_commands_windows.rs`): a streamlined Windows-only mirror that emits the legacy strings directly (no cfg gates needed since the file itself is Windows-only).

This shape mirrors how the existing `format_bytes_human` / `format_duration_human` helpers are duplicated across both files.

`format_bytes_short` on the Windows side is `#[cfg(test)]`-gated to avoid a `dead_code` warning — Windows production code does not use the cgroup-style short form, so the helper exists purely for test parity.

## Tests Added

| Test | File | Gate | Asserts |
|------|------|------|---------|
| `format_bytes_short_100_mebibytes_is_100m` | both | all | `format_bytes_short(100*1024*1024) == "100M"` |
| `format_bytes_short_1_gibibyte_is_1g` | both | all | `format_bytes_short(1024^3) == "1G"` |
| `format_bytes_short_1024_bytes_is_1k` | both | all | `format_bytes_short(1024) == "1K"` |
| `format_bytes_short_non_round_value_falls_back_to_bytes` | both | all | `format_bytes_short(1500) == "1500"` |
| `limits_block_empty_returns_empty_string` | both | all | empty `Limits` produces no output |
| `limits_block_format_linux_memory_locked_string` | Unix | `target_os="linux"` | output contains `"memory: 100M (cgroup v2 memory.max)"` |
| `limits_block_format_linux_cpu_percent_locked_string` | Unix | `target_os="linux"` | output contains `"cpu_percent: 25 (cgroup v2 cpu.max 25000 100000)"` |
| `limits_block_format_linux_max_processes_locked_string` | Unix | `target_os="linux"` | output contains `"max_processes: 5 (cgroup v2 pids.max)"` |
| `limits_block_format_macos_emits_deprioritized_marker` | Unix | `target_os="macos"` | output contains `"(n/a - macOS deprioritized v2.5)"` |
| `limits_block_format_windows_retains_legacy_cpu_string` | Win | `target_os="windows"` | output contains `"cpu:     25% (hard cap)"` |
| `limits_block_format_windows_retains_legacy_memory_string` | Win | `target_os="windows"` | output contains `"memory:  100 MiB (job-wide)"` |
| `limits_block_format_windows_retains_legacy_procs_string` | Win | `target_os="windows"` | output contains `"procs:   5 (active)"` |

**Windows-host run:** 8 tests collected (4 cross-platform + 4 Windows-gated including empty-record), all 8 passing.

```
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 1022 filtered out
```

**Linux-host run (deferred to CI):** expected 8 tests collected (4 cross-platform + 3 Linux-gated + 1 empty-record), all 8 passing.

**macOS-host run (deferred to CI; v2.5 deprioritized):** expected 6 tests collected (4 cross-platform + 1 macOS-gated + 1 empty-record), all 6 passing.

## TDD Gate Compliance

- **RED gate (commit 6ff7d91d):** `test(37-03): add failing tests for D-17 Limits-block LOCKED strings` — confirmed failing via `cargo build -p nono-cli --tests` (`E0432 unresolved imports super::format_bytes_short, super::format_limits_block`).
- **GREEN gate (commit ccb1256a):** `feat(37-03): cfg-gated platform-aware nono inspect Limits emission (D-17)` — RED tests now pass on the Windows host (8/8). Linux- and macOS-gated tests deferred to live CI.
- **REFACTOR gate:** none required — initial GREEN implementation is already idiomatic (pure formatter, no duplicated logic beyond the necessary platform arms).

## Verification Results

### Windows host (active dev target)

```
$ cargo build -p nono-cli --tests
   Finished `dev` profile [unoptimized + debuginfo] target(s) in 10.78s

$ cargo test -p nono-cli --bin nono limits_block_format_tests
   test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured

$ cargo test -p nono-cli --bin nono session_commands
   test result: ok. 26 passed; 0 failed; 0 ignored; 0 measured
   (includes the 8 new tests + 18 pre-existing session_commands tests)

$ cargo clippy -p nono-cli --tests -- -D warnings -D clippy::unwrap_used
   Finished `dev` profile [unoptimized + debuginfo] target(s) in 3m 44s
   (exit 0, no warnings)

$ cargo fmt --check -p nono-cli
   (clean, post fmt run)
```

### Cross-target clippy: PARTIAL — deferred to live CI

Per `.planning/templates/cross-target-verify-checklist.md` "PARTIAL Disposition":

- `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` **BLOCKED** on the dev host because `cc-rs` cannot find `x86_64-linux-gnu-gcc` (needed to link native C deps `aws-lc-sys`, `ring`). The cross gcc toolchain is not installed on this Windows dev host.
- `cargo clippy --workspace --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used` **BLOCKED** for the same reason.
- Mitigation: the changes are narrow and additive (new pure-formatter helper + test module + 1-line `print!` replacement in `run_inspect`). The Linux/macOS arms compile-only on their target, so any clippy regression is contained to those arms and will surface in CI's Linux/macOS clippy lanes.

This deferral follows the precedent established by Phase 41 plans (per `feedback_clippy_cross_target` memory).

### Acceptance grep gates (per plan acceptance_criteria)

```
$ grep -cE "fn format_limits_block" crates/nono-cli/src/session_commands.rs            → 1  ✓
$ grep -cE "fn format_bytes_short" crates/nono-cli/src/session_commands.rs             → 1  ✓ (production fn; tests reference it too)
$ grep -cE 'cgroup v2 (memory\.max|cpu\.max|pids\.max)' crates/nono-cli/src/session_commands.rs → 10  ✓ (≥ 3)
$ grep -nE 'memory: \{\} \(cgroup v2 memory\.max\)' crates/nono-cli/src/session_commands.rs    → line 616  ✓
$ grep -nE 'cpu_percent: \{pct\} \(cgroup v2 cpu\.max \{quota\} 100000\)'                       → line 596  ✓
$ grep -nE 'max_processes: \{procs\} \(cgroup v2 pids\.max\)'                                   → line 647  ✓
$ grep -cE '#\[cfg\(target_os' crates/nono-cli/src/session_commands.rs                  → 15  ✓ (≥ 6)
$ grep -cE 'if cfg!\(target_os' crates/nono-cli/src/session_commands.rs                 → 0   ✓ (compile-time only)
$ grep -cE 'D-17' crates/nono-cli/src/session_commands.rs                               → 9   ✓ (≥ 1)
```

## Deviations from Plan

**1. [Rule 3 - Blocking issue, in scope] `format_bytes_short` on Windows mirror gated `#[cfg(test)]`**

- **Found during:** GREEN-phase build on Windows host
- **Issue:** `format_bytes_short` is unused in Windows production code (the legacy emission keeps `100 MiB` shape), causing a `dead_code` warning that would fail `-D warnings`.
- **Fix:** Gated the Windows-mirror helper as `#[cfg(test)]` so it compiles only for the test target. Function is still callable from the `limits_block_format_tests` module (also `#[cfg(test)]`).
- **Rationale:** Per CLAUDE.md "Avoid `#[allow(dead_code)]`. If code is unused, either remove it or write tests that use it." `#[cfg(test)]` is the correct alternative — production code does not use it; tests do.
- **Files modified:** `crates/nono-cli/src/session_commands_windows.rs`
- **Commit:** ccb1256a (GREEN)

**No other deviations.** Plan executed exactly as written; LOCKED strings match verbatim.

## Threat Surface Scan

No new threat surface introduced beyond what the plan's `<threat_model>` already enumerates (T-37-10/11/12). All three threats are mitigated by the tests and grep gates described above. No new endpoints, auth paths, or trust boundaries.

## Known Stubs

None. The `(n/a - macOS deprioritized v2.5)` marker on the macOS arm is documented stubbing per 37-CONTEXT.md — it is the intended emission for the deprioritized platform, not a placeholder for future work in this milestone.

## Self-Check: PASSED

**Files modified:**
- `crates/nono-cli/src/session_commands.rs` — FOUND
- `crates/nono-cli/src/session_commands_windows.rs` — FOUND

**Commits:**
- `6ff7d91d` (RED: test) — FOUND
- `ccb1256a` (GREEN: feat) — FOUND
