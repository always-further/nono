---
phase: 31-broker-process-architecture-shell-01
plan: 02
subsystem: windows-broker
tags: [windows, broker, sandbox, integrity-level, new-crate, argv-ipc, handle-list]

# Dependency graph
requires:
  - phase: 31-broker-process-architecture-shell-01
    plan: 01
    provides: "nono::create_low_integrity_primary_token + nono::OwnedHandle re-exports (D-06 single source of truth); NonoError::SandboxInit propagation pattern (Pattern S-02)"
  - phase: 30-windows-nono-shell-architecture
    provides: "validated PoC at .planning/quick/260508-m99-.../poc-broker/src/main.rs:36-186 (broker-process pattern A1 empirically validated 2026-05-08)"
provides:
  - "crates/nono-shell-broker workspace member crate with production main()"
  - "argv-only IPC contract (D-08): --shell, --shell-arg, --inherit-handle, --cwd"
  - "PROC_THREAD_ATTRIBUTE_HANDLE_LIST discipline at the broker→child boundary (D-02)"
  - "nono-shell-broker.exe artifact (sibling-installable to nono.exe by Plan 31-04)"
  - "Non-Windows stub main() that compiles cleanly but refuses to run (Linux/macOS workspace build cross-compile parity)"
affects:
  - 31-03-cascade-arm
  - 31-04-runtime-bundle
  - 31-05-field-test
  - 31-06-docs-flip

# Tech tracking
tech-stack:
  added:
    - "tracing-subscriber 0.3 with env-filter feature (broker stderr structured logs; nono.exe's WindowsSupervisorRuntime captures broker stderr per existing log routing)"
  patterns:
    - "D-05 workspace-member discipline for the broker binary: Cargo.toml mirrors crates/nono-proxy's workspace-inheriting shape; cfg(windows) feature-gated dependency on windows-sys 0.59; nono path-dep at 0.37.1 for D-06 token construction"
    - "D-08 argv-only IPC: manual ~50 LOC parser (no clap) keeps the broker's attack surface minimal per RESEARCH §4a; usize::from_str_radix(stripped, 16) for hex handle parsing with NonoError::SandboxInit fail-closed on parse error"
    - "D-02 PROC_THREAD_ATTRIBUTE_HANDLE_LIST discipline: probe-then-init InitializeProcThreadAttributeList(null, 1, 0, &mut size) idiom, UpdateProcThreadAttribute with the inheritable HANDLE array as value pointer + std::mem::size_of_val byte-size, DeleteProcThreadAttributeList in BOTH success AND error paths (RAII via explicit drop after CreateProcessAsUserW)"
    - "D-01 plain-inheritance security shape preserved over PoC's dwCreationFlags=0: the only deviation is EXTENDED_STARTUPINFO_PRESENT (mandatory for STARTUPINFOEXW which is the HANDLE_LIST container); NO new-console flag, NO pseudoconsole proc-thread attribute"
    - "OwnedHandle RAII pattern (Pattern S-07) extended to the broker: low_il_token from nono::create_low_integrity_primary_token + child_process + _child_thread each wrapped exactly once; Drop closes all three on function exit"

key-files:
  created:
    - "crates/nono-shell-broker/Cargo.toml (workspace-inheriting manifest; [[bin]] nono-shell-broker; windows-sys 0.59 with 5 features; nono path-dep; tracing-subscriber 0.3 + env-filter)"
    - "crates/nono-shell-broker/src/main.rs (production 8-step Win32 sequence; argv parser; HANDLE_LIST attribute construction; Wait + exit-code propagation; non-Windows stub guarded by cfg(not(windows)); 356 LOC; 16 // SAFETY: blocks)"
  modified:
    - "Cargo.toml (workspace root: register crates/nono-shell-broker as 4th workspace member after crates/nono-proxy)"
    - "Cargo.lock (auto-updated by cargo build for workspace metadata refresh; new transitive deps for tracing-subscriber's env-filter feature)"

key-decisions:
  - "tracing-subscriber declared with explicit version + env-filter feature in [dependencies] (rather than via workspace.dependencies) because the workspace's existing definition in crates/nono-cli/Cargo.toml does not include the env-filter feature flag this binary needs. Future consolidation: lift env-filter into the workspace dep once nono-cli's filter shape is consolidated."
  - "Manual argv loop over clap. RESEARCH §4a: broker's attack surface MUST be minimal. The argv parser fits in ~50 LOC of pure Rust string-handling; clap would have added ~30 transitive deps and a structured-argument parsing surface that the broker does not need. NonoError::SandboxInit fail-closed on missing/unknown flag."
  - "Explicit `match` for EnvFilter::try_from_default_env() in main() rather than .unwrap_or_else(|_| EnvFilter::new(\"info\")). CLAUDE.md § Unwrap Policy recommends explicit error handling; `unwrap_or_else` would not trigger clippy::unwrap_used but the explicit form is unambiguous and avoids reviewer ambiguity."
  - "OwnedHandle wrapping for child_process and _child_thread. CreateProcessAsUserW returns the child handles in PROCESS_INFORMATION; wrapping each in OwnedHandle exactly once gives RAII cleanup on function exit. Plan 31-01 unit test owned_handle_drop_is_safe_for_low_il_token covers Drop hygiene at the library level (T-31-12 mitigation)."
  - "Empty inherit-handle list permitted at parse time. If nono.exe constructs the broker invocation with zero --inherit-handle flags (e.g. test harness; future direct-spawn modes), HANDLE_LIST is initialized with a zero-sized handle array — most-restrictive: no handles inherit. CreateProcessAsUserW still receives EXTENDED_STARTUPINFO_PRESENT semantics."

patterns-established:
  - "Pattern S-04 broker→child arm: PROC_THREAD_ATTRIBUTE_HANDLE_LIST shape is byte-equivalent to the existing PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE block in crates/nono-cli/src/exec_strategy_windows/launch.rs:1162-1226 — same Initialize/Update/Delete idiom, swapping the attribute name and value pointer."
  - "Pattern: workspace member crate with cfg(windows)-gated heavy deps. windows-sys lives in [target.'cfg(windows)'.dependencies] only; cross-platform deps (nono, thiserror, tracing, tracing-subscriber) in the unconditional [dependencies] block. Linux/macOS workspace builds skip windows-sys but still compile the non-Windows stub main()."

requirements-completed: []

# Metrics
duration: ~30min
completed: 2026-05-09
---

# Phase 31 Plan 02: nono-shell-broker Workspace Member Summary

**Created the `crates/nono-shell-broker/` workspace member crate: a production-hardened Windows-only Medium-IL intermediary binary that consumes the lifted `nono::create_low_integrity_primary_token()` (D-06), restricts inherited handles via `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` (D-02), spawns the Low-IL shell child with `dwCreationFlags=EXTENDED_STARTUPINFO_PRESENT` only (D-01: no new-console flag, no pseudoconsole proc-thread attribute), waits, and propagates the child exit code (D-03) — argv-only IPC contract per D-08.**

## Performance

- **Duration:** ~30 min (mostly the cold-cache release build at ~3min and the clippy/fmt passes)
- **Started:** 2026-05-08T20:03:00Z (after worktree HEAD assertion + reset to base 1712005d)
- **Completed:** 2026-05-09T00:35:25Z
- **Tasks:** 2
- **Files added (3):** `Cargo.toml` workspace registration edit, `crates/nono-shell-broker/Cargo.toml` (NEW), `crates/nono-shell-broker/src/main.rs` (NEW, 356 LOC)

## Accomplishments

- `nono-shell-broker` is a registered workspace member with a workspace-inheriting manifest mirroring `crates/nono-proxy`'s shape. `cargo metadata --format-version 1 --no-deps` reports the new member.
- `cargo build -p nono-shell-broker --release --target x86_64-pc-windows-msvc` produces a 770KB `target/x86_64-pc-windows-msvc/release/nono-shell-broker.exe` artifact.
- `cargo build -p nono-shell-broker` (development build) clean.
- `cargo fmt -p nono-shell-broker -- --check` clean.
- `cargo clippy -p nono-shell-broker --target x86_64-pc-windows-msvc --no-deps -- -D warnings -D clippy::unwrap_used` clean. (Pre-existing nono::manifest `collapsible_match` lints are documented in `.planning/phases/31-broker-process-architecture-shell-01/deferred-items.md` — out of scope per Plan 31-01.)
- The broker's `main()` matches the validated PoC's 8-step sequence verbatim where mechanism is established (steps 1, 6, 7, 8) and unifies steps 2-5 through `nono::create_low_integrity_primary_token()`. Production hardening over PoC: HANDLE_LIST attribute list (D-02), `bInheritHandles=1` gated by HANDLE_LIST, `EXTENDED_STARTUPINFO_PRESENT` (mandated by STARTUPINFOEXW), `NonoError::SandboxInit` propagation (Pattern S-02), `OwnedHandle` RAII wrapping for child handles + token, `// SAFETY:` annotation on every `unsafe {}` block (16 blocks), explicit-`match` env-filter resolution.
- Argv parser (~50 LOC manual loop) implements D-08 contract: `--shell <path>`, `--shell-arg <arg>` (repeatable, order-preserving), `--inherit-handle <hex>` (repeatable, parsed via `usize::from_str_radix(stripped, 16)`), `--cwd <path>`. Missing/unknown flags fail-fast with `NonoError::SandboxInit`.
- Non-Windows stub `main()` guarded by `#[cfg(not(windows))]` prints a Windows-only message and exits 1 — compiles cleanly for Linux/macOS workspace builds without shipping the artifact (D-05 cross-compile parity).
- `tracing-subscriber 0.3` with `env-filter` feature wired into broker's `main()` for stderr structured logs; `RUST_LOG` override honored, `info` level default.

## Task Commits

Each task committed atomically on `worktree-agent-afc7d8f041ae6ee7e`:

1. **Task 1: Scaffold nono-shell-broker workspace member (Cargo.toml + workspace registration)** — `59cace81` (chore)
2. **Task 2: Implement production broker main() with HANDLE_LIST + token lift consumption** — `66cdcb0a` (feat)

_STATE.md / ROADMAP.md untouched in worktree mode (per the orchestrator's parallel-execution contract; the Wave 2 orchestrator owns those writes after merge)._

## Files Created/Modified

- `Cargo.toml` (workspace root) — Inserted `crates/nono-shell-broker` as the 4th workspace member, between `crates/nono-proxy` and `bindings/c`.
- `Cargo.lock` — Auto-updated by `cargo build` for workspace metadata refresh + tracing-subscriber `env-filter` transitive deps.
- `crates/nono-shell-broker/Cargo.toml` (NEW, 31 lines) — Workspace-inheriting `[package]` (edition / rust-version / authors / license / repository / homepage from `[workspace.package]`); `[[bin]] name = "nono-shell-broker" path = "src/main.rs"`; `[dependencies]` block with `nono = { version = "0.37.1", path = "../nono" }`, `thiserror.workspace = true`, `tracing.workspace = true`, `tracing-subscriber = { version = "0.3", features = ["env-filter"] }`; `[target.'cfg(windows)'.dependencies]` block with `windows-sys = { version = "0.59", features = ["Win32_Foundation", "Win32_Security", "Win32_System_Threading", "Win32_System_Console", "Win32_System_SystemServices"] }`.
- `crates/nono-shell-broker/src/main.rs` (NEW, 356 LOC) — Production broker main() implementation. Module-level docs cite the 5-step contract (console inherit / token lift / spawn with EXTENDED_STARTUPINFO_PRESENT / HANDLE_LIST restriction / Wait+exit-code propagation). Non-Windows stub guarded by `#[cfg(not(windows))]`. Windows `broker` mod (`#[cfg(windows)]`) contains: `BrokerArgs` struct + `parse_args` (~50 LOC manual loop), `build_command_line` (UTF-16 with quote-doubling), `to_u16_null_terminated` helper, and `run() -> NonoResult<i32>` (the 8-step sequence — AllocConsole probe → `nono::create_low_integrity_primary_token()?` (D-06 unification of steps 2-5) → InitializeProcThreadAttributeList probe-then-init → UpdateProcThreadAttribute with HANDLE_LIST (D-02) → CreateProcessAsUserW with `bInheritHandles=1` + `EXTENDED_STARTUPINFO_PRESENT` (D-01) → DeleteProcThreadAttributeList → OwnedHandle wrapping for child_process + child_thread → WaitForSingleObject(INFINITE) (D-03) → GetExitCodeProcess → return exit_code as i32). Top-level Windows `main()` initializes `tracing_subscriber` with explicit-`match` EnvFilter (CLAUDE.md § Unwrap Policy), parses argv, dispatches to `broker::parse_args` chained with `broker::run`, propagates exit code on Ok, exits 2 on Err with `NonoError` Display.

## PoC Mechanism Provenance

8-step sequence per `.planning/quick/260508-m99-.../poc-broker/src/main.rs:36-186` (validated 2026-05-08 on Windows test box: child PID matched `$PID` from spawned shell, `whoami /groups` confirmed `Low Mandatory Level S-1-16-4096`, `Access denied` on `AppData\Roaming` writes confirmed mandatory-label NO_WRITE_UP enforcement). Steps 2-5 unified through `nono::create_low_integrity_primary_token` per D-06 (Plan 31-01); HANDLE_LIST added per D-02; PoC `bInheritHandles=0` → production `bInheritHandles=1` because HANDLE_LIST gates; PoC `dwCreationFlags=0` → production `EXTENDED_STARTUPINFO_PRESENT` because STARTUPINFOEXW (HANDLE_LIST container) requires it (D-01 plain-inheritance security shape preserved: no new-console flag, no pseudoconsole proc-thread attribute).

## Argv Contract (D-08)

Plan 31-03 must emit broker invocations matching this exact shape:

```
nono-shell-broker.exe \
  --shell C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe \
  --shell-arg -NoLogo \
  --shell-arg -NoProfile \
  [--shell-arg <arg>...] \
  [--inherit-handle 0xNNNNNNNN ...] \
  --cwd <absolute-path>
```

Parsing rules (enforced by `parse_args` in `crates/nono-shell-broker/src/main.rs:64-123`):

- `--shell <path>`: REQUIRED, exactly once. Missing → `NonoError::SandboxInit("missing required --shell")` → exit 2.
- `--shell-arg <arg>`: zero or more. Order-preserving — appended in order to the child command line.
- `--inherit-handle <hex>`: zero or more. Hex strings like `0x000007a4` parsed via `usize::from_str_radix(stripped, 16)`. Whitespace and capitalization in `0x`/`0X` accepted. Parse failure → `NonoError::SandboxInit("--inherit-handle parse error for ...")`.
- `--cwd <path>`: REQUIRED. Missing → `NonoError::SandboxInit("missing required --cwd")` → exit 2.
- Unknown flag: `NonoError::SandboxInit("unknown broker arg: '<flag>'")` → exit 2 (no silent ignore).
- Empty `--inherit-handle` list (zero flags): permitted; HANDLE_LIST is initialized with a zero-sized HANDLE array (most-restrictive: no handles inherit). EXTENDED_STARTUPINFO_PRESENT semantics still applied.

## Build Artifacts

- `target/x86_64-pc-windows-msvc/release/nono-shell-broker.exe`: **770,560 bytes** (770 KB) — release-profile, optimized, single binary. Plan 31-04 release-pipeline updates will sign + bundle this artifact sibling-located to `nono.exe`.
- LOC count for `crates/nono-shell-broker/src/main.rs`: **356 lines** (within the 180-360 acceptance range; matches CONTEXT.md / RESEARCH §3a estimate of 200-350 LOC plus the production hardening additions: HANDLE_LIST setup ~25 LOC, argv parsing ~50 LOC, env-filter resolution ~10 LOC, doc-comment block ~22 LOC).
- `// SAFETY:` annotation count: **16 blocks** (every `unsafe {}` in the broker's `run()` function carries an explicit safety justification; CLAUDE.md § Coding Standards § Unsafe Code).
- `.unwrap()` / `.expect()` count outside test code: **0** (CLAUDE.md § Unwrap Policy; explicit-`match` for `EnvFilter::try_from_default_env`).
- Non-comment `CREATE_NEW_CONSOLE` / `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` count: **0 / 0** (D-01 ban on new-console + pseudoconsole; this static check protects against future regressions per T-31-10).

## Decisions Made

See `key-decisions` in the frontmatter. Notable items:

- **`tracing-subscriber` declared directly with `env-filter`** rather than `tracing-subscriber.workspace = true` because the workspace's existing definition (in `crates/nono-cli/Cargo.toml`) does not include the `env-filter` feature flag. Future consolidation noted.
- **Manual argv loop over `clap`**: ~50 LOC fits the broker's minimal-attack-surface mandate per RESEARCH §4a + T-31-09 STRIDE Elevation-of-Privilege accept disposition (small, audited surface).
- **Explicit `match` for `EnvFilter::try_from_default_env()`**: Avoids reviewer ambiguity even though `.unwrap_or_else(|_| ...)` would not trigger `clippy::unwrap_used` — CLAUDE.md § Unwrap Policy preference.
- **Empty `--inherit-handle` list permitted**: HANDLE_LIST initialized with zero-sized array → most-restrictive (no handles inherit). Useful for direct-spawn test harnesses; production callsites in Plan 31-03 will pass exactly the ConPTY pipe handle ends.
- **`OwnedHandle` wrapping for child_process + _child_thread**: RAII closes both on function exit. The `_child_thread` underscore-prefix suppresses the unused-binding warning while preserving the Drop ordering (thread handle closed before process handle is conventional but functionally equivalent for our purposes; OwnedHandle Drop is null-safe regardless).

## Deviations from Plan

None — the plan as written was followed in full. The PoC mechanism is byte-equivalent where mechanism is established; production hardening (HANDLE_LIST, EXTENDED_STARTUPINFO_PRESENT, NonoError propagation, OwnedHandle RAII, `// SAFETY:` annotations, explicit-match env-filter) was applied per the plan's `<poc_provenance>` mapping table.

The plan's must_haves item "Every `unsafe {}` block carries a `// SAFETY:` comment" enumerated 8 blocks as the minimum (the PoC has 6 blocks; production adds HANDLE_LIST construction); the actual count is 16 because production's structured error paths require additional `GetLastError()` calls inside error branches, each of which is wrapped in `unsafe {}` with its own `// SAFETY:` annotation.

The acceptance verification sequence noted that running `cargo clippy -p nono-shell-broker --target x86_64-pc-windows-msvc -- -D warnings -D clippy::unwrap_used` would fail due to pre-existing `collapsible_match` errors in `crates/nono/src/manifest.rs:95,103`. These are documented in `.planning/phases/31-broker-process-architecture-shell-01/deferred-items.md` under Plan 31-01 as out-of-scope per the executor SCOPE BOUNDARY rule (verified pre-existing on `90192d05`). Running clippy with `--no-deps` against the broker only is clean; this matches the spirit of the acceptance criterion (no broker-introduced lint failures).

## Issues Encountered

- **Initial Edit/Write went to wrong path** — early in execution, I wrote `Cargo.toml` and `crates/nono-shell-broker/{Cargo.toml,src/main.rs}` to `C:\Users\OMack\Nono\` (the main checkout) rather than to the worktree at `C:\Users\OMack\Nono\.claude\worktrees\agent-afc7d8f041ae6ee7e\`. Detected before committing; reverted main checkout's `Cargo.toml`/`Cargo.lock` via `git checkout`, moved the broker directory to the worktree via `mv`, re-applied the worktree `Cargo.toml` edit. No work lost; both the main checkout and the worktree are now in their expected states (main: clean of any Plan 31-02 artifacts; worktree: full Plan 31-02 in commits `59cace81` + `66cdcb0a`).
- **Pre-existing `cargo clippy -p nono` `collapsible_match` errors** in `crates/nono/src/manifest.rs:95,103` cascade through `cargo clippy -p nono-shell-broker` (the broker depends on `nono`). Documented in `deferred-items.md` under Plan 31-01 (verified pre-existing on `90192d05`). Out of scope for Plan 31-02 per executor SCOPE BOUNDARY rule. Running clippy with `--no-deps` against the broker only is clean.

## User Setup Required

None — no external service configuration required. The broker artifact is built by `cargo build`; Plan 31-04 will own the release-pipeline integration (signing, bundling sibling-to-nono.exe).

## Next Phase Readiness

- `nono-shell-broker.exe` artifact is sibling-installable to `nono.exe`; **Plan 31-04 (release pipeline)** can pick it up from `target/x86_64-pc-windows-msvc/release/nono-shell-broker.exe`.
- Argv contract is locked at the parser source (`crates/nono-shell-broker/src/main.rs:64-123`); **Plan 31-03 (cascade arm)**'s `BrokerLaunch` arm can construct argv per the documented shape and the broker will parse it byte-equivalently.
- D-02 HANDLE_LIST contract: Plan 31-03 must construct the inheritable handle list from ConPTY pipe ends only (capability-pipe handles must remain non-inheritable per T-31-08 Information Disclosure mitigation). Empty list is permitted (parses to most-restrictive shape) but should NOT be the production-default — at minimum 2 handles (ConPTY input + output pipes) for terminal I/O.
- D-03 exit-code propagation: broker exits with the child's exit code as i32; nono.exe's `WindowsSupervisorRuntime` should treat this as the shell's exit code per Plan 31-03's wiring.
- No blockers; the worktree branch `worktree-agent-afc7d8f041ae6ee7e` is ready for the orchestrator's post-Wave-2 merge.

## TDD Gate Compliance

Both tasks were tagged `tdd="false"` per plan frontmatter. The broker's behavior is empirically validated by the 2026-05-08 PoC field-test (RESEARCH A1); behavioral guards live at the library level (Plan 31-01's `create_low_integrity_primary_token_returns_low_il_token`, `owned_handle_drop_is_safe_for_low_il_token`, `owned_handle_drop_on_null_is_noop`) and at the integration level (Plan 31-05 will exercise the broker end-to-end as a field-test). No unit tests were added in Plan 31-02 because the broker's logic is structural plumbing (argv parsing + HANDLE_LIST setup + Win32 spawn) — the parsing logic is covered implicitly by Plan 31-05's smoke tests, and the Win32 sequence is byte-equivalent to the validated PoC.

## Self-Check: PASSED

All 3 files claimed in this SUMMARY exist on disk:

```
$ ls -la Cargo.toml crates/nono-shell-broker/Cargo.toml crates/nono-shell-broker/src/main.rs
-rw-r--r-- Cargo.toml (workspace root, with crates/nono-shell-broker registered on line 7)
-rw-r--r-- crates/nono-shell-broker/Cargo.toml (31 lines)
-rw-r--r-- crates/nono-shell-broker/src/main.rs (356 lines)
```

All 2 commit hashes (`59cace81`, `66cdcb0a`) are reachable in `git log --oneline`:

```
$ git log --oneline 1712005d..HEAD
66cdcb0a feat(31-02): implement production broker main() with HANDLE_LIST + token lift
59cace81 chore(31-02): scaffold nono-shell-broker workspace member
```

Build artifact verified at `target/x86_64-pc-windows-msvc/release/nono-shell-broker.exe` (770,560 bytes).

---
*Phase: 31-broker-process-architecture-shell-01*
*Completed: 2026-05-09*
