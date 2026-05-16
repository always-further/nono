---
status: complete
quick_id: 260516-mxw
slug: fix-handletarget-import-linux
type: quick
date: 2026-05-16
commit: 3c1ddc40
files_changed: 1
files_list:
  - crates/nono-cli/src/exec_strategy.rs
lines_changed: "+1 / -1"
verification:
  host_cargo_check: pass
  grep_assertions: pass
  ci_re_run_required: true
  pr: 922
cross_link:
  memory: feedback_clippy_cross_target
  phase: 41
  plan: 41-01
  ci_run_id: 25970910911
---

# Quick 260516-mxw — Fix HandleTarget Import Path (Linux/macOS Regression)

## What Was Fixed

Single-line surgical edit at `crates/nono-cli/src/exec_strategy.rs:2634` inside
the body of the `request_path()` helper introduced by Phase 41 Plan 41-01:

```diff
 fn request_path(request: &nono::CapabilityRequest) -> &std::path::Path {
-    use nono::HandleTarget;
+    use nono::supervisor::HandleTarget;
     match &request.target {
         Some(HandleTarget::FilePath { path }) => path.as_path(),
         _ => {
             #[allow(deprecated)]
             { &request.path }
         }
     }
 }
```

Net change: +1 / -1 lines in one file. No other file in the workspace touched.

## Why (Root Cause)

The `nono` library has TWO re-export surfaces for supervisor types:

1. **`nono::supervisor::*`** (crates/nono/src/supervisor/mod.rs:50-64) — re-exports
   the full set including `HandleTarget`, `HandleKind`, `PipeDirection`, etc.
2. **`nono::*` (crate-root top-level)** (crates/nono/src/lib.rs:102-107) — a
   curated subset for ergonomic consumer use. `HandleTarget` is **intentionally
   omitted** from this list.

Plan 41-01 introduced `use nono::HandleTarget;` (top-level path) instead of the
correct `use nono::supervisor::HandleTarget;` (namespaced path). The Windows-host
local verification did not catch this because:

- `cargo check` on Windows compiled `exec_strategy.rs` under `#[cfg(windows)]`
  branches that may not exercise the broken `use` statement at the same call-graph
  resolution stage.
- The Phase 41 close-gate verifier marked REQ-CI-01 VERIFIED on grep evidence
  alone and explicitly SKIPPED cross-target Linux clippy.

Linux/macOS CI on PR #922 run `25970910911` correctly surfaced:

```
error[E0432]: unresolved import 'nono::HandleTarget'
  --> crates/nono-cli/src/exec_strategy.rs:2634
```

Failed lanes: `Test(ubuntu-latest)`, `Test(macos-latest)`, `Clippy(macos-latest)`.

## Verification

### Grep Assertions (from plan `<acceptance_criteria>`)

| Check | Expected | Actual | Result |
|---|---|---|---|
| `use nono::supervisor::HandleTarget;` occurrences | 1 | 1 | PASS |
| `use nono::HandleTarget;` occurrences | 0 | 0 | PASS |
| `HandleTarget::FilePath` match arm occurrences | 1 | 1 | PASS |
| `request_path(` occurrences (1 def + 14 calls) | 15 | 15 | PASS |

### Host Compile Check

`cargo check --workspace --all-targets` on Windows host:

```
Checking nono v0.53.0
Compiling nono-cli v0.53.0
Compiling nono-ffi v0.53.0
Checking nono-proxy v0.53.0
Checking nono-shell-broker v0.53.0
Finished `dev` profile [unoptimized + debuginfo] target(s) in 20.47s
```

Result: **PASS** (no errors; only a pre-existing unrelated "nono-shell-broker
missing lib target" warning, which is a workspace dependency-target shape issue
introduced by prior phases and out of scope for this quick fix).

### Linux/macOS Verification — Deferred to CI

Local cross-target verification was NOT run (no Linux/macOS host available and
no docker cross-build infrastructure on this Windows box). Authoritative
verification is the next CI run on PR #922 after this commit is pushed. The
specific signal to watch: `Test(ubuntu-latest)`, `Test(macos-latest)`, and
`Clippy(macos-latest)` lanes must clear the name-resolution stage (i.e. the
original `E0432` is gone).

## Lesson Reinforced

This regression reinforces the existing memory entry
**`feedback_clippy_cross_target`** (originally captured from the Phase 25 CR-A
regression):

> Windows-host `cargo clippy --workspace` cannot catch unused-import or
> unresolved-import drift inside `#[cfg(target_os = "linux"|"macos")]` blocks or
> in files heavily gated for Unix. Run `cargo clippy --workspace --target
> x86_64-unknown-linux-gnu --all-targets -- -D warnings` for any plan that
> touches cross-platform code paths.

Phase 41 verification accepted REQ-CI-01 on grep evidence alone, skipping
cross-target Linux clippy because the Windows host could not run it natively.
The lesson is now twice-reinforced: future close-gate verifiers should either
(a) wait for CI to confirm Linux/macOS lanes before marking REQ-CI-01 VERIFIED,
or (b) require docker-based cross-target clippy for plans touching shared
(non-cfg-gated) code in files containing heavy Unix `cfg` regions.

## Files Changed

| File | Lines | Description |
|---|---|---|
| `crates/nono-cli/src/exec_strategy.rs` | +1 / -1 | Namespaced `HandleTarget` import |

## Commits

| SHA | Message |
|---|---|
| `3c1ddc40` | `fix(quick/260516-mxw): import HandleTarget from nono::supervisor (Phase 41 regression)` |
| (pending) | `docs(quick/260516-mxw): record SUMMARY for HandleTarget import fix` |

## Next

1. Commit this SUMMARY.md with DCO sign-off.
2. Push the branch updating PR #922.
3. Watch CI run for the green signal on `Test(ubuntu-latest)`,
   `Test(macos-latest)`, and `Clippy(macos-latest)` lanes.
4. If CI is green: PR #922 is unblocked for re-review.
5. If CI surfaces a different error: that is a new regression, not this one;
   open a follow-up quick or debug task.

## Cross-Links

- **Memory:** `feedback_clippy_cross_target` (Phase 25 CR-A regression lesson)
- **Phase 41 Plan 41-01:** introduced the broken import
- **PR #922:** the umbrella upstream PR this fix unblocks
- **CI Run 25970910911:** original failure surface for `E0432`

## Self-Check: PASSED

- File `crates/nono-cli/src/exec_strategy.rs` exists and contains
  `use nono::supervisor::HandleTarget;` at line 2634 (verified).
- Commit `3c1ddc40` exists on `main` (verified via `git log` / `git rev-parse`).
- All four plan `<acceptance_criteria>` grep assertions pass.
- `cargo check --workspace --all-targets` exited 0 on Windows host.
