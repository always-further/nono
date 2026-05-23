---
phase: quick-260523-moe
plan: 01
subsystem: ci
tags: [phase-37, resl, pkgs-04, clippy, ignore, test-hygiene, REQ-CI-FU-01]
dependency_graph:
  requires:
    - .planning/debug/phase-37-post-fix-runtime.md  # source-of-truth for BUG-A + BUG-B
  provides:
    - "Phase 37 RESL-NIX cross-target Linux clippy gate passes (no clippy::unwrap_used violation at profile_cmd.rs:3836)"
    - "Phase 37 PKGS-04 auto_pull_e2e_linux test suite no longer reports 3 runtime failures — 3 protocol-mismatched tests are skipped via #[ignore], 3 passing tests still run and pass"
    - "Future developer running `cargo test` and seeing the ignored tests can locate the deferred follow-up context via the #[ignore] reason string (which names .planning/debug/phase-37-post-fix-runtime.md)"
  affects:
    - .planning/STATE.md "### Phase 46 — Resume Preconditions" item 2 (Phase 37 RESL failing dispatches)
tech_stack:
  added: []
  patterns:
    - "Use #[allow(clippy::unwrap_used)] on the `mod tests { ... }` declaration to cover all unwrap()/expect()/unwrap_err() calls in the test module (matches workspace-wide convention used by 14 other test modules)"
    - "Use #[ignore = \"<reason>\"] with a single-line reason string that names the debug doc path + req-tracking ID so a developer reading `cargo test --list` output can find the rewrite-tracking context"
key_files:
  created: []
  modified:
    - crates/nono-cli/src/profile_cmd.rs
    - crates/nono-cli/tests/auto_pull_e2e_linux.rs
decisions:
  - "Defer BUG-A (mock/production protocol mismatch) rewrite via #[ignore] rather than fix in place: production code (registry client, fixture pack, mock server helper) untouched; rewrite tracked under REQ-CI-FU-01 follow-up phase"
  - "Use #[allow(clippy::unwrap_used)] on the test module rather than rewriting `result.unwrap_err()` to `expect_err(...)`: workspace convention (14 sibling test modules use the allow-attribute), and the unwrap_err call is the ONLY unprotected site in the workspace per the debug-doc audit"
  - "Shared single-line #[ignore] reason string across all 3 deferred tests so `cargo test -- --list` shows a consistent skip rationale and the developer can grep for one canonical fragment"
metrics:
  duration: "~12 minutes"
  completed_date: 2026-05-23
  commits: 2
  files_modified: 2
  insertions: 4
  deletions: 0
---

# Phase quick-260523-moe Plan 01: Fix Phase 37 RESL Runtime Bug Summary

Two test-hygiene changes unblock the Phase 37 RESL workflow on `origin/main`: a `#[allow(clippy::unwrap_used)]` on `profile_cmd.rs`'s test module clears the cross-target Linux clippy gate (BUG-B), and three `#[ignore = "..."]` attributes on protocol-mismatched auto-pull e2e tests skip the runtime panics in PKGS-04 (BUG-A partial close — rewrite deferred under REQ-CI-FU-01).

## Tasks Completed

| Task | Name                                                                                | Commit     | Files                                                       |
| ---- | ----------------------------------------------------------------------------------- | ---------- | ----------------------------------------------------------- |
| 1    | Add #[allow(clippy::unwrap_used)] to profile_cmd.rs test module (BUG-B)             | `d3e13649` | `crates/nono-cli/src/profile_cmd.rs`                        |
| 2    | #[ignore] the 3 protocol-mismatched auto-pull e2e tests (BUG-A deferral)            | `697c713a` | `crates/nono-cli/tests/auto_pull_e2e_linux.rs`              |

## Diff Stats

```
 crates/nono-cli/src/profile_cmd.rs           | 1 +
 crates/nono-cli/tests/auto_pull_e2e_linux.rs | 3 +++
 2 files changed, 4 insertions(+)
```

Plan predicted "~5 lines added"; actual is 4 (1 allow-attribute + 3 ignore-attribute lines, no other lines touched).

## Decisions Made

1. **Defer BUG-A rewrite via `#[ignore]` rather than fix in place.** The debug doc (`phase-37-post-fix-runtime.md`) confirms the mock server in `tests/common/mock_registry.rs` serves a static-file layout (`/bundle.json`, `/mock-ns/mock-pack/manifest.json`) while the production registry client hits `/api/v1/packages/{ns}/{name}/versions/{ver}/pull`. Closing the protocol gap correctly requires rewriting either the mock or the production client — both production-impacting changes that exceed quick-task scope. The `#[ignore]` defers without lying about test status (the 3 tests will show up as `ignored` in CI logs, not `passed`).
2. **Use `#[allow(clippy::unwrap_used)]` on the test module rather than rewrite the offending `unwrap_err()`.** Workspace convention: 14 other test modules with `unwrap_err()` calls use this exact pattern (audited in plan context). Switching to `expect_err("...")` would create a single-file divergence from convention. The clippy allow-attribute on `mod tests { ... }` covers any future `unwrap()`/`expect()` calls in that module without per-line annotations.
3. **Shared single-line `#[ignore]` reason string across all 3 deferred tests.** A developer grepping `cargo test -- --list` output for `"mock/production protocol mismatch"` will find a single canonical fragment, and the reason string names both the debug doc path and the requirement ID (`REQ-CI-FU-01`) so the follow-up context is one click away.

## Verification

### Source-level verification (Windows host)

Both plan-defined `<automated>` checks pass:

```
$ grep -nP '^#\[allow\(clippy::unwrap_used\)\]\s*$' crates/nono-cli/src/profile_cmd.rs | head -5
3363:#[allow(clippy::unwrap_used)]

$ grep -nP '^#\[cfg\(test\)\]\s*$' crates/nono-cli/src/profile_cmd.rs | head -5
3364:#[cfg(test)]

$ grep -cP '^#\[ignore = "mock/production protocol mismatch' crates/nono-cli/tests/auto_pull_e2e_linux.rs
3

$ grep -nP '#\[ignore\b' crates/nono-cli/tests/auto_pull_e2e_linux.rs
186:#[ignore = "mock/production protocol mismatch — ... (REQ-CI-FU-01 follow-up)"]
396:#[ignore = "mock/production protocol mismatch — ... (REQ-CI-FU-01 follow-up)"]
497:#[ignore = "mock/production protocol mismatch — ... (REQ-CI-FU-01 follow-up)"]
```

Each `#[ignore]` is directly above the `#[test]` of its target function (`auto_pull_happy_path_mock` at line 188, `auto_pull_signature_failure_aborts` at line 398, `auto_pull_rejects_non_policy_pack_type` at line 499). The 3 untouched tests (`spawn_multi_endpoint_server_smoke`, `auto_pull_unknown_name_fails_closed`, `auto_pull_no_auto_pull_flag_falls_back_to_profile_not_found`) have `#[test]` directly above with no interposing `#[ignore]`. Crate-level attributes (`#![cfg(target_os = "linux")]` + `#![allow(clippy::unwrap_used)]`) at lines 18-19 are unchanged.

### Compile verification (Windows host)

```
$ cargo check --workspace
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1m 07s
```

Zero errors, zero warnings. The `profile_cmd.rs` edit compiles cleanly on Windows host. The `auto_pull_e2e_linux.rs` edit is inside `#![cfg(target_os = "linux")]` — on Windows host it compiles to zero test functions; the source-level grep verification above is the substitute for the gated cargo path per the plan's instructions.

### Cross-target clippy verification — PARTIAL (deferred to live CI)

Per CLAUDE.md § Coding Standards § Cross-target clippy verification, the `profile_cmd.rs` change touches a file containing `#[cfg(target_os = "linux")]` and `#[cfg(unix)]` test-module code (the flagged line 3826 lives inside `#[cfg(unix)]`). The canonical verification is:

```
cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used
cargo clippy --workspace --target x86_64-apple-darwin     -- -D warnings -D clippy::unwrap_used
```

The Linux/macOS cross-toolchains are not installed on this Windows host. Per `.planning/templates/cross-target-verify-checklist.md` partial-OK pattern, this verification is deferred to live CI. The Phase 37 RESL workflow on the next push to `origin/main` IS the live CI lane that verifies the Linux clippy gate; macOS clippy is exercised by separate workflows on push.

## Deviations from Plan

None — plan executed exactly as written. Both task `<action>` blocks were applied verbatim; both `<verify>` block invariants pass; both `<done>` criteria are satisfied.

(Operational note: the Edit tool's file-state cache temporarily disagreed with disk after the worktree-base hard-reset early in the session, so the two edits were re-applied via inline Python `text.replace` after the discrepancy was detected via `git hash-object` vs `git ls-tree`. Disk content + git index now reflect the intended changes; no functional deviation from the plan.)

## Known Stubs

None. Both changes are test-only annotations carrying canonical pointers to the deferral-tracking debug doc + requirement ID.

## Next Action

Per the plan's `<output>` block: next push to `origin/main` triggers Phase 37 RESL run — both jobs expected green; if green, the v2.6 Phase 46 Plan 46-02 Phase 37 RESL blocker (per STATE.md `### Phase 46 — Resume Preconditions` item 2) is cleared and 46-02 can resume.

## Self-Check: PASSED

Files exist:
- FOUND: crates/nono-cli/src/profile_cmd.rs (modified — `#[allow(clippy::unwrap_used)]` at line 3363)
- FOUND: crates/nono-cli/tests/auto_pull_e2e_linux.rs (modified — 3 `#[ignore]` attributes at lines 186, 396, 497)

Commits exist:
- FOUND: d3e13649 — `fix(quick-260523-moe): allow unwrap_used in profile_cmd test module (BUG-B)`
- FOUND: 697c713a — `test(quick-260523-moe): #[ignore] 3 mock/prod-mismatched auto-pull e2e tests (BUG-A defer)`
