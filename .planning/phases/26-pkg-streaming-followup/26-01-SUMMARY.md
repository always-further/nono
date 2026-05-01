---
phase: 26-pkg-streaming-followup
plan: 01
subsystem: pkg
tags: [pkg, package-manager, validation, plugin, fork-arch, cherry-pick, upstream-sync]
type: execute
wave: 1
status: complete
requirements: [PKGS-02, PKGS-03]
dependency-graph:
  requires: []
  provides:
    - ArtifactType::Plugin variant (prerequisite for Plan 26-02 streaming refactor)
    - validate_relative_path defense-in-depth pre-check (paired with validate_path_within)
  affects:
    - crates/nono-cli/src/package.rs
    - crates/nono-cli/src/package_cmd.rs
tech-stack:
  added: []
  patterns:
    - defense-in-depth path validation (input-string + canonicalize-and-component-compare)
    - serde rename_all = "snake_case" for variant JSON shape
    - D-20 manual replay with Upstream-commit + Upstream-replay trailers
key-files:
  created: []
  modified:
    - crates/nono-cli/src/package.rs
    - crates/nono-cli/src/package_cmd.rs
decisions:
  - "Used D-20 manual replay (not direct cherry-pick) for upstream 58b5a24e because that commit deletes validate_path_within entirely. Cherry-picking verbatim would have been a security regression vs CLAUDE.md Path Handling. Replay preserves both validators (defense-in-depth)."
  - "Added test module to package_cmd.rs (no existing one) and extended package.rs's existing tests block. Matches plan's instruction to use whichever file is closest to the function under test."
  - "Windows-host shapes (C:\\foo, \\\\server\\share) gated under #[cfg(windows)] in validate_relative_path_rejects_absolute_path because Path::Component::Prefix only fires on Windows; Unix-host parsing of those strings returns a single-Normal-component relative path, not the absolute shape upstream's check rejects."
metrics:
  duration: 22 minutes
  completed: 2026-04-29
---

# Phase 26 Plan 01: PKG Fork-Architectural Decisions Summary

**One-liner:** Closed REQ-PKGS-02 (port `validate_relative_path` as defense-in-depth pre-check alongside fork's `validate_path_within`) and REQ-PKGS-03 (add `ArtifactType::Plugin` variant + plumb match arms + remove deferred-divergence comment), unblocking Plan 26-02's streaming refactor.

## Outcome

Both deferred requirements from v2.2 Plan 22-03 closed:

- **REQ-PKGS-02** — `validate_relative_path` ported from upstream `58b5a24e` as a CHEAP-REJECTION layer that runs BEFORE any filesystem syscall in `install_manifest_artifact`. The fork's stricter `validate_path_within` (canonicalize-and-component-compare) is preserved verbatim at line 1035 and continues to fire post-match at line 696. Both validators now cover every artifact-write path; the input-string check rejects `..`, absolute paths, and Windows drive prefixes early; the canonicalize check catches symlink-traversal post-resolution.
- **REQ-PKGS-03** — `ArtifactType::Plugin` is now the 7th variant in `crates/nono-cli/src/package.rs:87` (after Profile, Hook, Instruction, TrustPolicy, Groups, Script). The deferred-divergence comment at `package_cmd.rs:671-688` (placeholder since v2.2 commit `73e1e3b8`) is removed and replaced with a live arm placing Plugin artifacts under `staging_root/plugins/<file_name>`. Compiler surfaced exactly **1** non-exhaustive match site (the `let store_path = match artifact.artifact_type` at line 620); secondary match-style sites (`matches!()` macro, `==`/`!=` boolean comparisons) did not require explicit Plugin arms and fall through cleanly.

## Verification Command Outputs

| Gate | Command | Result |
|------|---------|--------|
| 1 — Build | `cargo build --workspace` | Clean (Finished `dev` profile in 6.25s) |
| 2 — Tests | `cargo test -p nono-cli --bin nono` | 818 passed; 0 failed; 0 ignored (4 new tests added) |
| 3 — Clippy | `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` | 2 pre-existing `nono::manifest` `collapsible_match` errors at lines 95, 103 — **documented-skip per Phase 23/28/29 precedent**; Phase 26 does NOT touch `crates/nono/` |
| 4 — Fmt | `cargo fmt --all -- --check` | Clean (after follow-up `style(pkg)` fmt commit) |
| 5 — D-19 | `git diff --stat HEAD~5..HEAD -- crates/nono/ \| wc -l` | `0` (byte-identical preservation) |
| 6 — Grep | See below | All 5 must_haves grep counts pass |

### Must-haves grep verification

```
grep -c 'fn validate_relative_path' crates/nono-cli/src/package_cmd.rs   = 3 (1 production fn + 2 test names; production count = 1 verified by line-by-line inspection at lines 1068, 1159, 1180)
grep -c 'fn validate_path_within' crates/nono-cli/src/package_cmd.rs    = 1
grep -c '    Plugin,' crates/nono-cli/src/package.rs                    = 1
grep -c 'ArtifactType::Plugin' crates/nono-cli/src/package_cmd.rs       = 1
grep -c 'upstream ec49a7af also adds an ArtifactType::Plugin' ...       = 0 (deferred-divergence comment removed)
```

### New unit tests (4)

All 4 pass on Windows host:

```
test package::tests::artifact_type_plugin_round_trips        ... ok
test package::tests::artifact_type_unknown_fails_closed      ... ok
test package_cmd::tests::validate_relative_path_rejects_absolute_path ... ok
test package_cmd::tests::validate_relative_path_rejects_traversal     ... ok
```

## Commits Landed

5 atomic commits on `main` (chronological):

| # | Commit | Message |
|---|--------|---------|
| T1 | `e5e1f2d7` | `fix(pkg): port validate_relative_path defense-in-depth pre-check (REQ-PKGS-02)` |
| T2 | `dd7b28b3` | `feat(pkg): add ArtifactType::Plugin enum variant (REQ-PKGS-03)` |
| T3 | `797f3295` | `feat(pkg): plumb ArtifactType::Plugin match arms (REQ-PKGS-03)` |
| T5 | `8ff89923` | `test(pkg): cover REQ-PKGS-02 + REQ-PKGS-03 acceptance via 4 unit tests` |
| -- | `1f47d0ee` | `style(pkg): apply cargo fmt to ArtifactType test bodies` (follow-up after fmt-check surfaced two over-wrapped lines) |

All commits include `Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>` (DCO).
T1 includes `Upstream-commit: 58b5a24e` and `Upstream-replay: manual` provenance trailers.

The user-prompt's "Task 4 — comment removal" was executed atomically with Task 3 (the comment was deleted in the same commit that added the live `ArtifactType::Plugin` arm), per the plan file's explicit instruction that the deletion + arm-addition must be a single edit. No separate Task 4 commit was made; this is documented as deviation #2 below.

## Deviations from Plan

### 1. D-20 manual replay used for Task 1 (NOT cherry-pick)

**What:** Direct `git cherry-pick 58b5a24e` was NOT attempted because inspection of the upstream patch (`git show 58b5a24e`) revealed it would breach the fork's defense-in-depth posture in two ways:

1. The patch **deletes `validate_path_within`** entirely (replacing the line-691 callsite with `validate_relative_path` only). Per CLAUDE.md § Path Handling, this would be a security regression — the canonicalize-and-component-compare layer catches symlink-traversal that an input-string check cannot.
2. The patch's diff context references an `ArtifactType::Plugin` arm that doesn't exist in the fork's enum yet (it's added by this same plan in Task 2). The cherry-pick context-match would have failed.

**How:** Manual replay — wrote `validate_relative_path` adjacent to the existing `validate_path_within` (preserving both), wired one new callsite at the top of `install_manifest_artifact` BEFORE the match block. Both `Upstream-commit: 58b5a24e` and `Upstream-replay: manual` trailers recorded in the T1 commit message per Phase 28/29 D-20 precedent.

**Rule:** Rule 1 (security-correctness fix) — preserving `validate_path_within` is required by CLAUDE.md and was the explicit guidance in this plan's task action prose ("KEEP `validate_path_within` AT LINE 1035 INTACT").

### 2. Task 4 (deferred-divergence comment removal) folded into Task 3 atomically

**What:** The user-prompt's task ordering listed comment removal as Task 4 (separate commit). The plan file's Task 3 action prose explicitly required the comment deletion + Plugin arm addition to be a SINGLE atomic commit (line 204: "the comment block deletion AND the new arm addition are ONE atomic edit — do not commit the deletion alone (that would leave a non-exhaustive match the moment Task 2 lands ArtifactType::Plugin in the enum)").

**How:** Comment block at lines 671-688 was deleted as part of the Task 3 edit (`797f3295`). Per the user prompt's instruction "use `git commit --allow-empty` only if necessary," no separate Task 4 commit was made — the work was already complete. `grep -c 'upstream ec49a7af also adds an ArtifactType::Plugin' crates/nono-cli/src/package_cmd.rs` returns `0` confirming the removal.

**Rule:** No rule violated — the plan file's atomic-commit guidance was the binding constraint and the user prompt explicitly anticipated this case.

### 3. Style follow-up commit after `cargo fmt --all -- --check`

**What:** After Task 5 (test addition), `cargo fmt --all -- --check` (Gate 4) flagged two assignment expressions in `artifact_type_plugin_round_trips` and `artifact_type_unknown_fails_closed` that fit on one line under the 100-column rustfmt budget but had been broken across two lines.

**How:** Ran `cargo fmt --all`, committed as `1f47d0ee style(pkg): ...` per CLAUDE.md "create NEW commit rather than amending" rule (no `--amend` even though it would have been simpler).

**Rule:** Rule 1 (CI gate fix) — `cargo fmt --all -- --check` is part of the must_haves verification gate; not committing the fix would have failed `make ci`.

### 4. Windows-host gating in `validate_relative_path_rejects_absolute_path`

**What:** The test asserts `validate_relative_path("C:\\foo\\bar").is_err()` and `\\\\server\\share`. On Unix hosts these strings parse as single-`Component::Normal` relative paths (because `Path::Component::Prefix` only fires on Windows), so the test would FAIL on Linux/macOS.

**How:** Gated those assertions under `#[cfg(windows)]`. Plan 26-01 is Windows-OK by design, but the fork's CI also runs on Ubuntu and macOS; cross-platform compilation must remain green.

**Rule:** Rule 1 (cross-platform correctness) — preventing a build failure on Linux/macOS CI when the test eventually runs there.

## Auth Gates

None encountered.

## Cross-References

- Plan source: `.planning/phases/26-pkg-streaming-followup/26-01-PKGS-FORK-ARCH-PLAN.md`
- Phase context: `.planning/phases/26-pkg-streaming-followup/26-CONTEXT.md`
- Predecessor: `.planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-03-PKG-SUMMARY.md` (item §4 backlog → "PKG streaming + Plugin arm port" — sub-items 1, 2, 3 closed by this plan; sub-items 4, 5 remain in Plan 26-02 scope)
- Successor: `.planning/phases/26-pkg-streaming-followup/26-02-*` (Wave 2 — REQ-PKGS-01 streaming refactor + REQ-PKGS-04 registry auto-pull, scoped for Linux/macOS host)

## Self-Check: PASSED

- All 5 commits exist in `git log --oneline HEAD~5..HEAD`: e5e1f2d7, dd7b28b3, 797f3295, 8ff89923, 1f47d0ee — verified.
- File `.planning/phases/26-pkg-streaming-followup/26-01-SUMMARY.md` is being written by this same Write tool call.
- Files modified by plan exist:
  - `crates/nono-cli/src/package.rs` (Plugin variant + 2 new tests) — verified.
  - `crates/nono-cli/src/package_cmd.rs` (validate_relative_path + Plugin arm + 2 new tests) — verified.
- Files in `crates/nono/` UNTOUCHED (D-19): `git diff --stat HEAD~5..HEAD -- crates/nono/ | wc -l` = `0` — verified.
