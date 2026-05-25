---
plan_id: 48-06
plan_name: PTY-MUSL-PORTABILITY
phase: 48
phase_name: upst6-sync-execution
cluster: C7
cluster_disposition: will-sync
upstream_sha_range: 1f552106..279af554
upstream_commit_count: 4
baseline_sha: 3f638dc6
lane_transitions: "deferred to live CI; no local green→red transitions from C7"
skipped_gates_environmental: [3, 6, 7, 8, 9, 10]
skipped_gates_preexisting_debt: [1, 2, 4]
musl_target_verdict: PARTIAL_environmental
pr_section: 48-06-PR-SECTION.md
status: complete
completed: "2026-05-25"
duration_minutes: 90
tasks_completed: 4
files_modified: 7
requirements: [REQ-UPST6-02]
tags: [upstream-sync, cherry-pick, pty, musl, unix-portability, wave-2]

dependency_graph:
  requires: [48-02, 48-03]
  provides: [C7-PTY-MUSL-portability]
  affects:
    - crates/nono-cli/src/pty_proxy.rs
    - crates/nono-cli/src/exec_strategy.rs
    - crates/nono/src/sandbox/linux.rs

tech_stack:
  patterns:
    - "musl ioctl portability: use u32 as libc::Ioctl for SECCOMP_IOCTL literals"
    - "TIOCSCTTY/TIOCSWINSZ: remove as libc::c_ulong; use as _ for cross-platform inference"
    - "PTY ESC forwarding: only buffer ESC when '[' immediately follows in same read batch"

key_files:
  modified:
    - crates/nono-cli/src/pty_proxy.rs
    - crates/nono-cli/src/exec_strategy.rs
    - crates/nono/src/sandbox/linux.rs
    - CHANGELOG.md
  created:
    - docker/Dockerfile-musl
    - docker/Dockerfile-musl-cross
    - .planning/phases/48-upst6-sync-execution/48-06-CLOSE-GATE.md
    - .planning/phases/48-upst6-sync-execution/48-06-PR-SECTION.md

decisions:
  - "Topo-chronological cherry-pick order used (1f552106→3cd22aa5→3d0ff87f→279af554); ledger row order differs from commit date order"
  - "as _ applied in C7-02 for macOS compilation safety, pre-empting C7-03 refinement"
  - "C7-03 is effectively a no-op commit preserving upstream attribution; fork's unsafe fn outer declaration makes inner unsafe{} redundant"
  - "Docker Dockerfiles placed in docker/ directory (upstream has no docker/ dir; fork organizes infra there)"
  - "D-48-D4 musl-target verdict: PARTIAL _environmental — musl cross-toolchain absent on macOS dev host"
  - "pre-existing macOS clippy errors (8 in exec_strategy.rs/session_commands.rs/format_util.rs) are Class-B CI debt; not introduced by C7"
---

# Phase 48 Plan 06: PTY-MUSL-PORTABILITY Summary

**One-liner:** 4 upstream cherry-picks for PTY trailing-newline preservation, bare-ESC forwarding fix, and musl libc Ioctl type portability (Cluster C7, Wave 2).

## Objective

Cherry-pick Phase 47 ledger Cluster C7 (PTY proxy fixes + musl libc Ioctl portability; 4 commits in v0.55.0) onto fork `main`, preserving fork-side `unsafe fn` structure and applying `as _` cast inference for cross-platform musl/glibc Ioctl compatibility.

## Execution Context

Sequential Wave 2 executor on macOS host (`/Users/oscarmack/nono/.claude/worktrees/agent-ab466d67727f7c589`). Worktree branched off Wave 0 head; fast-forwarded to Wave 2 state (`b2a71ec3` — including Plans 48-02, 48-03, 48-04, 48-05) before cherry-picking C7.

Wave 1 prerequisite confirmed: Plan 48-03's D-48-D3 cleanup commit (`062b3aa7`) present in history — ensures `3cd22aa5`'s `exec_strategy.rs` hunk lands cleanly on post-cleanup tree per PATTERNS.md row #12 collision-risk resolution.

## Pre-flight inspection (Task 0)

| Check | Result |
|-------|--------|
| Wave 1 plans (48-02, 48-03) closed | CONFIRMED — SUMMARY files present |
| D-48-D3 cleanup commit `062b3aa7` in history | CONFIRMED |
| 4 C7 SHAs resolvable | CONFIRMED |
| musl cross-toolchain availability | NOT INSTALLED — D-48-D4 PARTIAL `_environmental` |
| Upstream topo order verification | `1f552106 → 3cd22aa5 → 3d0ff87f → 279af554` |

**Note:** Plan ledger order (`1f552106, 279af554, 3d0ff87f, 3cd22aa5`) differs from upstream topo-chronological order. Topo order used for cherry-picks per D-48-B1 convention.

## Per-Commit Notes

| # | Fork SHA | Upstream SHA | Resolution |
|---|----------|-------------|------------|
| C7-01 | ce6512ab | 1f552106 | Manual conflict: fork's `release_terminal_for_prompt` lacks `in_alt_screen` param in `leave_attach_screen()`. Added local `let in_alt_screen = ...` capture before call. Test `cursor_column_nonzero_after_output_without_trailing_newline` added. |
| C7-02 | c2ae8723 | 3cd22aa5 | Manual conflict: fork's `setup_child_pty` is `pub unsafe fn`; redundant inner `unsafe { }` omitted. Applied `TIOCSCTTY as _` (incorporating C7-03 refinement) for macOS compatibility. Docker Dockerfiles moved to `docker/`. SECCOMP_IOCTL `u32 as libc::Ioctl` applied cleanly. |
| C7-03 | 9d30ba0f | 3d0ff87f | Manual conflict: fork already has `TIOCSCTTY as _` from C7-02; resolved by keeping HEAD (fork's no-inner-unsafe form). Comment updated to document `as _` rationale. Net code change: comment-only. |
| C7-04 | 4307ef2b | 279af554 | Auto-merged cleanly. Bare ESC forwarding fix + 2 regression tests + CHANGELOG entry. |

## C7-02 sandbox/linux.rs invariant check (PATTERNS.md row #1)

- `SECCOMP_IOCTL_NOTIF_RECV: libc::Ioctl = 0xc0502100u32 as libc::Ioctl` — strictly allow-list preserved; no deny-style code path introduced.
- `#[cfg(target_os = "linux")]` gate preserved on all existing `pub` items in sandbox/linux.rs; no new pub items added by C7.

## C7-02 exec_strategy.rs invariant check (PATTERNS.md row #12)

- Confirmed D-48-D3 cleanup commit (`062b3aa7`) is upstream of C7-02 — startup_prompt references already removed; `3cd22aa5`'s exec_strategy.rs hunk (TIOCSWINSZ cast removal at line 2121) applied cleanly.
- Execution strategies (Direct/Monitor/Supervised) unaffected — TIOCSWINSZ only affects window resize in PTY-attached sessions.

## Cross-target clippy / build results

| Target | Command | Result | Notes |
|--------|---------|--------|-------|
| macOS native | `cargo build --workspace` | PASS | 3 pre-existing warnings |
| macOS (x86_64-apple-darwin) | `cargo clippy --target x86_64-apple-darwin` | PARTIAL | 8 pre-existing errors (Class-B debt) |
| Linux (x86_64-unknown-linux-gnu) | `cargo clippy --target x86_64-unknown-linux-gnu` | PARTIAL `_environmental` | Cross-toolchain absent |
| musl (x86_64-unknown-linux-musl) | `cargo check --target x86_64-unknown-linux-musl` | PARTIAL `_environmental` | musl-cross-toolchain absent |

**D-48-D4 musl-target verdict: PARTIAL `_environmental`** — defer to live CI.

## Test results

- `cargo test --workspace`: 1094 (nono-cli) + 680 (nono) + 40 (nono-proxy) = 1814 PASS
- 1 pre-existing failure: `audit_verify_reports_signed_attestation_with_pinned_public_key` (Class-B debt)
- Zero new test failures from C7

## Windows invariant (D-48-E1)

Zero files touched in:
- `crates/nono-cli/src/exec_strategy_windows/`
- `crates/nono-shell-broker/`
- Any `*_windows.rs` file

`git diff --name-only b2a71ec3..HEAD -- '*_windows.rs' '**/exec_strategy_windows/**' '**/nono-shell-broker/**' | wc -l` = 0.

## Baseline-aware CI gate (Gate 10)

Deferred to live CI operator push to `pre-merge` branch. Baseline SHA: `3f638dc6`. Per pre-existing STATE.md documentation, the following lanes are already red at baseline (Class-B debt):
- macOS Clippy
- Rustfmt
- Cargo Audit
- Docs Checks

C7 changes do not introduce any new failure paths in these lanes. Zero `success → failure` transitions expected from C7 cherry-picks.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] macOS compilation failure from bare TIOCSCTTY removal (C7-02)**
- **Found during:** C7-02 (`3cd22aa5`) conflict resolution
- **Issue:** Removing `as libc::c_ulong` from `TIOCSCTTY` cast (as upstream does in `3cd22aa5`) causes `E0308 mismatched types` on macOS: `ioctl` expects `u64` but `TIOCSCTTY` is `u32`.
- **Fix:** Applied `as _` form (from C7-03) in C7-02 resolution, pre-empting the C7-03 refinement commit.
- **Files modified:** `crates/nono-cli/src/pty_proxy.rs` (line ~216)
- **Commit:** c2ae8723

### Structural Adaptations (not bugs, fork-structure differences)

**1. [Structural] `in_alt_screen` capture in `release_terminal_for_prompt` (C7-01)**
- Fork's `leave_attach_screen()` does not accept `in_alt_screen` parameter (unlike upstream's version).
- Added local variable capture before the call; semantics are equivalent.

**2. [Structural] Inner `unsafe { }` wrapper omitted (C7-02/C7-03)**
- Fork's `setup_child_pty` is declared `pub unsafe fn`; inner `unsafe { }` is redundant.
- Kept fork's structure (no inner block); semantics identical.

**3. [Structural] Docker Dockerfiles placed in `docker/` (C7-02)**
- Upstream commit has `docker/Dockerfile-musl` and `docker/Dockerfile-musl-cross` inside a `docker/` directory, but git places them at root when that directory doesn't exist.
- Moved to `docker/` per fork's infrastructure organization.

## Known Stubs

None — all C7 changes are functional bug fixes (PTY output preservation, ESC forwarding, musl type portability). No placeholder values or mock data introduced.

## Threat Flags

No new security-relevant surface beyond the plan's threat model. All STRIDE threats (T-48-06-01 through T-48-06-04) mitigated as designed:
- T-48-06-01 (PTY trailing newline): accept — output formatting change only
- T-48-06-02 (bare ESC forwarding): accept — intended behavior change
- T-48-06-03 (musl Ioctl): mitigate — D-48-D4 PARTIAL `_environmental`
- T-48-06-04 (sandbox/linux.rs cfg gate): mitigate — PATTERNS.md row #1 invariant verified

## Self-Check: PASSED

- [x] `ce6512ab` exists: `git log --oneline | grep ce6512ab` → found
- [x] `c2ae8723` exists: found
- [x] `9d30ba0f` exists: found
- [x] `4307ef2b` exists: found
- [x] 4 Upstream-commit trailers: `git log b2a71ec3..HEAD --format=%B | grep -cE '^Upstream-commit: [0-9a-f]{40}$'` = 4
- [x] 4 Co-Authored-By lines: count = 4
- [x] 4 Signed-off-by lines: count = 4
- [x] Windows invariant: 0 files touched in exec_strategy_windows/ or nono-shell-broker/
- [x] Build clean: `cargo build --workspace` exits 0
- [x] 48-06-CLOSE-GATE.md created: ≥9 gate sections + D-48-D4 musl gate present
- [x] 48-06-PR-SECTION.md created
- [x] musl_target_verdict field present in frontmatter: PARTIAL_environmental
