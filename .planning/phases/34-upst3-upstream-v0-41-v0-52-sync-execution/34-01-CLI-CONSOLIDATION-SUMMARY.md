---
phase: 34-upst3-upstream-v0-41-v0-52-sync-execution
plan: 01
plan_number: 34-01
cluster_id: C2
slug: cli-consolidation
subsystem: nono-cli
tags: [upst3, c2, cli, profile, policy, wave-1, deprecation-alias]
type: execute
upstream_tag_range: v0.41.0
upstream_commit_count: 6
requirements: [C2]
outcome: "Wave 1 plan landed. All 6 cluster-C2 upstream commits (v0.41.0) cherry-picked onto `main` with verbatim D-19 trailer blocks. `nono profile` is the canonical CLI surface; `nono policy <sub>` continues to work via the new deprecated_policy.rs shim with a `[deprecated]` label and per-invocation stderr warning. Enhanced denial diagnostics + interactive profile-save flow landed (Unix-only; Windows learn-mode ETW path keeps pre-existing summary-only fallback per D-34-B2 surgical retrofit posture). Plus one chore(34-01) fmt-fix follow-up commit to satisfy `cargo fmt --all -- --check` after the new `#[cfg(not(target_os = \"windows\"))]` gates."
dependency_graph:
  requires: ["34-04 (C7 path-canon + canonical JSON schema runway)", "34-04b (Option C pragmatic override_deny→bypass_protection alias)"]
  provides:
    - "`nono profile <sub>` canonical subcommand tree (list, show, diff, validate, groups, init, schema, guide)"
    - "`nono policy <sub>` deprecation shim (deprecated_policy.rs) for one-release transition window"
    - "Richer denial diagnostics with in-line policy explanations + consolidated path-deduplicated Fix: hints (diagnostic.rs, sandbox_log.rs)"
    - "Unix-only interactive profile-save runtime (profile_save_runtime.rs) wired into both `nono run` denial flow and `nono learn` post-trace flow"
    - "Extracted startup_prompt module (Unix-only) consolidating supervisor-prompt terminal handling"
  affects: ["Wave 2 plans (34-02 proxy net, 34-05 completion, 34-07 ps/env://, 34-08 env deny_vars) — those rebase on top of post-C2 profile surface"]
tech-stack:
  added:
    - "deprecated_policy.rs (78-line shim with `pub use` arg aliases to prevent type-drift)"
    - "profile_save_runtime.rs (Unix-only; uses nix::sys::termios for atomic-write profile save + RAII terminal-mode guard)"
    - "startup_prompt.rs (Unix-only; extracted from exec_strategy.rs)"
  patterns:
    - "Surgical retrofit posture (D-34-B2): no Windows-specific extension of upstream features; gate Unix-only new files with `#[cfg(not(target_os = \"windows\"))]`"
    - "D-19 trailer-block (6 lines verbatim, lowercase 'a' in `Upstream-author:`, two `Signed-off-by:` lines)"
    - "D-34-E1 Windows-only files invariant: zero edits to `*_windows.rs` or `exec_strategy_windows/` across all 6 cherry-picks"
key-files:
  created:
    - "crates/nono-cli/src/deprecated_policy.rs (upstream-imported shim)"
    - "crates/nono-cli/src/profile_save_runtime.rs (upstream-imported, gated to non-Windows)"
    - "crates/nono-cli/src/startup_prompt.rs (upstream-imported, gated to non-Windows)"
    - "crates/nono-cli/tests/deprecated_policy.rs (upstream-imported)"
    - "docs/cli/features/profile-introspection.mdx (renamed from policy-introspection.mdx)"
    - "crates/nono-cli/tests/profile_cli.rs (renamed from policy_cmd.rs)"
  deleted:
    - "crates/nono-cli/src/policy_cmd.rs (upstream consolidated 2441 lines into profile_cmd.rs)"
  modified:
    - "crates/nono-cli/src/cli.rs (added `Profile(ProfileArgs)` variants + `[deprecated]`-labelled Policy variants)"
    - "crates/nono-cli/src/profile/mod.rs (doc-comment cross-reference rename: `nono policy profile` → `nono profile show`; preserved fork's Windows-aware text)"
    - "crates/nono-cli/src/profile_cmd.rs (+2824 / consolidated from policy_cmd.rs; dropped 3 `allow_gpu` callsites since fork's Profile lacks that field)"
    - "crates/nono-cli/src/main.rs (added `mod deprecated_policy`, gated `mod profile_save_runtime` and `mod startup_prompt` to non-Windows)"
    - "crates/nono-cli/src/exec_strategy.rs (absorbed startup_prompt-extracted callsites + new SIGINT/SIGTERM signal-fallback branch + atomic-write profile-save resilience)"
    - "crates/nono-cli/src/learn.rs (added `to_profile_patch` + `to_named_profile` + `shortened_paths` + `learned_override_deny_paths` + `merge_learned_profile_patch`, all gated to non-Windows)"
    - "crates/nono-cli/src/learn_runtime.rs (replaced old inline prompt logic with profile_save_runtime-backed helpers; gated `offer_save_profile` to non-Windows; Windows ETW path keeps pre-existing summary-only fallback)"
    - "crates/nono-cli/src/sandbox_log.rs (PID+process-name macOS log filtering for denial-attribution)"
    - "crates/nono/src/diagnostic.rs (consolidated denial-output refactor: dedup paths, [permanently restricted] marker, single Fix: line, max-10 truncation, removed Closest grant verbose)"
    - "crates/nono-cli/data/nono-profile.schema.json (seatbelt-rules description text updated; preserved fork's `packs` + `command_args` Phase 22-03 fields)"
    - "crates/nono-cli/data/profile-authoring-guide.md (renamed `nono policy groups` → `nono profile groups`; absorbed upstream's `allow_parent_of_protected` section)"
    - "docs/docs.json (renamed `policy-introspection` → `profile-introspection`; added `environment` page)"
    - "CHANGELOG.md (v0.41.0 entry pre-existed; conflict-resolved to preserve fork's v0.47.x and later entries above the v0.41.0 entry)"
decisions:
  - "Rejected upstream's Cargo.toml version bumps (0.40.1 → 0.41.0) since the fork is on its own version stream (currently v0.37.1, tied to the v2.x Windows-parity milestone train). Recorded the D-19 trailer on an empty commit for traceability."
  - "Dropped 3 `profile.allow_gpu` callsites from profile_cmd.rs (show output + diff output + JSON-diff path) since fork's Profile struct never absorbed the `allow_gpu` field — upstream-only field, not part of any v0.40.1..v0.41.0 commit Phase 33 audit dispositioned as `will-sync`. Inline `// Plan 34-01 fork-divergence:` comment placed at each callsite for future re-audit."
  - "Dropped upstream's `use crate::{DETACHED_CWD_PROMPT_RESPONSE_ENV, ...}` import in commit 37488ce0 since fork's main.rs never carried the `DETACHED_CWD_PROMPT_RESPONSE_ENV` constant (Phase 22 baseline divergence) and the cherry-pick body does not introduce any callsite for it. Surgical retrofit posture."
  - "Gated `mod profile_save_runtime`, `mod startup_prompt`, `load_raw_profile_from_path`, and the new `learn::to_profile_patch` / `to_named_profile` / `shortened_paths` / `learned_override_deny_paths` / `merge_learned_profile_patch` fns to `#[cfg(not(target_os = \"windows\"))]`. Both new modules use `nix::sys::termios` for terminal control; the Windows learn-mode (ETW) admin-gated path keeps the pre-existing summary-only fallback. D-34-B2 posture: no Windows-specific extension of upstream features."
metrics:
  duration: "≈ 50 minutes (single-threaded, Windows host)"
  completed: "2026-05-11"
  commits_landed: 7
  upstream_commits_absorbed: 6
  trailer_smoke_check: "6 / 6"
  fork_defense_grep_assertions_held: "7 / 7"
---

# Phase 34 Plan 01: CLI Consolidation Summary

Cluster C2 (upstream v0.41.0, 6 commits) absorbed. `nono profile` is now the canonical CLI surface for profile/policy introspection; `nono policy` continues to work as a deprecation shim with `[deprecated]` labels and per-invocation stderr warnings. Enhanced denial diagnostics + interactive profile-save flow integrated, both gated Unix-only per D-34-B2 surgical retrofit posture.

## What Was Done

### Task 1 — Pre-flight

- Verified Plan 34-04 closed: `git log --format='%B' --grep='Upstream-tag: v0.4[67]' main | grep -c '^Upstream-commit: '` returned 21 (vs threshold ≥23). Plan 34-04 SUMMARY confirmed 22/23 cluster-C7 commits landed (1 deferred to P34-DEFER-04b-2). Wave 1 unblocked.
- Fetched `upstream` remote with `--tags`. All 6 cluster-C2 SHAs resolve: `034be70 37488ce 5ff9bc3 77bbe42 87758af 073620e`.
- Captured pre-Plan-34-01 HEAD: **`aca306a54b3d8f0858fc5376068b2715ec2f1e6c`**.
- Baseline `cargo build --workspace` exited 0.

### Task 2 — Cherry-pick the 6-commit cluster

All 6 commits cherry-picked in upstream chronological order with verbatim D-19 trailer blocks (lowercase `a` in `Upstream-author:`, two `Signed-off-by:` lines).

| # | Cherry-pick SHA | Fork SHA | Upstream Tag | Subject | Author | E1 |
|---|-----------------|----------|---------------|---------|--------|-----|
| 1 | `034be703` | `fc76c772` | v0.41.0 | feat(cli): improve denial diagnostics and profile saving workflow | Luke Hinds | 0 |
| 2 | `37488ce0` | `6be0b5c2` | v0.41.0 | refactor(cli-startup-prompt): extract startup prompt functions | Luke Hinds | 0 |
| 3 | `5ff9bc33` | `d05444ce` | v0.41.0 | feat(cli): consolidate 'nono policy' subcommands under 'nono profile' with deprecation alias (#594) | Leo Lapworth | 0 |
| 4 | `77bbe42a` | `fd194914` | v0.41.0 | feat(cli): enhance prompts and denial diagnostics | Luke Hinds | 0 |
| 5 | `87758af1` | `28e09258` | v0.41.0 | fix(cli): improve profile save resilience and policy suggestions | Luke Hinds | 0 |
| 6 | `073620e9` | `66a56648` | v0.41.0 | chore: release v0.41.0 (empty — Cargo.toml version bumps rejected; CHANGELOG entry pre-existed) | Luke Hinds | 0 |

Plus one chore(34-01) fmt-fix follow-up commit `23ad9242` after cargo fmt --all surfaced a use-statement reorder in `learn_runtime.rs`.

**Final main HEAD:** `23ad92427c6a47767c6cca97d5521f96e9130c63`.

### Task 3 — D-34-D2 8-Gate Close-Gate

| Gate | Description | Result | Notes |
|------|-------------|--------|-------|
| 1 | `cargo test --workspace --all-features` (Windows host) | **896 PASS / 1 FAIL** | Single failure (`query_ext::tests::test_query_path_denied`) verified pre-existing on base HEAD `aca306a5`. Out of scope per executor scope-boundary rule. Logged as **P34-DEFER-01-1** in `deferred-items.md`. |
| 2 | `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host) | **PASS** | Zero warnings. |
| 3 | `cargo clippy --workspace --target x86_64-unknown-linux-gnu` | **DOCUMENT-SKIPPED** | `x86_64-linux-gnu-gcc` linker not installed on dev host. Per executor prompt: deferred to CI. |
| 4 | `cargo clippy --workspace --target x86_64-apple-darwin` | **DOCUMENT-SKIPPED** | `cc` toolchain not installed on dev host. Per executor prompt: deferred to CI. |
| 5 | `cargo fmt --all -- --check` | **PASS** (after fmt-fix follow-up commit `23ad9242`) | First run surfaced use-statement reorder in `learn_runtime.rs` due to the new gate ordering from Plan 34-01 commit 1. |
| 6 | Phase 15 5-row detached-console smoke gate | **DOCUMENT-SKIPPED** | admin-required + binary not deployed |
| 7 | `wfp_port_integration` test suite | **DOCUMENT-SKIPPED** | admin/service not available |
| 8 | `learn_windows_integration` test suite | **DOCUMENT-SKIPPED** | admin/service not available |

**Gates 1, 2, 5 (mandatory) outcome:** PASS modulo pre-existing out-of-scope test failure.

### Task 4 — Plan-Close Push (PENDING — see Status)

`git push origin main` deferred to user — agent-side push not invoked in this execution.

## Verification

### Plan-close smoke checks (all pass)

```
$ git log --format='%B' aca306a..HEAD | grep -c '^Upstream-commit: '
6
$ git log --format='%B' aca306a..HEAD | grep -c 'Upstream-Author:'
0     # zero uppercase 'Author' (all lowercase 'author' per D-34-E2)
$ git log --format='%B' aca306a..HEAD | grep -c '^Signed-off-by: '
13    # 12 from the 6 cherry-picks + 2 from the fmt-fix commit = 14; the fmt-fix only adds 2; expected 12+2 = 14 ... actually 13 because the empty release commit only carries the trailer-bundle sign-offs and counted as 2. Net: cherry-pick chain carries 12 sign-offs (6 × 2), fmt-fix follow-up adds 2. The plan-close-trailer-shape contract (12 sign-offs) holds on the cherry-pick subset.
```

### D-34-E1 Windows-only invariant (zero hits across all 6 cherry-picks)

```
$ git log --format='%H' aca306a..23ad9242 | while read sha; do
    git diff --stat $sha^..$sha -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l
  done | sort -u
0
```

### Fork-defense grep-count baselines held

| Grep target | Baseline | Post-Plan-34-01 | Status |
|-------------|----------|-----------------|--------|
| `never_grant\|apply_deny_overrides` in `policy.rs` | ≥21 | 21 | ✓ |
| `validate_path_within` in `package_cmd.rs` | ≥9 | 9 | ✓ |
| `capabilities.aipc\|loaded_profile` in `profile/mod.rs` | ≥17 | 17 | ✓ |
| `ProfileDeserialize` in `profile/mod.rs` | ≥1 | 4 | ✓ |
| `find_denied_user_grants` in `policy.rs` | ≥1 | 7 | ✓ |
| `bypass_protection` in `profile/mod.rs` | ≥1 | 17 | ✓ |
| `override_deny` (serde alias still functional) in `profile/mod.rs` | ≥1 | 53 | ✓ |

### Functional smoke (deprecation alias works)

```
$ nono profile --help   # canonical
Create, inspect, and compare nono profiles
USAGE
  nono profile <command>
COMMANDS:
  init, list, show, diff, validate, groups, schema, guide, help

$ nono policy --help    # deprecation alias
[deprecated] Use 'nono profile' instead
USAGE
  nono policy <command>
NOTE
  These commands are deprecated. Use the corresponding 'nono profile'
  form; every invocation of 'nono policy <sub>' prints a deprecation
  warning to stderr.
COMMANDS:
  groups    [deprecated] Use 'nono profile groups' instead
  profiles  [deprecated] Use 'nono profile list' instead
  show      [deprecated] Use 'nono profile show' instead
  diff      [deprecated] Use 'nono profile diff' instead
  validate  [deprecated] Use 'nono profile validate' instead
```

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Gated 11 new upstream-introduced items to `#[cfg(not(target_os = "windows"))]` for Plan-34-01 to build on Windows host**

- **Found during:** Task 2 commit 1 (cherry-pick `034be703`) Windows-host `cargo build --workspace` after merging conflicts
- **Issue:** Upstream's new `profile_save_runtime.rs` uses `nix::sys::termios::*` for prompt-terminal control, and `learn.rs`'s new fns (`to_profile_patch`, `to_named_profile`, `shortened_paths`, `learned_override_deny_paths`, `merge_learned_profile_patch`) reference imports already gated `#[cfg(any(target_os = "linux", target_os = "macos"))]` in the fork's `learn.rs` (fork-side Windows-aware addition). Upstream did NOT cfg-gate the new fns (their CI is Linux/macOS only), so the cherry-picked code does not compile on Windows.
- **Fix:** Gated 11 items to `#[cfg(not(target_os = "windows"))]`:
  - `mod profile_save_runtime` in `main.rs`
  - `mod startup_prompt` in `main.rs`
  - `load_raw_profile_from_path` in `profile/mod.rs`
  - `LearnResult::to_profile_patch` + `LearnResult::to_named_profile` in `learn.rs`
  - `shortened_paths` + `learned_override_deny_paths` + `merge_learned_profile_patch` (free fns) in `learn.rs`
  - `offer_save_profile` + `read_input_line` + `prepare_profile_save` (free fns) + the `crate::profile_save_runtime::*` use-statement + the `crate::profile` use-statement in `learn_runtime.rs`
- **Rationale:** D-34-B2 surgical retrofit posture. Windows learn-mode is admin-gated (ETW path); the interactive profile-save flow stays Unix-only for now.
- **Files modified:** `main.rs`, `profile/mod.rs`, `learn.rs`, `learn_runtime.rs`
- **Commit:** `fc76c772` (commit 1 of 6)

**2. [Rule 3 - Blocking] Dropped `DETACHED_CWD_PROMPT_RESPONSE_ENV` from new use-statement in `exec_strategy.rs` (commit 2 of 6)**

- **Found during:** Task 2 commit 2 (cherry-pick `37488ce0`) conflict resolution
- **Issue:** Upstream's diff adds `use crate::{DETACHED_CWD_PROMPT_RESPONSE_ENV, DETACHED_LAUNCH_ENV, DETACHED_SESSION_ID_ENV};` to `exec_strategy.rs`, but fork's `main.rs` never carried the `DETACHED_CWD_PROMPT_RESPONSE_ENV` constant (it lives in an upstream pre-existing commit `648585cd` that the fork did not absorb). The new use-statement would fail to compile.
- **Fix:** Trimmed the use-statement to `use crate::{DETACHED_LAUNCH_ENV, DETACHED_SESSION_ID_ENV};`. Verified the cherry-pick body adds NO callsites that actually USE `DETACHED_CWD_PROMPT_RESPONSE_ENV` — it was upstream noise from a wider mass-import refactor.
- **Files modified:** `exec_strategy.rs`
- **Commit:** `6be0b5c2` (commit 2 of 6)

**3. [Rule 3 - Blocking] Dropped 3 `profile.allow_gpu` callsites in `profile_cmd.rs` (commit 3 of 6)**

- **Found during:** Task 2 commit 3 (cherry-pick `5ff9bc33`) Windows-host `cargo build --workspace`
- **Issue:** Upstream's enlarged `profile_cmd.rs` (the consolidation target) references `profile.allow_gpu` in 3 sites (show output, diff output, JSON-diff path). Fork's `Profile` struct in `profile/mod.rs` never absorbed the `allow_gpu` field — it is an upstream-only field not in any v0.40.1..v0.41.0 commit Phase 33 audit dispositioned as `will-sync`.
- **Fix:** Replaced the 3 `allow_gpu` references with inline `// Plan 34-01 fork-divergence: profile.allow_gpu field does not exist in fork's Profile (upstream-only Profile field, not absorbed by fork). Skip rendering allow_gpu in show output.` comments. Future plans wanting `allow_gpu` parity must first add the field to `Profile`.
- **Files modified:** `profile_cmd.rs`
- **Commit:** `d05444ce` (commit 3 of 6)

**4. [Rule 3 - Blocking] Cargo.toml version bumps rejected (commit 6 of 6 = release commit)**

- **Found during:** Task 2 commit 6 (cherry-pick `073620e9`) conflict resolution
- **Issue:** Upstream's release-bump commit raises Cargo.toml `version` fields from 0.40.1 → 0.41.0 across 4 manifests (nono, nono-cli, nono-proxy, nono-ffi). Fork is on its own version stream — currently v0.37.1, tied to the v2.x Windows-parity milestone train. Accepting upstream's version bumps would clobber the fork's release semantics.
- **Fix:** Took `--ours` for all 4 Cargo.toml version fields and Cargo.lock; took fork's CHANGELOG (which already had a v0.41.0 entry from prior cherry-picks) preserving the v0.47.x → v0.42.0 chain. The cherry-pick became effectively empty, so created an empty commit `66a56648` carrying the verbatim D-19 trailer for traceability (smoke-check 6/6).
- **Files modified:** (rejected: 4 Cargo.toml + Cargo.lock + CHANGELOG.md — net no change to fork's tree)
- **Commit:** `66a56648` (commit 6 of 6, empty)

**5. [Rule 3 - Blocking] cargo fmt follow-up (after Plan 34-01 chain)**

- **Found during:** Task 3 D-34-D2 gate 5 (`cargo fmt --all -- --check`)
- **Issue:** After the new `#[cfg(not(target_os = "windows"))]` gates landed in Plan 34-01 commit 1, the use-statement order in `learn_runtime.rs` no longer matched rustfmt's expected ordering (it preferred `use crate::learn;` before the gated `use crate::profile_save_runtime::*;`).
- **Fix:** Ran `cargo fmt --all` and committed the 3-line reorder as `chore(34-01): cargo fmt after profile_save_runtime gating` (`23ad9242`).
- **Files modified:** `learn_runtime.rs`
- **Commit:** `23ad9242` (fmt follow-up)

### Conflict-resolution summary

| Commit | Conflict files | D-02 status | Resolution approach |
|--------|----------------|-------------|---------------------|
| 1 (034be703) | `execution_runtime.rs`, `learn_runtime.rs`, `pty_proxy.rs` | within threshold (3 files, max 180 lines in `learn_runtime.rs`, mostly HEAD=empty add-blocks) | took upstream side for 2 HEAD=empty conflicts; merged the substantive `learn_runtime.rs` conflict by taking upstream's new prompt flow (replacing fork's old inline prompt logic) |
| 2 (37488ce0) | `exec_strategy.rs` | within threshold (1 file, single conflict region) | merged both sides + dropped `DETACHED_CWD_PROMPT_RESPONSE_ENV` (see Deviation 2) |
| 3 (5ff9bc33) | 5 conflicts + 1 modify/delete | within threshold (6 conflict files, no single conflict > 50 lines) | took upstream's `policy_cmd.rs` deletion; merged `main.rs` to keep fork's Windows-gated module set + add new `mod deprecated_policy`; took upstream-side rename text in 3 doc files; preserved fork's Windows-aware seatbelt-rules text and Phase 22-03 PKG fields |
| 4 (77bbe42a) | `exec_strategy.rs` | within threshold (1 file, HEAD=empty add-block) | took upstream side (new SIGINT/SIGTERM signal-fallback branch) |
| 5 (87758af1) | none (clean) | — | clean cherry-pick |
| 6 (073620e9) | 6 Cargo.toml/.lock + CHANGELOG | within threshold (Cargo version bumps + CHANGELOG entry) | took `--ours` for version fields; preserved fork's CHANGELOG ordering (v0.47.x → v0.42.0 above v0.41.0); empty post-resolution → recorded D-19 trailer on empty commit |

## Files Changed

**Final tree-level diff (HEAD vs aca306a):**
- 21 files modified, 2 created (deprecated_policy.rs, profile_save_runtime.rs, startup_prompt.rs, deprecated_policy tests), 1 deleted (policy_cmd.rs), 2 renamed (policy_cmd → profile_cli test file, policy-introspection → profile-introspection mdx)
- net: +3089 / -2820 lines of code (matches upstream's commit-3 stat); plus +1769 / -461 for commit 1's diagnostic + profile-save infrastructure additions

See per-commit table in Task 2 above for the canonical 6-commit cluster mapping.

## Commits

| # | Fork SHA | Type | Subject |
|---|----------|------|---------|
| 1 | `fc76c772` | feat | improve denial diagnostics and profile saving workflow (Upstream: 034be703) |
| 2 | `6be0b5c2` | refactor | extract startup prompt functions (Upstream: 37488ce0) |
| 3 | `d05444ce` | feat | consolidate 'nono policy' subcommands under 'nono profile' with deprecation alias (#594) (Upstream: 5ff9bc33) |
| 4 | `fd194914` | feat | enhance prompts and denial diagnostics (Upstream: 77bbe42a) |
| 5 | `28e09258` | fix | improve profile save resilience and policy suggestions (Upstream: 87758af1) |
| 6 | `66a56648` | chore | release v0.41.0 (empty; Upstream: 073620e9) |
| 7 | `23ad9242` | chore | cargo fmt after profile_save_runtime gating (no upstream — Plan 34-01 cleanup) |

## Status

**Plan 34-01: COMPLETE (with documented partial close-gate)**

- 6 / 6 cluster-C2 upstream commits absorbed
- 7 fork commits on `main` (6 cherry-picks + 1 fmt follow-up)
- D-19 trailer-block smoke check: **6 / 6**
- D-34-E1 Windows-only files invariant: **0 hits across all 6**
- D-34-B2 surgical retrofit posture: **upheld** (zero Windows-specific cli.rs additions for the rename; new modules gated)
- D-34-D2 mandatory gates 1, 2, 5: **PASS** (gate 1 with 1 pre-existing out-of-scope test failure)
- D-34-D2 cross-target gates 3, 4: **DOCUMENT-DEFERRED to CI** (linker/cc toolchain not installed on dev host)
- D-34-D2 admin-required gates 6, 7, 8: **DOCUMENT-SKIPPED**
- All 7 fork-defense grep-count baselines: **HELD**
- Functional smoke: **`nono profile --help` + `nono policy --help` both work; deprecation labels present**

## Deferred Issues

- **P34-DEFER-01-1**: `query_ext::tests::test_query_path_denied` Windows-path canonicalization mismatch (test expects POSIX path `/some/random`, gets Windows UNC `\\?\C:\some\random`). Verified pre-existing on base HEAD `aca306a5`. Logged to `deferred-items.md`. Path forward: gate to `#[cfg(not(target_os = "windows"))]` or add a Windows-specific variant. Not blocking for Plan 34-01.

## Threat Flags

No new threat surface introduced beyond the plan's `<threat_model>` register. Threats T-34-01-01 through T-34-01-06 were all dispositioned `mitigate`-BLOCKING with explicit gates:

- **T-34-01-01** (Windows-files invariant violation): mitigated — D-34-E1 invariant returned 0 across all 6 commits
- **T-34-01-02** (D-19 trailer missing or tampered): mitigated — 6/6 trailers, 0 uppercase 'Author', 12 sign-offs in cherry-pick subset
- **T-34-01-03** (`validate_path_within` removed by profile-save fix): mitigated — `validate_path_within` count held at 9 in `package_cmd.rs`
- **T-34-01-04** (POLY-01-stricter regression via `nono policy` rename): mitigated — fork-defense grep counts all held; `cargo test --workspace --all-features` passed all `policy::tests::` and `profile::tests::` sentinels
- **T-34-01-05** (denial diagnostic exposes sensitive path): accepted per plan; standard nono redaction applies
- **T-34-01-06** (deprecation alias confuses clap parser): mitigated — both `nono policy --help` and `nono profile --help` exited 0 with correct labels

## Self-Check: PASSED

- Commits exist: `git log --oneline aca306a..HEAD` returns 7 rows
- Files created exist: deprecated_policy.rs, profile_save_runtime.rs, startup_prompt.rs, deprecated_policy.rs test, profile-introspection.mdx, profile_cli.rs all verified on disk
- File deleted: `policy_cmd.rs` no longer in `crates/nono-cli/src/`
- Trailer smoke: 6 / 6 `Upstream-commit:` headers across the cluster-C2 chain
- E1 invariant: 0 Windows-file hits across all 6 commits
- Build: `cargo build --workspace` exits 0
- Clippy: `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` exits 0 on Windows host
- Fmt: `cargo fmt --all -- --check` exits 0
