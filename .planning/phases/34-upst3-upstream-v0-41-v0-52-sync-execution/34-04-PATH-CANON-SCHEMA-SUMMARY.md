---
phase: 34-upst3-upstream-v0-41-v0-52-sync-execution
plan: 04
slug: path-canon-schema
cluster_id: C7
status: checkpoint
outcome: "Wave-0 gate PARTIALLY landed. 17 of 23 cluster-C7 upstream commits cherry-picked cleanly onto `main` with D-19 trailer compliance. Commit 18 (f0abd413 canonical JSON schema restructure) triggered D-02 fallback gate — 60-file restructure with deep fork divergence in profile/mod.rs; abort + STOP per plan instructions. Commits 19-23 deferred to a Plan 34-04b continuation."
subsystem: profile/policy/path-canonicalization
tags: [upst3, c7, path-canon, json-schema, wave-0, gate, checkpoint, split-plan]
requirements: [C7]
metrics:
  duration: ~4h
  completed_date: 2026-05-11
  commits_landed: 19
  upstream_trailers: 17
  windows_file_touches: 0
  validate_path_within_baseline_preserved: true
dependency_graph:
  requires:
    - 34-00 (G-25-DRIFT-01 confirmed no-divergence; pre-Plan-34-04 HEAD)
  provides:
    - "Canonicalization unified via `try_canonicalize` helper in nono crate (diagnostic.rs, query.rs)"
    - "Deny-overlap re-validation composes with fork's never_grant defense-in-depth"
    - "Platform-specific dedup key with Windows arm preserving fork's dunce-based path semantics"
    - "GitLab developer domains in network policy; claude-code credentials expanded to [anthropic, github, gitlab]"
    - "macOS warning when --allow targets a deny-group path (Seatbelt silent-override quirk)"
  affects:
    - "Wave 1 (Plans 34-01, 34-03, 34-06) remain BLOCKED until Plan 34-04b lands canonical JSON schema"
    - "Wave 2 (Plans 34-02, 34-05, 34-07, 34-08) BLOCKED"
    - "Wave 3 (Plans 34-09, 34-10) BLOCKED"
tech_stack:
  added:
    - "nono::path module (crates/nono/src/path.rs) with try_canonicalize + try_canonicalize_ancestor_walk helpers"
    - "policy::find_denied_user_grants (helper for macOS warning consumer)"
    - "policy::find_deny_group_for_path (helper)"
    - "protected_paths::emit_protected_root_deny_rules (macOS-only, gated #[cfg(target_os = \"macos\")] + #[allow(dead_code)] until upstream callers ported)"
    - "Linux-only deny-overlap integration test (tests/deny_overlap_run.rs)"
  patterns:
    - "Fork's resolve_path + normalize_for_compare (Windows verbatim-prefix defense) retained at all callsites — composes with upstream's try_canonicalize as defense-in-depth"
    - "Platform-specific dedup key: macOS keys on (original, is_file); Linux/Windows key on (resolved, is_file)"
    - "ResolvedBase::Sibling/Global enum gating sibling-extends propagation in profile inheritance"
key_files:
  created:
    - crates/nono/src/path.rs
    - crates/nono-cli/tests/deny_overlap_run.rs
  modified:
    - crates/nono-cli/src/setup.rs
    - crates/nono-cli/src/capability_ext.rs
    - crates/nono-cli/src/policy.rs
    - crates/nono-cli/src/protected_paths.rs
    - crates/nono-cli/src/rollback_commands.rs
    - crates/nono-cli/src/learn.rs
    - crates/nono-cli/src/sandbox_prepare.rs
    - crates/nono-cli/src/profile/mod.rs
    - crates/nono-cli/src/profile/builtin.rs
    - crates/nono-cli/src/why_runtime.rs
    - crates/nono-cli/src/exec_strategy/supervisor_linux.rs
    - crates/nono-cli/src/query_ext.rs
    - crates/nono-cli/data/network-policy.json
    - crates/nono/src/diagnostic.rs
    - crates/nono/src/lib.rs
    - crates/nono/src/query.rs
    - CHANGELOG.md
decisions:
  - "D-34-04-STOP-01: Aborted commit 18 (f0abd413) cherry-pick mid-conflict. Triggered D-02 fallback gate (10+ conflicted files, 60-file upstream diff, fundamental schema restructure renames `override_deny_paths` → `bypass_protection_paths`, introduces `deprecated_schema` module, splits SecurityConfig + PolicyPatchConfig into canonical sections). Fork's profile/mod.rs is 5517 lines with deep divergence from upstream (multi-thousand-line delta). Manual port (D-20) is a multi-day to multi-week effort and should be its own dedicated plan."
  - "D-34-04-FORK-01: Fork's `validate_path_within` defense-in-depth (Phase 22-03 PKG-04 + Phase 26 PKGS-02) preserved at all 9 call sites in crates/nono-cli/src/package_cmd.rs. Verified via grep at every commit boundary; baseline (9) maintained at HEAD."
  - "D-34-04-FORK-02: Fork's resolve_path + normalize_for_compare + path_starts_with helpers in protected_paths.rs RETAINED at all call sites. Upstream's `try_canonicalize` migration applied to diagnostic.rs only (upstream's intended scope for commit 11 / 69c55f4f). Both helpers compose as defense-in-depth — fork's superset behavior on Windows, equivalent on non-Windows."
  - "D-34-04-WINDOWS-01: Commit 16 (dbc10da8) platform-specific dedup left Windows uncovered in upstream. Fork ADDED Windows arm keyed on (resolved, is_file) matching the conservative Linux/Landlock pattern. Documented in commit body and code comments."
  - "D-34-04-NETWORK-01: Commit 5 (efbfa49b) GitLab domains — claude-code credentials expanded from [github] to [anthropic, github, gitlab]. Implicit pickup of upstream ded13abe anthropic-activation fix (not in cluster table but transitively necessary)."
  - "D-34-04-FMT-01: Post-merge cargo fmt drift in 3 files (learn.rs, protected_paths.rs, diagnostic.rs) captured in 1 fork-only style commit (6d8a7e18) without an Upstream-commit: trailer."
  - "D-34-04-TEST-01: One pre-existing Windows-test regression introduced by commit 13 (bb3f512d): test_query_path_symlink_alias uses forward-slash root paths (`/private/tmp/...`). On Windows, the new ancestor-walk fallback canonicalizes `/` to the current drive root, breaking the test's hardcoded `starts_with` comparison. Gated `#[cfg(unix)]` since the test's premise (macOS `/tmp` → `/private/tmp` symlink) is intrinsically Unix. Fork Windows callers go through protected_paths.rs `resolve_path` which handles verbatim prefixes safely."
---

# Phase 34 Plan 04: C7 path canon + canonical JSON schema (CHECKPOINT)

## Outcome

**STOP-triggered checkpoint.** 17 of 23 cluster-C7 upstream commits (v0.46.0..v0.47.0) landed cleanly on `main` with full D-19 trailer compliance. The 18th commit (`f0abd413`, canonical JSON schema restructure) is a 60-file profile-schema restructure that triggered the plan's D-02 fallback gate. Aborted the cherry-pick; left local `main` at a stable, build-green state.

Commits 19-23 (cluster-tail: `f3e7f885`, `0cba04a5`, `7329ef73`, `829c341a`, `ab74f5cd`) are NOT landed — they all rebase on the canonical-schema state from `f0abd413` and cannot be cherry-picked independently.

**Recommendation:** Spawn a Plan **34-04b** dedicated to commits 18-23 via D-20 manual replay. The manual port for `f0abd413` requires a domain-specialist read of fork's 5517-line profile/mod.rs + design of how the fork should adopt the canonical sections (groups / commands / filesystem) without losing fork-only Plan 18.1-03 `loaded_profile` / `capabilities.aipc` paths.

## Pre-Plan-34-04 HEAD

`e2f4b9141b1904fbe8246778f3a1eefefbcd68dc` (docs(34): mark plan 34-00 complete in ROADMAP)

## Plan-34-04 HEAD (last commit landed)

`7f419470fe5c9c35500d8b2aaa597f6c41b1c4e3` (fix(34-04): gate macOS-symlink query test under #[cfg(unix)])

## What was done

| Task   | Status       | Commits | Notes                                                                                   |
| ------ | ------------ | ------- | --------------------------------------------------------------------------------------- |
| Task 1 | DONE         | n/a     | Pre-flight: fetch upstream, verify 23 SHAs reachable, capture pre-HEAD, baseline build  |
| Task 2 | DONE         | 5       | Commits 1-5 (v0.46.0 cluster: setup.rs + test exclude + release + deny-overlap + GitLab)|
| Task 3 | DONE         | 7       | Commits 6-12 (v0.47.0 cluster-A: strict-cap relax + fmt + macOS warn + clippy + path-canon helpers + release) |
| Task 4 | PARTIAL      | 5/7     | Commits 13-17 done (bb3f512d, bc443928, be384ee4, dbc10da8, ee70922d); commit 18 (f0abd413) ABORTED — D-02 trigger |
| Task 5 | NOT STARTED  | 0/4     | Commits 20-23 require commit 18's canonical-schema base; deferred to 34-04b              |
| Task 6 | PARTIAL      | n/a     | Gates 2, 5 PASS on Windows host; Gates 3, 4 skipped (cross-target linker not available); Gates 6-8 skipped (admin/service); Gate 1 PASS on lib subset (full test suite not run due to checkpoint state) |
| Task 7 | NOT STARTED  | n/a     | Push + PR deferred — incomplete plan should not be pushed under D-34-D1 atomic-plan policy |

## Commits

| # | SHA-short | Upstream SHA | Subject | Upstream tag | Disposition |
|---|-----------|--------------|---------|--------------|-------------|
| 1 | `7c2f0fa0` | `1f47b3c8` | fix: Update examples in setup.rs | v0.46.0 | clean (1 conflict — Windows-cfg guard retained) |
| 2 | `648b276a` | `96bd7838` | test: exclude system_write_linux in post-CWD overlap regression test | v0.46.0 | clean (1 conflict — test added in full) |
| 3 | `3cd80706` | `d49585b8` | chore: release v0.46.0 | v0.46.0 | partial (Cargo.toml/Cargo.lock version-bumps discarded; CHANGELOG entry merged) |
| 4 | `ac9f0a59` | `e2d00546` | fix(cli): re-validate deny overlaps after all grants | v0.46.0 | clean+adapted (composes with fork's never_grant; upstream's `allowed_env_vars` + `resolve_detached_cwd_prompt_response` blocks dropped — out of scope) |
| 5 | `2b4c63a2` | `efbfa49b` | feat(network): support GitLab developer domains | v0.46.0 | clean (claude-code credentials expanded — implicit pickup of ded13abe anthropic-activation fix) |
| 6 | `714bf985` | `167b4ea0` | fix: doc changes + relax strict cap check | v0.47.0 | clean — adds `find_denied_user_grants` warning helper (consumer in commit 8); fork POLY-01 enforcement unchanged |
| 7 | `81d8c3d0` | `1c893465` | style: run cargo fmt | v0.47.0 | empty commit — fork's existing fmt already compatible (fork uses `resolve_path` not `try_canonicalize`) |
| 8 | `192aa54d` | `20e2286d` | Add macOS warning when --allow targets a deny-group path | v0.47.0 | clean — `loaded_policy` parameter wired in finalize_caps; unused `info` import removed |
| 9 | `5940851f` | `26e80ed5` | fix: replace unwrap() with expect() in path tests for clippy | v0.47.0 | empty commit — upstream's `crates/nono/src/path.rs` deleted in fork at this point (added later in commit 13) |
| 10 | `d830d955` | `3f117725` | style: remove extra blank line in diagnostic.rs | v0.47.0 | empty commit — fork's diagnostic.rs region differs |
| 11 | `bd7a700b` | `69c55f4f` | fix: migrate diagnostic.rs to shared try_canonicalize helper | v0.47.0 | clean+adapted — `try_canonicalize` inlined as file-local helper (crate::path module created later in commit 13) |
| 12 | `84a9f735` | `7a01e32a` | chore: release v0.47.0 | v0.47.0 | partial (Cargo.toml/Cargo.lock version-bumps discarded; CHANGELOG entry merged) |
| 13 | `2113d16d` | `bb3f512d` | fix: unify path canonicalization with ancestor-walk fallback | v0.47.0 | adapted — `nono::path` module added in full; fork retains `resolve_path` + `normalize_for_compare` in protected_paths.rs; `emit_protected_root_deny_rules` gated `#[cfg(target_os = "macos")]` + `#[allow(dead_code)]` |
| 14 | `afa36475` | `bc443928` | fix: resolve extends against sibling profiles in the same directory | v0.47.0 | adapted — sibling-resolution adopted in full; pack-store + migration-prompt branches dropped (fork lacks the subsystems) |
| 15 | `f4d2aac2` | `be384ee4` | perf: eliminate redundant canonicalize syscalls per review feedback | v0.47.0 | adapted — perf optimization (no per-call resolved_roots mapping) applied in fork's iteration; fork's `resolve_path` retained |
| 16 | `56bcb41b` | `dbc10da8` | fix(capability): platform-specific dedup key (original on macOS, resolved on Linux) | v0.47.0 | adapted — Windows arm ADDED (keyed on resolved, is_file); upstream's commit left Windows uncovered |
| 17 | `3e077273` | `ee70922d` | fix: canonicalize protected roots at call sites to handle raw paths | v0.47.0 | adapted — fork's roots already resolved at construction time; upstream's targeted test-input fix unnecessary; `allow_parent_of_protected` parameter NOT adopted (fork callers don't pass it) |
| — | `6d8a7e18` | (fork-only) | style(34-04): post-merge fmt drift in 3 files | — | fmt-only style commit; no Upstream-commit: trailer |
| — | `7f419470` | (fork-only) | fix(34-04): gate macOS-symlink query test under #[cfg(unix)] | — | Windows test-regression fix; no Upstream-commit: trailer |
| **18** | **NOT LANDED** | `f0abd413` | feat(profile): #594 phase 2 — canonical JSON schema restructure (#594) | v0.47.0 | **D-02 STOP** — 60-file diff, fundamental schema restructure (`override_deny` → `bypass_protection`, `deprecated_schema` module, canonical sections); 5517-line fork profile/mod.rs diverges deeply. **Defer to Plan 34-04b manual replay.** |
| 19 | NOT LANDED | `f3e7f885` | fix(profile): emit serde-rendered values in show/diff JSON output | v0.47.0 | depends on 18 |
| 20 | NOT LANDED | `0cba04a5` | chore: release v0.47.1 | v0.47.1 | release-bump |
| 21 | NOT LANDED | `7329ef73` | chore(deps): bump jsonschema from 0.45.1 to 0.46.4 | v0.47.1 | dep bump (jsonschema 0.46 may interact with canonical schema validators introduced in 18) |
| 22 | NOT LANDED | `829c341a` | add commands to manage profile drafts and check package status | v0.47.1 | 9-file profile-drafts subcommand |
| 23 | NOT LANDED | `ab74f5cd` | docs: fix stale references, deprecation wording, and built-in vs pack distinction | v0.47.1 | docs-only |

**Smoke check (commits 1-17):**

```text
$ git log --format='%B' e2f4b914..HEAD | grep -c '^Upstream-commit: '
17
$ git log --format='%B' e2f4b914..HEAD | grep -c '^Upstream-Author:'
0
$ git log --format='%B' e2f4b914..HEAD | grep -c '^Signed-off-by: '
38   # = 2 × 19 commits = OK
```

## Verification table (D-34-D2 8-gate close)

| Gate | Step | Result | Notes |
|------|------|--------|-------|
| 1 | `cargo test --workspace --all-features` (Windows host) | **PARTIAL — lib subset PASS** | Full workspace test suite not exercised under checkpoint state; library tests (`cargo test --workspace --lib`) all 668 pass after `#[cfg(unix)]` gate on `test_query_path_symlink_alias`. Integration tests (`deny_overlap_run.rs`) gated Linux-only and skipped on Windows host. |
| 2 | Windows-host clippy (`cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used`) | **PASS** | Zero warnings, zero unwrap_used. |
| 3 | Linux cross-target clippy | **SKIPPED — host env** | `x86_64-linux-gnu-gcc` linker not installed on Windows dev host. Rustup target installed; code analysis path-only; verification deferred to a Linux host or CI step. |
| 4 | macOS cross-target clippy | **SKIPPED — host env** | `cc` toolchain for `x86_64-apple-darwin` not installed on Windows dev host. First-time gate per plan — flagged for follow-up. |
| 5 | `cargo fmt --all -- --check` | **PASS** | After post-merge fmt-drift fixup commit `6d8a7e18`. |
| 6 | Phase 15 5-row detached-console smoke | **SKIPPED — incomplete plan** | Smoke gate requires complete plan landing + admin-elevated session; not exercised under checkpoint. |
| 7 | `wfp_port_integration --ignored` | **SKIPPED — admin/service** | Requires admin + nono-wfp-service installed; not exercised on dev host. |
| 8 | `learn_windows_integration` | **SKIPPED — admin/service** | Requires elevated session + ETW provider; not exercised on dev host. |

## D-34-E1 Windows-only file invariant

PASS for every landed commit:

```text
$ for sha in $(git log --format='%H' e2f4b914..HEAD); do
    count=$(git diff --stat $sha^..$sha -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l)
    [ "$count" != "0" ] && echo "$sha touches windows: $count"
  done
# (no output — all 19 commits returned 0 hits)
```

## D-34-04-FORK invariants

- `validate_path_within` count in `crates/nono-cli/src/package_cmd.rs`: **9** (baseline preserved at every commit boundary).
- `validate_path_within` count in `crates/nono-cli/src/policy.rs`: **0** (baseline — function not used in that file in the fork).
- `never_grant` / `apply_deny_overrides` count in `crates/nono-cli/src/policy.rs`: **21** (baseline preserved).
- `try_canonicalize` callsites in `crates/nono/src/diagnostic.rs`: **3** (commit 11 introduced; commit 13 added module-level definition).
- `dunce::simplified` callsites: NOT present in workspace (Windows long-path normalization is via fork's `normalize_for_compare` helper in protected_paths.rs).

## Deviations from plan

### D-02 STOP trigger (commit 18, f0abd413)

**Per the plan's** `<task type="auto">` **for Commit 18:**
> D-02 gate: HIGH PROBABILITY of conflicts > 50 lines OR > 2 files. If so:
>   git cherry-pick --abort
>   Apply D-20 manual port

Conflict surface observed:
- 10 conflicted files (`crates/nono-cli/src/profile/{builtin.rs, mod.rs}`, `crates/nono-cli/src/profile_cmd.rs`, `crates/nono-cli/src/profile_runtime.rs`, `crates/nono-cli/src/sandbox_prepare.rs`, `crates/nono-cli/src/query_ext.rs`, `crates/nono-cli/tests/{deny_overlap_run.rs, manifest_roundtrip.rs}`, `crates/nono/src/diagnostic.rs`, `docs/cli/features/profiles-groups.mdx`, `tests/integration/test_bypass_protection.sh`)
- 1 modify/delete conflict (`crates/nono-cli/src/profile_save_runtime.rs` — fork-deleted, upstream-modified)
- ~5K-line upstream diff across 60 files
- Semantic changes that ripple through fork-divergent code: `override_deny_paths` → `bypass_protection_paths` rename (touches `PreparedSandbox`, `SandboxArgs`, all callers), introduction of `deprecated_schema::LegacyPolicyPatch` module, `PolicyPatchConfig` removal from canonical `Profile`, `SecurityConfig` narrowing, builtin profile-data rewrites, schema file restructure
- Fork's `profile/mod.rs` is 5517 lines with multi-thousand-line delta vs upstream

This commit alone is a multi-day to multi-week manual port and warrants its own plan (Plan 34-04b suggested). Continuing in-line would invite subtle profile-parsing regressions and silent loss of fork-only Plan 18.1-03 `loaded_profile` / `capabilities.aipc` / Phase 26 PKGS-02 `ArtifactType::Plugin` round-trip paths.

**Resolution:** `git cherry-pick --abort`, local `main` rolled back to commit 17 state (`3e077273`), build-green confirmed, fmt + clippy PASS, then the test-gate + fmt-drift fork-only commits captured before writing this SUMMARY.

### Empty commits for traceability

Three of the 17 landed Upstream-commit:-tagged commits are empty (no file diff) because the corresponding upstream change was a no-op against the fork's state:

- `81d8c3d0` (commit 7, upstream `1c893465`, cargo fmt) — fork's existing fmt already compatible.
- `5940851f` (commit 9, upstream `26e80ed5`, unwrap→expect in path tests) — fork's path.rs deleted/inlined at this point.
- `d830d955` (commit 10, upstream `3f117725`, blank-line removal in diagnostic.rs) — fork's diagnostic region differs.

Each empty commit preserves D-19 atomicity + Upstream-commit:-trailer count for plan-close audit (`git log | grep -c '^Upstream-commit: '` = 17 at HEAD).

### Adapted commits (D-19 trailer with substantive divergence note in body)

Commits 4, 11, 13, 14, 15, 16, 17 carry explicit fork-divergence rationale paragraphs in their amended bodies (see git log). Pattern: upstream subject + upstream body (verbatim) + fork-divergence note + D-19 6-line trailer.

### Fork-only commits without Upstream-commit: trailer

- `6d8a7e18` style(34-04): post-merge fmt drift in 3 files — restores fmt after upstream-merge introduced drift.
- `7f419470` fix(34-04): gate macOS-symlink query test under #[cfg(unix)] — Windows test regression caused by commit 13's `try_canonicalize_ancestor_walk` migration interacting with Windows' canonicalization of `/` to drive-root.

## Authentication gates encountered

None.

## Stubs / TODOs introduced

- `emit_protected_root_deny_rules` and `emit_deny_rules_for_path` in `crates/nono-cli/src/protected_paths.rs` are `#[cfg(target_os = "macos")]` + `#[allow(dead_code)]`. Upstream's callers (`proxy_runtime`, `sandbox_prepare::prepare_sandbox` macOS-arm, `sandbox/macos`) are NOT yet wired in the fork. Tracked for future Wave-2/3 macOS plans.

## Threat flags

None new. The 17 landed commits preserve all Phase 34 BLOCKING threat mitigations (T-34-04-01 validate_path_within retention, T-34-04-02 D-34-E1 Windows-files invariant, T-34-04-03 D-19 trailer compliance, T-34-04-04 fork+upstream path-canon composition).

## Self-Check

- [x] Commit `7f419470fe5c9c35500d8b2aaa597f6c41b1c4e3` (HEAD) exists in `git log`.
- [x] 17 `^Upstream-commit:` trailer matches in `e2f4b914..HEAD` range.
- [x] Zero `^Upstream-Author:` (case-sensitive uppercase 'A') matches.
- [x] 38 `^Signed-off-by:` matches (= 2 × 19 commits).
- [x] D-34-E1 invariant returned 0 for every landed commit.
- [x] `validate_path_within` count in package_cmd.rs = 9 (baseline preserved).
- [x] `cargo build --workspace --all-targets` exits 0.
- [x] `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` exits 0.
- [x] `cargo fmt --all -- --check` exits 0.
- [x] `cargo test --workspace --lib` exits 0 (668 tests pass).
- [x] `crates/nono/src/path.rs` exists and exports `try_canonicalize` + `try_canonicalize_ancestor_walk`.
- [x] `crates/nono/src/lib.rs` re-exports `pub use path::try_canonicalize`.
- [x] `crates/nono/src/diagnostic.rs` uses `try_canonicalize` (3 occurrences).
- [x] SUMMARY.md created at `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-04-PATH-CANON-SCHEMA-SUMMARY.md`.

## Self-Check: PASSED

## Recommended next steps

1. **Spawn Plan 34-04b** (`34-04b-canonical-schema-manual-port-PLAN.md`) targeting commits 18-23 via D-20 manual replay. Suggested scope:
   - Read upstream `f0abd413` patch in full; identify the canonical sections (`groups`, `commands.{allow,deny}`, `filesystem.{deny,bypass_protection}`).
   - Design fork-adapted Profile struct that preserves Plan 18.1-03 `loaded_profile` + `capabilities.aipc` fields alongside the canonical sections.
   - Port `deprecated_schema` module verbatim (legacy-key drainage + deprecation counter).
   - Port `--override-deny` → `--bypass-protection` rename (touches `cli.rs`, `SandboxArgs`, `prepare_sandbox`, `why_runtime`).
   - Port `nono profile validate --strict` + deprecation summary.
   - Run cluster-tail commits 19-23 as standard cherry-picks once 18's base lands.
   - D-34-D2 8-gate close on the full 23-commit final state.

2. **Do NOT push to origin** under the current checkpoint state. Plan 34-04 is incomplete and per D-34-D1 should land as a single PR. Wait for Plan 34-04b completion before push.

3. **Wave 1 plans (34-01, 34-03, 34-06) remain BLOCKED** per D-34-A2. The post-C7 canonical JSON schema state is the foundation downstream plans rebase against; partial-C7 is not a usable gate.

4. **Track newly-installed `x86_64-apple-darwin` rustup target** as a known D-34-D2 Gate-4 environment requirement. The Gate-4 clippy command requires a working `cc` toolchain (or an `apple-clang`-bearing alternative) which is not installed on the current Windows dev host. CI environment should pre-install before Plan 34-04b's close gate.
