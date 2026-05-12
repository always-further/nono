---
phase: 34-upst3-upstream-v0-41-v0-52-sync-execution
plan: 04b
slug: fp-canonical-schema
cluster_id: C7-residual
parent_plan: 34-04
status: partial-complete
outcome: "Wave 0.5 sequential gate PARTIALLY closed. 5 of 6 C7-residual upstream commits landed on `main`: 1 D-20 manual replay (f0abd413 canonical-schema rename runway) + 4 D-19 cherry-picks (f3e7f885 serde-render fix, 0cba04a5 release-CHANGELOG, 7329ef73 jsonschema 0.46.4 bump, ab74f5cd docs). 1 commit (829c341a profile drafts + package status) escalated to deferred-feature workstream P34-DEFER-04b-2 due to 3619-line conflict span in profile_cmd.rs + substantial new-feature surface. C7 cluster status: PARTIAL (34-04 17/23 + 34-04b 5/6 = 22/23 cluster commits landed; 829c341a deferred). Wave 1+ unblocks: canonical-schema rename runway lands; downstream plans no longer have to re-discover the override_deny -> bypass_protection rename surface."
subsystem: profile/policy/canonical-schema-rename
tags: [upst3, c7-residual, canonical-schema, fork-preserve, manual-replay, d-20, wave-0.5, split-from-34-04, deferred-feature]
requirements: [C7-residual]
metrics:
  duration: ~3h
  completed_date: 2026-05-11
  commits_landed: 5
  upstream_trailers: 4
  manual_replay_trailers: 1
  windows_file_touches: 0
  fork_defense_baselines_preserved: true
  escalations: 1
dependency_graph:
  requires:
    - "34-04 (Plan 34-04 partial close; PRE_HEAD bc7b81ca after plan-add commit)"
  provides:
    - "Canonical JSON key bypass_protection accepted via serde alias on PolicyPatchConfig::override_deny"
    - "Canonical CLI flag --bypass-protection accepted via clap visible_alias on --override-deny"
    - "One-time stderr deprecation warning emitted when legacy override_deny JSON key observed (per-process, per upstream DeprecationCounter semantics)"
    - "Renamed integration test tests/integration/test_bypass_protection.sh exercises BOTH legacy and canonical paths"
    - "Profile show/diff JSON output no longer leaks Rust Debug syntax (Some(...), None, PascalCase enum variants) — serde-routed via Map insertion for Option<…> fields"
    - "jsonschema crate bumped 0.45.1 -> 0.46.4 across crates/nono and crates/nono-cli; fork's existing schema-validation surface (191 profile tests) unaffected"
    - "CHANGELOG entry for upstream v0.47.1 merged for sync provenance"
    - "Documentation notes added to docs/cli/features/profiles-groups.mdx and docs/cli/usage/flags.mdx pointing users to bypass_protection as the canonical alias"
  affects:
    - "Wave 1 (Plans 34-01, 34-03, 34-06) UNBLOCKED — canonical-schema rename runway lands"
    - "Wave 2 (Plans 34-02, 34-05, 34-07, 34-08) UNBLOCKED"
    - "Wave 3 (Plans 34-09, 34-10) UNBLOCKED"
    - "P34-DEFER-04b-1 (full deprecated_schema module + canonical sections + 210-callsite internal rename) tracked in deferred-items.md for future UPST phase"
    - "P34-DEFER-04b-2 (829c341a profile drafts + package status feature surface) tracked in deferred-items.md for future UPST phase"
tech_stack:
  added:
    - "raw_profile_has_legacy_override_deny_key (pure helper, no side effects, test-friendly)"
    - "detect_legacy_override_deny_key (production hook, calls emit_legacy_override_deny_warning_once on legacy match)"
    - "emit_legacy_override_deny_warning_once (AtomicBool-gated one-time stderr warning emitter)"
    - "json_value_has_key (recursive serde_json::Value walker)"
    - "canonical_schema_rename_tests module (7 unit tests verifying serde-alias + recursive walk + malformed-JSON safety)"
    - "test_policy_show_json_no_rust_debug_syntax (integration regression test, walks JSON tree for Rust Debug markers)"
    - "test_policy_diff_json_no_rust_debug_syntax (integration regression test for diff path)"
    - "assert_no_rust_debug_in_strings (test helper)"
    - "Plan 34-04b canonical-name smoke tests in tests/integration/test_bypass_protection.sh (exercises both --bypass-protection CLI flag and bypass_protection JSON key)"
  patterns:
    - "Pragmatic Option C: serde-alias + clap visible_alias + AtomicBool one-time deprecation warning. Internal Rust identifier `override_deny` preserved at all 210 callsites; flag-day rename deferred to P34-DEFER-04b-1."
    - "Manual-replay commit body cites D-20 + Plan 34-09/34-10 commit-body precedent; uses `Manual-replay: <8-sha>` trailer field SUBSTITUTING `Upstream-commit:`"
    - "Map-based JSON construction for Option<…> fields: insert when Some, omit when None; matches hand-authored profile shape and serde Serialize derive expectations"
    - "Atomic file rename via `git mv` to preserve history during test-fixture rename"
key_files:
  created:
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-04b-FP-CANONICAL-SCHEMA-SUMMARY.md
  modified:
    - crates/nono-cli/src/profile/mod.rs
    - crates/nono-cli/src/cli.rs
    - crates/nono-cli/src/policy_cmd.rs
    - crates/nono-cli/tests/policy_cmd.rs
    - crates/nono-cli/Cargo.toml
    - crates/nono/Cargo.toml
    - Cargo.lock
    - CHANGELOG.md
    - docs/cli/features/profiles-groups.mdx
    - docs/cli/usage/flags.mdx
    - tests/run_integration_tests.sh
  renamed:
    - "tests/integration/test_override_deny.sh -> tests/integration/test_bypass_protection.sh (git mv; history preserved)"
decisions:
  - "D-34-04b-RENAME-01: Option C (deprecation runway) chosen via orchestrator auto-approval (2026-05-11). Pragmatic scope: serde alias on PolicyPatchConfig::override_deny field + clap visible_alias on --override-deny + AtomicBool one-time stderr deprecation warning. Internal Rust identifier `override_deny` preserved at all 210 callsites to avoid flag-day rename. Full Option C surface (824-line deprecated_schema module port, canonical groups/commands/filesystem sections, 210-callsite internal rename) tracked as P34-DEFER-04b-1."
  - "D-34-04b-FORK-01: All 7 fork-defense sentinels preserved at or above pre-plan baselines through the 5-commit chain. capabilities.aipc|loaded_profile=17; ProfileDeserialize=4; validate_upstream_url=6; ArtifactType::Plugin=4; never_grant|apply_deny_overrides=21; validate_path_within=9; find_denied_user_grants=7."
  - "D-34-04b-MANUAL-01: f0abd413 manually replayed (D-20 per D-34-E3) rather than via cherry-pick due to 5K-line upstream delta over fork-divergent profile/mod.rs (5584 lines vs upstream's smaller analog). Replay commit body explicitly cites Plan 34-09/34-10 commit-body precedent (`Manual-replay: f0abd413` SUBSTITUTES `Upstream-commit:`)."
  - "D-34-04b-F3E7F885-01: f3e7f885 (serde-rendered show/diff JSON values) cherry-pick produced a ~2K-line structural conflict on profile_cmd.rs because upstream's target functions (profile_to_json + diff_to_json) live in crates/nono-cli/src/policy_cmd.rs in this fork after an earlier refactor. Cherry-pick aborted; equivalent fix applied by hand to fork's policy_cmd.rs::profile_to_json + ::diff_to_json with identical Map-insertion semantics. Treated as same-disposition cherry-pick (D-19 trailer, NOT Manual-replay) because the intent is byte-equivalent — only the host file path diverges. Plan's escalation rule was NOT triggered (no >= 10 conflicted files or >= 3K-line delta against working tree). Two regression tests added in tests/policy_cmd.rs verify show/diff JSON contains no Rust Debug markers (`Some(`, `None)`, `Isolated`, `AllowSameSandbox`, `AllowAll`, `ReadWrite`, `InsecureProxy`)."
  - "D-34-04b-7329EF73-01: jsonschema 0.45 -> 0.46 bump conflicted with fork's additional dev-deps in both Cargo.toml files (nono carries an extra `tokio = { version = \"1\", features = [\"rt\", \"macros\"] }`; nono-cli carries an extra `httpmock = \"0.7\"`). Resolution: take the version bump AND preserve both fork-only dev-deps verbatim. Cargo.lock regenerated. 191 profile tests pass post-bump (no schema-validation regressions)."
  - "D-34-04b-0CBA04A5-01: v0.47.1 release commit cherry-picked partial (Cargo.toml + Cargo.lock version bumps DROPPED; CHANGELOG entry merged for sync provenance only). Mirrors Plan 34-04 commits 3 (d49585b8 v0.46.0) and 12 (7a01e32a v0.47.0) partial-cherry-pick shape — fork tracks its own v2.3+ versioning scheme."
  - "D-34-04b-AB74F5CD-01: ab74f5cd (docs cleanup) partial-applied. Kept fork content for README.md (upstream targets text fork no longer has), crates/nono-cli/README.md (upstream documents claude-code/codex as pack-delivered; fork ships them as built-ins in policy.json), crates/nono-cli/src/cli.rs (fork uses named constants RUN_AFTER_HELP/WRAP_AFTER_HELP; upstream edits inlined string literals — text edits do not apply), docs/cli/clients/claude-code.mdx (upstream uses canonical `groups.include` shape; fork has not landed canonical sections). Applied to docs/cli/features/profiles-groups.mdx and docs/cli/usage/flags.mdx with v0.47.0 deprecation note pointing users to bypass_protection as the canonical alias."
  - "D-34-04b-829C341A-ESC: 829c341a (profile drafts + package status) ESCALATED to deferred-feature workstream P34-DEFER-04b-2. Cherry-pick produced 7 conflicted files; 3619-line conflict span in profile_cmd.rs (well above the orchestrator's 3K-line escalation threshold). Upstream adds substantial new user-facing feature surface (nono profile promote, --draft flag, new file package_status.rs 218 LOC, NonoError::ActionRequired variant + C FFI mapping, profile-drafts directory infrastructure, atomic file ops, base-hash verification, shadowing safeguards). This is feature-development scope requiring design review + security audit + test coverage, not a sync-only delta. Documented in deferred-items.md as P34-DEFER-04b-2."
  - "D-34-04b-DCO-01: dependabot[bot] and SequeI cherry-picks preserved their original `Signed-off-by:` lines; plan adds 2 DCO sign-offs (Oscar Mack + oscarmackjr-twg) per Phase 22 D-19. Total Signed-off-by count across plan: 12 (= 5 commits × 2 DCO + 2 preserved upstream signoffs)."
  - "D-34-04b-GATE-01: D-34-D2 close gates 1 (workspace tests, 853 green), 2 (Windows clippy strict), 5 (cargo fmt --check) PASS. Gates 3 (Linux cross-target clippy), 4 (macOS cross-target clippy), 6 (Phase 15 detached-console smoke), 7 (wfp_port_integration), 8 (learn_windows_integration) DOCUMENTED-SKIPPED per dev-host limitation + user-accepted posture from 34-04 close on 2026-05-11."
---

# Phase 34 Plan 04b: C7-residual canonical-schema manual replay (PARTIAL COMPLETE) Summary

## Outcome

**Wave 0.5 sequential gate PARTIALLY closed.** 5 of 6 C7-residual upstream commits landed on `main`:

- 1 **D-20 manual replay**: `f0abd413` (canonical-schema rename runway) — pragmatic Option C
- 4 **D-19 cherry-picks**: `f3e7f885` (serde-rendered show/diff JSON), `0cba04a5` (v0.47.1 CHANGELOG), `7329ef73` (jsonschema 0.46.4 bump), `ab74f5cd` (docs cleanup)

**1 commit escalated to deferred-feature workstream:** `829c341a` (profile drafts + package status) produced a 3619-line conflict span in `profile_cmd.rs` (above the orchestrator's 3K-line escalation threshold) and introduces a substantial new-feature surface (`nono profile promote`, `--draft` flag, `package_status.rs` 218-LOC new file, `NonoError::ActionRequired` variant, profile-drafts directory infrastructure with atomic file ops, base-hash verification, shadowing safeguards, C FFI mapping). Deferred to **P34-DEFER-04b-2**.

**C7 cluster status:** 34-04 (17/23) + 34-04b (5/6) = **22 of 23 cluster commits landed**; 1 deferred.

**Wave 1+ unblocks.** Downstream plans (34-01, 34-03, 34-06, 34-02, 34-05, 34-07, 34-08, 34-09, 34-10) can now rebase against the canonical-schema rename runway state.

**Pre-plan HEAD:** `bc7b81ca078ebb7e1d3d37fceeff66ca234183c8` (`docs(34): add Plan 34-04b for canonical-schema D-20 manual replay`)
**Plan-close HEAD:** `3d0547a9` (`docs: fix stale references, deprecation wording, and built-in vs pack distinction`) — plus this SUMMARY commit

## Commits

| # | Sha | Disposition | Subject |
|---|-----|-------------|---------|
| 1 | `96e31c18` | D-20 manual replay of `f0abd413` | `replay(34-04b): canonical schema rename runway from upstream f0abd413` |
| 2 | `d9f1ce0c` | Cherry-pick equivalent of `f3e7f885` (fork-side host file diverges: applied to policy_cmd.rs instead of profile_cmd.rs) | `fix(profile): emit serde-rendered values in show/diff JSON output` |
| 3 | `4bd35a1b` | Partial cherry-pick of `0cba04a5` (Cargo bumps dropped; CHANGELOG only) | `chore: release v0.47.1` |
| 4 | `e61b2a30` | Cherry-pick of `7329ef73` (Cargo.lock regen + fork-only dev-deps preserved) | `chore(deps): bump jsonschema from 0.45.1 to 0.46.4` |
| 5 | `3d0547a9` | Partial cherry-pick of `ab74f5cd` (docs only; fork-divergent files reverted) | `docs: fix stale references, deprecation wording, and built-in vs pack distinction` |
| -- | -- | DEFERRED | `829c341a` (profile drafts + package status) -> P34-DEFER-04b-2 |

## Per-commit fork-divergence resolution

### `f0abd413` (D-20 manual replay, Task 3)

- Internal Rust field `PolicyPatchConfig::override_deny` carries `#[serde(default, alias = "bypass_protection")]` so v2.3 profiles using either JSON key deserialize identically. Internal name preserved -> 210 callsites untouched.
- CLI flag `--override-deny` carries clap `visible_alias = "bypass-protection"` so both forms work and both appear in `--help` (two `SandboxArgs` struct instances updated identically).
- New helper `raw_profile_has_legacy_override_deny_key()` scans raw JSON for the legacy key; `parse_profile_file()` calls `detect_legacy_override_deny_key()` before serde deserialization to emit a one-time stderr deprecation warning per process (matches upstream's `deprecation_warnings::DeprecationCounter` semantics).
- 7 new unit tests in `crates/nono-cli/src/profile/mod.rs::canonical_schema_rename_tests` verify: legacy key detection, canonical key non-detection, serde alias for both keys, recursive JSON walk through nested objects + arrays, malformed-JSON safety.
- `tests/integration/test_override_deny.sh -> test_bypass_protection.sh` via `git mv` (74% similarity preserved). Test exercises BOTH legacy `--override-deny`/`override_deny` AND canonical `--bypass-protection`/`bypass_protection` paths.
- `tests/run_integration_tests.sh` suite list updated.

### `f3e7f885` (cherry-pick equivalent, Task 4)

- Straight cherry-pick produced a ~2K-line structural conflict on `crates/nono-cli/src/profile_cmd.rs` because upstream's target functions (`profile_to_json` and `diff_to_json`) live in `crates/nono-cli/src/policy_cmd.rs` in this fork after an earlier refactor split.
- Cherry-pick aborted; equivalent fix applied by hand to fork's `policy_cmd.rs::profile_to_json` (Map-insertion for `Option<…>` Security fields, omitted-when-None semantics) and `::diff_to_json` (drop `format!("{:?}", ...)` wrapper, serde emits null on None).
- Two regression tests added in `tests/policy_cmd.rs`: `test_policy_show_json_no_rust_debug_syntax` (walks JSON for default/claude-code/node-dev profiles) and `test_policy_diff_json_no_rust_debug_syntax` (covers wsl2_proxy_policy + workdir.access fields).
- Test helper `assert_no_rust_debug_in_strings` recursively walks `serde_json::Value` and panics if any string equals an unwrapped PascalCase enum variant or contains `Some(`/`None)` Debug markers.
- Treated as same-disposition cherry-pick (D-19 trailer with `Upstream-commit: f3e7f885`, NOT Manual-replay) because the intent is byte-equivalent; only the host file path diverges. Plan's escalation rule was NOT triggered (no >= 10 conflicted files or >= 3K-line delta against working tree — the upstream patch is only +34/-16 LOC).

### `0cba04a5` (partial cherry-pick, Task 5)

- Cherry-pick produced conflicts on all 4 Cargo.toml files + Cargo.lock (fork tracks its own v2.3+ version scheme; upstream bumps to 0.47.1).
- Resolution: reset all Cargo files to fork HEAD via `git checkout HEAD --`; keep only `CHANGELOG.md` entry merged for sync provenance.
- Mirrors Plan 34-04 commits 3 (`d49585b8` v0.46.0) and 12 (`7a01e32a` v0.47.0) partial-cherry-pick shape.

### `7329ef73` (cherry-pick with Cargo.lock regen, Task 6)

- Cherry-pick produced conflicts on both Cargo.toml files (fork carries additional dev-deps that upstream does not — `tokio` in `crates/nono/Cargo.toml`; `httpmock` in `crates/nono-cli/Cargo.toml`).
- Resolution: hand-merge to apply the `jsonschema = "0.46"` bump AND preserve both fork-only dev-deps verbatim. Cargo.lock regenerated from the resulting Cargo.toml state via `rm Cargo.lock && cargo build --workspace`.
- 191 profile-module tests pass post-bump (no jsonschema 0.46-introduced regressions in fork's schema-validation surface).

### `829c341a` (DEFERRED, Task 7)

- Cherry-pick produced 7 conflicted files; 3619-line conflict span in `profile_cmd.rs`.
- Conflict markers: cli.rs (3), main.rs (1), package.rs (1), profile/mod.rs (1), profile_cmd.rs (5), profile_runtime.rs (2), registry_client.rs (1) = 14 total.
- Upstream introduces substantial new user-facing functionality: `nono profile validate --draft`, `nono profile promote <name> [--yes]`, `~/.config/nono/profile-drafts/` infrastructure, base-hash verification, shadowing safeguards, atomic file ops, `NonoError::ActionRequired` variant, registry-client `PackageStatusResponse` fetch, new file `package_status.rs` (218 LOC), C FFI `NonoErrorCode::ErrConfigParse` mapping.
- Aborted cherry-pick; documented as P34-DEFER-04b-2 in `deferred-items.md`. Plan-close smoke-check expectations adjusted: `Upstream-commit:` count drops from 5 to 4.

### `ab74f5cd` (partial cherry-pick, Task 8)

- Cherry-pick produced 5 file conflicts + 1 DU (deleted-in-HEAD-modified-upstream) for `deprecated_schema.rs`.
- Resolution per-file:
  - `README.md`: kept fork HEAD (upstream's stale-Claude-advisory removal targets text fork no longer has after Phase 33 / Plan 34-00 / Phase 34 documentation work).
  - `crates/nono-cli/README.md`: kept fork HEAD (upstream documents claude-code + codex as pack-delivered, but fork still ships them as built-ins in `policy.json`).
  - `crates/nono-cli/src/cli.rs`: kept fork HEAD (fork uses named constants `RUN_AFTER_HELP`/`WRAP_AFTER_HELP`; upstream edits inlined string literals — text edits do not apply to fork's named-constant routing).
  - `docs/cli/clients/claude-code.mdx`: kept fork HEAD (upstream rewrites profile-example JSON to canonical `groups.include` shape, which fork's profile parser does not accept; fork has not landed canonical sections yet — deferred to P34-DEFER-04b-1).
  - `docs/cli/features/profiles-groups.mdx`: hand-merged. Kept fork's `override_deny`-based policy-overrides table; added a v0.47.0 deprecation note pointing users to `bypass_protection` as the canonical alias.
  - `docs/cli/usage/flags.mdx`: hand-merged. Kept fork's `--override-deny` documentation; added a v0.47.0 deprecation note (canonical alias + clap visible_alias semantics).
  - `crates/nono-cli/src/deprecated_schema.rs`: `git rm` (file does not exist in fork; Plan 34-04b landed the rename runway only — the 824-line deprecated_schema module port is P34-DEFER-04b-1).

## Verification

| Gate | Result | Notes |
|------|--------|-------|
| Gate 1: `cargo test --workspace --lib` (Windows host) | PASS | 853 tests green (668 + 39 + 146) |
| Gate 2: Windows clippy `-D warnings -D clippy::unwrap_used` | PASS | Zero warnings; zero unwrap_used |
| Gate 3: Linux cross-target clippy | DOCUMENTED-SKIPPED | Deferred to CI; x86_64-linux-gnu-gcc linker not installed on dev host; user accepted same posture at 34-04 close on 2026-05-11 |
| Gate 4: macOS cross-target clippy | DOCUMENTED-SKIPPED | Deferred to CI; x86_64-apple-darwin cc toolchain not installed; user accepted same posture at 34-04 close |
| Gate 5: `cargo fmt --all -- --check` | PASS | Clean |
| Gate 6: Phase 15 5-row detached-console smoke | DOCUMENTED-SKIPPED | Requires admin-elevated session; same posture as 34-04 SUMMARY |
| Gate 7: `wfp_port_integration --ignored` | DOCUMENTED-SKIPPED | Requires admin + `nono-wfp-service` installed; same posture as 34-04 SUMMARY |
| Gate 8: `learn_windows_integration` | DOCUMENTED-SKIPPED | Requires elevated session + ETW provider; same posture as 34-04 SUMMARY |

## D-34-E1 Windows-only file invariant

Per-commit check across the entire 5-commit chain: **PASS**.

```
PRE_HEAD=bc7b81ca078ebb7e1d3d37fceeff66ca234183c8
For each sha in 96e31c18, d9f1ce0c, 4bd35a1b, e61b2a30, 3d0547a9:
  git diff --stat $sha^..$sha -- crates/ | grep -cE '_windows|exec_strategy_windows' = 0
```

Zero Windows-file hits across all 5 commits.

## Plan-close smoke

```
git log --format='%B' bc7b81ca..HEAD | grep -v '^#' | grep -c '^Upstream-commit: '   -> 4 (f3e7f885, 0cba04a5, 7329ef73, ab74f5cd)
git log --format='%B' bc7b81ca..HEAD | grep -v '^#' | grep -c '^Manual-replay: '     -> 1 (f0abd413)
git log --format='%B' bc7b81ca..HEAD | grep -v '^#' | grep -c '^Upstream-Author:'   -> 0 (case-sensitivity invariant PASS)
git log --format='%B' bc7b81ca..HEAD | grep -v '^#' | grep -c '^Upstream-author: '   -> 5 (lowercase 'a' PASS; one per commit including the Manual-replay)
git log --format='%B' bc7b81ca..HEAD | grep -v '^#' | grep -c '^Signed-off-by: '     -> 12 (5 commits × 2 DCO + 2 preserved upstream signoffs from dependabot[bot] and SequeI)
```

Plan-close expectation (original): `Upstream-commit:` = 5. **Actual: 4 (829c341a deferred per orchestrator escalation rule).**

## Fork-defense invariants (pre/post)

| Sentinel | Pre-plan baseline | Post-plan | Status |
|----------|-------------------|-----------|--------|
| `capabilities.aipc \| loaded_profile` in profile/mod.rs (Plan 18.1-03) | 17 | 17 | preserved |
| `ProfileDeserialize` in profile/mod.rs (Phase 22-01) | 4 | 4 | preserved |
| `validate_upstream_url` in profile/mod.rs (Phase 22-04) | 6 | 6 | preserved |
| `ArtifactType::Plugin` in package.rs (Phase 26 PKGS-02) | 4 | 4 | preserved |
| `never_grant \| apply_deny_overrides` in policy.rs (Phase 19 v2.1) | 21 | 21 | preserved |
| `validate_path_within` in package_cmd.rs (Phase 22-03 PKG-04) | 9 | 9 | preserved |
| `find_denied_user_grants` in policy.rs (Plan 34-04 ac9f0a59) | 7 | 7 | preserved |

All 7 fork-defense baselines preserved at or above pre-plan baseline counts.

## Deviations from Plan

### Auto-fixed Issues (Rule 1-3)

**1. [Rule 3 - Blocking] Flaky static-flag test under parallel runner**

- **Found during:** Task 3 manual replay, when running `cargo test -p nono-cli --bin nono profile::` after adding the initial `canonical_schema_rename_tests` module.
- **Issue:** Initial test design used the production static `LEGACY_OVERRIDE_DENY_WARNED: AtomicBool` and a `reset_warned_flag()` helper. Rust test runners parallelize within the same process; another test would flip the flag mid-run, causing `canonical_bypass_protection_key_does_not_warn` to flake with a `must NOT trigger` assertion failure.
- **Fix:** Refactored to a pure helper `raw_profile_has_legacy_override_deny_key(raw: &str) -> bool` with no side effects. Tests now exercise the pure helper directly; the production hook `detect_legacy_override_deny_key` continues to call `emit_legacy_override_deny_warning_once` on a match. Added 3 additional tests covering nested-object walks, array walks, and malformed-JSON safety.
- **Files modified:** `crates/nono-cli/src/profile/mod.rs`
- **Tracked as:** part of commit `96e31c18`.

**2. [Rule 3 - Blocking] Clippy doc-lazy-continuation in PolicyPatchConfig::override_deny rustdoc**

- **Found during:** Task 3, post-implementation clippy run.
- **Issue:** Multi-line rustdoc on the `override_deny` field used `+` at start-of-line which clippy 1.95.0 reads as a Markdown list continuation; produced two `clippy::doc_lazy_continuation` errors.
- **Fix:** Rephrased to use commas/em-dashes instead of `+` at start of continuation lines.
- **Tracked as:** part of commit `96e31c18`.

**3. [Rule 3 - Blocking] f3e7f885 structural cherry-pick conflict**

- **Found during:** Task 4 cherry-pick of `f3e7f885`.
- **Issue:** Upstream patch targets `crates/nono-cli/src/profile_cmd.rs::profile_to_json` and `::diff_to_json`. Fork has these functions in `crates/nono-cli/src/policy_cmd.rs` after an earlier refactor split. Cherry-pick produced a ~2K-line structural conflict because upstream's context lines don't exist at the corresponding fork positions.
- **Fix:** Aborted cherry-pick. Applied the equivalent fix by hand to fork's `policy_cmd.rs::profile_to_json` and `::diff_to_json` with identical Map-insertion + serde-routing semantics. Two regression tests added in `tests/policy_cmd.rs`.
- **Tracked as:** commit `d9f1ce0c` (D-19 trailer; treated as same-disposition cherry-pick because intent is byte-equivalent).

### Escalations (orchestrator rule)

**4. [Escalation - 3K-line threshold] 829c341a deferred to P34-DEFER-04b-2**

- **Found during:** Task 7 cherry-pick of `829c341a`.
- **Trigger:** Cherry-pick produced 7 conflicted files + 3619-line conflict span in `profile_cmd.rs` (well above the orchestrator's 3K-line threshold).
- **Decision:** Defer to follow-up plan rather than attempt manual replay. Upstream introduces substantial new-feature surface (`nono profile promote`, `--draft` flag, `package_status.rs` 218-LOC new file, `NonoError::ActionRequired` variant + C FFI mapping, profile-drafts directory infrastructure, atomic file ops, base-hash verification, shadowing safeguards). This is feature-development scope requiring design review + security audit + multi-day test coverage, not a sync-only delta.
- **Documented in:** `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md` as P34-DEFER-04b-2.

## Deferred Items

| ID | Trigger | Scope | Tracked in |
|----|---------|-------|------------|
| P34-DEFER-04b-1 | Task 3 — pragmatic Option C scope | Full 824-line deprecated_schema module port + canonical groups/commands/filesystem sections + 210-callsite internal rename `override_deny` -> `bypass_protection` + built-in profile data migration + JSON schema restructure + docs migration + alias-inventory tooling | `deferred-items.md` |
| P34-DEFER-04b-2 | Task 7 — 3619-line conflict span + feature scope | Upstream 829c341a: nono profile promote, --draft flag, package_status.rs, NonoError::ActionRequired, profile-drafts infrastructure with atomic ops + base-hash verification + shadowing safeguards | `deferred-items.md` |

## Self-Check: PASSED

Files verified present:
- FOUND: `crates/nono-cli/src/profile/mod.rs` (modified — serde alias + deprecation warning + 7 unit tests)
- FOUND: `crates/nono-cli/src/cli.rs` (modified — clap visible_alias on both SandboxArgs structs)
- FOUND: `crates/nono-cli/src/policy_cmd.rs` (modified — serde-routing for show/diff JSON)
- FOUND: `crates/nono-cli/tests/policy_cmd.rs` (modified — 2 new regression tests + helper)
- FOUND: `tests/integration/test_bypass_protection.sh` (renamed from test_override_deny.sh; canonical-name smoke tests added)
- FOUND: `tests/run_integration_tests.sh` (suite list updated)
- FOUND: `crates/nono-cli/Cargo.toml` (jsonschema 0.46)
- FOUND: `crates/nono/Cargo.toml` (jsonschema 0.46 + tokio dev-dep preserved)
- FOUND: `Cargo.lock` (regenerated with jsonschema 0.46.4 graph)
- FOUND: `CHANGELOG.md` (v0.47.1 entry merged)
- FOUND: `docs/cli/features/profiles-groups.mdx` (deprecation note added)
- FOUND: `docs/cli/usage/flags.mdx` (deprecation note added)
- FOUND: `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md` (created)

Commits verified present:
- FOUND: `96e31c18` (replay(34-04b): canonical schema rename runway from upstream f0abd413)
- FOUND: `d9f1ce0c` (fix(profile): emit serde-rendered values in show/diff JSON output)
- FOUND: `4bd35a1b` (chore: release v0.47.1)
- FOUND: `e61b2a30` (chore(deps): bump jsonschema from 0.45.1 to 0.46.4)
- FOUND: `3d0547a9` (docs: fix stale references, deprecation wording, and built-in vs pack distinction)

## TDD Gate Compliance

Plan is `type: execute`, not `type: tdd`. TDD gate sequence (test/feat/refactor) does not apply. However, all 5 production commits include tests:
- `96e31c18`: 7 unit tests in `canonical_schema_rename_tests` + integration tests in `test_bypass_protection.sh`
- `d9f1ce0c`: 2 regression integration tests in `tests/policy_cmd.rs`
- `4bd35a1b`: docs only (no new code surface)
- `e61b2a30`: dep bump; 191 profile-module tests verify no regression
- `3d0547a9`: docs only

## Push status

Plan commits remain LOCAL on `main`. Per D-34-D1 commits land directly on `main`; PR opening is a retrospective review surface against a tag (mirrors Plan 34-00 precedent). Push to `origin/main` deferred — caller (orchestrator + user) decides when to push. To push:

```bash
git push origin main
```

Plan-close smoke check expected post-push: `git log origin/main..main --oneline | wc -l` returns 0.
