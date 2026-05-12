# Phase 34 — Deferred Items

Items discovered during Phase 34 plan execution that exceed the scope of
the current sync-execution plans and are deferred to follow-up plans.

## P34-DEFER-04b-1: Full Option C deprecated_schema module port

**Discovered during:** Plan 34-04b Task 3 (D-20 manual replay of upstream
`f0abd413` — canonical JSON schema restructure)

**Date:** 2026-05-11

**Scope:** Plan 34-04b landed the rename-acceptance contract (serde alias
+ clap visible_alias + one-time stderr deprecation warning + test file
rename) — sufficient to make v0.47.x JSON profiles and CLI invocations
load on the fork. The full upstream surface is deferred:

- Full 824-line upstream `deprecated_schema` module port (`LegacyPolicyPatch`
  rewriter, per-key `DeprecationCounter`, `--strict` mode for
  `nono profile validate`, alias inventory enforcement via
  `scripts/test-list-aliases.sh` and `scripts/lint-docs.sh`).
- Canonical sections `groups`, `commands.{allow,deny}`,
  `filesystem.{deny,bypass_protection}` in `Profile` / `LoadedProfile`
  structs.
- Internal Rust identifier rename `override_deny` → `bypass_protection`
  across the 210-callsite surface
  (`capability_ext.rs`, `cli.rs`, `command_runtime.rs`,
  `execution_runtime.rs`, `launch_runtime.rs`, `main.rs`, `policy.rs`,
  `policy_cmd.rs`, `profile_cmd.rs`, `profile_runtime.rs`,
  `query_ext.rs`, `sandbox_prepare.rs`, `sandbox_state.rs`,
  `why_runtime.rs`, JSON schema fixtures).
- Built-in profile data migration (claude-code, codex, opencode, etc.)
  to canonical schema sections.
- JSON schema (`nono-profile.schema.json`) restructure.
- Embedded profile-authoring guide + `docs/cli/features/profiles-groups.mdx`
  + `docs/cli/usage/flags.mdx` migration.
- `scripts/lint-docs.sh` + alias-inventory test surface.
- `profile_save_runtime.rs` modify/delete conflict re-evaluation
  (fork's deletion currently stands).

**Estimated scope:** multi-week. Likely splits into:
- 04b-2a: deprecated_schema module + LegacyPolicyPatch + DeprecationCounter
- 04b-2b: canonical Profile sections (groups/commands/filesystem)
- 04b-2c: 210-callsite internal rename `override_deny` → `bypass_protection`
- 04b-2d: data + docs + tooling migration

**Why deferred:** Plan 34-04b's scope was to clear the canonical-schema
foundation for Wave 1+ downstream plans. Full restructure is its own
multi-week workstream and would have indefinitely blocked Wave 1+.

## P34-DEFER-04b-2: Upstream 829c341a — profile drafts + package status

**Discovered during:** Plan 34-04b Task 7 (attempted cherry-pick of
upstream `829c341a` — "add commands to manage profile drafts and check
package status")

**Date:** 2026-05-11

**Scope:** Upstream commit `829c341a` (Luke Hinds, v0.47.1) introduces
substantial new user-facing functionality:

- `nono profile validate --draft` — validate drafts in
  `~/.config/nono/profile-drafts`
- `nono profile promote <name>` — interactive review-and-apply for
  profile drafts (with `--yes` for non-interactive use)
- `~/.config/nono/profile-drafts/` directory convention
- Base-hash verification to prevent stale-draft promotion
- Shadowing safeguards (refuse to promote over built-in or installed
  pack profiles)
- Atomic file operations for safe updates
- `NonoError::ActionRequired` variant for critical package advisories
- Registry-client fetch of `PackageStatusResponse`
- New file: `crates/nono-cli/src/package_status.rs` (218 LOC)
- C FFI: `NonoErrorCode::ErrConfigParse` mapping for the new variant

**Cherry-pick result:** 7 conflicted files; 3619-line conflict span in
`crates/nono-cli/src/profile_cmd.rs` (well above the 3K-line escalation
threshold). The new file `package_status.rs` has no analog in the fork.
The new `profile_cmd.rs` content (~460 new lines of subcommand handlers)
overlays heavy fork divergence.

**Why deferred:** This is feature-development scope, not a sync-only
delta. Manual replay requires:
1. Design review (does `--draft` fit nono's threat model?)
2. Security audit (atomic ops, base-hash verification, shadowing safeguards)
3. Test coverage (promote happy path, `--draft` validation, base-hash
   mismatch, shadowing rejection)
4. Documentation (CLI usage, profile-drafts directory convention)
5. C FFI thread-through for `ErrConfigParse` mapping

**Estimated scope:** multi-day at minimum (1-2 weeks if design/security
review surfaces concerns).

**Tracking:** Phase 34-04b SUMMARY records this as the escalation per
the orchestrator-approved escalation rule. The Plan 34-04b plan-close
smoke-check expected `Upstream-commit:` count of 5; actual is 4
(829c341a deferred); `Manual-replay:` count stays at 1 (only
`f0abd413`).

## P34-DEFER-01-1: query_ext::test_query_path_denied Windows-path canonicalization

**Discovered during:** Plan 34-01 D-34-D2 close-gate 1 (`cargo test --workspace --all-features`)

**Date:** 2026-05-11

**Scope:** `query_ext::tests::test_query_path_denied` asserts that the
suggested-flag output for a POSIX path `/some/random/path` round-trips
to `--read /some/random`. On Windows, the path canonicalization layer
prefixes the result with `\?\C:\` (UNC long-path form), producing
`--read \?\C:\some\random`. The test passes on Linux/macOS hosts.

**Pre-existing:** Verified pre-existing on `aca306a54b3d8f0858fc5376068b2715ec2f1e6c`
(the base HEAD before Plan 34-01 cherry-picks landed) — same `left/right` mismatch
when run against the baseline `query_ext.rs`. Plan 34-01's upstream cherry-picks
(notably `034be703`) modify the surrounding diagnostic message format but do NOT
introduce the path-canonicalization mismatch.

**Path forward:** Either gate the test to `#[cfg(not(target_os = "windows"))]`
(Phase 22-style pattern) or add a Windows-specific variant that asserts the
UNC-prefixed form. Deferred to a Windows-test-hygiene plan; not blocking for
Plan 34-01 close.

**Tracking:** Plan 34-01 SUMMARY records the gate-1 single-test failure as
out-of-scope per the executor's "auto-fix scope boundary" rule (only fix
issues directly caused by current-task changes; this was pre-existing).
