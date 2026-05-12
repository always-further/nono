---
phase: 36-upst3-deep-closure
plan: 01d
type: execute
wave: 2
depends_on:
  - 01c
files_modified:
  - crates/nono-cli/data/policy.json
  - crates/nono-cli/data/nono-profile.schema.json
  - crates/nono-cli/data/profile-authoring-guide.md
  - scripts/test-list-aliases.sh
  - scripts/lint-docs.sh
  - docs/cli/features/profiles-groups.mdx
  - docs/cli/usage/flags.mdx
  - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md
  - crates/nono-cli/tests/builtin_profile_load.rs
autonomous: true
requirements:
  - REQ-PORT-CLOSURE-02
tags:
  - phase-36
  - port-closure
  - data-migration
  - schema-restructure
  - docs-migration
  - tooling
  - p34-defer-04b-1
  - d-20-manual-replay
  - phase-36-closure

must_haves:
  truths:
    - "All 4 built-in profiles (claude-code, codex, opencode, claude-no-keychain) in `crates/nono-cli/data/policy.json` use canonical sections: top-level `groups`, `commands.{allow, deny}`, `filesystem.{deny, bypass_protection}`. Built-in profiles load without serde deserialization errors (post Plan 36-01b/c structure)."
    - "`crates/nono-cli/data/nono-profile.schema.json` (637 LOC) is restructured to match upstream `f0abd413` canonical form; `scripts/regenerate-schema.sh` produces output that matches the committed schema byte-for-byte."
    - "Two new tooling scripts exist and pass: `scripts/test-list-aliases.sh` (alias inventory enforcement) exits 0; `scripts/lint-docs.sh` (docs alias-inventory check) exits 0. Both are shell-portable (Git Bash on Windows OR have `.ps1` companions per the Windows host compatibility check)."
    - "`docs/cli/features/profiles-groups.mdx` and `docs/cli/usage/flags.mdx` reflect the canonical Profile shape; legacy `override_deny` references appear only in dedicated migration / deprecation notes citing Plan 36-01c."
    - "`.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md` carries an appended 'Phase 36 closure' section flipping P34-DEFER-04b-1, P34-DEFER-06-1, P34-DEFER-08b-1, P34-DEFER-08b-2, P34-DEFER-09-2 from open to closed-by-Phase-36."
  artifacts:
    - path: "crates/nono-cli/data/policy.json"
      provides: "Built-in profile data migrated. The 1 residual `override_deny` callsite at line 695 (per PATTERNS.md Drift Note 6) renamed to `bypass_protection`. All 4 built-in profiles use `commands.{allow,deny}` and `filesystem.{deny,bypass_protection}` sub-section shape — flat-shape legacy fields removed (or kept only as test-fixture coverage if any built-in profile intentionally exercises legacy acceptance — verify case-by-case)."
      contains: "bypass_protection"
    - path: "crates/nono-cli/data/nono-profile.schema.json"
      provides: "JSON Schema fixture restructured to match upstream canonical form. New `commands` object schema, new `filesystem.deny` + `filesystem.bypass_protection` properties. Schema regenerator (`scripts/regenerate-schema.sh`) emits identical byte-for-byte output."
      contains: "\"bypass_protection\""
    - path: "scripts/test-list-aliases.sh"
      provides: "New shell script (mirroring `scripts/check-upstream-drift.sh` header + argument-parsing shape). Inventories profile-schema legacy aliases vs canonical names; exits 0 on clean state; exits non-zero with diagnostic output on alias drift."
      contains: "#!/usr/bin/env bash"
    - path: "scripts/lint-docs.sh"
      provides: "New shell script (mirroring `scripts/check-upstream-drift.sh` shape). Greps documentation files (`docs/cli/**/*.mdx`) for unmarked legacy aliases; exits 0 on clean state; exits non-zero with the file:line of any drift."
      contains: "#!/usr/bin/env bash"
    - path: "crates/nono-cli/data/profile-authoring-guide.md"
      provides: "Embedded profile-authoring guide. If file exists pre-plan (PATTERNS.md says it does), MUTATE for canonical-section coverage. If absent, CREATE with the canonical-section authoring instructions + examples."
      contains: "bypass_protection"
    - path: "docs/cli/features/profiles-groups.mdx"
      provides: "Migrated to canonical Profile shape; legacy `override_deny` appears only in a dedicated 'Legacy Field Migration' section citing Plan 36-01c + D-36-B3 (indefinite acceptance)."
      contains: "bypass_protection"
    - path: "docs/cli/usage/flags.mdx"
      provides: "Migrated to canonical CLI flag shape (`--bypass-protection` canonical, `--override-deny` documented as alias)."
      contains: "--bypass-protection"
    - path: ".planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md"
      provides: "Appended '## Phase 36 closure' section flipping P34-DEFER-04b-1, 06-1, 08b-1, 08b-2, 09-2 from open to closed. Closure section cites Plan 36-01a/b/c/d + 36-02 + 36-03 SUMMARYs as evidence."
      contains: "## Phase 36 closure"
    - path: "crates/nono-cli/tests/builtin_profile_load.rs"
      provides: "New integration test file. Loads each of the 4 built-in profiles (claude-code, codex, opencode, claude-no-keychain); asserts deserialization succeeds AND canonical sections are populated."
      contains: "fn test_builtin_profile_claude_code_loads_canonical_sections"
  key_links:
    - from: "crates/nono-cli/data/policy.json"
      to: "crates/nono-cli/src/profile/mod.rs (Plan 36-01b canonical sections + Plan 36-01c canonical field names)"
      via: "serde deserialization of policy.json into Profile struct"
      pattern: "bypass_protection"
    - from: "scripts/regenerate-schema.sh"
      to: "crates/nono-cli/data/nono-profile.schema.json"
      via: "regenerator emits the canonical-form schema"
      pattern: "regenerate-schema|nono-profile\\.schema\\.json"
    - from: "crates/nono-cli/tests/builtin_profile_load.rs"
      to: "crates/nono-cli/data/policy.json + crates/nono-cli/src/profile/builtin.rs (Plan 36-01c renamed)"
      via: "integration test loads each built-in profile post-migration"
      pattern: "test_builtin_profile_.*_loads"
---

<objective>
Close REQ-PORT-CLOSURE-02 by completing the data + docs + tooling migration that Plans 36-01a/b/c set up. Migrate the 4 built-in profiles' JSON data + the JSON schema fixture to the canonical shape; create the two new alias-inventory enforcement shell scripts (`test-list-aliases.sh` + `lint-docs.sh`); migrate the two user-facing MDX docs (`profiles-groups.mdx` + `flags.mdx`) to canonical surface; embed the profile-authoring guide; and append the Phase 36 closure section to Phase 34's `deferred-items.md` flipping all 5 binding P34-DEFER-* items (04b-1, 06-1, 08b-1, 08b-2, 09-2) from open to closed.

**Purpose:** Tail of REQ-02. Plans 36-01a/b/c delivered the Rust surface (module, structs, atomic rename); Plan 36-01d delivers the data, docs, tooling, and ledger closure so the canonical-shape surface is end-to-end consistent. After Plan 36-01d lands, REQ-PORT-CLOSURE-02 acceptance criteria #4 (schema regenerator matches upstream canonical form), #5 (all 4 built-in profiles migrated), and #6 (docs alias-inventory check passes) are met.

**Output:** Data migration in `policy.json` (1 residual line + verify all 4 built-in profiles); schema restructure in `nono-profile.schema.json`; 2 new tooling scripts; 2 migrated MDX docs; 1 new/extended profile-authoring guide; 1 new integration test file; 1 appended closure section to Phase 34 deferred-items.md.

**Scope ceiling (D-34-B2):** ONLY the data + docs + tooling closure. NO Rust source code changes (Plans 36-01a/b/c covered the Rust surface). NO audit-event hooks. NO new error variants.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@CLAUDE.md
@.planning/STATE.md
@.planning/ROADMAP.md
@.planning/REQUIREMENTS.md
@.planning/phases/36-upst3-deep-closure/36-CONTEXT.md
@.planning/phases/36-upst3-deep-closure/36-RESEARCH.md
@.planning/phases/36-upst3-deep-closure/36-PATTERNS.md
@.planning/phases/36-upst3-deep-closure/36-VALIDATION.md
@.planning/phases/36-upst3-deep-closure/36-01a-DEPRECATED-SCHEMA-MODULE-SUMMARY.md
@.planning/phases/36-upst3-deep-closure/36-01b-CANONICAL-PROFILE-SECTIONS-SUMMARY.md
@.planning/phases/36-upst3-deep-closure/36-01c-OVERRIDE-DENY-RENAME-SUMMARY.md
@.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md

<interfaces>
<!-- Existing shell-script analog (PATTERNS.md § Scripts). -->

From `scripts/check-upstream-drift.sh` (header + argument-parsing pattern to mirror):
```bash
#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C.UTF-8 2>/dev/null || true

print_usage() { cat <<'USAGE'
Usage: scripts/check-upstream-drift.sh [--format table|json]
USAGE
}

FORMAT=table
while [[ $# -gt 0 ]]; do
    case "$1" in
        --format) FORMAT="$2"; shift 2 ;;
        -h|--help) print_usage; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done
```

<!-- Phase 34 deferred-items.md closure section pattern: mirror Phase 35 closure entry already in the file. -->
</interfaces>

<drift_notes>
1. **`policy.json` line 695 residual `override_deny` callsite.** Plan 36-01c deferred this to Plan 36-01d as part of "data migration." Task 1 handles this rename.
2. **`scripts/regenerate-schema.sh` Windows-host compatibility unknown** (RESEARCH.md Assumption A7). Task 4 verifies; adds `.ps1` companion if non-portable.
3. **`crates/nono-cli/data/profile-authoring-guide.md` existence** per PATTERNS.md ("already exists per grep"). Task 4 verifies — MUTATE if present; CREATE if absent.
4. **Built-in profiles in `policy.json`** already use top-level `groups` shape (PATTERNS.md Drift Note 6). Task 1 verifies sub-section canonical coverage of all 4 profiles.
</drift_notes>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Migrate built-in profile data in policy.json (4 profiles + 1 residual override_deny callsite) + restructure nono-profile.schema.json (per D-36-B1 / REQ-PORT-CLOSURE-02 #4 + #5)</name>
  <files>crates/nono-cli/data/policy.json, crates/nono-cli/data/nono-profile.schema.json</files>
  <read_first>
    - crates/nono-cli/data/policy.json (full file — 1029 LOC; identify all 4 built-in profiles claude-code / codex / opencode / claude-no-keychain; verify which already use canonical sections and which need migration)
    - crates/nono-cli/data/nono-profile.schema.json (full file — 637 LOC; current JSON Schema shape)
    - crates/nono-cli/src/profile/mod.rs (Plan 36-01b/c result: the post-rename canonical struct shape that policy.json + schema.json must align with)
    - .planning/phases/36-upst3-deep-closure/36-PATTERNS.md § Plan 36-01d (file-role classifications; analogs)
    - .planning/phases/36-upst3-deep-closure/36-RESEARCH.md § Plan 36-01d technical approach (lines 593-630)
  </read_first>
  <action>
    1. **Audit `policy.json` built-in profile alignment.** For each of the 4 profiles (claude-code, codex, opencode, claude-no-keychain), verify top-level `groups` (already partial), `commands.{allow, deny}` sub-section, and `filesystem.{deny, bypass_protection}` sub-section. Document per-profile audit in Task 6 commit body.
    2. **Migrate the 1 residual `override_deny` callsite at policy.json line 695.** Verify line via `grep -n 'override_deny' crates/nono-cli/data/policy.json`; rename key to `bypass_protection` while preserving JSON value.
    3. **Migrate any flat-shape fields to canonical sub-section shape.** For each built-in profile, if it uses pre-canonical shape, restructure to canonical. Maintain JSON-validity at every intermediate save (use a JSON formatter / linter to catch syntax errors).
    4. **Restructure `nono-profile.schema.json`** to match upstream canonical form per upstream `f0abd413`. Capture upstream shape via `git show upstream/f0abd413:crates/nono-cli/data/nono-profile.schema.json`. Add `commands` object schema; add `filesystem.deny` + `filesystem.bypass_protection` properties. PRESERVE fork-specific fields (`audit_signer`, `bypass_protection_paths`, `capability_elevation`, `resource_limits`, etc.) per D-36-D1 + D-34-B1 fork-only retention catalog.
    5. **Verify schema validates the migrated policy.json**. Run `cargo test -p nono-cli --lib` — embedded built-in profiles deserialize at build time, so any regression surfaces immediately.
    6. Run `cargo build -p nono-cli` then `cargo test -p nono-cli --lib` — must succeed.
  </action>
  <verify>
    <automated>grep -c '"bypass_protection"' crates/nono-cli/data/policy.json &amp;&amp; grep -c '"override_deny"' crates/nono-cli/data/policy.json ; cargo build -p nono-cli 2>&amp;1 | tail -10 ; cargo test -p nono-cli --lib 2>&amp;1 | tail -10</automated>
  </verify>
  <acceptance_criteria>
    - All 4 built-in profile names appear in policy.json (grep: `grep -cE '"claude-code"|"codex"|"opencode"|"claude-no-keychain"' crates/nono-cli/data/policy.json` returns ≥ 4).
    - Canonical `bypass_protection` key appears (grep: `grep -c '"bypass_protection"' crates/nono-cli/data/policy.json` returns ≥ 1).
    - Residual `override_deny` callsite at line 695 RENAMED — zero remaining `override_deny` keys (grep: `grep -c '"override_deny"' crates/nono-cli/data/policy.json` returns 0).
    - `nono-profile.schema.json` accepts canonical sections (grep: `grep -c '"bypass_protection"' crates/nono-cli/data/nono-profile.schema.json` returns ≥ 1; `grep -c '"commands"' crates/nono-cli/data/nono-profile.schema.json` returns ≥ 1).
    - `cargo build -p nono-cli` exits 0; `cargo test -p nono-cli --lib` exits 0.
    - Test ID **36-01d-* / T-36-01-DATA-MIGRATE**: built-in profiles load post-migration with no schema-validation errors.
  </acceptance_criteria>
  <done>Built-in profile data + JSON schema both migrated to canonical shape; embedded profiles still deserialize; schema accepts canonical surface + fork retention fields.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: Add integration test asserting all 4 built-in profiles use canonical sections post-migration (per REQ-PORT-CLOSURE-02 #5)</name>
  <files>crates/nono-cli/tests/builtin_profile_load.rs</files>
  <read_first>
    - crates/nono-cli/tests/profile_validate_strict.rs (Plan 36-01a Task 2 test file — mirror env-var save/restore pattern + tempfile use)
    - crates/nono-cli/src/profile/builtin.rs (post-Plan 36-01c canonical state)
    - CLAUDE.md § Coding Standards (env-var save/restore in tests; no .unwrap in source)
  </read_first>
  <behavior>
    - Test 1 (`test_builtin_profile_claude_code_loads_canonical_sections`): Load `claude-code`; assert loaded `Profile` carries canonical `commands` + `filesystem.bypass_protection` (NOT `override_deny`).
    - Test 2 (`test_builtin_profile_codex_loads_canonical_sections`): Same for codex.
    - Test 3 (`test_builtin_profile_opencode_loads_canonical_sections`): Same for opencode.
    - Test 4 (`test_builtin_profile_claude_no_keychain_loads_canonical_sections`): Same for claude-no-keychain.
    - Test 5 (`test_all_builtin_profiles_use_canonical_sections`): Iterate over all 4 names; each loads successfully via the embedded loader.
  </behavior>
  <action>
    1. Create `crates/nono-cli/tests/builtin_profile_load.rs` as new integration test file.
    2. Use the embedded-policy loader. Verify function name + signature via `grep -n 'fn load_embedded_policy\|pub fn .* embedded' crates/nono-cli/src/policy.rs`.
    3. For each built-in profile, assert: profile deserializes OK, references `bypass_protection` (NOT `override_deny`) as field name, `commands` section has canonical `{allow, deny}` shape.
    4. Save/restore env vars per CLAUDE.md only if a test manipulates `HOME`/`XDG_CONFIG_HOME`/`NONO_TEST_HOME` (likely unnecessary for embedded loads).
    5. Run `cargo test -p nono-cli --test builtin_profile_load` — all 5 tests pass.
  </action>
  <verify>
    <automated>cargo test -p nono-cli --test builtin_profile_load -- --nocapture 2>&amp;1 | tee /tmp/36-01d-task2.log</automated>
  </verify>
  <acceptance_criteria>
    - Test file exists with all 5 test functions (grep: `grep -cE 'fn test_builtin_profile_(claude_code|codex|opencode|claude_no_keychain)_loads|fn test_all_builtin_profiles_use_canonical_sections' crates/nono-cli/tests/builtin_profile_load.rs` returns 5).
    - All 5 tests pass: `cargo test -p nono-cli --test builtin_profile_load` exits 0.
    - No `.unwrap()` / `.expect()` outside `#[cfg(test)]` arms (acceptable in test bodies).
    - Test ID **36-01d-* / T-36-01-DATA-MIGRATE** (integration arm): covers REQ-PORT-CLOSURE-02 #5.
  </acceptance_criteria>
  <done>Integration test file covers all 4 built-in profiles post-migration; canonical-section invariant locked.</done>
</task>

<task type="auto">
  <name>Task 3: Create scripts/test-list-aliases.sh + scripts/lint-docs.sh (per REQ-PORT-CLOSURE-02 #6)</name>
  <files>scripts/test-list-aliases.sh, scripts/lint-docs.sh</files>
  <read_first>
    - scripts/check-upstream-drift.sh (full file — mirror header + argument-parsing + `set -euo pipefail` + `LC_ALL=C.UTF-8` pattern)
    - .planning/phases/36-upst3-deep-closure/36-PATTERNS.md § Scripts
    - docs/cli/features/*.mdx (sibling docs that lint-docs.sh will scan)
  </read_first>
  <action>
    1. **Create `scripts/test-list-aliases.sh`** mirroring `scripts/check-upstream-drift.sh` shape. Header preamble cites Plan 36-01d + D-20 manual-replay of upstream f0abd413. Body: greps `crates/nono-cli/data/` for `"override_deny"` JSON keys; greps `crates/nono-cli/src/` for `visible_alias = "override-deny"` (these are EXPECTED per D-36-B3 indefinite acceptance — script reports them but does NOT exit non-zero on clap aliases). Exit 0 on clean JSON state; exit 1 on unmarked JSON drift; exit 2 on bad arg.
    2. **Create `scripts/lint-docs.sh`** mirroring same pattern. Scans `docs/cli/**/*.mdx` for `override_deny` and `override-deny` references. Allows references that appear on lines also containing one of the marker words: `Legacy`, `Deprecated`, `D-36-B3`. Exit 0 on clean state; exit 1 on unmarked drift with file:line.
    3. **Make both scripts executable** (`chmod +x` on Linux/macOS; on Windows the file extension already routes to Git Bash for `.sh`).
    4. **Smoke test both scripts** after Task 1 lands:
       - `bash scripts/test-list-aliases.sh` exits 0 (no JSON-data drift post-Task-1 migration).
       - `bash scripts/lint-docs.sh` MAY exit non-zero pre-Task-4 — capture output as the punch-list for Task 4.
  </action>
  <verify>
    <automated>test -x scripts/test-list-aliases.sh &amp;&amp; test -x scripts/lint-docs.sh &amp;&amp; bash scripts/test-list-aliases.sh ; echo "list-aliases exit: $?" ; bash scripts/lint-docs.sh ; echo "lint-docs exit: $?"</automated>
  </verify>
  <acceptance_criteria>
    - Both scripts exist + executable (`test -x scripts/test-list-aliases.sh && test -x scripts/lint-docs.sh` succeeds).
    - Both shebang + `set -euo pipefail` (grep: `grep -c 'set -euo pipefail' scripts/test-list-aliases.sh` returns 1; same for lint-docs.sh).
    - `bash scripts/test-list-aliases.sh` exits 0 post-Task-1 migration.
    - `bash scripts/lint-docs.sh` exits 0 post-Task-4 migration (acceptable to exit non-zero between Task 3 and Task 4 completion).
  </acceptance_criteria>
  <done>Both inventory scripts created; test-list-aliases.sh exits clean post-Task-1; lint-docs.sh output (if non-zero) feeds Task 4.</done>
</task>

<task type="auto">
  <name>Task 4: Verify regenerate-schema.sh Windows compatibility + migrate profiles-groups.mdx + flags.mdx + create/update profile-authoring-guide.md (per REQ-PORT-CLOSURE-02 #6)</name>
  <files>docs/cli/features/profiles-groups.mdx, docs/cli/usage/flags.mdx, crates/nono-cli/data/profile-authoring-guide.md, [optional: scripts/regenerate-schema.ps1]</files>
  <read_first>
    - docs/cli/features/profiles-groups.mdx (existing — verify current shape; capture legacy refs)
    - docs/cli/usage/flags.mdx (existing — verify current shape; capture flag-table entries)
    - docs/cli/features/profile-authoring.mdx (sibling — frontmatter + cross-doc link patterns)
    - crates/nono-cli/data/profile-authoring-guide.md (verify existence first)
    - scripts/regenerate-schema.sh (verify existence + shell-portability)
    - .planning/phases/36-upst3-deep-closure/36-PATTERNS.md § Docs (frontmatter + cross-doc link pattern)
  </read_first>
  <action>
    1. **Verify `scripts/regenerate-schema.sh` exists + Windows-portable.** Try `bash scripts/regenerate-schema.sh` on Windows host (Git Bash). If success: verify produces output matching committed schema (`git diff --exit-code` clean). If fails: create `scripts/regenerate-schema.ps1` PowerShell companion mirroring `scripts/windows-test-harness.ps1` precedent; document rationale in commit body.
    2. **Migrate `docs/cli/features/profiles-groups.mdx`**: update body for canonical Profile shape (top-level `groups`, `commands.{allow, deny}`, `filesystem.{deny, bypass_protection}`); add "Legacy Field Migration" section citing Plan 36-01c + D-36-B3 (indefinite acceptance) and explicitly mentioning `override_deny` → `bypass_protection`; preserve frontmatter per PATTERNS.md § Docs.
    3. **Migrate `docs/cli/usage/flags.mdx`**: flag table shows `--bypass-protection` canonical + `--override-deny` alias; migration note marked `Legacy` or `Deprecated` so lint-docs.sh passes.
    4. **Create or extend `crates/nono-cli/data/profile-authoring-guide.md`**: verify existence (`ls`); MUTATE if present, CREATE if absent. Cover authoring with canonical sections; short example showing `filesystem.deny` + `filesystem.bypass_protection`. Verify `cargo build -p nono-cli` succeeds (embedded at build time).
    5. **Re-run `bash scripts/lint-docs.sh`** — must exit 0 after migration.
  </action>
  <verify>
    <automated>bash scripts/lint-docs.sh &amp;&amp; cargo build -p nono-cli 2>&amp;1 | tail -10 &amp;&amp; grep -c '\-\-bypass-protection' docs/cli/usage/flags.mdx &amp;&amp; grep -c 'bypass_protection' docs/cli/features/profiles-groups.mdx</automated>
  </verify>
  <acceptance_criteria>
    - `docs/cli/features/profiles-groups.mdx` references canonical `bypass_protection` (grep: `grep -c 'bypass_protection' docs/cli/features/profiles-groups.mdx` returns ≥ 1).
    - Legacy migration section present: `grep -cE 'Legacy|Deprecated|D-36-B3' docs/cli/features/profiles-groups.mdx` returns ≥ 1.
    - `docs/cli/usage/flags.mdx` references canonical `--bypass-protection` (grep: `grep -c '\-\-bypass-protection' docs/cli/usage/flags.mdx` returns ≥ 1).
    - `crates/nono-cli/data/profile-authoring-guide.md` exists + canonical (grep: `grep -E 'bypass_protection|commands\..*allow' crates/nono-cli/data/profile-authoring-guide.md` returns ≥ 1).
    - `bash scripts/lint-docs.sh` exits 0.
    - `cargo build -p nono-cli` exits 0.
    - `scripts/regenerate-schema.sh` Windows compatibility documented (either runs on Git Bash, OR `.ps1` companion exists).
  </acceptance_criteria>
  <done>2 MDX docs migrated; profile-authoring-guide.md canonical; lint-docs.sh clean; regenerate-schema.sh portability documented.</done>
</task>

<task type="auto">
  <name>Task 5: Append Phase 36 closure section to Phase 34 deferred-items.md (per CONTEXT.md Plan SUMMARY guidance)</name>
  <files>.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md</files>
  <read_first>
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md (full file — read Phase 35 closure section first to mirror shape; identify P34-DEFER-04b-1, 06-1, 08b-1, 08b-2, 09-2 current open-state entries)
    - .planning/phases/36-upst3-deep-closure/36-01a/b/c-*-SUMMARY.md (prior plans' closure outcomes — verify which SUMMARYs exist; Plans 36-02 + 36-03 may also have closed)
    - .planning/phases/36-upst3-deep-closure/36-CONTEXT.md § Claude's Discretion (line ~118 — closure section is planner discretion, last plan to close appends)
  </read_first>
  <action>
    1. Verify which Phase 36 plans have closed: `ls .planning/phases/36-upst3-deep-closure/36-*-SUMMARY.md` — expect 36-01a, 36-01b, 36-01c SUMMARYs at minimum; 36-02 + 36-03 SUMMARYs likely also present (Wave 1 concurrent).
    2. Append `## Phase 36 closure (appended YYYY-MM-DD)` section at the END of deferred-items.md. Content:
       - **P34-DEFER-04b-1** (Full deprecated_schema module port) — CLOSED by Plans 36-01a + 36-01b + 36-01c + 36-01d. Evidence: enumerate the 4 SUMMARY filenames.
       - **P34-DEFER-06-1** + **P34-DEFER-09-2** (yaml_merge wiring trio + wiring.rs base abstraction) — CLOSED-WITH-SCOPE-TRIM by Plan 36-02. Acceptance #1 (idempotent JSON-merge install records) DEFERRED to v2.5-FU-3 per D-36-C1. Evidence: 36-02 SUMMARY.
       - **P34-DEFER-08b-1** + **P34-DEFER-08b-2** (b5f0a3ab deep ExecConfig refactor + bbdf7b85 escape-quote pipeline) — CLOSED-WITH-SURGICAL-PORT by Plan 36-03 (3 sequenced commits). Fork ExecConfig preserved per D-36-D1; upstream-shape adoption deferred to v2.5-FU-4. Evidence: 36-03 SUMMARY.
       - List Phase 36 carry-forwards to v2.5+: v2.5-FU-3 (full wiring.rs), v2.5-FU-4 (upstream-shape ExecConfig), v2.5-FU-5 (override_deny hard-deprecation ADR), v2.5-FU-6 (PTY-quiet-period parametric proptest).
    3. Update the Traceability table at top of deferred-items.md (if such a table exists with status column): flip rows for the 5 P34-DEFER-* items from `open` → `closed-by-Phase-36`.
    4. **DO NOT modify** the existing Phase 35 closure section in the same file (immutable).
  </action>
  <verify>
    <automated>grep -c '^## Phase 36 closure' .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md ; grep -cE 'P34-DEFER-04b-1.*CLOSED|P34-DEFER-06-1.*CLOSED|P34-DEFER-08b-1.*CLOSED|P34-DEFER-08b-2.*CLOSED|P34-DEFER-09-2.*CLOSED' .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md</automated>
  </verify>
  <acceptance_criteria>
    - Closure section exists: `grep -c '^## Phase 36 closure' deferred-items.md` returns 1.
    - All 5 P34-DEFER-* items marked closed: `grep -cE 'P34-DEFER-04b-1.*CLOSED|P34-DEFER-06-1.*CLOSED|P34-DEFER-08b-1.*CLOSED|P34-DEFER-08b-2.*CLOSED|P34-DEFER-09-2.*CLOSED' deferred-items.md` returns ≥ 5.
    - Phase 35 closure section unchanged (verify via `git diff main~1..main -- .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md` — only additions at end, no deletions in Phase 35 region).
    - v2.5-FU-3/4/5/6 carry-forwards listed: `grep -cE 'v2\.5-FU-(3|4|5|6)' deferred-items.md` returns ≥ 4.
  </acceptance_criteria>
  <done>Phase 36 closure section appended; 5 P34-DEFER-* items flipped to closed; carry-forwards listed; Phase 35 closure region untouched.</done>
</task>

<task type="auto">
  <name>Task 6: Close-gate verification + D-20 commit body shape (per D-36-A5)</name>
  <files>(verification only — Tasks 1-5 already committed individually OR commit all of Task 1-5 in one squashed commit per planner choice; D-36-A4 says one PR per plan; recommend ONE commit per Plan 36-01d)</files>
  <read_first>
    - .planning/phases/36-upst3-deep-closure/36-CONTEXT.md § D-36-A5 (all 8 close-gate steps)
    - .planning/phases/36-upst3-deep-closure/36-CONTEXT.md § D-36-A4 (one PR per plan)
  </read_first>
  <action>
    1. Run all 8 D-36-A5 close-gate steps on Windows host:
       1. `cargo test --workspace --all-features` — must exit 0 (embedded built-in profile data + new builtin_profile_load test must pass)
       2. `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` — must exit 0
       3. `cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` — must exit 0
       4. `cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used` — must exit 0
       5. `cargo fmt --all -- --check` — must exit 0
       6. (skip-document: Plan 36-01d does not touch detached-console code paths)
       7. (skip-document: Plan 36-01d does not touch WFP)
       8. (skip-document: Plan 36-01d does not touch learn)
       9. ALSO RUN: `bash scripts/test-list-aliases.sh` exits 0; `bash scripts/lint-docs.sh` exits 0 (new tooling smoke).
    2. Commit (single atomic commit for the data + docs + tooling closure; if tasks were committed individually during execution, squash to one for clean reviewer diff per D-36-A4 one-PR-per-plan invariant). Commit body shape (D-20 manual-replay; NO `Upstream-commit:` trailer):
       ```
       feat(36-01d): migrate built-in profile data + JSON schema + docs + tooling to canonical sections (REQ-PORT-CLOSURE-02 closure)

       Closes REQ-PORT-CLOSURE-02 acceptance criteria #4 (schema regenerator
       matches upstream canonical form), #5 (all 4 built-in profiles migrated),
       and #6 (docs alias-inventory check passes).

       Migrations:
         - data/policy.json: 1 residual override_deny callsite renamed; all 4
           built-in profiles (claude-code, codex, opencode, claude-no-keychain)
           use canonical commands.{allow,deny} + filesystem.{deny,bypass_protection}.
         - data/nono-profile.schema.json: JSON Schema fixture restructured to
           upstream canonical form; fork-specific fields (audit_signer,
           bypass_protection_paths, capability_elevation, resource_limits)
           preserved per D-36-D1 + D-34-B1 fork retention.
         - docs/cli/features/profiles-groups.mdx + docs/cli/usage/flags.mdx:
           migrated to canonical surface; Legacy migration sections cite
           Plan 36-01c + D-36-B3 indefinite acceptance.
         - data/profile-authoring-guide.md: created/extended with canonical
           authoring instructions.

       New tooling:
         - scripts/test-list-aliases.sh: alias inventory enforcement (exits 0
           on clean state).
         - scripts/lint-docs.sh: docs alias-inventory check (exits 0 on clean
           state; marker words Legacy/Deprecated/D-36-B3 bypass lint).

       New test:
         - crates/nono-cli/tests/builtin_profile_load.rs: 5 tests asserting
           each built-in profile loads with canonical sections.

       Closure ledger:
         - Appended Phase 36 closure section to Phase 34 deferred-items.md
           flipping P34-DEFER-04b-1/06-1/08b-1/08b-2/09-2 from open to
           closed-by-Phase-36.

       Closes REQ-PORT-CLOSURE-02 in full (acceptance #1/#2/#3 closed by
       Plans 36-01a/b/c; #4/#5/#6 closed here).

       Design source (D-20 manual replay):
       - f0abd413 (upstream v0.47.0): canonical schema + docs surface

       Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
       Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
       ```
    3. Smoke check at plan close: `git log --format='%B' main~1..main | grep -c '^Upstream-commit: '` returns 0.
  </action>
  <verify>
    <automated>cargo test --workspace --all-features 2>&amp;1 | tail -10 &amp;&amp; cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used 2>&amp;1 | tail -10 &amp;&amp; cargo fmt --all -- --check &amp;&amp; bash scripts/test-list-aliases.sh &amp;&amp; bash scripts/lint-docs.sh &amp;&amp; git log --format='%B' main~1..main | grep -c '^Upstream-commit: '</automated>
  </verify>
  <acceptance_criteria>
    - Close-gate steps 1, 2, 3, 4, 5 exit 0 (Windows + Linux cross-target + macOS cross-target clippy + fmt-check).
    - Both new scripts exit 0: `bash scripts/test-list-aliases.sh && bash scripts/lint-docs.sh` succeeds.
    - Commit body cites Plan 36-01d + REQ-PORT-CLOSURE-02 closure: `git log --format='%B' main~1..main | grep -E '36-01d|REQ-PORT-CLOSURE-02' | wc -l` returns ≥ 2.
    - Commit body cites `f0abd413` as design source: `git log --format='%B' main~1..main | grep -c 'f0abd413'` returns ≥ 1.
    - NO `Upstream-commit:` trailer: `git log --format='%B' main~1..main | grep -c '^Upstream-commit: '` returns 0.
    - DCO trailer present: `git log --format='%B' main~1..main | grep -c '^Signed-off-by: '` returns ≥ 1.
  </acceptance_criteria>
  <done>Plan 36-01d committed on `main` with D-20 manual-replay shape; close-gate green; REQ-PORT-CLOSURE-02 fully closed across Plans 36-01a/b/c/d; Phase 36 closure ledger entry in deferred-items.md.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Built-in profile JSON data at build time → embedded loader | Trusted at build time (fork-controlled data files); regression here breaks every nono invocation that uses a built-in profile |
| JSON Schema fixture → `jsonschema` validator (dev-dep) | Trusted at test time; schema must accept all canonical + fork-only fields without false rejections |
| Shell scripts `test-list-aliases.sh` + `lint-docs.sh` → CI / pre-commit consumers | Trusted tooling output; must reject drift cleanly without false positives |
| Doc MDX files → user-facing documentation | Trusted public surface; legacy references must be marked or removed to avoid mixed messaging |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-36-01-DATA-MIGRATE | Tampering | Built-in profile JSON migration silently changes semantic content (e.g., a path moves from `allow` to `bypass_protection` when it shouldn't) | mitigate | Task 1 audits each of the 4 built-in profiles per-section; Task 2 integration tests assert each profile loads with expected canonical structure; commit body documents per-profile dispositions. |
| T-36-01-SCHEMA-FORK-LEAK | Information Disclosure | JSON Schema restructure silently removes fork-only fields (audit_signer, bypass_protection_paths, capability_elevation, resource_limits, etc.), causing future fork-profile-load failures | mitigate | Task 1 step 4 explicitly preserves fork-specific fields per D-36-D1 + D-34-B1 catalog. Schema regenerator (`scripts/regenerate-schema.sh`) byte-for-byte match check catches drift. |
| T-36-01-LINT-FALSE-POSITIVE | Denial of Service | `lint-docs.sh` false-positives on legitimate historical references in changelogs / migration sections | mitigate | Marker-word allowlist (`Legacy`, `Deprecated`, `D-36-B3`) lets intentional references through. Task 4 verifies clean exit after docs migration. |
| T-36-01-LINT-FALSE-NEGATIVE | Tampering | `lint-docs.sh` misses unmarked drift because the marker-word grep is too permissive | accept | The marker words are deliberate D-36-B3 indefinite-acceptance markers; any developer intentionally documenting a legacy alias adds the marker. Conservatism is acceptable given D-36-B3 keeps the surface accepted indefinitely. |
| T-36-01-SCRIPT-WINDOWS-FAIL | Denial of Service | New shell scripts fail on Windows Git Bash because of MSYS path conversion or `set -euo pipefail` interactions | mitigate | Both scripts mirror `scripts/check-upstream-drift.sh` shape verified to run on Git Bash. `LC_ALL=C.UTF-8 2>/dev/null || true` line guards against locale-shape failures. |
| T-36-01-CLOSURE-LEDGER-DRIFT | Information Disclosure | Phase 36 closure ledger entry silently overwrites or shadows the existing Phase 35 closure section | mitigate | Task 5 step 4 explicitly forbids modifying the Phase 35 region; `git diff` review verifies only-additions in the deferred-items.md diff. |
| T-36-01-SUMMARY-MISCITATION | Repudiation | Closure section cites SUMMARY files that don't exist yet (e.g., 36-02 + 36-03 not closed when 36-01d closes) | mitigate | Task 5 step 1 verifies existence via `ls` before composing the closure section. If 36-02 / 36-03 SUMMARYs are absent at Plan 36-01d close, the closure section omits their citations OR Plan 36-01d's closure is deferred to whichever plan is genuinely last. |
| T-36-01-LIBRARY-TIER-LEAK | Elevation of Privilege | Data migration accidentally introduces new policy invariants into `crates/nono/src/` library tier | accept | Plan 36-01d touches NO Rust source files (data + scripts + docs only). The risk is zero by construction. |
</threat_model>

<verification>
## Per-Plan Verification

1. **Built-in profile data migrated:**
   ```bash
   grep -c '"bypass_protection"' crates/nono-cli/data/policy.json
   # Expected: ≥ 1
   grep -c '"override_deny"' crates/nono-cli/data/policy.json
   # Expected: 0
   ```

2. **Schema fixture restructured:**
   ```bash
   grep -c '"bypass_protection"' crates/nono-cli/data/nono-profile.schema.json
   # Expected: ≥ 1
   grep -c '"commands"' crates/nono-cli/data/nono-profile.schema.json
   # Expected: ≥ 1
   ```

3. **Integration tests green:**
   - `cargo test -p nono-cli --test builtin_profile_load` exits 0 (all 5 tests pass)

4. **Tooling scripts present + green:**
   ```bash
   test -x scripts/test-list-aliases.sh && test -x scripts/lint-docs.sh
   bash scripts/test-list-aliases.sh ; echo "exit: $?"   # 0
   bash scripts/lint-docs.sh ; echo "exit: $?"            # 0
   ```

5. **Docs migrated:**
   ```bash
   grep -c 'bypass_protection' docs/cli/features/profiles-groups.mdx
   # Expected: ≥ 1
   grep -c '\-\-bypass-protection' docs/cli/usage/flags.mdx
   # Expected: ≥ 1
   ```

6. **Closure ledger entry present:**
   ```bash
   grep -c '^## Phase 36 closure' .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md
   # Expected: 1
   grep -cE 'P34-DEFER-04b-1.*CLOSED|P34-DEFER-06-1.*CLOSED|P34-DEFER-08b-1.*CLOSED|P34-DEFER-08b-2.*CLOSED|P34-DEFER-09-2.*CLOSED' .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md
   # Expected: ≥ 5
   ```

7. **Close-gate green (D-36-A5):**
   - Windows clippy + Linux cross-target clippy + macOS cross-target clippy + fmt-check + workspace tests all exit 0
   - `bash scripts/test-list-aliases.sh && bash scripts/lint-docs.sh` exits 0

8. **Commit body D-20 shape:**
   ```bash
   git log --format='%B' main~1..main | grep -c '^Upstream-commit: '
   # Expected: 0
   git log --format='%B' main~1..main | grep -c 'f0abd413'
   # Expected: ≥ 1
   ```
</verification>

<success_criteria>
- All 4 built-in profiles use canonical sections post-migration; embedded loader deserializes cleanly.
- `nono-profile.schema.json` restructured to upstream canonical form while preserving fork-specific fields.
- `scripts/test-list-aliases.sh` + `scripts/lint-docs.sh` created, executable, exiting 0.
- `docs/cli/features/profiles-groups.mdx` + `docs/cli/usage/flags.mdx` migrated with Legacy migration sections.
- `crates/nono-cli/data/profile-authoring-guide.md` present + canonical.
- `crates/nono-cli/tests/builtin_profile_load.rs` covers all 4 built-in profiles (5 tests).
- `scripts/regenerate-schema.sh` Windows compatibility documented (Git Bash OR `.ps1` companion).
- Phase 36 closure section appended to Phase 34 `deferred-items.md` flipping all 5 P34-DEFER-* items.
- All 8 D-36-A5 close-gate steps green (or documented-skipped for steps 6-8).
- Single commit on `main` with D-20 manual-replay shape citing `f0abd413`; NO `Upstream-commit:` trailer.
- **REQ-PORT-CLOSURE-02 FULLY CLOSED** (acceptance criteria #1-#6 across Plans 36-01a + 36-01b + 36-01c + 36-01d).
</success_criteria>

<output>
After completion, create `.planning/phases/36-upst3-deep-closure/36-01d-PROFILE-DATA-DOCS-TOOLING-SUMMARY.md` documenting:
- Files modified (data + scripts + docs + closure ledger)
- Per-built-in-profile audit + migration dispositions
- New tooling scripts + smoke-test outcomes
- Docs migration with Legacy markers used
- Closure ledger entry summary (5 P34-DEFER-* items flipped)
- Close-gate run outcomes
- Final REQ-PORT-CLOSURE-02 closure declaration (Plans 36-01a/b/c/d collectively)
- Hand-off to Phase 36 SUMMARY composition (`/gsd-verify-work` next)
</output>
</content>
</invoke>
