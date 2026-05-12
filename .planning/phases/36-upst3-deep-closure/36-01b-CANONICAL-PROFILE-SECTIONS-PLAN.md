---
phase: 36-upst3-deep-closure
plan: 01b
type: execute
wave: 2
depends_on:
  - 01a
files_modified:
  - crates/nono-cli/src/profile/mod.rs
autonomous: true
requirements:
  - REQ-PORT-CLOSURE-02
tags:
  - phase-36
  - port-closure
  - canonical-sections
  - profile-struct
  - p34-defer-04b-1
  - d-20-manual-replay

must_haves:
  truths:
    - "The `Profile` and `LoadedProfile` structs in `crates/nono-cli/src/profile/mod.rs` expose canonical sections matching upstream `f0abd413`: top-level `groups` (already partially present), `commands.{allow, deny}`, and `filesystem.{deny, bypass_protection}`."
    - "Legacy `override_deny` JSON profile files still deserialize correctly because Plan 36-01a's `LegacyPolicyPatch` rewriter normalizes them to canonical form before they reach `Profile` deserialization (D-36-B3 indefinite acceptance invariant preserved)."
    - "Phase 35 Plan 35-03's serde-driven Map-insertion + omit-when-None JSON emission shape in `profile_to_json` / `diff_to_json` (lines around 800-1000 in profile_cmd.rs) still produces clean JSON output after the canonical-section restructure — no flat-shape regression."
    - "The `From<ProfileDeserialize> for Profile` impl at profile/mod.rs:1642 exhaustively enumerates the new canonical-section fields; no compile error or silent drop on deserialization."
    - "`crates/nono/src/capability.rs::CapabilitySet` builder pattern still composes with the restructured Profile sections — verified via existing capability_ext.rs CapabilitySet-from-Profile construction path."
  artifacts:
    - path: "crates/nono-cli/src/profile/mod.rs"
      provides: "New `pub struct CommandsConfig` with `pub allow: Vec<String>` + `pub deny: Vec<String>` fields, both `#[serde(default)]`. New `pub struct GroupsConfig` with `pub include: Vec<String>` + `pub exclude: Vec<String>` fields if upstream f0abd413 carries that shape (otherwise match upstream's actual shape). Both structs `#[derive(Debug, Clone, Default, Serialize, Deserialize)]` with `#[serde(deny_unknown_fields)]` — mirror existing `CapabilitiesConfig` (lines 270-278) precedent."
      contains: "pub struct CommandsConfig"
    - path: "crates/nono-cli/src/profile/mod.rs"
      provides: "`FilesystemConfig` (currently at lines 202-224) extended with `pub deny: Vec<String>` and `pub bypass_protection: Vec<String>` fields (both `#[serde(default)]`; `bypass_protection` carries `#[serde(alias = \"override_deny\")]` for legacy JSON acceptance per D-36-B3). Existing 6 fields (`allow`, `read`, `write`, `allow_file`, `read_file`, `write_file`) preserved verbatim."
      contains: "pub bypass_protection: Vec<String>"
    - path: "crates/nono-cli/src/profile/mod.rs"
      provides: "`Profile` and `LoadedProfile` structs carry canonical-section fields (`pub groups: GroupsConfig`, `pub commands: CommandsConfig`) wired through the existing `From<ProfileDeserialize> for Profile` impl at line 1642."
      contains: "pub commands: CommandsConfig"
  key_links:
    - from: "crates/nono-cli/src/profile/mod.rs::Profile"
      to: "crates/nono-cli/src/profile/mod.rs::CommandsConfig (new) + ::FilesystemConfig (extended) + ::GroupsConfig (new)"
      via: "struct field composition; serde-driven JSON round-trip"
      pattern: "pub commands: CommandsConfig|pub filesystem: FilesystemConfig|pub groups: GroupsConfig"
    - from: "crates/nono-cli/src/profile/mod.rs::From<ProfileDeserialize> for Profile (line 1642)"
      to: "crates/nono-cli/src/profile/mod.rs::Profile canonical sections"
      via: "exhaustive field enumeration in the From impl"
      pattern: "From<ProfileDeserialize>"
    - from: "Plan 36-01a LegacyPolicyPatch::rewrite()"
      to: "canonical Profile sections (input shape for the normalization target)"
      via: "rewrite output deserializes into canonical-section Profile"
      pattern: "LegacyPolicyPatch::rewrite"
---

<objective>
Restructure `Profile` / `LoadedProfile` and their sibling section sub-structs in `crates/nono-cli/src/profile/mod.rs` (6140 LOC) to expose canonical sections per upstream `f0abd413`: introduce new `CommandsConfig` + `GroupsConfig` types (or match upstream's actual shape), extend `FilesystemConfig` with `deny` + `bypass_protection` fields (carrying serde alias to legacy `override_deny`), and wire all three through the existing `From<ProfileDeserialize> for Profile` impl at line 1642. Closes REQ-PORT-CLOSURE-02 acceptance criterion #1 (canonical sections present) and sets up Plan 36-01c's 183-callsite rename (canonical-field names must exist before rename targets them) and Plan 36-01d's data + docs migration (built-in profile data + JSON schema must align with the new shape).

**Purpose:** Plan 36-01a delivered the rewriter and the strict-mode lever. Plan 36-01b delivers the canonical target shape that the rewriter normalizes INTO. Without canonical sections, the rewriter has nothing to rewrite into.

**Output:** Modified `profile/mod.rs` with 2 new section sub-structs, 1 extended sub-struct, and an updated `From<ProfileDeserialize>` impl. No new files. Existing tests at `canonical_schema_rename_tests` (mod.rs:117-183) extended to cover the new fields.

**Scope ceiling (D-34-B2):** ONLY the struct field additions + `From` impl update + smoke test of `CapabilitySet` composition. NO callsite rename (Plan 36-01c), NO data/docs migration (Plan 36-01d), NO library-tier changes (verify only that `capability.rs::CapabilitySet` still composes; do NOT modify it). NO audit-event hooks.
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
@.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md
@.planning/phases/35-upst3-closure-quick-wins/35-03-WIN-TEST-HYGIENE-SUMMARY.md

<interfaces>
<!-- Existing FilesystemConfig pattern to extend additively (PATTERNS.md § Plan 36-01b). -->

From `crates/nono-cli/src/profile/mod.rs` lines 202-224:
```rust
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemConfig {
    /// Directories with read+write access
    #[serde(default)]
    pub allow: Vec<String>,
    /// Directories with read-only access
    #[serde(default)]
    pub read: Vec<String>,
    /// Directories with write-only access
    #[serde(default)]
    pub write: Vec<String>,
    /// Single files with read+write access
    #[serde(default)]
    pub allow_file: Vec<String>,
    /// Single files with read-only access
    #[serde(default)]
    pub read_file: Vec<String>,
    /// Single files with write-only access
    #[serde(default)]
    pub write_file: Vec<String>,
}
```

<!-- Existing CapabilitiesConfig in-file precedent for new sub-structs (PATTERNS.md § Plan 36-01b). -->

From `crates/nono-cli/src/profile/mod.rs` lines 270-278:
```rust
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitiesConfig {
    #[serde(default)]
    pub aipc: Option<AipcConfig>,
}
```

<!-- Existing From<ProfileDeserialize> for Profile impl at line 1642 — enumerates ~18 fields; canonical sections add 2-3 more. -->

<!-- Plan 36-01a deliverables (now in context from Wave 1): -->
<!-- - crates/nono-cli/src/deprecated_schema.rs::LegacyPolicyPatch::rewrite() returns canonical-form output that must deserialize into the canonical Profile sections this plan creates. -->
</interfaces>

<drift_notes>
1. `crates/nono-cli/data/policy.json` ALREADY uses top-level `groups` shape (verified at policy.json:6). If `groups` is already a struct-level field on `Profile`, Plan 36-01b may only need to add the typed wrapper struct `GroupsConfig` and migrate the existing field's type. Verify before adding a duplicate field.
2. Phase 34-04b's serde alias on the existing `override_deny` field at `profile/mod.rs:439-440` (`#[serde(default, alias = "bypass_protection")]`) MUST be flipped in this plan: canonical becomes `bypass_protection` with alias to legacy `override_deny`. The flip aligns the struct with upstream's canonical-first orientation.
3. Phase 35 Plan 35-03 landed `profile_to_json` / `diff_to_json` Map-insertion + omit-when-None JSON shape. Verify post-restructure that the new canonical-section fields serialize cleanly into the Map without flat-shape regression. Existing test coverage in `profile_to_json` tests should still pass.
</drift_notes>
</context>

<tasks>

<task type="auto" tdd="true">
  <name>Task 1: Add new section sub-structs (CommandsConfig, GroupsConfig) + extend FilesystemConfig with canonical deny/bypass_protection fields (per D-36-B1)</name>
  <files>crates/nono-cli/src/profile/mod.rs</files>
  <read_first>
    - crates/nono-cli/src/profile/mod.rs (lines 1-90 — preamble + imports; lines 200-280 — FilesystemConfig + CapabilitiesConfig + AipcConfig sub-structs; lines 430-475 — current `override_deny` field with Phase 34-04b serde alias; lines 1620-1675 — `From<ProfileDeserialize> for Profile` impl boundary)
    - .planning/phases/36-upst3-deep-closure/36-PATTERNS.md § `crates/nono-cli/src/profile/mod.rs` — canonical Profile sections (Plan 36-01b)
    - .planning/phases/36-upst3-deep-closure/36-RESEARCH.md § Plan 36-01b technical approach (lines 526-549)
    - crates/nono-cli/data/policy.json (lines 1-80 — verify existing `groups` shape so the new GroupsConfig struct matches the JSON data shape, not invents a divergent shape)
  </read_first>
  <behavior>
    - Test 1 (extend `canonical_schema_rename_tests`): legacy JSON `{"filesystem": {"override_deny": ["/var/log"]}}` deserializes into `FilesystemConfig` with `bypass_protection == ["/var/log"]` (legacy alias preserved per D-36-B3).
    - Test 2: canonical JSON `{"filesystem": {"deny": ["/etc"], "bypass_protection": ["/var/log"]}}` deserializes cleanly with both fields populated.
    - Test 3: empty JSON `{"filesystem": {}}` deserializes with both `deny` and `bypass_protection` defaulting to `vec![]` (per `#[serde(default)]`).
    - Test 4: JSON `{"commands": {"allow": ["git"], "deny": ["rm"]}}` deserializes into `CommandsConfig` with both fields populated.
    - Test 5: unknown field rejected: `{"commands": {"unknown_key": []}}` returns an error (`#[serde(deny_unknown_fields)]` invariant preserved).
  </behavior>
  <action>
    1. **Define `CommandsConfig`** as a new sub-struct in `profile/mod.rs` near the existing `CapabilitiesConfig` (lines 270-278). Mirror its shape exactly:
       ```rust
       /// Commands configuration in a profile (canonical section per upstream f0abd413, v0.47.0)
       #[derive(Debug, Clone, Default, Serialize, Deserialize)]
       #[serde(deny_unknown_fields)]
       pub struct CommandsConfig {
           /// Commands explicitly allowed for the sandboxed child
           #[serde(default)]
           pub allow: Vec<String>,
           /// Commands explicitly denied for the sandboxed child
           #[serde(default)]
           pub deny: Vec<String>,
       }
       ```
    2. **Define `GroupsConfig`** as a new sub-struct. FIRST verify what shape upstream f0abd413 actually carries — read upstream source: `git show upstream/f0abd413:crates/nono-cli/src/profile/mod.rs | grep -A 15 'struct.*GroupsConfig\|struct.*Groups'`. Match that shape exactly. If upstream has no `GroupsConfig` struct (the field is just `HashMap<String, GroupConfig>`), then either (a) wrap the existing fork field in a typed `GroupsConfig` newtype if useful, or (b) skip this struct and just verify the existing top-level `groups` field on `Profile` matches the upstream shape. Document the choice in commit body.
    3. **Extend `FilesystemConfig`** (currently lines 202-224) by adding `pub deny: Vec<String>` and `pub bypass_protection: Vec<String>` fields after the existing 6 fields. Apply this exact shape:
       ```rust
       /// Directories explicitly denied for the sandboxed child (canonical
       /// section per upstream f0abd413, v0.47.0)
       #[serde(default)]
       pub deny: Vec<String>,
       /// Paths that bypass deny rules when paired with an explicit
       /// user-intent grant. Canonical key per upstream f0abd413; legacy
       /// `override_deny` accepted indefinitely via serde alias per D-36-B3.
       #[serde(default, alias = "override_deny")]
       pub bypass_protection: Vec<String>,
       ```
       Preserve `#[serde(deny_unknown_fields)]` on the struct.
    4. **Verify existing `override_deny` field** at lines 439-440 (`PolicyPatchConfig` or wherever Phase 34-04b's Option C scaffolding lives). Plan 36-01b's task is the struct ADDITION; the field rename to `bypass_protection` happens atomically in Plan 36-01c. For now, leave `PolicyPatchConfig::override_deny` as-is — do NOT touch in this plan to avoid Wave 2 ordering conflict with Plan 36-01c.
    5. **Extend `canonical_schema_rename_tests`** mod (lines 117-183). Add the 5 tests enumerated in `<behavior>`. Use only inline `let json = r#"..."#; serde_json::from_str::<...>(json)` patterns; no env-var manipulation needed for these struct-deserialization tests.
    6. Run `cargo build -p nono-cli` — must succeed. Run `cargo test -p nono-cli --lib profile::canonical_schema_rename_tests` — all tests pass.
  </action>
  <verify>
    <automated>cargo test -p nono-cli --lib profile::canonical_schema_rename_tests -- --nocapture 2>&amp;1 | tee /tmp/36-01b-task1.log</automated>
  </verify>
  <acceptance_criteria>
    - `CommandsConfig` struct exists with allow + deny fields (grep: `grep -A 10 'pub struct CommandsConfig' crates/nono-cli/src/profile/mod.rs | grep -E 'pub allow:|pub deny:' | wc -l` returns 2).
    - `FilesystemConfig` extended with both new fields (grep: `grep -A 30 'pub struct FilesystemConfig' crates/nono-cli/src/profile/mod.rs | grep -E 'pub deny: Vec<String>|pub bypass_protection: Vec<String>' | wc -l` returns 2).
    - Legacy alias on `bypass_protection` preserved (grep: `grep -B1 'pub bypass_protection: Vec<String>' crates/nono-cli/src/profile/mod.rs | grep -c 'alias = "override_deny"'` returns 1).
    - All sub-structs preserve `#[serde(deny_unknown_fields)]` (grep: `grep -B1 'pub struct CommandsConfig' crates/nono-cli/src/profile/mod.rs | grep -c 'deny_unknown_fields'` returns 1; same for GroupsConfig if introduced).
    - 5 new tests pass: `cargo test -p nono-cli --lib profile::canonical_schema_rename_tests` exits 0 with test count ≥ 5 above pre-existing baseline.
    - Test ID **36-01b-* / T-36-01-CANONICAL**: serde round-trip of canonical JSON succeeds.
  </acceptance_criteria>
  <done>Section sub-structs added without touching Phase 34-04b's existing `override_deny` field; legacy alias preserved on the new `bypass_protection` field; 5 new tests lock the canonical-section serde invariants.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: Wire canonical sections through Profile/LoadedProfile + From<ProfileDeserialize> impl + verify CapabilitySet composition (per D-36-B1)</name>
  <files>crates/nono-cli/src/profile/mod.rs</files>
  <read_first>
    - crates/nono-cli/src/profile/mod.rs (lines 1620-1700 — `From<ProfileDeserialize> for Profile` impl with all enumerated fields; the existing Profile struct definition + LoadedProfile)
    - crates/nono/src/capability.rs (verify CapabilitySet builder shape — read-only; MUST NOT modify the library)
    - crates/nono-cli/src/capability_ext.rs (existing CapabilitySet-from-Profile construction path; reference for what the From impl must continue to support)
    - .planning/phases/35-upst3-closure-quick-wins/35-03-WIN-TEST-HYGIENE-SUMMARY.md (Phase 35 Map-insertion JSON shape invariant — must compose cleanly with new fields)
  </read_first>
  <behavior>
    - Test 1 (`profile_round_trip_with_canonical_sections`): canonical Profile JSON `{"name": "test", "filesystem": {"deny": ["/etc"]}, "commands": {"allow": ["git"]}}` round-trips through `From<ProfileDeserialize> for Profile` without field loss.
    - Test 2 (`legacy_filesystem_override_deny_normalizes_to_bypass_protection`): JSON `{"filesystem": {"override_deny": ["/var/log"]}}` deserializes into Profile with `filesystem.bypass_protection == ["/var/log"]` (via serde alias).
    - Test 3 (smoke; non-test code): `cargo build -p nono-cli` succeeds — proves CapabilitySet composition unchanged.
    - Test 4 (existing profile_to_json shape preserved): write a Profile with both canonical sections populated, run profile_to_json (or comparable serializer), parse the JSON back, verify `commands` and `filesystem.deny` and `filesystem.bypass_protection` keys are present at expected nesting depth (composes with Phase 35 Map-insertion shape).
  </behavior>
  <action>
    1. **Add canonical-section fields to `Profile` and `LoadedProfile`** structs. After identifying the structs' definitions (search for `pub struct Profile {` and `pub struct LoadedProfile {`), add these fields where appropriate (typically alongside or after the existing `policy: PolicyPatchConfig` / `filesystem: FilesystemConfig` fields):
       ```rust
       /// Commands configuration — canonical section per upstream f0abd413
       #[serde(default)]
       pub commands: CommandsConfig,
       ```
       For `GroupsConfig`: only add if Task 1 introduced the wrapper struct (and the existing top-level `groups` field needs the typed shape). If existing field is already a `HashMap<String, GroupConfig>` that aligns with upstream shape, skip.
    2. **Update `From<ProfileDeserialize> for Profile`** at line 1642. Enumerate the new canonical-section fields exhaustively. The pattern:
       ```rust
       impl From<ProfileDeserialize> for Profile {
           fn from(d: ProfileDeserialize) -> Self {
               Self {
                   // ... existing 18 fields ...
                   commands: d.commands,
                   // groups: d.groups,  // only if Task 1 added GroupsConfig
                   // ... continue ...
               }
           }
       }
       ```
       Verify the impl is exhaustive — Rust's missing-field error will catch omissions if the struct definition has a `#[non_exhaustive]` attribute (verify presence; if absent, add via Cargo build error if a field is missed).
    3. **Verify CapabilitySet composition unchanged** by reading `capability_ext.rs` (do NOT modify) and ensuring all references to `profile.policy.override_deny`, `profile.filesystem.allow`, etc. still compile post-restructure. Plan 36-01c will rename these callsites atomically; Plan 36-01b only needs `cargo build` to succeed with the new fields (existing callsites still reference `override_deny`, which still exists on `PolicyPatchConfig` — that's correct, the rename happens in Wave 2's Plan 36-01c).
    4. **Add the 4 tests** enumerated in `<behavior>` into `canonical_schema_rename_tests` mod (extending Task 1's additions).
    5. **Phase 35 Map-shape smoke test**: read Phase 35 Plan 35-03 SUMMARY notes on `profile_to_json` / `diff_to_json` Map-insertion. Run `cargo test -p nono-cli --lib profile_cmd::tests::profile_to_json` (or whichever test name Plan 35-03 used) and verify still green. If a test exists named `profile_to_json_omits_none_options` or similar, run it explicitly.
    6. Run `cargo build -p nono-cli` then `cargo test -p nono-cli --lib profile::` — all profile tests must pass.
    7. Run `cargo clippy -p nono-cli --all-targets -- -D warnings -D clippy::unwrap_used` — must be clean.
  </action>
  <verify>
    <automated>cargo build -p nono-cli 2>&amp;1 | tail -10 &amp;&amp; cargo test -p nono-cli --lib profile:: 2>&amp;1 | tail -20 &amp;&amp; cargo clippy -p nono-cli --all-targets -- -D warnings -D clippy::unwrap_used 2>&amp;1 | tail -10</automated>
  </verify>
  <acceptance_criteria>
    - `Profile` and `LoadedProfile` structs reference `CommandsConfig` (grep: `grep -E 'pub commands: CommandsConfig|commands: CommandsConfig' crates/nono-cli/src/profile/mod.rs | wc -l` returns ≥ 2 — once each for the two structs, plus once in From impl).
    - `From<ProfileDeserialize> for Profile` references the new fields (grep: `grep -A 50 'impl From<ProfileDeserialize> for Profile' crates/nono-cli/src/profile/mod.rs | grep -c 'commands:'` returns 1).
    - All existing profile tests still pass plus the 4 new tests: `cargo test -p nono-cli --lib profile::` exits 0.
    - Phase 35 Map-shape preserved: `cargo test -p nono-cli --lib profile_cmd::` exits 0 (no JSON Map regression).
    - CapabilitySet composition unchanged: `cargo build -p nono-cli` exits 0 (no compile error in capability_ext.rs).
    - Test ID **36-01b-* / T-36-01-CANONICAL** (full): canonical sections round-trip + legacy alias normalizes + Phase 35 Map shape preserved.
    - Windows host clippy clean: `cargo clippy -p nono-cli --all-targets -- -D warnings -D clippy::unwrap_used` exits 0.
  </acceptance_criteria>
  <done>Canonical-section fields land on `Profile` + `LoadedProfile`; From impl exhaustively maps them; Phase 35 Map-shape JSON serialization preserved; library-tier `capability.rs` untouched and composition verified by `cargo build`.</done>
</task>

<task type="auto">
  <name>Task 3: Close-gate verification + D-20 commit body citing upstream f0abd413 (per D-36-A5 + D-36-B1)</name>
  <files>(verification only — no code mutation; commit message follows D-20 manual-replay shape)</files>
  <read_first>
    - .planning/phases/36-upst3-deep-closure/36-CONTEXT.md § D-36-A5 (all 8 close-gate steps)
    - .planning/phases/36-upst3-deep-closure/36-01a-DEPRECATED-SCHEMA-MODULE-SUMMARY.md (Wave 1 closure)
  </read_first>
  <action>
    1. Run all 8 D-36-A5 close-gate steps on Windows host (steps 1, 2, 3, 4, 5 are load-bearing; 6, 7, 8 can be skip-documented if Plan 36-01b touches no detached-console / WFP / learn paths):
       1. `cargo test --workspace --all-features`
       2. `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used`
       3. `cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used`
       4. `cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used`
       5. `cargo fmt --all -- --check`
       6. (skip-document: Plan 36-01b does not touch detached-console code paths)
       7. (skip-document: Plan 36-01b does not touch WFP)
       8. (skip-document: Plan 36-01b does not touch learn)
    2. Commit in a single git commit with this exact body shape (D-20 manual-replay; NO `Upstream-commit:` trailer):
       ```
       feat(36-01b): canonical Profile sections (commands, filesystem.deny/bypass_protection, optional groups)

       Extends Plan 36-01a's deprecated_schema port with the canonical Profile
       struct shape from upstream f0abd413 (v0.47.0):
         - New CommandsConfig sub-struct: { allow: Vec<String>, deny: Vec<String> }.
         - FilesystemConfig extended with `deny` and `bypass_protection` fields;
           `bypass_protection` carries serde alias to legacy `override_deny`
           per D-36-B3 indefinite acceptance.
         - GroupsConfig wrapper added [or skipped, per upstream f0abd413 actual
           shape — see commit body for the verified choice].
         - From<ProfileDeserialize> for Profile updated exhaustively to map
           the new fields.

       Library tier (crates/nono/src/capability.rs::CapabilitySet) untouched;
       composition with restructured Profile sections verified by cargo build.
       Phase 35 Plan 35-03 Map-insertion JSON emission shape preserved (no
       flat-shape regression in profile_to_json / diff_to_json).

       Closes REQ-PORT-CLOSURE-02 acceptance criterion #1 in full. Plan
       36-01c follows with the 183-callsite override_deny → bypass_protection
       internal rename; Plan 36-01d migrates built-in profile data + JSON
       schema + docs to the canonical shape.

       Design source (D-20 manual replay):
       - f0abd413 (upstream v0.47.0): canonical Profile section restructure

       Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
       Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
       ```
    3. After commit, verify smoke check: `git log --format='%B' main~1..main | grep -c '^Upstream-commit: '` returns 0.
  </action>
  <verify>
    <automated>cargo test --workspace --all-features 2>&amp;1 | tail -10 &amp;&amp; cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used 2>&amp;1 | tail -10 &amp;&amp; cargo fmt --all -- --check &amp;&amp; git log --format='%B' main~1..main | grep -c '^Upstream-commit: '</automated>
  </verify>
  <acceptance_criteria>
    - Close-gate steps 1, 2, 3, 4, 5 exit 0.
    - Commit body cites `f0abd413` as design source: `git log --format='%B' main~1..main | grep -c 'f0abd413'` returns ≥ 1.
    - Commit body cites Plan 36-01b + REQ-PORT-CLOSURE-02: `git log --format='%B' main~1..main | grep -E '36-01b|REQ-PORT-CLOSURE-02' | wc -l` returns ≥ 2.
    - NO `Upstream-commit:` trailer: `git log --format='%B' main~1..main | grep -c '^Upstream-commit: '` returns 0.
    - DCO trailer present: `git log --format='%B' main~1..main | grep -c '^Signed-off-by: '` returns ≥ 1.
  </acceptance_criteria>
  <done>Plan 36-01b committed on `main` with D-20 manual-replay shape; canonical sections land on Profile / LoadedProfile; Wave 2 Plan 36-01c can proceed (canonical-field names now exist for the rename to target).</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| User-supplied JSON profile → `From<ProfileDeserialize> for Profile` | Untrusted input crosses here; serde must reject unknown fields and ill-typed sections |
| Legacy `override_deny` JSON key → canonical `bypass_protection` (via serde alias) | Trusted normalization boundary; alias must preserve semantic equivalence |
| `CapabilitySet` builder consumes restructured `Profile` | Library-CLI tier boundary; the library is policy-free per `crates/nono/src/lib.rs` invariant — Plan 36-01b must NOT push policy into the library |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-36-01-CANONICAL | Tampering / Elevation of Privilege | `From<ProfileDeserialize> for Profile` non-exhaustive impl could silently drop a canonical-section field | mitigate | Task 2 enumerates all new fields explicitly in the From impl; Rust's struct-literal exhaustiveness check (`Self { a, b, c }` without `..rest`) catches missing fields at compile time. `cargo build` step in Task 2 is the gate. |
| T-36-01-LEGACY-ALIAS | Tampering | Legacy `override_deny` JSON silently dropped if alias missing on `bypass_protection` | mitigate | Task 1 adds `#[serde(default, alias = "override_deny")]` on `bypass_protection`. Test 2 in Task 1 verifies legacy JSON deserializes correctly post-restructure. |
| T-36-01-UNKNOWN-FIELDS | Tampering | New sub-structs accept unknown fields silently, enabling typo'd attack surfaces | mitigate | Task 1 requires `#[serde(deny_unknown_fields)]` on `CommandsConfig` + `GroupsConfig`. Test 5 in Task 1 locks this invariant. |
| T-36-01-MAP-SHAPE-REGRESS | Information Disclosure | Phase 35 Plan 35-03's `profile_to_json` Map-insertion shape silently changes when new fields land, leaking flat-shape JSON to consumers | mitigate | Task 2 step 5 runs `cargo test -p nono-cli --lib profile_cmd::` to verify Map-shape tests still pass. Plan 35-03 closure SUMMARY available as reference. |
| T-36-01-LIB-TIER-LEAK | Elevation of Privilege | A change to `capability.rs::CapabilitySet` would push policy into the library (violating the library-is-policy-free invariant per `CLAUDE.md` § Library vs CLI Boundary) | mitigate | Task 2 step 3 explicitly verifies CapabilitySet composition by `cargo build` only — NO modification to `crates/nono/src/capability.rs`. PATTERNS.md § Plan 36-01b Match Quality `n/a` for this file (read-only verification). |
| T-36-01-PHASE-34-04B-COEXIST | Tampering | Plan 36-01b leaves Phase 34-04b's existing `override_deny` field on `PolicyPatchConfig` (lines 439-440); could create deserialization ambiguity if both `bypass_protection` (new on FilesystemConfig) and `override_deny` (existing on PolicyPatchConfig) coexist | accept | Plan 36-01c follows in Wave 2 and atomically renames `PolicyPatchConfig::override_deny` to `bypass_protection`. During the brief window (Wave 2 plans 36-01b → 36-01c → 36-01d) where both exist, the two are on DIFFERENT structs (FilesystemConfig vs PolicyPatchConfig) so no JSON deserialization ambiguity — they're sibling sections on Profile. |
</threat_model>

<verification>
## Per-Plan Verification

1. **New sub-structs exist with correct shape:**
   ```bash
   grep -c 'pub struct CommandsConfig' crates/nono-cli/src/profile/mod.rs
   # Expected: 1
   grep -A 10 'pub struct CommandsConfig' crates/nono-cli/src/profile/mod.rs | grep -E 'pub allow:|pub deny:' | wc -l
   # Expected: 2
   ```

2. **FilesystemConfig extended:**
   ```bash
   grep -A 30 'pub struct FilesystemConfig' crates/nono-cli/src/profile/mod.rs | grep -c 'pub bypass_protection: Vec<String>'
   # Expected: 1
   grep -B1 'pub bypass_protection: Vec<String>' crates/nono-cli/src/profile/mod.rs | grep -c 'alias = "override_deny"'
   # Expected: 1
   ```

3. **From impl updated:**
   ```bash
   grep -A 50 'impl From<ProfileDeserialize> for Profile' crates/nono-cli/src/profile/mod.rs | grep -c 'commands:'
   # Expected: 1
   ```

4. **Phase 35 Map-shape preserved:**
   ```bash
   cargo test -p nono-cli --lib profile_cmd:: 2>&1 | grep -E 'test result:|FAILED'
   # Expected: all green
   ```

5. **Library tier untouched:**
   ```bash
   git diff main~1..main -- crates/nono/src/capability.rs | wc -l
   # Expected: 0 (no library tier change)
   ```

6. **Close-gate green:**
   - Windows clippy + Linux cross-target clippy + macOS cross-target clippy + fmt-check all exit 0

7. **Commit shape correct (D-20 manual-replay):**
   ```bash
   git log --format='%B' main~1..main | grep -c '^Upstream-commit: '
   # Expected: 0 (no D-19 trailer)
   ```
</verification>

<success_criteria>
- `CommandsConfig` (+ optional `GroupsConfig` if upstream f0abd413 has it) sub-structs added to `profile/mod.rs` mirroring `CapabilitiesConfig` shape precedent.
- `FilesystemConfig` extended with `deny` + `bypass_protection` (legacy alias preserved).
- `Profile` + `LoadedProfile` carry the new canonical-section fields.
- `From<ProfileDeserialize> for Profile` impl exhaustively maps the new fields.
- `crates/nono/src/capability.rs` UNTOUCHED (library is policy-free per CLAUDE.md invariant).
- Phase 35 Plan 35-03 `profile_to_json` Map-insertion JSON shape preserved — all Phase 35 tests still green.
- 9 new tests in `canonical_schema_rename_tests` (5 from Task 1 + 4 from Task 2) lock the canonical-section serde + From-impl invariants.
- All 8 D-36-A5 close-gate steps green (or documented-skipped for steps 6-8).
- Single commit on `main` with D-20 manual-replay shape citing `f0abd413`; NO `Upstream-commit:` trailer.
- REQ-PORT-CLOSURE-02 acceptance criterion #1 fully met (canonical sections present + tested).
</success_criteria>

<output>
After completion, create `.planning/phases/36-upst3-deep-closure/36-01b-CANONICAL-PROFILE-SECTIONS-SUMMARY.md` documenting:
- Files modified with LOC deltas (single file: `profile/mod.rs`)
- New sub-structs added + extended sub-structs
- From impl field-enumeration list (paste the diff snippet)
- Phase 35 Map-shape test results (pass/fail)
- Close-gate steps run + outcomes
- Hand-off to Plan 36-01c (canonical-field NAMES now exist for the atomic rename target)
- Note for Plan 36-01d: built-in profile data + JSON schema migration consumes this struct shape
</output>
</content>
</invoke>