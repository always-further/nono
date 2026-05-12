---
phase: 36-upst3-deep-closure
plan: 01c
type: execute
wave: 2
depends_on:
  - 01b
files_modified:
  - crates/nono-cli/src/profile/mod.rs
  - crates/nono-cli/src/profile_save_runtime.rs
  - crates/nono-cli/src/capability_ext.rs
  - crates/nono-cli/src/cli.rs
  - crates/nono-cli/src/profile_cmd.rs
  - crates/nono-cli/src/profile_runtime.rs
  - crates/nono-cli/src/sandbox_state.rs
  - crates/nono-cli/src/learn.rs
  - crates/nono-cli/src/policy.rs
  - crates/nono-cli/src/profile/builtin.rs
  - crates/nono-cli/src/command_runtime.rs
  - crates/nono-cli/src/query_ext.rs
  - crates/nono-cli/src/sandbox_prepare.rs
  - crates/nono-cli/src/execution_runtime.rs
  - crates/nono-cli/src/launch_runtime.rs
  - crates/nono-cli/src/main.rs
  - crates/nono-cli/src/why_runtime.rs
autonomous: true
requirements:
  - REQ-PORT-CLOSURE-02
tags:
  - phase-36
  - port-closure
  - atomic-rename
  - override-deny
  - bypass-protection
  - p34-defer-04b-1
  - d-20-manual-replay
  - d-36-b4

must_haves:
  truths:
    - "Across all 17 fork-side source files listed in `files_modified`, every occurrence of the identifier `override_deny` that refers to the schema-level field has been renamed to `bypass_protection` in a SINGLE atomic git commit (per D-36-B4)."
    - "The clap CLI flag at `cli.rs` lines 1355-1368 has its long-name and visible_alias direction FLIPPED: canonical long-name becomes `--bypass-protection`; legacy `--override-deny` remains accepted via `visible_alias` (per PATTERNS.md § Plan 36-01c CLI flag alias direction flip)."
    - "Existing JSON profile files in user environments containing legacy `override_deny` keys continue to deserialize correctly because (a) the serde alias `#[serde(default, alias = \"override_deny\")]` on the new `bypass_protection` field (Plan 36-01b Task 1) preserves JSON-shape acceptance, AND (b) Plan 36-01a's `LegacyPolicyPatch` rewriter normalizes legacy keys post-parse."
    - "`cargo build --workspace --all-features` succeeds at the commit boundary; `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` is clean; `cargo test --workspace --all-features` is fully green — atomic rename gate per D-36-B4."
    - "All test fixtures in `crates/nono-cli/tests/fixtures/` and `crates/nono-cli/data/policy.json` referenced by tests use canonical key names (any residual `override_deny` references in JSON files are intentional legacy-coverage fixtures, NOT broken-after-rename callsites)."
  artifacts:
    - path: "crates/nono-cli/src/profile/mod.rs"
      provides: "66 callsites of `override_deny` renamed to `bypass_protection`. Includes Phase 34-04b's `PolicyPatchConfig` field rename (at lines 439-440 — the field that survived Plan 36-01b as-is), with its existing `#[serde(default, alias = \"bypass_protection\")]` annotation FLIPPED to `#[serde(default, alias = \"override_deny\")]` (canonical-first orientation)."
      contains: "pub bypass_protection: Vec<String>"
    - path: "crates/nono-cli/src/cli.rs"
      provides: "14 callsites renamed including the canonical CLI flag flip per PATTERNS.md § Plan 36-01c. `#[arg(long = \"bypass-protection\", visible_alias = \"override-deny\", ...)]` replaces the previous `#[arg(long = \"override-deny\", visible_alias = \"bypass-protection\", ...)]` shape. Internal Rust field rename: `pub override_deny: Vec<PathBuf>` → `pub bypass_protection: Vec<PathBuf>`."
      contains: "long = \"bypass-protection\""
    - path: "crates/nono-cli/src/capability_ext.rs"
      provides: "23 callsites renamed. Includes function-local variables like `profile_overrides` (line 629), function params like `profile_override_deny` → `profile_bypass_protection` for consistency. The underlying lower-level helper `apply_deny_overrides` (at line 668) is KEPT as-is — its semantics are broader than the field rename (PATTERNS.md guidance)."
      contains: "profile.policy.bypass_protection"
  key_links:
    - from: "crates/nono-cli/src/profile/mod.rs::FilesystemConfig::bypass_protection (already canonical post-Plan 36-01b)"
      to: "crates/nono-cli/src/profile/mod.rs::PolicyPatchConfig::bypass_protection (renamed in this plan)"
      via: "both fields now share the canonical name; serde alias on each preserves legacy JSON deserialization"
      pattern: "pub bypass_protection: Vec"
    - from: "crates/nono-cli/src/cli.rs::OverrideDenyArg (or whatever the cli-level type is named)"
      to: "all 16 other files consuming `profile.policy.bypass_protection`"
      via: "atomic rename across the dependency tree"
      pattern: "\\.bypass_protection\\b"
---

<objective>
Land the atomic single-commit rename of `override_deny` → `bypass_protection` across 17 fork-side source files (183 callsites verified by RESEARCH.md Drift Note 3) per D-36-B4. Flips the canonical CLI flag direction so `--bypass-protection` becomes the primary long-name and `--override-deny` survives as a clap `visible_alias`. Single mechanical sed/IDE rename pass; relies on Rust's type system + `cargo build --workspace --all-features` + `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` + `cargo test --workspace --all-features` gate at the commit boundary to guarantee rename consistency. Matches Phase 33 + Phase 34 atomic-cherry-pick discipline: reviewer sees one clean diff, rollback is one revert. NO staged file-by-file mini-commits; NO type-alias scaffolding; NO two-step types-first commits.

**Purpose:** Plan 36-01b added canonical-section fields (which now sit alongside Phase 34-04b's existing `override_deny` field on `PolicyPatchConfig`). Plan 36-01c retires the internal Rust identifier `override_deny` everywhere, leaving only the legacy JSON-key acceptance (via serde alias + LegacyPolicyPatch rewriter) and the legacy CLI flag (via clap visible_alias) for user-facing backward-compat. After Plan 36-01c, fork's `.rs` source contains ZERO references to `override_deny` as a struct field, variable name, or function param.

**Output:** Single atomic commit modifying 17 `.rs` files. Pre-flight `cargo clean -p nono-cli` to clear stale incremental compilation artifacts. Mechanical rename pass; cargo build/clippy/test gate at commit time guarantees consistency.

**Scope ceiling (D-36-B4):** ONLY the schema-level identifier rename. NO data migration (Plan 36-01d does built-in profile data + JSON schema fixtures). NO docs migration (Plan 36-01d). NO new helpers, NO new tests beyond what the rename pass touches (any test fixture string `"override_deny"` in JSON files is examined case-by-case per PATTERNS.md guidance).
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

<interfaces>
<!-- Existing CLI flag pattern to flip (PATTERNS.md § Plan 36-01c CLI flag alias direction flip). -->

From `crates/nono-cli/src/cli.rs` lines 1355-1368 (current Phase 34-04b state):
```rust
/// Override a deny rule for a path. Pair with --allow/--read/--write grant
///
/// Plan 34-04b (upstream f0abd413, v0.47.0, #594): canonical flag name
/// is `--bypass-protection`. `--override-deny` continues to work via
/// the clap `visible_alias` for v2.3 backwards-compat. Internal Rust
/// identifier remains `override_deny` (210-callsite flag-day rename
/// deferred to P34-DEFER-04b).
#[arg(
    long = "override-deny",
    visible_alias = "bypass-protection",
    value_name = "PATH",
    help_heading = "FILESYSTEM"
)]
pub override_deny: Vec<PathBuf>,
```

Target post-rename shape (PATTERNS.md exact target):
```rust
/// Override a deny rule for a path. Pair with --allow/--read/--write grant
///
/// Plan 36-01c (upstream f0abd413, v0.47.0, #594): canonical flag name
/// is `--bypass-protection`. `--override-deny` continues to work via
/// the clap `visible_alias` for backwards-compat (indefinite per
/// D-36-B3 — no hard-deprecation date).
#[arg(
    long = "bypass-protection",
    visible_alias = "override-deny",
    value_name = "PATH",
    help_heading = "FILESYSTEM"
)]
pub bypass_protection: Vec<PathBuf>,
```

<!-- Existing callsite shape in capability_ext.rs (PATTERNS.md Pattern: capability_ext.rs canonical callsite rename example). -->

From `crates/nono-cli/src/capability_ext.rs` lines 624-635 (current Phase 34-04b state):
```rust
// Expand profile-level override_deny paths for finalize_caps.
// Existing override targets must fail closed in apply_deny_overrides
// when they lack a matching user-intent grant. [...]
let mut profile_overrides = Vec::with_capacity(profile.policy.override_deny.len());
for path_template in &profile.policy.override_deny {
    let path = expand_vars(path_template, workdir)?;
    if path.exists() {
        profile_overrides.push(path);
    }
}
```

Target post-rename shape:
```rust
// Expand profile-level bypass_protection paths for finalize_caps.
// Existing bypass targets must fail closed in apply_deny_overrides
// when they lack a matching user-intent grant. [...]
let mut profile_overrides = Vec::with_capacity(profile.policy.bypass_protection.len());
for path_template in &profile.policy.bypass_protection {
    let path = expand_vars(path_template, workdir)?;
    if path.exists() {
        profile_overrides.push(path);
    }
}
```

<!-- Verified callsite counts per file (RESEARCH.md Drift Note 3). -->
<!--
   profile/mod.rs              66
   profile_save_runtime.rs     23
   capability_ext.rs           23
   cli.rs                      14
   profile_cmd.rs              13
   profile_runtime.rs          9
   sandbox_state.rs            8
   learn.rs                    6
   policy.rs                   6
   profile/builtin.rs          6
   command_runtime.rs          4
   query_ext.rs                4
   sandbox_prepare.rs          4
   execution_runtime.rs        3
   launch_runtime.rs           3
   main.rs                     2
   why_runtime.rs              2
   TOTAL                       196 (raw grep; ~183 schema-level + ~13 doc-comment refs to verify case-by-case)
-->
</interfaces>

<drift_notes>
1. **`policy_cmd.rs` does NOT exist in fork.** CONTEXT.md cites it as a rename target; the file is absent. The verified 17-file list above is canonical for this plan. (RESEARCH.md Drift Note 1.)
2. **Callsite count is 183 (schema-level), 196 (raw grep total).** The remaining ~13 are doc-comment references to historical contexts; verify each per PATTERNS.md guidance. Doc-comments that document the CURRENT rename are KEPT; doc-comments that talk about Phase 34-04b's pragmatic Option C scaffolding are UPDATED to cite Plan 36-01c. (RESEARCH.md Drift Note 3.)
3. **The underlying helper `apply_deny_overrides` (at capability_ext.rs:668) is NOT renamed.** Its semantics are broader than the schema field — it operates on any "deny override" concept including run-time overrides. PATTERNS.md § Plan 36-01c canonical callsite rename example explicitly preserves this helper name.
4. **The lexical function-local variable `profile_overrides` (capability_ext.rs:629) is planner discretion.** PATTERNS.md recommends rename for consistency; this plan adopts the recommendation: rename to `profile_bypass_targets` (or similar) to match the field name.
</drift_notes>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Pre-flight + atomic mechanical rename across 17 source files + CLI flag direction flip (per D-36-B4 atomic invariant)</name>
  <files>All 17 files listed in `files_modified` frontmatter</files>
  <read_first>
    - .planning/phases/36-upst3-deep-closure/36-PATTERNS.md § Plan 36-01c (full section — verified callsite-per-file counts + the canonical CLI flag flip example + the capability_ext.rs callsite example + the policy_cmd.rs ABSENT drift note)
    - .planning/phases/36-upst3-deep-closure/36-RESEARCH.md § Plan 36-01c — 183-callsite override_deny → bypass_protection rename (lines 551-591)
    - crates/nono-cli/src/profile/mod.rs (current state — verify Plan 36-01b's `bypass_protection` field on `FilesystemConfig` exists; verify Phase 34-04b's `override_deny` field still on `PolicyPatchConfig`)
    - crates/nono-cli/src/cli.rs (lines 1355-1368 + line ~1723 — both CLI flag callsites that need direction flip)
    - crates/nono-cli/src/capability_ext.rs (lines 620-680 — canonical callsite + apply_deny_overrides helper boundary; the helper does NOT rename)
    - .planning/phases/36-upst3-deep-closure/36-CONTEXT.md § D-36-B4 (atomic single-commit invariant)
    - CLAUDE.md § Coding Standards (no .unwrap, DCO sign-off — this rename is mechanical but must preserve all existing standards)
  </read_first>
  <action>
    1. **Pre-flight** (PATTERNS.md Pattern H): `cargo clean -p nono-cli` to clear stale incremental compilation artifacts. This ensures the build at the commit boundary is a true full-recompile gate.
    2. **Baseline inventory.** Run these greps and record exact pre-rename counts (will be cited in commit body):
       ```bash
       grep -rn 'override_deny' crates/nono-cli/src/ --include='*.rs' | wc -l
       # Expected: 196 (RESEARCH.md verified)

       grep -rn 'override_deny' crates/nono-cli/src/ --include='*.rs' -l | sort -u | wc -l
       # Expected: 17

       grep -rn 'override_deny' crates/nono-cli/tests/fixtures/ crates/nono-cli/data/
       # Inventory only — these are case-by-case per Pitfall 7
       ```
       If the per-file count diverges materially from PATTERNS.md's verified counts, STOP and surface (drift in the surface since RESEARCH.md was authored).
    3. **Atomic rename pass.** Use a deterministic tool — either:
       - `rustfmt` + IDE "rename symbol" (Rust-analyzer), driven from `profile/mod.rs::PolicyPatchConfig::override_deny`, AND from `cli.rs::OverrideDenyArg` (or whatever the CLI-arg type is named).
       - OR `sed -i` with deliberate word-boundary matching: `grep -rl 'override_deny' crates/nono-cli/src/ --include='*.rs' | xargs sed -i 's/\boverride_deny\b/bypass_protection/g'` (Linux/macOS) or PowerShell equivalent on Windows host.
       Whichever tool is used, the goal is: every occurrence of the identifier `override_deny` (and any function-local variable `profile_override_deny` per PATTERNS.md) becomes `bypass_protection` / `profile_bypass_protection`. The underlying helper `apply_deny_overrides` (capability_ext.rs:668) is NOT renamed.
    4. **CLI flag direction flip.** At cli.rs lines 1355-1368 (and the second callsite at ~1723 — find via grep), flip the canonical/alias direction per PATTERNS.md exact target shape:
       - `long = "override-deny"` → `long = "bypass-protection"`
       - `visible_alias = "bypass-protection"` → `visible_alias = "override-deny"`
       - Update the doc-comment to cite Plan 36-01c + D-36-B3 (indefinite — no hard-deprecation date).
       - The Rust field name `pub override_deny: Vec<PathBuf>` → `pub bypass_protection: Vec<PathBuf>` (already covered by step 3's rename pass).
    5. **PolicyPatchConfig serde alias flip.** At `profile/mod.rs:439-440` (the Phase 34-04b survivor): `#[serde(default, alias = "bypass_protection")] pub override_deny: Vec<String>` → `#[serde(default, alias = "override_deny")] pub bypass_protection: Vec<String>`. This is part of step 3's rename for the field name; the alias direction also flips so legacy JSON `override_deny` still deserializes.
    6. **Test-fixture inventory (case-by-case per Pitfall 7).** Run `grep -rn 'override_deny' crates/nono-cli/tests/fixtures/ crates/nono-cli/data/` and inspect each match:
       - If the fixture's PURPOSE is to test legacy-key acceptance: KEEP `override_deny` (intentional legacy coverage).
       - If the fixture's purpose is canonical/current behavior: RENAME to `bypass_protection`.
       - Document the disposition for each match in commit body.
       Note: `crates/nono-cli/data/policy.json` line 695 has one `override_deny` reference (verified at PATTERNS.md Drift Note 6). This is data in a non-test fixture; verify whether Plan 36-01d (data migration) will handle it OR Plan 36-01c renames it here. PATTERNS.md Plan 36-01d § file role classifies policy.json under "data migration" — leave for Plan 36-01d.
    7. **Doc-comment historical references.** Run `grep -rn 'override_deny' crates/nono-cli/src/ --include='*.rs'` post-rename and inspect any remaining hits. If they are doc-comments referring to Phase 34-04b's Option C scaffolding (or historical context like "Plan 34-04b ... override_deny"), update them to cite Plan 36-01c + the new canonical name. Doc-comments inside the SAME commit per atomic-rename discipline.
    8. **Build + clippy + test gate** (D-36-B4 single-commit atomic invariant — all gates must pass BEFORE commit lands):
       - `cargo build --workspace --all-features` (must succeed)
       - `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (must be clean)
       - `cargo test --workspace --all-features` (must be fully green; any test failure → roll back the rename pass and investigate)
    9. **Single atomic git commit.** All 17 file changes go in ONE commit. No staged mini-commits. Commit body (Task 2 below) follows D-20 manual-replay shape.
  </action>
  <verify>
    <automated>grep -rn 'override_deny' crates/nono-cli/src/ --include='*.rs' | grep -v '^[[:space:]]*//' | grep -v 'alias = "override_deny"' | grep -v '"override-deny"' | wc -l &amp;&amp; cargo build --workspace --all-features 2>&amp;1 | tail -5 &amp;&amp; cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used 2>&amp;1 | tail -5 &amp;&amp; cargo test --workspace --all-features 2>&amp;1 | tail -10</automated>
  </verify>
  <acceptance_criteria>
    - **Schema-level `override_deny` ELIMINATED from source** (excluding intentional serde alias + clap visible_alias + doc-comment historical refs): the grep `grep -rn '\boverride_deny\b' crates/nono-cli/src/ --include='*.rs' | grep -v '^[[:space:]]*//' | grep -v 'alias = "override_deny"' | grep -v '"override-deny"'` returns 0 lines.
    - **Canonical name appears** in all 17 files (grep: `grep -rln 'bypass_protection' crates/nono-cli/src/ --include='*.rs' | sort -u | wc -l` returns ≥ 17).
    - **CLI flag direction flipped** (grep: `grep -c 'long = "bypass-protection"' crates/nono-cli/src/cli.rs` returns ≥ 1; `grep -c 'visible_alias = "override-deny"' crates/nono-cli/src/cli.rs` returns ≥ 1).
    - **Serde alias preserved bidirectionally** (grep: `grep -c 'alias = "override_deny"' crates/nono-cli/src/profile/mod.rs` returns ≥ 1 — preserving legacy JSON deserialization on `bypass_protection` fields).
    - **`apply_deny_overrides` helper NOT renamed** (grep: `grep -c 'apply_deny_overrides' crates/nono-cli/src/capability_ext.rs` returns ≥ 1 — preserved per PATTERNS.md guidance).
    - **Build green at commit boundary**: `cargo build --workspace --all-features` exits 0.
    - **Clippy clean at commit boundary**: `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` exits 0.
    - **Test green at commit boundary**: `cargo test --workspace --all-features` exits 0.
    - **Single atomic commit shape**: `git log --format='%H' main~1..main | wc -l` returns 1 (single commit) AND `git diff --name-only main~1..main | wc -l` ≥ 17 (touches all 17 files in one commit).
    - Test ID **36-01c-* / T-36-01-RENAME-ATOMIC**: atomic gate per D-36-B4 satisfied at commit boundary.
  </acceptance_criteria>
  <done>17-file atomic rename committed as single revision; canonical name dominant in source; legacy JSON + legacy CLI flag still accepted via serde alias + clap visible_alias; all gates green pre-commit.</done>
</task>

<task type="auto">
  <name>Task 2: Close-gate verification (8-step gate) + D-20 commit body shape (per D-36-A5 + D-36-B4)</name>
  <files>(verification only — Task 1 already committed; this task validates close-gate + commit body shape)</files>
  <read_first>
    - .planning/phases/36-upst3-deep-closure/36-CONTEXT.md § D-36-A5 (all 8 close-gate steps)
    - .planning/phases/36-upst3-deep-closure/36-CONTEXT.md § D-36-B4 (atomic single-commit invariant)
    - memory/feedback_clippy_cross_target.md (cross-target clippy required for cfg-gated Unix code paths)
  </read_first>
  <action>
    1. Run all 8 D-36-A5 close-gate steps on Windows host. Steps 1-5 are already green from Task 1 (the atomic-rename gate). Steps 6-8 are additional:
       1. `cargo test --workspace --all-features` — (already green from Task 1).
       2. `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` — (already clean from Task 1).
       3. `cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` — LOAD-BEARING per memory/feedback_clippy_cross_target.md (any cfg-gated Linux code uses the renamed identifier must still compile).
       4. `cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used` — symmetric coverage for macOS.
       5. `cargo fmt --all -- --check` — formatting must be clean.
       6. (skip-document: Plan 36-01c renames identifiers; does not touch detached-console code paths beyond identifier rename. If the rename touched any session_command_windows.rs surface — verify via `git diff --stat main~1..main | grep windows` — DO NOT skip; run the Phase 15 5-row smoke gate.)
       7. (skip-document: Plan 36-01c does not touch WFP filter code beyond the identifier rename. Verify same condition.)
       8. (skip-document: Plan 36-01c does not touch learn integration. Verify same condition.)
    2. **Verify commit body shape.** Task 1 already committed; verify it matches D-20 manual-replay shape (NO `Upstream-commit:` trailer). The commit body should be (use `git commit --amend` only if shape is wrong; otherwise leave intact):
       ```
       refactor(36-01c): atomic rename override_deny → bypass_protection (17 files / 183 callsites)

       Atomic mechanical rename per D-36-B4 invariant — single commit across
       17 fork-side source files. Mirrors Phase 33 + Phase 34 atomic-cherry-pick
       discipline: reviewer sees one clean diff, rollback is one revert, NO
       staged file-by-file mini-commits with type-alias scaffolding.

       Internal Rust identifier `override_deny` (schema-level field, function-
       local variables, function params) → `bypass_protection`. Legacy JSON
       acceptance preserved via `#[serde(default, alias = "override_deny")]`
       on the renamed field (D-36-B3 indefinite acceptance). Legacy CLI flag
       `--override-deny` preserved via clap `visible_alias` — canonical
       long-name flipped to `--bypass-protection`. The underlying helper
       `apply_deny_overrides` is NOT renamed (its semantics are broader than
       the field rename; PATTERNS.md guidance).

       Per-file callsite counts (verified raw grep):
         profile/mod.rs              66
         profile_save_runtime.rs     23
         capability_ext.rs           23
         cli.rs                      14
         profile_cmd.rs              13
         profile_runtime.rs          9
         sandbox_state.rs            8
         learn.rs                    6
         policy.rs                   6
         profile/builtin.rs          6
         command_runtime.rs          4
         query_ext.rs                4
         sandbox_prepare.rs          4
         execution_runtime.rs        3
         launch_runtime.rs           3
         main.rs                     2
         why_runtime.rs              2
         TOTAL                       196 (183 schema-level + 13 doc-comment refs updated in-line)

       Test fixture dispositions:
         - tests/fixtures/legacy_*.json: KEPT override_deny (intentional legacy coverage).
         - data/policy.json line 695: deferred to Plan 36-01d data migration.
         - all other fixtures: renamed to canonical.

       Closes REQ-PORT-CLOSURE-02 acceptance criterion #1 (canonical rename
       portion). Plan 36-01d follows with built-in profile data + JSON schema
       fixture + docs migration to canonical shape.

       Design source (D-20 manual replay):
       - f0abd413 (upstream v0.47.0): canonical schema rename precedent

       Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
       Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
       ```
    3. Smoke check at plan close: `git log --format='%B' main~1..main | grep -c '^Upstream-commit: '` returns 0.
  </action>
  <verify>
    <automated>cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used 2>&amp;1 | tail -10 &amp;&amp; cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used 2>&amp;1 | tail -10 &amp;&amp; cargo fmt --all -- --check &amp;&amp; git log --format='%B' main~1..main | grep -c '^Upstream-commit: '</automated>
  </verify>
  <acceptance_criteria>
    - Close-gate steps 1, 2, 3, 4, 5 exit 0 (Windows + Linux cross-target + macOS cross-target clippy + fmt-check).
    - Single commit on main: `git rev-list --count main~1..main` returns 1.
    - Commit touches ≥ 17 files: `git diff --name-only main~1..main -- '*.rs' | wc -l` returns ≥ 17.
    - Commit body cites Plan 36-01c + D-36-B4 + 17-file count: `git log --format='%B' main~1..main | grep -E '36-01c|D-36-B4|17 files' | wc -l` returns ≥ 3.
    - NO `Upstream-commit:` trailer: `git log --format='%B' main~1..main | grep -c '^Upstream-commit: '` returns 0 (D-20 manual-replay shape).
    - Design source cited: `git log --format='%B' main~1..main | grep -c 'f0abd413'` returns ≥ 1.
    - DCO trailer present: `git log --format='%B' main~1..main | grep -c '^Signed-off-by: '` returns ≥ 1.
  </acceptance_criteria>
  <done>Plan 36-01c atomic-rename commit lands on `main` with full close-gate clean (Windows + Linux + macOS clippy); D-20 manual-replay shape verified; Wave 2 Plan 36-01d can proceed with data + docs + tooling migration.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Legacy JSON profile files in user environments → fork's serde deserializer | Untrusted input; must remain deserializable post-rename (no migration tool shipped in v2.4 per D-36-B3) |
| Legacy CLI flag `--override-deny` invocations → clap parser | User-supplied CLI input; must remain parseable post-rename (visible_alias) |
| `cargo build/clippy/test` gate at commit boundary → reviewer-visible diff | The atomic-rename discipline rests on the gate's ability to catch incomplete renames |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-36-01-RENAME-ATOMIC | Tampering | Incomplete rename across the 17 files — some callsites still reference `override_deny` after the commit lands; reviewer sees inconsistent code | mitigate | Pre-commit gate runs `cargo build --workspace --all-features` (catches struct field rename mismatches), `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (catches dead-code from incomplete rename), `cargo test --workspace --all-features` (catches behavioral regressions). All 3 gates must be green BEFORE the commit is finalized. |
| T-36-01-LEGACY-JSON-DROP | Tampering / Elevation of Privilege | Legacy JSON profile files silently fail to deserialize after rename; user-supplied capability sets ignored | mitigate | The `#[serde(default, alias = "override_deny")]` annotation on the renamed `bypass_protection` field preserves legacy JSON acceptance (Plan 36-01b Task 1 added the alias direction; Task 1 here flips it to the canonical-first orientation). Plan 36-01a's `LegacyPolicyPatch` rewriter adds defense-in-depth normalization. CONTEXT.md D-36-B3 indefinite-acceptance invariant satisfied. |
| T-36-01-LEGACY-CLI-DROP | Tampering | Legacy `--override-deny` CLI invocations fail after rename; user scripts break | mitigate | The clap `visible_alias = "override-deny"` annotation on the renamed `--bypass-protection` flag preserves legacy CLI acceptance. PATTERNS.md § CLI flag alias direction flip locks the bidirectional acceptance shape. |
| T-36-01-FIXTURE-DRIFT | Tampering | Test fixtures in `tests/fixtures/*.json` reference `override_deny`; renaming them silently breaks legacy-coverage tests | mitigate | Task 1 step 6 explicitly inventories test fixtures case-by-case. Fixtures whose purpose is legacy coverage are KEPT; others renamed. Commit body documents dispositions per fixture. |
| T-36-01-CROSS-PLATFORM-CFG | Tampering | A `#[cfg(target_os = "linux")]` or `#[cfg(target_os = "macos")]` code block uses `override_deny` but isn't covered by Windows-host clippy | mitigate | Close-gate steps 3 + 4 (cross-target Linux + macOS clippy) catch cfg-gated identifier mismatches per memory/feedback_clippy_cross_target.md. These are LOAD-BEARING for this plan (Plan 25 CR-A regression lesson). |
| T-36-01-HELPER-OVERRENAME | Information Disclosure | The `apply_deny_overrides` helper at capability_ext.rs:668 gets accidentally renamed; its broader "deny override" semantics get conflated with the narrower field rename | mitigate | PATTERNS.md § Plan 36-01c § Existing pattern explicitly preserves `apply_deny_overrides`. Task 1 step 3 instructs: "the underlying lower-level helper `apply_deny_overrides` is KEPT as-is." Acceptance criterion grep verifies the helper name is preserved. |
| T-36-01-DATA-JSON-MISS | Information Disclosure | `data/policy.json` line 695 `override_deny` callsite gets accidentally renamed here (out of scope for Plan 36-01c per Plan 36-01d handoff) | accept | Plan 36-01d explicitly owns built-in profile data migration. Task 1 step 6 documents the deferral. The single `override_deny` reference in `data/policy.json` is data, not source code — does not break the atomic-rename gate. |
</threat_model>

<verification>
## Per-Plan Verification

1. **Schema-level `override_deny` ELIMINATED:**
   ```bash
   grep -rn '\boverride_deny\b' crates/nono-cli/src/ --include='*.rs' \
     | grep -v '^[[:space:]]*//' \
     | grep -v 'alias = "override_deny"' \
     | grep -v '"override-deny"' \
     | wc -l
   # Expected: 0
   ```

2. **Canonical name dominant** (replaces it across all 17 files):
   ```bash
   grep -rln 'bypass_protection' crates/nono-cli/src/ --include='*.rs' | sort -u | wc -l
   # Expected: ≥ 17
   ```

3. **CLI flag direction flipped:**
   ```bash
   grep -c 'long = "bypass-protection"' crates/nono-cli/src/cli.rs
   # Expected: ≥ 1
   grep -c 'visible_alias = "override-deny"' crates/nono-cli/src/cli.rs
   # Expected: ≥ 1
   ```

4. **Legacy alias on renamed field preserved:**
   ```bash
   grep -c 'alias = "override_deny"' crates/nono-cli/src/profile/mod.rs
   # Expected: ≥ 1
   ```

5. **`apply_deny_overrides` helper preserved:**
   ```bash
   grep -c 'apply_deny_overrides' crates/nono-cli/src/capability_ext.rs
   # Expected: ≥ 1
   ```

6. **Atomic single-commit shape:**
   ```bash
   git rev-list --count main~1..main
   # Expected: 1
   git diff --name-only main~1..main -- '*.rs' | wc -l
   # Expected: ≥ 17
   ```

7. **Build + clippy + test gate green at commit boundary** (D-36-B4 invariant + D-36-A5 close-gate):
   - `cargo build --workspace --all-features` exits 0
   - `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` exits 0
   - `cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` exits 0
   - `cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used` exits 0
   - `cargo test --workspace --all-features` exits 0
   - `cargo fmt --all -- --check` exits 0

8. **Commit body D-20 manual-replay shape:**
   ```bash
   git log --format='%B' main~1..main | grep -c '^Upstream-commit: '
   # Expected: 0 (no D-19 trailer)
   git log --format='%B' main~1..main | grep -c 'f0abd413'
   # Expected: ≥ 1 (design source citation)
   ```
</verification>

<success_criteria>
- Atomic single commit on `main` renames `override_deny` → `bypass_protection` across all 17 fork-side source files (183 schema-level callsites + ~13 doc-comment historical refs updated in-line).
- CLI flag canonical direction flipped: `--bypass-protection` is the long-name; `--override-deny` is the clap `visible_alias`.
- Legacy JSON deserialization preserved via `#[serde(default, alias = "override_deny")]` on the renamed field.
- The `apply_deny_overrides` helper at capability_ext.rs:668 is preserved (broader semantics than the field rename).
- `cargo build --workspace --all-features` + `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` + `cargo test --workspace --all-features` all green at commit boundary (D-36-B4 atomic-gate invariant).
- All 8 D-36-A5 close-gate steps green (or documented-skipped for steps 6-8 if rename did NOT touch detached-console / WFP / learn surfaces).
- Single commit on `main` with D-20 manual-replay shape citing `f0abd413`; NO `Upstream-commit:` trailer.
- REQ-PORT-CLOSURE-02 acceptance criterion #1 (canonical rename portion) complete; Plan 36-01d follows with data + docs + tooling migration.
</success_criteria>

<output>
After completion, create `.planning/phases/36-upst3-deep-closure/36-01c-OVERRIDE-DENY-RENAME-SUMMARY.md` documenting:
- Single atomic commit SHA + per-file diff stats
- Per-file callsite counts (pre- and post-rename) — verify against PATTERNS.md baseline
- CLI flag flip verification (grep output before + after)
- Test fixture dispositions (per fixture: kept / renamed / deferred)
- Doc-comment historical references updated (cite line ranges)
- Close-gate run outcomes (all 8 steps) — Linux + macOS cross-target clippy MUST be green
- Hand-off to Plan 36-01d (data + docs + tooling migration is the final REQ-02 sub-plan)
</output>
</content>
</invoke>