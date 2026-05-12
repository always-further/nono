---
phase: 36-upst3-deep-closure
plan: 01a
type: execute
wave: 1
depends_on: []
files_modified:
  - crates/nono-cli/src/deprecated_schema.rs
  - crates/nono-cli/src/main.rs
  - crates/nono-cli/src/cli.rs
  - crates/nono-cli/src/profile_cmd.rs
  - crates/nono-cli/src/profile/mod.rs
  - crates/nono-cli/tests/profile_validate_strict.rs
autonomous: true
requirements:
  - REQ-PORT-CLOSURE-02
tags:
  - phase-36
  - port-closure
  - deprecated-schema
  - legacy-policy-patch
  - deprecation-counter
  - strict-mode
  - p34-defer-04b-1
  - d-20-manual-replay

must_haves:
  truths:
    - "A new module `crates/nono-cli/src/deprecated_schema.rs` exists and exports `LegacyPolicyPatch` + `DeprecationCounter` types."
    - "Legacy JSON profile files containing top-level `override_deny` keys still deserialize successfully through the profile load pipeline (indefinite acceptance per D-36-B3)."
    - "On encountering a legacy key, `DeprecationCounter::emit_once(key, canonical)` emits exactly one stderr WARN line per legacy key per process; subsequent encounters of the same key are silent."
    - "`nono profile validate --strict <legacy_profile.json>` exits non-zero with a clear error message that names both the legacy key and the canonical key."
    - "`nono profile validate <legacy_profile.json>` (no `--strict`) exits zero, prints the deprecation warning to stderr, and continues."
    - "The pre-existing `LEGACY_OVERRIDE_DENY_WARNED: AtomicBool` global at `profile/mod.rs:47` is either deleted or migrated into the new `DeprecationCounter` map — no double-emission of the deprecation warning."
  artifacts:
    - path: "crates/nono-cli/src/deprecated_schema.rs"
      provides: "New module containing `LegacyPolicyPatch` (Deserialize-impl-driven rewriter that captures legacy keys and exposes `#[must_use] pub fn rewrite(...) -> Result<CanonicalPolicy>`) AND `DeprecationCounter` (per-key `AtomicBool` collection with `pub fn emit_once(key, canonical)` API) AND `--strict` mode lever. Header preamble mirrors `package.rs:1-32` shape citing upstream `f0abd413` v0.47.0 + D-20 manual-replay declaration."
      contains: "pub struct LegacyPolicyPatch"
      min_lines: 200
    - path: "crates/nono-cli/src/main.rs"
      provides: "Module registration line `mod deprecated_schema;` added in mod-tree section (current mod lines 5-95)."
      contains: "mod deprecated_schema;"
    - path: "crates/nono-cli/src/cli.rs"
      provides: "`ProfileValidateArgs` (currently at lines 1300-1307) extended with `pub strict: bool` field after `pub json: bool`, carrying a clap `#[arg(long)]` annotation and a doc comment explaining the fail-closed semantics. No flag-name collision with existing `--strict` usage elsewhere in the file."
      contains: "pub strict: bool"
    - path: "crates/nono-cli/src/profile_cmd.rs"
      provides: "`cmd_validate` (currently at line 2142) extended to thread `args.strict` into the LegacyPolicyPatch rewriter result — strict-mode rejection pushes onto `errors` Vec; non-strict pushes onto `warnings` Vec. No existing handler-shape removed."
      contains: "args.strict"
    - path: "crates/nono-cli/tests/profile_validate_strict.rs"
      provides: "New integration test file exercising the strict-mode fail-closed path. Includes at minimum `test_profile_validate_strict_rejects_legacy_override_deny` (legacy key + --strict → non-zero exit + stderr contains both 'override_deny' and 'bypass_protection') AND `test_profile_validate_non_strict_warns_and_continues` (legacy key + no --strict → zero exit + stderr contains warning)."
      contains: "fn test_profile_validate_strict_rejects_legacy_override_deny"
  key_links:
    - from: "crates/nono-cli/src/profile_cmd.rs::cmd_validate"
      to: "crates/nono-cli/src/deprecated_schema.rs::LegacyPolicyPatch::rewrite"
      via: "called inside profile-load path; result drives the args.strict→errors / !args.strict→warnings split"
      pattern: "LegacyPolicyPatch::rewrite|deprecated_schema::"
    - from: "crates/nono-cli/src/deprecated_schema.rs::DeprecationCounter"
      to: "stderr (one-shot per-key WARN emission)"
      via: "AtomicBool::swap-on-encounter inside emit_once()"
      pattern: "AtomicBool::new|swap.*Ordering"
    - from: "crates/nono-cli/src/cli.rs::ProfileValidateArgs"
      to: "crates/nono-cli/src/profile_cmd.rs::cmd_validate"
      via: "`pub strict: bool` field forwarded to handler"
      pattern: "ProfileValidateArgs.*strict"
---

<objective>
Land the foundation of the full upstream `deprecated_schema` module port per D-36-B1 / D-36-B2: create the new `deprecated_schema.rs` module carrying `LegacyPolicyPatch` (legacy-key rewriter) and `DeprecationCounter` (per-key one-shot stderr warn tracker), expose the `--strict` flag on `nono profile validate`, and wire both into the profile-load pipeline. Closes REQ-PORT-CLOSURE-02 acceptance criteria #1 (LegacyPolicyPatch present + serde alias deserializes legacy keys), #2 (per-key DeprecationCounter with first-encounter-per-process emission), and #3 (`--strict` fails closed on legacy keys with clear canonical-key pointer). D-20 manual-replay shape — commit body cites upstream `f0abd413` v0.47.0 as design source; NO `Upstream-commit:` trailer (fork's profile-load pipeline diverges structurally from upstream; clean cherry-pick infeasible).

**Purpose:** Phase 34-04b shipped pragmatic Option C scaffolding (serde alias + clap visible_alias + single global `AtomicBool` at `profile/mod.rs:47`). Plan 36-01a replaces this with the full upstream surface so future P34-DEFER absorptions and any subsequent profile-schema evolution land on canonical primitives instead of accumulating fork divergence.

**Output:** New 200+ LOC module + `--strict` clap surface + handler wiring + integration test file + migrated AtomicBool seed (`LEGACY_OVERRIDE_DENY_WARNED` retired or rewired into the per-key map).

**Scope ceiling (D-34-B2):** ONLY the module + counter + strict flag + handler wiring. NO canonical Profile sections (deferred to Plan 36-01b), NO callsite rename (Plan 36-01c), NO data/docs migration (Plan 36-01d), NO audit-event hooks, NO new error variants beyond what upstream `f0abd413` carries.
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
@.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md
@.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md
@.planning/templates/upstream-sync-quick.md

<interfaces>
<!-- Existing fork-side seed implementation that Plan 36-01a extends or retires (do NOT silently drop). -->

From `crates/nono-cli/src/profile/mod.rs` lines 44-82 (Phase 34-04b Option C seed):
```rust
static LEGACY_OVERRIDE_DENY_WARNED: AtomicBool = AtomicBool::new(false);

fn emit_legacy_override_deny_warning_once() {
    if !LEGACY_OVERRIDE_DENY_WARNED.swap(true, Ordering::Relaxed) {
        eprintln!(
            "WARN: profile field `override_deny` is deprecated (upstream #594, \
             v0.47.0); the canonical key is `bypass_protection`. [...]"
        );
    }
}
```

<!-- Existing handler shape in profile_cmd.rs to extend, NOT replace. -->

From `crates/nono-cli/src/profile_cmd.rs` lines 2142-2155 (existing `cmd_validate`):
```rust
pub(crate) fn cmd_validate(args: ProfileValidateArgs) -> Result<()> {
    let pol = policy::load_embedded_policy()?;
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // Step 1: Load profile (parse JSON + resolve inheritance)
    let profile = match profile::load_profile_from_path(&args.file) {
        Ok(p) => Some(p),
        Err(e) => {
            let label = classify_profile_error(&e);
            errors.push(format!("{}: {}", label, e));
            None
        }
    };
    // [...continues with step 2/3/5 checks...]
}
```

<!-- Existing ProfileValidateArgs shape in cli.rs to extend additively. -->

From `crates/nono-cli/src/cli.rs` lines 1300-1307:
```rust
#[derive(Parser, Debug)]
pub struct ProfileValidateArgs {
    /// Profile JSON file to validate
    pub file: PathBuf,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}
```

<!-- Existing NonoError variants (use NonoError::ProfileParse for legacy-key rewrite failures). -->

From `crates/nono/src/error.rs`:
```rust
pub type Result<T> = std::result::Result<T, NonoError>;
// NonoError variants include ProfileParse(String) — use for legacy-key rewriter errors
```

<!-- Pattern for one-shot per-key emission (Plan 36-01a target shape from PATTERNS.md Pattern 2). -->

```rust
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

pub struct DeprecationCounter {
    keys: OnceLock<HashMap<&'static str, AtomicBool>>,
}

impl DeprecationCounter {
    pub fn emit_once(&self, key: &'static str, canonical: &'static str) {
        let map = self.keys.get_or_init(|| {
            let mut m = HashMap::new();
            m.insert("override_deny", AtomicBool::new(false));
            // additional legacy keys upstream f0abd413 carries
            m
        });
        if let Some(flag) = map.get(key) {
            if !flag.swap(true, Ordering::SeqCst) {
                eprintln!(
                    "WARN: profile field `{key}` is deprecated; use `{canonical}` instead"
                );
            }
        }
    }
}
```
</interfaces>

<drift_notes>
1. CONTEXT.md and deferred-items.md mention `crates/nono-cli/src/policy_cmd.rs` — that file does NOT exist in the fork. Plan 36-01a does not touch it (it touches profile_cmd.rs only). No action.
2. The "824 LOC" upstream module size is a planning estimate from deferred-items.md, NOT verified by RESEARCH.md. Task 1 confirms actual LOC via `git show f0abd413:crates/nono-cli/src/deprecated_schema.rs | wc -l`. If dramatically different, surface but proceed (D-34-D2 STOP trigger only on test/clippy/build failure, not on size mismatch).
</drift_notes>
</context>

<tasks>

<task type="auto" tdd="true">
  <name>Task 1: Create deprecated_schema.rs module skeleton with LegacyPolicyPatch + DeprecationCounter types (no wiring; unit tests inline) (per D-36-B1 + D-36-B2)</name>
  <files>crates/nono-cli/src/deprecated_schema.rs, crates/nono-cli/src/main.rs</files>
  <read_first>
    - crates/nono-cli/src/deprecated_schema.rs (must not exist yet — verify ENOENT; will be created)
    - crates/nono-cli/src/main.rs (verify mod-tree section at lines 5-95 to find correct insertion point for `mod deprecated_schema;`)
    - crates/nono-cli/src/package.rs (lines 1-40 — fork-divergence preamble shape to mirror; imports pattern)
    - crates/nono-cli/src/profile/mod.rs (lines 44-82 — `LEGACY_OVERRIDE_DENY_WARNED` AtomicBool seed; lines 117-183 `canonical_schema_rename_tests` test-module shape)
    - crates/nono-cli/src/deprecated_policy.rs (different concern — DO NOT replace; verify still 50+ LOC CLI alias shim)
    - .planning/phases/36-upst3-deep-closure/36-PATTERNS.md § `crates/nono-cli/src/deprecated_schema.rs` (NEW; Plan 36-01a)
    - .planning/phases/36-upst3-deep-closure/36-RESEARCH.md § Code Examples Pattern 2 (DeprecationCounter target shape)
    - CLAUDE.md § Coding Standards (no .unwrap, #[must_use] on critical Results, library should almost never panic)
  </read_first>
  <behavior>
    - Test 1 (`legacy_override_deny_rewrites_to_bypass_protection`): Construct a `LegacyPolicyPatch` from JSON `{"override_deny": ["/var/log"]}` and verify `rewrite()` returns a canonical form where `bypass_protection == ["/var/log"]`.
    - Test 2 (`deprecation_counter_emits_once_per_key`): Create a `DeprecationCounter`; call `emit_once("override_deny", "bypass_protection")` 3 times; verify exactly 1 stderr WARN was emitted (capture via `gag` crate IF already a dev-dep, otherwise via a test-only `Writer` parameter; if neither feasible, verify via `AtomicBool` state directly).
    - Test 3 (`deprecation_counter_emits_separately_per_key`): Call `emit_once` for two different legacy keys; verify both emit (independent per-key state).
    - Test 4 (`legacy_policy_patch_passes_through_unknown_legacy_keys`): Verify unknown legacy keys are rejected per `#[serde(deny_unknown_fields)]` (preserve invariant from `PolicyPatchConfig` at profile/mod.rs:441 successor).
  </behavior>
  <action>
    1. Run `git show upstream/f0abd413:crates/nono-cli/src/deprecated_schema.rs | wc -l` to confirm actual upstream LOC (record in Task notes; estimate is ~824).
    2. Create `crates/nono-cli/src/deprecated_schema.rs` with this exact header preamble (mirror `package.rs:1-32` shape):
       ```
       //! Deprecated profile-schema rewriter and per-key deprecation counter.
       //!
       //! # Upstream awareness (v0.47.0, manual-replay of f0abd413)
       //!
       //! In upstream nono v0.47.0 (commit `f0abd413`), the upstream project
       //! shipped a `deprecated_schema` module carrying:
       //!   - `LegacyPolicyPatch`: a Deserialize-driven rewriter that captures
       //!     legacy keys (e.g. `override_deny`) and exposes a `rewrite()`
       //!     method returning canonical form (`bypass_protection`).
       //!   - `DeprecationCounter`: a per-key `AtomicBool` collection emitting
       //!     exactly one stderr WARN per legacy key per process on first
       //!     encounter.
       //!   - `--strict` mode lever: `nono profile validate --strict` fails
       //!     closed on legacy keys with a clear pointer to the canonical key.
       //!
       //! Phase 34-04b shipped a pragmatic Option C (serde alias + clap
       //! visible_alias + single AtomicBool at `profile/mod.rs:47`); Plan
       //! 36-01a (D-20 manual-replay of f0abd413) replaces this with the
       //! full upstream surface. See `.planning/phases/36-upst3-deep-closure/
       //! 36-CONTEXT.md` § D-36-B1 for the locked decision rationale.
       //!
       //! Indefinite acceptance per D-36-B3: legacy keys keep deserializing
       //! after this port lands; `--strict` is the operator-controlled
       //! fail-closed lever. No hard-deprecation date in v2.4.
       ```
    3. Import block (mirror `package.rs:34-40`):
       ```rust
       use nono::{NonoError, Result};
       use serde::{Deserialize, Serialize};
       use std::collections::HashMap;
       use std::sync::atomic::{AtomicBool, Ordering};
       use std::sync::OnceLock;
       ```
    4. Define `pub struct LegacyPolicyPatch` carrying the legacy-key fields. Map upstream `f0abd413`'s known legacy keys (at minimum `override_deny`; if upstream carries others, include them). Implement `#[must_use] pub fn rewrite(&self) -> Result<CanonicalPolicy>` returning canonical form. Preserve `#[serde(deny_unknown_fields)]` to prevent silent acceptance of unknown legacy keys (per Pitfall #11 in RESEARCH § Security Considerations).
    5. Define `pub struct DeprecationCounter` per PATTERNS.md Pattern 2 exact shape — `OnceLock<HashMap<&'static str, AtomicBool>>` carrying one entry per known legacy key. Implement `pub fn emit_once(&self, key: &'static str, canonical: &'static str)`.
    6. Add `#[cfg(test)] mod tests` block with the 4 tests enumerated in `<behavior>`. No `.unwrap()` outside the test module. Use `#[must_use]` on `rewrite()` per CLAUDE.md.
    7. Add `mod deprecated_schema;` line to `crates/nono-cli/src/main.rs` in alphabetical order within the existing mod section (lines 5-95).
    8. Run `cargo build -p nono-cli` — must succeed (no wiring yet, just module + types).
    9. Run `cargo test -p nono-cli --lib deprecated_schema::tests` — all 4 tests must pass.
  </action>
  <verify>
    <automated>cargo test -p nono-cli --lib deprecated_schema::tests -- --nocapture 2>&amp;1 | tee /tmp/36-01a-task1.log; cargo build -p nono-cli 2>&amp;1 | tail -20</automated>
  </verify>
  <acceptance_criteria>
    - File `crates/nono-cli/src/deprecated_schema.rs` exists with `pub struct LegacyPolicyPatch` and `pub struct DeprecationCounter` declarations (grep: `grep -E '^pub struct (LegacyPolicyPatch|DeprecationCounter)' crates/nono-cli/src/deprecated_schema.rs | wc -l` returns 2).
    - File contains `#[must_use]` on the `rewrite()` function (grep: `grep -B1 'pub fn rewrite' crates/nono-cli/src/deprecated_schema.rs | grep -c '#\[must_use\]'` returns 1).
    - File contains `#[serde(deny_unknown_fields)]` on `LegacyPolicyPatch` (grep: `grep -B1 'pub struct LegacyPolicyPatch' crates/nono-cli/src/deprecated_schema.rs | grep -c 'deny_unknown_fields'` returns 1).
    - `crates/nono-cli/src/main.rs` contains `mod deprecated_schema;` line (grep: `grep -v '^//' crates/nono-cli/src/main.rs | grep -c '^mod deprecated_schema;'` returns 1).
    - Test ID **36-01a-* / T-36-01-LEGACY-KEY**: `cargo test -p nono-cli --lib deprecated_schema::tests` exits 0 with all 4 tests reported as `ok`.
    - No `.unwrap()` / `.expect()` outside `#[cfg(test)] mod tests` (grep: `grep -v '^//\|^[[:space:]]*//' crates/nono-cli/src/deprecated_schema.rs | grep -v '#\[cfg(test)\]' | grep -E '\.unwrap\(\)|\.expect\(' | wc -l` returns 0, accounting for cfg-test gating).
  </acceptance_criteria>
  <done>Module file created with both types, 4 inline tests pass, clippy clean on Windows host (Linux+macOS gates in Task 4 close-gate).</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: Wire LegacyPolicyPatch + DeprecationCounter into profile-load path; add --strict clap flag; migrate LEGACY_OVERRIDE_DENY_WARNED AtomicBool seed (per D-36-B1, D-36-B3)</name>
  <files>crates/nono-cli/src/cli.rs, crates/nono-cli/src/profile_cmd.rs, crates/nono-cli/src/profile/mod.rs, crates/nono-cli/tests/profile_validate_strict.rs</files>
  <read_first>
    - crates/nono-cli/src/cli.rs (lines 1300-1370 — `ProfileValidateArgs` definition + neighboring clap flags; verify no `--strict` collision)
    - crates/nono-cli/src/profile_cmd.rs (lines 2142-2200 — `cmd_validate` handler shape)
    - crates/nono-cli/src/profile/mod.rs (lines 44-82 — `LEGACY_OVERRIDE_DENY_WARNED` AtomicBool seed; this is the global being retired or migrated)
    - crates/nono-cli/src/deprecated_schema.rs (just created in Task 1)
    - crates/nono-cli/src/deprecated_policy.rs (lines 18-22 — `pub use crate::cli::ProfileValidateArgs as PolicyValidateArgs;` re-export; verify `--strict` propagates through this alias automatically)
    - .planning/phases/36-upst3-deep-closure/36-PATTERNS.md § `crates/nono-cli/src/cli.rs` — ProfileValidateArgs `--strict` flag (Plan 36-01a)
    - .planning/phases/36-upst3-deep-closure/36-PATTERNS.md § `crates/nono-cli/src/profile_cmd.rs` — wire LegacyPolicyPatch + DeprecationCounter (Plan 36-01a)
    - CLAUDE.md § Coding Standards (env-var save/restore in tests; no .unwrap)
  </read_first>
  <behavior>
    - Test 1 (`test_profile_validate_strict_rejects_legacy_override_deny`): Write a fixture JSON file with `{"override_deny": ["/var/log"], ...}`; run `nono profile validate --strict <path>`; assert exit code != 0 AND stderr contains both literal strings `"override_deny"` and `"bypass_protection"`.
    - Test 2 (`test_profile_validate_non_strict_warns_and_continues`): Same fixture; run `nono profile validate <path>` without `--strict`; assert exit code == 0 AND stderr contains the literal string `"deprecated"`.
    - Test 3 (`test_profile_validate_non_strict_emits_deprecation_warning_only_once`): Same fixture loaded twice in the same process (e.g., via two `cmd_validate` calls in a test); assert only ONE deprecation WARN appears in captured stderr (DeprecationCounter first-encounter invariant). NOTE: integration tests run in separate processes per Rust convention; if proxying via two `cmd_validate` calls in-process is infeasible from `tests/`, fall back to a unit test in `deprecated_schema::tests`.
  </behavior>
  <action>
    1. **cli.rs — add `--strict` flag.** In `ProfileValidateArgs` (currently at lines 1300-1307), add a `pub strict: bool` field after `pub json: bool` with the exact shape:
       ```rust
       /// Fail closed on legacy profile fields (e.g. `override_deny`). Default
       /// mode warns to stderr but continues; `--strict` exits non-zero.
       #[arg(long)]
       pub strict: bool,
       ```
       Verify no other `--strict` long flag exists elsewhere in `cli.rs` (grep: `grep -n 'long = "strict"\|long, .* "strict"' cli.rs` should return at most this one match).
    2. **profile_cmd.rs — wire LegacyPolicyPatch + DeprecationCounter.** In `cmd_validate` (line 2142), after the existing `profile::load_profile_from_path` call:
       - Instantiate the `DeprecationCounter` (`static`-scoped or constructed locally with `OnceLock` semantics — match Task 1's design).
       - Invoke `LegacyPolicyPatch::rewrite(...)` to detect legacy keys.
       - For each legacy key found: call `counter.emit_once(key, canonical)`.
       - If `args.strict == true` AND any legacy keys were observed: push a `format!("legacy key `{key}` rejected by --strict; use canonical `{canonical}`")` onto `errors: Vec<String>`.
       - If `args.strict == false`: do nothing (the emit_once warning already went to stderr).
       - Preserve the existing handler's exit-code logic (errors → non-zero, no errors → zero).
    3. **profile/mod.rs — migrate `LEGACY_OVERRIDE_DENY_WARNED` AtomicBool seed.** Delete the global at line 47 AND the `emit_legacy_override_deny_warning_once()` helper at lines 51-82. Migrate the warning-emission concern into the new `DeprecationCounter`. Any existing callers of `emit_legacy_override_deny_warning_once()` (grep first: `grep -n 'emit_legacy_override_deny_warning_once' crates/nono-cli/src/`) must be updated to call `DeprecationCounter::emit_once(...)` instead. If grep shows zero callers (because the seed was only triggered during serde deserialization on the existing serde alias), delete the function and its global cleanly. Add a tombstone comment immediately above the deletion site: `// Plan 36-01a: emit_legacy_override_deny_warning_once + LEGACY_OVERRIDE_DENY_WARNED retired; now lives in crates/nono-cli/src/deprecated_schema.rs::DeprecationCounter per D-36-B1 (upstream f0abd413).`
    4. **tests/profile_validate_strict.rs — create new integration test file.** Cover the 3 tests enumerated in `<behavior>`. Use a temp directory for the fixture file (`tempfile::TempDir`). Save/restore `HOME` / `XDG_CONFIG_HOME` / `NONO_TEST_HOME` env vars per CLAUDE.md § Environment variables in tests (save → set → run → restore in same scope, no `defer`/`drop`-only patterns).
    5. Run `cargo build -p nono-cli` — must succeed. Run `cargo clippy -p nono-cli --all-targets -- -D warnings -D clippy::unwrap_used` — must be clean.
    6. Run `cargo test -p nono-cli --test profile_validate_strict` — all 3 (or 2 with the fallback noted in behavior) tests must pass.
  </action>
  <verify>
    <automated>cargo test -p nono-cli --test profile_validate_strict -- --nocapture 2>&amp;1 | tee /tmp/36-01a-task2.log; cargo clippy -p nono-cli --all-targets -- -D warnings -D clippy::unwrap_used 2>&amp;1 | tail -20</automated>
  </verify>
  <acceptance_criteria>
    - `cli.rs` `ProfileValidateArgs` carries `pub strict: bool` field (grep: `grep -A 8 'pub struct ProfileValidateArgs' crates/nono-cli/src/cli.rs | grep -c 'pub strict: bool'` returns 1).
    - `profile_cmd.rs` `cmd_validate` references the new types (grep: `grep -A 80 'fn cmd_validate' crates/nono-cli/src/profile_cmd.rs | grep -E 'LegacyPolicyPatch|deprecated_schema::|emit_once' | wc -l` returns ≥ 2).
    - `LEGACY_OVERRIDE_DENY_WARNED` global is deleted from `profile/mod.rs` (grep: `grep -c 'LEGACY_OVERRIDE_DENY_WARNED' crates/nono-cli/src/profile/mod.rs` returns 0). Tombstone comment cites Plan 36-01a (grep: `grep -c 'Plan 36-01a.*retired' crates/nono-cli/src/profile/mod.rs` returns 1).
    - `tests/profile_validate_strict.rs` exists with required test function (grep: `grep -c 'fn test_profile_validate_strict_rejects_legacy_override_deny' crates/nono-cli/tests/profile_validate_strict.rs` returns 1).
    - Test ID **36-01a-* / T-36-01-STRICT-MODE**: `cargo test -p nono-cli --test profile_validate_strict` exits 0; both strict-fail-closed and non-strict-warn tests pass.
    - Windows host clippy clean: `cargo clippy -p nono-cli --all-targets -- -D warnings -D clippy::unwrap_used` exits 0 (matches D-36-A5 close-gate step 2).
    - No `.unwrap()` introduced in non-test source: `grep -v '^[[:space:]]*//' crates/nono-cli/src/profile_cmd.rs | grep -v '#\[cfg(test)\]' | grep -A 200 'fn cmd_validate' | grep -c '\.unwrap\(\)'` returns 0.
  </acceptance_criteria>
  <done>Strict-mode wiring lands end-to-end; legacy keys produce non-zero exit under --strict + clear canonical-key pointer; non-strict path warns once and continues; AtomicBool seed retired without orphan callers.</done>
</task>

<task type="auto">
  <name>Task 3: Close-gate verification + D-20 commit body citing upstream f0abd413 (per D-36-A5 + D-36-B1)</name>
  <files>(verification only — no code mutation; commit message follows D-20 manual-replay shape)</files>
  <read_first>
    - .planning/phases/36-upst3-deep-closure/36-CONTEXT.md § D-36-A5 (all 8 close-gate steps)
    - .planning/templates/upstream-sync-quick.md § D-19 cherry-pick trailer block (CONFIRMS Plan 36-01a does NOT use this trailer — D-20 manual-replay shape only)
    - memory/feedback_clippy_cross_target.md (cross-target clippy lesson)
    - CLAUDE.md § Coding Standards (DCO Signed-off-by trailer mandatory)
  </read_first>
  <action>
    1. Run all 8 D-36-A5 close-gate steps on Windows host:
       1. `cargo test --workspace --all-features` (must exit 0)
       2. `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (must exit 0)
       3. `cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` (must exit 0; install target via `rustup target add x86_64-unknown-linux-gnu` if missing)
       4. `cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used` (must exit 0; install target if missing)
       5. `cargo fmt --all -- --check` (must exit 0)
       6. Phase 15 5-row detached-console smoke gate (skip if no Windows shell handy; document as "skipped — Plan 36-01a does not touch detached-console code paths" in commit body)
       7. `wfp_port_integration` test suite (skip if hardware not available; document)
       8. `learn_windows_integration` test suite (skip if not applicable; document)
    2. Commit in a single git commit with this exact body shape (D-20 manual-replay; NO `Upstream-commit:` trailer):
       ```
       feat(36-01a): port deprecated_schema module foundation

       Replaces Phase 34-04b's pragmatic Option C rename-acceptance scaffolding
       (serde alias + clap visible_alias + single AtomicBool at
       profile/mod.rs:47) with the full upstream surface from f0abd413
       (v0.47.0):
         - `LegacyPolicyPatch`: Deserialize-driven rewriter capturing legacy
           keys (override_deny → bypass_protection) and exposing a `#[must_use]
           rewrite() -> Result<CanonicalPolicy>` method.
         - `DeprecationCounter`: per-key AtomicBool collection emitting exactly
           one stderr WARN per legacy key per process on first encounter.
         - `--strict` flag on `nono profile validate`: fails closed on legacy
           keys with a clear pointer to the canonical key.

       Indefinite acceptance per D-36-B3: legacy keys keep deserializing after
       this port lands; `--strict` is the operator-controlled fail-closed
       lever. No hard-deprecation date in v2.4 (deferred to v2.5-FU-5 ADR).

       Closes REQ-PORT-CLOSURE-02 acceptance criteria #1, #2, #3.
       Closes nothing on its own — Plan 36-01b/c/d complete the REQ.

       Design source (D-20 manual replay):
       - f0abd413 (upstream v0.47.0): deprecated_schema module wholesale

       Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
       Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
       ```
    3. After commit, verify smoke check: `git log --format='%B' main~1..main | grep -c '^Upstream-commit: '` returns 0 (Plan 36-01a uses D-20 manual-replay; D-19 trailer is exclusive to Plan 36-03 Commit 3).
  </action>
  <verify>
    <automated>cargo test --workspace --all-features 2>&amp;1 | tail -10 &amp;&amp; cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used 2>&amp;1 | tail -10 &amp;&amp; cargo fmt --all -- --check &amp;&amp; git log --format='%B' main~1..main | grep -c '^Upstream-commit: '</automated>
  </verify>
  <acceptance_criteria>
    - Close-gate steps 1, 2, 5 exit 0 (`cargo test --workspace --all-features`, `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used`, `cargo fmt --all -- --check`).
    - Close-gate steps 3 + 4 (cross-target Linux + macOS clippy) exit 0 (toolchains installed via `rustup target add` if absent).
    - Commit body cites `f0abd413` as design source: `git log --format='%B' main~1..main | grep -c 'f0abd413'` returns ≥ 1.
    - Commit body cites Plan 36-01a + REQ-PORT-CLOSURE-02: `git log --format='%B' main~1..main | grep -E '36-01a|REQ-PORT-CLOSURE-02' | wc -l` returns ≥ 2.
    - NO `Upstream-commit:` trailer: `git log --format='%B' main~1..main | grep -c '^Upstream-commit: '` returns 0 (D-20 manual-replay shape per D-36-D2 + D-34-E3).
    - DCO trailer present: `git log --format='%B' main~1..main | grep -c '^Signed-off-by: '` returns ≥ 1.
  </acceptance_criteria>
  <done>Plan 36-01a committed on `main` with D-20 manual-replay shape; all close-gate steps green; ready for Wave 2 Plan 36-01b to consume the new `deprecated_schema.rs` module.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| User-supplied JSON profile → fork's serde deserializer | Untrusted input crosses here; profile JSON may contain malformed shapes, legacy keys, or unknown fields |
| `LegacyPolicyPatch::rewrite()` → canonical Profile struct | Trusted normalization boundary; rewrite must preserve semantic equivalence (no silent capability widening) |
| `--strict` flag → process exit code | Operator-controlled fail-closed lever; regression here weakens deployment-time enforcement |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-36-01-LEGACY-KEY | Tampering / Elevation of Privilege | `LegacyPolicyPatch` JSON deserialization (`deprecated_schema.rs`) | mitigate | `#[serde(deny_unknown_fields)]` on `LegacyPolicyPatch` (Task 1); legacy keys must be enumerated explicitly. `rewrite()` returns `Result<T, NonoError>` — malformed input fails closed via `NonoError::ProfileParse`. Round-trip invariant test (`legacy_override_deny_rewrites_to_bypass_protection`) locks semantic equivalence (Task 1 behavior). |
| T-36-01-STRICT-MODE | Elevation of Privilege | `--strict` flag in `ProfileValidateArgs` + `cmd_validate` handler | mitigate | Integration test `test_profile_validate_strict_rejects_legacy_override_deny` (Task 2) asserts non-zero exit + clear canonical-key error. Test runs on all 3 close-gate clippy targets (Windows + Linux + macOS) to catch platform-specific regressions. |
| T-36-01-DEPRECATION-DOS | Denial of Service | `DeprecationCounter::emit_once` stderr emission | accept | Per-key AtomicBool collection means worst-case emission count is N legacy keys × 1 emission. No unbounded emission. AtomicBool::swap is wait-free, no lock contention. |
| T-36-01-CONFIG-FAIL-OPEN | Tampering / Elevation of Privilege | Profile load failure when `deprecated_schema` cannot deserialize | mitigate | `cmd_validate` pushes failure onto `errors: Vec<String>` (fail closed). No silent fall-through to a default profile. CLAUDE.md § Configuration load failures must be fatal invariant preserved. |
| T-36-01-AUDIT-RETROFIT | Repudiation | Profile-validate `--strict` rejection without audit-event emission | accept | D-34-B2 surgical-retrofit posture explicitly excludes new audit-event hooks (`.planning/phases/36-upst3-deep-closure/36-CONTEXT.md` § D-34-B2 inheritance). Stderr + non-zero exit is the documented surface; audit visibility deferred to v2.5+ ADR. |
| T-36-01-GLOBAL-STATE-LEAK | Information Disclosure | Process-wide `DeprecationCounter` state across multiple profile loads | accept | Counter state is local to the process and stores only static legacy-key names (no PII, no profile content). State persisting across multiple `cmd_validate` calls in the same process is the documented one-warning-per-process invariant. |
</threat_model>

<verification>
## Per-Plan Verification

1. **Module exists + types exported:**
   ```bash
   test -f crates/nono-cli/src/deprecated_schema.rs &&
   grep -E '^pub struct (LegacyPolicyPatch|DeprecationCounter)' crates/nono-cli/src/deprecated_schema.rs | wc -l
   # Expected: 2
   ```

2. **Module registered:**
   ```bash
   grep -c '^mod deprecated_schema;' crates/nono-cli/src/main.rs
   # Expected: 1
   ```

3. **--strict flag wired:**
   ```bash
   grep -A 10 'pub struct ProfileValidateArgs' crates/nono-cli/src/cli.rs | grep -c 'pub strict: bool'
   # Expected: 1
   ```

4. **AtomicBool seed retired:**
   ```bash
   grep -c 'LEGACY_OVERRIDE_DENY_WARNED' crates/nono-cli/src/profile/mod.rs
   # Expected: 0
   ```

5. **Tests green:**
   - `cargo test -p nono-cli --lib deprecated_schema::tests` exits 0
   - `cargo test -p nono-cli --test profile_validate_strict` exits 0

6. **Close-gate green (per D-36-A5):**
   - Windows clippy + Linux cross-target clippy + macOS cross-target clippy + fmt-check all exit 0

7. **Commit shape correct (D-20 manual-replay; per D-36-D2 + D-34-E3):**
   ```bash
   git log --format='%B' main~1..main | grep -c '^Upstream-commit: '
   # Expected: 0 (no D-19 trailer)
   git log --format='%B' main~1..main | grep -c 'f0abd413'
   # Expected: ≥ 1 (design source citation)
   ```
</verification>

<success_criteria>
- New module `crates/nono-cli/src/deprecated_schema.rs` exists with `LegacyPolicyPatch` + `DeprecationCounter` + inline unit tests; all 4 unit tests pass.
- `--strict` flag on `nono profile validate` exists, defaults to false, parses correctly via clap.
- `cmd_validate` handler wires `LegacyPolicyPatch::rewrite()` + `DeprecationCounter::emit_once()` into profile-load path; strict-mode rejection pushes to errors; non-strict warns to stderr.
- Existing `LEGACY_OVERRIDE_DENY_WARNED: AtomicBool` global at `profile/mod.rs:47` retired (deleted with tombstone comment) — no orphan callers.
- Integration test `tests/profile_validate_strict.rs` covers both strict-fail-closed and non-strict-warn paths.
- All 8 D-36-A5 close-gate steps green (or documented-skipped for steps 6-8 if Plan 36-01a does not touch those surfaces).
- Single commit on `main` with D-20 manual-replay shape citing `f0abd413`; NO `Upstream-commit:` trailer.
- REQ-PORT-CLOSURE-02 acceptance criteria #1, #2, #3 met (acceptance #4-#6 deferred to Plans 36-01b/c/d).
</success_criteria>

<output>
After completion, create `.planning/phases/36-upst3-deep-closure/36-01a-DEPRECATED-SCHEMA-MODULE-SUMMARY.md` documenting:
- Files created/modified with LOC deltas
- Test counts (unit + integration) with pass/fail status
- Close-gate steps run + outcomes
- Commit SHA + body shape verification (D-20, no D-19 trailer)
- Migration notes for the `LEGACY_OVERRIDE_DENY_WARNED` retirement (any callers found + handling)
- Open hand-off to Plan 36-01b (canonical Profile sections will compose on top of this module)
</output>
</content>
</invoke>