---
phase: 36-upst3-deep-closure
plan: 02
type: execute
wave: 1
depends_on: []
files_modified:
  - crates/nono-cli/src/wiring.rs
  - crates/nono-cli/Cargo.toml
  - crates/nono-cli/src/main.rs
  - crates/nono-cli/src/profile_cmd.rs
  - crates/nono-cli/tests/yaml_merge_reversal.rs
autonomous: true
requirements:
  - REQ-PORT-CLOSURE-04
tags:
  - phase-36
  - port-closure
  - yaml-merge
  - wiring-rs
  - serde-yaml-ng
  - p34-defer-06-1
  - p34-defer-09-2
  - d-20-manual-replay
  - d-36-c1
  - d-36-c2

must_haves:
  truths:
    - "A new file `crates/nono-cli/src/wiring.rs` exists carrying ONLY the yaml_merge directive parser + applier from upstream `d44f5541` plus the reversal-failure test from upstream `242d4917`. NO WriteFile / JsonMerge / JsonArrayAppend directives. NO SHA-256-keyed install records. NO lockfile v3+v4 machinery. NO `--force` on `nono remove`. (D-36-C1 scope-trim invariant.)"
    - "`crates/nono-cli/Cargo.toml` carries the line `serde_yaml_ng = \"=0.10.0\"` (exact-version pin, mirroring upstream `242d4917`)."
    - "`nono profile patch --yaml <overlay>` accepts `yaml_merge:` directives matching upstream semantics (REQ-PORT-CLOSURE-04 acceptance #2)."
    - "yaml_merge target-path validation uses `Path::components()` iteration + canonicalization (CLAUDE.md § Common Footguns #1) — NO `str::starts_with` shape on paths."
    - "Existing `validate_path_within` callsites in `crates/nono-cli/src/package_cmd.rs` are preserved where they intersect yaml_merge target paths (fork-only retention catalog entry inherited from D-34-B1)."
    - "REQ-PORT-CLOSURE-04 acceptance criterion #1 (idempotent JSON-merge install records) is EXPLICITLY scope-trimmed per D-36-C1; documented in commit body and Plan SUMMARY; deferred to v2.5-FU-3."
    - "Plan 36-02 commits as a SINGLE combined commit citing 3 upstream commits as design source (242d4917 + 802c8566 + d44f5541) per D-36-C2; NO `Upstream-commit:` D-19 trailer (upstream files structurally infeasible to cherry-pick into fork)."
  artifacts:
    - path: "crates/nono-cli/src/wiring.rs"
      provides: "New module (~300-400 LOC) carrying yaml_merge directive parser + applier. Header preamble mirrors `package.rs:1-32` fork-divergence-with-citation shape, citing 242d4917 + 802c8566 + d44f5541 as design source. Contains: yaml_merge struct (parse), yaml_merge applier (apply to target YAML file), target-path validator using `Path::components()` iteration + canonicalization, error variants mapped to `NonoError` via `?` propagation. Includes `#[cfg(test)] mod tests` with the reversal-failure test from upstream 242d4917 + path-validation tests for `../../../etc/passwd`-class escapes + UNC-alias attempts + symlink escapes."
      contains: "pub fn apply_yaml_merge"
    - path: "crates/nono-cli/Cargo.toml"
      provides: "Exact-version pin `serde_yaml_ng = \"=0.10.0\"` added to `[dependencies]` block. Mirroring existing exact-version-pin precedent at `sigstore-sign = \"0.6.5\"` line 64 (NB: upstream pin uses `=` prefix; fork's sigstore pin does not — Plan 36-02 explicitly adopts the `=`-prefix shape since the pin's whole point is to lock exact)."
      contains: "serde_yaml_ng = \"=0.10.0\""
    - path: "crates/nono-cli/src/main.rs"
      provides: "Module registration `mod wiring;` added in alphabetical order within mod section (lines 5-95). NO new public re-export at crate root."
      contains: "mod wiring;"
    - path: "crates/nono-cli/src/profile_cmd.rs"
      provides: "`nono profile patch --yaml <overlay>` handler extended to invoke `wiring::apply_yaml_merge(...)` on yaml_merge directives in the overlay. Preserves existing `--yaml` handler shape; ADDS yaml_merge directive support."
      contains: "wiring::apply_yaml_merge"
    - path: "crates/nono-cli/tests/yaml_merge_reversal.rs"
      provides: "New integration test reproducing the reversal-failure scenario from upstream `242d4917`. Covers: apply yaml_merge directive → assert overlay merged correctly → reverse the merge → assert reversal-failure error matches upstream-documented expected shape."
      contains: "fn test_yaml_merge_reversal_failure"
  key_links:
    - from: "crates/nono-cli/src/profile_cmd.rs::cmd_profile_patch (or equivalent `--yaml` handler)"
      to: "crates/nono-cli/src/wiring.rs::apply_yaml_merge"
      via: "function call on the yaml_merge directive in the overlay"
      pattern: "wiring::apply_yaml_merge"
    - from: "crates/nono-cli/src/wiring.rs::validate_target_path"
      to: "Path::components() iteration + canonicalize() — NO str::starts_with"
      via: "path-validation primitive per CLAUDE.md § Path Handling"
      pattern: "components\\(\\)|canonicalize\\(\\)"
    - from: "crates/nono-cli/Cargo.toml"
      to: "crates/nono-cli/src/wiring.rs (consumes serde_yaml_ng::from_str)"
      via: "dependency resolution via `cargo build`"
      pattern: "serde_yaml_ng"
---

<objective>
Land the stripped-down `wiring.rs` port per D-36-C1: create a NEW `crates/nono-cli/src/wiring.rs` carrying ONLY the yaml_merge directive parser + applier (from upstream `d44f5541` v0.49.0); pin `serde_yaml_ng = "=0.10.0"` in `crates/nono-cli/Cargo.toml` (from upstream `242d4917`); add the reversal-failure test from upstream `242d4917`; wire the directive into `nono profile patch --yaml <overlay>` handler in `profile_cmd.rs`; preserve fork's `validate_path_within` callsites that intersect yaml_merge target paths (D-34-B1 + fork-divergence catalog entry).

Acceptance criteria met: REQ-PORT-CLOSURE-04 #2 (yaml_merge directive accepted) + #3 (serde_yaml_ng pinned 0.10.0) + #4 (reversal-failure test). Acceptance criterion #1 (idempotent JSON-merge install records) EXPLICITLY scope-trimmed per D-36-C1; deferred to v2.5-FU-3.

D-20 single combined commit citing 3 upstream commits as design source (242d4917 + 802c8566 + d44f5541) per D-36-C2 — NO `Upstream-commit:` D-19 trailer since upstream's commits modified an upstream-only `wiring.rs` file which doesn't exist in fork (cherry-pick structurally infeasible).

**Purpose:** Fork users patching upstream profiles via YAML overlay need the `yaml_merge:` directive shape to apply patches that upstream accepts. Without the directive, fork's YAML overlay handler rejects upstream-shaped overlays. The full 1761-LOC upstream `wiring.rs` (WriteFile / JsonMerge / JsonArrayAppend / install records / lockfile v3+v4 / idempotent reversal) conflicts with fork's preserved package system (`package.rs` + `package_cmd.rs` + `hooks.rs` per D-34-B1) and is explicitly out of scope for v2.4 (D-36-C1) — deferred to v2.5-FU-3.

**Output:** ~300-400 LOC new file + 1 Cargo.toml dep line + 1 main.rs mod line + handler integration + integration test file. Single atomic combined commit.

**Scope ceiling (D-36-C1):** ONLY yaml_merge directive. NO WriteFile / JsonMerge / JsonArrayAppend. NO install records. NO `--force` on `nono remove`. NO audit-event hooks. NO removal of fork's `validate_path_within` callsites.
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
@.planning/templates/upstream-sync-quick.md

<interfaces>
<!-- Existing fork-divergence preamble pattern to mirror (PATTERNS.md § wiring.rs Analog 1). -->

From `crates/nono-cli/src/package.rs:1-32`:
```rust
//! Pack manifest, lockfile, and local store helpers.
//!
//! # Upstream registry-pack format awareness (v0.44.0, manual-replay of 24d8b924)
//!
//! In upstream nono v0.44.0 (commit `24d8b924`), the upstream project migrated [...]
//! That commit also introduced four upstream-only files implementing a `wiring`
//! abstraction [...]
//!
//! The fork does NOT carry that structural rewrite. Per Phase 33's
//! DIVERGENCE-LEDGER.md cluster C6 "fork-preserve" disposition [...]
```

<!-- Existing exact-version pin precedent (PATTERNS.md § Cargo.toml). -->

From `crates/nono-cli/Cargo.toml` line 64:
```toml
# Keyless (Sigstore/Fulcio/Rekor) signing for instruction file attestation
sigstore-sign = "0.6.5"
```

Plan 36-02 ADDS (mirroring style, with explicit `=`-prefix exact pin since upstream 242d4917 uses that shape):
```toml
# YAML-merge directive support (Plan 36-02; upstream-aligned at v0.10.0 per 242d4917)
serde_yaml_ng = "=0.10.0"
```

<!-- Path validation pattern — CRITICAL per Pitfall 6 (PATTERNS.md § wiring.rs Path validation). -->

```rust
// Plan 36-02 yaml_merge target-path validation MUST use Path::components()
// iteration + canonicalization, NOT str::starts_with. Preserve fork's
// validate_path_within callsites where they intersect yaml_merge targets.
fn validate_target_path(target: &Path, profile_dir: &Path) -> Result<PathBuf> {
    let canonical = target.canonicalize().map_err(|e| NonoError::PathCanonicalization {
        path: target.to_path_buf(),
        source: e,
    })?;
    let canonical_profile_dir = profile_dir.canonicalize()?;
    if !canonical.components().take(canonical_profile_dir.components().count())
        .zip(canonical_profile_dir.components())
        .all(|(a, b)| a == b)
    {
        return Err(NonoError::PathOutsideRoot { /* ... */ });
    }
    Ok(canonical)
}
```

<!-- Anti-pattern to AVOID (CLAUDE.md § Common Footguns #1). -->
```rust
// VULNERABILITY: path.starts_with("/home") matches "/homeevil"
if target_path.starts_with(profile_dir) { /* DO NOT USE */ }
```

<!-- Existing handler integration pattern (PATTERNS.md § profile_cmd.rs handler shape). -->

`cmd_validate` at profile_cmd.rs:2142 is the analog handler-integration pattern. For yaml_merge, find the `cmd_profile_patch` handler (or equivalent `--yaml` overlay path) via:
```bash
grep -n 'fn cmd_profile_patch\|fn cmd_patch\|--yaml' crates/nono-cli/src/profile_cmd.rs
```
</interfaces>

<drift_notes>
1. **Fork has NO `wiring.rs` currently** (RESEARCH.md verified — `ls crates/nono-cli/src/wiring.rs` returns ENOENT). Plan 36-02 creates fresh.
2. **Fork has NO `serde_yaml*` dep currently** (RESEARCH.md verified — no `serde_yaml*` in Cargo.toml). Plan 36-02 adds.
3. **`serde_yaml_ng` 0.10.0 availability on crates.io** is ASSUMED per RESEARCH.md A1. Task 1 verifies via `cargo search serde_yaml_ng` before committing the Cargo.toml change.
4. **Acceptance criterion #1 scope-trimmed** per D-36-C1 — Plan 36-02 PLAN.md `success_criteria` MUST mark #1 as "intentionally not satisfied in v2.4; deferred to v2.5-FU-3" with citation.
5. **D-19 trailer NOT used** — Plan 36-02 is D-20 manual-replay (D-36-C2); upstream's commits modified upstream-only `wiring.rs` (1761 LOC) which doesn't exist in fork. Cherry-pick structurally infeasible.
</drift_notes>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Verify serde_yaml_ng 0.10.0 availability + pin in Cargo.toml + scaffold wiring.rs module header (per D-36-C1 + D-36-C2)</name>
  <files>crates/nono-cli/Cargo.toml, crates/nono-cli/src/wiring.rs, crates/nono-cli/src/main.rs</files>
  <read_first>
    - crates/nono-cli/Cargo.toml (line 64 — existing `sigstore-sign = "0.6.5"` exact-version pin precedent; line 74 — workspace serde; line 109 — existing dev-dep jsonschema)
    - crates/nono-cli/src/wiring.rs (verify ENOENT — must NOT exist; will be created)
    - crates/nono-cli/src/main.rs (lines 5-95 — mod tree section for insertion order)
    - crates/nono-cli/src/package.rs (lines 1-40 — preamble + imports pattern to mirror)
    - .planning/phases/36-upst3-deep-closure/36-PATTERNS.md § `crates/nono-cli/src/wiring.rs` (NEW; Plan 36-02)
    - .planning/templates/upstream-sync-quick.md § Fork-divergence catalog § `validate_path_within` defense-in-depth retention (Phase 22-03 PKG-04)
  </read_first>
  <action>
    1. **Verify serde_yaml_ng 0.10.0 on crates.io**: `cargo search serde_yaml_ng | grep '^serde_yaml_ng'`. Expect a result line showing version 0.10.0 (or higher 0.10.x). If absent: fall back to the next 0.10.x available; document choice in commit body. If multiple 0.10.x versions are broken: escalate via D-36-A5 STOP trigger.
    2. **Pin dep in Cargo.toml**: Add this exact line in the `[dependencies]` block (near `sigstore-sign` for cohesion):
       ```toml
       # YAML-merge directive support (Plan 36-02; upstream-aligned at v0.10.0 per 242d4917)
       serde_yaml_ng = "=0.10.0"
       ```
    3. **Confirm resolution**: `cargo build -p nono-cli` (with no other changes yet). Must succeed with the new dep resolved. If resolution fails: investigate and fix before proceeding (escalate per D-36-A5).
    4. **Create `crates/nono-cli/src/wiring.rs`** with this exact header preamble (mirror `package.rs:1-32` shape):
       ```rust
       //! YAML-merge directive parser and applier.
       //!
       //! # Upstream wiring.rs awareness (v0.49.0, manual-replay of d44f5541)
       //!
       //! In upstream nono v0.49.0 (commits 242d4917 / 802c8566 / d44f5541), the upstream
       //! project introduced a `crates/nono-cli/src/wiring.rs` abstraction (~1761 LOC)
       //! carrying WriteFile / JsonMerge / JsonArrayAppend install directives,
       //! SHA-256-keyed install records, and lockfile v3+v4 with strict overwrite policy.
       //!
       //! The fork does NOT carry the full structural rewrite. Per Phase 33's
       //! DIVERGENCE-LEDGER + upstream-sync-quick.md catalog entries "Hooks subsystem
       //! ownership" + "validate_path_within retention", the fork's package system
       //! (package.rs + package_cmd.rs + hooks.rs) is preserved. Full wiring.rs port
       //! is deferred to v2.5-FU-3.
       //!
       //! Plan 36-02 (D-20 manual-replay per D-36-C1 + D-36-C2) lands ONLY the
       //! yaml_merge directive machinery from d44f5541, the serde_yaml_ng 0.10.0
       //! pin from 242d4917, and the reversal failure test. See the Plan 36-02
       //! SUMMARY for the per-acceptance disposition table.
       //!
       //! Acceptance criterion #1 (idempotent JSON-merge install records) is
       //! EXPLICITLY scope-trimmed per D-36-C1; deferred to v2.5-FU-3.

       use nono::{NonoError, Result};
       use serde::{Deserialize, Serialize};
       use std::path::{Path, PathBuf};
       ```
    5. **Add `mod wiring;`** to `crates/nono-cli/src/main.rs` in alphabetical order within the existing mod section (lines 5-95).
    6. Run `cargo build -p nono-cli` — must succeed (empty wiring.rs module + main.rs mod registration).
  </action>
  <verify>
    <automated>cargo search serde_yaml_ng 2>&amp;1 | grep '^serde_yaml_ng' &amp;&amp; grep -c 'serde_yaml_ng = "=0.10.0"' crates/nono-cli/Cargo.toml &amp;&amp; test -f crates/nono-cli/src/wiring.rs &amp;&amp; grep -c '^mod wiring;' crates/nono-cli/src/main.rs &amp;&amp; cargo build -p nono-cli 2>&amp;1 | tail -10</automated>
  </verify>
  <acceptance_criteria>
    - `serde_yaml_ng` 0.10.0 confirmed on crates.io (cargo search returns matching entry).
    - Cargo.toml carries the pin: `grep -c 'serde_yaml_ng = "=0.10.0"' crates/nono-cli/Cargo.toml` returns 1.
    - `wiring.rs` exists with preamble (grep: `grep -c 'manual-replay of d44f5541' crates/nono-cli/src/wiring.rs` returns 1).
    - Preamble cites all 3 upstream commits (grep: `grep -cE '242d4917|802c8566|d44f5541' crates/nono-cli/src/wiring.rs` returns ≥ 3).
    - Preamble cites v2.5-FU-3 deferral (grep: `grep -c 'v2\.5-FU-3' crates/nono-cli/src/wiring.rs` returns ≥ 1).
    - Module registered: `grep -c '^mod wiring;' crates/nono-cli/src/main.rs` returns 1.
    - `cargo build -p nono-cli` exits 0.
  </acceptance_criteria>
  <done>serde_yaml_ng pinned + verified; wiring.rs file scaffolded with fork-divergence preamble; module registered; build clean.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: Implement yaml_merge directive parser + applier + path-validation primitive (per D-36-C1 + CLAUDE.md § Path Handling)</name>
  <files>crates/nono-cli/src/wiring.rs</files>
  <read_first>
    - crates/nono-cli/src/wiring.rs (Task 1's scaffold)
    - upstream source for reference: `git show upstream/d44f5541:crates/nono-cli/src/wiring.rs` (capture the yaml_merge parser + applier shape; adapt to fork's profile-patch idioms)
    - crates/nono-cli/src/package_cmd.rs (existing `validate_path_within` callsites — 9 callsites per upstream-sync-quick.md retention entry; mirror the path-validation primitive shape)
    - CLAUDE.md § Path Handling (path component comparison + canonicalization + UNC / `\\?\` / drive-letter handling)
    - .planning/phases/36-upst3-deep-closure/36-PATTERNS.md § `crates/nono-cli/src/wiring.rs` (NEW; Plan 36-02)
  </read_first>
  <behavior>
    - Test 1 (`yaml_merge_directive_parses`): YAML input `yaml_merge:\n  target: profile.yaml\n  source: overlay.yaml` parses into the typed yaml_merge directive struct.
    - Test 2 (`apply_yaml_merge_merges_overlay_into_target`): with two YAML files where target has `{a: 1, b: 2}` and overlay has `{b: 3, c: 4}`, after applying yaml_merge the target file contains `{a: 1, b: 3, c: 4}` (overlay wins on conflicts, preserving target's unique keys).
    - Test 3 (`validate_target_path_rejects_traversal`): `validate_target_path` rejects target paths with `../../../etc/passwd` shape (canonicalized path escapes profile_dir).
    - Test 4 (`validate_target_path_rejects_unc_alias`): on Windows host, target `\\?\C:\Windows\System32\foo` is rejected (or canonicalized to a non-profile-dir prefix and rejected by component comparison).
    - Test 5 (`validate_target_path_rejects_symlink_escape`): target that resolves via symlink to outside profile_dir is rejected post-canonicalization.
    - Test 6 (`validate_target_path_accepts_valid_target`): a path inside profile_dir is accepted.
    - Test 7 (`yaml_merge_apply_uses_validate_target_path`): the `apply_yaml_merge` entry point invokes `validate_target_path` BEFORE writing — verified by passing a traversal-shaped target and asserting the apply returns an error WITHOUT writing.
  </behavior>
  <action>
    1. Read upstream source via `git show upstream/d44f5541:crates/nono-cli/src/wiring.rs` (full file or relevant yaml_merge portion). Capture the directive struct shape, parser, and applier semantics.
    2. **Define yaml_merge directive struct** matching upstream shape, adapted to fork's profile-patch idioms (the directive accepts `target` + `source` path fields; possibly other upstream-shape fields — verify by reading upstream source). Apply:
       - `#[derive(Debug, Clone, Deserialize, Serialize)]`
       - `#[serde(deny_unknown_fields)]`
       - `#[must_use]` on the parser return type
    3. **Implement `validate_target_path(target: &Path, profile_dir: &Path) -> Result<PathBuf>`** per PATTERNS.md exact target shape:
       - canonicalize both `target` and `profile_dir`
       - use `Path::components()` iteration to verify `canonical(target)` is contained within `canonical(profile_dir)`
       - return `Err(NonoError::PathOutsideRoot { ... })` on failure
       - NO `str::starts_with` on paths (CLAUDE.md Footgun #1)
       - Handle UNC / `\\?\` / drive-letter forms (Phase 35 Plan 35-03's `strip_verbatim_prefix` helper compose if needed; verify via existing test surface in `query_ext` or `path_handling` modules)
    4. **Implement `apply_yaml_merge(directive: &YamlMergeDirective, profile_dir: &Path) -> Result<()>`**:
       - Call `validate_target_path` for both `directive.target` and any nested path references — fail closed before any write.
       - Use `serde_yaml_ng::from_str` to parse target + source YAML.
       - Merge overlay into target per upstream `d44f5541` semantics (overlay wins on conflicts; preserve target's unique keys).
       - Use atomic write (file → temp file → rename) when persisting the merged result, mirroring fork's existing atomic-write helpers (search `crates/nono-cli/src/profile_save_runtime.rs` for the atomic-write primitive).
       - Return `Result<()>` — fail closed on any I/O error or canonicalization error.
       - NO `.unwrap()` / `.expect()` outside `#[cfg(test)]` (CLAUDE.md).
    5. **Add `#[cfg(test)] mod tests`** + `#[cfg(test)] mod path_validation_tests` with the 7 tests enumerated in `<behavior>`. Use `tempfile::TempDir` for filesystem-touching tests. Save/restore env vars per CLAUDE.md if any test manipulates `HOME` / `XDG_CONFIG_HOME` / `TMPDIR`.
    6. Run `cargo test -p nono-cli --lib wiring::tests` and `cargo test -p nono-cli --lib wiring::path_validation_tests` — all 7 tests must pass.
    7. Run `cargo clippy -p nono-cli --all-targets -- -D warnings -D clippy::unwrap_used` — must be clean.
  </action>
  <verify>
    <automated>cargo test -p nono-cli --lib wiring::tests 2>&amp;1 | tail -10 &amp;&amp; cargo test -p nono-cli --lib wiring::path_validation_tests 2>&amp;1 | tail -10 &amp;&amp; cargo clippy -p nono-cli --all-targets -- -D warnings -D clippy::unwrap_used 2>&amp;1 | tail -10</automated>
  </verify>
  <acceptance_criteria>
    - `apply_yaml_merge` function exists (grep: `grep -c 'pub fn apply_yaml_merge' crates/nono-cli/src/wiring.rs` returns 1).
    - `validate_target_path` uses Path::components() iteration (grep: `grep -A 30 'fn validate_target_path' crates/nono-cli/src/wiring.rs | grep -c 'components()'` returns ≥ 1).
    - NO `str::starts_with` on paths in wiring.rs (grep: `grep -E 'target_path.*starts_with|target\.starts_with' crates/nono-cli/src/wiring.rs | wc -l` returns 0).
    - All 7 tests pass: `cargo test -p nono-cli --lib wiring::` exits 0.
    - Clippy clean: `cargo clippy -p nono-cli --all-targets -- -D warnings -D clippy::unwrap_used` exits 0.
    - No `.unwrap()` in non-test code: `grep -v '^[[:space:]]*//' crates/nono-cli/src/wiring.rs | grep -v '#\[cfg(test)\]' | grep -c '\.unwrap()\|\.expect('` returns 0 (after accounting for test gating).
    - Test ID **36-02-* / T-36-02-YAML-MERGE** + **T-36-02-PATH-VALIDATE**: directive parses + applies; path validation rejects traversal/UNC/symlink escapes.
  </acceptance_criteria>
  <done>yaml_merge parser + applier + path-validation primitive implemented; 7 inline tests lock the directive + path-traversal invariants; clippy clean.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 3: Wire yaml_merge into `nono profile patch --yaml` handler + add reversal-failure integration test (per REQ-PORT-CLOSURE-04 #2 + #4)</name>
  <files>crates/nono-cli/src/profile_cmd.rs, crates/nono-cli/tests/yaml_merge_reversal.rs</files>
  <read_first>
    - crates/nono-cli/src/profile_cmd.rs (find the `--yaml` overlay handler via grep: `grep -n 'fn cmd_profile_patch\|fn cmd_patch\|"--yaml"\|long = "yaml"' crates/nono-cli/src/profile_cmd.rs`)
    - crates/nono-cli/src/wiring.rs (Task 2 deliverable — `apply_yaml_merge` API)
    - upstream source for reversal-failure test: `git show upstream/242d4917 -- crates/nono-cli/tests/` (capture upstream's reversal-failure test verbatim; adapt to fork's profile-patch idioms)
    - .planning/templates/upstream-sync-quick.md § Fork-divergence catalog § `validate_path_within` retention (preserve callsites)
    - crates/nono-cli/src/package_cmd.rs (existing `validate_path_within` callsites — preserve where they intersect yaml_merge target paths)
  </read_first>
  <behavior>
    - Test 1 (`test_profile_patch_yaml_merge_directive_applied`): construct a temp profile + overlay containing yaml_merge directive; run `nono profile patch --yaml <overlay>`; assert the profile file is mutated per yaml_merge semantics.
    - Test 2 (`test_yaml_merge_reversal_failure`): reproduce upstream 242d4917's reversal-failure scenario — apply yaml_merge → attempt reverse → assert reversal fails with an error message matching upstream's expected shape (the exact upstream error text is captured by reading upstream's test).
    - Test 3 (`test_yaml_merge_path_traversal_rejected_through_handler`): pass a yaml_merge directive with `target: "../../etc/passwd"` to the `--yaml` handler; assert exit code != 0 + error message references path-outside-root rejection.
    - Test 4 (`test_yaml_merge_preserves_validate_path_within`): if any existing `validate_path_within` callsite in `profile_cmd.rs` covers the yaml_merge target-path resolution, verify it is STILL invoked post-Plan-36-02 (smoke check via callgraph or by triggering a path-traversal that the `validate_path_within` callsite would have rejected and verifying it is rejected by the same callsite path, not bypassed by the new wiring code).
  </behavior>
  <action>
    1. **Locate `--yaml` handler** in `profile_cmd.rs`. Use grep to find the function (search for `--yaml` flag handling or `cmd_profile_patch`). Read 20-30 lines of context around the match.
    2. **Wire `wiring::apply_yaml_merge` into the handler** at the point where overlay directives are processed. The handler iterates over the overlay's directives; for each `yaml_merge` directive, call `wiring::apply_yaml_merge(directive, &profile_dir)`. Propagate errors via `?`.
    3. **Verify `validate_path_within` retention.** Search the handler for existing `validate_path_within` callsites. If any cover the yaml_merge target-path resolution, KEEP them; the new `apply_yaml_merge::validate_target_path` is defense-in-depth, NOT a replacement. Add this comment near the preserved callsite: `// Defense-in-depth (fork divergence: see upstream-sync-quick.md Fork-divergence catalog § validate_path_within retention). Plan 36-02 adds in-wiring.rs path validation but does NOT remove this callsite.`
    4. **Create `crates/nono-cli/tests/yaml_merge_reversal.rs`** as new integration test file. Reproduce upstream 242d4917's reversal-failure scenario verbatim where shape allows; adapt to fork's profile-patch idioms where structural differences require it. Document any adaptation in the test's `///` doc comment citing upstream commit hash.
    5. Add the 4 tests enumerated in `<behavior>`. Use `tempfile::TempDir` for fixture files. Save/restore env vars per CLAUDE.md.
    6. Run `cargo test -p nono-cli --test yaml_merge_reversal` — all 4 tests must pass.
    7. Run `cargo clippy -p nono-cli --all-targets -- -D warnings -D clippy::unwrap_used` — must be clean.
  </action>
  <verify>
    <automated>cargo test -p nono-cli --test yaml_merge_reversal -- --nocapture 2>&amp;1 | tee /tmp/36-02-task3.log &amp;&amp; cargo clippy -p nono-cli --all-targets -- -D warnings -D clippy::unwrap_used 2>&amp;1 | tail -10</automated>
  </verify>
  <acceptance_criteria>
    - `profile_cmd.rs` references the new wiring API (grep: `grep -c 'wiring::apply_yaml_merge\|use crate::wiring' crates/nono-cli/src/profile_cmd.rs` returns ≥ 1).
    - `validate_path_within` retention preserved (grep: count of `validate_path_within` callsites in profile_cmd.rs is GREATER THAN OR EQUAL TO the pre-Plan-36-02 count — no silent removal).
    - Integration test file exists with all 4 test functions (grep: `grep -cE 'fn test_profile_patch_yaml_merge_directive_applied|fn test_yaml_merge_reversal_failure|fn test_yaml_merge_path_traversal_rejected_through_handler|fn test_yaml_merge_preserves_validate_path_within' crates/nono-cli/tests/yaml_merge_reversal.rs` returns 4).
    - All 4 integration tests pass: `cargo test -p nono-cli --test yaml_merge_reversal` exits 0.
    - Windows host clippy clean.
    - Test ID **36-02-* / T-36-02-YAML-MERGE** (integration arm): directive flows through the `--yaml` handler end-to-end; reversal-failure test from upstream 242d4917 passes.
  </acceptance_criteria>
  <done>yaml_merge handler integration lands; fork's `validate_path_within` defense-in-depth callsites preserved; upstream reversal-failure test reproduced; path-traversal rejection enforced through the handler.</done>
</task>

<task type="auto">
  <name>Task 4: Close-gate verification + single combined D-20 commit citing 3 upstream commits (per D-36-A5 + D-36-C2)</name>
  <files>(verification only — single combined commit per D-36-C2)</files>
  <read_first>
    - .planning/phases/36-upst3-deep-closure/36-CONTEXT.md § D-36-A5 (all 8 close-gate steps) + § D-36-C2 (single combined commit citing 3 upstream commits; NO D-19 trailer)
    - .planning/templates/upstream-sync-quick.md § D-19 trailer block (CONFIRMS Plan 36-02 does NOT use this trailer)
  </read_first>
  <action>
    1. Run all 8 D-36-A5 close-gate steps on Windows host:
       1. `cargo test --workspace --all-features` — must include wiring::tests + wiring::path_validation_tests + yaml_merge_reversal; all green.
       2. `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used`
       3. `cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` (LOAD-BEARING — yaml_merge path-validation may have cfg-gated branches)
       4. `cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used`
       5. `cargo fmt --all -- --check`
       6. (skip-document: Plan 36-02 does not touch detached-console)
       7. (skip-document: Plan 36-02 does not touch WFP)
       8. (skip-document: Plan 36-02 does not touch learn)
    2. Squash Tasks 1-3 into a single combined git commit (D-36-C2 single-combined-commit invariant). Commit body shape (D-20 manual-replay; NO `Upstream-commit:` trailer):
       ```
       feat(36-02): port yaml_merge directive (stripped-down wiring.rs per D-36-C1)

       Creates fork-side crates/nono-cli/src/wiring.rs carrying ONLY the
       yaml_merge directive machinery from upstream's v0.49.0 surface. Full
       upstream wiring.rs (1761 LOC; WriteFile / JsonMerge / JsonArrayAppend /
       SHA-256-keyed install records / lockfile v3+v4 / idempotent reversal /
       `--force` on `nono remove`) is explicitly excluded — fork's package
       system (package.rs + package_cmd.rs + hooks.rs) is preserved per
       D-34-B1 + the "Hooks subsystem ownership" + "validate_path_within
       retention" upstream-sync-quick.md catalog entries.

       D-36-C1 scope-trim explicit:
       - REQ-PORT-CLOSURE-04 acceptance #1 (idempotent JSON-merge install
         records) INTENTIONALLY NOT SATISFIED in v2.4. Deferred to v2.5-FU-3
         (full wiring.rs base abstraction port; ~1761 LOC; 2-3 week D-20
         manual-replay plan with hooks.rs + validate_path_within braiding).

       Closes REQ-PORT-CLOSURE-04 acceptance criteria #2 (yaml_merge directive
       accepted by `nono profile patch --yaml`), #3 (serde_yaml_ng pinned
       =0.10.0), #4 (reversal failure test from upstream 242d4917).

       Path validation per CLAUDE.md § Common Footguns #1: Path::components()
       iteration + canonicalization; NO str::starts_with on paths. Fork's
       existing validate_path_within callsites in profile_cmd.rs PRESERVED
       as defense-in-depth — Plan 36-02 ADDS in-wiring.rs validation, does
       NOT remove fork's existing primitive.

       Design sources (D-20 manual replay per D-36-C2):
       - 242d4917 (upstream v0.49.0): serde_yaml_ng 0.10.0 pin + reversal
         failure test
       - 802c8566 (upstream v0.49.0): rustfmt over upstream's wiring.rs
         (no-op for fork's shape — fork's wiring.rs is a fresh file)
       - d44f5541 (upstream v0.49.0): yaml_merge directive parser + applier
         (primary content)

       Closes P34-DEFER-06-1 (yaml_merge wiring trio) + P34-DEFER-09-2
       (wiring.rs base abstraction, scope-trimmed).

       Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
       Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
       ```
    3. Smoke check at plan close: `git log --format='%B' main~1..main | grep -c '^Upstream-commit: '` returns 0.
  </action>
  <verify>
    <automated>cargo test --workspace --all-features 2>&amp;1 | tail -10 &amp;&amp; cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used 2>&amp;1 | tail -10 &amp;&amp; cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used 2>&amp;1 | tail -10 &amp;&amp; cargo fmt --all -- --check &amp;&amp; git log --format='%B' main~1..main | grep -c '^Upstream-commit: '</automated>
  </verify>
  <acceptance_criteria>
    - Close-gate steps 1, 2, 3, 4, 5 exit 0.
    - Single combined commit on `main`: `git rev-list --count main~1..main` returns 1.
    - Commit body cites all 3 upstream commits: `git log --format='%B' main~1..main | grep -cE '242d4917|802c8566|d44f5541'` returns ≥ 3.
    - Commit body cites scope-trim per D-36-C1: `git log --format='%B' main~1..main | grep -c 'D-36-C1'` returns ≥ 1.
    - Commit body cites v2.5-FU-3 deferral: `git log --format='%B' main~1..main | grep -c 'v2\.5-FU-3'` returns ≥ 1.
    - NO `Upstream-commit:` trailer: `git log --format='%B' main~1..main | grep -c '^Upstream-commit: '` returns 0 (D-20 manual-replay shape per D-36-C2).
    - DCO trailer: `git log --format='%B' main~1..main | grep -c '^Signed-off-by: '` returns ≥ 1.
  </acceptance_criteria>
  <done>Plan 36-02 single combined commit on `main` with D-20 manual-replay shape citing all 3 upstream commits; close-gate green; acceptance #1 scope-trim documented; P34-DEFER-06-1 + P34-DEFER-09-2 closed.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| User-supplied YAML overlay → fork's profile-patch handler | Untrusted input; YAML may contain malformed shapes, traversal-shaped target paths, or unknown directives |
| yaml_merge target path → filesystem write | Validation boundary; path must canonicalize within profile_dir; defense-in-depth via fork's `validate_path_within` retention catalog entry |
| `serde_yaml_ng` 0.10.0 dependency → process state | Trusted at dep-pin time; runtime parse-time errors propagate via `NonoError::ProfileParse` |
| Reversal-failure test fixture → upstream test reproduction | Trusted test boundary; reproduces upstream's locked test invariant |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-36-02-YAML-MERGE | Tampering | Malformed YAML input to yaml_merge applier; could cause panic or unexpected merge behavior | mitigate | `serde_yaml_ng::from_str` returns `Result<T, _>`; map to `NonoError::ProfileParse` via `?`. NO `.unwrap()` outside `#[cfg(test)]`. Test 1 (`yaml_merge_directive_parses`) locks the parser invariant. |
| T-36-02-PATH-VALIDATE | Tampering / Elevation of Privilege | yaml_merge directive accepts `target: ../../../etc/passwd` and silently writes outside profile_dir | mitigate | Task 2 `validate_target_path` uses `Path::components()` iteration + canonicalization (NOT `str::starts_with`). Tests 3-5 lock the rejection invariants for traversal / UNC / symlink-escape shapes. Task 3 step 3 PRESERVES fork's existing `validate_path_within` callsites in `profile_cmd.rs` as defense-in-depth. |
| T-36-02-VALIDATE-PATH-WITHIN-REMOVED | Tampering / Elevation of Privilege | Plan 36-02 silently removes `validate_path_within` callsites in `profile_cmd.rs` because upstream's wiring.rs doesn't need them | mitigate | Upstream-sync-quick.md § Fork-divergence catalog § `validate_path_within` retention entry locks the behavior: "When upstream commits remove `validate_path_within` calls, KEEP them in the fork." Task 3 step 3 + acceptance criterion explicitly verify count is GTE pre-plan baseline. Test 4 (`test_yaml_merge_preserves_validate_path_within`) is the regression gate. |
| T-36-02-DEP-PIN-DRIFT | Tampering | `serde_yaml_ng` version drift between fork and upstream causes yaml_merge directive semantic divergence | mitigate | Task 1 pins `=0.10.0` (exact-version `=` prefix). Mirrors upstream `242d4917`. Future drift triggers a deliberate pin-bump via a v2.5+ ADR. |
| T-36-02-ATOMIC-WRITE-RACE | Tampering | yaml_merge applier writes to target via non-atomic ops, causing TOCTOU race with concurrent profile loads | mitigate | Task 2 step 4 uses atomic write (file → temp file → rename) mirroring fork's existing primitives in `profile_save_runtime.rs`. Atomic-rename semantics are POSIX-guaranteed on Linux + macOS; Windows handled via `MoveFileEx` with `MOVEFILE_REPLACE_EXISTING` flag (verify the existing fork primitive's Windows path). |
| T-36-02-DENY-UNKNOWN-FIELDS | Tampering | yaml_merge directive struct missing `#[serde(deny_unknown_fields)]` allows attacker to inject unknown directive fields and exploit forward-compat surface | mitigate | Task 2 step 2 requires `#[serde(deny_unknown_fields)]` on the directive struct. Acceptance criterion verifies via grep. |
| T-36-02-REVERSAL-FAILURE-DROP | Repudiation | Upstream's reversal-failure test from 242d4917 silently fails to reproduce because fork's profile-patch idioms differ | mitigate | Task 3 step 4 EXPLICITLY documents any adaptation in the test's `///` doc comment citing upstream commit hash. Test 2 (`test_yaml_merge_reversal_failure`) is the locked invariant. |
| T-36-02-LIB-TIER-LEAK | Elevation of Privilege | yaml_merge logic accidentally lands in `crates/nono/src/` library tier | accept | Plan 36-02 touches only `crates/nono-cli/` files. Risk zero by file-modification scope. |
| T-36-02-IDEMPOTENT-DROP | Repudiation / Tampering | yaml_merge applier is NOT idempotent (acceptance criterion #1 scope-trimmed); a re-apply of the same overlay could double-apply or fail unexpectedly | accept | D-36-C1 explicitly scope-trims acceptance #1 to v2.5-FU-3. Commit body documents the trim. Operators are aware that yaml_merge re-apply may produce different results than first-apply; this is the documented v2.4 trade-off. |
</threat_model>

<verification>
## Per-Plan Verification

1. **Dep pin present:**
   ```bash
   grep -c 'serde_yaml_ng = "=0.10.0"' crates/nono-cli/Cargo.toml
   # Expected: 1
   ```

2. **wiring.rs exists with preamble citing all 3 upstream commits:**
   ```bash
   test -f crates/nono-cli/src/wiring.rs
   grep -cE '242d4917|802c8566|d44f5541' crates/nono-cli/src/wiring.rs
   # Expected: ≥ 3
   ```

3. **Module registered:**
   ```bash
   grep -c '^mod wiring;' crates/nono-cli/src/main.rs
   # Expected: 1
   ```

4. **Path validation primitive correct:**
   ```bash
   grep -c 'components()' crates/nono-cli/src/wiring.rs
   # Expected: ≥ 1 (component iteration)
   grep -cE 'target_path.*starts_with|target\.starts_with' crates/nono-cli/src/wiring.rs
   # Expected: 0 (no str::starts_with on paths)
   ```

5. **Handler integration:**
   ```bash
   grep -c 'wiring::apply_yaml_merge\|use crate::wiring' crates/nono-cli/src/profile_cmd.rs
   # Expected: ≥ 1
   ```

6. **Tests green:**
   - `cargo test -p nono-cli --lib wiring::` exits 0 (Task 2's 7 tests)
   - `cargo test -p nono-cli --test yaml_merge_reversal` exits 0 (Task 3's 4 tests)

7. **`validate_path_within` retention:** count in `profile_cmd.rs` ≥ pre-Plan-36-02 baseline.

8. **Close-gate green (D-36-A5):**
   - Windows + Linux cross-target + macOS cross-target clippy + fmt-check all exit 0

9. **Commit shape (D-36-C2 single combined commit):**
   ```bash
   git rev-list --count main~1..main
   # Expected: 1
   git log --format='%B' main~1..main | grep -c '^Upstream-commit: '
   # Expected: 0 (no D-19 trailer)
   git log --format='%B' main~1..main | grep -cE '242d4917|802c8566|d44f5541'
   # Expected: ≥ 3
   ```
</verification>

<success_criteria>
- New file `crates/nono-cli/src/wiring.rs` exists carrying yaml_merge directive parser + applier + path-validation primitive (Path::components() iteration; NO str::starts_with).
- `serde_yaml_ng = "=0.10.0"` pinned in Cargo.toml.
- `mod wiring;` registered in main.rs.
- `nono profile patch --yaml` handler wires the directive end-to-end.
- 11 new tests total (7 inline in wiring.rs + 4 in tests/yaml_merge_reversal.rs) lock yaml_merge parser, applier, path validation, handler integration, and upstream reversal-failure scenario.
- Fork's `validate_path_within` callsites in profile_cmd.rs PRESERVED (D-34-B1 + upstream-sync-quick.md catalog).
- REQ-PORT-CLOSURE-04 acceptance #2 + #3 + #4 met; acceptance #1 EXPLICITLY scope-trimmed to v2.5-FU-3 (documented in commit body + SUMMARY).
- All 8 D-36-A5 close-gate steps green (or documented-skipped for steps 6-8).
- Single combined commit on `main` with D-20 manual-replay shape citing 3 upstream commits; NO `Upstream-commit:` trailer (per D-36-C2).
- P34-DEFER-06-1 + P34-DEFER-09-2 closed.
</success_criteria>

<output>
After completion, create `.planning/phases/36-upst3-deep-closure/36-02-WIRING-YAML-MERGE-SUMMARY.md` documenting:
- New file LOC delta (~300-400 LOC target)
- Per-acceptance-criterion disposition table (#1 scope-trimmed; #2, #3, #4 met)
- Test counts (7 inline + 4 integration = 11 new tests)
- `validate_path_within` callsite count pre- and post-plan (must not decrease)
- Path-validation test results (traversal / UNC / symlink rejection)
- serde_yaml_ng 0.10.0 cargo-search confirmation
- Upstream-reversal-failure test adaptation notes (any deviation from upstream 242d4917's verbatim shape)
- Close-gate run outcomes
- Hand-off + carry-forward note: v2.5-FU-3 covers the full wiring.rs braiding deferral
</output>
</content>
</invoke>
