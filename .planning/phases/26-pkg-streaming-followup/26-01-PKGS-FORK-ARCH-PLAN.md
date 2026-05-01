---
phase: 26-pkg-streaming-followup
plan: 01
type: execute
wave: 1
depends_on: []
requirements: [PKGS-02, PKGS-03]
tags: [pkg, package-manager, validation, plugin, fork-arch, cherry-pick, upstream-sync]
tdd: false
risk: low
files_modified:
  # Add ArtifactType::Plugin variant (REQ-PKGS-03). 7th variant after Profile/Hook/Instruction/TrustPolicy/Groups/Script
  # (NB: enum has 6 variants today, NOT 5 — see Deviation #0 in Risks). #[serde(rename_all = "snake_case")] is already
  # set; the new variant serializes as "plugin" via that attr (no per-variant rename needed).
  - crates/nono-cli/src/package.rs
  # Port upstream's validate_relative_path (REQ-PKGS-02; from upstream commit 58b5a24e) as DEFENSE-IN-DEPTH alongside
  # fork's existing validate_path_within (currently at line 1035). Wire validate_relative_path BEFORE the existing
  # validate_path_within callsite at line 691 (and the now-restorable Plugin arm at the deferred-divergence comment
  # at lines 671-688). Add ArtifactType::Plugin match arms in the 5+ identified match sites
  # (lines 154, 568, 614-671 the big block, 707, 724, 754, 967-972 the filename-to-type matcher). Replace the
  # deferred-divergence comment block at lines 671-688 with the live ArtifactType::Plugin arm (REQ-PKGS-03).
  - crates/nono-cli/src/package_cmd.rs
autonomous: true

must_haves:
  truths:
    - "`validate_relative_path` function exists in `crates/nono-cli/src/package_cmd.rs` and runs BEFORE every install-dir-bound artifact-write callsite of `validate_path_within`. Verified by `grep -n 'fn validate_relative_path' crates/nono-cli/src/package_cmd.rs` returning exactly 1 match (the definition) AND `grep -c 'validate_relative_path' crates/nono-cli/src/package_cmd.rs` returning at least 2 (definition + at least one callsite); the callsite(s) appear textually BEFORE the corresponding `validate_path_within(staging_root, &store_path)?;` line at ~691 (verified by line-number ordering in the grep output)."
    - "`validate_path_within` is preserved verbatim at line ~1035; defense-in-depth posture from v2.2 commit `869349df` survives this plan unchanged. Verified by `grep -c 'fn validate_path_within' crates/nono-cli/src/package_cmd.rs` returning exactly 1 AND `grep -n 'validate_path_within(staging_root, &store_path)' crates/nono-cli/src/package_cmd.rs` returning the identical line content as on baseline (the call body wording is unchanged; only the new `validate_relative_path` call is interleaved BEFORE it)."
    - "`ArtifactType` enum gains a NEW `Plugin` variant (the SEVENTH variant after Profile, Hook, Instruction, TrustPolicy, Groups, Script). Verified by `grep -c '    Plugin' crates/nono-cli/src/package.rs` returning at least 1 (the variant body itself, indented inside the enum block at line 87) AND `grep -c 'pub enum ArtifactType' crates/nono-cli/src/package.rs` returning exactly 1 (no duplicate enum). The `#[serde(rename_all = \"snake_case\")]` attribute already on the enum (line 86) handles the JSON shape: `\"plugin\"` round-trips without a per-variant `#[serde(rename = ...)]`."
    - "All existing `ArtifactType::*` match arms in `crates/nono-cli/src/package_cmd.rs` (Profile/Hook/Instruction/TrustPolicy/Groups/Script — 6 arms today, at lines 615/630/636/643/652/664 in the big match block at line 614) are joined by an `ArtifactType::Plugin` arm. Verified by `grep -c 'ArtifactType::Plugin' crates/nono-cli/src/package_cmd.rs` returning at least 1 (the new arm in the big match) AND `cargo build --workspace` clean — any non-exhaustive `match` left over in the codebase becomes a compile error and the build will surface it; the build-clean signal is the definitive completeness test."
    - "Pack manifest with `..` traversal in `path` field is rejected by `validate_relative_path` at the input-string layer BEFORE any filesystem syscall. Verified by a new unit test `validate_relative_path_rejects_traversal` (in the existing `mod tests` block in `package_cmd.rs` OR a new sibling test module) that constructs a string containing `..` and asserts `validate_relative_path(...)` returns `Err(...)` with the error message containing the substring `\"..\"` or `\"traversal\"` (whichever upstream's text uses)."
    - "Pack manifest with absolute path (Unix `/foo/bar` OR Windows `C:\\\\foo\\\\bar`) in `path` field is rejected by `validate_relative_path`. Verified by a new unit test `validate_relative_path_rejects_absolute_path` asserting `Err(...)` on both `\"/foo\"` and `\"C:\\\\foo\"` inputs (cross-platform — both shapes must reject regardless of host OS, since the package registry is cross-platform)."
    - "Pack manifest exploiting symlink-traversal (where the `path` is innocuous but resolves through a symlink to outside `staging_root`) is STILL rejected by the surviving `validate_path_within` post-symlink-resolution layer; v2.2's defense-in-depth posture is preserved. Verified by the existing fork regression tests for `validate_path_within` continuing to pass without modification (no `#[ignore]` added; no test deletion). The dual-layer is the REQ-PKGS-02 acceptance shape: input-string check first (cheap rejection), canonicalize-and-component-compare second (definitive)."
    - "Round-trip JSON serialization of `ArtifactType::Plugin` produces the lowercase `\"plugin\"` token and parses back. Verified by a new unit test `artifact_type_plugin_round_trips` asserting `serde_json::to_string(&ArtifactType::Plugin)? == \"\\\"plugin\\\"\"` AND `serde_json::from_str::<ArtifactType>(\"\\\"plugin\\\"\")? == ArtifactType::Plugin` (ergonomic via the existing `#[serde(rename_all = \"snake_case\")]` attr)."
    - "Schema-validation rejects unknown `artifact_type` values fail-closed (does NOT silently coerce to a default variant or to `ArtifactType::Script` filename-fallback). Verified by a new unit test `artifact_type_unknown_fails_closed` asserting `serde_json::from_str::<ArtifactType>(\"\\\"made_up_variant\\\"\").is_err()`. NB: the filename-based fallback at `package_cmd.rs:967-972` (which assigns `ArtifactType::Script` to unknown extensions) is a DIFFERENT code path — it operates on filenames, not on user-supplied `artifact_type` JSON values. The schema-rejection contract here is on the JSON deserializer."
    - "The deferred-divergence comment block currently at `crates/nono-cli/src/package_cmd.rs:671-688` (the multi-line `// NOTE: upstream ec49a7af also adds an ArtifactType::Plugin arm here. ...` block describing the planned restoration) is REMOVED, and the live `ArtifactType::Plugin` arm replaces it. Verified by `grep -c 'upstream ec49a7af also adds an ArtifactType::Plugin' crates/nono-cli/src/package_cmd.rs` returning EXACTLY 0 (the deferred-divergence note is gone). Companion verification: `grep -A 5 'ArtifactType::Plugin' crates/nono-cli/src/package_cmd.rs | head -20` shows a real arm body with `staging_root.join(...).join(file_name(&artifact.path)?)` and `write_bytes(...)`, NOT a comment."
    - "`make ci` passes on the Windows host: `cargo build --workspace` clean; `cargo test --workspace` clean (4 new tests added — see truths #5/#6/#8/#9 — plus the existing 651-passing baseline holds; pre-existing 2 TUF failures and 2 `nono::manifest` clippy `collapsible_match` errors are pre-existing per Plan 22-03 § Out-of-scope #5 and DO NOT regress); `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` clean modulo the documented 2 pre-existing manifest.rs errors; `cargo fmt --all -- --check` clean."
    - "D-19 byte-identical preservation: `git diff --stat <baseline>..HEAD -- crates/nono/` returns empty across all of this plan's commits. The `nono` core library is UNTOUCHED; all changes are confined to `crates/nono-cli/src/package.rs` and `crates/nono-cli/src/package_cmd.rs`. Verified at the verification-gate task (Task 6) by piping `git diff --stat` to `wc -l` and asserting `0`."
  artifacts:
    - path: "crates/nono-cli/src/package.rs"
      provides: "ArtifactType::Plugin enum variant (the 7th variant) + serde-default snake-case JSON shape `plugin`"
      grep_pattern: "    Plugin,"
      grep_pattern_alt: "pub enum ArtifactType"
      function_signatures:
        - "pub enum ArtifactType { Profile, Hook, Instruction, TrustPolicy, Groups, Script, Plugin }"
      min_call_sites: 1
    - path: "crates/nono-cli/src/package_cmd.rs"
      provides: "validate_relative_path port (defense-in-depth pre-check); ArtifactType::Plugin match arms across all 5+ enum-discriminant sites; deferred-divergence comment removed and replaced with live Plugin arm body; 4 new unit tests covering both REQ-PKGS-02 and REQ-PKGS-03 acceptance"
      grep_pattern: "fn validate_relative_path"
      grep_pattern_alt: "ArtifactType::Plugin"
      grep_pattern_alt2: "validate_path_within"
      grep_negative: "upstream ec49a7af also adds an ArtifactType::Plugin"
      function_signatures:
        - "fn validate_relative_path(path: &str) -> Result<()>"
        - "fn validate_path_within(base: &Path, full: &Path) -> Result<()>"
      min_call_sites: 8
  key_links:
    - from: "package_cmd.rs::write_supporting_artifact (the writer path that hits the big match block at line 614)"
      to: "validate_relative_path (input-string pre-check)"
      via: "called early in the artifact-write path BEFORE any filesystem syscall touches `artifact.path`; rejects `..`, absolute paths, Windows drive prefixes at the cheap-string layer"
      pattern: "validate_relative_path\\(&artifact\\.path\\)"
    - from: "package_cmd.rs::write_supporting_artifact (continuing the same path)"
      to: "validate_path_within (canonicalize-and-component-compare, line 691, UNCHANGED)"
      via: "called AFTER the artifact bytes are written to `store_path`; canonicalizes both `staging_root` and `store_path` and walks Path components — definitive answer post-symlink-resolution. Defense-in-depth: even if validate_relative_path missed something, validate_path_within catches it."
      pattern: "validate_path_within\\(staging_root, &store_path\\)"
    - from: "package_cmd.rs:614 (the big match block)"
      to: "ArtifactType::Plugin arm (NEW; replaces the deferred-divergence comment at lines 671-688)"
      via: "the new arm constructs `let path = staging_root.join(\"plugins\").join(file_name(&artifact.path)?); write_bytes(&path, bytes)?; path` — mirroring the existing `ArtifactType::Script` arm at line 664-670 with `\"plugins\"` substituted for `\"scripts\"`. No new permission flag; no new install-dir handler; the existing post-match `validate_path_within(staging_root, &store_path)?;` at line 691 covers the new arm by virtue of being post-match."
      pattern: "ArtifactType::Plugin =>"
    - from: "package.rs:87 (ArtifactType enum definition)"
      to: "package_cmd.rs match-block consumers (5+ sites at lines 154, 568, 614, 707, 724, 754)"
      via: "Adding the `Plugin` variant forces the Rust compiler to flag any non-exhaustive `match` site; cargo build's first failure list IS the call-site cascade. Iterate until clean. The 6 sites listed above are the known surface; build-clean is the completeness signal."
      pattern: "ArtifactType::"
    - from: "ArtifactType serde shape (`#[serde(rename_all = \"snake_case\")]` at line 86)"
      to: "manifest deserialization (the JSON `artifact_type: \"plugin\"` field on every PackageArtifact)"
      via: "the existing rename-all attribute renders `ArtifactType::Plugin` as `\"plugin\"` (lowercase) without any per-variant `#[serde(rename = ...)]`. Round-trip parity with the other 6 variants is automatic."
      pattern: "rename_all = \"snake_case\""
---

<objective>
Close the two fork-architectural deferrals from v2.2 Plan 22-03's package-manager cherry-pick chain that exceeded cherry-pick scope: REQ-PKGS-02 (port upstream's `validate_relative_path` as defense-in-depth alongside fork's stricter `validate_path_within`) and REQ-PKGS-03 (add the missing `ArtifactType::Plugin` enum variant the deferred-divergence comment at `package_cmd.rs:671-688` has been waiting for since 22-03's commit `73e1e3b8`). This plan covers ONLY the Windows-host-OK fork-architectural decisions; the streaming refactor (REQ-PKGS-01) and registry auto-pull (REQ-PKGS-04) are scoped to a separate Plan 26-02 invocation because they pull in `tempfile::TempDir`, HTTP timeouts, `semver` dep, and registry test fixtures that are easier to develop/test on a Linux/macOS host.

Today, the fork's `crates/nono-cli/src/package.rs:87` `ArtifactType` enum has 6 variants (Profile, Hook, Instruction, TrustPolicy, Groups, Script) — upstream's `Plugin` variant was introduced by an upstream commit not in 22-03's chain (the same chain that landed `validate_path_within` hardening as commit `869349df`). The deferred-divergence comment at `package_cmd.rs:671-688` documents the planned restoration verbatim; this plan executes it. Today, the fork's path validation runs ONLY `validate_path_within` (canonicalize-and-component-compare); upstream's commit `58b5a24e` adds `validate_relative_path` (input-string pre-check) earlier in the call chain. Plan 22-03 deferred the cherry-pick because dropping `validate_path_within` in favor of `validate_relative_path` was a security regression vs CLAUDE.md § Path Handling — but ADDING `validate_relative_path` alongside (defense-in-depth) was always the right call.

Closes REQ-PKGS-02 (port `validate_relative_path` from upstream `58b5a24e` as defense-in-depth — keeps fork's `validate_path_within` UNCHANGED at line 1035 + adds the input-string pre-check earlier in the artifact-write path) and REQ-PKGS-03 (add `ArtifactType::Plugin` variant + plumb match arms through every consumer site in `package_cmd.rs` + remove the deferred-divergence comment at lines 671-688).

Purpose: Two outstanding blockers for Plan 26-02's streaming refactor. Plan 26-02 (REQ-PKGS-01) ports upstream's `9ebad89a refactor(pkg): stream package artifact downloads`, which assumes BOTH `ArtifactType::Plugin` AND `validate_relative_path` are already in fork — see 22-03 SUMMARY § Critical Deviation #2 ("Depends on `ArtifactType::Plugin` enum variant which does NOT exist in the fork yet ... Depends on the `validate_relative_path` helper from #5"). Landing this plan first unblocks Plan 26-02's cherry-pick of `9ebad89a` to apply against a chain that matches upstream's expected dependency shape. Without this plan, Plan 26-02 would face the same conflict mess that Plan 22-03 documented in its PROGRESS file — landing `9ebad89a` in a chain that lacks Plugin + validate_relative_path is a hand-merge of ~+267/-109 LOC across 5 files at high cherry-pick pressure.

Output: 2 modified files. `crates/nono-cli/src/package.rs` adds 1 new enum variant (`Plugin` after `Script`). `crates/nono-cli/src/package_cmd.rs` ports upstream's `validate_relative_path` definition + at least 1 call site BEFORE the existing `validate_path_within(staging_root, &store_path)?;` at line 691, adds `ArtifactType::Plugin` match arms across 5+ identified consumer sites, removes the deferred-divergence comment block at lines 671-688 (and replaces it with the live `Plugin` arm body), and adds 4 unit tests in the existing `mod tests` block: `validate_relative_path_rejects_traversal`, `validate_relative_path_rejects_absolute_path`, `artifact_type_plugin_round_trips`, `artifact_type_unknown_fails_closed`. The `nono` core library is UNTOUCHED (D-19 byte-identical preservation enforced by Task 6 verification gate).
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/ROADMAP.md
@.planning/STATE.md
@.planning/REQUIREMENTS.md
@CLAUDE.md

<!-- Source artifacts (read these BEFORE making any change) -->
@.planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-03-PKG-SUMMARY.md
@crates/nono-cli/src/package.rs
@crates/nono-cli/src/package_cmd.rs

<interfaces>
<!-- Key types and contracts for this plan. Extracted from existing source. -->
<!-- Executor MUST use these directly — do not re-derive by exploration. -->

From `crates/nono-cli/src/package.rs:85-94` (existing `ArtifactType` — Task 2 adds `Plugin` AFTER `Script`; do NOT touch the `#[serde(rename_all = "snake_case")]` attribute, which already produces the correct snake-case JSON shape):

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    Profile,
    Hook,
    Instruction,
    TrustPolicy,
    Groups,
    Script,
    // Plugin,  <-- Task 2 adds this line; #[serde(rename_all = "snake_case")] handles the JSON shape automatically.
}
```

NB: The user-facing scope-of-work briefing for this plan stated "5 variants today" but `package.rs:87` shows 6 (Script is the 6th). Plugin is the 7th variant. Task 2's commit message MUST NOT claim "5th -> 6th" — it's "6th -> 7th". This is a one-line variant addition; serde shape is automatic.

From `crates/nono-cli/src/package_cmd.rs:614-691` (the big match block at line 614 — the primary REQ-PKGS-03 plumbing site; deferred-divergence comment lives at lines 671-688 and IS the deliverable's removal target):

```rust
let store_path = match artifact.artifact_type {
    ArtifactType::Profile => {
        // ... (line 615; fully populated arm — DO NOT MODIFY)
    }
    ArtifactType::Hook => {
        // ... (line 630; DO NOT MODIFY)
    }
    ArtifactType::Instruction => {
        // ... (line 636; DO NOT MODIFY)
    }
    ArtifactType::TrustPolicy => {
        // ... (line 643; DO NOT MODIFY)
    }
    ArtifactType::Groups => {
        // ... (line 652; DO NOT MODIFY)
    }
    ArtifactType::Script => {
        let path = staging_root
            .join("scripts")
            .join(file_name(&artifact.path)?);
        write_bytes(&path, bytes)?;
        ensure_executable(&path)?;
        path
    } // NOTE: upstream ec49a7af also adds an ArtifactType::Plugin arm here.    <-- Task 3 removes
      // Fork's ArtifactType enum does not yet have Plugin (introduced by a       <-- this comment
      // later upstream commit not in Plan 22-03's cherry-pick chain). When       <-- block (lines
      // that variant lands, restore upstream's Plugin arm verbatim:              <-- 671-688) and
      //                                                                          <-- replaces it
      //     ArtifactType::Plugin => {                                            <-- with the
      //         if artifact.path.contains("..") { return Err(...) }              <-- live Plugin
      //         let path = staging_root.join(&artifact.path);                    <-- arm shown
      //         write_bytes(&path, bytes)?;                                      <-- below.
      //         validate_path_within(staging_root, &path)?;
      //         ...
      //     }
};

// Defense-in-depth (Rule 2): every artifact path must remain inside the
// staging root, regardless of which arm above produced it. ...   <-- Task 1's validate_relative_path
// canonicalizing first. Path-component comparison via Path::starts_with on  <-- callsite goes
// canonicalized PathBufs (not string starts_with — CLAUDE.md § Common       <-- BEFORE this line.
// Footguns #1).
validate_path_within(staging_root, &store_path)?;     // line 691 — UNCHANGED
```

Replacement shape for the area covering `Script` arm + the deferred-divergence comment block at lines 671-688 (Task 3):

```rust
ArtifactType::Script => {
    let path = staging_root
        .join("scripts")
        .join(file_name(&artifact.path)?);
    write_bytes(&path, bytes)?;
    ensure_executable(&path)?;
    path
}
ArtifactType::Plugin => {
    // REQ-PKGS-03: place under staging_root/plugins/<file_name>.
    // No special handling beyond staging-path placement; the existing
    // post-match validate_path_within(staging_root, &store_path)?; at
    // ~line 691 covers this arm by virtue of being post-match.
    let path = staging_root
        .join("plugins")
        .join(file_name(&artifact.path)?);
    write_bytes(&path, bytes)?;
    path
}
};   // <-- the closing brace of the let store_path = match { ... } expression
```

NB: the comment block deletion AND the new arm addition are ONE atomic edit — do not commit the deletion alone (that would leave a non-exhaustive match the moment Task 2 lands ArtifactType::Plugin in the enum).

From upstream `58b5a24e refactor(cli): improve artifact path validation` (the function this plan ports — read upstream's exact body via `git show 58b5a24e -- '**/package_cmd.rs'` if cherry-pick conflicts; the SHA is recorded in 22-03 SUMMARY § "What was done" row 5):

The upstream `validate_relative_path` is an INPUT-STRING pre-check that:
1. Rejects strings containing `..` as a Path component (NOT just substring match — `..` mid-token like `foo..bar` is fine; `foo/../bar` is not).
2. Rejects absolute paths (`/foo`, `\\foo`, Windows drive prefixes `C:\\foo`).
3. Returns `Err(...)` with a clear error message naming the offending shape.

The upstream signature is approximately `fn validate_relative_path(path: &str) -> Result<()>`. Confirm the exact signature against the upstream commit; preserve verbatim if cherry-pick succeeds, replicate manually if conflicts breach D-02 thresholds (see Task 1).

From `crates/nono-cli/src/package_cmd.rs:1035` (existing — DO NOT MODIFY; this function is the surviving defense-in-depth layer per REQ-PKGS-02 acceptance #2):

```rust
fn validate_path_within(base: &Path, full: &Path) -> Result<()> {
    // canonicalize-and-component-compare implementation (~30 LOC).
    // Catches symlink-traversal that input-string check cannot.
    // ...
}
```

From `crates/nono-cli/src/package_cmd.rs:154, 568, 707, 724, 754, 967-972` (the secondary match-block consumer sites — Task 3 may need to add `ArtifactType::Plugin` arms here; the build will tell you which ones via cargo's non-exhaustive match errors):

- Line 154: `if artifact.artifact_type != ArtifactType::Hook { ... }` — boolean-style comparison, no arm needed.
- Line 568: `&& artifact.artifact_type == ArtifactType::Instruction` — boolean-style, no arm needed.
- Line 707: `Ok(if artifact.artifact_type == ArtifactType::Profile { ... }` — boolean-style, no arm needed.
- Line 724: `matches!(artifact.artifact_type, ArtifactType::Hook | ArtifactType::Script)` — `matches!` is exhaustive-friendly; no arm needed (Plugin would just fall through the `else` path).
- Line 754: `if artifact.artifact_type != ArtifactType::Profile { ... }` — boolean-style, no arm needed.
- Lines 967-972: filename-based `_ => ArtifactType::Script` fallback — DIFFERENT code path (operates on filenames, not on user-supplied JSON). The fallback's existence is unchanged by Plugin's addition; if upstream's commit added a `.plugin.json` filename matcher, port it; otherwise leave alone. Plugin artifacts must be declared via explicit `artifact_type: "plugin"` in the manifest (no filename-shorthand).

The PRIMARY plumbing site is the line-614 big match block. The boolean-style sites and the `matches!` site DO NOT need explicit Plugin arms — the build will not flag them, and Plugin falls through to the existing else-path. Build-clean is the definitive completeness signal.

From `crates/nono-cli/src/package_cmd.rs:372` (the `DownloadedArtifact` struct — DO NOT MODIFY here; Plan 26-02 may add `bundle_json` field as part of the streaming refactor — see Out of Scope below):

```rust
struct DownloadedArtifact { /* ... */ }
```

NB: The user-facing briefing flagged `bundle_json` as a v2.2 backlog companion gap to PKGS-03. Investigation confirms `bundle_json` is currently a LOCAL VARIABLE at `package_cmd.rs:425`, NOT a field on `DownloadedArtifact`. Adding it as a struct field is meaningful only when streaming refactor lands (`9ebad89a` introduces it as part of the `bytes`-to-`PathBuf` flow — the bundle JSON travels alongside the artifact path). Since `9ebad89a` is REQ-PKGS-01 (Plan 26-02), `bundle_json` field addition is OUT OF SCOPE for this plan. Document this finding in the Task 6 commit message verification block.

From `crates/nono/src/error.rs::NonoError` (existing — DO NOT MODIFY; this plan does NOT add new error variants. `validate_relative_path` returns errors via the existing `NonoError::PackageInstall(String)` variant — same one upstream uses, same one fork's `validate_path_within` already returns):

```rust
pub enum NonoError {
    // ...
    PackageInstall(String),  // <-- validate_relative_path errors land here
    // ...
}
```

If upstream's `validate_relative_path` body uses a different variant (e.g., `NonoError::InvalidArgument(String)` or `NonoError::PathTraversal`), prefer reusing whichever variant the fork's `validate_path_within` already uses for traversal rejection — keeps the error taxonomy tight (Rule-3 minimal-surface preservation per CLAUDE.md). Document the chosen variant in the Task 1 commit message.

From `.planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-03-PKG-SUMMARY.md § "Out-of-scope / Backlog" item #4` (the verbatim recommendation this plan executes):

> 4. [Backlog → v2.3 follow-up plan] PKG streaming + Plugin arm port
>
> The deferred work above (items #1 and #2) wraps into a single follow-up plan that:
> 1. Introduces `ArtifactType::Plugin` enum variant + plumbing first (closes the deferred divergence comment at `package_cmd.rs:631-643` [actually 671-688 on current HEAD — line numbers shifted]).
> 2. Decides explicitly whether the fork keeps `validate_path_within` as defense-in-depth alongside upstream's `validate_relative_path`, or adopts upstream's pattern verbatim. **Recommendation: keep both** — fork's stance is stricter and matches CLAUDE.md.
> 3. Cherry-picks `58b5a24e` (path validation) with `validate_path_within` retained as belt-and-suspenders.

This plan executes 22-03 backlog item #4 sub-items 1, 2, 3 verbatim. Sub-item 4 (cherry-pick `9ebad89a`) and sub-item 5 (cherry-pick `115b5cfa load_registry_profile auto-pull`) are scoped to Plan 26-02 (REQ-PKGS-01 + REQ-PKGS-04).
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Cherry-pick `58b5a24e` (or D-20 manual replay) — port `validate_relative_path` defense-in-depth pre-check</name>
  <files>crates/nono-cli/src/package_cmd.rs</files>
  <action>
Cherry-pick upstream commit `58b5a24e` ("refactor(cli): improve artifact path validation") onto the current `windows-squash` HEAD via `git cherry-pick 58b5a24e`. This commit ports `validate_relative_path` (input-string pre-check that rejects `..` Path components + absolute paths + Windows drive prefixes BEFORE any filesystem syscall).

EXPECTED CHANGE SHAPE (~30-50 LOC in `crates/nono-cli/src/package_cmd.rs`):
- Add `fn validate_relative_path(path: &str) -> Result<()>` somewhere near the existing `fn validate_path_within` at line 1035 (group the two validators together for cohesion).
- Add at least 1 callsite of `validate_relative_path(&artifact.path)?` EARLIER in the artifact-write code path than the existing `validate_path_within(staging_root, &store_path)?;` at line 691 — typically immediately after the `bytes` are read from `downloads` and before the `let store_path = match artifact.artifact_type` block at line 614.

CRITICAL — KEEP `validate_path_within` AT LINE 1035 INTACT. This is the REQ-PKGS-02 acceptance #2 contract: defense-in-depth means BOTH validators fire, not the `validate_relative_path` replacing the canonicalize-and-compare one. The fork's commit `869349df` (per 22-03 SUMMARY § "What was done" row 4 — "PKG-02 hardening") explicitly added `validate_path_within` after every artifact-write arm. Dropping `validate_path_within` would be a security regression vs CLAUDE.md § Path Handling.

If `git cherry-pick 58b5a24e` succeeds without conflict, verify the resulting diff:
1. `validate_path_within` at line ~1035 is still present (`grep -c 'fn validate_path_within' crates/nono-cli/src/package_cmd.rs` returns 1).
2. `validate_relative_path` is added (`grep -c 'fn validate_relative_path' crates/nono-cli/src/package_cmd.rs` returns 1).
3. `validate_relative_path` is called BEFORE `validate_path_within` at line 691 (compare line numbers in `grep -n` output).

If upstream's commit DROPS `validate_path_within` (i.e., the cherry-pick deletes it OR replaces the line-691 callsite with `validate_relative_path` only), this is the security regression Plan 22-03 documented as Deviation #1. Restore `validate_path_within` immediately:
- Re-insert the function definition at line 1035 (recover from `git show HEAD~1:crates/nono-cli/src/package_cmd.rs` if needed).
- Re-insert the `validate_path_within(staging_root, &store_path)?;` callsite at line 691.
- Document the divergence in the commit message: "fork retains validate_path_within as defense-in-depth per REQ-PKGS-02 acceptance #2 + CLAUDE.md § Path Handling."

If `git cherry-pick 58b5a24e` produces conflicts that breach D-02 thresholds (more than 3 conflict hunks per file, OR conflicts in functions other than the path-validation surface), abort the cherry-pick (`git cherry-pick --abort`) and pivot to D-20 manual replay:
- `git show 58b5a24e -- '**/package_cmd.rs' > /tmp/58b5a24e.patch` to capture upstream's exact body.
- Manually port `validate_relative_path` definition + callsites by reading the patch and writing the function body inline.
- Preserve fork's `validate_path_within` unconditionally (it's the defense-in-depth layer).
- Commit with `Upstream-commit: 58b5a24e` trailer recording the manual-replay path.

NonoError variant: `validate_relative_path` returns `Err(NonoError::PackageInstall(String))` (or whichever variant the existing `validate_path_within` already uses for traversal rejection — read `crates/nono-cli/src/package_cmd.rs:1035-1080` once to confirm). Document the chosen variant in the commit message body.

Commit shape (D-19 trailers):
```
fix(pkg): port validate_relative_path defense-in-depth pre-check (REQ-PKGS-02)

Closes 22-03 Deviation #1 backlog. Adds upstream's input-string pre-check
(rejects `..` Path components + absolute paths + Windows drive prefixes
BEFORE any filesystem syscall) as a CHEAP-REJECTION layer alongside the
existing canonicalize-and-component-compare validate_path_within
(line ~1035; UNCHANGED).

Defense-in-depth posture: both validators fire on every artifact path
used in install_dir placement. Input-string check first (cheap rejection
of obviously-bad shapes); canonicalize check second (definitive answer
post-symlink-resolution).

Maps to REQ-PKGS-02 acceptance criteria:
1. Pack manifest with `..` traversal rejected by input-string pre-check
   before any filesystem syscall — covered.
2. Pack manifest with symlink-traversal still rejected by
   canonicalize-and-compare layer — covered (validate_path_within
   preserved verbatim).
3. Existing fork regression tests for validate_path_within still pass —
   covered (no test deletion, no #[ignore]).

Upstream-commit: 58b5a24e
Upstream-author: ...
Signed-off-by: ...
```

If D-20 manual replay is required, additionally include `Upstream-replay: manual` and a one-paragraph explanation of the conflict shape that forced the pivot.
  </action>
  <verify>
    <automated>cd /c/Users/OMack/nono &amp;&amp; git log -1 --format=%B | grep -q "REQ-PKGS-02" &amp;&amp; cargo build -p nono-cli</automated>
  </verify>
  <done>
- `git log -1 --pretty=format:'%B'` shows the commit message with `Upstream-commit: 58b5a24e` trailer (or `Upstream-commit: 58b5a24e` + `Upstream-replay: manual` if D-20 path was taken).
- `grep -n 'fn validate_relative_path' crates/nono-cli/src/package_cmd.rs` returns exactly 1 match.
- `grep -n 'fn validate_path_within' crates/nono-cli/src/package_cmd.rs` returns exactly 1 match (UNCHANGED — defense-in-depth preserved).
- `cargo build -p nono-cli` exits 0.
- `git diff --stat HEAD~1 HEAD -- crates/nono/` returns empty (D-19 byte-identical preservation; the cherry-pick must not touch the core library).
  </done>
</task>

<task type="auto">
  <name>Task 2: Add `ArtifactType::Plugin` enum variant in `crates/nono-cli/src/package.rs`</name>
  <files>crates/nono-cli/src/package.rs</files>
  <action>
Add the `Plugin` variant to the `ArtifactType` enum at `crates/nono-cli/src/package.rs:87`. Place it AFTER `Script` (the current 6th variant), making `Plugin` the 7th variant. NO per-variant `#[serde(rename = ...)]` is needed — the existing `#[serde(rename_all = "snake_case")]` attribute on the enum at line 86 handles the JSON shape automatically (`Plugin` -> `"plugin"`).

EXACT EDIT (one-line addition):

Before:
```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    Profile,
    Hook,
    Instruction,
    TrustPolicy,
    Groups,
    Script,
}
```

After:
```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    Profile,
    Hook,
    Instruction,
    TrustPolicy,
    Groups,
    Script,
    Plugin,
}
```

DO NOT touch the rename_all attribute. DO NOT add a doc comment unless upstream's variant body has one (read `git show <upstream-commit-introducing-Plugin>:**/package.rs` if cherry-picking) — keep the variant addition minimal.

After this single-line addition, `cargo build -p nono-cli` will FAIL with non-exhaustive match errors at every `match artifact.artifact_type` site that does not have a Plugin arm. The primary site is the big match block at `package_cmd.rs:614`. DO NOT FIX the build errors here — Task 3 plumbs the Plugin arms through `package_cmd.rs`. This task's commit can leave the workspace in a non-compiling state (it's an atomic-commit-pair with Task 3); the verification gate at Task 6 enforces final clean build.

If upstream's commit that introduces `Plugin` is identifiable (e.g., the commit that added `Plugin` to upstream's `package.rs` between fork's `869349df` baseline and upstream tip), include `Upstream-commit: <sha>` trailer. Otherwise commit as a fork-original variant addition with rationale referencing 22-03's deferred-divergence comment.

Commit shape:
```
feat(pkg): add ArtifactType::Plugin enum variant (REQ-PKGS-03)

Closes 22-03 Deviation #2 prerequisite. The deferred-divergence comment
at crates/nono-cli/src/package_cmd.rs:671-688 has been waiting for this
variant since v2.2 commit 73e1e3b8. Adding Plugin as the 7th variant
(after Script, the current 6th) using the existing
#[serde(rename_all = "snake_case")] attribute for the JSON shape.

Note: Task 3 (this commit's atomic pair) plumbs ArtifactType::Plugin
match arms through every consumer site in package_cmd.rs. Until Task 3
lands, cargo build -p nono-cli will fail with non-exhaustive match
errors — this is expected and gated by Task 6's verification.

Upstream-commit: <sha or "fork-original — see commit body">
Signed-off-by: ...
```
  </action>
  <verify>
    <automated>grep -c "    Plugin," C:/Users/OMack/nono/crates/nono-cli/src/package.rs</automated>
  </verify>
  <done>
- `grep -c '    Plugin,' crates/nono-cli/src/package.rs` returns at least 1 (the new variant).
- `grep -c 'pub enum ArtifactType' crates/nono-cli/src/package.rs` returns exactly 1 (no duplicate enum).
- `git log -1 --pretty=format:'%B'` shows the commit message referencing REQ-PKGS-03 and 22-03 Deviation #2 prerequisite.
- `git diff --stat HEAD~1 HEAD -- crates/nono/` returns empty (D-19 preservation).
- `cargo build -p nono-cli` is permitted to fail at this step (non-exhaustive match errors are expected; Task 3 fixes them).
  </done>
</task>

<task type="auto">
  <name>Task 3: Plumb `ArtifactType::Plugin` match arms in `package_cmd.rs` and remove the deferred-divergence comment</name>
  <files>crates/nono-cli/src/package_cmd.rs</files>
  <action>
Run `cargo build -p nono-cli` to surface the non-exhaustive match error list. Each error is a match site that needs an `ArtifactType::Plugin` arm. The build must be clean after this task.

PRIMARY SITE — the big match block at `package_cmd.rs:614-683`:

Add a new `ArtifactType::Plugin` arm AFTER the `ArtifactType::Script` arm at line 664-670, BEFORE the closing `};` at line 683. The arm body mirrors the `Script` arm with `"plugins"` substituted for `"scripts"`:

```rust
ArtifactType::Plugin => {
    // REQ-PKGS-03: place under staging_root/plugins/<file_name>.
    // No special handling beyond staging-path placement; the existing
    // post-match validate_path_within(staging_root, &store_path)?;
    // at ~line 691 covers this arm by virtue of being post-match.
    let path = staging_root
        .join("plugins")
        .join(file_name(&artifact.path)?);
    write_bytes(&path, bytes)?;
    path
}
```

DO NOT call `ensure_executable(&path)?` — Plugin artifacts are not assumed executable (Script arm calls it; Plugin does not). If upstream's commit that added the Plugin arm calls a different helper (e.g., `validate_groups` for Groups, `ensure_executable` for Hook/Script), inspect upstream's body via `git show <upstream-Plugin-arm-introduction-commit>` and port verbatim. If upstream's body is just the bare `staging_root.join("plugins").join(...).write_bytes(...).path` shape shown above, that's the deliverable.

SECONDARY SITES (the build will tell you which need arms):

Inspect each non-exhaustive-match error from `cargo build`. The expected NON-issues (these will NOT need explicit Plugin arms):
- `package_cmd.rs:154` — `if artifact.artifact_type != ArtifactType::Hook { ... }` is a boolean comparison, not a match.
- `package_cmd.rs:568` — `&& artifact.artifact_type == ArtifactType::Instruction` is boolean, not a match.
- `package_cmd.rs:707` — `Ok(if artifact.artifact_type == ArtifactType::Profile { ... }` is boolean, not a match.
- `package_cmd.rs:724` — `matches!(artifact.artifact_type, ArtifactType::Hook | ArtifactType::Script)` is exhaustive-friendly; Plugin falls through to else.
- `package_cmd.rs:754` — `if artifact.artifact_type != ArtifactType::Profile { ... }` is boolean.

If the build flags any OF THE ABOVE as needing a Plugin arm, the surrounding code uses an exhaustive `match` rather than the boolean shape this plan expected — in that case, add an arm that mirrors the closest semantic neighbor (e.g., for the line-754 site, mirror Profile's branch shape).

If the build flags additional sites not listed above, this is the call-site cascade Risk #2 warned about. Add arms iteratively. Build-clean is the completeness signal.

DELETE THE DEFERRED-DIVERGENCE COMMENT BLOCK at lines 671-688:

```
// NOTE: upstream ec49a7af also adds an ArtifactType::Plugin arm here.
// Fork's ArtifactType enum does not yet have Plugin (introduced by a
// later upstream commit not in Plan 22-03's cherry-pick chain). When
// that variant lands, restore upstream's Plugin arm verbatim:
//
//     ArtifactType::Plugin => {
//         if artifact.path.contains("..") { return Err(...) }
//         let path = staging_root.join(&artifact.path);
//         write_bytes(&path, bytes)?;
//         validate_path_within(staging_root, &path)?;
//         ...
//     }
```

These 18 lines become OBSOLETE once the live Plugin arm replaces them. Delete the comment block in the same commit as the live arm addition. The grep verification truth #10 enforces zero matches for the comment text.

NB: the commented-out `validate_path_within(staging_root, &path)?` call at line 680 (inside the comment) is NOT a real callsite — it's part of the comment text. Deleting the block removes it. The LIVE `validate_path_within(staging_root, &store_path)?;` at line 691 is the surviving callsite (post-match) and stays UNCHANGED.

If `bundle_json` field on `DownloadedArtifact` (struct at line 372) was identified as a fork-architectural addition during plan-time investigation: it is CONFIRMED OUT OF SCOPE for this plan (it is a local variable at line 425, not a struct field; field addition is coupled to streaming refactor — see Plan 26-02 / REQ-PKGS-01). Document this finding in this task's commit message as: "bundle_json field deferred to Plan 26-02 (REQ-PKGS-01 streaming refactor) — current state is a local var at line 425, not a struct field; field-shape addition is coupled to upstream 9ebad89a's bytes->PathBuf flow."

Commit shape:
```
feat(pkg): plumb ArtifactType::Plugin match arms (REQ-PKGS-03)

Atomic pair with the previous commit (Task 2 enum variant addition).
Adds ArtifactType::Plugin arm to the primary match block at
package_cmd.rs:614 (placement: staging_root/plugins/<file_name>) and to
any secondary match sites the compiler flagged as non-exhaustive.

Removes the deferred-divergence comment block at lines 671-688 (the v2.2
Plan 22-03 placeholder waiting for this variant since commit 73e1e3b8).

Note: bundle_json field on DownloadedArtifact remains out of scope for
Phase 26 Plan 01. It is currently a local variable at package_cmd.rs:425,
not a struct field. Adding it as a struct field is coupled to the
streaming refactor (upstream 9ebad89a / REQ-PKGS-01 / Plan 26-02). No
change here.

Upstream-commit: <sha if cherry-picked, fork-original otherwise>
Signed-off-by: ...
```
  </action>
  <verify>
    <automated>cd /c/Users/OMack/nono &amp;&amp; cargo build -p nono-cli</automated>
  </verify>
  <done>
- `cargo build -p nono-cli` exits 0 (workspace compiles clean; Plugin variant fully plumbed).
- `grep -c 'ArtifactType::Plugin' crates/nono-cli/src/package_cmd.rs` returns at least 1 (new arm in the big match block at line 614).
- `grep -c 'upstream ec49a7af also adds an ArtifactType::Plugin' crates/nono-cli/src/package_cmd.rs` returns 0 (deferred-divergence comment removed).
- `grep -A 5 'ArtifactType::Plugin' crates/nono-cli/src/package_cmd.rs | head -10` shows a real arm body with `staging_root.join("plugins").join(file_name(&artifact.path)?)` and `write_bytes(...)`, NOT comment markers.
- `git log -1 --pretty=format:'%B'` references REQ-PKGS-03, the deferred-divergence-comment removal, AND the bundle_json out-of-scope note.
- `git diff --stat HEAD~1 HEAD -- crates/nono/` returns empty (D-19 preservation).
  </done>
</task>

<task type="auto">
  <name>Task 4: Add 4 unit tests covering REQ-PKGS-02 + REQ-PKGS-03 acceptance</name>
  <files>crates/nono-cli/src/package_cmd.rs, crates/nono-cli/src/package.rs</files>
  <action>
Add 4 unit tests in the existing `mod tests` block at the bottom of `crates/nono-cli/src/package_cmd.rs` (or `crates/nono-cli/src/package.rs` for the `ArtifactType` round-trip tests, depending on which file's existing test module is the better fit). If neither file has a `#[cfg(test)] mod tests` block, add one to `package_cmd.rs` (the larger file with more existing infrastructure).

REQ-PKGS-02 tests (placed in `package_cmd.rs::mod tests`):

```rust
#[test]
fn validate_relative_path_rejects_traversal() {
    // Truth #5: Pack manifest with `..` traversal in `path` field is
    // rejected by validate_relative_path at the input-string layer
    // BEFORE any filesystem syscall.
    assert!(validate_relative_path("foo/../etc/passwd").is_err());
    assert!(validate_relative_path("../sneaky").is_err());
    assert!(validate_relative_path("a/b/../../../etc/passwd").is_err());
    // Mid-token `..` is fine (not a Path component); these must NOT reject:
    assert!(validate_relative_path("foo..bar").is_ok());
    assert!(validate_relative_path("file.bak").is_ok());
}

#[test]
fn validate_relative_path_rejects_absolute_path() {
    // Truth #6: Absolute paths (Unix and Windows drive prefix) rejected.
    // Cross-platform — both shapes must reject regardless of host OS,
    // since the package registry is cross-platform.
    assert!(validate_relative_path("/foo/bar").is_err());
    assert!(validate_relative_path("/etc/passwd").is_err());
    assert!(validate_relative_path("C:\\foo\\bar").is_err());
    assert!(validate_relative_path("D:\\Users\\evil").is_err());
    // Backslash leading-slash on Windows (UNC-style):
    assert!(validate_relative_path("\\\\server\\share").is_err());
    // Relative paths are fine:
    assert!(validate_relative_path("plugins/widget.so").is_ok());
    assert!(validate_relative_path("hooks/post-install.sh").is_ok());
}
```

REQ-PKGS-03 tests (placed in either `package.rs::mod tests` or `package_cmd.rs::mod tests` — wherever the existing `ArtifactType` test infrastructure lives; if no existing tests, add to `package.rs` since the enum lives there):

```rust
#[test]
fn artifact_type_plugin_round_trips() {
    // Truth #8: ArtifactType::Plugin serializes as "plugin" (lowercase)
    // and round-trips. The #[serde(rename_all = "snake_case")] attribute
    // handles the shape automatically.
    let json = serde_json::to_string(&ArtifactType::Plugin).expect("serialize");
    assert_eq!(json, "\"plugin\"");
    let parsed: ArtifactType =
        serde_json::from_str("\"plugin\"").expect("deserialize");
    assert_eq!(parsed, ArtifactType::Plugin);
}

#[test]
fn artifact_type_unknown_fails_closed() {
    // Truth #9: Unknown artifact_type values fail-closed. Schema-rejection
    // on the JSON deserializer (NOT the filename-based fallback at
    // package_cmd.rs:967-972, which is a different code path operating
    // on filenames not on user-supplied JSON).
    let bad: Result<ArtifactType, _> = serde_json::from_str("\"made_up_variant\"");
    assert!(bad.is_err());
    let bad2: Result<ArtifactType, _> = serde_json::from_str("\"PLUGIN\"");
    assert!(bad2.is_err()); // case-sensitive — uppercase is not "plugin"
    let bad3: Result<ArtifactType, _> = serde_json::from_str("42");
    assert!(bad3.is_err()); // non-string fails
}
```

CLAUDE.md compliance:
- DO NOT use `.unwrap()` or `.expect("...")` outside of test code. The above are test-only — `.expect("...")` is permitted in `#[test]` per project policy (the `#[allow(clippy::unwrap_used)]` exception applies to test modules per CLAUDE.md § Code Style "Exceptions").
- If the existing `mod tests` block is gated by `#[cfg(test)]`, the new tests inherit that gate. If the new tests need `use` imports (e.g., `use super::*;` to bring `ArtifactType` and `validate_relative_path` into scope), confirm the test module's existing `use` line and extend.

Commit shape:
```
test(pkg): cover REQ-PKGS-02 + REQ-PKGS-03 acceptance via 4 unit tests

REQ-PKGS-02 (validate_relative_path):
- validate_relative_path_rejects_traversal: `..` Path-component rejection
- validate_relative_path_rejects_absolute_path: Unix/Windows absolute rejection

REQ-PKGS-03 (ArtifactType::Plugin):
- artifact_type_plugin_round_trips: JSON `"plugin"` serde round-trip
- artifact_type_unknown_fails_closed: unknown variant fails-closed

Maps to plan must_haves truths #5, #6, #8, #9.

Signed-off-by: ...
```
  </action>
  <verify>
    <automated>cd /c/Users/OMack/nono &amp;&amp; cargo test -p nono-cli --lib -- validate_relative_path_rejects_traversal validate_relative_path_rejects_absolute_path artifact_type_plugin_round_trips artifact_type_unknown_fails_closed</automated>
  </verify>
  <done>
- All 4 new unit tests pass: `validate_relative_path_rejects_traversal`, `validate_relative_path_rejects_absolute_path`, `artifact_type_plugin_round_trips`, `artifact_type_unknown_fails_closed`.
- `cargo test -p nono-cli --lib` exits 0; the existing test baseline (~150+ unit tests) holds with no regressions.
- `git diff --stat HEAD~1 HEAD -- crates/nono/` returns empty (D-19 preservation).
- `git log -1 --pretty=format:'%B'` references all 4 truth IDs (#5, #6, #8, #9).
  </done>
</task>

<task type="auto">
  <name>Task 5: Verify regression coverage for `validate_path_within` symlink-traversal layer</name>
  <files>crates/nono-cli/src/package_cmd.rs</files>
  <action>
Run the existing fork regression tests for `validate_path_within` to confirm REQ-PKGS-02 acceptance #2 + truth #7 (defense-in-depth posture survives this plan unchanged):

```
cargo test -p nono-cli --lib -- validate_path_within
cargo test -p nono-cli --lib -- path_within
cargo test -p nono-cli --lib -- traversal
cargo test -p nono-cli --lib -- symlink
```

Capture the test names that fire AND the count. Expected: at least 1 test exists from v2.2 commit `869349df` exercising `validate_path_within` with a path that escapes `staging_root` (via `..`, via symlink, or via UNC alias). All such tests MUST pass without modification.

If NO regression tests exist for `validate_path_within` (the v2.2 hardening landed without explicit tests), this is a NEW-test gap and the plan must add at least 1:

```rust
#[test]
fn validate_path_within_rejects_symlink_escape() {
    // Truth #7: Defense-in-depth — symlink-traversal where the input
    // string is innocuous but resolves through a symlink to outside
    // staging_root is still rejected by validate_path_within
    // (canonicalize-and-component-compare layer; runs AFTER the
    // bytes are written, on the resolved path).
    let staging = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside");
    let staging_root = staging.path();
    let outside_target = outside.path();

    // Create a symlink inside staging_root pointing to a path outside.
    let symlink_in_staging = staging_root.join("escape");
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside_target, &symlink_in_staging)
        .expect("create symlink");
    #[cfg(windows)]
    {
        // On Windows, symlink creation requires elevated privilege
        // OR developer mode; gate the test or use junction.
        if std::os::windows::fs::symlink_dir(outside_target, &symlink_in_staging)
            .is_err()
        {
            eprintln!("skipping symlink test — Windows symlink privilege missing");
            return;
        }
    }

    // The symlink target (post-resolution) must reject:
    let escape_attempt = symlink_in_staging.join("evil.bin");
    assert!(validate_path_within(staging_root, &escape_attempt).is_err());
}
```

NB: Windows symlink creation requires privilege; if the test cannot create a symlink, gate via early-return (do NOT use `#[ignore]` — a skipped test is acceptable on a privilege-missing host; an ignored test is technical debt).

If the existing v2.2 test suite already covers this (likely — v2.2 SUMMARY § Threat surface T-22-03-01 documents the mitigation as tested), this task is a NO-OP verification gate and produces no commit. In that case, skip Task 5's commit and move to Task 6.

If a new test was added, commit shape:
```
test(pkg): regression-cover validate_path_within symlink-traversal layer (REQ-PKGS-02)

Adds validate_path_within_rejects_symlink_escape covering truth #7
(defense-in-depth canonicalize-and-component-compare layer survives this
plan unchanged; symlink-traversal where input string is innocuous but
resolves outside staging_root is still rejected post-symlink-resolution).

Test gates Windows symlink-creation privilege via early-return (not
#[ignore]).

Signed-off-by: ...
```
  </action>
  <verify>
    <automated>cd /c/Users/OMack/nono &amp;&amp; cargo test -p nono-cli --lib -- validate_path_within</automated>
  </verify>
  <done>
- The `cargo test -p nono-cli --lib -- validate_path_within` invocation finds at least 1 passing test (the existing v2.2 regression OR the new test added by this task).
- All such tests pass without modification.
- If a new test was added, the commit message references REQ-PKGS-02 acceptance #2 + truth #7.
- If no new test was needed, this task produces NO commit (verification only).
- `git diff --stat HEAD~1 HEAD -- crates/nono/` returns empty (D-19 preservation; only relevant if a commit was made).
  </done>
</task>

<task type="auto">
  <name>Task 6: Verification gate — build + test + clippy + fmt + D-19 preservation (no commit)</name>
  <files></files>
  <action>
Final verification gate. NO commit produced; this task validates the entire plan's deliverable.

Run each gate in order; STOP on first failure and surface the cause to the operator.

GATE 1 — Build clean:
```
cargo build --workspace
```
Exit 0 expected. If the build fails, the most likely cause is a missing `ArtifactType::Plugin` arm at a match site Task 3 missed. Re-run `cargo build` and add arms iteratively until clean.

GATE 2 — Test clean (workspace-wide; if too slow, scope to nono-cli):
```
cargo test --workspace
```
OR:
```
cargo test -p nono-cli --bin nono
cargo test -p nono-cli --lib
```

Expected: 651-passing baseline (per Plan 22-03 SUMMARY § Verification) + 4 new tests from Task 4 + (optionally) 1 new test from Task 5 = ~656 passing. Pre-existing 2 TUF failures from `869349df` baseline (TUF root signature freshness + verify_bundle_with_invalid_digest) MAY persist — if they do, document the carry-over disposition matching Plan 22-03 § Out-of-scope #5. They MUST NOT be NEW failures introduced by this plan.

GATE 3 — Clippy clean:
```
cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used
```

Expected: clean modulo the 2 pre-existing `nono::manifest` `collapsible_match` errors at `crates/nono/src/manifest.rs:95` and `:103` (per Plan 22-03 SUMMARY § Verification — pre-existing on `869349df` baseline). These are out of scope for this plan; document the carry-over in the verification log (NOT a commit; just operator-facing surfacing).

GATE 4 — Format clean:
```
cargo fmt --all -- --check
```
Exit 0 expected.

GATE 5 — D-19 byte-identical preservation:
```
git diff --stat <baseline-sha>..HEAD -- crates/nono/ | wc -l
```

Where `<baseline-sha>` is the commit SHA before this plan's first commit (Task 1's `git rev-parse HEAD~N` where N = number of commits this plan made — typically 4 or 5: Task 1 + Task 2 + Task 3 + Task 4 + (optionally) Task 5).

Expected: output `0` (no lines = no files changed in `crates/nono/`). If non-zero, the plan touched the core library and that's a D-19 violation — revert the offending commits and surface to operator.

GATE 6 — Plan must_haves grep verification:
Run each `grep` from the must_haves.truths section and confirm the documented match counts:
- `grep -c 'fn validate_relative_path' crates/nono-cli/src/package_cmd.rs` returns 1.
- `grep -c 'fn validate_path_within' crates/nono-cli/src/package_cmd.rs` returns 1.
- `grep -c '    Plugin,' crates/nono-cli/src/package.rs` returns at least 1.
- `grep -c 'ArtifactType::Plugin' crates/nono-cli/src/package_cmd.rs` returns at least 1.
- `grep -c 'upstream ec49a7af also adds an ArtifactType::Plugin' crates/nono-cli/src/package_cmd.rs` returns 0.

Surface the verification results to the operator as a structured report.

NO COMMIT FROM THIS TASK. The plan's git-log delta is exactly the commits from Tasks 1, 2, 3, 4 (and optionally Task 5 if a new test was added).
  </action>
  <verify>
    <automated>cd /c/Users/OMack/nono &amp;&amp; cargo build --workspace &amp;&amp; cargo test --workspace --lib 2&gt;&amp;1 | tail -5 &amp;&amp; cargo fmt --all -- --check</automated>
  </verify>
  <done>
- `cargo build --workspace` exits 0.
- `cargo test --workspace` (or scoped `-p nono-cli`) exits 0 modulo documented pre-existing 2 TUF failures.
- `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` exits 0 modulo documented pre-existing 2 `nono::manifest` errors.
- `cargo fmt --all -- --check` exits 0.
- `git diff --stat <baseline>..HEAD -- crates/nono/ | wc -l` returns `0` (D-19 byte-identical preservation).
- All 5 must_haves grep verifications return the expected counts.
- Operator receives a structured verification report listing each gate's pass/fail status.
  </done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| package registry / pack manifest --> package_cmd.rs artifact-write path | untrusted JSON manifest data crosses this boundary; `artifact.path` is attacker-controlled (the registry could publish a malicious manifest); the validation surface (`validate_relative_path` + `validate_path_within`) is the only barrier between the JSON `path` field and the local filesystem write |
| filesystem (post-canonicalize) --> install_dir placement | even after path-string validation, the staging_root + install_dir paths can resolve through symlinks; `validate_path_within` is the post-resolution check |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-26-01-01 | Tampering | manifest `artifact.path` field with `..` traversal (e.g., `foo/../../../etc/passwd`) | mitigate | `validate_relative_path` rejects `..` Path components at the input-string layer BEFORE any filesystem syscall (Task 1 deliverable). Defense-in-depth: even if validate_relative_path missed this shape, `validate_path_within` rejects post-canonicalization (Task 1 preserves it). |
| T-26-01-02 | Tampering | manifest `artifact.path` field with absolute path (`/etc/passwd`, `C:\Windows\System32`) | mitigate | `validate_relative_path` rejects absolute paths at input-string layer (Task 1). Tested by `validate_relative_path_rejects_absolute_path` (Task 4 truth #6). |
| T-26-01-03 | Tampering | manifest `artifact.path` field with symlink-traversal (innocuous string resolves through symlink to outside `staging_root`) | mitigate | `validate_path_within` (line 1035) canonicalizes and component-compares; defeats symlink-traversal. Preserved verbatim by Task 1 (truth #2 + truth #7). Existing v2.2 regression tests cover this layer (Task 5 verification gate). |
| T-26-01-04 | Tampering | manifest `artifact_type` field with unknown variant string (attempting to bypass type-discrimination by setting `artifact_type: "made_up"`) | mitigate | serde deserializer fails-closed on unknown variants (the `#[serde(rename_all = "snake_case")]` enum does NOT silently coerce). Tested by `artifact_type_unknown_fails_closed` (Task 4 truth #9). |
| T-26-01-05 | Tampering | manifest `artifact.path` for new `Plugin` artifact_type containing `..` traversal (the new arm at line 671-688 must inherit the same path-validation surface as the other 6 arms) | mitigate | The `Plugin` arm constructs `staging_root.join("plugins").join(file_name(&artifact.path)?)`. The `file_name` helper (existing fork helper used by Script arm) extracts only the basename, defeating in-string `..`. The post-match `validate_path_within(staging_root, &store_path)?;` at line 691 fires on the Plugin-produced `store_path` by virtue of being post-match (truth #4 + key_link #3). |
| T-26-01-06 | Information Disclosure | accidental introduction of dead-code (the deferred-divergence comment block at lines 671-688 referenced an attacker-controlled-component pattern via `staging_root.join(&artifact.path)` — if the live arm copied that pattern verbatim, it would be a regression vs. the `file_name` helper used by Script) | mitigate | Task 3 explicitly mirrors the Script arm shape (`staging_root.join("plugins").join(file_name(&artifact.path)?)`), NOT the comment's example shape. The example in the comment was illustrative; the live arm uses the safer pattern. Documented in the action prose. |
| T-26-01-07 | Repudiation | absence of D-19 trailers on cherry-picked commits (auditability of upstream provenance) | mitigate | Task 1 + Task 2 + Task 3 commit shapes include `Upstream-commit:` trailers (or `Upstream-commit: ... Upstream-replay: manual` pair if D-20 path was taken). All commits include `Signed-off-by:` per CLAUDE.md § Coding Standards. |
| T-26-01-08 | Elevation of Privilege | core library (`crates/nono/`) modification slipping in via cherry-pick widening the surface beyond `nono-cli` | mitigate | Task 6 GATE 5 enforces D-19 byte-identical preservation: `git diff --stat <baseline>..HEAD -- crates/nono/ | wc -l` MUST return 0. Plan-time investigation confirmed no `crates/nono/` files in `files_modified`. |
</threat_model>

<verification>
Phase-level checks (run after Task 6's verification gate completes):

1. **Source artifact coverage:** Both REQ-PKGS-02 and REQ-PKGS-03 have at least 1 task implementing them, and at least 1 unit test covering each acceptance criterion. Verified by truth count: 12 truths, 4 of which are grep-verifiable assertions about the new test names + at least 8 of which are grep-verifiable assertions about file structure.

2. **D-19 preservation (core library byte-identical):** `git diff --stat <baseline>..HEAD -- crates/nono/ | wc -l` returns `0`. Enforced by Task 6 GATE 5.

3. **D-02 conflict thresholds (cherry-pick path):** If Task 1 took the cherry-pick path, conflict count was within thresholds (per Task 1 action). If D-20 manual replay path was taken, the `Upstream-replay: manual` trailer is present on the commit.

4. **No regression on baseline tests:** The 651-passing baseline from Plan 22-03 holds. The 2 pre-existing TUF failures + 2 pre-existing `nono::manifest` clippy errors persist as documented carry-over (NOT new failures from this plan).

5. **No `#[ignore]` added:** This plan does NOT add any `#[ignore]` attributes. If Task 5's symlink test couldn't run on Windows due to privilege, it uses early-return, NOT `#[ignore]`.

6. **22-03 deferred-divergence comment removed:** `grep -c 'upstream ec49a7af also adds an ArtifactType::Plugin' crates/nono-cli/src/package_cmd.rs` returns 0.

7. **Plan 26-02 unblocked:** This plan delivers BOTH dependencies that 22-03 SUMMARY § Critical Deviation #2 enumerated as blockers for `9ebad89a` (streaming refactor): `ArtifactType::Plugin` enum variant + `validate_relative_path` helper. Plan 26-02 can now cherry-pick `9ebad89a` against a chain that matches upstream's expected dependency shape.
</verification>

<success_criteria>
This plan succeeds when:

- [ ] REQ-PKGS-02 closed: `validate_relative_path` ported from upstream `58b5a24e` (or D-20 manual replay) as defense-in-depth pre-check; `validate_path_within` preserved verbatim at line 1035 (defense-in-depth posture from v2.2 commit `869349df`).
- [ ] REQ-PKGS-03 closed: `ArtifactType::Plugin` variant added as the 7th variant in `crates/nono-cli/src/package.rs`; match arms plumbed through every consumer site in `package_cmd.rs` (build-clean is the completeness signal); deferred-divergence comment at lines 671-688 removed.
- [ ] 4 new unit tests pass: `validate_relative_path_rejects_traversal`, `validate_relative_path_rejects_absolute_path`, `artifact_type_plugin_round_trips`, `artifact_type_unknown_fails_closed`.
- [ ] `make ci` passes on Windows host: `cargo build --workspace` + `cargo test --workspace` + `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` + `cargo fmt --all -- --check` all clean (modulo documented pre-existing 2 TUF failures + 2 `nono::manifest` clippy errors).
- [ ] D-19 byte-identical preservation: `git diff --stat <baseline>..HEAD -- crates/nono/ | wc -l` returns `0`.
- [ ] All commits include `Signed-off-by:` (DCO) trailer; cherry-picked commits include `Upstream-commit: <sha>` trailer.
- [ ] Plan 26-02 (REQ-PKGS-01 + REQ-PKGS-04) is now unblocked — both `ArtifactType::Plugin` and `validate_relative_path` are in fork.
</success_criteria>

<risks>
## Top 3 Risks

### Risk 1 — Cherry-pick `58b5a24e` may conflict with fork divergence in `package_cmd.rs`
Phase 22 Plan 22-03 already touched this file extensively (1089 LOC added per 22-03 SUMMARY § Files changed); the file has fork-only adaptations beyond upstream (commit `869349df` "harden package installation security" added `validate_path_within(staging_root, &store_path)?;` after every artifact-write arm — fork-original code, not upstream). When upstream `58b5a24e` lands, the cherry-pick may produce conflicts in either the function-definition site (where `validate_relative_path` is being added) OR at any callsite that overlaps fork's hardening.

**Mitigation:** D-20 manual-replay fallback per the standard fork pattern. If `git cherry-pick 58b5a24e` produces conflicts that breach D-02 thresholds (>3 conflict hunks per file, OR conflicts in functions other than the path-validation surface), abort the cherry-pick and port the `validate_relative_path` function manually with `Upstream-commit: 58b5a24e` + `Upstream-replay: manual` trailer pair. Task 1's action documents the exact pivot procedure.

### Risk 2 — `ArtifactType::Plugin` variant addition cascades to call sites this plan didn't anticipate
The known surface is the big match block at `package_cmd.rs:614` (6 existing arms). The boolean-comparison sites at lines 154/568/707/724/754 should NOT need explicit Plugin arms (they're `==`/`!=`/`matches!` shapes that fall through). But any `match artifact.artifact_type { ... }` exhaustive-style block elsewhere in the codebase becomes a compile error after Task 2 lands the variant. Plan 22-03 SUMMARY documents 7 sites total; an 8th could surface.

**Mitigation:** `cargo build --workspace` after Task 2 surfaces the cascade exhaustively; Task 3's action explicitly says "build-clean is the completeness signal" and instructs the executor to add Plugin arms iteratively until the build passes. The compiler is the source of truth for completeness — there is no risk of silently missing a site.

### Risk 3 — The deferred-divergence comment may not exist anymore (line numbers shifted)
The v2.3 REQUIREMENTS.md backlog mentioned the comment at `package_cmd.rs:631-643` (per REQ-PKGS-03 description). Plan-time investigation found it at lines 671-688 (lines shifted ~40 forward since v2.3 REQUIREMENTS was written). Both Plan 22-03 SUMMARY (lines 631-643) and v2.3 REQUIREMENTS.md cite the older shape; the current HEAD shape is 671-688.

**Mitigation:** Task 3's grep-based verification (`grep -c 'upstream ec49a7af also adds an ArtifactType::Plugin' crates/nono-cli/src/package_cmd.rs` returns 0 after the deletion) is line-number-agnostic — it asserts the comment text is gone regardless of where it lives. If a future commit shifts the lines further before this plan executes, the grep continues to find the comment by content, not by line number. If the comment was already removed by an earlier phase (the most pessimistic case), Task 3's deletion is a no-op edit and the plan's deliverable is just the `ArtifactType::Plugin` arm addition — Task 3's commit body documents that case ("commit body MAY say: 'comment block was already removed by an earlier phase; this commit only adds the live Plugin arm'").

## Lower-priority risks (mitigated by plan structure)

- **Cargo.lock churn** from cherry-pick: `58b5a24e` is a refactor with no new dependencies; Cargo.lock should not change. If it does, that signals the cherry-pick pulled in more than `validate_relative_path` (e.g., a downstream commit got chained); Task 1's action prose tells the executor to abort and pivot to manual replay.
- **`bundle_json` field surprise:** Plan-time investigation confirmed `bundle_json` is a local variable, not a struct field. If a future PR adds it as a struct field before this plan executes, Task 3's commit body update covers it; if it lands AFTER this plan, Plan 26-02 owns it. No plan-level action needed.
</risks>

<out_of_scope>
## Explicit Deferrals to Plan 26-02

- **REQ-PKGS-01 (streaming refactor):** Upstream `9ebad89a refactor(pkg): stream package artifact downloads`. Includes `bytes`-to-`PathBuf` refactor + `tempfile::TempDir` + size limits + HTTP timeouts on hyper client + `semver` dependency for version comparison. Largest commit in the deferred chain (~+267/-109 LOC across 5 files per 22-03 SUMMARY § Critical Deviation #2). Develop/test on Linux/macOS host preferred (streaming/registry test fixtures are easier there).
- **REQ-PKGS-04 (`load_registry_profile` auto-pull):** Upstream `115b5cfa feat(profile): load profiles from registry packs`. Auto-pulls registry pack when profile's `extends` chain references one and pack is absent locally. Coupled to streaming infrastructure.
- **`bundle_json` field on `DownloadedArtifact`:** Currently a local variable at `package_cmd.rs:425`, NOT a struct field. Plan-time investigation confirmed adding it as a struct field is meaningful only when the streaming refactor lands (`9ebad89a` introduces it as part of the `bytes`-to-`PathBuf` flow). Out of scope for this plan; Plan 26-02 owns it.
- **Full e2e integration tests via `run_nono` harness:** Those depend on the streaming infrastructure landing (the e2e tests need to actually pull a pack from a registry); deferred to Plan 26-02. This plan's verification is unit-test-driven (4 new unit tests + Task 5 regression-check on existing `validate_path_within` tests).
- **Pre-existing TUF root signature freshness + `verify_bundle_with_invalid_digest` failures:** Per Plan 22-03 SUMMARY § Out-of-scope #5, these are pre-existing on the `869349df` baseline and out of scope for any cherry-pick chain plan in v2.3.
- **Pre-existing `nono::manifest` `collapsible_match` clippy errors at `crates/nono/src/manifest.rs:95` and `:103`:** Per Plan 22-03 SUMMARY § Verification, pre-existing on `869349df` baseline; out of scope.
</out_of_scope>

<output>
After completion, create `.planning/phases/26-pkg-streaming-followup/26-01-PKGS-FORK-ARCH-SUMMARY.md` documenting:

1. **Outcome:** REQ-PKGS-02 + REQ-PKGS-03 closed; what was implemented vs deferred.
2. **What was done:** commit table (Task 1 cherry-pick or D-20 replay; Task 2 enum variant; Task 3 match arm plumbing + comment removal; Task 4 4 unit tests; Task 5 optional regression-test addition).
3. **Verification:** all 6 gates' pass/fail status (build, test, clippy, fmt, D-19 preservation, must_haves grep).
4. **Deviations from plan:** any Risk-1/2/3 paths that activated (cherry-pick conflicts forcing D-20 replay; unexpected match-site cascade; deferred-divergence comment already removed; etc.).
5. **Threat surface:** STRIDE register results (T-26-01-01..08) — which mitigations were tested vs. structurally enforced.
6. **Out-of-scope items confirmed:** `bundle_json` field deferral; streaming refactor + auto-pull deferred to Plan 26-02; pre-existing TUF + manifest carry-overs.
7. **Plan 26-02 unblocked:** `ArtifactType::Plugin` + `validate_relative_path` confirmed in fork; Plan 26-02 can now cherry-pick `9ebad89a` against the expected dependency chain.

Self-check: SUMMARY exists; all commits reachable from `main`; D-19 preservation verified by `git diff --stat <baseline>..HEAD -- crates/nono/`.
</output>
