# Phase 36: UPST3 deep closure - Pattern Map

**Mapped:** 2026-05-12
**Files analyzed:** 30 (across 6 plans)
**Analogs found:** 28 / 30 (2 files have no fork-side analog; planner uses upstream RESEARCH excerpts)

## Drift Notes (load-bearing corrections to upstream-cited surface)

Carried forward from RESEARCH.md and verified against current main:

1. **`policy_cmd.rs` does NOT exist in fork.** CONTEXT.md's source-file list at line 174 and deferred-items.md cite `policy_cmd.rs` from upstream. Fork merged this surface into `profile_cmd.rs` + `policy.rs`. Plan 36-01c rename targets 17 actual files, NOT 14.
2. **`clear_signal_forwarding_target` already exists** at `crates/nono-cli/src/exec_strategy.rs:1987` with 2 existing callsites (lines 825, 2047). Plan 36-03 Commit 2 task is "ADD a new pre-profile-save callsite", NOT "restore the helper."
3. **Callsite count is 183 callsites across 17 files** (verified raw-grep total ~196, some are doc-comment refs), NOT the 210 figure CONTEXT.md inherited from upstream.
4. **`cli.rs:2272` carries a pre-existing doc-comment typo** (`\ Timeout in seconds...` looks like a backslash literal; verified to actually read `/// Timeout in seconds (default: run until command exits)`). Grep finds the canonical `///` shape — the "typo" RESEARCH.md flagged was already cleaned up. Plan 36-03 should grep before assuming a fix is needed; if `\ ` appears on line 2272 at execution time, fix during `LearnArgs.trace` restoration.
5. **Fork `LearnArgs` (cli.rs:2263-2295) lacks `trace`** — verified. Restoration is additive; existing fields `profile`, `json`, `timeout`, `all`, `no_rdns`, `verbose`, `command`, `help` stay verbatim.
6. **`policy.json` already uses canonical `groups` top-level shape** (verified at policy.json:6). Still carries one `override_deny` callsite at line 695. Plan 36-01d data migration is a partial alignment — verify the 4 built-in profiles' `commands.{allow,deny}` and `filesystem.{deny,bypass_protection}` shapes against canonical.

## File Classification

### Plan 36-01a — deprecated_schema module foundation

| File | Role | Data Flow | Closest Analog | Match Quality |
|------|------|-----------|----------------|---------------|
| `crates/nono-cli/src/deprecated_schema.rs` (NEW ~824 LOC) | NEW module | serde-driven transform (legacy JSON → canonical) + process-state counter | `crates/nono-cli/src/package.rs` (fork-divergence preamble; same crate; sibling `_cmd.rs` integration) AND `crates/nono-cli/src/profile/mod.rs:1-183` (seed serde-alias + AtomicBool pattern) | hybrid (no single perfect analog; closest by shape × concern) |
| `crates/nono-cli/src/main.rs` | callsite-rename / mod registration | mod tree | existing `mod` lines at lines 5-95 | exact |
| `crates/nono-cli/src/cli.rs` (ProfileValidateArgs.strict) | struct field addition | clap-derive bool flag | existing `ProfileValidateArgs.json` flag at cli.rs:1305 | exact |
| `crates/nono-cli/src/profile_cmd.rs` (wire LegacyPolicyPatch) | helper-restoration / wiring | request-response (handler) | `crates/nono-cli/src/profile_cmd.rs::cmd_validate` at line 2142 (existing handler — extend, don't replace) | exact |

### Plan 36-01b — canonical Profile sections

| File | Role | Data Flow | Closest Analog | Match Quality |
|------|------|-----------|----------------|---------------|
| `crates/nono-cli/src/profile/mod.rs` (Profile/LoadedProfile + new GroupsConfig/CommandsConfig + FilesystemConfig extend) | struct refactor | serde load + From impl | `crates/nono-cli/src/profile/mod.rs::FilesystemConfig` at line 205, `PolicyPatchConfig` at line 398, `CapabilitiesConfig` at line 271 (3 existing sibling section structs — mirror shape) | exact (in-file precedent) |
| `crates/nono-cli/src/profile/builtin.rs` | data migration | embedded JSON build | existing `crates/nono-cli/src/profile/builtin.rs` (6 `override_deny` callsites per RESEARCH) | exact |
| `crates/nono/src/capability.rs::CapabilitySet` | VERIFY composes | builder pattern (downstream consumer) | self (read-only verification — must NOT modify library) | n/a |

### Plan 36-01c — 183-callsite rename `override_deny` → `bypass_protection` (atomic)

| File | Role | Data Flow | Callsites | Match Quality |
|------|------|-----------|-----------|---------------|
| `crates/nono-cli/src/profile/mod.rs` | callsite-rename | struct field rename + alias flip | 66 | exact |
| `crates/nono-cli/src/profile_save_runtime.rs` | callsite-rename | Profile patch builder | 23 | exact |
| `crates/nono-cli/src/capability_ext.rs` | callsite-rename | CapabilitySet construction | 23 | exact |
| `crates/nono-cli/src/cli.rs` | callsite-rename | clap arg field rename + alias flip | 14 | exact |
| `crates/nono-cli/src/profile_cmd.rs` | callsite-rename | profile handlers | 13 | exact |
| `crates/nono-cli/src/profile_runtime.rs` | callsite-rename | profile load runtime | 9 | exact |
| `crates/nono-cli/src/sandbox_state.rs` | callsite-rename | state serialization | 8 | exact |
| `crates/nono-cli/src/learn.rs` | callsite-rename | learn pipeline | 6 | exact |
| `crates/nono-cli/src/policy.rs` | callsite-rename | group resolver | 6 | exact |
| `crates/nono-cli/src/profile/builtin.rs` | callsite-rename | built-in profile data | 6 | exact |
| `crates/nono-cli/src/command_runtime.rs` | callsite-rename | command exec | 4 | exact |
| `crates/nono-cli/src/query_ext.rs` | callsite-rename | query handler | 4 | exact |
| `crates/nono-cli/src/sandbox_prepare.rs` | callsite-rename | sandbox prep | 4 | exact |
| `crates/nono-cli/src/execution_runtime.rs` | callsite-rename | exec runtime | 3 | exact |
| `crates/nono-cli/src/launch_runtime.rs` | callsite-rename | launch plan | 3 | exact |
| `crates/nono-cli/src/main.rs` | callsite-rename | entry point | 2 | exact |
| `crates/nono-cli/src/why_runtime.rs` | callsite-rename | why query | 2 | exact |
| `crates/nono-cli/data/policy.json` | data migration | JSON fixture | 1 | exact |
| `crates/nono-cli/tests/fixtures/*` + `crates/nono-cli/data/nono-profile.schema.json` | data migration | JSON fixtures | verify via `grep -rn "override_deny" --include="*.json"` | partial |

**Total verified Rust callsites:** 196 (raw grep; some are doc-comment refs that may or may not need rename — verify each).

### Plan 36-01d — data + docs + tooling

| File | Role | Data Flow | Closest Analog | Match Quality |
|------|------|-----------|----------------|---------------|
| `crates/nono-cli/data/policy.json` | data migration | JSON fixture | self (1029 LOC; already partial canonical) | exact |
| `crates/nono-cli/data/nono-profile.schema.json` | data migration | JSON Schema fixture | self (637 LOC) | exact |
| `scripts/test-list-aliases.sh` (NEW) | helper / build tooling | shell CLI tool | `scripts/check-upstream-drift.sh` (existing fork shell script — `set -euo pipefail` + `print_usage` + arg parsing) | role-match |
| `scripts/lint-docs.sh` (NEW) | helper / build tooling | shell CLI tool | same as above (`check-upstream-drift.sh`) | role-match |
| `scripts/regenerate-schema.sh` | VERIFY exists, Windows host | shell CLI tool | self | n/a |
| `docs/cli/features/profiles-groups.mdx` | doc | docs frontmatter + markdown | existing `docs/cli/features/profile-authoring.mdx` (sibling) + the file itself (already exists) | exact |
| `docs/cli/usage/flags.mdx` | doc | docs frontmatter + markdown | self (already exists) | exact |
| `crates/nono-cli/data/profile-authoring-guide.md` | doc / embedded | embedded markdown | already exists per grep | exact |
| `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md` | doc | append closure section | existing Phase 34 deferred-items.md | exact |

### Plan 36-02 — wiring.rs stripped-down port (yaml_merge only)

| File | Role | Data Flow | Closest Analog | Match Quality |
|------|------|-----------|----------------|---------------|
| `crates/nono-cli/src/wiring.rs` (NEW ~300-400 LOC) | NEW module | YAML parse → patch directive applier | `crates/nono-cli/src/package.rs:1-40` (closest shape: same crate, fork-divergence preamble citing absent upstream `wiring.rs`, sibling `_cmd.rs` integration pattern) | partial (no fork wiring.rs; package.rs documents WHY) |
| `crates/nono-cli/Cargo.toml` | data migration | dep pin | existing `sigstore-sign = "0.6.5"` at line 64 (exact-version pin precedent) | role-match (no `=`-exact pin in fork yet) |
| `crates/nono-cli/src/main.rs` | callsite-rename | mod registration | existing `mod` lines at 5-95 | exact |
| `crates/nono-cli/src/profile_cmd.rs` (wire yaml_merge into `--yaml` handler) | helper-restoration / wiring | request-response (handler) | `cmd_validate` at line 2142 (existing handler integration shape) | role-match (no existing `--yaml` handler — new surface) |

### Plan 36-03 — b5f0a3ab surgical + bbdf7b85

| File | Role | Data Flow | Closest Analog | Match Quality |
|------|------|-----------|----------------|---------------|
| `crates/nono/src/diagnostic.rs` (Commit 1: restore 4 helpers + wire + 1 test; Commit 3: body rewrite + 2 tests) | helper-restoration / body rewrite | request-response (analyze_error_output is the consumer at line 215) | existing helpers `extract_relative_write_path_from_line` at line 421 + `extract_denied_path_from_error_line` (siblings already in file) | exact |
| `crates/nono-cli/src/exec_strategy.rs` (Commit 2: ADD `should_offer_profile_save`, `POST_EXIT_PTY_DRAIN_TIMEOUT`, new callsite, startup-timeout machinery) | helper-restoration | sandbox exec policy | existing `clear_signal_forwarding_target` at line 1987 + existing `ExecConfig<'a>` at line 276 (DO NOT MODIFY struct, only ADD helpers + callsites) | exact |
| `crates/nono-cli/src/execution_runtime.rs` (Commit 2: 3 helpers + tests) | helper-restoration | exec policy + identity | existing `apply_pre_fork_sandbox` at line 11, `cleanup_capability_state_file` at line 34, `next_capability_state_file_path` at line 40 (sibling helper shape with `#[cfg(test)] mod tests` at line 465) | exact |
| `crates/nono-cli/src/cli.rs` (Commit 2: restore `LearnArgs.trace`; fix line 2272 typo if present) | struct field addition | clap-derive | existing `LearnArgs` at line 2263 — restored field is a sibling to `timeout`, `all`, `no_rdns` | exact |
| `crates/nono-cli/src/profile_save_runtime.rs`, `pty_proxy.rs`, `sandbox_log.rs`, `startup_prompt.rs` | helper-restoration (minor refinements) | existing surface | self | exact |

## Pattern Assignments

### `crates/nono-cli/src/deprecated_schema.rs` (NEW; Plan 36-01a)

**Analog 1:** `crates/nono-cli/src/package.rs` (same crate; fork-divergence-with-upstream-citation preamble pattern)
**Analog 2:** `crates/nono-cli/src/profile/mod.rs:1-183` (seed serde-alias + AtomicBool one-shot counter — extend, don't replace)
**Analog 3:** `crates/nono-cli/src/deprecated_policy.rs` (existing deprecation shim; different concern — keep separate per CONTEXT.md line 167)

**Header preamble pattern** (from `package.rs:1-33`):
```rust
//! Pack manifest, lockfile, and local store helpers.
//!
//! # Upstream registry-pack format awareness (v0.44.0, manual-replay of 24d8b924)
//!
//! In upstream nono v0.44.0 (commit `24d8b924`, "feat(profile, migration): move codex,
//! claude-code to registry pack"), the upstream project migrated [...] That commit also
//! introduced four upstream-only files implementing a `wiring` abstraction [...]
//!
//! The fork does NOT carry that structural rewrite. Per Phase 33's DIVERGENCE-LEDGER.md
//! cluster C6 "fork-preserve" disposition [...]
//!
//! Plan 34-09 (Manual-replay: 24d8b924) acknowledges upstream's registry-pack shape but
//! does NOT port the structural rewrite [...]
```
Plan 36-01a's `deprecated_schema.rs` preamble should follow this shape, citing upstream `f0abd413` v0.47.0 as design source, declaring the D-20 manual-replay shape, and noting why fork's existing AtomicBool seed (`profile/mod.rs:47`) is being migrated into a per-key counter.

**Imports pattern** (from `package.rs:34-40`):
```rust
use crate::profile;
use chrono::Utc;
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
```

**Seed pattern to extend — per-key AtomicBool** (from `profile/mod.rs:44-82`):
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
Plan 36-01a target shape (per RESEARCH.md Code Examples Pattern 2):
```rust
use std::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashMap;

pub struct DeprecationCounter {
    keys: std::sync::OnceLock<HashMap<&'static str, AtomicBool>>,
}

impl DeprecationCounter {
    pub fn emit_once(&self, key: &'static str, canonical: &'static str) {
        let map = self.keys.get_or_init(|| { /* lazy init known legacy keys */ });
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
Migrate `LEGACY_OVERRIDE_DENY_WARNED` static at `profile/mod.rs:47` into the new counter as the `"override_deny"` key's `AtomicBool`. Delete the global.

**Error handling pattern** (must use `Result<T>` per CLAUDE.md):
```rust
use nono::{NonoError, Result};
// LegacyPolicyPatch::rewrite returns Result<canonical_value, NonoError>
// Use NonoError::ProfileParse for legacy-key rewrite failures
// #[must_use] on rewrite() return value per CLAUDE.md
```

**Module test pattern** (mirror `profile/mod.rs:117-183` `canonical_schema_rename_tests`):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    // NB: avoid touching globals; test pure helpers without AtomicBool state.

    #[test]
    fn legacy_override_deny_rewrites_to_bypass_protection() { /* ... */ }

    #[test]
    fn deprecation_counter_emits_once_per_key() { /* ... */ }

    #[test]
    fn strict_mode_fails_closed_on_legacy_key() { /* ... */ }
}
```

---

### `crates/nono-cli/src/cli.rs` — ProfileValidateArgs `--strict` flag (Plan 36-01a)

**Analog:** `ProfileValidateArgs` itself at `cli.rs:1300-1307`

**Existing pattern**:
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

**Target post-add pattern**:
```rust
#[derive(Parser, Debug)]
pub struct ProfileValidateArgs {
    /// Profile JSON file to validate
    pub file: PathBuf,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
    /// Fail closed on legacy profile fields (e.g. `override_deny`). Default
    /// mode warns to stderr but continues; `--strict` exits non-zero.
    #[arg(long)]
    pub strict: bool,
}
```
Same struct shape, additive only. Compose with existing `deprecated_policy.rs` re-export at line 21 (`pub use crate::cli::ProfileValidateArgs as PolicyValidateArgs;` — verified at deprecated_policy.rs:18-22) — flag propagates automatically.

---

### `crates/nono-cli/src/profile_cmd.rs` — wire LegacyPolicyPatch + DeprecationCounter (Plan 36-01a)

**Analog:** `cmd_validate` at line 2142 (extend, don't replace)

**Existing handler shape** (lines 2142-2155):
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
Plan 36-01a wires LegacyPolicyPatch into `profile::load_profile_from_path` (interior wiring) and threads `args.strict` to control whether observed legacy keys land as `errors` (strict) or `warnings` (default). Existing emit-once logic at `profile/mod.rs:73-83` gets migrated into the DeprecationCounter; the `cmd_validate` outer shape stays unchanged.

---

### `crates/nono-cli/src/profile/mod.rs` — canonical Profile sections (Plan 36-01b)

**Analog (in-file):** Three existing section sub-struct precedents at lines 205, 271, 398.

**FilesystemConfig pattern** (lines 202-224) — Plan 36-01b extends with `deny` + `bypass_protection`:
```rust
/// Filesystem configuration in a profile
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
Plan 36-01b target — ADD canonical-section fields:
```rust
pub struct FilesystemConfig {
    // existing fields verbatim
    pub allow: Vec<String>,
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub allow_file: Vec<String>,
    pub read_file: Vec<String>,
    pub write_file: Vec<String>,
    // NEW canonical sections
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default, alias = "override_deny")]
    pub bypass_protection: Vec<String>,
}
```

**CapabilitiesConfig pattern (in-file precedent for the new GroupsConfig + CommandsConfig)** (lines 270-278):
```rust
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitiesConfig {
    #[serde(default)]
    pub aipc: Option<AipcConfig>,
}
```
Plan 36-01b new sibling structs follow this shape:
```rust
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandsConfig {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupsConfig {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}
```
**Composition check:** Verify `From<ProfileDeserialize> for Profile` impl at profile/mod.rs:1642 enumerates the new fields. Phase 35 Plan 35-03 `profile_to_json` Map-emission shape composes cleanly with these (canonical sections nest within the existing Map).

---

### `crates/nono-cli/src/capability_ext.rs` — Plan 36-01c rename callsite (canonical example)

**Sample existing callsite** (line 624-635):
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
Plan 36-01c canonical post-rename shape:
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
Note that function-local variable names like `profile_overrides` (line 629), function params like `profile_override_deny: &[PathBuf]` (line 663), and helper-fn names like `apply_deny_overrides` (line 668) are case-by-case — RESEARCH.md Plan 36-01c Task 1-3 says "atomic rename of the schema-level identifier"; sub-rename of helper params + local vars is planner discretion (recommend: rename `profile_override_deny` → `profile_bypass_protection` for consistency; keep `apply_deny_overrides` as the underlying lower-level function since its semantics are broader).

---

### `crates/nono-cli/src/cli.rs` — Plan 36-01c CLI flag alias direction flip

**Existing pattern** (lines 1355-1368):
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
Plan 36-01c target — flip canonical / alias direction:
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

---

### `crates/nono-cli/src/wiring.rs` (NEW; Plan 36-02)

**Analog 1 (header shape):** `crates/nono-cli/src/package.rs:1-32` — fork-divergence preamble documenting why the fork's surface differs from upstream's.
**Analog 2 (handler integration pattern):** `crates/nono-cli/src/profile_cmd.rs::cmd_validate` at line 2142.
**Analog 3 (validate_path_within retention precedent):** `crates/nono-cli/src/package_cmd.rs` — fork retains 9 callsites per `package.rs:22` comment.

**Header preamble target shape** (mirror `package.rs:1-33` shape):
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
//! Plan 36-02 (D-20 manual-replay) lands ONLY the yaml_merge directive
//! machinery from d44f5541, the serde_yaml_ng 0.10.0 pin from 242d4917, and
//! the reversal failure test. See the Plan 36-02 SUMMARY for the
//! per-acceptance disposition table.

use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
// serde_yaml_ng integration imports
```

**Imports pattern** (mirror `package.rs:34-40`):
```rust
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
```

**Path validation pattern** — CRITICAL per Pitfall 6 (CLAUDE.md § Path Handling):
```rust
// Plan 36-02 yaml_merge target-path validation MUST use Path::components()
// iteration + canonicalization, NOT str::starts_with. Preserve fork's
// validate_path_within callsites where they intersect yaml_merge targets.
fn validate_target_path(target: &Path, profile_dir: &Path) -> Result<PathBuf> {
    let canonical = target.canonicalize().map_err(|e| NonoError::PathCanonicalization {
        path: target.to_path_buf(),
        source: e,
    })?;
    // Defense-in-depth: re-verify containment via component iteration.
    // [...]
    Ok(canonical)
}
```

**Error handling pattern** (consistent with the rest of nono-cli):
```rust
use nono::{NonoError, Result};
// NonoError::ProfileParse for invalid yaml_merge directives
// Result<T> + ? propagation throughout
```

---

### `crates/nono-cli/Cargo.toml` — serde_yaml_ng pin (Plan 36-02)

**Analog:** existing exact-version pin at line 64 (`sigstore-sign = "0.6.5"`)

**Existing pattern**:
```toml
# Keyless (Sigstore/Fulcio/Rekor) signing for instruction file attestation
sigstore-sign = "0.6.5"
```
**Plan 36-02 add** (in `[dependencies]` block, mirror style):
```toml
# YAML-merge directive support (Plan 36-02; upstream-aligned at v0.10.0 per 242d4917)
serde_yaml_ng = "=0.10.0"
```
Note: fork uses `version = "0.6.5"` (no `=` prefix). Upstream `242d4917` pins with `=0.10.0` (locked exact). Plan 36-02 should use the upstream `=0.10.0` shape since the pin's whole point is to lock the precise version.

---

### `crates/nono/src/diagnostic.rs` — Plan 36-03 Commit 1 (restore 4 helpers)

**Analog 1 (in-file):** existing helper `extract_relative_write_path_from_line` at line 421-440 (sibling shape).
**Analog 2 (in-file):** existing `analyze_error_output` at line 215-273 (the consumer to wire into).

**Existing deferred-state comment block to REMOVE** (lines 402-419):
```rust
// NOTE (P34-DEFER-08b-2): upstream `b5f0a3ab` + `bbdf7b85` together add a
// structured-property parsing pipeline (extract_path_after_syscall_word,
// infer_access_from_structured_syscall_line, extract_structured_path_property,
// extract_structured_string_property) plus the wiring into `analyze_error_output`
// that consumes them. [...]
//
// Restoration plan: a dedicated D-20 manual-replay plan will (1) port the
// `b5f0a3ab` analyze_error_output refactor on top of fork's diagnostic engine,
// (2) restore the four helper functions, and (3) restore both tests. [...]
```
Plan 36-03 Commit 1 deletes this block AND the matching block at lines 2258-2267 once helpers + wiring + test are restored.

**Wiring callsite into `analyze_error_output`** — existing engine loop at lines 226-273:
```rust
for line in error_output.lines() {
    if blocked_protected_file.is_none() {
        blocked_protected_file = detect_protected_file_in_error_line(protected_paths, line);
    }
    if non_sandbox_failure.is_none() {
        non_sandbox_failure = detect_non_sandbox_failure_line(line);
    }
    if let Some(path) =
        current_dir.and_then(|cwd| extract_relative_write_path_from_line(line, cwd))
    {
        pending_relative_write = Some(path);
    }
    // [...]
}
```
Plan 36-03 Commit 1 ADDS new structured-property dispatch arms in this loop using the 4 restored helpers — additive only, preserves the existing `extract_relative_write_path_from_line` fallback chain.

**Error handling pattern** (library-tier — CLAUDE.md "library should almost never panic"):
```rust
// Use Option<T> returns for parse helpers; the loop continues on None
// No unwrap; no expect. Pure functions where possible.
```

---

### `crates/nono-cli/src/exec_strategy.rs` — Plan 36-03 Commit 2 (ADD helpers + new callsite)

**Analog 1 (in-file invariant to PRESERVE):** `ExecConfig<'a>` at line 276-326 — DO NOT MODIFY (D-36-D1).
**Analog 2 (in-file pattern):** existing `clear_signal_forwarding_target` at line 1987-1991 (existing helper; ADD new callsite, do NOT redefine).

**ExecConfig preservation invariant** (lines 276-326 — verified shape):
```rust
pub struct ExecConfig<'a> {
    pub command: &'a [String],
    pub resolved_program: &'a std::path::Path,
    pub caps: &'a CapabilitySet,
    pub env_vars: Vec<(&'a str, &'a str)>,
    pub cap_file: Option<&'a std::path::Path>,
    pub current_dir: &'a std::path::Path,
    pub no_diagnostics: bool,
    pub threading: ThreadingContext,
    pub protected_paths: &'a [std::path::PathBuf],
    pub profile_save_base: Option<&'a str>,
    pub startup_timeout: Option<StartupTimeoutConfig<'a>>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub capability_elevation: bool,
    #[cfg(target_os = "linux")]
    pub seccomp_proxy_fallback: bool,
    pub allowed_env_vars: Option<Vec<String>>,
    pub denied_env_vars: Option<Vec<String>>,
}
```
**Plan 36-03 Commit 2 invariant:** This struct definition is FROZEN. New helpers add module-level `fn`s; they take `&ExecConfig` or threading state as args, not new struct fields.

**Existing helper pattern to mirror** (`clear_signal_forwarding_target` at line 1987):
```rust
fn clear_signal_forwarding_target() {
    CHILD_PID.store(0, std::sync::atomic::Ordering::SeqCst);
    PTY_MASTER_FD.store(-1, std::sync::atomic::Ordering::SeqCst);
    close_pause_pipe();
}
```
Existing callsites at lines 825 + 2047 (in `SignalForwardingGuard::drop` at line 2045-2049):
```rust
impl Drop for SignalForwardingGuard {
    fn drop(&mut self) {
        clear_signal_forwarding_target();
    }
}
```
**Plan 36-03 Commit 2 adds a THIRD callsite immediately before the profile-save prompt** (location to be discovered during execution; likely inside the supervisor's exit-handling path where `profile_save_base` is consulted). DRIFT NOTE 2: do not redefine the helper.

**`POST_EXIT_PTY_DRAIN_TIMEOUT` constant pattern**:
```rust
// Plan 36-03 Commit 2: per upstream b5f0a3ab, the post-exit PTY drain
// quiet period is reduced from 250ms to 100ms.
//
// REGRESSION COVERAGE per D-36-D3: this MUST NOT regress Phase 17
// attach-streaming (crates/nono-cli/tests/attach_streaming_integration.rs)
// or Phase 31 broker ConPTY (crates/nono-shell-broker/). Phase 15 5-row
// detached-console smoke gate (close-gate step 6) double-checks.
const POST_EXIT_PTY_DRAIN_TIMEOUT: Duration = Duration::from_millis(100);
```
Module-level const; declared near other timing constants if present, else at top-of-file scope after imports.

---

### `crates/nono-cli/src/execution_runtime.rs` — Plan 36-03 Commit 2 helpers (3 fns + tests)

**Analog (in-file):** existing helper shape at lines 11-50 + `#[cfg(test)] mod tests` at line 465-486.

**Existing helper pattern** (lines 34-50):
```rust
fn cleanup_capability_state_file(cap_file_path: &std::path::Path) {
    if cap_file_path.exists() {
        let _ = std::fs::remove_file(cap_file_path);
    }
}

fn next_capability_state_file_path() -> std::path::PathBuf {
    use rand::RngExt;
    let mut rng = rand::rng();
    let bytes: [u8; 8] = rng.random();
    let suffix = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    std::env::temp_dir().join(format!(".nono-{suffix}.json"))
}
```
**Plan 36-03 Commit 2** adds 3 sibling helpers in the same module-level fn style:
- `fn should_apply_startup_timeout(profile: &str) -> bool`
- `fn startup_timeout_profile(/* args */) -> Option<StartupTimeoutConfig<'_>>`
- `fn compute_executable_identity(path: &Path) -> /* identity type */`

**Existing test module pattern** (lines 465-486) — mirror this shape for new tests:
```rust
#[cfg(test)]
mod tests {
    use super::recommended_builtin_profile;
    use std::path::Path;

    #[test]
    fn recommended_builtin_profile_matches_known_agent_commands() {
        assert_eq!(
            recommended_builtin_profile(Path::new("/usr/local/bin/claude")),
            Some("claude-code")
        );
        // [...]
    }
}
```

---

### `crates/nono-cli/src/cli.rs` — Plan 36-03 Commit 2 LearnArgs.trace restoration

**Existing `LearnArgs` shape** (lines 2261-2295 — verified absent `trace`):
```rust
#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct LearnArgs {
    /// Use a named profile to compare against (shows only missing paths)
    #[arg(long, short = 'p', value_name = "NAME", help_heading = "OPTIONS")]
    pub profile: Option<String>,

    /// Output discovered paths as JSON fragment for profile
    #[arg(long, help_heading = "OPTIONS")]
    pub json: bool,

    /// Timeout in seconds (default: run until command exits)
    #[arg(long, value_name = "SECS", help_heading = "OPTIONS")]
    pub timeout: Option<u64>,

    /// Show all accessed paths, not just those that would be blocked
    #[arg(long, help_heading = "OPTIONS")]
    pub all: bool,

    /// Skip reverse DNS lookups for discovered IPs
    #[arg(long, help_heading = "OPTIONS")]
    pub no_rdns: bool,

    /// Enable verbose output
    #[arg(long, short = 'v', action = clap::ArgAction::Count, help_heading = "OPTIONS")]
    pub verbose: u8,

    /// Command to trace
    #[arg(required = true, hide = true)]
    pub command: Vec<String>,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}
```
**Plan 36-03 Commit 2** adds `pub trace: bool` (or appropriate type per upstream b5f0a3ab — likely `bool` flag) as a sibling to `verbose`, `all`, etc.:
```rust
/// Enable detailed strace/dtrace output for path-discovery diagnostics
#[arg(long, help_heading = "OPTIONS")]
pub trace: bool,
```
**DRIFT NOTE 4 verification:** Line 2272 in current main reads `/// Timeout in seconds (default: run until command exits)` — canonical `///` shape. The `\ ` typo RESEARCH.md flagged was already cleaned. If line 2272 reads otherwise at execution time, fix to `///` during the same edit pass.

---

### Scripts — `scripts/test-list-aliases.sh` + `scripts/lint-docs.sh` (NEW; Plan 36-01d)

**Analog:** `scripts/check-upstream-drift.sh` (existing fork shell script)

**Header pattern**:
```bash
#!/usr/bin/env bash
# scripts/test-list-aliases.sh
# Inventories profile-schema legacy aliases vs. canonical names and fails if
# anything drifts. Read-only - does NOT modify any source files.
#
# Usage:
#   ./scripts/test-list-aliases.sh                   # default audit
#   ./scripts/test-list-aliases.sh --format json     # JSON output
#
# Plan 36-01d (D-20 manual-replay): inventory enforcement per upstream f0abd413.

set -euo pipefail

# Best-effort UTF-8 locale to harden non-ASCII handling on Git-for-Windows MSYS bash.
export LC_ALL=C.UTF-8 2>/dev/null || true
```
**Argument parsing pattern** (from `check-upstream-drift.sh:29-50`):
```bash
print_usage() {
    cat <<'USAGE'
Usage: scripts/test-list-aliases.sh [--format table|json]

[Description]

Options:
  --format table    Human-readable output (default)
  --format json     Single-line JSON for templates / CI consumers
  -h, --help        Show this message
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

**Windows-host compatibility note:** `scripts/regenerate-schema.sh` must run on Windows host (close-gate runs on Windows per D-36-A5). Either ensure shell-script is portable (no Linux-only utilities) OR provide `.ps1` companion. RESEARCH.md Plan 36-01d Task 4 flags this as "verify reproducibility on Windows host."

---

### Docs — `docs/cli/features/profiles-groups.mdx` + `docs/cli/usage/flags.mdx` (Plan 36-01d)

**Analog:** existing `docs/cli/features/profile-authoring.mdx` (verified sibling exists at same directory).

**Frontmatter pattern** (from `profile-authoring.mdx:1-4`):
```mdx
---
title: Profile Authoring
description: Scaffolding, schema validation, and tooling for creating custom profiles
---

[content...]
```
Plan 36-01d docs migration preserves this frontmatter shape; updates body for canonical section names.

**Cross-doc link pattern** (from `profile-authoring.mdx:7-10`):
```mdx
<Tip>
  For an overview of what profiles are and how they compose with groups, see [Profiles & Groups](/cli/features/profiles-groups).
</Tip>
```

---

## Shared Patterns

### Pattern A — Error handling (`nono::Result<T>` + `?`)

**Source:** `crates/nono/src/error.rs::NonoError` + `nono::Result<T>` alias.
**Apply to:** ALL Phase 36 helpers and handlers.

**Excerpt** (canonical shape across nono-cli):
```rust
use nono::{NonoError, Result};

pub fn helper(input: &str) -> Result<Output> {
    let value = parse(input).map_err(|e| NonoError::ProfileParse(format!(
        "field {field}: {e}"
    )))?;
    Ok(value)
}
```
No `.unwrap()` / `.expect()` outside `#[cfg(test)]` or `no_run` doc examples (CLAUDE.md § Coding Standards).

### Pattern B — DCO sign-off in commits

**Source:** CLAUDE.md § Coding Standards; `.planning/templates/upstream-sync-quick.md` § D-19 trailer block.
**Apply to:** every Phase 36 commit (6 plans × N commits).

**Excerpt — D-20 manual-replay shape (Plans 36-01a/b/c/d, 36-02, 36-03 Commits 1+2):**
```
<subject>

<body — cites upstream commit(s) as design source; documents scope-trim>

Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```
**Excerpt — D-19 cherry-pick shape (Plan 36-03 Commit 3 ONLY):**
```
fix(diagnostic): parse escaped quotes in structured properties

<body>

Upstream-commit: bbdf7b85
Upstream-tag: v0.52.0
Upstream-author: Luke Hinds <lhinds@example.com>
Co-Authored-By: Luke Hinds <lhinds@example.com>
Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```
Lowercase 'a' in `Upstream-author:` is mandatory.

### Pattern C — Env-var save/restore in tests

**Source:** CLAUDE.md § Coding Standards § Environment variables in tests.
**Apply to:** Plan 36-01a + 36-01b tests that touch `HOME`, `XDG_CONFIG_HOME`, `NONO_TEST_HOME`.

**Excerpt:** save value, modify, run assertion, restore in the same flow (no `defer`/`drop`-only patterns — explicit restore for parallel-test safety).

### Pattern D — Path component comparison + canonicalization

**Source:** CLAUDE.md § Path Handling; existing `validate_path_within` callsites in `package_cmd.rs`.
**Apply to:** Plan 36-02 yaml_merge target-path validation; Plan 36-01a `LegacyPolicyPatch::rewrite` if path-shaped fields are rewritten.

**Excerpt — anti-pattern to AVOID** (CLAUDE.md § Common Footguns #1):
```rust
// VULNERABILITY: path.starts_with("/home") matches "/homeevil"
if target_path.starts_with(profile_dir) { /* ... */ }
```
**Excerpt — canonical pattern**:
```rust
let canonical = target_path.canonicalize().map_err(/* fail-closed */)?;
let canonical_profile_dir = profile_dir.canonicalize()?;
if !canonical.components().take(canonical_profile_dir.components().count())
    .zip(canonical_profile_dir.components())
    .all(|(a, b)| a == b)
{
    return Err(NonoError::PathOutsideRoot { /* ... */ });
}
```

### Pattern E — `#[must_use]` on critical Results

**Source:** CLAUDE.md § Coding Standards.
**Apply to:** Plan 36-01a `LegacyPolicyPatch::rewrite`, Plan 36-02 yaml_merge applier outputs, any helper that returns a security-relevant `Result`.

```rust
#[must_use]
pub fn rewrite(&self, raw: &str) -> Result<CanonicalPolicy> { /* ... */ }
```

### Pattern F — Cross-target clippy gate (Phase 25 CR-A precedent)

**Source:** `memory/feedback_clippy_cross_target.md`; D-36-A5 close-gate steps 3 + 4.
**Apply to:** ALL Phase 36 plans (cross-platform code).

**Close-gate commands** (run on Windows host):
```bash
cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used
cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used
cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used
```
macOS gate is especially load-bearing for Plan 36-03 (b5f0a3ab introduces macOS-gated `print_macos_run_guidance` per Plan 34-08b absorption).

### Pattern G — Atomic mass-rename discipline (D-36-B4)

**Source:** Phase 33 + Phase 34 atomic-cherry-pick precedent.
**Apply to:** Plan 36-01c ONLY.

- Single commit across 17 files; mechanical sed/IDE rename.
- `cargo build --workspace --all-features` + `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` + `cargo test --workspace --all-features` gate ALL green before commit lands.
- NO staged file-by-file mini-commits with type-alias scaffolding.
- Reviewer sees ONE clean diff; rollback is ONE revert.
- Planner MAY split into 2 commits ONLY if test fixtures require their own commit (file path renames) — but `.rs` rename MUST be atomic.

### Pattern H — Pre-flight `cargo clean -p nono-cli` before mass rename

**Source:** Plan 36-01c Task 1 (RESEARCH.md line 586).
**Apply to:** Plan 36-01c before the atomic rename pass to clear stale incremental artifacts.

## No Analog Found

| File | Role | Data Flow | Reason / Mitigation |
|------|------|-----------|---------------------|
| `crates/nono-cli/src/wiring.rs` (NEW) | NEW module | YAML directive applier | Fork has no `wiring.rs`. Closest analog is `package.rs` (fork-divergence preamble shape) but the actual yaml_merge logic is upstream-only. Use RESEARCH.md Code Examples + upstream `d44f5541` as design source. |
| `crates/nono-cli/src/deprecated_schema.rs` (NEW ~824 LOC) | NEW module | Legacy JSON rewrite + per-key counter | No fork-side analog at this scale. Closest seeds: `profile/mod.rs:44-114` (AtomicBool + raw-JSON walk pattern) + `package.rs:1-32` (fork-divergence preamble). Verbatim port from upstream `f0abd413`; planner consumes upstream source as primary design reference. |

## Metadata

**Analog search scope:**
- `crates/nono/src/` (library — diagnostic.rs deep-dive)
- `crates/nono-cli/src/` (CLI — all 17 rename-target files + package.rs analog + profile/ subdir)
- `crates/nono-cli/data/` (JSON fixtures — policy.json + nono-profile.schema.json)
- `crates/nono-cli/Cargo.toml` (dep-pin precedent)
- `scripts/*.sh` (script analog)
- `docs/cli/features/*.mdx` (docs analog)

**Files scanned:** ~25 source files; ~10 cross-referenced (Cargo.toml, JSON data, scripts, docs)

**Grep verifications run:**
- `override_deny` callsites across `crates/nono-cli/src/` — confirms 17-file actual scope (NOT 14)
- `policy_cmd.rs` — confirmed ABSENT (drift note 1)
- `clear_signal_forwarding_target` in `exec_strategy.rs` — confirmed EXISTS at line 1987 with 2 callsites (drift note 2)
- `cli.rs:2263-2295` `LearnArgs` — confirmed `trace` field ABSENT; line 2272 reads canonical `///` (drift note 4 partial — verify at execution)
- `serde_yaml` in fork — confirmed NONE present; Cargo.toml has no `serde_yaml*` dep currently

**Pattern extraction date:** 2026-05-12

**Cross-references to upstream:**
- `f0abd413` (v0.47.0) — Plans 36-01a/b/c/d design source
- `242d4917` / `802c8566` / `d44f5541` (v0.49.0) — Plan 36-02 design source
- `b5f0a3ab` (v0.52.0; Luke Hinds) — Plan 36-03 Commits 1+2 design source
- `bbdf7b85` (v0.52.0; Luke Hinds) — Plan 36-03 Commit 3 D-19 cherry-pick target
