---
phase: 49
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - crates/nono-cli/src/cli.rs
  - crates/nono-cli/src/setup.rs
  - crates/nono/src/trust/bundle.rs
  - crates/nono/src/trust/mod.rs
  - crates/nono-cli/tests/setup_trust_root.rs
autonomous: false
requirements: [REQ-POC-TRUST-01]
tags: [sigstore, trust-root, cli, setup, fail-secure]
must_haves:
  truths:
    - "`nono setup --from-file <good>.json` exits 0 and writes a cache file byte-identical to the input"
    - "`nono setup --from-file <expired>.json` exits non-zero with a freshness error and leaves the cache untouched"
    - "`nono setup --from-file <malformed>.json` exits non-zero with a parse error and leaves the cache untouched"
    - "`nono setup --from-file <missing>.json` exits non-zero with an IO error and leaves the cache untouched"
    - "`nono setup --from-file <p> --refresh-trust-root` is rejected at clap-parse time"
    - "Cross-target clippy passes on Linux + macOS targets (or PARTIAL with explicit live-CI deferral per `.planning/templates/cross-target-verify-checklist.md`)"
  artifacts:
    - path: "crates/nono-cli/src/cli.rs"
      provides: "SetupArgs::from_file clap field with conflicts_with=\"refresh_trust_root\""
      contains: "from_file"
    - path: "crates/nono-cli/src/setup.rs"
      provides: "SetupRunner::from_file_step + struct field + run wiring"
      contains: "from_file_step"
    - path: "crates/nono/src/trust/bundle.rs"
      provides: "pub fn check_trusted_root_freshness (visibility widened)"
      contains: "pub fn check_trusted_root_freshness"
    - path: "crates/nono-cli/tests/setup_trust_root.rs"
      provides: "Integration tests for --from-file (happy/expired/malformed/missing/mutex/stdout)"
      min_lines: 250
  key_links:
    - from: "crates/nono-cli/src/setup.rs::from_file_step"
      to: "crates/nono/src/trust/bundle.rs::load_trusted_root"
      via: "validation pipeline call"
      pattern: "nono::trust::bundle::load_trusted_root"
    - from: "crates/nono-cli/src/setup.rs::from_file_step"
      to: "crates/nono/src/trust/bundle.rs::check_trusted_root_freshness"
      via: "freshness gate call"
      pattern: "check_trusted_root_freshness"
    - from: "crates/nono-cli/src/setup.rs::from_file_step"
      to: "std::fs::copy"
      via: "byte-identical write (D-49-B1)"
      pattern: "std::fs::copy\\(src, &cache_path\\)"
---

<objective>
Add a `nono setup --from-file <PATH>` flag that populates `<nono_home>/.nono/trust-root/trusted_root.json` from a user-supplied JSON, bypassing `sigstore_verify::TrustedRoot::production()` entirely. Reuses the existing `nono::trust::bundle::load_trusted_root` + `check_trusted_root_freshness` validation pipeline (no new schema validator, no new code paths in `crates/nono` beyond a one-keyword visibility widen).

Purpose: Exit the sigstore-verify dep-bump treadmill (REQ-POC-TRUST-01). After this plan, POC users can `--from-file` a release asset and never depend on the upstream-embedded TUF anchor.

Output: New CLI flag wired end-to-end through `cli.rs`, `setup.rs`, the visibility-widen in `bundle.rs`/`mod.rs`, and 6 new integration tests covering F-01-01 through F-01-08.

Implements: REQ-POC-TRUST-01 (per D-49-A1, D-49-B1, D-49-B2, D-49-B3, D-49-D1, D-49-D2).
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-CONTEXT.md
@.planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-SPEC.md
@.planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-RESEARCH.md
@.planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-PATTERNS.md
@.planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-VALIDATION.md
@.planning/templates/cross-target-verify-checklist.md
@CLAUDE.md

<interfaces>
<!-- Key contracts the executor needs. Sourced from 49-RESEARCH.md verifications. -->

From `crates/nono/src/trust/bundle.rs:113` (existing, used as-is):
```rust
pub fn load_trusted_root<P: AsRef<Path>>(path: P) -> Result<TrustedRoot>;
```

From `crates/nono/src/trust/bundle.rs:247` (CURRENTLY PRIVATE — widened to `pub` by Task 1):
```rust
fn check_trusted_root_freshness(root: &TrustedRoot, cache_path: &std::path::Path) -> Result<()>;
// Target shape after widen:
// pub fn check_trusted_root_freshness(root: &TrustedRoot, cache_path: &std::path::Path) -> Result<()>;
```

Caller passes the DESTINATION cache path (used in the function's error-message path display), NOT the source path. The check inspects `root` for tlog `validFor.end` expiry; the path arg only flavors the error message.

From `crates/nono-cli/src/setup.rs:20-29` (existing `SetupRunner` struct — Task 2 adds one field):
```rust
pub struct SetupRunner {
    check_only: bool,
    #[cfg(target_os = "windows")] register_wfp_service: bool,
    #[cfg(target_os = "windows")] install_wfp_service: bool,
    #[cfg(target_os = "windows")] install_wfp_driver: bool,
    #[cfg(target_os = "windows")] start_wfp_service: bool,
    #[cfg(target_os = "windows")] start_wfp_driver: bool,
    refresh_trust_root: bool,
    generate_profiles: bool,
    show_shell_integration: bool,
}
```

From `crates/nono-cli/src/setup.rs:820-860` (existing `refresh_trust_root_step` — Task 2 mirrors its shape):
```rust
fn refresh_trust_root_step(&self) -> Result<()> {
    let cache_dir = crate::config::nono_home_dir()?
        .join(".nono")
        .join("trust-root");
    std::fs::create_dir_all(&cache_dir).map_err(NonoError::Io)?;

    println!(
        "[{}/{}] Refreshing Sigstore trusted root...",
        self.refresh_trust_root_phase_index(),
        self.total_phases()
    );
    // ... fetch + serialize + write ...
    println!("  * Sigstore trusted root cached at {}", cache_path.display());
    println!();
    Ok(())
}
```

From `crates/nono-cli/src/cli.rs:2341-2387` (existing `SetupArgs` clap struct — Task 2 adds one field, immediately after `refresh_trust_root`):
```rust
#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct SetupArgs {
    // ... check_only + 5 Windows-only WFP flags ...
    #[arg(long, help_heading = "OPTIONS")]
    pub refresh_trust_root: bool,
    #[arg(long, help_heading = "OPTIONS")]
    pub profiles: bool,
    // ... etc ...
}
```

Established `conflicts_with` style in `cli.rs` (verified at lines 1565, 2132, 2140, 2152, 2930, 2991, 3011, 3015, 3019, 3079, 3083, 3128 — 12+ sites): `#[arg(long, conflicts_with = "field_name", ...)]` — clap-v4 derive uses field-name string literal, snake_case (NOT enum/constant). Use `conflicts_with = "refresh_trust_root"`.

From `crates/nono-cli/tests/setup_trust_root.rs:1-44` (existing test helpers — Task 3 reuses):
```rust
fn nono_bin() -> Command { Command::new(env!("CARGO_BIN_EXE_nono")) }

fn run_nono(args: &[&str], home: &Path, cwd: &Path) -> Output {
    let mut cmd = nono_bin();
    cmd.args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("NONO_TEST_HOME", home)
        .env("NONO_NO_UPDATE_CHECK", "1");
    cmd.current_dir(cwd).output().expect("failed to run nono")
}

fn setup_isolated_home() -> (tempfile::TempDir, PathBuf, PathBuf) { /* TempDir under target/test-artifacts; creates home + workspace */ }
```

**IMPORTANT:** This file does NOT use `tests/common::test_env::{lock_env, EnvVarGuard}` — it uses subprocess isolation via env-args on each `Command` invocation (env vars only set for the child process, never mutating the parent process env). This pattern is HERMETIC by construction (no shared parent-env state to race on) and is the established pattern for `setup_trust_root.rs`. Task 3 REUSES `run_nono` + `setup_isolated_home` verbatim and follows this pattern — does NOT switch to `lock_env`/`EnvVarGuard`. The CONTEXT.md note about D-44-E6 applies only to tests that mutate the in-process parent env (which `setup_trust_root.rs` does not).

From `crates/nono/tests/fixtures/trust-root-frozen.json` — 126-line fixture. The 2 tlogs have ONLY `validFor.start`, NO `validFor.end` (so they are always-fresh per `check_trusted_root_freshness` at `bundle.rs:282-283` — "missing end = no expiry asserted; treat as active"). To make a tlog FAIL the freshness gate, an `"end": "1970-01-01T00:00:00Z"` field MUST be INSERTED into BOTH tlogs' `publicKey.validFor` objects. JSON keys are camelCase (`validFor`, `publicKey`, `rawBytes`).
</interfaces>
</context>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| CLI arg → process | User-supplied `<PATH>` arg crosses into the setup process; the file at that path is treated as untrusted JSON. |
| Source JSON → cache file | Bytes flow from user-controlled source into `<nono_home>/.nono/trust-root/trusted_root.json` (consumed by the verify path later). |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-49-01 | Tampering | `from_file_step` validation | mitigate | Two-step validation: `load_trusted_root(<PATH>)?` (schema/parse via `TrustedRoot::from_file`) THEN `check_trusted_root_freshness(&root, &cache_path)?` (D-32-03 tlog expiry gate). BOTH calls precede the `std::fs::copy`. On any `Err`, return early — the cache file is never touched. Fail-closed contract: validation failure ⇒ no cache mutation. Test gates F-01-02, F-01-03. |
| T-49-02 | Tampering | `--from-file <PATH>` clap surface | mitigate | clap parses `<PATH>` as `Option<PathBuf>` (no URL parsing; no scheme handling — http://, ftp://, file:// are all just treated as path bytes). The flag is documented as a LOCAL filesystem path. No network fetch on this code path. The TUF verification that `--refresh-trust-root` performs is replaced by the validation pipeline above; this is by design (the input is trusted by the user, not by TUF). |
| T-49-03 | Tampering / TOCTOU | symlink on cache path | accept | `std::fs::copy` follows symlinks on the source side — accepted because the user supplied the path. Destination cache path is constructed deterministically from `crate::config::nono_home_dir()?.join(".nono").join("trust-root").join("trusted_root.json")`. No symlink-following on the destination side outside the `nono_home` tree. No TOCTOU window between validation and copy that an attacker on the host could exploit beyond what they could already do (they could modify the source JSON directly if they have FS write to that path). |
| T-49-04 | Information Disclosure | partial cache leak on copy failure | mitigate | D-49-B2: wrap `std::fs::copy` in a guard; on `Err`, attempt `let _ = std::fs::remove_file(&cache_path);` (swallow inner error), then propagate the original `NonoError::Io`. Cache is fully-written-or-absent — never partial. Test gate F-01-04 (`from_file_missing_path_no_partial_cache`). |
| T-49-05 | Tampering | clap-mutex bypass on simultaneous `--from-file` + `--refresh-trust-root` | mitigate | clap-level `conflicts_with = "refresh_trust_root"` on the new `from_file` field. Parse-time rejection BEFORE any filesystem write. Test gate F-01-01 (`from_file_with_refresh_rejected`). |
</threat_model>

<verification_strategy>
## Failure Mode Coverage (Nyquist Dimension 8)

Cites IDs from `49-VALIDATION.md § Failure Modes (Nyquist Dimension 8) → REQ-POC-TRUST-01`. All 8 failure modes covered.

| Failure Mode | Validation Gate | Command |
|--------------|-----------------|---------|
| F-01-01 clap-mutex bypass | Test `from_file_with_refresh_rejected` | `cargo test -p nono-cli --test setup_trust_root from_file_with_refresh_rejected -- --include-ignored` (test is hermetic — no `--include-ignored` needed) |
| F-01-02 freshness gate bypass | Test `from_file_expired_fails_closed` (uses mutated-fixture with `validFor.end = 1970`) | `cargo test -p nono-cli --test setup_trust_root from_file_expired_fails_closed` |
| F-01-03 schema bypass | Tests `from_file_malformed_truncated_fails_closed` + `from_file_malformed_quote_flipped_fails_closed` | `cargo test -p nono-cli --test setup_trust_root from_file_malformed` |
| F-01-04 cache leak on copy failure | Test `from_file_missing_path_no_partial_cache` | `cargo test -p nono-cli --test setup_trust_root from_file_missing_path_no_partial_cache` |
| F-01-05 stdout drift | Test `from_file_stdout_matches_refresh_shape` (asserts `[X/N] Loading...` + `Source: <path>` strings on stdout) | `cargo test -p nono-cli --test setup_trust_root from_file_stdout_matches_refresh_shape` |
| F-01-06 cross-target clippy regression | Cross-target clippy (Linux + macOS) per `.planning/templates/cross-target-verify-checklist.md` | `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` AND `--target x86_64-apple-darwin -- ...` (PARTIAL allowed if cross-toolchain unavailable) |
| F-01-07 phase-index off-by-one | Test `from_file_phase_index_matches_refresh_index` (asserts `[X/N]` header where `X = self.refresh_trust_root_phase_index()`) | `cargo test -p nono-cli --test setup_trust_root from_file_phase_index` |
| F-01-08 freshness fn still private | `cargo build -p nono-cli` (would fail if `pub` keyword missing) + `cargo test` (links the fn) | `cargo build -p nono-cli && cargo test -p nono trust::bundle` |

## Cross-Target Clippy Verification (MANDATORY)

Plan 49-01 touches `crates/nono-cli/src/cli.rs` and `setup.rs`, both of which contain `#[cfg(target_os = "windows")]` blocks (5+ in `setup.rs` alone) and the `#[cfg(target_os = "macos")]` / `#[cfg(target_os = "linux")]` `installation_platform_label` blocks at `setup.rs:863-880`. Per CLAUDE.md § "Coding Standards" → "Cross-target clippy verification" bullet + `.planning/templates/cross-target-verify-checklist.md` Decision Tree Question 1 → Yes:

```bash
cargo clippy --workspace -- -D warnings -D clippy::unwrap_used                                 # Windows host (native)
cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used  # Linux cross
cargo clippy --workspace --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used        # macOS cross
```

**PARTIAL disposition allowed** ONLY if the cross-toolchain is missing (per checklist § PARTIAL Disposition). If PARTIAL: the verifier marks the related REQ PARTIAL with explicit live-CI deferral, and the verification status flips to `human_needed` pending CI confirmation. Document in SUMMARY using the exact prose from the checklist § PARTIAL Disposition Step 4.

## Pre-Commit Verification Block

```bash
cargo build -p nono-cli --release                                                        # F-01-08 (link smoke)
cargo test -p nono trust::bundle                                                         # vis-widen unit smoke
cargo test -p nono-cli --test setup_trust_root                                           # F-01-01..F-01-07 (integration)
cargo clippy --workspace -- -D warnings -D clippy::unwrap_used                           # Windows host
cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used  # F-01-06 Linux
cargo clippy --workspace --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used        # F-01-06 macOS
cargo fmt --all --check
```
</verification_strategy>

<tasks>

<task type="auto" tdd="false">
  <name>Task 1: Widen `check_trusted_root_freshness` visibility from private to `pub`</name>
  <files>crates/nono/src/trust/bundle.rs, crates/nono/src/trust/mod.rs</files>
  <read_first>
    - crates/nono/src/trust/bundle.rs (read lines 100-180 for the existing `pub fn load_trusted_root` + `pub fn load_production_trusted_root` style, then lines 240-310 for the current `fn check_trusted_root_freshness` body — the body is NOT modified)
    - crates/nono/src/trust/mod.rs (read entire file ~80 lines; the existing `pub use bundle::{...}` block at lines 39-46 is the insertion point for the re-export)
    - .planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-RESEARCH.md § "check_trusted_root_freshness accessibility" (lines 196-211) — explicitly recommends `pub fn` widen, justifies in-scope vs SPEC.md "no new schema validator"
    - .planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-PATTERNS.md § "crates/nono/src/trust/bundle.rs — visibility widen" (lines 70-79)
  </read_first>
  <behavior>
    - The function `check_trusted_root_freshness` must be callable from `crates/nono-cli/src/setup.rs` (currently a build error because the fn is module-private).
    - The function's SIGNATURE and BODY are unchanged — only the leading `fn` becomes `pub fn`.
    - The existing internal callsite at `bundle.rs:165` (inside `load_production_trusted_root`) continues to work without modification.
    - `cargo test -p nono trust::bundle` passes (no regression in the existing `pub` smoke or any other bundle test).
    - The `pub use` re-export in `trust/mod.rs` makes the fn reachable as `nono::trust::check_trusted_root_freshness` AND `nono::trust::bundle::check_trusted_root_freshness` (both paths work).
  </behavior>
  <action>
1. Edit `crates/nono/src/trust/bundle.rs` line 247: change

   ```rust
   fn check_trusted_root_freshness(root: &TrustedRoot, cache_path: &std::path::Path) -> Result<()> {
   ```

   to

   ```rust
   pub fn check_trusted_root_freshness(root: &TrustedRoot, cache_path: &std::path::Path) -> Result<()> {
   ```

   Do NOT touch the function body. Do NOT touch any other line in bundle.rs.

2. Edit `crates/nono/src/trust/mod.rs` lines 39-46. The existing `pub use bundle::{...}` block lists ~20 items alphabetically. Insert `check_trusted_root_freshness,` in alphabetical position (between `bundle_path_for,` at line 40 and `extract_all_subjects,`). The resulting block must look like:

   ```rust
   pub use bundle::{
       bundle_path_for, check_trusted_root_freshness, extract_all_subjects, extract_bundle_digest,
       extract_predicate_type, extract_signer_identity, load_bundle, load_bundle_from_str,
       load_production_trusted_root, load_trusted_root, load_trusted_root_from_str,
       multi_subject_bundle_path, parse_cert_info, verify_bundle, verify_bundle_keyed,
       verify_bundle_subject_name, verify_bundle_with_digest, verify_keyed_signature, Bundle,
       CertificateInfo, DerPublicKey, Sha256Hash, SigstoreVerificationResult, TrustedRoot,
       VerificationPolicy,
   };
   ```

   (Or insert as a single line — match whatever rustfmt produces on `cargo fmt --all`.)

3. Add a single-line `///` doc comment immediately above the function declaration in bundle.rs (line 247) describing what the function does for external callers (it was previously private with no doc):

   ```rust
   /// Checks that the trusted root has at least one active tlog (per-tlog
   /// `validFor.end` gate, D-32-03). Returns `NonoError::TrustPolicy` with
   /// a recovery hint referencing `cache_path` on failure.
   ///
   /// Per-tlog `validFor.end` missing = no expiry asserted = treated as active
   /// (WR-05 fail-closed format guard).
   pub fn check_trusted_root_freshness(...) -> Result<()> {
   ```

4. Verify:
   - `cargo build -p nono` (must succeed)
   - `cargo build -p nono-cli` (must succeed — but the call site in setup.rs doesn't exist yet; this just confirms the vis-widen didn't break anything)
   - `cargo test -p nono trust::bundle` (must pass — existing tests use the internal callsite via `load_production_trusted_root`)
   - `cargo fmt --all --check`
  </action>
  <verify>
    <automated>cargo build -p nono &amp;&amp; cargo test -p nono trust::bundle &amp;&amp; cargo fmt --all --check</automated>
  </verify>
  <acceptance_criteria>
    - `grep -n "pub fn check_trusted_root_freshness" crates/nono/src/trust/bundle.rs` returns exactly one match at line ~247.
    - `grep -n "check_trusted_root_freshness" crates/nono/src/trust/mod.rs` returns exactly one match inside the `pub use bundle::{...}` block.
    - `cargo build -p nono` exits 0.
    - `cargo test -p nono trust::bundle` exits 0 (all existing bundle tests pass — no regression).
    - `cargo fmt --all --check` exits 0.
    - The function body at `bundle.rs:248+` is byte-identical to the pre-edit state (verify via `git diff crates/nono/src/trust/bundle.rs` showing only the `fn` → `pub fn` line + the new `///` doc lines).
    - F-01-08 covered: subsequent `cargo build -p nono-cli` (after Task 2 lands) can reach the function via `nono::trust::bundle::check_trusted_root_freshness`.
    - Validates: F-01-08.
  </acceptance_criteria>
  <done>
    `check_trusted_root_freshness` is `pub` in `bundle.rs` and re-exported in `trust/mod.rs`; no regression in `cargo test -p nono trust::bundle`; rustfmt clean.
  </done>
</task>

<task type="auto" tdd="false">
  <name>Task 2: Wire `--from-file` flag end-to-end through `cli.rs` and `setup.rs`</name>
  <files>crates/nono-cli/src/cli.rs, crates/nono-cli/src/setup.rs</files>
  <read_first>
    - crates/nono-cli/src/cli.rs (lines 2341-2387 for the existing `SetupArgs` struct; lines 1565, 2132, 2140, 2152, 2930, 2991, 3011, 3019, 3079, 3083 for prior-art `conflicts_with = "field_name"` snake-case spellings)
    - crates/nono-cli/src/setup.rs (lines 1-50 for imports + `SetupRunner` struct; lines 50-100 for `SetupRunner::new` and `SetupRunner::run`; lines 700-810 for `total_phases()` + `refresh_trust_root_phase_index()`; lines 820-860 for the canonical `refresh_trust_root_step` pattern to mirror)
    - .planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-RESEARCH.md § "REQ-POC-TRUST-01 → cli.rs SetupArgs surface" (lines 24-58) AND § "setup.rs phase-step surface" (lines 60-194)
    - .planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-PATTERNS.md § "crates/nono-cli/src/cli.rs" and § "crates/nono-cli/src/setup.rs" (lines 43-68)
    - .planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-CONTEXT.md D-49-B1 (byte-copy), D-49-B2 (best-effort cleanup), D-49-B3 (stdout shape + Source breadcrumb)
  </read_first>
  <behavior>
    - `nono setup --from-file <p>` parses successfully when used alone.
    - `nono setup --from-file <p> --refresh-trust-root` is rejected at clap-parse time with stderr containing "cannot be used with" (clap's built-in conflict message).
    - Inside `from_file_step`, the validation order is: (1) `load_trusted_root(src)`, (2) `check_trusted_root_freshness(&root, &cache_path)`, (3) `std::fs::copy(src, &cache_path)` with best-effort cleanup on Err.
    - Stdout shape after success:
      ```
      [{X}/{N}] Loading Sigstore trusted root from file...
        * Sigstore trusted root cached at {cache_path}
        * Source: {src_path}

      ```
      where `{X}` and `{N}` are the same arithmetic as the `--refresh-trust-root` path (shared phase-index slot per clap-mutex).
    - On validation failure (parse error, expiry error, IO error), the function returns `Err` before any cache write — `cache_path` is unchanged from its pre-invocation state.
    - On copy failure (mid-write IO error), `cache_path` is removed via `let _ = std::fs::remove_file(&cache_path);` and the original `NonoError::Io` is propagated.
  </behavior>
  <action>
**Step 1: Add the `from_file` clap arg to `SetupArgs` in `crates/nono-cli/src/cli.rs`.**

Locate the existing `refresh_trust_root` field around line 2369-2370. Insert IMMEDIATELY AFTER it (before the `pub profiles: bool,` field):

```rust
    /// Populate the cached Sigstore trusted root from a local JSON file (skips network fetch).
    ///
    /// Validates the file via the same pipeline `nono trust verify` uses
    /// (`TrustedRoot::from_file` parse + tlog freshness gate), then writes
    /// it verbatim to `<nono_home>/.nono/trust-root/trusted_root.json`. Use
    /// this flag when `--refresh-trust-root` fails (e.g., stale embedded TUF
    /// anchor after a Sigstore root rotation) — POC users can download
    /// `trusted_root.json` from a GitHub Release and `--from-file` it.
    #[arg(long, value_name = "PATH", help_heading = "OPTIONS", conflicts_with = "refresh_trust_root")]
    pub from_file: Option<std::path::PathBuf>,
```

Use `std::path::PathBuf` literal (not a bare `PathBuf`) UNLESS the existing `SetupArgs` already imports `PathBuf` at the file/module level — verify via `grep -n "use std::path::PathBuf\|PathBuf" crates/nono-cli/src/cli.rs | head -5`. If the import exists, use the unqualified `PathBuf`.

**Step 2: Add the `from_file` field to `SetupRunner` in `crates/nono-cli/src/setup.rs`.**

Locate `pub struct SetupRunner` (~line 20-29). Add a new field AFTER `refresh_trust_root: bool,`:

```rust
    from_file: Option<std::path::PathBuf>,
```

(Use the same `PathBuf` qualifier convention as the `SetupArgs` field above — match whatever the file imports.)

**Step 3: Wire `from_file` in `SetupRunner::new` (or `SetupRunner::from_args` — read setup.rs:31-49 to confirm name).**

Add immediately after the `refresh_trust_root: args.refresh_trust_root,` line:

```rust
    from_file: args.from_file.clone(),
```

**Step 4: Thread `from_file` through phase-index arithmetic.**

Read `setup.rs:700-810` to find the EXACT lines of `total_phases()` and `refresh_trust_root_phase_index()`. The RESEARCH.md notes these sites are at approximately lines 719, 723, 740, 744, 795. Each of these counts `usize::from(self.refresh_trust_root)`. Replace EACH such site with:

```rust
usize::from(self.refresh_trust_root || self.from_file.is_some())
```

This makes the two flags share the same slot (clap-mutex guarantees they cannot both be true). Avoids F-01-07 off-by-one.

**IMPORTANT:** Do NOT introduce a new `from_file_phase_index()` helper. The clap-mutex contract means the shared `refresh_trust_root_phase_index()` is correct for BOTH branches.

**Step 5: Add the `from_file_step` branch in `SetupRunner::run`.**

Locate the existing branch around `setup.rs:91`:

```rust
if !self.check_only && self.refresh_trust_root {
    self.refresh_trust_root_step()?;
}
```

Add a sibling branch immediately below (clap-mutex guarantees the two cannot both be true):

```rust
if !self.check_only {
    if let Some(path) = self.from_file.as_ref() {
        self.from_file_step(path)?;
    }
}
```

**Step 6: Implement `from_file_step` in `setup.rs`, immediately BELOW `refresh_trust_root_step` (around line 861, before the `#[cfg(target_os = "macos")] fn installation_platform_label` block at line 863).**

```rust
    /// Populate the cached Sigstore trusted root from a user-supplied JSON file.
    ///
    /// Validates via the same pipeline `nono trust verify` uses
    /// (`nono::trust::bundle::load_trusted_root` parse +
    /// `nono::trust::bundle::check_trusted_root_freshness` gate),
    /// then byte-copies the validated input to the cache path.
    /// Fail-closed on any validation or IO error — no partial cache file
    /// is left on disk (D-49-B2 best-effort cleanup).
    ///
    /// Phase 49 D-49-B1 (verbatim copy, no re-serialize) + D-49-B2
    /// (best-effort cleanup on copy failure) + D-49-B3 (Source breadcrumb).
    fn from_file_step(&self, src: &std::path::Path) -> Result<()> {
        let cache_dir = crate::config::nono_home_dir()?
            .join(".nono")
            .join("trust-root");
        std::fs::create_dir_all(&cache_dir).map_err(NonoError::Io)?;

        println!(
            "[{}/{}] Loading Sigstore trusted root from file...",
            self.refresh_trust_root_phase_index(),
            self.total_phases()
        );

        // Step 1: schema/parse validation via existing pipeline (D-49-B1, SPEC.md
        // "no new schema validator" — reuses TrustedRoot::from_file).
        let trusted_root = nono::trust::bundle::load_trusted_root(src).map_err(|e| {
            NonoError::Setup(format!(
                "invalid Sigstore trusted root at {}: {e}",
                src.display()
            ))
        })?;

        let cache_path = cache_dir.join("trusted_root.json");

        // Step 2: freshness gate (D-32-03 tlog validFor.end expiry — reuses
        // bundle::check_trusted_root_freshness, widened to pub in Task 1).
        nono::trust::bundle::check_trusted_root_freshness(&trusted_root, &cache_path).map_err(
            |e| {
                NonoError::Setup(format!(
                    "Sigstore trusted root at {} failed freshness check: {e}",
                    src.display()
                ))
            },
        )?;

        // Step 3: byte-identical copy (D-49-B1) with best-effort cleanup on Err
        // (D-49-B2 — cache is fully-written-or-absent, never partial).
        if let Err(e) = std::fs::copy(src, &cache_path) {
            let _ = std::fs::remove_file(&cache_path);
            return Err(NonoError::Io(e));
        }

        println!(
            "  * Sigstore trusted root cached at {}",
            cache_path.display()
        );
        println!("  * Source: {}", src.display()); // D-49-B3 breadcrumb
        println!();
        Ok(())
    }
```

**No `.unwrap()` / `.expect()`** anywhere — every `?` propagates `NonoError::Io` or `NonoError::Setup`.

**Step 7: Verify build:**

```bash
cargo build -p nono-cli
cargo clippy -p nono-cli -- -D warnings -D clippy::unwrap_used
cargo fmt --all --check
```

**Step 8: Manual smoke (do not commit any output):**

```bash
# Should succeed:
cargo run -p nono-cli -- setup --from-file crates/nono/tests/fixtures/trust-root-frozen.json --check-only
# (--check-only short-circuits before from_file_step runs, so this just confirms clap accepts the flag)

# Should fail at clap-parse time with "cannot be used with":
cargo run -p nono-cli -- setup --from-file crates/nono/tests/fixtures/trust-root-frozen.json --refresh-trust-root
echo $?  # non-zero
```

(Smoke output is for the executor's confidence; the rigorous coverage lands in Task 3.)
  </action>
  <verify>
    <automated>cargo build -p nono-cli &amp;&amp; cargo clippy -p nono-cli -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo fmt --all --check</automated>
  </verify>
  <acceptance_criteria>
    - `grep -n "from_file" crates/nono-cli/src/cli.rs` returns at least one match showing `pub from_file: Option<...>` inside `SetupArgs`.
    - `grep -n 'conflicts_with = "refresh_trust_root"' crates/nono-cli/src/cli.rs` returns exactly one match (on the new `from_file` field).
    - `grep -n "from_file" crates/nono-cli/src/setup.rs` returns at least 4 matches (struct field + `from_args`/`new` wiring + `run` branch + `from_file_step` body).
    - `grep -n "fn from_file_step" crates/nono-cli/src/setup.rs` returns exactly one match.
    - `grep -nc "self.refresh_trust_root || self.from_file.is_some()" crates/nono-cli/src/setup.rs` returns a count >= 5 (one per existing phase-index site that previously used `usize::from(self.refresh_trust_root)`).
    - `grep -n 'std::fs::copy(src,' crates/nono-cli/src/setup.rs` returns exactly one match (D-49-B1 byte-copy).
    - `grep -n 'std::fs::remove_file(&cache_path)' crates/nono-cli/src/setup.rs` returns at least one match (D-49-B2 cleanup).
    - `grep -n '"  \* Source: ' crates/nono-cli/src/setup.rs` returns exactly one match (D-49-B3 breadcrumb).
    - `grep -n '"\[{}/{}\] Loading Sigstore trusted root from file' crates/nono-cli/src/setup.rs` returns exactly one match (D-49-B3 header shape).
    - `cargo build -p nono-cli` exits 0.
    - `cargo clippy -p nono-cli -- -D warnings -D clippy::unwrap_used` exits 0.
    - `cargo fmt --all --check` exits 0.
    - `grep -v '^[[:space:]]*//' crates/nono-cli/src/setup.rs | grep -c "\.unwrap()\|\.expect("` returns 0 inside the new `from_file_step` block (comment-stripped grep; CLAUDE.md unwrap policy).
    - Manual smoke: `cargo run -p nono-cli -- setup --from-file /tmp/x --refresh-trust-root 2>&1 | grep -q "cannot be used"` exits 0.
    - Validates: F-01-01 (clap-mutex), F-01-05 (stdout shape — verified more rigorously in Task 3), F-01-07 (phase-index sharing).
  </acceptance_criteria>
  <done>
    `--from-file` parses, the `from_file_step` is wired in `SetupRunner::run`, the phase-index arithmetic counts both flags into a shared slot, validation runs BEFORE any cache write, and best-effort cleanup runs on copy failure. `cargo build` + `cargo clippy` + `cargo fmt` all green.
  </done>
</task>

<task type="auto" tdd="true">
  <name>Task 3: Add integration tests for `--from-file` covering F-01-01 through F-01-07</name>
  <files>crates/nono-cli/tests/setup_trust_root.rs</files>
  <read_first>
    - crates/nono-cli/tests/setup_trust_root.rs (entire file — 149 lines; reuse `nono_bin`, `run_nono`, `setup_isolated_home` helpers verbatim)
    - crates/nono/tests/fixtures/trust-root-frozen.json (entire file — the 126-line fixture is the input to mutation logic; confirm both tlogs have `publicKey.validFor` with only a `start` key)
    - .planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-RESEARCH.md § "Integration test pattern" (lines 213-265) AND § "Fixture mutation surface" (lines 267-294)
    - .planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-PATTERNS.md § "crates/nono-cli/tests/setup_from_file.rs" (lines 90-108)
    - .planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-VALIDATION.md § "Failure Modes (Nyquist Dimension 8) → REQ-POC-TRUST-01" (lines 56-68) — IDs F-01-01 through F-01-07
    - .planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-CONTEXT.md D-49-D1 (TempDir fixture mutation), D-49-D2 (integration test via cargo_bin)
  </read_first>
  <behavior>
    - Each test runs hermetically (per-test `TempDir`; env vars set on the child process only via `run_nono`, not on the parent process — matches the existing file's pattern).
    - Each test asserts process exit status + cache-path state (existence / byte-identity / absence) + stderr/stdout substrings.
    - The expired-input mutation INSERTS `"end": "1970-01-01T00:00:00Z"` into BOTH tlogs' `publicKey.validFor` objects via `serde_json::Value` round-trip (the frozen fixture's tlogs have ONLY `validFor.start` — see RESEARCH.md fixture surprise).
    - The mutation logic targets camelCase JSON keys (`validFor`, `publicKey`).
    - `cargo test -p nono-cli --test setup_trust_root` runs all new tests in under 30 seconds.
  </behavior>
  <action>
**APPEND** the following tests to `crates/nono-cli/tests/setup_trust_root.rs` (keep the existing 3 tests intact). Add the helper functions at the bottom of the file, and the test functions immediately above the helpers.

**Step 1: Add required imports at the top (only if not already present).** The existing file already imports `std::fs`, `std::path::{Path, PathBuf}`, `std::process::{Command, Output}`. Add:

```rust
use serde_json::Value;
```

This will require the test build to use `serde_json` — verify `crates/nono-cli/Cargo.toml` `[dev-dependencies]` already includes `serde_json` (it should, given the existing test on line 72 uses `serde_json::from_str`).

**Step 2: Add a helper at the bottom of the file (after the last test):**

```rust
/// Path to the frozen Sigstore trusted-root fixture, resolved from the
/// `nono-cli` crate manifest dir up to `crates/nono/tests/fixtures/`.
fn frozen_fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("nono")
        .join("tests")
        .join("fixtures")
        .join("trust-root-frozen.json")
}

/// Reads the frozen fixture, mutates BOTH tlogs' `publicKey.validFor`
/// to insert `"end": "1970-01-01T00:00:00Z"` (forcing the freshness
/// gate to fail — RESEARCH.md fixture surprise: tlogs only have `start`,
/// no `end`, so any tlog without `end` is treated as active).
///
/// JSON keys are camelCase (`validFor`, `publicKey`) per
/// `sigstore_verify`'s proto-generated serde renames.
fn write_expired_fixture(dst: &Path) {
    let raw = fs::read_to_string(frozen_fixture_path()).expect("read frozen fixture");
    let mut root: Value = serde_json::from_str(&raw).expect("parse frozen fixture as JSON");
    let tlogs = root
        .get_mut("tlogs")
        .and_then(|v| v.as_array_mut())
        .expect("tlogs is a JSON array");
    assert!(
        tlogs.len() >= 1,
        "expected at least one tlog in the frozen fixture"
    );
    for tlog in tlogs.iter_mut() {
        let valid_for = tlog
            .get_mut("publicKey")
            .and_then(|pk| pk.get_mut("validFor"))
            .and_then(|vf| vf.as_object_mut())
            .expect("tlog.publicKey.validFor is a JSON object");
        valid_for.insert(
            "end".to_string(),
            Value::String("1970-01-01T00:00:00Z".to_string()),
        );
    }
    let mutated = serde_json::to_string_pretty(&root).expect("serialize mutated fixture");
    fs::write(dst, mutated).expect("write expired fixture");
}

/// Writes the first 100 bytes of the frozen fixture to `dst` —
/// forces `TrustedRoot::from_file` deserialize failure (truncation case).
fn write_truncated_fixture(dst: &Path) {
    let raw = fs::read(frozen_fixture_path()).expect("read frozen fixture");
    let truncated = &raw[..100.min(raw.len())];
    fs::write(dst, truncated).expect("write truncated fixture");
}

/// Writes the frozen fixture to `dst` with the first `"` byte flipped to
/// `'` — distinct JSON parse-error class from truncation.
fn write_quote_flipped_fixture(dst: &Path) {
    let mut raw = fs::read(frozen_fixture_path()).expect("read frozen fixture");
    let idx = raw
        .iter()
        .position(|&b| b == b'"')
        .expect("frozen fixture contains a double-quote byte");
    raw[idx] = b'\'';
    fs::write(dst, raw).expect("write quote-flipped fixture");
}
```

**Step 3: Add the 6 new test functions IMMEDIATELY ABOVE the helpers (and after the existing `setup_check_only_reports_stale_cache_with_recovery_hint` test):**

```rust
/// F-01-05 + happy-path: `nono setup --from-file <good>.json` exits 0 and
/// writes a cache file byte-identical to the input. Also asserts the
/// D-49-B3 stdout shape (`[X/N] Loading Sigstore trusted root from file...`
/// + `* Source: <abs_path>` lines).
#[test]
fn from_file_happy_path_writes_byte_identical_cache_and_stdout_matches_shape() {
    let (_tmp, home, workspace) = setup_isolated_home();
    let src = home.join("input.json");
    fs::copy(frozen_fixture_path(), &src).expect("copy frozen fixture to src");

    let src_arg = src.to_string_lossy().into_owned();
    let output = run_nono(&["setup", "--from-file", &src_arg], &home, &workspace);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "setup --from-file must succeed on a known-good fixture; stderr:\n{stderr}\nstdout:\n{stdout}"
    );

    let cache_path = home
        .join(".nono")
        .join("trust-root")
        .join("trusted_root.json");
    assert!(cache_path.exists(), "cache file must exist at {cache_path:?}");

    let src_bytes = fs::read(&src).expect("read src");
    let cache_bytes = fs::read(&cache_path).expect("read cache");
    assert_eq!(
        src_bytes, cache_bytes,
        "cache file must be byte-identical to the input (D-49-B1)"
    );

    // D-49-B3 stdout shape — verb "Loading", + Source: breadcrumb.
    assert!(
        stdout.contains("Loading Sigstore trusted root from file"),
        "stdout must contain 'Loading...' verb (D-49-B3); got:\n{stdout}"
    );
    assert!(
        stdout.contains("Sigstore trusted root cached at"),
        "stdout must contain 'cached at' line mirroring --refresh-trust-root; got:\n{stdout}"
    );
    assert!(
        stdout.contains("* Source: "),
        "stdout must contain 'Source:' breadcrumb (D-49-B3); got:\n{stdout}"
    );
}

/// F-01-07: `--from-file` and `--refresh-trust-root` share the same
/// phase-index slot (clap-mutex contract; counting them as separate slots
/// would break the displayed `[X/N]` counter). Asserts that the `[X/N]`
/// header in `--from-file` stdout has the SAME `X` value as the
/// `--refresh-trust-root` path would produce. Since both phases yield
/// `X = total_active_phases` when only one trust-root flag is set, and
/// `total_active_phases = 1` when only `--from-file` is set (no profiles,
/// no shell integration), the header MUST display `[1/1]`.
#[test]
fn from_file_phase_index_uses_shared_slot() {
    let (_tmp, home, workspace) = setup_isolated_home();
    let src = home.join("input.json");
    fs::copy(frozen_fixture_path(), &src).expect("copy frozen fixture to src");

    let src_arg = src.to_string_lossy().into_owned();
    let output = run_nono(&["setup", "--from-file", &src_arg], &home, &workspace);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "happy-path required for phase-index test; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("[1/1] Loading Sigstore trusted root from file"),
        "expected '[1/1] Loading...' header (single active phase = --from-file); got:\n{stdout}"
    );
}

/// F-01-02: `nono setup --from-file <expired>.json` exits non-zero with
/// a freshness-error stderr, and the cache file is NOT modified.
#[test]
fn from_file_expired_fails_closed() {
    let (_tmp, home, workspace) = setup_isolated_home();
    let src = home.join("expired.json");
    write_expired_fixture(&src);

    let cache_path = home
        .join(".nono")
        .join("trust-root")
        .join("trusted_root.json");
    // Pre-assert cache is absent.
    assert!(!cache_path.exists(), "cache should be absent before run");

    let src_arg = src.to_string_lossy().into_owned();
    let output = run_nono(&["setup", "--from-file", &src_arg], &home, &workspace);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        !output.status.success(),
        "expired fixture must exit non-zero; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("freshness")
            || stderr.contains("expired")
            || stderr.contains("STALE")
            || stderr.to_lowercase().contains("expir"),
        "stderr must reference freshness/expiry; got stderr:\n{stderr}"
    );
    assert!(
        !cache_path.exists(),
        "cache file must NOT be created on freshness failure (D-49-B2 fail-closed); found at {cache_path:?}"
    );
}

/// F-01-03 (truncation case): malformed JSON (truncation) exits non-zero
/// with a parse-error stderr, cache untouched.
#[test]
fn from_file_malformed_truncated_fails_closed() {
    let (_tmp, home, workspace) = setup_isolated_home();
    let src = home.join("truncated.json");
    write_truncated_fixture(&src);

    let cache_path = home
        .join(".nono")
        .join("trust-root")
        .join("trusted_root.json");

    let src_arg = src.to_string_lossy().into_owned();
    let output = run_nono(&["setup", "--from-file", &src_arg], &home, &workspace);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "truncated fixture must exit non-zero; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("invalid Sigstore trusted root")
            || stderr.to_lowercase().contains("parse")
            || stderr.to_lowercase().contains("eof")
            || stderr.to_lowercase().contains("expected"),
        "stderr must reference parse failure; got stderr:\n{stderr}"
    );
    assert!(
        !cache_path.exists(),
        "cache file must NOT be created on parse failure"
    );
}

/// F-01-03 (quote-flip case): a single-byte JSON corruption (distinct
/// parse-error class from truncation) exits non-zero, cache untouched.
#[test]
fn from_file_malformed_quote_flipped_fails_closed() {
    let (_tmp, home, workspace) = setup_isolated_home();
    let src = home.join("quote_flipped.json");
    write_quote_flipped_fixture(&src);

    let cache_path = home
        .join(".nono")
        .join("trust-root")
        .join("trusted_root.json");

    let src_arg = src.to_string_lossy().into_owned();
    let output = run_nono(&["setup", "--from-file", &src_arg], &home, &workspace);
    assert!(
        !output.status.success(),
        "quote-flipped fixture must exit non-zero"
    );
    assert!(
        !cache_path.exists(),
        "cache file must NOT be created on parse failure"
    );
}

/// F-01-04: missing source path exits non-zero with an IO-error stderr,
/// cache untouched (no partial cache written).
#[test]
fn from_file_missing_path_no_partial_cache() {
    let (_tmp, home, workspace) = setup_isolated_home();
    let src = home.join("does_not_exist.json");
    assert!(!src.exists(), "test precondition: src must not exist");

    let cache_path = home
        .join(".nono")
        .join("trust-root")
        .join("trusted_root.json");

    let src_arg = src.to_string_lossy().into_owned();
    let output = run_nono(&["setup", "--from-file", &src_arg], &home, &workspace);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "missing path must exit non-zero; stderr:\n{stderr}"
    );
    assert!(
        !cache_path.exists(),
        "cache file must NOT be created on missing-path failure (D-49-B2 fail-closed)"
    );
}

/// F-01-01: `--from-file <p> --refresh-trust-root` is rejected at
/// clap-parse time with a non-zero exit and a "cannot be used with"
/// style stderr message.
#[test]
fn from_file_with_refresh_rejected_by_clap() {
    let (_tmp, home, workspace) = setup_isolated_home();
    let src = home.join("any.json");
    fs::copy(frozen_fixture_path(), &src).expect("copy frozen fixture");

    let src_arg = src.to_string_lossy().into_owned();
    let output = run_nono(
        &["setup", "--from-file", &src_arg, "--refresh-trust-root"],
        &home,
        &workspace,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "clap-mutex must reject --from-file + --refresh-trust-root; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("cannot be used with"),
        "stderr must contain clap's 'cannot be used with' message; got stderr:\n{stderr}"
    );

    // Cache MUST NOT exist (clap rejection happens before any FS write).
    let cache_path = home
        .join(".nono")
        .join("trust-root")
        .join("trusted_root.json");
    assert!(
        !cache_path.exists(),
        "clap-mutex rejection must happen before any FS write; cache should not exist"
    );
}
```

**Step 4: Run the new tests and verify they pass.**

```bash
cargo test -p nono-cli --test setup_trust_root from_file
```

All 7 new tests must pass (6 listed above + the existing happy-path-with-stdout test counts as one). The existing 3 tests (`setup_refresh_trust_root_writes_cache` — `#[ignore]`d; `setup_check_only_reports_uninitialized_cache`; `setup_check_only_reports_stale_cache_with_recovery_hint`) must continue to pass.

**Step 5: Run the full test file:**

```bash
cargo test -p nono-cli --test setup_trust_root
```

Must show: `test result: ok. N passed; 0 failed; 1 ignored;` where N is the count of non-ignored tests (existing 2 hermetic + 7 new = 9; ignored 1 = `setup_refresh_trust_root_writes_cache` per its `#[ignore]` attribute).
  </action>
  <verify>
    <automated>cargo test -p nono-cli --test setup_trust_root</automated>
  </verify>
  <acceptance_criteria>
    - `grep -c "^#\[test\]" crates/nono-cli/tests/setup_trust_root.rs` returns 9 (3 existing + 6 new — including the merged happy-path-with-stdout-shape test that covers BOTH the F-01-05 stdout shape and the happy-path byte-identity in one test).
    - `grep -nc "fn from_file_" crates/nono-cli/tests/setup_trust_root.rs` returns at least 6 (test fn declarations).
    - `grep -n 'fn write_expired_fixture\|fn write_truncated_fixture\|fn write_quote_flipped_fixture\|fn frozen_fixture_path' crates/nono-cli/tests/setup_trust_root.rs` returns 4 matches (helper fns).
    - `grep -n '"end".to_string()' crates/nono-cli/tests/setup_trust_root.rs` returns at least one match (D-49-D1 expired-mutation via insert into camelCase `validFor`).
    - `grep -n '"1970-01-01T00:00:00Z"' crates/nono-cli/tests/setup_trust_root.rs` returns at least one match.
    - `grep -n '"validFor"' crates/nono-cli/tests/setup_trust_root.rs` returns at least one match (mutation logic targets camelCase, not snake_case — RESEARCH.md surprise).
    - `cargo test -p nono-cli --test setup_trust_root` exits 0 with `ok. 8 passed; 0 failed; 1 ignored` (or similar — exact count depends on whether the merged stdout-shape+happy-path test is one or two).
    - All 6 new `from_file_*` tests pass: `from_file_happy_path_*`, `from_file_phase_index_*`, `from_file_expired_*`, `from_file_malformed_truncated_*`, `from_file_malformed_quote_flipped_*`, `from_file_missing_path_*`, `from_file_with_refresh_rejected_*`.
    - `cargo fmt --all --check` exits 0.
    - Validates: F-01-01 (clap-mutex), F-01-02 (freshness), F-01-03 (parse, both cases), F-01-04 (no partial cache on IO error), F-01-05 (stdout shape), F-01-07 (phase-index shared slot). F-01-06 covered by Wave-close cross-target clippy. F-01-08 covered by Task 1 build smoke.
  </acceptance_criteria>
  <done>
    `cargo test -p nono-cli --test setup_trust_root` passes with 6 new `from_file_*` tests green. Mutation helpers target camelCase JSON keys per the fixture's actual shape. All fail-closed assertions confirm cache absence on every error path.
  </done>
</task>

<task type="checkpoint:human-verify" gate="blocking">
  <name>Task 4: Cross-target clippy verification (Linux + macOS targets)</name>
  <what-built>Tasks 1-3 created the `--from-file` flag wiring across `crates/nono-cli/src/{cli,setup}.rs` and `crates/nono/src/trust/{bundle,mod}.rs`. Both `cli.rs` and `setup.rs` contain `#[cfg(target_os = "windows")]` / `#[cfg(target_os = "macos")]` / `#[cfg(target_os = "linux")]` blocks. Per CLAUDE.md MUST/NEVER bullet + `.planning/templates/cross-target-verify-checklist.md`, cross-target clippy on Linux AND macOS MUST run from the dev host before this REQ flips to VERIFIED.</what-built>
  <how-to-verify>
1. Run on the dev host:
   ```bash
   cargo clippy --workspace -- -D warnings -D clippy::unwrap_used                                          # Windows host (native)
   cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used         # Linux cross
   cargo clippy --workspace --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used               # macOS cross
   ```
2. Expected outcomes:
   - **All three clean** → REQ-POC-TRUST-01 may be flipped to VERIFIED at codebase level. Reply `clean` and record SHAs.
   - **Cross-toolchain missing** (e.g., `error: linker x86_64-linux-gnu-gcc not found` or `error: could not find native static library...`) → mark REQ as PARTIAL per `.planning/templates/cross-target-verify-checklist.md § PARTIAL Disposition`. Reply `PARTIAL: <reason>` and the orchestrator/checker will record the live-CI deferral.
   - **Errors reported by clippy on a target** → close errors first; do NOT flip to VERIFIED. Reply with the clippy output.
3. Document the outcome in the eventual `49-01-SUMMARY.md` § "Verification" using the exact prose from `.planning/templates/cross-target-verify-checklist.md § PARTIAL Disposition Step 4` if PARTIAL.
  </how-to-verify>
  <resume-signal>Type `clean`, `PARTIAL: <reason>`, or paste the clippy error output.</resume-signal>
  <files>n/a (verification-only task; no source files modified)</files>
  <action>Execute the three cargo clippy commands from the &lt;how-to-verify&gt; block above on the dev host, in this exact order: (1) Windows-host native workspace clippy, (2) `--target x86_64-unknown-linux-gnu`, (3) `--target x86_64-apple-darwin`. Capture exit codes and any error output. If a cross-toolchain is missing, follow the PARTIAL Disposition from `.planning/templates/cross-target-verify-checklist.md` exactly — mark REQ-POC-TRUST-01 PARTIAL and reference the live GH Actions clippy lane on the head SHA as the decisive signal. Do NOT flip to VERIFIED until all three commands clean OR PARTIAL is formally recorded.</action>
  <verify>
    <automated>cargo clippy --workspace -- -D warnings -D clippy::unwrap_used</automated>
  </verify>
  <done>All three clippy invocations attempted; outcome recorded in SUMMARY as `clean` OR `PARTIAL` (with the exact PARTIAL Disposition prose from the checklist template).</done>
  <acceptance_criteria>
    - All three clippy invocations attempted from the dev host.
    - Outcome recorded: `clean` OR `PARTIAL` (with reason) OR errors-then-fixed.
    - If PARTIAL: REQ-POC-TRUST-01 verification status is `human_needed` pending live CI on the head SHA.
    - Validates: F-01-06 (cross-target clippy regression).
  </acceptance_criteria>
</task>

</tasks>

<verification>
- `cargo build -p nono` (Task 1 — vis-widen does not regress nono crate).
- `cargo build -p nono-cli` (Task 2 — `from_file` field wires through cli.rs + setup.rs without build errors).
- `cargo test -p nono trust::bundle` (Task 1 — bundle unit tests pass post vis-widen).
- `cargo test -p nono-cli --test setup_trust_root` (Task 3 — 6 new `from_file_*` integration tests pass).
- `cargo clippy --workspace -- -D warnings -D clippy::unwrap_used` (Windows host native).
- `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` (Task 4 — F-01-06; PARTIAL allowed).
- `cargo clippy --workspace --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used` (Task 4 — F-01-06; PARTIAL allowed).
- `cargo fmt --all --check`.

Manual smoke (executor records in SUMMARY):
- `cargo run -p nono-cli -- setup --from-file crates/nono/tests/fixtures/trust-root-frozen.json` succeeds on a clean test home (set `NONO_TEST_HOME` to a tmp path); cache file at `<NONO_TEST_HOME>/.nono/trust-root/trusted_root.json` is byte-identical to the input.
</verification>

<success_criteria>
- [ ] `pub fn check_trusted_root_freshness` reachable from `crates/nono-cli`; no regression in `cargo test -p nono trust::bundle` (F-01-08).
- [ ] `--from-file <PATH>` clap arg exists on `SetupArgs` with `conflicts_with = "refresh_trust_root"` (F-01-01).
- [ ] `from_file_step` validates input via `load_trusted_root` + `check_trusted_root_freshness` BEFORE any cache write; fail-closed on any validation error (F-01-02, F-01-03).
- [ ] `from_file_step` does verbatim `std::fs::copy` (D-49-B1); on copy failure, best-effort `remove_file` cleans up (D-49-B2) before propagating `NonoError::Io` (F-01-04).
- [ ] Stdout shape on success: `[X/N] Loading Sigstore trusted root from file...` + `* Sigstore trusted root cached at <path>` + `* Source: <src>` (D-49-B3 / F-01-05).
- [ ] Phase-index arithmetic counts `self.refresh_trust_root || self.from_file.is_some()` as a single slot (F-01-07).
- [ ] 6 new integration tests in `crates/nono-cli/tests/setup_trust_root.rs` all pass.
- [ ] `cargo build -p nono-cli`, `cargo clippy -p nono-cli -- -D warnings -D clippy::unwrap_used`, and `cargo fmt --all --check` all green on the dev host.
- [ ] Cross-target clippy on `x86_64-unknown-linux-gnu` + `x86_64-apple-darwin` either clean OR documented PARTIAL per `.planning/templates/cross-target-verify-checklist.md § PARTIAL Disposition` (F-01-06).
- [ ] No `.unwrap()` / `.expect()` introduced in production code (only in `#[cfg(test)]` / test modules per CLAUDE.md).
- [ ] No new `#[allow(dead_code)]` introduced (CLAUDE.md "lazy use of dead code" rule).
- [ ] DCO sign-off on the single atomic `feat(49-01):` commit.
</success_criteria>

<commit_shape>
Single atomic commit:

```
feat(49-01): nono setup --from-file flag for trusted_root.json

Add --from-file <PATH> to `nono setup` so POC users can populate the cached
Sigstore trusted root from a local JSON file (e.g., a GitHub Release asset)
without depending on the upstream-embedded TUF anchor in sigstore-verify.

Reuses the existing validation pipeline (`load_trusted_root` parse +
`check_trusted_root_freshness` D-32-03 expiry gate); the freshness fn is
widened from module-private to `pub` to make it callable from nono-cli.
Byte-identical `std::fs::copy` of the validated input (D-49-B1) with
best-effort cleanup on IO failure (D-49-B2). Mutually exclusive with
--refresh-trust-root via clap `conflicts_with`. Stdout adds a `Source:`
breadcrumb (D-49-B3) for debug ergonomics.

REQ-POC-TRUST-01. Closes the dep-bump treadmill for POC unblocking;
future Sigstore rotations require only fixture refresh per Phase 49-03
cadence template, not a sigstore-verify Cargo.toml bump.

Tests cover F-01-01 through F-01-07 in
crates/nono-cli/tests/setup_trust_root.rs (extends existing file rather
than create a new one — adjacent test cases live together).

Cross-target clippy: see SUMMARY for verifier disposition (clean or
PARTIAL per .planning/templates/cross-target-verify-checklist.md).

Signed-off-by: Oscar Mack Jr. <oscar.mack.jr@gmail.com>
```
</commit_shape>

<output>
After completion, create `.planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-01-SUMMARY.md` per `$HOME/.claude/get-shit-done/templates/summary.md`. Required sections:
- Verification: per-task automated commands run + outcomes.
- Cross-target clippy: explicit clean / PARTIAL disposition with the live-CI lane named if PARTIAL.
- Files modified: 5 (cli.rs, setup.rs, bundle.rs, trust/mod.rs, setup_trust_root.rs).
- Tests added: 6 new `from_file_*` cases + 4 helpers.
- Commit SHA: single atomic `feat(49-01):` commit.
</output>
