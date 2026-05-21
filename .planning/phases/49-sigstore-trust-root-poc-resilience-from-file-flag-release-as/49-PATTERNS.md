---
phase: 49
phase_name: sigstore-trust-root-poc-resilience-from-file-flag-release-as
generated: 2026-05-21
sourced_from: [49-CONTEXT.md, 49-RESEARCH.md, 49-SPEC.md]
status: Ready for planning
---

# Phase 49 Pattern Map

**Mapped:** 2026-05-21
**Files analyzed:** 10 (6 modified, 4 new)
**Analogs found:** 9 / 10 (1 net-new with no codebase analog; mirrors external template shape)

This file is a **structural reorganization** of pre-decided file lists, line ranges, and pattern excerpts already locked in `49-CONTEXT.md` and `49-RESEARCH.md`. No new analog discovery was performed — all excerpts are sourced from RESEARCH.md sections. Where RESEARCH.md already shows the verbatim excerpt at sufficient detail, this file references that section rather than duplicating.

## File Classification

| New / Modified | File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|---|
| Modified | `crates/nono-cli/src/cli.rs` | clap arg struct extension | request-response (CLI parse) | `SetupArgs::refresh_trust_root` field (cli.rs:2341-2387) | exact |
| Modified | `crates/nono-cli/src/setup.rs` | new phase-step + Setup struct extension | file-I/O (validate + copy) | `refresh_trust_root_step()` (setup.rs:820-860) | exact |
| Modified | `crates/nono/src/trust/bundle.rs` | visibility widening (`fn` → `pub fn`) | none (single-keyword edit) | other `pub` fns in same module | role-match |
| Modified | `crates/nono/src/trust/mod.rs` | re-export point | none (one-line `pub use`) | existing `pub use` lines in `trust/mod.rs` | role-match |
| New / Extension | `crates/nono-cli/tests/setup_from_file.rs` OR extend `crates/nono-cli/tests/setup_trust_root.rs` | integration test (assert_cmd OR raw `std::process::Command`) | request-response (process spawn) | `crates/nono-cli/tests/auto_pull_e2e_linux.rs` (raw Command pattern) + `setup_trust_root.rs` (already exists) | exact |
| Modified | `.github/workflows/release.yml` | CI step insertion (byte-identity assert + asset glob extension) | batch (CI step pipeline) | existing `softprops/action-gh-release` step + SHA256SUMS aggregation (release.yml:315-340) | exact |
| New | `.planning/templates/sigstore-rotation-refresh.md` | maintainer-cadence template | none (prose) | `.planning/templates/cross-target-verify-checklist.md` (78 lines, structural shape) | role-match |
| New | `scripts/verify-trust-root-cached.sh` | bash smoke script (~20 lines) | request-response (CLI wrap) | none — net-new file (mirror bash hygiene of other `scripts/*.sh`) | no-analog |
| New | `scripts/verify-trust-root-cached.ps1` | PowerShell smoke script (~20 lines) | request-response (CLI wrap) | none — net-new file (mirror exit-code propagation of other `scripts/*.ps1`) | no-analog |
| Modified | `docs/cli/development/windows-poc-handoff.mdx` | prose rewrite of "Known issue: Sigstore TUF root rotation" subsection + "Run once after install" block consistency edits | none (prose) | the same file's existing prose structure (lines 160-225) | exact |

**Surface partition:**
- **Plan 49-01:** `crates/nono-cli/src/{cli,setup}.rs` + `crates/nono/src/trust/{bundle,mod}.rs` (vis-widen + re-export) + `crates/nono-cli/tests/setup_*` test surface.
- **Plan 49-02:** `.github/workflows/release.yml` only.
- **Plan 49-03:** `.planning/templates/sigstore-rotation-refresh.md` + `scripts/verify-trust-root-cached.{sh,ps1}` + `docs/cli/development/windows-poc-handoff.mdx`.

---

## Pattern Assignments

### Modified Files

#### `crates/nono-cli/src/cli.rs` — SetupArgs clap extension (Plan 49-01)

- **Role:** clap derive struct gets new `from_file: Option<PathBuf>` field with `conflicts_with = "refresh_trust_root"`.
- **Closest analog:** `SetupArgs::refresh_trust_root` field at cli.rs:2369-2370 (verified in 49-RESEARCH.md "cli.rs SetupArgs surface").
- **Excerpt source:** 49-RESEARCH.md § "REQ-POC-TRUST-01 → cli.rs SetupArgs surface" — includes the verbatim current shape AND the proposed insertion shape with `#[arg(long, value_name = "PATH", help_heading = "OPTIONS", conflicts_with = "refresh_trust_root")]`.
- **Pattern to replicate:**
  - Same `help_heading = "OPTIONS"` convention as every other field in `SetupArgs`.
  - clap v4 derive `conflicts_with = "refresh_trust_root"` (field-name string spelling — Claude's-Discretion per CONTEXT.md; planner greps cli.rs for prior `conflicts_with` usage at plan-open).
  - Insertion point: immediately AFTER `refresh_trust_root` flag (line 2370), BEFORE `profiles` (line 2372).
  - Use `Option<PathBuf>` (not `Option<String>`) for type-safety; matches `dirs`-equivalent path resolution permitted in `nono-cli`.

#### `crates/nono-cli/src/setup.rs` — new phase-step + Setup wiring (Plan 49-01)

- **Role:** New `from_file_step(&self, src: &Path)` mirrors `refresh_trust_root_step()` shape (header + `create_dir_all` + validation pipeline + `std::fs::copy` + footer); `SetupRunner` struct gets new `from_file: Option<PathBuf>` field; `from_args` + `run` wired.
- **Closest analog:** `refresh_trust_root_step()` at setup.rs:820-860 + `SetupRunner` struct at setup.rs:20-29 + `SetupRunner::run` branch at setup.rs:91-93 (all verified in 49-RESEARCH.md).
- **Excerpt source:** 49-RESEARCH.md § "REQ-POC-TRUST-01 → setup.rs phase-step surface" — includes verbatim current `refresh_trust_root_step()` body AND skeleton `from_file_step()` body.
- **Pattern to replicate:**
  - **Verb tweak:** "Loading Sigstore trusted root from file..." replaces "Refreshing Sigstore trusted root..." (D-49-B3).
  - **Add `Source:` breadcrumb line:** `println!("  * Source: {}", src.display());` AFTER the cache-path line, before the trailing blank line (D-49-B3).
  - **D-49-B1 byte-identity:** `std::fs::copy(src, &cache_path)` — NOT `serde_json::to_string_pretty + fs::write` (the current `--refresh-trust-root` shape at setup.rs:849-852 IS the rejected pattern per D-49-B1).
  - **D-49-B2 best-effort cleanup:** on `std::fs::copy` Err, attempt `let _ = std::fs::remove_file(&cache_path);` (swallow inner error), then propagate original `NonoError::Io`. Cache is fully-written-or-absent — never partial.
  - **Validation pipeline:** call `nono::trust::bundle::load_trusted_root(src)?` THEN `nono::trust::bundle::check_trusted_root_freshness(&trusted_root, &cache_path)?` BEFORE the `std::fs::copy` — fail-closed validates input before any cache mutation.
  - **Phase-index threading:** `refresh_trust_root_phase_index()` (sites: setup.rs:719, 723, 740, 744, 795, 820) extended to count `usize::from(self.refresh_trust_root || self.from_file.is_some())` — both flags share the same slot (clap-mutex guarantees they cannot both be true). Avoids F-01-07 off-by-one.
  - **`SetupRunner::run` branch:** sibling branch under the existing `if !self.check_only && self.refresh_trust_root` block; planner chooses fold-into-same-`if` or distinct-`if-let-Some` for diff minimality.
  - **`from_args` wiring:** `from_file: args.from_file.clone(),` after the `refresh_trust_root:` line in `SetupRunner::new`.
  - **No `.unwrap()` / `.expect()`** anywhere — `?` propagation via `NonoError::Io` / `NonoError::Setup` only (CLAUDE.md `clippy::unwrap_used`).

#### `crates/nono/src/trust/bundle.rs` — visibility widen on `check_trusted_root_freshness` (Plan 49-01)

- **Role:** Flip `fn check_trusted_root_freshness(...)` at bundle.rs:247 from module-private to `pub` so `nono-cli` can invoke it directly.
- **Closest analog:** Other `pub fn` declarations in `crates/nono/src/trust/bundle.rs` (e.g., `load_trusted_root` at bundle.rs:113, `load_production_trusted_root` at bundle.rs:147 per 49-CONTEXT.md canonical refs).
- **Excerpt source:** 49-RESEARCH.md § "check_trusted_root_freshness accessibility" — confirms current visibility is private (no `pub` / no `pub(crate)`), recommends `pub fn` widen.
- **Pattern to replicate:**
  - **Minimal one-keyword change:** `fn check_trusted_root_freshness` → `pub fn check_trusted_root_freshness`.
  - **Signature unchanged:** `pub fn check_trusted_root_freshness(root: &TrustedRoot, cache_path: &Path) -> Result<()>` — caller passes destination cache path (used in the function's error-message path display), not the source path.
  - **SPEC justification:** RESEARCH.md confirms re-exposing an existing private fn is NOT "new code in `crates/nono`" — it's exposure of an existing one (SPEC.md "no new schema validator" wording is honored).
  - **Anti-pattern (rejected per RESEARCH.md):** factoring a new `pub fn validate_trusted_root(path: &Path) -> Result<TrustedRoot>` wrapper — heavier, risks SPEC-out-of-scope flag at review.

#### `crates/nono/src/trust/mod.rs` — `pub use` re-export point (Plan 49-01)

- **Role:** Add one-line `pub use bundle::check_trusted_root_freshness;` (or include in an existing `pub use bundle::{...}` block) so external callers reach it via `nono::trust::check_trusted_root_freshness` or stay at the full module path `nono::trust::bundle::check_trusted_root_freshness`.
- **Closest analog:** Existing `pub use` lines in `crates/nono/src/trust/mod.rs` — planner inventories at plan-open via `grep -n "pub use" crates/nono/src/trust/mod.rs`.
- **Excerpt source:** 49-RESEARCH.md § "check_trusted_root_freshness accessibility" → "Recommendation: flip to `pub fn` and add `pub use` in `crates/nono/src/trust/mod.rs`."
- **Pattern to replicate:**
  - Match the style of any existing `pub use bundle::{...}` block — if one already lists multiple items, append; if items are listed one-per-line, add one new line.
  - If `crates/nono-cli` already accesses the module via the full path `nono::trust::bundle::load_trusted_root`, the re-export at `trust/mod.rs` may be optional (the `pub fn` widen on bundle.rs alone is sufficient). Planner confirms at plan-open by checking the import shape in setup.rs at the call sites.

#### `crates/nono-cli/tests/setup_from_file.rs` (new) OR extension of `crates/nono-cli/tests/setup_trust_root.rs` (existing) — integration test (Plan 49-01)

- **Role:** Integration test covering F-01-01 through F-01-08 (49-RESEARCH.md Validation Architecture): happy path, clap-mutex, expired, malformed-truncation, malformed-quote-flip, missing path, cache leak on copy failure, stdout shape, phase-index continuity, build smoke for the vis-widen.
- **Closest analog:** `crates/nono-cli/tests/auto_pull_e2e_linux.rs` (raw `std::process::Command` + `env!("CARGO_BIN_EXE_nono")` + `tests/common::test_env::{lock_env, EnvVarGuard}`) per 49-RESEARCH.md § "Integration test pattern".
- **Excerpt source:** 49-RESEARCH.md § "REQ-POC-TRUST-01 → Integration test pattern" — verbatim canonical imports block AND per-test scaffold for `from_file_happy_path_writes_byte_identical_cache`.
- **Pattern to replicate:**
  - **Decision (planner at plan-open):** EXTEND existing `crates/nono-cli/tests/setup_trust_root.rs` rather than create a new file — RESEARCH.md confirms `setup_trust_root.rs` exists; adjacent test cases live together.
  - **Env-lock primitives (D-44-E6 mandatory):** `mod common; use common::test_env::{lock_env, EnvVarGuard};` — every test starts with `let _env_lock = lock_env(); let _home_guard = EnvVarGuard::set("NONO_TEST_HOME", tmp.path()); let _xdg_guard = EnvVarGuard::set("XDG_CONFIG_HOME", tmp.path());`. Phase 44 REQ-REVIEW-FU-01 D-44-E6 enforces this.
  - **Binary invocation:** raw `std::process::Command::new(env!("CARGO_BIN_EXE_nono"))` — NOT `assert_cmd` (CONTEXT.md says `assert_cmd` is in workspace, but RESEARCH.md notes the actual existing pattern in `auto_pull_e2e_linux.rs` is raw Command; planner verifies at plan-open via `grep -rn 'assert_cmd' crates/nono-cli/`).
  - **Per-test fixture mutation (D-49-D1):** in-TempDir mutation of `crates/nono/tests/fixtures/trust-root-frozen.json`:
    - **Expired:** insert `"end": "1970-01-01T00:00:00Z"` into BOTH tlogs' `publicKey.validFor` (RESEARCH.md fixture surprise — the frozen fixture has only `validFor.start`, not `end`; any tlog without `end` is treated as active).
    - **Malformed-truncation:** first 100 bytes only.
    - **Malformed-quote-flip:** flip first `"` byte → `'`.
    - **Missing-path:** TempDir-relative path that doesn't exist (no fs op needed).
  - **JSON key casing reminder:** mutation logic targets camelCase keys (`validFor`, `publicKey`, `rawBytes`) — `sigstore_verify`'s proto-generated `serde(rename_all = "camelCase")` style.
  - **No `#[cfg(target_os = "linux")]`** on the new test file — `--from-file` is cross-platform; tests run on all hosts.
  - **`#![allow(clippy::unwrap_used)]`** at the top of the test file (CLAUDE.md permits in test-only modules).
  - **No new dev-deps:** `tempfile` already in `crates/nono-cli/Cargo.toml [dev-dependencies]` per CONTEXT.md.

#### `.github/workflows/release.yml` — CI step insertion + asset glob extension (Plan 49-02)

- **Role:** New `Bundle Sigstore trusted_root.json as release asset` step (cp + SHA-256 byte-identity assert); extension of SHA256SUMS aggregation block; extension of `softprops/action-gh-release` `files:` glob.
- **Closest analog:** existing artifact-assembly step at release.yml:315-326 (SHA256SUMS aggregation) + existing `softprops/action-gh-release` step at release.yml:334-340 (verified in 49-RESEARCH.md "Release.yml insertion points").
- **Excerpt source:** 49-RESEARCH.md § "REQ-POC-TRUST-02 → Plan 49-02 minimal-diff insertion" — verbatim YAML for all three insertions (cp+assert step, SHA256SUMS extension, files-glob extension).
- **Pattern to replicate:**
  - **Insert location for cp+assert step:** BEFORE the SHA256SUMS aggregation (line 315), AFTER the `find . -name "*.deb" -exec mv {} . \;` line. RESEARCH.md recommends folding it INSIDE the existing aggregation step (same `runs-on: ubuntu-latest` step) since that block clearly chdirs to `artifacts/` (the `*.tar.gz` glob would otherwise fail). Avoids F-02-05 working-directory mismatch.
  - **`set -euo pipefail` is load-bearing** (F-02-04): bare `if [ ... ]` returns 0 even on syntax errors without `-e`; `| cut` pipe masks failures without `-o pipefail`.
  - **SHA256SUMS extension:** insert `if ls trusted_root.json >/dev/null 2>&1; then sha256sum trusted_root.json >> SHA256SUMS.txt; fi` BEFORE `cat SHA256SUMS.txt` at line 326 — mirrors the existing pattern for `*.zip` / `*.msi` / `*.exe` conditional aggregation.
  - **`files:` glob extension:** add one line `artifacts/trusted_root.json` to the `softprops/action-gh-release` `files:` block at line 340 (placement cosmetic — before or after `artifacts/SHA256SUMS.txt`).
  - **Byte-identity source path is repo-relative:** `crates/nono/tests/fixtures/trust-root-frozen.json` → `artifacts/trusted_root.json`. If folded into the artifacts-chdir step, the cp source needs absolute-or-back-traversal path; RESEARCH.md flags this as a reconcile point.

#### `docs/cli/development/windows-poc-handoff.mdx` — POC handoff doc rewrite (Plan 49-03)

- **Role:** Prose rewrite of the "Known issue: Sigstore TUF root rotation" subsection (lines 182-220) + consistency edits to the "Run once after install" block (lines 166-180).
- **Closest analog:** the same file's existing prose structure — RESEARCH.md identifies 5 specific stale assertions to fix.
- **Excerpt source:** 49-RESEARCH.md § "REQ-POC-TRUST-03 → POC handoff doc rewrite source" — enumerates all 5 stale lines (167, 184, 207, 209-211, 218) with replacement guidance.
- **Pattern to replicate:**
  - **Heading version-de-pin:** `#### Known issue: Sigstore TUF root rotation (sigstore-verify 0.6.5)` → `#### Known issue: Sigstore TUF root rotation` (line 184).
  - **Stale cross-ref removal:** delete `P32-DEFER-005 in .planning/phases/32-sigstore-integration/deferred-items.md` reference (line 207). Acceptance criterion REQ-POC-TRUST-03 (c) requires zero matches of `P32-DEFER-005` and `deferred-items.md`.
  - **Primary recommendation flip:** `nono setup --from-file <release-asset-url-downloaded-locally>` becomes the primary recommended path (replacing the direct-into-cache `Invoke-WebRequest -OutFile $cacheDir\trusted_root.json` at lines 209-211).
  - **Demote `Invoke-WebRequest`:** keep as a "if you can't reach the GitHub Releases page" fallback subsection — do not delete; some POC users will not have HTTPS to github.com/releases.
  - **Delete dep-treadmill prose:** line 218's "`--refresh-trust-root` will start working again once the dep is upgraded" is the prose pinning the doc to the treadmill Phase 49 exits.
  - **"Run once after install" block (lines 166-180):** add an `or nono setup --from-file <PATH>` alternative path; keep `--refresh-trust-root` as primary for network-reachable hosts.
  - **Acceptance criterion REQ-POC-TRUST-03 (e):** `grep -r "Known issue: Sigstore TUF root rotation" docs/cli/development/windows-poc-handoff.mdx` must return exactly one match whose surrounding lines no longer pin to a `sigstore-verify` version.

### New Files

#### `.planning/templates/sigstore-rotation-refresh.md` (Plan 49-03)

- **Role:** Maintainer-cadence template documenting Sigstore root rotation response procedure (6 sections per SPEC.md REQ-POC-TRUST-03 Target (a)).
- **Closest analog:** `.planning/templates/cross-target-verify-checklist.md` (78 lines — confirmed by 49-RESEARCH.md as the structural shape to mirror) + `.planning/templates/upstream-sync-quick.md`.
- **Excerpt source:** 49-RESEARCH.md § "REQ-POC-TRUST-03 → Existing template structural shape" — verbatim mirror of the section structure with phase-49-specific content placeholders.
- **Pattern to replicate:**
  - **Section structure (mirror cross-target-verify-checklist.md):** Scope / Decision Tree / Anti-Patterns / Enforcement (plus phase-49-specific Capture/Diff/Regression/Commit/Release-Asset-Gate steps inside Decision Tree).
  - **6 required sections per SPEC.md REQ-POC-TRUST-03 Target (a):**
    1. Trigger sources (Sigstore mailing list, blog, sigstore-rs CI failures).
    2. Capture command — `curl -L https://raw.githubusercontent.com/sigstore/root-signing/main/repository/trusted_root.json -o /tmp/new.json`.
    3. Byte-diff vs prior — `diff -u crates/nono/tests/fixtures/trust-root-frozen.json /tmp/new.json | head -50`.
    4. Regression check — `cargo test -p nono trust::bundle::load_test_trusted_root_smoke`.
    5. Commit-and-tag — `git add ... && git commit -m "chore(trust-root): refresh frozen fixture..." -s` (DCO sign-off mandatory per CLAUDE.md).
    6. Forward pointer to release-asset CI gate at `.github/workflows/release.yml` (Phase 49-02 byte-identity assert step).
  - **Reference smoke script (D-49-C3 maintainer-only gate):** the template MUST cite `scripts/verify-trust-root-cached.sh` / `.ps1` as the canonical pre-commit gate.
  - **Anti-Patterns block:** don't refresh without regression test; don't commit a fixture the smoke script rejects; don't ship without bumping a release tag.

#### `scripts/verify-trust-root-cached.sh` (Plan 49-03)

- **Role:** Bash smoke script (~20 lines) that takes a candidate `trusted_root.json` path, runs `NONO_TEST_HOME=<tmp> nono setup --from-file <path> && nono trust verify <known-good-bundle> <known-good-source>`, exits 0 on success / non-zero on failure.
- **Closest analog:** No direct analog — net-new file. Mirror bash hygiene of other `scripts/*.sh` files in the repo (planner inventories at plan-open via `ls scripts/*.sh`).
- **Excerpt source:** 49-RESEARCH.md § "REQ-POC-TRUST-03 → Smoke script signature" — verbatim ~20-line skeleton with `<BUNDLE>`/`<SOURCE>` placeholders.
- **Pattern to replicate:**
  - **Shebang + strict mode:** `#!/usr/bin/env bash` + `set -euo pipefail`.
  - **Arg check:** `if [ $# -lt 1 ]; then echo "usage: $0 <path-to-trusted_root.json>" >&2; exit 2; fi`.
  - **TempDir + trap cleanup:** `TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT`.
  - **Env scoping:** `export NONO_TEST_HOME="$TMP"; export XDG_CONFIG_HOME="$TMP"`.
  - **Invocations:** `nono setup --from-file "$CANDIDATE"` then `nono trust verify <BUNDLE> <SOURCE>` (planner fills placeholders per D-49-C2 inventory of existing trust fixtures).
  - **Success message:** `echo "PASS: $CANDIDATE accepted by setup and used successfully by verify."`.
  - **Exit code propagation:** `set -e` handles the success/fail propagation; no explicit `exit $?` needed.
  - **Executable bit:** `git update-index --chmod=+x scripts/verify-trust-root-cached.sh` BEFORE committing (avoids F-03-02 non-executable failure).

#### `scripts/verify-trust-root-cached.ps1` (Plan 49-03)

- **Role:** PowerShell smoke script (~20 lines), Windows-first POC UX sibling to the `.sh`; same invocation contract.
- **Closest analog:** No direct analog — net-new file. Mirror exit-code propagation patterns of other `scripts/*.ps1` files in the repo (planner inventories at plan-open via `ls scripts/*.ps1`).
- **Excerpt source:** 49-RESEARCH.md § "REQ-POC-TRUST-03 → Smoke script signature" — verbatim ~20-line PowerShell skeleton with `<BUNDLE>`/`<SOURCE>` placeholders.
- **Pattern to replicate:**
  - **Requires + ErrorActionPreference:** `#Requires -Version 5.1` + `$ErrorActionPreference = 'Stop'`.
  - **Param block:** `param([Parameter(Mandatory=$true)][string]$Candidate)`.
  - **TempDir + try/finally cleanup:** `$tmp = New-Item -ItemType Directory -Path "$env:TEMP\nono-trust-smoke-$(Get-Random)" -Force` + `try { ... } finally { Remove-Item -Recurse -Force $tmp.FullName -ErrorAction SilentlyContinue }`.
  - **Env scoping:** `$env:NONO_TEST_HOME = $tmp.FullName; $env:XDG_CONFIG_HOME = $tmp.FullName`.
  - **`$LASTEXITCODE` explicit checks** after every native command — F-03-05 silent-failure mode is exactly the case where `$ErrorActionPreference = 'Stop'` does NOT trap because native command failures don't throw PowerShell exceptions. Pattern: `& nono setup --from-file $Candidate; if ($LASTEXITCODE -ne 0) { throw "nono setup failed" }`.
  - **Success message:** `Write-Host "PASS: $Candidate accepted by setup and used successfully by verify."`.

---

## Shared Patterns (cross-cutting)

### Authentication / Authorization
**N/A** — Phase 49 surface contains zero auth-bearing code paths. `--from-file` is a local-fs operation; the release-asset bundling runs in CI under the existing release-job credentials.

### Error Handling
**Source:** `crates/nono/src/error.rs` (`NonoError` enum) + CLAUDE.md "Fail Secure" principle.
**Apply to:** `crates/nono-cli/src/setup.rs` (new `from_file_step`), `crates/nono/src/trust/bundle.rs` (vis-widen on `check_trusted_root_freshness`).
**Pattern:**
- `?` propagation via `NonoError::Io` (for `std::fs::copy` / `std::fs::create_dir_all` errors) and `NonoError::Setup(format!(...))` (for validation-layer failures with caller-friendly messages).
- **Fail-closed contract (SPEC.md acceptance criteria):** on `load_trusted_root` parse failure, `check_trusted_root_freshness` expiry failure, missing path, unreadable path, or mid-copy IO error → exit non-zero AND do NOT create or modify cache file. D-49-B2's best-effort `remove_file` on copy failure honors this.
- **Error messages cite recovery path:** per existing D-32-05 first-run UX convention, error messages name `nono setup --refresh-trust-root` OR a release-asset URL as the recovery path.

### Validation
**Source:** `crates/nono/src/trust/bundle.rs:113-167` (`load_trusted_root` + `load_production_trusted_root`) + `crates/nono/src/trust/bundle.rs:247-305` (`check_trusted_root_freshness` — currently private, widened to `pub` in Plan 49-01).
**Apply to:** the new `from_file_step` in `crates/nono-cli/src/setup.rs` ONLY (no other Phase 49 file performs validation).
**Pattern:**
- **Two-step validation pipeline (SPEC.md "no new schema validator"):** `nono::trust::bundle::load_trusted_root(<PATH>)?` (deserialize via `TrustedRoot::from_file` — IS the schema oracle) THEN `nono::trust::bundle::check_trusted_root_freshness(&trusted_root, &cache_path)?` (D-32-03 tlog expiry gate, WR-05 fail-closed ISO-8601 format guard).
- **NO new validator code in `crates/nono`** — only the `pub` keyword on the existing fn plus an optional `pub use` in `trust/mod.rs`.

### Testing
**Source:** `crates/nono-cli/tests/auto_pull_e2e_linux.rs` (canonical pattern per 49-RESEARCH.md) + `crates/nono-cli/tests/common/test_env::{lock_env, EnvVarGuard}` (Phase 44 D-44-E6 mandatory env-locking).
**Apply to:** integration test file (new `setup_from_file.rs` OR extension of existing `setup_trust_root.rs`).
**Pattern:**
- **Env-lock everywhere:** `let _env_lock = lock_env();` at the top of every test that mutates `NONO_TEST_HOME` / `XDG_CONFIG_HOME` / `HOME` (CLAUDE.md "Environment variables in tests" — Rust runs unit tests in parallel within the same process; unrestored env vars cause flaky failures across tests).
- **Per-test `tempfile::TempDir`:** `let tmp = TempDir::new().unwrap();` — every test gets a fresh `NONO_TEST_HOME`. No shared fixture state.
- **`#![allow(clippy::unwrap_used)]`** at the top of the test file (CLAUDE.md permits in `#[cfg(test)]` and test modules).
- **Raw `std::process::Command` + `env!("CARGO_BIN_EXE_nono")`** — NOT `assert_cmd` (planner verifies at plan-open; raw Command is the established pattern in `auto_pull_e2e_linux.rs`).
- **No new dev-deps anticipated** — `tempfile` already in `crates/nono-cli/Cargo.toml [dev-dependencies]`.

### Cross-target clippy verification (MANDATORY)
**Source:** CLAUDE.md § "Coding Standards" → "Cross-target clippy verification" bullet + `.planning/templates/cross-target-verify-checklist.md`.
**Apply to:** Plan 49-01 (touches `crates/nono-cli/src/cli.rs` and `setup.rs`, both of which contain `#[cfg(target_os = "windows")]` blocks per 49-RESEARCH.md — 5+ in `setup.rs` alone).
**Pattern:**
- `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` AND `--target x86_64-apple-darwin` MUST run from the dev host.
- Windows-host workspace clippy is NOT a substitute — does not exercise Unix cfg branches.
- PARTIAL deferral allowed only if cross-toolchain is not installed (per checklist template); REQ marked PARTIAL with explicit live-CI deferral.

### Commit hygiene
**Source:** CLAUDE.md § "Coding Standards" → "Commits" bullet (DCO sign-off).
**Apply to:** every commit on every plan in Phase 49.
**Pattern:**
- Every commit ends with `Signed-off-by: Oscar Mack Jr. <oscar.mack.jr@gmail.com>` (DCO).
- Conventional-commit prefix per plan: `feat(49-01):` / `chore(49-02):` / `docs(49-03):` (per D-49-A1 "one plan per REQ" naming).
- Per-plan commit shape (Claude's-Discretion per CONTEXT.md): 49-01 likely single atomic commit (CLI + setup + test tightly coupled); 49-02 single atomic commit (release.yml only); 49-03 1-3 commits (template / scripts / docs may split for per-file scope, or single atomic if `docs(49-03):` is cleaner).
- **No `--amend`** unless explicitly requested by the user (CLAUDE.md git safety protocol).

### Workspace + dependency hygiene
**Source:** memory `project_workspace_crates` + CLAUDE.md.
**Apply to:** Plan 49-01 only (the only plan with `Cargo.toml`-eligible changes).
**Pattern:**
- **Workspace has 5 crates, not 3** — but Phase 49 only touches `crates/nono-cli/` for code and `crates/nono/` for the one-keyword vis-widen.
- **No new deps anticipated:** `tempfile` already in `crates/nono-cli` dev-deps; `assert_cmd` NOT used (raw `std::process::Command` instead).
- **No internal path-dep version pins ripple** — neither the vis-widen on `bundle.rs` nor the new `from_file` field is a public-API addition that requires a workspace-wide version bump.

---

## No Analog Found

| File | Role | Data Flow | Reason |
|---|---|---|---|
| `scripts/verify-trust-root-cached.sh` | bash smoke script | request-response (CLI wrap) | Net-new file. No prior cross-platform smoke script in `scripts/` follows the precise pattern of "wrap nono setup + nono trust verify in a TempDir for fixture validation." Mirror bash hygiene of other `scripts/*.sh` and 49-RESEARCH.md's verbatim skeleton. |
| `scripts/verify-trust-root-cached.ps1` | PowerShell smoke script | request-response (CLI wrap) | Net-new file. No prior `.ps1` in `scripts/` follows the precise pattern. Mirror PowerShell hygiene of other `scripts/*.ps1` and 49-RESEARCH.md's verbatim skeleton. |
| `.planning/templates/sigstore-rotation-refresh.md` | maintainer-cadence template | none (prose) | Mirrors structural shape of `.planning/templates/cross-target-verify-checklist.md` but content is wholly new. Not a true "no analog" — the structural template IS the analog, the content is novel. |

---

## Metadata

- **Analog search scope:** No new analog discovery performed. All analogs are pre-identified in 49-CONTEXT.md "Canonical References" + 49-RESEARCH.md (which already verified line ranges for `cli.rs:2341-2387`, `setup.rs:20-29 / 91-93 / 820-860`, `bundle.rs:113-167 / 247-305`, `release.yml:315-340`, `windows-poc-handoff.mdx:166-225`).
- **Files scanned in this pattern-map session:** 3 (49-CONTEXT.md, 49-SPEC.md, 49-RESEARCH.md).
- **Pattern extraction date:** 2026-05-21.
- **Downstream consumer:** `gsd-planner` — produces per-plan PLAN.md files referencing this PATTERNS.md by section. Each plan's `<action_block>` section cites the analog file + line range + Pattern-to-replicate hint from this map.

## PATTERN MAPPING COMPLETE
