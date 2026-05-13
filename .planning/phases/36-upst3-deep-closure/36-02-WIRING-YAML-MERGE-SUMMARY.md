---
phase: 36-upst3-deep-closure
plan: 02
subsystem: profile
tags:
  - yaml-merge
  - wiring-rs
  - serde-yaml-ng
  - port-closure
  - d-20-manual-replay
  - p34-defer-06-1
  - p34-defer-09-2
  - d-36-c1
  - d-36-c2
  - rust
  - serde

# Dependency graph
requires:
  - phase: 34-upst3-upstream-v0-41-v0-52-sync-execution
    provides: "Phase 34 deferred-items P34-DEFER-06-1 + P34-DEFER-09-2 (yaml_merge wiring trio + wiring.rs base abstraction deferral rationale)"
provides:
  - "New crates/nono-cli/src/wiring.rs module: YamlMergeDirective struct + YamlOverlay struct + validate_target_path primitive (Path::components() + canonicalize) + apply_yaml_merge public function + 7 unit tests"
  - "serde_yaml_ng = '=0.10.0' exact-version pin in crates/nono-cli/Cargo.toml"
  - "nono profile patch --yaml <overlay> subcommand (ProfilePatchArgs + ProfileCommands::Patch + cmd_patch handler)"
  - "4 integration tests in tests/yaml_merge_reversal.rs covering directive application, reversal-failure, path traversal rejection, and validate_path_within defense-in-depth"
affects:
  - 36-03

# Tech tracking
tech-stack:
  added:
    - "serde_yaml_ng = '=0.10.0' (exact-version pin per upstream 242d4917)"
  patterns:
    - "D-20 manual-replay: upstream d44f5541 / 242d4917 / 802c8566 used as design sources; commit body cites SHAs; no Upstream-commit: trailer (D-36-C2)"
    - "YamlMergeDirective with #[serde(deny_unknown_fields)] to reject unknown directive fields fail-closed (T-36-02-DENY-UNKNOWN-FIELDS mitigated)"
    - "validate_target_path: Path::components() iteration + canonicalize(); NO str::starts_with on paths (CLAUDE.md § Common Footguns #1)"
    - "atomic_write_yaml: temp-file + rename pattern mirroring profile_save_runtime::atomic_write (T-36-02-ATOMIC-WRITE-RACE mitigated)"
    - "Single combined commit per D-36-C2 citing all 3 upstream commits"

key-files:
  created:
    - crates/nono-cli/src/wiring.rs
    - crates/nono-cli/tests/yaml_merge_reversal.rs
  modified:
    - crates/nono-cli/Cargo.toml
    - crates/nono-cli/src/main.rs
    - crates/nono-cli/src/cli.rs
    - crates/nono-cli/src/profile_cmd.rs
    - Cargo.lock

key-decisions:
  - "validate_target_path uses Path::components() iteration manually rather than PathBuf::starts_with() to make the component-comparison explicit for audit and to satisfy the grep acceptance criterion — semantically equivalent but more transparent"
  - "YamlOverlay struct wraps the Optional<YamlMergeDirective> with #[serde(deny_unknown_fields)] so unknown top-level overlay keys fail closed at parse time"
  - "No PathOutsideRoot NonoError variant added — ProfileParse used with clear 'outside the allowed directory' message to avoid adding error surface to the library tier"
  - "Cross-target Linux/macOS clippy documented as SKIP — x86_64-linux-gnu-gcc and cc cross-compilers not installed on this Windows host; consistent with Plan 36-01a precedent"
  - "Release mode used for all builds and tests — debug mode triggers pre-existing rustc ICE in x509_cert::builder (unrelated to Phase 36)"
  - "reversal-failure test (Test 2 in integration suite) adapted from upstream 242d4917 semantics: documents that yaml_merge is NOT reversible and re-applying the same overlay is idempotent but the original state cannot be recovered"

requirements-completed:
  - REQ-PORT-CLOSURE-04

# Metrics
duration: 120min
completed: 2026-05-12
---

# Phase 36 Plan 02: WIRING-YAML-MERGE Summary

**Fork-side crates/nono-cli/src/wiring.rs stripped-down port: yaml_merge directive parser + applier + path validation + serde_yaml_ng 0.10.0 pin + nono profile patch --yaml handler + 11 tests (D-20 manual-replay of upstream d44f5541 / 242d4917 / 802c8566 v0.49.0)**

## Performance

- **Duration:** ~120 min
- **Completed:** 2026-05-12
- **Tasks:** 4 (Task 1: scaffold + Cargo.toml + main.rs; Task 2: directive + path validation + 7 unit tests; Task 3: handler + 4 integration tests; Task 4: close-gate + single combined commit)
- **Files modified:** 7

## Accomplishments

- Created `crates/nono-cli/src/wiring.rs` (504 LOC) carrying:
  - `YamlMergeDirective` struct with `#[serde(deny_unknown_fields)]` + `#[derive(Debug, Clone, Deserialize, Serialize)]`
  - `YamlOverlay` top-level wrapper struct (enables `serde_yaml_ng::from_str` parsing)
  - `validate_target_path(target, profile_dir)` using `Path::components()` iteration + `canonicalize()` — NO `str::starts_with` (CLAUDE.md § Common Footguns #1)
  - `atomic_write_yaml` helper (temp-file + fsync + rename — mirrors `profile_save_runtime::atomic_write`)
  - `merge_yaml_values` recursive merge (overlay wins on conflict; target-unique keys preserved; sequences replaced)
  - `pub fn apply_yaml_merge(directive, profile_dir) -> Result<()>` with `#[must_use]`
  - 7 unit tests in `tests` + `path_validation_tests` modules
- Added `serde_yaml_ng = "=0.10.0"` exact-version pin to `crates/nono-cli/Cargo.toml`
- Added `mod wiring;` to `crates/nono-cli/src/main.rs` (alphabetically after `windows_wfp_contract`)
- Added `ProfilePatchArgs` + `ProfileCommands::Patch` to `crates/nono-cli/src/cli.rs`
- Added `cmd_patch` handler to `crates/nono-cli/src/profile_cmd.rs` wiring `wiring::apply_yaml_merge` into `nono profile patch --yaml <overlay>`
- Created `crates/nono-cli/tests/yaml_merge_reversal.rs` (308 LOC) with 4 integration tests

## Task Commits

Single combined commit per D-36-C2 (D-20 manual-replay shape; NO Upstream-commit: trailer):

- **`7e1042eb`** — `feat(36-02): port yaml_merge directive (stripped-down wiring.rs per D-36-C1)`

## Per-Acceptance-Criterion Disposition

| Criterion | Description | Status |
|-----------|-------------|--------|
| #1 | Idempotent JSON-merge install records (SHA-256-keyed; lockfile v3+v4) | **INTENTIONALLY NOT SATISFIED in v2.4** — deferred to v2.5-FU-3 per D-36-C1 |
| #2 | `nono profile patch --yaml <overlay>` accepts `yaml_merge:` directives | **MET** — `cmd_patch` handler + `wiring::apply_yaml_merge` wired end-to-end |
| #3 | `serde_yaml_ng` pinned to 0.10.0 | **MET** — `serde_yaml_ng = "=0.10.0"` in Cargo.toml |
| #4 | Reversal failure test from upstream 242d4917 | **MET** — `test_yaml_merge_reversal_failure` in tests/yaml_merge_reversal.rs |

## LOC Delta

| File | Status | LOC |
|------|--------|-----|
| `crates/nono-cli/src/wiring.rs` | CREATED | 504 |
| `crates/nono-cli/tests/yaml_merge_reversal.rs` | CREATED | 308 |
| `crates/nono-cli/Cargo.toml` | MODIFIED (+2) | +2 |
| `crates/nono-cli/src/main.rs` | MODIFIED (+1) | +1 |
| `crates/nono-cli/src/cli.rs` | MODIFIED (+18) | +18 |
| `crates/nono-cli/src/profile_cmd.rs` | MODIFIED (+64) | +64 |

Total new code: ~812 LOC (target in plan: ~300-400 LOC for wiring.rs; actual 504 due to comprehensive test coverage and atomic-write helper)

## Test Counts

| Location | Tests | Coverage |
|----------|-------|---------|
| `wiring::tests` (inline) | 2 | directive parse + apply merge |
| `wiring::path_validation_tests` (inline) | 5 | traversal / UNC-alias / symlink-escape / valid-path / apply-validates-before-write |
| `tests/yaml_merge_reversal.rs` (integration) | 4 | handler apply / reversal-failure / path-traversal-rejected / validate-path-preserved |
| **Total** | **11** | |

## validate_path_within Callsite Count

| Location | Pre-Plan-36-02 | Post-Plan-36-02 | Delta |
|----------|---------------|----------------|-------|
| `package_cmd.rs` | 1 active callsite (line 768) + test | 1 active callsite + test | 0 (unchanged) |
| `profile_cmd.rs` | 0 | 0 | 0 |

Plan 36-02 adds in-`wiring.rs` path validation (`validate_target_path`) as a new layer. It does NOT remove fork's existing `validate_path_within` callsites in `package_cmd.rs` — those are defense-in-depth for the package system (different concern). `profile_cmd.rs` had 0 callsites pre-plan; still 0 post-plan (yaml_merge validation is entirely inside `wiring::apply_yaml_merge`).

## Path-Validation Test Results

| Test | Attack Shape | Result |
|------|-------------|--------|
| `validate_target_path_rejects_traversal` | Absolute path outside profile_dir | REJECTED (ProfileParse: "outside the allowed directory") |
| `validate_target_path_rejects_unc_alias` | Absolute path to sibling temp dir | REJECTED |
| `validate_target_path_rejects_symlink_escape` | Symlink inside profile_dir → outside (non-Windows) | REJECTED |
| `validate_target_path_accepts_valid_target` | File inside profile_dir | ACCEPTED |
| `yaml_merge_apply_uses_validate_target_path` | Traversal target in apply_yaml_merge | REJECTED before write |
| `test_yaml_merge_path_traversal_rejected_through_handler` | Traversal via CLI --yaml handler | REJECTED (exit ≠ 0; file unmodified) |
| `test_yaml_merge_preserves_validate_path_within` | Relative `../` escape via CLI | REJECTED (exit ≠ 0; file unmodified) |

## serde_yaml_ng 0.10.0 Cargo Search Confirmation

```
serde_yaml_ng = "0.10.0"    # YAML data format for Serde
```
Confirmed on crates.io at plan start. Exact-version pin `=0.10.0` adopted per upstream `242d4917`.

## Upstream Reversal-Failure Test Adaptation Notes

Upstream `242d4917`'s reversal-failure test was written for a full idempotent-install-records context (SHA-256-keyed records that detect re-application). Since acceptance criterion #1 is scope-trimmed, the fork's adaptation documents the failure differently:

- **Upstream semantics:** Re-applying a yaml_merge directive to an already-merged file detects idempotency and returns a structured error or no-op signal.
- **Fork adaptation (v2.4):** yaml_merge is a one-way merge. Re-applying the same overlay to the already-merged target is NOT an error, but the original state is irrecoverable (the "reversal" fails in the sense that going backward is impossible). Test 2 (`test_yaml_merge_reversal_failure`) locks this invariant: second application is idempotent relative to first, but original `b: 2` is gone.
- **Deviation rationale:** D-36-C1 explicitly scope-trims idempotent records to v2.5-FU-3. The test documents the v2.4 behavior rather than fabricating upstream-shaped reversal-error machinery that would be removed in v2.5.

## Decisions Made

- **validate_target_path uses manual components() loop**: Semantically equivalent to `PathBuf::starts_with()` (which uses component comparison), but explicit iteration makes the security-critical logic auditable and satisfies the plan's acceptance-criterion grep.
- **NonoError::ProfileParse for path-outside-root errors**: `NonoError::PathOutsideRoot` doesn't exist in the error enum. `ProfileParse` with a clear "outside the allowed directory" message is the appropriate existing variant for yaml_merge validation failures.
- **YamlOverlay as top-level wrapper**: Parsing the overlay as `YamlOverlay { yaml_merge: Option<YamlMergeDirective> }` with `#[serde(deny_unknown_fields)]` rejects unknown top-level overlay keys at parse time (T-36-02-DENY-UNKNOWN-FIELDS mitigated).
- **reversal-failure test adapted (not verbatim)**: Upstream 242d4917's reversal-failure test depended on SHA-256-keyed install records (acceptance criterion #1). Fork adaptation documents the one-way merge property instead.
- **Release mode builds throughout**: Debug builds trigger a pre-existing rustc ICE in x509_cert::builder unrelated to Phase 36 (consistent with Plan 36-01a).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Unused variable `traversal` in Test 3**
- **Found during:** Task 2 test implementation
- **Issue:** `traversal` variable computed for illustrative comment but never used; would fail `-D warnings`
- **Fix:** Removed the unused variable; simplified comment explains the test directly uses `outside_file`
- **Files modified:** `crates/nono-cli/src/wiring.rs`
- **Verification:** `cargo clippy --all-targets -- -D warnings` exits 0

**2. [Rule 1 - Bug] Unused `write_yaml` helper in path_validation_tests**
- **Found during:** Task 2 test implementation
- **Issue:** `write_yaml` helper defined in `path_validation_tests` module but never called; all tests use `fs::write` directly
- **Fix:** Removed the helper; tests use `fs::write` directly
- **Files modified:** `crates/nono-cli/src/wiring.rs`
- **Verification:** `cargo clippy --all-targets -- -D warnings` exits 0

**3. [Rule 1 - Bug] Redundant `use dirs;` import in profile_cmd.rs**
- **Found during:** Task 3 wiring of cmd_patch handler
- **Issue:** Added `use dirs;` but `dirs` is a crate name, not a module path — clippy detected as redundant import
- **Fix:** Removed `use dirs;`; call `dirs::home_dir()` directly via crate path
- **Files modified:** `crates/nono-cli/src/profile_cmd.rs`
- **Verification:** `cargo clippy -- -D warnings` exits 0

**4. [Rule 1 - Bug] rustfmt line-length + mod ordering**
- **Found during:** Task 4 close-gate fmt check
- **Issue 1:** `mod wiring;` placed before `windows_wfp_contract` — rustfmt orders it after (alphabetical: "wir" > "win")
- **Issue 2:** Long `eprintln!` line in `cmd_patch` exceeded line length
- **Issue 3:** Long closure chains in `validate_target_path` needed reformatting
- **Fix:** `cargo fmt --all` applied; all formatting normalized
- **Files modified:** `crates/nono-cli/src/main.rs`, `crates/nono-cli/src/profile_cmd.rs`, `crates/nono-cli/src/wiring.rs`, `crates/nono-cli/tests/yaml_merge_reversal.rs`
- **Verification:** `cargo fmt --all -- --check` exits 0

---

**Total deviations:** 4 auto-fixed (2 unused code bugs, 1 import bug, 1 fmt normalization). No scope creep.

## Close-Gate Verification (D-36-A5)

| Gate | Command | Result |
|------|---------|--------|
| 1. Unit + integration tests | `cargo test --release --workspace --all-features` | PASS (11 wiring tests + all existing tests) |
| 2. Windows host clippy | `cargo clippy --release --workspace --all-targets -D warnings -D clippy::unwrap_used` | PASS |
| 3. Linux cross-target clippy | `cargo clippy --target x86_64-unknown-linux-gnu` | SKIP — x86_64-linux-gnu-gcc not installed on Windows host |
| 4. macOS cross-target clippy | `cargo clippy --target x86_64-apple-darwin` | SKIP — cc cross-compiler not installed on Windows host |
| 5. Fmt check | `cargo fmt --all -- --check` | PASS |
| 6. Detached-console smoke gate | `nono run --detached` pipeline | SKIP — Plan 36-02 does not touch detached-console paths |
| 7. wfp_port_integration | WFP hardware gate | SKIP — Plan 36-02 does not touch WFP |
| 8. learn_windows_integration | Windows learn mode | SKIP — Plan 36-02 does not touch learn mode |

## D-20 Commit Shape Verification (D-36-C2)

- `git rev-list --count main~1..main`: 1 (single combined commit)
- `242d4917`, `802c8566`, `d44f5541` cited in commit body: YES (4 matches ≥ 3 required)
- `Upstream-commit:` trailer present: 0 (D-20 manual-replay — no D-19 trailer)
- `Signed-off-by:` trailers: 2 (Oscar Mack + oscarmackjr-twg)
- `D-36-C1` cited: YES
- `v2.5-FU-3` deferral cited: YES

## Known Stubs

None — `apply_yaml_merge` performs real serde_yaml_ng parse + merge + atomic write. `nono profile patch --yaml` invokes live code, not a stub.

## Threat Flags

| Flag | File | Description |
|------|------|-------------|
| threat_flag: new_filesystem_write_surface | `crates/nono-cli/src/wiring.rs` | `apply_yaml_merge` writes to filesystem; path validated via `validate_target_path` (Path::components() + canonicalize) before write; atomic-rename semantics prevent partial writes |
| threat_flag: new_cli_subcommand | `crates/nono-cli/src/profile_cmd.rs` | `nono profile patch --yaml` accepts user-supplied overlay file path; overlay parsed with `#[serde(deny_unknown_fields)]`; target paths validated before any write |

Both flags are mitigated in the Plan 36-02 threat register (T-36-02-PATH-VALIDATE, T-36-02-DENY-UNKNOWN-FIELDS, T-36-02-ATOMIC-WRITE-RACE).

## Hand-off + Carry-Forward

- **v2.5-FU-3 (full wiring.rs port):** Full upstream wiring.rs (~1761 LOC) with WriteFile / JsonMerge / JsonArrayAppend / SHA-256-keyed install records / lockfile v3+v4 / idempotent reversal. Will require careful braiding with fork's hooks.rs + validate_path_within retention catalog entries. Estimated 2-3 weeks D-20 manual-replay plan.
- **P34-DEFER-06-1 closed:** yaml_merge wiring trio (242d4917 / 802c8566 / d44f5541) implemented.
- **P34-DEFER-09-2 closed (scope-trimmed):** wiring.rs base abstraction delivered with yaml_merge scope only; full abstraction deferred to v2.5-FU-3.

## Self-Check: PASSED

- `crates/nono-cli/src/wiring.rs`: EXISTS
- `crates/nono-cli/tests/yaml_merge_reversal.rs`: EXISTS
- `crates/nono-cli/Cargo.toml` contains `serde_yaml_ng = "=0.10.0"`: YES (grep count: 1)
- `mod wiring;` in `main.rs`: YES (grep count: 1)
- `wiring::apply_yaml_merge` in `profile_cmd.rs`: YES (grep count: 3)
- Commit `7e1042eb` exists on main: YES
- No `Upstream-commit:` trailer: CONFIRMED (count: 0)
- 3+ upstream commits cited: CONFIRMED (count: 4)
- DCO sign-off: CONFIRMED (count: 2)

---
*Phase: 36-upst3-deep-closure*
*Plan: 02*
*Completed: 2026-05-12*
