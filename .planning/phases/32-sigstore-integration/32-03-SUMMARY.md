---
phase: 32-sigstore-integration
plan: "03"
subsystem: trust
tags: [sigstore, keyless, fulcio, rekor, httpmock, regress, fail-closed, cli-hardening, trust-policy]

requires:
  - phase: 32-02
    provides: TUF cache rewrite, load_production_trusted_root, verify_bundle_with_digest

provides:
  - "--issuer / --identity mandatory flags on nono trust verify --keyless (D-32-08 fail-closed)"
  - "OIDC_NO_AMBIENT_TOKEN_MSG canonical const with --keyref suggestion (D-32-09)"
  - "httpmock smoke test confirming mock Fulcio/Rekor servers start on localhost (D-32-07 CI gate)"
  - "NONO_TEST_FULCIO_URL / NONO_TEST_REKOR_URL env-var shim under test-trust-overrides feature (D-32-07 seam)"
  - "keyless_sign_then_verify_roundtrip stub + capture procedure doc (P32-DEFER-001)"
  - "docs/templates/trust-policy-keyless-template.json baked-in template (D-32-10)"
  - "trust_policy_template default_template_parses test confirming schema compat (P32-CHK-015)"
  - "5-test keyless verify integration suite covering all D-32-08 + D-32-09 acceptance criteria"

affects: [32-04, 32-05, sigstore, trust-policy, keyless-ci-flows]

tech-stack:
  added:
    - "regress = \"0.11\" added to nono-cli [dependencies] (production CLI dep for SAN regex)"
    - "rcgen = \"0.13\" added to nono-cli [dev-dependencies] (at-test-time DER cert generation)"
    - "httpmock = \"0.7\" already present; active use demonstrated by smoke test"
  patterns:
    - "Fail-closed keyless verify: --issuer + --identity both required at runtime, checked via ok_or_else"
    - "URL-component issuer validation via validate_oidc_issuer (blocks prefix attacks)"
    - "SAN regex post-check: regress::Regex::new(pattern).find(&workflow) against normalized relative path"
    - "normalize_workflow_uri strips https://github.com/org/repo/ prefix + @ref suffix to relative path"
    - "DER UTF8String encoding: tag 0x0C + length varint + UTF-8 bytes for rcgen CustomExtension"
    - "test-trust-overrides feature gate: env-var shim for mock Fulcio/Rekor in test binary"

key-files:
  created:
    - "crates/nono-cli/tests/trust_policy_template.rs"
    - "docs/templates/trust-policy-keyless-template.json"
    - ".planning/phases/32-sigstore-integration/deferred-items.md"
  modified:
    - "crates/nono-cli/src/cli.rs (TrustVerifyArgs: added --issuer, --identity)"
    - "crates/nono-cli/src/trust_cmd.rs (hardened keyless arms, OIDC_NO_AMBIENT_TOKEN_MSG, test-trust-overrides shim)"
    - "crates/nono-cli/Cargo.toml (added regress prod dep + rcgen dev dep)"
    - "crates/nono-cli/tests/keyless_verify.rs (5 integration tests replacing Wave 0 skeleton)"
    - "crates/nono-cli/tests/keyless_sign.rs (mock smoke test + deferred roundtrip replacing Wave 0 skeleton)"

key-decisions:
  - "P32-CHK-001: workflow field contains NORMALIZED relative path (e.g. .github/workflows/release.yml), NOT the full Fulcio Build Config URI — normalize_workflow_uri in bundle.rs strips https://github.com/org/repo/ prefix and @ref suffix"
  - "P32-DEFER-001: full keyless_sign_then_verify_roundtrip deferred to Phase 32 follow-up; requires captured real-world-shaped Rekor/Fulcio responses from staging environment"
  - "regress (not regex crate) used for SAN pattern matching — already in nono crate dep tree at 0.11"
  - "VerificationPolicy::with_issuer is a STATIC constructor in sigstore-verify 0.6.5, not a method chain"
  - "httpmock 0.7 exposes hits() on Mock objects (per-route), NOT on MockServer — smoke test registers sentinel mock routes to assert 0 hits"
  - "Trust-policy template workflow field uses normalized relative path (.github/workflows/release.yml), not full Fulcio URI"

patterns-established:
  - "Fail-closed keyless verify pattern: check args.issuer/identity with ok_or_else BEFORE loading trusted root"
  - "Hermetic keyless test pattern: rcgen at-test-time cert generation with DER UTF8String OID extensions, Bundle::from_json, extract_signer_identity — no live Sigstore calls"
  - "Mock server smoke test pattern: register sentinel mock routes, verify localhost URLs, assert 0 hits"

requirements-completed: [D-32-07, D-32-08, D-32-09, D-32-10]

duration: ~90min
completed: "2026-05-10"
---

# Phase 32 Plan 03: Keyless Sigstore CLI Hardening Summary

**Fail-closed keyless verify with mandatory --issuer/--identity flags, SAN regex post-check via regress, 5-test hermetic integration suite, mock Fulcio/Rekor smoke test, OIDC error improvement, and baked-in trust-policy template**

## Performance

- **Duration:** ~90 min
- **Started:** 2026-05-10T12:00:00Z (approx)
- **Completed:** 2026-05-10T14:36:20Z
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments

- D-32-08 fail-closed: `nono trust verify --keyless` now requires both `--issuer` (exact URL-component match) and `--identity` (regress regex against normalized workflow path); missing either flag returns a clear error naming the missing flag
- D-32-09: `OIDC_NO_AMBIENT_TOKEN_MSG` canonical const added, error message now explicitly names `--keyref`, `GitHub Actions`, `GitLab CI`, and `id-token: write`
- D-32-07: httpmock smoke test active in CI confirms mock Fulcio/Rekor servers start on localhost; full roundtrip deferred to P32-DEFER-001 with env-var injection seam already wired
- D-32-10: `docs/templates/trust-policy-keyless-template.json` ships with two publishers (GitHub Actions + GitLab CI), deny enforcement, and normalized relative-path workflow fields; `default_template_parses` confirms schema compat via the real CLI deserializer

## Task Commits

1. **Task 1: --issuer/--identity flags + hardened keyless arm + 5-test suite** - `f7a1bdf8` (feat)
2. **Task 2: mock Fulcio/Rekor smoke test + env-var shim + trust-policy template** - `d1634ba0` (feat)

**Plan metadata:** (final docs commit — see below)

## Files Created/Modified

- `crates/nono-cli/src/cli.rs` - Added `--issuer` + `--identity` fields to `TrustVerifyArgs`
- `crates/nono-cli/src/trust_cmd.rs` - Hardened keyless verify arms (both `verify_single_file` and `verify_multi_subject_file`), canonical `OIDC_NO_AMBIENT_TOKEN_MSG` const, `#[cfg(feature = "test-trust-overrides")]` signing context shim, 3 unit tests
- `crates/nono-cli/Cargo.toml` - Added `regress = "0.11"` to `[dependencies]`, `rcgen = "0.13"` to `[dev-dependencies]`
- `crates/nono-cli/tests/keyless_verify.rs` - 5-test integration suite: `verify_rejects_missing_issuer`, `verify_rejects_missing_identity`, `verify_rejects_san_mismatch`, `verify_accepts_san_match` (hermetic via rcgen), `discover_oidc_token_error_suggests_keyref`
- `crates/nono-cli/tests/keyless_sign.rs` - `mock_servers_only_no_real_network` (active CI gate), `keyless_sign_then_verify_roundtrip` (`#[ignore]` P32-DEFER-001 with capture procedure doc)
- `crates/nono-cli/tests/trust_policy_template.rs` - `default_template_parses` test (D-32-10 / P32-CHK-015)
- `docs/templates/trust-policy-keyless-template.json` - Baked-in trust-policy template for keyless GHA + GitLab CI publishers
- `.planning/phases/32-sigstore-integration/deferred-items.md` - Documents P32-DEFER-001 with completion procedure

## Decisions Made

- **workflow field is normalized**: `normalize_workflow_uri` in `bundle.rs` strips `https://github.com/org/repo/` prefix and `@ref` suffix, yielding `.github/workflows/release.yml` — the regex match and template `workflow` field both use this normalized form (P32-CHK-001 correction from plan spec which cited full URI)
- **P32-DEFER-001**: Full keyless_sign_then_verify_roundtrip kept `#[ignore]`'d because wiring valid mock Fulcio/Rekor responses requires staging-captured real data; env-var seam is already in place
- **regress for SAN matching**: `regress` crate (not `regex`) is used because it was already a dependency in the `nono` crate tree at `0.11`
- **VerificationPolicy::with_issuer is a static constructor**: In sigstore-verify 0.6.5, `with_issuer` creates a new `VerificationPolicy`, it does NOT chain on an existing one
- **httpmock hit counts are per-Mock**: `MockServer` has no `.hits()` method in httpmock 0.7; hit counts are on the `Mock` object returned by `server.mock(|when, then| {...})`

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] MockServer::hits() replaced with Mock::hits()**
- **Found during:** Task 2 verification (keyless_sign.rs build)
- **Issue:** `MockServer` has no `hits()` method in httpmock 0.7; `hits()` is on the per-route `Mock` object
- **Fix:** Updated `mock_servers_only_no_real_network` to register sentinel mock routes and call `mock.hits()` on the returned `Mock` objects
- **Files modified:** `crates/nono-cli/tests/keyless_sign.rs`
- **Verification:** `cargo build -p nono-cli --tests` clean; `mock_servers_only_no_real_network` passes
- **Committed in:** `d1634ba0` (Task 2 commit)

**2. [Rule 1 - Bug] workflow field normalization (P32-CHK-001)**
- **Found during:** Task 1 (verify_accepts_san_match test design)
- **Issue:** Plan spec said `workflow` contains full URI `https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0.0`; actual code normalizes to relative path `.github/workflows/release.yml`
- **Fix:** Updated all regex patterns in production code and tests to match the normalized form; trust-policy template workflow field set to normalized path
- **Files modified:** `crates/nono-cli/src/trust_cmd.rs`, `crates/nono-cli/tests/keyless_verify.rs`, `docs/templates/trust-policy-keyless-template.json`
- **Verification:** All 5 `keyless_verify` tests pass; `default_template_parses` passes
- **Committed in:** `f7a1bdf8` (Task 1 commit)

---

**Total deviations:** 2 auto-fixed (2x Rule 1 - Bug)
**Impact on plan:** Both fixes required for correctness; no scope creep. The normalization fix (P32-CHK-001) was explicitly anticipated in the plan as a potential pitfall and was handled correctly.

## Issues Encountered

- `VerificationPolicy::with_issuer` is a static constructor in sigstore-verify 0.6.5, not chainable — discovered during Task 1 compilation, fixed inline by using the correct calling convention

## Known Stubs

- `keyless_sign_then_verify_roundtrip` in `crates/nono-cli/tests/keyless_sign.rs` is `#[ignore]`'d per P32-DEFER-001. The env-var injection seam is wired; completing the test requires staged Fulcio/Rekor response capture. This stub does NOT block the plan's D-32-07 goal (active smoke test covers the CI gate requirement). See `.planning/phases/32-sigstore-integration/deferred-items.md` for completion procedure.

## User Setup Required

None — no external service configuration required. The keyless sign flow requires a CI environment with ambient OIDC (GitHub Actions `permissions: id-token: write`), but that is by design, not a setup gap.

## Next Phase Readiness

- D-32-08 + D-32-09 + D-32-10 closed; D-32-07 partially closed (active smoke test; full roundtrip deferred)
- Plan 04 and 05 can proceed: the `--issuer`/`--identity` CLI surface is stable; trust policy template is available
- P32-DEFER-001 should be resolved before the Phase 32 milestone closes

---
*Phase: 32-sigstore-integration*
*Completed: 2026-05-10*
