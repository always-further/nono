# Phase 32 Deferred Items

## P32-DEFER-001: Full hermetic keyless sign+verify roundtrip test

**Tracking ID:** P32-DEFER-001
**Plan:** 32-03 (D-32-07)
**Deferred to:** Phase 32 follow-up plan
**Status:** open

### What is deferred

`keyless_sign_then_verify_roundtrip` in `crates/nono-cli/tests/keyless_sign.rs` is marked
`#[ignore]` and will `panic!()` if run without the full mock infrastructure.

### Why deferred

Completing the full roundtrip requires:

1. A `nono` binary built with `--features test-trust-overrides` (env-var shim for mock URLs).
2. A mock Fulcio endpoint returning a syntactically valid DER-encoded certificate for the
   rcgen-generated ECDSA keypair (with all required Fulcio v2 OID extensions).
3. A mock Rekor endpoint returning a syntactically valid Rekor v1/v2 log entry JSON that
   `sigstore-sign`'s client parses without error.
4. A test `TrustedRoot` with the rcgen CA's public key substituted for the real Fulcio CA
   public key, so `nono trust verify --keyless` accepts the generated bundle.

The env-var shim (`#[cfg(feature = "test-trust-overrides")]`) was implemented in Plan 03.
The mock infrastructure smoke test (`mock_servers_only_no_real_network`) is active and
passes in CI. The full roundtrip requires capturing real-world-shaped Rekor/Fulcio responses
against a staging environment.

### How to complete

See the capture procedure in `crates/nono-cli/tests/keyless_sign.rs` module-level doc:

1. Run `nono trust sign --keyless` against Fulcio staging (`https://fulcio.sigstage.dev`)
   with a test OIDC token from a GitHub Actions `workflow_dispatch` run.
2. Capture the Fulcio response (cert DER bytes) and Rekor entry JSON via a recording proxy
   or `sigstore-cli --debug`.
3. Feed those into the mock server responses in `keyless_sign.rs`.
4. Build the test binary with `--features test-trust-overrides` and lift the `#[ignore]`.

### Related files

- `crates/nono-cli/tests/keyless_sign.rs` — contains the deferred test + capture procedure doc
- `crates/nono-cli/src/trust_cmd.rs` — contains `#[cfg(feature = "test-trust-overrides")]` shim
- `crates/nono-cli/Cargo.toml` — `test-trust-overrides` feature gate definition
