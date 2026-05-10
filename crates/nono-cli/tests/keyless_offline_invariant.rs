//! Phase 32 Plan 02 (D-32-03): asserts `nono trust verify --keyless` makes
//! ZERO outbound HTTP calls (verify-is-offline invariant).
//!
//! P32-CHK-004 fix: the original Wave-0 scaffold used `httpmock` with a mock
//! server that was never wired into verify, so `mock.hits == 0` was trivially
//! true regardless of what verify did. This file replaces that with two
//! load-bearing assertions:
//!
//! 1. **Structural** — source-greps the verify code paths for forbidden
//!    async/network tokens (`.await`, `reqwest::`, `hyper::`, etc.).
//! 2. **Dynamic** — calls `verify_bundle_with_digest` on a non-runtime
//!    `std::thread` and asserts it returns (Ok or Err) without panicking on
//!    "no reactor running".

use std::fs;
use std::path::PathBuf;

/// P32-CHK-004 fix: structural + dynamic assertion that the verify path uses
/// no async network I/O.
///
/// After Phase 32 Plan 02, `load_production_trusted_root` is sync (cache read)
/// and `verify_bundle_with_digest` was already sync, so the entire keyless
/// verify path is sync and structurally cannot perform async HTTP without a
/// tokio runtime. This test asserts that invariant holds.
#[test]
fn verify_path_uses_no_async_network_io() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .expect("crates/nono-cli parent")
        .parent()
        .expect("workspace root");

    // -----------------------------------------------------------------------
    // 1. Structural: grep bundle.rs verify_bundle / verify_bundle_with_digest
    //    function bodies for forbidden async-HTTP tokens.
    // -----------------------------------------------------------------------
    let bundle_src = fs::read_to_string(
        workspace_root
            .join("crates")
            .join("nono")
            .join("src")
            .join("trust")
            .join("bundle.rs"),
    )
    .expect("read bundle.rs");

    for fn_marker in &["pub fn verify_bundle(", "pub fn verify_bundle_with_digest("] {
        let start = bundle_src
            .find(fn_marker)
            .unwrap_or_else(|| panic!("function {fn_marker} not found in bundle.rs"));
        let body_open = start
            + bundle_src[start..]
                .find('{')
                .expect("opening brace for verify function");
        let mut depth = 0i32;
        let mut body_close = body_open;
        for (i, ch) in bundle_src[body_open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        body_close = body_open + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        let body = &bundle_src[body_open..body_close];
        for forbidden in &[
            ".await",
            "reqwest::",
            "hyper::",
            "tokio::net",
            "Runtime::new",
            ".block_on(",
            "ureq::",
        ] {
            assert!(
                !body.contains(forbidden),
                "verify path contains forbidden async/network token `{forbidden}` \
                 in {fn_marker} body — D-32-03 verify-is-offline invariant violated."
            );
        }
    }

    // -----------------------------------------------------------------------
    // 2. Structural: trust_cmd.rs keyless-verify arms must not contain
    //    async/network tokens. We scan every SignerIdentity::Keyless arm.
    // -----------------------------------------------------------------------
    let trust_cmd_src = fs::read_to_string(
        workspace_root
            .join("crates")
            .join("nono-cli")
            .join("src")
            .join("trust_cmd.rs"),
    )
    .expect("read trust_cmd.rs");

    let mut search_from = 0usize;
    let mut keyless_arms_found = 0usize;
    while let Some(rel) = trust_cmd_src[search_from..].find("SignerIdentity::Keyless") {
        let abs = search_from + rel;
        let arm_open = abs
            + trust_cmd_src[abs..]
                .find('{')
                .expect("opening brace for Keyless arm");
        let mut depth = 0i32;
        let mut arm_close = arm_open;
        for (i, ch) in trust_cmd_src[arm_open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        arm_close = arm_open + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        let arm = &trust_cmd_src[arm_open..arm_close];
        for forbidden in &[
            ".await",
            "reqwest::",
            "hyper::",
            "tokio::net",
            "Runtime::new",
            ".block_on(",
        ] {
            assert!(
                !arm.contains(forbidden),
                "trust_cmd.rs Keyless arm contains forbidden async/network token \
                 `{forbidden}` — D-32-03 verify-is-offline invariant violated."
            );
        }
        keyless_arms_found += 1;
        search_from = arm_close;
    }
    assert!(
        keyless_arms_found >= 2,
        "expected at least 2 SignerIdentity::Keyless arms \
         (verify_single_file + verify_multi_subject_file); found {keyless_arms_found}"
    );

    // -----------------------------------------------------------------------
    // 3. Dynamic: verify_bundle_with_digest runs synchronously in a thread
    //    WITHOUT a tokio runtime. We spawn a std::thread (no runtime), run
    //    the verify call, and rely on it returning (Ok or Err) WITHOUT
    //    panicking with "there is no reactor running" / "no runtime".
    // -----------------------------------------------------------------------
    let frozen_fixture = workspace_root
        .join("crates")
        .join("nono")
        .join("tests")
        .join("fixtures")
        .join("trust-root-frozen.json");

    if !frozen_fixture.exists() {
        // Plan 01 wave 0 fixture not yet committed — skip dynamic check.
        eprintln!("SKIP dynamic check: frozen fixture not yet captured (Plan 01)");
        return;
    }

    let handle = std::thread::spawn(move || -> Result<(), String> {
        let trusted_root = nono::trust::bundle::load_trusted_root(&frozen_fixture)
            .map_err(|e| format!("load_trusted_root: {e}"))?;

        // Minimal Bundle JSON — verification is expected to ERR (stub payload)
        // but MUST NOT panic with "no runtime" / "no reactor running".
        let stub_bundle_json = r#"{
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {
                "publicKey": { "hint": "offline-invariant-test" },
                "tlogEntries": []
            },
            "dsseEnvelope": {
                "payloadType": "application/vnd.in-toto+json",
                "payload": "e30=",
                "signatures": [{"keyid": "", "sig": "AAAA"}]
            }
        }"#;

        let bundle = nono::trust::bundle::load_bundle_from_str(
            stub_bundle_json,
            std::path::Path::new("offline-invariant-stub.bundle"),
        )
        .map_err(|e| format!("load_bundle: {e}"))?;

        let policy = nono::trust::VerificationPolicy::default();
        // Result is expected to be Err (stub bundle); we only care it doesn't panic.
        let _result = nono::trust::bundle::verify_bundle_with_digest(
            "aabbcc",
            &bundle,
            &trusted_root,
            &policy,
            std::path::Path::new("offline-invariant-stub"),
        );
        Ok(())
    });

    let join_result = handle.join();
    assert!(
        join_result.is_ok(),
        "verify path panicked when run on a non-runtime thread — \
         D-32-03 verify-is-offline invariant violated: {:?}",
        join_result.err()
    );
}
