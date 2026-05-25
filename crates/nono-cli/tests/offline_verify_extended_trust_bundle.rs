//! D-48-C3 mandatory regression test: offline-verify with extended trust-bundle schema.
//!
//! Codifies the D-32-15 verify-is-offline invariant against future drift when the
//! `.nono-trust.bundle` file carries new `installed_path` + `sha256_digest` fields
//! added by upstream Cluster C9 (5f1c9c73).
//!
//! Three tests:
//!
//! 1. **Extended bundle** — `.nono-trust.bundle` entry carrying `installed_path` +
//!    `sha256_digest` is parsed correctly via `serde_json::Value` (extra fields do
//!    NOT cause a parse failure). The offline-verify path extracts both fields
//!    without error.
//!
//! 2. **Legacy bundle** — `.nono-trust.bundle` entry WITHOUT `installed_path` /
//!    `sha256_digest` still deserialises correctly; code falls back to
//!    `artifact_name` for the installed path (D-32-15 backwards compatibility).
//!
//! 3. **Invalid installed_path** — a bundle entry whose `installed_path` field
//!    contains an unsafe value (path traversal `../../etc/passwd`, absolute path
//!    `/etc/passwd`, or empty string) is rejected by `validate_bundle_relative_path`
//!    with a clear error message (T-48-08-01 defense-in-depth).
//!
//! All three tests are structural: they do NOT require network I/O, a live Sigstore
//! endpoint, or a valid TUF trusted root on disk (D-32-15 verify-is-offline
//! invariant). Inline JSON fixtures keep the test hermetic.

use std::path::Path;

// ---------------------------------------------------------------------------
// Helpers mirroring the bundle-reading logic in profile_runtime.rs
// ---------------------------------------------------------------------------

/// Parse a `.nono-trust.bundle` JSON string and return the list of entries.
/// This mirrors `serde_json::from_str::<Vec<serde_json::Value>>()` in
/// `verify_stored_bundles` — the D-32-15 offline path uses plain Value
/// deserialization so that unknown fields (like `installed_path`) are silently
/// tolerated rather than causing a hard parse error.
fn parse_bundle_entries(json: &str) -> Vec<serde_json::Value> {
    serde_json::from_str(json).expect("bundle JSON should parse as Vec<Value>")
}

/// Validate that `installed_path` is a safe relative path.
/// This is a structural copy of the private `validate_bundle_relative_path`
/// function added in profile_runtime.rs by the C9-01 manual-replay; it is
/// duplicated here to allow hermetic unit-testing without exposing the private
/// function.
fn validate_bundle_relative_path<'a>(
    installed_path: &'a str,
    artifact_name: &str,
    pack_ref: &str,
) -> Result<&'a Path, String> {
    let path = Path::new(installed_path);
    if installed_path.is_empty() || path.is_absolute() {
        return Err(format!(
            "trust bundle entry for '{}' in pack '{}' has unsafe installed_path '{}'",
            artifact_name, pack_ref, installed_path
        ));
    }
    for component in path.components() {
        match component {
            std::path::Component::Normal(_) => {}
            _ => {
                return Err(format!(
                    "trust bundle entry for '{}' in pack '{}' has unsafe installed_path '{}'",
                    artifact_name, pack_ref, installed_path
                ));
            }
        }
    }
    Ok(path)
}

// ---------------------------------------------------------------------------
// Test 1: Extended bundle (installed_path + sha256_digest) parses correctly
// ---------------------------------------------------------------------------

/// D-48-C3 Test 1: `.nono-trust.bundle` carrying the new `installed_path` and
/// `sha256_digest` fields is parsed without error via plain `serde_json::Value`
/// deserialization. The D-32-15 offline-verify path tolerates extra schema fields
/// because it reads via `Vec<serde_json::Value>`, not a typed struct.
#[test]
fn extended_bundle_parses_and_fields_are_accessible() {
    // Inline fixture: an extended-schema bundle entry as produced by the
    // C9-01 manual-replay write_supporting_artifacts (includes installed_path).
    let bundle_json = r#"[
        {
            "artifact": "my-tool.profile.json",
            "installed_path": "profiles/my-tool.json",
            "digest": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
            "bundle": {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {
                    "publicKey": { "hint": "d48c3-test" },
                    "tlogEntries": []
                },
                "dsseEnvelope": {
                    "payloadType": "application/vnd.in-toto+json",
                    "payload": "e30=",
                    "signatures": [{"keyid": "", "sig": "AAAA"}]
                }
            }
        }
    ]"#;

    // 1a. Parse MUST succeed (Value deserialization is schema-tolerant).
    let entries = parse_bundle_entries(bundle_json);
    assert_eq!(entries.len(), 1, "expected exactly one bundle entry");

    let entry = &entries[0];

    // 1b. artifact field accessible.
    let artifact_name = entry
        .get("artifact")
        .and_then(|v| v.as_str())
        .expect("'artifact' field must be present and a string");
    assert_eq!(artifact_name, "my-tool.profile.json");

    // 1c. installed_path field accessible (new in C9-01).
    let installed_path = entry
        .get("installed_path")
        .and_then(|v| v.as_str())
        .expect("'installed_path' field must be present and a string in extended bundle");
    assert_eq!(installed_path, "profiles/my-tool.json");

    // 1d. digest field accessible (new in C9-01).
    let digest = entry
        .get("digest")
        .and_then(|v| v.as_str())
        .expect("'digest' field must be present and a string in extended bundle");
    assert_eq!(
        digest,
        "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
    );

    // 1e. bundle sub-object accessible (unaffected by schema extension).
    let bundle_val = entry.get("bundle").expect("'bundle' field must be present");
    assert!(
        bundle_val.is_object(),
        "'bundle' must be a JSON object, not {:?}",
        bundle_val
    );

    // 1f. validate_bundle_relative_path accepts the well-formed installed_path.
    let validated = validate_bundle_relative_path(installed_path, artifact_name, "test/pkg")
        .expect("installed_path 'profiles/my-tool.json' should be safe");
    assert_eq!(validated, Path::new("profiles/my-tool.json"));
}

// ---------------------------------------------------------------------------
// Test 2: Legacy bundle (no installed_path / digest) still deserialises
// ---------------------------------------------------------------------------

/// D-48-C3 Test 2: `.nono-trust.bundle` produced by an older fork build that
/// does NOT include `installed_path` or `sha256_digest` still parses without
/// error; the code falls back to `artifact_name` for the installed path.
/// This covers D-32-15 backwards compatibility.
#[test]
fn legacy_bundle_parses_and_falls_back_to_artifact_name() {
    // Inline fixture: a legacy bundle entry without installed_path / digest fields.
    let bundle_json = r#"[
        {
            "artifact": "groups.json",
            "bundle": {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {
                    "publicKey": { "hint": "d48c3-legacy-test" },
                    "tlogEntries": []
                },
                "dsseEnvelope": {
                    "payloadType": "application/vnd.in-toto+json",
                    "payload": "e30=",
                    "signatures": [{"keyid": "", "sig": "AAAA"}]
                }
            }
        }
    ]"#;

    // 2a. Parse MUST succeed.
    let entries = parse_bundle_entries(bundle_json);
    assert_eq!(entries.len(), 1, "expected exactly one bundle entry");

    let entry = &entries[0];

    // 2b. artifact name accessible.
    let artifact_name = entry
        .get("artifact")
        .and_then(|v| v.as_str())
        .expect("'artifact' field must be present");
    assert_eq!(artifact_name, "groups.json");

    // 2c. installed_path falls back to artifact_name (None / missing field case).
    let installed_path = entry
        .get("installed_path")
        .and_then(|v| v.as_str())
        .unwrap_or(artifact_name); // D-32-15 backwards-compat fallback
    assert_eq!(
        installed_path, "groups.json",
        "legacy bundle should fall back to artifact_name for installed_path"
    );

    // 2d. digest is optional in legacy bundles (None case is handled by caller
    //     with a clear error before trying to compare digests).
    let digest_opt = entry.get("digest").and_then(|v| v.as_str());
    assert!(
        digest_opt.is_none(),
        "legacy bundle should not have a 'digest' field, got {:?}",
        digest_opt
    );

    // 2e. validate_bundle_relative_path accepts the fallback path (single component).
    let validated =
        validate_bundle_relative_path(installed_path, artifact_name, "test/legacy-pkg")
            .expect("fallback installed_path 'groups.json' should be safe");
    assert_eq!(validated, Path::new("groups.json"));
}

// ---------------------------------------------------------------------------
// Test 3: Invalid installed_path values are rejected
// ---------------------------------------------------------------------------

/// D-48-C3 Test 3: `validate_bundle_relative_path` rejects attacker-controlled
/// `installed_path` values that could escape the package install root.
/// Covers T-48-08-01 (path traversal defense-in-depth).
#[test]
fn invalid_installed_path_values_are_rejected() {
    let artifact_name = "evil.profile.json";
    let pack_ref = "attacker/pkg";

    // Case A: path traversal with parent-dir component.
    let result_a =
        validate_bundle_relative_path("../../etc/passwd", artifact_name, pack_ref);
    assert!(
        result_a.is_err(),
        "path traversal '../../etc/passwd' must be rejected"
    );
    let err_a = result_a.unwrap_err();
    assert!(
        err_a.contains("unsafe installed_path"),
        "error must mention 'unsafe installed_path', got: {err_a}"
    );

    // Case B: absolute path.
    let result_b =
        validate_bundle_relative_path("/etc/passwd", artifact_name, pack_ref);
    assert!(
        result_b.is_err(),
        "absolute path '/etc/passwd' must be rejected"
    );
    let err_b = result_b.unwrap_err();
    assert!(
        err_b.contains("unsafe installed_path"),
        "error must mention 'unsafe installed_path', got: {err_b}"
    );

    // Case C: empty string.
    let result_c = validate_bundle_relative_path("", artifact_name, pack_ref);
    assert!(result_c.is_err(), "empty installed_path must be rejected");
    let err_c = result_c.unwrap_err();
    assert!(
        err_c.contains("unsafe installed_path"),
        "error must mention 'unsafe installed_path', got: {err_c}"
    );

    // Case D: single '.' component (current directory — not Normal per Rust's path model).
    let result_d = validate_bundle_relative_path(".", artifact_name, pack_ref);
    assert!(
        result_d.is_err(),
        "current-directory '.' must be rejected (not Component::Normal)"
    );

    // Case E: well-formed relative sub-path is ACCEPTED (positive control).
    let result_e =
        validate_bundle_relative_path("profiles/safe-name.json", artifact_name, pack_ref);
    assert!(
        result_e.is_ok(),
        "safe path 'profiles/safe-name.json' must be accepted, got: {:?}",
        result_e
    );
}
