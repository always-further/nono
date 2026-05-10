//! Phase 32 D-32-10 (P32-CHK-015): verify that the baked-in keyless trust-policy
//! template at `docs/templates/trust-policy-keyless-template.json` loads correctly
//! via the existing `nono::trust::policy::TrustPolicy` deserializer.
//!
//! This test lives in `crates/nono-cli/tests/` (NOT in `crates/nono/src/`) per
//! P32-CHK-015: placing it here avoids any D-19 / D-32-15 enumeration ambiguity
//! (new test files under `crates/nono/src/` require explicit D-32-15 listing).
//! The test exercises the same parsing path as the production CLI.

use std::path::PathBuf;

/// D-32-10 (P32-CHK-015): the trust-policy template must load via the same
/// `TrustPolicy` deserializer the CLI uses at runtime, confirming the template
/// is schema-compatible and not just valid JSON.
#[test]
fn default_template_parses() {
    // CARGO_MANIFEST_DIR for crates/nono-cli is <workspace>/crates/nono-cli,
    // so `../..` reaches the workspace root where `docs/` lives.
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("docs")
        .join("templates")
        .join("trust-policy-keyless-template.json");

    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("template at {} must exist: {e}", path.display()));

    // Parse via the SAME deserializer the CLI uses at runtime.
    // Using load_policy_from_str to also exercise validate_version().
    let policy = nono::trust::policy::load_policy_from_str(&content).unwrap_or_else(|e| {
        panic!(
            "template must parse via TrustPolicy deserializer: {e}\n\
             content: {content}"
        )
    });

    // Sanity check: at least one publisher with the canonical GitHub Actions
    // OIDC issuer populated (confirms the template is not empty and uses the
    // canonical issuer documented in D-32-08 / D-32-10).
    assert!(
        !policy.publishers.is_empty(),
        "template must define at least one publisher"
    );
    let gha_publisher = policy
        .publishers
        .iter()
        .find(|p| {
            p.issuer
                .as_deref()
                .map(|i| i.contains("token.actions.githubusercontent.com"))
                .unwrap_or(false)
        })
        .unwrap_or_else(|| {
            panic!(
                "template must contain a publisher with the canonical GitHub Actions OIDC issuer; \
                 publishers: {:?}",
                policy.publishers
            )
        });

    // Confirm the ref_pattern field is populated (D-32-10 requirement).
    assert!(
        gha_publisher.ref_pattern.is_some(),
        "GitHub Actions publisher must have a ref_pattern; publisher: {:?}",
        gha_publisher
    );
}
