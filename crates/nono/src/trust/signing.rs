//! Keyed signing primitives for instruction file attestation
//!
//! Provides ECDSA P-256 key generation, DSSE envelope signing, and Sigstore
//! bundle construction for keyed attestation workflows.
//!
//! # Signing Flow
//!
//! ```text
//! file content --> SHA-256 digest --> in-toto statement --> DSSE envelope
//!   --> PAE(payloadType, payload) --> ECDSA P-256 sign --> Sigstore bundle v0.3
//! ```
//!
//! # Key Management
//!
//! This module handles signing operations only. Key storage and retrieval
//! from the system keystore is a CLI concern. The library accepts key
//! material in PKCS#8 DER format.
//!
//! # Keyless Signing: OIDC Issuer Pinning
//!
//! Keyless signing flows (GitHub ID tokens, GitLab ID tokens) rely on an
//! `oidc_issuer` URL in the signing predicate. The `validate_oidc_issuer`
//! function provides a fail-closed, URL-component-level comparison against
//! a configured issuer pin — guarding against the `string-prefix-match`
//! anti-pattern (CLAUDE.md § Common Footguns #1). The fork's GitHub +
//! GitLab trust paths (`crates/nono-cli/src/trust_cmd.rs`) may call this
//! helper to verify issuer authenticity prior to publishing a signature.

use crate::error::{NonoError, Result};
use crate::trust::dsse;
use std::path::Path;

// ---------------------------------------------------------------------------
// OIDC issuer validation (D-11 upstream parity port — GitLab ID tokens)
// ---------------------------------------------------------------------------

/// Validate a token's `iss` claim against a configured issuer pin with
/// URL-component equality. Returns `Ok(())` only when the scheme, host,
/// and port match exactly.
///
/// # Security rationale
///
/// Using `string-prefix-match` (string prefix matching) would allow
/// `https://gitlab.com.evil.example/` to pass validation against a pin of
/// `https://gitlab.com/` (CLAUDE.md § Common Footguns #1). Parsing both
/// sides through `url::Url::parse` and comparing structured components
/// closes this path-traversal analog for URLs.
///
/// Per CLAUDE.md § Fail Secure: on any parsing failure or mismatch this
/// returns `NonoError::ConfigParse` with a description; callers MUST treat
/// any non-`Ok` return as a rejection and refuse to emit a signature.
///
/// Paths, query strings, and fragments are intentionally ignored — an
/// OIDC issuer identity is scheme+authority, not a specific endpoint
/// URI. Upstream GitLab tokens carry `https://gitlab.com` as `iss`, not
/// `https://gitlab.com/.well-known/openid-configuration`.
///
/// # Examples
///
/// ```no_run
/// use nono::trust::signing::validate_oidc_issuer;
///
/// // Exact match — accepted.
/// assert!(validate_oidc_issuer("https://gitlab.com", "https://gitlab.com").is_ok());
///
/// // Prefix-match attack — rejected.
/// assert!(
///     validate_oidc_issuer("https://gitlab.com.evil.example", "https://gitlab.com").is_err()
/// );
///
/// // Port mismatch — rejected.
/// assert!(validate_oidc_issuer(
///     "https://gitlab.example.com:8443",
///     "https://gitlab.example.com"
/// )
/// .is_err());
/// ```
///
/// # Errors
///
/// Returns `NonoError::ConfigParse` when:
/// - Either URL fails to parse
/// - Scheme differs
/// - Host differs (case-insensitive comparison, per RFC 3986)
/// - Explicit port differs
pub fn validate_oidc_issuer(iss: &str, pin: &str) -> Result<()> {
    // CLAUDE.md § Common Footguns #1: NEVER use `string-prefix-match` for
    // URL comparison. The url::Url::parse component-level check below is
    // the authoritative fail-closed comparison.
    let iss_url = url::Url::parse(iss).map_err(|e| {
        NonoError::ConfigParse(format!("OIDC issuer URL '{iss}' is not a valid URL: {e}"))
    })?;
    let pin_url = url::Url::parse(pin).map_err(|e| {
        NonoError::ConfigParse(format!("OIDC issuer pin '{pin}' is not a valid URL: {e}"))
    })?;

    if iss_url.scheme() != pin_url.scheme() {
        return Err(NonoError::ConfigParse(format!(
            "OIDC issuer scheme mismatch: token iss='{iss}' pin='{pin}' \
             (scheme '{iss_scheme}' != '{pin_scheme}')",
            iss_scheme = iss_url.scheme(),
            pin_scheme = pin_url.scheme(),
        )));
    }
    if iss_url.host_str() != pin_url.host_str() {
        return Err(NonoError::ConfigParse(format!(
            "OIDC issuer host mismatch: token iss='{iss}' pin='{pin}' \
             (host {iss_host:?} != {pin_host:?}). \
             Rejected prefix-match attack (CLAUDE.md § Common Footguns #1).",
            iss_host = iss_url.host_str(),
            pin_host = pin_url.host_str(),
        )));
    }
    if iss_url.port() != pin_url.port() {
        return Err(NonoError::ConfigParse(format!(
            "OIDC issuer port mismatch: token iss='{iss}' pin='{pin}' \
             (port {iss_port:?} != {pin_port:?})",
            iss_port = iss_url.port(),
            pin_port = pin_url.port(),
        )));
    }
    Ok(())
}

/// Canonical GitLab.com OIDC issuer URL — the default pin for GitLab-SaaS
/// keyless signing flows (upstream v0.35 ab5a064). Self-managed GitLab
/// instances use their own host (e.g. `https://gitlab.example.com`),
/// which callers should pin explicitly rather than defaulting.
pub const GITLAB_COM_OIDC_ISSUER: &str = "https://gitlab.com";

/// Canonical GitHub Actions OIDC issuer URL — the default pin for GitHub
/// Actions keyless signing (Fulcio accepts this issuer). Matches upstream
/// Sigstore `Fulcio`'s default OIDC issuer list.
pub const GITHUB_ACTIONS_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Read the configured OIDC issuer pin, preferring the `NONO_TRUST_OIDC_ISSUER`
/// env-var over the canonical [`GITHUB_ACTIONS_OIDC_ISSUER`] default. Returns
/// the pin URL string to use for [`validate_oidc_issuer`] callers.
///
/// # Behavior
///
/// - **env var set + parseable URL** — returned verbatim. Downstream
///   [`validate_oidc_issuer`] then enforces URL-component equality against
///   the token's `iss` claim.
/// - **env var set + unparseable URL** — returns
///   [`NonoError::ConfigParse`]. Callers MUST refuse to publish or verify
///   a signature rather than silently falling back to the default
///   (CLAUDE.md § Fail Secure).
/// - **env var unset OR whitespace-only** — returns the canonical
///   [`GITHUB_ACTIONS_OIDC_ISSUER`] constant string. Whitespace-only
///   values are treated as unset to avoid the trap where a CI workflow
///   accidentally exports `NONO_TRUST_OIDC_ISSUER=` with no value.
///
/// # Phase 44 WR-09 P37 (REQ-REVIEW-FU-01 D-44-B3)
///
/// The Phase 37 CI workflow declared `NONO_TRUST_OIDC_ISSUER` but no
/// production code ever read the value — the env var was inert and the
/// REQ-PKGS-04 acceptance #4 coverage claim on the workflow header was
/// misleading. This reader closes the gap by composing existing primitives:
/// [`validate_oidc_issuer`] for URL-component equality + the canonical
/// default const for fallback.
///
/// # Errors
///
/// Returns [`NonoError::ConfigParse`] when `NONO_TRUST_OIDC_ISSUER` is
/// set to a non-empty, non-whitespace value that fails `url::Url::parse`.
///
/// # Examples
///
/// ```no_run
/// use nono::trust::signing::configured_oidc_issuer;
///
/// // Whatever the env var says (after URL validation), or the default.
/// let pin = configured_oidc_issuer().expect("configured_oidc_issuer");
/// assert!(pin.starts_with("https://"));
/// ```
pub fn configured_oidc_issuer() -> Result<String> {
    match std::env::var("NONO_TRUST_OIDC_ISSUER") {
        Ok(v) if !v.trim().is_empty() => {
            // Eagerly validate that the env-var value is a parseable URL —
            // fail-closed before any signature operation begins. CLAUDE.md
            // § Fail Secure: never silently fall back to the default when
            // the operator explicitly set a value (even if malformed).
            url::Url::parse(&v).map_err(|e| {
                NonoError::ConfigParse(format!(
                    "NONO_TRUST_OIDC_ISSUER='{v}' is not a valid URL: {e}"
                ))
            })?;
            Ok(v)
        }
        _ => Ok(GITHUB_ACTIONS_OIDC_ISSUER.to_string()),
    }
}

// Re-export sigstore-crypto signing types
pub use sigstore_verify::crypto::signing::{KeyPair, SigningScheme};
pub use sigstore_verify::types::{DerPublicKey, PayloadBytes, SignatureBytes};

// Internal imports from sigstore
use sigstore_verify::crypto::hash::sha256;
use sigstore_verify::types::bundle::{
    Bundle, MediaType, SignatureContent, VerificationMaterial, VerificationMaterialContent,
};
use sigstore_verify::types::dsse::{DsseEnvelope as SigstoreDsseEnvelope, DsseSignature};
use sigstore_verify::types::encoding::KeyId;

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// Generate a new ECDSA P-256 signing key pair.
///
/// Returns the key pair which can be used for signing and public key export.
/// The caller is responsible for persisting the key material (e.g., via the
/// system keystore).
///
/// # Errors
///
/// Returns `NonoError::TrustSigning` if key generation fails.
pub fn generate_signing_key() -> Result<KeyPair> {
    KeyPair::generate_ecdsa_p256().map_err(|e| NonoError::TrustSigning {
        path: String::new(),
        reason: format!("key generation failed: {e}"),
    })
}

/// Compute the key ID (SHA-256 of DER-encoded SPKI public key) as a hex string.
///
/// This is the canonical identifier used to reference keys in trust policies
/// and bundle `publicKey.hint` fields.
///
/// # Errors
///
/// Returns `NonoError::TrustSigning` if the public key cannot be exported.
pub fn key_id_hex(key_pair: &KeyPair) -> Result<String> {
    let spki = key_pair
        .public_key_der()
        .map_err(|e| NonoError::TrustSigning {
            path: String::new(),
            reason: format!("failed to export public key: {e}"),
        })?;
    let hash = sha256(spki.as_bytes());
    Ok(hash.to_hex())
}

// ---------------------------------------------------------------------------
// File signing (high-level)
// ---------------------------------------------------------------------------

/// Sign an instruction file with a keyed signing key.
///
/// Computes the SHA-256 digest, builds the in-toto statement, creates a
/// DSSE envelope, signs it with ECDSA P-256, and wraps everything in a
/// Sigstore bundle v0.3.
///
/// # Arguments
///
/// * `file_path` - Path to the instruction file to sign
/// * `key_pair` - The ECDSA P-256 signing key pair
/// * `key_id` - Human-readable key identifier (e.g., `"nono-keystore:default"`)
///
/// # Returns
///
/// The Sigstore bundle as a pretty-printed JSON string.
///
/// # Errors
///
/// Returns `NonoError::TrustSigning` on any failure (file read, signing, etc.).
pub fn sign_instruction_file(file_path: &Path, key_pair: &KeyPair, key_id: &str) -> Result<String> {
    let content = std::fs::read(file_path).map_err(|e| NonoError::TrustSigning {
        path: file_path.display().to_string(),
        reason: format!("failed to read file: {e}"),
    })?;

    let filename = file_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .ok_or_else(|| NonoError::TrustSigning {
            path: file_path.display().to_string(),
            reason: "path has no filename component".to_string(),
        })?;

    sign_bytes(&content, &filename, key_pair, key_id).map_err(|e| match e {
        NonoError::TrustSigning { reason, .. } => NonoError::TrustSigning {
            path: file_path.display().to_string(),
            reason,
        },
        other => other,
    })
}

/// Sign arbitrary bytes as an instruction file attestation.
///
/// Lower-level than `sign_instruction_file` — takes content bytes directly
/// instead of reading from the filesystem.
///
/// # Arguments
///
/// * `content` - The file content to sign
/// * `filename` - The filename for the in-toto subject
/// * `key_pair` - The ECDSA P-256 signing key pair
/// * `key_id` - Human-readable key identifier
///
/// # Returns
///
/// The Sigstore bundle as a pretty-printed JSON string.
///
/// # Errors
///
/// Returns `NonoError::TrustSigning` on signing or serialization failure.
pub fn sign_bytes(
    content: &[u8],
    filename: &str,
    key_pair: &KeyPair,
    key_id: &str,
) -> Result<String> {
    sign_bytes_inner(
        content,
        filename,
        key_pair,
        key_id,
        dsse::NONO_PREDICATE_TYPE,
    )
}

/// Sign arbitrary bytes as a trust policy attestation.
///
/// Identical to `sign_bytes` but uses the policy predicate type to
/// distinguish policy bundles from instruction file bundles.
///
/// # Errors
///
/// Returns `NonoError::TrustSigning` on signing or serialization failure.
pub fn sign_policy_bytes(
    content: &[u8],
    filename: &str,
    key_pair: &KeyPair,
    key_id: &str,
) -> Result<String> {
    sign_bytes_inner(
        content,
        filename,
        key_pair,
        key_id,
        dsse::NONO_POLICY_PREDICATE_TYPE,
    )
}

/// Sign a trust policy file with a keyed signing key.
///
/// Reads the file, computes the SHA-256 digest, and builds a Sigstore
/// bundle with the policy-specific predicate type.
///
/// # Errors
///
/// Returns `NonoError::TrustSigning` on any failure.
pub fn sign_policy_file(file_path: &Path, key_pair: &KeyPair, key_id: &str) -> Result<String> {
    let content = std::fs::read(file_path).map_err(|e| NonoError::TrustSigning {
        path: file_path.display().to_string(),
        reason: format!("failed to read file: {e}"),
    })?;

    let filename = file_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .ok_or_else(|| NonoError::TrustSigning {
            path: file_path.display().to_string(),
            reason: "path has no filename component".to_string(),
        })?;

    sign_policy_bytes(&content, &filename, key_pair, key_id).map_err(|e| match e {
        NonoError::TrustSigning { reason, .. } => NonoError::TrustSigning {
            path: file_path.display().to_string(),
            reason,
        },
        other => other,
    })
}

/// Shared signing logic for both instruction files and trust policies.
fn sign_bytes_inner(
    content: &[u8],
    filename: &str,
    key_pair: &KeyPair,
    key_id: &str,
    predicate_type: &str,
) -> Result<String> {
    // Compute SHA-256 digest
    let digest_hash = sha256(content);
    let digest_hex = digest_hash.to_hex();

    // Build the signer predicate
    let signer_predicate = serde_json::json!({
        "version": 1,
        "signer": {
            "kind": "keyed",
            "key_id": key_id
        }
    });

    // Create the in-toto statement with the appropriate predicate type
    let statement = dsse::new_statement(filename, &digest_hex, signer_predicate, predicate_type);

    sign_statement(&statement, key_pair)
}

/// Maximum number of files allowed in a multi-subject attestation.
///
/// Defense-in-depth bound to prevent resource exhaustion from unbounded input.
/// 1,000 files is sufficient for any legitimate skill bundle while limiting
/// potential abuse vectors.
pub const MAX_MULTI_SUBJECT_FILES: usize = 1_000;

/// Sign multiple files together as a single multi-subject attestation.
///
/// Each `(path, sha256_hex)` pair becomes a subject in the in-toto statement.
/// The caller computes digests and provides relative paths as subject names.
///
/// # Arguments
///
/// * `files` - File paths and their pre-computed SHA-256 hex digests (max 1,000)
/// * `key_pair` - The ECDSA P-256 signing key pair
/// * `key_id` - Human-readable key identifier (e.g., `"nono-keystore:default"`)
///
/// # Returns
///
/// The Sigstore bundle as a pretty-printed JSON string.
///
/// # Errors
///
/// Returns `NonoError::TrustSigning` if:
/// - More than 1,000 files are provided
/// - Signing or serialization fails
pub fn sign_files(
    files: &[(std::path::PathBuf, String)],
    key_pair: &KeyPair,
    key_id: &str,
) -> Result<String> {
    if files.len() > MAX_MULTI_SUBJECT_FILES {
        return Err(NonoError::TrustSigning {
            path: String::new(),
            reason: format!(
                "too many files: {} exceeds maximum of {}",
                files.len(),
                MAX_MULTI_SUBJECT_FILES
            ),
        });
    }

    let subjects: Vec<(String, String)> = files
        .iter()
        .map(|(path, digest)| (path.display().to_string(), digest.clone()))
        .collect();

    let signer_predicate = serde_json::json!({
        "version": 1,
        "signer": {
            "kind": "keyed",
            "key_id": key_id
        }
    });

    let statement = dsse::new_multi_subject_statement(&subjects, signer_predicate);
    sign_statement(&statement, key_pair)
}

/// Sign an in-toto statement and wrap in a Sigstore bundle.
///
/// Shared signing engine: serializes the statement to JSON, computes PAE,
/// signs with ECDSA P-256, and constructs a Sigstore bundle v0.3.
fn sign_statement(statement: &dsse::InTotoStatement, key_pair: &KeyPair) -> Result<String> {
    // Serialize the statement to JSON (this becomes the DSSE payload)
    let statement_json = serde_json::to_string(statement).map_err(|e| NonoError::TrustSigning {
        path: String::new(),
        reason: format!("failed to serialize statement: {e}"),
    })?;

    // Build the sigstore-types PayloadBytes
    let payload = PayloadBytes::from_bytes(statement_json.as_bytes());

    // Compute PAE over the raw payload bytes
    let pae_bytes =
        sigstore_verify::types::dsse::pae(dsse::IN_TOTO_PAYLOAD_TYPE, payload.as_bytes());

    // Sign the PAE
    let signature = key_pair
        .sign(&pae_bytes)
        .map_err(|e| NonoError::TrustSigning {
            path: String::new(),
            reason: format!("ECDSA signing failed: {e}"),
        })?;

    // Construct the DSSE envelope (sigstore-types format)
    let envelope = SigstoreDsseEnvelope::new(
        dsse::IN_TOTO_PAYLOAD_TYPE.to_string(),
        payload,
        vec![DsseSignature {
            sig: signature,
            keyid: KeyId::default(),
        }],
    );

    // Build the key hint from the public key hash
    let hint = key_id_hex(key_pair)?;

    // Construct the Sigstore bundle.
    // Keyed bundles omit tlog_entries because Rekor transparency log integration
    // is only used for keyless (Fulcio/OIDC) workflows where the signing certificate
    // is short-lived and the Rekor entry provides a signed timestamp proving the
    // signature was created during the certificate's validity window. For keyed
    // bundles, the long-lived key provides its own trust anchor.
    let bundle = Bundle {
        media_type: MediaType::Bundle0_3.as_str().to_string(),
        verification_material: VerificationMaterial {
            content: VerificationMaterialContent::PublicKey { hint },
            tlog_entries: Vec::new(),
            timestamp_verification_data: Default::default(),
        },
        content: SignatureContent::DsseEnvelope(envelope),
    };

    // Serialize to pretty JSON
    bundle
        .to_json_pretty()
        .map_err(|e| NonoError::TrustSigning {
            path: String::new(),
            reason: format!("failed to serialize bundle: {e}"),
        })
}

/// Write a bundle JSON string to the conventional path (`<file>.bundle`).
///
/// # Errors
///
/// Returns `NonoError::TrustSigning` if the write fails.
pub fn write_bundle(file_path: &Path, bundle_json: &str) -> Result<()> {
    let bundle_path = super::bundle::bundle_path_for(file_path);
    std::fs::write(&bundle_path, bundle_json).map_err(|e| NonoError::TrustSigning {
        path: bundle_path.display().to_string(),
        reason: format!("failed to write bundle: {e}"),
    })
}

// ---------------------------------------------------------------------------
// PKCS#8 key serialization helpers
// ---------------------------------------------------------------------------

/// Export the public key as DER-encoded SPKI bytes.
///
/// Use `DerPublicKey::to_pem()` on the result for PEM format output.
///
/// # Errors
///
/// Returns `NonoError::TrustSigning` if the public key cannot be exported.
pub fn export_public_key(key_pair: &KeyPair) -> Result<DerPublicKey> {
    key_pair
        .public_key_der()
        .map_err(|e| NonoError::TrustSigning {
            path: String::new(),
            reason: format!("failed to export public key: {e}"),
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::trust::dsse::IN_TOTO_PAYLOAD_TYPE;

    // -----------------------------------------------------------------------
    // Key generation
    // -----------------------------------------------------------------------

    #[test]
    fn generate_signing_key_produces_valid_keypair() {
        let kp = generate_signing_key().unwrap();
        assert!(!kp.public_key_bytes().is_empty());
    }

    #[test]
    fn key_id_hex_is_deterministic() {
        let kp = generate_signing_key().unwrap();
        let id1 = key_id_hex(&kp).unwrap();
        let id2 = key_id_hex(&kp).unwrap();
        assert_eq!(id1, id2);
        // SHA-256 hex is 64 characters
        assert_eq!(id1.len(), 64);
    }

    #[test]
    fn key_id_hex_differs_between_keys() {
        let kp1 = generate_signing_key().unwrap();
        let kp2 = generate_signing_key().unwrap();
        let id1 = key_id_hex(&kp1).unwrap();
        let id2 = key_id_hex(&kp2).unwrap();
        assert_ne!(id1, id2);
    }

    // -----------------------------------------------------------------------
    // sign_bytes
    // -----------------------------------------------------------------------

    #[test]
    fn sign_bytes_produces_valid_bundle_json() {
        let kp = generate_signing_key().unwrap();
        let content = b"# SKILLS.md\nHello, world!";
        let result = sign_bytes(content, "SKILLS.md", &kp, "test-key").unwrap();

        // Should be valid JSON
        let bundle: serde_json::Value = serde_json::from_str(&result).unwrap();

        // Check media type
        assert_eq!(
            bundle["mediaType"].as_str().unwrap(),
            "application/vnd.dev.sigstore.bundle.v0.3+json"
        );

        // Check verification material has public key hint
        let hint = bundle["verificationMaterial"]["publicKey"]["hint"]
            .as_str()
            .unwrap();
        assert_eq!(hint.len(), 64); // SHA-256 hex

        // Check DSSE envelope is present
        assert!(bundle["dsseEnvelope"].is_object());
        assert_eq!(
            bundle["dsseEnvelope"]["payloadType"].as_str().unwrap(),
            IN_TOTO_PAYLOAD_TYPE
        );

        // Check signature is present and non-empty
        let sigs = bundle["dsseEnvelope"]["signatures"].as_array().unwrap();
        assert_eq!(sigs.len(), 1);
        assert!(!sigs[0]["sig"].as_str().unwrap().is_empty());
    }

    #[test]
    fn sign_bytes_bundle_contains_correct_digest() {
        let kp = generate_signing_key().unwrap();
        let content = b"test content for digest verification";
        let result = sign_bytes(content, "test.md", &kp, "test-key").unwrap();

        // Parse the bundle
        let bundle: serde_json::Value = serde_json::from_str(&result).unwrap();

        // Decode the DSSE payload (base64 standard)
        let payload_b64 = bundle["dsseEnvelope"]["payload"].as_str().unwrap();
        let payload_bytes = base64_decode(payload_b64);
        let statement: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        // Compute expected digest
        let expected_digest = sha256(content).to_hex();

        // Check statement subject digest matches
        assert_eq!(
            statement["subject"][0]["digest"]["sha256"]
                .as_str()
                .unwrap(),
            expected_digest
        );
        assert_eq!(statement["subject"][0]["name"].as_str().unwrap(), "test.md");
    }

    #[test]
    fn sign_bytes_signature_verifies() {
        use sigstore_verify::crypto::verification::VerificationKey;

        let kp = generate_signing_key().unwrap();
        let content = b"verify me";
        let result = sign_bytes(content, "test.md", &kp, "test-key").unwrap();

        // Parse the bundle
        let bundle: serde_json::Value = serde_json::from_str(&result).unwrap();

        // Extract the signature
        let sig_b64 = bundle["dsseEnvelope"]["signatures"][0]["sig"]
            .as_str()
            .unwrap();
        let sig_bytes = SignatureBytes::from_base64(sig_b64).unwrap();

        // Extract the payload and compute PAE
        let payload_b64 = bundle["dsseEnvelope"]["payload"].as_str().unwrap();
        let payload_bytes = base64_decode(payload_b64);
        let pae_bytes = sigstore_verify::types::dsse::pae(IN_TOTO_PAYLOAD_TYPE, &payload_bytes);

        // Verify the signature with the public key
        let pub_key = kp.public_key_der().unwrap();
        let vk = VerificationKey::from_spki(&pub_key, kp.default_scheme()).unwrap();
        vk.verify(&pae_bytes, &sig_bytes).unwrap();
    }

    #[test]
    fn sign_bytes_bundle_roundtrips_through_sigstore_bundle() {
        let kp = generate_signing_key().unwrap();
        let content = b"roundtrip test";
        let json = sign_bytes(content, "test.md", &kp, "test-key").unwrap();

        // Should parse as a sigstore Bundle
        let bundle = Bundle::from_json(&json).unwrap();
        assert_eq!(
            bundle.media_type,
            "application/vnd.dev.sigstore.bundle.v0.3+json"
        );
        assert!(matches!(
            bundle.verification_material.content,
            VerificationMaterialContent::PublicKey { .. }
        ));
        assert!(matches!(bundle.content, SignatureContent::DsseEnvelope(_)));
    }

    // -----------------------------------------------------------------------
    // sign_instruction_file
    // -----------------------------------------------------------------------

    #[test]
    fn sign_instruction_file_works() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("SKILLS.md");
        std::fs::write(&file_path, "# Skills\nDo something").unwrap();

        let kp = generate_signing_key().unwrap();
        let result = sign_instruction_file(&file_path, &kp, "test-key").unwrap();

        // Verify it's valid JSON with expected structure
        let bundle: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(
            bundle["dsseEnvelope"]["payloadType"].as_str().unwrap(),
            IN_TOTO_PAYLOAD_TYPE
        );
    }

    #[test]
    fn sign_instruction_file_nonexistent_returns_error() {
        let kp = generate_signing_key().unwrap();
        let result = sign_instruction_file(Path::new("/nonexistent/SKILLS.md"), &kp, "key");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Signing failed"));
    }

    // -----------------------------------------------------------------------
    // write_bundle
    // -----------------------------------------------------------------------

    #[test]
    fn write_bundle_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("SKILLS.md");
        std::fs::write(&file_path, "content").unwrap();

        let kp = generate_signing_key().unwrap();
        let json = sign_bytes(b"content", "SKILLS.md", &kp, "test").unwrap();

        write_bundle(&file_path, &json).unwrap();

        let bundle_path = dir.path().join("SKILLS.md.bundle");
        assert!(bundle_path.exists());

        let written = std::fs::read_to_string(&bundle_path).unwrap();
        assert_eq!(written, json);
    }

    // -----------------------------------------------------------------------
    // export_public_key
    // -----------------------------------------------------------------------

    #[test]
    fn export_public_key_produces_valid_spki() {
        let kp = generate_signing_key().unwrap();
        let pub_key = export_public_key(&kp).unwrap();
        assert!(!pub_key.is_empty());
        // SPKI-encoded P-256 key is typically 91 bytes
        assert!(pub_key.len() > 60);
    }

    #[test]
    fn export_public_key_to_pem() {
        let kp = generate_signing_key().unwrap();
        let pub_key = export_public_key(&kp).unwrap();
        let pem = pub_key.to_pem();
        assert!(pem.contains("-----BEGIN PUBLIC KEY-----"));
        assert!(pem.contains("-----END PUBLIC KEY-----"));
    }

    // -----------------------------------------------------------------------
    // sign_policy_bytes
    // -----------------------------------------------------------------------

    #[test]
    fn sign_policy_bytes_uses_policy_predicate_type() {
        let kp = generate_signing_key().unwrap();
        let content = b"{\"publishers\":[]}";
        let result = sign_policy_bytes(content, "trust-policy.json", &kp, "test-key").unwrap();

        let bundle: serde_json::Value = serde_json::from_str(&result).unwrap();
        let payload_b64 = bundle["dsseEnvelope"]["payload"].as_str().unwrap();
        let payload_bytes = base64_decode(payload_b64);
        let statement: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        assert_eq!(
            statement["predicateType"].as_str().unwrap(),
            dsse::NONO_POLICY_PREDICATE_TYPE
        );
        assert_eq!(
            statement["subject"][0]["name"].as_str().unwrap(),
            "trust-policy.json"
        );
    }

    #[test]
    fn sign_policy_bytes_differs_from_instruction_bytes() {
        let kp = generate_signing_key().unwrap();
        let content = b"same content";

        let instruction_bundle = sign_bytes(content, "file.md", &kp, "key").unwrap();
        let policy_bundle = sign_policy_bytes(content, "file.md", &kp, "key").unwrap();

        // Bundles should differ because predicate types differ
        let instr_val: serde_json::Value = serde_json::from_str(&instruction_bundle).unwrap();
        let policy_val: serde_json::Value = serde_json::from_str(&policy_bundle).unwrap();

        let instr_payload = base64_decode(instr_val["dsseEnvelope"]["payload"].as_str().unwrap());
        let policy_payload = base64_decode(policy_val["dsseEnvelope"]["payload"].as_str().unwrap());

        let instr_stmt: serde_json::Value = serde_json::from_slice(&instr_payload).unwrap();
        let policy_stmt: serde_json::Value = serde_json::from_slice(&policy_payload).unwrap();

        assert_ne!(
            instr_stmt["predicateType"].as_str().unwrap(),
            policy_stmt["predicateType"].as_str().unwrap()
        );
    }

    #[test]
    fn sign_policy_bytes_signature_verifies() {
        use sigstore_verify::crypto::verification::VerificationKey;

        let kp = generate_signing_key().unwrap();
        let content = b"{\"publishers\":[],\"enforcement\":\"deny\"}";
        let result = sign_policy_bytes(content, "trust-policy.json", &kp, "key").unwrap();

        let bundle: serde_json::Value = serde_json::from_str(&result).unwrap();
        let sig_b64 = bundle["dsseEnvelope"]["signatures"][0]["sig"]
            .as_str()
            .unwrap();
        let sig_bytes = SignatureBytes::from_base64(sig_b64).unwrap();

        let payload_b64 = bundle["dsseEnvelope"]["payload"].as_str().unwrap();
        let payload_bytes = base64_decode(payload_b64);
        let pae_bytes = sigstore_verify::types::dsse::pae(IN_TOTO_PAYLOAD_TYPE, &payload_bytes);

        let pub_key = kp.public_key_der().unwrap();
        let vk = VerificationKey::from_spki(&pub_key, kp.default_scheme()).unwrap();
        vk.verify(&pae_bytes, &sig_bytes).unwrap();
    }

    // -----------------------------------------------------------------------
    // sign_policy_file
    // -----------------------------------------------------------------------

    #[test]
    fn sign_policy_file_works() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("trust-policy.json");
        std::fs::write(&file_path, "{\"publishers\":[]}").unwrap();

        let kp = generate_signing_key().unwrap();
        let result = sign_policy_file(&file_path, &kp, "test-key").unwrap();

        let bundle: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(
            bundle["dsseEnvelope"]["payloadType"].as_str().unwrap(),
            IN_TOTO_PAYLOAD_TYPE
        );

        let payload_b64 = bundle["dsseEnvelope"]["payload"].as_str().unwrap();
        let payload_bytes = base64_decode(payload_b64);
        let statement: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(
            statement["predicateType"].as_str().unwrap(),
            dsse::NONO_POLICY_PREDICATE_TYPE
        );
    }

    #[test]
    fn sign_policy_file_nonexistent_returns_error() {
        let kp = generate_signing_key().unwrap();
        let result = sign_policy_file(Path::new("/nonexistent/trust-policy.json"), &kp, "key");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // sign_files (multi-subject)
    // -----------------------------------------------------------------------

    #[test]
    fn sign_files_produces_valid_multi_subject_bundle() {
        let kp = generate_signing_key().unwrap();
        let files = vec![
            (
                std::path::PathBuf::from("SKILL.md"),
                crate::trust::digest::bytes_digest(b"skill content"),
            ),
            (
                std::path::PathBuf::from("lib/helper.py"),
                crate::trust::digest::bytes_digest(b"helper content"),
            ),
        ];
        let result = sign_files(&files, &kp, "test-key").unwrap();

        let bundle: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(
            bundle["mediaType"].as_str().unwrap(),
            "application/vnd.dev.sigstore.bundle.v0.3+json"
        );

        let payload_b64 = bundle["dsseEnvelope"]["payload"].as_str().unwrap();
        let payload_bytes = base64_decode(payload_b64);
        let statement: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        assert_eq!(
            statement["predicateType"].as_str().unwrap(),
            dsse::NONO_MULTI_SUBJECT_PREDICATE_TYPE
        );

        let subjects = statement["subject"].as_array().unwrap();
        assert_eq!(subjects.len(), 2);
        assert_eq!(subjects[0]["name"].as_str().unwrap(), "SKILL.md");
        assert_eq!(subjects[1]["name"].as_str().unwrap(), "lib/helper.py");
    }

    #[test]
    fn sign_files_signature_verifies() {
        use sigstore_verify::crypto::verification::VerificationKey;

        let kp = generate_signing_key().unwrap();
        let files = vec![
            (
                std::path::PathBuf::from("a.md"),
                crate::trust::digest::bytes_digest(b"aaa"),
            ),
            (
                std::path::PathBuf::from("b.py"),
                crate::trust::digest::bytes_digest(b"bbb"),
            ),
        ];
        let result = sign_files(&files, &kp, "test-key").unwrap();

        let bundle: serde_json::Value = serde_json::from_str(&result).unwrap();
        let sig_b64 = bundle["dsseEnvelope"]["signatures"][0]["sig"]
            .as_str()
            .unwrap();
        let sig_bytes = SignatureBytes::from_base64(sig_b64).unwrap();

        let payload_b64 = bundle["dsseEnvelope"]["payload"].as_str().unwrap();
        let payload_bytes = base64_decode(payload_b64);
        let pae_bytes = sigstore_verify::types::dsse::pae(IN_TOTO_PAYLOAD_TYPE, &payload_bytes);

        let pub_key = kp.public_key_der().unwrap();
        let vk = VerificationKey::from_spki(&pub_key, kp.default_scheme()).unwrap();
        vk.verify(&pae_bytes, &sig_bytes).unwrap();
    }

    #[test]
    fn sign_files_roundtrips_through_sigstore_bundle() {
        let kp = generate_signing_key().unwrap();
        let files = vec![(
            std::path::PathBuf::from("single.md"),
            crate::trust::digest::bytes_digest(b"content"),
        )];
        let json = sign_files(&files, &kp, "test-key").unwrap();

        let bundle = Bundle::from_json(&json).unwrap();
        assert_eq!(
            bundle.media_type,
            "application/vnd.dev.sigstore.bundle.v0.3+json"
        );
        assert!(matches!(bundle.content, SignatureContent::DsseEnvelope(_)));
    }

    #[test]
    fn sign_files_rejects_too_many_files() {
        let kp = generate_signing_key().unwrap();
        let files: Vec<_> = (0..MAX_MULTI_SUBJECT_FILES + 1)
            .map(|i| {
                (
                    std::path::PathBuf::from(format!("file{i}.md")),
                    crate::trust::digest::bytes_digest(format!("content{i}").as_bytes()),
                )
            })
            .collect();

        let result = sign_files(&files, &kp, "test-key");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("too many files"));
        assert!(err.contains(&MAX_MULTI_SUBJECT_FILES.to_string()));
    }

    #[test]
    fn sign_files_accepts_max_files() {
        // This test verifies the boundary condition - exactly MAX files should succeed
        // We use a smaller subset to keep the test fast
        let kp = generate_signing_key().unwrap();
        let files: Vec<_> = (0..100)
            .map(|i| {
                (
                    std::path::PathBuf::from(format!("file{i}.md")),
                    crate::trust::digest::bytes_digest(format!("content{i}").as_bytes()),
                )
            })
            .collect();

        let result = sign_files(&files, &kp, "test-key");
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn base64_decode(input: &str) -> Vec<u8> {
        use sigstore_verify::types::PayloadBytes;
        PayloadBytes::from_base64(input).unwrap().into_bytes()
    }

    // -----------------------------------------------------------------------
    // OIDC issuer validation (D-11 upstream parity port — GitLab ID tokens)
    //
    // Mirrors upstream's GitHub coverage. The prefix-match regression guard
    // (test_gitlab_id_token_rejects_prefix_matched_issuer) explicitly checks
    // that `https://gitlab.evil.com/` is REJECTED when the pin is
    // `https://gitlab.com/`, guarding against the `string-prefix-match`
    // anti-pattern (CLAUDE.md § Common Footguns #1).
    // -----------------------------------------------------------------------

    #[test]
    fn test_gitlab_id_token_happy_path() {
        // Mirrors upstream's GitHub happy-path: a GitLab.com-issued token
        // matches the canonical GitLab pin. This is the positive case the
        // issuer-pin check must not reject.
        let token_iss = "https://gitlab.com";
        assert!(validate_oidc_issuer(token_iss, GITLAB_COM_OIDC_ISSUER).is_ok());
    }

    #[test]
    fn test_gitlab_id_token_self_managed_happy_path() {
        // Self-managed GitLab instances use their own hostname. The pin must
        // match exactly — there is no wildcard or suffix logic.
        let pin = "https://gitlab.example.com";
        let iss = "https://gitlab.example.com";
        assert!(validate_oidc_issuer(iss, pin).is_ok());
    }

    #[test]
    fn test_gitlab_id_token_rejects_wrong_issuer() {
        // A token whose issuer does NOT match the pin returns an error.
        // `matches!` assertion (structural) — not a string match on the
        // error text (which can drift with message edits).
        let iss = "https://gitlab.example.com";
        let pin = GITLAB_COM_OIDC_ISSUER; // https://gitlab.com
        let err = validate_oidc_issuer(iss, pin).expect_err("must reject wrong issuer");
        assert!(
            matches!(err, NonoError::ConfigParse(_)),
            "unexpected error variant: {err:?}"
        );
    }

    #[test]
    fn test_gitlab_id_token_rejects_prefix_matched_issuer() {
        // EXPLICIT regression guard against the `string-prefix-match`
        // anti-pattern (CLAUDE.md § Common Footguns #1). If a future
        // refactor loses URL-component equality and regresses to string
        // prefix matching, this test must fail.
        //
        // Hostile issuer: `https://gitlab.com.evil.example` starts with
        // `https://gitlab.com` under string comparison but is a different
        // host under URL-component equality.
        let pin = GITLAB_COM_OIDC_ISSUER; // https://gitlab.com
        let hostile = "https://gitlab.com.evil.example";
        let err = validate_oidc_issuer(hostile, pin)
            .expect_err("prefix-matched hostile issuer must be rejected");
        assert!(
            matches!(err, NonoError::ConfigParse(_)),
            "unexpected error variant: {err:?}"
        );
    }

    #[test]
    fn test_gitlab_id_token_rejects_malformed_token() {
        // Malformed issuer URL returns an error. Each of these inputs
        // fails url::Url::parse (no scheme, garbage, empty) so validator
        // rejects with ConfigParse.
        let pin = GITLAB_COM_OIDC_ISSUER;
        for bad in ["", "not a url", "://missing-scheme"] {
            let result = validate_oidc_issuer(bad, pin);
            assert!(
                matches!(result, Err(NonoError::ConfigParse(_))),
                "malformed token issuer {bad:?} must return ConfigParse error; got {result:?}"
            );
        }
    }

    #[test]
    fn test_gitlab_id_token_rejects_scheme_mismatch() {
        // Upgrade-downgrade attack: http token with https pin. Schemes
        // must match exactly.
        let pin = "https://gitlab.com";
        let http_iss = "http://gitlab.com";
        assert!(matches!(
            validate_oidc_issuer(http_iss, pin),
            Err(NonoError::ConfigParse(_))
        ));
    }

    #[test]
    fn test_gitlab_id_token_rejects_port_mismatch() {
        // Port mismatch attack: self-managed instance on custom port vs
        // pin on default port.
        let pin = "https://gitlab.example.com";
        let port_iss = "https://gitlab.example.com:8443";
        assert!(matches!(
            validate_oidc_issuer(port_iss, pin),
            Err(NonoError::ConfigParse(_))
        ));
    }

    #[test]
    fn test_github_id_token_happy_path() {
        // Parity with existing GitHub ID token trust path. If this fails
        // without an intentional change to GITHUB_ACTIONS_OIDC_ISSUER the
        // mirrored GitLab test coverage has drifted from the GitHub path.
        assert!(validate_oidc_issuer(
            "https://token.actions.githubusercontent.com",
            GITHUB_ACTIONS_OIDC_ISSUER
        )
        .is_ok());
    }

    #[test]
    fn test_github_id_token_rejects_prefix_attack() {
        // Same regression guard applied to the GitHub pin — ensures the
        // pin helper is provider-agnostic rather than GitLab-special-cased.
        let hostile = "https://token.actions.githubusercontent.com.evil.example";
        assert!(matches!(
            validate_oidc_issuer(hostile, GITHUB_ACTIONS_OIDC_ISSUER),
            Err(NonoError::ConfigParse(_))
        ));
    }

    // -----------------------------------------------------------------------
    // configured_oidc_issuer (Phase 44 WR-09 P37, REQ-REVIEW-FU-01 D-44-B3)
    // -----------------------------------------------------------------------

    /// Process-global lock for tests that mutate NONO_TRUST_OIDC_ISSUER.
    /// Rust runs unit tests in parallel within the same process; concurrent
    /// env-var mutation across sibling tests in this module would race
    /// against each other. Acquire this lock before mutating the env-var
    /// at the start of every configured_oidc_issuer_* test.
    static OIDC_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// RAII guard that sets NONO_TRUST_OIDC_ISSUER (or removes it) for the
    /// duration of a test and restores the original value on drop.
    struct OidcEnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        prev: Option<String>,
    }

    impl OidcEnvGuard {
        #[allow(clippy::disallowed_methods)]
        fn set(val: &str) -> Self {
            let _lock = match OIDC_ENV_LOCK.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            let prev = std::env::var("NONO_TRUST_OIDC_ISSUER").ok();
            std::env::set_var("NONO_TRUST_OIDC_ISSUER", val);
            Self { _lock, prev }
        }

        #[allow(clippy::disallowed_methods)]
        fn remove() -> Self {
            let _lock = match OIDC_ENV_LOCK.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            let prev = std::env::var("NONO_TRUST_OIDC_ISSUER").ok();
            std::env::remove_var("NONO_TRUST_OIDC_ISSUER");
            Self { _lock, prev }
        }
    }

    impl Drop for OidcEnvGuard {
        #[allow(clippy::disallowed_methods)]
        fn drop(&mut self) {
            match self.prev.take() {
                Some(v) => std::env::set_var("NONO_TRUST_OIDC_ISSUER", v),
                None => std::env::remove_var("NONO_TRUST_OIDC_ISSUER"),
            }
        }
    }

    /// Phase 44 WR-09 P37: when the env var is set to a valid URL, the
    /// reader returns that value verbatim (downstream validate_oidc_issuer
    /// then enforces equality against the token's iss claim).
    #[test]
    fn configured_oidc_issuer_returns_env_when_set() {
        let _g = OidcEnvGuard::set("https://token.actions.githubusercontent.com");
        assert_eq!(
            configured_oidc_issuer().unwrap(),
            "https://token.actions.githubusercontent.com"
        );
    }

    /// Phase 44 WR-09 P37: with the env var unset, fall back to the
    /// canonical GitHub Actions default const.
    #[test]
    fn configured_oidc_issuer_falls_back_to_github_default_when_unset() {
        let _g = OidcEnvGuard::remove();
        assert_eq!(
            configured_oidc_issuer().unwrap(),
            GITHUB_ACTIONS_OIDC_ISSUER
        );
    }

    /// Phase 44 WR-09 P37: a whitespace-only env-var value is treated as
    /// unset — the "accidentally exported empty value" trap. Falls back
    /// to the canonical default.
    #[test]
    fn configured_oidc_issuer_treats_whitespace_only_as_unset() {
        let _g = OidcEnvGuard::set("   ");
        assert_eq!(
            configured_oidc_issuer().unwrap(),
            GITHUB_ACTIONS_OIDC_ISSUER
        );
    }

    /// Phase 44 WR-09 P37 (CLAUDE.md § Fail Secure): a malformed env-var
    /// value MUST surface as ConfigParse — the caller refuses to publish
    /// or verify rather than silently falling back to the default.
    #[test]
    fn configured_oidc_issuer_rejects_malformed_env_value() {
        let _g = OidcEnvGuard::set("not a valid url at all");
        let err = configured_oidc_issuer().unwrap_err();
        assert!(
            matches!(err, NonoError::ConfigParse(_)),
            "expected ConfigParse on malformed URL, got: {err:?}"
        );
    }
}
