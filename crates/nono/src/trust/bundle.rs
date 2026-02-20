//! Sigstore bundle loading, verification, and identity extraction
//!
//! Wraps the `sigstore-verify` crate to provide bundle parsing, cryptographic
//! verification, and signer identity extraction integrated with nono's trust
//! policy types.
//!
//! # Bundle Format
//!
//! Bundles follow the Sigstore bundle v0.3 JSON format and contain:
//! - A DSSE envelope (or message signature) with the signed payload
//! - Verification material (Fulcio certificate or public key hint)
//! - Transparency log entries (Rekor inclusion proof)
//!
//! # Fulcio Certificate Extensions
//!
//! Keyless bundles contain a Fulcio-issued certificate with OIDC identity
//! claims encoded as X.509 extensions:
//!
//! | OID | Field | Description |
//! |-----|-------|-------------|
//! | 1.3.6.1.4.1.57264.1.1 | Issuer | OIDC issuer URL |
//! | 1.3.6.1.4.1.57264.1.8 | Source Repository | Repository URI |
//! | 1.3.6.1.4.1.57264.1.10 | Source Repository Ref | Git ref at signing time |
//! | 1.3.6.1.4.1.57264.1.11 | Build Config URI | Workflow file path |

use crate::error::{NonoError, Result};
use crate::trust::types::SignerIdentity;
use std::path::Path;

// Re-export key sigstore types for downstream consumers
pub use sigstore_verify::crypto::CertificateInfo;
pub use sigstore_verify::trust_root::TrustedRoot;
pub use sigstore_verify::types::{Bundle, DerPublicKey, Sha256Hash};
pub use sigstore_verify::{VerificationPolicy, VerificationResult as SigstoreVerificationResult};

// Internal-only imports from sigstore
use sigstore_verify::crypto::parse_certificate_info;
use sigstore_verify::types::bundle::VerificationMaterialContent;

// ---------------------------------------------------------------------------
// Fulcio certificate extension OIDs (v2 extensions)
// ---------------------------------------------------------------------------

/// Fulcio OID for source repository URI: 1.3.6.1.4.1.57264.1.8
const OID_SOURCE_REPOSITORY: &str = "1.3.6.1.4.1.57264.1.8";

/// Fulcio OID for source repository ref (git ref): 1.3.6.1.4.1.57264.1.10
const OID_SOURCE_REPOSITORY_REF: &str = "1.3.6.1.4.1.57264.1.10";

/// Fulcio OID for build config URI (workflow): 1.3.6.1.4.1.57264.1.11
const OID_BUILD_CONFIG_URI: &str = "1.3.6.1.4.1.57264.1.11";

// ---------------------------------------------------------------------------
// Bundle loading
// ---------------------------------------------------------------------------

/// Load a Sigstore bundle from a JSON file.
///
/// Bundle files are typically named `<artifact>.bundle` (e.g., `SKILLS.md.bundle`).
///
/// # Errors
///
/// Returns `NonoError::Io` if the file cannot be read, or
/// `NonoError::TrustVerification` if the JSON is malformed.
pub fn load_bundle<P: AsRef<Path>>(path: P) -> Result<Bundle> {
    let path = path.as_ref();
    let json = std::fs::read_to_string(path).map_err(NonoError::Io)?;
    load_bundle_from_str(&json, path)
}

/// Parse a Sigstore bundle from a JSON string.
///
/// The `source_path` is used only for error messages.
///
/// # Errors
///
/// Returns `NonoError::TrustVerification` if the JSON is invalid.
pub fn load_bundle_from_str(json: &str, source_path: &Path) -> Result<Bundle> {
    Bundle::from_json(json).map_err(|e| NonoError::TrustVerification {
        path: source_path.display().to_string(),
        reason: format!("failed to parse bundle: {e}"),
    })
}

// ---------------------------------------------------------------------------
// Trust root loading
// ---------------------------------------------------------------------------

/// Load a Sigstore trusted root from a JSON file.
///
/// The trusted root contains Fulcio CA certificates, Rekor public keys,
/// and TSA certificates needed for verification.
///
/// # Errors
///
/// Returns `NonoError::TrustPolicy` if the file cannot be read or parsed.
pub fn load_trusted_root<P: AsRef<Path>>(path: P) -> Result<TrustedRoot> {
    TrustedRoot::from_file(path.as_ref())
        .map_err(|e| NonoError::TrustPolicy(format!("failed to load trusted root: {e}")))
}

/// Load a Sigstore trusted root from a JSON string.
///
/// # Errors
///
/// Returns `NonoError::TrustPolicy` if the JSON is invalid.
pub fn load_trusted_root_from_str(json: &str) -> Result<TrustedRoot> {
    TrustedRoot::from_json(json)
        .map_err(|e| NonoError::TrustPolicy(format!("failed to parse trusted root: {e}")))
}

/// Load the production Sigstore trusted root (embedded).
///
/// This uses the Sigstore public good instance trusted root that is
/// embedded in the `sigstore-trust-root` crate.
///
/// # Errors
///
/// Returns `NonoError::TrustPolicy` if the embedded root cannot be loaded.
pub fn load_production_trusted_root() -> Result<TrustedRoot> {
    TrustedRoot::production()
        .map_err(|e| NonoError::TrustPolicy(format!("failed to load production trusted root: {e}")))
}

// ---------------------------------------------------------------------------
// Bundle verification
// ---------------------------------------------------------------------------

/// Verify a Sigstore bundle against an artifact's content.
///
/// Performs the full Sigstore verification pipeline:
/// 1. Bundle structural validation
/// 2. Certificate chain verification (Fulcio CA -> signing cert)
/// 3. Transparency log inclusion proof (Rekor)
/// 4. Signature verification (ECDSA over DSSE PAE)
/// 5. Artifact digest match (SHA-256 in in-toto statement vs actual file)
/// 6. Policy checks (identity/issuer matching)
///
/// # Errors
///
/// Returns `NonoError::TrustVerification` if any verification step fails.
pub fn verify_bundle(
    artifact_bytes: &[u8],
    bundle: &Bundle,
    trusted_root: &TrustedRoot,
    policy: &VerificationPolicy,
    artifact_path: &Path,
) -> Result<SigstoreVerificationResult> {
    sigstore_verify::verify(artifact_bytes, bundle, policy, trusted_root).map_err(|e| {
        NonoError::TrustVerification {
            path: artifact_path.display().to_string(),
            reason: format!("{e}"),
        }
    })
}

/// Verify a Sigstore bundle using a pre-computed SHA-256 digest.
///
/// This avoids re-reading the artifact when the digest is already known
/// (e.g., from blocklist checking earlier in the pipeline).
///
/// # Errors
///
/// Returns `NonoError::TrustVerification` if verification fails, or if
/// the digest hex string is invalid.
pub fn verify_bundle_with_digest(
    digest_hex: &str,
    bundle: &Bundle,
    trusted_root: &TrustedRoot,
    policy: &VerificationPolicy,
    artifact_path: &Path,
) -> Result<SigstoreVerificationResult> {
    let hash = Sha256Hash::from_hex(digest_hex).map_err(|e| NonoError::TrustVerification {
        path: artifact_path.display().to_string(),
        reason: format!("invalid digest hex: {e}"),
    })?;
    sigstore_verify::verify(hash, bundle, policy, trusted_root).map_err(|e| {
        NonoError::TrustVerification {
            path: artifact_path.display().to_string(),
            reason: format!("{e}"),
        }
    })
}

/// Verify a Sigstore bundle using a provided public key (keyed signing).
///
/// Used for bundles signed with a managed key (from the system keystore)
/// rather than a Fulcio-issued certificate.
///
/// # Errors
///
/// Returns `NonoError::TrustVerification` if verification fails.
pub fn verify_bundle_keyed(
    artifact_bytes: &[u8],
    bundle: &Bundle,
    public_key: &DerPublicKey,
    trusted_root: &TrustedRoot,
    artifact_path: &Path,
) -> Result<SigstoreVerificationResult> {
    sigstore_verify::verify_with_key(artifact_bytes, bundle, public_key, trusted_root).map_err(
        |e| NonoError::TrustVerification {
            path: artifact_path.display().to_string(),
            reason: format!("{e}"),
        },
    )
}

// ---------------------------------------------------------------------------
// Identity extraction
// ---------------------------------------------------------------------------

/// Extract the signer identity from a Sigstore bundle's verification material.
///
/// For bundles with a Fulcio certificate (keyless), extracts:
/// - OIDC issuer (OID 1.3.6.1.4.1.57264.1.1)
/// - Source repository (OID 1.3.6.1.4.1.57264.1.8)
/// - Build config / workflow (OID 1.3.6.1.4.1.57264.1.11)
/// - Source repository ref (OID 1.3.6.1.4.1.57264.1.10)
///
/// For bundles with a public key hint (keyed), returns the key hint as
/// the key ID.
///
/// # Errors
///
/// Returns `NonoError::TrustVerification` if the certificate cannot be
/// parsed or lacks required identity fields.
pub fn extract_signer_identity(bundle: &Bundle, bundle_path: &Path) -> Result<SignerIdentity> {
    match &bundle.verification_material.content {
        VerificationMaterialContent::PublicKey { hint } => Ok(SignerIdentity::Keyed {
            key_id: hint.clone(),
        }),
        VerificationMaterialContent::Certificate(cert_content) => {
            extract_identity_from_cert(cert_content.raw_bytes.as_bytes(), bundle_path)
        }
        VerificationMaterialContent::X509CertificateChain { certificates } => {
            let leaf = certificates
                .first()
                .ok_or_else(|| NonoError::TrustVerification {
                    path: bundle_path.display().to_string(),
                    reason: "empty certificate chain".to_string(),
                })?;
            extract_identity_from_cert(leaf.raw_bytes.as_bytes(), bundle_path)
        }
    }
}

/// Extract signer identity fields from a DER-encoded Fulcio certificate.
fn extract_identity_from_cert(cert_der: &[u8], bundle_path: &Path) -> Result<SignerIdentity> {
    let cert_info = parse_certificate_info(cert_der).map_err(|e| NonoError::TrustVerification {
        path: bundle_path.display().to_string(),
        reason: format!("failed to parse signing certificate: {e}"),
    })?;

    let issuer = cert_info
        .issuer
        .ok_or_else(|| NonoError::TrustVerification {
            path: bundle_path.display().to_string(),
            reason: "signing certificate missing OIDC issuer extension".to_string(),
        })?;

    // Extract extended Fulcio OIDs from the raw certificate
    let extensions = extract_fulcio_extensions(cert_der, bundle_path)?;

    Ok(SignerIdentity::Keyless {
        issuer,
        repository: extensions.repository.unwrap_or_default(),
        workflow: extensions.workflow.unwrap_or_default(),
        git_ref: extensions.git_ref.unwrap_or_default(),
    })
}

/// Fulcio certificate extension values beyond what `sigstore-crypto` extracts.
struct FulcioExtensions {
    repository: Option<String>,
    workflow: Option<String>,
    git_ref: Option<String>,
}

/// Extract Fulcio v2 extension values from a DER-encoded certificate.
///
/// Parses the X.509 certificate and reads the OID extensions for
/// source repository, build config (workflow), and source ref.
fn extract_fulcio_extensions(cert_der: &[u8], bundle_path: &Path) -> Result<FulcioExtensions> {
    use der::Decode;
    use x509_cert::Certificate;

    let cert = Certificate::from_der(cert_der).map_err(|e| NonoError::TrustVerification {
        path: bundle_path.display().to_string(),
        reason: format!("failed to decode certificate DER: {e}"),
    })?;

    let extensions = match &cert.tbs_certificate.extensions {
        Some(exts) => exts,
        None => {
            return Ok(FulcioExtensions {
                repository: None,
                workflow: None,
                git_ref: None,
            });
        }
    };

    let mut repository = None;
    let mut workflow = None;
    let mut git_ref = None;

    for ext in extensions.iter() {
        let oid_str = ext.extn_id.to_string();
        match oid_str.as_str() {
            OID_SOURCE_REPOSITORY => {
                repository = decode_utf8_extension(ext.extn_value.as_bytes());
            }
            OID_BUILD_CONFIG_URI => {
                workflow = decode_utf8_extension(ext.extn_value.as_bytes());
            }
            OID_SOURCE_REPOSITORY_REF => {
                git_ref = decode_utf8_extension(ext.extn_value.as_bytes());
            }
            _ => {}
        }
    }

    Ok(FulcioExtensions {
        repository,
        workflow,
        git_ref,
    })
}

/// Decode an X.509 extension value as a UTF-8 string.
///
/// Tries DER-encoded UTF8String first, then raw bytes as UTF-8 fallback.
fn decode_utf8_extension(value_bytes: &[u8]) -> Option<String> {
    // Try DER-encoded UTF8String
    if let Ok(utf8_str) = <der::asn1::Utf8StringRef<'_> as der::Decode>::from_der(value_bytes) {
        return Some(utf8_str.to_string());
    }
    // Fallback: interpret raw bytes as UTF-8
    std::str::from_utf8(value_bytes).ok().map(String::from)
}

// ---------------------------------------------------------------------------
// Helper: resolve bundle path from artifact path
// ---------------------------------------------------------------------------

/// Resolve the bundle file path for a given artifact.
///
/// Follows the convention `<artifact>.bundle` (e.g., `SKILLS.md.bundle`).
#[must_use]
pub fn bundle_path_for(artifact_path: &Path) -> std::path::PathBuf {
    let mut bundle = artifact_path.as_os_str().to_owned();
    bundle.push(".bundle");
    std::path::PathBuf::from(bundle)
}

// ---------------------------------------------------------------------------
// Helper: extract CertificateInfo (re-export for CLI use)
// ---------------------------------------------------------------------------

/// Parse certificate info from a DER-encoded certificate.
///
/// Thin wrapper around `sigstore_crypto::parse_certificate_info` that maps
/// errors to `NonoError`.
///
/// # Errors
///
/// Returns `NonoError::TrustVerification` if the certificate cannot be parsed.
pub fn parse_cert_info(cert_der: &[u8], bundle_path: &Path) -> Result<CertificateInfo> {
    parse_certificate_info(cert_der).map_err(|e| NonoError::TrustVerification {
        path: bundle_path.display().to_string(),
        reason: format!("failed to parse certificate: {e}"),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // bundle_path_for
    // -----------------------------------------------------------------------

    #[test]
    fn bundle_path_for_appends_extension() {
        let path = Path::new("SKILLS.md");
        assert_eq!(bundle_path_for(path), Path::new("SKILLS.md.bundle"));
    }

    #[test]
    fn bundle_path_for_nested_path() {
        let path = Path::new(".claude/commands/deploy.md");
        assert_eq!(
            bundle_path_for(path),
            Path::new(".claude/commands/deploy.md.bundle")
        );
    }

    #[test]
    fn bundle_path_for_absolute_path() {
        let path = Path::new("/home/user/project/CLAUDE.md");
        assert_eq!(
            bundle_path_for(path),
            Path::new("/home/user/project/CLAUDE.md.bundle")
        );
    }

    // -----------------------------------------------------------------------
    // load_bundle_from_str
    // -----------------------------------------------------------------------

    #[test]
    fn load_bundle_invalid_json() {
        let result = load_bundle_from_str("not json", Path::new("test.bundle"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("failed to parse bundle"));
    }

    #[test]
    fn load_bundle_missing_fields() {
        let json = r#"{"mediaType": "test"}"#;
        let result = load_bundle_from_str(json, Path::new("test.bundle"));
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // load_bundle from file
    // -----------------------------------------------------------------------

    #[test]
    fn load_bundle_nonexistent_file() {
        let result = load_bundle(Path::new("/nonexistent/path/test.bundle"));
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // load_trusted_root
    // -----------------------------------------------------------------------

    #[test]
    fn load_trusted_root_invalid_json() {
        let result = load_trusted_root_from_str("not json");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("failed to parse trusted root"));
    }

    #[test]
    fn load_trusted_root_nonexistent_file() {
        let result = load_trusted_root(Path::new("/nonexistent/trusted_root.json"));
        assert!(result.is_err());
    }

    #[test]
    fn load_production_trusted_root_succeeds() {
        let root = load_production_trusted_root();
        assert!(root.is_ok());
    }

    // -----------------------------------------------------------------------
    // extract_signer_identity
    // -----------------------------------------------------------------------

    #[test]
    fn extract_identity_public_key_bundle() {
        let json = make_public_key_bundle_json("nono-keystore:my-key");
        let bundle = Bundle::from_json(&json).unwrap();
        let identity = extract_signer_identity(&bundle, Path::new("test.bundle")).unwrap();
        match identity {
            SignerIdentity::Keyed { key_id } => {
                assert_eq!(key_id, "nono-keystore:my-key");
            }
            SignerIdentity::Keyless { .. } => panic!("expected keyed identity"),
        }
    }

    #[test]
    fn extract_identity_empty_cert_chain() {
        let json = make_empty_cert_chain_bundle_json();
        let bundle = Bundle::from_json(&json).unwrap();
        let result = extract_signer_identity(&bundle, Path::new("test.bundle"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("empty certificate chain"));
    }

    // -----------------------------------------------------------------------
    // verify_bundle_with_digest
    // -----------------------------------------------------------------------

    #[test]
    fn verify_bundle_with_invalid_digest() {
        let json = make_public_key_bundle_json("key");
        let bundle = Bundle::from_json(&json).unwrap();
        let root = load_production_trusted_root().unwrap();
        let policy = VerificationPolicy::default();
        let result =
            verify_bundle_with_digest("not-hex!", &bundle, &root, &policy, Path::new("test"));
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // decode_utf8_extension
    // -----------------------------------------------------------------------

    #[test]
    fn decode_utf8_extension_raw_bytes() {
        let value = b"https://github.com/org/repo";
        let result = decode_utf8_extension(value);
        assert_eq!(result, Some("https://github.com/org/repo".to_string()));
    }

    #[test]
    fn decode_utf8_extension_invalid_utf8() {
        let value = &[0xFF, 0xFE, 0x00];
        let result = decode_utf8_extension(value);
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // Helpers for constructing test bundles
    // -----------------------------------------------------------------------

    fn make_public_key_bundle_json(key_hint: &str) -> String {
        format!(
            r#"{{
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {{
                    "publicKey": {{
                        "hint": "{key_hint}"
                    }},
                    "tlogEntries": []
                }},
                "dsseEnvelope": {{
                    "payloadType": "application/vnd.in-toto+json",
                    "payload": "e30=",
                    "signatures": [
                        {{
                            "keyid": "",
                            "sig": "AAAA"
                        }}
                    ]
                }}
            }}"#
        )
    }

    fn make_empty_cert_chain_bundle_json() -> String {
        r#"{
            "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
            "verificationMaterial": {
                "x509CertificateChain": {
                    "certificates": []
                },
                "tlogEntries": []
            },
            "dsseEnvelope": {
                "payloadType": "application/vnd.in-toto+json",
                "payload": "e30=",
                "signatures": [
                    {
                        "keyid": "",
                        "sig": "AAAA"
                    }
                ]
            }
        }"#
        .to_string()
    }
}
