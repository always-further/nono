//! Pre-exec instruction file scanning
//!
//! Before fork/exec, scans the working directory for files matching trust
//! policy instruction patterns. Each match is verified against the trust
//! policy (blocklist, bundle signature, publisher match, digest integrity).
//!
//! Verification must complete before the agent reads any instruction file.
//! This is the baseline interception point — it catches files present at
//! session start, which is the most common case since agent frameworks
//! read instruction files at initialization.

use colored::Colorize;
use nono::trust::{self, Enforcement, TrustPolicy, VerificationOutcome, VerificationResult};
use nono::Result;
use std::path::{Path, PathBuf};

/// Load the trust policy for scanning, auto-discovering from the given root and user config.
///
/// Checks `root` for `trust-policy.json`, then user config dir, merging if both
/// exist. Falls back to default policy (deny enforcement) if none found.
///
/// When `trust_override` is false, each discovered policy file must have a valid
/// `.bundle` sidecar with a verified signature. Unsigned or tampered policies
/// are rejected.
///
/// # Errors
///
/// Returns `NonoError::TrustPolicy` if a found policy file is malformed, or
/// `NonoError::TrustVerification` if signature verification fails.
pub fn load_scan_policy(root: &Path, trust_override: bool) -> Result<TrustPolicy> {
    let cwd_policy = root.join("trust-policy.json");

    let project = if cwd_policy.exists() {
        if !trust_override {
            verify_policy_signature(&cwd_policy)?;
        }
        Some(trust::load_policy_from_file(&cwd_policy)?)
    } else {
        None
    };

    let user_path = dirs::config_dir().map(|d| d.join("nono").join("trust-policy.json"));

    let user = if let Some(ref path) = user_path {
        if path.exists() {
            if !trust_override {
                verify_policy_signature(path)?;
            }
            Some(trust::load_policy_from_file(path)?)
        } else {
            None
        }
    } else {
        None
    };

    match (user, project) {
        (Some(u), Some(p)) => trust::merge_policies(&[u, p]),
        (Some(u), None) => Ok(u),
        (None, Some(p)) => {
            eprintln!(
                "  {}",
                "Warning: project-level trust-policy.json found but no user-level policy exists."
                    .yellow()
            );
            eprintln!(
                "  {}",
                "Project policies are not authoritative without a user-level policy to anchor trust."
                    .yellow()
            );
            eprintln!(
                "  {}",
                "Create a signed policy at ~/.config/nono/trust-policy.json to enforce verification."
                    .yellow()
            );
            Ok(p)
        }
        (None, None) => Ok(TrustPolicy::default()),
    }
}

/// Verify that a trust policy file has a valid cryptographic signature.
///
/// Checks for a `.bundle` sidecar, loads and verifies it. For keyed bundles,
/// the public key is looked up from the system keystore via the `key_id` in
/// the bundle's predicate. For keyless bundles, the Sigstore trusted root is
/// used.
///
/// # Trust model
///
/// Policy signature proves provenance and tamper-resistance, not signer
/// allowlisting. This function verifies that the policy content has a valid
/// cryptographic signature (authenticity + integrity + auditability via Rekor)
/// but does NOT check which identity signed it. There is no higher-level
/// document that defines who may author trust policy — the policy itself is
/// that document. Operator/user acceptance of the initial policy is the trust
/// bootstrap step, analogous to SSH's known_hosts or TLS's root CA store.
///
/// # Errors
///
/// Returns `NonoError::TrustVerification` if the policy is unsigned, tampered,
/// or the signature fails verification.
pub fn verify_policy_signature(policy_path: &Path) -> Result<()> {
    let bundle_path = trust::bundle_path_for(policy_path);

    if !bundle_path.exists() {
        return Err(nono::NonoError::TrustVerification {
            path: policy_path.display().to_string(),
            reason: "trust policy is unsigned (no .bundle sidecar found)".to_string(),
        });
    }

    // Load bundle
    let bundle =
        trust::load_bundle(&bundle_path).map_err(|e| nono::NonoError::TrustVerification {
            path: policy_path.display().to_string(),
            reason: format!("invalid policy bundle: {e}"),
        })?;

    // Validate predicate type matches trust policy attestation
    let predicate_type = trust::extract_predicate_type(&bundle, &bundle_path).map_err(|e| {
        nono::NonoError::TrustVerification {
            path: policy_path.display().to_string(),
            reason: format!("failed to extract predicate type: {e}"),
        }
    })?;
    if predicate_type != trust::NONO_POLICY_PREDICATE_TYPE {
        return Err(nono::NonoError::TrustVerification {
            path: policy_path.display().to_string(),
            reason: format!(
                "wrong bundle type: expected trust policy attestation, got {predicate_type}"
            ),
        });
    }

    // Compute file digest
    let file_digest = trust::file_digest(policy_path)?;

    // Verify digest matches bundle
    let bundle_digest = trust::extract_bundle_digest(&bundle, &bundle_path)?;

    if bundle_digest != file_digest {
        return Err(nono::NonoError::TrustVerification {
            path: policy_path.display().to_string(),
            reason: "trust policy has been modified since signing (digest mismatch)".to_string(),
        });
    }

    // Extract signer identity
    let identity = trust::extract_signer_identity(&bundle, &bundle_path).map_err(|e| {
        nono::NonoError::TrustVerification {
            path: policy_path.display().to_string(),
            reason: format!("no signer identity in policy bundle: {e}"),
        }
    })?;

    // Cryptographic verification
    match &identity {
        trust::SignerIdentity::Keyed { key_id } => {
            // Load only the public key from keystore (no private key in memory)
            let pub_key_bytes = crate::trust_cmd::load_public_key_bytes(key_id).map_err(|e| {
                nono::NonoError::TrustVerification {
                    path: policy_path.display().to_string(),
                    reason: format!(
                        "cannot load public key '{key_id}' for policy verification: {e}"
                    ),
                }
            })?;

            trust::verify_keyed_signature(&bundle, &pub_key_bytes, &bundle_path).map_err(|e| {
                nono::NonoError::TrustVerification {
                    path: policy_path.display().to_string(),
                    reason: format!("policy signature verification failed: {e}"),
                }
            })?;
        }
        trust::SignerIdentity::Keyless { .. } => {
            // Policy signature proves provenance and tamper-resistance, not signer
            // allowlisting. VerificationPolicy::default() verifies the Sigstore
            // cryptographic chain (Fulcio CA chain + Rekor inclusion proof + digest
            // match) without pinning to a specific OIDC identity. This is correct:
            // the trust policy is the root document that defines which identities
            // are trusted, so there is no higher-level document to check against.
            // Operator/user acceptance of the initial policy is the bootstrap step.
            let trusted_root = trust::load_production_trusted_root().map_err(|e| {
                nono::NonoError::TrustVerification {
                    path: policy_path.display().to_string(),
                    reason: format!("failed to load Sigstore trusted root: {e}"),
                }
            })?;

            let sigstore_policy = trust::VerificationPolicy::default();

            trust::verify_bundle_with_digest(
                &file_digest,
                &bundle,
                &trusted_root,
                &sigstore_policy,
                policy_path,
            )
            .map_err(|e| nono::NonoError::TrustVerification {
                path: policy_path.display().to_string(),
                reason: format!("policy Sigstore verification failed: {e}"),
            })?;
        }
    }

    Ok(())
}

/// Result of a pre-exec trust scan.
pub struct ScanResult {
    /// Individual file verification results
    pub results: Vec<VerificationResult>,
    /// Number of files that passed verification
    pub verified: u32,
    /// Number of files that were blocked or failed
    pub blocked: u32,
    /// Number of files that were warned (non-blocking failures)
    pub warned: u32,
}

impl ScanResult {
    /// Whether the scan allows execution to proceed.
    #[must_use]
    pub fn should_proceed(&self) -> bool {
        self.blocked == 0
    }

    /// Collect the absolute paths of all verified instruction files.
    ///
    /// These paths are used on macOS to inject literal `(allow file-read-data ...)`
    /// rules that override the deny-regex for instruction file patterns.
    #[must_use]
    pub fn verified_paths(&self) -> Vec<PathBuf> {
        self.results
            .iter()
            .filter(|r| r.outcome.is_verified())
            .map(|r| r.path.clone())
            .collect()
    }
}

/// Run a pre-exec trust scan on instruction files in the given directory.
///
/// Discovers all files matching the trust policy's instruction patterns,
/// verifies each one, and returns the aggregate result. The caller decides
/// whether to abort based on `ScanResult::should_proceed()`.
///
/// # Arguments
///
/// * `scan_root` - Directory to scan (typically the working directory)
/// * `policy` - Trust policy to evaluate against
/// * `silent` - Suppress output
///
/// # Errors
///
/// Returns `NonoError::TrustPolicy` if pattern compilation fails, or
/// `NonoError::Io` if directory traversal fails.
pub fn run_pre_exec_scan(
    scan_root: &Path,
    policy: &TrustPolicy,
    silent: bool,
) -> Result<ScanResult> {
    let files = trust::find_instruction_files(policy, scan_root)?;

    if files.is_empty() {
        return Ok(ScanResult {
            results: Vec::new(),
            verified: 0,
            blocked: 0,
            warned: 0,
        });
    }

    if !silent {
        eprintln!(
            "  Scanning {} instruction file(s) for trust verification...",
            files.len()
        );
    }

    let mut results = Vec::with_capacity(files.len());
    let mut verified = 0u32;
    let mut blocked = 0u32;
    let mut warned = 0u32;

    for file_path in &files {
        let result = verify_instruction_file(file_path, policy);

        if !silent {
            print_verification_line(file_path, scan_root, &result, policy.enforcement);
        }

        if result.outcome.is_verified() {
            verified = verified.saturating_add(1);
        } else if result.outcome.should_block(policy.enforcement) {
            blocked = blocked.saturating_add(1);
        } else {
            warned = warned.saturating_add(1);
        }

        results.push(result);
    }

    if !silent && !results.is_empty() {
        print_scan_summary(verified, blocked, warned, policy.enforcement);
    }

    Ok(ScanResult {
        results,
        verified,
        blocked,
        warned,
    })
}

/// Verify a single instruction file against the trust policy.
fn verify_instruction_file(file_path: &Path, policy: &TrustPolicy) -> VerificationResult {
    // Compute digest
    let digest = match trust::file_digest(file_path) {
        Ok(d) => d,
        Err(e) => {
            return VerificationResult {
                path: file_path.to_path_buf(),
                digest: String::new(),
                outcome: VerificationOutcome::InvalidSignature {
                    detail: format!("failed to compute digest: {e}"),
                },
            };
        }
    };

    // Try to load bundle and extract signer identity
    let bundle_path = trust::bundle_path_for(file_path);
    let signer = if bundle_path.exists() {
        match load_and_extract_signer(file_path, &bundle_path, &digest, policy) {
            Ok(identity) => Some(identity),
            Err(outcome) => {
                return VerificationResult {
                    path: file_path.to_path_buf(),
                    digest,
                    outcome,
                };
            }
        }
    } else {
        None
    };

    // Delegate to library-level evaluation
    trust::evaluate_file(policy, file_path, &digest, signer.as_ref())
}

/// Load a bundle, extract signer identity, verify digest integrity, and
/// perform cryptographic signature verification.
///
/// Both keyed and keyless bundles undergo cryptographic verification.
/// Returns the signer identity on success, or a `VerificationOutcome`
/// describing the failure.
fn load_and_extract_signer(
    file_path: &Path,
    bundle_path: &Path,
    file_digest: &str,
    policy: &TrustPolicy,
) -> std::result::Result<trust::SignerIdentity, VerificationOutcome> {
    // Load bundle
    let bundle =
        trust::load_bundle(bundle_path).map_err(|e| VerificationOutcome::InvalidSignature {
            detail: format!("invalid bundle: {e}"),
        })?;

    // Validate predicate type matches instruction file attestation
    let predicate_type = trust::extract_predicate_type(&bundle, bundle_path).map_err(|e| {
        VerificationOutcome::InvalidSignature {
            detail: format!("failed to extract predicate type: {e}"),
        }
    })?;
    if predicate_type != trust::NONO_PREDICATE_TYPE {
        return Err(VerificationOutcome::InvalidSignature {
            detail: format!(
                "wrong bundle type: expected instruction file attestation, got {predicate_type}"
            ),
        });
    }

    // Verify subject name matches the file being verified
    trust::verify_bundle_subject_name(&bundle, file_path).map_err(|e| {
        VerificationOutcome::InvalidSignature {
            detail: format!("subject name mismatch: {e}"),
        }
    })?;

    // Extract signer identity
    let identity = trust::extract_signer_identity(&bundle, bundle_path).map_err(|e| {
        VerificationOutcome::InvalidSignature {
            detail: format!("no signer identity: {e}"),
        }
    })?;

    // Verify bundle digest matches file content (fail-closed: extraction failure = reject)
    let bundle_digest = trust::extract_bundle_digest(&bundle, bundle_path).map_err(|e| {
        VerificationOutcome::InvalidSignature {
            detail: format!("{e}"),
        }
    })?;
    if bundle_digest != file_digest {
        return Err(VerificationOutcome::DigestMismatch {
            expected: bundle_digest,
            actual: file_digest.to_string(),
        });
    }

    // Cryptographic signature verification (both keyed and keyless)
    match &identity {
        trust::SignerIdentity::Keyed { .. } => {
            verify_keyed_crypto(&bundle, &identity, policy, bundle_path)?;
        }
        trust::SignerIdentity::Keyless { .. } => {
            verify_keyless_crypto(file_path, file_digest, &bundle, bundle_path)?;
        }
    }

    Ok(identity)
}

/// Verify the ECDSA signature on a keyed bundle using the publisher's public key.
///
/// Fail-closed: if no `public_key` is configured for a matching publisher,
/// verification fails rather than silently accepting.
fn verify_keyed_crypto(
    bundle: &trust::Bundle,
    identity: &trust::SignerIdentity,
    policy: &TrustPolicy,
    bundle_path: &Path,
) -> std::result::Result<(), VerificationOutcome> {
    let matching = policy.matching_publishers(identity);
    let pub_key_b64 = matching.iter().find_map(|p| p.public_key.as_ref());

    // Try inline public_key from publisher first, fall back to system keystore
    let key_bytes = if let Some(b64) = pub_key_b64 {
        base64_decode(b64).map_err(|_| VerificationOutcome::InvalidSignature {
            detail: "invalid base64 in publisher public_key".to_string(),
        })?
    } else if let trust::SignerIdentity::Keyed { key_id } = identity {
        crate::trust_cmd::load_public_key_bytes(key_id).map_err(|e| {
            VerificationOutcome::InvalidSignature {
                detail: format!(
                    "no public_key in publisher and keystore lookup failed for '{key_id}': {e}"
                ),
            }
        })?
    } else {
        return Err(VerificationOutcome::InvalidSignature {
            detail: "keyed bundle but no public_key in matching publisher".to_string(),
        });
    };

    trust::verify_keyed_signature(bundle, &key_bytes, bundle_path).map_err(|e| {
        VerificationOutcome::InvalidSignature {
            detail: format!("{e}"),
        }
    })?;
    Ok(())
}

/// Verify a keyless (Fulcio/Rekor) bundle using the Sigstore trusted root.
fn verify_keyless_crypto(
    file_path: &Path,
    file_digest: &str,
    bundle: &trust::Bundle,
    bundle_path: &Path,
) -> std::result::Result<(), VerificationOutcome> {
    let trusted_root = trust::load_production_trusted_root().map_err(|e| {
        VerificationOutcome::InvalidSignature {
            detail: format!("failed to load Sigstore trusted root: {e}"),
        }
    })?;

    let policy = trust::VerificationPolicy::default();

    trust::verify_bundle_with_digest(file_digest, bundle, &trusted_root, &policy, file_path)
        .map_err(|e| VerificationOutcome::InvalidSignature {
            detail: format!("Sigstore verification failed: {e}"),
        })?;

    let _ = bundle_path; // used for context in caller
    Ok(())
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

fn print_verification_line(
    file_path: &Path,
    scan_root: &Path,
    result: &VerificationResult,
    enforcement: Enforcement,
) {
    let rel = file_path.strip_prefix(scan_root).unwrap_or(file_path);

    match &result.outcome {
        VerificationOutcome::Verified { publisher } => {
            eprintln!(
                "    {} {} (publisher: {})",
                "PASS".green(),
                rel.display(),
                publisher
            );
        }
        VerificationOutcome::Blocked { reason } => {
            eprintln!(
                "    {} {} (blocklisted: {})",
                "BLOCK".red(),
                rel.display(),
                reason
            );
        }
        outcome => {
            let label = if outcome.should_block(enforcement) {
                "FAIL".red()
            } else {
                "WARN".yellow()
            };
            let detail = match outcome {
                VerificationOutcome::Unsigned => "no .bundle file".to_string(),
                VerificationOutcome::InvalidSignature { detail } => detail.clone(),
                VerificationOutcome::UntrustedPublisher { identity } => {
                    format!("untrusted signer: {}", format_identity(identity))
                }
                VerificationOutcome::DigestMismatch { .. } => {
                    "file content does not match bundle".to_string()
                }
                _ => "unknown".to_string(),
            };
            eprintln!("    {} {} ({})", label, rel.display(), detail);
        }
    }
}

fn print_scan_summary(verified: u32, blocked: u32, warned: u32, enforcement: Enforcement) {
    eprintln!();
    if blocked > 0 {
        eprintln!(
            "  {}",
            format!("Trust scan: {verified} verified, {blocked} blocked, {warned} warned").red()
        );
        if enforcement.is_blocking() {
            eprintln!(
                "  {}",
                "Aborting: instruction files failed trust verification (enforcement=deny).".red()
            );
        }
    } else if warned > 0 {
        eprintln!(
            "  {}",
            format!("Trust scan: {verified} verified, {warned} warned (enforcement allows)")
                .yellow()
        );
    } else if verified > 0 {
        eprintln!(
            "  {}",
            format!("Trust scan: {verified} file(s) verified.").green()
        );
    }
}

/// Decode standard base64 (with or without padding).
fn base64_decode(input: &str) -> std::result::Result<Vec<u8>, ()> {
    nono::trust::base64::base64_decode(input).map_err(|_| ())
}

fn format_identity(identity: &trust::SignerIdentity) -> String {
    match identity {
        trust::SignerIdentity::Keyed { key_id } => format!("{key_id} (keyed)"),
        trust::SignerIdentity::Keyless {
            repository,
            workflow,
            ..
        } => format!("{repository} ({workflow})"),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn scan_empty_dir_returns_empty_result() {
        let dir = tempfile::tempdir().unwrap();
        let policy = TrustPolicy::default();
        let result = run_pre_exec_scan(dir.path(), &policy, true).unwrap();
        assert!(result.should_proceed());
        assert_eq!(result.verified, 0);
        assert_eq!(result.blocked, 0);
        assert_eq!(result.warned, 0);
        assert!(result.results.is_empty());
    }

    #[test]
    fn scan_unsigned_file_warn_enforcement_proceeds() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("SKILLS.md"), "# Skills").unwrap();

        let policy = TrustPolicy {
            enforcement: Enforcement::Warn,
            ..TrustPolicy::default()
        };

        let result = run_pre_exec_scan(dir.path(), &policy, true).unwrap();
        assert!(result.should_proceed());
        assert_eq!(result.verified, 0);
        assert_eq!(result.warned, 1);
    }

    #[test]
    fn scan_unsigned_file_deny_enforcement_blocks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("CLAUDE.md"), "# Claude").unwrap();

        let policy = TrustPolicy {
            enforcement: Enforcement::Deny,
            ..TrustPolicy::default()
        };

        let result = run_pre_exec_scan(dir.path(), &policy, true).unwrap();
        assert!(!result.should_proceed());
        assert_eq!(result.blocked, 1);
    }

    #[test]
    fn scan_blocklisted_file_always_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"malicious content";
        std::fs::write(dir.path().join("SKILLS.md"), content).unwrap();

        let digest = trust::bytes_digest(content);

        let policy = TrustPolicy {
            enforcement: Enforcement::Audit, // Even audit blocks blocklisted files
            blocklist: trust::Blocklist {
                digests: vec![trust::BlocklistEntry {
                    sha256: digest,
                    description: "known malicious".to_string(),
                    added: "2026-01-01".to_string(),
                }],
                publishers: Vec::new(),
            },
            ..TrustPolicy::default()
        };

        let result = run_pre_exec_scan(dir.path(), &policy, true).unwrap();
        assert!(!result.should_proceed());
        assert_eq!(result.blocked, 1);
    }

    #[test]
    fn scan_audit_enforcement_always_proceeds() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("SKILLS.md"), "# Skills").unwrap();
        std::fs::write(dir.path().join("CLAUDE.md"), "# Claude").unwrap();

        let policy = TrustPolicy {
            enforcement: Enforcement::Audit,
            ..TrustPolicy::default()
        };

        let result = run_pre_exec_scan(dir.path(), &policy, true).unwrap();
        assert!(result.should_proceed());
        assert_eq!(result.warned, 2);
    }

    #[test]
    fn verified_paths_returns_only_verified() {
        let results = vec![
            VerificationResult {
                path: PathBuf::from("/tmp/SKILLS.md"),
                digest: "abc".to_string(),
                outcome: VerificationOutcome::Verified {
                    publisher: "test (keyed)".to_string(),
                },
            },
            VerificationResult {
                path: PathBuf::from("/tmp/CLAUDE.md"),
                digest: "def".to_string(),
                outcome: VerificationOutcome::Unsigned,
            },
            VerificationResult {
                path: PathBuf::from("/tmp/AGENT.MD"),
                digest: "ghi".to_string(),
                outcome: VerificationOutcome::Verified {
                    publisher: "ci (keyless)".to_string(),
                },
            },
        ];

        let scan = ScanResult {
            results,
            verified: 2,
            blocked: 0,
            warned: 1,
        };

        let paths = scan.verified_paths();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0], PathBuf::from("/tmp/SKILLS.md"));
        assert_eq!(paths[1], PathBuf::from("/tmp/AGENT.MD"));
    }

    #[test]
    fn verified_paths_empty_when_none_verified() {
        let scan = ScanResult {
            results: vec![VerificationResult {
                path: PathBuf::from("/tmp/SKILLS.md"),
                digest: "abc".to_string(),
                outcome: VerificationOutcome::Unsigned,
            }],
            verified: 0,
            blocked: 0,
            warned: 1,
        };
        assert!(scan.verified_paths().is_empty());
    }

    #[test]
    fn load_scan_policy_with_trust_override_skips_verification() {
        let dir = tempfile::tempdir().unwrap();
        // Create a policy file with no .bundle — should still load with trust_override=true
        std::fs::write(
            dir.path().join("trust-policy.json"),
            r#"{"version":1,"instruction_patterns":["SKILLS*","CLAUDE*"],"publishers":[],"blocklist":{"digests":[],"publishers":[]},"enforcement":"warn"}"#,
        )
        .unwrap();

        let policy = load_scan_policy(dir.path(), true).unwrap();
        assert_eq!(policy.enforcement, Enforcement::Warn);
    }

    #[test]
    fn verify_policy_signature_missing_bundle_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("trust-policy.json");
        std::fs::write(&policy_path, "{}").unwrap();

        let result = verify_policy_signature(&policy_path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unsigned"));
    }

    #[test]
    fn scan_nonmatching_files_ignored() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("README.md"), "# Readme").unwrap();
        std::fs::write(dir.path().join("src.rs"), "fn main() {}").unwrap();

        let policy = TrustPolicy::default();
        let result = run_pre_exec_scan(dir.path(), &policy, true).unwrap();
        assert!(result.should_proceed());
        assert!(result.results.is_empty());
    }
}
