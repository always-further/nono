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
use nono::{NonoError, Result};
use std::path::Path;

/// Load the trust policy for scanning, auto-discovering from CWD and user config.
///
/// Checks CWD for `trust-policy.json`, then user config dir, merging if both
/// exist. Falls back to default policy (warn enforcement) if none found.
///
/// # Errors
///
/// Returns `NonoError::TrustPolicy` if a found policy file is malformed.
pub fn load_scan_policy() -> Result<TrustPolicy> {
    let cwd = std::env::current_dir().map_err(NonoError::Io)?;
    let cwd_policy = cwd.join("trust-policy.json");

    let project = if cwd_policy.exists() {
        Some(trust::load_policy_from_file(&cwd_policy)?)
    } else {
        None
    };

    let user = dirs::config_dir()
        .map(|d| d.join("nono").join("trust-policy.json"))
        .filter(|p| p.exists())
        .map(|p| trust::load_policy_from_file(&p))
        .transpose()?;

    match (user, project) {
        (Some(u), Some(p)) => trust::merge_policies(&[u, p]),
        (Some(u), None) => Ok(u),
        (None, Some(p)) => Ok(p),
        (None, None) => Ok(TrustPolicy::default()),
    }
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
        match load_and_extract_signer(&bundle_path, &digest) {
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

/// Load a bundle, extract signer identity, and verify digest integrity.
///
/// Returns the signer identity on success, or a `VerificationOutcome`
/// describing the failure.
fn load_and_extract_signer(
    bundle_path: &Path,
    file_digest: &str,
) -> std::result::Result<trust::SignerIdentity, VerificationOutcome> {
    // Load bundle
    let bundle =
        trust::load_bundle(bundle_path).map_err(|e| VerificationOutcome::InvalidSignature {
            detail: format!("invalid bundle: {e}"),
        })?;

    // Extract signer identity
    let identity = trust::extract_signer_identity(&bundle, bundle_path).map_err(|e| {
        VerificationOutcome::InvalidSignature {
            detail: format!("no signer identity: {e}"),
        }
    })?;

    // Verify bundle digest matches file content
    if let Ok(bundle_digest) = extract_statement_digest(&bundle) {
        if bundle_digest != file_digest {
            return Err(VerificationOutcome::DigestMismatch {
                expected: bundle_digest,
                actual: file_digest.to_string(),
            });
        }
    }

    Ok(identity)
}

/// Extract the SHA-256 digest from a bundle's DSSE envelope statement.
fn extract_statement_digest(
    bundle: &trust::Bundle,
) -> std::result::Result<String, VerificationOutcome> {
    let bundle_json = bundle
        .to_json()
        .map_err(|e| VerificationOutcome::InvalidSignature {
            detail: format!("failed to serialize bundle: {e}"),
        })?;

    let value: serde_json::Value =
        serde_json::from_str(&bundle_json).map_err(|_| VerificationOutcome::InvalidSignature {
            detail: "invalid bundle JSON".to_string(),
        })?;

    // Decode base64 payload
    let payload_b64 =
        value["dsseEnvelope"]["payload"]
            .as_str()
            .ok_or(VerificationOutcome::InvalidSignature {
                detail: "missing DSSE payload".to_string(),
            })?;

    let payload_bytes =
        base64_decode(payload_b64).map_err(|_| VerificationOutcome::InvalidSignature {
            detail: "invalid base64 in DSSE payload".to_string(),
        })?;

    let statement: serde_json::Value = serde_json::from_slice(&payload_bytes).map_err(|_| {
        VerificationOutcome::InvalidSignature {
            detail: "invalid statement JSON in payload".to_string(),
        }
    })?;

    statement["subject"][0]["digest"]["sha256"]
        .as_str()
        .map(String::from)
        .ok_or(VerificationOutcome::InvalidSignature {
            detail: "no sha256 digest in statement subject".to_string(),
        })
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
    let input = input.trim_end_matches('=');
    let mut buf = Vec::with_capacity(input.len() * 3 / 4);
    let mut accum: u32 = 0;
    let mut bits: u32 = 0;

    for ch in input.chars() {
        let val = match ch {
            'A'..='Z' => ch as u32 - b'A' as u32,
            'a'..='z' => ch as u32 - b'a' as u32 + 26,
            '0'..='9' => ch as u32 - b'0' as u32 + 52,
            '+' | '-' => 62,
            '/' | '_' => 63,
            _ => return Err(()),
        };
        accum = (accum << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            buf.push((accum >> bits) as u8);
            accum &= (1 << bits) - 1;
        }
    }

    Ok(buf)
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
