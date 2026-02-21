//! CLI commands for instruction file trust and attestation
//!
//! Implements `nono trust sign|verify|list|keygen` subcommands.

use crate::cli::{
    TrustArgs, TrustCommands, TrustKeygenArgs, TrustListArgs, TrustSignArgs, TrustSignPolicyArgs,
    TrustVerifyArgs,
};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use colored::Colorize;
use nono::trust;
use nono::Result;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Keystore service name for signing keys (private key material)
const TRUST_SERVICE: &str = "nono-trust";

/// Keystore service name for public keys (verification-only, no private key material)
const TRUST_PUB_SERVICE: &str = "nono-trust-pub";

/// Run a trust subcommand.
pub fn run_trust(args: TrustArgs) -> Result<()> {
    match args.command {
        TrustCommands::Sign(sign_args) => run_sign(sign_args),
        TrustCommands::SignPolicy(sign_policy_args) => run_sign_policy(sign_policy_args),
        TrustCommands::Verify(verify_args) => run_verify(verify_args),
        TrustCommands::List(list_args) => run_list(list_args),
        TrustCommands::Keygen(keygen_args) => run_keygen(keygen_args),
    }
}

// ---------------------------------------------------------------------------
// keygen
// ---------------------------------------------------------------------------

fn run_keygen(args: TrustKeygenArgs) -> Result<()> {
    let key_id = &args.id;

    // Check if key already exists
    if !args.force {
        let entry = keyring::Entry::new(TRUST_SERVICE, key_id).map_err(|e| {
            nono::NonoError::KeystoreAccess(format!("failed to access keystore: {e}"))
        })?;
        if entry.get_password().is_ok() {
            return Err(nono::NonoError::KeystoreAccess(format!(
                "key '{key_id}' already exists in keystore (use --force to overwrite)"
            )));
        }
    }

    // Generate ECDSA P-256 key pair and get PKCS#8 bytes
    let rng = SystemRandom::new();
    let pkcs8_doc =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).map_err(|_| {
            nono::NonoError::TrustSigning {
                path: String::new(),
                reason: "ECDSA P-256 key generation failed".to_string(),
            }
        })?;

    // Reconstruct KeyPair to get the public key and key ID
    let key_pair = reconstruct_key_pair(pkcs8_doc.as_ref())?;
    let hex_id = trust::key_id_hex(&key_pair)?;
    let pub_key = trust::export_public_key(&key_pair)?;

    // Store PKCS#8 as base64 in system keystore (zeroized after store)
    let pkcs8_b64 = Zeroizing::new(base64_encode(pkcs8_doc.as_ref()));
    let entry = keyring::Entry::new(TRUST_SERVICE, key_id)
        .map_err(|e| nono::NonoError::KeystoreAccess(format!("failed to access keystore: {e}")))?;
    entry
        .set_password(pkcs8_b64.as_str())
        .map_err(|e| nono::NonoError::KeystoreAccess(format!("failed to store key: {e}")))?;

    // Store public key separately so verification never needs the private key
    let pub_key_b64 = base64_encode(pub_key.as_bytes());
    let pub_entry = keyring::Entry::new(TRUST_PUB_SERVICE, key_id)
        .map_err(|e| nono::NonoError::KeystoreAccess(format!("failed to access keystore: {e}")))?;
    pub_entry
        .set_password(&pub_key_b64)
        .map_err(|e| nono::NonoError::KeystoreAccess(format!("failed to store public key: {e}")))?;

    eprintln!("{}", "Signing key generated successfully.".green());
    eprintln!("  Key ID:      {key_id}");
    eprintln!("  Fingerprint: {hex_id}");
    eprintln!("  Algorithm:   ECDSA P-256 (SHA-256)");
    eprintln!("  Stored in:   system keystore (service: {TRUST_SERVICE})");
    eprintln!();
    eprintln!("Public key (base64 DER, for trust-policy.json):");
    eprintln!("  {pub_key_b64}");
    eprintln!();
    eprintln!("Public key (PEM):");
    eprintln!("{}", pub_key.to_pem());

    Ok(())
}

// ---------------------------------------------------------------------------
// sign
// ---------------------------------------------------------------------------

fn run_sign(args: TrustSignArgs) -> Result<()> {
    if args.keyless {
        return run_sign_keyless(args);
    }

    let key_id = args.key.as_deref().unwrap_or("default");

    // Load the signing key from keystore
    let key_pair = load_signing_key(key_id)?;

    // Resolve files to sign
    let files = resolve_files(&args.files, args.all, args.policy.as_deref())?;

    if files.is_empty() {
        eprintln!("No instruction files found to sign.");
        return Ok(());
    }

    let mut success_count = 0u32;
    let mut fail_count = 0u32;

    for file_path in &files {
        match trust::sign_instruction_file(file_path, &key_pair, key_id) {
            Ok(bundle_json) => {
                trust::write_bundle(file_path, &bundle_json)?;
                let bundle_path = trust::bundle_path_for(file_path);
                eprintln!(
                    "  {} {} -> {}",
                    "SIGNED".green(),
                    file_path.display(),
                    bundle_path.display()
                );
                success_count = success_count.saturating_add(1);
            }
            Err(e) => {
                eprintln!("  {} {}: {e}", "FAILED".red(), file_path.display());
                fail_count = fail_count.saturating_add(1);
            }
        }
    }

    eprintln!();
    if fail_count == 0 {
        eprintln!(
            "{}",
            format!("Signed {success_count} file(s) successfully.").green()
        );
    } else {
        eprintln!(
            "{}",
            format!("Signed {success_count}, failed {fail_count}.").yellow()
        );
    }

    if fail_count > 0 {
        return Err(nono::NonoError::TrustSigning {
            path: String::new(),
            reason: format!("{fail_count} file(s) failed to sign"),
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// keyless sign (Sigstore Fulcio + Rekor)
// ---------------------------------------------------------------------------

fn run_sign_keyless(args: TrustSignArgs) -> Result<()> {
    let files = resolve_files(&args.files, args.all, args.policy.as_deref())?;

    if files.is_empty() {
        eprintln!("No instruction files found to sign.");
        return Ok(());
    }

    // Build a tokio runtime for the async Fulcio/Rekor calls
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| nono::NonoError::TrustSigning {
            path: String::new(),
            reason: format!("failed to create async runtime: {e}"),
        })?;

    // Discover OIDC token from ambient environment (GitHub Actions, etc.)
    let token = discover_oidc_token(&rt)?;

    let context = sigstore_sign::SigningContext::production();
    let signer = context.signer(token);

    let mut success_count = 0u32;
    let mut fail_count = 0u32;

    for file_path in &files {
        match rt.block_on(sign_file_keyless(file_path, &signer)) {
            Ok(()) => {
                let bundle_path = trust::bundle_path_for(file_path);
                eprintln!(
                    "  {} {} -> {}",
                    "SIGNED".green(),
                    file_path.display(),
                    bundle_path.display()
                );
                success_count = success_count.saturating_add(1);
            }
            Err(e) => {
                eprintln!("  {} {}: {e}", "FAILED".red(), file_path.display());
                fail_count = fail_count.saturating_add(1);
            }
        }
    }

    eprintln!();
    if fail_count == 0 {
        eprintln!(
            "{}",
            format!("Signed {success_count} file(s) successfully (keyless).").green()
        );
    } else {
        eprintln!(
            "{}",
            format!("Signed {success_count}, failed {fail_count}.").yellow()
        );
    }

    if fail_count > 0 {
        return Err(nono::NonoError::TrustSigning {
            path: String::new(),
            reason: format!("{fail_count} file(s) failed to sign"),
        });
    }

    Ok(())
}

/// Sign a single file using Sigstore keyless signing.
///
/// Constructs an in-toto attestation with the nono instruction file predicate
/// type, signs it via Fulcio + Rekor, and writes the bundle v0.3 sidecar.
async fn sign_file_keyless(
    file_path: &Path,
    signer: &sigstore_sign::Signer,
) -> std::result::Result<(), String> {
    let content = std::fs::read(file_path).map_err(|e| format!("failed to read file: {e}"))?;

    let filename = file_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .ok_or_else(|| "path has no filename component".to_string())?;

    let digest_hex = trust::bytes_digest(&content);

    let digest_hash = sigstore_sign::types::Sha256Hash::from_hex(&digest_hex)
        .map_err(|e| format!("failed to parse digest: {e}"))?;

    // Build the signer predicate with OIDC metadata from environment
    let signer_predicate = build_keyless_predicate();

    // Build the attestation using sigstore-sign's Attestation type
    let attestation = sigstore_sign::Attestation::new(trust::NONO_PREDICATE_TYPE, signer_predicate)
        .add_subject(filename, digest_hash);

    let bundle = signer
        .sign_attestation(attestation)
        .await
        .map_err(|e| format!("keyless signing failed: {e}"))?;

    let bundle_json = bundle
        .to_json_pretty()
        .map_err(|e| format!("failed to serialize bundle: {e}"))?;

    trust::write_bundle(file_path, &bundle_json)
        .map_err(|e| format!("failed to write bundle: {e}"))?;

    Ok(())
}

/// Build the keyless signer predicate from ambient OIDC environment variables.
fn build_keyless_predicate() -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "signer": {
            "kind": "keyless",
            "oidc_issuer": std::env::var("ACTIONS_ID_TOKEN_ISSUER")
                .unwrap_or_else(|_| "https://token.actions.githubusercontent.com".to_string()),
            "repository": std::env::var("GITHUB_REPOSITORY").unwrap_or_default(),
            "workflow": std::env::var("GITHUB_WORKFLOW_REF").unwrap_or_default(),
            "ref": std::env::var("GITHUB_REF").unwrap_or_default()
        }
    })
}

/// Discover an OIDC identity token from the ambient environment.
///
/// Uses the `ambient-id` crate (via `sigstore-oidc`) to automatically detect
/// OIDC credentials from GitHub Actions, GitLab CI, Buildkite, and other CI
/// providers. Requests a token with the `sigstore` audience for Fulcio
/// certificate issuance.
fn discover_oidc_token(rt: &tokio::runtime::Runtime) -> Result<sigstore_sign::oidc::IdentityToken> {
    rt.block_on(async {
        sigstore_sign::oidc::IdentityToken::detect_ambient()
            .await
            .map_err(|e| nono::NonoError::TrustSigning {
                path: String::new(),
                reason: format!("failed to detect ambient OIDC credentials: {e}"),
            })?
            .ok_or_else(|| nono::NonoError::TrustSigning {
                path: String::new(),
                reason: "no ambient OIDC credentials found. \
                         Keyless signing requires a CI environment with OIDC support \
                         (e.g., GitHub Actions with `permissions: id-token: write`)."
                    .to_string(),
            })
    })
}

// ---------------------------------------------------------------------------
// sign-policy
// ---------------------------------------------------------------------------

fn run_sign_policy(args: TrustSignPolicyArgs) -> Result<()> {
    let key_id = args.key.as_deref().unwrap_or("default");

    // Load the signing key from keystore
    let key_pair = load_signing_key(key_id)?;

    // Resolve the policy file path
    let policy_path = match args.file {
        Some(path) => path,
        None => {
            let cwd = std::env::current_dir().map_err(nono::NonoError::Io)?;
            let default_path = cwd.join("trust-policy.json");
            if !default_path.exists() {
                return Err(nono::NonoError::TrustSigning {
                    path: default_path.display().to_string(),
                    reason: "trust-policy.json not found in current directory".to_string(),
                });
            }
            default_path
        }
    };

    let bundle_json = trust::sign_policy_file(&policy_path, &key_pair, key_id)?;
    trust::write_bundle(&policy_path, &bundle_json)?;
    let bundle_path = trust::bundle_path_for(&policy_path);

    eprintln!(
        "  {} {} -> {}",
        "SIGNED".green(),
        policy_path.display(),
        bundle_path.display()
    );
    eprintln!();
    eprintln!("{}", "Trust policy signed successfully.".green());

    Ok(())
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

fn run_verify(args: TrustVerifyArgs) -> Result<()> {
    let policy = load_trust_policy(args.policy.as_deref())?;

    // Resolve files to verify
    let files = resolve_files(&args.files, args.all, None)?;

    if files.is_empty() {
        eprintln!("No instruction files found to verify.");
        return Ok(());
    }

    let mut verified = 0u32;
    let mut failed = 0u32;

    for file_path in &files {
        match verify_single_file(file_path, &policy) {
            Ok(info) => {
                eprintln!("  {} {}", "VERIFIED".green(), file_path.display());
                eprintln!("    Signer: {info}");
                verified = verified.saturating_add(1);
            }
            Err(reason) => {
                eprintln!("  {} {}", "FAILED".red(), file_path.display());
                eprintln!("    Reason: {reason}");
                failed = failed.saturating_add(1);
            }
        }
    }

    eprintln!();
    if failed == 0 {
        eprintln!(
            "{}",
            format!("Verified {verified} file(s) successfully.").green()
        );
    } else {
        eprintln!(
            "{}",
            format!("Verified {verified}, failed {failed}.").yellow()
        );
    }

    if failed > 0 {
        return Err(nono::NonoError::TrustVerification {
            path: String::new(),
            reason: format!("{failed} file(s) failed verification"),
        });
    }

    Ok(())
}

fn verify_single_file(
    file_path: &Path,
    policy: &trust::TrustPolicy,
) -> std::result::Result<String, String> {
    // Check blocklist first
    let digest =
        trust::file_digest(file_path).map_err(|e| format!("failed to compute digest: {e}"))?;

    if let Some(entry) = policy.check_blocklist(&digest) {
        return Err(format!("blocked by trust policy: {}", entry.description));
    }

    // Look for bundle
    let bundle_path = trust::bundle_path_for(file_path);
    if !bundle_path.exists() {
        return Err("no .bundle file found".to_string());
    }

    // Load bundle
    let bundle = trust::load_bundle(&bundle_path).map_err(|e| format!("invalid bundle: {e}"))?;

    // Validate predicate type matches instruction file attestation
    let predicate_type = trust::extract_predicate_type(&bundle, &bundle_path)
        .map_err(|e| format!("failed to extract predicate type: {e}"))?;
    if predicate_type != trust::NONO_PREDICATE_TYPE {
        return Err(format!(
            "wrong bundle type: expected instruction file attestation, got {predicate_type}"
        ));
    }

    // Verify subject name matches the file being verified
    trust::verify_bundle_subject_name(&bundle, file_path)
        .map_err(|e| format!("subject name mismatch: {e}"))?;

    // Extract signer identity from bundle
    let identity = trust::extract_signer_identity(&bundle, &bundle_path)
        .map_err(|e| format!("no signer identity: {e}"))?;

    // Check if signer matches any publisher in the trust policy
    let matching = policy.matching_publishers(&identity);

    if matching.is_empty() {
        return Err(format!(
            "signer '{}' not in trusted publishers",
            format_identity(&identity)
        ));
    }

    // Verify bundle digest matches file digest
    let content = std::fs::read(file_path).map_err(|e| format!("failed to read file: {e}"))?;
    let file_digest_hex = trust::bytes_digest(&content);

    // Verify digest from bundle (fail-closed: extraction failure = reject)
    let statement_digest = trust::extract_bundle_digest(&bundle, file_path)
        .map_err(|e| format!("malformed bundle: {e}"))?;
    if statement_digest != file_digest_hex {
        return Err("bundle digest does not match file content".to_string());
    }

    // Cryptographic signature verification (both keyed and keyless)
    match &identity {
        trust::SignerIdentity::Keyed { key_id } => {
            let pub_key_b64 = matching.iter().find_map(|p| p.public_key.as_ref());
            // Try inline public_key from publisher first, fall back to system keystore
            let key_bytes = if let Some(b64) = pub_key_b64 {
                base64_decode(b64)
                    .map_err(|_| "invalid base64 in publisher public_key".to_string())?
            } else {
                load_public_key_bytes(key_id).map_err(|e| {
                    format!(
                        "no public_key in publisher and keystore lookup failed for '{key_id}': {e}"
                    )
                })?
            };
            trust::verify_keyed_signature(&bundle, &key_bytes, file_path)
                .map_err(|e| format!("signature verification failed: {e}"))?;
        }
        trust::SignerIdentity::Keyless { .. } => {
            let trusted_root = trust::load_production_trusted_root()
                .map_err(|e| format!("failed to load Sigstore trusted root: {e}"))?;
            let sigstore_policy = trust::VerificationPolicy::default();
            trust::verify_bundle_with_digest(
                &file_digest_hex,
                &bundle,
                &trusted_root,
                &sigstore_policy,
                file_path,
            )
            .map_err(|e| format!("Sigstore verification failed: {e}"))?;
        }
    }

    Ok(format_identity(&identity))
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

fn run_list(args: TrustListArgs) -> Result<()> {
    let policy = load_trust_policy(args.policy.as_deref())?;

    let cwd = std::env::current_dir().map_err(nono::NonoError::Io)?;
    let files = trust::find_instruction_files(&policy, &cwd)?;

    if files.is_empty() {
        eprintln!("No instruction files found in current directory.");
        return Ok(());
    }

    if args.json {
        let mut entries = Vec::new();
        for file_path in &files {
            let status = match verify_single_file(file_path, &policy) {
                Ok(signer) => serde_json::json!({
                    "file": file_path.display().to_string(),
                    "status": "verified",
                    "signer": signer,
                }),
                Err(reason) => {
                    let status_str = if trust::bundle_path_for(file_path).exists() {
                        "failed"
                    } else {
                        "unsigned"
                    };
                    serde_json::json!({
                        "file": file_path.display().to_string(),
                        "status": status_str,
                        "reason": reason,
                    })
                }
            };
            entries.push(status);
        }
        let output = serde_json::to_string_pretty(&entries)
            .map_err(|e| nono::NonoError::ConfigParse(format!("JSON serialization failed: {e}")))?;
        println!("{output}");
    } else {
        eprintln!(
            "  {:<40} {:<12} {}",
            "File".bold(),
            "Status".bold(),
            "Publisher".bold()
        );
        eprintln!("  {}", "-".repeat(70));

        for file_path in &files {
            let rel = file_path.strip_prefix(&cwd).unwrap_or(file_path);

            match verify_single_file(file_path, &policy) {
                Ok(signer) => {
                    eprintln!(
                        "  {:<40} {:<12} {}",
                        rel.display(),
                        "VERIFIED".green(),
                        signer
                    );
                }
                Err(reason) => {
                    let has_bundle = trust::bundle_path_for(file_path).exists();
                    let status = if has_bundle {
                        "FAILED".red().to_string()
                    } else {
                        "UNSIGNED".yellow().to_string()
                    };
                    eprintln!("  {:<40} {:<12} {}", rel.display(), status, reason);
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Key loading from system keystore
// ---------------------------------------------------------------------------

/// Load only the public key bytes for a given key ID from the keystore.
///
/// Uses the `nono-trust-pub` service to avoid loading private key material
/// into memory for verification-only operations.
pub(crate) fn load_public_key_bytes(key_id: &str) -> Result<Vec<u8>> {
    let entry = keyring::Entry::new(TRUST_PUB_SERVICE, key_id)
        .map_err(|e| nono::NonoError::KeystoreAccess(format!("failed to access keystore: {e}")))?;

    let b64 = entry.get_password().map_err(|e| match e {
        keyring::Error::NoEntry => nono::NonoError::SecretNotFound(format!(
            "public key '{key_id}' not found in keystore (run 'nono trust keygen' to regenerate)"
        )),
        other => nono::NonoError::KeystoreAccess(format!(
            "failed to load public key '{key_id}': {other}"
        )),
    })?;

    base64_decode(&b64)
        .map_err(|e| nono::NonoError::KeystoreAccess(format!("corrupt public key data: {e}")))
}

pub(crate) fn load_signing_key(key_id: &str) -> Result<trust::KeyPair> {
    let entry = keyring::Entry::new(TRUST_SERVICE, key_id)
        .map_err(|e| nono::NonoError::KeystoreAccess(format!("failed to access keystore: {e}")))?;

    let pkcs8_b64 = Zeroizing::new(entry.get_password().map_err(|e| match e {
        keyring::Error::NoEntry => nono::NonoError::SecretNotFound(format!(
            "signing key '{key_id}' not found in keystore (run 'nono trust keygen' first)"
        )),
        other => nono::NonoError::KeystoreAccess(format!("failed to load key '{key_id}': {other}")),
    })?);

    let pkcs8_bytes = Zeroizing::new(base64_decode(pkcs8_b64.as_str()).map_err(|e| {
        nono::NonoError::KeystoreAccess(format!("corrupt key data in keystore: {e}"))
    })?);

    reconstruct_key_pair(&pkcs8_bytes)
}

pub(crate) fn reconstruct_key_pair(pkcs8_bytes: &[u8]) -> Result<trust::KeyPair> {
    let ecdsa_kp =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_bytes).map_err(|e| {
            nono::NonoError::TrustSigning {
                path: String::new(),
                reason: format!("invalid PKCS#8 key data: {e}"),
            }
        })?;

    // KeyPair::EcdsaP256 has a public unnamed field, construct directly
    Ok(trust::KeyPair::EcdsaP256(ecdsa_kp))
}

// ---------------------------------------------------------------------------
// Trust policy loading
// ---------------------------------------------------------------------------

fn load_trust_policy(explicit_path: Option<&Path>) -> Result<trust::TrustPolicy> {
    if let Some(path) = explicit_path {
        verify_policy_if_exists(path)?;
        return trust::load_policy_from_file(path);
    }

    // Auto-discover: check CWD then user config dir
    let cwd = std::env::current_dir().map_err(nono::NonoError::Io)?;
    let cwd_policy = cwd.join("trust-policy.json");
    if cwd_policy.exists() {
        verify_policy_if_exists(&cwd_policy)?;
        let project_policy = trust::load_policy_from_file(&cwd_policy)?;
        // Try to load user-level policy and merge
        if let Some(user_policy_path) = user_trust_policy_path() {
            if user_policy_path.exists() {
                verify_policy_if_exists(&user_policy_path)?;
                let user_policy = trust::load_policy_from_file(&user_policy_path)?;
                return trust::merge_policies(&[user_policy, project_policy]);
            }
        }
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
        return Ok(project_policy);
    }

    // User-level only
    if let Some(user_path) = user_trust_policy_path() {
        if user_path.exists() {
            verify_policy_if_exists(&user_path)?;
            return trust::load_policy_from_file(&user_path);
        }
    }

    // No policy found — return a default empty policy
    Ok(trust::TrustPolicy::default())
}

/// Verify the trust policy signature if a `.bundle` sidecar exists.
///
/// Uses the same verification as the pre-exec scan (`trust_scan::verify_policy_signature`).
/// If no `.bundle` exists, logs a warning but allows the policy to load — this supports
/// development workflows where policies are unsigned. The pre-exec scan path enforces
/// signature requirements independently via `trust_override`.
fn verify_policy_if_exists(policy_path: &Path) -> Result<()> {
    let bundle_path = nono::trust::bundle_path_for(policy_path);
    if !bundle_path.exists() {
        eprintln!(
            "  {}",
            format!(
                "Warning: trust policy {} has no .bundle sidecar (unsigned).",
                policy_path.display()
            )
            .yellow()
        );
        return Ok(());
    }
    crate::trust_scan::verify_policy_signature(policy_path)
}

fn user_trust_policy_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("nono").join("trust-policy.json"))
}

// ---------------------------------------------------------------------------
// File resolution helpers
// ---------------------------------------------------------------------------

fn resolve_files(
    explicit: &[PathBuf],
    all: bool,
    policy_path: Option<&Path>,
) -> Result<Vec<PathBuf>> {
    if all {
        let policy = load_trust_policy(policy_path)?;
        let cwd = std::env::current_dir().map_err(nono::NonoError::Io)?;
        trust::find_instruction_files(&policy, &cwd)
    } else {
        // Canonicalize explicit paths
        let mut resolved = Vec::with_capacity(explicit.len());
        for path in explicit {
            let canonical =
                std::fs::canonicalize(path).map_err(|e| nono::NonoError::TrustSigning {
                    path: path.display().to_string(),
                    reason: format!("file not found: {e}"),
                })?;
            resolved.push(canonical);
        }
        Ok(resolved)
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

fn format_identity(identity: &trust::SignerIdentity) -> String {
    match identity {
        trust::SignerIdentity::Keyed { key_id } => format!("{key_id} (keyed)"),
        trust::SignerIdentity::Keyless {
            repository,
            workflow,
            ..
        } => {
            format!("{repository} ({workflow})")
        }
    }
}

// Base64 helpers delegated to the library's shared module
fn base64_encode(data: &[u8]) -> String {
    nono::trust::base64::base64_encode(data)
}

pub(crate) fn base64_decode(input: &str) -> std::result::Result<Vec<u8>, String> {
    nono::trust::base64::base64_decode(input)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip() {
        let data = b"hello world PKCS#8 key material";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64_empty() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn base64_known_value() {
        // "hello" -> "aGVsbG8="
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
    }

    #[test]
    fn format_identity_keyed() {
        let id = trust::SignerIdentity::Keyed {
            key_id: "default".to_string(),
        };
        assert_eq!(format_identity(&id), "default (keyed)");
    }

    #[test]
    fn format_identity_keyless() {
        let id = trust::SignerIdentity::Keyless {
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            repository: "org/repo".to_string(),
            workflow: ".github/workflows/sign.yml".to_string(),
            git_ref: "refs/heads/main".to_string(),
        };
        assert_eq!(
            format_identity(&id),
            "org/repo (.github/workflows/sign.yml)"
        );
    }

    #[test]
    fn user_trust_policy_path_is_some() {
        // Just verify it returns Some on a normal system
        let path = user_trust_policy_path();
        assert!(path.is_some());
    }

    #[test]
    fn load_trust_policy_returns_default_when_no_file() {
        // CWD mutation with catch_unwind to guarantee cleanup even on panic.
        let dir = tempfile::tempdir().unwrap();
        let original = std::env::current_dir().unwrap();

        let result = std::panic::catch_unwind(|| {
            std::env::set_current_dir(dir.path()).unwrap();
            let policy = load_trust_policy(None).unwrap();
            assert!(policy.publishers.is_empty());
        });

        std::env::set_current_dir(original).unwrap();
        result.unwrap();
    }
}
