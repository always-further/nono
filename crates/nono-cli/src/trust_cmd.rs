//! CLI commands for instruction file trust and attestation
//!
//! Implements `nono trust sign|verify|list|keygen` subcommands.

use crate::cli::{
    TrustArgs, TrustCommands, TrustExportKeyArgs, TrustInitArgs, TrustKeygenArgs, TrustListArgs,
    TrustSignArgs, TrustSignPolicyArgs, TrustVerifyArgs,
};
use crate::trust_keystore;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use colored::Colorize;
use nono::trust;
use nono::Result;
use std::path::{Path, PathBuf};
use tracing::debug;
use zeroize::Zeroizing;

/// Keystore service name for signing keys (private key material)
const TRUST_SERVICE: &str = "nono-trust";

/// Keystore service name for public keys (verification-only, no private key material)
const TRUST_PUB_SERVICE: &str = "nono-trust-pub";

/// On-disk cache extension for verification-only public keys.
const TRUST_PUB_CACHE_EXT: &str = "b64";

/// Test-only override for the user trust policy path.
#[cfg(feature = "test-trust-overrides")]
pub(crate) const TEST_USER_POLICY_PATH_ENV: &str = "NONO_TRUST_TEST_USER_POLICY_PATH";

/// Run a trust subcommand.
pub fn run_trust(args: TrustArgs) -> Result<()> {
    match args.command {
        TrustCommands::Init(init_args) => run_init(init_args),
        TrustCommands::Sign(sign_args) => run_sign(sign_args),
        TrustCommands::SignPolicy(sign_policy_args) => run_sign_policy(sign_policy_args),
        TrustCommands::Verify(verify_args) => run_verify(verify_args),
        TrustCommands::List(list_args) => run_list(list_args),
        TrustCommands::Keygen(keygen_args) => run_keygen(keygen_args),
        TrustCommands::ExportKey(export_args) => run_export_key(export_args),
    }
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

fn run_init(args: TrustInitArgs) -> Result<()> {
    let is_user = args.user;
    let policy_path = if is_user {
        let path = user_trust_policy_path().ok_or_else(|| {
            nono::NonoError::TrustPolicy("could not determine user config directory".to_string())
        })?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(nono::NonoError::Io)?;
        }
        path
    } else {
        let cwd = std::env::current_dir().map_err(nono::NonoError::Io)?;
        cwd.join("trust-policy.json")
    };

    if policy_path.exists() && !args.force {
        return Err(nono::NonoError::TrustPolicy(format!(
            "{} already exists (use --force to overwrite)",
            policy_path.display()
        )));
    }

    let patterns = if is_user && args.include.is_empty() {
        // User-level policies focus on publishers and enforcement, not file patterns
        Vec::new()
    } else {
        args.include
    };

    if !is_user && patterns.is_empty() {
        eprintln!("  {} no --include patterns specified", "Warning:".yellow(),);
        eprintln!(
            "  {}",
            "Add patterns manually to trust-policy.json or re-run with --include.".yellow()
        );
    }

    // Try to include the public key if a signing key exists
    let key_id = args.key.as_deref().unwrap_or("default");
    let publisher = match load_public_key_bytes(key_id) {
        Ok(pub_bytes) => {
            let b64 = base64_encode(&pub_bytes);
            Some(serde_json::json!({
                "name": key_id,
                "key_id": key_id,
                "public_key": b64
            }))
        }
        Err(_) => {
            eprintln!(
                "  {} signing key '{}' not found in keystore, skipping publisher entry.",
                "Note:".cyan(),
                key_id
            );
            eprintln!(
                "  {}",
                "Run 'nono trust keygen' to generate a key, then re-run 'nono trust init'.".cyan()
            );
            None
        }
    };

    let publishers = match publisher {
        Some(p) => vec![p],
        None => Vec::new(),
    };

    let policy = serde_json::json!({
        "version": 1,
        "includes": patterns,
        "publishers": publishers,
        "blocklist": {
            "digests": [],
            "publishers": []
        },
        "enforcement": "deny"
    });

    let json = serde_json::to_string_pretty(&policy).map_err(|e| {
        nono::NonoError::TrustPolicy(format!("failed to serialize trust policy: {e}"))
    })?;

    std::fs::write(&policy_path, format!("{json}\n")).map_err(nono::NonoError::Io)?;

    eprintln!("  {} {}", "Created".green(), policy_path.display());

    if !patterns.is_empty() {
        eprintln!("  Includes ({}):", patterns.len());
        for p in &patterns {
            eprintln!("    {p}");
        }
    }

    if publishers.is_empty() {
        eprintln!("\n  {}", "Next steps:".bold());
        eprintln!("  1. nono trust keygen");
        eprintln!("  2. nono trust init --force");
        eprintln!("  3. nono trust sign-policy {}", policy_path.display());
        eprintln!("  4. nono trust sign --all");
    } else {
        eprintln!("\n  {}", "Next steps:".bold());
        eprintln!("  1. nono trust sign-policy {}", policy_path.display());
        if !is_user {
            eprintln!("  2. nono trust sign --all");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// keygen
// ---------------------------------------------------------------------------

fn run_keygen(args: TrustKeygenArgs) -> Result<()> {
    let key_id = &args.id;

    // Check if key already exists
    if !args.force && trust_keystore::contains_secret(TRUST_SERVICE, key_id)? {
        return Err(nono::NonoError::KeystoreAccess(format!(
            "key '{key_id}' already exists in keystore (use --force to overwrite)"
        )));
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

    // Store PKCS#8 as base64 in the configured trust keystore.
    let pkcs8_b64 = Zeroizing::new(base64_encode(pkcs8_doc.as_ref()));
    trust_keystore::store_secret(TRUST_SERVICE, key_id, pkcs8_b64.as_str())?;

    // Store public key separately so verification never needs the private key
    let pub_key_b64 = base64_encode(pub_key.as_bytes());
    trust_keystore::store_secret(TRUST_PUB_SERVICE, key_id, &pub_key_b64)?;
    store_public_key_cache(key_id, &pub_key_b64)?;

    eprintln!("{}", "Signing key generated successfully.".green());
    eprintln!("  Key ID:      {key_id}");
    eprintln!("  Fingerprint: {hex_id}");
    eprintln!("  Algorithm:   ECDSA P-256 (SHA-256)");
    eprintln!(
        "  Stored in:   {}",
        trust_keystore::backend_description(TRUST_SERVICE)
    );
    eprintln!();
    eprintln!("Public key (base64 DER, for trust-policy.json):");
    eprintln!("  {pub_key_b64}");
    eprintln!();
    eprintln!("Public key (PEM):");
    eprintln!("{}", pub_key.to_pem());

    Ok(())
}

// ---------------------------------------------------------------------------
// export-key
// ---------------------------------------------------------------------------

fn run_export_key(args: TrustExportKeyArgs) -> Result<()> {
    let key_id = &args.id;
    let pub_key_bytes = load_public_key_bytes(key_id)?;

    if args.pem {
        let pub_key = trust::DerPublicKey::from(pub_key_bytes);
        print!("{}", pub_key.to_pem());
    } else {
        println!("{}", base64_encode(&pub_key_bytes));
    }

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
        eprintln!("No files found to sign.");
        return Ok(());
    }

    if args.multi_subject {
        return run_sign_multi_keyed(&files, &key_pair, key_id);
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

/// Sign multiple files into a single multi-subject bundle (keyed).
fn run_sign_multi_keyed(files: &[PathBuf], key_pair: &trust::KeyPair, key_id: &str) -> Result<()> {
    let cwd = std::env::current_dir().map_err(nono::NonoError::Io)?;

    // Compute digests for all files
    let mut file_pairs = Vec::with_capacity(files.len());
    for file_path in files {
        let digest = trust::file_digest(file_path).map_err(|e| nono::NonoError::TrustSigning {
            path: file_path.display().to_string(),
            reason: format!("failed to compute digest: {e}"),
        })?;
        // Use relative path as subject name when possible
        let name = file_path.strip_prefix(&cwd).unwrap_or(file_path);
        file_pairs.push((name.to_path_buf(), digest));
    }

    let bundle_json = trust::sign_files(&file_pairs, key_pair, key_id)?;

    // Write to .nono-trust.bundle in CWD
    let bundle_path = trust::multi_subject_bundle_path(&cwd);
    std::fs::write(&bundle_path, &bundle_json).map_err(|e| nono::NonoError::TrustSigning {
        path: bundle_path.display().to_string(),
        reason: format!("failed to write bundle: {e}"),
    })?;

    for file_path in files {
        let rel = file_path.strip_prefix(&cwd).unwrap_or(file_path);
        eprintln!("  {} {}", "SIGNED".green(), rel.display());
    }
    eprintln!();
    eprintln!(
        "{}",
        format!(
            "Signed {} file(s) into {} successfully.",
            files.len(),
            bundle_path.display()
        )
        .green()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// keyless sign (Sigstore Fulcio + Rekor)
// ---------------------------------------------------------------------------

fn run_sign_keyless(args: TrustSignArgs) -> Result<()> {
    let multi_subject = args.multi_subject;
    let files = resolve_files(&args.files, args.all, args.policy.as_deref())?;

    if files.is_empty() {
        eprintln!("No files found to sign.");
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

    if multi_subject {
        return rt.block_on(run_sign_multi_keyless(&files, &signer));
    }

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

/// Sign multiple files into a single multi-subject bundle (keyless via Fulcio + Rekor).
async fn run_sign_multi_keyless(files: &[PathBuf], signer: &sigstore_sign::Signer) -> Result<()> {
    let cwd = std::env::current_dir().map_err(nono::NonoError::Io)?;
    let signer_predicate = build_keyless_predicate();

    let mut attestation =
        sigstore_sign::Attestation::new(trust::NONO_MULTI_SUBJECT_PREDICATE_TYPE, signer_predicate);

    for file_path in files {
        let content = std::fs::read(file_path).map_err(|e| nono::NonoError::TrustSigning {
            path: file_path.display().to_string(),
            reason: format!("failed to read file: {e}"),
        })?;
        let digest_hex = trust::bytes_digest(&content);
        let digest_hash = sigstore_sign::types::Sha256Hash::from_hex(&digest_hex).map_err(|e| {
            nono::NonoError::TrustSigning {
                path: file_path.display().to_string(),
                reason: format!("failed to parse digest: {e}"),
            }
        })?;
        let name = file_path
            .strip_prefix(&cwd)
            .unwrap_or(file_path)
            .display()
            .to_string();
        attestation = attestation.add_subject(name, digest_hash);
    }

    let bundle =
        signer
            .sign_attestation(attestation)
            .await
            .map_err(|e| nono::NonoError::TrustSigning {
                path: String::new(),
                reason: format!("keyless signing failed: {e}"),
            })?;

    let bundle_json = bundle
        .to_json_pretty()
        .map_err(|e| nono::NonoError::TrustSigning {
            path: String::new(),
            reason: format!("failed to serialize bundle: {e}"),
        })?;

    let bundle_path = trust::multi_subject_bundle_path(&cwd);
    std::fs::write(&bundle_path, &bundle_json).map_err(|e| nono::NonoError::TrustSigning {
        path: bundle_path.display().to_string(),
        reason: format!("failed to write bundle: {e}"),
    })?;

    for file_path in files {
        let rel = file_path.strip_prefix(&cwd).unwrap_or(file_path);
        eprintln!("  {} {}", "SIGNED".green(), rel.display());
    }
    eprintln!();
    eprintln!(
        "{}",
        format!(
            "Signed {} file(s) into {} successfully (keyless).",
            files.len(),
            bundle_path.display()
        )
        .green()
    );

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
        None if args.user => {
            let user_path =
                user_trust_policy_path().ok_or_else(|| nono::NonoError::TrustSigning {
                    path: "~/.config/nono/trust-policy.json".to_string(),
                    reason: "could not resolve user config directory".to_string(),
                })?;
            if !user_path.exists() {
                return Err(nono::NonoError::TrustSigning {
                    path: user_path.display().to_string(),
                    reason: "user-level trust-policy.json not found. Run 'nono trust init --user' to create one.".to_string(),
                });
            }
            user_path
        }
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

    // Validate the policy file is well-formed before signing.
    trust::load_policy_from_file(&policy_path)?;

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

    // Check if user passed a .nono-trust.bundle directly
    let mut multi_bundles: Vec<PathBuf> = Vec::new();
    let mut single_files: Vec<PathBuf> = Vec::new();

    for f in &args.files {
        if f.file_name().and_then(|n| n.to_str()) == Some(".nono-trust.bundle") {
            multi_bundles.push(f.clone());
        } else {
            single_files.push(f.clone());
        }
    }

    // Resolve single instruction files (pass policy to avoid reloading)
    let files = resolve_files_with_policy(&single_files, args.all, &policy)?;

    // When --all, also check for .nono-trust.bundle in CWD
    if args.all {
        let cwd = std::env::current_dir().map_err(nono::NonoError::Io)?;
        let multi_path = trust::multi_subject_bundle_path(&cwd);
        if multi_path.exists() {
            multi_bundles.push(multi_path);
        }
    }

    // Run the same missing-literal check that nono run uses, so
    // `trust verify --all` surfaces the same errors as startup.
    if args.all {
        let cwd_for_check = std::env::current_dir().map_err(nono::NonoError::Io)?;
        crate::trust_scan::check_missing_literals(&policy, &cwd_for_check, &files, false)?;
    }

    if files.is_empty() && multi_bundles.is_empty() {
        eprintln!("No files or multi-subject bundles found to verify.");
        return Ok(());
    }

    let mut verified = 0u32;
    let mut failed = 0u32;

    // Verify multi-subject bundles first to collect covered paths
    let mut multi_verified_paths: std::collections::HashSet<PathBuf> =
        std::collections::HashSet::new();

    for bundle_path in &multi_bundles {
        let scan_root = bundle_path.parent().unwrap_or_else(|| Path::new("."));
        match verify_multi_subject_file(bundle_path, scan_root, &policy) {
            Ok(subjects) => {
                for (name, signer) in &subjects {
                    eprintln!("  {} {} (signer: {})", "VERIFIED".green(), name, signer);
                    verified = verified.saturating_add(1);
                    // Track the canonical path so per-file check can skip it
                    let subject_path = scan_root.join(name);
                    if let Ok(canon) = std::fs::canonicalize(&subject_path) {
                        multi_verified_paths.insert(canon);
                    }
                }
            }
            Err(reason) => {
                eprintln!("  {} {}", "FAILED".red(), bundle_path.display());
                eprintln!("    Reason: {reason}");
                failed = failed.saturating_add(1);
            }
        }
    }

    // Verify per-file bundles, skipping files already verified via multi-subject
    for file_path in &files {
        if multi_verified_paths.contains(file_path) {
            continue;
        }
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

/// Verify a `.nono-trust.bundle` multi-subject bundle.
///
/// Returns `Ok(Vec<(subject_name, signer_info)>)` on success, or an error string.
fn verify_multi_subject_file(
    bundle_path: &Path,
    scan_root: &Path,
    policy: &trust::TrustPolicy,
) -> std::result::Result<Vec<(String, String)>, String> {
    let bundle = trust::load_bundle(bundle_path).map_err(|e| format!("invalid bundle: {e}"))?;

    // Validate predicate type
    let predicate_type = trust::extract_predicate_type(&bundle, bundle_path)
        .map_err(|e| format!("failed to extract predicate type: {e}"))?;
    if predicate_type != trust::NONO_MULTI_SUBJECT_PREDICATE_TYPE {
        return Err(format!(
            "wrong bundle type: expected multi-file attestation, got {predicate_type}"
        ));
    }

    // Extract signer identity
    let identity = trust::extract_signer_identity(&bundle, bundle_path)
        .map_err(|e| format!("no signer identity: {e}"))?;

    // Check publisher match
    let matching = policy.matching_publishers(&identity);
    if matching.is_empty() {
        return Err(format!(
            "signer '{}' not in trusted publishers",
            format_identity(&identity)
        ));
    }

    // Cryptographic verification
    match &identity {
        trust::SignerIdentity::Keyed { key_id } => {
            let pub_key_b64 = matching.iter().find_map(|p| p.public_key.as_ref());
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
            trust::verify_keyed_signature(&bundle, &key_bytes, bundle_path)
                .map_err(|e| format!("signature verification failed: {e}"))?;
        }
        trust::SignerIdentity::Keyless { .. } => {
            // For keyless, verify using the first subject's digest
            let subjects = trust::extract_all_subjects(&bundle, bundle_path)
                .map_err(|e| format!("failed to extract subjects: {e}"))?;
            let first_digest = subjects
                .first()
                .map(|(_, d)| d.as_str())
                .ok_or("no subjects in bundle")?;
            let trusted_root = trust::load_production_trusted_root()
                .map_err(|e| format!("failed to load Sigstore trusted root: {e}"))?;
            let sigstore_policy = trust::VerificationPolicy::default();
            trust::verify_bundle_with_digest(
                first_digest,
                &bundle,
                &trusted_root,
                &sigstore_policy,
                bundle_path,
            )
            .map_err(|e| format!("Sigstore verification failed: {e}"))?;
        }
    }

    // Extract and verify each subject's digest
    let subjects = trust::extract_all_subjects(&bundle, bundle_path)
        .map_err(|e| format!("failed to extract subjects: {e}"))?;

    let signer_name = format_identity(&identity);
    let mut results = Vec::with_capacity(subjects.len());

    for (name, expected_digest) in &subjects {
        let file_path = scan_root.join(name);
        let actual_digest = trust::file_digest(&file_path)
            .map_err(|e| format!("failed to read subject '{}': {e}", name))?;
        if actual_digest != *expected_digest {
            return Err(format!(
                "digest mismatch for '{}': file has been modified since signing",
                name
            ));
        }
        results.push((name.clone(), signer_name.clone()));
    }

    Ok(results)
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
    let files = trust::find_included_files(&policy, &cwd)?;

    // Surface missing-literal warnings so `trust list` matches `nono run`.
    crate::trust_scan::check_missing_literals(&policy, &cwd, &files, false)?;

    if files.is_empty() {
        eprintln!("No files found matching policy includes in current directory.");
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
    if let Some(b64) = load_public_key_cache(key_id)? {
        return base64_decode(&b64)
            .map_err(|e| nono::NonoError::KeystoreAccess(format!("corrupt public key data: {e}")));
    }

    let b64 = trust_keystore::load_secret(TRUST_PUB_SERVICE, key_id).map_err(|e| match e {
        nono::NonoError::SecretNotFound(_) => nono::NonoError::SecretNotFound(format!(
            "public key '{key_id}' not found in keystore (run 'nono trust keygen' to regenerate)"
        )),
        other => other,
    })?;

    if let Err(e) = store_public_key_cache(key_id, &b64) {
        debug!(
            "failed to cache trust public key '{}' to disk after keystore load: {}",
            key_id, e
        );
    }

    base64_decode(b64.as_str())
        .map_err(|e| nono::NonoError::KeystoreAccess(format!("corrupt public key data: {e}")))
}

pub(crate) fn load_signing_key(key_id: &str) -> Result<trust::KeyPair> {
    let pkcs8_b64 = trust_keystore::load_secret(TRUST_SERVICE, key_id).map_err(|e| match e {
        nono::NonoError::SecretNotFound(_) => nono::NonoError::SecretNotFound(format!(
            "signing key '{key_id}' not found in keystore (run 'nono trust keygen' first)"
        )),
        other => other,
    })?;

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
        let user_path = user_trust_policy_path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "~/.config/nono/trust-policy.json".to_string());
        eprintln!(
            "  {}",
            "Warning: project-level trust-policy.json found but no user-level policy exists."
                .yellow()
        );
        eprintln!(
            "  {}",
            "A user-level policy defines who you trust across all projects (publishers, enforcement, blocklist)."
                .yellow()
        );
        eprintln!(
            "  {}",
            format!(
                "Run 'nono trust init --user' to create one, then 'nono trust sign-policy {user_path}' to sign it."
            )
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

pub(crate) fn user_trust_policy_path() -> Option<PathBuf> {
    #[cfg(feature = "test-trust-overrides")]
    {
        if let Some(raw_path) = std::env::var_os(TEST_USER_POLICY_PATH_ENV) {
            if !raw_path.is_empty() {
                let path = PathBuf::from(&raw_path);
                if path.is_absolute() {
                    return Some(path);
                }

                tracing::warn!(
                    "Ignoring invalid {}='{}' (must be absolute), falling back to user config dir",
                    TEST_USER_POLICY_PATH_ENV,
                    path.display()
                );
            }
        }
    }

    crate::profile::resolve_user_config_dir()
        .ok()
        .map(|d| d.join("nono").join("trust-policy.json"))
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
        if policy.includes.is_empty() {
            eprintln!(
                "No files found to sign: trust policy has no 'includes' patterns.\n\
                 Create a trust policy with: nono trust init --include \"<pattern>\""
            );
            return Ok(Vec::new());
        }
        let cwd = std::env::current_dir().map_err(nono::NonoError::Io)?;
        trust::find_included_files(&policy, &cwd)
    } else {
        canonicalize_paths(explicit)
    }
}

/// Resolve files using an already-loaded policy (avoids duplicate policy load warnings).
fn resolve_files_with_policy(
    explicit: &[PathBuf],
    all: bool,
    policy: &trust::TrustPolicy,
) -> Result<Vec<PathBuf>> {
    if all {
        let cwd = std::env::current_dir().map_err(nono::NonoError::Io)?;
        trust::find_included_files(policy, &cwd)
    } else {
        canonicalize_paths(explicit)
    }
}

fn canonicalize_paths(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut resolved = Vec::with_capacity(paths.len());
    for path in paths {
        let canonical = std::fs::canonicalize(path).map_err(|e| nono::NonoError::TrustSigning {
            path: path.display().to_string(),
            reason: format!("file not found: {e}"),
        })?;
        resolved.push(canonical);
    }
    Ok(resolved)
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

fn public_key_cache_path(key_id: &str) -> Result<PathBuf> {
    let dir = crate::config::user::user_trusted_keys_dir()?;
    Ok(dir.join(format!(
        "{}.{}",
        hex_component(key_id.as_bytes()),
        TRUST_PUB_CACHE_EXT
    )))
}

fn load_public_key_cache(key_id: &str) -> Result<Option<String>> {
    let path = public_key_cache_path(key_id)?;
    match std::fs::read_to_string(&path) {
        Ok(contents) => Ok(Some(contents.trim().to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(nono::NonoError::KeystoreAccess(format!(
            "failed to read cached public key '{}': {}",
            path.display(),
            e
        ))),
    }
}

fn store_public_key_cache(key_id: &str, public_key_b64: &str) -> Result<()> {
    let path = public_key_cache_path(key_id)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| nono::NonoError::ConfigWrite {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    std::fs::write(&path, format!("{public_key_b64}\n")).map_err(|e| {
        nono::NonoError::ConfigWrite {
            path: path.clone(),
            source: e,
        }
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
            nono::NonoError::ConfigWrite {
                path: path.clone(),
                source: e,
            }
        })?;
    }

    Ok(())
}

fn hex_component(value: &[u8]) -> String {
    let mut encoded = String::with_capacity(value.len().saturating_mul(2));
    for byte in value {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
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
    fn public_key_cache_path_encodes_key_id() {
        let dir = tempfile::tempdir().unwrap();
        let original = std::env::var("XDG_CONFIG_HOME").ok();
        std::env::set_var("XDG_CONFIG_HOME", dir.path());

        let path = public_key_cache_path("../default").unwrap();

        match original {
            Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }

        assert_eq!(path.extension().and_then(|ext| ext.to_str()), Some("b64"));
        assert!(!path.to_string_lossy().contains("../"));
        assert_eq!(
            path.file_stem().and_then(|stem| stem.to_str()),
            Some("2e2e2f64656661756c74")
        );
    }

    #[test]
    fn load_public_key_bytes_prefers_disk_cache() {
        let dir = tempfile::tempdir().unwrap();
        let original = std::env::var("XDG_CONFIG_HOME").ok();
        std::env::set_var("XDG_CONFIG_HOME", dir.path());

        let expected = b"public key bytes";
        let encoded = base64_encode(expected);
        store_public_key_cache("default", &encoded).unwrap();
        let loaded = load_public_key_bytes("default").unwrap();

        match original {
            Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }

        assert_eq!(loaded, expected);
    }

    #[cfg(feature = "test-trust-overrides")]
    #[test]
    fn user_trust_policy_path_prefers_test_override() {
        let dir = tempfile::tempdir().unwrap();
        let override_path = dir.path().join("trust-policy.json");
        let original = std::env::var(TEST_USER_POLICY_PATH_ENV).ok();

        std::env::set_var(TEST_USER_POLICY_PATH_ENV, &override_path);
        let resolved = user_trust_policy_path();

        match original {
            Some(value) => std::env::set_var(TEST_USER_POLICY_PATH_ENV, value),
            None => std::env::remove_var(TEST_USER_POLICY_PATH_ENV),
        }

        assert_eq!(resolved, Some(override_path));
    }

    #[test]
    fn load_trust_policy_returns_default_when_no_file() {
        // CWD mutation with catch_unwind to guarantee cleanup even on panic.
        // Isolate from real user config dir to avoid picking up invalid files.
        let dir = tempfile::tempdir().unwrap();
        let original = std::env::current_dir().unwrap();
        let orig_xdg = std::env::var("XDG_CONFIG_HOME").ok();
        let xdg_dir = dir.path().join("xdg");
        std::fs::create_dir_all(&xdg_dir).unwrap();
        std::env::set_var("XDG_CONFIG_HOME", &xdg_dir);

        let result = std::panic::catch_unwind(|| {
            std::env::set_current_dir(dir.path()).unwrap();
            let policy = load_trust_policy(None).unwrap();
            assert!(policy.publishers.is_empty());
        });

        std::env::set_current_dir(original).unwrap();
        match orig_xdg {
            Some(val) => std::env::set_var("XDG_CONFIG_HOME", val),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
        result.unwrap();
    }
}
