//! Instruction file attestation and integrity verification
//!
//! This module provides types, digest computation, and trust policy primitives
//! for verifying the provenance of instruction files (SKILLS.md, CLAUDE.md,
//! AGENT.MD, etc.) before an AI agent ingests them.
//!
//! # Architecture
//!
//! ```text
//! instruction file --> digest --> blocklist check --> bundle verify --> publisher match --> allow/deny
//! ```
//!
//! The library provides attestation primitives reusable by all language bindings.
//! Signing, CLI commands, and policy file loading live in `nono-cli`.
//!
//! # Components
//!
//! - **Types** ([`types`]): Trust policy, publisher identity, blocklist, verification result
//! - **Digest** ([`digest`]): SHA-256 digest computation for files and byte slices
//! - **Policy** ([`policy`]): Loading, merging, and evaluation of trust policies
//! - **DSSE** ([`dsse`]): Dead Simple Signing Envelope parsing, PAE construction, in-toto statements
//! - **Bundle** ([`bundle`]): Sigstore bundle loading, verification, and identity extraction
//! - **Signing** ([`signing`]): Keyed ECDSA P-256 signing and Sigstore bundle construction
//!
//! # Security
//!
//! - Blocklist checked before any cryptographic verification (fast reject)
//! - Enforcement modes: `Deny` (hard block), `Warn` (log + allow), `Audit` (silent allow + log)
//! - Project-level policy cannot weaken user-level enforcement
//! - No TOFU: files must have valid signatures from trusted publishers on first encounter

pub mod base64;
pub mod bundle;
pub mod digest;
pub mod dsse;
pub mod policy;
pub mod signing;
pub mod types;

pub use bundle::{
    bundle_path_for, extract_bundle_digest, extract_predicate_type, extract_signer_identity,
    load_bundle, load_bundle_from_str, load_production_trusted_root, load_trusted_root,
    load_trusted_root_from_str, parse_cert_info, verify_bundle, verify_bundle_keyed,
    verify_bundle_subject_name, verify_bundle_with_digest, verify_keyed_signature, Bundle,
    CertificateInfo, DerPublicKey, Sha256Hash, SigstoreVerificationResult, TrustedRoot,
    VerificationPolicy,
};
pub use digest::{bytes_digest, file_digest};
pub use dsse::{
    new_envelope, new_instruction_statement, new_policy_statement, new_statement, pae,
    DsseEnvelope, DsseSignature, InTotoStatement, InTotoSubject, IN_TOTO_PAYLOAD_TYPE,
    IN_TOTO_STATEMENT_TYPE, NONO_POLICY_PREDICATE_TYPE, NONO_PREDICATE_TYPE,
};
pub use policy::{
    evaluate_file, find_instruction_files, load_policy_from_file, load_policy_from_str,
    merge_policies,
};
pub use signing::{
    export_public_key, generate_signing_key, key_id_hex, sign_bytes, sign_instruction_file,
    sign_policy_bytes, sign_policy_file, write_bundle, KeyPair, SigningScheme,
};
pub use types::{
    BlockedPublisher, Blocklist, BlocklistEntry, Enforcement, InstructionPatterns, Publisher,
    SignerIdentity, TrustPolicy, VerificationOutcome, VerificationResult, TRUST_POLICY_VERSION,
};
