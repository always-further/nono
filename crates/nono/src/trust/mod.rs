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
//!
//! # Security
//!
//! - Blocklist checked before any cryptographic verification (fast reject)
//! - Enforcement modes: `Deny` (hard block), `Warn` (log + allow), `Audit` (silent allow + log)
//! - Project-level policy cannot weaken user-level enforcement
//! - No TOFU: files must have valid signatures from trusted publishers on first encounter

pub mod digest;
pub mod policy;
pub mod types;

pub use digest::{bytes_digest, file_digest};
pub use policy::{
    evaluate_file, find_instruction_files, load_policy_from_file, load_policy_from_str,
    merge_policies,
};
pub use types::{
    BlockedPublisher, Blocklist, BlocklistEntry, Enforcement, InstructionPatterns, Publisher,
    SignerIdentity, TrustPolicy, VerificationOutcome, VerificationResult,
};
