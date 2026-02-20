//! Core types for instruction file attestation
//!
//! Defines the trust policy structure, publisher identities, blocklist entries,
//! and verification results used throughout the attestation pipeline.

use crate::error::{NonoError, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Trust policy for instruction file verification.
///
/// Loaded from `trust-policy.json` files at embedded, user, and project levels.
/// Multiple policies are merged: publishers and blocklist entries are unioned,
/// enforcement uses the strictest level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustPolicy {
    /// Policy format version
    pub version: u32,
    /// Glob patterns identifying instruction files
    pub instruction_patterns: Vec<String>,
    /// Trusted publisher identities
    pub publishers: Vec<Publisher>,
    /// Known-malicious file digests
    pub blocklist: Blocklist,
    /// Default enforcement mode
    pub enforcement: Enforcement,
}

impl TrustPolicy {
    /// Build an [`InstructionPatterns`] matcher from this policy's patterns.
    ///
    /// # Errors
    ///
    /// Returns `NonoError::TrustPolicy` if any glob pattern is invalid.
    pub fn instruction_matcher(&self) -> Result<InstructionPatterns> {
        InstructionPatterns::new(&self.instruction_patterns)
    }

    /// Check if a file digest is on the blocklist.
    ///
    /// Returns the matching entry if blocked, `None` otherwise.
    #[must_use]
    pub fn check_blocklist(&self, digest_hex: &str) -> Option<&BlocklistEntry> {
        self.blocklist
            .digests
            .iter()
            .find(|entry| entry.sha256 == digest_hex)
    }

    /// Find all publishers that match a given signer identity.
    #[must_use]
    pub fn matching_publishers(&self, identity: &SignerIdentity) -> Vec<&Publisher> {
        self.publishers
            .iter()
            .filter(|p| p.matches(identity))
            .collect()
    }
}

/// A trusted publisher identity.
///
/// Publishers come in two forms:
/// - **Keyless** (OIDC): identified by issuer, repository, workflow, and ref pattern
/// - **Keyed**: identified by a key ID in the system keystore
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Publisher {
    /// Human-readable name for this publisher
    pub name: String,
    /// OIDC issuer URL (keyless publishers only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Source repository pattern, supports wildcards (keyless publishers only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    /// Workflow file pattern, supports wildcards (keyless publishers only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow: Option<String>,
    /// Git ref pattern, supports wildcards (keyless publishers only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ref_pattern: Option<String>,
    /// Key ID in the system keystore (keyed publishers only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

impl Publisher {
    /// Check if this publisher is a keyed publisher.
    #[must_use]
    pub fn is_keyed(&self) -> bool {
        self.key_id.is_some()
    }

    /// Check if this publisher is a keyless (OIDC) publisher.
    #[must_use]
    pub fn is_keyless(&self) -> bool {
        self.issuer.is_some()
    }

    /// Check if a signer identity matches this publisher.
    #[must_use]
    pub fn matches(&self, identity: &SignerIdentity) -> bool {
        match identity {
            SignerIdentity::Keyed { key_id } => self.key_id.as_deref() == Some(key_id.as_str()),
            SignerIdentity::Keyless {
                issuer,
                repository,
                workflow,
                git_ref,
            } => {
                let issuer_match = self.issuer.as_deref().is_some_and(|i| i == issuer);

                let repo_match = self
                    .repository
                    .as_deref()
                    .is_some_and(|pattern| wildcard_match(pattern, repository));

                let workflow_match = self
                    .workflow
                    .as_deref()
                    .is_some_and(|pattern| wildcard_match(pattern, workflow));

                let ref_match = self
                    .ref_pattern
                    .as_deref()
                    .is_some_and(|pattern| wildcard_match(pattern, git_ref));

                issuer_match && repo_match && workflow_match && ref_match
            }
        }
    }
}

/// Simple wildcard matching for publisher patterns.
///
/// Supports `*` as a suffix wildcard (e.g., `org/*` matches `org/repo`)
/// or a literal `*` to match anything. All other patterns require exact match.
fn wildcard_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        value.starts_with(prefix)
    } else {
        pattern == value
    }
}

/// Known-malicious file digests.
///
/// Checked before any cryptographic verification for fast rejection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blocklist {
    /// List of blocked digests
    pub digests: Vec<BlocklistEntry>,
    /// List of blocked publisher identities
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub publishers: Vec<BlockedPublisher>,
}

/// A single blocklist entry identifying a known-malicious file by digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistEntry {
    /// SHA-256 hex digest of the blocked file
    pub sha256: String,
    /// Human-readable description of why this file is blocked
    pub description: String,
    /// Date the entry was added (ISO 8601 date string)
    pub added: String,
}

/// A blocked publisher identity.
///
/// Any signature from a blocked publisher is rejected regardless of
/// cryptographic validity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedPublisher {
    /// OIDC issuer URL or key ID pattern
    pub identity: String,
    /// Human-readable reason for blocking
    pub reason: String,
    /// Date the entry was added (ISO 8601 date string)
    pub added: String,
}

/// Enforcement mode for trust verification failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Enforcement {
    /// Allow access, log verification result for post-hoc review
    Audit = 0,
    /// Log warning but allow access (migration/adoption mode)
    Warn = 1,
    /// Hard deny unsigned/invalid/untrusted files (production default)
    Deny = 2,
}

impl Enforcement {
    /// Return the stricter of two enforcement modes.
    ///
    /// Used during policy merging: project-level cannot weaken user-level.
    #[must_use]
    pub fn strictest(self, other: Self) -> Self {
        if self >= other {
            self
        } else {
            other
        }
    }

    /// Whether this enforcement mode blocks access on failure.
    #[must_use]
    pub fn is_blocking(&self) -> bool {
        matches!(self, Self::Deny)
    }
}

/// Compiled glob matcher for instruction file patterns.
///
/// Wraps a [`GlobSet`] built from the trust policy's `instruction_patterns`.
#[derive(Debug, Clone)]
pub struct InstructionPatterns {
    glob_set: GlobSet,
    patterns: Vec<String>,
}

impl InstructionPatterns {
    /// Compile a set of glob patterns into a matcher.
    ///
    /// # Errors
    ///
    /// Returns `NonoError::TrustPolicy` if any pattern is invalid.
    pub fn new(patterns: &[String]) -> Result<Self> {
        let mut builder = GlobSetBuilder::new();
        for pattern in patterns {
            let glob = Glob::new(pattern).map_err(|e| {
                NonoError::TrustPolicy(format!("invalid instruction pattern '{pattern}': {e}"))
            })?;
            builder.add(glob);
        }
        let glob_set = builder.build().map_err(|e| {
            NonoError::TrustPolicy(format!("failed to build instruction pattern matcher: {e}"))
        })?;
        Ok(Self {
            glob_set,
            patterns: patterns.to_vec(),
        })
    }

    /// Check if a path matches any instruction file pattern.
    #[must_use]
    pub fn is_match<P: AsRef<Path>>(&self, path: P) -> bool {
        self.glob_set.is_match(path)
    }

    /// Return the original pattern strings.
    #[must_use]
    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }
}

/// Identity of the entity that signed a file.
///
/// Extracted from a Sigstore bundle's Fulcio certificate (keyless) or
/// matched against a keystore entry (keyed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignerIdentity {
    /// Keyed signer: private key stored in system keystore
    Keyed {
        /// Key identifier (e.g., `nono-keystore:default`)
        key_id: String,
    },
    /// Keyless signer: OIDC identity from Fulcio certificate
    Keyless {
        /// OIDC issuer URL
        issuer: String,
        /// Source repository (e.g., `org/repo`)
        repository: String,
        /// Workflow file that performed the signing
        workflow: String,
        /// Git ref at signing time
        git_ref: String,
    },
}

/// Outcome of verifying an instruction file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationOutcome {
    /// File verified successfully against a trusted publisher
    Verified {
        /// Name of the matching publisher
        publisher: String,
    },
    /// File digest is on the blocklist
    Blocked {
        /// Description from the blocklist entry
        reason: String,
    },
    /// Bundle is missing for a file that requires attestation
    Unsigned,
    /// Bundle signature is cryptographically invalid
    InvalidSignature {
        /// Details about the failure
        detail: String,
    },
    /// Bundle is valid but signer does not match any trusted publisher
    UntrustedPublisher {
        /// The signer identity that was found
        identity: SignerIdentity,
    },
    /// File digest does not match the digest in the bundle
    DigestMismatch {
        /// Expected digest from the bundle
        expected: String,
        /// Actual digest computed from the file
        actual: String,
    },
}

impl VerificationOutcome {
    /// Whether the verification succeeded.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    /// Whether the file should be blocked under the given enforcement mode.
    #[must_use]
    pub fn should_block(&self, enforcement: Enforcement) -> bool {
        if self.is_verified() {
            return false;
        }
        // Blocklist entries are always blocked regardless of enforcement mode
        if matches!(self, Self::Blocked { .. }) {
            return true;
        }
        enforcement.is_blocking()
    }
}

/// Complete verification result for an instruction file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Path to the verified file
    pub path: std::path::PathBuf,
    /// SHA-256 hex digest of the file
    pub digest: String,
    /// Verification outcome
    pub outcome: VerificationOutcome,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample_policy() -> TrustPolicy {
        TrustPolicy {
            version: 1,
            instruction_patterns: vec![
                "SKILLS*".to_string(),
                "CLAUDE*".to_string(),
                "AGENT.MD".to_string(),
                ".claude/**/*.md".to_string(),
            ],
            publishers: vec![
                Publisher {
                    name: "ci-publisher".to_string(),
                    issuer: Some("https://token.actions.githubusercontent.com".to_string()),
                    repository: Some("org/repo".to_string()),
                    workflow: Some(".github/workflows/sign.yml".to_string()),
                    ref_pattern: Some("refs/tags/v*".to_string()),
                    key_id: None,
                },
                Publisher {
                    name: "local-dev".to_string(),
                    issuer: None,
                    repository: None,
                    workflow: None,
                    ref_pattern: None,
                    key_id: Some("nono-keystore:default".to_string()),
                },
            ],
            blocklist: Blocklist {
                digests: vec![BlocklistEntry {
                    sha256: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                        .to_string(),
                    description: "Known malicious SKILLS.md".to_string(),
                    added: "2026-02-20".to_string(),
                }],
                publishers: vec![],
            },
            enforcement: Enforcement::Deny,
        }
    }

    #[test]
    fn instruction_patterns_match() {
        let policy = sample_policy();
        let matcher = policy.instruction_matcher().unwrap();
        assert!(matcher.is_match("SKILLS.md"));
        assert!(matcher.is_match("SKILLS-custom.md"));
        assert!(matcher.is_match("CLAUDE.md"));
        assert!(matcher.is_match("CLAUDErc"));
        assert!(matcher.is_match("AGENT.MD"));
        assert!(matcher.is_match(".claude/commands/deploy.md"));
        assert!(!matcher.is_match("README.md"));
        assert!(!matcher.is_match("src/main.rs"));
    }

    #[test]
    fn instruction_patterns_returns_originals() {
        let policy = sample_policy();
        let matcher = policy.instruction_matcher().unwrap();
        assert_eq!(matcher.patterns().len(), 4);
        assert_eq!(matcher.patterns()[0], "SKILLS*");
    }

    #[test]
    fn instruction_patterns_invalid_glob() {
        let result = InstructionPatterns::new(&["[invalid".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn blocklist_check_hit() {
        let policy = sample_policy();
        let result = policy
            .check_blocklist("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        assert!(result.is_some());
        assert_eq!(result.unwrap().description, "Known malicious SKILLS.md");
    }

    #[test]
    fn blocklist_check_miss() {
        let policy = sample_policy();
        let result = policy
            .check_blocklist("0000000000000000000000000000000000000000000000000000000000000000");
        assert!(result.is_none());
    }

    #[test]
    fn publisher_matches_keyed() {
        let policy = sample_policy();
        let identity = SignerIdentity::Keyed {
            key_id: "nono-keystore:default".to_string(),
        };
        let matches = policy.matching_publishers(&identity);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "local-dev");
    }

    #[test]
    fn publisher_matches_keyless() {
        let policy = sample_policy();
        let identity = SignerIdentity::Keyless {
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            repository: "org/repo".to_string(),
            workflow: ".github/workflows/sign.yml".to_string(),
            git_ref: "refs/tags/v1.0.0".to_string(),
        };
        let matches = policy.matching_publishers(&identity);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "ci-publisher");
    }

    #[test]
    fn publisher_no_match_wrong_repo() {
        let policy = sample_policy();
        let identity = SignerIdentity::Keyless {
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            repository: "evil/repo".to_string(),
            workflow: ".github/workflows/sign.yml".to_string(),
            git_ref: "refs/tags/v1.0.0".to_string(),
        };
        let matches = policy.matching_publishers(&identity);
        assert!(matches.is_empty());
    }

    #[test]
    fn publisher_no_match_wrong_ref() {
        let policy = sample_policy();
        let identity = SignerIdentity::Keyless {
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            repository: "org/repo".to_string(),
            workflow: ".github/workflows/sign.yml".to_string(),
            git_ref: "refs/heads/main".to_string(),
        };
        let matches = policy.matching_publishers(&identity);
        assert!(matches.is_empty());
    }

    #[test]
    fn publisher_keyed_vs_keyless_no_cross_match() {
        let policy = sample_policy();
        let keyed_identity = SignerIdentity::Keyed {
            key_id: "wrong-key".to_string(),
        };
        assert!(policy.matching_publishers(&keyed_identity).is_empty());

        let keyless_identity = SignerIdentity::Keyless {
            issuer: "https://other.issuer.com".to_string(),
            repository: "org/repo".to_string(),
            workflow: ".github/workflows/sign.yml".to_string(),
            git_ref: "refs/tags/v1.0.0".to_string(),
        };
        assert!(policy.matching_publishers(&keyless_identity).is_empty());
    }

    #[test]
    fn wildcard_publisher_matching() {
        let publisher = Publisher {
            name: "wildcard-org".to_string(),
            issuer: Some("https://token.actions.githubusercontent.com".to_string()),
            repository: Some("my-org/*".to_string()),
            workflow: Some("*".to_string()),
            ref_pattern: Some("*".to_string()),
            key_id: None,
        };
        let identity = SignerIdentity::Keyless {
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            repository: "my-org/any-repo".to_string(),
            workflow: ".github/workflows/anything.yml".to_string(),
            git_ref: "refs/heads/main".to_string(),
        };
        assert!(publisher.matches(&identity));
    }

    #[test]
    fn enforcement_ordering() {
        assert!(Enforcement::Deny > Enforcement::Warn);
        assert!(Enforcement::Warn > Enforcement::Audit);
        assert_eq!(
            Enforcement::Audit.strictest(Enforcement::Deny),
            Enforcement::Deny
        );
        assert_eq!(
            Enforcement::Deny.strictest(Enforcement::Audit),
            Enforcement::Deny
        );
        assert_eq!(
            Enforcement::Warn.strictest(Enforcement::Warn),
            Enforcement::Warn
        );
    }

    #[test]
    fn enforcement_is_blocking() {
        assert!(Enforcement::Deny.is_blocking());
        assert!(!Enforcement::Warn.is_blocking());
        assert!(!Enforcement::Audit.is_blocking());
    }

    #[test]
    fn verification_outcome_verified() {
        let outcome = VerificationOutcome::Verified {
            publisher: "test".to_string(),
        };
        assert!(outcome.is_verified());
        assert!(!outcome.should_block(Enforcement::Deny));
    }

    #[test]
    fn verification_outcome_blocked_always_blocks() {
        let outcome = VerificationOutcome::Blocked {
            reason: "malicious".to_string(),
        };
        assert!(!outcome.is_verified());
        assert!(outcome.should_block(Enforcement::Deny));
        assert!(outcome.should_block(Enforcement::Warn));
        assert!(outcome.should_block(Enforcement::Audit));
    }

    #[test]
    fn verification_outcome_unsigned_respects_enforcement() {
        let outcome = VerificationOutcome::Unsigned;
        assert!(outcome.should_block(Enforcement::Deny));
        assert!(!outcome.should_block(Enforcement::Warn));
        assert!(!outcome.should_block(Enforcement::Audit));
    }

    #[test]
    fn verification_outcome_untrusted_respects_enforcement() {
        let outcome = VerificationOutcome::UntrustedPublisher {
            identity: SignerIdentity::Keyed {
                key_id: "unknown".to_string(),
            },
        };
        assert!(outcome.should_block(Enforcement::Deny));
        assert!(!outcome.should_block(Enforcement::Warn));
    }

    #[test]
    fn verification_outcome_digest_mismatch() {
        let outcome = VerificationOutcome::DigestMismatch {
            expected: "aaa".to_string(),
            actual: "bbb".to_string(),
        };
        assert!(!outcome.is_verified());
        assert!(outcome.should_block(Enforcement::Deny));
    }

    #[test]
    fn publisher_is_keyed_and_keyless() {
        let keyed = Publisher {
            name: "k".to_string(),
            issuer: None,
            repository: None,
            workflow: None,
            ref_pattern: None,
            key_id: Some("id".to_string()),
        };
        assert!(keyed.is_keyed());
        assert!(!keyed.is_keyless());

        let keyless = Publisher {
            name: "kl".to_string(),
            issuer: Some("https://issuer".to_string()),
            repository: Some("org/repo".to_string()),
            workflow: Some("*".to_string()),
            ref_pattern: Some("*".to_string()),
            key_id: None,
        };
        assert!(!keyless.is_keyed());
        assert!(keyless.is_keyless());
    }

    #[test]
    fn trust_policy_serde_roundtrip() {
        let policy = sample_policy();
        let json = serde_json::to_string_pretty(&policy).unwrap();
        let parsed: TrustPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.publishers.len(), 2);
        assert_eq!(parsed.blocklist.digests.len(), 1);
        assert_eq!(parsed.enforcement, Enforcement::Deny);
    }

    #[test]
    fn verification_result_serde_roundtrip() {
        let result = VerificationResult {
            path: std::path::PathBuf::from("SKILLS.md"),
            digest: "abcd1234".to_string(),
            outcome: VerificationOutcome::Verified {
                publisher: "test-pub".to_string(),
            },
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: VerificationResult = serde_json::from_str(&json).unwrap();
        assert!(parsed.outcome.is_verified());
    }
}
