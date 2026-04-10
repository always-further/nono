//! Core types for the undo/snapshot system
//!
//! Defines content hashes, file state, change tracking, and session metadata
//! used by the object store and snapshot manager.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

/// A SHA-256 content hash (32 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentHash([u8; 32]);

impl ContentHash {
    /// Create a ContentHash from raw bytes
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Return the first 2 hex characters (used for object store directory sharding)
    #[must_use]
    pub fn prefix(&self) -> String {
        format!("{:02x}", self.0[0])
    }

    /// Return the remaining hex characters after the prefix
    #[must_use]
    pub fn suffix(&self) -> String {
        let mut s = String::with_capacity(62);
        for byte in &self.0[1..] {
            s.push_str(&format!("{byte:02x}"));
        }
        s
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContentHash({})", self)
    }
}

impl FromStr for ContentHash {
    type Err = ContentHashParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s.len() != 64 {
            return Err(ContentHashParseError::InvalidLength(s.len()));
        }
        let mut bytes = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hex_str =
                std::str::from_utf8(chunk).map_err(|_| ContentHashParseError::InvalidHex)?;
            bytes[i] =
                u8::from_str_radix(hex_str, 16).map_err(|_| ContentHashParseError::InvalidHex)?;
        }
        Ok(Self(bytes))
    }
}

/// Error parsing a ContentHash from a hex string
#[derive(Debug, Clone)]
pub enum ContentHashParseError {
    /// Hex string was not 64 characters
    InvalidLength(usize),
    /// Hex string contained invalid characters
    InvalidHex,
}

impl fmt::Display for ContentHashParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength(len) => {
                write!(f, "expected 64 hex characters, got {len}")
            }
            Self::InvalidHex => write!(f, "invalid hex character"),
        }
    }
}

impl std::error::Error for ContentHashParseError {}

impl Serialize for ContentHash {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ContentHash {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// State of a single file at snapshot time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileState {
    /// SHA-256 hash of file content
    pub hash: ContentHash,
    /// File size in bytes
    pub size: u64,
    /// Last modification time (seconds since epoch)
    pub mtime: i64,
    /// File permissions (Unix mode bits)
    pub permissions: u32,
}

/// Type of change detected between snapshots
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeType {
    /// File was created (not in previous snapshot)
    Created,
    /// File content was modified
    Modified,
    /// File was deleted (in previous snapshot but not current)
    Deleted,
    /// Only file permissions changed
    PermissionsChanged,
}

impl fmt::Display for ChangeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Created => write!(f, "+"),
            Self::Modified => write!(f, "~"),
            Self::Deleted => write!(f, "-"),
            Self::PermissionsChanged => write!(f, "p"),
        }
    }
}

/// A change detected between two snapshots
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    /// Path to the changed file
    pub path: PathBuf,
    /// Type of change
    pub change_type: ChangeType,
    /// Size delta in bytes (positive = grew, negative = shrank)
    pub size_delta: Option<i64>,
    /// Hash before the change (None for Created)
    pub old_hash: Option<ContentHash>,
    /// Hash after the change (None for Deleted)
    pub new_hash: Option<ContentHash>,
}

/// Proxy mode used for network audit events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkAuditMode {
    /// CONNECT tunnel request
    Connect,
    /// Reverse proxy request
    Reverse,
    /// External proxy passthrough request
    External,
}

/// Decision outcome for a network audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkAuditDecision {
    /// Request was allowed
    Allow,
    /// Request was denied
    Deny,
}

/// A single network audit event captured by the proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAuditEvent {
    /// Event timestamp in Unix milliseconds
    pub timestamp_unix_ms: u64,
    /// Proxy mode handling the request
    pub mode: NetworkAuditMode,
    /// Allow or deny decision
    pub decision: NetworkAuditDecision,
    /// Hostname or logical service target (for reverse proxy events)
    pub target: String,
    /// Port when available (CONNECT/external), otherwise None
    pub port: Option<u16>,
    /// HTTP method when available
    pub method: Option<String>,
    /// Request path for reverse proxy events
    pub path: Option<String>,
    /// Upstream response status for reverse proxy events
    pub status: Option<u16>,
    /// Denial reason, if denied
    pub reason: Option<String>,
}

/// Rollback availability status for a session.
///
/// Recorded in [`SessionMetadata`] so that `nono rollback list/show/restore`
/// can surface exactly why rollback is or is not available without re-examining
/// snapshot files.
///
/// Older `session.json` payloads that lack this field deserialize as `Available`
/// (backward-compatible default) so existing sessions continue to behave as before.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RollbackStatus {
    /// Baseline snapshot captured successfully; rollback is available.
    #[default]
    Available,
    /// Rollback was explicitly disabled (`--no-rollback`) or skipped (no write paths).
    Skipped,
    /// Baseline snapshot capture was attempted but failed; execution continued with a
    /// warning and rollback is NOT available for this session.
    FailedWarningOnly {
        /// Human-readable reason the capture failed.
        reason: String,
    },
}

impl RollbackStatus {
    /// Returns `true` if rollback snapshots are available for this session.
    #[must_use]
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available)
    }

    /// Returns a human-readable label for display in `nono rollback list/show`.
    #[must_use]
    pub fn display_label(&self) -> &str {
        match self {
            Self::Available => "rollback-capable",
            Self::Skipped => "audit-only",
            Self::FailedWarningOnly { .. } => "audit-only (capture failed)",
        }
    }
}

/// Metadata for an undo session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetadata {
    /// Unique session identifier
    pub session_id: String,
    /// Session start time (ISO 8601)
    pub started: String,
    /// Session end time (ISO 8601), None if still running
    pub ended: Option<String>,
    /// Command that was executed
    pub command: Vec<String>,
    /// Paths being tracked for changes
    pub tracked_paths: Vec<PathBuf>,
    /// Number of snapshots taken
    pub snapshot_count: u32,
    /// Child process exit code
    pub exit_code: Option<i32>,
    /// Merkle roots from each snapshot (chain of state commitments)
    pub merkle_roots: Vec<ContentHash>,
    /// Network events captured by the proxy during this session
    #[serde(default)]
    pub network_events: Vec<NetworkAuditEvent>,
    /// Whether rollback snapshots were captured for this session.
    ///
    /// Defaults to `Available` when deserializing older payloads that lack this
    /// field, preserving backward compatibility.
    #[serde(default)]
    pub rollback_status: RollbackStatus,
}

/// A snapshot manifest capturing filesystem state at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotManifest {
    /// Snapshot sequence number (0 = baseline)
    pub number: u32,
    /// Timestamp when snapshot was taken (ISO 8601)
    pub timestamp: String,
    /// Parent snapshot number (None for baseline)
    pub parent: Option<u32>,
    /// Map of file paths to their state at snapshot time
    pub files: HashMap<PathBuf, FileState>,
    /// Merkle root over all file hashes (cryptographic state commitment)
    pub merkle_root: ContentHash,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_hash_hex_roundtrip() {
        let bytes = [
            0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45,
            0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
            0x23, 0x45, 0x67, 0x89,
        ];
        let hash = ContentHash::from_bytes(bytes);
        let hex = hash.to_string();
        let parsed: ContentHash = hex.parse().expect("should parse");
        assert_eq!(hash, parsed);
    }

    #[test]
    fn content_hash_prefix_suffix() {
        let bytes = [
            0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45,
            0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
            0x23, 0x45, 0x67, 0x89,
        ];
        let hash = ContentHash::from_bytes(bytes);
        assert_eq!(hash.prefix(), "ab");
        assert!(hash.suffix().starts_with("cdef"));
        assert_eq!(hash.prefix().len() + hash.suffix().len(), 64);
    }

    #[test]
    fn content_hash_invalid_length() {
        let result = "abc".parse::<ContentHash>();
        assert!(result.is_err());
    }

    #[test]
    fn content_hash_invalid_hex() {
        let result = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
            .parse::<ContentHash>();
        assert!(result.is_err());
    }

    #[test]
    fn content_hash_serde_roundtrip() {
        let bytes = [42u8; 32];
        let hash = ContentHash::from_bytes(bytes);
        let json = serde_json::to_string(&hash).expect("should serialize");
        let parsed: ContentHash = serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(hash, parsed);
    }

    #[test]
    fn change_type_display() {
        assert_eq!(ChangeType::Created.to_string(), "+");
        assert_eq!(ChangeType::Modified.to_string(), "~");
        assert_eq!(ChangeType::Deleted.to_string(), "-");
        assert_eq!(ChangeType::PermissionsChanged.to_string(), "p");
    }

    #[test]
    fn snapshot_manifest_serde_roundtrip() {
        let manifest = SnapshotManifest {
            number: 0,
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            parent: None,
            files: HashMap::new(),
            merkle_root: ContentHash::from_bytes([0u8; 32]),
        };
        let json = serde_json::to_string(&manifest).expect("should serialize");
        let parsed: SnapshotManifest = serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(parsed.number, 0);
        assert!(parsed.parent.is_none());
        assert!(parsed.files.is_empty());
    }

    #[test]
    fn rollback_status_available_is_available() {
        assert!(RollbackStatus::Available.is_available());
        assert!(!RollbackStatus::Skipped.is_available());
        assert!(!RollbackStatus::FailedWarningOnly {
            reason: "disk full".to_string()
        }
        .is_available());
    }

    #[test]
    fn rollback_status_display_labels() {
        assert_eq!(
            RollbackStatus::Available.display_label(),
            "rollback-capable"
        );
        assert_eq!(RollbackStatus::Skipped.display_label(), "audit-only");
        assert_eq!(
            RollbackStatus::FailedWarningOnly {
                reason: "error".to_string()
            }
            .display_label(),
            "audit-only (capture failed)"
        );
    }

    #[test]
    fn rollback_status_serde_roundtrip() {
        let status = RollbackStatus::FailedWarningOnly {
            reason: "locked file".to_string(),
        };
        let json = serde_json::to_string(&status).expect("serialize");
        let parsed: RollbackStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, status);
    }

    #[test]
    fn session_metadata_defaults_rollback_status_for_legacy_json() {
        // Older session.json payloads lack rollback_status; must deserialize as Available.
        let legacy = serde_json::json!({
            "session_id": "legacy-no-status",
            "started": "2025-01-01T00:00:00Z",
            "ended": null,
            "command": ["test"],
            "tracked_paths": [],
            "snapshot_count": 1,
            "exit_code": 0,
            "merkle_roots": [],
        });
        let meta: SessionMetadata = serde_json::from_value(legacy).expect("deserialize");
        // Default must be Available for backward compatibility
        assert_eq!(meta.rollback_status, RollbackStatus::Available);
        assert!(meta.rollback_status.is_available());
    }

    #[test]
    fn session_metadata_rollback_status_skipped_roundtrip() {
        let meta = SessionMetadata {
            session_id: "test-skip".to_string(),
            started: "2025-01-01T00:00:00Z".to_string(),
            ended: None,
            command: vec!["test".to_string()],
            tracked_paths: vec![],
            snapshot_count: 0,
            exit_code: None,
            merkle_roots: vec![],
            network_events: vec![],
            rollback_status: RollbackStatus::Skipped,
        };
        let json = serde_json::to_string(&meta).expect("serialize");
        let parsed: SessionMetadata = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.rollback_status, RollbackStatus::Skipped);
        assert!(!parsed.rollback_status.is_available());
    }

    #[test]
    fn session_metadata_rollback_status_failed_warning_roundtrip() {
        let reason = "disk full during baseline capture".to_string();
        let meta = SessionMetadata {
            session_id: "test-fail".to_string(),
            started: "2025-01-01T00:00:00Z".to_string(),
            ended: None,
            command: vec!["test".to_string()],
            tracked_paths: vec![],
            snapshot_count: 0,
            exit_code: None,
            merkle_roots: vec![],
            network_events: vec![],
            rollback_status: RollbackStatus::FailedWarningOnly {
                reason: reason.clone(),
            },
        };
        let json = serde_json::to_string(&meta).expect("serialize");
        let parsed: SessionMetadata = serde_json::from_str(&json).expect("deserialize");
        assert!(!parsed.rollback_status.is_available());
        assert_eq!(
            parsed.rollback_status.display_label(),
            "audit-only (capture failed)"
        );
    }
}
