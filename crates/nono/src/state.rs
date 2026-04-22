//! Sandbox state persistence
//!
//! This module provides serialization of capability state for diagnostic purposes.

use crate::capability::{
    AccessMode, CapabilitySet, FsCapability, UnixSocketCapability, UnixSocketMode,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Serializable representation of sandbox state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxState {
    /// Filesystem capabilities
    pub fs: Vec<FsCapState>,
    /// AF_UNIX socket capabilities (may be absent in states persisted
    /// by older nono builds; `#[serde(default)]` preserves backward compat).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unix_sockets: Vec<UnixSocketCapState>,
    /// Whether network is blocked
    pub net_blocked: bool,
}

/// Serializable representation of a filesystem capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsCapState {
    /// Original path as specified
    pub original: PathBuf,
    /// Resolved canonical path
    pub resolved: PathBuf,
    /// Access mode
    pub access: String,
    /// Whether this is a file (vs directory)
    pub is_file: bool,
}

/// Serializable representation of a [`UnixSocketCapability`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnixSocketCapState {
    /// Original path as specified
    pub original: PathBuf,
    /// Resolved canonical path
    pub resolved: PathBuf,
    /// Whether the grant is directory-scoped (non-recursive)
    pub is_directory: bool,
    /// Mode string: "connect" or "connect+bind"
    pub mode: String,
}

impl SandboxState {
    /// Create state from a capability set
    #[must_use]
    pub fn from_caps(caps: &CapabilitySet) -> Self {
        Self {
            fs: caps
                .fs_capabilities()
                .iter()
                .map(|cap| FsCapState {
                    original: cap.original.clone(),
                    resolved: cap.resolved.clone(),
                    access: cap.access.to_string(),
                    is_file: cap.is_file,
                })
                .collect(),
            unix_sockets: caps
                .unix_socket_capabilities()
                .iter()
                .map(|cap| UnixSocketCapState {
                    original: cap.original.clone(),
                    resolved: cap.resolved.clone(),
                    is_directory: cap.is_directory,
                    mode: cap.mode.to_string(),
                })
                .collect(),
            net_blocked: caps.is_network_blocked(),
        }
    }

    /// Convert state back to a capability set
    ///
    /// Paths are re-validated through the standard constructors (`new_dir`/`new_file`)
    /// which canonicalize paths and verify existence. This prevents crafted JSON from
    /// injecting arbitrary paths that bypass validation.
    ///
    /// Returns an error if any path no longer exists or fails validation.
    pub fn to_caps(&self) -> crate::error::Result<CapabilitySet> {
        let mut caps = CapabilitySet::new();

        for fs_cap in &self.fs {
            let access = match fs_cap.access.as_str() {
                "read" => AccessMode::Read,
                "write" => AccessMode::Write,
                "read+write" => AccessMode::ReadWrite,
                other => {
                    return Err(crate::error::NonoError::ConfigParse(format!(
                        "invalid access mode in sandbox state: {other}"
                    )));
                }
            };

            // Re-validate through the standard constructors to ensure
            // path canonicalization and existence checks are applied.
            let cap = if fs_cap.is_file {
                FsCapability::new_file(&fs_cap.original, access)?
            } else {
                FsCapability::new_dir(&fs_cap.original, access)?
            };
            caps.add_fs(cap);
        }

        for sock in &self.unix_sockets {
            let mode = match sock.mode.as_str() {
                "connect" => UnixSocketMode::Connect,
                "connect+bind" => UnixSocketMode::ConnectBind,
                other => {
                    return Err(crate::error::NonoError::ConfigParse(format!(
                        "invalid unix socket mode in sandbox state: {other}"
                    )));
                }
            };

            // Reconstruct from the caller-supplied `original` so the
            // stored alias survives the roundtrip (macOS Seatbelt uses
            // it for dual-path emission when original != resolved).
            // Then validate that canonicalisation produced the same
            // `resolved` as was serialized. The check rejects two
            // failure modes with one test:
            //
            // - Filesystem drift between save and reload (symlink moved,
            //   ConnectBind pending path now exists, etc.).
            // - Crafted JSON smuggling: attacker sets an evil `original`
            //   and legit `resolved`; the reconstructed cap's actual
            //   resolved won't match the crafted one, so we reject.
            let cap = if sock.is_directory {
                UnixSocketCapability::new_dir(&sock.original, mode)?
            } else {
                UnixSocketCapability::new_file(&sock.original, mode)?
            };
            if cap.resolved != sock.resolved {
                return Err(crate::error::NonoError::ConfigParse(format!(
                    "unix socket grant canonical path drifted at state reload: \
                     serialized resolved={}, actual resolved={}",
                    sock.resolved.display(),
                    cap.resolved.display(),
                )));
            }
            caps.add_unix_socket(cap);
        }

        caps.set_network_blocked(self.net_blocked);
        Ok(caps)
    }

    /// Serialize state to JSON
    pub fn to_json(&self) -> crate::error::Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| {
            crate::error::NonoError::ConfigParse(format!("Failed to serialize sandbox state: {e}"))
        })
    }

    /// Deserialize state from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_state_roundtrip() {
        let caps = CapabilitySet::new().block_network();
        let state = SandboxState::from_caps(&caps);

        assert!(state.net_blocked);
        assert!(state.fs.is_empty());

        let json = state.to_json().expect("serialize state");
        let restored = SandboxState::from_json(&json).expect("deserialize state");
        assert!(restored.net_blocked);
    }

    #[test]
    fn test_to_caps_rejects_nonexistent_path() {
        let json = r#"{
            "fs": [{
                "original": "/nonexistent/crafted/path",
                "resolved": "/nonexistent/crafted/path",
                "access": "read+write",
                "is_file": false
            }],
            "net_blocked": false
        }"#;
        let state = SandboxState::from_json(json).unwrap();
        assert!(
            state.to_caps().is_err(),
            "to_caps must reject nonexistent paths"
        );
    }

    #[test]
    fn test_to_caps_rejects_invalid_access_mode() {
        let json = r#"{
            "fs": [{
                "original": "/tmp",
                "resolved": "/tmp",
                "access": "root-access",
                "is_file": false
            }],
            "net_blocked": false
        }"#;
        let state = SandboxState::from_json(json).unwrap();
        assert!(
            state.to_caps().is_err(),
            "to_caps must reject invalid access modes"
        );
    }

    #[test]
    fn test_unix_socket_state_roundtrip_preserves_original_and_resolved() {
        use tempfile::tempdir;
        let dir = tempdir().expect("tempdir");
        let sock = dir.path().join("a.sock");
        std::fs::write(&sock, b"").expect("stub");

        let caps = CapabilitySet::new()
            .allow_unix_socket(&sock, UnixSocketMode::Connect)
            .expect("grant");
        let state = SandboxState::from_caps(&caps);
        let restored = state.to_caps().expect("to_caps");

        let round = restored.unix_socket_capabilities();
        assert_eq!(round.len(), 1);
        let before = &caps.unix_socket_capabilities()[0];
        let after = &round[0];
        assert_eq!(after.resolved, before.resolved);
        assert_eq!(after.original, before.original);
        assert_eq!(after.mode, before.mode);
        assert_eq!(after.is_directory, before.is_directory);
    }

    #[test]
    fn test_unix_socket_state_rejects_invalid_mode() {
        let json = r#"{
            "fs": [],
            "unix_sockets": [{
                "original": "/tmp",
                "resolved": "/tmp",
                "is_directory": true,
                "mode": "bind-only"
            }],
            "net_blocked": false
        }"#;
        let state = SandboxState::from_json(json).unwrap();
        assert!(
            state.to_caps().is_err(),
            "to_caps must reject unknown unix socket modes"
        );
    }
}
