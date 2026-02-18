//! CLI-specific query extensions for the sandbox
//!
//! This module provides query functions and output formatting for the
//! `nono why` command.

use crate::config;
use colored::Colorize;
use nono::{AccessMode, CapabilitySet, NonoError, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Result of querying whether an operation is permitted
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum QueryResult {
    /// The operation is allowed
    #[serde(rename = "allowed")]
    Allowed {
        reason: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        granted_path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        access: Option<String>,
    },
    /// The operation is denied
    #[serde(rename = "denied")]
    Denied {
        reason: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        details: Option<String>,
    },
    /// Not running inside a sandbox
    #[serde(rename = "not_sandboxed")]
    NotSandboxed { message: String },
}

/// Query whether a path operation is permitted
pub fn query_path(path: &Path, requested: AccessMode, caps: &CapabilitySet) -> Result<QueryResult> {
    // Canonicalize the path for proper comparison
    let canonical = if path.exists() {
        path.canonicalize()
            .map_err(|e| NonoError::PathCanonicalization {
                path: path.to_path_buf(),
                source: e,
            })?
    } else {
        // For non-existent paths, try to canonicalize the parent
        if let Some(parent) = path.parent() {
            if parent.exists() {
                let parent_canonical =
                    parent
                        .canonicalize()
                        .map_err(|e| NonoError::PathCanonicalization {
                            path: parent.to_path_buf(),
                            source: e,
                        })?;
                parent_canonical.join(path.file_name().unwrap_or_default())
            } else {
                path.to_path_buf()
            }
        } else {
            path.to_path_buf()
        }
    };

    // First, check if this is a sensitive path (CLI security policy)
    if let Some(matched) = config::check_sensitive_path(&canonical.to_string_lossy())? {
        return Ok(QueryResult::Denied {
            reason: "sensitive_path".to_string(),
            details: Some(format!(
                "Path matches sensitive pattern '{}'. Access blocked by security policy.",
                matched
            )),
        });
    }

    // Check capabilities. Prefer the most specific matching grant so broad system
    // reads (e.g. /private on macOS) do not shadow explicit user grants.
    let mut best_covering: Option<&nono::FsCapability> = None;
    let mut best_sufficient: Option<&nono::FsCapability> = None;
    let mut best_covering_score = 0usize;
    let mut best_sufficient_score = 0usize;

    for cap in caps.fs_capabilities() {
        let covers = if cap.is_file {
            cap.resolved == canonical
        } else {
            canonical.starts_with(&cap.resolved)
        };

        if !covers {
            continue;
        }

        let score = cap.resolved.as_os_str().len();
        if score >= best_covering_score {
            best_covering = Some(cap);
            best_covering_score = score;
        }

        let sufficient = matches!(
            (cap.access, requested),
            (AccessMode::ReadWrite, _)
                | (AccessMode::Read, AccessMode::Read)
                | (AccessMode::Write, AccessMode::Write)
        );

        if sufficient && score >= best_sufficient_score {
            best_sufficient = Some(cap);
            best_sufficient_score = score;
        }
    }

    if let Some(cap) = best_sufficient {
        return Ok(QueryResult::Allowed {
            reason: "granted_path".to_string(),
            granted_path: Some(cap.resolved.display().to_string()),
            access: Some(cap.access.to_string()),
        });
    }

    if let Some(cap) = best_covering {
        return Ok(QueryResult::Denied {
            reason: "insufficient_access".to_string(),
            details: Some(format!(
                "Path is covered by capability with {} access, but {} was requested",
                cap.access, requested
            )),
        });
    }

    Ok(QueryResult::Denied {
        reason: "path_not_granted".to_string(),
        details: Some("Path is not covered by any capability".to_string()),
    })
}

/// Query whether network access is permitted
pub fn query_network(host: &str, port: u16, caps: &CapabilitySet) -> QueryResult {
    if caps.is_network_blocked() {
        QueryResult::Denied {
            reason: "network_blocked".to_string(),
            details: Some(format!(
                "Network access is blocked. Connection to {}:{} would be denied.",
                host, port
            )),
        }
    } else {
        QueryResult::Allowed {
            reason: "network_allowed".to_string(),
            granted_path: None,
            access: Some(format!("Connection to {}:{} would be allowed", host, port)),
        }
    }
}

/// Print a query result in human-readable format
pub fn print_result(result: &QueryResult) {
    match result {
        QueryResult::Allowed {
            reason,
            granted_path,
            access,
        } => {
            println!("{}", "ALLOWED".green().bold());
            println!("  Reason: {}", reason);
            if let Some(path) = granted_path {
                println!("  Granted by: {}", path);
            }
            if let Some(acc) = access {
                println!("  Access: {}", acc);
            }
        }
        QueryResult::Denied { reason, details } => {
            println!("{}", "DENIED".red().bold());
            println!("  Reason: {}", reason);
            if let Some(d) = details {
                println!("  Details: {}", d);
            }
        }
        QueryResult::NotSandboxed { message } => {
            println!("{}", "NOT SANDBOXED".yellow().bold());
            println!("  {}", message);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nono::{CapabilitySource, FsCapability};
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn test_query_path_granted() {
        let dir = tempdir().expect("Failed to create temp dir");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: dir.path().to_path_buf(),
            resolved: dir.path().canonicalize().expect("Failed to canonicalize"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });

        let test_file = dir.path().join("test.txt");
        std::fs::write(&test_file, "test").expect("Failed to write test file");

        let result = query_path(&test_file, AccessMode::Read, &caps).expect("Query failed");
        assert!(matches!(result, QueryResult::Allowed { .. }));
    }

    #[test]
    fn test_query_path_denied() {
        let caps = CapabilitySet::new();
        let path = PathBuf::from("/some/random/path");

        let result = query_path(&path, AccessMode::Read, &caps).expect("Query failed");
        assert!(matches!(result, QueryResult::Denied { .. }));
    }

    #[test]
    fn test_query_path_prefers_more_specific_sufficient_capability() {
        let dir = tempdir().expect("Failed to create temp dir");
        let dir_canon = dir.path().canonicalize().expect("Failed to canonicalize");

        let mut caps = CapabilitySet::new();
        let parent = dir_canon
            .parent()
            .expect("tempdir has parent")
            .to_path_buf();

        // Broad read-only capability.
        caps.add_fs(FsCapability {
            original: parent.clone(),
            resolved: parent,
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::System,
        });

        // More specific read-write user capability.
        caps.add_fs(FsCapability {
            original: dir_canon.clone(),
            resolved: dir_canon.clone(),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });

        let test_file = dir_canon.join("test.txt");
        std::fs::write(&test_file, "test").expect("Failed to write test file");

        let result = query_path(&test_file, AccessMode::Write, &caps).expect("Query failed");
        assert!(matches!(result, QueryResult::Allowed { .. }));
    }

    #[test]
    fn test_query_network_allowed() {
        let caps = CapabilitySet::new(); // Network allowed by default
        let result = query_network("example.com", 443, &caps);
        assert!(matches!(result, QueryResult::Allowed { .. }));
    }

    #[test]
    fn test_query_network_blocked() {
        let caps = CapabilitySet::new().block_network();
        let result = query_network("example.com", 443, &caps);
        assert!(matches!(result, QueryResult::Denied { .. }));
    }
}
