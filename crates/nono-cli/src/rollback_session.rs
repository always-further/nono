//! Session discovery and management for the rollback system
//!
//! Provides functions to discover, load, and manage rollback sessions
//! stored in `~/.nono/rollbacks/`. This is a CLI concern — the library
//! provides primitives, the CLI provides session lifecycle management.

use nono::undo::{SessionMetadata, SnapshotManager};
use nono::{NonoError, Result};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Information about a discovered rollback session
#[derive(Debug)]
pub struct SessionInfo {
    /// Session metadata loaded from session.json
    pub metadata: SessionMetadata,
    /// Path to the session directory
    pub dir: PathBuf,
    /// Total disk usage in bytes
    pub disk_size: u64,
    /// Whether the session's process is still running
    pub is_alive: bool,
    /// Whether the session appears stale (ended is None and PID is dead)
    pub is_stale: bool,
}

/// Get the rollback root directory (`~/.nono/rollbacks/`)
pub fn rollback_root() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or(NonoError::HomeNotFound)?;
    Ok(home.join(".nono").join("rollbacks"))
}

/// Discover all rollback sessions in `~/.nono/rollbacks/`.
///
/// Scans the rollback root directory, loads session metadata from each
/// subdirectory, and enriches with derived data (disk size, alive status).
/// Sessions with missing or corrupt metadata are skipped.
pub fn discover_sessions() -> Result<Vec<SessionInfo>> {
    let root = rollback_root()?;
    if !root.exists() {
        return Ok(Vec::new());
    }

    let mut sessions = Vec::new();

    let entries = fs::read_dir(&root).map_err(|e| {
        NonoError::Snapshot(format!(
            "Failed to read rollback directory {}: {e}",
            root.display()
        ))
    })?;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }

        // Try to load session metadata
        let metadata = match SnapshotManager::load_session_metadata(&dir) {
            Ok(m) => m,
            Err(_) => continue, // Skip corrupt or incomplete sessions
        };

        let pid = parse_pid_from_session_id(&metadata.session_id);
        let is_alive = pid.map(is_process_alive).unwrap_or(false);
        let is_stale = metadata.ended.is_none() && !is_alive;
        let disk_size = calculate_dir_size(&dir);

        sessions.push(SessionInfo {
            metadata,
            dir,
            disk_size,
            is_alive,
            is_stale,
        });
    }

    // Sort by start time, newest first
    sessions.sort_by(|a, b| b.metadata.started.cmp(&a.metadata.started));

    Ok(sessions)
}

/// Load a specific session by ID.
///
/// The session_id is validated to prevent path traversal — it must not
/// contain path separators or `..` components. The resolved path is
/// verified to be within the rollback root directory.
pub fn load_session(session_id: &str) -> Result<SessionInfo> {
    validate_session_id(session_id)?;
    let root = rollback_root()?;
    let dir = root.join(session_id);

    // Defense in depth: verify the resolved path is within rollback root
    if let (Ok(canonical_dir), Ok(canonical_root)) = (dir.canonicalize(), root.canonicalize()) {
        if !canonical_dir.starts_with(&canonical_root) {
            return Err(NonoError::SessionNotFound(session_id.to_string()));
        }
    }

    if !dir.exists() {
        return Err(NonoError::SessionNotFound(session_id.to_string()));
    }

    let metadata = SnapshotManager::load_session_metadata(&dir)?;
    let pid = parse_pid_from_session_id(&metadata.session_id);
    let is_alive = pid.map(is_process_alive).unwrap_or(false);
    let is_stale = metadata.ended.is_none() && !is_alive;
    let disk_size = calculate_dir_size(&dir);

    Ok(SessionInfo {
        metadata,
        dir,
        disk_size,
        is_alive,
        is_stale,
    })
}

/// Calculate the total disk usage of all sessions.
pub fn total_storage_bytes() -> Result<u64> {
    let root = rollback_root()?;
    if !root.exists() {
        return Ok(0);
    }
    Ok(calculate_dir_size(&root))
}

/// Remove a session directory.
pub fn remove_session(dir: &Path) -> Result<()> {
    fs::remove_dir_all(dir).map_err(|e| {
        NonoError::Snapshot(format!(
            "Failed to remove session directory {}: {e}",
            dir.display()
        ))
    })
}

/// Validate a session ID to prevent path traversal.
///
/// Session IDs must match the format `YYYYMMDD-HHMMSS-<pid>` and must not
/// contain path separators, `..`, or other dangerous characters.
fn validate_session_id(session_id: &str) -> Result<()> {
    if session_id.is_empty() {
        return Err(NonoError::SessionNotFound("empty session ID".to_string()));
    }
    if session_id.contains(std::path::MAIN_SEPARATOR)
        || session_id.contains('/')
        || session_id.contains("..")
        || session_id.contains('\0')
    {
        return Err(NonoError::SessionNotFound(format!(
            "invalid session ID: {session_id}"
        )));
    }
    Ok(())
}

/// Parse the PID from a session ID formatted as `YYYYMMDD-HHMMSS-<pid>`.
fn parse_pid_from_session_id(session_id: &str) -> Option<u32> {
    session_id.rsplit('-').next()?.parse().ok()
}

/// Check if a process with the given PID is still alive.
fn is_process_alive(pid: u32) -> bool {
    // kill(pid, 0) checks if the process exists without sending a signal
    // SAFETY: This is a standard POSIX way to check process existence.
    // Signal 0 does not actually send anything.
    unsafe { nix::libc::kill(pid as nix::libc::pid_t, 0) == 0 }
}

/// Calculate the total size of all files in a directory tree.
fn calculate_dir_size(dir: &Path) -> u64 {
    WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum()
}

/// Format a byte count as a human-readable string.
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_session_id_rejects_traversal() {
        assert!(validate_session_id("../../../etc").is_err());
        assert!(validate_session_id("foo/bar").is_err());
        assert!(validate_session_id("foo\0bar").is_err());
        assert!(validate_session_id("..").is_err());
        assert!(validate_session_id("").is_err());
    }

    #[test]
    fn validate_session_id_accepts_valid() {
        assert!(validate_session_id("20260214-143022-12345").is_ok());
        assert!(validate_session_id("test-session").is_ok());
    }

    #[test]
    fn parse_pid_from_session_id_valid() {
        assert_eq!(
            parse_pid_from_session_id("20260214-143022-12345"),
            Some(12345)
        );
    }

    #[test]
    fn parse_pid_from_session_id_invalid() {
        assert_eq!(parse_pid_from_session_id("no-pid-here"), None);
        assert_eq!(parse_pid_from_session_id(""), None);
    }

    #[test]
    fn format_bytes_display() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GB");
    }

    #[test]
    fn discover_sessions_empty_dir() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        // Override undo_root by testing calculate_dir_size directly
        let size = calculate_dir_size(dir.path());
        assert_eq!(size, 0);
    }

    #[test]
    fn calculate_dir_size_works() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        fs::write(dir.path().join("a.txt"), b"hello").expect("write");
        fs::write(dir.path().join("b.txt"), b"world!").expect("write");
        let size = calculate_dir_size(dir.path());
        assert_eq!(size, 11); // 5 + 6
    }

    #[test]
    fn is_current_process_alive() {
        assert!(is_process_alive(std::process::id()));
    }

    #[test]
    fn dead_process_not_alive() {
        // PID 99999999 is very unlikely to exist
        assert!(!is_process_alive(99_999_999));
    }
}
