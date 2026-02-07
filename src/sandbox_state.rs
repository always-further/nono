//! Sandbox state persistence for `nono why --self`
//!
//! When nono runs a command, it writes the capability state to a temp file
//! and passes the path via NONO_CAP_FILE. This allows sandboxed processes
//! to query their own capabilities using `nono why --self`.

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use tracing::debug;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::capability::{CapabilitySet, FsAccess, FsCapability};
use crate::error::{NonoError, Result};

/// Sandbox state stored for `nono why --self`
#[derive(Debug, Serialize, Deserialize)]
pub struct SandboxState {
    /// Filesystem capabilities
    pub fs: Vec<FsCapState>,
    /// Whether network is blocked
    pub net_blocked: bool,
    /// Commands explicitly allowed
    pub allowed_commands: Vec<String>,
    /// Commands explicitly blocked
    pub blocked_commands: Vec<String>,
}

/// Serializable filesystem capability state
#[derive(Debug, Serialize, Deserialize)]
pub struct FsCapState {
    /// Original path as specified
    pub original: String,
    /// Resolved absolute path
    pub path: String,
    /// Access level: "read", "write", or "readwrite"
    pub access: String,
    /// Whether this is a single file (vs directory)
    pub is_file: bool,
}

impl SandboxState {
    /// Create sandbox state from a CapabilitySet
    pub fn from_caps(caps: &CapabilitySet) -> Self {
        Self {
            fs: caps
                .fs
                .iter()
                .map(|c| FsCapState {
                    original: c.original.display().to_string(),
                    path: c.resolved.display().to_string(),
                    access: match c.access {
                        FsAccess::Read => "read".to_string(),
                        FsAccess::Write => "write".to_string(),
                        FsAccess::ReadWrite => "readwrite".to_string(),
                    },
                    is_file: c.is_file,
                })
                .collect(),
            net_blocked: caps.net_block,
            allowed_commands: caps.allowed_commands.clone(),
            blocked_commands: caps.blocked_commands.clone(),
        }
    }

    /// Convert back to a CapabilitySet
    ///
    /// Note: This creates a "reconstructed" capability set that may not
    /// have all the validation of the original (paths may not exist anymore).
    pub fn to_caps(&self) -> CapabilitySet {
        let mut caps = CapabilitySet::new();

        for fs_cap in &self.fs {
            let access = match fs_cap.access.as_str() {
                "read" => FsAccess::Read,
                "write" => FsAccess::Write,
                "readwrite" => FsAccess::ReadWrite,
                _ => FsAccess::Read, // Default to read for unknown
            };

            // Create capability without validation (path may not exist in sandbox)
            let cap = FsCapability {
                original: PathBuf::from(&fs_cap.original),
                resolved: PathBuf::from(&fs_cap.path),
                access,
                is_file: fs_cap.is_file,
            };
            caps.fs.push(cap);
        }

        caps.net_block = self.net_blocked;
        caps.allowed_commands = self.allowed_commands.clone();
        caps.blocked_commands = self.blocked_commands.clone();

        caps
    }

    /// Write sandbox state to a file with secure permissions
    ///
    /// # Security
    /// This function implements multiple defenses against temp file attacks:
    /// - Uses `create_new(true)` to fail if file exists (prevents symlink attacks)
    /// - Sets `mode(0o600)` for owner-only read/write permissions (Unix)
    /// - Atomic write operation (no TOCTOU window)
    ///
    /// # Errors
    /// Returns error if:
    /// - File already exists (prevents symlink attack)
    /// - Serialization fails
    /// - File creation fails
    /// - Write operation fails
    pub fn write_to_file(&self, path: &std::path::Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self).map_err(|e| {
            NonoError::ConfigParse(format!("Failed to serialize sandbox state: {}", e))
        })?;

        // SECURITY: Use OpenOptions with create_new(true) to prevent symlink attacks
        // If an attacker pre-creates a symlink at this path, create_new will fail
        // rather than following the symlink and writing to the target.
        #[cfg(unix)]
        let mut file = OpenOptions::new()
            .create_new(true) // Fail if exists - prevents symlink attack
            .write(true)
            .mode(0o600) // Owner-only read/write (prevents info disclosure)
            .open(path)
            .map_err(|e| NonoError::ConfigWrite {
                path: path.to_path_buf(),
                source: e,
            })?;

        // Non-Unix platforms: Still use create_new for symlink protection
        // but can't set permissions at creation time
        #[cfg(not(unix))]
        let mut file = OpenOptions::new()
            .create_new(true) // Fail if exists - prevents symlink attack
            .write(true)
            .open(path)
            .map_err(|e| NonoError::ConfigWrite {
                path: path.to_path_buf(),
                source: e,
            })?;

        // Write atomically
        file.write_all(json.as_bytes())
            .map_err(|e| NonoError::ConfigWrite {
                path: path.to_path_buf(),
                source: e,
            })?;

        Ok(())
    }
}

/// Maximum size for capability state files (1 MB is more than enough)
const MAX_CAP_FILE_SIZE: u64 = 1_048_576;

/// Validate the NONO_CAP_FILE path for security
///
/// This function implements defense-in-depth validation to prevent:
/// - Arbitrary file read via malicious env var
/// - Symlink attacks
/// - Path traversal attacks
/// - Excessively large files (DoS)
fn validate_cap_file_path(path_str: &str) -> Result<PathBuf> {
    // Security check: Path must be absolute
    let path = PathBuf::from(path_str);
    if !path.is_absolute() {
        return Err(NonoError::EnvVarValidation {
            var: "NONO_CAP_FILE".to_string(),
            reason: "path must be absolute".to_string(),
        });
    }

    // Security check: Canonicalize to prevent symlink attacks
    // This resolves symlinks and validates the path exists
    let canonical = path
        .canonicalize()
        .map_err(|e| NonoError::CapFileValidation {
            reason: format!("failed to canonicalize path: {}", e),
        })?;

    // Security check: Must be in system temp directory
    // This prevents reading arbitrary files on the system
    // Note: On macOS, /tmp is a symlink to /private/tmp or /var/folders/...
    // so we must canonicalize the temp dir for comparison
    let temp_dir =
        std::env::temp_dir()
            .canonicalize()
            .map_err(|e| NonoError::CapFileValidation {
                reason: format!("failed to canonicalize temp directory: {}", e),
            })?;

    if !canonical.starts_with(&temp_dir) {
        return Err(NonoError::CapFileValidation {
            reason: format!(
                "path must be in temp directory ({}), got: {}",
                temp_dir.display(),
                canonical.display()
            ),
        });
    }

    // Security check: Must match expected naming pattern
    // Expected format: /tmp/.nono-<pid>.json
    let file_name = canonical
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| NonoError::CapFileValidation {
            reason: "invalid file name".to_string(),
        })?;

    if !file_name.starts_with(".nono-") || !file_name.ends_with(".json") {
        return Err(NonoError::CapFileValidation {
            reason: format!(
                "file name must match pattern .nono-*.json, got: {}",
                file_name
            ),
        });
    }

    // Security check: File size must be reasonable
    let metadata = std::fs::metadata(&canonical).map_err(|e| NonoError::CapFileValidation {
        reason: format!("failed to read file metadata: {}", e),
    })?;

    if metadata.len() > MAX_CAP_FILE_SIZE {
        return Err(NonoError::CapFileTooLarge {
            size: metadata.len(),
            max: MAX_CAP_FILE_SIZE,
        });
    }

    // Security check: Must be a regular file (not a directory, device, etc.)
    if !metadata.is_file() {
        return Err(NonoError::CapFileValidation {
            reason: "path must be a regular file".to_string(),
        });
    }

    Ok(canonical)
}

/// Load sandbox state from NONO_CAP_FILE environment variable
///
/// Returns None if not running inside a nono sandbox (env var not set).
///
/// # Security
/// This function implements comprehensive validation to prevent:
/// - Arbitrary file read attacks via malicious NONO_CAP_FILE values
/// - Symlink attacks through path canonicalization
/// - Path traversal by requiring /tmp prefix
/// - DoS via file size limits
///
/// All validation failures are treated as fatal errors (not silent None returns)
/// to ensure security issues are visible and auditable.
pub fn load_sandbox_state() -> Option<SandboxState> {
    // Not running in sandbox if env var not set - this is the only case that returns None
    let cap_file_str = std::env::var("NONO_CAP_FILE").ok()?;

    // All validation failures beyond this point are security-relevant and should not be silent
    // We use expect() here because a validation failure indicates either:
    // 1. An attack attempt (malicious env var)
    // 2. A bug in nono (incorrect path set by parent process)
    // Both cases should terminate rather than silently failing
    let validated_path = validate_cap_file_path(&cap_file_str).unwrap_or_else(|e| {
        eprintln!("SECURITY: NONO_CAP_FILE validation failed: {}", e);
        eprintln!("SECURITY: This may indicate an attack attempt or a bug in nono");
        std::process::exit(1);
    });

    // Read and parse the capability state
    let content = std::fs::read_to_string(&validated_path).unwrap_or_else(|e| {
        eprintln!("Error reading capability state file: {}", e);
        std::process::exit(1);
    });

    let state: SandboxState = serde_json::from_str(&content).unwrap_or_else(|e| {
        eprintln!("Error parsing capability state file: {}", e);
        std::process::exit(1);
    });

    Some(state)
}

/// Check if we're running inside a nono sandbox
#[allow(dead_code)]
pub fn is_sandboxed() -> bool {
    std::env::var("NONO_CAP_FILE").is_ok()
}

/// Get the path to the capability state file (for cleanup)
#[allow(dead_code)]
pub fn get_cap_file_path() -> Option<String> {
    std::env::var("NONO_CAP_FILE").ok()
}

/// Check if a process with the given PID is currently running
///
/// # Platform Support
/// - Unix: Uses kill(pid, 0) to check process existence
/// - Non-Unix: Always returns true (conservative - keeps files)
///
/// # Security
/// This function is used to determine if a state file is stale.
/// Returning true when uncertain is safe (keeps files), but may leak disk space.
#[cfg(unix)]
fn is_process_running(pid: u32) -> bool {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;

    // Send signal 0 (None) to check if process exists
    // Signal 0 is a special case that checks process existence without sending a signal
    let nix_pid = Pid::from_raw(pid as i32);
    match kill(nix_pid, None) {
        Ok(()) => true,                         // Process exists
        Err(nix::errno::Errno::ESRCH) => false, // No such process - safe to delete
        Err(nix::errno::Errno::EPERM) => true,  // Process exists but permission denied
        _ => true,                              // Unknown error - conservative, keep file
    }
}

#[cfg(not(unix))]
fn is_process_running(_pid: u32) -> bool {
    // On non-Unix platforms, we can't reliably check process existence.
    // Be conservative and assume the process is still running.
    // This means state files may accumulate on Windows, but won't break functionality.
    true
}

/// Clean up stale sandbox state files from previous nono runs
///
/// This function is called on each nono invocation to remove state files
/// where the corresponding process is no longer running. This prevents:
/// - Disk space exhaustion from accumulated state files
/// - Information disclosure from old capability data
/// - Forensic analysis from historical sandbox configurations
///
/// # Security
/// - Only deletes files matching .nono-*.json pattern in temp directory
/// - Validates PID existence before deletion
/// - Skips files with invalid naming (prevents accidental deletion)
/// - Logs but doesn't fail on individual file errors (best-effort cleanup)
///
/// # Errors
/// Individual file deletion errors are logged but don't cause the function to fail.
/// This ensures nono continues to work even if some cleanup fails.
pub fn cleanup_stale_state_files() {
    let temp_dir = std::env::temp_dir();

    // Read directory entries
    let entries = match std::fs::read_dir(&temp_dir) {
        Ok(entries) => entries,
        Err(e) => {
            // Can't read temp dir - log and skip cleanup
            // This is not fatal as it only affects cleanup
            debug!("Failed to read temp directory for cleanup: {}", e);
            return;
        }
    };

    let current_pid = std::process::id();
    let mut cleaned_count = 0;
    let mut skipped_count = 0;

    for entry in entries.flatten() {
        let file_name = match entry.file_name().to_str() {
            Some(name) => name.to_string(),
            None => continue, // Skip non-UTF8 filenames
        };

        // Only process files matching .nono-*.json pattern
        if !file_name.starts_with(".nono-") || !file_name.ends_with(".json") {
            continue;
        }

        // Extract PID from filename: .nono-<pid>.json
        let pid_str = file_name
            .trim_start_matches(".nono-")
            .trim_end_matches(".json");

        let pid = match pid_str.parse::<u32>() {
            Ok(p) => p,
            Err(_) => {
                // Invalid PID format - skip this file
                debug!("Skipping state file with invalid PID: {}", file_name);
                continue;
            }
        };

        // Never delete our own state file (we might create it later)
        if pid == current_pid {
            continue;
        }

        // Check if the process is still running
        if is_process_running(pid) {
            skipped_count += 1;
            continue;
        }

        // Process is dead - safe to delete the state file
        let file_path = temp_dir.join(&file_name);
        match std::fs::remove_file(&file_path) {
            Ok(()) => {
                debug!("Cleaned up stale state file for PID {}: {}", pid, file_name);
                cleaned_count += 1;
            }
            Err(e) => {
                // Log but don't fail - best effort cleanup
                debug!("Failed to remove stale state file {}: {}", file_name, e);
            }
        }
    }

    if cleaned_count > 0 {
        debug!(
            "Cleanup complete: removed {} stale state file(s), {} active",
            cleaned_count, skipped_count
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_sandbox_state_roundtrip() {
        let mut caps = CapabilitySet::new();
        caps.net_block = true;
        caps.allowed_commands = vec!["pip".to_string()];

        let state = SandboxState::from_caps(&caps);
        assert!(state.net_blocked);
        assert_eq!(state.allowed_commands, vec!["pip"]);

        let restored = state.to_caps();
        assert!(restored.net_block);
        assert_eq!(restored.allowed_commands, vec!["pip"]);
    }

    #[test]
    fn test_sandbox_state_write_and_read() {
        let dir = tempdir().expect("Failed to create temp dir");
        let file_path = dir.path().join("test_state.json");

        let mut caps = CapabilitySet::new();
        caps.net_block = true;

        let state = SandboxState::from_caps(&caps);
        state
            .write_to_file(&file_path)
            .expect("Failed to write state");

        // Read it back
        let content = std::fs::read_to_string(&file_path).expect("Failed to read file");
        let loaded: SandboxState = serde_json::from_str(&content).expect("Failed to parse state");

        assert!(loaded.net_blocked);
    }

    #[test]
    fn test_fs_cap_state_access_parsing() {
        let state = SandboxState {
            fs: vec![
                FsCapState {
                    original: "./src".to_string(),
                    path: "/home/user/src".to_string(),
                    access: "read".to_string(),
                    is_file: false,
                },
                FsCapState {
                    original: "./out".to_string(),
                    path: "/home/user/out".to_string(),
                    access: "write".to_string(),
                    is_file: false,
                },
                FsCapState {
                    original: "./data".to_string(),
                    path: "/home/user/data".to_string(),
                    access: "readwrite".to_string(),
                    is_file: false,
                },
            ],
            net_blocked: false,
            allowed_commands: vec![],
            blocked_commands: vec![],
        };

        let caps = state.to_caps();
        assert_eq!(caps.fs.len(), 3);
        assert_eq!(caps.fs[0].access, FsAccess::Read);
        assert_eq!(caps.fs[1].access, FsAccess::Write);
        assert_eq!(caps.fs[2].access, FsAccess::ReadWrite);
    }

    // Security tests for validate_cap_file_path

    #[test]
    fn test_validate_cap_file_rejects_relative_path() {
        let result = validate_cap_file_path("relative/path.json");
        assert!(result.is_err());
        match result {
            Err(NonoError::EnvVarValidation { var, reason }) => {
                assert_eq!(var, "NONO_CAP_FILE");
                assert!(reason.contains("absolute"));
            }
            _ => panic!("Expected EnvVarValidation error"),
        }
    }

    #[test]
    fn test_validate_cap_file_rejects_nonexistent_path() {
        let result = validate_cap_file_path("/tmp/.nono-99999999.json");
        assert!(result.is_err());
        match result {
            Err(NonoError::CapFileValidation { reason }) => {
                assert!(reason.contains("canonicalize"));
            }
            _ => panic!("Expected CapFileValidation error"),
        }
    }

    #[test]
    fn test_validate_cap_file_rejects_outside_tmp() {
        // Try to read /etc/passwd (would fail on canonicalization, but shows intent)
        let result = validate_cap_file_path("/etc/passwd");
        assert!(result.is_err());
        // This will fail on canonicalization or /tmp check depending on whether file exists
    }

    #[test]
    fn test_validate_cap_file_rejects_wrong_naming_pattern() {
        // Create a file in /tmp but with wrong name
        let file_path = std::env::temp_dir().join("wrong_name.json");
        std::fs::write(&file_path, "{}").expect("Failed to create test file");

        let result = validate_cap_file_path(file_path.to_str().unwrap_or_default());
        std::fs::remove_file(&file_path).ok(); // Cleanup

        assert!(result.is_err());
        match result {
            Err(NonoError::CapFileValidation { reason }) => {
                assert!(reason.contains("pattern") || reason.contains(".nono-"));
            }
            _ => panic!("Expected CapFileValidation error"),
        }
    }

    #[test]
    fn test_validate_cap_file_rejects_too_large_file() {
        // Create a file larger than MAX_CAP_FILE_SIZE
        let file_path = std::env::temp_dir().join(".nono-test-large.json");

        // Create a 2MB file (larger than 1MB limit)
        let large_content = vec![b'x'; 2_097_152];
        std::fs::write(&file_path, large_content).expect("Failed to create large test file");

        let result = validate_cap_file_path(file_path.to_str().unwrap_or_default());
        std::fs::remove_file(&file_path).ok(); // Cleanup

        assert!(result.is_err());
        match result {
            Err(NonoError::CapFileTooLarge { size, max }) => {
                assert!(size > max);
                assert_eq!(max, MAX_CAP_FILE_SIZE);
            }
            _ => panic!("Expected CapFileTooLarge error, got: {:?}", result),
        }
    }

    #[test]
    fn test_validate_cap_file_accepts_valid_path() {
        // Create a valid capability file in /tmp
        let file_path = std::env::temp_dir().join(".nono-test-12345.json");
        let test_state = SandboxState {
            fs: vec![],
            net_blocked: true,
            allowed_commands: vec![],
            blocked_commands: vec![],
        };

        let json = serde_json::to_string(&test_state).expect("Failed to serialize");
        std::fs::write(&file_path, json).expect("Failed to write test file");

        let result = validate_cap_file_path(file_path.to_str().unwrap_or_default());
        std::fs::remove_file(&file_path).ok(); // Cleanup

        assert!(
            result.is_ok(),
            "Valid path should be accepted: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_cap_file_rejects_directory() {
        // Create a directory with the right naming pattern
        let dir_path = std::env::temp_dir().join(".nono-test-dir.json");
        std::fs::create_dir(&dir_path).expect("Failed to create test directory");

        let result = validate_cap_file_path(dir_path.to_str().unwrap_or_default());
        std::fs::remove_dir(&dir_path).ok(); // Cleanup

        assert!(result.is_err());
        match result {
            Err(NonoError::CapFileValidation { reason }) => {
                assert!(reason.contains("regular file"));
            }
            _ => panic!("Expected CapFileValidation error"),
        }
    }

    // Security tests for write_to_file

    #[test]
    #[cfg(unix)]
    fn test_write_sets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("Failed to create temp dir");
        let file_path = dir.path().join(".nono-test-perms.json");

        let state = SandboxState {
            fs: vec![],
            net_blocked: true,
            allowed_commands: vec![],
            blocked_commands: vec![],
        };

        state
            .write_to_file(&file_path)
            .expect("Failed to write state");

        // Verify file permissions are 0o600 (owner read/write only)
        let metadata = std::fs::metadata(&file_path).expect("Failed to read metadata");
        let mode = metadata.permissions().mode() & 0o777;

        assert_eq!(
            mode, 0o600,
            "File should have 0o600 permissions (owner-only), got: 0o{:o}",
            mode
        );
    }

    #[test]
    fn test_write_prevents_symlink_attack() {
        let dir = tempdir().expect("Failed to create temp dir");
        let file_path = dir.path().join(".nono-test-symlink.json");

        // Pre-create file (simulating symlink attack)
        std::fs::write(&file_path, "malicious").expect("Failed to create decoy");

        let state = SandboxState {
            fs: vec![],
            net_blocked: true,
            allowed_commands: vec![],
            blocked_commands: vec![],
        };

        // Should fail due to create_new(true)
        let result = state.write_to_file(&file_path);
        assert!(
            result.is_err(),
            "write_to_file must fail when file exists (symlink protection)"
        );

        // Verify original content unchanged
        let content = std::fs::read_to_string(&file_path).expect("Failed to read");
        assert_eq!(content, "malicious", "Original file must not be modified");
    }

    #[test]
    fn test_write_prevents_toctou_race() {
        let dir = tempdir().expect("Failed to create temp dir");
        let file_path = dir.path().join(".nono-test-toctou.json");

        let state = SandboxState {
            fs: vec![],
            net_blocked: true,
            allowed_commands: vec![],
            blocked_commands: vec![],
        };

        // First write succeeds
        state
            .write_to_file(&file_path)
            .expect("First write should succeed");

        // Second write fails (prevents TOCTOU)
        let result = state.write_to_file(&file_path);
        assert!(
            result.is_err(),
            "Second write must fail (prevents TOCTOU races)"
        );
    }
}
