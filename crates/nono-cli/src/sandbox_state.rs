//! Sandbox state persistence for `nono why --self`
//!
//! When nono runs a command, it writes the capability state to a temp file
//! and passes the path via NONO_CAP_FILE. This allows sandboxed processes
//! to query their own capabilities using `nono why --self`.

#[cfg(target_os = "macos")]
use crate::capability_ext::new_exact_path_capability;
use nono::{AccessMode, CapabilitySet, CapabilitySource, FsCapability, NonoError, Result};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::debug;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

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
    /// Paths exempted from deny groups via bypass_protection (canonicalized)
    /// ALIAS(canonical="bypass_protection_paths", introduced="v0.41.0", remove_by="v1.0.0", issue="#594")
    #[serde(default, alias = "override_deny_paths")]
    pub bypass_protection_paths: Vec<String>,
    /// Proxy domain allowlist at sandbox creation time
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// Endpoint-restricted domains with method+path rules
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_endpoints: Vec<DomainEndpointState>,
}

/// Serializable domain endpoint restriction state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainEndpointState {
    /// Domain hostname
    pub domain: String,
    /// Allowed method+path rules (default-deny when non-empty)
    pub endpoints: Vec<EndpointRuleState>,
}

/// Serializable endpoint rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointRuleState {
    /// HTTP method ("GET", "POST", "*", etc.)
    pub method: String,
    /// URL path glob pattern
    pub path: String,
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
    /// Capability source for diagnostics (`user`, `profile`, `group:<name>`, `system`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl SandboxState {
    /// Create sandbox state from a CapabilitySet, bypass_protection paths, and domain allowlist
    pub fn from_caps(
        caps: &CapabilitySet,
        bypass_protection_paths: &[PathBuf],
        allowed_domains: &[String],
        domain_endpoints: &[DomainEndpointState],
    ) -> Self {
        Self {
            fs: caps
                .fs_capabilities()
                .iter()
                .map(|c| FsCapState {
                    original: c.original.display().to_string(),
                    path: c.resolved.display().to_string(),
                    access: match c.access {
                        AccessMode::Read => "read".to_string(),
                        AccessMode::Write => "write".to_string(),
                        AccessMode::ReadWrite => "readwrite".to_string(),
                    },
                    is_file: c.is_file,
                    source: Some(c.source.to_string()),
                })
                .collect(),
            net_blocked: caps.is_network_blocked(),
            allowed_commands: caps.allowed_commands().to_vec(),
            blocked_commands: caps.blocked_commands().to_vec(),
            bypass_protection_paths: bypass_protection_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
            allowed_domains: allowed_domains.to_vec(),
            domain_endpoints: domain_endpoints.to_vec(),
        }
    }

    /// Get bypass_protection paths as PathBufs for query use
    pub fn bypass_protection_as_paths(&self) -> Vec<PathBuf> {
        self.bypass_protection_paths
            .iter()
            .map(PathBuf::from)
            .collect()
    }

    /// Convert back to a CapabilitySet
    ///
    /// Paths are re-validated through the standard constructors whenever
    /// possible. On macOS, exact-file grants for missing leaf paths are
    /// reconstructed with the same future-file logic used at profile load time.
    /// In all cases, the reconstructed canonical path must match the path
    /// serialized in the state file.
    ///
    /// Returns an error if a stored grant fails validation or if the current
    /// filesystem state no longer matches the serialized grant.
    pub fn to_caps(&self) -> Result<CapabilitySet> {
        let mut caps = CapabilitySet::new();

        for fs_cap in &self.fs {
            let access = parse_access_mode(&fs_cap.access)?;
            let source = parse_capability_source(fs_cap.source.as_deref())?;

            let cap = if fs_cap.is_file {
                restore_exact_path_capability(fs_cap, access, &source)?
            } else {
                restore_directory_capability(fs_cap, access, &source)?
            };
            caps.add_fs(cap);
        }

        if !self.allowed_domains.is_empty() {
            caps.set_network_mode_mut(nono::NetworkMode::ProxyOnly {
                port: 0,
                bind_ports: vec![],
            });
        } else {
            caps.set_network_blocked(self.net_blocked);
        }
        for cmd in &self.allowed_commands {
            caps.add_allowed_command(cmd.clone());
        }
        for cmd in &self.blocked_commands {
            caps.add_blocked_command(cmd.clone());
        }

        Ok(caps)
    }

    /// Write sandbox state to a file with secure permissions
    ///
    /// # Security
    /// This function implements multiple defenses against temp file attacks:
    /// - Uses `create_new(true)` to fail if file exists (prevents symlink attacks)
    /// - Sets `mode(0o600)` for owner-only read/write permissions (Unix)
    /// - Atomic write operation (no TOCTOU window)
    pub fn write_to_file(&self, path: &std::path::Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self).map_err(|e| {
            NonoError::ConfigParse(format!("Failed to serialize sandbox state: {}", e))
        })?;

        // SECURITY: Use OpenOptions with create_new(true) to prevent symlink attacks
        #[cfg(unix)]
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| NonoError::ConfigWrite {
                path: path.to_path_buf(),
                source: e,
            })?;

        #[cfg(not(unix))]
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(|e| NonoError::ConfigWrite {
                path: path.to_path_buf(),
                source: e,
            })?;

        file.write_all(json.as_bytes())
            .map_err(|e| NonoError::ConfigWrite {
                path: path.to_path_buf(),
                source: e,
            })?;

        Ok(())
    }
}

fn parse_access_mode(access: &str) -> Result<AccessMode> {
    match access {
        "read" => Ok(AccessMode::Read),
        "write" => Ok(AccessMode::Write),
        "readwrite" => Ok(AccessMode::ReadWrite),
        other => Err(NonoError::ConfigParse(format!(
            "invalid access mode in sandbox state: {other}"
        ))),
    }
}

fn parse_capability_source(source: Option<&str>) -> Result<CapabilitySource> {
    match source {
        None | Some("") | Some("user") => Ok(CapabilitySource::User),
        Some("profile") => Ok(CapabilitySource::Profile),
        Some("system") => Ok(CapabilitySource::System),
        Some(group) if let Some(name) = group.strip_prefix("group:") => {
            if name.is_empty() {
                return Err(NonoError::ConfigParse(
                    "invalid capability source in sandbox state: empty group name".to_string(),
                ));
            }
            Ok(CapabilitySource::Group(name.to_string()))
        }
        Some(other) => Err(NonoError::ConfigParse(format!(
            "invalid capability source in sandbox state: {other}"
        ))),
    }
}

fn validate_restored_path(fs_cap: &FsCapState, actual: &Path) -> Result<()> {
    let serialized = Path::new(&fs_cap.path);
    if actual != serialized {
        return Err(NonoError::ConfigParse(format!(
            "sandbox state path drifted at reload: serialized resolved={}, actual resolved={}",
            serialized.display(),
            actual.display(),
        )));
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn restore_exact_path_capability(
    fs_cap: &FsCapState,
    access: AccessMode,
    source: &CapabilitySource,
) -> Result<FsCapability> {
    let mut cap = new_exact_path_capability(Path::new(&fs_cap.original), access)?;
    validate_restored_path(fs_cap, &cap.resolved)?;
    cap.source = source.clone();
    Ok(cap)
}

#[cfg(not(target_os = "macos"))]
fn restore_exact_path_capability(
    fs_cap: &FsCapState,
    access: AccessMode,
    source: &CapabilitySource,
) -> Result<FsCapability> {
    let mut cap = FsCapability::new_file(&fs_cap.original, access)?;
    validate_restored_path(fs_cap, &cap.resolved)?;
    cap.source = source.clone();
    Ok(cap)
}

fn restore_directory_capability(
    fs_cap: &FsCapState,
    access: AccessMode,
    source: &CapabilitySource,
) -> Result<FsCapability> {
    let mut cap = FsCapability::new_dir(&fs_cap.original, access)?;
    validate_restored_path(fs_cap, &cap.resolved)?;
    cap.source = source.clone();
    Ok(cap)
}

/// Maximum size for capability state files (1 MB is more than enough)
const MAX_CAP_FILE_SIZE: u64 = 1_048_576;

/// Validate the NONO_CAP_FILE path for security
fn validate_cap_file_path(path_str: &str) -> Result<PathBuf> {
    let path = PathBuf::from(path_str);
    if !path.is_absolute() {
        return Err(NonoError::EnvVarValidation {
            var: "NONO_CAP_FILE".to_string(),
            reason: "path must be absolute".to_string(),
        });
    }

    let canonical = path
        .canonicalize()
        .map_err(|e| NonoError::CapFileValidation {
            reason: format!("failed to canonicalize path: {}", e),
        })?;

    // Must be in system temp directory
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

    // Must match expected naming pattern
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

    // File size must be reasonable
    let metadata = std::fs::metadata(&canonical).map_err(|e| NonoError::CapFileValidation {
        reason: format!("failed to read file metadata: {}", e),
    })?;

    if metadata.len() > MAX_CAP_FILE_SIZE {
        return Err(NonoError::CapFileTooLarge {
            size: metadata.len(),
            max: MAX_CAP_FILE_SIZE,
        });
    }

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
pub fn load_sandbox_state() -> Option<SandboxState> {
    let cap_file_str = std::env::var("NONO_CAP_FILE").ok()?;

    let validated_path = validate_cap_file_path(&cap_file_str).unwrap_or_else(|e| {
        eprintln!("SECURITY: NONO_CAP_FILE validation failed: {}", e);
        eprintln!("SECURITY: This may indicate an attack attempt or a bug in nono");
        std::process::exit(1);
    });

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

/// Check if a process with the given PID is currently running
#[cfg(unix)]
fn is_process_running(pid: u32) -> bool {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;

    let nix_pid = Pid::from_raw(pid as i32);
    match kill(nix_pid, None) {
        Ok(()) => true,
        Err(nix::errno::Errno::ESRCH) => false,
        Err(nix::errno::Errno::EPERM) => true,
        _ => true,
    }
}

#[cfg(not(unix))]
fn is_process_running(_pid: u32) -> bool {
    true
}

/// Clean up stale sandbox state files from previous nono runs
pub fn cleanup_stale_state_files() {
    let temp_dir = std::env::temp_dir();

    let entries = match std::fs::read_dir(&temp_dir) {
        Ok(entries) => entries,
        Err(e) => {
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
            None => continue,
        };

        if !file_name.starts_with(".nono-") || !file_name.ends_with(".json") {
            continue;
        }

        let pid_str = file_name
            .trim_start_matches(".nono-")
            .trim_end_matches(".json");

        let pid = match pid_str.parse::<u32>() {
            Ok(p) => p,
            Err(_) => {
                debug!("Skipping state file with invalid PID: {}", file_name);
                continue;
            }
        };

        if pid == current_pid {
            continue;
        }

        if is_process_running(pid) {
            skipped_count += 1;
            continue;
        }

        let file_path = temp_dir.join(&file_name);
        match std::fs::remove_file(&file_path) {
            Ok(()) => {
                debug!("Cleaned up stale state file for PID {}: {}", pid, file_name);
                cleaned_count += 1;
            }
            Err(e) => {
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
    use nono::CapabilitySource;
    use tempfile::tempdir;

    #[test]
    fn test_sandbox_state_roundtrip() {
        let mut caps = CapabilitySet::new().block_network();
        caps.add_allowed_command("pip".to_string());

        let state = SandboxState::from_caps(&caps, &[], &[], &[]);
        assert!(state.net_blocked);
        assert_eq!(state.allowed_commands, vec!["pip"]);

        let restored = state
            .to_caps()
            .expect("to_caps failed on network-only state");
        assert!(restored.is_network_blocked());
        assert_eq!(restored.allowed_commands(), vec!["pip"]);
    }

    #[test]
    fn test_sandbox_state_write_and_read() {
        let dir = tempdir().expect("Failed to create temp dir");
        let file_path = dir.path().join("test_state.json");

        let caps = CapabilitySet::new().block_network();

        let state = SandboxState::from_caps(&caps, &[], &[], &[]);
        state
            .write_to_file(&file_path)
            .expect("Failed to write state");

        let content = std::fs::read_to_string(&file_path).expect("Failed to read file");
        let loaded: SandboxState = serde_json::from_str(&content).expect("Failed to parse state");

        assert!(loaded.net_blocked);
    }

    #[test]
    fn test_sandbox_state_roundtrip_preserves_source() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("granted.txt");
        std::fs::write(&file_path, b"ok").expect("write test file");

        let mut cap = FsCapability::new_file(&file_path, AccessMode::Read).expect("create cap");
        cap.source = CapabilitySource::Group("system_read_macos".to_string());

        let mut caps = CapabilitySet::new();
        caps.add_fs(cap);

        let state = SandboxState::from_caps(&caps, &[], &[], &[]);
        let restored = state.to_caps().expect("restore caps");

        assert_eq!(restored.fs_capabilities().len(), 1);
        assert_eq!(
            restored.fs_capabilities()[0].source,
            CapabilitySource::Group("system_read_macos".to_string())
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_sandbox_state_restores_missing_future_file() {
        let dir = tempdir().expect("tempdir");
        let missing = dir.path().join("future.lock");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: missing.clone(),
            resolved: dir
                .path()
                .canonicalize()
                .expect("canonicalize dir")
                .join("future.lock"),
            access: AccessMode::ReadWrite,
            is_file: true,
            source: CapabilitySource::Profile,
        });

        let state = SandboxState::from_caps(&caps, &[], &[], &[]);
        let restored = state.to_caps().expect("restore future file cap");

        assert_eq!(restored.fs_capabilities().len(), 1);
        assert_eq!(restored.fs_capabilities()[0].original, missing);
        assert_eq!(restored.fs_capabilities()[0].access, AccessMode::ReadWrite);
        assert_eq!(
            restored.fs_capabilities()[0].source,
            CapabilitySource::Profile
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_sandbox_state_restores_exact_directory_literal_path() {
        let dir = tempdir().expect("tempdir");
        let lock_dir = dir.path().join("claude.lock");
        std::fs::create_dir_all(&lock_dir).expect("create lock dir");
        let child = lock_dir.join("child.txt");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: lock_dir.clone(),
            resolved: lock_dir.canonicalize().expect("canonicalize lock dir"),
            access: AccessMode::ReadWrite,
            is_file: true,
            source: CapabilitySource::Profile,
        });

        let state = SandboxState::from_caps(&caps, &[], &[], &[]);
        let restored = state.to_caps().expect("restore exact directory literal");

        assert_eq!(restored.fs_capabilities().len(), 1);
        assert_eq!(restored.fs_capabilities()[0].original, lock_dir);
        assert!(restored.fs_capabilities()[0].is_file);
        assert_eq!(
            restored.fs_capabilities()[0].source,
            CapabilitySource::Profile
        );
        assert!(
            !restored.path_covered(&child),
            "exact-path directory literal must not recursively cover descendants"
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_sandbox_state_rejects_drifted_future_file_path() {
        let dir = tempdir().expect("tempdir");
        let missing = dir.path().join("future.lock");

        let state = SandboxState {
            fs: vec![FsCapState {
                original: missing.display().to_string(),
                path: dir
                    .path()
                    .canonicalize()
                    .expect("canonicalize dir")
                    .join("other.lock")
                    .display()
                    .to_string(),
                access: "readwrite".to_string(),
                is_file: true,
                source: Some("profile".to_string()),
            }],
            net_blocked: false,
            allowed_commands: vec![],
            blocked_commands: vec![],
            bypass_protection_paths: vec![],
            allowed_domains: vec![],
            domain_endpoints: vec![],
        };

        let err = state
            .to_caps()
            .expect_err("drifted future file must be rejected");
        assert!(
            format!("{err}").contains("sandbox state path drifted"),
            "error should mention path drift"
        );
    }
}
