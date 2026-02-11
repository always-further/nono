use crate::cli::SandboxArgs;
use crate::error::{NonoError, Result};
use crate::profile::{self, Profile};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Filesystem access mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsAccess {
    /// Read-only access
    Read,
    /// Write-only access
    Write,
    /// Read and write access
    ReadWrite,
}

impl std::fmt::Display for FsAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FsAccess::Read => write!(f, "read"),
            FsAccess::Write => write!(f, "write"),
            FsAccess::ReadWrite => write!(f, "read+write"),
        }
    }
}

/// A filesystem capability - grants access to a specific path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsCapability {
    /// The original path as specified by the user
    pub original: PathBuf,
    /// The canonicalized absolute path
    pub resolved: PathBuf,
    /// The access mode granted
    pub access: FsAccess,
    /// True if this is a single file, false if directory (recursive)
    pub is_file: bool,
}

impl FsCapability {
    /// Create a new directory capability, canonicalizing the path
    pub fn new_dir(path: PathBuf, access: FsAccess) -> Result<Self> {
        // Check path exists
        if !path.exists() {
            return Err(NonoError::PathNotFound(path));
        }

        // Verify it's a directory
        if !path.is_dir() {
            return Err(NonoError::ExpectedDirectory(path));
        }

        // Canonicalize to absolute path, resolving symlinks
        let resolved = path
            .canonicalize()
            .map_err(|e| NonoError::PathCanonicalization {
                path: path.clone(),
                source: e,
            })?;

        Ok(Self {
            original: path,
            resolved,
            access,
            is_file: false,
        })
    }

    /// Create a new single file capability, canonicalizing the path.
    ///
    /// Accepts any non-directory filesystem entry: regular files, Unix domain
    /// sockets, FIFOs, and device files. The file-vs-directory distinction is
    /// what matters for sandbox rule generation (`literal` vs `subpath`), not
    /// the specific file type.
    pub fn new_file(path: PathBuf, access: FsAccess) -> Result<Self> {
        // Check path exists
        if !path.exists() {
            return Err(NonoError::PathNotFound(path));
        }

        // Reject directories — they need recursive subpath rules (use new_dir)
        if path.is_dir() {
            return Err(NonoError::ExpectedFile(path));
        }

        // Canonicalize to absolute path, resolving symlinks
        let resolved = path
            .canonicalize()
            .map_err(|e| NonoError::PathCanonicalization {
                path: path.clone(),
                source: e,
            })?;

        Ok(Self {
            original: path,
            resolved,
            access,
            is_file: true,
        })
    }
}

impl FsCapability {
    /// Human-readable label for the filesystem entry type.
    ///
    /// Inspects the resolved path to distinguish regular files, sockets,
    /// FIFOs, etc. Falls back to "file" if the type cannot be determined.
    pub fn kind_label(&self) -> &'static str {
        if !self.is_file {
            return "dir";
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            if let Ok(meta) = std::fs::metadata(&self.resolved) {
                let ft = meta.file_type();
                if ft.is_socket() {
                    return "socket";
                }
                if ft.is_fifo() {
                    return "fifo";
                }
                if ft.is_block_device() || ft.is_char_device() {
                    return "device";
                }
            }
        }
        "file"
    }
}

impl std::fmt::Display for FsCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.resolved.display(), self.access)
    }
}

/// The complete set of capabilities granted to the sandbox
#[derive(Debug, Clone, Default)]
pub struct CapabilitySet {
    /// Filesystem capabilities
    pub fs: Vec<FsCapability>,
    /// Network access blocked (network allowed by default; true = blocked)
    pub net_block: bool,
    /// Commands explicitly allowed (overrides default blocklist)
    pub allowed_commands: Vec<String>,
    /// Additional commands to block (extends default blocklist)
    pub blocked_commands: Vec<String>,
}

impl CapabilitySet {
    /// Create a new empty capability set
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a filesystem capability
    pub fn add_fs(&mut self, cap: FsCapability) {
        self.fs.push(cap);
    }

    /// Deduplicate filesystem capabilities by resolved path
    /// For duplicates, keeps the highest access level (ReadWrite > Read/Write)
    pub fn deduplicate(&mut self) {
        use std::collections::HashMap;

        // Group by (resolved path, is_file)
        let mut seen: HashMap<(PathBuf, bool), usize> = HashMap::new();
        let mut to_remove = Vec::new();

        for (i, cap) in self.fs.iter().enumerate() {
            let key = (cap.resolved.clone(), cap.is_file);
            if let Some(&existing_idx) = seen.get(&key) {
                // Duplicate found - decide which to keep
                let existing = &self.fs[existing_idx];
                if cap.access == FsAccess::ReadWrite && existing.access != FsAccess::ReadWrite {
                    // New one has higher access, remove old
                    to_remove.push(existing_idx);
                    seen.insert(key, i);
                } else {
                    // Keep existing, remove new
                    to_remove.push(i);
                }
            } else {
                seen.insert(key, i);
            }
        }

        // Remove duplicates in reverse order to maintain indices
        to_remove.sort_unstable();
        to_remove.reverse();
        for idx in to_remove {
            self.fs.remove(idx);
        }
    }

    /// Check if this set has any filesystem capabilities
    pub fn has_fs(&self) -> bool {
        !self.fs.is_empty()
    }

    /// Check if the given path is already covered by an existing directory capability.
    ///
    /// Uses component-wise Path::starts_with() to prevent path traversal issues
    /// (e.g., "/home" must not match "/homeevil").
    pub fn path_covered(&self, path: &Path) -> bool {
        self.fs
            .iter()
            .any(|cap| !cap.is_file && path.starts_with(&cap.resolved))
    }

    /// Build capabilities from CLI arguments
    pub fn from_args(args: &SandboxArgs) -> Result<Self> {
        let mut caps = Self::new();

        // Process directory permissions
        for path in &args.allow {
            let cap = FsCapability::new_dir(path.clone(), FsAccess::ReadWrite)?;
            caps.add_fs(cap);
        }

        for path in &args.read {
            let cap = FsCapability::new_dir(path.clone(), FsAccess::Read)?;
            caps.add_fs(cap);
        }

        for path in &args.write {
            let cap = FsCapability::new_dir(path.clone(), FsAccess::Write)?;
            caps.add_fs(cap);
        }

        // Process file permissions
        for path in &args.allow_file {
            let cap = FsCapability::new_file(path.clone(), FsAccess::ReadWrite)?;
            caps.add_fs(cap);
        }

        for path in &args.read_file {
            let cap = FsCapability::new_file(path.clone(), FsAccess::Read)?;
            caps.add_fs(cap);
        }

        for path in &args.write_file {
            let cap = FsCapability::new_file(path.clone(), FsAccess::Write)?;
            caps.add_fs(cap);
        }

        // Process --net-block flag
        caps.net_block = args.net_block;

        // Process command allow/block lists
        caps.allowed_commands = args.allow_command.clone();
        caps.blocked_commands = args.block_command.clone();

        caps.deduplicate();
        Ok(caps)
    }

    /// Build capabilities from a profile, with CLI overrides
    pub fn from_profile(profile: &Profile, workdir: &Path, args: &SandboxArgs) -> Result<Self> {
        let mut caps = Self::new();

        // Helper to process profile paths and add capabilities
        fn process_profile_paths(
            caps: &mut CapabilitySet,
            paths: &[String],
            workdir: &Path,
            access: FsAccess,
            is_file: bool,
        ) -> Result<()> {
            for path_str in paths {
                let path = profile::expand_vars(path_str, workdir);
                if is_file {
                    if path.exists() && !path.is_dir() {
                        caps.add_fs(FsCapability::new_file(path, access)?);
                    } else if path.exists() {
                        tracing::warn!(
                            "Profile path '{}' exists but is a directory, skipping (use allow/read/write for directories)",
                            path.display()
                        );
                    } else {
                        tracing::warn!("Profile path '{}' not found, skipping", path.display());
                    }
                } else if path.exists() && path.is_dir() {
                    caps.add_fs(FsCapability::new_dir(path, access)?);
                } else if path.exists() {
                    tracing::warn!(
                        "Profile path '{}' exists but is not a directory, skipping",
                        path.display()
                    );
                } else {
                    tracing::warn!("Profile path '{}' not found, skipping", path.display());
                }
            }
            Ok(())
        }

        // Process profile directory permissions
        process_profile_paths(
            &mut caps,
            &profile.filesystem.allow,
            workdir,
            FsAccess::ReadWrite,
            false,
        )?;
        process_profile_paths(
            &mut caps,
            &profile.filesystem.read,
            workdir,
            FsAccess::Read,
            false,
        )?;
        process_profile_paths(
            &mut caps,
            &profile.filesystem.write,
            workdir,
            FsAccess::Write,
            false,
        )?;

        // Process profile file permissions
        process_profile_paths(
            &mut caps,
            &profile.filesystem.allow_file,
            workdir,
            FsAccess::ReadWrite,
            true,
        )?;
        process_profile_paths(
            &mut caps,
            &profile.filesystem.read_file,
            workdir,
            FsAccess::Read,
            true,
        )?;
        process_profile_paths(
            &mut caps,
            &profile.filesystem.write_file,
            workdir,
            FsAccess::Write,
            true,
        )?;

        // Merge CLI overrides (extend the profile)
        for path in &args.allow {
            let cap = FsCapability::new_dir(path.clone(), FsAccess::ReadWrite)?;
            caps.add_fs(cap);
        }

        for path in &args.read {
            let cap = FsCapability::new_dir(path.clone(), FsAccess::Read)?;
            caps.add_fs(cap);
        }

        for path in &args.write {
            let cap = FsCapability::new_dir(path.clone(), FsAccess::Write)?;
            caps.add_fs(cap);
        }

        for path in &args.allow_file {
            let cap = FsCapability::new_file(path.clone(), FsAccess::ReadWrite)?;
            caps.add_fs(cap);
        }

        for path in &args.read_file {
            let cap = FsCapability::new_file(path.clone(), FsAccess::Read)?;
            caps.add_fs(cap);
        }

        for path in &args.write_file {
            let cap = FsCapability::new_file(path.clone(), FsAccess::Write)?;
            caps.add_fs(cap);
        }

        // Network: profile OR CLI flag can block network (network allowed by default)
        caps.net_block = profile.network.block || args.net_block;

        // Process command allow/block lists from CLI
        // Profile support for commands will be added later
        caps.allowed_commands = args.allow_command.clone();
        caps.blocked_commands = args.block_command.clone();

        caps.deduplicate();
        Ok(caps)
    }

    /// Display a summary of capabilities (plain text, for programmatic use)
    #[allow(dead_code)]
    pub fn summary(&self) -> String {
        let mut lines = Vec::new();

        if !self.fs.is_empty() {
            lines.push("Filesystem:".to_string());
            for cap in &self.fs {
                let kind = if cap.is_file { "file" } else { "dir" };
                lines.push(format!(
                    "  {} [{}] ({})",
                    cap.resolved.display(),
                    cap.access,
                    kind
                ));
            }
        }

        lines.push("Network:".to_string());
        if self.net_block {
            lines.push("  outbound: blocked".to_string());
        } else {
            lines.push("  outbound: allowed".to_string());
        }

        if lines.is_empty() {
            lines.push("(no capabilities granted)".to_string());
        }

        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_fs_capability_new_dir() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_path_buf();

        let cap = FsCapability::new_dir(path.clone(), FsAccess::Read).unwrap();
        assert_eq!(cap.access, FsAccess::Read);
        assert!(cap.resolved.is_absolute());
        assert!(!cap.is_file);
    }

    #[test]
    fn test_fs_capability_new_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "test").unwrap();

        let cap = FsCapability::new_file(file_path.clone(), FsAccess::Read).unwrap();
        assert_eq!(cap.access, FsAccess::Read);
        assert!(cap.resolved.is_absolute());
        assert!(cap.is_file);
    }

    #[test]
    fn test_fs_capability_nonexistent() {
        let result = FsCapability::new_dir("/nonexistent/path/12345".into(), FsAccess::Read);
        assert!(matches!(result, Err(NonoError::PathNotFound(_))));
    }

    #[test]
    fn test_fs_capability_file_as_dir_error() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "test").unwrap();

        let result = FsCapability::new_dir(file_path, FsAccess::Read);
        assert!(matches!(result, Err(NonoError::ExpectedDirectory(_))));
    }

    #[test]
    fn test_fs_capability_dir_as_file_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_path_buf();

        let result = FsCapability::new_file(path, FsAccess::Read);
        assert!(matches!(result, Err(NonoError::ExpectedFile(_))));
    }

    #[cfg(unix)]
    #[test]
    fn test_fs_capability_unix_socket() {
        use std::os::unix::net::UnixListener;

        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("test.sock");

        // Create a Unix domain socket
        let _listener = UnixListener::bind(&socket_path).unwrap();

        // Sockets are not regular files but new_file should accept them
        assert!(!socket_path.is_file(), "socket should not be is_file()");
        assert!(socket_path.exists(), "socket should exist");

        let cap = FsCapability::new_file(socket_path.clone(), FsAccess::Read).unwrap();
        assert!(cap.is_file); // generates literal rule, not subpath
        assert!(cap.resolved.is_absolute());
        assert_eq!(cap.access, FsAccess::Read);
    }

    #[test]
    fn test_fs_capability_symlink_resolution() {
        let dir = tempdir().unwrap();
        let real_dir = dir.path().join("real");
        let symlink = dir.path().join("link");

        fs::create_dir(&real_dir).unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_dir, &symlink).unwrap();

        #[cfg(unix)]
        {
            let cap = FsCapability::new_dir(symlink, FsAccess::Read).unwrap();
            // Symlink should be resolved to real path
            assert_eq!(cap.resolved, real_dir.canonicalize().unwrap());
        }
    }

    #[test]
    fn test_capability_set_from_args() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_path_buf();

        let args = SandboxArgs {
            allow: vec![path.clone()],
            read: vec![],
            write: vec![],
            allow_file: vec![],
            read_file: vec![],
            write_file: vec![],
            net_block: false,
            allow_command: vec![],
            block_command: vec![],
            secrets: None,
            profile: None,
            allow_cwd: false,
            workdir: None,
            trust_unsigned: false,
            config: None,
            verbose: 0,
            dry_run: false,
        };

        let caps = CapabilitySet::from_args(&args).unwrap();
        assert_eq!(caps.fs.len(), 1);
        assert!(!caps.fs[0].is_file);
        assert!(!caps.net_block); // network allowed by default
    }

    #[test]
    fn test_capability_set_with_files() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "test").unwrap();

        let args = SandboxArgs {
            allow: vec![dir.path().to_path_buf()],
            read: vec![],
            write: vec![],
            allow_file: vec![],
            read_file: vec![],
            write_file: vec![file_path],
            net_block: false,
            allow_command: vec![],
            block_command: vec![],
            secrets: None,
            profile: None,
            allow_cwd: false,
            workdir: None,
            trust_unsigned: false,
            config: None,
            verbose: 0,
            dry_run: false,
        };

        let caps = CapabilitySet::from_args(&args).unwrap();
        assert_eq!(caps.fs.len(), 2);
        // First is directory
        assert!(!caps.fs[0].is_file);
        // Second is file
        assert!(caps.fs[1].is_file);
    }

    #[test]
    fn test_capability_set_network_blocked() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_path_buf();

        let args = SandboxArgs {
            allow: vec![path.clone()],
            read: vec![],
            write: vec![],
            allow_file: vec![],
            read_file: vec![],
            write_file: vec![],
            net_block: true,
            allow_command: vec![],
            block_command: vec![],
            secrets: None,
            profile: None,
            allow_cwd: false,
            workdir: None,
            trust_unsigned: false,
            config: None,
            verbose: 0,
            dry_run: false,
        };

        let caps = CapabilitySet::from_args(&args).unwrap();
        assert!(caps.net_block);
    }
}
