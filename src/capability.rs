use crate::cli::Args;
use crate::error::{NonoError, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
        let resolved = path.canonicalize().map_err(|e| NonoError::PathCanonicalization {
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

    /// Create a new single file capability, canonicalizing the path
    pub fn new_file(path: PathBuf, access: FsAccess) -> Result<Self> {
        // Check path exists
        if !path.exists() {
            return Err(NonoError::PathNotFound(path));
        }

        // Verify it's a file
        if !path.is_file() {
            return Err(NonoError::ExpectedFile(path));
        }

        // Canonicalize to absolute path, resolving symlinks
        let resolved = path.canonicalize().map_err(|e| NonoError::PathCanonicalization {
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
    /// Network access allowed (binary: all outbound or none)
    pub net_allow: bool,
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

    /// Check if this set has any filesystem capabilities
    pub fn has_fs(&self) -> bool {
        !self.fs.is_empty()
    }

    /// Build capabilities from CLI arguments
    pub fn from_args(args: &Args) -> Result<Self> {
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

        // Process --net-allow flag
        caps.net_allow = args.net_allow;

        Ok(caps)
    }

    /// Display a summary of capabilities
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
        if self.net_allow {
            lines.push("  outbound: allowed".to_string());
        } else {
            lines.push("  outbound: blocked".to_string());
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

        let args = Args {
            allow: vec![path.clone()],
            read: vec![],
            write: vec![],
            allow_file: vec![],
            read_file: vec![],
            write_file: vec![],
            net_allow: true,
            config: None,
            verbose: 0,
            dry_run: false,
            command: vec!["echo".to_string()],
        };

        let caps = CapabilitySet::from_args(&args).unwrap();
        assert_eq!(caps.fs.len(), 1);
        assert!(!caps.fs[0].is_file);
        assert!(caps.net_allow);
    }

    #[test]
    fn test_capability_set_with_files() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "test").unwrap();

        let args = Args {
            allow: vec![dir.path().to_path_buf()],
            read: vec![],
            write: vec![],
            allow_file: vec![],
            read_file: vec![],
            write_file: vec![file_path],
            net_allow: false,
            config: None,
            verbose: 0,
            dry_run: false,
            command: vec!["echo".to_string()],
        };

        let caps = CapabilitySet::from_args(&args).unwrap();
        assert_eq!(caps.fs.len(), 2);
        // First is directory
        assert!(!caps.fs[0].is_file);
        // Second is file
        assert!(caps.fs[1].is_file);
    }

    #[test]
    fn test_capability_set_network_disabled() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_path_buf();

        let args = Args {
            allow: vec![path.clone()],
            read: vec![],
            write: vec![],
            allow_file: vec![],
            read_file: vec![],
            write_file: vec![],
            net_allow: false,
            config: None,
            verbose: 0,
            dry_run: false,
            command: vec!["echo".to_string()],
        };

        let caps = CapabilitySet::from_args(&args).unwrap();
        assert!(!caps.net_allow);
    }
}
