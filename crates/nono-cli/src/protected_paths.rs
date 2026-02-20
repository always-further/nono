//! Protection for nono's own state paths.
//!
//! These checks enforce a hard fail if initial sandbox capabilities overlap
//! with internal CLI state roots (currently `~/.nono`).

use nono::{CapabilitySet, NonoError, Result};
use std::path::{Path, PathBuf};

/// Resolved internal state roots that must not be accessible by the sandboxed child.
///
/// This is intentionally modeled as a list so configured/custom roots can be
/// added later without changing call sites.
pub struct ProtectedRoots {
    roots: Vec<PathBuf>,
}

impl ProtectedRoots {
    /// Build protected roots from current defaults.
    ///
    /// Today this protects the full `~/.nono` subtree.
    pub fn from_defaults() -> Result<Self> {
        let home = dirs::home_dir().ok_or(NonoError::HomeNotFound)?;
        let state_root = resolve_path(&home.join(".nono"));
        Ok(Self {
            roots: vec![state_root],
        })
    }

    /// Return protected roots as absolute/canonicalized path strings for
    /// feeding into `NeverGrantChecker`.
    pub fn as_strings(&self) -> Result<Vec<String>> {
        self.roots
            .iter()
            .map(|p| {
                p.to_str().map(|s| s.to_owned()).ok_or_else(|| {
                    NonoError::SandboxInit(format!(
                        "Protected root path is not valid UTF-8: {}",
                        p.display()
                    ))
                })
            })
            .collect()
    }

    /// Return a slice of protected root paths.
    pub fn as_paths(&self) -> &[PathBuf] {
        &self.roots
    }
}

/// Validate that no filesystem capability overlaps any protected root.
///
/// Overlap rules:
/// - Any file capability inside a protected root is rejected.
/// - Any directory capability inside a protected root is rejected.
/// - Any directory capability that is a parent of a protected root is rejected
///   (e.g. granting `~` would cover `~/.nono`).
pub fn validate_caps_against_protected_roots(
    caps: &CapabilitySet,
    protected_roots: &[PathBuf],
) -> Result<()> {
    for cap in caps.fs_capabilities() {
        validate_requested_path_against_protected_roots(
            &cap.resolved,
            cap.is_file,
            &cap.source.to_string(),
            protected_roots,
        )?;
    }

    Ok(())
}

/// Validate an intended grant path before capability construction.
///
/// This catches protected-root overlaps even when requested paths don't exist
/// yet and are later skipped during capability creation.
pub fn validate_requested_path_against_protected_roots(
    path: &Path,
    is_file: bool,
    source: &str,
    protected_roots: &[PathBuf],
) -> Result<()> {
    let requested_path = resolve_path(path);
    let resolved_roots: Vec<PathBuf> = protected_roots.iter().map(|p| resolve_path(p)).collect();

    for protected_root in &resolved_roots {
        let inside_protected = requested_path.starts_with(protected_root);
        let parent_of_protected = !is_file && protected_root.starts_with(&requested_path);
        if inside_protected || parent_of_protected {
            return Err(NonoError::SandboxInit(format!(
                "Refusing to grant '{}' (source: {}) because it overlaps protected nono state root '{}'.",
                requested_path.display(),
                source,
                protected_root.display(),
            )));
        }
    }

    Ok(())
}

/// Resolve path by canonicalizing the full path, or canonicalizing the longest
/// existing ancestor and appending remaining components.
fn resolve_path(path: &Path) -> PathBuf {
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }

    let mut remaining = Vec::new();
    let mut current = path.to_path_buf();
    loop {
        if let Ok(canonical) = current.canonicalize() {
            let mut result = canonical;
            for component in remaining.iter().rev() {
                result = result.join(component);
            }
            return result;
        }

        match current.file_name() {
            Some(name) => {
                remaining.push(name.to_os_string());
                if !current.pop() {
                    break;
                }
            }
            None => break,
        }
    }

    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nono::{AccessMode, CapabilitySet, FsCapability};
    use tempfile::TempDir;

    #[test]
    fn blocks_parent_directory_capability() {
        let tmp = TempDir::new().expect("tmpdir");
        let parent = tmp.path().to_path_buf();
        let protected = parent.join(".nono");

        let mut caps = CapabilitySet::new();
        let cap = FsCapability::new_dir(&parent, AccessMode::ReadWrite).expect("dir cap");
        caps.add_fs(cap);

        let err = validate_caps_against_protected_roots(&caps, &[protected]).expect_err("blocked");
        assert!(
            err.to_string()
                .contains("overlaps protected nono state root"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn blocks_child_directory_capability() {
        let tmp = TempDir::new().expect("tmpdir");
        let protected = tmp.path().join(".nono");
        let child = protected.join("rollbacks");
        std::fs::create_dir_all(&child).expect("mkdir");

        let mut caps = CapabilitySet::new();
        let cap = FsCapability::new_dir(&child, AccessMode::ReadWrite).expect("dir cap");
        caps.add_fs(cap);

        validate_caps_against_protected_roots(&caps, &[protected]).expect_err("blocked");
    }

    #[test]
    fn allows_unrelated_capability() {
        let tmp = TempDir::new().expect("tmpdir");
        let protected = tmp.path().join(".nono");
        let workspace = tmp.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir");

        let mut caps = CapabilitySet::new();
        let cap = FsCapability::new_dir(&workspace, AccessMode::ReadWrite).expect("dir cap");
        caps.add_fs(cap);

        validate_caps_against_protected_roots(&caps, &[protected]).expect("allowed");
    }

    #[test]
    fn requested_path_blocks_nonexistent_child_under_protected_root() {
        let tmp = TempDir::new().expect("tmpdir");
        let protected = tmp.path().join(".nono");
        std::fs::create_dir_all(&protected).expect("mkdir");
        let child = protected.join("rollbacks").join("future-session");

        let err =
            validate_requested_path_against_protected_roots(&child, false, "CLI", &[protected])
                .expect_err("blocked");
        assert!(
            err.to_string()
                .contains("overlaps protected nono state root"),
            "unexpected error: {err}",
        );
    }

    #[cfg(unix)]
    #[test]
    fn as_strings_rejects_non_utf8_paths() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let non_utf8 = PathBuf::from(OsString::from_vec(vec![0x66, 0x80, 0x6f]));
        let roots = ProtectedRoots {
            roots: vec![non_utf8],
        };
        roots.as_strings().expect_err("non-utf8 path must error");
    }
}
