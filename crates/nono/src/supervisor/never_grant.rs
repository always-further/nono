//! `never_grant` path validation for supervisor capability expansion
//!
//! Paths on the `never_grant` list are permanently blocked from being granted
//! via supervisor IPC, regardless of user approval. This prevents social
//! engineering attacks where a compromised agent crafts convincing reasons
//! for accessing critical system files.

use crate::error::{NonoError, Result};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// Validates paths against the `never_grant` list from policy.json.
///
/// The checker rejects any path that falls under a `never_grant` entry.
/// Path matching uses [`Path::starts_with()`] (component-wise comparison),
/// never string operations.
///
/// # Security
///
/// - Paths are canonicalized before checking to prevent symlink bypass
/// - Component-wise comparison prevents path confusion attacks
///   (e.g., `/etc/shadow2` does NOT match `/etc/shadow`)
/// - The list is immutable after construction
pub struct NeverGrantChecker {
    /// Canonicalized never_grant paths
    paths: Vec<PathBuf>,
}

impl NeverGrantChecker {
    /// Create a new checker from a list of path strings.
    ///
    /// Paths are canonicalized at construction time. Paths that cannot be
    /// canonicalized (e.g., they don't exist) are stored as-is with `~`
    /// expanded to the home directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the home directory cannot be determined when
    /// `~` expansion is needed.
    pub fn new(paths: &[String]) -> Result<Self> {
        let home = dirs_home();
        let mut resolved = Vec::with_capacity(paths.len());

        for path_str in paths {
            let expanded = if let Some(suffix) = path_str.strip_prefix("~/") {
                match home {
                    Some(ref h) => h.join(suffix),
                    None => {
                        return Err(NonoError::HomeNotFound);
                    }
                }
            } else {
                PathBuf::from(path_str)
            };

            // Try to canonicalize; fall back to the expanded path if it doesn't exist
            let canonical = expanded.canonicalize().unwrap_or(expanded);
            resolved.push(canonical);
        }

        Ok(NeverGrantChecker { paths: resolved })
    }

    /// Check whether a path is blocked by the `never_grant` list.
    ///
    /// The requested path is canonicalized before checking. Returns `true`
    /// if the path (or any parent) is on the `never_grant` list.
    ///
    /// # Security Note
    ///
    /// Uses [`Path::starts_with()`] for component-wise matching, not string
    /// operations. This prevents `/etc/shadow2` from matching `/etc/shadow`.
    #[must_use]
    pub fn is_blocked(&self, path: &Path) -> bool {
        let resolved = resolve_path(path);

        for blocked_path in &self.paths {
            if resolved.starts_with(blocked_path) {
                return true;
            }
            // Also check the original path in case resolve_path returned it unchanged
            if path.starts_with(blocked_path) {
                return true;
            }
        }
        false
    }

    /// Check a path and return a detailed result.
    ///
    /// If blocked, returns the specific `never_grant` entry that matched.
    #[must_use]
    pub fn check(&self, path: &Path) -> NeverGrantResult {
        let resolved = resolve_path(path);

        for blocked_path in &self.paths {
            if resolved.starts_with(blocked_path) || path.starts_with(blocked_path) {
                return NeverGrantResult::Blocked {
                    matched_rule: blocked_path.clone(),
                };
            }
        }
        NeverGrantResult::Allowed
    }

    /// Returns the number of paths in the `never_grant` list.
    #[must_use]
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    /// Returns true if the `never_grant` list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

/// Result of a `never_grant` check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NeverGrantResult {
    /// The path is allowed (not on the `never_grant` list)
    Allowed,
    /// The path is permanently blocked
    Blocked {
        /// The `never_grant` entry that matched
        matched_rule: PathBuf,
    },
}

impl NeverGrantResult {
    /// Returns true if the path is allowed.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, NeverGrantResult::Allowed)
    }

    /// Returns true if the path is blocked.
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        matches!(self, NeverGrantResult::Blocked { .. })
    }
}

/// Resolve a path by canonicalizing it, or by canonicalizing its longest
/// existing ancestor and appending the remaining components.
///
/// This handles the case where a child path doesn't exist yet but its parent
/// directory does. On macOS, `/var/folders/.../blocked/subfile` needs to resolve
/// to `/private/var/folders/.../blocked/subfile` even when `subfile` doesn't exist.
fn resolve_path(path: &Path) -> PathBuf {
    // Try full canonicalization first
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }

    // Walk up to find the longest existing ancestor, collect remaining components
    let mut remaining = Vec::new();
    let mut current = path.to_path_buf();
    loop {
        if let Ok(canonical) = current.canonicalize() {
            // Rebuild the path: canonical ancestor + remaining components
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

    // Nothing could be canonicalized, return the original
    path.to_path_buf()
}

/// Get the user's home directory.
fn dirs_home() -> Option<PathBuf> {
    let env_home = std::env::var_os("HOME").map(PathBuf::from);
    let pw_home = home_from_passwd();

    match (env_home, pw_home) {
        (Some(env), Some(pw)) => {
            if same_path(&env, &pw) {
                Some(env)
            } else {
                // HOME is untrusted input; prefer passwd database for security checks.
                Some(pw)
            }
        }
        (Some(env), None) => Some(env),
        (None, Some(pw)) => Some(pw),
        (None, None) => None,
    }
}

fn same_path(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(ac), Ok(bc)) => ac == bc,
        _ => false,
    }
}

fn home_from_passwd() -> Option<PathBuf> {
    let uid = unsafe { libc::geteuid() };
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf_len = 1024usize;

    loop {
        let mut buf = vec![0u8; buf_len];
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                &mut pwd,
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf.len(),
                &mut result,
            )
        };

        if rc == 0 {
            if result.is_null() || pwd.pw_dir.is_null() {
                return None;
            }
            let cstr = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) };
            return Some(PathBuf::from(std::ffi::OsStr::from_bytes(cstr.to_bytes())));
        }

        if rc == libc::ERANGE {
            buf_len = buf_len.saturating_mul(2);
            if buf_len > 1024 * 1024 {
                return None;
            }
            continue;
        }

        return None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_empty_checker_allows_all() {
        let checker = NeverGrantChecker::new(&[]).expect("checker creation");
        assert!(checker.is_empty());
        assert!(!checker.is_blocked(Path::new("/etc/shadow")));
        assert!(!checker.is_blocked(Path::new("/tmp/anything")));
    }

    #[test]
    fn test_exact_path_blocked() {
        let tmp = TempDir::new().expect("tmpdir");
        let blocked_file = tmp.path().join("shadow");
        std::fs::write(&blocked_file, "secret").expect("write");

        let checker =
            NeverGrantChecker::new(&[blocked_file.to_string_lossy().to_string()]).expect("checker");

        assert!(checker.is_blocked(&blocked_file));
    }

    #[test]
    fn test_subpath_blocked() {
        let tmp = TempDir::new().expect("tmpdir");
        let blocked_dir = tmp.path().join("secure");
        std::fs::create_dir(&blocked_dir).expect("mkdir");
        let child_file = blocked_dir.join("secret.txt");
        std::fs::write(&child_file, "secret").expect("write");

        let checker =
            NeverGrantChecker::new(&[blocked_dir.to_string_lossy().to_string()]).expect("checker");

        assert!(checker.is_blocked(&child_file));
    }

    #[test]
    fn test_similar_name_not_blocked() {
        let tmp = TempDir::new().expect("tmpdir");
        let shadow = tmp.path().join("shadow");
        let shadow2 = tmp.path().join("shadow2");
        std::fs::write(&shadow, "secret").expect("write");
        std::fs::write(&shadow2, "not secret").expect("write");

        let checker =
            NeverGrantChecker::new(&[shadow.to_string_lossy().to_string()]).expect("checker");

        assert!(checker.is_blocked(&shadow));
        // shadow2 is NOT blocked - component-wise matching prevents this
        assert!(!checker.is_blocked(&shadow2));
    }

    #[test]
    fn test_check_returns_matched_rule() {
        let tmp = TempDir::new().expect("tmpdir");
        let blocked = tmp.path().join("blocked");
        std::fs::create_dir(&blocked).expect("mkdir");

        let checker =
            NeverGrantChecker::new(&[blocked.to_string_lossy().to_string()]).expect("checker");

        let result = checker.check(&blocked.join("subfile"));
        assert!(result.is_blocked());
        if let NeverGrantResult::Blocked { matched_rule } = result {
            // The matched rule should be the canonicalized blocked path
            assert_eq!(
                matched_rule.canonicalize().ok(),
                blocked.canonicalize().ok()
            );
        }
    }

    #[test]
    fn test_nonexistent_path_still_checked() {
        // Paths that don't exist yet should still be checked
        let checker =
            NeverGrantChecker::new(&["/nonexistent/secure".to_string()]).expect("checker");

        assert!(checker.is_blocked(Path::new("/nonexistent/secure/file.txt")));
        assert!(!checker.is_blocked(Path::new("/nonexistent/other")));
    }

    #[test]
    fn test_tilde_expansion() {
        if std::env::var_os("HOME").is_none() {
            return; // Skip if HOME not set
        }

        let checker =
            NeverGrantChecker::new(&["~/.ssh/authorized_keys".to_string()]).expect("checker");

        let home = dirs_home().expect("home");
        assert!(checker.is_blocked(&home.join(".ssh/authorized_keys")));
        // Regular .ssh dir should not be blocked (authorized_keys is a file, not a dir prefix)
        // unless .ssh/authorized_keys path includes it as a component
    }

    #[test]
    fn test_len_and_is_empty() {
        let checker = NeverGrantChecker::new(&[]).expect("checker");
        assert_eq!(checker.len(), 0);
        assert!(checker.is_empty());

        let checker = NeverGrantChecker::new(&["/etc/shadow".to_string(), "/boot".to_string()])
            .expect("checker");
        assert_eq!(checker.len(), 2);
        assert!(!checker.is_empty());
    }
}
