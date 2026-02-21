//! Capability model for filesystem and network access
//!
//! This module defines the capability types used to specify what resources
//! a sandboxed process can access.

use crate::error::{NonoError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Source of a filesystem capability for diagnostics
///
/// Tracks whether a capability was added by the user directly,
/// from a profile's filesystem section, resolved from a named
/// policy group, or is a system-level path.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilitySource {
    /// Added directly by the user via CLI flags (--allow, --read, --allow-cwd)
    #[default]
    User,
    /// Added from a profile's filesystem section (allow, read, etc.)
    Profile,
    /// Resolved from a named policy group
    Group(String),
    /// System-level path required for execution (e.g., /usr, /bin, /lib)
    System,
}

impl CapabilitySource {
    /// Whether this source represents explicit user intent (CLI flags or profile config).
    /// Used by deduplication to prefer user-intentional entries over system/group entries.
    #[must_use]
    pub fn is_user_intent(&self) -> bool {
        matches!(self, CapabilitySource::User | CapabilitySource::Profile)
    }
}

impl std::fmt::Display for CapabilitySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CapabilitySource::User => write!(f, "user"),
            CapabilitySource::Profile => write!(f, "profile"),
            CapabilitySource::Group(name) => write!(f, "group:{}", name),
            CapabilitySource::System => write!(f, "system"),
        }
    }
}

/// Filesystem access mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessMode {
    /// Read-only access
    Read,
    /// Write-only access
    Write,
    /// Read and write access
    ReadWrite,
}

impl std::fmt::Display for AccessMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessMode::Read => write!(f, "read"),
            AccessMode::Write => write!(f, "write"),
            AccessMode::ReadWrite => write!(f, "read+write"),
        }
    }
}

/// A filesystem capability - grants access to a specific path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsCapability {
    /// The original path as specified by the caller
    pub original: PathBuf,
    /// The canonicalized absolute path
    pub resolved: PathBuf,
    /// The access mode granted
    pub access: AccessMode,
    /// True if this is a single file, false if directory (recursive)
    pub is_file: bool,
    /// Where this capability came from (user CLI flags or a policy group)
    #[serde(default)]
    pub source: CapabilitySource,
}

impl FsCapability {
    /// Create a new directory capability, canonicalizing the path
    ///
    /// Canonicalizes first, then checks metadata on the resolved path
    /// to avoid TOCTOU races between exists() and canonicalize().
    pub fn new_dir(path: impl AsRef<Path>, access: AccessMode) -> Result<Self> {
        let path = path.as_ref();

        // Canonicalize first - this atomically resolves symlinks and verifies existence.
        // No separate exists() check needed, eliminating TOCTOU window.
        let resolved = path.canonicalize().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                NonoError::PathNotFound(path.to_path_buf())
            } else {
                NonoError::PathCanonicalization {
                    path: path.to_path_buf(),
                    source: e,
                }
            }
        })?;

        // Verify type on the already-resolved path (no TOCTOU: same inode)
        if !resolved.is_dir() {
            return Err(NonoError::ExpectedDirectory(path.to_path_buf()));
        }

        Ok(Self {
            original: path.to_path_buf(),
            resolved,
            access,
            is_file: false,
            source: CapabilitySource::User,
        })
    }

    /// Create a new single file capability, canonicalizing the path
    ///
    /// Canonicalizes first, then checks metadata on the resolved path
    /// to avoid TOCTOU races between exists() and canonicalize().
    pub fn new_file(path: impl AsRef<Path>, access: AccessMode) -> Result<Self> {
        let path = path.as_ref();

        // Canonicalize first - this atomically resolves symlinks and verifies existence.
        // No separate exists() check needed, eliminating TOCTOU window.
        let resolved = path.canonicalize().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                NonoError::PathNotFound(path.to_path_buf())
            } else {
                NonoError::PathCanonicalization {
                    path: path.to_path_buf(),
                    source: e,
                }
            }
        })?;

        // Verify type on the already-resolved path (no TOCTOU: same inode)
        if resolved.is_dir() {
            return Err(NonoError::ExpectedFile(path.to_path_buf()));
        }

        Ok(Self {
            original: path.to_path_buf(),
            resolved,
            access,
            is_file: true,
            source: CapabilitySource::User,
        })
    }
}

impl std::fmt::Display for FsCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.resolved.display(), self.access)
    }
}

/// Validate a platform-specific rule for obvious security issues.
///
/// Rejects rules that:
/// - Don't start with `(` (malformed S-expressions)
/// - Contain unbalanced parentheses
/// - Grant root-level filesystem access `(allow file-read* (subpath "/"))`
/// - Grant root-level write access `(allow file-write* (subpath "/"))`
///
/// Validation is performed on tokenized S-expression content with comments
/// stripped, so whitespace variations and `#| ... |#` block comments cannot
/// bypass the checks.
fn validate_platform_rule(rule: &str) -> Result<()> {
    let trimmed = rule.trim();

    if !trimmed.starts_with('(') {
        return Err(NonoError::SandboxInit(format!(
            "platform rule must be an S-expression starting with '(': {}",
            rule
        )));
    }

    let tokens = tokenize_sexp(trimmed)?;

    // Check for balanced parentheses
    let mut depth: i32 = 0;
    for tok in &tokens {
        match tok.as_str() {
            "(" => depth = depth.saturating_add(1),
            ")" => {
                depth = depth.saturating_sub(1);
                if depth < 0 {
                    return Err(NonoError::SandboxInit(format!(
                        "platform rule has unbalanced parentheses: {rule}"
                    )));
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(NonoError::SandboxInit(format!(
            "platform rule has unbalanced parentheses: {rule}"
        )));
    }

    // Look for dangerous patterns: (allow file-read* (subpath "/"))
    // and (allow file-write* (subpath "/"))
    // We check the non-parenthesis tokens for the sequence:
    // "allow", file-read*/file-write*, "subpath", "/"
    let content_tokens: Vec<&str> = tokens
        .iter()
        .map(String::as_str)
        .filter(|t| *t != "(" && *t != ")")
        .collect();
    for window in content_tokens.windows(4) {
        if window[0] == "allow"
            && (window[1] == "file-read*" || window[1] == "file-write*")
            && window[2] == "subpath"
            && window[3] == "/"
        {
            let kind = if window[1] == "file-read*" {
                "read"
            } else {
                "write"
            };
            return Err(NonoError::SandboxInit(format!(
                "platform rule must not grant root-level {kind} access"
            )));
        }
    }

    Ok(())
}

/// Tokenize an S-expression string, stripping `#| ... |#` block comments
/// and `;` line comments. Parentheses and quoted strings are returned as
/// individual tokens.
fn tokenize_sexp(input: &str) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(&c) = chars.peek() {
        match c {
            // Whitespace: skip
            c if c.is_ascii_whitespace() => {
                chars.next();
            }
            // Block comment: #| ... |#
            '#' => {
                chars.next();
                if chars.peek() == Some(&'|') {
                    chars.next();
                    let mut closed = false;
                    while let Some(cc) = chars.next() {
                        if cc == '|' && chars.peek() == Some(&'#') {
                            chars.next();
                            closed = true;
                            break;
                        }
                    }
                    if !closed {
                        return Err(NonoError::SandboxInit(
                            "platform rule has unterminated block comment".to_string(),
                        ));
                    }
                } else {
                    // Bare '#' is part of a token
                    let mut tok = String::from('#');
                    while let Some(&nc) = chars.peek() {
                        if nc.is_ascii_whitespace() || nc == '(' || nc == ')' || nc == '"' {
                            break;
                        }
                        tok.push(nc);
                        chars.next();
                    }
                    tokens.push(tok);
                }
            }
            // Line comment: ; until end of line
            ';' => {
                chars.next();
                while let Some(&nc) = chars.peek() {
                    chars.next();
                    if nc == '\n' {
                        break;
                    }
                }
            }
            // Parentheses: individual tokens
            '(' | ')' => {
                tokens.push(String::from(c));
                chars.next();
            }
            // Quoted string: extract content without quotes
            '"' => {
                chars.next();
                let mut s = String::new();
                let mut closed = false;
                while let Some(sc) = chars.next() {
                    if sc == '\\' {
                        // Consume escaped character
                        if let Some(esc) = chars.next() {
                            s.push(esc);
                        }
                    } else if sc == '"' {
                        closed = true;
                        break;
                    } else {
                        s.push(sc);
                    }
                }
                if !closed {
                    return Err(NonoError::SandboxInit(
                        "platform rule has unterminated string".to_string(),
                    ));
                }
                tokens.push(s);
            }
            // Bare token
            _ => {
                let mut tok = String::new();
                while let Some(&nc) = chars.peek() {
                    if nc.is_ascii_whitespace() || nc == '(' || nc == ')' || nc == '"' {
                        break;
                    }
                    tok.push(nc);
                    chars.next();
                }
                tokens.push(tok);
            }
        }
    }

    Ok(tokens)
}

/// The complete set of capabilities granted to the sandbox
///
/// Use the builder pattern to construct a capability set:
///
/// ```no_run
/// use nono::{CapabilitySet, AccessMode};
///
/// let caps = CapabilitySet::new()
///     .allow_path("/usr", AccessMode::Read)?
///     .allow_path("/project", AccessMode::ReadWrite)?
///     .block_network();
/// # Ok::<(), nono::NonoError>(())
/// ```
#[derive(Debug, Clone, Default)]
pub struct CapabilitySet {
    /// Filesystem capabilities
    fs: Vec<FsCapability>,
    /// Network access blocked (network allowed by default; true = blocked)
    net_block: bool,
    /// Commands explicitly allowed (overrides blocklists - for CLI use)
    allowed_commands: Vec<String>,
    /// Additional commands to block (extends blocklists - for CLI use)
    blocked_commands: Vec<String>,
    /// Raw platform-specific rules injected verbatim into the sandbox profile.
    /// On macOS these are Seatbelt S-expression strings; ignored on Linux.
    platform_rules: Vec<String>,
    /// Enable sandbox extension support for runtime capability expansion.
    /// On macOS, adds extension filter rules to the Seatbelt profile so that
    /// `sandbox_extension_consume()` tokens can expand the sandbox dynamically.
    /// On Linux, this flag is informational (seccomp-notify is installed separately).
    extensions_enabled: bool,
}

impl CapabilitySet {
    /// Create a new empty capability set
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // Builder methods (consume self and return Result<Self>)

    /// Add directory access permission (builder pattern)
    ///
    /// The path is canonicalized and validated. Returns an error if the path
    /// does not exist or is not a directory.
    pub fn allow_path(mut self, path: impl AsRef<Path>, mode: AccessMode) -> Result<Self> {
        let cap = FsCapability::new_dir(path, mode)?;
        self.fs.push(cap);
        Ok(self)
    }

    /// Add file access permission (builder pattern)
    ///
    /// The path is canonicalized and validated. Returns an error if the path
    /// does not exist or is not a file.
    pub fn allow_file(mut self, path: impl AsRef<Path>, mode: AccessMode) -> Result<Self> {
        let cap = FsCapability::new_file(path, mode)?;
        self.fs.push(cap);
        Ok(self)
    }

    /// Block network access (builder pattern)
    ///
    /// By default, network access is allowed. Call this to block it.
    #[must_use]
    pub fn block_network(mut self) -> Self {
        self.net_block = true;
        self
    }

    /// Enable sandbox extensions for runtime capability expansion (builder pattern)
    ///
    /// On macOS, this adds extension filter rules to the Seatbelt profile so that
    /// `sandbox_extension_consume()` tokens can dynamically expand access. The rules
    /// are inert until a matching token is consumed -- they add no access by themselves.
    ///
    /// On Linux, this flag is informational only; seccomp-notify is installed
    /// separately in the child process.
    #[must_use]
    pub fn enable_extensions(mut self) -> Self {
        self.extensions_enabled = true;
        self
    }

    /// Add a command to the allow list (builder pattern)
    ///
    /// Allowed commands override any blocklist. This is primarily for CLI use.
    #[must_use]
    pub fn allow_command(mut self, cmd: impl Into<String>) -> Self {
        self.allowed_commands.push(cmd.into());
        self
    }

    /// Add a command to the block list (builder pattern)
    ///
    /// Blocked commands extend any existing blocklist. This is primarily for CLI use.
    #[must_use]
    pub fn block_command(mut self, cmd: impl Into<String>) -> Self {
        self.blocked_commands.push(cmd.into());
        self
    }

    /// Add a raw platform-specific rule (builder pattern)
    ///
    /// On macOS, these are Seatbelt S-expression strings injected verbatim
    /// into the generated profile. Ignored on Linux.
    ///
    /// Returns an error if the rule is malformed or grants root-level access.
    pub fn platform_rule(mut self, rule: impl Into<String>) -> Result<Self> {
        let rule = rule.into();
        validate_platform_rule(&rule)?;
        self.platform_rules.push(rule);
        Ok(self)
    }

    // Mutable methods (for advanced/programmatic use)

    /// Add a filesystem capability directly
    pub fn add_fs(&mut self, cap: FsCapability) {
        self.fs.push(cap);
    }

    /// Set network blocking state
    pub fn set_network_blocked(&mut self, blocked: bool) {
        self.net_block = blocked;
    }

    /// Set sandbox extensions state
    pub fn set_extensions_enabled(&mut self, enabled: bool) {
        self.extensions_enabled = enabled;
    }

    /// Add to allowed commands list
    pub fn add_allowed_command(&mut self, cmd: impl Into<String>) {
        self.allowed_commands.push(cmd.into());
    }

    /// Add to blocked commands list
    pub fn add_blocked_command(&mut self, cmd: impl Into<String>) {
        self.blocked_commands.push(cmd.into());
    }

    /// Add a raw platform-specific rule
    ///
    /// Returns an error if the rule is malformed or grants root-level access.
    pub fn add_platform_rule(&mut self, rule: impl Into<String>) -> Result<()> {
        let rule = rule.into();
        validate_platform_rule(&rule)?;
        self.platform_rules.push(rule);
        Ok(())
    }

    // Accessors

    /// Get filesystem capabilities
    #[must_use]
    pub fn fs_capabilities(&self) -> &[FsCapability] {
        &self.fs
    }

    /// Check if network access is blocked
    #[must_use]
    pub fn is_network_blocked(&self) -> bool {
        self.net_block
    }

    /// Check if sandbox extensions are enabled for runtime capability expansion
    #[must_use]
    pub fn extensions_enabled(&self) -> bool {
        self.extensions_enabled
    }

    /// Get allowed commands
    #[must_use]
    pub fn allowed_commands(&self) -> &[String] {
        &self.allowed_commands
    }

    /// Get blocked commands
    #[must_use]
    pub fn blocked_commands(&self) -> &[String] {
        &self.blocked_commands
    }

    /// Get platform-specific rules
    #[must_use]
    pub fn platform_rules(&self) -> &[String] {
        &self.platform_rules
    }

    /// Check if this set has any filesystem capabilities
    #[must_use]
    pub fn has_fs(&self) -> bool {
        !self.fs.is_empty()
    }

    /// Deduplicate filesystem capabilities by resolved path.
    ///
    /// Priority rules:
    /// 1. **User source wins over System/Group**: if the user explicitly chose
    ///    `--read /tmp`, a system default of ReadWrite must not override it.
    /// 2. **Among same-source entries**, highest access level wins
    ///    (ReadWrite > Read/Write).
    /// 3. **Symlink originals are preserved**: if any duplicate has
    ///    `original != resolved` (e.g., `/tmp` -> `/private/tmp`), the surviving
    ///    entry inherits that original so Seatbelt profile generation can emit
    ///    rules for both the symlink and target paths.
    pub fn deduplicate(&mut self) {
        use std::collections::HashMap;

        // Group by (resolved path, is_file)
        let mut seen: HashMap<(PathBuf, bool), usize> = HashMap::new();
        let mut to_remove = Vec::new();
        // Deferred updates: (target_index, new_original) to apply after iteration
        let mut original_updates: Vec<(usize, PathBuf)> = Vec::new();
        // Deferred access upgrades: (target_index, new_access) for Read+Write merges
        let mut access_upgrades: Vec<(usize, AccessMode)> = Vec::new();

        for (i, cap) in self.fs.iter().enumerate() {
            let key = (cap.resolved.clone(), cap.is_file);
            if let Some(&existing_idx) = seen.get(&key) {
                let existing = &self.fs[existing_idx];

                // Determine which entry to keep and whether to merge access modes.
                // User-intent entries (User/Profile) always win over
                // system/group entries regardless of access level.
                let new_is_user = cap.source.is_user_intent();
                let existing_is_user = existing.source.is_user_intent();

                let keep_new = if new_is_user && !existing_is_user {
                    // New is User, existing is System/Group -> keep User
                    true
                } else if !new_is_user && existing_is_user {
                    // Existing is User, new is System/Group -> keep existing
                    false
                } else {
                    // Same source category: highest access wins
                    cap.access == AccessMode::ReadWrite && existing.access != AccessMode::ReadWrite
                };

                // Merge complementary access modes (Read + Write = ReadWrite).
                // When two entries from the same source category have different
                // non-ReadWrite modes, upgrade the kept entry to ReadWrite.
                let merged_access = match (existing.access, cap.access) {
                    (AccessMode::Read, AccessMode::Write)
                    | (AccessMode::Write, AccessMode::Read) => Some(AccessMode::ReadWrite),
                    _ => None,
                };

                if keep_new {
                    to_remove.push(existing_idx);
                    seen.insert(key, i);
                    // Preserve symlink original from the removed entry
                    if cap.original == cap.resolved && existing.original != existing.resolved {
                        original_updates.push((i, existing.original.clone()));
                    }
                    // Apply merged access to the new (kept) entry
                    if let Some(access) = merged_access {
                        access_upgrades.push((i, access));
                    }
                } else {
                    // Inherit symlink original from the entry being discarded
                    if existing.original == existing.resolved && cap.original != cap.resolved {
                        original_updates.push((existing_idx, cap.original.clone()));
                    }
                    to_remove.push(i);
                    // Apply merged access to the existing (kept) entry
                    if let Some(access) = merged_access {
                        access_upgrades.push((existing_idx, access));
                    }
                }
            } else {
                seen.insert(key, i);
            }
        }

        // Apply deferred symlink original updates
        for (idx, original) in original_updates {
            self.fs[idx].original = original;
        }

        // Apply deferred access upgrades (Read + Write -> ReadWrite)
        for (idx, access) in access_upgrades {
            self.fs[idx].access = access;
        }

        // Remove duplicates in reverse order to maintain indices
        to_remove.sort_unstable();
        to_remove.reverse();
        for idx in to_remove {
            self.fs.remove(idx);
        }
    }

    /// Check if the given path is already covered by an existing directory capability.
    ///
    /// Uses component-wise Path::starts_with() to prevent path traversal issues
    /// (e.g., "/home" must not match "/homeevil").
    #[must_use]
    pub fn path_covered(&self, path: &Path) -> bool {
        self.fs
            .iter()
            .any(|cap| !cap.is_file && path.starts_with(&cap.resolved))
    }

    /// Display a summary of capabilities (plain text)
    #[must_use]
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

        if lines.is_empty() {
            lines.push("(no capabilities granted)".to_string());
        }

        lines.push("Network:".to_string());
        if self.net_block {
            lines.push("  outbound: blocked".to_string());
        } else {
            lines.push("  outbound: allowed".to_string());
        }

        lines.join("\n")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_fs_capability_new_dir() {
        let dir = tempdir().unwrap();
        let path = dir.path();

        let cap = FsCapability::new_dir(path, AccessMode::Read).unwrap();
        assert_eq!(cap.access, AccessMode::Read);
        assert!(cap.resolved.is_absolute());
        assert!(!cap.is_file);
    }

    #[test]
    fn test_fs_capability_new_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "test").unwrap();

        let cap = FsCapability::new_file(&file_path, AccessMode::Read).unwrap();
        assert_eq!(cap.access, AccessMode::Read);
        assert!(cap.resolved.is_absolute());
        assert!(cap.is_file);
    }

    #[test]
    fn test_fs_capability_nonexistent() {
        let result = FsCapability::new_dir("/nonexistent/path/12345", AccessMode::Read);
        assert!(matches!(result, Err(NonoError::PathNotFound(_))));
    }

    #[test]
    fn test_fs_capability_file_as_dir_error() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "test").unwrap();

        let result = FsCapability::new_dir(&file_path, AccessMode::Read);
        assert!(matches!(result, Err(NonoError::ExpectedDirectory(_))));
    }

    #[test]
    fn test_fs_capability_dir_as_file_error() {
        let dir = tempdir().unwrap();
        let path = dir.path();

        let result = FsCapability::new_file(path, AccessMode::Read);
        assert!(matches!(result, Err(NonoError::ExpectedFile(_))));
    }

    #[test]
    fn test_capability_set_builder() {
        let dir = tempdir().unwrap();

        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::ReadWrite)
            .unwrap()
            .block_network()
            .allow_command("allowed_cmd")
            .block_command("blocked_cmd");

        assert_eq!(caps.fs_capabilities().len(), 1);
        assert!(caps.is_network_blocked());
        assert_eq!(caps.allowed_commands(), &["allowed_cmd"]);
        assert_eq!(caps.blocked_commands(), &["blocked_cmd"]);
    }

    #[test]
    fn test_capability_set_deduplicate() {
        let dir = tempdir().unwrap();

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_dir(dir.path(), AccessMode::Read).unwrap());
        caps.add_fs(FsCapability::new_dir(dir.path(), AccessMode::ReadWrite).unwrap());

        assert_eq!(caps.fs_capabilities().len(), 2);
        caps.deduplicate();
        assert_eq!(caps.fs_capabilities().len(), 1);
        // Should keep ReadWrite (higher access)
        assert_eq!(caps.fs_capabilities()[0].access, AccessMode::ReadWrite);
    }

    #[test]
    fn test_deduplicate_user_wins_over_system() {
        // User says --read /path, system says ReadWrite for same path.
        // User intent must win: surviving entry should be Read.
        let path = PathBuf::from("/some/path");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: path.clone(),
            resolved: path.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::User,
        });
        caps.add_fs(FsCapability {
            original: path.clone(),
            resolved: path.clone(),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::System,
        });

        caps.deduplicate();
        assert_eq!(caps.fs_capabilities().len(), 1);
        let surviving = &caps.fs_capabilities()[0];
        assert_eq!(surviving.access, AccessMode::Read);
        assert!(matches!(surviving.source, CapabilitySource::User));
    }

    #[test]
    fn test_deduplicate_user_wins_over_system_reverse_order() {
        // Same as above but system entry added first.
        let path = PathBuf::from("/some/path");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: path.clone(),
            resolved: path.clone(),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::System,
        });
        caps.add_fs(FsCapability {
            original: path.clone(),
            resolved: path.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::User,
        });

        caps.deduplicate();
        assert_eq!(caps.fs_capabilities().len(), 1);
        let surviving = &caps.fs_capabilities()[0];
        assert_eq!(surviving.access, AccessMode::Read);
        assert!(matches!(surviving.source, CapabilitySource::User));
    }

    #[test]
    fn test_deduplicate_merges_read_and_write_to_readwrite() {
        // Two system/group entries for the same path with Read and Write
        // should merge to ReadWrite (e.g., /dev from system_read + system_write).
        let path = PathBuf::from("/some/path");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: path.clone(),
            resolved: path.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::System,
        });
        caps.add_fs(FsCapability {
            original: path.clone(),
            resolved: path.clone(),
            access: AccessMode::Write,
            is_file: false,
            source: CapabilitySource::System,
        });

        caps.deduplicate();
        assert_eq!(caps.fs_capabilities().len(), 1);
        let surviving = &caps.fs_capabilities()[0];
        assert_eq!(surviving.access, AccessMode::ReadWrite);
    }

    #[test]
    fn test_deduplicate_merges_write_then_read_to_readwrite() {
        // Same merge but with Write added first, Read second.
        let path = PathBuf::from("/some/path");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: path.clone(),
            resolved: path.clone(),
            access: AccessMode::Write,
            is_file: false,
            source: CapabilitySource::System,
        });
        caps.add_fs(FsCapability {
            original: path.clone(),
            resolved: path.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::System,
        });

        caps.deduplicate();
        assert_eq!(caps.fs_capabilities().len(), 1);
        let surviving = &caps.fs_capabilities()[0];
        assert_eq!(surviving.access, AccessMode::ReadWrite);
    }

    #[test]
    fn test_deduplicate_preserves_symlink_original() {
        // User adds --read /tmp (original: /tmp, resolved: /private/tmp, Read)
        // System adds /private/tmp (original: /private/tmp, resolved: /private/tmp, ReadWrite)
        // User wins: surviving entry should be Read with symlink original preserved
        let symlink_path = PathBuf::from("/symlink/path");
        let real_path = PathBuf::from("/real/path");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: symlink_path.clone(),
            resolved: real_path.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::User,
        });
        caps.add_fs(FsCapability {
            original: real_path.clone(),
            resolved: real_path.clone(),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::System,
        });

        caps.deduplicate();
        assert_eq!(caps.fs_capabilities().len(), 1);
        let surviving = &caps.fs_capabilities()[0];
        // User wins with Read access
        assert_eq!(surviving.access, AccessMode::Read);
        assert!(matches!(surviving.source, CapabilitySource::User));
        // Symlink original preserved
        assert_eq!(surviving.original, symlink_path);
        assert_eq!(surviving.resolved, real_path);
    }

    #[test]
    fn test_deduplicate_preserves_symlink_original_keep_existing() {
        // System entry first (original == resolved),
        // User entry second via symlink — User wins and inherits symlink
        let symlink_path = PathBuf::from("/symlink/path");
        let real_path = PathBuf::from("/real/path");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: real_path.clone(),
            resolved: real_path.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::System,
        });
        caps.add_fs(FsCapability {
            original: symlink_path.clone(),
            resolved: real_path.clone(),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::User,
        });

        caps.deduplicate();
        assert_eq!(caps.fs_capabilities().len(), 1);
        let surviving = &caps.fs_capabilities()[0];
        // The symlink original must be inherited from the discarded entry
        assert_eq!(surviving.original, symlink_path);
        assert_eq!(surviving.resolved, real_path);
    }

    #[cfg(unix)]
    #[test]
    fn test_fs_capability_symlink_resolution() {
        let dir = tempdir().unwrap();
        let real_dir = dir.path().join("real");
        let symlink = dir.path().join("link");

        fs::create_dir(&real_dir).unwrap();
        std::os::unix::fs::symlink(&real_dir, &symlink).unwrap();

        let cap = FsCapability::new_dir(&symlink, AccessMode::Read).unwrap();
        // Symlink should be resolved to real path
        assert_eq!(cap.resolved, real_dir.canonicalize().unwrap());
    }

    #[test]
    fn test_extensions_flag() {
        let caps = CapabilitySet::new();
        assert!(!caps.extensions_enabled());

        let caps = caps.enable_extensions();
        assert!(caps.extensions_enabled());
    }

    #[test]
    fn test_extensions_flag_mutable() {
        let mut caps = CapabilitySet::new();
        assert!(!caps.extensions_enabled());

        caps.set_extensions_enabled(true);
        assert!(caps.extensions_enabled());

        caps.set_extensions_enabled(false);
        assert!(!caps.extensions_enabled());
    }

    #[test]
    fn test_platform_rule_validation_valid_deny() {
        let mut caps = CapabilitySet::new();
        assert!(caps.add_platform_rule("(deny file-write-unlink)").is_ok());
        assert!(caps
            .add_platform_rule("(deny file-read-data (subpath \"/secret\"))")
            .is_ok());
    }

    #[test]
    fn test_platform_rule_validation_rejects_malformed() {
        let mut caps = CapabilitySet::new();
        assert!(caps.add_platform_rule("not an s-expression").is_err());
        assert!(caps.add_platform_rule("").is_err());
    }

    #[test]
    fn test_platform_rule_validation_rejects_root_access() {
        let mut caps = CapabilitySet::new();
        assert!(caps
            .add_platform_rule("(allow file-read* (subpath \"/\"))")
            .is_err());
        assert!(caps
            .add_platform_rule("(allow file-write* (subpath \"/\"))")
            .is_err());
        // Specific subpaths should be fine
        assert!(caps
            .add_platform_rule("(allow file-read* (subpath \"/usr\"))")
            .is_ok());
    }

    #[test]
    fn test_platform_rule_validation_rejects_whitespace_bypass() {
        let mut caps = CapabilitySet::new();
        // Tab-separated
        assert!(caps
            .add_platform_rule("(allow\tfile-read*\t(subpath\t\"/\"))")
            .is_err());
        // Extra spaces
        assert!(caps
            .add_platform_rule("(allow  file-read*  (subpath  \"/\"))")
            .is_err());
        // Mixed whitespace
        assert!(caps
            .add_platform_rule("(allow \t file-write* \t (subpath \"/\"))")
            .is_err());
    }

    #[test]
    fn test_platform_rule_validation_rejects_comment_bypass() {
        let mut caps = CapabilitySet::new();
        // Block comment between tokens
        assert!(caps
            .add_platform_rule("(allow file-read* #| comment |# (subpath \"/\"))")
            .is_err());
        // Block comment inside nested expression
        assert!(caps
            .add_platform_rule("(allow #| sneaky |# file-write* (subpath \"/\"))")
            .is_err());
    }

    #[test]
    fn test_platform_rule_validation_rejects_unbalanced_parens() {
        let mut caps = CapabilitySet::new();
        assert!(caps.add_platform_rule("(deny file-read*").is_err());
        assert!(caps.add_platform_rule("(deny file-read*))").is_err());
    }

    #[test]
    fn test_platform_rule_validation_rejects_unterminated_constructs() {
        let mut caps = CapabilitySet::new();
        assert!(caps
            .add_platform_rule("(deny file-read* #| unterminated comment")
            .is_err());
        assert!(caps
            .add_platform_rule("(deny file-read* (subpath \"/usr))")
            .is_err());
    }
}
