//! Group-based policy resolver
//!
//! Parses `policy.json` and resolves named groups into `CapabilitySet` entries
//! and platform-specific rules using composable, platform-aware groups.

use crate::profile;
use nono::{AccessMode, CapabilitySet, CapabilitySource, FsCapability, NonoError, Result};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

// ============================================================================
// JSON schema types
// ============================================================================

/// Root policy file structure
#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    #[allow(dead_code)]
    pub meta: PolicyMeta,
    /// Paths that can never be granted via supervisor IPC, regardless of user approval.
    /// Consumed by `NeverGrantChecker` during supervisor orchestration.
    #[serde(default)]
    pub never_grant: Vec<String>,
    /// Default groups applied to all sandbox invocations
    #[serde(default)]
    pub base_groups: Vec<String>,
    pub groups: HashMap<String, Group>,
    /// Built-in profile definitions
    #[serde(default)]
    pub profiles: HashMap<String, ProfileDef>,
}

/// Policy metadata
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyMeta {
    #[allow(dead_code)]
    pub version: u64,
    #[allow(dead_code)]
    pub schema_version: String,
}

/// A named group of rules
#[derive(Debug, Clone, Deserialize)]
pub struct Group {
    #[allow(dead_code)]
    pub description: String,
    /// If set, this group only applies on the specified platform
    #[serde(default)]
    pub platform: Option<String>,
    /// If true, this group cannot be removed via trust_groups
    #[serde(default)]
    pub required: bool,
    /// Allow operations
    #[serde(default)]
    pub allow: Option<AllowOps>,
    /// Deny operations
    #[serde(default)]
    pub deny: Option<DenyOps>,
    /// macOS symlink path pairs (symlink -> real target)
    #[serde(default)]
    pub symlink_pairs: Option<HashMap<String, String>>,
}

/// Allow operations nested under `allow`
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AllowOps {
    /// Paths granted read access
    #[serde(default)]
    pub read: Vec<String>,
    /// Paths granted write-only access
    #[serde(default)]
    pub write: Vec<String>,
    /// Paths granted read+write access
    #[serde(default)]
    pub readwrite: Vec<String>,
}

/// Deny operations nested under `deny`
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DenyOps {
    /// Paths denied all content access (read+write; metadata still allowed)
    #[serde(default)]
    pub access: Vec<String>,
    /// Block file deletion globally
    #[serde(default)]
    pub unlink: bool,
    /// Override unlink denial for user-writable paths
    #[serde(default)]
    pub unlink_override_for_user_writable: bool,
    /// Commands to block
    #[serde(default)]
    pub commands: Vec<String>,
}

/// Profile definition as stored in policy.json
///
/// Separate from `profile::Profile` because in JSON `trust_groups` lives at the
/// profile level and `security.groups` means "additional groups on top of base",
/// not the complete merged list.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProfileDef {
    #[serde(default)]
    pub meta: profile::ProfileMeta,
    #[serde(default)]
    pub security: profile::SecurityConfig,
    /// Base groups to exclude for this profile
    #[serde(default)]
    pub trust_groups: Vec<String>,
    #[serde(default)]
    pub filesystem: profile::FilesystemConfig,
    #[serde(default)]
    pub network: profile::NetworkConfig,
    #[serde(default)]
    pub secrets: profile::SecretsConfig,
    #[serde(default)]
    pub workdir: profile::WorkdirConfig,
    #[serde(default)]
    pub hooks: profile::HooksConfig,
    #[serde(default, alias = "undo")]
    pub rollback: profile::RollbackConfig,
    #[serde(default)]
    pub interactive: bool,
}

impl ProfileDef {
    /// Convert to a full Profile with merged group list.
    ///
    /// Computes: `(base_groups - trust_groups) + security.groups`
    ///
    /// Returns an error if trust_groups attempts to remove a required group.
    pub fn to_profile(&self, base_groups: &[String], policy: &Policy) -> Result<profile::Profile> {
        validate_trust_groups(policy, &self.trust_groups)?;

        let mut groups: Vec<String> = base_groups
            .iter()
            .filter(|g| !self.trust_groups.contains(g))
            .cloned()
            .collect();
        groups.extend(self.security.groups.clone());

        Ok(profile::Profile {
            meta: self.meta.clone(),
            security: profile::SecurityConfig {
                groups,
                trust_groups: self.trust_groups.clone(),
            },
            filesystem: self.filesystem.clone(),
            network: self.network.clone(),
            secrets: self.secrets.clone(),
            workdir: self.workdir.clone(),
            hooks: self.hooks.clone(),
            rollback: self.rollback.clone(),
            interactive: self.interactive,
        })
    }
}

// ============================================================================
// Platform detection
// ============================================================================

/// Current platform identifier
fn current_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    }
}

/// Check if a group applies to the current platform
fn group_matches_platform(group: &Group) -> bool {
    match &group.platform {
        Some(platform) => platform == current_platform(),
        None => true, // No platform restriction = applies everywhere
    }
}

// ============================================================================
// Path expansion
// ============================================================================

/// Expand `~` to $HOME and `$TMPDIR` to the environment variable value.
///
/// Returns an error if HOME or TMPDIR are set to non-absolute paths.
fn expand_path(path_str: &str) -> Result<PathBuf> {
    use crate::config;

    let expanded = if let Some(rest) = path_str.strip_prefix("~/") {
        let home = config::validated_home()?;
        format!("{}/{}", home, rest)
    } else if path_str == "~" || path_str == "$HOME" {
        config::validated_home()?
    } else if let Some(rest) = path_str.strip_prefix("$HOME/") {
        let home = config::validated_home()?;
        format!("{}/{}", home, rest)
    } else if path_str == "$TMPDIR" {
        config::validated_tmpdir()?
    } else if let Some(rest) = path_str.strip_prefix("$TMPDIR/") {
        let tmpdir = config::validated_tmpdir()?;
        format!("{}/{}", tmpdir, rest)
    } else {
        path_str.to_string()
    };

    Ok(PathBuf::from(expanded))
}

/// Convert a PathBuf to a UTF-8 string, returning an error for non-UTF-8 paths.
///
/// Non-UTF-8 paths would produce incorrect Seatbelt rules via lossy conversion,
/// potentially targeting the wrong path in deny rules.
fn path_to_utf8(path: &Path) -> Result<&str> {
    path.to_str().ok_or_else(|| {
        NonoError::ConfigParse(format!("Path contains non-UTF-8 bytes: {}", path.display()))
    })
}

/// Escape a path for Seatbelt profile strings.
///
/// Paths are placed inside double-quoted S-expression strings where `\` and `"`
/// are the significant characters. Control characters are rejected (not stripped)
/// to match the library's escape_path behavior — silently stripping could cause
/// deny rules to target wrong paths.
fn escape_seatbelt_path(path: &str) -> Result<String> {
    let mut result = String::with_capacity(path.len());
    for c in path.chars() {
        if c.is_control() {
            return Err(NonoError::ConfigParse(format!(
                "Path contains control character: {:?}",
                path
            )));
        }
        match c {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            _ => result.push(c),
        }
    }
    Ok(result)
}

// ============================================================================
// Group resolution
// ============================================================================

/// Load policy from JSON string
pub fn load_policy(json: &str) -> Result<Policy> {
    serde_json::from_str(json)
        .map_err(|e| NonoError::ConfigParse(format!("Failed to parse policy.json: {}", e)))
}

/// Result of resolving policy groups
pub struct ResolvedGroups {
    /// Names of groups that were resolved (platform-matching only)
    pub names: Vec<String>,
    /// Whether unlink overrides should be applied after all paths are finalized.
    /// This is deferred because the caller may add more writable paths (e.g., from
    /// the profile's [filesystem] section or CLI flags) after group resolution.
    pub needs_unlink_overrides: bool,
    /// Expanded deny.access paths for post-resolution validation.
    /// On macOS these also generate platform_rules; on Linux they're
    /// validation-only since Landlock has no deny semantics.
    pub deny_paths: Vec<PathBuf>,
}

/// Resolve a list of group names into capability set entries and platform rules.
///
/// For each group:
/// - `allow.read` paths become `FsCapability` with `AccessMode::Read`
/// - `allow.write` paths become `FsCapability` with `AccessMode::Write`
/// - `allow.readwrite` paths become `FsCapability` with `AccessMode::ReadWrite`
/// - `deny.access` paths become platform rules (deny read data + deny write)
/// - `deny.unlink` becomes a platform rule
/// - `deny.commands` are added to the blocked commands list
/// - `symlink_pairs` become platform rules for non-canonical paths
///
/// Groups with a `platform` field that doesn't match the current OS are skipped.
/// Non-existent allow paths are skipped with a warning.
/// Non-existent deny paths still generate rules (defensive).
///
/// **Important**: If `resolved.needs_unlink_overrides` is true, the caller MUST call
/// `apply_unlink_overrides(caps)` after all writable paths have been added to the
/// capability set (including profile [filesystem] and CLI overrides).
pub fn resolve_groups(
    policy: &Policy,
    group_names: &[String],
    caps: &mut CapabilitySet,
) -> Result<ResolvedGroups> {
    let mut resolved_groups = Vec::new();
    let mut needs_unlink_overrides = false;
    let mut deny_paths = Vec::new();

    for name in group_names {
        let group = policy
            .groups
            .get(name.as_str())
            .ok_or_else(|| NonoError::ConfigParse(format!("Unknown policy group: '{}'", name)))?;

        if !group_matches_platform(group) {
            debug!(
                "Skipping group '{}' (platform {:?} != {})",
                name,
                group.platform,
                current_platform()
            );
            continue;
        }

        if resolve_single_group(name, group, caps, &mut deny_paths)? {
            needs_unlink_overrides = true;
        }
        resolved_groups.push(name.clone());
    }

    Ok(ResolvedGroups {
        names: resolved_groups,
        needs_unlink_overrides,
        deny_paths,
    })
}

/// Resolve a single group into capability set entries.
/// Returns true if unlink overrides were requested (to be deferred).
fn resolve_single_group(
    group_name: &str,
    group: &Group,
    caps: &mut CapabilitySet,
    deny_paths: &mut Vec<PathBuf>,
) -> Result<bool> {
    let source = CapabilitySource::Group(group_name.to_string());
    let mut needs_unlink_overrides = false;

    // Process allow operations
    if let Some(allow) = &group.allow {
        for path_str in &allow.read {
            add_fs_capability(path_str, AccessMode::Read, &source, caps)?;
        }
        for path_str in &allow.write {
            add_fs_capability(path_str, AccessMode::Write, &source, caps)?;
        }
        for path_str in &allow.readwrite {
            add_fs_capability(path_str, AccessMode::ReadWrite, &source, caps)?;
        }
    }

    // Process deny operations
    if let Some(deny) = &group.deny {
        for path_str in &deny.access {
            add_deny_access_rules(path_str, caps, deny_paths)?;
        }

        // Seatbelt-only: global unlink denial. Landlock handles file deletion
        // via AccessFs flags in access_to_landlock() (RemoveDir excluded from write).
        if deny.unlink && cfg!(target_os = "macos") {
            caps.add_platform_rule("(deny file-write-unlink)")?;
        }

        if deny.unlink_override_for_user_writable {
            // Deferred: caller must call apply_unlink_overrides() after all writable
            // paths are finalized (profile [filesystem] + CLI overrides).
            needs_unlink_overrides = true;
        }

        for cmd in &deny.commands {
            caps.add_blocked_command(cmd.clone());
        }
    }

    // Process symlink pairs (Seatbelt-only: macOS symlink → target path handling)
    if cfg!(target_os = "macos") {
        if let Some(pairs) = &group.symlink_pairs {
            for symlink in pairs.keys() {
                let expanded = expand_path(symlink)?;
                let escaped = escape_seatbelt_path(path_to_utf8(&expanded)?)?;
                caps.add_platform_rule(format!("(allow file-read* (subpath \"{}\"))", escaped))?;
            }
        }
    }

    Ok(needs_unlink_overrides)
}

/// Add a filesystem capability from a group path, handling expansion and existence checks
fn add_fs_capability(
    path_str: &str,
    mode: AccessMode,
    source: &CapabilitySource,
    caps: &mut CapabilitySet,
) -> Result<()> {
    let path = expand_path(path_str)?;

    if !path.exists() {
        debug!(
            "Group path '{}' (expanded to '{}') does not exist, skipping",
            path_str,
            path.display()
        );
        return Ok(());
    }

    if path.is_dir() {
        match FsCapability::new_dir(&path, mode) {
            Ok(mut cap) => {
                cap.source = source.clone();
                caps.add_fs(cap);
            }
            Err(e) => {
                debug!("Could not add group directory {}: {}", path_str, e);
            }
        }
    } else if path.is_file() {
        match FsCapability::new_file(&path, mode) {
            Ok(mut cap) => {
                cap.source = source.clone();
                caps.add_fs(cap);
            }
            Err(e) => {
                debug!("Could not add group file {}: {}", path_str, e);
            }
        }
    } else {
        debug!(
            "Group path '{}' is neither file nor directory, skipping",
            path_str
        );
    }

    Ok(())
}

/// Add deny.access rules, collecting the expanded path for validation.
///
/// On macOS, generates Seatbelt platform rules:
/// - `(allow file-read-metadata ...)` — programs can stat/check existence
/// - `(deny file-read-data ...)` — deny reading content
/// - `(deny file-write* ...)` — deny writing
///
/// On Linux, deny paths are collected for overlap validation only —
/// Landlock has no deny semantics so platform rules would be ignored.
///
/// Uses `subpath` for directories, `literal` for files.
/// For non-existent paths, defaults to `subpath` (defensive).
fn add_deny_access_rules(
    path_str: &str,
    caps: &mut CapabilitySet,
    deny_paths: &mut Vec<PathBuf>,
) -> Result<()> {
    let path = expand_path(path_str)?;
    deny_paths.push(path.clone());

    // Seatbelt deny rules only apply on macOS
    if cfg!(target_os = "macos") {
        let escaped = escape_seatbelt_path(path_to_utf8(&path)?)?;

        // Determine filter type: literal for files, subpath for directories
        let filter = if path.exists() && path.is_file() {
            format!("literal \"{}\"", escaped)
        } else {
            // Default to subpath for dirs and non-existent paths (defensive)
            format!("subpath \"{}\"", escaped)
        };

        caps.add_platform_rule(format!("(allow file-read-metadata ({}))", filter))?;
        caps.add_platform_rule(format!("(deny file-read-data ({}))", filter))?;
        caps.add_platform_rule(format!("(deny file-write* ({}))", filter))?;
    }

    Ok(())
}

/// Add a narrow macOS exception for explicit login.keychain-db file grants.
///
/// This keeps broad keychain deny groups active while allowing only the exact
/// file capability intended by a profile or CLI flag.
pub fn apply_macos_login_keychain_exception(caps: &mut CapabilitySet) {
    if !cfg!(target_os = "macos") {
        return;
    }

    let user_login_db = std::env::var("HOME")
        .ok()
        .map(|home| Path::new(&home).join("Library/Keychains/login.keychain-db"));
    let system_login_db = Path::new("/Library/Keychains/login.keychain-db");

    let is_login_db = |path: &Path| -> bool {
        if path == system_login_db {
            return true;
        }
        if let Some(ref user_login_db) = user_login_db {
            if path == user_login_db {
                return true;
            }
        }
        false
    };

    let allow_rules: Vec<String> = caps
        .fs_capabilities()
        .iter()
        .filter(|cap| cap.is_file)
        .filter(|cap| matches!(cap.access, AccessMode::Read | AccessMode::ReadWrite))
        .map(|cap| cap.resolved.clone())
        .filter(|path| is_login_db(path))
        .filter_map(|path| {
            let path_str = match path_to_utf8(&path) {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        "Skipping login keychain exception for {}: {}",
                        path.display(),
                        e
                    );
                    return None;
                }
            };
            let escaped = match escape_seatbelt_path(path_str) {
                Ok(v) => v,
                Err(e) => {
                    warn!(
                        "Skipping login keychain exception for {}: {}",
                        path.display(),
                        e
                    );
                    return None;
                }
            };
            Some(format!("(allow file-read-data (literal \"{}\"))", escaped))
        })
        .collect();

    for rule in allow_rules {
        if let Err(e) = caps.add_platform_rule(rule) {
            warn!("Failed to add login keychain exception rule: {}", e);
        }
    }
}

/// Apply unlink override rules for all writable paths in the capability set.
///
/// This allows file deletion in paths that have Write or ReadWrite access,
/// counteracting a global `(deny file-write-unlink)` rule.
///
/// Seatbelt-only: Landlock handles file deletion via `AccessFs` flags in
/// `access_to_landlock()` and has no equivalent deny-then-allow mechanism.
///
/// **Must be called after all paths are finalized** (groups + profile + CLI overrides).
pub fn apply_unlink_overrides(caps: &mut CapabilitySet) {
    if cfg!(target_os = "linux") {
        return; // Unlink overrides are Seatbelt-specific
    }

    // Collect writable paths from existing capabilities
    let writable_paths: Vec<PathBuf> = caps
        .fs_capabilities()
        .iter()
        .filter(|cap| matches!(cap.access, AccessMode::Write | AccessMode::ReadWrite))
        .filter(|cap| !cap.is_file)
        .map(|cap| cap.resolved.clone())
        .collect();

    for path in writable_paths {
        let path_str = match path_to_utf8(&path) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("Skipping unlink override for {}: {}", path.display(), e);
                continue;
            }
        };
        let escaped = match escape_seatbelt_path(path_str) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("Skipping unlink override for {}: {}", path.display(), e);
                continue;
            }
        };
        // These rules are well-formed S-expressions for user-granted writable paths,
        // so validation should not fail. Log and skip on error to avoid breaking the sandbox.
        if let Err(e) = caps.add_platform_rule(format!(
            "(allow file-write-unlink (subpath \"{}\"))",
            escaped
        )) {
            tracing::warn!("Skipping unlink override rule: {}", e);
        }
    }
}

/// Resolve deny.access paths for a group list without mutating caller capabilities.
pub fn resolve_deny_paths_for_groups(
    policy: &Policy,
    group_names: &[String],
) -> Result<Vec<PathBuf>> {
    let mut tmp_caps = CapabilitySet::new();
    let resolved = resolve_groups(policy, group_names, &mut tmp_caps)?;
    Ok(resolved.deny_paths)
}

/// Check for deny paths that overlap with allowed paths on Linux.
///
/// Landlock is strictly allow-list and cannot deny a child of an allowed parent.
/// On Linux, overlap between `deny.access` and allowed parent paths is a hard error
/// because the deny rule would silently have no effect.
///
/// On macOS this is a no-op (Seatbelt handles deny-within-allow natively).
///
/// **Must be called after all paths are finalized** (groups + profile + CLI overrides + CWD).
pub fn validate_deny_overlaps(deny_paths: &[PathBuf], caps: &CapabilitySet) -> Result<()> {
    if cfg!(target_os = "macos") {
        return Ok(());
    }

    let mut fatal_conflicts = Vec::new();

    for deny_path in deny_paths {
        for cap in caps.fs_capabilities() {
            if cap.is_file {
                continue; // File caps can't cover a directory subtree
            }
            // Check if deny path is a child of an allowed directory
            if deny_path.starts_with(&cap.resolved) && *deny_path != cap.resolved {
                let conflict = format!(
                    "deny '{}' overlaps allowed parent '{}' (source: {})",
                    deny_path.display(),
                    cap.resolved.display(),
                    cap.source,
                );
                warn!(
                    "Landlock cannot enforce {}. This deny has no effect on Linux.",
                    conflict
                );
                if cap.source.is_user_intent() {
                    fatal_conflicts.push(conflict);
                }
            }
        }
    }

    if fatal_conflicts.is_empty() {
        return Ok(());
    }

    fatal_conflicts.sort();
    fatal_conflicts.dedup();

    let preview = fatal_conflicts
        .iter()
        .take(5)
        .map(|c| format!("- {}", c))
        .collect::<Vec<_>>()
        .join("\n");

    let remainder = fatal_conflicts.len().saturating_sub(5);
    let more = if remainder > 0 {
        format!("\n- ... and {} more conflict(s)", remainder)
    } else {
        String::new()
    };

    Err(NonoError::SandboxInit(format!(
        "Landlock deny-overlap is not enforceable on Linux. Refusing to start with conflicting policy.\n\
         Remove the broad allow path, remove the deny path, or restructure permissions.\n\
         Conflicts:\n{}{}",
        preview, more
    )))
}

/// Get the list of all group names defined in the policy
#[cfg(test)]
pub fn list_groups(policy: &Policy) -> Vec<&str> {
    let mut names: Vec<&str> = policy.groups.keys().map(|s| s.as_str()).collect();
    names.sort();
    names
}

/// Get group description by name
#[cfg(test)]
pub fn group_description<'a>(policy: &'a Policy, name: &str) -> Option<&'a str> {
    policy.groups.get(name).map(|g| g.description.as_str())
}

// ============================================================================
// Query helpers: extract flat lists from policy groups
// ============================================================================

/// Get all sensitive (deny.access) paths from platform-matching policy groups.
///
/// Returns a list of `(expanded_path, group_description)` tuples suitable for
/// display in `nono why`. Paths are expanded (~ -> $HOME, $TMPDIR -> value).
pub fn get_sensitive_paths(policy: &Policy) -> Result<Vec<(String, String)>> {
    let mut result = Vec::new();

    for group in policy.groups.values() {
        if !group_matches_platform(group) {
            continue;
        }
        if let Some(deny) = &group.deny {
            for path_str in &deny.access {
                let expanded = expand_path(path_str)?;
                result.push((
                    expanded.to_string_lossy().into_owned(),
                    group.description.clone(),
                ));
            }
        }
    }

    Ok(result)
}

/// Get all dangerous (deny.commands) from platform-matching policy groups.
///
/// Returns a flat set of command names that should be blocked.
pub fn get_dangerous_commands(policy: &Policy) -> HashSet<String> {
    let mut result = HashSet::new();

    for group in policy.groups.values() {
        if !group_matches_platform(group) {
            continue;
        }
        if let Some(deny) = &group.deny {
            for cmd in &deny.commands {
                result.insert(cmd.clone());
            }
        }
    }

    result
}

/// Get all system read paths from allow.read groups for the current platform.
///
/// Collects `allow.read` entries from all platform-matching groups. Paths are
/// returned unexpanded (with `~` and `$TMPDIR` intact) for caller to expand.
/// Used by learn mode (Linux only).
#[cfg(target_os = "linux")]
pub fn get_system_read_paths(policy: &Policy) -> Vec<String> {
    let mut result = Vec::new();

    for group in policy.groups.values() {
        if !group_matches_platform(group) {
            continue;
        }
        if let Some(allow) = &group.allow {
            result.extend(allow.read.iter().cloned());
        }
    }

    result
}

/// Validate that trust_groups does not attempt to remove any required groups.
///
/// Required groups have `required: true` in policy.json and cannot be excluded
/// by profiles or user configuration. Returns an error listing all violations.
pub fn validate_trust_groups(policy: &Policy, trust_groups: &[String]) -> Result<()> {
    let violations: Vec<&String> = trust_groups
        .iter()
        .filter(|name| policy.groups.get(name.as_str()).is_some_and(|g| g.required))
        .collect();

    if violations.is_empty() {
        return Ok(());
    }

    let names = violations
        .iter()
        .map(|n| format!("'{}'", n))
        .collect::<Vec<_>>()
        .join(", ");

    Err(NonoError::ConfigParse(format!(
        "Cannot exclude required groups via trust_groups: {}",
        names
    )))
}

/// Common deny + system groups shared by all sandbox invocations.
///
/// Reads from the embedded policy.json `base_groups` array. This is the base
/// set of groups that both `from_args()` (non-profile CLI) and built-in
/// profiles use. Profiles extend this with additional groups.
pub fn base_groups() -> Result<Vec<String>> {
    let policy = load_embedded_policy()?;
    Ok(policy.base_groups)
}

/// Get a built-in profile from embedded policy.json.
///
/// Returns `None` if the profile name is not defined in policy.json.
pub fn get_policy_profile(name: &str) -> Result<Option<profile::Profile>> {
    let policy = load_embedded_policy()?;
    match policy.profiles.get(name) {
        Some(def) => Ok(Some(def.to_profile(&policy.base_groups, &policy)?)),
        None => Ok(None),
    }
}

/// List all built-in profile names from embedded policy.json.
pub fn list_policy_profiles() -> Result<Vec<String>> {
    let policy = load_embedded_policy()?;
    let mut names: Vec<String> = policy.profiles.keys().cloned().collect();
    names.sort();
    Ok(names)
}

/// Load the embedded policy and return the parsed Policy struct.
///
/// Convenience wrapper that loads from the compile-time embedded JSON.
pub fn load_embedded_policy() -> Result<Policy> {
    let json = crate::config::embedded::embedded_policy_json();
    load_policy(json)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_policy_json() -> &'static str {
        r#"{
            "meta": { "version": 2, "schema_version": "2.0" },
            "groups": {
                "test_read": {
                    "description": "Test read group",
                    "allow": { "read": ["/tmp"] }
                },
                "test_deny": {
                    "description": "Test deny group",
                    "deny": { "access": ["/nonexistent/test/path"] }
                },
                "test_commands": {
                    "description": "Test command blocking",
                    "deny": { "commands": ["rm", "dd"] }
                },
                "test_macos_only": {
                    "description": "macOS-only group",
                    "platform": "macos",
                    "allow": { "read": ["/tmp"] }
                },
                "test_linux_only": {
                    "description": "Linux-only group",
                    "platform": "linux",
                    "allow": { "read": ["/tmp"] }
                },
                "test_unlink": {
                    "description": "Unlink protection",
                    "deny": { "unlink": true }
                },
                "test_symlinks": {
                    "description": "Symlink test",
                    "symlink_pairs": { "/etc": "/private/etc" }
                },
                "test_required": {
                    "description": "Required deny group",
                    "required": true,
                    "deny": { "access": ["/nonexistent/required/path"] }
                }
            }
        }"#
    }

    #[test]
    fn test_load_policy() {
        let policy = load_policy(sample_policy_json());
        assert!(policy.is_ok());
        let policy = policy.expect("parse failed");
        assert_eq!(policy.meta.version, 2);
        assert_eq!(policy.groups.len(), 8);
    }

    #[test]
    fn test_load_embedded_policy() {
        let json = crate::config::embedded::embedded_policy_json();
        let policy = load_policy(json);
        assert!(policy.is_ok(), "Failed to parse embedded policy.json");
        let policy = policy.expect("parse failed");
        assert!(policy.meta.version >= 2);
        assert!(!policy.groups.is_empty());
    }

    #[test]
    fn test_resolve_read_group() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let mut caps = CapabilitySet::new();
        let resolved = resolve_groups(&policy, &["test_read".to_string()], &mut caps);
        assert!(resolved.is_ok());
        // /tmp should exist on all platforms
        assert!(caps.has_fs());
    }

    #[test]
    fn test_resolve_deny_group() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let mut caps = CapabilitySet::new();
        let resolved =
            resolve_groups(&policy, &["test_deny".to_string()], &mut caps).expect("resolve failed");

        // Deny paths should always be collected regardless of platform
        assert!(!resolved.deny_paths.is_empty());

        if cfg!(target_os = "macos") {
            // On macOS, should have platform rules for deny
            assert!(!caps.platform_rules().is_empty());
            let rules = caps.platform_rules().join("\n");
            assert!(rules.contains("deny file-read-data"));
            assert!(rules.contains("deny file-write*"));
            assert!(rules.contains("allow file-read-metadata"));
        } else {
            // On Linux, no platform rules (Landlock has no deny semantics)
            assert!(caps.platform_rules().is_empty());
        }
    }

    #[test]
    fn test_resolve_command_group() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let mut caps = CapabilitySet::new();
        let resolved = resolve_groups(&policy, &["test_commands".to_string()], &mut caps);
        assert!(resolved.is_ok());
        assert!(caps.blocked_commands().contains(&"rm".to_string()));
        assert!(caps.blocked_commands().contains(&"dd".to_string()));
    }

    #[test]
    fn test_platform_filtering() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let mut caps = CapabilitySet::new();

        // Resolve both platform groups - only the matching one should be active
        let resolved = resolve_groups(
            &policy,
            &["test_macos_only".to_string(), "test_linux_only".to_string()],
            &mut caps,
        )
        .expect("resolve failed");

        // Exactly one should have been resolved
        assert_eq!(resolved.names.len(), 1);

        if cfg!(target_os = "macos") {
            assert_eq!(resolved.names[0], "test_macos_only");
        } else {
            assert_eq!(resolved.names[0], "test_linux_only");
        }
    }

    #[test]
    fn test_unknown_group_error() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let mut caps = CapabilitySet::new();
        let result = resolve_groups(&policy, &["nonexistent_group".to_string()], &mut caps);
        assert!(result.is_err());
    }

    #[test]
    fn test_unlink_protection() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let mut caps = CapabilitySet::new();
        let resolved = resolve_groups(&policy, &["test_unlink".to_string()], &mut caps);
        assert!(resolved.is_ok());

        if cfg!(target_os = "macos") {
            assert!(caps
                .platform_rules()
                .iter()
                .any(|r| r.contains("deny file-write-unlink")));
        } else {
            // On Linux, unlink protection is Seatbelt-only
            assert!(!caps
                .platform_rules()
                .iter()
                .any(|r| r.contains("deny file-write-unlink")));
        }
    }

    #[test]
    fn test_symlink_pairs() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let mut caps = CapabilitySet::new();
        let resolved = resolve_groups(&policy, &["test_symlinks".to_string()], &mut caps);
        assert!(resolved.is_ok());

        if cfg!(target_os = "macos") {
            assert!(caps.platform_rules().iter().any(|r| r.contains("/etc")));
        } else {
            // On Linux, symlink pairs are Seatbelt-only
            assert!(caps.platform_rules().is_empty());
        }
    }

    #[test]
    fn test_expand_path_tilde() {
        let path = expand_path("~/.ssh").expect("HOME must be valid");
        assert!(path.to_string_lossy().contains(".ssh"));
        assert!(!path.to_string_lossy().starts_with("~"));
    }

    #[test]
    fn test_expand_path_tmpdir() {
        let path = expand_path("$TMPDIR").expect("TMPDIR must be valid");
        assert!(!path.to_string_lossy().starts_with("$"));
    }

    #[test]
    fn test_expand_path_absolute() {
        let path = expand_path("/usr/bin").expect("absolute path needs no env");
        assert_eq!(path, PathBuf::from("/usr/bin"));
    }

    #[test]
    fn test_list_groups() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let names = list_groups(&policy);
        assert!(names.contains(&"test_read"));
        assert!(names.contains(&"test_deny"));
    }

    #[test]
    fn test_group_description() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        assert_eq!(
            group_description(&policy, "test_read"),
            Some("Test read group")
        );
        assert_eq!(group_description(&policy, "nonexistent"), None);
    }

    #[test]
    fn test_deny_access_collects_path_and_generates_rules() {
        let mut caps = CapabilitySet::new();
        let mut deny_paths = Vec::new();
        add_deny_access_rules("/nonexistent/test/deny", &mut caps, &mut deny_paths)
            .expect("expand_path should succeed for absolute paths");

        // Deny path should always be collected regardless of platform
        assert_eq!(deny_paths.len(), 1);
        assert_eq!(deny_paths[0], PathBuf::from("/nonexistent/test/deny"));

        if cfg!(target_os = "macos") {
            // On macOS, Seatbelt platform rules should be generated
            let rules = caps.platform_rules();
            assert_eq!(rules.len(), 3);
            assert!(rules[0].contains("allow file-read-metadata"));
            assert!(rules[1].contains("deny file-read-data"));
            assert!(rules[2].contains("deny file-write*"));
        } else {
            // On Linux, no platform rules generated (Landlock has no deny semantics)
            assert!(caps.platform_rules().is_empty());
        }
    }

    #[test]
    fn test_escape_seatbelt_path() {
        assert_eq!(
            escape_seatbelt_path("/simple/path").expect("simple path"),
            "/simple/path"
        );
        assert_eq!(
            escape_seatbelt_path("/path with\\slash").expect("backslash"),
            "/path with\\\\slash"
        );
        assert_eq!(
            escape_seatbelt_path("/path\"quoted").expect("quote"),
            "/path\\\"quoted"
        );
    }

    #[test]
    fn test_escape_seatbelt_path_rejects_control_chars() {
        assert!(escape_seatbelt_path("/path\nwith\nnewlines").is_err());
        assert!(escape_seatbelt_path("/path\rwith\rreturns").is_err());
        assert!(escape_seatbelt_path("/path\0with\0nulls").is_err());
        assert!(escape_seatbelt_path("/path\twith\ttabs").is_err());
        assert!(escape_seatbelt_path("/path\x0bwith\x0cfeeds").is_err());
        assert!(escape_seatbelt_path("/path\x1bwith\x1bescape").is_err());
        assert!(escape_seatbelt_path("/path\x7fwith\x7fdel").is_err());
    }

    #[test]
    fn test_escape_seatbelt_path_injection_via_newline() {
        let malicious = "/tmp/evil\n(allow file-read* (subpath \"/\"))";
        // Control characters are now rejected outright
        assert!(escape_seatbelt_path(malicious).is_err());
    }

    #[test]
    fn test_escape_seatbelt_path_injection_via_quote() {
        let malicious = "/tmp/evil\")(allow file-read* (subpath \"/\"))(\"";
        let escaped = escape_seatbelt_path(malicious).expect("no control chars");
        let chars: Vec<char> = escaped.chars().collect();
        for (i, &c) in chars.iter().enumerate() {
            if c == '"' {
                assert!(
                    i > 0 && chars[i - 1] == '\\',
                    "unescaped quote at position {}",
                    i
                );
            }
        }
    }

    #[test]
    fn test_validate_deny_overlaps_detects_conflict() {
        use nono::FsCapability;

        let mut caps = CapabilitySet::new();
        // Allow /tmp (parent)
        let cap = FsCapability::new_dir(std::path::Path::new("/tmp"), AccessMode::Read)
            .expect("/tmp must exist");
        caps.add_fs(cap);

        // Deny /tmp/secret (child of allowed parent)
        let deny_paths = vec![PathBuf::from("/tmp/secret")];

        // On macOS: no-op (Seatbelt handles deny-within-allow natively)
        // On Linux: would warn, but we can't assert on warn!() easily
        // Instead, verify the detection logic directly
        if cfg!(target_os = "linux") {
            // Manually check the overlap detection logic
            let has_overlap = deny_paths.iter().any(|deny| {
                caps.fs_capabilities().iter().any(|cap| {
                    !cap.is_file && deny.starts_with(&cap.resolved) && *deny != cap.resolved
                })
            });
            assert!(
                has_overlap,
                "Should detect /tmp/secret overlapping with /tmp"
            );
        }

        // macOS: no-op, Linux: hard error
        if cfg!(target_os = "linux") {
            let err = validate_deny_overlaps(&deny_paths, &caps)
                .expect_err("Expected overlap to fail on Linux");
            assert!(
                err.to_string().contains("Landlock deny-overlap"),
                "Expected deny-overlap error message, got: {err}"
            );
        } else {
            validate_deny_overlaps(&deny_paths, &caps).expect("no-op on macOS");
        }
    }

    #[test]
    fn test_validate_deny_overlaps_no_false_positive() {
        use nono::FsCapability;

        let mut caps = CapabilitySet::new();
        // Allow /tmp
        let cap = FsCapability::new_dir(std::path::Path::new("/tmp"), AccessMode::Read)
            .expect("/tmp must exist");
        caps.add_fs(cap);

        // Deny /home/secret (NOT under /tmp — no overlap)
        let deny_paths = vec![PathBuf::from("/home/secret")];

        // Should not detect overlap
        let has_overlap = deny_paths.iter().any(|deny| {
            caps.fs_capabilities()
                .iter()
                .any(|cap| !cap.is_file && deny.starts_with(&cap.resolved) && *deny != cap.resolved)
        });
        assert!(
            !has_overlap,
            "Should not detect overlap for unrelated paths"
        );

        validate_deny_overlaps(&deny_paths, &caps).expect("No overlap should succeed");
    }

    #[test]
    fn test_validate_deny_overlaps_group_overlap_warn_only() {
        use nono::FsCapability;

        let mut caps = CapabilitySet::new();
        let mut cap = FsCapability::new_dir(std::path::Path::new("/tmp"), AccessMode::Read)
            .expect("/tmp must exist");
        cap.source = CapabilitySource::Group("user_tools".to_string());
        caps.add_fs(cap);

        let deny_paths = vec![PathBuf::from("/tmp/secret")];

        // Group/system overlaps are warning-only. Fatal errors are reserved for
        // explicit user intent (CLI/profile), where deny-within-allow is likely accidental.
        validate_deny_overlaps(&deny_paths, &caps)
            .expect("group overlap should not hard-fail validation");
    }

    #[test]
    fn test_all_groups_no_deny_within_allow_overlap() {
        // Invariant: across ALL Linux-applicable groups in the policy, no
        // deny.access path may be equal to or a child of any allow path.
        // Landlock is strictly allow-list: it cannot deny a path that falls
        // under an allowed subtree, and allowing + denying the same directory
        // means the allow wins. Both cases silently disable the deny.
        //
        // We check every group (not just base_groups) because profiles can
        // combine arbitrary groups, and validate_deny_overlaps is warn-only
        // for group-sourced capabilities at runtime. This test is the real
        // safety net for the embedded policy.
        //
        // We filter to Linux-applicable groups (platform: None or "linux")
        // and check directly from parsed policy so this catches regressions
        // on all CI platforms (including macOS).
        let policy = load_embedded_policy().expect("embedded policy must load");

        let is_linux_applicable =
            |g: &Group| g.platform.is_none() || g.platform.as_deref() == Some("linux");

        let mut deny_paths: Vec<(String, PathBuf)> = Vec::new();
        let mut allow_paths: Vec<(String, PathBuf)> = Vec::new();

        for (name, group) in &policy.groups {
            if !is_linux_applicable(group) {
                continue;
            }

            if let Some(deny) = &group.deny {
                for p in &deny.access {
                    let expanded = expand_path(p).unwrap_or_else(|e| {
                        panic!("expand_path({p}) failed in group '{name}': {e}")
                    });
                    deny_paths.push((name.clone(), expanded));
                }
            }

            if let Some(allow) = &group.allow {
                for p in allow
                    .read
                    .iter()
                    .chain(&allow.write)
                    .chain(&allow.readwrite)
                {
                    let expanded = expand_path(p).unwrap_or_else(|e| {
                        panic!("expand_path({p}) failed in group '{name}': {e}")
                    });
                    allow_paths.push((name.clone(), expanded));
                }
            }
        }

        for (deny_group, deny_path) in &deny_paths {
            for (allow_group, allow_path) in &allow_paths {
                // Landlock is purely additive: if a path is allowed, denying
                // that same path or any child has no effect. This covers both
                // child overlaps (deny starts_with allow) and exact matches.
                assert!(
                    !deny_path.starts_with(allow_path),
                    "Deny-within-allow overlap on Linux: deny '{}' (group: {}) \
                     is under or equal to allowed '{}' (group: {}). Landlock \
                     cannot enforce this. Narrow the allow path or move the \
                     deny to never_grant.",
                    deny_path.display(),
                    deny_group,
                    allow_path.display(),
                    allow_group,
                );
            }
        }
    }

    #[test]
    fn test_resolve_deny_group_collects_deny_paths() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let mut caps = CapabilitySet::new();
        let resolved =
            resolve_groups(&policy, &["test_deny".to_string()], &mut caps).expect("resolve failed");

        // deny_paths should be populated with the expanded deny.access paths
        assert_eq!(resolved.deny_paths.len(), 1);
        assert!(
            resolved.deny_paths[0]
                .to_string_lossy()
                .contains("nonexistent/test/path"),
            "Expected deny path to contain 'nonexistent/test/path', got: {}",
            resolved.deny_paths[0].display()
        );
    }

    #[test]
    fn test_validate_trust_groups_allows_non_required() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let result = validate_trust_groups(&policy, &["test_read".to_string()]);
        assert!(result.is_ok(), "Non-required group should be removable");
    }

    #[test]
    fn test_validate_trust_groups_rejects_required() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let result = validate_trust_groups(&policy, &["test_required".to_string()]);
        assert!(result.is_err(), "Required group must not be removable");
        let err = result.expect_err("expected error");
        assert!(
            err.to_string().contains("test_required"),
            "Error should name the group: {}",
            err
        );
    }

    #[test]
    fn test_validate_trust_groups_ignores_unknown() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let result = validate_trust_groups(&policy, &["nonexistent_group".to_string()]);
        assert!(
            result.is_ok(),
            "Unknown groups should not trigger required check"
        );
    }

    #[test]
    fn test_embedded_policy_required_groups() {
        let policy = load_embedded_policy().expect("embedded policy");
        let required: Vec<&str> = policy
            .groups
            .iter()
            .filter(|(_, g)| g.required)
            .map(|(name, _)| name.as_str())
            .collect();
        assert!(
            required.contains(&"deny_credentials"),
            "deny_credentials must be required"
        );
        assert!(
            required.contains(&"deny_shell_configs"),
            "deny_shell_configs must be required"
        );
    }
}
