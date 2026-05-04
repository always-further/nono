//! Hook installation for agent integrations
//!
//! This module handles automatic installation of hooks for AI agents
//! like Claude Code. When a profile defines hooks, nono installs them
//! to the appropriate location (e.g., ~/.claude/hooks/).

use crate::profile::HookConfig;
use nono::{NonoError, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Embedded hook scripts (compiled into binary)
mod embedded {
    /// nono-hook.sh for Claude Code integration
    pub const NONO_HOOK_SH: &str = include_str!(concat!(env!("OUT_DIR"), "/nono-hook.sh"));
}

/// Get embedded hook script by name
fn get_embedded_script(name: &str) -> Option<&'static str> {
    match name {
        "nono-hook.sh" => Some(embedded::NONO_HOOK_SH),
        _ => None,
    }
}

/// Result of hook installation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookInstallResult {
    /// Hook was installed for the first time
    Installed,
    /// Hook was already installed and up to date
    AlreadyInstalled,
    /// Hook was updated to a newer version
    Updated,
    /// Target not recognized, skipped
    Skipped,
}

/// Install hooks for a target application
///
/// This is called when a profile with hooks is loaded. It:
/// 1. Creates the hooks directory if needed
/// 2. Installs the hook script (if missing or outdated)
/// 3. Registers the hook in the application's settings
///
/// Returns the installation result so callers can inform the user.
pub fn install_hooks(
    profile_name: Option<&str>,
    target: &str,
    config: &HookConfig,
) -> Result<HookInstallResult> {
    match target {
        "claude-code" => install_claude_code_hook(profile_name, config),
        other => {
            tracing::warn!(
                "Unknown hook target '{}', skipping hook installation",
                other
            );
            Ok(HookInstallResult::Skipped)
        }
    }
}

/// Install Claude Code hook
///
/// Installs to ~/.claude/hooks/ and updates ~/.claude/settings.json
fn install_claude_code_hook(
    profile_name: Option<&str>,
    config: &HookConfig,
) -> Result<HookInstallResult> {
    let home = crate::config::nono_home_dir()?;
    let hooks_dir = home.join(".claude").join("hooks");
    let script_path = hooks_dir.join(&config.script);
    let settings_path = home.join(".claude").join("settings.json");

    let script_content = resolve_hook_script(profile_name, config)?;

    // Create hooks directory if needed
    if !hooks_dir.exists() {
        tracing::info!(
            "Creating Claude Code hooks directory: {}",
            hooks_dir.display()
        );
        fs::create_dir_all(&hooks_dir).map_err(|e| {
            NonoError::HookInstall(format!(
                "Failed to create hooks directory {}: {}",
                hooks_dir.display(),
                e
            ))
        })?;
    }

    // Check installation state
    let script_existed = script_path.exists();
    let needs_install = if script_existed {
        // Check if script is outdated by comparing content
        let existing = fs::read_to_string(&script_path).unwrap_or_default();
        existing != script_content
    } else {
        true
    };

    if needs_install {
        tracing::info!("Installing hook script: {}", script_path.display());
        fs::write(&script_path, script_content).map_err(|e| {
            NonoError::HookInstall(format!(
                "Failed to write hook script {}: {}",
                script_path.display(),
                e
            ))
        })?;

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&script_path)
                .map_err(|e| NonoError::HookInstall(format!("Failed to get permissions: {}", e)))?
                .permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script_path, perms)
                .map_err(|e| NonoError::HookInstall(format!("Failed to set permissions: {}", e)))?;
        }
    } else {
        tracing::debug!("Hook script already installed and up to date");
    }

    // Update settings.json to register the hook
    let settings_modified = update_claude_settings(&settings_path, config)?;

    // Port of upstream v0.37.1 `97f7294` (fix(claude-code): enable token
    // refresh via .claude.json symlink, D-07). Claude Code performs atomic
    // writes to `~/.claude.json` via dynamically-named temp files
    // (`~/.claude.json.tmp.<pid>.<ts>`). Landlock/Seatbelt cannot grant
    // permission for these unpredictable filenames in `~/`, so token
    // refreshes silently fail. Fix: redirect `~/.claude.json` to
    // `~/.claude/claude.json` via a symlink. Claude Code resolves symlinks
    // before computing the temp file path, so temps land in `~/.claude/`
    // which is already readwrite inside the sandbox. This is best-effort
    // at hook-install time — failures are logged and the install proceeds.
    if let Err(e) = install_claude_json_symlink(&home) {
        tracing::warn!(
            "Failed to install ~/.claude.json symlink (token refresh may require manual setup): {}",
            e
        );
    }

    // Determine result based on what changed
    let result = if needs_install && !script_existed {
        HookInstallResult::Installed
    } else if needs_install && script_existed {
        HookInstallResult::Updated
    } else if settings_modified {
        // Script was up to date but settings needed updating
        HookInstallResult::Installed
    } else {
        HookInstallResult::AlreadyInstalled
    };

    Ok(result)
}

/// Install the `~/.claude.json` → `~/.claude/claude.json` redirect symlink.
///
/// Ported from upstream v0.37.1 `97f7294`. Atomic-write workflows in Claude
/// Code create temp files next to `~/.claude.json` — paths the sandbox can
/// not predict. Pointing `~/.claude.json` at `~/.claude/claude.json` via a
/// symlink moves the temp-file blast radius into the already-writable
/// claude-code config root.
///
/// Security:
/// - The resolved symlink target is canonicalized and validated to stay
///   inside `<home>/.claude` (the claude-code config root). Any target
///   escaping the root is rejected with `NonoError::InvalidConfig` (see
///   `validate_symlink_target_under_root`). This closes CLAUDE.md §
///   "Common Footguns" #1 (string-based path prefix check) by using
///   `Path::starts_with` on canonicalized components.
///
/// Platform dispatch:
/// - Unix (Linux/macOS): `std::os::unix::fs::symlink`. Propagates IO
///   errors — these are genuine setup failures.
/// - Windows: `std::os::windows::fs::symlink_file`. Unprivileged hosts
///   (no Developer Mode, no `SeCreateSymbolicLinkPrivilege`) cannot
///   create symlinks; the error is caught, logged via `tracing::warn!`,
///   and the function returns `Ok(())`. Runtime behavior on such hosts
///   is unchanged from the pre-port state — token refresh simply falls
///   back to the same path it takes today (no symlink, no redirect).
#[must_use = "the returned Result signals install-time failure and is caught by the caller"]
fn install_claude_json_symlink(home: &Path) -> Result<()> {
    let claude_json = home.join(".claude.json");
    let claude_dir = home.join(".claude");
    let redirect_target = claude_dir.join("claude.json");

    // Ensure the claude-code config root exists; without it the symlink
    // target cannot be canonicalized.
    fs::create_dir_all(&claude_dir).map_err(|e| {
        NonoError::HookInstall(format!(
            "Failed to create claude-code config root {}: {}",
            claude_dir.display(),
            e
        ))
    })?;

    // Validate the intended redirect target stays inside the claude-code
    // config root BEFORE creating the symlink. This is the path-traversal
    // guard — canonicalize both and use Path::starts_with (component
    // comparison, NOT string starts_with). Per upstream 97f7294 the target
    // is always `<home>/.claude/claude.json`, but defensive validation
    // protects against future changes to this constant.
    validate_symlink_target_under_root(&redirect_target, &claude_dir)?;

    // If the symlink already exists (regardless of where it points), leave
    // it alone. A previous nono run — or the user — already set it up.
    if claude_json.is_symlink() {
        tracing::debug!(
            "~/.claude.json symlink already present at {}, leaving unchanged",
            claude_json.display()
        );
        return Ok(());
    }

    // Pre-seed the target so the sandbox can attach a path rule to it even
    // on first-ever run. If a regular file already exists at the source,
    // move it into the target location first so the user's existing state
    // survives the redirect.
    if claude_json.exists() {
        if let Err(e) = fs::rename(&claude_json, &redirect_target) {
            return Err(NonoError::HookInstall(format!(
                "Failed to move existing {} to {}: {}",
                claude_json.display(),
                redirect_target.display(),
                e
            )));
        }
    } else if !redirect_target.exists() {
        // Pre-create an empty file at the target so sandbox rules can bind.
        fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&redirect_target)
            .map(|_| ())
            .or_else(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    Ok(())
                } else {
                    Err(NonoError::HookInstall(format!(
                        "Failed to pre-create claude.json target {}: {}",
                        redirect_target.display(),
                        e
                    )))
                }
            })?;
    }

    // Use the relative link target upstream uses: ".claude/claude.json".
    // This keeps the symlink portable if $HOME moves, and matches the
    // upstream 97f7294 layout exactly so claude-code's symlink-resolving
    // temp-file logic works identically.
    let link_target = Path::new(".claude").join("claude.json");

    create_symlink_platform(&link_target, &claude_json)
}

/// Canonicalize the symlink target and assert it stays inside `root`.
///
/// Uses `Path::starts_with` (component-wise comparison) per CLAUDE.md §
/// "Common Footguns" #1 — string-based `starts_with` on paths is a known
/// vulnerability (e.g. `/home/victim` matching `/home/victimhacker`).
/// Both sides are canonicalized first to strip `..`, symlinks, and
/// platform-specific prefix differences.
///
/// Returns `NonoError::HookInstall` if the target resolves to a path that
/// does not start with `root`. (The upstream 97f7294 patch predates the
/// fork's error enum; `HookInstall` is the closest config-shaped variant
/// per `crates/nono/src/error.rs`. The plan text suggested
/// `NonoError::InvalidConfig` — that variant does not exist in the fork,
/// so `HookInstall` is used instead and tested against explicitly below.)
/// Absent targets are canonicalized by resolving their parent directory
/// (the target may not yet exist on first install).
fn validate_symlink_target_under_root(target: &Path, root: &Path) -> Result<()> {
    let canonical_root = fs::canonicalize(root).map_err(|e| {
        NonoError::HookInstall(format!(
            "claude-code config root {} is not canonicalizable: {}",
            root.display(),
            e
        ))
    })?;

    // Canonicalize the target's parent (it may not exist yet), then
    // append the final component. This keeps validation deterministic
    // even when the target file is about to be created.
    let target_parent = target.parent().ok_or_else(|| {
        NonoError::HookInstall(format!(
            "claude.json target {} has no parent directory",
            target.display()
        ))
    })?;
    let canonical_parent = fs::canonicalize(target_parent).map_err(|e| {
        NonoError::HookInstall(format!(
            "claude.json target parent {} is not canonicalizable: {}",
            target_parent.display(),
            e
        ))
    })?;
    let target_name = target.file_name().ok_or_else(|| {
        NonoError::HookInstall(format!(
            "claude.json target {} has no file name component",
            target.display()
        ))
    })?;
    let canonical_target = canonical_parent.join(target_name);

    if !canonical_target.starts_with(&canonical_root) {
        return Err(NonoError::HookInstall(format!(
            "claude.json symlink target escapes config root: {} is not under {}",
            canonical_target.display(),
            canonical_root.display()
        )));
    }
    Ok(())
}

/// Platform-specific symlink creation with Windows fail-open.
///
/// Linux/macOS: propagates IO errors — the sandbox genuinely needs the
/// redirect and a failure here is a real setup bug.
///
/// Windows: catches IO errors (most commonly the unprivileged-symlink
/// failure when Developer Mode is off and the process lacks
/// `SeCreateSymbolicLinkPrivilege`), emits `tracing::warn!`, and returns
/// `Ok(())`. This is a deliberate fail-open: on such hosts the runtime
/// behavior is unchanged from the pre-port state — the user simply does
/// not get the upstream token-refresh fix until they enable Developer
/// Mode. The install itself must not hard-fail on typical Windows
/// machines.
#[cfg(unix)]
fn create_symlink_platform(link_target: &Path, link_path: &Path) -> Result<()> {
    use std::os::unix::fs::symlink;
    symlink(link_target, link_path).map_err(|e| {
        NonoError::HookInstall(format!(
            "Failed to create ~/.claude.json symlink ({} -> {}): {}",
            link_path.display(),
            link_target.display(),
            e
        ))
    })
}

#[cfg(windows)]
fn create_symlink_platform(link_target: &Path, link_path: &Path) -> Result<()> {
    use std::os::windows::fs::symlink_file;
    match symlink_file(link_target, link_path) {
        Ok(()) => Ok(()),
        Err(e) => {
            tracing::warn!(
                "Failed to create ~/.claude.json symlink on Windows ({} -> {}): {}; \
                 claude-code token refresh may require manual setup or Developer Mode",
                link_path.display(),
                link_target.display(),
                e
            );
            Ok(())
        }
    }
}

/// Update Claude Code settings.json to register the hook
/// Returns true if settings were modified, false if hook was already registered
fn update_claude_settings(settings_path: &PathBuf, config: &HookConfig) -> Result<bool> {
    // Load existing settings or create new
    let mut settings: Value = if settings_path.exists() {
        let content = fs::read_to_string(settings_path).map_err(|e| {
            NonoError::HookInstall(format!(
                "Failed to read settings {}: {}",
                settings_path.display(),
                e
            ))
        })?;
        serde_json::from_str(&content).unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };

    // Ensure settings is an object
    let settings_obj = settings
        .as_object_mut()
        .ok_or_else(|| NonoError::HookInstall("settings.json is not a JSON object".to_string()))?;

    // Get or create hooks section
    if !settings_obj.contains_key("hooks") {
        settings_obj.insert("hooks".to_string(), json!({}));
    }
    let hooks = settings_obj
        .get_mut("hooks")
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| NonoError::HookInstall("hooks is not a JSON object".to_string()))?;

    // Get or create event array
    if !hooks.contains_key(&config.event) {
        hooks.insert(config.event.clone(), json!([]));
    }
    let event_hooks = hooks
        .get_mut(&config.event)
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| NonoError::HookInstall(format!("{} is not a JSON array", config.event)))?;

    // Build the hook command path (use $HOME for portability)
    let hook_command = format!("$HOME/.claude/hooks/{}", config.script);

    // Check if hook already registered
    let hook_exists = event_hooks.iter().any(|h| {
        if let Some(hooks_array) = h.get("hooks").and_then(|v| v.as_array()) {
            hooks_array.iter().any(|hook| {
                hook.get("command")
                    .and_then(|c| c.as_str())
                    .map(|c| c == hook_command)
                    .unwrap_or(false)
            })
        } else {
            false
        }
    });

    if !hook_exists {
        tracing::info!(
            "Registering hook for {} event with matcher '{}'",
            config.event,
            config.matcher
        );

        let hook_entry = json!({
            "matcher": config.matcher,
            "hooks": [{
                "type": "command",
                "command": hook_command
            }]
        });
        event_hooks.push(hook_entry);

        // Write updated settings
        let content = serde_json::to_string_pretty(&settings)
            .map_err(|e| NonoError::HookInstall(format!("Failed to serialize settings: {}", e)))?;
        fs::write(settings_path, content).map_err(|e| {
            NonoError::HookInstall(format!(
                "Failed to write settings {}: {}",
                settings_path.display(),
                e
            ))
        })?;

        tracing::info!("Updated {}", settings_path.display());
        Ok(true)
    } else {
        tracing::debug!("Hook already registered in settings.json");
        Ok(false)
    }
}

/// Install all hooks from a profile's hooks configuration
/// Returns a list of (target, result) pairs for each hook installed
pub fn install_profile_hooks(
    profile_name: Option<&str>,
    hooks: &HashMap<String, HookConfig>,
) -> Result<Vec<(String, HookInstallResult)>> {
    let mut results = Vec::new();
    for (target, config) in hooks {
        let result = install_hooks(profile_name, target, config)?;
        results.push((target.clone(), result));
    }
    Ok(results)
}

/// Resolve the script body for a hook, using the fallback chain
/// (package → user override → embedded).
///
/// 1. If a profile name is supplied and that profile is package-managed
///    (`crate::profile::get_package_for_profile` resolves a package store
///    directory), prefer the package's own `hooks/<script>` file.
/// 2. Otherwise, look for a user override at `<config-dir>/nono/hooks/<script>`.
/// 3. Finally, fall back to the script embedded in the binary.
fn resolve_hook_script(profile_name: Option<&str>, config: &HookConfig) -> Result<String> {
    if let Some(profile_name) = profile_name {
        if let Some(package_dir) = crate::profile::get_package_for_profile(profile_name) {
            let package_script = package_dir.join("hooks").join(&config.script);
            if package_script.exists() {
                return fs::read_to_string(&package_script).map_err(|e| {
                    NonoError::HookInstall(format!(
                        "Failed to read package hook script {}: {}",
                        package_script.display(),
                        e
                    ))
                });
            }
        }
    }

    let user_override = crate::package::nono_config_dir()?
        .join("hooks")
        .join(&config.script);
    if user_override.exists() {
        return fs::read_to_string(&user_override).map_err(|e| {
            NonoError::HookInstall(format!(
                "Failed to read user hook override {}: {}",
                user_override.display(),
                e
            ))
        });
    }

    get_embedded_script(&config.script)
        .map(ToOwned::to_owned)
        .ok_or_else(|| NonoError::HookInstall(format!("Unknown hook script: {}", config.script)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_embedded_script_exists() {
        assert!(get_embedded_script("nono-hook.sh").is_some());
        assert!(get_embedded_script("nonexistent.sh").is_none());
    }

    #[test]
    fn test_embedded_script_content() {
        let script = get_embedded_script("nono-hook.sh").expect("Script not found");
        assert!(script.contains("NONO_CAP_FILE"));
        assert!(script.contains("jq"));
    }

    /// Ported from upstream v0.37.1 `97f7294`. Hostile `claude.json` symlink
    /// targets that escape the claude-code config root MUST be rejected
    /// BEFORE any symlink is attempted. Uses a mocked config root inside a
    /// tempdir — no real filesystem traversal occurs. This is the
    /// path-traversal guard required by the plan's acceptance criteria.
    #[test]
    fn test_claude_json_rejects_path_traversal() {
        let root = tempdir().expect("tempdir for config root");

        // Create a sibling directory that is NOT under `root`. A hostile
        // symlink target pointing at this sibling must be rejected by
        // `validate_symlink_target_under_root`.
        let sibling = tempdir().expect("tempdir for sibling");
        let hostile_target = sibling.path().join("escaped.json");

        let err = validate_symlink_target_under_root(&hostile_target, root.path())
            .expect_err("path-traversal must fail-closed");

        assert!(
            matches!(err, NonoError::HookInstall(_)),
            "path-traversal must surface HookInstall error, got {:?}",
            err
        );

        let msg = err.to_string();
        assert!(
            msg.contains("escapes") || msg.contains("not under"),
            "error must explain the escape: {}",
            msg
        );
    }

    /// A legitimate target inside the claude-code config root must pass
    /// validation. Regression guard against an over-aggressive guard that
    /// rejects the real upstream-97f7294 redirect (`<root>/claude.json`).
    #[test]
    fn test_claude_json_accepts_target_inside_root() {
        let root = tempdir().expect("tempdir for config root");
        let legit_target = root.path().join("claude.json");

        validate_symlink_target_under_root(&legit_target, root.path())
            .expect("in-root target must be accepted");
    }

    /// On Windows, an unprivileged symlink attempt must NOT panic and must
    /// NOT propagate as an install failure — it must log + return Ok(()),
    /// matching the fork's documented fail-open behavior (CLAUDE.md §
    /// Platform-Specific Notes: "Windows symlink creation requires
    /// Developer Mode or elevation"). On Unix, this test verifies the
    /// happy path instead: the symlink is actually created.
    #[test]
    fn test_install_claude_json_symlink_does_not_panic() {
        let home = tempdir().expect("tempdir for fake home");

        // install_claude_json_symlink creates the claude-code config root
        // (`<home>/.claude/`) and wires up the symlink. On unprivileged
        // Windows it logs a warn and returns Ok(()); on Unix it creates
        // the symlink and returns Ok(()).
        let result = install_claude_json_symlink(home.path());
        assert!(
            result.is_ok(),
            "install must fail-open (Windows) or succeed (Unix), got: {:?}",
            result
        );

        // The claude-code config root must exist either way.
        let claude_dir = home.path().join(".claude");
        assert!(
            claude_dir.is_dir(),
            "claude-code config root must be created at {}",
            claude_dir.display()
        );

        // The redirect target must exist (either pre-created by the
        // install, or — on Windows fail-open — left in place for a later
        // privileged retry).
        let redirect_target = claude_dir.join("claude.json");
        assert!(
            redirect_target.exists(),
            "claude.json redirect target must be pre-created at {}",
            redirect_target.display()
        );

        // On Unix, the symlink itself must exist. On Windows we accept
        // either outcome (created if privileged, absent if not).
        #[cfg(unix)]
        {
            let claude_json = home.path().join(".claude.json");
            assert!(
                claude_json.is_symlink(),
                "~/.claude.json must be a symlink on Unix: {}",
                claude_json.display()
            );
        }
    }
}
