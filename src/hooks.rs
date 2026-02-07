//! Hook installation for agent integrations
//!
//! This module handles automatic installation of hooks for AI agents
//! like Claude Code. When a profile defines hooks, nono installs them
//! to the appropriate location (e.g., ~/.claude/hooks/).

use crate::error::{NonoError, Result};
use crate::profile::HookConfig;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

/// Embedded hook scripts (compiled into binary)
mod embedded {
    /// nono-hook.sh for Claude Code integration
    pub const NONO_HOOK_SH: &str = include_str!("../data/hooks/nono-hook.sh");
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
pub fn install_hooks(target: &str, config: &HookConfig) -> Result<HookInstallResult> {
    match target {
        "claude-code" => install_claude_code_hook(config),
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
fn install_claude_code_hook(config: &HookConfig) -> Result<HookInstallResult> {
    let home = xdg_home::home_dir().ok_or(NonoError::HomeNotFound)?;
    let hooks_dir = home.join(".claude").join("hooks");
    let script_path = hooks_dir.join(&config.script);
    let settings_path = home.join(".claude").join("settings.json");

    // Get embedded script content
    let script_content = get_embedded_script(&config.script)
        .ok_or_else(|| NonoError::HookInstall(format!("Unknown hook script: {}", config.script)))?;

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
    let settings_modified = update_claude_settings(&settings_path, config, &script_path)?;

    // Update CLAUDE.md with nono sandbox instructions
    let claude_md_path = home.join(".claude").join("CLAUDE.md");
    update_claude_md(&claude_md_path)?;

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

/// Update Claude Code settings.json to register the hook
/// Returns true if settings were modified, false if hook was already registered
fn update_claude_settings(
    settings_path: &PathBuf,
    config: &HookConfig,
    _script_path: &PathBuf,
) -> Result<bool> {
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

/// Nono sandbox section marker for CLAUDE.md
const NONO_SECTION_START: &str = "<!-- nono-sandbox-start -->";
const NONO_SECTION_END: &str = "<!-- nono-sandbox-end -->";

/// Content for the nono sandbox section in CLAUDE.md
const NONO_CLAUDE_MD_CONTENT: &str = r#"## Nono Sandbox - CRITICAL

**You are running inside the nono security sandbox.** This is a capability-based sandbox that CANNOT be bypassed or modified from within the session.

### On ANY "operation not permitted" or "EPERM" error:

**IMMEDIATELY tell the user:**
> This path is not accessible in the current nono sandbox session. You need to exit and restart with:
> `nono run --allow /path/to/needed -- claude`

**NEVER attempt:**
- Alternative file paths or locations
- Copying files to accessible directories
- Using sudo or permission changes
- Manual workarounds for the user to try
- ANY other approach besides restarting nono

The sandbox is a hard security boundary. Once applied, it cannot be expanded. The ONLY solution is to restart the session with additional --allow flags.
"#;

/// Update ~/.claude/CLAUDE.md with nono sandbox instructions
///
/// Adds or updates a nono-managed section in CLAUDE.md. This provides
/// upfront context to Claude about the sandbox restrictions.
fn update_claude_md(claude_md_path: &PathBuf) -> Result<()> {
    let nono_section = format!(
        "{}\n{}{}",
        NONO_SECTION_START, NONO_CLAUDE_MD_CONTENT, NONO_SECTION_END
    );

    let content = if claude_md_path.exists() {
        let existing = fs::read_to_string(claude_md_path).map_err(|e| {
            NonoError::HookInstall(format!(
                "Failed to read {}: {}",
                claude_md_path.display(),
                e
            ))
        })?;

        // Check if nono section already exists
        if existing.contains(NONO_SECTION_START) {
            // Replace existing section
            let start_idx = existing.find(NONO_SECTION_START);
            let end_idx = existing.find(NONO_SECTION_END);

            // Validate: both markers exist and end comes after start
            if let (Some(start), Some(end)) = (start_idx, end_idx) {
                if end > start {
                    let end_of_section = end + NONO_SECTION_END.len();
                    let before = &existing[..start];
                    let after = &existing[end_of_section..];
                    format!("{}\n\n{}{}", before.trim_end(), nono_section, after)
                } else {
                    // Markers in wrong order - malformed, append fresh
                    tracing::warn!("Malformed nono section markers in CLAUDE.md (end before start), appending fresh");
                    format!("{}\n\n{}", existing.trim_end(), nono_section)
                }
            } else {
                // Only one marker present - malformed, append fresh
                tracing::warn!(
                    "Malformed nono section in CLAUDE.md (missing marker), appending fresh"
                );
                format!("{}\n\n{}", existing.trim_end(), nono_section)
            }
        } else {
            // Append section
            format!("{}\n\n{}", existing.trim_end(), nono_section)
        }
    } else {
        // Create new file with just the nono section
        nono_section
    };

    // Atomic write: write to temp file, then rename
    let temp_path = claude_md_path.with_extension("md.tmp");
    fs::write(&temp_path, &content).map_err(|e| {
        NonoError::HookInstall(format!(
            "Failed to write temp file {}: {}",
            temp_path.display(),
            e
        ))
    })?;

    fs::rename(&temp_path, claude_md_path).map_err(|e| {
        // Clean up temp file on rename failure
        let _ = fs::remove_file(&temp_path);
        NonoError::HookInstall(format!(
            "Failed to rename temp file to {}: {}",
            claude_md_path.display(),
            e
        ))
    })?;

    tracing::info!("Updated {}", claude_md_path.display());
    Ok(())
}

/// Install all hooks from a profile's hooks configuration
/// Returns a list of (target, result) pairs for each hook installed
pub fn install_profile_hooks(
    hooks: &HashMap<String, HookConfig>,
) -> Result<Vec<(String, HookInstallResult)>> {
    let mut results = Vec::new();
    for (target, config) in hooks {
        let result = install_hooks(target, config)?;
        results.push((target.clone(), result));
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_script_exists() {
        assert!(get_embedded_script("nono-hook.sh").is_some());
        assert!(get_embedded_script("nonexistent.sh").is_none());
    }

    #[test]
    fn test_embedded_script_content() {
        let script = get_embedded_script("nono-hook.sh").unwrap();
        assert!(script.contains("NONO_CAP_FILE"));
        assert!(script.contains("jq"));
    }
}
