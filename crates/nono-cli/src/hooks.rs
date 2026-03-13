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
use std::path::PathBuf;

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
    let settings_modified = update_claude_settings(&settings_path, config)?;

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
        let script = get_embedded_script("nono-hook.sh").expect("Script not found");
        assert!(script.contains("NONO_CAP_FILE"));
        assert!(script.contains("jq"));
    }
}
