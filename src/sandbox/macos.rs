use crate::capability::{CapabilitySet, FsAccess};
use crate::error::{NonoError, Result};
use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;
use tracing::{debug, info};

// FFI bindings to macOS sandbox API
// These are private APIs but have been stable for years
// Reference: https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf

// Flags for sandbox_init
// 0 = raw profile string (what we use)
// SANDBOX_NAMED = 1 = use a named profile from disk
#[allow(dead_code)]
const SANDBOX_NAMED: u32 = 0x0001;

extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> i32;

    fn sandbox_free_error(errorbuf: *mut c_char);
}

/// Check if Seatbelt sandboxing is supported
pub fn is_supported() -> bool {
    // Seatbelt is available on all modern macOS versions
    true
}

/// Get information about sandbox support
pub fn support_info() -> String {
    "macOS Seatbelt sandbox available".to_string()
}

/// Get list of sensitive paths that should be denied read access
fn get_sensitive_paths() -> Vec<String> {
    let mut paths = vec![
        // SSH keys and config
        "~/.ssh".to_string(),
        // AWS credentials
        "~/.aws".to_string(),
        // GnuPG keys
        "~/.gnupg".to_string(),
        // Generic credentials directories
        "~/.credentials".to_string(),
        "~/.secrets".to_string(),
        // Cloud provider configs
        "~/.azure".to_string(),
        "~/.gcloud".to_string(),
        "~/.config/gcloud".to_string(),
        // Kubernetes configs
        "~/.kube".to_string(),
        // Docker configs (may contain registry credentials)
        "~/.docker".to_string(),
        // NPM tokens
        "~/.npmrc".to_string(),
        // Git credentials
        "~/.git-credentials".to_string(),
        // Netrc (FTP/HTTP credentials)
        "~/.netrc".to_string(),
        // Password managers
        "~/.password-store".to_string(),
        "~/.1password".to_string(),
        // Private keys directory
        "~/.keys".to_string(),
        "~/.pki".to_string(),
        // Terraform state (may contain secrets)
        "~/.terraform.d".to_string(),
        // Vault tokens
        "~/.vault-token".to_string(),
        // macOS Keychain (extra protection layer)
        "~/Library/Keychains".to_string(),
        // Shell configuration files (often contain API keys, tokens, secrets)
        "~/.zshrc".to_string(),
        "~/.zprofile".to_string(),
        "~/.zshenv".to_string(),
        "~/.zlogin".to_string(),
        "~/.zlogout".to_string(),
        "~/.bashrc".to_string(),
        "~/.bash_profile".to_string(),
        "~/.bash_login".to_string(),
        "~/.bash_logout".to_string(),
        "~/.profile".to_string(),
        // Shell history files (may contain sensitive commands)
        "~/.zsh_history".to_string(),
        "~/.bash_history".to_string(),
        "~/.history".to_string(),
        // Fish shell
        "~/.config/fish".to_string(),
        // Environment files
        "~/.env".to_string(),
        "~/.envrc".to_string(),
    ];

    // Expand ~ to actual home directory
    if let Ok(home) = std::env::var("HOME") {
        paths = paths.into_iter().map(|p| p.replace("~", &home)).collect();
    }

    paths
}

/// Generate a Seatbelt profile from capabilities
fn generate_profile(caps: &CapabilitySet) -> String {
    let mut profile = String::new();

    // Profile version
    profile.push_str("(version 1)\n");

    // Start with deny default, but we'll allow many things needed for basic operation
    profile.push_str("(deny default)\n");

    // Debug: log denials (comment out for production)
    // profile.push_str("(debug deny)\n");

    // Allow all process operations
    profile.push_str("(allow process*)\n");

    // Allow all system operations except what we specifically want to deny
    profile.push_str("(allow sysctl*)\n");
    profile.push_str("(allow mach*)\n");
    profile.push_str("(allow ipc*)\n");
    profile.push_str("(allow signal)\n");
    profile.push_str("(allow system*)\n");

    // File read permissions:
    // Allow all file reads EXCEPT sensitive credential paths
    // This is a pragmatic compromise: executables need broad read access to function,
    // but we explicitly protect high-value credential locations
    profile.push_str("(allow file-read*)\n");

    // Deny access to sensitive paths (credentials, keys, tokens)
    // These denials override the allow above
    for path in get_sensitive_paths() {
        let escaped_path = path.replace('\\', "\\\\").replace('"', "\\\"");
        profile.push_str(&format!(
            "(deny file-read* (subpath \"{}\"))\n",
            escaped_path
        ));
    }

    // Allow writes only to specific system paths and granted paths
    profile.push_str("(allow file-write*\n");
    profile.push_str("    (subpath \"/dev\")\n");
    profile.push_str("    (subpath \"/private/tmp\")\n");
    profile.push_str("    (subpath \"/tmp\")\n");
    profile.push_str("    (subpath \"/private/var/folders\")\n");
    profile.push_str(")\n");

    // Allow file ioctl for TTY
    profile.push_str("(allow file-ioctl)\n");

    // Add user-specified filesystem capabilities
    // Note: These come AFTER the deny rules, so explicit user grants can override
    // the sensitive path denials. This is intentional - if a user explicitly grants
    // access to ~/.ssh, we respect that decision.
    for cap in &caps.fs {
        let path = cap.resolved.display().to_string();
        // Escape any special characters in path
        let escaped_path = path.replace('\\', "\\\\").replace('"', "\\\"");

        // Use "literal" for files, "subpath" for directories
        let path_filter = if cap.is_file {
            format!("literal \"{}\"", escaped_path)
        } else {
            format!("subpath \"{}\"", escaped_path)
        };

        match cap.access {
            FsAccess::Read => {
                profile.push_str(&format!("(allow file-read* ({}))\n", path_filter));
            }
            FsAccess::Write => {
                profile.push_str(&format!("(allow file-write* ({}))\n", path_filter));
            }
            FsAccess::ReadWrite => {
                profile.push_str(&format!(
                    "(allow file-read* file-write* ({}))\n",
                    path_filter
                ));
            }
        }
    }

    // Allow read access to user's home directory essentials
    // (library caches, preferences, etc. needed for many tools)
    if let Ok(home) = std::env::var("HOME") {
        let home_escaped = home.replace('\\', "\\\\").replace('"', "\\\"");
        profile.push_str(&format!(
            "(allow file-read* (subpath \"{}/Library\"))\n",
            home_escaped
        ));
        profile.push_str(&format!(
            "(allow file-write* (subpath \"{}/Library/Caches\"))\n",
            home_escaped
        ));
        profile.push_str(&format!(
            "(allow file-write* (subpath \"{}/Library/Logs\"))\n",
            home_escaped
        ));
    }

    // Block destructive file operations globally
    // These deny rules prevent file deletion and truncation as defense-in-depth
    // against destructive commands like `rm -rf` or accidental data loss.
    // Note: These use file-write-unlink for file deletion.
    // Seatbelt doesn't have separate truncate operation, but file-write-mode
    // controls the ability to modify file contents (including truncation via open with O_TRUNC).
    profile.push_str("(deny file-write-unlink)\n");

    // Network rules
    // Note: macOS Seatbelt supports some filtering (tcp/udp, local/remote, ports)
    // but not per-host filtering. For that, a proxy-based approach is needed.
    if caps.net_block {
        // Network blocked
        profile.push_str("(deny network*)\n");
    } else {
        // Network access enabled (default) - allow outbound, inbound, and bind
        profile.push_str("(allow network-outbound)\n");
        profile.push_str("(allow network-inbound)\n");
        profile.push_str("(allow network-bind)\n");
    }

    profile
}

/// Apply Seatbelt sandbox with the given capabilities
pub fn apply(caps: &CapabilitySet) -> Result<()> {
    let profile = generate_profile(caps);

    debug!("Generated Seatbelt profile:\n{}", profile);

    let profile_cstr = CString::new(profile)
        .map_err(|e| NonoError::SandboxInit(format!("Invalid profile string: {}", e)))?;

    let mut error_buf: *mut c_char = ptr::null_mut();

    // Use 0 flag for raw profile string (not a named profile)
    let result = unsafe {
        sandbox_init(
            profile_cstr.as_ptr(),
            0, // Raw profile mode
            &mut error_buf,
        )
    };

    if result != 0 {
        let error_msg = if !error_buf.is_null() {
            let msg = unsafe {
                std::ffi::CStr::from_ptr(error_buf)
                    .to_string_lossy()
                    .into_owned()
            };
            unsafe { sandbox_free_error(error_buf) };
            msg
        } else {
            format!("sandbox_init returned error code {}", result)
        };

        return Err(NonoError::SandboxInit(error_msg));
    }

    info!("Seatbelt sandbox applied successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::FsCapability;
    use std::path::PathBuf;

    #[test]
    fn test_generate_profile_empty() {
        let caps = CapabilitySet::default();
        let profile = generate_profile(&caps);

        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default)"));
        // Network is allowed by default
        assert!(profile.contains("(allow network-outbound)"));
    }

    #[test]
    fn test_generate_profile_with_dir() {
        let mut caps = CapabilitySet::default();
        caps.fs.push(FsCapability {
            original: PathBuf::from("/test"),
            resolved: PathBuf::from("/test"),
            access: FsAccess::ReadWrite,
            is_file: false,
        });

        let profile = generate_profile(&caps);

        assert!(profile.contains("file-read* file-write*"));
        assert!(profile.contains("subpath \"/test\""));
    }

    #[test]
    fn test_generate_profile_with_file() {
        let mut caps = CapabilitySet::default();
        caps.fs.push(FsCapability {
            original: PathBuf::from("/test.txt"),
            resolved: PathBuf::from("/test.txt"),
            access: FsAccess::Write,
            is_file: true,
        });

        let profile = generate_profile(&caps);

        assert!(profile.contains("file-write*"));
        assert!(profile.contains("literal \"/test.txt\""));
    }

    #[test]
    fn test_generate_profile_network_allowed() {
        let mut caps = CapabilitySet::default();
        caps.net_block = false; // network allowed (default)

        let profile = generate_profile(&caps);

        // With network allowed, should allow outbound, inbound, and bind
        assert!(profile.contains("(allow network-outbound)"));
        assert!(profile.contains("(allow network-inbound)"));
        assert!(profile.contains("(allow network-bind)"));
        // Should not deny network when allowed
        assert!(!profile.contains("(deny network*)"));
    }

    #[test]
    fn test_generate_profile_network_blocked() {
        let mut caps = CapabilitySet::default();
        caps.net_block = true;

        let profile = generate_profile(&caps);

        // With network blocked, should deny all
        assert!(profile.contains("(deny network*)"));
        assert!(!profile.contains("(allow network-outbound)"));
    }

    #[test]
    fn test_support_info() {
        let info = support_info();
        assert!(info.contains("Seatbelt"));
    }

    #[test]
    fn test_sensitive_paths_denied() {
        let caps = CapabilitySet::default();
        let profile = generate_profile(&caps);

        // Should deny common sensitive paths
        assert!(profile.contains(".ssh"));
        assert!(profile.contains(".aws"));
        assert!(profile.contains(".gnupg"));
        assert!(profile.contains("(deny file-read*"));
    }

    #[test]
    fn test_get_sensitive_paths() {
        let paths = get_sensitive_paths();

        // Should have multiple sensitive paths (credentials, shell configs, etc.)
        assert!(paths.len() > 25);

        // Paths should be expanded (not contain ~)
        for path in &paths {
            assert!(!path.contains('~'), "Path should be expanded: {}", path);
        }
    }

    #[test]
    fn test_destructive_operations_blocked() {
        let caps = CapabilitySet::default();
        let profile = generate_profile(&caps);

        // Should deny file deletion (unlink) to prevent rm -rf style attacks
        assert!(
            profile.contains("(deny file-write-unlink)"),
            "Profile should block file deletion"
        );
    }
}
