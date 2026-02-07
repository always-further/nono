use crate::capability::{CapabilitySet, FsAccess};
use crate::config;
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
/// Now loaded from the embedded security-lists.toml via the config module
fn get_sensitive_paths() -> Vec<String> {
    let paths = config::get_sensitive_paths();

    // Expand ~ to actual home directory
    if let Ok(home) = std::env::var("HOME") {
        paths.into_iter().map(|p| p.replace("~", &home)).collect()
    } else {
        paths
    }
}

/// Expand ~ to home directory
fn expand_home(path: &str) -> String {
    if path.starts_with("~/") || path == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return path.replacen("~", &home, 1);
        }
    }
    path.to_string()
}

/// Collect parent directories that need metadata access for path resolution.
///
/// Programs need to lstat() each path component when resolving paths.
/// For example, to access /Users/luke/.claude, Node.js needs to lstat:
/// - /Users
/// - /Users/luke
///
/// This function returns those parent directories so we can allow metadata
/// (but not data) access to them.
fn collect_parent_dirs(caps: &CapabilitySet) -> std::collections::HashSet<String> {
    let mut parents = std::collections::HashSet::new();

    for cap in &caps.fs {
        let path = cap.resolved.as_path();
        let mut current = path.parent();

        // Walk up the directory tree, collecting each parent
        while let Some(parent) = current {
            let parent_str = parent.to_string_lossy().to_string();

            // Stop at root
            if parent_str == "/" || parent_str.is_empty() {
                break;
            }

            // If already present, ancestors were processed too - early exit
            if !parents.insert(parent_str) {
                break;
            }
            current = parent.parent();
        }
    }

    parents
}

/// Generate a Seatbelt profile from capabilities
fn generate_profile(caps: &CapabilitySet) -> String {
    let mut profile = String::new();

    // Profile version
    profile.push_str("(version 1)\n");

    // Start with deny default, but we'll allow many things needed for basic operation
    profile.push_str("(deny default)\n");

    // Debug: log denials to Console.app (enable for debugging)
    // profile.push_str("(debug deny)\n");

    // Allow specific process operations needed for execution
    profile.push_str("(allow process-exec*)\n"); // Execute programs
    profile.push_str("(allow process-fork)\n"); // Fork child processes

    // Process info: allow self-inspection (needed for dyld, code signing, etc.)
    // but deny inspecting OTHER processes (blocks `ps aux` style info leaks)
    // Luke: if target others gets noisy we can narrow it down to the big three:
    // (allow process-info-pidinfo (target self))
    // (allow process-info-codesignature (target self))
    // (allow process-info-setcontrol (target self))
    profile.push_str("(allow process-info* (target self))\n");
    profile.push_str("(deny process-info* (target others))\n");

    // Allow specific system operations (narrowed from blanket system*)
    profile.push_str("(allow sysctl-read)\n");
    profile.push_str("(allow mach*)\n");
    profile.push_str("(allow ipc*)\n");
    profile.push_str("(allow signal)\n");
    // Only allow system operations commonly needed by programs:
    // - system-socket: for network socket operations
    // - system-fsctl: for filesystem control operations
    // - system-info: for reading system information (uname, etc.)
    // Notably omitted: system-audit, system-privilege, system-reboot, system-set-time
    profile.push_str("(allow system-socket)\n");
    profile.push_str("(allow system-fsctl)\n");
    profile.push_str("(allow system-info)\n");

    // File read permissions:
    // Default DENY for all file reads (via deny default above)
    // Explicitly allow only system paths and user-granted paths

    // Allow reading the root directory entry itself (NOT subpaths)
    // This is required because nono uses sandbox_init() then exec().
    // When exec() runs, the kernel resolves the binary path which requires
    // stat/readdir on "/" for path canonicalization.
    // Note: (literal "/") only allows access to "/" itself, NOT files under it.
    // Files like /etc/passwd remain blocked unless explicitly allowed.
    profile.push_str("(allow file-read* (literal \"/\"))\n");

    // Allow metadata access to parent directories of granted paths.
    // This is required for path resolution - programs need to lstat() each path component.
    // Example: to access /Users/luke/.claude, we need to stat /Users and /Users/luke.
    // Using file-read-metadata (not file-read*) allows stat/lstat but blocks:
    // - file-read-data: reading directory contents (ls, readdir)
    // - file-read*: all read operations including content
    // This prevents directory listing of parent dirs while allowing path traversal.
    let parent_dirs = collect_parent_dirs(caps);
    for parent in &parent_dirs {
        let escaped = parent.replace('\\', "\\\\").replace('"', "\\\"");
        profile.push_str(&format!(
            "(allow file-read-metadata (literal \"{}\"))\n",
            escaped
        ));
    }

    // Allow mapping executables into memory (required for dyld to load binaries)
    // Without this, exec() will abort even if file-read* is allowed
    profile.push_str("(allow file-map-executable)\n");

    // 1. Allow system paths from config (needed for executables to function)
    let system_paths = config::get_system_read_paths();
    for path in &system_paths {
        // Expand ~ to home directory for user_library paths
        let expanded = expand_home(path);
        if !expanded.is_empty() {
            let escaped = expanded.replace('\\', "\\\\").replace('"', "\\\"");
            profile.push_str(&format!("(allow file-read* (subpath \"{}\"))\n", escaped));
        }
    }

    // 2. Allow TMPDIR for temp file reads (dynamic path)
    if let Ok(tmpdir) = std::env::var("TMPDIR") {
        let escaped = tmpdir.replace('\\', "\\\\").replace('"', "\\\"");
        profile.push_str(&format!("(allow file-read* (subpath \"{}\"))\n", escaped));
    }

    // Allow file ioctl for TTY
    profile.push_str("(allow file-ioctl)\n");

    // Allow pseudo-terminal operations (needed for interactive CLIs)
    profile.push_str("(allow pseudo-tty)\n");

    // 3. Add user-specified filesystem capabilities for reads
    for cap in &caps.fs {
        let path = cap.resolved.display().to_string();
        let escaped_path = path.replace('\\', "\\\\").replace('"', "\\\"");

        let path_filter = if cap.is_file {
            format!("literal \"{}\"", escaped_path)
        } else {
            format!("subpath \"{}\"", escaped_path)
        };

        match cap.access {
            FsAccess::Read | FsAccess::ReadWrite => {
                profile.push_str(&format!("(allow file-read* ({}))\n", path_filter));
            }
            FsAccess::Write => {
                // Write-only doesn't need read access
            }
        }
    }

    // 4. Deny access to sensitive paths (credentials, keys, tokens)
    // These denials override the allows above, UNLESS user explicitly granted access
    //
    // Strategy: "Allow Discovery, Deny Content"
    // - file-read-data: Blocks reading actual file contents (cat, read, mmap)
    // - file-read-metadata: Allows stat, existence checks, directory listing
    //
    // This approach prevents data exfiltration while allowing programs to check
    // if files exist (for graceful error handling) without crashing.
    for path in get_sensitive_paths() {
        let escaped_path = path.replace('\\', "\\\\").replace('"', "\\\"");

        // Check if user explicitly granted access to this sensitive path
        // Only skip denial if the granted path IS the sensitive path or a subpath of it.
        // This prevents granting ~ or ~/Library from disabling protection for ~/.ssh or ~/Library/Keychains.
        // User must explicitly grant --read ~/.ssh to access SSH keys.
        let user_granted = caps.fs.iter().any(|cap| {
            let sensitive_path = std::path::Path::new(&path);
            // `Path::starts_with` performs a component-wise check, which is safer
            // and more idiomatic than string manipulation for path comparisons.
            // It correctly handles cases like `/a/b` vs `/a` and prevents
            // bypasses like `/a-b` matching `/a`.
            cap.resolved.starts_with(sensitive_path)
        });

        if !user_granted {
            // Allow metadata access (stat, existence checks) for graceful error handling
            profile.push_str(&format!(
                "(allow file-read-metadata (subpath \"{}\"))\n",
                escaped_path
            ));
            // Deny reading actual file content (the sensitive data)
            profile.push_str(&format!(
                "(deny file-read-data (subpath \"{}\"))\n",
                escaped_path
            ));
        }
    }

    // Allow writes only to specific system paths and granted paths
    profile.push_str("(allow file-write*\n");
    profile.push_str("    (subpath \"/dev\")\n");
    profile.push_str("    (subpath \"/private/tmp\")\n");
    profile.push_str("    (subpath \"/tmp\")\n");
    profile.push_str("    (subpath \"/private/var/folders\")\n");
    profile.push_str("    (subpath \"/var/folders\")\n");
    profile.push_str(")\n");

    // Allow TMPDIR for writes too
    if let Ok(tmpdir) = std::env::var("TMPDIR") {
        let escaped = tmpdir.replace('\\', "\\\\").replace('"', "\\\"");
        profile.push_str(&format!("(allow file-write* (subpath \"{}\"))\n", escaped));
    }

    // Allow writes to user's ~/Library/Caches and ~/Library/Logs
    if let Ok(home) = std::env::var("HOME") {
        let home_escaped = home.replace('\\', "\\\\").replace('"', "\\\"");
        profile.push_str(&format!(
            "(allow file-write* (subpath \"{}/Library/Caches\"))\n",
            home_escaped
        ));
        profile.push_str(&format!(
            "(allow file-write* (subpath \"{}/Library/Logs\"))\n",
            home_escaped
        ));
    }

    // 5. Block destructive file operations globally (BEFORE user-granted allows)
    // In Seatbelt, specific allows override broader denies when the allow comes later.
    // By placing the global deny first, user-granted paths can still allow deletion.
    // This prevents rm -rf style attacks while allowing intentional file management.
    profile.push_str("(deny file-write-unlink)\n");

    // 6. Add user-specified filesystem capabilities for writes
    // These specific allows override the global deny above for user-granted paths
    for cap in &caps.fs {
        let path = cap.resolved.display().to_string();
        let escaped_path = path.replace('\\', "\\\\").replace('"', "\\\"");

        let path_filter = if cap.is_file {
            format!("literal \"{}\"", escaped_path)
        } else {
            format!("subpath \"{}\"", escaped_path)
        };

        match cap.access {
            FsAccess::Write | FsAccess::ReadWrite => {
                profile.push_str(&format!("(allow file-write* ({}))\n", path_filter));
                // Allow file deletion (unlink) for writable paths
                profile.push_str(&format!("(allow file-write-unlink ({}))\n", path_filter));
            }
            FsAccess::Read => {
                // Read-only doesn't need write access
            }
        }
    }

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

        // ReadWrite now generates separate read and write rules
        assert!(profile.contains("(allow file-read* (subpath \"/test\"))"));
        assert!(profile.contains("(allow file-write* (subpath \"/test\"))"));
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
        let caps = CapabilitySet {
            net_block: false, // network allowed (default)
            ..Default::default()
        };

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
        let caps = CapabilitySet {
            net_block: true,
            ..Default::default()
        };

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

        // Should deny data reads for common sensitive paths (but allow metadata)
        assert!(profile.contains(".ssh"));
        assert!(profile.contains(".aws"));
        assert!(profile.contains(".gnupg"));
        // "Allow Discovery, Deny Content" strategy
        assert!(
            profile.contains("(allow file-read-metadata"),
            "Should allow metadata for graceful error handling"
        );
        assert!(
            profile.contains("(deny file-read-data"),
            "Should deny data reads for sensitive paths"
        );
    }

    #[test]
    fn test_get_sensitive_paths() {
        let paths = get_sensitive_paths();

        // Should have multiple sensitive paths from embedded config
        assert!(!paths.is_empty(), "Should have sensitive paths");

        // Paths should be expanded (not contain ~)
        for path in &paths {
            assert!(!path.contains('~'), "Path should be expanded: {}", path);
        }

        // Should contain key sensitive paths
        let paths_str = paths.join(" ");
        assert!(paths_str.contains("ssh"), "Should contain ssh path");
        assert!(paths_str.contains("aws"), "Should contain aws path");
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

    #[test]
    fn test_profile_no_blanket_file_read_allow() {
        let caps = CapabilitySet::default();
        let profile = generate_profile(&caps);

        // Should NOT contain blanket allow (the security fix)
        // Check that there's no standalone "(allow file-read*)" without a path filter
        let has_blanket = profile.lines().any(|line| {
            let trimmed = line.trim();
            trimmed == "(allow file-read*)" || trimmed == "(allow file-read* )"
        });
        assert!(
            !has_blanket,
            "Profile should not have blanket file-read allow"
        );
    }

    #[test]
    fn test_profile_allows_system_paths() {
        let caps = CapabilitySet::default();
        let profile = generate_profile(&caps);

        // Should allow critical system paths from config
        assert!(
            profile.contains("(allow file-read* (subpath \"/System/Library\"))"),
            "Profile should allow /System/Library"
        );
        assert!(
            profile.contains("(allow file-read* (subpath \"/usr/lib\"))"),
            "Profile should allow /usr/lib"
        );
    }

    #[test]
    fn test_user_grant_allows_read() {
        let mut caps = CapabilitySet::default();
        caps.fs.push(FsCapability {
            original: PathBuf::from("/Users/test/project"),
            resolved: PathBuf::from("/Users/test/project"),
            access: FsAccess::Read,
            is_file: false,
        });

        let profile = generate_profile(&caps);

        assert!(
            profile.contains("(allow file-read* (subpath \"/Users/test/project\"))"),
            "Profile should allow user-granted read path"
        );
    }

    #[test]
    fn test_expand_home() {
        // Test ~ expansion
        std::env::set_var("HOME", "/Users/testuser");
        assert_eq!(expand_home("~/Library"), "/Users/testuser/Library");
        assert_eq!(expand_home("~"), "/Users/testuser");
        assert_eq!(expand_home("/absolute/path"), "/absolute/path");
    }

    #[test]
    fn test_collect_parent_dirs() {
        let mut caps = CapabilitySet::default();
        caps.fs.push(FsCapability {
            original: PathBuf::from("/Users/test/.claude"),
            resolved: PathBuf::from("/Users/test/.claude"),
            access: FsAccess::ReadWrite,
            is_file: false,
        });

        let parents = collect_parent_dirs(&caps);

        // Should include parent directories but not root
        assert!(parents.contains("/Users"), "Should include /Users");
        assert!(
            parents.contains("/Users/test"),
            "Should include /Users/test"
        );
        assert!(!parents.contains("/"), "Should not include root");
    }

    #[test]
    fn test_profile_allows_parent_metadata() {
        let mut caps = CapabilitySet::default();
        caps.fs.push(FsCapability {
            original: PathBuf::from("/Users/test/.claude"),
            resolved: PathBuf::from("/Users/test/.claude"),
            access: FsAccess::ReadWrite,
            is_file: false,
        });

        let profile = generate_profile(&caps);

        // Should allow METADATA access (not full read) to parent directories for path resolution
        // This allows stat/lstat but blocks readdir (directory listing)
        assert!(
            profile.contains("(allow file-read-metadata (literal \"/Users\"))"),
            "Profile should allow metadata on /Users"
        );
        assert!(
            profile.contains("(allow file-read-metadata (literal \"/Users/test\"))"),
            "Profile should allow metadata on /Users/test"
        );
        // Should NOT use file-read* for parent directories (would allow directory listing)
        assert!(
            !profile.contains("(allow file-read* (literal \"/Users\"))"),
            "Profile should NOT allow full read on parent /Users"
        );
    }

    #[test]
    fn test_process_info_denied_for_others() {
        let caps = CapabilitySet::default();
        let profile = generate_profile(&caps);

        // Should NOT have blanket process* allow (would leak info about other processes)
        assert!(
            !profile.contains("(allow process*)\n"),
            "Profile should not have blanket process allow"
        );

        // Should allow process-info for SELF (needed for dyld, code signing, etc.)
        assert!(
            profile.contains("(allow process-info* (target self))\n"),
            "Profile should allow process-info for self"
        );

        // Should deny process-info for OTHERS to prevent `ps aux` style attacks
        assert!(
            profile.contains("(deny process-info* (target others))\n"),
            "Profile should deny process-info for other processes"
        );

        // Should allow specific process operations needed for execution
        assert!(
            profile.contains("(allow process-exec*)\n"),
            "Profile should allow process execution"
        );
        assert!(
            profile.contains("(allow process-fork)\n"),
            "Profile should allow process forking"
        );
    }

    // =========================================================================
    // Security regression tests for path comparison bypass (CVE-like)
    // These tests ensure the fix for string-based starts_with() is preserved.
    // =========================================================================

    #[test]
    fn test_path_collision_bypass_blocked() {
        // Attack: Create ~/.sshfoo to bypass ~/.ssh protection
        // The vulnerable code would match "/Users/test/.sshfoo".starts_with("/Users/test/.ssh")
        // Fixed code requires exact match OR path separator after the sensitive path
        std::env::set_var("HOME", "/Users/test");

        let mut caps = CapabilitySet::default();
        caps.fs.push(FsCapability {
            original: PathBuf::from("/Users/test/.sshfoo"),
            resolved: PathBuf::from("/Users/test/.sshfoo"),
            access: FsAccess::Read,
            is_file: false,
        });

        let profile = generate_profile(&caps);

        // ~/.ssh should STILL be denied (the bypass attempt should fail)
        assert!(
            profile.contains("(deny file-read-data (subpath \"/Users/test/.ssh\"))"),
            "Path collision bypass: ~/.sshfoo grant must NOT disable ~/.ssh protection"
        );
    }

    #[test]
    fn test_exact_sensitive_path_grant_allows_access() {
        // Legitimate use: explicitly granting ~/.ssh should disable protection for it
        std::env::set_var("HOME", "/Users/test");

        let mut caps = CapabilitySet::default();
        caps.fs.push(FsCapability {
            original: PathBuf::from("/Users/test/.ssh"),
            resolved: PathBuf::from("/Users/test/.ssh"),
            access: FsAccess::Read,
            is_file: false,
        });

        let profile = generate_profile(&caps);

        // ~/.ssh should NOT be denied when explicitly granted
        assert!(
            !profile.contains("(deny file-read-data (subpath \"/Users/test/.ssh\"))"),
            "Exact grant of ~/.ssh should disable its protection"
        );
        // But should still allow reading it
        assert!(
            profile.contains("(allow file-read* (subpath \"/Users/test/.ssh\"))"),
            "Exact grant of ~/.ssh should allow reading"
        );
    }

    #[test]
    fn test_child_path_grant_allows_access() {
        // Granting ~/.ssh/keys (a child of sensitive ~/.ssh) should disable protection
        std::env::set_var("HOME", "/Users/test");

        let mut caps = CapabilitySet::default();
        caps.fs.push(FsCapability {
            original: PathBuf::from("/Users/test/.ssh/keys"),
            resolved: PathBuf::from("/Users/test/.ssh/keys"),
            access: FsAccess::Read,
            is_file: false,
        });

        let profile = generate_profile(&caps);

        // ~/.ssh should NOT be denied when a child path is granted
        // (user explicitly acknowledged they want access to something under ~/.ssh)
        assert!(
            !profile.contains("(deny file-read-data (subpath \"/Users/test/.ssh\"))"),
            "Grant of ~/.ssh/keys should disable ~/.ssh protection"
        );
    }

    #[test]
    fn test_unrelated_path_does_not_affect_sensitive() {
        // Granting an unrelated path should not affect sensitive path protection
        std::env::set_var("HOME", "/Users/test");

        let mut caps = CapabilitySet::default();
        caps.fs.push(FsCapability {
            original: PathBuf::from("/Users/test/projects"),
            resolved: PathBuf::from("/Users/test/projects"),
            access: FsAccess::Read,
            is_file: false,
        });

        let profile = generate_profile(&caps);

        // ~/.ssh should still be denied
        assert!(
            profile.contains("(deny file-read-data (subpath \"/Users/test/.ssh\"))"),
            "Unrelated path grant must not affect ~/.ssh protection"
        );
        // ~/.aws should still be denied
        assert!(
            profile.contains("(deny file-read-data (subpath \"/Users/test/.aws\"))"),
            "Unrelated path grant must not affect ~/.aws protection"
        );
    }

    #[test]
    fn test_multiple_collision_attempts_blocked() {
        // Test multiple collision patterns
        std::env::set_var("HOME", "/Users/test");

        let mut caps = CapabilitySet::default();
        // Try to bypass ~/.aws with ~/.awsbackup
        caps.fs.push(FsCapability {
            original: PathBuf::from("/Users/test/.awsbackup"),
            resolved: PathBuf::from("/Users/test/.awsbackup"),
            access: FsAccess::Read,
            is_file: false,
        });
        // Try to bypass ~/.gnupg with ~/.gnupg2
        caps.fs.push(FsCapability {
            original: PathBuf::from("/Users/test/.gnupg2"),
            resolved: PathBuf::from("/Users/test/.gnupg2"),
            access: FsAccess::Read,
            is_file: false,
        });

        let profile = generate_profile(&caps);

        // Both sensitive paths should STILL be protected
        assert!(
            profile.contains("(deny file-read-data (subpath \"/Users/test/.aws\"))"),
            "~/.awsbackup must NOT bypass ~/.aws protection"
        );
        assert!(
            profile.contains("(deny file-read-data (subpath \"/Users/test/.gnupg\"))"),
            "~/.gnupg2 must NOT bypass ~/.gnupg protection"
        );
    }

    #[test]
    fn test_trailing_slash_normalization() {
        // Paths with trailing slashes should be normalized for comparison
        std::env::set_var("HOME", "/Users/test");

        let mut caps = CapabilitySet::default();
        // Grant path WITH trailing slash
        caps.fs.push(FsCapability {
            original: PathBuf::from("/Users/test/.ssh/"),
            resolved: PathBuf::from("/Users/test/.ssh/"),
            access: FsAccess::Read,
            is_file: false,
        });

        let profile = generate_profile(&caps);

        // ~/.ssh should NOT be denied (trailing slash should be normalized)
        assert!(
            !profile.contains("(deny file-read-data (subpath \"/Users/test/.ssh\"))"),
            "Grant with trailing slash should still disable protection"
        );
    }
}
