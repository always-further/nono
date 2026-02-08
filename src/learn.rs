//! Learn mode: trace file accesses to discover required paths
//!
//! Uses strace to monitor a command's file system accesses and produces
//! a list of paths that would need to be allowed in a nono profile.

use crate::cli::LearnArgs;
use crate::error::{NonoError, Result};
use std::collections::BTreeSet;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use crate::config;
#[cfg(target_os = "linux")]
use crate::profile::{self, Profile};
#[cfg(target_os = "linux")]
use std::collections::HashSet;
#[cfg(target_os = "linux")]
use std::io::{BufRead, BufReader};
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
#[cfg(target_os = "linux")]
use tracing::{debug, info, warn};

/// Result of learning file access patterns
#[derive(Debug)]
pub struct LearnResult {
    /// Paths that need read access
    pub read_paths: BTreeSet<PathBuf>,
    /// Paths that need write access
    pub write_paths: BTreeSet<PathBuf>,
    /// Paths that need read+write access
    pub readwrite_paths: BTreeSet<PathBuf>,
    /// Paths that were accessed but are already covered by system paths
    pub system_covered: BTreeSet<PathBuf>,
    /// Paths that were accessed but are already covered by profile
    pub profile_covered: BTreeSet<PathBuf>,
}

impl LearnResult {
    #[cfg(target_os = "linux")]
    fn new() -> Self {
        Self {
            read_paths: BTreeSet::new(),
            write_paths: BTreeSet::new(),
            readwrite_paths: BTreeSet::new(),
            system_covered: BTreeSet::new(),
            profile_covered: BTreeSet::new(),
        }
    }

    /// Check if any paths were discovered
    pub fn has_paths(&self) -> bool {
        !self.read_paths.is_empty()
            || !self.write_paths.is_empty()
            || !self.readwrite_paths.is_empty()
    }

    /// Format as TOML fragment for profile
    pub fn to_toml(&self) -> String {
        let mut lines = Vec::new();
        lines.push("[filesystem]".to_string());

        if !self.readwrite_paths.is_empty() {
            lines.push("allow = [".to_string());
            for path in &self.readwrite_paths {
                lines.push(format!("    \"{}\",", path.display()));
            }
            lines.push("]".to_string());
        } else {
            lines.push("allow = []".to_string());
        }

        if !self.read_paths.is_empty() {
            lines.push("read = [".to_string());
            for path in &self.read_paths {
                lines.push(format!("    \"{}\",", path.display()));
            }
            lines.push("]".to_string());
        } else {
            lines.push("read = []".to_string());
        }

        if !self.write_paths.is_empty() {
            lines.push("write = [".to_string());
            for path in &self.write_paths {
                lines.push(format!("    \"{}\",", path.display()));
            }
            lines.push("]".to_string());
        } else {
            lines.push("write = []".to_string());
        }

        lines.join("\n")
    }

    /// Format as human-readable summary
    pub fn to_summary(&self) -> String {
        let mut lines = Vec::new();

        if !self.read_paths.is_empty() {
            lines.push("Read access needed:".to_string());
            for path in &self.read_paths {
                lines.push(format!("  {}", path.display()));
            }
        }

        if !self.write_paths.is_empty() {
            lines.push("Write access needed:".to_string());
            for path in &self.write_paths {
                lines.push(format!("  {}", path.display()));
            }
        }

        if !self.readwrite_paths.is_empty() {
            lines.push("Read+Write access needed:".to_string());
            for path in &self.readwrite_paths {
                lines.push(format!("  {}", path.display()));
            }
        }

        if !self.system_covered.is_empty() {
            lines.push(format!(
                "\n({} paths already covered by system defaults)",
                self.system_covered.len()
            ));
        }

        if !self.profile_covered.is_empty() {
            lines.push(format!(
                "({} paths already covered by profile)",
                self.profile_covered.len()
            ));
        }

        if lines.is_empty() {
            lines.push("No additional paths needed.".to_string());
        }

        lines.join("\n")
    }
}

/// Check if strace is available
#[cfg(target_os = "linux")]
fn check_strace() -> Result<()> {
    match Command::new("strace").arg("--version").output() {
        Ok(output) if output.status.success() => Ok(()),
        _ => Err(NonoError::LearnError(
            "strace not found. Install with: apt install strace".to_string(),
        )),
    }
}

/// Run learn mode (non-Linux stub)
#[cfg(not(target_os = "linux"))]
pub fn run_learn(_args: &LearnArgs) -> Result<LearnResult> {
    Err(NonoError::LearnError(
        "nono learn is only available on Linux (requires strace)".to_string(),
    ))
}

/// Run learn mode (Linux implementation)
#[cfg(target_os = "linux")]
pub fn run_learn(args: &LearnArgs) -> Result<LearnResult> {
    check_strace()?;

    // Load profile if specified
    let profile = if let Some(ref profile_name) = args.profile {
        Some(profile::load_profile(profile_name, args.trust_unsigned)?)
    } else {
        None
    };

    // Run strace and collect paths
    let raw_accesses = run_strace(&args.command, args.timeout)?;

    // Process and categorize paths
    let result = process_accesses(raw_accesses, profile.as_ref(), args.all)?;

    Ok(result)
}

/// Represents a file access from strace
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct FileAccess {
    path: PathBuf,
    is_write: bool,
}

/// Run strace on the command and collect file accesses
#[cfg(target_os = "linux")]
fn run_strace(command: &[String], timeout: Option<u64>) -> Result<Vec<FileAccess>> {
    use std::time::{Duration, Instant};

    if command.is_empty() {
        return Err(NonoError::NoCommand);
    }

    let mut strace_args = vec![
        "-f".to_string(), // Follow forks
        "-e".to_string(), // Trace these syscalls
        "openat,open,access,stat,lstat,readlink,execve,creat,mkdir,rename,unlink".to_string(),
        "-o".to_string(),
        "/dev/stderr".to_string(), // Output to stderr so we can capture it
        "--".to_string(),
    ];
    strace_args.extend(command.iter().cloned());

    info!("Running strace with args: {:?}", strace_args);

    let mut child = Command::new("strace")
        .args(&strace_args)
        .stdout(Stdio::inherit()) // Let command output go to terminal
        .stderr(Stdio::piped()) // Capture strace output
        .spawn()
        .map_err(|e| NonoError::LearnError(format!("Failed to spawn strace: {}", e)))?;

    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| NonoError::LearnError("Failed to capture strace stderr".to_string()))?;

    let start = Instant::now();
    let timeout_duration = timeout.map(Duration::from_secs);

    let mut accesses = Vec::new();
    let reader = BufReader::new(stderr);

    for line in reader.lines() {
        // Check timeout
        if let Some(timeout) = timeout_duration {
            if start.elapsed() > timeout {
                warn!("Timeout reached, killing child process");
                let _ = child.kill();
                break;
            }
        }

        let line = match line {
            Ok(l) => l,
            Err(e) => {
                debug!("Error reading strace line: {}", e);
                continue;
            }
        };

        // Parse strace output
        if let Some(access) = parse_strace_line(&line) {
            accesses.push(access);
        }
    }

    // Wait for child to finish
    let _ = child.wait();

    Ok(accesses)
}

/// Parse a single strace line to extract file access
#[cfg(target_os = "linux")]
fn parse_strace_line(line: &str) -> Option<FileAccess> {
    // strace output format examples:
    // openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3
    // openat(AT_FDCWD, "/tmp/foo", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 4
    // access("/etc/ld.so.preload", R_OK) = -1 ENOENT
    // stat("/usr/bin/bash", {st_mode=...) = 0
    // execve("/usr/bin/ls", ["ls"], ...) = 0

    // Skip lines that don't contain syscalls we care about
    let syscalls = [
        "openat", "open", "access", "stat", "lstat", "readlink", "execve", "creat", "mkdir",
        "rename", "unlink",
    ];

    let syscall = syscalls
        .iter()
        .find(|&s| line.contains(&format!("{}(", s)))?;

    // Extract the path from the syscall
    let path = extract_path_from_syscall(line, syscall)?;

    // Determine if this is a write access
    let is_write = is_write_access(line, syscall);

    // Filter out invalid paths
    if path.is_empty() || path == "." || path == ".." {
        return None;
    }

    Some(FileAccess {
        path: PathBuf::from(path),
        is_write,
    })
}

/// Extract path from strace syscall line
#[cfg(target_os = "linux")]
fn extract_path_from_syscall(line: &str, syscall: &str) -> Option<String> {
    // Find the opening paren after syscall
    let start_idx = line.find(&format!("{}(", syscall))?;
    let after_paren = &line[start_idx + syscall.len() + 1..];

    // For openat, skip AT_FDCWD
    let path_start = if syscall == "openat" {
        // Skip "AT_FDCWD, " or similar
        if let Some(comma_idx) = after_paren.find(',') {
            comma_idx + 2 // Skip ", "
        } else {
            return None;
        }
    } else {
        0
    };

    let remaining = &after_paren[path_start..];

    // Path should be in quotes
    if !remaining.starts_with('"') {
        return None;
    }

    // Find closing quote
    let end_quote = remaining[1..].find('"')?;
    let path = &remaining[1..end_quote + 1];

    // Unescape C-style escapes from strace output
    let path = unescape_strace_string(path);

    Some(path)
}

/// Unescape C-style escape sequences from strace output.
/// Handles: \n \t \r \\ \" \0 \xNN (hex) \NNN (octal)
///
/// Invalid or incomplete escape sequences are passed through literally
/// to avoid data loss.
#[cfg(target_os = "linux")]
fn unescape_strace_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('n') => {
                    chars.next();
                    result.push('\n');
                }
                Some('t') => {
                    chars.next();
                    result.push('\t');
                }
                Some('r') => {
                    chars.next();
                    result.push('\r');
                }
                Some('\\') => {
                    chars.next();
                    result.push('\\');
                }
                Some('"') => {
                    chars.next();
                    result.push('"');
                }
                Some(c) if ('0'..='7').contains(c) => {
                    // Octal escape \NNN (1-3 digits, including \0 for null)
                    let mut octal = String::new();
                    while octal.len() < 3 && chars.peek().is_some_and(|c| ('0'..='7').contains(c)) {
                        octal.push(chars.next().unwrap());
                    }
                    // from_str_radix is safe here since we validated digits are 0-7
                    let val = u8::from_str_radix(&octal, 8).unwrap();
                    result.push(val as char);
                }
                Some('x') => {
                    chars.next(); // consume 'x'
                                  // Hex escape \xNN - must have exactly 2 hex digits
                    let mut hex = String::new();
                    for _ in 0..2 {
                        if chars.peek().is_some_and(|c| c.is_ascii_hexdigit()) {
                            hex.push(chars.next().unwrap());
                        } else {
                            break;
                        }
                    }
                    if hex.len() == 2 {
                        // from_str_radix is safe here since we validated hex digits
                        let val = u8::from_str_radix(&hex, 16).unwrap();
                        result.push(val as char);
                    } else {
                        // Invalid/incomplete hex escape - pass through literally
                        result.push('\\');
                        result.push('x');
                        result.push_str(&hex);
                    }
                }
                _ => {
                    // Unknown escape, keep as-is
                    result.push('\\');
                }
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Determine if a syscall represents a write access
#[cfg(target_os = "linux")]
fn is_write_access(line: &str, syscall: &str) -> bool {
    match syscall {
        "creat" | "mkdir" | "unlink" | "rename" => true,
        "openat" | "open" => {
            // Check flags for write intent
            line.contains("O_WRONLY")
                || line.contains("O_RDWR")
                || line.contains("O_CREAT")
                || line.contains("O_TRUNC")
        }
        _ => false,
    }
}

/// Process raw accesses into categorized result
#[cfg(target_os = "linux")]
fn process_accesses(
    accesses: Vec<FileAccess>,
    profile: Option<&Profile>,
    show_all: bool,
) -> Result<LearnResult> {
    let mut result = LearnResult::new();

    // Get system paths that are already allowed
    let system_read_paths = config::get_system_read_paths();
    let system_read_set: HashSet<&str> = system_read_paths.iter().map(|s| s.as_str()).collect();

    // Get profile paths if available
    let profile_paths: HashSet<String> = if let Some(prof) = profile {
        let mut paths = HashSet::new();
        paths.extend(prof.filesystem.allow.iter().cloned());
        paths.extend(prof.filesystem.read.iter().cloned());
        paths.extend(prof.filesystem.write.iter().cloned());
        paths
    } else {
        HashSet::new()
    };

    // Track unique paths (canonicalized where possible)
    let mut seen_paths: HashSet<PathBuf> = HashSet::new();

    for access in accesses {
        // Try to canonicalize, fall back to original
        let canonical = access.path.canonicalize().unwrap_or(access.path.clone());

        // Skip if we've seen this path
        if seen_paths.contains(&canonical) {
            continue;
        }
        seen_paths.insert(canonical.clone());

        // Check if covered by system paths
        if is_covered_by_set(&canonical, &system_read_set) {
            if show_all {
                result.system_covered.insert(canonical);
            }
            continue;
        }

        // Check if covered by profile
        if is_covered_by_profile(&canonical, &profile_paths) {
            if show_all {
                result.profile_covered.insert(canonical);
            }
            continue;
        }

        // Categorize by access type
        // Collapse to parent directories for cleaner output
        let collapsed = collapse_to_parent(&canonical);

        if access.is_write {
            // Check if already in read, upgrade to readwrite
            if result.read_paths.contains(&collapsed) {
                result.read_paths.remove(&collapsed);
                result.readwrite_paths.insert(collapsed);
            } else if !result.readwrite_paths.contains(&collapsed) {
                result.write_paths.insert(collapsed);
            }
        } else {
            // Read access
            if result.write_paths.contains(&collapsed) {
                result.write_paths.remove(&collapsed);
                result.readwrite_paths.insert(collapsed);
            } else if !result.readwrite_paths.contains(&collapsed) {
                result.read_paths.insert(collapsed);
            }
        }
    }

    Ok(result)
}

/// Check if a path is covered by a set of allowed paths
#[cfg(target_os = "linux")]
fn is_covered_by_set(path: &Path, allowed: &HashSet<&str>) -> bool {
    for allowed_path in allowed {
        let allowed_expanded = expand_home(allowed_path);
        if let Ok(allowed_canonical) = std::fs::canonicalize(&allowed_expanded) {
            if path.starts_with(&allowed_canonical) {
                return true;
            }
        }
        // Also check without canonicalization for paths that may not exist
        let allowed_path_buf = PathBuf::from(&allowed_expanded);
        if path.starts_with(&allowed_path_buf) {
            return true;
        }
    }
    false
}

/// Check if a path is covered by profile paths
#[cfg(target_os = "linux")]
fn is_covered_by_profile(path: &Path, profile_paths: &HashSet<String>) -> bool {
    for profile_path in profile_paths {
        let expanded = expand_home(profile_path);
        if let Ok(canonical) = std::fs::canonicalize(&expanded) {
            if path.starts_with(&canonical) {
                return true;
            }
        }
        let path_buf = PathBuf::from(&expanded);
        if path.starts_with(&path_buf) {
            return true;
        }
    }
    false
}

/// Expand ~ to home directory
#[cfg(target_os = "linux")]
fn expand_home(path: &str) -> String {
    if path.starts_with('~') {
        if let Ok(home) = std::env::var("HOME") {
            return path.replacen('~', &home, 1);
        }
    }
    if path.starts_with("$HOME") {
        if let Ok(home) = std::env::var("HOME") {
            return path.replacen("$HOME", &home, 1);
        }
    }
    path.to_string()
}

/// Collapse a file path to its parent directory for cleaner output
#[cfg(target_os = "linux")]
fn collapse_to_parent(path: &Path) -> PathBuf {
    // Don't collapse if it's already a directory
    if path.is_dir() {
        return path.to_path_buf();
    }

    // Collapse files to their parent directory
    path.parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| path.to_path_buf())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn test_parse_strace_openat() {
        let line = r#"openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3"#;
        let access = parse_strace_line(line).unwrap();
        assert_eq!(access.path, PathBuf::from("/etc/passwd"));
        assert!(!access.is_write);
    }

    #[test]
    fn test_parse_strace_openat_write() {
        let line = r#"openat(AT_FDCWD, "/tmp/test", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 4"#;
        let access = parse_strace_line(line).unwrap();
        assert_eq!(access.path, PathBuf::from("/tmp/test"));
        assert!(access.is_write);
    }

    #[test]
    fn test_parse_strace_stat() {
        let line = r#"stat("/usr/bin/bash", {st_mode=S_IFREG|0755, ...}) = 0"#;
        let access = parse_strace_line(line).unwrap();
        assert_eq!(access.path, PathBuf::from("/usr/bin/bash"));
        assert!(!access.is_write);
    }

    #[test]
    fn test_parse_strace_execve() {
        let line = r#"execve("/usr/bin/ls", ["ls", "-la"], 0x...) = 0"#;
        let access = parse_strace_line(line).unwrap();
        assert_eq!(access.path, PathBuf::from("/usr/bin/ls"));
        assert!(!access.is_write);
    }

    #[test]
    fn test_extract_path_from_openat() {
        let line = r#"openat(AT_FDCWD, "/some/path", O_RDONLY) = 3"#;
        let path = extract_path_from_syscall(line, "openat").unwrap();
        assert_eq!(path, "/some/path");
    }

    #[test]
    fn test_is_write_access() {
        assert!(is_write_access(
            "openat(..., O_WRONLY|O_CREAT, ...)",
            "openat"
        ));
        assert!(is_write_access("openat(..., O_RDWR, ...)", "openat"));
        assert!(!is_write_access("openat(..., O_RDONLY, ...)", "openat"));
        assert!(is_write_access("creat(...)", "creat"));
        assert!(is_write_access("mkdir(...)", "mkdir"));
    }

    #[test]
    fn test_expand_home() {
        std::env::set_var("HOME", "/home/test");
        assert_eq!(expand_home("~/foo"), "/home/test/foo");
        assert_eq!(expand_home("$HOME/bar"), "/home/test/bar");
        assert_eq!(expand_home("/absolute/path"), "/absolute/path");
    }

    #[test]
    fn test_collapse_to_parent() {
        // For a file that doesn't exist, collapse to parent
        let path = PathBuf::from("/some/dir/file.txt");
        let collapsed = collapse_to_parent(&path);
        assert_eq!(collapsed, PathBuf::from("/some/dir"));
    }

    #[test]
    fn test_learn_result_to_toml() {
        let mut result = LearnResult::new();
        result.read_paths.insert(PathBuf::from("/some/read/path"));
        result.write_paths.insert(PathBuf::from("/some/write/path"));

        let toml = result.to_toml();
        assert!(toml.contains("[filesystem]"));
        assert!(toml.contains("/some/read/path"));
        assert!(toml.contains("/some/write/path"));
    }

    #[test]
    fn test_unescape_simple() {
        assert_eq!(unescape_strace_string(r#"hello"#), "hello");
        assert_eq!(unescape_strace_string(r#"hello\nworld"#), "hello\nworld");
        assert_eq!(unescape_strace_string(r#"hello\tworld"#), "hello\tworld");
        assert_eq!(unescape_strace_string(r#"hello\\world"#), "hello\\world");
        assert_eq!(unescape_strace_string(r#"hello\"world"#), "hello\"world");
    }

    #[test]
    fn test_unescape_hex() {
        // \x41 = 'A'
        assert_eq!(unescape_strace_string(r#"\x41"#), "A");
        // \x2f = '/'
        assert_eq!(
            unescape_strace_string(r#"/path\x2fwith\x2fslash"#),
            "/path/with/slash"
        );
    }

    #[test]
    fn test_unescape_octal() {
        // \101 = 'A' (octal 101 = 65 decimal)
        assert_eq!(unescape_strace_string(r#"\101"#), "A");
        // \040 = ' ' (space)
        assert_eq!(unescape_strace_string(r#"hello\040world"#), "hello world");
    }

    #[test]
    fn test_unescape_null() {
        // \0 alone is null
        assert_eq!(unescape_strace_string(r#"hello\0world"#), "hello\0world");
    }

    #[test]
    fn test_unescape_incomplete_hex() {
        // Incomplete hex escape should be passed through literally
        assert_eq!(unescape_strace_string(r#"\x1"#), r#"\x1"#);
        // Note: \x1e would be valid (1e are both hex digits), so use \x1g instead
        assert_eq!(unescape_strace_string(r#"path\x1gnd"#), r#"path\x1gnd"#);
    }

    #[test]
    fn test_unescape_invalid_hex() {
        // Invalid hex digits should be passed through literally
        assert_eq!(unescape_strace_string(r#"\xZZ"#), r#"\xZZ"#);
        assert_eq!(unescape_strace_string(r#"\xGH"#), r#"\xGH"#);
    }

    #[test]
    fn test_unescape_invalid_octal() {
        // 8 and 9 are not valid octal digits
        // \18 should parse \1 as octal (= 0x01) and leave '8' as literal
        assert_eq!(unescape_strace_string(r#"\18"#), "\x018");
        // \19 should parse \1 as octal (= 0x01) and leave '9' as literal
        assert_eq!(unescape_strace_string(r#"\19"#), "\x019");
    }

    #[test]
    fn test_unescape_trailing_backslash() {
        // Trailing backslash should be passed through
        assert_eq!(unescape_strace_string(r#"hello\"#), r#"hello\"#);
    }
}
