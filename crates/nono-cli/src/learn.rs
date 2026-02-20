//! Learn mode: trace file accesses to discover required paths
//!
//! Uses strace to monitor a command's file system accesses and produces
//! a list of paths that would need to be allowed in a nono profile.

use crate::cli::LearnArgs;
use nono::{NonoError, Result};
use std::collections::BTreeSet;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use crate::profile::{self, Profile};
#[cfg(target_os = "linux")]
use std::collections::{HashMap, HashSet};
#[cfg(target_os = "linux")]
use std::io::{BufRead, BufReader};
#[cfg(target_os = "linux")]
use std::net::IpAddr;
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
    /// Outbound network connections observed
    pub outbound_connections: Vec<NetworkConnectionSummary>,
    /// Listening ports observed
    pub listening_ports: Vec<NetworkConnectionSummary>,
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
            outbound_connections: Vec::new(),
            listening_ports: Vec::new(),
        }
    }

    /// Check if any paths were discovered
    pub fn has_paths(&self) -> bool {
        !self.read_paths.is_empty()
            || !self.write_paths.is_empty()
            || !self.readwrite_paths.is_empty()
    }

    /// Check if any network activity was observed
    pub fn has_network_activity(&self) -> bool {
        !self.outbound_connections.is_empty() || !self.listening_ports.is_empty()
    }

    /// Format as JSON fragment for profile
    pub fn to_json(&self) -> String {
        let allow: Vec<String> = self
            .readwrite_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        let read: Vec<String> = self
            .read_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        let write: Vec<String> = self
            .write_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect();

        let outbound: Vec<serde_json::Value> = self
            .outbound_connections
            .iter()
            .map(|c| {
                let mut obj = serde_json::json!({
                    "addr": c.endpoint.addr.to_string(),
                    "port": c.endpoint.port,
                    "count": c.count,
                });
                if let Some(ref hostname) = c.endpoint.hostname {
                    obj["hostname"] = serde_json::Value::String(hostname.clone());
                }
                obj
            })
            .collect();

        let listening: Vec<serde_json::Value> = self
            .listening_ports
            .iter()
            .map(|c| {
                let mut obj = serde_json::json!({
                    "addr": c.endpoint.addr.to_string(),
                    "port": c.endpoint.port,
                    "count": c.count,
                });
                if let Some(ref hostname) = c.endpoint.hostname {
                    obj["hostname"] = serde_json::Value::String(hostname.clone());
                }
                obj
            })
            .collect();

        let fragment = serde_json::json!({
            "filesystem": {
                "allow": allow,
                "read": read,
                "write": write
            },
            "network": {
                "outbound": outbound,
                "listening": listening
            }
        });

        serde_json::to_string_pretty(&fragment).unwrap_or_else(|_| "{}".to_string())
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

        // Network sections
        if !self.outbound_connections.is_empty() {
            if !lines.is_empty() {
                lines.push(String::new());
            }
            lines.push("Outbound connections:".to_string());
            for conn in &self.outbound_connections {
                lines.push(format_network_summary(conn));
            }
        }

        if !self.listening_ports.is_empty() {
            if !lines.is_empty() {
                lines.push(String::new());
            }
            lines.push("Listening ports:".to_string());
            for conn in &self.listening_ports {
                lines.push(format_network_summary(conn));
            }
        }

        if lines.is_empty() {
            lines.push("No additional paths needed.".to_string());
        }

        lines.join("\n")
    }
}

/// Format a single network connection summary line
fn format_network_summary(conn: &NetworkConnectionSummary) -> String {
    let count_str = if conn.count > 1 {
        format!(" ({}x)", conn.count)
    } else {
        String::new()
    };

    if let Some(ref hostname) = conn.endpoint.hostname {
        format!(
            "  {} ({}):{}{}",
            hostname, conn.endpoint.addr, conn.endpoint.port, count_str
        )
    } else {
        format!(
            "  {}:{}{}",
            conn.endpoint.addr, conn.endpoint.port, count_str
        )
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
        Some(profile::load_profile(profile_name)?)
    } else {
        None
    };

    // Run strace and collect file accesses, network accesses, and DNS queries
    let (raw_file_accesses, raw_network_accesses, dns_queries) =
        run_strace(&args.command, args.timeout)?;

    // Process and categorize file paths
    let mut result = process_accesses(raw_file_accesses, profile.as_ref(), args.all)?;

    // Process network accesses with forward DNS correlation
    let (outbound, listening) =
        process_network_accesses(raw_network_accesses, dns_queries, !args.no_rdns);
    result.outbound_connections = outbound;
    result.listening_ports = listening;

    Ok(result)
}

/// Represents a file access from strace
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct FileAccess {
    path: PathBuf,
    is_write: bool,
}

/// Kind of network access observed via strace
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
enum NetworkAccessKind {
    Connect,
    Bind,
}

/// A single network access observed via strace
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct NetworkAccess {
    addr: IpAddr,
    port: u16,
    kind: NetworkAccessKind,
    /// Hostname from the most recent DNS query (timing-based correlation)
    queried_hostname: Option<String>,
}

/// A resolved network endpoint with optional reverse DNS hostname
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NetworkEndpoint {
    pub addr: IpAddr,
    pub port: u16,
    pub hostname: Option<String>,
}

/// Summary of connections to a single endpoint (with count)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NetworkConnectionSummary {
    pub endpoint: NetworkEndpoint,
    pub count: usize,
}

/// Unified type for parsed strace accesses
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
enum TracedAccess {
    File(FileAccess),
    Network(NetworkAccess),
    DnsQuery(String),
}

/// Run strace on the command and collect file accesses, network accesses, and DNS queries
#[cfg(target_os = "linux")]
fn run_strace(
    command: &[String],
    timeout: Option<u64>,
) -> Result<(Vec<FileAccess>, Vec<NetworkAccess>, Vec<String>)> {
    use std::time::{Duration, Instant};

    if command.is_empty() {
        return Err(NonoError::NoCommand);
    }

    let mut strace_args = vec![
        "-f".to_string(),  // Follow forks
        "-s".to_string(),  // Increase max string size for DNS packet capture
        "256".to_string(),
        "-e".to_string(),  // Trace these syscalls
        "openat,open,access,stat,lstat,readlink,execve,creat,mkdir,rename,unlink,connect,bind,sendto"
            .to_string(),
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

    let mut file_accesses = Vec::new();
    let mut network_accesses = Vec::new();
    let mut dns_queries = Vec::new();
    // Track the most recently queried hostname for timing-based correlation.
    // When a DNS query precedes a connect(), we attach the hostname directly
    // to the NetworkAccess. This handles DNS round-robin (where forward DNS
    // after the fact may resolve to different IPs than the traced program got).
    let mut last_queried_hostname: Option<String> = None;
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
            match access {
                TracedAccess::File(fa) => file_accesses.push(fa),
                TracedAccess::Network(mut na) => {
                    na.queried_hostname = last_queried_hostname.clone();
                    network_accesses.push(na);
                }
                TracedAccess::DnsQuery(hostname) => {
                    last_queried_hostname = Some(hostname.clone());
                    dns_queries.push(hostname);
                }
            }
        }
    }

    // Wait for child to finish
    let _ = child.wait();

    Ok((file_accesses, network_accesses, dns_queries))
}

/// Parse a single strace line to extract file or network access
#[cfg(target_os = "linux")]
fn parse_strace_line(line: &str) -> Option<TracedAccess> {
    // strace output format examples:
    // openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3
    // openat(AT_FDCWD, "/tmp/foo", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 4
    // access("/etc/ld.so.preload", R_OK) = -1 ENOENT
    // stat("/usr/bin/bash", {st_mode=...) = 0
    // execve("/usr/bin/ls", ["ls"], ...) = 0
    // connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0
    // bind(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("0.0.0.0")}, 16) = 0
    // sendto(5, "\xab\x12...\7example\3com\0...", 29, 0, {sa_family=AF_INET, sin_port=htons(53), ...}, 16) = 29

    // DNS/resolver query detection via sendto
    if line.contains("sendto(") {
        if let Some(hostname) = parse_dns_sendto(line) {
            return Some(TracedAccess::DnsQuery(hostname));
        }
        // Check for systemd-resolved Varlink JSON protocol
        if let Some(hostname) = parse_resolved_sendto(line) {
            return Some(TracedAccess::DnsQuery(hostname));
        }
        return None;
    }

    // Network syscalls
    let network_syscalls = ["connect", "bind"];
    for &syscall in &network_syscalls {
        if line.contains(&format!("{}(", syscall)) {
            let kind = match syscall {
                "connect" => NetworkAccessKind::Connect,
                _ => NetworkAccessKind::Bind,
            };
            if let Some(na) = parse_network_syscall(line, kind) {
                return Some(TracedAccess::Network(na));
            }
            return None;
        }
    }

    // File syscalls
    let file_syscalls = [
        "openat", "open", "access", "stat", "lstat", "readlink", "execve", "creat", "mkdir",
        "rename", "unlink",
    ];

    let syscall = file_syscalls
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

    Some(TracedAccess::File(FileAccess {
        path: PathBuf::from(path),
        is_write,
    }))
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
                        if let Some(c) = chars.next() {
                            octal.push(c);
                        }
                    }
                    if let Ok(val) = u8::from_str_radix(&octal, 8) {
                        result.push(val as char);
                    } else {
                        // Malformed octal - pass through literally
                        result.push('\\');
                        result.push_str(&octal);
                    }
                }
                Some('x') => {
                    chars.next(); // consume 'x'
                                  // Hex escape \xNN - must have exactly 2 hex digits
                    let mut hex = String::new();
                    for _ in 0..2 {
                        if chars.peek().is_some_and(|c| c.is_ascii_hexdigit()) {
                            if let Some(c) = chars.next() {
                                hex.push(c);
                            }
                        } else {
                            break;
                        }
                    }
                    if hex.len() == 2 {
                        if let Ok(val) = u8::from_str_radix(&hex, 16) {
                            result.push(val as char);
                        } else {
                            // Malformed hex - pass through literally
                            result.push('\\');
                            result.push('x');
                            result.push_str(&hex);
                        }
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

    // Get system paths that are already allowed (from policy.json groups)
    let loaded_policy = crate::policy::load_embedded_policy()?;
    let system_read_paths = crate::policy::get_system_read_paths(&loaded_policy);
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
        if is_covered_by_set(&canonical, &system_read_set)? {
            if show_all {
                result.system_covered.insert(canonical);
            }
            continue;
        }

        // Check if covered by profile
        if is_covered_by_profile(&canonical, &profile_paths)? {
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
fn is_covered_by_set(path: &Path, allowed: &HashSet<&str>) -> Result<bool> {
    for allowed_path in allowed {
        let allowed_expanded = expand_home(allowed_path)?;
        if let Ok(allowed_canonical) = std::fs::canonicalize(&allowed_expanded) {
            if path.starts_with(&allowed_canonical) {
                return Ok(true);
            }
        }
        // Also check without canonicalization for paths that may not exist
        let allowed_path_buf = PathBuf::from(&allowed_expanded);
        if path.starts_with(&allowed_path_buf) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Check if a path is covered by profile paths
#[cfg(target_os = "linux")]
fn is_covered_by_profile(path: &Path, profile_paths: &HashSet<String>) -> Result<bool> {
    for profile_path in profile_paths {
        let expanded = expand_home(profile_path)?;
        if let Ok(canonical) = std::fs::canonicalize(&expanded) {
            if path.starts_with(&canonical) {
                return Ok(true);
            }
        }
        let path_buf = PathBuf::from(&expanded);
        if path.starts_with(&path_buf) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Expand ~ to home directory
#[cfg(target_os = "linux")]
fn expand_home(path: &str) -> Result<String> {
    use crate::config;

    if path.starts_with('~') {
        let home = config::validated_home()?;
        return Ok(path.replacen('~', &home, 1));
    }
    if path.starts_with("$HOME") {
        let home = config::validated_home()?;
        return Ok(path.replacen("$HOME", &home, 1));
    }
    Ok(path.to_string())
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

/// Extract a substring between a prefix and suffix
#[cfg(target_os = "linux")]
fn extract_between<'a>(s: &'a str, prefix: &str, suffix: &str) -> Option<&'a str> {
    let start = s.find(prefix)?;
    let after = &s[start + prefix.len()..];
    let end = after.find(suffix)?;
    Some(&after[..end])
}

/// Parse a network syscall (connect or bind) from strace output
#[cfg(target_os = "linux")]
fn parse_network_syscall(line: &str, kind: NetworkAccessKind) -> Option<NetworkAccess> {
    // Skip Unix domain sockets — local IPC, not network
    if line.contains("sa_family=AF_UNIX") || line.contains("sa_family=AF_LOCAL") {
        return None;
    }

    let (addr, port) = if line.contains("sa_family=AF_INET6") {
        // IPv6: inet_pton(AF_INET6, "::1") and sin6_port=htons(443)
        let port_str = extract_between(line, "sin6_port=htons(", ")")?;
        let addr_str = extract_between(line, "inet_pton(AF_INET6, \"", "\"")?;
        let port: u16 = port_str.parse().ok()?;
        let addr: IpAddr = addr_str.parse().ok()?;
        (addr, port)
    } else if line.contains("sa_family=AF_INET") {
        // IPv4: inet_addr("93.184.216.34") and sin_port=htons(443)
        let port_str = extract_between(line, "sin_port=htons(", ")")?;
        let addr_str = extract_between(line, "inet_addr(\"", "\"")?;
        let port: u16 = port_str.parse().ok()?;
        let addr: IpAddr = addr_str.parse().ok()?;
        (addr, port)
    } else {
        return None;
    };

    // Filter out port 0 (ephemeral/OS-assigned)
    if port == 0 {
        return None;
    }

    Some(NetworkAccess {
        addr,
        port,
        kind,
        queried_hostname: None,
    })
}

/// Parse a DNS query from a sendto syscall to extract the queried hostname.
///
/// Only processes sendto calls to port 53 (DNS). Extracts the query
/// hostname from the DNS wire format in the buffer argument.
#[cfg(target_os = "linux")]
fn parse_dns_sendto(line: &str) -> Option<String> {
    // Only interested in DNS (port 53)
    if !line.contains("htons(53)") {
        return None;
    }
    // Must be IP family (not unix socket)
    if !line.contains("AF_INET") {
        return None;
    }

    let buf_str = extract_sendto_buffer(line)?;
    let bytes = unescape_strace_bytes(&buf_str);
    parse_dns_query_hostname(&bytes)
}

/// Parse a systemd-resolved Varlink hostname resolution request.
///
/// systemd-resolved uses a JSON-based Varlink protocol over a Unix socket.
/// The sendto buffer contains JSON like:
/// `{"method":"io.systemd.Resolve.ResolveHostname","parameters":{"name":"example.com",...}}`
///
/// In strace output, quotes inside the buffer are C-escaped as `\"`, so we
/// must extract and unescape the buffer before searching for the hostname.
#[cfg(target_os = "linux")]
fn parse_resolved_sendto(line: &str) -> Option<String> {
    // Quick filter: ResolveHostname is plain ASCII, visible in raw strace output
    if !line.contains("ResolveHostname") {
        return None;
    }

    // Extract the buffer content and unescape C-style escapes (\" → ", etc.)
    let buf_str = extract_sendto_buffer(line)?;
    let unescaped = unescape_strace_string(&buf_str);

    // Extract hostname from "name":"HOSTNAME" in the unescaped JSON
    let name_str = extract_between(&unescaped, "\"name\":\"", "\"")?;

    // Validate: must look like a hostname (not empty, contains a dot, ASCII only)
    if name_str.is_empty() || !name_str.contains('.') {
        return None;
    }
    if !name_str
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return None;
    }

    Some(name_str.to_string())
}

/// Extract the buffer string from a sendto syscall line.
///
/// Given `sendto(fd, "BUFFER", len, ...)`, returns the content between quotes.
#[cfg(target_os = "linux")]
fn extract_sendto_buffer(line: &str) -> Option<String> {
    let start = line.find("sendto(")?;
    let after = &line[start..];

    // Find first '"' — start of buffer
    let q_start = after.find('"')? + 1;
    let remaining = &after[q_start..];

    // Find unescaped closing '"'
    let bytes = remaining.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2; // skip escape sequence
        } else if bytes[i] == b'"' {
            return Some(remaining[..i].to_string());
        } else {
            i += 1;
        }
    }
    None
}

/// Convert a C-escaped strace string to raw bytes.
///
/// Reuses the char-level unescaping from `unescape_strace_string` and
/// converts each char back to its byte value (all values are 0–255).
#[cfg(target_os = "linux")]
fn unescape_strace_bytes(s: &str) -> Vec<u8> {
    unescape_strace_string(s).chars().map(|c| c as u8).collect()
}

/// Parse a hostname from DNS wire format query data.
///
/// Expects at least the 12-byte DNS header followed by the question section.
/// Returns the queried hostname (e.g., "example.com") or None if the data
/// is malformed or truncated.
#[cfg(target_os = "linux")]
fn parse_dns_query_hostname(data: &[u8]) -> Option<String> {
    // Minimum: 12-byte header + at least 1 label byte
    if data.len() < 13 {
        return None;
    }

    let mut pos = 12; // skip DNS header
    let mut labels = Vec::new();

    loop {
        if pos >= data.len() {
            return None; // truncated
        }

        let len = data[pos] as usize;
        pos += 1;

        if len == 0 {
            break; // root label — end of hostname
        }

        // Compression pointer (high 2 bits set) — shouldn't appear in queries
        if len & 0xC0 != 0 {
            return None;
        }

        // DNS labels are max 63 bytes
        if len > 63 {
            return None;
        }

        if pos + len > data.len() {
            return None; // truncated
        }

        // Label must be valid ASCII
        let label = std::str::from_utf8(&data[pos..pos + len]).ok()?;

        // Validate: DNS labels contain alphanumeric, hyphen, underscore
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }

        labels.push(label.to_string());
        pos += len;
    }

    if labels.is_empty() {
        return None;
    }

    Some(labels.join("."))
}

/// Process raw network accesses into categorized summaries.
///
/// Uses forward DNS correlation from captured DNS queries to map IPs to
/// hostnames. Falls back to reverse DNS for unmatched IPs when `resolve_dns`
/// is true.
#[cfg(target_os = "linux")]
fn process_network_accesses(
    accesses: Vec<NetworkAccess>,
    dns_queries: Vec<String>,
    resolve_dns: bool,
) -> (Vec<NetworkConnectionSummary>, Vec<NetworkConnectionSummary>) {
    let mut connect_counts: HashMap<(IpAddr, u16), usize> = HashMap::new();
    let mut bind_counts: HashMap<(IpAddr, u16), usize> = HashMap::new();

    for access in &accesses {
        let key = (access.addr, access.port);
        match access.kind {
            NetworkAccessKind::Connect => {
                *connect_counts.entry(key).or_insert(0) += 1;
            }
            NetworkAccessKind::Bind => {
                *bind_counts.entry(key).or_insert(0) += 1;
            }
        }
    }

    // Build IP → hostname mapping using three strategies (in priority order):
    // 1. Timing-based: hostname attached directly from preceding DNS query
    // 2. Forward DNS: resolve captured hostnames to IPs
    // 3. Reverse DNS: lookup IP → hostname as last resort
    let hostnames = if resolve_dns {
        // Strategy 1: Use hostnames attached during tracing (timing correlation)
        let mut map: HashMap<IpAddr, String> = HashMap::new();
        for access in &accesses {
            if let Some(ref hostname) = access.queried_hostname {
                map.entry(access.addr).or_insert_with(|| hostname.clone());
            }
        }

        // Strategy 2: Forward DNS for IPs not covered by timing correlation
        let all_ips: HashSet<IpAddr> = accesses.iter().map(|a| a.addr).collect();
        let unresolved_after_timing: HashSet<IpAddr> = all_ips
            .iter()
            .filter(|ip| !map.contains_key(ip))
            .copied()
            .collect();

        if !unresolved_after_timing.is_empty() && !dns_queries.is_empty() {
            let forward = resolve_forward_dns(&dns_queries);
            for (ip, hostname) in forward {
                map.entry(ip).or_insert(hostname);
            }
        }

        // Strategy 3: Reverse DNS for anything still unresolved
        let unresolved_after_forward: HashSet<IpAddr> = all_ips
            .iter()
            .filter(|ip| !map.contains_key(ip))
            .copied()
            .collect();

        if !unresolved_after_forward.is_empty() {
            let reverse = resolve_reverse_dns(&unresolved_after_forward);
            map.extend(reverse);
        }

        map
    } else {
        HashMap::new()
    };

    let build_summaries =
        |counts: &HashMap<(IpAddr, u16), usize>| -> Vec<NetworkConnectionSummary> {
            let mut summaries: Vec<NetworkConnectionSummary> = counts
                .iter()
                .map(|(&(addr, port), &count)| NetworkConnectionSummary {
                    endpoint: NetworkEndpoint {
                        addr,
                        port,
                        hostname: hostnames.get(&addr).cloned(),
                    },
                    count,
                })
                .collect();
            summaries.sort();
            summaries
        };

    (
        build_summaries(&connect_counts),
        build_summaries(&bind_counts),
    )
}

/// Resolve captured DNS query hostnames to IPs via forward DNS lookup.
///
/// For each hostname the traced program queried, resolves it to its current
/// IPs to build an IP→hostname mapping. This gives the actual hostname the
/// program intended to reach (e.g., "google.com") rather than infrastructure
/// names from reverse DNS (e.g., "jr-in-f100.1e100.net").
#[cfg(target_os = "linux")]
fn resolve_forward_dns(hostnames: &[String]) -> HashMap<IpAddr, String> {
    let mut result = HashMap::new();
    let unique: HashSet<&String> = hostnames.iter().collect();

    for hostname in unique {
        match dns_lookup::lookup_host(hostname) {
            Ok(ips) => {
                for ip in ips {
                    // First hostname to resolve to this IP wins
                    result.entry(ip).or_insert_with(|| hostname.clone());
                }
            }
            Err(e) => {
                debug!("Forward DNS lookup failed for {}: {}", hostname, e);
            }
        }
    }

    result
}

/// Resolve IP addresses to hostnames via reverse DNS (fallback)
#[cfg(target_os = "linux")]
fn resolve_reverse_dns(ips: &HashSet<IpAddr>) -> HashMap<IpAddr, String> {
    let mut result = HashMap::new();

    for &ip in ips {
        match dns_lookup::lookup_addr(&ip) {
            Ok(hostname) => {
                // Skip if the hostname is just the IP address stringified
                if hostname != ip.to_string() {
                    result.insert(ip, hostname);
                }
            }
            Err(e) => {
                debug!("Reverse DNS lookup failed for {}: {}", ip, e);
            }
        }
    }

    result
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// Helper to extract FileAccess from TracedAccess
    fn expect_file_access(traced: Option<TracedAccess>) -> FileAccess {
        match traced {
            Some(TracedAccess::File(fa)) => fa,
            other => panic!("Expected File, got {:?}", other),
        }
    }

    /// Helper to extract NetworkAccess from TracedAccess
    fn expect_network_access(traced: Option<TracedAccess>) -> NetworkAccess {
        match traced {
            Some(TracedAccess::Network(na)) => na,
            other => panic!("Expected Network, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_strace_openat() {
        let line = r#"openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3"#;
        let access = expect_file_access(parse_strace_line(line));
        assert_eq!(access.path, PathBuf::from("/etc/passwd"));
        assert!(!access.is_write);
    }

    #[test]
    fn test_parse_strace_openat_write() {
        let line = r#"openat(AT_FDCWD, "/tmp/test", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 4"#;
        let access = expect_file_access(parse_strace_line(line));
        assert_eq!(access.path, PathBuf::from("/tmp/test"));
        assert!(access.is_write);
    }

    #[test]
    fn test_parse_strace_stat() {
        let line = r#"stat("/usr/bin/bash", {st_mode=S_IFREG|0755, ...}) = 0"#;
        let access = expect_file_access(parse_strace_line(line));
        assert_eq!(access.path, PathBuf::from("/usr/bin/bash"));
        assert!(!access.is_write);
    }

    #[test]
    fn test_parse_strace_execve() {
        let line = r#"execve("/usr/bin/ls", ["ls", "-la"], 0x...) = 0"#;
        let access = expect_file_access(parse_strace_line(line));
        assert_eq!(access.path, PathBuf::from("/usr/bin/ls"));
        assert!(!access.is_write);
    }

    #[test]
    fn test_extract_path_from_openat() {
        let line = r#"openat(AT_FDCWD, "/some/path", O_RDONLY) = 3"#;
        let path = extract_path_from_syscall(line, "openat").expect("should extract");
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
        assert_eq!(expand_home("~/foo").expect("valid home"), "/home/test/foo");
        assert_eq!(
            expand_home("$HOME/bar").expect("valid home"),
            "/home/test/bar"
        );
        assert_eq!(
            expand_home("/absolute/path").expect("no expansion needed"),
            "/absolute/path"
        );
    }

    #[test]
    fn test_collapse_to_parent() {
        // For a file that doesn't exist, collapse to parent
        let path = PathBuf::from("/some/dir/file.txt");
        let collapsed = collapse_to_parent(&path);
        assert_eq!(collapsed, PathBuf::from("/some/dir"));
    }

    #[test]
    fn test_learn_result_to_json() {
        let mut result = LearnResult::new();
        result.read_paths.insert(PathBuf::from("/some/read/path"));
        result.write_paths.insert(PathBuf::from("/some/write/path"));

        let json = result.to_json();
        assert!(json.contains("filesystem"));
        assert!(json.contains("/some/read/path"));
        assert!(json.contains("/some/write/path"));
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

    // --- Network parsing tests ---

    #[test]
    fn test_parse_connect_ipv4() {
        let line = r#"connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0"#;
        let access = expect_network_access(parse_strace_line(line));
        assert_eq!(access.addr, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(access.port, 443);
        assert!(matches!(access.kind, NetworkAccessKind::Connect));
    }

    #[test]
    fn test_parse_connect_ipv6() {
        let line = r#"connect(3, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2606:2800:220:1:248:1893:25c8:1946"), sin6_scope_id=0}, 28) = 0"#;
        let access = expect_network_access(parse_strace_line(line));
        assert_eq!(
            access.addr,
            "2606:2800:220:1:248:1893:25c8:1946"
                .parse::<IpAddr>()
                .unwrap()
        );
        assert_eq!(access.port, 443);
        assert!(matches!(access.kind, NetworkAccessKind::Connect));
    }

    #[test]
    fn test_parse_connect_unix_ignored() {
        let line =
            r#"connect(3, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT"#;
        assert!(parse_strace_line(line).is_none());
    }

    #[test]
    fn test_parse_bind_ipv4() {
        let line = r#"bind(4, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("0.0.0.0")}, 16) = 0"#;
        let access = expect_network_access(parse_strace_line(line));
        assert_eq!(access.addr, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(access.port, 8080);
        assert!(matches!(access.kind, NetworkAccessKind::Bind));
    }

    #[test]
    fn test_parse_bind_ipv6() {
        let line = r#"bind(4, {sa_family=AF_INET6, sin6_port=htons(3000), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::"), sin6_scope_id=0}, 28) = 0"#;
        let access = expect_network_access(parse_strace_line(line));
        assert_eq!(access.addr, "::".parse::<IpAddr>().unwrap());
        assert_eq!(access.port, 3000);
        assert!(matches!(access.kind, NetworkAccessKind::Bind));
    }

    #[test]
    fn test_parse_connect_failed() {
        // Failed connections should still be captured — they reveal intent
        let line = r#"connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("10.0.0.1")}, 16) = -1 ECONNREFUSED (Connection refused)"#;
        let access = expect_network_access(parse_strace_line(line));
        assert_eq!(access.addr, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(access.port, 80);
    }

    #[test]
    fn test_parse_connect_port_zero_ignored() {
        let line = r#"connect(3, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("0.0.0.0")}, 16) = 0"#;
        assert!(parse_strace_line(line).is_none());
    }

    #[test]
    fn test_existing_file_parsing_unchanged() {
        // Regression: ensure file syscalls still parse correctly after refactor
        let lines = [
            (
                r#"openat(AT_FDCWD, "/etc/hosts", O_RDONLY|O_CLOEXEC) = 3"#,
                "/etc/hosts",
                false,
            ),
            (
                r#"access("/etc/ld.so.preload", R_OK) = -1 ENOENT"#,
                "/etc/ld.so.preload",
                false,
            ),
            (r#"mkdir("/tmp/newdir", 0755) = 0"#, "/tmp/newdir", true),
        ];

        for (line, expected_path, expected_write) in &lines {
            let access = expect_file_access(parse_strace_line(line));
            assert_eq!(access.path, PathBuf::from(expected_path));
            assert_eq!(access.is_write, *expected_write);
        }
    }

    #[test]
    fn test_network_dedup() {
        // Duplicate endpoints should be merged with count
        let accesses = vec![
            NetworkAccess {
                addr: "93.184.216.34".parse().unwrap(),
                port: 443,
                kind: NetworkAccessKind::Connect,
                queried_hostname: None,
            },
            NetworkAccess {
                addr: "93.184.216.34".parse().unwrap(),
                port: 443,
                kind: NetworkAccessKind::Connect,
                queried_hostname: None,
            },
            NetworkAccess {
                addr: "93.184.216.34".parse().unwrap(),
                port: 443,
                kind: NetworkAccessKind::Connect,
                queried_hostname: None,
            },
        ];

        let (outbound, listening) = process_network_accesses(accesses, vec![], false);
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].count, 3);
        assert!(listening.is_empty());
    }

    #[test]
    fn test_learn_result_network_json() {
        let mut result = LearnResult::new();
        result.outbound_connections.push(NetworkConnectionSummary {
            endpoint: NetworkEndpoint {
                addr: "93.184.216.34".parse().unwrap(),
                port: 443,
                hostname: Some("example.com".to_string()),
            },
            count: 5,
        });
        result.listening_ports.push(NetworkConnectionSummary {
            endpoint: NetworkEndpoint {
                addr: "0.0.0.0".parse().unwrap(),
                port: 3000,
                hostname: None,
            },
            count: 1,
        });

        let json = result.to_json();
        assert!(json.contains("\"network\""));
        assert!(json.contains("\"outbound\""));
        assert!(json.contains("\"listening\""));
        assert!(json.contains("93.184.216.34"));
        assert!(json.contains("443"));
        assert!(json.contains("example.com"));
        assert!(json.contains("0.0.0.0"));
        assert!(json.contains("3000"));
    }

    #[test]
    fn test_learn_result_network_summary() {
        let mut result = LearnResult::new();
        result.outbound_connections.push(NetworkConnectionSummary {
            endpoint: NetworkEndpoint {
                addr: "93.184.216.34".parse().unwrap(),
                port: 443,
                hostname: Some("example.com".to_string()),
            },
            count: 12,
        });
        result.listening_ports.push(NetworkConnectionSummary {
            endpoint: NetworkEndpoint {
                addr: "0.0.0.0".parse().unwrap(),
                port: 3000,
                hostname: None,
            },
            count: 1,
        });

        let summary = result.to_summary();
        assert!(summary.contains("Outbound connections:"));
        assert!(summary.contains("example.com (93.184.216.34):443 (12x)"));
        assert!(summary.contains("Listening ports:"));
        assert!(summary.contains("0.0.0.0:3000"));
        // Count of 1 should NOT show "(1x)"
        assert!(!summary.contains("(1x)"));
    }

    #[test]
    fn test_has_network_activity() {
        let mut result = LearnResult::new();
        assert!(!result.has_network_activity());

        result.outbound_connections.push(NetworkConnectionSummary {
            endpoint: NetworkEndpoint {
                addr: "10.0.0.1".parse().unwrap(),
                port: 80,
                hostname: None,
            },
            count: 1,
        });
        assert!(result.has_network_activity());

        let mut result2 = LearnResult::new();
        result2.listening_ports.push(NetworkConnectionSummary {
            endpoint: NetworkEndpoint {
                addr: "0.0.0.0".parse().unwrap(),
                port: 8080,
                hostname: None,
            },
            count: 1,
        });
        assert!(result2.has_network_activity());
    }

    #[test]
    fn test_extract_between() {
        assert_eq!(extract_between("htons(443)", "htons(", ")"), Some("443"));
        assert_eq!(
            extract_between(r#"inet_addr("1.2.3.4")"#, r#"inet_addr(""#, r#"""#),
            Some("1.2.3.4")
        );
        assert_eq!(extract_between("no match here", "foo(", ")"), None);
        assert_eq!(extract_between("prefix(", "prefix(", ")"), None);
    }

    #[test]
    fn test_parse_connect_af_local_ignored() {
        // AF_LOCAL is an alias for AF_UNIX, should also be ignored
        let line = r#"connect(3, {sa_family=AF_LOCAL, sun_path="/tmp/socket"}, 110) = 0"#;
        assert!(parse_strace_line(line).is_none());
    }

    #[test]
    fn test_format_network_summary_with_hostname() {
        let conn = NetworkConnectionSummary {
            endpoint: NetworkEndpoint {
                addr: "93.184.216.34".parse().unwrap(),
                port: 443,
                hostname: Some("example.com".to_string()),
            },
            count: 5,
        };
        let line = format_network_summary(&conn);
        assert_eq!(line, "  example.com (93.184.216.34):443 (5x)");
    }

    #[test]
    fn test_format_network_summary_without_hostname() {
        let conn = NetworkConnectionSummary {
            endpoint: NetworkEndpoint {
                addr: "10.0.0.1".parse().unwrap(),
                port: 8080,
                hostname: None,
            },
            count: 1,
        };
        let line = format_network_summary(&conn);
        assert_eq!(line, "  10.0.0.1:8080");
    }

    // --- DNS query parsing tests ---

    #[test]
    fn test_parse_dns_query_hostname_simple() {
        // DNS wire format for "example.com"
        // Header (12 bytes) + \x07example\x03com\x00 + type A + class IN
        let mut data = vec![
            0xab, 0x12, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        data.push(7); // length of "example"
        data.extend_from_slice(b"example");
        data.push(3); // length of "com"
        data.extend_from_slice(b"com");
        data.push(0); // root label
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // type A, class IN

        let hostname = parse_dns_query_hostname(&data).expect("should parse");
        assert_eq!(hostname, "example.com");
    }

    #[test]
    fn test_parse_dns_query_hostname_subdomain() {
        // DNS wire format for "api.example.com"
        let mut data = vec![0; 12]; // header
        data.push(3);
        data.extend_from_slice(b"api");
        data.push(7);
        data.extend_from_slice(b"example");
        data.push(3);
        data.extend_from_slice(b"com");
        data.push(0);
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        let hostname = parse_dns_query_hostname(&data).expect("should parse");
        assert_eq!(hostname, "api.example.com");
    }

    #[test]
    fn test_parse_dns_query_hostname_truncated() {
        // Data too short for header
        assert!(parse_dns_query_hostname(&[0; 10]).is_none());
        // Header only, no labels
        assert!(parse_dns_query_hostname(&[0; 12]).is_none());
    }

    #[test]
    fn test_unescape_strace_bytes() {
        let bytes = unescape_strace_bytes(r#"\7example\3com\0"#);
        assert_eq!(bytes[0], 7);
        assert_eq!(&bytes[1..8], b"example");
        assert_eq!(bytes[8], 3);
        assert_eq!(&bytes[9..12], b"com");
        assert_eq!(bytes[12], 0);
    }

    #[test]
    fn test_extract_sendto_buffer() {
        let line = r#"sendto(5, "\7example\3com\0", 13, 0, {}, 16) = 13"#;
        let buf = extract_sendto_buffer(line).expect("should extract");
        assert_eq!(buf, r#"\7example\3com\0"#);
    }

    #[test]
    fn test_extract_sendto_buffer_with_escaped_backslash() {
        // Buffer containing \\  (escaped backslash)
        let line = r#"sendto(5, "hello\\world", 11, 0, {}, 16) = 11"#;
        let buf = extract_sendto_buffer(line).expect("should extract");
        assert_eq!(buf, r#"hello\\world"#);
    }

    #[test]
    fn test_parse_dns_sendto_ipv4() {
        let line = r#"sendto(5, "\xab\x12\1\0\0\1\0\0\0\0\0\0\7example\3com\0\0\1\0\1", 29, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = 29"#;
        let hostname = parse_dns_sendto(line).expect("should parse DNS query");
        assert_eq!(hostname, "example.com");
    }

    #[test]
    fn test_parse_dns_sendto_ipv6_dest() {
        // DNS query sent to IPv6 DNS server (AF_INET6 contains "AF_INET" as substring)
        let line = r#"sendto(5, "\xab\x12\1\0\0\1\0\0\0\0\0\0\6google\3com\0\0\1\0\1", 28, 0, {sa_family=AF_INET6, sin6_port=htons(53), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2001:4860:4860::8888"), sin6_scope_id=0}, 28) = 28"#;
        let hostname = parse_dns_sendto(line).expect("should parse DNS query via IPv6");
        assert_eq!(hostname, "google.com");
    }

    #[test]
    fn test_parse_dns_sendto_non_dns_ignored() {
        // sendto to port 80, not DNS
        let line = r#"sendto(5, "GET / HTTP/1.1\r\n", 16, 0, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("93.184.216.34")}, 16) = 16"#;
        assert!(parse_dns_sendto(line).is_none());
    }

    #[test]
    fn test_parse_strace_line_dns_query() {
        let line = r#"sendto(5, "\xab\x12\1\0\0\1\0\0\0\0\0\0\7example\3com\0\0\1\0\1", 29, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = 29"#;
        match parse_strace_line(line) {
            Some(TracedAccess::DnsQuery(hostname)) => assert_eq!(hostname, "example.com"),
            other => panic!("Expected DnsQuery, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_strace_line_sendto_non_dns_returns_none() {
        // sendto to non-DNS port should return None (not a file or network access we track)
        let line = r#"sendto(5, "data", 4, 0, {sa_family=AF_INET, sin_port=htons(1234), sin_addr=inet_addr("10.0.0.1")}, 16) = 4"#;
        assert!(parse_strace_line(line).is_none());
    }

    #[test]
    fn test_dns_timing_correlation_maps_hostname() {
        // Simulate: program queried "example.com", then connected to an IP.
        // The queried_hostname attached during tracing should map directly.
        let accesses = vec![NetworkAccess {
            addr: "93.184.216.34".parse().unwrap(),
            port: 443,
            kind: NetworkAccessKind::Connect,
            queried_hostname: Some("example.com".to_string()),
        }];
        let dns_queries = vec!["example.com".to_string()];

        let (outbound, _) = process_network_accesses(accesses, dns_queries, true);
        assert_eq!(outbound.len(), 1);
        // Timing correlation attaches the hostname directly — no DNS lookup needed
        assert_eq!(
            outbound[0].endpoint.hostname,
            Some("example.com".to_string())
        );
    }
}
