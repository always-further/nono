//! Linux learn mode implementation using strace

use super::{FileAccess, NetworkAccess, NetworkAccessKind};
use crate::cli::LearnArgs;
use crate::profile;
use nono::{NonoError, Result};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use tracing::{debug, info, warn};

/// Unified type for parsed strace accesses
#[derive(Debug, Clone)]
enum TracedAccess {
    File(FileAccess),
    Network(NetworkAccess),
    DnsQuery(String),
}

/// Check if strace is available
fn check_strace() -> Result<()> {
    match Command::new("strace").arg("--version").output() {
        Ok(output) if output.status.success() => Ok(()),
        _ => Err(NonoError::LearnError(
            "strace not found. Install with: apt install strace".to_string(),
        )),
    }
}

/// Run learn mode (Linux implementation)
pub fn run_learn(args: &LearnArgs) -> Result<super::LearnResult> {
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
    let mut result = super::process_accesses(raw_file_accesses, profile.as_ref(), args.all)?;

    // Process network accesses with forward DNS correlation
    let (outbound, listening) =
        super::process_network_accesses(raw_network_accesses, dns_queries, !args.no_rdns);
    result.outbound_connections = outbound;
    result.listening_ports = listening;

    Ok(result)
}

/// Run strace on the command and collect file accesses, network accesses, and DNS queries
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
        "openat,open,access,stat,lstat,readlink,execve,creat,mkdir,rename,unlink,connect,bind,sendto,sendmsg"
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
    // Track the most recently queried hostname per PID for timing-based
    // correlation. strace -f interleaves output from multiple PIDs, so a
    // global "last hostname" would incorrectly pair a DNS query from one
    // thread with a connect() from another.
    let mut pid_hostnames: HashMap<u32, String> = HashMap::new();
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

        let pid = extract_strace_pid(&line);

        // Parse strace output
        if let Some(access) = parse_strace_line(&line) {
            match access {
                TracedAccess::File(fa) => file_accesses.push(fa),
                TracedAccess::Network(mut na) => {
                    na.queried_hostname =
                        pid.and_then(|p| pid_hostnames.get(&p).cloned())
                            .or_else(|| {
                                // Fallback for single-process traces (no PID prefix)
                                if pid.is_none() && pid_hostnames.len() == 1 {
                                    pid_hostnames.values().next().cloned()
                                } else {
                                    None
                                }
                            });
                    network_accesses.push(na);
                }
                TracedAccess::DnsQuery(hostname) => {
                    if let Some(p) = pid {
                        pid_hostnames.insert(p, hostname.clone());
                    } else if pid_hostnames.is_empty() {
                        // Single-process trace with no PID prefix: use PID 0 as sentinel
                        pid_hostnames.insert(0, hostname.clone());
                    }
                    dns_queries.push(hostname);
                }
            }
        }
    }

    // Wait for child to finish
    let _ = child.wait();

    Ok((file_accesses, network_accesses, dns_queries))
}

/// Extract the PID from a strace line with `-f` (follow forks).
///
/// strace prefixes multi-process lines with `[pid NNNNN] `. Returns None
/// for single-process traces (no prefix).
fn extract_strace_pid(line: &str) -> Option<u32> {
    let trimmed = line.trim_start();
    let rest = trimmed.strip_prefix("[pid ")?;
    let end = rest.find(']')?;
    rest[..end].trim().parse().ok()
}

/// Parse a single strace line to extract file or network access
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

    // DNS/resolver query detection via sendto or sendmsg
    if line.contains("sendto(") || line.contains("sendmsg(") {
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
        path: std::path::PathBuf::from(path),
        is_write,
    }))
}

/// Extract path from strace syscall line
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

/// Extract a substring between a prefix and suffix
fn extract_between<'a>(s: &'a str, prefix: &str, suffix: &str) -> Option<&'a str> {
    let start = s.find(prefix)?;
    let after = &s[start + prefix.len()..];
    let end = after.find(suffix)?;
    Some(&after[..end])
}

/// Parse a network syscall (connect or bind) from strace output
fn parse_network_syscall(line: &str, kind: NetworkAccessKind) -> Option<NetworkAccess> {
    use std::net::IpAddr;

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
/// must extract and unescape the buffer before parsing the JSON.
fn parse_resolved_sendto(line: &str) -> Option<String> {
    // Quick filter: ResolveHostname is plain ASCII, visible in raw strace output
    if !line.contains("ResolveHostname") {
        return None;
    }

    // Extract the buffer content and unescape C-style escapes (\" → ", etc.)
    let buf_str = extract_sendto_buffer(line)?;
    let unescaped = unescape_strace_string(&buf_str);

    // The unescaped buffer may contain a trailing null byte from the Varlink
    // protocol. Strip it before parsing as JSON.
    let json_str = unescaped.trim_end_matches('\0');

    // Parse with serde_json for robust handling of whitespace and escaping
    let parsed: serde_json::Value = serde_json::from_str(json_str).ok()?;
    let name_str = parsed.pointer("/parameters/name")?.as_str()?;

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

/// Extract the buffer string from a sendto or sendmsg syscall line.
///
/// For `sendto(fd, "BUFFER", len, ...)`, extracts BUFFER from the second arg.
/// For `sendmsg(fd, {msg_name=..., msg_iov=[{iov_base="BUFFER", ...}], ...})`,
/// extracts BUFFER from the iov_base field.
fn extract_sendto_buffer(line: &str) -> Option<String> {
    // Determine where to start looking for the quoted buffer
    let search_start = if let Some(pos) = line.find("iov_base=") {
        // sendmsg: buffer is in iov_base="..."
        pos
    } else if let Some(pos) = line.find("sendto(") {
        // sendto: buffer is the second argument
        pos
    } else {
        return None;
    };

    let after = &line[search_start..];

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
fn unescape_strace_bytes(s: &str) -> Vec<u8> {
    unescape_strace_string(s).chars().map(|c| c as u8).collect()
}

/// Parse a hostname from DNS wire format query data.
///
/// Expects at least the 12-byte DNS header followed by the question section.
/// Returns the queried hostname (e.g., "example.com") or None if the data
/// is malformed or truncated.
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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
        use std::net::IpAddr;
        let line = r#"connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0"#;
        let access = expect_network_access(parse_strace_line(line));
        assert_eq!(access.addr, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(access.port, 443);
        assert!(matches!(access.kind, NetworkAccessKind::Connect));
    }

    #[test]
    fn test_parse_connect_ipv6() {
        use std::net::IpAddr;
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
        use std::net::IpAddr;
        let line = r#"bind(4, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("0.0.0.0")}, 16) = 0"#;
        let access = expect_network_access(parse_strace_line(line));
        assert_eq!(access.addr, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(access.port, 8080);
        assert!(matches!(access.kind, NetworkAccessKind::Bind));
    }

    #[test]
    fn test_parse_bind_ipv6() {
        use std::net::IpAddr;
        let line = r#"bind(4, {sa_family=AF_INET6, sin6_port=htons(3000), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::"), sin6_scope_id=0}, 28) = 0"#;
        let access = expect_network_access(parse_strace_line(line));
        assert_eq!(access.addr, "::".parse::<IpAddr>().unwrap());
        assert_eq!(access.port, 3000);
        assert!(matches!(access.kind, NetworkAccessKind::Bind));
    }

    #[test]
    fn test_parse_connect_failed() {
        use std::net::IpAddr;
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
        use super::super::{NetworkAccess, NetworkAccessKind};
        // Simulate: program queried "example.com", then connected to an IP.
        // The queried_hostname attached during tracing should map directly.
        let accesses = vec![NetworkAccess {
            addr: "93.184.216.34".parse().unwrap(),
            port: 443,
            kind: NetworkAccessKind::Connect,
            queried_hostname: Some("example.com".to_string()),
        }];
        let dns_queries = vec!["example.com".to_string()];

        let (outbound, _) = super::super::process_network_accesses(accesses, dns_queries, true);
        assert_eq!(outbound.len(), 1);
        // Timing correlation attaches the hostname directly — no DNS lookup needed
        assert_eq!(
            outbound[0].endpoint.hostname,
            Some("example.com".to_string())
        );
    }

    // --- PID extraction tests ---

    #[test]
    fn test_extract_strace_pid_with_prefix() {
        let line = r#"[pid 12345] sendto(5, "data", 4, 0, {sa_family=AF_INET, ...}, 16) = 4"#;
        assert_eq!(extract_strace_pid(line), Some(12345));
    }

    #[test]
    fn test_extract_strace_pid_without_prefix() {
        let line = r#"sendto(5, "data", 4, 0, {sa_family=AF_INET, ...}, 16) = 4"#;
        assert_eq!(extract_strace_pid(line), None);
    }

    #[test]
    fn test_extract_strace_pid_padded() {
        // strace sometimes pads PID with spaces
        let line = r#"[pid  1234] openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3"#;
        assert_eq!(extract_strace_pid(line), Some(1234));
    }

    // --- sendmsg buffer extraction tests ---

    #[test]
    fn test_extract_sendmsg_buffer() {
        let line = r#"sendmsg(5, {msg_name={sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, msg_namelen=16, msg_iov=[{iov_base="\7example\3com\0", iov_len=13}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 13"#;
        let buf = extract_sendto_buffer(line).expect("should extract from sendmsg");
        assert_eq!(buf, r#"\7example\3com\0"#);
    }

    #[test]
    fn test_parse_resolved_sendto_json() {
        // systemd-resolved Varlink protocol with proper JSON parsing
        let line = r#"sendto(5, "{\"method\":\"io.systemd.Resolve.ResolveHostname\",\"parameters\":{\"name\":\"example.com\",\"flags\":0}}\0", 94, MSG_DONTWAIT|MSG_NOSIGNAL, NULL, 0) = 94"#;
        let hostname = parse_resolved_sendto(line).expect("should parse resolved JSON");
        assert_eq!(hostname, "example.com");
    }

    #[test]
    fn test_parse_sendmsg_dns_query() {
        // DNS query sent via sendmsg instead of sendto
        let line = r#"sendmsg(5, {msg_name={sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, msg_namelen=16, msg_iov=[{iov_base="\xab\x12\1\0\0\1\0\0\0\0\0\0\7example\3com\0\0\1\0\1", iov_len=29}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 29"#;
        let hostname = parse_dns_sendto(line).expect("should parse DNS query from sendmsg");
        assert_eq!(hostname, "example.com");
    }
}
