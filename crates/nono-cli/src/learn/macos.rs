//! macOS learn mode implementation using Seatbelt report-mode
//!
//! Uses `(allow (with report) default)` Seatbelt profile — allows all ops
//! but logs each to kernel log. The parent reads kernel log events via
//! `log stream` to discover the traced process's file and network accesses.

use super::{FileAccess, NetworkAccess, NetworkAccessKind};
use crate::cli::LearnArgs;
use crate::profile;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult};
use nono::{NonoError, Result};
use std::ffi::{CStr, CString};
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::os::raw::c_char;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::ptr;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tracing::debug;

// FFI bindings to macOS sandbox API
// Same declarations as in crates/nono/src/sandbox/macos.rs
extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> i32;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

/// Parsed event from seatbelt log stream
#[derive(Debug)]
enum TracedEvent {
    File(FileAccess),
    Network(NetworkAccess),
}

/// Run learn mode (macOS implementation)
pub fn run_learn(args: &LearnArgs) -> Result<super::LearnResult> {
    // Load profile if specified
    let profile = if let Some(ref profile_name) = args.profile {
        Some(profile::load_profile(profile_name)?)
    } else {
        None
    };

    // Resolve target program path before fork for a clear error message
    if args.command.is_empty() {
        return Err(NonoError::NoCommand);
    }
    let program = which::which(&args.command[0])
        .map_err(|_| NonoError::LearnError(format!("Command not found: {}", args.command[0])))?;

    let program_path = program
        .to_str()
        .ok_or_else(|| NonoError::LearnError("Program path contains invalid UTF-8".to_string()))?;

    // Prepare CStrings before fork (async-signal-safety)
    let sandbox_profile_cstr =
        CString::new("(version 1)(allow (with report) default)").map_err(|e| {
            NonoError::LearnError(format!("Failed to create sandbox profile CString: {}", e))
        })?;

    let program_cstr = CString::new(program_path)
        .map_err(|e| NonoError::LearnError(format!("Invalid program path: {}", e)))?;

    let args_cstrs: Vec<CString> = args
        .command
        .iter()
        .map(|a| {
            CString::new(a.as_str())
                .map_err(|e| NonoError::LearnError(format!("Invalid argument '{}': {}", a, e)))
        })
        .collect::<Result<_>>()?;

    // Start log stream process before fork so it captures all child events
    let mut log_child = start_log_stream()?;

    let log_stdout = log_child
        .stdout
        .take()
        .ok_or_else(|| NonoError::LearnError("Failed to get log stream stdout".to_string()))?;

    let mut log_reader = BufReader::new(log_stdout);

    // Wait for the log stream header line to confirm it's running
    let mut header = String::new();
    log_reader
        .read_line(&mut header)
        .map_err(|e| NonoError::LearnError(format!("Failed to read log stream header: {}", e)))?;

    // SAFETY: fork() is called before spawning any threads in this function.
    // All CStrings are prepared above for async-signal-safety in the child.
    let child_pid = match unsafe { fork() }
        .map_err(|e| NonoError::LearnError(format!("fork() failed: {}", e)))?
    {
        ForkResult::Child => {
            // Child process: apply sandbox then exec
            // SAFETY: Only async-signal-safe operations after fork.
            // All CStrings were prepared before fork.
            unsafe {
                let mut err_ptr: *mut c_char = ptr::null_mut();
                if sandbox_init(sandbox_profile_cstr.as_ptr(), 0, &mut err_ptr) != 0 {
                    if !err_ptr.is_null() {
                        sandbox_free_error(err_ptr);
                    }
                    nix::libc::_exit(126);
                }

                let args_refs: Vec<&CStr> = args_cstrs.iter().map(|c| c.as_c_str()).collect();

                // execvp replaces the process image; returns only on error
                let _ = execvp(program_cstr.as_c_str(), &args_refs);
                nix::libc::_exit(127);
            }
        }
        ForkResult::Parent { child } => child,
    };

    // Parent process: spawn reader thread to collect log events
    let (tx, rx) = mpsc::channel::<String>();
    let reader_thread = thread::spawn(move || {
        for line in log_reader.lines() {
            match line {
                Ok(line) => {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let start = Instant::now();
    let timeout_duration = args.timeout.map(Duration::from_secs);

    let mut file_accesses: Vec<FileAccess> = Vec::new();
    let mut network_accesses: Vec<NetworkAccess> = Vec::new();

    // Poll waitpid and drain event channel until child exits
    loop {
        // Drain available events
        while let Ok(line) = rx.try_recv() {
            if let Some(event) = parse_seatbelt_log_line(&line) {
                match event {
                    TracedEvent::File(fa) => file_accesses.push(fa),
                    TracedEvent::Network(na) => network_accesses.push(na),
                }
            }
        }

        // Check if child has exited
        match waitpid(child_pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(_, _)) | Ok(WaitStatus::Signaled(_, _, _)) => break,
            Ok(_) => {} // Still running
            Err(e) => {
                debug!("waitpid error: {}", e);
                break;
            }
        }

        // Check timeout
        if let Some(timeout) = timeout_duration {
            if start.elapsed() > timeout {
                let _ = nix::sys::signal::kill(child_pid, nix::sys::signal::Signal::SIGTERM);
                let _ = waitpid(child_pid, None);
                break;
            }
        }

        thread::sleep(Duration::from_millis(10));
    }

    // Drain window: allow remaining log events to arrive after child exits
    thread::sleep(Duration::from_millis(100));
    while let Ok(line) = rx.try_recv() {
        if let Some(event) = parse_seatbelt_log_line(&line) {
            match event {
                TracedEvent::File(fa) => file_accesses.push(fa),
                TracedEvent::Network(na) => network_accesses.push(na),
            }
        }
    }

    // Shut down log stream
    let _ = log_child.kill();
    let _ = log_child.wait();
    let _ = reader_thread.join();

    // Warn if no events were captured — most likely a privilege issue
    if file_accesses.is_empty() && network_accesses.is_empty() {
        eprintln!(
            "warning: no events captured from log stream \
             — ensure your user is in the admin group"
        );
    }

    // Process and categorize file paths (shared cross-platform code)
    let mut result = super::process_accesses(file_accesses, profile.as_ref(), args.all)?;

    // Process network accesses (no DNS queries on macOS — mDNSResponder handles DNS
    // outside our sandbox, so forward DNS correlation is unavailable)
    let (outbound, listening) =
        super::process_network_accesses(network_accesses, vec![], !args.no_rdns);
    result.outbound_connections = outbound;
    result.listening_ports = listening;

    Ok(result)
}

/// Start a `log stream` process filtered to Seatbelt kernel events
fn start_log_stream() -> Result<Child> {
    // Match both file and network sandbox report events
    let predicate = r#"process == "kernel" AND message CONTAINS "Sandbox: " AND (message CONTAINS " allow file-" OR message CONTAINS " allow network-")"#;

    Command::new("log")
        .args(["stream", "--level", "debug", "--predicate", predicate])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            NonoError::LearnError(format!(
                "Failed to start log stream (requires admin privileges): {}",
                e
            ))
        })
}

/// Parse a seatbelt log line into a TracedEvent.
///
/// Log line format (from `log stream`):
/// ```text
/// 2024-01-15 10:30:45.123456+0000  0x1234  Default  0x0  0  0  kernel: (Sandbox) Sandbox: bash(12345) allow file-read-data /usr/lib/libSystem.B.dylib
/// ```
///
/// The function extracts the operation and path/address from the "Sandbox: " portion.
fn parse_seatbelt_log_line(line: &str) -> Option<TracedEvent> {
    // Find "Sandbox: " marker
    let marker = "Sandbox: ";
    let idx = line.find(marker)?;
    let after_marker = &line[idx + marker.len()..];

    // Skip "processname(pid) " — find ") " to locate where the action starts
    let paren_close = after_marker.find(") ")?;
    let rest = &after_marker[paren_close + 2..];

    // Must start with "allow " (report mode always logs allows)
    let rest = rest.strip_prefix("allow ")?;

    // Split into operation and optional path/address
    let (operation, path_part) = match rest.find(' ') {
        Some(space_idx) => {
            let op = &rest[..space_idx];
            let path = rest[space_idx + 1..].trim();
            (op, if path.is_empty() { None } else { Some(path) })
        }
        None => (rest.trim(), None),
    };

    // File operations
    if operation.starts_with("file-") {
        let path_str = path_part?;
        if path_str.is_empty() {
            return None;
        }
        // Any file-write-* operation requires write access: file-write-data,
        // file-write-create, file-write-unlink, file-write-truncate,
        // file-write-mode, file-write-xattr, file-write-owner, file-write-times, etc.
        let is_write = operation.starts_with("file-write-");
        return Some(TracedEvent::File(FileAccess {
            path: PathBuf::from(path_str),
            is_write,
        }));
    }

    // Network operations
    if operation == "network-outbound" || operation == "network-bind" {
        let kind = if operation == "network-outbound" {
            NetworkAccessKind::Connect
        } else {
            NetworkAccessKind::Bind
        };

        // Network entries may include "*:port" or "addr:port"; skip Unix socket paths
        if let Some(addr_str) = path_part {
            if let Some(na) = parse_network_address(addr_str, kind) {
                return Some(TracedEvent::Network(na));
            }
        }
        // Network event without parseable address (e.g., mDNSResponder socket) — skip
        return None;
    }

    None
}

/// Parse a network address string from a seatbelt log event.
///
/// Handles formats:
/// - `*:port` (wildcard address)
/// - `addr:port` (specific IPv4, e.g. `93.184.216.34:443`)
/// - `addr:port` (IPv6 without brackets, e.g. `::1:443` where `::1` is the
///   address and `443` is the port — Seatbelt does not use `[addr]:port` notation)
///
/// The last `:` in the string is used as the addr/port separator (via `rfind`).
/// This works for both IPv4 and compact IPv6 notation.
///
/// Returns None for Unix socket paths (start with `/`) or unparseable strings.
fn parse_network_address(addr_str: &str, kind: NetworkAccessKind) -> Option<NetworkAccess> {
    // Unix socket paths start with '/' — not network addresses
    if addr_str.starts_with('/') {
        return None;
    }

    // Find the last ':' to split address from port
    let colon_idx = addr_str.rfind(':')?;
    let addr_part = &addr_str[..colon_idx];
    let port_str = &addr_str[colon_idx + 1..];

    let port: u16 = port_str.parse().ok()?;
    if port == 0 {
        return None;
    }

    let addr: IpAddr = if addr_part == "*" {
        // Wildcard: use unspecified address
        "0.0.0.0".parse().ok()?
    } else {
        addr_part.parse().ok()?
    };

    Some(NetworkAccess {
        addr,
        port,
        kind,
        queried_hostname: None,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn parse_file(line: &str) -> FileAccess {
        match parse_seatbelt_log_line(line) {
            Some(TracedEvent::File(fa)) => fa,
            other => panic!("Expected File event, got {:?}", other),
        }
    }

    fn parse_network(line: &str) -> NetworkAccess {
        match parse_seatbelt_log_line(line) {
            Some(TracedEvent::Network(na)) => na,
            other => panic!("Expected Network event, got {:?}", other),
        }
    }

    const LOG_PREFIX: &str =
        "2024-01-15 10:30:45.123456+0000  0x1234  Default  0x0  0  0  kernel: (Sandbox) ";

    fn make_line(msg: &str) -> String {
        format!("{}{}", LOG_PREFIX, msg)
    }

    #[test]
    fn test_parse_file_read_data() {
        let line =
            make_line("Sandbox: bash(12345) allow file-read-data /usr/lib/libSystem.B.dylib");
        let fa = parse_file(&line);
        assert_eq!(fa.path, PathBuf::from("/usr/lib/libSystem.B.dylib"));
        assert!(!fa.is_write);
    }

    #[test]
    fn test_parse_file_read_metadata() {
        let line = make_line("Sandbox: bash(12345) allow file-read-metadata /usr/bin/ls");
        let fa = parse_file(&line);
        assert_eq!(fa.path, PathBuf::from("/usr/bin/ls"));
        assert!(!fa.is_write);
    }

    #[test]
    fn test_parse_file_write_create() {
        let line = make_line("Sandbox: bash(12345) allow file-write-create /tmp/output.txt");
        let fa = parse_file(&line);
        assert_eq!(fa.path, PathBuf::from("/tmp/output.txt"));
        assert!(fa.is_write);
    }

    #[test]
    fn test_parse_file_write_data() {
        let line = make_line("Sandbox: bash(12345) allow file-write-data /tmp/output.txt");
        let fa = parse_file(&line);
        assert_eq!(fa.path, PathBuf::from("/tmp/output.txt"));
        assert!(fa.is_write);
    }

    #[test]
    fn test_parse_file_write_unlink_is_write() {
        // file-write-unlink (deletion) requires write access
        let line = make_line("Sandbox: bash(12345) allow file-write-unlink /tmp/old.txt");
        let fa = parse_file(&line);
        assert!(fa.is_write);
    }

    #[test]
    fn test_parse_file_write_ops_are_writes() {
        // All file-write-* operations must be classified as writes
        let write_ops = [
            "file-write-data",
            "file-write-create",
            "file-write-unlink",
            "file-write-truncate",
            "file-write-mode",
            "file-write-xattr",
            "file-write-owner",
            "file-write-times",
            "file-write-setugid",
        ];
        for op in &write_ops {
            let line = make_line(&format!("Sandbox: bash(12345) allow {} /tmp/file.txt", op));
            let fa = parse_file(&line);
            assert!(fa.is_write, "expected is_write=true for op={}", op);
        }
    }

    #[test]
    fn test_parse_network_outbound_mdns() {
        // mDNSResponder is a Unix socket path → should not parse as network address
        let line =
            make_line("Sandbox: curl(12345) allow network-outbound /private/var/run/mDNSResponder");
        assert!(parse_seatbelt_log_line(&line).is_none());
    }

    #[test]
    fn test_parse_network_outbound_tcp() {
        let line = make_line("Sandbox: curl(12345) allow network-outbound *:443");
        let na = parse_network(&line);
        assert_eq!(na.port, 443);
        assert!(matches!(na.kind, NetworkAccessKind::Connect));
    }

    #[test]
    fn test_parse_network_bind() {
        let line = make_line("Sandbox: node(12345) allow network-bind *:8080");
        let na = parse_network(&line);
        assert_eq!(na.port, 8080);
        assert!(matches!(na.kind, NetworkAccessKind::Bind));
    }

    #[test]
    fn test_parse_network_outbound_with_ip() {
        let line = make_line("Sandbox: curl(12345) allow network-outbound 93.184.216.34:443");
        let na = parse_network(&line);
        assert_eq!(na.addr, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(na.port, 443);
        assert!(matches!(na.kind, NetworkAccessKind::Connect));
    }

    #[test]
    fn test_parse_no_sandbox_marker() {
        let line = "Some random log line without sandbox info";
        assert!(parse_seatbelt_log_line(line).is_none());
    }

    #[test]
    fn test_parse_network_no_path_skipped() {
        // Network event with no address info — should be skipped
        let line = make_line("Sandbox: curl(12345) allow network-outbound");
        assert!(parse_seatbelt_log_line(&line).is_none());
    }

    #[test]
    fn test_parse_network_port_zero_skipped() {
        let line = make_line("Sandbox: curl(12345) allow network-outbound *:0");
        assert!(parse_seatbelt_log_line(&line).is_none());
    }

    #[test]
    fn test_parse_network_address_wildcard() {
        let na = parse_network_address("*:443", NetworkAccessKind::Connect).unwrap();
        assert_eq!(na.addr, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(na.port, 443);
    }

    #[test]
    fn test_parse_network_address_unix_socket() {
        assert!(parse_network_address(
            "/private/var/run/mDNSResponder",
            NetworkAccessKind::Connect
        )
        .is_none());
    }

    #[test]
    fn test_parse_network_address_invalid() {
        assert!(parse_network_address("notanaddress", NetworkAccessKind::Connect).is_none());
        assert!(parse_network_address("", NetworkAccessKind::Connect).is_none());
    }

    // --- IPv6 network tests (equivalent of test_parse_connect_ipv6 / test_parse_bind_ipv6) ---

    #[test]
    fn test_parse_network_outbound_ipv6_loopback() {
        // Seatbelt logs IPv6 addresses as addr:port using rfind(':') to split
        let line = make_line("Sandbox: curl(12345) allow network-outbound ::1:443");
        let na = parse_network(&line);
        assert_eq!(na.addr, "::1".parse::<IpAddr>().unwrap());
        assert_eq!(na.port, 443);
        assert!(matches!(na.kind, NetworkAccessKind::Connect));
    }

    #[test]
    fn test_parse_network_bind_ipv6_any() {
        // IPv6 bind on all interfaces
        let line = make_line("Sandbox: node(12345) allow network-bind :::8080");
        let na = parse_network(&line);
        assert_eq!(na.addr, "::".parse::<IpAddr>().unwrap());
        assert_eq!(na.port, 8080);
        assert!(matches!(na.kind, NetworkAccessKind::Bind));
    }

    #[test]
    fn test_parse_network_outbound_ipv6_with_addr() {
        // Specific IPv6 address
        let line = make_line("Sandbox: curl(12345) allow network-outbound 2001:db8::1:443");
        let na = parse_network(&line);
        assert_eq!(na.addr, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(na.port, 443);
        assert!(matches!(na.kind, NetworkAccessKind::Connect));
    }

    // --- Regression: multiple file operations in one pass ---
    // (equivalent of test_existing_file_parsing_unchanged in linux.rs)

    #[test]
    fn test_existing_file_parsing_unchanged() {
        let cases = [
            ("file-read-data", "/etc/hosts", false),
            ("file-read-metadata", "/usr/bin/ls", false),
            ("file-write-create", "/tmp/newdir", true),
            ("file-write-data", "/tmp/file.txt", true),
            ("file-write-unlink", "/tmp/old.txt", true),
            ("file-write-truncate", "/tmp/file.txt", true),
        ];

        for (op, path, expected_write) in &cases {
            let line = make_line(&format!("Sandbox: bash(12345) allow {} {}", op, path));
            let fa = parse_file(&line);
            assert_eq!(fa.path, PathBuf::from(path), "path mismatch for op={}", op);
            assert_eq!(
                fa.is_write, *expected_write,
                "is_write mismatch for op={}",
                op
            );
        }
    }

    // --- Unix-socket / AF_LOCAL skipped via full log line ---
    // (equivalent of test_parse_connect_af_local_ignored in linux.rs,
    //  complementing test_parse_network_address_unix_socket which only tests
    //  the address parser directly)

    #[test]
    fn test_parse_network_outbound_unix_socket_skipped() {
        // A Unix socket path that looks network-ish should still be skipped
        let line = make_line("Sandbox: curl(12345) allow network-outbound /var/run/varlink.socket");
        assert!(parse_seatbelt_log_line(&line).is_none());
    }

    #[test]
    fn test_parse_network_outbound_private_path_skipped() {
        // Any absolute path for network-outbound should be skipped (it's a socket file)
        let line = make_line("Sandbox: curl(12345) allow network-outbound /private/tmp/sock");
        assert!(parse_seatbelt_log_line(&line).is_none());
    }
}
