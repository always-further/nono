//! Shared localhost/loopback host utilities for relay policy.

use std::net::IpAddr;

/// Returns true when `host` is a loopback hostname/address used by relay policy.
///
/// Accepts:
/// - `localhost` (case-insensitive, optional trailing dot)
/// - Any loopback IP literal (IPv4 127.0.0.0/8 or IPv6 ::1), with optional brackets.
pub(crate) fn is_loopback_host(host: &str) -> bool {
    let normalized = host
        .trim()
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if normalized == "localhost" {
        return true;
    }
    match normalized.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::is_loopback_host;

    #[test]
    fn test_is_loopback_host() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("LOCALHOST"));
        assert!(is_loopback_host("localhost."));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("127.0.0.42"));
        assert!(is_loopback_host("::1"));
        assert!(is_loopback_host("[::1]"));
        assert!(!is_loopback_host("0.0.0.0"));
        assert!(!is_loopback_host("::"));
        assert!(!is_loopback_host("example.com"));
    }
}
