//! Shared localhost/loopback host utilities for relay policy.

/// Returns true when `host` is a loopback hostname/address used by relay policy.
///
/// This intentionally includes canonical loopback names only:
/// `localhost`, `127.0.0.1`, and `::1` (with or without IPv6 brackets).
pub(crate) fn is_loopback_host(host: &str) -> bool {
    let normalized = host.trim_matches(['[', ']']).to_ascii_lowercase();
    normalized == "localhost" || normalized == "127.0.0.1" || normalized == "::1"
}

#[cfg(test)]
mod tests {
    use super::is_loopback_host;

    #[test]
    fn test_is_loopback_host() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("::1"));
        assert!(is_loopback_host("[::1]"));
        assert!(!is_loopback_host("0.0.0.0"));
        assert!(!is_loopback_host("::"));
        assert!(!is_loopback_host("example.com"));
    }
}
