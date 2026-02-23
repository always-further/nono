//! Audit logging for proxy requests.
//!
//! Logs all proxy requests with structured fields via `tracing`.
//! Sensitive data (authorization headers, tokens, request bodies)
//! is never included in audit logs.

use tracing::info;

/// Proxy mode for audit logging.
#[derive(Debug, Clone, Copy)]
pub enum ProxyMode {
    /// CONNECT tunnel (host filtering only)
    Connect,
    /// Reverse proxy (credential injection)
    Reverse,
    /// External proxy passthrough (enterprise)
    External,
}

impl std::fmt::Display for ProxyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyMode::Connect => write!(f, "connect"),
            ProxyMode::Reverse => write!(f, "reverse"),
            ProxyMode::External => write!(f, "external"),
        }
    }
}

/// Log an allowed proxy request.
pub fn log_allowed(mode: ProxyMode, host: &str, port: u16, method: &str) {
    info!(
        target: "nono_proxy::audit",
        mode = %mode,
        host = host,
        port = port,
        method = method,
        decision = "allow",
        "proxy request allowed"
    );
}

/// Log a denied proxy request.
pub fn log_denied(mode: ProxyMode, host: &str, port: u16, reason: &str) {
    info!(
        target: "nono_proxy::audit",
        mode = %mode,
        host = host,
        port = port,
        decision = "deny",
        reason = reason,
        "proxy request denied"
    );
}

/// Log a reverse proxy request with service info.
pub fn log_reverse_proxy(service: &str, method: &str, path: &str, status: u16) {
    info!(
        target: "nono_proxy::audit",
        mode = "reverse",
        service = service,
        method = method,
        path = path,
        status = status,
        "reverse proxy response"
    );
}
