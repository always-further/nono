//! HTTP CONNECT tunnel handler (Mode 1 — Host Filtering).
//!
//! Handles `CONNECT host:port HTTP/1.1` requests by:
//! 1. Validating the session token
//! 2. Checking the host against the filter (cloud metadata deny list, then allowlist)
//! 3. Establishing a TCP connection to the upstream
//! 4. Returning `200 Connection Established`
//! 5. Relaying bytes bidirectionally (transparent TLS tunnel)
//!
//! The proxy never terminates TLS — it just passes encrypted bytes through.
//! Streaming (SSE, MCP Streamable HTTP, A2A) works transparently.

use crate::audit;
use crate::error::{ProxyError, Result};
use crate::filter::{ProxyFilter, RuntimeProxyFilter};
use crate::token;
use nono::{ApprovalScope, NetworkApprovalDecision, NetworkApprovalRequest};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tracing::debug;
use zeroize::Zeroizing;

/// Timeout for upstream TCP connect.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// A request sent from the proxy to the approval backend.
pub struct ApprovalChannelRequest {
    /// The network approval request data.
    pub request: NetworkApprovalRequest,
    /// One-shot channel to send the decision back.
    pub response_tx: oneshot::Sender<NetworkApprovalDecision>,
}

/// Context for approval-enabled CONNECT handling.
pub struct ApprovalContext<'a> {
    /// Original (immutable) proxy filter — checked first for allowlisted hosts,
    /// route-matched hosts, credential hosts, etc.
    pub primary_filter: &'a ProxyFilter,
    /// Runtime-mutable proxy filter — updated when the user approves a host
    pub runtime_filter: &'a RuntimeProxyFilter,
    /// Session token for proxy auth
    pub session_token: &'a Zeroizing<String>,
    /// Shared audit log
    pub audit_log: Option<&'a audit::SharedAuditLog>,
    /// Channel to send approval requests to the backend
    pub approval_tx: &'a tokio::sync::mpsc::Sender<ApprovalChannelRequest>,
    /// PID of the sandboxed child process
    pub child_pid: u32,
    /// Session ID for correlating approval requests
    pub session_id: &'a str,
    /// Timeout for waiting on a network approval response
    pub approval_timeout: Duration,
}

/// Handle an HTTP CONNECT request with approval fallback.
///
/// Checks the primary (immutable) filter first. If the host is allowed,
/// proceeds normally. If denied AND an approval channel is available,
/// sends an approval request and awaits the user's decision. If approved,
/// the host is added to the runtime filter and the request proceeds.
pub async fn handle_connect_with_approval(
    first_line: &str,
    stream: &mut TcpStream,
    remaining_header: &[u8],
    ctx: &ApprovalContext<'_>,
) -> Result<()> {
    let (host, port) = parse_connect_target(first_line)?;
    debug!("CONNECT request to {}:{}", host, port);

    if let Err(e) = validate_proxy_auth(remaining_header, ctx.session_token) {
        debug!("CONNECT auth skipped: {}", e);
    }

    let primary_check = ctx.primary_filter.check_host(&host, port).await?;
    debug!(
        "CONNECT {}:{} primary_filter result: {:?}",
        host, port, primary_check.result
    );
    if primary_check.result.is_allowed() {
        let resolved = &primary_check.resolved_addrs;
        if resolved.is_empty() {
            let reason = "DNS resolution returned no addresses".to_string();
            audit::log_denied(
                ctx.audit_log,
                audit::ProxyMode::Connect,
                &host,
                port,
                &reason,
            );
            send_response(stream, 502, "DNS resolution failed").await?;
            return Err(ProxyError::UpstreamConnect { host, reason });
        }

        let mut upstream = connect_to_resolved(resolved, &host).await?;
        send_response(stream, 200, "Connection Established").await?;
        audit::log_allowed(
            ctx.audit_log,
            audit::ProxyMode::Connect,
            &host,
            port,
            "CONNECT",
        );
        let result = tokio::io::copy_bidirectional(stream, &mut upstream).await;
        debug!("CONNECT tunnel closed for {}:{}: {:?}", host, port, result);
        return Ok(());
    }

    if matches!(
        primary_check.result,
        nono::net_filter::FilterResult::DenyHost { .. }
    ) {
        let reason = primary_check.result.reason();
        debug!(
            "CONNECT {}:{} explicitly denied by primary filter: {}",
            host, port, reason
        );
        audit::log_denied(
            ctx.audit_log,
            audit::ProxyMode::Connect,
            &host,
            port,
            &reason,
        );
        send_response(stream, 403, &format!("Host denied: {reason}")).await?;
        return Ok(());
    }

    let runtime_check = ctx.runtime_filter.check_host(&host, port).await?;
    debug!(
        "CONNECT {}:{} runtime_filter result: {:?}",
        host, port, runtime_check.result
    );
    if runtime_check.result.is_allowed() {
        let resolved = &runtime_check.resolved_addrs;
        if resolved.is_empty() {
            let reason = "DNS resolution returned no addresses".to_string();
            audit::log_denied(
                ctx.audit_log,
                audit::ProxyMode::Connect,
                &host,
                port,
                &reason,
            );
            send_response(stream, 502, "DNS resolution failed").await?;
            return Err(ProxyError::UpstreamConnect { host, reason });
        }

        let mut upstream = connect_to_resolved(resolved, &host).await?;
        send_response(stream, 200, "Connection Established").await?;
        audit::log_allowed(
            ctx.audit_log,
            audit::ProxyMode::Connect,
            &host,
            port,
            "CONNECT (runtime)",
        );
        let result = tokio::io::copy_bidirectional(stream, &mut upstream).await;
        debug!("CONNECT tunnel closed for {}:{}: {:?}", host, port, result);
        return Ok(());
    }

    if matches!(
        runtime_check.result,
        nono::net_filter::FilterResult::DenyHost { .. }
    ) {
        let reason = runtime_check.result.reason();
        debug!(
            "CONNECT {}:{} explicitly denied by runtime filter: {}",
            host, port, reason
        );
        audit::log_denied(
            ctx.audit_log,
            audit::ProxyMode::Connect,
            &host,
            port,
            &reason,
        );
        send_response(stream, 403, &format!("Host denied: {reason}")).await?;
        return Ok(());
    }

    let request_id = generate_request_id();
    let request = NetworkApprovalRequest {
        request_id,
        host: host.clone(),
        port: Some(port),
        reason: Some("Blocked by host filter".to_string()),
        child_pid: ctx.child_pid,
        session_id: ctx.session_id.to_string(),
    };

    let (response_tx, response_rx) = oneshot::channel();
    let approval_req = ApprovalChannelRequest {
        request,
        response_tx,
    };

    if ctx.approval_tx.send(approval_req).await.is_err() {
        let reason = "Approval channel closed";
        audit::log_denied(
            ctx.audit_log,
            audit::ProxyMode::Connect,
            &host,
            port,
            reason,
        );
        send_response(stream, 403, &format!("Forbidden: {}", reason)).await?;
        return Err(ProxyError::HostDenied {
            host,
            reason: reason.to_string(),
        });
    }

    let decision = match tokio::time::timeout(ctx.approval_timeout, response_rx).await {
        Ok(Ok(d)) => d,
        Ok(Err(_)) => {
            let reason = "Approval response channel dropped";
            audit::log_denied(
                ctx.audit_log,
                audit::ProxyMode::Connect,
                &host,
                port,
                reason,
            );
            send_response(stream, 403, &format!("Forbidden: {}", reason)).await?;
            return Err(ProxyError::HostDenied {
                host,
                reason: reason.to_string(),
            });
        }
        Err(_) => NetworkApprovalDecision::Timeout,
    };

    match decision {
        NetworkApprovalDecision::Granted(scope) => {
            debug!(
                "Host {} approved ({})",
                host,
                match scope {
                    ApprovalScope::Once => "once",
                    ApprovalScope::Session => "session",
                    ApprovalScope::Persistent => "persistent",
                }
            );

            let resolved = if scope == ApprovalScope::Once {
                let addrs = ctx.runtime_filter.resolve_host(&host, port).await?;
                if addrs.is_empty() {
                    let reason = "Could not resolve host after approval";
                    audit::log_denied(
                        ctx.audit_log,
                        audit::ProxyMode::Connect,
                        &host,
                        port,
                        reason,
                    );
                    send_response(stream, 403, &format!("Forbidden: {}", reason)).await?;
                    return Err(ProxyError::HostDenied {
                        host,
                        reason: reason.to_string(),
                    });
                }
                addrs
            } else {
                let runtime_check = ctx.runtime_filter.check_host(&host, port).await?;
                let resolved = &runtime_check.resolved_addrs;
                if !runtime_check.result.is_allowed() || resolved.is_empty() {
                    let reason = "Host still denied after approval";
                    audit::log_denied(
                        ctx.audit_log,
                        audit::ProxyMode::Connect,
                        &host,
                        port,
                        reason,
                    );
                    send_response(stream, 403, &format!("Forbidden: {}", reason)).await?;
                    return Err(ProxyError::HostDenied {
                        host,
                        reason: reason.to_string(),
                    });
                }
                runtime_check.resolved_addrs
            };

            let mut upstream = connect_to_resolved(&resolved, &host).await?;
            send_response(stream, 200, "Connection Established").await?;
            audit::log_allowed(
                ctx.audit_log,
                audit::ProxyMode::Connect,
                &host,
                port,
                "CONNECT (approved)",
            );
            let result = tokio::io::copy_bidirectional(stream, &mut upstream).await;
            debug!("CONNECT tunnel closed for {}:{}: {:?}", host, port, result);
            Ok(())
        }
        NetworkApprovalDecision::Denied { reason: _ } | NetworkApprovalDecision::Timeout => {
            let display_reason = match &decision {
                NetworkApprovalDecision::Timeout => "Approval timed out",
                NetworkApprovalDecision::Denied { reason } => reason,
                _ => "unreachable",
            };
            audit::log_denied(
                ctx.audit_log,
                audit::ProxyMode::Connect,
                &host,
                port,
                display_reason,
            );
            send_response(stream, 403, &format!("Forbidden: {}", display_reason)).await?;
            Err(ProxyError::HostDenied {
                host,
                reason: display_reason.to_string(),
            })
        }
    }
}

fn generate_request_id() -> String {
    use std::fmt::Write;
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).unwrap_or_else(|_| {
        buf = [0; 16];
    });
    buf.iter().fold(String::with_capacity(32), |mut s, b| {
        write!(s, "{b:02x}").unwrap_or_default();
        s
    })
}

/// Handle an HTTP CONNECT request.
///
/// `first_line` is the already-read CONNECT line (e.g., "CONNECT api.openai.com:443 HTTP/1.1").
/// `stream` is the raw TCP stream from the client.
pub async fn handle_connect(
    first_line: &str,
    stream: &mut TcpStream,
    filter: &ProxyFilter,
    session_token: &Zeroizing<String>,
    remaining_header: &[u8],
    audit_log: Option<&audit::SharedAuditLog>,
) -> Result<()> {
    // Parse host:port from CONNECT line
    let (host, port) = parse_connect_target(first_line)?;
    debug!("CONNECT request to {}:{}", host, port);

    // Validate session token from Proxy-Authorization header.
    // Non-fatal for CONNECT: Node.js undici doesn't send Proxy-Authorization
    // from URL userinfo for CONNECT requests.
    if let Err(e) = validate_proxy_auth(remaining_header, session_token) {
        debug!("CONNECT auth skipped: {}", e);
    }

    // Check host against filter (DNS resolution happens here)
    let check = filter.check_host(&host, port).await?;
    if !check.result.is_allowed() {
        let reason = check.result.reason();
        audit::log_denied(audit_log, audit::ProxyMode::Connect, &host, port, &reason);
        send_response(stream, 403, &format!("Forbidden: {}", reason)).await?;
        return Err(ProxyError::HostDenied { host, reason });
    }

    // Connect to the resolved IP directly — NOT re-resolving the hostname.
    // This eliminates the DNS rebinding TOCTOU: the IPs were already checked
    // against the link-local range in check_host() above.
    let resolved = &check.resolved_addrs;
    if resolved.is_empty() {
        let reason = "DNS resolution returned no addresses".to_string();
        audit::log_denied(audit_log, audit::ProxyMode::Connect, &host, port, &reason);
        send_response(stream, 502, "DNS resolution failed").await?;
        return Err(ProxyError::UpstreamConnect {
            host: host.clone(),
            reason,
        });
    }

    let mut upstream = connect_to_resolved(resolved, &host).await?;

    // Send 200 Connection Established
    send_response(stream, 200, "Connection Established").await?;
    audit::log_allowed(audit_log, audit::ProxyMode::Connect, &host, port, "CONNECT");

    // Bidirectional relay
    let result = tokio::io::copy_bidirectional(stream, &mut upstream).await;
    debug!("CONNECT tunnel closed for {}:{}: {:?}", host, port, result);

    Ok(())
}

/// Connect to one of the pre-resolved socket addresses with timeout.
///
/// Tries each address in order until one succeeds. This connects to the
/// IP directly (not re-resolving the hostname), preventing DNS rebinding.
async fn connect_to_resolved(addrs: &[SocketAddr], host: &str) -> Result<TcpStream> {
    let mut last_err = None;
    for addr in addrs {
        match tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => {
                debug!("Connect to {} failed: {}", addr, e);
                last_err = Some(e.to_string());
            }
            Err(_) => {
                debug!("Connect to {} timed out", addr);
                last_err = Some("connection timed out".to_string());
            }
        }
    }
    Err(ProxyError::UpstreamConnect {
        host: host.to_string(),
        reason: last_err.unwrap_or_else(|| "no addresses to connect to".to_string()),
    })
}

/// Parse the target host and port from a CONNECT request line.
///
/// Expected format: "CONNECT host:port HTTP/1.1"
fn parse_connect_target(line: &str) -> Result<(String, u16)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 || parts[0] != "CONNECT" {
        return Err(ProxyError::HttpParse(format!(
            "malformed CONNECT line: {}",
            line
        )));
    }

    let authority = parts[1];
    if let Some((host, port_str)) = authority.rsplit_once(':') {
        let port = port_str.parse::<u16>().map_err(|_| {
            ProxyError::HttpParse(format!("invalid port in CONNECT: {}", authority))
        })?;
        Ok((host.to_string(), port))
    } else {
        // No port specified, default to 443 for CONNECT
        Ok((authority.to_string(), 443))
    }
}

/// Validate the Proxy-Authorization header against the session token.
///
/// Delegates to `token::validate_proxy_auth` which accepts both Bearer
/// and Basic auth formats.
fn validate_proxy_auth(header_bytes: &[u8], session_token: &Zeroizing<String>) -> Result<()> {
    token::validate_proxy_auth(header_bytes, session_token)
}

/// Send an HTTP response line to the client.
async fn send_response(stream: &mut TcpStream, status: u16, reason: &str) -> Result<()> {
    let response = format!("HTTP/1.1 {} {}\r\n\r\n", status, reason);
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_connect_with_port() {
        let (host, port) = parse_connect_target("CONNECT api.openai.com:443 HTTP/1.1").unwrap();
        assert_eq!(host, "api.openai.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_connect_without_port() {
        let (host, port) = parse_connect_target("CONNECT example.com HTTP/1.1").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_connect_custom_port() {
        let (host, port) = parse_connect_target("CONNECT internal:8443 HTTP/1.1").unwrap();
        assert_eq!(host, "internal");
        assert_eq!(port, 8443);
    }

    #[test]
    fn test_parse_connect_malformed() {
        assert!(parse_connect_target("GET /").is_err());
        assert!(parse_connect_target("").is_err());
    }

    #[test]
    fn test_validate_proxy_auth_valid() {
        let token = Zeroizing::new("abc123".to_string());
        let header = b"Proxy-Authorization: Bearer abc123\r\n\r\n";
        assert!(validate_proxy_auth(header, &token).is_ok());
    }

    #[test]
    fn test_validate_proxy_auth_invalid() {
        let token = Zeroizing::new("abc123".to_string());
        let header = b"Proxy-Authorization: Bearer wrong\r\n\r\n";
        assert!(validate_proxy_auth(header, &token).is_err());
    }

    #[test]
    fn test_validate_proxy_auth_missing() {
        let token = Zeroizing::new("abc123".to_string());
        let header = b"Host: example.com\r\n\r\n";
        assert!(validate_proxy_auth(header, &token).is_err());
    }
}
