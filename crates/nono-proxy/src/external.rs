//! External proxy passthrough handler (Mode 3 — Enterprise).
//!
//! Chains CONNECT requests to an upstream enterprise proxy (Squid, Cisco WSA,
//! Zscaler, etc.). Nono's `default_deny` (cloud metadata, RFC1918) applies as
//! a security floor before forwarding. The enterprise proxy makes the final
//! allow/deny decision.

use crate::audit;
use crate::config::ExternalProxyConfig;
use crate::error::{ProxyError, Result};
use crate::filter::ProxyFilter;
use crate::token;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::debug;
use zeroize::Zeroizing;

/// Handle a CONNECT request by chaining it to an external proxy.
///
/// 1. Validate session token
/// 2. Check host against default_deny (SSRF floor)
/// 3. Connect to enterprise proxy
/// 4. Send CONNECT to enterprise proxy (with optional Proxy-Authorization)
/// 5. Wait for enterprise proxy 200
/// 6. Bidirectional tunnel: agent <-> enterprise proxy <-> upstream
pub async fn handle_external_proxy(
    first_line: &str,
    stream: &mut TcpStream,
    remaining_header: &[u8],
    filter: &ProxyFilter,
    session_token: &Zeroizing<String>,
    external_config: &ExternalProxyConfig,
) -> Result<()> {
    // Parse CONNECT target
    let (host, port) = parse_connect_target(first_line)?;
    debug!("External proxy CONNECT to {}:{}", host, port);

    // Validate session token
    validate_proxy_auth(remaining_header, session_token)?;

    // Check default_deny (SSRF protection floor).
    // For external proxy mode, we connect to the enterprise proxy (not the resolved
    // IP directly), so the DNS rebinding TOCTOU doesn't apply — the enterprise proxy
    // does its own resolution. But we still check deny CIDRs on the resolved IPs here
    // to prevent requesting known-bad targets even through the enterprise proxy.
    let check = filter.check_host(&host, port).await?;
    if !check.result.is_allowed() {
        let reason = check.result.reason();
        audit::log_denied(audit::ProxyMode::External, &host, port, &reason);
        send_response(stream, 403, &format!("Forbidden: {}", reason)).await?;
        return Err(ProxyError::HostDenied { host, reason });
    }

    // Connect to enterprise proxy
    let mut proxy_stream = TcpStream::connect(&external_config.address)
        .await
        .map_err(|e| {
            ProxyError::ExternalProxy(format!(
                "cannot connect to external proxy {}: {}",
                external_config.address, e
            ))
        })?;

    // Build CONNECT request for enterprise proxy
    let mut connect_req = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n",
        host, port, host, port
    );

    // External proxy authentication is not yet implemented. If auth is
    // configured, fail loudly rather than silently sending unauthenticated
    // requests that the enterprise proxy will reject.
    if external_config.auth.is_some() {
        return Err(ProxyError::ExternalProxy(
            "external proxy authentication is configured but not yet implemented; \
             remove the auth section from the external proxy config or wait for \
             a future release"
                .to_string(),
        ));
    }

    connect_req.push_str("\r\n");
    proxy_stream
        .write_all(connect_req.as_bytes())
        .await
        .map_err(|e| {
            ProxyError::ExternalProxy(format!("failed to send CONNECT to external proxy: {}", e))
        })?;

    // Read enterprise proxy response
    let mut buf_reader = BufReader::new(&mut proxy_stream);
    let mut response_line = String::new();
    buf_reader
        .read_line(&mut response_line)
        .await
        .map_err(|e| {
            ProxyError::ExternalProxy(format!(
                "failed to read response from external proxy: {}",
                e
            ))
        })?;

    // Parse status code from response
    let status = parse_status_code(&response_line)?;
    if status != 200 {
        audit::log_denied(
            audit::ProxyMode::External,
            &host,
            port,
            &format!("external proxy rejected with status {}", status),
        );
        send_response(
            stream,
            status,
            &format!("Blocked by upstream proxy (status {})", status),
        )
        .await?;
        return Err(ProxyError::ExternalProxy(format!(
            "enterprise proxy rejected CONNECT to {}:{} with status {}",
            host, port, status
        )));
    }

    // Drain remaining response headers from enterprise proxy
    loop {
        let mut line = String::new();
        buf_reader.read_line(&mut line).await.map_err(|e| {
            ProxyError::ExternalProxy(format!("failed to drain proxy response headers: {}", e))
        })?;
        if line.trim().is_empty() {
            break;
        }
    }

    // Get the inner stream back from BufReader
    let proxy_stream = buf_reader.into_inner();

    // Send 200 to agent
    send_response(stream, 200, "Connection Established").await?;
    audit::log_allowed(audit::ProxyMode::External, &host, port, "CONNECT");

    // Bidirectional tunnel: agent <-> enterprise proxy <-> upstream
    let result = tokio::io::copy_bidirectional(stream, proxy_stream).await;
    debug!(
        "External proxy tunnel closed for {}:{}: {:?}",
        host, port, result
    );

    Ok(())
}

/// Parse CONNECT target (reused from connect.rs pattern).
fn parse_connect_target(line: &str) -> Result<(String, u16)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
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
        Ok((authority.to_string(), 443))
    }
}

/// Validate Proxy-Authorization header.
///
/// Delegates to `token::validate_proxy_auth` which accepts both Bearer
/// and Basic auth formats.
fn validate_proxy_auth(header_bytes: &[u8], session_token: &Zeroizing<String>) -> Result<()> {
    token::validate_proxy_auth(header_bytes, session_token)
}

/// Parse HTTP status code from a response line.
fn parse_status_code(line: &str) -> Result<u16> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(ProxyError::HttpParse(format!(
            "malformed HTTP response: {}",
            line
        )));
    }
    parts[1]
        .parse::<u16>()
        .map_err(|_| ProxyError::HttpParse(format!("invalid status code in response: {}", line)))
}

/// Send an HTTP response line.
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
    fn test_parse_connect_target() {
        let (host, port) = parse_connect_target("CONNECT api.openai.com:443 HTTP/1.1").unwrap();
        assert_eq!(host, "api.openai.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_status_code_200() {
        assert_eq!(
            parse_status_code("HTTP/1.1 200 Connection Established\r\n").unwrap(),
            200
        );
    }

    #[test]
    fn test_parse_status_code_403() {
        assert_eq!(
            parse_status_code("HTTP/1.1 403 Forbidden\r\n").unwrap(),
            403
        );
    }

    #[test]
    fn test_parse_status_code_malformed() {
        assert!(parse_status_code("garbage").is_err());
    }
}
