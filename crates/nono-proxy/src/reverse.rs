//! Reverse proxy handler (Mode 2 — Credential Injection).
//!
//! Routes requests by path prefix to upstream APIs, injecting credentials
//! from the keystore. The agent uses `http://localhost:PORT/openai/v1/chat`
//! and the proxy rewrites to `https://api.openai.com/v1/chat` with the
//! real API key injected as a header.
//!
//! Streaming responses (SSE, MCP Streamable HTTP, A2A JSON-RPC) are
//! forwarded without buffering.

use crate::audit;
use crate::credential::CredentialStore;
use crate::error::{ProxyError, Result};
use crate::filter::ProxyFilter;
use crate::token;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};
use zeroize::Zeroizing;

/// Maximum request body size (16 MiB). Prevents DoS from malicious Content-Length.
const MAX_REQUEST_BODY: usize = 16 * 1024 * 1024;

/// Timeout for upstream TCP connect.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Handle a non-CONNECT HTTP request (reverse proxy mode).
///
/// Reads the full HTTP request from the client, matches path prefix to
/// a configured route, injects credentials, and forwards to the upstream.
/// Shared context passed from the server to the reverse proxy handler.
pub struct ReverseProxyCtx<'a> {
    /// Credential store for service lookups
    pub credential_store: &'a CredentialStore,
    /// Session token for authentication
    pub session_token: &'a Zeroizing<String>,
    /// Host filter for upstream validation
    pub filter: &'a ProxyFilter,
    /// Shared TLS connector
    pub tls_connector: &'a TlsConnector,
}

/// Handle a non-CONNECT HTTP request (reverse proxy mode).
///
/// `buffered_body` contains any bytes the BufReader read ahead beyond the
/// headers. These are prepended to the body read from the stream to prevent
/// data loss.
pub async fn handle_reverse_proxy(
    first_line: &str,
    stream: &mut TcpStream,
    remaining_header: &[u8],
    ctx: &ReverseProxyCtx<'_>,
    buffered_body: &[u8],
) -> Result<()> {
    // Parse method, path, and HTTP version
    let (method, path, version) = parse_request_line(first_line)?;
    debug!("Reverse proxy: {} {}", method, path);

    // Validate session token from X-Nono-Token header
    validate_nono_token(remaining_header, ctx.session_token)?;

    // Extract service prefix from path (e.g., "/openai/v1/chat" -> ("openai", "/v1/chat"))
    let (service, upstream_path) = parse_service_prefix(&path)?;

    // Look up credential for service
    let cred = ctx
        .credential_store
        .get(&service)
        .ok_or_else(|| ProxyError::UnknownService {
            prefix: service.clone(),
        })?;

    // Parse upstream URL
    let upstream_url = format!("{}{}", cred.upstream.trim_end_matches('/'), upstream_path);
    debug!("Forwarding to upstream: {} {}", method, upstream_url);

    let (upstream_host, upstream_port, upstream_path_full) = parse_upstream_url(&upstream_url)?;

    // DNS resolve + CIDR check via the filter (prevents rebinding TOCTOU)
    let check = ctx.filter.check_host(&upstream_host, upstream_port).await?;
    if !check.result.is_allowed() {
        let reason = check.result.reason();
        warn!("Upstream host denied by filter: {}", reason);
        send_error(stream, 403, "Forbidden").await?;
        audit::log_denied(audit::ProxyMode::Reverse, &service, 0, &reason);
        return Ok(());
    }

    // Collect remaining request headers (excluding X-Nono-Token and Host)
    let filtered_headers = filter_headers(remaining_header);
    let content_length = extract_content_length(remaining_header);

    // Read request body if present, with size limit.
    // `buffered_body` may contain bytes the BufReader read ahead beyond
    // headers; we prepend those to avoid data loss.
    let body = if let Some(len) = content_length {
        if len > MAX_REQUEST_BODY {
            send_error(stream, 413, "Payload Too Large").await?;
            return Ok(());
        }
        let mut buf = Vec::with_capacity(len);
        let pre = buffered_body.len().min(len);
        buf.extend_from_slice(&buffered_body[..pre]);
        let remaining = len - pre;
        if remaining > 0 {
            let mut rest = vec![0u8; remaining];
            stream.read_exact(&mut rest).await?;
            buf.extend_from_slice(&rest);
        }
        buf
    } else {
        Vec::new()
    };

    // Connect to upstream over TLS using pre-resolved addresses
    let upstream_result = connect_upstream_tls(
        &upstream_host,
        upstream_port,
        &check.resolved_addrs,
        ctx.tls_connector,
    )
    .await;
    let mut tls_stream = match upstream_result {
        Ok(s) => s,
        Err(e) => {
            warn!("Upstream connection failed: {}", e);
            send_error(stream, 502, "Bad Gateway").await?;
            audit::log_denied(audit::ProxyMode::Reverse, &service, 0, &e.to_string());
            return Ok(());
        }
    };

    // Build the upstream request into a Zeroizing buffer since it contains
    // the credential header value. This ensures the credential is zeroed
    // from heap memory when the buffer is dropped.
    let mut request = Zeroizing::new(format!(
        "{} {} {}\r\nHost: {}\r\n",
        method, upstream_path_full, version, upstream_host
    ));

    // Inject credential header
    request.push_str(&format!(
        "{}: {}\r\n",
        cred.header_name,
        cred.header_value.as_str()
    ));

    // Forward filtered headers
    for (name, value) in &filtered_headers {
        request.push_str(&format!("{}: {}\r\n", name, value));
    }

    // Content-Length for body
    if !body.is_empty() {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");

    tls_stream.write_all(request.as_bytes()).await?;
    if !body.is_empty() {
        tls_stream.write_all(&body).await?;
    }
    tls_stream.flush().await?;

    // Stream the response back to the client without buffering.
    // This handles SSE (text/event-stream), chunked transfer, and regular responses.
    let mut response_buf = [0u8; 8192];
    let mut status_code: u16 = 502;
    let mut first_chunk = true;

    loop {
        let n = match tls_stream.read(&mut response_buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                debug!("Upstream read error: {}", e);
                break;
            }
        };

        // Parse status from first chunk. The HTTP status line format is:
        // "HTTP/1.1 200 OK\r\n..." — we need the 3-digit code after the
        // first space. We scan up to 32 bytes (enough for any valid status line).
        if first_chunk {
            status_code = parse_response_status(&response_buf[..n]);
            first_chunk = false;
        }

        stream.write_all(&response_buf[..n]).await?;
        stream.flush().await?;
    }

    audit::log_reverse_proxy(&service, &method, &upstream_path, status_code);
    Ok(())
}

/// Parse an HTTP request line into (method, path, version).
fn parse_request_line(line: &str) -> Result<(String, String, String)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(ProxyError::HttpParse(format!(
            "malformed request line: {}",
            line
        )));
    }
    Ok((
        parts[0].to_string(),
        parts[1].to_string(),
        parts[2].to_string(),
    ))
}

/// Extract service prefix from path.
///
/// "/openai/v1/chat/completions" -> ("openai", "/v1/chat/completions")
/// "/anthropic/v1/messages" -> ("anthropic", "/v1/messages")
fn parse_service_prefix(path: &str) -> Result<(String, String)> {
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    if let Some((prefix, rest)) = trimmed.split_once('/') {
        Ok((prefix.to_string(), format!("/{}", rest)))
    } else {
        // No sub-path, just the prefix
        Ok((trimmed.to_string(), "/".to_string()))
    }
}

/// Validate the X-Nono-Token header.
fn validate_nono_token(header_bytes: &[u8], session_token: &Zeroizing<String>) -> Result<()> {
    let header_str = std::str::from_utf8(header_bytes).map_err(|_| ProxyError::InvalidToken)?;

    for line in header_str.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("x-nono-token:") {
            let value = line.split_once(':').map(|(_, v)| v.trim()).unwrap_or("");
            if token::constant_time_eq(value.as_bytes(), session_token.as_bytes()) {
                return Ok(());
            }
            warn!("Invalid X-Nono-Token");
            return Err(ProxyError::InvalidToken);
        }
    }

    warn!("Missing X-Nono-Token header");
    Err(ProxyError::InvalidToken)
}

/// Filter headers, removing X-Nono-Token, Host, Content-Length, and x-api-key.
///
/// Content-Length is re-added after body is read, and Host is rewritten
/// to the upstream. Authorization and x-api-key headers are stripped since
/// we inject our own credential.
fn filter_headers(header_bytes: &[u8]) -> Vec<(String, String)> {
    let header_str = std::str::from_utf8(header_bytes).unwrap_or("");
    let mut headers = Vec::new();

    for line in header_str.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("x-nono-token:")
            || lower.starts_with("host:")
            || lower.starts_with("content-length:")
            || lower.starts_with("authorization:")
            || lower.starts_with("x-api-key:")
            || line.trim().is_empty()
        {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }

    headers
}

/// Extract Content-Length value from raw headers.
fn extract_content_length(header_bytes: &[u8]) -> Option<usize> {
    let header_str = std::str::from_utf8(header_bytes).ok()?;
    for line in header_str.lines() {
        if line.to_lowercase().starts_with("content-length:") {
            let value = line.split_once(':')?.1.trim();
            return value.parse().ok();
        }
    }
    None
}

/// Parse an upstream URL into (host, port, path).
fn parse_upstream_url(url_str: &str) -> Result<(String, u16, String)> {
    let parsed = url::Url::parse(url_str)
        .map_err(|e| ProxyError::HttpParse(format!("invalid upstream URL '{}': {}", url_str, e)))?;

    let scheme = parsed.scheme();
    if scheme != "https" && scheme != "http" {
        return Err(ProxyError::HttpParse(format!(
            "unsupported URL scheme: {}",
            url_str
        )));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| ProxyError::HttpParse(format!("missing host in URL: {}", url_str)))?
        .to_string();

    let default_port = if scheme == "https" { 443 } else { 80 };
    let port = parsed.port().unwrap_or(default_port);

    let path = parsed.path().to_string();
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        path
    };

    Ok((host, port, path))
}

/// Connect to an upstream host over TLS using pre-resolved addresses.
///
/// Uses the pre-resolved `SocketAddr`s from the filter check to prevent
/// DNS rebinding TOCTOU. Falls back to hostname resolution only if no
/// pre-resolved addresses are available.
///
/// The `TlsConnector` is shared across all connections (created once at
/// server startup with the system root certificate store).
async fn connect_upstream_tls(
    host: &str,
    port: u16,
    resolved_addrs: &[SocketAddr],
    connector: &TlsConnector,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = if resolved_addrs.is_empty() {
        // Fallback: no pre-resolved addresses (shouldn't happen in practice)
        let addr = format!("{}:{}", host, port);
        match tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                return Err(ProxyError::UpstreamConnect {
                    host: host.to_string(),
                    reason: e.to_string(),
                });
            }
            Err(_) => {
                return Err(ProxyError::UpstreamConnect {
                    host: host.to_string(),
                    reason: "connection timed out".to_string(),
                });
            }
        }
    } else {
        connect_to_resolved(resolved_addrs, host).await?
    };

    let server_name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|_| {
        ProxyError::UpstreamConnect {
            host: host.to_string(),
            reason: "invalid server name for TLS".to_string(),
        }
    })?;

    let tls_stream =
        connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| ProxyError::UpstreamConnect {
                host: host.to_string(),
                reason: format!("TLS handshake failed: {}", e),
            })?;

    Ok(tls_stream)
}

/// Connect to one of the pre-resolved socket addresses with timeout.
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

/// Parse HTTP status code from the first response chunk.
///
/// Looks for the "HTTP/x.y NNN" pattern in the first line. Returns 502
/// if the response doesn't contain a valid status line (upstream sent
/// garbage or incomplete data).
fn parse_response_status(data: &[u8]) -> u16 {
    // Find the end of the first line (or use full data if no newline)
    let line_end = data
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(data.len());
    let first_line = &data[..line_end.min(64)];

    if let Ok(line) = std::str::from_utf8(first_line) {
        // Split on whitespace: ["HTTP/1.1", "200", "OK"]
        let mut parts = line.split_whitespace();
        if let Some(version) = parts.next() {
            if version.starts_with("HTTP/") {
                if let Some(code_str) = parts.next() {
                    if code_str.len() == 3 {
                        return code_str.parse().unwrap_or(502);
                    }
                }
            }
        }
    }
    502
}

/// Send an HTTP error response.
async fn send_error(stream: &mut TcpStream, status: u16, reason: &str) -> Result<()> {
    let body = format!("{{\"error\":\"{}\"}}", reason);
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        status,
        reason,
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_request_line() {
        let (method, path, version) = parse_request_line("POST /openai/v1/chat HTTP/1.1").unwrap();
        assert_eq!(method, "POST");
        assert_eq!(path, "/openai/v1/chat");
        assert_eq!(version, "HTTP/1.1");
    }

    #[test]
    fn test_parse_request_line_malformed() {
        assert!(parse_request_line("GET").is_err());
    }

    #[test]
    fn test_parse_service_prefix() {
        let (service, path) = parse_service_prefix("/openai/v1/chat/completions").unwrap();
        assert_eq!(service, "openai");
        assert_eq!(path, "/v1/chat/completions");
    }

    #[test]
    fn test_parse_service_prefix_no_subpath() {
        let (service, path) = parse_service_prefix("/anthropic").unwrap();
        assert_eq!(service, "anthropic");
        assert_eq!(path, "/");
    }

    #[test]
    fn test_validate_nono_token_valid() {
        let token = Zeroizing::new("secret123".to_string());
        let header = b"X-Nono-Token: secret123\r\nContent-Type: application/json\r\n\r\n";
        assert!(validate_nono_token(header, &token).is_ok());
    }

    #[test]
    fn test_validate_nono_token_invalid() {
        let token = Zeroizing::new("secret123".to_string());
        let header = b"X-Nono-Token: wrong\r\n\r\n";
        assert!(validate_nono_token(header, &token).is_err());
    }

    #[test]
    fn test_validate_nono_token_missing() {
        let token = Zeroizing::new("secret123".to_string());
        let header = b"Content-Type: application/json\r\n\r\n";
        assert!(validate_nono_token(header, &token).is_err());
    }

    #[test]
    fn test_filter_headers_removes_token_host_auth() {
        let header = b"X-Nono-Token: secret\r\nHost: localhost:8080\r\nAuthorization: Bearer old\r\nContent-Type: application/json\r\nAccept: */*\r\n\r\n";
        let filtered = filter_headers(header);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].0, "Content-Type");
        assert_eq!(filtered[1].0, "Accept");
    }

    #[test]
    fn test_filter_headers_removes_x_api_key() {
        let header = b"x-api-key: sk-old\r\nContent-Type: application/json\r\n\r\n";
        let filtered = filter_headers(header);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].0, "Content-Type");
    }

    #[test]
    fn test_extract_content_length() {
        let header = b"Content-Type: application/json\r\nContent-Length: 42\r\n\r\n";
        assert_eq!(extract_content_length(header), Some(42));
    }

    #[test]
    fn test_extract_content_length_missing() {
        let header = b"Content-Type: application/json\r\n\r\n";
        assert_eq!(extract_content_length(header), None);
    }

    #[test]
    fn test_parse_upstream_url_https() {
        let (host, port, path) =
            parse_upstream_url("https://api.openai.com/v1/chat/completions").unwrap();
        assert_eq!(host, "api.openai.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/v1/chat/completions");
    }

    #[test]
    fn test_parse_upstream_url_http_with_port() {
        let (host, port, path) = parse_upstream_url("http://localhost:8080/api").unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 8080);
        assert_eq!(path, "/api");
    }

    #[test]
    fn test_parse_upstream_url_no_path() {
        let (host, port, path) = parse_upstream_url("https://api.anthropic.com").unwrap();
        assert_eq!(host, "api.anthropic.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/");
    }

    #[test]
    fn test_parse_upstream_url_invalid_scheme() {
        assert!(parse_upstream_url("ftp://example.com").is_err());
    }

    #[test]
    fn test_parse_response_status_200() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
        assert_eq!(parse_response_status(data), 200);
    }

    #[test]
    fn test_parse_response_status_404() {
        let data = b"HTTP/1.1 404 Not Found\r\n\r\n";
        assert_eq!(parse_response_status(data), 404);
    }

    #[test]
    fn test_parse_response_status_garbage() {
        let data = b"not an http response";
        assert_eq!(parse_response_status(data), 502);
    }

    #[test]
    fn test_parse_response_status_empty() {
        assert_eq!(parse_response_status(b""), 502);
    }

    #[test]
    fn test_parse_response_status_partial() {
        let data = b"HTTP/1.1 ";
        assert_eq!(parse_response_status(data), 502);
    }
}
