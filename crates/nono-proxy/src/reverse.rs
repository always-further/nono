//! Reverse proxy handler (Mode 2 — Credential Injection).
//!
//! Routes requests by path prefix to upstream APIs, injecting credentials
//! from the keystore. The agent uses `http://localhost:PORT/openai/v1/chat`
//! and the proxy rewrites to `https://api.openai.com/v1/chat` with the
//! real credential injected.
//!
//! Supports multiple injection modes:
//! - `header`: Inject into HTTP header (e.g., `Authorization: Bearer ...`)
//! - `url_path`: Replace pattern in URL path (e.g., Telegram `/bot{}/`)
//! - `query_param`: Add/replace query parameter (e.g., `?api_key=...`)
//! - `basic_auth`: HTTP Basic Authentication
//!
//! Streaming responses (SSE, MCP Streamable HTTP, A2A JSON-RPC) are
//! forwarded without buffering.

use crate::audit;
use crate::config::InjectMode;
use crate::credential::{CredentialStore, LoadedCredential};
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
    /// Shared network audit sink for session metadata capture
    pub audit_log: Option<&'a audit::SharedAuditLog>,
}

/// Handle a non-CONNECT HTTP request (reverse proxy mode).
///
/// `buffered_body` contains any bytes the BufReader read ahead beyond the
/// headers. These are prepended to the body read from the stream to prevent
/// data loss.
///
/// ## Phantom Token Pattern
///
/// The client (SDK) sends the session token as its "API key". The proxy:
/// 1. Extracts the service from the path (e.g., `/openai/v1/chat` → `openai`)
/// 2. Looks up which header that service uses (e.g., `Authorization` or `x-api-key`)
/// 3. Validates the phantom token from that header
/// 4. Replaces it with the real credential from keyring
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

    // Extract service prefix from path (e.g., "/openai/v1/chat" -> ("openai", "/v1/chat"))
    let (service, upstream_path) = parse_service_prefix(&path)?;

    // Look up credential for service
    let cred = ctx
        .credential_store
        .get(&service)
        .ok_or_else(|| ProxyError::UnknownService {
            prefix: service.clone(),
        })?;

    // L7 endpoint filtering: check method+path against rules before any
    // credential operations. Denied endpoints get 403 immediately.
    if !cred.endpoint_rules.is_allowed(&method, &upstream_path) {
        let reason = format!(
            "endpoint denied: {} {} on service '{}'",
            method, upstream_path, service
        );
        warn!("{}", reason);
        audit::log_denied(
            ctx.audit_log,
            audit::ProxyMode::Reverse,
            &service,
            0,
            &reason,
        );
        send_error(stream, 403, "Forbidden").await?;
        return Ok(());
    }

    // Validate phantom token based on injection mode.
    // For header/basic_auth modes: validate from Authorization/x-api-key header
    // For url_path mode: validate from URL path pattern
    // For query_param mode: validate from query parameter
    if let Err(e) = validate_phantom_token_for_mode(
        &cred.inject_mode,
        remaining_header,
        &upstream_path,
        &cred.header_name,
        cred.path_pattern.as_deref(),
        cred.query_param_name.as_deref(),
        ctx.session_token,
    ) {
        audit::log_denied(
            ctx.audit_log,
            audit::ProxyMode::Reverse,
            &service,
            0,
            &e.to_string(),
        );
        send_error(stream, 401, "Unauthorized").await?;
        return Ok(());
    }

    // Transform the path based on injection mode (url_path and query_param modes)
    let transformed_path = transform_path_for_mode(
        &cred.inject_mode,
        &upstream_path,
        cred.path_pattern.as_deref(),
        cred.path_replacement.as_deref(),
        cred.query_param_name.as_deref(),
        &cred.raw_credential,
    )?;

    // Parse upstream URL with potentially transformed path
    let upstream_url = format!(
        "{}{}",
        cred.upstream.trim_end_matches('/'),
        transformed_path
    );
    debug!("Forwarding to upstream: {} {}", method, upstream_url);

    let (upstream_host, upstream_port, upstream_path_full) = parse_upstream_url(&upstream_url)?;

    // DNS resolve + host check via the filter
    let check = ctx.filter.check_host(&upstream_host, upstream_port).await?;
    if !check.result.is_allowed() {
        let reason = check.result.reason();
        warn!("Upstream host denied by filter: {}", reason);
        send_error(stream, 403, "Forbidden").await?;
        audit::log_denied(
            ctx.audit_log,
            audit::ProxyMode::Reverse,
            &service,
            0,
            &reason,
        );
        return Ok(());
    }

    // Collect remaining request headers (excluding X-Nono-Token and Host)
    let filtered_headers = filter_headers(remaining_header, &cred.header_name);
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

    // Connect to upstream over TLS using pre-resolved addresses.
    // Use the per-route TLS connector (with custom CA) if configured,
    // otherwise fall back to the shared default connector.
    let connector = cred.tls_connector.as_ref().unwrap_or(ctx.tls_connector);
    let upstream_result = connect_upstream_tls(
        &upstream_host,
        upstream_port,
        &check.resolved_addrs,
        connector,
    )
    .await;
    let mut tls_stream = match upstream_result {
        Ok(s) => s,
        Err(e) => {
            warn!("Upstream connection failed: {}", e);
            send_error(stream, 502, "Bad Gateway").await?;
            audit::log_denied(
                ctx.audit_log,
                audit::ProxyMode::Reverse,
                &service,
                0,
                &e.to_string(),
            );
            return Ok(());
        }
    };

    // Build the upstream request into a Zeroizing buffer since it may contain
    // credential values. This ensures credentials are zeroed from heap memory
    // when the buffer is dropped.
    let mut request = Zeroizing::new(format!(
        "{} {} {}\r\nHost: {}\r\n",
        method, upstream_path_full, version, upstream_host
    ));

    // Inject credential based on mode
    inject_credential_for_mode(cred, &mut request);

    // Forward filtered headers (excluding auth headers that we're replacing)
    let auth_header_lower = cred.header_name.to_lowercase();
    for (name, value) in &filtered_headers {
        // Skip the auth header if we're using header/basic_auth mode
        // (we already injected our own)
        if matches!(cred.inject_mode, InjectMode::Header | InjectMode::BasicAuth)
            && name.to_lowercase() == auth_header_lower
        {
            continue;
        }
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

    audit::log_reverse_proxy(
        ctx.audit_log,
        &service,
        &method,
        &upstream_path,
        status_code,
    );
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

/// Validate the phantom token from the service's auth header.
///
/// The SDK sends the session token as its "API key" in the standard auth header
/// for that service (e.g., `Authorization: Bearer <token>` for OpenAI,
/// `x-api-key: <token>` for Anthropic). We validate the token matches the
/// session token before swapping in the real credential.
fn validate_phantom_token(
    header_bytes: &[u8],
    header_name: &str,
    session_token: &Zeroizing<String>,
) -> Result<()> {
    let header_str = std::str::from_utf8(header_bytes).map_err(|_| ProxyError::InvalidToken)?;
    let header_name_lower = header_name.to_lowercase();

    for line in header_str.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with(&format!("{}:", header_name_lower)) {
            let value = line.split_once(':').map(|(_, v)| v.trim()).unwrap_or("");

            // Handle "Bearer <token>" format (strip "Bearer " prefix if present)
            // Use case-insensitive check, then slice original value by length
            let value_lower = value.to_lowercase();
            let token_value = if value_lower.starts_with("bearer ") {
                // "bearer ".len() == 7
                value[7..].trim()
            } else {
                value
            };

            if token::constant_time_eq(token_value.as_bytes(), session_token.as_bytes()) {
                return Ok(());
            }
            warn!("Invalid phantom token in {} header", header_name);
            return Err(ProxyError::InvalidToken);
        }
    }

    warn!(
        "Missing {} header for phantom token validation",
        header_name
    );
    Err(ProxyError::InvalidToken)
}

/// Filter headers, removing Host, Content-Length, and the credential header.
///
/// Content-Length is re-added after body is read, and Host is rewritten
/// to the upstream. The route's configured credential header is stripped
/// so the phantom token is not forwarded alongside the real credential.
fn filter_headers(header_bytes: &[u8], cred_header: &str) -> Vec<(String, String)> {
    let header_str = std::str::from_utf8(header_bytes).unwrap_or("");
    let cred_header_lower = format!("{}:", cred_header.to_lowercase());
    let mut headers = Vec::new();

    for line in header_str.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("host:")
            || lower.starts_with("content-length:")
            || lower.starts_with(&cred_header_lower)
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

    // Include query string if present
    let path_with_query = if let Some(query) = parsed.query() {
        format!("{}?{}", path, query)
    } else {
        path
    };

    Ok((host, port, path_with_query))
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

// ============================================================================
// Injection mode helpers
// ============================================================================

/// Validate phantom token based on injection mode.
///
/// Different modes extract the phantom token from different locations:
/// - `Header`/`BasicAuth`: From the auth header (Authorization, x-api-key, etc.)
/// - `UrlPath`: From the URL path pattern (e.g., `/bot<token>/getMe`)
/// - `QueryParam`: From the query parameter (e.g., `?api_key=<token>`)
fn validate_phantom_token_for_mode(
    mode: &InjectMode,
    header_bytes: &[u8],
    path: &str,
    header_name: &str,
    path_pattern: Option<&str>,
    query_param_name: Option<&str>,
    session_token: &Zeroizing<String>,
) -> Result<()> {
    match mode {
        InjectMode::Header | InjectMode::BasicAuth => {
            // Validate from header (existing behavior)
            validate_phantom_token(header_bytes, header_name, session_token)
        }
        InjectMode::UrlPath => {
            // Validate from URL path
            let pattern = path_pattern.ok_or_else(|| {
                ProxyError::HttpParse("url_path mode requires path_pattern".to_string())
            })?;
            validate_phantom_token_in_path(path, pattern, session_token)
        }
        InjectMode::QueryParam => {
            // Validate from query parameter
            let param_name = query_param_name.ok_or_else(|| {
                ProxyError::HttpParse("query_param mode requires query_param_name".to_string())
            })?;
            validate_phantom_token_in_query(path, param_name, session_token)
        }
    }
}

/// Validate phantom token embedded in URL path.
///
/// Extracts the token from the path using the pattern (e.g., `/bot{}/` matches
/// `/bot<token>/getMe` and extracts `<token>`).
fn validate_phantom_token_in_path(
    path: &str,
    pattern: &str,
    session_token: &Zeroizing<String>,
) -> Result<()> {
    // Split pattern on {} to get prefix and suffix
    let parts: Vec<&str> = pattern.split("{}").collect();
    if parts.len() != 2 {
        return Err(ProxyError::HttpParse(format!(
            "invalid path_pattern '{}': must contain exactly one {{}}",
            pattern
        )));
    }
    let (prefix, suffix) = (parts[0], parts[1]);

    // Find the token in the path
    if let Some(start) = path.find(prefix) {
        let after_prefix = start + prefix.len();

        // Handle empty suffix case (token extends to end of path or next '/' or '?')
        let end_offset = if suffix.is_empty() {
            path[after_prefix..]
                .find(['/', '?'])
                .unwrap_or(path[after_prefix..].len())
        } else {
            match path[after_prefix..].find(suffix) {
                Some(offset) => offset,
                None => {
                    warn!("Missing phantom token in URL path (pattern: {})", pattern);
                    return Err(ProxyError::InvalidToken);
                }
            }
        };

        let token = &path[after_prefix..after_prefix + end_offset];
        if token::constant_time_eq(token.as_bytes(), session_token.as_bytes()) {
            return Ok(());
        }
        warn!("Invalid phantom token in URL path");
        return Err(ProxyError::InvalidToken);
    }

    warn!("Missing phantom token in URL path (pattern: {})", pattern);
    Err(ProxyError::InvalidToken)
}

/// Validate phantom token in query parameter.
fn validate_phantom_token_in_query(
    path: &str,
    param_name: &str,
    session_token: &Zeroizing<String>,
) -> Result<()> {
    // Parse query string from path
    if let Some(query_start) = path.find('?') {
        let query = &path[query_start + 1..];
        for pair in query.split('&') {
            if let Some((name, value)) = pair.split_once('=') {
                if name == param_name {
                    // URL-decode the value
                    let decoded = urlencoding::decode(value).unwrap_or_else(|_| value.into());
                    if token::constant_time_eq(decoded.as_bytes(), session_token.as_bytes()) {
                        return Ok(());
                    }
                    warn!("Invalid phantom token in query parameter '{}'", param_name);
                    return Err(ProxyError::InvalidToken);
                }
            }
        }
    }

    warn!("Missing phantom token in query parameter '{}'", param_name);
    Err(ProxyError::InvalidToken)
}

/// Transform URL path based on injection mode.
///
/// - `UrlPath`: Replace phantom token with real credential in path
/// - `QueryParam`: Add/replace query parameter with real credential
/// - `Header`/`BasicAuth`: No path transformation needed
fn transform_path_for_mode(
    mode: &InjectMode,
    path: &str,
    path_pattern: Option<&str>,
    path_replacement: Option<&str>,
    query_param_name: Option<&str>,
    credential: &Zeroizing<String>,
) -> Result<String> {
    match mode {
        InjectMode::Header | InjectMode::BasicAuth => {
            // No path transformation needed
            Ok(path.to_string())
        }
        InjectMode::UrlPath => {
            let pattern = path_pattern.ok_or_else(|| {
                ProxyError::HttpParse("url_path mode requires path_pattern".to_string())
            })?;
            let replacement = path_replacement.unwrap_or(pattern);
            transform_url_path(path, pattern, replacement, credential)
        }
        InjectMode::QueryParam => {
            let param_name = query_param_name.ok_or_else(|| {
                ProxyError::HttpParse("query_param mode requires query_param_name".to_string())
            })?;
            transform_query_param(path, param_name, credential)
        }
    }
}

/// Transform URL path by replacing phantom token pattern with real credential.
///
/// Example: `/bot<phantom>/getMe` with pattern `/bot{}/` becomes `/bot<real>/getMe`
fn transform_url_path(
    path: &str,
    pattern: &str,
    replacement: &str,
    credential: &Zeroizing<String>,
) -> Result<String> {
    // Split pattern on {} to get prefix and suffix
    let parts: Vec<&str> = pattern.split("{}").collect();
    if parts.len() != 2 {
        return Err(ProxyError::HttpParse(format!(
            "invalid path_pattern '{}': must contain exactly one {{}}",
            pattern
        )));
    }
    let (pattern_prefix, pattern_suffix) = (parts[0], parts[1]);

    // Split replacement on {}
    let repl_parts: Vec<&str> = replacement.split("{}").collect();
    if repl_parts.len() != 2 {
        return Err(ProxyError::HttpParse(format!(
            "invalid path_replacement '{}': must contain exactly one {{}}",
            replacement
        )));
    }
    let (repl_prefix, repl_suffix) = (repl_parts[0], repl_parts[1]);

    // Find and replace the token in the path
    if let Some(start) = path.find(pattern_prefix) {
        let after_prefix = start + pattern_prefix.len();

        // Handle empty suffix case (token extends to end of path or next '/' or '?')
        let end_offset = if pattern_suffix.is_empty() {
            // Find the next path segment delimiter or end of path
            path[after_prefix..]
                .find(['/', '?'])
                .unwrap_or(path[after_prefix..].len())
        } else {
            // Find the suffix in the remaining path
            match path[after_prefix..].find(pattern_suffix) {
                Some(offset) => offset,
                None => {
                    return Err(ProxyError::HttpParse(format!(
                        "path '{}' does not match pattern '{}'",
                        path, pattern
                    )));
                }
            }
        };

        let before = &path[..start];
        let after = &path[after_prefix + end_offset + pattern_suffix.len()..];
        return Ok(format!(
            "{}{}{}{}{}",
            before,
            repl_prefix,
            credential.as_str(),
            repl_suffix,
            after
        ));
    }

    Err(ProxyError::HttpParse(format!(
        "path '{}' does not match pattern '{}'",
        path, pattern
    )))
}

/// Transform query string by adding or replacing a parameter with the credential.
fn transform_query_param(
    path: &str,
    param_name: &str,
    credential: &Zeroizing<String>,
) -> Result<String> {
    let encoded_value = urlencoding::encode(credential.as_str());

    if let Some(query_start) = path.find('?') {
        let base_path = &path[..query_start];
        let query = &path[query_start + 1..];

        // Check if parameter already exists
        let mut found = false;
        let new_query: Vec<String> = query
            .split('&')
            .map(|pair| {
                if let Some((name, _)) = pair.split_once('=') {
                    if name == param_name {
                        found = true;
                        return format!("{}={}", param_name, encoded_value);
                    }
                }
                pair.to_string()
            })
            .collect();

        if found {
            Ok(format!("{}?{}", base_path, new_query.join("&")))
        } else {
            // Append the parameter
            Ok(format!(
                "{}?{}&{}={}",
                base_path, query, param_name, encoded_value
            ))
        }
    } else {
        // No query string, add one
        Ok(format!("{}?{}={}", path, param_name, encoded_value))
    }
}

/// Inject credential into request based on mode.
///
/// For header/basic_auth modes, adds the credential header.
/// For url_path/query_param modes, the credential is already in the path.
fn inject_credential_for_mode(cred: &LoadedCredential, request: &mut Zeroizing<String>) {
    match cred.inject_mode {
        InjectMode::Header | InjectMode::BasicAuth => {
            // Inject credential header
            request.push_str(&format!(
                "{}: {}\r\n",
                cred.header_name,
                cred.header_value.as_str()
            ));
        }
        InjectMode::UrlPath | InjectMode::QueryParam => {
            // Credential is already injected into the URL path/query
            // No header injection needed
        }
    }
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
    fn test_validate_phantom_token_bearer_valid() {
        let token = Zeroizing::new("secret123".to_string());
        let header = b"Authorization: Bearer secret123\r\nContent-Type: application/json\r\n\r\n";
        assert!(validate_phantom_token(header, "Authorization", &token).is_ok());
    }

    #[test]
    fn test_validate_phantom_token_bearer_invalid() {
        let token = Zeroizing::new("secret123".to_string());
        let header = b"Authorization: Bearer wrong\r\n\r\n";
        assert!(validate_phantom_token(header, "Authorization", &token).is_err());
    }

    #[test]
    fn test_validate_phantom_token_x_api_key_valid() {
        let token = Zeroizing::new("secret123".to_string());
        let header = b"x-api-key: secret123\r\nContent-Type: application/json\r\n\r\n";
        assert!(validate_phantom_token(header, "x-api-key", &token).is_ok());
    }

    #[test]
    fn test_validate_phantom_token_x_goog_api_key_valid() {
        let token = Zeroizing::new("secret123".to_string());
        let header = b"x-goog-api-key: secret123\r\nContent-Type: application/json\r\n\r\n";
        assert!(validate_phantom_token(header, "x-goog-api-key", &token).is_ok());
    }

    #[test]
    fn test_validate_phantom_token_missing() {
        let token = Zeroizing::new("secret123".to_string());
        let header = b"Content-Type: application/json\r\n\r\n";
        assert!(validate_phantom_token(header, "Authorization", &token).is_err());
    }

    #[test]
    fn test_validate_phantom_token_case_insensitive_header() {
        let token = Zeroizing::new("secret123".to_string());
        let header = b"AUTHORIZATION: Bearer secret123\r\n\r\n";
        assert!(validate_phantom_token(header, "Authorization", &token).is_ok());
    }

    #[test]
    fn test_filter_headers_removes_host_auth() {
        let header = b"Host: localhost:8080\r\nAuthorization: Bearer old\r\nContent-Type: application/json\r\nAccept: */*\r\n\r\n";
        let filtered = filter_headers(header, "Authorization");
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].0, "Content-Type");
        assert_eq!(filtered[1].0, "Accept");
    }

    #[test]
    fn test_filter_headers_removes_x_api_key() {
        let header = b"x-api-key: sk-old\r\nContent-Type: application/json\r\n\r\n";
        let filtered = filter_headers(header, "x-api-key");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].0, "Content-Type");
    }

    #[test]
    fn test_filter_headers_removes_custom_header() {
        let header = b"PRIVATE-TOKEN: phantom123\r\nContent-Type: application/json\r\n\r\n";
        let filtered = filter_headers(header, "PRIVATE-TOKEN");
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

    // ============================================================================
    // URL Path Injection Mode Tests
    // ============================================================================

    #[test]
    fn test_validate_phantom_token_in_path_valid() {
        let token = Zeroizing::new("session123".to_string());
        let path = "/bot/session123/getMe";
        let pattern = "/bot/{}/";
        assert!(validate_phantom_token_in_path(path, pattern, &token).is_ok());
    }

    #[test]
    fn test_validate_phantom_token_in_path_invalid() {
        let token = Zeroizing::new("session123".to_string());
        let path = "/bot/wrong_token/getMe";
        let pattern = "/bot/{}/";
        assert!(validate_phantom_token_in_path(path, pattern, &token).is_err());
    }

    #[test]
    fn test_validate_phantom_token_in_path_missing() {
        let token = Zeroizing::new("session123".to_string());
        let path = "/api/getMe";
        let pattern = "/bot/{}/";
        assert!(validate_phantom_token_in_path(path, pattern, &token).is_err());
    }

    #[test]
    fn test_transform_url_path_basic() {
        let credential = Zeroizing::new("real_token".to_string());
        let path = "/bot/phantom_token/getMe";
        let pattern = "/bot/{}/";
        let replacement = "/bot/{}/";
        let result = transform_url_path(path, pattern, replacement, &credential).unwrap();
        assert_eq!(result, "/bot/real_token/getMe");
    }

    #[test]
    fn test_transform_url_path_different_replacement() {
        let credential = Zeroizing::new("real_token".to_string());
        let path = "/api/v1/phantom_token/chat";
        let pattern = "/api/v1/{}/";
        let replacement = "/v2/bot/{}/";
        let result = transform_url_path(path, pattern, replacement, &credential).unwrap();
        assert_eq!(result, "/v2/bot/real_token/chat");
    }

    #[test]
    fn test_transform_url_path_no_trailing_slash() {
        let credential = Zeroizing::new("real_token".to_string());
        let path = "/bot/phantom_token";
        let pattern = "/bot/{}";
        let replacement = "/bot/{}";
        let result = transform_url_path(path, pattern, replacement, &credential).unwrap();
        assert_eq!(result, "/bot/real_token");
    }

    // ============================================================================
    // Query Param Injection Mode Tests
    // ============================================================================

    #[test]
    fn test_validate_phantom_token_in_query_valid() {
        let token = Zeroizing::new("session123".to_string());
        let path = "/api/data?api_key=session123&other=value";
        assert!(validate_phantom_token_in_query(path, "api_key", &token).is_ok());
    }

    #[test]
    fn test_validate_phantom_token_in_query_invalid() {
        let token = Zeroizing::new("session123".to_string());
        let path = "/api/data?api_key=wrong_token";
        assert!(validate_phantom_token_in_query(path, "api_key", &token).is_err());
    }

    #[test]
    fn test_validate_phantom_token_in_query_missing_param() {
        let token = Zeroizing::new("session123".to_string());
        let path = "/api/data?other=value";
        assert!(validate_phantom_token_in_query(path, "api_key", &token).is_err());
    }

    #[test]
    fn test_validate_phantom_token_in_query_no_query_string() {
        let token = Zeroizing::new("session123".to_string());
        let path = "/api/data";
        assert!(validate_phantom_token_in_query(path, "api_key", &token).is_err());
    }

    #[test]
    fn test_validate_phantom_token_in_query_url_encoded() {
        let token = Zeroizing::new("token with spaces".to_string());
        let path = "/api/data?api_key=token%20with%20spaces";
        assert!(validate_phantom_token_in_query(path, "api_key", &token).is_ok());
    }

    #[test]
    fn test_transform_query_param_add_to_no_query() {
        let credential = Zeroizing::new("real_key".to_string());
        let path = "/api/data";
        let result = transform_query_param(path, "api_key", &credential).unwrap();
        assert_eq!(result, "/api/data?api_key=real_key");
    }

    #[test]
    fn test_transform_query_param_add_to_existing_query() {
        let credential = Zeroizing::new("real_key".to_string());
        let path = "/api/data?other=value";
        let result = transform_query_param(path, "api_key", &credential).unwrap();
        assert_eq!(result, "/api/data?other=value&api_key=real_key");
    }

    #[test]
    fn test_transform_query_param_replace_existing() {
        let credential = Zeroizing::new("real_key".to_string());
        let path = "/api/data?api_key=phantom&other=value";
        let result = transform_query_param(path, "api_key", &credential).unwrap();
        assert_eq!(result, "/api/data?api_key=real_key&other=value");
    }

    #[test]
    fn test_transform_query_param_url_encodes_special_chars() {
        let credential = Zeroizing::new("key with spaces".to_string());
        let path = "/api/data";
        let result = transform_query_param(path, "api_key", &credential).unwrap();
        assert_eq!(result, "/api/data?api_key=key%20with%20spaces");
    }
}
