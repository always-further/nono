//! HTTP forward proxy handler for non-CONNECT requests.
//!
//! Handles absolute-form HTTP requests such as:
//! `GET http://localhost:11434/path HTTP/1.1`
//!
//! This is used for localhost relay MVP mode where clients may issue plain
//! HTTP requests instead of CONNECT tunneling.

use crate::audit;
use crate::error::{ProxyError, Result};
use crate::filter::ProxyFilter;
use crate::localhost::is_loopback_host;
use crate::token;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::debug;
use url::Url;
use zeroize::Zeroizing;

/// Timeout for upstream TCP connect.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Handle a non-CONNECT HTTP proxy request.
pub async fn handle_forward_proxy(
    first_line: &str,
    stream: &mut TcpStream,
    filter: &ProxyFilter,
    session_token: &Zeroizing<String>,
    remaining_header: &[u8],
    buffered: &[u8],
    localhost_connect_ports: &[u16],
) -> Result<()> {
    let (method, target, version) = parse_request_line(first_line)?;
    let parsed = Url::parse(&target).map_err(|e| {
        ProxyError::HttpParse(format!("invalid absolute URL in request target: {}", e))
    })?;

    if parsed.scheme() != "http" {
        send_response(stream, 400, "Bad Request").await?;
        return Err(ProxyError::HttpParse(format!(
            "forward proxy only supports http:// targets, got: {}",
            parsed.scheme()
        )));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| ProxyError::HttpParse("missing host in absolute URL".to_string()))?
        .to_string();
    let port = parsed.port_or_known_default().ok_or_else(|| {
        ProxyError::HttpParse("unable to determine destination port for request".to_string())
    })?;

    if !localhost_connect_ports.is_empty()
        && is_loopback_host(&host)
        && !localhost_connect_ports.contains(&port)
    {
        let reason = format!("localhost port {} is not allowed", port);
        audit::log_denied(audit::ProxyMode::Forward, &host, port, &reason);
        send_response(stream, 403, &format!("Forbidden: {}", reason)).await?;
        return Err(ProxyError::HostDenied { host, reason });
    }

    // Forward mode requires proxy auth.
    if let Err(e) = token::validate_proxy_auth(remaining_header, session_token) {
        debug!("FORWARD auth failed: {}", e);
        send_response(stream, 407, "Proxy Authentication Required").await?;
        return Err(ProxyError::InvalidToken);
    }

    let check = filter.check_host(&host, port).await?;
    if !check.result.is_allowed() {
        let reason = check.result.reason();
        audit::log_denied(audit::ProxyMode::Forward, &host, port, &reason);
        send_response(stream, 403, &format!("Forbidden: {}", reason)).await?;
        return Err(ProxyError::HostDenied { host, reason });
    }

    let resolved = &check.resolved_addrs;
    if resolved.is_empty() {
        let reason = "DNS resolution returned no addresses".to_string();
        audit::log_denied(audit::ProxyMode::Forward, &host, port, &reason);
        send_response(stream, 502, "DNS resolution failed").await?;
        return Err(ProxyError::UpstreamConnect { host, reason });
    }

    let mut upstream = connect_to_resolved(resolved, &host).await?;

    let request = build_upstream_request(&method, &parsed, &version, remaining_header);
    upstream.write_all(request.as_bytes()).await?;
    if !buffered.is_empty() {
        upstream.write_all(buffered).await?;
    }

    audit::log_allowed(audit::ProxyMode::Forward, &host, port, &method);
    let _ = tokio::io::copy_bidirectional(stream, &mut upstream).await;
    Ok(())
}

fn parse_request_line(line: &str) -> Result<(String, String, String)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() != 3 {
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

fn build_upstream_request(method: &str, parsed: &Url, version: &str, headers: &[u8]) -> String {
    let path = path_and_query(parsed);
    let mut out = format!("{} {} {}\r\n", method, path, version);
    append_target_host_header(&mut out, parsed);

    let headers_str = String::from_utf8_lossy(headers);
    for raw_line in headers_str.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }

        // Never forward folded headers or lines containing raw CR/LF.
        if line
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_whitespace())
            || line.contains('\r')
            || line.contains('\n')
        {
            continue;
        }

        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let normalized_name = name.trim().to_ascii_lowercase();
        if normalized_name.is_empty()
            || normalized_name == "host"
            || normalized_name == "proxy-authorization"
            || normalized_name == "proxy-connection"
        {
            continue;
        }

        out.push_str(name.trim());
        out.push(':');
        out.push_str(value);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out
}

fn append_target_host_header(out: &mut String, parsed: &Url) {
    if let Some(host) = parsed.host_str() {
        if let Some(port) = parsed.port() {
            out.push_str(&format!("Host: {}:{}\r\n", host, port));
        } else {
            out.push_str(&format!("Host: {}\r\n", host));
        }
    }
}

fn path_and_query(parsed: &Url) -> String {
    let mut out = parsed.path().to_string();
    if out.is_empty() {
        out.push('/');
    }
    if let Some(q) = parsed.query() {
        out.push('?');
        out.push_str(q);
    }
    out
}

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
    fn test_parse_request_line() {
        let (m, t, v) = parse_request_line("GET http://localhost:8080/x HTTP/1.1").unwrap();
        assert_eq!(m, "GET");
        assert_eq!(t, "http://localhost:8080/x");
        assert_eq!(v, "HTTP/1.1");
    }

    #[test]
    fn test_parse_request_line_malformed() {
        assert!(parse_request_line("GET /").is_err());
        assert!(parse_request_line("").is_err());
    }

    #[test]
    fn test_path_and_query() {
        let url = Url::parse("http://localhost:8080/v1/chat?q=1").unwrap();
        assert_eq!(path_and_query(&url), "/v1/chat?q=1");
    }

    #[test]
    fn test_build_upstream_request_strips_proxy_headers() {
        let url = Url::parse("http://localhost:8080/v1").unwrap();
        let headers = b"Host: localhost:8080\r\nProxy-Authorization: Bearer t\r\nProxy-Connection: Keep-Alive\r\nAccept: */*\r\n";
        let req = build_upstream_request("GET", &url, "HTTP/1.1", headers);
        assert!(req.starts_with("GET /v1 HTTP/1.1\r\n"));
        assert!(req.contains("Host: localhost:8080\r\n"));
        assert!(req.contains("Accept: */*\r\n"));
        assert!(!req.to_ascii_lowercase().contains("proxy-authorization"));
        assert!(!req.to_ascii_lowercase().contains("proxy-connection"));
    }

    #[test]
    fn test_build_upstream_request_replaces_host_header() {
        let url = Url::parse("http://localhost:8080/v1").unwrap();
        let headers = b"Host: attacker.example\r\nAccept: text/plain\r\n";
        let req = build_upstream_request("GET", &url, "HTTP/1.1", headers);
        assert!(req.contains("Host: localhost:8080\r\n"));
        assert!(!req.contains("Host: attacker.example\r\n"));
        assert!(req.contains("Accept: text/plain\r\n"));
    }

    #[test]
    fn test_build_upstream_request_drops_proxy_auth_with_spaced_colon() {
        let url = Url::parse("http://localhost:8080/v1").unwrap();
        let headers = b"Proxy-Authorization : Bearer leaked\r\nAccept: */*\r\n";
        let req = build_upstream_request("GET", &url, "HTTP/1.1", headers);
        assert!(!req.to_ascii_lowercase().contains("proxy-authorization"));
        assert!(req.contains("Accept: */*\r\n"));
    }

    #[test]
    fn test_build_upstream_request_drops_headers_with_embedded_cr() {
        let url = Url::parse("http://localhost:8080/v1").unwrap();
        let headers = b"X-Test: ok\rInjected: evil\r\nAccept: */*\r\n";
        let req = build_upstream_request("GET", &url, "HTTP/1.1", headers);
        assert!(!req.contains("X-Test: ok\rInjected: evil\r\n"));
        assert!(req.contains("Accept: */*\r\n"));
    }
}
