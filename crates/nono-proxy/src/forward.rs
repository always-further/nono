//! Shared L7 upstream-forwarding pipeline.
//!
//! Used by both the reverse-proxy path ([`crate::reverse`]) and the
//! TLS-intercept CONNECT path ([`crate::tls_intercept`]). The two callers
//! differ in how they parse the inbound request, look up the route, and
//! transform/inject credentials, but converge on the same wire-level
//! upstream operation:
//!
//! 1. Establish an upstream byte stream — direct TCP (with optional TLS)
//!    or chained CONNECT through an enterprise proxy (then TLS).
//! 2. Write the pre-built HTTP/1.1 request bytes + body.
//! 3. Stream the response back into the inbound sink.
//! 4. Emit one L7 audit event with the response status.
//!
//! ## Why pre-built request bytes
//!
//! Each caller has its own rules for header filtering, credential
//! injection, and path transformation. Asking this module to handle that
//! would mean smuggling all of that policy through a parameter struct.
//! Instead, the caller hands in finished bytes: a clean separation
//! between "build the request" and "speak it on the wire".

use crate::audit;
use crate::error::{ProxyError, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::debug;

/// Timeout for upstream TCP connect (matches the historical reverse-proxy value).
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Scheme of the upstream connection. `Http` is only legal for loopback
/// targets; the caller is responsible for enforcing that invariant
/// (`reverse.rs` does so via `validate_http_upstream_target`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamScheme {
    Http,
    Https,
}

/// How the upstream byte stream is established.
pub enum UpstreamStrategy<'a> {
    /// Connect directly to one of `resolved_addrs` (DNS rebinding-safe:
    /// the addresses must already have been validated by the host filter).
    Direct { resolved_addrs: &'a [SocketAddr] },
    /// Chain a CONNECT through an enterprise proxy. `proxy_addr` is the
    /// `host:port` of the corporate proxy; `proxy_auth_header` is the literal
    /// value to send in `Proxy-Authorization` (e.g. `"Basic …"`), or `None`
    /// for unauthenticated proxies.
    ExternalProxy {
        proxy_addr: &'a str,
        proxy_auth_header: Option<&'a str>,
    },
}

/// Description of the upstream the caller wants to reach.
pub struct UpstreamSpec<'a> {
    pub scheme: UpstreamScheme,
    pub host: &'a str,
    pub port: u16,
    pub strategy: UpstreamStrategy<'a>,
    /// TLS connector to use for an `Https` scheme. Reverse-proxy callers
    /// pass either the route's per-route connector (custom CA / mTLS) or
    /// the shared default; intercept callers do the same.
    pub tls_connector: &'a TlsConnector,
}

/// A response-body rewriter for OAuth-capture routes.
///
/// When passed to [`forward_request`], it switches the response path from
/// chunk-by-chunk streaming to buffer-the-whole-response: the closure is
/// invoked on the body bytes (chunked transfer decoded first), and:
/// - `Some(new_body)` → forward rebuilt headers (Content-Length replaced;
///   Transfer-Encoding / Content-Encoding dropped) + the new body.
/// - `None` → forward the original response unchanged (pass-through-on-error
///   — body wasn't JSON, no token fields, etc.).
///
/// Pass `None` at the call site to keep the historical streaming behaviour
/// for non-capture routes.
pub type ResponseBodyRewriter<'a> = Box<dyn FnOnce(&[u8]) -> Option<Vec<u8>> + Send + 'a>;

/// Audit-emission context.
pub struct AuditCtx<'a> {
    pub log: Option<&'a audit::SharedAuditLog>,
    pub mode: audit::ProxyMode,
    pub event_ctx: audit::EventContext<'a>,
    /// Logical target string (route prefix for reverse, hostname for intercept).
    pub target: &'a str,
    pub method: &'a str,
    /// Path as it should appear in the audit log (the *inbound* path before
    /// any rewriting — e.g. `/v1/chat/completions`, not the upstream URL).
    pub path: &'a str,
}

/// Connect to the upstream, write `request_bytes + body`, stream the
/// response back into `inbound`, and emit the L7 audit event.
///
/// Returns the response status code (or 502 if the upstream sent something
/// unparseable).
pub async fn forward_request<S>(
    inbound: &mut S,
    request_bytes: &[u8],
    body: &[u8],
    upstream: UpstreamSpec<'_>,
    audit: AuditCtx<'_>,
    response_hook: Option<ResponseBodyRewriter<'_>>,
) -> Result<u16>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let status = match upstream.scheme {
        UpstreamScheme::Https => {
            let mut tls_stream = open_https_upstream(&upstream).await?;
            write_then_stream(&mut tls_stream, request_bytes, body, inbound, response_hook).await?
        }
        UpstreamScheme::Http => {
            let mut tcp_stream = open_http_upstream(&upstream).await?;
            write_then_stream(&mut tcp_stream, request_bytes, body, inbound, response_hook).await?
        }
    };

    audit::log_l7_request(
        audit.log,
        audit.mode,
        &audit.event_ctx,
        audit.target,
        audit.method,
        audit.path,
        status,
    );
    Ok(status)
}

/// Open an upstream HTTPS connection (Direct TLS or ExternalProxy + TLS).
async fn open_https_upstream(
    upstream: &UpstreamSpec<'_>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = open_tcp_upstream(upstream).await?;
    let server_name =
        rustls::pki_types::ServerName::try_from(upstream.host.to_string()).map_err(|_| {
            ProxyError::UpstreamConnect {
                host: upstream.host.to_string(),
                reason: "invalid server name for TLS".to_string(),
            }
        })?;
    upstream
        .tls_connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| ProxyError::UpstreamConnect {
            host: upstream.host.to_string(),
            reason: format!("TLS handshake failed: {}", e),
        })
}

/// Open an upstream HTTP (plain) connection. Caller has already validated
/// that this is a loopback target.
async fn open_http_upstream(upstream: &UpstreamSpec<'_>) -> Result<TcpStream> {
    open_tcp_upstream(upstream).await
}

/// Establish the TCP layer of the upstream connection (without TLS).
pub(crate) async fn open_tcp_upstream(upstream: &UpstreamSpec<'_>) -> Result<TcpStream> {
    match upstream.strategy {
        UpstreamStrategy::Direct { resolved_addrs } => {
            if resolved_addrs.is_empty() {
                let addr = format!("{}:{}", upstream.host, upstream.port);
                match tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(&addr))
                    .await
                {
                    Ok(Ok(s)) => Ok(s),
                    Ok(Err(e)) => Err(ProxyError::UpstreamConnect {
                        host: upstream.host.to_string(),
                        reason: e.to_string(),
                    }),
                    Err(_) => Err(ProxyError::UpstreamConnect {
                        host: upstream.host.to_string(),
                        reason: "connection timed out".to_string(),
                    }),
                }
            } else {
                connect_to_resolved(resolved_addrs, upstream.host).await
            }
        }
        UpstreamStrategy::ExternalProxy {
            proxy_addr,
            proxy_auth_header,
        } => crate::external::connect_via_proxy(
            proxy_addr,
            upstream.host,
            upstream.port,
            proxy_auth_header,
        )
        .await
        .map_err(|e| match e {
            ProxyError::ExternalProxy(reason) => ProxyError::UpstreamConnect {
                host: upstream.host.to_string(),
                reason,
            },
            other => other,
        }),
    }
}

/// Connect to one of the pre-resolved socket addresses with timeout.
///
/// Tries each address in order until one succeeds. Connecting to the IP
/// directly (not re-resolving the hostname) prevents DNS rebinding TOCTOU.
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

async fn write_request<S>(stream: &mut S, request: &[u8], body: &[u8]) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(request).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }
    stream.flush().await?;
    Ok(())
}

/// Write the request upstream, then stream the response back.
///
/// A write-side failure is **not** fatal on its own: when an upstream rejects a
/// request (e.g. `401 Unauthorized` for an expired bearer token, or `413`) it
/// commonly sends the error response and closes the socket *before* it has read
/// the whole request body, which surfaces here as `EPIPE`/`Broken pipe` on the
/// write. If we bailed on that error we would discard the very response the
/// client needs to see — and for OAuth that 401 is exactly what triggers the
/// client's token refresh. So we always attempt to read the upstream response;
/// only if there is no readable response do we surface the write error.
async fn write_then_stream<U, I>(
    upstream: &mut U,
    request: &[u8],
    body: &[u8],
    inbound: &mut I,
    response_hook: Option<ResponseBodyRewriter<'_>>,
) -> Result<u16>
where
    U: AsyncRead + AsyncWrite + Unpin,
    I: AsyncWrite + Unpin,
{
    let write_result = write_request(upstream, request, body).await;
    match stream_response(upstream, inbound, response_hook).await {
        Ok(status) => match write_result {
            Ok(()) => Ok(status),
            // The write failed but the upstream still returned a parseable
            // response — relay it (the 401-then-close case). A bare
            // `NO_RESPONSE_STATUS` means nothing parseable came back, so the
            // write failure is the real error and must surface.
            Err(write_err) if status == NO_RESPONSE_STATUS => Err(write_err),
            Err(write_err) => {
                debug!(
                    "upstream closed during request write but returned a response \
                     (status {status}): {write_err}"
                );
                Ok(status)
            }
        },
        // No readable response: surface the earlier write failure if there was
        // one, otherwise the read error.
        Err(read_err) => {
            write_result?;
            Err(read_err)
        }
    }
}

/// Status returned by [`stream_response`] when the upstream sent nothing
/// parseable (no bytes, or an unparseable first line). Matches the default in
/// [`stream_response_passthrough`] and [`parse_response_status`].
const NO_RESPONSE_STATUS: u16 = 502;

/// Stream the upstream response back to the inbound sink.
///
/// Returns the HTTP status code parsed from the first chunk. Streams
/// chunked / SSE / HTTP-streaming bodies transparently because we never
/// buffer the body — each upstream read is mirrored to the inbound write.
async fn stream_response<U, I>(
    upstream: &mut U,
    inbound: &mut I,
    response_hook: Option<ResponseBodyRewriter<'_>>,
) -> Result<u16>
where
    U: AsyncRead + AsyncWrite + Unpin,
    I: AsyncWrite + Unpin,
{
    match response_hook {
        None => stream_response_passthrough(upstream, inbound).await,
        Some(rewriter) => stream_response_buffered(upstream, inbound, rewriter).await,
    }
}

/// Historical chunk-by-chunk pass-through (no buffering). Used for every
/// non-OAuth-capture route, preserving streaming/SSE/gRPC behaviour.
async fn stream_response_passthrough<U, I>(upstream: &mut U, inbound: &mut I) -> Result<u16>
where
    U: AsyncRead + AsyncWrite + Unpin,
    I: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192];
    let mut status_code: u16 = 502;
    let mut first_chunk = true;

    loop {
        let n = match upstream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                debug!("Upstream read error: {}", e);
                break;
            }
        };

        if first_chunk {
            status_code = parse_response_status(&buf[..n]);
            first_chunk = false;
        }

        inbound.write_all(&buf[..n]).await?;
        inbound.flush().await?;
    }

    Ok(status_code)
}

/// Buffer the full upstream response, hand the body to `rewriter`, and — if it
/// returns `Some(new_body)` — rebuild framing with the new Content-Length
/// (dropping Transfer-Encoding / Content-Encoding, since we now hold plaintext
/// rewritten bytes). On any framing-parse failure or a `None` from the
/// rewriter, the original bytes are forwarded unchanged (pass-through-on-error
/// preserves `/login` even when the body isn't what we expected). Used only by
/// OAuth-capture routes, whose token endpoint returns a small, non-streaming
/// JSON body.
async fn stream_response_buffered<U, I>(
    upstream: &mut U,
    inbound: &mut I,
    rewriter: ResponseBodyRewriter<'_>,
) -> Result<u16>
where
    U: AsyncRead + AsyncWrite + Unpin,
    I: AsyncWrite + Unpin,
{
    let mut raw = Vec::new();
    if let Err(e) = upstream.read_to_end(&mut raw).await {
        debug!("Upstream read error while buffering for rewriter: {}", e);
        // Forward whatever we managed to read.
    }
    let status_code = parse_response_status(&raw);

    // Locate the header/body split. Tolerate a lone-LF separator.
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .or_else(|| raw.windows(2).position(|w| w == b"\n\n").map(|i| i + 2));

    let Some(body_start) = header_end else {
        debug!("response-hook: no header/body separator; forwarding unchanged");
        inbound.write_all(&raw).await?;
        inbound.flush().await?;
        return Ok(status_code);
    };

    let header_bytes = &raw[..body_start];
    let body_bytes = &raw[body_start..];

    // Decode chunked transfer encoding before invoking the rewriter, so it
    // sees plaintext JSON rather than `<hex>\r\n{...}\r\n0\r\n\r\n`. On a
    // malformed chunked body, fall back to the raw bytes (the rewriter will
    // just decline if they aren't sensible JSON).
    let decoded_body_owned;
    let body_for_rewriter: &[u8] = if has_chunked_transfer_encoding(header_bytes) {
        match decode_chunked_body(body_bytes) {
            Some(decoded) => {
                decoded_body_owned = decoded;
                &decoded_body_owned
            }
            None => {
                debug!("response-hook: chunked decode failed; passing raw body to rewriter");
                body_bytes
            }
        }
    } else {
        body_bytes
    };

    let Some(new_body) = rewriter(body_for_rewriter) else {
        debug!("response-hook: rewriter returned None; forwarding unchanged");
        inbound.write_all(&raw).await?;
        inbound.flush().await?;
        return Ok(status_code);
    };

    // Rebuild headers: drop Content-Length / Transfer-Encoding /
    // Content-Encoding, then append the correct Content-Length + terminator.
    let header_str = std::str::from_utf8(header_bytes).unwrap_or("");
    let mut rebuilt = String::with_capacity(header_bytes.len() + 32);
    for line in header_str.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("content-length:")
            || lower.starts_with("transfer-encoding:")
            || lower.starts_with("content-encoding:")
        {
            continue;
        }
        rebuilt.push_str(line);
        rebuilt.push_str("\r\n");
    }
    rebuilt.push_str(&format!("Content-Length: {}\r\n\r\n", new_body.len()));

    inbound.write_all(rebuilt.as_bytes()).await?;
    inbound.write_all(&new_body).await?;
    inbound.flush().await?;
    Ok(status_code)
}

/// Return true if the response headers declare `Transfer-Encoding: chunked`
/// (case-insensitive; comma-lists like `gzip, chunked` are split per RFC 7230).
fn has_chunked_transfer_encoding(header_bytes: &[u8]) -> bool {
    let Ok(header_str) = std::str::from_utf8(header_bytes) else {
        return false;
    };
    header_str.split("\r\n").any(|line| {
        let lower = line.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("transfer-encoding:") {
            value.split(',').any(|token| token.trim() == "chunked")
        } else {
            false
        }
    })
}

/// Decode an HTTP/1.1 chunked-transfer-encoded body. Returns `None` on any
/// malformation (bad hex size, truncated chunk) so callers can pass-through
/// the original bytes. Chunk extensions are accepted and ignored; trailers
/// after the 0-size chunk are dropped (the body is what the rewriter cares
/// about, and the rebuilt response drops Transfer-Encoding anyway).
fn decode_chunked_body(body: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(body.len());
    let mut pos: usize = 0;
    loop {
        let rest = body.get(pos..)?;
        let line_end = rest.iter().position(|&b| b == b'\n')?;
        let line_end_abs = pos.checked_add(line_end)?;
        let raw_line = body.get(pos..line_end_abs)?;
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        let line_str = std::str::from_utf8(line).ok()?;
        let size_str = line_str.split(';').next()?.trim();
        let size = usize::from_str_radix(size_str, 16).ok()?;

        pos = line_end_abs.checked_add(1)?;

        if size == 0 {
            return Some(decoded);
        }

        let chunk_end = pos.checked_add(size)?;
        let chunk = body.get(pos..chunk_end)?;
        decoded.extend_from_slice(chunk);
        pos = chunk_end;

        if body.get(pos) == Some(&b'\r') {
            pos = pos.checked_add(1)?;
        }
        if body.get(pos) == Some(&b'\n') {
            pos = pos.checked_add(1)?;
        }
    }
}

/// Parse HTTP status code from the first response chunk.
///
/// Returns 502 when the response doesn't contain a valid status line.
fn parse_response_status(data: &[u8]) -> u16 {
    let line_end = data
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(data.len());
    let first_line = &data[..line_end.min(64)];

    if let Ok(line) = std::str::from_utf8(first_line) {
        let mut parts = line.split_whitespace();
        if let Some(version) = parts.next()
            && version.starts_with("HTTP/")
            && let Some(code_str) = parts.next()
            && code_str.len() == 3
        {
            return code_str.parse().unwrap_or(502);
        }
    }
    502
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_response_status_extracts_code() {
        assert_eq!(parse_response_status(b"HTTP/1.1 200 OK\r\n"), 200);
        assert_eq!(parse_response_status(b"HTTP/1.1 404 Not Found\r\n"), 404);
        assert_eq!(parse_response_status(b"HTTP/1.1 502 Bad Gateway\r\n"), 502);
    }

    #[test]
    fn parse_response_status_handles_garbage() {
        assert_eq!(parse_response_status(b""), 502);
        assert_eq!(parse_response_status(b"garbage"), 502);
        assert_eq!(parse_response_status(b"NOT-HTTP 200 OK"), 502);
    }

    // --- buffered response-rewrite path ---

    /// Run `stream_response_buffered` against an in-memory upstream that yields
    /// `payload` then EOF, returning the bytes written to the inbound sink.
    async fn run_buffered(payload: &[u8], rewriter: ResponseBodyRewriter<'_>) -> String {
        let (mut up_w, mut up_r) = tokio::io::duplex(payload.len() + 64);
        up_w.write_all(payload).await.unwrap();
        drop(up_w); // signal EOF to the reader
        let mut inbound: Vec<u8> = Vec::new();
        stream_response_buffered(&mut up_r, &mut inbound, rewriter)
            .await
            .unwrap();
        String::from_utf8_lossy(&inbound).into_owned()
    }

    #[tokio::test]
    async fn buffered_replaces_body_and_rewrites_content_length() {
        let payload =
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello";
        let rewriter: ResponseBodyRewriter<'_> =
            Box::new(|_body| Some(b"REWRITTEN-BODY!".to_vec())); // 15 bytes
        let out = run_buffered(payload, rewriter).await;
        assert!(out.contains("Content-Length: 15\r\n"), "new CL: {out:?}");
        assert!(
            !out.contains("Content-Length: 5\r\n"),
            "old CL dropped: {out:?}"
        );
        assert!(out.ends_with("REWRITTEN-BODY!"), "new body: {out:?}");
        assert!(
            out.contains("Content-Type: text/plain"),
            "other headers kept"
        );
    }

    #[tokio::test]
    async fn buffered_forwards_unchanged_when_rewriter_returns_none() {
        let payload = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let rewriter: ResponseBodyRewriter<'_> = Box::new(|_| None);
        let out = run_buffered(payload, rewriter).await;
        assert_eq!(out, String::from_utf8_lossy(payload));
    }

    #[tokio::test]
    async fn buffered_strips_transfer_and_content_encoding() {
        // Chunked + gzip headers must be dropped once we hold rewritten bytes.
        let payload = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let rewriter: ResponseBodyRewriter<'_> =
            Box::new(|_| Some(b"plaintext-json-here!".to_vec()));
        let out = run_buffered(payload, rewriter).await;
        assert!(out.contains("Content-Length: 20"), "CL added: {out:?}");
        assert!(
            !out.to_ascii_lowercase().contains("transfer-encoding"),
            "TE dropped"
        );
        assert!(
            !out.to_ascii_lowercase().contains("content-encoding"),
            "CE dropped"
        );
    }

    #[tokio::test]
    async fn buffered_forwards_unchanged_on_missing_header_separator() {
        let payload = b"HTTP/1.1 200 OK no separator here";
        let rewriter: ResponseBodyRewriter<'_> = Box::new(|_| Some(b"x".to_vec()));
        let out = run_buffered(payload, rewriter).await;
        assert_eq!(
            out,
            String::from_utf8_lossy(payload),
            "no split → unchanged"
        );
    }

    #[tokio::test]
    async fn buffered_decodes_chunked_body_before_rewriter() {
        // The rewriter must see decoded JSON, not the chunk framing.
        let payload = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n1a\r\n{\"access_token\":\"REAL!!\"}\r\n0\r\n\r\n";
        let rewriter: ResponseBodyRewriter<'_> = Box::new(|body| {
            let s = std::str::from_utf8(body).unwrap();
            assert!(
                s.starts_with("{\"access_token\""),
                "decoded JSON, got: {s:?}"
            );
            assert!(!s.contains("1a\r\n"), "chunk framing must be stripped");
            Some(b"{\"access_token\":\"nono_x\"}".to_vec())
        });
        let out = run_buffered(payload, rewriter).await;
        assert!(out.contains("nono_x"), "rewritten: {out:?}");
    }

    #[tokio::test]
    async fn buffered_passes_raw_body_when_chunked_decode_fails() {
        // Malformed chunk size ("ZZZ") → decode None → raw body to rewriter.
        let payload = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZZ\r\nbad\r\n";
        let rewriter: ResponseBodyRewriter<'_> = Box::new(|body| {
            assert!(
                body.starts_with(b"ZZZ"),
                "raw body passed through on decode fail"
            );
            None
        });
        let out = run_buffered(payload, rewriter).await;
        assert_eq!(out, String::from_utf8_lossy(payload));
    }

    #[test]
    fn has_chunked_transfer_encoding_detects_token() {
        assert!(has_chunked_transfer_encoding(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        ));
        assert!(has_chunked_transfer_encoding(
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: Chunked\r\n\r\n"
        ));
        assert!(has_chunked_transfer_encoding(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"
        ));
        assert!(!has_chunked_transfer_encoding(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
        ));
    }

    #[test]
    fn decode_chunked_body_roundtrips_and_rejects_malformed() {
        assert_eq!(
            decode_chunked_body(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"),
            Some(b"hello world".to_vec())
        );
        // Chunk extensions accepted and ignored.
        assert_eq!(
            decode_chunked_body(b"5;ext=1\r\nhello\r\n0\r\n\r\n"),
            Some(b"hello".to_vec())
        );
        // Malformed / truncated → None.
        assert_eq!(decode_chunked_body(b"ZZZ\r\nbad\r\n"), None);
        assert_eq!(decode_chunked_body(b"5\r\nhel"), None);
        assert_eq!(decode_chunked_body(b""), None);
    }

    // --- write-side close must not discard the upstream response ---

    /// Mock upstream that always fails writes with `BrokenPipe` (modelling a
    /// server that rejected the request and closed before reading the whole
    /// body) but serves `response` then EOF on reads.
    struct RejectingUpstream {
        response: std::io::Cursor<Vec<u8>>,
    }

    impl AsyncWrite for RejectingUpstream {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for RejectingUpstream {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.response).poll_read(cx, buf)
        }
    }

    #[tokio::test]
    async fn write_then_stream_relays_response_despite_write_epipe() {
        // The upstream rejects the body write (EPIPE) but sends a 401. The
        // client must still receive that 401 — otherwise the OAuth refresh it
        // would trigger never happens.
        let mut upstream = RejectingUpstream {
            response: std::io::Cursor::new(
                b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n".to_vec(),
            ),
        };
        let mut inbound: Vec<u8> = Vec::new();
        let status = write_then_stream(
            &mut upstream,
            b"POST /v1/messages HTTP/1.1\r\nConnection: close\r\n\r\n",
            b"a very large body the upstream never finished reading",
            &mut inbound,
            None,
        )
        .await
        .expect("a readable 401 response must not be reported as a forwarding failure");
        assert_eq!(status, 401);
        assert!(
            String::from_utf8_lossy(&inbound).contains("401 Unauthorized"),
            "client must receive the upstream 401: {inbound:?}"
        );
    }

    #[tokio::test]
    async fn write_then_stream_surfaces_write_error_when_no_response() {
        // Write fails AND the upstream sent nothing → the write error is the
        // real failure and must propagate.
        let mut upstream = RejectingUpstream {
            response: std::io::Cursor::new(Vec::new()),
        };
        let mut inbound: Vec<u8> = Vec::new();
        let result = write_then_stream(
            &mut upstream,
            b"POST / HTTP/1.1\r\n\r\n",
            b"body",
            &mut inbound,
            None,
        )
        .await;
        assert!(
            result.is_err(),
            "no response + write failure must surface as an error"
        );
    }
}
