//! HTTP/2 per-stream credential injection and forwarding.
//!
//! When the inbound TLS handshake negotiates `h2` via ALPN, this module takes
//! over from [`super::handle`]. It uses the `h2` crate directly to accept
//! frames from the client and forward them upstream, applying credential
//! injection on each request stream's headers.
//!
//! Bodies are streamed frame-by-frame (DATA + TRAILERS) in both directions
//! without buffering, supporting all gRPC patterns including bidirectional
//! streaming.

use crate::audit;
use crate::config::InjectMode;
use crate::credential::CredentialStore;
use crate::error::{ProxyError, Result};
use crate::forward::{self, UpstreamScheme, UpstreamSpec, UpstreamStrategy};
use crate::reverse;
use crate::route::RouteStore;
use crate::tls_intercept::handle::InterceptCtx;
use bytes::Bytes;
use h2::{RecvStream, SendStream};
use http::{HeaderMap, HeaderValue, Request, Response};
use std::future::poll_fn;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, warn};

/// Spawn-safe context for per-stream h2 handlers.
///
/// Built from `InterceptCtx` at connection setup. Contains only the fields
/// needed by `handle_h2_stream`, all behind owned/Arc types so the struct
/// is `'static + Send`.
#[derive(Clone)]
struct SharedH2Ctx {
    host: String,
    port: u16,
    route_store: Arc<RouteStore>,
    credential_store: Arc<CredentialStore>,
    audit_log: Option<audit::SharedAuditLog>,
}

/// Accept an h2 connection from the client, open an h2 connection to the
/// upstream, and forward request streams with credential injection.
///
/// Each inbound stream is spawned as an independent task so multiple gRPC
/// RPCs can be multiplexed concurrently over a single connection.
pub(crate) async fn forward_h2_connection<S>(io: S, ctx: &InterceptCtx<'_>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut server_conn = h2::server::Builder::new()
        .max_send_buffer_size(1024 * 1024)
        .max_concurrent_streams(128)
        .handshake(io)
        .await
        .map_err(|e| ProxyError::HttpParse(format!("h2 server handshake failed: {}", e)))?;

    // Resolve upstream addresses (DNS-rebind-safe via filter).
    let check = ctx.filter.check_host(ctx.host, ctx.port).await?;
    if !check.result.is_allowed() {
        let reason = check.result.reason();
        warn!("h2_forward: upstream host denied by filter: {}", reason);
        return Ok(());
    }

    // Open upstream TLS with h2 ALPN.
    let upstream_tls = open_upstream_h2(ctx, &check.resolved_addrs).await?;

    let (h2_client, h2_conn) = h2::client::Builder::new()
        .max_send_buffer_size(1024 * 1024)
        .handshake(upstream_tls)
        .await
        .map_err(|e| ProxyError::UpstreamConnect {
            host: ctx.host.to_string(),
            reason: format!("h2 client handshake failed: {}", e),
        })?;

    // Spawn a task to continuously drive the upstream h2 connection. It must
    // be polled independently so frame I/O can progress while we handle
    // streams concurrently below.
    let conn_task = tokio::spawn(async move {
        if let Err(e) = h2_conn.await {
            debug!("h2_forward: upstream connection closed: {}", e);
        }
    });

    let shared_ctx = SharedH2Ctx {
        host: ctx.host.to_string(),
        port: ctx.port,
        route_store: Arc::clone(&ctx.route_store),
        credential_store: Arc::clone(&ctx.credential_store),
        audit_log: ctx.audit_log.cloned(),
    };

    let mut tasks = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            result = server_conn.accept() => {
                match result {
                    Some(Ok((request, respond))) => {
                        let ctx = shared_ctx.clone();
                        let mut client_send = h2_client.clone();
                        tasks.spawn(async move {
                            if let Err(e) =
                                handle_h2_stream(request, respond, &mut client_send, &ctx).await
                            {
                                debug!(
                                    "h2_forward: stream error for {}:{}: {}",
                                    ctx.host, ctx.port, e
                                );
                            }
                        });
                    }
                    Some(Err(e)) => {
                        debug!("h2_forward: server accept error: {}", e);
                        break;
                    }
                    None => break,
                }
            }
            Some(_) = tasks.join_next() => {
                // Stream task completed; continue accepting.
            }
        }
    }

    // Drain remaining in-flight streams. Keep driving the server connection
    // so flow-control frames (WINDOW_UPDATE) are processed for active streams.
    let mut conn_closed = false;
    while !tasks.is_empty() {
        if conn_closed {
            tasks.join_next().await;
        } else {
            tokio::select! {
                biased;
                result = tasks.join_next() => {
                    if result.is_none() {
                        break;
                    }
                }
                _ = poll_fn(|cx| server_conn.poll_closed(cx)) => {
                    conn_closed = true;
                }
            }
        }
    }

    conn_task.abort();
    Ok(())
}

/// Open upstream TLS with h2 ALPN.
async fn open_upstream_h2(
    ctx: &InterceptCtx<'_>,
    resolved_addrs: &[SocketAddr],
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let upstream_spec = UpstreamSpec {
        scheme: UpstreamScheme::Https,
        host: ctx.host,
        port: ctx.port,
        strategy: UpstreamStrategy::Direct { resolved_addrs },
        tls_connector: ctx.tls_connector_h2,
    };
    let tcp = forward::open_tcp_upstream(&upstream_spec).await?;
    let server_name =
        rustls::pki_types::ServerName::try_from(ctx.host.to_string()).map_err(|_| {
            ProxyError::UpstreamConnect {
                host: ctx.host.to_string(),
                reason: "invalid server name for TLS".to_string(),
            }
        })?;
    ctx.tls_connector_h2
        .connect(server_name, tcp)
        .await
        .map_err(|e| ProxyError::UpstreamConnect {
            host: ctx.host.to_string(),
            reason: format!("h2 upstream TLS failed: {}", e),
        })
}

/// Handle a single h2 request stream: route selection, credential injection,
/// and bidirectional body streaming.
async fn handle_h2_stream(
    request: Request<RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    client_send: &mut h2::client::SendRequest<Bytes>,
    ctx: &SharedH2Ctx,
) -> Result<()> {
    let method = request.method().clone();
    let path = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    debug!(
        "h2_forward: {} {} on {}:{}",
        method, path, ctx.host, ctx.port
    );

    // Route selection (same logic as handle.rs forward_inner_request).
    let host_port = format!("{}:{}", ctx.host.to_lowercase(), ctx.port);
    let candidates = ctx.route_store.lookup_all_by_upstream(&host_port);
    if candidates.is_empty() {
        warn!(
            "h2_forward: no route for {} after intercept handshake",
            host_port
        );
        send_h2_error(&mut respond, 502)?;
        return Ok(());
    }

    let method_str = method.as_str().to_string();
    let mut matches: Vec<(&str, &crate::route::LoadedRoute)> = Vec::new();
    let mut catch_all: Option<(&str, &crate::route::LoadedRoute)> = None;
    for (prefix, route) in &candidates {
        if route.endpoint_rules.is_empty() {
            if catch_all.is_none() {
                catch_all = Some((prefix, route));
            }
        } else if route.endpoint_rules.is_allowed(&method_str, &path) {
            matches.push((prefix, route));
        }
    }

    if matches.len() > 1 {
        let names: Vec<_> = matches.iter().map(|(p, _)| *p).collect();
        warn!(
            "h2_forward: ambiguous route: {} {} matched {:?}",
            method_str, path, names
        );
        audit::log_denied(
            ctx.audit_log.as_ref(),
            audit::ProxyMode::ConnectIntercept,
            &audit::EventContext {
                denial_category: Some(nono::undo::NetworkAuditDenialCategory::EndpointPolicy),
                ..audit::EventContext::default()
            },
            &ctx.host,
            ctx.port,
            "ambiguous route",
        );
        send_h2_error(&mut respond, 403)?;
        return Ok(());
    }

    let selected = matches.into_iter().next().or(catch_all);
    let service: Option<&str> = selected.map(|(s, _)| s);
    let route: Option<&crate::route::LoadedRoute> = selected.map(|(_, r)| r);
    let cred = service.and_then(|s| ctx.credential_store.get(s));

    if let Some(rt) = route
        && rt.missing_managed_credential(
            cred.is_some(),
            service
                .and_then(|s| ctx.credential_store.get_oauth2(s))
                .is_some(),
        )
    {
        warn!("h2_forward: managed credential unavailable for route");
        send_h2_error(&mut respond, 503)?;
        return Ok(());
    }

    // Build transformed path (credential injection into path/query if needed).
    let transformed_path = if let Some(cred) = cred {
        let cleaned = reverse::strip_proxy_artifacts(
            &path,
            &cred.proxy_inject_mode,
            &cred.inject_mode,
            cred.proxy_path_pattern.as_deref(),
            cred.proxy_query_param_name.as_deref(),
        );
        reverse::transform_path_for_mode(
            &cred.inject_mode,
            &cleaned,
            cred.path_pattern.as_deref(),
            cred.path_replacement.as_deref(),
            cred.query_param_name.as_deref(),
            &cred.raw_credential,
        )?
    } else {
        path.clone()
    };

    // Build upstream request headers.
    let mut upstream_headers = HeaderMap::new();
    for (name, value) in request.headers() {
        let name_lower = name.as_str().to_lowercase();
        // Skip hop-by-hop and connection-specific headers.
        if name_lower == "host" || name_lower == "connection" || name_lower == "proxy-authorization"
        {
            continue;
        }
        // Skip the credential header if we're injecting a replacement.
        if let Some(cred) = cred
            && matches!(cred.inject_mode, InjectMode::Header | InjectMode::BasicAuth)
            && name_lower == cred.header_name.to_lowercase()
        {
            continue;
        }
        upstream_headers.insert(name.clone(), value.clone());
    }

    // Inject credential header.
    if let Some(cred) = cred
        && matches!(cred.inject_mode, InjectMode::Header | InjectMode::BasicAuth)
        && let Ok(val) = HeaderValue::from_str(cred.header_value.as_str())
        && let Ok(name) = http::header::HeaderName::from_bytes(cred.header_name.as_bytes())
    {
        upstream_headers.insert(name, val);
    }

    // Build upstream h2 request.
    let uri = format!("https://{}:{}{}", ctx.host, ctx.port, transformed_path);
    let mut upstream_req = Request::builder().method(method.clone()).uri(&uri);
    if let Some(headers) = upstream_req.headers_mut() {
        *headers = upstream_headers;
    }

    let (recv_body, is_end_stream) = {
        let body = request.into_body();
        let end = body.is_end_stream();
        (body, end)
    };

    let upstream_req = upstream_req
        .body(())
        .map_err(|e| ProxyError::HttpParse(format!("h2 request build error: {}", e)))?;

    // Send request to upstream.
    let (response_fut, mut send_stream) = client_send
        .send_request(upstream_req, is_end_stream)
        .map_err(|e| ProxyError::UpstreamConnect {
            host: ctx.host.to_string(),
            reason: format!("h2 send_request failed: {}", e),
        })?;

    // Stream request body to upstream (frame-by-frame).
    if !is_end_stream {
        stream_body_to_upstream(recv_body, &mut send_stream).await?;
    }

    // Await upstream response.
    let response = response_fut
        .await
        .map_err(|e| ProxyError::UpstreamConnect {
            host: ctx.host.to_string(),
            reason: format!("h2 response error: {}", e),
        })?;

    let status = response.status();
    let resp_headers = response.headers().clone();
    let recv_resp_body = response.into_body();
    let resp_end_stream = recv_resp_body.is_end_stream();

    // Send response headers back to client.
    let mut client_response = Response::builder().status(status);
    if let Some(headers) = client_response.headers_mut() {
        *headers = resp_headers;
    }
    let client_response = client_response
        .body(())
        .map_err(|e| ProxyError::HttpParse(format!("h2 response build error: {}", e)))?;

    let mut send_resp = respond
        .send_response(client_response, resp_end_stream)
        .map_err(|e| ProxyError::HttpParse(format!("h2 send_response failed: {}", e)))?;

    // Stream response body back to client (frame-by-frame).
    if !resp_end_stream {
        stream_body_to_client(recv_resp_body, &mut send_resp).await?;
    }

    // Audit event.
    audit::log_l7_request(
        ctx.audit_log.as_ref(),
        audit::ProxyMode::ConnectIntercept,
        &audit::EventContext {
            route_id: service,
            auth_mechanism: cred.map(|c| match c.proxy_inject_mode {
                InjectMode::Header | InjectMode::BasicAuth => {
                    nono::undo::NetworkAuditAuthMechanism::PhantomHeader
                }
                InjectMode::UrlPath => nono::undo::NetworkAuditAuthMechanism::PhantomPath,
                InjectMode::QueryParam => nono::undo::NetworkAuditAuthMechanism::PhantomQuery,
            }),
            auth_outcome: cred.map(|_| nono::undo::NetworkAuditAuthOutcome::Succeeded),
            managed_credential_active: Some(cred.is_some()),
            injection_mode: cred.map(|c| match c.inject_mode {
                InjectMode::Header => nono::undo::NetworkAuditInjectionMode::Header,
                InjectMode::UrlPath => nono::undo::NetworkAuditInjectionMode::UrlPath,
                InjectMode::QueryParam => nono::undo::NetworkAuditInjectionMode::QueryParam,
                InjectMode::BasicAuth => nono::undo::NetworkAuditInjectionMode::BasicAuth,
            }),
            denial_category: None,
        },
        &ctx.host,
        &method_str,
        &path,
        status.as_u16(),
    );

    Ok(())
}

/// Stream h2 DATA frames from client to upstream without buffering.
async fn stream_body_to_upstream(mut recv: RecvStream, send: &mut SendStream<Bytes>) -> Result<()> {
    loop {
        match recv.data().await {
            Some(Ok(data)) => {
                let len = data.len();
                send.send_data(data, false)
                    .map_err(|e| ProxyError::HttpParse(format!("h2 send_data upstream: {e}")))?;
                recv.flow_control()
                    .release_capacity(len)
                    .map_err(|e| ProxyError::HttpParse(format!("h2 flow control: {e}")))?;
            }
            Some(Err(e)) => {
                debug!("h2_forward: client body read error: {}", e);
                send.send_reset(h2::Reason::INTERNAL_ERROR);
                return Err(ProxyError::HttpParse(format!(
                    "h2 client body read failed: {e}"
                )));
            }
            None => break,
        }
    }
    // Forward trailers if present (gRPC uses trailers for grpc-status).
    if let Some(trailers) = recv
        .trailers()
        .await
        .map_err(|e| ProxyError::HttpParse(format!("h2 recv trailers: {e}")))?
    {
        send.send_trailers(trailers)
            .map_err(|e| ProxyError::HttpParse(format!("h2 send_trailers upstream: {e}")))?;
    } else {
        send.send_data(Bytes::new(), true)
            .map_err(|e| ProxyError::HttpParse(format!("h2 end stream upstream: {e}")))?;
    }
    Ok(())
}

/// Stream h2 DATA frames from upstream response to client without buffering.
async fn stream_body_to_client(mut recv: RecvStream, send: &mut SendStream<Bytes>) -> Result<()> {
    loop {
        match recv.data().await {
            Some(Ok(data)) => {
                let len = data.len();
                send.send_data(data, false)
                    .map_err(|e| ProxyError::HttpParse(format!("h2 send_data client: {e}")))?;
                recv.flow_control()
                    .release_capacity(len)
                    .map_err(|e| ProxyError::HttpParse(format!("h2 flow control: {e}")))?;
            }
            Some(Err(e)) => {
                debug!("h2_forward: upstream body read error: {}", e);
                send.send_reset(h2::Reason::INTERNAL_ERROR);
                return Err(ProxyError::HttpParse(format!(
                    "h2 upstream body read failed: {e}"
                )));
            }
            None => break,
        }
    }
    // Forward trailers (gRPC uses grpc-status + grpc-message as trailers).
    if let Some(trailers) = recv
        .trailers()
        .await
        .map_err(|e| ProxyError::HttpParse(format!("h2 recv trailers: {e}")))?
    {
        send.send_trailers(trailers)
            .map_err(|e| ProxyError::HttpParse(format!("h2 send_trailers client: {e}")))?;
    } else {
        send.send_data(Bytes::new(), true)
            .map_err(|e| ProxyError::HttpParse(format!("h2 end stream client: {e}")))?;
    }
    Ok(())
}

/// Send a simple h2 error response (no body).
fn send_h2_error(respond: &mut h2::server::SendResponse<Bytes>, status_code: u16) -> Result<()> {
    let status =
        http::StatusCode::from_u16(status_code).unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
    let response = Response::builder()
        .status(status)
        .body(())
        .map_err(|e| ProxyError::HttpParse(format!("h2 error response build: {}", e)))?;
    respond
        .send_response(response, true)
        .map_err(|e| ProxyError::HttpParse(format!("h2 send error response: {}", e)))?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::{EndpointRule, InjectMode, RouteConfig};
    use crate::credential::{CredentialStore, LoadedCredential};
    use crate::filter::ProxyFilter;
    use crate::route::RouteStore;
    use crate::tls_intercept::ca::EphemeralCa;
    use crate::tls_intercept::cert_cache::CertCache;
    use bytes::Bytes;
    use rustls::pki_types::CertificateDer;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use zeroize::Zeroizing;

    /// Build a TLS connector that trusts the given CA PEM and offers h2 ALPN.
    fn h2_tls_connector_trusting(ca_pem: &str) -> tokio_rustls::TlsConnector {
        use rustls::pki_types::pem::PemObject;

        let mut roots = rustls::RootCertStore::empty();
        let cert = CertificateDer::from_pem_slice(ca_pem.as_bytes()).unwrap();
        roots.add(cert).unwrap();
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];
        tokio_rustls::TlsConnector::from(Arc::new(config))
    }

    /// Build a TLS server config for the mock upstream (uses the same ephemeral CA).
    fn upstream_server_config(ca: &EphemeralCa) -> Arc<rustls::server::ServerConfig> {
        use rcgen::{CertificateParams, KeyPair};
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use time::OffsetDateTime;

        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + time::Duration::hours(1);

        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params
            .signed_by(&key_pair, ca.ca_cert(), ca.key_pair())
            .unwrap();

        let cert_der = cert.der().clone();
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

        let mut config = rustls::server::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], private_key)
        .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        Arc::new(config)
    }

    /// Build a RouteStore with a single route pointing at `host:port`.
    fn make_route_store(host: &str, port: u16, rules: Vec<EndpointRule>) -> RouteStore {
        let routes = vec![RouteConfig {
            prefix: "test-svc".to_string(),
            upstream: format!("https://{}:{}", host, port),
            credential_key: None,
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: Some("Bearer {}".to_string()),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: rules,
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: None,
        }];
        RouteStore::load(&routes).unwrap()
    }

    /// Build a CredentialStore with a test credential.
    fn make_credential_store(secret: &str) -> CredentialStore {
        let mut store = CredentialStore::empty();
        store.insert_for_test(
            "test-svc".to_string(),
            LoadedCredential {
                inject_mode: InjectMode::Header,
                proxy_inject_mode: InjectMode::Header,
                raw_credential: Zeroizing::new(secret.to_string()),
                header_name: "Authorization".to_string(),
                proxy_header_name: "Authorization".to_string(),
                header_value: Zeroizing::new(format!("Bearer {}", secret)),
                path_pattern: None,
                proxy_path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy_query_param_name: None,
            },
        );
        store
    }

    /// Spawn a mock h2 upstream server that captures received request headers
    /// and responds with 200. Returns the captured headers via the channel.
    async fn spawn_mock_h2_upstream(
        ca: &EphemeralCa,
    ) -> (
        u16,
        tokio::sync::oneshot::Receiver<(String, http::HeaderMap)>,
    ) {
        let server_config = upstream_server_config(ca);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let (tcp_stream, _) = listener.accept().await.unwrap();
            let tls_acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            let tls_stream = tls_acceptor.accept(tcp_stream).await.unwrap();

            let mut h2_conn = h2::server::handshake(tls_stream).await.unwrap();
            let mut tx = Some(tx);
            // Drive the server connection — accept() both drives I/O and yields streams.
            while let Some(Ok((request, mut respond))) = h2_conn.accept().await {
                if let Some(tx) = tx.take() {
                    let method_path = format!(
                        "{} {}",
                        request.method(),
                        request
                            .uri()
                            .path_and_query()
                            .map(|pq| pq.as_str())
                            .unwrap_or("/")
                    );
                    let headers = request.headers().clone();

                    let response = http::Response::builder().status(200).body(()).unwrap();
                    respond.send_response(response, true).unwrap();

                    let _ = tx.send((method_path, headers));
                }
            }
        });

        (port, rx)
    }

    /// Spawn a mock h2 upstream that echoes body and trailers back.
    async fn spawn_mock_h2_upstream_echo(
        ca: &EphemeralCa,
    ) -> (u16, tokio::sync::oneshot::Receiver<Vec<u8>>) {
        let server_config = upstream_server_config(ca);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let (tcp_stream, _) = listener.accept().await.unwrap();
            let tls_acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            let tls_stream = tls_acceptor.accept(tcp_stream).await.unwrap();

            let mut h2_conn = h2::server::handshake(tls_stream).await.unwrap();
            let mut tx = Some(tx);
            while let Some(Ok((request, mut respond))) = h2_conn.accept().await {
                if let Some(tx) = tx.take() {
                    let mut body_recv = request.into_body();
                    let mut collected = Vec::new();

                    while let Some(Ok(data)) = body_recv.data().await {
                        let len = data.len();
                        collected.extend_from_slice(&data);
                        body_recv.flow_control().release_capacity(len).unwrap();
                    }

                    let response = http::Response::builder().status(200).body(()).unwrap();
                    let mut send_stream = respond.send_response(response, false).unwrap();
                    send_stream
                        .send_data(Bytes::from(collected.clone()), false)
                        .unwrap();

                    let mut trailers = http::HeaderMap::new();
                    trailers.insert("grpc-status", "0".parse().unwrap());
                    trailers.insert("grpc-message", "OK".parse().unwrap());
                    send_stream.send_trailers(trailers).unwrap();

                    let _ = tx.send(collected);
                }
            }
        });

        (port, rx)
    }

    #[tokio::test]
    async fn h2_forward_injects_credential_header() {
        use std::time::Duration;

        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let (upstream_port, rx) = spawn_mock_h2_upstream(&ca).await;

        let route_store = make_route_store(
            "localhost",
            upstream_port,
            vec![EndpointRule {
                method: "POST".to_string(),
                path: "/v1/chat/completions".to_string(),
            }],
        );
        let credential_store = make_credential_store("sk-test-secret-key");
        let cert_cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let tls_connector = h2_tls_connector_trusting(ca.cert_pem());
        let filter = ProxyFilter::allow_all();
        let session_token = Zeroizing::new("session-tok".to_string());

        let ctx = InterceptCtx {
            route_id: Some("test-svc"),
            host: "localhost",
            port: upstream_port,
            route_store: Arc::new(route_store),
            credential_store: Arc::new(credential_store),
            session_token: &session_token,
            cert_cache,
            tls_connector: &tls_connector,
            tls_connector_h2: &tls_connector,
            filter: &filter,
            audit_log: None,
        };

        let (client_io, server_io) = tokio::io::duplex(65536);

        // The forward arm will block after handling the stream. We use a
        // timeout on the overall join to detect the test completing.
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                async {
                    let _ = forward_h2_connection(server_io, &ctx).await;
                },
                async {
                    let (mut h2_client, h2_conn) = h2::client::handshake(client_io).await.unwrap();
                    let conn_handle = tokio::spawn(async move {
                        let _ = h2_conn.await;
                    });

                    let request = http::Request::builder()
                        .method("POST")
                        .uri(format!(
                            "https://localhost:{}/v1/chat/completions",
                            upstream_port
                        ))
                        .header("content-type", "application/json")
                        .body(())
                        .unwrap();
                    let (response_fut, mut send_stream) =
                        h2_client.send_request(request, false).unwrap();
                    send_stream
                        .send_data(Bytes::from(r#"{"model":"gpt-4"}"#), true)
                        .unwrap();

                    let response = response_fut.await.unwrap();
                    assert_eq!(response.status(), 200);

                    let (method_path, headers) = rx.await.unwrap();
                    assert_eq!(method_path, "POST /v1/chat/completions");
                    assert_eq!(
                        headers.get("authorization").map(|v| v.to_str().unwrap()),
                        Some("Bearer sk-test-secret-key")
                    );
                    assert_eq!(
                        headers.get("content-type").map(|v| v.to_str().unwrap()),
                        Some("application/json")
                    );

                    // Close client h2 so server_conn.accept() returns None.
                    drop(h2_client);
                    conn_handle.abort();
                    let _ = conn_handle.await;
                }
            );
        })
        .await;
        assert!(result.is_ok(), "test timed out — h2 forwarding hung");
    }

    #[tokio::test]
    async fn h2_forward_streams_body_and_trailers() {
        use std::time::Duration;

        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let (upstream_port, rx) = spawn_mock_h2_upstream_echo(&ca).await;

        let route_store = make_route_store("localhost", upstream_port, vec![]);
        let credential_store = CredentialStore::empty();
        let cert_cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let tls_connector = h2_tls_connector_trusting(ca.cert_pem());
        let filter = ProxyFilter::allow_all();
        let session_token = Zeroizing::new("session-tok".to_string());

        let ctx = InterceptCtx {
            route_id: Some("test-svc"),
            host: "localhost",
            port: upstream_port,
            route_store: Arc::new(route_store),
            credential_store: Arc::new(credential_store),
            session_token: &session_token,
            cert_cache,
            tls_connector: &tls_connector,
            tls_connector_h2: &tls_connector,
            filter: &filter,
            audit_log: None,
        };

        let (client_io, server_io) = tokio::io::duplex(65536);

        let result = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                async {
                    let _ = forward_h2_connection(server_io, &ctx).await;
                },
                async {
                    let (mut h2_client, h2_conn) = h2::client::handshake(client_io).await.unwrap();
                    let conn_handle = tokio::spawn(async move {
                        let _ = h2_conn.await;
                    });

                    let request = http::Request::builder()
                        .method("POST")
                        .uri(format!(
                            "https://localhost:{}/test.Service/Method",
                            upstream_port
                        ))
                        .header("content-type", "application/grpc")
                        .body(())
                        .unwrap();
                    let (response_fut, mut send_stream) =
                        h2_client.send_request(request, false).unwrap();

                    let payload = b"hello grpc world";
                    send_stream
                        .send_data(Bytes::from(&payload[..8]), false)
                        .unwrap();
                    send_stream
                        .send_data(Bytes::from(&payload[8..]), true)
                        .unwrap();

                    let response = response_fut.await.unwrap();
                    assert_eq!(response.status(), 200);

                    let mut resp_body = response.into_body();
                    let mut received = Vec::new();
                    while let Some(Ok(chunk)) = resp_body.data().await {
                        let len = chunk.len();
                        received.extend_from_slice(&chunk);
                        resp_body.flow_control().release_capacity(len).unwrap();
                    }
                    assert_eq!(received, payload);

                    let trailers = resp_body.trailers().await.unwrap().unwrap();
                    assert_eq!(trailers.get("grpc-status").unwrap(), "0");
                    assert_eq!(trailers.get("grpc-message").unwrap(), "OK");

                    let upstream_body = rx.await.unwrap();
                    assert_eq!(upstream_body, payload);

                    drop(h2_client);
                    conn_handle.abort();
                    let _ = conn_handle.await;
                }
            );
        })
        .await;
        assert!(result.is_ok(), "test timed out — h2 forwarding hung");
    }

    #[tokio::test]
    async fn h2_forward_returns_502_when_no_route() {
        let ca = Arc::new(EphemeralCa::generate().unwrap());

        let route_store = RouteStore::empty();
        let credential_store = CredentialStore::empty();
        let cert_cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let tls_connector = h2_tls_connector_trusting(ca.cert_pem());
        let filter = ProxyFilter::allow_all();
        let session_token = Zeroizing::new("session-tok".to_string());

        // Mock upstream that accepts h2 connections (needed so
        // forward_h2_connection can open the upstream h2 session).
        let server_config = upstream_server_config(&ca);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let tls_acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            let tls = tls_acceptor.accept(tcp).await.unwrap();
            let mut h2_conn = h2::server::handshake(tls).await.unwrap();
            while h2_conn.accept().await.is_some() {}
        });

        let ctx = InterceptCtx {
            route_id: None,
            host: "localhost",
            port: upstream_port,
            route_store: Arc::new(route_store),
            credential_store: Arc::new(credential_store),
            session_token: &session_token,
            cert_cache,
            tls_connector: &tls_connector,
            tls_connector_h2: &tls_connector,
            filter: &filter,
            audit_log: None,
        };

        let (client_io, server_io) = tokio::io::duplex(65536);

        let (_, client_result) = tokio::join!(
            async {
                let _ = forward_h2_connection(server_io, &ctx).await;
            },
            async {
                let (h2_client, h2_conn) = h2::client::handshake(client_io).await.unwrap();
                let conn_handle = tokio::spawn(async move {
                    let _ = h2_conn.await;
                });

                let mut client_send = h2_client.ready().await.unwrap();
                let request = http::Request::builder()
                    .method("GET")
                    .uri(format!("https://localhost:{}/v1/models", upstream_port))
                    .body(())
                    .unwrap();
                let (response_fut, _send_stream) = client_send.send_request(request, true).unwrap();

                let response = response_fut.await.unwrap();
                assert_eq!(response.status(), 502);

                drop(client_send);
                conn_handle.abort();
            }
        );
        client_result
    }

    #[tokio::test]
    async fn h2_forward_returns_403_on_ambiguous_routes() {
        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let (upstream_port, _rx) = spawn_mock_h2_upstream(&ca).await;

        let routes = vec![
            RouteConfig {
                prefix: "svc-a".to_string(),
                upstream: format!("https://localhost:{}", upstream_port),
                credential_key: None,
                inject_mode: InjectMode::Header,
                inject_header: "Authorization".to_string(),
                credential_format: Some("Bearer {}".to_string()),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: None,
                endpoint_rules: vec![EndpointRule {
                    method: "*".to_string(),
                    path: "/v1/*".to_string(),
                }],
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
            },
            RouteConfig {
                prefix: "svc-b".to_string(),
                upstream: format!("https://localhost:{}", upstream_port),
                credential_key: None,
                inject_mode: InjectMode::Header,
                inject_header: "Authorization".to_string(),
                credential_format: Some("Bearer {}".to_string()),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                proxy: None,
                env_var: None,
                endpoint_rules: vec![EndpointRule {
                    method: "*".to_string(),
                    path: "/v1/*".to_string(),
                }],
                tls_ca: None,
                tls_client_cert: None,
                tls_client_key: None,
                oauth2: None,
            },
        ];
        let route_store = RouteStore::load(&routes).unwrap();
        let credential_store = CredentialStore::empty();
        let cert_cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let tls_connector = h2_tls_connector_trusting(ca.cert_pem());
        let filter = ProxyFilter::allow_all();
        let session_token = Zeroizing::new("session-tok".to_string());

        let ctx = InterceptCtx {
            route_id: None,
            host: "localhost",
            port: upstream_port,
            route_store: Arc::new(route_store),
            credential_store: Arc::new(credential_store),
            session_token: &session_token,
            cert_cache,
            tls_connector: &tls_connector,
            tls_connector_h2: &tls_connector,
            filter: &filter,
            audit_log: None,
        };

        let (client_io, server_io) = tokio::io::duplex(65536);

        let (_, client_result) = tokio::join!(
            async {
                let _ = forward_h2_connection(server_io, &ctx).await;
            },
            async {
                let (h2_client, h2_conn) = h2::client::handshake(client_io).await.unwrap();
                let conn_handle = tokio::spawn(async move {
                    let _ = h2_conn.await;
                });

                let mut client_send = h2_client.ready().await.unwrap();
                let request = http::Request::builder()
                    .method("POST")
                    .uri(format!(
                        "https://localhost:{}/v1/chat/completions",
                        upstream_port
                    ))
                    .body(())
                    .unwrap();
                let (response_fut, _send_stream) = client_send.send_request(request, true).unwrap();

                let response = response_fut.await.unwrap();
                assert_eq!(response.status(), 403);

                drop(client_send);
                conn_handle.abort();
            }
        );
        client_result
    }

    #[tokio::test]
    async fn h2_forward_passthrough_without_credentials_when_no_endpoint_match() {
        use std::time::Duration;

        let ca = Arc::new(EphemeralCa::generate().unwrap());
        let (upstream_port, rx) = spawn_mock_h2_upstream(&ca).await;

        let route_store = make_route_store(
            "localhost",
            upstream_port,
            vec![EndpointRule {
                method: "POST".to_string(),
                path: "/v1/chat/completions".to_string(),
            }],
        );
        let credential_store = make_credential_store("sk-should-not-appear");
        let cert_cache = Arc::new(CertCache::new(Arc::clone(&ca)));
        let tls_connector = h2_tls_connector_trusting(ca.cert_pem());
        let filter = ProxyFilter::allow_all();
        let session_token = Zeroizing::new("session-tok".to_string());

        let ctx = InterceptCtx {
            route_id: Some("test-svc"),
            host: "localhost",
            port: upstream_port,
            route_store: Arc::new(route_store),
            credential_store: Arc::new(credential_store),
            session_token: &session_token,
            cert_cache,
            tls_connector: &tls_connector,
            tls_connector_h2: &tls_connector,
            filter: &filter,
            audit_log: None,
        };

        let (client_io, server_io) = tokio::io::duplex(65536);

        let result = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                async {
                    let _ = forward_h2_connection(server_io, &ctx).await;
                },
                async {
                    let (mut h2_client, h2_conn) = h2::client::handshake(client_io).await.unwrap();
                    let conn_handle = tokio::spawn(async move {
                        let _ = h2_conn.await;
                    });

                    let request = http::Request::builder()
                        .method("GET")
                        .uri(format!(
                            "https://localhost:{}/v1/unmatched-path",
                            upstream_port
                        ))
                        .body(())
                        .unwrap();
                    let (response_fut, _send_stream) =
                        h2_client.send_request(request, true).unwrap();

                    let response = response_fut.await.unwrap();
                    assert_eq!(response.status(), 200);

                    let (method_path, headers) = rx.await.unwrap();
                    assert_eq!(method_path, "GET /v1/unmatched-path");
                    assert!(
                        headers.get("authorization").is_none(),
                        "credential should NOT be injected when endpoint rules don't match"
                    );

                    drop(h2_client);
                    conn_handle.abort();
                    let _ = conn_handle.await;
                }
            );
        })
        .await;
        assert!(result.is_ok(), "test timed out — h2 forwarding hung");
    }
}
