//! SPIFFE/SPIRE Workload API credential sources.
//!
//! - [`SpiffeX509Source`] — streams X.509-SVIDs, maintains an atomically-swappable `rustls` connector.
//! - [`SpiffeJwtSource`] — fetches JWT-SVIDs on demand, refreshes before expiry.
//!
//! SVID private key material is never written to disk or logged.

use crate::error::{ProxyError, Result};
use arc_swap::ArcSwap;
use base64::Engine as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use spiffe_workload::{JwtSource, SpiffeId, X509Source};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio_rustls::TlsConnector;
use tracing::{debug, error, warn};
use zeroize::Zeroizing;

/// Event emitted when an X.509-SVID rotates in the background.
pub struct SvidRotationEvent {
    pub route_id: String,
    pub workload_spiffe_id: String,
    pub trust_domain: String,
}

// Warn when a freshly-fetched JWT-SVID has fewer than this many seconds left —
// indicates SPIRE JWT TTL is too short. Refresh is per-request via the agent cache.
const JWT_REFRESH_SECS: i64 = 60;

// ─── X.509-SVID source ───────────────────────────────────────────────────────

/// X.509-SVID source backed by the SPIRE Workload API.
///
/// The `TlsConnector` is atomically swapped on rotation; in-flight connections
/// keep the old cert while new requests pick up the rotated one.
pub struct SpiffeX509Source {
    connector: Arc<ArcSwap<TlsConnector>>,
    spiffe_id: Arc<ArcSwap<String>>,
    expected_upstream_spiffe_id: Option<String>,
    /// `false` when the Workload API stream terminates unexpectedly.
    available: Arc<AtomicBool>,
    _shutdown: tokio_util::sync::DropGuard,
}

impl std::fmt::Debug for SpiffeX509Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeX509Source")
            .field("available", &self.available.load(Ordering::Relaxed))
            .finish()
    }
}

impl SpiffeX509Source {
    /// Fails closed if the socket is unreachable or no SVID is available.
    pub async fn connect(
        route_id: &str,
        socket_path: &str,
        svid_hint: Option<&str>,
        expected_upstream_spiffe_id: Option<String>,
        upstream_tls_ca: Option<String>,
    ) -> Result<Self> {
        let endpoint = format!("unix:{socket_path}");
        let source = X509Source::builder()
            .endpoint(&endpoint)
            // Fail-closed: refuse to start if the Workload API is unreachable.
            .initial_sync_timeout(std::time::Duration::from_secs(10))
            .build()
            .await
            .map_err(|e| {
                ProxyError::Config(format!(
                    "SPIFFE X.509 source failed to connect to '{socket_path}': {e}"
                ))
            })?;

        let svid = select_svid(&source, svid_hint)?;
        let spiffe_id_str = svid.spiffe_id().to_string();
        let connector = build_connector_from_svid(
            &source,
            svid_hint,
            &expected_upstream_spiffe_id,
            upstream_tls_ca.as_deref(),
        )?;

        debug!("SPIFFE X.509-SVID acquired: {}", spiffe_id_str);

        let connector_cell = Arc::new(ArcSwap::new(Arc::new(connector)));
        let spiffe_id_cell = Arc::new(ArcSwap::new(Arc::new(spiffe_id_str)));
        let available = Arc::new(AtomicBool::new(true));

        let cancel = tokio_util::sync::CancellationToken::new();
        let shutdown = cancel.clone().drop_guard();

        let connector_bg = Arc::clone(&connector_cell);
        let id_bg = Arc::clone(&spiffe_id_cell);
        let available_bg = Arc::clone(&available);
        let hint = svid_hint.map(str::to_string);
        let expected_id = expected_upstream_spiffe_id.clone();
        let upstream_ca = upstream_tls_ca.clone();
        let route_id_bg = route_id.to_string();

        tokio::spawn(async move {
            let mut updates = source.updated();
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    result = updates.changed() => match result {
                        Ok(_) => {
                            match build_connector_from_svid(
                                &source,
                                hint.as_deref(),
                                &expected_id,
                                upstream_ca.as_deref(),
                            ) {
                                Ok(new_connector) => {
                                    if let Ok(svid) = select_svid(&source, hint.as_deref()) {
                                        let new_id = svid.spiffe_id().to_string();
                                        let trust_domain = crate::auth::extract_trust_domain(&new_id);
                                        id_bg.store(Arc::new(new_id.clone()));
                                        crate::audit::log_svid_rotation(&SvidRotationEvent {
                                            route_id: route_id_bg.clone(),
                                            workload_spiffe_id: new_id,
                                            trust_domain,
                                        });
                                    }
                                    connector_bg.store(Arc::new(new_connector));
                                    available_bg.store(true, Ordering::Release);
                                }
                                Err(e) => {
                                    error!("SPIFFE X.509-SVID rotation failed: {e}; route remains available with previous SVID");
                                }
                            }
                        }
                        Err(e) => {
                            error!("SPIRE Workload API stream closed: {e}; route unavailable");
                            available_bg.store(false, Ordering::Release);
                            break;
                        }
                    }
                }
            }
        });

        Ok(Self {
            connector: connector_cell,
            spiffe_id: spiffe_id_cell,
            expected_upstream_spiffe_id,
            available,
            _shutdown: shutdown,
        })
    }

    pub fn tls_connector(&self) -> TlsConnector {
        let guard = self.connector.load();
        (**guard).clone()
    }

    /// `false` when the Workload API stream has terminated; routes fail-closed.
    pub fn is_available(&self) -> bool {
        self.available.load(Ordering::Acquire)
    }

    pub fn spiffe_id(&self) -> String {
        (**self.spiffe_id.load()).clone()
    }

    pub fn expected_upstream_spiffe_id(&self) -> Option<&str> {
        self.expected_upstream_spiffe_id.as_deref()
    }
}

fn build_connector_from_svid(
    source: &X509Source,
    svid_hint: Option<&str>,
    expected_upstream_spiffe_id: &Option<String>,
    upstream_tls_ca: Option<&str>,
) -> Result<TlsConnector> {
    let svid = select_svid(source, svid_hint)?;

    let cert_chain: Vec<CertificateDer<'static>> = svid
        .cert_chain()
        .iter()
        .map(|c| CertificateDer::from(c.as_bytes().to_vec()))
        .collect();

    let private_key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(svid.private_key().as_bytes().to_vec()),
    );

    let bundle_set = source
        .bundle_set()
        .map_err(|e| ProxyError::Config(format!("SPIFFE trust bundle unavailable: {e}")))?;

    let mut root_store = rustls::RootCertStore::empty();
    for (_td, bundle) in bundle_set.iter() {
        for ca_cert in bundle.authorities() {
            root_store
                .add(CertificateDer::from(ca_cert.as_bytes().to_vec()))
                .map_err(|e| ProxyError::Config(format!("invalid SPIFFE CA cert: {e}")))?;
        }
    }

    if let Some(ca_path) = upstream_tls_ca {
        crate::route::add_ca_file_to_store(&mut root_store, ca_path)?;
    }

    let verifier = SpiffeServerCertVerifier::new(root_store, expected_upstream_spiffe_id.clone())?;

    let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| ProxyError::Config(format!("TLS config error: {e}")))?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(verifier))
    .with_client_auth_cert(cert_chain, private_key_der)
    .map_err(|e| ProxyError::Config(format!("SPIFFE client cert error: {e}")))?;

    Ok(TlsConnector::from(Arc::new(tls_config)))
}

fn select_svid(
    source: &X509Source,
    svid_hint: Option<&str>,
) -> Result<Arc<spiffe_workload::X509Svid>> {
    let ctx = source
        .x509_context()
        .map_err(|e| ProxyError::Config(format!("SPIFFE X.509 context unavailable: {e}")))?;

    let svids = ctx.svids();
    if svids.is_empty() {
        return Err(ProxyError::Config(
            "SPIFFE Workload API returned no X.509-SVIDs".to_string(),
        ));
    }

    if let Some(hint) = svid_hint {
        if let Some(matched) = svids.iter().find(|s| s.hint() == Some(hint)) {
            return Ok(Arc::clone(matched));
        }
        warn!(
            "SPIFFE svid_hint '{}' did not match any SVID; using first available",
            hint
        );
    }

    Ok(Arc::clone(&svids[0]))
}

// ─── Custom upstream SPIFFE ID verifier ──────────────────────────────────────

/// Verifies the upstream's URI SAN against an expected SPIFFE ID,
/// after delegating chain verification to `WebPkiServerVerifier`.
#[derive(Debug)]
struct SpiffeServerCertVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    expected_spiffe_id: Option<SpiffeId>,
}

impl SpiffeServerCertVerifier {
    fn new(root_store: rustls::RootCertStore, expected_spiffe_id: Option<String>) -> Result<Self> {
        let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(root_store),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .map_err(|e| ProxyError::Config(format!("SPIFFE verifier build error: {e}")))?;

        let expected = expected_spiffe_id
            .map(|id| {
                SpiffeId::new(&id).map_err(|e| {
                    ProxyError::Config(format!("invalid expected_upstream_spiffe_id '{id}': {e}"))
                })
            })
            .transpose()?;

        Ok(Self {
            inner,
            expected_spiffe_id: expected,
        })
    }
}

impl ServerCertVerifier for SpiffeServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        // SPIFFE SVIDs carry URI SANs (e.g. spiffe://trust-domain/workload),
        // not DNS SANs, so WebPKI will always reject them with
        // `NotValidForName`. We allow that specific error and continue to the
        // SPIFFE ID check below; all other errors (bad chain, expired cert,
        // revoked, etc.) are still fatal.
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(_) => {}
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName)) => {
                // Expected for SPIFFE SVIDs: identity lives in the URI SAN,
                // not in the DNS SAN that WebPKI checks. Chain trust has
                // still been verified; fall through to the SPIFFE ID check.
            }
            Err(e) => return Err(e),
        }

        if let Some(expected) = &self.expected_spiffe_id {
            let actual =
                spiffe_workload::cert::spiffe_id_from_der(end_entity.as_ref()).map_err(|e| {
                    rustls::Error::General(format!(
                        "upstream certificate has no valid SPIFFE ID URI SAN: {e}"
                    ))
                })?;

            if &actual != expected {
                return Err(rustls::Error::General(format!(
                    "upstream SPIFFE ID mismatch: got '{actual}', expected '{expected}'"
                )));
            }
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

// ─── JWT-SVID source ─────────────────────────────────────────────────────────

/// JWT-SVID source backed by the SPIRE Workload API.
///
/// Tokens are fetched on demand via the agent cache; a warning is logged when
/// fewer than `JWT_REFRESH_SECS` remain (see `fetch_token`).
pub struct SpiffeJwtSource {
    inner: Arc<JwtSource>,
    pub audience: Vec<String>,
    pub inject_header: String,
    pub svid_hint: Option<SpiffeId>,
}

impl std::fmt::Debug for SpiffeJwtSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeJwtSource").finish()
    }
}

impl SpiffeJwtSource {
    /// Fails closed if the socket is unreachable.
    pub async fn connect(
        socket_path: &str,
        audience: Vec<String>,
        inject_header: String,
        svid_hint: Option<&str>,
    ) -> Result<Self> {
        let endpoint = format!("unix:{socket_path}");
        let source = JwtSource::builder()
            .endpoint(&endpoint)
            .initial_sync_timeout(std::time::Duration::from_secs(10))
            .build()
            .await
            .map_err(|e| {
                ProxyError::Config(format!(
                    "SPIFFE JWT source failed to connect to '{socket_path}': {e}"
                ))
            })?;

        let svid_hint = svid_hint
            .map(|h| {
                SpiffeId::new(h).map_err(|e| {
                    ProxyError::Config(format!("invalid svid_hint SPIFFE ID '{h}': {e}"))
                })
            })
            .transpose()?;

        debug!("SPIFFE JWT source connected to {}", socket_path);
        Ok(Self {
            inner: Arc::new(source),
            audience,
            inject_header,
            svid_hint,
        })
    }

    /// Returns `(token, spiffe_id)` for the requested audience.
    pub async fn fetch_token(&self, audience: &[String]) -> Result<(Zeroizing<String>, String)> {
        let svid = self
            .inner
            .fetch_jwt_svid_with_id(audience.iter().map(String::as_str), self.svid_hint.as_ref())
            .await
            .map_err(|e| ProxyError::Credential(format!("SPIFFE JWT-SVID fetch failed: {e}")))?;

        let now_ts = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs() as i64,
            Err(e) => -(e.duration().as_secs() as i64),
        };
        let exp_ts = svid.expiry().unix_timestamp();
        let remaining = exp_ts - now_ts;
        if remaining < JWT_REFRESH_SECS {
            warn!(
                "SPIFFE JWT-SVID expires in {}s, below the {}s refresh threshold; \
                 check SPIRE JWT TTL configuration",
                remaining, JWT_REFRESH_SECS
            );
        }

        let spiffe_id = svid.spiffe_id().to_string();
        Ok((Zeroizing::new(svid.token().to_string()), spiffe_id))
    }
}

// ─── Delegation chain ─────────────────────────────────────────────────────────

/// Parses the `act` claim (RFC 8693) from a JWT-SVID payload.
///
/// SPIRE has already verified the signature; this is JSON parsing only.
/// Returns `None` when no `act` claim is present.
pub fn delegation_from_jwt(token: &str) -> Option<nono::undo::SpiffeDelegationContext> {
    let payload = token.split('.').nth(1)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&decoded).ok()?;

    let act = claims.get("act")?;
    let authorized_by = act.get("sub")?.as_str()?.to_string();
    let on_behalf_of = claims
        .get("sub")
        .and_then(|s| s.as_str())
        .map(str::to_string);

    let mut depth: u32 = 1;
    let mut cursor = act;
    while let Some(nested) = cursor.get("act") {
        depth = depth.saturating_add(1);
        cursor = nested;
    }

    Some(nono::undo::SpiffeDelegationContext {
        authorized_by,
        on_behalf_of,
        chain_depth: depth,
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_x509_source_fails_closed_on_missing_socket() {
        let endpoint = "unix:/tmp/nono-test-nonexistent-spire-agent.sock";
        let result = X509Source::builder()
            .endpoint(endpoint)
            .initial_sync_timeout(std::time::Duration::from_secs(1))
            .build()
            .await;
        assert!(result.is_err(), "should fail when socket does not exist");
    }

    #[tokio::test]
    async fn test_jwt_source_fails_closed_on_missing_socket() {
        let endpoint = "unix:/tmp/nono-test-nonexistent-spire-agent.sock";
        let result = JwtSource::builder()
            .endpoint(endpoint)
            .initial_sync_timeout(std::time::Duration::from_secs(1))
            .build()
            .await;
        assert!(result.is_err(), "should fail when socket does not exist");
    }

    fn root_store_with_webpki() -> rustls::RootCertStore {
        let mut store = rustls::RootCertStore::empty();
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        store
    }

    #[test]
    fn test_spiffe_verifier_rejects_invalid_expected_id() {
        let result = SpiffeServerCertVerifier::new(
            root_store_with_webpki(),
            Some("not-a-spiffe-id".to_string()),
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("invalid expected_upstream_spiffe_id"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_spiffe_verifier_accepts_valid_expected_id() {
        let result = SpiffeServerCertVerifier::new(
            root_store_with_webpki(),
            Some("spiffe://prod.example/internal/api".to_string()),
        );
        assert!(result.is_ok(), "valid SPIFFE ID should be accepted");
    }

    #[test]
    fn test_spiffe_verifier_no_expected_id() {
        let result = SpiffeServerCertVerifier::new(root_store_with_webpki(), None);
        assert!(result.is_ok());
    }
}
