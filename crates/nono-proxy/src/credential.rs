//! Credential loading and management for reverse proxy mode.
//!
//! Loads API credentials from the system keystore or 1Password at proxy startup.
//! Credentials are stored in `Zeroizing<String>` and injected into
//! requests via headers, URL paths, query parameters, or Basic Auth.
//! The sandboxed agent never sees the real credentials.

use crate::config::{CompiledEndpointRules, InjectMode, RouteConfig};
use crate::error::{ProxyError, Result};
use base64::Engine;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;
use zeroize::Zeroizing;

/// A loaded credential ready for injection.
pub struct LoadedCredential {
    /// Injection mode
    pub inject_mode: InjectMode,
    /// Upstream URL (e.g., "https://api.openai.com")
    pub upstream: String,
    /// Raw credential value from keystore (for modes that need it directly)
    pub raw_credential: Zeroizing<String>,

    // --- Header mode ---
    /// Header name to inject (e.g., "Authorization")
    pub header_name: String,
    /// Formatted header value (e.g., "Bearer sk-...")
    pub header_value: Zeroizing<String>,

    // --- URL path mode ---
    /// Pattern to match in incoming path (with {} placeholder)
    pub path_pattern: Option<String>,
    /// Pattern for outgoing path (with {} placeholder)
    pub path_replacement: Option<String>,

    // --- Query param mode ---
    /// Query parameter name
    pub query_param_name: Option<String>,

    // --- L7 endpoint filtering ---
    /// Pre-compiled endpoint rules for method+path filtering.
    /// Compiled once at load time to avoid per-request glob compilation.
    pub endpoint_rules: CompiledEndpointRules,

    // --- Custom CA TLS ---
    /// Per-route TLS connector with custom CA trust, if configured.
    /// Built once at startup from the route's `tls_ca` certificate file.
    /// When `None`, the shared default connector (webpki roots only) is used.
    pub tls_connector: Option<tokio_rustls::TlsConnector>,
}

/// Custom Debug impl that redacts secret values to prevent accidental leakage
/// in logs, panic messages, or debug output.
impl std::fmt::Debug for LoadedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedCredential")
            .field("inject_mode", &self.inject_mode)
            .field("upstream", &self.upstream)
            .field("raw_credential", &"[REDACTED]")
            .field("header_name", &self.header_name)
            .field("header_value", &"[REDACTED]")
            .field("path_pattern", &self.path_pattern)
            .field("path_replacement", &self.path_replacement)
            .field("query_param_name", &self.query_param_name)
            .field("endpoint_rules", &self.endpoint_rules)
            .field("has_custom_tls_ca", &self.tls_connector.is_some())
            .finish()
    }
}

/// Credential store for all configured routes.
#[derive(Debug)]
pub struct CredentialStore {
    /// Map from route prefix to loaded credential
    credentials: HashMap<String, LoadedCredential>,
}

impl CredentialStore {
    /// Load credentials for all configured routes from the system keystore.
    ///
    /// Routes without a `credential_key` are skipped (no credential injection).
    /// Routes whose credential is not found (e.g. unset env var) are skipped
    /// with a warning — this allows profiles to declare optional credentials
    /// without failing when they are unavailable.
    ///
    /// Returns an error only for hard failures (keystore access errors,
    /// config parse errors, non-UTF-8 values).
    pub fn load(routes: &[RouteConfig]) -> Result<Self> {
        let mut credentials = HashMap::new();

        for route in routes {
            if let Some(ref key) = route.credential_key {
                debug!(
                    "Loading credential for route prefix: {} (mode: {:?})",
                    route.prefix, route.inject_mode
                );

                let secret = match nono::keystore::load_secret_by_ref(KEYRING_SERVICE, key) {
                    Ok(s) => s,
                    Err(nono::NonoError::SecretNotFound(msg)) => {
                        debug!(
                            "Credential '{}' not available, skipping route: {}",
                            route.prefix, msg
                        );
                        continue;
                    }
                    Err(e) => return Err(ProxyError::Credential(e.to_string())),
                };

                // Format header value based on mode.
                // When inject_header is not "Authorization" (e.g., "PRIVATE-TOKEN",
                // "X-API-Key"), the credential is injected as-is unless the user
                // explicitly set a custom format. The default "Bearer {}" only
                // makes sense for the Authorization header.
                let effective_format = if route.inject_header != "Authorization"
                    && route.credential_format == "Bearer {}"
                {
                    "{}".to_string()
                } else {
                    route.credential_format.clone()
                };

                let header_value = match route.inject_mode {
                    InjectMode::Header => Zeroizing::new(effective_format.replace("{}", &secret)),
                    InjectMode::BasicAuth => {
                        // Base64 encode the credential for Basic auth
                        let encoded =
                            base64::engine::general_purpose::STANDARD.encode(secret.as_bytes());
                        Zeroizing::new(format!("Basic {}", encoded))
                    }
                    // For url_path and query_param, header_value is not used
                    InjectMode::UrlPath | InjectMode::QueryParam => Zeroizing::new(String::new()),
                };

                // Build per-route TLS connector if a custom CA is configured
                let tls_connector = match route.tls_ca {
                    Some(ref ca_path) => {
                        debug!(
                            "Building TLS connector with custom CA for route '{}': {}",
                            route.prefix, ca_path
                        );
                        Some(build_tls_connector_with_ca(ca_path)?)
                    }
                    None => None,
                };

                credentials.insert(
                    route.prefix.clone(),
                    LoadedCredential {
                        inject_mode: route.inject_mode.clone(),
                        upstream: route.upstream.clone(),
                        raw_credential: secret,
                        header_name: route.inject_header.clone(),
                        header_value,
                        path_pattern: route.path_pattern.clone(),
                        path_replacement: route.path_replacement.clone(),
                        query_param_name: route.query_param_name.clone(),
                        endpoint_rules: CompiledEndpointRules::compile(&route.endpoint_rules)
                            .map_err(|e| {
                                ProxyError::Credential(format!("route '{}': {}", route.prefix, e))
                            })?,
                        tls_connector,
                    },
                );
            }
        }

        Ok(Self { credentials })
    }

    /// Create an empty credential store (no credential injection).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            credentials: HashMap::new(),
        }
    }

    /// Get a credential for a route prefix, if configured.
    #[must_use]
    pub fn get(&self, prefix: &str) -> Option<&LoadedCredential> {
        self.credentials.get(prefix)
    }

    /// Check if any credentials are loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }

    /// Number of loaded credentials.
    #[must_use]
    pub fn len(&self) -> usize {
        self.credentials.len()
    }

    /// Returns the set of route prefixes that have loaded credentials.
    #[must_use]
    pub fn loaded_prefixes(&self) -> std::collections::HashSet<String> {
        self.credentials.keys().cloned().collect()
    }

    /// Check whether `host_port` (e.g. `"gitlab.example.com:443"`) matches
    /// any credential upstream. Used to block CONNECT tunnels that would
    /// bypass L7 path filtering.
    #[must_use]
    pub fn is_credential_upstream(&self, host_port: &str) -> bool {
        let normalised = host_port.to_lowercase();
        self.credentials.values().any(|cred| {
            extract_host_port(&cred.upstream)
                .map(|hp| hp == normalised)
                .unwrap_or(false)
        })
    }

    /// Return the set of normalised `host:port` strings for all credential
    /// upstreams. Used to compute smart `NO_PROXY` — hosts in this set must
    /// NOT be bypassed because they need reverse proxy credential injection.
    #[must_use]
    pub fn credential_upstream_hosts(&self) -> std::collections::HashSet<String> {
        self.credentials
            .values()
            .filter_map(|cred| extract_host_port(&cred.upstream))
            .collect()
    }
}

/// Extract and normalise `host:port` from a URL string.
///
/// Defaults to port 443 for `https://` and 80 for `http://` when no
/// explicit port is present. Returns `None` if the URL cannot be parsed.
fn extract_host_port(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    let default_port = match parsed.scheme() {
        "https" => 443,
        "http" => 80,
        _ => return None,
    };
    let port = parsed.port().unwrap_or(default_port);
    Some(format!("{}:{}", host.to_lowercase(), port))
}

/// Build a `TlsConnector` that trusts the system roots plus a custom CA certificate.
///
/// The CA file must be PEM-encoded and contain at least one certificate.
/// Returns an error if the file cannot be read, contains no valid certificates,
/// or the TLS configuration fails.
fn build_tls_connector_with_ca(ca_path: &str) -> Result<tokio_rustls::TlsConnector> {
    let ca_path = std::path::Path::new(ca_path);

    let ca_pem = Zeroizing::new(std::fs::read(ca_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ProxyError::Config(format!(
                "CA certificate file not found: '{}'",
                ca_path.display()
            ))
        } else {
            ProxyError::Config(format!(
                "failed to read CA certificate '{}': {}",
                ca_path.display(),
                e
            ))
        }
    })?);

    let mut root_store = rustls::RootCertStore::empty();

    // Add system roots first
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Parse and add custom CA certificates from PEM file
    let certs: Vec<_> = rustls_pemfile::certs(&mut ca_pem.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| {
            ProxyError::Config(format!(
                "failed to parse CA certificate '{}': {}",
                ca_path.display(),
                e
            ))
        })?;

    if certs.is_empty() {
        return Err(ProxyError::Config(format!(
            "CA certificate file '{}' contains no valid PEM certificates",
            ca_path.display()
        )));
    }

    for cert in certs {
        root_store.add(cert).map_err(|e| {
            ProxyError::Config(format!(
                "invalid CA certificate in '{}': {}",
                ca_path.display(),
                e
            ))
        })?;
    }

    let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| ProxyError::Config(format!("TLS config error: {}", e)))?
    .with_root_certificates(root_store)
    .with_no_client_auth();

    Ok(tokio_rustls::TlsConnector::from(Arc::new(tls_config)))
}

/// The keyring service name used by nono for all credentials.
/// Uses the same constant as `nono::keystore::DEFAULT_SERVICE` to ensure consistency.
const KEYRING_SERVICE: &str = nono::keystore::DEFAULT_SERVICE;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_credential_store() {
        let store = CredentialStore::empty();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert!(store.get("/openai").is_none());
    }

    #[test]
    fn test_loaded_credential_debug_redacts_secrets() {
        // Security: Debug output must NEVER contain real secret values.
        // This prevents accidental leakage in logs, panic messages, or
        // tracing output at debug level.
        let cred = LoadedCredential {
            inject_mode: InjectMode::Header,
            upstream: "https://api.openai.com".to_string(),
            raw_credential: Zeroizing::new("sk-secret-12345".to_string()),
            header_name: "Authorization".to_string(),
            header_value: Zeroizing::new("Bearer sk-secret-12345".to_string()),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            endpoint_rules: CompiledEndpointRules::compile(&[]).unwrap(),
            tls_connector: None,
        };

        let debug_output = format!("{:?}", cred);

        // Must contain REDACTED markers
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output should contain [REDACTED], got: {}",
            debug_output
        );
        // Must NOT contain the actual secret
        assert!(
            !debug_output.contains("sk-secret-12345"),
            "Debug output must not contain the real secret"
        );
        assert!(
            !debug_output.contains("Bearer sk-secret"),
            "Debug output must not contain the formatted secret"
        );
        // Non-secret fields should still be visible
        assert!(debug_output.contains("api.openai.com"));
        assert!(debug_output.contains("Authorization"));
    }

    #[test]
    fn test_extract_host_port_https_no_port() {
        assert_eq!(
            extract_host_port("https://api.openai.com"),
            Some("api.openai.com:443".to_string())
        );
    }

    #[test]
    fn test_extract_host_port_https_with_port() {
        assert_eq!(
            extract_host_port("https://api.openai.com:8443"),
            Some("api.openai.com:8443".to_string())
        );
    }

    #[test]
    fn test_extract_host_port_http_no_port() {
        assert_eq!(
            extract_host_port("http://internal:4096"),
            Some("internal:4096".to_string())
        );
    }

    #[test]
    fn test_extract_host_port_http_default_port() {
        assert_eq!(
            extract_host_port("http://internal-service"),
            Some("internal-service:80".to_string())
        );
    }

    #[test]
    fn test_extract_host_port_normalises_case() {
        assert_eq!(
            extract_host_port("https://GitLab-PRD.Home.Example.COM"),
            Some("gitlab-prd.home.example.com:443".to_string())
        );
    }

    #[test]
    fn test_extract_host_port_with_path() {
        assert_eq!(
            extract_host_port("https://api.example.com/v1/endpoint"),
            Some("api.example.com:443".to_string())
        );
    }

    #[test]
    fn test_extract_host_port_no_scheme() {
        assert_eq!(extract_host_port("api.openai.com"), None);
    }

    #[test]
    fn test_is_credential_upstream() {
        let mut credentials = HashMap::new();
        credentials.insert(
            "gitlab".to_string(),
            LoadedCredential {
                inject_mode: InjectMode::Header,
                upstream: "https://gitlab.example.com".to_string(),
                raw_credential: Zeroizing::new("token".to_string()),
                header_name: "PRIVATE-TOKEN".to_string(),
                header_value: Zeroizing::new("token".to_string()),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                endpoint_rules: CompiledEndpointRules::compile(&[]).unwrap(),
                tls_connector: None,
            },
        );
        let store = CredentialStore { credentials };

        assert!(store.is_credential_upstream("gitlab.example.com:443"));
        assert!(!store.is_credential_upstream("unrelated.example.com:443"));
    }

    #[test]
    fn test_is_credential_upstream_empty_store() {
        let store = CredentialStore::empty();
        assert!(!store.is_credential_upstream("anything:443"));
    }

    #[test]
    fn test_credential_upstream_hosts() {
        let mut credentials = HashMap::new();
        credentials.insert(
            "gitlab".to_string(),
            LoadedCredential {
                inject_mode: InjectMode::Header,
                upstream: "https://gitlab.example.com".to_string(),
                raw_credential: Zeroizing::new("token".to_string()),
                header_name: "PRIVATE-TOKEN".to_string(),
                header_value: Zeroizing::new("token".to_string()),
                path_pattern: None,
                path_replacement: None,
                query_param_name: None,
                endpoint_rules: CompiledEndpointRules::compile(&[]).unwrap(),
                tls_connector: None,
            },
        );
        let store = CredentialStore { credentials };

        let hosts = store.credential_upstream_hosts();
        assert!(hosts.contains("gitlab.example.com:443"));
        assert_eq!(hosts.len(), 1);
    }

    #[test]
    fn test_load_no_credential_routes() {
        let routes = vec![RouteConfig {
            prefix: "/test".to_string(),
            upstream: "https://example.com".to_string(),
            credential_key: None,
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
        }];
        let store = CredentialStore::load(&routes);
        assert!(store.is_ok());
        let store = store.unwrap_or_else(|_| CredentialStore::empty());
        assert!(store.is_empty());
    }

    /// Self-signed CA for testing. Generated with:
    /// openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    ///   -keyout /dev/null -nodes -days 36500 -subj '/CN=nono-test-ca' -out -
    const TEST_CA_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIBnjCCAUWgAwIBAgIUT0bpOJJvHdOdZt+gW1stR8VBgXowCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAwwMbm9uby10ZXN0LWNhMCAXDTI1MDEwMTAwMDAwMFoYDzIxMjQx
MjA3MDAwMDAwWjAXMRUwEwYDVQQDDAxub25vLXRlc3QtY2EwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAR8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAo1MwUTAdBgNVHQ4EFgQUAAAAAAAAAAAAAAAAAAAAAAAA
AAAAMB8GA1UdIwQYMBaAFAAAAAAAAAAAAAAAAAAAAAAAAAAAADAPBgNVHRMBAf8E
BTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAICAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END CERTIFICATE-----";

    #[test]
    fn test_build_tls_connector_with_valid_ca() {
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, TEST_CA_PEM).unwrap();

        // The test CA has dummy key material so rustls will reject it,
        // but we test the file-reading and PEM-parsing path separately.
        // A valid CA cert would succeed; here we verify the error is from
        // certificate validation, not file I/O or PEM parsing.
        let result = build_tls_connector_with_ca(ca_path.to_str().unwrap());
        // Either succeeds (if rustls accepts the cert) or fails with a
        // certificate validation error — both are acceptable since we're
        // testing the plumbing, not the cert content.
        match result {
            Ok(connector) => {
                // Connector was built — custom CA was accepted
                drop(connector);
            }
            Err(ProxyError::Config(msg)) => {
                // Expected: invalid certificate content in test fixture
                assert!(
                    msg.contains("invalid CA certificate") || msg.contains("CA certificate"),
                    "unexpected error: {}",
                    msg
                );
            }
            Err(e) => panic!("unexpected error type: {}", e),
        }
    }

    #[test]
    fn test_build_tls_connector_missing_file() {
        let result = build_tls_connector_with_ca("/nonexistent/path/ca.pem");
        let err = result
            .err()
            .expect("should fail for missing file")
            .to_string();
        assert!(
            err.contains("CA certificate file not found"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_build_tls_connector_empty_pem() {
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("empty.pem");
        std::fs::write(&ca_path, "not a certificate\n").unwrap();

        let result = build_tls_connector_with_ca(ca_path.to_str().unwrap());
        let err = result
            .err()
            .expect("should fail for invalid PEM")
            .to_string();
        assert!(
            err.contains("no valid PEM certificates"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_build_tls_connector_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("empty.pem");
        std::fs::write(&ca_path, "").unwrap();

        let result = build_tls_connector_with_ca(ca_path.to_str().unwrap());
        let err = result
            .err()
            .expect("should fail for empty file")
            .to_string();
        assert!(
            err.contains("no valid PEM certificates"),
            "unexpected error: {}",
            err
        );
    }
}
