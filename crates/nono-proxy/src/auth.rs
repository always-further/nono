// Adding a new auth mechanism: add a ManagedUpstreamAuth variant and implement
// acquire() for it. No handler files need to change.

use crate::error::{ProxyError, Result};
use std::sync::Arc;
use zeroize::Zeroizing;

/// What a single upstream request needs from the auth layer.
pub enum UpstreamAuthMaterial {
    /// mTLS: use the connector for the upstream TLS handshake.
    MtlsConnector {
        connector: tokio_rustls::TlsConnector,
        workload_spiffe_id: String,
        upstream_spiffe_id: Option<String>,
    },
    /// Bearer token: inject `{header}: Bearer {token}` into the request.
    BearerToken {
        header: String,
        token: Zeroizing<String>,
        workload_spiffe_id: String,
    },
}

impl UpstreamAuthMaterial {
    pub fn spiffe_audit_context(&self) -> nono::undo::SpiffeAuditContext {
        match self {
            UpstreamAuthMaterial::MtlsConnector {
                workload_spiffe_id,
                upstream_spiffe_id,
                ..
            } => nono::undo::SpiffeAuditContext {
                trust_domain: extract_trust_domain(workload_spiffe_id),
                workload_spiffe_id: workload_spiffe_id.clone(),
                svid_type: "x509".to_string(),
                source: "spire-workload-api".to_string(),
                upstream_spiffe_id: upstream_spiffe_id.clone(),
                delegation: None,
            },
            UpstreamAuthMaterial::BearerToken {
                workload_spiffe_id,
                token,
                ..
            } => nono::undo::SpiffeAuditContext {
                trust_domain: extract_trust_domain(workload_spiffe_id),
                workload_spiffe_id: workload_spiffe_id.clone(),
                svid_type: "jwt".to_string(),
                source: "spire-workload-api".to_string(),
                upstream_spiffe_id: None,
                delegation: crate::spiffe::delegation_from_jwt(token.as_str()),
            },
        }
    }
}

pub enum ManagedUpstreamAuth {
    SpiffeX509(Arc<crate::spiffe::SpiffeX509Source>),
    SpiffeJwt(Arc<crate::spiffe::SpiffeJwtSource>),
}

impl ManagedUpstreamAuth {
    /// Acquire the material needed for one upstream request.
    pub async fn acquire(&self) -> Result<UpstreamAuthMaterial> {
        match self {
            ManagedUpstreamAuth::SpiffeX509(src) => {
                if !src.is_available() {
                    return Err(ProxyError::Credential(
                        "SPIFFE X.509 source unavailable: Workload API stream terminated"
                            .to_string(),
                    ));
                }
                Ok(UpstreamAuthMaterial::MtlsConnector {
                    connector: src.tls_connector(),
                    workload_spiffe_id: src.spiffe_id(),
                    upstream_spiffe_id: src.expected_upstream_spiffe_id().map(str::to_string),
                })
            }
            ManagedUpstreamAuth::SpiffeJwt(src) => {
                let (token, spiffe_id) = src
                    .fetch_token(&src.audience)
                    .await
                    .map_err(|e| ProxyError::Credential(e.to_string()))?;
                Ok(UpstreamAuthMaterial::BearerToken {
                    header: src.inject_header.clone(),
                    token,
                    workload_spiffe_id: spiffe_id,
                })
            }
        }
    }

    pub fn audit_mechanism(&self) -> nono::undo::NetworkAuditAuthMechanism {
        match self {
            ManagedUpstreamAuth::SpiffeX509(_) => {
                nono::undo::NetworkAuditAuthMechanism::SpiffeX509Mtls
            }
            ManagedUpstreamAuth::SpiffeJwt(_) => {
                nono::undo::NetworkAuditAuthMechanism::SpiffeJwtBearer
            }
        }
    }

    pub fn audit_injection_mode(&self) -> Option<nono::undo::NetworkAuditInjectionMode> {
        match self {
            ManagedUpstreamAuth::SpiffeX509(_) => None,
            ManagedUpstreamAuth::SpiffeJwt(_) => {
                Some(nono::undo::NetworkAuditInjectionMode::SpiffeJwt)
            }
        }
    }
}

/// `spiffe://prod.example/workload` → `"prod.example"`.
/// Returns `""` and logs a warning for malformed IDs.
pub fn extract_trust_domain(spiffe_id: &str) -> String {
    match spiffe_id
        .strip_prefix("spiffe://")
        .and_then(|s| s.split('/').next())
    {
        Some(domain) => domain.to_string(),
        None => {
            tracing::warn!(
                "extract_trust_domain: malformed SPIFFE ID (missing spiffe:// prefix): \
                 audit trust_domain will be empty"
            );
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_trust_domain_valid() {
        assert_eq!(
            extract_trust_domain("spiffe://prod.example/workload"),
            "prod.example"
        );
    }

    #[test]
    fn extract_trust_domain_no_path() {
        assert_eq!(
            extract_trust_domain("spiffe://prod.example"),
            "prod.example"
        );
    }

    #[test]
    fn extract_trust_domain_invalid() {
        assert_eq!(extract_trust_domain("not-a-spiffe-id"), "");
    }

    #[test]
    fn extract_trust_domain_empty() {
        assert_eq!(extract_trust_domain(""), "");
    }
}
