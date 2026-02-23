//! Credential loading and management for reverse proxy mode.
//!
//! Loads API credentials from the system keystore at proxy startup.
//! Credentials are stored in `Zeroizing<String>` and injected as HTTP
//! headers on reverse proxy requests. The sandboxed agent never sees
//! the real credentials.

use crate::config::RouteConfig;
use crate::error::{ProxyError, Result};
use std::collections::HashMap;
use tracing::{debug, warn};
use zeroize::Zeroizing;

/// A loaded credential ready for injection.
#[derive(Debug)]
pub struct LoadedCredential {
    /// Header name to inject (e.g., "Authorization")
    pub header_name: String,
    /// Formatted header value (e.g., "Bearer sk-...")
    pub header_value: Zeroizing<String>,
    /// Upstream URL (e.g., "https://api.openai.com")
    pub upstream: String,
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
    /// Returns an error if any configured credential fails to load.
    pub fn load(routes: &[RouteConfig]) -> Result<Self> {
        let mut credentials = HashMap::new();

        for route in routes {
            if let Some(ref key) = route.credential_key {
                debug!("Loading credential for route prefix: {}", route.prefix);

                let secret = load_from_keyring(key)?;
                let formatted = route.credential_format.replace("{}", &secret);

                credentials.insert(
                    route.prefix.clone(),
                    LoadedCredential {
                        header_name: route.inject_header.clone(),
                        header_value: Zeroizing::new(formatted),
                        upstream: route.upstream.clone(),
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
}

/// Load a secret from the system keyring.
fn load_from_keyring(account: &str) -> Result<Zeroizing<String>> {
    let entry = keyring::Entry::new("nono-proxy", account).map_err(|e| {
        ProxyError::Credential(format!(
            "failed to create keyring entry for '{}': {}",
            account, e
        ))
    })?;

    match entry.get_password() {
        Ok(password) => Ok(Zeroizing::new(password)),
        Err(keyring::Error::NoEntry) => {
            warn!("No keyring entry found for account: {}", account);
            Err(ProxyError::Credential(format!(
                "secret not found in keyring for account '{}'",
                account
            )))
        }
        Err(e) => Err(ProxyError::Credential(format!(
            "failed to load secret for '{}': {}",
            account, e
        ))),
    }
}

#[cfg(test)]
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
    fn test_load_no_credential_routes() {
        let routes = vec![RouteConfig {
            prefix: "/test".to_string(),
            upstream: "https://example.com".to_string(),
            credential_key: None,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
        }];
        let store = CredentialStore::load(&routes);
        assert!(store.is_ok());
        let store = store.unwrap_or_else(|_| CredentialStore::empty());
        assert!(store.is_empty());
    }
}
