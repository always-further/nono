//! Proxy configuration types.
//!
//! Defines the configuration for the proxy server, including allowed hosts,
//! credential routes, and external proxy settings.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Configuration for the proxy server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Bind address (default: 127.0.0.1)
    #[serde(default = "default_bind_addr")]
    pub bind_addr: IpAddr,

    /// Bind port (0 = OS-assigned ephemeral port)
    #[serde(default)]
    pub bind_port: u16,

    /// Allowed hosts for CONNECT mode (exact match + wildcards).
    /// Empty = allow all hosts (except deny list).
    #[serde(default)]
    pub allowed_hosts: Vec<String>,

    /// Additional CIDR ranges to deny (on top of built-in defaults).
    #[serde(default)]
    pub deny_cidrs: Vec<IpNet>,

    /// Reverse proxy credential routes.
    #[serde(default)]
    pub routes: Vec<RouteConfig>,

    /// External (enterprise) proxy URL for passthrough mode.
    /// When set, CONNECT requests are chained to this proxy.
    #[serde(default)]
    pub external_proxy: Option<ExternalProxyConfig>,

    /// Maximum concurrent connections (0 = unlimited).
    #[serde(default)]
    pub max_connections: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_bind_addr(),
            bind_port: 0,
            allowed_hosts: Vec::new(),
            deny_cidrs: Vec::new(),
            routes: Vec::new(),
            external_proxy: None,
            max_connections: 256,
        }
    }
}

fn default_bind_addr() -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
}

/// Configuration for a reverse proxy credential route.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// Path prefix for routing (e.g., "/openai")
    pub prefix: String,

    /// Upstream URL to forward to (e.g., "https://api.openai.com")
    pub upstream: String,

    /// Keystore account name to load the credential from.
    /// If `None`, no credential is injected.
    pub credential_key: Option<String>,

    /// HTTP header name for the credential (default: "Authorization")
    #[serde(default = "default_inject_header")]
    pub inject_header: String,

    /// Format string for the credential value. `{}` is replaced with the secret.
    /// Default: "Bearer {}"
    #[serde(default = "default_credential_format")]
    pub credential_format: String,
}

fn default_inject_header() -> String {
    "Authorization".to_string()
}

fn default_credential_format() -> String {
    "Bearer {}".to_string()
}

/// Configuration for an external (enterprise) proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalProxyConfig {
    /// Proxy address (e.g., "squid.corp.internal:3128")
    pub address: String,

    /// Optional authentication for the external proxy.
    pub auth: Option<ExternalProxyAuth>,
}

/// Authentication for an external proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalProxyAuth {
    /// Keystore account name for proxy credentials.
    pub keyring_account: String,

    /// Authentication scheme (only "basic" supported).
    #[serde(default = "default_auth_scheme")]
    pub scheme: String,
}

fn default_auth_scheme() -> String {
    "basic".to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ProxyConfig::default();
        assert_eq!(config.bind_addr, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        assert_eq!(config.bind_port, 0);
        assert!(config.allowed_hosts.is_empty());
        assert!(config.routes.is_empty());
        assert!(config.external_proxy.is_none());
    }

    #[test]
    fn test_config_serialization() {
        let config = ProxyConfig {
            allowed_hosts: vec!["api.openai.com".to_string()],
            ..Default::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ProxyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.allowed_hosts, vec!["api.openai.com"]);
    }
}
