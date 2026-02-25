//! Network policy resolver
//!
//! Parses `network-policy.json` and resolves named groups into flat host
//! lists and credential route configurations for the proxy.

use crate::profile::CustomCredentialDef;
use nono::{NonoError, Result};
use nono_proxy::config::{ProxyConfig, RouteConfig};
use serde::Deserialize;
use std::collections::HashMap;
use tracing::debug;
use url::Url;

// ============================================================================
// JSON schema types
// ============================================================================

/// Root network policy file structure
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkPolicy {
    #[allow(dead_code)]
    pub meta: NetworkPolicyMeta,
    pub groups: HashMap<String, NetworkGroup>,
    #[serde(default)]
    pub profiles: HashMap<String, NetworkProfileDef>,
    #[serde(default)]
    pub credentials: HashMap<String, CredentialDef>,
}

/// Network policy metadata
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkPolicyMeta {
    #[allow(dead_code)]
    pub version: u64,
    #[allow(dead_code)]
    pub schema_version: String,
}

/// A named group of allowed hosts
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkGroup {
    #[allow(dead_code)]
    pub description: String,
    /// Exact hostname matches
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Wildcard suffix matches (e.g., ".googleapis.com")
    #[serde(default)]
    pub suffixes: Vec<String>,
}

/// A network profile composing groups and optional credentials
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkProfileDef {
    pub groups: Vec<String>,
    /// Credential services to automatically enable with this profile
    #[serde(default)]
    pub credentials: Vec<String>,
}

/// A credential route definition
#[derive(Debug, Clone, Deserialize)]
pub struct CredentialDef {
    pub upstream: String,
    pub credential_key: String,
    #[serde(default = "default_inject_header")]
    pub inject_header: String,
    #[serde(default = "default_credential_format")]
    pub credential_format: String,
}

fn default_inject_header() -> String {
    "Authorization".to_string()
}

fn default_credential_format() -> String {
    "Bearer {}".to_string()
}

// ============================================================================
// Resolution
// ============================================================================

/// Resolved network policy: flat host lists and credential routes
#[derive(Debug, Clone)]
pub struct ResolvedNetworkPolicy {
    /// All allowed hostnames (exact match)
    pub hosts: Vec<String>,
    /// All allowed hostname suffixes (wildcard match)
    pub suffixes: Vec<String>,
    /// Credential routes for reverse proxy mode
    pub routes: Vec<RouteConfig>,
    /// Credential service names from the profile (to be resolved later)
    pub profile_credentials: Vec<String>,
}

/// Load network policy from JSON string
pub fn load_network_policy(json: &str) -> Result<NetworkPolicy> {
    serde_json::from_str(json)
        .map_err(|e| NonoError::ConfigParse(format!("Failed to parse network-policy.json: {}", e)))
}

/// Resolve a network profile name into flat host lists and routes.
///
/// Merges all groups referenced by the profile into a single set of
/// allowed hosts and suffixes. Deduplicates entries. Also returns
/// any credentials bundled with the profile.
pub fn resolve_network_profile(
    policy: &NetworkPolicy,
    profile_name: &str,
) -> Result<ResolvedNetworkPolicy> {
    let profile = policy.profiles.get(profile_name).ok_or_else(|| {
        NonoError::ConfigParse(format!(
            "Network profile '{}' not found in policy",
            profile_name
        ))
    })?;

    let mut resolved = resolve_groups(policy, &profile.groups)?;
    resolved.profile_credentials = profile.credentials.clone();
    Ok(resolved)
}

/// Resolve a list of group names into flat host lists.
pub fn resolve_groups(
    policy: &NetworkPolicy,
    group_names: &[String],
) -> Result<ResolvedNetworkPolicy> {
    let mut hosts = Vec::new();
    let mut suffixes = Vec::new();

    for name in group_names {
        let group = policy.groups.get(name).ok_or_else(|| {
            NonoError::ConfigParse(format!("Network group '{}' not found in policy", name))
        })?;
        debug!(
            "Resolving network group: {} ({} hosts, {} suffixes)",
            name,
            group.hosts.len(),
            group.suffixes.len()
        );
        hosts.extend(group.hosts.clone());
        suffixes.extend(group.suffixes.clone());
    }

    // Deduplicate
    hosts.sort();
    hosts.dedup();
    suffixes.sort();
    suffixes.dedup();

    Ok(ResolvedNetworkPolicy {
        hosts,
        suffixes,
        routes: Vec::new(),
        profile_credentials: Vec::new(),
    })
}

/// Check if a host string represents a loopback address.
///
/// Accepts:
/// - `localhost`
/// - `127.x.x.x` (full 127.0.0.0/8 CIDR range)
/// - `::1` (IPv6 loopback)
/// - `0.0.0.0` (binds to all interfaces, commonly used for local dev servers)
fn is_loopback_host(host: &str) -> bool {
    if host == "localhost" || host == "::1" || host == "0.0.0.0" {
        return true;
    }

    // Check 127.0.0.0/8 CIDR range
    if let Some(rest) = host.strip_prefix("127.") {
        // Validate remaining octets are valid IPv4
        let parts: Vec<&str> = rest.split('.').collect();
        if parts.len() == 3 {
            return parts.iter().all(|p| p.parse::<u8>().is_ok());
        }
    }

    false
}

/// Validate an upstream URL for security.
///
/// Ensures the URL is HTTPS, or HTTP only for loopback addresses (for local development).
/// This prevents credential injection to arbitrary HTTP endpoints.
fn validate_upstream_url(url: &str, service_name: &str) -> Result<()> {
    let parsed = Url::parse(url).map_err(|e| {
        NonoError::ConfigParse(format!(
            "Invalid upstream URL for credential '{}': {}",
            service_name, e
        ))
    })?;

    match parsed.scheme() {
        "https" => Ok(()),
        "http" => {
            // Allow HTTP only for loopback addresses
            let host = parsed.host_str().unwrap_or("");
            if is_loopback_host(host) {
                Ok(())
            } else {
                Err(NonoError::ConfigParse(format!(
                    "Upstream URL for credential '{}' must use HTTPS (HTTP only allowed for loopback addresses): {}",
                    service_name, url
                )))
            }
        }
        scheme => Err(NonoError::ConfigParse(format!(
            "Upstream URL for credential '{}' must use HTTPS, got scheme '{}': {}",
            service_name, scheme, url
        ))),
    }
}

/// Check if a character is a valid HTTP token character per RFC 7230.
///
/// token = 1*tchar
/// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
///         "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
fn is_http_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '!' | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '.'
                | '^'
                | '_'
                | '`'
                | '|'
                | '~'
        )
}

/// Validate an HTTP header name for RFC 7230 compliance.
///
/// Header names must be valid HTTP tokens: non-empty strings containing only
/// tchar characters (alphanumeric + specific punctuation). This prevents
/// header injection attacks via control characters.
fn validate_inject_header(header: &str, service_name: &str) -> Result<()> {
    if header.is_empty() {
        return Err(NonoError::ConfigParse(format!(
            "inject_header for service '{}' cannot be empty",
            service_name
        )));
    }

    if !header.chars().all(is_http_token_char) {
        return Err(NonoError::ConfigParse(format!(
            "inject_header '{}' for service '{}' contains invalid characters; \
             header names must be valid HTTP tokens (alphanumeric and !#$%&'*+-.^_`|~)",
            header, service_name
        )));
    }

    Ok(())
}

/// Validate a credential format string for injection safety.
///
/// Rejects format strings containing CRLF sequences (\r, \n) which could
/// enable header injection attacks. The `{}` placeholder will be replaced
/// with the actual credential value.
fn validate_credential_format(format: &str, service_name: &str) -> Result<()> {
    if format.contains('\r') || format.contains('\n') {
        return Err(NonoError::ConfigParse(format!(
            "credential_format for service '{}' contains invalid CRLF characters; \
             this could enable header injection attacks",
            service_name
        )));
    }

    Ok(())
}

/// Validate a credential key name for security.
///
/// Ensures the key contains only alphanumeric characters and underscores,
/// which are valid for keystore account names.
fn validate_credential_key(key: &str, service_name: &str) -> Result<()> {
    if key.is_empty() {
        return Err(NonoError::ConfigParse(format!(
            "Credential key for service '{}' cannot be empty",
            service_name
        )));
    }

    if !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(NonoError::ConfigParse(format!(
            "Credential key '{}' for service '{}' must contain only alphanumeric characters and underscores",
            key, service_name
        )));
    }

    Ok(())
}

/// Resolve credential definitions into proxy RouteConfig entries.
///
/// Merges custom credentials from the profile with built-in credentials from
/// the network policy. Custom credentials take precedence (allowing overrides).
///
/// Only includes credentials whose service name is in the given list.
/// If `service_names` is empty, returns no routes (no credential injection).
///
/// Returns an error if any requested service name is not defined in either
/// the custom credentials or the built-in policy.
pub fn resolve_credentials(
    policy: &NetworkPolicy,
    service_names: &[String],
    custom_credentials: &HashMap<String, CustomCredentialDef>,
) -> Result<Vec<RouteConfig>> {
    if service_names.is_empty() {
        return Ok(Vec::new());
    }

    // Validate all requested services exist in either custom or built-in
    for name in service_names {
        if !custom_credentials.contains_key(name) && !policy.credentials.contains_key(name) {
            let mut available: Vec<_> = policy.credentials.keys().cloned().collect();
            available.extend(custom_credentials.keys().cloned());
            available.sort();
            available.dedup();
            return Err(NonoError::ConfigParse(format!(
                "Unknown credential service '{}'. Available: {:?}",
                name, available
            )));
        }
    }

    let mut routes = Vec::new();

    for name in service_names {
        // Custom credentials take precedence over built-in
        if let Some(cred) = custom_credentials.get(name) {
            // Validate custom credential definition
            validate_upstream_url(&cred.upstream, name)?;
            validate_credential_key(&cred.credential_key, name)?;
            validate_inject_header(&cred.inject_header, name)?;
            validate_credential_format(&cred.credential_format, name)?;

            routes.push(RouteConfig {
                prefix: name.clone(),
                upstream: cred.upstream.clone(),
                credential_key: Some(cred.credential_key.clone()),
                inject_header: cred.inject_header.clone(),
                credential_format: cred.credential_format.clone(),
            });
        } else if let Some(cred) = policy.credentials.get(name) {
            routes.push(RouteConfig {
                prefix: name.clone(),
                upstream: cred.upstream.clone(),
                credential_key: Some(cred.credential_key.clone()),
                inject_header: cred.inject_header.clone(),
                credential_format: cred.credential_format.clone(),
            });
        }
        // We already validated existence above, so this else branch won't be hit
    }

    Ok(routes)
}

/// Build a complete `ProxyConfig` from a resolved network policy.
///
/// Combines resolved hosts/suffixes with credential routes and optional
/// CLI overrides (extra hosts).
pub fn build_proxy_config(resolved: &ResolvedNetworkPolicy, extra_hosts: &[String]) -> ProxyConfig {
    let mut allowed_hosts = resolved.hosts.clone();
    // Convert suffixes to wildcard format for the proxy filter
    for suffix in &resolved.suffixes {
        let wildcard = if suffix.starts_with('.') {
            format!("*{}", suffix)
        } else {
            format!("*.{}", suffix)
        };
        allowed_hosts.push(wildcard);
    }
    // Add CLI override hosts
    allowed_hosts.extend(extra_hosts.iter().cloned());

    ProxyConfig {
        allowed_hosts,
        routes: resolved.routes.clone(),
        ..Default::default()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::embedded::embedded_network_policy_json;

    #[test]
    fn test_load_embedded_network_policy() {
        let json = embedded_network_policy_json();
        let policy = load_network_policy(json).unwrap();
        assert!(!policy.groups.is_empty());
        assert!(!policy.profiles.is_empty());
    }

    #[test]
    fn test_resolve_claude_code_profile() {
        let json = embedded_network_policy_json();
        let policy = load_network_policy(json).unwrap();
        let resolved = resolve_network_profile(&policy, "claude-code").unwrap();
        assert!(!resolved.hosts.is_empty());
        // Should include known LLM API hosts
        assert!(resolved.hosts.contains(&"api.openai.com".to_string()));
        assert!(resolved.hosts.contains(&"api.anthropic.com".to_string()));
    }

    #[test]
    fn test_resolve_minimal_profile() {
        let json = embedded_network_policy_json();
        let policy = load_network_policy(json).unwrap();
        let resolved = resolve_network_profile(&policy, "minimal").unwrap();
        // Minimal only has llm_apis
        assert!(resolved.hosts.contains(&"api.openai.com".to_string()));
        // Should not have package registries
        assert!(!resolved.hosts.contains(&"registry.npmjs.org".to_string()));
    }

    #[test]
    fn test_resolve_nonexistent_profile() {
        let json = embedded_network_policy_json();
        let policy = load_network_policy(json).unwrap();
        assert!(resolve_network_profile(&policy, "nonexistent").is_err());
    }

    #[test]
    fn test_resolve_enterprise_has_suffixes() {
        let json = embedded_network_policy_json();
        let policy = load_network_policy(json).unwrap();
        let resolved = resolve_network_profile(&policy, "enterprise").unwrap();
        assert!(!resolved.suffixes.is_empty());
        assert!(resolved.suffixes.contains(&".googleapis.com".to_string()));
    }

    #[test]
    fn test_resolve_credentials_empty_returns_none() {
        let json = embedded_network_policy_json();
        let policy = load_network_policy(json).unwrap();
        // Empty service list = no credential injection
        let routes = resolve_credentials(&policy, &[], &HashMap::new()).unwrap();
        assert!(routes.is_empty());
    }

    #[test]
    fn test_resolve_credentials_by_name() {
        let json = embedded_network_policy_json();
        let policy = load_network_policy(json).unwrap();
        let routes = resolve_credentials(
            &policy,
            &["openai".to_string(), "anthropic".to_string()],
            &HashMap::new(),
        )
        .unwrap();
        assert!(!routes.is_empty());
        let openai_route = routes.iter().find(|r| r.prefix == "openai");
        assert!(openai_route.is_some());
        assert_eq!(openai_route.unwrap().upstream, "https://api.openai.com/v1");
    }

    #[test]
    fn test_resolve_credentials_filtered() {
        let json = embedded_network_policy_json();
        let policy = load_network_policy(json).unwrap();
        let routes =
            resolve_credentials(&policy, &["openai".to_string()], &HashMap::new()).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, "openai");
    }

    #[test]
    fn test_resolve_credentials_unknown_service_fails() {
        let json = embedded_network_policy_json();
        let policy = load_network_policy(json).unwrap();
        let result = resolve_credentials(
            &policy,
            &["nonexistent_service".to_string()],
            &HashMap::new(),
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("nonexistent_service"));
        assert!(err.contains("Unknown credential service"));
    }

    #[test]
    fn test_resolve_credentials_with_custom() {
        use crate::profile::CustomCredentialDef;

        let json = embedded_network_policy_json();
        let policy = load_network_policy(json).unwrap();

        let mut custom = HashMap::new();
        custom.insert(
            "telegram".to_string(),
            CustomCredentialDef {
                upstream: "https://api.telegram.org".to_string(),
                credential_key: "telegram_bot_token".to_string(),
                inject_header: "Authorization".to_string(),
                credential_format: "Bearer {}".to_string(),
            },
        );

        let routes = resolve_credentials(&policy, &["telegram".to_string()], &custom).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, "telegram");
        assert_eq!(routes[0].upstream, "https://api.telegram.org");
        assert_eq!(
            routes[0].credential_key,
            Some("telegram_bot_token".to_string())
        );
    }

    #[test]
    fn test_resolve_credentials_custom_overrides_builtin() {
        use crate::profile::CustomCredentialDef;

        let json = embedded_network_policy_json();
        let policy = load_network_policy(json).unwrap();

        // Override built-in openai with custom definition
        let mut custom = HashMap::new();
        custom.insert(
            "openai".to_string(),
            CustomCredentialDef {
                upstream: "https://my-proxy.example.com/openai".to_string(),
                credential_key: "my_openai_key".to_string(),
                inject_header: "X-Custom-Auth".to_string(),
                credential_format: "Token {}".to_string(),
            },
        );

        let routes = resolve_credentials(&policy, &["openai".to_string()], &custom).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].upstream, "https://my-proxy.example.com/openai");
        assert_eq!(routes[0].credential_key, Some("my_openai_key".to_string()));
        assert_eq!(routes[0].inject_header, "X-Custom-Auth");
    }

    #[test]
    fn test_resolve_credentials_mixed_custom_and_builtin() {
        use crate::profile::CustomCredentialDef;

        let json = embedded_network_policy_json();
        let policy = load_network_policy(json).unwrap();

        let mut custom = HashMap::new();
        custom.insert(
            "telegram".to_string(),
            CustomCredentialDef {
                upstream: "https://api.telegram.org".to_string(),
                credential_key: "telegram_bot_token".to_string(),
                inject_header: "Authorization".to_string(),
                credential_format: "Bearer {}".to_string(),
            },
        );

        // Request both custom and built-in
        let routes = resolve_credentials(
            &policy,
            &["openai".to_string(), "telegram".to_string()],
            &custom,
        )
        .unwrap();

        assert_eq!(routes.len(), 2);

        let openai = routes.iter().find(|r| r.prefix == "openai").unwrap();
        assert_eq!(openai.upstream, "https://api.openai.com/v1"); // built-in

        let telegram = routes.iter().find(|r| r.prefix == "telegram").unwrap();
        assert_eq!(telegram.upstream, "https://api.telegram.org"); // custom
    }

    #[test]
    fn test_custom_credential_http_localhost_allowed() {
        use crate::profile::CustomCredentialDef;

        let json = embedded_network_policy_json();
        let policy = load_network_policy(json).unwrap();

        let mut custom = HashMap::new();
        custom.insert(
            "local".to_string(),
            CustomCredentialDef {
                upstream: "http://localhost:8080/api".to_string(),
                credential_key: "local_api_key".to_string(),
                inject_header: "Authorization".to_string(),
                credential_format: "Bearer {}".to_string(),
            },
        );

        let routes = resolve_credentials(&policy, &["local".to_string()], &custom).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].upstream, "http://localhost:8080/api");
    }

    #[test]
    fn test_custom_credential_http_remote_rejected() {
        use crate::profile::CustomCredentialDef;

        let json = embedded_network_policy_json();
        let policy = load_network_policy(json).unwrap();

        let mut custom = HashMap::new();
        custom.insert(
            "insecure".to_string(),
            CustomCredentialDef {
                upstream: "http://api.example.com".to_string(), // HTTP to remote host
                credential_key: "api_key".to_string(),
                inject_header: "Authorization".to_string(),
                credential_format: "Bearer {}".to_string(),
            },
        );

        let result = resolve_credentials(&policy, &["insecure".to_string()], &custom);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("HTTPS"));
        assert!(err.contains("insecure"));
    }

    #[test]
    fn test_custom_credential_invalid_key_rejected() {
        use crate::profile::CustomCredentialDef;

        let json = embedded_network_policy_json();
        let policy = load_network_policy(json).unwrap();

        let mut custom = HashMap::new();
        custom.insert(
            "bad".to_string(),
            CustomCredentialDef {
                upstream: "https://api.example.com".to_string(),
                credential_key: "bad-key-with-dashes".to_string(), // Invalid: contains dashes
                inject_header: "Authorization".to_string(),
                credential_format: "Bearer {}".to_string(),
            },
        );

        let result = resolve_credentials(&policy, &["bad".to_string()], &custom);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("alphanumeric"));
    }

    #[test]
    fn test_build_proxy_config() {
        let resolved = ResolvedNetworkPolicy {
            hosts: vec!["api.openai.com".to_string()],
            suffixes: vec![".googleapis.com".to_string()],
            routes: vec![],
            profile_credentials: vec![],
        };
        let config = build_proxy_config(&resolved, &["extra.example.com".to_string()]);
        assert!(config.allowed_hosts.contains(&"api.openai.com".to_string()));
        assert!(config
            .allowed_hosts
            .contains(&"*.googleapis.com".to_string()));
        assert!(config
            .allowed_hosts
            .contains(&"extra.example.com".to_string()));
    }

    #[test]
    fn test_deduplication() {
        let json = r#"{
            "meta": { "version": 1, "schema_version": "1.0" },
            "groups": {
                "a": { "description": "A", "hosts": ["foo.com", "bar.com"] },
                "b": { "description": "B", "hosts": ["bar.com", "baz.com"] }
            },
            "profiles": {},
            "credentials": {}
        }"#;
        let policy = load_network_policy(json).unwrap();
        let resolved = resolve_groups(&policy, &["a".to_string(), "b".to_string()]).unwrap();
        // bar.com should appear only once
        assert_eq!(resolved.hosts.iter().filter(|h| *h == "bar.com").count(), 1);
        assert_eq!(resolved.hosts.len(), 3);
    }

    // ============================================================================
    // Loopback host detection tests
    // ============================================================================

    #[test]
    fn test_is_loopback_host_localhost() {
        assert!(is_loopback_host("localhost"));
    }

    #[test]
    fn test_is_loopback_host_127_0_0_1() {
        assert!(is_loopback_host("127.0.0.1"));
    }

    #[test]
    fn test_is_loopback_host_127_cidr_range() {
        // Various addresses in 127.0.0.0/8
        assert!(is_loopback_host("127.0.0.2"));
        assert!(is_loopback_host("127.1.2.3"));
        assert!(is_loopback_host("127.255.255.255"));
    }

    #[test]
    fn test_is_loopback_host_ipv6_loopback() {
        assert!(is_loopback_host("::1"));
    }

    #[test]
    fn test_is_loopback_host_0_0_0_0() {
        assert!(is_loopback_host("0.0.0.0"));
    }

    #[test]
    fn test_is_loopback_host_rejects_remote() {
        assert!(!is_loopback_host("example.com"));
        assert!(!is_loopback_host("192.168.1.1"));
        assert!(!is_loopback_host("10.0.0.1"));
        assert!(!is_loopback_host("8.8.8.8"));
    }

    #[test]
    fn test_is_loopback_host_rejects_invalid_127() {
        // Invalid octets
        assert!(!is_loopback_host("127.0.0.256"));
        assert!(!is_loopback_host("127.0.0"));
        assert!(!is_loopback_host("127.0.0.0.0"));
        assert!(!is_loopback_host("127.abc.0.1"));
    }

    #[test]
    fn test_custom_credential_http_127_cidr_allowed() {
        use crate::profile::CustomCredentialDef;

        let json = embedded_network_policy_json();
        let policy = load_network_policy(json).unwrap();

        let mut custom = HashMap::new();
        custom.insert(
            "local".to_string(),
            CustomCredentialDef {
                upstream: "http://127.1.2.3:8080/api".to_string(),
                credential_key: "local_api_key".to_string(),
                inject_header: "Authorization".to_string(),
                credential_format: "Bearer {}".to_string(),
            },
        );

        let routes = resolve_credentials(&policy, &["local".to_string()], &custom).unwrap();
        assert_eq!(routes.len(), 1);
    }

    #[test]
    fn test_custom_credential_http_0_0_0_0_allowed() {
        use crate::profile::CustomCredentialDef;

        let json = embedded_network_policy_json();
        let policy = load_network_policy(json).unwrap();

        let mut custom = HashMap::new();
        custom.insert(
            "local".to_string(),
            CustomCredentialDef {
                upstream: "http://0.0.0.0:3000/api".to_string(),
                credential_key: "local_api_key".to_string(),
                inject_header: "Authorization".to_string(),
                credential_format: "Bearer {}".to_string(),
            },
        );

        let routes = resolve_credentials(&policy, &["local".to_string()], &custom).unwrap();
        assert_eq!(routes.len(), 1);
    }

    // ============================================================================
    // inject_header validation tests (RFC 7230)
    // ============================================================================

    #[test]
    fn test_validate_inject_header_valid() {
        assert!(validate_inject_header("Authorization", "test").is_ok());
        assert!(validate_inject_header("X-Api-Key", "test").is_ok());
        assert!(validate_inject_header("x-custom-header", "test").is_ok());
        assert!(validate_inject_header("Content-Type", "test").is_ok());
    }

    #[test]
    fn test_validate_inject_header_valid_special_chars() {
        // RFC 7230 tchar: !#$%&'*+-.^_`|~
        assert!(validate_inject_header("X-Header!", "test").is_ok());
        assert!(validate_inject_header("X#Header", "test").is_ok());
        assert!(validate_inject_header("X$Header", "test").is_ok());
        assert!(validate_inject_header("X%Header", "test").is_ok());
        assert!(validate_inject_header("X&Header", "test").is_ok());
        assert!(validate_inject_header("X'Header", "test").is_ok());
        assert!(validate_inject_header("X*Header", "test").is_ok());
        assert!(validate_inject_header("X+Header", "test").is_ok());
        assert!(validate_inject_header("X-Header", "test").is_ok());
        assert!(validate_inject_header("X.Header", "test").is_ok());
        assert!(validate_inject_header("X^Header", "test").is_ok());
        assert!(validate_inject_header("X_Header", "test").is_ok());
        assert!(validate_inject_header("X`Header", "test").is_ok());
        assert!(validate_inject_header("X|Header", "test").is_ok());
        assert!(validate_inject_header("X~Header", "test").is_ok());
    }

    #[test]
    fn test_validate_inject_header_empty_rejected() {
        let result = validate_inject_header("", "test");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot be empty"));
    }

    #[test]
    fn test_validate_inject_header_control_chars_rejected() {
        let result = validate_inject_header("X-Header\r\nEvil: injected", "test");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid characters"));
    }

    #[test]
    fn test_validate_inject_header_space_rejected() {
        let result = validate_inject_header("X Header", "test");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid characters"));
    }

    #[test]
    fn test_validate_inject_header_colon_rejected() {
        let result = validate_inject_header("X-Header:", "test");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid characters"));
    }

    #[test]
    fn test_validate_inject_header_parentheses_rejected() {
        let result = validate_inject_header("X-Header()", "test");
        assert!(result.is_err());
    }

    // ============================================================================
    // credential_format validation tests (CRLF injection)
    // ============================================================================

    #[test]
    fn test_validate_credential_format_valid() {
        assert!(validate_credential_format("Bearer {}", "test").is_ok());
        assert!(validate_credential_format("Token {}", "test").is_ok());
        assert!(validate_credential_format("{}", "test").is_ok());
        assert!(validate_credential_format("Basic {}", "test").is_ok());
        assert!(validate_credential_format("ApiKey={}", "test").is_ok());
    }

    #[test]
    fn test_validate_credential_format_cr_rejected() {
        let result = validate_credential_format("Bearer {}\rEvil: header", "test");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("CRLF"));
    }

    #[test]
    fn test_validate_credential_format_lf_rejected() {
        let result = validate_credential_format("Bearer {}\nEvil: header", "test");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("CRLF"));
    }

    #[test]
    fn test_validate_credential_format_crlf_rejected() {
        let result = validate_credential_format("Bearer {}\r\nEvil: header", "test");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("CRLF"));
    }

    // ============================================================================
    // Integration tests for full validation chain
    // ============================================================================

    #[test]
    fn test_custom_credential_invalid_header_rejected() {
        use crate::profile::CustomCredentialDef;

        let json = embedded_network_policy_json();
        let policy = load_network_policy(json).unwrap();

        let mut custom = HashMap::new();
        custom.insert(
            "bad".to_string(),
            CustomCredentialDef {
                upstream: "https://api.example.com".to_string(),
                credential_key: "api_key".to_string(),
                inject_header: "X-Header\r\nEvil: injected".to_string(), // CRLF injection attempt
                credential_format: "Bearer {}".to_string(),
            },
        );

        let result = resolve_credentials(&policy, &["bad".to_string()], &custom);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid characters"));
    }

    #[test]
    fn test_custom_credential_invalid_format_rejected() {
        use crate::profile::CustomCredentialDef;

        let json = embedded_network_policy_json();
        let policy = load_network_policy(json).unwrap();

        let mut custom = HashMap::new();
        custom.insert(
            "bad".to_string(),
            CustomCredentialDef {
                upstream: "https://api.example.com".to_string(),
                credential_key: "api_key".to_string(),
                inject_header: "Authorization".to_string(),
                credential_format: "Bearer {}\r\nEvil: injected".to_string(), // CRLF injection attempt
            },
        );

        let result = resolve_credentials(&policy, &["bad".to_string()], &custom);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("CRLF"));
    }
}
