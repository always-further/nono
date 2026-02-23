//! Network policy resolver
//!
//! Parses `network-policy.json` and resolves named groups into flat host
//! lists and credential route configurations for the proxy.

use nono::{NonoError, Result};
use nono_proxy::config::{ProxyConfig, RouteConfig};
use serde::Deserialize;
use std::collections::HashMap;
use tracing::debug;

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

/// A network profile composing groups
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkProfileDef {
    pub groups: Vec<String>,
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
}

/// Load network policy from JSON string
pub fn load_network_policy(json: &str) -> Result<NetworkPolicy> {
    serde_json::from_str(json)
        .map_err(|e| NonoError::ConfigParse(format!("Failed to parse network-policy.json: {}", e)))
}

/// Resolve a network profile name into flat host lists and routes.
///
/// Merges all groups referenced by the profile into a single set of
/// allowed hosts and suffixes. Deduplicates entries.
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

    resolve_groups(policy, &profile.groups)
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
    })
}

/// Resolve credential definitions into proxy RouteConfig entries.
///
/// Only includes credentials whose service name is in the given list.
/// If `service_names` is empty, returns no routes (no credential injection).
pub fn resolve_credentials(policy: &NetworkPolicy, service_names: &[String]) -> Vec<RouteConfig> {
    if service_names.is_empty() {
        return Vec::new();
    }

    let mut routes = Vec::new();

    for (name, cred) in &policy.credentials {
        if !service_names.contains(name) {
            continue;
        }
        routes.push(RouteConfig {
            prefix: name.clone(),
            upstream: cred.upstream.clone(),
            credential_key: Some(cred.credential_key.clone()),
            inject_header: cred.inject_header.clone(),
            credential_format: cred.credential_format.clone(),
        });
    }

    routes
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
        let routes = resolve_credentials(&policy, &[]);
        assert!(routes.is_empty());
    }

    #[test]
    fn test_resolve_credentials_by_name() {
        let json = embedded_network_policy_json();
        let policy = load_network_policy(json).unwrap();
        let routes = resolve_credentials(&policy, &["openai".to_string(), "anthropic".to_string()]);
        assert!(!routes.is_empty());
        let openai_route = routes.iter().find(|r| r.prefix == "openai");
        assert!(openai_route.is_some());
        assert_eq!(openai_route.unwrap().upstream, "https://api.openai.com");
    }

    #[test]
    fn test_resolve_credentials_filtered() {
        let json = embedded_network_policy_json();
        let policy = load_network_policy(json).unwrap();
        let routes = resolve_credentials(&policy, &["openai".to_string()]);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, "openai");
    }

    #[test]
    fn test_build_proxy_config() {
        let resolved = ResolvedNetworkPolicy {
            hosts: vec!["api.openai.com".to_string()],
            suffixes: vec![".googleapis.com".to_string()],
            routes: vec![],
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
}
