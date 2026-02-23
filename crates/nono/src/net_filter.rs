//! Network host filtering for proxy-level domain and CIDR matching.
//!
//! This module provides application-layer host filtering that complements
//! the OS-level port restrictions from [`CapabilitySet`](crate::CapabilitySet).
//! The proxy uses [`HostFilter`] to decide whether to allow or deny CONNECT
//! requests based on hostname allowlists and CIDR deny ranges.
//!
//! # Security Properties
//!
//! - **Default deny list is hardcoded and non-overridable**: Cloud metadata
//!   endpoints, RFC1918 private networks, link-local, and loopback ranges
//!   are always denied regardless of allowlist configuration.
//! - **DNS rebinding protection**: Callers resolve DNS first and pass resolved
//!   IPs; the filter checks all resolved IPs against deny CIDRs before
//!   checking the hostname allowlist.
//! - **Wildcard subdomain matching**: `*.googleapis.com` matches
//!   `storage.googleapis.com` but not `googleapis.com` itself.

use ipnet::IpNet;
use std::net::IpAddr;

/// Result of a host filter check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterResult {
    /// Host is allowed by the allowlist
    Allow,
    /// Host is denied because it matches a CIDR deny range
    DenyCidr {
        /// The resolved IP that matched a deny range
        ip: IpAddr,
        /// The CIDR range that matched
        cidr: IpNet,
    },
    /// Host is denied because a specific hostname is in the deny list
    DenyHost {
        /// The hostname that was denied
        host: String,
    },
    /// Host is not in the allowlist (default deny)
    DenyNotAllowed {
        /// The hostname that was not found in any allowlist
        host: String,
    },
}

impl FilterResult {
    /// Whether the result is an allow decision
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, FilterResult::Allow)
    }

    /// A human-readable reason for the decision
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            FilterResult::Allow => "allowed by host filter".to_string(),
            FilterResult::DenyCidr { ip, cidr } => {
                format!("resolved IP {} matches denied CIDR {}", ip, cidr)
            }
            FilterResult::DenyHost { host } => {
                format!("host {} is in the deny list", host)
            }
            FilterResult::DenyNotAllowed { host } => {
                format!("host {} is not in the allowlist", host)
            }
        }
    }
}

/// Hosts that are always denied regardless of allowlist configuration.
/// These are cloud metadata endpoints commonly targeted for SSRF attacks.
const DENY_HOSTS: &[&str] = &[
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.azure.internal",
];

/// CIDR ranges that are always denied regardless of allowlist configuration.
/// Includes RFC1918 private networks, link-local, loopback, and IPv6 equivalents.
fn default_deny_cidrs() -> Vec<IpNet> {
    // These are all well-known CIDR ranges; parse failures would be a programming error.
    let ranges = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "127.0.0.0/8",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    ];
    ranges
        .iter()
        .filter_map(|s| s.parse::<IpNet>().ok())
        .collect()
}

/// A filter for host-based network access control.
///
/// Supports exact domain match, wildcard subdomains (`*.googleapis.com`),
/// and CIDR deny ranges (RFC1918, link-local, cloud metadata).
///
/// The default deny list is always applied and cannot be overridden.
/// The allowlist determines which hosts are permitted; everything else
/// is denied by default.
#[derive(Debug, Clone)]
pub struct HostFilter {
    /// Allowed exact hosts (lowercased)
    allowed_hosts: Vec<String>,
    /// Allowed wildcard suffixes (e.g., ".googleapis.com", lowercased)
    allowed_suffixes: Vec<String>,
    /// CIDR ranges that are always denied
    deny_cidrs: Vec<IpNet>,
    /// Hostnames that are always denied
    deny_hosts: Vec<String>,
}

impl HostFilter {
    /// Create a new host filter with the given allowed hosts.
    ///
    /// The default deny list (cloud metadata, RFC1918, loopback, link-local)
    /// is automatically included and cannot be removed.
    ///
    /// Hosts starting with `*.` are treated as wildcard subdomain patterns.
    /// All other entries are exact matches. Matching is case-insensitive.
    #[must_use]
    pub fn new(allowed_hosts: &[String]) -> Self {
        let mut exact = Vec::new();
        let mut suffixes = Vec::new();

        for host in allowed_hosts {
            let lower = host.to_lowercase();
            if let Some(suffix) = lower.strip_prefix('*') {
                // *.example.com -> .example.com
                suffixes.push(suffix.to_string());
            } else {
                exact.push(lower);
            }
        }

        Self {
            allowed_hosts: exact,
            allowed_suffixes: suffixes,
            deny_cidrs: default_deny_cidrs(),
            deny_hosts: DENY_HOSTS.iter().map(|s| s.to_lowercase()).collect(),
        }
    }

    /// Create a host filter that allows everything (no filtering).
    ///
    /// The default deny list still applies — cloud metadata and private
    /// networks are always blocked.
    #[must_use]
    pub fn allow_all() -> Self {
        Self {
            allowed_hosts: Vec::new(),
            allowed_suffixes: Vec::new(),
            deny_cidrs: default_deny_cidrs(),
            deny_hosts: DENY_HOSTS.iter().map(|s| s.to_lowercase()).collect(),
        }
    }

    /// Check a host against the filter.
    ///
    /// `resolved_ips` should contain the DNS-resolved IP addresses for the host.
    /// The caller is responsible for performing DNS resolution before calling this
    /// method. This prevents DNS rebinding attacks: the proxy resolves once, checks
    /// the resolved IPs here, then connects to the same resolved IP.
    ///
    /// # Check Order
    ///
    /// 1. Deny hosts (exact match against cloud metadata hostnames)
    /// 2. Deny CIDRs (resolved IPs against RFC1918, link-local, loopback)
    /// 3. Allowlist (exact host match, then wildcard subdomain match)
    /// 4. Default deny (if not in allowlist and allowlist is non-empty)
    #[must_use]
    pub fn check_host(&self, host: &str, resolved_ips: &[IpAddr]) -> FilterResult {
        let lower_host = host.to_lowercase();

        // 1. Check deny hosts
        if self.deny_hosts.contains(&lower_host) {
            return FilterResult::DenyHost {
                host: host.to_string(),
            };
        }

        // 2. Check resolved IPs against deny CIDRs
        for ip in resolved_ips {
            for cidr in &self.deny_cidrs {
                if cidr.contains(ip) {
                    return FilterResult::DenyCidr {
                        ip: *ip,
                        cidr: *cidr,
                    };
                }
            }
        }

        // 3. If no allowlist is configured (allow_all mode), allow
        if self.allowed_hosts.is_empty() && self.allowed_suffixes.is_empty() {
            return FilterResult::Allow;
        }

        // 4. Check exact host match
        if self.allowed_hosts.contains(&lower_host) {
            return FilterResult::Allow;
        }

        // 5. Check wildcard subdomain match
        for suffix in &self.allowed_suffixes {
            if lower_host.ends_with(suffix.as_str()) && lower_host.len() > suffix.len() {
                return FilterResult::Allow;
            }
        }

        // 6. Not in allowlist
        FilterResult::DenyNotAllowed {
            host: host.to_string(),
        }
    }

    /// Check if a single IP is in any deny CIDR range.
    #[must_use]
    pub fn is_denied_cidr(&self, ip: &IpAddr) -> bool {
        self.deny_cidrs.iter().any(|cidr| cidr.contains(ip))
    }

    /// Number of allowed hosts (exact + wildcard)
    #[must_use]
    pub fn allowed_count(&self) -> usize {
        self.allowed_hosts
            .len()
            .saturating_add(self.allowed_suffixes.len())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn public_ip() -> Vec<IpAddr> {
        vec![IpAddr::V4(Ipv4Addr::new(104, 18, 7, 96))]
    }

    #[test]
    fn test_exact_host_allowed() {
        let filter = HostFilter::new(&["api.openai.com".to_string()]);
        let result = filter.check_host("api.openai.com", &public_ip());
        assert!(result.is_allowed());
    }

    #[test]
    fn test_exact_host_case_insensitive() {
        let filter = HostFilter::new(&["API.OpenAI.COM".to_string()]);
        let result = filter.check_host("api.openai.com", &public_ip());
        assert!(result.is_allowed());
    }

    #[test]
    fn test_host_not_in_allowlist() {
        let filter = HostFilter::new(&["api.openai.com".to_string()]);
        let result = filter.check_host("evil.com", &public_ip());
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyNotAllowed { .. }));
    }

    #[test]
    fn test_wildcard_subdomain_match() {
        let filter = HostFilter::new(&["*.googleapis.com".to_string()]);

        // Subdomain should match
        let result = filter.check_host("storage.googleapis.com", &public_ip());
        assert!(result.is_allowed());

        // Deep subdomain should match
        let result = filter.check_host("us-central1-aiplatform.googleapis.com", &public_ip());
        assert!(result.is_allowed());
    }

    #[test]
    fn test_wildcard_does_not_match_bare_domain() {
        let filter = HostFilter::new(&["*.googleapis.com".to_string()]);

        // Bare domain should NOT match wildcard
        let result = filter.check_host("googleapis.com", &public_ip());
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_deny_cloud_metadata_hostname() {
        let filter = HostFilter::new(&["169.254.169.254".to_string()]);

        // Should be denied even if in allowlist
        let result = filter.check_host("169.254.169.254", &public_ip());
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyHost { .. }));
    }

    #[test]
    fn test_deny_google_metadata() {
        let filter = HostFilter::new(&["metadata.google.internal".to_string()]);
        let result = filter.check_host("metadata.google.internal", &public_ip());
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_deny_rfc1918_ip_via_cidr() {
        let filter = HostFilter::new(&["*.example.com".to_string()]);

        // Even if hostname matches allowlist, resolved IP in RFC1918 should be denied
        let private_ip = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
        let result = filter.check_host("api.example.com", &private_ip);
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyCidr { .. }));
    }

    #[test]
    fn test_deny_link_local_cidr() {
        let filter = HostFilter::new(&["*.example.com".to_string()]);
        let link_local = vec![IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))];
        let result = filter.check_host("api.example.com", &link_local);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_deny_loopback_cidr() {
        let filter = HostFilter::new(&["*.example.com".to_string()]);
        let loopback = vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))];
        let result = filter.check_host("api.example.com", &loopback);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_deny_ipv6_loopback() {
        let filter = HostFilter::new(&["*.example.com".to_string()]);
        let ipv6_loopback = vec![IpAddr::V6(Ipv6Addr::LOCALHOST)];
        let result = filter.check_host("api.example.com", &ipv6_loopback);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_deny_ipv6_unique_local() {
        let filter = HostFilter::new(&["*.example.com".to_string()]);
        let ipv6_ula = vec![IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1))];
        let result = filter.check_host("api.example.com", &ipv6_ula);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_dns_rebinding_protection() {
        // Attacker's domain resolves to cloud metadata IP
        let filter = HostFilter::new(&["attacker.com".to_string()]);
        let metadata_ip = vec![IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))];
        let result = filter.check_host("attacker.com", &metadata_ip);
        assert!(!result.is_allowed());
        assert!(matches!(result, FilterResult::DenyCidr { .. }));
    }

    #[test]
    fn test_allow_all_mode() {
        // No allowlist = allow all (except deny list)
        let filter = HostFilter::allow_all();
        let result = filter.check_host("any-host.example.com", &public_ip());
        assert!(result.is_allowed());
    }

    #[test]
    fn test_allow_all_still_denies_private() {
        let filter = HostFilter::allow_all();
        let private_ip = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
        let result = filter.check_host("internal.corp.com", &private_ip);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_is_denied_cidr() {
        let filter = HostFilter::new(&[]);
        assert!(filter.is_denied_cidr(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(filter.is_denied_cidr(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(!filter.is_denied_cidr(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn test_allowed_count() {
        let filter = HostFilter::new(&[
            "api.openai.com".to_string(),
            "*.googleapis.com".to_string(),
            "github.com".to_string(),
        ]);
        assert_eq!(filter.allowed_count(), 3);
    }

    #[test]
    fn test_empty_resolved_ips_skips_cidr_check() {
        let filter = HostFilter::new(&["api.openai.com".to_string()]);
        // No resolved IPs = skip CIDR check, just check hostname
        let result = filter.check_host("api.openai.com", &[]);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_filter_result_reason() {
        let allow = FilterResult::Allow;
        assert!(allow.reason().contains("allowed"));

        let deny = FilterResult::DenyNotAllowed {
            host: "evil.com".to_string(),
        };
        assert!(deny.reason().contains("evil.com"));
    }

    #[test]
    fn test_multiple_ips_any_denied() {
        let filter = HostFilter::new(&["multi.example.com".to_string()]);
        // First IP is public, second is private
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(104, 18, 7, 96)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        ];
        let result = filter.check_host("multi.example.com", &ips);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_172_16_range_denied() {
        let filter = HostFilter::new(&["*.example.com".to_string()]);
        let ip = vec![IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))];
        let result = filter.check_host("api.example.com", &ip);
        assert!(!result.is_allowed());

        // 172.15.x.x should be allowed (outside the /12 range)
        let ip = vec![IpAddr::V4(Ipv4Addr::new(172, 15, 255, 255))];
        let result = filter.check_host("api.example.com", &ip);
        assert!(result.is_allowed());
    }
}
