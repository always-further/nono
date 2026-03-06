//! Learn mode: trace file accesses to discover required paths
//!
//! Uses platform-specific tracing to monitor a command's filesystem and network
//! accesses and produces a list of paths that would need to be allowed in a nono profile.
//!
//! - Linux: strace
//! - macOS: Seatbelt report-mode + log stream

use crate::cli::LearnArgs;
use crate::profile::Profile;
use nono::Result;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use tracing::debug;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

// ============================================================================
// Shared types
// ============================================================================

/// Represents a file access from tracing
#[derive(Debug, Clone)]
pub(crate) struct FileAccess {
    pub path: PathBuf,
    pub is_write: bool,
}

/// Kind of network access observed
#[derive(Debug, Clone)]
pub(crate) enum NetworkAccessKind {
    Connect,
    Bind,
}

/// A single network access observed
#[derive(Debug, Clone)]
pub(crate) struct NetworkAccess {
    pub addr: IpAddr,
    pub port: u16,
    pub kind: NetworkAccessKind,
    /// Hostname from the most recent DNS query (timing-based correlation)
    pub queried_hostname: Option<String>,
}

/// A resolved network endpoint with optional reverse DNS hostname
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NetworkEndpoint {
    pub addr: IpAddr,
    pub port: u16,
    pub hostname: Option<String>,
}

/// Summary of connections to a single endpoint (with count)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NetworkConnectionSummary {
    pub endpoint: NetworkEndpoint,
    pub count: usize,
}

/// Result of learning file access patterns
#[derive(Debug)]
pub struct LearnResult {
    /// Paths that need read access
    pub read_paths: BTreeSet<PathBuf>,
    /// Paths that need write access
    pub write_paths: BTreeSet<PathBuf>,
    /// Paths that need read+write access
    pub readwrite_paths: BTreeSet<PathBuf>,
    /// Paths that were accessed but are already covered by system paths
    pub system_covered: BTreeSet<PathBuf>,
    /// Paths that were accessed but are already covered by profile
    pub profile_covered: BTreeSet<PathBuf>,
    /// Outbound network connections observed
    pub outbound_connections: Vec<NetworkConnectionSummary>,
    /// Listening ports observed
    pub listening_ports: Vec<NetworkConnectionSummary>,
}

impl LearnResult {
    pub(crate) fn new() -> Self {
        Self {
            read_paths: BTreeSet::new(),
            write_paths: BTreeSet::new(),
            readwrite_paths: BTreeSet::new(),
            system_covered: BTreeSet::new(),
            profile_covered: BTreeSet::new(),
            outbound_connections: Vec::new(),
            listening_ports: Vec::new(),
        }
    }

    /// Check if any paths were discovered
    pub fn has_paths(&self) -> bool {
        !self.read_paths.is_empty()
            || !self.write_paths.is_empty()
            || !self.readwrite_paths.is_empty()
    }

    /// Check if any network activity was observed
    pub fn has_network_activity(&self) -> bool {
        !self.outbound_connections.is_empty() || !self.listening_ports.is_empty()
    }

    /// Format as JSON fragment for profile
    pub fn to_json(&self) -> String {
        let allow: Vec<String> = self
            .readwrite_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        let read: Vec<String> = self
            .read_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        let write: Vec<String> = self
            .write_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect();

        let outbound: Vec<serde_json::Value> = self
            .outbound_connections
            .iter()
            .map(|c| {
                let mut obj = serde_json::json!({
                    "addr": c.endpoint.addr.to_string(),
                    "port": c.endpoint.port,
                    "count": c.count,
                });
                if let Some(ref hostname) = c.endpoint.hostname {
                    obj["hostname"] = serde_json::Value::String(hostname.clone());
                }
                obj
            })
            .collect();

        let listening: Vec<serde_json::Value> = self
            .listening_ports
            .iter()
            .map(|c| {
                let mut obj = serde_json::json!({
                    "addr": c.endpoint.addr.to_string(),
                    "port": c.endpoint.port,
                    "count": c.count,
                });
                if let Some(ref hostname) = c.endpoint.hostname {
                    obj["hostname"] = serde_json::Value::String(hostname.clone());
                }
                obj
            })
            .collect();

        let fragment = serde_json::json!({
            "filesystem": {
                "allow": allow,
                "read": read,
                "write": write
            },
            "network": {
                "outbound": outbound,
                "listening": listening
            }
        });

        serde_json::to_string_pretty(&fragment).unwrap_or_else(|e| {
            tracing::warn!("Failed to serialize learn result to JSON: {}", e);
            "{}".to_string()
        })
    }

    /// Format as human-readable summary
    pub fn to_summary(&self) -> String {
        let mut lines = Vec::new();

        if !self.read_paths.is_empty() {
            lines.push("Read access needed:".to_string());
            for path in &self.read_paths {
                lines.push(format!("  {}", path.display()));
            }
        }

        if !self.write_paths.is_empty() {
            lines.push("Write access needed:".to_string());
            for path in &self.write_paths {
                lines.push(format!("  {}", path.display()));
            }
        }

        if !self.readwrite_paths.is_empty() {
            lines.push("Read+Write access needed:".to_string());
            for path in &self.readwrite_paths {
                lines.push(format!("  {}", path.display()));
            }
        }

        if !self.system_covered.is_empty() {
            lines.push(format!(
                "\n({} paths already covered by system defaults)",
                self.system_covered.len()
            ));
        }

        if !self.profile_covered.is_empty() {
            lines.push(format!(
                "({} paths already covered by profile)",
                self.profile_covered.len()
            ));
        }

        // Network sections
        if !self.outbound_connections.is_empty() {
            if !lines.is_empty() {
                lines.push(String::new());
            }
            lines.push("Outbound connections:".to_string());
            for conn in &self.outbound_connections {
                lines.push(format_network_summary(conn));
            }
        }

        if !self.listening_ports.is_empty() {
            if !lines.is_empty() {
                lines.push(String::new());
            }
            lines.push("Listening ports:".to_string());
            for conn in &self.listening_ports {
                lines.push(format_network_summary(conn));
            }
        }

        if lines.is_empty() {
            lines.push("No additional paths needed.".to_string());
        }

        lines.join("\n")
    }
}

/// Format a single network connection summary line
fn format_network_summary(conn: &NetworkConnectionSummary) -> String {
    let count_str = if conn.count > 1 {
        format!(" ({}x)", conn.count)
    } else {
        String::new()
    };

    if let Some(ref hostname) = conn.endpoint.hostname {
        format!(
            "  {} ({}):{}{}",
            hostname, conn.endpoint.addr, conn.endpoint.port, count_str
        )
    } else {
        format!(
            "  {}:{}{}",
            conn.endpoint.addr, conn.endpoint.port, count_str
        )
    }
}

// ============================================================================
// Cross-platform dispatcher
// ============================================================================

/// Run learn mode
#[cfg(target_os = "linux")]
pub fn run_learn(args: &LearnArgs) -> Result<LearnResult> {
    linux::run_learn(args)
}

/// Run learn mode
#[cfg(target_os = "macos")]
pub fn run_learn(args: &LearnArgs) -> Result<LearnResult> {
    macos::run_learn(args)
}

/// Run learn mode (unsupported platform stub)
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn run_learn(_args: &LearnArgs) -> Result<LearnResult> {
    use nono::NonoError;
    Err(NonoError::LearnError(
        "nono learn is not supported on this platform".to_string(),
    ))
}

// ============================================================================
// Shared helpers (used by both Linux and macOS implementations)
// ============================================================================

/// Process raw file accesses into categorized result
pub(crate) fn process_accesses(
    accesses: Vec<FileAccess>,
    profile: Option<&Profile>,
    show_all: bool,
) -> Result<LearnResult> {
    let mut result = LearnResult::new();

    // Get system paths that are already allowed (from policy.json groups)
    let loaded_policy = crate::policy::load_embedded_policy()?;
    let system_read_paths = crate::policy::get_system_read_paths(&loaded_policy);
    let system_read_set: HashSet<&str> = system_read_paths.iter().map(|s| s.as_str()).collect();

    // Get profile paths if available
    let profile_paths: HashSet<String> = if let Some(prof) = profile {
        let mut paths = HashSet::new();
        paths.extend(prof.filesystem.allow.iter().cloned());
        paths.extend(prof.filesystem.read.iter().cloned());
        paths.extend(prof.filesystem.write.iter().cloned());
        paths
    } else {
        HashSet::new()
    };

    // Merge accesses by canonical path, upgrading to write if any access is a write.
    // This prevents the same canonical path seen first as read then as write from
    // having the write silently dropped.
    let mut merged: HashMap<PathBuf, bool> = HashMap::new(); // canonical → is_write
    for access in accesses {
        let canonical = access.path.canonicalize().unwrap_or(access.path);
        let entry = merged.entry(canonical).or_insert(false);
        if access.is_write {
            *entry = true;
        }
    }

    for (canonical, is_write) in merged {
        // Check if covered by system paths
        if is_covered_by_set(&canonical, &system_read_set)? {
            if show_all {
                result.system_covered.insert(canonical);
            }
            continue;
        }

        // Check if covered by profile
        if is_covered_by_profile(&canonical, &profile_paths)? {
            if show_all {
                result.profile_covered.insert(canonical);
            }
            continue;
        }

        // Categorize by access type
        // Collapse to parent directories for cleaner output
        let collapsed = collapse_to_parent(&canonical);

        if is_write {
            // Check if already in read, upgrade to readwrite
            if result.read_paths.contains(&collapsed) {
                result.read_paths.remove(&collapsed);
                result.readwrite_paths.insert(collapsed);
            } else if !result.readwrite_paths.contains(&collapsed) {
                result.write_paths.insert(collapsed);
            }
        } else {
            // Read access
            if result.write_paths.contains(&collapsed) {
                result.write_paths.remove(&collapsed);
                result.readwrite_paths.insert(collapsed);
            } else if !result.readwrite_paths.contains(&collapsed) {
                result.read_paths.insert(collapsed);
            }
        }
    }

    Ok(result)
}

/// Check if a path is covered by a set of allowed paths
pub(crate) fn is_covered_by_set(path: &Path, allowed: &HashSet<&str>) -> Result<bool> {
    for allowed_path in allowed {
        let allowed_expanded = expand_home(allowed_path)?;
        if let Ok(allowed_canonical) = std::fs::canonicalize(&allowed_expanded) {
            if path.starts_with(&allowed_canonical) {
                return Ok(true);
            }
        }
        // Also check without canonicalization for paths that may not exist
        let allowed_path_buf = PathBuf::from(&allowed_expanded);
        if path.starts_with(&allowed_path_buf) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Check if a path is covered by profile paths
pub(crate) fn is_covered_by_profile(path: &Path, profile_paths: &HashSet<String>) -> Result<bool> {
    for profile_path in profile_paths {
        let expanded = expand_home(profile_path)?;
        if let Ok(canonical) = std::fs::canonicalize(&expanded) {
            if path.starts_with(&canonical) {
                return Ok(true);
            }
        }
        let path_buf = PathBuf::from(&expanded);
        if path.starts_with(&path_buf) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Expand ~ to home directory
///
/// Only expands `~` when it appears as a complete prefix: `~` alone or `~/...`.
/// A `~` embedded mid-path (e.g. `/path/with~tilde`) is left unchanged.
pub(crate) fn expand_home(path: &str) -> Result<String> {
    use crate::config;

    // Only expand '~' as a leading component: "~" or "~/..."
    if path == "~" || path.starts_with("~/") {
        let home = config::validated_home()?;
        return Ok(format!("{}{}", home, &path[1..]));
    }
    // Only expand "$HOME" as a leading component: "$HOME" or "$HOME/..."
    if path == "$HOME" || path.starts_with("$HOME/") {
        let home = config::validated_home()?;
        return Ok(format!("{}{}", home, &path[5..]));
    }
    Ok(path.to_string())
}

/// Collapse a file path to its parent directory for cleaner output
pub(crate) fn collapse_to_parent(path: &Path) -> PathBuf {
    // Don't collapse if it's already a directory
    if path.is_dir() {
        return path.to_path_buf();
    }

    // Collapse files to their parent directory
    path.parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| path.to_path_buf())
}

/// Process raw network accesses into categorized summaries.
///
/// Uses forward DNS correlation from captured DNS queries to map IPs to
/// hostnames. Falls back to reverse DNS for unmatched IPs when `resolve_dns`
/// is true.
pub(crate) fn process_network_accesses(
    accesses: Vec<NetworkAccess>,
    dns_queries: Vec<String>,
    resolve_dns: bool,
) -> (Vec<NetworkConnectionSummary>, Vec<NetworkConnectionSummary>) {
    let mut connect_counts: HashMap<(IpAddr, u16), usize> = HashMap::new();
    let mut bind_counts: HashMap<(IpAddr, u16), usize> = HashMap::new();

    for access in &accesses {
        let key = (access.addr, access.port);
        match access.kind {
            NetworkAccessKind::Connect => {
                *connect_counts.entry(key).or_insert(0) += 1;
            }
            NetworkAccessKind::Bind => {
                *bind_counts.entry(key).or_insert(0) += 1;
            }
        }
    }

    // Build IP → hostname mapping using three strategies (in priority order):
    // 1. Timing-based: hostname attached directly from preceding DNS query
    // 2. Forward DNS: resolve captured hostnames to IPs
    // 3. Reverse DNS: lookup IP → hostname as last resort
    let hostnames = if resolve_dns {
        // Strategy 1: Use hostnames attached during tracing (timing correlation)
        let mut map: HashMap<IpAddr, String> = HashMap::new();
        for access in &accesses {
            if let Some(ref hostname) = access.queried_hostname {
                map.entry(access.addr).or_insert_with(|| hostname.clone());
            }
        }

        // Strategy 2: Forward DNS for IPs not covered by timing correlation
        let all_ips: HashSet<IpAddr> = accesses.iter().map(|a| a.addr).collect();
        let unresolved_after_timing: HashSet<IpAddr> = all_ips
            .iter()
            .filter(|ip| !map.contains_key(ip))
            .copied()
            .collect();

        if !unresolved_after_timing.is_empty() && !dns_queries.is_empty() {
            let forward = resolve_forward_dns(&dns_queries);
            for (ip, hostname) in forward {
                map.entry(ip).or_insert(hostname);
            }
        }

        // Strategy 3: Reverse DNS for anything still unresolved
        let unresolved_after_forward: HashSet<IpAddr> = all_ips
            .iter()
            .filter(|ip| !map.contains_key(ip))
            .copied()
            .collect();

        if !unresolved_after_forward.is_empty() {
            let reverse = resolve_reverse_dns(&unresolved_after_forward);
            map.extend(reverse);
        }

        map
    } else {
        HashMap::new()
    };

    let build_summaries =
        |counts: &HashMap<(IpAddr, u16), usize>| -> Vec<NetworkConnectionSummary> {
            let mut summaries: Vec<NetworkConnectionSummary> = counts
                .iter()
                .map(|(&(addr, port), &count)| NetworkConnectionSummary {
                    endpoint: NetworkEndpoint {
                        addr,
                        port,
                        hostname: hostnames.get(&addr).cloned(),
                    },
                    count,
                })
                .collect();
            summaries.sort();
            summaries
        };

    (
        build_summaries(&connect_counts),
        build_summaries(&bind_counts),
    )
}

/// Resolve captured DNS query hostnames to IPs via forward DNS lookup.
///
/// For each hostname the traced program queried, resolves it to its current
/// IPs to build an IP→hostname mapping. This gives the actual hostname the
/// program intended to reach (e.g., "google.com") rather than infrastructure
/// names from reverse DNS (e.g., "jr-in-f100.1e100.net").
fn resolve_forward_dns(hostnames: &[String]) -> HashMap<IpAddr, String> {
    let mut result = HashMap::new();
    let unique: HashSet<&String> = hostnames.iter().collect();

    for hostname in unique {
        match dns_lookup::lookup_host(hostname) {
            Ok(ips) => {
                for ip in ips {
                    // First hostname to resolve to this IP wins
                    result.entry(ip).or_insert_with(|| hostname.clone());
                }
            }
            Err(e) => {
                debug!("Forward DNS lookup failed for {}: {}", hostname, e);
            }
        }
    }

    result
}

/// Resolve IP addresses to hostnames via reverse DNS (fallback)
fn resolve_reverse_dns(ips: &HashSet<IpAddr>) -> HashMap<IpAddr, String> {
    let mut result = HashMap::new();

    for &ip in ips {
        match dns_lookup::lookup_addr(&ip) {
            Ok(hostname) => {
                // Skip if the hostname is just the IP address stringified
                if hostname != ip.to_string() {
                    result.insert(ip, hostname);
                }
            }
            Err(e) => {
                debug!("Reverse DNS lookup failed for {}: {}", ip, e);
            }
        }
    }

    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_learn_result_to_json() {
        let mut result = LearnResult::new();
        result.read_paths.insert(PathBuf::from("/some/read/path"));
        result.write_paths.insert(PathBuf::from("/some/write/path"));

        let json = result.to_json();
        assert!(json.contains("filesystem"));
        assert!(json.contains("/some/read/path"));
        assert!(json.contains("/some/write/path"));
    }

    #[test]
    fn test_expand_home() {
        // RAII guard: restores HOME even if the test panics
        struct HomeGuard(Option<String>);
        impl Drop for HomeGuard {
            fn drop(&mut self) {
                match &self.0 {
                    Some(home) => std::env::set_var("HOME", home),
                    None => std::env::remove_var("HOME"),
                }
            }
        }
        let _guard = HomeGuard(std::env::var("HOME").ok());

        std::env::set_var("HOME", "/home/test");
        assert_eq!(expand_home("~/foo").expect("valid home"), "/home/test/foo");
        assert_eq!(expand_home("~").expect("tilde alone"), "/home/test");
        assert_eq!(
            expand_home("$HOME/bar").expect("valid home"),
            "/home/test/bar"
        );
        assert_eq!(expand_home("$HOME").expect("HOME alone"), "/home/test");
        assert_eq!(
            expand_home("/absolute/path").expect("no expansion needed"),
            "/absolute/path"
        );
        // Tilde not at position 0+/ boundary must not be expanded
        assert_eq!(
            expand_home("/path/with~tilde").expect("mid-path tilde unchanged"),
            "/path/with~tilde"
        );
    }

    #[test]
    fn test_collapse_to_parent() {
        // For a file that doesn't exist, collapse to parent
        let path = PathBuf::from("/some/dir/file.txt");
        let collapsed = collapse_to_parent(&path);
        assert_eq!(collapsed, PathBuf::from("/some/dir"));
    }

    #[test]
    fn test_learn_result_network_json() {
        let mut result = LearnResult::new();
        result.outbound_connections.push(NetworkConnectionSummary {
            endpoint: NetworkEndpoint {
                addr: "93.184.216.34".parse().unwrap(),
                port: 443,
                hostname: Some("example.com".to_string()),
            },
            count: 5,
        });
        result.listening_ports.push(NetworkConnectionSummary {
            endpoint: NetworkEndpoint {
                addr: "0.0.0.0".parse().unwrap(),
                port: 3000,
                hostname: None,
            },
            count: 1,
        });

        let json = result.to_json();
        assert!(json.contains("\"network\""));
        assert!(json.contains("\"outbound\""));
        assert!(json.contains("\"listening\""));
        assert!(json.contains("93.184.216.34"));
        assert!(json.contains("443"));
        assert!(json.contains("example.com"));
        assert!(json.contains("0.0.0.0"));
        assert!(json.contains("3000"));
    }

    #[test]
    fn test_learn_result_network_summary() {
        let mut result = LearnResult::new();
        result.outbound_connections.push(NetworkConnectionSummary {
            endpoint: NetworkEndpoint {
                addr: "93.184.216.34".parse().unwrap(),
                port: 443,
                hostname: Some("example.com".to_string()),
            },
            count: 12,
        });
        result.listening_ports.push(NetworkConnectionSummary {
            endpoint: NetworkEndpoint {
                addr: "0.0.0.0".parse().unwrap(),
                port: 3000,
                hostname: None,
            },
            count: 1,
        });

        let summary = result.to_summary();
        assert!(summary.contains("Outbound connections:"));
        assert!(summary.contains("example.com (93.184.216.34):443 (12x)"));
        assert!(summary.contains("Listening ports:"));
        assert!(summary.contains("0.0.0.0:3000"));
        // Count of 1 should NOT show "(1x)"
        assert!(!summary.contains("(1x)"));
    }

    #[test]
    fn test_has_network_activity() {
        let mut result = LearnResult::new();
        assert!(!result.has_network_activity());

        result.outbound_connections.push(NetworkConnectionSummary {
            endpoint: NetworkEndpoint {
                addr: "10.0.0.1".parse().unwrap(),
                port: 80,
                hostname: None,
            },
            count: 1,
        });
        assert!(result.has_network_activity());

        let mut result2 = LearnResult::new();
        result2.listening_ports.push(NetworkConnectionSummary {
            endpoint: NetworkEndpoint {
                addr: "0.0.0.0".parse().unwrap(),
                port: 8080,
                hostname: None,
            },
            count: 1,
        });
        assert!(result2.has_network_activity());
    }

    #[test]
    fn test_format_network_summary_with_hostname() {
        let conn = NetworkConnectionSummary {
            endpoint: NetworkEndpoint {
                addr: "93.184.216.34".parse().unwrap(),
                port: 443,
                hostname: Some("example.com".to_string()),
            },
            count: 5,
        };
        let line = format_network_summary(&conn);
        assert_eq!(line, "  example.com (93.184.216.34):443 (5x)");
    }

    #[test]
    fn test_format_network_summary_without_hostname() {
        let conn = NetworkConnectionSummary {
            endpoint: NetworkEndpoint {
                addr: "10.0.0.1".parse().unwrap(),
                port: 8080,
                hostname: None,
            },
            count: 1,
        };
        let line = format_network_summary(&conn);
        assert_eq!(line, "  10.0.0.1:8080");
    }

    #[test]
    fn test_process_accesses_read_then_write_upgrades() {
        // The same canonical path accessed first as read then as write must NOT have
        // the write silently dropped (previous dedup bug: seen_paths keyed on canonical
        // caused the second access to be skipped entirely).
        //
        // Use a path that is guaranteed not to be in any system read group so it
        // passes through the coverage filter.
        let accesses = vec![
            FileAccess {
                path: PathBuf::from("/nonexistent_nono_test_upgrade/dir/file.txt"),
                is_write: false,
            },
            FileAccess {
                path: PathBuf::from("/nonexistent_nono_test_upgrade/dir/file.txt"),
                is_write: true,
            },
        ];
        let result = process_accesses(accesses, None, false).expect("process_accesses failed");
        let collapsed = PathBuf::from("/nonexistent_nono_test_upgrade/dir");
        // The path must appear with write access, not only as a read
        assert!(
            !result.read_paths.contains(&collapsed),
            "path must not remain read-only after write access"
        );
        assert!(
            result.write_paths.contains(&collapsed) || result.readwrite_paths.contains(&collapsed),
            "path must be in write_paths or readwrite_paths"
        );
    }

    #[test]
    fn test_network_dedup() {
        // Duplicate endpoints should be merged with count
        let accesses = vec![
            NetworkAccess {
                addr: "93.184.216.34".parse().unwrap(),
                port: 443,
                kind: NetworkAccessKind::Connect,
                queried_hostname: None,
            },
            NetworkAccess {
                addr: "93.184.216.34".parse().unwrap(),
                port: 443,
                kind: NetworkAccessKind::Connect,
                queried_hostname: None,
            },
            NetworkAccess {
                addr: "93.184.216.34".parse().unwrap(),
                port: 443,
                kind: NetworkAccessKind::Connect,
                queried_hostname: None,
            },
        ];

        let (outbound, listening) = process_network_accesses(accesses, vec![], false);
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].count, 3);
        assert!(listening.is_empty());
    }
}
