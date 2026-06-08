use crate::cli::SandboxArgs;
use crate::command_policy::{
    CommandCredentialGrantConfig, CommandCredentialType, CommandFromConfig, CommandPoliciesConfig,
    CommandSandboxConfig, EndpointPolicyConfig, PolicyDecision, PolicyDecisionConfig,
};
use crate::launch_runtime::ProxyLaunchOptions;
use crate::network_policy;
use crate::sandbox_prepare::{PreparedSandbox, validate_external_proxy_bypass};
#[cfg(not(target_os = "macos"))]
use nono::AccessMode;
use nono::{CapabilitySet, NonoError, Result};
use nono_proxy::config::{
    EndpointPolicyConfig as ProxyEndpointPolicyConfig,
    EndpointPolicyDecision as ProxyEndpointPolicyDecision,
    EndpointPolicyDefault as ProxyEndpointPolicyDefault,
    EndpointPolicyRule as ProxyEndpointPolicyRule, InjectMode,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

pub(crate) struct ActiveProxyRuntime {
    pub(crate) env_vars: Vec<(String, String)>,
    pub(crate) tool_sandbox_credential_env_vars: BTreeMap<String, Vec<(String, String)>>,
    pub(crate) tool_sandbox_trust_bundle_paths: Vec<std::path::PathBuf>,
    pub(crate) handle: Option<nono_proxy::server::ProxyHandle>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct EffectiveProxySettings {
    pub(crate) network_profile: Option<String>,
    pub(crate) allow_domain: Vec<crate::profile::AllowDomainEntry>,
    pub(crate) credentials: Vec<String>,
}

pub(crate) fn prepare_proxy_launch_options(
    args: &SandboxArgs,
    prepared: &PreparedSandbox,
    silent: bool,
) -> Result<ProxyLaunchOptions> {
    validate_external_proxy_bypass(args, prepared)?;

    let effective_proxy = resolve_effective_proxy_settings(args, prepared);
    let network_profile = effective_proxy.network_profile;
    let allow_domain = effective_proxy.allow_domain;
    let mut credentials = effective_proxy.credentials;
    let mut custom_credentials = prepared.custom_credentials.clone();
    let mut proxy_source_env_vars = HashMap::new();
    let mut tool_sandbox_base_url_env_vars = HashMap::new();
    let mut tool_sandbox_proxy_credentials = HashSet::new();
    extend_proxy_settings_with_tool_sandbox_credentials(
        prepared.command_policies.as_ref(),
        &mut credentials,
        &mut custom_credentials,
        &mut proxy_source_env_vars,
        &mut tool_sandbox_base_url_env_vars,
        &mut tool_sandbox_proxy_credentials,
    )?;
    let allow_bind_ports = merge_dedup_ports(&prepared.listen_ports, &args.allow_bind);
    let tls_options = resolve_tls_intercept_options(args, prepared)?;

    let upstream_proxy = if args.allow_net {
        None
    } else {
        args.external_proxy
            .clone()
            .or_else(|| prepared.upstream_proxy.clone())
    };

    let upstream_bypass = if args.allow_net {
        Vec::new()
    } else if args.external_proxy.is_some() {
        args.external_proxy_bypass.clone()
    } else {
        let mut bypass = prepared.upstream_bypass.clone();
        bypass.extend(args.external_proxy_bypass.clone());
        bypass
    };

    let active = if matches!(prepared.caps.network_mode(), nono::NetworkMode::Blocked) {
        if !credentials.is_empty()
            || network_profile.is_some()
            || !allow_domain.is_empty()
            || upstream_proxy.is_some()
        {
            warn!(
                "--block-net is active; ignoring proxy configuration \
                 that would re-enable network access"
            );
            if !silent {
                eprintln!(
                    "  [nono] Warning: --block-net overrides proxy/credential settings. \
                     Network remains fully blocked."
                );
            }
        }
        false
    } else {
        matches!(
            prepared.caps.network_mode(),
            nono::NetworkMode::ProxyOnly { .. }
        ) || !credentials.is_empty()
            || network_profile.is_some()
            || !allow_domain.is_empty()
            || upstream_proxy.is_some()
    };

    Ok(ProxyLaunchOptions {
        active,
        network_profile,
        allow_domain,
        credentials,
        custom_credentials,
        proxy_source_env_vars,
        tool_sandbox_base_url_env_vars,
        tool_sandbox_proxy_credentials,
        upstream_proxy,
        upstream_bypass,
        allow_bind_ports,
        proxy_port: args.proxy_port,
        open_url_origins: prepared.open_url_origins.clone(),
        open_url_allow_localhost: prepared.open_url_allow_localhost,
        allow_launch_services_active: prepared.allow_launch_services_active,
        #[cfg(target_os = "macos")]
        trust_proxy_ca: tls_options.trust_proxy_ca,
        proxy_ca_validity: tls_options.ca_validity,
        network_block: prepared.network_block_requested,
        proxy_leaf_validity: tls_options.leaf_validity,
        command_policies: prepared.command_policies.clone(),
    })
}

struct ResolvedTlsInterceptOptions {
    #[cfg(target_os = "macos")]
    trust_proxy_ca: bool,
    ca_validity: Option<std::time::Duration>,
    leaf_validity: Option<std::time::Duration>,
}

fn resolve_tls_intercept_options(
    args: &SandboxArgs,
    prepared: &PreparedSandbox,
) -> Result<ResolvedTlsInterceptOptions> {
    let profile_tls = prepared.tls_intercept.as_ref();
    #[cfg(target_os = "macos")]
    let profile_trusted = profile_tls
        .map(|tls| matches!(tls.ca_lifecycle, crate::profile::TlsCaLifecycle::Trusted))
        .unwrap_or(false);
    #[cfg(target_os = "macos")]
    if args.trust_proxy_ca
        && let Some(tls) = profile_tls
        && tls.ca_lifecycle == crate::profile::TlsCaLifecycle::Session
    {
        return Err(NonoError::ConfigParse(
            "profile requests network.tls_intercept.ca_lifecycle=session but \
             --trust-proxy-ca requests trusted"
                .to_string(),
        ));
    }
    #[cfg(not(target_os = "macos"))]
    if let Some(tls) = profile_tls
        && tls.ca_lifecycle == crate::profile::TlsCaLifecycle::Trusted
    {
        return Err(NonoError::ConfigParse(
            "network.tls_intercept.ca_lifecycle=trusted is currently only supported on macOS"
                .to_string(),
        ));
    }

    let profile_ca_validity = profile_tls
        .and_then(|tls| tls.ca_validity.as_deref())
        .map(|value| crate::profile::parse_tls_duration("network.tls_intercept.ca_validity", value))
        .transpose()?;
    let ca_validity = args
        .proxy_ca_validity
        .map(|days| std::time::Duration::from_secs(u64::from(days) * 24 * 60 * 60))
        .or(profile_ca_validity);
    let leaf_validity = profile_tls
        .and_then(|tls| tls.leaf_validity.as_deref())
        .map(|value| {
            crate::profile::parse_tls_duration("network.tls_intercept.leaf_validity", value)
        })
        .transpose()?;

    Ok(ResolvedTlsInterceptOptions {
        #[cfg(target_os = "macos")]
        trust_proxy_ca: args.trust_proxy_ca || profile_trusted,
        ca_validity,
        leaf_validity,
    })
}

pub(crate) fn resolve_effective_proxy_settings(
    args: &SandboxArgs,
    prepared: &PreparedSandbox,
) -> EffectiveProxySettings {
    if args.allow_net {
        return EffectiveProxySettings {
            network_profile: None,
            allow_domain: Vec::new(),
            credentials: Vec::new(),
        };
    }

    let network_profile = args
        .network_profile
        .clone()
        .or_else(|| prepared.network_profile.clone());
    let mut allow_domain = prepared.allow_domain.clone();
    allow_domain.extend(args.allow_proxy.iter().map(|s| parse_allow_domain_arg(s)));
    let mut credentials = prepared.credentials.clone();
    credentials.extend(args.proxy_credential.clone());

    EffectiveProxySettings {
        network_profile,
        allow_domain,
        credentials,
    }
}

fn extend_proxy_settings_with_tool_sandbox_credentials(
    config: Option<&CommandPoliciesConfig>,
    credentials: &mut Vec<String>,
    custom_credentials: &mut HashMap<String, crate::profile::CustomCredentialDef>,
    proxy_source_env_vars: &mut HashMap<String, String>,
    base_url_env_vars: &mut HashMap<String, String>,
    tool_sandbox_proxy_credentials: &mut HashSet<String>,
) -> Result<()> {
    let Some(config) = config.filter(|config| config.is_active()) else {
        return Ok(());
    };

    for command in config.commands.values() {
        if let Some(sandbox) = &command.sandbox {
            collect_tool_sandbox_proxy_grants(
                config,
                sandbox,
                credentials,
                custom_credentials,
                proxy_source_env_vars,
                base_url_env_vars,
                tool_sandbox_proxy_credentials,
            )?;
        }
        for from in command.from.values() {
            match from {
                CommandFromConfig::Edge(edge) => collect_tool_sandbox_proxy_grants(
                    config,
                    &edge.sandbox,
                    credentials,
                    custom_credentials,
                    proxy_source_env_vars,
                    base_url_env_vars,
                    tool_sandbox_proxy_credentials,
                )?,
                CommandFromConfig::Policy(sandbox) => collect_tool_sandbox_proxy_grants(
                    config,
                    sandbox,
                    credentials,
                    custom_credentials,
                    proxy_source_env_vars,
                    base_url_env_vars,
                    tool_sandbox_proxy_credentials,
                )?,
                CommandFromConfig::Deny(_) => {}
            }
        }
    }

    Ok(())
}

fn collect_tool_sandbox_proxy_grants(
    config: &CommandPoliciesConfig,
    sandbox: &CommandSandboxConfig,
    credentials: &mut Vec<String>,
    custom_credentials: &mut HashMap<String, crate::profile::CustomCredentialDef>,
    proxy_source_env_vars: &mut HashMap<String, String>,
    base_url_env_vars: &mut HashMap<String, String>,
    tool_sandbox_proxy_credentials: &mut HashSet<String>,
) -> Result<()> {
    for name in &sandbox.use_credentials {
        if config
            .credentials
            .get(name)
            .is_some_and(|credential| credential.credential_type == CommandCredentialType::Proxy)
        {
            return Err(NonoError::ConfigParse(format!(
                "tool-sandbox proxy credential '{name}' must be granted with sandbox.credentials and endpoint_policy"
            )));
        }
    }

    for grant in &sandbox.credentials {
        let CommandCredentialGrantConfig::Policy(grant) = grant else {
            let CommandCredentialGrantConfig::Name(name) = grant else {
                continue;
            };
            if config.credentials.get(name).is_some_and(|credential| {
                credential.credential_type == CommandCredentialType::Proxy
            }) {
                return Err(NonoError::ConfigParse(format!(
                    "tool-sandbox proxy credential '{name}' must include endpoint_policy"
                )));
            }
            continue;
        };
        let Some(credential) = config.credentials.get(&grant.name) else {
            continue;
        };
        if credential.credential_type != CommandCredentialType::Proxy {
            continue;
        }
        let endpoint_policy = grant.endpoint_policy.as_ref().ok_or_else(|| {
            NonoError::ConfigParse(format!(
                "tool-sandbox proxy credential '{}' requires endpoint_policy",
                grant.name
            ))
        })?;
        validate_endpoint_policy_approval_routes(config, &grant.name, endpoint_policy)?;
        let endpoint_policy = endpoint_policy_to_proxy_policy(config, endpoint_policy);
        let upstream = credential.upstream.clone().ok_or_else(|| {
            NonoError::ConfigParse(format!(
                "tool-sandbox proxy credential '{}' missing upstream",
                grant.name
            ))
        })?;
        let env_var = credential.env_var.clone().ok_or_else(|| {
            NonoError::ConfigParse(format!(
                "tool-sandbox proxy credential '{}' missing env_var",
                grant.name
            ))
        })?;
        nono::validate_destination_env_var(&env_var).map_err(|err| {
            NonoError::ConfigParse(format!(
                "tool-sandbox proxy credential '{}' has invalid env_var: {err}",
                grant.name
            ))
        })?;
        if let Some(base_url_env_var) = &credential.base_url_env_var {
            nono::validate_destination_env_var(base_url_env_var).map_err(|err| {
                NonoError::ConfigParse(format!(
                    "tool-sandbox proxy credential '{}' has invalid base_url_env_var: {err}",
                    grant.name
                ))
            })?;
        }

        let credential_key = if let Some(source) = &credential.source {
            let env_var = proxy_source_env_var(&grant.name);
            let value = load_supervisor_credential_source(source)?;
            proxy_source_env_vars.insert(env_var.clone(), value);
            Some(format!("env://{env_var}"))
        } else {
            credential.credential_key.clone()
        };

        let route = crate::profile::CustomCredentialDef {
            upstream,
            credential_key,
            auth: None,
            inject_mode: InjectMode::Header,
            inject_header: credential
                .inject_header
                .clone()
                .unwrap_or_else(|| "Authorization".to_string()),
            credential_format: credential.credential_format.clone(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: Some(env_var),
            endpoint_rules: Vec::new(),
            endpoint_policy: Some(endpoint_policy),
            tls_ca: credential
                .tls_ca
                .as_deref()
                .map(|path| {
                    crate::policy::expand_path(path).map(|path| path.to_string_lossy().into_owned())
                })
                .transpose()?,
            tls_client_cert: credential
                .tls_client_cert
                .as_deref()
                .map(|path| {
                    crate::policy::expand_path(path).map(|path| path.to_string_lossy().into_owned())
                })
                .transpose()?,
            tls_client_key: credential
                .tls_client_key
                .as_deref()
                .map(|path| {
                    crate::policy::expand_path(path).map(|path| path.to_string_lossy().into_owned())
                })
                .transpose()?,
        };

        if let Some(existing) = custom_credentials.get(&grant.name) {
            if existing != &route {
                return Err(NonoError::ConfigParse(format!(
                    "tool-sandbox proxy credential '{}' has conflicting endpoint policies across command grants",
                    grant.name
                )));
            }
        } else {
            if credentials.iter().any(|name| name == &grant.name) {
                return Err(NonoError::ConfigParse(format!(
                    "tool-sandbox proxy credential '{}' collides with an existing proxy credential route",
                    grant.name
                )));
            }
            custom_credentials.insert(grant.name.clone(), route);
        }
        if !credentials.iter().any(|name| name == &grant.name) {
            credentials.push(grant.name.clone());
        }
        tool_sandbox_proxy_credentials.insert(grant.name.clone());
        if let Some(base_url_env_var) = &credential.base_url_env_var {
            base_url_env_vars.insert(grant.name.clone(), base_url_env_var.clone());
        }
    }
    Ok(())
}

fn proxy_source_env_var(name: &str) -> String {
    let mut out = String::from("NONO_TOOL_SANDBOX_PROXY_CREDENTIAL_");
    for byte in name.bytes() {
        let ch = byte as char;
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push('_');
        }
    }
    out
}

fn load_supervisor_credential_source(
    source: &crate::command_policy::AmbientCredentialSourceConfig,
) -> Result<String> {
    match source {
        crate::command_policy::AmbientCredentialSourceConfig::Keystore { key } => {
            nono::keystore::load_secret_by_ref(nono::keystore::DEFAULT_SERVICE, key)
                .map(|secret| secret.to_string())
        }
        crate::command_policy::AmbientCredentialSourceConfig::Command {
            command,
            args,
            timeout_secs,
        } => load_command_credential_source(command, args, *timeout_secs),
    }
}

fn load_command_credential_source(
    command: &str,
    args: &[String],
    timeout_secs: Option<u64>,
) -> Result<String> {
    let timeout = Duration::from_secs(timeout_secs.unwrap_or(30));
    let mut child = Command::new(command)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| {
            NonoError::SandboxInit(format!(
                "failed to start supervisor credential source '{command}': {err}"
            ))
        })?;

    let start = Instant::now();
    loop {
        if let Some(_status) = child.try_wait().map_err(|err| {
            NonoError::SandboxInit(format!(
                "failed to wait for supervisor credential source '{command}': {err}"
            ))
        })? {
            break;
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(NonoError::SandboxInit(format!(
                "supervisor credential source '{command}' timed out after {}s",
                timeout.as_secs()
            )));
        }
        std::thread::sleep(Duration::from_millis(25));
    }

    let output = child.wait_with_output().map_err(|err| {
        NonoError::SandboxInit(format!(
            "failed to collect supervisor credential source '{command}': {err}"
        ))
    })?;
    if !output.status.success() {
        return Err(NonoError::SandboxInit(format!(
            "supervisor credential source '{command}' failed with exit code {}",
            output
                .status
                .code()
                .map_or_else(|| "unknown".to_string(), |code| code.to_string())
        )));
    }
    let value = String::from_utf8(output.stdout).map_err(|err| {
        NonoError::SandboxInit(format!(
            "supervisor credential source '{command}' produced non-UTF-8 stdout: {err}"
        ))
    })?;
    Ok(value.trim_end_matches(['\r', '\n']).to_string())
}

struct ScopedEnvVars {
    previous: Vec<(String, Option<std::ffi::OsString>)>,
}

impl ScopedEnvVars {
    fn set(vars: &HashMap<String, String>) -> Self {
        let mut previous = Vec::new();
        for (name, value) in vars {
            previous.push((name.clone(), std::env::var_os(name)));
            // SAFETY: proxy startup is performed before the sandboxed command is
            // launched. The values are restored immediately after the proxy has
            // loaded its credential store.
            unsafe { std::env::set_var(name, value) };
        }
        Self { previous }
    }
}

impl Drop for ScopedEnvVars {
    fn drop(&mut self) {
        for (name, value) in self.previous.drain(..).rev() {
            match value {
                Some(value) => {
                    // SAFETY: see ScopedEnvVars::set.
                    unsafe { std::env::set_var(name, value) };
                }
                None => {
                    // SAFETY: see ScopedEnvVars::set.
                    unsafe { std::env::remove_var(name) };
                }
            }
        }
    }
}

fn endpoint_policy_to_proxy_policy(
    config: &CommandPoliciesConfig,
    policy: &EndpointPolicyConfig,
) -> ProxyEndpointPolicyConfig {
    ProxyEndpointPolicyConfig {
        default: endpoint_default_to_proxy(config, &policy.default),
        deny: policy
            .deny
            .iter()
            .map(|rule| endpoint_rule_to_proxy(config, rule))
            .collect(),
        approve: policy
            .approve
            .iter()
            .map(|rule| endpoint_rule_to_proxy(config, rule))
            .collect(),
        allow: policy
            .allow
            .iter()
            .map(|rule| endpoint_rule_to_proxy(config, rule))
            .collect(),
    }
}

fn validate_endpoint_policy_approval_routes(
    config: &CommandPoliciesConfig,
    credential_name: &str,
    policy: &EndpointPolicyConfig,
) -> Result<()> {
    if endpoint_decision_is_approve(&policy.default) {
        let backend = default_backend_name(&policy.default);
        validate_endpoint_approval_backend(config, credential_name, backend)?;
    }
    for rule in &policy.approve {
        validate_endpoint_approval_backend(config, credential_name, rule.backend.as_deref())?;
    }
    Ok(())
}

fn endpoint_decision_is_approve(decision: &PolicyDecisionConfig) -> bool {
    match decision {
        PolicyDecisionConfig::Decision(decision) => *decision == PolicyDecision::Approve,
        PolicyDecisionConfig::RoutedApproval(route) => route.decision == PolicyDecision::Approve,
    }
}

fn default_backend_name(default: &PolicyDecisionConfig) -> Option<&str> {
    match default {
        PolicyDecisionConfig::Decision(_) => None,
        PolicyDecisionConfig::RoutedApproval(route) => route.backend.as_deref(),
    }
}

fn validate_endpoint_approval_backend(
    config: &CommandPoliciesConfig,
    credential_name: &str,
    backend: Option<&str>,
) -> Result<()> {
    let backend_name = backend
        .or(config.approval_defaults.backend.as_deref())
        .ok_or_else(|| {
            NonoError::ConfigParse(format!(
                "tool-sandbox proxy credential '{credential_name}' endpoint_policy approve route requires an approval backend"
            ))
        })?;
    if !config.approval_backends.contains_key(backend_name) {
        return Err(NonoError::ConfigParse(format!(
            "tool-sandbox proxy credential '{credential_name}' endpoint_policy references unknown approval backend '{backend_name}'"
        )));
    };
    Ok(())
}

fn endpoint_default_to_proxy(
    config: &CommandPoliciesConfig,
    default: &PolicyDecisionConfig,
) -> ProxyEndpointPolicyDefault {
    match default {
        PolicyDecisionConfig::Decision(decision) => ProxyEndpointPolicyDefault {
            decision: policy_decision_to_proxy(decision),
            backend: None,
            timeout_secs: config.approval_defaults.timeout_secs,
        },
        PolicyDecisionConfig::RoutedApproval(route) => ProxyEndpointPolicyDefault {
            decision: policy_decision_to_proxy(&route.decision),
            backend: route.backend.clone(),
            timeout_secs: resolve_approval_timeout(
                config,
                route.backend.as_deref(),
                route.timeout_secs,
            ),
        },
    }
}

fn endpoint_rule_to_proxy(
    config: &CommandPoliciesConfig,
    rule: &crate::command_policy::EndpointRuleConfig,
) -> ProxyEndpointPolicyRule {
    ProxyEndpointPolicyRule {
        method: rule.method.clone(),
        path: rule.path.clone(),
        backend: rule.backend.clone(),
        reason: rule.reason.clone(),
        timeout_secs: resolve_approval_timeout(config, rule.backend.as_deref(), rule.timeout_secs),
    }
}

fn resolve_approval_timeout(
    config: &CommandPoliciesConfig,
    backend: Option<&str>,
    explicit_timeout: Option<u64>,
) -> Option<u64> {
    explicit_timeout
        .or_else(|| {
            backend
                .or(config.approval_defaults.backend.as_deref())
                .and_then(|name| config.approval_backends.get(name))
                .and_then(|backend| backend.timeout_secs)
        })
        .or(config.approval_defaults.timeout_secs)
}

fn policy_decision_to_proxy(decision: &PolicyDecision) -> ProxyEndpointPolicyDecision {
    match decision {
        PolicyDecision::Deny => ProxyEndpointPolicyDecision::Deny,
        PolicyDecision::Approve => ProxyEndpointPolicyDecision::Approve,
        PolicyDecision::Allow => ProxyEndpointPolicyDecision::Allow,
    }
}

/// Parse a `--allow-domain` CLI argument into an `AllowDomainEntry`.
///
/// Accepts either:
/// - A plain hostname: `github.com` → `Plain("github.com")`
/// - A URL with a path pattern: `https://github.com/atko-cic/**` →
///   `WithEndpoints { domain: "github.com", endpoints: [{method: "*", path: "/atko-cic/**"}] }`
fn parse_allow_domain_arg(input: &str) -> crate::profile::AllowDomainEntry {
    if let Ok(parsed) = url::Url::parse(input) {
        let domain = parsed.host_str().unwrap_or(input).to_string();
        let path = parsed.path();
        if path.is_empty() || path == "/" {
            crate::profile::AllowDomainEntry::Plain(domain)
        } else {
            crate::profile::AllowDomainEntry::WithEndpoints {
                domain,
                endpoints: vec![nono_proxy::config::EndpointRule {
                    method: "*".to_string(),
                    path: path.to_string(),
                }],
            }
        }
    } else {
        crate::profile::AllowDomainEntry::Plain(input.to_string())
    }
}

pub(crate) fn merge_dedup_ports(a: &[u16], b: &[u16]) -> Vec<u16> {
    let mut ports = a.to_vec();
    ports.extend_from_slice(b);
    ports.sort_unstable();
    ports.dedup();
    ports
}

pub(crate) fn build_proxy_config_from_flags(
    proxy: &ProxyLaunchOptions,
) -> Result<nono_proxy::config::ProxyConfig> {
    let net_policy_json = crate::config::embedded::embedded_network_policy_json();
    let net_policy = network_policy::load_network_policy(net_policy_json)?;

    let mut resolved = if let Some(ref profile_name) = proxy.network_profile {
        network_policy::resolve_network_profile(&net_policy, profile_name)?
    } else {
        network_policy::ResolvedNetworkPolicy {
            hosts: Vec::new(),
            suffixes: Vec::new(),
            routes: Vec::new(),
            profile_credentials: Vec::new(),
        }
    };

    let mut all_credentials = resolved.profile_credentials.clone();
    for cred in &proxy.credentials {
        if !all_credentials.contains(cred) {
            all_credentials.push(cred.clone());
        }
    }

    let mut routes = network_policy::resolve_credentials(
        &net_policy,
        &all_credentials,
        &proxy.custom_credentials,
    )?;

    let (mut plain_hosts, endpoint_routes) =
        network_policy::partition_allow_domain(&net_policy, &proxy.allow_domain)?;
    // Endpoint-restricted domains need filter allowlist access so the proxy
    // can reach upstream after TLS interception (h2 checks the filter at
    // connection setup, before per-stream route matching).
    for route in &endpoint_routes {
        if let Some(ref hp) = route.upstream.strip_prefix("https://") {
            plain_hosts.push(hp.to_string());
        } else if let Some(ref hp) = route.upstream.strip_prefix("http://") {
            plain_hosts.push(hp.to_string());
        }
    }
    routes.extend(endpoint_routes);
    resolved.routes = routes;

    let mut proxy_config = network_policy::build_proxy_config(&resolved, &plain_hosts);
    proxy_config.strict_filter = proxy.network_block;

    if let Some(ref addr) = proxy.upstream_proxy {
        proxy_config.external_proxy = Some(nono_proxy::config::ExternalProxyConfig {
            address: addr.clone(),
            auth: None,
            bypass_hosts: proxy.upstream_bypass.clone(),
        });
    }

    if let Some(port) = proxy.proxy_port {
        proxy_config.bind_port = port;
    }

    proxy_config.ca_validity = proxy.proxy_ca_validity;
    proxy_config.leaf_validity = proxy.proxy_leaf_validity;

    Ok(proxy_config)
}

pub(crate) fn start_proxy_runtime(
    proxy: &ProxyLaunchOptions,
    caps: &mut CapabilitySet,
) -> Result<ActiveProxyRuntime> {
    if !proxy.active {
        return Ok(ActiveProxyRuntime {
            env_vars: Vec::new(),
            tool_sandbox_credential_env_vars: BTreeMap::new(),
            tool_sandbox_trust_bundle_paths: Vec::new(),
            handle: None,
        });
    }

    let _source_env_guard = ScopedEnvVars::set(&proxy.proxy_source_env_vars);
    let mut proxy_config = build_proxy_config_from_flags(proxy)?;
    proxy_config.direct_connect_ports = caps.tcp_connect_ports().to_vec();

    // Wire up TLS interception: pick a session-scoped directory for the
    // ephemeral CA bundle and merge any parent `SSL_CERT_FILE` so corporate
    // trust survives our env-var override.
    if let Some(dir) = prepare_intercept_ca_dir()? {
        proxy_config.intercept_ca_dir = Some(dir);
        proxy_config.intercept_parent_ca_pems = read_parent_ssl_cert_file();
    }

    #[cfg(target_os = "macos")]
    if proxy.trust_proxy_ca {
        if proxy_config.intercept_ca_dir.is_some() {
            let validity = proxy
                .proxy_ca_validity
                .unwrap_or(nono_proxy::tls_intercept::ca::CA_VALIDITY_DEFAULT);
            proxy_config.preloaded_ca = crate::macos_trust::load_or_generate_proxy_ca(validity);
        } else {
            tracing::warn!(
                "--trust-proxy-ca has no effect without TLS-intercepting credential routes"
            );
        }
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| NonoError::SandboxInit(format!("Failed to start proxy runtime: {}", e)))?;
    let approval_registry =
        crate::approval_runtime::build_proxy_approval_registry(proxy.command_policies.as_ref())?;
    let handle = rt
        .block_on(async {
            nono_proxy::server::start_with_approval_registry(
                proxy_config.clone(),
                approval_registry,
            )
            .await
        })
        .map_err(|e| NonoError::SandboxInit(format!("Failed to start proxy: {}", e)))?;

    let port = handle.port;
    if proxy.allow_bind_ports.is_empty() {
        info!("Network proxy started on localhost:{}", port);
    } else {
        info!(
            "Network proxy started on localhost:{}, bind ports: {:?}",
            port, proxy.allow_bind_ports
        );
    }

    // Per-route diagnostic banner. Lifts credential resolution status —
    // including misses — to the user-visible info level so the silent
    // "WARN at debug" failure mode (issue #797) becomes immediately
    // discoverable.
    let route_rows = handle.route_diagnostics(&proxy_config);
    if !route_rows.is_empty() {
        info!("Proxy routes:");
        for (prefix, summary) in &route_rows {
            info!("  /{}  {}", prefix, summary);
        }
        if handle.intercept_ca_path().is_some() {
            info!(
                "TLS interception trust bundle: {}",
                handle
                    .intercept_ca_path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
            );
        }
    }
    caps.set_network_mode_mut(nono::NetworkMode::ProxyOnly {
        port,
        bind_ports: proxy.allow_bind_ports.clone(),
    });

    // Grant the sandboxed child a read capability on the ephemeral
    // trust bundle so `SSL_CERT_FILE` etc. are actually openable after
    // the sandbox is applied. Only when interception is active.
    //
    // The bundle lives under `~/.nono/sessions/...`, which the protected-root
    // deny rules (`emit_protected_root_deny_rules`) cover with
    // `(deny file-read-data (subpath "~/.nono"))`. On macOS, action specificity
    // beats path specificity in Seatbelt: a `file-read*` allow on a literal
    // path is shadowed by an action-specific `file-read-data` deny on a
    // containing subpath. To override, emit action-matching `file-read-data`
    // and `file-read-metadata` allows as platform rules, which are appended
    // after the deny and win by both action specificity and last-match.
    //
    // On Linux, Landlock cannot express deny-within-allow, so the protected-
    // root rules don't shadow the grant; a plain FS cap is sufficient.
    let tool_sandbox_trust_bundle_paths = handle
        .intercept_ca_path()
        .map(|path| vec![path.to_path_buf()])
        .unwrap_or_default();

    if let Some(ca_path) = handle.intercept_ca_path() {
        #[cfg(target_os = "macos")]
        {
            let path_str = crate::policy::path_to_utf8(ca_path)?;
            let escaped = crate::policy::escape_seatbelt_path(path_str)?;
            caps.add_platform_rule(format!("(allow file-read-data (literal \"{}\"))", escaped))?;
            caps.add_platform_rule(format!(
                "(allow file-read-metadata (literal \"{}\"))",
                escaped
            ))?;
        }
        #[cfg(not(target_os = "macos"))]
        {
            caps.allow_file_mut(ca_path, AccessMode::Read)
                .map_err(|e| {
                    NonoError::SandboxInit(format!(
                        "Failed to grant read capability on TLS-intercept bundle '{}': {}",
                        ca_path.display(),
                        e
                    ))
                })?;
        }
        debug!(
            "Granted sandboxed child read access to TLS-intercept trust bundle: {}",
            ca_path.display()
        );
    }

    let mut env_vars: Vec<(String, String)> = Vec::new();
    for (key, value) in handle.env_vars() {
        env_vars.push((key, value));
    }

    let credential_env_vars = handle.credential_env_vars(&proxy_config);
    let tool_sandbox_credential_env_vars = scoped_tool_sandbox_proxy_credential_env_vars(
        proxy,
        &proxy_config,
        &credential_env_vars,
        port,
    )?;
    let tool_sandbox_env_var_names = tool_sandbox_proxy_env_var_names(proxy, &proxy_config);
    for (key, value) in credential_env_vars {
        if tool_sandbox_env_var_names.contains(&key) {
            continue;
        }
        env_vars.push((key, value));
    }

    std::mem::forget(rt);

    Ok(ActiveProxyRuntime {
        env_vars,
        tool_sandbox_credential_env_vars,
        tool_sandbox_trust_bundle_paths,
        handle: Some(handle),
    })
}

fn tool_sandbox_proxy_env_var_names(
    proxy: &ProxyLaunchOptions,
    proxy_config: &nono_proxy::config::ProxyConfig,
) -> HashSet<String> {
    let mut names = HashSet::new();
    for credential_name in &proxy.tool_sandbox_proxy_credentials {
        let prefix = credential_name.trim_matches('/');
        names.insert(format!("{}_BASE_URL", prefix.to_uppercase()));
        if let Some(base_url_env_var) = proxy.tool_sandbox_base_url_env_vars.get(credential_name) {
            names.insert(base_url_env_var.clone());
        }
        for route in proxy_config
            .routes
            .iter()
            .filter(|route| route.prefix.trim_matches('/') == prefix)
        {
            if let Some(env_var) = &route.env_var {
                names.insert(env_var.clone());
            } else if let Some(credential_key) = &route.credential_key
                && !credential_key.contains("://")
            {
                names.insert(credential_key.to_uppercase());
            }
        }
    }
    names
}

fn scoped_tool_sandbox_proxy_credential_env_vars(
    proxy: &ProxyLaunchOptions,
    proxy_config: &nono_proxy::config::ProxyConfig,
    credential_env_vars: &[(String, String)],
    port: u16,
) -> Result<BTreeMap<String, Vec<(String, String)>>> {
    let mut scoped = BTreeMap::new();
    for credential_name in &proxy.tool_sandbox_proxy_credentials {
        let prefix = credential_name.trim_matches('/');
        let route = proxy_config
            .routes
            .iter()
            .find(|route| route.prefix.trim_matches('/') == prefix)
            .ok_or_else(|| {
                NonoError::SandboxInit(format!(
                    "tool-sandbox proxy credential '{credential_name}' did not produce a proxy route"
                ))
            })?;
        let env_var = route.env_var.as_ref().ok_or_else(|| {
            NonoError::ConfigParse(format!(
                "tool-sandbox proxy credential '{credential_name}' missing env_var"
            ))
        })?;
        let token_value = credential_env_vars
            .iter()
            .find(|(key, _)| key == env_var)
            .map(|(_, value)| value.clone())
            .ok_or_else(|| {
                NonoError::SandboxInit(format!(
                    "tool-sandbox proxy credential '{credential_name}' is unavailable to the proxy"
                ))
            })?;

        let mut env_vars = vec![(env_var.clone(), token_value)];
        if let Some(base_url_env_var) = proxy.tool_sandbox_base_url_env_vars.get(credential_name) {
            env_vars.push((
                base_url_env_var.clone(),
                format!("http://127.0.0.1:{}/{}", port, prefix),
            ));
        }
        scoped.insert(credential_name.clone(), env_vars);
    }
    Ok(scoped)
}

/// Choose the directory the proxy will write the TLS-intercept trust bundle
/// into. Conventionally `~/.nono/sessions/<random>/`, kept owner-only.
///
/// Returns `Ok(None)` if no `HOME` is set (rare edge cases like CI). We log
/// a warning rather than failing because TLS interception is opt-in: a
/// missing directory just means CONNECTs to L7-bearing routes will get the
/// usual 403, which is a coherent fallback rather than a hard error.
fn prepare_intercept_ca_dir() -> Result<Option<PathBuf>> {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => {
            warn!(
                "no $HOME found; skipping TLS-intercept setup (CONNECTs to L7-bearing routes \
                 will be denied with 403)"
            );
            return Ok(None);
        }
    };
    // PID + start-time-nanos disambiguates concurrent invocations without
    // pulling in a randomness dep. Cryptographic uniqueness isn't the
    // goal; we just need two `nono` processes started at the same second
    // not to share a directory.
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let suffix = format!("{}-{:09}", pid, nanos);
    let dir = home
        .join(".nono")
        .join("sessions")
        .join(format!("intercept-{}", suffix));
    if let Err(e) = std::fs::create_dir_all(&dir) {
        warn!(
            "failed to create TLS-intercept dir '{}': {}; skipping interception",
            dir.display(),
            e
        );
        return Ok(None);
    }
    set_intercept_ca_dir_permissions(&dir)?;
    Ok(Some(dir))
}

#[cfg(unix)]
fn set_intercept_ca_dir_permissions(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
        NonoError::SandboxInit(format!(
            "failed to set owner-only permissions on TLS-intercept dir '{}': {e}",
            dir.display()
        ))
    })
}

#[cfg(not(unix))]
fn set_intercept_ca_dir_permissions(_dir: &Path) -> Result<()> {
    Ok(())
}

/// Read the parent process's `SSL_CERT_FILE`, if set, so any corporate
/// CAs configured on the host are merged into the intercept trust bundle.
///
/// On any read failure we log at warn and return `None` — the proxy will
/// continue without merging, and the agent may lose trust for corp hosts.
/// Aborting feels too aggressive: nono is opt-in, and TLS interception is
/// opt-in within nono, so a corp-trust mismatch is a recoverable misconfig
/// not a security failure.
fn read_parent_ssl_cert_file() -> Option<Vec<u8>> {
    let path = std::env::var_os("SSL_CERT_FILE")?;
    match std::fs::read(&path) {
        Ok(bytes) => {
            debug!(
                "merging parent SSL_CERT_FILE '{}' ({} bytes) into TLS-intercept trust bundle",
                std::path::Path::new(&path).display(),
                bytes.len()
            );
            Some(bytes)
        }
        Err(e) => {
            warn!(
                "could not read parent SSL_CERT_FILE '{}': {} — corporate CAs configured on \
                 the host will not be trusted by the sandboxed child",
                std::path::Path::new(&path).display(),
                e
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_policy::{
        ApprovalBackendConfig, ApprovalBackendType, CommandCredentialConfig,
        CommandCredentialGrantPolicyConfig, CommandPolicyConfig, EndpointRuleConfig,
    };

    #[cfg(unix)]
    #[test]
    fn set_intercept_ca_dir_permissions_fails_closed() -> Result<()> {
        let tmp = tempfile::tempdir().map_err(NonoError::Io)?;
        let missing = tmp.path().join("missing");

        let err = set_intercept_ca_dir_permissions(&missing)
            .err()
            .ok_or_else(|| {
                NonoError::SandboxInit("expected missing intercept dir to fail".to_string())
            })?;

        assert!(matches!(err, NonoError::SandboxInit(_)));
        assert!(err.to_string().contains("TLS-intercept dir"));
        Ok(())
    }

    #[test]
    fn test_parse_allow_domain_arg_plain_hostname() {
        let entry = parse_allow_domain_arg("github.com");
        assert_eq!(
            entry,
            crate::profile::AllowDomainEntry::Plain("github.com".to_string())
        );
    }

    #[test]
    fn test_parse_allow_domain_arg_url_with_path() {
        let entry = parse_allow_domain_arg("https://github.com/atko-cic/**");
        match entry {
            crate::profile::AllowDomainEntry::WithEndpoints { domain, endpoints } => {
                assert_eq!(domain, "github.com");
                assert_eq!(endpoints.len(), 1);
                assert_eq!(endpoints[0].method, "*");
                assert_eq!(endpoints[0].path, "/atko-cic/**");
            }
            _ => panic!("expected WithEndpoints, got: {:?}", entry),
        }
    }

    #[test]
    fn test_parse_allow_domain_arg_url_root_is_plain() {
        let entry = parse_allow_domain_arg("https://api.example.com/");
        assert_eq!(
            entry,
            crate::profile::AllowDomainEntry::Plain("api.example.com".to_string())
        );
    }

    #[test]
    fn test_parse_allow_domain_arg_url_no_path_is_plain() {
        let entry = parse_allow_domain_arg("https://api.example.com");
        assert_eq!(
            entry,
            crate::profile::AllowDomainEntry::Plain("api.example.com".to_string())
        );
    }

    #[test]
    fn test_parse_allow_domain_arg_deep_path() {
        let entry = parse_allow_domain_arg("https://github.com/org/repo/tree/**");
        match entry {
            crate::profile::AllowDomainEntry::WithEndpoints { domain, endpoints } => {
                assert_eq!(domain, "github.com");
                assert_eq!(endpoints[0].path, "/org/repo/tree/**");
            }
            _ => panic!("expected WithEndpoints"),
        }
    }

    /// `network_block: true` must set `strict_filter` on the generated `ProxyConfig`.
    #[test]
    fn test_build_proxy_config_propagates_network_block_to_strict_filter() {
        let proxy = ProxyLaunchOptions {
            active: true,
            network_block: true,
            ..ProxyLaunchOptions::default()
        };
        let config = build_proxy_config_from_flags(&proxy).expect("build_proxy_config_from_flags");
        assert!(
            config.strict_filter,
            "network_block: true must set strict_filter on ProxyConfig"
        );
    }

    #[test]
    fn test_build_proxy_config_strict_filter_off_when_no_block() {
        let proxy = ProxyLaunchOptions {
            active: true,
            network_block: false,
            ..ProxyLaunchOptions::default()
        };
        let config = build_proxy_config_from_flags(&proxy).expect("build_proxy_config_from_flags");
        assert!(
            !config.strict_filter,
            "strict_filter must default off when network_block is false"
        );
    }

    #[test]
    fn tool_sandbox_proxy_credentials_create_endpoint_filtered_route() -> Result<()> {
        let mut policies = CommandPoliciesConfig::default();
        policies.credentials.insert(
            "github-api".to_string(),
            CommandCredentialConfig {
                credential_type: CommandCredentialType::Proxy,
                upstream: Some("https://api.github.com".to_string()),
                credential_key: Some("github-token".to_string()),
                env_var: Some("GITHUB_TOKEN".to_string()),
                base_url_env_var: Some("GITHUB_API_BASE_URL".to_string()),
                inject_header: Some("Authorization".to_string()),
                credential_format: Some("Bearer {}".to_string()),
                tls_ca: Some("/tmp/github-ca.pem".to_string()),
                ..CommandCredentialConfig::default()
            },
        );
        policies.commands.insert(
            "claude".to_string(),
            CommandPolicyConfig {
                sandbox: Some(CommandSandboxConfig {
                    credentials: vec![CommandCredentialGrantConfig::Policy(
                        CommandCredentialGrantPolicyConfig {
                            name: "github-api".to_string(),
                            endpoint_policy: Some(EndpointPolicyConfig {
                                default: PolicyDecisionConfig::Decision(PolicyDecision::Deny),
                                allow: vec![EndpointRuleConfig {
                                    method: "GET".to_string(),
                                    path: "/repos/example/**".to_string(),
                                    backend: None,
                                    reason: None,
                                    timeout_secs: None,
                                }],
                                ..EndpointPolicyConfig::default()
                            }),
                        },
                    )],
                    ..CommandSandboxConfig::default()
                }),
                ..CommandPolicyConfig::default()
            },
        );

        let mut credentials = Vec::new();
        let mut custom_credentials = HashMap::new();
        let mut proxy_source_env_vars = HashMap::new();
        let mut base_url_env_vars = HashMap::new();
        let mut tool_sandbox_proxy_credentials = HashSet::new();
        extend_proxy_settings_with_tool_sandbox_credentials(
            Some(&policies),
            &mut credentials,
            &mut custom_credentials,
            &mut proxy_source_env_vars,
            &mut base_url_env_vars,
            &mut tool_sandbox_proxy_credentials,
        )?;

        assert_eq!(credentials, vec!["github-api".to_string()]);
        assert!(tool_sandbox_proxy_credentials.contains("github-api"));
        assert_eq!(
            base_url_env_vars.get("github-api"),
            Some(&"GITHUB_API_BASE_URL".to_string())
        );
        let route = custom_credentials
            .get("github-api")
            .ok_or_else(|| NonoError::ConfigParse("missing github-api route".to_string()))?;
        assert_eq!(route.upstream, "https://api.github.com");
        assert_eq!(route.credential_key, Some("github-token".to_string()));
        assert_eq!(route.env_var, Some("GITHUB_TOKEN".to_string()));
        assert_eq!(route.tls_ca, Some("/tmp/github-ca.pem".to_string()));
        assert!(route.endpoint_rules.is_empty());
        let endpoint_policy = route
            .endpoint_policy
            .as_ref()
            .ok_or_else(|| NonoError::ConfigParse("missing endpoint policy".to_string()))?;
        assert_eq!(endpoint_policy.allow.len(), 1);
        assert_eq!(endpoint_policy.allow[0].method, "GET");
        assert_eq!(endpoint_policy.allow[0].path, "/repos/example/**");

        Ok(())
    }

    #[test]
    fn tool_sandbox_proxy_credentials_require_policy_grants() -> Result<()> {
        let mut policies = CommandPoliciesConfig::default();
        policies.credentials.insert(
            "github-api".to_string(),
            CommandCredentialConfig {
                credential_type: CommandCredentialType::Proxy,
                upstream: Some("https://api.github.com".to_string()),
                env_var: Some("GITHUB_TOKEN".to_string()),
                ..CommandCredentialConfig::default()
            },
        );
        policies.commands.insert(
            "claude".to_string(),
            CommandPolicyConfig {
                sandbox: Some(CommandSandboxConfig {
                    credentials: vec![CommandCredentialGrantConfig::Name("github-api".to_string())],
                    ..CommandSandboxConfig::default()
                }),
                ..CommandPolicyConfig::default()
            },
        );

        let mut credentials = Vec::new();
        let mut custom_credentials = HashMap::new();
        let mut proxy_source_env_vars = HashMap::new();
        let mut base_url_env_vars = HashMap::new();
        let mut tool_sandbox_proxy_credentials = HashSet::new();
        let err = extend_proxy_settings_with_tool_sandbox_credentials(
            Some(&policies),
            &mut credentials,
            &mut custom_credentials,
            &mut proxy_source_env_vars,
            &mut base_url_env_vars,
            &mut tool_sandbox_proxy_credentials,
        )
        .err()
        .ok_or_else(|| NonoError::ConfigParse("expected proxy grant failure".to_string()))?;

        assert!(err.to_string().contains("must include endpoint_policy"));
        Ok(())
    }

    #[test]
    fn tool_sandbox_proxy_endpoint_policy_preserves_deny_and_approve_routes() {
        let policy = EndpointPolicyConfig {
            default: PolicyDecisionConfig::Decision(PolicyDecision::Deny),
            deny: vec![EndpointRuleConfig {
                method: "DELETE".to_string(),
                path: "/repos/example/**".to_string(),
                backend: None,
                reason: Some("destructive endpoint".to_string()),
                timeout_secs: None,
            }],
            approve: vec![EndpointRuleConfig {
                method: "POST".to_string(),
                path: "/repos/example/*/issues".to_string(),
                backend: Some("terminal".to_string()),
                reason: None,
                timeout_secs: None,
            }],
            allow: vec![EndpointRuleConfig {
                method: "GET".to_string(),
                path: "/repos/example/**".to_string(),
                backend: None,
                reason: None,
                timeout_secs: None,
            }],
        };

        let proxy_policy =
            endpoint_policy_to_proxy_policy(&CommandPoliciesConfig::default(), &policy);

        assert_eq!(proxy_policy.deny.len(), 1);
        assert_eq!(proxy_policy.deny[0].method, "DELETE");
        assert_eq!(proxy_policy.approve.len(), 1);
        assert_eq!(proxy_policy.approve[0].method, "POST");
        assert_eq!(
            proxy_policy.approve[0].backend,
            Some("terminal".to_string())
        );
        assert_eq!(proxy_policy.allow.len(), 1);
    }

    #[test]
    fn tool_sandbox_proxy_approve_routes_accept_configured_backend() -> Result<()> {
        let mut policies = CommandPoliciesConfig::default();
        policies.approval_defaults.backend = Some("security-review".to_string());
        policies.approval_backends.insert(
            "security-review".to_string(),
            ApprovalBackendConfig {
                backend_type: ApprovalBackendType::Webhook,
                url: Some("https://approvals.internal.example/tool_sandbox".to_string()),
                timeout_secs: Some(10),
                mode: None,
                backends: Vec::new(),
            },
        );
        policies.credentials.insert(
            "internal-api".to_string(),
            CommandCredentialConfig {
                credential_type: CommandCredentialType::Proxy,
                upstream: Some("https://api.internal.example".to_string()),
                credential_key: Some("internal-token".to_string()),
                env_var: Some("INTERNAL_API_TOKEN".to_string()),
                ..CommandCredentialConfig::default()
            },
        );
        policies.commands.insert(
            "claude".to_string(),
            CommandPolicyConfig {
                sandbox: Some(CommandSandboxConfig {
                    credentials: vec![CommandCredentialGrantConfig::Policy(
                        CommandCredentialGrantPolicyConfig {
                            name: "internal-api".to_string(),
                            endpoint_policy: Some(EndpointPolicyConfig {
                                approve: vec![EndpointRuleConfig {
                                    method: "POST".to_string(),
                                    path: "/v1/tasks/*/comments".to_string(),
                                    backend: None,
                                    reason: Some("comment write".to_string()),
                                    timeout_secs: Some(5),
                                }],
                                ..EndpointPolicyConfig::default()
                            }),
                        },
                    )],
                    ..CommandSandboxConfig::default()
                }),
                ..CommandPolicyConfig::default()
            },
        );

        let mut credentials = Vec::new();
        let mut custom_credentials = HashMap::new();
        let mut proxy_source_env_vars = HashMap::new();
        let mut base_url_env_vars = HashMap::new();
        let mut tool_sandbox_proxy_credentials = HashSet::new();
        extend_proxy_settings_with_tool_sandbox_credentials(
            Some(&policies),
            &mut credentials,
            &mut custom_credentials,
            &mut proxy_source_env_vars,
            &mut base_url_env_vars,
            &mut tool_sandbox_proxy_credentials,
        )?;

        let route = custom_credentials
            .get("internal-api")
            .ok_or_else(|| NonoError::ConfigParse("missing internal-api route".to_string()))?;
        let endpoint_policy = route
            .endpoint_policy
            .as_ref()
            .ok_or_else(|| NonoError::ConfigParse("missing endpoint policy".to_string()))?;
        assert_eq!(endpoint_policy.approve.len(), 1);
        assert_eq!(endpoint_policy.approve[0].timeout_secs, Some(5));

        Ok(())
    }

    #[test]
    fn tool_sandbox_proxy_env_vars_are_scoped_out_of_global_env() -> Result<()> {
        let mut proxy = ProxyLaunchOptions::default();
        proxy
            .tool_sandbox_proxy_credentials
            .insert("github-api".to_string());
        proxy
            .tool_sandbox_base_url_env_vars
            .insert("github-api".to_string(), "GITHUB_API_BASE_URL".to_string());

        let mut proxy_config = nono_proxy::config::ProxyConfig::default();
        proxy_config.routes.push(nono_proxy::config::RouteConfig {
            prefix: "github-api".to_string(),
            upstream: "https://api.github.com".to_string(),
            credential_key: Some("github-token".to_string()),
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: Some("Bearer {}".to_string()),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: Some("GITHUB_TOKEN".to_string()),
            endpoint_rules: Vec::new(),
            endpoint_policy: None,
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: None,
        });
        let credential_env_vars = vec![
            (
                "GITHUB-API_BASE_URL".to_string(),
                "http://127.0.0.1:7777/github-api".to_string(),
            ),
            ("GITHUB_TOKEN".to_string(), "phantom-token".to_string()),
        ];

        let scoped = scoped_tool_sandbox_proxy_credential_env_vars(
            &proxy,
            &proxy_config,
            &credential_env_vars,
            7777,
        )?;
        let env_names = tool_sandbox_proxy_env_var_names(&proxy, &proxy_config);

        assert!(env_names.contains("GITHUB-API_BASE_URL"));
        assert!(env_names.contains("GITHUB_API_BASE_URL"));
        assert!(env_names.contains("GITHUB_TOKEN"));
        assert_eq!(
            scoped.get("github-api"),
            Some(&vec![
                ("GITHUB_TOKEN".to_string(), "phantom-token".to_string()),
                (
                    "GITHUB_API_BASE_URL".to_string(),
                    "http://127.0.0.1:7777/github-api".to_string()
                ),
            ])
        );
        Ok(())
    }
}
