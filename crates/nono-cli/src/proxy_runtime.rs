use std::time::Duration;

use crate::cli::SandboxArgs;
use crate::launch_runtime::ProxyLaunchOptions;
use crate::network_approval::{NetworkApprovalBackend, NetworkApprovalMode};
use crate::network_policy;
use crate::sandbox_prepare::{validate_external_proxy_bypass, PreparedSandbox};
use nono::{CapabilitySet, HostFilter, NonoError, Result, RuntimeHostFilter};
use tracing::info;
use tracing::warn;

pub(crate) struct ActiveProxyRuntime {
    pub(crate) env_vars: Vec<(String, String)>,
    pub(crate) handle: Option<nono_proxy::server::ProxyHandle>,
    pub(crate) approval_backend: Option<std::sync::Arc<NetworkApprovalBackend>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct EffectiveProxySettings {
    pub(crate) network_profile: Option<String>,
    pub(crate) allow_domain: Vec<String>,
    pub(crate) reject_domain: Vec<String>,
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
    let reject_domain = effective_proxy.reject_domain;
    let credentials = effective_proxy.credentials;
    let allow_bind_ports = merge_dedup_ports(&prepared.listen_ports, &args.allow_bind);

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

    let approval_mode =
        resolve_network_approval_mode(args, prepared.profile_network_approval_mode.as_deref());

    Ok(ProxyLaunchOptions {
        active,
        network_profile,
        profile_name: args.profile.clone(),
        allow_domain,
        reject_domain,
        credentials,
        custom_credentials: prepared.custom_credentials.clone(),
        upstream_proxy,
        upstream_bypass,
        allow_bind_ports,
        proxy_port: args.proxy_port,
        open_url_origins: prepared.open_url_origins.clone(),
        open_url_allow_localhost: prepared.open_url_allow_localhost,
        allow_launch_services_active: prepared.allow_launch_services_active,
        network_approval_mode: approval_mode,
        network_approval_timeout_secs: resolve_approval_timeout_secs(
            prepared.profile_network_approval_timeout_secs,
        ),
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
            reject_domain: Vec::new(),
            credentials: Vec::new(),
        };
    }

    let network_profile = args
        .network_profile
        .clone()
        .or_else(|| prepared.network_profile.clone());
    let mut allow_domain = prepared.allow_domain.clone();
    allow_domain.extend(args.allow_proxy.clone());
    let reject_domain = prepared.reject_domain.clone();
    let mut credentials = prepared.credentials.clone();
    credentials.extend(args.proxy_credential.clone());

    EffectiveProxySettings {
        network_profile,
        allow_domain,
        reject_domain,
        credentials,
    }
}

pub(crate) fn merge_dedup_ports(a: &[u16], b: &[u16]) -> Vec<u16> {
    let mut ports = a.to_vec();
    ports.extend_from_slice(b);
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn resolve_network_approval_mode(
    args: &SandboxArgs,
    profile_approval_mode: Option<&str>,
) -> NetworkApprovalMode {
    use crate::cli::NetworkApprovalArg;

    if let Some(ref mode) = args.network_approval {
        match mode {
            NetworkApprovalArg::Ask => NetworkApprovalMode::Ask,
        }
    } else if let Ok(val) = std::env::var("NONO_NETWORK_APPROVAL") {
        match val.to_lowercase().as_str() {
            "ask" => NetworkApprovalMode::Ask,
            _ => NetworkApprovalMode::Off,
        }
    } else if let Some(mode) = profile_approval_mode {
        match mode.to_lowercase().as_str() {
            "ask" => NetworkApprovalMode::Ask,
            _ => NetworkApprovalMode::Off,
        }
    } else if let Ok(Some(config)) = crate::config::user::load_user_config() {
        match config
            .network
            .approval_mode
            .as_deref()
            .unwrap_or("off")
            .to_lowercase()
            .as_str()
        {
            "ask" => NetworkApprovalMode::Ask,
            _ => NetworkApprovalMode::Off,
        }
    } else {
        NetworkApprovalMode::Off
    }
}

fn resolve_approval_timeout_secs(profile_timeout: Option<u64>) -> u64 {
    if let Ok(val) = std::env::var("NONO_NETWORK_APPROVAL_TIMEOUT") {
        if let Ok(secs) = val.parse::<u64>() {
            return secs.clamp(5, 300);
        }
    }
    if let Some(secs) = profile_timeout {
        return secs.clamp(5, 300);
    }
    if let Ok(Some(config)) = crate::config::user::load_user_config() {
        if let Some(secs) = config.network.approval_timeout_secs {
            return secs.clamp(5, 300);
        }
    }
    60
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

    let routes = network_policy::resolve_credentials(
        &net_policy,
        &all_credentials,
        &proxy.custom_credentials,
    )?;
    resolved.routes = routes;

    let expanded_allow_domain =
        network_policy::expand_proxy_allow(&net_policy, &proxy.allow_domain);
    let mut proxy_config =
        network_policy::build_proxy_config(&resolved, &expanded_allow_domain, &proxy.reject_domain);

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

    Ok(proxy_config)
}

pub(crate) fn start_proxy_runtime(
    proxy: &ProxyLaunchOptions,
    caps: &mut CapabilitySet,
) -> Result<ActiveProxyRuntime> {
    if !proxy.active {
        return Ok(ActiveProxyRuntime {
            env_vars: Vec::new(),
            handle: None,
            approval_backend: None,
        });
    }

    let proxy_config = build_proxy_config_from_flags(proxy)?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| NonoError::SandboxInit(format!("Failed to start proxy runtime: {}", e)))?;

    let (approval_backend, approval_tx, runtime_filter) = match proxy.network_approval_mode {
        NetworkApprovalMode::Off => (None, None, None),
        NetworkApprovalMode::Ask => {
            let host_filter = HostFilter::deny_all();
            let runtime_filter = RuntimeHostFilter::new(host_filter);
            let proxy_runtime_filter =
                nono_proxy::filter::RuntimeProxyFilter::new(runtime_filter.clone());

            let (tx, mut rx) = tokio::sync::mpsc::channel::<nono_proxy::ApprovalChannelRequest>(16);

            let config_writer = proxy
                .network_profile
                .as_deref()
                .or(proxy.profile_name.as_deref())
                .map(crate::network_approval::ConfigWriter::new);

            let backend = NetworkApprovalBackend::new(
                proxy.network_approval_mode,
                runtime_filter,
                proxy.network_approval_timeout_secs,
                config_writer,
            );
            let backend_arc = std::sync::Arc::new(backend);

            let backend_clone = std::sync::Arc::clone(&backend_arc);
            rt.spawn(async move {
                while let Some(req) = rx.recv().await {
                    let decision = backend_clone
                        .request_network_approval_async(&req.request)
                        .await;
                    let _ = req.response_tx.send(decision);
                }
            });

            (Some(backend_arc), Some(tx), Some(proxy_runtime_filter))
        }
    };

    let handle = rt
        .block_on(async {
            nono_proxy::server::start_with_approval(
                proxy_config.clone(),
                runtime_filter,
                approval_tx,
                std::process::id(),
                &format!("nono-{}", std::process::id()),
                Duration::from_secs(proxy.network_approval_timeout_secs),
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
    caps.set_network_mode_mut(nono::NetworkMode::ProxyOnly {
        port,
        bind_ports: proxy.allow_bind_ports.clone(),
    });

    let mut env_vars: Vec<(String, String)> = Vec::new();
    for (key, value) in handle.env_vars() {
        env_vars.push((key, value));
    }

    for (key, value) in handle.credential_env_vars(&proxy_config) {
        env_vars.push((key, value));
    }

    std::mem::forget(rt);

    Ok(ActiveProxyRuntime {
        env_vars,
        handle: Some(handle),
        approval_backend,
    })
}
