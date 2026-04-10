use crate::cli::SandboxArgs;
use crate::{hooks, profile};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub(crate) struct PreparedProfile {
    pub(crate) loaded_profile: Option<profile::Profile>,
    pub(crate) capability_elevation: bool,
    #[cfg(target_os = "linux")]
    pub(crate) wsl2_proxy_policy: profile::Wsl2ProxyPolicy,
    pub(crate) workdir_access: Option<profile::WorkdirAccess>,
    pub(crate) rollback_exclude_patterns: Vec<String>,
    pub(crate) rollback_exclude_globs: Vec<String>,
    pub(crate) network_profile: Option<String>,
    pub(crate) allow_domain: Vec<String>,
    pub(crate) credentials: Vec<String>,
    pub(crate) custom_credentials: HashMap<String, profile::CustomCredentialDef>,
    pub(crate) upstream_proxy: Option<String>,
    pub(crate) upstream_bypass: Vec<String>,
    pub(crate) listen_ports: Vec<u16>,
    pub(crate) open_url_origins: Vec<String>,
    pub(crate) open_url_allow_localhost: bool,
    pub(crate) allow_launch_services: bool,
    pub(crate) allow_gpu: bool,
    pub(crate) allow_parent_of_protected: bool,
    pub(crate) override_deny_paths: Vec<PathBuf>,
}

#[derive(Clone, Copy)]
struct PrepareProfileOptions {
    install_hooks: bool,
    hook_output_silent: bool,
}

fn install_profile_hooks(profile: &profile::Profile, silent: bool) {
    if profile.hooks.hooks.is_empty() {
        return;
    }

    match hooks::install_profile_hooks(&profile.hooks.hooks) {
        Ok(results) => {
            for (target, result) in results {
                match result {
                    hooks::HookInstallResult::Installed => {
                        if !silent {
                            eprintln!(
                                "  Installing {} hook to ~/.claude/hooks/nono-hook.sh",
                                target
                            );
                        }
                    }
                    hooks::HookInstallResult::Updated => {
                        if !silent {
                            eprintln!("  Updating {} hook (new version available)", target);
                        }
                    }
                    hooks::HookInstallResult::AlreadyInstalled
                    | hooks::HookInstallResult::Skipped => {}
                }
            }
        }
        Err(e) => {
            tracing::warn!("Failed to install profile hooks: {}", e);
            if !silent {
                eprintln!("  Warning: Failed to install hooks: {}", e);
            }
        }
    }
}

fn expand_override_deny_path(path: &Path, workdir: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();
    let expanded = profile::expand_vars(&path_str, workdir).unwrap_or_else(|_| path.to_path_buf());
    if expanded.exists() {
        expanded.canonicalize().unwrap_or(expanded)
    } else {
        expanded
    }
}

fn collect_override_deny_paths(
    loaded_profile: Option<&profile::Profile>,
    cli_override_deny: &[PathBuf],
    workdir: &Path,
) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = loaded_profile
        .map(|profile| {
            profile
                .policy
                .override_deny
                .iter()
                .filter_map(|template| {
                    profile::expand_vars(template, workdir)
                        .ok()
                        .map(|expanded| {
                            if expanded.exists() {
                                expanded.canonicalize().unwrap_or(expanded)
                            } else {
                                expanded
                            }
                        })
                })
                .collect()
        })
        .unwrap_or_default();

    for path in cli_override_deny {
        let canonical = expand_override_deny_path(path, workdir);
        if !paths.contains(&canonical) {
            paths.push(canonical);
        }
    }

    paths
}

fn prepare_profile_with_options(
    args: &SandboxArgs,
    workdir: &Path,
    options: PrepareProfileOptions,
) -> crate::Result<PreparedProfile> {
    let loaded_profile = if let Some(ref profile_name) = args.profile {
        let profile = profile::load_profile(profile_name)?;
        if options.install_hooks {
            install_profile_hooks(&profile, options.hook_output_silent);
        }
        Some(profile)
    } else {
        None
    };

    Ok(PreparedProfile {
        capability_elevation: loaded_profile
            .as_ref()
            .and_then(|profile| profile.security.capability_elevation)
            .unwrap_or(false),
        #[cfg(target_os = "linux")]
        wsl2_proxy_policy: loaded_profile
            .as_ref()
            .and_then(|profile| profile.security.wsl2_proxy_policy)
            .unwrap_or_default(),
        workdir_access: loaded_profile
            .as_ref()
            .map(|profile| profile.workdir.access.clone()),
        rollback_exclude_patterns: loaded_profile
            .as_ref()
            .map(|profile| profile.rollback.exclude_patterns.clone())
            .unwrap_or_default(),
        rollback_exclude_globs: loaded_profile
            .as_ref()
            .map(|profile| profile.rollback.exclude_globs.clone())
            .unwrap_or_default(),
        network_profile: loaded_profile.as_ref().and_then(|profile| {
            profile
                .network
                .resolved_network_profile()
                .map(|value| value.to_string())
        }),
        allow_domain: loaded_profile
            .as_ref()
            .map(|profile| profile.network.allow_domain.clone())
            .unwrap_or_default(),
        credentials: loaded_profile
            .as_ref()
            .and_then(|profile| profile.network.credentials.clone())
            .unwrap_or_default(),
        custom_credentials: loaded_profile
            .as_ref()
            .map(|profile| profile.network.custom_credentials.clone())
            .unwrap_or_default(),
        upstream_proxy: loaded_profile
            .as_ref()
            .and_then(|profile| profile.network.upstream_proxy.clone()),
        upstream_bypass: loaded_profile
            .as_ref()
            .map(|profile| profile.network.upstream_bypass.clone())
            .unwrap_or_default(),
        listen_ports: loaded_profile
            .as_ref()
            .map(|profile| profile.network.listen_port.clone())
            .unwrap_or_default(),
        open_url_origins: loaded_profile
            .as_ref()
            .and_then(|profile| profile.open_urls.as_ref())
            .map(|open_urls| open_urls.allow_origins.clone())
            .unwrap_or_default(),
        open_url_allow_localhost: loaded_profile
            .as_ref()
            .and_then(|profile| profile.open_urls.as_ref())
            .map(|open_urls| open_urls.allow_localhost)
            .unwrap_or(false),
        allow_launch_services: loaded_profile
            .as_ref()
            .and_then(|profile| profile.allow_launch_services)
            .unwrap_or(false),
        allow_gpu: loaded_profile
            .as_ref()
            .and_then(|profile| profile.allow_gpu)
            .unwrap_or(false),
        allow_parent_of_protected: loaded_profile
            .as_ref()
            .and_then(|profile| profile.allow_parent_of_protected)
            .unwrap_or(false),
        override_deny_paths: collect_override_deny_paths(
            loaded_profile.as_ref(),
            &args.override_deny,
            workdir,
        ),
        loaded_profile,
    })
}

pub(crate) fn prepare_profile(
    args: &SandboxArgs,
    silent: bool,
    workdir: &Path,
) -> crate::Result<PreparedProfile> {
    prepare_profile_with_options(
        args,
        workdir,
        PrepareProfileOptions {
            install_hooks: true,
            hook_output_silent: silent,
        },
    )
}

pub(crate) fn prepare_profile_for_preflight(
    args: &SandboxArgs,
    workdir: &Path,
) -> crate::Result<PreparedProfile> {
    prepare_profile_with_options(
        args,
        workdir,
        PrepareProfileOptions {
            install_hooks: false,
            hook_output_silent: true,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn prepare_profile_for_preflight_matches_runtime_resolution() {
        let workdir = match tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("failed to create tempdir: {err}"),
        };
        let cli_override = workdir.path().join("cli-override");
        if let Err(err) = fs::create_dir_all(&cli_override) {
            panic!("failed to create CLI override path: {err}");
        }

        let profile_path = workdir.path().join("preflight-profile.json");
        if let Err(err) = fs::write(
            &profile_path,
            r#"{
                "extends": "default",
                "meta": { "name": "preflight-profile" },
                "workdir": { "access": "write" },
                "rollback": { "exclude_patterns": ["target"] },
                "network": {
                    "allow_domain": ["example.com"],
                    "upstream_bypass": ["localhost"],
                    "listen_port": [8080]
                },
                "policy": {
                    "override_deny": ["$WORKDIR/.git"]
                }
            }"#,
        ) {
            panic!("failed to write profile: {err}");
        }

        let args = SandboxArgs {
            profile: Some(profile_path.to_string_lossy().into_owned()),
            override_deny: vec![cli_override],
            ..SandboxArgs::default()
        };

        let runtime = match prepare_profile(&args, true, workdir.path()) {
            Ok(profile) => profile,
            Err(err) => panic!("runtime prepare_profile failed: {err}"),
        };
        let preflight = match prepare_profile_for_preflight(&args, workdir.path()) {
            Ok(profile) => profile,
            Err(err) => panic!("preflight prepare_profile failed: {err}"),
        };

        assert_eq!(runtime.capability_elevation, preflight.capability_elevation);
        #[cfg(target_os = "linux")]
        assert_eq!(runtime.wsl2_proxy_policy, preflight.wsl2_proxy_policy);
        assert_eq!(runtime.workdir_access, preflight.workdir_access);
        assert_eq!(
            runtime.rollback_exclude_patterns,
            preflight.rollback_exclude_patterns
        );
        assert_eq!(
            runtime.rollback_exclude_globs,
            preflight.rollback_exclude_globs
        );
        assert_eq!(runtime.network_profile, preflight.network_profile);
        assert_eq!(runtime.allow_domain, preflight.allow_domain);
        assert_eq!(runtime.credentials, preflight.credentials);
        assert_eq!(runtime.custom_credentials, preflight.custom_credentials);
        assert_eq!(runtime.upstream_proxy, preflight.upstream_proxy);
        assert_eq!(runtime.upstream_bypass, preflight.upstream_bypass);
        assert_eq!(runtime.listen_ports, preflight.listen_ports);
        assert_eq!(runtime.open_url_origins, preflight.open_url_origins);
        assert_eq!(
            runtime.open_url_allow_localhost,
            preflight.open_url_allow_localhost
        );
        assert_eq!(
            runtime.allow_launch_services,
            preflight.allow_launch_services
        );
        assert_eq!(runtime.allow_gpu, preflight.allow_gpu);
        assert_eq!(runtime.override_deny_paths, preflight.override_deny_paths);
        assert_eq!(
            runtime.loaded_profile.as_ref().map(|profile| {
                (
                    profile.meta.name.clone(),
                    profile.extends.clone(),
                    profile.security.groups.clone(),
                    profile.workdir.access.clone(),
                    profile.filesystem.allow.clone(),
                )
            }),
            preflight.loaded_profile.as_ref().map(|profile| {
                (
                    profile.meta.name.clone(),
                    profile.extends.clone(),
                    profile.security.groups.clone(),
                    profile.workdir.access.clone(),
                    profile.filesystem.allow.clone(),
                )
            })
        );
    }
}
