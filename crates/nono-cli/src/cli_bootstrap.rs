use crate::cli::{Cli, Commands};
use crate::{config, theme};
use tracing_subscriber::EnvFilter;

pub(crate) fn normalize_legacy_flag_env_vars() {
    copy_legacy_env_var("NONO_NET_BLOCK", "NONO_BLOCK_NET");
    copy_legacy_env_var("NONO_NET_ALLOW", "NONO_ALLOW_NET");
    copy_legacy_env_var("NONO_ALLOW_PROXY", "NONO_ALLOW_DOMAIN");
    copy_legacy_env_var("NONO_PROXY_ALLOW", "NONO_ALLOW_DOMAIN");
    copy_legacy_env_var("NONO_PROXY_CREDENTIAL", "NONO_CREDENTIAL");
    copy_legacy_env_var("NONO_EXTERNAL_PROXY", "NONO_UPSTREAM_PROXY");
    copy_legacy_env_var("NONO_EXTERNAL_PROXY_BYPASS", "NONO_UPSTREAM_BYPASS");
}

pub(crate) fn collect_legacy_network_warnings() -> Vec<String> {
    let mut warnings = Vec::new();
    let args: Vec<String> = std::env::args().skip(1).collect();

    for (legacy, replacement) in [
        ("--allow-net", Some("network is unrestricted by default")),
        ("--net-allow", Some("network is unrestricted by default")),
        ("--allow-proxy", Some("--allow-domain")),
        ("--proxy-allow", Some("--allow-domain")),
        ("--proxy-credential", Some("--credential")),
        ("--allow-bind", Some("--listen-port")),
        ("--allow-port", Some("--open-port")),
        ("--external-proxy", Some("--upstream-proxy")),
        ("--external-proxy-bypass", Some("--upstream-bypass")),
        ("--net-block", Some("--block-net")),
    ] {
        if args
            .iter()
            .any(|arg| arg == legacy || arg.starts_with(&format!("{legacy}=")))
        {
            let message = if let Some(replacement) = replacement {
                format!("Warning: `{legacy}` is deprecated; use `{replacement}` instead.")
            } else {
                format!("Warning: `{legacy}` is deprecated.")
            };
            warnings.push(message);
        }
    }

    for (legacy, replacement) in [
        ("NONO_NET_BLOCK", "NONO_BLOCK_NET"),
        ("NONO_NET_ALLOW", "NONO_ALLOW_NET"),
        ("NONO_ALLOW_PROXY", "NONO_ALLOW_DOMAIN"),
        ("NONO_PROXY_ALLOW", "NONO_ALLOW_DOMAIN"),
        ("NONO_PROXY_CREDENTIAL", "NONO_CREDENTIAL"),
        ("NONO_EXTERNAL_PROXY", "NONO_UPSTREAM_PROXY"),
        ("NONO_EXTERNAL_PROXY_BYPASS", "NONO_UPSTREAM_BYPASS"),
    ] {
        if std::env::var_os(legacy).is_some() {
            warnings.push(format!(
                "Warning: `{legacy}` is deprecated; use `{replacement}` instead."
            ));
        }
    }

    warnings
}

pub(crate) fn print_legacy_network_warnings(warnings: &[String], silent: bool) {
    if silent {
        return;
    }

    for warning in warnings {
        eprintln!("  [nono] {warning}");
    }
}

pub(crate) fn init_theme(cli: &Cli) {
    let config_theme = config::user::load_user_config()
        .ok()
        .flatten()
        .and_then(|config| config.ui.theme);

    theme::init(cli.theme.as_deref(), config_theme.as_deref());
}

pub(crate) fn init_tracing(cli: &Cli) {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_filter(cli))
        .with_target(false)
        .init();
}

fn copy_legacy_env_var(old: &str, new: &str) {
    if std::env::var_os(new).is_some() {
        return;
    }

    if let Some(value) = std::env::var_os(old) {
        std::env::set_var(new, value);
    }
}

fn tracing_filter(cli: &Cli) -> EnvFilter {
    cli_log_override(cli)
        .map(EnvFilter::new)
        .unwrap_or_else(|| {
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"))
        })
}

fn cli_log_override(cli: &Cli) -> Option<&'static str> {
    if cli.silent {
        return Some("off");
    }

    match cli_verbosity(cli) {
        0 => None,
        1 => Some("info"),
        2 => Some("debug"),
        _ => Some("trace"),
    }
}

fn cli_verbosity(cli: &Cli) -> u8 {
    match &cli.command {
        Commands::Learn(args) => args.verbose,
        Commands::Run(args) => args.sandbox.verbose,
        Commands::Shell(args) => args.sandbox.verbose,
        Commands::Wrap(args) => args.sandbox.verbose,
        Commands::Setup(args) => args.verbose,
        Commands::Why(_)
        | Commands::Rollback(_)
        | Commands::Trust(_)
        | Commands::Audit(_)
        | Commands::Ps(_)
        | Commands::Stop(_)
        | Commands::Detach(_)
        | Commands::Attach(_)
        | Commands::Logs(_)
        | Commands::Inspect(_)
        | Commands::Prune(_)
        | Commands::Policy(_)
        | Commands::Profile(_)
        | Commands::OpenUrlHelper(_) => 0,
    }
}
