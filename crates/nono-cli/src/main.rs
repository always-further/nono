//! nono CLI - Capability-based sandbox for AI agents
//!
//! This is the CLI binary that uses the nono library for OS-level sandboxing.

mod audit_commands;
mod capability_ext;
mod cli;
mod config;
#[cfg(not(target_os = "windows"))]
mod exec_strategy;
#[cfg(target_os = "windows")]
#[path = "exec_strategy_windows.rs"]
mod exec_strategy;
mod hooks;
mod instruction_deny;
mod learn;
mod network_policy;
mod output;
mod policy;
mod policy_cmd;
mod profile;
mod profile_cmd;
mod protected_paths;
mod query_ext;
mod rollback_commands;
mod rollback_preflight;
mod rollback_session;
mod rollback_ui;
mod sandbox_state;
mod setup;
#[cfg(not(target_os = "windows"))]
mod terminal_approval;
mod theme;
mod trust_cmd;
#[cfg(not(target_os = "windows"))]
mod trust_intercept;
#[cfg(target_os = "windows")]
#[path = "trust_intercept_windows.rs"]
mod trust_intercept;
mod trust_keystore;
mod trust_scan;
mod update_check;
#[cfg(target_os = "windows")]
mod windows_wfp_contract;

use capability_ext::CapabilitySetExt;
use clap::Parser;
use cli::{
    Cli, Commands, LearnArgs, OpenUrlHelperArgs, RunArgs, SandboxArgs, SetupArgs, ShellArgs,
    WhyArgs, WhyOp, WrapArgs,
};
use colored::Colorize;
use nono::{AccessMode, CapabilitySet, FsCapability, NonoError, Result, Sandbox};
use profile::WorkdirAccess;
#[cfg(target_os = "windows")]
use std::collections::BTreeMap;
use std::ffi::OsString;
#[cfg(target_os = "windows")]
use std::process::Command;
use std::sync::Mutex;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

fn main() {
    let legacy_network_warnings = collect_legacy_network_warnings();
    normalize_legacy_flag_env_vars();
    let cli = Cli::parse();
    init_tracing(&cli);
    init_theme(&cli);
    print_legacy_network_warnings(&legacy_network_warnings, cli.silent);

    if let Err(e) = run(cli) {
        error!("{}", e);
        eprintln!("nono: {}", e);
        std::process::exit(1);
    }
}

fn normalize_legacy_flag_env_vars() {
    copy_legacy_env_var("NONO_NET_BLOCK", "NONO_BLOCK_NET");
    copy_legacy_env_var("NONO_NET_ALLOW", "NONO_ALLOW_NET");
    copy_legacy_env_var("NONO_ALLOW_PROXY", "NONO_ALLOW_DOMAIN");
    copy_legacy_env_var("NONO_PROXY_ALLOW", "NONO_ALLOW_DOMAIN");
    copy_legacy_env_var("NONO_PROXY_CREDENTIAL", "NONO_CREDENTIAL");
    copy_legacy_env_var("NONO_EXTERNAL_PROXY", "NONO_UPSTREAM_PROXY");
    copy_legacy_env_var("NONO_EXTERNAL_PROXY_BYPASS", "NONO_UPSTREAM_BYPASS");
}

fn copy_legacy_env_var(old: &str, new: &str) {
    if std::env::var_os(new).is_some() {
        return;
    }

    if let Some(value) = std::env::var_os(old) {
        std::env::set_var(new, value);
    }
}

fn collect_legacy_network_warnings() -> Vec<String> {
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

fn print_legacy_network_warnings(warnings: &[String], silent: bool) {
    if silent {
        return;
    }

    for warning in warnings {
        eprintln!("  [nono] {warning}");
    }
}

fn init_theme(cli: &Cli) {
    // Try loading config theme (best-effort, don't fail on config errors)
    let config_theme = config::user::load_user_config()
        .ok()
        .flatten()
        .and_then(|c| c.ui.theme);

    theme::init(cli.theme.as_deref(), config_theme.as_deref());
}

fn init_tracing(cli: &Cli) {
    let builder = || {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_filter(cli))
            .with_target(false)
    };

    if let Some(path) = &cli.log_file {
        match std::fs::File::create(path) {
            Ok(file) => {
                let writer = Mutex::new(file);
                builder().with_ansi(false).with_writer(writer).init();
            }
            Err(e) => {
                eprintln!("nono: failed to open log file {}: {e}", path.display());
                std::process::exit(1);
            }
        }
    } else {
        builder().init();
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
        | Commands::Policy(_)
        | Commands::Profile(_)
        | Commands::OpenUrlHelper(_) => 0,
    }
}

fn run(cli: Cli) -> Result<()> {
    // Start background update check (non-blocking, 3s timeout)
    let mut update_handle = if !cli.silent {
        update_check::start_background_check()
    } else {
        None
    };

    match cli.command {
        Commands::Learn(args) => run_learn(*args, cli.silent),
        Commands::Run(args) => {
            output::print_banner(cli.silent);
            show_update_notification(&mut update_handle, cli.silent);
            run_sandbox(*args, cli.silent)
        }
        Commands::Shell(args) => {
            output::print_banner(cli.silent);
            show_update_notification(&mut update_handle, cli.silent);
            run_shell(*args, cli.silent)
        }
        Commands::Wrap(args) => {
            output::print_banner(cli.silent);
            show_update_notification(&mut update_handle, cli.silent);
            run_wrap(*args, cli.silent)
        }
        Commands::Why(args) => {
            show_update_notification(&mut update_handle, cli.silent);
            run_why(*args)
        }
        Commands::Setup(args) => {
            output::print_banner(cli.silent);
            show_update_notification(&mut update_handle, cli.silent);
            run_setup(args)
        }
        Commands::Rollback(args) => {
            show_update_notification(&mut update_handle, cli.silent);
            rollback_commands::run_rollback(args)
        }
        Commands::Trust(args) => {
            show_update_notification(&mut update_handle, cli.silent);
            trust_cmd::run_trust(args)
        }
        Commands::Audit(args) => {
            show_update_notification(&mut update_handle, cli.silent);
            audit_commands::run_audit(args)
        }
        Commands::Policy(args) => {
            show_update_notification(&mut update_handle, cli.silent);
            policy_cmd::run_policy(args)
        }
        Commands::Profile(args) => {
            show_update_notification(&mut update_handle, cli.silent);
            profile_cmd::run_profile(args)
        }
        Commands::OpenUrlHelper(args) => run_open_url_helper(args),
    }
}

/// Consume an update check handle and print notification if available
fn show_update_notification(handle: &mut Option<update_check::UpdateCheckHandle>, silent: bool) {
    if let Some(h) = handle.take() {
        if let Some(info) = h.take_result() {
            output::print_update_notification(&info, silent);
        }
    }
}

/// Internal helper invoked via BROWSER env var (Linux) or PATH shim (macOS).
///
/// Reads the supervisor socket fd from `NONO_SUPERVISOR_FD`, sends an
/// `OpenUrl` IPC message, waits for the response, and exits with the
/// appropriate exit code.
#[cfg(not(target_os = "windows"))]
fn run_open_url_helper(args: OpenUrlHelperArgs) -> Result<()> {
    use nono::supervisor::types::{SupervisorMessage, SupervisorResponse};
    use nono::supervisor::{SupervisorSocket, UrlOpenRequest};
    use std::os::fd::FromRawFd;
    use std::os::unix::net::UnixStream;

    let fd_str = std::env::var("NONO_SUPERVISOR_FD").map_err(|_| {
        NonoError::SandboxInit(
            "NONO_SUPERVISOR_FD not set. open-url-helper must be invoked inside a nono sandbox."
                .to_string(),
        )
    })?;

    let fd: i32 = fd_str.parse().map_err(|_| {
        NonoError::SandboxInit(format!("Invalid NONO_SUPERVISOR_FD value: {fd_str}"))
    })?;

    // SAFETY: The fd was inherited from the parent process via fork+exec.
    // It is a valid Unix domain socket created by the supervisor.
    let stream = unsafe { UnixStream::from(std::os::unix::io::OwnedFd::from_raw_fd(fd)) };
    let mut sock = SupervisorSocket::from_stream(stream);

    let request = UrlOpenRequest {
        request_id: format!("url-{}", std::process::id()),
        url: args.url.clone(),
        child_pid: std::process::id(),
        session_id: String::new(),
    };

    sock.send_message(&SupervisorMessage::OpenUrl(request))?;

    let response = sock.recv_response()?;
    match response {
        SupervisorResponse::UrlOpened { success: true, .. } => Ok(()),
        SupervisorResponse::UrlOpened {
            success: false,
            error,
            ..
        } => {
            let msg = error.unwrap_or_else(|| "Unknown error".to_string());
            Err(NonoError::SandboxInit(format!(
                "Supervisor denied URL open: {msg}"
            )))
        }
        other => Err(NonoError::SandboxInit(format!(
            "Unexpected supervisor response: {other:?}"
        ))),
    }
}

#[cfg(target_os = "windows")]
fn run_open_url_helper(_args: OpenUrlHelperArgs) -> Result<()> {
    Err(NonoError::UnsupportedPlatform(
        "open-url-helper is not implemented on Windows yet".to_string(),
    ))
}

/// Set up nono on this system
fn run_setup(args: SetupArgs) -> Result<()> {
    let runner = setup::SetupRunner::new(&args);
    runner.run()
}

/// Learn mode: trace file accesses to discover required paths
fn run_learn(args: LearnArgs, silent: bool) -> Result<()> {
    // Warn user that the command runs unrestricted
    if !silent {
        eprintln!(
            "{}",
            "WARNING: nono learn runs the command WITHOUT any sandbox restrictions.".yellow()
        );
        eprintln!(
            "{}",
            "The command will have full access to your system to discover required paths.".yellow()
        );
        #[cfg(target_os = "macos")]
        eprintln!(
            "{}",
            "NOTE: macOS learn mode uses fs_usage which requires sudo.".yellow()
        );
        eprintln!();
        eprint!("Continue? [y/N] ");

        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| NonoError::LearnError(format!("Failed to read input: {}", e)))?;

        let input = input.trim().to_lowercase();
        if input != "y" && input != "yes" {
            eprintln!("Aborted.");
            return Ok(());
        }
        eprintln!();
    }

    eprintln!("nono learn - Tracing file accesses and network activity...\n");

    let result = learn::run_learn(&args)?;

    if args.json {
        println!("{}", result.to_json()?);
    } else {
        println!("{}", result.to_summary());
    }

    if (result.has_paths() || result.has_network_activity()) && !silent && !args.json {
        offer_save_profile(&result, &args.command)?;
    } else if result.has_paths() || result.has_network_activity() {
        if result.has_paths() {
            eprintln!(
                "\nTo use these paths, add them to your profile or use --read/--write/--allow flags."
            );
        }
        if result.has_network_activity() {
            eprintln!("Network activity detected. Use --block-net to restrict network access.");
        }
    }

    Ok(())
}

/// Prompt the user to save discovered paths as a named profile
fn offer_save_profile(result: &learn::LearnResult, command: &[String]) -> Result<()> {
    let cmd_name = command
        .first()
        .and_then(|c| std::path::Path::new(c).file_name())
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            NonoError::LearnError("Cannot derive profile name from command".to_string())
        })?;

    eprintln!();
    eprint!(
        "Save as profile? Enter a name (or press Enter to skip) [{}]: ",
        cmd_name
    );

    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|e| NonoError::LearnError(format!("Failed to read input: {}", e)))?;

    let input = input.trim();
    let profile_name = if input.is_empty() { cmd_name } else { input };

    // Validate profile name: alphanumeric, hyphens, underscores only
    if !profile_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        eprintln!(
            "{}",
            "Invalid profile name. Use only letters, numbers, hyphens, and underscores.".red()
        );
        return Ok(());
    }

    let profile_json = result.to_profile(profile_name, cmd_name)?;

    // Resolve the profiles directory
    let config_dir = profile::resolve_user_config_dir()?;
    let profiles_dir = config_dir.join("nono").join("profiles");
    std::fs::create_dir_all(&profiles_dir).map_err(|e| {
        NonoError::LearnError(format!(
            "Failed to create profiles directory {}: {}",
            profiles_dir.display(),
            e
        ))
    })?;

    let profile_path = profiles_dir.join(format!("{}.json", profile_name));

    // Check if file already exists
    if profile_path.exists() {
        eprint!(
            "Profile '{}' already exists. Overwrite? [y/N] ",
            profile_name
        );
        let mut confirm = String::new();
        std::io::stdin()
            .read_line(&mut confirm)
            .map_err(|e| NonoError::LearnError(format!("Failed to read input: {}", e)))?;
        if !confirm.trim().eq_ignore_ascii_case("y") {
            eprintln!("Skipped.");
            return Ok(());
        }
    }

    std::fs::write(&profile_path, profile_json).map_err(|e| {
        NonoError::LearnError(format!(
            "Failed to write profile to {}: {}",
            profile_path.display(),
            e
        ))
    })?;

    eprintln!("\n{} {}", "Profile saved:".green(), profile_path.display());
    eprintln!(
        "Run with: {} {} -- {}",
        "nono run --profile".bold(),
        profile_name,
        command.join(" ")
    );

    Ok(())
}

/// Check why a path or network operation would be allowed or denied
fn run_why(args: WhyArgs) -> Result<()> {
    use query_ext::{print_result, query_network, query_path, QueryResult};
    use sandbox_state::load_sandbox_state;

    // Build capability set from args or load from sandbox state.
    // Also collect overridden paths so the query can skip sensitive-path checks
    // for paths that have been exempted via override_deny.
    let (caps, overridden_paths): (CapabilitySet, Vec<std::path::PathBuf>) = if args.self_query {
        // Inside sandbox - load from state file
        match load_sandbox_state() {
            Some(state) => {
                let paths = state.override_deny_as_paths();
                (state.to_caps()?, paths)
            }
            None => {
                let result = QueryResult::NotSandboxed {
                    message: "Not running inside a nono sandbox".to_string(),
                };
                if args.json {
                    let json = serde_json::to_string_pretty(&result).map_err(|e| {
                        NonoError::ConfigParse(format!("JSON serialization failed: {}", e))
                    })?;
                    println!("{}", json);
                } else {
                    print_result(&result);
                }
                return Ok(());
            }
        }
    } else if let Some(ref profile_name) = args.profile {
        // Load from profile
        let prof = profile::load_profile(profile_name)?;
        let workdir = args
            .workdir
            .clone()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| std::path::PathBuf::from("."));

        let sandbox_args = SandboxArgs {
            allow: args.allow.clone(),
            read: args.read.clone(),
            write: args.write.clone(),
            allow_file: args.allow_file.clone(),
            read_file: args.read_file.clone(),
            write_file: args.write_file.clone(),
            block_net: args.block_net,
            workdir: args.workdir.clone(),
            ..SandboxArgs::default()
        };

        // Collect overridden paths from profile for the query
        let mut override_paths = Vec::new();
        for tmpl in &prof.policy.override_deny {
            let expanded = profile::expand_vars(tmpl, &workdir)?;
            if expanded.exists() {
                if let Ok(c) = expanded.canonicalize() {
                    override_paths.push(c);
                }
            } else {
                override_paths.push(expanded);
            }
        }

        let (mut caps, needs_unlink) = CapabilitySet::from_profile(&prof, &workdir, &sandbox_args)?;
        if needs_unlink {
            crate::policy::apply_unlink_overrides(&mut caps);
        }
        (caps, override_paths)
    } else {
        let sandbox_args = SandboxArgs {
            allow: args.allow.clone(),
            read: args.read.clone(),
            write: args.write.clone(),
            allow_file: args.allow_file.clone(),
            read_file: args.read_file.clone(),
            write_file: args.write_file.clone(),
            block_net: args.block_net,
            workdir: args.workdir.clone(),
            ..SandboxArgs::default()
        };

        let (mut caps, needs_unlink) = CapabilitySet::from_args(&sandbox_args)?;
        if needs_unlink {
            crate::policy::apply_unlink_overrides(&mut caps);
        }
        (caps, vec![])
    };

    // Execute the query
    let result = if let Some(ref path) = args.path {
        let op = match args.op {
            Some(WhyOp::Read) => AccessMode::Read,
            Some(WhyOp::Write) => AccessMode::Write,
            Some(WhyOp::ReadWrite) => AccessMode::ReadWrite,
            None => AccessMode::Read, // Default to read
        };
        query_path(path, op, &caps, &overridden_paths)?
    } else if let Some(ref host) = args.host {
        query_network(host, args.port, &caps)
    } else {
        return Err(NonoError::ConfigParse(
            "--path or --host is required".to_string(),
        ));
    };

    // Output result
    if args.json {
        let json = serde_json::to_string_pretty(&result)
            .map_err(|e| NonoError::ConfigParse(format!("JSON serialization failed: {}", e)))?;
        println!("{}", json);
    } else {
        print_result(&result);
    }

    Ok(())
}

/// Run a command inside the sandbox
fn run_sandbox(run_args: RunArgs, silent: bool) -> Result<()> {
    let args = run_args.sandbox;
    let command = run_args.command;
    #[cfg(not(target_os = "windows"))]
    let no_diagnostics = run_args.no_diagnostics;
    let rollback = run_args.rollback;
    let no_rollback_prompt = run_args.no_rollback_prompt;
    let no_audit = run_args.no_audit;
    let trust_override = run_args.trust_override;

    // Check if we have a command to run
    if command.is_empty() {
        return Err(NonoError::NoCommand);
    }

    let mut command_iter = command.into_iter();
    let program = OsString::from(command_iter.next().ok_or(NonoError::NoCommand)?);
    let cmd_args: Vec<OsString> = command_iter.map(OsString::from).collect();

    // Dry run mode - just show what would happen
    if args.dry_run {
        let prepared = prepare_sandbox(&args, silent)?;
        validate_external_proxy_bypass(&args, &prepared)?;
        if !prepared.secrets.is_empty() && !silent {
            eprintln!(
                "  Would inject {} credential(s) as environment variables",
                prepared.secrets.len()
            );
        }
        let support = Sandbox::support_info();
        output::print_dry_run(&program, &cmd_args, &support, silent);
        return Ok(());
    }

    let mut prepared = prepare_sandbox(&args, silent)?;
    let mut merged_skip_dirs = prepared.skip_dirs.clone();
    merged_skip_dirs.extend(run_args.skip_dir.iter().cloned());

    if prepared.allow_launch_services_active {
        print_allow_launch_services_warning(silent);
    }

    // CLI --capability-elevation overrides profile setting
    if run_args.capability_elevation {
        prepared.capability_elevation = true;
    }

    // On WSL2, seccomp user notification returns EBUSY (microsoft/WSL#9548).
    // Disable features that depend on it and warn the user.
    // If the kernel banner already showed the WSL2 docs link (Landlock < V4),
    // keep the message brief. If V4+ arrives but EBUSY persists, include the URL.
    #[cfg(target_os = "linux")]
    if nono::is_wsl2() && prepared.capability_elevation {
        let banner_showed_wsl2_link = nono::Sandbox::detect_abi()
            .ok()
            .is_some_and(|abi| !abi.has_network() || !abi.has_ioctl_dev() || !abi.has_scoping());
        if banner_showed_wsl2_link {
            eprintln!("  [nono] WSL2: capability elevation disabled");
        } else {
            eprintln!(
                "  [nono] WSL2: capability elevation disabled \
                 (https://nono.sh/docs/cli/internals/wsl2)"
            );
        }
        prepared.capability_elevation = false;
    }

    // Compute scan root for trust policy discovery and instruction file scanning.
    let scan_root = args
        .workdir
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    // Pre-exec trust scan: verify instruction files before the agent reads them.
    // Must run BEFORE sandbox application so we can still read bundles and policy.
    // The trust_policy and scan_result are preserved for macOS deny rule injection.
    let (trust_policy, scan_result) = if trust_override {
        if !silent {
            eprintln!(
                "  {}",
                "WARNING: --trust-override active, skipping instruction file verification."
                    .yellow()
            );
        }
        (None, None)
    } else {
        let trust_policy = trust_scan::load_scan_policy(&scan_root, false, &merged_skip_dirs)?;
        let result =
            trust_scan::run_pre_exec_scan(&scan_root, &trust_policy, silent, &merged_skip_dirs)?;
        if !result.results.is_empty() {
            info!(
                "Trust scan: {} verified, {} blocked, {} warned ({} total files)",
                result.verified,
                result.blocked,
                result.warned,
                result.results.len()
            );
        }
        if !result.should_proceed() {
            return Err(NonoError::TrustVerification {
                path: String::new(),
                reason: "instruction files failed trust verification".to_string(),
            });
        }

        // Write-protect verified instruction files in the Seatbelt profile (macOS).
        // Literal deny-write rules make verified files structurally immutable at the
        // kernel level, preventing the agent from tampering with them mid-session.
        let verified = result.verified_paths();
        instruction_deny::write_protect_verified_files(&mut prepared.caps, &verified)?;

        // Add verified multi-subject files as read-only capabilities.
        // This makes the files structurally immutable post-sandbox on both
        // platforms (Landlock on Linux, Seatbelt on macOS). No runtime digest
        // re-checking is needed.
        for path in &verified {
            match FsCapability::new_file(path, AccessMode::Read) {
                Ok(mut cap) => {
                    cap.source = nono::CapabilitySource::System;
                    prepared.caps.add_fs(cap);
                }
                Err(e) => {
                    warn!(
                        "Failed to create capability for verified subject {}: {}",
                        path.display(),
                        e
                    );
                }
            }
        }

        (Some(trust_policy), Some(result))
    };
    let _ = &scan_result; // suppress unused warning on non-macOS

    // Enable sandbox extensions for transparent capability expansion in supervised mode,
    // but only when the profile opts into capability elevation. Without elevation,
    // supervised mode runs with static capabilities (no seccomp, no PTY, no prompts).
    #[cfg(target_os = "linux")]
    if prepared.capability_elevation {
        prepared.caps.set_extensions_enabled(true);
    }

    let trust_interception_active = trust_interception_active(trust_policy.as_ref());

    // Extract write-protected paths (signed instruction files) for diagnostic output
    #[cfg(not(target_os = "windows"))]
    let verified_protected_paths = scan_result
        .as_ref()
        .map(|r| r.verified_paths())
        .unwrap_or_default();

    let effective_proxy = resolve_effective_proxy_settings(&args, &prepared);
    let network_profile = effective_proxy.network_profile;
    let allow_domain = effective_proxy.allow_domain;
    let credentials = effective_proxy.credentials;
    let effective_listen_ports = merge_dedup_ports(&prepared.listen_ports, &args.allow_bind);

    // Resolve effective upstream proxy: --allow-net clears it (same as other
    // proxy settings), otherwise CLI overrides profile.
    let effective_upstream_proxy = if args.allow_net {
        None
    } else {
        args.external_proxy
            .clone()
            .or_else(|| prepared.upstream_proxy.clone())
    };

    // Resolve effective bypass hosts: cleared by --allow-net, otherwise
    // CLI --upstream-proxy wins (use CLI bypass only), otherwise merge
    // profile + CLI bypass hosts.
    let effective_bypass = if args.allow_net {
        Vec::new()
    } else if args.external_proxy.is_some() {
        args.external_proxy_bypass.clone()
    } else {
        let mut bypass = prepared.upstream_bypass.clone();
        bypass.extend(args.external_proxy_bypass.clone());
        bypass
    };

    // Validate: bypass hosts require an external proxy (from CLI or profile)
    validate_external_proxy_bypass(&args, &prepared)?;

    // The proxy is needed when the network mode is ProxyOnly OR when there are
    // credential routes to inject. However, --block-net takes precedence: if
    // network is explicitly blocked, the proxy must NOT activate since that
    // would re-enable network access through the proxy's localhost listener.
    let proxy_active = if matches!(prepared.caps.network_mode(), nono::NetworkMode::Blocked) {
        if !credentials.is_empty()
            || network_profile.is_some()
            || !allow_domain.is_empty()
            || effective_upstream_proxy.is_some()
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
            || effective_upstream_proxy.is_some()
    };

    // Split --rollback-exclude values: glob metacharacters route to filename
    // matching, everything else routes to component-based pattern matching.
    let is_glob = |v: &String| v.contains('*') || v.contains('?') || v.contains('[');
    let (cli_exclude_globs, cli_exclude_patterns): (Vec<_>, Vec<_>) =
        run_args.rollback_exclude.into_iter().partition(is_glob);

    let mut merged_patterns = prepared.rollback_exclude_patterns;
    merged_patterns.extend(cli_exclude_patterns);

    let mut merged_globs = prepared.rollback_exclude_globs;
    merged_globs.extend(cli_exclude_globs);

    // Precheck: if --rollback-dest was given, verify the destination (or a
    // parent) is covered by a writable sandbox capability. Fail before the
    // sandbox is locked in so the user gets a clear, actionable error.
    //
    // When the dest doesn't exist yet (will be created by create_dir_all),
    // walk up to the nearest existing ancestor for canonicalization so that
    // symlinks are resolved consistently with capability resolved paths.
    if let Some(ref dest) = run_args.rollback_dest {
        let dest_abs = {
            let mut p = if dest.is_absolute() {
                dest.clone()
            } else {
                std::env::current_dir()
                    .map_err(|e| NonoError::SandboxInit(format!("Failed to get cwd: {e}")))?
                    .join(dest)
            };
            loop {
                match p.canonicalize() {
                    Ok(canonical) => break canonical,
                    Err(_) => match p.parent() {
                        Some(parent) => p = parent.to_path_buf(),
                        None => break p,
                    },
                }
            }
        };
        let covered = prepared.caps.fs_capabilities().iter().any(|cap| {
            matches!(cap.access, AccessMode::Write | AccessMode::ReadWrite)
                && dest_abs.starts_with(&cap.resolved)
        });
        if !covered {
            eprintln!(
                "nono: --rollback-dest '{}' is not covered by sandbox write permissions.\n\
                 Add --allow {} to grant access, or omit --rollback-dest to use the default platform rollback path.",
                dest.display(),
                dest.display()
            );
            std::process::exit(1);
        }
    }

    // Select execution strategy. Supervised mode is needed when any feature
    // requires a parent process: rollback snapshots, network proxy, capability
    // elevation (seccomp + PTY), or trust interception. Direct mode (exec,
    // nono disappears) gives the child native terminal access — required for
    // TUI programs like Claude Code that call setRawMode.
    let strategy = select_exec_strategy(
        rollback,
        proxy_active,
        prepared.capability_elevation,
        trust_interception_active,
    );

    execute_sandboxed(
        program,
        cmd_args,
        prepared.caps,
        prepared.secrets,
        ExecutionFlags {
            strategy,
            workdir: args
                .workdir
                .clone()
                .or_else(|| std::env::current_dir().ok())
                .unwrap_or_else(|| std::path::PathBuf::from(".")),
            #[cfg(not(target_os = "windows"))]
            no_diagnostics,
            rollback,
            no_rollback: run_args.no_rollback,
            no_rollback_prompt,
            no_audit,
            silent,
            rollback_all: run_args.rollback_all,
            rollback_include: run_args.rollback_include,
            rollback_dest: run_args.rollback_dest,
            #[cfg(not(target_os = "windows"))]
            scan_root,
            #[cfg(not(target_os = "windows"))]
            trust_policy,
            trust_interception_active,
            #[cfg(not(target_os = "windows"))]
            protected_paths: verified_protected_paths,
            rollback_exclude_patterns: merged_patterns,
            rollback_exclude_globs: merged_globs,
            skip_dirs: merged_skip_dirs,
            #[cfg(not(target_os = "windows"))]
            capability_elevation: prepared.capability_elevation,
            #[cfg(target_os = "linux")]
            wsl2_proxy_policy: prepared.wsl2_proxy_policy,
            proxy_active,
            network_profile,
            allow_domain,
            credentials,
            custom_credentials: prepared.custom_credentials,
            upstream_proxy: effective_upstream_proxy,
            upstream_bypass: effective_bypass,
            allow_bind_ports: effective_listen_ports,
            allow_endpoint: args.allow_endpoint.clone(),
            proxy_port: args.proxy_port,
            #[cfg(target_os = "windows")]
            supervisor_requested_features: collect_windows_supervisor_requested_features(
                rollback,
                proxy_active,
                prepared.capability_elevation,
                trust_interception_active,
            ),
            #[cfg(not(target_os = "windows"))]
            open_url_origins: prepared.open_url_origins,
            #[cfg(not(target_os = "windows"))]
            open_url_allow_localhost: prepared.open_url_allow_localhost,
            #[cfg(not(target_os = "windows"))]
            allow_launch_services_active: prepared.allow_launch_services_active,
            override_deny_paths: prepared.override_deny_paths,
        },
    )
}

fn select_exec_strategy(
    rollback: bool,
    proxy_active: bool,
    capability_elevation: bool,
    trust_interception_active: bool,
) -> exec_strategy::ExecStrategy {
    if rollback || proxy_active || capability_elevation || trust_interception_active {
        exec_strategy::ExecStrategy::Supervised
    } else {
        exec_strategy::ExecStrategy::Direct
    }
}

/// Run an interactive shell inside the sandbox
fn run_shell(args: ShellArgs, silent: bool) -> Result<()> {
    let shell_path = args
        .shell
        .or_else(|| {
            std::env::var("SHELL")
                .ok()
                .filter(|s| !s.is_empty())
                .map(std::path::PathBuf::from)
        })
        .unwrap_or_else(|| std::path::PathBuf::from("/bin/sh"));

    // Dry run mode - just show what would happen
    if args.sandbox.dry_run {
        let prepared = prepare_sandbox(&args.sandbox, silent)?;
        if !prepared.secrets.is_empty() && !silent {
            eprintln!(
                "  Would inject {} credential(s) as environment variables",
                prepared.secrets.len()
            );
        }
        let support = Sandbox::support_info();
        output::print_dry_run(shell_path.as_os_str(), &[], &support, silent);
        return Ok(());
    }

    let prepared = prepare_sandbox(&args.sandbox, silent)?;

    #[cfg(target_os = "windows")]
    if !Sandbox::support_info().is_supported {
        Sandbox::validate_windows_preview_entry_point(
            nono::WindowsPreviewEntryPoint::Shell,
            &prepared.caps,
            &args
                .sandbox
                .workdir
                .clone()
                .or_else(|| std::env::current_dir().ok())
                .unwrap_or_else(|| std::path::PathBuf::from(".")),
            nono::WindowsPreviewContext {
                has_deny_override_policy: !prepared.override_deny_paths.is_empty(),
            },
        )?;
    }

    if prepared.allow_launch_services_active {
        print_allow_launch_services_warning(silent);
    }

    if !silent {
        eprintln!("{}", {
            let t = theme::current();
            theme::fg("Exit the shell with Ctrl-D or 'exit'.", t.subtext)
        });
        eprintln!();
    }

    execute_sandboxed(
        shell_path.into_os_string(),
        vec![],
        prepared.caps,
        prepared.secrets,
        ExecutionFlags {
            workdir: args
                .sandbox
                .workdir
                .clone()
                .or_else(|| std::env::current_dir().ok())
                .unwrap_or_else(|| std::path::PathBuf::from(".")),
            #[cfg(not(target_os = "windows"))]
            no_diagnostics: true,
            #[cfg(not(target_os = "windows"))]
            capability_elevation: prepared.capability_elevation,
            override_deny_paths: prepared.override_deny_paths,
            ..ExecutionFlags::defaults(silent)?
        },
    )
}

/// Apply sandbox and exec into command (nono disappears).
/// For scripts, piping, and embedding where no parent process is wanted.
fn run_wrap(wrap_args: WrapArgs, silent: bool) -> Result<()> {
    let args: SandboxArgs = wrap_args.sandbox.into();
    let command = wrap_args.command;
    #[cfg(not(target_os = "windows"))]
    let no_diagnostics = wrap_args.no_diagnostics;

    if command.is_empty() {
        return Err(NonoError::NoCommand);
    }

    let mut command_iter = command.into_iter();
    let program = OsString::from(command_iter.next().ok_or(NonoError::NoCommand)?);
    let cmd_args: Vec<OsString> = command_iter.map(OsString::from).collect();

    if args.dry_run {
        let prepared = prepare_sandbox(&args, silent)?;
        if !prepared.secrets.is_empty() && !silent {
            eprintln!(
                "  Would inject {} credential(s) as environment variables",
                prepared.secrets.len()
            );
        }
        let support = Sandbox::support_info();
        output::print_dry_run(&program, &cmd_args, &support, silent);
        return Ok(());
    }

    let prepared = prepare_sandbox(&args, silent)?;

    #[cfg(target_os = "windows")]
    if !Sandbox::support_info().is_supported {
        Sandbox::validate_windows_preview_entry_point(
            nono::WindowsPreviewEntryPoint::Wrap,
            &prepared.caps,
            &args
                .workdir
                .clone()
                .or_else(|| std::env::current_dir().ok())
                .unwrap_or_else(|| std::path::PathBuf::from(".")),
            nono::WindowsPreviewContext {
                has_deny_override_policy: !prepared.override_deny_paths.is_empty(),
            },
        )?;
    }

    // Also reject proxy flags that came from the profile (not just CLI).
    // Profile-provided upstream_proxy / network settings activate ProxyOnly
    // mode, which requires a parent process that wrap doesn't provide.
    if prepared.upstream_proxy.is_some()
        || matches!(
            prepared.caps.network_mode(),
            nono::NetworkMode::ProxyOnly { .. }
        )
    {
        return Err(NonoError::ConfigParse(
            "nono wrap does not support proxy mode (activated by profile network settings). \
             Use `nono run` instead."
                .to_string(),
        ));
    }

    if prepared.allow_launch_services_active {
        print_allow_launch_services_warning(silent);
    }

    execute_sandboxed(
        program,
        cmd_args,
        prepared.caps,
        prepared.secrets,
        ExecutionFlags {
            strategy: exec_strategy::ExecStrategy::Direct,
            workdir: args
                .workdir
                .clone()
                .or_else(|| std::env::current_dir().ok())
                .unwrap_or_else(|| std::path::PathBuf::from(".")),
            #[cfg(not(target_os = "windows"))]
            no_diagnostics,
            override_deny_paths: prepared.override_deny_paths,
            ..ExecutionFlags::defaults(silent)?
        },
    )
}

/// Flags controlling sandboxed execution behavior.
#[cfg(not(target_os = "windows"))]
struct ExecutionFlags {
    strategy: exec_strategy::ExecStrategy,
    workdir: std::path::PathBuf,
    no_diagnostics: bool,
    rollback: bool,
    no_rollback: bool,
    no_rollback_prompt: bool,
    /// Disable audit trail recording for this session
    no_audit: bool,
    silent: bool,
    /// Override all auto-exclusions (full snapshot)
    rollback_all: bool,
    /// Force-include specific directories that would otherwise be auto-excluded
    rollback_include: Vec<String>,
    /// Custom destination directory for rollback snapshots (overrides the default platform rollback path)
    rollback_dest: Option<std::path::PathBuf>,
    /// Root directory for trust policy discovery and scanning
    scan_root: std::path::PathBuf,
    /// Loaded trust policy from the pre-exec scan path.
    trust_policy: Option<nono::trust::TrustPolicy>,
    /// Whether runtime trust interception is relevant for this session.
    trust_interception_active: bool,
    /// Write-protected paths (signed instruction files) for diagnostic output
    protected_paths: Vec<std::path::PathBuf>,
    /// Profile-specific rollback exclusion patterns (additive on base)
    rollback_exclude_patterns: Vec<String>,
    /// Profile-specific rollback exclusion globs (filename matching)
    rollback_exclude_globs: Vec<String>,
    /// Directory names to skip during trust scanning and rollback preflight.
    skip_dirs: Vec<String>,
    /// Whether runtime capability elevation is enabled (seccomp-notify + PTY mux).
    /// When false, supervised mode runs with static capabilities only.
    capability_elevation: bool,
    /// WSL2 proxy fallback policy from profile (controls fail-secure vs insecure-proxy)
    #[cfg(target_os = "linux")]
    wsl2_proxy_policy: crate::profile::Wsl2ProxyPolicy,
    /// Whether proxy-based network filtering is active (forces Supervised mode)
    proxy_active: bool,
    /// Network profile name for proxy filtering (from --network-profile or profile config)
    network_profile: Option<String>,
    /// Additional domains to allow through the proxy (from --allow-domain or profile config)
    allow_domain: Vec<String>,
    /// Credential services for reverse proxy (from --credential or profile config)
    credentials: Vec<String>,
    /// Custom credential definitions from profile (merged with built-in during resolution)
    custom_credentials: std::collections::HashMap<String, profile::CustomCredentialDef>,
    /// Upstream proxy address (from --upstream-proxy)
    upstream_proxy: Option<String>,
    /// Hosts to bypass the upstream proxy (from --upstream-bypass)
    upstream_bypass: Vec<String>,
    /// Ports the sandboxed process is allowed to bind (from --allow-bind)
    allow_bind_ports: Vec<u16>,
    /// Endpoint rules from --allow-endpoint (parsed into per-service rules)
    allow_endpoint: Vec<String>,
    /// Fixed port for the credential proxy (from --proxy-port)
    proxy_port: Option<u16>,
    /// Allowed URL origins for supervisor-delegated browser opens
    open_url_origins: Vec<String>,
    /// Whether to allow http://localhost URL opens
    open_url_allow_localhost: bool,
    /// Whether direct LaunchServices opening is enabled for this session.
    allow_launch_services_active: bool,
    /// Canonicalized paths exempted from deny groups via override_deny
    override_deny_paths: Vec<std::path::PathBuf>,
}

#[cfg(target_os = "windows")]
struct ExecutionFlags {
    strategy: exec_strategy::ExecStrategy,
    workdir: std::path::PathBuf,
    rollback: bool,
    no_rollback: bool,
    no_rollback_prompt: bool,
    no_audit: bool,
    silent: bool,
    rollback_all: bool,
    rollback_include: Vec<String>,
    rollback_dest: Option<std::path::PathBuf>,
    trust_interception_active: bool,
    rollback_exclude_patterns: Vec<String>,
    rollback_exclude_globs: Vec<String>,
    skip_dirs: Vec<String>,
    proxy_active: bool,
    network_profile: Option<String>,
    allow_domain: Vec<String>,
    credentials: Vec<String>,
    custom_credentials: std::collections::HashMap<String, profile::CustomCredentialDef>,
    upstream_proxy: Option<String>,
    upstream_bypass: Vec<String>,
    allow_bind_ports: Vec<u16>,
    allow_endpoint: Vec<String>,
    proxy_port: Option<u16>,
    supervisor_requested_features: Vec<String>,
    override_deny_paths: Vec<std::path::PathBuf>,
}

#[cfg(not(target_os = "windows"))]
impl ExecutionFlags {
    /// Create flags with sensible defaults.
    /// Fields that vary per call site (strategy, silent, no_diagnostics, etc.)
    /// are overridden via struct update syntax.
    fn defaults(silent: bool) -> Result<Self> {
        Ok(Self {
            strategy: exec_strategy::ExecStrategy::Supervised,
            workdir: std::env::current_dir()
                .map_err(|e| NonoError::SandboxInit(format!("Failed to get cwd: {e}")))?,
            no_diagnostics: false,
            rollback: false,
            no_rollback: false,
            no_rollback_prompt: false,
            no_audit: false,
            silent,
            rollback_all: false,
            rollback_include: Vec::new(),
            rollback_dest: None,
            scan_root: std::env::current_dir()
                .map_err(|e| NonoError::SandboxInit(format!("Failed to get cwd: {e}")))?,
            trust_policy: None,
            trust_interception_active: false,
            protected_paths: Vec::new(),
            rollback_exclude_patterns: Vec::new(),
            rollback_exclude_globs: Vec::new(),
            skip_dirs: Vec::new(),
            capability_elevation: false,
            #[cfg(target_os = "linux")]
            wsl2_proxy_policy: crate::profile::Wsl2ProxyPolicy::Error,
            proxy_active: false,
            network_profile: None,
            allow_domain: Vec::new(),
            credentials: Vec::new(),
            custom_credentials: std::collections::HashMap::new(),
            upstream_proxy: None,
            upstream_bypass: Vec::new(),
            allow_bind_ports: Vec::new(),
            allow_endpoint: Vec::new(),
            proxy_port: None,
            open_url_origins: Vec::new(),
            open_url_allow_localhost: false,
            allow_launch_services_active: false,
            override_deny_paths: Vec::new(),
        })
    }
}

#[cfg(not(target_os = "windows"))]
fn trust_interception_active(policy: Option<&nono::trust::TrustPolicy>) -> bool {
    policy.is_some_and(|policy| !policy.includes.is_empty())
}

#[cfg(target_os = "windows")]
fn trust_interception_active(_policy: Option<&nono::trust::TrustPolicy>) -> bool {
    false
}

#[cfg(not(target_os = "windows"))]
fn build_supervisor_config<'a>(
    protected_roots: &'a protected_paths::ProtectedRoots,
    approval_backend: &'a terminal_approval::TerminalApproval,
    supervisor_session_id: &'a str,
    flags: &'a ExecutionFlags,
    #[cfg(target_os = "linux")] sup_proxy_port: u16,
    #[cfg(target_os = "linux")] sup_proxy_bind_ports: Vec<u16>,
) -> exec_strategy::SupervisorConfig<'a> {
    exec_strategy::SupervisorConfig {
        protected_roots: protected_roots.as_paths(),
        approval_backend,
        session_id: supervisor_session_id,
        open_url_origins: &flags.open_url_origins,
        open_url_allow_localhost: flags.open_url_allow_localhost,
        allow_launch_services_active: flags.allow_launch_services_active,
        #[cfg(target_os = "linux")]
        proxy_port: sup_proxy_port,
        #[cfg(target_os = "linux")]
        proxy_bind_ports: sup_proxy_bind_ports,
    }
}

#[cfg(target_os = "windows")]
impl ExecutionFlags {
    fn defaults(silent: bool) -> Result<Self> {
        Ok(Self {
            strategy: exec_strategy::ExecStrategy::Supervised,
            workdir: std::env::current_dir()
                .map_err(|e| NonoError::SandboxInit(format!("Failed to get cwd: {e}")))?,
            rollback: false,
            no_rollback: false,
            no_rollback_prompt: false,
            no_audit: false,
            silent,
            rollback_all: false,
            rollback_include: Vec::new(),
            rollback_dest: None,
            trust_interception_active: false,
            rollback_exclude_patterns: Vec::new(),
            rollback_exclude_globs: Vec::new(),
            skip_dirs: Vec::new(),
            proxy_active: false,
            network_profile: None,
            allow_domain: Vec::new(),
            credentials: Vec::new(),
            custom_credentials: std::collections::HashMap::new(),
            upstream_proxy: None,
            upstream_bypass: Vec::new(),
            allow_bind_ports: Vec::new(),
            allow_endpoint: Vec::new(),
            proxy_port: None,
            supervisor_requested_features: Vec::new(),
            override_deny_paths: Vec::new(),
        })
    }
}

#[cfg(target_os = "windows")]
fn build_supervisor_config<'a>(
    flags: &'a ExecutionFlags,
    supervisor_session_id: &'a str,
) -> exec_strategy::SupervisorConfig<'a> {
    let requested_features: Vec<_> = flags
        .supervisor_requested_features
        .iter()
        .map(String::as_str)
        .collect();
    let support = Sandbox::windows_supervisor_support(nono::WindowsSupervisorContext {
        rollback_snapshots: requested_features.contains(&"rollback snapshots"),
        proxy_filtering: requested_features.contains(&"proxy filtering"),
        runtime_capability_expansion: requested_features.contains(&"runtime capability elevation"),
        runtime_trust_interception: requested_features.contains(&"runtime trust interception"),
    });
    exec_strategy::SupervisorConfig {
        session_id: supervisor_session_id,
        requested_features,
        support,
    }
}

#[cfg(target_os = "windows")]
fn collect_windows_supervisor_requested_features(
    rollback: bool,
    proxy_active: bool,
    capability_elevation: bool,
    trust_interception_active: bool,
) -> Vec<String> {
    Sandbox::windows_supervisor_support(nono::WindowsSupervisorContext {
        rollback_snapshots: rollback,
        proxy_filtering: proxy_active,
        runtime_capability_expansion: capability_elevation,
        runtime_trust_interception: trust_interception_active,
    })
    .requested_feature_labels()
    .into_iter()
    .map(str::to_string)
    .collect()
}

#[cfg(target_os = "windows")]
fn validate_windows_preview_direct_execution(
    flags: &ExecutionFlags,
    caps: &CapabilitySet,
) -> Result<()> {
    let support = Sandbox::support_info();
    if support.is_supported {
        return Ok(());
    }

    Sandbox::validate_windows_preview_entry_point(
        nono::WindowsPreviewEntryPoint::RunDirect,
        caps,
        &flags.workdir,
        nono::WindowsPreviewContext {
            has_deny_override_policy: !flags.override_deny_paths.is_empty(),
        },
    )
}

#[derive(Debug, PartialEq, Eq)]
struct EffectiveProxySettings {
    network_profile: Option<String>,
    allow_domain: Vec<String>,
    credentials: Vec<String>,
}

fn resolve_effective_proxy_settings(
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
    allow_domain.extend(args.allow_proxy.clone());
    let mut credentials = prepared.credentials.clone();
    credentials.extend(args.proxy_credential.clone());

    EffectiveProxySettings {
        network_profile,
        allow_domain,
        credentials,
    }
}

/// Validate that bypass hosts are not specified without an external proxy.
/// Called from both the dry-run and live execution paths.
fn validate_external_proxy_bypass(args: &SandboxArgs, prepared: &PreparedSandbox) -> Result<()> {
    let has_bypass = !args.external_proxy_bypass.is_empty() || !prepared.upstream_bypass.is_empty();
    let has_external_proxy = args.external_proxy.is_some() || prepared.upstream_proxy.is_some();

    if has_bypass && !has_external_proxy {
        return Err(NonoError::ConfigParse(
            "--upstream-bypass requires --upstream-proxy \
             (or upstream_proxy in profile network config)"
                .to_string(),
        ));
    }
    Ok(())
}

/// Merge two port lists, sort, and deduplicate.
pub(crate) fn merge_dedup_ports(a: &[u16], b: &[u16]) -> Vec<u16> {
    let mut ports = a.to_vec();
    ports.extend_from_slice(b);
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Apply sandbox pre-fork for Direct mode (both parent+child confined).
fn apply_pre_fork_sandbox(
    strategy: exec_strategy::ExecStrategy,
    caps: &CapabilitySet,
    #[cfg(target_os = "windows")] current_dir: &std::path::Path,
    #[cfg(not(target_os = "windows"))] _current_dir: &std::path::Path,
    silent: bool,
) -> Result<()> {
    if matches!(strategy, exec_strategy::ExecStrategy::Direct) {
        #[cfg(target_os = "windows")]
        {
            let support = Sandbox::support_info();
            if !support.is_supported {
                let preview = Sandbox::preview_runtime_status(
                    caps,
                    current_dir,
                    nono::WindowsPreviewContext {
                        has_deny_override_policy: false,
                    },
                );
                info!("Windows preview runtime status: {:?}", preview);
                if !silent {
                    output::print_warning(
                        "Windows preview: running with basic Windows process containment and a limited Windows filesystem subset for executable coverage and supported directory allowlists; full filesystem and network enforcement are not active yet",
                    );
                    eprintln!();
                }
                return Ok(());
            }
        }

        output::print_applying_sandbox(silent);

        // On Linux, use the ABI-aware path to avoid BestEffort flag masking.
        #[cfg(target_os = "linux")]
        {
            let detected = Sandbox::detect_abi()?;
            info!("Direct mode: detected {}", detected);
            let _fallback = Sandbox::apply_with_abi(caps, &detected)?;
            // Direct mode cannot handle ProxyOnly fallback (no supervisor loop).
            // If ProxyOnly was needed and Landlock couldn't handle it, apply()
            // would have already failed with an error.
        }

        #[cfg(not(target_os = "linux"))]
        {
            Sandbox::apply(caps)?;
        }

        output::print_sandbox_active(silent);
    }
    Ok(())
}

/// Build a `ProxyConfig` from execution flags and network policy.
///
/// Resolves the network profile (if set), merges extra hosts from CLI/profile,
/// and includes credential routes. Custom credentials from the profile are
/// merged with built-in credentials during resolution.
fn build_proxy_config_from_flags(
    flags: &ExecutionFlags,
) -> Result<nono_proxy::config::ProxyConfig> {
    let net_policy_json = config::embedded::embedded_network_policy_json();
    let net_policy = network_policy::load_network_policy(net_policy_json)?;

    // Resolve network profile groups into flat host lists
    let mut resolved = if let Some(ref profile_name) = flags.network_profile {
        network_policy::resolve_network_profile(&net_policy, profile_name)?
    } else {
        network_policy::ResolvedNetworkPolicy {
            hosts: Vec::new(),
            suffixes: Vec::new(),
            routes: Vec::new(),
            profile_credentials: Vec::new(),
        }
    };

    // Merge profile credentials with CLI credentials (CLI takes precedence/adds to profile)
    let mut all_credentials = resolved.profile_credentials.clone();
    for cred in &flags.credentials {
        if !all_credentials.contains(cred) {
            all_credentials.push(cred.clone());
        }
    }

    // Resolve credential routes (validates all services exist in either custom or built-in)
    let routes = network_policy::resolve_credentials(
        &net_policy,
        &all_credentials,
        &flags.custom_credentials,
    )?;
    resolved.routes = routes;

    // Expand --allow-domain entries: group names become their hosts,
    // literal hostnames pass through as-is.
    let expanded_allow_domain =
        network_policy::expand_proxy_allow(&net_policy, &flags.allow_domain);

    // Apply --allow-endpoint rules to matching routes
    for entry in &flags.allow_endpoint {
        let (service, rule) = parse_allow_endpoint(entry)?;
        let mut found = false;
        for route in &mut resolved.routes {
            if route.prefix == service {
                route.endpoint_rules.push(rule.clone());
                found = true;
            }
        }
        if !found {
            return Err(NonoError::ConfigParse(format!(
                "--allow-endpoint references unknown service '{}'. \
                 Add it with --credential {} first.",
                service, service
            )));
        }
    }

    // Build the proxy config with expanded extra hosts
    let mut proxy_config = network_policy::build_proxy_config(&resolved, &expanded_allow_domain);

    // Wire in upstream proxy if specified
    if let Some(ref addr) = flags.upstream_proxy {
        proxy_config.external_proxy = Some(nono_proxy::config::ExternalProxyConfig {
            address: addr.clone(),
            auth: None,
            bypass_hosts: flags.upstream_bypass.clone(),
        });
    }

    // Set fixed proxy port if specified
    if let Some(port) = flags.proxy_port {
        proxy_config.bind_port = port;
    }

    Ok(proxy_config)
}

/// Parse an `--allow-endpoint` value in "SERVICE:METHOD:/path/pattern" format.
fn parse_allow_endpoint(entry: &str) -> Result<(String, nono_proxy::config::EndpointRule)> {
    // Split on first two colons: "github:GET:/repos/*/issues"
    // -> ("github", "GET", "/repos/*/issues")
    let first_colon = entry.find(':').ok_or_else(|| {
        NonoError::ConfigParse(format!(
            "invalid --allow-endpoint format '{}': expected SERVICE:METHOD:/path",
            entry
        ))
    })?;
    let service = &entry[..first_colon];
    let rest = &entry[first_colon + 1..];

    let second_colon = rest.find(':').ok_or_else(|| {
        NonoError::ConfigParse(format!(
            "invalid --allow-endpoint format '{}': expected SERVICE:METHOD:/path",
            entry
        ))
    })?;
    let method = &rest[..second_colon];
    let path = &rest[second_colon + 1..];

    if service.is_empty() || method.is_empty() || path.is_empty() {
        return Err(NonoError::ConfigParse(format!(
            "invalid --allow-endpoint format '{}': service, method, and path must be non-empty",
            entry
        )));
    }

    Ok((
        service.to_string(),
        nono_proxy::config::EndpointRule {
            method: method.to_string(),
            path: path.to_string(),
        },
    ))
}

fn cleanup_capability_state_file(cap_file_path: &std::path::Path) {
    if cap_file_path.exists() {
        let _ = std::fs::remove_file(cap_file_path);
    }
}

#[cfg(target_os = "windows")]
fn windows_runtime_state_dir(
    strategy: exec_strategy::ExecStrategy,
    caps: &CapabilitySet,
    current_dir: &std::path::Path,
) -> Option<std::path::PathBuf> {
    if !matches!(strategy, exec_strategy::ExecStrategy::Direct) {
        return None;
    }

    let support = Sandbox::support_info();
    if support.is_supported {
        return None;
    }

    let fs_policy = Sandbox::windows_filesystem_policy(caps);
    Sandbox::windows_runtime_state_dir(&fs_policy, current_dir)
}

#[cfg(target_os = "windows")]
struct WindowsRuntimeLayout {
    runtime_root: std::path::PathBuf,
    dirs: BTreeMap<&'static str, std::path::PathBuf>,
}

#[cfg(target_os = "windows")]
impl WindowsRuntimeLayout {
    fn new(runtime_root: std::path::PathBuf) -> Self {
        let mut dirs = BTreeMap::new();
        let mut insert_dir = |key: &'static str, relative: &[&str]| {
            let mut path = runtime_root.clone();
            for segment in relative {
                path.push(segment);
            }
            dirs.insert(key, path);
        };

        insert_dir("tmp", &["tmp"]);
        insert_dir("home", &["home"]);
        insert_dir("appdata_roaming", &["appdata", "Roaming"]);
        insert_dir("appdata_local", &["appdata", "Local"]);
        insert_dir("programdata", &["programdata"]);
        insert_dir("programfiles", &["programfiles"]);
        insert_dir("programfiles_x86", &["programfilesx86"]);
        insert_dir("common_programfiles", &["common-programfiles"]);
        insert_dir("common_programfiles_x86", &["common-programfilesx86"]);
        insert_dir("bin", &["bin"]);
        insert_dir("public", &["public"]);
        insert_dir("onedrive", &["onedrive"]);
        insert_dir("inetcache", &["inetcache"]);
        insert_dir("inetcookies", &["inetcookies"]);
        insert_dir("inethistory", &["inethistory"]);
        insert_dir("psmodules", &["psmodules"]);
        insert_dir("psmodule_analysis_cache", &["psmodule-analysis-cache"]);
        insert_dir("cargo_home", &["cargo-home"]);
        insert_dir("rustup_home", &["rustup-home"]);
        insert_dir("dotnet_home", &["dotnet-home"]);
        insert_dir("nuget_packages", &["nuget-packages"]);
        insert_dir("nuget_http_cache", &["nuget-http-cache"]);
        insert_dir("nuget_plugins_cache", &["nuget-plugins-cache"]);
        insert_dir("chocolatey", &["chocolatey"]);
        insert_dir("vcpkg", &["vcpkg"]);
        insert_dir("npm_cache", &["npm-cache"]);
        insert_dir("npm", &["npm"]);
        insert_dir("yarn_cache", &["yarn-cache"]);
        insert_dir("pip_cache", &["pip-cache"]);
        insert_dir("pip_config", &["pip-config"]);
        insert_dir("pip_build_tracker", &["pip-build-tracker"]);
        insert_dir("python_pycache", &["python-pycache"]);
        insert_dir("python_user_base", &["python-user-base"]);
        insert_dir("go_cache", &["go-cache"]);
        insert_dir("go_mod_cache", &["go-mod-cache"]);
        insert_dir("go_path", &["go-path"]);
        insert_dir("history", &["history"]);
        insert_dir("ipython", &["ipython"]);
        insert_dir("gem_home", &["gem-home"]);
        insert_dir("gem_path", &["gem-path"]);
        insert_dir("bundler_home", &["bundler-home"]);
        insert_dir("bundler_cache", &["bundler-cache"]);
        insert_dir("bundler_config", &["bundler-config"]);
        insert_dir("composer_home", &["composer-home"]);
        insert_dir("composer_cache", &["composer-cache"]);
        insert_dir("gradle_home", &["gradle-home"]);
        insert_dir("maven_home", &["maven-home"]);
        insert_dir("aws", &["cloud", "aws"]);
        insert_dir("azure", &["cloud", "azure"]);
        insert_dir("kube", &["cloud", "kube"]);
        insert_dir("docker", &["cloud", "docker"]);
        insert_dir("gcloud", &["cloud", "gcloud"]);
        insert_dir("terraform", &["cloud", "terraform"]);
        insert_dir("git", &["git"]);
        insert_dir("gnupg", &["gnupg"]);
        insert_dir("xdg_config", &["xdg", "config"]);
        insert_dir("xdg_cache", &["xdg", "cache"]);
        insert_dir("xdg_data", &["xdg", "data"]);
        insert_dir("xdg_state", &["xdg", "state"]);
        insert_dir("ripgrep", &["ripgrep"]);

        Self { runtime_root, dirs }
    }

    fn ensure_dirs(&self) -> Result<()> {
        std::fs::create_dir_all(&self.runtime_root).map_err(|e| {
            NonoError::SandboxInit(format!(
                "Failed to prepare Windows runtime state directory {}: {}",
                self.runtime_root.display(),
                e
            ))
        })?;

        for dir in self.dirs.values() {
            std::fs::create_dir_all(dir).map_err(|e| {
                NonoError::SandboxInit(format!(
                    "Failed to prepare Windows runtime state directory {}: {}",
                    dir.display(),
                    e
                ))
            })?;
        }
        Ok(())
    }

    fn dir(&self, key: &'static str) -> &std::path::Path {
        self.dirs
            .get(key)
            .map(std::path::PathBuf::as_path)
            .unwrap_or_else(|| panic!("missing Windows runtime layout key: {key}"))
    }

    fn file(&self, key: &'static str, name: &str) -> std::path::PathBuf {
        self.dir(key).join(name)
    }
}

#[cfg(target_os = "windows")]
fn build_windows_baseline_env(
    system_root: &str,
    system32: &std::path::Path,
    system_drive: &str,
) -> Result<Vec<(String, String)>> {
    let path_value = std::env::join_paths([
        system32.as_os_str(),
        std::path::Path::new(system_root).as_os_str(),
    ])
    .map_err(|e| NonoError::SandboxInit(format!("Failed to prepare Windows runtime PATH: {e}")))?
    .to_string_lossy()
    .into_owned();

    Ok(vec![
        ("PATH".to_string(), path_value),
        (
            "PATHEXT".to_string(),
            ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC".to_string(),
        ),
        (
            "COMSPEC".to_string(),
            system32.join("cmd.exe").to_string_lossy().into_owned(),
        ),
        ("SystemRoot".to_string(), system_root.to_string()),
        ("windir".to_string(), system_root.to_string()),
        ("SystemDrive".to_string(), system_drive.to_string()),
        (
            "NoDefaultCurrentDirectoryInExePath".to_string(),
            "1".to_string(),
        ),
    ])
}

#[cfg(target_os = "windows")]
fn try_prepare_low_integrity_runtime_root(
    runtime_state_dir: &std::path::Path,
) -> Result<Option<std::path::PathBuf>> {
    let managed_root = runtime_state_dir.join(".nono-runtime-low");
    std::fs::create_dir_all(&managed_root).map_err(|e| {
        NonoError::SandboxInit(format!(
            "Failed to prepare Windows managed runtime root {}: {}",
            managed_root.display(),
            e
        ))
    })?;

    let output = Command::new("icacls")
        .arg(&managed_root)
        .args(["/setintegritylevel", "(OI)(CI)L"])
        .output();

    let Ok(output) = output else {
        return Ok(None);
    };

    if !output.status.success() {
        return Ok(None);
    }

    if Sandbox::windows_supports_direct_writable_dir(&managed_root) {
        Ok(Some(managed_root))
    } else {
        Ok(None)
    }
}

#[cfg(target_os = "windows")]
fn try_set_low_integrity_label(path: &std::path::Path) -> bool {
    let Ok(output) = Command::new("icacls")
        .arg(path)
        .args(["/setintegritylevel", "(OI)(CI)L"])
        .output()
    else {
        return false;
    };

    output.status.success()
}

#[cfg(target_os = "windows")]
fn prepare_windows_runtime_env_vars(
    runtime_state_dir: Option<&std::path::Path>,
) -> Result<Vec<(String, String)>> {
    let system_root = std::env::var("SystemRoot")
        .or_else(|_| std::env::var("windir"))
        .unwrap_or_else(|_| r"C:\Windows".to_string());
    let system32 = std::path::Path::new(&system_root).join("System32");
    let system_drive = if system_root.len() >= 2 && system_root.as_bytes()[1] == b':' {
        system_root[..2].to_string()
    } else {
        "C:".to_string()
    };

    let Some(runtime_state_dir) = runtime_state_dir else {
        return build_windows_baseline_env(&system_root, &system32, &system_drive);
    };

    let runtime_root = if Sandbox::windows_supports_direct_writable_dir(runtime_state_dir) {
        runtime_state_dir.join(".nono-runtime")
    } else if let Some(managed_root) = try_prepare_low_integrity_runtime_root(runtime_state_dir)? {
        managed_root
    } else {
        std::env::var_os("LOCALAPPDATA")
            .map(std::path::PathBuf::from)
            .map(|local| local.join("Temp").join("Low"))
            .unwrap_or_else(|| runtime_state_dir.join(".nono-runtime-low"))
            .join("nono")
            .join(
                runtime_state_dir
                    .to_string_lossy()
                    .replace(['\\', '/', ':'], "_"),
            )
    };
    let layout = WindowsRuntimeLayout::new(runtime_root);
    layout.ensure_dirs()?;
    if !Sandbox::windows_supports_direct_writable_dir(&layout.runtime_root)
        && layout
            .runtime_root
            .to_string_lossy()
            .to_ascii_lowercase()
            .contains("\\temp\\low\\")
    {
        let _ = try_set_low_integrity_label(&layout.runtime_root);
    }

    if !Sandbox::windows_supports_direct_writable_dir(&layout.runtime_root) {
        return Err(NonoError::SandboxInit(format!(
            "Failed to prepare Windows writable runtime root {}: the directory is not low-integrity-compatible",
            layout.runtime_root.display()
        )));
    }

    let path_value = std::env::join_paths([
        system32.as_os_str(),
        std::path::Path::new(&system_root).as_os_str(),
        layout.dir("bin").as_os_str(),
        layout.dir("programfiles").as_os_str(),
        layout.dir("common_programfiles").as_os_str(),
    ])
    .map_err(|e| NonoError::SandboxInit(format!("Failed to prepare Windows runtime PATH: {e}")))?
    .to_string_lossy()
    .into_owned();

    let mut env = build_windows_baseline_env(&system_root, &system32, &system_drive)?;
    env[0].1 = path_value;

    for (key, dir_key) in [
        ("TMP", "tmp"),
        ("TEMP", "tmp"),
        ("TMPDIR", "tmp"),
        ("HOME", "home"),
        ("USERPROFILE", "home"),
        ("APPDATA", "appdata_roaming"),
        ("LOCALAPPDATA", "appdata_local"),
        ("XDG_CONFIG_HOME", "xdg_config"),
        ("XDG_CACHE_HOME", "xdg_cache"),
        ("XDG_DATA_HOME", "xdg_data"),
        ("XDG_STATE_HOME", "xdg_state"),
        ("PROGRAMDATA", "programdata"),
        ("ALLUSERSPROFILE", "programdata"),
        ("PUBLIC", "public"),
        ("ProgramFiles", "programfiles"),
        ("ProgramFiles(x86)", "programfiles_x86"),
        ("ProgramW6432", "programfiles"),
        ("CommonProgramFiles", "common_programfiles"),
        ("CommonProgramFiles(x86)", "common_programfiles_x86"),
        ("CommonProgramW6432", "common_programfiles"),
        ("OneDrive", "onedrive"),
        ("OneDriveConsumer", "onedrive"),
        ("OneDriveCommercial", "onedrive"),
        ("INETCACHE", "inetcache"),
        ("INETCOOKIES", "inetcookies"),
        ("INETHISTORY", "inethistory"),
        ("PSModulePath", "psmodules"),
        ("CARGO_HOME", "cargo_home"),
        ("RUSTUP_HOME", "rustup_home"),
        ("DOTNET_CLI_HOME", "dotnet_home"),
        ("NUGET_PACKAGES", "nuget_packages"),
        ("NUGET_HTTP_CACHE_PATH", "nuget_http_cache"),
        ("NUGET_PLUGINS_CACHE_PATH", "nuget_plugins_cache"),
        ("ChocolateyInstall", "chocolatey"),
        ("ChocolateyToolsLocation", "chocolatey"),
        ("VCPKG_ROOT", "vcpkg"),
        ("NPM_CONFIG_CACHE", "npm_cache"),
        ("YARN_CACHE_FOLDER", "yarn_cache"),
        ("PIP_CACHE_DIR", "pip_cache"),
        ("PIP_BUILD_TRACKER", "pip_build_tracker"),
        ("PYTHONPYCACHEPREFIX", "python_pycache"),
        ("PYTHONUSERBASE", "python_user_base"),
        ("GOCACHE", "go_cache"),
        ("GOMODCACHE", "go_mod_cache"),
        ("GOPATH", "go_path"),
        ("IPYTHONDIR", "ipython"),
        ("GEM_HOME", "gem_home"),
        ("GEM_PATH", "gem_path"),
        ("BUNDLE_USER_HOME", "bundler_home"),
        ("BUNDLE_USER_CACHE", "bundler_cache"),
        ("BUNDLE_USER_CONFIG", "bundler_config"),
        ("BUNDLE_APP_CONFIG", "bundler_config"),
        ("COMPOSER_HOME", "composer_home"),
        ("COMPOSER_CACHE_DIR", "composer_cache"),
        ("GRADLE_USER_HOME", "gradle_home"),
        ("MAVEN_USER_HOME", "maven_home"),
        ("AZURE_CONFIG_DIR", "azure"),
        ("DOCKER_CONFIG", "docker"),
        ("CLOUDSDK_CONFIG", "gcloud"),
        ("GNUPGHOME", "gnupg"),
        ("TF_DATA_DIR", "terraform"),
    ] {
        env.push((
            key.to_string(),
            layout.dir(dir_key).to_string_lossy().into_owned(),
        ));
    }

    for (key, file_path) in [
        (
            "PSModuleAnalysisCachePath",
            layout.file("psmodule_analysis_cache", "ModuleAnalysisCache"),
        ),
        ("HISTFILE", layout.file("history", "shell_history")),
        ("LESSHISTFILE", layout.file("history", "less_history")),
        (
            "NODE_REPL_HISTORY",
            layout.file("history", "node_repl_history"),
        ),
        ("PYTHONHISTFILE", layout.file("history", "python_history")),
        ("SQLITE_HISTORY", layout.file("history", "sqlite_history")),
        (
            "AWS_SHARED_CREDENTIALS_FILE",
            layout.file("aws", "credentials"),
        ),
        ("AWS_CONFIG_FILE", layout.file("aws", "config")),
        ("KUBECONFIG", layout.file("kube", "config")),
        ("GIT_CONFIG_GLOBAL", layout.file("git", "config")),
        ("NPM_CONFIG_USERCONFIG", layout.file("npm", "npmrc")),
        ("PIP_CONFIG_FILE", layout.file("pip_config", "pip.ini")),
        ("RIPGREP_CONFIG_PATH", layout.file("ripgrep", "ripgreprc")),
        (
            "TF_CLI_CONFIG_FILE",
            layout.file("terraform", "terraform.rc"),
        ),
    ] {
        env.push((key.to_string(), file_path.to_string_lossy().into_owned()));
    }

    let home_str = layout.dir("home").to_string_lossy().into_owned();
    if home_str.len() >= 3 && home_str.as_bytes()[1] == b':' {
        env.push(("HOMEDRIVE".to_string(), home_str[..2].to_string()));
        env.push(("HOMEPATH".to_string(), home_str[2..].to_string()));
    }

    Ok(env)
}

fn execution_start_dir(
    workdir: &std::path::Path,
    caps: &CapabilitySet,
) -> Result<std::path::PathBuf> {
    let workdir_canonical =
        workdir
            .canonicalize()
            .map_err(|e| NonoError::PathCanonicalization {
                path: workdir.to_path_buf(),
                source: e,
            })?;

    if caps.path_covered(&workdir_canonical) {
        Ok(workdir_canonical)
    } else {
        Ok(std::path::PathBuf::from("/"))
    }
}

fn execute_sandboxed(
    program: OsString,
    cmd_args: Vec<OsString>,
    mut caps: CapabilitySet,
    loaded_secrets: Vec<nono::LoadedSecret>,
    flags: ExecutionFlags,
) -> Result<()> {
    // Check if command is blocked using config module
    if let Some(blocked) =
        config::check_blocked_command(&program, caps.allowed_commands(), caps.blocked_commands())?
    {
        return Err(NonoError::BlockedCommand {
            command: blocked,
            reason: "This command is blocked by default due to destructive potential. \
                     Use --allow-command to override if you understand the risks."
                .to_string(),
        });
    }

    // Convert OsString command to String for exec_strategy
    let command: Vec<String> = std::iter::once(program.to_string_lossy().into_owned())
        .chain(cmd_args.iter().map(|s| s.to_string_lossy().into_owned()))
        .collect();

    if command.is_empty() {
        return Err(NonoError::NoCommand);
    }

    // Resolve the program path BEFORE applying the sandbox
    let resolved_program = exec_strategy::resolve_program(&command[0])?;

    // Validate that secret env var names are not dangerous (e.g. LD_PRELOAD).
    // A malicious profile could map a keystore secret to a linker/interpreter
    // injection variable, bypassing the env var filter.
    for secret in &loaded_secrets {
        if exec_strategy::is_dangerous_env_var(&secret.env_var) {
            return Err(NonoError::ConfigParse(format!(
                "secret mapping targets dangerous environment variable: {}",
                secret.env_var
            )));
        }
    }

    let strategy = flags.strategy;

    if matches!(strategy, exec_strategy::ExecStrategy::Supervised) {
        output::print_supervised_info(flags.silent, flags.rollback, flags.proxy_active);
    }

    // Start network proxy if proxy mode is active.
    // The proxy runs in the parent process (unsandboxed) and binds to a random
    // ephemeral port on localhost. The child is sandboxed to only connect to
    // that port via ProxyOnly mode.
    let mut proxy_env_vars: Vec<(String, String)> = Vec::new();
    let proxy_handle: Option<nono_proxy::server::ProxyHandle> = if flags.proxy_active {
        let proxy_config = build_proxy_config_from_flags(&flags)?;

        // Use multi-thread runtime so the accept loop and connection handlers
        // are driven by background worker threads. A current_thread runtime
        // would only drive tasks inside block_on() — once block_on() returns
        // after start(), the spawned accept loop would be orphaned and never
        // poll, making the proxy a dead listener.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| NonoError::SandboxInit(format!("Failed to start proxy runtime: {}", e)))?;
        let handle = rt
            .block_on(async { nono_proxy::server::start(proxy_config.clone()).await })
            .map_err(|e| NonoError::SandboxInit(format!("Failed to start proxy: {}", e)))?;

        // Update the sandbox capability port to the actual bound port.
        // Include allow_bind_ports so the sandboxed process can listen on those ports
        // while still routing outbound HTTP through the credential injection proxy.
        let port = handle.port;
        // Log before moving allow_bind_ports
        if flags.allow_bind_ports.is_empty() {
            info!("Network proxy started on localhost:{}", port);
        } else {
            info!(
                "Network proxy started on localhost:{}, bind ports: {:?}",
                port, flags.allow_bind_ports
            );
        }
        caps.set_network_mode_mut(nono::NetworkMode::ProxyOnly {
            port,
            bind_ports: flags.allow_bind_ports.clone(),
        });

        // Collect proxy env vars for the child process
        for (k, v) in handle.env_vars() {
            proxy_env_vars.push((k, v));
        }

        // Add SDK base URL overrides for credential routes
        // (e.g., OPENAI_BASE_URL=http://127.0.0.1:<port>/openai)
        for (k, v) in handle.credential_env_vars(&proxy_config) {
            proxy_env_vars.push((k, v));
        }

        // Leak the runtime so it keeps running in the parent after fork.
        // The multi-thread runtime's worker threads continue polling the
        // accept loop and connection handlers after block_on returns.
        std::mem::forget(rt);
        Some(handle)
    } else {
        None
    };

    #[cfg(not(target_os = "windows"))]
    let current_dir = execution_start_dir(&flags.workdir, &caps)?;
    #[cfg(target_os = "windows")]
    let current_dir = {
        let support = Sandbox::support_info();
        if support.is_supported {
            execution_start_dir(&flags.workdir, &caps)?
        } else {
            flags.workdir.clone()
        }
    };

    #[cfg(target_os = "windows")]
    if matches!(strategy, exec_strategy::ExecStrategy::Direct) {
        validate_windows_preview_direct_execution(&flags, &caps)?;
    }

    #[cfg(target_os = "windows")]
    let runtime_state_dir = windows_runtime_state_dir(strategy, &caps, &current_dir);
    #[cfg(not(target_os = "windows"))]
    let runtime_state_dir: Option<std::path::PathBuf> = None;

    // Write capability state file before sandbox activation and child launch.
    let cap_file_path = write_capability_state_file(
        &caps,
        &flags.override_deny_paths,
        runtime_state_dir.as_deref(),
        flags.silent,
    );

    // Apply sandbox BEFORE fork for Direct mode.
    apply_pre_fork_sandbox(strategy, &caps, &current_dir, flags.silent)?;

    // Build environment variables for the command
    let mut env_vars: Vec<(&str, &str)> = loaded_secrets
        .iter()
        .map(|s| (s.env_var.as_str(), s.value.as_str()))
        .collect();

    // Add proxy env vars (HTTP_PROXY, HTTPS_PROXY, NONO_PROXY_TOKEN)
    for (k, v) in &proxy_env_vars {
        env_vars.push((k.as_str(), v.as_str()));
    }

    #[cfg(target_os = "windows")]
    let windows_runtime_env_vars = prepare_windows_runtime_env_vars(runtime_state_dir.as_deref())?;
    #[cfg(not(target_os = "windows"))]
    let windows_runtime_env_vars: Vec<(String, String)> = Vec::new();
    #[cfg(target_os = "windows")]
    for (k, v) in &windows_runtime_env_vars {
        env_vars.push((k.as_str(), v.as_str()));
    }

    // Determine threading context for fork safety.
    // Secret loading uses the keyring backend which may spawn background threads
    // (macOS Security framework XPC dispatch). However, get_password() is synchronous
    // — by the time we reach here, the keyring call is complete and any spawned
    // threads are idle dispatch workers (not holding allocator locks).
    //
    // When proxy mode is active (forces Supervised), keyring threads are safe to
    // fork over because: (1) the synchronous call completed, (2) idle XPC workers
    // behave like idle tokio workers (parked on kqueue), (3) the child applies
    // sandbox then immediately calls execve which replaces the address space.
    let threading = if !loaded_secrets.is_empty() && !flags.proxy_active {
        exec_strategy::ThreadingContext::KeyringExpected
    } else if flags.trust_interception_active || flags.proxy_active || !loaded_secrets.is_empty() {
        // Proxy uses tokio threads (parked on epoll/kqueue, safe for fork+exec).
        // Keyring threads are idle XPC dispatch workers when proxy is also active.
        // Trust policy signature verification and runtime attestation may also
        // leave crypto worker threads parked before we fork.
        exec_strategy::ThreadingContext::CryptoExpected
    } else {
        exec_strategy::ThreadingContext::Strict
    };

    info!(
        "Executing with strategy: {:?}, threading: {:?}",
        strategy, threading
    );

    // Determine whether the seccomp proxy-only fallback is needed.
    // This must be decided before fork so both parent and child agree.
    //
    // On WSL2, seccomp user notification is unavailable (EBUSY). The
    // wsl2_proxy_policy controls what happens:
    //   Error (default) → refuse to run, fail secure
    //   InsecureProxy   → allow degraded execution with explicit warning
    #[cfg(target_os = "linux")]
    let seccomp_proxy_fallback = {
        let needs_proxy = matches!(caps.network_mode(), nono::NetworkMode::ProxyOnly { .. });
        if needs_proxy && nono::is_wsl2() {
            let needs_seccomp_fallback = !Sandbox::detect_abi()
                .ok()
                .is_some_and(|abi| abi.has_network());
            if needs_seccomp_fallback {
                match flags.wsl2_proxy_policy {
                    crate::profile::Wsl2ProxyPolicy::Error => {
                        return Err(NonoError::SandboxInit(
                            "WSL2: proxy-only network mode cannot be kernel-enforced. \
                             seccomp user notification returns EBUSY on WSL2 and Landlock V4 \
                             (per-port TCP filtering) is not available on this kernel.\n\n\
                             The sandboxed process would be able to bypass the credential proxy \
                             and open arbitrary outbound connections.\n\n\
                             To allow degraded execution (credential proxy without network lockdown), \
                             set wsl2_proxy_policy: \"insecure_proxy\" in your profile's security config.\n\n\
                             See: https://nono.sh/docs/cli/internals/wsl2"
                                .to_string(),
                        ));
                    }
                    crate::profile::Wsl2ProxyPolicy::InsecureProxy => {
                        eprintln!(
                            "  [nono] WARNING: WSL2 insecure proxy mode — credential proxy active \
                             but network is NOT kernel-enforced. The sandboxed process can bypass \
                             the proxy and open arbitrary outbound connections."
                        );
                    }
                }
            }
            false
        } else if needs_proxy {
            match Sandbox::detect_abi() {
                Ok(detected) => !detected.has_network(),
                Err(_) => false,
            }
        } else {
            false
        }
    };

    // Create execution config
    #[cfg(not(target_os = "windows"))]
    let config = exec_strategy::ExecConfig {
        command: &command,
        resolved_program: &resolved_program,
        caps: &caps,
        env_vars,
        cap_file: cap_file_path.as_deref(),
        current_dir: &current_dir,
        no_diagnostics: flags.no_diagnostics || flags.silent,
        threading,
        protected_paths: &flags.protected_paths,
        capability_elevation: flags.capability_elevation,
        #[cfg(target_os = "linux")]
        seccomp_proxy_fallback,
    };
    #[cfg(target_os = "windows")]
    let config = exec_strategy::ExecConfig {
        command: &command,
        resolved_program: &resolved_program,
        caps: &caps,
        env_vars,
        cap_file: cap_file_path.as_deref(),
        current_dir: &current_dir,
    };

    // Execute based on strategy
    match strategy {
        #[cfg(not(target_os = "windows"))]
        exec_strategy::ExecStrategy::Direct => {
            exec_strategy::execute_direct(&config)?;
            unreachable!("execute_direct only returns on error");
        }
        #[cfg(target_os = "windows")]
        exec_strategy::ExecStrategy::Direct => {
            let exit_code = exec_strategy::execute_direct(&config)?;
            if let Some(cap_file_path) = cap_file_path.as_ref() {
                cleanup_capability_state_file(cap_file_path);
            }
            drop(config);
            drop(loaded_secrets);
            std::process::exit(exit_code);
        }
        exec_strategy::ExecStrategy::Supervised => {
            #[cfg(not(target_os = "windows"))]
            output::print_applying_sandbox(flags.silent);
            #[cfg(target_os = "windows")]
            if !Sandbox::support_info().is_supported && !flags.silent {
                output::print_warning(
                    "Windows preview: supervised execution is active for supported Windows features such as rollback snapshots; unsupported supervised features still fail loudly",
                );
                eprintln!();
            }

            // --- Audit session setup (always, unless --no-audit) ---
            // The session directory and ID are shared between audit and rollback.
            // Audit writes session.json; rollback adds snapshot data to the same dir.
            let audit_state = if !flags.no_audit {
                let session_id = format!(
                    "{}-{}",
                    chrono::Local::now().format("%Y%m%d-%H%M%S"),
                    std::process::id()
                );

                let session_dir =
                    rollback_session::rollback_root_with_override(flags.rollback_dest.as_ref())?
                        .join(&session_id);
                std::fs::create_dir_all(&session_dir).map_err(|e| {
                    NonoError::Snapshot(format!(
                        "Failed to create session directory {}: {}",
                        session_dir.display(),
                        e
                    ))
                })?;

                // Set directory permissions to 0700
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = std::fs::Permissions::from_mode(0o700);
                    if let Err(e) = std::fs::set_permissions(&session_dir, perms) {
                        warn!("Failed to set session directory permissions to 0700: {e}");
                    }
                }

                Some((session_id, session_dir))
            } else {
                None
            };

            // --- Rollback snapshot lifecycle (only when --rollback is active) ---
            // Warn if rollback-related flags are set but rollback is disabled.
            if flags.no_rollback {
                let has_rollback_flags = flags.rollback_all
                    || !flags.rollback_include.is_empty()
                    || !flags.rollback_exclude_patterns.is_empty()
                    || !flags.rollback_exclude_globs.is_empty();
                if has_rollback_flags {
                    warn!(
                        "--no-rollback is active; rollback flags \
                         (--rollback-all, --rollback-include, --rollback-exclude) \
                         have no effect"
                    );
                    if !flags.silent {
                        eprintln!(
                            "  [nono] Warning: --no-rollback is active; \
                             rollback customization flags have no effect."
                        );
                    }
                }
            }
            let rollback_state = if flags.rollback && !flags.no_rollback {
                // Enforce storage limits before creating snapshots (audit-only sessions
                // are tiny and don't count toward these limits)
                enforce_rollback_limits(flags.silent);

                if let Some((ref _session_id, ref session_dir)) = audit_state {
                    // Collect tracked paths: only USER-specified directories with write access.
                    // System/group paths (caches, frameworks, etc.) are excluded to avoid
                    // snapshotting system directories the user didn't ask to track.
                    let tracked_paths: Vec<std::path::PathBuf> = caps
                        .fs_capabilities()
                        .iter()
                        .filter(|c| {
                            !c.is_file
                                && matches!(c.access, AccessMode::Write | AccessMode::ReadWrite)
                                && matches!(c.source, nono::CapabilitySource::User)
                        })
                        .map(|c| c.resolved.clone())
                        .collect();

                    if !tracked_paths.is_empty() {
                        // When --rollback-all is set, only exclude VCS internals
                        // (restoring partial .git/ corrupts the repo). Otherwise
                        // use the full base exclusion list.
                        let mut patterns = if flags.rollback_all {
                            rollback_vcs_exclusions()
                        } else {
                            rollback_base_exclusions()
                        };
                        patterns.extend(flags.rollback_exclude_patterns.iter().cloned());
                        patterns.sort_unstable();
                        patterns.dedup();
                        let base_patterns = patterns.clone();
                        let exclusion_config = nono::undo::ExclusionConfig {
                            use_gitignore: true,
                            exclude_patterns: patterns,
                            exclude_globs: flags.rollback_exclude_globs.clone(),
                            force_include: flags.rollback_include.clone(),
                        };
                        // Use the first tracked path as gitignore root
                        let gitignore_root = tracked_paths
                            .first()
                            .cloned()
                            .unwrap_or_else(|| std::path::PathBuf::from("."));
                        let mut exclusion =
                            nono::undo::ExclusionFilter::new(exclusion_config, &gitignore_root)?;

                        // Run preflight to detect large unexcluded directories.
                        // When --rollback-all is NOT set, auto-exclude detected heavy dirs
                        // and print a one-line notice. This ensures zero-flag usage Just Works.
                        // Directories listed in --rollback-include are kept (not auto-excluded).
                        if !flags.rollback_all {
                            let preflight_result = rollback_preflight::run_preflight(
                                &tracked_paths,
                                &exclusion,
                                &flags.skip_dirs,
                            );

                            if preflight_result.needs_warning() {
                                // Filter out any dirs the user explicitly wants to include
                                let auto_excluded: Vec<&rollback_preflight::HeavyDir> =
                                    preflight_result
                                        .heavy_dirs
                                        .iter()
                                        .filter(|d| !flags.rollback_include.contains(&d.name))
                                        .collect();

                                if !auto_excluded.is_empty() {
                                    let excluded_names: Vec<String> =
                                        auto_excluded.iter().map(|d| d.name.clone()).collect();
                                    let mut all_patterns = base_patterns.clone();
                                    all_patterns.extend(excluded_names);
                                    all_patterns.sort_unstable();
                                    all_patterns.dedup();
                                    let updated_config = nono::undo::ExclusionConfig {
                                        use_gitignore: true,
                                        exclude_patterns: all_patterns,
                                        exclude_globs: flags.rollback_exclude_globs.clone(),
                                        force_include: flags.rollback_include.clone(),
                                    };
                                    exclusion = nono::undo::ExclusionFilter::new(
                                        updated_config,
                                        &gitignore_root,
                                    )?;

                                    // Print notice showing only actually-excluded dirs
                                    if !flags.silent {
                                        rollback_preflight::print_auto_exclude_notice(
                                            &auto_excluded,
                                            &preflight_result,
                                        );
                                    }
                                }
                            }
                        }

                        let mut manager = nono::undo::SnapshotManager::new(
                            session_dir.clone(),
                            tracked_paths.clone(),
                            exclusion,
                            nono::undo::WalkBudget::default(),
                        )?;

                        let baseline = manager.create_baseline()?;
                        let atomic_temp_before = manager.collect_atomic_temp_files();

                        output::print_rollback_tracking(&tracked_paths, flags.silent);

                        Some((manager, baseline, tracked_paths, atomic_temp_before))
                    } else {
                        None
                    }
                } else {
                    // audit_state is None (--no-audit). Clap prevents --rollback + --no-audit,
                    // so this branch is unreachable in normal CLI usage.
                    None
                }
            } else {
                None
            };

            // --- Supervisor IPC setup (always active in Supervised mode) ---
            #[cfg(not(target_os = "windows"))]
            let protected_roots = protected_paths::ProtectedRoots::from_defaults()?;
            #[cfg(not(target_os = "windows"))]
            let approval_backend = terminal_approval::TerminalApproval;
            #[cfg(not(target_os = "windows"))]
            let supervisor_session_id = audit_state
                .as_ref()
                .map(|(session_id, _)| session_id.clone())
                .unwrap_or_else(|| {
                    format!(
                        "supervised-{}-{}",
                        std::process::id(),
                        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
                    )
                });
            // Extract proxy port and bind ports for seccomp fallback config
            #[cfg(target_os = "linux")]
            let (sup_proxy_port, sup_proxy_bind_ports) = match caps.network_mode() {
                nono::NetworkMode::ProxyOnly { port, bind_ports } => (*port, bind_ports.clone()),
                _ => (0, Vec::new()),
            };

            #[cfg(not(target_os = "windows"))]
            let supervisor_cfg = build_supervisor_config(
                &protected_roots,
                &approval_backend,
                &supervisor_session_id,
                &flags,
                #[cfg(target_os = "linux")]
                sup_proxy_port,
                #[cfg(target_os = "linux")]
                sup_proxy_bind_ports,
            );
            #[cfg(target_os = "windows")]
            let supervisor_session_id = audit_state
                .as_ref()
                .map(|(session_id, _)| session_id.clone())
                .unwrap_or_else(|| {
                    format!(
                        "windows-preview-{}-{}",
                        std::process::id(),
                        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
                    )
                });
            #[cfg(target_os = "windows")]
            let supervisor_cfg = build_supervisor_config(&flags, &supervisor_session_id);

            #[cfg(not(target_os = "windows"))]
            let trust_interceptor = if flags.trust_interception_active {
                match flags.trust_policy.clone() {
                    Some(policy) => {
                        match trust_intercept::TrustInterceptor::new(
                            policy,
                            flags.scan_root.clone(),
                        ) {
                            Ok(interceptor) => Some(interceptor),
                            Err(e) => {
                                tracing::warn!("Trust interceptor pattern compilation failed: {e}");
                                eprintln!(
                                    "  {}",
                                    format!(
                                        "WARNING: Runtime instruction file verification disabled \
                                     (pattern error: {e})"
                                    )
                                    .yellow()
                                );
                                None
                            }
                        }
                    }
                    None => None,
                }
            } else {
                None
            };
            #[cfg(target_os = "windows")]
            let trust_interceptor: Option<trust_intercept::TrustInterceptor> = None;

            let started = chrono::Local::now().to_rfc3339();
            let exit_code = exec_strategy::execute_supervised(
                &config,
                Some(&supervisor_cfg),
                trust_interceptor,
            )?;
            let ended = chrono::Local::now().to_rfc3339();

            // --- Post-exit: rollback snapshots + audit metadata ---
            let mut network_events = proxy_handle.as_ref().map_or_else(
                Vec::new,
                nono_proxy::server::ProxyHandle::drain_audit_events,
            );

            let mut audit_saved = false;

            if let Some((mut manager, baseline, tracked_paths, atomic_temp_before)) = rollback_state
            {
                let (final_manifest, changes) = manager.create_incremental(&baseline)?;
                let merkle_roots = vec![baseline.merkle_root, final_manifest.merkle_root];

                // Save session metadata (via SnapshotManager which owns the session dir)
                let meta = nono::undo::SessionMetadata {
                    session_id: audit_state
                        .as_ref()
                        .map(|(id, _)| id.clone())
                        .unwrap_or_default(),
                    started: started.clone(),
                    ended: Some(ended.clone()),
                    command: command.clone(),
                    tracked_paths,
                    snapshot_count: manager.snapshot_count(),
                    exit_code: Some(exit_code),
                    merkle_roots,
                    network_events: std::mem::take(&mut network_events),
                };
                manager.save_session_metadata(&meta)?;
                audit_saved = true;

                // Show summary and offer restore
                if !changes.is_empty() {
                    output::print_rollback_session_summary(&changes, flags.silent);

                    if !flags.no_rollback_prompt && !flags.silent {
                        let _ = rollback_ui::review_and_restore(&manager, &baseline, &changes);
                    }
                }

                let _ = manager.cleanup_new_atomic_temp_files(&atomic_temp_before);
            }

            // Audit-only: write session.json when rollback didn't handle it
            if !audit_saved {
                if let Some((ref session_id, ref session_dir)) = audit_state {
                    let meta = nono::undo::SessionMetadata {
                        session_id: session_id.clone(),
                        started,
                        ended: Some(ended),
                        command: command.clone(),
                        tracked_paths: Vec::new(),
                        snapshot_count: 0,
                        exit_code: Some(exit_code),
                        merkle_roots: Vec::new(),
                        network_events,
                    };
                    nono::undo::SnapshotManager::write_session_metadata(session_dir, &meta)?;
                }
            }

            if let Some(cap_file_path) = cap_file_path.as_ref() {
                cleanup_capability_state_file(cap_file_path);
            }
            drop(config);
            drop(loaded_secrets);
            std::process::exit(exit_code);
        }
    }
}

/// VCS-only exclusions for `--rollback-all` mode.
///
/// When the user opts into snapshotting everything, only VCS internals are
/// excluded because restoring partial `.git/` contents corrupts the repository.
fn rollback_vcs_exclusions() -> Vec<String> {
    [".git", ".hg", ".svn"]
        .iter()
        .map(|s| String::from(*s))
        .collect()
}

/// Base exclusion patterns for rollback snapshots.
///
/// These are CLI policy — the library provides only the matching mechanism.
/// Profiles can add additional patterns via `rollback.exclude_patterns` in
/// policy.json. Patterns without `/` match exact path components; patterns
/// with `/` match as substrings of the full path.
pub(crate) fn rollback_base_exclusions() -> Vec<String> {
    [
        // VCS internals — git manages its own state; restoring partial
        // .git/ contents (e.g. index without matching objects) corrupts
        // the repository
        ".git",
        ".hg",
        ".svn",
        // Build artifacts — fully regenerable from source
        "target",
        "node_modules",
        "__pycache__",
        ".venv",
        // OS metadata
        ".DS_Store",
    ]
    .iter()
    .map(|s| String::from(*s))
    .collect()
}

/// Result of sandbox preparation
struct PreparedSandbox {
    caps: CapabilitySet,
    secrets: Vec<nono::LoadedSecret>,
    /// Profile-specific rollback exclusion patterns (additive on base patterns)
    rollback_exclude_patterns: Vec<String>,
    /// Profile-specific rollback exclusion globs (filename matching)
    rollback_exclude_globs: Vec<String>,
    /// Directory names to skip during trust scanning and rollback preflight.
    skip_dirs: Vec<String>,
    /// Network profile name from profile config (if any)
    network_profile: Option<String>,
    /// Additional proxy-allowed domains from profile config
    allow_domain: Vec<String>,
    /// Credential services from profile config
    credentials: Vec<String>,
    /// Custom credential definitions from profile config
    custom_credentials: std::collections::HashMap<String, profile::CustomCredentialDef>,
    /// Upstream proxy address from profile config (if any)
    upstream_proxy: Option<String>,
    /// Bypass hosts for upstream proxy from profile config
    upstream_bypass: Vec<String>,
    /// TCP ports the sandboxed child may listen on from profile config
    listen_ports: Vec<u16>,
    /// Whether the profile enables runtime capability elevation (seccomp-notify + PTY)
    capability_elevation: bool,
    /// WSL2 proxy fallback policy from profile
    #[cfg(target_os = "linux")]
    wsl2_proxy_policy: crate::profile::Wsl2ProxyPolicy,
    /// Whether direct LaunchServices opens are enabled for this session.
    allow_launch_services_active: bool,
    /// Allowed URL origins for supervisor-delegated browser opens
    #[cfg(not(target_os = "windows"))]
    open_url_origins: Vec<String>,
    /// Whether to allow http://localhost URL opens
    #[cfg(not(target_os = "windows"))]
    open_url_allow_localhost: bool,
    /// Canonicalized paths exempted from deny groups via override_deny
    override_deny_paths: Vec<std::path::PathBuf>,
}

fn parse_env_credential_map_args(values: &[String]) -> Result<Vec<(String, String)>> {
    // Clap enforces 2 values per occurrence for --env-credential-map, but keep
    // this check fail-secure in case argument wiring changes.
    if values.len() % 2 != 0 {
        return Err(NonoError::ConfigParse(
            "--env-credential-map expects pairs: <CREDENTIAL_REF> <ENV_VAR>".to_string(),
        ));
    }

    let mut pairs = Vec::with_capacity(values.len() / 2);
    for chunk in values.chunks_exact(2) {
        let credential_ref = chunk[0].trim();
        let env_var = chunk[1].trim();

        if credential_ref.is_empty() {
            return Err(NonoError::ConfigParse(
                "--env-credential-map has an empty credential reference".to_string(),
            ));
        }

        if env_var.is_empty() {
            return Err(NonoError::ConfigParse(
                "--env-credential-map has an empty destination env var".to_string(),
            ));
        }

        pairs.push((credential_ref.to_string(), env_var.to_string()));
    }

    Ok(pairs)
}

#[cfg(target_os = "macos")]
fn maybe_enable_macos_launch_services(
    caps: &mut CapabilitySet,
    cli_requested: bool,
    profile_allowed: bool,
    open_url_origins: &[String],
    open_url_allow_localhost: bool,
) -> Result<bool> {
    if !cli_requested {
        return Ok(false);
    }

    if !profile_allowed {
        return Err(NonoError::ConfigParse(
            "--allow-launch-services requires a profile that opts into allow_launch_services"
                .to_string(),
        ));
    }

    if open_url_origins.is_empty() && !open_url_allow_localhost {
        return Err(NonoError::ConfigParse(
            "--allow-launch-services requires the selected profile to configure open_urls"
                .to_string(),
        ));
    }

    // Allow LaunchServices URL opening directly from inside the Seatbelt sandbox.
    // This bypasses supervisor URL validation on macOS, so it must be gated by
    // both profile opt-in and an explicit CLI flag.
    caps.add_platform_rule("(allow lsopen)")?;
    warn!("--allow-launch-services enabled: allowing direct LaunchServices opens on macOS");
    Ok(true)
}

#[cfg(not(target_os = "macos"))]
fn maybe_enable_macos_launch_services(
    _caps: &mut CapabilitySet,
    cli_requested: bool,
    _profile_allowed: bool,
    _open_url_origins: &[String],
    _open_url_allow_localhost: bool,
) -> Result<bool> {
    if cli_requested {
        return Err(NonoError::ConfigParse(
            "--allow-launch-services is only supported on macOS".to_string(),
        ));
    }
    Ok(false)
}

fn print_allow_launch_services_warning(silent: bool) {
    if silent {
        return;
    }

    eprintln!(
        "  {}",
        "WARNING: --allow-launch-services permits the sandboxed process to ask macOS \
         LaunchServices to open URLs, files, or apps."
            .yellow()
    );
    eprintln!("  Use this only for temporary login/setup flows, then exit and rerun without it.");
    eprintln!("  Prefer using it from a trusted directory, not inside an untrusted project.");
}

fn prepare_sandbox(args: &SandboxArgs, silent: bool) -> Result<PreparedSandbox> {
    // Clean up stale state files from previous nono runs
    sandbox_state::cleanup_stale_state_files();

    // Load profile once if specified (used for both capabilities and secrets)
    let loaded_profile = if let Some(ref profile_name) = args.profile {
        let prof = profile::load_profile(profile_name)?;

        // Install hooks defined in the profile (idempotent - only installs if needed)
        if !prof.hooks.hooks.is_empty() {
            match hooks::install_profile_hooks(&prof.hooks.hooks) {
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
                            | hooks::HookInstallResult::Skipped => {
                                // Silent - hook already set up
                            }
                        }
                    }
                }
                Err(e) => {
                    // Hook installation failure is non-fatal - warn and continue
                    tracing::warn!("Failed to install profile hooks: {}", e);
                    if !silent {
                        eprintln!("  Warning: Failed to install hooks: {}", e);
                    }
                }
            }
        }

        Some(prof)
    } else {
        None
    };

    // Resolve the working directory
    let workdir = args
        .workdir
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    // Collect override_deny paths from profile (canonicalized for query use)
    let override_deny_paths: Vec<std::path::PathBuf> = loaded_profile
        .as_ref()
        .map(|prof| {
            prof.policy
                .override_deny
                .iter()
                .filter_map(|tmpl| {
                    profile::expand_vars(tmpl, &workdir).ok().map(|expanded| {
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

    // Also include CLI --override-deny paths.
    // Apply the same ~ / $HOME expansion that apply_deny_overrides uses
    // so the stored paths match the canonicalized form used by query_path.
    let override_deny_paths: Vec<std::path::PathBuf> = {
        let mut paths = override_deny_paths;
        for p in &args.override_deny {
            let path_str = p.to_string_lossy();
            let expanded = profile::expand_vars(&path_str, &workdir).unwrap_or_else(|_| p.clone());
            let canonical = if expanded.exists() {
                expanded.canonicalize().unwrap_or(expanded)
            } else {
                expanded
            };
            if !paths.contains(&canonical) {
                paths.push(canonical);
            }
        }
        paths
    };

    // Extract config before profile is consumed for secrets
    let capability_elevation = loaded_profile
        .as_ref()
        .and_then(|p| p.security.capability_elevation)
        .unwrap_or(false);
    #[cfg(target_os = "linux")]
    let wsl2_proxy_policy = loaded_profile
        .as_ref()
        .and_then(|p| p.security.wsl2_proxy_policy)
        .unwrap_or_default();
    let profile_workdir_access = loaded_profile.as_ref().map(|p| p.workdir.access.clone());
    let profile_rollback_patterns = loaded_profile
        .as_ref()
        .map(|p| p.rollback.exclude_patterns.clone())
        .unwrap_or_default();
    let profile_rollback_globs = loaded_profile
        .as_ref()
        .map(|p| p.rollback.exclude_globs.clone())
        .unwrap_or_default();
    let profile_skip_dirs = loaded_profile
        .as_ref()
        .map(|p| p.skipdirs.clone())
        .unwrap_or_default();
    let profile_network_profile = loaded_profile.as_ref().and_then(|p| {
        p.network
            .resolved_network_profile()
            .map(|value| value.to_string())
    });
    let profile_allow_domain = loaded_profile
        .as_ref()
        .map(|p| p.network.allow_domain.clone())
        .unwrap_or_default();
    let profile_credentials = loaded_profile
        .as_ref()
        .map(|p| p.network.credentials.clone())
        .unwrap_or_default();
    let profile_custom_credentials = loaded_profile
        .as_ref()
        .map(|p| p.network.custom_credentials.clone())
        .unwrap_or_default();
    let profile_upstream_proxy = loaded_profile
        .as_ref()
        .and_then(|p| p.network.upstream_proxy.clone());
    let profile_upstream_bypass = loaded_profile
        .as_ref()
        .map(|p| p.network.upstream_bypass.clone())
        .unwrap_or_default();
    let profile_listen_ports = loaded_profile
        .as_ref()
        .map(|p| p.network.listen_port.clone())
        .unwrap_or_default();
    let open_url_origins = loaded_profile
        .as_ref()
        .and_then(|p| p.open_urls.as_ref())
        .map(|u| u.allow_origins.clone())
        .unwrap_or_default();
    let open_url_allow_localhost = loaded_profile
        .as_ref()
        .and_then(|p| p.open_urls.as_ref())
        .map(|u| u.allow_localhost)
        .unwrap_or(false);
    let profile_allow_launch_services = loaded_profile
        .as_ref()
        .and_then(|p| p.allow_launch_services)
        .unwrap_or(false);

    // On Linux, pre-create paths that the claude-code profile grants but
    // may not exist yet. Non-existent paths are skipped during capability
    // construction (capability_ext.rs:14), so they must exist before we
    // build the CapabilitySet.
    #[cfg(target_os = "linux")]
    if args.profile.as_deref() == Some("claude-code") {
        let home = config::validated_home()?;
        let home_path = std::path::Path::new(&home);

        let precreate = |path: &std::path::Path, is_dir: bool| {
            if !path.exists() {
                let result = if is_dir {
                    std::fs::create_dir_all(path)
                } else {
                    std::fs::File::create(path).map(|_| ())
                };
                if let Err(e) = result {
                    warn!("Failed to pre-create {}: {}", path.display(), e);
                }
            }
        };

        // ~/.claude.json.lock — Claude Code's saveConfigWithLock creates this
        // next to ~/.claude.json. Landlock cannot grant permission to create
        // new files in ~/ without opening the entire directory.
        precreate(&home_path.join(".claude.json.lock"), false);

        // ~/.cache/claude-cli-nodejs — MCP server logs and CLI cache.
        // The claude_cache_linux group grants this directory, but it may
        // not exist on a fresh system.
        precreate(&home_path.join(".cache/claude-cli-nodejs"), true);
    }

    // Build capabilities from profile or arguments.
    // Unlink overrides are deferred so they can cover the CWD path added below.
    let (mut caps, needs_unlink_overrides) = if let Some(ref prof) = loaded_profile {
        CapabilitySet::from_profile(prof, &workdir, args)?
    } else {
        CapabilitySet::from_args(args)?
    };

    let allow_launch_services_active = maybe_enable_macos_launch_services(
        &mut caps,
        args.allow_launch_services,
        profile_allow_launch_services,
        &open_url_origins,
        open_url_allow_localhost,
    )?;

    // Auto-include CWD based on profile [workdir] config or default behavior
    let cwd_access = if let Some(ref access) = profile_workdir_access {
        match access {
            WorkdirAccess::Read => Some(AccessMode::Read),
            WorkdirAccess::Write => Some(AccessMode::Write),
            WorkdirAccess::ReadWrite => Some(AccessMode::ReadWrite),
            WorkdirAccess::None => None,
        }
    } else {
        // No profile: default to read-only CWD access
        Some(AccessMode::Read)
    };

    if let Some(access) = cwd_access {
        // Canonicalize CWD for path comparison
        let cwd_canonical =
            workdir
                .canonicalize()
                .map_err(|e| NonoError::PathCanonicalization {
                    path: workdir.clone(),
                    source: e,
                })?;

        // Only auto-add if CWD is not already covered with sufficient access
        if !caps.path_covered_with_access(&cwd_canonical, access) {
            if args.allow_cwd {
                // --allow-cwd: add without prompting
                info!("Auto-including CWD with {} access (--allow-cwd)", access);
                let cap = FsCapability::new_dir(workdir.clone(), access)?;
                caps.add_fs(cap);
            } else if silent {
                // Silent mode: cannot prompt, require --allow-cwd
                return Err(NonoError::CwdPromptRequired);
            } else {
                // Interactive: prompt user for confirmation
                let confirmed = output::prompt_cwd_sharing(&cwd_canonical, &access)?;
                if confirmed {
                    let cap = FsCapability::new_dir(workdir.clone(), access)?;
                    caps.add_fs(cap);
                } else {
                    info!("User declined CWD sharing. Continuing without automatic CWD access.");
                }
            }
            caps.deduplicate();
        }
    }

    // Final deny/allow overlap validation after ALL path grants are finalized,
    // including auto-included CWD. This closes the Linux Landlock blind spot
    // where deny-within-allow cannot be enforced.
    let active_groups = if let Some(prof) = loaded_profile
        .as_ref()
        .filter(|p| !p.security.groups.is_empty())
    {
        prof.security.groups.clone()
    } else {
        crate::capability_ext::default_profile_groups()?
    };
    let loaded_policy = policy::load_embedded_policy()?;
    let deny_paths = policy::resolve_deny_paths_for_groups(&loaded_policy, &active_groups)?;
    policy::validate_deny_overlaps(&deny_paths, &caps)?;
    let protected_roots = protected_paths::ProtectedRoots::from_defaults()?;
    protected_paths::validate_caps_against_protected_roots(&caps, protected_roots.as_paths())?;

    // Apply deferred unlink overrides now that ALL writable paths are finalized
    // (groups + profile [filesystem] + CLI overrides + CWD).
    if needs_unlink_overrides {
        crate::policy::apply_unlink_overrides(&mut caps);
    }

    // Check if any capabilities are specified
    if !caps.has_fs() && caps.is_network_blocked() {
        return Err(NonoError::NoCapabilities);
    }

    // Build secret mappings from profile and/or CLI
    let profile_secrets = loaded_profile
        .map(|p| p.env_credentials.mappings)
        .unwrap_or_default();
    let cli_secret_mappings = parse_env_credential_map_args(&args.env_credential_map)?;

    let secret_mappings = nono::keystore::build_secret_mappings(
        args.env_credential.as_deref(),
        &cli_secret_mappings,
        &profile_secrets,
    )?;

    // Load credentials from keystore/URI managers BEFORE sandbox is applied
    let loaded_secrets = if !secret_mappings.is_empty() {
        let op_count = secret_mappings
            .keys()
            .filter(|k| nono::keystore::is_op_uri(k))
            .count();
        let apple_password_count = secret_mappings
            .keys()
            .filter(|k| nono::keystore::is_apple_password_uri(k))
            .count();
        let keyring_count = secret_mappings.len() - op_count - apple_password_count;

        info!(
            "Loading {} credential(s) (keyring: {}, 1Password: {}, Apple Passwords: {})",
            secret_mappings.len(),
            keyring_count,
            op_count,
            apple_password_count
        );
        if !silent {
            let mut source_parts: Vec<String> = Vec::new();
            if keyring_count > 0 {
                source_parts.push(format!("{} from keystore", keyring_count));
            }
            if op_count > 0 {
                source_parts.push(format!("{} from 1Password", op_count));
            }
            if apple_password_count > 0 {
                source_parts.push(format!("{} from Apple Passwords", apple_password_count));
            }

            eprintln!(
                "  Loading {} credential(s) ({})...",
                secret_mappings.len(),
                source_parts.join(", ")
            );

            // Warn that env credentials are visible to the sandboxed process
            for account in secret_mappings.keys() {
                let display_account = if nono::keystore::is_op_uri(account) {
                    nono::keystore::redact_op_uri(account)
                } else if nono::keystore::is_apple_password_uri(account) {
                    nono::keystore::redact_apple_password_uri(account)
                } else {
                    account.to_string()
                };
                eprintln!(
                    "  {}: env credential '{}' exposes the secret directly to the sandboxed process.\n\
                     {}  For network API keys, use a profile with credentials for credential isolation.",
                    "warning".yellow(),
                    display_account,
                    " ".repeat(11),
                );
            }
        }
        nono::keystore::load_secrets(nono::keystore::DEFAULT_SERVICE, &secret_mappings)?
    } else {
        Vec::new()
    };

    // Print capability summary
    output::print_capabilities(&caps, args.verbose, silent);

    // Print Landlock ABI info on Linux
    #[cfg(target_os = "linux")]
    output::print_abi_info(silent);

    // Check platform support. Dry-run validates configuration and command
    // resolution, so it must remain usable on preview platforms even when
    // live sandbox enforcement is not implemented yet.
    let support = Sandbox::support_info();
    #[cfg(not(target_os = "windows"))]
    if !args.dry_run && !support.is_supported {
        return Err(NonoError::SandboxInit(format!(
            "{} support status: {}. {}",
            support.platform,
            support.status_label(),
            support.details
        )));
    }

    #[cfg(target_os = "windows")]
    if !args.dry_run && !support.is_supported {
        info!(
            "{} support status: {}. {}",
            support.platform,
            support.status_label(),
            support.details
        );
    }

    if support.is_supported || args.dry_run {
        info!(
            "{} support status: {}. {}",
            support.platform,
            support.status_label(),
            support.details
        );
    }

    Ok(PreparedSandbox {
        caps,
        secrets: loaded_secrets,
        rollback_exclude_patterns: profile_rollback_patterns,
        rollback_exclude_globs: profile_rollback_globs,
        skip_dirs: profile_skip_dirs,
        network_profile: profile_network_profile,
        allow_domain: profile_allow_domain,
        credentials: profile_credentials,
        custom_credentials: profile_custom_credentials,
        upstream_proxy: profile_upstream_proxy,
        upstream_bypass: profile_upstream_bypass,
        listen_ports: profile_listen_ports,
        capability_elevation,
        #[cfg(target_os = "linux")]
        wsl2_proxy_policy,
        allow_launch_services_active,
        #[cfg(not(target_os = "windows"))]
        open_url_origins,
        #[cfg(not(target_os = "windows"))]
        open_url_allow_localhost,
        override_deny_paths,
    })
}

/// Enforce rollback storage limits before creating a new session.
///
/// Loads user config (or defaults) and prunes oldest completed sessions
/// until session count and total storage are under the configured limits.
/// Errors are logged but non-fatal — failing to prune should not block
/// the sandbox from running.
fn enforce_rollback_limits(silent: bool) {
    let config = match config::user::load_user_config() {
        Ok(Some(c)) => c,
        Ok(None) => config::user::UserConfig::default(),
        Err(e) => {
            tracing::warn!("Failed to load user config for rollback limits: {e}");
            return;
        }
    };

    let sessions = match rollback_session::discover_sessions() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("Failed to discover sessions for limit enforcement: {e}");
            return;
        }
    };

    if sessions.is_empty() {
        return;
    }

    let max_sessions = config.rollback.max_sessions;
    // Clamp to 0.0 to prevent negative/NaN from producing bogus u64 values
    let storage_bytes_f64 =
        (config.rollback.max_storage_gb.max(0.0) * 1024.0 * 1024.0 * 1024.0).min(u64::MAX as f64);
    let max_storage_bytes = storage_bytes_f64 as u64;

    // Sessions are sorted newest-first. Only prune completed (non-alive) sessions.
    let completed: Vec<&rollback_session::SessionInfo> =
        sessions.iter().filter(|s| !s.is_alive).collect();

    let mut pruned = 0usize;
    let mut pruned_bytes = 0u64;

    // Prune excess sessions beyond keep limit
    if completed.len() > max_sessions {
        for s in &completed[max_sessions..] {
            if let Err(e) = rollback_session::remove_session(&s.dir) {
                tracing::warn!("Failed to prune session {}: {e}", s.metadata.session_id);
            } else {
                pruned = pruned.saturating_add(1);
                pruned_bytes = pruned_bytes.saturating_add(s.disk_size);
            }
        }
    }

    // Prune by storage limit if still over
    let total = match rollback_session::total_storage_bytes() {
        Ok(t) => t,
        Err(_) => return,
    };

    if total > max_storage_bytes {
        // Re-discover after count-based pruning
        let remaining = match rollback_session::discover_sessions() {
            Ok(s) => s,
            Err(_) => return,
        };

        // Prune oldest completed sessions until under limit
        let mut current_total = total;
        for s in remaining.iter().rev().filter(|s| !s.is_alive) {
            if current_total <= max_storage_bytes {
                break;
            }
            if let Err(e) = rollback_session::remove_session(&s.dir) {
                tracing::warn!("Failed to prune session {}: {e}", s.metadata.session_id);
            } else {
                current_total = current_total.saturating_sub(s.disk_size);
                pruned = pruned.saturating_add(1);
                pruned_bytes = pruned_bytes.saturating_add(s.disk_size);
            }
        }
    }

    if pruned > 0 && !silent {
        eprintln!(
            "  Auto-pruned {} old session(s) (freed {})",
            pruned,
            rollback_session::format_bytes(pruned_bytes),
        );
    }
}

fn write_capability_state_file(
    caps: &CapabilitySet,
    override_deny_paths: &[std::path::PathBuf],
    preferred_runtime_dir: Option<&std::path::Path>,
    silent: bool,
) -> Option<std::path::PathBuf> {
    // Write sandbox state for `nono why --self`.
    #[cfg(target_os = "windows")]
    let cap_file = if let Some(runtime_dir) = preferred_runtime_dir {
        let runtime_tmp_dir = runtime_dir.join(".nono-runtime").join("tmp");
        if let Err(e) = std::fs::create_dir_all(&runtime_tmp_dir) {
            error!(
                "Failed to create Windows runtime state directory {}: {}",
                runtime_tmp_dir.display(),
                e
            );
            if !silent {
                eprintln!(
                    "  WARNING: Windows runtime state directory could not be created.\n  \
                     The sandbox will continue, but runtime state files will be disabled."
                );
            }
            return None;
        }
        runtime_tmp_dir.join(format!(".nono-{}.json", std::process::id()))
    } else {
        return None;
    };
    #[cfg(not(target_os = "windows"))]
    let cap_file = {
        let _ = preferred_runtime_dir;
        std::env::temp_dir().join(format!(".nono-{}.json", std::process::id()))
    };

    let state = sandbox_state::SandboxState::from_caps(caps, override_deny_paths);
    if let Err(e) = state.write_to_file(&cap_file) {
        error!(
            "Failed to write capability state file: {}. \
             Sandboxed processes will not be able to query their own capabilities using 'nono why --self'.",
            e
        );
        if !silent {
            eprintln!(
                "  WARNING: Capability state file could not be written.\n  \
                 The sandbox is active, but 'nono why --self' will not work inside this sandbox."
            );
        }
        None
    } else {
        Some(cap_file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox_args() -> SandboxArgs {
        SandboxArgs::default()
    }

    #[test]
    fn test_sensitive_paths_defined() {
        let loaded_policy = policy::load_embedded_policy().expect("policy must load");
        let paths = policy::get_sensitive_paths(&loaded_policy).expect("must resolve");
        assert!(paths.iter().any(|(p, _)| p.contains("ssh")));
        assert!(paths.iter().any(|(p, _)| p.contains("aws")));
    }

    #[test]
    fn test_dangerous_commands_defined() {
        let loaded_policy = policy::load_embedded_policy().expect("policy must load");
        let commands = policy::get_dangerous_commands(&loaded_policy);
        assert!(commands.contains("rm"));
        assert!(commands.contains("dd"));
        assert!(commands.contains("chmod"));
    }

    #[test]
    fn test_check_blocked_command_basic() {
        assert!(config::check_blocked_command("echo", &[], &[])
            .expect("policy must load")
            .is_none());
        assert!(config::check_blocked_command("ls", &[], &[])
            .expect("policy must load")
            .is_none());
        assert!(config::check_blocked_command("cat", &[], &[])
            .expect("policy must load")
            .is_none());
    }

    #[test]
    fn test_check_blocked_command_with_path() {
        let blocked = vec!["rm".to_string(), "dd".to_string()];
        assert!(config::check_blocked_command("/bin/rm", &[], &blocked)
            .expect("policy must load")
            .is_some());
        assert!(config::check_blocked_command("/usr/bin/dd", &[], &blocked)
            .expect("policy must load")
            .is_some());
        assert!(config::check_blocked_command("./rm", &[], &blocked)
            .expect("policy must load")
            .is_some());
    }

    #[test]
    fn test_check_blocked_command_allow_override() {
        let allowed = vec!["rm".to_string()];
        let blocked = vec!["rm".to_string(), "dd".to_string()];
        assert!(config::check_blocked_command("rm", &allowed, &blocked)
            .expect("policy must load")
            .is_none());
        assert!(config::check_blocked_command("dd", &allowed, &blocked)
            .expect("policy must load")
            .is_some());
    }

    #[test]
    fn test_check_blocked_command_extra_blocked() {
        let extra = vec!["custom-dangerous".to_string()];
        assert!(
            config::check_blocked_command("custom-dangerous", &[], &extra)
                .expect("policy must load")
                .is_some()
        );
        assert!(config::check_blocked_command("rm", &[], &extra)
            .expect("policy must load")
            .is_none());
    }

    #[test]
    fn test_check_blocked_command_uses_resolved_policy_only() {
        assert!(config::check_blocked_command("rm", &[], &[])
            .expect("policy must load")
            .is_none());
    }

    #[test]
    fn test_resolve_effective_proxy_settings_allow_net_clears_profile_proxy_state() {
        let args = SandboxArgs {
            allow_net: true,
            ..sandbox_args()
        };
        let prepared = PreparedSandbox {
            caps: CapabilitySet::new(),
            secrets: Vec::new(),
            rollback_exclude_patterns: Vec::new(),
            rollback_exclude_globs: Vec::new(),
            skip_dirs: Vec::new(),
            network_profile: Some("developer".to_string()),
            allow_domain: vec!["docs.python.org".to_string()],
            credentials: vec!["github".to_string()],
            custom_credentials: std::collections::HashMap::new(),
            upstream_proxy: None,
            upstream_bypass: Vec::new(),
            listen_ports: Vec::new(),
            capability_elevation: false,
            #[cfg(target_os = "linux")]
            wsl2_proxy_policy: crate::profile::Wsl2ProxyPolicy::Error,
            allow_launch_services_active: false,
            #[cfg(not(target_os = "windows"))]
            open_url_origins: Vec::new(),
            #[cfg(not(target_os = "windows"))]
            open_url_allow_localhost: false,
            override_deny_paths: Vec::new(),
        };

        let effective = resolve_effective_proxy_settings(&args, &prepared);

        assert_eq!(
            effective,
            EffectiveProxySettings {
                network_profile: None,
                allow_domain: Vec::new(),
                credentials: Vec::new(),
            }
        );
    }

    #[test]
    fn test_resolve_effective_proxy_settings_merges_cli_and_profile() {
        let args = SandboxArgs {
            network_profile: Some("minimal".to_string()),
            allow_proxy: vec!["example.com".to_string()],
            proxy_credential: vec!["openai".to_string()],
            ..sandbox_args()
        };
        let prepared = PreparedSandbox {
            caps: CapabilitySet::new(),
            secrets: Vec::new(),
            rollback_exclude_patterns: Vec::new(),
            rollback_exclude_globs: Vec::new(),
            skip_dirs: Vec::new(),
            network_profile: Some("developer".to_string()),
            allow_domain: vec!["docs.python.org".to_string()],
            credentials: vec!["github".to_string()],
            custom_credentials: std::collections::HashMap::new(),
            upstream_proxy: None,
            upstream_bypass: Vec::new(),
            listen_ports: Vec::new(),
            capability_elevation: false,
            #[cfg(target_os = "linux")]
            wsl2_proxy_policy: crate::profile::Wsl2ProxyPolicy::Error,
            allow_launch_services_active: false,
            #[cfg(not(target_os = "windows"))]
            open_url_origins: Vec::new(),
            #[cfg(not(target_os = "windows"))]
            open_url_allow_localhost: false,
            override_deny_paths: Vec::new(),
        };

        let effective = resolve_effective_proxy_settings(&args, &prepared);

        assert_eq!(
            effective,
            EffectiveProxySettings {
                network_profile: Some("minimal".to_string()),
                allow_domain: vec!["docs.python.org".to_string(), "example.com".to_string()],
                credentials: vec!["github".to_string(), "openai".to_string()],
            }
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_apply_pre_fork_sandbox_allows_windows_preview_direct_execution() {
        let caps = CapabilitySet::new();
        let current_dir = std::env::current_dir().expect("cwd");
        apply_pre_fork_sandbox(
            exec_strategy::ExecStrategy::Direct,
            &caps,
            &current_dir,
            true,
        )
        .expect("windows preview direct execution should not fail");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_preview_context_marks_deny_override_policy() {
        let args = SandboxArgs {
            profile: Some("codex".to_string()),
            block_net: true,
            network_profile: Some("restricted".to_string()),
            allow_proxy: vec!["example.com".to_string()],
            override_deny: vec![std::path::PathBuf::from("~/secret")],
            ..sandbox_args()
        };

        let context = nono::WindowsPreviewContext {
            has_deny_override_policy: !args.override_deny.is_empty(),
        };
        assert!(context.has_deny_override_policy);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_validate_windows_preview_direct_execution_allows_supported_directory_subset() {
        let dir = tempfile::tempdir().expect("tempdir");
        let workdir = dir.path().join("workspace");
        std::fs::create_dir_all(&workdir).expect("mkdir workspace");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let flags = ExecutionFlags {
            strategy: exec_strategy::ExecStrategy::Direct,
            workdir,
            rollback: false,
            no_rollback: false,
            no_rollback_prompt: false,
            no_audit: false,
            silent: true,
            rollback_all: false,
            rollback_include: Vec::new(),
            rollback_dest: None,
            trust_interception_active: false,
            rollback_exclude_patterns: Vec::new(),
            rollback_exclude_globs: Vec::new(),
            skip_dirs: Vec::new(),
            proxy_active: false,
            network_profile: None,
            allow_domain: Vec::new(),
            credentials: Vec::new(),
            custom_credentials: std::collections::HashMap::new(),
            upstream_proxy: None,
            upstream_bypass: Vec::new(),
            allow_bind_ports: Vec::new(),
            allow_endpoint: Vec::new(),
            proxy_port: None,
            supervisor_requested_features: Vec::new(),
            override_deny_paths: Vec::new(),
        };

        validate_windows_preview_direct_execution(&flags, &caps)
            .expect("supported directory subset should proceed on Windows preview");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_validate_windows_preview_direct_execution_blocks_unsupported_override_deny() {
        let dir = tempfile::tempdir().expect("tempdir");
        let flags = ExecutionFlags {
            strategy: exec_strategy::ExecStrategy::Direct,
            workdir: dir.path().to_path_buf(),
            rollback: false,
            no_rollback: false,
            no_rollback_prompt: false,
            no_audit: false,
            silent: true,
            rollback_all: false,
            rollback_include: Vec::new(),
            rollback_dest: None,
            trust_interception_active: false,
            rollback_exclude_patterns: Vec::new(),
            rollback_exclude_globs: Vec::new(),
            skip_dirs: Vec::new(),
            proxy_active: false,
            network_profile: None,
            allow_domain: Vec::new(),
            credentials: Vec::new(),
            custom_credentials: std::collections::HashMap::new(),
            upstream_proxy: None,
            upstream_bypass: Vec::new(),
            allow_bind_ports: Vec::new(),
            allow_endpoint: Vec::new(),
            proxy_port: None,
            supervisor_requested_features: Vec::new(),
            override_deny_paths: vec![dir.path().to_path_buf()],
        };

        let err = validate_windows_preview_direct_execution(&flags, &CapabilitySet::new())
            .expect_err("override_deny should remain blocked on Windows preview");
        assert!(err.to_string().contains("deny-override"));
    }

    #[test]
    fn test_trust_interception_inactive_for_default_policy() {
        let policy = nono::trust::TrustPolicy::default();

        assert!(!trust_interception_active(Some(&policy)));
    }

    #[test]
    fn test_trust_interception_active_when_includes_exist() {
        let policy = nono::trust::TrustPolicy {
            includes: vec!["SKILLS.md".to_string()],
            ..nono::trust::TrustPolicy::default()
        };

        assert!(trust_interception_active(Some(&policy)));
    }

    #[test]
    fn test_select_exec_strategy_prefers_direct_for_plain_run() {
        assert_eq!(
            select_exec_strategy(false, false, false, false),
            exec_strategy::ExecStrategy::Direct
        );
    }

    #[test]
    fn test_select_exec_strategy_uses_supervised_for_rollback() {
        assert_eq!(
            select_exec_strategy(true, false, false, false),
            exec_strategy::ExecStrategy::Supervised
        );
    }

    #[test]
    fn test_select_exec_strategy_uses_supervised_for_proxy() {
        assert_eq!(
            select_exec_strategy(false, true, false, false),
            exec_strategy::ExecStrategy::Supervised
        );
    }

    #[test]
    fn test_select_exec_strategy_uses_supervised_for_capability_elevation() {
        assert_eq!(
            select_exec_strategy(false, false, true, false),
            exec_strategy::ExecStrategy::Supervised
        );
    }

    #[test]
    fn test_select_exec_strategy_uses_supervised_for_trust_interception() {
        assert_eq!(
            select_exec_strategy(false, false, false, true),
            exec_strategy::ExecStrategy::Supervised
        );
    }

    #[test]
    fn test_execution_start_dir_keeps_workdir_when_covered() {
        let dir = tempfile::tempdir().expect("tempdir");
        let canonical = dir.path().canonicalize().expect("canonicalize");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_dir(dir.path(), AccessMode::Read).expect("grant"));

        let start_dir = execution_start_dir(dir.path(), &caps).expect("start dir");

        assert_eq!(start_dir, canonical);
    }

    #[test]
    fn test_execution_start_dir_falls_back_to_root_when_not_covered() {
        let dir = tempfile::tempdir().expect("tempdir");
        let caps = CapabilitySet::new();

        let start_dir = execution_start_dir(dir.path(), &caps).expect("start dir");

        assert_eq!(start_dir, std::path::PathBuf::from("/"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_maybe_enable_macos_launch_services_adds_rule_when_enabled() {
        let mut caps = CapabilitySet::new();

        let enabled = maybe_enable_macos_launch_services(
            &mut caps,
            true,
            true,
            &["https://claude.ai".to_string()],
            false,
        )
        .expect("launch services gate should apply");

        assert!(enabled, "launch services should be active");
        assert!(
            caps.platform_rules().iter().any(|r| r == "(allow lsopen)"),
            "lsopen platform rule should be present"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_maybe_enable_macos_launch_services_rejects_without_profile_opt_in() {
        let mut caps = CapabilitySet::new();

        let err = maybe_enable_macos_launch_services(
            &mut caps,
            true,
            false,
            &["https://claude.ai".to_string()],
            false,
        )
        .expect_err("missing profile opt-in should fail");

        assert!(
            err.to_string().contains("requires a profile"),
            "error should mention profile opt-in"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_maybe_enable_macos_launch_services_rejects_without_open_urls() {
        let mut caps = CapabilitySet::new();

        let err = maybe_enable_macos_launch_services(&mut caps, true, true, &[], false)
            .expect_err("missing open_urls should fail");

        assert!(
            err.to_string().contains("configure open_urls"),
            "error should mention open_urls"
        );
    }
}
