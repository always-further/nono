mod capability;
mod cli;
mod config;
mod diagnostic;
mod error;
mod exec_strategy;
mod hooks;
mod keystore;
mod output;
mod profile;
mod query;
mod sandbox;
mod sandbox_state;
mod setup;

use capability::{CapabilitySet, FsAccess, FsCapability};
use clap::Parser;
use cli::{Cli, Commands, SandboxArgs, SetupArgs, ShellArgs, WhyArgs, WhyOp};
use colored::Colorize;
use error::{NonoError, Result};
use profile::WorkdirAccess;
use std::ffi::OsString;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_target(false)
        .init();

    if let Err(e) = run() {
        error!("{}", e);
        eprintln!("nono: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run(args) => {
            // Print banner for run command (unless silent)
            output::print_banner(cli.silent);
            run_sandbox(args.sandbox, args.command, cli.silent)
        }
        Commands::Shell(args) => {
            // Print banner for shell command (unless silent)
            output::print_banner(cli.silent);
            run_shell(*args, cli.silent)
        }
        Commands::Why(args) => {
            // Why doesn't print banner (designed for programmatic use by agents)
            run_why(*args)
        }
        Commands::Setup(args) => {
            // Setup prints its own banner
            run_setup(args)
        }
    }
}

/// Set up nono on this system
fn run_setup(args: SetupArgs) -> Result<()> {
    let runner = setup::SetupRunner::new(&args);
    runner.run()
}

/// Check why a path or network operation would be allowed or denied
fn run_why(args: WhyArgs) -> Result<()> {
    use query::{print_result, query_network, query_path, QueryResult};
    use sandbox_state::load_sandbox_state;

    // Build capability set from args or load from sandbox state
    let caps = if args.self_query {
        // Inside sandbox - load from state file
        match load_sandbox_state() {
            Some(state) => state.to_caps(),
            None => {
                let result = QueryResult::NotSandboxed {
                    message: "Not running inside a nono sandbox".to_string(),
                };
                if args.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&result).unwrap_or_default()
                    );
                } else {
                    print_result(&result);
                }
                return Ok(());
            }
        }
    } else if let Some(ref profile_name) = args.profile {
        // Load from profile
        let prof = profile::load_profile(profile_name, args.trust_unsigned)?;
        let workdir = args
            .workdir
            .clone()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| std::path::PathBuf::from("."));

        // Create a minimal SandboxArgs to pass to from_profile
        let sandbox_args = SandboxArgs {
            allow: args.allow.clone(),
            read: args.read.clone(),
            write: args.write.clone(),
            allow_file: args.allow_file.clone(),
            read_file: args.read_file.clone(),
            write_file: args.write_file.clone(),
            net_block: args.net_block,
            allow_command: vec![],
            block_command: vec![],
            secrets: None,
            profile: None,
            allow_cwd: false,
            workdir: args.workdir.clone(),
            trust_unsigned: args.trust_unsigned,
            config: None,
            verbose: 0,
            dry_run: false,
        };

        CapabilitySet::from_profile(&prof, &workdir, &sandbox_args)?
    } else {
        // Build from CLI args
        let sandbox_args = SandboxArgs {
            allow: args.allow.clone(),
            read: args.read.clone(),
            write: args.write.clone(),
            allow_file: args.allow_file.clone(),
            read_file: args.read_file.clone(),
            write_file: args.write_file.clone(),
            net_block: args.net_block,
            allow_command: vec![],
            block_command: vec![],
            secrets: None,
            profile: None,
            allow_cwd: false,
            workdir: args.workdir.clone(),
            trust_unsigned: false,
            config: None,
            verbose: 0,
            dry_run: false,
        };

        CapabilitySet::from_args(&sandbox_args)?
    };

    // Execute the query
    let result = if let Some(ref path) = args.path {
        let op = match args.op {
            Some(WhyOp::Read) => FsAccess::Read,
            Some(WhyOp::Write) => FsAccess::Write,
            Some(WhyOp::ReadWrite) => FsAccess::ReadWrite,
            None => FsAccess::Read, // Default to read
        };
        query_path(path, op, &caps)?
    } else if let Some(ref host) = args.host {
        query_network(host, args.port, &caps)
    } else {
        return Err(NonoError::ConfigParse(
            "--path or --host is required".to_string(),
        ));
    };

    // Output result
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
    } else {
        print_result(&result);
    }

    Ok(())
}

/// Run a command inside the sandbox
fn run_sandbox(args: SandboxArgs, command: Vec<String>, silent: bool) -> Result<()> {
    // Check if we have a command to run
    if command.is_empty() {
        return Err(NonoError::NoCommand);
    }

    let mut command_iter = command.into_iter();
    let program = OsString::from(
        command_iter
            .next()
            .expect("command was validated non-empty above"),
    );
    let cmd_args: Vec<OsString> = command_iter.map(OsString::from).collect();

    // Dry run mode - just show what would happen
    if args.dry_run {
        let prepared = prepare_sandbox(&args, silent)?;
        if !prepared.secrets.is_empty() && !silent {
            eprintln!(
                "  Would inject {} secret(s) as environment variables",
                prepared.secrets.len()
            );
        }
        output::print_dry_run(&program, &cmd_args, silent);
        return Ok(());
    }

    let prepared = prepare_sandbox(&args, silent)?;
    execute_sandboxed(
        program,
        cmd_args,
        &prepared.caps,
        prepared.secrets,
        prepared.interactive,
        silent,
    )
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
                "  Would inject {} secret(s) as environment variables",
                prepared.secrets.len()
            );
        }
        output::print_dry_run(shell_path.as_os_str(), &[], silent);
        return Ok(());
    }

    let prepared = prepare_sandbox(&args.sandbox, silent)?;

    if !silent {
        eprintln!(
            "{}",
            "Exit the shell with Ctrl-D or 'exit'.".truecolor(150, 150, 150)
        );
        eprintln!();
    }

    // Shell is always interactive - needs TTY preservation
    execute_sandboxed(
        shell_path.into_os_string(),
        vec![],
        &prepared.caps,
        prepared.secrets,
        true, // Force interactive for shell
        silent,
    )
}

fn execute_sandboxed(
    program: OsString,
    cmd_args: Vec<OsString>,
    caps: &CapabilitySet,
    loaded_secrets: Vec<keystore::LoadedSecret>,
    interactive: bool,
    silent: bool,
) -> Result<()> {
    // Check if command is blocked using config module
    if let Some(blocked) =
        config::check_blocked_command(&program, &caps.allowed_commands, &caps.blocked_commands)
    {
        return Err(NonoError::BlockedCommand {
            command: blocked,
            reason: "This command is blocked by default due to destructive potential. \
                     Use --allow-command to override if you understand the risks."
                .to_string(),
        });
    }

    // Convert OsString command to String for exec_strategy
    // (lossy conversion is acceptable - non-UTF8 commands are rare)
    let command: Vec<String> = std::iter::once(program.to_string_lossy().into_owned())
        .chain(cmd_args.iter().map(|s| s.to_string_lossy().into_owned()))
        .collect();

    // Dry run mode - just show what would happen
    if command.is_empty() {
        return Err(NonoError::NoCommand);
    }

    // Resolve the program path BEFORE applying the sandbox.
    // This ensures the program can be found even if its directory
    // is not in the sandbox's allowed paths.
    let resolved_program = exec_strategy::resolve_program(&command[0])?;

    // Apply the sandbox
    output::print_applying_sandbox(silent);
    sandbox::apply(caps)?;
    output::print_sandbox_active(silent);

    // Write capability state file for `nono why --self`
    let cap_file = write_capability_state_file(caps, silent);
    let cap_file_path = cap_file.unwrap_or_else(|| std::path::PathBuf::from("/dev/null"));

    // Build environment variables for the command
    let env_vars: Vec<(&str, &str)> = loaded_secrets
        .iter()
        .map(|s| (s.env_var.as_str(), s.value.as_str()))
        .collect();

    // Determine execution strategy
    // Interactive mode (shell, TUI apps): use Direct exec for TTY preservation
    // Non-interactive: use Monitor mode for diagnostic output on failure
    let strategy = if interactive {
        exec_strategy::ExecStrategy::Direct
    } else {
        exec_strategy::ExecStrategy::Monitor
    };

    // Determine threading context for fork safety
    // If secrets were loaded, keyring may have spawned threads
    let threading = if !loaded_secrets.is_empty() {
        exec_strategy::ThreadingContext::KeyringExpected
    } else {
        exec_strategy::ThreadingContext::Strict
    };

    info!(
        "Executing with strategy: {:?}, threading: {:?}",
        strategy, threading
    );

    // Create execution config
    let config = exec_strategy::ExecConfig {
        command: &command,
        resolved_program: &resolved_program,
        caps,
        env_vars,
        cap_file: &cap_file_path,
        no_diagnostics: silent,
        threading,
    };

    // Execute based on strategy
    match strategy {
        exec_strategy::ExecStrategy::Direct => {
            // Direct exec: nono disappears after exec
            exec_strategy::execute_direct(&config)?;
            // Note: loaded_secrets will be dropped here, zeroizing the secret values
            unreachable!("execute_direct only returns on error");
        }
        exec_strategy::ExecStrategy::Monitor => {
            // Monitor mode: fork+wait with diagnostic on failure
            let exit_code = exec_strategy::execute_monitor(&config)?;
            // Note: loaded_secrets will be dropped here, zeroizing the secret values
            std::process::exit(exit_code);
        }
        exec_strategy::ExecStrategy::Supervised => {
            // Not yet implemented
            Err(NonoError::SandboxInit(
                "Supervised mode not yet implemented".to_string(),
            ))
        }
    }
}

/// Result of sandbox preparation
struct PreparedSandbox {
    caps: CapabilitySet,
    secrets: Vec<keystore::LoadedSecret>,
    /// Whether the profile indicates interactive mode (needs TTY)
    interactive: bool,
}

fn prepare_sandbox(args: &SandboxArgs, silent: bool) -> Result<PreparedSandbox> {
    // Set log level based on verbosity
    if args.verbose > 0 {
        match args.verbose {
            1 => std::env::set_var("RUST_LOG", "info"),
            2 => std::env::set_var("RUST_LOG", "debug"),
            _ => std::env::set_var("RUST_LOG", "trace"),
        }
    }

    // Clean up stale state files from previous nono runs
    // This prevents disk space exhaustion and information disclosure
    sandbox_state::cleanup_stale_state_files();
    // Load profile once if specified (used for both capabilities and secrets)
    let loaded_profile = if let Some(ref profile_name) = args.profile {
        let prof = profile::load_profile(profile_name, args.trust_unsigned)?;

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

    // Resolve the working directory (used for both profile expansion and CWD auto-inclusion)
    let workdir = args
        .workdir
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    // Extract config before profile is consumed for secrets
    let profile_workdir_access = loaded_profile.as_ref().map(|p| p.workdir.access.clone());
    let profile_interactive = loaded_profile
        .as_ref()
        .map(|p| p.interactive)
        .unwrap_or(false);

    // Build capabilities from profile or arguments
    let mut caps = if let Some(ref prof) = loaded_profile {
        CapabilitySet::from_profile(prof, &workdir, args)?
    } else {
        CapabilitySet::from_args(args)?
    };

    // Auto-include CWD based on profile [workdir] config or default behavior
    let cwd_access = if let Some(ref access) = profile_workdir_access {
        // Profile loaded: use its [workdir] config
        match access {
            WorkdirAccess::Read => Some(FsAccess::Read),
            WorkdirAccess::Write => Some(FsAccess::Write),
            WorkdirAccess::ReadWrite => Some(FsAccess::ReadWrite),
            WorkdirAccess::None => None,
        }
    } else {
        // No profile: default to read-only CWD access
        Some(FsAccess::Read)
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

        // Only auto-add if CWD is not already covered by existing capabilities
        if !caps.path_covered(&cwd_canonical) {
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

    // Check if any capabilities are specified (must have fs or network)
    // Network is allowed by default, so only error if no fs AND network is blocked
    if !caps.has_fs() && caps.net_block {
        return Err(NonoError::NoCapabilities);
    }

    // Build secret mappings from profile and/or CLI
    let profile_secrets = loaded_profile
        .map(|p| p.secrets.mappings)
        .unwrap_or_default();

    let secret_mappings =
        keystore::build_secret_mappings(args.secrets.as_deref(), &profile_secrets);

    // Load secrets from keystore BEFORE sandbox is applied
    // (sandbox will block access to keystore after this point)
    let loaded_secrets = if !secret_mappings.is_empty() {
        info!(
            "Loading {} secret(s) from system keystore",
            secret_mappings.len()
        );
        if !silent {
            eprintln!(
                "  Loading {} secret(s) from keystore...",
                secret_mappings.len()
            );
        }
        keystore::load_secrets(&secret_mappings)?
    } else {
        Vec::new()
    };

    // Print capability summary
    output::print_capabilities(&caps, silent);

    // Check platform support
    if !sandbox::is_supported() {
        return Err(NonoError::SandboxInit(sandbox::support_info()));
    }

    info!("{}", sandbox::support_info());

    Ok(PreparedSandbox {
        caps,
        secrets: loaded_secrets,
        interactive: profile_interactive,
    })
}

fn write_capability_state_file(caps: &CapabilitySet, silent: bool) -> Option<std::path::PathBuf> {
    // Write sandbox state for `nono why --self`.
    // This allows sandboxed processes to query their own capabilities.
    let cap_file = std::env::temp_dir().join(format!(".nono-{}.json", std::process::id()));
    let state = sandbox_state::SandboxState::from_caps(caps);
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

    #[test]
    fn test_sensitive_paths_defined() {
        // Verify expected sensitive paths are included in embedded config
        let paths = config::get_sensitive_paths();
        assert!(paths.iter().any(|p| p.contains("ssh")));
        assert!(paths.iter().any(|p| p.contains("aws")));
    }

    #[test]
    fn test_dangerous_commands_defined() {
        // Verify expected dangerous commands are included in embedded config
        let commands = config::get_dangerous_commands();
        assert!(commands.contains("rm"));
        assert!(commands.contains("dd"));
        assert!(commands.contains("chmod"));
    }

    #[test]
    fn test_check_blocked_command_basic() {
        // Blocked commands should be detected
        assert!(config::check_blocked_command("rm", &[], &[]).is_some());
        assert!(config::check_blocked_command("dd", &[], &[]).is_some());
        assert!(config::check_blocked_command("chmod", &[], &[]).is_some());

        // Safe commands should not be blocked
        assert!(config::check_blocked_command("echo", &[], &[]).is_none());
        assert!(config::check_blocked_command("ls", &[], &[]).is_none());
        assert!(config::check_blocked_command("cat", &[], &[]).is_none());
    }

    #[test]
    fn test_check_blocked_command_with_path() {
        // Full paths should still be detected
        assert!(config::check_blocked_command("/bin/rm", &[], &[]).is_some());
        assert!(config::check_blocked_command("/usr/bin/dd", &[], &[]).is_some());
        assert!(config::check_blocked_command("./rm", &[], &[]).is_some());
    }

    #[test]
    fn test_check_blocked_command_allow_override() {
        // Explicitly allowed commands should not be blocked
        let allowed = vec!["rm".to_string()];
        assert!(config::check_blocked_command("rm", &allowed, &[]).is_none());

        // Other commands still blocked
        assert!(config::check_blocked_command("dd", &allowed, &[]).is_some());
    }

    #[test]
    fn test_check_blocked_command_extra_blocked() {
        // Extra blocked commands should be detected
        let extra = vec!["custom-dangerous".to_string()];
        assert!(config::check_blocked_command("custom-dangerous", &[], &extra).is_some());

        // Default blocked still works
        assert!(config::check_blocked_command("rm", &[], &extra).is_some());
    }

    #[test]
    fn test_check_blocked_command_no_file_name() {
        // Edge case: path with no file name (e.g., just "/")
        // Should fall back to using the full path and not crash
        assert!(config::check_blocked_command("/", &[], &[]).is_none());
        assert!(config::check_blocked_command("", &[], &[]).is_none());
    }

    #[test]
    fn test_check_blocked_command_osstr_comparison() {
        // Verify OsStr comparison works correctly for various path formats
        assert!(config::check_blocked_command("rm", &[], &[]).is_some());
        assert!(config::check_blocked_command("./rm", &[], &[]).is_some());
        assert!(config::check_blocked_command("../rm", &[], &[]).is_some());
        assert!(config::check_blocked_command("/usr/local/bin/rm", &[], &[]).is_some());

        // Nested paths should still extract correct binary name
        assert!(
            config::check_blocked_command("/some/deeply/nested/path/to/rm", &[], &[]).is_some()
        );
    }

    #[test]
    fn test_check_sensitive_path() {
        // Verify sensitive path checking works
        assert!(config::check_sensitive_path("~/.ssh").is_some());
        assert!(config::check_sensitive_path("~/.aws").is_some());
        assert!(config::check_sensitive_path("~/.bashrc").is_some());

        // Non-sensitive paths should return None
        assert!(config::check_sensitive_path("/tmp").is_none());
        assert!(config::check_sensitive_path("~/Documents").is_none());
    }
}
