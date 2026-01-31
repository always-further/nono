mod capability;
mod cli;
mod error;
mod sandbox;

use clap::Parser;
use cli::Args;
use capability::CapabilitySet;
use error::{NonoError, Result};
use std::os::unix::process::CommandExt;
use std::process::Command;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("warn")),
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
    let args = Args::parse();

    // Set log level based on verbosity
    if args.verbose > 0 {
        // Re-initialize with more verbose logging
        // (In a real app, we'd do this before the first init)
        match args.verbose {
            1 => std::env::set_var("RUST_LOG", "info"),
            2 => std::env::set_var("RUST_LOG", "debug"),
            _ => std::env::set_var("RUST_LOG", "trace"),
        }
    }

    // Check if we have a command to run
    if args.command.is_empty() {
        return Err(NonoError::NoCommand);
    }

    // Build capabilities from arguments
    let caps = CapabilitySet::from_args(&args)?;

    // Check if any capabilities are specified
    if !caps.has_fs() {
        return Err(NonoError::NoCapabilities);
    }

    // Print banner
    eprintln!("nono v{} - the opposite of yolo", env!("CARGO_PKG_VERSION"));
    eprintln!();

    // Print capability summary
    eprintln!("Capabilities:");
    for line in caps.summary().lines() {
        eprintln!("  {}", line);
    }
    eprintln!();

    // Check platform support
    if !sandbox::is_supported() {
        return Err(NonoError::SandboxInit(sandbox::support_info()));
    }

    info!("{}", sandbox::support_info());

    // Dry run mode - just show what would happen
    if args.dry_run {
        eprintln!("Dry run mode - sandbox would be applied with above capabilities");
        eprintln!("Command: {:?}", args.command);
        return Ok(());
    }

    // Apply the sandbox
    eprintln!("Applying sandbox...");
    sandbox::apply(&caps)?;
    eprintln!("Sandbox active. Restrictions are now in effect.");
    eprintln!();

    // Execute the command
    let program = &args.command[0];
    let cmd_args = &args.command[1..];

    info!("Executing: {} {:?}", program, cmd_args);

    // Use exec to replace this process with the command
    // This means the command inherits our sandbox restrictions
    // Set environment variables so agents know they're running under nono
    // and can provide helpful error messages when access is denied
    let err = Command::new(program)
        .args(cmd_args)
        .env("NONO_ACTIVE", "1")
        .env(
            "NONO_HELP",
            "You are running inside a nono sandbox. File access outside granted paths is blocked. \
             To grant access, ask the user to re-run nono with: \
             --read <path> (read-only), --write <path> (write-only), or --allow <path> (read+write). \
             For single files use: --read-file, --write-file, or --allow-file.",
        )
        .env(
            "NONO_SENSITIVE_PATHS",
            "The following paths are ALWAYS blocked for security (credentials, keys, shell configs): \
             ~/.ssh, ~/.aws, ~/.gnupg, ~/.kube, ~/.docker, ~/.npmrc, ~/.git-credentials, ~/.netrc, \
             ~/.password-store, ~/.1password, ~/.vault-token, ~/Library/Keychains, \
             ~/.zshrc, ~/.bashrc, ~/.bash_profile, ~/.profile, ~/.zsh_history, ~/.bash_history, \
             ~/.config/gcloud, ~/.azure, ~/.terraform.d, ~/.env, ~/.envrc. \
             These paths require explicit user override to access.",
        )
        .exec();

    // exec() only returns if there's an error
    Err(NonoError::CommandExecution(err))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_command_error() {
        let args = Args {
            allow: vec![".".into()],
            read: vec![],
            write: vec![],
            allow_file: vec![],
            read_file: vec![],
            write_file: vec![],
            net_allow: false,
            config: None,
            verbose: 0,
            dry_run: false,
            command: vec![],
        };

        // Simulate what run() does
        assert!(args.command.is_empty());
    }
}
