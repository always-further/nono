mod capability;
mod cli;
mod error;
mod keystore;
mod output;
mod profile;
mod sandbox;
mod setup;

use capability::CapabilitySet;
use clap::Parser;
use cli::{Cli, Commands, RunArgs, SetupArgs, WhyArgs};
use error::{NonoError, Result};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

/// Commands that are blocked by default due to destructive potential
const DANGEROUS_COMMANDS: &[&str] = &[
    // File destruction
    "rm",
    "rmdir",
    "shred",
    "srm", // secure rm
    // Disk/filesystem destruction
    "dd",
    "mkfs",
    "mkfs.ext4",
    "mkfs.xfs",
    "mkfs.btrfs",
    "mkswap",
    "fdisk",
    "parted",
    "gdisk",
    "wipefs",
    // Permission/ownership chaos
    "chmod",
    "chown",
    "chgrp",
    "chattr",
    // System modification
    "init",
    "shutdown",
    "reboot",
    "halt",
    "poweroff",
    "systemctl",
    // Package management (can break system)
    "apt",
    "apt-get",
    "dpkg",
    "yum",
    "dnf",
    "pacman",
    "brew",
    "pip", // can overwrite system packages
    // Dangerous file operations
    "mv",       // can overwrite files
    "cp",       // with -f can overwrite
    "truncate", // can zero out files
    // Network exfiltration tools
    "scp",
    "rsync",
    "sftp",
    "ftp",
    // Arbitrary code execution helpers
    "xargs", // can execute arbitrary commands
    // Credential access
    "sudo",
    "su",
    "doas",
    "pkexec",
];

/// List of sensitive paths that are always blocked
const SENSITIVE_PATHS: &[&str] = &[
    "~/.ssh",
    "~/.aws",
    "~/.gnupg",
    "~/.kube",
    "~/.docker",
    "~/.npmrc",
    "~/.git-credentials",
    "~/.netrc",
    "~/.zshrc",
    "~/.zprofile",
    "~/.zshenv",
    "~/.bashrc",
    "~/.bash_profile",
    "~/.profile",
    "~/.bash_history",
    "~/.zsh_history",
    "~/Library/Keychains",
    "~/.credentials",
    "~/.secrets",
    "~/.azure",
    "~/.gcloud",
    "~/.config/gcloud",
    "~/.password-store",
    "~/.1password",
    "~/.keys",
    "~/.pki",
    "~/.terraform.d",
    "~/.vault-token",
];

/// Check if a command is in the dangerous commands list
/// Returns the matched command name if blocked, None if allowed
///
/// Uses OsStr for all comparisons to prevent bypass via non-UTF8 paths.
/// If a path contains non-UTF8 characters, we still correctly extract
/// and compare the binary name.
fn is_blocked_command(
    cmd: &str,
    allowed_commands: &[String],
    extra_blocked: &[String],
) -> Option<String> {
    use std::ffi::OsStr;

    // Extract just the binary name (handle paths like /bin/rm)
    // Use OsStr to handle non-UTF8 paths safely
    let binary_os = Path::new(cmd)
        .file_name()
        .unwrap_or_else(|| OsStr::new(cmd));

    // Check if explicitly allowed (overrides default blocklist)
    if allowed_commands.iter().any(|a| OsStr::new(a) == binary_os) {
        return None;
    }

    // Check extra blocked commands first
    if extra_blocked.iter().any(|b| OsStr::new(b) == binary_os) {
        return Some(binary_os.to_string_lossy().into_owned());
    }

    // Check default dangerous commands list
    DANGEROUS_COMMANDS
        .iter()
        .find(|&&blocked| OsStr::new(blocked) == binary_os)
        .map(|&s| s.to_string())
}

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
            run_sandbox(*args, cli.silent)
        }
        Commands::Why(args) => {
            // Print banner for why command (unless silent)
            output::print_banner(cli.silent);
            run_why(args)
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

/// Check why a path would be blocked or allowed
fn run_why(args: WhyArgs) -> Result<()> {
    let path = &args.path;
    let path_str = path.display().to_string();

    // Expand ~ in the input path for comparison
    let home = std::env::var("HOME").unwrap_or_default();
    let expanded_path = if path_str.starts_with("~/") {
        path_str.replacen("~", &home, 1)
    } else if path_str == "~" {
        home.clone()
    } else {
        path_str.clone()
    };

    // Check if path is in sensitive paths list
    for sensitive in SENSITIVE_PATHS {
        let expanded_sensitive = sensitive.replace('~', &home);

        // Check if the path matches or is under a sensitive path
        if expanded_path == expanded_sensitive
            || expanded_path.starts_with(&format!("{}/", expanded_sensitive))
        {
            println!("BLOCKED: {} is a sensitive path", path.display());
            println!();
            println!("Reason: This path is in the always-blocked list because it may contain:");
            println!("  - Credentials (API keys, tokens, passwords)");
            println!("  - Private keys (SSH, GPG, TLS)");
            println!("  - Shell configuration (which often embeds secrets)");
            println!();
            if args.suggest {
                let flag = if path.is_file() || !Path::new(&expanded_path).exists() {
                    "--read-file"
                } else {
                    "--read"
                };
                println!(
                    "To allow access, re-run nono with: {} {}",
                    flag,
                    path.display()
                );
                println!("WARNING: Granting access to sensitive paths can expose secrets to untrusted code.");
            }
            return Ok(());
        }
    }

    // Check if path exists
    let canonical = if Path::new(&expanded_path).exists() {
        Path::new(&expanded_path)
            .canonicalize()
            .ok()
            .map(|p| p.display().to_string())
    } else {
        None
    };

    // Not in sensitive list - would depend on explicit grants
    println!("NOT BLOCKED (by default): {}", path.display());
    if let Some(ref canon) = canonical {
        println!("Resolved path: {}", canon);
    }
    println!();
    println!("This path is not in the sensitive paths list.");
    println!("Access depends on what --allow/--read/--write flags are passed to 'nono run'.");
    println!();

    if args.suggest {
        println!("To grant access:");
        if Path::new(&expanded_path).is_file() {
            println!(
                "  Read-only:   nono run --read-file {} -- <command>",
                path.display()
            );
            println!(
                "  Write-only:  nono run --write-file {} -- <command>",
                path.display()
            );
            println!(
                "  Read+Write:  nono run --allow-file {} -- <command>",
                path.display()
            );
        } else if Path::new(&expanded_path).is_dir() {
            println!(
                "  Read-only:   nono run --read {} -- <command>",
                path.display()
            );
            println!(
                "  Write-only:  nono run --write {} -- <command>",
                path.display()
            );
            println!(
                "  Read+Write:  nono run --allow {} -- <command>",
                path.display()
            );
        } else {
            println!("  (path does not exist - use file or directory flags as appropriate)");
            println!("  For directories: --read, --write, --allow");
            println!("  For files:       --read-file, --write-file, --allow-file");
        }
    }

    Ok(())
}

/// Run a command inside the sandbox
fn run_sandbox(args: RunArgs, silent: bool) -> Result<()> {
    // Set log level based on verbosity
    if args.verbose > 0 {
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

    // Load profile once if specified (used for both capabilities and secrets)
    let loaded_profile = if let Some(ref profile_name) = args.profile {
        Some(profile::load_profile(profile_name, args.trust_unsigned)?)
    } else {
        None
    };

    // Build capabilities from profile or arguments
    let caps = if let Some(ref prof) = loaded_profile {
        let workdir = args
            .workdir
            .clone()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        CapabilitySet::from_profile(prof, &workdir, &args)?
    } else {
        CapabilitySet::from_args(&args)?
    };

    // Check if any capabilities are specified (must have fs or network)
    // Network is allowed by default, so only error if no fs AND network is blocked
    if !caps.has_fs() && caps.net_block {
        return Err(NonoError::NoCapabilities);
    }

    // Check if command is blocked
    let program = &args.command[0];
    if let Some(blocked) =
        is_blocked_command(program, &caps.allowed_commands, &caps.blocked_commands)
    {
        return Err(NonoError::BlockedCommand {
            command: blocked,
            reason: "This command is blocked by default due to destructive potential. \
                     Use --allow-command to override if you understand the risks."
                .to_string(),
        });
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

    // Dry run mode - just show what would happen
    if args.dry_run {
        if !loaded_secrets.is_empty() && !silent {
            eprintln!(
                "  Would inject {} secret(s) as environment variables",
                loaded_secrets.len()
            );
        }
        output::print_dry_run(&args.command, silent);
        return Ok(());
    }

    // Apply the sandbox
    output::print_applying_sandbox(silent);
    sandbox::apply(&caps)?;
    output::print_sandbox_active(silent);

    // Execute the command
    let program = &args.command[0];
    let cmd_args = &args.command[1..];

    info!("Executing: {} {:?}", program, cmd_args);

    // Build environment variables for agent awareness
    let allowed_paths = if caps.fs.is_empty() {
        "(none)".to_string()
    } else {
        caps.fs
            .iter()
            .map(|c| format!("{}[{}]", c.resolved.display(), c.access))
            .collect::<Vec<_>>()
            .join(":")
    };

    let blocked_paths = SENSITIVE_PATHS.join(":");

    let nono_context = format!(
        "You are running inside the nono sandbox (v{}). \
If you see 'Operation not permitted', 'Permission denied', or EPERM errors on file operations, \
this is nono blocking access, NOT macOS TCC or filesystem permissions. \
Blocked sensitive paths: ~/.ssh, ~/.aws, ~/.gnupg, ~/.kube, ~/.docker, shell configs. \
Allowed paths: {}. Network: {}. \
To check why a specific path is blocked, run: nono why <path>. \
To request access, ask the user to re-run nono with --read/--write/--allow flags.",
        env!("CARGO_PKG_VERSION"),
        if caps.fs.is_empty() {
            "(none)".to_string()
        } else {
            caps.fs
                .iter()
                .map(|c| c.resolved.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        },
        if caps.net_block { "blocked" } else { "allowed" }
    );

    let mut cmd = Command::new(program);
    cmd.args(cmd_args)
        .env("NONO_ACTIVE", "1")
        .env("NONO_ALLOWED", &allowed_paths)
        .env(
            "NONO_NET",
            if caps.net_block { "blocked" } else { "allowed" },
        )
        .env("NONO_BLOCKED", &blocked_paths)
        .env(
            "NONO_HELP",
            "To request access, ask user to re-run nono with: --read <path>, --write <path>, --allow <path> for directories; --read-file, --write-file, --allow-file for single files",
        )
        .env("NONO_CONTEXT", &nono_context);

    // Inject secrets as environment variables
    // These were loaded from the keystore before sandbox was applied
    for secret in &loaded_secrets {
        info!("Injecting secret as ${}", secret.env_var);
        cmd.env(&secret.env_var, secret.value.as_str());
    }

    let err = cmd.exec();

    // exec() only returns if there's an error
    // Note: loaded_secrets will be dropped here, zeroizing the secret values
    Err(NonoError::CommandExecution(err))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sensitive_paths_defined() {
        assert!(!SENSITIVE_PATHS.is_empty());
        assert!(SENSITIVE_PATHS.contains(&"~/.ssh"));
        assert!(SENSITIVE_PATHS.contains(&"~/.aws"));
    }

    #[test]
    fn test_dangerous_commands_defined() {
        assert!(!DANGEROUS_COMMANDS.is_empty());
        assert!(DANGEROUS_COMMANDS.contains(&"rm"));
        assert!(DANGEROUS_COMMANDS.contains(&"dd"));
        assert!(DANGEROUS_COMMANDS.contains(&"chmod"));
    }

    #[test]
    fn test_is_blocked_command_basic() {
        // Blocked commands should be detected
        assert!(is_blocked_command("rm", &[], &[]).is_some());
        assert!(is_blocked_command("dd", &[], &[]).is_some());
        assert!(is_blocked_command("chmod", &[], &[]).is_some());

        // Safe commands should not be blocked
        assert!(is_blocked_command("echo", &[], &[]).is_none());
        assert!(is_blocked_command("ls", &[], &[]).is_none());
        assert!(is_blocked_command("cat", &[], &[]).is_none());
    }

    #[test]
    fn test_is_blocked_command_with_path() {
        // Full paths should still be detected
        assert!(is_blocked_command("/bin/rm", &[], &[]).is_some());
        assert!(is_blocked_command("/usr/bin/dd", &[], &[]).is_some());
        assert!(is_blocked_command("./rm", &[], &[]).is_some());
    }

    #[test]
    fn test_is_blocked_command_allow_override() {
        // Explicitly allowed commands should not be blocked
        let allowed = vec!["rm".to_string()];
        assert!(is_blocked_command("rm", &allowed, &[]).is_none());

        // Other commands still blocked
        assert!(is_blocked_command("dd", &allowed, &[]).is_some());
    }

    #[test]
    fn test_is_blocked_command_extra_blocked() {
        // Extra blocked commands should be detected
        let extra = vec!["custom-dangerous".to_string()];
        assert!(is_blocked_command("custom-dangerous", &[], &extra).is_some());

        // Default blocked still works
        assert!(is_blocked_command("rm", &[], &extra).is_some());
    }

    #[test]
    fn test_is_blocked_command_no_file_name() {
        // Edge case: path with no file name (e.g., just "/")
        // Should fall back to using the full path and not crash
        assert!(is_blocked_command("/", &[], &[]).is_none());
        assert!(is_blocked_command("", &[], &[]).is_none());
    }

    #[test]
    fn test_is_blocked_command_osstr_comparison() {
        // Verify OsStr comparison works correctly for various path formats
        assert!(is_blocked_command("rm", &[], &[]).is_some());
        assert!(is_blocked_command("./rm", &[], &[]).is_some());
        assert!(is_blocked_command("../rm", &[], &[]).is_some());
        assert!(is_blocked_command("/usr/local/bin/rm", &[], &[]).is_some());

        // Nested paths should still extract correct binary name
        assert!(is_blocked_command("/some/deeply/nested/path/to/rm", &[], &[]).is_some());
    }
}
