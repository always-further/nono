use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// nono - The opposite of YOLO
///
/// A capability-based shell for running untrusted AI agents and processes
/// with OS-enforced filesystem and network isolation.
#[derive(Parser, Debug)]
#[command(name = "nono")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Silent mode - suppress all nono output (banner, summary, status)
    #[arg(long, short = 's', global = true)]
    pub silent: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run a command inside the sandbox
    #[command(trailing_var_arg = true)]
    #[command(after_help = "EXAMPLES:
    # Allow read/write to current directory, run claude
    nono run --allow . claude

    # Use a named profile (built-in)
    nono run --profile claude-code claude

    # Profile with explicit working directory
    nono run --profile claude-code --workdir ./my-project claude

    # Profile + additional permissions
    nono run --profile openclaw --read /tmp/extra openclaw gateway

    # Read-only access to src, write to output
    nono run --read ./src --write ./output cargo build

    # Multiple allowed paths
    nono run --allow ./project-a --allow ./project-b claude

    # Block network access (network allowed by default)
    nono run --allow . --net-block cargo build

    # Allow specific files (not directories)
    nono run --allow . --write-file ~/.claude.json claude

    # Load secrets from system keystore (profile defines which secrets)
    nono run --profile claude-code --secrets claude

    # Load specific secrets from keystore (comma-separated)
    nono run --allow . --secrets openai_api_key,anthropic_api_key -- claude
")]
    Run(Box<RunArgs>),

    /// Check why a path would be blocked or allowed
    #[command(after_help = "EXAMPLES:
    # Check if ~/.ssh/id_rsa would be accessible
    nono why ~/.ssh/id_rsa

    # Check a project directory
    nono why ./my-project
")]
    Why(WhyArgs),

    /// Set up nono on this system
    #[command(after_help = "EXAMPLES:
    # Full setup with profile generation
    nono setup --profiles

    # Just verify installation and sandbox support
    nono setup --check-only

    # Setup with shell integration help
    nono setup --profiles --shell-integration

    # Verbose setup
    nono setup -v --profiles
")]
    Setup(SetupArgs),
}

#[derive(Parser, Debug)]
pub struct RunArgs {
    // === Directory permissions (recursive) ===
    /// Directories to allow read+write access (recursive)
    #[arg(long, short = 'a', value_name = "DIR")]
    pub allow: Vec<PathBuf>,

    /// Directories to allow read-only access (recursive)
    #[arg(long, short = 'r', value_name = "DIR")]
    pub read: Vec<PathBuf>,

    /// Directories to allow write-only access (recursive)
    #[arg(long, short = 'w', value_name = "DIR")]
    pub write: Vec<PathBuf>,

    // === Single file permissions ===
    /// Single files to allow read+write access
    #[arg(long, value_name = "FILE")]
    pub allow_file: Vec<PathBuf>,

    /// Single files to allow read-only access
    #[arg(long, value_name = "FILE")]
    pub read_file: Vec<PathBuf>,

    /// Single files to allow write-only access
    #[arg(long, value_name = "FILE")]
    pub write_file: Vec<PathBuf>,

    /// Block network access (network allowed by default; use this flag to block)
    /// Note: Per-host filtering not supported by OS sandbox; this is on/off only
    #[arg(long)]
    pub net_block: bool,

    // === Command blocking ===
    /// Allow a normally-blocked dangerous command (use with caution).
    /// By default, destructive commands like rm, dd, chmod are blocked.
    #[arg(long, value_name = "CMD")]
    pub allow_command: Vec<String>,

    /// Block an additional command beyond the default blocklist
    #[arg(long, value_name = "CMD")]
    pub block_command: Vec<String>,

    // === Secrets options ===
    /// Load secrets from system keystore and inject as environment variables.
    /// Use with --profile to load secrets defined in the profile's [secrets] section,
    /// or specify comma-separated account names to load from the 'nono' service.
    /// Secrets are loaded before sandbox is applied and zeroized from memory after exec.
    #[arg(long, value_name = "ACCOUNTS")]
    pub secrets: Option<String>,

    // === Profile options ===
    /// Use a named profile (built-in or from ~/.config/nono/profiles/)
    #[arg(long, short = 'p', value_name = "NAME")]
    pub profile: Option<String>,

    /// Working directory for $WORKDIR expansion in profiles (defaults to current dir)
    #[arg(long, value_name = "DIR")]
    pub workdir: Option<PathBuf>,

    /// Trust unsigned user profiles (required for profiles without signatures)
    #[arg(long)]
    pub trust_unsigned: bool,

    /// Configuration file path
    #[arg(long, short = 'c', value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Enable verbose output
    #[arg(long, short = 'v', action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Dry run - show what would be sandboxed without executing
    #[arg(long)]
    pub dry_run: bool,

    /// Command to run inside the sandbox
    #[arg(required = true)]
    pub command: Vec<String>,
}

#[derive(Parser, Debug)]
pub struct WhyArgs {
    /// Path to check
    pub path: PathBuf,

    /// Also show what flags would grant access
    #[arg(long)]
    pub suggest: bool,
}

#[derive(Parser, Debug)]
pub struct SetupArgs {
    /// Only verify installation and sandbox support, don't create files
    #[arg(long)]
    pub check_only: bool,

    /// Generate example user profiles in ~/.config/nono/profiles/
    #[arg(long)]
    pub profiles: bool,

    /// Show shell integration instructions
    #[arg(long)]
    pub shell_integration: bool,

    /// Show detailed information during setup
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_basic() {
        let cli = Cli::parse_from(["nono", "run", "--allow", ".", "echo", "hello"]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.allow.len(), 1);
                assert_eq!(args.command, vec!["echo", "hello"]);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_run_with_separator() {
        let cli = Cli::parse_from(["nono", "run", "--allow", ".", "--", "echo", "hello"]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.allow.len(), 1);
                assert_eq!(args.command, vec!["echo", "hello"]);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_run_multiple_paths() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow",
            "./src",
            "--allow",
            "./docs",
            "--read",
            "/usr/share",
            "ls",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.allow.len(), 2);
                assert_eq!(args.read.len(), 1);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_why_basic() {
        let cli = Cli::parse_from(["nono", "why", "~/.ssh/id_rsa"]);
        match cli.command {
            Commands::Why(args) => {
                assert_eq!(args.path, PathBuf::from("~/.ssh/id_rsa"));
            }
            _ => panic!("Expected Why command"),
        }
    }

    #[test]
    fn test_why_with_suggest() {
        let cli = Cli::parse_from(["nono", "why", "--suggest", "/tmp/foo"]);
        match cli.command {
            Commands::Why(args) => {
                assert!(args.suggest);
                assert_eq!(args.path, PathBuf::from("/tmp/foo"));
            }
            _ => panic!("Expected Why command"),
        }
    }

    #[test]
    fn test_run_with_secrets() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--secrets",
            "openai_api_key,anthropic_api_key",
            "claude",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(
                    args.secrets,
                    Some("openai_api_key,anthropic_api_key".to_string())
                );
                assert_eq!(args.command, vec!["claude"]);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_run_with_profile_and_secrets() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--profile",
            "claude-code",
            "--secrets",
            "openai_api_key",
            "claude",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.profile, Some("claude-code".to_string()));
                assert_eq!(args.secrets, Some("openai_api_key".to_string()));
                assert_eq!(args.command, vec!["claude"]);
            }
            _ => panic!("Expected Run command"),
        }
    }
}
