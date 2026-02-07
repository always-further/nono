use clap::{Parser, Subcommand, ValueEnum};
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

    /// Start an interactive shell inside the sandbox
    #[command(after_help = "EXAMPLES:
    # Start a shell with read/write access to current directory
    nono shell --allow .

    # Use a named profile
    nono shell --profile claude-code

    # Override shell binary
    nono shell --allow . --shell /bin/zsh
")]
    Shell(Box<ShellArgs>),

    /// Check why a path or network operation would be allowed or denied
    #[command(after_help = "EXAMPLES:
    # Check if ~/.ssh is readable (sensitive path check)
    nono why --path ~/.ssh --op read

    # Check with capability context
    nono why --path ./src --op write --allow .

    # JSON output for programmatic use (for agents)
    nono why --json --path ~/.aws --op read

    # Query network access
    nono why --host api.openai.com --port 443

    # Inside a sandbox, query own capabilities
    nono why --self --path /tmp --op write --json
")]
    Why(Box<WhyArgs>),

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

#[derive(Parser, Debug, Clone)]
pub struct SandboxArgs {
    // === Directory permissions (recursive) ===
    /// Directories to allow read+write access (recursive).
    /// Combines full read and write permissions (see --read and --write for details).
    #[arg(long, short = 'a', value_name = "DIR")]
    pub allow: Vec<PathBuf>,

    /// Directories to allow read-only access (recursive)
    #[arg(long, short = 'r', value_name = "DIR")]
    pub read: Vec<PathBuf>,

    /// Directories to allow write-only access (recursive).
    /// Write access includes: creating files/dirs, modifying content, deleting files,
    /// renaming/moving files (atomic writes), and truncating files.
    /// Note: Directory deletion is NOT included for safety.
    #[arg(long, short = 'w', value_name = "DIR")]
    pub write: Vec<PathBuf>,

    // === Single file permissions ===
    /// Single files to allow read+write access
    #[arg(long, value_name = "FILE")]
    pub allow_file: Vec<PathBuf>,

    /// Single files to allow read-only access
    #[arg(long, value_name = "FILE")]
    pub read_file: Vec<PathBuf>,

    /// Single files to allow write-only access.
    /// Write access includes: modifying content, deleting, renaming, and truncating.
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

    /// Allow access to current working directory without prompting.
    /// Access level determined by profile or defaults to read-only.
    #[arg(long)]
    pub allow_cwd: bool,

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
}

#[derive(Parser, Debug)]
pub struct RunArgs {
    #[command(flatten)]
    pub sandbox: SandboxArgs,

    /// Suppress diagnostic footer on command failure.
    /// By default, nono prints a helpful summary when commands exit non-zero.
    /// Use this flag for scripts that parse stderr.
    #[arg(long)]
    pub no_diagnostics: bool,

    /// Preserve TTY for interactive apps (e.g., Claude Code, vim, htop).
    /// Without this flag, nono monitors output which can break interactive UIs.
    #[arg(long = "exec")]
    pub direct_exec: bool,

    /// Command to run inside the sandbox
    #[arg(required = true)]
    pub command: Vec<String>,
}

#[derive(Parser, Debug)]
pub struct ShellArgs {
    #[command(flatten)]
    pub sandbox: SandboxArgs,

    /// Shell to execute (defaults to $SHELL or /bin/sh)
    #[arg(long, value_name = "SHELL")]
    pub shell: Option<PathBuf>,
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

#[derive(Parser, Debug)]
pub struct WhyArgs {
    /// Path to check
    #[arg(long)]
    pub path: Option<PathBuf>,

    /// Operation to check: read, write, or readwrite
    #[arg(long, value_enum)]
    pub op: Option<WhyOp>,

    /// Network host to check
    #[arg(long)]
    pub host: Option<String>,

    /// Network port (default 443)
    #[arg(long, default_value = "443")]
    pub port: u16,

    /// Output JSON instead of human-readable format
    #[arg(long)]
    pub json: bool,

    /// Query current sandbox state (use inside a sandboxed process)
    #[arg(long = "self")]
    pub self_query: bool,

    // === Capability context (same as RunArgs) ===
    /// Directories to allow read+write access (for query context)
    #[arg(long, short = 'a', value_name = "DIR")]
    pub allow: Vec<PathBuf>,

    /// Directories to allow read-only access (for query context)
    #[arg(long, short = 'r', value_name = "DIR")]
    pub read: Vec<PathBuf>,

    /// Directories to allow write-only access (for query context)
    #[arg(long, short = 'w', value_name = "DIR")]
    pub write: Vec<PathBuf>,

    /// Single files to allow read+write access (for query context)
    #[arg(long, value_name = "FILE")]
    pub allow_file: Vec<PathBuf>,

    /// Single files to allow read-only access (for query context)
    #[arg(long, value_name = "FILE")]
    pub read_file: Vec<PathBuf>,

    /// Single files to allow write-only access (for query context)
    #[arg(long, value_name = "FILE")]
    pub write_file: Vec<PathBuf>,

    /// Block network access (for query context)
    #[arg(long)]
    pub net_block: bool,

    /// Use a named profile for query context
    #[arg(long, short = 'p', value_name = "NAME")]
    pub profile: Option<String>,

    /// Working directory for $WORKDIR expansion in profiles
    #[arg(long, value_name = "DIR")]
    pub workdir: Option<PathBuf>,

    /// Trust unsigned user profiles
    #[arg(long)]
    pub trust_unsigned: bool,
}

/// Operation type for why command
#[derive(Clone, Debug, ValueEnum)]
pub enum WhyOp {
    /// Read-only access
    Read,
    /// Write-only access
    Write,
    /// Read and write access
    #[value(name = "readwrite")]
    ReadWrite,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_basic() {
        let cli = Cli::parse_from(["nono", "run", "--allow", ".", "echo", "hello"]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.allow.len(), 1);
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
                assert_eq!(args.sandbox.allow.len(), 1);
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
                assert_eq!(args.sandbox.allow.len(), 2);
                assert_eq!(args.sandbox.read.len(), 1);
            }
            _ => panic!("Expected Run command"),
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
                    args.sandbox.secrets,
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
                assert_eq!(args.sandbox.profile, Some("claude-code".to_string()));
                assert_eq!(args.sandbox.secrets, Some("openai_api_key".to_string()));
                assert_eq!(args.command, vec!["claude"]);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_why_path_parsing() {
        let cli = Cli::parse_from(["nono", "why", "--path", "./src", "--op", "read"]);
        match cli.command {
            Commands::Why(args) => {
                assert_eq!(args.path, Some(PathBuf::from("./src")));
                assert!(matches!(args.op, Some(WhyOp::Read)));
                assert!(!args.json);
                assert!(!args.self_query);
            }
            _ => panic!("Expected Why command"),
        }
    }

    #[test]
    fn test_why_self_mode() {
        let cli = Cli::parse_from([
            "nono", "why", "--self", "--path", "/tmp", "--op", "write", "--json",
        ]);
        match cli.command {
            Commands::Why(args) => {
                assert!(args.self_query);
                assert!(args.json);
                assert_eq!(args.path, Some(PathBuf::from("/tmp")));
                assert!(matches!(args.op, Some(WhyOp::Write)));
            }
            _ => panic!("Expected Why command"),
        }
    }

    #[test]
    fn test_why_network() {
        let cli = Cli::parse_from([
            "nono",
            "why",
            "--host",
            "api.openai.com",
            "--port",
            "443",
            "--net-block",
        ]);
        match cli.command {
            Commands::Why(args) => {
                assert_eq!(args.host, Some("api.openai.com".to_string()));
                assert_eq!(args.port, 443);
                assert!(args.net_block);
            }
            _ => panic!("Expected Why command"),
        }
    }

    #[test]
    fn test_why_with_capability_context() {
        let cli = Cli::parse_from([
            "nono", "why", "--path", "./src", "--op", "write", "--allow", ".", "--json",
        ]);
        match cli.command {
            Commands::Why(args) => {
                assert_eq!(args.allow.len(), 1);
                assert!(args.json);
            }
            _ => panic!("Expected Why command"),
        }
    }

    #[test]
    fn test_shell_basic() {
        let cli = Cli::parse_from(["nono", "shell", "--allow", "."]);
        match cli.command {
            Commands::Shell(args) => {
                assert_eq!(args.sandbox.allow.len(), 1);
                assert!(args.shell.is_none());
            }
            _ => panic!("Expected Shell command"),
        }
    }
}
