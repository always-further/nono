//! CLI argument definitions for nono
//!
//! Uses clap for argument parsing. This module defines all subcommands
//! and their options.

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
    /// Trace a command to discover required filesystem paths (Linux only)
    #[command(trailing_var_arg = true)]
    #[command(after_help = "EXAMPLES:
    # Discover paths needed by a command
    nono learn -- my-app

    # With an existing profile to see what's missing
    nono learn --profile my-profile -- my-app

    # Output as JSON for profile
    nono learn --json -- node server.js

    # Limit trace duration
    nono learn --timeout 30 -- my-app
")]
    Learn(Box<LearnArgs>),

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

    /// Manage rollback sessions (browse, restore, cleanup)
    #[command(after_help = "EXAMPLES:
    # List sessions with file changes
    nono rollback list

    # Show changes in a session (with diff)
    nono rollback show 20260214-143022-12345 --diff

    # Restore files from a session
    nono rollback restore 20260214-143022-12345

    # Dry-run restore to see what would change
    nono rollback restore 20260214-143022-12345 --dry-run

    # Verify session integrity
    nono rollback verify 20260214-143022-12345

    # Clean up old sessions (dry-run first)
    nono rollback cleanup --dry-run
")]
    Rollback(RollbackArgs),

    /// View audit trail of sandboxed commands
    #[command(after_help = "EXAMPLES:
    # List all sessions (including read-only commands)
    nono audit list

    # List sessions from today
    nono audit list --today

    # Filter by command
    nono audit list --command claude

    # Filter by path
    nono audit list --path ~/projects

    # Show audit details for a session
    nono audit show 20260214-143022-12345

    # Export as JSON
    nono audit show 20260214-143022-12345 --json
")]
    Audit(AuditArgs),
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
    /// Use a profile by name or file path.
    /// Names resolve from ~/.config/nono/profiles/ then built-ins.
    /// Paths (containing '/' or ending in .json) load directly.
    #[arg(long, short = 'p', value_name = "NAME_OR_PATH")]
    pub profile: Option<String>,

    /// Allow access to current working directory without prompting.
    /// Access level determined by profile or defaults to read-only.
    #[arg(long)]
    pub allow_cwd: bool,

    /// Working directory for $WORKDIR expansion in profiles (defaults to current dir)
    #[arg(long, value_name = "DIR")]
    pub workdir: Option<PathBuf>,

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

    /// Enable atomic rollback snapshots for the session.
    /// Takes content-addressable snapshots of writable directories so you
    /// can restore to the pre-session state after the command exits.
    #[arg(long)]
    pub rollback: bool,

    /// Use supervised execution mode for capability expansion approval.
    /// Fork first, sandbox only the child. The parent stays unsandboxed
    /// to handle approval prompts for additional path access requests.
    #[arg(long)]
    pub supervised: bool,

    /// Skip the post-exit rollback review prompt.
    /// Snapshots are still taken for audit purposes, but the interactive
    /// restore UI is suppressed.
    #[arg(long)]
    pub no_rollback_prompt: bool,

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
}

#[derive(Parser, Debug)]
pub struct LearnArgs {
    /// Use a named profile to compare against (shows only missing paths)
    #[arg(long, short = 'p', value_name = "NAME")]
    pub profile: Option<String>,

    /// Output discovered paths as JSON fragment for profile
    #[arg(long)]
    pub json: bool,

    /// Timeout in seconds (default: run until command exits)
    #[arg(long, value_name = "SECS")]
    pub timeout: Option<u64>,

    /// Show all accessed paths, not just those that would be blocked
    #[arg(long)]
    pub all: bool,

    /// Enable verbose output
    #[arg(long, short = 'v', action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Command to trace
    #[arg(required = true)]
    pub command: Vec<String>,
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

#[derive(Parser, Debug)]
pub struct RollbackArgs {
    #[command(subcommand)]
    pub command: RollbackCommands,
}

#[derive(Subcommand, Debug)]
pub enum RollbackCommands {
    /// List sessions with file changes
    List(RollbackListArgs),
    /// Show changes in a session
    Show(RollbackShowArgs),
    /// Restore files from a past session
    Restore(RollbackRestoreArgs),
    /// Verify session integrity
    Verify(RollbackVerifyArgs),
    /// Clean up old sessions
    Cleanup(RollbackCleanupArgs),
}

#[derive(Parser, Debug)]
pub struct RollbackListArgs {
    /// Show only the N most recent sessions
    #[arg(long, value_name = "N")]
    pub recent: Option<usize>,

    /// Filter sessions by tracked path (matches if session tracked this path or a parent/child)
    #[arg(long, value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Show all sessions (including those with no file changes)
    #[arg(long)]
    pub all: bool,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser, Debug)]
pub struct RollbackShowArgs {
    /// Session ID (e.g., 20260214-143022-12345)
    pub session_id: String,

    /// Show unified diff (git diff style)
    #[arg(long)]
    pub diff: bool,

    /// Show side-by-side diff
    #[arg(long)]
    pub side_by_side: bool,

    /// Show full file content from snapshot
    #[arg(long)]
    pub full: bool,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser, Debug)]
pub struct RollbackRestoreArgs {
    /// Session ID (e.g., 20260214-143022-12345)
    pub session_id: String,

    /// Snapshot number to restore to (default: last snapshot)
    #[arg(long)]
    pub snapshot: Option<u32>,

    /// Show what would change without modifying files
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Parser, Debug)]
pub struct RollbackVerifyArgs {
    /// Session ID (e.g., 20260214-143022-12345)
    pub session_id: String,
}

#[derive(Parser, Debug)]
pub struct RollbackCleanupArgs {
    /// Retain N newest sessions (default: from config, usually 10)
    #[arg(long, value_name = "N")]
    pub keep: Option<usize>,

    /// Remove sessions older than N days
    #[arg(long, value_name = "DAYS")]
    pub older_than: Option<u64>,

    /// Show what would be removed without deleting
    #[arg(long)]
    pub dry_run: bool,

    /// Remove all sessions (requires confirmation)
    #[arg(long)]
    pub all: bool,
}

// ---------------------------------------------------------------------------
// Audit command args
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub command: AuditCommands,
}

#[derive(Subcommand, Debug)]
pub enum AuditCommands {
    /// List all sandboxed sessions
    List(AuditListArgs),
    /// Show audit details for a session
    Show(AuditShowArgs),
}

#[derive(Parser, Debug)]
pub struct AuditListArgs {
    /// Show only sessions from today
    #[arg(long)]
    pub today: bool,

    /// Show sessions since date (YYYY-MM-DD)
    #[arg(long, value_name = "DATE")]
    pub since: Option<String>,

    /// Show sessions until date (YYYY-MM-DD)
    #[arg(long, value_name = "DATE")]
    pub until: Option<String>,

    /// Filter by command name (e.g., claude, cat)
    #[arg(long, value_name = "CMD")]
    pub command: Option<String>,

    /// Filter by tracked path
    #[arg(long, value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Show only the N most recent sessions
    #[arg(long, value_name = "N")]
    pub recent: Option<usize>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser, Debug)]
pub struct AuditShowArgs {
    /// Session ID (e.g., 20260214-143022-12345)
    pub session_id: String,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
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
    fn test_run_with_supervised_flag() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--supervised",
            "--",
            "echo",
            "hello",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert!(args.supervised);
                assert_eq!(args.command, vec!["echo", "hello"]);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_run_without_supervised_flag() {
        let cli = Cli::parse_from(["nono", "run", "--allow", ".", "echo", "hello"]);
        match cli.command {
            Commands::Run(args) => {
                assert!(!args.supervised);
            }
            _ => panic!("Expected Run command"),
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

    #[test]
    fn test_rollback_list() {
        let cli = Cli::parse_from(["nono", "rollback", "list"]);
        match cli.command {
            Commands::Rollback(args) => match args.command {
                RollbackCommands::List(list_args) => {
                    assert!(list_args.recent.is_none());
                    assert!(list_args.path.is_none());
                    assert!(!list_args.json);
                }
                _ => panic!("Expected List subcommand"),
            },
            _ => panic!("Expected Rollback command"),
        }
    }

    #[test]
    fn test_rollback_list_recent_json() {
        let cli = Cli::parse_from(["nono", "rollback", "list", "--recent", "5", "--json"]);
        match cli.command {
            Commands::Rollback(args) => match args.command {
                RollbackCommands::List(list_args) => {
                    assert_eq!(list_args.recent, Some(5));
                    assert!(list_args.json);
                }
                _ => panic!("Expected List subcommand"),
            },
            _ => panic!("Expected Rollback command"),
        }
    }

    #[test]
    fn test_rollback_show() {
        let cli = Cli::parse_from(["nono", "rollback", "show", "20260214-143022-12345"]);
        match cli.command {
            Commands::Rollback(args) => match args.command {
                RollbackCommands::Show(show_args) => {
                    assert_eq!(show_args.session_id, "20260214-143022-12345");
                    assert!(!show_args.json);
                }
                _ => panic!("Expected Show subcommand"),
            },
            _ => panic!("Expected Rollback command"),
        }
    }

    #[test]
    fn test_rollback_restore_defaults() {
        let cli = Cli::parse_from(["nono", "rollback", "restore", "20260214-143022-12345"]);
        match cli.command {
            Commands::Rollback(args) => match args.command {
                RollbackCommands::Restore(restore_args) => {
                    assert_eq!(restore_args.session_id, "20260214-143022-12345");
                    assert_eq!(restore_args.snapshot, None); // Default to last snapshot
                    assert!(!restore_args.dry_run);
                }
                _ => panic!("Expected Restore subcommand"),
            },
            _ => panic!("Expected Rollback command"),
        }
    }

    #[test]
    fn test_rollback_restore_with_options() {
        let cli = Cli::parse_from([
            "nono",
            "rollback",
            "restore",
            "20260214-143022-12345",
            "--snapshot",
            "3",
            "--dry-run",
        ]);
        match cli.command {
            Commands::Rollback(args) => match args.command {
                RollbackCommands::Restore(restore_args) => {
                    assert_eq!(restore_args.snapshot, Some(3));
                    assert!(restore_args.dry_run);
                }
                _ => panic!("Expected Restore subcommand"),
            },
            _ => panic!("Expected Rollback command"),
        }
    }

    #[test]
    fn test_audit_list() {
        let cli = Cli::parse_from(["nono", "audit", "list", "--today"]);
        match cli.command {
            Commands::Audit(args) => match args.command {
                AuditCommands::List(list_args) => {
                    assert!(list_args.today);
                    assert!(!list_args.json);
                }
                _ => panic!("Expected List subcommand"),
            },
            _ => panic!("Expected Audit command"),
        }
    }

    #[test]
    fn test_audit_show() {
        let cli = Cli::parse_from(["nono", "audit", "show", "20260214-143022-12345", "--json"]);
        match cli.command {
            Commands::Audit(args) => match args.command {
                AuditCommands::Show(show_args) => {
                    assert_eq!(show_args.session_id, "20260214-143022-12345");
                    assert!(show_args.json);
                }
                _ => panic!("Expected Show subcommand"),
            },
            _ => panic!("Expected Audit command"),
        }
    }

    #[test]
    fn test_rollback_verify() {
        let cli = Cli::parse_from(["nono", "rollback", "verify", "20260214-143022-12345"]);
        match cli.command {
            Commands::Rollback(args) => match args.command {
                RollbackCommands::Verify(verify_args) => {
                    assert_eq!(verify_args.session_id, "20260214-143022-12345");
                }
                _ => panic!("Expected Verify subcommand"),
            },
            _ => panic!("Expected Rollback command"),
        }
    }

    #[test]
    fn test_rollback_cleanup_defaults() {
        let cli = Cli::parse_from(["nono", "rollback", "cleanup"]);
        match cli.command {
            Commands::Rollback(args) => match args.command {
                RollbackCommands::Cleanup(cleanup_args) => {
                    assert!(cleanup_args.keep.is_none());
                    assert!(cleanup_args.older_than.is_none());
                    assert!(!cleanup_args.dry_run);
                    assert!(!cleanup_args.all);
                }
                _ => panic!("Expected Cleanup subcommand"),
            },
            _ => panic!("Expected Rollback command"),
        }
    }

    #[test]
    fn test_rollback_cleanup_with_options() {
        let cli = Cli::parse_from([
            "nono",
            "rollback",
            "cleanup",
            "--keep",
            "5",
            "--older-than",
            "30",
            "--dry-run",
        ]);
        match cli.command {
            Commands::Rollback(args) => match args.command {
                RollbackCommands::Cleanup(cleanup_args) => {
                    assert_eq!(cleanup_args.keep, Some(5));
                    assert_eq!(cleanup_args.older_than, Some(30));
                    assert!(cleanup_args.dry_run);
                    assert!(!cleanup_args.all);
                }
                _ => panic!("Expected Cleanup subcommand"),
            },
            _ => panic!("Expected Rollback command"),
        }
    }
}
