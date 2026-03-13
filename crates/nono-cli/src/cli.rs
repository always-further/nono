//! CLI argument definitions for nono
//!
//! Uses clap for argument parsing. This module defines all subcommands
//! and their options.

use clap::builder::styling::{Style, Styles};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

const STYLES: Styles = Styles::plain().header(Style::new().bold());

/// nono - The opposite of YOLO
///
/// A capability-based shell for running untrusted AI agents and processes
/// with OS-enforced filesystem and network isolation.
#[derive(Parser, Debug)]
#[command(name = "nono")]
#[command(author, version, about, long_about = None)]
#[command(styles = STYLES, next_help_heading = "OPTIONS")]
#[command(subcommand_help_heading = "")]
#[command(help_template = "\
{about-with-newline}
\x1b[1mUSAGE\x1b[0m
  nono <command> [flags]

\x1b[1mGETTING STARTED\x1b[0m
  setup      Set up nono on this system

\x1b[1mCORE USAGE\x1b[0m
  run        Run a command inside the sandbox
  shell      Start an interactive shell inside the sandbox
  wrap       Apply sandbox and exec into command (nono disappears)

\x1b[1mEXPLORATION & DEBUGGING\x1b[0m
  learn      Trace a command to discover required filesystem paths
  why        Check why a path or network operation would be allowed or denied

\x1b[1mSESSION MANAGEMENT\x1b[0m
  rollback   Manage rollback sessions (browse, restore, cleanup)
  audit      View audit trail of sandboxed commands
  trust      Manage instruction file trust and attestation

\x1b[1mPOLICY & PROFILES\x1b[0m
  policy     Inspect policy groups, profiles, and security rules
  profile    Create and manage nono profiles

\x1b[1mOPTIONS\x1b[0m
{options}

\x1b[1mLEARN MORE\x1b[0m
  Use `nono <command> --help` for more information about a command.
  Read the docs at https://nono.sh/docs
")]
pub struct Cli {
    /// Silent mode - suppress all nono output (banner, summary, status)
    #[arg(long, short = 's', global = true, help_heading = "OPTIONS")]
    pub silent: bool,

    /// Color theme for output (mocha, latte, frappe, macchiato, tokyo-night, minimal)
    #[arg(
        long,
        global = true,
        env = "NONO_THEME",
        value_name = "THEME",
        help_heading = "OPTIONS"
    )]
    pub theme: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    // ── Getting started ─────────────────────────────────────────────────
    /// Set up nono on this system
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono setup [flags]

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono setup --profiles                        # Full setup with profile generation
  nono setup --check-only                      # Verify installation and sandbox support
  nono setup --profiles --shell-integration    # Setup with shell integration help
  nono setup -v --profiles                     # Verbose setup
")]
    Setup(SetupArgs),

    // ── Core usage ──────────────────────────────────────────────────────
    /// Run a command inside the sandbox
    #[command(trailing_var_arg = true)]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono run [flags] <program>...

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono run --allow . claude                    # Read/write current dir, run claude
  nono run --profile claude-code claude        # Use a built-in profile
  nono run --profile claude-code --allow-net claude
                                               # Profile with unrestricted network
  nono run --read ./src --write ./output cargo build
                                               # Separate read/write permissions
  nono run --allow . --block-net cargo build   # Block network access
  nono run --allow . --env-credential openai_api_key,anthropic_api_key -- claude
                                               # Load secrets from system keystore
")]
    Run(Box<RunArgs>),

    /// Start an interactive shell inside the sandbox
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono shell [flags]

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono shell --allow .                         # Shell with read/write to current dir
  nono shell --profile claude-code             # Use a named profile
  nono shell --allow . --shell /bin/zsh        # Override shell binary
")]
    Shell(Box<ShellArgs>),

    /// Apply sandbox and exec into command (nono disappears).
    /// For scripts, piping, and embedding where no parent process is wanted.
    #[command(trailing_var_arg = true)]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono wrap [flags] <program>...

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono wrap --allow . -- cargo build           # Sandbox and exec into cargo build
  nono wrap --profile developer -- cargo test  # Use a named profile
")]
    Wrap(Box<WrapArgs>),

    // ── Exploration & debugging ─────────────────────────────────────────
    /// Trace a command to discover required filesystem paths
    #[command(trailing_var_arg = true)]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono learn [flags] <program>...

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono learn -- my-app                         # Discover paths needed by a command
  nono learn --profile my-profile -- my-app    # Compare against an existing profile
  nono learn --json -- node server.js          # Output as JSON for profile
  nono learn --timeout 30 -- my-app            # Limit trace duration

\x1b[1mPLATFORM NOTES\x1b[0m
  Linux   Uses strace (install with: apt install strace)
  macOS   Uses fs_usage (requires sudo)
")]
    Learn(Box<LearnArgs>),

    /// Check why a path or network operation would be allowed or denied
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono why [flags]

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono why --path ~/.ssh --op read             # Check if ~/.ssh is readable
  nono why --path ./src --op write --allow .   # Check with capability context
  nono why --json --path ~/.aws --op read      # JSON output for agents
  nono why --host api.openai.com --port 443    # Query network access
  nono why --self --path /tmp --op write       # Inside sandbox, query own capabilities
")]
    Why(Box<WhyArgs>),

    // ── Session management ───────────────────────────────────────────────
    /// Manage rollback sessions (browse, restore, cleanup)
    #[command(subcommand_help_heading = "COMMANDS", disable_help_subcommand = true)]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono rollback <command>

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono rollback list                           # List sessions with file changes
  nono rollback show <id> --diff               # Show changes with diff
  nono rollback restore <id>                   # Restore files from a session
  nono rollback restore <id> --dry-run         # Preview what would change
  nono rollback verify <id>                    # Verify session integrity
  nono rollback cleanup --dry-run              # Preview cleanup
")]
    Rollback(RollbackArgs),

    /// View audit trail of sandboxed commands
    #[command(subcommand_help_heading = "COMMANDS", disable_help_subcommand = true)]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono audit <command>

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono audit list                              # List all sessions
  nono audit list --today                      # List sessions from today
  nono audit list --command claude             # Filter by command
  nono audit show <id> --json                  # Export as JSON
")]
    Audit(AuditArgs),

    /// Manage instruction file trust and attestation
    #[command(subcommand_help_heading = "COMMANDS", disable_help_subcommand = true)]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono trust <command>

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono trust sign SKILLS.md                    # Sign with default keystore key
  nono trust sign SKILLS.md --key my-key       # Sign with a specific key ID
  nono trust verify SKILLS.md                  # Verify an instruction file
  nono trust verify --all                      # Verify all instruction files
  nono trust list                              # List files and verification status
  nono trust keygen                            # Generate a new signing key pair
")]
    Trust(TrustArgs),

    // ── Policy & profiles ────────────────────────────────────────────────
    /// Inspect policy groups, profiles, and security rules
    #[command(subcommand_help_heading = "COMMANDS")]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono policy <command>

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono policy groups                           # List all policy groups
  nono policy groups deny_credentials          # Show details for a specific group
  nono policy profiles                         # List all profiles (built-in and user)
  nono policy show claude-code                 # Show a fully resolved profile
  nono policy diff default claude-code         # Compare two profiles
  nono policy validate ~/my-profile.json       # Validate a user profile file
")]
    Policy(PolicyArgs),

    /// Create and manage nono profiles
    #[command(subcommand_help_heading = "COMMANDS")]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono profile <command>

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono profile init my-agent                   # Create a new profile with defaults
  nono profile init my-agent --extends default --groups deny_credentials
                                               # Extend an existing profile
  nono profile init my-agent --full            # Generate a full skeleton
  nono profile init my-agent --output ./my-profile.json
                                               # Output to a specific file
  nono profile schema                          # Print JSON Schema for editor validation
  nono profile guide                           # Print profile authoring guide
")]
    Profile(ProfileCmdArgs),

    /// Internal: open a URL via supervisor IPC
    #[command(hide = true)]
    OpenUrlHelper(OpenUrlHelperArgs),
}

/// Arguments for the hidden open-url-helper subcommand.
///
/// Invoked as `BROWSER=nono open-url-helper` on Linux, or via the `open`
/// PATH shim on macOS. Reads `NONO_SUPERVISOR_FD` from the environment,
/// sends an `OpenUrl` IPC message to the unsandboxed supervisor, and
/// waits for a response.
#[derive(Parser, Debug, Clone)]
pub struct OpenUrlHelperArgs {
    /// The URL to open
    pub url: String,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub command: PolicyCommands,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Subcommand, Debug)]
pub enum PolicyCommands {
    /// List policy groups or show details for a specific group
    Groups(PolicyGroupsArgs),
    /// List all available profiles (built-in and user)
    Profiles(PolicyProfilesArgs),
    /// Show a fully resolved profile
    Show(PolicyShowArgs),
    /// Diff two profiles
    Diff(PolicyDiffArgs),
    /// Validate a profile JSON file
    Validate(PolicyValidateArgs),
}

#[derive(Parser, Debug)]
pub struct PolicyGroupsArgs {
    /// Group name to show details for (omit to list all)
    pub name: Option<String>,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
    /// Show all platforms (not just current)
    #[arg(long)]
    pub all_platforms: bool,
}

#[derive(Parser, Debug)]
pub struct PolicyProfilesArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser, Debug)]
pub struct PolicyShowArgs {
    /// Profile name or path
    pub profile: String,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
    /// Show raw paths before expansion (e.g., $HOME instead of /Users/luke)
    #[arg(long)]
    pub raw: bool,
}

#[derive(Parser, Debug)]
pub struct PolicyDiffArgs {
    /// First profile name or path
    pub profile1: String,
    /// Second profile name or path
    pub profile2: String,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser, Debug)]
pub struct PolicyValidateArgs {
    /// Profile JSON file to validate
    pub file: PathBuf,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct ProfileCmdArgs {
    #[command(subcommand)]
    pub command: ProfileCommands,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Subcommand, Debug)]
pub enum ProfileCommands {
    /// Generate a skeleton profile JSON file
    Init(ProfileInitArgs),
    /// Output the JSON Schema for profile files
    Schema(ProfileSchemaArgs),
    /// Print the profile authoring guide
    Guide(ProfileGuideArgs),
}

#[derive(Parser, Debug)]
pub struct ProfileInitArgs {
    /// Profile name (alphanumeric + hyphens)
    pub name: String,
    /// Base profile to extend
    #[arg(long)]
    pub extends: Option<String>,
    /// Security groups to include (comma-separated)
    #[arg(long, value_delimiter = ',')]
    pub groups: Vec<String>,
    /// Profile description
    #[arg(long)]
    pub description: Option<String>,
    /// Generate a full skeleton with all sections
    #[arg(long)]
    pub full: bool,
    /// Output file path (default: ~/.config/nono/profiles/<name>.json)
    #[arg(long, short)]
    pub output: Option<PathBuf>,
    /// Overwrite existing file
    #[arg(long)]
    pub force: bool,
}

#[derive(Parser, Debug)]
pub struct ProfileSchemaArgs {
    /// Write schema to a file instead of stdout
    #[arg(long, short)]
    pub output: Option<PathBuf>,
}

#[derive(Parser, Debug)]
pub struct ProfileGuideArgs {}

#[derive(Parser, Debug, Clone, Default)]
pub struct SandboxArgs {
    // ── Filesystem ───────────────────────────────────────────────────────
    /// Allow read+write access to a directory (recursive)
    #[arg(
        long,
        short = 'a',
        value_name = "DIR",
        env = "NONO_ALLOW",
        value_delimiter = ',',
        help_heading = "FILESYSTEM"
    )]
    pub allow: Vec<PathBuf>,

    /// Allow read-only access to a directory (recursive)
    #[arg(long, short = 'r', value_name = "DIR", help_heading = "FILESYSTEM")]
    pub read: Vec<PathBuf>,

    /// Allow write-only access to a directory (recursive). Directory deletion NOT included
    #[arg(long, short = 'w', value_name = "DIR", help_heading = "FILESYSTEM")]
    pub write: Vec<PathBuf>,

    /// Allow read+write access to a single file
    #[arg(long, value_name = "FILE", help_heading = "FILESYSTEM")]
    pub allow_file: Vec<PathBuf>,

    /// Allow read-only access to a single file
    #[arg(long, value_name = "FILE", help_heading = "FILESYSTEM")]
    pub read_file: Vec<PathBuf>,

    /// Allow write-only access to a single file
    #[arg(long, value_name = "FILE", help_heading = "FILESYSTEM")]
    pub write_file: Vec<PathBuf>,

    /// Override a deny rule for a path. Pair with --allow/--read/--write grant
    #[arg(long, value_name = "PATH", help_heading = "FILESYSTEM")]
    pub override_deny: Vec<PathBuf>,

    /// Allow CWD access without prompting (level set by profile, defaults to read-only)
    #[arg(long, help_heading = "FILESYSTEM")]
    pub allow_cwd: bool,

    /// Working directory for $WORKDIR expansion in profiles
    #[arg(long, value_name = "DIR", help_heading = "FILESYSTEM")]
    pub workdir: Option<PathBuf>,

    // ── Network ──────────────────────────────────────────────────────────
    /// Block outbound network access (allowed by default)
    #[arg(
        long = "block-net",
        alias = "net-block",
        conflicts_with = "allow_net",
        env = "NONO_BLOCK_NET",
        value_parser = clap::builder::BoolishValueParser::new(),
        action = clap::ArgAction::SetTrue,
        help_heading = "NETWORK"
    )]
    pub block_net: bool,

    /// Allow unrestricted network; disables proxy filtering and credential injection
    #[arg(
        long = "allow-net",
        alias = "net-allow",
        env = "NONO_ALLOW_NET",
        value_parser = clap::builder::BoolishValueParser::new(),
        action = clap::ArgAction::SetTrue,
        conflicts_with_all = [
            "block_net",
            "network_profile",
            "allow_proxy",
            "proxy_credential",
            "external_proxy",
            "external_proxy_bypass",
            "proxy_port"
        ],
        help_heading = "NETWORK"
    )]
    pub allow_net: bool,

    /// Enable proxy filtering with a named network profile
    #[arg(
        long,
        value_name = "PROFILE",
        env = "NONO_NETWORK_PROFILE",
        help_heading = "NETWORK"
    )]
    pub network_profile: Option<String>,

    /// Allow additional hosts through the proxy (repeatable)
    #[arg(
        long = "allow-proxy",
        alias = "proxy-allow",
        value_name = "HOST",
        help_heading = "NETWORK"
    )]
    pub allow_proxy: Vec<String>,

    /// Allow binding on a TCP port. macOS: enables blanket inbound (no per-port filtering)
    #[arg(long, value_name = "PORT", help_heading = "NETWORK")]
    pub allow_bind: Vec<u16>,

    /// Allow bidirectional TCP on a port — connect + bind (repeatable)
    #[arg(long, value_name = "PORT", help_heading = "NETWORK")]
    pub allow_port: Vec<u16>,

    /// Chain through an external proxy (host:port)
    #[arg(
        long,
        value_name = "HOST:PORT",
        env = "NONO_EXTERNAL_PROXY",
        help_heading = "NETWORK"
    )]
    pub external_proxy: Option<String>,

    /// Bypass external proxy for these domains (repeatable)
    #[arg(
        long,
        value_name = "HOST",
        env = "NONO_EXTERNAL_PROXY_BYPASS",
        value_delimiter = ',',
        help_heading = "NETWORK"
    )]
    pub external_proxy_bypass: Vec<String>,

    /// Fixed port for the credential proxy (default: OS-assigned)
    #[arg(long, value_name = "PORT", help_heading = "NETWORK")]
    pub proxy_port: Option<u16>,

    // ── Credentials ──────────────────────────────────────────────────────
    /// Inject credentials via reverse proxy for a service (repeatable)
    #[arg(long, value_name = "SERVICE", help_heading = "CREDENTIALS")]
    pub proxy_credential: Vec<String>,

    /// Load credentials as env vars. For network API keys, prefer --proxy-credential
    #[arg(
        long,
        value_name = "CREDENTIALS",
        env = "NONO_ENV_CREDENTIAL",
        help_heading = "CREDENTIALS"
    )]
    pub env_credential: Option<String>,

    /// Map a credential reference to an environment variable (repeatable)
    #[arg(
        long,
        value_names = ["CREDENTIAL_REF", "ENV_VAR"],
        num_args = 2,
        action = clap::ArgAction::Append,
        help_heading = "CREDENTIALS"
    )]
    pub env_credential_map: Vec<String>,

    // ── Commands ─────────────────────────────────────────────────────────
    /// Allow a normally-blocked dangerous command (use with caution)
    #[arg(long, value_name = "CMD", help_heading = "COMMANDS")]
    pub allow_command: Vec<String>,

    /// Block an additional command beyond the default blocklist
    #[arg(long, value_name = "CMD", help_heading = "COMMANDS")]
    pub block_command: Vec<String>,

    // ── General ──────────────────────────────────────────────────────────
    /// Use a profile by name or file path
    #[arg(
        long,
        short = 'p',
        value_name = "NAME_OR_PATH",
        env = "NONO_PROFILE",
        help_heading = "OPTIONS"
    )]
    pub profile: Option<String>,

    /// Allow direct LaunchServices opens on macOS (temporary login/setup flows)
    #[arg(long, help_heading = "OPTIONS")]
    pub allow_launch_services: bool,

    /// Configuration file path
    #[arg(long, short = 'c', value_name = "FILE", help_heading = "OPTIONS")]
    pub config: Option<PathBuf>,

    /// Enable verbose output
    #[arg(long, short = 'v', action = clap::ArgAction::Count, help_heading = "OPTIONS")]
    pub verbose: u8,

    /// Show what would be sandboxed without executing
    #[arg(long, help_heading = "OPTIONS")]
    pub dry_run: bool,
}

impl SandboxArgs {
    /// Whether any CLI flag requires proxy mode activation.
    pub fn has_proxy_flags(&self) -> bool {
        self.network_profile.is_some()
            || !self.allow_proxy.is_empty()
            || !self.proxy_credential.is_empty()
            || self.external_proxy.is_some()
    }
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct RunArgs {
    #[command(flatten)]
    pub sandbox: SandboxArgs,

    // ── Rollback ──────────────────────────────────────────────────────
    /// Enable atomic rollback snapshots for the session
    #[arg(long, conflicts_with = "no_rollback", help_heading = "ROLLBACK")]
    pub rollback: bool,

    /// Skip the post-exit rollback review prompt
    #[arg(long, help_heading = "ROLLBACK")]
    pub no_rollback_prompt: bool,

    /// Disable rollback entirely (no snapshots taken)
    #[arg(long, conflicts_with = "rollback", help_heading = "ROLLBACK")]
    pub no_rollback: bool,

    /// Exclude from snapshots. Globs match filenames; plain names match path components
    #[arg(long, value_name = "PATTERN", help_heading = "ROLLBACK")]
    pub rollback_exclude: Vec<String>,

    /// Force-include an auto-excluded directory (name only, not full path)
    #[arg(long, value_name = "DIR_NAME", help_heading = "ROLLBACK")]
    pub rollback_include: Vec<String>,

    /// Include all directories in snapshots. VCS dirs (.git) always excluded
    #[arg(long, conflicts_with = "rollback_include", help_heading = "ROLLBACK")]
    pub rollback_all: bool,

    // ── Options ────────────────────────────────────────────────────────
    /// Suppress diagnostic footer on command failure
    #[arg(long, help_heading = "OPTIONS")]
    pub no_diagnostics: bool,

    /// Disable the audit trail for this session
    #[arg(long, conflicts_with = "rollback", help_heading = "OPTIONS")]
    pub no_audit: bool,

    /// Disable trust verification for instruction files (not recommended for production)
    #[arg(long, help_heading = "OPTIONS")]
    pub trust_override: bool,

    /// Enable runtime capability elevation (interactive prompts)
    #[arg(long, env = "NONO_CAPABILITY_ELEVATION", help_heading = "OPTIONS")]
    pub capability_elevation: bool,

    /// Command to run inside the sandbox
    #[arg(required = true, hide = true)]
    pub command: Vec<String>,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct ShellArgs {
    #[command(flatten)]
    pub sandbox: SandboxArgs,

    /// Shell to execute (defaults to $SHELL or /bin/sh)
    #[arg(long, value_name = "SHELL", help_heading = "OPTIONS")]
    pub shell: Option<PathBuf>,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct WrapArgs {
    #[command(flatten)]
    pub sandbox: SandboxArgs,

    /// Suppress diagnostic footer on command failure
    #[arg(long, help_heading = "OPTIONS")]
    pub no_diagnostics: bool,

    /// Command to run inside the sandbox
    #[arg(required = true, hide = true)]
    pub command: Vec<String>,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct SetupArgs {
    /// Only verify installation and sandbox support, don't create files
    #[arg(long, help_heading = "OPTIONS")]
    pub check_only: bool,

    /// Generate example user profiles in ~/.config/nono/profiles/
    #[arg(long, help_heading = "OPTIONS")]
    pub profiles: bool,

    /// Show shell integration instructions
    #[arg(long, help_heading = "OPTIONS")]
    pub shell_integration: bool,

    /// Show detailed information during setup
    #[arg(short, long, action = clap::ArgAction::Count, help_heading = "OPTIONS")]
    pub verbose: u8,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct WhyArgs {
    /// Path to check
    #[arg(long, help_heading = "QUERY")]
    pub path: Option<PathBuf>,

    /// Operation to check: read, write, or readwrite
    #[arg(long, value_enum, help_heading = "QUERY")]
    pub op: Option<WhyOp>,

    /// Network host to check
    #[arg(long, help_heading = "QUERY")]
    pub host: Option<String>,

    /// Network port (default 443)
    #[arg(long, default_value = "443", help_heading = "QUERY")]
    pub port: u16,

    /// Output JSON instead of human-readable format
    #[arg(long, help_heading = "OPTIONS")]
    pub json: bool,

    /// Query current sandbox state (use inside a sandboxed process)
    #[arg(long = "self", help_heading = "OPTIONS")]
    pub self_query: bool,

    // ── Capability context ─────────────────────────────────────────────
    /// Directories to allow read+write access (for query context)
    #[arg(long, short = 'a', value_name = "DIR", help_heading = "CONTEXT")]
    pub allow: Vec<PathBuf>,

    /// Directories to allow read-only access (for query context)
    #[arg(long, short = 'r', value_name = "DIR", help_heading = "CONTEXT")]
    pub read: Vec<PathBuf>,

    /// Directories to allow write-only access (for query context)
    #[arg(long, short = 'w', value_name = "DIR", help_heading = "CONTEXT")]
    pub write: Vec<PathBuf>,

    /// Single files to allow read+write access (for query context)
    #[arg(long, value_name = "FILE", help_heading = "CONTEXT")]
    pub allow_file: Vec<PathBuf>,

    /// Single files to allow read-only access (for query context)
    #[arg(long, value_name = "FILE", help_heading = "CONTEXT")]
    pub read_file: Vec<PathBuf>,

    /// Single files to allow write-only access (for query context)
    #[arg(long, value_name = "FILE", help_heading = "CONTEXT")]
    pub write_file: Vec<PathBuf>,

    /// Block network access (for query context)
    #[arg(long = "block-net", alias = "net-block", help_heading = "CONTEXT")]
    pub block_net: bool,

    /// Use a named profile for query context
    #[arg(long, short = 'p', value_name = "NAME", help_heading = "CONTEXT")]
    pub profile: Option<String>,

    /// Working directory for $WORKDIR expansion in profiles
    #[arg(long, value_name = "DIR", help_heading = "CONTEXT")]
    pub workdir: Option<PathBuf>,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct LearnArgs {
    /// Use a named profile to compare against (shows only missing paths)
    #[arg(long, short = 'p', value_name = "NAME", help_heading = "OPTIONS")]
    pub profile: Option<String>,

    /// Output discovered paths as JSON fragment for profile
    #[arg(long, help_heading = "OPTIONS")]
    pub json: bool,

    /// Timeout in seconds (default: run until command exits)
    #[arg(long, value_name = "SECS", help_heading = "OPTIONS")]
    pub timeout: Option<u64>,

    /// Show all accessed paths, not just those that would be blocked
    #[arg(long, help_heading = "OPTIONS")]
    pub all: bool,

    /// Skip reverse DNS lookups for discovered IPs
    #[arg(long, help_heading = "OPTIONS")]
    pub no_rdns: bool,

    /// Enable verbose output
    #[arg(long, short = 'v', action = clap::ArgAction::Count, help_heading = "OPTIONS")]
    pub verbose: u8,

    /// Command to trace
    #[arg(required = true, hide = true)]
    pub command: Vec<String>,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
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
#[command(disable_help_flag = true)]
pub struct RollbackArgs {
    #[command(subcommand)]
    pub command: RollbackCommands,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
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
#[command(disable_help_flag = true)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub command: AuditCommands,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
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

// ---------------------------------------------------------------------------
// Trust command args
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct TrustArgs {
    #[command(subcommand)]
    pub command: TrustCommands,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Subcommand, Debug)]
pub enum TrustCommands {
    /// Sign an instruction file, producing a .bundle alongside it
    Sign(TrustSignArgs),
    /// Sign a trust policy file, producing a .bundle alongside it
    SignPolicy(TrustSignPolicyArgs),
    /// Verify an instruction file's bundle against the trust policy
    Verify(TrustVerifyArgs),
    /// List instruction files and their verification status
    List(TrustListArgs),
    /// Generate a new ECDSA P-256 signing key pair
    Keygen(TrustKeygenArgs),
    /// Export the public key for a signing key (base64 DER)
    ExportKey(TrustExportKeyArgs),
}

#[derive(Parser, Debug)]
pub struct TrustSignArgs {
    /// Instruction file(s) to sign
    #[arg(required_unless_present = "all")]
    pub files: Vec<PathBuf>,

    /// Sign all instruction files matching trust policy patterns in CWD
    #[arg(long)]
    pub all: bool,

    /// Key ID to use from the system keystore (default: "default")
    #[arg(long, value_name = "KEY_ID", conflicts_with = "keyless")]
    pub key: Option<String>,

    /// Use Sigstore keyless signing (Fulcio + Rekor via ambient OIDC)
    #[arg(long)]
    pub keyless: bool,

    /// Trust policy file (default: auto-discover)
    #[arg(long, value_name = "FILE")]
    pub policy: Option<PathBuf>,
}

#[derive(Parser, Debug)]
pub struct TrustSignPolicyArgs {
    /// Trust policy file to sign (default: trust-policy.json in CWD)
    pub file: Option<PathBuf>,

    /// Key ID to use from the system keystore (default: "default")
    #[arg(long, value_name = "KEY_ID")]
    pub key: Option<String>,
}

#[derive(Parser, Debug)]
pub struct TrustVerifyArgs {
    /// Instruction file(s) to verify
    #[arg(required_unless_present = "all")]
    pub files: Vec<PathBuf>,

    /// Verify all instruction files matching trust policy patterns in CWD
    #[arg(long)]
    pub all: bool,

    /// Trust policy file (default: auto-discover)
    #[arg(long, value_name = "FILE")]
    pub policy: Option<PathBuf>,
}

#[derive(Parser, Debug)]
pub struct TrustListArgs {
    /// Trust policy file (default: auto-discover)
    #[arg(long, value_name = "FILE")]
    pub policy: Option<PathBuf>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser, Debug)]
pub struct TrustKeygenArgs {
    /// Key identifier (stored in system keystore under this name)
    #[arg(long, value_name = "NAME", default_value = "default")]
    pub id: String,

    /// Overwrite existing key with the same ID
    #[arg(long)]
    pub force: bool,
}

#[derive(Parser, Debug)]
pub struct TrustExportKeyArgs {
    /// Key identifier to export (default: "default")
    #[arg(long, value_name = "NAME", default_value = "default")]
    pub id: String,

    /// Output as PEM instead of base64 DER
    #[arg(long)]
    pub pem: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

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
    fn test_wrap_basic() {
        let cli = Cli::parse_from(["nono", "wrap", "--allow", ".", "--", "cargo", "build"]);
        match cli.command {
            Commands::Wrap(args) => {
                assert_eq!(args.command, vec!["cargo", "build"]);
                assert_eq!(args.sandbox.allow.len(), 1);
                assert!(!args.no_diagnostics);
            }
            _ => panic!("Expected Wrap command"),
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

    #[test]
    fn test_trust_sign() {
        let cli = Cli::parse_from(["nono", "trust", "sign", "SKILLS.md"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::Sign(sign_args) => {
                    assert_eq!(sign_args.files, vec![PathBuf::from("SKILLS.md")]);
                    assert!(!sign_args.all);
                    assert!(sign_args.key.is_none());
                }
                _ => panic!("Expected Sign subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_sign_with_key() {
        let cli = Cli::parse_from(["nono", "trust", "sign", "SKILLS.md", "--key", "my-key"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::Sign(sign_args) => {
                    assert_eq!(sign_args.key, Some("my-key".to_string()));
                }
                _ => panic!("Expected Sign subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_sign_all() {
        let cli = Cli::parse_from(["nono", "trust", "sign", "--all"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::Sign(sign_args) => {
                    assert!(sign_args.all);
                    assert!(sign_args.files.is_empty());
                }
                _ => panic!("Expected Sign subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_verify() {
        let cli = Cli::parse_from(["nono", "trust", "verify", "SKILLS.md"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::Verify(verify_args) => {
                    assert_eq!(verify_args.files, vec![PathBuf::from("SKILLS.md")]);
                    assert!(!verify_args.all);
                }
                _ => panic!("Expected Verify subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_list() {
        let cli = Cli::parse_from(["nono", "trust", "list"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::List(list_args) => {
                    assert!(!list_args.json);
                }
                _ => panic!("Expected List subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_keygen() {
        let cli = Cli::parse_from(["nono", "trust", "keygen"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::Keygen(keygen_args) => {
                    assert_eq!(keygen_args.id, "default");
                    assert!(!keygen_args.force);
                }
                _ => panic!("Expected Keygen subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_keygen_with_id() {
        let cli = Cli::parse_from(["nono", "trust", "keygen", "--id", "my-key", "--force"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::Keygen(keygen_args) => {
                    assert_eq!(keygen_args.id, "my-key");
                    assert!(keygen_args.force);
                }
                _ => panic!("Expected Keygen subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_export_key_defaults() {
        let cli = Cli::parse_from(["nono", "trust", "export-key"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::ExportKey(export_args) => {
                    assert_eq!(export_args.id, "default");
                    assert!(!export_args.pem);
                }
                _ => panic!("Expected ExportKey subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_export_key_with_options() {
        let cli = Cli::parse_from(["nono", "trust", "export-key", "--id", "my-key", "--pem"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::ExportKey(export_args) => {
                    assert_eq!(export_args.id, "my-key");
                    assert!(export_args.pem);
                }
                _ => panic!("Expected ExportKey subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_rollback_flags_with_no_rollback() {
        // --no-rollback alongside rollback customization flags should parse
        // (the warning is emitted at runtime, not parse time)
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--no-rollback",
            "--rollback-exclude",
            "target",
            "echo",
            "hello",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert!(args.no_rollback);
                assert_eq!(args.rollback_exclude, vec!["target"]);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_rollback_all_conflicts_with_include() {
        // --rollback-all conflicts with --rollback-include (clap enforced)
        let result = Cli::try_parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--rollback-all",
            "--rollback-include",
            "target",
            "echo",
            "hello",
        ]);
        assert!(
            result.is_err(),
            "--rollback-all and --rollback-include should conflict"
        );
    }

    #[test]
    fn test_allow_net_parsing() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--allow-net",
            "echo",
            "hello",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert!(args.sandbox.allow_net);
                assert!(!args.sandbox.block_net);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_allow_net_conflicts_with_block_net() {
        let result = Cli::try_parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--allow-net",
            "--block-net",
            "echo",
        ]);
        assert!(
            result.is_err(),
            "--allow-net and --block-net should conflict"
        );
    }

    #[test]
    fn test_allow_net_conflicts_with_network_profile() {
        let result = Cli::try_parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--allow-net",
            "--network-profile",
            "developer",
            "echo",
        ]);
        assert!(
            result.is_err(),
            "--allow-net and --network-profile should conflict"
        );
    }

    #[test]
    fn test_allow_net_conflicts_with_allow_proxy() {
        let result = Cli::try_parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--allow-net",
            "--allow-proxy",
            "api.openai.com",
            "echo",
        ]);
        assert!(
            result.is_err(),
            "--allow-net and --allow-proxy should conflict"
        );
    }

    #[test]
    fn test_legacy_flag_aliases_still_parse() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--net-allow",
            "echo",
            "hello",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert!(args.sandbox.allow_net);
            }
            _ => panic!("Expected Run command"),
        }

        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--proxy-allow",
            "api.openai.com",
            "echo",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.allow_proxy, vec!["api.openai.com"]);
            }
            _ => panic!("Expected Run command"),
        }

        let cli = Cli::parse_from(["nono", "why", "--host", "example.com", "--net-block"]);
        match cli.command {
            Commands::Why(args) => {
                assert!(args.block_net);
            }
            _ => panic!("Expected Why command"),
        }
    }

    #[test]
    fn test_override_deny_single() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--override-deny",
            "/tmp/test",
            "--allow",
            "/tmp/test",
            "echo",
            "hello",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.override_deny.len(), 1);
                assert_eq!(args.sandbox.override_deny[0], PathBuf::from("/tmp/test"));
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_override_deny_multiple() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--override-deny",
            "/tmp/a",
            "--override-deny",
            "/tmp/b",
            "--allow",
            ".",
            "echo",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.override_deny.len(), 2);
                assert_eq!(args.sandbox.override_deny[0], PathBuf::from("/tmp/a"));
                assert_eq!(args.sandbox.override_deny[1], PathBuf::from("/tmp/b"));
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_env_credential_map_repeatable_parses_pairs() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--env-credential-map",
            "op://vault/item/field",
            "OPENAI_API_KEY",
            "--env-credential-map",
            "apple-password://github.com/user=name",
            "GITHUB_PASSWORD",
            "echo",
            "ok",
        ]);

        match cli.command {
            Commands::Run(args) => {
                assert_eq!(
                    args.sandbox.env_credential_map,
                    vec![
                        "op://vault/item/field".to_string(),
                        "OPENAI_API_KEY".to_string(),
                        "apple-password://github.com/user=name".to_string(),
                        "GITHUB_PASSWORD".to_string()
                    ]
                );
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_allow_port_parsing() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow-port",
            "3000",
            "--allow-port",
            "5000",
            "--allow",
            ".",
            "echo",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.allow_port, vec![3000, 5000]);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_profile_init_basic() {
        let cli = Cli::parse_from(["nono", "profile", "init", "my-agent"]);
        match cli.command {
            Commands::Profile(args) => match args.command {
                ProfileCommands::Init(init) => {
                    assert_eq!(init.name, "my-agent");
                    assert!(init.extends.is_none());
                    assert!(init.groups.is_empty());
                    assert!(init.description.is_none());
                    assert!(!init.full);
                    assert!(init.output.is_none());
                    assert!(!init.force);
                }
                _ => panic!("Expected Init subcommand"),
            },
            _ => panic!("Expected Profile command"),
        }
    }

    #[test]
    fn test_profile_init_all_flags() {
        let cli = Cli::parse_from([
            "nono",
            "profile",
            "init",
            "my-agent",
            "--extends",
            "default",
            "--groups",
            "deny_credentials,node_runtime",
            "--description",
            "My agent profile",
            "--full",
            "--output",
            "/tmp/out.json",
            "--force",
        ]);
        match cli.command {
            Commands::Profile(args) => match args.command {
                ProfileCommands::Init(init) => {
                    assert_eq!(init.name, "my-agent");
                    assert_eq!(init.extends, Some("default".to_string()));
                    assert_eq!(init.groups, vec!["deny_credentials", "node_runtime"]);
                    assert_eq!(init.description, Some("My agent profile".to_string()));
                    assert!(init.full);
                    assert_eq!(init.output, Some(std::path::PathBuf::from("/tmp/out.json")));
                    assert!(init.force);
                }
                _ => panic!("Expected Init subcommand"),
            },
            _ => panic!("Expected Profile command"),
        }
    }

    #[test]
    fn test_profile_schema_default() {
        let cli = Cli::parse_from(["nono", "profile", "schema"]);
        match cli.command {
            Commands::Profile(args) => match args.command {
                ProfileCommands::Schema(schema) => {
                    assert!(schema.output.is_none());
                }
                _ => panic!("Expected Schema subcommand"),
            },
            _ => panic!("Expected Profile command"),
        }
    }

    #[test]
    fn test_profile_schema_with_output() {
        let cli = Cli::parse_from(["nono", "profile", "schema", "-o", "/tmp/schema.json"]);
        match cli.command {
            Commands::Profile(args) => match args.command {
                ProfileCommands::Schema(schema) => {
                    assert_eq!(
                        schema.output,
                        Some(std::path::PathBuf::from("/tmp/schema.json"))
                    );
                }
                _ => panic!("Expected Schema subcommand"),
            },
            _ => panic!("Expected Profile command"),
        }
    }

    #[test]
    fn test_profile_guide() {
        let cli = Cli::parse_from(["nono", "profile", "guide"]);
        match cli.command {
            Commands::Profile(args) => match args.command {
                ProfileCommands::Guide(_) => {}
                _ => panic!("Expected Guide subcommand"),
            },
            _ => panic!("Expected Profile command"),
        }
    }

    #[test]
    fn test_profile_init_missing_name() {
        let result = Cli::try_parse_from(["nono", "profile", "init"]);
        assert!(result.is_err(), "init without name should fail");
    }

    #[test]
    fn test_profile_no_subcommand() {
        let result = Cli::try_parse_from(["nono", "profile"]);
        assert!(result.is_err(), "profile without subcommand should fail");
    }

    /// All subcommand names that must appear in the root help template.
    /// If you add a new command to the `Commands` enum, add it here too.
    const ALL_SUBCOMMANDS: &[&str] = &[
        "setup", "run", "shell", "wrap", "learn", "why", "rollback", "audit", "trust", "policy",
        "profile",
    ];

    #[test]
    fn test_root_help_lists_all_commands() {
        // The root help template is hardcoded — verify every subcommand appears in it.
        let cmd = Cli::command();
        let mut buf = Vec::new();
        cmd.clone()
            .write_help(&mut buf)
            .expect("failed to write help");
        let help = String::from_utf8(buf).expect("help is not utf-8");

        for name in ALL_SUBCOMMANDS {
            assert!(
                help.contains(&format!("  {name}")),
                "Root --help is missing subcommand `{name}`. \
                 Update the help_template on the Cli struct.",
            );
        }

        // Also verify we haven't forgotten to add a new variant to ALL_SUBCOMMANDS.
        for sub in cmd.get_subcommands() {
            let name = sub.get_name().to_string();
            if name == "help" || sub.is_hide_set() {
                continue; // clap auto-generates help; hidden commands are internal
            }
            assert!(
                ALL_SUBCOMMANDS.contains(&name.as_str()),
                "Commands enum has variant `{name}` not listed in ALL_SUBCOMMANDS. \
                 Add it to the constant and to the root help_template.",
            );
        }
    }

    #[test]
    fn test_root_help_shows_all_flags() {
        // Every non-hidden root-level flag must appear in the rendered help.
        // Catches flags missing a help_heading (which puts them in an unnamed
        // group that our custom template doesn't render).
        let cmd = Cli::command();
        let mut buf = Vec::new();
        cmd.clone()
            .write_help(&mut buf)
            .expect("failed to write help");
        let help = String::from_utf8(buf).expect("help is not utf-8");

        for arg in cmd.get_arguments() {
            if arg.is_hide_set() {
                continue;
            }
            if let Some(long) = arg.get_long() {
                assert!(
                    help.contains(&format!("--{long}")),
                    "Root --help is missing flag `--{long}`. \
                     Add `help_heading = \"OPTIONS\"` to its #[arg] attribute.",
                );
            }
        }
    }

    #[test]
    fn test_subcommand_help_structure() {
        let root = Cli::command();

        for sub in root.get_subcommands() {
            let name = sub.get_name().to_string();
            if name == "help" || sub.is_hide_set() {
                continue;
            }

            // Render the help text
            let mut buf = Vec::new();
            sub.clone()
                .write_help(&mut buf)
                .expect("failed to write help");
            let help = String::from_utf8(buf).expect("help is not utf-8");

            // Every subcommand must have a USAGE section
            assert!(
                help.contains("USAGE"),
                "`nono {name} --help` is missing a USAGE section",
            );

            // Every subcommand must have an EXAMPLES section
            assert!(
                help.contains("EXAMPLES"),
                "`nono {name} --help` is missing an EXAMPLES section",
            );

            // USAGE line should reference the correct command name
            assert!(
                help.contains(&format!("nono {name}")),
                "`nono {name} --help` USAGE line doesn't mention `nono {name}`",
            );

            // Collect all flags this subcommand actually accepts
            let known_flags: Vec<String> = sub
                .get_arguments()
                .filter_map(|a: &clap::Arg| a.get_long().map(|l| l.to_string()))
                .collect();

            // Also collect flags from nested subcommands (for rollback/audit/trust)
            let known_sub_flags: Vec<String> = sub
                .get_subcommands()
                .flat_map(|s: &clap::Command| s.get_arguments())
                .filter_map(|a: &clap::Arg| a.get_long().map(|l| l.to_string()))
                .collect();

            // Extract the EXAMPLES section and check flags referenced there
            if let Some(examples_start) = help.find("EXAMPLES") {
                let examples = &help[examples_start..];

                // Find all --flag patterns in examples
                for token in examples.split_whitespace() {
                    if let Some(flag) = token.strip_prefix("--") {
                        let flag =
                            flag.trim_end_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-');
                        if flag.is_empty() || flag == "help" {
                            continue;
                        }
                        let valid = known_flags.iter().any(|f| f == flag)
                            || known_sub_flags.iter().any(|f| f == flag);
                        assert!(
                            valid,
                            "`nono {name} --help` EXAMPLES references --{flag} \
                             which is not a known flag on this subcommand",
                        );
                    }
                }
            }
        }
    }
}
