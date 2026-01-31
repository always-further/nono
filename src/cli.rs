use clap::Parser;
use std::path::PathBuf;

/// nono - The opposite of YOLO
///
/// A capability-based shell for running untrusted AI agents and processes
/// with OS-enforced filesystem and network isolation.
#[derive(Parser, Debug)]
#[command(name = "nono")]
#[command(author, version, about, long_about = None)]
#[command(trailing_var_arg = true)]
#[command(after_help = "EXAMPLES:
    # Allow read/write to current directory, run claude
    nono --allow . claude

    # Use a named profile (built-in)
    nono --profile claude-code claude

    # Profile with explicit working directory
    nono --profile claude-code --workdir ./my-project claude

    # Profile + additional permissions
    nono --profile openclaw --read /tmp/extra openclaw gateway

    # Read-only access to src, write to output
    nono --read ./src --write ./output cargo build

    # Multiple allowed paths
    nono --allow ./project-a --allow ./project-b claude

    # With network access enabled
    nono --allow . --net-allow claude

    # Allow specific files (not directories)
    nono --allow . --write-file ~/.claude.json claude
")]
pub struct Args {
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

    /// Enable network access (binary: all outbound allowed when flag is present)
    /// Note: Per-host filtering not supported by OS sandbox; this is on/off only
    #[arg(long)]
    pub net_allow: bool,

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_args() {
        // Without --
        let args = Args::parse_from(["nono", "--allow", ".", "echo", "hello"]);
        assert_eq!(args.allow.len(), 1);
        assert_eq!(args.command, vec!["echo", "hello"]);
    }

    #[test]
    fn test_basic_args_with_separator() {
        // With -- (still works)
        let args = Args::parse_from(["nono", "--allow", ".", "--", "echo", "hello"]);
        assert_eq!(args.allow.len(), 1);
        assert_eq!(args.command, vec!["echo", "hello"]);
    }

    #[test]
    fn test_multiple_paths() {
        let args = Args::parse_from([
            "nono",
            "--allow",
            "./src",
            "--allow",
            "./docs",
            "--read",
            "/usr/share",
            "ls",
        ]);
        assert_eq!(args.allow.len(), 2);
        assert_eq!(args.read.len(), 1);
    }
}
