//! DEPRECATED: this module exists solely to keep `nono policy <sub>` working
//! while the canonical home is `nono profile <sub>`. It prints a deprecation
//! warning to stderr and delegates to the `profile_cmd` handlers.
//!
//! Removal steps (when the deprecation window ends):
//!   1. Delete this file.
//!   2. Delete `mod deprecated_policy;` in `main.rs`.
//!   3. Delete the `Commands::Policy` variant in `cli.rs`.
//!   4. Delete the `Commands::Policy` dispatch arm in `app_runtime.rs`.
//!   5. Delete `crates/nono-cli/tests/deprecated_policy.rs`.

use clap::{Parser, Subcommand};
use nono::Result;

// Share arg shapes with the canonical profile commands so any future
// field changes propagate automatically — no parallel arg types to keep
// in sync.
pub use crate::cli::{
    ProfileDiffArgs as PolicyDiffArgs, ProfileGroupsArgs as PolicyGroupsArgs,
    ProfileListArgs as PolicyProfilesArgs, ProfileShowArgs as PolicyShowArgs,
    ProfileValidateArgs as PolicyValidateArgs,
};

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
    /// [deprecated] Use 'nono profile groups' instead
    Groups(PolicyGroupsArgs),
    /// [deprecated] Use 'nono profile list' instead
    Profiles(PolicyProfilesArgs),
    /// [deprecated] Use 'nono profile show' instead
    Show(PolicyShowArgs),
    /// [deprecated] Use 'nono profile diff' instead
    Diff(PolicyDiffArgs),
    /// [deprecated] Use 'nono profile validate' instead
    Validate(PolicyValidateArgs),
}

fn warn(old_sub: &str, new_sub: &str) {
    eprintln!(
        "warning: 'nono policy {old_sub}' is deprecated and will be removed in a future release; use 'nono profile {new_sub}'"
    );
}

pub fn dispatch(args: PolicyArgs) -> Result<()> {
    match args.command {
        PolicyCommands::Groups(a) => {
            warn("groups", "groups");
            crate::profile_cmd::cmd_groups(a)
        }
        PolicyCommands::Profiles(a) => {
            warn("profiles", "list");
            crate::profile_cmd::cmd_list(a)
        }
        PolicyCommands::Show(a) => {
            warn("show", "show");
            crate::profile_cmd::cmd_show(a)
        }
        PolicyCommands::Diff(a) => {
            warn("diff", "diff");
            crate::profile_cmd::cmd_diff(a)
        }
        PolicyCommands::Validate(a) => {
            warn("validate", "validate");
            crate::profile_cmd::cmd_validate(a)
        }
    }
}
