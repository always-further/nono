//! Post-exit interactive review/restore UI for the rollback system
//!
//! Presents the user with a summary of changes made during the session
//! and offers to restore to the initial state.

use colored::Colorize;
use nono::undo::{Change, ChangeType, SnapshotManager, SnapshotManifest};
use nono::Result;
use std::io::{BufRead, IsTerminal, Write};

/// Run the post-exit rollback review UI.
///
/// Shows a change summary and prompts the user to restore or exit.
/// Returns `true` if the user chose to restore.
pub fn review_and_restore(
    manager: &SnapshotManager,
    baseline: &SnapshotManifest,
    changes: &[Change],
) -> Result<bool> {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        return Ok(false);
    }

    print_change_details(changes);

    eprint!(
        "{} {}",
        "[nono]".truecolor(204, 102, 0),
        "Restore to initial state? [y/N]: ".white()
    );
    std::io::stderr().flush().ok();

    let mut input = String::new();
    stdin
        .lock()
        .read_line(&mut input)
        .map_err(nono::NonoError::Io)?;

    let answer = input.trim().to_lowercase();
    if answer == "y" || answer == "yes" {
        eprintln!(
            "{} {}",
            "[nono]".truecolor(204, 102, 0),
            "Restoring...".white()
        );

        let applied = manager.restore_to(baseline)?;

        eprintln!(
            "{} Restored {} files.",
            "[nono]".truecolor(204, 102, 0),
            applied.len()
        );
        Ok(true)
    } else {
        eprintln!(
            "{} {}",
            "[nono]".truecolor(204, 102, 0),
            "Exiting without restoring.".truecolor(150, 150, 150)
        );
        Ok(false)
    }
}

/// Print details of each change
fn print_change_details(changes: &[Change]) {
    eprintln!(
        "{} {}",
        "[nono]".truecolor(204, 102, 0),
        "Changes:".white().bold()
    );

    for change in changes {
        let symbol = match change.change_type {
            ChangeType::Created => "+".green(),
            ChangeType::Modified => "~".yellow(),
            ChangeType::Deleted => "-".red(),
            ChangeType::PermissionsChanged => "p".truecolor(150, 150, 150),
        };

        let label = match change.change_type {
            ChangeType::Created => "created",
            ChangeType::Modified => "modified",
            ChangeType::Deleted => "deleted",
            ChangeType::PermissionsChanged => "permissions",
        };

        let size_info = change
            .size_delta
            .map(|delta| {
                if delta > 0 {
                    format!(" (+{delta} bytes)")
                } else if delta < 0 {
                    format!(" ({delta} bytes)")
                } else {
                    String::new()
                }
            })
            .unwrap_or_default();

        eprintln!(
            "  {} {} ({}){}",
            symbol,
            change.path.display(),
            label.truecolor(150, 150, 150),
            size_info.truecolor(100, 100, 100)
        );
    }
    eprintln!();
}
