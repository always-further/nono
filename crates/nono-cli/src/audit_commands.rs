//! Audit subcommand implementations
//!
//! Handles `nono audit list|show` for viewing the audit trail of sandboxed sessions.

use crate::cli::{AuditArgs, AuditCommands, AuditListArgs, AuditShowArgs};
use crate::rollback_session::{discover_sessions, load_session, SessionInfo};
use colored::Colorize;
use nono::undo::SnapshotManager;
use nono::{NonoError, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Prefix used for all audit command output
fn prefix() -> colored::ColoredString {
    "[nono]".truecolor(204, 102, 0)
}

/// Dispatch to the appropriate audit subcommand.
pub fn run_audit(args: AuditArgs) -> Result<()> {
    match args.command {
        AuditCommands::List(args) => cmd_list(args),
        AuditCommands::Show(args) => cmd_show(args),
    }
}

// ---------------------------------------------------------------------------
// nono audit list
// ---------------------------------------------------------------------------

fn cmd_list(args: AuditListArgs) -> Result<()> {
    let mut sessions = discover_sessions()?;

    // Apply filters
    sessions = filter_sessions(sessions, &args)?;

    if let Some(n) = args.recent {
        sessions.truncate(n);
    }

    if args.json {
        return print_list_json(&sessions);
    }

    if sessions.is_empty() {
        eprintln!("{} No sessions found matching filters.", prefix());
        return Ok(());
    }

    // Group sessions by their primary tracked path (project directory)
    let grouped = group_by_project(&sessions);
    eprintln!("{} {} session(s)\n", prefix(), sessions.len());

    for (project_path, group) in &grouped {
        let display_path = shorten_home(project_path);
        eprintln!(
            "  {} ({} session{})",
            display_path.white().bold(),
            group.len(),
            if group.len() == 1 { "" } else { "s" },
        );
        for s in group {
            let cmd = truncate_command(&s.metadata.command, 35);
            let status = session_status_label(s);
            eprintln!(
                "    {} {} {}",
                s.metadata.session_id,
                status,
                cmd.truecolor(150, 150, 150),
            );
        }
        eprintln!();
    }

    Ok(())
}

fn filter_sessions(
    mut sessions: Vec<SessionInfo>,
    args: &AuditListArgs,
) -> Result<Vec<SessionInfo>> {
    // Filter by --today
    if args.today {
        let today_start = today_start_epoch()?;
        sessions.retain(|s| {
            parse_session_start_time(s)
                .map(|t| t >= today_start)
                .unwrap_or(false)
        });
    }

    // Filter by --since
    if let Some(ref since) = args.since {
        let since_epoch = parse_date_to_epoch(since)?;
        sessions.retain(|s| {
            parse_session_start_time(s)
                .map(|t| t >= since_epoch)
                .unwrap_or(false)
        });
    }

    // Filter by --until
    if let Some(ref until) = args.until {
        let until_epoch = parse_date_to_epoch(until)?.saturating_add(86400); // End of day
        sessions.retain(|s| {
            parse_session_start_time(s)
                .map(|t| t < until_epoch)
                .unwrap_or(false)
        });
    }

    // Filter by --command
    if let Some(ref cmd_filter) = args.command {
        let filter_lower = cmd_filter.to_lowercase();
        sessions.retain(|s| {
            s.metadata
                .command
                .first()
                .map(|c| c.to_lowercase().contains(&filter_lower))
                .unwrap_or(false)
        });
    }

    // Filter by --path
    if let Some(ref path_filter) = args.path {
        sessions.retain(|s| {
            s.metadata
                .tracked_paths
                .iter()
                .any(|p| p.starts_with(path_filter) || path_filter.starts_with(p))
        });
    }

    Ok(sessions)
}

fn parse_session_start_time(s: &SessionInfo) -> Option<u64> {
    // Try parsing as ISO timestamp first, then as epoch seconds
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&s.metadata.started) {
        return Some(dt.timestamp() as u64);
    }
    s.metadata.started.parse::<u64>().ok()
}

fn today_start_epoch() -> Result<u64> {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| NonoError::Snapshot(format!("System time error: {e}")))?
        .as_secs();
    // Round down to start of day (UTC)
    Ok(now - (now % 86400))
}

fn parse_date_to_epoch(date_str: &str) -> Result<u64> {
    // Parse YYYY-MM-DD format
    let dt = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d")
        .map_err(|e| NonoError::Snapshot(format!("Invalid date format '{}': {}", date_str, e)))?;
    Ok(dt
        .and_hms_opt(0, 0, 0)
        .ok_or_else(|| NonoError::Snapshot("Invalid time".to_string()))?
        .and_utc()
        .timestamp() as u64)
}

fn print_list_json(sessions: &[SessionInfo]) -> Result<()> {
    let entries: Vec<serde_json::Value> = sessions
        .iter()
        .map(|s| {
            serde_json::json!({
                "session_id": s.metadata.session_id,
                "started": s.metadata.started,
                "ended": s.metadata.ended,
                "command": s.metadata.command,
                "tracked_paths": s.metadata.tracked_paths,
                "snapshot_count": s.metadata.snapshot_count,
                "exit_code": s.metadata.exit_code,
                "disk_size": s.disk_size,
                "is_alive": s.is_alive,
                "is_stale": s.is_stale,
            })
        })
        .collect();

    let json = serde_json::to_string_pretty(&entries)
        .map_err(|e| NonoError::Snapshot(format!("JSON serialization failed: {e}")))?;
    println!("{json}");
    Ok(())
}

// ---------------------------------------------------------------------------
// nono audit show
// ---------------------------------------------------------------------------

fn cmd_show(args: AuditShowArgs) -> Result<()> {
    let session = load_session(&args.session_id)?;

    if args.json {
        return print_show_json(&session);
    }

    let status = session_status_label(&session);
    eprintln!(
        "{} Audit trail for session: {} {}",
        prefix(),
        session.metadata.session_id.white().bold(),
        status
    );
    eprintln!(
        "  Command:  {}",
        session.metadata.command.join(" ").truecolor(150, 150, 150)
    );
    eprintln!("  Started:  {}", session.metadata.started);
    if let Some(ref ended) = session.metadata.ended {
        eprintln!("  Ended:    {ended}");
    }
    if let Some(code) = session.metadata.exit_code {
        eprintln!("  Exit:     {code}");
    }

    let paths: Vec<String> = session
        .metadata
        .tracked_paths
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    eprintln!("  Paths:    {}", paths.join(", "));
    eprintln!();

    // Show snapshot details
    for i in 0..session.metadata.snapshot_count {
        let manifest = match SnapshotManager::load_manifest_from(&session.dir, i) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if i == 0 {
            eprintln!(
                "  [{}] Baseline at {}  ({} files, root: {})",
                format!("{i:03}").white().bold(),
                manifest.timestamp,
                manifest.files.len(),
                &manifest.merkle_root.to_string()[..16],
            );
        } else {
            let changes = SnapshotManager::load_changes_from(&session.dir, i).unwrap_or_default();
            eprintln!(
                "  [{}] Snapshot at {}  (root: {})",
                format!("{i:03}").white().bold(),
                manifest.timestamp,
                &manifest.merkle_root.to_string()[..16],
            );

            for change in &changes {
                let symbol = change_symbol(&change.change_type);
                eprintln!("        {} {}", symbol, change.path.display());
            }
        }
    }

    Ok(())
}

fn print_show_json(session: &SessionInfo) -> Result<()> {
    let mut snapshots = Vec::new();
    for i in 0..session.metadata.snapshot_count {
        let manifest = match SnapshotManager::load_manifest_from(&session.dir, i) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let changes = SnapshotManager::load_changes_from(&session.dir, i).unwrap_or_default();

        snapshots.push(serde_json::json!({
            "number": manifest.number,
            "timestamp": manifest.timestamp,
            "file_count": manifest.files.len(),
            "merkle_root": manifest.merkle_root.to_string(),
            "changes": changes.iter().map(|c| serde_json::json!({
                "path": c.path.display().to_string(),
                "type": format!("{}", c.change_type),
                "size_delta": c.size_delta,
                "old_hash": c.old_hash.map(|h| h.to_string()),
                "new_hash": c.new_hash.map(|h| h.to_string()),
            })).collect::<Vec<_>>(),
        }));
    }

    let output = serde_json::json!({
        "session_id": session.metadata.session_id,
        "started": session.metadata.started,
        "ended": session.metadata.ended,
        "command": session.metadata.command,
        "tracked_paths": session.metadata.tracked_paths,
        "exit_code": session.metadata.exit_code,
        "merkle_roots": session.metadata.merkle_roots.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
        "snapshots": snapshots,
    });

    let json = serde_json::to_string_pretty(&output)
        .map_err(|e| NonoError::Snapshot(format!("JSON serialization failed: {e}")))?;
    println!("{json}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn session_status_label(s: &SessionInfo) -> colored::ColoredString {
    if s.is_alive {
        "running".green()
    } else if s.is_stale {
        "orphaned".yellow()
    } else {
        "completed".truecolor(150, 150, 150)
    }
}

fn group_by_project(sessions: &[SessionInfo]) -> BTreeMap<PathBuf, Vec<&SessionInfo>> {
    let mut groups: BTreeMap<PathBuf, Vec<&SessionInfo>> = BTreeMap::new();
    for s in sessions {
        let project = s
            .metadata
            .tracked_paths
            .first()
            .cloned()
            .unwrap_or_else(|| PathBuf::from("(unknown)"));
        groups.entry(project).or_default().push(s);
    }
    groups
}

fn shorten_home(path: &Path) -> String {
    let s = path.display().to_string();
    if let Some(home) = dirs::home_dir() {
        let home_str = home.display().to_string();
        if let Some(rest) = s.strip_prefix(&home_str) {
            return format!("~{rest}");
        }
    }
    s
}

fn truncate_command(cmd: &[String], max_len: usize) -> String {
    let full = cmd.join(" ");
    if full.len() <= max_len {
        full
    } else {
        format!("{}...", &full[..max_len.saturating_sub(3)])
    }
}

fn change_symbol(ct: &nono::undo::ChangeType) -> colored::ColoredString {
    match ct {
        nono::undo::ChangeType::Created => "+".green(),
        nono::undo::ChangeType::Modified => "~".yellow(),
        nono::undo::ChangeType::Deleted => "-".red(),
        nono::undo::ChangeType::PermissionsChanged => "p".truecolor(150, 150, 150),
    }
}
