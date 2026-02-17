//! Undo subcommand implementations
//!
//! Handles `nono undo list|show|restore|verify|cleanup`.

use crate::cli::{
    UndoArgs, UndoCleanupArgs, UndoCommands, UndoListArgs, UndoRestoreArgs, UndoShowArgs,
    UndoVerifyArgs,
};
use crate::config::user::load_user_config;
use crate::undo_base_exclusions;
use crate::undo_session::{
    discover_sessions, format_bytes, load_session, remove_session, undo_root, SessionInfo,
};
use colored::Colorize;
use nono::undo::{MerkleTree, ObjectStore, SnapshotManager};
use nono::{NonoError, Result};

/// Prefix used for all undo command output
fn prefix() -> colored::ColoredString {
    "[nono]".truecolor(204, 102, 0)
}

/// Dispatch to the appropriate undo subcommand.
pub fn run_undo(args: UndoArgs) -> Result<()> {
    match args.command {
        UndoCommands::List(args) => cmd_list(args),
        UndoCommands::Show(args) => cmd_show(args),
        UndoCommands::Restore(args) => cmd_restore(args),
        UndoCommands::Verify(args) => cmd_verify(args),
        UndoCommands::Cleanup(args) => cmd_cleanup(args),
    }
}

// ---------------------------------------------------------------------------
// nono undo list
// ---------------------------------------------------------------------------

fn cmd_list(args: UndoListArgs) -> Result<()> {
    let mut sessions = discover_sessions()?;

    if let Some(n) = args.recent {
        sessions.truncate(n);
    }

    // Compute change summary for each session
    let sessions_with_changes: Vec<_> = sessions
        .iter()
        .map(|s| {
            let changes = get_session_total_changes(s);
            (s, changes)
        })
        .collect();

    // Filter to only sessions with actual changes (unless --all)
    let filtered: Vec<_> = if args.all {
        sessions_with_changes
    } else {
        sessions_with_changes
            .into_iter()
            .filter(|(_, (c, m, d))| *c > 0 || *m > 0 || *d > 0)
            .collect()
    };

    if args.json {
        return print_sessions_json(&filtered.iter().map(|(s, _)| *s).collect::<Vec<_>>());
    }

    if filtered.is_empty() {
        if args.all {
            eprintln!("{} No undo sessions found.", prefix());
        } else {
            eprintln!(
                "{} No sessions with file changes. Use --all to see all sessions.",
                prefix()
            );
        }
        return Ok(());
    }

    eprintln!("{} {} session(s)\n", prefix(), filtered.len());

    for (s, (created, modified, deleted)) in &filtered {
        // Show just the first command (program name), not args
        let cmd_name = s
            .metadata
            .command
            .first()
            .map(|c| {
                // Extract just the program name from path
                std::path::Path::new(c)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| c.clone())
            })
            .unwrap_or_else(|| "(unknown)".to_string());
        let change_summary = format_change_summary(*created, *modified, *deleted);

        eprintln!(
            "  {}  {}  {}",
            s.metadata.session_id.white().bold(),
            cmd_name.truecolor(150, 150, 150),
            change_summary,
        );
    }

    Ok(())
}

/// Get total changes across all snapshots in a session
fn get_session_total_changes(s: &SessionInfo) -> (usize, usize, usize) {
    let mut total_created = 0usize;
    let mut total_modified = 0usize;
    let mut total_deleted = 0usize;

    for i in 1..s.metadata.snapshot_count {
        let changes = SnapshotManager::load_changes_from(&s.dir, i).unwrap_or_default();
        let (c, m, d) = count_change_types(&changes);
        total_created = total_created.saturating_add(c);
        total_modified = total_modified.saturating_add(m);
        total_deleted = total_deleted.saturating_add(d);
    }

    (total_created, total_modified, total_deleted)
}

/// Truncate command for display, adding ... if too long
/// Format change summary for display
fn format_change_summary(created: usize, modified: usize, deleted: usize) -> String {
    let mut parts = Vec::new();

    if created > 0 {
        let suffix = if created == 1 { "file" } else { "files" };
        parts.push(format!("+{created} {suffix}"));
    }
    if modified > 0 {
        parts.push(format!("~{modified} modified"));
    }
    if deleted > 0 {
        parts.push(format!("-{deleted} deleted"));
    }

    if parts.is_empty() {
        "(no changes)".to_string()
    } else {
        parts.join(", ")
    }
}

fn print_sessions_json(sessions: &[&SessionInfo]) -> Result<()> {
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
// nono undo show
// ---------------------------------------------------------------------------

fn cmd_show(args: UndoShowArgs) -> Result<()> {
    let session = load_session(&args.session_id)?;

    if args.json {
        return print_show_json(&session);
    }

    // Collect all changes from all snapshots
    let mut all_changes = Vec::new();
    for i in 1..session.metadata.snapshot_count {
        let changes = SnapshotManager::load_changes_from(&session.dir, i).unwrap_or_default();
        all_changes.extend(changes);
    }

    if all_changes.is_empty() {
        eprintln!(
            "{} Session {} has no file changes.",
            prefix(),
            args.session_id
        );
        return Ok(());
    }

    let object_store = ObjectStore::new(session.dir.clone())?;

    eprintln!(
        "{} Session {} ({})\n",
        prefix(),
        session.metadata.session_id.white().bold(),
        session.metadata.command.join(" ").truecolor(150, 150, 150)
    );

    if args.diff {
        print_unified_diff(&all_changes, &object_store)?;
    } else if args.side_by_side {
        print_side_by_side_diff(&all_changes, &object_store)?;
    } else if args.full {
        print_full_content(&all_changes, &object_store)?;
    } else {
        // Default: summary with line counts
        print_change_summary(&all_changes, &object_store)?;
    }

    Ok(())
}

/// Print summary of changes with line counts
fn print_change_summary(changes: &[nono::undo::Change], object_store: &ObjectStore) -> Result<()> {
    use nono::undo::ChangeType;

    for change in changes {
        let symbol = change_symbol(&change.change_type);
        let filename = change
            .path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| change.path.display().to_string());

        let line_info = match change.change_type {
            ChangeType::Created => {
                if let Some(hash) = &change.new_hash {
                    let content = object_store.retrieve(hash).unwrap_or_default();
                    let lines = count_lines(&content);
                    format!("(+{lines} lines)")
                } else {
                    String::new()
                }
            }
            ChangeType::Deleted => {
                if let Some(hash) = &change.old_hash {
                    let content = object_store.retrieve(hash).unwrap_or_default();
                    let lines = count_lines(&content);
                    format!("(-{lines} lines)")
                } else {
                    String::new()
                }
            }
            ChangeType::Modified => {
                let old_lines = change
                    .old_hash
                    .as_ref()
                    .and_then(|h| object_store.retrieve(h).ok())
                    .map(|c| count_lines(&c))
                    .unwrap_or(0);
                let new_lines = change
                    .new_hash
                    .as_ref()
                    .and_then(|h| object_store.retrieve(h).ok())
                    .map(|c| count_lines(&c))
                    .unwrap_or(0);
                let diff = new_lines as i64 - old_lines as i64;
                if diff >= 0 {
                    format!("(+{diff} lines)")
                } else {
                    format!("({diff} lines)")
                }
            }
            ChangeType::PermissionsChanged => "(permissions)".to_string(),
        };

        eprintln!(
            "  {} {:<40} {}",
            symbol,
            filename,
            line_info.truecolor(100, 100, 100)
        );
    }

    Ok(())
}

/// Print unified diff (git diff style)
fn print_unified_diff(changes: &[nono::undo::Change], object_store: &ObjectStore) -> Result<()> {
    use nono::undo::ChangeType;
    use similar::{ChangeTag, TextDiff};

    for change in changes {
        let path_str = change.path.display().to_string();

        let old_content = change
            .old_hash
            .as_ref()
            .and_then(|h| object_store.retrieve(h).ok())
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_default();

        let new_content = change
            .new_hash
            .as_ref()
            .and_then(|h| object_store.retrieve(h).ok())
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_default();

        let old_path = match change.change_type {
            ChangeType::Created => "/dev/null".to_string(),
            _ => format!("a/{}", path_str),
        };
        let new_path = match change.change_type {
            ChangeType::Deleted => "/dev/null".to_string(),
            _ => format!("b/{}", path_str),
        };

        eprintln!("{}", format!("--- {old_path}").red());
        eprintln!("{}", format!("+++ {new_path}").green());

        let diff = TextDiff::from_lines(&old_content, &new_content);
        for hunk in diff.unified_diff().context_radius(3).iter_hunks() {
            eprintln!("{}", format!("{hunk}").cyan());
            for change_op in hunk.iter_changes() {
                match change_op.tag() {
                    ChangeTag::Delete => eprint!("{}", format!("-{}", change_op).red()),
                    ChangeTag::Insert => eprint!("{}", format!("+{}", change_op).green()),
                    ChangeTag::Equal => eprint!(" {}", change_op),
                }
            }
        }
        eprintln!();
    }

    Ok(())
}

/// Print side-by-side diff
fn print_side_by_side_diff(
    changes: &[nono::undo::Change],
    object_store: &ObjectStore,
) -> Result<()> {
    use similar::{ChangeTag, TextDiff};

    let term_width = 120usize; // reasonable default
    let col_width = term_width.saturating_sub(3) / 2;

    for change in changes {
        eprintln!(
            "{}",
            format!("=== {} ===", change.path.display()).white().bold()
        );

        let old_content = change
            .old_hash
            .as_ref()
            .and_then(|h| object_store.retrieve(h).ok())
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_default();

        let new_content = change
            .new_hash
            .as_ref()
            .and_then(|h| object_store.retrieve(h).ok())
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_default();

        let diff = TextDiff::from_lines(&old_content, &new_content);

        for change_op in diff.iter_all_changes() {
            let line = change_op.to_string_lossy();
            let line_trimmed = line.trim_end();

            match change_op.tag() {
                ChangeTag::Equal => {
                    let truncated = truncate_str(line_trimmed, col_width);
                    eprintln!(
                        "{:<width$} | {:<width$}",
                        truncated,
                        truncated,
                        width = col_width
                    );
                }
                ChangeTag::Delete => {
                    let truncated = truncate_str(line_trimmed, col_width);
                    eprintln!("{} < {:<width$}", truncated.red(), "", width = col_width);
                }
                ChangeTag::Insert => {
                    let truncated = truncate_str(line_trimmed, col_width);
                    eprintln!("{:<width$} > {}", "", truncated.green(), width = col_width);
                }
            }
        }
        eprintln!();
    }

    Ok(())
}

/// Print full file content from snapshot
fn print_full_content(changes: &[nono::undo::Change], object_store: &ObjectStore) -> Result<()> {
    use nono::undo::ChangeType;

    for change in changes {
        let symbol = change_symbol(&change.change_type);
        eprintln!(
            "{} {} {}",
            symbol,
            change.path.display().to_string().white().bold(),
            format!("({})", change.change_type).truecolor(100, 100, 100)
        );

        let content_hash = match change.change_type {
            ChangeType::Deleted => change.old_hash.as_ref(),
            _ => change.new_hash.as_ref(),
        };

        if let Some(hash) = content_hash {
            if let Ok(content) = object_store.retrieve(hash) {
                if let Ok(text) = String::from_utf8(content) {
                    for (i, line) in text.lines().enumerate() {
                        eprintln!(
                            "  {} {}",
                            format!("{:4}", i + 1).truecolor(100, 100, 100),
                            line
                        );
                    }
                } else {
                    eprintln!("  (binary file)");
                }
            }
        }
        eprintln!();
    }

    Ok(())
}

fn count_lines(content: &[u8]) -> usize {
    content
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        .saturating_add(1)
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
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
            "parent": manifest.parent,
            "file_count": manifest.files.len(),
            "merkle_root": manifest.merkle_root.to_string(),
            "changes": changes.iter().map(|c| serde_json::json!({
                "path": c.path.display().to_string(),
                "type": format!("{}", c.change_type),
                "size_delta": c.size_delta,
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
        "disk_size": session.disk_size,
        "is_alive": session.is_alive,
        "is_stale": session.is_stale,
        "snapshots": snapshots,
    });

    let json = serde_json::to_string_pretty(&output)
        .map_err(|e| NonoError::Snapshot(format!("JSON serialization failed: {e}")))?;
    println!("{json}");
    Ok(())
}

// ---------------------------------------------------------------------------
// nono undo restore
// ---------------------------------------------------------------------------

fn cmd_restore(args: UndoRestoreArgs) -> Result<()> {
    let session = load_session(&args.session_id)?;

    // Default to the last snapshot (final state), not baseline
    let snapshot = args
        .snapshot
        .unwrap_or_else(|| session.metadata.snapshot_count.saturating_sub(1));

    if snapshot >= session.metadata.snapshot_count {
        return Err(NonoError::Snapshot(format!(
            "Snapshot {} does not exist (session has {} snapshots)",
            snapshot, session.metadata.snapshot_count
        )));
    }

    let manifest = SnapshotManager::load_manifest_from(&session.dir, snapshot)?;

    // Restore must use the same exclusions as snapshot creation so that
    // walk_current() does not see VCS internals and try to delete them
    let exclusion_config = nono::undo::ExclusionConfig {
        use_gitignore: false,
        exclude_patterns: undo_base_exclusions(),
        exclude_globs: Vec::new(),
        force_include: Vec::new(),
    };

    // Use the first tracked path as the root for the exclusion filter
    let filter_root = session
        .metadata
        .tracked_paths
        .first()
        .cloned()
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    let exclusion = nono::undo::ExclusionFilter::new(exclusion_config, &filter_root)?;
    let manager = SnapshotManager::new(
        session.dir.clone(),
        session.metadata.tracked_paths.clone(),
        exclusion,
    )?;

    if args.dry_run {
        let diff = manager.compute_restore_diff(&manifest)?;
        if diff.is_empty() {
            eprintln!("{} No changes needed (already matches snapshot).", prefix());
            return Ok(());
        }

        eprintln!(
            "{} Dry run: restoring to snapshot {} would apply {} change(s):\n",
            prefix(),
            snapshot,
            diff.len()
        );
        print_changes(&diff);
        return Ok(());
    }

    let applied = manager.restore_to(&manifest)?;

    if applied.is_empty() {
        eprintln!("{} No changes needed (already matches snapshot).", prefix());
    } else {
        eprintln!(
            "{} Restored {} file(s) to snapshot {}.",
            prefix(),
            applied.len(),
            snapshot
        );
        print_changes(&applied);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// nono undo verify
// ---------------------------------------------------------------------------

fn cmd_verify(args: UndoVerifyArgs) -> Result<()> {
    let session = load_session(&args.session_id)?;
    let object_store = ObjectStore::new(session.dir.clone())?;

    eprintln!(
        "{} Verifying session: {}",
        prefix(),
        session.metadata.session_id.white().bold()
    );

    let mut all_passed = true;
    let mut objects_checked = 0u64;

    for i in 0..session.metadata.snapshot_count {
        let manifest = match SnapshotManager::load_manifest_from(&session.dir, i) {
            Ok(m) => m,
            Err(e) => {
                eprintln!(
                    "  [{}] {} Failed to load: {e}",
                    format!("{i:03}").white(),
                    "FAIL".red()
                );
                all_passed = false;
                continue;
            }
        };

        // Rebuild Merkle tree from file hashes and compare
        let rebuilt = MerkleTree::from_manifest(&manifest.files)?;
        let merkle_ok = *rebuilt.root() == manifest.merkle_root;

        if !merkle_ok {
            eprintln!(
                "  [{}] {} Merkle root mismatch (stored: {}, rebuilt: {})",
                format!("{i:03}").white(),
                "FAIL".red(),
                &manifest.merkle_root.to_string()[..16],
                &rebuilt.root().to_string()[..16],
            );
            all_passed = false;
            continue;
        }

        // Verify referenced objects in the store
        let mut snapshot_ok = true;
        for state in manifest.files.values() {
            match object_store.verify(&state.hash) {
                Ok(true) => {
                    objects_checked = objects_checked.saturating_add(1);
                }
                Ok(false) => {
                    snapshot_ok = false;
                    all_passed = false;
                }
                Err(_) => {
                    snapshot_ok = false;
                    all_passed = false;
                }
            }
        }

        let status = if snapshot_ok {
            "OK".green()
        } else {
            all_passed = false;
            "FAIL".red()
        };

        eprintln!(
            "  [{}] {} Merkle root matches, {} objects verified",
            format!("{i:03}").white(),
            status,
            manifest.files.len(),
        );
    }

    eprintln!();
    if all_passed {
        eprintln!(
            "{} {} All {} snapshot(s) verified, {} objects checked.",
            prefix(),
            "PASS".green().bold(),
            session.metadata.snapshot_count,
            objects_checked,
        );
    } else {
        eprintln!(
            "{} {} Some snapshots failed verification.",
            prefix(),
            "FAIL".red().bold(),
        );
        return Err(NonoError::Snapshot(
            "Session integrity verification failed".to_string(),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// nono undo cleanup
// ---------------------------------------------------------------------------

fn cmd_cleanup(args: UndoCleanupArgs) -> Result<()> {
    if args.all {
        return cleanup_all(args.dry_run);
    }

    let sessions = discover_sessions()?;
    if sessions.is_empty() {
        eprintln!("{} No undo sessions to clean up.", prefix());
        return Ok(());
    }

    let config = load_user_config()?.unwrap_or_default();
    let keep = args.keep.unwrap_or(config.undo.max_sessions);

    let mut to_remove: Vec<&SessionInfo> = Vec::new();

    // Filter by --older-than
    if let Some(days) = args.older_than {
        let cutoff_secs = days.saturating_mul(86400);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for s in &sessions {
            if let Some(started) = parse_session_start_time(s) {
                if now.saturating_sub(started) > cutoff_secs && !s.is_alive {
                    to_remove.push(s);
                }
            }
        }
    } else {
        // Default: remove orphaned sessions + enforce keep limit
        let orphan_grace_secs = config.undo.stale_grace_hours.saturating_mul(3600);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Orphaned sessions (process crashed/killed before clean exit)
        for s in &sessions {
            if s.is_stale {
                if let Some(started) = parse_session_start_time(s) {
                    if now.saturating_sub(started) > orphan_grace_secs {
                        to_remove.push(s);
                    }
                }
            }
        }

        // Excess sessions beyond keep limit (sessions already sorted newest-first)
        let completed: Vec<&SessionInfo> = sessions.iter().filter(|s| !s.is_alive).collect();

        if completed.len() > keep {
            for s in &completed[keep..] {
                if !to_remove
                    .iter()
                    .any(|r| r.metadata.session_id == s.metadata.session_id)
                {
                    to_remove.push(s);
                }
            }
        }
    }

    if to_remove.is_empty() {
        eprintln!("{} Nothing to clean up.", prefix());
        return Ok(());
    }

    let total_size: u64 = to_remove.iter().map(|s| s.disk_size).sum();

    if args.dry_run {
        eprintln!(
            "{} Dry run: would remove {} session(s) ({})\n",
            prefix(),
            to_remove.len(),
            format_bytes(total_size)
        );
        for s in &to_remove {
            eprintln!(
                "  {} {} ({})",
                s.metadata.session_id,
                s.metadata.command.join(" ").truecolor(150, 150, 150),
                format_bytes(s.disk_size).truecolor(150, 150, 150),
            );
        }
        return Ok(());
    }

    let mut removed = 0usize;
    for s in &to_remove {
        if let Err(e) = remove_session(&s.dir) {
            eprintln!(
                "{} Failed to remove {}: {e}",
                prefix(),
                s.metadata.session_id
            );
        } else {
            removed = removed.saturating_add(1);
        }
    }

    eprintln!(
        "{} Removed {} session(s), freed {}.",
        prefix(),
        removed,
        format_bytes(total_size)
    );

    Ok(())
}

fn cleanup_all(dry_run: bool) -> Result<()> {
    let root = undo_root()?;
    if !root.exists() {
        eprintln!("{} No undo directory found.", prefix());
        return Ok(());
    }

    let sessions = discover_sessions()?;
    let alive_count = sessions.iter().filter(|s| s.is_alive).count();

    if alive_count > 0 {
        eprintln!(
            "{} {} session(s) still running, skipping those.",
            prefix(),
            alive_count,
        );
    }

    let removable: Vec<&SessionInfo> = sessions.iter().filter(|s| !s.is_alive).collect();
    let total_size: u64 = removable.iter().map(|s| s.disk_size).sum();

    if removable.is_empty() {
        eprintln!("{} No sessions to remove.", prefix());
        return Ok(());
    }

    if dry_run {
        eprintln!(
            "{} Dry run: would remove {} session(s) ({})",
            prefix(),
            removable.len(),
            format_bytes(total_size)
        );
        return Ok(());
    }

    let mut removed = 0usize;
    for s in &removable {
        if let Err(e) = remove_session(&s.dir) {
            eprintln!(
                "{} Failed to remove {}: {e}",
                prefix(),
                s.metadata.session_id
            );
        } else {
            removed = removed.saturating_add(1);
        }
    }

    eprintln!(
        "{} Removed {} session(s), freed {}.",
        prefix(),
        removed,
        format_bytes(total_size)
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Parse session start time from either RFC3339 or epoch seconds format
fn parse_session_start_time(s: &SessionInfo) -> Option<u64> {
    // Try parsing as RFC3339 timestamp first, then as epoch seconds
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&s.metadata.started) {
        return Some(dt.timestamp() as u64);
    }
    s.metadata.started.parse::<u64>().ok()
}

fn count_change_types(changes: &[nono::undo::Change]) -> (usize, usize, usize) {
    let mut created = 0usize;
    let mut modified = 0usize;
    let mut deleted = 0usize;
    for c in changes {
        match c.change_type {
            nono::undo::ChangeType::Created => created = created.saturating_add(1),
            nono::undo::ChangeType::Modified => modified = modified.saturating_add(1),
            nono::undo::ChangeType::Deleted => deleted = deleted.saturating_add(1),
            nono::undo::ChangeType::PermissionsChanged => modified = modified.saturating_add(1),
        }
    }
    (created, modified, deleted)
}

fn change_symbol(ct: &nono::undo::ChangeType) -> colored::ColoredString {
    match ct {
        nono::undo::ChangeType::Created => "+".green(),
        nono::undo::ChangeType::Modified => "~".yellow(),
        nono::undo::ChangeType::Deleted => "-".red(),
        nono::undo::ChangeType::PermissionsChanged => "p".truecolor(150, 150, 150),
    }
}

fn print_changes(changes: &[nono::undo::Change]) {
    for change in changes {
        let symbol = change_symbol(&change.change_type);
        eprintln!("  {} {}", symbol, change.path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_change_types_empty() {
        let (c, m, d) = count_change_types(&[]);
        assert_eq!((c, m, d), (0, 0, 0));
    }

    #[test]
    fn count_change_types_mixed() {
        use nono::undo::{Change, ChangeType};
        use std::path::PathBuf;

        let changes = vec![
            Change {
                path: PathBuf::from("a.txt"),
                change_type: ChangeType::Created,
                size_delta: None,
                old_hash: None,
                new_hash: None,
            },
            Change {
                path: PathBuf::from("b.txt"),
                change_type: ChangeType::Modified,
                size_delta: None,
                old_hash: None,
                new_hash: None,
            },
            Change {
                path: PathBuf::from("c.txt"),
                change_type: ChangeType::Deleted,
                size_delta: None,
                old_hash: None,
                new_hash: None,
            },
            Change {
                path: PathBuf::from("d.txt"),
                change_type: ChangeType::PermissionsChanged,
                size_delta: None,
                old_hash: None,
                new_hash: None,
            },
        ];
        let (c, m, d) = count_change_types(&changes);
        assert_eq!(c, 1);
        assert_eq!(m, 2); // Modified + PermissionsChanged
        assert_eq!(d, 1);
    }
}
