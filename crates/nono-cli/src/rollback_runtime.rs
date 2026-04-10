use crate::launch_runtime::{rollback_base_exclusions, RollbackLaunchOptions};
use crate::{config, output, rollback_preflight, rollback_session, rollback_ui};
use nono::undo::RollbackStatus;
use nono::{AccessMode, CapabilitySet, NonoError, Result};
use std::collections::HashSet;
use std::path::PathBuf;
use tracing::warn;

pub(crate) struct AuditState {
    pub(crate) session_id: String,
    pub(crate) session_dir: PathBuf,
}

pub(crate) type RollbackRuntimeState = (
    nono::undo::SnapshotManager,
    nono::undo::SnapshotManifest,
    Vec<PathBuf>,
    HashSet<PathBuf>,
);

pub(crate) struct RollbackExitContext<'a> {
    pub(crate) audit_state: Option<&'a AuditState>,
    pub(crate) rollback_state: Option<RollbackRuntimeState>,
    /// The rollback status recorded at session start (from `initialize_rollback_state`).
    pub(crate) rollback_status: RollbackStatus,
    pub(crate) proxy_handle: Option<&'a nono_proxy::server::ProxyHandle>,
    pub(crate) started: &'a str,
    pub(crate) ended: &'a str,
    pub(crate) command: &'a [String],
    pub(crate) exit_code: i32,
    pub(crate) silent: bool,
    pub(crate) rollback_prompt_disabled: bool,
}

fn rollback_vcs_exclusions() -> Vec<String> {
    [".git", ".hg", ".svn"]
        .iter()
        .map(|entry| String::from(*entry))
        .collect()
}

fn enforce_rollback_limits(silent: bool) {
    let config = match config::user::load_user_config() {
        Ok(Some(config)) => config,
        Ok(None) => config::user::UserConfig::default(),
        Err(e) => {
            tracing::warn!("Failed to load user config for rollback limits: {e}");
            return;
        }
    };

    let sessions = match rollback_session::discover_sessions() {
        Ok(sessions) => sessions,
        Err(e) => {
            tracing::warn!("Failed to discover sessions for limit enforcement: {e}");
            return;
        }
    };

    if sessions.is_empty() {
        return;
    }

    let max_sessions = config.rollback.max_sessions;
    let storage_bytes_f64 =
        (config.rollback.max_storage_gb.max(0.0) * 1024.0 * 1024.0 * 1024.0).min(u64::MAX as f64);
    let max_storage_bytes = storage_bytes_f64 as u64;

    let completed: Vec<&rollback_session::SessionInfo> = sessions
        .iter()
        .filter(|session| !session.is_alive)
        .collect();

    let mut pruned = 0usize;
    let mut pruned_bytes = 0u64;

    if completed.len() > max_sessions {
        for session in &completed[max_sessions..] {
            if let Err(e) = rollback_session::remove_session(&session.dir) {
                tracing::warn!(
                    "Failed to prune session {}: {e}",
                    session.metadata.session_id
                );
            } else {
                pruned = pruned.saturating_add(1);
                pruned_bytes = pruned_bytes.saturating_add(session.disk_size);
            }
        }
    }

    let total = match rollback_session::total_storage_bytes() {
        Ok(total) => total,
        Err(_) => return,
    };

    if total > max_storage_bytes {
        let remaining = match rollback_session::discover_sessions() {
            Ok(sessions) => sessions,
            Err(_) => return,
        };

        let mut current_total = total;
        for session in remaining.iter().rev().filter(|session| !session.is_alive) {
            if current_total <= max_storage_bytes {
                break;
            }
            if let Err(e) = rollback_session::remove_session(&session.dir) {
                tracing::warn!(
                    "Failed to prune session {}: {e}",
                    session.metadata.session_id
                );
            } else {
                current_total = current_total.saturating_sub(session.disk_size);
                pruned = pruned.saturating_add(1);
                pruned_bytes = pruned_bytes.saturating_add(session.disk_size);
            }
        }
    }

    if pruned > 0 && !silent {
        eprintln!(
            "  Auto-pruned {} old session(s) (freed {})",
            pruned,
            rollback_session::format_bytes(pruned_bytes),
        );
    }
}

pub(crate) fn create_audit_state(
    rollback_requested: bool,
    rollback_disabled: bool,
    audit_disabled: bool,
    rollback_destination: Option<&PathBuf>,
) -> Result<Option<AuditState>> {
    if !rollback_requested || rollback_disabled || audit_disabled {
        return Ok(None);
    }

    let session_id = format!(
        "{}-{}",
        chrono::Local::now().format("%Y%m%d-%H%M%S"),
        std::process::id()
    );

    let rollback_root = match rollback_destination {
        Some(path) => path.clone(),
        None => {
            let home = dirs::home_dir().ok_or(nono::NonoError::HomeNotFound)?;
            home.join(".nono").join("rollbacks")
        }
    };
    let session_dir = rollback_root.join(&session_id);
    std::fs::create_dir_all(&session_dir).map_err(|e| {
        nono::NonoError::Snapshot(format!(
            "Failed to create session directory {}: {}",
            session_dir.display(),
            e
        ))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        if let Err(e) = std::fs::set_permissions(&session_dir, perms) {
            warn!("Failed to set session directory permissions to 0700: {e}");
        }
    }

    Ok(Some(AuditState {
        session_id,
        session_dir,
    }))
}

pub(crate) fn warn_if_rollback_flags_ignored(rollback: &RollbackLaunchOptions, silent: bool) {
    if !rollback.disabled {
        return;
    }

    let has_rollback_flags = rollback.track_all
        || !rollback.include.is_empty()
        || !rollback.exclude_patterns.is_empty()
        || !rollback.exclude_globs.is_empty();
    if has_rollback_flags {
        warn!(
            "--no-rollback is active; rollback flags \
             (--rollback-all, --rollback-include, --rollback-exclude) \
             have no effect"
        );
        if !silent {
            eprintln!(
                "  [nono] Warning: --no-rollback is active; \
                 rollback customization flags have no effect."
            );
        }
    }
}

/// Initialize rollback state for a supervised session.
///
/// Returns `Ok((Some(state), RollbackStatus::Available))` on success, or
/// `Ok((None, RollbackStatus::Skipped | RollbackStatus::FailedWarningOnly))` with a
/// warning emitted to stderr if baseline snapshot capture fails (D-04: failure-warning-only).
/// Callers must record the returned `RollbackStatus` in `SessionMetadata`.
///
/// # Decision alignment
///
/// - D-01: Uses the existing Merkle-tree rollback engine.
/// - D-02: Snapshots all granted write-capable paths for the session scope.
/// - D-03: Soft-limit warnings remain visible and do not turn fatal.
/// - D-04: Snapshot initialization failures warn and execution continues.
pub(crate) fn initialize_rollback_state(
    rollback: &RollbackLaunchOptions,
    caps: &CapabilitySet,
    audit_state: Option<&AuditState>,
    silent: bool,
) -> Result<(Option<RollbackRuntimeState>, RollbackStatus)> {
    if !rollback.requested || rollback.disabled {
        return Ok((None, RollbackStatus::Skipped));
    }

    enforce_rollback_limits(silent);

    let Some(audit_state) = audit_state else {
        return Ok((None, RollbackStatus::Skipped));
    };

    let tracked_paths: Vec<PathBuf> = caps
        .fs_capabilities()
        .iter()
        .filter(|cap| {
            !cap.is_file
                && matches!(cap.access, AccessMode::Write | AccessMode::ReadWrite)
                && matches!(cap.source, nono::CapabilitySource::User)
        })
        .map(|cap| cap.resolved.clone())
        .collect();

    if tracked_paths.is_empty() {
        return Ok((None, RollbackStatus::Skipped));
    }

    let mut patterns = if rollback.track_all {
        rollback_vcs_exclusions()
    } else {
        rollback_base_exclusions()
    };
    patterns.extend(rollback.exclude_patterns.iter().cloned());
    patterns.sort_unstable();
    patterns.dedup();
    let base_patterns = patterns.clone();
    let exclusion_config = nono::undo::ExclusionConfig {
        use_gitignore: true,
        exclude_patterns: patterns,
        exclude_globs: rollback.exclude_globs.clone(),
        force_include: rollback.include.clone(),
    };
    let gitignore_root = tracked_paths
        .first()
        .cloned()
        .unwrap_or_else(|| PathBuf::from("."));
    let mut exclusion = match nono::undo::ExclusionFilter::new(exclusion_config, &gitignore_root) {
        Ok(e) => e,
        Err(e) => {
            let reason = format!("exclusion filter init failed: {e}");
            warn!("Rollback unavailable: {reason}");
            if !silent {
                eprintln!(
                    "  [nono] Warning: rollback unavailable for this session ({reason}). \
                     Execution will continue without snapshot capability."
                );
            }
            return Ok((None, RollbackStatus::FailedWarningOnly { reason }));
        }
    };

    if !rollback.track_all {
        let preflight_result =
            rollback_preflight::run_preflight(&tracked_paths, &exclusion, &rollback.skip_dirs);

        if preflight_result.needs_warning() {
            let auto_excluded: Vec<&rollback_preflight::HeavyDir> = preflight_result
                .heavy_dirs
                .iter()
                .filter(|dir| !rollback.include.contains(&dir.name))
                .collect();

            if !auto_excluded.is_empty() {
                let excluded_names: Vec<String> =
                    auto_excluded.iter().map(|dir| dir.name.clone()).collect();
                let mut all_patterns = base_patterns.clone();
                all_patterns.extend(excluded_names);
                all_patterns.sort_unstable();
                all_patterns.dedup();
                let updated_config = nono::undo::ExclusionConfig {
                    use_gitignore: true,
                    exclude_patterns: all_patterns,
                    exclude_globs: rollback.exclude_globs.clone(),
                    force_include: rollback.include.clone(),
                };
                exclusion = match nono::undo::ExclusionFilter::new(updated_config, &gitignore_root)
                {
                    Ok(e) => e,
                    Err(e) => {
                        let reason = format!("exclusion filter update failed: {e}");
                        warn!("Rollback unavailable: {reason}");
                        if !silent {
                            eprintln!(
                                "  [nono] Warning: rollback unavailable for this session ({reason}). \
                                 Execution will continue without snapshot capability."
                            );
                        }
                        return Ok((None, RollbackStatus::FailedWarningOnly { reason }));
                    }
                };

                if !silent {
                    rollback_preflight::print_auto_exclude_notice(
                        &auto_excluded,
                        &preflight_result,
                    );
                }
            }
        }
    }

    // D-04: snapshot manager init failure → warning-only, execution continues.
    let mut manager = match nono::undo::SnapshotManager::new(
        audit_state.session_dir.clone(),
        tracked_paths.clone(),
        exclusion,
        nono::undo::WalkBudget::default(),
    ) {
        Ok(m) => m,
        Err(e) => {
            let reason = format!("snapshot manager init failed: {e}");
            warn!("Rollback unavailable: {reason}");
            if !silent {
                eprintln!(
                    "  [nono] Warning: rollback unavailable for this session ({reason}). \
                     Execution will continue without snapshot capability."
                );
            }
            return Ok((None, RollbackStatus::FailedWarningOnly { reason }));
        }
    };

    // D-04: baseline capture failure → warning-only, execution continues.
    match manager.create_baseline() {
        Ok(baseline) => {
            let atomic_temp_before = manager.collect_atomic_temp_files();
            output::print_rollback_tracking(&tracked_paths, silent);
            Ok((
                Some((manager, baseline, tracked_paths, atomic_temp_before)),
                RollbackStatus::Available,
            ))
        }
        Err(e) => {
            let reason = format!("{e}");
            warn!("Rollback baseline capture failed: {reason}. Continuing without rollback.");
            if !silent {
                eprintln!(
                    "  [nono] Warning: rollback baseline capture failed ({reason}). \
                     Execution will continue; rollback will not be available for this session."
                );
            }
            Ok((None, RollbackStatus::FailedWarningOnly { reason }))
        }
    }
}

/// Error variant carrying partial restore results.
///
/// Used to surface which files could not be restored (e.g., locked on Windows)
/// without claiming full rollback success.
#[derive(Debug)]
pub(crate) struct PartialRestoreError {
    /// Changes that were applied successfully.
    pub applied: Vec<nono::undo::Change>,
    /// Per-file errors (path → error message).
    pub failures: Vec<(PathBuf, String)>,
}

impl std::fmt::Display for PartialRestoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "partial rollback: {} file(s) applied, {} file(s) failed",
            self.applied.len(),
            self.failures.len()
        )?;
        for (path, reason) in &self.failures {
            write!(f, "\n  {} — {}", path.display(), reason)?;
        }
        Ok(())
    }
}

impl std::error::Error for PartialRestoreError {}

impl From<PartialRestoreError> for NonoError {
    fn from(e: PartialRestoreError) -> Self {
        NonoError::Snapshot(e.to_string())
    }
}

pub(crate) fn finalize_supervised_exit(ctx: RollbackExitContext<'_>) -> Result<()> {
    let RollbackExitContext {
        audit_state,
        rollback_state,
        rollback_status,
        proxy_handle,
        started,
        ended,
        command,
        exit_code,
        silent,
        rollback_prompt_disabled,
    } = ctx;

    let mut network_events = proxy_handle.map_or_else(
        Vec::new,
        nono_proxy::server::ProxyHandle::drain_audit_events,
    );

    let mut audit_saved = false;

    if let Some((mut manager, baseline, tracked_paths, atomic_temp_before)) = rollback_state {
        let (final_manifest, changes) = manager.create_incremental(&baseline)?;
        let merkle_roots = vec![baseline.merkle_root, final_manifest.merkle_root];

        let meta = nono::undo::SessionMetadata {
            session_id: audit_state
                .map(|state| state.session_id.clone())
                .unwrap_or_default(),
            started: started.to_string(),
            ended: Some(ended.to_string()),
            command: command.to_vec(),
            tracked_paths,
            snapshot_count: manager.snapshot_count(),
            exit_code: Some(exit_code),
            merkle_roots,
            network_events: std::mem::take(&mut network_events),
            rollback_status: RollbackStatus::Available,
        };
        manager.save_session_metadata(&meta)?;
        audit_saved = true;

        if !changes.is_empty() {
            output::print_rollback_session_summary(&changes, silent);

            if !rollback_prompt_disabled && !silent {
                let _ = rollback_ui::review_and_restore(&manager, &baseline, &changes);
            }
        }

        let _ = manager.cleanup_new_atomic_temp_files(&atomic_temp_before);
    }

    if !audit_saved {
        if let Some(audit_state) = audit_state {
            let meta = nono::undo::SessionMetadata {
                session_id: audit_state.session_id.clone(),
                started: started.to_string(),
                ended: Some(ended.to_string()),
                command: command.to_vec(),
                tracked_paths: Vec::new(),
                snapshot_count: 0,
                exit_code: Some(exit_code),
                merkle_roots: Vec::new(),
                network_events,
                rollback_status,
            };
            nono::undo::SnapshotManager::write_session_metadata(&audit_state.session_dir, &meta)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_restore_error_display_names_failed_paths() {
        let err = PartialRestoreError {
            applied: vec![],
            failures: vec![(
                PathBuf::from("C:/project/locked.txt"),
                "The process cannot access the file because it is being used by another process"
                    .to_string(),
            )],
        };
        let msg = err.to_string();
        assert!(
            msg.contains("locked.txt"),
            "Error message should name the locked path, got: {msg}"
        );
        assert!(
            msg.contains("partial rollback"),
            "Error message should describe partial rollback, got: {msg}"
        );
    }

    #[test]
    fn partial_restore_error_counts() {
        let err = PartialRestoreError {
            applied: vec![],
            failures: vec![
                (PathBuf::from("a.txt"), "locked".to_string()),
                (PathBuf::from("b.txt"), "locked".to_string()),
            ],
        };
        let msg = err.to_string();
        assert!(
            msg.contains("2 file(s) failed"),
            "Should count 2 failures, got: {msg}"
        );
    }

    #[test]
    fn partial_restore_error_converts_to_nono_error() {
        let err = PartialRestoreError {
            applied: vec![],
            failures: vec![(PathBuf::from("x.txt"), "locked".to_string())],
        };
        let nono_err: NonoError = err.into();
        assert!(nono_err.to_string().contains("partial rollback"));
    }

    #[test]
    fn rollback_status_skipped_when_rollback_disabled() {
        // When rollback is not requested, status should be Skipped.
        let status = RollbackStatus::Skipped;
        assert!(!status.is_available());
        assert_eq!(status.display_label(), "audit-only");
    }

    #[test]
    fn rollback_status_failed_warning_only_records_reason() {
        let reason = "baseline capture failed: disk full".to_string();
        let status = RollbackStatus::FailedWarningOnly {
            reason: reason.clone(),
        };
        assert!(!status.is_available());
        assert_eq!(status.display_label(), "audit-only (capture failed)");

        // Verify serde round-trip preserves reason
        let json = serde_json::to_string(&status).expect("serialize");
        let parsed: RollbackStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, status);
    }
}
