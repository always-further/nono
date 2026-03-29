//! Session management command implementations.
//!
//! Handles `nono ps`, `nono stop`, `nono detach`, `nono attach`, `nono logs`,
//! `nono inspect`, and `nono prune`.

use crate::cli::{AttachArgs, DetachArgs, InspectArgs, LogsArgs, PruneArgs, PsArgs, StopArgs};
use crate::session::{self, SessionAttachment, SessionRecord, SessionStatus};
use colored::Colorize;
use nono::{NonoError, Result};
use tracing::debug;

const ATTACH_BUSY_MESSAGE: &str = "Session already has an active attached client";

/// Refuse to run if we're inside a nono sandbox.
///
/// Commands that send signals or delete files (stop, prune) must not run
/// inside a sandbox — a sandboxed agent could use them to kill other
/// supervisors or tamper with session state.
fn reject_if_sandboxed(command: &str) -> Result<()> {
    if std::env::var_os("NONO_CAP_FILE").is_some() {
        return Err(NonoError::ConfigParse(format!(
            "`nono {}` cannot be used inside a sandbox.",
            command
        )));
    }
    Ok(())
}

/// Dispatch `nono ps`.
pub fn run_ps(args: &PsArgs) -> Result<()> {
    let sessions = session::list_sessions()?;

    // Filter: by default show live sessions, whether attached or detached.
    let filtered: Vec<&SessionRecord> = sessions
        .iter()
        .filter(|s| args.all || s.status != SessionStatus::Exited)
        .collect();

    if args.json {
        let json = serde_json::to_string_pretty(&filtered)
            .map_err(|e| nono::NonoError::ConfigParse(format!("JSON serialization failed: {e}")))?;
        println!("{json}");
        return Ok(());
    }

    if filtered.is_empty() {
        if args.all {
            eprintln!("No sessions found.");
        } else {
            eprintln!("No running or detached sessions. Use --all to include exited sessions.");
        }
        return Ok(());
    }

    // Table header
    println!(
        "{:<10} {:<12} {:<10} {:<10} {:<8} {:<10} {:<14} COMMAND",
        "SESSION", "NAME", "STATUS", "ATTACH", "PID", "UPTIME", "PROFILE"
    );

    for session in &filtered {
        let name = session.name.as_deref().unwrap_or("-");
        let status = match session.status {
            SessionStatus::Running => "running".green().to_string(),
            SessionStatus::Paused => "paused".yellow().to_string(),
            SessionStatus::Exited => {
                let code = session.exit_code.unwrap_or(-1);
                if code == 0 {
                    "exited(0)".to_string()
                } else {
                    format!("exited({})", code).red().to_string()
                }
            }
        };
        let attach = match session.status {
            SessionStatus::Exited => "-".to_string(),
            _ => match session.attachment {
                SessionAttachment::Attached => "attached".green().to_string(),
                SessionAttachment::Detached => "detached".yellow().to_string(),
            },
        };
        let pid = session.child_pid;
        let uptime = format_uptime(&session.started);
        let profile = session.profile.as_deref().unwrap_or("-");
        let command = truncate_command(&session.command, 40);

        println!(
            "{:<10} {:<12} {:<10} {:<10} {:<8} {:<10} {:<14} {}",
            session.session_id, name, status, attach, pid, uptime, profile, command
        );
    }

    Ok(())
}

/// Format uptime from an ISO 8601 start time string.
fn format_uptime(started: &str) -> String {
    let Ok(start) = chrono::DateTime::parse_from_rfc3339(started) else {
        return "-".to_string();
    };
    let now = chrono::Local::now();
    let duration = now.signed_duration_since(start);

    if duration.num_days() > 0 {
        format!("{}d", duration.num_days())
    } else if duration.num_hours() > 0 {
        format!("{}h", duration.num_hours())
    } else if duration.num_minutes() > 0 {
        format!("{}m", duration.num_minutes())
    } else {
        format!("{}s", duration.num_seconds().max(0))
    }
}

/// Dispatch `nono stop`.
pub fn run_stop(args: &StopArgs) -> Result<()> {
    reject_if_sandboxed("stop")?;
    let record = session::load_session(&args.session)?;

    if record.status == SessionStatus::Exited {
        return Err(NonoError::ConfigParse(format!(
            "Session {} is already exited",
            record.session_id
        )));
    }

    if !session::is_process_alive(record.supervisor_pid, record.started_epoch) {
        return Err(NonoError::ConfigParse(format!(
            "Session {} supervisor (PID {}) is no longer running",
            record.session_id, record.supervisor_pid
        )));
    }

    let pid = nix::unistd::Pid::from_raw(record.supervisor_pid as i32);

    if args.force {
        nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL)
            .map_err(|e| NonoError::ConfigParse(format!("Failed to send SIGKILL: {}", e)))?;
        eprintln!("Stopped session {}.", record.session_id);
    } else {
        nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM)
            .map_err(|e| NonoError::ConfigParse(format!("Failed to send SIGTERM: {}", e)))?;

        // Wait for the process to exit with a timeout
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(args.timeout);
        loop {
            if !session::is_process_alive(record.supervisor_pid, record.started_epoch) {
                eprintln!("Stopped session {}.", record.session_id);
                break;
            }
            if std::time::Instant::now() >= deadline {
                let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
                eprintln!("Stopped session {} (forced).", record.session_id);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }

    Ok(())
}

/// Dispatch `nono detach`.
pub fn run_detach(args: &DetachArgs) -> Result<()> {
    reject_if_sandboxed("detach")?;
    let record = session::load_session(&args.session)?;

    if record.attachment == SessionAttachment::Detached {
        eprintln!("Session {} is already detached.", record.session_id);
        return Ok(());
    }

    if record.status != SessionStatus::Running {
        return Err(NonoError::ConfigParse(format!(
            "Session {} is not running (status: {:?})",
            record.session_id, record.status
        )));
    }

    if !session::is_process_alive(record.supervisor_pid, record.started_epoch) {
        return Err(NonoError::ConfigParse(format!(
            "Session {} supervisor (PID {}) is no longer running",
            record.session_id, record.supervisor_pid
        )));
    }

    // Send SIGUSR1 to the supervisor. The supervisor's signal handler sets
    // an atomic flag; the poll loop checks it, detaches the PTY client, and
    // restores the local terminal without stopping the session.
    let sup_pid = nix::unistd::Pid::from_raw(record.supervisor_pid as i32);
    nix::sys::signal::kill(sup_pid, nix::sys::signal::Signal::SIGUSR1)
        .map_err(|e| NonoError::ConfigParse(format!("Failed to send SIGUSR1: {}", e)))?;

    // Wait for the supervisor to acknowledge detach by updating attachment state.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if !session::is_process_alive(record.supervisor_pid, record.started_epoch) {
            return Err(NonoError::ConfigParse(format!(
                "Session {} supervisor (PID {}) exited before detach completed",
                record.session_id, record.supervisor_pid
            )));
        }
        if let Ok(updated) = session::load_session(&record.session_id) {
            if updated.attachment == SessionAttachment::Detached {
                break;
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(NonoError::ConfigParse(format!(
                "Timed out waiting for session {} to detach",
                record.session_id
            )));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    eprintln!("Detached session {}.", record.session_id);
    Ok(())
}

/// Dispatch `nono attach`.
pub fn run_attach(args: &AttachArgs) -> Result<()> {
    reject_if_sandboxed("attach")?;
    let record = session::load_session(&args.session)?;

    if record.status == SessionStatus::Exited {
        match record.exit_code {
            Some(code) => {
                eprintln!(
                    "[nono] Session {} has already exited (exit code {}).",
                    record.session_id, code
                );
            }
            None => {
                eprintln!("[nono] Session {} has already exited.", record.session_id);
            }
        }
        return Ok(());
    }

    if !session::is_process_alive(record.supervisor_pid, record.started_epoch) {
        return Err(NonoError::ConfigParse(format!(
            "Session {} supervisor (PID {}) is no longer running",
            record.session_id, record.supervisor_pid
        )));
    }

    eprintln!("[nono] Attaching to session {}...", record.session_id);

    if record.status == SessionStatus::Paused {
        return Err(NonoError::ConfigParse(format!(
            "Session {} is paused/stopped and cannot accept attach",
            record.session_id
        )));
    }

    match crate::pty_proxy::attach_to_session(&record.session_id) {
        Err(NonoError::ConfigParse(msg)) if msg == ATTACH_BUSY_MESSAGE => {
            eprintln!(
                "[nono] Session {} already has an active attached client.",
                record.session_id
            );
            Ok(())
        }
        other => other,
    }
}

/// Dispatch `nono logs` — placeholder for Step 3.
pub fn run_logs(args: &LogsArgs) -> Result<()> {
    let _record = session::load_session(&args.session)?;
    eprintln!(
        "Event logging not yet implemented. Session {} found.",
        _record.session_id
    );
    Ok(())
}

/// Dispatch `nono inspect` — placeholder for Step 4.
pub fn run_inspect(args: &InspectArgs) -> Result<()> {
    let record = session::load_session(&args.session)?;

    if args.json {
        let json = serde_json::to_string_pretty(&record)
            .map_err(|e| NonoError::ConfigParse(format!("JSON serialization failed: {e}")))?;
        println!("{json}");
        return Ok(());
    }

    println!("Session:    {}", record.session_id);
    if let Some(ref name) = record.name {
        println!("Name:       {}", name);
    }
    println!("Status:     {:?}", record.status);
    println!("Attached:   {:?}", record.attachment);
    println!(
        "PID:        {} (supervisor: {})",
        record.child_pid, record.supervisor_pid
    );
    println!("Started:    {}", record.started);
    if let Some(code) = record.exit_code {
        println!("Exit code:  {}", code);
    }
    println!("Command:    {}", record.command.join(" "));
    if let Some(ref profile) = record.profile {
        println!("Profile:    {}", profile);
    }
    println!("Workdir:    {}", record.workdir.display());
    println!("Network:    {}", record.network);
    if let Some(ref rollback) = record.rollback_session {
        println!("Rollback:   {}", rollback);
    }

    Ok(())
}

/// Dispatch `nono prune`.
pub fn run_prune(args: &PruneArgs) -> Result<()> {
    reject_if_sandboxed("prune")?;
    let sessions = session::list_sessions()?;

    let now = chrono::Utc::now();
    let mut to_remove: Vec<&SessionRecord> = Vec::new();

    for s in &sessions {
        // Skip running sessions
        if s.status == SessionStatus::Running {
            continue;
        }

        let should_remove = if let Some(days) = args.older_than {
            if let Ok(started) = chrono::DateTime::parse_from_rfc3339(&s.started) {
                let age = now.signed_duration_since(started);
                age.num_days() >= days as i64
            } else {
                false
            }
        } else {
            true // No age filter: all exited sessions are candidates
        };

        if should_remove {
            to_remove.push(s);
        }
    }

    // Apply --keep: keep the N most recent, remove the rest
    if let Some(keep) = args.keep {
        // to_remove is sorted newest-first (from list_sessions), so skip the first `keep`
        if to_remove.len() > keep {
            to_remove = to_remove[keep..].to_vec();
        } else {
            to_remove.clear();
        }
    }

    if to_remove.is_empty() {
        eprintln!("Nothing to prune.");
        return Ok(());
    }

    let dir = session::sessions_dir()?;

    for s in &to_remove {
        let session_file = dir.join(format!("{}.json", s.session_id));
        let events_file = dir.join(format!("{}.events.ndjson", s.session_id));

        if args.dry_run {
            eprintln!("Would remove: {} (started {})", s.session_id, s.started);
        } else {
            if let Err(e) = std::fs::remove_file(&session_file) {
                debug!(
                    "Failed to remove session file {}: {}",
                    session_file.display(),
                    e
                );
            }
            if events_file.exists() {
                if let Err(e) = std::fs::remove_file(&events_file) {
                    debug!(
                        "Failed to remove events file {}: {}",
                        events_file.display(),
                        e
                    );
                }
            }
            eprintln!("Removed: {} (started {})", s.session_id, s.started);
        }
    }

    eprintln!(
        "\n{} {} session(s).",
        if args.dry_run {
            "Would prune"
        } else {
            "Pruned"
        },
        to_remove.len()
    );

    Ok(())
}

/// Truncate command display to max_len characters.
fn truncate_command(command: &[String], max_len: usize) -> String {
    let full = command.join(" ");
    if full.len() <= max_len {
        full
    } else {
        format!("{}...", &full[..max_len.saturating_sub(3)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_command_short() {
        let cmd = vec!["echo".to_string(), "hello".to_string()];
        assert_eq!(truncate_command(&cmd, 40), "echo hello");
    }

    #[test]
    fn test_truncate_command_long() {
        let cmd = vec![
            "very-long-command".to_string(),
            "with-many-arguments-that-exceed-the-limit".to_string(),
        ];
        let result = truncate_command(&cmd, 20);
        assert!(result.len() <= 20);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_format_uptime_seconds() {
        let now = chrono::Local::now();
        let started = (now - chrono::Duration::seconds(30)).to_rfc3339();
        let result = format_uptime(&started);
        assert!(result.ends_with('s'));
    }

    #[test]
    fn test_format_uptime_minutes() {
        let now = chrono::Local::now();
        let started = (now - chrono::Duration::minutes(5)).to_rfc3339();
        let result = format_uptime(&started);
        assert!(result.ends_with('m'));
    }
}
