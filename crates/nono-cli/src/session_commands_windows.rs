use crate::cli::{AttachArgs, DetachArgs, InspectArgs, LogsArgs, PruneArgs, PsArgs, StopArgs};
use crate::exec_strategy::{to_u16_null_terminated, JOB_OBJECT_QUERY, JOB_OBJECT_TERMINATE};
use crate::session::{self, SessionAttachment, SessionRecord, SessionStatus};
use colored::Colorize;
use nono::{NonoError, Result};
use std::collections::VecDeque;
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::path::Path;
use tracing::debug;

fn reject_if_sandboxed(command: &str) -> Result<()> {
    if std::env::var_os("NONO_CAP_FILE").is_some() {
        return Err(NonoError::ConfigParse(format!(
            "`nono {}` cannot be used inside a sandbox.",
            command
        )));
    }
    Ok(())
}

pub fn run_ps(args: &PsArgs) -> Result<()> {
    let sessions = session::list_sessions()?;

    // Filter: by default show live sessions
    let filtered: Vec<&SessionRecord> = sessions
        .iter()
        .filter(|s| args.all || s.status != SessionStatus::Exited)
        .collect();

    if args.json {
        let json = serde_json::to_string_pretty(&filtered)
            .map_err(|e| NonoError::ConfigParse(format!("JSON serialization failed: {e}")))?;
        println!("{json}");
        return Ok(());
    }

    if filtered.is_empty() {
        if args.all {
            eprintln!("No sessions found.");
        } else {
            eprintln!("No running sessions. Use --all to include exited sessions.");
        }
        return Ok(());
    }

    // Table header
    println!(
        "{:<16} {:<12} {:<10} {:<10} {:<12} {:<10} {:<14} COMMAND",
        "SESSION", "NAME", "STATUS", "ATTACH", "PIDS", "UPTIME", "PROFILE"
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

        let pids_str = if session.status == SessionStatus::Running {
            if let Some(ref job_name) = session.job_object_name {
                let pids = session::get_job_pids(job_name);
                if pids.is_empty() {
                    format!("{}", session.child_pid)
                } else if pids.len() == 1 {
                    format!("{}", pids[0])
                } else {
                    format!("{} (+{})", pids[0], pids.len() - 1)
                }
            } else {
                format!("{}", session.child_pid)
            }
        } else {
            "-".to_string()
        };

        let uptime = format_uptime(&session.started);
        let profile = session.profile.as_deref().unwrap_or("-");
        let command = truncate_command(&session.command, 40);

        println!(
            "{:<16} {:<12} {:<10} {:<10} {:<12} {:<10} {:<14} {}",
            session.session_id, name, status, attach, pids_str, uptime, profile, command
        );
    }

    Ok(())
}

fn format_uptime(started: &str) -> String {
    let Ok(start) = chrono::DateTime::parse_from_rfc3339(started) else {
        return "-".to_string();
    };
    let now = chrono::Utc::now();
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

fn truncate_command(command: &[String], max_len: usize) -> String {
    let full = command.join(" ");
    if full.len() <= max_len {
        full
    } else {
        format!("{}...", &full[..max_len.saturating_sub(3)])
    }
}

pub fn run_stop(args: &StopArgs) -> Result<()> {
    let session = session::load_session(&args.session)?;

    if session.status == SessionStatus::Exited {
        println!("Session {} is already stopped.", session.session_id);
        return Ok(());
    }

    // 1. Try Polite (Named Pipe)
    let pipe_name = format!("\\\\.\\pipe\\nono-session-{}", session.session_id);
    let pipe_name_u16 = to_u16_null_terminated(&pipe_name);

    // Wait for pipe availability (short timeout)
    unsafe {
        windows_sys::Win32::System::Pipes::WaitNamedPipeW(pipe_name_u16.as_ptr(), 500);
    }

    let mut polite_success = false;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&pipe_name)
    {
        let msg = nono::supervisor::SupervisorMessage::Terminate {
            session_id: session.session_id.clone(),
        };
        if let Ok(body) = serde_json::to_vec(&msg) {
            let len = body.len() as u32;
            let mut full_msg = len.to_be_bytes().to_vec();
            full_msg.extend(body);

            if file.write_all(&full_msg).is_ok() {
                polite_success = true;
                println!(
                    "Termination request sent to supervisor for session {}",
                    session.session_id
                );
            }
        }
    }

    // 2. Wait or Force (Job Object)
    let job_name = format!("Local\\nono-session-{}", session.session_id);
    let job_name_u16 = to_u16_null_terminated(&job_name);

    if polite_success {
        // Wait up to 5 seconds for it to exit
        print!("Waiting for session to stop gracefully...");
        let _ = std::io::stdout().flush();
        for _ in 0..50 {
            let h_job = unsafe {
                windows_sys::Win32::System::JobObjects::OpenJobObjectW(
                    JOB_OBJECT_QUERY,
                    0,
                    job_name_u16.as_ptr(),
                )
            };
            if h_job.is_null() {
                println!("\nSession {} stopped gracefully.", session.session_id);
                return Ok(());
            }
            unsafe { windows_sys::Win32::Foundation::CloseHandle(h_job) };
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        println!("\nGraceful stop timed out.");
    }

    // Force Stop
    println!(
        "Forcing termination of session {} and its process tree...",
        session.session_id
    );
    let h_job = unsafe {
        windows_sys::Win32::System::JobObjects::OpenJobObjectW(
            JOB_OBJECT_TERMINATE,
            0,
            job_name_u16.as_ptr(),
        )
    };
    if !h_job.is_null() {
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(h_job, 1);
            windows_sys::Win32::Foundation::CloseHandle(h_job);
        }
        println!("Session {} forced to stop.", session.session_id);
    } else {
        println!(
            "Session {} is no longer running in a Job Object.",
            session.session_id
        );
    }

    Ok(())
}

pub fn run_detach(args: &DetachArgs) -> Result<()> {
    let session = session::load_session(&args.session)?;

    if session.status == SessionStatus::Exited {
        println!("Session {} is already stopped.", session.session_id);
        return Ok(());
    }

    let pipe_name = format!("\\\\.\\pipe\\nono-session-{}", session.session_id);
    let pipe_name_u16 = to_u16_null_terminated(&pipe_name);

    unsafe {
        windows_sys::Win32::System::Pipes::WaitNamedPipeW(pipe_name_u16.as_ptr(), 500);
    }

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&pipe_name)
    {
        let msg = nono::supervisor::SupervisorMessage::Detach {
            session_id: session.session_id.clone(),
        };
        if let Ok(body) = serde_json::to_vec(&msg) {
            let len = body.len() as u32;
            let mut full_msg = len.to_be_bytes().to_vec();
            full_msg.extend(body);

            if file.write_all(&full_msg).is_ok() {
                println!(
                    "Detachment request sent to supervisor for session {}",
                    session.session_id
                );
                return Ok(());
            }
        }
    }

    Err(NonoError::Setup(format!(
        "Failed to connect to supervisor for session {}. Is it running?",
        session.session_id
    )))
}

pub fn run_attach(args: &AttachArgs) -> Result<()> {
    let session = session::load_session(&args.session)?;

    if session.status == SessionStatus::Exited {
        return Err(NonoError::Setup(format!(
            "Session {} has already exited.",
            session.session_id
        )));
    }

    // 1. Show scrollback
    let log_path = crate::session::session_log_path(&session.session_id)?;
    if log_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&log_path) {
            // Print last 1000 lines or similar. For now, just print the whole thing.
            print!("{}", content);
            let _ = std::io::stdout().flush();
        }
    }

    // 2. Connect to Data Pipe
    let data_pipe_name = format!("\\\\.\\pipe\\nono-data-{}", session.session_id);
    let data_pipe_name_u16 = to_u16_null_terminated(&data_pipe_name);

    unsafe {
        windows_sys::Win32::System::Pipes::WaitNamedPipeW(data_pipe_name_u16.as_ptr(), 1000);
    }

    let pipe_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&data_pipe_name)
        .map_err(|e| {
            NonoError::Setup(format!(
                "Failed to connect to session data pipe: {}. Is another client already attached?",
                e
            ))
        })?;

    println!(
        "\n{} to session {}. Press {} to detach.",
        "Attached".green().bold(),
        session.session_id.cyan(),
        "Ctrl-] d".yellow()
    );

    // 3. Bi-directional streaming
    let mut pipe_reader = pipe_file.try_clone().map_err(NonoError::Io)?;
    let mut pipe_writer = pipe_file;

    // Output thread: Pipe -> Stdout
    std::thread::spawn(move || {
        let mut stdout = std::io::stdout();
        let mut buf = [0u8; 4096];
        while let Ok(n) = pipe_reader.read(&mut buf) {
            if n == 0 {
                break;
            }
            let _ = stdout.write_all(&buf[..n]);
            let _ = stdout.flush();
        }
    });

    // Input loop: Stdin -> Pipe
    let mut stdin = std::io::stdin();
    let mut buf = [0u8; 4096];

    // We need to handle the escape sequence Ctrl-] d
    // For now, a simple byte-by-byte check or small buffer check.
    // Ctrl-] is 0x1D.
    let mut last_byte_was_escape = false;

    while let Ok(n) = stdin.read(&mut buf) {
        if n == 0 {
            break;
        }

        let mut i = 0;
        while i < n {
            if last_byte_was_escape {
                if buf[i] == b'd' || buf[i] == b'D' {
                    println!("\nDetaching...");
                    return Ok(());
                }
                last_byte_was_escape = false;
            } else if buf[i] == 0x1D {
                last_byte_was_escape = true;
            }
            i += 1;
        }

        if pipe_writer.write_all(&buf[..n]).is_err() {
            break;
        }
    }

    println!("\nSession connection closed.");
    Ok(())
}

pub fn run_logs(args: &LogsArgs) -> Result<()> {
    let record = session::load_session(&args.session)?;
    let events_path = session::session_events_path(&record.session_id)?;

    if !events_path.exists() {
        eprintln!("No event log recorded for session {}.", record.session_id);
        return Ok(());
    }

    if args.follow {
        follow_event_log(&events_path, args.tail, args.json)
    } else {
        let lines = read_event_log_lines(&events_path, args.tail)?;
        print_event_log_lines(&lines, args.json)
    }
}

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

pub fn run_prune(args: &PruneArgs) -> Result<()> {
    reject_if_sandboxed("prune")?;
    let sessions = session::list_sessions()?;

    let now = chrono::Utc::now();
    let mut to_remove: Vec<&SessionRecord> = Vec::new();

    for s in &sessions {
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
            true
        };

        if should_remove {
            to_remove.push(s);
        }
    }

    if let Some(keep) = args.keep {
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

fn read_event_log_lines(path: &Path, tail: Option<usize>) -> Result<Vec<String>> {
    let file = std::fs::File::open(path).map_err(|e| NonoError::ConfigRead {
        path: path.to_path_buf(),
        source: e,
    })?;
    let reader = std::io::BufReader::new(file);

    if let Some(limit) = tail {
        let mut lines = VecDeque::with_capacity(limit.min(256));
        for line in reader.lines() {
            let line = line.map_err(|e| NonoError::ConfigRead {
                path: path.to_path_buf(),
                source: e,
            })?;
            if lines.len() == limit {
                let _ = lines.pop_front();
            }
            lines.push_back(line);
        }
        Ok(lines.into_iter().collect())
    } else {
        reader
            .lines()
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|e| NonoError::ConfigRead {
                path: path.to_path_buf(),
                source: e,
            })
    }
}

fn print_event_log_lines(lines: &[String], as_json: bool) -> Result<()> {
    if as_json {
        let values: Vec<serde_json::Value> = lines
            .iter()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line)
                    .unwrap_or_else(|_| serde_json::Value::String(line.clone()))
            })
            .collect();
        let json = serde_json::to_string_pretty(&values)
            .map_err(|e| NonoError::ConfigParse(format!("JSON serialization failed: {e}")))?;
        println!("{json}");
    } else {
        for line in lines {
            println!("{line}");
        }
    }
    Ok(())
}

fn follow_event_log(path: &Path, tail: Option<usize>, as_json: bool) -> Result<()> {
    let initial_lines = read_event_log_lines(path, tail)?;
    if as_json {
        for line in &initial_lines {
            println!("{line}");
        }
    } else {
        print_event_log_lines(&initial_lines, false)?;
    }

    let mut file = std::fs::File::open(path).map_err(|e| NonoError::ConfigRead {
        path: path.to_path_buf(),
        source: e,
    })?;
    file.seek(SeekFrom::End(0))
        .map_err(|e| NonoError::ConfigRead {
            path: path.to_path_buf(),
            source: e,
        })?;
    let mut reader = std::io::BufReader::new(file);

    loop {
        let mut line = String::new();
        let bytes = reader
            .read_line(&mut line)
            .map_err(|e| NonoError::ConfigRead {
                path: path.to_path_buf(),
                source: e,
            })?;
        if bytes == 0 {
            std::thread::sleep(std::time::Duration::from_millis(250));
            continue;
        }
        print!("{}", line);
    }
}
