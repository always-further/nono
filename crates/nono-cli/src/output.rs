//! CLI output styling for nono

use colored::Colorize;
use nono::{AccessMode, CapabilitySet, NetworkMode, NonoError, Result};
use rand::prelude::IndexedRandom;
use std::ffi::{OsStr, OsString};
use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;

/// Hedgehog puns for the banner
const QUOTES: &[&str] = &[
    "¡Hola Nono!",
    "Bonjour Nono !",
    "Hallo Nono!",
    "Ciao Nono!",
    "Olá Nono!",
    "こんにちは、Nono！",
    "안녕하세요, Nono!",
    "你好，Nono！",
    "!مرحبًا نونو",
    "नमस्ते नोनो!",
    "Hej Nono!",
    "Merhaba Nono!",
    "Halo Nono!",
    "Xin chào Nono!",
    "Sawubona Nono!",
    "Γεια σου Nono!",
    "Привет, Nono!",
    "Cześć Nono!",
    "Shalom Nono!",
    "Kamusta Nono!",
];

/// Print the nono banner with hedgehog mascot
pub fn print_banner(silent: bool) {
    if silent {
        return;
    }

    let quote = QUOTES
        .choose(&mut rand::rng())
        .unwrap_or(&"The opposite of yolo");

    let version = env!("CARGO_PKG_VERSION");

    // Hedgehog in brown/tan - 2 lines, compact
    let hog_line1 = " \u{2584}\u{2588}\u{2584}".truecolor(139, 90, 43); //  ▄█▄ (leading space to center)
    let hog_line2 = "\u{2580}\u{2584}^\u{2584}\u{2580}".truecolor(139, 90, 43); // ▀▄^▄▀

    // Title in orange
    let title = "  nono".truecolor(204, 102, 0).bold();
    let ver = format!("v{}", version).white();

    eprintln!();
    eprintln!(" {} {} {}", hog_line1, title, ver);
    eprintln!(" {}  - {}", hog_line2, quote.truecolor(150, 150, 150));
    eprintln!();
}

/// Print the capability summary with colors
///
/// When `verbose` is 0, only user-specified capabilities are shown (CLI flags
/// and profile filesystem entries). System paths and group-resolved paths are
/// hidden to reduce noise. Use `-v` to show all capabilities.
pub fn print_capabilities(caps: &CapabilitySet, verbose: u8, silent: bool) {
    if silent {
        return;
    }

    eprintln!("{}", "Capabilities:".white().bold());

    // Filesystem capabilities
    let fs_caps = caps.fs_capabilities();
    if !fs_caps.is_empty() {
        let (user_caps, other_count) = if verbose > 0 {
            // Show everything with source labels
            (fs_caps.to_vec(), 0)
        } else {
            // Only show user-specified and profile capabilities
            let user: Vec<_> = fs_caps
                .iter()
                .filter(|c| c.source.is_user_intent())
                .cloned()
                .collect();
            let hidden = fs_caps.len() - user.len();
            (user, hidden)
        };

        eprintln!("  {}", "Filesystem:".white());
        for cap in &user_caps {
            let kind = if cap.is_file { "file" } else { "dir" };
            let access_str = cap.access.to_string();
            let access_colored = match cap.access {
                AccessMode::Read => access_str.green(),
                AccessMode::Write => access_str.yellow(),
                AccessMode::ReadWrite => access_str.truecolor(204, 102, 0), // orange
            };

            if verbose > 0 {
                let source_str = format!("{}", cap.source);
                eprintln!(
                    "    {} [{}] ({}) [{}]",
                    cap.resolved.display().to_string().white(),
                    access_colored,
                    kind.truecolor(150, 150, 150),
                    source_str.truecolor(100, 100, 100),
                );
            } else {
                eprintln!(
                    "    {} [{}] ({})",
                    cap.resolved.display().to_string().white(),
                    access_colored,
                    kind.truecolor(150, 150, 150)
                );
            }
        }

        if other_count > 0 {
            eprintln!(
                "    {}",
                format!("+ {} system/group paths (use -v to show)", other_count)
                    .truecolor(100, 100, 100)
            );
        }
    }

    // Network status
    eprintln!("  {}", "Network:".white());
    match caps.network_mode() {
        NetworkMode::Blocked => {
            eprintln!("    outbound: {}", "blocked".red());
        }
        NetworkMode::ProxyOnly { port, bind_ports } => {
            if bind_ports.is_empty() {
                eprintln!("    outbound: {} (localhost:{})", "proxy".yellow(), port);
            } else {
                let ports_str: Vec<String> = bind_ports.iter().map(|p| p.to_string()).collect();
                eprintln!(
                    "    outbound: {} (localhost:{}), bind: {}",
                    "proxy".yellow(),
                    port,
                    ports_str.join(", ")
                );
            }
        }
        NetworkMode::AllowAll => {
            eprintln!("    outbound: {}", "allowed".green());
        }
    }

    eprintln!();
}

/// Print supervised mode status
pub fn print_supervised_info(silent: bool, rollback: bool, supervised: bool, proxy_active: bool) {
    if silent {
        return;
    }
    let detail = match (rollback, supervised, proxy_active) {
        (true, true, _) => "rollback snapshots + approval sidecar",
        (true, false, true) => "rollback snapshots + network proxy",
        (true, false, false) => "rollback snapshots",
        (false, true, true) => "approval sidecar + network proxy",
        (false, true, false) => "approval sidecar",
        (false, false, true) => "network proxy",
        (false, false, false) => return, // shouldn't happen
    };
    eprintln!(
        "{}",
        format!("Supervised mode: child sandboxed, parent manages {detail}.")
            .truecolor(150, 150, 150)
    );
    eprintln!();
}

/// Print status message for applying sandbox
pub fn print_applying_sandbox(silent: bool) {
    if silent {
        return;
    }
    eprintln!(
        "{}",
        "Applying Kernel sandbox protections.".truecolor(150, 150, 150)
    );
}

/// Print success message when sandbox is active
pub fn print_sandbox_active(silent: bool) {
    if silent {
        return;
    }
    eprintln!(
        "{}",
        "Sandbox active. Restrictions are now in effect.".green()
    );
    eprintln!();
}

/// Print dry run message
pub fn print_dry_run(program: &OsStr, cmd_args: &[OsString], silent: bool) {
    if silent {
        return;
    }
    let mut command = Vec::with_capacity(1 + cmd_args.len());
    command.push(program.to_string_lossy().into_owned());
    command.extend(
        cmd_args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned()),
    );

    eprintln!(
        "{}",
        "Dry run mode - sandbox would be applied with above capabilities".yellow()
    );
    eprintln!("Command: {:?}", command);
}

/// Print rollback tracking status during session start
pub fn print_rollback_tracking(paths: &[std::path::PathBuf], silent: bool) {
    if silent {
        return;
    }
    eprintln!("{}", "Rollback snapshots enabled.".truecolor(150, 150, 150));
    if paths.len() <= 3 {
        for path in paths {
            eprintln!(
                "  {} {}",
                "tracking:".truecolor(100, 100, 100),
                path.display().to_string().white()
            );
        }
    } else {
        for path in &paths[..2] {
            eprintln!(
                "  {} {}",
                "tracking:".truecolor(100, 100, 100),
                path.display().to_string().white()
            );
        }
        eprintln!(
            "  {}",
            format!("+ {} more paths", paths.len() - 2).truecolor(100, 100, 100)
        );
    }
    eprintln!();
}

/// Print post-exit summary of changes detected by the rollback system
pub fn print_rollback_session_summary(changes: &[nono::undo::Change], silent: bool) {
    if silent || changes.is_empty() {
        return;
    }

    let created = changes
        .iter()
        .filter(|c| c.change_type == nono::undo::ChangeType::Created)
        .count();
    let modified = changes
        .iter()
        .filter(|c| c.change_type == nono::undo::ChangeType::Modified)
        .count();
    let deleted = changes
        .iter()
        .filter(|c| c.change_type == nono::undo::ChangeType::Deleted)
        .count();

    let mut parts = Vec::new();
    if created > 0 {
        parts.push(format!("{created} created"));
    }
    if modified > 0 {
        parts.push(format!("{modified} modified"));
    }
    if deleted > 0 {
        parts.push(format!("{deleted} deleted"));
    }

    eprintln!();
    eprintln!(
        "{} {} files changed. ({})",
        "[nono]".truecolor(204, 102, 0),
        changes.len(),
        parts.join(", ")
    );
}

/// Detect how nono was installed based on the binary's path.
fn detect_install_command() -> &'static str {
    let exe = match std::env::current_exe().and_then(|p| p.canonicalize()) {
        Ok(p) => p,
        Err(_) => return "cargo install nono-cli",
    };
    let path = exe.to_string_lossy();

    // Homebrew (macOS Intel or Apple Silicon)
    if path.contains("/opt/homebrew/") || path.contains("/usr/local/Cellar/") {
        return "brew upgrade nono";
    }

    // Cargo
    if path.contains("/.cargo/bin/") {
        return "cargo install nono-cli";
    }

    // Linux system package manager
    if path.starts_with("/usr/bin/") || path.starts_with("/usr/local/bin/") {
        if Path::new("/usr/bin/apt").exists() {
            return "sudo apt update && sudo apt upgrade nono";
        }
        if Path::new("/usr/bin/dnf").exists() {
            return "sudo dnf upgrade nono";
        }
        // Fallback for other system installs
        return "upgrade nono via your package manager";
    }

    "cargo install nono-cli"
}

/// Strip ANSI escape sequences and non-printable characters from a string.
///
/// Prevents terminal injection from a compromised update server.
fn sanitize_terminal_output(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip ESC and the entire escape sequence
            if let Some(next) = chars.next() {
                if next == '[' {
                    // CSI sequence: skip until a letter is found
                    for seq_char in chars.by_ref() {
                        if seq_char.is_ascii_alphabetic() {
                            break;
                        }
                    }
                }
                // OSC, other sequences: already consumed the next char, continue
            }
        } else if c.is_control() && c != '\n' {
            // Strip control characters (except newline)
        } else {
            result.push(c);
        }
    }
    result
}

/// Print update notification if a newer version is available
pub fn print_update_notification(info: &crate::update_check::UpdateInfo, silent: bool) {
    if silent {
        return;
    }

    let version = sanitize_terminal_output(&info.latest_version);
    eprintln!(
        "  {} nono {} is available (current: {})",
        "Update:".yellow().bold(),
        version.green(),
        env!("CARGO_PKG_VERSION"),
    );
    if let Some(ref msg) = info.message {
        let safe_msg = sanitize_terminal_output(msg);
        eprintln!("  {}", safe_msg.truecolor(150, 150, 150));
    }
    let install_cmd = detect_install_command();
    eprintln!(
        "  {}",
        format!("Run: {install_cmd}").truecolor(150, 150, 150)
    );
    if let Some(ref url) = info.release_url {
        let safe_url = sanitize_terminal_output(url);
        eprintln!("  {}", safe_url.truecolor(100, 100, 100));
    }
    eprintln!();
}

/// Prompt the user to confirm sharing the current working directory.
///
/// Returns `Ok(true)` if user confirms, `Ok(false)` if user declines.
/// Returns `Ok(false)` with a hint if stdin is not a TTY.
pub fn prompt_cwd_sharing(cwd: &Path, access: &AccessMode) -> Result<bool> {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        eprintln!(
            "{}",
            "Skipping CWD prompt (non-interactive). Use --allow-cwd to include working directory."
                .truecolor(150, 150, 150),
        );
        return Ok(false);
    }

    let access_str = access.to_string();
    let access_colored = match access {
        AccessMode::Read => access_str.green(),
        AccessMode::Write => access_str.yellow(),
        AccessMode::ReadWrite => access_str.truecolor(204, 102, 0),
    };

    eprintln!(
        "Current directory '{}' will be shared with {} access.",
        cwd.display().to_string().white().bold(),
        access_colored,
    );
    eprintln!(
        "{}",
        "tip: use --allow-cwd to skip this prompt".truecolor(150, 150, 150),
    );
    eprint!("  {} ", "Proceed? [y/N]:".white());
    std::io::stderr().flush().ok();

    let mut input = String::new();
    stdin.lock().read_line(&mut input).map_err(NonoError::Io)?;

    let answer = input.trim().to_lowercase();
    Ok(answer == "y" || answer == "yes")
}
