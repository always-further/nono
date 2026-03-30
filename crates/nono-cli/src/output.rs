//! CLI output styling for nono
//!
//! All colors are drawn from the active theme via `theme::current()`.

use crate::theme::{self, badge, fg, Rgb};
use colored::Colorize;
use nono::{AccessMode, CapabilitySet, NetworkMode, NonoError, Result};
use std::ffi::{OsStr, OsString};
use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Dark foreground for badge text (works on both light and dark bg colors)
const BADGE_FG_DARK: Rgb = Rgb(30, 30, 46);

/// Print a thin horizontal rule using overlay color
fn rule() {
    let t = theme::current();
    eprintln!("  {}", theme::fg(&"\u{2500}".repeat(52), t.overlay));
}

// ---------------------------------------------------------------------------
// Banner
// ---------------------------------------------------------------------------

/// Print the nono banner
pub fn print_banner(silent: bool) {
    if silent {
        return;
    }

    let t = theme::current();
    let version = env!("CARGO_PKG_VERSION");

    eprintln!();
    eprintln!(
        "  {} {}",
        theme::fg("nono", t.brand).bold(),
        theme::fg(&format!("v{version}"), t.subtext),
    );

    #[cfg(target_os = "windows")]
    {
        let support = nono::Sandbox::support_info();
        if !support.is_supported {
            eprintln!(
                "  {} {}",
                theme::fg("preview", t.yellow).bold(),
                theme::fg(
                    "Windows sandbox enforcement is partial and still in progress",
                    t.subtext
                ),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

/// Print the capability summary
///
/// When `verbose` is 0, only user-specified capabilities are shown (CLI flags
/// and profile filesystem entries). System paths and group-resolved paths are
/// hidden to reduce noise. Use `-v` to show all capabilities.
pub fn print_capabilities(caps: &CapabilitySet, verbose: u8, silent: bool) {
    if silent {
        return;
    }

    let t = theme::current();

    eprintln!("  {}", theme::fg("Capabilities:", t.subtext).bold());
    rule();

    // Filesystem capabilities
    let fs_caps = caps.fs_capabilities();
    if !fs_caps.is_empty() {
        let (user_caps, other_count) = if verbose > 0 {
            (fs_caps.to_vec(), 0)
        } else {
            let user: Vec<_> = fs_caps
                .iter()
                .filter(|c| c.source.is_user_intent())
                .cloned()
                .collect();
            let hidden = fs_caps.len() - user.len();
            (user, hidden)
        };

        for cap in &user_caps {
            let kind = if cap.is_file { "file" } else { "dir" };
            let access_badge = format_access_badge(&cap.access);

            if verbose > 0 {
                let source_str = format!("{}", cap.source);
                eprintln!(
                    "  {} {} {}",
                    access_badge,
                    theme::fg(&cap.resolved.display().to_string(), t.text),
                    theme::fg(&format!("({kind}) [{source_str}]"), t.subtext),
                );
            } else {
                eprintln!(
                    "  {} {} {}",
                    access_badge,
                    theme::fg(&cap.resolved.display().to_string(), t.text),
                    theme::fg(&format!("({kind})"), t.subtext),
                );
            }
        }

        if other_count > 0 {
            eprintln!(
                "       {}",
                theme::fg(
                    &format!("+ {other_count} system/group paths (-v to show)"),
                    t.subtext
                )
            );
        }
    }

    // Network status
    match caps.network_mode() {
        NetworkMode::Blocked => {
            eprintln!(
                "  {} {}",
                theme::badge(" net ", t.red, BADGE_FG_DARK),
                theme::fg("outbound blocked", t.subtext),
            );
        }
        NetworkMode::ProxyOnly { port, bind_ports } => {
            if bind_ports.is_empty() {
                eprintln!(
                    "  {} {}",
                    theme::badge(" net ", t.yellow, BADGE_FG_DARK),
                    theme::fg(&format!("proxy localhost:{port}"), t.subtext),
                );
            } else {
                let ports_str: Vec<String> = bind_ports.iter().map(|p| p.to_string()).collect();
                eprintln!(
                    "  {} {}",
                    theme::badge(" net ", t.yellow, BADGE_FG_DARK),
                    theme::fg(
                        &format!("proxy localhost:{port}, bind: {}", ports_str.join(", ")),
                        t.subtext,
                    ),
                );
            }
        }
        NetworkMode::AllowAll => {
            eprintln!(
                "  {} {}",
                theme::badge(" net ", t.green, BADGE_FG_DARK),
                theme::fg("outbound allowed", t.subtext),
            );
        }
    }
    if !caps.localhost_ports().is_empty() {
        let ports_str: Vec<String> = caps
            .localhost_ports()
            .iter()
            .map(|p| p.to_string())
            .collect();
        eprintln!(
            "  {} {}",
            theme::badge(" ipc ", t.teal, BADGE_FG_DARK),
            theme::fg(&format!("localhost:{}", ports_str.join(", ")), t.subtext,),
        );
    }

    rule();
    eprintln!();
}

/// Format an access mode as a fixed-width colored badge
fn format_access_badge(access: &AccessMode) -> String {
    let t = theme::current();
    match access {
        AccessMode::Read => theme::badge("  r  ", t.green, BADGE_FG_DARK),
        AccessMode::Write => theme::badge("  w  ", t.yellow, BADGE_FG_DARK),
        AccessMode::ReadWrite => theme::badge(" r+w ", t.brand, BADGE_FG_DARK),
    }
}

/// Format an access mode as inline colored text (for prompts)
fn format_access_inline(access: &AccessMode) -> colored::ColoredString {
    let t = theme::current();
    match access {
        AccessMode::Read => theme::fg("read", t.green),
        AccessMode::Write => theme::fg("write", t.yellow),
        AccessMode::ReadWrite => theme::fg("read+write", t.brand),
    }
}

// ---------------------------------------------------------------------------
// Kernel / ABI
// ---------------------------------------------------------------------------

/// Print Landlock ABI information (Linux only).
///
/// Shows the detected ABI version and available features. When features
/// are degraded (ABI < V5), displays which features are unavailable.
#[cfg(target_os = "linux")]
pub fn print_abi_info(silent: bool) {
    if silent {
        return;
    }
    let t = theme::current();
    match nono::Sandbox::detect_abi() {
        Ok(detected) => {
            let features = detected.feature_names();
            let feature_summary: Vec<&str> = features.iter().skip(1).map(|s| s.as_str()).collect();
            if feature_summary.is_empty() {
                eprintln!(
                    "  {} {}",
                    badge(" kernel ", t.green, BADGE_FG_DARK),
                    fg(&detected.to_string(), t.text),
                );
            } else {
                eprintln!(
                    "  {} {} {}",
                    badge(" kernel ", t.green, BADGE_FG_DARK),
                    fg(&detected.to_string(), t.text),
                    fg(&format!("({})", feature_summary.join(", ")), t.subtext,),
                );
            }

            // Show what's missing on degraded ABI versions
            type AbiFeatureCheck = (&'static str, fn(&nono::DetectedAbi) -> bool);
            const ALL_FEATURES: &[AbiFeatureCheck] = &[
                ("Refer", nono::DetectedAbi::has_refer),
                ("Truncate", nono::DetectedAbi::has_truncate),
                ("TCP filtering", nono::DetectedAbi::has_network),
                ("IoctlDev", nono::DetectedAbi::has_ioctl_dev),
                ("Scoping", nono::DetectedAbi::has_scoping),
            ];

            let missing: Vec<&str> = ALL_FEATURES
                .iter()
                .filter(|(_, check)| !check(&detected))
                .map(|(name, _)| *name)
                .collect();
            if !missing.is_empty() {
                eprintln!(
                    "          {}",
                    fg(
                        &format!(
                            "degraded: {} (upgrade kernel for full support)",
                            missing.join(", "),
                        ),
                        t.yellow,
                    ),
                );
            }
        }
        Err(e) => {
            eprintln!(
                "  {} {}",
                badge(" kernel ", t.red, BADGE_FG_DARK),
                fg(&format!("Landlock detection failed: {e}"), t.red),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Status messages
// ---------------------------------------------------------------------------

/// Print supervised mode status
pub fn print_supervised_info(silent: bool, rollback: bool, proxy_active: bool) {
    if silent {
        return;
    }
    let t = theme::current();
    let mut features = Vec::new();
    if rollback {
        features.push("snapshots");
    }
    if proxy_active {
        features.push("proxy");
    }
    features.push("supervisor");

    #[cfg(target_os = "windows")]
    {
        let support = nono::Sandbox::support_info();
        if !support.is_supported {
            eprintln!(
                "  {} {}",
                fg("mode", t.subtext),
                fg(&format!("preview ({})", features.join(", ")), t.subtext,),
            );
            return;
        }
    }

    eprintln!(
        "  {} {}",
        fg("mode", t.subtext),
        fg(&format!("supervised ({})", features.join(", ")), t.subtext),
    );
}

/// Print status message for applying sandbox
pub fn print_applying_sandbox(silent: bool) {
    if silent {
        return;
    }
    let t = theme::current();
    eprint!("  {}", fg("Applying sandbox...", t.subtext));
    // Flush so it appears immediately (no newline yet)
    std::io::stderr().flush().ok();
}

/// Print success message when sandbox is active
pub fn print_sandbox_active(silent: bool) {
    if silent {
        return;
    }
    let t = theme::current();
    // Complete the "Applying sandbox..." line
    eprintln!(" {}", fg("active", t.green).bold());
    eprintln!();
}

/// Print a styled warning message to stderr
pub fn print_warning(message: &str) {
    let t = theme::current();
    eprintln!("  {} {}", fg("warning:", t.red).bold(), fg(message, t.text),);
}

/// Print dry run message
pub fn print_dry_run(
    program: &OsStr,
    cmd_args: &[OsString],
    support: &nono::SupportInfo,
    silent: bool,
) {
    if silent {
        return;
    }
    let t = theme::current();
    let mut command = Vec::with_capacity(1 + cmd_args.len());
    command.push(program.to_string_lossy().into_owned());
    command.extend(
        cmd_args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned()),
    );

    eprintln!(
        "  {} {}",
        fg("dry-run", t.yellow).bold(),
        fg(dry_run_summary(support), t.subtext),
    );
    eprintln!(
        "  {} {}",
        fg("$", t.subtext),
        fg(&command.join(" "), t.text)
    );
}

fn dry_run_summary(support: &nono::SupportInfo) -> &'static str {
    #[cfg(target_os = "windows")]
    {
        if !support.is_supported {
            return "preview validation only; sandbox enforcement is not implemented on Windows yet";
        }
    }

    "sandbox would be applied with above capabilities"
}

// ---------------------------------------------------------------------------
// Rollback / Snapshots
// ---------------------------------------------------------------------------

/// Print rollback tracking status during session start
pub fn print_rollback_tracking(paths: &[std::path::PathBuf], silent: bool) {
    if silent {
        return;
    }
    let t = theme::current();
    let display_paths = if paths.len() <= 3 { paths } else { &paths[..2] };
    for path in display_paths {
        eprintln!(
            "  {} {}",
            badge(" snap ", t.surface, t.subtext),
            fg(&path.display().to_string(), t.subtext),
        );
    }
    if paths.len() > 3 {
        eprintln!(
            "         {}",
            fg(&format!("+ {} more paths", paths.len() - 2), t.subtext),
        );
    }
}

/// Print post-exit summary of changes detected by the rollback system
pub fn print_rollback_session_summary(changes: &[nono::undo::Change], silent: bool) {
    if silent || changes.is_empty() {
        return;
    }

    let t = theme::current();

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
        parts.push(format!("{}", fg(&format!("{created} created"), t.green)));
    }
    if modified > 0 {
        parts.push(format!("{}", fg(&format!("{modified} modified"), t.yellow)));
    }
    if deleted > 0 {
        parts.push(format!("{}", fg(&format!("{deleted} deleted"), t.red)));
    }

    eprintln!();
    eprintln!(
        "  {} {} files changed ({})",
        fg("nono", t.brand).bold(),
        changes.len(),
        parts.join(", "),
    );
}

// ---------------------------------------------------------------------------
// Update notification
// ---------------------------------------------------------------------------

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

    let t = theme::current();
    let version = sanitize_terminal_output(&info.latest_version);
    let install_cmd = detect_install_command();
    eprintln!(
        "  {} {} {} {}",
        fg("update", t.yellow).bold(),
        fg(&version, t.green).bold(),
        fg("available", t.subtext),
        fg(
            &format!("(current: {})", env!("CARGO_PKG_VERSION")),
            t.subtext,
        ),
    );
    if let Some(ref msg) = info.message {
        let safe_msg = sanitize_terminal_output(msg);
        eprintln!("  {}", fg(&safe_msg, t.subtext));
    }
    eprintln!("  {} {}", fg("$", t.subtext), fg(install_cmd, t.text));
    if let Some(ref url) = info.release_url {
        let safe_url = sanitize_terminal_output(url);
        eprintln!("  {}", fg(&safe_url, t.blue));
    }
    eprintln!();
}

// ---------------------------------------------------------------------------
// Interactive prompts
// ---------------------------------------------------------------------------

/// Prompt the user to confirm sharing the current working directory.
///
/// Returns `Ok(true)` if user confirms, `Ok(false)` if user declines.
/// Returns `Ok(false)` with a hint if stdin is not a TTY.
pub fn prompt_cwd_sharing(cwd: &Path, access: &AccessMode) -> Result<bool> {
    let t = theme::current();
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        eprintln!(
            "  {}",
            fg(
                "Skipping CWD prompt (non-interactive). Use --allow-cwd to include working directory.",
                t.subtext,
            ),
        );
        return Ok(false);
    }

    let access_colored = format_access_inline(access);

    eprintln!(
        "  Share {} with {} access?",
        fg(&cwd.display().to_string(), t.text).bold(),
        access_colored,
    );
    eprintln!("  {}", fg("use --allow-cwd to skip this prompt", t.subtext),);
    eprint!("  {} ", fg("[y/N]", t.text).bold());
    std::io::stderr().flush().ok();

    let mut input = String::new();
    stdin.lock().read_line(&mut input).map_err(NonoError::Io)?;

    let answer = input.trim().to_lowercase();
    Ok(answer == "y" || answer == "yes")
}
