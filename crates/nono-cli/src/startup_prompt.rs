use crate::exec_strategy::StartupTimeoutConfig;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::io::{self, BufRead, IsTerminal, Write};
use std::time::Duration;

pub(crate) fn print_terminal_safe_stderr(message: &str) {
    let mut stderr = io::stderr();
    if stderr.is_terminal() {
        let normalized = message.replace('\n', "\r\n");
        let _ = writeln!(stderr, "\r{}", normalized);
    } else {
        let _ = writeln!(stderr, "{}", message);
    }
}

fn prompt_startup_termination(timeout_cfg: StartupTimeoutConfig<'_>, has_output: bool) -> bool {
    let description = if has_output {
        format!(
            "[nono] Startup appears blocked: `{}` has not become interactive after {} seconds.",
            timeout_cfg.program,
            timeout_cfg.timeout.as_secs()
        )
    } else {
        format!(
            "[nono] Startup appears blocked: `{}` produced no terminal output after {} seconds.",
            timeout_cfg.program,
            timeout_cfg.timeout.as_secs()
        )
    };

    let tty_in = match std::fs::File::open("/dev/tty") {
        Ok(file) => file,
        Err(_) => {
            print_terminal_safe_stderr(&format!(
                "{}\n[nono] `{}` usually needs the built-in `{}` profile.\n[nono] Try: nono run --profile {} -- {}",
                description,
                timeout_cfg.program,
                timeout_cfg.profile,
                timeout_cfg.profile,
                timeout_cfg.program,
            ));
            return false;
        }
    };

    let mut tty_out = match std::fs::OpenOptions::new().write(true).open("/dev/tty") {
        Ok(file) => file,
        Err(_) => {
            print_terminal_safe_stderr(&format!(
                "{}\n[nono] `{}` usually needs the built-in `{}` profile.\n[nono] Try: nono run --profile {} -- {}",
                description,
                timeout_cfg.program,
                timeout_cfg.profile,
                timeout_cfg.profile,
                timeout_cfg.program,
            ));
            return false;
        }
    };

    let _ = writeln!(tty_out);
    let _ = writeln!(tty_out, "{}", description);
    let _ = writeln!(
        tty_out,
        "[nono] `{}` usually needs the built-in `{}` profile.",
        timeout_cfg.program, timeout_cfg.profile
    );
    let _ = writeln!(
        tty_out,
        "[nono] Try: nono run --profile {} -- {}",
        timeout_cfg.profile, timeout_cfg.program
    );
    let _ = write!(tty_out, "[nono] Do you wish to terminate? [y/N] ");
    let _ = tty_out.flush();

    let mut reader = io::BufReader::new(tty_in);
    let mut input = String::new();
    if reader.read_line(&mut input).is_err() {
        let _ = writeln!(tty_out, "\n[nono] Continuing to wait.");
        return false;
    }

    let affirmative = matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes");
    if affirmative {
        let _ = writeln!(tty_out, "[nono] Terminating startup-blocked process.");
    } else {
        let _ = writeln!(tty_out, "[nono] Continuing to wait.");
    }
    affirmative
}

struct StartupPromptTerminalGuard {
    tty: Option<std::fs::File>,
    saved_termios: Option<nix::sys::termios::Termios>,
    child: Pid,
    child_stopped: bool,
}

impl StartupPromptTerminalGuard {
    fn pause_without_pty(child: Pid) -> Self {
        // SIGSTOP freezes the direct child so its output doesn't interleave with
        // the prompt. Descendants keep running, and the child's network peers
        // may time out if the prompt is answered "no". Acceptable tradeoff:
        // the prompt only fires after the startup timeout already elapsed.
        let child_stopped = signal::kill(child, Signal::SIGSTOP).is_ok();
        if child_stopped {
            std::thread::sleep(Duration::from_millis(20));
        }

        let mut guard = Self {
            tty: None,
            saved_termios: None,
            child,
            child_stopped,
        };

        let tty = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
        {
            Ok(tty) => tty,
            Err(_) => return guard,
        };

        let original = match nix::sys::termios::tcgetattr(&tty) {
            Ok(termios) => termios,
            Err(_) => return guard,
        };

        let mut prompt_termios = original.clone();
        crate::profile_save_runtime::configure_prompt_termios(&mut prompt_termios);
        if nix::sys::termios::tcsetattr(&tty, nix::sys::termios::SetArg::TCSANOW, &prompt_termios)
            .is_err()
        {
            return guard;
        }

        let _ = nix::sys::termios::tcflush(&tty, nix::sys::termios::FlushArg::TCIFLUSH);
        guard.saved_termios = Some(original);
        guard.tty = Some(tty);
        guard
    }

    fn finish(self, resume_child: bool) {
        if let (Some(tty), Some(saved_termios)) = (self.tty.as_ref(), self.saved_termios.as_ref()) {
            let _ = nix::sys::termios::tcsetattr(
                tty,
                nix::sys::termios::SetArg::TCSANOW,
                saved_termios,
            );
        }

        if self.child_stopped && resume_child {
            let _ = signal::kill(self.child, Signal::SIGCONT);
        }
    }
}

pub(crate) fn prompt_startup_termination_for_child(
    child: Pid,
    timeout_cfg: StartupTimeoutConfig<'_>,
    has_output: bool,
    pty: Option<&mut crate::pty_proxy::PtyProxy>,
) -> bool {
    if let Some(proxy) = pty {
        let paused_terminal = proxy.pause_terminal_for_prompt();
        let terminate = prompt_startup_termination(timeout_cfg, has_output);
        if paused_terminal {
            proxy.resume_terminal_after_prompt();
        }
        return terminate;
    }

    let guard = StartupPromptTerminalGuard::pause_without_pty(child);
    let terminate = prompt_startup_termination(timeout_cfg, has_output);
    guard.finish(!terminate);
    terminate
}
