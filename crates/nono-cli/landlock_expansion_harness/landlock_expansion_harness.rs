#[cfg(target_os = "linux")]
mod linux {
    use clap::Parser;
    use landlock::{
        Access, AccessFs, BitFlags, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset,
        RulesetAttr, RulesetCreatedAttr, ABI,
    };
    use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
    use nono::supervisor::socket::{recv_fd_via_socket, send_fd_via_socket};
    use nono::{NonoError, Result, Sandbox};
    use serde::{de::DeserializeOwned, Deserialize, Serialize};
    use std::collections::{BTreeSet, HashSet};
    use std::ffi::{CStr, CString};
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    const DEFAULT_EXEC_DIRS: &[&str] =
        &["/bin", "/usr/bin", "/usr/local/bin", "/sbin", "/usr/sbin"];
    const DEFAULT_SUPPORT_DIRS: &[&str] = &[
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
        "/usr/local/lib",
        "/usr/local/lib64",
    ];
    const DEFAULT_SUPPORT_FILES: &[&str] = &[
        "/etc/ld.so.cache",
        "/etc/ld.so.conf",
        "/etc/nsswitch.conf",
        "/etc/hosts",
        "/etc/resolv.conf",
    ];
    const STDIO_PROOF_INPUT: &[u8] = b"nono-stdin-proof\n";
    const TTY_READY_MARKER: &[u8] = b"tty-helper-ready";
    const COMMAND_PTY_READY_MARKER: &[u8] = b"command-pty-helper-ready";
    static SIGNAL_FORWARD_PID: AtomicI32 = AtomicI32::new(0);

    #[derive(Debug, Parser)]
    #[command(
        name = "nono-landlock-expansion-harness",
        about = "Measure file-level executable Landlock expansion for command policies"
    )]
    struct Args {
        /// Executable entrypoint directory to enumerate. Defaults to common system bin dirs.
        #[arg(long = "exec-dir", value_name = "PATH")]
        exec_dirs: Vec<PathBuf>,

        /// Directory to grant read-only support access for dynamic loaders/libraries.
        #[arg(long = "support-dir", value_name = "PATH")]
        support_dirs: Vec<PathBuf>,

        /// File to grant read-only support access.
        #[arg(long = "support-file", value_name = "PATH")]
        support_files: Vec<PathBuf>,

        /// Policy-controlled binary to exclude from the outer session sandbox.
        #[arg(long = "exclude", value_name = "PATH")]
        excludes: Vec<PathBuf>,

        /// Stop after scanning and rule construction; do not restrict this process.
        #[arg(long)]
        dry_run: bool,

        /// Apply the Landlock ruleset after scanning. This is irreversible for this process.
        #[arg(long, conflicts_with = "dry_run")]
        apply: bool,

        /// Exec probe expected to succeed after --apply.
        #[arg(long = "probe-allow", value_name = "PATH")]
        probe_allow: Vec<PathBuf>,

        /// Exec probe expected to fail after --apply.
        #[arg(long = "probe-deny", value_name = "PATH")]
        probe_deny: Vec<PathBuf>,

        /// Emit JSON instead of a human-readable summary.
        #[arg(long)]
        json: bool,

        /// Run the full v4 topology smoke test for a policy-controlled binary.
        #[arg(long = "topology-smoke", value_name = "PATH")]
        topology_smoke: Option<PathBuf>,

        /// Run topology smoke with deterministic stdin, stderr, and fd-hygiene checks.
        #[arg(long = "stdio-fd-smoke")]
        stdio_fd_smoke: bool,

        /// Run topology smoke through a PTY and verify terminal-generated SIGINT forwarding.
        #[arg(long = "tty-signal-smoke")]
        tty_signal_smoke: bool,

        /// Run topology smoke through a PTY and verify job-control signal forwarding.
        #[arg(long = "tty-job-control-smoke")]
        tty_job_control_smoke: bool,

        /// Run a git -> ssh style chaining and credential-isolation smoke test.
        #[arg(long = "chain-credential-smoke")]
        chain_credential_smoke: bool,

        /// Run topology smoke with a supervisor-created command PTY and controlling terminal.
        #[arg(long = "command-pty-bridge-smoke")]
        command_pty_bridge_smoke: bool,

        /// Internal topology role. Hidden; spawned by --topology-smoke.
        #[arg(long = "topology-role", hide = true)]
        topology_role: Option<String>,

        /// Internal supervisor socket path. Hidden; spawned by --topology-smoke.
        #[arg(long = "topology-socket", value_name = "PATH", hide = true)]
        topology_socket: Option<PathBuf>,

        /// Internal policy binary path. Hidden; spawned by --topology-smoke.
        #[arg(long = "topology-policy", value_name = "PATH", hide = true)]
        topology_policy: Option<PathBuf>,

        /// Internal shim binary path. Hidden; spawned by --topology-smoke.
        #[arg(long = "topology-shim", value_name = "PATH", hide = true)]
        topology_shim: Option<PathBuf>,

        /// Internal helper role to pass to the final policy exec. Hidden; spawned by smoke tests.
        #[arg(long = "topology-helper-role", hide = true)]
        topology_helper_role: Option<String>,

        /// Internal flag that makes the command launcher acquire stdio as a controlling PTY.
        #[arg(long = "topology-command-pty", hide = true)]
        topology_command_pty: bool,
    }

    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    struct FileId {
        dev: u64,
        ino: u64,
    }

    #[derive(Debug)]
    struct Exclusion {
        requested: PathBuf,
        canonical: PathBuf,
        id: FileId,
    }

    #[derive(Debug)]
    struct ScanOutput {
        executable_files: Vec<PathBuf>,
        support_dirs: Vec<PathBuf>,
        support_files: Vec<PathBuf>,
        excluded: Vec<Exclusion>,
        stats: ScanStats,
    }

    #[derive(Debug, Default, Serialize)]
    struct ScanStats {
        exec_dirs_requested: usize,
        exec_dirs_scanned: usize,
        exec_entries_seen: usize,
        executable_candidates: usize,
        allowed_executable_files: usize,
        excluded_by_path: usize,
        excluded_by_inode: usize,
        duplicate_inode_skips: usize,
        non_file_skips: usize,
        metadata_errors: usize,
        support_dirs_allowed: usize,
        support_files_allowed: usize,
        total_landlock_rules: usize,
    }

    #[derive(Debug, Serialize)]
    struct TimingSummary {
        scan_ms: u128,
        ruleset_build_ms: Option<u128>,
        restrict_self_ms: Option<u128>,
        total_ms: u128,
    }

    #[derive(Debug, Serialize)]
    struct ProbeSummary {
        path: String,
        expected: ProbeExpectation,
        outcome: ProbeOutcome,
        matched: bool,
    }

    #[derive(Clone, Copy, Debug, Serialize)]
    #[serde(rename_all = "snake_case")]
    enum ProbeExpectation {
        Allow,
        Deny,
    }

    #[derive(Debug, Serialize)]
    #[serde(rename_all = "snake_case")]
    enum ProbeOutcome {
        Exited { code: Option<i32> },
        SpawnDenied,
        SpawnError { message: String },
    }

    #[derive(Debug, Serialize)]
    struct JsonSummary {
        landlock_abi: String,
        scan: ScanStats,
        timings: TimingSummary,
        excluded: Vec<JsonExclusion>,
        probes: Vec<ProbeSummary>,
    }

    #[derive(Debug, Serialize)]
    struct JsonExclusion {
        requested: String,
        canonical: String,
        dev: u64,
        ino: u64,
    }

    #[derive(Debug)]
    struct ExtraRule {
        path: PathBuf,
        access: BitFlags<AccessFs>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    struct ShimRequest {
        command: String,
        helper_role: Option<String>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    struct ShimFdRequest {
        send_stdio_fds: bool,
    }

    #[derive(Debug, Deserialize, Serialize)]
    struct ShimStartMessage {
        grandchild_pid: Option<i32>,
        spawn_error: Option<String>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    struct ShimResponse {
        exit_code: Option<i32>,
        signal: Option<i32>,
        spawn_error: Option<String>,
    }

    #[derive(Debug)]
    struct TopologyAuth {
        peer_pid: i32,
        peer_uid: u32,
        peer_gid: u32,
        peer_exe: PathBuf,
        peer_id: FileId,
    }

    struct StdioFds {
        stdin: OwnedFd,
        stdout: OwnedFd,
        stderr: OwnedFd,
    }

    struct PtyPair {
        master: RawFd,
        slave_path: PathBuf,
    }

    pub fn main() {
        if let Err(err) = run() {
            eprintln!("nono-landlock-expansion-harness: {err}");
            std::process::exit(1);
        }
    }

    fn run() -> Result<()> {
        let started = Instant::now();
        let args = Args::parse();

        if let Some(role) = args.topology_role.as_deref() {
            return run_topology_role(role, &args);
        }

        if args.tty_signal_smoke {
            return run_tty_signal_smoke(&args);
        }

        if args.tty_job_control_smoke {
            return run_tty_job_control_smoke(&args);
        }

        if args.chain_credential_smoke {
            return run_chain_credential_smoke(&args);
        }

        if args.command_pty_bridge_smoke {
            return run_command_pty_bridge_smoke(&args);
        }

        if try_run_auto_shim(&args)? {
            return Ok(());
        }

        if args.stdio_fd_smoke {
            return run_stdio_fd_smoke(&args);
        }

        if let Some(policy_binary) = args.topology_smoke.as_ref() {
            return run_topology_smoke(&args, policy_binary);
        }

        let abi = Sandbox::detect_abi()?;

        let scan_started = Instant::now();
        let scan = scan_inputs(&args)?;
        let scan_elapsed = scan_started.elapsed();

        let mut build_elapsed = None;
        let mut restrict_elapsed = None;
        let mut probes = Vec::new();
        let should_apply = args.apply && !args.dry_run;

        if should_apply {
            let build_started = Instant::now();
            let ruleset = build_ruleset(&abi.abi, &scan)?;
            build_elapsed = Some(build_started.elapsed());

            let restrict_started = Instant::now();
            let status = ruleset
                .restrict_self()
                .map_err(|err| NonoError::SandboxInit(format!("restrict_self failed: {err}")))?;
            restrict_elapsed = Some(restrict_started.elapsed());

            if !matches!(
                status.ruleset,
                landlock::RulesetStatus::FullyEnforced | landlock::RulesetStatus::PartiallyEnforced
            ) {
                return Err(NonoError::SandboxInit(format!(
                    "Landlock ruleset was not enforced: {:?}",
                    status.ruleset
                )));
            }

            probes = run_probes(&args.probe_allow, &args.probe_deny);
        }

        let timings = TimingSummary {
            scan_ms: millis(scan_elapsed),
            ruleset_build_ms: build_elapsed.map(millis),
            restrict_self_ms: restrict_elapsed.map(millis),
            total_ms: millis(started.elapsed()),
        };

        if args.json {
            print_json(&abi.abi, &scan, timings, probes)?;
        } else {
            print_human(&abi.abi, &scan, &timings, &probes, should_apply);
        }

        Ok(())
    }

    fn run_topology_role(role: &str, args: &Args) -> Result<()> {
        match role {
            "session" => run_topology_session(args),
            "shim" => run_topology_shim(args),
            "command" => run_topology_command(args),
            "stdio-helper" => run_stdio_helper(),
            "tty-helper" => run_tty_helper(),
            "tty-job-helper" => run_tty_job_helper(),
            "command-pty-helper" => run_command_pty_helper(),
            "chain-git-helper" => run_chain_git_helper(),
            "chain-ssh-helper" => run_chain_ssh_helper(),
            other => Err(NonoError::Setup(format!(
                "unknown internal topology role: {other}"
            ))),
        }
    }

    fn try_run_auto_shim(args: &Args) -> Result<bool> {
        if std::env::var_os("NONO_HARNESS_AUTO_SHIM").is_none() {
            return Ok(false);
        }
        if args.topology_role.is_some() {
            return Ok(false);
        }

        let argv0 = std::env::args_os()
            .next()
            .ok_or_else(|| NonoError::Setup("auto shim argv[0] was missing".to_string()))?;
        let command_name = Path::new(&argv0)
            .file_name()
            .ok_or_else(|| {
                NonoError::Setup(format!(
                    "auto shim argv[0] had no file name: {}",
                    Path::new(&argv0).display()
                ))
            })?
            .to_string_lossy()
            .into_owned();
        let env_suffix = env_key_suffix(&command_name);
        let socket = PathBuf::from(required_env("NONO_SUPERVISOR_SOCK")?);
        let policy = PathBuf::from(required_env(&format!("NONO_HARNESS_POLICY_{env_suffix}"))?);
        let helper_role = Some(required_env(&format!("NONO_HARNESS_HELPER_{env_suffix}"))?);
        run_shim_client(&socket, &policy, helper_role)?;
        Ok(true)
    }

    fn run_stdio_fd_smoke(args: &Args) -> Result<()> {
        let current_exe = std::env::current_exe().map_err(|err| {
            NonoError::Setup(format!("failed to locate current executable: {err}"))
        })?;
        run_topology_smoke_config(
            &args,
            &current_exe,
            Some("stdio-helper".to_string()),
            Some(STDIO_PROOF_INPUT.to_vec()),
        )
    }

    fn run_tty_signal_smoke(args: &Args) -> Result<()> {
        let started = Instant::now();
        let current_exe = std::env::current_exe().map_err(|err| {
            NonoError::Setup(format!("failed to locate current executable: {err}"))
        })?;
        let policy = canonicalize_file(&current_exe)?;
        let temp_dir = tempfile::tempdir()
            .map_err(|err| NonoError::Setup(format!("failed to create temp dir: {err}")))?;
        let socket_path = temp_dir.path().join("supervisor.sock");
        let shim_name = policy.file_name().ok_or_else(|| {
            NonoError::Setup(format!(
                "policy path has no file name: {}",
                policy.display()
            ))
        })?;
        let shim_path = temp_dir.path().join(shim_name).with_extension("shim");
        materialize_shim(&current_exe, &shim_path)?;
        let trusted_shim_id = file_id(&fs::metadata(&shim_path).map_err(|err| {
            NonoError::Setup(format!(
                "failed to stat trusted shim {}: {err}",
                shim_path.display()
            ))
        })?);

        let pty = open_pty_pair()?;
        let listener = UnixListener::bind(&socket_path).map_err(|err| {
            NonoError::Setup(format!(
                "failed to bind supervisor socket {}: {err}",
                socket_path.display()
            ))
        })?;
        listener.set_nonblocking(true).map_err(|err| {
            NonoError::Setup(format!(
                "failed to make supervisor socket nonblocking: {err}"
            ))
        })?;

        let stdin_fd = open_pty_slave(&pty.slave_path)?;
        let stdout_fd = open_pty_slave(&pty.slave_path)?;
        let stderr_fd = open_pty_slave(&pty.slave_path)?;

        let mut session_command = Command::new(&current_exe);
        session_command
            .arg("--topology-role")
            .arg("session")
            .arg("--topology-socket")
            .arg(&socket_path)
            .arg("--topology-policy")
            .arg(&policy)
            .arg("--topology-shim")
            .arg(&shim_path)
            .arg("--topology-helper-role")
            .arg("tty-helper")
            .arg("--exclude")
            .arg(&policy)
            .args(flatten_repeated("--exec-dir", &args.exec_dirs))
            .args(flatten_repeated("--support-dir", &args.support_dirs))
            .args(flatten_repeated("--support-file", &args.support_files))
            // SAFETY: These fds were opened specifically for the child stdio slots and are
            // transferred into File ownership exactly once here.
            .stdin(Stdio::from(unsafe { File::from_raw_fd(stdin_fd) }))
            .stdout(Stdio::from(unsafe { File::from_raw_fd(stdout_fd) }))
            .stderr(Stdio::from(unsafe { File::from_raw_fd(stderr_fd) }));
        // SAFETY: pre_exec runs in the session child after fork and before exec. The closure only
        // calls async-signal-safe libc functions to establish the PTY as the child's controlling
        // terminal.
        unsafe {
            session_command.pre_exec(|| {
                if nix::libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if nix::libc::ioctl(nix::libc::STDIN_FILENO, nix::libc::TIOCSCTTY, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let pgrp = nix::libc::getpgrp();
                if nix::libc::tcsetpgrp(nix::libc::STDIN_FILENO, pgrp) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let mut session = session_command
            .spawn()
            .map_err(|err| NonoError::Setup(format!("failed to spawn session child: {err}")))?;
        let mut stream = accept_shim_connection(&listener, &mut session)?;
        let auth = authenticate_shim(&stream, trusted_shim_id)?;
        let request: ShimRequest = read_json_line(&mut stream)?;
        write_json_line(
            &mut stream,
            &ShimFdRequest {
                send_stdio_fds: true,
            },
        )?;
        let mut child = match recv_stdio_fds(&stream) {
            Ok(stdio_fds) => spawn_supervised_command(
                &current_exe,
                &policy,
                request.helper_role.as_deref(),
                stdio_fds,
            )
            .map_err(|err| NonoError::Setup(format!("failed to spawn command child: {err}")))?,
            Err(err) => {
                return Err(NonoError::Setup(format!(
                    "failed to receive stdio fds: {err}"
                )));
            }
        };
        let grandchild_pid = child_pid_i32(&child)?;
        write_json_line(
            &mut stream,
            &ShimStartMessage {
                grandchild_pid: Some(grandchild_pid),
                spawn_error: None,
            },
        )?;

        let mut transcript = read_fd_until(pty.master, TTY_READY_MARKER, Duration::from_secs(10))?;
        write_all_fd(pty.master, &[0x03])?;
        let response = wait_supervised_command_timeout(&mut child, Duration::from_secs(5));
        write_json_line(&mut stream, &response)?;

        let session_status = session
            .wait()
            .map_err(|err| NonoError::Setup(format!("failed to wait for session child: {err}")))?;
        transcript.extend(read_fd_available(
            pty.master,
            Duration::from_millis(250),
            Duration::from_secs(2),
        )?);
        close_fd(pty.master);

        println!("TTY signal smoke result");
        println!("  policy binary: {}", policy.display());
        println!(
            "  trusted shim: {} [{}:{}]",
            shim_path.display(),
            trusted_shim_id.dev,
            trusted_shim_id.ino
        );
        println!(
            "  peer auth: pid={} uid={} gid={} exe={} [{}:{}]",
            auth.peer_pid,
            auth.peer_uid,
            auth.peer_gid,
            auth.peer_exe.display(),
            auth.peer_id.dev,
            auth.peer_id.ino
        );
        println!("  shim request command: {}", request.command);
        println!("  grandchild pid: {grandchild_pid}");
        println!("  supervised command response: {:?}", response);
        println!("  session child status: {session_status}");
        println!("  PTY transcript bytes: {}", transcript.len());
        println!("  total time: {} ms", millis(started.elapsed()));
        if !transcript.is_empty() {
            println!("--- PTY transcript ---");
            print!("{}", String::from_utf8_lossy(&transcript));
            println!("--- end PTY transcript ---");
        }

        if response.signal != Some(nix::libc::SIGINT) {
            return Err(NonoError::Setup(format!(
                "expected command child to terminate with SIGINT, got {:?}",
                response
            )));
        }
        if !session_status.success() {
            return Err(NonoError::Setup(format!(
                "TTY session failed: {session_status}"
            )));
        }

        Ok(())
    }

    fn run_tty_job_control_smoke(args: &Args) -> Result<()> {
        let started = Instant::now();
        let current_exe = std::env::current_exe().map_err(|err| {
            NonoError::Setup(format!("failed to locate current executable: {err}"))
        })?;
        let policy = canonicalize_file(&current_exe)?;
        let temp_dir = tempfile::tempdir()
            .map_err(|err| NonoError::Setup(format!("failed to create temp dir: {err}")))?;
        let socket_path = temp_dir.path().join("supervisor.sock");
        let shim_name = policy.file_name().ok_or_else(|| {
            NonoError::Setup(format!(
                "policy path has no file name: {}",
                policy.display()
            ))
        })?;
        let shim_path = temp_dir.path().join(shim_name).with_extension("shim");
        materialize_shim(&current_exe, &shim_path)?;
        let trusted_shim_id = file_id(&fs::metadata(&shim_path).map_err(|err| {
            NonoError::Setup(format!(
                "failed to stat trusted shim {}: {err}",
                shim_path.display()
            ))
        })?);

        let pty = open_pty_pair()?;
        let listener = UnixListener::bind(&socket_path).map_err(|err| {
            NonoError::Setup(format!(
                "failed to bind supervisor socket {}: {err}",
                socket_path.display()
            ))
        })?;
        listener.set_nonblocking(true).map_err(|err| {
            NonoError::Setup(format!(
                "failed to make supervisor socket nonblocking: {err}"
            ))
        })?;

        let stdin_fd = open_pty_slave(&pty.slave_path)?;
        let stdout_fd = open_pty_slave(&pty.slave_path)?;
        let stderr_fd = open_pty_slave(&pty.slave_path)?;

        let mut session_command = Command::new(&current_exe);
        session_command
            .arg("--topology-role")
            .arg("session")
            .arg("--topology-socket")
            .arg(&socket_path)
            .arg("--topology-policy")
            .arg(&policy)
            .arg("--topology-shim")
            .arg(&shim_path)
            .arg("--topology-helper-role")
            .arg("tty-job-helper")
            .arg("--exclude")
            .arg(&policy)
            .args(flatten_repeated("--exec-dir", &args.exec_dirs))
            .args(flatten_repeated("--support-dir", &args.support_dirs))
            .args(flatten_repeated("--support-file", &args.support_files))
            // SAFETY: These fds were opened specifically for the child stdio slots and are
            // transferred into File ownership exactly once here.
            .stdin(Stdio::from(unsafe { File::from_raw_fd(stdin_fd) }))
            .stdout(Stdio::from(unsafe { File::from_raw_fd(stdout_fd) }))
            .stderr(Stdio::from(unsafe { File::from_raw_fd(stderr_fd) }));
        // SAFETY: pre_exec runs in the session child after fork and before exec. The closure only
        // calls async-signal-safe libc functions to establish the PTY as the child's controlling
        // terminal.
        unsafe {
            session_command.pre_exec(|| {
                if nix::libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if nix::libc::ioctl(nix::libc::STDIN_FILENO, nix::libc::TIOCSCTTY, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let pgrp = nix::libc::getpgrp();
                if nix::libc::tcsetpgrp(nix::libc::STDIN_FILENO, pgrp) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let mut session = session_command
            .spawn()
            .map_err(|err| NonoError::Setup(format!("failed to spawn session child: {err}")))?;
        let mut stream = accept_shim_connection(&listener, &mut session)?;
        let auth = authenticate_shim(&stream, trusted_shim_id)?;
        let request: ShimRequest = read_json_line(&mut stream)?;
        write_json_line(
            &mut stream,
            &ShimFdRequest {
                send_stdio_fds: true,
            },
        )?;
        let mut child = match recv_stdio_fds(&stream) {
            Ok(stdio_fds) => spawn_supervised_command(
                &current_exe,
                &policy,
                request.helper_role.as_deref(),
                stdio_fds,
            )
            .map_err(|err| NonoError::Setup(format!("failed to spawn command child: {err}")))?,
            Err(err) => {
                return Err(NonoError::Setup(format!(
                    "failed to receive stdio fds: {err}"
                )));
            }
        };
        let grandchild_pid = child_pid_i32(&child)?;
        write_json_line(
            &mut stream,
            &ShimStartMessage {
                grandchild_pid: Some(grandchild_pid),
                spawn_error: None,
            },
        )?;

        let mut transcript = Vec::new();
        read_fd_until_accumulate(
            pty.master,
            &mut transcript,
            b"tty-job-helper-ready",
            Duration::from_secs(10),
        )?;
        set_pty_winsize(pty.master, 41, 101)?;
        read_fd_until_accumulate(
            pty.master,
            &mut transcript,
            b"tty-job-helper-signal: SIGWINCH",
            Duration::from_secs(5),
        )?;
        write_all_fd(pty.master, &[0x1A])?;
        read_fd_until_accumulate(
            pty.master,
            &mut transcript,
            b"tty-job-helper-signal: SIGTSTP",
            Duration::from_secs(5),
        )?;
        send_signal(auth.peer_pid, nix::libc::SIGCONT)?;
        read_fd_until_accumulate(
            pty.master,
            &mut transcript,
            b"tty-job-helper-signal: SIGCONT",
            Duration::from_secs(5),
        )?;
        write_all_fd(pty.master, &[0x03])?;
        let response = wait_supervised_command_timeout(&mut child, Duration::from_secs(5));
        write_json_line(&mut stream, &response)?;

        let session_status = session
            .wait()
            .map_err(|err| NonoError::Setup(format!("failed to wait for session child: {err}")))?;
        transcript.extend(read_fd_available(
            pty.master,
            Duration::from_millis(250),
            Duration::from_secs(2),
        )?);
        close_fd(pty.master);

        println!("TTY job-control smoke result");
        println!("  policy binary: {}", policy.display());
        println!(
            "  trusted shim: {} [{}:{}]",
            shim_path.display(),
            trusted_shim_id.dev,
            trusted_shim_id.ino
        );
        println!(
            "  peer auth: pid={} uid={} gid={} exe={} [{}:{}]",
            auth.peer_pid,
            auth.peer_uid,
            auth.peer_gid,
            auth.peer_exe.display(),
            auth.peer_id.dev,
            auth.peer_id.ino
        );
        println!("  shim request command: {}", request.command);
        println!("  grandchild pid: {grandchild_pid}");
        println!("  supervised command response: {:?}", response);
        println!("  session child status: {session_status}");
        println!("  PTY transcript bytes: {}", transcript.len());
        println!("  total time: {} ms", millis(started.elapsed()));
        if !transcript.is_empty() {
            println!("--- PTY transcript ---");
            print!("{}", String::from_utf8_lossy(&transcript));
            println!("--- end PTY transcript ---");
        }

        for marker in [
            b"tty-job-helper-signal: SIGWINCH".as_slice(),
            b"tty-job-helper-signal: SIGTSTP".as_slice(),
            b"tty-job-helper-signal: SIGCONT".as_slice(),
        ] {
            if !contains_subslice(&transcript, marker) {
                return Err(NonoError::Setup(format!(
                    "missing expected PTY marker: {}",
                    String::from_utf8_lossy(marker)
                )));
            }
        }
        if response.signal != Some(nix::libc::SIGINT) {
            return Err(NonoError::Setup(format!(
                "expected command child to terminate with SIGINT, got {:?}",
                response
            )));
        }
        if !session_status.success() {
            return Err(NonoError::Setup(format!(
                "TTY job-control session failed: {session_status}"
            )));
        }

        Ok(())
    }

    fn run_chain_credential_smoke(args: &Args) -> Result<()> {
        let started = Instant::now();
        let current_exe = std::env::current_exe().map_err(|err| {
            NonoError::Setup(format!("failed to locate current executable: {err}"))
        })?;
        let socket_dir = tempfile::tempdir()
            .map_err(|err| NonoError::Setup(format!("failed to create socket temp dir: {err}")))?;
        let real_temp = tempfile::tempdir()
            .map_err(|err| NonoError::Setup(format!("failed to create real temp dir: {err}")))?;
        let shim_temp = tempfile::tempdir()
            .map_err(|err| NonoError::Setup(format!("failed to create shim temp dir: {err}")))?;
        let raw_dir = tempfile::tempdir()
            .map_err(|err| NonoError::Setup(format!("failed to create raw-key temp dir: {err}")))?;
        let real_dir = real_temp.path().to_path_buf();
        let shim_dir = shim_temp.path().to_path_buf();

        let git_real = real_dir.join("git-real");
        let ssh_real = real_dir.join("ssh-real");
        materialize_shim(&current_exe, &git_real)?;
        materialize_shim(&current_exe, &ssh_real)?;

        let git_shim = shim_dir.join("git");
        let ssh_shim = shim_dir.join("ssh");
        materialize_shim(&current_exe, &git_shim)?;
        fs::hard_link(&git_shim, &ssh_shim).map_err(|err| {
            NonoError::Setup(format!(
                "failed to hard-link ssh shim {} -> {}: {err}",
                ssh_shim.display(),
                git_shim.display()
            ))
        })?;

        let trusted_shim_id = file_id(&fs::metadata(&git_shim).map_err(|err| {
            NonoError::Setup(format!(
                "failed to stat trusted shim {}: {err}",
                git_shim.display()
            ))
        })?);
        let ssh_shim_id = file_id(&fs::metadata(&ssh_shim).map_err(|err| {
            NonoError::Setup(format!(
                "failed to stat ssh shim {}: {err}",
                ssh_shim.display()
            ))
        })?);
        if ssh_shim_id != trusted_shim_id {
            return Err(NonoError::Setup(
                "git and ssh shims do not share the trusted inode".to_string(),
            ));
        }

        let raw_key = raw_dir.path().join("id_rsa");
        fs::write(&raw_key, b"not-a-real-private-key\n").map_err(|err| {
            NonoError::Setup(format!(
                "failed to write raw key {}: {err}",
                raw_key.display()
            ))
        })?;
        let socket_path = socket_dir.path().join("supervisor.sock");
        let agent_sock = socket_dir.path().join("ssh-agent.sock");
        let _agent_listener = UnixListener::bind(&agent_sock).map_err(|err| {
            NonoError::Setup(format!(
                "failed to bind fake ssh-agent socket {}: {err}",
                agent_sock.display()
            ))
        })?;
        let listener = UnixListener::bind(&socket_path).map_err(|err| {
            NonoError::Setup(format!(
                "failed to bind supervisor socket {}: {err}",
                socket_path.display()
            ))
        })?;
        listener.set_nonblocking(true).map_err(|err| {
            NonoError::Setup(format!(
                "failed to make supervisor socket nonblocking: {err}"
            ))
        })?;

        let mut session_command = Command::new(&current_exe);
        session_command
            .arg("--topology-role")
            .arg("session")
            .arg("--topology-socket")
            .arg(&socket_path)
            .arg("--topology-policy")
            .arg(&git_real)
            .arg("--topology-shim")
            .arg(&git_shim)
            .arg("--topology-helper-role")
            .arg("chain-git-helper")
            .arg("--exclude")
            .arg(&git_real)
            .arg("--exclude")
            .arg(&ssh_real)
            .arg("--exec-dir")
            .arg(&real_dir)
            .args(flatten_repeated("--exec-dir", &args.exec_dirs))
            .args(flatten_repeated("--support-dir", &args.support_dirs))
            .args(flatten_repeated("--support-file", &args.support_files))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut session = session_command
            .spawn()
            .map_err(|err| NonoError::Setup(format!("failed to spawn session child: {err}")))?;
        let stdout_reader = session
            .stdout
            .take()
            .ok_or_else(|| NonoError::Setup("failed to capture session stdout pipe".to_string()))?;
        let stderr_reader = session
            .stderr
            .take()
            .ok_or_else(|| NonoError::Setup("failed to capture session stderr pipe".to_string()))?;
        let stdout_handle = thread::spawn(move || read_pipe_to_end(stdout_reader));
        let stderr_handle = thread::spawn(move || read_pipe_to_end(stderr_reader));

        let mut git_stream = accept_shim_connection(&listener, &mut session)?;
        let git_auth = authenticate_shim(&git_stream, trusted_shim_id)?;
        let git_request: ShimRequest = read_json_line(&mut git_stream)?;
        write_json_line(
            &mut git_stream,
            &ShimFdRequest {
                send_stdio_fds: true,
            },
        )?;
        let git_stdio = recv_stdio_fds(&git_stream)?;
        let chain_env = chain_env(&shim_dir, &socket_path, &ssh_real, &raw_key, &agent_sock);
        let mut git_child = spawn_supervised_command_with_context(
            &current_exe,
            &git_real,
            git_request.helper_role.as_deref(),
            git_stdio,
            Some(&socket_path),
            Some(&shim_dir),
            &chain_env,
            false,
        )
        .map_err(|err| NonoError::Setup(format!("failed to spawn git command child: {err}")))?;
        let git_pid = child_pid_i32(&git_child)?;
        write_json_line(
            &mut git_stream,
            &ShimStartMessage {
                grandchild_pid: Some(git_pid),
                spawn_error: None,
            },
        )?;

        let mut ssh_stream =
            accept_shim_connection_with_child(&listener, &mut session, &mut git_child)?;
        let ssh_auth = authenticate_shim(&ssh_stream, trusted_shim_id)?;
        let ssh_request: ShimRequest = read_json_line(&mut ssh_stream)?;
        let ancestry_ok = ancestry_contains(ssh_auth.peer_pid, git_pid)?;
        if !ancestry_ok {
            return Err(NonoError::Setup(format!(
                "ssh shim pid {} did not have git command pid {git_pid} in its ancestry",
                ssh_auth.peer_pid
            )));
        }
        write_json_line(
            &mut ssh_stream,
            &ShimFdRequest {
                send_stdio_fds: true,
            },
        )?;
        let ssh_stdio = recv_stdio_fds(&ssh_stream)?;
        let mut ssh_child = spawn_supervised_command_with_context(
            &current_exe,
            &ssh_real,
            ssh_request.helper_role.as_deref(),
            ssh_stdio,
            Some(&socket_path),
            Some(&shim_dir),
            &chain_env,
            false,
        )
        .map_err(|err| NonoError::Setup(format!("failed to spawn ssh command child: {err}")))?;
        let ssh_pid = child_pid_i32(&ssh_child)?;
        write_json_line(
            &mut ssh_stream,
            &ShimStartMessage {
                grandchild_pid: Some(ssh_pid),
                spawn_error: None,
            },
        )?;
        let ssh_response = wait_supervised_command(&mut ssh_child);
        write_json_line(&mut ssh_stream, &ssh_response)?;

        let git_response = wait_supervised_command(&mut git_child);
        write_json_line(&mut git_stream, &git_response)?;

        let session_status = session
            .wait()
            .map_err(|err| NonoError::Setup(format!("failed to wait for session child: {err}")))?;
        let session_stdout = join_pipe_reader(stdout_handle, "stdout")?;
        let session_stderr = join_pipe_reader(stderr_handle, "stderr")?;

        println!("Chain credential smoke result");
        println!("  git real: {}", git_real.display());
        println!("  ssh real: {}", ssh_real.display());
        println!(
            "  trusted shim inode: {} [{}:{}]",
            git_shim.display(),
            trusted_shim_id.dev,
            trusted_shim_id.ino
        );
        println!(
            "  git peer auth: pid={} exe={} [{}:{}]",
            git_auth.peer_pid,
            git_auth.peer_exe.display(),
            git_auth.peer_id.dev,
            git_auth.peer_id.ino
        );
        println!(
            "  ssh peer auth: pid={} exe={} [{}:{}]",
            ssh_auth.peer_pid,
            ssh_auth.peer_exe.display(),
            ssh_auth.peer_id.dev,
            ssh_auth.peer_id.ino
        );
        println!("  git command pid: {git_pid}");
        println!("  ssh command pid: {ssh_pid}");
        println!("  ssh ancestry contains git pid: {ancestry_ok}");
        println!("  git request command: {}", git_request.command);
        println!("  ssh request command: {}", ssh_request.command);
        println!("  ssh response: {:?}", ssh_response);
        println!("  git response: {:?}", git_response);
        println!("  session child status: {session_status}");
        println!("  captured session stdout bytes: {}", session_stdout.len());
        println!("  captured session stderr bytes: {}", session_stderr.len());
        println!("  total time: {} ms", millis(started.elapsed()));
        if !session_stdout.is_empty() {
            println!("--- captured session stdout ---");
            print!("{}", String::from_utf8_lossy(&session_stdout));
            println!("--- end captured session stdout ---");
        }
        if !session_stderr.is_empty() {
            println!("--- captured session stderr ---");
            print!("{}", String::from_utf8_lossy(&session_stderr));
            println!("--- end captured session stderr ---");
        }

        let stdout_text = String::from_utf8_lossy(&session_stdout);
        for marker in [
            "chain-git-helper-raw-key: denied",
            "chain-ssh-helper-raw-key: denied",
            "chain-ssh-helper-agent: connected",
            "chain-git-helper-ssh-status: 0",
        ] {
            if !stdout_text.contains(marker) {
                return Err(NonoError::Setup(format!(
                    "missing expected chain marker: {marker}"
                )));
            }
        }
        if ssh_response.exit_code != Some(0) || git_response.exit_code != Some(0) {
            return Err(NonoError::Setup(format!(
                "expected git and ssh command helpers to exit 0, got git={git_response:?} ssh={ssh_response:?}"
            )));
        }
        if !session_status.success() {
            return Err(NonoError::Setup(format!(
                "chain session failed: {session_status}"
            )));
        }

        Ok(())
    }

    fn run_command_pty_bridge_smoke(args: &Args) -> Result<()> {
        let started = Instant::now();
        let current_exe = std::env::current_exe().map_err(|err| {
            NonoError::Setup(format!("failed to locate current executable: {err}"))
        })?;
        let policy = canonicalize_file(&current_exe)?;
        let temp_dir = tempfile::tempdir()
            .map_err(|err| NonoError::Setup(format!("failed to create temp dir: {err}")))?;
        let socket_path = temp_dir.path().join("supervisor.sock");
        let shim_name = policy.file_name().ok_or_else(|| {
            NonoError::Setup(format!(
                "policy path has no file name: {}",
                policy.display()
            ))
        })?;
        let shim_path = temp_dir.path().join(shim_name).with_extension("shim");
        materialize_shim(&current_exe, &shim_path)?;
        let trusted_shim_id = file_id(&fs::metadata(&shim_path).map_err(|err| {
            NonoError::Setup(format!(
                "failed to stat trusted shim {}: {err}",
                shim_path.display()
            ))
        })?);

        let listener = UnixListener::bind(&socket_path).map_err(|err| {
            NonoError::Setup(format!(
                "failed to bind supervisor socket {}: {err}",
                socket_path.display()
            ))
        })?;
        listener.set_nonblocking(true).map_err(|err| {
            NonoError::Setup(format!(
                "failed to make supervisor socket nonblocking: {err}"
            ))
        })?;

        let mut session_command = Command::new(&current_exe);
        session_command
            .arg("--topology-role")
            .arg("session")
            .arg("--topology-socket")
            .arg(&socket_path)
            .arg("--topology-policy")
            .arg(&policy)
            .arg("--topology-shim")
            .arg(&shim_path)
            .arg("--topology-helper-role")
            .arg("command-pty-helper")
            .arg("--exclude")
            .arg(&policy)
            .args(flatten_repeated("--exec-dir", &args.exec_dirs))
            .args(flatten_repeated("--support-dir", &args.support_dirs))
            .args(flatten_repeated("--support-file", &args.support_files))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut session = session_command
            .spawn()
            .map_err(|err| NonoError::Setup(format!("failed to spawn session child: {err}")))?;
        let stdout_reader = session
            .stdout
            .take()
            .ok_or_else(|| NonoError::Setup("failed to capture session stdout pipe".to_string()))?;
        let stderr_reader = session
            .stderr
            .take()
            .ok_or_else(|| NonoError::Setup("failed to capture session stderr pipe".to_string()))?;
        let stdout_handle = thread::spawn(move || read_pipe_to_end(stdout_reader));
        let stderr_handle = thread::spawn(move || read_pipe_to_end(stderr_reader));

        let mut stream = accept_shim_connection(&listener, &mut session)?;
        let auth = authenticate_shim(&stream, trusted_shim_id)?;
        let request: ShimRequest = read_json_line(&mut stream)?;
        write_json_line(
            &mut stream,
            &ShimFdRequest {
                send_stdio_fds: true,
            },
        )?;
        let StdioFds {
            stdin: shim_stdin,
            stdout: shim_stdout,
            stderr: shim_stderr,
        } = recv_stdio_fds(&stream)?;

        let command_pty = open_pty_pair()?;
        let command_stdin_fd = open_pty_slave(&command_pty.slave_path)?;
        let command_stdout_fd = open_pty_slave(&command_pty.slave_path)?;
        let command_stderr_fd = open_pty_slave(&command_pty.slave_path)?;
        let command_stdio = StdioFds {
            // SAFETY: each fd was freshly opened for this command stdio set and is transferred
            // into OwnedFd exactly once here.
            stdin: unsafe { OwnedFd::from_raw_fd(command_stdin_fd) },
            // SAFETY: see stdin field above.
            stdout: unsafe { OwnedFd::from_raw_fd(command_stdout_fd) },
            // SAFETY: see stdin field above.
            stderr: unsafe { OwnedFd::from_raw_fd(command_stderr_fd) },
        };

        let mut child = spawn_supervised_command_with_context(
            &current_exe,
            &policy,
            request.helper_role.as_deref(),
            command_stdio,
            None,
            None,
            &[],
            true,
        )
        .map_err(|err| NonoError::Setup(format!("failed to spawn command child: {err}")))?;
        let grandchild_pid = child_pid_i32(&child)?;
        write_json_line(
            &mut stream,
            &ShimStartMessage {
                grandchild_pid: Some(grandchild_pid),
                spawn_error: None,
            },
        )?;

        let mut command_transcript = read_fd_until(
            command_pty.master,
            COMMAND_PTY_READY_MARKER,
            Duration::from_secs(10),
        )?;
        command_transcript.extend(read_fd_available(
            command_pty.master,
            Duration::from_millis(50),
            Duration::from_millis(500),
        )?);
        write_all_fd(shim_stdout.as_raw_fd(), &command_transcript)?;
        let response = wait_supervised_command_timeout(&mut child, Duration::from_secs(5));
        close_fd(command_pty.master);
        write_json_line(&mut stream, &response)?;
        drop(shim_stdin);
        drop(shim_stdout);
        drop(shim_stderr);

        let session_status = session
            .wait()
            .map_err(|err| NonoError::Setup(format!("failed to wait for session child: {err}")))?;
        let session_stdout = join_pipe_reader(stdout_handle, "stdout")?;
        let session_stderr = join_pipe_reader(stderr_handle, "stderr")?;

        println!("Command PTY bridge smoke result");
        println!("  policy binary: {}", policy.display());
        println!(
            "  trusted shim: {} [{}:{}]",
            shim_path.display(),
            trusted_shim_id.dev,
            trusted_shim_id.ino
        );
        println!(
            "  peer auth: pid={} uid={} gid={} exe={} [{}:{}]",
            auth.peer_pid,
            auth.peer_uid,
            auth.peer_gid,
            auth.peer_exe.display(),
            auth.peer_id.dev,
            auth.peer_id.ino
        );
        println!("  shim request command: {}", request.command);
        println!("  grandchild pid: {grandchild_pid}");
        println!("  supervised command response: {:?}", response);
        println!("  session child status: {session_status}");
        println!(
            "  command PTY transcript bytes: {}",
            command_transcript.len()
        );
        println!("  captured session stdout bytes: {}", session_stdout.len());
        println!("  captured session stderr bytes: {}", session_stderr.len());
        println!("  total time: {} ms", millis(started.elapsed()));
        if !command_transcript.is_empty() {
            println!("--- command PTY transcript ---");
            print!("{}", String::from_utf8_lossy(&command_transcript));
            println!("--- end command PTY transcript ---");
        }
        if !session_stdout.is_empty() {
            println!("--- captured session stdout ---");
            print!("{}", String::from_utf8_lossy(&session_stdout));
            println!("--- end captured session stdout ---");
        }
        if !session_stderr.is_empty() {
            println!("--- captured session stderr ---");
            print!("{}", String::from_utf8_lossy(&session_stderr));
            println!("--- end captured session stderr ---");
        }

        let stdout_text = String::from_utf8_lossy(&session_stdout);
        for marker in [
            "topology-session: direct policy exec matched=true",
            "command-pty-helper-isatty-stdin: true",
            "command-pty-helper-ready",
        ] {
            if !stdout_text.contains(marker) {
                return Err(NonoError::Setup(format!(
                    "missing expected command PTY marker: {marker}"
                )));
            }
        }
        if !stdout_text.contains("tcgetpgrp=") || stdout_text.contains("tcgetpgrp=error") {
            return Err(NonoError::Setup(format!(
                "command helper did not observe a controlling terminal: {stdout_text}"
            )));
        }
        if response.exit_code != Some(0)
            || response.signal.is_some()
            || response.spawn_error.is_some()
        {
            return Err(NonoError::Setup(format!(
                "expected command PTY helper to exit 0, got {response:?}"
            )));
        }
        if !session_status.success() {
            return Err(NonoError::Setup(format!(
                "command PTY bridge session failed: {session_status}"
            )));
        }

        Ok(())
    }

    fn run_topology_smoke(args: &Args, policy_binary: &Path) -> Result<()> {
        run_topology_smoke_config(args, policy_binary, None, None)
    }

    fn run_topology_smoke_config(
        args: &Args,
        policy_binary: &Path,
        helper_role: Option<String>,
        stdin_payload: Option<Vec<u8>>,
    ) -> Result<()> {
        let started = Instant::now();
        let policy = canonicalize_file(policy_binary)?;
        let temp_dir = tempfile::tempdir()
            .map_err(|err| NonoError::Setup(format!("failed to create temp dir: {err}")))?;
        let socket_path = temp_dir.path().join("supervisor.sock");
        let shim_name = policy.file_name().ok_or_else(|| {
            NonoError::Setup(format!(
                "policy path has no file name: {}",
                policy.display()
            ))
        })?;
        let shim_path = temp_dir.path().join(shim_name).with_extension("shim");
        let current_exe = std::env::current_exe().map_err(|err| {
            NonoError::Setup(format!("failed to locate current executable: {err}"))
        })?;

        materialize_shim(&current_exe, &shim_path)?;

        let trusted_shim_id = file_id(&fs::metadata(&shim_path).map_err(|err| {
            NonoError::Setup(format!(
                "failed to stat trusted shim {}: {err}",
                shim_path.display()
            ))
        })?);

        let listener = UnixListener::bind(&socket_path).map_err(|err| {
            NonoError::Setup(format!(
                "failed to bind supervisor socket {}: {err}",
                socket_path.display()
            ))
        })?;
        listener.set_nonblocking(true).map_err(|err| {
            NonoError::Setup(format!(
                "failed to make supervisor socket nonblocking: {err}"
            ))
        })?;

        let mut session_command = Command::new(&current_exe);
        session_command
            .arg("--topology-role")
            .arg("session")
            .arg("--topology-socket")
            .arg(&socket_path)
            .arg("--topology-policy")
            .arg(&policy)
            .arg("--topology-shim")
            .arg(&shim_path)
            .arg("--exclude")
            .arg(&policy)
            .args(flatten_repeated("--exec-dir", &args.exec_dirs))
            .args(flatten_repeated("--support-dir", &args.support_dirs))
            .args(flatten_repeated("--support-file", &args.support_files))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(role) = helper_role.as_deref() {
            session_command.arg("--topology-helper-role").arg(role);
        }
        if stdin_payload.is_some() {
            session_command.stdin(Stdio::piped());
        }

        let mut session = session_command
            .spawn()
            .map_err(|err| NonoError::Setup(format!("failed to spawn session child: {err}")))?;
        if let Some(payload) = stdin_payload {
            let mut session_stdin = session.stdin.take().ok_or_else(|| {
                NonoError::Setup("failed to capture session stdin pipe".to_string())
            })?;
            session_stdin.write_all(&payload).map_err(|err| {
                NonoError::Setup(format!(
                    "failed to write session stdin proof payload: {err}"
                ))
            })?;
        }
        let stdout_reader = session
            .stdout
            .take()
            .ok_or_else(|| NonoError::Setup("failed to capture session stdout pipe".to_string()))?;
        let stderr_reader = session
            .stderr
            .take()
            .ok_or_else(|| NonoError::Setup("failed to capture session stderr pipe".to_string()))?;
        let stdout_handle = thread::spawn(move || read_pipe_to_end(stdout_reader));
        let stderr_handle = thread::spawn(move || read_pipe_to_end(stderr_reader));

        let mut accepted = None;
        let accept_deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < accept_deadline {
            match listener.accept() {
                Ok((stream, _addr)) => {
                    accepted = Some(stream);
                    break;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if let Some(status) = session.try_wait().map_err(|err| {
                        NonoError::Setup(format!("failed to poll session child: {err}"))
                    })? {
                        return Err(NonoError::Setup(format!(
                            "session child exited before shim connected: {status}"
                        )));
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => {
                    return Err(NonoError::Setup(format!(
                        "failed to accept shim connection: {err}"
                    )));
                }
            }
        }

        let mut stream = accepted
            .ok_or_else(|| NonoError::Setup("timed out waiting for shim connection".to_string()))?;
        let auth = authenticate_shim(&stream, trusted_shim_id)?;
        let request: ShimRequest = read_json_line(&mut stream)?;
        write_json_line(
            &mut stream,
            &ShimFdRequest {
                send_stdio_fds: true,
            },
        )?;
        let mut child_started = false;
        let response = match recv_stdio_fds(&stream) {
            Ok(stdio_fds) => match spawn_supervised_command(
                &current_exe,
                &policy,
                request.helper_role.as_deref(),
                stdio_fds,
            ) {
                Ok(mut child) => {
                    let pid = child_pid_i32(&child)?;
                    child_started = true;
                    write_json_line(
                        &mut stream,
                        &ShimStartMessage {
                            grandchild_pid: Some(pid),
                            spawn_error: None,
                        },
                    )?;
                    wait_supervised_command(&mut child)
                }
                Err(error) => {
                    write_json_line(
                        &mut stream,
                        &ShimStartMessage {
                            grandchild_pid: None,
                            spawn_error: Some(error.clone()),
                        },
                    )?;
                    ShimResponse {
                        exit_code: None,
                        signal: None,
                        spawn_error: Some(error),
                    }
                }
            },
            Err(err) => {
                let error = format!("failed to receive stdio fds: {err}");
                write_json_line(
                    &mut stream,
                    &ShimStartMessage {
                        grandchild_pid: None,
                        spawn_error: Some(error.clone()),
                    },
                )?;
                ShimResponse {
                    exit_code: None,
                    signal: None,
                    spawn_error: Some(error),
                }
            }
        };
        if child_started {
            write_json_line(&mut stream, &response)?;
        }

        let session_status = session
            .wait()
            .map_err(|err| NonoError::Setup(format!("failed to wait for session child: {err}")))?;
        let session_stdout = join_pipe_reader(stdout_handle, "stdout")?;
        let session_stderr = join_pipe_reader(stderr_handle, "stderr")?;

        println!("Topology smoke result");
        println!("  policy binary: {}", policy.display());
        println!(
            "  trusted shim: {} [{}:{}]",
            shim_path.display(),
            trusted_shim_id.dev,
            trusted_shim_id.ino
        );
        println!(
            "  peer auth: pid={} uid={} gid={} exe={} [{}:{}]",
            auth.peer_pid,
            auth.peer_uid,
            auth.peer_gid,
            auth.peer_exe.display(),
            auth.peer_id.dev,
            auth.peer_id.ino
        );
        println!("  shim request command: {}", request.command);
        println!("  supervised command response: {:?}", response);
        println!("  session child status: {session_status}");
        println!("  captured session stdout bytes: {}", session_stdout.len());
        println!("  captured session stderr bytes: {}", session_stderr.len());
        println!("  total time: {} ms", millis(started.elapsed()));

        if !session_stdout.is_empty() {
            println!("--- captured session stdout ---");
            print!("{}", String::from_utf8_lossy(&session_stdout));
            println!("--- end captured session stdout ---");
        }
        if !session_stderr.is_empty() {
            println!("--- captured session stderr ---");
            print!("{}", String::from_utf8_lossy(&session_stderr));
            println!("--- end captured session stderr ---");
        }

        if !session_status.success() {
            return Err(NonoError::Setup(format!(
                "topology session failed: {session_status}"
            )));
        }
        if response.spawn_error.is_some() {
            return Err(NonoError::Setup(
                "supervisor failed to spawn command child".to_string(),
            ));
        }

        Ok(())
    }

    fn materialize_shim(source: &Path, shim_path: &Path) -> Result<()> {
        fs::copy(source, shim_path).map_err(|err| {
            NonoError::Setup(format!(
                "failed to materialize shim {} from {}: {err}",
                shim_path.display(),
                source.display()
            ))
        })?;
        let mut permissions = fs::metadata(shim_path)
            .map_err(|err| {
                NonoError::Setup(format!(
                    "failed to stat shim {}: {err}",
                    shim_path.display()
                ))
            })?
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(shim_path, permissions).map_err(|err| {
            NonoError::Setup(format!(
                "failed to set shim permissions {}: {err}",
                shim_path.display()
            ))
        })
    }

    fn accept_shim_connection(listener: &UnixListener, session: &mut Child) -> Result<UnixStream> {
        let accept_deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < accept_deadline {
            match listener.accept() {
                Ok((stream, _addr)) => return Ok(stream),
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if let Some(status) = session.try_wait().map_err(|err| {
                        NonoError::Setup(format!("failed to poll session child: {err}"))
                    })? {
                        return Err(NonoError::Setup(format!(
                            "session child exited before shim connected: {status}"
                        )));
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => {
                    return Err(NonoError::Setup(format!(
                        "failed to accept shim connection: {err}"
                    )));
                }
            }
        }

        Err(NonoError::Setup(
            "timed out waiting for shim connection".to_string(),
        ))
    }

    fn accept_shim_connection_with_child(
        listener: &UnixListener,
        session: &mut Child,
        child: &mut Child,
    ) -> Result<UnixStream> {
        let accept_deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < accept_deadline {
            match listener.accept() {
                Ok((stream, _addr)) => return Ok(stream),
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if let Some(status) = session.try_wait().map_err(|err| {
                        NonoError::Setup(format!("failed to poll session child: {err}"))
                    })? {
                        return Err(NonoError::Setup(format!(
                            "session child exited before chained shim connected: {status}"
                        )));
                    }
                    if let Some(status) = child.try_wait().map_err(|err| {
                        NonoError::Setup(format!("failed to poll command child: {err}"))
                    })? {
                        return Err(NonoError::Setup(format!(
                            "command child exited before chained shim connected: {status}"
                        )));
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => {
                    return Err(NonoError::Setup(format!(
                        "failed to accept chained shim connection: {err}"
                    )));
                }
            }
        }

        Err(NonoError::Setup(
            "timed out waiting for chained shim connection".to_string(),
        ))
    }

    fn chain_env(
        shim_dir: &Path,
        socket_path: &Path,
        ssh_real: &Path,
        raw_key: &Path,
        agent_sock: &Path,
    ) -> Vec<(String, String)> {
        vec![
            (
                "PATH".to_string(),
                format!(
                    "{}:{}",
                    shim_dir.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            ),
            ("NONO_HARNESS_AUTO_SHIM".to_string(), "1".to_string()),
            (
                "NONO_SUPERVISOR_SOCK".to_string(),
                socket_path.display().to_string(),
            ),
            (
                "NONO_HARNESS_POLICY_SSH".to_string(),
                ssh_real.display().to_string(),
            ),
            (
                "NONO_HARNESS_HELPER_SSH".to_string(),
                "chain-ssh-helper".to_string(),
            ),
            ("CHAIN_RAW_KEY".to_string(), raw_key.display().to_string()),
            (
                "SSH_AUTH_SOCK".to_string(),
                agent_sock.display().to_string(),
            ),
        ]
    }

    fn run_topology_session(args: &Args) -> Result<()> {
        let abi = Sandbox::detect_abi()?;
        let socket = required_path(&args.topology_socket, "--topology-socket")?;
        let policy = required_path(&args.topology_policy, "--topology-policy")?;
        let shim = required_path(&args.topology_shim, "--topology-shim")?;
        let socket_parent = socket.parent().ok_or_else(|| {
            NonoError::Setup(format!("socket path has no parent: {}", socket.display()))
        })?;

        let scan = scan_inputs(args)?;
        let extra_rules = vec![
            ExtraRule {
                path: shim.clone(),
                access: supported(&abi.abi, AccessFs::ReadFile | AccessFs::Execute),
            },
            ExtraRule {
                path: socket_parent.to_path_buf(),
                access: supported(
                    &abi.abi,
                    AccessFs::ReadFile
                        | AccessFs::ReadDir
                        | AccessFs::Execute
                        | AccessFs::WriteFile
                        | AccessFs::MakeSock,
                ),
            },
        ];
        let ruleset = build_ruleset_with_extra(&abi.abi, &scan, &extra_rules)?;
        restrict_ruleset(ruleset)?;

        let direct_probe = run_probe(&policy, ProbeExpectation::Deny);
        println!(
            "topology-session: direct policy exec matched={}",
            direct_probe.matched
        );
        if !direct_probe.matched {
            return Err(NonoError::Setup(format!(
                "direct policy exec was not denied: {:?}",
                direct_probe.outcome
            )));
        }

        if matches!(
            args.topology_helper_role.as_deref(),
            Some("tty-helper" | "tty-job-helper")
        ) {
            ignore_signal(Signal::SIGINT)?;
            ignore_signal(Signal::SIGQUIT)?;
            ignore_signal(Signal::SIGTSTP)?;
        }

        let shim_status = Command::new(&shim)
            .arg("--topology-role")
            .arg("shim")
            .arg("--topology-socket")
            .arg(&socket)
            .arg("--topology-policy")
            .arg(&policy)
            .args(optional_arg(
                "--topology-helper-role",
                args.topology_helper_role.as_deref(),
            ))
            .status()
            .map_err(|err| {
                NonoError::Setup(format!("failed to spawn shim {}: {err}", shim.display()))
            })?;
        println!("topology-session: shim exited with {shim_status}");

        Ok(())
    }

    fn run_topology_shim(args: &Args) -> Result<()> {
        let socket = required_path(&args.topology_socket, "--topology-socket")?;
        let policy = required_path(&args.topology_policy, "--topology-policy")?;
        run_shim_client(&socket, &policy, args.topology_helper_role.clone())
    }

    fn run_shim_client(socket: &Path, policy: &Path, helper_role: Option<String>) -> Result<()> {
        let mut stream = UnixStream::connect(&socket).map_err(|err| {
            NonoError::Setup(format!(
                "shim failed to connect to supervisor socket {}: {err}",
                socket.display()
            ))
        })?;
        write_json_line(
            &mut stream,
            &ShimRequest {
                command: policy.display().to_string(),
                helper_role,
            },
        )?;
        let fd_request: ShimFdRequest = read_json_line(&mut stream)?;
        if !fd_request.send_stdio_fds {
            return Err(NonoError::Setup(
                "supervisor did not request stdio fd handoff".to_string(),
            ));
        }
        send_stdio_fds(&stream)?;
        let start: ShimStartMessage = read_json_line(&mut stream)?;
        if let Some(error) = start.spawn_error {
            eprintln!("topology-shim: supervisor spawn error: {error}");
            std::process::exit(126);
        }
        let grandchild_pid = start.grandchild_pid.ok_or_else(|| {
            NonoError::Setup("supervisor start message omitted grandchild pid".to_string())
        })?;
        install_signal_forwarders(grandchild_pid)?;
        let response: ShimResponse = read_json_line(&mut stream)?;

        if let Some(error) = response.spawn_error {
            eprintln!("topology-shim: supervisor spawn error: {error}");
            std::process::exit(126);
        }
        if let Some(signal) = response.signal {
            std::process::exit(128_i32.saturating_add(signal));
        }
        std::process::exit(response.exit_code.unwrap_or(1));
    }

    fn run_topology_command(args: &Args) -> Result<()> {
        let abi = Sandbox::detect_abi()?;
        let policy = required_path(&args.topology_policy, "--topology-policy")?;
        if args.topology_command_pty {
            setup_current_stdio_as_controlling_tty()?;
        }
        let scan = command_sandbox_scan(&policy)?;
        let mut extra_rules = command_device_rules(&abi.abi);
        append_command_context_rules(args, &abi.abi, &mut extra_rules)?;
        let ruleset = build_ruleset_with_extra(&abi.abi, &scan, &extra_rules)?;
        restrict_ruleset(ruleset)?;

        let _deliberate_leak = open_non_cloexec_dev_null()?;
        let mut command = Command::new(&policy);
        if let Some(role) = args.topology_helper_role.as_deref() {
            command.arg("--topology-role").arg(role);
        }
        close_fds_from(3)?;

        let err = command.exec();
        Err(NonoError::CommandExecution(err))
    }

    fn setup_current_stdio_as_controlling_tty() -> Result<()> {
        // SAFETY: This runs in the short-lived command launcher before final exec. It only changes
        // process/session terminal state for the current process, whose stdio fds were set up by
        // the supervisor to point at a fresh PTY slave.
        unsafe {
            if nix::libc::setsid() < 0 {
                return Err(NonoError::Setup(format!(
                    "command PTY setsid failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            if nix::libc::ioctl(nix::libc::STDIN_FILENO, nix::libc::TIOCSCTTY, 0) < 0 {
                return Err(NonoError::Setup(format!(
                    "command PTY TIOCSCTTY failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            let pgrp = nix::libc::getpgrp();
            if nix::libc::tcsetpgrp(nix::libc::STDIN_FILENO, pgrp) < 0 {
                return Err(NonoError::Setup(format!(
                    "command PTY tcsetpgrp failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
        }
        Ok(())
    }

    fn run_stdio_helper() -> Result<()> {
        let mut input = Vec::new();
        std::io::stdin()
            .read_to_end(&mut input)
            .map_err(|err| NonoError::Setup(format!("stdio helper failed to read stdin: {err}")))?;

        if input != STDIO_PROOF_INPUT {
            eprintln!(
                "stdio-helper: stdin mismatch, got {:?}",
                String::from_utf8_lossy(&input)
            );
            std::process::exit(42);
        }

        let open_fds = open_fds_above_stdio(64);
        println!(
            "stdio-helper-stdout: {}",
            String::from_utf8_lossy(&input).trim_end()
        );
        println!("stdio-helper-open-fds: {open_fds:?}");
        eprintln!("stdio-helper-stderr: proof");

        if !open_fds.is_empty() {
            eprintln!("stdio-helper: leaked fds above stderr: {open_fds:?}");
            std::process::exit(43);
        }

        Ok(())
    }

    fn run_tty_helper() -> Result<()> {
        // SAFETY: isatty only inspects the validity/type of stdin in this process.
        let stdin_is_tty = unsafe { nix::libc::isatty(nix::libc::STDIN_FILENO) == 1 };
        println!("tty-helper-isatty-stdin: {stdin_is_tty}");
        println!("{}", String::from_utf8_lossy(TTY_READY_MARKER));
        std::io::stdout()
            .flush()
            .map_err(|err| NonoError::Setup(format!("tty helper failed to flush stdout: {err}")))?;

        loop {
            thread::sleep(Duration::from_secs(1));
        }
    }

    fn run_tty_job_helper() -> Result<()> {
        install_job_helper_signal_handlers()?;
        // SAFETY: These libc calls inspect process/session ids and terminal state for diagnostics.
        let pid = unsafe { nix::libc::getpid() };
        let pgrp = unsafe { nix::libc::getpgrp() };
        let sid = unsafe { nix::libc::getsid(0) };
        let tc_pgrp = tcgetpgrp_diagnostic(nix::libc::STDIN_FILENO);
        // SAFETY: isatty only inspects the validity/type of stdin in this process.
        let stdin_is_tty = unsafe { nix::libc::isatty(nix::libc::STDIN_FILENO) == 1 };

        println!("tty-job-helper-isatty-stdin: {stdin_is_tty}");
        println!("tty-job-helper-pid: {pid} pgrp={pgrp} sid={sid} tcgetpgrp={tc_pgrp}");
        println!("tty-job-helper-ready");
        std::io::stdout().flush().map_err(|err| {
            NonoError::Setup(format!("tty job helper failed to flush stdout: {err}"))
        })?;

        loop {
            thread::sleep(Duration::from_secs(1));
        }
    }

    fn run_command_pty_helper() -> Result<()> {
        // SAFETY: These libc calls inspect process/session ids and terminal state for diagnostics.
        let pid = unsafe { nix::libc::getpid() };
        let pgrp = unsafe { nix::libc::getpgrp() };
        let sid = unsafe { nix::libc::getsid(0) };
        let tc_pgrp = tcgetpgrp_diagnostic(nix::libc::STDIN_FILENO);
        // SAFETY: isatty only inspects the validity/type of stdin in this process.
        let stdin_is_tty = unsafe { nix::libc::isatty(nix::libc::STDIN_FILENO) == 1 };

        println!("command-pty-helper-isatty-stdin: {stdin_is_tty}");
        println!("command-pty-helper-pid: {pid} pgrp={pgrp} sid={sid} tcgetpgrp={tc_pgrp}");
        println!("{}", String::from_utf8_lossy(COMMAND_PTY_READY_MARKER));
        std::io::stdout().flush().map_err(|err| {
            NonoError::Setup(format!("command PTY helper failed to flush stdout: {err}"))
        })
    }

    fn run_chain_git_helper() -> Result<()> {
        let raw_key = PathBuf::from(required_env("CHAIN_RAW_KEY")?);
        assert_raw_key_denied("chain-git-helper", &raw_key)?;
        let status = Command::new("ssh").status().map_err(|err| {
            NonoError::Setup(format!("chain git helper failed to spawn ssh shim: {err}"))
        })?;
        let code = status.code().unwrap_or(128);
        println!("chain-git-helper-ssh-status: {code}");
        if code != 0 {
            std::process::exit(code);
        }
        Ok(())
    }

    fn run_chain_ssh_helper() -> Result<()> {
        let raw_key = PathBuf::from(required_env("CHAIN_RAW_KEY")?);
        assert_raw_key_denied("chain-ssh-helper", &raw_key)?;
        let agent_sock = PathBuf::from(required_env("SSH_AUTH_SOCK")?);
        match UnixStream::connect(&agent_sock) {
            Ok(_) => {
                println!("chain-ssh-helper-agent: connected");
            }
            Err(err) => {
                eprintln!(
                    "chain-ssh-helper-agent: failed to connect {}: {err}",
                    agent_sock.display()
                );
                std::process::exit(44);
            }
        }
        Ok(())
    }

    fn assert_raw_key_denied(label: &str, path: &Path) -> Result<()> {
        match File::open(path) {
            Ok(_) => {
                eprintln!("{label}-raw-key: unexpectedly-readable");
                std::process::exit(45);
            }
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                println!("{label}-raw-key: denied");
                Ok(())
            }
            Err(err) => Err(NonoError::Setup(format!(
                "{label} raw-key probe failed with non-permission error for {}: {err}",
                path.display()
            ))),
        }
    }

    fn canonicalize_file(path: &Path) -> Result<PathBuf> {
        let canonical = path
            .canonicalize()
            .map_err(|source| NonoError::PathCanonicalization {
                path: path.to_path_buf(),
                source,
            })?;
        if !canonical.is_file() {
            return Err(NonoError::ExpectedFile(path.to_path_buf()));
        }
        Ok(canonical)
    }

    fn command_sandbox_scan(policy: &Path) -> Result<ScanOutput> {
        let policy = canonicalize_file(policy)?;
        let support_dirs = existing_dirs(normalize_input_paths(&[], DEFAULT_SUPPORT_DIRS, false)?);
        let support_files =
            existing_files(normalize_input_paths(&[], DEFAULT_SUPPORT_FILES, false)?);
        let mut stats = ScanStats {
            executable_candidates: 1,
            allowed_executable_files: 1,
            support_dirs_allowed: support_dirs.len(),
            support_files_allowed: support_files.len(),
            ..ScanStats::default()
        };
        stats.total_landlock_rules = stats
            .allowed_executable_files
            .saturating_add(executable_parent_dirs(std::slice::from_ref(&policy)).len())
            .saturating_add(stats.support_dirs_allowed)
            .saturating_add(stats.support_files_allowed);

        Ok(ScanOutput {
            executable_files: vec![policy],
            support_dirs,
            support_files,
            excluded: Vec::new(),
            stats,
        })
    }

    fn command_device_rules(abi: &ABI) -> Vec<ExtraRule> {
        let mut rules = Vec::new();
        push_extra_if_exists(
            &mut rules,
            PathBuf::from("/dev/null"),
            supported(abi, AccessFs::ReadFile | AccessFs::WriteFile),
        );
        push_extra_if_exists(
            &mut rules,
            PathBuf::from("/dev/zero"),
            supported(abi, AccessFs::ReadFile),
        );
        push_extra_if_exists(
            &mut rules,
            PathBuf::from("/dev/urandom"),
            supported(abi, AccessFs::ReadFile),
        );
        rules
    }

    fn append_command_context_rules(
        args: &Args,
        abi: &ABI,
        rules: &mut Vec<ExtraRule>,
    ) -> Result<()> {
        if let Some(shim_path) = args.topology_shim.as_ref() {
            if shim_path.is_dir() {
                rules.push(ExtraRule {
                    path: shim_path.clone(),
                    access: supported(
                        abi,
                        AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute,
                    ),
                });
            } else if shim_path.exists() {
                rules.push(ExtraRule {
                    path: shim_path.clone(),
                    access: supported(abi, AccessFs::ReadFile | AccessFs::Execute),
                });
                if let Some(parent) = shim_path.parent() {
                    rules.push(ExtraRule {
                        path: parent.to_path_buf(),
                        access: supported(abi, AccessFs::ReadDir),
                    });
                }
            }
        }

        if let Some(socket) = args.topology_socket.as_ref() {
            let socket_parent = socket.parent().ok_or_else(|| {
                NonoError::Setup(format!("socket path has no parent: {}", socket.display()))
            })?;
            rules.push(ExtraRule {
                path: socket_parent.to_path_buf(),
                access: supported(
                    abi,
                    AccessFs::ReadFile
                        | AccessFs::ReadDir
                        | AccessFs::Execute
                        | AccessFs::WriteFile
                        | AccessFs::MakeSock,
                ),
            });
        }

        Ok(())
    }

    fn push_extra_if_exists(rules: &mut Vec<ExtraRule>, path: PathBuf, access: BitFlags<AccessFs>) {
        if path.exists() {
            rules.push(ExtraRule { path, access });
        }
    }

    fn open_non_cloexec_dev_null() -> Result<RawFd> {
        let path = b"/dev/null\0";
        // SAFETY: `path` is a valid NUL-terminated byte string, and `open` either returns a
        // process-local fd or -1 with errno set. The fd is intentionally not O_CLOEXEC so the
        // helper can prove close_fds_from() removed it before the final exec.
        let fd = unsafe { nix::libc::open(path.as_ptr().cast(), nix::libc::O_RDONLY) };
        if fd < 0 {
            return Err(NonoError::Setup(format!(
                "failed to open deliberate fd hygiene probe /dev/null: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(fd)
    }

    fn close_fds_from(first: RawFd) -> Result<()> {
        // SAFETY: close_range only affects file descriptors in the current process. This function
        // is called in the short-lived command launcher after stdio is already on fds 0/1/2 and
        // immediately before execing the final policy binary.
        let rc = unsafe {
            nix::libc::syscall(
                nix::libc::SYS_close_range,
                first as nix::libc::c_uint,
                u32::MAX,
                0u32,
            )
        };
        if rc == 0 {
            return Ok(());
        }

        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(code) if code == nix::libc::ENOSYS || code == nix::libc::EINVAL => {
                close_fds_fallback(first);
                Ok(())
            }
            _ => Err(NonoError::Setup(format!("close_range failed: {error}"))),
        }
    }

    fn close_fds_fallback(first: RawFd) {
        for fd in first..1024 {
            // SAFETY: Closing an integer fd in the current process is safe. EBADF is expected for
            // entries that are not open, and all errors are ignored because this is a best-effort
            // fallback for kernels without close_range.
            unsafe {
                nix::libc::close(fd);
            }
        }
    }

    fn open_fds_above_stdio(max_fd: RawFd) -> Vec<RawFd> {
        let mut open_fds = Vec::new();
        for fd in 3..max_fd {
            // SAFETY: fcntl(F_GETFD) only inspects the descriptor table for this process.
            let rc = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) };
            if rc >= 0 {
                open_fds.push(fd);
            }
        }
        open_fds
    }

    fn open_pty_pair() -> Result<PtyPair> {
        // SAFETY: posix_openpt returns a new master fd or -1 with errno set.
        let master = unsafe {
            nix::libc::posix_openpt(nix::libc::O_RDWR | nix::libc::O_NOCTTY | nix::libc::O_CLOEXEC)
        };
        if master < 0 {
            return Err(NonoError::Setup(format!(
                "posix_openpt failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        // SAFETY: grantpt/unlockpt operate on the valid PTY master fd created above.
        if unsafe { nix::libc::grantpt(master) } != 0 {
            let error = std::io::Error::last_os_error();
            close_fd(master);
            return Err(NonoError::Setup(format!("grantpt failed: {error}")));
        }
        // SAFETY: grantpt/unlockpt operate on the valid PTY master fd created above.
        if unsafe { nix::libc::unlockpt(master) } != 0 {
            let error = std::io::Error::last_os_error();
            close_fd(master);
            return Err(NonoError::Setup(format!("unlockpt failed: {error}")));
        }

        let mut buffer = [0 as nix::libc::c_char; 128];
        // SAFETY: buffer is valid for writes and large enough for normal /dev/pts paths. On
        // failure ptsname_r reports an errno-style return code.
        let rc = unsafe { nix::libc::ptsname_r(master, buffer.as_mut_ptr(), buffer.len()) };
        if rc != 0 {
            close_fd(master);
            return Err(NonoError::Setup(format!(
                "ptsname_r failed: {}",
                std::io::Error::from_raw_os_error(rc)
            )));
        }
        // SAFETY: ptsname_r returned success and wrote a NUL-terminated path into buffer.
        let slave_path = unsafe { CStr::from_ptr(buffer.as_ptr()) }
            .to_string_lossy()
            .into_owned();

        Ok(PtyPair {
            master,
            slave_path: PathBuf::from(slave_path),
        })
    }

    fn open_pty_slave(path: &Path) -> Result<RawFd> {
        let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|err| {
            NonoError::Setup(format!("PTY slave path contains interior NUL: {err}"))
        })?;
        // SAFETY: c_path is NUL-terminated and open returns a process-local fd or -1.
        let fd = unsafe {
            nix::libc::open(
                c_path.as_ptr(),
                nix::libc::O_RDWR | nix::libc::O_NOCTTY | nix::libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(NonoError::Setup(format!(
                "failed to open PTY slave {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            )));
        }
        Ok(fd)
    }

    fn read_fd_until(fd: RawFd, needle: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        let deadline = Instant::now() + timeout;
        let mut output = Vec::new();
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if poll_readable(fd, remaining)? {
                read_fd_once(fd, &mut output)?;
                if contains_subslice(&output, needle) {
                    return Ok(output);
                }
            }
        }

        Err(NonoError::Setup(format!(
            "timed out waiting for PTY marker {}; transcript so far: {}",
            String::from_utf8_lossy(needle),
            String::from_utf8_lossy(&output)
        )))
    }

    fn read_fd_until_accumulate(
        fd: RawFd,
        output: &mut Vec<u8>,
        needle: &[u8],
        timeout: Duration,
    ) -> Result<()> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if contains_subslice(output, needle) {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if poll_readable(fd, remaining)? {
                read_fd_once(fd, output)?;
            }
        }

        Err(NonoError::Setup(format!(
            "timed out waiting for PTY marker {}; transcript so far: {}",
            String::from_utf8_lossy(needle),
            String::from_utf8_lossy(output)
        )))
    }

    fn read_fd_available(fd: RawFd, quiet_for: Duration, max_total: Duration) -> Result<Vec<u8>> {
        let started = Instant::now();
        let mut last_data = Instant::now();
        let mut output = Vec::new();
        while started.elapsed() < max_total && last_data.elapsed() < quiet_for {
            if poll_readable(fd, Duration::from_millis(50))? {
                let before = output.len();
                if !read_fd_once(fd, &mut output)? {
                    break;
                }
                if output.len() > before {
                    last_data = Instant::now();
                }
            }
        }
        Ok(output)
    }

    fn read_fd_once(fd: RawFd, output: &mut Vec<u8>) -> Result<bool> {
        let mut buffer = [0_u8; 4096];
        loop {
            // SAFETY: buffer is valid for writes, and read only affects the supplied fd.
            let n = unsafe { nix::libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
            if n > 0 {
                let n = usize::try_from(n).map_err(|err| {
                    NonoError::Setup(format!("read size did not fit usize: {err}"))
                })?;
                output.extend_from_slice(&buffer[..n]);
                return Ok(true);
            }
            if n == 0 {
                return Ok(false);
            }

            let error = std::io::Error::last_os_error();
            match error.raw_os_error() {
                Some(code) if code == nix::libc::EINTR => continue,
                Some(code) if code == nix::libc::EIO => return Ok(false),
                _ => return Err(NonoError::Setup(format!("PTY read failed: {error}"))),
            }
        }
    }

    fn write_all_fd(fd: RawFd, mut bytes: &[u8]) -> Result<()> {
        while !bytes.is_empty() {
            // SAFETY: bytes points to initialized memory and write only affects the supplied fd.
            let n = unsafe { nix::libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
            if n > 0 {
                let n = usize::try_from(n).map_err(|err| {
                    NonoError::Setup(format!("write size did not fit usize: {err}"))
                })?;
                bytes = &bytes[n..];
                continue;
            }

            let error = std::io::Error::last_os_error();
            match error.raw_os_error() {
                Some(code) if code == nix::libc::EINTR => continue,
                _ => return Err(NonoError::Setup(format!("PTY write failed: {error}"))),
            }
        }
        Ok(())
    }

    fn poll_readable(fd: RawFd, timeout: Duration) -> Result<bool> {
        let mut poll_fd = nix::libc::pollfd {
            fd,
            events: nix::libc::POLLIN,
            revents: 0,
        };
        let timeout_ms = i32::try_from(timeout.as_millis().min(i32::MAX as u128))
            .map_err(|err| NonoError::Setup(format!("poll timeout conversion failed: {err}")))?;
        loop {
            // SAFETY: poll_fd points to one valid pollfd entry for this stack frame.
            let rc = unsafe { nix::libc::poll(&mut poll_fd, 1, timeout_ms) };
            if rc > 0 {
                return Ok((poll_fd.revents & (nix::libc::POLLIN | nix::libc::POLLHUP)) != 0);
            }
            if rc == 0 {
                return Ok(false);
            }

            let error = std::io::Error::last_os_error();
            match error.raw_os_error() {
                Some(code) if code == nix::libc::EINTR => continue,
                _ => return Err(NonoError::Setup(format!("poll failed: {error}"))),
            }
        }
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() {
            return true;
        }
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    fn close_fd(fd: RawFd) {
        // SAFETY: Closing an owned raw fd in this harness process.
        unsafe {
            nix::libc::close(fd);
        }
    }

    fn set_pty_winsize(fd: RawFd, rows: u16, cols: u16) -> Result<()> {
        let winsize = nix::libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: ioctl(TIOCSWINSZ) reads the provided winsize and applies it to this PTY fd.
        let rc = unsafe { nix::libc::ioctl(fd, nix::libc::TIOCSWINSZ, &winsize) };
        if rc != 0 {
            return Err(NonoError::Setup(format!(
                "TIOCSWINSZ failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn send_signal(pid: i32, signal: nix::libc::c_int) -> Result<()> {
        // SAFETY: kill sends the requested signal to a pid discovered from kernel peer creds.
        let rc = unsafe { nix::libc::kill(pid, signal) };
        if rc != 0 {
            return Err(NonoError::Setup(format!(
                "failed to send signal {signal} to pid {pid}: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn tcgetpgrp_diagnostic(fd: RawFd) -> String {
        // SAFETY: tcgetpgrp only inspects terminal state for this fd.
        let pgrp = unsafe { nix::libc::tcgetpgrp(fd) };
        if pgrp < 0 {
            format!("error({})", std::io::Error::last_os_error())
        } else {
            pgrp.to_string()
        }
    }

    fn required_path(value: &Option<PathBuf>, name: &str) -> Result<PathBuf> {
        value
            .clone()
            .ok_or_else(|| NonoError::Setup(format!("missing internal argument {name}")))
    }

    fn required_env(name: &str) -> Result<String> {
        std::env::var(name).map_err(|err| {
            NonoError::Setup(format!(
                "missing or invalid environment variable {name}: {err}"
            ))
        })
    }

    fn env_key_suffix(command_name: &str) -> String {
        command_name
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() {
                    ch.to_ascii_uppercase()
                } else {
                    '_'
                }
            })
            .collect()
    }

    fn ancestry_contains(mut pid: i32, wanted_ancestor: i32) -> Result<bool> {
        for _ in 0..128 {
            if pid == wanted_ancestor {
                return Ok(true);
            }
            if pid <= 1 {
                return Ok(false);
            }
            pid = parent_pid(pid)?;
        }
        Err(NonoError::Setup(format!(
            "ancestry walk exceeded depth limit looking for {wanted_ancestor}"
        )))
    }

    fn parent_pid(pid: i32) -> Result<i32> {
        let status_path = PathBuf::from(format!("/proc/{pid}/status"));
        let status = fs::read_to_string(&status_path).map_err(|source| NonoError::ConfigRead {
            path: status_path.clone(),
            source,
        })?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("PPid:") {
                return rest.trim().parse::<i32>().map_err(|err| {
                    NonoError::Setup(format!(
                        "failed to parse PPid from {}: {err}",
                        status_path.display()
                    ))
                });
            }
        }
        Err(NonoError::Setup(format!(
            "missing PPid in {}",
            status_path.display()
        )))
    }

    fn flatten_repeated(name: &'static str, values: &[PathBuf]) -> Vec<String> {
        let mut args = Vec::with_capacity(values.len().saturating_mul(2));
        for value in values {
            args.push(name.to_string());
            args.push(value.display().to_string());
        }
        args
    }

    fn optional_arg(name: &'static str, value: Option<&str>) -> Vec<String> {
        match value {
            Some(value) => vec![name.to_string(), value.to_string()],
            None => Vec::new(),
        }
    }

    fn send_stdio_fds(stream: &UnixStream) -> Result<()> {
        for fd in [
            nix::libc::STDIN_FILENO,
            nix::libc::STDOUT_FILENO,
            nix::libc::STDERR_FILENO,
        ] {
            send_fd_via_socket(stream.as_raw_fd(), fd)?;
        }
        Ok(())
    }

    fn recv_stdio_fds(stream: &UnixStream) -> Result<StdioFds> {
        let stdin = recv_fd_via_socket(stream.as_raw_fd())?;
        let stdout = recv_fd_via_socket(stream.as_raw_fd())?;
        let stderr = recv_fd_via_socket(stream.as_raw_fd())?;
        Ok(StdioFds {
            stdin,
            stdout,
            stderr,
        })
    }

    extern "C" fn forward_signal(signal: nix::libc::c_int) {
        let pid = SIGNAL_FORWARD_PID.load(Ordering::Relaxed);
        if pid > 0 {
            // SAFETY: kill(2) is async-signal-safe. The pid is set from the supervisor's
            // kernel-observed child id before handlers are installed.
            unsafe {
                nix::libc::kill(pid, signal);
            }
        }
    }

    fn install_signal_forwarders(grandchild_pid: i32) -> Result<()> {
        SIGNAL_FORWARD_PID.store(grandchild_pid, Ordering::SeqCst);
        let action = SigAction::new(
            SigHandler::Handler(forward_signal),
            SaFlags::SA_RESTART,
            SigSet::empty(),
        );
        for signal in [
            Signal::SIGINT,
            Signal::SIGTERM,
            Signal::SIGHUP,
            Signal::SIGQUIT,
            Signal::SIGTSTP,
            Signal::SIGCONT,
            Signal::SIGWINCH,
        ] {
            // SAFETY: Installing a process-local signal handler with nix's validated SigAction.
            unsafe { sigaction(signal, &action) }.map_err(|err| {
                NonoError::Setup(format!("failed to install {signal:?} forwarder: {err}"))
            })?;
        }
        Ok(())
    }

    fn ignore_signal(signal: Signal) -> Result<()> {
        let action = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty());
        // SAFETY: Installing a process-local ignored disposition for the harness session process.
        unsafe { sigaction(signal, &action) }
            .map_err(|err| NonoError::Setup(format!("failed to ignore {signal:?}: {err}")))?;
        Ok(())
    }

    extern "C" fn job_helper_signal(signal: nix::libc::c_int) {
        let message: &[u8] = match signal {
            nix::libc::SIGTSTP => b"tty-job-helper-signal: SIGTSTP\n",
            nix::libc::SIGCONT => b"tty-job-helper-signal: SIGCONT\n",
            nix::libc::SIGWINCH => b"tty-job-helper-signal: SIGWINCH\n",
            _ => b"tty-job-helper-signal: UNKNOWN\n",
        };
        // SAFETY: write(2) is async-signal-safe and stdout is process-local.
        unsafe {
            nix::libc::write(
                nix::libc::STDOUT_FILENO,
                message.as_ptr().cast(),
                message.len(),
            );
        }
    }

    fn install_job_helper_signal_handlers() -> Result<()> {
        let action = SigAction::new(
            SigHandler::Handler(job_helper_signal),
            SaFlags::SA_RESTART,
            SigSet::empty(),
        );
        for signal in [Signal::SIGTSTP, Signal::SIGCONT, Signal::SIGWINCH] {
            // SAFETY: Installing a process-local signal handler with nix's validated SigAction.
            unsafe { sigaction(signal, &action) }.map_err(|err| {
                NonoError::Setup(format!(
                    "failed to install job-helper {signal:?} handler: {err}"
                ))
            })?;
        }
        Ok(())
    }

    fn read_pipe_to_end<R>(mut reader: R) -> std::io::Result<Vec<u8>>
    where
        R: Read,
    {
        let mut output = Vec::new();
        reader.read_to_end(&mut output)?;
        Ok(output)
    }

    fn join_pipe_reader(
        handle: thread::JoinHandle<std::io::Result<Vec<u8>>>,
        name: &str,
    ) -> Result<Vec<u8>> {
        match handle.join() {
            Ok(Ok(output)) => Ok(output),
            Ok(Err(err)) => Err(NonoError::Setup(format!(
                "failed to read session {name}: {err}"
            ))),
            Err(_) => Err(NonoError::Setup(format!(
                "session {name} reader thread panicked"
            ))),
        }
    }

    fn authenticate_shim(stream: &UnixStream, trusted_shim_id: FileId) -> Result<TopologyAuth> {
        let credentials = peer_credentials(stream)?;
        let peer_pid = credentials.pid;
        let peer_exe_link = PathBuf::from(format!("/proc/{peer_pid}/exe"));
        let peer_exe = fs::read_link(&peer_exe_link).map_err(|err| {
            NonoError::Setup(format!(
                "failed to read peer executable {}: {err}",
                peer_exe_link.display()
            ))
        })?;
        let peer_metadata = fs::metadata(&peer_exe_link).map_err(|err| {
            NonoError::Setup(format!(
                "failed to stat peer executable {}: {err}",
                peer_exe_link.display()
            ))
        })?;
        let peer_id = file_id(&peer_metadata);
        if peer_id != trusted_shim_id {
            return Err(NonoError::Setup(format!(
                "shim authentication failed: peer executable {} has inode {}:{}, expected {}:{}",
                peer_exe.display(),
                peer_id.dev,
                peer_id.ino,
                trusted_shim_id.dev,
                trusted_shim_id.ino
            )));
        }

        Ok(TopologyAuth {
            peer_pid,
            peer_uid: credentials.uid,
            peer_gid: credentials.gid,
            peer_exe,
            peer_id,
        })
    }

    fn peer_credentials(stream: &UnixStream) -> Result<nix::libc::ucred> {
        let mut credentials = std::mem::MaybeUninit::<nix::libc::ucred>::uninit();
        let mut credentials_len = std::mem::size_of::<nix::libc::ucred>() as nix::libc::socklen_t;

        // SAFETY: `stream.as_raw_fd()` is a valid Unix socket fd for the duration of this call.
        // The kernel writes at most `credentials_len` bytes to the properly sized ucred buffer,
        // and we only assume initialization after getsockopt reports success.
        let rc = unsafe {
            nix::libc::getsockopt(
                stream.as_raw_fd(),
                nix::libc::SOL_SOCKET,
                nix::libc::SO_PEERCRED,
                credentials.as_mut_ptr().cast(),
                &mut credentials_len,
            )
        };
        if rc != 0 {
            return Err(NonoError::Setup(format!(
                "SO_PEERCRED failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        // SAFETY: getsockopt returned success and initialized the ucred buffer.
        Ok(unsafe { credentials.assume_init() })
    }

    fn spawn_supervised_command(
        current_exe: &Path,
        policy: &Path,
        helper_role: Option<&str>,
        stdio_fds: StdioFds,
    ) -> std::result::Result<Child, String> {
        spawn_supervised_command_with_context(
            current_exe,
            policy,
            helper_role,
            stdio_fds,
            None,
            None,
            &[],
            false,
        )
    }

    fn spawn_supervised_command_with_context(
        current_exe: &Path,
        policy: &Path,
        helper_role: Option<&str>,
        stdio_fds: StdioFds,
        topology_socket: Option<&Path>,
        topology_shim: Option<&Path>,
        envs: &[(String, String)],
        command_pty: bool,
    ) -> std::result::Result<Child, String> {
        let StdioFds {
            stdin,
            stdout,
            stderr,
        } = stdio_fds;
        let mut command = Command::new(current_exe);
        command
            .arg("--topology-role")
            .arg("command")
            .arg("--topology-policy")
            .arg(policy);
        if let Some(role) = helper_role {
            command.arg("--topology-helper-role").arg(role);
        }
        if let Some(socket) = topology_socket {
            command.arg("--topology-socket").arg(socket);
        }
        if let Some(shim) = topology_shim {
            command.arg("--topology-shim").arg(shim);
        }
        if command_pty {
            command.arg("--topology-command-pty");
        }
        for (name, value) in envs {
            command.env(name, value);
        }

        command
            .stdin(Stdio::from(File::from(stdin)))
            .stdout(Stdio::from(File::from(stdout)))
            .stderr(Stdio::from(File::from(stderr)))
            .spawn()
            .map_err(|err| err.to_string())
    }

    fn child_pid_i32(child: &Child) -> Result<i32> {
        i32::try_from(child.id())
            .map_err(|err| NonoError::Setup(format!("child pid did not fit in i32: {err}")))
    }

    fn wait_supervised_command(child: &mut Child) -> ShimResponse {
        match child.wait() {
            Ok(status) => status_to_response(status),
            Err(err) => ShimResponse {
                exit_code: None,
                signal: None,
                spawn_error: Some(err.to_string()),
            },
        }
    }

    fn wait_supervised_command_timeout(child: &mut Child, timeout: Duration) -> ShimResponse {
        let deadline = Instant::now() + timeout;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return status_to_response(status),
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return ShimResponse {
                        exit_code: None,
                        signal: None,
                        spawn_error: Some(format!(
                            "command child timed out after {} ms",
                            millis(timeout)
                        )),
                    };
                }
                Err(err) => {
                    return ShimResponse {
                        exit_code: None,
                        signal: None,
                        spawn_error: Some(err.to_string()),
                    };
                }
            }
        }
    }

    fn status_to_response(status: std::process::ExitStatus) -> ShimResponse {
        ShimResponse {
            exit_code: status.code(),
            signal: status.signal(),
            spawn_error: None,
        }
    }

    fn read_json_line<T>(stream: &mut UnixStream) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let mut line = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            let n = stream
                .read(&mut byte)
                .map_err(|err| NonoError::Setup(format!("failed to read IPC message: {err}")))?;
            if n == 0 {
                return Err(NonoError::Setup(
                    "IPC stream closed before newline".to_string(),
                ));
            }
            if byte[0] == b'\n' {
                break;
            }
            line.push(byte[0]);
            if line.len() > 1024 * 1024 {
                return Err(NonoError::Setup("IPC message exceeded 1 MiB".to_string()));
            }
        }

        serde_json::from_slice(&line)
            .map_err(|err| NonoError::Setup(format!("failed to parse IPC message: {err}")))
    }

    fn write_json_line<T>(stream: &mut UnixStream, value: &T) -> Result<()>
    where
        T: Serialize,
    {
        let mut line = serde_json::to_string(value)
            .map_err(|err| NonoError::Setup(format!("failed to serialize IPC message: {err}")))?;
        line.push('\n');
        stream
            .write_all(line.as_bytes())
            .map_err(|err| NonoError::Setup(format!("failed to write IPC message: {err}")))
    }

    fn scan_inputs(args: &Args) -> Result<ScanOutput> {
        let exec_dirs = normalize_input_paths(&args.exec_dirs, DEFAULT_EXEC_DIRS, true)?;
        let support_dirs = normalize_input_paths(&args.support_dirs, DEFAULT_SUPPORT_DIRS, false)?;
        let support_files =
            normalize_input_paths(&args.support_files, DEFAULT_SUPPORT_FILES, false)?;
        let excluded = canonicalize_exclusions(&args.excludes)?;

        let excluded_paths: HashSet<PathBuf> = excluded
            .iter()
            .map(|entry| entry.canonical.clone())
            .collect();
        let excluded_ids: HashSet<FileId> = excluded.iter().map(|entry| entry.id).collect();

        let mut stats = ScanStats {
            exec_dirs_requested: exec_dirs.len(),
            ..ScanStats::default()
        };
        let mut seen_ids = HashSet::new();
        let mut executable_files = Vec::new();

        for dir in &exec_dirs {
            stats.exec_dirs_scanned = stats.exec_dirs_scanned.saturating_add(1);
            let entries = fs::read_dir(dir).map_err(|source| NonoError::ConfigRead {
                path: dir.clone(),
                source,
            })?;

            for entry in entries {
                stats.exec_entries_seen = stats.exec_entries_seen.saturating_add(1);
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(_) => {
                        stats.metadata_errors = stats.metadata_errors.saturating_add(1);
                        continue;
                    }
                };

                let path = entry.path();
                let canonical = match path.canonicalize() {
                    Ok(path) => path,
                    Err(_) => {
                        stats.metadata_errors = stats.metadata_errors.saturating_add(1);
                        continue;
                    }
                };
                let metadata = match fs::metadata(&canonical) {
                    Ok(metadata) => metadata,
                    Err(_) => {
                        stats.metadata_errors = stats.metadata_errors.saturating_add(1);
                        continue;
                    }
                };

                if !metadata.is_file() {
                    stats.non_file_skips = stats.non_file_skips.saturating_add(1);
                    continue;
                }
                if metadata.permissions().mode() & 0o111 == 0 {
                    stats.non_file_skips = stats.non_file_skips.saturating_add(1);
                    continue;
                }

                stats.executable_candidates = stats.executable_candidates.saturating_add(1);
                let id = file_id(&metadata);

                if excluded_paths.contains(&canonical) {
                    stats.excluded_by_path = stats.excluded_by_path.saturating_add(1);
                    continue;
                }
                if excluded_ids.contains(&id) {
                    stats.excluded_by_inode = stats.excluded_by_inode.saturating_add(1);
                    continue;
                }
                if !seen_ids.insert(id) {
                    stats.duplicate_inode_skips = stats.duplicate_inode_skips.saturating_add(1);
                    continue;
                }

                executable_files.push(canonical);
            }
        }

        let support_dirs = existing_dirs(support_dirs);
        let support_files = existing_files(support_files);
        stats.allowed_executable_files = executable_files.len();
        stats.support_dirs_allowed = support_dirs.len();
        stats.support_files_allowed = support_files.len();
        stats.total_landlock_rules = stats
            .allowed_executable_files
            .saturating_add(executable_parent_dirs(&executable_files).len())
            .saturating_add(stats.support_dirs_allowed)
            .saturating_add(stats.support_files_allowed);

        executable_files.sort();

        Ok(ScanOutput {
            executable_files,
            support_dirs,
            support_files,
            excluded,
            stats,
        })
    }

    fn normalize_input_paths(
        provided: &[PathBuf],
        defaults: &[&str],
        require_dir: bool,
    ) -> Result<Vec<PathBuf>> {
        let raw_paths: Vec<PathBuf> = if provided.is_empty() {
            defaults.iter().map(PathBuf::from).collect()
        } else {
            provided.to_vec()
        };

        let mut paths = BTreeSet::new();
        for raw in raw_paths {
            if !raw.exists() {
                continue;
            }
            let canonical =
                raw.canonicalize()
                    .map_err(|source| NonoError::PathCanonicalization {
                        path: raw.clone(),
                        source,
                    })?;
            if require_dir && !canonical.is_dir() {
                return Err(NonoError::ExpectedDirectory(raw));
            }
            paths.insert(canonical);
        }

        Ok(paths.into_iter().collect())
    }

    fn existing_dirs(paths: Vec<PathBuf>) -> Vec<PathBuf> {
        paths.into_iter().filter(|path| path.is_dir()).collect()
    }

    fn existing_files(paths: Vec<PathBuf>) -> Vec<PathBuf> {
        paths.into_iter().filter(|path| path.is_file()).collect()
    }

    fn canonicalize_exclusions(paths: &[PathBuf]) -> Result<Vec<Exclusion>> {
        let mut exclusions = Vec::new();
        let mut seen = HashSet::new();

        for requested in paths {
            let canonical =
                requested
                    .canonicalize()
                    .map_err(|source| NonoError::PathCanonicalization {
                        path: requested.clone(),
                        source,
                    })?;
            let metadata = fs::metadata(&canonical).map_err(|source| NonoError::ConfigRead {
                path: canonical.clone(),
                source,
            })?;
            if !metadata.is_file() {
                return Err(NonoError::ExpectedFile(requested.clone()));
            }

            let id = file_id(&metadata);
            if seen.insert(id) {
                exclusions.push(Exclusion {
                    requested: requested.clone(),
                    canonical,
                    id,
                });
            }
        }

        Ok(exclusions)
    }

    fn build_ruleset(abi: &ABI, scan: &ScanOutput) -> Result<landlock::RulesetCreated> {
        build_ruleset_with_extra(abi, scan, &[])
    }

    fn build_ruleset_with_extra(
        abi: &ABI,
        scan: &ScanOutput,
        extra_rules: &[ExtraRule],
    ) -> Result<landlock::RulesetCreated> {
        let handled_fs = AccessFs::from_all(*abi);
        let mut ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(handled_fs)
            .map_err(|err| {
                NonoError::SandboxInit(format!("failed to handle filesystem access: {err}"))
            })?
            .set_compatibility(CompatLevel::BestEffort)
            .create()
            .map_err(|err| NonoError::SandboxInit(format!("failed to create ruleset: {err}")))?;

        let exec_file_access = supported(abi, AccessFs::ReadFile | AccessFs::Execute);
        let dir_read_access = supported(abi, AccessFs::ReadDir);
        let support_read_access = supported(
            abi,
            AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute,
        );

        for path in &scan.executable_files {
            ruleset = add_path_rule(ruleset, path, exec_file_access)?;
        }
        for dir in executable_parent_dirs(&scan.executable_files) {
            ruleset = add_path_rule(ruleset, &dir, dir_read_access)?;
        }
        for dir in &scan.support_dirs {
            ruleset = add_path_rule(ruleset, dir, support_read_access)?;
        }
        for file in &scan.support_files {
            ruleset = add_path_rule(ruleset, file, supported(abi, AccessFs::ReadFile))?;
        }
        for extra in extra_rules {
            ruleset = add_path_rule(ruleset, &extra.path, extra.access)?;
        }

        Ok(ruleset)
    }

    fn restrict_ruleset(ruleset: landlock::RulesetCreated) -> Result<()> {
        let status = ruleset
            .restrict_self()
            .map_err(|err| NonoError::SandboxInit(format!("restrict_self failed: {err}")))?;
        if !matches!(
            status.ruleset,
            landlock::RulesetStatus::FullyEnforced | landlock::RulesetStatus::PartiallyEnforced
        ) {
            return Err(NonoError::SandboxInit(format!(
                "Landlock ruleset was not enforced: {:?}",
                status.ruleset
            )));
        }
        Ok(())
    }

    fn add_path_rule(
        ruleset: landlock::RulesetCreated,
        path: &Path,
        access: BitFlags<AccessFs>,
    ) -> Result<landlock::RulesetCreated> {
        let path_fd = PathFd::new(path)?;
        ruleset
            .add_rule(PathBeneath::new(path_fd, access))
            .map_err(|err| {
                NonoError::SandboxInit(format!(
                    "cannot add Landlock rule for {}: {err}",
                    path.display()
                ))
            })
    }

    fn supported<A>(abi: &ABI, access: A) -> BitFlags<AccessFs>
    where
        A: Into<BitFlags<AccessFs>>,
    {
        access.into() & AccessFs::from_all(*abi)
    }

    fn executable_parent_dirs(executable_files: &[PathBuf]) -> Vec<PathBuf> {
        let mut dirs = BTreeSet::new();
        for file in executable_files {
            if let Some(parent) = file.parent() {
                dirs.insert(parent.to_path_buf());
            }
        }
        dirs.into_iter().collect()
    }

    fn run_probes(allow: &[PathBuf], deny: &[PathBuf]) -> Vec<ProbeSummary> {
        let mut probes = Vec::new();
        for path in allow {
            probes.push(run_probe(path, ProbeExpectation::Allow));
        }
        for path in deny {
            probes.push(run_probe(path, ProbeExpectation::Deny));
        }
        probes
    }

    fn run_probe(path: &Path, expected: ProbeExpectation) -> ProbeSummary {
        let outcome = match Command::new(path).status() {
            Ok(status) => ProbeOutcome::Exited {
                code: status.code(),
            },
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                ProbeOutcome::SpawnDenied
            }
            Err(err) => ProbeOutcome::SpawnError {
                message: err.to_string(),
            },
        };
        let matched = match (&expected, &outcome) {
            (ProbeExpectation::Allow, ProbeOutcome::Exited { .. }) => true,
            (ProbeExpectation::Deny, ProbeOutcome::SpawnDenied) => true,
            (ProbeExpectation::Deny, ProbeOutcome::SpawnError { message }) => {
                message.contains("Permission denied")
            }
            _ => false,
        };

        ProbeSummary {
            path: path.display().to_string(),
            expected,
            outcome,
            matched,
        }
    }

    fn file_id(metadata: &fs::Metadata) -> FileId {
        FileId {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    }

    fn millis(duration: Duration) -> u128 {
        duration.as_millis()
    }

    fn print_json(
        abi: &ABI,
        scan: &ScanOutput,
        timings: TimingSummary,
        probes: Vec<ProbeSummary>,
    ) -> Result<()> {
        let excluded = scan
            .excluded
            .iter()
            .map(|entry| JsonExclusion {
                requested: entry.requested.display().to_string(),
                canonical: entry.canonical.display().to_string(),
                dev: entry.id.dev,
                ino: entry.id.ino,
            })
            .collect();
        let summary = JsonSummary {
            landlock_abi: format!("{abi:?}"),
            scan: ScanStats {
                exec_dirs_requested: scan.stats.exec_dirs_requested,
                exec_dirs_scanned: scan.stats.exec_dirs_scanned,
                exec_entries_seen: scan.stats.exec_entries_seen,
                executable_candidates: scan.stats.executable_candidates,
                allowed_executable_files: scan.stats.allowed_executable_files,
                excluded_by_path: scan.stats.excluded_by_path,
                excluded_by_inode: scan.stats.excluded_by_inode,
                duplicate_inode_skips: scan.stats.duplicate_inode_skips,
                non_file_skips: scan.stats.non_file_skips,
                metadata_errors: scan.stats.metadata_errors,
                support_dirs_allowed: scan.stats.support_dirs_allowed,
                support_files_allowed: scan.stats.support_files_allowed,
                total_landlock_rules: scan.stats.total_landlock_rules,
            },
            timings,
            excluded,
            probes,
        };
        let json = serde_json::to_string_pretty(&summary)
            .map_err(|err| NonoError::Setup(format!("failed to serialize JSON: {err}")))?;
        println!("{json}");
        Ok(())
    }

    fn print_human(
        abi: &ABI,
        scan: &ScanOutput,
        timings: &TimingSummary,
        probes: &[ProbeSummary],
        applied: bool,
    ) {
        println!("Landlock ABI: {abi:?}");
        println!(
            "Executable dirs requested: {}",
            scan.stats.exec_dirs_requested
        );
        println!("Executable dirs scanned: {}", scan.stats.exec_dirs_scanned);
        println!("Entries seen: {}", scan.stats.exec_entries_seen);
        println!(
            "Executable candidates: {}",
            scan.stats.executable_candidates
        );
        println!(
            "Allowed executable files: {}",
            scan.stats.allowed_executable_files
        );
        println!("Excluded by path: {}", scan.stats.excluded_by_path);
        println!("Excluded by inode: {}", scan.stats.excluded_by_inode);
        println!(
            "Duplicate inode skips: {}",
            scan.stats.duplicate_inode_skips
        );
        println!("Support dirs allowed: {}", scan.stats.support_dirs_allowed);
        println!(
            "Support files allowed: {}",
            scan.stats.support_files_allowed
        );
        println!("Total Landlock rules: {}", scan.stats.total_landlock_rules);
        println!("Scan time: {} ms", timings.scan_ms);

        if let Some(build_ms) = timings.ruleset_build_ms {
            println!("Ruleset build time: {build_ms} ms");
        }
        if let Some(restrict_ms) = timings.restrict_self_ms {
            println!("restrict_self time: {restrict_ms} ms");
        }
        println!("Total time: {} ms", timings.total_ms);

        if !scan.excluded.is_empty() {
            println!("Excluded binaries:");
            for entry in &scan.excluded {
                println!(
                    "  {} -> {} [{}:{}]",
                    entry.requested.display(),
                    entry.canonical.display(),
                    entry.id.dev,
                    entry.id.ino
                );
            }
        }

        if !applied {
            println!("Landlock was not applied. Re-run with --apply to measure restrict_self.");
        }

        if !probes.is_empty() {
            println!("Exec probes:");
            for probe in probes {
                println!(
                    "  {} expected {:?}, outcome {:?}, matched={}",
                    probe.path, probe.expected, probe.outcome, probe.matched
                );
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("nono-landlock-expansion-harness is Linux-only because it applies Landlock rules");
    std::process::exit(2);
}
