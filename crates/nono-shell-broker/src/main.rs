//! `nono-shell-broker` — Phase 31 D-05 broker binary.
//!
//! Medium-IL intermediary spawned by `nono.exe` for the `nono shell` command on
//! Windows. The broker:
//!
//! 1. Inherits a console attachment from `nono.exe` at Medium IL (KernelBase
//!    skips CSRSS attach for already-inherited consoles — RESEARCH A1, validated
//!    by the 2026-05-08 PoC at `.planning/quick/260508-m99-.../`).
//! 2. Constructs a Low-IL primary token via `nono::create_low_integrity_primary_token`
//!    (D-06: single source of truth shared with `nono-cli`).
//! 3. Spawns the actual sandboxed shell child via `CreateProcessAsUserW` with
//!    `dwCreationFlags = EXTENDED_STARTUPINFO_PRESENT` only (D-01: NO new
//!    console flag, NO pseudoconsole proc-thread attribute — child inherits
//!    broker's console without re-triggering CSRSS attach at Low IL).
//! 4. Restricts inherited handles via `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` to
//!    only those passed by `nono.exe` via `--inherit-handle <hex>` (D-02:
//!    capability-pipe and other supervisor handles are NEVER inheritable past
//!    `nono.exe`).
//! 5. Waits for the child via `WaitForSingleObject(INFINITE)` and propagates
//!    the exit code via `std::process::exit(child_exit_code as i32)` (D-03).
//!
//! No JSON parsing surface; argv is the only IPC channel from `nono.exe` (D-08).

#[cfg(not(windows))]
fn main() {
    eprintln!(
        "nono-shell-broker is a Windows-only binary; \
         this build target should not ship it. \
         Phase 31 D-05: cross-compile parity stub."
    );
    std::process::exit(1);
}

#[cfg(windows)]
mod broker {
    use std::ffi::{OsStr, OsString};
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::path::PathBuf;

    use nono::{NonoError, OwnedHandle, Result as NonoResult};
    use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
    use windows_sys::Win32::System::Console::AllocConsole;
    use windows_sys::Win32::System::Threading::{
        CreateProcessAsUserW, DeleteProcThreadAttributeList, GetExitCodeProcess,
        InitializeProcThreadAttributeList, UpdateProcThreadAttribute, WaitForSingleObject,
        EXTENDED_STARTUPINFO_PRESENT, INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTUPINFOEXW, STARTUPINFOW,
    };

    /// D-08: argv-only IPC. CapabilitySet/Profile NOT passed (RESEARCH §3a —
    /// labels applied supervisor-side BEFORE the broker is spawned).
    #[derive(Debug)]
    pub struct BrokerArgs {
        pub shell_path: PathBuf,
        pub shell_args: Vec<String>,
        pub inherit_handles: Vec<HANDLE>,
        pub cwd: PathBuf,
    }

    /// Manual argv loop. No `clap` — RESEARCH §4a: broker attack surface MUST
    /// be minimal. Parse errors fail fast; no positional args, every arg is
    /// flag-prefixed.
    pub fn parse_args(raw: &[OsString]) -> NonoResult<BrokerArgs> {
        let mut shell_path: Option<PathBuf> = None;
        let mut shell_args: Vec<String> = Vec::new();
        let mut inherit_handles: Vec<HANDLE> = Vec::new();
        let mut cwd: Option<PathBuf> = None;

        // Skip argv[0] (the broker binary path).
        let mut iter = raw.iter().skip(1);
        while let Some(flag) = iter.next() {
            let flag_str = flag.to_string_lossy();
            match flag_str.as_ref() {
                "--shell" => {
                    let v = iter
                        .next()
                        .ok_or_else(|| NonoError::SandboxInit("--shell requires a value".into()))?;
                    shell_path = Some(PathBuf::from(v));
                }
                "--shell-arg" => {
                    let v = iter.next().ok_or_else(|| {
                        NonoError::SandboxInit("--shell-arg requires a value".into())
                    })?;
                    shell_args.push(v.to_string_lossy().into_owned());
                }
                "--inherit-handle" => {
                    let v = iter.next().ok_or_else(|| {
                        NonoError::SandboxInit("--inherit-handle requires a hex value".into())
                    })?;
                    let hex_str = v.to_string_lossy();
                    let stripped = hex_str.trim_start_matches("0x").trim_start_matches("0X");
                    let raw_value = usize::from_str_radix(stripped, 16).map_err(|e| {
                        NonoError::SandboxInit(format!(
                            "--inherit-handle parse error for '{hex_str}': {e}"
                        ))
                    })?;
                    inherit_handles.push(raw_value as HANDLE);
                }
                "--cwd" => {
                    let v = iter
                        .next()
                        .ok_or_else(|| NonoError::SandboxInit("--cwd requires a value".into()))?;
                    cwd = Some(PathBuf::from(v));
                }
                other => {
                    return Err(NonoError::SandboxInit(format!(
                        "unknown broker arg: '{other}'"
                    )));
                }
            }
        }

        let shell_path =
            shell_path.ok_or_else(|| NonoError::SandboxInit("missing required --shell".into()))?;
        let cwd = cwd.ok_or_else(|| NonoError::SandboxInit("missing required --cwd".into()))?;
        Ok(BrokerArgs {
            shell_path,
            shell_args,
            inherit_handles,
            cwd,
        })
    }

    /// Build a Win32 command line: `"<shell_path>" arg1 arg2 ...`.
    /// Quoting policy: shell_path always quoted; args quoted if they contain
    /// whitespace or `"`. This matches the PoC's implicit shape (PoC used a
    /// single literal string `"powershell.exe -NoLogo"`).
    pub fn build_command_line(args: &BrokerArgs) -> Vec<u16> {
        let mut cmd = String::new();
        cmd.push('"');
        cmd.push_str(&args.shell_path.to_string_lossy());
        cmd.push('"');
        for a in &args.shell_args {
            cmd.push(' ');
            if a.contains(' ') || a.contains('"') {
                cmd.push('"');
                // Escape embedded quotes by doubling them (PowerShell convention).
                cmd.push_str(&a.replace('"', "\"\""));
                cmd.push('"');
            } else {
                cmd.push_str(a);
            }
        }
        OsStr::new(&cmd).encode_wide().chain(Some(0)).collect()
    }

    fn to_u16_null_terminated(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(Some(0)).collect()
    }

    /// 8-step sequence. Mechanism MUST stay byte-equivalent to the validated
    /// PoC at `.planning/quick/260508-m99-.../poc-broker/src/main.rs:36-186`,
    /// with token construction unified through `nono::create_low_integrity_primary_token`
    /// per D-06 and HANDLE_LIST discipline added per D-02.
    pub fn run(args: BrokerArgs) -> NonoResult<i32> {
        // Step 1: AllocConsole — non-fatal if parent already attached.
        // rc=0 means console inherited (expected when spawned by nono.exe);
        // rc != 0 means new console (when broker invoked standalone for testing).
        let alloc_rc = unsafe {
            // SAFETY: AllocConsole takes no arguments; safe to call unconditionally.
            AllocConsole()
        };
        tracing::info!(alloc_console_rc = alloc_rc, "broker: console attach probe");

        // Steps 2-5: Construct Low-IL primary token via the lifted library function (D-06).
        // The OwnedHandle returned manages CloseHandle on drop — RAII per Pattern S-07.
        let low_il_token: OwnedHandle = nono::create_low_integrity_primary_token()?;
        tracing::info!("broker: Low-IL primary token constructed");

        // Step 6: Build PROC_THREAD_ATTRIBUTE_HANDLE_LIST per D-02 (production hardening over PoC).
        // Probe required size for one attribute slot.
        let mut attr_size: usize = 0;
        unsafe {
            // SAFETY: First call with null list queries required size; documented Win32 idiom.
            // Documented to return ERROR_INSUFFICIENT_BUFFER and write the required size.
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut attr_size);
        }
        let mut attr_buf = vec![0u8; attr_size];
        let attr_list: LPPROC_THREAD_ATTRIBUTE_LIST =
            attr_buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
        let ok = unsafe {
            // SAFETY: attr_list points to attr_buf, sized by the probe call above for one attribute.
            InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size)
        };
        if ok == 0 {
            let err = unsafe {
                // SAFETY: GetLastError takes no arguments; always safe to call.
                GetLastError()
            };
            return Err(NonoError::SandboxInit(format!(
                "InitializeProcThreadAttributeList failed (GetLastError={err})"
            )));
        }

        // D-02: HANDLE_LIST = exactly the inheritable handles passed via --inherit-handle.
        // If the array is empty, we still must initialize the attr_list and pass
        // EXTENDED_STARTUPINFO_PRESENT — the empty list means no handles inherit
        // (most restrictive shape).
        let handles_array: Vec<HANDLE> = args.inherit_handles.clone();
        let handles_byte_size = std::mem::size_of_val(handles_array.as_slice());
        let ok = unsafe {
            // SAFETY: attr_list initialized above; handles_array lives for the duration of the call.
            UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles_array.as_ptr() as *mut _,
                handles_byte_size,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            let err = unsafe {
                // SAFETY: GetLastError takes no arguments; always safe to call.
                GetLastError()
            };
            unsafe {
                // SAFETY: attr_list was initialized successfully above.
                DeleteProcThreadAttributeList(attr_list);
            }
            return Err(NonoError::SandboxInit(format!(
                "UpdateProcThreadAttribute(HANDLE_LIST) failed (GetLastError={err})"
            )));
        }

        // Step 7: CreateProcessAsUserW with dwCreationFlags = EXTENDED_STARTUPINFO_PRESENT only.
        // D-01: no new-console flag, no pseudoconsole proc-thread attribute — child inherits
        // the broker's already-attached console; KernelBase skips CSRSS attach at Low IL because
        // a console handle is already inherited (RESEARCH A1, PoC-validated 2026-05-08).
        let mut command_line = build_command_line(&args);
        let cwd_wide = to_u16_null_terminated(args.cwd.as_os_str());

        let mut startup_info_ex: STARTUPINFOEXW = unsafe {
            // SAFETY: STARTUPINFOEXW is #[repr(C)] POD; zero-init is documented Win32 idiom.
            std::mem::zeroed()
        };
        startup_info_ex.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup_info_ex.lpAttributeList = attr_list;

        let mut process_info: PROCESS_INFORMATION = unsafe {
            // SAFETY: PROCESS_INFORMATION zero-init is documented Win32 idiom.
            std::mem::zeroed()
        };

        let lp_startup_info = &startup_info_ex.StartupInfo as *const STARTUPINFOW;

        let created = unsafe {
            // SAFETY: low_il_token.raw() is a valid primary token (RAII-owned by OwnedHandle).
            // command_line is null-terminated UTF-16. cwd_wide is null-terminated. The startup
            // struct is correctly initialized with EXTENDED_STARTUPINFO_PRESENT semantics.
            // bInheritHandles=1 is required when PROC_THREAD_ATTRIBUTE_HANDLE_LIST is set;
            // the HANDLE_LIST attribute restricts the actual inherited set to args.inherit_handles.
            CreateProcessAsUserW(
                low_il_token.raw(),
                std::ptr::null(),
                command_line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,                            // bInheritHandles=TRUE (HANDLE_LIST gates)
                EXTENDED_STARTUPINFO_PRESENT, // dwCreationFlags (D-01: no new-console flag)
                std::ptr::null(),             // lpEnvironment: inherit broker env
                cwd_wide.as_ptr(),
                lp_startup_info,
                &mut process_info,
            )
        };

        unsafe {
            // SAFETY: attr_list was initialized above and is no longer needed
            // after CreateProcessAsUserW.
            DeleteProcThreadAttributeList(attr_list);
        }

        if created == 0 {
            let err = unsafe {
                // SAFETY: GetLastError takes no arguments; always safe to call.
                GetLastError()
            };
            return Err(NonoError::SandboxInit(format!(
                "CreateProcessAsUserW failed (GetLastError={err})"
            )));
        }

        // Wrap child handles in OwnedHandle for RAII cleanup.
        let child_process = OwnedHandle(process_info.hProcess);
        let _child_thread = OwnedHandle(process_info.hThread);
        tracing::info!(
            child_pid = process_info.dwProcessId,
            "broker: spawned Low-IL child"
        );

        // Step 8: Wait + propagate exit code (D-03).
        let wait_rc = unsafe {
            // SAFETY: child_process.raw() is a valid process handle from CreateProcessAsUserW.
            WaitForSingleObject(child_process.raw(), INFINITE)
        };
        if wait_rc != 0 {
            let err = unsafe {
                // SAFETY: GetLastError takes no arguments; always safe to call.
                GetLastError()
            };
            return Err(NonoError::SandboxInit(format!(
                "WaitForSingleObject failed (rc={wait_rc}, GetLastError={err})"
            )));
        }

        let mut exit_code: u32 = 0;
        let ok = unsafe {
            // SAFETY: child_process.raw() is still valid; exit_code is a valid out-pointer.
            GetExitCodeProcess(child_process.raw(), &mut exit_code)
        };
        if ok == 0 {
            let err = unsafe {
                // SAFETY: GetLastError takes no arguments; always safe to call.
                GetLastError()
            };
            return Err(NonoError::SandboxInit(format!(
                "GetExitCodeProcess failed (GetLastError={err})"
            )));
        }

        tracing::info!(child_exit_code = exit_code, "broker: child exited");
        // OwnedHandle Drop closes child_process, child_thread, and low_il_token automatically.
        Ok(exit_code as i32)
    }
}

#[cfg(windows)]
fn main() {
    // Tracing → broker's stderr; nono.exe's WindowsSupervisorRuntime captures
    // broker stderr per existing log routing (Claude's Discretion: stderr-only,
    // no separate file).
    //
    // EnvFilter resolution: explicit `match` (not `unwrap_or_else`) — CLAUDE.md
    // § Unwrap Policy. RUST_LOG override → use it; otherwise default to "info".
    let env_filter = match tracing_subscriber::EnvFilter::try_from_default_env() {
        Ok(filter) => filter,
        Err(_) => tracing_subscriber::EnvFilter::new("info"),
    };
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(env_filter)
        .init();

    let raw: Vec<std::ffi::OsString> = std::env::args_os().collect();
    match broker::parse_args(&raw).and_then(broker::run) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            tracing::error!(error = %e, "broker: fatal error");
            eprintln!("nono-shell-broker: {e}");
            std::process::exit(2);
        }
    }
}
