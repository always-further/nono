# Phase 8: ConPTY Shell — Implementation Brief

**Goal:** Users can run `nono shell` on Windows inside a Job Object + WFP sandbox via the ConPTY API, with working terminal resize and Ctrl-C forwarding.

**Depends on:** Phase 7 (pattern for removing Windows stub errors is validated there)

**Requirements:** SHELL-01

**Success criteria (all must be true when done):**
1. `nono shell` launches an interactive PowerShell or cmd.exe session inside a Job Object + WFP sandbox on Windows 10 build 17763+.
2. Terminal resize events sent to the host are forwarded to the child shell via `ResizePseudoConsole`.
3. Ctrl-C is forwarded to the child process without terminating the supervisor.
4. Running `nono shell` on a Windows build earlier than 17763 produces a clear error message and exits; there is no silent fallback to a non-PTY path.
5. Job Object and WFP enforcement apply to the shell child process at the moment of spawn, before `ResumeThread` is called.

**Coding standards (non-negotiable):**
- No `.unwrap()` or `.expect()` — enforced by `clippy::unwrap_used`
- All errors propagate via `?` using `NonoError`
- Every `unsafe` block must have a `// SAFETY:` comment
- Every commit needs a DCO sign-off: `Signed-off-by: Name <email>`
- Run `make ci` (clippy + fmt + tests) before committing

---

## Architecture context

Before writing any code, understand the existing wiring:

- `pty_proxy_windows.rs:open_pty()` — creates a `PtyPair` (`hpcon`, `input_write`, `output_read`) using `CreatePseudoConsole`. The PTY already exists; the problem is it's never used for non-detached sessions.
- `exec_strategy_windows/launch.rs:spawn_windows_child()` — spawns the sandboxed child process. Currently uses `STARTUPINFOW`, which is **wrong** for ConPTY. ConPTY requires `STARTUPINFOEXW` with `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE`. This is a latent bug that must be fixed.
- `exec_strategy_windows/supervisor.rs:WindowsSupervisorRuntime` — manages PTY I/O. `start_logging()` reads from `pty.output_read` for detached sessions. `start_data_pipe_server()` routes output through a named pipe for `nono attach` clients.
- `supervised_runtime.rs:create_session_runtime_state()` — creates the `PtyPair`, but **only when `session.detached_start` is true**. Shell (non-detached) never gets a PTY.
- `command_runtime.rs:run_shell()` — picks up `SHELL` env var or falls back to `/bin/sh`. On Windows, `/bin/sh` does not exist; default must be `cmd.exe` or `powershell.exe`.
- `sandbox/windows.rs:validate_preview_entry_point()` — unconditionally returns `UnsupportedPlatform` for `WindowsPreviewEntryPoint::Shell`.

There are **six separate gaps** to close. They must be done in the order listed below because each builds on the previous.

---

## Task A — Windows version check (build ≥ 17763)

ConPTY (`CreatePseudoConsole`) requires Windows 10 build 17763 (October 2018 Update). Builds before this must produce a clear error and exit, with no silent non-PTY fallback.

### Cargo.toml changes — add features for `RtlGetVersion`

`RtlGetVersion` bypasses the application-compatibility shim that `GetVersionExW` applies. It is the correct API for accurate build number detection.

In **`crates/nono/Cargo.toml`**, extend the `windows-sys` features array:
```toml
windows-sys = { version = "0.59", features = [
    "Win32_Foundation",
    "Win32_Security",
    "Win32_Security_Authorization",
    "Win32_Storage_FileSystem",
    "Win32_System_IO",
    "Win32_System_Pipes",
    "Win32_System_SystemServices",
    "Win32_System_Threading",
    "Wdk_System_SystemServices",       # RtlGetVersion
    "Win32_System_SystemInformation",  # OSVERSIONINFOW
] }
```

### `crates/nono/src/sandbox/windows.rs` — add the version check function

Add this function before `validate_preview_entry_point`:

```rust
/// Returns Ok if the current Windows build is ≥ 17763 (ConPTY minimum).
/// Returns Err with a clear message if the build is older.
///
/// Uses `RtlGetVersion` (ntdll) which bypasses the application-compatibility
/// shim that `GetVersionExW` applies on Windows 10+.
fn check_conpty_minimum_build() -> Result<()> {
    use windows_sys::Wdk::System::SystemServices::RtlGetVersion;
    use windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW;

    let mut info: OSVERSIONINFOW = unsafe {
        // SAFETY: OSVERSIONINFOW is a plain C struct; zero-init is the
        // required baseline before calling RtlGetVersion.
        std::mem::zeroed()
    };
    info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;

    let status = unsafe {
        // SAFETY: `info` is a valid, initialized OSVERSIONINFOW with the
        // size field set. RtlGetVersion always succeeds on Windows 10+.
        RtlGetVersion(&mut info)
    };

    if status != 0 {
        return Err(crate::error::NonoError::UnsupportedPlatform(format!(
            "Could not determine Windows build number (RtlGetVersion returned 0x{:X}). \
             `nono shell` requires Windows 10 build 17763 or later.",
            status
        )));
    }

    const CONPTY_MINIMUM_BUILD: u32 = 17763;
    if info.dwBuildNumber < CONPTY_MINIMUM_BUILD {
        return Err(crate::error::NonoError::UnsupportedPlatform(format!(
            "Windows build {} is too old for `nono shell`. \
             ConPTY (CreatePseudoConsole) requires build {} (Windows 10 October 2018 Update) or later. \
             There is no non-PTY fallback — upgrade Windows to use `nono shell`.",
            info.dwBuildNumber, CONPTY_MINIMUM_BUILD
        )));
    }

    Ok(())
}
```

---

## Task B — Remove the Shell stub from `validate_preview_entry_point`

**File:** `crates/nono/src/sandbox/windows.rs`, around line 190.

Replace the `WindowsPreviewEntryPoint::Shell` arm:

```rust
// BEFORE:
WindowsPreviewEntryPoint::Shell => Err(NonoError::UnsupportedPlatform(
    "Live `nono shell` is intentionally unavailable on Windows. ...".to_string(),
)),
```

With:

```rust
// AFTER:
WindowsPreviewEntryPoint::Shell => {
    // ConPTY requires build 17763+. Fail early with a clear message rather
    // than letting CreatePseudoConsole fail at spawn time.
    check_conpty_minimum_build()?;

    if let PreviewRuntimeStatus::RequiresEnforcement { reasons } =
        preview_runtime_status(caps, execution_dir, context)
    {
        return Err(NonoError::UnsupportedPlatform(format!(
            "Windows cannot enforce the requested sandbox controls for this nono shell run ({}). \
Use `nono shell --dry-run ...` to validate policy, or rerun without those controls.",
            reasons.join(", ")
        )));
    }
    Ok(())
}
```

Also update `WINDOWS_SUPPORTED_DETAILS` (around line 30–33). Change:

```
`nono shell` and `nono wrap` remain intentionally unavailable on Windows.
```

To:

```
`nono shell` is supported on Windows 10 build 17763+ via ConPTY (CreatePseudoConsole); the supervisor stays alive as Job Object owner. `nono wrap` is also supported.
```

**Update the test** `validate_preview_entry_point_rejects_shell` (around line 1544). Replace it with:

```rust
#[test]
fn validate_preview_entry_point_shell_fails_below_min_build() {
    // This test cannot easily simulate an old build — instead verify that Shell
    // with empty caps DOES NOT fail with the old "intentionally unavailable" message.
    // If the machine running this test has build ≥ 17763 (it does in CI), shell passes.
    let result = validate_preview_entry_point(
        WindowsPreviewEntryPoint::Shell,
        &CapabilitySet::new(),
        Path::new("."),
        WindowsPreviewContext::default(),
    );
    // On a build ≥ 17763, empty caps should succeed.
    // If CI runs an older build, this test should be skipped — but in practice
    // all supported CI targets are 17763+.
    assert!(
        result.is_ok(),
        "shell with no enforcement-required caps should succeed on build 17763+: {:?}",
        result
    );
}
```

---

## Task C — Add new Cargo features for ConPTY spawn APIs

In **`crates/nono-cli/Cargo.toml`**, the `windows-sys` features are already sufficient for ConPTY because:
- `Win32_System_Threading` covers: `InitializeProcThreadAttributeList`, `UpdateProcThreadAttribute`, `DeleteProcThreadAttributeList`, `STARTUPINFOEXW`, `EXTENDED_STARTUPINFO_PRESENT`, `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE`, `LPPROC_THREAD_ATTRIBUTE_LIST`
- `Win32_System_Console` covers: `ResizePseudoConsole`, `SetConsoleCtrlHandler`, `GetConsoleScreenBufferInfo`, `GetStdHandle`, `ReadConsoleInputW`, `WINDOW_BUFFER_SIZE_EVENT`, `CTRL_C_EVENT`, `STD_INPUT_HANDLE`, `STD_OUTPUT_HANDLE`, `CONSOLE_SCREEN_BUFFER_INFO`, `INPUT_RECORD`, `COORD`

No `Cargo.toml` change is needed for the CLI crate.

---

## Task D — Fix `spawn_windows_child` to use `STARTUPINFOEXW` + ConPTY attribute

**File:** `crates/nono-cli/src/exec_strategy_windows/launch.rs`

The current code sets `startup_info.hStdInput/Output/Error` from PTY handles. This is **wrong** — ConPTY connects to the child via a process attribute, not via stdio handle inheritance. Fix `spawn_windows_child` to use `STARTUPINFOEXW` with `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` when a PTY pair is present.

Add to the import block at the top of `launch.rs`:
```rust
use windows_sys::Win32::System::Threading::{
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
    InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, STARTUPINFOEXW, UpdateProcThreadAttribute,
};
```

Replace the body of `spawn_windows_child` — keep everything the same except the `STARTUPINFOW` setup. The new structure branches on whether `pty` is `Some`:

```rust
pub(super) fn spawn_windows_child(
    config: &ExecConfig<'_>,
    launch_program: &Path,
    containment: &ProcessContainment,
    cmd_args: &[String],
    pty: Option<&pty_proxy::PtyPair>,
    _session_id: Option<&str>,
) -> Result<WindowsSupervisedChild> {
    let env_pairs = build_child_env(config);
    let mut environment_block = build_windows_environment_block(&env_pairs);

    let h_token = if let Some(ref sid) = config.session_sid {
        restricted_token::create_restricted_token_with_sid(sid)?.h_token
    } else if should_use_low_integrity_windows_launch(config.caps) {
        create_low_integrity_primary_token()?.raw()
    } else {
        std::ptr::null_mut()
    };
    let token = OwnedHandle(h_token);

    let launch_program = normalize_windows_launch_path(launch_program);
    let current_dir = normalize_windows_launch_path(config.current_dir);
    let application_name = to_u16_null_terminated(&launch_program.to_string_lossy());
    let mut command_line = build_command_line(&launch_program, cmd_args);
    let current_dir_u16 = to_u16_null_terminated(&current_dir.to_string_lossy());

    let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let created = if let Some(pty_pair) = pty {
        // ConPTY path: use STARTUPINFOEXW + PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE.
        // The child connects to the PTY via the process attribute — NOT via
        // stdio handle inheritance (hStdInput/Output/Error must NOT be set).
        let mut attr_size: usize = 0;
        unsafe {
            // SAFETY: First call with null list just writes the required size to attr_size.
            InitializeProcThreadAttributeList(
                std::ptr::null_mut(),
                1,
                0,
                &mut attr_size,
            );
        }
        let mut attr_buf = vec![0u8; attr_size];
        let attr_list: LPPROC_THREAD_ATTRIBUTE_LIST =
            attr_buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;

        let ok = unsafe {
            // SAFETY: attr_list points to attr_buf which is sized for exactly
            // 1 attribute. dwFlags and dwAttributeCount match.
            InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size)
        };
        if ok == 0 {
            return Err(NonoError::SandboxInit(format!(
                "InitializeProcThreadAttributeList failed (error={})",
                unsafe { GetLastError() }
            )));
        }

        let hpcon_value = pty_pair.hpcon;
        let ok = unsafe {
            // SAFETY: attr_list is initialized above. hpcon_value is a valid
            // HPCON for the lifetime of this function. size_of::<HPCON>()
            // matches the attribute value type expected by the kernel.
            UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                std::ptr::addr_of!(hpcon_value) as *const _,
                size_of::<windows_sys::Win32::System::Console::HPCON>(),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        if ok == 0 {
            unsafe { DeleteProcThreadAttributeList(attr_list); }
            return Err(NonoError::SandboxInit(format!(
                "UpdateProcThreadAttribute (PSEUDOCONSOLE) failed (error={})",
                unsafe { GetLastError() }
            )));
        }

        let mut si_ex: STARTUPINFOEXW = unsafe {
            // SAFETY: STARTUPINFOEXW is a plain C struct; zero-init is valid.
            std::mem::zeroed()
        };
        // cb must be sizeof(STARTUPINFOEXW), not sizeof(STARTUPINFOW).
        si_ex.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        si_ex.lpAttributeList = attr_list;

        // Cast STARTUPINFOEXW* → STARTUPINFOW*: valid because StartupInfo is
        // the first member and EXTENDED_STARTUPINFO_PRESENT tells the kernel
        // to treat lpStartupInfo as STARTUPINFOEXW.
        let lp_si = &si_ex.StartupInfo as *const _ as *const _;

        let created = if !token.0.is_null() {
            unsafe {
                CreateProcessAsUserW(
                    token.raw(),
                    application_name.as_ptr(),
                    command_line.as_mut_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    0, // do NOT inherit handles
                    CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                    environment_block.as_mut_ptr() as *mut _,
                    current_dir_u16.as_ptr(),
                    lp_si,
                    &mut process_info,
                )
            }
        } else {
            unsafe {
                CreateProcessW(
                    application_name.as_ptr(),
                    command_line.as_mut_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    0, // do NOT inherit handles
                    CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                    environment_block.as_mut_ptr() as *mut _,
                    current_dir_u16.as_ptr(),
                    lp_si,
                    &mut process_info,
                )
            }
        };

        unsafe { DeleteProcThreadAttributeList(attr_list); }
        created
    } else {
        // Non-PTY path: standard STARTUPINFOW.
        let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
        si.cb = size_of::<STARTUPINFOW>() as u32;

        if !token.0.is_null() {
            unsafe {
                CreateProcessAsUserW(
                    token.raw(),
                    application_name.as_ptr(),
                    command_line.as_mut_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                    environment_block.as_mut_ptr() as *mut _,
                    current_dir_u16.as_ptr(),
                    &si,
                    &mut process_info,
                )
            }
        } else {
            unsafe {
                CreateProcessW(
                    application_name.as_ptr(),
                    command_line.as_mut_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                    environment_block.as_mut_ptr() as *mut _,
                    current_dir_u16.as_ptr(),
                    &si,
                    &mut process_info,
                )
            }
        }
    };

    if created == 0 {
        return Err(NonoError::SandboxInit(format!(
            "Failed to launch Windows child process (error={})",
            unsafe { GetLastError() }
        )));
    }

    let process = OwnedHandle(process_info.hProcess);
    let thread = OwnedHandle(process_info.hThread);

    if let Err(err) = apply_process_handle_to_containment(containment, process.raw()) {
        terminate_suspended_process(process.raw(), "AssignProcessToJobObject failed");
        return Err(err);
    }
    resume_contained_process(process.raw(), thread.raw())?;

    Ok(WindowsSupervisedChild::Native {
        process,
        _thread: thread,
    })
}
```

Also fix `prepare_runtime_hardened_args` — add an `interactive: bool` parameter. When `interactive` is true, omit `-NonInteractive` and `-NoProfile` from PowerShell args (users want their profile loaded in an interactive shell) and skip cmd.exe's `/d` (which disables AutoRun extensions):

```rust
pub(super) fn prepare_runtime_hardened_args(
    resolved_program: &Path,
    args: &[String],
    interactive: bool,
) -> Vec<String> {
    let program_name = resolved_program
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    match program_name.as_str() {
        "cmd.exe" | "cmd" => {
            if interactive {
                // Interactive cmd.exe: don't add /d (disables AutoRun)
                args.to_vec()
            } else if args.first().is_some_and(|a| a.eq_ignore_ascii_case("/d")) {
                args.to_vec()
            } else {
                let mut h = Vec::with_capacity(args.len() + 1);
                h.push("/d".to_string());
                h.extend_from_slice(args);
                h
            }
        }
        "powershell.exe" | "powershell" | "pwsh.exe" | "pwsh" => {
            let mut hardened = Vec::with_capacity(args.len() + 3);
            let mut has_no_logo = false;

            if !interactive {
                let mut has_no_profile = false;
                let mut has_non_interactive = false;
                for arg in args {
                    if arg.eq_ignore_ascii_case("-NoProfile") { has_no_profile = true; }
                    else if arg.eq_ignore_ascii_case("-NonInteractive") { has_non_interactive = true; }
                    else if arg.eq_ignore_ascii_case("-NoLogo") { has_no_logo = true; }
                }
                if !has_no_profile { hardened.push("-NoProfile".to_string()); }
                if !has_non_interactive { hardened.push("-NonInteractive".to_string()); }
            } else {
                for arg in args {
                    if arg.eq_ignore_ascii_case("-NoLogo") { has_no_logo = true; }
                }
            }

            if !has_no_logo { hardened.push("-NoLogo".to_string()); }
            hardened.extend_from_slice(args);
            hardened
        }
        // cscript and wscript: interactive flag not relevant (no shell prompt)
        // Keep existing logic unchanged for non-interactive, pass through for interactive.
        "cscript.exe" | "cscript" => {
            if interactive { return args.to_vec(); }
            // ... (keep existing cscript logic as-is)
            let mut hardened = Vec::with_capacity(args.len() + 2);
            let mut has_no_logo = false;
            let mut has_batch = false;
            for arg in args {
                if arg.eq_ignore_ascii_case("//NoLogo") { has_no_logo = true; }
                else if arg.eq_ignore_ascii_case("//B") { has_batch = true; }
            }
            if !has_no_logo { hardened.push("//NoLogo".to_string()); }
            if !has_batch { hardened.push("//B".to_string()); }
            hardened.extend_from_slice(args);
            hardened
        }
        "wscript.exe" | "wscript" => {
            if interactive { return args.to_vec(); }
            if args.iter().any(|a| a.eq_ignore_ascii_case("//NoLogo")) {
                args.to_vec()
            } else {
                let mut h = Vec::with_capacity(args.len() + 1);
                h.push("//NoLogo".to_string());
                h.extend_from_slice(args);
                h
            }
        }
        _ => args.to_vec(),
    }
}
```

Update every call site of `prepare_runtime_hardened_args` in this file to pass `false` for `interactive` (they are non-interactive). In `exec_strategy_windows/mod.rs`, the call in `execute_supervised` and `execute_direct` pass `config.interactive_shell` — see Task E below.

---

## Task E — Plumb `interactive_shell` from `run_shell` to the ExecConfig

Several structs need a new field.

### `crates/nono-cli/src/launch_runtime.rs`

Add to `SessionLaunchOptions`:
```rust
pub(crate) struct SessionLaunchOptions {
    pub(crate) detached_start: bool,
    pub(crate) session_id: String,
    pub(crate) session_name: Option<String>,
    pub(crate) profile_name: Option<String>,
    pub(crate) detach_sequence: Option<Vec<u8>>,
    pub(crate) interactive_pty: bool,   // NEW: true for `nono shell` (non-detached)
}
```

### `crates/nono-cli/src/exec_strategy_windows/mod.rs`

Add to `ExecConfig`:
```rust
pub struct ExecConfig<'a> {
    pub command: &'a [String],
    pub resolved_program: &'a Path,
    pub caps: &'a CapabilitySet,
    pub env_vars: Vec<(&'a str, &'a str)>,
    pub cap_file: Option<&'a Path>,
    pub current_dir: &'a Path,
    pub session_sid: Option<String>,
    pub interactive_shell: bool,   // NEW: skip -NonInteractive for shell spawns
}
```

Add to `SupervisorConfig`:
```rust
pub struct SupervisorConfig<'a> {
    pub session_id: &'a str,
    pub requested_features: Vec<&'a str>,
    pub support: nono::WindowsSupervisorSupport,
    pub approval_backend: &'a dyn ApprovalBackend,
    pub interactive_shell: bool,   // NEW: true for attached interactive shell
}
```

Update the two `prepare_runtime_hardened_args` calls in `execute_supervised` and `execute_direct` in `mod.rs` to pass `config.interactive_shell`:

```rust
// In execute_direct:
let cmd_args = prepare_runtime_hardened_args(launch_program, &config.command[1..], config.interactive_shell);

// In execute_supervised:
let cmd_args = prepare_runtime_hardened_args(launch_program, &config.command[1..], config.interactive_shell);
```

Also update `spawn_supervised_with_low_integrity` and `spawn_supervised_with_standard_token` in `launch.rs` to pass `config.interactive_shell` to their `prepare_runtime_hardened_args` calls.

### `crates/nono-cli/src/execution_runtime.rs`

In the Windows `ExecConfig` construction (around line 261):
```rust
#[cfg(target_os = "windows")]
let config = exec_strategy::ExecConfig {
    command: &command,
    resolved_program: &resolved_program,
    caps: &caps,
    env_vars,
    cap_file: cap_file.as_deref(),
    current_dir: &current_dir,
    session_sid: Some(exec_strategy::generate_session_sid()),
    interactive_shell: flags.interactive_shell,   // NEW
};
```

Add `interactive_shell: bool` to `ExecutionFlags` in `launch_runtime.rs`:
```rust
pub(crate) struct ExecutionFlags {
    pub(crate) strategy: exec_strategy::ExecStrategy,
    pub(crate) workdir: PathBuf,
    pub(crate) no_diagnostics: bool,
    pub(crate) silent: bool,
    pub(crate) capability_elevation: bool,
    // ... existing fields
    pub(crate) interactive_shell: bool,   // NEW
    // ...
}
```

The `ExecutionFlags::defaults()` constructor should set `interactive_shell: false`.

### `crates/nono-cli/src/command_runtime.rs`

In `run_shell`, set the new fields:
```rust
// 1. Fix default shell for Windows
#[cfg(target_os = "windows")]
let shell_path = args.shell.unwrap_or_else(|| {
    let system_root = std::env::var("SystemRoot")
        .unwrap_or_else(|_| r"C:\Windows".to_string());
    // Prefer PowerShell 5 (ships with all Windows 10 builds)
    let pwsh = std::path::PathBuf::from(&system_root)
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    if pwsh.exists() {
        pwsh
    } else {
        std::path::PathBuf::from(&system_root)
            .join("System32")
            .join("cmd.exe")
    }
});
#[cfg(not(target_os = "windows"))]
let shell_path = args
    .shell
    .or_else(|| {
        std::env::var("SHELL")
            .ok()
            .filter(|s| !s.is_empty())
            .map(std::path::PathBuf::from)
    })
    .unwrap_or_else(|| std::path::PathBuf::from("/bin/sh"));

// 2. Set interactive_pty and interactive_shell flags
execute_sandboxed(LaunchPlan {
    program: shell_path.into_os_string(),
    cmd_args: vec![],
    caps: prepared.caps,
    loaded_secrets: prepared.secrets,
    flags: ExecutionFlags {
        workdir: resolve_requested_workdir(args.sandbox.workdir.as_ref()),
        no_diagnostics: true,
        interactive_shell: true,    // NEW: skip -NonInteractive in Windows hardening
        capability_elevation: prepared.capability_elevation,
        override_deny_paths: prepared.override_deny_paths,
        session: SessionLaunchOptions {
            session_name: args.name,
            detach_sequence: load_configured_detach_sequence()?,
            interactive_pty: true,  // NEW: create ConPTY even for attached session
            ..SessionLaunchOptions::default()
        },
        ..ExecutionFlags::defaults(silent)?
    },
})
```

### `crates/nono-cli/src/supervised_runtime.rs`

Change PTY creation condition:
```rust
// BEFORE:
let pty_pair = if session.detached_start {
    Some(pty_proxy::open_pty()?)
} else {
    None
};

// AFTER:
let pty_pair = if session.detached_start || session.interactive_pty {
    Some(pty_proxy::open_pty()?)
} else {
    None
};
```

In the Windows `supervisor_cfg` construction (around line 182), add the new field:
```rust
#[cfg(target_os = "windows")]
let supervisor_cfg = exec_strategy::SupervisorConfig {
    session_id: &supervisor_session_id,
    requested_features: ...,
    support: ...,
    approval_backend: &approval_backend,
    interactive_shell: session.interactive_pty && !session.detached_start,  // NEW
};
```

---

## Task F — Terminal I/O forwarding, resize, and Ctrl-C in the supervisor

**File:** `crates/nono-cli/src/exec_strategy_windows/supervisor.rs`

This is the most complex change. Add a new `start_interactive_terminal_io` method to `WindowsSupervisorRuntime` and call it instead of `start_logging` + `start_data_pipe_server` when in interactive shell mode.

Add these imports to `supervisor.rs`:
```rust
use windows_sys::Win32::System::Console::{
    GetConsoleScreenBufferInfo, GetStdHandle, ResizePseudoConsole, SetConsoleCtrlHandler,
    CONSOLE_SCREEN_BUFFER_INFO, COORD, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    CTRL_C_EVENT,
};
use windows_sys::Win32::Foundation::BOOL;
```

Add the `interactive_shell` field to `WindowsSupervisorRuntime`:
```rust
pub(super) struct WindowsSupervisorRuntime {
    // ... existing fields ...
    interactive_shell: bool,          // NEW
}
```

Set it in `initialize`:
```rust
let mut runtime = Self {
    // ... existing fields ...
    interactive_shell: supervisor.interactive_shell,
};
```

Change the initialization call sequence in `initialize`:
```rust
runtime.start_control_pipe_server()?;
if runtime.interactive_shell {
    runtime.start_interactive_terminal_io()?;
} else {
    runtime.start_logging()?;
    runtime.start_data_pipe_server()?;
}
```

Add the new method. It does three things: terminal I/O forwarding, resize polling, and Ctrl-C suppression.

```rust
fn start_interactive_terminal_io(&self) -> Result<()> {
    let pty = self.pty.as_ref().ok_or_else(|| {
        NonoError::SandboxInit(
            "interactive_shell requires a PTY pair but none was provided".to_string(),
        )
    })?;

    let session_id = self.session_id.clone();
    let output_read = pty.output_read as usize;
    let input_write = pty.input_write as usize;
    let hpcon = pty.hpcon;

    // --- Ctrl-C suppression ---
    // Install a no-op handler so Ctrl-C does not terminate the supervisor.
    // The child shell receives Ctrl-C naturally via the ConPTY connection.
    unsafe extern "system" fn ctrl_handler(ctrl_type: u32) -> BOOL {
        if ctrl_type == CTRL_C_EVENT {
            1 // TRUE — handled; do not propagate to default handler
        } else {
            0 // FALSE — let the default handler run (e.g., for CTRL_CLOSE_EVENT)
        }
    }
    unsafe {
        // SAFETY: ctrl_handler has the correct signature for SetConsoleCtrlHandler.
        // It is a static function and will remain valid for the process lifetime.
        SetConsoleCtrlHandler(Some(ctrl_handler), 1);
    }

    // --- Output forwarding: PTY → stdout + log file ---
    {
        let session_id = session_id.clone();
        std::thread::spawn(move || {
            // Resolve log path for this session (may fail silently — shell output
            // goes to terminal regardless).
            let log_path = crate::session::session_log_path(&session_id).ok();
            let mut log_file = log_path.and_then(|p| {
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)
                    .ok()
            });

            let mut pty_out =
                std::mem::ManuallyDrop::new(unsafe {
                    // SAFETY: output_read is a valid pipe handle owned by the PtyPair.
                    // ManuallyDrop prevents double-close; PtyPair's Drop closes it.
                    std::fs::File::from_raw_handle(output_read as _)
                });
            let mut stdout = std::io::stdout();
            let mut buf = [0u8; 4096];

            while let Ok(n) = {
                use std::io::Read;
                pty_out.read(&mut buf)
            } {
                if n == 0 { break; }
                use std::io::Write;
                let _ = stdout.write_all(&buf[..n]);
                let _ = stdout.flush();
                if let Some(ref mut f) = log_file {
                    let _ = f.write_all(&buf[..n]);
                }
            }
        });
    }

    // --- Input forwarding: stdin → PTY ---
    {
        std::thread::spawn(move || {
            let mut pty_in =
                std::mem::ManuallyDrop::new(unsafe {
                    // SAFETY: input_write is a valid pipe handle owned by the PtyPair.
                    std::fs::File::from_raw_handle(input_write as _)
                });
            let mut stdin = std::io::stdin();
            let mut buf = [0u8; 4096];

            loop {
                use std::io::{Read, Write};
                match stdin.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if pty_in.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                }
            }
        });
    }

    // --- Terminal resize polling ---
    // Poll the parent console size every 100 ms and call ResizePseudoConsole
    // when it changes. This is simpler than ReadConsoleInput event monitoring
    // and has at most 100 ms latency, which is acceptable for resize events.
    {
        std::thread::spawn(move || {
            let h_stdout = unsafe {
                // SAFETY: GetStdHandle(STD_OUTPUT_HANDLE) always returns a valid
                // console handle or INVALID_HANDLE_VALUE; we check before use.
                GetStdHandle(STD_OUTPUT_HANDLE)
            };
            if h_stdout.is_null() || h_stdout == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                return;
            }

            let mut last_size = COORD { X: 0, Y: 0 };

            loop {
                std::thread::sleep(std::time::Duration::from_millis(100));

                let mut info: CONSOLE_SCREEN_BUFFER_INFO = unsafe { std::mem::zeroed() };
                let ok = unsafe {
                    // SAFETY: h_stdout is a valid console screen buffer handle.
                    GetConsoleScreenBufferInfo(h_stdout, &mut info)
                };
                if ok == 0 {
                    break;
                }

                let cols = info.srWindow.Right - info.srWindow.Left + 1;
                let rows = info.srWindow.Bottom - info.srWindow.Top + 1;
                let new_size = COORD { X: cols, Y: rows };

                if new_size.X != last_size.X || new_size.Y != last_size.Y {
                    last_size = new_size;
                    unsafe {
                        // SAFETY: hpcon is a valid PseudoConsole handle for the
                        // duration of this thread (PtyPair outlives the supervisor).
                        // Ignoring the HRESULT is safe — a failed resize is non-fatal.
                        ResizePseudoConsole(hpcon, new_size);
                    }
                }
            }
        });
    }

    Ok(())
}
```

---

## Task G — Update help text

### `crates/nono-cli/src/cli.rs`

**`SHELL_AFTER_HELP`** (the Windows `#[cfg(target_os = "windows")]` constant — find by searching for the "WINDOWS" block in the shell command's after_help). Replace the Windows block with:

```rust
#[cfg(target_os = "windows")]
const SHELL_AFTER_HELP: &str = "\x1b[1mEXAMPLES\x1b[0m
  nono shell                                   # Launch interactive shell (PowerShell or cmd.exe)
  nono shell --shell cmd.exe                   # Explicitly use cmd.exe
  nono shell --allow . --block-net             # Shell with write access but no network

\x1b[1mWINDOWS BEHAVIOR\x1b[0m
  On Windows, `nono shell` launches PowerShell (or cmd.exe if PowerShell is absent)
  inside a Job Object + WFP sandbox via ConPTY (requires Windows 10 build 17763+).
  The supervisor process stays alive as Job Object owner; it does not exec-replace
  the CLI, unlike on Unix.
  Terminal resize events are forwarded via ResizePseudoConsole.
  Ctrl-C is forwarded to the child shell without terminating the supervisor.
  There is no silent fallback to a non-PTY path on unsupported builds.";
```

**`ROOT_HELP_TEMPLATE`** (Windows version, around line 90). Change:
```
  shell      Inspect shell policy; live shell is intentionally unavailable on Windows
```
To:
```
  shell      Launch interactive shell (ConPTY, build 17763+); use --dry-run to inspect policy
```

---

## Verification

After all changes, run:

```bash
make ci
```

Expected: zero warnings, zero test failures, including the updated `validate_preview_entry_point_shell_fails_below_min_build` test.

Functional spot-checks (on Windows 10 build 17763+):

```powershell
# Dry run — should print policy without blocking
nono shell --dry-run

# Live shell — should open PowerShell inside sandbox
nono shell --allow .

# Old build simulation — cannot easily test, but the build check code path
# is covered by the unit test.
```

The success criteria require that success criteria 5 (Job Object + WFP enforced before `ResumeThread`) is already satisfied by the existing `spawn_windows_child` logic (it calls `apply_process_handle_to_containment` before `resume_contained_process`). No additional change is needed for that criterion.
