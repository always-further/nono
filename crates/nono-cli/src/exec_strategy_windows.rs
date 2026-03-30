//! Windows execution strategy placeholder.
//!
//! WIN-101 needs the CLI to compile on Windows without pulling in the Unix
//! supervisor and fork/exec machinery. This file intentionally provides a
//! smaller Windows surface that can be expanded in later stories.

#[path = "exec_strategy/env_sanitization.rs"]
mod env_sanitization;

use nono::{CapabilitySet, NonoError, Result, Sandbox};
use std::collections::HashSet;
use std::ffi::OsStr;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::Command;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, DuplicateTokenEx, SecurityImpersonation, SetTokenInformation,
    TokenIntegrityLevel, TokenPrimary, WinLowLabelSid, SECURITY_IMPERSONATION_LEVEL,
    SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES, TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY,
    TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::SystemServices::SE_GROUP_INTEGRITY;
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken,
    WaitForSingleObject, CREATE_UNICODE_ENVIRONMENT, INFINITE, PROCESS_INFORMATION, STARTUPINFOW,
};

pub(crate) use env_sanitization::is_dangerous_env_var;
use env_sanitization::should_skip_env_var;

pub fn resolve_program(program: &str) -> Result<PathBuf> {
    which::which(program).map_err(|e| {
        NonoError::CommandExecution(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{}: {}", program, e),
        ))
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThreadingContext {
    #[default]
    Strict,
    KeyringExpected,
    CryptoExpected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExecStrategy {
    Direct,
    #[default]
    Supervised,
}

pub struct ExecConfig<'a> {
    pub command: &'a [String],
    pub resolved_program: &'a Path,
    pub caps: &'a CapabilitySet,
    pub env_vars: Vec<(&'a str, &'a str)>,
    pub cap_file: Option<&'a Path>,
    pub current_dir: &'a Path,
}

pub struct SupervisorConfig<'a> {
    pub session_id: &'a str,
    pub requested_features: Vec<&'a str>,
}

struct ProcessContainment {
    job: HANDLE,
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                // SAFETY: This handle is owned by the wrapper and is closed
                // exactly once on drop.
                CloseHandle(self.0);
            }
        }
    }
}

impl Drop for ProcessContainment {
    fn drop(&mut self) {
        if !self.job.is_null() {
            unsafe {
                // SAFETY: `self.job` was returned by CreateJobObjectW and is
                // owned by this struct. Closing the handle releases the job.
                CloseHandle(self.job);
            }
        }
    }
}

fn create_process_containment() -> Result<ProcessContainment> {
    let job = unsafe {
        // SAFETY: Null security attributes and name are valid for creating an
        // unnamed job object owned by the current process.
        CreateJobObjectW(std::ptr::null(), std::ptr::null())
    };
    if job.is_null() {
        return Err(NonoError::SandboxInit(
            "Failed to create Windows process containment job object".to_string(),
        ));
    }

    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe {
        // SAFETY: JOBOBJECT_EXTENDED_LIMIT_INFORMATION is a plain Win32 FFI
        // struct. Zero-initialization is the standard baseline before setting
        // the specific fields we rely on below.
        std::mem::zeroed()
    };
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;

    let ok = unsafe {
        // SAFETY: `limits` points to initialized memory of the exact struct
        // type required for JobObjectExtendedLimitInformation.
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &limits as *const _ as *const _,
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if ok == 0 {
        unsafe {
            // SAFETY: `job` is an owned handle created above.
            CloseHandle(job);
        }
        return Err(NonoError::SandboxInit(
            "Failed to configure Windows process containment job object".to_string(),
        ));
    }

    Ok(ProcessContainment { job })
}

fn apply_process_containment(
    containment: &ProcessContainment,
    child: &std::process::Child,
) -> Result<()> {
    let process = child.as_raw_handle() as HANDLE;
    let ok = unsafe {
        // SAFETY: `containment.job` is a live job handle owned by the current
        // process, and `process` is the live child process handle returned by
        // std::process::Command::spawn().
        AssignProcessToJobObject(containment.job, process)
    };
    if ok == 0 {
        return Err(NonoError::SandboxInit(
            "Failed to assign Windows child process to process containment job object".to_string(),
        ));
    }
    Ok(())
}

fn apply_process_handle_to_containment(
    containment: &ProcessContainment,
    process: HANDLE,
) -> Result<()> {
    let ok = unsafe {
        // SAFETY: `containment.job` is a live job handle owned by the current
        // process, and `process` is a live process handle returned by
        // CreateProcessAsUserW.
        AssignProcessToJobObject(containment.job, process)
    };
    if ok == 0 {
        return Err(NonoError::SandboxInit(
            "Failed to assign Windows child process to process containment job object".to_string(),
        ));
    }
    Ok(())
}

fn initialize_supervisor_control_channel(
) -> Result<(nono::SupervisorSocket, nono::SupervisorSocket)> {
    nono::SupervisorSocket::pair().map_err(|e| {
        NonoError::SandboxInit(format!(
            "Failed to initialize Windows supervisor control channel: {e}"
        ))
    })
}

fn prepare_runtime_hardened_args(resolved_program: &Path, args: &[String]) -> Vec<String> {
    let program_name = resolved_program
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    match program_name.as_str() {
        "cmd.exe" | "cmd" => {
            if args
                .first()
                .is_some_and(|arg| arg.eq_ignore_ascii_case("/d"))
            {
                args.to_vec()
            } else {
                let mut hardened = Vec::with_capacity(args.len() + 1);
                hardened.push("/d".to_string());
                hardened.extend_from_slice(args);
                hardened
            }
        }
        "powershell.exe" | "powershell" | "pwsh.exe" | "pwsh" => {
            let mut hardened = Vec::with_capacity(args.len() + 3);
            let mut has_no_profile = false;
            let mut has_non_interactive = false;
            let mut has_no_logo = false;

            for arg in args {
                if arg.eq_ignore_ascii_case("-NoProfile") {
                    has_no_profile = true;
                } else if arg.eq_ignore_ascii_case("-NonInteractive") {
                    has_non_interactive = true;
                } else if arg.eq_ignore_ascii_case("-NoLogo") {
                    has_no_logo = true;
                }
            }

            if !has_no_profile {
                hardened.push("-NoProfile".to_string());
            }
            if !has_non_interactive {
                hardened.push("-NonInteractive".to_string());
            }
            if !has_no_logo {
                hardened.push("-NoLogo".to_string());
            }
            hardened.extend_from_slice(args);
            hardened
        }
        "cscript.exe" | "cscript" => {
            let mut hardened = Vec::with_capacity(args.len() + 2);
            let mut has_no_logo = false;
            let mut has_batch = false;

            for arg in args {
                if arg.eq_ignore_ascii_case("//NoLogo") {
                    has_no_logo = true;
                } else if arg.eq_ignore_ascii_case("//B") {
                    has_batch = true;
                }
            }

            if !has_no_logo {
                hardened.push("//NoLogo".to_string());
            }
            if !has_batch {
                hardened.push("//B".to_string());
            }
            hardened.extend_from_slice(args);
            hardened
        }
        "wscript.exe" | "wscript" => {
            if args.iter().any(|arg| arg.eq_ignore_ascii_case("//NoLogo")) {
                args.to_vec()
            } else {
                let mut hardened = Vec::with_capacity(args.len() + 1);
                hardened.push("//NoLogo".to_string());
                hardened.extend_from_slice(args);
                hardened
            }
        }
        _ => args.to_vec(),
    }
}

fn build_child_env(config: &ExecConfig<'_>) -> Vec<(String, String)> {
    let mut env_pairs = Vec::new();
    for (key, value) in std::env::vars() {
        if !should_skip_env_var(
            &key,
            &config.env_vars,
            &[
                "NONO_CAP_FILE",
                "PATH",
                "PATHEXT",
                "COMSPEC",
                "SystemRoot",
                "windir",
                "SystemDrive",
                "NoDefaultCurrentDirectoryInExePath",
                "TMP",
                "TEMP",
                "TMPDIR",
                "APPDATA",
                "LOCALAPPDATA",
                "HOME",
                "USERPROFILE",
                "HOMEDRIVE",
                "HOMEPATH",
                "XDG_CONFIG_HOME",
                "XDG_DATA_HOME",
                "PROGRAMDATA",
                "ALLUSERSPROFILE",
                "PUBLIC",
                "ProgramFiles",
                "ProgramFiles(x86)",
                "ProgramW6432",
                "CommonProgramFiles",
                "CommonProgramFiles(x86)",
                "CommonProgramW6432",
                "OneDrive",
                "OneDriveConsumer",
                "OneDriveCommercial",
                "INETCACHE",
                "INETCOOKIES",
                "INETHISTORY",
                "PSModulePath",
                "PSModuleAnalysisCachePath",
                "CARGO_HOME",
                "RUSTUP_HOME",
                "DOTNET_CLI_HOME",
                "NUGET_PACKAGES",
                "NUGET_HTTP_CACHE_PATH",
                "NUGET_PLUGINS_CACHE_PATH",
                "ChocolateyInstall",
                "ChocolateyToolsLocation",
                "VCPKG_ROOT",
                "NPM_CONFIG_CACHE",
                "YARN_CACHE_FOLDER",
                "PIP_CACHE_DIR",
                "PIP_BUILD_TRACKER",
                "PYTHONPYCACHEPREFIX",
                "PYTHONUSERBASE",
                "GOCACHE",
                "GOMODCACHE",
                "GOPATH",
                "HISTFILE",
                "LESSHISTFILE",
                "NODE_REPL_HISTORY",
                "PYTHONHISTFILE",
                "SQLITE_HISTORY",
                "IPYTHONDIR",
                "GRADLE_USER_HOME",
                "MAVEN_USER_HOME",
            ],
        ) {
            env_pairs.push((key, value));
        }
    }

    if let Some(cap_file) = config.cap_file {
        env_pairs.push((
            "NONO_CAP_FILE".to_string(),
            cap_file.to_string_lossy().into_owned(),
        ));
    }

    for (key, value) in &config.env_vars {
        env_pairs.push(((*key).to_string(), (*value).to_string()));
    }

    env_pairs
}

fn build_windows_environment_block(env_pairs: &[(String, String)]) -> Vec<u16> {
    let mut deduped = Vec::with_capacity(env_pairs.len());
    let mut seen_keys = HashSet::with_capacity(env_pairs.len());
    for (key, value) in env_pairs.iter().rev() {
        let folded = key.to_ascii_lowercase();
        if seen_keys.insert(folded) {
            deduped.push((key.clone(), value.clone()));
        }
    }
    deduped.reverse();

    let mut sorted = deduped;
    sorted.sort_by(|left, right| {
        left.0
            .to_ascii_lowercase()
            .cmp(&right.0.to_ascii_lowercase())
    });

    let mut block = Vec::new();
    for (key, value) in sorted {
        let pair = format!("{key}={value}");
        block.extend(OsStr::new(&pair).encode_wide());
        block.push(0);
    }
    block.push(0);
    block
}

fn quote_windows_arg(arg: &str) -> String {
    if !arg.contains([' ', '\t', '"']) && !arg.is_empty() {
        return arg.to_string();
    }

    let mut quoted = String::from("\"");
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.push_str(&"\\".repeat(backslashes));
                backslashes = 0;
                quoted.push(ch);
            }
        }
    }
    quoted.push_str(&"\\".repeat(backslashes * 2));
    quoted.push('"');
    quoted
}

fn build_command_line(resolved_program: &Path, args: &[String]) -> Vec<u16> {
    let mut command_line = quote_windows_arg(&resolved_program.to_string_lossy());
    for arg in args {
        command_line.push(' ');
        command_line.push_str(&quote_windows_arg(arg));
    }
    OsStr::new(&command_line)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn should_use_low_integrity_windows_launch(caps: &CapabilitySet) -> bool {
    let policy = Sandbox::windows_filesystem_policy(caps);
    policy.has_rules()
}

fn create_low_integrity_primary_token() -> Result<OwnedHandle> {
    let mut current_token = std::ptr::null_mut();
    let opened = unsafe {
        // SAFETY: We pass a valid mutable out-pointer and request access on the
        // current process token only.
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
            &mut current_token,
        )
    };
    if opened == 0 {
        return Err(NonoError::SandboxInit(format!(
            "Failed to open Windows process token for low-integrity launch (GetLastError={})",
            unsafe { GetLastError() }
        )));
    }
    let current_token = OwnedHandle(current_token);

    let mut primary_token = std::ptr::null_mut();
    let duplicated = unsafe {
        // SAFETY: We duplicate the current process token into a primary token
        // for child process creation.
        DuplicateTokenEx(
            current_token.raw(),
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
            std::ptr::null(),
            SecurityImpersonation as SECURITY_IMPERSONATION_LEVEL,
            TokenPrimary,
            &mut primary_token,
        )
    };
    if duplicated == 0 {
        return Err(NonoError::SandboxInit(format!(
            "Failed to duplicate Windows process token for low-integrity launch (GetLastError={})",
            unsafe { GetLastError() }
        )));
    }
    let primary_token = OwnedHandle(primary_token);

    let mut sid_buffer = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut sid_size = sid_buffer.len() as u32;
    let created = unsafe {
        // SAFETY: The destination buffer is valid and sized per
        // SECURITY_MAX_SID_SIZE for a well-known SID.
        CreateWellKnownSid(
            WinLowLabelSid,
            std::ptr::null_mut(),
            sid_buffer.as_mut_ptr() as *mut _,
            &mut sid_size,
        )
    };
    if created == 0 {
        return Err(NonoError::SandboxInit(format!(
            "Failed to create Windows low-integrity SID (GetLastError={})",
            unsafe { GetLastError() }
        )));
    }

    let mut label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: sid_buffer.as_mut_ptr() as *mut _,
            Attributes: SE_GROUP_INTEGRITY as u32,
        },
    };
    let label_size = size_of::<TOKEN_MANDATORY_LABEL>() + sid_size as usize;
    let adjusted = unsafe {
        // SAFETY: The token handle is valid and the TOKEN_MANDATORY_LABEL
        // points to a valid low-integrity SID buffer for the duration
        // of the call.
        SetTokenInformation(
            primary_token.raw(),
            TokenIntegrityLevel,
            &mut label as *mut _ as *mut _,
            label_size as u32,
        )
    };
    if adjusted == 0 {
        return Err(NonoError::SandboxInit(format!(
            "Failed to lower Windows child token integrity level (GetLastError={})",
            unsafe { GetLastError() }
        )));
    }

    Ok(primary_token)
}

fn execute_direct_with_low_integrity(
    config: &ExecConfig<'_>,
    containment: &ProcessContainment,
    cmd_args: &[String],
) -> Result<i32> {
    let env_pairs = build_child_env(config);
    let mut environment_block = build_windows_environment_block(&env_pairs);
    let token = create_low_integrity_primary_token()?;
    let application_name: Vec<u16> = config
        .resolved_program
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut command_line = build_command_line(config.resolved_program, cmd_args);
    let current_dir: Vec<u16> = config
        .current_dir
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let startup_info = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        ..unsafe {
            // SAFETY: STARTUPINFOW is a plain FFI struct; zero initialization
            // is valid before filling the documented fields.
            std::mem::zeroed()
        }
    };
    let mut process_info = PROCESS_INFORMATION {
        ..unsafe {
            // SAFETY: PROCESS_INFORMATION is a plain FFI struct populated by
            // CreateProcessAsUserW.
            std::mem::zeroed()
        }
    };

    let created = unsafe {
        // SAFETY: All pointers either refer to valid, nul-terminated UTF-16
        // buffers or are null as documented by CreateProcessAsUserW.
        CreateProcessAsUserW(
            token.raw(),
            application_name.as_ptr(),
            command_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_UNICODE_ENVIRONMENT,
            environment_block.as_mut_ptr() as *mut _,
            current_dir.as_ptr(),
            &startup_info,
            &mut process_info,
        )
    };
    if created == 0 {
        return Err(NonoError::SandboxInit(format!(
            "Failed to launch Windows low-integrity child process (GetLastError={})",
            unsafe { GetLastError() }
        )));
    }

    let process = OwnedHandle(process_info.hProcess);
    let thread = OwnedHandle(process_info.hThread);
    let _ = &thread;

    apply_process_handle_to_containment(containment, process.raw())?;
    unsafe {
        // SAFETY: The process handle is valid until drop.
        WaitForSingleObject(process.raw(), INFINITE);
    }
    let mut exit_code = 1u32;
    let got_code = unsafe {
        // SAFETY: The process handle is valid until drop.
        GetExitCodeProcess(process.raw(), &mut exit_code)
    };
    if got_code == 0 {
        return Err(NonoError::CommandExecution(std::io::Error::other(
            "Failed to read Windows child exit code",
        )));
    }

    Ok(exit_code as i32)
}

pub fn execute_direct(config: &ExecConfig<'_>) -> Result<i32> {
    let fs_policy = Sandbox::windows_filesystem_policy(config.caps);
    Sandbox::validate_windows_launch_paths(
        &fs_policy,
        config.resolved_program,
        config.current_dir,
    )?;
    Sandbox::validate_windows_command_args(
        &fs_policy,
        config.resolved_program,
        &config.command[1..],
        config.current_dir,
    )?;
    tracing::debug!(
        "Windows direct-execution filesystem policy compiler is available: {} compiled rule(s), {} unsupported rule(s)",
        fs_policy.rules.len(),
        fs_policy.unsupported.len()
    );

    let cmd_args = prepare_runtime_hardened_args(config.resolved_program, &config.command[1..]);
    let containment = create_process_containment()?;
    if should_use_low_integrity_windows_launch(config.caps) {
        return execute_direct_with_low_integrity(config, &containment, &cmd_args);
    }

    let mut cmd = Command::new(config.resolved_program);
    cmd.env_clear();
    cmd.current_dir(config.current_dir);
    for (key, value) in build_child_env(config) {
        cmd.env(key, value);
    }
    cmd.args(&cmd_args);
    let mut child = cmd.spawn().map_err(NonoError::CommandExecution)?;
    apply_process_containment(&containment, &child)?;
    let status = child.wait().map_err(NonoError::CommandExecution)?;
    Ok(status.code().unwrap_or(1))
}

pub fn execute_supervised(
    _config: &ExecConfig<'_>,
    supervisor: Option<&SupervisorConfig<'_>>,
    _trust_interceptor: Option<crate::trust_intercept::TrustInterceptor>,
) -> Result<i32> {
    if let Some(supervisor) = supervisor {
        let (parent_control, _child_control) = initialize_supervisor_control_channel()?;
        let requested = if supervisor.requested_features.is_empty() {
            "future supervisor features".to_string()
        } else {
            supervisor.requested_features.join(", ")
        };
        return Err(NonoError::UnsupportedPlatform(
            format!(
                "Windows preview initialized the supervisor control channel scaffold \
                 (session: {}, transport: {}), but the supervisor event loop is not implemented yet. \
                 Requested features: {}. This is a preview limitation, not permanent product behavior.",
                supervisor.session_id,
                parent_control.transport_name(),
                requested
            ),
        ));
    }

    Err(NonoError::UnsupportedPlatform(
        "Windows supervised execution is not implemented yet".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_process_containment_job() {
        let containment =
            create_process_containment().expect("Windows process containment should initialize");
        assert!(!containment.job.is_null(), "job handle should be valid");
    }

    #[test]
    fn test_initialize_supervisor_control_channel() {
        let (parent, child) = initialize_supervisor_control_channel()
            .expect("Windows control channel should initialize");
        assert!(
            parent.transport_name().starts_with("windows-supervisor-"),
            "parent transport should use the Windows supervisor channel naming scheme"
        );
        assert_eq!(parent.transport_name(), child.transport_name());
    }

    #[test]
    fn test_execute_supervised_reports_scaffold_state() {
        let command = vec![
            "cmd".to_string(),
            "/c".to_string(),
            "echo".to_string(),
            "test".to_string(),
        ];
        let resolved_program = PathBuf::from(r"C:\Windows\System32\cmd.exe");
        let cap_file = PathBuf::from("C:\\tmp\\nono-cap-state");
        let current_dir = std::env::current_dir().expect("cwd");
        let config = ExecConfig {
            command: &command,
            resolved_program: &resolved_program,
            caps: &CapabilitySet::new(),
            env_vars: Vec::new(),
            cap_file: Some(&cap_file),
            current_dir: &current_dir,
        };
        let supervisor = SupervisorConfig {
            session_id: "test-session",
            requested_features: vec!["rollback"],
        };

        let err = execute_supervised(&config, Some(&supervisor), None)
            .expect_err("supervised preview should stop after initializing the channel");
        let message = err.to_string();
        assert!(message.contains("control channel scaffold"));
        assert!(message.contains("transport:"));
        assert!(message.contains("event loop is not implemented yet"));
    }

    #[test]
    fn test_execute_direct_runs_inside_containment_job() {
        let command = vec![
            "cmd".to_string(),
            "/c".to_string(),
            "exit".to_string(),
            "0".to_string(),
        ];
        let resolved_program = PathBuf::from(r"C:\Windows\System32\cmd.exe");
        let cap_file = PathBuf::from("C:\\tmp\\nono-cap-state");
        let current_dir = std::env::current_dir().expect("cwd");
        let config = ExecConfig {
            command: &command,
            resolved_program: &resolved_program,
            caps: &CapabilitySet::new(),
            env_vars: Vec::new(),
            cap_file: Some(&cap_file),
            current_dir: &current_dir,
        };

        let exit_code = execute_direct(&config).expect("direct execution should succeed");
        assert_eq!(exit_code, 0);
    }

    #[test]
    fn test_execute_direct_rejects_program_outside_windows_policy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let current_dir = dir.path().join("workspace");
        std::fs::create_dir_all(&current_dir).expect("mkdir");
        let mut caps = CapabilitySet::new();
        caps.add_fs(
            nono::FsCapability::new_dir(&current_dir, nono::AccessMode::ReadWrite)
                .expect("dir cap"),
        );
        let command = vec![
            "cmd".to_string(),
            "/c".to_string(),
            "echo".to_string(),
            "test".to_string(),
        ];
        let resolved_program = PathBuf::from(r"C:\Windows\System32\cmd.exe");
        let cap_file = PathBuf::from("C:\\tmp\\nono-cap-state");
        let config = ExecConfig {
            command: &command,
            resolved_program: &resolved_program,
            caps: &caps,
            env_vars: Vec::new(),
            cap_file: Some(&cap_file),
            current_dir: &current_dir,
        };

        let err = execute_direct(&config)
            .expect_err("launch should fail when executable is outside filesystem policy");
        assert!(err.to_string().contains("executable path"));
    }

    #[test]
    fn test_execute_direct_rejects_absolute_path_argument_outside_windows_policy() {
        let allowed = tempfile::tempdir().expect("allowed");
        let outside = tempfile::tempdir().expect("outside");
        let outside_file = outside.path().join("outside.txt");
        std::fs::write(&outside_file, "hello").expect("write file");

        let mut caps = CapabilitySet::new();
        caps.add_fs(
            nono::FsCapability::new_dir(allowed.path(), nono::AccessMode::ReadWrite)
                .expect("dir cap"),
        );
        let command = vec![
            "more.com".to_string(),
            outside_file.to_string_lossy().into_owned(),
        ];
        let resolved_program = PathBuf::from(r"C:\Windows\System32\more.com");
        let cap_file = PathBuf::from("C:\\tmp\\nono-cap-state");
        let config = ExecConfig {
            command: &command,
            resolved_program: &resolved_program,
            caps: &caps,
            env_vars: Vec::new(),
            cap_file: Some(&cap_file),
            current_dir: allowed.path(),
        };

        let err = execute_direct(&config)
            .expect_err("launch should fail when absolute path arg is outside filesystem policy");
        assert!(
            err.to_string().contains("Windows filesystem policy")
                || err.to_string().contains("Platform not supported"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_prepare_runtime_hardened_args_injects_cmd_disable_autorun() {
        let args = vec!["/c".to_string(), "echo".to_string(), "hello".to_string()];
        let hardened =
            prepare_runtime_hardened_args(Path::new("C:\\Windows\\System32\\cmd.exe"), &args);

        assert_eq!(hardened[0], "/d");
        assert_eq!(&hardened[1..], args.as_slice());
    }

    #[test]
    fn test_prepare_runtime_hardened_args_injects_powershell_safety_flags() {
        let args = vec!["-Command".to_string(), "Get-Content inside.txt".to_string()];
        let hardened = prepare_runtime_hardened_args(
            Path::new("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            &args,
        );

        assert!(hardened.contains(&"-NoProfile".to_string()));
        assert!(hardened.contains(&"-NonInteractive".to_string()));
        assert!(hardened.contains(&"-NoLogo".to_string()));
        assert!(hardened.ends_with(&args));
    }

    #[test]
    fn test_prepare_runtime_hardened_args_injects_cscript_safety_flags() {
        let args = vec!["copy.vbs".to_string(), "source.txt".to_string()];
        let hardened =
            prepare_runtime_hardened_args(Path::new("C:\\Windows\\System32\\cscript.exe"), &args);

        assert!(hardened.contains(&"//NoLogo".to_string()));
        assert!(hardened.contains(&"//B".to_string()));
        assert!(hardened.ends_with(&args));
    }

    #[test]
    fn test_should_use_low_integrity_windows_launch_detects_restricted_caps() {
        let dir = tempfile::tempdir().expect("tempdir");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), nono::AccessMode::Read)
            .expect("allow path");

        assert!(should_use_low_integrity_windows_launch(&caps));
    }
}
