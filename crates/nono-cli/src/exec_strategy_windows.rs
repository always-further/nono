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
use std::time::{SystemTime, UNIX_EPOCH};
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

#[derive(Debug)]
struct NetworkEnforcementGuard {
    staged_program: PathBuf,
    staged_dir: PathBuf,
    inbound_rule: String,
    outbound_rule: String,
}

trait WindowsNetworkBackend {
    fn label(&self) -> &'static str;

    fn install(
        &self,
        policy: &nono::WindowsNetworkPolicy,
        config: &ExecConfig<'_>,
    ) -> Result<Option<NetworkEnforcementGuard>>;
}

struct FirewallRulesNetworkBackend;
struct WfpNetworkBackend;

const WINDOWS_WFP_PLATFORM_SERVICE: &str = "BFE";
const WINDOWS_WFP_BACKEND_SERVICE: &str = "nono-wfp-service";
const WINDOWS_WFP_BACKEND_DRIVER: &str = "nono-wfp-driver";
const WINDOWS_WFP_BACKEND_BINARY: &str = "nono-wfp-service.exe";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsServiceState {
    Running,
    Stopped,
    Missing,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WfpProbeStatus {
    Ready,
    BackendBinaryMissing,
    PlatformServiceMissing,
    PlatformServiceStopped,
    BackendServiceMissing,
    BackendServiceStopped,
    BackendDriverMissing,
    BackendDriverStopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WfpProbeConfig {
    platform_service: &'static str,
    backend_service: &'static str,
    backend_driver: &'static str,
    backend_binary_path: PathBuf,
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

impl Drop for NetworkEnforcementGuard {
    fn drop(&mut self) {
        let _ = delete_firewall_rule(&self.inbound_rule);
        let _ = delete_firewall_rule(&self.outbound_rule);
        cleanup_network_enforcement_staging(&self.staged_dir);
    }
}

fn run_netsh_firewall(args: &[&str]) -> Result<String> {
    let output = Command::new("netsh")
        .args(args)
        .output()
        .map_err(NonoError::CommandExecution)?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if output.status.success() {
        Ok(stdout)
    } else {
        Err(classify_netsh_firewall_failure(
            args,
            &format!("{stdout}{stderr}"),
        ))
    }
}

fn classify_netsh_firewall_failure(args: &[&str], output: &str) -> NonoError {
    let detail = if output.contains("requires elevation") || output.contains("Access is denied") {
        "Windows blocked-network enforcement currently uses temporary Windows Firewall rules and requires an elevated administrator session on this machine. The long-term Windows backend target is WFP.".to_string()
    } else if output.trim().is_empty() {
        "Windows Firewall did not return diagnostic output. The current blocked-network backend uses temporary Windows Firewall rules; the long-term backend target is WFP.".to_string()
    } else {
        format!(
            "{} (current backend: Windows Firewall rules; preferred backend: WFP)",
            output.trim()
        )
    };
    NonoError::SandboxInit(format!(
        "Failed to apply Windows blocked-network rule (args: {}): {}",
        args.join(" "),
        detail
    ))
}

fn delete_firewall_rule(name: &str) -> Result<()> {
    let rule_name = format!("name={name}");
    let _ = run_netsh_firewall(&["advfirewall", "firewall", "delete", "rule", &rule_name]);
    Ok(())
}

fn unique_windows_firewall_rule_suffix() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    )
}

fn stage_program_for_blocked_network_launch(program: &Path) -> Result<(PathBuf, PathBuf)> {
    let file_name = program.file_name().ok_or_else(|| {
        NonoError::SandboxInit(format!(
            "Failed to stage Windows blocked-network executable copy for {}",
            program.display()
        ))
    })?;
    let staged_dir = std::env::temp_dir()
        .join("nono-net-block")
        .join(unique_windows_firewall_rule_suffix());
    std::fs::create_dir_all(&staged_dir).map_err(|e| {
        NonoError::SandboxInit(format!(
            "Failed to prepare Windows blocked-network staging directory {}: {}",
            staged_dir.display(),
            e
        ))
    })?;
    let staged_program = staged_dir.join(file_name);
    std::fs::copy(program, &staged_program).map_err(|e| {
        NonoError::SandboxInit(format!(
            "Failed to stage Windows blocked-network executable copy {} -> {}: {}",
            program.display(),
            staged_program.display(),
            e
        ))
    })?;
    Ok((staged_program, staged_dir))
}

fn cleanup_network_enforcement_staging(staged_dir: &Path) {
    let _ = std::fs::remove_dir_all(staged_dir);
}

fn current_wfp_probe_config() -> Result<WfpProbeConfig> {
    let current_exe = std::env::current_exe().map_err(|e| {
        NonoError::SandboxInit(format!(
            "Failed to resolve current executable for Windows WFP backend probing: {e}"
        ))
    })?;
    let exe_dir = current_exe.parent().ok_or_else(|| {
        NonoError::SandboxInit(format!(
            "Failed to resolve executable directory for Windows WFP backend probing: {}",
            current_exe.display()
        ))
    })?;

    Ok(WfpProbeConfig {
        platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
        backend_service: WINDOWS_WFP_BACKEND_SERVICE,
        backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
        backend_binary_path: exe_dir.join(WINDOWS_WFP_BACKEND_BINARY),
    })
}

fn run_sc_query(service: &str) -> Result<String> {
    let output = Command::new("sc")
        .args(["query", service])
        .output()
        .map_err(NonoError::CommandExecution)?;
    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn parse_windows_service_state(output: &str) -> WindowsServiceState {
    let normalized = output.to_ascii_uppercase();
    if normalized.contains("FAILED 1060") || normalized.contains("DOES NOT EXIST") {
        WindowsServiceState::Missing
    } else if normalized.contains("STATE") && normalized.contains("RUNNING") {
        WindowsServiceState::Running
    } else if normalized.contains("STATE")
        && (normalized.contains("STOPPED") || normalized.contains("STOP_PENDING"))
    {
        WindowsServiceState::Stopped
    } else {
        WindowsServiceState::Unknown
    }
}

fn build_wfp_probe_status(
    backend_binary_exists: bool,
    platform_service: WindowsServiceState,
    backend_service: WindowsServiceState,
    backend_driver: WindowsServiceState,
) -> WfpProbeStatus {
    if !backend_binary_exists {
        return WfpProbeStatus::BackendBinaryMissing;
    }

    match platform_service {
        WindowsServiceState::Missing | WindowsServiceState::Unknown => {
            return WfpProbeStatus::PlatformServiceMissing;
        }
        WindowsServiceState::Stopped => return WfpProbeStatus::PlatformServiceStopped,
        WindowsServiceState::Running => {}
    }

    match backend_service {
        WindowsServiceState::Missing | WindowsServiceState::Unknown => {
            return WfpProbeStatus::BackendServiceMissing;
        }
        WindowsServiceState::Stopped => return WfpProbeStatus::BackendServiceStopped,
        WindowsServiceState::Running => {}
    }

    match backend_driver {
        WindowsServiceState::Missing | WindowsServiceState::Unknown => {
            return WfpProbeStatus::BackendDriverMissing;
        }
        WindowsServiceState::Stopped => return WfpProbeStatus::BackendDriverStopped,
        WindowsServiceState::Running => {}
    }

    WfpProbeStatus::Ready
}

fn probe_wfp_backend_status_with_config(config: &WfpProbeConfig) -> Result<WfpProbeStatus> {
    if !config.backend_binary_path.exists() {
        return Ok(WfpProbeStatus::BackendBinaryMissing);
    }

    let platform_output = run_sc_query(config.platform_service)?;
    let platform_state = parse_windows_service_state(&platform_output);
    let backend_service_state = parse_windows_service_state(&run_sc_query(config.backend_service)?);
    let backend_driver_state = parse_windows_service_state(&run_sc_query(config.backend_driver)?);

    Ok(build_wfp_probe_status(
        true,
        platform_state,
        backend_service_state,
        backend_driver_state,
    ))
}

fn probe_wfp_backend_status() -> Result<WfpProbeStatus> {
    let config = current_wfp_probe_config()?;
    probe_wfp_backend_status_with_config(&config)
}

fn describe_wfp_probe_failure(
    policy: &nono::WindowsNetworkPolicy,
    status: WfpProbeStatus,
) -> String {
    match status {
        WfpProbeStatus::Ready => format!(
            "Windows WFP backend probing reported ready, but the enforcement installer is not implemented yet ({}).",
            policy.backend_summary()
        ),
        WfpProbeStatus::BackendBinaryMissing => format!(
            "Windows network enforcement is targeting the WFP backend, but its expected binary is missing from this build output ({}).",
            policy.backend_summary()
        ),
        WfpProbeStatus::PlatformServiceMissing => format!(
            "Windows WFP prerequisites are unavailable because the Base Filtering Engine service is missing or could not be queried ({}).",
            policy.backend_summary()
        ),
        WfpProbeStatus::PlatformServiceStopped => format!(
            "Windows WFP prerequisites are unavailable because the Base Filtering Engine service is not running ({}).",
            policy.backend_summary()
        ),
        WfpProbeStatus::BackendServiceMissing => format!(
            "Windows WFP backend is not installed: its service is missing ({}).",
            policy.backend_summary()
        ),
        WfpProbeStatus::BackendServiceStopped => format!(
            "Windows WFP backend is installed but its service is not running ({}).",
            policy.backend_summary()
        ),
        WfpProbeStatus::BackendDriverMissing => format!(
            "Windows WFP backend is installed incompletely: its driver is missing ({}).",
            policy.backend_summary()
        ),
        WfpProbeStatus::BackendDriverStopped => format!(
            "Windows WFP backend is installed but its driver is not running ({}).",
            policy.backend_summary()
        ),
    }
}

fn select_network_backend(
    policy: &nono::WindowsNetworkPolicy,
) -> Result<Option<Box<dyn WindowsNetworkBackend>>> {
    match (&policy.mode, policy.active_backend) {
        (nono::WindowsNetworkPolicyMode::AllowAll, nono::WindowsNetworkBackendKind::None) => {
            Ok(None)
        }
        (
            nono::WindowsNetworkPolicyMode::Blocked,
            nono::WindowsNetworkBackendKind::FirewallRules,
        ) => Ok(Some(Box::new(FirewallRulesNetworkBackend))),
        (nono::WindowsNetworkPolicyMode::Blocked, nono::WindowsNetworkBackendKind::None)
            if policy.preferred_backend == nono::WindowsNetworkBackendKind::Wfp =>
        {
            Ok(Some(Box::new(WfpNetworkBackend)))
        }
        (nono::WindowsNetworkPolicyMode::ProxyOnly { .. }, _)
            if policy.preferred_backend == nono::WindowsNetworkBackendKind::Wfp =>
        {
            Ok(Some(Box::new(WfpNetworkBackend)))
        }
        (_, active_backend) => Err(NonoError::UnsupportedPlatform(format!(
            "Windows network enforcement does not have an applicable active backend for this policy ({}, active backend: {}).",
            policy.backend_summary(),
            active_backend.label()
        ))),
    }
}

impl WindowsNetworkBackend for FirewallRulesNetworkBackend {
    fn label(&self) -> &'static str {
        "windows-firewall-rules"
    }

    fn install(
        &self,
        policy: &nono::WindowsNetworkPolicy,
        config: &ExecConfig<'_>,
    ) -> Result<Option<NetworkEnforcementGuard>> {
        match Sandbox::windows_network_launch_support(policy, config.resolved_program) {
            nono::WindowsNetworkLaunchSupport::Supported => {}
            nono::WindowsNetworkLaunchSupport::UnsupportedShellHost => {
                return Err(NonoError::UnsupportedPlatform(format!(
                    "Windows blocked-network enforcement currently supports standalone executable launches, not shell or interpreter hosts such as {}. \
Use a direct executable target for the current backend subset. \
This limitation comes from the current Windows Firewall-rule backend; the long-term backend target is WFP. \
This is a current Windows backend limitation, not permanent product behavior.",
                    config.resolved_program.display(),
                )));
            }
        }

        let (staged_program, staged_dir) =
            stage_program_for_blocked_network_launch(config.resolved_program)?;
        let suffix = unique_windows_firewall_rule_suffix();
        let inbound_rule = format!("nono-win-block-in-{suffix}");
        let outbound_rule = format!("nono-win-block-out-{suffix}");
        let program_arg = format!("program={}", staged_program.display());

        if let Err(err) = run_netsh_firewall(&[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={outbound_rule}"),
            "dir=out",
            "action=block",
            &program_arg,
            "enable=yes",
            "profile=any",
        ]) {
            cleanup_network_enforcement_staging(&staged_dir);
            return Err(err);
        }

        if let Err(err) = run_netsh_firewall(&[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={inbound_rule}"),
            "dir=in",
            "action=block",
            &program_arg,
            "enable=yes",
            "profile=any",
        ]) {
            let _ = delete_firewall_rule(&outbound_rule);
            cleanup_network_enforcement_staging(&staged_dir);
            return Err(err);
        }

        Ok(Some(NetworkEnforcementGuard {
            staged_program,
            staged_dir,
            inbound_rule,
            outbound_rule,
        }))
    }
}

impl WindowsNetworkBackend for WfpNetworkBackend {
    fn label(&self) -> &'static str {
        "windows-filtering-platform"
    }

    fn install(
        &self,
        policy: &nono::WindowsNetworkPolicy,
        _config: &ExecConfig<'_>,
    ) -> Result<Option<NetworkEnforcementGuard>> {
        match &policy.mode {
            nono::WindowsNetworkPolicyMode::AllowAll => Ok(None),
            nono::WindowsNetworkPolicyMode::Blocked
            | nono::WindowsNetworkPolicyMode::ProxyOnly { .. } => {
                let status = probe_wfp_backend_status().map_err(|err| {
                    NonoError::SandboxInit(format!(
                        "Failed to probe Windows WFP backend status ({}): {}",
                        policy.backend_summary(),
                        err
                    ))
                })?;
                Err(NonoError::UnsupportedPlatform(format!(
                    "{} This request remains fail-closed until WFP is available.",
                    describe_wfp_probe_failure(policy, status)
                )))
            }
        }
    }
}

fn prepare_network_enforcement(config: &ExecConfig<'_>) -> Result<Option<NetworkEnforcementGuard>> {
    let policy = Sandbox::windows_network_policy(config.caps);
    if !policy.is_fully_supported() {
        return Err(NonoError::UnsupportedPlatform(format!(
            "Windows network enforcement does not support this capability set yet ({}, {}).",
            policy.unsupported_messages().join(", "),
            policy.backend_summary()
        )));
    }

    let Some(backend) = select_network_backend(&policy)? else {
        return Ok(None);
    };

    tracing::debug!(
        "Windows network enforcement selecting backend {} ({})",
        backend.label(),
        policy.backend_summary()
    );

    backend.install(&policy, config)
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

fn collect_unsupported_supervised_features(supervisor: &SupervisorConfig<'_>) -> Vec<String> {
    supervisor
        .requested_features
        .iter()
        .filter(|feature| **feature != "rollback snapshots")
        .map(|feature| (*feature).to_string())
        .collect()
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
                "XDG_CACHE_HOME",
                "XDG_DATA_HOME",
                "XDG_STATE_HOME",
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
                "NPM_CONFIG_USERCONFIG",
                "YARN_CACHE_FOLDER",
                "PIP_CACHE_DIR",
                "PIP_CONFIG_FILE",
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
                "GEM_HOME",
                "GEM_PATH",
                "BUNDLE_USER_HOME",
                "BUNDLE_USER_CACHE",
                "BUNDLE_USER_CONFIG",
                "BUNDLE_APP_CONFIG",
                "COMPOSER_HOME",
                "COMPOSER_CACHE_DIR",
                "GRADLE_USER_HOME",
                "MAVEN_USER_HOME",
                "RIPGREP_CONFIG_PATH",
                "AWS_SHARED_CREDENTIALS_FILE",
                "AWS_CONFIG_FILE",
                "AZURE_CONFIG_DIR",
                "KUBECONFIG",
                "DOCKER_CONFIG",
                "CLOUDSDK_CONFIG",
                "GIT_CONFIG_GLOBAL",
                "GNUPGHOME",
                "TF_CLI_CONFIG_FILE",
                "TF_DATA_DIR",
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
    launch_program: &Path,
    containment: &ProcessContainment,
    cmd_args: &[String],
) -> Result<i32> {
    let env_pairs = build_child_env(config);
    let mut environment_block = build_windows_environment_block(&env_pairs);
    let token = create_low_integrity_primary_token()?;
    let application_name: Vec<u16> = launch_program
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut command_line = build_command_line(launch_program, cmd_args);
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

fn execute_supervised_with_low_integrity(
    config: &ExecConfig<'_>,
    launch_program: &Path,
    containment: &ProcessContainment,
) -> Result<i32> {
    let cmd_args = prepare_runtime_hardened_args(launch_program, &config.command[1..]);
    execute_direct_with_low_integrity(config, launch_program, containment, &cmd_args)
}

fn execute_supervised_with_standard_token(
    config: &ExecConfig<'_>,
    launch_program: &Path,
    containment: &ProcessContainment,
) -> Result<i32> {
    let cmd_args = prepare_runtime_hardened_args(launch_program, &config.command[1..]);
    let mut cmd = Command::new(launch_program);
    cmd.env_clear();
    cmd.current_dir(config.current_dir);
    for (key, value) in build_child_env(config) {
        cmd.env(key, value);
    }
    cmd.args(&cmd_args);
    let mut child = cmd.spawn().map_err(NonoError::CommandExecution)?;
    apply_process_containment(containment, &child)?;
    let status = child.wait().map_err(NonoError::CommandExecution)?;
    Ok(status.code().unwrap_or(1))
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
    let network_enforcement = prepare_network_enforcement(config)?;
    let launch_program = network_enforcement
        .as_ref()
        .map(|guard| guard.staged_program.as_path())
        .unwrap_or(config.resolved_program);

    let cmd_args = prepare_runtime_hardened_args(launch_program, &config.command[1..]);
    let containment = create_process_containment()?;
    if should_use_low_integrity_windows_launch(config.caps) {
        return execute_direct_with_low_integrity(config, launch_program, &containment, &cmd_args);
    }

    let mut cmd = Command::new(launch_program);
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
    config: &ExecConfig<'_>,
    supervisor: Option<&SupervisorConfig<'_>>,
    _trust_interceptor: Option<crate::trust_intercept::TrustInterceptor>,
) -> Result<i32> {
    let Some(supervisor) = supervisor else {
        return Err(NonoError::UnsupportedPlatform(
            "Windows supervised execution requires supervisor configuration".to_string(),
        ));
    };

    let (parent_control, _child_control) = initialize_supervisor_control_channel()?;
    let unsupported = collect_unsupported_supervised_features(supervisor);
    if !unsupported.is_empty() {
        return Err(NonoError::UnsupportedPlatform(format!(
            "Windows supervised execution initialized the control channel \
             (session: {}, transport: {}), but these supervised features are not implemented yet: {}. \
             Supported Windows supervised features currently: rollback snapshots. \
             This is a preview limitation, not permanent product behavior.",
            supervisor.session_id,
            parent_control.transport_name(),
            unsupported.join(", ")
        )));
    }

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
    let network_enforcement = prepare_network_enforcement(config)?;
    let launch_program = network_enforcement
        .as_ref()
        .map(|guard| guard.staged_program.as_path())
        .unwrap_or(config.resolved_program);

    let containment = create_process_containment()?;
    tracing::debug!(
        "Windows supervised execution starting event loop (session: {}, transport: {}, features: {})",
        supervisor.session_id,
        parent_control.transport_name(),
        if supervisor.requested_features.is_empty() {
            "none".to_string()
        } else {
            supervisor.requested_features.join(", ")
        }
    );

    let exit_code = if should_use_low_integrity_windows_launch(config.caps) {
        execute_supervised_with_low_integrity(config, launch_program, &containment)?
    } else {
        execute_supervised_with_standard_token(config, launch_program, &containment)?
    };

    tracing::debug!(
        "Windows supervised execution finished cleanly (session: {}, transport: {}, exit_code: {})",
        supervisor.session_id,
        parent_control.transport_name(),
        exit_code
    );
    Ok(exit_code)
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
    fn test_execute_supervised_rejects_unsupported_features() {
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
            .expect_err("unsupported supervised features should fail clearly");
        let message = err.to_string();
        assert!(message.contains("initialized the control channel"));
        assert!(message.contains("transport:"));
        assert!(message.contains("rollback snapshots"));
        assert!(message.contains("not implemented yet"));
    }

    #[test]
    fn test_execute_supervised_runs_supported_rollback_lifecycle() {
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
        let supervisor = SupervisorConfig {
            session_id: "rollback-session",
            requested_features: vec!["rollback snapshots"],
        };

        let exit_code =
            execute_supervised(&config, Some(&supervisor), None).expect("rollback should run");
        assert_eq!(exit_code, 0);
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

    #[test]
    fn test_classify_netsh_firewall_failure_reports_elevation_actionably() {
        let err = classify_netsh_firewall_failure(
            &["advfirewall", "firewall", "add", "rule"],
            "The requested operation requires elevation (Run as administrator).\r\n",
        );

        let message = err.to_string();
        assert!(message.contains("requires an elevated administrator session"));
        assert!(message.contains("long-term Windows backend target is WFP"));
    }

    #[test]
    fn test_classify_netsh_firewall_failure_preserves_generic_output() {
        let err = classify_netsh_firewall_failure(
            &["advfirewall", "firewall", "add", "rule"],
            "Some other firewall failure",
        );

        let message = err.to_string();
        assert!(message.contains("Some other firewall failure"));
        assert!(message.contains("current backend: Windows Firewall rules"));
        assert!(message.contains("preferred backend: WFP"));
    }

    #[test]
    fn test_cleanup_network_enforcement_staging_removes_staged_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let staged_dir = dir.path().join("staged");
        std::fs::create_dir_all(&staged_dir).expect("mkdir");
        std::fs::write(staged_dir.join("probe.exe"), b"probe").expect("write");

        cleanup_network_enforcement_staging(&staged_dir);

        assert!(!staged_dir.exists(), "staged directory should be removed");
    }

    #[test]
    fn test_prepare_network_enforcement_rejects_blocked_backend_without_active_backend() {
        let dir = tempfile::tempdir().expect("tempdir");
        let current_dir = dir.path().join("workspace");
        std::fs::create_dir_all(&current_dir).expect("mkdir");
        let mut caps = CapabilitySet::new().set_network_mode(nono::NetworkMode::Blocked);
        caps.add_tcp_connect_port(443);
        let command = vec![r"C:\tools\probe.exe".to_string()];
        let resolved_program = PathBuf::from(r"C:\tools\probe.exe");
        let config = ExecConfig {
            command: &command,
            resolved_program: &resolved_program,
            caps: &caps,
            env_vars: Vec::new(),
            cap_file: None,
            current_dir: &current_dir,
        };

        let err = prepare_network_enforcement(&config)
            .expect_err("unsupported blocked-network shape should fail clearly");
        let message = err.to_string();
        assert!(message.contains("does not support this capability set yet"));
        assert!(message.contains("preferred backend: windows-filtering-platform"));
    }

    #[test]
    fn test_select_network_backend_returns_none_for_allow_all() {
        let policy = Sandbox::windows_network_policy(&CapabilitySet::new());
        let backend = select_network_backend(&policy).expect("allow-all selection");
        assert!(backend.is_none(), "allow-all should not install a backend");
    }

    #[test]
    fn test_select_network_backend_rejects_proxy_only_without_active_backend() {
        let policy = Sandbox::windows_network_policy(&CapabilitySet::new().set_network_mode(
            nono::NetworkMode::ProxyOnly {
                port: 8080,
                bind_ports: vec![8080],
            },
        ));

        let backend = select_network_backend(&policy)
            .expect("proxy-only should select the WFP scaffold backend")
            .expect("proxy-only should use a backend scaffold");
        assert_eq!(backend.label(), "windows-filtering-platform");
    }

    #[test]
    fn test_select_network_backend_routes_blocked_without_active_backend_to_wfp_scaffold() {
        let mut caps = CapabilitySet::new().set_network_mode(nono::NetworkMode::Blocked);
        caps.add_tcp_connect_port(443);
        let policy = Sandbox::windows_network_policy(&caps);

        let backend = select_network_backend(&policy)
            .expect("blocked policy should select a backend scaffold")
            .expect("blocked policy should use a backend scaffold");
        assert_eq!(backend.label(), "windows-filtering-platform");
    }

    #[test]
    fn test_parse_windows_service_state_detects_running() {
        let output = "STATE              : 4  RUNNING";
        assert_eq!(
            parse_windows_service_state(output),
            WindowsServiceState::Running
        );
    }

    #[test]
    fn test_parse_windows_service_state_detects_stopped() {
        let output = "STATE              : 1  STOPPED";
        assert_eq!(
            parse_windows_service_state(output),
            WindowsServiceState::Stopped
        );
    }

    #[test]
    fn test_parse_windows_service_state_detects_missing() {
        let output = "[SC] OpenService FAILED 1060:\nThe specified service does not exist as an installed service.";
        assert_eq!(
            parse_windows_service_state(output),
            WindowsServiceState::Missing
        );
    }

    #[test]
    fn test_build_wfp_probe_status_reports_missing_binary() {
        let status = build_wfp_probe_status(
            false,
            WindowsServiceState::Running,
            WindowsServiceState::Running,
            WindowsServiceState::Running,
        );
        assert_eq!(status, WfpProbeStatus::BackendBinaryMissing);
    }

    #[test]
    fn test_build_wfp_probe_status_reports_missing_service() {
        let status = build_wfp_probe_status(
            true,
            WindowsServiceState::Running,
            WindowsServiceState::Missing,
            WindowsServiceState::Running,
        );
        assert_eq!(status, WfpProbeStatus::BackendServiceMissing);
    }

    #[test]
    fn test_describe_wfp_probe_failure_reports_platform_service_stopped() {
        let policy = Sandbox::windows_network_policy(&CapabilitySet::new().set_network_mode(
            nono::NetworkMode::ProxyOnly {
                port: 8080,
                bind_ports: vec![8080],
            },
        ));
        let message = describe_wfp_probe_failure(&policy, WfpProbeStatus::PlatformServiceStopped);
        assert!(message.contains("Base Filtering Engine service is not running"));
        assert!(message.contains("preferred backend: windows-filtering-platform"));
    }

    #[test]
    fn test_describe_wfp_probe_failure_reports_missing_binary() {
        let policy = Sandbox::windows_network_policy(
            &CapabilitySet::new().set_network_mode(nono::NetworkMode::Blocked),
        );
        let message = describe_wfp_probe_failure(&policy, WfpProbeStatus::BackendBinaryMissing);
        assert!(message.contains("expected binary is missing from this build output"));
        assert!(message.contains("preferred backend: windows-filtering-platform"));
    }

    #[test]
    fn test_probe_wfp_backend_status_with_config_reports_missing_binary_before_service_checks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: dir.path().join("missing-wfp-service.exe"),
        };

        let status =
            probe_wfp_backend_status_with_config(&config).expect("probe status should resolve");
        assert_eq!(status, WfpProbeStatus::BackendBinaryMissing);
    }

    #[test]
    fn test_wfp_backend_reports_blocked_backend_unavailable() {
        let backend = WfpNetworkBackend;
        let mut caps = CapabilitySet::new().set_network_mode(nono::NetworkMode::Blocked);
        caps.add_tcp_connect_port(443);
        let policy = Sandbox::windows_network_policy(&caps);
        let dir = tempfile::tempdir().expect("tempdir");
        let command = vec![r"C:\tools\probe.exe".to_string()];
        let resolved_program = PathBuf::from(r"C:\tools\probe.exe");
        let config = ExecConfig {
            command: &command,
            resolved_program: &resolved_program,
            caps: &caps,
            env_vars: Vec::new(),
            cap_file: None,
            current_dir: dir.path(),
        };

        let err = backend
            .install(&policy, &config)
            .expect_err("WFP scaffold should fail closed for blocked mode");
        let message = err.to_string();
        assert!(message.contains("expected binary is missing from this build output"));
        assert!(message.contains("preferred backend: windows-filtering-platform"));
        assert!(message.contains("fail-closed"));
    }

    #[test]
    fn test_wfp_backend_reports_proxy_backend_unavailable() {
        let backend = WfpNetworkBackend;
        let caps = CapabilitySet::new().set_network_mode(nono::NetworkMode::ProxyOnly {
            port: 8080,
            bind_ports: vec![8080],
        });
        let policy = Sandbox::windows_network_policy(&caps);
        let dir = tempfile::tempdir().expect("tempdir");
        let command = vec![r"C:\tools\probe.exe".to_string()];
        let resolved_program = PathBuf::from(r"C:\tools\probe.exe");
        let config = ExecConfig {
            command: &command,
            resolved_program: &resolved_program,
            caps: &caps,
            env_vars: Vec::new(),
            cap_file: None,
            current_dir: dir.path(),
        };

        let err = backend
            .install(&policy, &config)
            .expect_err("WFP scaffold should fail closed for proxy mode");
        let message = err.to_string();
        assert!(message.contains("expected binary is missing from this build output"));
        assert!(message.contains("fail-closed"));
    }
}
