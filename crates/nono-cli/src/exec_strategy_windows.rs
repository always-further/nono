//! Windows execution strategy placeholder.
//!
//! WIN-101 needs the CLI to compile on Windows without pulling in the Unix
//! supervisor and fork/exec machinery. This file intentionally provides a
//! smaller Windows surface that can be expanded in later stories.

#[path = "exec_strategy/env_sanitization.rs"]
mod env_sanitization;

use crate::windows_wfp_contract::{
    WfpRuntimeActivationRequest, WfpRuntimeActivationResponse, WFP_RUNTIME_PROTOCOL_VERSION,
};
use nono::supervisor::AuditEntry;
use nono::{ApprovalBackend, CapabilitySet, NonoError, Result, Sandbox};
use rand::RngExt;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::io::Write;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
#[cfg(debug_assertions)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(test)]
use std::time::SystemTime;
use std::time::{Duration, Instant};
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
    CreateProcessAsUserW, CreateProcessW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken,
    ResumeThread, TerminateProcess, WaitForSingleObject, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
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
    pub support: nono::WindowsSupervisorSupport,
    pub approval_backend: &'a dyn ApprovalBackend,
}

pub struct WindowsSupervisorDenyAllApprovalBackend;

impl ApprovalBackend for WindowsSupervisorDenyAllApprovalBackend {
    fn request_capability(
        &self,
        request: &nono::CapabilityRequest,
    ) -> Result<nono::ApprovalDecision> {
        Ok(nono::ApprovalDecision::Denied {
            reason: format!(
                "Windows live runtime capability expansion is not attached to generic child processes yet for request {}",
                request.request_id
            ),
        })
    }

    fn backend_name(&self) -> &str {
        "windows-preview-deny"
    }
}

#[derive(Debug)]
enum NetworkEnforcementGuard {
    FirewallRules {
        staged_program: PathBuf,
        staged_dir: PathBuf,
        inbound_rule: String,
        outbound_rule: String,
    },
    WfpServiceManaged {
        policy: Box<nono::WindowsNetworkPolicy>,
        probe_config: WfpProbeConfig,
        target_program: PathBuf,
        inbound_rule: String,
        outbound_rule: String,
    },
}

struct PreparedWindowsLaunch {
    _network_enforcement: Option<NetworkEnforcementGuard>,
    launch_program: PathBuf,
}

impl NetworkEnforcementGuard {
    fn launch_program(&self) -> &Path {
        match self {
            NetworkEnforcementGuard::FirewallRules { staged_program, .. } => {
                staged_program.as_path()
            }
            NetworkEnforcementGuard::WfpServiceManaged { target_program, .. } => {
                target_program.as_path()
            }
        }
    }
}

fn prepare_live_windows_launch(config: &ExecConfig<'_>) -> Result<PreparedWindowsLaunch> {
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
        "Windows live-execution backend prepared filesystem policy: {} compiled rule(s), {} unsupported rule(s)",
        fs_policy.rules.len(),
        fs_policy.unsupported.len()
    );

    let network_enforcement = prepare_network_enforcement(config)?;
    let launch_program = network_enforcement
        .as_ref()
        .map(NetworkEnforcementGuard::launch_program)
        .unwrap_or(config.resolved_program)
        .to_path_buf();

    Ok(PreparedWindowsLaunch {
        _network_enforcement: network_enforcement,
        launch_program,
    })
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
const WINDOWS_WFP_BACKEND_DRIVER_BINARY: &str = "nono-wfp-driver.sys";
const WINDOWS_WFP_BACKEND_SERVICE_ARGS: &[&str] = &["--service-mode"];
const WINDOWS_WFP_RUNTIME_PROBE_ARG: &str = "--probe-runtime-activation";
const WINDOWS_SUPERVISOR_POLL_INTERVAL: Duration = Duration::from_millis(100);

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
    BackendDriverBinaryMissing,
    BackendDriverMissing,
    BackendDriverStopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WfpProbeConfig {
    platform_service: &'static str,
    backend_service: &'static str,
    backend_driver: &'static str,
    backend_binary_path: PathBuf,
    backend_driver_binary_path: PathBuf,
    backend_service_args: &'static [&'static str],
}

#[cfg(debug_assertions)]
static WINDOWS_WFP_TEST_FORCE_READY: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, PartialEq, Eq)]
struct WfpRuntimeProbeOutput {
    status_code: Option<i32>,
    response: WfpRuntimeActivationResponse,
    stderr: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WfpRuntimeActivationProbeStatus {
    Ready,
    AcceptedButNotEnforced,
    EnforcedPendingCleanup,
    CleanupSucceeded,
    FilteringProbeSucceeded,
    NotImplemented,
}

#[cfg(debug_assertions)]
pub(crate) fn set_windows_wfp_test_force_ready(force_ready: bool) {
    WINDOWS_WFP_TEST_FORCE_READY.store(force_ready, Ordering::Relaxed);
}

#[cfg(not(debug_assertions))]
pub(crate) fn set_windows_wfp_test_force_ready(_force_ready: bool) {}

fn windows_wfp_test_force_ready() -> bool {
    #[cfg(debug_assertions)]
    {
        WINDOWS_WFP_TEST_FORCE_READY.load(Ordering::Relaxed)
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowsWfpReadinessReport {
    pub status_label: &'static str,
    pub details: String,
    pub next_action: Option<String>,
    pub service_status_label: &'static str,
    pub service_details: String,
    pub driver_status_label: &'static str,
    pub driver_details: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowsWfpInstallReport {
    pub status_label: &'static str,
    pub details: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowsWfpDriverInstallReport {
    pub status_label: &'static str,
    pub details: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowsWfpStartReport {
    pub status_label: &'static str,
    pub details: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowsWfpDriverStartReport {
    pub status_label: &'static str,
    pub details: String,
}

struct ProcessContainment {
    job: HANDLE,
}

struct OwnedHandle(HANDLE);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsSupervisorLifecycleState {
    Initializing,
    ControlChannelReady,
    LaunchingChild,
    WaitingForChild,
    ShuttingDown,
    Completed,
}

impl WindowsSupervisorLifecycleState {
    fn label(self) -> &'static str {
        match self {
            Self::Initializing => "initializing",
            Self::ControlChannelReady => "control-channel-ready",
            Self::LaunchingChild => "launching-child",
            Self::WaitingForChild => "waiting-for-child",
            Self::ShuttingDown => "shutting-down",
            Self::Completed => "completed",
        }
    }
}

enum WindowsSupervisedChild {
    Native {
        process: OwnedHandle,
        _thread: OwnedHandle,
    },
}

impl WindowsSupervisedChild {
    fn poll_exit_code(&mut self) -> Result<Option<i32>> {
        match self {
            Self::Native { process, .. } => {
                let wait_result = unsafe {
                    // SAFETY: `process.0` is a valid process handle owned by this child wrapper.
                    WaitForSingleObject(process.0, 0)
                };
                if wait_result == 0 {
                    let mut exit_code = 0u32;
                    let ok = unsafe {
                        // SAFETY: `process.0` remains a valid process handle for the duration
                        // of this query and `exit_code` points to writable memory.
                        GetExitCodeProcess(process.0, &mut exit_code)
                    };
                    if ok == 0 {
                        return Err(NonoError::SandboxInit(
                            "Failed to query Windows supervised child exit code".to_string(),
                        ));
                    }
                    Ok(Some(exit_code as i32))
                } else if wait_result == 0x0000_0102 {
                    Ok(None)
                } else {
                    Err(NonoError::SandboxInit(format!(
                        "Windows supervisor failed while waiting for child process state: {}",
                        std::io::Error::last_os_error()
                    )))
                }
            }
        }
    }
}

struct WindowsSupervisorRuntime {
    session_id: String,
    requested_features: Vec<String>,
    transport_name: String,
    _parent_control: nono::SupervisorSocket,
    child_control: Option<nono::SupervisorSocket>,
    started_at: Instant,
    state: WindowsSupervisorLifecycleState,
    audit_log: Vec<AuditEntry>,
}

impl WindowsSupervisorRuntime {
    fn initialize(supervisor: &SupervisorConfig<'_>) -> Result<Self> {
        let started_at = Instant::now();
        let (parent_control, child_control) = initialize_supervisor_control_channel()?;
        let transport_name = parent_control.transport_name().to_string();
        let mut runtime = Self {
            session_id: supervisor.session_id.to_string(),
            requested_features: supervisor
                .requested_features
                .iter()
                .map(|feature| (*feature).to_string())
                .collect(),
            transport_name,
            _parent_control: parent_control,
            child_control: Some(child_control),
            started_at,
            state: WindowsSupervisorLifecycleState::Initializing,
            audit_log: Vec::new(),
        };
        runtime.state = WindowsSupervisorLifecycleState::ControlChannelReady;
        Ok(runtime)
    }

    fn transport_name(&self) -> &str {
        self.transport_name.as_str()
    }

    fn run_child_event_loop(&mut self, child: &mut WindowsSupervisedChild) -> Result<i32> {
        self.state = WindowsSupervisorLifecycleState::WaitingForChild;
        tracing::debug!(
            "Windows supervisor event loop entering wait phase (session: {}, transport: {}, state: {}, features: {})",
            self.session_id,
            self.transport_name,
            self.state.label(),
            if self.requested_features.is_empty() {
                "none".to_string()
            } else {
                self.requested_features.join(", ")
            }
        );

        loop {
            if let Some(exit_code) = child.poll_exit_code()? {
                self.state = WindowsSupervisorLifecycleState::ShuttingDown;
                self.shutdown();
                self.state = WindowsSupervisorLifecycleState::Completed;
                tracing::debug!(
                    "Windows supervisor event loop completed (session: {}, transport: {}, exit_code: {}, elapsed_ms: {})",
                    self.session_id,
                    self.transport_name,
                    exit_code,
                    self.started_at.elapsed().as_millis()
                );
                return Ok(exit_code);
            }

            std::thread::sleep(WINDOWS_SUPERVISOR_POLL_INTERVAL);
        }
    }

    fn startup_failure(&mut self, message: String) -> NonoError {
        self.shutdown();
        NonoError::SandboxInit(format!(
            "Windows supervised execution failed during {} (session: {}, transport: {}, supervisor_audit_entries: {}): {}",
            self.state.label(),
            self.session_id,
            self.transport_name,
            self.audit_log.len(),
            message
        ))
    }

    fn command_failure(&mut self, message: String) -> NonoError {
        self.shutdown();
        NonoError::CommandExecution(std::io::Error::other(format!(
            "Windows supervised execution failed during {} (session: {}, transport: {}, supervisor_audit_entries: {}): {}",
            self.state.label(),
            self.session_id,
            self.transport_name,
            self.audit_log.len(),
            message
        )))
    }

    fn shutdown(&mut self) {
        let _ = self.child_control.take();
        self.state = WindowsSupervisorLifecycleState::ShuttingDown;
    }
}

impl Drop for WindowsSupervisorRuntime {
    fn drop(&mut self) {
        if self.state != WindowsSupervisorLifecycleState::Completed {
            self.shutdown();
        }
    }
}

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
        match self {
            NetworkEnforcementGuard::FirewallRules {
                staged_dir,
                inbound_rule,
                outbound_rule,
                ..
            } => {
                let _ = delete_firewall_rule(inbound_rule);
                let _ = delete_firewall_rule(outbound_rule);
                cleanup_network_enforcement_staging(staged_dir);
            }
            NetworkEnforcementGuard::WfpServiceManaged {
                policy,
                probe_config,
                target_program,
                inbound_rule,
                outbound_rule,
            } => {
                let _ = cleanup_wfp_service_managed_enforcement_with_runner(
                    policy,
                    probe_config,
                    target_program,
                    inbound_rule,
                    outbound_rule,
                    run_wfp_runtime_probe_with_request,
                );
            }
        }
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
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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
        backend_driver_binary_path: exe_dir.join(WINDOWS_WFP_BACKEND_DRIVER_BINARY),
        backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
    })
}

fn format_wfp_service_command(config: &WfpProbeConfig) -> String {
    format!(
        "\"{}\" {}",
        config.backend_binary_path.display(),
        config.backend_service_args.join(" ")
    )
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

fn run_sc_command(args: &[String]) -> Result<String> {
    let output = Command::new("sc")
        .args(args)
        .output()
        .map_err(NonoError::CommandExecution)?;
    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn sc_create_conflict_is_registered(output: &str) -> bool {
    let normalized = output.to_ascii_uppercase();
    normalized.contains("FAILED 1073")
        || normalized.contains("ALREADY EXISTS")
        || normalized.contains("MARKED FOR DELETION")
}

fn build_wfp_service_create_args(config: &WfpProbeConfig) -> Vec<String> {
    vec![
        "create".to_string(),
        config.backend_service.to_string(),
        "binPath=".to_string(),
        format_wfp_service_command(config),
        "start=".to_string(),
        "demand".to_string(),
        "type=".to_string(),
        "own".to_string(),
        "DisplayName=".to_string(),
        "nono WFP Service".to_string(),
    ]
}

fn build_wfp_service_description_args(config: &WfpProbeConfig) -> Vec<String> {
    vec![
        "description".to_string(),
        config.backend_service.to_string(),
        "Placeholder service host for the future nono Windows WFP backend. Registration is supported; runtime still fails closed until enforcement is implemented.".to_string(),
    ]
}

fn build_wfp_driver_create_args(config: &WfpProbeConfig) -> Vec<String> {
    vec![
        "create".to_string(),
        config.backend_driver.to_string(),
        "binPath=".to_string(),
        config.backend_driver_binary_path.display().to_string(),
        "type=".to_string(),
        "kernel".to_string(),
        "start=".to_string(),
        "demand".to_string(),
        "DisplayName=".to_string(),
        "nono WFP Driver".to_string(),
    ]
}

fn build_wfp_driver_description_args(config: &WfpProbeConfig) -> Vec<String> {
    vec![
        "description".to_string(),
        config.backend_driver.to_string(),
        "Placeholder kernel-driver registration for the future nono Windows WFP backend. Registration is supported; enforcement is not implemented yet.".to_string(),
    ]
}

fn build_wfp_service_start_args(config: &WfpProbeConfig) -> Vec<String> {
    vec!["start".to_string(), config.backend_service.to_string()]
}

fn build_wfp_driver_start_args(config: &WfpProbeConfig) -> Vec<String> {
    vec!["start".to_string(), config.backend_driver.to_string()]
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
    backend_driver_binary_exists: bool,
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

    if !backend_driver_binary_exists {
        return WfpProbeStatus::BackendDriverBinaryMissing;
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
    if windows_wfp_test_force_ready() {
        return Ok(build_wfp_probe_status(
            config.backend_binary_path.exists(),
            config.backend_driver_binary_path.exists(),
            WindowsServiceState::Running,
            WindowsServiceState::Running,
            WindowsServiceState::Running,
        ));
    }

    if !config.backend_binary_path.exists() {
        return Ok(WfpProbeStatus::BackendBinaryMissing);
    }

    let platform_output = run_sc_query(config.platform_service)?;
    let platform_state = parse_windows_service_state(&platform_output);
    let backend_service_state = parse_windows_service_state(&run_sc_query(config.backend_service)?);
    let backend_driver_state = parse_windows_service_state(&run_sc_query(config.backend_driver)?);

    Ok(build_wfp_probe_status(
        true,
        config.backend_driver_binary_path.exists(),
        platform_state,
        backend_service_state,
        backend_driver_state,
    ))
}

fn describe_wfp_runtime_activation_failure(
    policy: &nono::WindowsNetworkPolicy,
    config: &WfpProbeConfig,
    status: WfpProbeStatus,
) -> String {
    let runtime_target = describe_windows_network_runtime_target(policy);
    let reason = match status {
        WfpProbeStatus::Ready => format!(
            "the service `{}` and driver `{}` are present, but the runtime activation exchange did not install an enforceable network-policy state",
            config.backend_service, config.backend_driver
        ),
        WfpProbeStatus::BackendBinaryMissing => format!(
            "the WFP service binary `{}` is missing from this build output. Run `cargo build -p nono-cli --bins` first",
            config.backend_binary_path.display()
        ),
        WfpProbeStatus::PlatformServiceMissing => format!(
            "the Windows Base Filtering Engine service `{}` is missing on this machine",
            config.platform_service
        ),
        WfpProbeStatus::PlatformServiceStopped => format!(
            "the Windows Base Filtering Engine service `{}` is not running. Start it before retrying WFP activation",
            config.platform_service
        ),
        WfpProbeStatus::BackendServiceMissing => format!(
            "the WFP service `{}` is not registered. Run `nono setup --install-wfp-service` first",
            config.backend_service
        ),
        WfpProbeStatus::BackendServiceStopped => format!(
            "the WFP service `{}` is registered but not running. Run `nono setup --start-wfp-service` first",
            config.backend_service
        ),
        WfpProbeStatus::BackendDriverBinaryMissing => format!(
            "the WFP driver binary `{}` is missing from this build output. Run `cargo build -p nono-cli --bins` first",
            config.backend_driver_binary_path.display()
        ),
        WfpProbeStatus::BackendDriverMissing => format!(
            "the WFP driver `{}` is not registered. Run `nono setup --install-wfp-driver` first",
            config.backend_driver
        ),
        WfpProbeStatus::BackendDriverStopped => format!(
            "the WFP driver `{}` is registered but not running. Run `nono setup --start-wfp-driver` first",
            config.backend_driver
        ),
    };

    format!(
        "Windows WFP runtime activation is required for {} but {} ({}). This request remains fail-closed until WFP activation is implemented.",
        runtime_target,
        reason,
        policy.backend_summary()
    )
}

fn describe_windows_network_runtime_target(policy: &nono::WindowsNetworkPolicy) -> String {
    let base = match &policy.mode {
        nono::WindowsNetworkPolicyMode::AllowAll => "allow-all Windows network access".to_string(),
        nono::WindowsNetworkPolicyMode::Blocked => "blocked Windows network access".to_string(),
        nono::WindowsNetworkPolicyMode::ProxyOnly { port, bind_ports } => format!(
            "Windows proxy-only network access via localhost:{} with bind ports {:?}",
            port, bind_ports
        ),
    };

    let mut restrictions = Vec::new();
    if !policy.tcp_connect_ports.is_empty() {
        restrictions.push(format!("connect ports {:?}", policy.tcp_connect_ports));
    }
    if !policy.tcp_bind_ports.is_empty() {
        restrictions.push(format!("bind ports {:?}", policy.tcp_bind_ports));
    }
    if !policy.localhost_ports.is_empty() {
        restrictions.push(format!("localhost ports {:?}", policy.localhost_ports));
    }

    if restrictions.is_empty() {
        base
    } else {
        format!("{} with {}", base, restrictions.join(", "))
    }
}

fn build_wfp_runtime_activation_request(
    policy: &nono::WindowsNetworkPolicy,
) -> WfpRuntimeActivationRequest {
    let network_mode = match &policy.mode {
        nono::WindowsNetworkPolicyMode::AllowAll => "allow-all",
        nono::WindowsNetworkPolicyMode::Blocked => "blocked",
        nono::WindowsNetworkPolicyMode::ProxyOnly { .. } => "proxy-only",
    };
    let mut tcp_bind_ports = policy.tcp_bind_ports.clone();
    let mut localhost_ports = policy.localhost_ports.clone();
    if let nono::WindowsNetworkPolicyMode::ProxyOnly { port, bind_ports } = &policy.mode {
        tcp_bind_ports.extend(bind_ports.iter().copied());
        tcp_bind_ports.sort_unstable();
        tcp_bind_ports.dedup();
        localhost_ports.push(*port);
        localhost_ports.sort_unstable();
        localhost_ports.dedup();
    }

    WfpRuntimeActivationRequest {
        protocol_version: WFP_RUNTIME_PROTOCOL_VERSION,
        request_kind: match &policy.mode {
            nono::WindowsNetworkPolicyMode::Blocked => "activate_blocked_mode",
            nono::WindowsNetworkPolicyMode::AllowAll => "activate_allow_all_mode",
            nono::WindowsNetworkPolicyMode::ProxyOnly { .. } => "activate_proxy_mode",
        }
        .to_string(),
        network_mode: network_mode.to_string(),
        preferred_backend: policy.preferred_backend.label().to_string(),
        active_backend: policy.active_backend.label().to_string(),
        runtime_target: describe_windows_network_runtime_target(policy),
        tcp_connect_ports: policy.tcp_connect_ports.clone(),
        tcp_bind_ports,
        localhost_ports,
        target_program_path: None,
        outbound_rule_name: None,
        inbound_rule_name: None,
    }
}

fn build_wfp_target_activation_request(
    policy: &nono::WindowsNetworkPolicy,
    target_program: &Path,
    outbound_rule: &str,
    inbound_rule: &str,
) -> WfpRuntimeActivationRequest {
    let mut request = build_wfp_runtime_activation_request(policy);
    request.target_program_path = Some(target_program.display().to_string());
    request.outbound_rule_name = Some(outbound_rule.to_string());
    request.inbound_rule_name = Some(inbound_rule.to_string());
    request
}

fn build_wfp_runtime_cleanup_request(
    policy: &nono::WindowsNetworkPolicy,
    target_program: &Path,
    inbound_rule: &str,
    outbound_rule: &str,
) -> WfpRuntimeActivationRequest {
    let mut request = build_wfp_runtime_activation_request(policy);
    request.request_kind = "deactivate_policy_mode".to_string();
    request.target_program_path = Some(target_program.display().to_string());
    request.outbound_rule_name = Some(outbound_rule.to_string());
    request.inbound_rule_name = Some(inbound_rule.to_string());
    request.runtime_target = format!(
        "{} for {}",
        describe_windows_network_runtime_target(policy),
        target_program.display()
    );
    request
}

fn cleanup_wfp_service_managed_enforcement_with_runner<R>(
    policy: &nono::WindowsNetworkPolicy,
    probe_config: &WfpProbeConfig,
    target_program: &Path,
    inbound_rule: &str,
    outbound_rule: &str,
    run_probe: R,
) -> Result<()>
where
    R: Fn(&WfpProbeConfig, &WfpRuntimeActivationRequest) -> Result<WfpRuntimeProbeOutput>,
{
    let request =
        build_wfp_runtime_cleanup_request(policy, target_program, inbound_rule, outbound_rule);
    let output = run_probe(probe_config, &request)?;
    match parse_wfp_runtime_probe_status(&output)? {
        WfpRuntimeActivationProbeStatus::CleanupSucceeded => Ok(()),
        WfpRuntimeActivationProbeStatus::Ready
        | WfpRuntimeActivationProbeStatus::AcceptedButNotEnforced
        | WfpRuntimeActivationProbeStatus::EnforcedPendingCleanup
        | WfpRuntimeActivationProbeStatus::FilteringProbeSucceeded
        | WfpRuntimeActivationProbeStatus::NotImplemented => Err(NonoError::SandboxInit(format!(
            "Windows WFP cleanup returned an unexpected network-policy state: {:?}",
            output.response
        ))),
    }
}

fn describe_wfp_probe_status_for_setup(config: &WfpProbeConfig, status: WfpProbeStatus) -> String {
    let service_command = format_wfp_service_command(config);
    match status {
        WfpProbeStatus::Ready => format!(
            "WFP backend components are present (service binary: {}, driver binary: {}, service: {}, driver: {}), and live network-policy activation now depends on the service-host runtime transport. Expected service command: {}.",
            config.backend_binary_path.display(),
            config.backend_driver_binary_path.display(),
            config.backend_service,
            config.backend_driver,
            service_command
        ),
        WfpProbeStatus::BackendBinaryMissing => format!(
            "Expected WFP backend service binary is missing: {}. Expected service: {}. Expected driver: {}. Expected driver binary: {}. Expected registration/start command: {}.",
            config.backend_binary_path.display(),
            config.backend_service,
            config.backend_driver,
            config.backend_driver_binary_path.display(),
            service_command
        ),
        WfpProbeStatus::PlatformServiceMissing => format!(
            "Base Filtering Engine service ({}) is missing or could not be queried.",
            config.platform_service
        ),
        WfpProbeStatus::PlatformServiceStopped => format!(
            "Base Filtering Engine service ({}) is not running.",
            config.platform_service
        ),
        WfpProbeStatus::BackendServiceMissing => format!(
            "WFP backend service is missing: {}. Register it to launch {} with: {}.",
            config.backend_service,
            config.backend_service,
            service_command
        ),
        WfpProbeStatus::BackendServiceStopped => format!(
            "WFP backend service is installed but not running: {}. Its expected startup command remains: {}.",
            config.backend_service,
            service_command
        ),
        WfpProbeStatus::BackendDriverBinaryMissing => format!(
            "WFP backend driver binary is missing: {}. Expected driver registration name: {}.",
            config.backend_driver_binary_path.display(),
            config.backend_driver
        ),
        WfpProbeStatus::BackendDriverMissing => format!(
            "WFP backend driver is not registered: {}. Expected driver binary: {}.",
            config.backend_driver,
            config.backend_driver_binary_path.display()
        ),
        WfpProbeStatus::BackendDriverStopped => format!(
            "WFP backend driver is installed but not running: {}. Expected driver binary: {}.",
            config.backend_driver,
            config.backend_driver_binary_path.display()
        ),
    }
}

fn describe_wfp_service_status_for_setup(
    config: &WfpProbeConfig,
    status: WfpProbeStatus,
) -> (&'static str, String) {
    let service_command = format_wfp_service_command(config);
    match status {
        WfpProbeStatus::Ready => (
            "ready",
            format!(
                "WFP backend service {} is present and running. Expected startup command: {}.",
                config.backend_service, service_command
            ),
        ),
        WfpProbeStatus::BackendBinaryMissing => (
            "missing binary",
            format!(
                "WFP backend service binary is missing: {}. Expected service registration name: {}. Expected startup command: {}.",
                config.backend_binary_path.display(),
                config.backend_service,
                service_command
            ),
        ),
        WfpProbeStatus::PlatformServiceMissing => (
            "blocked by bfe",
            format!(
                "WFP backend service readiness is blocked because the Base Filtering Engine service ({}) is missing or could not be queried.",
                config.platform_service
            ),
        ),
        WfpProbeStatus::PlatformServiceStopped => (
            "blocked by bfe",
            format!(
                "WFP backend service readiness is blocked because the Base Filtering Engine service ({}) is not running.",
                config.platform_service
            ),
        ),
        WfpProbeStatus::BackendServiceMissing => (
            "not registered",
            format!(
                "WFP backend service is not registered: {}. Register it to launch {} with: {}.",
                config.backend_service, config.backend_service, service_command
            ),
        ),
        WfpProbeStatus::BackendServiceStopped => (
            "stopped",
            format!(
                "WFP backend service is registered but not running: {}. Its expected startup command remains: {}.",
                config.backend_service, service_command
            ),
        ),
        WfpProbeStatus::BackendDriverBinaryMissing
        | WfpProbeStatus::BackendDriverMissing
        | WfpProbeStatus::BackendDriverStopped => (
            "ready",
            format!(
                "WFP backend service {} is present and running. Expected startup command: {}.",
                config.backend_service, service_command
            ),
        ),
    }
}

fn describe_wfp_driver_status_for_setup(
    config: &WfpProbeConfig,
    status: WfpProbeStatus,
) -> (&'static str, String) {
    match status {
        WfpProbeStatus::Ready => (
            "ready",
            format!(
                "WFP backend driver {} is present and running from binary {}.",
                config.backend_driver,
                config.backend_driver_binary_path.display()
            ),
        ),
        WfpProbeStatus::BackendBinaryMissing => (
            "blocked by service",
            format!(
                "WFP backend driver readiness is blocked until the service binary {} is available.",
                config.backend_binary_path.display()
            ),
        ),
        WfpProbeStatus::PlatformServiceMissing => (
            "blocked by bfe",
            format!(
                "WFP backend driver readiness is blocked because the Base Filtering Engine service ({}) is missing or could not be queried.",
                config.platform_service
            ),
        ),
        WfpProbeStatus::PlatformServiceStopped => (
            "blocked by bfe",
            format!(
                "WFP backend driver readiness is blocked because the Base Filtering Engine service ({}) is not running.",
                config.platform_service
            ),
        ),
        WfpProbeStatus::BackendServiceMissing => (
            "blocked by service",
            format!(
                "WFP backend driver readiness is blocked until the service {} is registered.",
                config.backend_service
            ),
        ),
        WfpProbeStatus::BackendServiceStopped => (
            "blocked by service",
            format!(
                "WFP backend driver readiness is blocked until the service {} is running.",
                config.backend_service
            ),
        ),
        WfpProbeStatus::BackendDriverBinaryMissing => (
            "missing binary",
            format!(
                "WFP backend driver binary is missing: {}. Expected driver registration name: {}.",
                config.backend_driver_binary_path.display(),
                config.backend_driver
            ),
        ),
        WfpProbeStatus::BackendDriverMissing => (
            "not registered",
            format!(
                "WFP backend driver is not registered: {}. Expected driver binary: {}.",
                config.backend_driver,
                config.backend_driver_binary_path.display()
            ),
        ),
        WfpProbeStatus::BackendDriverStopped => (
            "stopped",
            format!(
                "WFP backend driver is registered but not running: {}. Expected driver binary: {}.",
                config.backend_driver,
                config.backend_driver_binary_path.display()
            ),
        ),
    }
}

fn describe_wfp_next_action_for_setup(
    config: &WfpProbeConfig,
    status: WfpProbeStatus,
) -> Option<String> {
    match status {
        WfpProbeStatus::Ready => Some(
            "Next action: Windows WFP components are present, but runtime activation is still not implemented in this build."
                .to_string(),
        ),
        WfpProbeStatus::BackendBinaryMissing => Some(format!(
            "Next action: build the Windows backend artifacts first with `cargo build -p nono-cli --bins` so `{}` exists.",
            config.backend_binary_path.display()
        )),
        WfpProbeStatus::PlatformServiceMissing => Some(format!(
            "Next action: verify that the Windows Base Filtering Engine service `{}` is available on this machine.",
            config.platform_service
        )),
        WfpProbeStatus::PlatformServiceStopped => Some(format!(
            "Next action: start the Windows Base Filtering Engine service `{}` before retrying WFP setup or activation.",
            config.platform_service
        )),
        WfpProbeStatus::BackendServiceMissing => Some(
            "Next action: run `nono setup --install-wfp-service`.".to_string(),
        ),
        WfpProbeStatus::BackendServiceStopped => Some(
            "Next action: run `nono setup --start-wfp-service`.".to_string(),
        ),
        WfpProbeStatus::BackendDriverBinaryMissing => Some(format!(
            "Next action: build the Windows backend artifacts first with `cargo build -p nono-cli --bins` so `{}` exists.",
            config.backend_driver_binary_path.display()
        )),
        WfpProbeStatus::BackendDriverMissing => Some(
            "Next action: run `nono setup --install-wfp-driver`.".to_string(),
        ),
        WfpProbeStatus::BackendDriverStopped => Some(
            "Next action: run `nono setup --start-wfp-driver`.".to_string(),
        ),
    }
}

fn run_wfp_runtime_probe_with_request(
    config: &WfpProbeConfig,
    request: &WfpRuntimeActivationRequest,
) -> Result<WfpRuntimeProbeOutput> {
    let request_json = serde_json::to_vec(request).map_err(|err| {
        NonoError::SandboxInit(format!(
            "Failed to serialize Windows WFP runtime activation request: {}",
            err
        ))
    })?;
    let mut child = Command::new(&config.backend_binary_path)
        .arg(WINDOWS_WFP_RUNTIME_PROBE_ARG)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| {
            NonoError::SandboxInit(format!(
                "Failed to execute Windows WFP runtime probe `{}` {}: {}",
                config.backend_binary_path.display(),
                WINDOWS_WFP_RUNTIME_PROBE_ARG,
                err
            ))
        })?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(&request_json).map_err(|err| {
            NonoError::SandboxInit(format!(
                "Failed to write Windows WFP runtime activation request to `{}` {}: {}",
                config.backend_binary_path.display(),
                WINDOWS_WFP_RUNTIME_PROBE_ARG,
                err
            ))
        })?;
    }
    let output = child.wait_with_output().map_err(|err| {
        NonoError::SandboxInit(format!(
            "Failed to wait for Windows WFP runtime probe `{}` {}: {}",
            config.backend_binary_path.display(),
            WINDOWS_WFP_RUNTIME_PROBE_ARG,
            err
        ))
    })?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let response: WfpRuntimeActivationResponse = serde_json::from_str(&stdout).map_err(|err| {
        NonoError::SandboxInit(format!(
            "Windows WFP runtime probe returned invalid JSON (status: {:?}, stdout: {:?}): {}",
            output.status.code(),
            stdout,
            err
        ))
    })?;

    Ok(WfpRuntimeProbeOutput {
        status_code: output.status.code(),
        response,
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

fn parse_wfp_runtime_probe_status(
    output: &WfpRuntimeProbeOutput,
) -> Result<WfpRuntimeActivationProbeStatus> {
    if output.response.status == "ready" {
        return Ok(WfpRuntimeActivationProbeStatus::Ready);
    }
    if output.response.status == "accepted-but-not-enforced" {
        return Ok(WfpRuntimeActivationProbeStatus::AcceptedButNotEnforced);
    }
    if output.response.status == "enforced-pending-cleanup" {
        return Ok(WfpRuntimeActivationProbeStatus::EnforcedPendingCleanup);
    }
    if output.response.status == "cleanup-succeeded" {
        return Ok(WfpRuntimeActivationProbeStatus::CleanupSucceeded);
    }
    if output.response.status == "filtering-probe-succeeded" {
        return Ok(WfpRuntimeActivationProbeStatus::FilteringProbeSucceeded);
    }
    if output.response.status == "not-implemented" {
        return Ok(WfpRuntimeActivationProbeStatus::NotImplemented);
    }
    if output.response.status == "invalid-request" {
        return Err(NonoError::UnsupportedPlatform(format!(
            "Windows WFP service rejected the runtime activation request: {}",
            output.response.details
        )));
    }
    if output.response.status == "protocol-mismatch" {
        return Err(NonoError::SandboxInit(format!(
            "Windows WFP activation protocol mismatch: {}",
            output.response.details
        )));
    }
    if output.response.status == "prerequisites-missing" {
        return Err(NonoError::UnsupportedPlatform(format!(
            "Windows WFP activation prerequisites are missing: {}",
            output.response.details
        )));
    }
    if output.response.status == "filtering-probe-failed" {
        return Err(NonoError::UnsupportedPlatform(format!(
            "Windows WFP service could not install its network-policy filtering probe: {}",
            output.response.details
        )));
    }
    if output.response.status == "cleanup-failed" {
        return Err(NonoError::UnsupportedPlatform(format!(
            "Windows WFP service could not clean up target-attached network-policy enforcement: {}",
            output.response.details
        )));
    }

    Err(NonoError::SandboxInit(format!(
        "Windows WFP runtime probe returned unexpected response (status: {:?}, response: {:?}, stderr: {:?})",
        output.status_code, output.response, output.stderr
    )))
}

fn describe_wfp_runtime_probe_failure(
    config: &WfpProbeConfig,
    output: &WfpRuntimeProbeOutput,
) -> String {
    format!(
        "the WFP service probe `{}` {} reported an unexpected runtime activation state (status: {:?}, response: {:?}, stderr: {:?})",
        config.backend_binary_path.display(),
        WINDOWS_WFP_RUNTIME_PROBE_ARG,
        output.status_code,
        output.response,
        output.stderr
    )
}

fn install_windows_wfp_service_with_runner<Q, R>(
    config: &WfpProbeConfig,
    query_service: Q,
    run_service_command: R,
) -> Result<WindowsWfpInstallReport>
where
    Q: Fn(&str) -> Result<String>,
    R: Fn(&[String]) -> Result<String>,
{
    if !config.backend_binary_path.exists() {
        return Err(NonoError::Setup(format!(
            "Cannot register Windows WFP service because the backend binary is missing: {}. Build nono-wfp-service first.",
            config.backend_binary_path.display()
        )));
    }

    let platform_state = parse_windows_service_state(&query_service(config.platform_service)?);
    match platform_state {
        WindowsServiceState::Running => {}
        WindowsServiceState::Stopped => {
            return Err(NonoError::Setup(format!(
                "Cannot register Windows WFP service because the Base Filtering Engine service ({}) is not running.",
                config.platform_service
            )));
        }
        WindowsServiceState::Missing | WindowsServiceState::Unknown => {
            return Err(NonoError::Setup(format!(
                "Cannot register Windows WFP service because the Base Filtering Engine service ({}) is missing or could not be queried.",
                config.platform_service
            )));
        }
    }

    let service_command = format_wfp_service_command(config);
    let service_state = parse_windows_service_state(&query_service(config.backend_service)?);
    if service_state != WindowsServiceState::Missing {
        return Ok(WindowsWfpInstallReport {
            status_label: "already installed",
            details: format!(
                "Windows WFP service {} is already registered. Expected startup command: {}. The service host is used for blocked-mode activation, but unsupported states still fail closed until full backend parity is implemented.",
                config.backend_service, service_command
            ),
        });
    }

    if let Err(err) = run_service_command(&build_wfp_service_create_args(config)) {
        if let Ok(state) = query_service(config.backend_service) {
            let registered_state = parse_windows_service_state(&state);
            if registered_state != WindowsServiceState::Missing
                && sc_create_conflict_is_registered(&err.to_string())
            {
                return Ok(WindowsWfpInstallReport {
                    status_label: "already installed",
                    details: format!(
                        "Windows WFP service {} is already registered. Expected startup command: {}. The service host is used for blocked-mode activation, but unsupported states still fail closed until full backend parity is implemented.",
                        config.backend_service, service_command
                    ),
                });
            }
        }
        return Err(err);
    }
    run_service_command(&build_wfp_service_description_args(config))?;

    let registered_state = parse_windows_service_state(&query_service(config.backend_service)?);
    if registered_state == WindowsServiceState::Missing {
        return Err(NonoError::Setup(format!(
            "Windows WFP service registration did not persist for {}. Expected startup command: {}.",
            config.backend_service, service_command
        )));
    }

    Ok(WindowsWfpInstallReport {
        status_label: "installed",
        details: format!(
            "Registered Windows WFP service {} with startup command: {}. Service startup is not attempted automatically because explicit lifecycle control is still required before live WFP activation.",
            config.backend_service, service_command
        ),
    })
}

pub(crate) fn install_windows_wfp_service() -> Result<WindowsWfpInstallReport> {
    let config = current_wfp_probe_config()?;
    install_windows_wfp_service_with_runner(&config, run_sc_query, run_sc_command)
}

fn install_windows_wfp_driver_with_runner<Q, R>(
    config: &WfpProbeConfig,
    query_service: Q,
    run_service_command: R,
) -> Result<WindowsWfpDriverInstallReport>
where
    Q: Fn(&str) -> Result<String>,
    R: Fn(&[String]) -> Result<String>,
{
    if !config.backend_driver_binary_path.exists() {
        return Err(NonoError::Setup(format!(
            "Cannot register Windows WFP driver because the driver binary is missing: {}. Build nono-cli so the placeholder driver artifact is staged first.",
            config.backend_driver_binary_path.display()
        )));
    }

    let platform_state = parse_windows_service_state(&query_service(config.platform_service)?);
    match platform_state {
        WindowsServiceState::Running => {}
        WindowsServiceState::Stopped => {
            return Err(NonoError::Setup(format!(
                "Cannot register Windows WFP driver because the Base Filtering Engine service ({}) is not running.",
                config.platform_service
            )));
        }
        WindowsServiceState::Missing | WindowsServiceState::Unknown => {
            return Err(NonoError::Setup(format!(
                "Cannot register Windows WFP driver because the Base Filtering Engine service ({}) is missing or could not be queried.",
                config.platform_service
            )));
        }
    }

    let driver_state = parse_windows_service_state(&query_service(config.backend_driver)?);
    if driver_state != WindowsServiceState::Missing {
        return Ok(WindowsWfpDriverInstallReport {
            status_label: "already installed",
            details: format!(
                "Windows WFP driver {} is already registered. Expected driver binary path: {}. Driver startup is not attempted automatically.",
                config.backend_driver,
                config.backend_driver_binary_path.display()
            ),
        });
    }

    if let Err(err) = run_service_command(&build_wfp_driver_create_args(config)) {
        if let Ok(state) = query_service(config.backend_driver) {
            let registered_state = parse_windows_service_state(&state);
            if registered_state != WindowsServiceState::Missing
                && sc_create_conflict_is_registered(&err.to_string())
            {
                return Ok(WindowsWfpDriverInstallReport {
                    status_label: "already installed",
                    details: format!(
                        "Windows WFP driver {} is already registered. Expected driver binary path: {}. Driver startup is not attempted automatically.",
                        config.backend_driver,
                        config.backend_driver_binary_path.display()
                    ),
                });
            }
        }
        return Err(err);
    }
    run_service_command(&build_wfp_driver_description_args(config))?;

    let registered_state = parse_windows_service_state(&query_service(config.backend_driver)?);
    if registered_state == WindowsServiceState::Missing {
        return Err(NonoError::Setup(format!(
            "Windows WFP driver registration did not persist for {}. Expected driver binary path: {}.",
            config.backend_driver,
            config.backend_driver_binary_path.display()
        )));
    }

    Ok(WindowsWfpDriverInstallReport {
        status_label: "installed",
        details: format!(
            "Registered Windows WFP driver {} with binary path {}. Driver startup is not attempted automatically because this branch still does not ship a working WFP driver.",
            config.backend_driver,
            config.backend_driver_binary_path.display()
        ),
    })
}

pub(crate) fn install_windows_wfp_driver() -> Result<WindowsWfpDriverInstallReport> {
    let config = current_wfp_probe_config()?;
    install_windows_wfp_driver_with_runner(&config, run_sc_query, run_sc_command)
}

fn start_windows_wfp_driver_with_runner<Q, R>(
    config: &WfpProbeConfig,
    query_service: Q,
    run_service_command: R,
) -> Result<WindowsWfpDriverStartReport>
where
    Q: Fn(&str) -> Result<String>,
    R: Fn(&[String]) -> Result<String>,
{
    if !config.backend_driver_binary_path.exists() {
        return Err(NonoError::Setup(format!(
            "Cannot start Windows WFP driver because the driver binary is missing: {}. Build nono-cli so the placeholder driver artifact is staged first.",
            config.backend_driver_binary_path.display()
        )));
    }

    let platform_state = parse_windows_service_state(&query_service(config.platform_service)?);
    match platform_state {
        WindowsServiceState::Running => {}
        WindowsServiceState::Stopped => {
            return Err(NonoError::Setup(format!(
                "Cannot start Windows WFP driver because the Base Filtering Engine service ({}) is not running.",
                config.platform_service
            )));
        }
        WindowsServiceState::Missing | WindowsServiceState::Unknown => {
            return Err(NonoError::Setup(format!(
                "Cannot start Windows WFP driver because the Base Filtering Engine service ({}) is missing or could not be queried.",
                config.platform_service
            )));
        }
    }

    let driver_state = parse_windows_service_state(&query_service(config.backend_driver)?);
    match driver_state {
        WindowsServiceState::Running => {
            return Ok(WindowsWfpDriverStartReport {
                status_label: "already running",
                details: format!(
                    "Windows WFP driver {} is already running from binary {}. Network enforcement is still not active until the real WFP backend is implemented.",
                    config.backend_driver,
                    config.backend_driver_binary_path.display()
                ),
            });
        }
        WindowsServiceState::Missing | WindowsServiceState::Unknown => {
            return Err(NonoError::Setup(format!(
                "Cannot start Windows WFP driver because it is not registered: {}. Run `nono setup --install-wfp-driver` first.",
                config.backend_driver
            )));
        }
        WindowsServiceState::Stopped => {}
    }

    let start_output = run_service_command(&build_wfp_driver_start_args(config))?;
    let updated_state = parse_windows_service_state(&query_service(config.backend_driver)?);
    if updated_state == WindowsServiceState::Running {
        return Ok(WindowsWfpDriverStartReport {
            status_label: "running",
            details: format!(
                "Windows WFP driver {} is running from binary {}. The placeholder driver still does not provide network enforcement yet.",
                config.backend_driver,
                config.backend_driver_binary_path.display()
            ),
        });
    }

    Err(NonoError::Setup(format!(
        "Windows WFP driver {} did not reach RUNNING after an explicit start attempt. Driver binary: {}. Current host output: {}. This is expected while the placeholder driver still fails closed.",
        config.backend_driver,
        config.backend_driver_binary_path.display(),
        start_output.trim()
    )))
}

pub(crate) fn start_windows_wfp_driver() -> Result<WindowsWfpDriverStartReport> {
    let config = current_wfp_probe_config()?;
    start_windows_wfp_driver_with_runner(&config, run_sc_query, run_sc_command)
}

fn start_windows_wfp_service_with_runner<Q, R>(
    config: &WfpProbeConfig,
    query_service: Q,
    run_service_command: R,
) -> Result<WindowsWfpStartReport>
where
    Q: Fn(&str) -> Result<String>,
    R: Fn(&[String]) -> Result<String>,
{
    if !config.backend_binary_path.exists() {
        return Err(NonoError::Setup(format!(
            "Cannot start Windows WFP service because the backend binary is missing: {}. Build nono-wfp-service first.",
            config.backend_binary_path.display()
        )));
    }

    let platform_state = parse_windows_service_state(&query_service(config.platform_service)?);
    match platform_state {
        WindowsServiceState::Running => {}
        WindowsServiceState::Stopped => {
            return Err(NonoError::Setup(format!(
                "Cannot start Windows WFP service because the Base Filtering Engine service ({}) is not running.",
                config.platform_service
            )));
        }
        WindowsServiceState::Missing | WindowsServiceState::Unknown => {
            return Err(NonoError::Setup(format!(
                "Cannot start Windows WFP service because the Base Filtering Engine service ({}) is missing or could not be queried.",
                config.platform_service
            )));
        }
    }

    let service_command = format_wfp_service_command(config);
    let service_state = parse_windows_service_state(&query_service(config.backend_service)?);
    match service_state {
        WindowsServiceState::Running => {
            return Ok(WindowsWfpStartReport {
                status_label: "already running",
                details: format!(
                    "Windows WFP service {} is already running. Its registered startup command is {}. Network enforcement is still not active until the real WFP backend is implemented.",
                    config.backend_service, service_command
                ),
            });
        }
        WindowsServiceState::Missing | WindowsServiceState::Unknown => {
            return Err(NonoError::Setup(format!(
                "Cannot start Windows WFP service because it is not registered: {}. Run `nono setup --install-wfp-service` first.",
                config.backend_service
            )));
        }
        WindowsServiceState::Stopped => {}
    }

    let start_output = run_service_command(&build_wfp_service_start_args(config))?;
    let updated_state = parse_windows_service_state(&query_service(config.backend_service)?);
    if updated_state == WindowsServiceState::Running {
        return Ok(WindowsWfpStartReport {
            status_label: "running",
            details: format!(
                "Windows WFP service {} is running with startup command {}. The placeholder service host still does not provide network enforcement yet.",
                config.backend_service, service_command
            ),
        });
    }

    Err(NonoError::Setup(format!(
        "Windows WFP service {} did not reach RUNNING after an explicit start attempt. Startup command: {}. Current host output: {}. This is expected while the placeholder service host still fails closed.",
        config.backend_service,
        service_command,
        start_output.trim()
    )))
}

pub(crate) fn start_windows_wfp_service() -> Result<WindowsWfpStartReport> {
    let config = current_wfp_probe_config()?;
    start_windows_wfp_service_with_runner(&config, run_sc_query, run_sc_command)
}

pub(crate) fn probe_windows_wfp_readiness() -> WindowsWfpReadinessReport {
    let Ok(config) = current_wfp_probe_config() else {
        return WindowsWfpReadinessReport {
            status_label: "probe failed",
            details: "Failed to resolve expected WFP backend component paths from the current executable layout.".to_string(),
            next_action: None,
            service_status_label: "probe failed",
            service_details: "Failed to resolve expected WFP backend service component paths from the current executable layout.".to_string(),
            driver_status_label: "probe failed",
            driver_details: "Failed to resolve expected WFP backend driver component paths from the current executable layout.".to_string(),
        };
    };

    match probe_wfp_backend_status_with_config(&config) {
        Ok(status) => {
            let (service_status_label, service_details) =
                describe_wfp_service_status_for_setup(&config, status);
            let (driver_status_label, driver_details) =
                describe_wfp_driver_status_for_setup(&config, status);
            WindowsWfpReadinessReport {
                status_label: match status {
                    WfpProbeStatus::Ready => "ready",
                    WfpProbeStatus::BackendBinaryMissing => "missing binary",
                    WfpProbeStatus::PlatformServiceMissing => "missing bfe",
                    WfpProbeStatus::PlatformServiceStopped => "bfe stopped",
                    WfpProbeStatus::BackendServiceMissing => "missing service",
                    WfpProbeStatus::BackendServiceStopped => "service stopped",
                    WfpProbeStatus::BackendDriverBinaryMissing => "missing driver binary",
                    WfpProbeStatus::BackendDriverMissing => "driver not registered",
                    WfpProbeStatus::BackendDriverStopped => "driver stopped",
                },
                details: describe_wfp_probe_status_for_setup(&config, status),
                next_action: describe_wfp_next_action_for_setup(&config, status),
                service_status_label,
                service_details,
                driver_status_label,
                driver_details,
            }
        }
        Err(err) => WindowsWfpReadinessReport {
            status_label: "probe failed",
            details: format!("Failed to probe Windows WFP readiness: {err}"),
            next_action: None,
            service_status_label: "probe failed",
            service_details: format!("Failed to probe Windows WFP service readiness: {err}"),
            driver_status_label: "probe failed",
            driver_details: format!("Failed to probe Windows WFP driver readiness: {err}"),
        },
    }
}

fn select_network_backend(
    policy: &nono::WindowsNetworkPolicy,
) -> Result<Option<Box<dyn WindowsNetworkBackend>>> {
    if matches!(&policy.mode, nono::WindowsNetworkPolicyMode::AllowAll) && policy.has_port_rules() {
        return Ok(Some(Box::new(WfpNetworkBackend)));
    }

    match (&policy.mode, policy.active_backend) {
        (nono::WindowsNetworkPolicyMode::AllowAll, nono::WindowsNetworkBackendKind::None) => {
            Ok(None)
        }
        (
            nono::WindowsNetworkPolicyMode::Blocked,
            nono::WindowsNetworkBackendKind::FirewallRules,
        ) => Ok(Some(Box::new(FirewallRulesNetworkBackend))),
        (
            nono::WindowsNetworkPolicyMode::Blocked,
            nono::WindowsNetworkBackendKind::Wfp,
        ) => Ok(Some(Box::new(WfpNetworkBackend))),
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
        let _ = Sandbox::windows_network_launch_support(policy, config.resolved_program);

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

        Ok(Some(NetworkEnforcementGuard::FirewallRules {
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
        config: &ExecConfig<'_>,
    ) -> Result<Option<NetworkEnforcementGuard>> {
        let probe_config = current_wfp_probe_config()?;
        install_wfp_network_backend(policy, config, &probe_config)
    }
}

fn install_wfp_network_backend(
    policy: &nono::WindowsNetworkPolicy,
    config: &ExecConfig<'_>,
    probe_config: &WfpProbeConfig,
) -> Result<Option<NetworkEnforcementGuard>> {
    if matches!(&policy.mode, nono::WindowsNetworkPolicyMode::AllowAll) && !policy.has_port_rules()
    {
        return Ok(None);
    }

    match &policy.mode {
        nono::WindowsNetworkPolicyMode::AllowAll
        | nono::WindowsNetworkPolicyMode::Blocked
        | nono::WindowsNetworkPolicyMode::ProxyOnly { .. } => {
            let _ = Sandbox::windows_network_launch_support(policy, config.resolved_program);
            let status = probe_wfp_backend_status_with_config(probe_config).map_err(|err| {
                NonoError::SandboxInit(format!(
                    "Failed to probe Windows WFP backend status ({}): {}",
                    policy.backend_summary(),
                    err
                ))
            })?;
            if status == WfpProbeStatus::Ready {
                let suffix = unique_windows_firewall_rule_suffix();
                let outbound_rule = format!("nono-wfp-block-out-{suffix}");
                let inbound_rule = format!("nono-wfp-block-in-{suffix}");
                let request = build_wfp_target_activation_request(
                    policy,
                    config.resolved_program,
                    &outbound_rule,
                    &inbound_rule,
                );
                let probe_output = run_wfp_runtime_probe_with_request(probe_config, &request)?;
                return match parse_wfp_runtime_probe_status(&probe_output)? {
                    WfpRuntimeActivationProbeStatus::Ready => Err(NonoError::UnsupportedPlatform(
                        format!(
                            "Windows WFP runtime activation reported ready for {}, but enforcement installation is still not implemented ({}). This request remains fail-closed.",
                            describe_windows_network_runtime_target(policy),
                            policy.backend_summary()
                        ),
                    )),
                    WfpRuntimeActivationProbeStatus::NotImplemented => Err(
                        NonoError::UnsupportedPlatform(format!(
                            "Windows WFP runtime activation is required for {} but {} ({}). This request remains fail-closed until WFP activation is implemented.",
                            describe_windows_network_runtime_target(policy),
                            describe_wfp_runtime_probe_failure(probe_config, &probe_output),
                            policy.backend_summary()
                        )),
                    ),
                    WfpRuntimeActivationProbeStatus::AcceptedButNotEnforced => Err(
                        NonoError::UnsupportedPlatform(format!(
                            "Windows WFP network-policy activation was accepted by the service host but no filtering primitive was installed yet: {}. This request remains fail-closed.",
                            probe_output.response.details
                        )),
                    ),
                    WfpRuntimeActivationProbeStatus::EnforcedPendingCleanup => Ok(Some(
                        NetworkEnforcementGuard::WfpServiceManaged {
                            policy: Box::new(policy.clone()),
                            probe_config: probe_config.clone(),
                            target_program: config.resolved_program.to_path_buf(),
                            inbound_rule,
                            outbound_rule,
                        },
                    )),
                    WfpRuntimeActivationProbeStatus::CleanupSucceeded => Err(
                        NonoError::SandboxInit(
                            "Windows WFP activation returned cleanup success during install; this is an unexpected protocol state.".to_string(),
                        ),
                    ),
                    WfpRuntimeActivationProbeStatus::FilteringProbeSucceeded => Err(
                        NonoError::UnsupportedPlatform(format!(
                            "Windows WFP network-policy activation successfully exercised a service-owned filtering primitive, but it is not attached to the target process yet: {}. This request remains fail-closed.",
                            probe_output.response.details
                        )),
                    ),
                };
            }
            Err(NonoError::UnsupportedPlatform(
                describe_wfp_runtime_activation_failure(policy, probe_config, status),
            ))
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

fn apply_process_handle_to_containment(
    containment: &ProcessContainment,
    process: HANDLE,
) -> Result<()> {
    let ok = unsafe {
        // SAFETY: `containment.job` is a live job handle owned by the current
        // process, and `process` is a live process handle returned by
        // CreateProcessW/CreateProcessAsUserW.
        AssignProcessToJobObject(containment.job, process)
    };
    if ok == 0 {
        return Err(NonoError::SandboxInit(
            "Failed to assign Windows child process to process containment job object".to_string(),
        ));
    }
    Ok(())
}

fn terminate_suspended_process(process: HANDLE, reason: &str) {
    let _ = unsafe {
        // SAFETY: `process` is a live process handle that the caller owns for the
        // duration of this cleanup path. Best-effort termination preserves fail-closed behavior.
        TerminateProcess(process, 1)
    };
    tracing::debug!("terminated suspended Windows child after containment failure: {reason}");
}

fn resume_contained_process(process: HANDLE, thread: HANDLE) -> Result<()> {
    let resume_result = unsafe {
        // SAFETY: `thread` is the live primary thread handle returned by
        // CreateProcessW/CreateProcessAsUserW. Resuming it starts execution only
        // after containment has already been attached.
        ResumeThread(thread)
    };
    if resume_result == u32::MAX {
        terminate_suspended_process(process, "ResumeThread failed");
        return Err(NonoError::SandboxInit(
            "Failed to resume Windows child process after attaching containment".to_string(),
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

#[cfg(test)]
fn open_windows_supervisor_path(path: &Path, access: &nono::AccessMode) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    match access {
        nono::AccessMode::Read => {
            options.read(true);
        }
        nono::AccessMode::Write => {
            options.write(true);
        }
        nono::AccessMode::ReadWrite => {
            options.read(true).write(true);
        }
    }

    options.open(path).map_err(|e| {
        NonoError::SandboxInit(format!(
            "Windows supervisor failed to open approved path {}: {}",
            path.display(),
            e
        ))
    })
}

#[cfg(test)]
fn handle_windows_supervisor_message(
    sock: &mut nono::SupervisorSocket,
    msg: nono::supervisor::SupervisorMessage,
    approval_backend: &dyn ApprovalBackend,
    target_process: nono::BrokerTargetProcess,
    seen_request_ids: &mut HashSet<String>,
    audit_log: &mut Vec<AuditEntry>,
) -> Result<()> {
    match msg {
        nono::supervisor::SupervisorMessage::Request(request) => {
            let started_at = Instant::now();
            if seen_request_ids.contains(&request.request_id) {
                let decision = nono::ApprovalDecision::Denied {
                    reason: "Duplicate request_id rejected (replay detected)".to_string(),
                };
                audit_log.push(AuditEntry {
                    timestamp: SystemTime::now(),
                    request: request.clone(),
                    decision: decision.clone(),
                    backend: approval_backend.backend_name().to_string(),
                    duration_ms: started_at.elapsed().as_millis() as u64,
                });
                return sock.send_response(&nono::supervisor::SupervisorResponse::Decision {
                    request_id: request.request_id,
                    decision,
                    grant: None,
                });
            }
            seen_request_ids.insert(request.request_id.clone());

            let decision = approval_backend
                .request_capability(&request)
                .unwrap_or_else(|e| nono::ApprovalDecision::Denied {
                    reason: format!("Approval backend error: {e}"),
                });

            let grant = if decision.is_granted() {
                let file = open_windows_supervisor_path(&request.path, &request.access)?;
                Some(nono::supervisor::socket::broker_file_handle_to_process(
                    &file,
                    target_process,
                    request.access,
                )?)
            } else {
                None
            };

            audit_log.push(AuditEntry {
                timestamp: SystemTime::now(),
                request: request.clone(),
                decision: decision.clone(),
                backend: approval_backend.backend_name().to_string(),
                duration_ms: started_at.elapsed().as_millis() as u64,
            });

            sock.send_response(&nono::supervisor::SupervisorResponse::Decision {
                request_id: request.request_id,
                decision,
                grant,
            })
        }
        nono::supervisor::SupervisorMessage::OpenUrl(url_request) => sock
            .send_response(&nono::supervisor::SupervisorResponse::UrlOpened {
            request_id: url_request.request_id,
            success: false,
            error: Some(
                "Windows delegated browser-open flows are not available yet. Windows supervised child processes do not have an attached supervisor control channel for open-url requests."
                    .to_string(),
            ),
        }),
    }
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
    let mut child =
        spawn_low_integrity_windows_child(config, launch_program, containment, cmd_args)?;
    let Some(exit_code) = child.poll_exit_code()? else {
        loop {
            if let Some(exit_code) = child.poll_exit_code()? {
                return Ok(exit_code);
            }
            std::thread::sleep(WINDOWS_SUPERVISOR_POLL_INTERVAL);
        }
    };
    Ok(exit_code)
}

fn spawn_low_integrity_windows_child(
    config: &ExecConfig<'_>,
    launch_program: &Path,
    containment: &ProcessContainment,
    cmd_args: &[String],
) -> Result<WindowsSupervisedChild> {
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
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
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

fn spawn_supervised_with_low_integrity(
    config: &ExecConfig<'_>,
    launch_program: &Path,
    containment: &ProcessContainment,
) -> Result<WindowsSupervisedChild> {
    let cmd_args = prepare_runtime_hardened_args(launch_program, &config.command[1..]);
    spawn_low_integrity_windows_child(config, launch_program, containment, &cmd_args)
}

fn spawn_supervised_with_standard_token(
    config: &ExecConfig<'_>,
    launch_program: &Path,
    containment: &ProcessContainment,
) -> Result<WindowsSupervisedChild> {
    let cmd_args = prepare_runtime_hardened_args(launch_program, &config.command[1..]);
    spawn_windows_child_with_current_token(config, launch_program, containment, &cmd_args)
}

fn spawn_windows_child_with_current_token(
    config: &ExecConfig<'_>,
    launch_program: &Path,
    containment: &ProcessContainment,
    cmd_args: &[String],
) -> Result<WindowsSupervisedChild> {
    let env_pairs = build_child_env(config);
    let mut environment_block = build_windows_environment_block(&env_pairs);
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
            // SAFETY: PROCESS_INFORMATION is a plain FFI struct populated by CreateProcessW.
            std::mem::zeroed()
        }
    };

    let created = unsafe {
        // SAFETY: All pointers either refer to valid, nul-terminated UTF-16 buffers
        // or are null as documented by CreateProcessW.
        CreateProcessW(
            application_name.as_ptr(),
            command_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
            environment_block.as_mut_ptr() as *mut _,
            current_dir.as_ptr(),
            &startup_info,
            &mut process_info,
        )
    };
    if created == 0 {
        return Err(NonoError::SandboxInit(format!(
            "Failed to launch Windows child process with containment staging (GetLastError={})",
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

pub fn execute_direct(config: &ExecConfig<'_>) -> Result<i32> {
    let prepared = prepare_live_windows_launch(config)?;
    let launch_program = prepared.launch_program.as_path();

    let cmd_args = prepare_runtime_hardened_args(launch_program, &config.command[1..]);
    let containment = create_process_containment()?;
    if should_use_low_integrity_windows_launch(config.caps) {
        return execute_direct_with_low_integrity(config, launch_program, &containment, &cmd_args);
    }

    let mut child =
        spawn_windows_child_with_current_token(config, launch_program, &containment, &cmd_args)?;
    loop {
        if let Some(exit_code) = child.poll_exit_code()? {
            return Ok(exit_code);
        }
        std::thread::sleep(WINDOWS_SUPERVISOR_POLL_INTERVAL);
    }
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

    let mut runtime = WindowsSupervisorRuntime::initialize(supervisor)?;
    tracing::debug!(
        "Windows supervised approval backend: {}",
        supervisor.approval_backend.backend_name()
    );
    let unsupported = supervisor.support.unsupported_feature_labels();
    let unsupported_details = supervisor.support.unsupported_feature_descriptions();
    let supported = supervisor.support.supported_feature_labels();
    if !unsupported.is_empty() {
        return Err(NonoError::UnsupportedPlatform(format!(
            "Windows supervised execution initialized the control channel \
             (session: {}, transport: {}), but these supervised features are not available yet: {}. \
             Details: {}. Supported Windows supervised features currently: {}.",
            supervisor.session_id,
            runtime.transport_name(),
            unsupported.join(", "),
            unsupported_details.join(" | "),
            if supported.is_empty() {
                "none".to_string()
            } else {
                supported.join(", ")
            }
        )));
    }

    let prepared = prepare_live_windows_launch(config)?;
    let launch_program = prepared.launch_program.as_path();

    let containment = create_process_containment()?;
    runtime.state = WindowsSupervisorLifecycleState::LaunchingChild;
    tracing::debug!(
        "Windows supervised execution starting event loop (session: {}, transport: {}, features: {})",
        supervisor.session_id,
        runtime.transport_name(),
        if supervisor.requested_features.is_empty() {
            "none".to_string()
        } else {
            supervisor.requested_features.join(", ")
        }
    );

    let mut child = if should_use_low_integrity_windows_launch(config.caps) {
        spawn_supervised_with_low_integrity(config, launch_program, &containment)
    } else {
        spawn_supervised_with_standard_token(config, launch_program, &containment)
    }
    .map_err(|err| runtime.startup_failure(err.to_string()))?;

    let exit_code = runtime
        .run_child_event_loop(&mut child)
        .map_err(|err| runtime.command_failure(err.to_string()))?;

    tracing::debug!(
        "Windows supervised execution finished cleanly (session: {}, transport: {}, exit_code: {})",
        supervisor.session_id,
        runtime.transport_name(),
        exit_code
    );
    Ok(exit_code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    struct EnvVarRestoreGuard {
        saved: Vec<(String, Option<std::ffi::OsString>)>,
    }

    impl EnvVarRestoreGuard {
        fn capture(keys: &[&str]) -> Self {
            Self {
                saved: keys
                    .iter()
                    .map(|key| ((*key).to_string(), std::env::var_os(key)))
                    .collect(),
            }
        }
    }

    impl Drop for EnvVarRestoreGuard {
        fn drop(&mut self) {
            for (key, value) in self.saved.drain(..) {
                match value {
                    Some(value) => std::env::set_var(&key, value),
                    None => std::env::remove_var(&key),
                }
            }
        }
    }

    struct TestGrantBackend;
    struct TestDenyBackend;

    impl ApprovalBackend for TestGrantBackend {
        fn request_capability(
            &self,
            _request: &nono::CapabilityRequest,
        ) -> Result<nono::ApprovalDecision> {
            Ok(nono::ApprovalDecision::Granted)
        }

        fn backend_name(&self) -> &str {
            "test-grant"
        }
    }

    impl ApprovalBackend for TestDenyBackend {
        fn request_capability(
            &self,
            _request: &nono::CapabilityRequest,
        ) -> Result<nono::ApprovalDecision> {
            Ok(nono::ApprovalDecision::Denied {
                reason: "test deny".to_string(),
            })
        }

        fn backend_name(&self) -> &str {
            "test-deny"
        }
    }

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
            requested_features: vec!["rollback snapshots", "proxy filtering"],
            support: Sandbox::windows_supervisor_support(nono::WindowsSupervisorContext {
                rollback_snapshots: true,
                proxy_filtering: true,
                runtime_capability_expansion: false,
                runtime_trust_interception: false,
            }),
            approval_backend: &TestDenyBackend,
        };

        let err = execute_supervised(&config, Some(&supervisor), None)
            .expect_err("unsupported supervised features should fail clearly");
        let message = err.to_string();
        assert!(message.contains("initialized the control channel"));
        assert!(message.contains("transport:"));
        assert!(message.contains("rollback snapshots"));
        assert!(message.contains("not available yet"));
        assert!(message.contains("proxy filtering"));
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
            support: Sandbox::windows_supervisor_support(nono::WindowsSupervisorContext {
                rollback_snapshots: true,
                proxy_filtering: false,
                runtime_capability_expansion: false,
                runtime_trust_interception: false,
            }),
            approval_backend: &TestDenyBackend,
        };

        let exit_code =
            execute_supervised(&config, Some(&supervisor), None).expect("rollback should run");
        assert_eq!(exit_code, 0);
    }

    #[test]
    fn test_execute_supervised_reports_actionable_launch_failure() {
        let command = vec!["missing-supervised-binary".to_string()];
        let resolved_program = PathBuf::from(r"C:\definitely-missing\nono-test-missing.exe");
        let current_dir = std::env::current_dir().expect("cwd");
        let config = ExecConfig {
            command: &command,
            resolved_program: &resolved_program,
            caps: &CapabilitySet::new(),
            env_vars: Vec::new(),
            cap_file: None,
            current_dir: &current_dir,
        };
        let supervisor = SupervisorConfig {
            session_id: "launch-failure-session",
            requested_features: vec!["rollback snapshots"],
            support: Sandbox::windows_supervisor_support(nono::WindowsSupervisorContext {
                rollback_snapshots: true,
                proxy_filtering: false,
                runtime_capability_expansion: false,
                runtime_trust_interception: false,
            }),
            approval_backend: &TestDenyBackend,
        };

        let err = execute_supervised(&config, Some(&supervisor), None)
            .expect_err("missing binary should fail clearly");
        let message = err.to_string();
        assert!(message.contains("launch-failure-session"));
        assert!(
            message.contains("transport:")
                || message.contains("windows-supervisor-")
                || message.contains("Failed to spawn")
                || message.contains("The system cannot find the file specified")
        );
        assert!(message.contains("failed during"));
    }

    #[test]
    fn test_handle_windows_supervisor_message_grants_brokered_handle_and_audits() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("allowed.txt");
        std::fs::write(&path, b"hello windows broker").expect("write file");
        let (mut parent, mut child) =
            nono::SupervisorSocket::pair().expect("supervisor socket pair");
        let mut seen_request_ids = HashSet::new();
        let mut audit_log = Vec::new();

        let request = nono::CapabilityRequest {
            request_id: "req-1".to_string(),
            path: path.clone(),
            access: nono::AccessMode::Read,
            reason: Some("read test file".to_string()),
            child_pid: std::process::id(),
            session_id: "win-803".to_string(),
        };
        child
            .send_message(&nono::supervisor::SupervisorMessage::Request(request))
            .expect("send request");
        let msg = parent.recv_message().expect("recv request");

        handle_windows_supervisor_message(
            &mut parent,
            msg,
            &TestGrantBackend,
            nono::BrokerTargetProcess::current(),
            &mut seen_request_ids,
            &mut audit_log,
        )
        .expect("handle request");

        let response = child.recv_response().expect("recv response");
        let raw_handle = match response {
            nono::supervisor::SupervisorResponse::Decision {
                request_id,
                decision,
                grant,
            } => {
                assert_eq!(request_id, "req-1");
                assert!(decision.is_granted());
                let grant = grant.expect("grant metadata");
                assert_eq!(
                    grant.transfer,
                    nono::ResourceTransferKind::DuplicatedWindowsHandle
                );
                grant.raw_handle.expect("raw handle")
            }
            other => panic!("unexpected response: {other:?}"),
        };

        let mut file = unsafe {
            // SAFETY: The raw handle was duplicated into the current process by
            // the broker helper above, and this test takes ownership exactly once.
            <std::fs::File as std::os::windows::io::FromRawHandle>::from_raw_handle(
                raw_handle as usize as *mut std::ffi::c_void,
            )
        };
        let mut text = String::new();
        file.read_to_string(&mut text)
            .expect("read duplicated file");
        assert_eq!(text, "hello windows broker");
        assert_eq!(audit_log.len(), 1);
        assert_eq!(audit_log[0].backend, "test-grant");
        assert!(audit_log[0].decision.is_granted());
    }

    #[test]
    fn test_handle_windows_supervisor_message_denies_and_audits() {
        let (mut parent, mut child) =
            nono::SupervisorSocket::pair().expect("supervisor socket pair");
        let mut seen_request_ids = HashSet::new();
        let mut audit_log = Vec::new();

        child
            .send_message(&nono::supervisor::SupervisorMessage::Request(
                nono::CapabilityRequest {
                    request_id: "req-deny".to_string(),
                    path: PathBuf::from(r"C:\forbidden.txt"),
                    access: nono::AccessMode::Read,
                    reason: None,
                    child_pid: 7,
                    session_id: "win-803-deny".to_string(),
                },
            ))
            .expect("send request");
        let msg = parent.recv_message().expect("recv request");

        handle_windows_supervisor_message(
            &mut parent,
            msg,
            &TestDenyBackend,
            nono::BrokerTargetProcess::current(),
            &mut seen_request_ids,
            &mut audit_log,
        )
        .expect("handle denied request");

        match child.recv_response().expect("recv response") {
            nono::supervisor::SupervisorResponse::Decision {
                decision, grant, ..
            } => {
                assert!(decision.is_denied());
                assert!(grant.is_none());
            }
            other => panic!("unexpected response: {other:?}"),
        }
        assert_eq!(audit_log.len(), 1);
        assert_eq!(audit_log[0].backend, "test-deny");
        assert!(audit_log[0].decision.is_denied());
    }

    #[test]
    fn test_handle_windows_supervisor_message_rejects_duplicate_request_ids() {
        let (mut parent, mut child) =
            nono::SupervisorSocket::pair().expect("supervisor socket pair");
        let mut seen_request_ids = HashSet::new();
        let mut audit_log = Vec::new();
        seen_request_ids.insert("req-dup".to_string());

        child
            .send_message(&nono::supervisor::SupervisorMessage::Request(
                nono::CapabilityRequest {
                    request_id: "req-dup".to_string(),
                    path: PathBuf::from(r"C:\duplicate.txt"),
                    access: nono::AccessMode::Read,
                    reason: None,
                    child_pid: 7,
                    session_id: "win-1101-dup".to_string(),
                },
            ))
            .expect("send request");
        let msg = parent.recv_message().expect("recv request");

        handle_windows_supervisor_message(
            &mut parent,
            msg,
            &TestGrantBackend,
            nono::BrokerTargetProcess::current(),
            &mut seen_request_ids,
            &mut audit_log,
        )
        .expect("handle duplicate request");

        match child.recv_response().expect("recv response") {
            nono::supervisor::SupervisorResponse::Decision {
                decision, grant, ..
            } => {
                assert!(decision.is_denied());
                assert!(grant.is_none());
                match decision {
                    nono::ApprovalDecision::Denied { reason } => {
                        assert!(reason.contains("Duplicate request_id"));
                    }
                    other => panic!("unexpected decision: {other:?}"),
                }
            }
            other => panic!("unexpected response: {other:?}"),
        }
        assert_eq!(audit_log.len(), 1);
        assert!(audit_log[0].decision.is_denied());
    }

    #[test]
    fn test_handle_windows_supervisor_message_reports_open_url_limitation() {
        let (mut parent, mut child) =
            nono::SupervisorSocket::pair().expect("supervisor socket pair");
        let mut seen_request_ids = HashSet::new();
        let mut audit_log = Vec::new();

        child
            .send_message(&nono::supervisor::SupervisorMessage::OpenUrl(
                nono::supervisor::UrlOpenRequest {
                    request_id: "req-open-url".to_string(),
                    url: "https://example.com".to_string(),
                    child_pid: 7,
                    session_id: "win-1101-open-url".to_string(),
                },
            ))
            .expect("send request");
        let msg = parent.recv_message().expect("recv request");

        handle_windows_supervisor_message(
            &mut parent,
            msg,
            &TestGrantBackend,
            nono::BrokerTargetProcess::current(),
            &mut seen_request_ids,
            &mut audit_log,
        )
        .expect("handle open url request");

        match child.recv_response().expect("recv response") {
            nono::supervisor::SupervisorResponse::UrlOpened {
                success,
                error,
                request_id,
            } => {
                assert_eq!(request_id, "req-open-url");
                assert!(!success);
                let error = error.expect("error");
                assert!(error.contains("delegated browser-open flows"));
                assert!(error.contains("attached supervisor control channel"));
            }
            other => panic!("unexpected response: {other:?}"),
        }
        assert!(audit_log.is_empty());
    }

    #[test]
    fn test_windows_supervisor_runtime_shutdown_on_drop() {
        let supervisor = SupervisorConfig {
            session_id: "drop-session",
            requested_features: vec!["rollback snapshots"],
            support: Sandbox::windows_supervisor_support(nono::WindowsSupervisorContext {
                rollback_snapshots: true,
                proxy_filtering: false,
                runtime_capability_expansion: false,
                runtime_trust_interception: false,
            }),
            approval_backend: &TestDenyBackend,
        };

        let runtime = WindowsSupervisorRuntime::initialize(&supervisor).expect("runtime");
        let transport = runtime.transport_name().to_string();
        drop(runtime);
        assert!(!transport.is_empty());
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
    fn test_prepare_runtime_hardened_args_does_not_duplicate_existing_cmd_disable_autorun() {
        let args = vec!["/d".to_string(), "/c".to_string(), "echo".to_string()];
        let hardened =
            prepare_runtime_hardened_args(Path::new("C:\\Windows\\System32\\cmd.exe"), &args);

        assert_eq!(hardened, args);
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
    fn test_prepare_runtime_hardened_args_does_not_duplicate_existing_powershell_safety_flags() {
        let args = vec![
            "-NoProfile".to_string(),
            "-NonInteractive".to_string(),
            "-NoLogo".to_string(),
            "-Command".to_string(),
            "Get-ChildItem".to_string(),
        ];
        let hardened = prepare_runtime_hardened_args(
            Path::new("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            &args,
        );

        assert_eq!(hardened, args);
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
    fn test_build_child_env_filters_dangerous_host_vars_and_keeps_explicit_overrides() {
        let _guard = crate::config::test_env_lock()
            .lock()
            .expect("env lock");
        let _restore = EnvVarRestoreGuard::capture(&[
            "LD_PRELOAD",
            "PATH",
            "HOME",
            "SAFE_KEEP",
            "EXPLICIT_ONLY",
        ]);

        std::env::set_var("LD_PRELOAD", "dangerous-host-value");
        std::env::set_var("PATH", r"C:\Windows\System32");
        std::env::set_var("HOME", r"C:\Users\Host");
        std::env::set_var("SAFE_KEEP", "host-safe");
        std::env::remove_var("EXPLICIT_ONLY");

        let cap_file = PathBuf::from(r"C:\temp\nono-cap-state.json");
        let command = vec!["cmd".to_string(), "/c".to_string(), "echo".to_string()];
        let current_dir = PathBuf::from(r"C:\workspace");
        let config = ExecConfig {
            command: &command,
            resolved_program: Path::new(r"C:\Windows\System32\cmd.exe"),
            caps: &CapabilitySet::new(),
            env_vars: vec![
                ("PATH", r"C:\sandbox\bin"),
                ("EXPLICIT_ONLY", "from-explicit"),
                ("HOME", r"C:\sandbox\home"),
            ],
            cap_file: Some(&cap_file),
            current_dir: &current_dir,
        };

        let env_pairs = build_child_env(&config);

        assert!(
            !env_pairs.iter().any(|(key, _)| key == "LD_PRELOAD"),
            "dangerous host env vars should be filtered out"
        );
        assert!(
            env_pairs
                .iter()
                .any(|(key, value)| key == "SAFE_KEEP" && value == "host-safe"),
            "safe host env vars should be preserved"
        );
        assert!(
            env_pairs
                .iter()
                .any(|(key, value)| key == "PATH" && value == r"C:\sandbox\bin"),
            "explicit PATH should be appended for the child"
        );
        assert!(
            env_pairs
                .iter()
                .any(|(key, value)| key == "HOME" && value == r"C:\sandbox\home"),
            "explicit HOME should be appended for the child"
        );
        assert!(
            env_pairs
                .iter()
                .any(|(key, value)| key == "EXPLICIT_ONLY" && value == "from-explicit"),
            "explicit-only env vars should be injected"
        );
        assert!(
            env_pairs.iter().any(|(key, value)| {
                key == "NONO_CAP_FILE" && value == r"C:\temp\nono-cap-state.json"
            }),
            "cap file should always be exposed to the child when configured"
        );
    }

    #[test]
    fn test_build_child_env_skips_host_value_when_explicit_override_matches_case_insensitively() {
        let _guard = crate::config::test_env_lock()
            .lock()
            .expect("env lock");
        let _restore = EnvVarRestoreGuard::capture(&["Path"]);

        std::env::set_var("Path", r"C:\host\bin");

        let command = vec!["cmd".to_string(), "/c".to_string(), "echo".to_string()];
        let current_dir = PathBuf::from(r"C:\workspace");
        let config = ExecConfig {
            command: &command,
            resolved_program: Path::new(r"C:\Windows\System32\cmd.exe"),
            caps: &CapabilitySet::new(),
            env_vars: vec![("PATH", r"C:\sandbox\bin")],
            cap_file: None,
            current_dir: &current_dir,
        };

        let env_pairs = build_child_env(&config);

        assert!(
            !env_pairs
                .iter()
                .any(|(key, value)| key == "Path" && value == r"C:\host\bin"),
            "host value should be skipped when an explicit override is present"
        );
        assert!(
            env_pairs
                .iter()
                .any(|(key, value)| key == "PATH" && value == r"C:\sandbox\bin"),
            "explicit override should be present in the child env"
        );
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
    fn test_unique_windows_firewall_rule_suffix_is_hex() {
        let suffix = unique_windows_firewall_rule_suffix();
        assert_eq!(suffix.len(), 32);
        assert!(suffix.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn test_unique_windows_firewall_rule_suffix_is_unpredictable_across_calls() {
        let first = unique_windows_firewall_rule_suffix();
        let second = unique_windows_firewall_rule_suffix();
        assert_ne!(first, second);
    }

    #[test]
    fn test_prepare_network_enforcement_routes_blocked_port_policy_to_wfp_backend() {
        let mut caps = CapabilitySet::new().set_network_mode(nono::NetworkMode::Blocked);
        caps.add_tcp_connect_port(443);
        let policy = Sandbox::windows_network_policy(&caps);
        let backend = select_network_backend(&policy)
            .expect("blocked port policy should select a backend")
            .expect("blocked port policy should use a backend");
        assert_eq!(backend.label(), "windows-filtering-platform");
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
    fn test_select_network_backend_routes_supported_blocked_mode_to_wfp() {
        let policy = Sandbox::windows_network_policy(
            &CapabilitySet::new().set_network_mode(nono::NetworkMode::Blocked),
        );

        let backend = select_network_backend(&policy)
            .expect("supported blocked policy should select a backend")
            .expect("supported blocked policy should use a backend");
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
            true,
            WindowsServiceState::Running,
            WindowsServiceState::Missing,
            WindowsServiceState::Running,
        );
        assert_eq!(status, WfpProbeStatus::BackendServiceMissing);
    }

    #[test]
    fn test_build_wfp_probe_status_reports_missing_driver_binary() {
        let status = build_wfp_probe_status(
            true,
            false,
            WindowsServiceState::Running,
            WindowsServiceState::Running,
            WindowsServiceState::Running,
        );
        assert_eq!(status, WfpProbeStatus::BackendDriverBinaryMissing);
    }

    #[test]
    fn test_build_wfp_probe_status_reports_driver_not_registered() {
        let status = build_wfp_probe_status(
            true,
            true,
            WindowsServiceState::Running,
            WindowsServiceState::Running,
            WindowsServiceState::Missing,
        );
        assert_eq!(status, WfpProbeStatus::BackendDriverMissing);
    }

    #[test]
    fn test_describe_wfp_runtime_activation_failure_reports_platform_service_stopped() {
        let policy = Sandbox::windows_network_policy(&CapabilitySet::new().set_network_mode(
            nono::NetworkMode::ProxyOnly {
                port: 8080,
                bind_ports: vec![8080],
            },
        ));
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: PathBuf::from(r"C:\tools\nono-wfp-service.exe"),
            backend_driver_binary_path: PathBuf::from(r"C:\tools\nono-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };
        let message = describe_wfp_runtime_activation_failure(
            &policy,
            &config,
            WfpProbeStatus::PlatformServiceStopped,
        );
        assert!(message.contains("Base Filtering Engine service `BFE` is not running"));
        assert!(message.contains("preferred backend: windows-filtering-platform"));
    }

    #[test]
    fn test_describe_wfp_runtime_activation_failure_reports_missing_binary() {
        let policy = Sandbox::windows_network_policy(
            &CapabilitySet::new().set_network_mode(nono::NetworkMode::Blocked),
        );
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: PathBuf::from(r"C:\missing\nono-wfp-service.exe"),
            backend_driver_binary_path: PathBuf::from(r"C:\tools\nono-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };
        let message = describe_wfp_runtime_activation_failure(
            &policy,
            &config,
            WfpProbeStatus::BackendBinaryMissing,
        );
        assert!(message.contains("WFP service binary `C:\\missing\\nono-wfp-service.exe` is missing from this build output"));
        assert!(message.contains("preferred backend: windows-filtering-platform"));
    }

    #[test]
    fn test_describe_wfp_runtime_activation_failure_reports_missing_driver_binary() {
        let policy = Sandbox::windows_network_policy(
            &CapabilitySet::new().set_network_mode(nono::NetworkMode::Blocked),
        );
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: PathBuf::from(r"C:\tools\nono-wfp-service.exe"),
            backend_driver_binary_path: PathBuf::from(r"C:\missing\nono-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };
        let message = describe_wfp_runtime_activation_failure(
            &policy,
            &config,
            WfpProbeStatus::BackendDriverBinaryMissing,
        );
        assert!(message.contains("WFP driver binary `C:\\missing\\nono-wfp-driver.sys` is missing from this build output"));
        assert!(message.contains("preferred backend: windows-filtering-platform"));
    }

    #[test]
    fn test_describe_wfp_probe_status_for_setup_reports_missing_binary() {
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: PathBuf::from(r"C:\missing\nono-wfp-service.exe"),
            backend_driver_binary_path: PathBuf::from(r"C:\missing\nono-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };
        let message =
            describe_wfp_probe_status_for_setup(&config, WfpProbeStatus::BackendBinaryMissing);
        assert!(message.contains("Expected WFP backend service binary is missing"));
        assert!(message.contains("nono-wfp-service"));
        assert!(message.contains("nono-wfp-driver"));
        assert!(message.contains("--service-mode"));
    }

    #[test]
    fn test_probe_wfp_backend_status_with_config_reports_missing_binary_before_service_checks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: dir.path().join("missing-wfp-service.exe"),
            backend_driver_binary_path: dir.path().join("missing-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };

        let status =
            probe_wfp_backend_status_with_config(&config).expect("probe status should resolve");
        assert_eq!(status, WfpProbeStatus::BackendBinaryMissing);
    }

    #[test]
    fn test_describe_wfp_probe_status_for_setup_reports_missing_service_contract() {
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: PathBuf::from(r"C:\tools\nono-wfp-service.exe"),
            backend_driver_binary_path: PathBuf::from(r"C:\tools\nono-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };
        let message =
            describe_wfp_probe_status_for_setup(&config, WfpProbeStatus::BackendServiceMissing);
        assert!(message.contains("Register it to launch nono-wfp-service"));
        assert!(message.contains("--service-mode"));
    }

    #[test]
    fn test_describe_wfp_probe_status_for_setup_reports_missing_driver_binary() {
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: PathBuf::from(r"C:\tools\nono-wfp-service.exe"),
            backend_driver_binary_path: PathBuf::from(r"C:\tools\nono-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };
        let message = describe_wfp_probe_status_for_setup(
            &config,
            WfpProbeStatus::BackendDriverBinaryMissing,
        );
        assert!(message.contains(r"C:\tools\nono-wfp-driver.sys"));
        assert!(message.contains("Expected driver registration name"));
    }

    #[test]
    fn test_describe_wfp_service_status_for_setup_reports_missing_service() {
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: PathBuf::from(r"C:\tools\nono-wfp-service.exe"),
            backend_driver_binary_path: PathBuf::from(r"C:\tools\nono-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };
        let (label, details) =
            describe_wfp_service_status_for_setup(&config, WfpProbeStatus::BackendServiceMissing);
        assert_eq!(label, "not registered");
        assert!(details.contains("Register it to launch"));
    }

    #[test]
    fn test_describe_wfp_driver_status_for_setup_reports_blocked_by_service() {
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: PathBuf::from(r"C:\tools\nono-wfp-service.exe"),
            backend_driver_binary_path: PathBuf::from(r"C:\tools\nono-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };
        let (label, details) =
            describe_wfp_driver_status_for_setup(&config, WfpProbeStatus::BackendServiceMissing);
        assert_eq!(label, "blocked by service");
        assert!(details.contains("blocked until the service"));
    }

    #[test]
    fn test_describe_wfp_driver_status_for_setup_reports_not_registered() {
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: PathBuf::from(r"C:\tools\nono-wfp-service.exe"),
            backend_driver_binary_path: PathBuf::from(r"C:\tools\nono-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };
        let (label, details) =
            describe_wfp_driver_status_for_setup(&config, WfpProbeStatus::BackendDriverMissing);
        assert_eq!(label, "not registered");
        assert!(details.contains("nono-wfp-driver"));
    }

    #[test]
    fn test_describe_wfp_next_action_for_setup_reports_install_service() {
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: PathBuf::from(r"C:\tools\nono-wfp-service.exe"),
            backend_driver_binary_path: PathBuf::from(r"C:\tools\nono-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };
        let action =
            describe_wfp_next_action_for_setup(&config, WfpProbeStatus::BackendServiceMissing);
        assert_eq!(
            action.as_deref(),
            Some("Next action: run `nono setup --install-wfp-service`.")
        );
    }

    #[test]
    fn test_describe_wfp_next_action_for_setup_reports_start_driver() {
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: PathBuf::from(r"C:\tools\nono-wfp-service.exe"),
            backend_driver_binary_path: PathBuf::from(r"C:\tools\nono-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };
        let action =
            describe_wfp_next_action_for_setup(&config, WfpProbeStatus::BackendDriverStopped);
        assert_eq!(
            action.as_deref(),
            Some("Next action: run `nono setup --start-wfp-driver`.")
        );
    }

    #[test]
    fn test_build_wfp_runtime_activation_request_for_proxy_mode() {
        let policy = Sandbox::windows_network_policy(&CapabilitySet::new().set_network_mode(
            nono::NetworkMode::ProxyOnly {
                port: 8080,
                bind_ports: vec![8080, 9090],
            },
        ));
        let request = build_wfp_runtime_activation_request(&policy);
        assert_eq!(request.protocol_version, WFP_RUNTIME_PROTOCOL_VERSION);
        assert_eq!(request.request_kind, "activate_proxy_mode");
        assert_eq!(request.network_mode, "proxy-only");
        assert_eq!(request.preferred_backend, "windows-filtering-platform");
        assert_eq!(request.active_backend, "windows-filtering-platform");
        assert_eq!(request.tcp_bind_ports, vec![8080, 9090]);
        assert_eq!(request.localhost_ports, vec![8080]);
        assert!(request.runtime_target.contains("localhost:8080"));
    }

    #[test]
    fn test_build_wfp_runtime_cleanup_request_carries_target_and_rules() {
        let policy = Sandbox::windows_network_policy(
            &CapabilitySet::new().set_network_mode(nono::NetworkMode::Blocked),
        );
        let request = build_wfp_runtime_cleanup_request(
            &policy,
            Path::new(r"C:\tools\target.exe"),
            "nono-in",
            "nono-out",
        );
        assert_eq!(request.request_kind, "deactivate_policy_mode");
        assert_eq!(
            request.target_program_path.as_deref(),
            Some(r"C:\tools\target.exe")
        );
        assert_eq!(request.inbound_rule_name.as_deref(), Some("nono-in"));
        assert_eq!(request.outbound_rule_name.as_deref(), Some("nono-out"));
    }

    #[test]
    fn test_parse_wfp_runtime_probe_status_reports_not_implemented() {
        let output = WfpRuntimeProbeOutput {
            status_code: Some(4),
            response: WfpRuntimeActivationResponse {
                protocol_version: WFP_RUNTIME_PROTOCOL_VERSION,
                status: "not-implemented".to_string(),
                details: "placeholder".to_string(),
            },
            stderr: "placeholder".to_string(),
        };
        let status = parse_wfp_runtime_probe_status(&output).expect("probe output should parse");
        assert_eq!(status, WfpRuntimeActivationProbeStatus::NotImplemented);
    }

    #[test]
    fn test_parse_wfp_runtime_probe_status_reports_accepted_but_not_enforced() {
        let output = WfpRuntimeProbeOutput {
            status_code: Some(4),
            response: WfpRuntimeActivationResponse {
                protocol_version: WFP_RUNTIME_PROTOCOL_VERSION,
                status: "accepted-but-not-enforced".to_string(),
                details: "placeholder".to_string(),
            },
            stderr: "placeholder".to_string(),
        };
        let status = parse_wfp_runtime_probe_status(&output).expect("probe output should parse");
        assert_eq!(
            status,
            WfpRuntimeActivationProbeStatus::AcceptedButNotEnforced
        );
    }

    #[test]
    fn test_parse_wfp_runtime_probe_status_reports_filtering_probe_succeeded() {
        let output = WfpRuntimeProbeOutput {
            status_code: Some(4),
            response: WfpRuntimeActivationResponse {
                protocol_version: WFP_RUNTIME_PROTOCOL_VERSION,
                status: "filtering-probe-succeeded".to_string(),
                details: "probe ok".to_string(),
            },
            stderr: "placeholder".to_string(),
        };
        let status = parse_wfp_runtime_probe_status(&output).expect("probe output should parse");
        assert_eq!(
            status,
            WfpRuntimeActivationProbeStatus::FilteringProbeSucceeded
        );
    }

    #[test]
    fn test_parse_wfp_runtime_probe_status_rejects_invalid_request() {
        let output = WfpRuntimeProbeOutput {
            status_code: Some(2),
            response: WfpRuntimeActivationResponse {
                protocol_version: WFP_RUNTIME_PROTOCOL_VERSION,
                status: "invalid-request".to_string(),
                details: "unsupported WFP runtime activation request kind `activate_proxy_mode`"
                    .to_string(),
            },
            stderr: "placeholder".to_string(),
        };
        let err = parse_wfp_runtime_probe_status(&output).expect_err("invalid request should fail");
        assert!(err
            .to_string()
            .contains("service rejected the runtime activation request"));
    }

    #[test]
    fn test_parse_wfp_runtime_probe_status_reports_missing_prerequisites() {
        let output = WfpRuntimeProbeOutput {
            status_code: Some(3),
            response: WfpRuntimeActivationResponse {
                protocol_version: WFP_RUNTIME_PROTOCOL_VERSION,
                status: "prerequisites-missing".to_string(),
                details: "driver artifact missing".to_string(),
            },
            stderr: "placeholder".to_string(),
        };
        let err = parse_wfp_runtime_probe_status(&output)
            .expect_err("missing prerequisites should fail closed");
        assert!(err
            .to_string()
            .contains("activation prerequisites are missing"));
    }

    #[test]
    fn test_parse_wfp_runtime_probe_status_reports_filtering_probe_failed() {
        let output = WfpRuntimeProbeOutput {
            status_code: Some(4),
            response: WfpRuntimeActivationResponse {
                protocol_version: WFP_RUNTIME_PROTOCOL_VERSION,
                status: "filtering-probe-failed".to_string(),
                details: "access denied".to_string(),
            },
            stderr: "placeholder".to_string(),
        };
        let err =
            parse_wfp_runtime_probe_status(&output).expect_err("failed probe should fail closed");
        assert!(err
            .to_string()
            .contains("could not install its network-policy filtering probe"));
    }

    #[test]
    fn test_cleanup_wfp_service_managed_enforcement_with_runner_sends_deactivate_request() {
        let policy = Sandbox::windows_network_policy(
            &CapabilitySet::new().set_network_mode(nono::NetworkMode::Blocked),
        );
        let probe_config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: PathBuf::from(r"C:\tools\nono-wfp-service.exe"),
            backend_driver_binary_path: PathBuf::from(r"C:\tools\nono-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };
        let result = cleanup_wfp_service_managed_enforcement_with_runner(
            &policy,
            &probe_config,
            Path::new(r"C:\tools\target.exe"),
            "nono-in",
            "nono-out",
            |_cfg, request| {
                assert_eq!(request.request_kind, "deactivate_policy_mode");
                assert_eq!(
                    request.target_program_path.as_deref(),
                    Some(r"C:\tools\target.exe")
                );
                assert_eq!(request.inbound_rule_name.as_deref(), Some("nono-in"));
                assert_eq!(request.outbound_rule_name.as_deref(), Some("nono-out"));
                Ok(WfpRuntimeProbeOutput {
                    status_code: Some(0),
                    response: WfpRuntimeActivationResponse {
                        protocol_version: WFP_RUNTIME_PROTOCOL_VERSION,
                        status: "cleanup-succeeded".to_string(),
                        details: "ok".to_string(),
                    },
                    stderr: String::new(),
                })
            },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_describe_wfp_runtime_probe_failure_includes_probe_command() {
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: PathBuf::from(r"C:\tools\nono-wfp-service.exe"),
            backend_driver_binary_path: PathBuf::from(r"C:\tools\nono-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };
        let output = WfpRuntimeProbeOutput {
            status_code: Some(4),
            response: WfpRuntimeActivationResponse {
                protocol_version: WFP_RUNTIME_PROTOCOL_VERSION,
                status: "not-implemented".to_string(),
                details: "placeholder".to_string(),
            },
            stderr: "placeholder".to_string(),
        };
        let message = describe_wfp_runtime_probe_failure(&config, &output);
        assert!(message.contains("--probe-runtime-activation"));
        assert!(message.contains("not-implemented"));
    }

    #[test]
    fn test_probe_wfp_backend_status_with_config_reports_missing_driver_binary_before_driver_query()
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let service_binary = dir.path().join("nono-wfp-service.exe");
        std::fs::write(&service_binary, b"stub").expect("write stub service binary");
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: service_binary,
            backend_driver_binary_path: dir.path().join("missing-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };

        let status =
            probe_wfp_backend_status_with_config(&config).expect("probe status should resolve");
        assert_eq!(status, WfpProbeStatus::BackendServiceMissing);
    }

    #[test]
    fn test_probe_wfp_backend_status_with_config_can_force_ready_for_live_tests() {
        let dir = tempfile::tempdir().expect("tempdir");
        let service_binary = dir.path().join("nono-wfp-service.exe");
        let driver_binary = dir.path().join("nono-wfp-driver.sys");
        std::fs::write(&service_binary, b"stub").expect("write stub service binary");
        std::fs::write(&driver_binary, b"stub").expect("write stub driver binary");
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: service_binary,
            backend_driver_binary_path: driver_binary,
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };

        set_windows_wfp_test_force_ready(true);
        let status = probe_wfp_backend_status_with_config(&config)
            .expect("forced ready probe status should resolve");
        set_windows_wfp_test_force_ready(false);

        assert_eq!(status, WfpProbeStatus::Ready);
    }

    #[test]
    fn test_probe_wfp_backend_status_with_config_ignores_legacy_force_ready_env_var() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: temp.path().join("missing-service.exe"),
            backend_driver_binary_path: temp.path().join("missing-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };

        let prior = std::env::var_os("NONO_TEST_ONLY_WFP_FORCE_READY");
        std::env::set_var("NONO_TEST_ONLY_WFP_FORCE_READY", "1");
        let status =
            probe_wfp_backend_status_with_config(&config).expect("probe status should resolve");
        match prior {
            Some(value) => std::env::set_var("NONO_TEST_ONLY_WFP_FORCE_READY", value),
            None => std::env::remove_var("NONO_TEST_ONLY_WFP_FORCE_READY"),
        }

        assert_eq!(status, WfpProbeStatus::BackendBinaryMissing);
    }

    #[test]
    fn test_build_wfp_service_create_args_uses_service_contract() {
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: PathBuf::from(r"C:\tools\nono-wfp-service.exe"),
            backend_driver_binary_path: PathBuf::from(r"C:\tools\nono-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };
        let args = build_wfp_service_create_args(&config);
        let joined = args.join(" ");
        assert!(joined.contains("create nono-wfp-service"));
        assert!(joined.contains(r#""C:\tools\nono-wfp-service.exe" --service-mode"#));
        assert!(joined.contains("start= demand"));
    }

    #[test]
    fn test_build_wfp_driver_create_args_uses_driver_contract() {
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: PathBuf::from(r"C:\tools\nono-wfp-service.exe"),
            backend_driver_binary_path: PathBuf::from(r"C:\tools\nono-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };
        let args = build_wfp_driver_create_args(&config);
        let joined = args.join(" ");
        assert!(joined.contains("create nono-wfp-driver"));
        assert!(joined.contains(r"C:\tools\nono-wfp-driver.sys"));
        assert!(joined.contains("type= kernel"));
    }

    #[test]
    fn test_build_wfp_driver_start_args_uses_driver_name() {
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: PathBuf::from(r"C:\tools\nono-wfp-service.exe"),
            backend_driver_binary_path: PathBuf::from(r"C:\tools\nono-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };
        let args = build_wfp_driver_start_args(&config);
        assert_eq!(
            args,
            vec!["start".to_string(), "nono-wfp-driver".to_string()]
        );
    }

    #[test]
    fn test_build_wfp_service_start_args_uses_service_name() {
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: PathBuf::from(r"C:\tools\nono-wfp-service.exe"),
            backend_driver_binary_path: PathBuf::from(r"C:\tools\nono-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };
        let args = build_wfp_service_start_args(&config);
        assert_eq!(
            args,
            vec!["start".to_string(), "nono-wfp-service".to_string()]
        );
    }

    #[test]
    fn test_install_windows_wfp_service_registers_missing_service() {
        use std::cell::RefCell;

        let dir = tempfile::tempdir().expect("tempdir");
        let binary_path = dir.path().join("nono-wfp-service.exe");
        std::fs::write(&binary_path, b"stub").expect("write stub binary");
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: binary_path,
            backend_driver_binary_path: dir.path().join("nono-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };

        let create_calls = RefCell::new(Vec::<Vec<String>>::new());
        let backend_service_seen = RefCell::new(0usize);
        let report = install_windows_wfp_service_with_runner(
            &config,
            |service| match service {
                WINDOWS_WFP_PLATFORM_SERVICE => Ok("STATE              : 4  RUNNING".to_string()),
                WINDOWS_WFP_BACKEND_SERVICE => {
                    let seen = *backend_service_seen.borrow();
                    *backend_service_seen.borrow_mut() = seen + 1;
                    if seen == 0 {
                        Ok("[SC] EnumQueryServicesStatus:OpenService FAILED 1060".to_string())
                    } else {
                        Ok("STATE              : 1  STOPPED".to_string())
                    }
                }
                other => Err(NonoError::Setup(format!(
                    "unexpected service query in test: {other}"
                ))),
            },
            |args| {
                create_calls.borrow_mut().push(args.to_vec());
                Ok("SUCCESS".to_string())
            },
        )
        .expect("service registration should succeed");

        assert_eq!(report.status_label, "installed");
        assert!(report.details.contains("--service-mode"));
        let calls = create_calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0][0], "create");
        assert_eq!(calls[1][0], "description");
    }

    #[test]
    fn test_install_windows_wfp_service_reports_already_installed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let binary_path = dir.path().join("nono-wfp-service.exe");
        std::fs::write(&binary_path, b"stub").expect("write stub binary");
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: binary_path,
            backend_driver_binary_path: dir.path().join("nono-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };

        let report = install_windows_wfp_service_with_runner(
            &config,
            |service| match service {
                WINDOWS_WFP_PLATFORM_SERVICE => Ok("STATE              : 4  RUNNING".to_string()),
                WINDOWS_WFP_BACKEND_SERVICE => Ok("STATE              : 1  STOPPED".to_string()),
                other => Err(NonoError::Setup(format!(
                    "unexpected service query in test: {other}"
                ))),
            },
            |_args| Err(NonoError::Setup("create should not run".to_string())),
        )
        .expect("existing registration should be accepted");

        assert_eq!(report.status_label, "already installed");
        assert!(report.details.contains("already registered"));
    }

    #[test]
    fn test_install_windows_wfp_service_treats_create_conflict_as_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let binary_path = dir.path().join("nono-wfp-service.exe");
        std::fs::write(&binary_path, b"stub").expect("write stub binary");
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: binary_path,
            backend_driver_binary_path: dir.path().join("nono-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };

        let report = install_windows_wfp_service_with_runner(
            &config,
            |service| match service {
                WINDOWS_WFP_PLATFORM_SERVICE => Ok("STATE              : 4  RUNNING".to_string()),
                WINDOWS_WFP_BACKEND_SERVICE => Ok("STATE              : 1  STOPPED".to_string()),
                other => Err(NonoError::Setup(format!(
                    "unexpected service query in test: {other}"
                ))),
            },
            |_args| {
                Err(NonoError::Setup(
                    "[SC] CreateService FAILED 1073: The specified service already exists."
                        .to_string(),
                ))
            },
        )
        .expect("create conflict should be treated as already installed");

        assert_eq!(report.status_label, "already installed");
    }

    #[test]
    fn test_install_windows_wfp_driver_registers_missing_driver() {
        use std::cell::RefCell;

        let dir = tempfile::tempdir().expect("tempdir");
        let driver_binary = dir.path().join("nono-wfp-driver.sys");
        std::fs::write(&driver_binary, b"stub").expect("write stub driver binary");
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: dir.path().join("nono-wfp-service.exe"),
            backend_driver_binary_path: driver_binary,
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };

        let calls = RefCell::new(Vec::<Vec<String>>::new());
        let backend_driver_seen = RefCell::new(0usize);
        let report = install_windows_wfp_driver_with_runner(
            &config,
            |service| match service {
                WINDOWS_WFP_PLATFORM_SERVICE => Ok("STATE              : 4  RUNNING".to_string()),
                WINDOWS_WFP_BACKEND_DRIVER => {
                    let seen = *backend_driver_seen.borrow();
                    *backend_driver_seen.borrow_mut() = seen + 1;
                    if seen == 0 {
                        Ok("[SC] EnumQueryServicesStatus:OpenService FAILED 1060".to_string())
                    } else {
                        Ok("STATE              : 1  STOPPED".to_string())
                    }
                }
                other => Err(NonoError::Setup(format!(
                    "unexpected service query in test: {other}"
                ))),
            },
            |args| {
                calls.borrow_mut().push(args.to_vec());
                Ok("SUCCESS".to_string())
            },
        )
        .expect("driver registration should succeed");

        assert_eq!(report.status_label, "installed");
        assert!(report.details.contains("nono-wfp-driver"));
        assert!(report
            .details
            .contains("does not ship a working WFP driver"));
        let calls = calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0][0], "create");
        assert_eq!(calls[1][0], "description");
    }

    #[test]
    fn test_install_windows_wfp_driver_reports_already_installed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let driver_binary = dir.path().join("nono-wfp-driver.sys");
        std::fs::write(&driver_binary, b"stub").expect("write stub driver binary");
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: dir.path().join("nono-wfp-service.exe"),
            backend_driver_binary_path: driver_binary,
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };

        let report = install_windows_wfp_driver_with_runner(
            &config,
            |service| match service {
                WINDOWS_WFP_PLATFORM_SERVICE => Ok("STATE              : 4  RUNNING".to_string()),
                WINDOWS_WFP_BACKEND_DRIVER => Ok("STATE              : 1  STOPPED".to_string()),
                other => Err(NonoError::Setup(format!(
                    "unexpected service query in test: {other}"
                ))),
            },
            |_args| Err(NonoError::Setup("create should not run".to_string())),
        )
        .expect("existing driver registration should be accepted");

        assert_eq!(report.status_label, "already installed");
        assert!(report.details.contains("already registered"));
    }

    #[test]
    fn test_start_windows_wfp_driver_reports_missing_registration() {
        let dir = tempfile::tempdir().expect("tempdir");
        let driver_binary = dir.path().join("nono-wfp-driver.sys");
        std::fs::write(&driver_binary, b"stub").expect("write stub driver binary");
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: dir.path().join("nono-wfp-service.exe"),
            backend_driver_binary_path: driver_binary,
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };

        let err = start_windows_wfp_driver_with_runner(
            &config,
            |service| match service {
                WINDOWS_WFP_PLATFORM_SERVICE => Ok("STATE              : 4  RUNNING".to_string()),
                WINDOWS_WFP_BACKEND_DRIVER => {
                    Ok("[SC] EnumQueryServicesStatus:OpenService FAILED 1060".to_string())
                }
                other => Err(NonoError::Setup(format!(
                    "unexpected service query in test: {other}"
                ))),
            },
            |_args| Ok("unused".to_string()),
        )
        .expect_err("missing driver registration should fail");

        assert!(err
            .to_string()
            .contains("Run `nono setup --install-wfp-driver` first"));
    }

    #[test]
    fn test_start_windows_wfp_driver_reports_already_running() {
        let dir = tempfile::tempdir().expect("tempdir");
        let driver_binary = dir.path().join("nono-wfp-driver.sys");
        std::fs::write(&driver_binary, b"stub").expect("write stub driver binary");
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: dir.path().join("nono-wfp-service.exe"),
            backend_driver_binary_path: driver_binary,
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };

        let report = start_windows_wfp_driver_with_runner(
            &config,
            |service| match service {
                WINDOWS_WFP_PLATFORM_SERVICE | WINDOWS_WFP_BACKEND_DRIVER => {
                    Ok("STATE              : 4  RUNNING".to_string())
                }
                other => Err(NonoError::Setup(format!(
                    "unexpected service query in test: {other}"
                ))),
            },
            |_args| Err(NonoError::Setup("start should not run".to_string())),
        )
        .expect("already running driver should be reported cleanly");

        assert_eq!(report.status_label, "already running");
        assert!(report
            .details
            .contains("Network enforcement is still not active"));
    }

    #[test]
    fn test_start_windows_wfp_driver_reports_placeholder_start_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let driver_binary = dir.path().join("nono-wfp-driver.sys");
        std::fs::write(&driver_binary, b"stub").expect("write stub driver binary");
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: dir.path().join("nono-wfp-service.exe"),
            backend_driver_binary_path: driver_binary,
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };

        let err = start_windows_wfp_driver_with_runner(
            &config,
            |service| match service {
                WINDOWS_WFP_PLATFORM_SERVICE => Ok("STATE              : 4  RUNNING".to_string()),
                WINDOWS_WFP_BACKEND_DRIVER => Ok("STATE              : 1  STOPPED".to_string()),
                other => Err(NonoError::Setup(format!(
                    "unexpected service query in test: {other}"
                ))),
            },
            |args| {
                assert_eq!(
                    args,
                    &[String::from("start"), String::from("nono-wfp-driver")]
                );
                Ok("FAILED 577: invalid image hash".to_string())
            },
        )
        .expect_err("placeholder driver start should fail closed");

        let message = err.to_string();
        assert!(message.contains("did not reach RUNNING"));
        assert!(message.contains("placeholder driver still fails closed"));
    }

    #[test]
    fn test_start_windows_wfp_service_reports_missing_registration() {
        let dir = tempfile::tempdir().expect("tempdir");
        let binary_path = dir.path().join("nono-wfp-service.exe");
        std::fs::write(&binary_path, b"stub").expect("write stub binary");
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: binary_path,
            backend_driver_binary_path: dir.path().join("nono-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };

        let err = start_windows_wfp_service_with_runner(
            &config,
            |service| match service {
                WINDOWS_WFP_PLATFORM_SERVICE => Ok("STATE              : 4  RUNNING".to_string()),
                WINDOWS_WFP_BACKEND_SERVICE => {
                    Ok("[SC] EnumQueryServicesStatus:OpenService FAILED 1060".to_string())
                }
                other => Err(NonoError::Setup(format!(
                    "unexpected service query in test: {other}"
                ))),
            },
            |_args| Ok("unused".to_string()),
        )
        .expect_err("missing registration should fail");

        assert!(err
            .to_string()
            .contains("Run `nono setup --install-wfp-service` first"));
    }

    #[test]
    fn test_start_windows_wfp_service_reports_already_running() {
        let dir = tempfile::tempdir().expect("tempdir");
        let binary_path = dir.path().join("nono-wfp-service.exe");
        std::fs::write(&binary_path, b"stub").expect("write stub binary");
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: binary_path,
            backend_driver_binary_path: dir.path().join("nono-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };

        let report = start_windows_wfp_service_with_runner(
            &config,
            |service| match service {
                WINDOWS_WFP_PLATFORM_SERVICE | WINDOWS_WFP_BACKEND_SERVICE => {
                    Ok("STATE              : 4  RUNNING".to_string())
                }
                other => Err(NonoError::Setup(format!(
                    "unexpected service query in test: {other}"
                ))),
            },
            |_args| Err(NonoError::Setup("start should not run".to_string())),
        )
        .expect("already running service should be reported cleanly");

        assert_eq!(report.status_label, "already running");
        assert!(report
            .details
            .contains("Network enforcement is still not active"));
    }

    #[test]
    fn test_start_windows_wfp_service_reports_placeholder_start_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let binary_path = dir.path().join("nono-wfp-service.exe");
        std::fs::write(&binary_path, b"stub").expect("write stub binary");
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: binary_path,
            backend_driver_binary_path: dir.path().join("nono-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };
        let backend_service_seen = std::cell::RefCell::new(0usize);

        let err = start_windows_wfp_service_with_runner(
            &config,
            |service| match service {
                WINDOWS_WFP_PLATFORM_SERVICE => Ok("STATE              : 4  RUNNING".to_string()),
                WINDOWS_WFP_BACKEND_SERVICE => {
                    let seen = *backend_service_seen.borrow();
                    *backend_service_seen.borrow_mut() = seen + 1;
                    let _ = seen;
                    Ok("STATE              : 1  STOPPED".to_string())
                }
                other => Err(NonoError::Setup(format!(
                    "unexpected service query in test: {other}"
                ))),
            },
            |args| {
                assert_eq!(
                    args,
                    &[String::from("start"), String::from("nono-wfp-service")]
                );
                Ok("FAILED 1053: service did not respond".to_string())
            },
        )
        .expect_err("placeholder start should fail closed");

        let message = err.to_string();
        assert!(message.contains("did not reach RUNNING"));
        assert!(message.contains("placeholder service host still fails closed"));
    }

    #[test]
    fn test_wfp_runtime_activation_reports_missing_service_registration() {
        let caps = CapabilitySet::new().set_network_mode(nono::NetworkMode::ProxyOnly {
            port: 8080,
            bind_ports: vec![8080],
        });
        let policy = Sandbox::windows_network_policy(&caps);
        let dir = tempfile::tempdir().expect("tempdir");
        let service_binary = dir.path().join("nono-wfp-service.exe");
        let driver_binary = dir.path().join("nono-wfp-driver.sys");
        std::fs::write(&service_binary, b"stub").expect("write stub service binary");
        std::fs::write(&driver_binary, b"stub").expect("write stub driver binary");
        let probe_config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: service_binary,
            backend_driver_binary_path: driver_binary,
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };
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

        let err = install_wfp_network_backend(&policy, &config, &probe_config)
            .expect_err("missing service registration should fail closed");
        let message = err.to_string();
        assert!(message.contains("Run `nono setup --install-wfp-service` first"));
        assert!(message.contains("preferred backend: windows-filtering-platform"));
        assert!(message.contains("active backend: windows-filtering-platform"));
        assert!(message.contains("fail-closed"));
    }

    #[test]
    fn test_wfp_runtime_activation_reports_stopped_service() {
        let policy = Sandbox::windows_network_policy(
            &CapabilitySet::new().set_network_mode(nono::NetworkMode::Blocked),
        );
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: PathBuf::from(r"C:\tools\nono-wfp-service.exe"),
            backend_driver_binary_path: PathBuf::from(r"C:\tools\nono-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };

        let message = describe_wfp_runtime_activation_failure(
            &policy,
            &config,
            WfpProbeStatus::BackendServiceStopped,
        );
        assert!(message.contains("Run `nono setup --start-wfp-service` first"));
        assert!(message.contains("active backend: windows-filtering-platform"));
        assert!(message.contains("fail-closed"));
    }

    #[test]
    fn test_wfp_runtime_activation_reports_stopped_driver() {
        let policy = Sandbox::windows_network_policy(
            &CapabilitySet::new().set_network_mode(nono::NetworkMode::Blocked),
        );
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: PathBuf::from(r"C:\tools\nono-wfp-service.exe"),
            backend_driver_binary_path: PathBuf::from(r"C:\tools\nono-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };

        let message = describe_wfp_runtime_activation_failure(
            &policy,
            &config,
            WfpProbeStatus::BackendDriverStopped,
        );
        assert!(message.contains("Run `nono setup --start-wfp-driver` first"));
        assert!(message.contains("fail-closed"));
    }

    #[test]
    fn test_wfp_runtime_activation_reports_ready_but_not_enforceable() {
        let policy = Sandbox::windows_network_policy(
            &CapabilitySet::new().set_network_mode(nono::NetworkMode::Blocked),
        );
        let config = WfpProbeConfig {
            platform_service: WINDOWS_WFP_PLATFORM_SERVICE,
            backend_service: WINDOWS_WFP_BACKEND_SERVICE,
            backend_driver: WINDOWS_WFP_BACKEND_DRIVER,
            backend_binary_path: PathBuf::from(r"C:\tools\nono-wfp-service.exe"),
            backend_driver_binary_path: PathBuf::from(r"C:\tools\nono-wfp-driver.sys"),
            backend_service_args: WINDOWS_WFP_BACKEND_SERVICE_ARGS,
        };

        let message =
            describe_wfp_runtime_activation_failure(&policy, &config, WfpProbeStatus::Ready);
        assert!(message.contains("did not install an enforceable network-policy state"));
        assert!(message.contains("fail-closed"));
    }
}
