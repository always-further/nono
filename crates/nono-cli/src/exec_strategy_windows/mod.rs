#![allow(dead_code)]

//! Windows execution strategy placeholder.
//!
//! WIN-101 needs the CLI to compile on Windows without pulling in the Unix
//! supervisor and fork/exec machinery. This file intentionally provides a
//! smaller Windows surface that can be expanded in later stories.

#[path = "../exec_strategy/env_sanitization.rs"]
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

#[derive(Debug)]
struct ProcessContainment {
    job: HANDLE,
}

#[derive(Debug)]
struct OwnedHandle(HANDLE);

mod launch;
mod network;
mod supervisor;

use launch::*;
use network::*;
pub(crate) use network::{
    install_windows_wfp_driver, install_windows_wfp_service, probe_windows_wfp_readiness,
    start_windows_wfp_driver, start_windows_wfp_service,
};
use supervisor::*;

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
        let _guard = crate::config::test_env_lock().lock().expect("env lock");
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
        let _guard = crate::config::test_env_lock().lock().expect("env lock");
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
