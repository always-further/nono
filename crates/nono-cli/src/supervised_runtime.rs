use crate::launch_runtime::{
    ProxyLaunchOptions, RollbackLaunchOptions, SessionLaunchOptions, TrustLaunchOptions,
};
use crate::rollback_runtime::{
    create_audit_state, finalize_supervised_exit, initialize_rollback_state,
    warn_if_rollback_flags_ignored, AuditState, RollbackExitContext,
};
use crate::{
    exec_strategy, output, protected_paths, pty_proxy, session, terminal_approval, trust_intercept,
    DETACHED_SESSION_ID_ENV,
};
use colored::Colorize;
use nono::{CapabilitySet, Result};

struct SessionRuntimeState {
    started: String,
    short_session_id: String,
    session_guard: Option<session::SessionGuard>,
    pty_pair: Option<pty_proxy::PtyPair>,
}

pub(crate) struct SupervisedRuntimeContext<'a> {
    pub(crate) config: &'a exec_strategy::ExecConfig<'a>,
    pub(crate) caps: &'a CapabilitySet,
    pub(crate) command: &'a [String],
    pub(crate) session: &'a SessionLaunchOptions,
    pub(crate) rollback: &'a RollbackLaunchOptions,
    pub(crate) trust: &'a TrustLaunchOptions,
    pub(crate) proxy: &'a ProxyLaunchOptions,
    pub(crate) proxy_handle: Option<&'a nono_proxy::server::ProxyHandle>,
    pub(crate) silent: bool,
}

fn build_supervisor_session_id(audit_state: Option<&AuditState>) -> String {
    audit_state
        .map(|state| state.session_id.clone())
        .unwrap_or_else(|| {
            format!(
                "supervised-{}-{}",
                std::process::id(),
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
            )
        })
}

fn create_trust_interceptor(
    trust: &TrustLaunchOptions,
) -> Option<trust_intercept::TrustInterceptor> {
    if !trust.interception_active {
        return None;
    }

    match trust.policy.clone() {
        Some(policy) => {
            match trust_intercept::TrustInterceptor::new(policy, trust.scan_root.clone()) {
                Ok(interceptor) => Some(interceptor),
                Err(e) => {
                    tracing::warn!("Trust interceptor pattern compilation failed: {e}");
                    eprintln!(
                        "  {}",
                        format!(
                            "WARNING: Runtime instruction file verification disabled \
                         (pattern error: {e})"
                        )
                        .yellow()
                    );
                    None
                }
            }
        }
        None => None,
    }
}

fn create_session_runtime_state(
    command: &[String],
    caps: &CapabilitySet,
    session: &SessionLaunchOptions,
    audit_state: Option<&AuditState>,
) -> Result<SessionRuntimeState> {
    let started = chrono::Local::now().to_rfc3339();
    let short_session_id = std::env::var(DETACHED_SESSION_ID_ENV)
        .ok()
        .filter(|id| !id.is_empty())
        .unwrap_or_else(session::generate_session_id);
    let session_record = session::SessionRecord {
        session_id: short_session_id.clone(),
        name: Some(
            session
                .session_name
                .clone()
                .unwrap_or_else(session::generate_random_name),
        ),
        supervisor_pid: std::process::id(),
        child_pid: 0,
        started: started.clone(),
        started_epoch: session::current_process_start_epoch(),
        status: session::SessionStatus::Running,
        attachment: if session.detached_start {
            session::SessionAttachment::Detached
        } else {
            session::SessionAttachment::Attached
        },
        exit_code: None,
        command: command.to_vec(),
        profile: session.profile_name.clone(),
        workdir: std::env::current_dir().unwrap_or_default(),
        network: match caps.network_mode() {
            nono::NetworkMode::Blocked => "blocked".to_string(),
            nono::NetworkMode::AllowAll => "allowed".to_string(),
            nono::NetworkMode::ProxyOnly { port, .. } => format!("proxy (localhost:{port})"),
        },
        rollback_session: audit_state.map(|state| state.session_id.clone()),
    };
    let session_guard = Some(session::SessionGuard::new(session_record)?);
    let pty_pair = if session.detached_start {
        Some(pty_proxy::open_pty()?)
    } else {
        None
    };

    Ok(SessionRuntimeState {
        started,
        short_session_id,
        session_guard,
        pty_pair,
    })
}

pub(crate) fn execute_supervised_runtime(ctx: SupervisedRuntimeContext<'_>) -> Result<i32> {
    let SupervisedRuntimeContext {
        config,
        caps,
        command,
        session,
        rollback,
        trust,
        proxy,
        proxy_handle,
        silent,
    } = ctx;

    output::print_applying_sandbox(silent);

    let audit_state = create_audit_state(rollback.audit_disabled, rollback.destination.as_ref())?;
    warn_if_rollback_flags_ignored(rollback, silent);
    let rollback_state = initialize_rollback_state(rollback, caps, audit_state.as_ref(), silent)?;

    let protected_roots = protected_paths::ProtectedRoots::from_defaults()?;
    let approval_backend = terminal_approval::TerminalApproval;
    let supervisor_session_id = build_supervisor_session_id(audit_state.as_ref());
    let supervisor_cfg = exec_strategy::SupervisorConfig {
        protected_roots: protected_roots.as_paths(),
        approval_backend: &approval_backend,
        session_id: &supervisor_session_id,
        attach_initial_client: !session.detached_start,
        detach_sequence: session.detach_sequence.as_deref(),
        open_url_origins: &proxy.open_url_origins,
        open_url_allow_localhost: proxy.open_url_allow_localhost,
        allow_launch_services_active: proxy.allow_launch_services_active,
        #[cfg(target_os = "linux")]
        proxy_port: match caps.network_mode() {
            nono::NetworkMode::ProxyOnly { port, .. } => *port,
            _ => 0,
        },
        #[cfg(target_os = "linux")]
        proxy_bind_ports: match caps.network_mode() {
            nono::NetworkMode::ProxyOnly { bind_ports, .. } => bind_ports.clone(),
            _ => Vec::new(),
        },
    };

    let trust_interceptor = create_trust_interceptor(trust);
    let session_runtime =
        create_session_runtime_state(command, caps, session, audit_state.as_ref())?;
    let SessionRuntimeState {
        started,
        short_session_id,
        mut session_guard,
        pty_pair,
    } = session_runtime;

    if !session.detached_start {
        output::finish_status_line_for_handoff(silent);
    }

    let exit_code = {
        let mut on_fork = |child_pid: u32| {
            if let Some(ref mut guard) = session_guard {
                guard.set_child_pid(child_pid);
            }
        };
        exec_strategy::execute_supervised(
            config,
            Some(&supervisor_cfg),
            trust_interceptor,
            Some(&mut on_fork),
            pty_pair,
            Some(&short_session_id),
        )?
    };
    if let Some(ref mut guard) = session_guard {
        guard.set_exited(exit_code);
    }
    let ended = chrono::Local::now().to_rfc3339();
    finalize_supervised_exit(RollbackExitContext {
        audit_state: audit_state.as_ref(),
        rollback_state,
        proxy_handle,
        started: &started,
        ended: &ended,
        command,
        exit_code,
        silent,
        rollback_prompt_disabled: rollback.prompt_disabled,
    })?;

    Ok(exit_code)
}
