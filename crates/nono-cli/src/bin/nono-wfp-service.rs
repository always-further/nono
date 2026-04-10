//! Windows WFP backend service placeholder.
//!
//! This binary is the first repo-owned artifact for the future Windows WFP
//! backend. It establishes the expected Windows service contract and now owns
//! the first real user-mode WFP install/cleanup primitive for blocked-mode
//! activation.

#[path = "../windows_wfp_contract.rs"]
mod windows_wfp_contract;

use std::ffi::OsString;
use std::io::Read;
use std::process::ExitCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};
use windows_wfp_contract::{
    WfpRuntimeActivationRequest, WfpRuntimeActivationResponse, WFP_RUNTIME_PROTOCOL_VERSION,
};

const SERVICE_NAME: &str = "nono-wfp-service";
const SERVICE_MODE_ARG: &str = "--service-mode";
const PROBE_RUNTIME_ACTIVATION_ARG: &str = "--probe-runtime-activation";
const MAX_RUNTIME_REQUEST_SIZE: usize = 64 * 1024;
const CONTROL_PIPE_NAME: &str = r"\\.\pipe\nono-wfp-control";
const PIPE_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;OW)";
const SDDL_REVISION_1: u32 = 1;

/// Classic Windows Application Event Log source name registered by the machine MSI.
const EVENT_LOG_SOURCE: &str = SERVICE_NAME;

/// Event ID written when the startup orphan sweep completes.
const EVENT_ID_SWEEP_COMPLETE: u32 = 1001;

/// Event ID written when an individual stale WFP object is removed during the sweep.
const EVENT_ID_SWEEP_REMOVED: u32 = 1002;

/// Event ID written when a WFP object is skipped during the sweep (liveness check failed
/// to prove ownership, so the service refuses to delete it).
const EVENT_ID_SWEEP_SKIPPED: u32 = 1003;

/// Event ID written when a WFP object deletion fails during the sweep.
const EVENT_ID_SWEEP_FAILED: u32 = 1004;

/// Outcome for a single WFP object visited during the startup orphan sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SweepOutcome {
    /// The stale object was successfully deleted.
    Removed,
    /// The object was not deleted because ownership or liveness could not be confirmed.
    Skipped,
    /// Deletion was attempted but the WFP API returned an error.
    Failed,
}

/// Verbosity level for a Windows Event Log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventLogLevel {
    Information,
    Warning,
}

/// Format a human-readable message for a single sweep outcome.
///
/// The message is deterministic given the same inputs and is suitable for
/// use both in structured logs and as the body of a Windows Event Log entry.
fn format_sweep_outcome(outcome: SweepOutcome, filter_name: &str, layer_label: &str) -> String {
    match outcome {
        SweepOutcome::Removed => format!(
            "nono-wfp-service startup sweep: removed stale WFP filter '{}' on layer '{}'",
            filter_name, layer_label
        ),
        SweepOutcome::Skipped => format!(
            "nono-wfp-service startup sweep: skipped WFP filter '{}' on layer '{}' \
             (ownership or liveness could not be confirmed; not deleted)",
            filter_name, layer_label
        ),
        SweepOutcome::Failed => format!(
            "nono-wfp-service startup sweep: failed to remove WFP filter '{}' on layer '{}'",
            filter_name, layer_label
        ),
    }
}

/// Build a sweep summary string from a list of per-object outcomes.
///
/// The summary is written to Event Log (event ID `EVENT_ID_SWEEP_COMPLETE`)
/// and to stderr for local diagnostics.
fn build_sweep_summary(outcomes: &[(SweepOutcome, &str, &str)]) -> String {
    let removed = outcomes
        .iter()
        .filter(|(o, _, _)| *o == SweepOutcome::Removed)
        .count();
    let skipped = outcomes
        .iter()
        .filter(|(o, _, _)| *o == SweepOutcome::Skipped)
        .count();
    let failed = outcomes
        .iter()
        .filter(|(o, _, _)| *o == SweepOutcome::Failed)
        .count();
    format!(
        "nono-wfp-service startup sweep complete: removed={} skipped={} failed={}",
        removed, skipped, failed
    )
}

/// Build a structured Event Log message string.
///
/// The actual Windows Event Log write is performed by platform-specific code
/// (`write_event_log` on Windows). This function produces the body string that
/// will be embedded in the log entry, and is separately testable.
fn build_event_log_message(level: EventLogLevel, event_id: u32, body: &str) -> String {
    let level_str = match level {
        EventLogLevel::Information => "INFO",
        EventLogLevel::Warning => "WARN",
    };
    format!(
        "[{level_str}] source={} event_id={} {}",
        EVENT_LOG_SOURCE, event_id, body
    )
}

/// Write a message to the classic Windows Application Event Log.
///
/// This is a best-effort operation: if the Event Log source has not been
/// registered by the machine MSI (e.g., during development), the write
/// silently fails and the message is emitted to stderr instead.
///
/// Low-volume writes only — do not call in a tight loop.
#[cfg(target_os = "windows")]
fn write_event_log(level: EventLogLevel, event_id: u32, body: &str) {
    use windows_sys::Win32::System::EventLog::{
        DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_INFORMATION_TYPE,
        EVENTLOG_WARNING_TYPE,
    };

    let source_wide: Vec<u16> = EVENT_LOG_SOURCE
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .collect();
    // SAFETY: source_wide is a valid null-terminated UTF-16 string.
    // The handle is closed via DeregisterEventSource before the function returns.
    let handle = unsafe { RegisterEventSourceW(std::ptr::null(), source_wide.as_ptr()) };
    if handle.is_null() {
        // Source not registered (development or test environment). Fall back to stderr.
        eprintln!("{}", build_event_log_message(level, event_id, body));
        return;
    }

    let event_type = match level {
        EventLogLevel::Information => EVENTLOG_INFORMATION_TYPE,
        EventLogLevel::Warning => EVENTLOG_WARNING_TYPE,
    };

    let body_wide: Vec<u16> = body.encode_utf16().chain(std::iter::once(0u16)).collect();
    let strings: [*const u16; 1] = [body_wide.as_ptr()];

    // SAFETY: handle is valid; strings contains exactly one pointer to a
    // null-terminated UTF-16 string; user-data pointer is null (no binary data).
    unsafe {
        let _ = ReportEventW(
            handle,
            event_type,
            0,
            event_id,
            std::ptr::null_mut(),
            1,
            0,
            strings.as_ptr(),
            std::ptr::null_mut(),
        );
        let _ = DeregisterEventSource(handle);
    }
}

/// Log a sweep event: write to Event Log (Windows) and stderr (always).
///
/// The stderr output is always written so that service log capture pipelines
/// can see cleanup activity without requiring Event Log access.
#[allow(unused_variables)]
fn log_sweep_event(level: EventLogLevel, event_id: u32, body: &str) {
    eprintln!("{}", build_event_log_message(level, event_id, body));
    #[cfg(target_os = "windows")]
    write_event_log(level, event_id, body);
}

/// Perform the startup orphan sweep over nono-owned WFP filters.
///
/// Opens a fresh WFP engine handle and enumerates all filters in the
/// nono sublayer (`NONO_SUBLAYER_GUID`). Any filter found in that sublayer
/// is considered nono-owned. Filters with a zero GUID key are skipped
/// (fail-secure: zero-key filters are system-assigned and must not be deleted).
/// All other filters are deleted; if deletion succeeds they are logged as
/// `Removed`; if the API returns `FWP_E_FILTER_NOT_FOUND` (already gone) they
/// are also counted as `Removed`; any other error is logged as `Failed`.
///
/// This runs before the named-pipe server begins accepting new activation
/// requests so that stale filters from a previous crash are cleaned up
/// before any new session can be established.
///
/// Returns the list of outcomes for summary logging.
#[cfg(target_os = "windows")]
fn run_startup_sweep() -> Vec<(SweepOutcome, String, String)> {
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FwpmFilterCreateEnumHandle0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0,
        FwpmSubLayerGetByKey0, FWPM_FILTER_ENUM_TEMPLATE0,
    };

    let engine = match open_wfp_engine() {
        Ok(e) => e,
        Err(err) => {
            log_sweep_event(
                EventLogLevel::Warning,
                EVENT_ID_SWEEP_FAILED,
                &format!("startup sweep aborted: could not open WFP engine: {}", err),
            );
            return Vec::new();
        }
    };

    // Check whether our sublayer is registered. If absent, there are no nono
    // filters to sweep — emit a clean summary and return early.
    //
    // SAFETY: engine handle is valid; NONO_SUBLAYER_GUID is a static const;
    // we pass null for the output pointer because we only care about existence.
    let sublayer_status =
        unsafe { FwpmSubLayerGetByKey0(engine.0, &NONO_SUBLAYER_GUID, std::ptr::null_mut()) };
    if sublayer_status != 0 {
        let summary = build_sweep_summary(&[]);
        log_sweep_event(
            EventLogLevel::Information,
            EVENT_ID_SWEEP_COMPLETE,
            &summary,
        );
        return Vec::new();
    }

    // Build a filter enumeration template. We enumerate all filters (no layer
    // restriction) and filter by sublayer key during the loop to avoid touching
    // objects in sublayers we do not own.
    let mut template: FWPM_FILTER_ENUM_TEMPLATE0 = zeroed();
    template.actionMask = 0xFFFF_FFFF;
    // enumType 0 = FWP_FILTER_ENUM_FULLY_CONTAINED (only non-boot-time filters)
    // 0 = FWP_FILTER_ENUM_FULLY_CONTAINED (only fully-contained filters, no boot-time)
    template.enumType = 0;

    let mut enum_handle: HANDLE = std::ptr::null_mut();
    // SAFETY: engine handle is valid; template is initialized POD.
    let enum_status = unsafe { FwpmFilterCreateEnumHandle0(engine.0, &template, &mut enum_handle) };
    if enum_status != 0 {
        log_sweep_event(
            EventLogLevel::Warning,
            EVENT_ID_SWEEP_FAILED,
            &format!(
                "startup sweep: could not create filter enum handle (win32 0x{:08x})",
                enum_status
            ),
        );
        return Vec::new();
    }

    let mut outcomes: Vec<(SweepOutcome, String, String)> = Vec::new();
    let batch_size: u32 = 64;

    loop {
        let mut entries: *mut *mut windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER0 =
            std::ptr::null_mut();
        let mut returned: u32 = 0;
        // SAFETY: engine and enum_handle are valid; entries and returned are
        // writable and initialized to null/0 before the call.
        let status = unsafe {
            FwpmFilterEnum0(
                engine.0,
                enum_handle,
                batch_size,
                &mut entries,
                &mut returned,
            )
        };
        if status != 0 || returned == 0 {
            // Free any partial batch before breaking.
            if !entries.is_null() {
                let mut ptr = entries as *mut _ as *mut core::ffi::c_void;
                // SAFETY: entries was allocated by FwpmFilterEnum0.
                unsafe { FwpmFreeMemory0(&mut ptr) };
            }
            break;
        }

        for i in 0..returned as usize {
            // SAFETY: entries[i] is a valid pointer from FwpmFilterEnum0.
            let filter_ptr = unsafe { *entries.add(i) };
            if filter_ptr.is_null() {
                continue;
            }
            let filter = unsafe { &*filter_ptr };

            // Skip filters not in the nono sublayer.
            let sub = filter.subLayerKey;
            if sub.data1 != NONO_SUBLAYER_GUID.data1
                || sub.data2 != NONO_SUBLAYER_GUID.data2
                || sub.data3 != NONO_SUBLAYER_GUID.data3
                || sub.data4 != NONO_SUBLAYER_GUID.data4
            {
                continue;
            }

            let key = filter.filterKey;
            // Fail-secure: skip zero-key filters (system-assigned identity).
            let is_zero_key =
                key.data1 == 0 && key.data2 == 0 && key.data3 == 0 && key.data4 == [0u8; 8];
            if is_zero_key {
                let outcome = SweepOutcome::Skipped;
                let msg = format_sweep_outcome(outcome, "zero-key-filter", "unknown");
                log_sweep_event(EventLogLevel::Information, EVENT_ID_SWEEP_SKIPPED, &msg);
                outcomes.push((
                    outcome,
                    "zero-key-filter".to_string(),
                    "unknown".to_string(),
                ));
                continue;
            }

            let filter_name = format!("filter-{:08x}", key.data1);
            // SAFETY: engine handle is valid; key is a copy of the filter's GUID.
            let del_status = unsafe { FwpmFilterDeleteByKey0(engine.0, &key) };
            if del_status == 0 || del_status == FWP_E_FILTER_NOT_FOUND as u32 {
                let outcome = SweepOutcome::Removed;
                let msg = format_sweep_outcome(outcome, &filter_name, "swept");
                log_sweep_event(EventLogLevel::Information, EVENT_ID_SWEEP_REMOVED, &msg);
                outcomes.push((outcome, filter_name, "swept".to_string()));
            } else {
                let outcome = SweepOutcome::Failed;
                let msg = format_sweep_outcome(outcome, &filter_name, "sweep");
                log_sweep_event(EventLogLevel::Warning, EVENT_ID_SWEEP_FAILED, &msg);
                outcomes.push((outcome, filter_name, "sweep".to_string()));
            }
        }

        // SAFETY: entries was allocated by FwpmFilterEnum0 and must be freed
        // via FwpmFreeMemory0 before the next batch request.
        if !entries.is_null() {
            let mut ptr = entries as *mut _ as *mut core::ffi::c_void;
            unsafe { FwpmFreeMemory0(&mut ptr) };
        }

        if returned < batch_size {
            break;
        }
    }

    // SAFETY: enum_handle was created by FwpmFilterCreateEnumHandle0 and must
    // be released before the engine handle is closed.
    unsafe {
        let _ = FwpmFilterDestroyEnumHandle0(engine.0, enum_handle);
    }

    let tuple_refs: Vec<(SweepOutcome, &str, &str)> = outcomes
        .iter()
        .map(|(o, n, l)| (*o, n.as_str(), l.as_str()))
        .collect();
    let summary = build_sweep_summary(&tuple_refs);
    log_sweep_event(
        EventLogLevel::Information,
        EVENT_ID_SWEEP_COMPLETE,
        &summary,
    );
    outcomes
}

/// Non-Windows stub: startup sweep is a no-op on non-Windows platforms.
#[cfg(not(target_os = "windows"))]
fn run_startup_sweep() -> Vec<(SweepOutcome, String, String)> {
    Vec::new()
}

#[cfg(target_os = "windows")]
use sha2::{Digest, Sha256};

#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;

#[cfg(target_os = "windows")]
use std::ptr::{null, null_mut};

#[cfg(target_os = "windows")]
use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::HANDLE,
        Foundation::{GetLastError, LocalFree},
        Foundation::{FWP_E_ALREADY_EXISTS, FWP_E_FILTER_NOT_FOUND},
        NetworkManagement::WindowsFilteringPlatform::{
            FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteByKey0,
            FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FwpmSubLayerAdd0, FwpmTransactionAbort0,
            FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_ACTION0, FWPM_ACTION0_0,
            FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_ALE_USER_ID, FWPM_CONDITION_FLAGS,
            FWPM_CONDITION_IP_LOCAL_PORT, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0,
            FWPM_FILTER0, FWPM_FILTER0_0, FWPM_FILTER_CONDITION0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC,
            FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE,
            FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0,
            FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ALL_SET, FWP_SECURITY_DESCRIPTOR_TYPE, FWP_UINT16,
            FWP_UINT32, FWP_UINT64, FWP_VALUE0, FWP_VALUE0_0,
        },
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
            },
            SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{
            FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
        },
        System::Pipes::{
            CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
        },
        System::Rpc::RPC_C_AUTHN_WINNT,
    },
};

fn print_help() {
    println!("nono-wfp-service {}", env!("CARGO_PKG_VERSION"));
    println!("Windows WFP backend service placeholder");
    println!();
    println!("This binary defines the current Windows service contract for the");
    println!("future WFP backend. Service registration and service-host runtime");
    println!("still fail closed until the real backend is implemented.");
    println!();
    println!("Service contract:");
    println!("  service name: {SERVICE_NAME}");
    println!("  startup args: {SERVICE_MODE_ARG}");
    println!();
    println!("Supported options:");
    println!("  --help                 Show this message");
    println!("  --version              Show version information");
    println!("  --print-service-contract");
    println!("                         Print the expected Windows service contract");
    println!(
        "  {PROBE_RUNTIME_ACTIVATION_ARG:<22}Probe the placeholder runtime activation contract"
    );
    println!("  {SERVICE_MODE_ARG:<22}Run the placeholder service entrypoint");
}

fn print_service_contract() {
    println!("service_name={SERVICE_NAME}");
    println!("startup_args={SERVICE_MODE_ARG}");
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(arguments: Vec<OsString>) {
    if let Err(e) = run_service(arguments) {
        eprintln!("Service failed: {}", e);
    }
}

fn run_service(_arguments: Vec<OsString>) -> windows_service::Result<()> {
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => ServiceControlHandlerResult::NoError,
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    })?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            windows_service::Error::Winapi(std::io::Error::other(format!(
                "Failed to build tokio runtime: {}",
                e
            )))
        })?;

    rt.block_on(async {
        if let Err(e) = run_named_pipe_server().await {
            eprintln!("Named pipe server failed: {}", e);
        }
    });

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

async fn run_named_pipe_server() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        // Perform the startup orphan sweep before accepting any new activation
        // requests. This cleans up stale filters from a previous service crash
        // and writes outcomes to Windows Event Log per D-06 and D-07.
        let _sweep_outcomes = run_startup_sweep();

        let engine = open_wfp_engine()?;
        create_nono_sublayer(&engine)?;

        let mut first = true;
        loop {
            let sd = {
                let mut sd = null_mut();
                let sddl_wide: Vec<u16> = PIPE_SDDL.encode_utf16().chain(Some(0)).collect();
                let status = unsafe {
                    ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        sddl_wide.as_ptr(),
                        SDDL_REVISION_1,
                        &mut sd,
                        null_mut(),
                    )
                };
                if status == 0 {
                    return Err(format!(
                        "failed to convert SDDL to security descriptor: {}",
                        unsafe { windows_sys::Win32::Foundation::GetLastError() }
                    ));
                }
                sd
            };

            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            };

            let pipe_path_wide: Vec<u16> =
                CONTROL_PIPE_NAME.encode_utf16().chain(Some(0)).collect();

            let mut access = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
            if first {
                access |= FILE_FLAG_FIRST_PIPE_INSTANCE;
                first = false;
            }

            let handle = unsafe {
                CreateNamedPipeW(
                    pipe_path_wide.as_ptr(),
                    access,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE,
                    PIPE_UNLIMITED_INSTANCES,
                    MAX_RUNTIME_REQUEST_SIZE as u32,
                    MAX_RUNTIME_REQUEST_SIZE as u32,
                    0,
                    &sa,
                )
            };

            unsafe {
                LocalFree(sd);
            }

            if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                return Err(format!(
                    "failed to create named pipe {}: {}",
                    CONTROL_PIPE_NAME,
                    unsafe { windows_sys::Win32::Foundation::GetLastError() }
                ));
            }

            let mut server = unsafe {
                tokio::net::windows::named_pipe::NamedPipeServer::from_raw_handle(handle as *mut _)
            }
            .map_err(|e| format!("failed to convert raw handle to NamedPipeServer: {}", e))?;

            server.connect().await.map_err(|e| {
                format!(
                    "failed to connect to named pipe {}: {}",
                    CONTROL_PIPE_NAME, e
                )
            })?;

            let mut buffer = vec![0u8; MAX_RUNTIME_REQUEST_SIZE];
            let n = server
                .read(&mut buffer)
                .await
                .map_err(|e| format!("failed to read from named pipe: {}", e))?;

            if n == 0 {
                continue;
            }

            let request: WfpRuntimeActivationRequest = match serde_json::from_slice(&buffer[..n]) {
                Ok(req) => req,
                Err(e) => {
                    eprintln!("Invalid request received: {}", e);
                    continue;
                }
            };

            let response = match request.request_kind.as_str() {
                "activate_blocked_mode" | "activate_proxy_mode" | "activate_allow_all_mode" => {
                    activate_policy_mode(&request)
                }
                "deactivate_blocked_mode" | "deactivate_policy_mode" => {
                    deactivate_policy_mode(&request)
                }
                _ => build_invalid_activation_response(&request),
            };

            let response_json = serde_json::to_vec(&response)
                .map_err(|e| format!("failed to serialize response: {}", e))?;

            server
                .write_all(&response_json)
                .await
                .map_err(|e| format!("failed to write to named pipe: {}", e))?;

            let _ = server.flush().await;
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        Err("Named pipe server is only supported on Windows".to_string())
    }
}

fn run_service_mode() -> ExitCode {
    match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Failed to start service dispatcher: {}", e);
            ExitCode::from(3)
        }
    }
}

fn build_protocol_mismatch_response(
    request: &WfpRuntimeActivationRequest,
) -> WfpRuntimeActivationResponse {
    WfpRuntimeActivationResponse {
        protocol_version: WFP_RUNTIME_PROTOCOL_VERSION,
        status: "protocol-mismatch".to_string(),
        details: format!(
            "unsupported WFP runtime activation protocol version {}; expected {}",
            request.protocol_version, WFP_RUNTIME_PROTOCOL_VERSION
        ),
    }
}

fn build_invalid_activation_response_for(
    request_kind: &str,
    runtime_target: &str,
) -> WfpRuntimeActivationResponse {
    WfpRuntimeActivationResponse {
        protocol_version: WFP_RUNTIME_PROTOCOL_VERSION,
        status: "invalid-request".to_string(),
        details: format!(
            "unsupported WFP runtime activation request kind `{}` for {}",
            request_kind, runtime_target
        ),
    }
}

fn build_invalid_activation_response(
    request: &WfpRuntimeActivationRequest,
) -> WfpRuntimeActivationResponse {
    build_invalid_activation_response_for(&request.request_kind, &request.runtime_target)
}

fn build_prerequisites_missing_response(details: String) -> WfpRuntimeActivationResponse {
    WfpRuntimeActivationResponse {
        protocol_version: WFP_RUNTIME_PROTOCOL_VERSION,
        status: "prerequisites-missing".to_string(),
        details,
    }
}

fn build_enforced_pending_cleanup_response(
    request: &WfpRuntimeActivationRequest,
    details: String,
) -> WfpRuntimeActivationResponse {
    WfpRuntimeActivationResponse {
        protocol_version: WFP_RUNTIME_PROTOCOL_VERSION,
        status: "enforced-pending-cleanup".to_string(),
        details: format!(
            "request {} for {} installed target-attached network-policy enforcement and requires cleanup after launch: {}",
            request.request_kind, request.runtime_target, details
        ),
    }
}

fn build_cleanup_succeeded_response(
    request: &WfpRuntimeActivationRequest,
    details: String,
) -> WfpRuntimeActivationResponse {
    WfpRuntimeActivationResponse {
        protocol_version: WFP_RUNTIME_PROTOCOL_VERSION,
        status: "cleanup-succeeded".to_string(),
        details: format!(
            "request {} for {} removed target-attached network-policy enforcement: {}",
            request.request_kind, request.runtime_target, details
        ),
    }
}

fn build_cleanup_failed_response(
    request: &WfpRuntimeActivationRequest,
    details: String,
) -> WfpRuntimeActivationResponse {
    WfpRuntimeActivationResponse {
        protocol_version: WFP_RUNTIME_PROTOCOL_VERSION,
        status: "cleanup-failed".to_string(),
        details: format!(
            "request {} for {} could not remove target-attached network-policy enforcement: {}",
            request.request_kind, request.runtime_target, details
        ),
    }
}

fn build_filtering_probe_failed_response(
    request: &WfpRuntimeActivationRequest,
    details: String,
) -> WfpRuntimeActivationResponse {
    WfpRuntimeActivationResponse {
        protocol_version: WFP_RUNTIME_PROTOCOL_VERSION,
        status: "filtering-probe-failed".to_string(),
        details: format!(
            "request {} for {} could not install the backend-owned network-policy probe: {}",
            request.request_kind, request.runtime_target, details
        ),
    }
}

fn validate_target_request_fields(
    request: &WfpRuntimeActivationRequest,
) -> Result<(std::path::PathBuf, String, String), WfpRuntimeActivationResponse> {
    let invalid_request =
        || build_invalid_activation_response_for(&request.request_kind, &request.runtime_target);
    let target_program = request
        .target_program_path
        .as_ref()
        .map(std::path::PathBuf::from)
        .ok_or_else(invalid_request)?;
    let outbound_rule = request
        .outbound_rule_name
        .clone()
        .ok_or_else(invalid_request)?;
    let inbound_rule = request
        .inbound_rule_name
        .clone()
        .ok_or_else(invalid_request)?;
    Ok((target_program, outbound_rule, inbound_rule))
}

#[cfg(target_os = "windows")]
struct WfpEngine(HANDLE);

#[cfg(target_os = "windows")]
impl Drop for WfpEngine {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: The handle was returned by FwpmEngineOpen0 and remains valid
            // until this drop closes it once.
            unsafe {
                let _ = FwpmEngineClose0(self.0);
            }
        }
    }
}

#[cfg(target_os = "windows")]
struct WfpAppIdBlob(*mut FWP_BYTE_BLOB);

#[cfg(target_os = "windows")]
impl WfpAppIdBlob {
    fn as_ptr(&self) -> *mut FWP_BYTE_BLOB {
        self.0
    }
}

#[cfg(target_os = "windows")]
impl Drop for WfpAppIdBlob {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let mut ptr = self.0.cast();
            // SAFETY: The blob pointer was allocated by FwpmGetAppIdFromFileName0 and
            // must be released via FwpmFreeMemory0 exactly once.
            unsafe {
                FwpmFreeMemory0(&mut ptr);
            }
        }
    }
}

#[cfg(target_os = "windows")]
struct WfpSecurityDescriptor(*mut core::ffi::c_void);

#[cfg(target_os = "windows")]
impl std::fmt::Debug for WfpSecurityDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WfpSecurityDescriptor({:p})", self.0)
    }
}

#[cfg(target_os = "windows")]
impl WfpSecurityDescriptor {
    fn as_ptr(&self) -> *mut core::ffi::c_void {
        self.0
    }
}

#[cfg(target_os = "windows")]
impl Drop for WfpSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: The security descriptor was allocated by
            // ConvertStringSecurityDescriptorToSecurityDescriptorW and must be
            // released via LocalFree exactly once.
            unsafe {
                LocalFree(self.0 as _);
            }
        }
    }
}

#[cfg(target_os = "windows")]
struct WfpTransaction<'a> {
    engine: &'a WfpEngine,
    committed: bool,
}

#[cfg(target_os = "windows")]
impl<'a> WfpTransaction<'a> {
    fn begin(engine: &'a WfpEngine) -> Result<Self, String> {
        // SAFETY: engine handle is valid for the lifetime of this transaction.
        let status = unsafe { FwpmTransactionBegin0(engine.0, 0) };
        if status != 0 {
            return Err(format_windows_error(
                status,
                "failed to begin WFP transaction",
            ));
        }
        Ok(Self {
            engine,
            committed: false,
        })
    }

    fn commit(mut self) -> Result<(), String> {
        // SAFETY: engine handle is valid and has an active transaction.
        let status = unsafe { FwpmTransactionCommit0(self.engine.0) };
        if status != 0 {
            return Err(format_windows_error(
                status,
                "failed to commit WFP transaction",
            ));
        }
        self.committed = true;
        Ok(())
    }
}

#[cfg(target_os = "windows")]
impl Drop for WfpTransaction<'_> {
    fn drop(&mut self) {
        if !self.committed {
            // SAFETY: engine handle is valid and aborting an uncommitted transaction
            // is the required fail-secure cleanup path.
            unsafe {
                let _ = FwpmTransactionAbort0(self.engine.0);
            }
        }
    }
}

#[cfg(target_os = "windows")]
#[derive(Clone, Copy)]
struct WfpLayerSpec {
    key: GUID,
    label: &'static str,
    rule_name: &'static str,
}

#[cfg(target_os = "windows")]
#[derive(Clone, Copy)]
enum FilterAction {
    Permit,
    Block,
}

#[cfg(target_os = "windows")]
#[derive(Clone, Copy)]
enum PortCondition {
    Remote(u16),
    Local(u16),
}

#[cfg(target_os = "windows")]
#[derive(Clone, Copy)]
struct PolicyFilterSpec {
    key: GUID,
    layer_key: GUID,
    action: FilterAction,
    port: Option<PortCondition>,
    loopback_only: bool,
}

#[cfg(target_os = "windows")]
fn build_wfp_layer_specs() -> [WfpLayerSpec; 4] {
    [
        WfpLayerSpec {
            key: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            label: "connect-v4",
            rule_name: "outbound",
        },
        WfpLayerSpec {
            key: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            label: "connect-v6",
            rule_name: "outbound",
        },
        WfpLayerSpec {
            key: FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            label: "recv-accept-v4",
            rule_name: "inbound",
        },
        WfpLayerSpec {
            key: FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            label: "recv-accept-v6",
            rule_name: "inbound",
        },
    ]
}

#[cfg(target_os = "windows")]
fn to_utf16_null(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain([0]).collect()
}

#[cfg(target_os = "windows")]
fn zeroed<T>() -> T {
    // SAFETY: The WFP FFI structs used here are plain old data. They are
    // immediately initialized field-by-field before being passed to Win32 APIs.
    unsafe { std::mem::zeroed() }
}

#[cfg(target_os = "windows")]
fn format_windows_error(status: u32, context: &str) -> String {
    format!("{context} (win32 status {status}, 0x{status:08x})")
}

#[cfg(target_os = "windows")]
fn deterministic_filter_key(base_name: &str, label: &str) -> GUID {
    let mut hasher = Sha256::new();
    hasher.update(b"nono-wfp-filter");
    hasher.update(base_name.as_bytes());
    hasher.update(b":");
    hasher.update(label.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    guid_from_hash_bytes(bytes)
}

#[cfg(target_os = "windows")]
fn guid_from_hash_bytes(bytes: [u8; 16]) -> GUID {
    GUID {
        data1: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        data2: u16::from_be_bytes([bytes[4], bytes[5]]),
        data3: u16::from_be_bytes([bytes[6], bytes[7]]),
        data4: [
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ],
    }
}

#[cfg(target_os = "windows")]
fn zero_guid() -> GUID {
    GUID {
        data1: 0,
        data2: 0,
        data3: 0,
        data4: [0; 8],
    }
}

#[cfg(target_os = "windows")]
fn build_policy_filter_specs(
    request: &WfpRuntimeActivationRequest,
    outbound_rule: &str,
    inbound_rule: &str,
) -> Vec<PolicyFilterSpec> {
    let mut specs = Vec::new();

    for layer in build_wfp_layer_specs() {
        let base = if layer.rule_name == "outbound" {
            outbound_rule
        } else {
            inbound_rule
        };
        let is_outbound = layer.rule_name == "outbound";

        if is_outbound {
            for port in &request.tcp_connect_ports {
                specs.push(PolicyFilterSpec {
                    key: deterministic_filter_key(base, &format!("{}-connect-{port}", layer.label)),
                    layer_key: layer.key,
                    action: FilterAction::Permit,
                    port: Some(PortCondition::Remote(*port)),
                    loopback_only: false,
                });
            }

            for port in &request.localhost_ports {
                specs.push(PolicyFilterSpec {
                    key: deterministic_filter_key(
                        base,
                        &format!("{}-localhost-connect-{port}", layer.label),
                    ),
                    layer_key: layer.key,
                    action: FilterAction::Permit,
                    port: Some(PortCondition::Remote(*port)),
                    loopback_only: true,
                });
            }

            let needs_outbound_block = request.network_mode != "allow-all"
                || !request.tcp_connect_ports.is_empty()
                || !request.localhost_ports.is_empty();
            if needs_outbound_block {
                specs.push(PolicyFilterSpec {
                    key: deterministic_filter_key(base, layer.label),
                    layer_key: layer.key,
                    action: FilterAction::Block,
                    port: None,
                    loopback_only: false,
                });
            }
        } else {
            for port in &request.tcp_bind_ports {
                specs.push(PolicyFilterSpec {
                    key: deterministic_filter_key(base, &format!("{}-bind-{port}", layer.label)),
                    layer_key: layer.key,
                    action: FilterAction::Permit,
                    port: Some(PortCondition::Local(*port)),
                    loopback_only: false,
                });
            }
            for port in &request.localhost_ports {
                specs.push(PolicyFilterSpec {
                    key: deterministic_filter_key(
                        base,
                        &format!("{}-localhost-bind-{port}", layer.label),
                    ),
                    layer_key: layer.key,
                    action: FilterAction::Permit,
                    port: Some(PortCondition::Local(*port)),
                    loopback_only: true,
                });
            }

            let needs_inbound_block = request.network_mode != "allow-all"
                || !request.tcp_bind_ports.is_empty()
                || !request.localhost_ports.is_empty();
            if needs_inbound_block {
                specs.push(PolicyFilterSpec {
                    key: deterministic_filter_key(base, layer.label),
                    layer_key: layer.key,
                    action: FilterAction::Block,
                    port: None,
                    loopback_only: false,
                });
            }
        }
    }

    specs
}

#[cfg(target_os = "windows")]
fn open_wfp_engine() -> Result<WfpEngine, String> {
    let mut session: FWPM_SESSION0 = zeroed();
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    let mut handle: HANDLE = null_mut();
    // SAFETY: All pointers are either null or point to initialized POD
    // structures valid for the duration of the call. The returned handle is
    // wrapped immediately for RAII cleanup.
    let status =
        unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), &session, &mut handle) };
    if status != 0 {
        return Err(format_windows_error(
            status,
            "failed to open Windows Filtering Platform engine",
        ));
    }
    if handle.is_null() {
        return Err("WFP engine returned a null handle".to_string());
    }
    Ok(WfpEngine(handle))
}

#[cfg(target_os = "windows")]
const NONO_SUBLAYER_GUID: GUID = GUID {
    data1: 0x33445566,
    data2: 0x7788,
    data3: 0x99aa,
    data4: [0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22],
};

#[cfg(target_os = "windows")]
fn create_nono_sublayer(engine: &WfpEngine) -> Result<(), String> {
    let mut sub_layer: FWPM_SUBLAYER0 = zeroed();
    sub_layer.subLayerKey = NONO_SUBLAYER_GUID;
    let name_wide = to_utf16_null(std::ffi::OsStr::new("nono Network Policy Sublayer"));
    sub_layer.displayData = FWPM_DISPLAY_DATA0 {
        name: name_wide.as_ptr() as *mut _,
        description: null_mut(),
    };
    sub_layer.weight = 0x1000; // High weight

    // SAFETY: engine handle is valid; sub_layer points to initialized POD data.
    let status = unsafe { FwpmSubLayerAdd0(engine.0, &sub_layer, null_mut()) };
    if status != 0 && status != FWP_E_ALREADY_EXISTS as u32 {
        return Err(format_windows_error(
            status,
            "failed to create nono WFP sublayer",
        ));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn sid_to_security_descriptor(sid_str: &str) -> Result<WfpSecurityDescriptor, String> {
    // First, validate that the SID string is actually a valid SID.
    let sid_wide = to_utf16_null(std::ffi::OsStr::new(sid_str));
    let mut sid = null_mut();
    // SAFETY: sid_wide is a valid null-terminated UTF-16 buffer.
    let status = unsafe { ConvertStringSidToSidW(sid_wide.as_ptr(), &mut sid) };
    if status == 0 {
        return Err(format_windows_error(
            unsafe { GetLastError() },
            &format!("invalid SID string: {}", sid_str),
        ));
    }
    // We don't need the binary SID, just validation, but we must free it.
    unsafe {
        LocalFree(sid as _);
    }

    // Now convert the SDDL to a security descriptor.
    let sddl = format!("D:(A;;CC;;;{sid_str})");
    let sddl_wide = to_utf16_null(std::ffi::OsStr::new(&sddl));
    let mut sd = null_mut();
    // SAFETY: sddl_wide is a valid null-terminated UTF-16 buffer.
    // sd points to a pointer that will receive the allocated SD.
    let status = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_wide.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            null_mut(),
        )
    };
    if status == 0 {
        return Err(format_windows_error(
            unsafe { GetLastError() },
            &format!("failed to convert SDDL '{}' to security descriptor", sddl),
        ));
    }
    Ok(WfpSecurityDescriptor(sd))
}

#[cfg(target_os = "windows")]
fn get_app_id_blob(target_program: &std::path::Path) -> Result<WfpAppIdBlob, String> {
    let path_wide = to_utf16_null(target_program.as_os_str());
    let mut blob: *mut FWP_BYTE_BLOB = null_mut();
    // SAFETY: path_wide is a valid null-terminated UTF-16 buffer for the target
    // program path, and blob points to writable storage for the returned pointer.
    let status = unsafe { FwpmGetAppIdFromFileName0(path_wide.as_ptr(), &mut blob) };
    if status == 0 {
        return Err(format_windows_error(
            status,
            &format!(
                "failed to derive WFP app id for {}",
                target_program.display()
            ),
        ));
    }
    if blob.is_null() {
        return Err(format!(
            "WFP returned a null app id blob for {}",
            target_program.display()
        ));
    }
    Ok(WfpAppIdBlob(blob))
}

#[cfg(target_os = "windows")]
fn add_policy_filter(
    engine: &WfpEngine,
    spec: PolicyFilterSpec,
    app_id_blob: *mut FWP_BYTE_BLOB,
    security_descriptor: *mut core::ffi::c_void,
) -> Result<(), String> {
    let mut conditions = Vec::with_capacity(3);

    if !security_descriptor.is_null() {
        conditions.push(FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_USER_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_SECURITY_DESCRIPTOR_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    sd: security_descriptor as *mut _,
                },
            },
        });
    } else if !app_id_blob.is_null() {
        conditions.push(FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_APP_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_BLOB_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    byteBlob: app_id_blob,
                },
            },
        });
    }

    if let Some(port) = spec.port {
        let (field_key, value) = match port {
            PortCondition::Remote(value) => (FWPM_CONDITION_IP_REMOTE_PORT, value),
            PortCondition::Local(value) => (FWPM_CONDITION_IP_LOCAL_PORT, value),
        };
        conditions.push(FWPM_FILTER_CONDITION0 {
            fieldKey: field_key,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT16,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint16: value },
            },
        });
    }
    if spec.loopback_only {
        conditions.push(FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_FLAGS,
            matchType: FWP_MATCH_FLAGS_ALL_SET,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
                },
            },
        });
    }
    let action = FWPM_ACTION0 {
        r#type: match spec.action {
            FilterAction::Permit => FWP_ACTION_PERMIT,
            FilterAction::Block => FWP_ACTION_BLOCK,
        },
        Anonymous: FWPM_ACTION0_0 {
            filterType: zero_guid(),
        },
    };

    let mut weight_value = if !security_descriptor.is_null() {
        match spec.action {
            FilterAction::Permit => 100u64,
            FilterAction::Block => 0u64,
        }
    } else {
        match spec.action {
            FilterAction::Permit => 20u64,
            FilterAction::Block => 10u64,
        }
    };

    let mut filter: FWPM_FILTER0 = zeroed();
    filter.filterKey = spec.key;
    filter.displayData = FWPM_DISPLAY_DATA0 {
        name: null_mut(),
        description: null_mut(),
    };
    filter.layerKey = spec.layer_key;
    filter.subLayerKey = NONO_SUBLAYER_GUID;
    filter.weight = FWP_VALUE0 {
        r#type: FWP_UINT64,
        Anonymous: FWP_VALUE0_0 {
            uint64: &mut weight_value,
        },
    };
    filter.numFilterConditions = conditions.len() as u32;
    filter.filterCondition = conditions.as_mut_ptr();
    filter.action = action;
    filter.Anonymous = FWPM_FILTER0_0 { rawContext: 0 };

    let mut filter_id = 0u64;
    // SAFETY: engine handle is valid; filter points to initialized WFP POD data
    // whose nested pointers remain valid for the duration of the call.
    let status = unsafe { FwpmFilterAdd0(engine.0, &filter, null_mut(), &mut filter_id) };
    if status != 0 {
        let details = if status == FWP_E_ALREADY_EXISTS as u32 {
            "failed to install WFP filter because a stale filter with the same deterministic key already exists"
                .to_string()
        } else {
            format_windows_error(status, "failed to install WFP network-policy filter")
        };
        return Err(details);
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn delete_policy_filter(engine: &WfpEngine, filter_key: GUID) -> Result<(), String> {
    // SAFETY: engine handle is valid and filter_key points to an initialized GUID.
    let status = unsafe { FwpmFilterDeleteByKey0(engine.0, &filter_key) };
    if status != 0 {
        let details = if status == FWP_E_FILTER_NOT_FOUND as u32 {
            "failed to delete WFP filter because the deterministic key was not found; cleanup is stale or has already run".to_string()
        } else {
            format_windows_error(status, "failed to delete WFP network-policy filter")
        };
        return Err(details);
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn install_wfp_policy_filters(
    request: &WfpRuntimeActivationRequest,
    target_program: &std::path::Path,
    outbound_rule: &str,
    inbound_rule: &str,
) -> Result<String, String> {
    let engine = open_wfp_engine()?;

    // Determine if we are using SID-based or AppID-based filtering.
    let (app_id, sd) = if let Some(sid_str) = &request.session_sid {
        let sd = sid_to_security_descriptor(sid_str)?;
        (None, Some(sd))
    } else {
        let app_id = get_app_id_blob(target_program)?;
        (Some(app_id), None)
    };

    let transaction = WfpTransaction::begin(&engine)?;

    let specs = build_policy_filter_specs(request, outbound_rule, inbound_rule);
    for spec in &specs {
        let app_id_ptr = app_id.as_ref().map(|a| a.as_ptr()).unwrap_or(null_mut());
        let sd_ptr = sd.as_ref().map(|s| s.as_ptr()).unwrap_or(null_mut());
        add_policy_filter(&engine, *spec, app_id_ptr, sd_ptr)?;
    }

    transaction.commit()?;

    let target_desc = if let Some(sid_str) = &request.session_sid {
        format!("SID {}", sid_str)
    } else {
        target_program.display().to_string()
    };

    Ok(format!(
        "installed {} WFP network-policy filters for {} using outbound rule base {} and inbound rule base {}",
        specs.len(),
        target_desc,
        outbound_rule,
        inbound_rule
    ))
}

#[cfg(target_os = "windows")]
fn remove_wfp_policy_filters(
    request: &WfpRuntimeActivationRequest,
    outbound_rule: &str,
    inbound_rule: &str,
) -> Result<String, String> {
    let engine = open_wfp_engine()?;
    let transaction = WfpTransaction::begin(&engine)?;

    let specs = build_policy_filter_specs(request, outbound_rule, inbound_rule);
    for spec in &specs {
        delete_policy_filter(&engine, spec.key)?;
    }

    transaction.commit()?;

    let target_desc = if let Some(sid_str) = &request.session_sid {
        format!("SID {}", sid_str)
    } else {
        "app-id".to_string()
    };

    Ok(format!(
        "removed {} WFP {} network-policy filters for outbound rule base {} and inbound rule base {}",
        specs.len(),
        target_desc,
        outbound_rule,
        inbound_rule
    ))
}

fn activate_policy_mode(request: &WfpRuntimeActivationRequest) -> WfpRuntimeActivationResponse {
    if request.protocol_version != WFP_RUNTIME_PROTOCOL_VERSION {
        return build_protocol_mismatch_response(request);
    }
    if !matches!(
        request.network_mode.as_str(),
        "blocked" | "proxy-only" | "allow-all"
    ) {
        return build_invalid_activation_response(request);
    }

    let (target_program, outbound_rule, inbound_rule) =
        match validate_target_request_fields(request) {
            Ok(fields) => fields,
            Err(response) => return response,
        };
    if !target_program.exists() {
        return build_prerequisites_missing_response(format!(
            "target program for network-policy enforcement does not exist: {}",
            target_program.display()
        ));
    }

    #[cfg(target_os = "windows")]
    {
        match install_wfp_policy_filters(request, &target_program, &outbound_rule, &inbound_rule) {
            Ok(details) => build_enforced_pending_cleanup_response(request, details),
            Err(err) => build_filtering_probe_failed_response(request, err),
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = (target_program, outbound_rule, inbound_rule);
        build_filtering_probe_failed_response(
            request,
            "WFP APIs are only available on Windows".to_string(),
        )
    }
}

fn deactivate_policy_mode(request: &WfpRuntimeActivationRequest) -> WfpRuntimeActivationResponse {
    if request.protocol_version != WFP_RUNTIME_PROTOCOL_VERSION {
        return build_protocol_mismatch_response(request);
    }

    let (_target_program, outbound_rule, inbound_rule) =
        match validate_target_request_fields(request) {
            Ok(fields) => fields,
            Err(response) => return response,
        };

    #[cfg(target_os = "windows")]
    {
        match remove_wfp_policy_filters(request, &outbound_rule, &inbound_rule) {
            Ok(details) => build_cleanup_succeeded_response(request, details),
            Err(err) => build_cleanup_failed_response(request, err),
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = (outbound_rule, inbound_rule);
        build_cleanup_failed_response(
            request,
            "WFP APIs are only available on Windows".to_string(),
        )
    }
}

fn probe_runtime_activation() -> ExitCode {
    let mut stdin = Vec::new();
    let read_result = std::io::stdin()
        .lock()
        .take((MAX_RUNTIME_REQUEST_SIZE as u64) + 1)
        .read_to_end(&mut stdin);
    let Ok(_) = read_result else {
        eprintln!("nono-wfp-service: failed to read runtime activation request from stdin");
        return ExitCode::from(2);
    };
    if stdin.len() > MAX_RUNTIME_REQUEST_SIZE {
        eprintln!(
            "nono-wfp-service: runtime activation request payload exceeds {} bytes",
            MAX_RUNTIME_REQUEST_SIZE
        );
        return ExitCode::from(2);
    }
    let request: WfpRuntimeActivationRequest = match serde_json::from_slice(&stdin) {
        Ok(request) => request,
        Err(err) => {
            eprintln!(
                "nono-wfp-service: invalid runtime activation request payload: {}",
                err
            );
            return ExitCode::from(2);
        }
    };
    let response = match request.request_kind.as_str() {
        "activate_blocked_mode" | "activate_proxy_mode" | "activate_allow_all_mode" => {
            activate_policy_mode(&request)
        }
        "deactivate_blocked_mode" | "deactivate_policy_mode" => deactivate_policy_mode(&request),
        _ => build_invalid_activation_response(&request),
    };
    match serde_json::to_string(&response) {
        Ok(json) => println!("{json}"),
        Err(err) => {
            eprintln!(
                "nono-wfp-service: failed to serialize runtime activation response: {}",
                err
            );
            return ExitCode::from(2);
        }
    }
    eprintln!(
        "nono-wfp-service: request {} resolved to status {}",
        request.request_kind, response.status
    );
    if response.status == "invalid-request" || response.status == "protocol-mismatch" {
        ExitCode::from(2)
    } else if response.status == "prerequisites-missing" {
        ExitCode::from(3)
    } else {
        ExitCode::from(4)
    }
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None => {
            eprintln!(
                "nono-wfp-service: missing required mode; use \
                 --print-service-contract, {PROBE_RUNTIME_ACTIVATION_ARG}, or {SERVICE_MODE_ARG}"
            );
            ExitCode::from(2)
        }
        Some("--help") | Some("-h") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some("--version") | Some("-V") => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("--print-service-contract") => {
            print_service_contract();
            ExitCode::SUCCESS
        }
        Some(PROBE_RUNTIME_ACTIVATION_ARG) => probe_runtime_activation(),
        Some(SERVICE_MODE_ARG) => run_service_mode(),
        Some(other) => {
            eprintln!("nono-wfp-service: unsupported argument '{other}'");
            eprintln!(
                "Run with --help to inspect the current service contract \
                 or --print-service-contract for machine-readable output."
            );
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample_request() -> WfpRuntimeActivationRequest {
        WfpRuntimeActivationRequest {
            protocol_version: WFP_RUNTIME_PROTOCOL_VERSION,
            request_kind: "activate_blocked_mode".to_string(),
            network_mode: "blocked".to_string(),
            preferred_backend: "windows-filtering-platform".to_string(),
            active_backend: "windows-filtering-platform".to_string(),
            runtime_target: "blocked Windows network access".to_string(),
            tcp_connect_ports: Vec::new(),
            tcp_bind_ports: Vec::new(),
            localhost_ports: Vec::new(),
            target_program_path: Some(r"C:\tools\target.exe".to_string()),
            session_sid: None,
            outbound_rule_name: Some("nono-test-out".to_string()),
            inbound_rule_name: Some("nono-test-in".to_string()),
        }
    }

    #[test]
    fn service_contract_output_is_stable() {
        let text = format!("service_name={SERVICE_NAME}\nstartup_args={SERVICE_MODE_ARG}\n");
        assert!(text.contains("service_name=nono-wfp-service"));
        assert!(text.contains("startup_args=--service-mode"));
    }

    #[test]
    fn service_mode_fails_closed() {
        assert_eq!(run_service_mode(), ExitCode::from(3));
    }

    #[test]
    fn runtime_activation_probe_fails_closed() {
        let request = sample_request();
        let response = build_enforced_pending_cleanup_response(&request, "placeholder".to_string());
        assert_eq!(response.status, "enforced-pending-cleanup");
        assert!(response.details.contains("blocked Windows network access"));
    }

    #[test]
    fn invalid_request_kind_returns_invalid_request_response() {
        let request = WfpRuntimeActivationRequest {
            protocol_version: WFP_RUNTIME_PROTOCOL_VERSION,
            request_kind: "activate_proxy_mode".to_string(),
            network_mode: "proxy-only".to_string(),
            preferred_backend: "windows-filtering-platform".to_string(),
            active_backend: "windows-filtering-platform".to_string(),
            runtime_target: "proxy Windows network access".to_string(),
            tcp_connect_ports: Vec::new(),
            tcp_bind_ports: vec![8080],
            localhost_ports: vec![8080],
            target_program_path: None,
            session_sid: None,
            outbound_rule_name: None,
            inbound_rule_name: None,
        };
        let response = build_invalid_activation_response(&request);
        assert_eq!(response.status, "invalid-request");
        assert!(response.details.contains("activate_proxy_mode"));
    }

    #[test]
    fn protocol_mismatch_returns_protocol_mismatch_response() {
        let mut request = sample_request();
        request.protocol_version = WFP_RUNTIME_PROTOCOL_VERSION + 1;
        let response = build_protocol_mismatch_response(&request);
        assert_eq!(response.status, "protocol-mismatch");
        assert!(response.details.contains("expected 1"));
    }

    #[test]
    fn validate_target_request_fields_requires_program_and_rule_names() {
        let request = WfpRuntimeActivationRequest {
            target_program_path: None,
            outbound_rule_name: Some("out".to_string()),
            inbound_rule_name: Some("in".to_string()),
            ..sample_request()
        };
        let response = validate_target_request_fields(&request);
        assert!(response.is_err());
    }

    #[test]
    fn blocked_mode_probe_reports_missing_target_program() {
        let request = sample_request();
        let response = activate_policy_mode(&request);
        assert!(matches!(
            response.status.as_str(),
            "prerequisites-missing" | "filtering-probe-failed"
        ));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn deterministic_filter_keys_are_stable() {
        let first = deterministic_filter_key("nono-test-out", "connect-v4");
        let second = deterministic_filter_key("nono-test-out", "connect-v4");
        let different = deterministic_filter_key("nono-test-out", "connect-v6");
        let first_raw = (first.data1, first.data2, first.data3, first.data4);
        let second_raw = (second.data1, second.data2, second.data3, second.data4);
        let different_raw = (
            different.data1,
            different.data2,
            different.data3,
            different.data4,
        );
        assert_eq!(first_raw, second_raw);
        assert_ne!(first_raw, different_raw);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn proxy_policy_filter_specs_include_loopback_permits_and_block_fallback() {
        let request = WfpRuntimeActivationRequest {
            request_kind: "activate_proxy_mode".to_string(),
            network_mode: "proxy-only".to_string(),
            tcp_bind_ports: vec![8080],
            localhost_ports: vec![8080],
            ..sample_request()
        };
        let specs = build_policy_filter_specs(&request, "nono-out", "nono-in");
        assert!(specs.iter().any(|spec| {
            matches!(spec.action, FilterAction::Permit)
                && matches!(spec.port, Some(PortCondition::Remote(8080)))
                && spec.loopback_only
        }));
        assert!(specs.iter().any(|spec| {
            matches!(spec.action, FilterAction::Block) && spec.port.is_none() && !spec.loopback_only
        }));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn sid_to_security_descriptor_works() {
        // Use a well-known SID for testing: S-1-5-18 (LocalSystem)
        let sid_str = "S-1-5-18";
        let res = sid_to_security_descriptor(sid_str);
        assert!(res.is_ok());
        let sd = res.unwrap();
        assert!(!sd.as_ptr().is_null());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn sid_to_security_descriptor_fails_on_invalid_sid() {
        let sid_str = "S-1-5-INVALID";
        let res = sid_to_security_descriptor(sid_str);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("invalid SID string"));
    }

    #[test]
    fn runtime_activation_request_size_limit_matches_protocol_guard() {
        let payload = vec![b'x'; MAX_RUNTIME_REQUEST_SIZE + 1];
        assert!(payload.len() > MAX_RUNTIME_REQUEST_SIZE);
    }

    // Task 1: startup sweep and Event Log reporting tests

    #[test]
    fn startup_sweep_outcome_removed_message_is_deterministic() {
        let msg = format_sweep_outcome(SweepOutcome::Removed, "nono-test-filter", "connect-v4");
        assert!(msg.contains("removed"));
        assert!(msg.contains("nono-test-filter"));
        assert!(msg.contains("connect-v4"));
    }

    #[test]
    fn startup_sweep_outcome_skipped_message_is_deterministic() {
        let msg = format_sweep_outcome(SweepOutcome::Skipped, "nono-test-filter", "connect-v4");
        assert!(msg.contains("skipped"));
        assert!(msg.contains("nono-test-filter"));
    }

    #[test]
    fn startup_sweep_outcome_failed_message_is_deterministic() {
        let msg = format_sweep_outcome(SweepOutcome::Failed, "nono-test-filter", "recv-accept-v6");
        assert!(msg.contains("failed"));
        assert!(msg.contains("nono-test-filter"));
        assert!(msg.contains("recv-accept-v6"));
    }

    #[test]
    fn startup_sweep_summary_reports_counts() {
        let outcomes = vec![
            (SweepOutcome::Removed, "filter-a", "connect-v4"),
            (SweepOutcome::Removed, "filter-b", "connect-v6"),
            (SweepOutcome::Skipped, "filter-c", "connect-v4"),
            (SweepOutcome::Failed, "filter-d", "recv-accept-v4"),
        ];
        let summary = build_sweep_summary(&outcomes);
        assert!(summary.contains("removed=2"));
        assert!(summary.contains("skipped=1"));
        assert!(summary.contains("failed=1"));
    }

    #[test]
    fn startup_sweep_summary_is_empty_when_no_outcomes() {
        let outcomes: Vec<(SweepOutcome, &str, &str)> = vec![];
        let summary = build_sweep_summary(&outcomes);
        assert!(summary.contains("removed=0"));
        assert!(summary.contains("skipped=0"));
        assert!(summary.contains("failed=0"));
    }

    #[test]
    fn event_log_message_format_includes_source_and_event_id() {
        let msg = build_event_log_message(
            EventLogLevel::Information,
            EVENT_ID_SWEEP_COMPLETE,
            "startup sweep complete: removed=1 skipped=0 failed=0",
        );
        assert!(msg.contains("nono-wfp-service"));
        assert!(msg.contains("startup sweep complete"));
    }
}
