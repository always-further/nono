//! Windows WFP backend service placeholder.
//!
//! This binary is the first repo-owned artifact for the future Windows WFP
//! backend. It establishes the expected Windows service contract and now owns
//! the first real user-mode WFP install/cleanup primitive for blocked-mode
//! activation.

#[path = "../windows_wfp_contract.rs"]
mod windows_wfp_contract;

use sha2::{Digest, Sha256};
use std::process::ExitCode;
use windows_wfp_contract::{
    WfpRuntimeActivationRequest, WfpRuntimeActivationResponse, WFP_RUNTIME_PROTOCOL_VERSION,
};

const SERVICE_NAME: &str = "nono-wfp-service";
const SERVICE_MODE_ARG: &str = "--service-mode";
const PROBE_RUNTIME_ACTIVATION_ARG: &str = "--probe-runtime-activation";
const EXPECTED_DRIVER_BINARY: &str = "nono-wfp-driver.sys";

#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;

#[cfg(target_os = "windows")]
use std::ptr::{null, null_mut};

#[cfg(target_os = "windows")]
use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::HANDLE,
        NetworkManagement::WindowsFilteringPlatform::{
            FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteByKey0,
            FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FwpmTransactionAbort0,
            FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_ACTION0, FWPM_ACTION0_0,
            FWPM_CONDITION_ALE_APP_ID, FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER0_0,
            FWPM_FILTER_CONDITION0, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWPM_SESSION0,
            FWPM_SUBLAYER_UNIVERSAL, FWP_ACTION_BLOCK, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE,
            FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_EMPTY, FWP_MATCH_EQUAL,
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

fn run_service_mode() -> ExitCode {
    eprintln!(
        "nono-wfp-service: service runtime is not implemented yet; \
         registration may target '{SERVICE_NAME} {SERVICE_MODE_ARG}', but startup still fails closed"
    );
    ExitCode::from(3)
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

fn build_invalid_activation_response(
    request: &WfpRuntimeActivationRequest,
) -> WfpRuntimeActivationResponse {
    WfpRuntimeActivationResponse {
        protocol_version: WFP_RUNTIME_PROTOCOL_VERSION,
        status: "invalid-request".to_string(),
        details: format!(
            "unsupported WFP runtime activation request kind `{}` for {}",
            request.request_kind, request.runtime_target
        ),
    }
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
            "request {} for {} installed target-attached blocked-mode enforcement and requires cleanup after launch: {}",
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
            "request {} for {} removed target-attached blocked-mode enforcement: {}",
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
            "request {} for {} could not remove target-attached blocked-mode enforcement: {}",
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
            "request {} for {} could not install the backend-owned filtering probe: {}",
            request.request_kind, request.runtime_target, details
        ),
    }
}

fn current_driver_binary_path() -> Result<std::path::PathBuf, String> {
    let exe = std::env::current_exe()
        .map_err(|err| format!("failed to resolve current service binary path: {}", err))?;
    let parent = exe.parent().ok_or_else(|| {
        format!(
            "failed to resolve parent directory for current service binary {}",
            exe.display()
        )
    })?;
    Ok(parent.join(EXPECTED_DRIVER_BINARY))
}

fn validate_target_request_fields(
    request: &WfpRuntimeActivationRequest,
) -> Result<(std::path::PathBuf, String, String), WfpRuntimeActivationResponse> {
    let target_program = request
        .target_program_path
        .as_ref()
        .map(std::path::PathBuf::from)
        .ok_or_else(|| {
            build_invalid_activation_response(&WfpRuntimeActivationRequest {
                request_kind: request.request_kind.clone(),
                ..request.clone()
            })
        })?;
    let outbound_rule = request.outbound_rule_name.clone().ok_or_else(|| {
        build_invalid_activation_response(&WfpRuntimeActivationRequest {
            request_kind: request.request_kind.clone(),
            ..request.clone()
        })
    })?;
    let inbound_rule = request.inbound_rule_name.clone().ok_or_else(|| {
        build_invalid_activation_response(&WfpRuntimeActivationRequest {
            request_kind: request.request_kind.clone(),
            ..request.clone()
        })
    })?;
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
    GUID::from_u128(u128::from_be_bytes(bytes))
}

#[cfg(target_os = "windows")]
fn open_wfp_engine() -> Result<WfpEngine, String> {
    let session: FWPM_SESSION0 = zeroed();
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
fn get_app_id_blob(target_program: &std::path::Path) -> Result<WfpAppIdBlob, String> {
    let path_wide = to_utf16_null(target_program.as_os_str());
    let mut blob: *mut FWP_BYTE_BLOB = null_mut();
    // SAFETY: path_wide is a valid null-terminated UTF-16 buffer for the target
    // program path, and blob points to writable storage for the returned pointer.
    let status = unsafe { FwpmGetAppIdFromFileName0(path_wide.as_ptr(), &mut blob) };
    if status != 0 {
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
fn add_block_filter(
    engine: &WfpEngine,
    filter_key: GUID,
    layer_key: GUID,
    app_id_blob: *mut FWP_BYTE_BLOB,
) -> Result<(), String> {
    let mut condition = FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_ALE_APP_ID,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_BYTE_BLOB_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                byteBlob: app_id_blob,
            },
        },
    };
    let action = FWPM_ACTION0 {
        r#type: FWP_ACTION_BLOCK,
        Anonymous: FWPM_ACTION0_0 {
            filterType: GUID::from_u128(0),
        },
    };
    let mut filter: FWPM_FILTER0 = zeroed();
    filter.filterKey = filter_key;
    filter.displayData = FWPM_DISPLAY_DATA0 {
        name: null_mut(),
        description: null_mut(),
    };
    filter.layerKey = layer_key;
    filter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
    filter.weight.r#type = FWP_EMPTY;
    filter.numFilterConditions = 1;
    filter.filterCondition = &mut condition;
    filter.action = action;
    filter.Anonymous = FWPM_FILTER0_0 { rawContext: 0 };

    let mut filter_id = 0u64;
    // SAFETY: engine handle is valid; filter points to initialized WFP POD data
    // whose nested pointers remain valid for the duration of the call.
    let status = unsafe { FwpmFilterAdd0(engine.0, &filter, null_mut(), &mut filter_id) };
    if status != 0 {
        return Err(format_windows_error(
            status,
            "failed to install WFP blocked-mode filter",
        ));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn delete_block_filter(engine: &WfpEngine, filter_key: GUID) -> Result<(), String> {
    // SAFETY: engine handle is valid and filter_key points to an initialized GUID.
    let status = unsafe { FwpmFilterDeleteByKey0(engine.0, &filter_key) };
    if status != 0 {
        return Err(format_windows_error(
            status,
            "failed to delete WFP blocked-mode filter",
        ));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn install_wfp_blocked_mode_filters(
    target_program: &std::path::Path,
    outbound_rule: &str,
    inbound_rule: &str,
) -> Result<String, String> {
    let engine = open_wfp_engine()?;
    let app_id = get_app_id_blob(target_program)?;
    let transaction = WfpTransaction::begin(&engine)?;

    for layer in build_wfp_layer_specs() {
        let base = if layer.rule_name == "outbound" {
            outbound_rule
        } else {
            inbound_rule
        };
        let filter_key = deterministic_filter_key(base, layer.label);
        add_block_filter(&engine, filter_key, layer.key, app_id.as_ptr())?;
    }

    transaction.commit()?;
    Ok(format!(
        "installed WFP app-id block filters for {} using outbound rule base {} and inbound rule base {}",
        target_program.display(),
        outbound_rule,
        inbound_rule
    ))
}

#[cfg(target_os = "windows")]
fn remove_wfp_blocked_mode_filters(
    outbound_rule: &str,
    inbound_rule: &str,
) -> Result<String, String> {
    let engine = open_wfp_engine()?;
    let transaction = WfpTransaction::begin(&engine)?;

    for layer in build_wfp_layer_specs() {
        let base = if layer.rule_name == "outbound" {
            outbound_rule
        } else {
            inbound_rule
        };
        let filter_key = deterministic_filter_key(base, layer.label);
        delete_block_filter(&engine, filter_key)?;
    }

    transaction.commit()?;
    Ok(format!(
        "removed WFP app-id block filters for outbound rule base {} and inbound rule base {}",
        outbound_rule, inbound_rule
    ))
}

fn activate_blocked_mode(request: &WfpRuntimeActivationRequest) -> WfpRuntimeActivationResponse {
    if request.protocol_version != WFP_RUNTIME_PROTOCOL_VERSION {
        return build_protocol_mismatch_response(request);
    }
    if request.network_mode != "blocked" {
        return build_invalid_activation_response(request);
    }

    let driver_binary_path = match current_driver_binary_path() {
        Ok(path) => path,
        Err(err) => return build_prerequisites_missing_response(err),
    };
    if !driver_binary_path.exists() {
        return build_prerequisites_missing_response(format!(
            "expected driver artifact is missing beside the service host: {}",
            driver_binary_path.display()
        ));
    }

    let (target_program, outbound_rule, inbound_rule) =
        match validate_target_request_fields(request) {
            Ok(fields) => fields,
            Err(response) => return response,
        };
    if !target_program.exists() {
        return build_prerequisites_missing_response(format!(
            "target program for blocked-mode enforcement does not exist: {}",
            target_program.display()
        ));
    }

    #[cfg(target_os = "windows")]
    {
        match install_wfp_blocked_mode_filters(&target_program, &outbound_rule, &inbound_rule) {
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

fn deactivate_blocked_mode(request: &WfpRuntimeActivationRequest) -> WfpRuntimeActivationResponse {
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
        match remove_wfp_blocked_mode_filters(&outbound_rule, &inbound_rule) {
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
    let stdin = std::io::read_to_string(std::io::stdin());
    let Ok(stdin) = stdin else {
        eprintln!("nono-wfp-service: failed to read runtime activation request from stdin");
        return ExitCode::from(2);
    };
    let request: WfpRuntimeActivationRequest = match serde_json::from_str(&stdin) {
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
        "activate_blocked_mode" => activate_blocked_mode(&request),
        "deactivate_blocked_mode" => deactivate_blocked_mode(&request),
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
mod tests {
    use super::*;

    fn sample_request() -> WfpRuntimeActivationRequest {
        WfpRuntimeActivationRequest {
            protocol_version: WFP_RUNTIME_PROTOCOL_VERSION,
            request_kind: "activate_blocked_mode".to_string(),
            network_mode: "blocked".to_string(),
            preferred_backend: "windows-filtering-platform".to_string(),
            active_backend: "none".to_string(),
            runtime_target: "blocked Windows network access".to_string(),
            target_program_path: Some(r"C:\tools\target.exe".to_string()),
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
            active_backend: "none".to_string(),
            runtime_target: "proxy Windows network access".to_string(),
            target_program_path: None,
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
        let response = activate_blocked_mode(&request);
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
}
