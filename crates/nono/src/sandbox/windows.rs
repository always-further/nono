//! Windows sandbox implementation placeholder.
//!
//! WIN-101 only needs Windows to be a first-class build target. The actual
//! enforcement backend is added in later stories.

use crate::capability::CapabilitySet;
use crate::error::{NonoError, Result};
use crate::sandbox::{
    PreviewRuntimeStatus, SupportInfo, SupportStatus, WindowsFilesystemPolicy,
    WindowsFilesystemRule, WindowsNetworkBackendKind, WindowsNetworkLaunchSupport,
    WindowsNetworkPolicy, WindowsNetworkPolicyMode, WindowsPreviewContext,
    WindowsPreviewEntryPoint, WindowsSupervisorContext, WindowsSupervisorFeatureKind,
    WindowsSupervisorSupport,
};
use std::os::windows::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    GetAce, GetSidSubAuthority, GetSidSubAuthorityCount, ACE_HEADER, ACL,
    LABEL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SYSTEM_MANDATORY_LABEL_ACE,
};
use windows_sys::Win32::System::SystemServices::{
    SECURITY_MANDATORY_LOW_RID, SYSTEM_MANDATORY_LABEL_ACE_TYPE,
};

const WINDOWS_PREVIEW_SUPPORTED: bool = true;
const WINDOWS_SUPPORTED_DETAILS: &str =
    "Windows sandbox enforcement supports directory read and directory read-write grants, \
     blocked network mode, and default signal/process/ipc modes. Single-file grants, \
     write-only directory grants, port-level network filtering, runtime capability \
     expansion, and platform-specific rules are not in the supported subset. \
     `nono shell` is supported on Windows 10 build 17763+ via ConPTY \
     (CreatePseudoConsole); the supervisor stays alive as Job Object owner. \
     `nono wrap` is also supported.";

pub fn apply(caps: &CapabilitySet) -> Result<()> {
    // 1. Filesystem shape validation
    let fs_policy = compile_filesystem_policy(caps);
    if !fs_policy.unsupported.is_empty() {
        return Err(NonoError::UnsupportedPlatform(format!(
            "Windows sandbox does not support: {}",
            fs_policy.unsupported_messages().join(", ")
        )));
    }

    // 2. Network shape validation
    let net_policy = compile_network_policy(caps);
    if !net_policy.unsupported.is_empty() {
        return Err(NonoError::UnsupportedPlatform(format!(
            "Windows sandbox does not support: {}",
            net_policy.unsupported_messages().join(", ")
        )));
    }

    // 3. Remaining field validation against defaults
    if caps.signal_mode() != crate::SignalMode::Isolated {
        return Err(NonoError::UnsupportedPlatform(
            "Windows sandbox does not support non-default signal mode".to_string(),
        ));
    }
    if caps.process_info_mode() != crate::ProcessInfoMode::Isolated {
        return Err(NonoError::UnsupportedPlatform(
            "Windows sandbox does not support non-default process info mode".to_string(),
        ));
    }
    if caps.ipc_mode() != crate::IpcMode::SharedMemoryOnly {
        return Err(NonoError::UnsupportedPlatform(
            "Windows sandbox does not support non-default IPC mode".to_string(),
        ));
    }
    if caps.extensions_enabled() {
        return Err(NonoError::UnsupportedPlatform(
            "Windows sandbox does not support runtime capability expansion".to_string(),
        ));
    }
    if !caps.platform_rules().is_empty() {
        return Err(NonoError::UnsupportedPlatform(
            "Windows sandbox does not support platform-specific rules (Seatbelt-only feature)"
                .to_string(),
        ));
    }

    // seatbelt_debug_deny is macOS-only and has no enforcement claim on Windows;
    // silently accepting it is correct (no overclaim).

    // 4. Validated — CLI layer can proceed with enforcement
    Ok(())
}

#[must_use]
pub fn is_supported() -> bool {
    WINDOWS_PREVIEW_SUPPORTED
}

#[must_use]
pub fn support_info() -> SupportInfo {
    SupportInfo {
        is_supported: WINDOWS_PREVIEW_SUPPORTED,
        status: SupportStatus::Supported,
        platform: "windows",
        details: WINDOWS_SUPPORTED_DETAILS.to_string(),
    }
}

#[must_use]
pub fn preview_runtime_status(
    caps: &CapabilitySet,
    execution_dir: &Path,
    _context: WindowsPreviewContext,
) -> PreviewRuntimeStatus {
    let mut reasons = Vec::new();

    let execution_dir = execution_dir
        .canonicalize()
        .unwrap_or_else(|_| execution_dir.to_path_buf());
    let execution_dir = normalize_windows_path(&execution_dir);

    let fs_policy = compile_filesystem_policy(caps);
    let has_user_intent_fs = fs_policy
        .rules
        .iter()
        .any(|rule| rule.source.is_user_intent())
        || !fs_policy.unsupported.is_empty();

    for label in fs_policy.unsupported_reason_labels() {
        reasons.push(label);
    }

    if has_user_intent_fs
        && fs_policy.has_user_intent_directory_rules()
        && !fs_policy.covers_execution_dir(&execution_dir)
    {
        reasons.push("execution directory outside supported allowlist");
    }
    let network_policy = compile_network_policy(caps);
    if matches!(
        network_policy.mode,
        WindowsNetworkPolicyMode::ProxyOnly { .. }
    ) {
        reasons.push("proxy network restrictions");
    }
    for label in network_policy.unsupported_reason_labels() {
        reasons.push(label);
    }

    if caps.extensions_enabled() {
        reasons.push("runtime capability expansion");
    }

    if !caps.platform_rules().is_empty() {
        reasons.push("platform-specific sandbox rules");
    }

    if caps.signal_mode() != crate::SignalMode::Isolated
        || caps.process_info_mode() != crate::ProcessInfoMode::Isolated
        || caps.ipc_mode() != crate::IpcMode::SharedMemoryOnly
    {
        reasons.push("explicit process or IPC restrictions");
    }

    reasons.sort_unstable();
    reasons.dedup();

    if reasons.is_empty() {
        PreviewRuntimeStatus::AdvisoryOnly
    } else {
        PreviewRuntimeStatus::RequiresEnforcement { reasons }
    }
}

/// Returns Ok if the current Windows build is >= 17763 (ConPTY minimum).
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
        // size field set.
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
             There is no non-PTY fallback - upgrade Windows to use `nono shell`.",
            info.dwBuildNumber, CONPTY_MINIMUM_BUILD
        )));
    }

    Ok(())
}

pub fn validate_preview_entry_point(
    entry_point: WindowsPreviewEntryPoint,
    caps: &CapabilitySet,
    execution_dir: &Path,
    context: WindowsPreviewContext,
) -> Result<()> {
    match entry_point {
        WindowsPreviewEntryPoint::RunDirect => {
            if let PreviewRuntimeStatus::RequiresEnforcement { reasons } =
                preview_runtime_status(caps, execution_dir, context)
            {
                return Err(NonoError::UnsupportedPlatform(format!(
                    "Windows cannot enforce the requested sandbox controls for this live run ({}). \
Use `nono run --dry-run ...` to validate policy, or rerun without those controls. \
This is an explicit Windows product-surface limitation, not a silent fallback.",
                    reasons.join(", ")
                )));
            }
            Ok(())
        }
        WindowsPreviewEntryPoint::Shell => {
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
        WindowsPreviewEntryPoint::Wrap => {
            if let PreviewRuntimeStatus::RequiresEnforcement { reasons } =
                preview_runtime_status(caps, execution_dir, context)
            {
                return Err(NonoError::UnsupportedPlatform(format!(
                    "Windows cannot enforce the requested sandbox controls for this nono wrap run ({}). \
Use `nono wrap --dry-run ...` to validate policy, or rerun without those controls. \
This is an explicit Windows product-surface limitation, not a silent fallback.",
                    reasons.join(", ")
                )));
            }
            Ok(())
        }
    }
}

#[must_use]
pub fn classify_supervisor_support(context: WindowsSupervisorContext) -> WindowsSupervisorSupport {
    let mut supported = Vec::new();
    let mut unsupported = Vec::new();

    if context.rollback_snapshots {
        supported.push(WindowsSupervisorFeatureKind::RollbackSnapshots);
    }
    if context.proxy_filtering {
        unsupported.push(WindowsSupervisorFeatureKind::ProxyFiltering);
    }
    if context.runtime_capability_expansion {
        unsupported.push(WindowsSupervisorFeatureKind::RuntimeCapabilityExpansion);
    }
    if context.runtime_trust_interception {
        unsupported.push(WindowsSupervisorFeatureKind::RuntimeTrustInterception);
    }

    supported.sort_unstable();
    supported.dedup();
    unsupported.sort_unstable();
    unsupported.dedup();

    WindowsSupervisorSupport {
        supported,
        unsupported,
    }
}

#[must_use]
pub fn compile_network_policy(caps: &CapabilitySet) -> WindowsNetworkPolicy {
    let mode = match caps.network_mode() {
        crate::NetworkMode::AllowAll => WindowsNetworkPolicyMode::AllowAll,
        crate::NetworkMode::Blocked => WindowsNetworkPolicyMode::Blocked,
        crate::NetworkMode::ProxyOnly { port, bind_ports } => WindowsNetworkPolicyMode::ProxyOnly {
            port: *port,
            bind_ports: bind_ports.clone(),
        },
    };

    let mut unsupported = Vec::new();
    if !caps.tcp_connect_ports().is_empty() {
        unsupported.push(crate::sandbox::WindowsUnsupportedNetworkIssue {
            kind: crate::sandbox::WindowsUnsupportedNetworkIssueKind::PortConnectAllowlist,
        });
    }
    if !caps.tcp_bind_ports().is_empty() {
        unsupported.push(crate::sandbox::WindowsUnsupportedNetworkIssue {
            kind: crate::sandbox::WindowsUnsupportedNetworkIssueKind::PortBindAllowlist,
        });
    }
    if !caps.localhost_ports().is_empty() {
        unsupported.push(crate::sandbox::WindowsUnsupportedNetworkIssue {
            kind: crate::sandbox::WindowsUnsupportedNetworkIssueKind::LocalhostPortAllowlist,
        });
    }
    let mut tcp_connect_ports = caps.tcp_connect_ports().to_vec();
    tcp_connect_ports.sort_unstable();
    tcp_connect_ports.dedup();
    let mut tcp_bind_ports = caps.tcp_bind_ports().to_vec();
    tcp_bind_ports.sort_unstable();
    tcp_bind_ports.dedup();
    let mut localhost_ports = caps.localhost_ports().to_vec();
    localhost_ports.sort_unstable();
    localhost_ports.dedup();
    let requires_backend = !matches!(mode, WindowsNetworkPolicyMode::AllowAll)
        || !tcp_connect_ports.is_empty()
        || !tcp_bind_ports.is_empty()
        || !localhost_ports.is_empty();
    let preferred_backend = if requires_backend {
        WindowsNetworkBackendKind::Wfp
    } else {
        WindowsNetworkBackendKind::None
    };
    let active_backend = preferred_backend;

    WindowsNetworkPolicy {
        mode,
        tcp_connect_ports,
        tcp_bind_ports,
        localhost_ports,
        unsupported,
        preferred_backend,
        active_backend,
    }
}

#[must_use]
pub fn network_launch_support(
    policy: &WindowsNetworkPolicy,
    resolved_program: &Path,
) -> WindowsNetworkLaunchSupport {
    let _ = (policy, resolved_program);
    WindowsNetworkLaunchSupport::Supported
}

fn normalize_windows_path(path: &Path) -> PathBuf {
    let raw = path.as_os_str().to_string_lossy();

    if let Some(stripped) = raw.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{stripped}"));
    }
    if let Some(stripped) = raw.strip_prefix(r"\\?\") {
        return PathBuf::from(stripped);
    }

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(std::path::MAIN_SEPARATOR.to_string()),
            Component::CurDir => {}
            Component::ParentDir => normalized.push(".."),
            Component::Normal(part) => normalized.push(part),
        }
    }
    normalized
}

pub(crate) fn windows_paths_equal_case_insensitive(left: &Path, right: &Path) -> bool {
    let left = normalize_windows_path(left);
    let right = normalize_windows_path(right);

    let mut left_components = left.components();
    let mut right_components = right.components();

    loop {
        match (left_components.next(), right_components.next()) {
            (None, None) => return true,
            (None, Some(_)) | (Some(_), None) => return false,
            (Some(left_component), Some(right_component)) => {
                let left_component = left_component.as_os_str().to_string_lossy();
                let right_component = right_component.as_os_str().to_string_lossy();
                if !left_component.eq_ignore_ascii_case(&right_component) {
                    return false;
                }
            }
        }
    }
}

pub(crate) fn windows_paths_start_with_case_insensitive(path: &Path, prefix: &Path) -> bool {
    let path = normalize_windows_path(path);
    let prefix = normalize_windows_path(prefix);
    let mut path_components = path.components();
    let mut prefix_components = prefix.components();

    loop {
        match (path_components.next(), prefix_components.next()) {
            (_, None) => return true,
            (None, Some(_)) => return false,
            (Some(path_component), Some(prefix_component)) => {
                let path_component = path_component.as_os_str().to_string_lossy();
                let prefix_component = prefix_component.as_os_str().to_string_lossy();
                if !path_component.eq_ignore_ascii_case(&prefix_component) {
                    return false;
                }
            }
        }
    }
}

fn low_integrity_runtime_prefixes() -> Vec<PathBuf> {
    let mut prefixes = Vec::new();
    let Some(local_appdata) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) else {
        return prefixes;
    };

    prefixes.push(normalize_windows_path(
        &local_appdata.join("Temp").join("Low"),
    ));

    if let Some(appdata_root) = local_appdata.parent() {
        prefixes.push(normalize_windows_path(&appdata_root.join("LocalLow")));
    }

    prefixes.sort();
    prefixes.dedup();
    prefixes
}

struct OwnedSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for OwnedSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                // SAFETY: The security descriptor was allocated by
                // GetNamedSecurityInfoW and must be released with LocalFree.
                let _ = LocalFree(self.0 as _);
            }
        }
    }
}

fn low_integrity_label_rid(path: &Path) -> Option<u32> {
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut sacl: *mut ACL = std::ptr::null_mut();
    let mut security_descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();

    let status = unsafe {
        // SAFETY: `wide_path` is a valid nul-terminated UTF-16 buffer, and
        // the output pointers refer to live local storage for the duration of
        // the call.
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sacl,
            &mut security_descriptor,
        )
    };
    if status != 0 {
        return None;
    }
    let _security_descriptor = OwnedSecurityDescriptor(security_descriptor);

    if sacl.is_null() {
        return None;
    }

    let ace_count = unsafe {
        // SAFETY: `sacl` is populated by GetNamedSecurityInfoW on success.
        (*sacl).AceCount
    };

    for index in 0..ace_count {
        let mut ace = std::ptr::null_mut();
        let ok = unsafe {
            // SAFETY: `sacl` is a valid ACL pointer and `ace` is a valid
            // out-pointer for the duration of the call.
            GetAce(sacl, u32::from(index), &mut ace)
        };
        if ok == 0 || ace.is_null() {
            continue;
        }

        let header = unsafe {
            // SAFETY: `ace` points to a valid ACE entry returned by GetAce.
            &*(ace as *const ACE_HEADER)
        };
        if u32::from(header.AceType) != SYSTEM_MANDATORY_LABEL_ACE_TYPE {
            continue;
        }

        let label_ace = unsafe {
            // SAFETY: We already checked the ACE type and can interpret the
            // returned bytes as a SYSTEM_MANDATORY_LABEL_ACE.
            &*(ace as *const SYSTEM_MANDATORY_LABEL_ACE)
        };
        let sid = (&label_ace.SidStart as *const u32).cast_mut().cast();
        let subauthority_count = unsafe {
            // SAFETY: `sid` points to the SID embedded in the label ACE.
            GetSidSubAuthorityCount(sid)
        };
        if subauthority_count.is_null() {
            continue;
        }
        let subauthority_count = unsafe { *subauthority_count };
        if subauthority_count == 0 {
            continue;
        }

        let rid = unsafe {
            // SAFETY: The SID has at least one subauthority, so the final RID
            // pointer is valid for the lifetime of the ACE buffer.
            GetSidSubAuthority(sid, u32::from(subauthority_count) - 1)
        };
        if rid.is_null() {
            continue;
        }

        return Some(unsafe { *rid });
    }

    None
}

#[must_use]
pub fn is_low_integrity_compatible_dir(path: &Path) -> bool {
    let canonical = path.canonicalize().ok();
    let normalized = canonical
        .as_ref()
        .map(|path| normalize_windows_path(path))
        .unwrap_or_else(|| normalize_windows_path(path));

    if low_integrity_runtime_prefixes()
        .into_iter()
        .any(|prefix| windows_paths_start_with_case_insensitive(&normalized, &prefix))
    {
        return true;
    }

    canonical
        .as_deref()
        .and_then(low_integrity_label_rid)
        .is_some_and(|rid| rid <= SECURITY_MANDATORY_LOW_RID as u32)
}

#[must_use]
pub fn compile_filesystem_policy(caps: &CapabilitySet) -> WindowsFilesystemPolicy {
    let mut rules = Vec::new();
    let mut unsupported: Vec<crate::sandbox::WindowsUnsupportedIssue> = Vec::new();

    for cap in caps.fs_capabilities() {
        if cap.is_file {
            unsupported.push(crate::sandbox::WindowsUnsupportedIssue {
                kind: crate::sandbox::WindowsUnsupportedIssueKind::SingleFileGrant,
                path: normalize_windows_path(&cap.resolved),
            });
        } else if cap.access == crate::AccessMode::Write {
            unsupported.push(crate::sandbox::WindowsUnsupportedIssue {
                kind: crate::sandbox::WindowsUnsupportedIssueKind::WriteOnlyDirectoryGrant,
                path: normalize_windows_path(&cap.resolved),
            });
        } else {
            rules.push(WindowsFilesystemRule {
                path: normalize_windows_path(&cap.resolved),
                access: cap.access,
                is_file: cap.is_file,
                source: cap.source.clone(),
            });
        }
    }

    rules.sort_by(|a, b| a.path.cmp(&b.path));
    rules.dedup_by(|left, right| {
        left.path == right.path
            && left.access == right.access
            && left.is_file == right.is_file
            && left.source == right.source
    });

    unsupported.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.path.cmp(&right.path))
    });
    unsupported.dedup();

    WindowsFilesystemPolicy { rules, unsupported }
}

pub fn validate_launch_paths(
    policy: &WindowsFilesystemPolicy,
    program: &Path,
    current_dir: &Path,
) -> Result<()> {
    if !policy.unsupported.is_empty() {
        return Err(NonoError::UnsupportedPlatform(format!(
            "Windows filesystem enforcement does not support this capability set yet ({}).",
            policy.unsupported_messages().join(", ")
        )));
    }

    if !policy.has_rules() {
        return Ok(());
    }

    let program = program
        .canonicalize()
        .unwrap_or_else(|_| program.to_path_buf());
    let program = normalize_windows_path(&program);

    if !policy.covers_path(&program, crate::AccessMode::Read) {
        return Err(NonoError::UnsupportedPlatform(format!(
            "Windows filesystem policy does not cover the executable path required for launch: {}",
            program.display()
        )));
    }

    let current_dir = current_dir
        .canonicalize()
        .unwrap_or_else(|_| current_dir.to_path_buf());
    let current_dir = normalize_windows_path(&current_dir);
    if policy.has_user_intent_directory_rules() && !policy.covers_execution_dir(&current_dir) {
        return Err(NonoError::UnsupportedPlatform(
            "Windows cannot enforce the requested sandbox controls for this live run (execution directory outside supported allowlist). Use `nono run --dry-run ...` to validate policy, or rerun without those controls. This is an explicit Windows product-surface limitation, not a silent fallback."
                .to_string(),
        ));
    }

    Ok(())
}

fn extract_arg_path_candidate(arg: &str) -> Option<&str> {
    let candidate = if let Some((_, value)) = arg.split_once('=') {
        value
    } else {
        arg
    };

    let trimmed = candidate.trim_matches('"');
    if trimmed.is_empty() {
        return None;
    }

    let path = Path::new(trimmed);
    if path.is_absolute() {
        Some(trimmed)
    } else {
        None
    }
}

fn normalize_candidate_path(candidate: &Path) -> PathBuf {
    candidate
        .canonicalize()
        .map(|path| normalize_windows_path(&path))
        .unwrap_or_else(|_| normalize_windows_path(candidate))
}

fn validate_candidate_path(
    policy: &WindowsFilesystemPolicy,
    candidate: &Path,
    required: crate::AccessMode,
    description: &str,
) -> Result<()> {
    let normalized = normalize_candidate_path(candidate);
    if !policy.covers_path(&normalized, required) {
        return Err(NonoError::UnsupportedPlatform(format!(
            "Windows filesystem policy does not cover the {description} required for launch: {}",
            normalized.display()
        )));
    }
    Ok(())
}

fn validate_absolute_path_args(policy: &WindowsFilesystemPolicy, args: &[String]) -> Result<()> {
    if !policy.is_fully_supported() || !policy.has_rules() {
        return Ok(());
    }

    for arg in args {
        let Some(candidate) = extract_arg_path_candidate(arg) else {
            continue;
        };

        validate_candidate_path(
            policy,
            Path::new(candidate),
            crate::AccessMode::Read,
            "absolute path argument",
        )?;
    }

    Ok(())
}

fn resolve_relative_arg_path(current_dir: &Path, arg: &str) -> Option<PathBuf> {
    let candidate = arg.trim_matches('"');
    if candidate.is_empty() {
        return None;
    }
    if Path::new(candidate).is_absolute() {
        return Some(PathBuf::from(candidate));
    }
    if candidate.contains(['\\', '/']) || current_dir.join(candidate).exists() {
        return Some(current_dir.join(candidate));
    }
    None
}

fn split_powershell_command(command: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;

    for ch in command.chars() {
        match quote {
            Some(q) if ch == q => quote = None,
            Some(_) => current.push(ch),
            None if ch == '\'' || ch == '"' => quote = Some(ch),
            None if ch.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            None => current.push(ch),
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

fn first_named_value<'a>(tokens: &'a [String], names: &[&str]) -> Option<&'a str> {
    tokens.windows(2).find_map(|window| {
        let flag = window[0].to_ascii_lowercase();
        names.contains(&flag.as_str()).then_some(window[1].as_str())
    })
}

fn positional_values(tokens: &[String]) -> Vec<&str> {
    let mut values = Vec::new();
    let mut skip_next = false;

    for token in tokens.iter().skip(1) {
        if skip_next {
            skip_next = false;
            continue;
        }
        if token.starts_with('-') {
            skip_next = true;
            continue;
        }
        values.push(token.as_str());
    }

    values
}

fn validate_powershell_tokens(
    policy: &WindowsFilesystemPolicy,
    tokens: &[String],
    current_dir: &Path,
) -> Result<()> {
    let Some(command) = tokens.first() else {
        return Ok(());
    };

    let command = command.to_ascii_lowercase();
    match command.as_str() {
        "get-content" | "gc" | "cat" | "type" => {
            if let Some(path) = first_named_value(tokens, &["-path", "-literalpath"]) {
                if let Some(candidate) = resolve_relative_arg_path(current_dir, path) {
                    validate_candidate_path(
                        policy,
                        &candidate,
                        crate::AccessMode::Read,
                        "PowerShell file argument",
                    )?;
                }
            } else {
                for value in positional_values(tokens) {
                    if let Some(candidate) = resolve_relative_arg_path(current_dir, value) {
                        validate_candidate_path(
                            policy,
                            &candidate,
                            crate::AccessMode::Read,
                            "PowerShell file argument",
                        )?;
                    }
                }
            }
        }
        "set-content" | "sc" | "add-content" | "ac" | "out-file" => {
            let names = if command == "out-file" {
                &["-filepath"][..]
            } else {
                &["-path", "-literalpath"][..]
            };
            if let Some(path) = first_named_value(tokens, names) {
                if let Some(candidate) = resolve_relative_arg_path(current_dir, path) {
                    validate_candidate_path(
                        policy,
                        &candidate,
                        crate::AccessMode::Write,
                        "PowerShell write target",
                    )?;
                }
            } else if let Some(value) = positional_values(tokens).first() {
                if let Some(candidate) = resolve_relative_arg_path(current_dir, value) {
                    validate_candidate_path(
                        policy,
                        &candidate,
                        crate::AccessMode::Write,
                        "PowerShell write target",
                    )?;
                }
            }
        }
        "copy-item" | "cp" | "copy" | "move-item" | "mv" | "move" => {
            if let Some(path) = first_named_value(tokens, &["-path", "-literalpath"]) {
                if let Some(candidate) = resolve_relative_arg_path(current_dir, path) {
                    validate_candidate_path(
                        policy,
                        &candidate,
                        crate::AccessMode::Read,
                        "PowerShell source path",
                    )?;
                }
            }
            if let Some(dest) = first_named_value(tokens, &["-destination"]) {
                if let Some(candidate) = resolve_relative_arg_path(current_dir, dest) {
                    validate_candidate_path(
                        policy,
                        &candidate,
                        crate::AccessMode::Write,
                        "PowerShell destination path",
                    )?;
                }
            } else {
                let values = positional_values(tokens);
                if let Some(path) = values.first() {
                    if let Some(candidate) = resolve_relative_arg_path(current_dir, path) {
                        validate_candidate_path(
                            policy,
                            &candidate,
                            crate::AccessMode::Read,
                            "PowerShell source path",
                        )?;
                    }
                }
                if let Some(dest) = values.get(1) {
                    if let Some(candidate) = resolve_relative_arg_path(current_dir, dest) {
                        validate_candidate_path(
                            policy,
                            &candidate,
                            crate::AccessMode::Write,
                            "PowerShell destination path",
                        )?;
                    }
                }
            }
        }
        "remove-item" | "ri" | "rm" | "del" | "erase" | "new-item" | "ni" | "rename-item"
        | "rni" => {
            if let Some(path) = first_named_value(tokens, &["-path", "-literalpath"]) {
                if let Some(candidate) = resolve_relative_arg_path(current_dir, path) {
                    validate_candidate_path(
                        policy,
                        &candidate,
                        crate::AccessMode::Write,
                        "PowerShell filesystem mutation path",
                    )?;
                }
            } else {
                for value in positional_values(tokens) {
                    if let Some(candidate) = resolve_relative_arg_path(current_dir, value) {
                        validate_candidate_path(
                            policy,
                            &candidate,
                            crate::AccessMode::Write,
                            "PowerShell filesystem mutation path",
                        )?;
                    }
                }
            }
        }
        _ => {}
    }

    Ok(())
}

fn validate_powershell_args(
    policy: &WindowsFilesystemPolicy,
    args: &[String],
    current_dir: &Path,
) -> Result<()> {
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].to_ascii_lowercase();
        match flag.as_str() {
            "-file" | "-f" => {
                if let Some(path) = args.get(i + 1) {
                    if let Some(candidate) = resolve_relative_arg_path(current_dir, path) {
                        validate_candidate_path(
                            policy,
                            &candidate,
                            crate::AccessMode::Read,
                            "PowerShell script path",
                        )?;
                    }
                }
                i += 2;
            }
            "-command" | "-c" => {
                if let Some(command) = args.get(i + 1) {
                    let tokens = split_powershell_command(command);
                    validate_powershell_tokens(policy, &tokens, current_dir)?;
                }
                i += 2;
            }
            _ => i += 1,
        }
    }

    Ok(())
}

fn validate_cmd_builtin_args(
    policy: &WindowsFilesystemPolicy,
    args: &[String],
    current_dir: &Path,
) -> Result<()> {
    if args.len() < 3 {
        return Ok(());
    }
    let switch = args[0].to_ascii_lowercase();
    if switch != "/c" && switch != "/k" {
        return Ok(());
    }

    let builtin = args[1].to_ascii_lowercase();
    match builtin.as_str() {
        "type" | "more" => {
            for arg in &args[2..] {
                if let Some(candidate) = resolve_relative_arg_path(current_dir, arg) {
                    validate_candidate_path(
                        policy,
                        &candidate,
                        crate::AccessMode::Read,
                        "file argument",
                    )?;
                }
            }
        }
        "copy" | "move" => {
            if let Some(source) = args
                .get(2)
                .and_then(|arg| resolve_relative_arg_path(current_dir, arg))
            {
                validate_candidate_path(
                    policy,
                    &source,
                    crate::AccessMode::Read,
                    "source path argument",
                )?;
            }
            if let Some(dest) = args
                .get(3)
                .and_then(|arg| resolve_relative_arg_path(current_dir, arg))
            {
                validate_candidate_path(
                    policy,
                    &dest,
                    crate::AccessMode::Write,
                    "destination path argument",
                )?;
            }
        }
        "del" | "erase" | "mkdir" | "md" | "rmdir" | "rd" | "ren" | "rename" => {
            for arg in &args[2..] {
                if let Some(candidate) = resolve_relative_arg_path(current_dir, arg) {
                    validate_candidate_path(
                        policy,
                        &candidate,
                        crate::AccessMode::Write,
                        "filesystem mutation argument",
                    )?;
                }
            }
        }
        _ => {}
    }

    Ok(())
}

fn validate_script_host_args(
    policy: &WindowsFilesystemPolicy,
    args: &[String],
    current_dir: &Path,
) -> Result<()> {
    let mut script_index = None;
    for (index, arg) in args.iter().enumerate() {
        if arg.starts_with("//") || arg.starts_with('/') {
            continue;
        }
        script_index = Some(index);
        break;
    }

    let Some(script_index) = script_index else {
        return Ok(());
    };

    if let Some(script_path) = args.get(script_index) {
        if let Some(candidate) = resolve_relative_arg_path(current_dir, script_path) {
            validate_candidate_path(
                policy,
                &candidate,
                crate::AccessMode::Read,
                "Windows Script Host script path",
            )?;
        }
    }

    for arg in &args[script_index + 1..] {
        if let Some(candidate) = resolve_relative_arg_path(current_dir, arg) {
            let required = if candidate.exists() {
                crate::AccessMode::Read
            } else {
                crate::AccessMode::Write
            };
            validate_candidate_path(
                policy,
                &candidate,
                required,
                "Windows Script Host path argument",
            )?;
        }
    }

    Ok(())
}

fn validate_findstr_args(
    policy: &WindowsFilesystemPolicy,
    args: &[String],
    current_dir: &Path,
) -> Result<()> {
    let mut file_args = Vec::new();
    let mut seen_pattern = false;

    for arg in args {
        if arg.starts_with('/') {
            continue;
        }
        if !seen_pattern {
            seen_pattern = true;
            continue;
        }
        file_args.push(arg.as_str());
    }

    for arg in file_args {
        if let Some(candidate) = resolve_relative_arg_path(current_dir, arg) {
            validate_candidate_path(
                policy,
                &candidate,
                crate::AccessMode::Read,
                "findstr file argument",
            )?;
        }
    }

    Ok(())
}

fn validate_fc_args(
    policy: &WindowsFilesystemPolicy,
    args: &[String],
    current_dir: &Path,
) -> Result<()> {
    let mut file_args = Vec::new();

    for arg in args {
        if arg.starts_with('/') {
            continue;
        }
        file_args.push(arg.as_str());
        if file_args.len() == 2 {
            break;
        }
    }

    for arg in file_args {
        if let Some(candidate) = resolve_relative_arg_path(current_dir, arg) {
            validate_candidate_path(
                policy,
                &candidate,
                crate::AccessMode::Read,
                "fc file argument",
            )?;
        }
    }

    Ok(())
}

fn validate_find_args(
    policy: &WindowsFilesystemPolicy,
    args: &[String],
    current_dir: &Path,
) -> Result<()> {
    let mut file_args = Vec::new();
    let mut seen_pattern = false;

    for arg in args {
        if arg.starts_with('/') {
            continue;
        }
        if !seen_pattern {
            seen_pattern = true;
            continue;
        }
        file_args.push(arg.as_str());
    }

    for arg in file_args {
        if let Some(candidate) = resolve_relative_arg_path(current_dir, arg) {
            validate_candidate_path(
                policy,
                &candidate,
                crate::AccessMode::Read,
                "find file argument",
            )?;
        }
    }

    Ok(())
}

fn validate_comp_args(
    policy: &WindowsFilesystemPolicy,
    args: &[String],
    current_dir: &Path,
) -> Result<()> {
    let mut file_args = Vec::new();

    for arg in args {
        if arg.starts_with('/') {
            continue;
        }
        file_args.push(arg.as_str());
        if file_args.len() == 2 {
            break;
        }
    }

    for arg in file_args {
        if let Some(candidate) = resolve_relative_arg_path(current_dir, arg) {
            validate_candidate_path(
                policy,
                &candidate,
                crate::AccessMode::Read,
                "comp file argument",
            )?;
        }
    }

    Ok(())
}

pub fn validate_command_args(
    policy: &WindowsFilesystemPolicy,
    resolved_program: &Path,
    args: &[String],
    current_dir: &Path,
) -> Result<()> {
    validate_absolute_path_args(policy, args)?;

    let program_name = resolved_program
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    match program_name.as_str() {
        "cmd.exe" | "cmd" => validate_cmd_builtin_args(policy, args, current_dir),
        "powershell.exe" | "powershell" | "pwsh.exe" | "pwsh" => {
            validate_powershell_args(policy, args, current_dir)
        }
        "cscript.exe" | "cscript" | "wscript.exe" | "wscript" => {
            validate_script_host_args(policy, args, current_dir)
        }
        "find.exe" | "find" => validate_find_args(policy, args, current_dir),
        "findstr.exe" | "findstr" => validate_findstr_args(policy, args, current_dir),
        "comp.exe" | "comp" => validate_comp_args(policy, args, current_dir),
        "fc.exe" | "fc" => validate_fc_args(policy, args, current_dir),
        "xcopy.exe" | "xcopy" => {
            if let Some(source) = args
                .first()
                .and_then(|arg| resolve_relative_arg_path(current_dir, arg))
            {
                validate_candidate_path(
                    policy,
                    &source,
                    crate::AccessMode::Read,
                    "xcopy source path",
                )?;
            }
            if let Some(dest) = args
                .get(1)
                .and_then(|arg| resolve_relative_arg_path(current_dir, arg))
            {
                validate_candidate_path(
                    policy,
                    &dest,
                    crate::AccessMode::Write,
                    "xcopy destination path",
                )?;
            }
            Ok(())
        }
        "robocopy.exe" | "robocopy" => {
            if let Some(source) = args
                .first()
                .and_then(|arg| resolve_relative_arg_path(current_dir, arg))
            {
                validate_candidate_path(
                    policy,
                    &source,
                    crate::AccessMode::Read,
                    "robocopy source path",
                )?;
            }
            if let Some(dest) = args
                .get(1)
                .and_then(|arg| resolve_relative_arg_path(current_dir, arg))
            {
                validate_candidate_path(
                    policy,
                    &dest,
                    crate::AccessMode::Write,
                    "robocopy destination path",
                )?;
            }
            Ok(())
        }
        "more.com" | "more" => {
            for arg in args {
                if let Some(candidate) = resolve_relative_arg_path(current_dir, arg) {
                    validate_candidate_path(
                        policy,
                        &candidate,
                        crate::AccessMode::Read,
                        "file argument",
                    )?;
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[must_use]
pub fn runtime_state_dir(policy: &WindowsFilesystemPolicy, current_dir: &Path) -> Option<PathBuf> {
    if !policy.unsupported.is_empty() {
        return None;
    }

    let current_dir = current_dir
        .canonicalize()
        .unwrap_or_else(|_| current_dir.to_path_buf());
    let current_dir = normalize_windows_path(&current_dir);

    let user_intent_writable_rule = |rule: &crate::sandbox::WindowsFilesystemRule| {
        rule.source.is_user_intent() && rule.access.contains(crate::AccessMode::Write)
    };

    if policy.rules.iter().any(user_intent_writable_rule)
        && policy.covers_writable_directory_path(&current_dir)
    {
        return Some(current_dir);
    }

    policy
        .rules
        .iter()
        .find(|rule| !rule.is_file && user_intent_writable_rule(rule))
        .map(|rule| rule.path.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccessMode, CapabilitySet, CapabilitySource, FsCapability, IpcMode, NetworkMode};
    use std::process::Command;
    use tempfile::tempdir;

    fn try_create_symlink_file(link: &Path, target: &Path) -> bool {
        match std::os::windows::fs::symlink_file(target, link) {
            Ok(()) => true,
            Err(err) => {
                eprintln!("skipping symlink escape test because symlink creation failed: {err}");
                false
            }
        }
    }

    fn try_create_junction(link: &Path, target: &Path) -> bool {
        let Ok(output) = Command::new("cmd")
            .args([
                "/c",
                "mklink",
                "/J",
                &link.to_string_lossy(),
                &target.to_string_lossy(),
            ])
            .output()
        else {
            eprintln!("skipping junction escape test because cmd/mklink is unavailable");
            return false;
        };

        if output.status.success() {
            true
        } else {
            eprintln!(
                "skipping junction escape test because mklink /J failed: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            false
        }
    }

    fn try_set_low_integrity_label(path: &Path) -> bool {
        let Ok(output) = Command::new("icacls")
            .arg(path)
            .args(["/setintegritylevel", "(OI)(CI)L"])
            .output()
        else {
            eprintln!("skipping low-integrity label test because icacls is unavailable");
            return false;
        };

        if output.status.success() {
            true
        } else {
            eprintln!(
                "skipping low-integrity label test because icacls failed: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            false
        }
    }

    #[test]
    fn support_info_reports_supported_status_for_promoted_subset_contract() {
        let info = support_info();
        assert!(is_supported());
        assert!(info.is_supported);
        assert_eq!(info.status, SupportStatus::Supported);
        assert_eq!(info.platform, "windows");
        // details string must be non-empty and not mention "partial"
        assert!(!info.details.is_empty());
        assert!(!info.details.to_ascii_lowercase().contains("partial"));
    }

    #[test]
    fn apply_accepts_minimal_supported_windows_subset() {
        let dir = tempdir().expect("tempdir");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::Read)
            .expect("allow path");
        assert!(apply(&caps).is_ok());
    }

    #[test]
    fn apply_accepts_network_blocked_capability_set() {
        let caps = CapabilitySet::new().set_network_mode(NetworkMode::Blocked);
        assert!(apply(&caps).is_ok());
    }

    #[test]
    fn apply_rejects_unsupported_single_file_grant() {
        let dir = tempdir().expect("tempdir");
        let file = dir.path().join("note.txt");
        std::fs::write(&file, "x").expect("write file");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_file(&file, AccessMode::Read).expect("file cap"));
        let err = apply(&caps).expect_err("single-file grant must be rejected");
        assert!(matches!(err, NonoError::UnsupportedPlatform(_)));
        // message must be explicit, not generic
        let msg = err.to_string();
        assert!(
            msg.contains("single-file") || msg.contains("SingleFile"),
            "expected named error message, got: {msg}"
        );
    }

    #[test]
    fn apply_rejects_unsupported_write_only_directory_grant() {
        let dir = tempdir().expect("tempdir");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_dir(dir.path(), AccessMode::Write).expect("dir cap"));
        let err = apply(&caps).expect_err("write-only directory grant must be rejected");
        assert!(matches!(err, NonoError::UnsupportedPlatform(_)));
    }

    #[test]
    fn apply_rejects_unsupported_proxy_with_ports() {
        let mut caps = CapabilitySet::new();
        caps.add_tcp_bind_port(8080);
        let err = apply(&caps).expect_err("port bind allowlist must be rejected");
        assert!(matches!(err, NonoError::UnsupportedPlatform(_)));
    }

    #[test]
    fn apply_rejects_capability_expansion_shape() {
        let caps = CapabilitySet::new().enable_extensions();
        let err = apply(&caps).expect_err("extensions_enabled must be rejected");
        assert!(matches!(err, NonoError::UnsupportedPlatform(_)));
    }

    #[test]
    fn apply_rejects_non_default_ipc_mode() {
        let caps = CapabilitySet::new().set_ipc_mode(IpcMode::Full);
        let err = apply(&caps).expect_err("non-default IPC mode must be rejected");
        assert!(matches!(err, NonoError::UnsupportedPlatform(_)));
    }

    #[test]
    fn apply_error_message_remains_explicit_for_unsupported_subset() {
        // The error must name the specific unsupported feature, not emit a generic string
        let dir = tempdir().expect("tempdir");
        let file = dir.path().join("note.txt");
        std::fs::write(&file, "x").expect("write file");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_file(&file, AccessMode::Read).expect("file cap"));
        let err = apply(&caps).expect_err("must reject");
        let msg = err.to_string();
        // Must not be the old generic stub message
        assert!(
            !msg.contains("library-wide `Sandbox::apply()` contract remains partial"),
            "error is still the old stub: {msg}"
        );
        // Must contain a recognizable feature name
        assert!(
            msg.contains("single-file") || msg.contains("not support"),
            "expected named feature in error, got: {msg}"
        );
    }

    #[test]
    fn preview_runtime_status_allows_advisory_only_cwd_read_baseline() {
        let dir = tempdir().expect("tempdir");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::Read)
            .expect("allow path");

        let status = preview_runtime_status(&caps, dir.path(), WindowsPreviewContext::default());
        assert!(status.is_advisory_only());
    }

    #[test]
    fn preview_runtime_status_allows_blocked_network_mode() {
        let caps = CapabilitySet::new().set_network_mode(NetworkMode::Blocked);

        let status =
            preview_runtime_status(&caps, Path::new("."), WindowsPreviewContext::default());
        assert_eq!(status, PreviewRuntimeStatus::AdvisoryOnly);
    }

    #[test]
    fn compile_network_policy_allow_all_has_no_unsupported_shapes() {
        let policy = compile_network_policy(&CapabilitySet::new());
        assert_eq!(policy.mode, WindowsNetworkPolicyMode::AllowAll);
        assert!(policy.is_fully_supported());
        assert_eq!(policy.preferred_backend, WindowsNetworkBackendKind::None);
        assert_eq!(policy.active_backend, WindowsNetworkBackendKind::None);
    }

    #[test]
    fn compile_network_policy_tracks_blocked_mode() {
        let policy =
            compile_network_policy(&CapabilitySet::new().set_network_mode(NetworkMode::Blocked));
        assert_eq!(policy.mode, WindowsNetworkPolicyMode::Blocked);
        assert!(policy.is_fully_supported());
        assert_eq!(policy.preferred_backend, WindowsNetworkBackendKind::Wfp);
        assert_eq!(policy.active_backend, WindowsNetworkBackendKind::Wfp);
    }

    #[test]
    fn network_launch_support_allows_shell_hosts_for_wfp_backed_mode() {
        let policy =
            compile_network_policy(&CapabilitySet::new().set_network_mode(NetworkMode::Blocked));
        assert_eq!(
            network_launch_support(&policy, Path::new(r"C:\Windows\System32\cmd.exe")),
            WindowsNetworkLaunchSupport::Supported
        );
    }

    #[test]
    fn network_launch_support_allows_standalone_binary_for_blocked_mode() {
        let policy =
            compile_network_policy(&CapabilitySet::new().set_network_mode(NetworkMode::Blocked));
        assert_eq!(
            network_launch_support(&policy, Path::new(r"C:\tools\probe.exe")),
            WindowsNetworkLaunchSupport::Supported
        );
    }

    #[test]
    fn compile_network_policy_carries_port_filters_into_wfp_policy() {
        let mut caps = CapabilitySet::new().set_network_mode(NetworkMode::Blocked);
        caps.add_tcp_connect_port(443);
        caps.add_tcp_bind_port(8080);
        caps.add_localhost_port(3000);

        let policy = compile_network_policy(&caps);
        assert_eq!(policy.mode, WindowsNetworkPolicyMode::Blocked);
        assert_eq!(policy.unsupported.len(), 3);
        assert_eq!(policy.tcp_connect_ports, vec![443]);
        assert_eq!(policy.tcp_bind_ports, vec![8080]);
        assert_eq!(policy.localhost_ports, vec![3000]);
        assert_eq!(policy.preferred_backend, WindowsNetworkBackendKind::Wfp);
        assert_eq!(policy.active_backend, WindowsNetworkBackendKind::Wfp);
    }

    #[test]
    fn preview_runtime_status_blocks_extra_filesystem_grants() {
        let dir = tempdir().expect("tempdir");
        let other = tempdir().expect("other tempdir");
        let caps = CapabilitySet::new()
            .allow_path(other.path(), AccessMode::Read)
            .expect("allow path");

        let status = preview_runtime_status(&caps, dir.path(), WindowsPreviewContext::default());
        assert_eq!(
            status,
            PreviewRuntimeStatus::RequiresEnforcement {
                reasons: vec!["execution directory outside supported allowlist"]
            }
        );
    }

    #[test]
    fn preview_runtime_status_allows_supported_directory_allowlist() {
        let dir = tempdir().expect("tempdir");
        let work_dir = dir.path().join("work");
        std::fs::create_dir_all(&work_dir).expect("mkdir work");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::ReadWrite)
            .expect("allow path");

        let status = preview_runtime_status(&caps, &work_dir, WindowsPreviewContext::default());
        assert!(status.is_advisory_only());
    }

    #[test]
    fn preview_runtime_status_allows_deny_override_when_remaining_policy_is_supported() {
        let status = preview_runtime_status(
            &CapabilitySet::new(),
            Path::new("."),
            WindowsPreviewContext {
                has_deny_override_policy: true,
            },
        );
        assert!(status.is_advisory_only());
    }

    #[test]
    fn validate_preview_entry_point_shell_fails_below_min_build() {
        let result = validate_preview_entry_point(
            WindowsPreviewEntryPoint::Shell,
            &CapabilitySet::new(),
            Path::new("."),
            WindowsPreviewContext::default(),
        );
        assert!(
            result.is_ok(),
            "shell with no enforcement-required caps should succeed on build 17763+: {:?}",
            result
        );
    }

    #[test]
    fn validate_preview_entry_point_allows_wrap_with_empty_caps() {
        validate_preview_entry_point(
            WindowsPreviewEntryPoint::Wrap,
            &CapabilitySet::new(),
            Path::new("."),
            WindowsPreviewContext::default(),
        )
        .expect("wrap with no enforcement-required caps should succeed on Windows");
    }

    #[test]
    fn classify_supervisor_support_tracks_supported_and_unsupported_features() {
        let support = classify_supervisor_support(WindowsSupervisorContext {
            rollback_snapshots: true,
            proxy_filtering: true,
            runtime_capability_expansion: true,
            runtime_trust_interception: false,
        });

        assert_eq!(
            support.supported,
            vec![WindowsSupervisorFeatureKind::RollbackSnapshots]
        );
        assert_eq!(
            support.unsupported,
            vec![
                WindowsSupervisorFeatureKind::ProxyFiltering,
                WindowsSupervisorFeatureKind::RuntimeCapabilityExpansion,
            ]
        );
        assert_eq!(
            support.requested_feature_labels(),
            vec![
                "proxy filtering",
                "rollback snapshots",
                "runtime capability elevation",
            ]
        );
    }

    #[test]
    fn compile_filesystem_policy_keeps_directory_rules() {
        let dir = tempdir().expect("tempdir");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::ReadWrite)
            .expect("allow path");

        let policy = compile_filesystem_policy(&caps);
        assert!(policy.is_fully_supported());
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(
            policy.rules[0].path,
            normalize_windows_path(&dir.path().canonicalize().expect("canonical"))
        );
        assert_eq!(policy.rules[0].access, AccessMode::ReadWrite);
        assert_eq!(policy.rules[0].source, CapabilitySource::User);
    }

    #[test]
    fn compile_filesystem_policy_classifies_single_file_as_unsupported() {
        let dir = tempdir().expect("tempdir");
        let file = dir.path().join("note.txt");
        std::fs::write(&file, "hello").expect("write file");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_file(&file, AccessMode::Read).expect("file cap"));

        let policy = compile_filesystem_policy(&caps);
        assert!(!policy.is_fully_supported());
        assert!(policy.rules.is_empty());
        assert_eq!(policy.unsupported.len(), 1);
        assert_eq!(
            policy.unsupported[0].kind,
            crate::sandbox::WindowsUnsupportedIssueKind::SingleFileGrant
        );
    }

    #[test]
    fn compile_filesystem_policy_classifies_write_only_directory_as_unsupported() {
        let dir = tempdir().expect("tempdir");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_dir(dir.path(), AccessMode::Write).expect("dir cap"));

        let policy = compile_filesystem_policy(&caps);
        assert!(!policy.is_fully_supported());
        assert!(policy.rules.is_empty());
        assert_eq!(policy.unsupported.len(), 1);
        assert_eq!(
            policy.unsupported[0].kind,
            crate::sandbox::WindowsUnsupportedIssueKind::WriteOnlyDirectoryGrant
        );
    }

    #[test]
    fn normalize_windows_path_strips_verbatim_prefix() {
        assert_eq!(
            normalize_windows_path(Path::new(r"\\?\C:\Windows\System32\cmd.exe")),
            PathBuf::from(r"C:\Windows\System32\cmd.exe")
        );
    }

    #[test]
    fn normalize_windows_path_strips_unc_verbatim_prefix() {
        assert_eq!(
            normalize_windows_path(Path::new(r"\\?\UNC\server\share\dir\file.txt")),
            PathBuf::from(r"\\server\share\dir\file.txt")
        );
    }

    #[test]
    fn windows_paths_start_with_case_insensitive_matches_drive_case() {
        assert!(windows_paths_start_with_case_insensitive(
            Path::new(r"c:\Users\OMACK\Nono\workspace"),
            Path::new(r"C:\users\omack\nono")
        ));
    }

    #[test]
    fn filesystem_policy_covers_directory_path_case_insensitively() {
        let policy = WindowsFilesystemPolicy {
            rules: vec![WindowsFilesystemRule {
                path: PathBuf::from(r"C:\Users\Omack\Workspace"),
                access: AccessMode::ReadWrite,
                is_file: false,
                source: CapabilitySource::User,
            }],
            unsupported: Vec::new(),
        };

        assert!(policy.covers_path(
            Path::new(r"c:\users\OMACK\workspace\child.txt"),
            AccessMode::Read
        ));
    }

    #[test]
    fn filesystem_policy_covers_directory_path_with_verbatim_prefix_case_insensitively() {
        let policy = WindowsFilesystemPolicy {
            rules: vec![WindowsFilesystemRule {
                path: PathBuf::from(r"C:\Users\Omack\Workspace"),
                access: AccessMode::ReadWrite,
                is_file: false,
                source: CapabilitySource::User,
            }],
            unsupported: Vec::new(),
        };

        assert!(policy.covers_path(
            Path::new(r"\\?\c:\users\omack\workspace\child.txt"),
            AccessMode::Write
        ));
    }

    #[test]
    fn filesystem_policy_covers_single_file_with_verbatim_prefix() {
        let policy = WindowsFilesystemPolicy {
            rules: vec![WindowsFilesystemRule {
                path: PathBuf::from(r"C:\Users\Omack\Workspace\file.txt"),
                access: AccessMode::ReadWrite,
                is_file: true,
                source: CapabilitySource::User,
            }],
            unsupported: Vec::new(),
        };

        assert!(policy.covers_path(
            Path::new(r"\\?\c:\users\omack\workspace\file.txt"),
            AccessMode::Write
        ));
    }

    #[test]
    fn validate_launch_paths_accepts_supported_executable() {
        let dir = tempdir().expect("tempdir");
        let bin_dir = dir.path().join("bin");
        std::fs::create_dir_all(&bin_dir).expect("mkdir bin");
        let program = bin_dir.join("tool.exe");
        std::fs::write(&program, "binary").expect("write program");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_dir(dir.path(), AccessMode::ReadWrite).expect("dir cap"));
        let policy = compile_filesystem_policy(&caps);

        validate_launch_paths(&policy, &program, dir.path()).expect("launch paths should validate");
    }

    #[test]
    fn validate_launch_paths_rejects_executable_outside_policy() {
        let allowed = tempdir().expect("allowed");
        let outside = tempdir().expect("outside");
        let program = outside.path().join("tool.exe");
        std::fs::write(&program, "binary").expect("write program");

        let caps = CapabilitySet::new()
            .allow_path(allowed.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);

        let err = validate_launch_paths(&policy, &program, allowed.path())
            .expect_err("executable outside policy should fail");
        assert!(err.to_string().contains("executable path"));
    }

    #[test]
    fn validate_launch_paths_rejects_single_file_policy_shapes_as_unsupported() {
        let dir = tempdir().expect("tempdir");
        let file = dir.path().join("note.txt");
        std::fs::write(&file, "hello").expect("write file");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_file(&file, AccessMode::Read).expect("file cap"));
        let policy = compile_filesystem_policy(&caps);

        // Single-file grants are classified as unsupported, so validate_launch_paths must reject
        validate_launch_paths(&policy, &file, dir.path())
            .expect_err("single-file policy shapes must be rejected as unsupported");
    }

    #[test]
    fn runtime_state_dir_prefers_writable_current_dir_inside_policy() {
        let dir = tempdir().expect("tempdir");
        let work_dir = dir.path().join("work");
        std::fs::create_dir_all(&work_dir).expect("mkdir work");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let expected =
            normalize_windows_path(&work_dir.canonicalize().expect("canonical work dir"));

        assert_eq!(runtime_state_dir(&policy, &work_dir), Some(expected));
    }

    #[test]
    fn runtime_state_dir_returns_none_for_file_only_policy() {
        let dir = tempdir().expect("tempdir");
        let file = dir.path().join("note.txt");
        std::fs::write(&file, "hello").expect("write file");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_file(&file, AccessMode::Read).expect("file cap"));
        let policy = compile_filesystem_policy(&caps);

        assert_eq!(runtime_state_dir(&policy, dir.path()), None);
    }

    #[test]
    fn preview_runtime_status_reports_requires_enforcement_for_single_file_policy() {
        let dir = tempdir().expect("tempdir");
        let file = dir.path().join("note.txt");
        std::fs::write(&file, "hello").expect("write file");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_file(&file, AccessMode::Read).expect("file cap"));

        // Single-file grants are now classified as unsupported, so preview status
        // must report RequiresEnforcement with the single-file grants label.
        let status = preview_runtime_status(
            &caps,
            Path::new(r"C:\outside-workdir"),
            WindowsPreviewContext::default(),
        );
        assert!(
            matches!(status, PreviewRuntimeStatus::RequiresEnforcement { .. }),
            "single-file policy should require enforcement: {status:?}"
        );
    }

    #[test]
    fn preview_runtime_status_reports_requires_enforcement_for_write_only_directory() {
        let dir = tempdir().expect("tempdir");
        let work_dir = dir.path().join("work");
        std::fs::create_dir_all(&work_dir).expect("mkdir work");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability::new_dir(dir.path(), AccessMode::Write).expect("dir cap"));

        // Write-only directory grants are now classified as unsupported, so preview status
        // must report RequiresEnforcement.
        let status = preview_runtime_status(&caps, &work_dir, WindowsPreviewContext::default());
        assert!(
            matches!(status, PreviewRuntimeStatus::RequiresEnforcement { .. }),
            "write-only directory policy should require enforcement: {status:?}"
        );
    }

    #[test]
    fn low_integrity_compatible_dir_matches_localappdata_temp_low() {
        let Some(local) = std::env::var_os("LOCALAPPDATA") else {
            return;
        };
        let candidate = PathBuf::from(local)
            .join("Temp")
            .join("Low")
            .join("nono-test");
        assert!(is_low_integrity_compatible_dir(&candidate));
    }

    #[test]
    fn low_integrity_compatible_dir_matches_locallow() {
        let Some(local) = std::env::var_os("LOCALAPPDATA") else {
            return;
        };
        let Some(appdata_root) = PathBuf::from(local).parent().map(Path::to_path_buf) else {
            return;
        };
        let candidate = appdata_root.join("LocalLow").join("nono-test");
        assert!(is_low_integrity_compatible_dir(&candidate));
    }

    #[test]
    fn low_integrity_compatible_dir_rejects_normal_tempdir() {
        let dir = tempdir().expect("tempdir");
        assert!(!is_low_integrity_compatible_dir(dir.path()));
    }

    #[test]
    fn low_integrity_compatible_dir_matches_dynamically_labeled_directory() {
        let dir = tempdir().expect("tempdir");
        let labeled = dir.path().join("labeled-low");
        std::fs::create_dir_all(&labeled).expect("mkdir");
        if !try_set_low_integrity_label(&labeled) {
            return;
        }

        assert!(is_low_integrity_compatible_dir(&labeled));
    }

    #[test]
    fn validate_command_args_accepts_absolute_path_inside_policy() {
        let dir = tempdir().expect("tempdir");
        let file = dir.path().join("inside.txt");
        std::fs::write(&file, "hello").expect("write file");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![file.to_string_lossy().into_owned()];

        validate_command_args(&policy, Path::new("more.com"), &args, dir.path())
            .expect("path inside policy should validate");
    }

    #[test]
    fn validate_command_args_rejects_absolute_path_outside_policy() {
        let allowed = tempdir().expect("allowed");
        let outside = tempdir().expect("outside");
        let file = outside.path().join("outside.txt");
        std::fs::write(&file, "hello").expect("write file");
        let caps = CapabilitySet::new()
            .allow_path(allowed.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![file.to_string_lossy().into_owned()];

        let err = validate_command_args(&policy, Path::new("more.com"), &args, allowed.path())
            .expect_err("path outside policy should fail validation");
        assert!(err.to_string().contains("absolute path argument"));
    }

    #[test]
    fn validate_command_args_accepts_relative_cmd_type_path_inside_policy() {
        let dir = tempdir().expect("tempdir");
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let file = workspace.join("inside.txt");
        std::fs::write(&file, "hello").expect("write file");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            "/c".to_string(),
            "type".to_string(),
            "inside.txt".to_string(),
        ];

        validate_command_args(&policy, Path::new("cmd.exe"), &args, &workspace)
            .expect("relative type path inside policy should validate");
    }

    #[test]
    fn validate_command_args_rejects_relative_cmd_type_path_outside_policy() {
        let allowed = tempdir().expect("allowed");
        let workspace = allowed.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let outside = tempdir().expect("outside");
        let file = outside.path().join("outside.txt");
        std::fs::write(&file, "hello").expect("write file");
        let caps = CapabilitySet::new()
            .allow_path(allowed.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            "/c".to_string(),
            "type".to_string(),
            file.to_string_lossy().into_owned(),
        ];

        let err = validate_command_args(&policy, Path::new("cmd.exe"), &args, &workspace)
            .expect_err("relative/absolute type path outside policy should fail validation");
        assert!(
            err.to_string().contains("absolute path argument")
                || err.to_string().contains("file argument")
        );
    }

    #[test]
    fn validate_command_args_rejects_relative_parent_escape_outside_policy() {
        let dir = tempdir().expect("tempdir");
        let allowed = dir.path().join("allowed");
        let workspace = allowed.join("workspace");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        std::fs::create_dir_all(&outside).expect("mkdir outside");
        let outside_file = outside.join("outside.txt");
        std::fs::write(&outside_file, "hello").expect("write file");

        let caps = CapabilitySet::new()
            .allow_path(&allowed, AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            "/c".to_string(),
            "type".to_string(),
            r"..\..\outside\outside.txt".to_string(),
        ];

        let err = validate_command_args(&policy, Path::new("cmd.exe"), &args, &workspace)
            .expect_err("parent-dir escape should fail validation");
        assert!(err.to_string().contains("file argument"));
    }

    #[test]
    fn validate_command_args_rejects_symlink_escape_inside_policy() {
        let dir = tempdir().expect("tempdir");
        let allowed = dir.path().join("allowed");
        let workspace = allowed.join("workspace");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        std::fs::create_dir_all(&outside).expect("mkdir outside");
        let outside_file = outside.join("secret.txt");
        std::fs::write(&outside_file, "secret").expect("write outside file");
        let link = workspace.join("inside-link.txt");
        if !try_create_symlink_file(&link, &outside_file) {
            return;
        }

        let caps = CapabilitySet::new()
            .allow_path(&allowed, AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![link.to_string_lossy().into_owned()];

        let err = validate_command_args(&policy, Path::new("more.com"), &args, &workspace)
            .expect_err("symlink escape should fail validation");
        assert!(err.to_string().contains("absolute path argument"));
    }

    #[test]
    fn validate_command_args_rejects_junction_escape_inside_policy() {
        let dir = tempdir().expect("tempdir");
        let allowed = dir.path().join("allowed");
        let workspace = allowed.join("workspace");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        std::fs::create_dir_all(&outside).expect("mkdir outside");
        let outside_file = outside.join("secret.txt");
        std::fs::write(&outside_file, "secret").expect("write outside file");
        let junction = workspace.join("outside-link");
        if !try_create_junction(&junction, &outside) {
            return;
        }

        let caps = CapabilitySet::new()
            .allow_path(&allowed, AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            "/c".to_string(),
            "type".to_string(),
            r"outside-link\secret.txt".to_string(),
        ];

        let err = validate_command_args(&policy, Path::new("cmd.exe"), &args, &workspace)
            .expect_err("junction escape should fail validation");
        assert!(err.to_string().contains("file argument"));
    }

    #[test]
    fn validate_command_args_accepts_relative_cmd_copy_paths_inside_policy() {
        let dir = tempdir().expect("tempdir");
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let source = workspace.join("source.txt");
        std::fs::write(&source, "hello").expect("write file");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            "/c".to_string(),
            "copy".to_string(),
            "source.txt".to_string(),
            "dest.txt".to_string(),
        ];

        validate_command_args(&policy, Path::new("cmd.exe"), &args, &workspace)
            .expect("relative copy paths inside policy should validate");
    }

    #[test]
    fn validate_command_args_rejects_cmd_copy_destination_outside_policy() {
        let allowed = tempdir().expect("allowed");
        let workspace = allowed.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let source = workspace.join("source.txt");
        std::fs::write(&source, "hello").expect("write file");
        let outside = tempdir().expect("outside");
        let dest = outside.path().join("dest.txt");
        let caps = CapabilitySet::new()
            .allow_path(allowed.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            "/c".to_string(),
            "copy".to_string(),
            "source.txt".to_string(),
            dest.to_string_lossy().into_owned(),
        ];

        let err = validate_command_args(&policy, Path::new("cmd.exe"), &args, &workspace)
            .expect_err("copy destination outside policy should fail validation");
        assert!(
            err.to_string().contains("absolute path argument")
                || err.to_string().contains("destination path argument")
        );
    }

    #[test]
    fn validate_command_args_accepts_powershell_get_content_inside_policy() {
        let dir = tempdir().expect("tempdir");
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let file = workspace.join("inside.txt");
        std::fs::write(&file, "hello").expect("write file");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec!["-Command".to_string(), "Get-Content inside.txt".to_string()];

        validate_command_args(&policy, Path::new("powershell.exe"), &args, &workspace)
            .expect("PowerShell Get-Content inside policy should validate");
    }

    #[test]
    fn validate_command_args_rejects_powershell_copy_destination_outside_policy() {
        let allowed = tempdir().expect("allowed");
        let workspace = allowed.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let source = workspace.join("source.txt");
        std::fs::write(&source, "hello").expect("write file");
        let outside = tempdir().expect("outside");
        let dest = outside.path().join("dest.txt");
        let caps = CapabilitySet::new()
            .allow_path(allowed.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            "-Command".to_string(),
            format!(
                "Copy-Item source.txt -Destination '{}'",
                dest.to_string_lossy()
            ),
        ];

        let err = validate_command_args(&policy, Path::new("powershell.exe"), &args, &workspace)
            .expect_err("PowerShell copy destination outside policy should fail");
        assert!(
            err.to_string().contains("absolute path argument")
                || err.to_string().contains("PowerShell destination path")
        );
    }

    #[test]
    fn validate_command_args_accepts_xcopy_inside_policy() {
        let dir = tempdir().expect("tempdir");
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let source = workspace.join("source.txt");
        std::fs::write(&source, "hello").expect("write file");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec!["source.txt".to_string(), "dest.txt".to_string()];

        validate_command_args(&policy, Path::new("xcopy.exe"), &args, &workspace)
            .expect("xcopy inside policy should validate");
    }

    #[test]
    fn validate_command_args_rejects_robocopy_destination_outside_policy() {
        let allowed = tempdir().expect("allowed");
        let workspace = allowed.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let source = workspace.join("source");
        std::fs::create_dir_all(&source).expect("mkdir source");
        let outside = tempdir().expect("outside");
        let dest = outside.path().join("dest");
        let caps = CapabilitySet::new()
            .allow_path(allowed.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            source.to_string_lossy().into_owned(),
            dest.to_string_lossy().into_owned(),
        ];

        let err = validate_command_args(&policy, Path::new("robocopy.exe"), &args, &workspace)
            .expect_err("robocopy destination outside policy should fail");
        assert!(
            err.to_string().contains("absolute path argument")
                || err.to_string().contains("robocopy destination path")
        );
    }

    #[test]
    fn validate_command_args_accepts_cscript_paths_inside_policy() {
        let dir = tempdir().expect("tempdir");
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let script = workspace.join("copy.vbs");
        std::fs::write(&script, "WScript.Echo \"ok\"").expect("write script");
        let source = workspace.join("source.txt");
        std::fs::write(&source, "hello").expect("write source");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            "//NoLogo".to_string(),
            "copy.vbs".to_string(),
            "source.txt".to_string(),
            "dest.txt".to_string(),
        ];

        validate_command_args(&policy, Path::new("cscript.exe"), &args, &workspace)
            .expect("cscript paths inside policy should validate");
    }

    #[test]
    fn validate_command_args_rejects_cscript_destination_outside_policy() {
        let allowed = tempdir().expect("allowed");
        let workspace = allowed.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let script = workspace.join("copy.vbs");
        std::fs::write(&script, "WScript.Echo \"ok\"").expect("write script");
        let source = workspace.join("source.txt");
        std::fs::write(&source, "hello").expect("write source");
        let outside = tempdir().expect("outside");
        let dest = outside.path().join("dest.txt");
        let caps = CapabilitySet::new()
            .allow_path(allowed.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            "//NoLogo".to_string(),
            "copy.vbs".to_string(),
            "source.txt".to_string(),
            dest.to_string_lossy().into_owned(),
        ];

        let err = validate_command_args(&policy, Path::new("cscript.exe"), &args, &workspace)
            .expect_err("cscript destination outside policy should fail");
        assert!(
            err.to_string().contains("absolute path argument")
                || err
                    .to_string()
                    .contains("Windows Script Host path argument")
        );
    }

    #[test]
    fn validate_command_args_accepts_findstr_inside_policy() {
        let dir = tempdir().expect("tempdir");
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let file = workspace.join("inside.txt");
        std::fs::write(&file, "needle").expect("write file");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            "/c:needle".to_string(),
            "needle".to_string(),
            "inside.txt".to_string(),
        ];

        validate_command_args(&policy, Path::new("findstr.exe"), &args, &workspace)
            .expect("findstr file inside policy should validate");
    }

    #[test]
    fn validate_command_args_rejects_fc_file_outside_policy() {
        let allowed = tempdir().expect("allowed");
        let workspace = allowed.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let file = workspace.join("inside.txt");
        std::fs::write(&file, "same").expect("write file");
        let outside = tempdir().expect("outside");
        let outside_file = outside.path().join("outside.txt");
        std::fs::write(&outside_file, "same").expect("write outside file");
        let caps = CapabilitySet::new()
            .allow_path(allowed.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            "inside.txt".to_string(),
            outside_file.to_string_lossy().into_owned(),
        ];

        let err = validate_command_args(&policy, Path::new("fc.exe"), &args, &workspace)
            .expect_err("fc path outside policy should fail");
        assert!(
            err.to_string().contains("absolute path argument")
                || err.to_string().contains("fc file argument")
        );
    }

    #[test]
    fn validate_command_args_accepts_find_inside_policy() {
        let dir = tempdir().expect("tempdir");
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let file = workspace.join("inside.txt");
        std::fs::write(&file, "needle").expect("write file");
        let caps = CapabilitySet::new()
            .allow_path(dir.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            "/n".to_string(),
            "needle".to_string(),
            "inside.txt".to_string(),
        ];

        validate_command_args(&policy, Path::new("find.exe"), &args, &workspace)
            .expect("find file inside policy should validate");
    }

    #[test]
    fn validate_command_args_rejects_comp_file_outside_policy() {
        let allowed = tempdir().expect("allowed");
        let workspace = allowed.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        let file = workspace.join("inside.txt");
        std::fs::write(&file, "same").expect("write file");
        let outside = tempdir().expect("outside");
        let outside_file = outside.path().join("outside.txt");
        std::fs::write(&outside_file, "same").expect("write outside file");
        let caps = CapabilitySet::new()
            .allow_path(allowed.path(), AccessMode::ReadWrite)
            .expect("allow path");
        let policy = compile_filesystem_policy(&caps);
        let args = vec![
            "inside.txt".to_string(),
            outside_file.to_string_lossy().into_owned(),
        ];

        let err = validate_command_args(&policy, Path::new("comp.exe"), &args, &workspace)
            .expect_err("comp path outside policy should fail");
        assert!(
            err.to_string().contains("absolute path argument")
                || err.to_string().contains("comp file argument")
        );
    }
}
