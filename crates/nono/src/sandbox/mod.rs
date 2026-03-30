//! OS-level sandbox implementation
//!
//! This module provides the core sandboxing functionality using platform-specific
//! mechanisms:
//! - Linux: Landlock LSM
//! - macOS: Seatbelt sandbox

use crate::capability::CapabilitySet;
use crate::error::Result;
#[cfg(target_os = "windows")]
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "windows")]
mod windows;

// Re-export macOS extension functions for supervisor use
#[cfg(target_os = "macos")]
pub use macos::{extension_consume, extension_issue_file, extension_release};

// Re-export Linux Landlock ABI detection
#[cfg(target_os = "linux")]
pub use linux::{detect_abi, DetectedAbi};

// Re-export Linux seccomp-notify primitives for supervisor use
#[cfg(target_os = "linux")]
pub use linux::{
    classify_access_from_flags, continue_notif, deny_notif, inject_fd, install_seccomp_notify,
    install_seccomp_proxy_filter, notif_id_valid, probe_seccomp_block_network_support,
    read_notif_path, read_notif_sockaddr, read_open_how, recv_notif, resolve_notif_path,
    respond_notif_errno, validate_openat2_size, OpenHow, SeccompData, SeccompNetFallback,
    SeccompNotif, SockaddrInfo, SYS_BIND, SYS_CONNECT, SYS_OPENAT, SYS_OPENAT2,
};

/// Level of sandbox support on this platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportStatus {
    /// The platform has full supported sandbox enforcement.
    Supported,
    /// The platform has preview or incomplete support.
    Partial,
    /// The platform backend is not implemented.
    NotImplemented,
}

impl SupportStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Partial => "partial",
            Self::NotImplemented => "not implemented",
        }
    }

    #[must_use]
    pub fn is_supported(self) -> bool {
        matches!(self, Self::Supported)
    }
}

/// Information about sandbox support on this platform
#[derive(Debug, Clone)]
pub struct SupportInfo {
    /// Whether sandboxing is supported
    pub is_supported: bool,
    /// Support status for reporting and UX.
    pub status: SupportStatus,
    /// Platform name
    pub platform: &'static str,
    /// Detailed support information
    pub details: String,
}

impl SupportInfo {
    #[must_use]
    pub fn status_label(&self) -> &'static str {
        self.status.as_str()
    }
}

/// Windows preview runtime classification for a specific capability set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreviewRuntimeStatus {
    /// Preview execution can continue, but no sandbox enforcement will occur.
    AdvisoryOnly,
    /// The requested capability set requires enforcement that Windows preview
    /// does not implement yet.
    RequiresEnforcement {
        /// Human-readable reasons that explain what requires real enforcement.
        reasons: Vec<&'static str>,
    },
}

impl PreviewRuntimeStatus {
    #[must_use]
    pub fn is_advisory_only(&self) -> bool {
        matches!(self, Self::AdvisoryOnly)
    }
}

/// A Windows filesystem rule compiled from the capability set.
#[cfg(target_os = "windows")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsFilesystemRule {
    /// Canonicalized path granted by this rule.
    pub path: PathBuf,
    /// Access mode requested for this path.
    pub access: crate::AccessMode,
    /// Whether the rule targets a single file rather than a directory subtree.
    pub is_file: bool,
    /// Where the rule came from.
    pub source: crate::CapabilitySource,
}

/// A Windows filesystem capability shape that the current backend does not yet
/// enforce directly.
#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WindowsUnsupportedIssueKind {
    SingleFileGrant,
    WriteOnlyDirectoryGrant,
}

#[cfg(target_os = "windows")]
impl WindowsUnsupportedIssueKind {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::SingleFileGrant => "single-file grants",
            Self::WriteOnlyDirectoryGrant => "write-only directory grants",
        }
    }

    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::SingleFileGrant => {
                "single-file grants are not in the current Windows filesystem enforcement subset"
            }
            Self::WriteOnlyDirectoryGrant => {
                "write-only directory grants are not in the current Windows filesystem enforcement subset"
            }
        }
    }
}

/// A specific unsupported Windows filesystem capability instance.
#[cfg(target_os = "windows")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsUnsupportedIssue {
    pub kind: WindowsUnsupportedIssueKind,
    pub path: PathBuf,
}

#[cfg(target_os = "windows")]
impl WindowsUnsupportedIssue {
    #[must_use]
    pub fn label(&self) -> &'static str {
        self.kind.label()
    }

    #[must_use]
    pub fn message(&self) -> String {
        format!("{}: {}", self.kind.description(), self.path.display())
    }
}

/// Compiled Windows filesystem policy plan derived from a capability set.
#[cfg(target_os = "windows")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsFilesystemPolicy {
    /// Rules that map cleanly into the initial Windows backend plan.
    pub rules: Vec<WindowsFilesystemRule>,
    /// Rules that are intentionally not in the first enforceable subset.
    pub unsupported: Vec<WindowsUnsupportedIssue>,
}

#[cfg(target_os = "windows")]
impl WindowsFilesystemPolicy {
    #[must_use]
    pub fn is_fully_supported(&self) -> bool {
        self.unsupported.is_empty()
    }

    #[must_use]
    pub fn has_rules(&self) -> bool {
        !self.rules.is_empty()
    }

    #[must_use]
    pub fn covers_path(&self, path: &Path, required: crate::AccessMode) -> bool {
        self.rules.iter().any(|rule| {
            !rule.is_file && path.starts_with(&rule.path) && rule.access.contains(required)
        })
    }

    #[must_use]
    pub fn preferred_runtime_dir(&self, current_dir: &Path) -> Option<PathBuf> {
        windows::runtime_state_dir(self, current_dir)
    }

    #[must_use]
    pub fn unsupported_reason_labels(&self) -> Vec<&'static str> {
        let mut labels: Vec<_> = self
            .unsupported
            .iter()
            .map(WindowsUnsupportedIssue::label)
            .collect();
        labels.sort_unstable();
        labels.dedup();
        labels
    }

    #[must_use]
    pub fn unsupported_messages(&self) -> Vec<String> {
        let mut messages: Vec<_> = self
            .unsupported
            .iter()
            .map(WindowsUnsupportedIssue::message)
            .collect();
        messages.sort();
        messages.dedup();
        messages
    }
}

/// Main sandbox API
///
/// This struct provides static methods for applying sandboxing restrictions.
/// Once applied, restrictions cannot be removed or expanded.
///
/// # Example
///
/// ```no_run
/// use nono::{CapabilitySet, AccessMode, Sandbox};
///
/// let caps = CapabilitySet::new()
///     .allow_path("/usr", AccessMode::Read)?
///     .allow_path("/project", AccessMode::ReadWrite)?
///     .block_network();
///
/// // Check if sandbox is supported
/// if Sandbox::is_supported() {
///     Sandbox::apply(&caps)?;
/// }
/// # Ok::<(), nono::NonoError>(())
/// ```
pub struct Sandbox;

impl Sandbox {
    /// Detect the Landlock ABI version supported by the running kernel.
    ///
    /// This is only available on Linux. Returns a `DetectedAbi` that can
    /// be passed to `apply_with_abi()` to avoid re-probing.
    ///
    /// # Errors
    ///
    /// Returns an error if Landlock is not available.
    #[cfg(target_os = "linux")]
    #[must_use = "ABI detection result should be checked"]
    pub fn detect_abi() -> Result<DetectedAbi> {
        linux::detect_abi()
    }

    /// Apply the sandbox with the given capabilities.
    ///
    /// This function applies OS-level restrictions that **cannot be undone**.
    /// After calling this, the current process (and all children) will
    /// only be able to access resources granted by the capabilities.
    ///
    /// On Linux, returns the seccomp network fallback mode. `BlockAll` is
    /// already enforced. `ProxyOnly` signals the caller to install the
    /// proxy filter post-fork via `install_seccomp_proxy_filter()`.
    /// On macOS, always returns `()` (no seccomp fallback concept).
    ///
    /// # Errors
    ///
    /// Returns an error if sandbox initialization fails.
    #[cfg(target_os = "linux")]
    #[must_use = "sandbox application result should be checked"]
    pub fn apply(caps: &CapabilitySet) -> Result<linux::SeccompNetFallback> {
        linux::apply(caps)
    }

    /// Apply the sandbox with the given capabilities (macOS).
    #[cfg(target_os = "macos")]
    #[must_use = "sandbox application result should be checked"]
    pub fn apply(caps: &CapabilitySet) -> Result<()> {
        macos::apply(caps)
    }

    /// Apply the sandbox with the given capabilities (Windows).
    #[cfg(target_os = "windows")]
    #[must_use = "sandbox application result should be checked"]
    pub fn apply(caps: &CapabilitySet) -> Result<()> {
        windows::apply(caps)
    }

    /// Apply the sandbox with the given capabilities (unsupported platforms).
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    #[must_use = "sandbox application result should be checked"]
    pub fn apply(caps: &CapabilitySet) -> Result<()> {
        let _ = caps;
        #[cfg(target_arch = "wasm32")]
        {
            Err(crate::error::NonoError::UnsupportedPlatform(
                "WASM: Browser sandboxing requires different approach (CSP, iframe sandbox)".into(),
            ))
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            Err(crate::error::NonoError::UnsupportedPlatform(
                std::env::consts::OS.to_string(),
            ))
        }
    }

    /// Apply the sandbox with a pre-detected Landlock ABI (Linux only).
    ///
    /// Avoids re-probing the kernel when the caller has already detected
    /// the ABI (e.g., probed once at startup).
    ///
    /// Returns the seccomp network fallback mode (see `apply()` docs).
    ///
    /// # Errors
    ///
    /// Returns an error if sandbox initialization fails.
    #[cfg(target_os = "linux")]
    #[must_use = "sandbox application result should be checked"]
    pub fn apply_with_abi(
        caps: &CapabilitySet,
        abi: &DetectedAbi,
    ) -> Result<linux::SeccompNetFallback> {
        linux::apply_with_abi(caps, abi)
    }

    /// Check if sandboxing is supported on this platform.
    ///
    /// This should only return `true` when the current platform can enforce
    /// the sandbox semantics that nono considers supported. Preview builds,
    /// partial scaffolding, or future-platform placeholders must still
    /// return `false`.
    #[must_use]
    pub fn is_supported() -> bool {
        #[cfg(target_os = "linux")]
        {
            linux::is_supported()
        }

        #[cfg(target_os = "macos")]
        {
            macos::is_supported()
        }

        #[cfg(target_os = "windows")]
        {
            windows::is_supported()
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            false
        }
    }

    /// Get detailed information about sandbox support on this platform
    #[must_use]
    pub fn support_info() -> SupportInfo {
        #[cfg(target_os = "linux")]
        {
            linux::support_info()
        }

        #[cfg(target_os = "macos")]
        {
            macos::support_info()
        }

        #[cfg(target_os = "windows")]
        {
            windows::support_info()
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            SupportInfo {
                is_supported: false,
                status: SupportStatus::NotImplemented,
                platform: std::env::consts::OS,
                details: format!("Platform '{}' is not supported", std::env::consts::OS),
            }
        }
    }

    /// Classify whether the current Windows preview runtime can safely proceed
    /// with advisory-only execution for this capability set.
    #[cfg(target_os = "windows")]
    #[must_use]
    pub fn preview_runtime_status(
        caps: &CapabilitySet,
        execution_dir: &Path,
    ) -> PreviewRuntimeStatus {
        windows::preview_runtime_status(caps, execution_dir)
    }

    /// Compile the current capability set into the Windows filesystem policy
    /// representation used by the backend implementation work.
    #[cfg(target_os = "windows")]
    #[must_use]
    pub fn windows_filesystem_policy(caps: &CapabilitySet) -> WindowsFilesystemPolicy {
        windows::compile_filesystem_policy(caps)
    }

    /// Validate whether the current Windows filesystem policy can enforce the
    /// launch-time paths required by the child process.
    #[cfg(target_os = "windows")]
    #[must_use = "launch-time filesystem validation result should be checked"]
    pub fn validate_windows_launch_paths(
        policy: &WindowsFilesystemPolicy,
        program: &Path,
        current_dir: &Path,
    ) -> Result<()> {
        windows::validate_launch_paths(policy, program, current_dir)
    }

    /// Validate absolute Windows command arguments against the compiled
    /// directory allowlist subset used by the preview backend.
    #[cfg(target_os = "windows")]
    #[must_use = "Windows command-argument validation result should be checked"]
    pub fn validate_windows_command_args(
        policy: &WindowsFilesystemPolicy,
        resolved_program: &Path,
        args: &[String],
        current_dir: &Path,
    ) -> Result<()> {
        windows::validate_command_args(policy, resolved_program, args, current_dir)
    }

    /// Select the preferred writable runtime directory for Windows preview
    /// state files and temporary data based on the compiled filesystem policy.
    #[cfg(target_os = "windows")]
    #[must_use]
    pub fn windows_runtime_state_dir(
        policy: &WindowsFilesystemPolicy,
        current_dir: &Path,
    ) -> Option<PathBuf> {
        windows::runtime_state_dir(policy, current_dir)
    }

    /// Return whether a Windows directory is directly writable by the current
    /// low-integrity restricted-launch path without mutating the directory's
    /// label. This is currently limited to known low-integrity-compatible
    /// roots such as `%LOCALAPPDATA%\\Temp\\Low`.
    #[cfg(target_os = "windows")]
    #[must_use]
    pub fn windows_supports_direct_writable_dir(path: &Path) -> bool {
        windows::is_low_integrity_compatible_dir(path)
    }
}
