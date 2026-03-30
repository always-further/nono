//! nono - Capability-based sandboxing library
//!
//! This library provides OS-level sandboxing using Landlock (Linux) and
//! Seatbelt (macOS) for capability-based filesystem and network isolation.
//!
//! # Overview
//!
//! nono is a pure sandboxing primitive - it provides the mechanism for
//! OS-enforced isolation without imposing any security policy. Clients
//! (CLI tools, language bindings) define their own policies.
//!
//! # Example
//!
//! ```no_run
//! use nono::{CapabilitySet, AccessMode, Sandbox};
//!
//! fn main() -> nono::Result<()> {
//!     // Build capability set - client must add ALL paths, including system paths
//!     let caps = CapabilitySet::new()
//!         // System paths for executables to run
//!         .allow_path("/usr", AccessMode::Read)?
//!         .allow_path("/lib", AccessMode::Read)?
//!         .allow_path("/bin", AccessMode::Read)?
//!         // User paths
//!         .allow_path("/project", AccessMode::ReadWrite)?
//!         .block_network();
//!
//!     // Check platform support
//!     let support = Sandbox::support_info();
//!     if !support.is_supported {
//!         eprintln!("Warning: {}", support.details);
//!     }
//!
//!     // Apply sandbox - this is irreversible
//!     Sandbox::apply(&caps)?;
//!
//!     // Now running sandboxed...
//!     Ok(())
//! }
//! ```
//!
//! # Platform Support
//!
//! - **Linux**: Uses Landlock LSM (kernel 5.13+)
//! - **macOS**: Uses Seatbelt sandbox
//! - **Other platforms**: Returns `UnsupportedPlatform` error

pub mod capability;
pub mod diagnostic;
pub mod error;
pub mod keystore;
pub mod net_filter;
pub mod query;
pub mod sandbox;
pub mod state;
pub mod supervisor;
pub mod trust;
pub mod undo;

// Re-exports for convenience
pub use capability::{
    AccessMode, CapabilitySet, CapabilitySource, FsCapability, IpcMode, NetworkMode,
    ProcessInfoMode, SignalMode,
};
pub use diagnostic::{
    CommandContext, DenialReason, DenialRecord, DiagnosticFormatter, DiagnosticMode,
};
pub use error::{NonoError, Result};
pub use keystore::{
    is_apple_password_uri, is_env_uri, is_op_uri, load_secret_by_ref, load_secrets,
    redact_apple_password_uri, redact_op_uri, validate_apple_password_uri,
    validate_destination_env_var, validate_env_uri, validate_op_uri, LoadedSecret,
};
pub use net_filter::{FilterResult, HostFilter};
#[cfg(target_os = "linux")]
pub use sandbox::{detect_abi, DetectedAbi};
pub use sandbox::{PreviewRuntimeStatus, Sandbox, SupportInfo, SupportStatus};
#[cfg(target_os = "windows")]
pub use sandbox::{WindowsFilesystemPolicy, WindowsFilesystemRule, WindowsPreviewContext};
pub use state::SandboxState;
pub use supervisor::{
    ApprovalBackend, ApprovalDecision, CapabilityRequest, SupervisorSocket, UrlOpenRequest,
};
pub use trust::{
    Enforcement, IncludePatterns, Publisher, SignerIdentity, TrustPolicy, VerificationOutcome,
    VerificationResult,
};
