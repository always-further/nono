//! Supervisor IPC types for capability expansion
//!
//! These types define the protocol between a sandboxed child process and its
//! unsandboxed supervisor parent. The child sends [`CapabilityRequest`]s over
//! a supervisor transport, and the supervisor responds with
//! [`ApprovalDecision`]s plus explicit resource-transfer metadata when a
//! request is granted.

use crate::capability::AccessMode;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::SystemTime;

/// A request from the sandboxed child for additional filesystem access.
///
/// Sent over the supervisor Unix socket when the child needs access to a path
/// not covered by its initial sandbox policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityRequest {
    /// Unique identifier for this request (for replay protection and audit)
    pub request_id: String,
    /// The filesystem path being requested
    pub path: PathBuf,
    /// The access mode requested (read, write, or read+write)
    pub access: AccessMode,
    /// Human-readable reason for the request (provided by the agent)
    pub reason: Option<String>,
    /// PID of the requesting child process
    pub child_pid: u32,
    /// Session identifier for correlating requests within a single run
    pub session_id: String,
}

/// The supervisor's response to a [`CapabilityRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApprovalDecision {
    /// Access was granted. Resource-transfer details, if any, are carried by
    /// [`SupervisorResponse::Decision`].
    Granted,
    /// Access was denied with a reason.
    Denied {
        /// Why the request was denied
        reason: String,
    },
    /// The approval request timed out without a decision.
    Timeout,
}

/// The kind of resource the supervisor transferred for a granted request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GrantedResourceKind {
    /// A filesystem-backed file handle or descriptor.
    File,
}

/// The transport mechanism used to deliver a granted resource to the child.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResourceTransferKind {
    /// The resource arrives out-of-band via Unix `SCM_RIGHTS`.
    SidebandFileDescriptor,
    /// The resource is an already-duplicated Windows handle carried inline.
    DuplicatedWindowsHandle,
}

/// Metadata describing how a granted resource reaches the sandboxed child.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceGrant {
    /// Which transfer mechanism the child must expect.
    pub transfer: ResourceTransferKind,
    /// What kind of resource was granted.
    pub resource_kind: GrantedResourceKind,
    /// Which access mode the supervisor opened or brokered.
    pub access: AccessMode,
    /// Raw Windows handle value when `transfer` is
    /// [`ResourceTransferKind::DuplicatedWindowsHandle`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_handle: Option<u64>,
}

impl ResourceGrant {
    /// Build Unix-side metadata for a granted file descriptor transferred via
    /// `SCM_RIGHTS`.
    #[must_use]
    pub fn sideband_file_descriptor(access: AccessMode) -> Self {
        Self {
            transfer: ResourceTransferKind::SidebandFileDescriptor,
            resource_kind: GrantedResourceKind::File,
            access,
            raw_handle: None,
        }
    }

    /// Build Windows-side metadata for a duplicated file handle transferred
    /// inline over the supervisor transport.
    #[must_use]
    pub fn duplicated_windows_file_handle(raw_handle: u64, access: AccessMode) -> Self {
        Self {
            transfer: ResourceTransferKind::DuplicatedWindowsHandle,
            resource_kind: GrantedResourceKind::File,
            access,
            raw_handle: Some(raw_handle),
        }
    }
}

impl ApprovalDecision {
    /// Returns true if access was granted.
    #[must_use]
    pub fn is_granted(&self) -> bool {
        matches!(self, ApprovalDecision::Granted)
    }

    /// Returns true if access was denied.
    #[must_use]
    pub fn is_denied(&self) -> bool {
        matches!(self, ApprovalDecision::Denied { .. })
    }
}

/// A structured audit record for every approval decision.
///
/// Every capability request produces an audit entry regardless of outcome.
/// These entries support fleet-level monitoring and compliance reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// When the decision was made
    pub timestamp: SystemTime,
    /// The original request
    pub request: CapabilityRequest,
    /// The decision that was reached
    pub decision: ApprovalDecision,
    /// Which approval backend handled the request
    pub backend: String,
    /// How long the decision took (milliseconds)
    pub duration_ms: u64,
}

/// A request from the sandboxed child to open a URL in the user's browser.
///
/// Sent over the supervisor Unix socket when the child needs to launch a
/// browser (e.g., for OAuth2 login). The unsandboxed supervisor validates
/// the URL against the profile's allowed origins and opens it outside the
/// sandbox, where the browser can access its own config files freely.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlOpenRequest {
    /// Unique identifier for this request (for replay protection and audit)
    pub request_id: String,
    /// The URL to open in the user's browser
    pub url: String,
    /// PID of the requesting child process
    pub child_pid: u32,
    /// Session identifier for correlating requests within a single run
    pub session_id: String,
}

/// IPC message envelope sent from child to supervisor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SupervisorMessage {
    /// A capability expansion request (explicit, from SDK clients)
    Request(CapabilityRequest),
    /// A request to open a URL in the user's browser (e.g., OAuth2 login)
    OpenUrl(UrlOpenRequest),
    /// A request to terminate the supervisor and its child (Windows only)
    Terminate {
        /// Session identifier for verification
        session_id: String,
    },
    /// A request to detach the CLI from the supervisor (Windows only)
    Detach {
        /// Session identifier for verification
        session_id: String,
    },
}

/// IPC message envelope sent from supervisor to child.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SupervisorResponse {
    /// Response to a capability request
    Decision {
        /// The request_id this responds to
        request_id: String,
        /// The approval decision
        decision: ApprovalDecision,
        /// Resource-transfer metadata when the supervisor granted access.
        grant: Option<ResourceGrant>,
    },
    /// Response to a URL open request
    UrlOpened {
        /// The request_id this responds to
        request_id: String,
        /// Whether the URL was opened successfully
        success: bool,
        /// Error message if the open failed
        error: Option<String>,
    },
}
