//! Command-backed credential capture interface.
//!
//! The proxy owns the trigger (`cmd://` route needs a credential), while the
//! CLI/supervisor owns command execution. This module defines the narrow
//! boundary between those crates.

use zeroize::Zeroizing;

/// Request context for a command-backed credential capture.
#[derive(Debug, Clone)]
pub struct CredentialCaptureRequest {
    /// Logical credential name from `cmd://<name>`.
    pub credential_name: String,
    /// Route prefix that triggered capture.
    pub route_id: String,
    /// Upstream host for the request.
    pub request_host: String,
    /// Upstream request path.
    pub request_path: String,
    /// HTTP method that triggered capture.
    pub request_method: String,
    /// Stable supervisor/proxy session identifier.
    pub session_id: String,
    /// Cache scope derived from request context.
    pub cache_scope: String,
}

/// Metadata about a capture attempt. Secret stdout is intentionally excluded.
#[derive(Debug, Clone, Default)]
pub struct CredentialCaptureMetadata {
    pub cache_action: String,
    pub command: Option<String>,
    pub argv: Vec<String>,
    pub exit_status: Option<i32>,
    pub duration_ms: u64,
    pub stdout_bytes: Option<usize>,
    pub stderr_redacted: Option<String>,
    pub cache_scope: Option<String>,
    pub output_format: Option<String>,
    pub header_names: Vec<String>,
    pub stdin_mode: Option<String>,
    pub interactive: Option<bool>,
}

/// Captured material that can be injected into the upstream request.
#[derive(Debug, Clone)]
pub enum CredentialCaptureMaterial {
    /// A single credential value, formatted later by the route config.
    Secret(Zeroizing<String>),
    /// Fully materialized headers produced by the capture command.
    Headers(Vec<(String, Zeroizing<String>)>),
}

/// Result of a capture attempt.
#[derive(Debug, Clone)]
pub struct CredentialCaptureResponse {
    pub material: CredentialCaptureMaterial,
    pub metadata: CredentialCaptureMetadata,
}

/// Error returned by a capture backend. It contains only redacted diagnostics.
#[derive(Debug, Clone)]
pub struct CredentialCaptureError {
    pub reason: String,
    pub metadata: Box<CredentialCaptureMetadata>,
}

impl CredentialCaptureError {
    pub fn new(reason: String, metadata: CredentialCaptureMetadata) -> Self {
        Self {
            reason,
            metadata: Box::new(metadata),
        }
    }
}

impl std::fmt::Display for CredentialCaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for CredentialCaptureError {}

/// Supervisor-provided backend for command-backed proxy credentials.
pub trait CredentialCaptureBackend: Send + Sync + std::fmt::Debug {
    fn capture(
        &self,
        request: CredentialCaptureRequest,
    ) -> std::result::Result<CredentialCaptureResponse, CredentialCaptureError>;
}
