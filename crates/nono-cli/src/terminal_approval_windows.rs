use nono::{ApprovalBackend, ApprovalDecision, CapabilityRequest, Result};

pub struct TerminalApproval;

impl ApprovalBackend for TerminalApproval {
    fn request_capability(&self, request: &CapabilityRequest) -> Result<ApprovalDecision> {
        Ok(ApprovalDecision::Denied {
            reason: format!(
                "Windows runtime capability expansion is not available yet for request {}",
                request.request_id
            ),
        })
    }

    fn backend_name(&self) -> &str {
        "windows-preview-deny"
    }
}
