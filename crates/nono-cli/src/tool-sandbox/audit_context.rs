#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Clone)]
pub(crate) struct ToolSandboxAuditContext {
    pub(super) profile_display_name: Option<String>,
    pub(super) redaction_policy: nono::ScrubPolicy,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl ToolSandboxAuditContext {
    pub(crate) fn new(
        profile_display_name: Option<String>,
        redaction_policy: nono::ScrubPolicy,
    ) -> Self {
        Self {
            profile_display_name,
            redaction_policy,
        }
    }
}
