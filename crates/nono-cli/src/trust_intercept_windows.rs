//! Windows trust interception placeholder.
//!
//! Runtime instruction-file verification depends on supervised execution and
//! file-open mediation, which are not implemented on Windows yet.

use nono::{NonoError, Result};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct TrustInterceptor;

impl TrustInterceptor {
    #[allow(dead_code)]
    pub fn new(_policy: nono::trust::TrustPolicy, _project_root: PathBuf) -> Result<Self> {
        Err(NonoError::UnsupportedPlatform(
            "Windows runtime trust interception is not available yet. Pre-exec trust verification still runs, but Windows supervised child processes do not have an attached file-open mediation channel for runtime interception.".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::TrustInterceptor;

    #[test]
    fn windows_trust_interceptor_reports_documented_limitation() {
        let err = TrustInterceptor::new(nono::trust::TrustPolicy::default(), std::env::temp_dir())
            .expect_err("Windows trust interceptor should fail closed");

        let text = err.to_string();
        assert!(
            text.contains("Windows runtime trust interception is not available yet"),
            "expected documented trust interception limitation, got: {text}"
        );
        assert!(
            text.contains("Pre-exec trust verification still runs"),
            "expected startup trust verification note, got: {text}"
        );
        assert!(
            text.contains("attached file-open mediation channel"),
            "expected explicit child-transport limitation, got: {text}"
        );
    }
}
