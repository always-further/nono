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
            "Windows trust interception is not implemented yet".to_string(),
        ))
    }
}
