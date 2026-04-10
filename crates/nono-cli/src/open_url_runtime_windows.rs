use crate::cli::OpenUrlHelperArgs;
use nono::{NonoError, Result};

pub(crate) fn run_open_url_helper(_args: OpenUrlHelperArgs) -> Result<()> {
    Err(NonoError::UnsupportedPlatform(
        "Windows delegated browser-open flows are not available yet. The Windows sandboxed child does not have an attached supervisor control channel for open-url-helper requests. Use supported direct execution flows instead."
            .to_string(),
    ))
}
