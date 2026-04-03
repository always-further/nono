use crate::cli::{AttachArgs, DetachArgs, InspectArgs, LogsArgs, PruneArgs, PsArgs, StopArgs};
use nono::{NonoError, Result};

fn unsupported(command: &str) -> Result<()> {
    Err(NonoError::UnsupportedPlatform(format!(
        "Windows `{command}` is not available yet. Detached session management still depends on Unix-specific PTY and signal handling."
    )))
}

pub fn run_ps(_args: &PsArgs) -> Result<()> {
    unsupported("ps")
}

pub fn run_stop(_args: &StopArgs) -> Result<()> {
    unsupported("stop")
}

pub fn run_detach(_args: &DetachArgs) -> Result<()> {
    unsupported("detach")
}

pub fn run_attach(_args: &AttachArgs) -> Result<()> {
    unsupported("attach")
}

pub fn run_logs(_args: &LogsArgs) -> Result<()> {
    unsupported("logs")
}

pub fn run_inspect(_args: &InspectArgs) -> Result<()> {
    unsupported("inspect")
}

pub fn run_prune(_args: &PruneArgs) -> Result<()> {
    unsupported("prune")
}
