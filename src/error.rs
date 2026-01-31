use std::path::PathBuf;
use thiserror::Error;

/// Errors that can occur in nono
#[derive(Error, Debug)]
pub enum NonoError {
    #[error("Path does not exist: {0}")]
    PathNotFound(PathBuf),

    #[error("Expected a directory but got a file: {0}")]
    ExpectedDirectory(PathBuf),

    #[error("Expected a file but got a directory: {0}")]
    ExpectedFile(PathBuf),

    #[error("Failed to canonicalize path {path}: {source}")]
    PathCanonicalization {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("No filesystem capabilities specified. Use --allow, --read, or --write")]
    NoCapabilities,

    #[error("Command not specified")]
    NoCommand,

    #[error("Failed to execute command: {0}")]
    CommandExecution(#[from] std::io::Error),

    #[error("Sandbox initialization failed: {0}")]
    SandboxInit(String),

    #[error("Platform not supported: {0}")]
    UnsupportedPlatform(String),

    #[cfg(target_os = "linux")]
    #[error("Landlock error: {0}")]
    Landlock(#[from] landlock::RulesetError),

    #[cfg(target_os = "linux")]
    #[error("Landlock path error: {0}")]
    LandlockPath(#[from] landlock::PathFdError),

    #[cfg(target_os = "linux")]
    #[error("Landlock create error: {0}")]
    LandlockCreate(#[from] landlock::CreateRulesetError),

    #[error("Configuration error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, NonoError>;
