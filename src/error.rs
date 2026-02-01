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

    #[cfg(target_os = "linux")]
    #[error("Landlock error: {0}")]
    Landlock(#[from] landlock::RulesetError),

    #[cfg(target_os = "linux")]
    #[error("Landlock path error: {0}")]
    LandlockPath(#[from] landlock::PathFdError),

    #[error("Profile not found: {0}")]
    ProfileNotFound(String),

    #[error("Profile parse error: {0}")]
    ProfileParse(String),

    #[error("Unsigned profile requires --trust-unsigned flag: {0}")]
    UnsignedProfile(String),

    #[error("Failed to read profile {path}: {source}")]
    ProfileRead {
        path: std::path::PathBuf,
        source: std::io::Error,
    },

    #[error("Could not determine home directory")]
    HomeNotFound,

    #[error("Setup error: {0}")]
    Setup(String),

    #[error("Failed to access system keystore: {0}")]
    KeystoreAccess(String),

    #[error("Secret not found in keystore: {0}")]
    SecretNotFound(String),

    #[error("Command '{command}' is blocked: {reason}")]
    BlockedCommand { command: String, reason: String },
}

pub type Result<T> = std::result::Result<T, NonoError>;
