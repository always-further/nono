//! Environment sanitization boundary for sandboxed execution.
//!
//! Threat model:
//! - Untrusted parent/shell environments may inject execution behavior via
//!   linker, shell, or interpreter environment variables.
//! - All sandbox execution strategies must share one allow/deny implementation
//!   to avoid drift in security behavior across code paths.

/// Returns true if an environment variable is unsafe to inherit into a sandboxed child.
///
/// Covers linker injection (LD_PRELOAD, DYLD_INSERT_LIBRARIES), shell startup
/// injection (BASH_ENV, PROMPT_COMMAND, IFS), and interpreter code/module injection
/// (NODE_OPTIONS, PYTHONPATH, PERL5OPT, RUBYOPT, JAVA_TOOL_OPTIONS, etc.).
pub(crate) fn is_dangerous_env_var(key: &str) -> bool {
    // Linker injection
    key.starts_with("LD_")
        || key.starts_with("DYLD_")
        // Shell injection
        || key == "BASH_ENV"
        || key == "ENV"
        || key == "CDPATH"
        || key == "GLOBIGNORE"
        || key.starts_with("BASH_FUNC_")
        || key == "PROMPT_COMMAND"
        || key == "IFS"
        // Python injection
        || key == "PYTHONSTARTUP"
        || key == "PYTHONPATH"
        // Node.js injection
        || key == "NODE_OPTIONS"
        || key == "NODE_PATH"
        // Perl injection
        || key == "PERL5OPT"
        || key == "PERL5LIB"
        // Ruby injection
        || key == "RUBYOPT"
        || key == "RUBYLIB"
        || key == "GEM_PATH"
        || key == "GEM_HOME"
        // JVM injection
        || key == "JAVA_TOOL_OPTIONS"
        || key == "_JAVA_OPTIONS"
        // .NET injection
        || key == "DOTNET_STARTUP_HOOKS"
        // Go injection
        || key == "GOFLAGS"
        // 1Password secrets and session tokens — meta-secrets used by
        // the parent to authenticate `op` CLI, must never leak to sandboxed child
        || key == "OP_SERVICE_ACCOUNT_TOKEN"
        || key == "OP_CONNECT_TOKEN"
        || key == "OP_CONNECT_HOST"
        || key.starts_with("OP_SESSION_")
}

/// Decide whether an inherited env var should be dropped for sandbox execution.
pub(super) fn should_skip_env_var(
    key: &str,
    config_env_vars: &[(&str, &str)],
    blocked_extra: &[&str],
) -> bool {
    config_env_vars.iter().any(|(ek, _)| *ek == key)
        || blocked_extra.contains(&key)
        || is_dangerous_env_var(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================================
    // 1Password env var blocklist — security-critical regression tests
    //
    // These vars are credential or session leaks that must NEVER reach a
    // sandboxed child process. If a future refactor accidentally removes one,
    // these tests will catch it.
    // ============================================================================

    #[test]
    fn test_blocks_op_service_account_token() {
        assert!(is_dangerous_env_var("OP_SERVICE_ACCOUNT_TOKEN"));
    }

    #[test]
    fn test_blocks_op_connect_token() {
        assert!(is_dangerous_env_var("OP_CONNECT_TOKEN"));
    }

    #[test]
    fn test_blocks_op_connect_host() {
        assert!(is_dangerous_env_var("OP_CONNECT_HOST"));
    }

    #[test]
    fn test_blocks_op_session_prefix() {
        // OP_SESSION_* vars carry per-account bearer tokens
        assert!(is_dangerous_env_var("OP_SESSION_my_team"));
        assert!(is_dangerous_env_var("OP_SESSION_personal"));
        assert!(is_dangerous_env_var("OP_SESSION_"));
    }

    #[test]
    fn test_allows_unrelated_env_vars() {
        // Env vars that happen to start with "OP" but aren't 1Password
        assert!(!is_dangerous_env_var("OPENAI_API_KEY"));
        assert!(!is_dangerous_env_var("OPERATOR_TOKEN"));
        assert!(!is_dangerous_env_var("OPTIONS"));
        assert!(!is_dangerous_env_var("HOME"));
        assert!(!is_dangerous_env_var("PATH"));
    }

    // ============================================================================
    // Existing categories — spot-check that the broader blocklist still works
    // ============================================================================

    #[test]
    fn test_blocks_linker_injection() {
        assert!(is_dangerous_env_var("LD_PRELOAD"));
        assert!(is_dangerous_env_var("DYLD_INSERT_LIBRARIES"));
    }

    #[test]
    fn test_blocks_interpreter_injection() {
        assert!(is_dangerous_env_var("NODE_OPTIONS"));
        assert!(is_dangerous_env_var("PYTHONPATH"));
        assert!(is_dangerous_env_var("RUBYOPT"));
    }
}
