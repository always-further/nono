//! Secure credential loading from system keystore and 1Password
//!
//! This module provides functionality to load secrets from the system keystore
//! (macOS Keychain / Linux Secret Service) or 1Password (via the `op` CLI) and
//! return them as zeroized strings.
//!
//! Credential references starting with `op://` are loaded via the 1Password CLI.
//! All other references are loaded from the system keyring.
//!
//! All secrets are wrapped in `Zeroizing<String>` to ensure they are securely
//! cleared from memory after use.

use crate::error::{NonoError, Result};
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::time::Duration;
use zeroize::Zeroizing;

/// Timeout for `op read` subprocess. Generous to allow biometric prompts.
const OP_TIMEOUT: Duration = Duration::from_secs(30);

/// A credential loaded from the keystore
pub struct LoadedSecret {
    /// The environment variable name to set
    pub env_var: String,
    /// The secret value (automatically zeroized when dropped)
    pub value: Zeroizing<String>,
}

/// The default service name for secrets in the keystore
pub const DEFAULT_SERVICE: &str = "nono";

/// The `op://` URI scheme prefix, indicating 1Password CLI backend.
const OP_URI_PREFIX: &str = "op://";

/// Characters forbidden in `op://` URIs to prevent argument/shell injection.
const FORBIDDEN_URI_CHARS: &[char] = &[
    ';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '!', '\\', '"', '\'', '\n', '\r', '\0',
];

/// Load secrets from the system keystore or 1Password
///
/// Credential references starting with `op://` are loaded via the 1Password CLI.
/// All other references are loaded from the system keyring.
///
/// # Arguments
/// * `service` - The service name in the keystore (e.g., "nono")
/// * `mappings` - Map of credential reference -> env var name
///
/// # Returns
/// Vector of loaded secrets ready to be set as env vars
///
/// # Example
///
/// ```no_run
/// use nono::keystore::{load_secrets, DEFAULT_SERVICE};
/// use std::collections::HashMap;
///
/// let mut mappings = HashMap::new();
/// mappings.insert("api_key".to_string(), "API_KEY".to_string());
///
/// let secrets = load_secrets(DEFAULT_SERVICE, &mappings)?;
/// for secret in secrets {
///     std::env::set_var(&secret.env_var, secret.value.as_str());
/// }
/// # Ok::<(), nono::NonoError>(())
/// ```
#[must_use = "loaded secrets should be used to set environment variables"]
pub fn load_secrets(
    service: &str,
    mappings: &HashMap<String, String>,
) -> Result<Vec<LoadedSecret>> {
    let mut secrets = Vec::with_capacity(mappings.len());

    for (account, env_var) in mappings {
        tracing::debug!("Loading secret '{}' -> ${}", account, env_var);
        let secret = load_secret_by_ref(service, account)?;
        secrets.push(LoadedSecret {
            env_var: env_var.clone(),
            value: secret,
        });
    }

    Ok(secrets)
}

/// Load a single secret, dispatching to the appropriate backend.
///
/// If `credential_ref` starts with `op://`, delegates to the 1Password CLI.
/// Otherwise, loads from the system keyring under the given service name.
///
/// # Arguments
/// * `service` - Keyring service name (only used for keyring backend)
/// * `credential_ref` - Either a keyring account name or an `op://` URI
///
/// # Security
/// The returned value is wrapped in `Zeroizing<String>`. For `op://` URIs,
/// the CLI stdout is captured and trimmed before wrapping. Note: the
/// intermediate `Vec<u8>` from `Command::output()` is not zeroized — this
/// is the same class of limitation as the keyring crate's internal buffers.
#[must_use = "loaded secret should be used or explicitly dropped"]
pub fn load_secret_by_ref(service: &str, credential_ref: &str) -> Result<Zeroizing<String>> {
    if credential_ref.starts_with(OP_URI_PREFIX) {
        load_from_op(credential_ref)
    } else {
        load_single_secret(service, credential_ref)
    }
}

/// Validate an `op://` URI has the correct structure.
///
/// Expected format: `op://vault/item/field` (3 path segments after the scheme).
/// Additional segments (section-qualified) are also accepted:
/// `op://vault/item/section/field`.
///
/// Rejects:
/// - Empty vault, item, or field
/// - Characters that could enable argument injection
/// - URIs with query strings or fragments
pub fn validate_op_uri(uri: &str) -> Result<()> {
    let path = uri.strip_prefix(OP_URI_PREFIX).ok_or_else(|| {
        NonoError::ConfigParse(format!(
            "credential reference '{}' does not start with '{}'",
            uri, OP_URI_PREFIX
        ))
    })?;

    // Reject shell metacharacters to prevent injection
    if let Some(bad) = path.chars().find(|c| FORBIDDEN_URI_CHARS.contains(c)) {
        return Err(NonoError::ConfigParse(format!(
            "1Password URI contains forbidden character {:?}: {}",
            bad, uri
        )));
    }

    // Reject query strings and fragments
    if path.contains('?') || path.contains('#') {
        return Err(NonoError::ConfigParse(format!(
            "1Password URI must not contain query strings or fragments: {}",
            uri
        )));
    }

    // Split into segments: vault/item/field (minimum 3)
    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() < 3 {
        return Err(NonoError::ConfigParse(format!(
            "1Password URI must have at least vault/item/field segments: {}",
            uri
        )));
    }

    // No empty segments (catches `op:///item/field`, `op://vault//field`, etc.)
    if segments.iter().any(|s| s.is_empty()) {
        return Err(NonoError::ConfigParse(format!(
            "1Password URI has empty path segment: {}",
            uri
        )));
    }

    Ok(())
}

/// Returns true if the credential reference is a 1Password `op://` URI.
#[must_use]
pub fn is_op_uri(credential_ref: &str) -> bool {
    credential_ref.starts_with(OP_URI_PREFIX)
}

/// Load a single secret from the keystore.
///
/// The returned value is immediately wrapped in `Zeroizing` so the heap
/// buffer will be zeroed on drop. Note: the keyring crate may create
/// intermediate heap allocations internally (e.g. during UTF-8 conversion)
/// that are freed without being zeroed. This is a known limitation of the
/// keyring crate that we cannot address from the caller side.
fn load_single_secret(service: &str, account: &str) -> Result<Zeroizing<String>> {
    let entry = keyring::Entry::new(service, account).map_err(|e| {
        NonoError::KeystoreAccess(format!(
            "Failed to access keystore for '{}': {}",
            account, e
        ))
    })?;

    match entry.get_password() {
        Ok(password) => {
            // Immediately wrap in Zeroizing so the String's heap buffer is
            // zeroed when the secret is dropped. The move does not copy the
            // heap allocation - it transfers ownership of the same buffer.
            tracing::debug!("Successfully loaded secret '{}'", account);
            Ok(Zeroizing::new(password))
        }
        Err(keyring::Error::NoEntry) => Err(NonoError::SecretNotFound(account.to_string())),
        Err(keyring::Error::Ambiguous(creds)) => Err(NonoError::KeystoreAccess(format!(
            "Multiple entries ({}) found for '{}' - please resolve manually",
            creds.len(),
            account
        ))),
        Err(e) => Err(NonoError::KeystoreAccess(format!(
            "Cannot access '{}': {}",
            account, e
        ))),
    }
}

/// Load a secret from 1Password using the `op` CLI.
///
/// Runs `op read <uri>` and captures stdout. The `op` binary must be
/// installed and authenticated (via biometric, CLI session, or
/// `OP_SERVICE_ACCOUNT_TOKEN` in the parent environment).
///
/// # Security Notes
/// - `op` runs BEFORE the sandbox is applied, so it has network access.
/// - stdout is read into a `Zeroizing<String>` to minimize plaintext lifetime.
/// - The URI is validated before being passed to `op` to prevent argument injection.
/// - `Command::new` is used (no shell), so shell metacharacters in the URI
///   cannot cause command injection.
fn load_from_op(uri: &str) -> Result<Zeroizing<String>> {
    validate_op_uri(uri)?;

    tracing::debug!("Loading secret from 1Password: {}", redact_op_uri(uri));

    let mut child = Command::new("op")
        .args(["read", "--", uri])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                NonoError::KeystoreAccess(
                    "1Password CLI ('op') not found. \
                     Install it from https://developer.1password.com/docs/cli/"
                        .to_string(),
                )
            } else {
                NonoError::KeystoreAccess(format!("Could not start the 1Password CLI: {}", e))
            }
        })?;

    let output = wait_with_timeout(&mut child, OP_TIMEOUT).map_err(|e| {
        // Kill the process if it timed out
        let _ = child.kill();
        let _ = child.wait();
        e
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(classify_op_error(&stderr, uri));
    }

    // Convert stdout to string, trim trailing newline, wrap in Zeroizing.
    // `op read` outputs the raw secret followed by a newline.
    let raw = String::from_utf8(output.stdout).map_err(|_| {
        NonoError::KeystoreAccess(format!(
            "1Password returned non-UTF-8 data for '{}'",
            redact_op_uri(uri)
        ))
    })?;

    let trimmed = raw.trim_end_matches(['\n', '\r']).to_string();
    Ok(Zeroizing::new(trimmed))
}

/// Classify `op` CLI errors into actionable error messages.
fn classify_op_error(stderr: &str, uri: &str) -> NonoError {
    let redacted = redact_op_uri(uri);
    let stderr_trimmed = stderr.trim();

    if stderr.contains("not signed in")
        || stderr.contains("sign in")
        || stderr.contains("authentication required")
        || stderr.contains("session expired")
    {
        NonoError::KeystoreAccess(format!(
            "1Password authentication required for '{}'. \
             Run 'op signin' or set OP_SERVICE_ACCOUNT_TOKEN. \
             Detail: {}",
            redacted, stderr_trimmed
        ))
    } else if stderr.contains("not found")
        || stderr.contains("could not find")
        || stderr.contains("isn't an item")
    {
        NonoError::SecretNotFound(format!(
            "1Password item not found: '{}'. Detail: {}",
            redacted, stderr_trimmed
        ))
    } else {
        NonoError::KeystoreAccess(format!(
            "1Password CLI failed for '{}': {}",
            redacted, stderr_trimmed
        ))
    }
}

/// Redact the field segment of an `op://` URI for safe logging.
///
/// `op://vault/item/field` → `op://vault/item/<redacted>`
pub fn redact_op_uri(uri: &str) -> String {
    if let Some(path) = uri.strip_prefix(OP_URI_PREFIX) {
        let parts: Vec<&str> = path.splitn(3, '/').collect();
        if parts.len() >= 3 {
            return format!("op://{}/{}/<redacted>", parts[0], parts[1]);
        }
    }
    "op://***".to_string()
}

/// Wait for a child process with a timeout.
///
/// Returns the process output on success, or a timeout error.
fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<std::process::Output> {
    let start = std::time::Instant::now();
    let poll_interval = Duration::from_millis(100);

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Process exited — collect output
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                if let Some(mut out) = child.stdout.take() {
                    std::io::Read::read_to_end(&mut out, &mut stdout).ok();
                }
                if let Some(mut err) = child.stderr.take() {
                    std::io::Read::read_to_end(&mut err, &mut stderr).ok();
                }
                return Ok(std::process::Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                // Still running
                if start.elapsed() >= timeout {
                    return Err(NonoError::KeystoreAccess(format!(
                        "1Password CLI timed out after {}s. \
                         Is 1Password waiting for authentication?",
                        timeout.as_secs()
                    )));
                }
                std::thread::sleep(poll_interval);
            }
            Err(e) => {
                return Err(NonoError::KeystoreAccess(format!(
                    "Failed to check 1Password CLI status: {}",
                    e
                )));
            }
        }
    }
}

/// Build secret mappings from a comma-separated list of credential entries.
///
/// Supports two formats:
/// - **Keyring names**: `openai_api_key` → env var `OPENAI_API_KEY` (auto-uppercased)
/// - **1Password URIs with explicit var**: `op://vault/item/field=MY_VAR` → env var `MY_VAR`
///
/// 1Password URIs (`op://...`) **must** include `=VAR_NAME` because uppercasing a URI
/// produces a meaningless env var name. Bare `op://` URIs without `=` are rejected
/// and return an error.
///
/// # Errors
///
/// Returns an error if an `op://` URI is provided without an `=VAR_NAME` suffix.
///
/// # Example
///
/// ```
/// use nono::keystore::build_mappings_from_list;
///
/// let mappings = build_mappings_from_list("openai_api_key,anthropic_key").unwrap();
/// assert_eq!(mappings.get("openai_api_key"), Some(&"OPENAI_API_KEY".to_string()));
/// assert_eq!(mappings.get("anthropic_key"), Some(&"ANTHROPIC_KEY".to_string()));
/// ```
pub fn build_mappings_from_list(accounts: &str) -> Result<HashMap<String, String>> {
    let mut mappings = HashMap::new();

    for entry in accounts.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }

        if entry.starts_with(OP_URI_PREFIX) {
            // 1Password URI: must have =VAR_NAME suffix
            // Find the last '=' that separates the URI from the var name.
            // op:// URIs don't contain '=', so the last '=' is unambiguous.
            if let Some(eq_pos) = entry.rfind('=') {
                let uri = &entry[..eq_pos];
                let var_name = &entry[eq_pos + 1..];

                if var_name.is_empty() {
                    return Err(NonoError::ConfigParse(format!(
                        "1Password credential '{}' has '=' but no variable name. \
                         Use format: op://vault/item/field=MY_VAR",
                        redact_op_uri(uri)
                    )));
                }

                // Validate the URI portion
                validate_op_uri(uri)?;

                mappings.insert(uri.to_string(), var_name.to_string());
            } else {
                return Err(NonoError::ConfigParse(format!(
                    "1Password credential requires an explicit variable name. \
                     Use format: op://vault/item/field=MY_VAR (got '{}')",
                    redact_op_uri(entry)
                )));
            }
        } else {
            // Keyring name: auto-uppercase to env var name
            let env_var = entry.to_uppercase();
            mappings.insert(entry.to_string(), env_var);
        }
    }

    Ok(mappings)
}

/// Build secret mappings from CLI argument and/or profile secrets
///
/// Merges secrets from both sources, with CLI taking precedence.
///
/// # Arguments
/// * `cli_secrets` - Optional comma-separated list from CLI (--env-credential flag)
/// * `profile_secrets` - Mappings from profile's [secrets] section
///
/// # Returns
/// Combined map of credential reference -> env var name
///
/// # Errors
///
/// Returns an error if an `op://` URI in `cli_secrets` is missing `=VAR_NAME`.
pub fn build_secret_mappings(
    cli_secrets: Option<&str>,
    profile_secrets: &HashMap<String, String>,
) -> Result<HashMap<String, String>> {
    let mut combined = profile_secrets.clone();

    // CLI secrets override profile secrets
    if let Some(secrets_str) = cli_secrets {
        let cli_mappings = build_mappings_from_list(secrets_str)?;
        combined.extend(cli_mappings);
    }

    Ok(combined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_mappings_from_list() {
        let mappings =
            build_mappings_from_list("openai_api_key,anthropic_api_key").expect("should parse");

        assert_eq!(mappings.len(), 2);
        assert_eq!(
            mappings.get("openai_api_key"),
            Some(&"OPENAI_API_KEY".to_string())
        );
        assert_eq!(
            mappings.get("anthropic_api_key"),
            Some(&"ANTHROPIC_API_KEY".to_string())
        );
    }

    #[test]
    fn test_build_mappings_handles_whitespace() {
        let mappings = build_mappings_from_list(" key1 , key2 , key3 ").expect("should parse");

        assert_eq!(mappings.len(), 3);
        assert!(mappings.contains_key("key1"));
        assert!(mappings.contains_key("key2"));
        assert!(mappings.contains_key("key3"));
    }

    #[test]
    fn test_build_mappings_empty() {
        let mappings = build_mappings_from_list("").expect("should parse");
        assert!(mappings.is_empty());
    }

    // --- op:// URI support in build_mappings_from_list ---

    #[test]
    fn test_build_mappings_op_uri_with_var_name() {
        let mappings =
            build_mappings_from_list("op://Development/OpenAI/credential=OPENAI_API_KEY")
                .expect("should parse");

        assert_eq!(mappings.len(), 1);
        assert_eq!(
            mappings.get("op://Development/OpenAI/credential"),
            Some(&"OPENAI_API_KEY".to_string())
        );
    }

    #[test]
    fn test_build_mappings_mixed_keyring_and_op() {
        let mappings = build_mappings_from_list("my_api_key,op://vault/item/field=SECRET_VAR")
            .expect("should parse");

        assert_eq!(mappings.len(), 2);
        assert_eq!(mappings.get("my_api_key"), Some(&"MY_API_KEY".to_string()));
        assert_eq!(
            mappings.get("op://vault/item/field"),
            Some(&"SECRET_VAR".to_string())
        );
    }

    #[test]
    fn test_build_mappings_op_uri_without_var_rejected() {
        // Bare op:// URIs produce garbage env var names when uppercased
        let err = build_mappings_from_list("op://vault/item/field")
            .expect_err("should reject bare op:// URI");
        assert!(
            err.to_string().contains("explicit variable name"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_build_mappings_op_uri_empty_var_rejected() {
        // Trailing '=' with no var name
        let err = build_mappings_from_list("op://vault/item/field=")
            .expect_err("should reject empty var name");
        assert!(err.to_string().contains("no variable name"), "got: {}", err);
    }

    #[test]
    fn test_build_mappings_op_uri_invalid_uri_rejected() {
        // URI with only 2 segments should fail validation
        let err = build_mappings_from_list("op://vault/item=MY_VAR")
            .expect_err("should reject invalid URI");
        assert!(
            err.to_string().contains("at least vault/item/field"),
            "got: {}",
            err
        );
    }

    // --- op:// URI validation tests ---
    //
    // These tests verify that validate_op_uri correctly accepts valid 1Password
    // secret references and rejects malformed or dangerous ones. The rejection
    // tests are security-critical: the URI is passed as an argument to
    // `op read <uri>`, so we must prevent characters that could alter command
    // behavior even though we use Command::new (no shell).

    #[test]
    fn test_validate_op_uri_valid_3_segments() {
        // Standard 1Password reference: op://vault/item/field
        assert!(validate_op_uri("op://vault/item/field").is_ok());
    }

    #[test]
    fn test_validate_op_uri_valid_4_segments() {
        // Section-qualified reference: op://vault/item/section/field
        // 1Password supports organizing fields into sections within an item
        assert!(validate_op_uri("op://vault/item/section/field").is_ok());
    }

    #[test]
    fn test_validate_op_uri_valid_with_spaces_and_dashes() {
        // 1Password vault and item names commonly contain spaces and dashes
        assert!(validate_op_uri("op://My Vault/My-Item/api-key").is_ok());
    }

    #[test]
    fn test_validate_op_uri_missing_prefix() {
        let err = validate_op_uri("vault/item/field").expect_err("should be rejected");
        assert!(
            err.to_string().contains("does not start with"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_op_uri_too_few_segments() {
        // op://vault/item is missing the field segment — `op read` would fail
        // but we reject early to give a clear error message
        let err = validate_op_uri("op://vault/item").expect_err("should be rejected");
        assert!(
            err.to_string().contains("at least vault/item/field"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_op_uri_single_segment() {
        let err = validate_op_uri("op://vault").expect_err("should be rejected");
        assert!(
            err.to_string().contains("at least vault/item/field"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_op_uri_empty_vault() {
        // Empty vault segment could cause unexpected behavior in `op read`
        let err = validate_op_uri("op:///item/field").expect_err("should be rejected");
        assert!(
            err.to_string().contains("empty path segment"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_op_uri_empty_item() {
        let err = validate_op_uri("op://vault//field").expect_err("should be rejected");
        assert!(
            err.to_string().contains("empty path segment"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_op_uri_empty_field() {
        // Trailing slash produces an empty final segment
        let err = validate_op_uri("op://vault/item/").expect_err("should be rejected");
        assert!(
            err.to_string().contains("empty path segment"),
            "got: {}",
            err
        );
    }

    // --- Injection prevention tests ---
    //
    // Although we use Command::new (no shell), these characters are still
    // rejected as defense-in-depth. A semicolon or pipe in a URI is never
    // legitimate and likely indicates an injection attempt.

    #[test]
    fn test_validate_op_uri_forbidden_semicolon() {
        // Semicolons are shell command separators — reject to prevent
        // injection if the URI is ever accidentally passed through a shell
        let err = validate_op_uri("op://vault/item;rm -rf/field").expect_err("should be rejected");
        assert!(
            err.to_string().contains("forbidden character"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_op_uri_forbidden_pipe() {
        // Pipes could chain commands in a shell context
        let err = validate_op_uri("op://vault/item|evil/field").expect_err("should be rejected");
        assert!(
            err.to_string().contains("forbidden character"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_op_uri_forbidden_dollar() {
        // Dollar signs enable variable expansion in shell contexts —
        // could leak env vars like $HOME into the `op` argument
        let err = validate_op_uri("op://vault/$HOME/field").expect_err("should be rejected");
        assert!(
            err.to_string().contains("forbidden character"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_op_uri_forbidden_backtick() {
        // Backticks trigger command substitution in sh/bash — a classic
        // injection vector where `whoami` would execute as a subprocess
        let err = validate_op_uri("op://vault/`whoami`/field").expect_err("should be rejected");
        assert!(
            err.to_string().contains("forbidden character"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_op_uri_forbidden_newline() {
        // Newlines could cause argument splitting or log injection
        let err = validate_op_uri("op://vault/item\n/field").expect_err("should be rejected");
        assert!(
            err.to_string().contains("forbidden character"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_op_uri_query_string() {
        // 1Password URIs don't use query strings — their presence suggests
        // confusion with HTTP URLs or an attempt to inject extra parameters
        let err = validate_op_uri("op://vault/item/field?x=y").expect_err("should be rejected");
        assert!(
            err.to_string().contains("query strings or fragments"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_validate_op_uri_fragment() {
        let err = validate_op_uri("op://vault/item/field#section").expect_err("should be rejected");
        assert!(
            err.to_string().contains("query strings or fragments"),
            "got: {}",
            err
        );
    }

    // --- redact_op_uri tests ---
    //
    // The field segment (the actual secret name) is masked in logs to avoid
    // leaking what secret is being accessed. Vault and item names are kept
    // visible for debuggability.

    #[test]
    fn test_redact_op_uri_3_segments() {
        assert_eq!(
            redact_op_uri("op://MyVault/MyItem/credential"),
            "op://MyVault/MyItem/<redacted>"
        );
    }

    #[test]
    fn test_redact_op_uri_4_segments() {
        // Section-qualified URIs: everything after item is redacted
        assert_eq!(
            redact_op_uri("op://MyVault/MyItem/section/field"),
            "op://MyVault/MyItem/<redacted>"
        );
    }

    #[test]
    fn test_redact_op_uri_malformed() {
        // Malformed URIs get fully redacted — no partial information leak
        assert_eq!(redact_op_uri("op://only"), "op://***");
    }

    #[test]
    fn test_redact_op_uri_not_op() {
        // Non-op:// strings get fully redacted
        assert_eq!(redact_op_uri("keyring_account"), "op://***");
    }

    // --- classify_op_error tests ---
    //
    // Verify that `op` CLI stderr messages are mapped to actionable errors
    // so users know whether to run `op signin`, fix a typo, or debug network.

    #[test]
    fn test_classify_op_error_auth_required() {
        let err = classify_op_error(
            "[ERROR] not signed in. Run 'op signin' first.\n",
            "op://vault/item/field",
        );
        let msg = err.to_string();
        assert!(msg.contains("authentication required"), "got: {}", msg);
        assert!(msg.contains("op signin"), "got: {}", msg);
    }

    #[test]
    fn test_classify_op_error_session_expired() {
        let err = classify_op_error("[ERROR] session expired\n", "op://vault/item/field");
        let msg = err.to_string();
        assert!(msg.contains("authentication required"), "got: {}", msg);
    }

    #[test]
    fn test_classify_op_error_not_found() {
        // Maps to SecretNotFound so callers can distinguish "auth problem"
        // from "wrong vault/item name"
        let err = classify_op_error(
            "[ERROR] \"item\" not found in vault \"vault\"\n",
            "op://vault/item/field",
        );
        let msg = err.to_string();
        assert!(msg.contains("not found"), "got: {}", msg);
    }

    #[test]
    fn test_classify_op_error_unknown() {
        // Unrecognized errors fall through to a generic message
        let err = classify_op_error("[ERROR] network timeout\n", "op://vault/item/field");
        let msg = err.to_string();
        assert!(msg.contains("1Password CLI failed"), "got: {}", msg);
    }

    // --- is_op_uri tests ---

    #[test]
    fn test_is_op_uri_positive() {
        assert!(is_op_uri("op://vault/item/field"));
    }

    #[test]
    fn test_is_op_uri_negative() {
        // Bare keyring account names must not be misidentified as 1Password refs
        assert!(!is_op_uri("openai_api_key"));
    }

    // --- load_secret_by_ref dispatch ---

    #[test]
    fn test_load_secret_by_ref_dispatches_op() {
        // Verify that op:// URIs are routed to the 1Password backend, not keyring.
        // We expect a 1Password-specific error (op not installed or auth failure),
        // NOT a keyring "entry not found" error.
        let result = load_secret_by_ref("nono", "op://vault/item/field");
        assert!(result.is_err());
        let err = result.expect_err("should be rejected").to_string();
        assert!(
            err.contains("1Password") || err.contains("op"),
            "expected 1Password error, got: {}",
            err
        );
    }
}
