//! Secure credential loading from system keystore
//!
//! This module provides functionality to load secrets from the system keystore
//! (macOS Keychain / Linux Secret Service) and inject them as environment
//! variables into the sandboxed process.
//!
//! All secrets are stored under the service name "nono" in the keystore.
//! Secrets are wrapped in `Zeroizing<String>` to ensure they are securely
//! cleared from memory after use.

use crate::error::{NonoError, Result};
use std::collections::HashMap;
use std::io::{self, Write};
use zeroize::Zeroizing;

/// A credential loaded from the keystore
pub struct LoadedSecret {
    /// The environment variable name to set
    pub env_var: String,
    /// The secret value (automatically zeroized when dropped)
    pub value: Zeroizing<String>,
}

/// The service name used for all nono secrets in the keystore
const KEYSTORE_SERVICE: &str = "nono";

/// Load secrets from the system keystore
///
/// # Arguments
/// * `mappings` - Map of keystore account name -> env var name
///
/// # Returns
/// Vector of loaded secrets ready to be set as env vars
#[must_use = "loaded secrets should be used to set environment variables"]
pub fn load_secrets(mappings: &HashMap<String, String>) -> Result<Vec<LoadedSecret>> {
    let mut secrets = Vec::with_capacity(mappings.len());

    for (account, env_var) in mappings {
        tracing::debug!("Loading secret '{}' -> ${}", account, env_var);
        let secret = load_single_secret(account)?;
        secrets.push(LoadedSecret {
            env_var: env_var.clone(),
            value: secret,
        });
    }

    Ok(secrets)
}

/// Build secret mappings from CLI args and/or profile
///
/// If `--secrets` is provided with comma-separated account names,
/// auto-generates env var names by uppercasing (e.g., `openai_api_key` -> `OPENAI_API_KEY`).
///
/// If a profile is provided with a `[secrets]` section, uses those mappings.
/// CLI secrets override profile secrets for the same account.
pub fn build_secret_mappings(
    cli_secrets: Option<&str>,
    profile_secrets: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut mappings = profile_secrets.clone();

    // Parse CLI secrets (comma-separated account names)
    if let Some(secrets_arg) = cli_secrets {
        for account in secrets_arg.split(',') {
            let account = account.trim();
            if !account.is_empty() {
                // Auto-generate env var name by uppercasing
                let env_var = account.to_uppercase();
                mappings.insert(account.to_string(), env_var);
            }
        }
    }

    mappings
}

/// Load a single secret from the keystore
fn load_single_secret(account: &str) -> Result<Zeroizing<String>> {
    let entry = keyring::Entry::new(KEYSTORE_SERVICE, account).map_err(|e| {
        NonoError::KeystoreAccess(format!(
            "Failed to access keystore for '{}': {}",
            account, e
        ))
    })?;

    match entry.get_password() {
        Ok(password) => {
            tracing::debug!("Successfully loaded secret '{}'", account);
            Ok(Zeroizing::new(password))
        }
        Err(keyring::Error::NoEntry) => Err(NonoError::SecretNotFound(account.to_string())),
        Err(keyring::Error::Ambiguous(creds)) => Err(NonoError::KeystoreAccess(format!(
            "Multiple entries ({}) found for '{}' - please resolve manually",
            creds.len(),
            account
        ))),
        Err(e) => {
            // Prompt user if keystore might be locked
            prompt_unlock_and_retry(account, &entry, e)
        }
    }
}

/// Prompt the user to unlock the keystore and retry
fn prompt_unlock_and_retry(
    account: &str,
    entry: &keyring::Entry,
    original_error: keyring::Error,
) -> Result<Zeroizing<String>> {
    eprintln!(
        "Keystore access failed for '{}': {}",
        account, original_error
    );
    eprint!("Please unlock your keystore and press Enter to retry (or Ctrl+C to abort): ");
    io::stderr().flush().ok();

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| NonoError::KeystoreAccess(format!("Failed to read input: {}", e)))?;

    entry.get_password().map(Zeroizing::new).map_err(|e| {
        NonoError::KeystoreAccess(format!(
            "Still cannot access '{}' after retry: {}",
            account, e
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_secret_mappings_from_cli() {
        let mappings =
            build_secret_mappings(Some("openai_api_key,anthropic_api_key"), &HashMap::new());

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
    fn test_build_secret_mappings_from_profile() {
        let mut profile_secrets = HashMap::new();
        profile_secrets.insert("github_token".to_string(), "GITHUB_TOKEN".to_string());

        let mappings = build_secret_mappings(None, &profile_secrets);

        assert_eq!(mappings.len(), 1);
        assert_eq!(
            mappings.get("github_token"),
            Some(&"GITHUB_TOKEN".to_string())
        );
    }

    #[test]
    fn test_build_secret_mappings_cli_overrides_profile() {
        let mut profile_secrets = HashMap::new();
        profile_secrets.insert("api_key".to_string(), "PROFILE_API_KEY".to_string());

        // CLI provides same account but auto-generates different env var name
        let mappings = build_secret_mappings(Some("api_key"), &profile_secrets);

        assert_eq!(mappings.len(), 1);
        // CLI auto-generated name should override profile
        assert_eq!(mappings.get("api_key"), Some(&"API_KEY".to_string()));
    }

    #[test]
    fn test_build_secret_mappings_handles_whitespace() {
        let mappings = build_secret_mappings(Some(" key1 , key2 , key3 "), &HashMap::new());

        assert_eq!(mappings.len(), 3);
        assert!(mappings.contains_key("key1"));
        assert!(mappings.contains_key("key2"));
        assert!(mappings.contains_key("key3"));
    }

    #[test]
    fn test_build_secret_mappings_empty() {
        let mappings = build_secret_mappings(None, &HashMap::new());
        assert!(mappings.is_empty());
    }
}
