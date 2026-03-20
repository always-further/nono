//! Trust signing key storage backends.
//!
//! Trust commands use the OS keyring by default. Integration tests can opt
//! into a file-backed store by setting `NONO_TRUST_TEST_KEYSTORE_DIR`, which
//! avoids interactive keychain prompts on local machines and in CI.

use nono::{NonoError, Result};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Test-only override for trust key storage.
pub(crate) const TEST_KEYSTORE_DIR_ENV: &str = "NONO_TRUST_TEST_KEYSTORE_DIR";

enum TrustKeyStore {
    System,
    File(PathBuf),
}

impl TrustKeyStore {
    fn selected() -> Self {
        match std::env::var_os(TEST_KEYSTORE_DIR_ENV) {
            Some(dir) if !dir.is_empty() => Self::File(PathBuf::from(dir)),
            _ => Self::System,
        }
    }

    fn description(&self, service: &str) -> String {
        match self {
            Self::System => format!("system keystore (service: {service})"),
            Self::File(root) => format!("test keystore directory ({})", root.display()),
        }
    }

    fn contains(&self, service: &str, account: &str) -> Result<bool> {
        match self {
            Self::System => {
                let entry = keyring::Entry::new(service, account).map_err(|e| {
                    NonoError::KeystoreAccess(format!("failed to access keystore: {e}"))
                })?;
                match entry.get_password() {
                    Ok(_) => Ok(true),
                    Err(keyring::Error::NoEntry) => Ok(false),
                    Err(other) => Err(NonoError::KeystoreAccess(format!(
                        "failed to access key '{account}': {other}"
                    ))),
                }
            }
            Self::File(root) => Ok(file_path(root, service, account).exists()),
        }
    }

    fn load(&self, service: &str, account: &str) -> Result<String> {
        match self {
            Self::System => {
                let entry = keyring::Entry::new(service, account).map_err(|e| {
                    NonoError::KeystoreAccess(format!("failed to access keystore: {e}"))
                })?;
                entry.get_password().map_err(|e| match e {
                    keyring::Error::NoEntry => {
                        NonoError::SecretNotFound(format!("key '{account}' not found in keystore"))
                    }
                    other => NonoError::KeystoreAccess(format!(
                        "failed to load key '{account}': {other}"
                    )),
                })
            }
            Self::File(root) => {
                let path = file_path(root, service, account);
                std::fs::read_to_string(&path).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        NonoError::SecretNotFound(format!(
                            "key '{account}' not found in test keystore"
                        ))
                    } else {
                        NonoError::KeystoreAccess(format!(
                            "failed to load key '{account}' from {}: {e}",
                            path.display()
                        ))
                    }
                })
            }
        }
    }

    fn store(&self, service: &str, account: &str, secret: &str) -> Result<()> {
        match self {
            Self::System => {
                let entry = keyring::Entry::new(service, account).map_err(|e| {
                    NonoError::KeystoreAccess(format!("failed to access keystore: {e}"))
                })?;
                entry
                    .set_password(secret)
                    .map_err(|e| NonoError::KeystoreAccess(format!("failed to store key: {e}")))
            }
            Self::File(root) => {
                let path = file_path(root, service, account);
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        NonoError::KeystoreAccess(format!(
                            "failed to create test keystore directory {}: {e}",
                            parent.display()
                        ))
                    })?;
                }

                std::fs::write(&path, secret).map_err(|e| {
                    NonoError::KeystoreAccess(format!(
                        "failed to store key '{account}' at {}: {e}",
                        path.display()
                    ))
                })?;

                #[cfg(unix)]
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(
                    |e| {
                        NonoError::KeystoreAccess(format!(
                            "failed to secure test keystore file {}: {e}",
                            path.display()
                        ))
                    },
                )?;

                Ok(())
            }
        }
    }
}

fn file_path(root: &Path, service: &str, account: &str) -> PathBuf {
    root.join(hex_component(service))
        .join(hex_component(account))
}

fn hex_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len().saturating_mul(2));
    for byte in value.as_bytes() {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

pub(crate) fn backend_description(service: &str) -> String {
    TrustKeyStore::selected().description(service)
}

pub(crate) fn contains_secret(service: &str, account: &str) -> Result<bool> {
    TrustKeyStore::selected().contains(service, account)
}

pub(crate) fn load_secret(service: &str, account: &str) -> Result<String> {
    TrustKeyStore::selected().load(service, account)
}

pub(crate) fn store_secret(service: &str, account: &str, secret: &str) -> Result<()> {
    TrustKeyStore::selected().store(service, account, secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_backend_roundtrips_secret() {
        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(e) => panic!("failed to create tempdir: {e}"),
        };
        let store = TrustKeyStore::File(dir.path().to_path_buf());

        assert!(!store.contains("service", "account").unwrap_or(true));
        assert!(store.store("service", "account", "secret-value").is_ok());
        assert!(store.contains("service", "account").unwrap_or(false));

        let loaded = match store.load("service", "account") {
            Ok(loaded) => loaded,
            Err(e) => panic!("failed to load test secret: {e}"),
        };
        assert_eq!(loaded, "secret-value");
    }

    #[test]
    fn file_backend_missing_secret_is_not_found() {
        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(e) => panic!("failed to create tempdir: {e}"),
        };
        let store = TrustKeyStore::File(dir.path().to_path_buf());

        match store.load("service", "missing") {
            Err(NonoError::SecretNotFound(msg)) => {
                assert!(msg.contains("missing"));
            }
            Err(e) => panic!("unexpected error: {e}"),
            Ok(_) => panic!("expected missing secret to fail"),
        }
    }

    #[test]
    fn file_backend_separates_service_namespaces() {
        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(e) => panic!("failed to create tempdir: {e}"),
        };
        let store = TrustKeyStore::File(dir.path().to_path_buf());

        assert!(store.store("service-a", "account", "secret-a").is_ok());
        assert!(store.store("service-b", "account", "secret-b").is_ok());

        let a = match store.load("service-a", "account") {
            Ok(value) => value,
            Err(e) => panic!("failed to load service-a secret: {e}"),
        };
        let b = match store.load("service-b", "account") {
            Ok(value) => value,
            Err(e) => panic!("failed to load service-b secret: {e}"),
        };

        assert_eq!(a, "secret-a");
        assert_eq!(b, "secret-b");
    }
}
