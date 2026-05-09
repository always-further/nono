//! Registry client for package hosting.

use crate::package::{PackageRef, PackageSearchResponse, PackageSearchResult, PullResponse};
use nono::{NonoError, Result};
use serde::de::DeserializeOwned;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

pub const DEFAULT_REGISTRY_URL: &str = "https://registry.nono.sh";

const REGISTRY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REGISTRY_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const REGISTRY_BODY_TIMEOUT: Duration = Duration::from_secs(300);
const REGISTRY_CALL_TIMEOUT: Duration = Duration::from_secs(300);
const REGISTRY_JSON_LIMIT_BYTES: u64 = 2 * 1024 * 1024;
const REGISTRY_BUNDLE_LIMIT_BYTES: u64 = 8 * 1024 * 1024;
const REGISTRY_ARTIFACT_LIMIT_BYTES: u64 = 64 * 1024 * 1024;

pub struct RegistryClient {
    base_url: String,
    http: ureq::Agent,
}

impl RegistryClient {
    #[must_use]
    pub fn new(base_url: String) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http: ureq::Agent::config_builder()
                .timeout_global(Some(REGISTRY_CALL_TIMEOUT))
                .timeout_resolve(Some(REGISTRY_CONNECT_TIMEOUT))
                .timeout_connect(Some(REGISTRY_CONNECT_TIMEOUT))
                .timeout_recv_response(Some(REGISTRY_RESPONSE_TIMEOUT))
                .timeout_recv_body(Some(REGISTRY_BODY_TIMEOUT))
                .build()
                .new_agent(),
        }
    }

    pub fn fetch_pull_response(
        &self,
        package_ref: &PackageRef,
        version: &str,
    ) -> Result<PullResponse> {
        self.get_json(&format!(
            "/api/v1/packages/{}/{}/versions/{version}/pull",
            package_ref.namespace, package_ref.name
        ))
    }

    pub fn search_packages(&self, query: &str) -> Result<Vec<PackageSearchResult>> {
        let response: PackageSearchResponse =
            self.get_json(&format!("/api/v1/packages?q={query}"))?;
        Ok(response.packages)
    }

    /// Download a trust bundle JSON document, capped to
    /// `REGISTRY_BUNDLE_LIMIT_BYTES` and returned as a string.
    pub fn download_bundle(&self, url: &str) -> Result<String> {
        let resolved_url = self.resolve_url(url);
        let mut response = self
            .http
            .get(&resolved_url)
            .call()
            .map_err(map_ureq_error)?;
        enforce_content_length(
            response.body().content_length(),
            REGISTRY_BUNDLE_LIMIT_BYTES,
            &resolved_url,
        )?;
        response
            .body_mut()
            .with_config()
            .limit(REGISTRY_BUNDLE_LIMIT_BYTES)
            .read_to_string()
            .map_err(|e| {
                NonoError::RegistryError(format!(
                    "failed to read registry response from {}: {}",
                    resolved_url, e
                ))
            })
    }

    /// Stream an artifact response body to `dest`, computing its SHA-256
    /// digest incrementally. Memory profile is bounded to the 8 KiB I/O
    /// buffer regardless of artifact size; the body is capped at
    /// `REGISTRY_ARTIFACT_LIMIT_BYTES` and any partial file is removed
    /// on stream-read failure.
    ///
    /// Returns the lowercase hex SHA-256 digest of the streamed bytes.
    pub fn download_artifact_to_path(&self, url: &str, dest: &Path) -> Result<String> {
        let resolved_url = self.resolve_url(url);
        let mut response = self
            .http
            .get(&resolved_url)
            .call()
            .map_err(map_ureq_error)?;
        enforce_content_length(
            response.body().content_length(),
            REGISTRY_ARTIFACT_LIMIT_BYTES,
            &resolved_url,
        )?;

        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(NonoError::Io)?;
        }

        let mut reader = response
            .body_mut()
            .with_config()
            .limit(REGISTRY_ARTIFACT_LIMIT_BYTES)
            .reader();
        let mut file = fs::File::create(dest).map_err(NonoError::Io)?;
        let mut hasher = sha2::Sha256::new();
        let mut buffer = [0_u8; 8192];

        loop {
            let bytes_read = match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(bytes_read) => bytes_read,
                Err(error) => {
                    let _ = fs::remove_file(dest);
                    return Err(NonoError::RegistryError(format!(
                        "failed to read registry response from {}: {}",
                        resolved_url, error
                    )));
                }
            };
            file.write_all(&buffer[..bytes_read])
                .map_err(NonoError::Io)?;
            use sha2::Digest as _;
            hasher.update(&buffer[..bytes_read]);
        }

        use sha2::Digest as _;
        let digest = hasher.finalize();
        Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);
        let mut response = self.http.get(&url).call().map_err(map_ureq_error)?;
        enforce_content_length(
            response.body().content_length(),
            REGISTRY_JSON_LIMIT_BYTES,
            &url,
        )?;
        let body = response
            .body_mut()
            .with_config()
            .limit(REGISTRY_JSON_LIMIT_BYTES)
            .read_to_string()
            .map_err(|e| {
                NonoError::RegistryError(format!(
                    "failed to read registry response from {}: {}",
                    url, e
                ))
            })?;
        serde_json::from_str(&body).map_err(|e| {
            NonoError::RegistryError(format!("failed to decode registry response: {e}"))
        })
    }

    fn resolve_url(&self, url: &str) -> String {
        // SAFETY: not a path comparison — `url` is a registry URL string and these
        // checks are URL scheme prefix tests. CLAUDE.md § Common Footguns #1 forbids
        // `&str::starts_with` on PATH inputs, but URL scheme prefix detection is
        // the canonical use case for it.
        if url.starts_with("http://") || url.starts_with("https://") {
            url.to_string()
        } else {
            format!("{}{}", self.base_url, url)
        }
    }
}

pub fn resolve_registry_url(override_url: Option<&str>) -> String {
    override_url
        .map(ToOwned::to_owned)
        .or_else(|| std::env::var("NONO_REGISTRY").ok())
        .unwrap_or_else(|| DEFAULT_REGISTRY_URL.to_string())
}

fn map_ureq_error(error: ureq::Error) -> NonoError {
    NonoError::RegistryError(error.to_string())
}

/// Reject responses whose advertised Content-Length exceeds `limit`.
/// Returns Ok(()) when the header is absent (not all servers send it);
/// downstream readers also enforce the limit via `with_config().limit(...)`.
fn enforce_content_length(content_length: Option<u64>, limit: u64, url: &str) -> Result<()> {
    if let Some(content_length) = content_length {
        if content_length > limit {
            return Err(NonoError::RegistryError(format!(
                "registry response from {} exceeds {} bytes",
                url, limit
            )));
        }
    }

    Ok(())
}
