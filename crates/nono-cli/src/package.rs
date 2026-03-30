//! Package manifest, lockfile, and local store helpers.

use crate::profile;
use chrono::Utc;
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const LOCKFILE_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRef {
    pub namespace: String,
    pub name: String,
    pub version: Option<String>,
}

impl PackageRef {
    #[must_use]
    pub fn key(&self) -> String {
        format!("{}/{}", self.namespace, self.name)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageManifest {
    pub schema_version: u32,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub platforms: Vec<String>,
    #[serde(default)]
    pub min_nono_version: Option<String>,
    #[serde(default)]
    pub artifacts: Vec<ArtifactEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactEntry {
    #[serde(rename = "type")]
    pub artifact_type: ArtifactType,
    pub path: String,
    #[serde(default)]
    pub install_as: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub install_dir: Option<String>,
    #[serde(default)]
    pub placement: Option<String>,
    #[serde(default)]
    pub merge_strategy: Option<String>,
    #[serde(default)]
    pub prefix: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    Profile,
    Hook,
    Instruction,
    TrustPolicy,
    Groups,
    Script,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Lockfile {
    pub lockfile_version: u32,
    #[serde(default)]
    pub registry: String,
    #[serde(default)]
    pub packages: BTreeMap<String, LockedPackage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockedPackage {
    pub version: String,
    pub installed_at: String,
    #[serde(default)]
    pub provenance: Option<PackageProvenance>,
    #[serde(default)]
    pub artifacts: BTreeMap<String, LockedArtifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageProvenance {
    pub signer_identity: String,
    pub repository: String,
    pub workflow: String,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub rekor_log_index: u64,
    pub signed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockedArtifact {
    pub sha256: String,
    #[serde(rename = "type")]
    pub artifact_type: ArtifactType,
    /// External path where this artifact was installed (outside the package store).
    /// Used by `nono remove` to clean up files placed via `install_dir`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_path: Option<String>,
}

impl Default for LockedPackage {
    fn default() -> Self {
        Self {
            version: String::new(),
            installed_at: Utc::now().to_rfc3339(),
            provenance: None,
            artifacts: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageSearchResult {
    pub namespace: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub latest_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageSearchResponse {
    pub packages: Vec<PackageSearchResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullResponse {
    pub namespace: String,
    pub name: String,
    pub version: String,
    pub provenance: PullProvenance,
    pub artifacts: Vec<PullArtifact>,
    pub scan_passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullProvenance {
    pub signer_identity: String,
    pub repository: String,
    pub workflow: String,
    pub git_ref: String,
    #[serde(default)]
    pub rekor_log_index: Option<i64>,
    #[serde(default)]
    pub signed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullArtifact {
    pub filename: String,
    pub sha256_digest: String,
    pub size_bytes: i64,
    pub download_url: String,
    pub bundle_url: String,
}

pub fn parse_package_ref(input: &str) -> Result<PackageRef> {
    let (path_part, version) = match input.split_once('@') {
        Some((path, version)) if !version.is_empty() => (path, Some(version.to_string())),
        Some((_path, _)) => {
            return Err(NonoError::PackageInstall(format!(
                "invalid package reference '{input}': version must not be empty"
            )));
        }
        None => (input, None),
    };

    let mut parts = path_part.split('/');
    let namespace = parts.next().unwrap_or_default();
    let name = parts.next().unwrap_or_default();

    if namespace.is_empty() || name.is_empty() || parts.next().is_some() {
        return Err(NonoError::PackageInstall(format!(
            "invalid package reference '{input}': expected <namespace>/<name>[@<version>]"
        )));
    }

    validate_package_component("namespace", namespace)?;
    validate_package_component("name", name)?;

    Ok(PackageRef {
        namespace: namespace.to_string(),
        name: name.to_string(),
        version,
    })
}

fn validate_package_component(label: &str, value: &str) -> Result<()> {
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        Ok(())
    } else {
        Err(NonoError::PackageInstall(format!(
            "invalid package {label} '{value}': only alphanumeric, '-', '_' and '.' are allowed"
        )))
    }
}

pub fn nono_config_dir() -> Result<PathBuf> {
    Ok(profile::resolve_user_config_dir()?.join("nono"))
}

pub fn package_store_dir() -> Result<PathBuf> {
    Ok(nono_config_dir()?.join("packages"))
}

pub fn package_install_dir(namespace: &str, name: &str) -> Result<PathBuf> {
    Ok(package_store_dir()?.join(namespace).join(name))
}

pub fn package_groups_path(namespace: &str, name: &str) -> Result<PathBuf> {
    Ok(package_install_dir(namespace, name)?.join("groups.json"))
}

pub fn profiles_dir() -> Result<PathBuf> {
    Ok(nono_config_dir()?.join("profiles"))
}

pub fn lockfile_path() -> Result<PathBuf> {
    Ok(package_store_dir()?.join("lockfile.json"))
}

pub fn read_lockfile() -> Result<Lockfile> {
    let path = lockfile_path()?;
    if !path.exists() {
        return Ok(Lockfile::default());
    }

    let content = fs::read_to_string(&path).map_err(|e| NonoError::ConfigRead {
        path: path.clone(),
        source: e,
    })?;

    serde_json::from_str(&content)
        .map_err(|e| NonoError::ConfigParse(format!("failed to parse {}: {e}", path.display())))
}

pub fn write_lockfile(lockfile: &Lockfile) -> Result<()> {
    let path = lockfile_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(NonoError::Io)?;
    }

    let tmp_path = path.with_extension("json.tmp");
    let json = serde_json::to_string_pretty(lockfile)
        .map_err(|e| NonoError::ConfigParse(format!("failed to serialize lockfile: {e}")))?;
    fs::write(&tmp_path, format!("{json}\n")).map_err(NonoError::Io)?;
    fs::rename(&tmp_path, &path).map_err(NonoError::Io)?;
    Ok(())
}

pub fn remove_package_from_lockfile(package_ref: &PackageRef) -> Result<bool> {
    let mut lockfile = read_lockfile()?;
    let removed = lockfile.packages.remove(&package_ref.key()).is_some();
    if removed {
        if lockfile.lockfile_version == 0 {
            lockfile.lockfile_version = LOCKFILE_VERSION;
        }
        write_lockfile(&lockfile)?;
    }
    Ok(removed)
}

pub fn profile_link_path(profile_name: &str) -> Result<PathBuf> {
    Ok(profiles_dir()?.join(format!("{profile_name}.json")))
}

pub fn is_profile_symlink_into_package_store(profile_name: &str) -> Option<PathBuf> {
    let link_path = profile_link_path(profile_name).ok()?;
    if !link_path.exists() {
        return None;
    }

    let target = fs::canonicalize(&link_path).ok()?;
    let store = fs::canonicalize(package_store_dir().ok()?).ok()?;
    if target.starts_with(&store) {
        target.parent().map(Path::to_path_buf)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_package_ref_with_version() {
        let parsed = parse_package_ref("acme/claude-code@1.2.3").expect("parse");
        assert_eq!(parsed.namespace, "acme");
        assert_eq!(parsed.name, "claude-code");
        assert_eq!(parsed.version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn rejects_invalid_package_ref() {
        let err = parse_package_ref("broken").expect_err("must fail");
        assert!(err.to_string().contains("expected <namespace>/<name>"));
    }
}
