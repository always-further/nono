//! Package command handlers.

use crate::cli::{ListArgs, PullArgs, RemoveArgs, SearchArgs, UpdateArgs};
use crate::package::{
    self, ArtifactEntry, ArtifactType, LockedArtifact, LockedPackage, PackageManifest,
    PackageProvenance, PackageRef, PullResponse,
};
use crate::registry_client::{resolve_registry_url, RegistryClient};
use chrono::{DateTime, Local, Utc};
use nono::{NonoError, Result, SignerIdentity};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

pub fn run_pull(args: PullArgs) -> Result<()> {
    let package_ref = package::parse_package_ref(&args.package_ref)?;
    let registry_url = resolve_registry_url(args.registry.as_deref());
    let client = RegistryClient::new(registry_url.clone());

    let requested_version = package_ref.version.as_deref().unwrap_or("latest");
    let pull = client.fetch_pull_response(&package_ref, requested_version)?;
    validate_pull_response(&package_ref, &pull)?;

    let lockfile = package::read_lockfile()?;
    if let Some(existing) = lockfile.packages.get(&package_ref.key()) {
        if existing.version == pull.version && !args.force {
            eprintln!(
                "{} is already up to date at {}",
                package_ref.key(),
                pull.version
            );
            return Ok(());
        }
    }

    let downloads = download_and_verify_artifacts(&client, &package_ref, &pull)?;
    let manifest = load_manifest(&downloads)?;
    validate_manifest(&manifest)?;

    let signer_identity = signer_identity_uri(&downloads[0].signer_identity)?;
    enforce_signer_pinning(
        lockfile.packages.get(&package_ref.key()),
        &signer_identity,
        args.force,
    )?;

    let install = install_package(&package_ref, &manifest, &downloads, args.init)?;
    update_lockfile(
        &package_ref,
        &registry_url,
        &pull,
        &signer_identity,
        &downloads,
        &install.external_paths,
    )?;

    print_pull_summary(&package_ref, &pull, &install);
    Ok(())
}

pub fn run_remove(args: RemoveArgs) -> Result<()> {
    let package_ref = package::parse_package_ref(&args.package_ref)?;

    // Read lockfile before deleting anything — we need external paths and
    // hook artifact info for cleanup.
    let lockfile = package::read_lockfile()?;
    let locked_pkg = lockfile.packages.get(&package_ref.key());

    let install_dir = package::package_install_dir(&package_ref.namespace, &package_ref.name)?;
    let install_dir_existed = install_dir.exists();

    if locked_pkg.is_none() && !install_dir_existed {
        return Err(NonoError::PackageInstall(format!(
            "package {} is not installed",
            package_ref.key()
        )));
    }

    // Remove externally placed files tracked in the lockfile.
    if let Some(pkg) = locked_pkg {
        remove_external_artifacts(pkg);
        // Unregister hooks from target app settings.
        unregister_package_hooks(&package_ref, &install_dir);
    }

    // Remove profile symlinks.
    let profile_link = package::profile_link_path(&package_ref.name)?;
    if profile_link.exists()
        && package::is_profile_symlink_into_package_store(&package_ref.name).is_some()
    {
        fs::remove_file(&profile_link).map_err(NonoError::Io)?;
    }

    // Also check for other profile symlinks from the manifest.
    if install_dir.exists() {
        remove_all_profile_symlinks_for_package(&install_dir)?;
    }

    // Remove the package store directory.
    if install_dir.exists() {
        fs::remove_dir_all(&install_dir).map_err(NonoError::Io)?;
    }

    // Clean up empty namespace directory.
    if let Some(ns_dir) = install_dir.parent() {
        if ns_dir.exists() && is_dir_empty(ns_dir) {
            let _ = fs::remove_dir(ns_dir);
        }
    }

    package::remove_package_from_lockfile(&package_ref)?;

    eprintln!("Removed {}", package_ref.key());
    Ok(())
}

/// Remove files that were installed outside the package store via install_dir.
fn remove_external_artifacts(pkg: &LockedPackage) {
    for (name, artifact) in &pkg.artifacts {
        if let Some(installed_path) = &artifact.installed_path {
            let path = Path::new(installed_path);
            if path.exists() {
                if let Err(e) = fs::remove_file(path) {
                    tracing::warn!("Failed to remove external artifact {}: {}", name, e);
                } else {
                    tracing::info!("Removed {}", installed_path);
                }
            }
        }
    }
}

/// Attempt to unregister hooks from target app settings files.
///
/// Reads the package's stored manifest to find hook artifacts with target info,
/// then removes the corresponding entries from the target app's settings.
fn unregister_package_hooks(package_ref: &PackageRef, install_dir: &Path) {
    let manifest_path = install_dir.join("package.json");
    if !manifest_path.exists() {
        return;
    }

    let manifest: PackageManifest = match fs::read_to_string(&manifest_path)
        .ok()
        .and_then(|c| serde_json::from_str(&c).ok())
    {
        Some(m) => m,
        None => return,
    };

    for artifact in &manifest.artifacts {
        if artifact.artifact_type != ArtifactType::Hook {
            continue;
        }

        let target = artifact.target.as_deref().unwrap_or(&package_ref.name);

        match target {
            "claude-code" => {
                if let Err(e) = unregister_claude_code_hook(&artifact.path) {
                    tracing::warn!("Failed to unregister Claude Code hook: {}", e);
                }
            }
            _ => {
                tracing::debug!("No unregistration logic for hook target '{}'", target);
            }
        }
    }
}

/// Remove a hook entry from Claude Code's ~/.claude/settings.json.
fn unregister_claude_code_hook(script_filename: &str) -> Result<()> {
    let home = xdg_home::home_dir().ok_or(NonoError::HomeNotFound)?;
    let settings_path = home.join(".claude").join("settings.json");
    if !settings_path.exists() {
        return Ok(());
    }

    let content = fs::read_to_string(&settings_path).map_err(|e| NonoError::ConfigRead {
        path: settings_path.clone(),
        source: e,
    })?;

    let mut settings: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| NonoError::ConfigParse(format!("failed to parse settings.json: {e}")))?;

    let fname = file_name(script_filename).unwrap_or(script_filename);
    let hook_command = format!("$HOME/.claude/hooks/{fname}");

    let modified = remove_hook_command_from_settings(&mut settings, &hook_command);
    if modified {
        let json = serde_json::to_string_pretty(&settings)
            .map_err(|e| NonoError::ConfigParse(format!("failed to serialize settings: {e}")))?;
        fs::write(&settings_path, json).map_err(NonoError::Io)?;
        tracing::info!("Unregistered hook from {}", settings_path.display());
    }

    // Also remove the script file from ~/.claude/hooks/.
    let script_path = home.join(".claude").join("hooks").join(fname);
    if script_path.exists() {
        let _ = fs::remove_file(&script_path);
    }

    Ok(())
}

/// Walk through settings.hooks.* arrays and remove entries whose command
/// matches the given hook_command. Returns true if anything was removed.
fn remove_hook_command_from_settings(settings: &mut serde_json::Value, hook_command: &str) -> bool {
    let hooks = match settings.get_mut("hooks").and_then(|v| v.as_object_mut()) {
        Some(h) => h,
        None => return false,
    };

    let mut modified = false;
    for (_event, entries) in hooks.iter_mut() {
        if let Some(arr) = entries.as_array_mut() {
            let before = arr.len();
            arr.retain(|entry| {
                if let Some(hook_arr) = entry.get("hooks").and_then(|v| v.as_array()) {
                    !hook_arr.iter().any(|h| {
                        h.get("command")
                            .and_then(|c| c.as_str())
                            .map(|c| c == hook_command)
                            .unwrap_or(false)
                    })
                } else {
                    true
                }
            });
            if arr.len() != before {
                modified = true;
            }
        }
    }

    modified
}

/// Find all profile symlinks in the global profiles dir that point into
/// the given package install directory and remove them.
fn remove_all_profile_symlinks_for_package(install_dir: &Path) -> Result<()> {
    let profiles_dir = package::profiles_dir()?;
    if !profiles_dir.exists() {
        return Ok(());
    }

    let entries = fs::read_dir(&profiles_dir).map_err(NonoError::Io)?;
    for entry in entries {
        let entry = entry.map_err(NonoError::Io)?;
        let path = entry.path();
        if let Ok(target) = fs::read_link(&path) {
            // Resolve to absolute for comparison.
            let resolved = if target.is_absolute() {
                target
            } else {
                profiles_dir.join(&target)
            };
            if resolved.starts_with(install_dir) {
                let _ = fs::remove_file(&path);
            }
        }
    }

    Ok(())
}

fn is_dir_empty(path: &Path) -> bool {
    fs::read_dir(path)
        .map(|mut entries| entries.next().is_none())
        .unwrap_or(false)
}

pub fn run_update(args: UpdateArgs) -> Result<()> {
    if let Some(package_ref) = args.package_ref {
        let package_ref = package::parse_package_ref(&package_ref)?;
        return Err(NonoError::PackageInstall(format!(
            "package update flow for {} is not implemented yet",
            package_ref.key()
        )));
    }

    Err(NonoError::PackageInstall(
        "bulk package update is not implemented yet".to_string(),
    ))
}

pub fn run_search(args: SearchArgs) -> Result<()> {
    let registry_url = resolve_registry_url(args.registry.as_deref());
    let client = RegistryClient::new(registry_url);
    let results = client.search_packages(&args.query)?;

    if args.json {
        let json = serde_json::to_string_pretty(&results).map_err(|e| {
            NonoError::ConfigParse(format!("failed to serialize search results: {e}"))
        })?;
        println!("{json}");
        return Ok(());
    }

    if results.is_empty() {
        println!("No packages found.");
        return Ok(());
    }

    for result in results {
        let version = result.latest_version.unwrap_or_else(|| "-".to_string());
        let description = result.description.unwrap_or_default();
        println!(
            "{}\t{}\t{}",
            format_args!("{}/{}", result.namespace, result.name),
            version,
            description
        );
    }

    Ok(())
}

pub fn run_list(args: ListArgs) -> Result<()> {
    let lockfile = package::read_lockfile()?;

    if args.installed {
        if args.json {
            let json = serde_json::to_string_pretty(&lockfile).map_err(|e| {
                NonoError::ConfigParse(format!("failed to serialize lockfile: {e}"))
            })?;
            println!("{json}");
            return Ok(());
        }

        if lockfile.packages.is_empty() {
            println!("No installed packages.");
            return Ok(());
        }

        for (name, pkg) in lockfile.packages {
            let installed_at = format_timestamp(&pkg.installed_at);
            println!("{name}\t{}\t{installed_at}", pkg.version);
        }
        return Ok(());
    }

    Err(NonoError::PackageInstall(
        "only `nono list --installed` is currently supported".to_string(),
    ))
}

#[derive(Clone)]
struct DownloadedArtifact {
    filename: String,
    bytes: Vec<u8>,
    sha256_digest: String,
    signer_identity: SignerIdentity,
}

struct InstallSummary {
    installed_artifacts: usize,
    copied_to_project: usize,
    /// Maps artifact filename -> external installed path (if install_dir was used).
    external_paths: HashMap<String, PathBuf>,
}

fn validate_pull_response(package_ref: &PackageRef, pull: &PullResponse) -> Result<()> {
    if pull.namespace != package_ref.namespace || pull.name != package_ref.name {
        return Err(NonoError::PackageVerification {
            package: package_ref.key(),
            reason: format!(
                "registry returned {} / {} for requested package {}",
                pull.namespace,
                pull.name,
                package_ref.key()
            ),
        });
    }

    if pull.artifacts.is_empty() {
        return Err(NonoError::PackageVerification {
            package: package_ref.key(),
            reason: "pull response did not include any artifacts".to_string(),
        });
    }

    Ok(())
}

fn download_and_verify_artifacts(
    client: &RegistryClient,
    package_ref: &PackageRef,
    pull: &PullResponse,
) -> Result<Vec<DownloadedArtifact>> {
    let trusted_root = nono::trust::load_production_trusted_root()?;
    let policy = nono::trust::VerificationPolicy::default();
    let mut downloads = Vec::with_capacity(pull.artifacts.len());
    let mut expected_signer: Option<SignerIdentity> = None;

    for artifact in &pull.artifacts {
        let bytes = client.download_bytes(&artifact.download_url)?;
        let bundle_json = client.download_text(&artifact.bundle_url)?;
        let bundle = nono::trust::load_bundle_from_str(
            &bundle_json,
            Path::new(&format!("{}.bundle", artifact.filename)),
        )?;

        nono::trust::verify_bundle_subject_name(&bundle, Path::new(&artifact.filename))?;
        nono::trust::verify_bundle(
            &bytes,
            &bundle,
            &trusted_root,
            &policy,
            Path::new(&artifact.filename),
        )?;

        let signer_identity =
            nono::trust::extract_signer_identity(&bundle, Path::new(&artifact.filename))?;
        enforce_namespace_assertion(package_ref, &signer_identity)?;
        enforce_signer_consistency(package_ref, &mut expected_signer, &signer_identity)?;

        let digest = sha256_hex(&bytes);
        if digest != artifact.sha256_digest {
            return Err(NonoError::PackageVerification {
                package: package_ref.key(),
                reason: format!(
                    "artifact {} digest mismatch: registry={}, local={}",
                    artifact.filename, artifact.sha256_digest, digest
                ),
            });
        }

        downloads.push(DownloadedArtifact {
            filename: artifact.filename.clone(),
            bytes,
            sha256_digest: digest,
            signer_identity,
        });
    }

    Ok(downloads)
}

fn load_manifest(downloads: &[DownloadedArtifact]) -> Result<PackageManifest> {
    let manifest = downloads
        .iter()
        .find(|artifact| artifact.filename == "package.json")
        .ok_or_else(|| NonoError::PackageInstall("package is missing package.json".to_string()))?;

    serde_json::from_slice::<PackageManifest>(&manifest.bytes).map_err(|e| {
        NonoError::PackageInstall(format!("failed to parse package.json manifest: {e}"))
    })
}

fn validate_manifest(manifest: &PackageManifest) -> Result<()> {
    if !manifest.platforms.is_empty()
        && !manifest
            .platforms
            .iter()
            .any(|platform| platform == current_platform())
    {
        return Err(NonoError::PackageInstall(format!(
            "package does not support {}",
            current_platform()
        )));
    }

    if let Some(min_version) = &manifest.min_nono_version {
        if compare_versions(env!("CARGO_PKG_VERSION"), min_version).is_lt() {
            return Err(NonoError::PackageInstall(format!(
                "package requires nono >= {}, current version is {}",
                min_version,
                env!("CARGO_PKG_VERSION")
            )));
        }
    }

    Ok(())
}

fn install_package(
    package_ref: &PackageRef,
    manifest: &PackageManifest,
    downloads: &[DownloadedArtifact],
    init: bool,
) -> Result<InstallSummary> {
    let staging_parent = package::package_store_dir()?
        .join(".staging")
        .join(&package_ref.namespace);
    fs::create_dir_all(&staging_parent).map_err(NonoError::Io)?;
    let tempdir = TempDir::new_in(&staging_parent).map_err(NonoError::Io)?;
    let staging_root = tempdir.path().join(&package_ref.name);
    fs::create_dir_all(&staging_root).map_err(NonoError::Io)?;

    let mut downloaded_by_name: HashMap<&str, &DownloadedArtifact> =
        HashMap::with_capacity(downloads.len());
    for artifact in downloads {
        downloaded_by_name.insert(artifact.filename.as_str(), artifact);
    }

    write_supporting_artifacts(&staging_root, downloads)?;

    let mut copied_to_project = 0usize;
    let mut external_paths: HashMap<String, PathBuf> = HashMap::new();
    for artifact in &manifest.artifacts {
        let downloaded = downloaded_by_name
            .get(artifact.path.as_str())
            .ok_or_else(|| {
                NonoError::PackageInstall(format!(
                    "manifest references missing artifact '{}'",
                    artifact.path
                ))
            })?;
        if let Some(ext_path) =
            install_manifest_artifact(&staging_root, artifact, downloaded.bytes.as_slice())?
        {
            external_paths.insert(artifact.path.clone(), ext_path);
        }
        if init
            && artifact.artifact_type == ArtifactType::Instruction
            && artifact.placement.as_deref() == Some("project")
        {
            copy_instruction_to_project(artifact, downloaded.bytes.as_slice())?;
            copied_to_project = copied_to_project.saturating_add(1);
        }
    }

    let final_root = package::package_install_dir(&package_ref.namespace, &package_ref.name)?;
    if let Some(parent) = final_root.parent() {
        fs::create_dir_all(parent).map_err(NonoError::Io)?;
    }
    if final_root.exists() {
        fs::remove_dir_all(&final_root).map_err(NonoError::Io)?;
    }
    fs::rename(&staging_root, &final_root).map_err(NonoError::Io)?;
    tempdir.close().map_err(NonoError::Io)?;

    create_profile_symlinks(package_ref, manifest)?;

    Ok(InstallSummary {
        installed_artifacts: manifest.artifacts.len(),
        copied_to_project,
        external_paths,
    })
}

fn write_supporting_artifacts(staging_root: &Path, downloads: &[DownloadedArtifact]) -> Result<()> {
    for artifact in downloads {
        if artifact.filename == "package.json" {
            let path = staging_root.join("package.json");
            fs::write(&path, &artifact.bytes).map_err(NonoError::Io)?;
        }
    }
    Ok(())
}

/// Install an artifact into the package staging directory and optionally to an
/// external `install_dir` path declared in the manifest. Returns the external
/// path if one was written, so callers can record it in the lockfile.
fn install_manifest_artifact(
    staging_root: &Path,
    artifact: &ArtifactEntry,
    bytes: &[u8],
) -> Result<Option<PathBuf>> {
    // Write into the package store (staging root) based on type.
    let store_path = match artifact.artifact_type {
        ArtifactType::Profile => {
            let install_name = artifact.install_as.as_deref().ok_or_else(|| {
                NonoError::PackageInstall(format!(
                    "profile artifact '{}' is missing install_as",
                    artifact.path
                ))
            })?;
            let path = staging_root
                .join("profiles")
                .join(format!("{install_name}.json"));
            write_bytes(&path, bytes)?;
            parse_json::<crate::profile::Profile>(&path)?;
            path
        }
        ArtifactType::Hook => {
            let path = staging_root.join("hooks").join(file_name(&artifact.path)?);
            write_bytes(&path, bytes)?;
            ensure_executable(&path)?;
            path
        }
        ArtifactType::Instruction => {
            let path = staging_root
                .join("instructions")
                .join(file_name(&artifact.path)?);
            write_bytes(&path, bytes)?;
            path
        }
        ArtifactType::TrustPolicy => {
            let path = staging_root.join("trust-policy.json");
            write_bytes(&path, bytes)?;
            let content = std::str::from_utf8(bytes).map_err(|e| {
                NonoError::PackageInstall(format!("trust policy is not valid UTF-8: {e}"))
            })?;
            nono::trust::load_policy_from_str(content)?;
            path
        }
        ArtifactType::Groups => {
            let prefix = artifact.prefix.as_deref().ok_or_else(|| {
                NonoError::PackageInstall(format!(
                    "groups artifact '{}' is missing prefix",
                    artifact.path
                ))
            })?;
            let path = staging_root.join("groups.json");
            write_bytes(&path, bytes)?;
            validate_groups(bytes, prefix)?;
            path
        }
        ArtifactType::Script => {
            let path = staging_root
                .join("scripts")
                .join(file_name(&artifact.path)?);
            write_bytes(&path, bytes)?;
            ensure_executable(&path)?;
            path
        }
    };

    // If the manifest declares an install_dir, also place the file there.
    let external_path = if let Some(install_dir) = &artifact.install_dir {
        let expanded = expand_tilde(install_dir)?;
        let dest_name = artifact
            .install_as
            .as_deref()
            .map(|n| {
                // For profiles, install_as is already just the name
                if artifact.artifact_type == ArtifactType::Profile {
                    format!("{n}.json")
                } else {
                    n.to_string()
                }
            })
            .unwrap_or_else(|| {
                store_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("artifact")
                    .to_string()
            });
        let dest = expanded.join(&dest_name);
        write_bytes(&dest, bytes)?;
        if matches!(
            artifact.artifact_type,
            ArtifactType::Hook | ArtifactType::Script
        ) {
            ensure_executable(&dest)?;
        }
        Some(dest)
    } else {
        None
    };

    Ok(external_path)
}

fn copy_instruction_to_project(artifact: &ArtifactEntry, bytes: &[u8]) -> Result<()> {
    let cwd = std::env::current_dir().map_err(NonoError::Io)?;
    let path = cwd.join(file_name(&artifact.path)?);
    if path.exists() {
        return Ok(());
    }
    fs::write(path, bytes).map_err(NonoError::Io)
}

fn create_profile_symlinks(package_ref: &PackageRef, manifest: &PackageManifest) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        fs::create_dir_all(package::profiles_dir()?).map_err(NonoError::Io)?;
        for artifact in &manifest.artifacts {
            if artifact.artifact_type != ArtifactType::Profile {
                continue;
            }

            let install_name = artifact.install_as.as_deref().ok_or_else(|| {
                NonoError::PackageInstall(format!(
                    "profile artifact '{}' is missing install_as",
                    artifact.path
                ))
            })?;
            let link_path = package::profile_link_path(install_name)?;
            let target = package::package_install_dir(&package_ref.namespace, &package_ref.name)?
                .join("profiles")
                .join(format!("{install_name}.json"));

            if link_path.exists() {
                if package::is_profile_symlink_into_package_store(install_name).is_none() {
                    return Err(NonoError::PackageInstall(format!(
                        "profile '{}' already exists and is not package-managed",
                        install_name
                    )));
                }
                fs::remove_file(&link_path).map_err(NonoError::Io)?;
            }

            symlink(&target, &link_path).map_err(NonoError::Io)?;
        }
    }

    Ok(())
}

fn validate_groups(bytes: &[u8], prefix: &str) -> Result<()> {
    let groups: HashMap<String, crate::policy::Group> = serde_json::from_slice(bytes)
        .map_err(|e| NonoError::PackageInstall(format!("failed to parse groups.json: {e}")))?;
    let embedded = crate::policy::load_policy(crate::config::embedded::embedded_policy_json())?;

    for name in groups.keys() {
        if !name.starts_with(prefix) {
            return Err(NonoError::PackageInstall(format!(
                "group '{}' does not start with required prefix '{}'",
                name, prefix
            )));
        }
        if embedded.groups.contains_key(name) {
            return Err(NonoError::PackageInstall(format!(
                "group '{}' collides with an embedded policy group",
                name
            )));
        }
    }

    Ok(())
}

fn update_lockfile(
    package_ref: &PackageRef,
    registry_url: &str,
    pull: &PullResponse,
    signer_identity: &str,
    downloads: &[DownloadedArtifact],
    external_paths: &HashMap<String, PathBuf>,
) -> Result<()> {
    let mut lockfile = package::read_lockfile()?;
    lockfile.lockfile_version = package::LOCKFILE_VERSION;
    lockfile.registry = registry_url.to_string();

    let artifacts = downloads
        .iter()
        .filter(|artifact| artifact.filename != "package.json")
        .map(|artifact| {
            let installed_path = external_paths
                .get(&artifact.filename)
                .map(|p| p.to_string_lossy().into_owned());
            (
                artifact.filename.clone(),
                LockedArtifact {
                    sha256: artifact.sha256_digest.clone(),
                    artifact_type: infer_artifact_type(&artifact.filename),
                    installed_path,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    lockfile.packages.insert(
        package_ref.key(),
        LockedPackage {
            version: pull.version.clone(),
            installed_at: Utc::now().to_rfc3339(),
            provenance: Some(PackageProvenance {
                signer_identity: signer_identity.to_string(),
                repository: pull.provenance.repository.clone(),
                workflow: pull.provenance.workflow.clone(),
                git_ref: pull.provenance.git_ref.clone(),
                rekor_log_index: pull.provenance.rekor_log_index.unwrap_or_default() as u64,
                signed_at: pull
                    .provenance
                    .signed_at
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_else(|| Utc::now().to_rfc3339()),
            }),
            artifacts,
        },
    );

    package::write_lockfile(&lockfile)
}

fn print_pull_summary(package_ref: &PackageRef, pull: &PullResponse, install: &InstallSummary) {
    eprintln!("Pulled {}@{}", package_ref.key(), pull.version);
    eprintln!("  Signer: {}", pull.provenance.signer_identity);
    eprintln!("  Repository: {}", pull.provenance.repository);
    eprintln!("  Workflow: {}", pull.provenance.workflow);
    eprintln!(
        "  Scan: {}",
        if pull.scan_passed { "passed" } else { "failed" }
    );
    eprintln!("  Installed {} artifact(s)", install.installed_artifacts);
    for (artifact_name, ext_path) in &install.external_paths {
        eprintln!("    {} -> {}", artifact_name, ext_path.display());
    }
    if install.copied_to_project > 0 {
        eprintln!(
            "  Copied {} instruction file(s) into the current directory",
            install.copied_to_project
        );
    }
}

fn enforce_namespace_assertion(
    package_ref: &PackageRef,
    signer_identity: &SignerIdentity,
) -> Result<()> {
    match signer_identity {
        SignerIdentity::Keyless { repository, .. } => {
            let signer_namespace = repository.split('/').next().unwrap_or_default();
            if signer_namespace != package_ref.namespace {
                return Err(NonoError::PackageVerification {
                    package: package_ref.key(),
                    reason: format!(
                        "signer namespace '{}' does not match requested namespace '{}'",
                        signer_namespace, package_ref.namespace
                    ),
                });
            }
            Ok(())
        }
        SignerIdentity::Keyed { .. } => Err(NonoError::PackageVerification {
            package: package_ref.key(),
            reason: "registry packages must use keyless Sigstore signing".to_string(),
        }),
    }
}

fn enforce_signer_consistency(
    package_ref: &PackageRef,
    expected_signer: &mut Option<SignerIdentity>,
    signer_identity: &SignerIdentity,
) -> Result<()> {
    match expected_signer {
        Some(existing) if !same_signer(existing, signer_identity) => {
            Err(NonoError::PackageVerification {
                package: package_ref.key(),
                reason: "artifacts in the package were signed by different identities".to_string(),
            })
        }
        Some(_) => Ok(()),
        None => {
            *expected_signer = Some(signer_identity.clone());
            Ok(())
        }
    }
}

fn enforce_signer_pinning(
    existing: Option<&LockedPackage>,
    signer_identity: &str,
    force: bool,
) -> Result<()> {
    if force {
        return Ok(());
    }

    if let Some(existing) = existing {
        if let Some(provenance) = &existing.provenance {
            if provenance.signer_identity != signer_identity {
                return Err(NonoError::PackageVerification {
                    package: provenance.repository.clone(),
                    reason: format!(
                        "signer identity changed from '{}' to '{}'",
                        provenance.signer_identity, signer_identity
                    ),
                });
            }
        }
    }

    Ok(())
}

fn same_signer(left: &SignerIdentity, right: &SignerIdentity) -> bool {
    match (left, right) {
        (
            SignerIdentity::Keyless {
                repository: l_repo,
                workflow: l_workflow,
                git_ref: l_ref,
                ..
            },
            SignerIdentity::Keyless {
                repository: r_repo,
                workflow: r_workflow,
                git_ref: r_ref,
                ..
            },
        ) => l_repo == r_repo && l_workflow == r_workflow && l_ref == r_ref,
        (SignerIdentity::Keyed { key_id: l }, SignerIdentity::Keyed { key_id: r }) => l == r,
        _ => false,
    }
}

fn signer_identity_uri(identity: &SignerIdentity) -> Result<String> {
    match identity {
        SignerIdentity::Keyless {
            repository,
            workflow,
            git_ref,
            ..
        } => Ok(format!(
            "https://github.com/{repository}/{workflow}@{git_ref}"
        )),
        SignerIdentity::Keyed { key_id } => Ok(format!("keyed:{key_id}")),
    }
}

fn infer_artifact_type(filename: &str) -> ArtifactType {
    match filename {
        "groups.json" => ArtifactType::Groups,
        "trust-policy.json" => ArtifactType::TrustPolicy,
        name if name.ends_with(".profile.json") => ArtifactType::Profile,
        name if name.ends_with(".sh") => ArtifactType::Hook,
        name if name.ends_with(".md") => ArtifactType::Instruction,
        _ => ArtifactType::Script,
    }
}

fn parse_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let content = fs::read_to_string(path).map_err(NonoError::Io)?;
    serde_json::from_str(&content)
        .map_err(|e| NonoError::PackageInstall(format!("failed to parse {}: {e}", path.display())))
}

fn write_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(NonoError::Io)?;
    }
    fs::write(path, bytes).map_err(NonoError::Io)
}

fn ensure_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path).map_err(NonoError::Io)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).map_err(NonoError::Io)?;
    }

    Ok(())
}

fn expand_tilde(path: &str) -> Result<PathBuf> {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = xdg_home::home_dir().ok_or(NonoError::HomeNotFound)?;
        Ok(home.join(rest))
    } else if path == "~" {
        xdg_home::home_dir().ok_or(NonoError::HomeNotFound)
    } else {
        Ok(PathBuf::from(path))
    }
}

fn file_name(path: &str) -> Result<&str> {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| NonoError::PackageInstall(format!("invalid artifact path '{}'", path)))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn current_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    }
}

fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    let parse = |value: &str| -> Vec<u64> {
        value
            .split('.')
            .map(|part| {
                part.split_once('-')
                    .map(|(base, _)| base)
                    .unwrap_or(part)
                    .parse::<u64>()
                    .unwrap_or(0)
            })
            .collect()
    };

    let left = parse(left);
    let right = parse(right);
    let max_len = left.len().max(right.len());
    for idx in 0..max_len {
        let l = *left.get(idx).unwrap_or(&0);
        let r = *right.get(idx).unwrap_or(&0);
        match l.cmp(&r) {
            std::cmp::Ordering::Equal => continue,
            ordering => return ordering,
        }
    }
    std::cmp::Ordering::Equal
}

fn format_timestamp(value: &str) -> String {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| {
            dt.with_timezone(&Local)
                .format("%Y-%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_else(|_| value.to_string())
}
