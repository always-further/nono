//! Snapshot manager for capturing and restoring filesystem state
//!
//! Orchestrates the object store, exclusion filter, and Merkle tree to
//! create baseline snapshots, detect incremental changes, and restore
//! to a previous state.

use crate::error::{NonoError, Result};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use super::exclusion::ExclusionFilter;
use super::merkle::MerkleTree;
use super::object_store::ObjectStore;
use super::types::{Change, ChangeType, FileState, SessionMetadata, SnapshotManifest};

/// Manages snapshots for an undo session.
///
/// Coordinates the object store, exclusion filter, and Merkle tree to
/// capture filesystem state, detect changes, and restore files.
pub struct SnapshotManager {
    session_dir: PathBuf,
    tracked_paths: Vec<PathBuf>,
    exclusion: ExclusionFilter,
    object_store: ObjectStore,
    snapshot_count: u32,
}

impl SnapshotManager {
    /// Create a new snapshot manager for the given session directory.
    ///
    /// Creates `snapshots/` and `changes/` subdirectories.
    pub fn new(
        session_dir: PathBuf,
        tracked_paths: Vec<PathBuf>,
        exclusion: ExclusionFilter,
    ) -> Result<Self> {
        let snapshots_dir = session_dir.join("snapshots");
        let changes_dir = session_dir.join("changes");

        fs::create_dir_all(&snapshots_dir).map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to create snapshots directory {}: {}",
                snapshots_dir.display(),
                e
            ))
        })?;
        fs::create_dir_all(&changes_dir).map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to create changes directory {}: {}",
                changes_dir.display(),
                e
            ))
        })?;

        let object_store = ObjectStore::new(session_dir.clone())?;

        Ok(Self {
            session_dir,
            tracked_paths,
            exclusion,
            object_store,
            snapshot_count: 0,
        })
    }

    /// Create a baseline snapshot (snapshot 0) of all tracked paths.
    ///
    /// Walks all tracked directories, applies exclusion filter, hashes and
    /// stores each file, builds the manifest with Merkle root, and writes
    /// it atomically to `snapshots/000.json`.
    pub fn create_baseline(&mut self) -> Result<SnapshotManifest> {
        let files = self.walk_and_store()?;
        let merkle = MerkleTree::from_manifest(&files)?;

        let manifest = SnapshotManifest {
            number: 0,
            timestamp: now_iso8601(),
            parent: None,
            files,
            merkle_root: *merkle.root(),
        };

        self.save_manifest(&manifest)?;
        self.snapshot_count = 1;

        Ok(manifest)
    }

    /// Create an incremental snapshot by comparing current state to previous.
    ///
    /// Uses mtime/size as a fast check to skip unchanged files, then hashes
    /// changed files. Detects created, modified, and deleted files.
    pub fn create_incremental(
        &mut self,
        previous: &SnapshotManifest,
    ) -> Result<(SnapshotManifest, Vec<Change>)> {
        let current_files = self.walk_and_store()?;
        let changes = compute_changes(&previous.files, &current_files);
        let merkle = MerkleTree::from_manifest(&current_files)?;

        let number = previous.number.saturating_add(1);
        let manifest = SnapshotManifest {
            number,
            timestamp: now_iso8601(),
            parent: Some(previous.number),
            files: current_files,
            merkle_root: *merkle.root(),
        };

        self.save_manifest(&manifest)?;

        // Save changes list
        if !changes.is_empty() {
            let changes_path = self
                .session_dir
                .join("changes")
                .join(format!("{number:03}.json"));
            let json = serde_json::to_string_pretty(&changes)
                .map_err(|e| NonoError::Snapshot(format!("Failed to serialize changes: {e}")))?;
            atomic_write(&changes_path, json.as_bytes())?;
        }

        self.snapshot_count = number.saturating_add(1);

        Ok((manifest, changes))
    }

    /// Compute what `restore_to` would change without actually restoring.
    ///
    /// Compares the current filesystem state against the manifest and returns
    /// the list of changes that would be applied. Useful for dry-run previews.
    pub fn compute_restore_diff(&self, manifest: &SnapshotManifest) -> Result<Vec<Change>> {
        self.validate_manifest_paths(manifest)?;
        let current_files = self.walk_current()?;
        let mut changes = Vec::new();

        for (path, state) in &manifest.files {
            let needs_restore = match current_files.get(path) {
                Some(current) => current.hash != state.hash,
                None => true,
            };

            if needs_restore {
                let change_type = if current_files.contains_key(path) {
                    ChangeType::Modified
                } else {
                    ChangeType::Created
                };

                changes.push(Change {
                    path: path.clone(),
                    change_type,
                    size_delta: None,
                    old_hash: current_files.get(path).map(|s| s.hash),
                    new_hash: Some(state.hash),
                });
            }
        }

        for (path, state) in &current_files {
            if !manifest.files.contains_key(path) {
                changes.push(Change {
                    path: path.clone(),
                    change_type: ChangeType::Deleted,
                    size_delta: None,
                    old_hash: Some(state.hash),
                    new_hash: None,
                });
            }
        }

        changes.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(changes)
    }

    /// Restore filesystem to the state captured by the given manifest.
    ///
    /// For each file in the manifest: restores content from object store
    /// via atomic temp+rename. Deletes files that exist on disk but aren't
    /// in the manifest. Returns the list of changes applied.
    ///
    /// All manifest paths are validated to be within tracked directories
    /// before any writes occur.
    pub fn restore_to(&self, manifest: &SnapshotManifest) -> Result<Vec<Change>> {
        self.validate_manifest_paths(manifest)?;
        let current_files = self.walk_current()?;
        let mut applied_changes = Vec::new();

        // Restore files from manifest
        for (path, state) in &manifest.files {
            let needs_restore = match current_files.get(path) {
                Some(current) => current.hash != state.hash,
                None => true, // File was deleted, need to recreate
            };

            if needs_restore {
                // Ensure parent directory exists
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).map_err(|e| {
                        NonoError::Snapshot(format!(
                            "Failed to create directory {}: {e}",
                            parent.display()
                        ))
                    })?;
                }

                self.object_store.retrieve_to(&state.hash, path)?;

                // Restore permissions (mask out setuid/setgid/sticky bits)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = fs::Permissions::from_mode(state.permissions & 0o0777);
                    if let Err(e) = fs::set_permissions(path, perms) {
                        tracing::warn!("Failed to set permissions on {}: {}", path.display(), e);
                    }
                }

                let change_type = if current_files.contains_key(path) {
                    ChangeType::Modified
                } else {
                    ChangeType::Created
                };

                applied_changes.push(Change {
                    path: path.clone(),
                    change_type,
                    size_delta: None,
                    old_hash: current_files.get(path).map(|s| s.hash),
                    new_hash: Some(state.hash),
                });
            }
        }

        // Delete files not in the manifest (created during session)
        for path in current_files.keys() {
            if !manifest.files.contains_key(path) {
                if let Err(e) = fs::remove_file(path) {
                    tracing::warn!("Failed to remove {}: {}", path.display(), e);
                } else {
                    applied_changes.push(Change {
                        path: path.clone(),
                        change_type: ChangeType::Deleted,
                        size_delta: None,
                        old_hash: current_files.get(path).map(|s| s.hash),
                        new_hash: None,
                    });
                }
            }
        }

        Ok(applied_changes)
    }

    /// Collect files that match the atomic temp-file pattern used by editors/tools.
    ///
    /// These files are typically named `<name>.tmp.<pid>.<timestamp>` and may be
    /// left behind when interrupted. The undo flow uses this baseline set so we
    /// can remove only files created during the session.
    #[must_use]
    pub fn collect_atomic_temp_files(&self) -> HashSet<PathBuf> {
        let mut files = HashSet::new();

        for tracked in &self.tracked_paths {
            if !tracked.exists() {
                continue;
            }

            if tracked.is_file() {
                if has_atomic_temp_suffix(tracked) {
                    files.insert(tracked.clone());
                }
                continue;
            }

            for entry in WalkDir::new(tracked)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                if has_atomic_temp_suffix(path) {
                    files.insert(path.to_path_buf());
                }
            }
        }

        files
    }

    /// Remove newly-created atomic temp files after a session completes.
    ///
    /// `existing` should come from `collect_atomic_temp_files()` before command
    /// execution. Files that existed before the session are preserved.
    pub fn cleanup_new_atomic_temp_files(&self, existing: &HashSet<PathBuf>) -> usize {
        let mut removed = 0usize;

        for path in self.collect_atomic_temp_files() {
            if existing.contains(&path) {
                continue;
            }

            match fs::remove_file(&path) {
                Ok(()) => removed = removed.saturating_add(1),
                Err(e) => tracing::warn!("Failed to remove temp file {}: {}", path.display(), e),
            }
        }

        removed
    }

    /// Load a manifest from disk by snapshot number.
    pub fn load_manifest(&self, number: u32) -> Result<SnapshotManifest> {
        let path = self
            .session_dir
            .join("snapshots")
            .join(format!("{number:03}.json"));
        let content = fs::read_to_string(&path).map_err(|e| {
            NonoError::Snapshot(format!("Failed to read manifest {}: {e}", path.display()))
        })?;
        serde_json::from_str(&content).map_err(|e| {
            NonoError::Snapshot(format!("Failed to parse manifest {}: {e}", path.display()))
        })
    }

    /// Save session metadata to `session.json`.
    pub fn save_session_metadata(&self, meta: &SessionMetadata) -> Result<()> {
        let path = self.session_dir.join("session.json");
        let json = serde_json::to_string_pretty(meta).map_err(|e| {
            NonoError::Snapshot(format!("Failed to serialize session metadata: {e}"))
        })?;
        atomic_write(&path, json.as_bytes())
    }

    /// Get the number of snapshots taken in this session.
    #[must_use]
    pub fn snapshot_count(&self) -> u32 {
        self.snapshot_count
    }

    /// Load session metadata from a session directory.
    ///
    /// Does not require tracked paths or exclusion filter — reads `session.json`
    /// directly. Useful for session discovery and browsing.
    pub fn load_session_metadata(session_dir: &Path) -> Result<SessionMetadata> {
        let path = session_dir.join("session.json");
        let content = fs::read_to_string(&path).map_err(|e| {
            NonoError::SessionNotFound(format!(
                "Failed to read session metadata {}: {e}",
                path.display()
            ))
        })?;
        serde_json::from_str(&content).map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to parse session metadata {}: {e}",
                path.display()
            ))
        })
    }

    /// Load a snapshot manifest from a session directory by number.
    ///
    /// Does not require a full `SnapshotManager` — reads directly from disk.
    pub fn load_manifest_from(session_dir: &Path, number: u32) -> Result<SnapshotManifest> {
        let path = session_dir
            .join("snapshots")
            .join(format!("{number:03}.json"));
        let content = fs::read_to_string(&path).map_err(|e| {
            NonoError::Snapshot(format!("Failed to read manifest {}: {e}", path.display()))
        })?;
        serde_json::from_str(&content).map_err(|e| {
            NonoError::Snapshot(format!("Failed to parse manifest {}: {e}", path.display()))
        })
    }

    /// Load a change record from a session directory by snapshot number.
    ///
    /// Returns `Ok(vec![])` if the change file doesn't exist (baseline or no changes).
    pub fn load_changes_from(session_dir: &Path, number: u32) -> Result<Vec<Change>> {
        let path = session_dir
            .join("changes")
            .join(format!("{number:03}.json"));
        if !path.exists() {
            return Ok(Vec::new());
        }
        let content = fs::read_to_string(&path).map_err(|e| {
            NonoError::Snapshot(format!("Failed to read changes {}: {e}", path.display()))
        })?;
        serde_json::from_str(&content).map_err(|e| {
            NonoError::Snapshot(format!("Failed to parse changes {}: {e}", path.display()))
        })
    }

    /// Validate that all paths in a manifest are within the tracked directories.
    ///
    /// Prevents path traversal attacks via tampered manifests. Each path must
    /// be a descendant of at least one tracked path (checked via `Path::starts_with`
    /// which performs component-wise comparison, not string prefix matching).
    fn validate_manifest_paths(&self, manifest: &SnapshotManifest) -> Result<()> {
        for path in manifest.files.keys() {
            let within_tracked = self
                .tracked_paths
                .iter()
                .any(|tracked| path.starts_with(tracked));
            if !within_tracked {
                return Err(NonoError::Snapshot(format!(
                    "Manifest contains path outside tracked directories: {}",
                    path.display()
                )));
            }
        }
        Ok(())
    }

    /// Walk tracked paths and store all non-excluded files in the object store.
    ///
    /// Permission errors on individual files are logged and skipped rather than
    /// failing the entire snapshot. This handles files with restrictive permissions
    /// (e.g., credential databases, lock files) that exist in tracked directories.
    fn walk_and_store(&self) -> Result<HashMap<PathBuf, FileState>> {
        let mut files = HashMap::new();

        for tracked in &self.tracked_paths {
            if !tracked.exists() {
                continue;
            }

            if tracked.is_file() {
                if !self.exclusion.is_excluded(tracked) {
                    match self.hash_and_store_file(tracked) {
                        Ok(state) => {
                            files.insert(tracked.clone(), state);
                        }
                        Err(e) => {
                            tracing::warn!("Skipping unreadable file {}: {}", tracked.display(), e);
                        }
                    }
                }
                continue;
            }

            for entry in WalkDir::new(tracked)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                if self.exclusion.is_excluded(path) {
                    continue;
                }
                match self.hash_and_store_file(path) {
                    Ok(state) => {
                        files.insert(path.to_path_buf(), state);
                    }
                    Err(e) => {
                        tracing::warn!("Skipping unreadable file {}: {}", path.display(), e);
                    }
                }
            }
        }

        Ok(files)
    }

    /// Walk tracked paths to get current file states without storing.
    fn walk_current(&self) -> Result<HashMap<PathBuf, FileState>> {
        let mut files = HashMap::new();

        for tracked in &self.tracked_paths {
            if !tracked.exists() {
                continue;
            }

            if tracked.is_file() {
                if !self.exclusion.is_excluded(tracked) {
                    if let Ok(state) = file_state_from_metadata(tracked) {
                        files.insert(tracked.clone(), state);
                    }
                }
                continue;
            }

            for entry in WalkDir::new(tracked)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                if self.exclusion.is_excluded(path) {
                    continue;
                }
                if let Ok(state) = file_state_from_metadata(path) {
                    files.insert(path.to_path_buf(), state);
                }
            }
        }

        Ok(files)
    }

    /// Hash a file, store it in the object store, and return its FileState.
    fn hash_and_store_file(&self, path: &Path) -> Result<FileState> {
        let hash = self.object_store.store_file(path)?;
        let metadata = fs::metadata(path).map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to read metadata for {}: {e}",
                path.display()
            ))
        })?;

        Ok(FileState {
            hash,
            size: metadata.len(),
            mtime: metadata.mtime(),
            permissions: metadata.mode(),
        })
    }

    /// Write a manifest to the snapshots directory atomically.
    fn save_manifest(&self, manifest: &SnapshotManifest) -> Result<()> {
        let path = self
            .session_dir
            .join("snapshots")
            .join(format!("{:03}.json", manifest.number));
        let json = serde_json::to_string_pretty(manifest)
            .map_err(|e| NonoError::Snapshot(format!("Failed to serialize manifest: {e}")))?;
        atomic_write(&path, json.as_bytes())
    }
}

/// Compute changes between two snapshot file maps.
fn compute_changes(
    previous: &HashMap<PathBuf, FileState>,
    current: &HashMap<PathBuf, FileState>,
) -> Vec<Change> {
    let mut changes = Vec::new();

    // Check for modified and deleted files
    for (path, prev_state) in previous {
        match current.get(path) {
            Some(curr_state) => {
                if prev_state.hash != curr_state.hash {
                    let size_delta = i64::try_from(curr_state.size).ok().and_then(|curr| {
                        i64::try_from(prev_state.size)
                            .ok()
                            .map(|prev| curr.saturating_sub(prev))
                    });
                    changes.push(Change {
                        path: path.clone(),
                        change_type: ChangeType::Modified,
                        size_delta,
                        old_hash: Some(prev_state.hash),
                        new_hash: Some(curr_state.hash),
                    });
                } else if prev_state.permissions != curr_state.permissions {
                    changes.push(Change {
                        path: path.clone(),
                        change_type: ChangeType::PermissionsChanged,
                        size_delta: Some(0),
                        old_hash: Some(prev_state.hash),
                        new_hash: Some(curr_state.hash),
                    });
                }
            }
            None => {
                changes.push(Change {
                    path: path.clone(),
                    change_type: ChangeType::Deleted,
                    size_delta: i64::try_from(prev_state.size)
                        .ok()
                        .map(|s| s.saturating_neg()),
                    old_hash: Some(prev_state.hash),
                    new_hash: None,
                });
            }
        }
    }

    // Check for created files
    for (path, curr_state) in current {
        if !previous.contains_key(path) {
            changes.push(Change {
                path: path.clone(),
                change_type: ChangeType::Created,
                size_delta: i64::try_from(curr_state.size).ok(),
                old_hash: None,
                new_hash: Some(curr_state.hash),
            });
        }
    }

    // Sort for deterministic output
    changes.sort_by(|a, b| a.path.cmp(&b.path));
    changes
}

/// Get file state from metadata (hash is zeroed - used for walk_current where
/// we only need to track which files exist for deletion during restore).
fn file_state_from_metadata(path: &Path) -> Result<FileState> {
    use sha2::{Digest, Sha256};

    let content = fs::read(path)
        .map_err(|e| NonoError::Snapshot(format!("Failed to read {}: {e}", path.display())))?;
    let hash_bytes: [u8; 32] = Sha256::digest(&content).into();

    let metadata = fs::metadata(path).map_err(|e| {
        NonoError::Snapshot(format!(
            "Failed to read metadata for {}: {e}",
            path.display()
        ))
    })?;

    Ok(FileState {
        hash: super::types::ContentHash::from_bytes(hash_bytes),
        size: metadata.len(),
        mtime: metadata.mtime(),
        permissions: metadata.mode(),
    })
}

/// Write content to a file atomically via temp file + rename.
fn atomic_write(path: &Path, content: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        NonoError::Snapshot(format!("Path has no parent directory: {}", path.display()))
    })?;

    let temp_path = parent.join(format!(
        ".tmp-{}-{}",
        std::process::id(),
        super::object_store::random_u32()
    ));

    let write_result = (|| -> Result<()> {
        let mut file = fs::File::create(&temp_path).map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to create temp file {}: {e}",
                temp_path.display()
            ))
        })?;
        use std::io::Write;
        file.write_all(content).map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to write temp file {}: {e}",
                temp_path.display()
            ))
        })?;
        file.sync_all().map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to sync temp file {}: {e}",
                temp_path.display()
            ))
        })?;
        Ok(())
    })();

    if let Err(e) = write_result {
        let _ = fs::remove_file(&temp_path);
        return Err(e);
    }

    fs::rename(&temp_path, path).map_err(|e| {
        let _ = fs::remove_file(&temp_path);
        NonoError::Snapshot(format!(
            "Failed to rename {} to {}: {e}",
            temp_path.display(),
            path.display()
        ))
    })
}

/// Get the current time as an ISO 8601 string.
fn now_iso8601() -> String {
    // Use a simple format without chrono dependency in library
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", duration.as_secs())
}

/// Match files named like `<name>.tmp.<pid>.<timestamp>`.
fn has_atomic_temp_suffix(path: &Path) -> bool {
    let Some(filename) = path.file_name().and_then(|f| f.to_str()) else {
        return false;
    };

    let Some((base, tail)) = filename.rsplit_once(".tmp.") else {
        return false;
    };
    if base.is_empty() {
        return false;
    }

    let Some((pid, ts)) = tail.split_once('.') else {
        return false;
    };

    !pid.is_empty()
        && !ts.is_empty()
        && pid.bytes().all(|b| b.is_ascii_digit())
        && ts.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::undo::exclusion::ExclusionConfig;
    use tempfile::TempDir;

    fn setup_test_dir() -> (TempDir, PathBuf) {
        let dir = TempDir::new().expect("tempdir");
        let tracked = dir.path().join("project");
        fs::create_dir_all(&tracked).expect("create project dir");
        fs::write(tracked.join("file1.txt"), b"hello world").expect("write file1");
        fs::write(tracked.join("file2.txt"), b"goodbye world").expect("write file2");
        (dir, tracked)
    }

    fn make_manager(session_dir: &Path, tracked: &Path) -> SnapshotManager {
        let config = ExclusionConfig {
            use_gitignore: false,
            exclude_patterns: Vec::new(),
            exclude_globs: Vec::new(),
            force_include: Vec::new(),
        };
        let filter = ExclusionFilter::new(config, tracked).expect("filter");
        SnapshotManager::new(
            session_dir.to_path_buf(),
            vec![tracked.to_path_buf()],
            filter,
        )
        .expect("manager")
    }

    #[test]
    fn baseline_captures_all_files() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let mut manager = make_manager(&session_dir, &tracked);
        let manifest = manager.create_baseline().expect("baseline");

        assert_eq!(manifest.number, 0);
        assert!(manifest.parent.is_none());
        assert_eq!(manifest.files.len(), 2);
        assert!(manifest.files.contains_key(&tracked.join("file1.txt")));
        assert!(manifest.files.contains_key(&tracked.join("file2.txt")));
    }

    #[test]
    fn incremental_detects_modification() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let mut manager = make_manager(&session_dir, &tracked);
        let baseline = manager.create_baseline().expect("baseline");

        // Modify a file
        fs::write(tracked.join("file1.txt"), b"modified content").expect("modify");

        let (manifest, changes) = manager.create_incremental(&baseline).expect("incremental");

        assert_eq!(manifest.number, 1);
        assert_eq!(manifest.parent, Some(0));
        assert!(!changes.is_empty());

        let modified = changes
            .iter()
            .find(|c| c.path == tracked.join("file1.txt"))
            .expect("should find modified file");
        assert_eq!(modified.change_type, ChangeType::Modified);
    }

    #[test]
    fn incremental_detects_creation() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let mut manager = make_manager(&session_dir, &tracked);
        let baseline = manager.create_baseline().expect("baseline");

        // Create a new file
        fs::write(tracked.join("new_file.txt"), b"new content").expect("create");

        let (_manifest, changes) = manager.create_incremental(&baseline).expect("incremental");

        let created = changes
            .iter()
            .find(|c| c.path == tracked.join("new_file.txt"))
            .expect("should find created file");
        assert_eq!(created.change_type, ChangeType::Created);
    }

    #[test]
    fn incremental_detects_deletion() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let mut manager = make_manager(&session_dir, &tracked);
        let baseline = manager.create_baseline().expect("baseline");

        // Delete a file
        fs::remove_file(tracked.join("file2.txt")).expect("delete");

        let (_manifest, changes) = manager.create_incremental(&baseline).expect("incremental");

        let deleted = changes
            .iter()
            .find(|c| c.path == tracked.join("file2.txt"))
            .expect("should find deleted file");
        assert_eq!(deleted.change_type, ChangeType::Deleted);
    }

    #[test]
    fn restore_reverts_to_baseline() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let mut manager = make_manager(&session_dir, &tracked);
        let baseline = manager.create_baseline().expect("baseline");

        // Make changes: modify one file, create another, delete one
        fs::write(tracked.join("file1.txt"), b"modified").expect("modify");
        fs::write(tracked.join("new.txt"), b"new file").expect("create");
        fs::remove_file(tracked.join("file2.txt")).expect("delete");

        // Restore to baseline
        let applied = manager.restore_to(&baseline).expect("restore");
        assert!(!applied.is_empty());

        // Verify: file1 should be back to original
        let content = fs::read_to_string(tracked.join("file1.txt")).expect("read file1");
        assert_eq!(content, "hello world");

        // file2 should be recreated
        let content = fs::read_to_string(tracked.join("file2.txt")).expect("read file2");
        assert_eq!(content, "goodbye world");

        // new.txt should be deleted
        assert!(!tracked.join("new.txt").exists());
    }

    #[test]
    fn merkle_root_differs_between_snapshots() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let mut manager = make_manager(&session_dir, &tracked);
        let baseline = manager.create_baseline().expect("baseline");

        // Modify a file
        fs::write(tracked.join("file1.txt"), b"changed").expect("modify");

        let (incremental, _) = manager.create_incremental(&baseline).expect("incremental");

        // Merkle roots should differ
        assert_ne!(baseline.merkle_root, incremental.merkle_root);
    }

    #[test]
    fn manifest_roundtrip_via_disk() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let mut manager = make_manager(&session_dir, &tracked);
        let baseline = manager.create_baseline().expect("baseline");

        let loaded = manager.load_manifest(0).expect("load");
        assert_eq!(loaded.number, baseline.number);
        assert_eq!(loaded.files.len(), baseline.files.len());
        assert_eq!(loaded.merkle_root, baseline.merkle_root);
    }

    #[test]
    fn session_metadata_save() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let mut manager = make_manager(&session_dir, &tracked);
        let baseline = manager.create_baseline().expect("baseline");

        let meta = SessionMetadata {
            session_id: "test-session".to_string(),
            started: "2025-01-01T00:00:00Z".to_string(),
            ended: Some("2025-01-01T00:01:00Z".to_string()),
            command: vec!["bash".to_string(), "-c".to_string(), "echo hi".to_string()],
            tracked_paths: vec![tracked.to_path_buf()],
            snapshot_count: 2,
            exit_code: Some(0),
            merkle_roots: vec![baseline.merkle_root],
            signature: None,
            signing_key_id: None,
        };

        manager.save_session_metadata(&meta).expect("save metadata");

        let content =
            fs::read_to_string(session_dir.join("session.json")).expect("read session.json");
        let loaded: SessionMetadata = serde_json::from_str(&content).expect("parse session.json");
        assert_eq!(loaded.session_id, "test-session");
        assert_eq!(loaded.merkle_roots.len(), 1);
    }

    #[test]
    fn compute_restore_diff_shows_changes_without_modifying_disk() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let mut manager = make_manager(&session_dir, &tracked);
        let baseline = manager.create_baseline().expect("baseline");

        // Make changes
        fs::write(tracked.join("file1.txt"), b"modified").expect("modify");
        fs::write(tracked.join("new.txt"), b"new file").expect("create");
        fs::remove_file(tracked.join("file2.txt")).expect("delete");

        // Compute diff without restoring
        let diff = manager.compute_restore_diff(&baseline).expect("diff");
        assert!(!diff.is_empty());

        // Files should NOT be restored — disk state unchanged
        let content = fs::read_to_string(tracked.join("file1.txt")).expect("read");
        assert_eq!(content, "modified");
        assert!(tracked.join("new.txt").exists());
        assert!(!tracked.join("file2.txt").exists());
    }

    #[test]
    fn load_session_metadata_static() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let mut manager = make_manager(&session_dir, &tracked);
        let baseline = manager.create_baseline().expect("baseline");

        let meta = SessionMetadata {
            session_id: "static-load-test".to_string(),
            started: "2025-01-01T00:00:00Z".to_string(),
            ended: None,
            command: vec!["test".to_string()],
            tracked_paths: vec![tracked.to_path_buf()],
            snapshot_count: 1,
            exit_code: None,
            merkle_roots: vec![baseline.merkle_root],
            signature: None,
            signing_key_id: None,
        };
        manager.save_session_metadata(&meta).expect("save");

        // Load without a SnapshotManager
        let loaded = SnapshotManager::load_session_metadata(&session_dir).expect("load");
        assert_eq!(loaded.session_id, "static-load-test");
    }

    #[test]
    fn load_manifest_and_changes_static() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");

        let mut manager = make_manager(&session_dir, &tracked);
        let baseline = manager.create_baseline().expect("baseline");

        // Modify and create incremental
        fs::write(tracked.join("file1.txt"), b"modified").expect("modify");
        let (_incr, _changes) = manager.create_incremental(&baseline).expect("incremental");

        // Load via static methods
        let manifest = SnapshotManager::load_manifest_from(&session_dir, 0).expect("load manifest");
        assert_eq!(manifest.number, 0);

        let changes = SnapshotManager::load_changes_from(&session_dir, 1).expect("load changes");
        assert!(!changes.is_empty());

        // Baseline has no change file
        let baseline_changes =
            SnapshotManager::load_changes_from(&session_dir, 0).expect("load baseline changes");
        assert!(baseline_changes.is_empty());
    }

    #[test]
    fn cleanup_new_atomic_temp_files_removes_only_new_files() {
        let (dir, tracked) = setup_test_dir();
        let session_dir = dir.path().join("session");
        fs::create_dir_all(&session_dir).expect("create session dir");
        let manager = make_manager(&session_dir, &tracked);

        let preexisting = tracked.join("preexisting.txt.tmp.100.200");
        fs::write(&preexisting, b"old temp").expect("write preexisting temp");
        let before = manager.collect_atomic_temp_files();

        let new_temp = tracked.join("new.txt.tmp.300.400");
        fs::write(&new_temp, b"new temp").expect("write new temp");
        let not_atomic = tracked.join("kept.tmp");
        fs::write(&not_atomic, b"keep").expect("write non-atomic temp");

        let removed = manager.cleanup_new_atomic_temp_files(&before);
        assert_eq!(removed, 1);
        assert!(preexisting.exists());
        assert!(!new_temp.exists());
        assert!(not_atomic.exists());
    }
}
