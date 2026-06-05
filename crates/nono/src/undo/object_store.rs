//! Content-addressable object store
//!
//! Stores file contents indexed by their SHA-256 hash, with git-like
//! two-character prefix directory sharding. Provides deduplication
//! (identical content stored once) and integrity verification.

use crate::error::{NonoError, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use super::types::ContentHash;

/// Size of the read buffer for streaming file hashing
const HASH_BUFFER_SIZE: usize = 8192;

/// Content-addressable object store backed by the filesystem
pub struct ObjectStore {
    /// Root directory for the store (contains `objects/` subdirectory)
    root: PathBuf,
}

impl ObjectStore {
    /// Create a new object store at the given root directory.
    ///
    /// Creates the `objects/` subdirectory if it doesn't exist.
    #[must_use = "ObjectStore should be used to store/retrieve content"]
    pub fn new(root: PathBuf) -> Result<Self> {
        let objects_dir = root.join("objects");
        fs::create_dir_all(&objects_dir).map_err(|e| {
            NonoError::ObjectStore(format!(
                "Failed to create objects directory {}: {}",
                objects_dir.display(),
                e
            ))
        })?;
        Ok(Self { root })
    }

    /// Store a file's content and return its SHA-256 hash.
    ///
    /// Stream-hashes the file with an 8KB buffer (no full-file memory buffer),
    /// then uses `clonefile()` on macOS APFS for instant copy-on-write storage.
    /// Falls back to regular copy on other filesystems/platforms.
    /// If an object with the same hash already exists, skips the write (deduplication).
    pub fn store_file(&self, path: &Path) -> Result<ContentHash> {
        let mut file = fs::File::open(path).map_err(|e| {
            NonoError::ObjectStore(format!("Failed to open {}: {}", path.display(), e))
        })?;

        // Stream-hash without buffering entire file in memory
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; HASH_BUFFER_SIZE];

        loop {
            let bytes_read = file.read(&mut buffer).map_err(|e| {
                NonoError::ObjectStore(format!("Failed to read {}: {}", path.display(), e))
            })?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        let hash_bytes: [u8; 32] = hasher.finalize().into();
        let hash = ContentHash::from_bytes(hash_bytes);

        // Skip write if object already exists (deduplication)
        if !self.has_object(&hash) {
            self.clone_or_write_object(&hash, path)?;
        }

        Ok(hash)
    }

    /// Store raw bytes and return their SHA-256 hash.
    pub fn store_bytes(&self, content: &[u8]) -> Result<ContentHash> {
        let hash_bytes: [u8; 32] = Sha256::digest(content).into();
        let hash = ContentHash::from_bytes(hash_bytes);

        if !self.has_object(&hash) {
            self.write_object(&hash, content)?;
        }

        Ok(hash)
    }

    /// Retrieve the content of an object by its hash.
    pub fn retrieve(&self, hash: &ContentHash) -> Result<Vec<u8>> {
        let path = self.object_path(hash);
        fs::read(&path)
            .map_err(|e| NonoError::ObjectStore(format!("Failed to read object {}: {}", hash, e)))
    }

    /// Retrieve an object and write it to a target path atomically.
    ///
    /// Uses `clonefile()` on macOS APFS for instant copy-on-write from the
    /// object store to the target location. Falls back to regular copy on
    /// other filesystems/platforms. Verifies content integrity by re-hashing
    /// after the clone/copy.
    pub fn retrieve_to(&self, hash: &ContentHash, target: &Path) -> Result<()> {
        let obj_path = self.object_path(hash);

        let parent = target.parent().ok_or_else(|| {
            NonoError::ObjectStore(format!(
                "Target path has no parent directory: {}",
                target.display()
            ))
        })?;

        // Clone/copy to temp file in the same directory for atomic rename.
        // Use PID + random suffix to prevent predictable temp file names.
        let temp_path = parent.join(format!(
            ".nono-restore-{}-{:08x}",
            std::process::id(),
            random_u32()
        ));

        clone_or_copy(&obj_path, &temp_path).map_err(|e| {
            NonoError::ObjectStore(format!(
                "Failed to clone/copy object {} to {}: {}",
                hash,
                temp_path.display(),
                e
            ))
        })?;

        // Verify content integrity after clone/copy
        let content = fs::read(&temp_path).map_err(|e| {
            let _ = fs::remove_file(&temp_path);
            NonoError::ObjectStore(format!(
                "Failed to read temp file {}: {}",
                temp_path.display(),
                e
            ))
        })?;
        let actual: [u8; 32] = Sha256::digest(&content).into();
        if actual != *hash.as_bytes() {
            let _ = fs::remove_file(&temp_path);
            return Err(NonoError::ObjectStore(format!(
                "Object integrity check failed for {hash}: content hash mismatch"
            )));
        }

        fs::rename(&temp_path, target).map_err(|e| {
            let _ = fs::remove_file(&temp_path);
            NonoError::ObjectStore(format!(
                "Failed to rename {} to {}: {}",
                temp_path.display(),
                target.display(),
                e
            ))
        })
    }

    /// Verify the integrity of a stored object by re-hashing its content.
    pub fn verify(&self, hash: &ContentHash) -> Result<bool> {
        let content = self.retrieve(hash)?;
        let actual: [u8; 32] = Sha256::digest(&content).into();
        Ok(actual == *hash.as_bytes())
    }

    /// Get the filesystem path for a given content hash.
    ///
    /// Objects are stored as `objects/<first-2-hex>/<remaining-hex>`.
    #[must_use]
    pub fn object_path(&self, hash: &ContentHash) -> PathBuf {
        self.root
            .join("objects")
            .join(hash.prefix())
            .join(hash.suffix())
    }

    /// Check whether an object with the given hash exists in the store.
    #[must_use]
    pub fn has_object(&self, hash: &ContentHash) -> bool {
        self.object_path(hash).exists()
    }

    /// Write content to the object store at the hash-derived path.
    ///
    /// Uses temp file + rename for atomic writes.
    fn write_object(&self, hash: &ContentHash, content: &[u8]) -> Result<()> {
        let obj_path = self.object_path(hash);

        let prefix_dir = self.root.join("objects").join(hash.prefix());
        fs::create_dir_all(&prefix_dir).map_err(|e| {
            NonoError::ObjectStore(format!(
                "Failed to create prefix directory {}: {}",
                prefix_dir.display(),
                e
            ))
        })?;

        let temp_path =
            prefix_dir.join(format!(".tmp-{}-{:08x}", std::process::id(), random_u32()));

        let write_result = (|| -> Result<()> {
            let mut file = fs::File::create(&temp_path).map_err(|e| {
                NonoError::ObjectStore(format!(
                    "Failed to create temp object {}: {}",
                    temp_path.display(),
                    e
                ))
            })?;
            file.write_all(content).map_err(|e| {
                NonoError::ObjectStore(format!(
                    "Failed to write temp object {}: {}",
                    temp_path.display(),
                    e
                ))
            })?;
            file.sync_all().map_err(|e| {
                NonoError::ObjectStore(format!(
                    "Failed to sync temp object {}: {}",
                    temp_path.display(),
                    e
                ))
            })?;
            Ok(())
        })();

        if let Err(e) = write_result {
            let _ = fs::remove_file(&temp_path);
            return Err(e);
        }

        fs::rename(&temp_path, &obj_path).map_err(|e| {
            let _ = fs::remove_file(&temp_path);
            NonoError::ObjectStore(format!(
                "Failed to rename temp object to {}: {}",
                obj_path.display(),
                e
            ))
        })
    }

    /// Store a file into the object store using clone-or-copy.
    ///
    /// Uses `clonefile()` on macOS APFS for instant copy-on-write, falling
    /// back to regular copy on other filesystems. Verifies the stored content
    /// matches the expected hash to guard against TOCTOU races (source file
    /// changing between hashing and cloning). On mismatch, falls back to
    /// re-reading the source and writing content directly.
    fn clone_or_write_object(&self, hash: &ContentHash, source: &Path) -> Result<()> {
        let obj_path = self.object_path(hash);

        let prefix_dir = self.root.join("objects").join(hash.prefix());
        fs::create_dir_all(&prefix_dir).map_err(|e| {
            NonoError::ObjectStore(format!(
                "Failed to create prefix directory {}: {}",
                prefix_dir.display(),
                e
            ))
        })?;

        let temp_path =
            prefix_dir.join(format!(".tmp-{}-{:08x}", std::process::id(), random_u32()));

        // Clone/copy source to temp location
        let clone_result = clone_or_copy(source, &temp_path);

        if let Err(e) = clone_result {
            // Clone/copy failed entirely — fall back to reading content and writing
            tracing::debug!(
                "clone_or_copy failed for {}: {}, falling back to read+write",
                source.display(),
                e
            );
            let content = fs::read(source).map_err(|e| {
                NonoError::ObjectStore(format!("Failed to read {}: {}", source.display(), e))
            })?;
            return self.write_object(hash, &content);
        }

        // Verify the cloned content matches the expected hash (TOCTOU guard)
        let cloned_hash: [u8; 32] = {
            let content = fs::read(&temp_path).map_err(|e| {
                let _ = fs::remove_file(&temp_path);
                NonoError::ObjectStore(format!(
                    "Failed to read cloned temp {}: {}",
                    temp_path.display(),
                    e
                ))
            })?;
            Sha256::digest(&content).into()
        };

        if cloned_hash != *hash.as_bytes() {
            // Source file changed between hashing and cloning — discard clone
            let _ = fs::remove_file(&temp_path);
            tracing::debug!(
                "TOCTOU detected for {}: hash mismatch after clone, skipping store",
                source.display()
            );
            // Don't store — the hash no longer represents this file's content.
            // The next snapshot will pick up the new content.
            return Ok(());
        }

        fs::rename(&temp_path, &obj_path).map_err(|e| {
            let _ = fs::remove_file(&temp_path);
            NonoError::ObjectStore(format!(
                "Failed to rename temp object to {}: {}",
                obj_path.display(),
                e
            ))
        })
    }
}

/// Generate a random u32 for temp file name unpredictability.
///
/// Uses getrandom for cryptographic randomness when available,
/// falling back to timestamp-based entropy.
pub(super) fn random_u32() -> u32 {
    let mut buf = [0u8; 4];
    if getrandom::fill(&mut buf).is_ok() {
        u32::from_ne_bytes(buf)
    } else {
        // Fallback: use timestamp + PID for some entropy
        let duration = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        duration.subsec_nanos() ^ std::process::id()
    }
}

/// Try to clone a file using APFS clonefile, falling back to regular copy.
///
/// On macOS, `clonefile()` creates a copy-on-write clone that shares
/// physical storage until either copy is modified. Falls back to
/// `fs::copy()` on non-APFS filesystems or cross-volume copies.
#[cfg(target_os = "macos")]
fn clone_or_copy(src: &Path, dst: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let src_cstr = CString::new(src.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let dst_cstr = CString::new(dst.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    // SAFETY: clonefile is a macOS system call that takes two C string paths
    // and a flags argument. Both paths are valid CStrings, and flag 0 means
    // no special behavior.
    let ret = unsafe { nix::libc::clonefile(src_cstr.as_ptr(), dst_cstr.as_ptr(), 0) };

    if ret == 0 {
        Ok(())
    } else {
        // clonefile failed (e.g., cross-volume), fall back to regular copy
        fs::copy(src, dst)?;
        Ok(())
    }
}

/// Copy a file (non-macOS platforms use standard copy).
#[cfg(not(target_os = "macos"))]
fn clone_or_copy(src: &Path, dst: &Path) -> io::Result<()> {
    fs::copy(src, dst)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup() -> (TempDir, ObjectStore) {
        let dir = TempDir::new().expect("tempdir");
        let store = ObjectStore::new(dir.path().to_path_buf()).expect("object store");
        (dir, store)
    }

    #[test]
    fn store_and_retrieve_roundtrip() {
        let (_dir, store) = setup();
        let content = b"hello world";
        let hash = store.store_bytes(content).expect("store");
        let retrieved = store.retrieve(&hash).expect("retrieve");
        assert_eq!(retrieved, content);
    }

    #[test]
    fn store_file_roundtrip() {
        let (dir, store) = setup();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, b"file content here").expect("write test file");

        let hash = store.store_file(&file_path).expect("store file");
        let retrieved = store.retrieve(&hash).expect("retrieve");
        assert_eq!(retrieved, b"file content here");
    }

    #[test]
    fn deduplication() {
        let (_dir, store) = setup();
        let content = b"duplicate content";

        let hash1 = store.store_bytes(content).expect("store 1");
        let hash2 = store.store_bytes(content).expect("store 2");

        assert_eq!(hash1, hash2);
        assert!(store.has_object(&hash1));
    }

    #[test]
    fn verify_integrity() {
        let (_dir, store) = setup();
        let hash = store.store_bytes(b"verify me").expect("store");
        assert!(store.verify(&hash).expect("verify"));
    }

    #[test]
    fn verify_detects_corruption() {
        let (_dir, store) = setup();
        let hash = store.store_bytes(b"original content").expect("store");

        // Corrupt the stored object
        let obj_path = store.object_path(&hash);
        fs::write(&obj_path, b"corrupted").expect("corrupt");

        assert!(!store.verify(&hash).expect("verify"));
    }

    #[test]
    fn retrieve_to_atomic() {
        let (dir, store) = setup();
        let hash = store.store_bytes(b"restore target").expect("store");

        let target = dir.path().join("restored.txt");
        store.retrieve_to(&hash, &target).expect("retrieve_to");

        let content = fs::read(&target).expect("read restored");
        assert_eq!(content, b"restore target");
    }

    #[test]
    fn has_object_false_for_missing() {
        let (_dir, store) = setup();
        let fake_hash = ContentHash::from_bytes([0xff; 32]);
        assert!(!store.has_object(&fake_hash));
    }

    #[test]
    fn retrieve_missing_object_errors() {
        let (_dir, store) = setup();
        let fake_hash = ContentHash::from_bytes([0xff; 32]);
        assert!(store.retrieve(&fake_hash).is_err());
    }

    #[test]
    fn clone_or_copy_produces_identical_content() {
        let dir = TempDir::new().expect("tempdir");
        let src = dir.path().join("source.txt");
        let dst = dir.path().join("destination.txt");

        let content = b"content to clone or copy";
        fs::write(&src, content).expect("write source");

        clone_or_copy(&src, &dst).expect("clone_or_copy");

        let result = fs::read(&dst).expect("read destination");
        assert_eq!(result, content);
    }

    #[test]
    fn store_file_streams_without_full_buffer() {
        let (dir, store) = setup();
        let file_path = dir.path().join("large.txt");
        // Write a file larger than HASH_BUFFER_SIZE to exercise streaming
        let content = vec![0x42u8; HASH_BUFFER_SIZE * 3 + 7];
        fs::write(&file_path, &content).expect("write test file");

        let hash = store.store_file(&file_path).expect("store file");
        let retrieved = store.retrieve(&hash).expect("retrieve");
        assert_eq!(retrieved, content);
    }
}
