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
    /// Reads the file in streaming fashion with an 8KB buffer to handle
    /// large files without excessive memory use. If an object with the
    /// same hash already exists, skips the write (content deduplication).
    pub fn store_file(&self, path: &Path) -> Result<ContentHash> {
        let mut file = fs::File::open(path).map_err(|e| {
            NonoError::ObjectStore(format!("Failed to open {}: {}", path.display(), e))
        })?;

        // Hash the file content in streaming fashion
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; HASH_BUFFER_SIZE];
        let mut content = Vec::new();

        loop {
            let bytes_read = file.read(&mut buffer).map_err(|e| {
                NonoError::ObjectStore(format!("Failed to read {}: {}", path.display(), e))
            })?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
            content.extend_from_slice(&buffer[..bytes_read]);
        }

        let hash_bytes: [u8; 32] = hasher.finalize().into();
        let hash = ContentHash::from_bytes(hash_bytes);

        // Skip write if object already exists (deduplication)
        if !self.has_object(&hash) {
            self.write_object(&hash, &content)?;
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
    /// Verifies content integrity by re-hashing before writing. Writes to
    /// a temp file in the same directory as target, then renames for atomic
    /// replacement.
    pub fn retrieve_to(&self, hash: &ContentHash, target: &Path) -> Result<()> {
        let content = self.retrieve(hash)?;

        // Verify content integrity before writing to target
        let actual: [u8; 32] = Sha256::digest(&content).into();
        if actual != *hash.as_bytes() {
            return Err(NonoError::ObjectStore(format!(
                "Object integrity check failed for {hash}: content hash mismatch"
            )));
        }

        let parent = target.parent().ok_or_else(|| {
            NonoError::ObjectStore(format!(
                "Target path has no parent directory: {}",
                target.display()
            ))
        })?;

        // Write to temp file in the same directory for atomic rename.
        // Use PID + random suffix to prevent predictable temp file names.
        let temp_path = parent.join(format!(
            ".nono-restore-{}-{:08x}",
            std::process::id(),
            random_u32()
        ));

        let write_result = (|| -> Result<()> {
            let mut file = fs::File::create(&temp_path).map_err(|e| {
                NonoError::ObjectStore(format!(
                    "Failed to create temp file {}: {}",
                    temp_path.display(),
                    e
                ))
            })?;
            file.write_all(&content).map_err(|e| {
                NonoError::ObjectStore(format!(
                    "Failed to write temp file {}: {}",
                    temp_path.display(),
                    e
                ))
            })?;
            file.sync_all().map_err(|e| {
                NonoError::ObjectStore(format!(
                    "Failed to sync temp file {}: {}",
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
}

/// Generate a random u32 for temp file name unpredictability.
///
/// Uses getrandom for cryptographic randomness when available,
/// falling back to timestamp-based entropy.
pub(super) fn random_u32() -> u32 {
    let mut buf = [0u8; 4];
    if getrandom::getrandom(&mut buf).is_ok() {
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
/// physical storage until either copy is modified.
#[cfg(target_os = "macos")]
pub fn clone_or_copy(src: &Path, dst: &Path) -> io::Result<()> {
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
pub fn clone_or_copy(src: &Path, dst: &Path) -> io::Result<()> {
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
}
