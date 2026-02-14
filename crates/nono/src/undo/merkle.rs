//! Merkle tree over snapshot file hashes
//!
//! Computes a Merkle root that cryptographically commits to the entire
//! filesystem state captured by a snapshot. The root is a single 32-byte
//! value - any change to any file path or content changes the root.
//!
//! This root is the value that will be signed by a hardware key to provide
//! tamper-evident proof of what an AI agent did or didn't modify.

use crate::error::{NonoError, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::types::{ContentHash, FileState};

/// Domain separation prefixes per RFC 6962 to prevent second-preimage attacks.
/// Leaf and internal nodes use distinct prefixes so an attacker cannot substitute
/// a leaf node hash for an internal node hash or vice versa.
const LEAF_PREFIX: u8 = 0x00;
const INTERNAL_PREFIX: u8 = 0x01;

/// A Merkle tree computed over snapshot file hashes.
///
/// Leaves are `SHA-256(0x00 || canonical_path_bytes || file_content_hash)` to bind
/// path identity to content with domain separation. Internal nodes are
/// `SHA-256(0x01 || left_child_hash || right_child_hash)`.
///
/// File paths are sorted lexicographically to ensure deterministic tree
/// construction regardless of insertion order.
pub struct MerkleTree {
    root: ContentHash,
    leaf_count: usize,
}

impl MerkleTree {
    /// Build a Merkle tree from a snapshot's file map.
    ///
    /// Sorts file paths lexicographically, computes leaf hashes binding
    /// path to content, then builds the tree bottom-up.
    pub fn from_manifest(files: &HashMap<PathBuf, FileState>) -> Result<Self> {
        if files.is_empty() {
            // Well-defined empty root: SHA-256 of empty input
            let empty_root: [u8; 32] = Sha256::digest(b"").into();
            return Ok(Self {
                root: ContentHash::from_bytes(empty_root),
                leaf_count: 0,
            });
        }

        // Sort paths for deterministic ordering
        let mut sorted_paths: Vec<&PathBuf> = files.keys().collect();
        sorted_paths.sort();

        // Compute leaf hashes: SHA-256(path_bytes || content_hash)
        let mut level: Vec<[u8; 32]> = sorted_paths
            .iter()
            .map(|path| {
                let file_state = &files[*path];
                compute_leaf_hash(path, &file_state.hash)
            })
            .collect();

        let leaf_count = level.len();

        // Build tree bottom-up
        while level.len() > 1 {
            let mut next_level = Vec::with_capacity(level.len().saturating_add(1) / 2);
            let mut i = 0;
            while i < level.len() {
                if i + 1 < level.len() {
                    // Pair two siblings
                    next_level.push(compute_internal_hash(&level[i], &level[i + 1]));
                    i += 2;
                } else {
                    // Odd node: promote unpaired child
                    next_level.push(level[i]);
                    i += 1;
                }
            }
            level = next_level;
        }

        let root_bytes = level.into_iter().next().ok_or_else(|| {
            NonoError::Snapshot("Merkle tree construction produced no root".to_string())
        })?;

        Ok(Self {
            root: ContentHash::from_bytes(root_bytes),
            leaf_count,
        })
    }

    /// Get the Merkle root hash.
    #[must_use]
    pub fn root(&self) -> &ContentHash {
        &self.root
    }

    /// Get the number of leaves (files) in the tree.
    #[must_use]
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }
}

/// Compute a leaf hash: SHA-256(0x00 || path_bytes || content_hash)
///
/// The 0x00 prefix provides domain separation per RFC 6962,
/// preventing second-preimage attacks where leaf and internal
/// node hashes could be confused.
fn compute_leaf_hash(path: &Path, content_hash: &ContentHash) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(path.to_string_lossy().as_bytes());
    hasher.update(content_hash.as_bytes());
    hasher.finalize().into()
}

/// Compute an internal node hash: SHA-256(0x01 || left || right)
///
/// The 0x01 prefix provides domain separation per RFC 6962.
fn compute_internal_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([INTERNAL_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_file_state(hash_byte: u8) -> FileState {
        FileState {
            hash: ContentHash::from_bytes([hash_byte; 32]),
            size: 100,
            mtime: 1000,
            permissions: 0o644,
        }
    }

    #[test]
    fn empty_tree_has_deterministic_root() {
        let files: HashMap<PathBuf, FileState> = HashMap::new();
        let tree1 = MerkleTree::from_manifest(&files).expect("tree1");
        let tree2 = MerkleTree::from_manifest(&files).expect("tree2");
        assert_eq!(tree1.root(), tree2.root());
        assert_eq!(tree1.leaf_count(), 0);
    }

    #[test]
    fn single_file_tree() {
        let mut files = HashMap::new();
        files.insert(PathBuf::from("/a/file.txt"), make_file_state(0x01));
        let tree = MerkleTree::from_manifest(&files).expect("tree");
        assert_eq!(tree.leaf_count(), 1);
        // Root should be the leaf hash itself
        let expected_leaf = compute_leaf_hash(
            Path::new("/a/file.txt"),
            &ContentHash::from_bytes([0x01; 32]),
        );
        assert_eq!(*tree.root().as_bytes(), expected_leaf);
    }

    #[test]
    fn root_changes_when_file_content_changes() {
        let mut files1 = HashMap::new();
        files1.insert(PathBuf::from("/a.txt"), make_file_state(0x01));
        files1.insert(PathBuf::from("/b.txt"), make_file_state(0x02));

        let mut files2 = HashMap::new();
        files2.insert(PathBuf::from("/a.txt"), make_file_state(0x01));
        files2.insert(PathBuf::from("/b.txt"), make_file_state(0xff)); // different content

        let tree1 = MerkleTree::from_manifest(&files1).expect("tree1");
        let tree2 = MerkleTree::from_manifest(&files2).expect("tree2");
        assert_ne!(tree1.root(), tree2.root());
    }

    #[test]
    fn root_changes_when_file_path_changes() {
        let mut files1 = HashMap::new();
        files1.insert(PathBuf::from("/a.txt"), make_file_state(0x01));

        let mut files2 = HashMap::new();
        files2.insert(PathBuf::from("/b.txt"), make_file_state(0x01)); // same content, different path

        let tree1 = MerkleTree::from_manifest(&files1).expect("tree1");
        let tree2 = MerkleTree::from_manifest(&files2).expect("tree2");
        assert_ne!(tree1.root(), tree2.root());
    }

    #[test]
    fn deterministic_regardless_of_insertion_order() {
        let mut files1 = HashMap::new();
        files1.insert(PathBuf::from("/z.txt"), make_file_state(0x01));
        files1.insert(PathBuf::from("/a.txt"), make_file_state(0x02));
        files1.insert(PathBuf::from("/m.txt"), make_file_state(0x03));

        let mut files2 = HashMap::new();
        files2.insert(PathBuf::from("/a.txt"), make_file_state(0x02));
        files2.insert(PathBuf::from("/m.txt"), make_file_state(0x03));
        files2.insert(PathBuf::from("/z.txt"), make_file_state(0x01));

        let tree1 = MerkleTree::from_manifest(&files1).expect("tree1");
        let tree2 = MerkleTree::from_manifest(&files2).expect("tree2");
        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn odd_number_of_files() {
        let mut files = HashMap::new();
        files.insert(PathBuf::from("/a.txt"), make_file_state(0x01));
        files.insert(PathBuf::from("/b.txt"), make_file_state(0x02));
        files.insert(PathBuf::from("/c.txt"), make_file_state(0x03));
        let tree = MerkleTree::from_manifest(&files).expect("tree");
        assert_eq!(tree.leaf_count(), 3);
        // Should not panic or error with odd number of nodes
    }

    #[test]
    fn adding_file_changes_root() {
        let mut files1 = HashMap::new();
        files1.insert(PathBuf::from("/a.txt"), make_file_state(0x01));

        let mut files2 = files1.clone();
        files2.insert(PathBuf::from("/b.txt"), make_file_state(0x02));

        let tree1 = MerkleTree::from_manifest(&files1).expect("tree1");
        let tree2 = MerkleTree::from_manifest(&files2).expect("tree2");
        assert_ne!(tree1.root(), tree2.root());
    }
}
