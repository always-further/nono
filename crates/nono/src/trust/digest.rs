//! SHA-256 digest computation for instruction file verification
//!
//! Provides functions for computing hex-encoded SHA-256 digests of files and
//! byte slices. Used for blocklist checking and as the subject digest in
//! DSSE/in-toto attestation statements.

use crate::error::{NonoError, Result};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

/// Compute the SHA-256 hex digest of a file.
///
/// Reads the file in 8 KiB chunks to avoid loading large files into memory.
///
/// # Errors
///
/// Returns `NonoError::Io` if the file cannot be opened or read.
pub fn file_digest<P: AsRef<Path>>(path: P) -> Result<String> {
    let path = path.as_ref();
    let mut file = std::fs::File::open(path).map_err(NonoError::Io)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf).map_err(NonoError::Io)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_encode(&hasher.finalize()))
}

/// Compute the SHA-256 hex digest of a byte slice.
#[must_use]
pub fn bytes_digest(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    hex_encode(&hash)
}

/// Encode bytes as a lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn bytes_digest_empty() {
        // SHA-256 of empty input is well-known
        let digest = bytes_digest(b"");
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn bytes_digest_hello_world() {
        let digest = bytes_digest(b"hello world");
        assert_eq!(
            digest,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn bytes_digest_deterministic() {
        let d1 = bytes_digest(b"test data");
        let d2 = bytes_digest(b"test data");
        assert_eq!(d1, d2);
    }

    #[test]
    fn bytes_digest_different_inputs() {
        let d1 = bytes_digest(b"input a");
        let d2 = bytes_digest(b"input b");
        assert_ne!(d1, d2);
    }

    #[test]
    fn bytes_digest_length() {
        let digest = bytes_digest(b"any input");
        assert_eq!(digest.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn file_digest_matches_bytes_digest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        let content = b"instruction file content";
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(content).unwrap();
        }
        let fd = file_digest(&path).unwrap();
        let bd = bytes_digest(content);
        assert_eq!(fd, bd);
    }

    #[test]
    fn file_digest_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.txt");
        std::fs::File::create(&path).unwrap();
        let digest = file_digest(&path).unwrap();
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn file_digest_nonexistent() {
        let result = file_digest("/nonexistent/path/to/file.txt");
        assert!(result.is_err());
    }

    #[test]
    fn file_digest_large_file() {
        // Test with data larger than the 8 KiB buffer
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large.bin");
        let content = vec![0x42u8; 32768]; // 32 KiB
        std::fs::write(&path, &content).unwrap();
        let fd = file_digest(&path).unwrap();
        let bd = bytes_digest(&content);
        assert_eq!(fd, bd);
    }

    #[test]
    fn hex_encode_correctness() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0xab, 0x01]), "00ffab01");
    }
}
