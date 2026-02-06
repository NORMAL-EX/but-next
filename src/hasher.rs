//! # Content Hashing
//!
//! Uses BLAKE3 for fast, cryptographically secure content hashing. BLAKE3 is
//! significantly faster than SHA-256 (especially with SIMD), making it ideal
//! for hashing large backup sets where thousands of files need deduplication.
//!
//! The hash is used as the content-addressable key in the blob store — two files
//! with identical content produce the same hash and are stored only once.

use crate::error::{BackupError, Result};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Size of the read buffer for streaming hash computation (64 KiB).
///
/// Chosen to balance syscall overhead against memory usage. Larger buffers
/// provide diminishing returns on modern kernels with readahead.
const BUF_SIZE: usize = 64 * 1024;

/// Computes the BLAKE3 hash of a file's contents, returning a hex string.
///
/// Uses streaming reads to handle arbitrarily large files without loading
/// the entire contents into memory.
pub fn hash_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).map_err(|e| BackupError::HashFailed {
        path: path.to_path_buf(),
        source: e,
    })?;

    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; BUF_SIZE];

    loop {
        let bytes_read = file.read(&mut buf).map_err(|e| BackupError::HashFailed {
            path: path.to_path_buf(),
            source: e,
        })?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buf[..bytes_read]);
    }

    Ok(hasher.finalize().to_hex().to_string())
}

/// Computes the BLAKE3 hash of in-memory data.
pub fn hash_bytes(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// Returns the first `n` characters of a hash for display purposes.
pub fn short_hash(hash: &str, n: usize) -> &str {
    &hash[..n.min(hash.len())]
}

/// Splits a hash into a 2-char prefix and remaining suffix for directory sharding.
///
/// Content-addressable stores use this to avoid placing millions of files in a
/// single directory, which degrades filesystem performance on ext4/NTFS.
///
/// Example: `"a1b2c3d4..."` → `("a1", "b2c3d4...")`
pub fn shard_path(hash: &str) -> (&str, &str) {
    hash.split_at(2.min(hash.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn hash_deterministic() {
        let dir = std::env::temp_dir().join("but-next-test-hash");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.txt");
        let mut f = File::create(&path).unwrap();
        f.write_all(b"hello world").unwrap();
        drop(f);

        let h1 = hash_file(&path).unwrap();
        let h2 = hash_file(&path).unwrap();
        assert_eq!(h1, h2);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn hash_bytes_consistent() {
        let h1 = hash_bytes(b"test data");
        let h2 = hash_bytes(b"test data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_bytes_different_inputs() {
        let h1 = hash_bytes(b"data A");
        let h2 = hash_bytes(b"data B");
        assert_ne!(h1, h2);
    }

    #[test]
    fn shard_split() {
        let hash = "a1b2c3d4e5f6";
        let (prefix, suffix) = shard_path(hash);
        assert_eq!(prefix, "a1");
        assert_eq!(suffix, "b2c3d4e5f6");
    }

    #[test]
    fn short_hash_truncates() {
        let hash = "abcdefghij";
        assert_eq!(short_hash(hash, 4), "abcd");
    }
}
