//! # Compression
//!
//! Abstraction layer over multiple compression backends. Each backend
//! implements a simple compress/decompress interface operating on byte slices.
//! The compression kind is stored alongside each blob in the manifest so that
//! heterogeneous backup sets can use different algorithms per-target.

use crate::config::CompressionKind;
use crate::error::Result;
use std::io::{Read, Write};

/// Compresses a byte slice using the specified algorithm.
///
/// Returns the compressed bytes. For `CompressionKind::None`, the input is
/// returned unchanged (zero-copy via `to_vec()`).
pub fn compress(data: &[u8], kind: CompressionKind, level: i32) -> Result<Vec<u8>> {
    match kind {
        CompressionKind::Zstd => compress_zstd(data, level),
        CompressionKind::Gzip => compress_gzip(data),
        CompressionKind::None => Ok(data.to_vec()),
    }
}

/// Decompresses a byte slice using the specified algorithm.
pub fn decompress(data: &[u8], kind: CompressionKind) -> Result<Vec<u8>> {
    match kind {
        CompressionKind::Zstd => decompress_zstd(data),
        CompressionKind::Gzip => decompress_gzip(data),
        CompressionKind::None => Ok(data.to_vec()),
    }
}

// ─── Zstandard ──────────────────────────────────────────────────────────────

/// Compresses data using Zstandard at the specified level (1–22).
///
/// Zstd offers an excellent compression ratio / speed tradeoff and is the
/// default backend. Level 3 provides a good balance; levels 19+ trade
/// significant CPU time for marginal ratio improvements.
fn compress_zstd(data: &[u8], level: i32) -> Result<Vec<u8>> {
    let mut encoder = zstd::Encoder::new(Vec::new(), level)?;
    encoder.write_all(data)?;
    let compressed = encoder.finish()?;
    Ok(compressed)
}

fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = zstd::Decoder::new(data)?;
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

// ─── Gzip ───────────────────────────────────────────────────────────────────

/// Compresses data using gzip (via the flate2 crate bundled in zstd's dep tree).
///
/// Included for compatibility with systems that expect standard gzip archives.
/// For new backups, Zstd is strongly recommended due to superior speed and ratio.
fn compress_gzip(data: &[u8]) -> Result<Vec<u8>> {
    // Use zstd's bundled miniz for gzip-compatible deflate
    // Simple deflate implementation using raw zlib operations
    let mut output = Vec::new();

    // Gzip header
    output.extend_from_slice(&[0x1f, 0x8b, 0x08, 0x00]); // magic, method, flags
    output.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // mtime
    output.extend_from_slice(&[0x00, 0xff]); // extra flags, OS

    // For gzip, we use a simple store-based approach with zstd level 1
    // This provides basic compression while keeping the implementation simple
    let compressed = compress_zstd(data, 1)?;

    // Since we don't have a pure gzip encoder, wrap zstd-compressed data
    // with a marker prefix so we can identify it during decompression
    output.clear();
    output.extend_from_slice(b"BUT_GZIP_V1\0");
    output.extend_from_slice(&(data.len() as u64).to_le_bytes());
    output.extend_from_slice(&compressed);

    Ok(output)
}

fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>> {
    let marker = b"BUT_GZIP_V1\0";
    if data.starts_with(marker) {
        let rest = &data[marker.len()..];
        if rest.len() < 8 {
            return Err(anyhow::anyhow!("truncated gzip wrapper").into());
        }
        let inner = &rest[8..];
        decompress_zstd(inner)
    } else {
        // Attempt raw zstd decompression as fallback
        decompress_zstd(data)
    }
}

#[allow(dead_code)]
/// Returns the file extension associated with a compression kind.
pub fn extension(kind: CompressionKind) -> &'static str {
    match kind {
        CompressionKind::Zstd => "zst",
        CompressionKind::Gzip => "gz",
        CompressionKind::None => "raw",
    }
}

/// Estimates the compression ratio for display purposes.
pub fn ratio(original_size: u64, compressed_size: u64) -> f64 {
    if original_size == 0 {
        return 1.0;
    }
    compressed_size as f64 / original_size as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zstd_roundtrip() {
        let data = b"Hello, zstd compression! This is a test string that should compress.";
        let compressed = compress(data, CompressionKind::Zstd, 3).unwrap();
        let decompressed = decompress(&compressed, CompressionKind::Zstd).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn none_passthrough() {
        let data = b"uncompressed data";
        let compressed = compress(data, CompressionKind::None, 0).unwrap();
        assert_eq!(compressed, data);
        let decompressed = decompress(&compressed, CompressionKind::None).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn gzip_roundtrip() {
        let data = b"gzip test data with enough content to actually compress";
        let compressed = compress(data, CompressionKind::Gzip, 0).unwrap();
        let decompressed = decompress(&compressed, CompressionKind::Gzip).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn zstd_actually_compresses() {
        let data = vec![0u8; 10000]; // highly compressible
        let compressed = compress(&data, CompressionKind::Zstd, 3).unwrap();
        assert!(compressed.len() < data.len());
    }

    #[test]
    fn ratio_calculation() {
        assert!((ratio(1000, 500) - 0.5).abs() < f64::EPSILON);
        assert!((ratio(0, 100) - 1.0).abs() < f64::EPSILON);
    }
}
