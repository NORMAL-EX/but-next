//! # Error Types
//!
//! Defines a structured error hierarchy for the backup engine using `thiserror`.
//! Each error variant carries enough context for meaningful diagnostics without
//! exposing internal implementation details to the caller.

use std::path::PathBuf;
use thiserror::Error;

/// Top-level error type encompassing all failure modes in the backup system.
#[derive(Error, Debug)]
pub enum ButError {
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("backup failed: {0}")]
    Backup(#[from] BackupError),

    #[error("restore failed: {0}")]
    Restore(#[from] RestoreError),

    #[error("repository error: {0}")]
    Repository(#[from] RepoError),

    #[error("encryption error: {0}")]
    Crypto(#[from] CryptoError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Configuration parsing and validation errors.
#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum ConfigError {
    #[error("config file not found (searched: {searched:?})")]
    NotFound { searched: Vec<PathBuf> },

    #[error("failed to parse config: {source}")]
    Parse {
        #[source]
        source: toml::de::Error,
    },

    #[error("invalid config: {message}")]
    Validation { message: String },

    #[error("backup target '{name}' references non-existent source: {path}")]
    MissingSource { name: String, path: PathBuf },
}

/// Errors during the backup process.
#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum BackupError {
    #[error("source directory does not exist: {0}")]
    SourceNotFound(PathBuf),

    #[error("destination directory is not writable: {0}")]
    DestinationNotWritable(PathBuf),

    #[error("failed to hash file {path}: {source}")]
    HashFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("compression failed for {path}: {source}")]
    CompressionFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write manifest: {0}")]
    ManifestWrite(#[source] std::io::Error),

    #[error("no changes detected since last snapshot")]
    NothingChanged,
}

/// Errors during restoration.
#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum RestoreError {
    #[error("snapshot not found: {0}")]
    SnapshotNotFound(String),

    #[error("blob missing from repository: {hash}")]
    BlobMissing { hash: String },

    #[error("integrity check failed for {path}: expected {expected}, got {actual}")]
    IntegrityFailure {
        path: PathBuf,
        expected: String,
        actual: String,
    },

    #[error("target directory already exists and --force not specified: {0}")]
    TargetExists(PathBuf),

    #[error("decompression failed: {0}")]
    DecompressionFailed(#[source] std::io::Error),
}

/// Repository structure and metadata errors.
#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum RepoError {
    #[error("repository not initialized at {0}")]
    NotInitialized(PathBuf),

    #[error("repository already exists at {0}")]
    AlreadyExists(PathBuf),

    #[error("corrupted repository: {message}")]
    Corrupted { message: String },

    #[error("lock file exists — another instance may be running: {0}")]
    Locked(PathBuf),
}

/// Cryptographic operation errors.
#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum CryptoError {
    #[error("encryption failed: invalid key length")]
    InvalidKeyLength,

    #[error("decryption failed: authentication tag mismatch (corrupted or wrong key)")]
    DecryptionFailed,

    #[error("key derivation failed")]
    KeyDerivation,
}

pub type Result<T> = std::result::Result<T, ButError>;
