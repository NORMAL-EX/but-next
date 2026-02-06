//! # Snapshot Manifest
//!
//! Each backup operation produces a snapshot — an immutable point-in-time record
//! of all files in the backup set. The manifest stores file metadata (path, size,
//! permissions, modification time) alongside the content hash used to locate the
//! corresponding blob in the content-addressable store.
//!
//! ## Repository Layout
//!
//! ```text
//! .but/
//! ├── snapshots/
//! │   ├── 20240101-120000-documents.json
//! │   └── 20240101-130000-documents.json
//! ├── blobs/
//! │   ├── a1/
//! │   │   └── b2c3d4e5f6...   (compressed file content)
//! │   ├── ff/
//! │   │   └── 0011aabb...
//! │   └── ...
//! └── lock
//! ```

use crate::config::CompressionKind;
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A complete snapshot of a backup target at a specific point in time.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Snapshot {
    /// Unique snapshot identifier (timestamp + target name).
    pub id: String,

    /// Name of the backup target (from config).
    pub target_name: String,

    /// Source directory that was backed up.
    pub source_path: PathBuf,

    /// When the snapshot was created.
    pub created_at: DateTime<Local>,

    /// Compression algorithm used for blobs in this snapshot.
    pub compression: CompressionKind,

    /// Whether blobs are encrypted.
    pub encrypted: bool,

    /// Map of relative file paths to their metadata and content hash.
    pub files: BTreeMap<String, FileEntry>,

    /// Summary statistics computed after the backup completes.
    pub stats: SnapshotStats,
}

/// Metadata for a single file within a snapshot.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileEntry {
    /// BLAKE3 content hash — the key into the blob store.
    pub hash: String,

    /// Original (uncompressed) file size in bytes.
    pub size: u64,

    /// Size after compression (and optional encryption).
    pub stored_size: u64,

    /// Unix file permissions (mode bits). `None` on Windows.
    pub permissions: Option<u32>,

    /// Last modification time as Unix timestamp.
    pub modified: u64,

    /// Whether this blob was already present (deduplicated).
    pub deduplicated: bool,
}

/// Aggregate statistics for a snapshot.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SnapshotStats {
    /// Total number of files in the snapshot.
    pub total_files: u64,

    /// Number of new files not present in any previous snapshot.
    pub new_files: u64,

    /// Number of files whose content changed since the last snapshot.
    pub modified_files: u64,

    /// Number of files unchanged (deduplicated, not re-stored).
    pub unchanged_files: u64,

    /// Total size of all files before compression.
    pub total_size: u64,

    /// Total size of newly stored blobs after compression.
    pub stored_size: u64,

    /// Total number of blobs deduplicated (already in the store).
    pub deduplicated_blobs: u64,

    /// Backup duration in milliseconds.
    pub duration_ms: u64,
}

impl Snapshot {
    /// Generates a snapshot ID from the current time and target name.
    pub fn generate_id(target_name: &str) -> String {
        let now = Local::now();
        format!("{}-{}", now.format("%Y%m%d-%H%M%S"), target_name)
    }

    /// Creates a new empty snapshot.
    pub fn new(
        target_name: &str,
        source_path: PathBuf,
        compression: CompressionKind,
        encrypted: bool,
    ) -> Self {
        Self {
            id: Self::generate_id(target_name),
            target_name: target_name.to_string(),
            source_path,
            created_at: Local::now(),
            compression,
            encrypted,
            files: BTreeMap::new(),
            stats: SnapshotStats::default(),
        }
    }

    /// Adds a file entry to the snapshot.
    pub fn add_file(&mut self, relative_path: String, entry: FileEntry) {
        self.stats.total_files += 1;
        self.stats.total_size += entry.size;

        if entry.deduplicated {
            self.stats.deduplicated_blobs += 1;
            self.stats.unchanged_files += 1;
        } else {
            self.stats.stored_size += entry.stored_size;
            self.stats.new_files += 1;
        }

        self.files.insert(relative_path, entry);
    }

    /// Serializes the snapshot to JSON.
    pub fn to_json(&self) -> anyhow::Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("failed to serialize snapshot: {e}"))
    }

    /// Deserializes a snapshot from JSON.
    pub fn from_json(json: &str) -> anyhow::Result<Self> {
        serde_json::from_str(json).map_err(|e| anyhow::anyhow!("failed to parse snapshot: {e}"))
    }
}

// ─── Repository Operations ──────────────────────────────────────────────────

/// Initializes the repository directory structure.
pub fn init_repo(repo_path: &Path) -> anyhow::Result<()> {
    let dirs = ["snapshots", "blobs"];
    for dir in &dirs {
        std::fs::create_dir_all(repo_path.join(dir))?;
    }
    Ok(())
}

/// Returns the filesystem path for a blob given its hash, using 2-char sharding.
pub fn blob_path(repo_path: &Path, hash: &str) -> PathBuf {
    let (prefix, suffix) = crate::hasher::shard_path(hash);
    repo_path.join("blobs").join(prefix).join(suffix)
}

/// Checks whether a blob with the given hash already exists in the repository.
pub fn blob_exists(repo_path: &Path, hash: &str) -> bool {
    blob_path(repo_path, hash).exists()
}

/// Writes a blob to the content-addressable store, creating shard directories as needed.
pub fn store_blob(repo_path: &Path, hash: &str, data: &[u8]) -> anyhow::Result<()> {
    let path = blob_path(repo_path, hash);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, data)?;
    Ok(())
}

/// Reads a blob from the content-addressable store.
pub fn read_blob(repo_path: &Path, hash: &str) -> anyhow::Result<Vec<u8>> {
    let path = blob_path(repo_path, hash);
    std::fs::read(&path).map_err(|e| anyhow::anyhow!("failed to read blob {}: {e}", hash))
}

/// Saves a snapshot manifest to the snapshots directory.
pub fn save_snapshot(repo_path: &Path, snapshot: &Snapshot) -> anyhow::Result<PathBuf> {
    let filename = format!("{}.json", snapshot.id);
    let path = repo_path.join("snapshots").join(&filename);
    let json = snapshot.to_json()?;
    std::fs::write(&path, json)?;
    Ok(path)
}

/// Lists all snapshots in the repository, sorted by creation time.
pub fn list_snapshots(repo_path: &Path) -> anyhow::Result<Vec<Snapshot>> {
    let snapshots_dir = repo_path.join("snapshots");
    if !snapshots_dir.exists() {
        return Ok(Vec::new());
    }

    let mut snapshots = Vec::new();
    for entry in std::fs::read_dir(&snapshots_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            let json = std::fs::read_to_string(&path)?;
            match Snapshot::from_json(&json) {
                Ok(snap) => snapshots.push(snap),
                Err(e) => eprintln!(
                    "warning: skipping corrupted snapshot {}: {e}",
                    path.display()
                ),
            }
        }
    }

    snapshots.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    Ok(snapshots)
}

/// Lists snapshots filtered by target name.
pub fn list_snapshots_for_target(repo_path: &Path, target: &str) -> anyhow::Result<Vec<Snapshot>> {
    let all = list_snapshots(repo_path)?;
    Ok(all
        .into_iter()
        .filter(|s| s.target_name == target)
        .collect())
}

/// Finds a specific snapshot by ID (exact or prefix match).
pub fn find_snapshot(repo_path: &Path, id_prefix: &str) -> anyhow::Result<Option<Snapshot>> {
    let all = list_snapshots(repo_path)?;
    let matches: Vec<_> = all
        .into_iter()
        .filter(|s| s.id.starts_with(id_prefix))
        .collect();

    match matches.len() {
        0 => Ok(None),
        1 => Ok(Some(matches.into_iter().next().unwrap())),
        n => Err(anyhow::anyhow!(
            "ambiguous snapshot prefix '{id_prefix}': matched {n} snapshots"
        )),
    }
}

/// Deletes a snapshot and any orphaned blobs.
pub fn delete_snapshot(repo_path: &Path, snapshot: &Snapshot) -> anyhow::Result<u64> {
    // Collect all blob hashes referenced by other snapshots
    let all_snapshots = list_snapshots(repo_path)?;
    let mut referenced_hashes = std::collections::HashSet::new();

    for snap in &all_snapshots {
        if snap.id == snapshot.id {
            continue;
        }
        for entry in snap.files.values() {
            referenced_hashes.insert(entry.hash.clone());
        }
    }

    // Delete orphaned blobs (only referenced by the snapshot being deleted)
    let mut freed_bytes = 0u64;
    for entry in snapshot.files.values() {
        if !referenced_hashes.contains(&entry.hash) {
            let path = blob_path(repo_path, &entry.hash);
            if path.exists() {
                freed_bytes += std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                let _ = std::fs::remove_file(&path);
            }
        }
    }

    // Delete the snapshot manifest
    let manifest_path = repo_path
        .join("snapshots")
        .join(format!("{}.json", snapshot.id));
    let _ = std::fs::remove_file(&manifest_path);

    Ok(freed_bytes)
}
