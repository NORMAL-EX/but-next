//! # Restore Engine
//!
//! Reconstructs files from a snapshot by reading blobs from the content-addressable
//! store, decompressing, optionally decrypting, and writing to the target directory.
//!
//! Supports both full restore (all files) and selective restore (specific paths).
//! Integrity verification is performed after each file is restored by re-hashing
//! the written content and comparing against the manifest.

use crate::compress;
use crate::config::Settings;
use crate::crypto;
use crate::error::{RestoreError, Result};
use crate::hasher;
use crate::manifest::{self, Snapshot};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;

/// Options controlling restore behavior.
pub struct RestoreOptions<'a> {
    /// Target directory to restore files into.
    pub target_dir: PathBuf,

    /// Optional password for decrypting encrypted snapshots.
    pub password: Option<&'a str>,

    /// If true, overwrite existing files in the target directory.
    pub force: bool,

    /// If true, verify integrity of each restored file.
    pub verify: bool,

    /// If set, only restore files matching these prefixes.
    pub filter: Option<Vec<String>>,

    /// Enable verbose output.
    pub verbose: bool,
}

/// Restores all files from a snapshot to the target directory.
pub fn restore_snapshot(
    settings: &Settings,
    snapshot: &Snapshot,
    opts: &RestoreOptions,
) -> Result<RestoreStats> {
    let repo_path = &settings.repo_path;

    // Check target directory
    if opts.target_dir.exists() && !opts.force {
        let is_empty = opts
            .target_dir
            .read_dir()
            .map(|mut d| d.next().is_none())
            .unwrap_or(false);
        if !is_empty {
            return Err(RestoreError::TargetExists(opts.target_dir.clone()).into());
        }
    }

    std::fs::create_dir_all(&opts.target_dir)?;

    // Filter files if a filter is specified
    let files: Vec<_> = snapshot
        .files
        .iter()
        .filter(|(path, _)| {
            opts.filter.as_ref().map_or(true, |filters| {
                filters
                    .iter()
                    .any(|f| path.starts_with(f) || path.contains(f))
            })
        })
        .collect();

    let total = files.len() as u64;
    let pb = create_restore_progress(total);

    let mut stats = RestoreStats::default();

    for (relative_path, entry) in &files {
        pb.set_message(crate::backup::format_size(entry.size));

        // Read the blob from the store
        let raw_blob =
            manifest::read_blob(repo_path, &entry.hash).map_err(|_| RestoreError::BlobMissing {
                hash: entry.hash.clone(),
            })?;

        // Decrypt if necessary
        let compressed_data = if snapshot.encrypted {
            let password = opts
                .password
                .ok_or_else(|| anyhow::anyhow!("snapshot is encrypted but no password provided"))?;
            crypto::decrypt(&raw_blob, password)?
        } else {
            raw_blob
        };

        // Decompress
        let file_data =
            compress::decompress(&compressed_data, snapshot.compression).map_err(|e| {
                RestoreError::DecompressionFailed(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e.to_string(),
                ))
            })?;

        // Verify integrity
        if opts.verify {
            let actual_hash = hasher::hash_bytes(&file_data);
            if actual_hash != entry.hash {
                return Err(RestoreError::IntegrityFailure {
                    path: PathBuf::from(relative_path),
                    expected: entry.hash.clone(),
                    actual: actual_hash,
                }
                .into());
            }
        }

        // Write the file
        let target_path = opts.target_dir.join(relative_path);

        if let Some(parent) = target_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(&target_path, &file_data)?;

        // Restore Unix permissions
        #[cfg(unix)]
        if let Some(mode) = entry.permissions {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(mode);
            let _ = std::fs::set_permissions(&target_path, perms);
        }

        stats.files_restored += 1;
        stats.bytes_restored += entry.size;

        if opts.verbose {
            eprintln!("  {} {}", colored::Colorize::green("  ✓"), relative_path,);
        }

        pb.inc(1);
    }

    pb.finish_with_message("done");

    Ok(stats)
}

/// Compares two snapshots and returns the differences.
pub fn diff_snapshots(older: &Snapshot, newer: &Snapshot) -> SnapshotDiff {
    let mut diff = SnapshotDiff::default();

    // Files added or modified in newer
    for (path, new_entry) in &newer.files {
        match older.files.get(path) {
            None => {
                diff.added.push(path.clone());
                diff.added_size += new_entry.size;
            }
            Some(old_entry) => {
                if old_entry.hash != new_entry.hash {
                    diff.modified.push(path.clone());
                    diff.modified_size_delta += new_entry.size as i64 - old_entry.size as i64;
                }
            }
        }
    }

    // Files removed in newer
    for path in older.files.keys() {
        if !newer.files.contains_key(path) {
            diff.removed.push(path.clone());
            if let Some(entry) = older.files.get(path) {
                diff.removed_size += entry.size;
            }
        }
    }

    diff
}

/// Differences between two snapshots.
#[derive(Debug, Default)]
pub struct SnapshotDiff {
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub removed: Vec<String>,
    pub added_size: u64,
    pub modified_size_delta: i64,
    pub removed_size: u64,
}

impl SnapshotDiff {
    pub fn has_changes(&self) -> bool {
        !self.added.is_empty() || !self.modified.is_empty() || !self.removed.is_empty()
    }

    pub fn print_summary(&self) {
        if self.added.is_empty() && self.modified.is_empty() && self.removed.is_empty() {
            eprintln!("  No changes.");
            return;
        }

        if !self.added.is_empty() {
            eprintln!(
                "  {} {} files added (+{})",
                colored::Colorize::green("+"),
                self.added.len(),
                crate::backup::format_size(self.added_size),
            );
        }
        if !self.modified.is_empty() {
            eprintln!(
                "  {} {} files modified (Δ {})",
                colored::Colorize::yellow("~"),
                self.modified.len(),
                if self.modified_size_delta >= 0 {
                    format!(
                        "+{}",
                        crate::backup::format_size(self.modified_size_delta as u64)
                    )
                } else {
                    format!(
                        "-{}",
                        crate::backup::format_size((-self.modified_size_delta) as u64)
                    )
                },
            );
        }
        if !self.removed.is_empty() {
            eprintln!(
                "  {} {} files removed (-{})",
                colored::Colorize::red("-"),
                self.removed.len(),
                crate::backup::format_size(self.removed_size),
            );
        }
    }

    /// Prints the full list of changed files.
    pub fn print_detail(&self) {
        for path in &self.added {
            eprintln!("  {} {}", colored::Colorize::green("+"), path);
        }
        for path in &self.modified {
            eprintln!("  {} {}", colored::Colorize::yellow("~"), path);
        }
        for path in &self.removed {
            eprintln!("  {} {}", colored::Colorize::red("-"), path);
        }
    }
}

/// Statistics from a restore operation.
#[derive(Debug, Default)]
pub struct RestoreStats {
    pub files_restored: u64,
    pub bytes_restored: u64,
}

fn create_restore_progress(total: u64) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("  {spinner:.green} Restoring [{bar:30.cyan/dim}] {pos}/{len} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("━╸─"),
    );
    pb
}
