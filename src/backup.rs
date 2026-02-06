//! # Backup Engine
//!
//! Implements incremental, content-addressable backup with deduplication.
//!
//! ## Algorithm
//!
//! 1. Walk the source directory tree, collecting file metadata
//! 2. Compute BLAKE3 content hash for each file
//! 3. Check if the blob already exists in the repository (deduplication)
//! 4. For new/modified blobs: compress → (optionally encrypt) → store
//! 5. Write the snapshot manifest with all file entries
//!
//! Deduplication is automatic and cross-snapshot: if two files (even in different
//! targets or at different points in time) have identical content, the blob is
//! stored only once.

use crate::compress;
use crate::config::{BackupTarget, Config, Settings};
use crate::crypto;
use crate::error::Result;
use crate::hasher;
use crate::manifest::{self, FileEntry, Snapshot, SnapshotStats};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::Path;
use std::time::Instant;
use walkdir::WalkDir;

/// Executes a backup for a single target, returning the created snapshot.
pub fn backup_target(
    settings: &Settings,
    name: &str,
    target: &BackupTarget,
    password: Option<&str>,
    verbose: bool,
) -> Result<Snapshot> {
    let source = &target.from;
    let repo_path = &settings.repo_path;

    // Ensure source exists
    if !source.exists() {
        return Err(crate::error::BackupError::SourceNotFound(source.clone()).into());
    }

    // Initialize repo if needed
    manifest::init_repo(repo_path)?;

    let compression = target.compression.unwrap_or(settings.compression);
    let encrypted = settings.encrypt && password.is_some();

    let mut snapshot = Snapshot::new(name, source.clone(), compression, encrypted);

    // Collect all files first for progress tracking
    let files: Vec<_> = WalkDir::new(source)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| !is_excluded(e.path(), source, &target.exclude))
        .collect();

    let total_files = files.len() as u64;
    let pb = create_progress_bar(total_files, name);

    let start = Instant::now();
    let mut total_original_size = 0u64;
    let mut total_stored_size = 0u64;
    let mut dedup_count = 0u64;

    for entry in &files {
        let path = entry.path();
        let relative = path
            .strip_prefix(source)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();

        // Normalize path separators for cross-platform consistency
        let relative = relative.replace('\\', "/");

        pb.set_message(truncate_path(&relative, 40));

        // Get file metadata
        let metadata = std::fs::metadata(path)?;
        let file_size = metadata.len();
        total_original_size += file_size;

        #[cfg(unix)]
        let permissions = {
            use std::os::unix::fs::PermissionsExt;
            Some(metadata.permissions().mode())
        };
        #[cfg(not(unix))]
        let permissions = None;

        let modified = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Hash the file content
        let hash = hasher::hash_file(path)?;

        // Check for deduplication
        if manifest::blob_exists(repo_path, &hash) {
            dedup_count += 1;
            snapshot.add_file(
                relative,
                FileEntry {
                    hash,
                    size: file_size,
                    stored_size: 0,
                    permissions,
                    modified,
                    deduplicated: true,
                },
            );
            pb.inc(1);
            continue;
        }

        // Read, compress, and optionally encrypt the file
        let raw_data = std::fs::read(path)?;
        let compressed = compress::compress(&raw_data, compression, settings.zstd_level)?;

        let final_data = if encrypted {
            crypto::encrypt(&compressed, password.unwrap())?
        } else {
            compressed
        };

        let stored_size = final_data.len() as u64;
        total_stored_size += stored_size;

        // Store the blob
        manifest::store_blob(repo_path, &hash, &final_data)?;

        if verbose {
            let ratio = compress::ratio(file_size, stored_size);
            eprintln!(
                "  {} {} ({} → {}, {:.0}%)",
                colored::Colorize::green("  +"),
                relative,
                format_size(file_size),
                format_size(stored_size),
                ratio * 100.0,
            );
        }

        snapshot.add_file(
            relative,
            FileEntry {
                hash,
                size: file_size,
                stored_size,
                permissions,
                modified,
                deduplicated: false,
            },
        );

        pb.inc(1);
    }

    let duration = start.elapsed();
    pb.finish_with_message("done");

    snapshot.stats = SnapshotStats {
        total_files,
        new_files: total_files - dedup_count,
        modified_files: 0,
        unchanged_files: dedup_count,
        total_size: total_original_size,
        stored_size: total_stored_size,
        deduplicated_blobs: dedup_count,
        duration_ms: duration.as_millis() as u64,
    };

    // Save the snapshot manifest
    manifest::save_snapshot(repo_path, &snapshot)?;

    Ok(snapshot)
}

/// Runs backup for all targets defined in the configuration.
pub fn backup_all(config: &Config, password: Option<&str>, verbose: bool) -> Result<Vec<Snapshot>> {
    let mut snapshots = Vec::new();

    for (name, target) in &config.backup {
        eprintln!(
            "\n{} Backing up: {}",
            colored::Colorize::bold(colored::Colorize::cyan("▶")),
            colored::Colorize::bold(name.as_str()),
        );
        eprintln!("  Source: {}", target.from.display());

        match backup_target(&config.settings, name, target, password, verbose) {
            Ok(snapshot) => {
                print_snapshot_summary(&snapshot);
                snapshots.push(snapshot);
            }
            Err(e) => {
                eprintln!("  {} Failed: {e}", colored::Colorize::red("✗"),);
            }
        }
    }

    Ok(snapshots)
}

/// Prunes old snapshots, keeping only the most recent `keep` per target.
pub fn prune_snapshots(repo_path: &Path, target: &str, keep: usize) -> Result<(usize, u64)> {
    let mut snapshots = manifest::list_snapshots_for_target(repo_path, target)?;

    if snapshots.len() <= keep {
        return Ok((0, 0));
    }

    // Sort newest first
    snapshots.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    let to_delete = &snapshots[keep..];
    let mut deleted = 0usize;
    let mut freed = 0u64;

    for snap in to_delete {
        let bytes = manifest::delete_snapshot(repo_path, snap)?;
        freed += bytes;
        deleted += 1;
    }

    Ok((deleted, freed))
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Checks if a path matches any exclusion glob pattern.
fn is_excluded(path: &Path, base: &Path, patterns: &[String]) -> bool {
    let relative = path.strip_prefix(base).unwrap_or(path);
    let rel_str = relative.to_string_lossy();

    for pattern in patterns {
        // Simple glob matching: supports trailing * and /
        let pat = pattern.trim_end_matches('/');

        if let Some(suffix) = pat.strip_prefix('*') {
            // Suffix match: *.tmp matches any .tmp file
            if rel_str.ends_with(suffix) {
                return true;
            }
        } else if let Some(prefix) = pat.strip_suffix('*') {
            // Prefix match
            if rel_str.starts_with(prefix) {
                return true;
            }
        } else {
            // Exact or component match
            let components: Vec<_> = relative.components().collect();
            for component in &components {
                if component.as_os_str().to_string_lossy() == pat.trim_end_matches('/') {
                    return true;
                }
            }
        }
    }

    false
}

fn create_progress_bar(total: u64, target_name: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(&format!(
                "  {{spinner:.green}} {target_name} [{{bar:30.cyan/dim}}] {{pos}}/{{len}} {{msg}}"
            ))
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("━╸─"),
    );
    pb
}

fn truncate_path(path: &str, max_len: usize) -> String {
    if path.len() <= max_len {
        path.to_string()
    } else {
        format!("…{}", &path[path.len() - max_len + 1..])
    }
}

/// Prints a summary of the completed snapshot.
pub fn print_snapshot_summary(snapshot: &Snapshot) {
    let stats = &snapshot.stats;
    let ratio = if stats.total_size > 0 {
        stats.stored_size as f64 / stats.total_size as f64
    } else {
        0.0
    };

    eprintln!();
    eprintln!(
        "  {} Snapshot: {}",
        colored::Colorize::green("✓"),
        colored::Colorize::bold(snapshot.id.as_str()),
    );
    eprintln!(
        "    Files:       {} total, {} new, {} deduplicated",
        stats.total_files, stats.new_files, stats.deduplicated_blobs,
    );
    eprintln!(
        "    Size:        {} → {} ({:.1}% ratio)",
        format_size(stats.total_size),
        format_size(stats.stored_size),
        ratio * 100.0,
    );
    eprintln!(
        "    Compression: {}{}",
        snapshot.compression,
        if snapshot.encrypted {
            " + AES-256-GCM"
        } else {
            ""
        },
    );
    eprintln!("    Duration:    {:.2}s", stats.duration_ms as f64 / 1000.0);
}

/// Formats a byte count as a human-readable size string.
pub fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = bytes as f64;
    for unit in UNITS {
        if size < 1024.0 {
            return format!("{size:.1} {unit}");
        }
        size /= 1024.0;
    }
    format!("{size:.1} PiB")
}
