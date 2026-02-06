//! # but-next
//!
//! A modern, incremental file backup tool with content-addressable storage,
//! deduplication, encryption, and snapshot management.
//!
//! ## Architecture
//!
//! ```text
//!                    ┌─────────────┐
//!                    │   CLI (clap) │
//!                    └──────┬──────┘
//!                           │
//!              ┌────────────┼────────────┐
//!              ▼            ▼            ▼
//!         ┌────────┐  ┌─────────┐  ┌─────────┐
//!         │ Backup │  │ Restore │  │  Prune  │
//!         └───┬────┘  └────┬────┘  └────┬────┘
//!             │            │            │
//!     ┌───────┴───────┐    │            │
//!     ▼               ▼    ▼            ▼
//! ┌────────┐    ┌──────────────┐  ┌──────────┐
//! │ Hasher │    │  Compress    │  │ Manifest │
//! │(BLAKE3)│    │(zstd/gzip)  │  │(Snapshot)│
//! └────────┘    └──────┬───────┘  └──────────┘
//!                      │
//!                      ▼
//!               ┌────────────┐
//!               │   Crypto   │
//!               │(AES-256-GCM│
//!               └────────────┘
//! ```
//!
//! ## Comparison with `but` (predecessor)
//!
//! | Feature              | but          | but-next              |
//! |----------------------|--------------|-----------------------|
//! | Incremental backup   | ✗            | ✓ (content-addressed) |
//! | Deduplication        | ✗            | ✓ (BLAKE3 + CAS)     |
//! | Encryption           | ✗            | ✓ (AES-256-GCM)      |
//! | Restore              | ✗            | ✓ (full + selective)  |
//! | Snapshot management  | ✗            | ✓ (list/diff/prune)   |
//! | Integrity check      | ✗            | ✓ (per-file hash)     |
//! | Compression backends | zip, zstd    | zstd, gzip, none      |
//! | Error handling       | Box<dyn Err> | thiserror hierarchy   |
//! | Progress display     | ✗            | ✓ (indicatif)         |
//! | Tests                | ✗            | ✓                     |

mod backup;
mod compress;
mod config;
mod crypto;
mod error;
mod hasher;
mod manifest;
mod restore;

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

/// but-next — A modern incremental backup tool with content-addressable storage
#[derive(Parser, Debug)]
#[command(
    name = "but-next",
    version,
    about = "A modern incremental backup tool with deduplication and encryption 🔒",
    long_about = "but-next is a file backup tool that uses content-addressable storage \
                  for automatic deduplication, BLAKE3 hashing for integrity verification, \
                  and optional AES-256-GCM encryption for security.\n\n\
                  Successor to 'but' with incremental backups, restore support, \
                  and snapshot management."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Path to configuration file (overrides default search)
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Initialize a new configuration file
    Init {
        /// Output path for the configuration file
        #[arg(short, long, default_value = "but-next.toml")]
        output: PathBuf,
    },

    /// Run backup for all configured targets (or a specific one)
    Backup {
        /// Backup only this specific target
        #[arg(short, long)]
        target: Option<String>,

        /// Encryption password (or set BUT_NEXT_PASSWORD env var)
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Restore files from a snapshot
    Restore {
        /// Snapshot ID or prefix to restore from
        snapshot: String,

        /// Target directory to restore into
        #[arg(short, long)]
        output: PathBuf,

        /// Overwrite existing files
        #[arg(short, long)]
        force: bool,

        /// Verify integrity after restore
        #[arg(long, default_value_t = true)]
        verify: bool,

        /// Only restore files matching these path prefixes
        #[arg(short = 'F', long)]
        filter: Option<Vec<String>>,

        /// Decryption password
        #[arg(short, long)]
        password: Option<String>,
    },

    /// List all snapshots (optionally filtered by target)
    List {
        /// Filter snapshots by target name
        #[arg(short, long)]
        target: Option<String>,
    },

    /// Show differences between two snapshots
    Diff {
        /// Older snapshot ID (or prefix)
        older: String,
        /// Newer snapshot ID (or prefix)
        newer: String,

        /// Show full file listing
        #[arg(short, long)]
        detail: bool,
    },

    /// Remove old snapshots, keeping the most recent N per target
    Prune {
        /// Target to prune
        target: String,

        /// Number of most recent snapshots to keep
        #[arg(short, long, default_value_t = 5)]
        keep: usize,
    },

    /// Verify integrity of a snapshot's blobs
    Verify {
        /// Snapshot ID or prefix to verify
        snapshot: String,
    },

    /// Watch for changes and backup on interval
    Watch {
        /// Encryption password
        #[arg(short, long)]
        password: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("{} {}", colored::Colorize::red("error:"), e);
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> error::Result<()> {
    match &cli.command {
        Command::Init { output } => cmd_init(output),
        Command::Backup { target, password } => {
            cmd_backup(&cli, target.as_deref(), password.as_deref())
        }
        Command::Restore {
            snapshot,
            output,
            force,
            verify,
            filter,
            password,
        } => cmd_restore(
            &cli,
            snapshot,
            output,
            *force,
            *verify,
            filter.clone(),
            password.as_deref(),
        ),
        Command::List { target } => cmd_list(&cli, target.as_deref()),
        Command::Diff {
            older,
            newer,
            detail,
        } => cmd_diff(&cli, older, newer, *detail),
        Command::Prune { target, keep } => cmd_prune(&cli, target, *keep),
        Command::Verify { snapshot } => cmd_verify(&cli, snapshot),
        Command::Watch { password } => cmd_watch(&cli, password.as_deref()),
    }
}

// ─── Command Implementations ────────────────────────────────────────────────

fn cmd_init(output: &Path) -> error::Result<()> {
    config::init_config(output)?;
    eprintln!(
        "{} Created configuration file: {}",
        colored::Colorize::green("✓"),
        output.display(),
    );
    eprintln!("  Edit the file to configure your backup targets, then run:");
    eprintln!("  {} but-next backup", colored::Colorize::bold("$"));
    Ok(())
}

fn cmd_backup(cli: &Cli, target: Option<&str>, password: Option<&str>) -> error::Result<()> {
    let cfg = load_config(cli)?;
    let password = password
        .map(String::from)
        .or_else(|| std::env::var("BUT_NEXT_PASSWORD").ok());

    print_header("Backup");

    if let Some(target_name) = target {
        let target_config = cfg
            .backup
            .get(target_name)
            .ok_or_else(|| anyhow::anyhow!("target '{target_name}' not found in configuration"))?;

        eprintln!(
            "\n{} Backing up: {}",
            colored::Colorize::bold(colored::Colorize::cyan("▶")),
            colored::Colorize::bold(target_name),
        );

        let snapshot = backup::backup_target(
            &cfg.settings,
            target_name,
            target_config,
            password.as_deref(),
            cli.verbose,
        )?;
        backup::print_snapshot_summary(&snapshot);
    } else {
        backup::backup_all(&cfg, password.as_deref(), cli.verbose)?;
    }

    Ok(())
}

fn cmd_restore(
    cli: &Cli,
    snapshot_id: &str,
    output: &Path,
    force: bool,
    verify: bool,
    filter: Option<Vec<String>>,
    password: Option<&str>,
) -> error::Result<()> {
    let cfg = load_config(cli)?;
    let password = password
        .map(String::from)
        .or_else(|| std::env::var("BUT_NEXT_PASSWORD").ok());

    print_header("Restore");

    let snapshot = manifest::find_snapshot(&cfg.settings.repo_path, snapshot_id)?
        .ok_or_else(|| anyhow::anyhow!("snapshot '{snapshot_id}' not found"))?;

    eprintln!(
        "  Snapshot:  {} ({})",
        colored::Colorize::bold(snapshot.id.as_str()),
        snapshot.created_at.format("%Y-%m-%d %H:%M:%S"),
    );
    eprintln!("  Target:    {}", output.display());
    eprintln!("  Files:     {}", snapshot.stats.total_files);
    eprintln!();

    let opts = restore::RestoreOptions {
        target_dir: output.to_path_buf(),
        password: password.as_deref(),
        force,
        verify,
        filter,
        verbose: cli.verbose,
    };

    let stats = restore::restore_snapshot(&cfg.settings, &snapshot, &opts)?;

    eprintln!();
    eprintln!(
        "  {} Restored {} files ({})",
        colored::Colorize::green("✓"),
        stats.files_restored,
        backup::format_size(stats.bytes_restored),
    );

    Ok(())
}

fn cmd_list(cli: &Cli, target: Option<&str>) -> error::Result<()> {
    let cfg = load_config(cli)?;

    let snapshots = if let Some(target_name) = target {
        manifest::list_snapshots_for_target(&cfg.settings.repo_path, target_name)?
    } else {
        manifest::list_snapshots(&cfg.settings.repo_path)?
    };

    if snapshots.is_empty() {
        eprintln!("No snapshots found.");
        return Ok(());
    }

    eprintln!(
        "{:>4}  {:30}  {:12}  {:>8}  {:>10}  {:>10}",
        "#", "Snapshot ID", "Target", "Files", "Size", "Stored"
    );
    eprintln!("{}", "─".repeat(88));

    for (i, snap) in snapshots.iter().enumerate() {
        let enc = if snap.encrypted { "🔒" } else { "  " };
        eprintln!(
            "{:>4}  {:30}  {:12}  {:>8}  {:>10}  {:>10} {}",
            i + 1,
            snap.id,
            snap.target_name,
            snap.stats.total_files,
            backup::format_size(snap.stats.total_size),
            backup::format_size(snap.stats.stored_size),
            enc,
        );
    }

    eprintln!();
    eprintln!("  {} snapshot(s)", snapshots.len());

    Ok(())
}

fn cmd_diff(cli: &Cli, older_id: &str, newer_id: &str, detail: bool) -> error::Result<()> {
    let cfg = load_config(cli)?;

    let older = manifest::find_snapshot(&cfg.settings.repo_path, older_id)?
        .ok_or_else(|| anyhow::anyhow!("snapshot '{older_id}' not found"))?;

    let newer = manifest::find_snapshot(&cfg.settings.repo_path, newer_id)?
        .ok_or_else(|| anyhow::anyhow!("snapshot '{newer_id}' not found"))?;

    eprintln!("  Comparing:");
    eprintln!(
        "    older: {} ({})",
        older.id,
        older.created_at.format("%Y-%m-%d %H:%M:%S")
    );
    eprintln!(
        "    newer: {} ({})",
        newer.id,
        newer.created_at.format("%Y-%m-%d %H:%M:%S")
    );
    eprintln!();

    let diff = restore::diff_snapshots(&older, &newer);
    diff.print_summary();

    if detail && diff.has_changes() {
        eprintln!();
        diff.print_detail();
    }

    Ok(())
}

fn cmd_prune(cli: &Cli, target: &str, keep: usize) -> error::Result<()> {
    let cfg = load_config(cli)?;

    print_header("Prune");

    let (deleted, freed) = backup::prune_snapshots(&cfg.settings.repo_path, target, keep)?;

    if deleted == 0 {
        eprintln!("  Nothing to prune (≤{keep} snapshots exist for '{target}').");
    } else {
        eprintln!(
            "  {} Pruned {} snapshot(s), freed {}",
            colored::Colorize::green("✓"),
            deleted,
            backup::format_size(freed),
        );
    }

    Ok(())
}

fn cmd_verify(cli: &Cli, snapshot_id: &str) -> error::Result<()> {
    let cfg = load_config(cli)?;

    let snapshot = manifest::find_snapshot(&cfg.settings.repo_path, snapshot_id)?
        .ok_or_else(|| anyhow::anyhow!("snapshot '{snapshot_id}' not found"))?;

    eprintln!(
        "  Verifying snapshot: {} ({} files)",
        snapshot.id, snapshot.stats.total_files
    );

    let mut ok = 0u64;
    let mut missing = 0u64;

    for (path, entry) in &snapshot.files {
        if manifest::blob_exists(&cfg.settings.repo_path, &entry.hash) {
            ok += 1;
        } else {
            missing += 1;
            eprintln!(
                "  {} missing blob for: {} ({})",
                colored::Colorize::red("✗"),
                path,
                hasher::short_hash(&entry.hash, 12),
            );
        }
    }

    eprintln!();
    if missing == 0 {
        eprintln!(
            "  {} All {} blobs verified",
            colored::Colorize::green("✓"),
            ok,
        );
    } else {
        eprintln!(
            "  {} {ok} ok, {missing} missing",
            colored::Colorize::red("✗"),
        );
    }

    Ok(())
}

fn cmd_watch(cli: &Cli, password: Option<&str>) -> error::Result<()> {
    let cfg = load_config(cli)?;
    let password = password
        .map(String::from)
        .or_else(|| std::env::var("BUT_NEXT_PASSWORD").ok());

    let interval = cfg.settings.interval;
    eprintln!(
        "  {} Watching for changes every {}s (Ctrl+C to stop)",
        colored::Colorize::cyan("👁"),
        interval,
    );

    loop {
        std::thread::sleep(std::time::Duration::from_secs(interval));
        eprintln!(
            "\n  {} {}",
            colored::Colorize::dimmed("───"),
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        );
        backup::backup_all(&cfg, password.as_deref(), cli.verbose)?;
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn load_config(cli: &Cli) -> error::Result<config::Config> {
    if let Some(path) = &cli.config {
        config::load_config_from(path)
    } else {
        config::load_config()
    }
}

fn print_header(action: &str) {
    eprintln!();
    eprintln!(
        "  {} but-next v{} — {action}",
        colored::Colorize::bold("⚡"),
        env!("CARGO_PKG_VERSION"),
    );
    eprintln!();
}
