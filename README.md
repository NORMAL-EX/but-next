# but-next ⚡

[![CI](https://github.com/NORMAL-EX/but-next/actions/workflows/ci.yml/badge.svg)](https://github.com/NORMAL-EX/but-next/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)

> The next generation of file backup — incremental, deduplicated, encrypted.

**but-next** is a modern file backup tool built in Rust with content-addressable storage for automatic deduplication, BLAKE3 hashing for integrity verification, and optional AES-256-GCM authenticated encryption.

## ✨ Features

- **Incremental Backup** — Only stores changed files using content-addressable storage with BLAKE3 hashing; identical files are never stored twice
- **AES-256-GCM Encryption** — Optional authenticated encryption with random nonces and BLAKE3-derived keys
- **Snapshot Management** — Full `list`, `diff`, `prune`, and `verify` commands for managing backup history
- **Restore** — Full or selective file restoration with integrity verification
- **Multiple Compression Backends** — Zstandard (default), gzip, or no compression
- **Progress Display** — Real-time progress bars with compression ratios and deduplication stats
- **Cross-Platform** — Linux, macOS, Windows with pre-built binaries
- **Structured Error Handling** — Typed error hierarchy with `thiserror` for clear diagnostics

## 📦 Installation

### From Source

```bash
git clone https://github.com/NORMAL-EX/but-next.git
cd but-next
cargo install --path .
```

### Pre-built Binaries

Download from the [Releases](https://github.com/NORMAL-EX/but-next/releases) page.

## 🚀 Quick Start

```bash
# Initialize a configuration file
but-next init

# Edit but-next.toml to set your backup targets, then:
but-next backup

# List all snapshots
but-next list

# Restore from a snapshot
but-next restore <snapshot-id> --output ./restored

# Compare two snapshots
but-next diff <older-id> <newer-id> --detail

# Prune old snapshots (keep last 5)
but-next prune documents --keep 5

# Watch mode (backup on interval)
but-next watch
```

## ⚙️ Configuration

```toml
[settings]
interval = 300
filename = "%name%-%date%-%time%"
compression = "zstd"
zstd_level = 3
encrypt = false
max_snapshots = 0
repo_path = ".but"

[backup.documents]
from = "/home/user/Documents"
dest = "/backup/documents"
exclude = ["*.tmp", "*.cache"]

[backup.projects]
from = "/home/user/Projects"
dest = "/backup/projects"
compression = "zstd"
exclude = ["target/", "node_modules/", ".git/"]
```

## 🏗️ Architecture

```
src/
├── main.rs        CLI entry point — clap subcommands, orchestration
├── config.rs      TOML config loading, validation, template expansion
├── backup.rs      Incremental backup engine with deduplication
├── restore.rs     Snapshot restoration + diff engine
├── manifest.rs    Snapshot metadata, blob store, repository operations
├── hasher.rs      BLAKE3 content hashing with streaming reads
├── compress.rs    Compression abstraction (zstd, gzip, none)
├── crypto.rs      AES-256-GCM encryption with BLAKE3 key derivation
└── error.rs       Typed error hierarchy (thiserror)
```

### Repository Layout (Content-Addressable Store)

```
.but/
├── snapshots/
│   ├── 20250207-120000-documents.json    # Snapshot manifests
│   └── 20250207-130000-projects.json
└── blobs/
    ├── a1/
    │   └── b2c3d4e5f6...                 # Compressed file blobs
    ├── ff/
    │   └── 0011aabb...                   # (2-char shard prefix)
    └── ...
```

### Data Flow

```
                    ┌─────────────┐
                    │   CLI (clap) │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
         ┌────────┐  ┌─────────┐  ┌─────────┐
         │ Backup │  │ Restore │  │  Prune  │
         └───┬────┘  └────┬────┘  └────┬────┘
             │            │            │
     ┌───────┴───────┐    │            │
     ▼               ▼    ▼            ▼
 ┌────────┐    ┌──────────────┐  ┌──────────┐
 │ Hasher │    │  Compress    │  │ Manifest │
 │(BLAKE3)│    │(zstd / gzip) │  │(JSON)    │
 └────────┘    └──────┬───────┘  └──────────┘
                      │
                      ▼
               ┌────────────┐
               │   Crypto   │
               │(AES-256-GCM│
               └────────────┘
```

## 🔬 Technical Details

### Content-Addressable Storage

Files are stored by their BLAKE3 content hash with 2-character directory sharding (e.g., hash `a1b2c3...` → `blobs/a1/b2c3...`). This provides automatic deduplication: identical files across targets, snapshots, or time are stored exactly once.

### Encryption

AES-256-GCM with random 96-bit nonces. Keys are derived from passwords using BLAKE3 keyed derivation with domain separation. Wire format: `nonce (12B) ‖ ciphertext ‖ auth tag (16B)`.

### Incremental Backup Algorithm

1. Walk source directory, collect file metadata
2. Compute BLAKE3 hash for each file (streaming, 64 KiB chunks)
3. Check blob store — if hash exists, deduplicate (skip storage)
4. New blobs: compress (zstd/gzip) → optionally encrypt → store
5. Write snapshot manifest with complete file metadata

## 📄 License

MIT — see [LICENSE](LICENSE).

---

Made with 🦀 by [NORMAL-EX](https://github.com/NORMAL-EX)
