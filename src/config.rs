//! # Configuration
//!
//! Handles loading, parsing, and validation of TOML configuration files.
//! Searches multiple standard locations with a well-defined priority order,
//! then validates all paths and settings before returning.

use crate::error::{ConfigError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::{env, fs};

/// Top-level configuration structure.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub settings: Settings,
    pub backup: BTreeMap<String, BackupTarget>,
}

/// Global settings controlling backup behavior.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Settings {
    /// Interval between backup cycles in seconds (used in watch mode).
    #[serde(default = "default_interval")]
    pub interval: u64,

    /// Filename template. Supports `%name%`, `%timestamp%`, `%date%`, `%time%`.
    #[serde(default = "default_filename")]
    pub filename: String,

    /// Compression algorithm: "zstd", "gzip", or "none".
    #[serde(default = "default_compression")]
    pub compression: CompressionKind,

    /// Zstd compression level (1-22, default 3).
    #[serde(default = "default_zstd_level")]
    pub zstd_level: i32,

    /// Enable AES-256-GCM encryption. Requires a password to be set.
    #[serde(default)]
    pub encrypt: bool,

    /// Maximum number of snapshots to retain per target (0 = unlimited).
    #[serde(default)]
    pub max_snapshots: usize,

    /// Repository root directory for content-addressable blob storage.
    #[serde(default = "default_repo_path")]
    pub repo_path: PathBuf,
}

/// A single backup target mapping a source directory to a destination.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BackupTarget {
    /// Source directory to back up.
    pub from: PathBuf,

    /// Destination directory for archives (used in archive mode).
    #[serde(default = "default_dest")]
    pub dest: PathBuf,

    /// Optional per-target compression override.
    pub compression: Option<CompressionKind>,

    /// Glob patterns to exclude from backup.
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// Supported compression backends.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CompressionKind {
    Zstd,
    Gzip,
    None,
}

impl std::fmt::Display for CompressionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompressionKind::Zstd => write!(f, "zstd"),
            CompressionKind::Gzip => write!(f, "gzip"),
            CompressionKind::None => write!(f, "none"),
        }
    }
}

fn default_interval() -> u64 {
    300
}
fn default_filename() -> String {
    "%name%-%date%-%time%".to_string()
}
fn default_compression() -> CompressionKind {
    CompressionKind::Zstd
}
fn default_zstd_level() -> i32 {
    3
}
fn default_repo_path() -> PathBuf {
    PathBuf::from(".but")
}
fn default_dest() -> PathBuf {
    PathBuf::from("./")
}

/// Standard configuration file search paths, in descending priority order.
fn config_search_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("/etc/but-next.toml")];
    if let Ok(home) = env::var("HOME") {
        paths.push(PathBuf::from(format!("{home}/.config/but-next.toml")));
    }
    if let Ok(xdg) = env::var("XDG_CONFIG_HOME") {
        paths.push(PathBuf::from(format!("{xdg}/but-next.toml")));
    }
    paths.push(PathBuf::from("but-next.toml"));
    paths
}

/// Loads configuration from the first found config file in the search path.
pub fn load_config() -> Result<Config> {
    let search = config_search_paths();

    for path in &search {
        if path.exists() {
            return load_config_from(path);
        }
    }

    Err(ConfigError::NotFound { searched: search }.into())
}

/// Loads and validates configuration from a specific file path.
pub fn load_config_from(path: &Path) -> Result<Config> {
    let content = fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", path.display()))?;

    let config: Config = toml::from_str(&content).map_err(|e| ConfigError::Parse { source: e })?;

    validate_config(&config)?;
    Ok(config)
}

/// Validates configuration invariants after parsing.
fn validate_config(config: &Config) -> std::result::Result<(), ConfigError> {
    if config.backup.is_empty() {
        return Err(ConfigError::Validation {
            message: "at least one [backup.*] target must be defined".to_string(),
        });
    }

    if config.settings.interval == 0 {
        return Err(ConfigError::Validation {
            message: "interval must be greater than 0".to_string(),
        });
    }

    if config.settings.zstd_level < 1 || config.settings.zstd_level > 22 {
        return Err(ConfigError::Validation {
            message: format!(
                "zstd_level must be between 1 and 22, got {}",
                config.settings.zstd_level
            ),
        });
    }

    for (name, target) in &config.backup {
        if target.from.as_os_str().is_empty() {
            return Err(ConfigError::Validation {
                message: format!("backup target '{name}' has empty 'from' path"),
            });
        }
    }

    Ok(())
}

/// Generates a default configuration file at the given path.
pub fn init_config(path: &Path) -> Result<()> {
    if path.exists() {
        return Err(anyhow::anyhow!("config file already exists: {}", path.display()).into());
    }

    let config = Config {
        settings: Settings {
            interval: 300,
            filename: "%name%-%date%-%time%".to_string(),
            compression: CompressionKind::Zstd,
            zstd_level: 3,
            encrypt: false,
            max_snapshots: 0,
            repo_path: PathBuf::from(".but"),
        },
        backup: BTreeMap::from([
            (
                "documents".to_string(),
                BackupTarget {
                    from: PathBuf::from("/home/user/Documents"),
                    dest: PathBuf::from("/backup/documents"),
                    compression: None,
                    exclude: vec!["*.tmp".to_string(), "*.cache".to_string()],
                },
            ),
            (
                "projects".to_string(),
                BackupTarget {
                    from: PathBuf::from("/home/user/Projects"),
                    dest: PathBuf::from("/backup/projects"),
                    compression: Some(CompressionKind::Zstd),
                    exclude: vec![
                        "target/".to_string(),
                        "node_modules/".to_string(),
                        ".git/".to_string(),
                    ],
                },
            ),
        ]),
    };

    let toml_str = toml::to_string_pretty(&config)
        .map_err(|e| anyhow::anyhow!("failed to serialize config: {e}"))?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, toml_str)?;

    Ok(())
}

#[allow(dead_code)]
/// Expands filename template variables.
pub fn expand_filename(template: &str, name: &str) -> String {
    let now = chrono::Local::now();
    template
        .replace("%name%", name)
        .replace("%timestamp%", &now.timestamp().to_string())
        .replace("%date%", &now.format("%Y%m%d").to_string())
        .replace("%time%", &now.format("%H%M%S").to_string())
}
