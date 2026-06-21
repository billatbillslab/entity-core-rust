//! Configuration and paths (~/.entity/).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Get the base entity directory (~/.entity/).
pub fn entity_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("ENTITY_HOME") {
        return PathBuf::from(dir);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".entity")
}

/// Get the identities directory.
pub fn identities_dir() -> PathBuf {
    entity_dir().join("identities")
}

/// Get the peers directory.
pub fn peers_dir() -> PathBuf {
    entity_dir().join("peers")
}

/// Get the path for a specific identity keypair.
pub fn identity_key_path(name: &str) -> PathBuf {
    identities_dir().join(name)
}

/// Get the directory for a specific peer.
pub fn peer_dir(name: &str) -> PathBuf {
    peers_dir().join(name)
}

/// Peer configuration stored as config.toml.
/// Compatible with old Rust implementation's [peer] section format.
#[derive(Debug, Serialize, Deserialize)]
pub struct PeerToml {
    pub peer: PeerSection,
    #[serde(default)]
    pub logging: Option<LoggingSection>,
    #[serde(default)]
    pub storage: Option<StorageSection>,
    // Ignore other sections from old config
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, toml::Value>,
}

/// Storage backend configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageSection {
    /// Backend type: "memory" or "sqlite". Default: "memory".
    #[serde(default = "default_storage_backend")]
    pub backend: String,
    /// Path to SQLite database file (relative to peer directory).
    /// Default: "store.db". Only used when backend = "sqlite".
    #[serde(default)]
    pub path: Option<String>,
}

fn default_storage_backend() -> String {
    "memory".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerSection {
    pub listen_addr: String,
    #[serde(default)]
    pub max_connections: Option<usize>,
    #[serde(default)]
    pub connection_timeout_secs: Option<u64>,
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, toml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingSection {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub format: Option<String>,
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for PeerToml {
    fn default() -> Self {
        Self {
            peer: PeerSection {
                listen_addr: "127.0.0.1:9000".to_string(),
                max_connections: Some(100),
                connection_timeout_secs: Some(30),
                extra: std::collections::HashMap::new(),
            },
            logging: None,
            storage: None,
            extra: std::collections::HashMap::new(),
        }
    }
}

/// Grant configuration stored as grants.toml.
#[derive(Debug, Serialize, Deserialize)]
pub struct GrantsToml {
    pub grants: Vec<GrantEntry>,
}

impl Default for GrantsToml {
    fn default() -> Self {
        Self {
            grants: vec![GrantEntry::default()],
        }
    }
}

/// A single grant entry.
#[derive(Debug, Serialize, Deserialize)]
pub struct GrantEntry {
    pub handlers: Vec<String>,
    pub resources: Vec<String>,
    pub operations: Vec<String>,
}

impl Default for GrantEntry {
    fn default() -> Self {
        Self {
            handlers: vec!["*".to_string()],
            resources: vec!["*".to_string()],
            operations: vec!["*".to_string()],
        }
    }
}
