//! Persistence — on-disk peer storage for the Godot binding (app layer).
//!
//! Spec layout per `GUIDE-PERSISTENCE.md` §1 / `SDK-OPERATIONS.md` §15:
//! ```text
//! {data_root}/peers/{name}/
//!   ├── keypair      ← restored at startup (created on first boot)
//!   ├── config.toml  ← storage_backend, label
//!   └── store.db     ← SQLite tree (when storage_backend = "sqlite")
//! ```
//!
//! `data_root` resolution (first hit wins):
//!   1. the explicit `data_dir` passed by GDScript — the Godot app sets
//!      this to `ProjectSettings.globalize_path("user://entity")` so
//!      `user://` per-OS resolution stays in the GDScript layer where it
//!      belongs;
//!   2. `ENTITY_DATA_DIR` env var (spec §15.3 override — tests/ops);
//!   3. `$HOME/.entity`;
//!   4. `./.entity` (last resort).
//!
//! The SDK owns no I/O; this module produces a keypair + sqlite path that
//! the caller feeds into `PeerContextBuilder` (`.keypair()` + `.sqlite()`).
//! egui's `src/persistence.rs` is the cross-impl reference; this is the
//! Godot-flavored, single-named-peer subset (no PeerMode, no localStorage,
//! no legacy-layout migration — Godot is greenfield).

#![cfg(not(target_arch = "wasm32"))]

use std::path::{Path, PathBuf};

use entity_crypto::Keypair;

/// Resolve the configuration root. See module docs for precedence.
pub fn resolve_data_root(explicit: Option<&str>) -> PathBuf {
    if let Some(p) = explicit {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    if let Ok(env) = std::env::var("ENTITY_DATA_DIR") {
        if !env.is_empty() {
            return PathBuf::from(env);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home).join(".entity");
        }
    }
    PathBuf::from("./.entity")
}

/// Sanitize a user-chosen peer name into a filesystem-safe directory
/// segment. Lowercases ASCII alnum/`-`/`_`, maps whitespace to `-`,
/// drops everything else, caps at 32 chars. Mirrors egui's rule so the
/// same name produces the same directory across frontends.
pub fn sanitize_name(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter_map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                Some(c.to_ascii_lowercase())
            } else if c.is_whitespace() {
                Some('-')
            } else {
                None
            }
        })
        .collect();
    let trimmed = cleaned
        .trim_matches(|c: char| c == '-' || c == '_')
        .to_string();
    if trimmed.is_empty() {
        "peer".to_string()
    } else {
        trimmed.chars().take(32).collect()
    }
}

/// `{data_root}/peers/{sanitized name}`. Creates the directory tree.
pub fn peer_dir(data_root: &Path, name: &str) -> std::io::Result<PathBuf> {
    let dir = data_root.join("peers").join(sanitize_name(name));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Minimal `config.toml` reader — only the two keys this binding needs
/// (`storage_backend`, `label`). Hand-rolled instead of pulling the
/// `toml` crate into the binding: the file is two scalar keys, and
/// unknown lines are ignored so future spec keys don't break loading.
pub struct PeerConfigFile {
    pub storage_backend: String,
    pub label: Option<String>,
}

impl Default for PeerConfigFile {
    fn default() -> Self {
        Self {
            storage_backend: "sqlite".into(),
            label: None,
        }
    }
}

fn unquote(v: &str) -> String {
    let v = v.trim();
    v.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(v)
        .replace("\\\"", "\"")
}

pub fn read_config(dir: &Path) -> PeerConfigFile {
    let body = match std::fs::read_to_string(dir.join("config.toml")) {
        Ok(s) => s,
        Err(_) => return PeerConfigFile::default(),
    };
    let mut cfg = PeerConfigFile::default();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, val)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "storage_backend" => cfg.storage_backend = unquote(val),
            "label" => {
                let l = unquote(val);
                cfg.label = if l.is_empty() { None } else { Some(l) };
            }
            _ => {}
        }
    }
    cfg
}

pub fn write_config(dir: &Path, label: Option<&str>) -> std::io::Result<()> {
    let body = format!(
        "# entity-core-godot peer configuration\n\
         # Spec: GUIDE-PERSISTENCE.md §1\n\
         storage_backend = \"sqlite\"\n\
         {}\n",
        label
            .map(|l| format!("label = \"{}\"", l.replace('"', "\\\"")))
            .unwrap_or_default(),
    );
    std::fs::write(dir.join("config.toml"), body)
}

/// Load the peer's keypair from `{dir}/keypair`, creating + persisting a
/// fresh one on first boot. This is the identity-restore step of the
/// `GUIDE-PERSISTENCE.md` startup contract: same name → same peer_id
/// across runs.
pub fn load_or_create_keypair(dir: &Path) -> Result<Keypair, String> {
    let kp_path = dir.join("keypair");
    if kp_path.exists() {
        Keypair::load_from_file(&kp_path)
            .map_err(|e| format!("keypair load failed ({:?}): {}", kp_path, e))
    } else {
        let kp = Keypair::generate();
        kp.save_to_file(&kp_path)
            .map_err(|e| format!("keypair save failed ({:?}): {}", kp_path, e))?;
        Ok(kp)
    }
}

/// SQLite tree path for a peer dir, honoring `storage_backend`.
/// `None` when the config selects a non-sqlite backend.
pub fn store_db_path(dir: &Path, storage_backend: &str) -> Option<PathBuf> {
    if storage_backend == "sqlite" {
        Some(dir.join("store.db"))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_rules_match_reference() {
        assert_eq!(sanitize_name("My Peer"), "my-peer");
        assert_eq!(sanitize_name("  --weird!!__  "), "weird");
        assert_eq!(sanitize_name(""), "peer");
        assert_eq!(sanitize_name("///"), "peer");
        assert_eq!(sanitize_name(&"x".repeat(50)).len(), 32);
    }

    #[test]
    fn config_round_trip_and_tolerates_unknown_keys() {
        let tmp = std::env::temp_dir().join(format!("ecg-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        write_config(&tmp, Some("Net \"Main\"")).unwrap();
        // Inject a future/unknown key — must not break parsing.
        let mut body = std::fs::read_to_string(tmp.join("config.toml")).unwrap();
        body.push_str("future_key = \"ignored\"\n");
        std::fs::write(tmp.join("config.toml"), body).unwrap();

        let cfg = read_config(&tmp);
        assert_eq!(cfg.storage_backend, "sqlite");
        assert_eq!(cfg.label.as_deref(), Some("Net \"Main\""));
        assert_eq!(
            store_db_path(&tmp, &cfg.storage_backend),
            Some(tmp.join("store.db"))
        );
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn keypair_persists_same_id_across_calls() {
        let tmp = std::env::temp_dir().join(format!("ecg-kp-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let a = load_or_create_keypair(&tmp).unwrap();
        let b = load_or_create_keypair(&tmp).unwrap();
        assert_eq!(a.peer_id().to_string(), b.peer_id().to_string());
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn data_root_precedence() {
        assert_eq!(
            resolve_data_root(Some("/explicit/path")),
            PathBuf::from("/explicit/path")
        );
        // Empty explicit falls through.
        assert_ne!(resolve_data_root(Some("")), PathBuf::from(""));
    }
}
