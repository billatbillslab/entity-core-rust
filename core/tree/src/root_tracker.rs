//! Incremental trie root tracker — EXTENSION-TREE §3.4.
//!
//! A synchronous emit pathway consumer (SYSTEM-COMPOSITION §2.2, position 6)
//! that maintains trie root hashes for configured prefixes. For each enabled
//! `system/tree/tracking-config` entity, the tracker reflects every tree
//! mutation under the config's prefix into a stored trie, writing the current
//! root hash to `system/tree/root/{prefix}`.
//!
//! Self-guard: mutations under `system/tree/root/*` are ignored to prevent
//! recursive updates when the tracker itself writes root hashes.
//!
//! Config hot-reload: writes to `system/tree/tracking-config/*` trigger an
//! initial build (or clear) for the affected prefix.

use std::sync::{Arc, RwLock};

use entity_entity::Entity;
use entity_hash::Hash;
use entity_store::{ContentStore, ExecutionContext, LocationIndex, SyncTreeHook, TreeChangeEvent};

use crate::trie;

/// A decoded `system/tree/tracking-config` entry.
#[derive(Debug, Clone)]
struct TrackingConfig {
    /// Bare prefix (relative to the peer), MUST end with `/`.
    prefix: String,
    enabled: bool,
}

pub struct RootTrackerEngine {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    local_peer_id: String,
    /// Pre-computed prefix `/{peer_id}/system/tree/root/` for the self-guard
    /// check and for writing root entries.
    root_path_prefix: String,
    /// Pre-computed prefix `/{peer_id}/system/tree/tracking-config/` for
    /// the config-change branch.
    config_path_prefix: String,
    /// Cached enabled configs. Refreshed at bootstrap and on every event under
    /// `config_path_prefix`. The per-put hot path reads this cache instead of
    /// scanning + decoding the location index on every tree mutation.
    cached_configs: RwLock<Vec<TrackingConfig>>,
}

impl RootTrackerEngine {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
    ) -> Self {
        let root_path_prefix = format!("/{}/system/tree/root/", &local_peer_id);
        let config_path_prefix = format!("/{}/system/tree/tracking-config/", &local_peer_id);
        Self {
            content_store,
            location_index,
            local_peer_id,
            root_path_prefix,
            config_path_prefix,
            cached_configs: RwLock::new(Vec::new()),
        }
    }

    /// Scan existing tracking configs and rebuild tries for all enabled
    /// prefixes. Called once at peer startup.
    pub fn bootstrap(&self) {
        let configs = self.load_all_configs();
        tracing::info!(
            peer_id = %self.local_peer_id,
            configs = configs.len(),
            "[root-tracker] bootstrap"
        );
        for cfg in &configs {
            if cfg.enabled {
                self.rebuild_prefix(&cfg.prefix);
            }
        }
        *self.cached_configs.write().unwrap() = configs;
    }

    fn load_all_configs(&self) -> Vec<TrackingConfig> {
        let entries = self.location_index.list(&self.config_path_prefix);
        entries
            .into_iter()
            .filter_map(|e| {
                let entity = self.content_store.get(&e.hash)?;
                decode_tracking_config(&entity)
            })
            .collect()
    }

    fn refresh_cache(&self) {
        let configs = self.load_all_configs();
        *self.cached_configs.write().unwrap() = configs;
    }

    /// Compute the qualified absolute path for the root entry of `bare_prefix`.
    fn qualified_root_path(&self, bare_prefix: &str) -> String {
        let stripped = bare_prefix.trim_end_matches('/');
        format!("{}{}", self.root_path_prefix, stripped)
    }

    /// Qualified prefix for events under `bare_prefix` (e.g. `/{peer}/project/`).
    fn qualified_bare_prefix(&self, bare_prefix: &str) -> String {
        format!("/{}/{}", self.local_peer_id, bare_prefix)
    }

    /// Read the currently tracked root hash for a prefix, if any.
    ///
    /// The binding at `system/tree/root/{prefix}` points directly at the
    /// root trie node's content hash — no wrapper entity
    /// (EXTENSION-TREE §3.4.1 + TREE-ROOT-PATH-AMBIGUITY.md direct-binding).
    fn load_tracked_root(&self, bare_prefix: &str) -> Option<Hash> {
        self.location_index.get(&self.qualified_root_path(bare_prefix))
    }

    /// Bind the trie root hash directly at `system/tree/root/{prefix}`.
    /// No wrapper: the binding is the trie root node's content hash.
    fn store_tracked_root(
        &self,
        bare_prefix: &str,
        root_hash: Hash,
        ctx: Option<&ExecutionContext>,
    ) {
        let path = self.qualified_root_path(bare_prefix);
        match ctx {
            Some(c) => {
                let _cascade = self
                    .location_index
                    .set_with_context(&path, root_hash, c.clone());
            }
            None => self.location_index.set(&path, root_hash),
        }
    }

    fn remove_tracked_root(&self, bare_prefix: &str, ctx: Option<&ExecutionContext>) {
        let path = self.qualified_root_path(bare_prefix);
        match ctx {
            Some(c) => {
                let _cascade = self.location_index.remove_with_context(&path, c.clone());
            }
            None => {
                self.location_index.remove(&path);
            }
        }
    }

    /// Full rebuild of the trie for `bare_prefix` from the current bindings
    /// in the location index. Used on config creation and startup discovery.
    fn rebuild_prefix(&self, bare_prefix: &str) {
        let qualified = self.qualified_bare_prefix(bare_prefix);
        let entries = self.location_index.list(&qualified);
        let mut bindings = std::collections::BTreeMap::new();
        for e in entries {
            // Skip the tracker's own output paths to avoid circular inclusion.
            if e.path.starts_with(&self.root_path_prefix) {
                continue;
            }
            // Strip the qualified prefix to get the relative path the trie indexes by.
            let rel = &e.path[qualified.len()..];
            bindings.insert(rel.to_string(), e.hash);
        }
        match trie::build_trie(self.content_store.as_ref(), &bindings) {
            Ok(root) => {
                tracing::info!(
                    prefix = %bare_prefix,
                    root = %root,
                    bindings = bindings.len(),
                    "[root-tracker] rebuild"
                );
                self.store_tracked_root(bare_prefix, root, None);
            }
            Err(e) => {
                tracing::warn!(prefix = %bare_prefix, error = %e, "[root-tracker] build_trie failed");
            }
        }
    }

    /// Incrementally apply a single tree-change event to the trie for
    /// `bare_prefix`. Returns silently when the event's path is not under
    /// the prefix.
    fn apply_event(
        &self,
        bare_prefix: &str,
        event: &TreeChangeEvent,
        ctx: Option<&ExecutionContext>,
    ) {
        let qualified = self.qualified_bare_prefix(bare_prefix);
        if !event.path.starts_with(&qualified) {
            return;
        }
        let rel = &event.path[qualified.len()..];
        let current_root = self.load_tracked_root(bare_prefix);

        let result = match event.new_hash {
            Some(new) => trie::trie_put(self.content_store.as_ref(), current_root, rel, new),
            None => trie::trie_remove(self.content_store.as_ref(), current_root, rel),
        };

        match result {
            Ok(new_root) => {
                tracing::info!(
                    prefix = %bare_prefix,
                    path = %event.path,
                    root = %new_root,
                    "[root-tracker] update"
                );
                self.store_tracked_root(bare_prefix, new_root, ctx);
            }
            Err(e) => {
                tracing::warn!(prefix = %bare_prefix, path = %event.path, error = %e, "[root-tracker] incremental update failed");
            }
        }
    }

    fn handle_config_change(&self, event: &TreeChangeEvent, ctx: Option<&ExecutionContext>) {
        // Decode the new config if present.
        let new_cfg = event
            .new_hash
            .and_then(|h| self.content_store.get(&h))
            .as_ref()
            .and_then(decode_tracking_config);

        let previous_cfg = event
            .previous_hash
            .and_then(|h| self.content_store.get(&h))
            .as_ref()
            .and_then(decode_tracking_config);

        match (previous_cfg.as_ref(), new_cfg.as_ref()) {
            (None, Some(cfg)) if cfg.enabled => {
                self.rebuild_prefix(&cfg.prefix);
            }
            (Some(prev), Some(cfg)) => {
                if prev.prefix != cfg.prefix {
                    // Prefix changed: clear the old root and rebuild for the new one.
                    self.remove_tracked_root(&prev.prefix, ctx);
                    if cfg.enabled {
                        self.rebuild_prefix(&cfg.prefix);
                    }
                } else if prev.enabled && !cfg.enabled {
                    self.remove_tracked_root(&cfg.prefix, ctx);
                } else if !prev.enabled && cfg.enabled {
                    self.rebuild_prefix(&cfg.prefix);
                }
            }
            (Some(prev), None) => {
                // Config removed — clear the tracked root.
                self.remove_tracked_root(&prev.prefix, ctx);
            }
            _ => {}
        }
    }
}

impl SyncTreeHook for RootTrackerEngine {
    fn on_tree_change(&self, event: &TreeChangeEvent, ctx: &mut ExecutionContext)
        -> Result<(), entity_store::CascadeHalt>
    {
        if event.path.starts_with(&self.root_path_prefix) {
            return Ok(());
        }

        if event.path.starts_with(&self.config_path_prefix) {
            self.handle_config_change(event, Some(ctx));
            self.refresh_cache();
            return Ok(());
        }

        // Hot path: read cached configs instead of scanning + decoding the
        // index on every tree mutation. Scope the read lock so apply_event
        // (which writes the index → re-enters this hook for the root path)
        // can't deadlock against another thread upgrading the cache.
        let configs: Vec<TrackingConfig> = {
            let guard = self.cached_configs.read().unwrap();
            if guard.is_empty() {
                return Ok(());
            }
            guard.clone()
        };
        for cfg in configs {
            if !cfg.enabled {
                continue;
            }
            self.apply_event(&cfg.prefix, event, Some(ctx));
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "tree/root-tracker"
    }

    fn handler_pattern(&self) -> &str {
        "system/tree"
    }
}

// ---------------------------------------------------------------------------
// Entity encoders / decoders
// ---------------------------------------------------------------------------

fn decode_tracking_config(entity: &Entity) -> Option<TrackingConfig> {
    if entity.entity_type != "system/tree/tracking-config" {
        return None;
    }
    let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).ok()?;
    let map = value.as_map()?;
    let mut prefix = None;
    let mut enabled = None;
    for (k, v) in map {
        match k.as_text()? {
            "prefix" => prefix = v.as_text().map(|s| s.to_string()),
            "enabled" => enabled = v.as_bool(),
            _ => {}
        }
    }
    let prefix = prefix?;
    if !prefix.ends_with('/') {
        return None;
    }
    Some(TrackingConfig {
        prefix,
        enabled: enabled.unwrap_or(false),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use entity_store::{MemoryContentStore, MemoryLocationIndex};
    use std::collections::BTreeMap;

    fn peer_id() -> String {
        "peerTEST".to_string()
    }

    fn make_entity(et: &str, data_str: &str) -> Entity {
        let data = entity_ecf::to_ecf(&entity_ecf::text(data_str));
        Entity::new(et, data).unwrap()
    }

    fn make_tracking_config_entity(prefix: &str, enabled: bool) -> Entity {
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("enabled"), entity_ecf::bool_val(enabled)),
            (entity_ecf::text("prefix"), entity_ecf::text(prefix)),
        ]));
        Entity::new("system/tree/tracking-config", data).unwrap()
    }

    fn setup() -> (
        Arc<MemoryContentStore>,
        Arc<MemoryLocationIndex>,
        Arc<RootTrackerEngine>,
    ) {
        let cs: Arc<MemoryContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<MemoryLocationIndex> = Arc::new(MemoryLocationIndex::new());
        let engine = Arc::new(RootTrackerEngine::new(cs.clone(), li.clone(), peer_id()));
        (cs, li, engine)
    }

    /// Store an entity at a path (under the peer's qualified prefix).
    fn put_at(cs: &dyn ContentStore, li: &dyn LocationIndex, path: &str, entity: Entity) -> Hash {
        let hash = cs.put(entity).unwrap();
        li.set(path, hash);
        hash
    }

    fn synthetic_event(path: &str, new_hash: Option<Hash>, previous_hash: Option<Hash>) -> TreeChangeEvent {
        TreeChangeEvent {
            path: path.to_string(),
            hash: new_hash.or(previous_hash).unwrap_or(Hash::zero()),
            previous_hash,
            new_hash,
            change_type: if new_hash.is_some() {
                if previous_hash.is_some() {
                    entity_store::ChangeType::Modified
                } else {
                    entity_store::ChangeType::Created
                }
            } else {
                entity_store::ChangeType::Deleted
            },
            context: None,
        }
    }

    #[test]
    fn self_guard_skips_root_paths() {
        let (cs, li, engine) = setup();
        // Install a config for prefix "project/".
        let cfg = make_tracking_config_entity("project/", true);
        put_at(
            cs.as_ref(),
            li.as_ref(),
            &format!("/{}/system/tree/tracking-config/project", peer_id()),
            cfg,
        );
        engine.bootstrap();

        // Simulate an event at a root path — should be ignored entirely.
        let bogus = Hash::compute("t", b"bogus");
        let mut ctx = ExecutionContext::default();
        let event = synthetic_event(
            &format!("/{}/system/tree/root/project", peer_id()),
            Some(bogus),
            None,
        );
        // Should not panic or overwrite the root.
        engine.on_tree_change(&event, &mut ctx);

        // The existing tracked root (from bootstrap) must still decode.
        let tracked = engine.load_tracked_root("project/");
        assert!(tracked.is_some());
        // And it must differ from the bogus hash we tried to inject.
        assert_ne!(tracked.unwrap(), bogus);
    }

    #[test]
    fn tracks_put_updates_root() {
        let (cs, li, engine) = setup();
        let cfg = make_tracking_config_entity("project/", true);
        put_at(
            cs.as_ref(),
            li.as_ref(),
            &format!("/{}/system/tree/tracking-config/project", peer_id()),
            cfg,
        );
        engine.bootstrap();

        let hash_a = cs.put(make_entity("t", "a")).unwrap();
        li.set(&format!("/{}/project/src/a.rs", peer_id()), hash_a);
        let mut ctx = ExecutionContext::default();
        engine.on_tree_change(
            &synthetic_event(
                &format!("/{}/project/src/a.rs", peer_id()),
                Some(hash_a),
                None,
            ),
            &mut ctx,
        );

        let root = engine.load_tracked_root("project/").unwrap();
        let bindings = trie::collect_all_bindings(cs.as_ref(), root, "");
        assert_eq!(bindings.get("src/a.rs"), Some(&hash_a));
    }

    #[test]
    fn tracks_remove_updates_root() {
        let (cs, li, engine) = setup();
        let cfg = make_tracking_config_entity("project/", true);
        put_at(
            cs.as_ref(),
            li.as_ref(),
            &format!("/{}/system/tree/tracking-config/project", peer_id()),
            cfg,
        );

        let hash_a = cs.put(make_entity("t", "a")).unwrap();
        li.set(&format!("/{}/project/src/a.rs", peer_id()), hash_a);
        engine.bootstrap();

        // Now remove the binding and emit a Deleted event.
        li.remove(&format!("/{}/project/src/a.rs", peer_id()));
        let mut ctx = ExecutionContext::default();
        engine.on_tree_change(
            &synthetic_event(
                &format!("/{}/project/src/a.rs", peer_id()),
                None,
                Some(hash_a),
            ),
            &mut ctx,
        );

        let root = engine.load_tracked_root("project/").unwrap();
        let bindings = trie::collect_all_bindings(cs.as_ref(), root, "");
        assert!(bindings.is_empty());
    }

    #[test]
    fn config_disable_removes_tracked_root() {
        let (cs, li, engine) = setup();
        let enabled = make_tracking_config_entity("project/", true);
        let cfg_path = format!("/{}/system/tree/tracking-config/project", peer_id());
        put_at(cs.as_ref(), li.as_ref(), &cfg_path, enabled.clone());
        engine.bootstrap();
        assert!(engine.load_tracked_root("project/").is_some());

        // Replace with disabled config.
        let disabled = make_tracking_config_entity("project/", false);
        let old_hash = li.get(&cfg_path).unwrap();
        let new_hash = cs.put(disabled).unwrap();
        li.set(&cfg_path, new_hash);
        let mut ctx = ExecutionContext::default();
        engine.on_tree_change(
            &synthetic_event(&cfg_path, Some(new_hash), Some(old_hash)),
            &mut ctx,
        );
        assert!(engine.load_tracked_root("project/").is_none());
    }

    #[test]
    fn incremental_root_matches_full_rebuild() {
        let (cs, li, engine) = setup();
        let cfg = make_tracking_config_entity("project/", true);
        put_at(
            cs.as_ref(),
            li.as_ref(),
            &format!("/{}/system/tree/tracking-config/project", peer_id()),
            cfg,
        );
        engine.bootstrap();

        let paths = [
            "src/main.rs",
            "src/lib.rs",
            "Cargo.toml",
            "tests/unit.rs",
            "tests/integration.rs",
            "docs/README.md",
        ];
        let mut expected = BTreeMap::new();
        let mut ctx = ExecutionContext::default();
        for (i, rel) in paths.iter().enumerate() {
            let entity = make_entity("t", &format!("e{}", i));
            let hash = cs.put(entity).unwrap();
            let abs = format!("/{}/project/{}", peer_id(), rel);
            li.set(&abs, hash);
            engine.on_tree_change(&synthetic_event(&abs, Some(hash), None), &mut ctx);
            expected.insert(rel.to_string(), hash);
        }

        // Remove one, insert another.
        let abs_main = format!("/{}/project/src/main.rs", peer_id());
        let prev_main = li.get(&abs_main).unwrap();
        li.remove(&abs_main);
        engine.on_tree_change(
            &synthetic_event(&abs_main, None, Some(prev_main)),
            &mut ctx,
        );
        expected.remove("src/main.rs");

        let extra_entity = make_entity("t", "new");
        let extra_hash = cs.put(extra_entity).unwrap();
        let abs_extra = format!("/{}/project/src/extra.rs", peer_id());
        li.set(&abs_extra, extra_hash);
        engine.on_tree_change(
            &synthetic_event(&abs_extra, Some(extra_hash), None),
            &mut ctx,
        );
        expected.insert("src/extra.rs".to_string(), extra_hash);

        let tracked = engine.load_tracked_root("project/").unwrap();
        let from_build = trie::build_trie(cs.as_ref(), &expected).unwrap();
        assert_eq!(tracked, from_build);
    }
}
