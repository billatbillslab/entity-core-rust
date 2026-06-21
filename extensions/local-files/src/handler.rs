//! `local/files` handler — read, write, list, delete, watch.
//!
//! Spec: DOMAIN-LOCAL-FILES v1.2 §3–§4.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use entity_capability::{GrantEntry, IdScope, PathScope};
use entity_entity::EntityUri;
use entity_handler::{
    error_entity, Handler, HandlerContext, HandlerError, HandlerResult,
    STATUS_BAD_REQUEST, STATUS_FORBIDDEN, STATUS_NOT_FOUND,
};
use entity_store::{ContentStore, LocationIndex};

use crate::config::RootMapping;
use crate::operations::{handle_delete, handle_list, handle_read, handle_watch, handle_write};
use crate::types::RootConfigData;

pub const HANDLER_PATTERN: &str = "local/files";
pub(crate) const CONFIG_PATH_PREFIX: &str = "system/config/local/files/";

/// `local/files` handler. Owns the in-memory `RootMapping` map and a
/// reference to the watcher registry. The handler is constructed once
/// and registered at peer build; roots are loaded from configs in the
/// tree (`Load`) or added imperatively (`add_root`).
pub struct LocalFilesHandler {
    pub(crate) qualified_pattern: String,
    pub(crate) local_peer_id: String,
    pub(crate) content_store: Arc<dyn ContentStore>,
    pub(crate) location_index: Arc<dyn LocationIndex>,
    pub(crate) roots: Arc<RwLock<HashMap<String, RootMapping>>>,
    pub(crate) watchers: Arc<RwLock<HashMap<String, crate::watcher::Watcher>>>,
    /// v1.3 §10.2 L7 stat-cache — shared between reverse-write
    /// circuit breaker and watcher fast-path. Single cache per handler
    /// instance so a watcher-driven cache entry suppresses the
    /// reverse-write rechunk on the loop-back path and vice versa.
    pub(crate) stat_cache: Arc<crate::stat_cache::StatCache>,
}

impl LocalFilesHandler {
    pub fn new(
        local_peer_id: impl Into<String>,
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
    ) -> Self {
        let pid = local_peer_id.into();
        let qualified = format!("/{}/{}", pid, HANDLER_PATTERN);
        Self {
            qualified_pattern: qualified,
            local_peer_id: pid,
            content_store,
            location_index,
            roots: Arc::new(RwLock::new(HashMap::new())),
            watchers: Arc::new(RwLock::new(HashMap::new())),
            stat_cache: Arc::new(crate::stat_cache::StatCache::new()),
        }
    }

    /// Add a root mapping, persisting the config entity at
    /// `/{peer_id}/system/config/local/files/{name}`. Rejects overlapping
    /// prefixes.
    pub fn add_root(&self, name: &str, cfg: RootConfigData) -> Result<(), String> {
        let mapping = RootMapping::from_config(name.to_string(), &cfg)?;

        {
            let mut roots = self.roots.write().unwrap();
            for (_, existing) in roots.iter() {
                if existing.name == name {
                    continue;
                }
                if mapping.prefix.starts_with(&existing.prefix)
                    || existing.prefix.starts_with(&mapping.prefix)
                {
                    return Err(format!(
                        "prefix {:?} overlaps with existing root {:?} ({:?})",
                        mapping.prefix, existing.name, existing.prefix
                    ));
                }
            }
            roots.insert(name.to_string(), mapping);
        }

        let entity = cfg.to_entity()?;
        let hash = self
            .content_store
            .put(entity)
            .map_err(|e| format!("store config entity: {e}"))?;
        let path = format!("/{}/{}{}", self.local_peer_id, CONFIG_PATH_PREFIX, name);
        self.location_index.set(&path, hash);
        Ok(())
    }

    /// Start the filesystem watcher for `root_name`. Idempotent — replaces
    /// any existing watcher for that name. Returns Err if the root is not
    /// registered. Public so peer startup (after `load`) can wire watchers
    /// for rehydrated roots without dispatching an `EXECUTE local/files
    /// watch` (v1.3 §10.2 auto-start SHOULD).
    pub fn start_watcher(&self, root_name: &str, debounce_ms: u64) -> Result<(), String> {
        let root = self
            .roots
            .read()
            .unwrap()
            .get(root_name)
            .cloned()
            .ok_or_else(|| format!("root {root_name:?} not registered"))?;
        let watcher = crate::watcher::Watcher::start(
            root,
            debounce_ms,
            self.content_store.clone(),
            self.location_index.clone(),
            self.local_peer_id.clone(),
            self.stat_cache.clone(),
        )
        .map_err(|e| format!("start watcher: {e}"))?;
        let mut ws = self.watchers.write().unwrap();
        if let Some(old) = ws.remove(root_name) {
            old.stop();
        }
        ws.insert(root_name.to_string(), watcher);
        Ok(())
    }

    /// Rebuild root-mapping in-memory state from tree configs at
    /// `system/config/local/files/*`. Idempotent. Called once at peer
    /// startup after the content store and location index are populated
    /// (`GUIDE-RESTART-AND-PERSISTENCE.md` §3 RE-1).
    ///
    /// **v1.3 §10.2 auto-start SHOULD**: after rehydrating roots,
    /// auto-start a watcher for each one (default debounce). Without
    /// this, persisted roots are visible to read/write/list/delete but
    /// disk→tree edits never propagate — a silent-failure mode for sync
    /// deployments that the v1.3 §10.1 conditional-MUST closes on
    /// freshly-registered roots but not on rehydrated ones. Watcher
    /// startup failures are logged-not-fatal: the root mapping itself
    /// loaded fine, only the observability path is degraded.
    pub fn load(&self) {
        let prefix = format!("/{}/{}", self.local_peer_id, CONFIG_PATH_PREFIX);
        let entries = self.location_index.list(&prefix);
        let mut loaded = 0;
        for entry in entries {
            // Filter watcher-config subnamespace (system/config/local/files/watch/*).
            let rel = match entry.path.strip_prefix(&prefix) {
                Some(r) => r,
                None => continue,
            };
            if rel.is_empty() || rel.contains('/') {
                continue;
            }
            let ent = match self.content_store.get(&entry.hash) {
                Some(e) => e,
                None => continue,
            };
            if ent.entity_type != crate::types::TYPE_ROOT_CONFIG {
                continue;
            }
            let cfg = match RootConfigData::from_entity(&ent) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(name = rel, error = %e, "skip malformed root config");
                    continue;
                }
            };
            let mapping = match RootMapping::from_config(rel.to_string(), &cfg) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(name = rel, error = %e, "skip root");
                    continue;
                }
            };
            self.roots.write().unwrap().insert(rel.to_string(), mapping);
            loaded += 1;
        }
        if loaded > 0 {
            tracing::info!(loaded, "local-files: rehydrated roots from tree");
            // v1.3 §10.2 auto-start SHOULD. Snapshot names then start
            // watchers — start_watcher takes its own lock.
            let names: Vec<String> = self.roots.read().unwrap().keys().cloned().collect();
            for name in names {
                match self.start_watcher(&name, 2000) {
                    Ok(()) => tracing::info!(root = name, "watcher auto-started"),
                    Err(e) => tracing::warn!(root = name, error = %e, "watcher auto-start failed"),
                }
            }
        }
    }

    /// Look up the root mapping that owns `bare_tree_path` — longest-prefix
    /// match across the configured roots.
    pub(crate) fn find_root_mapping(&self, bare_tree_path: &str) -> Option<RootMapping> {
        let roots = self.roots.read().unwrap();
        let mut best: Option<&RootMapping> = None;
        for (_, m) in roots.iter() {
            if bare_tree_path.starts_with(&m.prefix) {
                if best.map_or(true, |b| m.prefix.len() > b.prefix.len()) {
                    best = Some(m);
                }
            }
        }
        best.cloned()
    }

    pub(crate) fn qualified(&self, bare_path: &str) -> String {
        format!("/{}/{}", self.local_peer_id, bare_path)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for LocalFilesHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            "read" => Ok(handle_read(self, ctx).await),
            "write" => Ok(handle_write(self, ctx).await),
            "list" => Ok(handle_list(self, ctx).await),
            "delete" => Ok(handle_delete(self, ctx)),
            "watch" => Ok(handle_watch(self, ctx)),
            other => Ok(bad_request(
                "unknown_operation",
                &format!("local/files does not support {other}"),
            )),
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "local-files"
    }

    fn operations(&self) -> &[&str] {
        &["read", "write", "list", "delete", "watch"]
    }

    fn internal_scope(&self) -> Option<Vec<GrantEntry>> {
        // §3.1: four grants — tree get/put on local/files/*, subscription
        // subscribe/unsubscribe, content ingest/get, tree put on
        // system/content/descriptor/* (gated per-root by publish_descriptors).
        Some(vec![
            GrantEntry {
                handlers: PathScope::new(vec!["system/tree".into()]),
                resources: PathScope::new(vec!["local/files/*".into()]),
                operations: IdScope::new(vec!["get".into(), "put".into()]),
                peers: None,
                constraints: None,
                allowances: None,
            },
            GrantEntry {
                handlers: PathScope::new(vec!["system/subscription".into()]),
                resources: PathScope::new(vec!["local/files/*".into()]),
                operations: IdScope::new(vec!["subscribe".into(), "unsubscribe".into()]),
                peers: None,
                constraints: None,
                allowances: None,
            },
            GrantEntry {
                handlers: PathScope::new(vec!["system/content".into()]),
                resources: PathScope::new(vec!["system/content".into()]),
                operations: IdScope::new(vec!["ingest".into(), "get".into()]),
                peers: None,
                constraints: None,
                allowances: None,
            },
            GrantEntry {
                handlers: PathScope::new(vec!["system/tree".into()]),
                resources: PathScope::new(vec!["system/content/descriptor/*".into()]),
                operations: IdScope::new(vec!["put".into()]),
                peers: None,
                constraints: None,
                allowances: None,
            },
        ])
    }
}

// ---------------------------------------------------------------------------
// Shared response helpers
// ---------------------------------------------------------------------------

pub(crate) fn bad_request(code: &str, message: &str) -> HandlerResult {
    HandlerResult::error(STATUS_BAD_REQUEST, error_entity(code, message))
}

pub(crate) fn not_found(code: &str, message: &str) -> HandlerResult {
    HandlerResult::error(STATUS_NOT_FOUND, error_entity(code, message))
}

pub(crate) fn forbidden(code: &str, message: &str) -> HandlerResult {
    HandlerResult::error(STATUS_FORBIDDEN, error_entity(code, message))
}

/// Extract the bare (peer-stripped) target tree path from the handler
/// context's `resource_target`. Returns `Err` when no resource is set.
pub(crate) fn resource_bare_path(ctx: &HandlerContext) -> Result<String, HandlerResult> {
    let target = ctx
        .resource_target
        .as_ref()
        .and_then(|rt| rt.targets.first().cloned())
        .ok_or_else(|| bad_request("invalid_resource", "missing resource target"))?;
    Ok(EntityUri::strip_peer_prefix(&target).to_string())
}
