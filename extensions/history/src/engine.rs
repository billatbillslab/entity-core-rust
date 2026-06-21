//! History engine — records transitions on tree mutations.
//!
//! Subscribes to TreeChangeEvent via broadcast channel and creates
//! transition entities for paths with history configuration enabled.

use std::sync::{Arc, RwLock};

use entity_entity::Entity;
use entity_hash::Hash;
use entity_store::{ChangeType, ClockState, ContentStore, ExecutionContext, LocationIndex, SyncTreeHook, TreeChangeEvent};

// ---------------------------------------------------------------------------
// HistoryEngine
// ---------------------------------------------------------------------------

pub struct HistoryEngine {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    local_peer_id_str: String,
    /// Content hash of the peer's identity entity — used as author fallback
    /// for engine-initiated writes (when EmitContext has no author).
    local_identity_hash: Hash,
    /// Pre-computed self-guard prefix to avoid format! allocation per event.
    history_path_prefix: String,
    /// Pre-computed config-path prefix `/{peer_id}/system/history/config/`.
    config_path_prefix: String,
    /// Cached configs. Populated lazily from a sentinel `None` and refreshed
    /// whenever an event under `config_path_prefix` arrives. The hot path
    /// reads this cache instead of scanning + decoding the location index per
    /// put.
    cached_configs: RwLock<Option<Vec<HistoryConfig>>>,
}

impl HistoryEngine {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
        local_identity_hash: Hash,
    ) -> Self {
        let history_path_prefix = format!("/{}/system/history/head", &local_peer_id);
        let config_path_prefix = format!("/{}/system/history/config/", &local_peer_id);
        Self {
            content_store,
            location_index,
            local_peer_id_str: local_peer_id,
            local_identity_hash,
            history_path_prefix,
            config_path_prefix,
            cached_configs: RwLock::new(None),
        }
    }

    /// Load+decode every history config from the location index.
    fn load_all_configs(&self) -> Vec<HistoryConfig> {
        let entries = self.location_index.list(&self.config_path_prefix);
        entries
            .into_iter()
            .filter_map(|e| {
                let entity = self.content_store.get(&e.hash)?;
                decode_history_config(&entity)
            })
            .collect()
    }

    /// Read-through cache: populate on first call, return cloned slice
    /// (small list — O(configured patterns), not O(tree size)).
    fn cached_configs(&self) -> Vec<HistoryConfig> {
        if let Some(ref cached) = *self.cached_configs.read().unwrap() {
            return cached.clone();
        }
        let loaded = self.load_all_configs();
        *self.cached_configs.write().unwrap() = Some(loaded.clone());
        loaded
    }

    fn invalidate_cache(&self) {
        *self.cached_configs.write().unwrap() = None;
    }

    /// Start the engine: spawn a background task that processes tree change events.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn start(self: &Arc<Self>, mut events_rx: tokio::sync::broadcast::Receiver<TreeChangeEvent>) {
        let engine = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                match events_rx.recv().await {
                    Ok(event) => engine.process_event(&event),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(skipped = n, "history engine lagged");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        tracing::debug!("history engine: broadcast closed");
                        break;
                    }
                }
            }
        });
    }

    #[cfg(target_arch = "wasm32")]
    pub fn start(self: &Arc<Self>, mut events_rx: tokio::sync::broadcast::Receiver<TreeChangeEvent>) {
        let engine = Arc::clone(self);
        wasm_bindgen_futures::spawn_local(async move {
            loop {
                match events_rx.recv().await {
                    Ok(event) => engine.process_event(&event),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(skipped = n, "history engine lagged");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        tracing::debug!("history engine: broadcast closed");
                        break;
                    }
                }
            }
        });
    }

}

// ---------------------------------------------------------------------------
// SyncTreeHook — synchronous emit consumer (SYSTEM-COMPOSITION §2.2, position 4)
// ---------------------------------------------------------------------------

impl SyncTreeHook for HistoryEngine {
    fn on_tree_change(&self, event: &TreeChangeEvent, ctx: &mut ExecutionContext)
        -> Result<(), entity_store::CascadeHalt>
    {
        if event.path.starts_with(&self.history_path_prefix) {
            return Ok(());
        }
        // Invalidate cache when a history config changes; we still want to
        // record a transition for the config write itself, so fall through.
        if event.path.starts_with(&self.config_path_prefix) {
            self.invalidate_cache();
        }
        self.process_event_with_context(event, ctx);
        Ok(())
    }

    fn name(&self) -> &str {
        "history/transition-recorder"
    }

    fn handler_pattern(&self) -> &str {
        "system/history"
    }
}

impl HistoryEngine {
    /// Process a tree change event with cascade context preserved.
    /// The ctx carries inherited cascade fields (chain_id, author, etc.)
    /// and per-write fields set by the dispatcher to history's values.
    fn process_event_with_context(&self, event: &TreeChangeEvent, ctx: &ExecutionContext) {
        self.process_event_inner(event, Some(ctx));
    }

    /// Process a single tree change event (legacy path without cascade context).
    pub fn process_event(&self, event: &TreeChangeEvent) {
        self.process_event_inner(event, None);
    }

    fn process_event_inner(&self, event: &TreeChangeEvent, cascade_ctx: Option<&ExecutionContext>) {
        // §3.2 — recursion prevention: skip local system/history/ paths
        if is_local_history_path(&event.path, &self.local_peer_id_str) {
            return;
        }

        // Fast path: nothing to do if no history configs are registered.
        let configs = self.cached_configs();
        if configs.is_empty() {
            return;
        }

        // Find matching history config (most-specific pattern wins).
        let config = match select_matching_config(&configs, &event.path, &self.local_peer_id_str) {
            Some(c) => c,
            None => return,
        };

        if !config.enabled {
            return;
        }

        // Map change type to event string
        let event_name = match event.change_type {
            ChangeType::Created => "created",
            ChangeType::Modified => "updated",
            ChangeType::Deleted => "deleted",
        };

        // Check if this event type is in the configured events list
        if !config.events.iter().any(|e| e == event_name) {
            return;
        }

        // Build and store transition
        let head_pointer_path = format!(
            "/{}/system/history/head{}",
            self.local_peer_id_str, event.path
        );
        let previous_transition_hash = self.location_index.get(&head_pointer_path);

        // Immutable cascade fields come from the event snapshot (set before hooks).
        // Extension-contributed fields (clock) come from cascade_ctx (the live
        // mutable context updated by earlier hooks — clock at position 2).
        let ectx = event.context.as_ref();
        let cap = ectx.and_then(|c| c.capability);
        let caller_cap = ectx.and_then(|c| c.caller_capability);
        let caller_capability = match (cap, caller_cap) {
            (Some(c), Some(cc)) if c != cc => Some(cc),
            _ => None,
        };
        let transition = build_transition_entity(&TransitionFields {
            path: &event.path,
            event: event_name,
            hash: event.new_hash,
            previous_hash: event.previous_hash,
            author: ectx.and_then(|c| c.author).or(Some(self.local_identity_hash)),
            capability: cap,
            caller_capability,
            handler: ectx.and_then(|c| c.handler_pattern.as_deref()),
            operation: ectx.and_then(|c| c.operation.as_deref()),
            chain_id: ectx.and_then(|c| c.chain_id.as_deref()),
            parent_chain_id: ectx.and_then(|c| c.parent_chain_id.as_deref()),
            clock: cascade_ctx.and_then(|c| c.clock.as_ref()),
            previous: previous_transition_hash,
        });

        match self.content_store.put(transition) {
            Ok(transition_hash) => {
                // Update head pointer with cascade context preserved
                if let Some(ctx) = cascade_ctx {
                    let _cascade = self.location_index.set_with_context(
                        &head_pointer_path,
                        transition_hash,
                        ctx.clone(),
                    );
                } else {
                    self.location_index.set(&head_pointer_path, transition_hash);
                }
                tracing::trace!(
                    path = %event.path,
                    event = event_name,
                    transition_hash = %transition_hash,
                    "history: recorded transition"
                );
            }
            Err(e) => {
                tracing::warn!(
                    path = %event.path,
                    error = %e,
                    "history: failed to store transition"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Transition entity builder
// ---------------------------------------------------------------------------

struct TransitionFields<'a> {
    path: &'a str,
    event: &'a str,
    hash: Option<Hash>,
    previous_hash: Option<Hash>,
    author: Option<Hash>,
    capability: Option<Hash>,
    /// Included only when it differs from capability (W6).
    caller_capability: Option<Hash>,
    handler: Option<&'a str>,
    operation: Option<&'a str>,
    chain_id: Option<&'a str>,
    parent_chain_id: Option<&'a str>,
    clock: Option<&'a ClockState>,
    previous: Option<Hash>,
}

fn build_transition_entity(f: &TransitionFields<'_>) -> Entity {
    let now_ms = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let mut fields = vec![
        (entity_ecf::text("path"), entity_ecf::text(f.path)),
        (entity_ecf::text("event"), entity_ecf::text(f.event)),
    ];

    if let Some(h) = f.hash {
        fields.push((
            entity_ecf::text("hash"),
            entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
        ));
    }
    if let Some(h) = f.previous_hash {
        fields.push((
            entity_ecf::text("previous_hash"),
            entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
        ));
    }

    let author_bytes = f.author.unwrap_or(Hash::zero()).to_bytes().to_vec();
    fields.push((
        entity_ecf::text("author"),
        entity_ecf::Value::Bytes(author_bytes),
    ));

    let cap_bytes = f.capability.unwrap_or(Hash::zero()).to_bytes().to_vec();
    fields.push((
        entity_ecf::text("capability"),
        entity_ecf::Value::Bytes(cap_bytes),
    ));

    // W6: caller_capability — only when it differs from capability
    if let Some(cc) = f.caller_capability {
        fields.push((
            entity_ecf::text("caller_capability"),
            entity_ecf::Value::Bytes(cc.to_bytes().to_vec()),
        ));
    }

    fields.push((
        entity_ecf::text("handler"),
        entity_ecf::text(f.handler.unwrap_or("")),
    ));

    fields.push((
        entity_ecf::text("operation"),
        entity_ecf::text(f.operation.unwrap_or("")),
    ));

    fields.push((
        entity_ecf::text("timestamp"),
        entity_ecf::integer(now_ms as i64),
    ));

    if let Some(cid) = f.chain_id {
        fields.push((entity_ecf::text("chain_id"), entity_ecf::text(cid)));
    }

    if let Some(pcid) = f.parent_chain_id {
        fields.push((entity_ecf::text("parent_chain_id"), entity_ecf::text(pcid)));
    }

    // F7: structured clock state (system/clock/state)
    if let Some(clock) = &f.clock {
        let mut clock_fields = vec![
            (entity_ecf::text("mode"), entity_ecf::text(&clock.mode)),
        ];
        if let Some(ts) = clock.timestamp {
            clock_fields.push((
                entity_ecf::text("timestamp"),
                entity_ecf::Value::Map(vec![
                    (entity_ecf::text("ms"), entity_ecf::integer(ts as i64)),
                ]),
            ));
        }
        if let Some(ref logical) = clock.logical {
            clock_fields.push((
                entity_ecf::text("logical"),
                entity_ecf::Value::Map(vec![
                    (entity_ecf::text("counter"), entity_ecf::integer(logical.counter as i64)),
                ]),
            ));
        }
        if let Some(ref vector) = clock.vector {
            let entries: Vec<_> = vector.iter()
                .map(|(k, v)| (entity_ecf::text(k), entity_ecf::integer(*v as i64)))
                .collect();
            clock_fields.push((
                entity_ecf::text("vector"),
                entity_ecf::Value::Map(vec![
                    (entity_ecf::text("entries"), entity_ecf::Value::Map(entries)),
                ]),
            ));
        }
        if let Some(ref hlc) = clock.hlc {
            clock_fields.push((
                entity_ecf::text("hlc"),
                entity_ecf::Value::Map(vec![
                    (entity_ecf::text("logical"), entity_ecf::integer(hlc.logical as i64)),
                    (entity_ecf::text("peer"), entity_ecf::Value::Bytes(hlc.peer.to_bytes().to_vec())),
                    (entity_ecf::text("physical"), entity_ecf::integer(hlc.physical as i64)),
                ]),
            ));
        }
        fields.push((
            entity_ecf::text("clock"),
            entity_ecf::Value::Map(clock_fields),
        ));
    }

    if let Some(prev) = f.previous {
        fields.push((
            entity_ecf::text("previous"),
            entity_ecf::Value::Bytes(prev.to_bytes().to_vec()),
        ));
    }

    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
    Entity::new(entity_types::TYPE_HISTORY_TRANSITION, data)
        .expect("transition entity creation should not fail")
}

// ---------------------------------------------------------------------------
// History configuration helpers
// ---------------------------------------------------------------------------

/// Parsed history configuration.
#[derive(Debug, Clone)]
pub struct HistoryConfig {
    pub pattern: String,
    pub enabled: bool,
    pub events: Vec<String>,
    pub max_depth: Option<u64>,
}

impl Default for HistoryConfig {
    fn default() -> Self {
        Self {
            pattern: String::new(),
            enabled: false,
            events: vec![
                "created".to_string(),
                "updated".to_string(),
                "deleted".to_string(),
            ],
            max_depth: None,
        }
    }
}

/// Check if a path is in the local peer's system/history/ namespace (§3.2).
pub fn is_local_history_path(path: &str, local_peer_id: &str) -> bool {
    let prefix = format!("/{}/", local_peer_id);
    if !path.starts_with(&prefix) {
        return false;
    }
    let suffix = &path[prefix.len()..];
    // Only skip head pointer paths (where the engine writes transitions).
    // Config paths (system/history/config/*) SHOULD be recorded — they're
    // operationally significant and written by handlers, not the engine.
    suffix.starts_with("system/history/head")
}

/// Canonicalize a history config pattern (spec §2.2).
///
/// Different from core `canonicalize`: peer-wildcard patterns like `*/project/*`
/// pass through unchanged.
pub fn canonicalize_pattern(pattern: &str, local_peer_id: &str) -> String {
    if pattern.starts_with('/') {
        return pattern.to_string(); // already absolute
    }
    // Check first segment — if it's `*`, it's a peer wildcard
    if let Some(first) = pattern.split('/').next() {
        if first == "*" {
            return pattern.to_string(); // peer wildcard — pass through
        }
    }
    // Short-form → prepend local peer namespace
    format!("/{}/{}", local_peer_id, pattern)
}

/// Compute pattern specificity for history config matching (spec §2.2).
///
/// Higher value = more specific. Rules:
/// 1. Count literal (non-wildcard) segments
/// 2. Explicit peer ID beats wildcard peer at same depth
fn pattern_specificity(pattern: &str) -> u32 {
    let segments: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let mut score: u32 = 0;
    for seg in &segments {
        if *seg != "*" {
            score += 2; // literal segment
        } else {
            score += 1; // wildcard segment (less specific)
        }
    }
    score
}

/// Check if a path matches a pattern (simplified §5.4 pattern matching).
fn matches_history_pattern(path: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    // Peer wildcard: `*/rest` matches any peer prefix
    if let Some(rest) = pattern.strip_prefix("*/") {
        // Path must be /{peer_id}/rest or /{peer_id}/rest/...
        if let Some(after_peer) = path.strip_prefix('/') {
            if let Some(slash_idx) = after_peer.find('/') {
                let after_peer_prefix = &after_peer[slash_idx + 1..];
                if let Some(prefix) = rest.strip_suffix("/*") {
                    return after_peer_prefix.starts_with(prefix)
                        && (after_peer_prefix.len() == prefix.len()
                            || after_peer_prefix.as_bytes().get(prefix.len()) == Some(&b'/'));
                }
                return after_peer_prefix == rest
                    || after_peer_prefix.starts_with(&format!("{}/", rest));
            }
        }
        return false;
    }
    // Subtree pattern: `prefix/*`
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return path.starts_with(prefix)
            && path.len() > prefix.len()
            && path.as_bytes()[prefix.len()] == b'/';
    }
    // Exact match
    path == pattern
}

/// Find the most specific history configuration matching a path.
pub fn find_history_config(
    path: &str,
    content_store: &dyn ContentStore,
    location_index: &dyn LocationIndex,
    local_peer_id: &str,
) -> Option<HistoryConfig> {
    let config_prefix = format!("/{}/system/history/config/", local_peer_id);
    let entries = location_index.list(&config_prefix);

    let configs: Vec<HistoryConfig> = entries
        .into_iter()
        .filter_map(|e| {
            let entity = content_store.get(&e.hash)?;
            decode_history_config(&entity)
        })
        .collect();

    select_matching_config(&configs, path, local_peer_id)
}

/// Pick the most-specific matching config from an already-decoded list.
/// Used by the engine's hot path against its cached configs.
pub fn select_matching_config(
    configs: &[HistoryConfig],
    path: &str,
    local_peer_id: &str,
) -> Option<HistoryConfig> {
    let mut best: Option<(&HistoryConfig, u32)> = None;
    for cfg in configs {
        let canonical = canonicalize_pattern(&cfg.pattern, local_peer_id);
        if !matches_history_pattern(path, &canonical) {
            continue;
        }
        let specificity = pattern_specificity(&canonical);
        if best.as_ref().is_none_or(|(_, s)| specificity > *s) {
            best = Some((cfg, specificity));
        }
    }
    best.map(|(c, _)| c.clone())
}

/// Decode a history config entity's data.
fn decode_history_config(entity: &Entity) -> Option<HistoryConfig> {
    if entity.entity_type != entity_types::TYPE_HISTORY_CONFIG {
        return None;
    }

    let val: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).ok()?;
    let map = val.as_map()?;

    let pattern = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("pattern"))
        .and_then(|(_, v)| v.as_text())
        .unwrap_or("")
        .to_string();

    let enabled = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("enabled"))
        .and_then(|(_, v)| v.as_bool())
        .unwrap_or(false);

    let events = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("events"))
        .and_then(|(_, v)| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_text().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_else(|| {
            vec![
                "created".to_string(),
                "updated".to_string(),
                "deleted".to_string(),
            ]
        });

    let max_depth = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("max_depth"))
        .and_then(|(_, v)| v.as_integer())
        .and_then(|i| u64::try_from(i).ok());

    Some(HistoryConfig {
        pattern,
        enabled,
        events,
        max_depth,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use entity_store::{EmitContext, MemoryContentStore, MemoryLocationIndex};

    fn test_peer_id() -> String {
        "TestPeerABCDEFGH1234567890abcdefghijklmnop123".to_string()
    }

    fn make_stores() -> (Arc<MemoryContentStore>, Arc<MemoryLocationIndex>) {
        (
            Arc::new(MemoryContentStore::new()),
            Arc::new(MemoryLocationIndex::new()),
        )
    }

    fn test_identity_hash() -> Hash {
        Hash::compute("system/peer", b"test-peer-identity")
    }

    fn make_engine(
        store: Arc<MemoryContentStore>,
        li: Arc<MemoryLocationIndex>,
    ) -> Arc<HistoryEngine> {
        Arc::new(HistoryEngine::new(
            store,
            li,
            test_peer_id(),
            test_identity_hash(),
        ))
    }

    fn store_config(
        store: &dyn ContentStore,
        li: &dyn LocationIndex,
        name: &str,
        pattern: &str,
        enabled: bool,
    ) {
        let peer_id = test_peer_id();
        let mut fields = vec![
            (entity_ecf::text("pattern"), entity_ecf::text(pattern)),
            (
                entity_ecf::text("enabled"),
                entity_ecf::bool_val(enabled),
            ),
        ];
        // Default events
        fields.push((
            entity_ecf::text("events"),
            entity_ecf::Value::Array(vec![
                entity_ecf::text("created"),
                entity_ecf::text("updated"),
                entity_ecf::text("deleted"),
            ]),
        ));
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
        let entity = Entity::new(entity_types::TYPE_HISTORY_CONFIG, data).unwrap();
        let hash = store.put(entity).unwrap();
        li.set(
            &format!("/{}/system/history/config/{}", peer_id, name),
            hash,
        );
    }

    fn make_event(path: &str, change_type: ChangeType) -> TreeChangeEvent {
        let hash = Hash::compute("test", b"data");
        TreeChangeEvent {
            path: path.to_string(),
            hash,
            previous_hash: if change_type == ChangeType::Modified {
                Some(Hash::compute("test", b"old"))
            } else {
                None
            },
            new_hash: if change_type == ChangeType::Deleted {
                None
            } else {
                Some(hash)
            },
            change_type,
            context: Some(EmitContext {
                author: Some(Hash::compute("identity", b"alice")),
                capability: Some(Hash::compute("cap", b"token")),
                caller_capability: Some(Hash::compute("cap", b"token")),
                handler_pattern: Some(format!("/{}/system/tree", test_peer_id())),
                operation: Some("put".to_string()),
                request_id: Some("req-1".to_string()),
                chain_id: None,
                ..Default::default()
            }),
        }
    }

    // --- is_local_history_path ---

    #[test]
    fn test_local_history_path_detected() {
        let pid = test_peer_id();
        // Head pointer paths: engine writes these → must skip (recursion prevention)
        assert!(is_local_history_path(
            &format!("/{}/system/history/head/foo", pid),
            &pid
        ));
        assert!(is_local_history_path(
            &format!("/{}/system/history/head/app/data/x", pid),
            &pid
        ));
        // Config paths: written by handlers, not engine → should NOT be skipped
        // (config changes are operationally significant and should be recorded)
        assert!(!is_local_history_path(
            &format!("/{}/system/history/config/all", pid),
            &pid
        ));
    }

    #[test]
    fn test_non_history_path() {
        let pid = test_peer_id();
        assert!(!is_local_history_path(
            &format!("/{}/system/tree", pid),
            &pid
        ));
        assert!(!is_local_history_path("system/history/head/foo", &pid));
    }

    #[test]
    fn test_remote_history_path_not_excluded() {
        let pid = test_peer_id();
        assert!(!is_local_history_path(
            "/OtherPeer123456789012345678901234567890123456/system/history/head/foo",
            &pid
        ));
    }

    // --- canonicalize_pattern ---

    #[test]
    fn test_canonicalize_absolute() {
        let pid = test_peer_id();
        assert_eq!(
            canonicalize_pattern("/peerA/project/*", &pid),
            "/peerA/project/*"
        );
    }

    #[test]
    fn test_canonicalize_short_form() {
        let pid = test_peer_id();
        assert_eq!(
            canonicalize_pattern("project/*", &pid),
            format!("/{}/project/*", pid)
        );
    }

    #[test]
    fn test_canonicalize_peer_wildcard() {
        let pid = test_peer_id();
        assert_eq!(
            canonicalize_pattern("*/project/*", &pid),
            "*/project/*"
        );
    }

    // --- pattern_specificity ---

    #[test]
    fn test_specificity_ordering() {
        // More literal segments = more specific
        assert!(pattern_specificity("/peer/project/readme") > pattern_specificity("/peer/project/*"));
        assert!(pattern_specificity("/peer/project/*") > pattern_specificity("*/project/*"));
        assert!(pattern_specificity("/peer/*") > pattern_specificity("*"));
    }

    // --- matches_history_pattern ---

    #[test]
    fn test_matches_wildcard_all() {
        assert!(matches_history_pattern("/peer/any/path", "*"));
    }

    #[test]
    fn test_matches_subtree() {
        let pid = test_peer_id();
        let pattern = format!("/{}/project/*", pid);
        assert!(matches_history_pattern(
            &format!("/{}/project/readme", pid),
            &pattern
        ));
        assert!(!matches_history_pattern(
            &format!("/{}/other/file", pid),
            &pattern
        ));
        // Exact prefix without child should not match subtree
        assert!(!matches_history_pattern(
            &format!("/{}/project", pid),
            &pattern
        ));
    }

    #[test]
    fn test_matches_exact() {
        let pid = test_peer_id();
        let path = format!("/{}/project/readme", pid);
        assert!(matches_history_pattern(&path, &path));
        assert!(!matches_history_pattern(
            &format!("/{}/project/other", pid),
            &path
        ));
    }

    #[test]
    fn test_matches_peer_wildcard() {
        assert!(matches_history_pattern(
            "/peerA/project/readme",
            "*/project/*"
        ));
        assert!(matches_history_pattern(
            "/peerB/project/sub/file",
            "*/project/*"
        ));
        assert!(!matches_history_pattern(
            "/peerA/other/readme",
            "*/project/*"
        ));
    }

    // --- process_event integration ---

    #[test]
    fn test_process_event_creates_transition() {
        let pid = test_peer_id();
        let (store, li) = make_stores();
        let engine = make_engine(store.clone(), li.clone());

        store_config(&*store, &*li, "all", "docs/*", true);

        let event = make_event(&format!("/{}/docs/readme", pid), ChangeType::Created);
        engine.process_event(&event);

        // Verify head pointer was created
        let head_path = format!("/{}/system/history/head/{}/docs/readme", pid, pid);
        assert!(li.get(&head_path).is_some(), "head pointer should exist");

        // Verify transition entity
        let head_hash = li.get(&head_path).unwrap();
        let transition = store.get(&head_hash).unwrap();
        assert_eq!(transition.entity_type, entity_types::TYPE_HISTORY_TRANSITION);

        // Decode and verify fields
        let val: ciborium::Value =
            ciborium::from_reader(transition.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let event_field = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("event"))
            .unwrap()
            .1
            .as_text()
            .unwrap();
        assert_eq!(event_field, "created");
    }

    #[test]
    fn test_recursion_prevention() {
        let pid = test_peer_id();
        let (store, li) = make_stores();
        let engine = make_engine(store.clone(), li.clone());

        store_config(&*store, &*li, "all", "*", true);

        // Event on a system/history/ path should be skipped
        let event = make_event(
            &format!("/{}/system/history/head/docs/readme", pid),
            ChangeType::Created,
        );
        engine.process_event(&event);

        // No head pointer for this path
        let head_path = format!(
            "/{}/system/history/head/{}/system/history/head/docs/readme",
            pid, pid
        );
        assert!(li.get(&head_path).is_none());
    }

    #[test]
    fn test_transition_chaining() {
        let pid = test_peer_id();
        let (store, li) = make_stores();
        let engine = make_engine(store.clone(), li.clone());

        store_config(&*store, &*li, "all", "docs/*", true);

        let path = format!("/{}/docs/readme", pid);
        let head_path = format!("/{}/system/history/head/{}/docs/readme", pid, pid);

        // First event
        let event1 = make_event(&path, ChangeType::Created);
        engine.process_event(&event1);
        let first_hash = li.get(&head_path).unwrap();

        // Second event
        let event2 = make_event(&path, ChangeType::Modified);
        engine.process_event(&event2);
        let second_hash = li.get(&head_path).unwrap();

        assert_ne!(first_hash, second_hash, "head should update");

        // Verify chaining: second transition should have previous = first
        let second_transition = store.get(&second_hash).unwrap();
        let val: ciborium::Value =
            ciborium::from_reader(second_transition.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let prev = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("previous"))
            .unwrap()
            .1
            .as_bytes()
            .unwrap();
        let prev_hash = Hash::from_bytes(prev).unwrap();
        assert_eq!(prev_hash, first_hash);
    }

    #[test]
    fn test_event_type_filtering() {
        let pid = test_peer_id();
        let (store, li) = make_stores();
        let engine = make_engine(store.clone(), li.clone());

        // Config that only tracks "created" events
        let config_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("pattern"), entity_ecf::text("docs/*")),
            (entity_ecf::text("enabled"), entity_ecf::bool_val(true)),
            (
                entity_ecf::text("events"),
                entity_ecf::Value::Array(vec![entity_ecf::text("created")]),
            ),
        ]));
        let config_entity =
            Entity::new(entity_types::TYPE_HISTORY_CONFIG, config_data).unwrap();
        let config_hash = store.put(config_entity).unwrap();
        li.set(
            &format!("/{}/system/history/config/docs-created-only", pid),
            config_hash,
        );

        let path = format!("/{}/docs/readme", pid);
        let head_path = format!("/{}/system/history/head/{}/docs/readme", pid, pid);

        // Modified event should be skipped
        let event = make_event(&path, ChangeType::Modified);
        engine.process_event(&event);
        assert!(li.get(&head_path).is_none(), "modified should be filtered");

        // Created event should be recorded
        let event = make_event(&path, ChangeType::Created);
        engine.process_event(&event);
        assert!(li.get(&head_path).is_some(), "created should be recorded");
    }

    #[test]
    fn test_no_config_no_recording() {
        let pid = test_peer_id();
        let (store, li) = make_stores();
        let engine = make_engine(store.clone(), li.clone());

        // No config stored — events should not be recorded
        let event = make_event(&format!("/{}/docs/readme", pid), ChangeType::Created);
        engine.process_event(&event);

        let head_path = format!("/{}/system/history/head/{}/docs/readme", pid, pid);
        assert!(li.get(&head_path).is_none());
    }

    #[test]
    fn test_context_fields_preserved() {
        let pid = test_peer_id();
        let (store, li) = make_stores();
        let engine = make_engine(store.clone(), li.clone());

        store_config(&*store, &*li, "all", "docs/*", true);

        let author_hash = Hash::compute("identity", b"alice");
        let cap_hash = Hash::compute("cap", b"token");
        let handler_pattern = format!("/{}/system/tree", pid);

        let event = TreeChangeEvent {
            path: format!("/{}/docs/readme", pid),
            hash: Hash::compute("test", b"data"),
            previous_hash: None,
            new_hash: Some(Hash::compute("test", b"data")),
            change_type: ChangeType::Created,
            context: Some(EmitContext {
                author: Some(author_hash),
                capability: Some(cap_hash),
                caller_capability: Some(cap_hash),
                handler_pattern: Some(handler_pattern.clone()),
                operation: Some("put".to_string()),
                request_id: Some("req-42".to_string()),
                chain_id: None,
                ..Default::default()
            }),
        };
        engine.process_event(&event);

        let head_path = format!("/{}/system/history/head/{}/docs/readme", pid, pid);
        let head_hash = li.get(&head_path).unwrap();
        let transition = store.get(&head_hash).unwrap();

        let val: ciborium::Value =
            ciborium::from_reader(transition.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();

        // Verify author
        let author_bytes = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("author"))
            .unwrap()
            .1
            .as_bytes()
            .unwrap();
        assert_eq!(Hash::from_bytes(author_bytes).unwrap(), author_hash);

        // Verify capability
        let cap_bytes = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("capability"))
            .unwrap()
            .1
            .as_bytes()
            .unwrap();
        assert_eq!(Hash::from_bytes(cap_bytes).unwrap(), cap_hash);

        // Verify handler
        let handler_val = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("handler"))
            .unwrap()
            .1
            .as_text()
            .unwrap();
        assert_eq!(handler_val, handler_pattern);

        // Verify operation
        let op_val = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("operation"))
            .unwrap()
            .1
            .as_text()
            .unwrap();
        assert_eq!(op_val, "put");
    }
}
