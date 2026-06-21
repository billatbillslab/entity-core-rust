//! Clock engine — advances clock state on tree writes.
//!
//! Listens on a broadcast channel for tree change events and advances
//! the clock for non-clock paths per spec §4.2.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use entity_entity::Entity;
use entity_hash::Hash;
use entity_store::{ClockHlc, ClockLogical, ClockState, ContentStore, ExecutionContext, LocationIndex, SyncTreeHook, TreeChangeEvent};

use crate::{decode_counter, decode_hlc, decode_vector_entries, read_config, system_clock_ms, ClockConfig};

// Platform-aware task spawning: tokio::spawn on native, wasm_bindgen_futures::spawn_local on WASM.
// On native, the start() method uses tokio::spawn directly for JoinHandle return type,
// so this function is only called from the WASM cfg path.
#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)]
fn spawn_task<F: std::future::Future<Output = ()> + Send + 'static>(f: F) {
    tokio::spawn(f);
}
#[cfg(target_arch = "wasm32")]
fn spawn_task<F: std::future::Future<Output = ()> + 'static>(f: F) {
    wasm_bindgen_futures::spawn_local(f);
}

// ---------------------------------------------------------------------------
// Constants (§8)
// ---------------------------------------------------------------------------

/// Default clock mode when no configuration is present.
pub const DEFAULT_CLOCK_MODE: &str = "wall";

/// Default tick interval in milliseconds.
pub const DEFAULT_TICK_INTERVAL_MS: u64 = 1000;

/// Maximum entries in a vector clock before eviction.
pub const MAX_VECTOR_ENTRIES: usize = 1024;

/// Maximum allowed HLC physical drift from wall clock (ms).
pub const MAX_HLC_DRIFT_MS: u64 = 60000;

// ---------------------------------------------------------------------------
// ClockEngine
// ---------------------------------------------------------------------------

/// The clock engine that advances clock state on tree writes.
pub struct ClockEngine {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    local_peer_id: Hash,
    local_peer_id_str: String,
    /// Pre-computed self-guard prefix to avoid format! allocation per event.
    clock_path_prefix: String,
    /// Pre-computed config path `/{peer_id}/system/clock/config` for cache
    /// invalidation.
    clock_config_path: String,
    /// Cached config. Populated lazily; refreshed when an event arrives at
    /// `clock_config_path`. Replaces the per-put `read_config()` index lookups
    /// (previously called twice per `on_tree_change`).
    cached_config: RwLock<Option<ClockConfig>>,
    /// Cascade context set during sync hook processing.
    /// Used by store methods to call set_with_context instead of plain set.
    active_ctx: std::sync::Mutex<Option<ExecutionContext>>,
}

impl ClockEngine {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: Hash,
        local_peer_id_str: String,
    ) -> Self {
        let clock_path_prefix = format!("/{}/system/clock/", &local_peer_id_str);
        let clock_config_path = format!("/{}/system/clock/config", &local_peer_id_str);
        Self {
            content_store,
            location_index,
            local_peer_id,
            local_peer_id_str,
            clock_path_prefix,
            clock_config_path,
            cached_config: RwLock::new(None),
            active_ctx: std::sync::Mutex::new(None),
        }
    }

    /// Read-through cache for the clock config.
    fn cached_config(&self) -> ClockConfig {
        if let Some(ref cached) = *self.cached_config.read().unwrap() {
            return cached.clone();
        }
        let loaded = read_config(
            self.content_store.as_ref(),
            self.location_index.as_ref(),
            &self.local_peer_id_str,
        );
        *self.cached_config.write().unwrap() = Some(loaded.clone());
        loaded
    }

    fn invalidate_config_cache(&self) {
        *self.cached_config.write().unwrap() = None;
    }

    /// Start the event processing loop in a background task.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn start(
        self: &Arc<Self>,
        mut events_rx: tokio::sync::broadcast::Receiver<TreeChangeEvent>,
    ) -> tokio::task::JoinHandle<()> {
        let engine = self.clone();
        tokio::spawn(async move {
            loop {
                match events_rx.recv().await {
                    Ok(event) => {
                        engine.process_event(&event);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("clock engine lagged, missed {} events", n);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        tracing::info!("clock engine: event channel closed");
                        break;
                    }
                }
            }
        })
    }

    /// Start the event processing loop in a background task (WASM).
    #[cfg(target_arch = "wasm32")]
    pub fn start(
        self: &Arc<Self>,
        mut events_rx: tokio::sync::broadcast::Receiver<TreeChangeEvent>,
    ) {
        let engine = self.clone();
        spawn_task(async move {
            loop {
                match events_rx.recv().await {
                    Ok(event) => {
                        engine.process_event(&event);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("clock engine lagged, missed {} events", n);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        tracing::info!("clock engine: event channel closed");
                        break;
                    }
                }
            }
        });
    }

    /// Process a single tree change event (legacy broadcast path).
    fn process_event(&self, event: &TreeChangeEvent) {
        // Config path → invalidate cache.
        if event.path == self.clock_config_path {
            self.invalidate_config_cache();
            return;
        }
        // §4.3: Clock writes do not advance the clock
        if event.path.starts_with(&self.clock_path_prefix) {
            return;
        }
        tracing::trace!(path = %event.path, "clock engine: advancing clock");
        let config = self.cached_config();
        self.advance_clock(&config);
    }

}

// ---------------------------------------------------------------------------
// SyncTreeHook — synchronous emit consumer (SYSTEM-COMPOSITION §2.2, position 2+3)
// ---------------------------------------------------------------------------

impl SyncTreeHook for ClockEngine {
    fn on_tree_change(&self, event: &TreeChangeEvent, ctx: &mut ExecutionContext)
        -> Result<(), entity_store::CascadeHalt>
    {
        // Writes under `/{peer}/system/clock/` (incl. our own state writes) do
        // not advance the clock (§4.3). The config path lives there too — but
        // we need to invalidate the cache when it changes.
        if event.path == self.clock_config_path {
            self.invalidate_config_cache();
            return Ok(());
        }
        if event.path.starts_with(&self.clock_path_prefix) {
            return Ok(());
        }
        // Read config once, reuse for advance + state build.
        let config = self.cached_config();
        self.advance_clock_with_context(ctx, &config);
        ctx.clock = Some(self.build_clock_state(&config));
        Ok(())
    }

    fn name(&self) -> &str {
        "clock/advance"
    }

    fn handler_pattern(&self) -> &str {
        "system/clock"
    }
}

impl ClockEngine {
    /// Advance the clock per §4.2 (context-aware — preserves cascade context).
    fn advance_clock_with_context(&self, ctx: &ExecutionContext, config: &ClockConfig) {
        // Store context so emit_set() can use set_with_context
        *self.active_ctx.lock().unwrap() = Some(ctx.clone());
        self.advance_clock(config);
        *self.active_ctx.lock().unwrap() = None;
    }

    /// Advance the clock per §4.2.
    fn advance_clock(&self, config: &ClockConfig) {
        if config.mode == "wall" {
            return;
        }

        let current_counter = self.read_logical_counter();
        let new_counter = current_counter + 1;
        self.store_logical(new_counter);

        if config.mode == "vector" {
            self.advance_vector(new_counter);
        }

        if config.mode == "hlc" {
            self.advance_hlc();
        }
    }

    /// Build the full structured ClockState for the execution context (F6).
    fn build_clock_state(&self, config: &ClockConfig) -> ClockState {
        let mut state = ClockState {
            mode: config.mode.clone(),
            timestamp: None,
            logical: None,
            vector: None,
            hlc: None,
        };
        if config.mode == "wall" || config.wall_clock {
            state.timestamp = Some(system_clock_ms());
        }
        if config.mode == "logical" || config.mode == "vector" || config.mode == "hlc" {
            state.logical = Some(ClockLogical {
                counter: self.read_logical_counter(),
            });
        }
        if config.mode == "vector" {
            state.vector = Some(self.read_vector_entries());
        }
        if config.mode == "hlc" {
            let hlc = self.read_hlc();
            state.hlc = Some(ClockHlc {
                physical: hlc.physical,
                logical: hlc.logical,
                peer: hlc.peer,
            });
        }
        state
    }

    /// Write to location index, using active cascade context if set.
    fn emit_set(&self, path: &str, hash: Hash) {
        let ctx = self.active_ctx.lock().unwrap().clone();
        if let Some(ctx) = ctx {
            let _cascade = self.location_index.set_with_context(path, hash, ctx);
        } else {
            self.location_index.set(path, hash);
        }
    }

    fn read_logical_counter(&self) -> u64 {
        let path = format!("/{}/system/clock/logical", self.local_peer_id_str);
        let hash = match self.location_index.get(&path) {
            Some(h) => h,
            None => return 0,
        };
        let entity = match self.content_store.get(&hash) {
            Some(e) => e,
            None => return 0,
        };
        decode_counter(&entity.data).unwrap_or(0)
    }

    fn store_logical(&self, counter: u64) {
        let path = format!("/{}/system/clock/logical", self.local_peer_id_str);
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("counter"),
            entity_ecf::integer(counter as i64),
        )]));
        let entity = match Entity::new(&path, data) {
            Ok(e) => e,
            Err(e) => {
                tracing::error!("failed to create logical clock entity: {}", e);
                return;
            }
        };
        match self.content_store.put(entity) {
            Ok(hash) => self.emit_set(&path, hash),
            Err(e) => tracing::error!("failed to store logical clock: {}", e),
        }
    }

    fn advance_vector(&self, new_counter: u64) {
        let mut entries = self.read_vector_entries();

        // Update local peer entry with new counter
        let peer_key = self.local_peer_id.to_string();
        entries.insert(peer_key, new_counter);

        // Evict oldest if exceeding MAX_VECTOR_ENTRIES (§7.3)
        while entries.len() > MAX_VECTOR_ENTRIES {
            if let Some(min_key) = entries
                .iter()
                .min_by_key(|(_, v)| *v)
                .map(|(k, _)| k.clone())
            {
                entries.remove(&min_key);
            } else {
                break;
            }
        }

        self.store_vector(&entries);
    }

    fn read_vector_entries(&self) -> HashMap<String, u64> {
        let path = format!("/{}/system/clock/vector", self.local_peer_id_str);
        let hash = match self.location_index.get(&path) {
            Some(h) => h,
            None => return HashMap::new(),
        };
        let entity = match self.content_store.get(&hash) {
            Some(e) => e,
            None => return HashMap::new(),
        };
        decode_vector_entries(&entity.data).unwrap_or_default()
    }

    fn store_vector(&self, entries: &HashMap<String, u64>) {
        let path = format!("/{}/system/clock/vector", self.local_peer_id_str);
        let entry_pairs: Vec<_> = entries
            .iter()
            .map(|(k, v)| (entity_ecf::text(k), entity_ecf::integer(*v as i64)))
            .collect();
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("entries"),
            entity_ecf::Value::Map(entry_pairs),
        )]));
        let entity = match Entity::new(&path, data) {
            Ok(e) => e,
            Err(e) => {
                tracing::error!("failed to create vector clock entity: {}", e);
                return;
            }
        };
        match self.content_store.put(entity) {
            Ok(hash) => self.emit_set(&path, hash),
            Err(e) => tracing::error!("failed to store vector clock: {}", e),
        }
    }

    fn advance_hlc(&self) {
        let current = self.read_hlc();
        let new_hlc = hlc_local_event(&current, &self.local_peer_id);
        self.store_hlc(&new_hlc);
    }

    fn read_hlc(&self) -> HlcValue {
        let path = format!("/{}/system/clock/hlc", self.local_peer_id_str);
        let hash = match self.location_index.get(&path) {
            Some(h) => h,
            None => {
                return HlcValue {
                    physical: 0,
                    logical: 0,
                    peer: self.local_peer_id,
                };
            }
        };
        let entity = match self.content_store.get(&hash) {
            Some(e) => e,
            None => {
                return HlcValue {
                    physical: 0,
                    logical: 0,
                    peer: self.local_peer_id,
                };
            }
        };
        match decode_hlc(&entity.data) {
            Some(hlc) => HlcValue {
                physical: hlc.physical,
                logical: hlc.logical,
                peer: hlc.peer,
            },
            None => HlcValue {
                physical: 0,
                logical: 0,
                peer: self.local_peer_id,
            },
        }
    }

    fn store_hlc(&self, hlc: &HlcValue) {
        let path = format!("/{}/system/clock/hlc", self.local_peer_id_str);
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("logical"),
                entity_ecf::integer(hlc.logical as i64),
            ),
            (
                entity_ecf::text("peer"),
                entity_ecf::Value::Bytes(hlc.peer.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("physical"),
                entity_ecf::integer(hlc.physical as i64),
            ),
        ]));
        let entity = match Entity::new(&path, data) {
            Ok(e) => e,
            Err(e) => {
                tracing::error!("failed to create HLC entity: {}", e);
                return;
            }
        };
        match self.content_store.put(entity) {
            Ok(hash) => self.emit_set(&path, hash),
            Err(e) => tracing::error!("failed to store HLC: {}", e),
        }
    }
}

// ---------------------------------------------------------------------------
// HLC algorithm (§6.2)
// ---------------------------------------------------------------------------

struct HlcValue {
    physical: u64,
    logical: u64,
    peer: Hash,
}

/// §6.2: HLC local event — advance for a local tree write.
fn hlc_local_event(current: &HlcValue, local_peer_id: &Hash) -> HlcValue {
    let wall = system_clock_ms();
    let new_physical = wall.max(current.physical);

    let new_logical = if new_physical == current.physical {
        current.logical + 1
    } else {
        0 // physical advanced — reset logical
    };

    HlcValue {
        physical: new_physical,
        logical: new_logical,
        peer: *local_peer_id,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use entity_store::{ChangeType, MemoryContentStore, MemoryLocationIndex};

    fn test_peer_id_str() -> String {
        "peer1abc".to_string()
    }

    fn make_engine() -> (Arc<ClockEngine>, Arc<dyn ContentStore>, Arc<dyn LocationIndex>) {
        let store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let index: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let peer_id = Hash::compute("test", b"local-peer");
        let peer_id_str = test_peer_id_str();
        let engine = Arc::new(ClockEngine::new(store.clone(), index.clone(), peer_id, peer_id_str));
        (engine, store, index)
    }

    fn store_config(
        store: &Arc<dyn ContentStore>,
        index: &Arc<dyn LocationIndex>,
        mode: &str,
    ) {
        let peer_id = test_peer_id_str();
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("mode"), entity_ecf::text(mode)),
            (
                entity_ecf::text("wall_clock"),
                entity_ecf::bool_val(true),
            ),
        ]));
        let path = format!("/{}/system/clock/config", peer_id);
        let entity = Entity::new(&path, data).unwrap();
        let hash = store.put(entity).unwrap();
        index.set(&path, hash);
    }

    fn make_event(path: &str) -> TreeChangeEvent {
        TreeChangeEvent {
            path: path.to_string(),
            hash: Hash::compute("test", b"data"),
            previous_hash: None,
            new_hash: Some(Hash::compute("test", b"data")),
            change_type: ChangeType::Created,
            context: None,
        }
    }

    #[test]
    fn test_advance_logical() {
        let (engine, store, index) = make_engine();
        store_config(&store, &index, "logical");

        // First event: counter should go from 0 to 1
        engine.process_event(&make_event("app/data"));
        let counter = engine.read_logical_counter();
        assert_eq!(counter, 1);

        // Second event: counter should increment to 2
        engine.process_event(&make_event("app/other"));
        let counter = engine.read_logical_counter();
        assert_eq!(counter, 2);
    }

    #[test]
    fn test_advance_vector() {
        let (engine, store, index) = make_engine();
        store_config(&store, &index, "vector");

        engine.process_event(&make_event("app/data"));

        let entries = engine.read_vector_entries();
        let peer_key = engine.local_peer_id.to_string();
        assert_eq!(*entries.get(&peer_key).unwrap(), 1);

        // Second event: local peer entry should increment
        engine.process_event(&make_event("app/more"));
        let entries = engine.read_vector_entries();
        assert_eq!(*entries.get(&peer_key).unwrap(), 2);
    }

    #[test]
    fn test_advance_hlc() {
        let (engine, store, index) = make_engine();
        store_config(&store, &index, "hlc");

        engine.process_event(&make_event("app/data"));

        let hlc = engine.read_hlc();
        assert!(hlc.physical > 0);
        assert_eq!(hlc.peer, engine.local_peer_id);
    }

    #[test]
    fn test_skip_clock_paths() {
        let (engine, store, index) = make_engine();
        store_config(&store, &index, "logical");
        let peer_id = test_peer_id_str();

        // Write to a clock path should NOT advance the clock
        engine.process_event(&make_event(&format!("/{}/system/clock/config", peer_id)));
        let counter = engine.read_logical_counter();
        assert_eq!(counter, 0);

        engine.process_event(&make_event(&format!("/{}/system/clock/logical", peer_id)));
        let counter = engine.read_logical_counter();
        assert_eq!(counter, 0);

        // Non-clock path should advance
        engine.process_event(&make_event("app/data"));
        let counter = engine.read_logical_counter();
        assert_eq!(counter, 1);
    }

    #[test]
    fn test_wall_mode_no_state() {
        let (engine, store, index) = make_engine();
        store_config(&store, &index, "wall");
        let peer_id = test_peer_id_str();

        // Wall mode doesn't store any persistent state
        engine.process_event(&make_event("app/data"));
        assert!(index.get(&format!("/{}/system/clock/logical", peer_id)).is_none());
    }

    #[test]
    fn test_hlc_drift_bound() {
        let (engine, store, index) = make_engine();
        store_config(&store, &index, "hlc");
        let peer_id = test_peer_id_str();

        // Store an HLC with a far-future physical time
        let far_future = system_clock_ms() + MAX_HLC_DRIFT_MS + 100_000;
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("logical"),
                entity_ecf::integer(5),
            ),
            (
                entity_ecf::text("peer"),
                entity_ecf::Value::Bytes(engine.local_peer_id.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("physical"),
                entity_ecf::integer(far_future as i64),
            ),
        ]));
        let path = format!("/{}/system/clock/hlc", peer_id);
        let entity = Entity::new(&path, data).unwrap();
        let hash = store.put(entity).unwrap();
        index.set(&path, hash);

        // Advance: physical should be max(wall, current.physical) = far_future
        // But logical should increment (same physical)
        engine.process_event(&make_event("app/data"));
        let hlc = engine.read_hlc();
        // Physical stays at far_future (it's already > wall clock)
        assert_eq!(hlc.physical, far_future);
        // Logical increments since physical didn't advance
        assert_eq!(hlc.logical, 6);
    }

    #[test]
    fn test_hlc_local_event_physical_advances() {
        let peer = Hash::compute("test", b"peer");
        // Current HLC is in the past
        let current = HlcValue {
            physical: 1000,
            logical: 5,
            peer,
        };
        let result = hlc_local_event(&current, &peer);
        // Wall clock is definitely > 1000, so physical should advance
        assert!(result.physical > 1000);
        // Logical resets to 0 when physical advances
        assert_eq!(result.logical, 0);
    }

    #[test]
    fn test_hlc_local_event_same_physical() {
        let peer = Hash::compute("test", b"peer");
        // Set physical to far future so wall clock won't exceed it
        let far_future = system_clock_ms() + 1_000_000;
        let current = HlcValue {
            physical: far_future,
            logical: 10,
            peer,
        };
        let result = hlc_local_event(&current, &peer);
        assert_eq!(result.physical, far_future);
        assert_eq!(result.logical, 11);
    }
}
