//! Resolution log (§11.2 SHOULD) — one entry per top-level `meta_resolve`.
//!
//! Ring-buffer at `resolver-config.resolution_log_capacity` (default 1024);
//! eviction removes the oldest tree pointer but does NOT reset the per-peer
//! monotonic `seq`. `seq` is recovered on startup by walking the
//! `system/registry/resolution-log/` prefix and taking max+1. Cache hits MAY be
//! elided (`log_cache_hits`); transport-fallback re-resolves are NOT written
//! (a flapping endpoint must not write per-retry to the content store).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};

use crate::data::ResolutionLogData;
use crate::{resolution_log_path, resolution_log_prefix};

/// Current wall-clock in milliseconds since the Unix epoch.
pub(crate) fn now_ms() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A per-peer monotonic, ring-bounded resolution log.
pub struct ResolutionLog {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    peer_id: String,
    next_seq: AtomicU64,
    capacity: u64,
}

impl ResolutionLog {
    /// Build a log, recovering `next_seq` from any existing entries in the tree.
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        peer_id: String,
        capacity: u64,
    ) -> Self {
        let prefix = resolution_log_prefix(&peer_id);
        let max_seq = location_index
            .list(&prefix)
            .into_iter()
            .filter_map(|e| e.path.rsplit('/').next().and_then(|s| s.parse::<u64>().ok()))
            .max();
        let next = max_seq.map(|m| m + 1).unwrap_or(0);
        Self {
            content_store,
            location_index,
            peer_id,
            next_seq: AtomicU64::new(next),
            capacity: capacity.max(1),
        }
    }

    /// Write one log entry, returning its content hash. Performs ring eviction
    /// of the oldest pointer once `capacity` is exceeded.
    pub fn record(
        &self,
        name: &str,
        status: &str,
        backend_id: Option<String>,
        reason: Option<String>,
        binding: Option<Hash>,
        is_fallback_reresolve: bool,
    ) -> Option<Hash> {
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        let entry = ResolutionLogData {
            seq,
            name: name.to_string(),
            backend_id,
            status: status.to_string(),
            reason,
            binding,
            attempted_at: now_ms(),
            is_fallback_reresolve,
        };
        let entity = entry.to_entity().ok()?;
        let hash = entity.content_hash;
        if self.content_store.put(entity).is_err() {
            return None;
        }
        self.location_index
            .set(&resolution_log_path(&self.peer_id, seq), hash);
        // Ring eviction: drop the pointer for seq - capacity (body GC'd later).
        if seq >= self.capacity {
            let evict = seq - self.capacity;
            self.location_index
                .remove(&resolution_log_path(&self.peer_id, evict));
        }
        Some(hash)
    }

    #[cfg(test)]
    pub fn peek_next_seq(&self) -> u64 {
        self.next_seq.load(Ordering::SeqCst)
    }
}
