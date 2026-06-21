//! SyncTreeHook adapter that populates `AttestationIndex` for cross-peer
//! `system/attestation` arrivals (Phase 6 wiring per
//! MIGRATION-IDENTITY-V3.2.md).
//!
//! Local handler writes (via `AttestationHandler:create`/`:supersede`/
//! `:revoke`) populate the index directly. This hook covers the
//! complementary path: cross-peer sync delivers a `system/attestation`
//! entity at some path on the local tree → hook fires → index updates.
//!
//! Per spec §I1–I3 invariants, the index entry MUST appear before
//! subsequent `find_*` calls return. The hook fires synchronously in
//! Phase 1 of the cascade (before broadcast), satisfying this.

use std::sync::Arc;

use entity_store::{
    CascadeHalt, ContentStore, ExecutionContext, SyncTreeHook, TreeChangeEvent,
};
use entity_types::TYPE_ATTESTATION;

use crate::data::AttestationData;
use crate::index::AttestationIndex;

/// SyncTreeHook that maintains the attestation index in response to
/// `system/attestation` entity writes from any source.
pub struct AttestationIndexHook {
    index: Arc<AttestationIndex>,
    content_store: Arc<dyn ContentStore>,
    qualified_pattern: String,
}

impl AttestationIndexHook {
    pub fn new(
        index: Arc<AttestationIndex>,
        content_store: Arc<dyn ContentStore>,
        local_peer_id: String,
    ) -> Self {
        // Hook attribution path matches the substrate handler so
        // cascade-halt reports name it consistently.
        let qualified_pattern = format!("/{}/system/attestation", local_peer_id);
        Self {
            index,
            content_store,
            qualified_pattern,
        }
    }
}

impl SyncTreeHook for AttestationIndexHook {
    fn on_tree_change(
        &self,
        event: &TreeChangeEvent,
        _ctx: &mut ExecutionContext,
    ) -> Result<(), CascadeHalt> {
        // Only react to writes (create/modify) — deletions don't remove
        // index entries (per I4 — revoked attestations stay indexed).
        let new_hash = match event.new_hash {
            Some(h) => h,
            None => return Ok(()),
        };
        let entity = match self.content_store.get(&new_hash) {
            Some(e) => e,
            None => return Ok(()),
        };
        if entity.entity_type != TYPE_ATTESTATION {
            return Ok(());
        }
        if let Ok(att) = AttestationData::from_entity(&entity) {
            self.index.insert(new_hash, att);
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "attestation/index-maintainer"
    }

    fn handler_pattern(&self) -> &str {
        &self.qualified_pattern
    }
}
