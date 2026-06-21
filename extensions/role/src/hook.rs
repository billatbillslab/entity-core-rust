//! Reactive fleet sweep hook (EXTENSION-ROLE v1.6 §6.5 / IA8).
//!
//! When an exclusion entity arrives at
//! `[/{peer_id}/]system/role/{context}/excluded/{excluded_peer_hex}` via
//! tree sync (or any other write source), every peer holding role-
//! derived tokens for `(context, excluded_peer)` MUST sweep its local
//! `system/capability/grants/role-derived/{context}/{excluded_peer_hex}/...`
//! subtree.
//!
//! Without this bridge, `alice_phone` would keep issuing/holding
//! role-derived tokens for Bob even after `alice_desktop` excluded him,
//! defeating the fleet-wide intent of layer 1.
//!
//! The hook fires synchronously in Phase 1 of the cascade so layer-1
//! enforcement is observable on the same write that delivered the
//! exclusion.
//!
//! **SI-17 v1.6 compliance.** This implementation uses the
//! "idempotent-hook" pattern: the cascade re-runs on every relevant
//! write (handler-originated AND sync-originated), but the cascade is a
//! no-op if there are no tokens to sweep. Per the proposal, this
//! satisfies the SI-17 MUST without needing to inspect
//! `event.context.handler_pattern`.

use std::sync::Arc;

use entity_store::{
    CascadeHalt, ContentStore, ExecutionContext, LocationIndex, SyncTreeHook,
    TreeChangeEvent,
};
use entity_types::TYPE_ROLE_EXCLUSION;

use crate::paths::{parse_exclusion_path, prefix_role_derived_peer};

/// Sweeps role-derived tokens whenever a `system/role/exclusion` entity
/// is bound on the tree.
///
/// Per RA-7 in `docs/SPEC-AMBIGUITIES-ROLE.md`, this implements the broad
/// reading: every token at the (context, excluded_peer) prefix is
/// removed, regardless of which peer issued it. Each peer in the fleet
/// runs the same hook on its local view; together they make exclusion
/// fleet-wide.
pub struct RoleExclusionSweepHook {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    qualified_pattern: String,
    qualified_prefix: String,
}

impl RoleExclusionSweepHook {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
    ) -> Self {
        let qualified_pattern = format!("/{}/system/role", local_peer_id);
        let qualified_prefix = format!("/{}/", local_peer_id);
        Self {
            content_store,
            location_index,
            qualified_pattern,
            qualified_prefix,
        }
    }
}

impl SyncTreeHook for RoleExclusionSweepHook {
    fn on_tree_change(
        &self,
        event: &TreeChangeEvent,
        _ctx: &mut ExecutionContext,
    ) -> Result<(), CascadeHalt> {
        // Only react to writes — removing the exclusion entity does NOT
        // restore tokens (§6.4). The only signal that fires the sweep is
        // a new/updated exclusion entity binding.
        let new_hash = match event.new_hash {
            Some(h) => h,
            None => return Ok(()),
        };
        let entity = match self.content_store.get(&new_hash) {
            Some(e) => e,
            None => return Ok(()),
        };
        if entity.entity_type != TYPE_ROLE_EXCLUSION {
            return Ok(());
        }
        // Decompose the path to recover (context, excluded_peer). We use
        // the path-parser rather than the entity's `peer_id` field so the
        // sweep target is the location-keyed peer, not whatever the
        // entity claims (defensive against ill-formed exclusions).
        let parsed = match parse_exclusion_path(&event.path) {
            Some(p) => p,
            None => return Ok(()),
        };
        let prefix = format!(
            "{}{}",
            self.qualified_prefix,
            prefix_role_derived_peer(&parsed.context, &parsed.peer_id)
        );
        for entry in self.location_index.list(&prefix) {
            self.location_index.remove(&entry.path);
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "role/exclusion-sweep"
    }

    fn handler_pattern(&self) -> &str {
        &self.qualified_pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::RoleExclusionData;
    use crate::paths::path_role_exclusion;
    use entity_hash::Hash;
    use entity_store::{ChangeType, ExecutionContext, MemoryContentStore, MemoryLocationIndex};

    fn fixture() -> (
        Arc<RoleExclusionSweepHook>,
        Arc<dyn ContentStore>,
        Arc<dyn LocationIndex>,
        String,
    ) {
        let cs: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let pid = "peer42".to_string();
        let hook = Arc::new(RoleExclusionSweepHook::new(
            cs.clone(),
            li.clone(),
            pid.clone(),
        ));
        (hook, cs, li, pid)
    }

    fn plant_role_derived_token(
        cs: &Arc<dyn ContentStore>,
        li: &Arc<dyn LocationIndex>,
        pid: &str,
        context: &str,
        peer_id: &str,
        token_segment: &str,
    ) -> Hash {
        // Token contents are irrelevant for the sweep — bind a sentinel.
        let stub = entity_entity::Entity::new(
            "system/capability/token",
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![])),
        )
        .unwrap();
        let h = cs.put(stub).unwrap();
        let path = format!(
            "/{}/{}{}",
            pid,
            prefix_role_derived_peer(context, peer_id),
            token_segment
        );
        li.set(&path, h);
        h
    }

    #[test]
    fn hook_sweeps_on_exclusion_arrival() {
        let (hook, cs, li, pid) = fixture();

        plant_role_derived_token(&cs, &li, &pid, "group/team-alpha", "dave", "tok-a");
        plant_role_derived_token(&cs, &li, &pid, "group/team-alpha", "dave", "tok-b");
        // Sentinel token for an unrelated (context, peer) — must NOT be swept.
        plant_role_derived_token(&cs, &li, &pid, "group/team-alpha", "alice", "tok-keep");

        // Plant the exclusion entity (v1.6 SI-3: no peer_id body field).
        let exclusion = RoleExclusionData {
            excluded_by: Hash::zero(),
            excluded_at: 1,
            reason: None,
        };
        let entity = exclusion.to_entity().unwrap();
        let exclusion_hash = cs.put(entity).unwrap();
        let exclusion_path = format!(
            "/{}/{}",
            pid,
            path_role_exclusion("group/team-alpha", "dave")
        );

        let event = TreeChangeEvent {
            path: exclusion_path.clone(),
            hash: exclusion_hash,
            previous_hash: None,
            new_hash: Some(exclusion_hash),
            change_type: ChangeType::Created,
            context: None,
        };
        let mut ctx = ExecutionContext::default();
        hook.on_tree_change(&event, &mut ctx).unwrap();

        // Dave's tokens are gone; alice's untouched.
        let dave_prefix = format!(
            "/{}/{}",
            pid,
            prefix_role_derived_peer("group/team-alpha", "dave")
        );
        assert!(li.list(&dave_prefix).is_empty(), "dave's tokens must be swept");
        let alice_prefix = format!(
            "/{}/{}",
            pid,
            prefix_role_derived_peer("group/team-alpha", "alice")
        );
        assert_eq!(
            li.list(&alice_prefix).len(),
            1,
            "alice's tokens (different peer) must NOT be swept"
        );
    }

    #[test]
    fn hook_ignores_non_exclusion_entities() {
        let (hook, cs, li, pid) = fixture();
        plant_role_derived_token(&cs, &li, &pid, "ctx", "dave", "tok");
        // Bind some random non-exclusion entity at an exclusion-shaped
        // path — the entity-type check should skip it.
        let stub = entity_entity::Entity::new(
            "system/random",
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![])),
        )
        .unwrap();
        let h = cs.put(stub).unwrap();
        let exclusion_path = format!("/{}/{}", pid, path_role_exclusion("ctx", "dave"));
        li.set(&exclusion_path, h);

        let event = TreeChangeEvent {
            path: exclusion_path,
            hash: h,
            previous_hash: None,
            new_hash: Some(h),
            change_type: ChangeType::Created,
            context: None,
        };
        let mut ctx = ExecutionContext::default();
        hook.on_tree_change(&event, &mut ctx).unwrap();

        let prefix = format!("/{}/{}", pid, prefix_role_derived_peer("ctx", "dave"));
        assert_eq!(
            li.list(&prefix).len(),
            1,
            "non-exclusion-typed entity must not trigger the sweep"
        );
    }

    #[test]
    fn hook_no_op_on_removal() {
        let (hook, cs, li, pid) = fixture();
        plant_role_derived_token(&cs, &li, &pid, "ctx", "dave", "tok");
        let event = TreeChangeEvent {
            path: format!("/{}/{}", pid, path_role_exclusion("ctx", "dave")),
            hash: Hash::zero(),
            previous_hash: Some(Hash::zero()),
            new_hash: None,
            change_type: ChangeType::Deleted,
            context: None,
        };
        let mut ctx = ExecutionContext::default();
        hook.on_tree_change(&event, &mut ctx).unwrap();
        let prefix = format!("/{}/{}", pid, prefix_role_derived_peer("ctx", "dave"));
        assert_eq!(li.list(&prefix).len(), 1);
    }
}
