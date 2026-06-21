//! Startup-time L0 access for role definitions and assignments
//! (EXTENSION-ROLE v1.6 §4.5 / IA13). Renamed from "bootstrap" per
//! SI-28 — the prior name conflated this L0-time setup with the
//! first-contact policy of §4.7.
//!
//! Startup-time is the *only* write path that bypasses the role
//! handler's runtime dispatch. Per §4.5, startup-derived tokens have:
//! - `parent: null` (root cap convention, V7 §5.5)
//! - `granter: local_peer_identity_hash`
//!
//! RL2 does NOT apply at startup-time (no caller capability exists yet
//! — the peer-owner is acting via L0 direct-store). However, **R7 layer
//! 2 (block-new-derivation) still fires** — an excluded peer cannot
//! receive a startup-derived cap (§6.1 layer 2, IA13).
//!
//! IA13 conformance: these helpers are the only L0 derivation entry
//! point. Once the role handler is registered in the dispatch table,
//! callers MUST switch to `system/role:assign`. The helpers don't
//! enforce a runtime "already-registered" gate — that's an SDK-layer
//! invariant. The peer crate calls these helpers only from
//! `PeerBuilder::build()` before serving, which structurally satisfies
//! the rule.
//!
//! v1.6 SI-1 / SI-8: the assignee parameter is the assignee's
//! identity-entity `Hash` directly (not a peer-id string). The path
//! segment is hex of that hash; the cap `grantee` field carries the
//! raw bytes.

use std::sync::Arc;

use entity_capability::{CapabilityToken, GrantEntry, Granter};
use entity_crypto::Keypair;
use entity_ecf::{text, to_ecf, Value};
use entity_entity::{Entity, TYPE_SIGNATURE};
use entity_hash::{invariant_signature_path, Hash};
use entity_store::{ContentStore, LocationIndex};

use crate::data::{hex_segment, RoleAssignmentData, RoleData, RoleDerivedTokenLinkData};
use crate::handler::role_metadata_ttl;
use crate::helpers::{is_excluded, resolve_grant_templates};
use crate::paths::{
    path_role_assignment, path_role_definition, path_role_derived_link,
    path_role_derived_token, peer_segment_from_hash,
};

/// Outcome of a successful startup-time role assignment.
#[derive(Debug, Clone)]
pub struct StartupAssignmentResult {
    pub assignment_path: String,
    pub token_hash: Hash,
}

/// Errors specific to the L0 startup-time path.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("role definition not found at {0}")]
    RoleNotFound(String),
    #[error("role definition decode failed: {0}")]
    RoleDecode(String),
    #[error("assignee is in the context's exclusion subtree")]
    AssigneeExcluded,
    #[error("encode failed: {0}")]
    Encode(String),
    #[error("storage failed: {0}")]
    Store(String),
}

/// L0 helper: install a role *definition* into the startup
/// administrative context. Equivalent to a tree:put of a `system/role`
/// entity.
///
/// `qualified_prefix` is `/{local_peer_id}/`. `context` and `role_name`
/// follow the usual conventions (R10 reserved-name rejection deferred
/// to caller).
pub fn startup_role_definition(
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    qualified_prefix: &str,
    context: &str,
    role_name: &str,
    grants: Vec<GrantEntry>,
    metadata: Option<Vec<(ciborium::Value, ciborium::Value)>>,
) -> Result<Hash, StartupError> {
    let role_def = RoleData {
        name: role_name.to_string(),
        grants,
        metadata,
    };
    let entity = role_def
        .to_entity()
        .map_err(|e| StartupError::Encode(e.to_string()))?;
    let hash = content_store
        .put(entity)
        .map_err(|e| StartupError::Store(e.to_string()))?;
    let path = format!(
        "{}{}",
        qualified_prefix,
        path_role_definition(context, role_name)
    );
    location_index.set(&path, hash);
    Ok(hash)
}

/// L0 helper: provision a role assignment + root cap for the assignee
/// identified by `assignee_identity_hash` in `context`. Per §4.5:
/// - Reads the role definition at the canonical path.
/// - Layer-2 check: reject if the assignee is in the exclusion subtree
///   (R7 layer 2 / IA13).
/// - Persists `system/role/assignment` entity at the assignment path.
/// - Issues a root capability token (`parent: null`, `granter:
///   identity_hash`), signs it with `keypair`, persists at the pinned
///   R4 path.
/// - Writes the SI-5 linkage entity at the sibling subtree so future
///   `unassign` / `:delegate` find the cap deterministically.
///
/// The path-segment for the assignee is hex of `assignee_identity_hash`
/// (SI-1).
pub fn startup_role_assignment(
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    qualified_prefix: &str,
    identity_hash: Hash,
    keypair: &Keypair,
    context: &str,
    assignee_identity_hash: Hash,
    role_name: &str,
) -> Result<StartupAssignmentResult, StartupError> {
    let assignee_segment = peer_segment_from_hash(&assignee_identity_hash);

    // R7 layer 2: excluded peer cannot receive a startup-derived cap.
    if is_excluded(location_index, qualified_prefix, context, &assignee_segment) {
        return Err(StartupError::AssigneeExcluded);
    }

    // Read role definition.
    let role_def_path = format!(
        "{}{}",
        qualified_prefix,
        path_role_definition(context, role_name)
    );
    let role_hash = location_index
        .get(&role_def_path)
        .ok_or_else(|| StartupError::RoleNotFound(role_def_path.clone()))?;
    let role_entity = content_store
        .get(&role_hash)
        .ok_or_else(|| StartupError::RoleNotFound(role_def_path))?;
    let role_def = RoleData::from_entity(&role_entity)
        .map_err(|e| StartupError::RoleDecode(e.to_string()))?;

    // Resolve template grants for the assignee. `{peer_id}` substitutes
    // to hex of the assignee's identity hash (same form as path segments).
    let derived_grants: Vec<GrantEntry> = role_def
        .grants
        .iter()
        .map(|g| resolve_grant_templates(g, context, &assignee_segment))
        .collect();

    // Persist assignment entity.
    let now_ms = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let assignment = RoleAssignmentData {
        role: role_name.to_string(),
        assigned_by: identity_hash,
        assigned_at: now_ms,
        metadata: None,
    };
    let assignment_entity = assignment
        .to_entity()
        .map_err(|e| StartupError::Encode(e.to_string()))?;
    let assignment_hash = content_store
        .put(assignment_entity)
        .map_err(|e| StartupError::Store(e.to_string()))?;
    let assignment_path = format!(
        "{}{}",
        qualified_prefix,
        path_role_assignment(context, &assignee_segment, role_name)
    );
    location_index.set(&assignment_path, assignment_hash);

    // Build, sign, persist root cap. parent=None, granter=identity_hash
    // (V7 §5.5 root-cap convention). `grantee` is the assignee's
    // identity-entity hash directly (SI-8). v1.7 §5.3: startup-derived
    // caps still respect `role.metadata.ttl` (parent + caller bounds
    // don't apply at L0 — there's no parent, no caller cap).
    let role_expires_at = role_metadata_ttl(&role_def.metadata)
        .map(|ttl| now_ms.saturating_add(ttl));
    let token = CapabilityToken {
        grants: derived_grants,
        granter: Granter::Single(identity_hash),
        grantee: assignee_identity_hash,
        parent: None,
        created_at: now_ms,
        expires_at: role_expires_at,
        not_before: None,
        delegation_caveats: None,
    };
    let cap_entity = token
        .to_entity()
        .map_err(|e| StartupError::Encode(e.to_string()))?;
    let cap_hash = content_store
        .put(cap_entity.clone())
        .map_err(|e| StartupError::Store(e.to_string()))?;
    let sig_bytes = keypair.sign(&cap_entity.content_hash.to_bytes());
    let sig_data = to_ecf(&Value::Map(vec![
        (text("algorithm"), text("ed25519")),
        (text("signature"), Value::Bytes(sig_bytes.to_vec())),
        (
            text("signer"),
            Value::Bytes(identity_hash.to_bytes().to_vec()),
        ),
        (
            text("target"),
            Value::Bytes(cap_entity.content_hash.to_bytes().to_vec()),
        ),
    ]));
    let sig_entity =
        Entity::new(TYPE_SIGNATURE, sig_data).map_err(|e| StartupError::Encode(e.to_string()))?;
    let sig_hash = content_store
        .put(sig_entity)
        .map_err(|e| StartupError::Store(e.to_string()))?;
    let cap_path = format!(
        "{}{}",
        qualified_prefix,
        path_role_derived_token(context, &assignee_segment, &hex_segment(&cap_hash))
    );
    location_index.set(&cap_path, cap_hash);
    // V7 §3.5 (v7.44 MUST): the startup L0 role-derived cap is a
    // transportable chain root (ROLE PR-1) — bind its signature at the
    // invariant pointer path (sole canonical location; no sibling).
    let signer = keypair.peer_id();
    location_index.set(
        &invariant_signature_path(signer.as_str(), &cap_hash),
        sig_hash,
    );

    // SI-5 v1.6: write the linkage entity at the sibling subtree.
    let link = RoleDerivedTokenLinkData {
        token_hash: cap_hash,
        issued_at: now_ms,
    };
    let link_entity = link
        .to_entity()
        .map_err(|e| StartupError::Encode(e.to_string()))?;
    let link_hash = content_store
        .put(link_entity)
        .map_err(|e| StartupError::Store(e.to_string()))?;
    let link_path = format!(
        "{}{}",
        qualified_prefix,
        path_role_derived_link(context, &assignee_segment, role_name)
    );
    location_index.set(&link_path, link_hash);

    Ok(StartupAssignmentResult {
        assignment_path,
        token_hash: cap_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_capability::{IdScope, PathScope};
    use entity_store::{MemoryContentStore, MemoryLocationIndex};

    fn fixture() -> (
        Arc<dyn ContentStore>,
        Arc<dyn LocationIndex>,
        Keypair,
        Hash,
        String,
    ) {
        let cs: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let kp = Keypair::from_seed([0x77; 32]);
        let identity = kp.peer_entity().unwrap();
        let identity_hash = identity.content_hash;
        cs.put(identity).unwrap();
        let prefix = format!("/{}/", kp.peer_id().as_str());
        (cs, li, kp, identity_hash, prefix)
    }

    /// Build an assignee identity entity for tests so the cap's grantee
    /// hash and the path-segment hex correspond to a real identity.
    fn assignee_identity_hash(cs: &Arc<dyn ContentStore>, seed: u8) -> Hash {
        let kp = Keypair::from_seed([seed; 32]);
        let id = kp.peer_entity().unwrap();
        let h = id.content_hash;
        cs.put(id).unwrap();
        h
    }

    fn template_grant() -> GrantEntry {
        GrantEntry {
            handlers: PathScope::new(vec!["system/tree".into()]),
            resources: PathScope::new(vec!["shared/{context}/*".into()]),
            operations: IdScope::new(vec!["get".into(), "put".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        }
    }

    #[test]
    fn startup_definition_persists_role_entity() {
        let (cs, li, _kp, _id, prefix) = fixture();
        let hash = startup_role_definition(
            &cs,
            &li,
            &prefix,
            "admin",
            "operator",
            vec![template_grant()],
            None,
        )
        .unwrap();
        let path = format!("{}{}", prefix, path_role_definition("admin", "operator"));
        assert_eq!(li.get(&path), Some(hash));
        let entity = cs.get(&hash).unwrap();
        let role = RoleData::from_entity(&entity).unwrap();
        assert_eq!(role.name, "operator");
    }

    #[test]
    fn startup_assignment_issues_root_cap_with_real_grantee() {
        let (cs, li, kp, identity_hash, prefix) = fixture();
        startup_role_definition(
            &cs,
            &li,
            &prefix,
            "admin",
            "operator",
            vec![template_grant()],
            None,
        )
        .unwrap();
        let alice_hash = assignee_identity_hash(&cs, 0xA1);
        let result = startup_role_assignment(
            &cs,
            &li,
            &prefix,
            identity_hash,
            &kp,
            "admin",
            alice_hash,
            "operator",
        )
        .unwrap();
        assert!(result.assignment_path.ends_with("/operator"));
        let cap_entity = cs.get(&result.token_hash).unwrap();
        let token = CapabilityToken::from_entity(&cap_entity).unwrap();
        assert!(token.parent.is_none(), "startup caps must be root");
        assert_eq!(
            token.grantee, alice_hash,
            "SI-8: grantee MUST be assignee's identity-entity content hash"
        );
        match token.granter {
            Granter::Single(h) => assert_eq!(h, identity_hash),
            _ => panic!("expected single-sig granter"),
        }
        assert_eq!(
            token.grants[0].resources.include[0],
            "shared/admin/*",
            "template variables must be resolved"
        );

        // SI-5 linkage entity must be present.
        let alice_seg = peer_segment_from_hash(&alice_hash);
        let link_path = format!(
            "{}{}",
            prefix,
            path_role_derived_link("admin", &alice_seg, "operator")
        );
        let link_hash = li.get(&link_path).expect("linkage entity bound");
        let link_entity = cs.get(&link_hash).unwrap();
        let link = RoleDerivedTokenLinkData::from_entity(&link_entity).unwrap();
        assert_eq!(link.token_hash, result.token_hash);
    }

    #[test]
    fn startup_assignment_layer2_blocks_excluded_peer() {
        let (cs, li, kp, identity_hash, prefix) = fixture();
        startup_role_definition(
            &cs,
            &li,
            &prefix,
            "admin",
            "operator",
            vec![template_grant()],
            None,
        )
        .unwrap();
        let alice_hash = assignee_identity_hash(&cs, 0xA2);
        // Plant exclusion entity for alice in admin context.
        let dummy = Hash::compute("system/role/exclusion", b"x");
        let alice_seg = peer_segment_from_hash(&alice_hash);
        let exclusion_path = format!(
            "{}{}",
            prefix,
            crate::paths::path_role_exclusion("admin", &alice_seg)
        );
        li.set(&exclusion_path, dummy);

        let err = startup_role_assignment(
            &cs,
            &li,
            &prefix,
            identity_hash,
            &kp,
            "admin",
            alice_hash,
            "operator",
        )
        .unwrap_err();
        assert!(matches!(err, StartupError::AssigneeExcluded));
    }

    #[test]
    fn startup_assignment_404_when_role_undefined() {
        let (cs, li, kp, identity_hash, prefix) = fixture();
        let alice_hash = assignee_identity_hash(&cs, 0xA3);
        let err = startup_role_assignment(
            &cs,
            &li,
            &prefix,
            identity_hash,
            &kp,
            "admin",
            alice_hash,
            "ghost",
        )
        .unwrap_err();
        assert!(matches!(err, StartupError::RoleNotFound(_)));
    }
}
