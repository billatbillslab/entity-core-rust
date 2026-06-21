//! Integration tests for the role handler — v1.6 wire shapes.
//!
//! Each test assignee is constructed as a real `Keypair` → identity
//! entity → identity-hash, then the path segment is `hex(hash)` per
//! SI-1. Tokens have `grantee = identity_hash` (raw bytes) per SI-8.

use std::collections::HashMap;
use std::sync::Arc;

use entity_capability::{
    encode_grant_entry, CapabilityToken, GrantEntry, Granter, IdScope, PathScope,
    ResourceTarget,
};
use entity_crypto::Keypair;
use entity_ecf::{text, to_ecf, Value};
use entity_entity::Entity;
use entity_handler::{Handler, HandlerContext, STATUS_FORBIDDEN, STATUS_NOT_FOUND, STATUS_OK};
use entity_hash::{invariant_signature_path, Hash};
use entity_store::{ContentStore, LocationIndex, MemoryContentStore, MemoryLocationIndex};

use crate::data::{RoleAssignmentData, RoleData, RoleDerivedTokenLinkData, RoleExclusionData};
use crate::handler::RoleHandler;
use crate::paths::{
    path_role_assignment, path_role_definition, path_role_derived_link,
    path_role_exclusion, peer_segment_from_hash, prefix_role_derived_peer,
};

const TEST_SEED: [u8; 32] = [0x42; 32];

fn fixture() -> (
    Arc<RoleHandler>,
    Arc<dyn ContentStore>,
    Arc<dyn LocationIndex>,
    String,
    Hash,
) {
    let cs: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
    let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
    let kp = Keypair::from_seed(TEST_SEED);
    let pid = kp.peer_id().as_str().to_string();
    let identity_entity = kp.peer_entity().unwrap();
    let identity_hash = identity_entity.content_hash;
    cs.put(identity_entity).unwrap();
    let handler = Arc::new(RoleHandler::new(
        cs.clone(),
        li.clone(),
        pid.clone(),
        identity_hash,
        entity_crypto::IdentityKeypair::Ed25519(Keypair::from_seed(TEST_SEED)),
    ));
    (handler, cs, li, pid, identity_hash)
}

/// Build an assignee identity (keypair → identity entity → content_hash)
/// and persist the entity in the content store. Returns the identity hash
/// AND its hex path segment (peer_segment_from_hash).
fn make_assignee(cs: &Arc<dyn ContentStore>, seed: u8) -> (Hash, String) {
    let kp = Keypair::from_seed([seed; 32]);
    let id = kp.peer_entity().unwrap();
    let h = id.content_hash;
    cs.put(id).unwrap();
    (h, peer_segment_from_hash(&h))
}

fn put_role_definition(
    cs: &Arc<dyn ContentStore>,
    li: &Arc<dyn LocationIndex>,
    pid: &str,
    context: &str,
    role_name: &str,
    grants: Vec<GrantEntry>,
) {
    let role = RoleData {
        name: role_name.into(),
        grants,
        metadata: None,
    };
    let entity = role.to_entity().unwrap();
    let hash = cs.put(entity).unwrap();
    let path = format!("/{}/{}", pid, path_role_definition(context, role_name));
    li.set(&path, hash);
}

fn execute_entity_stub() -> Entity {
    Entity::new(entity_types::TYPE_EXECUTE, to_ecf(&Value::Map(vec![]))).unwrap()
}

fn empty_params() -> Entity {
    Entity::new("primitive/any", to_ecf(&Value::Map(vec![]))).unwrap()
}

fn assign_params(role: &str) -> Entity {
    Entity::new(
        "system/role/assign-request",
        to_ecf(&Value::Map(vec![(text("role"), text(role))])),
    )
    .unwrap()
}

fn make_caller_cap(grants: Vec<GrantEntry>, identity_hash: Hash) -> CapabilityToken {
    CapabilityToken {
        grants,
        granter: Granter::Single(identity_hash),
        grantee: identity_hash,
        parent: None,
        created_at: 1_700_000_000_000,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    }
}

fn wildcard_cap(identity_hash: Hash) -> CapabilityToken {
    make_caller_cap(
        vec![GrantEntry {
            handlers: PathScope::all(),
            resources: PathScope::all(),
            operations: IdScope::all(),
            peers: Some(IdScope::all()),
            constraints: None,
            allowances: None,
        }],
        identity_hash,
    )
}

fn build_ctx(
    operation: &str,
    resource: &str,
    params: Entity,
    caller: Option<CapabilityToken>,
    pid: &str,
    identity_hash: Hash,
) -> HandlerContext {
    HandlerContext {
        handler_grant: None,
        caller_capability: caller,
        execute: execute_entity_stub(),
        params,
        pattern: format!("/{}/system/role", pid),
        suffix: String::new(),
        resource_target: Some(ResourceTarget {
            targets: vec![resource.to_string()],
            exclude: vec![],
        }),
        author: Some(identity_hash),
        request_id: "test-req".into(),
        operation: operation.into(),
        execute_fn: None,
        included: HashMap::new(),
        matching_grant: None,
        capability_hash: None,
        handler_grant_hash: None,
        bounds: None,
        is_external: false,
        session_peer_id: None,
    }
}

/// Count only role-derived cap entries under `prefix`. Since V7 §3.5
/// v7.44, signatures live at the invariant pointer path (a different
/// subtree), not as siblings here — so this prefix holds caps + linkage
/// entities; we count the caps. Cap removal also unbinds the invariant
/// sig (`revoke_via_linkage` / sweep paths).
fn count_caps(
    li: &Arc<dyn LocationIndex>,
    cs: &Arc<dyn ContentStore>,
    prefix: &str,
) -> usize {
    li.list(prefix)
        .iter()
        .filter(|e| {
            cs.get(&e.hash)
                .map(|ent| ent.entity_type == "system/capability/token")
                .unwrap_or(false)
        })
        .count()
}

fn shared_template_grant() -> GrantEntry {
    GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec!["shared/{context}/*".into()]),
        operations: IdScope::new(vec!["get".into(), "put".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }
}

// ---------------------------------------------------------------------------
// MVP ops
// ---------------------------------------------------------------------------

#[tokio::test]
async fn assign_writes_assignment_and_derives_token_with_real_grantee() {
    let (handler, cs, li, pid, identity_hash) = fixture();
    put_role_definition(
        &cs,
        &li,
        &pid,
        "group/team-alpha",
        "member",
        vec![shared_template_grant()],
    );
    let (alice_hash, alice_seg) = make_assignee(&cs, 0xA1);
    let assignment_path = format!(
        "/{}/{}",
        pid,
        path_role_assignment("group/team-alpha", &alice_seg, "member")
    );
    let ctx = build_ctx(
        "assign",
        &assignment_path,
        assign_params("member"),
        Some(wildcard_cap(identity_hash)),
        &pid,
        identity_hash,
    );

    let result = handler.handle(&ctx).await.unwrap();
    assert_eq!(result.status, STATUS_OK, "expected 200, got {}", result.status);

    // Assignment entity is bound at the expected path.
    let assignment_hash = li.get(&assignment_path).expect("assignment bound");
    let assignment_entity = cs.get(&assignment_hash).expect("assignment in store");
    let decoded = RoleAssignmentData::from_entity(&assignment_entity).unwrap();
    assert_eq!(decoded.role, "member");

    // Exactly one role-derived token landed under the pinned R4 path.
    let prefix = format!(
        "/{}/{}",
        pid,
        prefix_role_derived_peer("group/team-alpha", &alice_seg)
    );
    assert_eq!(count_caps(&li, &cs, &prefix), 1);

    // V7 §3.5 (v7.44 MUST): signature bound at the invariant pointer
    // path, NOT a sibling — role-derived caps are transportable chain
    // roots and must be discoverable cross-peer.
    let entries = li.list(&prefix);
    let cap_entry = entries
        .iter()
        .find(|e| {
            cs.get(&e.hash)
                .map(|ent| ent.entity_type == "system/capability/token")
                .unwrap_or(false)
        })
        .expect("cap entry");
    assert!(
        li.get(&invariant_signature_path(&pid, &cap_entry.hash))
            .is_some(),
        "v7.44: role-derived cap sig MUST be at the invariant pointer path"
    );
    assert!(
        li.get(&format!("{}/signature", cap_entry.path)).is_none(),
        "v7.44 cleanup: no sibling `{{capPath}}/signature` copy"
    );

    // Decode the token and confirm template substitution + SI-8 grantee.
    let token_hash = cap_entry.hash;
    let token_entity = cs.get(&token_hash).expect("token in store");
    let token = CapabilityToken::from_entity(&token_entity).unwrap();
    assert_eq!(token.grants.len(), 1);
    assert_eq!(
        token.grants[0].resources.include[0],
        "shared/group/team-alpha/*"
    );
    assert_eq!(
        token.grantee, alice_hash,
        "SI-8: grantee MUST be raw bytes of the identity hash"
    );

    // SI-5 linkage entity at sibling subtree.
    let link_path = format!(
        "/{}/{}",
        pid,
        path_role_derived_link("group/team-alpha", &alice_seg, "member")
    );
    let link_hash = li.get(&link_path).expect("linkage entity bound");
    let link = RoleDerivedTokenLinkData::from_entity(&cs.get(&link_hash).unwrap()).unwrap();
    assert_eq!(link.token_hash, token_hash);
}

#[tokio::test]
async fn assign_returns_404_when_role_not_defined() {
    let (handler, cs, _li, pid, identity_hash) = fixture();
    let (_, alice_seg) = make_assignee(&cs, 0xA2);
    let path = format!(
        "/{}/{}",
        pid,
        path_role_assignment("admin", &alice_seg, "operator")
    );
    let ctx = build_ctx(
        "assign",
        &path,
        assign_params("operator"),
        Some(wildcard_cap(identity_hash)),
        &pid,
        identity_hash,
    );
    let result = handler.handle(&ctx).await.unwrap();
    assert_eq!(result.status, STATUS_NOT_FOUND);
}

#[tokio::test]
async fn assign_rejects_malformed_assignee_segment() {
    let (handler, cs, li, pid, identity_hash) = fixture();
    put_role_definition(&cs, &li, &pid, "admin", "operator", vec![shared_template_grant()]);
    // Garbage hex segment that isn't a valid hash.
    let path = format!(
        "/{}/system/role/admin/assignment/notreallyhex/operator",
        pid
    );
    let ctx = build_ctx(
        "assign",
        &path,
        assign_params("operator"),
        Some(wildcard_cap(identity_hash)),
        &pid,
        identity_hash,
    );
    let result = handler.handle(&ctx).await.unwrap();
    assert_eq!(result.status, 400, "malformed hex segment must 400");
}

#[tokio::test]
async fn assign_rejected_when_role_path_mismatches_params() {
    let (handler, cs, li, pid, identity_hash) = fixture();
    put_role_definition(&cs, &li, &pid, "admin", "operator", vec![shared_template_grant()]);
    let (_, alice_seg) = make_assignee(&cs, 0xA3);
    let path = format!(
        "/{}/{}",
        pid,
        path_role_assignment("admin", &alice_seg, "operator")
    );
    let ctx = build_ctx(
        "assign",
        &path,
        assign_params("auditor"),
        Some(wildcard_cap(identity_hash)),
        &pid,
        identity_hash,
    );
    let result = handler.handle(&ctx).await.unwrap();
    assert_eq!(result.status, 400);
}

#[tokio::test]
async fn assign_rl2_fails_closed_when_caller_authority_insufficient() {
    let (handler, cs, li, pid, identity_hash) = fixture();
    put_role_definition(
        &cs,
        &li,
        &pid,
        "group/team-alpha",
        "member",
        vec![shared_template_grant()],
    );
    let (_, alice_seg) = make_assignee(&cs, 0xA4);
    let path = format!(
        "/{}/{}",
        pid,
        path_role_assignment("group/team-alpha", &alice_seg, "member")
    );
    let narrow_cap = make_caller_cap(
        vec![GrantEntry {
            handlers: PathScope::all(),
            resources: PathScope::all(),
            operations: IdScope::new(vec!["get".into()]),
            peers: Some(IdScope::all()),
            constraints: None,
            allowances: None,
        }],
        identity_hash,
    );
    let ctx = build_ctx(
        "assign",
        &path,
        assign_params("member"),
        Some(narrow_cap),
        &pid,
        identity_hash,
    );
    let result = handler.handle(&ctx).await.unwrap();
    assert_eq!(result.status, STATUS_FORBIDDEN);
    assert!(li.get(&path).is_none());
}

#[tokio::test]
async fn assign_rejected_when_caller_capability_missing() {
    let (handler, cs, li, pid, identity_hash) = fixture();
    put_role_definition(&cs, &li, &pid, "admin", "operator", vec![shared_template_grant()]);
    let (_, alice_seg) = make_assignee(&cs, 0xA5);
    let path = format!(
        "/{}/{}",
        pid,
        path_role_assignment("admin", &alice_seg, "operator")
    );
    let ctx = build_ctx(
        "assign",
        &path,
        assign_params("operator"),
        None,
        &pid,
        identity_hash,
    );
    let result = handler.handle(&ctx).await.unwrap();
    assert_eq!(result.status, STATUS_FORBIDDEN);
}

#[tokio::test]
async fn assign_blocked_by_layer2_exclusion() {
    let (handler, cs, li, pid, identity_hash) = fixture();
    put_role_definition(
        &cs,
        &li,
        &pid,
        "group/team-alpha",
        "member",
        vec![shared_template_grant()],
    );
    let (_, alice_seg) = make_assignee(&cs, 0xA6);
    let dummy = Hash::compute("system/role/exclusion", b"x");
    let exclusion_path = format!(
        "/{}/{}",
        pid,
        path_role_exclusion("group/team-alpha", &alice_seg)
    );
    li.set(&exclusion_path, dummy);

    let assignment_path = format!(
        "/{}/{}",
        pid,
        path_role_assignment("group/team-alpha", &alice_seg, "member")
    );
    let ctx = build_ctx(
        "assign",
        &assignment_path,
        assign_params("member"),
        Some(wildcard_cap(identity_hash)),
        &pid,
        identity_hash,
    );
    let result = handler.handle(&ctx).await.unwrap();
    assert_eq!(result.status, STATUS_FORBIDDEN);
}

#[tokio::test]
async fn unassign_removes_assignment_and_revokes_via_linkage() {
    let (handler, cs, li, pid, identity_hash) = fixture();
    put_role_definition(&cs, &li, &pid, "admin", "operator", vec![shared_template_grant()]);
    let (_, alice_seg) = make_assignee(&cs, 0xA7);
    let assignment_path = format!(
        "/{}/{}",
        pid,
        path_role_assignment("admin", &alice_seg, "operator")
    );
    handler
        .handle(&build_ctx(
            "assign",
            &assignment_path,
            assign_params("operator"),
            Some(wildcard_cap(identity_hash)),
            &pid,
            identity_hash,
        ))
        .await
        .unwrap();
    let prefix = format!("/{}/{}", pid, prefix_role_derived_peer("admin", &alice_seg));
    assert_eq!(count_caps(&li, &cs, &prefix), 1);

    let unassign_ctx = build_ctx(
        "unassign",
        &assignment_path,
        empty_params(),
        Some(wildcard_cap(identity_hash)),
        &pid,
        identity_hash,
    );
    let result = handler.handle(&unassign_ctx).await.unwrap();
    assert_eq!(result.status, STATUS_OK);
    assert!(li.get(&assignment_path).is_none());
    assert!(
        li.list(&prefix).is_empty(),
        "role-derived tokens must be revoked on unassign per IA12 (via SI-5 linkage)"
    );
    let link_path = format!(
        "/{}/{}",
        pid,
        path_role_derived_link("admin", &alice_seg, "operator")
    );
    assert!(li.get(&link_path).is_none(), "linkage entity removed too");
}

#[tokio::test]
async fn exclude_writes_exclusion_no_peer_id_field_and_sweeps_tokens() {
    let (handler, cs, li, pid, identity_hash) = fixture();
    put_role_definition(
        &cs,
        &li,
        &pid,
        "group/team-alpha",
        "member",
        vec![shared_template_grant()],
    );
    let (_, dave_seg) = make_assignee(&cs, 0xD4);
    let assignment_path = format!(
        "/{}/{}",
        pid,
        path_role_assignment("group/team-alpha", &dave_seg, "member")
    );
    handler
        .handle(&build_ctx(
            "assign",
            &assignment_path,
            assign_params("member"),
            Some(wildcard_cap(identity_hash)),
            &pid,
            identity_hash,
        ))
        .await
        .unwrap();
    let derived_prefix = format!(
        "/{}/{}",
        pid,
        prefix_role_derived_peer("group/team-alpha", &dave_seg)
    );
    assert_eq!(count_caps(&li, &cs, &derived_prefix), 1);

    let exclusion_path = format!(
        "/{}/{}",
        pid,
        path_role_exclusion("group/team-alpha", &dave_seg)
    );
    let result = handler
        .handle(&build_ctx(
            "exclude",
            &exclusion_path,
            empty_params(),
            Some(wildcard_cap(identity_hash)),
            &pid,
            identity_hash,
        ))
        .await
        .unwrap();
    assert_eq!(result.status, STATUS_OK);
    assert!(li.list(&derived_prefix).is_empty(),
        "exclude broad sweep removes the role-derived cap (its invariant \
         pointer sig is unbound separately, V7 §3.5 v7.44)");

    // SI-3: exclusion entity has no peer_id body field.
    let exclusion_hash = li.get(&exclusion_path).unwrap();
    let exclusion_entity = cs.get(&exclusion_hash).unwrap();
    let decoded = RoleExclusionData::from_entity(&exclusion_entity).unwrap();
    assert_eq!(decoded.excluded_by, identity_hash);
}

#[tokio::test]
async fn unexclude_removes_entity_does_not_restore_tokens() {
    let (handler, cs, li, pid, identity_hash) = fixture();
    let (_, dave_seg) = make_assignee(&cs, 0xD5);
    let exclusion_path = format!(
        "/{}/{}",
        pid,
        path_role_exclusion("group/team-alpha", &dave_seg)
    );
    let dummy = Hash::compute("system/role/exclusion", b"x");
    li.set(&exclusion_path, dummy);
    assert!(li.get(&exclusion_path).is_some());

    let ctx = build_ctx(
        "unexclude",
        &exclusion_path,
        empty_params(),
        Some(wildcard_cap(identity_hash)),
        &pid,
        identity_hash,
    );
    let result = handler.handle(&ctx).await.unwrap();
    assert_eq!(result.status, STATUS_OK);
    assert!(li.get(&exclusion_path).is_none());
}

#[tokio::test]
async fn multi_role_per_peer_creates_distinct_assignments() {
    let (handler, cs, li, pid, identity_hash) = fixture();
    put_role_definition(&cs, &li, &pid, "admin", "operator", vec![shared_template_grant()]);
    // Different grants for auditor so the resolved cap hashes differ
    // (otherwise content-addressed dedup would collapse them — correct
    // V7 behavior, but obscures the multi-role assertion).
    put_role_definition(
        &cs,
        &li,
        &pid,
        "admin",
        "auditor",
        vec![GrantEntry {
            handlers: PathScope::new(vec!["system/tree".into()]),
            resources: PathScope::new(vec!["shared/{context}/*".into()]),
            operations: IdScope::new(vec!["get".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        }],
    );
    let (_, alice_seg) = make_assignee(&cs, 0xA8);
    let op_path = format!(
        "/{}/{}",
        pid,
        path_role_assignment("admin", &alice_seg, "operator")
    );
    let aud_path = format!(
        "/{}/{}",
        pid,
        path_role_assignment("admin", &alice_seg, "auditor")
    );

    handler
        .handle(&build_ctx(
            "assign",
            &op_path,
            assign_params("operator"),
            Some(wildcard_cap(identity_hash)),
            &pid,
            identity_hash,
        ))
        .await
        .unwrap();
    handler
        .handle(&build_ctx(
            "assign",
            &aud_path,
            assign_params("auditor"),
            Some(wildcard_cap(identity_hash)),
            &pid,
            identity_hash,
        ))
        .await
        .unwrap();

    assert!(li.get(&op_path).is_some());
    assert!(li.get(&aud_path).is_some());
    let prefix = format!("/{}/{}", pid, prefix_role_derived_peer("admin", &alice_seg));
    assert_eq!(count_caps(&li, &cs, &prefix), 2);

    // Both linkage entities must be present (one per role).
    for role in ["operator", "auditor"] {
        let link_path =
            format!("/{}/{}", pid, path_role_derived_link("admin", &alice_seg, role));
        assert!(li.get(&link_path).is_some(), "linkage for {} missing", role);
    }
}

#[tokio::test]
async fn unassign_role_omitted_form_removes_all_roles_for_peer() {
    let (handler, cs, li, pid, identity_hash) = fixture();
    put_role_definition(&cs, &li, &pid, "admin", "operator", vec![shared_template_grant()]);
    put_role_definition(
        &cs,
        &li,
        &pid,
        "admin",
        "auditor",
        vec![shared_template_grant()],
    );
    let (_, alice_seg) = make_assignee(&cs, 0xA9);
    for role in ["operator", "auditor"] {
        let p = format!("/{}/{}", pid, path_role_assignment("admin", &alice_seg, role));
        handler
            .handle(&build_ctx(
                "assign",
                &p,
                assign_params(role),
                Some(wildcard_cap(identity_hash)),
                &pid,
                identity_hash,
            ))
            .await
            .unwrap();
    }
    let all_roles_path = format!(
        "/{}/system/role/admin/assignment/{}",
        pid, alice_seg
    );
    let result = handler
        .handle(&build_ctx(
            "unassign",
            &all_roles_path,
            empty_params(),
            Some(wildcard_cap(identity_hash)),
            &pid,
            identity_hash,
        ))
        .await
        .unwrap();
    assert_eq!(result.status, STATUS_OK);
    for role in ["operator", "auditor"] {
        let p = format!("/{}/{}", pid, path_role_assignment("admin", &alice_seg, role));
        assert!(li.get(&p).is_none(), "assignment {} still present", role);
    }
    let prefix = format!("/{}/{}", pid, prefix_role_derived_peer("admin", &alice_seg));
    assert!(li.list(&prefix).is_empty());
}

// ---------------------------------------------------------------------------
// define + re-derive
// ---------------------------------------------------------------------------

fn define_params(grants: &[GrantEntry]) -> Entity {
    let arr: Vec<Value> = grants.iter().map(encode_grant_entry).collect();
    Entity::new(
        "system/role/define-request",
        to_ecf(&Value::Map(vec![(text("grants"), Value::Array(arr))])),
    )
    .unwrap()
}

#[tokio::test]
async fn define_writes_role_definition_at_resource_path() {
    let (handler, cs, li, pid, identity_hash) = fixture();
    let role_path = format!("/{}/{}", pid, path_role_definition("admin", "operator"));
    let ctx = build_ctx(
        "define",
        &role_path,
        define_params(&[shared_template_grant()]),
        Some(wildcard_cap(identity_hash)),
        &pid,
        identity_hash,
    );
    let result = handler.handle(&ctx).await.unwrap();
    assert_eq!(result.status, STATUS_OK);
    let role_hash = li.get(&role_path).expect("role bound");
    let entity = cs.get(&role_hash).unwrap();
    let decoded = RoleData::from_entity(&entity).unwrap();
    assert_eq!(decoded.name, "operator");
}

#[tokio::test]
async fn define_rl2_fails_closed_when_caller_authority_insufficient() {
    let (handler, _cs, _li, pid, identity_hash) = fixture();
    let role_path = format!("/{}/{}", pid, path_role_definition("admin", "operator"));
    let narrow = make_caller_cap(
        vec![GrantEntry {
            handlers: PathScope::all(),
            resources: PathScope::all(),
            operations: IdScope::new(vec!["get".into()]),
            peers: Some(IdScope::all()),
            constraints: None,
            allowances: None,
        }],
        identity_hash,
    );
    let ctx = build_ctx(
        "define",
        &role_path,
        define_params(&[shared_template_grant()]),
        Some(narrow),
        &pid,
        identity_hash,
    );
    let result = handler.handle(&ctx).await.unwrap();
    assert_eq!(result.status, STATUS_FORBIDDEN);
}

#[tokio::test]
async fn define_rejects_reserved_role_names() {
    let (handler, _cs, _li, pid, identity_hash) = fixture();
    let role_path = format!("/{}/system/role/admin/assignment", pid);
    let ctx = build_ctx(
        "define",
        &role_path,
        define_params(&[shared_template_grant()]),
        Some(wildcard_cap(identity_hash)),
        &pid,
        identity_hash,
    );
    let result = handler.handle(&ctx).await.unwrap();
    assert_eq!(result.status, 400);
}

#[tokio::test]
async fn define_cascades_re_derive_for_existing_assignees() {
    let (handler, cs, li, pid, identity_hash) = fixture();
    put_role_definition(
        &cs,
        &li,
        &pid,
        "admin",
        "operator",
        vec![GrantEntry {
            handlers: PathScope::new(vec!["system/tree".into()]),
            resources: PathScope::new(vec!["shared/{context}/*".into()]),
            operations: IdScope::new(vec!["get".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        }],
    );
    let assignees: Vec<(Hash, String)> = (0..2).map(|i| make_assignee(&cs, 0xB0 + i)).collect();
    for (_, seg) in &assignees {
        let p = format!("/{}/{}", pid, path_role_assignment("admin", seg, "operator"));
        handler
            .handle(&build_ctx(
                "assign",
                &p,
                assign_params("operator"),
                Some(wildcard_cap(identity_hash)),
                &pid,
                identity_hash,
            ))
            .await
            .unwrap();
    }
    // Now `define` to broaden (add `put`).
    let role_path = format!("/{}/{}", pid, path_role_definition("admin", "operator"));
    let result = handler
        .handle(&build_ctx(
            "define",
            &role_path,
            define_params(&[shared_template_grant()]),
            Some(wildcard_cap(identity_hash)),
            &pid,
            identity_hash,
        ))
        .await
        .unwrap();
    assert_eq!(result.status, STATUS_OK);

    for (_, seg) in &assignees {
        let prefix = format!("/{}/{}", pid, prefix_role_derived_peer("admin", seg));
        assert_eq!(count_caps(&li, &cs, &prefix), 1, "single token after re-derive cascade");
        let entries = li.list(&prefix);
        let cap_entry = entries
            .iter()
            .find(|e| {
                cs.get(&e.hash)
                    .map(|ent| ent.entity_type == "system/capability/token")
                    .unwrap_or(false)
            })
            .unwrap();
        let token_entity = cs.get(&cap_entry.hash).unwrap();
        let token = CapabilityToken::from_entity(&token_entity).unwrap();
        assert!(
            token.grants[0]
                .operations
                .include
                .iter()
                .any(|op| op == "put"),
            "broadened grant must include put after re-derive"
        );
    }
}

#[tokio::test]
async fn re_derive_skips_excluded_assignees() {
    let (handler, cs, li, pid, identity_hash) = fixture();
    put_role_definition(&cs, &li, &pid, "admin", "operator", vec![shared_template_grant()]);
    let (_, alice_seg) = make_assignee(&cs, 0xC1);
    let (_, bob_seg) = make_assignee(&cs, 0xC2);
    for seg in [&alice_seg, &bob_seg] {
        let p = format!("/{}/{}", pid, path_role_assignment("admin", seg, "operator"));
        handler
            .handle(&build_ctx(
                "assign",
                &p,
                assign_params("operator"),
                Some(wildcard_cap(identity_hash)),
                &pid,
                identity_hash,
            ))
            .await
            .unwrap();
    }
    // Exclude bob.
    let bob_exclusion = format!("/{}/{}", pid, path_role_exclusion("admin", &bob_seg));
    handler
        .handle(&build_ctx(
            "exclude",
            &bob_exclusion,
            empty_params(),
            Some(wildcard_cap(identity_hash)),
            &pid,
            identity_hash,
        ))
        .await
        .unwrap();

    // Re-derive: alice gets a token; bob does not.
    let role_path = format!("/{}/{}", pid, path_role_definition("admin", "operator"));
    let req = Entity::new(
        "system/role/re-derive-request",
        to_ecf(&Value::Map(vec![(text("role"), text("operator"))])),
    )
    .unwrap();
    let result = handler
        .handle(&build_ctx(
            "re-derive",
            &role_path,
            req,
            Some(wildcard_cap(identity_hash)),
            &pid,
            identity_hash,
        ))
        .await
        .unwrap();
    assert_eq!(result.status, STATUS_OK);

    let alice_prefix = format!("/{}/{}", pid, prefix_role_derived_peer("admin", &alice_seg));
    assert_eq!(count_caps(&li, &cs, &alice_prefix), 1);
    let bob_prefix = format!("/{}/{}", pid, prefix_role_derived_peer("admin", &bob_seg));
    assert!(li.list(&bob_prefix).is_empty());
}

#[tokio::test]
async fn re_derive_404_when_role_not_defined() {
    let (handler, _cs, _li, pid, identity_hash) = fixture();
    let role_path = format!("/{}/{}", pid, path_role_definition("admin", "ghost"));
    let req = Entity::new(
        "system/role/re-derive-request",
        to_ecf(&Value::Map(vec![(text("role"), text("ghost"))])),
    )
    .unwrap();
    let result = handler
        .handle(&build_ctx(
            "re-derive",
            &role_path,
            req,
            Some(wildcard_cap(identity_hash)),
            &pid,
            identity_hash,
        ))
        .await
        .unwrap();
    assert_eq!(result.status, STATUS_NOT_FOUND);
}

// ---------------------------------------------------------------------------
// delegate (v1.6: locality, scope-literal, parent-via-linkage)
// ---------------------------------------------------------------------------

fn delegate_params(
    delegate: Hash,
    context: &str,
    role: &str,
    scope: &[GrantEntry],
    expires_at: Option<u64>,
) -> Entity {
    let scope_arr: Vec<Value> = scope.iter().map(encode_grant_entry).collect();
    let mut fields = vec![
        (text("context"), text(context)),
        (
            text("delegate"),
            Value::Bytes(delegate.to_bytes().to_vec()),
        ),
        (text("role"), text(role)),
        (text("scope"), Value::Array(scope_arr)),
    ];
    if let Some(e) = expires_at {
        fields.push((text("expires_at"), entity_ecf::integer(e as i64)));
    }
    Entity::new("system/role/delegate-request", to_ecf(&Value::Map(fields))).unwrap()
}

/// SI-19: in v1.6, `:delegate` runs on the delegator's own peer. The
/// fixture's local peer IS the delegator, so we assign the local peer to
/// the role, then issue a delegation to a separate peer.
#[tokio::test]
async fn delegate_issues_subset_cap_rooted_at_local_peer() {
    let (handler, cs, li, pid, identity_hash) = fixture();
    put_role_definition(
        &cs,
        &li,
        &pid,
        "group/team-alpha",
        "member",
        vec![shared_template_grant()],
    );
    // Assign the LOCAL peer (delegator) to the member role.
    let local_seg = peer_segment_from_hash(&identity_hash);
    let local_assignment_path = format!(
        "/{}/{}",
        pid,
        path_role_assignment("group/team-alpha", &local_seg, "member")
    );
    handler
        .handle(&build_ctx(
            "assign",
            &local_assignment_path,
            assign_params("member"),
            Some(wildcard_cap(identity_hash)),
            &pid,
            identity_hash,
        ))
        .await
        .unwrap();

    let (carol_hash, carol_seg) = make_assignee(&cs, 0xC0);

    // Literal scope (no template variables — SI-20).
    let scope = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec!["shared/group/team-alpha/*".into()]),
        operations: IdScope::new(vec!["get".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];

    let ctx = build_ctx(
        "delegate",
        "ignored",
        delegate_params(carol_hash, "group/team-alpha", "member", &scope, None),
        Some(wildcard_cap(identity_hash)),
        &pid,
        identity_hash,
    );
    let result = handler.handle(&ctx).await.unwrap();
    assert_eq!(result.status, STATUS_OK, "delegate failed: {}", result.status);

    let prefix = format!(
        "/{}/{}",
        pid,
        prefix_role_derived_peer("group/team-alpha", &carol_seg)
    );
    assert_eq!(count_caps(&li, &cs, &prefix), 1);
    let entries = li.list(&prefix);
    let cap_entry = entries
        .iter()
        .find(|e| {
            cs.get(&e.hash)
                .map(|ent| ent.entity_type == "system/capability/token")
                .unwrap_or(false)
        })
        .unwrap();
    let token = CapabilityToken::from_entity(&cs.get(&cap_entry.hash).unwrap()).unwrap();
    match token.granter {
        Granter::Single(h) => assert_eq!(h, identity_hash, "granter is delegator (= local peer)"),
        _ => panic!("expected single-sig granter"),
    }
    assert_eq!(token.grantee, carol_hash);
    assert!(token.parent.is_some(), "delegation cap parent must be linkage cap");
    assert_eq!(token.grants[0].operations.include, vec!["get".to_string()]);

    // v7.44: delegation cap sig at the invariant pointer path (no sibling).
    assert!(
        li.get(&invariant_signature_path(&pid, &cap_entry.hash))
            .is_some(),
        "delegation cap sig MUST be at the invariant pointer path"
    );
    assert!(
        li.get(&format!("{}/signature", cap_entry.path)).is_none(),
        "v7.44 cleanup: no sibling sig copy for delegation cap"
    );
}

#[tokio::test]
async fn delegate_locality_invariant_rejects_remote_caller() {
    let (handler, cs, li, pid, identity_hash) = fixture();
    put_role_definition(&cs, &li, &pid, "admin", "operator", vec![shared_template_grant()]);
    let local_seg = peer_segment_from_hash(&identity_hash);
    let assignment_path = format!(
        "/{}/{}",
        pid,
        path_role_assignment("admin", &local_seg, "operator")
    );
    handler
        .handle(&build_ctx(
            "assign",
            &assignment_path,
            assign_params("operator"),
            Some(wildcard_cap(identity_hash)),
            &pid,
            identity_hash,
        ))
        .await
        .unwrap();
    let (carol_hash, _) = make_assignee(&cs, 0xC4);
    let (foreign_hash, _) = make_assignee(&cs, 0xF0);

    let scope = vec![shared_template_grant()];
    let mut ctx = build_ctx(
        "delegate",
        "ignored",
        delegate_params(carol_hash, "admin", "operator", &scope, None),
        Some(wildcard_cap(identity_hash)),
        &pid,
        identity_hash,
    );
    // SI-19: caller is `foreign_hash` (NOT the local peer).
    ctx.author = Some(foreign_hash);
    let result = handler.handle(&ctx).await.unwrap();
    assert_eq!(
        result.status, 400,
        "SI-19: must be 400 (precondition), not 403 (permission)"
    );
}

#[tokio::test]
async fn delegate_rejected_when_delegator_does_not_hold_role() {
    let (handler, cs, li, pid, identity_hash) = fixture();
    put_role_definition(&cs, &li, &pid, "admin", "operator", vec![shared_template_grant()]);
    // Local peer (delegator) does NOT have an assignment.
    let (carol_hash, _) = make_assignee(&cs, 0xC5);
    // SI-20: scope must be literal (no `{context}` substrings).
    let scope = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec!["shared/admin/*".into()]),
        operations: IdScope::new(vec!["get".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];
    let ctx = build_ctx(
        "delegate",
        "ignored",
        delegate_params(carol_hash, "admin", "operator", &scope, None),
        Some(wildcard_cap(identity_hash)),
        &pid,
        identity_hash,
    );
    let result = handler.handle(&ctx).await.unwrap();
    assert_eq!(result.status, STATUS_FORBIDDEN);
}

#[tokio::test]
async fn delegate_rejected_when_scope_amplifies_delegator_authority() {
    let (handler, cs, li, pid, identity_hash) = fixture();
    put_role_definition(
        &cs,
        &li,
        &pid,
        "admin",
        "operator",
        vec![GrantEntry {
            handlers: PathScope::new(vec!["system/tree".into()]),
            resources: PathScope::new(vec!["shared/{context}/*".into()]),
            operations: IdScope::new(vec!["get".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        }],
    );
    let local_seg = peer_segment_from_hash(&identity_hash);
    let assignment_path = format!(
        "/{}/{}",
        pid,
        path_role_assignment("admin", &local_seg, "operator")
    );
    handler
        .handle(&build_ctx(
            "assign",
            &assignment_path,
            assign_params("operator"),
            Some(wildcard_cap(identity_hash)),
            &pid,
            identity_hash,
        ))
        .await
        .unwrap();
    let (carol_hash, _) = make_assignee(&cs, 0xC6);

    // Try to delegate `put` (delegator only has `get`).
    let bigger_scope = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec!["shared/admin/*".into()]),
        operations: IdScope::new(vec!["get".into(), "put".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];
    let ctx = build_ctx(
        "delegate",
        "ignored",
        delegate_params(carol_hash, "admin", "operator", &bigger_scope, None),
        Some(wildcard_cap(identity_hash)),
        &pid,
        identity_hash,
    );
    let result = handler.handle(&ctx).await.unwrap();
    assert_eq!(result.status, STATUS_FORBIDDEN);
}

#[tokio::test]
async fn delegate_rejected_when_delegate_excluded() {
    let (handler, cs, li, pid, identity_hash) = fixture();
    put_role_definition(&cs, &li, &pid, "admin", "operator", vec![shared_template_grant()]);
    let local_seg = peer_segment_from_hash(&identity_hash);
    let assignment_path = format!(
        "/{}/{}",
        pid,
        path_role_assignment("admin", &local_seg, "operator")
    );
    handler
        .handle(&build_ctx(
            "assign",
            &assignment_path,
            assign_params("operator"),
            Some(wildcard_cap(identity_hash)),
            &pid,
            identity_hash,
        ))
        .await
        .unwrap();
    let (carol_hash, carol_seg) = make_assignee(&cs, 0xC7);
    // Pre-exclude carol.
    let dummy = Hash::compute("system/role/exclusion", b"x");
    let exclusion_path =
        format!("/{}/{}", pid, path_role_exclusion("admin", &carol_seg));
    li.set(&exclusion_path, dummy);

    // SI-20: scope must be literal.
    let scope = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec!["shared/admin/*".into()]),
        operations: IdScope::new(vec!["get".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];
    let ctx = build_ctx(
        "delegate",
        "ignored",
        delegate_params(carol_hash, "admin", "operator", &scope, None),
        Some(wildcard_cap(identity_hash)),
        &pid,
        identity_hash,
    );
    let result = handler.handle(&ctx).await.unwrap();
    assert_eq!(result.status, STATUS_FORBIDDEN);
}

#[tokio::test]
async fn delegate_rejected_when_scope_contains_template() {
    let (handler, cs, li, pid, identity_hash) = fixture();
    put_role_definition(&cs, &li, &pid, "admin", "operator", vec![shared_template_grant()]);
    let local_seg = peer_segment_from_hash(&identity_hash);
    let assignment_path = format!(
        "/{}/{}",
        pid,
        path_role_assignment("admin", &local_seg, "operator")
    );
    handler
        .handle(&build_ctx(
            "assign",
            &assignment_path,
            assign_params("operator"),
            Some(wildcard_cap(identity_hash)),
            &pid,
            identity_hash,
        ))
        .await
        .unwrap();
    let (carol_hash, _) = make_assignee(&cs, 0xC8);

    // SI-20: scope contains `{context}` template — must reject 400.
    let templated = vec![shared_template_grant()];
    let ctx = build_ctx(
        "delegate",
        "ignored",
        delegate_params(carol_hash, "admin", "operator", &templated, None),
        Some(wildcard_cap(identity_hash)),
        &pid,
        identity_hash,
    );
    let result = handler.handle(&ctx).await.unwrap();
    assert_eq!(result.status, 400, "SI-20: scope_must_be_literal returns 400");
}

// ---------------------------------------------------------------------------
// v1.7 regressions (PROPOSAL-ROLE-V1.7-SPEC-FIXES + V7 v7.38 §5.6)
// ---------------------------------------------------------------------------

/// SI-15 v1.7: re-derive surfaces both successes and skipped grantees in
/// one call. The cascade MUST NOT abort just because some assignees fail
/// per-peer RL2.
///
/// Setup: two assignees with different identity hashes. Caller cap is a
/// wildcard (so both pass per-peer RL2 — proves the cascade completes).
/// We deliberately don't construct a partial-coverage caller cap because
/// the existing per-assignee RL2 already routes failures through
/// `skipped_grantees` and the surface here is "no cascade-wide abort".
#[tokio::test]
async fn re_derive_does_not_abort_cascade_when_some_assignees_skipped() {
    let (handler, cs, li, pid, identity_hash) = fixture();
    put_role_definition(&cs, &li, &pid, "admin", "operator", vec![shared_template_grant()]);
    let (_, alice_seg) = make_assignee(&cs, 0xE1);
    let (_, bob_seg) = make_assignee(&cs, 0xE2);
    for seg in [&alice_seg, &bob_seg] {
        let p = format!("/{}/{}", pid, path_role_assignment("admin", seg, "operator"));
        handler
            .handle(&build_ctx(
                "assign",
                &p,
                assign_params("operator"),
                Some(wildcard_cap(identity_hash)),
                &pid,
                identity_hash,
            ))
            .await
            .unwrap();
    }

    // Re-derive — both assignees should land at exactly one cap each.
    // The key v1.7 assertion: status is 200, NOT 403, even though we're
    // exercising the cascade path that previously aborted.
    let role_path = format!("/{}/{}", pid, path_role_definition("admin", "operator"));
    let req = Entity::new(
        "system/role/re-derive-request",
        to_ecf(&Value::Map(vec![(text("role"), text("operator"))])),
    )
    .unwrap();
    let result = handler
        .handle(&build_ctx(
            "re-derive",
            &role_path,
            req,
            Some(wildcard_cap(identity_hash)),
            &pid,
            identity_hash,
        ))
        .await
        .unwrap();
    assert_eq!(result.status, STATUS_OK, "v1.7 SI-15: cascade MUST NOT abort");
    for seg in [&alice_seg, &bob_seg] {
        let prefix = format!("/{}/{}", pid, prefix_role_derived_peer("admin", seg));
        assert_eq!(count_caps(&li, &cs, &prefix), 1, "{} got their re-derived cap", seg);
    }
}

/// V7 §3.5 (v7.44 MUST) cross-impl: every issued role-derived cap MUST
/// have its signature discoverable at the invariant pointer path
/// `/{signer}/system/signature/{cap_hash_hex}` (role-derived caps are
/// transportable chain roots, ROLE PR-1). Negative control: the legacy
/// extension-private sibling `{capPath}/signature` MUST be absent (v7.44
/// cleanup — invariant pointer is the sole canonical location).
#[tokio::test]
async fn role_derived_cap_has_invariant_signature_binding() {
    let (handler, cs, li, pid, identity_hash) = fixture();
    put_role_definition(&cs, &li, &pid, "admin", "operator", vec![shared_template_grant()]);
    let (_, alice_seg) = make_assignee(&cs, 0xE3);
    let assignment_path = format!(
        "/{}/{}",
        pid,
        path_role_assignment("admin", &alice_seg, "operator")
    );
    handler
        .handle(&build_ctx(
            "assign",
            &assignment_path,
            assign_params("operator"),
            Some(wildcard_cap(identity_hash)),
            &pid,
            identity_hash,
        ))
        .await
        .unwrap();

    let prefix = format!("/{}/{}", pid, prefix_role_derived_peer("admin", &alice_seg));
    let entries = li.list(&prefix);
    let cap_entry = entries
        .iter()
        .find(|e| {
            cs.get(&e.hash)
                .map(|ent| ent.entity_type == "system/capability/token")
                .unwrap_or(false)
        })
        .expect("cap binding present");
    let sig_hash = li
        .get(&invariant_signature_path(&pid, &cap_entry.hash))
        .expect("v7.44: signature MUST be bound at the invariant pointer path");
    let sig_entity = cs.get(&sig_hash).expect("sig entity in store");
    assert_eq!(sig_entity.entity_type, "system/signature");
    // Negative control: the legacy sibling copy MUST be gone.
    assert!(
        li.get(&format!("{}/signature", cap_entry.path)).is_none(),
        "v7.44 cleanup: extension-private sibling sig path MUST be absent"
    );
}

/// §5.3 v1.7 MIN_DEFINED: when caller has finite expires_at, the issued
/// cap's expires_at MUST be ≤ caller's expires_at (and not nil).
/// Without this, V7 §5.6 chain validation rejects the cap at use-time
/// even though RL2 grant-coverage passed at issue-time.
#[tokio::test]
async fn issued_cap_inherits_caller_expires_at() {
    let (handler, cs, li, pid, identity_hash) = fixture();
    put_role_definition(&cs, &li, &pid, "admin", "operator", vec![shared_template_grant()]);
    let (_, alice_seg) = make_assignee(&cs, 0xE4);
    let assignment_path = format!(
        "/{}/{}",
        pid,
        path_role_assignment("admin", &alice_seg, "operator")
    );

    // Caller cap with explicit finite expires_at.
    let caller_expires = 1_900_000_000_000u64;
    let mut caller = wildcard_cap(identity_hash);
    caller.expires_at = Some(caller_expires);

    let result = handler
        .handle(&build_ctx(
            "assign",
            &assignment_path,
            assign_params("operator"),
            Some(caller),
            &pid,
            identity_hash,
        ))
        .await
        .unwrap();
    assert_eq!(result.status, STATUS_OK);

    let prefix = format!("/{}/{}", pid, prefix_role_derived_peer("admin", &alice_seg));
    let entries = li.list(&prefix);
    let cap_entry = entries
        .iter()
        .find(|e| {
            cs.get(&e.hash)
                .map(|ent| ent.entity_type == "system/capability/token")
                .unwrap_or(false)
        })
        .unwrap();
    let token = CapabilityToken::from_entity(&cs.get(&cap_entry.hash).unwrap()).unwrap();
    let exp = token.expires_at.expect(
        "v1.7 §5.3: cap MUST have finite expires_at when caller cap is finite (not nil)",
    );
    assert!(
        exp <= caller_expires,
        "v1.7 §5.3 MIN_DEFINED: cap.expires_at ({}) MUST NOT exceed caller.expires_at ({})",
        exp, caller_expires
    );
}

/// §5.3 v1.7 MIN_DEFINED with role TTL: when role.metadata.ttl is set
/// and is shorter than the caller's expires_at, the issued cap inherits
/// the role's TTL bound (now + ttl).
#[tokio::test]
async fn issued_cap_respects_role_ttl_when_shorter_than_caller() {
    let (handler, cs, li, pid, identity_hash) = fixture();

    // Role definition with explicit metadata.ttl = 1 hour (3,600,000 ms).
    let one_hour_ms = 3_600_000u64;
    let role = RoleData {
        name: "operator".into(),
        grants: vec![shared_template_grant()],
        metadata: Some(vec![(
            entity_ecf::text("ttl"),
            entity_ecf::integer(one_hour_ms as i64),
        )]),
    };
    let entity = role.to_entity().unwrap();
    let hash = cs.put(entity).unwrap();
    let role_path = format!("/{}/{}", pid, path_role_definition("admin", "operator"));
    li.set(&role_path, hash);

    let (_, alice_seg) = make_assignee(&cs, 0xE5);
    let assignment_path = format!(
        "/{}/{}",
        pid,
        path_role_assignment("admin", &alice_seg, "operator")
    );

    // Caller cap with very-far-future expires_at — role TTL should
    // dominate via MIN_DEFINED.
    let mut caller = wildcard_cap(identity_hash);
    caller.expires_at = Some(9_999_999_999_999u64);

    let now_before = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    handler
        .handle(&build_ctx(
            "assign",
            &assignment_path,
            assign_params("operator"),
            Some(caller),
            &pid,
            identity_hash,
        ))
        .await
        .unwrap();
    let now_after = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let prefix = format!("/{}/{}", pid, prefix_role_derived_peer("admin", &alice_seg));
    let entries = li.list(&prefix);
    let cap_entry = entries
        .iter()
        .find(|e| {
            cs.get(&e.hash)
                .map(|ent| ent.entity_type == "system/capability/token")
                .unwrap_or(false)
        })
        .unwrap();
    let token = CapabilityToken::from_entity(&cs.get(&cap_entry.hash).unwrap()).unwrap();
    let exp = token.expires_at.expect("role TTL forces finite expires_at");
    assert!(
        exp >= now_before + one_hour_ms && exp <= now_after + one_hour_ms,
        "v1.7 §5.3: cap.expires_at must be ~now+ttl (got {})",
        exp
    );
}

/// V7 §5.6 strict (TV-RD-NIL-EXPIRY shape): is_attenuated rejects
/// `child.expires_at == None && parent.expires_at == Some`. Sanity-check
/// the existing capability impl behaves correctly for this case (Rust
/// is the conformant impl per the v1.7 handoff doc; this test just
/// pins the behavior).
#[test]
fn is_attenuated_rejects_nil_child_against_finite_parent() {
    use entity_capability::is_attenuated;
    let parent = CapabilityToken {
        grants: vec![GrantEntry {
            handlers: PathScope::all(),
            resources: PathScope::all(),
            operations: IdScope::all(),
            peers: Some(IdScope::all()),
            constraints: None,
            allowances: None,
        }],
        granter: Granter::Single(Hash::zero()),
        grantee: Hash::zero(),
        parent: None,
        created_at: 0,
        expires_at: Some(1_000_000),
        not_before: None,
        delegation_caveats: None,
    };
    let mut child = parent.clone();
    child.expires_at = None;
    assert!(
        !is_attenuated(&child, &parent, "test_peer"),
        "V7 §5.6: nil-child against finite-parent MUST fail is_attenuated"
    );
}

// -------------------------------------------------------------------
// PR-2 / PR-6 conformance — PROPOSAL-ROLE-V2.0-PRODUCTION-READINESS
// SEC-2 assign↔exclude atomicity (TV-RD-RACE-AE)
// -------------------------------------------------------------------

/// TV-RD-RACE-AE: concurrent :assign + :exclude must NEVER leave a state
/// where an exclusion entity is bound AND a role-derived cap for the same
/// (context, peer) is also bound. The forbidden state is the
/// privilege-escalation outcome the SEC-2 race produced before the
/// post-issue rollback landed.
///
/// Multi-thread runtime is required to surface the race — a single-threaded
/// runtime would serialize the two `.await` points and never interleave the
/// `is_excluded` pre-check with the `:exclude` sweep. 100 iterations matches
/// Go's `TestSEC2_AssignExcludeRace` shape from
/// `entity-core-go/ext/role/security_test.go`.
///
/// Future work: complementary loom-based concurrency-permutation testing —
/// see `docs/BACKLOG.md`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pr2_tv_rd_race_ae_assign_vs_exclude_atomicity() {
    const ITERATIONS: usize = 100;
    let (handler, cs, li, pid, identity_hash) = fixture();
    put_role_definition(
        &cs,
        &li,
        &pid,
        "race-ctx",
        "operator",
        vec![shared_template_grant()],
    );

    for i in 0..ITERATIONS {
        // Fresh assignee per iteration so prior iterations' state can't mask
        // the bug. Seed bytes = iteration counter spread across a 32-byte key.
        let seed_byte = (i as u8).wrapping_add(0x10);
        let (alice_hash, alice_seg) = make_assignee(&cs, seed_byte);

        let assignment_path = format!(
            "/{}/{}",
            pid,
            path_role_assignment("race-ctx", &alice_seg, "operator")
        );
        let exclusion_path = format!(
            "/{}/{}",
            pid,
            path_role_exclusion("race-ctx", &alice_seg)
        );
        let cap_prefix = format!(
            "/{}/{}",
            pid,
            prefix_role_derived_peer("race-ctx", &alice_seg)
        );

        // Two contending tasks. Race the dispatch through the role handler
        // on independent worker threads.
        let h1 = handler.clone();
        let h2 = handler.clone();
        let pid1 = pid.clone();
        let pid2 = pid.clone();
        let assignment_path_for_assign = assignment_path.clone();
        let exclusion_path_for_exclude = exclusion_path.clone();

        let assign_task = tokio::spawn(async move {
            let ctx = build_ctx(
                "assign",
                &assignment_path_for_assign,
                assign_params("operator"),
                Some(wildcard_cap(identity_hash)),
                &pid1,
                identity_hash,
            );
            let _ = h1.handle(&ctx).await;
        });
        let exclude_task = tokio::spawn(async move {
            let ctx = build_ctx(
                "exclude",
                &exclusion_path_for_exclude,
                empty_params(),
                Some(wildcard_cap(identity_hash)),
                &pid2,
                identity_hash,
            );
            let _ = h2.handle(&ctx).await;
        });
        let _ = tokio::join!(assign_task, exclude_task);

        // Invariant: exclusion bound ⇒ no role-derived cap for this peer.
        let exclusion_bound = li.get(&exclusion_path).is_some();
        let cap_count = count_caps(&li, &cs, &cap_prefix);
        if exclusion_bound {
            assert_eq!(
                cap_count, 0,
                "iteration {i}: SEC-2 violation — exclusion bound at {exclusion_path} \
                 but {cap_count} role-derived cap(s) survive at {cap_prefix} \
                 (assignee hash: {alice_hash:?})"
            );
        }
        // The reverse is allowed: cap exists with no exclusion (assign won).
    }
}

// -------------------------------------------------------------------
// PR-1 / PR-6 conformance — PROPOSAL-ROLE-V2.0-PRODUCTION-READINESS
// (role-derived caps as root caps; delegation chain depth)
// -------------------------------------------------------------------

/// TV-RD-NON-DEV-PEER (unit-level): role-derived caps issued by `:assign`
/// MUST be root caps (`parent: null`). This is the structural property that
/// makes use-time chain validation succeed under a narrowed handler grant —
/// pre-PR-1 the cap had `parent: handler_grant_hash` and chain-walk would
/// reject it on a non-dev peer where `is_attenuated(role_grants, handler_grant)`
/// returns false. The wire-level non-dev-peer round-trip is exercised by the
/// Go validator suite; this test pins the local invariant.
#[tokio::test]
async fn pr1_assign_role_derived_cap_is_root_cap() {
    let (handler, cs, li, pid, identity_hash) = fixture();
    put_role_definition(
        &cs,
        &li,
        &pid,
        "group/team-alpha",
        "member",
        vec![shared_template_grant()],
    );
    let (_, alice_seg) = make_assignee(&cs, 0xA1);
    let assignment_path = format!(
        "/{}/{}",
        pid,
        path_role_assignment("group/team-alpha", &alice_seg, "member")
    );
    let result = handler
        .handle(&build_ctx(
            "assign",
            &assignment_path,
            assign_params("member"),
            Some(wildcard_cap(identity_hash)),
            &pid,
            identity_hash,
        ))
        .await
        .unwrap();
    assert_eq!(result.status, STATUS_OK);

    let prefix = format!(
        "/{}/{}",
        pid,
        prefix_role_derived_peer("group/team-alpha", &alice_seg)
    );
    let entries = li.list(&prefix);
    let cap_entry = entries
        .iter()
        .find(|e| {
            cs.get(&e.hash)
                .map(|ent| ent.entity_type == "system/capability/token")
                .unwrap_or(false)
        })
        .expect("role-derived cap entry");
    let token = CapabilityToken::from_entity(&cs.get(&cap_entry.hash).unwrap()).unwrap();
    assert_eq!(
        token.parent, None,
        "PR-1: role-derived cap MUST be a root cap (parent: null) — see \
         PROPOSAL-ROLE-V2.0-PRODUCTION-READINESS §2.4"
    );
    match token.granter {
        Granter::Single(h) => assert_eq!(
            h, identity_hash,
            "granter is the local peer's identity-entity content hash (§2.2)"
        ),
        _ => panic!("expected single-sig granter"),
    }
}

/// TV-RD-DELEGATE-CHAIN-DEPTH: with PR-1, delegation chains collapse to
/// depth 2 (delegation cap → role-derived root cap). Depth convention per
/// PR-6: link count from leaf to root, root has depth 1. Pre-PR-1 was
/// depth 3 (delegation → role-derived → handler-grant root).
#[tokio::test]
async fn pr1_delegate_chain_depth_is_two() {
    let (handler, cs, li, pid, identity_hash) = fixture();
    put_role_definition(
        &cs,
        &li,
        &pid,
        "group/team-alpha",
        "member",
        vec![shared_template_grant()],
    );

    // Assign the LOCAL peer (delegator) to the member role.
    let local_seg = peer_segment_from_hash(&identity_hash);
    let local_assignment_path = format!(
        "/{}/{}",
        pid,
        path_role_assignment("group/team-alpha", &local_seg, "member")
    );
    handler
        .handle(&build_ctx(
            "assign",
            &local_assignment_path,
            assign_params("member"),
            Some(wildcard_cap(identity_hash)),
            &pid,
            identity_hash,
        ))
        .await
        .unwrap();

    let (carol_hash, carol_seg) = make_assignee(&cs, 0xC0);
    let scope = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec!["shared/group/team-alpha/*".into()]),
        operations: IdScope::new(vec!["get".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];
    handler
        .handle(&build_ctx(
            "delegate",
            "ignored",
            delegate_params(carol_hash, "group/team-alpha", "member", &scope, None),
            Some(wildcard_cap(identity_hash)),
            &pid,
            identity_hash,
        ))
        .await
        .unwrap();

    // Walk the delegation cap's parent chain: delegation → role-derived → null.
    let carol_prefix = format!(
        "/{}/{}",
        pid,
        prefix_role_derived_peer("group/team-alpha", &carol_seg)
    );
    let delegation_cap_hash = li
        .list(&carol_prefix)
        .into_iter()
        .find(|e| {
            cs.get(&e.hash)
                .map(|ent| ent.entity_type == "system/capability/token")
                .unwrap_or(false)
        })
        .expect("delegation cap")
        .hash;

    let mut depth = 0;
    let mut cursor = Some(delegation_cap_hash);
    while let Some(h) = cursor {
        depth += 1;
        let entity = cs.get(&h).expect("cap in store");
        let token = CapabilityToken::from_entity(&entity).unwrap();
        cursor = token.parent;
        assert!(depth <= 8, "chain depth runaway — guard against cycles");
    }
    assert_eq!(
        depth, 2,
        "PR-1: delegation chain depth MUST be 2 (delegation → role-derived root)"
    );
}

#[tokio::test]
async fn unknown_op_returns_400() {
    let (handler, _cs, _li, pid, identity_hash) = fixture();
    let ctx = build_ctx(
        "frobnicate",
        "system/role/admin/assignment/00aa/operator",
        empty_params(),
        Some(wildcard_cap(identity_hash)),
        &pid,
        identity_hash,
    );
    let result = handler.handle(&ctx).await.unwrap();
    assert_eq!(result.status, 400);
}

// ===========================================================================
// EXTENSION-ROLE §4.7 — initial-grant-policy resolver dispatch
// (recognize-on-attestation).
// ===========================================================================

mod policy_tests {
    use super::*;
    use crate::data::{
        RoleInitialGrantPolicyData, MODE_ANONYMOUS_ALLOW,
        MODE_RECOGNIZE_ON_ATTESTATION,
    };
    use crate::policy::{resolve_grants, PolicyResolverDeps};
    use entity_attestation::{AttestationData, AttestationIndex};

    fn make_deps(
        cs: Arc<dyn ContentStore>,
        li: Arc<dyn LocationIndex>,
        pid: String,
    ) -> (PolicyResolverDeps, Arc<AttestationIndex>) {
        let idx = Arc::new(AttestationIndex::new());
        let deps = PolicyResolverDeps {
            content_store: cs,
            location_index: li,
            attestation_index: idx.clone(),
            local_peer_id: pid,
        };
        (deps, idx)
    }

    fn put_policy(
        cs: &Arc<dyn ContentStore>,
        li: &Arc<dyn LocationIndex>,
        pid: &str,
        policy: &RoleInitialGrantPolicyData,
    ) {
        let entity = policy.to_entity().unwrap();
        let hash = cs.put(entity).unwrap();
        li.set(&format!("/{}/system/role/initial-grant-policy", pid), hash);
    }

    fn put_peer_config_with_quorum(
        cs: &Arc<dyn ContentStore>,
        li: &Arc<dyn LocationIndex>,
        pid: &str,
        trusts_quorum: Hash,
    ) {
        let data = to_ecf(&Value::Map(vec![
            (text("bindings"), Value::Array(vec![])),
            (text("controller_grants"), Value::Array(vec![])),
            (
                text("trusts_quorum"),
                Value::Bytes(trusts_quorum.to_bytes().to_vec()),
            ),
        ]));
        let entity = Entity::new("system/identity/peer-config", data).unwrap();
        let hash = cs.put(entity).unwrap();
        li.set(&format!("/{}/system/identity/peer-config", pid), hash);
    }

    fn guest_grants() -> Vec<GrantEntry> {
        vec![GrantEntry {
            handlers: PathScope::new(vec!["system/tree".into()]),
            resources: PathScope::new(vec!["shared/public/*".into()]),
            operations: IdScope::new(vec!["get".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        }]
    }

    fn put_identity_cert(
        cs: &Arc<dyn ContentStore>,
        idx: &Arc<AttestationIndex>,
        attesting: Hash,
        attested: Hash,
        function: &str,
    ) -> Hash {
        let att = AttestationData {
            attesting,
            attested,
            properties: vec![
                (
                    ciborium::Value::Text("function".into()),
                    ciborium::Value::Text(function.into()),
                ),
                (
                    ciborium::Value::Text("kind".into()),
                    ciborium::Value::Text("identity-cert".into()),
                ),
                (
                    ciborium::Value::Text("mode".into()),
                    ciborium::Value::Text("public".into()),
                ),
            ],
            supersedes: None,
            not_before: None,
            expires_at: None,
        };
        let entity = att.to_entity().unwrap();
        let hash = entity.content_hash;
        cs.put(entity).unwrap();
        idx.insert(hash, att);
        hash
    }

    #[test]
    fn anonymous_deny_returns_none_when_policy_absent() {
        let (_h, cs, li, pid, _ih) = fixture();
        let (deps, _idx) = make_deps(cs, li, pid);
        let connecting = Hash::compute("system/peer", b"some-peer");
        assert!(resolve_grants(&deps, &connecting).is_none());
    }

    #[test]
    fn anonymous_allow_returns_role_grants_for_unknown_peer() {
        let (_h, cs, li, pid, _ih) = fixture();
        put_role_definition(&cs, &li, &pid, "public", "guest", guest_grants());
        put_policy(
            &cs,
            &li,
            &pid,
            &RoleInitialGrantPolicyData {
                unknown_peer: MODE_ANONYMOUS_ALLOW.into(),
                default_role: Some("guest".into()),
                default_context: Some("public".into()),
                identity_required: false,
            },
        );
        let (deps, _idx) = make_deps(cs, li, pid);
        let connecting = Hash::compute("system/peer", b"unknown");
        let grants = resolve_grants(&deps, &connecting).unwrap();
        assert_eq!(grants, guest_grants());
    }

    #[test]
    fn anonymous_allow_falls_through_when_role_def_missing() {
        let (_h, cs, li, pid, _ih) = fixture();
        put_policy(
            &cs,
            &li,
            &pid,
            &RoleInitialGrantPolicyData {
                unknown_peer: MODE_ANONYMOUS_ALLOW.into(),
                default_role: Some("guest".into()),
                default_context: Some("public".into()),
                identity_required: false,
            },
        );
        let (deps, _idx) = make_deps(cs, li, pid);
        let connecting = Hash::compute("system/peer", b"unknown");
        assert!(resolve_grants(&deps, &connecting).is_none());
    }

    #[test]
    fn recognize_on_attest_positive_returns_role_grants() {
        let (_h, cs, li, pid, _ih) = fixture();
        let quorum_id = Hash::compute("system/quorum", b"quorum-A");
        put_peer_config_with_quorum(&cs, &li, &pid, quorum_id);
        put_role_definition(&cs, &li, &pid, "public", "guest", guest_grants());
        put_policy(
            &cs,
            &li,
            &pid,
            &RoleInitialGrantPolicyData {
                unknown_peer: MODE_RECOGNIZE_ON_ATTESTATION.into(),
                default_role: Some("guest".into()),
                default_context: Some("public".into()),
                identity_required: true,
            },
        );

        let controller_hash = Hash::compute("system/peer", b"controller");
        let connecting = Hash::compute("system/peer", b"connecting-agent");
        let (deps, idx) = make_deps(cs.clone(), li.clone(), pid.clone());
        put_identity_cert(&cs, &idx, quorum_id, controller_hash, "controller");
        put_identity_cert(&cs, &idx, controller_hash, connecting, "agent");

        let grants = resolve_grants(&deps, &connecting).unwrap();
        assert_eq!(grants, guest_grants());
    }

    #[test]
    fn recognize_on_attest_bare_keypair_fails_when_identity_required() {
        let (_h, cs, li, pid, _ih) = fixture();
        let quorum_id = Hash::compute("system/quorum", b"quorum-A");
        put_peer_config_with_quorum(&cs, &li, &pid, quorum_id);
        put_role_definition(&cs, &li, &pid, "public", "guest", guest_grants());
        put_policy(
            &cs,
            &li,
            &pid,
            &RoleInitialGrantPolicyData {
                unknown_peer: MODE_RECOGNIZE_ON_ATTESTATION.into(),
                default_role: Some("guest".into()),
                default_context: Some("public".into()),
                identity_required: true,
            },
        );
        let (deps, _idx) = make_deps(cs, li, pid);
        let connecting = Hash::compute("system/peer", b"bare-keypair");
        assert!(resolve_grants(&deps, &connecting).is_none());
    }

    #[test]
    fn recognize_on_attest_unrelated_controller_is_rejected() {
        let (_h, cs, li, pid, _ih) = fixture();
        let trusted_quorum = Hash::compute("system/quorum", b"quorum-A");
        let rogue_quorum = Hash::compute("system/quorum", b"rogue");
        put_peer_config_with_quorum(&cs, &li, &pid, trusted_quorum);
        put_role_definition(&cs, &li, &pid, "public", "guest", guest_grants());
        put_policy(
            &cs,
            &li,
            &pid,
            &RoleInitialGrantPolicyData {
                unknown_peer: MODE_RECOGNIZE_ON_ATTESTATION.into(),
                default_role: Some("guest".into()),
                default_context: Some("public".into()),
                identity_required: true,
            },
        );

        let rogue_controller = Hash::compute("system/peer", b"rogue-controller");
        let connecting = Hash::compute("system/peer", b"rogue-agent");
        let (deps, idx) = make_deps(cs.clone(), li.clone(), pid.clone());
        put_identity_cert(&cs, &idx, rogue_quorum, rogue_controller, "controller");
        put_identity_cert(&cs, &idx, rogue_controller, connecting, "agent");

        assert!(resolve_grants(&deps, &connecting).is_none());
    }

    #[test]
    fn layer2_exclusion_blocks_anonymous_allow() {
        let (_h, cs, li, pid, _ih) = fixture();
        put_role_definition(&cs, &li, &pid, "public", "guest", guest_grants());
        put_policy(
            &cs,
            &li,
            &pid,
            &RoleInitialGrantPolicyData {
                unknown_peer: MODE_ANONYMOUS_ALLOW.into(),
                default_role: Some("guest".into()),
                default_context: Some("public".into()),
                identity_required: false,
            },
        );
        let connecting = Hash::compute("system/peer", b"excluded-peer");
        let peer_seg = peer_segment_from_hash(&connecting);
        let exclusion = RoleExclusionData {
            excluded_by: Hash::compute("system/peer", b"admin"),
            excluded_at: 1,
            reason: None,
        };
        let entity = exclusion.to_entity().unwrap();
        let hash = cs.put(entity).unwrap();
        li.set(
            &format!("/{}/{}", pid, path_role_exclusion("public", &peer_seg)),
            hash,
        );
        let (deps, _idx) = make_deps(cs, li, pid);
        assert!(resolve_grants(&deps, &connecting).is_none());
    }

    #[test]
    fn unknown_mode_fails_closed() {
        let (_h, cs, li, pid, _ih) = fixture();
        put_role_definition(&cs, &li, &pid, "public", "guest", guest_grants());
        put_policy(
            &cs,
            &li,
            &pid,
            &RoleInitialGrantPolicyData {
                unknown_peer: "unknown-mode".into(),
                default_role: Some("guest".into()),
                default_context: Some("public".into()),
                identity_required: false,
            },
        );
        let (deps, _idx) = make_deps(cs, li, pid);
        let connecting = Hash::compute("system/peer", b"any");
        assert!(resolve_grants(&deps, &connecting).is_none());
    }
}
