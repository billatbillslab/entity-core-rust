use super::*;
use entity_capability::{canonicalize, CapabilityToken, GrantEntry, Granter, IdScope, PathScope};
use entity_crypto::Keypair;
use entity_entity::Entity;
use entity_handler::{HandlerContext, STATUS_BAD_REQUEST, STATUS_FORBIDDEN, STATUS_OK};
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex, MemoryContentStore, MemoryLocationIndex};
use std::sync::Arc;

fn make_handler() -> (
    CapabilityHandler,
    Keypair,
    Hash,
    String,
    Arc<dyn ContentStore>,
) {
    let store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
    let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
    let kp = Keypair::generate();
    let identity_entity = kp.peer_entity().unwrap();
    let identity_hash = Hash::compute(entity_crypto::TYPE_PEER, &identity_entity.data);
    let pid = kp.peer_id().as_str().to_string();
    let handler = CapabilityHandler::new(
        store.clone(),
        li,
        pid.clone(),
        identity_hash,
        identity_entity,
        entity_crypto::IdentityKeypair::Ed25519(kp.clone_inner()),
    );
    (handler, kp, identity_hash, pid, store)
}

fn caller_cap_tree_get_all(local_pid: &str, identity_hash: Hash) -> CapabilityToken {
    CapabilityToken {
        grants: vec![GrantEntry {
            handlers: PathScope::new(vec!["system/tree".into()]),
            resources: PathScope::new(vec![canonicalize("data/*", local_pid).unwrap()]),
            operations: IdScope::new(vec!["get".into(), "put".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        }],
        granter: Granter::single(identity_hash),
        grantee: Hash::compute("system/peer", &[1, 2, 3]),
        parent: None,
        created_at: 1,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    }
}

fn request_params(grants: &[GrantEntry]) -> Entity {
    let arr: Vec<entity_ecf::Value> = grants
        .iter()
        .map(entity_capability::encode_grant_entry)
        .collect();
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
        entity_ecf::text("grants"),
        entity_ecf::Value::Array(arr),
    )]));
    Entity::new("system/capability/request", data).unwrap()
}

fn revocation_params(token: Hash) -> Entity {
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
        entity_ecf::text("token"),
        entity_ecf::Value::Bytes(token.to_bytes().to_vec()),
    )]));
    Entity::new("system/capability/revoke-request", data).unwrap()
}

fn delegate_params(parent: Hash, grants: &[GrantEntry]) -> Entity {
    let arr: Vec<entity_ecf::Value> = grants
        .iter()
        .map(entity_capability::encode_grant_entry)
        .collect();
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (entity_ecf::text("grants"), entity_ecf::Value::Array(arr)),
        (
            entity_ecf::text("parent"),
            entity_ecf::Value::Bytes(parent.to_bytes().to_vec()),
        ),
    ]));
    Entity::new("system/capability/delegate-request", data).unwrap()
}

fn make_ctx(
    op: &str,
    params: Entity,
    caller: Option<CapabilityToken>,
    author: Hash,
    resource: Option<entity_capability::ResourceTarget>,
) -> HandlerContext {
    let exec_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
        entity_ecf::text("operation"),
        entity_ecf::text(op),
    )]));
    let execute = Entity::new("system/protocol/execute", exec_data).unwrap();
    let mut b = HandlerContext::builder(execute, params)
        .pattern("system/capability".to_string())
        .operation(op.to_string())
        .author(author);
    if let Some(c) = caller {
        b = b.caller_capability(c);
    }
    if let Some(r) = resource {
        b = b.resource_target(r);
    }
    b.build()
}

fn caller_author_hash() -> Hash {
    Hash::compute("system/peer", &[1, 2, 3])
}

#[tokio::test]
async fn request_returns_attenuated_grant_with_included_token() {
    let (handler, _kp, identity_hash, pid, _store) = make_handler();
    let caller = caller_cap_tree_get_all(&pid, identity_hash);

    let req_grants = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec![canonicalize("data/foo", &pid).unwrap()]),
        operations: IdScope::new(vec!["get".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];
    let ctx = make_ctx(
        "request",
        request_params(&req_grants),
        Some(caller),
        caller_author_hash(),
        None,
    );
    let res = handler.handle(&ctx).await.unwrap();
    assert_eq!(res.status, STATUS_OK, "request should succeed");
    assert_eq!(res.result.entity_type, "system/capability/grant");
    assert_eq!(
        res.included.len(),
        3,
        "included should carry token, signature, identity"
    );
    let token_entities: Vec<_> = res
        .included
        .values()
        .filter(|e| e.entity_type == "system/capability/token")
        .collect();
    assert_eq!(token_entities.len(), 1);
    let token = CapabilityToken::from_entity(token_entities[0]).unwrap();
    assert_eq!(token.granter.as_single().copied(), Some(identity_hash));
    assert_eq!(token.grantee, caller_author_hash());
    assert!(token.parent.is_none(), "request mints peer-rooted token");
}

#[tokio::test]
async fn request_rejects_scope_exceeding_caller() {
    let (handler, _kp, identity_hash, pid, _store) = make_handler();
    let caller = caller_cap_tree_get_all(&pid, identity_hash);

    // Asking for write on /other-peer/* is not covered by caller's tree:get/put on /pid/data/*
    let req_grants = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec!["/some-other-peer/secret/*".into()]),
        operations: IdScope::new(vec!["get".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];
    let ctx = make_ctx(
        "request",
        request_params(&req_grants),
        Some(caller),
        caller_author_hash(),
        None,
    );
    let res = handler.handle(&ctx).await.unwrap();
    assert_eq!(res.status, STATUS_FORBIDDEN);
    assert_eq!(res.result.entity_type, "system/protocol/error");
}

#[tokio::test]
async fn request_without_caller_capability_is_unauthenticated() {
    let (handler, _kp, _identity_hash, _pid, _store) = make_handler();
    let ctx = make_ctx(
        "request",
        request_params(&[GrantEntry {
            handlers: PathScope::new(vec!["system/tree".into()]),
            resources: PathScope::new(vec!["data/*".into()]),
            operations: IdScope::new(vec!["get".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        }]),
        None,
        caller_author_hash(),
        None,
    );
    let res = handler.handle(&ctx).await.unwrap();
    assert_eq!(res.status, 401);
}

#[tokio::test]
async fn delegate_attenuates_caller_held_parent() {
    // V7.62 §6.2: delegate v1 is self-attenuation only. Auth check is
    // `parent.grantee == caller's authenticated identity` — direct hold,
    // not granter-based. We mint a parent for the caller via `request`,
    // then call `delegate` carrying parent in the delegate-request params.
    //
    // Closeout F1: caller MUST be the local peer (same-peer-only). The
    // request + delegate authors are both `identity_hash` (the handler's
    // own peer identity), which is the only chain shape that verifies
    // under §5.5 since the handler signs with its own keypair.
    let (handler, _kp, identity_hash, pid, store) = make_handler();
    let caller = caller_cap_tree_self(&pid, identity_hash);
    let req_grants = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec![canonicalize("data/foo", &pid).unwrap()]),
        operations: IdScope::new(vec!["get".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];
    let ctx = make_ctx(
        "request",
        request_params(&req_grants),
        Some(caller),
        identity_hash,
        None,
    );
    let res = handler.handle(&ctx).await.unwrap();
    assert_eq!(res.status, STATUS_OK);
    let token_entity = res
        .included
        .values()
        .find(|e| e.entity_type == "system/capability/token")
        .unwrap()
        .clone();
    let parent_hash = token_entity.content_hash;
    assert!(store.get(&parent_hash).is_some());

    let del_ctx = make_ctx(
        "delegate",
        delegate_params(parent_hash, &req_grants),
        None,
        identity_hash,
        None,
    );
    let del_res = handler.handle(&del_ctx).await.unwrap();
    assert_eq!(del_res.status, STATUS_OK, "delegate should succeed");
    // Find the actual LEAF child (the one with parent = parent_hash) —
    // .included now carries the full parent-chain bundle per V7.62
    // §6.2 result-envelope, so iteration order isn't guaranteed.
    let child = del_res
        .included
        .values()
        .find(|e| {
            e.entity_type == "system/capability/token"
                && CapabilityToken::from_entity(e)
                    .map(|t| t.parent == Some(parent_hash))
                    .unwrap_or(false)
        })
        .expect("leaf child token present in delegate response");
    let child_token = CapabilityToken::from_entity(child).unwrap();
    assert_eq!(child_token.parent, Some(parent_hash));
    assert_eq!(
        child_token.granter.as_single().copied(),
        Some(identity_hash)
    );
    assert_eq!(child_token.grantee, identity_hash);
}

#[tokio::test]
async fn delegate_rejects_remote_caller_with_501() {
    // V7.62 closeout F1: cross-peer self-attenuation is structurally
    // underspecified (§5.5 requires the child's `granter` to sign, but
    // the handler cannot sign with a remote caller's keypair). v1 scopes
    // `delegate` to same-peer-only and returns 501 unsupported_operation
    // (not 403 — this is a missing-mechanism case, not a missing-
    // authority case). Mint a parent for the remote caller via store
    // injection (since `request` would itself hit 501 on a cross-peer
    // delegate path — but request still works cross-peer); call delegate
    // with a remote author; expect 501.
    let (handler, _kp, identity_hash, pid, store) = make_handler();
    let remote_author = caller_author_hash();
    let parent_token = CapabilityToken {
        grants: vec![GrantEntry {
            handlers: PathScope::new(vec!["system/tree".into()]),
            resources: PathScope::new(vec![canonicalize("data/*", &pid).unwrap()]),
            operations: IdScope::new(vec!["get".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        }],
        granter: Granter::single(identity_hash),
        grantee: remote_author,
        parent: None,
        created_at: 1,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let parent_hash = store.put(parent_token.to_entity().unwrap()).unwrap();

    let req_grants = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec![canonicalize("data/foo", &pid).unwrap()]),
        operations: IdScope::new(vec!["get".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];
    let del_ctx = make_ctx(
        "delegate",
        delegate_params(parent_hash, &req_grants),
        None,
        remote_author,
        None,
    );
    let res = handler.handle(&del_ctx).await.unwrap();
    assert_eq!(res.status, 501);
    // The error body must signal `unsupported_operation` (not a 403-style
    // scope failure), so the SDK routes the caller to local
    // self-attenuation rather than re-requesting with a wider cap.
    let text = String::from_utf8_lossy(&res.result.data);
    assert!(
        text.contains("unsupported_operation"),
        "expected unsupported_operation marker, got: {text}"
    );
}

fn caller_cap_tree_self(local_pid: &str, identity_hash: Hash) -> CapabilityToken {
    CapabilityToken {
        grants: vec![GrantEntry {
            handlers: PathScope::new(vec!["system/tree".into()]),
            resources: PathScope::new(vec![canonicalize("data/*", local_pid).unwrap()]),
            operations: IdScope::new(vec!["get".into(), "put".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        }],
        granter: Granter::single(identity_hash),
        grantee: identity_hash,
        parent: None,
        created_at: 1,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    }
}

#[tokio::test]
async fn delegate_rejects_non_holder() {
    // V7.62 §6.2: parent.grantee MUST equal caller's authenticated
    // identity. A same-peer caller (F1 gate passes) who does NOT directly
    // hold the parent still gets 403 scope_exceeds_authority — even if
    // the parent is in the store.
    let (handler, _kp, identity_hash, pid, store) = make_handler();
    let other_grantee = Hash::compute("system/peer", &[7, 7, 7]);
    let parent_for_other = CapabilityToken {
        grants: vec![GrantEntry {
            handlers: PathScope::new(vec!["system/tree".into()]),
            resources: PathScope::new(vec![canonicalize("data/*", &pid).unwrap()]),
            operations: IdScope::new(vec!["get".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        }],
        granter: Granter::single(identity_hash),
        grantee: other_grantee,
        parent: None,
        created_at: 1,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let parent_hash = store.put(parent_for_other.to_entity().unwrap()).unwrap();

    let req_grants = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec![canonicalize("data/foo", &pid).unwrap()]),
        operations: IdScope::new(vec!["get".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];
    let del_ctx = make_ctx(
        "delegate",
        delegate_params(parent_hash, &req_grants),
        None,
        identity_hash,
        None,
    );
    let res = handler.handle(&del_ctx).await.unwrap();
    assert_eq!(res.status, STATUS_FORBIDDEN);
}

#[tokio::test]
async fn delegate_response_includes_parent_chain() {
    // V7.62 §6.2 result-envelope: included MAY carry the full
    // authority-chain bundle for cross-peer dispatch. After issuing a
    // parent via `request`, a `delegate` call should include both the
    // child token + sig + granter AND the parent token + sig.
    let (handler, _kp, identity_hash, pid, _store) = make_handler();
    let caller = caller_cap_tree_self(&pid, identity_hash);
    let req_grants = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec![canonicalize("data/foo", &pid).unwrap()]),
        operations: IdScope::new(vec!["get".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];

    let req_ctx = make_ctx(
        "request",
        request_params(&req_grants),
        Some(caller),
        identity_hash,
        None,
    );
    let req_res = handler.handle(&req_ctx).await.unwrap();
    let parent_token = req_res
        .included
        .values()
        .find(|e| e.entity_type == "system/capability/token")
        .unwrap()
        .clone();
    let parent_hash = parent_token.content_hash;

    let del_ctx = make_ctx(
        "delegate",
        delegate_params(parent_hash, &req_grants),
        None,
        identity_hash,
        None,
    );
    let del_res = handler.handle(&del_ctx).await.unwrap();
    assert_eq!(del_res.status, STATUS_OK);

    // The bundle must contain both tokens (leaf + parent).
    let tokens: Vec<_> = del_res
        .included
        .values()
        .filter(|e| e.entity_type == "system/capability/token")
        .collect();
    assert_eq!(tokens.len(), 2, "leaf + parent token both in included");
    assert!(del_res.included.contains_key(&parent_hash));

    // Parent's signature should resolve via the §3.5 invariant pointer
    // path (handler binds sigs there at mint time).
    let sigs: Vec<_> = del_res
        .included
        .values()
        .filter(|e| e.entity_type == "system/signature")
        .collect();
    assert!(
        sigs.len() >= 2,
        "leaf sig + parent sig both expected in included, got {}",
        sigs.len()
    );
}

#[tokio::test]
async fn revoke_writes_marker_for_peer_issued_token() {
    let (handler, _kp, identity_hash, pid, store) = make_handler();
    let caller = caller_cap_tree_get_all(&pid, identity_hash);
    let req_grants = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec![canonicalize("data/foo", &pid).unwrap()]),
        operations: IdScope::new(vec!["get".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];
    let ctx = make_ctx(
        "request",
        request_params(&req_grants),
        Some(caller),
        caller_author_hash(),
        None,
    );
    let res = handler.handle(&ctx).await.unwrap();
    let token_entity = res
        .included
        .values()
        .find(|e| e.entity_type == "system/capability/token")
        .unwrap()
        .clone();
    let token_hash = token_entity.content_hash;
    let _ = store.get(&token_hash).unwrap();

    let rev_ctx = make_ctx(
        "revoke",
        revocation_params(token_hash),
        None,
        caller_author_hash(),
        None,
    );
    let rev_res = handler.handle(&rev_ctx).await.unwrap();
    assert_eq!(rev_res.status, STATUS_OK);
    assert_eq!(rev_res.result.entity_type, "system/capability/revocation");

    let rev_path = format!(
        "/{}/system/capability/revocations/{}",
        pid,
        hex_of(&token_hash)
    );
    let rev_hash = handler.location_index.get(&rev_path).unwrap();
    let rev_entity = store.get(&rev_hash).unwrap();
    assert_eq!(rev_entity.entity_type, "system/capability/revocation");
}

#[tokio::test]
async fn revoke_writes_marker_for_unknown_token_hash() {
    // V7.62 §6.2 universal-revocation-entry-point: revoke is
    // path-agnostic. For wire-only / unknown tokens, the handler writes
    // the marker only — no granter-identity carve-out, no requirement
    // that the token be present in the local store. The dispatcher's
    // cap check is the only gate.
    let (handler, _kp, _identity_hash, pid, store) = make_handler();
    let token_hash = Hash::compute("system/capability/token", &[9, 9, 9]);

    let rev_ctx = make_ctx(
        "revoke",
        revocation_params(token_hash),
        None,
        caller_author_hash(),
        None,
    );
    let res = handler.handle(&rev_ctx).await.unwrap();
    assert_eq!(res.status, STATUS_OK);
    let rev_path = format!(
        "/{}/system/capability/revocations/{}",
        pid,
        hex_of(&token_hash)
    );
    let rev_hash = handler.location_index.get(&rev_path).unwrap();
    let rev = store.get(&rev_hash).unwrap();
    assert_eq!(rev.entity_type, "system/capability/revocation");
}

fn policy_entry_params(peer_pattern: &str, grants: &[GrantEntry]) -> Entity {
    let arr: Vec<entity_ecf::Value> = grants
        .iter()
        .map(entity_capability::encode_grant_entry)
        .collect();
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (entity_ecf::text("grants"), entity_ecf::Value::Array(arr)),
        (
            entity_ecf::text("peer_pattern"),
            entity_ecf::text(peer_pattern),
        ),
    ]));
    Entity::new("system/capability/policy-entry", data).unwrap()
}

#[tokio::test]
async fn request_rejected_when_exceeds_policy_entry() {
    // V7.62 §6.2: when a policy entry exists for the caller, the request
    // grants MUST be a subset of BOTH the caller's auth cap AND the
    // policy entry. Caller holds tree:get + tree:put on data/*; policy
    // entry permits only tree:get on data/*. Request asks for tree:put
    // — covered by caller, but exceeds policy entry → 403.
    let (handler, _kp, identity_hash, pid, _store) = make_handler();
    let caller = caller_cap_tree_get_all(&pid, identity_hash);
    let author = caller_author_hash();
    let author_hex = hex_of(&author);

    let policy_grants = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec![canonicalize("data/*", &pid).unwrap()]),
        operations: IdScope::new(vec!["get".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];
    let cfg_ctx = make_ctx(
        "configure",
        policy_entry_params(&author_hex, &policy_grants),
        None,
        author,
        None,
    );
    assert_eq!(handler.handle(&cfg_ctx).await.unwrap().status, STATUS_OK);

    let req_grants = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec![canonicalize("data/foo", &pid).unwrap()]),
        operations: IdScope::new(vec!["put".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];
    let req_ctx = make_ctx(
        "request",
        request_params(&req_grants),
        Some(caller),
        author,
        None,
    );
    let res = handler.handle(&req_ctx).await.unwrap();
    assert_eq!(res.status, STATUS_FORBIDDEN);
}

#[tokio::test]
async fn configure_writes_policy_at_peer_path() {
    let (handler, _kp, _identity_hash, pid, store) = make_handler();
    let peer_hex = "00".to_string() + &"ab".repeat(32);
    let grants = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec![canonicalize("data/*", &pid).unwrap()]),
        operations: IdScope::new(vec!["get".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];
    let ctx = make_ctx(
        "configure",
        policy_entry_params(&peer_hex, &grants),
        None,
        caller_author_hash(),
        None,
    );
    let res = handler.handle(&ctx).await.unwrap();
    assert_eq!(res.status, STATUS_OK);
    assert_eq!(res.result.entity_type, "system/capability/policy-entry");

    let path = format!("/{}/system/capability/policy/{}", pid, peer_hex);
    let h = handler.location_index.get(&path).unwrap();
    assert_eq!(
        store.get(&h).unwrap().entity_type,
        "system/capability/policy-entry"
    );
}

#[tokio::test]
async fn configure_accepts_default_peer_pattern() {
    // V7.62 §6.2 closeout F8: the fallback segment is the literal
    // `default` (renamed from `*` in v7.62 to remove the glyph collision
    // with `*`-as-glob).
    let (handler, _kp, _identity_hash, pid, _store) = make_handler();
    let grants = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec![canonicalize("data/*", &pid).unwrap()]),
        operations: IdScope::new(vec!["get".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];
    let ctx = make_ctx(
        "configure",
        policy_entry_params(entity_capability::POLICY_FALLBACK_SEGMENT, &grants),
        None,
        caller_author_hash(),
        None,
    );
    let res = handler.handle(&ctx).await.unwrap();
    assert_eq!(res.status, STATUS_OK);
    let path = format!(
        "/{}/system/capability/policy/{}",
        pid,
        entity_capability::POLICY_FALLBACK_SEGMENT
    );
    assert!(handler.location_index.get(&path).is_some());
}

#[tokio::test]
async fn configure_rejects_legacy_star_pattern() {
    // V7.62 §6.2 closeout F8: the literal `*` is no longer a valid
    // peer_pattern — `*` is V7's glob glyph everywhere else and is now
    // reserved for that role in this path. Old payloads that send `*`
    // MUST be rejected (and any operator with a pre-rename entry must
    // migrate to `default`).
    let (handler, _kp, _identity_hash, _pid, _store) = make_handler();
    let grants = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec!["data/*".into()]),
        operations: IdScope::new(vec!["get".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];
    let ctx = make_ctx(
        "configure",
        policy_entry_params("*", &grants),
        None,
        caller_author_hash(),
        None,
    );
    let res = handler.handle(&ctx).await.unwrap();
    assert_eq!(res.status, STATUS_BAD_REQUEST);
}

#[tokio::test]
async fn configure_rejects_partial_prefix_pattern() {
    let (handler, _kp, _identity_hash, pid, _store) = make_handler();
    let grants = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec![canonicalize("data/*", &pid).unwrap()]),
        operations: IdScope::new(vec!["get".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];
    let ctx = make_ctx(
        "configure",
        policy_entry_params("00abc*", &grants),
        None,
        caller_author_hash(),
        None,
    );
    let res = handler.handle(&ctx).await.unwrap();
    assert_eq!(res.status, STATUS_BAD_REQUEST);
}

// ---------------- V7 §6.2 v7.64 POL-DF conformance vectors ----------------
//
// Per `PROPOSAL-V7-POLICY-DUAL-FORM-PRE-CONFIGURATION.md` §2.7. The dual-form
// resolver tries hex (canonical) → Base58 (pre-config affordance) → default.
// A Base58 hit canonicalizes (writes hex, deletes Base58 — §2.3 SHOULD).

/// Build a `system/peer` entity for a Keypair AND insert it into the store
/// at its content_hash, so the dual-form resolver can recover the peer's
/// Base58 PeerID from the author hash.
fn insert_remote_peer_in_store(kp: &Keypair, store: &Arc<dyn ContentStore>) -> (Hash, String) {
    let entity = kp.peer_entity().expect("peer entity");
    let h = entity.content_hash;
    store.put(entity).expect("put peer entity");
    (h, kp.peer_id().as_str().to_string())
}

/// POL-DF-1: hex-form entry → matches on request.
#[tokio::test]
async fn pol_df_1_hex_form_match() {
    let (handler, _kp, identity_hash, pid, store) = make_handler();
    let remote_kp = Keypair::from_seed([200u8; 32]);
    let (remote_hash, _remote_b58) = insert_remote_peer_in_store(&remote_kp, &store);
    let remote_hex = hex_of(&remote_hash);

    let policy_grants = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec![canonicalize("data/*", &pid).unwrap()]),
        operations: IdScope::new(vec!["get".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];
    let cfg_ctx = make_ctx(
        "configure",
        policy_entry_params(&remote_hex, &policy_grants),
        None,
        identity_hash,
        None,
    );
    assert_eq!(handler.handle(&cfg_ctx).await.unwrap().status, STATUS_OK);

    // Request from the remote — author = remote's identity hash. Caller cap
    // grants tree:get on data/*; request asks for tree:get on data/foo —
    // covered by both the cap AND the matched policy entry.
    let caller = caller_cap_tree_get_all(&pid, identity_hash);
    let req_grants = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec![canonicalize("data/foo", &pid).unwrap()]),
        operations: IdScope::new(vec!["get".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];
    let req_ctx = make_ctx(
        "request",
        request_params(&req_grants),
        Some(caller),
        remote_hash,
        None,
    );
    let res = handler.handle(&req_ctx).await.unwrap();
    assert_eq!(
        res.status, STATUS_OK,
        "hex-form policy entry MUST be honored"
    );
}

/// POL-DF-2: Base58-form entry → matches on request, and canonicalizes.
#[tokio::test]
async fn pol_df_2_base58_form_match_and_canonicalize() {
    let (handler, _kp, identity_hash, pid, store) = make_handler();
    let remote_kp = Keypair::from_seed([201u8; 32]);
    let (remote_hash, remote_b58) = insert_remote_peer_in_store(&remote_kp, &store);
    let remote_hex = hex_of(&remote_hash);

    let policy_grants = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec![canonicalize("data/*", &pid).unwrap()]),
        operations: IdScope::new(vec!["get".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];
    let cfg_ctx = make_ctx(
        "configure",
        policy_entry_params(&remote_b58, &policy_grants),
        None,
        identity_hash,
        None,
    );
    assert_eq!(
        handler.handle(&cfg_ctx).await.unwrap().status,
        STATUS_OK,
        "Base58-form `configure` MUST be accepted"
    );

    let b58_path = format!("/{}/system/capability/policy/{}", pid, remote_b58);
    let hex_path = format!("/{}/system/capability/policy/{}", pid, remote_hex);
    assert!(handler.location_index.get(&b58_path).is_some());
    assert!(handler.location_index.get(&hex_path).is_none());

    // Request triggers the lookup → match → canonicalize.
    let caller = caller_cap_tree_get_all(&pid, identity_hash);
    let req_grants = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec![canonicalize("data/foo", &pid).unwrap()]),
        operations: IdScope::new(vec!["get".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];
    let req_ctx = make_ctx(
        "request",
        request_params(&req_grants),
        Some(caller),
        remote_hash,
        None,
    );
    let res = handler.handle(&req_ctx).await.unwrap();
    assert_eq!(
        res.status, STATUS_OK,
        "Base58-form policy entry MUST be honored"
    );

    // §2.3 canonicalization: hex entry exists; Base58 entry removed.
    assert!(
        handler.location_index.get(&hex_path).is_some(),
        "Base58 → hex canonicalization MUST write the hex entry"
    );
    assert!(
        handler.location_index.get(&b58_path).is_none(),
        "Base58 → hex canonicalization MUST remove the Base58 entry"
    );
}

/// POL-DF-3: hex precedence over Base58 when both exist.
#[tokio::test]
async fn pol_df_3_hex_wins_over_base58() {
    let (handler, _kp, identity_hash, pid, store) = make_handler();
    let remote_kp = Keypair::from_seed([202u8; 32]);
    let (remote_hash, remote_b58) = insert_remote_peer_in_store(&remote_kp, &store);
    let remote_hex = hex_of(&remote_hash);

    // Write a permissive Base58-form entry that, if it matched, would allow
    // tree:put. Then write a restrictive hex-form entry — only tree:get.
    let permissive = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec![canonicalize("data/*", &pid).unwrap()]),
        operations: IdScope::new(vec!["get".into(), "put".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];
    let restrictive = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec![canonicalize("data/*", &pid).unwrap()]),
        operations: IdScope::new(vec!["get".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];

    let b58_ctx = make_ctx(
        "configure",
        policy_entry_params(&remote_b58, &permissive),
        None,
        identity_hash,
        None,
    );
    assert_eq!(handler.handle(&b58_ctx).await.unwrap().status, STATUS_OK);

    let hex_ctx = make_ctx(
        "configure",
        policy_entry_params(&remote_hex, &restrictive),
        None,
        identity_hash,
        None,
    );
    assert_eq!(handler.handle(&hex_ctx).await.unwrap().status, STATUS_OK);

    // Now request tree:put — caller cap allows it, but the HEX policy entry
    // restricts to get-only. If the resolver mistakenly picked the Base58
    // entry it would allow put; hex precedence MUST kick in → 403.
    let caller = caller_cap_tree_get_all(&pid, identity_hash);
    let req_grants = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec![canonicalize("data/foo", &pid).unwrap()]),
        operations: IdScope::new(vec!["put".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];
    let req_ctx = make_ctx(
        "request",
        request_params(&req_grants),
        Some(caller),
        remote_hash,
        None,
    );
    let res = handler.handle(&req_ctx).await.unwrap();
    assert_eq!(
        res.status, STATUS_FORBIDDEN,
        "hex form is canonical — Base58 entry MUST be ignored when hex exists"
    );
}

/// POL-DF-5: no specific entry → `default` applies. (POL-DF-4 canonicalization
/// is already proven by POL-DF-2.)
#[tokio::test]
async fn pol_df_5_default_applies_when_no_specific_entry() {
    let (handler, _kp, identity_hash, pid, store) = make_handler();
    let remote_kp = Keypair::from_seed([203u8; 32]);
    let (remote_hash, _remote_b58) = insert_remote_peer_in_store(&remote_kp, &store);

    // Only a `default` entry — get-only.
    let default_grants = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec![canonicalize("data/*", &pid).unwrap()]),
        operations: IdScope::new(vec!["get".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];
    let cfg_ctx = make_ctx(
        "configure",
        policy_entry_params(entity_capability::POLICY_FALLBACK_SEGMENT, &default_grants),
        None,
        identity_hash,
        None,
    );
    assert_eq!(handler.handle(&cfg_ctx).await.unwrap().status, STATUS_OK);

    let caller = caller_cap_tree_get_all(&pid, identity_hash);
    let req_grants = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec![canonicalize("data/foo", &pid).unwrap()]),
        operations: IdScope::new(vec!["get".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];
    let req_ctx = make_ctx(
        "request",
        request_params(&req_grants),
        Some(caller),
        remote_hash,
        None,
    );
    let res = handler.handle(&req_ctx).await.unwrap();
    assert_eq!(
        res.status, STATUS_OK,
        "`default` MUST apply when no specific entry"
    );
}

/// POL-DF-6: invalid peer_pattern → 400 invalid_peer_pattern.
#[tokio::test]
async fn pol_df_6_invalid_peer_pattern_rejected() {
    let (handler, _kp, _identity_hash, _pid, _store) = make_handler();
    let grants = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec!["data/*".into()]),
        operations: IdScope::new(vec!["get".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];

    // Garbage string — not hex (wrong length), not Base58 (contains
    // disallowed `_`), not `default`.
    let ctx = make_ctx(
        "configure",
        policy_entry_params("not_a_peer_id_pattern", &grants),
        None,
        caller_author_hash(),
        None,
    );
    let res = handler.handle(&ctx).await.unwrap();
    assert_eq!(
        res.status, STATUS_BAD_REQUEST,
        "garbage peer_pattern MUST be rejected with 400"
    );
}

/// POL-DF-7: `peer_pattern` hex width is format-relative (v7.70 §1.2 /
/// V7 §3.5). A SHA-384 identity hash is 49 wire bytes → 98 hex chars; the
/// validator MUST accept it, not just the 66-hex SHA-256 width. Regression
/// for the cross-impl bug where a Rust SHA-384 peer rejected a valid
/// canonical SHA-384 peer_pattern with `invalid_peer_pattern`.
#[test]
fn pol_df_7_peer_pattern_hex_width_is_format_relative() {
    // SHA-256: format byte 0x00 + 32-byte digest = 66 hex chars.
    let sha256_hex = format!("00{}", "ab".repeat(32));
    assert_eq!(sha256_hex.len(), 66);
    assert!(
        is_valid_peer_pattern(&sha256_hex),
        "SHA-256 66-hex must pass"
    );

    // SHA-384: format byte 0x01 + 48-byte digest = 98 hex chars.
    let sha384_hex = format!("01{}", "cd".repeat(48));
    assert_eq!(sha384_hex.len(), 98);
    assert!(
        is_valid_peer_pattern(&sha384_hex),
        "SHA-384 98-hex must pass"
    );

    // `default` and the negatives still hold.
    assert!(is_valid_peer_pattern(POLICY_FALLBACK_SEGMENT));
    // Right length but unallocated format byte (0x02) → reject.
    assert!(!is_valid_peer_pattern(&format!("02{}", "ab".repeat(32))));
    // 98 hex but declaring SHA-256 (0x00) → width/format mismatch, reject.
    assert!(!is_valid_peer_pattern(&format!("00{}", "ab".repeat(48))));
    // Odd length / non-hex / empty → reject.
    assert!(!is_valid_peer_pattern("00abc"));
    assert!(!is_valid_peer_pattern(&format!("00{}", "zz".repeat(32))));
    assert!(!is_valid_peer_pattern(""));
}

#[tokio::test]
async fn unknown_operation_returns_501() {
    // V7.62 §6.2: when the capability handler is registered but doesn't
    // implement the named operation, return 501 unsupported_operation.
    // 400 is reserved for malformed input; 404 for handler not registered;
    // 403 for authority failures.
    let (handler, _kp, _identity_hash, _pid, _store) = make_handler();
    let ctx = make_ctx(
        "merge",
        request_params(&[]),
        None,
        caller_author_hash(),
        None,
    );
    let res = handler.handle(&ctx).await.unwrap();
    assert_eq!(res.status, 501);
}
