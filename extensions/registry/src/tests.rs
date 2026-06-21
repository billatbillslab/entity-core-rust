//! EXTENSION-REGISTRY v1.0 unit + integration tests.

use std::sync::Arc;

use entity_handler::{Handler, HandlerContext};
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex, MemoryContentStore, MemoryLocationIndex};
use entity_ecf::{text, to_ecf, Value};
use entity_entity::Entity;

use crate::data::*;
use crate::log::ResolutionLog;
use crate::local_name::LocalNameHandler;
use crate::resolver::{glob_match, RegistryHandler};

const PEER: &str = "z6MkTestPeerIdForRegistry";

fn stores() -> (Arc<dyn ContentStore>, Arc<dyn LocationIndex>) {
    (
        Arc::new(MemoryContentStore::new()),
        Arc::new(MemoryLocationIndex::new()),
    )
}

fn ctx(op: &str, params_fields: Vec<(Value, Value)>) -> HandlerContext {
    let params = Entity::new(entity_types::TYPE_PROTOCOL_STATUS, to_ecf(&Value::Map(params_fields)))
        .unwrap();
    let execute = Entity::new(entity_types::TYPE_EXECUTE, to_ecf(&Value::Map(vec![]))).unwrap();
    HandlerContext::builder(execute, params)
        .operation(op.to_string())
        .build()
}

fn registry(cs: &Arc<dyn ContentStore>, li: &Arc<dyn LocationIndex>) -> RegistryHandler {
    let log = Arc::new(ResolutionLog::new(cs.clone(), li.clone(), PEER.into(), 1024));
    RegistryHandler::new(cs.clone(), li.clone(), PEER.into(), log)
}

fn decode_result(r: &entity_handler::HandlerResult) -> Vec<(Value, Value)> {
    let v: Value = ciborium::from_reader(r.result.data.as_slice()).unwrap();
    v.into_map().unwrap()
}

fn result_field<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter().find_map(|(k, v)| if k.as_text() == Some(key) { Some(v) } else { None })
}

// ---------------------------------------------------------------------------
// Entity round-trips (R5 *_round_trip)
// ---------------------------------------------------------------------------

#[test]
fn binding_round_trip() {
    let b = BindingData {
        name: "alice".into(),
        kind: KIND_LOCAL_NAME.into(),
        target_peer_id: "z6MkAlice".into(),
        transports: vec![Value::Text("tcp://host:9000".into())],
        issued_at: 1_700_000_000_000,
        ttl: None,
        supersedes: Some(Hash::compute("x", b"a")),
        issuer_attestation: None,
        metadata: Some(Value::Map(vec![(text("pinned"), Value::Bool(true))])),
    };
    let e = b.to_entity().unwrap();
    assert_eq!(BindingData::from_entity(&e).unwrap(), b);
}

#[test]
fn revocation_round_trip() {
    let r = RevocationData {
        revokes: Hash::compute("x", b"b"),
        revoked_at: 42,
        reason: Some("compromised".into()),
    };
    let e = r.to_entity().unwrap();
    assert_eq!(RevocationData::from_entity(&e).unwrap(), r);
}

#[test]
fn resolver_config_round_trip() {
    let c = ResolverConfigData {
        resolver_chain: vec![ResolverChainEntry {
            backend_kind: "local-name".into(),
            backend_id: PEER.into(),
            priority: 0,
            accepted_trust_anchors: vec!["local_name".into()],
            hints: None,
        }],
        pinned_bindings: vec![PinnedBinding {
            name: "nad-ccf".into(),
            target_peer_id: "z6MkCcf".into(),
            reason: Some("preload".into()),
        }],
        name_format_dispatch: vec![DispatchRule {
            pattern: "*.eth".into(),
            backend_kinds: vec!["dns-txt".into()],
        }],
        log_cache_hits: false,
        resolution_log_capacity: 512,
    };
    let e = c.to_entity().unwrap();
    assert_eq!(ResolverConfigData::from_entity(&e).unwrap(), c);
}

#[test]
fn local_name_config_round_trip() {
    let c = LocalNameConfigData {
        default_pinned: true,
        allow_supersede: false,
        case_normalization: "lower".into(),
    };
    let e = c.to_entity().unwrap();
    assert_eq!(LocalNameConfigData::from_entity(&e).unwrap(), c);
}

#[test]
fn resolution_log_round_trip() {
    let l = ResolutionLogData {
        seq: 5,
        name: "alice".into(),
        backend_id: Some(PEER.into()),
        status: STATUS_RESOLVED.into(),
        reason: None,
        binding: Some(Hash::compute("x", b"c")),
        attempted_at: 99,
        is_fallback_reresolve: false,
    };
    let e = l.to_entity().unwrap();
    assert_eq!(ResolutionLogData::from_entity(&e).unwrap(), l);
}

// ---------------------------------------------------------------------------
// Local-name bind / resolve / list / unbind / update-transports
// ---------------------------------------------------------------------------

#[tokio::test]
async fn local_name_bind_resolve_roundtrip() {
    let (cs, li) = stores();
    let pet = LocalNameHandler::new(cs.clone(), li.clone(), PEER.into());
    let reg = registry(&cs, &li);

    let r = pet
        .handle(&ctx(
            "bind",
            vec![
                (text("name"), text("alice")),
                (text("target_peer_id"), text("z6MkAlice")),
                (text("notes"), text("my friend")),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(r.status, 200);

    let r = reg
        .handle(&ctx("resolve", vec![(text("name"), text("alice"))]))
        .await
        .unwrap();
    // §2.1 Ruling-3: resolve returns the flat `system/registry/resolution-result`.
    assert_eq!(r.result.entity_type, crate::TYPE_REGISTRY_RESOLUTION_RESULT);
    let res = decode_result(&r);
    assert_eq!(result_field(&res, "status").unwrap().as_text(), Some("resolved"));
    assert_eq!(result_field(&res, "peer_id").unwrap().as_text(), Some("z6MkAlice"));
    assert_eq!(
        result_field(&res, "trust_anchor").unwrap().as_text(),
        Some("local_name")
    );
}

#[tokio::test]
async fn local_name_bind_invalid_name() {
    let (cs, li) = stores();
    let pet = LocalNameHandler::new(cs.clone(), li.clone(), PEER.into());
    for bad in ["a/b", "ctrl\u{7f}", "tab\tx", ""] {
        let r = pet
            .handle(&ctx(
                "bind",
                vec![(text("name"), text(bad)), (text("target_peer_id"), text("z6Mk"))],
            ))
            .await
            .unwrap();
        assert_eq!(r.status, 400, "name {:?} should be rejected", bad);
        let m = decode_result(&r);
        assert_eq!(result_field(&m, "code").unwrap().as_text(), Some("bind_invalid_name"));
    }
}

#[tokio::test]
async fn local_name_bind_already_exists() {
    let (cs, li) = stores();
    // allow_supersede = false
    let cfg = LocalNameConfigData {
        default_pinned: true,
        allow_supersede: false,
        case_normalization: "none".into(),
    };
    li.set(
        &crate::local_name_config_path(PEER),
        cs.put(cfg.to_entity().unwrap()).unwrap(),
    );
    let pet = LocalNameHandler::new(cs.clone(), li.clone(), PEER.into());
    let bind = |n: &str| {
        ctx(
            "bind",
            vec![(text("name"), text(n)), (text("target_peer_id"), text("z6MkX"))],
        )
    };
    assert_eq!(pet.handle(&bind("bob")).await.unwrap().status, 200);
    let r = pet.handle(&bind("bob")).await.unwrap();
    assert_eq!(r.status, 409);
    let m = decode_result(&r);
    assert_eq!(result_field(&m, "code").unwrap().as_text(), Some("bind_already_exists"));
}

#[tokio::test]
async fn local_name_supersede_on_rebind() {
    let (cs, li) = stores();
    let pet = LocalNameHandler::new(cs.clone(), li.clone(), PEER.into());
    let bind = |t: &str| {
        ctx(
            "bind",
            vec![(text("name"), text("carol")), (text("target_peer_id"), text(t))],
        )
    };
    let h1 = pet.handle(&bind("z6MkFirst")).await.unwrap();
    let first_hash = result_field(&decode_result(&h1), "binding_hash")
        .unwrap()
        .as_bytes()
        .unwrap()
        .to_vec();
    let _ = pet.handle(&bind("z6MkSecond")).await.unwrap();

    // resolve returns the new target; supersedes chain walks back to the first.
    let reg = registry(&cs, &li);
    let r = reg.handle(&ctx("resolve", vec![(text("name"), text("carol"))])).await.unwrap();
    // §2.1 Ruling-3: resolve returns the flat `system/registry/resolution-result`.
    let res = decode_result(&r);
    assert_eq!(result_field(&res, "peer_id").unwrap().as_text(), Some("z6MkSecond"));
    let head_hash = result_field(&res, "binding").unwrap().as_bytes().unwrap();
    let head = BindingData::from_entity(&cs.get(&Hash::from_bytes(head_hash).unwrap()).unwrap()).unwrap();
    assert_eq!(head.supersedes.unwrap().to_bytes().to_vec(), first_hash);
}

#[tokio::test]
async fn local_name_list_and_unbind() {
    let (cs, li) = stores();
    let pet = LocalNameHandler::new(cs.clone(), li.clone(), PEER.into());
    for (n, t) in [("a", "z6MkA"), ("b", "z6MkB")] {
        pet.handle(&ctx("bind", vec![(text("name"), text(n)), (text("target_peer_id"), text(t))]))
            .await
            .unwrap();
    }
    let r = pet.handle(&ctx("list", vec![])).await.unwrap();
    let m = decode_result(&r);
    let entries = result_field(&m, "entries").unwrap().as_array().unwrap();
    assert_eq!(entries.len(), 2);

    // unbind one
    let r = pet.handle(&ctx("unbind", vec![(text("name"), text("a"))])).await.unwrap();
    assert_eq!(r.status, 200);
    let r = pet.handle(&ctx("list", vec![])).await.unwrap();
    let m = decode_result(&r);
    assert_eq!(result_field(&m, "entries").unwrap().as_array().unwrap().len(), 1);

    // resolve of unbound name → chain_exhausted (§4.1.4: a backend miss folds
    // into fail-closed chain exhaustion; the meta-resolver does not surface a
    // top-level not_found).
    let reg = registry(&cs, &li);
    let r = reg.handle(&ctx("resolve", vec![(text("name"), text("a"))])).await.unwrap();
    // §2.1 Ruling-3: resolve returns the flat `system/registry/resolution-result`.
    let res = decode_result(&r);
    assert_eq!(result_field(&res, "status").unwrap().as_text(), Some("chain_exhausted"));
}

#[tokio::test]
async fn local_name_resolve_nfc_symmetry() {
    let (cs, li) = stores();
    let pet = LocalNameHandler::new(cs.clone(), li.clone(), PEER.into());
    // Bind NFC "Café" (precomposed é = U+00E9).
    let nfc = "Caf\u{00e9}";
    pet.handle(&ctx("bind", vec![(text("name"), text(nfc)), (text("target_peer_id"), text("z6MkCafe"))]))
        .await
        .unwrap();
    // Resolve with NFD "Café" (e + combining acute U+0301) → normalizes to same key.
    let nfd = "Cafe\u{0301}";
    let reg = registry(&cs, &li);
    let r = reg.handle(&ctx("resolve", vec![(text("name"), text(nfd))])).await.unwrap();
    // §2.1 Ruling-3: resolve returns the flat `system/registry/resolution-result`.
    let res = decode_result(&r);
    assert_eq!(result_field(&res, "status").unwrap().as_text(), Some("resolved"));
    assert_eq!(result_field(&res, "peer_id").unwrap().as_text(), Some("z6MkCafe"));
}

// ---------------------------------------------------------------------------
// Meta-resolver: pins, dispatch, chain exhaustion, revocation
// ---------------------------------------------------------------------------

fn install_config(cs: &Arc<dyn ContentStore>, li: &Arc<dyn LocationIndex>, cfg: &ResolverConfigData) {
    let h = cs.put(cfg.to_entity().unwrap()).unwrap();
    li.set(&crate::resolver_config_path(PEER), h);
}

#[tokio::test]
async fn meta_resolver_pin_precedence() {
    let (cs, li) = stores();
    // bind a local-name for "nad" that should be overridden by a pin.
    let pet = LocalNameHandler::new(cs.clone(), li.clone(), PEER.into());
    pet.handle(&ctx("bind", vec![(text("name"), text("nad")), (text("target_peer_id"), text("z6MkLocalName"))]))
        .await
        .unwrap();
    let cfg = ResolverConfigData {
        resolver_chain: vec![ResolverChainEntry {
            backend_kind: "local-name".into(),
            backend_id: PEER.into(),
            priority: 0,
            accepted_trust_anchors: vec![],
            hints: None,
        }],
        pinned_bindings: vec![PinnedBinding {
            name: "nad".into(),
            target_peer_id: "z6MkPinned".into(),
            reason: None,
        }],
        name_format_dispatch: vec![],
        log_cache_hits: false,
        resolution_log_capacity: 1024,
    };
    install_config(&cs, &li, &cfg);
    let reg = registry(&cs, &li);
    let r = reg.handle(&ctx("resolve", vec![(text("name"), text("nad"))])).await.unwrap();
    // §2.1 Ruling-3: resolve returns the flat `system/registry/resolution-result`.
    let res = decode_result(&r);
    assert_eq!(result_field(&res, "peer_id").unwrap().as_text(), Some("z6MkPinned"));
    assert_eq!(result_field(&res, "trust_anchor").unwrap().as_text(), Some("out_of_band"));
    assert_eq!(result_field(&res, "backend_id").unwrap().as_text(), Some("pinned"));
}

#[tokio::test]
async fn meta_resolver_chain_exhaustion() {
    let (cs, li) = stores();
    // empty chain → fail-closed.
    let cfg = ResolverConfigData::default();
    install_config(&cs, &li, &cfg);
    let reg = registry(&cs, &li);
    let r = reg.handle(&ctx("resolve", vec![(text("name"), text("ghost"))])).await.unwrap();
    // §2.1 Ruling-3: resolve returns the flat `system/registry/resolution-result`.
    let res = decode_result(&r);
    assert_eq!(result_field(&res, "status").unwrap().as_text(), Some("chain_exhausted"));
}

#[tokio::test]
async fn meta_resolver_dispatch_filter_excludes_local_name() {
    let (cs, li) = stores();
    let pet = LocalNameHandler::new(cs.clone(), li.clone(), PEER.into());
    pet.handle(&ctx("bind", vec![(text("name"), text("alice")), (text("target_peer_id"), text("z6MkAlice"))]))
        .await
        .unwrap();
    // Restrict local-name to names matching "*.local" — "alice" won't match.
    let cfg = ResolverConfigData {
        resolver_chain: vec![ResolverChainEntry {
            backend_kind: "local-name".into(),
            backend_id: PEER.into(),
            priority: 0,
            accepted_trust_anchors: vec![],
            hints: None,
        }],
        pinned_bindings: vec![],
        name_format_dispatch: vec![DispatchRule {
            pattern: "*.local".into(),
            backend_kinds: vec!["local-name".into()],
        }],
        log_cache_hits: false,
        resolution_log_capacity: 1024,
    };
    install_config(&cs, &li, &cfg);
    let reg = registry(&cs, &li);
    // "alice" excluded by dispatch → chain_exhausted
    let r = reg.handle(&ctx("resolve", vec![(text("name"), text("alice"))])).await.unwrap();
    let res = decode_result(&r);
    assert_eq!(result_field(&res, "status").unwrap().as_text(), Some("chain_exhausted"));
    // "alice.local" matches dispatch → local-name consulted, no such name →
    // chain_exhausted (the backend miss folds into fail-closed exhaustion).
    let r = reg.handle(&ctx("resolve", vec![(text("name"), text("alice.local"))])).await.unwrap();
    let res = decode_result(&r);
    assert_eq!(result_field(&res, "status").unwrap().as_text(), Some("chain_exhausted"));
}

#[tokio::test]
async fn meta_resolver_revocation_honored() {
    let (cs, li) = stores();
    let pet = LocalNameHandler::new(cs.clone(), li.clone(), PEER.into());
    let h = pet
        .handle(&ctx("bind", vec![(text("name"), text("dave")), (text("target_peer_id"), text("z6MkDave"))]))
        .await
        .unwrap();
    let binding_hash = Hash::from_bytes(
        result_field(&decode_result(&h), "binding_hash").unwrap().as_bytes().unwrap(),
    )
    .unwrap();
    // Install a revocation under the cohort convention: keyed by the
    // revocation entity's OWN content hash, not the binding it revokes (Go
    // `RevocationStoragePath`, validate-peer v6). `:resolve` discovers it by
    // scanning the revocation subtree and matching `revokes:`.
    let rev = RevocationData {
        revokes: binding_hash,
        revoked_at: 1,
        reason: Some("test".into()),
    };
    let rev_hash = cs.put(rev.to_entity().unwrap()).unwrap();
    li.set(
        &format!("/{}/system/registry/revocation/{}", PEER, rev_hash.to_hex()),
        rev_hash,
    );
    let reg = registry(&cs, &li);
    let r = reg.handle(&ctx("resolve", vec![(text("name"), text("dave"))])).await.unwrap();
    let res = decode_result(&r);
    // revoked → excluded → chain_exhausted (no other backend)
    assert_eq!(result_field(&res, "status").unwrap().as_text(), Some("chain_exhausted"));
}

// ---------------------------------------------------------------------------
// Resolution log
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolution_log_writes_and_recovers_seq() {
    let (cs, li) = stores();
    let pet = LocalNameHandler::new(cs.clone(), li.clone(), PEER.into());
    pet.handle(&ctx("bind", vec![(text("name"), text("e")), (text("target_peer_id"), text("z6MkE"))]))
        .await
        .unwrap();
    let reg = registry(&cs, &li);
    for _ in 0..3 {
        reg.handle(&ctx("resolve", vec![(text("name"), text("e"))])).await.unwrap();
    }
    // 3 log entries written at seq 0,1,2.
    let entries = li.list(&crate::resolution_log_prefix(PEER));
    assert_eq!(entries.len(), 3);
    // A fresh log recovers next_seq = 3.
    let log2 = ResolutionLog::new(cs.clone(), li.clone(), PEER.into(), 1024);
    assert_eq!(log2.peek_next_seq(), 3);
}

#[tokio::test]
async fn resolution_log_skips_fallback_reresolve() {
    let (cs, li) = stores();
    let pet = LocalNameHandler::new(cs.clone(), li.clone(), PEER.into());
    pet.handle(&ctx("bind", vec![(text("name"), text("f")), (text("target_peer_id"), text("z6MkF"))]))
        .await
        .unwrap();
    let reg = registry(&cs, &li);
    reg.handle(&ctx(
        "resolve",
        vec![(text("name"), text("f")), (text("is_fallback_reresolve"), Value::Bool(true))],
    ))
    .await
    .unwrap();
    assert_eq!(li.list(&crate::resolution_log_prefix(PEER)).len(), 0);
}

#[test]
fn resolution_log_ring_eviction() {
    let (cs, li) = stores();
    let log = ResolutionLog::new(cs.clone(), li.clone(), PEER.into(), 3);
    for i in 0..5 {
        log.record(&format!("n{}", i), "not_found", None, None, None, false);
    }
    // capacity 3 → only seq 2,3,4 pointers remain.
    let entries = li.list(&crate::resolution_log_prefix(PEER));
    assert_eq!(entries.len(), 3);
}

// ---------------------------------------------------------------------------
// Glob matcher
// ---------------------------------------------------------------------------

#[test]
fn glob_matcher() {
    assert!(glob_match("*", "anything"));
    assert!(glob_match("*.eth", "vitalik.eth"));
    assert!(!glob_match("*.eth", "vitalik.com"));
    assert!(glob_match("did:web:*", "did:web:example.com"));
    assert!(glob_match("*@*.*", "alice@example.com"));
    assert!(!glob_match("*@*.*", "noatsign"));
    assert!(glob_match("a?c", "abc"));
    assert!(!glob_match("a?c", "ac"));
    assert!(glob_match("[a-c]x", "bx"));
    assert!(!glob_match("[a-c]x", "dx"));
    assert!(glob_match("[!a-c]x", "dx"));
}

// ---------------------------------------------------------------------------
// Binding signature verification primitive (§3)
// ---------------------------------------------------------------------------

#[test]
fn self_certifying_binding_verifies_without_signature() {
    use crate::resolver::verify_binding_signature;
    let kp = entity_crypto::Keypair::generate();
    let peer_id = entity_crypto::PeerId::from_keypair(&kp).as_str().to_string();
    let b = BindingData {
        name: peer_id.clone(),
        kind: KIND_SELF_CERTIFYING.into(),
        target_peer_id: peer_id,
        transports: vec![],
        issued_at: 0,
        ttl: None,
        supersedes: None,
        issuer_attestation: None,
        metadata: None,
    };
    let (cs, li) = stores();
    let included = std::collections::HashMap::new();
    let h = b.to_entity().unwrap().content_hash;
    assert!(verify_binding_signature(&b, &h, &cs, &li, &included));

    // Tampered self-certifying (name != target) → reject.
    let mut bad = b.clone();
    bad.name = "not-the-peer-id".into();
    assert!(!verify_binding_signature(&bad, &h, &cs, &li, &included));
}

// ===========================================================================
// Peer-issued backend (PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND) — Part-A vectors.
//
// The reads resolve against the local store: the offline/precede path (§2.2),
// which is byte-identical to a live fetch's verify (precedes are a warm cache).
// ===========================================================================

use crate::{
    by_name_pointer_path, revocation_prefix, signature_pointer_path, BACKEND_KIND_PEER_ISSUED,
};
use crate::peer_issued;
use entity_crypto::Keypair;

fn pi_entry(registry_id: &str, hints: Option<Value>) -> ResolverChainEntry {
    ResolverChainEntry {
        backend_kind: BACKEND_KIND_PEER_ISSUED.into(),
        backend_id: registry_id.into(),
        priority: 0,
        accepted_trust_anchors: vec![],
        hints,
    }
}

/// Sign `target` with `signer` and publish the signature at the invariant
/// pointer under the registry's namespace, plus the signer's identity entity.
fn sign_into(
    cs: &Arc<dyn ContentStore>,
    li: &Arc<dyn LocationIndex>,
    registry_id: &str,
    signer: &Keypair,
    target: &Hash,
) {
    cs.put(signer.peer_entity().unwrap()).unwrap();
    let sig = entity_types::SignatureData {
        target: *target,
        signer: signer.peer_identity_hash(),
        algorithm: "ed25519".into(),
        signature: signer.sign(&target.to_bytes()).to_vec(),
    };
    let sig_entity = sig.to_entity().unwrap();
    let sig_hash = sig_entity.content_hash;
    cs.put(sig_entity).unwrap();
    li.set(&signature_pointer_path(registry_id, target), sig_hash);
}

/// Publish a peer-issued binding into the local store (the precede path):
/// body + by-name pointer + invariant-pointer signature (by `signer`).
#[allow(clippy::too_many_arguments)]
fn publish_binding(
    cs: &Arc<dyn ContentStore>,
    li: &Arc<dyn LocationIndex>,
    registry_id: &str,
    signer: &Keypair,
    name: &str,
    target: &str,
    issued_at: u64,
    ttl: Option<u64>,
) -> Hash {
    let binding = BindingData {
        name: name.into(),
        kind: KIND_PEER_ISSUED.into(),
        target_peer_id: target.into(),
        transports: vec![Value::Text("tcp://billslab.com:9000".into())],
        issued_at,
        ttl,
        supersedes: None,
        issuer_attestation: None,
        metadata: None,
    };
    let entity = binding.to_entity().unwrap();
    let binding_hash = entity.content_hash;
    cs.put(entity).unwrap();
    li.set(&by_name_pointer_path(registry_id, name), binding_hash);
    sign_into(cs, li, registry_id, signer, &binding_hash);
    binding_hash
}

// REG-PEERISSUED-RESOLVE-1 — happy path: by-name → binding → verify against the
// pinned registry key → resolved.
#[test]
fn peer_issued_resolve_happy_path() {
    let (cs, li) = stores();
    let registry = Keypair::generate();
    let rid = registry.peer_id().as_str().to_string();
    let target = Keypair::generate().peer_id().as_str().to_string();
    let bh = publish_binding(&cs, &li, &rid, &registry, "billslab.com", &target, 1000, None);

    let r = peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com")
        .expect("backend returned a result");
    assert!(r.is_resolved(), "expected resolved, got {}", r.status);
    assert_eq!(r.peer_id.as_deref(), Some(target.as_str()));
    assert_eq!(r.binding, Some(bh));
    assert_eq!(r.trust_anchor.as_deref(), Some(format!("peer_issued:{rid}").as_str()));
    assert_eq!(r.backend_id.as_deref(), Some(rid.as_str()));
    assert_eq!(r.transports.len(), 1);
}

// REG-PEERISSUED-VERIFY-FAIL-1 — binding signed by a NON-pinned key → rejected,
// chain advances. NOT accepted, NOT downgraded to a pin.
#[test]
fn peer_issued_verify_fail_rejected() {
    let (cs, li) = stores();
    let registry = Keypair::generate();
    let attacker = Keypair::generate();
    let rid = registry.peer_id().as_str().to_string();
    let target = Keypair::generate().peer_id().as_str().to_string();
    // Signed by the attacker, but the chain entry pins the real registry id.
    publish_binding(&cs, &li, &rid, &attacker, "billslab.com", &target, 1000, None);

    let r = peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com");
    assert!(r.is_none(), "non-pinned signer must reject (chain advances), got {r:?}");
}

// REG-PEERISSUED-REVOKED-1 — valid binding + a verifying revocation → excluded.
// Also asserts an UNSIGNED revocation does NOT exclude (peer-issued revocations
// MUST verify against the registry key, proposal §2.3).
#[test]
fn peer_issued_revoked_excluded() {
    let (cs, li) = stores();
    let registry = Keypair::generate();
    let rid = registry.peer_id().as_str().to_string();
    let target = Keypair::generate().peer_id().as_str().to_string();
    let bh = publish_binding(&cs, &li, &rid, &registry, "billslab.com", &target, 1000, None);

    // Unsigned revocation present → still resolves (signature is required).
    let rev = RevocationData { revokes: bh, revoked_at: 2000, reason: None };
    let rev_entity = rev.to_entity().unwrap();
    let rev_hash = rev_entity.content_hash;
    cs.put(rev_entity).unwrap();
    li.set(&format!("{}{}", revocation_prefix(&rid), rev_hash.to_hex()), rev_hash);
    assert!(
        peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com")
            .map(|r| r.is_resolved())
            .unwrap_or(false),
        "unsigned revocation must NOT exclude"
    );

    // Registry-signed revocation → excluded, chain advances.
    sign_into(&cs, &li, &rid, &registry, &rev_hash);
    let r = peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com");
    assert!(r.is_none(), "verifying revocation must exclude, got {r:?}");
}

// REG-PEERISSUED-EXPIRED-1 — issued_at + ttl < now → excluded.
#[test]
fn peer_issued_expired_excluded() {
    let (cs, li) = stores();
    let registry = Keypair::generate();
    let rid = registry.peer_id().as_str().to_string();
    let target = Keypair::generate().peer_id().as_str().to_string();
    // issued_at=1ms, ttl=1ms → expired long ago.
    publish_binding(&cs, &li, &rid, &registry, "billslab.com", &target, 1, Some(1));

    let r = peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com");
    assert!(r.is_none(), "expired binding must be excluded, got {r:?}");
}

// REG-PEERISSUED-PRECEDE-1 — a binding resolved from the local store (precede)
// has identical verify + result as a live fetch. Here the store IS the precede;
// the assertion is that the offline path produces a fully-verified resolved
// result (same code path the live-fetch precede would populate).
#[test]
fn peer_issued_precede_identical_to_live() {
    let (cs, li) = stores();
    let registry = Keypair::generate();
    let rid = registry.peer_id().as_str().to_string();
    let target = Keypair::generate().peer_id().as_str().to_string();
    publish_binding(&cs, &li, &rid, &registry, "billslab.com", &target, 1000, None);

    let r = peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com").unwrap();
    assert!(r.is_resolved());
    assert_eq!(r.trust_anchor.as_deref(), Some(format!("peer_issued:{rid}").as_str()));
}

// REG-PEERISSUED-OFFLINE-NOTFOUND-1 — name not in the by-name index → not_found
// with neg_ttl (read from the chain entry's hints, spec-problems P3).
#[test]
fn peer_issued_offline_not_found() {
    let (cs, li) = stores();
    let registry = Keypair::generate();
    let rid = registry.peer_id().as_str().to_string();
    cs.put(registry.peer_entity().unwrap()).unwrap();
    let hints = Value::Map(vec![(text("neg_ttl"), entity_ecf::integer(5000))]);

    let r = peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, Some(hints)), "absent.com")
        .expect("backend returns a not_found result");
    assert_eq!(r.status, STATUS_NOT_FOUND);
    assert_eq!(r.neg_ttl, Some(5000));
    assert!(r.binding.is_none());
}

// Integration through meta_resolve: a peer-issued chain entry resolves end-to-end.
#[tokio::test]
async fn peer_issued_via_meta_resolve() {
    let (cs, li) = stores();
    let registry_kp = Keypair::generate();
    let rid = registry_kp.peer_id().as_str().to_string();
    let target = Keypair::generate().peer_id().as_str().to_string();
    publish_binding(&cs, &li, &rid, &registry_kp, "billslab.com", &target, 1000, None);

    let cfg = ResolverConfigData {
        resolver_chain: vec![pi_entry(&rid, None)],
        ..Default::default()
    };
    let cfg_entity = cfg.to_entity().unwrap();
    let cfg_hash = cfg_entity.content_hash;
    cs.put(cfg_entity).unwrap();
    li.set(&crate::resolver_config_path(PEER), cfg_hash);

    let handler = registry(&cs, &li);
    let result = handler
        .handle(&ctx("resolve", vec![(text("name"), text("billslab.com"))]))
        .await
        .unwrap();
    let map = decode_result(&result);
    assert_eq!(result_field(&map, "status").and_then(|v| v.as_text()), Some("resolved"));
    assert_eq!(result_field(&map, "peer_id").and_then(|v| v.as_text()), Some(target.as_str()));
}

// VERIFY-FAIL through meta_resolve → chain_exhausted (fail-closed, no pin downgrade).
#[tokio::test]
async fn peer_issued_verify_fail_via_meta_is_chain_exhausted() {
    let (cs, li) = stores();
    let registry_kp = Keypair::generate();
    let attacker = Keypair::generate();
    let rid = registry_kp.peer_id().as_str().to_string();
    let target = Keypair::generate().peer_id().as_str().to_string();
    publish_binding(&cs, &li, &rid, &attacker, "billslab.com", &target, 1000, None);

    let cfg = ResolverConfigData {
        resolver_chain: vec![pi_entry(&rid, None)],
        ..Default::default()
    };
    let cfg_entity = cfg.to_entity().unwrap();
    let cfg_hash = cfg_entity.content_hash;
    cs.put(cfg_entity).unwrap();
    li.set(&crate::resolver_config_path(PEER), cfg_hash);

    let handler = registry(&cs, &li);
    let result = handler
        .handle(&ctx("resolve", vec![(text("name"), text("billslab.com"))]))
        .await
        .unwrap();
    let map = decode_result(&result);
    assert_eq!(
        result_field(&map, "status").and_then(|v| v.as_text()),
        Some("chain_exhausted"),
        "verify-fail must fail closed, never downgrade to a pin"
    );
}

// ---------------------------------------------------------------------------
// §6a.9 live registration — register-request / issuer-policy / replay
// ---------------------------------------------------------------------------

use std::collections::HashMap;

use crate::registration::RegisterRequestHandler;
use crate::{issuer_policy_path, RegisterRequestData};
use entity_crypto::IdentityKeypair;
use entity_types::SignatureData;

fn reg_handler(
    cs: &Arc<dyn ContentStore>,
    li: &Arc<dyn LocationIndex>,
    registry: &IdentityKeypair,
) -> RegisterRequestHandler {
    RegisterRequestHandler::new(
        cs.clone(),
        li.clone(),
        registry.peer_id().as_str().to_string(),
        registry.clone_identity(),
    )
}

fn install_policy(
    cs: &Arc<dyn ContentStore>,
    li: &Arc<dyn LocationIndex>,
    registry_id: &str,
    policy: &IssuerPolicyData,
) {
    let e = policy.to_entity().unwrap();
    let h = e.content_hash;
    cs.put(e).unwrap();
    li.set(&issuer_policy_path(registry_id), h);
}

/// Build a `register-request` entity for `name → target`, fresh `issued_at`.
fn mk_request(name: &str, target: &str, nonce: &[u8]) -> Entity {
    RegisterRequestData {
        name: name.into(),
        target_peer_id: target.into(),
        transports: vec![Value::Text("tcp://billslab.com:9000".into())],
        requested_ttl: Some(86_400_000),
        nonce: nonce.to_vec(),
        issued_at: crate::log::now_ms(),
    }
    .to_entity()
    .unwrap()
}

/// A `register-request` ctx: params = the request entity; `included` carries the
/// layer-1 `system/signature` (by `signing_key`) over the request hash + the
/// signer's `system/peer` entity.
fn register_ctx(req: Entity, signing_key: &Keypair) -> HandlerContext {
    let request_hash = req.content_hash;
    let sig = SignatureData {
        target: request_hash,
        signer: signing_key.peer_identity_hash(),
        algorithm: "ed25519".into(),
        signature: signing_key.sign(&request_hash.to_bytes()).to_vec(),
    };
    let sig_entity = sig.to_entity().unwrap();
    let peer_entity = signing_key.peer_entity().unwrap();
    let mut included = HashMap::new();
    included.insert(sig_entity.content_hash, sig_entity);
    included.insert(peer_entity.content_hash, peer_entity);

    let execute = Entity::new(entity_types::TYPE_EXECUTE, to_ecf(&Value::Map(vec![]))).unwrap();
    HandlerContext::builder(execute, req)
        .operation("register-request".to_string())
        .included(included)
        .build()
}

fn binding_hash_of(r: &entity_handler::HandlerResult) -> Hash {
    let map = decode_result(r);
    let b = result_field(&map, "binding_hash")
        .and_then(|v| v.as_bytes())
        .expect("binding_hash present");
    Hash::from_bytes(b).unwrap()
}

// REG-REGISTER-PROOF-1 — a request whose signature is NOT by target_peer_id is
// rejected (layer-1 ownership proof). `open` policy, so only layer-1 can fail.
#[tokio::test]
async fn register_proof_signature_not_by_target_rejected() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    install_policy(&cs, &li, registry.peer_id().as_str(), &IssuerPolicyData {
        mode: MODE_OPEN.into(),
        ..Default::default()
    });

    let owner = Keypair::generate(); // the peer the name should bind to
    let attacker = Keypair::generate(); // signs the request with the WRONG key
    let req = mk_request("billslab.com", owner.peer_id().as_str(), b"n1");
    // Signed by `attacker`, not by `owner` (= target_peer_id) → proof fails.
    let result = reg_handler(&cs, &li, &registry)
        .handle(&register_ctx(req, &attacker))
        .await
        .unwrap();
    assert_eq!(result.status, 403, "non-target signer must be rejected");
}

// REG-REGISTER-POLICY-1 — allowlist: a non-listed target → not_entitled; an
// allow-listed target → issued + resolvable through the peer-issued backend.
#[tokio::test]
async fn register_policy_allowlist() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    let rid = registry.peer_id().as_str().to_string();
    let allowed = Keypair::generate();
    let blocked = Keypair::generate();
    install_policy(&cs, &li, &rid, &IssuerPolicyData {
        mode: MODE_ALLOWLIST.into(),
        allowlist: Some(vec![allowed.peer_id().as_str().to_string()]),
        ..Default::default()
    });
    let handler = reg_handler(&cs, &li, &registry);

    // Non-listed target → not_entitled (403).
    let rej = handler
        .handle(&register_ctx(
            mk_request("blocked.com", blocked.peer_id().as_str(), b"nb"),
            &blocked,
        ))
        .await
        .unwrap();
    assert_eq!(rej.status, 403);
    let rej_map = decode_result(&rej);
    assert_eq!(result_field(&rej_map, "code").and_then(|v| v.as_text()), Some("not_entitled"));

    // Allow-listed target → issued, and resolvable end-to-end.
    let ok = handler
        .handle(&register_ctx(
            mk_request("billslab.com", allowed.peer_id().as_str(), b"na"),
            &allowed,
        ))
        .await
        .unwrap();
    assert_eq!(ok.status, 200);
    let bh = binding_hash_of(&ok);

    let resolved = peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com")
        .expect("resolvable");
    assert!(resolved.is_resolved());
    assert_eq!(resolved.binding, Some(bh));
    assert_eq!(resolved.peer_id.as_deref(), Some(allowed.peer_id().as_str()));
}

// REG-REGISTER-REPLAY-1 — a re-submitted request (same requester + nonce) is
// rejected. `open` policy, so the only difference from the first call is the
// seen-nonce marker.
#[tokio::test]
async fn register_replay_rejected() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    install_policy(&cs, &li, registry.peer_id().as_str(), &IssuerPolicyData {
        mode: MODE_OPEN.into(),
        ..Default::default()
    });
    let handler = reg_handler(&cs, &li, &registry);
    let owner = Keypair::generate();

    let first = handler
        .handle(&register_ctx(
            mk_request("billslab.com", owner.peer_id().as_str(), b"nonce-1"),
            &owner,
        ))
        .await
        .unwrap();
    assert_eq!(first.status, 200, "first registration succeeds");

    // Replay the same nonce (a fresh name so name_taken can't be the cause).
    let replay = handler
        .handle(&register_ctx(
            mk_request("other.com", owner.peer_id().as_str(), b"nonce-1"),
            &owner,
        ))
        .await
        .unwrap();
    assert_eq!(replay.status, 409);
    let map = decode_result(&replay);
    assert_eq!(result_field(&map, "code").and_then(|v| v.as_text()), Some("replay"));
}

// `manual` mode (also the default when no policy is installed): a valid request
// queues as pending_review rather than auto-issuing.
#[tokio::test]
async fn register_manual_queues_pending_review() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    let rid = registry.peer_id().as_str().to_string();
    let owner = Keypair::generate();
    // No policy installed → default `manual`.
    let result = reg_handler(&cs, &li, &registry)
        .handle(&register_ctx(
            mk_request("billslab.com", owner.peer_id().as_str(), b"nm"),
            &owner,
        ))
        .await
        .unwrap();
    assert_eq!(result.status, 200);
    let map = decode_result(&result);
    assert_eq!(result_field(&map, "status").and_then(|v| v.as_text()), Some("pending_review"));
    // Nothing was published.
    assert!(li.get(&crate::by_name_pointer_path(&rid, "billslab.com")).is_none());
}

// `open` mode: a free name is first-come-first-serve; a second target claiming
// the same name is rejected name_taken.
#[tokio::test]
async fn register_open_name_taken() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    install_policy(&cs, &li, registry.peer_id().as_str(), &IssuerPolicyData {
        mode: MODE_OPEN.into(),
        ..Default::default()
    });
    let handler = reg_handler(&cs, &li, &registry);
    let first = Keypair::generate();
    let second = Keypair::generate();

    let ok = handler
        .handle(&register_ctx(mk_request("dup.com", first.peer_id().as_str(), b"a"), &first))
        .await
        .unwrap();
    assert_eq!(ok.status, 200);

    let taken = handler
        .handle(&register_ctx(mk_request("dup.com", second.peer_id().as_str(), b"b"), &second))
        .await
        .unwrap();
    assert_eq!(taken.status, 409);
    assert_eq!(
        result_field(&decode_result(&taken), "code").and_then(|v| v.as_text()),
        Some("name_taken")
    );
}

// :revoke-request emits a registry-signed revocation that the peer-issued
// backend honors (the resolved binding is then excluded → chain dead-ends).
#[tokio::test]
async fn register_then_revoke_excludes() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    let rid = registry.peer_id().as_str().to_string();
    install_policy(&cs, &li, &rid, &IssuerPolicyData { mode: MODE_OPEN.into(), ..Default::default() });
    let handler = reg_handler(&cs, &li, &registry);
    let owner = Keypair::generate();

    let issued = handler
        .handle(&register_ctx(mk_request("billslab.com", owner.peer_id().as_str(), b"r1"), &owner))
        .await
        .unwrap();
    let bh = binding_hash_of(&issued);
    assert!(peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com")
        .map(|r| r.is_resolved())
        .unwrap_or(false));

    // Revoke it → resolve now dead-ends (fail-closed).
    let revoked = handler
        .handle(
            &ctx("revoke-request", vec![(text("binding_hash"), Value::Bytes(bh.to_bytes().to_vec()))]),
        )
        .await
        .unwrap();
    assert_eq!(revoked.status, 200);
    assert!(peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com").is_none());
}

// :renew-request issues a successor binding (supersedes-chain) the by-name
// pointer now points at, with the new TTL.
#[tokio::test]
async fn register_then_renew_supersedes() {
    let (cs, li) = stores();
    let registry = IdentityKeypair::Ed25519(Keypair::generate());
    let rid = registry.peer_id().as_str().to_string();
    install_policy(&cs, &li, &rid, &IssuerPolicyData { mode: MODE_OPEN.into(), ..Default::default() });
    let handler = reg_handler(&cs, &li, &registry);
    let owner = Keypair::generate();

    let issued = handler
        .handle(&register_ctx(mk_request("billslab.com", owner.peer_id().as_str(), b"n"), &owner))
        .await
        .unwrap();
    let old = binding_hash_of(&issued);

    let renewed = handler
        .handle(&ctx(
            "renew-request",
            vec![
                (text("binding_hash"), Value::Bytes(old.to_bytes().to_vec())),
                (text("ttl"), entity_ecf::integer(172_800_000)),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(renewed.status, 200);
    let new = binding_hash_of(&renewed);
    assert_ne!(old, new, "renew issues a fresh successor binding");

    // The by-name pointer + resolve now follow the successor.
    let resolved = peer_issued::resolve_one(&cs, &li, &pi_entry(&rid, None), "billslab.com").unwrap();
    assert_eq!(resolved.binding, Some(new));
    let body = cs.get(&new).unwrap();
    let binding = BindingData::from_entity(&body).unwrap();
    assert_eq!(binding.supersedes, Some(old));
    assert_eq!(binding.ttl, Some(172_800_000));
}
