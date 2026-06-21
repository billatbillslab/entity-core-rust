//! EXTENSION-RELAY v1.0 unit tests — entity codecs (§3, §4) + handler behavior
//! (Mode S put/poll/cursor/errors, Mode F ttl/no_route/fallback).

use std::collections::HashMap;
use std::sync::Arc;

use entity_crypto::{IdentityKeypair, Keypair};
use entity_ecf::{text, to_ecf, Value};
use entity_entity::Entity;
use entity_handler::{Handler, HandlerContext, HandlerResult};
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex, MemoryContentStore, MemoryLocationIndex};

use crate::data::*;
use crate::handler::RelayHandler;
use crate::*;

const PEER: &str = "z6MkTestRelayPeerId";

fn lit_hash(fill: u8) -> Hash {
    Hash::new(0x00, [fill; 32])
}

fn stores() -> (Arc<dyn ContentStore>, Arc<dyn LocationIndex>) {
    (
        Arc::new(MemoryContentStore::new()),
        Arc::new(MemoryLocationIndex::new()),
    )
}

fn relay(cs: &Arc<dyn ContentStore>, li: &Arc<dyn LocationIndex>) -> RelayHandler {
    RelayHandler::new(cs.clone(), li.clone(), PEER.into())
}

/// An opaque inner envelope — the relay never decodes it; we just need a
/// content-addressed blob to reference and carry in `included`.
fn inner_envelope(tag: u8) -> Entity {
    Entity::new(entity_types::TYPE_ENVELOPE, vec![0x80 | tag, tag, tag]).unwrap()
}

fn ctx(op: &str, params: Entity, author: Option<Hash>, included: Vec<Entity>) -> HandlerContext {
    ctx_session(op, params, author, included, None)
}

/// Like [`ctx`] but with an explicit authenticated connection peer (RELAY §2.2
/// session-peer — what `put_by` is checked against).
fn ctx_session(
    op: &str,
    params: Entity,
    author: Option<Hash>,
    included: Vec<Entity>,
    session: Option<&str>,
) -> HandlerContext {
    let execute = Entity::new(entity_types::TYPE_EXECUTE, to_ecf(&Value::Map(vec![]))).unwrap();
    let mut inc = HashMap::new();
    for e in included {
        inc.insert(e.content_hash, e);
    }
    let mut b = HandlerContext::builder(execute, params)
        .operation(op.to_string())
        .included(inc);
    if let Some(a) = author {
        b = b.author(a);
    }
    if let Some(s) = session {
        b = b.session_peer_id(s);
    }
    b.build()
}

fn decode(data: &[u8]) -> Vec<(Value, Value)> {
    let v: Value = ciborium::from_reader(data).unwrap();
    v.into_map().unwrap()
}

fn field<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find_map(|(k, v)| if k.as_text() == Some(key) { Some(v) } else { None })
}

fn result_code(r: &HandlerResult) -> Option<String> {
    field(&decode(&r.result.data), "code").and_then(|v| v.as_text()).map(|s| s.to_string())
}

// ---------------------------------------------------------------------------
// Codec round-trips
// ---------------------------------------------------------------------------

#[test]
fn forward_request_round_trip() {
    let fr = ForwardRequest {
        destination: "z6MkDest".into(),
        route: None,
        next_hop: Some("z6MkHop".into()),
        ttl_hops: 8,
        envelope_inner: lit_hash(0xAB),
    };
    let e = fr.to_entity().unwrap();
    assert_eq!(ForwardRequest::from_entity(&e).unwrap(), fr);
    // next_hop absent when None.
    let fr2 = ForwardRequest {
        next_hop: None,
        ..fr.clone()
    };
    let e2 = fr2.to_entity().unwrap();
    assert!(field(&decode(&e2.data), "next_hop").is_none());
    assert_eq!(ForwardRequest::from_entity(&e2).unwrap(), fr2);

    // §3.1 v1.0 single-hop byte-equality: a request with no `route` must NOT
    // carry a `route` key (omitempty), so it stays byte-identical to v1.0.
    assert!(field(&decode(&e.data), "route").is_none());

    // v1.1 source route round-trips and the key is present + ordered.
    let fr3 = ForwardRequest {
        route: Some(vec!["z6MkB".into(), "z6MkC".into(), "z6MkDest".into()]),
        next_hop: Some("z6MkB".into()),
        ..fr.clone()
    };
    let e3 = fr3.to_entity().unwrap();
    assert_eq!(ForwardRequest::from_entity(&e3).unwrap(), fr3);
    match field(&decode(&e3.data), "route") {
        Some(Value::Array(a)) => assert_eq!(a.len(), 3),
        other => panic!("route must be a 3-element array, got {:?}", other),
    }

    // An explicitly-empty route decodes back to None (behaves as absent).
    let fr4 = ForwardRequest {
        route: Some(vec![]),
        ..fr.clone()
    };
    assert_eq!(ForwardRequest::from_entity(&fr4.to_entity().unwrap()).unwrap().route, None);
}

#[test]
fn store_entry_round_trip() {
    let se = StoreEntry {
        namespace: "z6MkDest".into(),
        expires_at: Some(1_700_000_000_000),
        put_by: "z6MkPutter".into(),
        envelope_inner: lit_hash(0x11),
    };
    let e = se.to_entity().unwrap();
    assert_eq!(StoreEntry::from_entity(&e).unwrap(), se);
}

#[test]
fn advertise_round_trip() {
    let a = AdvertiseData {
        modes: vec![MODE_FORWARD.into(), MODE_STORE.into()],
        endpoints: vec![text("tcp://10.0.0.1:9000")],
        limits: AdvertiseLimits {
            max_envelope_size: Some(1 << 20),
            max_storage_bytes: None,
            forward_rate_limit: Some(100),
        },
        caps_required: vec![CAP_RELAY_FORWARD.into()],
        expires_at: None,
    };
    let e = a.to_entity().unwrap();
    assert_eq!(AdvertiseData::from_entity(&e).unwrap(), a);
}

#[test]
fn poll_request_round_trip() {
    let p = PollRequest {
        namespace: "z6MkDest".into(),
        since: Some(5u64.to_be_bytes().to_vec()),
        limit: Some(10),
    };
    let e = p.to_entity().unwrap();
    assert_eq!(PollRequest::from_params(&e.data).unwrap(), p);
}

// ---------------------------------------------------------------------------
// Wire-shape invariants (§3.0 / interop pitfalls)
// ---------------------------------------------------------------------------

#[test]
fn peer_id_fields_are_text_not_hash() {
    let fr = ForwardRequest {
        destination: "z6MkDest".into(),
        route: None,
        next_hop: Some("z6MkHop".into()),
        ttl_hops: 1,
        envelope_inner: lit_hash(0x01),
    };
    let map = decode(&fr.to_entity().unwrap().data);
    assert!(matches!(field(&map, "destination"), Some(Value::Text(_))));
    assert!(matches!(field(&map, "next_hop"), Some(Value::Text(_))));
    // envelope_inner is a bare 33-byte system/hash bstr, never wrapped.
    match field(&map, "envelope_inner") {
        Some(Value::Bytes(b)) => assert_eq!(b.len(), 33),
        other => panic!("envelope_inner must be 33-byte bstr, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Mode S — :put / :poll
// ---------------------------------------------------------------------------

fn put_ctx(keypair: &IdentityKeypair, namespace: &str, expires_at: Option<i64>, inner: &Entity) -> HandlerContext {
    let identity = keypair.peer_entity().unwrap();
    let author = identity.content_hash;
    let peer_id = keypair.peer_id().as_str().to_string();
    let se = StoreEntry {
        namespace: namespace.into(),
        expires_at,
        put_by: peer_id.clone(),
        envelope_inner: inner.content_hash,
    };
    // §2.2: put_by is checked against the authenticated *session* peer.
    ctx_session("put", se.to_entity().unwrap(), Some(author), vec![identity, inner.clone()], Some(&peer_id))
}

#[tokio::test]
async fn put_then_poll_returns_entry() {
    let (cs, li) = stores();
    let r = relay(&cs, &li);
    let kp = IdentityKeypair::from(Keypair::generate());
    let inner = inner_envelope(1);

    let put = r.handle(&put_ctx(&kp, "alice-ns", None, &inner)).await.unwrap();
    assert_eq!(put.status, 200, "{:?}", result_code(&put));
    let put_map = decode(&put.result.data);
    let entry_hash = match field(&put_map, "entry_hash") {
        Some(Value::Bytes(b)) => Hash::from_bytes(b).unwrap(),
        _ => panic!("missing entry_hash"),
    };
    // The opaque inner envelope was stored verbatim and is fetchable by hash.
    assert!(cs.get(&inner.content_hash).is_some(), "inner envelope must be stored");
    // Relay receive-side fetch-surface ruling: the inner is ALSO
    // tree-bound under the namespace subtree so the receiver fetches it via
    // `tree:get` (not `system/content`). path→hash to the same content-store blob.
    let inner_path = inner_store_path(PEER, "alice-ns", &inner.content_hash.to_hex());
    assert_eq!(
        li.get(&inner_path),
        Some(inner.content_hash),
        "inner must be tree-bound at system/relay/store/{{ns}}/inner/{{hash}}"
    );

    // Poll from start.
    let pr = PollRequest { namespace: "alice-ns".into(), since: None, limit: None };
    let poll = r.handle(&ctx("poll", pr.to_entity().unwrap(), None, vec![])).await.unwrap();
    assert_eq!(poll.status, 200);
    let pmap = decode(&poll.result.data);
    let entries = field(&pmap, "entries").and_then(|v| v.as_array()).cloned().unwrap();
    assert_eq!(entries.len(), 1);
    match &entries[0] {
        Value::Bytes(b) => assert_eq!(Hash::from_bytes(b).unwrap(), entry_hash),
        _ => panic!("entry must be a hash bstr"),
    }
    assert_eq!(field(&pmap, "has_more"), Some(&Value::Bool(false)));
}

#[tokio::test]
async fn empty_namespace_returns_empty_not_404() {
    let (cs, li) = stores();
    let r = relay(&cs, &li);
    let pr = PollRequest { namespace: "never-written".into(), since: None, limit: None };
    let poll = r.handle(&ctx("poll", pr.to_entity().unwrap(), None, vec![])).await.unwrap();
    assert_eq!(poll.status, 200); // NOT namespace_not_found/404 (§4.2)
    let pmap = decode(&poll.result.data);
    assert_eq!(field(&pmap, "entries").and_then(|v| v.as_array()).unwrap().len(), 0);
    assert_eq!(field(&pmap, "has_more"), Some(&Value::Bool(false)));
}

#[tokio::test]
async fn poll_cursor_advances() {
    let (cs, li) = stores();
    let r = relay(&cs, &li);
    let kp = IdentityKeypair::from(Keypair::generate());
    for i in 0..3u8 {
        let put = r.handle(&put_ctx(&kp, "ns", None, &inner_envelope(i))).await.unwrap();
        assert_eq!(put.status, 200, "{:?}", result_code(&put));
    }
    // Page size 2 → first page 2 entries + has_more, second page 1 + done.
    let p1 = PollRequest { namespace: "ns".into(), since: None, limit: Some(2) };
    let r1 = r.handle(&ctx("poll", p1.to_entity().unwrap(), None, vec![])).await.unwrap();
    let m1 = decode(&r1.result.data);
    assert_eq!(field(&m1, "entries").and_then(|v| v.as_array()).unwrap().len(), 2);
    assert_eq!(field(&m1, "has_more"), Some(&Value::Bool(true)));
    let cursor = field(&m1, "cursor").and_then(|v| v.as_bytes()).unwrap().to_vec();

    let p2 = PollRequest { namespace: "ns".into(), since: Some(cursor), limit: Some(2) };
    let r2 = r.handle(&ctx("poll", p2.to_entity().unwrap(), None, vec![])).await.unwrap();
    let m2 = decode(&r2.result.data);
    assert_eq!(field(&m2, "entries").and_then(|v| v.as_array()).unwrap().len(), 1);
    assert_eq!(field(&m2, "has_more"), Some(&Value::Bool(false)));
}

#[tokio::test]
async fn put_by_mismatch_rejected() {
    let (cs, li) = stores();
    let r = relay(&cs, &li);
    let kp = IdentityKeypair::from(Keypair::generate());
    let identity = kp.peer_entity().unwrap();
    let inner = inner_envelope(7);
    // put_by claims a DIFFERENT peer than the authenticated session peer.
    let se = StoreEntry {
        namespace: "ns".into(),
        expires_at: None,
        put_by: "z6MkSomeoneElse".into(),
        envelope_inner: inner.content_hash,
    };
    let session = kp.peer_id().as_str().to_string();
    let c = ctx_session(
        "put",
        se.to_entity().unwrap(),
        Some(identity.content_hash),
        vec![identity, inner],
        Some(&session),
    );
    let res = r.handle(&c).await.unwrap();
    assert_eq!(res.status, 400);
    assert_eq!(result_code(&res).as_deref(), Some(CODE_PUT_BY_MISMATCH));
}

#[tokio::test]
async fn expired_on_arrival_rejected_400() {
    let (cs, li) = stores();
    let r = relay(&cs, &li);
    let kp = IdentityKeypair::from(Keypair::generate());
    let inner = inner_envelope(3);
    // expires_at in the distant past.
    let res = r.handle(&put_ctx(&kp, "ns", Some(1), &inner)).await.unwrap();
    assert_eq!(res.status, 400);
    assert_eq!(result_code(&res).as_deref(), Some(CODE_EXPIRED_ON_ARRIVAL));
}

#[tokio::test]
async fn namespace_invalid_rejected() {
    let (cs, li) = stores();
    let r = relay(&cs, &li);
    let kp = IdentityKeypair::from(Keypair::generate());
    let inner = inner_envelope(4);
    let res = r.handle(&put_ctx(&kp, "bad/../escape", None, &inner)).await.unwrap();
    assert_eq!(res.status, 400);
    assert_eq!(result_code(&res).as_deref(), Some(CODE_NAMESPACE_INVALID));
}

// ---------------------------------------------------------------------------
// Mode F — :forward
// ---------------------------------------------------------------------------

fn forward_ctx(req: &ForwardRequest, inner: &Entity) -> HandlerContext {
    ctx("forward", req.to_entity().unwrap(), None, vec![inner.clone()])
}

#[tokio::test]
async fn forward_ttl_zero_rejected() {
    let (cs, li) = stores();
    let r = relay(&cs, &li);
    let inner = inner_envelope(1);
    let req = ForwardRequest {
        destination: "z6MkDest".into(),
        route: None,
        next_hop: Some("z6MkDest".into()),
        ttl_hops: 0,
        envelope_inner: inner.content_hash,
    };
    let res = r.handle(&forward_ctx(&req, &inner)).await.unwrap();
    assert_eq!(res.status, 400);
    assert_eq!(result_code(&res).as_deref(), Some(CODE_TTL_EXHAUSTED));
}

#[tokio::test]
async fn forward_no_next_hop_is_no_route() {
    let (cs, li) = stores();
    let r = relay(&cs, &li);
    let inner = inner_envelope(2);
    let req = ForwardRequest {
        destination: "z6MkDest".into(),
        route: None,
        next_hop: None,
        ttl_hops: 4,
        envelope_inner: inner.content_hash,
    };
    let res = r.handle(&forward_ctx(&req, &inner)).await.unwrap();
    assert_eq!(res.status, 502);
    assert_eq!(result_code(&res).as_deref(), Some(CODE_NO_ROUTE));
}

#[tokio::test]
async fn forward_unreachable_falls_back_to_mode_s() {
    let (cs, li) = stores();
    let r = relay(&cs, &li); // no forwarder → destination unreachable
    let dest = "z6MkOfflineDest";
    let inner = inner_envelope(9);
    let req = ForwardRequest {
        destination: dest.into(),
        route: None,
        next_hop: Some(dest.into()),
        ttl_hops: 4,
        envelope_inner: inner.content_hash,
    };
    let res = r.handle(&forward_ctx(&req, &inner)).await.unwrap();
    assert_eq!(res.status, 200, "{:?}", result_code(&res));
    let m = decode(&res.result.data);
    assert_eq!(field(&m, "status").and_then(|v| v.as_text()), Some(FORWARD_STATUS_QUEUED_FALLBACK));
    // §6.2.1: stored at namespace = destination peer_id; the destination polls
    // its own peer-id namespace on reconnect and retrieves the entry.
    assert_eq!(field(&m, "stored_at").and_then(|v| v.as_text()), Some(dest));

    let pr = PollRequest { namespace: dest.into(), since: None, limit: None };
    let poll = r.handle(&ctx("poll", pr.to_entity().unwrap(), None, vec![])).await.unwrap();
    let pm = decode(&poll.result.data);
    assert_eq!(field(&pm, "entries").and_then(|v| v.as_array()).unwrap().len(), 1);
    // The opaque inner envelope rode the fallback store and is fetchable.
    assert!(cs.get(&inner.content_hash).is_some());
}

// ---------------------------------------------------------------------------
// §3.1.1 — source-routed multi-hop + EXTENSION-ROUTE table read (v1.1)
// ---------------------------------------------------------------------------

/// A `RelayForwarder` that records the routing decision the handler made (the
/// resolved `next_hop`, terminal flag, decremented ttl, and the popped onward
/// route) and reports success — so a unit test can assert the §3.1.1 per-hop
/// algorithm without a live transport.
#[derive(Default)]
struct RecordingForwarder {
    last: std::sync::Mutex<Option<RecordedHop>>,
}

#[derive(Clone, Debug, PartialEq)]
struct RecordedHop {
    destination: String,
    next_hop: String,
    is_terminal: bool,
    ttl_hops: u32,
    onward_route: Vec<String>,
}

#[async_trait::async_trait]
impl crate::forwarder::RelayForwarder for RecordingForwarder {
    async fn forward(&self, ctx: crate::forwarder::ForwardCtx<'_>) -> ForwardOutcome {
        *self.last.lock().unwrap() = Some(RecordedHop {
            destination: ctx.destination.to_string(),
            next_hop: ctx.next_hop.to_string(),
            is_terminal: ctx.is_terminal,
            ttl_hops: ctx.ttl_hops,
            onward_route: ctx.onward_route.to_vec(),
        });
        ForwardOutcome::Forwarded {
            next_hop: ctx.next_hop.to_string(),
        }
    }
}

/// Build a forward-request, run it through a relay wired with a recording
/// forwarder, and return (handler result, the recorded hop).
async fn forward_recorded(req: ForwardRequest) -> (HandlerResult, Option<RecordedHop>) {
    let (cs, li) = stores();
    forward_recorded_with(&cs, &li, req).await
}

async fn forward_recorded_with(
    cs: &Arc<dyn ContentStore>,
    li: &Arc<dyn LocationIndex>,
    req: ForwardRequest,
) -> (HandlerResult, Option<RecordedHop>) {
    let rec = Arc::new(RecordingForwarder::default());
    let r = relay(cs, li).with_forwarder(rec.clone());
    let inner = inner_envelope(req.envelope_inner.digest()[0]);
    let req = ForwardRequest { envelope_inner: inner.content_hash, ..req };
    let res = r.handle(&forward_ctx(&req, &inner)).await.unwrap();
    let last = rec.last.lock().unwrap().clone();
    (res, last)
}

/// Tree-bind a `system/route` entity under this relay's route subtree, the way
/// a `route-configure`-capped `tree:put` would (EXTENSION-ROUTE §2).
fn install_route(cs: &Arc<dyn ContentStore>, li: &Arc<dyn LocationIndex>, rd: entity_route::RouteData) {
    let e = rd.to_entity().unwrap();
    let h = cs.put(e.clone()).unwrap();
    let path = format!("/{}/{}", PEER, entity_route::route_path(&h));
    li.set(&path, h);
}

const DEST: &str = "z6MkSourceRouteDest";
const HOP_B: &str = "z6MkHopB";
const HOP_C: &str = "z6MkHopC";

// --- SRCROUTE: invariant — route + mismatching next_hop → invalid_request/400,
//     PRE-DISPATCH (the recording forwarder must NOT be reached). ------------
#[tokio::test]
async fn source_route_next_hop_mismatch_rejected_pre_dispatch() {
    let req = ForwardRequest {
        destination: DEST.into(),
        route: Some(vec![HOP_B.into(), DEST.into()]),
        next_hop: Some("z6MkSomethingElse".into()), // ≠ route[0]
        ttl_hops: 8,
        envelope_inner: lit_hash(0x21),
    };
    let (res, recorded) = forward_recorded(req).await;
    assert_eq!(res.status, 400);
    assert_eq!(result_code(&res).as_deref(), Some(CODE_INVALID_REQUEST));
    assert!(recorded.is_none(), "invariant must reject before any forward");
}

// A matching next_hop == route[0] is accepted (advisory, not an error).
#[tokio::test]
async fn source_route_next_hop_matching_head_ok() {
    let req = ForwardRequest {
        destination: DEST.into(),
        route: Some(vec![HOP_B.into(), DEST.into()]),
        next_hop: Some(HOP_B.into()), // == route[0]
        ttl_hops: 8,
        envelope_inner: lit_hash(0x22),
    };
    let (res, recorded) = forward_recorded(req).await;
    assert_eq!(res.status, 200);
    assert_eq!(recorded.unwrap().next_hop, HOP_B);
}

// --- SRCROUTE: intermediate pops the head — route'=route[1:], next='B',
//     ttl-1, not terminal (cross-impl trap #3). ----------------------------
#[tokio::test]
async fn source_route_intermediate_pops_head() {
    let req = ForwardRequest {
        destination: DEST.into(),
        route: Some(vec![HOP_B.into(), HOP_C.into(), DEST.into()]),
        next_hop: None,
        ttl_hops: 8,
        envelope_inner: lit_hash(0x23),
    };
    let (res, recorded) = forward_recorded(req).await;
    assert_eq!(res.status, 200);
    let hop = recorded.unwrap();
    assert_eq!(hop.next_hop, HOP_B);
    assert!(!hop.is_terminal, "B != destination → intermediate");
    assert_eq!(hop.ttl_hops, 7, "ttl decremented once");
    assert_eq!(hop.onward_route, vec![HOP_C.to_string(), DEST.to_string()]);
}

// --- SRCROUTE-TERMINAL-EQUIV: route=[D] behaves identically to next_hop=D. --
#[tokio::test]
async fn source_route_single_element_is_terminal_equiv() {
    let via_route = ForwardRequest {
        destination: DEST.into(),
        route: Some(vec![DEST.into()]),
        next_hop: None,
        ttl_hops: 5,
        envelope_inner: lit_hash(0x24),
    };
    let (res_r, hop_r) = forward_recorded(via_route).await;
    let via_next_hop = ForwardRequest {
        destination: DEST.into(),
        route: None,
        next_hop: Some(DEST.into()),
        ttl_hops: 5,
        envelope_inner: lit_hash(0x24),
    };
    let (res_n, hop_n) = forward_recorded(via_next_hop).await;

    assert_eq!(res_r.status, 200);
    assert_eq!(res_n.status, 200);
    let (hop_r, hop_n) = (hop_r.unwrap(), hop_n.unwrap());
    assert!(hop_r.is_terminal && hop_n.is_terminal);
    assert_eq!(hop_r.next_hop, DEST);
    assert_eq!(hop_r.onward_route, Vec::<String>::new());
    // The two paths produce the same routing decision.
    assert_eq!(hop_r, hop_n);
}

// --- ROUTE table: forward route resolves next=via when no source route. -----
#[tokio::test]
async fn route_table_forward_resolves_via() {
    let (cs, li) = stores();
    install_route(
        &cs,
        &li,
        entity_route::RouteData {
            match_dest: DEST.into(),
            action: entity_route::ROUTE_ACTION_FORWARD.into(),
            via: Some(HOP_B.into()),
            metric: 0,
            expires_at: 0,
        },
    );
    let req = ForwardRequest {
        destination: DEST.into(),
        route: None,
        next_hop: None, // no source route, no next_hop → table read
        ttl_hops: 4,
        envelope_inner: lit_hash(0x25),
    };
    let (res, recorded) = forward_recorded_with(&cs, &li, req).await;
    assert_eq!(res.status, 200);
    let hop = recorded.unwrap();
    assert_eq!(hop.next_hop, HOP_B);
    assert!(!hop.is_terminal);
}

// --- ROUTE table: deliver route makes this relay terminal. ------------------
#[tokio::test]
async fn route_table_deliver_is_terminal() {
    let (cs, li) = stores();
    install_route(
        &cs,
        &li,
        entity_route::RouteData {
            match_dest: DEST.into(),
            action: entity_route::ROUTE_ACTION_DELIVER.into(),
            via: None,
            metric: 0,
            expires_at: 0,
        },
    );
    let req = ForwardRequest {
        destination: DEST.into(),
        route: None,
        next_hop: None,
        ttl_hops: 4,
        envelope_inner: lit_hash(0x26),
    };
    let (res, recorded) = forward_recorded_with(&cs, &li, req).await;
    assert_eq!(res.status, 200);
    let hop = recorded.unwrap();
    assert_eq!(hop.next_hop, DEST);
    assert!(hop.is_terminal);
}

// --- ROUTE precedence: an explicit source route OVERRIDES the table (trap #5).
#[tokio::test]
async fn source_route_takes_precedence_over_table() {
    let (cs, li) = stores();
    // Table says dest → via HOP_C, but the originator dictates route via HOP_B.
    install_route(
        &cs,
        &li,
        entity_route::RouteData {
            match_dest: DEST.into(),
            action: entity_route::ROUTE_ACTION_FORWARD.into(),
            via: Some(HOP_C.into()),
            metric: 0,
            expires_at: 0,
        },
    );
    let req = ForwardRequest {
        destination: DEST.into(),
        route: Some(vec![HOP_B.into(), DEST.into()]),
        next_hop: None,
        ttl_hops: 6,
        envelope_inner: lit_hash(0x27),
    };
    let (res, recorded) = forward_recorded_with(&cs, &li, req).await;
    assert_eq!(res.status, 200);
    assert_eq!(recorded.unwrap().next_hop, HOP_B, "source route must win over table");
}

// --- ROUTE table: non-matching table → no_route/502 (no fallback before a
//     dispatch attempt; the table read found nothing to dispatch). ----------
#[tokio::test]
async fn route_table_no_match_is_no_route() {
    let (cs, li) = stores();
    install_route(
        &cs,
        &li,
        entity_route::RouteData {
            match_dest: "z6MkSomeoneElse".into(),
            action: entity_route::ROUTE_ACTION_FORWARD.into(),
            via: Some(HOP_B.into()),
            metric: 0,
            expires_at: 0,
        },
    );
    let req = ForwardRequest {
        destination: DEST.into(),
        route: None,
        next_hop: None,
        ttl_hops: 4,
        envelope_inner: lit_hash(0x28),
    };
    let (res, recorded) = forward_recorded_with(&cs, &li, req).await;
    assert_eq!(res.status, 502);
    assert_eq!(result_code(&res).as_deref(), Some(CODE_NO_ROUTE));
    assert!(recorded.is_none());
}

// ---------------------------------------------------------------------------
// §3.5 inbox-relay declaration + resolver + no_inbox_relay fallback
// ---------------------------------------------------------------------------

#[test]
fn inbox_relay_round_trip() {
    let d = InboxRelayData {
        relays: vec![
            InboxRelayEntry { relay: "z6MkR1".into(), namespace: "z6MkDest".into(), priority: 10 },
            InboxRelayEntry { relay: "z6MkR2".into(), namespace: "z6MkDest".into(), priority: 50 },
        ],
        expires_at: Some(1730999999999),
    };
    let e = d.to_entity().unwrap();
    assert_eq!(InboxRelayData::from_entity(&e).unwrap(), d);
    // priority sort: lower wins among entries targeting a given relay.
    assert_eq!(d.namespace_for_relay("z6MkR1").as_deref(), Some("z6MkDest"));
    assert_eq!(d.namespace_for_relay("z6MkUnlisted"), None);
}

struct StaticResolver(Option<InboxRelayData>);
#[async_trait::async_trait]
impl InboxRelayResolver for StaticResolver {
    async fn resolve(&self, _destination: &str) -> Option<InboxRelayData> {
        self.0.clone()
    }
}

#[tokio::test]
async fn fallback_honors_declared_inbox_relay_namespace() {
    let (cs, li) = stores();
    // The destination declares THIS relay (PEER) as its inbox-relay, with a
    // custom namespace. The fallback MUST store at that declared namespace.
    let decl = InboxRelayData {
        relays: vec![InboxRelayEntry {
            relay: PEER.into(),
            namespace: "custom-inbox".into(),
            priority: 10,
        }],
        expires_at: None,
    };
    let r = relay(&cs, &li).with_inbox_relay_resolver(Arc::new(StaticResolver(Some(decl))));
    let inner = inner_envelope(5);
    let req = ForwardRequest {
        destination: "z6MkOffline".into(),
        route: None,
        next_hop: Some("z6MkOffline".into()),
        ttl_hops: 4,
        envelope_inner: inner.content_hash,
    };
    let res = r.handle(&forward_ctx(&req, &inner)).await.unwrap();
    assert_eq!(res.status, 200);
    let m = decode(&res.result.data);
    assert_eq!(field(&m, "status").and_then(|v| v.as_text()), Some(FORWARD_STATUS_QUEUED_FALLBACK));
    assert_eq!(field(&m, "stored_at").and_then(|v| v.as_text()), Some("custom-inbox"));
    // Pollable at the declared namespace.
    let pr = PollRequest { namespace: "custom-inbox".into(), since: None, limit: None };
    let poll = r.handle(&ctx("poll", pr.to_entity().unwrap(), None, vec![])).await.unwrap();
    assert_eq!(field(&decode(&poll.result.data), "entries").and_then(|v| v.as_array()).unwrap().len(), 1);
}

#[tokio::test]
async fn fallback_no_inbox_relay_when_mx_required() {
    let (cs, li) = stores();
    // MX-required posture + no declaration → no_inbox_relay/502, never silent.
    let r = relay(&cs, &li)
        .with_inbox_relay_resolver(Arc::new(StaticResolver(None)))
        .with_disable_default_fallback(true);
    let inner = inner_envelope(6);
    let req = ForwardRequest {
        destination: "z6MkOffline".into(),
        route: None,
        next_hop: Some("z6MkOffline".into()),
        ttl_hops: 4,
        envelope_inner: inner.content_hash,
    };
    let res = r.handle(&forward_ctx(&req, &inner)).await.unwrap();
    assert_eq!(res.status, 502);
    assert_eq!(result_code(&res).as_deref(), Some(CODE_NO_INBOX_RELAY));
}

// ---------------------------------------------------------------------------
// §3.5 TreeInboxRelayResolver — tree-read + V7 §5.2 signature verification
// (forged-redirection defense). Mirrors Go's TreeInboxRelayResolver path.
// ---------------------------------------------------------------------------

/// Publish a signed `system/peer/inbox-relay` declaration into the relay's tree
/// the way the §3.5 fixture does: the declaration entity at the inbox-relay
/// path, and its V7 §5.2 invariant-pointer signature (authored by `signer_kp`).
/// For the honest case `signer_kp` IS the destination; for the forged case it
/// is an attacker key declaring a redirect of the destination's mail.
fn publish_inbox_relay_decl(
    cs: &Arc<dyn ContentStore>,
    li: &Arc<dyn LocationIndex>,
    dest_pid: &str,
    decl: &InboxRelayData,
    signer_kp: &IdentityKeypair,
) {
    let decl_entity = decl.to_entity().unwrap();
    let decl_hash = decl_entity.content_hash;
    cs.put(decl_entity).unwrap();
    li.set(&format!("/{}/{}", PEER, inbox_relay_path(dest_pid)), decl_hash);

    let signer_identity = signer_kp.peer_entity().unwrap();
    cs.put(signer_identity.clone()).unwrap();
    let sig = entity_types::SignatureData {
        target: decl_hash,
        signer: signer_identity.content_hash,
        algorithm: "ed25519".into(),
        signature: signer_kp.sign(&decl_hash.to_bytes()).to_vec(),
    }
    .to_entity()
    .unwrap();
    let sig_hash = sig.content_hash;
    cs.put(sig).unwrap();
    li.set(&entity_hash::invariant_signature_path(PEER, &decl_hash), sig_hash);
}

#[tokio::test]
async fn tree_resolver_returns_verified_declaration() {
    let (cs, li) = stores();
    let dest_kp = IdentityKeypair::from(Keypair::generate());
    let dest_pid = dest_kp.peer_id().as_str().to_string();
    let decl = InboxRelayData {
        relays: vec![InboxRelayEntry {
            relay: PEER.into(),
            namespace: "custom-inbox".into(),
            priority: 10,
        }],
        expires_at: None,
    };
    // Honest: the destination itself signs its declaration.
    publish_inbox_relay_decl(&cs, &li, &dest_pid, &decl, &dest_kp);

    let resolver = TreeInboxRelayResolver::new(cs.clone(), li.clone(), PEER.into());
    assert_eq!(resolver.resolve(&dest_pid).await, Some(decl));
}

#[tokio::test]
async fn tree_resolver_rejects_forged_declaration() {
    let (cs, li) = stores();
    let dest_kp = IdentityKeypair::from(Keypair::generate());
    let dest_pid = dest_kp.peer_id().as_str().to_string();
    let attacker_kp = IdentityKeypair::from(Keypair::generate());
    // Forged-redirection (V7 §5.2): the attacker plants a declaration redirecting
    // the destination's mail, with a real, self-consistent signature — but by the
    // attacker's OWN key, not the destination's. The resolver derives the
    // destination's key from its peer-id and rejects (signer ≠ destination).
    let decl = InboxRelayData {
        relays: vec![InboxRelayEntry {
            relay: PEER.into(),
            namespace: "attacker-controlled".into(),
            priority: 10,
        }],
        expires_at: None,
    };
    publish_inbox_relay_decl(&cs, &li, &dest_pid, &decl, &attacker_kp);

    let resolver = TreeInboxRelayResolver::new(cs.clone(), li.clone(), PEER.into());
    assert_eq!(
        resolver.resolve(&dest_pid).await,
        None,
        "forged decl (signed by a non-destination key) MUST be rejected fail-closed"
    );
}

#[tokio::test]
async fn tree_resolver_none_when_undeclared() {
    let (cs, li) = stores();
    let dest_kp = IdentityKeypair::from(Keypair::generate());
    let resolver = TreeInboxRelayResolver::new(cs.clone(), li.clone(), PEER.into());
    // No declaration published → None (the handler then takes the default
    // convention or surfaces no_inbox_relay under the MX-required posture).
    assert_eq!(resolver.resolve(dest_kp.peer_id().as_str()).await, None);
}

// ---------------------------------------------------------------------------
// Byte-equal cohort fixtures (RELAY-R5-COHORT-HANDOFF.md §3) — the cross-impl
// convergence gate. Content-hash digests MUST match Go's pins byte-for-byte.
// ---------------------------------------------------------------------------

const FIX_SENDER: &str = "2KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const FIX_RELAY: &str = "2KBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const FIX_DEST: &str = "2KCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

/// Digest-only hex (32 bytes, no leading format byte) — the form Go pins as
/// `ecf-sha256:<hex>`.
fn digest_hex(e: &Entity) -> String {
    e.content_hash.digest().iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn fixture_f1_forward_request_full() {
    let e = ForwardRequest {
        destination: FIX_DEST.into(),
        route: None,
        next_hop: Some(FIX_RELAY.into()),
        ttl_hops: 5,
        envelope_inner: lit_hash(0xEE),
    }
    .to_entity()
    .unwrap();
    // §3.1 omitempty: the absent `route` keeps this byte-identical to v1.0, so
    // the digest is unchanged — the cross-impl byte-equality pin still holds.
    assert_eq!(digest_hex(&e), "a5f7048f6c5f44ba64c5a3373ded97d77c2600f62236e7e48be3d1cc42a24476");
}

#[test]
fn fixture_f2_forward_request_no_next_hop() {
    let e = ForwardRequest {
        destination: FIX_DEST.into(),
        route: None,
        next_hop: None,
        ttl_hops: 3,
        envelope_inner: lit_hash(0xEE),
    }
    .to_entity()
    .unwrap();
    assert_eq!(digest_hex(&e), "73acd98db5781cbe28ad777628a72696cf9494e0135647888cfc98f918b1d42b");
}

#[test]
fn fixture_s1_store_entry_full() {
    let e = StoreEntry {
        namespace: FIX_DEST.into(),
        expires_at: Some(1730000900000),
        put_by: FIX_SENDER.into(),
        envelope_inner: lit_hash(0xEE),
    }
    .to_entity()
    .unwrap();
    assert_eq!(digest_hex(&e), "7170ad83b98218b6e976b1612573ad2f22bd3a6cc07be05aeb954a8cbeadb893");
}

#[test]
fn fixture_s2_store_entry_no_expiry() {
    let e = StoreEntry {
        namespace: FIX_DEST.into(),
        expires_at: None,
        put_by: FIX_SENDER.into(),
        envelope_inner: lit_hash(0xEE),
    }
    .to_entity()
    .unwrap();
    assert_eq!(digest_hex(&e), "e6b39ba557d16e0434ca8a9f99c4dd3a18b1c5ce5811a7da08e8802cfbefd660");
}

#[test]
fn fixture_a2_advertise_mode_s_only() {
    let e = AdvertiseData {
        modes: vec![MODE_STORE.into()],
        endpoints: vec![],
        limits: AdvertiseLimits::default(),
        caps_required: vec![CAP_RELAY_POLL.into()],
        expires_at: None,
    }
    .to_entity()
    .unwrap();
    assert_eq!(digest_hex(&e), "ad08fae1f18d664eeaa00cc81980fef729ed9208f10027d281b45f81b2f361cb");
}

#[test]
fn fixture_r1_forward_result_forwarded() {
    let e = ForwardResult {
        status: FORWARD_STATUS_FORWARDED.into(),
        next_hop: Some(FIX_RELAY.into()),
        stored_at: None,
    }
    .to_entity()
    .unwrap();
    assert_eq!(digest_hex(&e), "301ad8fa052934d2f89dfdadf55c1a935dde76a1961bda294e66007a91c41cac");
}

#[test]
fn fixture_r2_forward_result_queued_fallback() {
    let e = ForwardResult {
        status: FORWARD_STATUS_QUEUED_FALLBACK.into(),
        next_hop: None,
        stored_at: Some(FIX_DEST.into()), // bare namespace, not full path
    }
    .to_entity()
    .unwrap();
    assert_eq!(digest_hex(&e), "beb909b6fd44a8f18f8922e69b514b63951f553b9e9faf1004ebd929047e801c");
}

#[test]
fn fixture_r4_poll_request_fresh() {
    let e = PollRequest { namespace: FIX_DEST.into(), since: None, limit: None }
        .to_entity()
        .unwrap();
    assert_eq!(digest_hex(&e), "02e3b67a804e7f8fe8ced4db9ae3b50f141635e53632e2e9decfcfd57188e2d3");
}

#[test]
fn fixture_r6_poll_result_empty() {
    let e = PollResult::new(vec![], 0, false).to_entity().unwrap();
    assert_eq!(digest_hex(&e), "31945acad42877af8832ceba4a2521b24dd1615606a128ed8185d55ad9cabec8");
}

#[test]
fn fixture_r7_poll_result_with_entries() {
    let e = PollResult::new(vec![lit_hash(0xA1), lit_hash(0xA2), lit_hash(0xA3)], 3, true)
        .to_entity()
        .unwrap();
    assert_eq!(digest_hex(&e), "00ef28d4599590dcae25c30f81fce96102aa05fdcbfae88dbb09e2429f3d3485");
}

#[test]
fn fixture_i1_inbox_relay_single() {
    let e = InboxRelayData {
        relays: vec![InboxRelayEntry {
            relay: FIX_RELAY.into(),
            namespace: FIX_DEST.into(),
            priority: 10,
        }],
        expires_at: Some(1730999999999),
    }
    .to_entity()
    .unwrap();
    assert_eq!(digest_hex(&e), "8d2039cbea7ab65ff59fa6ad5055e062c357d3314f8ccfd2ab31c03ef31629b0");
}

#[test]
fn fixture_i2_inbox_relay_primary_backup() {
    let e = InboxRelayData {
        relays: vec![
            InboxRelayEntry { relay: FIX_RELAY.into(), namespace: FIX_DEST.into(), priority: 10 },
            InboxRelayEntry { relay: FIX_SENDER.into(), namespace: FIX_DEST.into(), priority: 50 },
        ],
        expires_at: None,
    }
    .to_entity()
    .unwrap();
    assert_eq!(digest_hex(&e), "9e00962b4b7023e21431cd9d04e00e75fb7b785c602558494a15346e98a336cc");
}

#[test]
fn namespace_validation() {
    assert!(is_valid_namespace("z6MkDest"));
    assert!(is_valid_namespace("a/b/c"));
    assert!(!is_valid_namespace(""));
    assert!(!is_valid_namespace("/leading"));
    assert!(!is_valid_namespace("trailing/"));
    assert!(!is_valid_namespace("a//b"));
    assert!(!is_valid_namespace("a/../b"));
}
