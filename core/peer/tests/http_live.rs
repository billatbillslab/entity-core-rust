//! HTTP live transport — integration tests.
//!
//! End-to-end coverage for `system/peer/transport/http` server-side
//! per `PROPOSAL-EXTENSION-NETWORK-TRANSPORT-FAMILY §5` + cohort
//! handoff alignment. Each test binds a real
//! HttpLiveListener on 127.0.0.1:0 and drives it with a `reqwest`
//! client.
//!
//! Wire shape under test (Amendment 3):
//! - Body = bare ECF envelope; HTTP Content-Length frames it; NO
//!   4-byte length prefix (the V7 §1.6 TCP prefix MUST NOT apply).
//! - `X-Entity-Session` header for multi-POST session correlation.
//!
//! What we validate at the transport layer:
//! - GET / → 405 with Allow: POST (POST-only per §5.2)
//! - POST to wrong path → 404
//! - POST garbage → 400 (envelope decode fails)
//! - POST a hello envelope (no session ID) → 200 with the server's
//!   allocated session ID echoed in the response header
//! - Second POST with same session ID → server reuses session state

#![cfg(all(feature = "http-live", not(target_arch = "wasm32")))]

use std::sync::Arc;

use entity_crypto::{IdentityKeypair, Keypair};
use entity_entity::{Entity, Envelope};
use entity_hash::Hash;
use entity_peer::http_live::{HttpLiveListener, NamespaceScope, ScopePredicate, SESSION_HEADER};
use entity_peer::PeerBuilder;
use entity_protocol::HelloData;
use entity_wire::{decode_envelope, encode_envelope};

/// Bind a listener on an ephemeral port and spawn its accept loop.
/// Returns the bound URL (`http://127.0.0.1:<port>/entity`).
async fn spawn_listener(seed: u8) -> (String, tokio::task::JoinHandle<()>) {
    let server = PeerBuilder::new()
        .keypair(Keypair::from_seed([seed; 32]))
        .build()
        .expect("peer builds");
    let shared = server.shared();
    server.start_engines(&shared);

    let listener = HttpLiveListener::bind("127.0.0.1:0", "/entity")
        .await
        .expect("http listener binds");
    let addr = listener.bound_addr();
    let path = listener.url_path().expect("listener has execute path").to_string();
    let url = format!("http://{}{}", addr, path);

    let shared_clone = shared.clone();
    let handle = tokio::spawn(async move {
        let _ = listener.serve(shared_clone).await;
    });

    // Yield so the accept loop is parked on `accept().await`.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    (url, handle)
}

/// Build a POST body: bare ECF envelope. Per EXTENSION-NETWORK
/// §6.5.2c Amendment 3, HTTP carries the bare envelope and HTTP's own
/// Content-Length frames it — no 4-byte length prefix.
fn body_from_envelope(envelope: &Envelope) -> Vec<u8> {
    encode_envelope(envelope)
}

/// Decode a response body as a bare ECF envelope.
fn envelope_from_body(body: &[u8]) -> Envelope {
    decode_envelope(body).expect("response decodes as bare envelope")
}

/// Build a real HELLO EXECUTE envelope from the given keypair. Used to
/// drive the session-correlated handshake tests.
fn build_hello_envelope(keypair: &Keypair) -> Envelope {
    let mut nonce = vec![0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    let hello = HelloData {
        peer_id: keypair.peer_id().as_str().to_string(),
        nonce,
        protocols: vec!["entity-core/1.0".to_string()],
        hash_formats: vec![],
        key_types: vec![],
        timestamp: None,
    };
    let hello_entity = hello.to_entity().expect("hello to_entity");
    // Wrap in an EXECUTE envelope. The hello EXECUTE has uri =
    // "system/protocol/connect" and operation = "hello"; params is the
    // hello data entity.
    let request_id = "hello-test-1";
    let execute_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (
            entity_ecf::text("uri"),
            entity_ecf::text("system/protocol/connect"),
        ),
        (entity_ecf::text("operation"), entity_ecf::text("hello")),
        (entity_ecf::text("request_id"), entity_ecf::text(request_id)),
        (
            entity_ecf::text("params"),
            entity_ecf::Value::Map(vec![
                (
                    entity_ecf::text("type"),
                    entity_ecf::text(entity_types::TYPE_HELLO),
                ),
                (
                    entity_ecf::text("data"),
                    ciborium::from_reader::<ciborium::Value, _>(hello_entity.data.as_slice())
                        .unwrap(),
                ),
                (
                    entity_ecf::text("content_hash"),
                    entity_ecf::Value::Bytes(hello_entity.content_hash.to_bytes().to_vec()),
                ),
            ]),
        ),
    ]));
    let execute_entity =
        Entity::new("system/protocol/execute", execute_data).expect("execute entity");
    Envelope::new(execute_entity)
}

#[tokio::test]
async fn get_returns_405_with_allow_post() {
    let (url, handle) = spawn_listener(40).await;

    let client = reqwest::Client::new();
    let resp = client.get(&url).send().await.expect("GET sends");
    assert_eq!(resp.status().as_u16(), 405);
    let allow = resp
        .headers()
        .get(reqwest::header::ALLOW)
        .and_then(|v| v.to_str().ok());
    assert_eq!(allow, Some("POST"));

    handle.abort();
}

#[tokio::test]
async fn wrong_path_returns_404() {
    let (url, handle) = spawn_listener(41).await;

    let base = url.rsplit_once('/').map(|(b, _)| b).unwrap().to_string();
    let bad_url = format!("{}/not-the-entity-path", base);

    let client = reqwest::Client::new();
    let resp = client
        .post(&bad_url)
        .body("anything")
        .send()
        .await
        .expect("POST sends");
    assert_eq!(resp.status().as_u16(), 404);

    handle.abort();
}

#[tokio::test]
async fn post_garbage_returns_400() {
    let (url, handle) = spawn_listener(42).await;

    let client = reqwest::Client::new();
    // Garbage that isn't a valid CBOR envelope; HTTP-layer 400.
    let body = vec![0xFF, 0xFE, 0xFD, 0xFC];
    let resp = client
        .post(&url)
        .body(body)
        .send()
        .await
        .expect("POST sends");
    assert_eq!(resp.status().as_u16(), 400);

    handle.abort();
}

#[tokio::test]
async fn post_empty_body_returns_400() {
    // Amendment 3 — body is bare ECF; an empty body fails envelope
    // decode at the HTTP layer (400, NOT a framing error since there
    // is no length prefix in scope anymore).
    let (url, handle) = spawn_listener(43).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .body(Vec::<u8>::new())
        .send()
        .await
        .expect("POST sends");
    assert_eq!(resp.status().as_u16(), 400);

    handle.abort();
}

#[tokio::test]
async fn hello_envelope_round_trips_and_allocates_session() {
    // First POST: client has no session ID; server allocates one and
    // returns it in the X-Entity-Session response header. The body is
    // a hello EXECUTE; the response is the server's HELLO_RESPONSE
    // envelope (status 200 entity-protocol-level + the server's nonce
    // + peer_id in the included hello entity).
    let (url, handle) = spawn_listener(44).await;
    let client_keypair = Keypair::from_seed([99u8; 32]);

    let hello = build_hello_envelope(&client_keypair);
    let body = body_from_envelope(&hello);

    let client = reqwest::Client::new();
    let resp = client.post(&url).body(body).send().await.expect("POST sends");

    assert_eq!(resp.status().as_u16(), 200);
    let session_id = resp
        .headers()
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .expect("session header on response");
    // ID format is impl-opaque (ruling §2 — NOT a cohort
    // pin). Just check the header round-tripped non-empty.
    assert!(!session_id.is_empty(), "session ID present + non-empty");

    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());
    assert_eq!(ct, Some("application/cbor"));

    let response_body = resp.bytes().await.expect("body reads").to_vec();
    let response_envelope = envelope_from_body(&response_body);

    // Response root is a system/protocol/execute_response carrying
    // the server's HELLO data as the result.
    assert!(
        !response_envelope.root.entity_type.is_empty(),
        "response envelope root has a type"
    );

    handle.abort();
}

#[tokio::test]
async fn session_id_persists_across_two_posts() {
    // After the first POST allocates a session, echoing the session
    // header on the next POST MUST reuse the same Connection state
    // (the server doesn't allocate a fresh session). This is what lets
    // the multi-step handshake spread across requests.
    let (url, handle) = spawn_listener(45).await;
    let client_keypair = Keypair::from_seed([99u8; 32]);
    let client = reqwest::Client::new();

    // POST 1: hello (no session header on request)
    let body1 = body_from_envelope(&build_hello_envelope(&client_keypair));
    let resp1 = client.post(&url).body(body1).send().await.expect("POST 1");
    assert_eq!(resp1.status().as_u16(), 200);
    let session_1 = resp1
        .headers()
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .expect("session 1");
    // Drain body so the connection can be reused.
    let _ = resp1.bytes().await;

    // POST 2: pass the session header back. Server MUST echo the SAME
    // ID (no fresh allocation). The body here is a hello again — the
    // server will now reject it (state != AwaitingHello) but the
    // session identity is what we're testing.
    let body2 = body_from_envelope(&build_hello_envelope(&client_keypair));
    let resp2 = client
        .post(&url)
        .header(SESSION_HEADER, &session_1)
        .body(body2)
        .send()
        .await
        .expect("POST 2");
    assert_eq!(resp2.status().as_u16(), 200);
    let session_2 = resp2
        .headers()
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .expect("session 2");
    assert_eq!(session_1, session_2, "session ID must persist across POSTs");

    handle.abort();
}

#[tokio::test]
async fn url_path_normalized_with_leading_slash() {
    let listener = HttpLiveListener::bind("127.0.0.1:0", "entity")
        .await
        .expect("bind with non-slash path");
    assert_eq!(listener.url_path(), Some("/entity"));
    assert_eq!(listener.poll_prefix(), None);

    let listener2 = HttpLiveListener::bind("127.0.0.1:0", "/v1/entity")
        .await
        .expect("bind with slash path");
    assert_eq!(listener2.url_path(), Some("/v1/entity"));

    drop(listener);
    drop(listener2);
}

// ============================================================
// Chunk E — http-poll serving-mode routes
// ============================================================
//
// Per the serving-mode content-scope ruling:
// - Content route: hash-knowledge-as-auth, scope-predicate is the
//   serving-side lever. v1 ships NamespaceScope (tree-binding under
//   `system/content/{ns}` is membership).
// - T4 mitigation: identical 404 for out-of-scope vs not-held vs
//   no-scope-configured (no presence oracle).
// - Tree-get + manifest-get stubs return 501 (deferred).

/// Convenience hex encoder for tests (same impl as http_live's
/// internal one — kept inline to avoid leaking a public hex helper
/// from a transport module).
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Spawn a Posture-1 (isolated-port) poll-only listener with a
/// NamespaceScope predicate. Returns (base_url, peer_id, shared,
/// join_handle). The peer_id is needed to build the namespace-scoped
/// tree path for binding test content.
async fn spawn_poll_listener_with_namespace(
    seed: u8,
    namespace: &str,
) -> (
    String,
    String,
    std::sync::Arc<entity_peer::PeerShared>,
    tokio::task::JoinHandle<()>,
) {
    let server = PeerBuilder::new()
        .keypair(Keypair::from_seed([seed; 32]))
        .build()
        .expect("peer builds");
    let peer_id = server.peer_id().to_string();
    let shared = server.shared();
    server.start_engines(&shared);

    let listener = HttpLiveListener::bind_poll("127.0.0.1:0", "")
        .await
        .expect("poll listener binds")
        .with_scope(Arc::new(NamespaceScope::new(namespace)));
    let addr = listener.bound_addr();
    let url = format!("http://{}", addr);

    let shared_clone = shared.clone();
    let handle = tokio::spawn(async move {
        let _ = listener.serve(shared_clone).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    (url, peer_id, shared, handle)
}

/// Put an entity into the peer's content store and bind it into the
/// given namespace at `/{peer_id}/{namespace}/{hex(H)}` so it becomes
/// in-scope for NamespaceScope.
fn publish_into_namespace(
    shared: &Arc<entity_peer::PeerShared>,
    peer_id: &str,
    namespace: &str,
    entity: Entity,
) -> Hash {
    let h = entity.content_hash;
    shared
        .content_store
        .put(entity)
        .expect("content store put");
    // 66-char wire-hash leaf per ruling §5 B.
    let hex_h = hex_encode(&h.to_bytes());
    let path = format!("/{}/{}/{}", peer_id, namespace, hex_h);
    shared.location_index.set(&path, h);
    h
}

#[tokio::test]
async fn poll_content_get_in_namespace_returns_200_with_entity_ecf_that_rehashes_to_url_hash() {
    // **Arch ruling 1b5c125 §1.** The body is the full
    // entity ECF — `ecf_for_hash(type, data)`, the exact bytes that
    // produce H under SHA-256. Content-Type: application/cbor. The
    // load-bearing invariant: re-hashing the body MUST equal the URL
    // hash; this is the verify-by-rehash contract that makes the
    // route content-addressed. (Mirrors Go's
    // `crossimpl_poll_test.go:114` `hash.Validate(...)` assertion —
    // the "one-line invariant that catches all three divergences".)
    let (url, peer_id, shared, handle) =
        spawn_poll_listener_with_namespace(60, "system/content/public").await;

    let entity = Entity::new("test/blob", b"hello chunk E".to_vec()).expect("entity");
    let expected_type = entity.entity_type.clone();
    let expected_data = entity.data.clone();
    let h = publish_into_namespace(&shared, &peer_id, "system/content/public", entity);
    let hex_h = hex_encode(&h.to_bytes());
    let target = format!("{}/content/{}", url, hex_h);

    let client = reqwest::Client::new();
    let resp = client.get(&target).send().await.expect("GET sends");

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/cbor"),
        "ruling §1: application/cbor reflects the wrapped entity ECF"
    );
    let etag = resp
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .expect("ETag header");
    assert_eq!(etag, format!("\"{}\"", hex_h));
    let cache_control = resp
        .headers()
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .expect("Cache-Control header");
    assert!(
        cache_control.contains("immutable"),
        "Cache-Control should include 'immutable', got: {}",
        cache_control
    );

    let body = resp.bytes().await.expect("body reads").to_vec();

    // Invariant 1 — body == ecf_for_hash(type, data).
    let expected = entity_ecf::ecf_for_hash(&expected_type, &expected_data);
    assert_eq!(
        body, expected,
        "body MUST be ecf_for_hash(type, data) per arch ruling §1"
    );

    // Invariant 2 — verify-by-rehash. Validate that
    // SHA-256(body) reproduces the URL hash. This is THE
    // content-addressed contract; a hostile CDN can't substitute.
    Hash::validate(&expected_type, &expected_data, &h)
        .expect("entity validates locally against H");
    let recomputed = entity_hash::Hash::compute(&expected_type, &expected_data);
    assert_eq!(
        recomputed, h,
        "recomputed hash of (type, data) MUST equal the URL hash"
    );

    handle.abort();
}

// ---------------------------------------------------------------------------
// ClosureScope — closure-of-signed-root (NETWORK §6.5.6 Amendment 10).
// Mirrors the validate-peer published_root v4/v5/v7 contract: a publisher
// advertising signed_pointer MUST serve the trie-node closure of the signed
// root (so CONTENT_GET(root_hash) and every interior node resolve), the
// published-root entity (MANIFEST_GET), and the signature pointer (tree-face).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn poll_closure_scope_serves_signed_root_closure() {
    use entity_peer::http_live::ClosureScope;
    use std::collections::BTreeMap;

    let server = PeerBuilder::new()
        .keypair(Keypair::from_seed([91u8; 32]))
        .build()
        .expect("peer builds");
    let peer_id = server.peer_id().to_string();
    let shared = server.shared();
    server.start_engines(&shared);

    // Bind a content entity into a namespace, then build the CHAMP trie over it
    // and publish a signed root committing to that trie.
    let entity = Entity::new("test/blob", b"closure payload".to_vec()).expect("entity");
    let leaf_hash = entity.content_hash;
    shared.content_store.put(entity).expect("put leaf");
    let key = format!("system/content/public/{}", hex_encode(&leaf_hash.to_bytes()));
    shared
        .location_index
        .set(&format!("/{}/{}", peer_id, key), leaf_hash);

    let mut bindings = BTreeMap::new();
    bindings.insert(key, leaf_hash);
    let root = entity_tree::trie::build_trie(shared.content_store.as_ref(), &bindings)
        .expect("build trie");
    let head = server.publish_root(root).expect("publish root");

    let sig_path = entity_hash::invariant_signature_path(&peer_id, &head);
    let sig_hash = shared
        .location_index
        .get(&sig_path)
        .expect("signature bound at invariant pointer");

    let listener = HttpLiveListener::bind_poll("127.0.0.1:0", "")
        .await
        .expect("poll listener binds")
        .with_scope(Arc::new(ClosureScope::new()));
    let url = format!("http://{}", listener.bound_addr());
    let shared_clone = shared.clone();
    let handle = tokio::spawn(async move {
        let _ = listener.serve(shared_clone).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let client = reqwest::Client::new();
    let content_get = |h: &Hash| {
        let u = format!("{}/content/{}", url, hex_encode(&h.to_bytes()));
        client.get(u).send()
    };

    // v7 — CONTENT_GET(root_hash): the trie root node MUST be served.
    let r = content_get(&root).await.expect("GET root");
    assert_eq!(r.status().as_u16(), 200, "trie root node must be in closure (v7)");
    // The leaf value, the published-root entity, and the signature are all in
    // the served closure.
    assert_eq!(content_get(&leaf_hash).await.unwrap().status().as_u16(), 200);
    assert_eq!(content_get(&head).await.unwrap().status().as_u16(), 200);
    assert_eq!(content_get(&sig_hash).await.unwrap().status().as_u16(), 200);

    // v4 — MANIFEST_GET serves the published-root entity.
    let manifest = client
        .get(format!("{}/manifest", url))
        .send()
        .await
        .expect("GET manifest");
    assert_eq!(manifest.status().as_u16(), 200, "manifest served (v4)");

    // v5 tree-face — the signature pointer resolves at the invariant path
    // `/{peer}/system/signature/{hex(head)}.bin` (no /tree/ prefix, Amendment 5).
    let sig_leaf = client
        .get(format!("{}{}.bin", url, sig_path))
        .send()
        .await
        .expect("GET signature pointer");
    assert_eq!(sig_leaf.status().as_u16(), 200, "signature pointer served (v5)");

    // A hash that is NOT in the closure → identical 404 (T4).
    let stray = Hash::compute("test/stray", b"not in closure");
    assert_eq!(content_get(&stray).await.unwrap().status().as_u16(), 404);

    handle.abort();
}

#[tokio::test]
async fn poll_content_get_out_of_namespace_returns_404() {
    // The peer has the bytes in its store but they're NOT bound into
    // the served namespace → 404 (NamespaceScope rejects).
    let (url, _peer_id, shared, handle) =
        spawn_poll_listener_with_namespace(61, "system/content/public").await;

    let entity = Entity::new("test/blob", b"private bytes".to_vec()).expect("entity");
    let h = entity.content_hash;
    shared.content_store.put(entity).expect("content put");
    // Deliberately NOT binding it into the namespace.

    let hex_h = hex_encode(&h.to_bytes());
    let target = format!("{}/content/{}", url, hex_h);

    let client = reqwest::Client::new();
    let resp = client.get(&target).send().await.expect("GET sends");
    assert_eq!(
        resp.status().as_u16(),
        404,
        "out-of-namespace hash MUST 404"
    );

    handle.abort();
}

#[tokio::test]
async fn poll_content_get_not_held_returns_same_404_as_out_of_scope() {
    // T4 mitigation: a hash the peer doesn't even hold should look
    // identical to one that's out-of-scope. We assert the status code;
    // the body MUST also be uniform (kept opaque server-side).
    let (url, _peer_id, _shared, handle) =
        spawn_poll_listener_with_namespace(62, "system/content/public").await;

    // 66-char wire hash (0x00 algo byte + 32-byte digest) for a hash
    // the peer doesn't hold. With the §5 B URL shape this PARSES
    // cleanly and reaches the scope + store lookup — both miss → 404.
    let mut bogus_wire = [0u8; 33];
    bogus_wire[0] = 0x00;
    for b in bogus_wire[1..].iter_mut() {
        *b = 0xAB;
    }
    let bogus_hex = hex_encode(&bogus_wire);
    let target = format!("{}/content/{}", url, bogus_hex);

    let client = reqwest::Client::new();
    let resp = client.get(&target).send().await.expect("GET sends");
    assert_eq!(resp.status().as_u16(), 404);

    handle.abort();
}

#[tokio::test]
async fn poll_content_get_malformed_hex_returns_400() {
    let (url, _peer_id, _shared, handle) =
        spawn_poll_listener_with_namespace(63, "system/content/public").await;

    let client = reqwest::Client::new();

    // Too short.
    let target1 = format!("{}/content/notahash", url);
    let resp1 = client.get(&target1).send().await.expect("GET sends");
    assert_eq!(resp1.status().as_u16(), 400);

    // Right length, non-hex chars.
    let target2 = format!("{}/content/{}", url, "z".repeat(66));
    let resp2 = client.get(&target2).send().await.expect("GET sends");
    assert_eq!(resp2.status().as_u16(), 400);

    // **§5 B regression guard.** 64-char digest-only form (no
    // algorithm byte) MUST be rejected — that's the pre-ruling shape
    // Go and Rust both had. Returning 400 keeps the regression loud.
    let digest_only = hex_encode(&[0xAB; 32]);
    assert_eq!(digest_only.len(), 64);
    let target3 = format!("{}/content/{}", url, digest_only);
    let resp3 = client.get(&target3).send().await.expect("GET sends");
    assert_eq!(
        resp3.status().as_u16(),
        400,
        "64-hex digest-only URL MUST 400 (cohort regression class)"
    );

    // **§5 B regression guard.** Unknown algorithm byte at the right
    // length — also 400, since the route can't verify-by-rehash with
    // an algorithm it doesn't recognize.
    let mut unknown_algo = [0u8; 33];
    unknown_algo[0] = 0xFE;
    let unknown_hex = hex_encode(&unknown_algo);
    let target4 = format!("{}/content/{}", url, unknown_hex);
    let resp4 = client.get(&target4).send().await.expect("GET sends");
    assert_eq!(
        resp4.status().as_u16(),
        400,
        "unknown algorithm byte MUST 400 (V7 §3.5 only registers SHA-256)"
    );

    handle.abort();
}

#[tokio::test]
async fn poll_content_post_returns_405_allow_get() {
    let (url, _peer_id, _shared, handle) =
        spawn_poll_listener_with_namespace(64, "system/content/public").await;

    // 66-char wire hash so the path passes the syntactic shape check
    // (the 405 short-circuits earlier on method anyway, but using a
    // well-formed path is the spec-faithful test surface).
    let mut bogus_wire = [0u8; 33];
    bogus_wire[0] = 0x00;
    for b in bogus_wire[1..].iter_mut() {
        *b = 0xAB;
    }
    let bogus_hex = hex_encode(&bogus_wire);
    let target = format!("{}/content/{}", url, bogus_hex);

    let client = reqwest::Client::new();
    let resp = client
        .post(&target)
        .body("not a get")
        .send()
        .await
        .expect("POST sends");
    assert_eq!(resp.status().as_u16(), 405);
    let allow = resp
        .headers()
        .get(reqwest::header::ALLOW)
        .and_then(|v| v.to_str().ok());
    assert_eq!(allow, Some("GET"));

    handle.abort();
}

#[tokio::test]
async fn poll_tree_get_in_namespace_returns_200_with_entity_ecf() {
    // **Arch ruling F-PY-12.** Tree-get over poll is
    // published-scope-gated, NOT "always 501." At the poll boundary
    // there's no protocol cap; the served scope IS the auth — same
    // model as content. The published set has a tree-face (which
    // paths resolve) and a content-face (which hashes resolve), same
    // serve_scope.
    //
    // For NamespaceScope, the tree-face is: any path under
    // `/{peer_id}/{namespace}/` is served. Bind an entity at such a
    // path and GET it via /tree/{path}.
    let (url, peer_id, shared, handle) =
        spawn_poll_listener_with_namespace(65, "system/content/public").await;

    // Publish a "named" entity inside the namespace at a known path
    // (alongside the auto-bound `/{hex(H)}` leaf that ingest writes).
    let entity = Entity::new("test/blob", b"tree-get content".to_vec()).expect("entity");
    let etype = entity.entity_type.clone();
    let edata = entity.data.clone();
    let h = entity.content_hash;
    shared.content_store.put(entity).expect("content put");
    let named_path = format!("/{}/system/content/public/named-doc", peer_id);
    shared.location_index.set(&named_path, h);

    // **Amendment 5 URL shape (§6.5.3.1).** `/{peer_id}/{path}.bin`.
    // No `/tree/` prefix; co-located demux uses the peer-id as the
    // first segment, and the `.bin` suffix selects entity-vs-listing.
    let target = format!(
        "{}/{}/system/content/public/named-doc.bin",
        url, peer_id
    );
    let client = reqwest::Client::new();
    let resp = client.get(&target).send().await.expect("GET sends");

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/cbor")
    );
    let etag = resp
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .expect("ETag header");
    assert_eq!(etag, format!("\"{}\"", hex_encode(&h.to_bytes())));

    // **Merged spec §6.5.3.1 — Cache-Control asymmetry.** Tree
    // bindings are mutable (operator can rebind a path at any time),
    // so a `Cache-Control: immutable` header on tree-get would be a
    // stale-serving bug. Content is hash-addressed and immutable by
    // construction; tree-get is path-addressed and is NOT.
    assert!(
        resp.headers().get(reqwest::header::CACHE_CONTROL).is_none(),
        "tree-get MUST NOT set Cache-Control (path bindings are mutable; \
         spec §6.5.3.1 — immutable on content only)"
    );

    // **Body shape — §6.5.3.1 Amendment 6.** TREE_GET
    // leaf is now a **`system/hash` 2-key bare pointer** —
    // `ECF({type:"system/hash", data:H})` — NOT the dereferenced
    // entity. Two-hop semantics: the consumer reads `H` from `data`
    // and follows up with `CONTENT_GET /content/{hex33(H)}` to get
    // the entity bytes. Preserves the V7 §1.7 content-store dedup
    // invariant (one copy per hash, no duplication across paths).
    let body = resp.bytes().await.expect("body reads").to_vec();
    let expected = entity_ecf::ecf_for_hash_value(
        "system/hash",
        &entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
    );
    assert_eq!(
        body, expected,
        "tree-get leaf body MUST be ECF({{type:system/hash, data:H}}) — \
         the 2-key bare pointer (§6.5.3.1 Amendment 6)"
    );

    // The pointer is NOT the dereferenced entity wire form — assert
    // explicitly so a regression that reverts to the one-hop reading
    // (which broke V7 §1.7 dedup) is caught immediately.
    let dereferenced = entity_wire::encode_entity(&Entity {
        entity_type: etype.clone(),
        data: edata.clone(),
        content_hash: h,
    });
    assert_ne!(
        body, dereferenced,
        "tree-get leaf MUST NOT inline the dereferenced entity (Amendment 6 — \
         that violates V7 §1.7 dedup; consumer does the second hop)"
    );

    handle.abort();
}

#[tokio::test]
async fn poll_content_get_has_immutable_but_tree_get_does_not() {
    // **Asymmetry the merged spec §6.5.3.1 pins.** Content is
    // hash-addressed → bytes are immutable by construction. Tree is
    // path-addressed → bindings are mutable (operator can rebind
    // any path). The Cache-Control posture MUST differ:
    //   - /content/{hex}: Cache-Control: immutable, max-age=...
    //   - /tree/{path}:   no Cache-Control (HTTP defaults apply)
    // Test the asymmetry on a single peer end-to-end so a future
    // regression that adds `immutable` to the tree path (or strips
    // it from content) lands loud.
    let (url, peer_id, shared, handle) =
        spawn_poll_listener_with_namespace(78, "system/content/public").await;
    let entity = Entity::new("test/blob", b"asymmetry probe".to_vec()).expect("entity");
    let h = publish_into_namespace(&shared, &peer_id, "system/content/public", entity);
    let hex_h = hex_encode(&h.to_bytes());

    let client = reqwest::Client::new();

    // Content route MUST set immutable.
    let content_url = format!("{}/content/{}", url, hex_h);
    let content_resp = client.get(&content_url).send().await.expect("GET sends");
    assert_eq!(content_resp.status().as_u16(), 200);
    let cc = content_resp
        .headers()
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .expect("content MUST have Cache-Control");
    assert!(
        cc.contains("immutable"),
        "/content MUST set Cache-Control: immutable (hash-addressed); got: {}",
        cc
    );

    // Bind a tree path so tree-get hits, then assert NO immutable.
    let tree_path = format!("/{}/system/content/public/asym", peer_id);
    shared.location_index.set(&tree_path, h);
    // Amendment 5: tree URL is `/{peer_id}/{path}.bin` (no `/tree/`).
    let tree_url = format!("{}{}.bin", url, tree_path);
    let tree_resp = client.get(&tree_url).send().await.expect("GET sends");
    assert_eq!(tree_resp.status().as_u16(), 200);
    assert!(
        tree_resp
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .is_none(),
        "/tree MUST NOT set Cache-Control: immutable (path bindings \
         are mutable; rebinding the path would serve stale)"
    );

    handle.abort();
}

#[tokio::test]
async fn poll_tree_get_out_of_namespace_returns_404() {
    // Path outside the served namespace's tree-face → 404. Same
    // identical body as not-held (T4 mitigation).
    let (url, peer_id, shared, handle) =
        spawn_poll_listener_with_namespace(75, "system/content/public").await;

    // Bind an entity at a path NOT under the public namespace.
    let entity = Entity::new("test/blob", b"private".to_vec()).expect("entity");
    let h = entity.content_hash;
    shared.content_store.put(entity).expect("content put");
    let private_path = format!("/{}/system/content/private/secret", peer_id);
    shared.location_index.set(&private_path, h);

    // Amendment 5: tree URL is `/{peer_id}/{path}.bin` (no `/tree/`).
    let target = format!(
        "{}/{}/system/content/private/secret.bin",
        url, peer_id
    );
    let client = reqwest::Client::new();
    let resp = client.get(&target).send().await.expect("GET sends");
    assert_eq!(
        resp.status().as_u16(),
        404,
        "out-of-namespace tree path MUST 404"
    );

    handle.abort();
}

#[tokio::test]
async fn poll_tree_get_unbound_path_in_namespace_returns_same_404() {
    // T4 mitigation: a path that's in-scope but unbound returns the
    // same 404 as an out-of-scope path — no presence oracle on the
    // tree-face either.
    let (url, peer_id, _shared, handle) =
        spawn_poll_listener_with_namespace(76, "system/content/public").await;

    // Amendment 5: tree URL is `/{peer_id}/{path}.bin` (no `/tree/`).
    let target = format!(
        "{}/{}/system/content/public/no-such-thing.bin",
        url, peer_id
    );
    let client = reqwest::Client::new();
    let resp = client.get(&target).send().await.expect("GET sends");
    assert_eq!(resp.status().as_u16(), 404);

    handle.abort();
}

#[tokio::test]
async fn poll_tree_get_no_scope_configured_returns_404() {
    // Same posture as content: a poll listener with no scope wired
    // 404s every GET, uniform with any other miss.
    let server = PeerBuilder::new()
        .keypair(Keypair::from_seed([77u8; 32]))
        .build()
        .expect("peer builds");
    let peer_id = server.peer_id().to_string();
    let shared = server.shared();
    server.start_engines(&shared);

    let listener = HttpLiveListener::bind_poll("127.0.0.1:0", "")
        .await
        .expect("poll listener binds");
    let url = format!("http://{}", listener.bound_addr());

    let shared_clone = shared.clone();
    let handle = tokio::spawn(async move {
        let _ = listener.serve(shared_clone).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    // Amendment 5: tree URL is `/{peer_id}/{path}.bin` (no `/tree/`).
    let target = format!("{}/{}/system/content/public/x.bin", url, peer_id);
    let client = reqwest::Client::new();
    let resp = client.get(&target).send().await.expect("GET sends");
    assert_eq!(resp.status().as_u16(), 404);

    handle.abort();
}

#[tokio::test]
async fn poll_manifest_get_unconfigured_returns_404() {
    // §6.5.3.1 Amendment 5: `/manifest` with no manifest configured
    // ⇒ 404 (was 501 pre-Amendment-5; the spec removed the
    // bring-up-deferral path). Any URL under `/manifest/...` ⇒ 404
    // (singular/terminal, no path tail).
    let (url, _peer_id, _shared, handle) =
        spawn_poll_listener_with_namespace(66, "system/content/public").await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/manifest", url))
        .send()
        .await
        .expect("GET sends");
    assert_eq!(
        resp.status().as_u16(),
        404,
        "unconfigured manifest MUST 404 (§6.5.3.1 Amendment 5)"
    );

    // `/manifest/` and `/manifest/anything` ⇒ 404 (terminal).
    let resp = client
        .get(format!("{}/manifest/some/path", url))
        .send()
        .await
        .expect("GET sends");
    assert_eq!(
        resp.status().as_u16(),
        404,
        "manifest is singular/terminal — no path tail (§6.5.3.1)"
    );

    handle.abort();
}

#[tokio::test]
async fn poll_unknown_route_returns_404() {
    let (url, _peer_id, _shared, handle) =
        spawn_poll_listener_with_namespace(67, "system/content/public").await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/not-a-real-route", url))
        .send()
        .await
        .expect("GET sends");
    assert_eq!(resp.status().as_u16(), 404);

    handle.abort();
}

#[tokio::test]
async fn poll_no_scope_configured_returns_404() {
    // bind_poll without with_scope — the route is enabled but the
    // scope predicate is absent. Per the listener's design this 404s
    // every GET, indistinguishable from any other scope miss.
    let server = PeerBuilder::new()
        .keypair(Keypair::from_seed([68u8; 32]))
        .build()
        .expect("peer builds");
    let shared = server.shared();
    server.start_engines(&shared);

    let listener = HttpLiveListener::bind_poll("127.0.0.1:0", "")
        .await
        .expect("poll listener binds");
    let url = format!("http://{}", listener.bound_addr());

    let shared_clone = shared.clone();
    let handle = tokio::spawn(async move {
        let _ = listener.serve(shared_clone).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    // Valid 66-char wire hash so we hit the scope check (which is
    // None → 404), not the syntactic 400 path.
    let mut wire = [0u8; 33];
    wire[0] = 0x00;
    for b in wire[1..].iter_mut() {
        *b = 0xAB;
    }
    let target = format!("{}/content/{}", url, hex_encode(&wire));
    let client = reqwest::Client::new();
    let resp = client.get(&target).send().await.expect("GET sends");
    assert_eq!(resp.status().as_u16(), 404);

    handle.abort();
}

#[tokio::test]
async fn posture_2_same_listener_routes_post_execute_and_get_content() {
    // Posture 2: one listener serves both POST /entity (live) and
    // GET /poll/content/{hex} (serving). G4 says operator picks
    // non-colliding paths; /entity + /poll/ is the conventional
    // default.
    let server = PeerBuilder::new()
        .keypair(Keypair::from_seed([69u8; 32]))
        .build()
        .expect("peer builds");
    let peer_id = server.peer_id().to_string();
    let shared = server.shared();
    server.start_engines(&shared);

    // Bind a Posture-2 listener: live POST + mounted poll routes.
    let listener = HttpLiveListener::bind("127.0.0.1:0", "/entity")
        .await
        .expect("listener binds")
        .with_poll_prefix("/poll")
        .with_scope(Arc::new(NamespaceScope::new("system/content/public")));
    let base = format!("http://{}", listener.bound_addr());

    assert_eq!(listener.url_path(), Some("/entity"));
    assert_eq!(listener.poll_prefix(), Some("/poll"));

    let shared_clone = shared.clone();
    let handle = tokio::spawn(async move {
        let _ = listener.serve(shared_clone).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    // Publish a public entity.
    let entity = Entity::new("test/blob", b"posture 2 content".to_vec()).expect("entity");
    let etype = entity.entity_type.clone();
    let edata = entity.data.clone();
    let h = publish_into_namespace(&shared, &peer_id, "system/content/public", entity);
    let hex_h = hex_encode(&h.to_bytes());

    let client = reqwest::Client::new();

    // GET /poll/content/{hex(H)} → 200 + entity ECF (re-hashes to URL hash).
    let get_url = format!("{}/poll/content/{}", base, hex_h);
    let r = client.get(&get_url).send().await.expect("GET sends");
    assert_eq!(r.status().as_u16(), 200);
    let body = r.bytes().await.unwrap().to_vec();
    let expected_ecf = entity_ecf::ecf_for_hash(&etype, &edata);
    assert_eq!(body, expected_ecf, "Posture 2 body must be entity ECF");
    assert_eq!(
        entity_hash::Hash::compute(&etype, &edata),
        h,
        "Posture 2 body must re-hash to URL hash"
    );

    // GET /entity → 405 Allow:POST (live route, wrong method).
    let bad = format!("{}/entity", base);
    let r2 = client.get(&bad).send().await.expect("GET sends");
    assert_eq!(r2.status().as_u16(), 405);
    assert_eq!(
        r2.headers()
            .get(reqwest::header::ALLOW)
            .and_then(|v| v.to_str().ok()),
        Some("POST")
    );

    // POST /poll/content/... → 405 Allow:GET.
    let r3 = client
        .post(&get_url)
        .body("nope")
        .send()
        .await
        .expect("POST sends");
    assert_eq!(r3.status().as_u16(), 405);
    assert_eq!(
        r3.headers()
            .get(reqwest::header::ALLOW)
            .and_then(|v| v.to_str().ok()),
        Some("GET")
    );

    handle.abort();
}

#[tokio::test]
async fn ingest_writes_namespace_binding_then_namespacescope_hits() {
    // **Arch ruling 1b5c125 §2.3 — CONTENT §6.4.2
    // Hash Tree Presence binding.** When `system/content:ingest` is
    // invoked against a namespace, the handler MUST write a
    // LocationIndex binding at `{namespace_uri}/{hex(H)}` so that
    // (a) `system/tree:get` finds the content, (b) the http-poll
    // NamespaceScope predicate accepts the hash. The cohort-wide
    // gap (all three impls shipped without this) is what was
    // blocking serving-mode E.4 from working without an explicit
    // tree:put workaround.
    //
    // End-to-end: drive `system/content:ingest` (via direct handler
    // dispatch) against namespace `system/content/public`, then
    // GET /content/{hex(H)} through the http-poll listener. With
    // §2.3 wired, no test-side `location_index.set(...)` is needed.
    use entity_capability::ResourceTarget;
    use entity_entity::Entity;
    use entity_handler::HandlerContext;

    let (url, peer_id, shared, handle) =
        spawn_poll_listener_with_namespace(80, "system/content/public").await;

    // Mint the entity we want to publish. We construct the data side
    // as a CBOR text Value so the ingest-handler's round-trip (decode
    // -> to_ecf -> Entity::new) reproduces the original bytes 1:1.
    let etype = "test/blob".to_string();
    let data_val = entity_ecf::text("sec-2-3 binding via ingest");
    let edata = entity_ecf::to_ecf(&data_val);
    let entity = Entity::new(&etype, edata.clone()).expect("entity");
    let h = entity.content_hash;
    let hex_h = hex_encode(&h.to_bytes());

    // Build the ingest params: `{ entity: <core/entity map> }`.
    let entity_map = entity_ecf::Value::Map(vec![
        (entity_ecf::text("type"), entity_ecf::text(&etype)),
        (entity_ecf::text("data"), data_val),
        (
            entity_ecf::text("content_hash"),
            entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
        ),
    ]);
    let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
        entity_ecf::text("entity"),
        entity_map,
    )]));
    let params_entity =
        Entity::new("system/content/ingest-params", params_data).expect("params entity");

    // Build a minimal EXECUTE entity for the context.
    let execute_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (
            entity_ecf::text("uri"),
            entity_ecf::text(format!("/{}/system/content/public", peer_id)),
        ),
        (entity_ecf::text("operation"), entity_ecf::text("ingest")),
    ]));
    let execute_entity =
        Entity::new("system/protocol/execute", execute_data).expect("execute entity");

    // Dispatch the ingest through the registry. The handler's
    // pattern resolves to `/{peer_id}/system/content`; suffix is
    // `/public` (the namespace below the pattern).
    let resource = ResourceTarget {
        targets: vec![format!("/{}/system/content/public", peer_id)],
        exclude: Vec::new(),
    };
    let pattern = format!("/{}/system/content", peer_id);
    let ctx = HandlerContext::builder(execute_entity, params_entity)
        .pattern(pattern.clone())
        .suffix("/public".to_string())
        .resource_target(resource)
        .operation("ingest".to_string())
        .build();

    let registry = shared.handler_registry.clone();
    let handler = registry
        .get(&pattern)
        .expect("content handler registered");
    let result = handler.handle(&ctx).await.expect("ingest dispatches");
    // Sanity: ingest returned status 200.
    assert_eq!(result.status, 200, "ingest must succeed");

    // The CONTENT-store Put happened inside ingest; the §6.4.2
    // binding should have been written too. Verify:
    let binding_path = format!("/{}/system/content/public/{}", peer_id, hex_h);
    assert_eq!(
        shared.location_index.get(&binding_path),
        Some(h),
        "ingest MUST write §6.4.2 Hash Tree Presence binding at {}",
        binding_path
    );

    // End-to-end: hit the http-poll route and confirm the
    // NamespaceScope predicate now sees it (no test-side
    // `location_index.set` workaround needed).
    let target = format!("{}/content/{}", url, hex_h);
    let client = reqwest::Client::new();
    let resp = client.get(&target).send().await.expect("GET sends");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "after §2.3 ingest, /content/{{hex(H)}} MUST resolve via NamespaceScope"
    );
    let body = resp.bytes().await.expect("body reads").to_vec();
    let expected = entity_ecf::ecf_for_hash(&etype, &edata);
    assert_eq!(body, expected, "body is the entity ECF (§1 invariant)");

    handle.abort();
}

#[tokio::test]
async fn posture_2_prefix_boundary_does_not_match_pollute_route() {
    // The prefix-strip MUST require either exact-match or `/` after
    // the prefix. `/poller/foo` should NOT match prefix `/poll` (would
    // accidentally treat it as nested under poll, breaking namespaces).
    let server = PeerBuilder::new()
        .keypair(Keypair::from_seed([70u8; 32]))
        .build()
        .expect("peer builds");
    let shared = server.shared();
    server.start_engines(&shared);

    let listener = HttpLiveListener::bind("127.0.0.1:0", "/entity")
        .await
        .expect("listener binds")
        .with_poll_prefix("/poll")
        .with_scope(Arc::new(NamespaceScope::new("system/content/public")));
    let base = format!("http://{}", listener.bound_addr());

    let shared_clone = shared.clone();
    let handle = tokio::spawn(async move {
        let _ = listener.serve(shared_clone).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    // /poller/foo — starts with `/poll` lexically but is its own
    // path; the listener MUST 404 it (not route into the poll mux).
    let client = reqwest::Client::new();
    let r = client
        .get(format!("{}/poller/foo", base))
        .send()
        .await
        .expect("GET sends");
    assert_eq!(r.status().as_u16(), 404);

    handle.abort();
}

// ============================================================================
// Amendment 5 — HTTP pathing regression matrix
// ============================================================================
//
// Cohort-validation checklist (HANDOFF §4): demux variations,
// strip-one bijection, manifest semantics, status table, scope-gated
// listings, empty-in-scope 200, %2F-reject, URL cap, CapTokenScope
// one-ACL-machinery.

#[tokio::test]
async fn amendment5_list_suffix_returns_listing_at_path() {
    // The `.list` suffix on a tree URL returns the listing of the
    // path's children as a `system/tree/listing` wire entity in ECF.
    let (url, peer_id, shared, handle) =
        spawn_poll_listener_with_namespace(110, "system/content/public").await;

    // Publish two siblings under a "dir" prefix.
    let e1 = Entity::new("test/blob", b"alpha".to_vec()).expect("entity");
    let e2 = Entity::new("test/blob", b"beta".to_vec()).expect("entity");
    let h1 = e1.content_hash;
    let h2 = e2.content_hash;
    shared.content_store.put(e1).expect("put");
    shared.content_store.put(e2).expect("put");
    shared
        .location_index
        .set(&format!("/{}/system/content/public/dir/a", peer_id), h1);
    shared
        .location_index
        .set(&format!("/{}/system/content/public/dir/b", peer_id), h2);

    // GET the listing of `dir` via the `.list` suffix.
    let target = format!(
        "{}/{}/system/content/public/dir.list",
        url, peer_id
    );
    let client = reqwest::Client::new();
    let resp = client.get(&target).send().await.expect("GET sends");
    assert_eq!(resp.status().as_u16(), 200, "in-scope listing → 200");
    assert_eq!(
        resp.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/cbor"),
    );
    assert!(
        resp.headers().get(reqwest::header::CACHE_CONTROL).is_none(),
        "listings are mutable views; MUST NOT be immutable-cached"
    );

    let body = resp.bytes().await.expect("body reads").to_vec();
    let decoded = entity_wire::decode_entity(&body).expect("listing decodes");
    assert_eq!(decoded.entity_type, "system/tree/listing");
    decoded.validate().expect("listing hash matches body");

    handle.abort();
}

#[tokio::test]
async fn amendment5_strip_one_bijection_foo_bin_bin_is_entity_at_foo_bin() {
    // A path component literally ending in `.bin` is addressed by
    // appending another `.bin`. Strip-one recovers `foo.bin` as the
    // bound path; the bijection is total.
    let (url, peer_id, shared, handle) =
        spawn_poll_listener_with_namespace(111, "system/content/public").await;

    // Bind an entity at the path `/{pid}/system/content/public/foo.bin`
    // (the path component literally ends in `.bin`).
    let e = Entity::new("test/blob", b"suffix-name probe".to_vec()).expect("entity");
    let h = e.content_hash;
    shared.content_store.put(e).expect("put");
    let bound = format!("/{}/system/content/public/foo.bin", peer_id);
    shared.location_index.set(&bound, h);

    // URL: append ONE more `.bin` → `foo.bin.bin`.
    let target = format!(
        "{}/{}/system/content/public/foo.bin.bin",
        url, peer_id
    );
    let client = reqwest::Client::new();
    let resp = client.get(&target).send().await.expect("GET sends");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "entity at `foo.bin` MUST be reachable at `foo.bin.bin` (strip-one bijection)"
    );

    // Confirm the listing of `foo.bin` is `foo.bin.list` (different URL).
    // No children, but `foo.bin` is in scope so the request should 200
    // with empty entries (in-scope-empty per §6.5.6).
    let listing_url = format!(
        "{}/{}/system/content/public/foo.bin.list",
        url, peer_id
    );
    let r = client.get(&listing_url).send().await.expect("GET sends");
    assert_eq!(
        r.status().as_u16(),
        200,
        "listing of `foo.bin` at `foo.bin.list` MUST be a distinct, reachable URL"
    );

    handle.abort();
}

#[tokio::test]
async fn amendment5_bare_no_suffix_returns_404() {
    // §6.5.3.1: bare path with no recognized suffix ⇒ 404. A leaf
    // MUST be addressed with `.bin`; a listing MUST be addressed with
    // `.list`. No URL form depends on a trailing slash.
    let (url, peer_id, shared, handle) =
        spawn_poll_listener_with_namespace(112, "system/content/public").await;

    let e = Entity::new("test/blob", b"x".to_vec()).expect("entity");
    let h = e.content_hash;
    shared.content_store.put(e).expect("put");
    let bound = format!("/{}/system/content/public/x", peer_id);
    shared.location_index.set(&bound, h);

    // URL without `.bin` or `.list` — even though the path exists.
    let bare_url = format!("{}/{}/system/content/public/x", url, peer_id);
    let client = reqwest::Client::new();
    let r = client.get(&bare_url).send().await.expect("GET sends");
    assert_eq!(
        r.status().as_u16(),
        404,
        "bare path (no recognized suffix) MUST 404 (§6.5.3.1)"
    );

    handle.abort();
}

#[tokio::test]
async fn amendment5_peer_id_bin_returns_404_root_is_directory() {
    // §6.5.3.1: `{peer_id}.bin` ⇒ 404 (the peer-id root is a
    // directory per V7 §1.4; an entity-at-root URL is invalid).
    let (url, peer_id, _shared, handle) =
        spawn_poll_listener_with_namespace(113, "system/content/public").await;

    let target = format!("{}/{}.bin", url, peer_id);
    let client = reqwest::Client::new();
    let r = client.get(&target).send().await.expect("GET sends");
    assert_eq!(
        r.status().as_u16(),
        404,
        "{{peer_id}}.bin MUST 404 (root is a directory; §6.5.3.1)"
    );

    handle.abort();
}

#[tokio::test]
async fn amendment5_peer_id_list_returns_peer_root_listing() {
    // §6.5.3: `{peer_id}.list` ⇒ the peer-root listing.
    let (url, peer_id, shared, handle) =
        spawn_poll_listener_with_namespace(114, "system/content/public").await;

    // Publish one entry so the listing has something to show.
    let e = Entity::new("test/blob", b"r".to_vec()).expect("entity");
    let h = e.content_hash;
    shared.content_store.put(e).expect("put");
    shared
        .location_index
        .set(&format!("/{}/system/content/public/r", peer_id), h);

    let target = format!("{}/{}.list", url, peer_id);
    let client = reqwest::Client::new();
    let r = client.get(&target).send().await.expect("GET sends");
    assert_eq!(r.status().as_u16(), 200, "{{peer_id}}.list ⇒ peer-root listing");
    let body = r.bytes().await.expect("body").to_vec();
    let decoded = entity_wire::decode_entity(&body).expect("decodes");
    assert_eq!(decoded.entity_type, "system/tree/listing");

    handle.abort();
}

#[tokio::test]
async fn amendment5_peers_bare_returns_404_and_peers_list_returns_all_peers_listing() {
    // §6.5.6 demux: bare `peers` ⇒ 404 (no recognized suffix).
    // `peers.list` ⇒ all-peers (universal-tree-root) listing.
    let (url, _peer_id, _shared, handle) =
        spawn_poll_listener_with_namespace(115, "system/content/public").await;

    let client = reqwest::Client::new();

    let r = client.get(format!("{}/peers", url)).send().await.expect("GET");
    assert_eq!(r.status().as_u16(), 404, "bare `peers` MUST 404");

    let r = client
        .get(format!("{}/peers.list", url))
        .send()
        .await
        .expect("GET");
    assert_eq!(
        r.status().as_u16(),
        200,
        "`peers.list` MUST return the all-peers listing"
    );

    handle.abort();
}

#[tokio::test]
async fn amendment5_empty_in_scope_listing_returns_200_with_empty_entries() {
    // §6.5.6: an in-scope prefix with no children MUST return 200 +
    // entries={} + count=0 (in-scope-ness is the access boundary;
    // empty published directory is legitimately observable).
    let (url, peer_id, _shared, handle) =
        spawn_poll_listener_with_namespace(116, "system/content/public").await;

    // The namespace is in scope; no children bound under it. Listing
    // returns 200 + empty.
    let target = format!("{}/{}/system/content/public.list", url, peer_id);
    let client = reqwest::Client::new();
    let r = client.get(&target).send().await.expect("GET");
    assert_eq!(
        r.status().as_u16(),
        200,
        "in-scope empty prefix → 200 (§6.5.6)"
    );
    let body = r.bytes().await.expect("body").to_vec();
    let decoded = entity_wire::decode_entity(&body).expect("decodes");
    // Confirm `count` is 0 by parsing the listing data.
    let val: ciborium::Value =
        ciborium::from_reader(decoded.data.as_slice()).expect("data is CBOR");
    let map = val.as_map().expect("listing data is a map");
    let count = map
        .iter()
        .find_map(|(k, v)| {
            if k.as_text() == Some("count") {
                v.as_integer().map(|i| {
                    let n: i128 = i.into();
                    n
                })
            } else {
                None
            }
        })
        .expect("count present");
    assert_eq!(count, 0, "empty in-scope listing has count=0");

    handle.abort();
}

#[tokio::test]
async fn amendment5_listing_filters_out_of_scope_children_and_count_is_filtered_total() {
    // §6.5.6 scope-gating: listing enumerates only children within
    // serve_scope; `count` MUST be the filtered total (never the raw
    // subtree total — leaks hidden-path existence, TREE §1176).
    let (url, peer_id, shared, handle) =
        spawn_poll_listener_with_namespace(117, "system/content/public").await;

    // Two siblings under in-scope namespace, plus one out-of-scope
    // (different namespace).
    let e1 = Entity::new("test/blob", b"a".to_vec()).expect("entity");
    let e2 = Entity::new("test/blob", b"b".to_vec()).expect("entity");
    let e3 = Entity::new("test/blob", b"hidden".to_vec()).expect("entity");
    let h1 = e1.content_hash;
    let h2 = e2.content_hash;
    let h3 = e3.content_hash;
    shared.content_store.put(e1).expect("put");
    shared.content_store.put(e2).expect("put");
    shared.content_store.put(e3).expect("put");
    shared
        .location_index
        .set(&format!("/{}/system/content/public/a", peer_id), h1);
    shared
        .location_index
        .set(&format!("/{}/system/content/public/b", peer_id), h2);
    // Hidden binding in a DIFFERENT (out-of-scope) namespace — must
    // not appear in the in-scope listing.
    shared
        .location_index
        .set(&format!("/{}/system/content/private/h", peer_id), h3);

    let target = format!("{}/{}/system/content/public.list", url, peer_id);
    let client = reqwest::Client::new();
    let r = client.get(&target).send().await.expect("GET");
    assert_eq!(r.status().as_u16(), 200);
    let body = r.bytes().await.expect("body").to_vec();
    let decoded = entity_wire::decode_entity(&body).expect("decodes");
    let val: ciborium::Value =
        ciborium::from_reader(decoded.data.as_slice()).expect("CBOR");
    let map = val.as_map().expect("map");
    let count: i128 = map
        .iter()
        .find_map(|(k, v)| {
            (k.as_text() == Some("count")).then(|| v.as_integer().map(|i| i.into()))?
        })
        .expect("count present");
    assert_eq!(count, 2, "count is filtered total (a + b); hidden NOT counted");

    let entries = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("entries"))
        .and_then(|(_, v)| v.as_map())
        .expect("entries map");
    let names: Vec<&str> = entries
        .iter()
        .filter_map(|(k, _)| k.as_text())
        .collect();
    assert!(names.iter().any(|n| *n == "a"), "a present");
    assert!(names.iter().any(|n| *n == "b"), "b present");
    assert!(
        !names.iter().any(|n| *n == "h"),
        "hidden child MUST be filtered out (presence-oracle mitigation, §6.5.6)"
    );

    handle.abort();
}

#[tokio::test]
async fn amendment5_percent_encoded_slash_in_path_returns_400() {
    // §6.5.3.1 status table: `%2F` inside a path component is
    // explicitly malformed (path components are `/`-delimited; reject
    // rather than recover as literal).
    let (url, peer_id, _shared, handle) =
        spawn_poll_listener_with_namespace(118, "system/content/public").await;

    // Note reqwest will not re-encode `%2F` for us — pass it raw.
    let target = format!("{}/{}/system/content/public/a%2Fb.bin", url, peer_id);
    let client = reqwest::Client::new();
    let r = client.get(&target).send().await.expect("GET");
    assert_eq!(
        r.status().as_u16(),
        400,
        "%2F inside a path component MUST 400 (§6.5.3.1)"
    );

    handle.abort();
}

#[tokio::test]
async fn amendment5_url_exceeds_cap_returns_414() {
    // §6.5.3.1 status table: above the operator-configured URL byte
    // cap ⇒ 414 (parser-DoS guard).
    let server = PeerBuilder::new()
        .keypair(Keypair::from_seed([119u8; 32]))
        .build()
        .expect("peer builds");
    let shared = server.shared();
    server.start_engines(&shared);

    let listener = HttpLiveListener::bind_poll("127.0.0.1:0", "")
        .await
        .expect("listener binds")
        .with_max_url_bytes(64); // tiny cap for the test
    let url = format!("http://{}", listener.bound_addr());

    let shared_clone = shared.clone();
    let handle = tokio::spawn(async move {
        let _ = listener.serve(shared_clone).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    // Build a URL longer than the cap.
    let long_path = "/".to_string() + &"a".repeat(200);
    let r = reqwest::Client::new()
        .get(format!("{}{}", url, long_path))
        .send()
        .await
        .expect("GET");
    assert_eq!(
        r.status().as_u16(),
        414,
        "URL above the configured cap MUST 414"
    );

    handle.abort();
}

#[tokio::test]
async fn amendment5_manifest_get_with_configured_hash_returns_wire_entity() {
    // §6.5.3.1 MANIFEST_GET: configured manifest hash → 200, wire
    // entity in ECF, application/cbor, ETag, NOT immutable.
    let server = PeerBuilder::new()
        .keypair(Keypair::from_seed([120u8; 32]))
        .build()
        .expect("peer builds");
    let shared = server.shared();
    server.start_engines(&shared);

    // Put a "manifest" entity into the store and configure the
    // listener with its hash.
    let manifest = Entity::new(
        "system/peer/published-root",
        b"fake-published-root-data".to_vec(),
    )
    .expect("entity");
    let h = manifest.content_hash;
    shared.content_store.put(manifest).expect("put");

    let listener = HttpLiveListener::bind_poll("127.0.0.1:0", "")
        .await
        .expect("listener binds")
        .with_manifest_hash(h);
    let url = format!("http://{}", listener.bound_addr());

    let shared_clone = shared.clone();
    let handle = tokio::spawn(async move {
        let _ = listener.serve(shared_clone).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let client = reqwest::Client::new();
    let r = client
        .get(format!("{}/manifest", url))
        .send()
        .await
        .expect("GET");
    assert_eq!(r.status().as_u16(), 200);
    assert_eq!(
        r.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/cbor"),
    );
    let cc = r
        .headers()
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    assert!(
        cc.as_deref().is_some_and(|s| !s.contains("immutable")),
        "manifest MUST NOT be immutable-cached (mutable per §6.5.3.1); got {:?}",
        cc
    );
    let etag = r
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .expect("ETag");
    assert_eq!(etag, format!("\"{}\"", hex_encode(&h.to_bytes())));

    handle.abort();
}

#[tokio::test]
async fn amendment6_tree_leaf_is_two_hop_hash_pointer() {
    // **Cohort regression — Amendment 6 (arch 0993d34 + 0f60891).**
    // Mirrors validate-peer's three new tree_entity_* checks:
    //   - body_is_hash_pointer           — 2-key map, type=system/hash, data is 33 bytes
    //   - pointer_data_matches_bound_hash — data bytes == H bytes
    //   - second_hop_dereferences         — GET /content/{hex33(H)} returns
    //                                       bytes pure-body-rehashing to H
    // This is the single load-bearing regression catching any future
    // reversion to the Amendment-5 one-hop reading.
    let (url, peer_id, shared, handle) =
        spawn_poll_listener_with_namespace(150, "system/content/public").await;

    let entity = Entity::new("test/blob", b"two-hop content".to_vec()).expect("entity");
    let etype = entity.entity_type.clone();
    let edata = entity.data.clone();
    let h = entity.content_hash;
    shared.content_store.put(entity).expect("put");
    // Also bind the content under the content namespace so CONTENT_GET
    // (the second hop) resolves under NamespaceScope.
    publish_into_namespace(
        &shared,
        &peer_id,
        "system/content/public",
        Entity::new(&etype, edata.clone()).expect("entity-dup"),
    );
    // Bind the same content at a *path*-addressed location too.
    let leaf_path = format!("/{}/system/content/public/two-hop", peer_id);
    shared.location_index.set(&leaf_path, h);

    // ---- HOP 1: GET /{peer_id}/system/content/public/two-hop.bin
    let leaf_url = format!(
        "{}/{}/system/content/public/two-hop.bin",
        url, peer_id
    );
    let client = reqwest::Client::new();
    let r1 = client.get(&leaf_url).send().await.expect("hop 1 GET");
    assert_eq!(r1.status().as_u16(), 200);
    assert_eq!(
        r1.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/cbor")
    );
    // ETag = bound hash (mutable cache key per Amendment 6 polish).
    let etag = r1
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .expect("ETag");
    assert_eq!(etag, format!("\"{}\"", hex_encode(&h.to_bytes())));

    let body = r1.bytes().await.expect("body").to_vec();

    // ---- ASSERTION 1: body_is_hash_pointer
    //
    // 2-key bare map: major type 5 (map), count 2 ⇒ first byte 0xA2.
    // Then ECF key order ("data" before "type"). The `data` value is
    // a CBOR bstr of 33 bytes.
    assert_eq!(
        body[0], 0xA2,
        "leaf body MUST be a 2-key CBOR map (got first byte 0x{:02x}; \
         a 3-key map would be 0xA3 — the old wire-entity reading)",
        body[0]
    );
    // Decode the map: extract `type` and `data` fields.
    let val: ciborium::Value =
        ciborium::from_reader(body.as_slice()).expect("body is CBOR");
    let map = val.as_map().expect("body is a CBOR map");
    let mut got_type: Option<&str> = None;
    let mut got_data: Option<&[u8]> = None;
    for (k, v) in map {
        match k.as_text() {
            Some("type") => got_type = v.as_text(),
            Some("data") => got_data = v.as_bytes().map(|b| b.as_slice()),
            _ => {}
        }
    }
    assert_eq!(
        got_type,
        Some("system/hash"),
        "pointer type MUST be `system/hash` (Amendment 6)"
    );
    let data_bytes = got_data.expect("pointer data MUST be a CBOR bstr");
    assert_eq!(
        data_bytes.len(),
        33,
        "pointer data MUST be 33 bytes (1 algorithm byte + 32 digest); got {}",
        data_bytes.len()
    );

    // ---- ASSERTION 2: pointer_data_matches_bound_hash
    assert_eq!(
        data_bytes,
        h.to_bytes(),
        "pointer data bytes MUST equal the bound hash H"
    );

    // ---- ASSERTION 3: second_hop_dereferences
    //
    // Read H from the pointer, do a CONTENT_GET, verify pure-body-rehash.
    let hex_h = hex_encode(data_bytes);
    let content_url = format!("{}/content/{}", url, hex_h);
    let r2 = client.get(&content_url).send().await.expect("hop 2 GET");
    assert_eq!(
        r2.status().as_u16(),
        200,
        "second hop CONTENT_GET /content/{{hex33(H)}} MUST resolve"
    );
    let content_body = r2.bytes().await.expect("content body").to_vec();
    // CONTENT_GET is bare 2-key hashable form; pure-body-rehash MUST
    // recover H (Mechanism A, §6.5.3.1).
    assert_eq!(
        content_body,
        entity_ecf::ecf_for_hash(&etype, &edata),
        "CONTENT_GET body MUST be the bare 2-key hashable form"
    );
    let rehashed = entity_hash::Hash::compute(&etype, &edata);
    assert_eq!(
        rehashed, h,
        "SHA-256({{type,data}}) MUST recover H (pure-body-rehash, §6.5.3.1)"
    );

    handle.abort();
}

#[tokio::test]
async fn amendment6_tree_leaf_pointer_does_not_inline_entity_bytes() {
    // V7 §1.7 dedup invariant guard: two paths bound to the same hash
    // MUST return identical small pointers, NOT two copies of the
    // entity bytes. This is the proof-of-correctness for the
    // dedup-preserving two-hop reading.
    let (url, peer_id, shared, handle) =
        spawn_poll_listener_with_namespace(151, "system/content/public").await;

    let entity =
        Entity::new("test/blob", b"shared by two paths".to_vec()).expect("entity");
    let h = entity.content_hash;
    shared.content_store.put(entity).expect("put");

    let p1 = format!("/{}/system/content/public/alpha", peer_id);
    let p2 = format!("/{}/system/content/public/beta", peer_id);
    shared.location_index.set(&p1, h);
    shared.location_index.set(&p2, h);

    let client = reqwest::Client::new();
    let r1 = client
        .get(format!("{}{}.bin", url, p1))
        .send()
        .await
        .expect("alpha");
    let r2 = client
        .get(format!("{}{}.bin", url, p2))
        .send()
        .await
        .expect("beta");

    let b1 = r1.bytes().await.expect("b1").to_vec();
    let b2 = r2.bytes().await.expect("b2").to_vec();

    // Both URLs MUST return byte-identical pointers (dedup preserved).
    assert_eq!(b1, b2, "two paths to the same H MUST return identical pointers");
    // And the pointer body MUST be tiny — order of bytes (CBOR map +
    // type string + 33-byte bstr), not the entity payload size. The
    // entity itself is small here, so an upper bound is the only
    // assertion that's stable; check it's well under the entity's
    // wire form size, which is what would land if we one-hopped.
    let dereferenced = entity_wire::encode_entity(&Entity {
        entity_type: "test/blob".to_string(),
        data: b"shared by two paths".to_vec(),
        content_hash: h,
    });
    assert!(
        b1.len() < dereferenced.len(),
        "pointer body ({} bytes) MUST be smaller than the dereferenced \
         entity wire form ({} bytes) — Amendment 6 dedup",
        b1.len(),
        dereferenced.len()
    );

    handle.abort();
}

#[tokio::test]
async fn amendment5_multi_peer_publish_via_tree_put_surfaces_in_peers_list() {
    // **Cohort regression** — matches the validate-peer
    // `multi_peer_publish_via_tree_put` probe (Go arch commit
    // 0793732). Setup: the local peer accepts a binding at a
    // foreign-peer-id absolute path. The all-peers (universal-tree-
    // root) listing MUST surface the foreign peer-id, because the
    // universal tree is open and `serve_scope` interprets a
    // configured namespace as peer-wildcard (per the
    // universal-tree cross-peer audit).
    //
    // We drive it at the LocationIndex level here because the test
    // harness doesn't ship a full wire-EXECUTE setup; the wire path
    // through tree:put is exercised by `validate-peer` cross-impl.
    // What this test guards is the universal-tree-root walk + scope
    // filter — the layer that was buggy before the audit.
    let (url, local_pid, shared, handle) =
        spawn_poll_listener_with_namespace(140, "system/content/public").await;

    // Construct a foreign peer-id (independent keypair, not the
    // local one).
    let foreign_kp = Keypair::from_seed([141u8; 32]);
    let foreign_pid = foreign_kp.peer_id().to_string();
    assert_ne!(
        foreign_pid, local_pid,
        "foreign peer-id must differ from local — sanity check"
    );

    // Publish an in-scope binding under the FOREIGN peer-id. This is
    // exactly what a cross-peer `tree:put` would land in the store.
    let e = Entity::new("test/blob", b"cross-peer publish".to_vec())
        .expect("entity");
    let h = e.content_hash;
    shared.content_store.put(e).expect("put");
    let foreign_path = format!(
        "/{}/system/content/public/cross-peer-blob",
        foreign_pid
    );
    shared.location_index.set(&foreign_path, h);

    // GET /peers.list — MUST surface the foreign peer-id.
    let client = reqwest::Client::new();
    let r = client
        .get(format!("{}/peers.list", url))
        .send()
        .await
        .expect("GET");
    assert_eq!(r.status().as_u16(), 200);
    let body = r.bytes().await.expect("body").to_vec();
    let decoded = entity_wire::decode_entity(&body).expect("decodes");
    let val: ciborium::Value =
        ciborium::from_reader(decoded.data.as_slice()).expect("CBOR");
    let map = val.as_map().expect("map");
    let entries = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("entries"))
        .and_then(|(_, v)| v.as_map())
        .expect("entries map");
    let names: Vec<&str> = entries
        .iter()
        .filter_map(|(k, _)| k.as_text())
        .collect();
    assert!(
        names.iter().any(|n| *n == foreign_pid.as_str()),
        "peers.list MUST surface the foreign peer-id when it has in-scope \
         bindings; got entries = {:?}",
        names
    );

    // And the foreign peer-root listing itself MUST also resolve
    // (so a consumer can drill down). Walk the chain.
    let r = client
        .get(format!("{}/{}.list", url, foreign_pid))
        .send()
        .await
        .expect("GET");
    assert_eq!(
        r.status().as_u16(),
        200,
        "/{{foreign_pid}}.list MUST 200 — the foreign peer's root \
         listing is reachable from the universal-tree walk"
    );

    handle.abort();
}

#[tokio::test]
async fn amendment5_cap_token_scope_is_drift_free_vs_check_permission() {
    // §6.5.6 Amendment 5: `serve_scope` as cap-token. Verify the
    // CapTokenScope routes both faces through the same evaluator the
    // live-EXECUTE surface uses — by construction, drift impossible.
    use entity_capability::{
        CapabilityToken, GrantEntry, Granter, IdScope, PathScope,
    };
    use entity_peer::http_live::CapTokenScope;

    let server = PeerBuilder::new()
        .keypair(Keypair::from_seed([121u8; 32]))
        .build()
        .expect("peer builds");
    let peer_id = server.peer_id().to_string();
    let shared = server.shared();
    server.start_engines(&shared);

    // Build a published-set cap: `system/tree:get` on
    // `/{pid}/system/content/public/*`.
    let allowed_path = format!("/{}/system/content/public/*", peer_id);
    let grant = GrantEntry {
        handlers: PathScope::new(vec!["system/tree".to_string()]),
        operations: IdScope::new(vec!["get".to_string()]),
        resources: PathScope::new(vec![allowed_path.clone()]),
        peers: None,
        constraints: None,
        allowances: None,
    };
    let cap = CapabilityToken {
        grants: vec![grant],
        granter: Granter::Single(Hash::compute("test/granter", b"x")),
        grantee: Hash::compute("test/grantee", b"y"),
        parent: None,
        created_at: 0,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };

    let scope = CapTokenScope::new(cap);

    // Tree-face: in-scope path under the include → true.
    let in_path = format!("/{}/system/content/public/foo", peer_id);
    let out_path = format!("/{}/system/content/private/foo", peer_id);
    let result_in = scope
        .in_scope_path(&in_path, &shared)
        .await
        .expect("in_scope_path");
    let result_out = scope
        .in_scope_path(&out_path, &shared)
        .await
        .expect("in_scope_path");
    assert!(result_in, "in-namespace path MUST be in scope");
    assert!(!result_out, "out-of-namespace path MUST be out of scope");

    // Content-face: bind a hash under the in-scope namespace ⇒ in
    // scope; bind another out-of-scope ⇒ not in scope.
    let e_in = Entity::new("test/blob", b"in".to_vec()).expect("entity");
    let e_out = Entity::new("test/blob", b"out".to_vec()).expect("entity");
    let h_in = e_in.content_hash;
    let h_out = e_out.content_hash;
    shared.content_store.put(e_in).expect("put");
    shared.content_store.put(e_out).expect("put");

    let hex_in = hex_encode(&h_in.to_bytes());
    let hex_out = hex_encode(&h_out.to_bytes());
    shared.location_index.set(
        &format!("/{}/system/content/public/{}", peer_id, hex_in),
        h_in,
    );
    shared.location_index.set(
        &format!("/{}/system/content/private/{}", peer_id, hex_out),
        h_out,
    );

    let c_in = scope.in_scope(&h_in, &shared).await.expect("in_scope");
    let c_out = scope.in_scope(&h_out, &shared).await.expect("in_scope");
    assert!(c_in, "hash bound in cap-included namespace MUST be in scope");
    assert!(
        !c_out,
        "hash bound only in out-of-cap namespace MUST be out of scope"
    );
}

// ============================================================
// R1 — HTTP outbound (HttpConnection + RemoteEndpoint + multi-profile
// resolver). PROPOSAL-TRANSPORT-FAMILY-LIVE-REACHABILITY §7.3.
// ============================================================
//
// These tests pin the bidirectional + no-TCP-fallback shapes Go landed
// at commit 24de569 (TestHTTPLive_P2P_Bidirectional +
// TestHTTPLive_P2P_OnlyHTTPProfile_NoTCPFallback). The
// cross-peer-subscription-over-HTTP gate (the test that actually pins
// R1 vs the single-peer-local pass) is filed separately; these confirm
// the lower-level surfaces are sound.

use entity_peer::http_connection::HttpConnection;
use entity_peer::remote::{
    resolve_transport_address, send_execute, RemoteEndpoint, PROFILE_ID_PRIMARY_HTTP,
};
use entity_peer::transport_profile::HttpProfileData;

/// R1 — HttpConnection.connect runs HELLO/AUTHENTICATE over POST
/// round-trips against a live HttpLiveListener and captures a
/// post-handshake state with the remote's peer_id, identity hash, and
/// granted capability. Gate test for the outbound-HTTP path.
#[tokio::test]
async fn http_outbound_connect_completes_handshake() {
    let (url, handle) = spawn_listener(50).await;

    let client_kp = Keypair::from_seed([51u8; 32]);
    let http = HttpConnection::connect(&url, &IdentityKeypair::Ed25519(client_kp.clone_inner()), entity_hash::HASH_ALGORITHM_SHA256)
        .await
        .expect("HTTP outbound handshake should complete");

    // Remote peer_id is whatever the seed=50 peer derived.
    let expected_remote_pid = Keypair::from_seed([50u8; 32]).peer_id().to_string();
    assert_eq!(http.remote_peer_id(), &expected_remote_pid);
    assert_ne!(http.remote_identity_hash(), Hash::zero());
    // The granted cap is non-empty (default_connection_grants pinned by
    // the connect-handler) — the entity has data bytes.
    assert!(!http.capability().data.is_empty());

    handle.abort();
}

/// R1 — send_execute over a `&dyn RemoteEndpoint` backed by
/// HttpConnection performs an authenticated EXECUTE round-trip
/// (POST in / POST out) and decodes the response. Smoke-tests the
/// full envelope build → POST → response-parse pipeline through the
/// trait, not just the raw transport.
#[tokio::test]
async fn http_outbound_execute_via_send_execute_round_trip() {
    let (url, handle) = spawn_listener(52).await;

    let client_kp = Keypair::from_seed([53u8; 32]);
    let http = HttpConnection::connect(&url, &IdentityKeypair::Ed25519(client_kp.clone_inner()), entity_hash::HASH_ALGORITHM_SHA256)
        .await
        .expect("connect");

    // Build a tree:get params entity for the remote peer's `system/handler`
    // prefix (a path that always resolves on a freshly-built peer because
    // bootstrap handlers register under it). The exact response doesn't
    // matter for this gate — what matters is "EXECUTE went out, response
    // came back, status is a valid V7 §8.3 code" (200 or a structured
    // 4xx). Anything else means the outbound HTTP transport broke
    // somewhere we'd want to know about.
    let remote_pid = Keypair::from_seed([52u8; 32]).peer_id().to_string();
    let params_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
        entity_ecf::text("path"),
        entity_ecf::text(&format!("/{}/system/handler", remote_pid)),
    )]));
    let params = Entity::new("system/tree/get-params", params_data).unwrap();

    let resource = entity_capability::ResourceTarget {
        targets: vec![format!("/{}/system/handler", remote_pid)],
        exclude: vec![],
    };
    let no_chain = std::collections::HashMap::new();

    let resp = send_execute(
        &http as &dyn RemoteEndpoint,
        &IdentityKeypair::Ed25519(client_kp.clone_inner()),
        &format!("/{}/system/tree", remote_pid),
        "get",
        &params,
        Some(&resource),
        None,
        None,
        &no_chain,
    )
    .await
    .expect("send_execute over HttpConnection should succeed");

    // The handler may return 200 (found) or 404 (path empty under bootstrap),
    // but it MUST NOT be 0 (default) or a 5xx — those would indicate the
    // outbound path itself failed.
    assert!(
        resp.status >= 200 && resp.status < 500,
        "execute returned implausible status {} — outbound HTTP path broken",
        resp.status
    );

    handle.abort();
}

/// R1 — bidirectional. Two peers each running HttpLiveListener. A→B and
/// B→A both succeed. Pre-R1 this would fail because A's outbound
/// would have no HTTP dispatcher. Class-G deadlock cannot recur on
/// HTTP (separate POST goroutines, no shared in-flight state).
#[tokio::test]
async fn http_outbound_p2p_bidirectional() {
    let (url_a, handle_a) = spawn_listener(60).await;
    let (url_b, handle_b) = spawn_listener(61).await;

    let kp_a = Keypair::from_seed([60u8; 32]);
    let kp_b = Keypair::from_seed([61u8; 32]);
    let pid_a = kp_a.peer_id().to_string();
    let pid_b = kp_b.peer_id().to_string();

    // A dials B (A as client, B's listener).
    let a_to_b = HttpConnection::connect(&url_b, &IdentityKeypair::Ed25519(kp_a.clone_inner()), entity_hash::HASH_ALGORITHM_SHA256)
        .await
        .expect("A→B HTTP connect");
    assert_eq!(a_to_b.remote_peer_id(), &pid_b);

    // B dials A (B as client, A's listener). Mirror-direction.
    let b_to_a = HttpConnection::connect(&url_a, &IdentityKeypair::Ed25519(kp_b.clone_inner()), entity_hash::HASH_ALGORITHM_SHA256)
        .await
        .expect("B→A HTTP connect");
    assert_eq!(b_to_a.remote_peer_id(), &pid_a);

    // Both directions had successful handshakes. Class-G structural
    // proof: HttpConnection holds no shared in-flight state between
    // calls (each `dispatch_envelope` is its own `reqwest` POST
    // Future), so the bidirectional-symmetric-load deadlock that
    // motivated RemoteConnection's multiplexed reader cannot recur.

    handle_a.abort();
    handle_b.abort();
}

/// R1 — multi-profile resolver picks the HTTP profile when only HTTP
/// is published (Go's TestHTTPLive_P2P_OnlyHTTPProfile_NoTCPFallback
/// shape). Regression guard: pre-R1, `resolve_transport_address`
/// already decoded HTTP profile entities, but the dispatcher had no
/// HTTP outbound — so an HTTP-only peer was unreachable. Now the
/// resolved `http://...` URL routes through `HttpConnection` in
/// `get_or_connect` (covered by the bidirectional test above);
/// here we pin the resolver-side selection itself.
#[tokio::test]
async fn http_outbound_resolver_selects_http_profile_when_no_tcp() {
    let kp_a = Keypair::from_seed([70u8; 32]);
    let kp_b = Keypair::from_seed([71u8; 32]);
    let pid_a = kp_a.peer_id().to_string();
    let pid_b = kp_b.peer_id().to_string();

    let server_a = PeerBuilder::new()
        .keypair(kp_a)
        .build()
        .expect("peer A builds");
    let shared_a = server_a.shared();

    // Publish ONLY an HTTP profile for B under A's tree, at the
    // `primary-http` profile-id slot (G1 — distinct id avoids the
    // primary-vs-primary collision that would silently overwrite a
    // TCP profile at the same path).
    let http_profile = HttpProfileData::for_local_listener(
        &pid_b,
        "http://127.0.0.1:9999/entity",
        1_000,
    )
    .to_entity();
    let h = http_profile.content_hash;
    shared_a.content_store.put(http_profile).expect("put profile");
    // v7.64 §1.4: path-segment is `{peer_id_hex}` (hex of remote's
    // `system/peer` content_hash), not Base58.
    let pid_b_hex = entity_crypto::PeerId::from(pid_b.as_str())
        .identity_hex_local()
        .expect("identity-form PID for test peer");
    let profile_path = format!(
        "/{}/system/peer/transport/{}/{}",
        pid_a, pid_b_hex, PROFILE_ID_PRIMARY_HTTP
    );
    shared_a.location_index.set(&profile_path, h);

    // Resolve: with no TCP profile at all, the resolver MUST pick the
    // HTTP profile and return its endpoint.url.
    let resolved = resolve_transport_address(
        &pid_b,
        shared_a.content_store.as_ref(),
        shared_a.location_index.as_ref(),
        &pid_a,
    )
    .expect("resolver should select HTTP-only profile, not error");
    assert_eq!(resolved, "http://127.0.0.1:9999/entity");
    // The returned URL starts with http:// so `get_or_connect`'s
    // R1 branch will route it to HttpConnection rather than the
    // stream-transport Connector. (The actual dial would fail since
    // there's no listener at :9999 — that's not what this test gates;
    // it gates the selection.)
}
