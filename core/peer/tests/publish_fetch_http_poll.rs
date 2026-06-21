//! Tier-1 `publish_fetch_http_poll` — the v1 relay/network gate.
//!
//! Rust mirror of Go's `cmd/internal/validate/publish_fetch_http_poll.go`
//! (per the publish/fetch http-poll cohort handoff). Proves the
//! **end-to-end publish→fetch flow** over the real http-poll wire: a
//! publisher mints a signed root over a small blog tree, exposes its tree
//! as a static HTTP origin (`HttpLiveListener` bind_poll — wire-equivalent
//! to nginx / R2 / S3 serving the same routes), and a consumer drives:
//!
//!   MANIFEST_GET → signature verify (pinned identity) → TREE_GET
//!   (system/hash Amendment-6 pointer) → CONTENT_GET /content/{hex33(H)}
//!   → verify-by-rehash → ingest → byte-equality vs publisher originals.
//!
//! This is **Mechanism A** (NETWORK §6.5.3.1, HTTP-as-storage-transport),
//! NOT BRIDGE-HTTP.
//!
//! ## Two deliberate, documented divergences from Go's category
//!
//! 1. **Scope: ClosureScope + real signed root (not WholeStoreScope +
//!    fake root).** Rust ships no `WholeStoreScope` — serving is
//!    scope-gated by design (scope.rs: whole-store is a not-yet-shipped
//!    §6.5.6 explicit-opt-in shape). So we publish a *real* trie root
//!    committing to the served blog tree and serve it with `ClosureScope`
//!    (the spec-faithful scope for a publisher advertising a signed root).
//!    This is strictly stronger than Go's fake-root + serve-everything
//!    convenience and still proves every vector; the wire shapes the
//!    consumer sees (manifest, pointer, content) are identical.
//!
//! 2. **Consumer re-hashes inline rather than driving the full
//!    `PublishedRootClient`.** `published_root::verify_content`
//!    / `verify_signed_root` are form-agnostic and recompute the hash (the Gap
//!    A/B fix in `docs/SPEC-AMBIGUITIES.md`), so the content path *could* now
//!    run through `verify_content`. This test deliberately keeps an explicit
//!    Mechanism-A consumer — recompute `Hash::compute(type,data)` and trust the
//!    bytes only if they reproduce the requested hash — so the live wire shapes
//!    (manifest, 2-key pointer, 2-key content) stay visible at the test surface,
//!    and because the live two-hop signature fetch (pointer → CONTENT_GET) that
//!    `PublishedRootClient` over `HttpPollFetcher` needs is still Phase P7.

#![cfg(all(feature = "http-live", not(target_arch = "wasm32")))]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use entity_crypto::{verify_for_key_type, Keypair, KeyType};
use entity_entity::Entity;
use entity_hash::Hash;
use entity_peer::http_live::{ClosureScope, HttpLiveListener};
use entity_peer::published_root::{content_url, manifest_url, signature_url};
use entity_peer::PeerBuilder;
use entity_types::{PublishedRootData, SignatureData, TYPE_PUBLISHED_ROOT};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---------------------------------------------------------------------------
// Fixture + harness
// ---------------------------------------------------------------------------

const BLOG_TYPE: &str = "test/blog/post/v1";

/// One authored blog entity. `rel_path` is the peer-relative tree path the
/// consumer dials (the listener resolves `/{peer_id}/{rel_path}`); `data` is
/// the raw ECF payload the consumer asserts byte-equality on.
struct Authored {
    rel_path: String,
    data: Vec<u8>,
    hash: Hash,
}

/// Hand-rolled deterministic CBOR for a blog post — mirrors Go's
/// `mustCBORMap(map[string]any{"title":.., "body":..})`. ECF sorts map
/// keys ("body" < "title", same length), so we author in sorted order;
/// `to_ecf` is canonical regardless.
fn blog_entry(title: &str, body: &str) -> Vec<u8> {
    entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (entity_ecf::text("body"), entity_ecf::text(body)),
        (entity_ecf::text("title"), entity_ecf::text(title)),
    ]))
}

struct Harness {
    base: String,
    peer_id: String,
    pinned_pubkey: Vec<u8>,
    pinned_key_type: KeyType,
    head: Hash,
    entries: Vec<Authored>,
    _handle: tokio::task::JoinHandle<()>,
}

/// Stand up an in-process publisher + static origin: author 3 blog entries,
/// bind them at peer-relative paths, build a real trie root, publish a signed
/// `published-root`, and serve with `ClosureScope` on an ephemeral port.
async fn setup_publisher(seed: u8) -> Harness {
    let server = PeerBuilder::new()
        .keypair(Keypair::from_seed([seed; 32]))
        .build()
        .expect("peer builds");
    let peer_id = server.peer_id().to_string();
    let shared = server.shared();
    server.start_engines(&shared);

    let specs = [
        ("system/blog/post/entry-1", "first", "hello"),
        ("system/blog/post/entry-2", "second", "world"),
        ("system/blog/post/entry-3", "third", "fin"),
    ];
    let mut entries = Vec::new();
    let mut bindings = BTreeMap::new();
    for (rel, title, body) in specs {
        let data = blog_entry(title, body);
        let entity = Entity::new(BLOG_TYPE, data.clone()).expect("author blog entity");
        let hash = entity.content_hash;
        shared.content_store.put(entity).expect("content put");
        // Peer-relative path → absolute binding (the NamespacedIndex shell in Go).
        shared
            .location_index
            .set(&format!("/{}/{}", peer_id, rel), hash);
        bindings.insert(rel.to_string(), hash);
        entries.push(Authored {
            rel_path: rel.to_string(),
            data,
            hash,
        });
    }

    // Real signed root committing to the served tree (see divergence #1).
    let root = entity_tree::trie::build_trie(shared.content_store.as_ref(), &bindings)
        .expect("build trie");
    let head = server.publish_root(root).expect("publish signed root");

    let listener = HttpLiveListener::bind_poll("127.0.0.1:0", "")
        .await
        .expect("poll listener binds")
        .with_scope(Arc::new(ClosureScope::new()));
    let base = format!("http://{}", listener.bound_addr());
    let shared_clone = shared.clone();
    let handle = tokio::spawn(async move {
        let _ = listener.serve(shared_clone).await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    Harness {
        base,
        peer_id,
        pinned_pubkey: shared.keypair.public_key_bytes(),
        pinned_key_type: shared.keypair.key_type(),
        head,
        entries,
        _handle: handle,
    }
}

// ---------------------------------------------------------------------------
// Correct Mechanism-A consumer helpers (see divergence #2)
// ---------------------------------------------------------------------------

/// GET a URL, returning (status, body).
async fn get(client: &reqwest::Client, url: &str) -> (u16, Vec<u8>) {
    let resp = client.get(url).send().await.expect("GET sends");
    let status = resp.status().as_u16();
    let body = resp.bytes().await.expect("body reads").to_vec();
    (status, body)
}

/// Decode a TREE_GET leaf — the Amendment-6 `system/hash` 2-key bare pointer
/// `ECF({type:"system/hash", data:<bstr 33>})` — back to the pointed Hash.
fn parse_pointer(body: &[u8]) -> Hash {
    let val: entity_ecf::Value = ciborium::from_reader(body).expect("pointer is CBOR");
    let entries = match &val {
        entity_ecf::Value::Map(m) => m,
        _ => panic!("tree-get pointer is not a CBOR map"),
    };
    let mut etype: Option<String> = None;
    let mut data: Option<Vec<u8>> = None;
    for (k, v) in entries {
        match k.as_text() {
            Some("type") => etype = v.as_text().map(|s| s.to_string()),
            Some("data") => {
                data = match v {
                    entity_ecf::Value::Bytes(b) => Some(b.clone()),
                    _ => None,
                }
            }
            _ => {}
        }
    }
    assert_eq!(
        etype.as_deref(),
        Some("system/hash"),
        "tree-get leaf MUST be an Amendment-6 system/hash pointer"
    );
    Hash::from_bytes(&data.expect("pointer carries a 33-byte system/hash")).expect("valid hash")
}

/// Mechanism-A (§1.2) consumer-side CONTENT_GET verification. The content
/// route serves `ecf_for_hash(type, data)` (2-key {data, type}, NO
/// content_hash). Recover (type, data), recompute `Hash::compute(type,data)`,
/// and trust the bytes ONLY if they reproduce `requested`. Never trust a
/// wire-provided content_hash — the route doesn't carry one. Returns the
/// reconstructed entity (content_hash recomputed, not wire-trusted).
fn fetch_and_rehash(body: &[u8], requested: &Hash) -> Result<Entity, String> {
    let val: entity_ecf::Value =
        ciborium::from_reader(body).map_err(|e| format!("content body not CBOR: {e}"))?;
    let entries = match &val {
        entity_ecf::Value::Map(m) => m,
        _ => return Err("content body is not a CBOR map".into()),
    };
    let mut etype: Option<String> = None;
    let mut data: Option<Vec<u8>> = None;
    for (k, v) in entries {
        match k.as_text() {
            Some("type") => etype = v.as_text().map(|s| s.to_string()),
            // Fixtures are authored as canonical ECF, so re-encoding the
            // decoded data value reproduces the on-wire bytes 1:1 (the v5
            // ecf_for_hash byte-equality assertion is the airtight guard).
            Some("data") => data = Some(entity_ecf::to_ecf(v)),
            _ => {}
        }
    }
    let etype = etype.ok_or("content body missing 'type'")?;
    let data = data.ok_or("content body missing 'data'")?;
    let recomputed = Hash::compute(&etype, &data);
    if &recomputed != requested {
        return Err(format!(
            "content hash mismatch: re-hash {} != requested {}",
            recomputed.to_hex(),
            requested.to_hex()
        ));
    }
    Ok(Entity {
        entity_type: etype,
        data,
        content_hash: recomputed,
    })
}

/// Stand up a hostile static origin that serves `imposter` bytes for ANY
/// `/content/...` request, regardless of the requested hash. Mirrors Go's
/// swap-bytes server (v6).
async fn spawn_hostile_origin(imposter: Vec<u8>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("hostile origin binds");
    let addr = listener.local_addr().expect("hostile addr");
    let handle = tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => break,
            };
            let body = imposter.clone();
            tokio::spawn(async move {
                // Best-effort consume of the request head; we ignore it and
                // serve imposter bytes regardless of the requested hash.
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (format!("http://{}", addr), handle)
}

// ---------------------------------------------------------------------------
// The six vectors (gate = the combination; v5 is the end-to-end assertion)
// ---------------------------------------------------------------------------

/// v1 — publisher mints; PollHandler MANIFEST_GET serves a
/// `system/peer/published-root` with the right type, non-zero root_hash, and
/// matching peer_id. Unpinned read is fine here; the verify cycle is v2.
#[tokio::test]
async fn v1_publish_manifest_served() {
    let h = setup_publisher(0xC1).await;
    let client = reqwest::Client::new();

    let (status, body) = get(&client, &manifest_url(&h.base)).await;
    assert_eq!(status, 200, "MANIFEST_GET serves the published-root");

    let entity = entity_wire::decode_entity(&body).expect("manifest decodes (3-key form)");
    assert_eq!(
        entity.entity_type, TYPE_PUBLISHED_ROOT,
        "manifest entity is a system/peer/published-root"
    );
    let data = PublishedRootData::from_entity(&entity).expect("published-root data");
    assert!(
        data.root_hash.to_bytes().iter().any(|b| *b != 0),
        "published-root.root_hash is non-zero"
    );
    assert_eq!(data.peer_id, h.peer_id, "manifest peer_id == publisher peer_id");
}

/// v2 — a consumer with the publisher's pinned identity walks the V7 §5.2
/// invariant-pointer signature carriage (TREE_GET pointer → CONTENT_GET sig
/// entity) and the signature validates against the pinned key.
#[tokio::test]
async fn v2_manifest_signature_verified() {
    let h = setup_publisher(0xC2).await;
    let client = reqwest::Client::new();

    // MANIFEST_GET → published-root; recompute head (don't trust the wire hash).
    let (s1, manifest) = get(&client, &manifest_url(&h.base)).await;
    assert_eq!(s1, 200);
    let pr = entity_wire::decode_entity(&manifest).expect("manifest decodes");
    let head = Hash::compute(&pr.entity_type, &pr.data);
    assert_eq!(head, h.head, "recomputed manifest hash == published head");

    // Discover the signature at the invariant pointer: TREE_GET → pointer →
    // CONTENT_GET → re-hash → SignatureData.
    let (s2, ptr_body) = get(
        &client,
        &signature_url(&h.base, &h.peer_id, &head, ".bin"),
    )
    .await;
    assert_eq!(s2, 200, "signature invariant-pointer served (V7 §5.2)");
    let sig_hash = parse_pointer(&ptr_body);

    let (s3, sig_body) = get(&client, &content_url(&h.base, &sig_hash)).await;
    assert_eq!(s3, 200, "signature entity served by CONTENT_GET");
    let sig_entity = fetch_and_rehash(&sig_body, &sig_hash).expect("signature re-hashes");
    let sig = SignatureData::from_entity(&sig_entity).expect("signature data decodes");

    assert_eq!(sig.target, head, "signature targets the published head");
    verify_for_key_type(
        h.pinned_key_type,
        &h.pinned_pubkey,
        &head.to_bytes(),
        &sig.signature,
    )
    .expect("published-root signature verifies against the pinned identity");
}

/// v3 — for each authored peer-relative path, TREE_GET returns the bound
/// `system/hash` Amendment-6 pointer, byte-equal to the publisher's hash.
#[tokio::test]
async fn v3_tree_leaf_pointer_resolves() {
    let h = setup_publisher(0xC3).await;
    let client = reqwest::Client::new();

    for e in &h.entries {
        let url = format!("{}/{}/{}.bin", h.base, h.peer_id, e.rel_path);
        let (status, body) = get(&client, &url).await;
        assert_eq!(status, 200, "TREE_GET {} → 200", e.rel_path);
        let ptr = parse_pointer(&body);
        assert_eq!(
            ptr, e.hash,
            "tree-leaf pointer at {} == publisher hash",
            e.rel_path
        );
    }
}

/// v4 — CONTENT_GET on each leaf pointer returns an entity that re-hashes to
/// the requested H (Mechanism A trust gate fires positively).
#[tokio::test]
async fn v4_content_fetch_hash_verified() {
    let h = setup_publisher(0xC4).await;
    let client = reqwest::Client::new();

    for e in &h.entries {
        let (status, body) = get(&client, &content_url(&h.base, &e.hash)).await;
        assert_eq!(status, 200, "CONTENT_GET {} → 200", e.rel_path);
        let entity = fetch_and_rehash(&body, &e.hash)
            .unwrap_or_else(|err| panic!("re-hash gate at {}: {}", e.rel_path, err));
        assert_eq!(entity.content_hash, e.hash);
        assert_eq!(entity.entity_type, BLOG_TYPE);
    }
}

/// v5 — the end-to-end ingest gate: after the full TREE_GET → CONTENT_GET
/// walk, every consumer entity's `.data` is byte-equal to the publisher's
/// original (ECF byte-stability across the wire round-trip).
#[tokio::test]
async fn v5_ingest_byte_equality() {
    let h = setup_publisher(0xC5).await;
    let client = reqwest::Client::new();

    for e in &h.entries {
        // Walk the pointer (host-trusted), then fetch + re-hash the content.
        let url = format!("{}/{}/{}.bin", h.base, h.peer_id, e.rel_path);
        let (s1, ptr_body) = get(&client, &url).await;
        assert_eq!(s1, 200);
        let ptr = parse_pointer(&ptr_body);

        let (s2, content) = get(&client, &content_url(&h.base, &ptr)).await;
        assert_eq!(s2, 200);
        let entity = fetch_and_rehash(&content, &ptr).expect("content re-hashes");

        // Byte-equality on .data — and the airtight wire-stability guard:
        // the served body IS exactly ecf_for_hash(type, original_data).
        assert_eq!(
            entity.data, e.data,
            "ingested .data byte-equal to publisher original at {}",
            e.rel_path
        );
        assert_eq!(
            content,
            entity_ecf::ecf_for_hash(BLOG_TYPE, &e.data),
            "content body is the re-hashable ecf_for_hash(type,data) at {}",
            e.rel_path
        );
    }
}

/// v6 — §1.1 threat-model gate on the blog-entity shape: a swap-bytes static
/// origin is rejected by the connector's CONTENT_GET re-hash check (proves
/// the gate is shape-agnostic).
#[tokio::test]
async fn v6_host_bytes_distrust() {
    // The hash the consumer asks for (a legitimate blog entity).
    let real_data = blog_entry("real", "post");
    let real = Entity::new(BLOG_TYPE, real_data).expect("real entity");
    let requested = real.content_hash;

    // The bytes the hostile origin actually serves (a different blog entity).
    let imposter_data = blog_entry("imposter", "bytes");
    let imposter_body = entity_ecf::ecf_for_hash(BLOG_TYPE, &imposter_data);

    let (url, handle) = spawn_hostile_origin(imposter_body).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let client = reqwest::Client::new();
    let (status, body) = get(&client, &content_url(&url, &requested)).await;
    assert_eq!(status, 200, "hostile origin returns 200 with imposter bytes");

    match fetch_and_rehash(&body, &requested) {
        Ok(_) => panic!("§1.1 gate broken: imposter bytes accepted for blog-entity shape"),
        Err(msg) => assert!(
            msg.contains("hash"),
            "rejection must cite a hash mismatch, got: {msg}"
        ),
    }

    handle.abort();
}
