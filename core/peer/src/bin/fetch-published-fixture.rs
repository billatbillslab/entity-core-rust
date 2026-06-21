//! fetch-published-fixture — cross-impl interop harness consumer (Rust-side).
//!
//! Rust sibling of Go's `cmd/fetch-published-fixture` (per the cross-impl
//! publish/fetch fixture cohort handoff).
//! Drives the Tier-1 published-root read flow against an **external** HTTP-poll
//! origin URL (Go's `cmd/publish-fixture`, or any cohort publisher serving the
//! pinned contract) and asserts byte-equality against the pinned hashes:
//!
//!   MANIFEST_GET → signature verify (pinned identity, V7 §5.2 two-hop
//!   invariant pointer) → TREE_GET (Amendment-6 `system/hash` pointer) →
//!   CONTENT_GET → re-hash (§1.2 host-bytes-distrust) → byte-equality.
//!
//! This is the proof Thread B's in-process self-PASS was missing: a real
//! cross-process wire drive over HTTP, not an in-process listener.
//!
//! ## Why this drives the wire explicitly (not `PublishedRootClient`)
//!
//! The fixture publisher uses `WholeStoreScope` + a **fake** root hash
//! (`0xC0..0xDF`) with leaves bound by `path → hash` location-index entries —
//! the trie-closure `root_hash → leaves` is deliberately NOT asserted (it is a
//! separate v7 check). So `PublishedRootClient::resolve()` — which walks the
//! HAMT from `root_hash` — cannot resolve against this fixture, and
//! `HttpPollFetcher::signature_for` does a single-hop GET where the live
//! carriage needs the TREE_GET-pointer → CONTENT_GET two-hop (still Phase P7).
//! We therefore drive the live wire directly, mirroring Go's consumer and the
//! Rust Thread B test (`core/peer/tests/publish_fetch_http_poll.rs`).
//!
//! Usage:
//!   fetch-published-fixture -url http://127.0.0.1:9301 \
//!     [-peer-id 2KHcFAKPfQLw2ug7exu2mYTYAzPSKrWX2CsYY1cBVbBYJt]
//!
//! Exit 0 on full PASS; 1 on first FAIL with a diagnostic to stderr; 2 on a
//! build/feature misconfiguration.

#[cfg(all(feature = "http-live", not(target_arch = "wasm32")))]
fn main() {
    std::process::exit(driver::run());
}

#[cfg(not(all(feature = "http-live", not(target_arch = "wasm32"))))]
fn main() {
    eprintln!("fetch-published-fixture requires --features http-live on a non-wasm target");
    std::process::exit(2);
}

#[cfg(all(feature = "http-live", not(target_arch = "wasm32")))]
mod driver {
    use entity_crypto::{verify_for_key_type, Keypair, KeyType};
    use entity_entity::Entity;
    use entity_hash::Hash;
    use entity_peer::published_root::{content_url, manifest_url, signature_url};
    use entity_types::{PublishedRootData, SignatureData, TYPE_PUBLISHED_ROOT, TYPE_SIGNATURE};

    // -----------------------------------------------------------------------
    // Pinned contract — cross-impl publish/fetch fixture §1.
    // The digests are SHA-256 (format 0x00); Rust's display tag is
    // "ecfv1-sha256:" (Go renders them "ecf-sha256:" — same 64 hex digest).
    // -----------------------------------------------------------------------
    const PINNED_PEER_ID: &str = "2KHcFAKPfQLw2ug7exu2mYTYAzPSKrWX2CsYY1cBVbBYJt";
    const PINNED_IDENTITY_HASH: &str =
        "ecfv1-sha256:356a7a81d4eaa197ad2d2a2fb131246a824e50665ea75dce0c1b11ddd0a10e38";
    const PINNED_ROOT_HASH: &str =
        "ecfv1-sha256:c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf";
    const BLOG_TYPE: &str = "test/blog/post/v1";

    // Same fixture seed as cmd/publish-fixture: "entity-core-publish-fixture-v1"
    // (30 bytes) + two trailing zero bytes = 32 bytes.
    const SEED: &[u8; 32] = b"entity-core-publish-fixture-v1\x00\x00";

    struct Entry {
        path: &'static str,
        title: &'static str,
        body: &'static str,
        hash: &'static str,
    }

    const ENTRIES: [Entry; 3] = [
        Entry {
            path: "system/blog/post/entry-1",
            title: "first",
            body: "hello",
            hash: "ecfv1-sha256:d20663fce170dc9c2fd970d765b11d1f077fac49a46e18532acc8305ffa7fc6a",
        },
        Entry {
            path: "system/blog/post/entry-2",
            title: "second",
            body: "world",
            hash: "ecfv1-sha256:e1f0e4d46fe870259f207e1427e47890e81d511055bc94babdaa349bb4ce1308",
        },
        Entry {
            path: "system/blog/post/entry-3",
            title: "third",
            body: "fin",
            hash: "ecfv1-sha256:5e53c3dd00cef1ff28e7063cce622ae8e77a80b2c9077010016b5e86479aa756",
        },
    ];

    // -----------------------------------------------------------------------
    // Wire helpers — mirror core/peer/tests/publish_fetch_http_poll.rs.
    // -----------------------------------------------------------------------

    /// GET a URL, returning (status, body) or a transport error.
    fn get(client: &reqwest::blocking::Client, url: &str) -> Result<(u16, Vec<u8>), String> {
        let resp = client.get(url).send().map_err(|e| format!("GET {url}: {e}"))?;
        let status = resp.status().as_u16();
        let body = resp.bytes().map_err(|e| format!("body {url}: {e}"))?.to_vec();
        Ok((status, body))
    }

    /// Hand-rolled deterministic blog-post data — mirrors cmd/publish-fixture's
    /// CBOR map `{body, title}` (ECF sorts "body" < "title"). The cross-impl
    /// content-hash pins prove this byte-matches Go's serializer.
    fn blog_entry(title: &str, body: &str) -> Vec<u8> {
        entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("body"), entity_ecf::text(body)),
            (entity_ecf::text("title"), entity_ecf::text(title)),
        ]))
    }

    /// Decode a TREE_GET leaf — the Amendment-6 `system/hash` 2-key bare
    /// pointer `ECF({type:"system/hash", data:<bstr 33>})` — to the pointed
    /// Hash. (Uses ciborium directly because the inner 33-byte hash is a CBOR
    /// bstr, not a re-hashable data slice.)
    fn parse_pointer(body: &[u8]) -> Result<Hash, String> {
        let val: entity_ecf::Value =
            ciborium::from_reader(body).map_err(|e| format!("pointer not CBOR: {e}"))?;
        let entries = match &val {
            entity_ecf::Value::Map(m) => m,
            _ => return Err("tree-get pointer is not a CBOR map".into()),
        };
        let mut etype: Option<String> = None;
        let mut data: Option<Vec<u8>> = None;
        for (k, v) in entries {
            match k.as_text() {
                Some("type") => etype = v.as_text().map(|s| s.to_string()),
                Some("data") => {
                    if let entity_ecf::Value::Bytes(b) = v {
                        data = Some(b.clone());
                    }
                }
                _ => {}
            }
        }
        if etype.as_deref() != Some("system/hash") {
            return Err(format!(
                "tree-get leaf must be a system/hash pointer, got {:?}",
                etype
            ));
        }
        let bytes = data.ok_or("pointer carries no 33-byte system/hash")?;
        Hash::from_bytes(&bytes).map_err(|e| format!("pointer hash decode: {e}"))
    }

    /// Mechanism-A (§1.2) CONTENT_GET verification. The content route serves
    /// `ecf_for_hash(type, data)` (2-key, NO content_hash). Recover (type,
    /// data) form-agnostically, recompute `Hash::compute(type, data)`, and
    /// trust the bytes ONLY if they reproduce `requested`. Never trust a
    /// wire-supplied content_hash.
    fn fetch_and_rehash(body: &[u8], requested: &Hash) -> Result<Entity, String> {
        let (etype, data) =
            entity_wire::decode_entity_parts(body).map_err(|e| format!("content decode: {e}"))?;
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

    fn pinned(tag: &str) -> Hash {
        Hash::from_display(tag).unwrap_or_else(|e| panic!("pinned hash {tag:?} invalid: {e}"))
    }

    fn pass(msg: &str) {
        eprintln!("PASS  {msg}");
    }

    // -----------------------------------------------------------------------
    // Driver
    // -----------------------------------------------------------------------

    pub fn run() -> i32 {
        match drive() {
            Ok(()) => {
                println!("ALL PASS");
                0
            }
            Err(msg) => {
                eprintln!("FAIL  {msg}");
                1
            }
        }
    }

    fn drive() -> Result<(), String> {
        let mut url: Option<String> = None;
        let mut peer_id_flag: Option<String> = None;
        let mut args = std::env::args().skip(1);
        while let Some(a) = args.next() {
            match a.as_str() {
                "-url" | "--url" => url = args.next(),
                "-peer-id" | "--peer-id" => peer_id_flag = args.next(),
                other => return Err(format!("unknown flag {other:?} (want -url, -peer-id)")),
            }
        }
        let url = url.ok_or("-url flag is required (e.g. -url http://127.0.0.1:9301)")?;
        let base = url.trim_end_matches('/').to_string();

        // Pin the publisher identity by re-deriving from the fixture seed —
        // mirrors cmd/fetch-published-fixture. This locally computes the pinned
        // pubkey, peer-id, and identity content-hash, so the §1 table values are
        // cross-impl assertions, not blind trust.
        let keypair = Keypair::from_seed(*SEED);
        let pinned_pubkey = keypair.public_key_bytes();
        let derived_peer_id = keypair.peer_id().as_str().to_string();
        let derived_identity_hash = keypair.peer_identity_hash();

        if derived_peer_id != PINNED_PEER_ID {
            return Err(format!(
                "seed-derived peer-id {derived_peer_id} != pinned {PINNED_PEER_ID} \
                 (cross-impl peer-id derivation drift)"
            ));
        }
        if let Some(flag) = &peer_id_flag {
            if flag != &derived_peer_id {
                return Err(format!(
                    "-peer-id {flag} != fixture-seed-derived peer-id {derived_peer_id}"
                ));
            }
        }
        if derived_identity_hash != pinned(PINNED_IDENTITY_HASH) {
            return Err(format!(
                "seed-derived identity content-hash {} != pinned {PINNED_IDENTITY_HASH} \
                 (cross-impl identity-entity ECF drift)",
                derived_identity_hash.to_hex()
            ));
        }
        pass(&format!(
            "v0: pinned identity re-derived from seed (peer_id={derived_peer_id}, identity={})",
            derived_identity_hash.to_hex()
        ));

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| format!("build http client: {e}"))?;

        // -- v1 + v2 -- MANIFEST_GET → published-root → signature verify.
        let (status, manifest) = get(&client, &manifest_url(&base))?;
        if status != 200 {
            return Err(format!("v1 MANIFEST_GET → HTTP {status}"));
        }
        // Decode form-agnostically and recompute the head hash (§1.2 — never
        // trust a wire content_hash even on the manifest).
        let (m_type, m_data) =
            entity_wire::decode_entity_parts(&manifest).map_err(|e| format!("v1 manifest: {e}"))?;
        if m_type != TYPE_PUBLISHED_ROOT {
            return Err(format!(
                "v1 manifest type {m_type:?} != {TYPE_PUBLISHED_ROOT}"
            ));
        }
        let head = Hash::compute(&m_type, &m_data);
        let manifest_entity = Entity::new(&m_type, m_data).map_err(|e| format!("v1 entity: {e}"))?;
        let pr = PublishedRootData::from_entity(&manifest_entity)
            .map_err(|e| format!("v1 published-root data: {e}"))?;
        if pr.peer_id != derived_peer_id {
            return Err(format!(
                "v1 manifest peer_id {} != publisher {derived_peer_id}",
                pr.peer_id
            ));
        }
        if pr.root_hash != pinned(PINNED_ROOT_HASH) {
            return Err(format!(
                "v1 published root_hash {} != pinned {PINNED_ROOT_HASH}",
                pr.root_hash.to_hex()
            ));
        }

        // Signature carriage: TREE_GET invariant pointer → CONTENT_GET sig.
        let (sp_status, ptr_body) =
            get(&client, &signature_url(&base, &derived_peer_id, &head, ".bin"))?;
        if sp_status != 200 {
            return Err(format!(
                "v2 signature pointer (invariant path) → HTTP {sp_status}"
            ));
        }
        let sig_hash = parse_pointer(&ptr_body).map_err(|e| format!("v2 sig pointer: {e}"))?;
        let (sc_status, sig_body) = get(&client, &content_url(&base, &sig_hash))?;
        if sc_status != 200 {
            return Err(format!("v2 signature CONTENT_GET → HTTP {sc_status}"));
        }
        let sig_entity = fetch_and_rehash(&sig_body, &sig_hash).map_err(|e| format!("v2 sig: {e}"))?;
        if sig_entity.entity_type != TYPE_SIGNATURE {
            return Err(format!(
                "v2 signature entity type {:?} != {TYPE_SIGNATURE}",
                sig_entity.entity_type
            ));
        }
        let sig = SignatureData::from_entity(&sig_entity)
            .map_err(|e| format!("v2 signature data: {e}"))?;
        if sig.target != head {
            return Err(format!(
                "v2 signature target {} != published head {}",
                sig.target.to_hex(),
                head.to_hex()
            ));
        }
        if sig.signer != derived_identity_hash {
            return Err(format!(
                "v2 signature signer {} != pinned identity {}",
                sig.signer.to_hex(),
                derived_identity_hash.to_hex()
            ));
        }
        verify_for_key_type(KeyType::Ed25519, &pinned_pubkey, &head.to_bytes(), &sig.signature)
            .map_err(|e| format!("v2 signature does not verify under pinned key: {e}"))?;
        pass(&format!(
            "v1+v2: manifest served + signature verified (seq={} root={})",
            pr.seq,
            pr.root_hash.to_hex()
        ));

        // -- v3 + v4 -- TREE_GET pointer → assert pinned → CONTENT_GET → re-hash.
        for e in &ENTRIES {
            let want = pinned(e.hash);
            let (ts, ptr_body) = get(&client, &format!("{base}/{derived_peer_id}/{}.bin", e.path))?;
            if ts != 200 {
                return Err(format!("v3 TREE_GET {} → HTTP {ts}", e.path));
            }
            let ptr = parse_pointer(&ptr_body).map_err(|err| format!("v3 {} pointer: {err}", e.path))?;
            if ptr != want {
                return Err(format!(
                    "v3 tree pointer at {} = {} != pinned {}",
                    e.path,
                    ptr.to_hex(),
                    want.to_hex()
                ));
            }
            let (cs, content) = get(&client, &content_url(&base, &ptr))?;
            if cs != 200 {
                return Err(format!("v4 CONTENT_GET {} → HTTP {cs}", e.path));
            }
            let entity = fetch_and_rehash(&content, &ptr).map_err(|err| format!("v4 {}: {err}", e.path))?;
            if entity.content_hash != want {
                return Err(format!("v4 {} re-hash drift", e.path));
            }
            if entity.entity_type != BLOG_TYPE {
                return Err(format!(
                    "v4 {} type {:?} != {BLOG_TYPE}",
                    e.path, entity.entity_type
                ));
            }
        }
        pass(&format!(
            "v3+v4: resolved {} tree-leaf pointers + fetched + hash-verified",
            ENTRIES.len()
        ));

        // -- v5 -- byte-equality: the fetched .data byte-matches a locally
        // authored shape, and the served body IS ecf_for_hash(type, data).
        for e in &ENTRIES {
            let want = pinned(e.hash);
            let expected_data = blog_entry(e.title, e.body);
            let (cs, content) = get(&client, &content_url(&base, &want))?;
            if cs != 200 {
                return Err(format!("v5 CONTENT_GET {} → HTTP {cs}", e.path));
            }
            let entity = fetch_and_rehash(&content, &want).map_err(|err| format!("v5 {}: {err}", e.path))?;
            if entity.data != expected_data {
                return Err(format!("v5 .data byte-equality drift at {}", e.path));
            }
            if content != entity_ecf::ecf_for_hash(BLOG_TYPE, &expected_data) {
                return Err(format!(
                    "v5 content body != ecf_for_hash(type, data) at {}",
                    e.path
                ));
            }
        }
        pass(&format!(
            "v5: byte-equality holds across {} entities",
            ENTRIES.len()
        ));

        Ok(())
    }
}
