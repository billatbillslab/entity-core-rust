//! Phase P resolution-substrate baseline — `system/peer/published-root`
//! publisher + http-poll outbound verification/walk.
//!
//! Spec: `PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE.md` §1 (threat model), §2
//! (trust model), §4 (`published-root`, NORMATIVE-LOCKED).
//!
//! **Publisher** ([`PublishRootEngine`]) — on tree-root change, authors + signs
//! a `published-root` entity (monotonic `seq`, `predecessor` chain), carries the
//! signature at the invariant-pointer path, and binds the current head at
//! `/{peer}/system/peer/published-root` so `MANIFEST_GET` serves the latest.
//!
//! **Consumer** ([`PublishedRootClient`]) — fetches a peer's signed root,
//! verifies the signature against a **pinned** publisher key (the §2 trust
//! model: the signature defends against an untrusted intermediary), enforces
//! `seq` monotonicity (rollback rejection, §1.4), and resolves a path by
//! walking the HAMT **from the signed `root_hash`** — never trusting a
//! host-served `path → hash` binding (§1.1). Content is hash-verified on
//! receive (§1.2). The walk + verification are transport-agnostic over a
//! [`ContentFetcher`]; [`HttpPollFetcher`] is the live reqwest-backed impl.

use std::sync::Arc;
use std::sync::Mutex;

use entity_crypto::{verify_for_key_type, IdentityKeypair, KeyType};
use entity_entity::Entity;
use entity_hash::{default_hash_format, invariant_signature_path, Hash};
use entity_store::{ContentStore, LocationIndex, StoreError};
use entity_tree::trie::trie_get;
use entity_types::{PublishedRootData, SignatureData, TYPE_PUBLISHED_ROOT};

/// Well-known head-pointer path holding the current published-root hash.
pub fn published_root_head_path(peer_id: &str) -> String {
    format!("/{}/system/peer/published-root", peer_id)
}

fn now_ms() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, thiserror::Error)]
pub enum PublishedRootError {
    #[error("store error: {0}")]
    Store(String),
    #[error("encode error: {0}")]
    Encode(String),
    #[error("decode error: {0}")]
    Decode(String),
    #[error("published-root signature missing")]
    SignatureMissing,
    #[error("published-root signature invalid")]
    SignatureInvalid,
    #[error("peer_id mismatch: expected {expected}, got {got}")]
    PeerIdMismatch { expected: String, got: String },
    #[error("seq rollback: cached {cached}, received {received}")]
    SeqRollback { cached: u64, received: u64 },
    #[error("content hash mismatch (host served bytes that do not match the requested hash)")]
    ContentHashMismatch,
    #[error("path does not hash-chain from the signed root")]
    PathNotInSignedTree,
    #[error("fetch error: {0}")]
    Fetch(String),
}

impl From<StoreError> for PublishedRootError {
    fn from(e: StoreError) -> Self {
        PublishedRootError::Store(e.to_string())
    }
}

// ===========================================================================
// Publisher — task P1/P2 publisher half
// ===========================================================================

/// Authors + signs `system/peer/published-root` entities and serves them via
/// the head pointer (read by `MANIFEST_GET`).
pub struct PublishRootEngine {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    keypair: IdentityKeypair,
    peer_id: String,
    identity_hash: Hash,
}

impl PublishRootEngine {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        keypair: IdentityKeypair,
        peer_id: String,
        identity_hash: Hash,
    ) -> Self {
        Self {
            content_store,
            location_index,
            keypair,
            peer_id,
            identity_hash,
        }
    }

    fn head_path(&self) -> String {
        published_root_head_path(&self.peer_id)
    }

    /// The current head published-root hash (what `MANIFEST_GET` serves).
    pub fn current_head_hash(&self) -> Option<Hash> {
        self.location_index.get(&self.head_path())
    }

    /// The current head published-root, decoded.
    pub fn current_head(&self) -> Option<(Hash, PublishedRootData)> {
        let h = self.current_head_hash()?;
        let e = self.content_store.get(&h)?;
        PublishedRootData::from_entity(&e).ok().map(|d| (h, d))
    }

    /// Author + sign a new published-root committing to `root_hash`. `seq`
    /// increments from the prior head (recovered on startup from the tree);
    /// `predecessor` chains to it. Re-publishing an unchanged `root_hash` is a
    /// no-op (returns the existing head) so idempotent tree writes don't churn
    /// the chain. Returns the new (or unchanged) head hash.
    pub fn publish(&self, root_hash: Hash) -> Result<Hash, PublishedRootError> {
        let prev = self.current_head();
        if let Some((prev_hash, prev_data)) = &prev {
            if prev_data.root_hash == root_hash {
                return Ok(*prev_hash);
            }
        }
        let (seq, predecessor) = match &prev {
            Some((prev_hash, prev_data)) => (prev_data.seq + 1, Some(*prev_hash)),
            None => (0, None),
        };
        let pr = PublishedRootData {
            peer_id: self.peer_id.clone(),
            root_hash,
            seq,
            published_at: now_ms(),
            predecessor,
        };
        let entity = pr.to_entity().map_err(|e| PublishedRootError::Encode(e.to_string()))?;
        let hash = entity.content_hash;
        self.content_store.put(entity)?;

        // Sign the published-root's content hash; carry the signature at the
        // invariant-pointer path (§4 — NOT a refs: block).
        let sig = SignatureData {
            target: hash,
            signer: self.identity_hash,
            algorithm: self.keypair.key_type().label().to_string(),
            signature: self.keypair.sign(&hash.to_bytes()),
        };
        let sig_entity = sig
            .to_entity()
            .map_err(|e| PublishedRootError::Encode(e.to_string()))?;
        let sig_hash = sig_entity.content_hash;
        self.content_store.put(sig_entity)?;
        self.location_index
            .set(&invariant_signature_path(&self.peer_id, &hash), sig_hash);

        // Bind the head pointer last (MANIFEST_GET reads it).
        self.location_index.set(&self.head_path(), hash);
        Ok(hash)
    }
}

// ===========================================================================
// Pure verification (no I/O) — shared by sync + async consumers
// ===========================================================================

/// Decode + hash-verify a content body fetched by hash. Mechanism A (§1.2):
/// the consumer trusts the bytes only if they **re-hash** to the requested
/// hash. The body is parsed form-agnostically — both the 3-key authored form
/// and the 2-key `CONTENT_GET` form (`{data, type}`) are accepted — and the
/// hash is **recomputed** from `(type, data)` under the requested hash's own
/// format code. Any `content_hash` the host put on the wire is never read: a
/// host serving `{type, data:<evil>, content_hash:<expected>}` is rejected
/// because the recompute over `<evil>` will not equal `expected`.
pub fn verify_content(bytes: &[u8], expected: &Hash) -> Result<Entity, PublishedRootError> {
    let (entity_type, data) = entity_wire::decode_entity_parts(bytes)
        .map_err(|e| PublishedRootError::Decode(e.to_string()))?;
    // Recompute under the EXPECTED hash's format (§1.8 validate-on-receipt) —
    // never trust a wire-supplied content_hash. `new_with_format` rejects an
    // unsupported format code, which surfaces as a decode error.
    let entity = Entity::new_with_format(&entity_type, data, expected.algorithm)
        .map_err(|e| PublishedRootError::Decode(e.to_string()))?;
    if &entity.content_hash != expected {
        return Err(PublishedRootError::ContentHashMismatch);
    }
    Ok(entity)
}

/// Verify a fetched published-root against a **pinned** publisher key.
///
/// `manifest_bytes` is the published-root entity ECF; `signature_bytes` is its
/// `system/signature` entity ECF (carried per the §4 invariant pointer).
/// Verifies: (a) the published-root entity re-hashes consistently; (b) the
/// signature targets it and validates against `pinned_pubkey`; (c) the
/// `peer_id` matches `expected_peer_id` when given. Returns
/// `(published_root_hash, data)`. Does NOT enforce `seq` monotonicity — that is
/// stateful and lives in the client.
pub fn verify_signed_root(
    manifest_bytes: &[u8],
    signature_bytes: Option<&[u8]>,
    pinned_pubkey: &[u8],
    pinned_key_type: KeyType,
    expected_peer_id: Option<&str>,
) -> Result<(Hash, PublishedRootData), PublishedRootError> {
    // The manifest is served as a full wire entity (§6.5.3.1 MANIFEST_GET), so
    // it carries its own `content_hash` (with the publisher's format code). We
    // read that format but NEVER trust the digest: recompute under it and
    // require equality (§1.2 host-bytes-distrust). A host that swaps `data` —
    // e.g. to repoint the inner `root_hash` at an attacker-chosen tree while
    // keeping the outer hash that the publisher signed — fails the recompute,
    // and it cannot forge the publisher signature over the genuine hash.
    let entity = entity_wire::decode_entity(manifest_bytes)
        .map_err(|e| PublishedRootError::Decode(e.to_string()))?;
    if entity.entity_type != TYPE_PUBLISHED_ROOT {
        return Err(PublishedRootError::Decode(format!(
            "expected {}, got {}",
            TYPE_PUBLISHED_ROOT, entity.entity_type
        )));
    }
    Hash::validate(&entity.entity_type, &entity.data, &entity.content_hash)
        .map_err(|_| PublishedRootError::ContentHashMismatch)?;
    let root_hash = entity.content_hash;
    let data = PublishedRootData::from_entity(&entity)
        .map_err(|e| PublishedRootError::Decode(e.to_string()))?;

    if let Some(expected) = expected_peer_id {
        if data.peer_id != expected {
            return Err(PublishedRootError::PeerIdMismatch {
                expected: expected.to_string(),
                got: data.peer_id.clone(),
            });
        }
    }

    let sig_bytes = signature_bytes.ok_or(PublishedRootError::SignatureMissing)?;
    // The signature entity may be served in either the 3-key authored form or
    // the 2-key `CONTENT_GET` form, so decode it form-agnostically. Its own
    // `content_hash` is not security-relevant — trust comes from the Ed25519
    // verify against the pinned key below, not from the entity's self-hash —
    // so we reconstruct it under the floor format purely to parse the data.
    let (sig_type, sig_data) = entity_wire::decode_entity_parts(sig_bytes)
        .map_err(|e| PublishedRootError::Decode(e.to_string()))?;
    let sig_entity = Entity::new_with_format(&sig_type, sig_data, default_hash_format())
        .map_err(|e| PublishedRootError::Decode(e.to_string()))?;
    let sig = SignatureData::from_entity(&sig_entity)
        .map_err(|e| PublishedRootError::Decode(e.to_string()))?;
    if sig.target != root_hash {
        return Err(PublishedRootError::SignatureInvalid);
    }
    verify_for_key_type(pinned_key_type, pinned_pubkey, &root_hash.to_bytes(), &sig.signature)
        .map_err(|_| PublishedRootError::SignatureInvalid)?;

    Ok((root_hash, data))
}

// ===========================================================================
// Consumer — sync transport-agnostic client (task P5 verification core)
// ===========================================================================

/// Transport-agnostic fetch surface for the outbound connector. Errors are
/// transport-level (connection / HTTP status) and carried as strings.
pub trait ContentFetcher: Send + Sync {
    /// `MANIFEST_GET` → the published-root entity ECF bytes.
    fn manifest(&self) -> Result<Vec<u8>, String>;
    /// `CONTENT_GET {hash}` → entity ECF bytes (verified by the caller).
    fn content(&self, hash: &Hash) -> Result<Vec<u8>, String>;
    /// The published-root's `system/signature` entity ECF, if served. May be
    /// fetched host-trusted (a forged signature simply fails verification).
    fn signature_for(&self, target: &Hash) -> Result<Option<Vec<u8>>, String>;
}

/// A hash-verifying [`ContentStore`] view over a [`ContentFetcher`], so the
/// shared sync [`trie_get`] walk fetches + verifies each HAMT node by hash.
struct VerifyingFetchStore<'a> {
    fetcher: &'a dyn ContentFetcher,
}

impl ContentStore for VerifyingFetchStore<'_> {
    fn put(&self, _entity: Entity) -> Result<Hash, StoreError> {
        Err(StoreError::Internal("read-only fetch store".into()))
    }
    fn get(&self, hash: &Hash) -> Option<Entity> {
        let bytes = self.fetcher.content(hash).ok()?;
        verify_content(&bytes, hash).ok()
    }
    fn has(&self, hash: &Hash) -> bool {
        self.get(hash).is_some()
    }
    fn remove(&self, _hash: &Hash) -> bool {
        false
    }
    fn len(&self) -> usize {
        0
    }
}

/// Pins a publisher key + dials it over a [`ContentFetcher`]; verifies the
/// signed root, enforces `seq` monotonicity, and resolves paths by walking from
/// the signed root.
pub struct PublishedRootClient<F: ContentFetcher> {
    fetcher: F,
    pinned_pubkey: Vec<u8>,
    pinned_key_type: KeyType,
    expected_peer_id: Option<String>,
    cached_seq: Mutex<Option<u64>>,
}

impl<F: ContentFetcher> PublishedRootClient<F> {
    pub fn new(
        fetcher: F,
        pinned_pubkey: Vec<u8>,
        pinned_key_type: KeyType,
        expected_peer_id: Option<String>,
    ) -> Self {
        Self {
            fetcher,
            pinned_pubkey,
            pinned_key_type,
            expected_peer_id,
            cached_seq: Mutex::new(None),
        }
    }

    /// Fetch + verify the publisher's current signed root, enforcing `seq`
    /// monotonicity against the highest `seq` seen this session.
    pub fn fetch_root(&self) -> Result<PublishedRootData, PublishedRootError> {
        let manifest = self.fetcher.manifest().map_err(PublishedRootError::Fetch)?;
        // Decode once to learn the root hash so we can fetch the signature.
        let probe = entity_wire::decode_entity(&manifest)
            .map_err(|e| PublishedRootError::Decode(e.to_string()))?;
        let sig = self
            .fetcher
            .signature_for(&probe.content_hash)
            .map_err(PublishedRootError::Fetch)?;
        let (_, data) = verify_signed_root(
            &manifest,
            sig.as_deref(),
            &self.pinned_pubkey,
            self.pinned_key_type,
            self.expected_peer_id.as_deref(),
        )?;

        let mut cached = self.cached_seq.lock().unwrap();
        if let Some(prev) = *cached {
            if data.seq < prev {
                return Err(PublishedRootError::SeqRollback {
                    cached: prev,
                    received: data.seq,
                });
            }
        }
        *cached = Some(data.seq);
        Ok(data)
    }

    /// Resolve `relative_key` by walking the HAMT from the verified signed root.
    /// Returns the hash-verified leaf entity, or `None` if the key is not in the
    /// signed tree (host-fabricated bindings cannot appear here — §1.1).
    pub fn resolve(&self, relative_key: &str) -> Result<Option<Entity>, PublishedRootError> {
        let root = self.fetch_root()?;
        let store = VerifyingFetchStore {
            fetcher: &self.fetcher,
        };
        let leaf = match trie_get(&store, root.root_hash, relative_key) {
            Some(h) => h,
            None => return Ok(None),
        };
        let bytes = self.fetcher.content(&leaf).map_err(PublishedRootError::Fetch)?;
        Ok(Some(verify_content(&bytes, &leaf)?))
    }
}

// ===========================================================================
// Live HTTP-poll fetcher — speaks the http_live publisher URL layout
// ===========================================================================

/// `{base}/manifest`.
pub fn manifest_url(base: &str) -> String {
    format!("{}/manifest", base.trim_end_matches('/'))
}

/// `{base}/content/{hex66}` (flat content layout — what http_live serves).
pub fn content_url(base: &str, hash: &Hash) -> String {
    format!("{}/content/{}", base.trim_end_matches('/'), hash.to_hex())
}

/// `{base}/{peer}/system/signature/{hex66}{suffix}` — the invariant-pointer
/// tree path the publisher binds the signature at. Host-trusted fetch; the
/// signature is verified against the pinned key, so host tampering is caught.
pub fn signature_url(base: &str, peer_id: &str, target: &Hash, tree_leaf_suffix: &str) -> String {
    format!(
        "{}/{}/system/signature/{}{}",
        base.trim_end_matches('/'),
        peer_id,
        target.to_hex(),
        tree_leaf_suffix
    )
}

/// Live reqwest-backed [`ContentFetcher`] for dialing an http-poll publisher.
///
/// Uses `reqwest::blocking` so it drives the sync [`PublishedRootClient`] walk
/// directly. **Caveat:** a blocking client MUST NOT be called from within an
/// async runtime — wrap usage in `tokio::task::spawn_blocking` when dialing
/// from an async context. Wiring this into the live transport-dispatch loop is
/// Phase P P7 (cohort convergence); the verification + walk logic it drives is
/// covered by the in-memory tests below.
#[cfg(all(feature = "http-live", not(target_arch = "wasm32")))]
pub struct HttpPollFetcher {
    client: reqwest::blocking::Client,
    base: String,
    peer_id: String,
    tree_leaf_suffix: String,
}

#[cfg(all(feature = "http-live", not(target_arch = "wasm32")))]
impl HttpPollFetcher {
    /// `base` is the poll route root (e.g. `http://host:port` or
    /// `http://host:port/poll`); `peer_id` is the publisher's Base58 id;
    /// `tree_leaf_suffix` is the publisher's leaf suffix (default `.bin`).
    pub fn new(base: impl Into<String>, peer_id: impl Into<String>, tree_leaf_suffix: impl Into<String>) -> Self {
        Self {
            client: reqwest::blocking::Client::new(),
            base: base.into(),
            peer_id: peer_id.into(),
            tree_leaf_suffix: tree_leaf_suffix.into(),
        }
    }

    fn get(&self, url: &str) -> Result<Option<Vec<u8>>, String> {
        let resp = self.client.get(url).send().map_err(|e| e.to_string())?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(format!("http status {}", resp.status()));
        }
        let bytes = resp.bytes().map_err(|e| e.to_string())?;
        Ok(Some(bytes.to_vec()))
    }
}

#[cfg(all(feature = "http-live", not(target_arch = "wasm32")))]
impl ContentFetcher for HttpPollFetcher {
    fn manifest(&self) -> Result<Vec<u8>, String> {
        self.get(&manifest_url(&self.base))?
            .ok_or_else(|| "manifest not found".to_string())
    }
    fn content(&self, hash: &Hash) -> Result<Vec<u8>, String> {
        self.get(&content_url(&self.base, hash))?
            .ok_or_else(|| "content not found".to_string())
    }
    fn signature_for(&self, target: &Hash) -> Result<Option<Vec<u8>>, String> {
        self.get(&signature_url(&self.base, &self.peer_id, target, &self.tree_leaf_suffix))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashMap};

    use entity_crypto::Keypair;
    use entity_store::{MemoryContentStore, MemoryLocationIndex};
    use entity_tree::trie::build_trie;

    fn kp() -> IdentityKeypair {
        IdentityKeypair::Ed25519(Keypair::from_seed([7u8; 32]))
    }

    fn dummy_identity_hash() -> Hash {
        Hash::compute("system/peer", b"identity")
    }

    fn leaf_entity(tag: &str) -> Entity {
        Entity::new("test/leaf", entity_ecf::to_ecf(&entity_ecf::text(tag))).unwrap()
    }

    /// Fetcher serving directly off the publisher's content store + location
    /// index — mirrors the real http_live publisher (manifest = the head
    /// published-root; content by hash; signature via invariant pointer).
    struct StoreFetcher {
        store: Arc<dyn ContentStore>,
        li: Arc<dyn LocationIndex>,
        peer_id: String,
        manifest_hash: Mutex<Hash>,
        forced_sig: Mutex<Option<Option<Vec<u8>>>>,
        content_override: Mutex<HashMap<Hash, Vec<u8>>>,
    }

    impl StoreFetcher {
        fn new(
            store: Arc<dyn ContentStore>,
            li: Arc<dyn LocationIndex>,
            peer_id: String,
            manifest_hash: Hash,
        ) -> Self {
            Self {
                store,
                li,
                peer_id,
                manifest_hash: Mutex::new(manifest_hash),
                forced_sig: Mutex::new(None),
                content_override: Mutex::new(HashMap::new()),
            }
        }
        fn serve(&self, h: &Hash) -> Result<Vec<u8>, String> {
            if let Some(b) = self.content_override.lock().unwrap().get(h) {
                return Ok(b.clone());
            }
            self.store
                .get(h)
                .map(|e| entity_wire::encode_entity(&e))
                .ok_or_else(|| "not found".to_string())
        }
    }

    impl ContentFetcher for StoreFetcher {
        fn manifest(&self) -> Result<Vec<u8>, String> {
            let h = *self.manifest_hash.lock().unwrap();
            self.serve(&h)
        }
        fn content(&self, hash: &Hash) -> Result<Vec<u8>, String> {
            self.serve(hash)
        }
        fn signature_for(&self, target: &Hash) -> Result<Option<Vec<u8>>, String> {
            if let Some(forced) = &*self.forced_sig.lock().unwrap() {
                return Ok(forced.clone());
            }
            let path = invariant_signature_path(&self.peer_id, target);
            match self.li.get(&path) {
                Some(sig_hash) => self.serve(&sig_hash).map(Some),
                None => Ok(None),
            }
        }
    }

    fn build_published(
        bindings: BTreeMap<String, Hash>,
    ) -> (Arc<dyn ContentStore>, Arc<dyn LocationIndex>, IdentityKeypair, String, Hash) {
        let store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let root_hash = build_trie(store.as_ref(), &bindings).unwrap();
        let keypair = kp();
        let peer_id = keypair.peer_id().as_str().to_string();
        let engine = PublishRootEngine::new(
            store.clone(),
            li.clone(),
            keypair.clone_identity(),
            peer_id.clone(),
            dummy_identity_hash(),
        );
        let head = engine.publish(root_hash).unwrap();
        (store, li, keypair, peer_id, head)
    }

    // ----- Publisher -----

    #[test]
    fn url_construction_matches_http_live_routes() {
        let h = Hash::compute("t", b"x");
        let hex = h.to_hex();
        assert_eq!(manifest_url("http://host:9/poll"), "http://host:9/poll/manifest");
        assert_eq!(manifest_url("http://host:9/poll/"), "http://host:9/poll/manifest");
        assert_eq!(content_url("http://host:9", &h), format!("http://host:9/content/{}", hex));
        assert_eq!(
            signature_url("http://host:9", "z6Mk", &h, ".bin"),
            format!("http://host:9/z6Mk/system/signature/{}.bin", hex)
        );
    }

    #[test]
    fn publisher_increments_seq_and_chains() {
        let store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let keypair = kp();
        let peer_id = keypair.peer_id().as_str().to_string();
        let engine = PublishRootEngine::new(
            store.clone(),
            li.clone(),
            keypair.clone_identity(),
            peer_id.clone(),
            dummy_identity_hash(),
        );
        let root_a = Hash::compute("test", b"root-a");
        let root_b = Hash::compute("test", b"root-b");

        let h0 = engine.publish(root_a).unwrap();
        let (_, d0) = engine.current_head().unwrap();
        assert_eq!(d0.seq, 0);
        assert!(d0.predecessor.is_none());
        assert_eq!(d0.root_hash, root_a);

        let h1 = engine.publish(root_b).unwrap();
        let (_, d1) = engine.current_head().unwrap();
        assert_eq!(d1.seq, 1);
        assert_eq!(d1.predecessor, Some(h0));
        assert_eq!(d1.root_hash, root_b);

        // Re-publishing the same root is a no-op (no churn).
        let h1_again = engine.publish(root_b).unwrap();
        assert_eq!(h1_again, h1);
        assert_eq!(engine.current_head().unwrap().1.seq, 1);
    }

    // ----- Consumer: verify + walk -----

    fn client_for(
        store: Arc<dyn ContentStore>,
        li: Arc<dyn LocationIndex>,
        keypair: &IdentityKeypair,
        peer_id: &str,
        head: Hash,
    ) -> PublishedRootClient<StoreFetcher> {
        let fetcher = StoreFetcher::new(store, li, peer_id.to_string(), head);
        PublishedRootClient::new(
            fetcher,
            keypair.public_key_bytes(),
            keypair.key_type(),
            Some(peer_id.to_string()),
        )
    }

    #[test]
    fn consumer_verifies_and_resolves_from_signed_root() {
        let leaf = leaf_entity("alpha");
        let mut bindings = BTreeMap::new();
        bindings.insert("system/a".to_string(), leaf.content_hash);
        let (store, li, keypair, peer_id, head) = build_published(bindings);
        store.put(leaf.clone()).unwrap();

        let client = client_for(store, li, &keypair, &peer_id, head);
        let root = client.fetch_root().unwrap();
        assert_eq!(root.seq, 0);

        let got = client.resolve("system/a").unwrap().unwrap();
        assert_eq!(got.content_hash, leaf.content_hash);
        // Absent key → None (not an error).
        assert!(client.resolve("system/absent").unwrap().is_none());
    }

    #[test]
    fn consumer_rejects_forged_root_signature() {
        let (store, li, keypair, peer_id, head) = build_published(BTreeMap::new());
        let client = client_for(store, li.clone(), &keypair, &peer_id, head);
        // Force a garbage signature entity (valid shape, wrong bytes).
        let bad_sig = SignatureData {
            target: head,
            signer: dummy_identity_hash(),
            algorithm: "ed25519".into(),
            signature: vec![0u8; 64],
        };
        *client.fetcher.forced_sig.lock().unwrap() =
            Some(Some(entity_wire::encode_entity(&bad_sig.to_entity().unwrap())));
        match client.fetch_root() {
            Err(PublishedRootError::SignatureInvalid) => {}
            other => panic!("expected SignatureInvalid, got {:?}", other),
        }
    }

    #[test]
    fn consumer_rejects_missing_signature() {
        let (store, li, keypair, peer_id, head) = build_published(BTreeMap::new());
        let client = client_for(store, li, &keypair, &peer_id, head);
        *client.fetcher.forced_sig.lock().unwrap() = Some(None);
        match client.fetch_root() {
            Err(PublishedRootError::SignatureMissing) => {}
            other => panic!("expected SignatureMissing, got {:?}", other),
        }
    }

    #[test]
    fn consumer_rejects_seq_rollback() {
        // Publish seq 0 then seq 1 in the same store.
        let store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let keypair = kp();
        let peer_id = keypair.peer_id().as_str().to_string();
        let engine = PublishRootEngine::new(
            store.clone(),
            li.clone(),
            keypair.clone_identity(),
            peer_id.clone(),
            dummy_identity_hash(),
        );
        let h0 = engine.publish(Hash::compute("t", b"r0")).unwrap();
        let h1 = engine.publish(Hash::compute("t", b"r1")).unwrap();

        let client = client_for(store, li, &keypair, &peer_id, h1);
        // Fetch the newer (seq 1) first → caches seq 1.
        assert_eq!(client.fetch_root().unwrap().seq, 1);
        // Now serve the older (seq 0) → rollback rejected.
        *client.fetcher.manifest_hash.lock().unwrap() = h0;
        match client.fetch_root() {
            Err(PublishedRootError::SeqRollback { cached: 1, received: 0 }) => {}
            other => panic!("expected SeqRollback, got {:?}", other),
        }
    }

    #[test]
    fn consumer_rejects_host_fabricated_binding() {
        // The signed trie binds "system/a" → real leaf. A hostile host cannot
        // make resolve() return a different entity for "system/a" (the walk is
        // from the signed root) and cannot inject a binding for an unsigned key.
        let real = leaf_entity("real");
        let mut bindings = BTreeMap::new();
        bindings.insert("system/a".to_string(), real.content_hash);
        let (store, li, keypair, peer_id, head) = build_published(bindings);
        store.put(real.clone()).unwrap();

        let client = client_for(store, li, &keypair, &peer_id, head);
        // resolve returns the real leaf, never anything the host fabricates.
        assert_eq!(
            client.resolve("system/a").unwrap().unwrap().content_hash,
            real.content_hash
        );
        // A key the host might "claim" but the signed trie never bound → None.
        assert!(client.resolve("system/evil").unwrap().is_none());
    }

    #[test]
    fn consumer_rejects_tampered_content() {
        let leaf = leaf_entity("honest");
        let mut bindings = BTreeMap::new();
        bindings.insert("system/a".to_string(), leaf.content_hash);
        let (store, li, keypair, peer_id, head) = build_published(bindings);
        store.put(leaf.clone()).unwrap();

        let client = client_for(store, li, &keypair, &peer_id, head);
        // Host serves a valid-but-DIFFERENT entity for the leaf hash → it
        // decodes fine but re-hashes to a different hash → rejected (§1.2).
        let impostor = leaf_entity("impostor");
        client
            .fetcher
            .content_override
            .lock()
            .unwrap()
            .insert(leaf.content_hash, entity_wire::encode_entity(&impostor));
        match client.resolve("system/a") {
            Err(PublishedRootError::ContentHashMismatch) => {}
            other => panic!("expected ContentHashMismatch, got {:?}", other),
        }
    }

    // ----- verify_content: §1.2 host-bytes-distrust (Gap A + Gap B) -----

    #[test]
    fn verify_content_accepts_2key_content_get_form() {
        // The live CONTENT_GET route serves the bare 2-key `{data, type}` form
        // (`ecf_for_hash`), with NO `content_hash` on the wire. verify_content
        // must decode it and recompute the hash itself.
        let leaf = leaf_entity("alpha");
        let body = entity_ecf::ecf_for_hash(&leaf.entity_type, &leaf.data);
        let got = verify_content(&body, &leaf.content_hash).unwrap();
        assert_eq!(got.content_hash, leaf.content_hash);
        assert_eq!(got.data, leaf.data);
    }

    #[test]
    fn verify_content_rejects_hash_lying_host() {
        // The Gap B attack: a host serves the 3-key form with HONEST-looking
        // `content_hash:<expected>` but `data:<evil>`. The old code trusted the
        // wire `content_hash` and let this pass. verify_content now recomputes
        // from (type, data) and must reject — the evil bytes do not re-hash to
        // the requested hash.
        let honest = leaf_entity("honest");
        let evil = leaf_entity("evil");
        let lying = Entity {
            entity_type: evil.entity_type.clone(),
            data: evil.data.clone(),
            content_hash: honest.content_hash, // the lie
        };
        let body = entity_wire::encode_entity(&lying);
        match verify_content(&body, &honest.content_hash) {
            Err(PublishedRootError::ContentHashMismatch) => {}
            other => panic!("expected ContentHashMismatch, got {:?}", other),
        }
    }
}
