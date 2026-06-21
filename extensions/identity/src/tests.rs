//! Integration tests for EXTENSION-IDENTITY v3.2.
//!
//! Exercises the 7 handler ops plus the convergence side effects in
//! `process_attestation`. Substrate primitives (attestation + quorum)
//! have their own test suites covering TV-A1–A11, TV-I1–I5, TV-Q1–Q9,
//! TV-QF12–15. These tests cover the v3.2 identity contributions:
//! kind+function topology dispatch, chain walking, §9.4 fail-closed
//! recovery validation, peer-config + cap issuance.

use std::collections::HashMap;
use std::sync::Arc;

use entity_attestation::{AttestationData, AttestationIndex};
use entity_capability::{wildcard_handler_grant, ResourceTarget};
use entity_crypto::Keypair;
use entity_ecf::{text, to_ecf, Value};
use entity_entity::Entity;
use entity_hash::Hash;
use entity_quorum::{
    path_quorum, path_quorum_event, QuorumData, ResolverRegistry, SignerSetCache,
};
use entity_store::{
    ContentStore, LocationIndex, MemoryContentStore, MemoryLocationIndex,
};
use entity_types::SignatureData;

use crate::handler::IdentityHandler;
use crate::kinds::{KIND_IDENTITY_CERT, KIND_IDENTITY_ROTATION_RECOVERY};
use crate::paths::{path_internal_cert, path_public_cert};
use crate::validation::{
    identity_topology_for, identity_verify_cert, IdentityCtx, Topology,
};

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

struct Harness {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    attestation_index: Arc<AttestationIndex>,
    resolver_registry: ResolverRegistry,
    signer_set_cache: Arc<SignerSetCache>,
    /// Local peer's identity hash (used as the granter for caps).
    local_identity_hash: Hash,
    /// Local peer's keypair.
    local_keypair: Keypair,
    /// Local peer's PeerID string.
    local_peer_id: String,
    /// Named keypairs for ceremony participants.
    keypairs: HashMap<String, Keypair>,
    identity_hashes: HashMap<String, Hash>,
}

impl Harness {
    fn new() -> Self {
        let content_store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let location_index: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        // Local peer's keypair.
        let local_keypair = Keypair::from_seed([1u8; 32]);
        let local_id_entity = local_keypair.peer_entity().unwrap();
        let local_identity_hash = local_id_entity.content_hash;
        content_store.put(local_id_entity).unwrap();
        let local_peer_id = local_keypair.peer_id().to_string();
        Self {
            content_store,
            location_index,
            attestation_index: Arc::new(AttestationIndex::new()),
            resolver_registry: ResolverRegistry::new(),
            signer_set_cache: Arc::new(SignerSetCache::new()),
            local_identity_hash,
            local_keypair,
            local_peer_id,
            keypairs: HashMap::new(),
            identity_hashes: HashMap::new(),
        }
    }

    fn add_peer(&mut self, name: &str, seed: u8) -> Hash {
        let kp = Keypair::from_seed([seed; 32]);
        let id_entity = kp.peer_entity().unwrap();
        let id_hash = id_entity.content_hash;
        self.content_store.put(id_entity).unwrap();
        self.identity_hashes.insert(name.to_string(), id_hash);
        self.keypairs.insert(name.to_string(), kp);
        id_hash
    }

    fn peer(&self, name: &str) -> Hash {
        *self.identity_hashes.get(name).expect("peer not added")
    }

    fn keypair(&self, name: &str) -> &Keypair {
        self.keypairs.get(name).expect("keypair missing")
    }

    fn handler(&self) -> IdentityHandler {
        IdentityHandler::new(
            self.content_store.clone(),
            self.location_index.clone(),
            self.attestation_index.clone(),
            self.resolver_registry.clone(),
            self.signer_set_cache.clone(),
            self.local_peer_id.clone(),
            self.local_identity_hash,
            entity_crypto::IdentityKeypair::Ed25519(self.local_keypair.clone_inner()),
        )
    }

    fn qualify(&self, bare: &str) -> String {
        format!("/{}/{}", self.local_peer_id, bare)
    }

    /// Persist a quorum at canonical path.
    fn add_quorum(&mut self, signer_names: &[&str], threshold: u64) -> Hash {
        let signers: Vec<Hash> = signer_names.iter().map(|n| self.peer(n)).collect();
        let q = QuorumData {
            signers,
            threshold,
            signer_resolution: None,
            name: None,
            metadata: None,
        };
        let entity = q.to_entity().unwrap();
        let q_hash = entity.content_hash;
        self.content_store.put(entity).unwrap();
        let path = self.qualify(&path_quorum(&q_hash));
        self.location_index.set(&path, q_hash);
        q_hash
    }

    /// Sign `target` with each named signer and bind at the V7 invariant
    /// pointer path so the substrate's signature lookup finds it.
    fn sign_with(&mut self, target: &Hash, signer_names: &[&str]) {
        for name in signer_names {
            let kp = self.keypair(name);
            let signer = self.peer(name);
            let sig_bytes = kp.sign(&target.to_bytes());
            let sig_data = SignatureData {
                target: *target,
                signer,
                algorithm: "ed25519".into(),
                signature: sig_bytes.to_vec(),
            };
            let sig_entity = sig_data.to_entity().unwrap();
            let sig_hash = sig_entity.content_hash;
            self.content_store.put(sig_entity).unwrap();
            let path = self.qualify(&format!(
                "{}/system/signature/{}",
                entity_attestation::hex_segment(&signer),
                entity_attestation::hex_segment(target)
            ));
            self.location_index.set(&path, sig_hash);
        }
    }

    /// Build, sign, persist, and index an `identity-cert` attestation.
    fn add_identity_cert(
        &mut self,
        attesting_peer: &str,
        attested_peer: &str,
        function: &str,
        mode: &str,
        sign_with: &[&str],
        contact_id: Option<&str>,
    ) -> Hash {
        let attesting = self.peer(attesting_peer);
        let attested = self.peer(attested_peer);
        let mut props: Vec<(ciborium::Value, ciborium::Value)> = vec![
            (text("function"), text(function)),
            (text("kind"), text(KIND_IDENTITY_CERT)),
            (text("mode"), text(mode)),
        ];
        if let Some(cid) = contact_id {
            let cid_hash = self.peer(cid);
            props.push((text("contact_id"), Value::Bytes(cid_hash.to_bytes().to_vec())));
        }
        props.sort_by(|a, b| a.0.as_text().unwrap_or("").cmp(b.0.as_text().unwrap_or("")));
        let att = AttestationData {
            attesting,
            attested,
            properties: props,
            supersedes: None,
            not_before: None,
            expires_at: None,
        };
        let entity = att.to_entity().unwrap();
        let att_hash = entity.content_hash;
        self.content_store.put(entity).unwrap();
        let bare_path = match mode {
            "internal" => path_internal_cert(&att_hash),
            "public" => path_public_cert(&att_hash),
            other => panic!("unsupported test mode: {}", other),
        };
        let path = self.qualify(&bare_path);
        self.location_index.set(&path, att_hash);
        self.attestation_index.insert(att_hash, att);
        self.sign_with(&att_hash, sign_with);
        att_hash
    }

    /// Build, sign, persist, and index a quorum-publish for a contact's
    /// quorum. Used for §9.4 fail-closed tests.
    fn add_quorum_publish_cache(
        &mut self,
        quorum_id: Hash,
        signer_names: &[&str],
        threshold: u64,
        published_handle: Hash,
        sign_with: &[&str],
    ) -> Hash {
        let signers: Vec<Hash> = signer_names.iter().map(|n| self.peer(n)).collect();
        let mut props: Vec<(ciborium::Value, ciborium::Value)> = vec![
            (text("kind"), text(entity_quorum::KIND_QUORUM_PUBLISH)),
            (
                text("published_handle"),
                Value::Bytes(published_handle.to_bytes().to_vec()),
            ),
            (
                text("signers"),
                Value::Array(
                    signers
                        .iter()
                        .map(|h| Value::Bytes(h.to_bytes().to_vec()))
                        .collect(),
                ),
            ),
            (text("threshold"), entity_ecf::integer(threshold as i64)),
        ];
        props.sort_by(|a, b| a.0.as_text().unwrap_or("").cmp(b.0.as_text().unwrap_or("")));
        let att = AttestationData {
            attesting: quorum_id,
            attested: quorum_id,
            properties: props,
            supersedes: None,
            not_before: None,
            expires_at: None,
        };
        let entity = att.to_entity().unwrap();
        let att_hash = entity.content_hash;
        self.content_store.put(entity).unwrap();
        let path = self.qualify(&path_quorum_event(&quorum_id, &att_hash));
        self.location_index.set(&path, att_hash);
        self.attestation_index.insert(att_hash, att);
        self.sign_with(&att_hash, sign_with);
        // Seed the contact-quorum cache (the convergence point's job).
        let cache_path =
            self.qualify(&crate::paths::path_contact_quorum_publish(&published_handle));
        self.location_index.set(&cache_path, att_hash);
        att_hash
    }

    /// Add a rotation-recovery attestation. Caller controls signing.
    fn add_rotation_recovery(
        &mut self,
        quorum_id: Hash,
        new_key: Hash,
        target_cert: Hash,
        old_handle: Hash,
        sign_with: &[&str],
    ) -> (Hash, AttestationData) {
        let mut props: Vec<(ciborium::Value, ciborium::Value)> = vec![
            (text("kind"), text(KIND_IDENTITY_ROTATION_RECOVERY)),
            (text("old_handle"), Value::Bytes(old_handle.to_bytes().to_vec())),
            (
                text("target_cert"),
                Value::Bytes(target_cert.to_bytes().to_vec()),
            ),
        ];
        props.sort_by(|a, b| a.0.as_text().unwrap_or("").cmp(b.0.as_text().unwrap_or("")));
        let att = AttestationData {
            attesting: quorum_id,
            attested: new_key,
            properties: props,
            supersedes: None,
            not_before: None,
            expires_at: None,
        };
        let entity = att.to_entity().unwrap();
        let att_hash = entity.content_hash;
        self.content_store.put(entity).unwrap();
        // Same audience tier as target.
        let path = self.qualify(&path_public_cert(&att_hash));
        self.location_index.set(&path, att_hash);
        self.attestation_index.insert(att_hash, att.clone());
        self.sign_with(&att_hash, sign_with);
        (att_hash, att)
    }

    fn ictx(&self) -> IdentityCtx<'_> {
        IdentityCtx {
            attestation_index: &self.attestation_index,
            content_store: &self.content_store,
            location_index: &self.location_index,
            included: leak_empty(),
            resolver_registry: &self.resolver_registry,
            signer_set_cache: &self.signer_set_cache,
        }
    }
}

fn leak_empty() -> &'static HashMap<Hash, Entity> {
    use std::sync::OnceLock;
    static EMPTY: OnceLock<HashMap<Hash, Entity>> = OnceLock::new();
    EMPTY.get_or_init(HashMap::new)
}

// ===========================================================================
// Topology dispatch (§3.6)
// ===========================================================================

#[test]
fn topology_top_level_controller_is_k_of_n() {
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    h.add_peer("k3", 12);
    h.add_peer("ctrl", 20);
    let q_hash = h.add_quorum(&["k1", "k2", "k3"], 2);
    h.identity_hashes.insert("quorum".into(), q_hash);
    h.keypairs.insert("quorum".into(), Keypair::from_seed([99u8; 32])); // unused; quorum doesn't sign as a peer
    let cert_hash = h.add_identity_cert("quorum", "ctrl", "controller", "public", &["k1", "k2"], None);
    let cert = h.attestation_index.get(&cert_hash).unwrap();
    let topology = identity_topology_for(&cert, &h.ictx()).expect("topology");
    match topology {
        Topology::KofN { signers, threshold } => {
            assert_eq!(signers.len(), 3);
            assert_eq!(threshold, 2);
        }
        other => panic!("expected K-of-N, got {:?}", other),
    }
}

#[test]
fn topology_agent_cert_is_single_sig() {
    let mut h = Harness::new();
    h.add_peer("ctrl", 20);
    h.add_peer("agent", 30);
    let cert_hash = h.add_identity_cert("ctrl", "agent", "agent", "internal", &["ctrl"], None);
    let cert = h.attestation_index.get(&cert_hash).unwrap();
    let topology = identity_topology_for(&cert, &h.ictx()).expect("topology");
    match topology {
        Topology::Single { expected_signer } => {
            assert_eq!(expected_signer, h.peer("ctrl"));
        }
        other => panic!("expected Single, got {:?}", other),
    }
}

// ===========================================================================
// Three-key default ceremony — full chain validation
// ===========================================================================

#[test]
fn three_key_default_ceremony_validates_chain() {
    let mut h = Harness::new();
    // Quorum constituents.
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    h.add_peer("k3", 12);
    // Controller (= handle in 3-key default).
    h.add_peer("ctrl", 20);
    // Agent (per-device daemon).
    h.add_peer("agent", 30);

    // 1. Quorum entity.
    let q_hash = h.add_quorum(&["k1", "k2", "k3"], 2);
    h.identity_hashes.insert("quorum".into(), q_hash);
    h.keypairs.insert("quorum".into(), Keypair::from_seed([99u8; 32]));

    // 2. Controller cert (public, K-of-N signed).
    let ctrl_cert = h.add_identity_cert(
        "quorum",
        "ctrl",
        "controller",
        "public",
        &["k1", "k2"],
        None,
    );

    // 3. Agent cert (internal, single-sig from controller).
    let agent_cert = h.add_identity_cert(
        "ctrl",
        "agent",
        "agent",
        "internal",
        &["ctrl"],
        None,
    );

    // Validate both certs via identity_verify_cert.
    let ctrl_data = h.attestation_index.get(&ctrl_cert).unwrap();
    let agent_data = h.attestation_index.get(&agent_cert).unwrap();
    identity_verify_cert(&ctrl_cert, &ctrl_data, &h.ictx())
        .expect("controller cert should validate");
    identity_verify_cert(&agent_cert, &agent_data, &h.ictx())
        .expect("agent cert should validate (chain walks back to quorum)");
}

#[test]
fn missing_quorum_signature_fails_chain_validation() {
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    h.add_peer("k3", 12);
    h.add_peer("ctrl", 20);
    let q_hash = h.add_quorum(&["k1", "k2", "k3"], 2);
    h.identity_hashes.insert("quorum".into(), q_hash);
    h.keypairs.insert("quorum".into(), Keypair::from_seed([99u8; 32]));
    // Sign with only K=1 instead of K=2.
    let cert = h.add_identity_cert("quorum", "ctrl", "controller", "public", &["k1"], None);
    let cert_data = h.attestation_index.get(&cert).unwrap();
    let result = identity_verify_cert(&cert, &cert_data, &h.ictx());
    assert!(result.is_err(), "K=1 should fail K-of-N=2 validation");
}

// ===========================================================================
// Handler ops — configure, create_attestation, process_attestation
// ===========================================================================

use entity_handler::{Handler, HandlerContext, STATUS_OK};

fn build_ctx(
    handler: &IdentityHandler,
    operation: &str,
    resource: Option<&str>,
    params_data: Vec<u8>,
) -> HandlerContext {
    let _ = handler;
    let params = Entity::new("test/params", params_data).unwrap();
    HandlerContext {
        handler_grant: None,
        caller_capability: None,
        execute: Entity::new("test/execute", vec![0xa0]).unwrap(),
        params,
        pattern: String::new(),
        suffix: String::new(),
        resource_target: resource.map(|r| ResourceTarget {
            targets: vec![r.to_string()],
            exclude: vec![],
        }),
        author: None,
        request_id: String::new(),
        operation: operation.to_string(),
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

/// R-1 (cross-impl spec): `create_attestation` request shape
/// per EXTENSION-ATTESTATION §6.1 nests `kind`/`function`/`mode`/etc. under
/// a `properties: map` field. Pre-R-1 Rust flattened them; that broke wire
/// parity with Go/Python.
#[tokio::test]
async fn create_attestation_writes_at_canonical_path_and_indexes() {
    let mut h = Harness::new();
    h.add_peer("ctrl", 20);
    h.add_peer("agent", 30);
    let handler = h.handler();
    let ctrl = h.peer("ctrl");
    let agent = h.peer("agent");
    let params = to_ecf(&Value::Map(vec![
        (text("attested"), Value::Bytes(agent.to_bytes().to_vec())),
        (text("attesting"), Value::Bytes(ctrl.to_bytes().to_vec())),
        (
            text("properties"),
            Value::Map(vec![
                (text("function"), text("agent")),
                (text("kind"), text(KIND_IDENTITY_CERT)),
                (text("mode"), text("internal")),
            ]),
        ),
    ]));
    let ctx = build_ctx(&handler, "create_attestation", None, params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_eq!(result.status, STATUS_OK, "create_attestation should succeed");
    // The attestation is now in the index.
    assert_eq!(h.attestation_index.len(), 1, "exactly one attestation indexed");
}

#[tokio::test]
async fn create_attestation_rejects_missing_function_for_identity_cert() {
    let mut h = Harness::new();
    h.add_peer("ctrl", 20);
    h.add_peer("agent", 30);
    let handler = h.handler();
    let ctrl = h.peer("ctrl");
    let agent = h.peer("agent");
    let params = to_ecf(&Value::Map(vec![
        (text("attested"), Value::Bytes(agent.to_bytes().to_vec())),
        (text("attesting"), Value::Bytes(ctrl.to_bytes().to_vec())),
        (
            text("properties"),
            Value::Map(vec![
                (text("kind"), text(KIND_IDENTITY_CERT)),
                (text("mode"), text("internal")),
                // function omitted
            ]),
        ),
    ]));
    let ctx = build_ctx(&handler, "create_attestation", None, params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_ne!(result.status, STATUS_OK, "missing function should reject");
}

#[tokio::test]
async fn create_attestation_rejects_missing_mode_for_identity_cert() {
    let mut h = Harness::new();
    h.add_peer("ctrl", 20);
    h.add_peer("agent", 30);
    let handler = h.handler();
    let ctrl = h.peer("ctrl");
    let agent = h.peer("agent");
    let params = to_ecf(&Value::Map(vec![
        (text("attested"), Value::Bytes(agent.to_bytes().to_vec())),
        (text("attesting"), Value::Bytes(ctrl.to_bytes().to_vec())),
        (
            text("properties"),
            Value::Map(vec![
                (text("function"), text("agent")),
                (text("kind"), text(KIND_IDENTITY_CERT)),
                // mode omitted
            ]),
        ),
    ]));
    let ctx = build_ctx(&handler, "create_attestation", None, params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_ne!(result.status, STATUS_OK, "missing mode should reject");
}

/// R-4 (cross-impl spec): `:create_quorum` MUST preserve
/// `name` and `metadata` from the request so that the recomputed canonical
/// path matches the caller's locally-computed canonical path. Pre-R-4 Rust
/// dropped both → resource_target_mismatch under R-3 strict.
///
/// This test follows the SDK shape exactly: caller computes the canonical
/// QuorumData hash locally (with all fields included), passes the canonical
/// path as the resource target, and dispatches `:create_quorum`. The handler
/// MUST persist the entity at that path with byte-identical content_hash.
#[tokio::test]
async fn create_quorum_preserves_name_and_metadata_for_canonical_path() {
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    h.add_peer("k3", 12);
    let handler = h.handler();
    let signers = vec![h.peer("k1"), h.peer("k2"), h.peer("k3")];

    // Caller-side canonical: build the exact QuorumData the handler will
    // build from these inputs, hash it, derive the canonical path.
    let quorum_metadata = vec![(text("purpose"), text("acme-founders"))];
    let canonical_q = QuorumData {
        signers: signers.clone(),
        threshold: 2,
        signer_resolution: None,
        name: Some("acme-founders-quorum".into()),
        metadata: Some(quorum_metadata.clone()),
    };
    let canonical_hash = canonical_q.to_entity().unwrap().content_hash;
    let canonical_path = h.qualify(&path_quorum(&canonical_hash));

    // Dispatch the request with the canonical path as the resource target.
    let params = to_ecf(&Value::Map(vec![
        (text("metadata"), Value::Map(quorum_metadata)),
        (text("name"), text("acme-founders-quorum")),
        (
            text("signers"),
            Value::Array(
                signers
                    .iter()
                    .map(|p| Value::Bytes(p.to_bytes().to_vec()))
                    .collect(),
            ),
        ),
        (text("threshold"), entity_ecf::integer(2)),
    ]));
    let ctx = build_ctx(
        &handler,
        "create_quorum",
        Some(&canonical_path),
        params,
    );
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_eq!(
        result.status, STATUS_OK,
        "R-4: create_quorum must succeed with canonical path matching name+metadata"
    );

    // Tree binding lands at the canonical path with the canonical hash.
    let bound = h
        .location_index
        .get(&canonical_path)
        .expect("quorum bound at canonical path");
    assert_eq!(
        bound, canonical_hash,
        "R-4: bound hash MUST equal the caller-computed canonical hash"
    );

    // Round-trip via from_entity: name and metadata both persist.
    let entity = h.content_store.get(&bound).expect("quorum in store");
    let decoded = QuorumData::from_entity(&entity).unwrap();
    assert_eq!(decoded.name.as_deref(), Some("acme-founders-quorum"));
    assert!(decoded.metadata.is_some(), "metadata MUST round-trip");
}

/// R-4 negative: a request whose name doesn't match the canonical path
/// MUST be rejected with `resource_target_mismatch` under R-3 strict.
#[tokio::test]
async fn create_quorum_rejects_when_request_diverges_from_canonical_path() {
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    let handler = h.handler();
    let signers = vec![h.peer("k1"), h.peer("k2")];

    // Caller-side canonical built WITHOUT a name.
    let canonical_no_name = QuorumData {
        signers: signers.clone(),
        threshold: 2,
        signer_resolution: None,
        name: None,
        metadata: None,
    };
    let no_name_path = h.qualify(&path_quorum(&canonical_no_name.to_entity().unwrap().content_hash));

    // Dispatch WITH a name in params (creates a different QuorumData) but
    // supply the no-name canonical path as the resource. R-3 strict +
    // R-4 round-trip MUST surface the mismatch.
    let params = to_ecf(&Value::Map(vec![
        (text("name"), text("oops-name")),
        (
            text("signers"),
            Value::Array(
                signers
                    .iter()
                    .map(|p| Value::Bytes(p.to_bytes().to_vec()))
                    .collect(),
            ),
        ),
        (text("threshold"), entity_ecf::integer(2)),
    ]));
    let ctx = build_ctx(&handler, "create_quorum", Some(&no_name_path), params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_eq!(
        result.status, 400,
        "R-3 strict + R-4 fidelity: divergent canonical path MUST 400"
    );
}

/// R-6 (cross-impl spec): `:create_attestation` with
/// `properties.mode = "embedded"` MUST return the AttestationData inline
/// under `embedded_attestation`, with `attestation_hash` and `storage_path`
/// absent (the absence of `attestation_hash` is the wire signal for "not
/// bound in tree" per Go's reference shape).
#[tokio::test]
async fn create_attestation_embedded_returns_inline_entity() {
    let mut h = Harness::new();
    h.add_peer("ctrl", 20);
    h.add_peer("agent", 30);
    let handler = h.handler();
    let ctrl = h.peer("ctrl");
    let agent = h.peer("agent");

    // Embedded mode is signaled by `mode: "embedded"` in properties.
    // `compute_storage_path` returns None for embedded mode (no canonical
    // tree path), and the (None, None) branch routes through the
    // embedded-result helper.
    let params = to_ecf(&Value::Map(vec![
        (text("attested"), Value::Bytes(agent.to_bytes().to_vec())),
        (text("attesting"), Value::Bytes(ctrl.to_bytes().to_vec())),
        (
            text("properties"),
            Value::Map(vec![
                (text("function"), text("agent")),
                (text("kind"), text(KIND_IDENTITY_CERT)),
                (text("mode"), text("embedded")),
            ]),
        ),
    ]));
    let ctx = build_ctx(&handler, "create_attestation", None, params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_eq!(result.status, STATUS_OK, "embedded create_attestation must succeed");

    // The result entity carries the per-op type tag (R-2).
    assert_eq!(
        result.result.entity_type, "system/identity/create-attestation-result",
        "R-2: embedded result MUST use the spec-pinned type tag"
    );

    // Decode the result payload.
    let result_value: ciborium::Value =
        ciborium::from_reader(result.result.data.as_slice()).expect("CBOR result decodes");
    let result_map = result_value.as_map().expect("result is a CBOR map");

    // R-6: `embedded_attestation` MUST be present and be a sub-map.
    let embedded = result_map
        .iter()
        .find_map(|(k, v)| if k.as_text() == Some("embedded_attestation") { Some(v) } else { None })
        .expect("R-6: embedded_attestation field MUST be present");
    let embedded_map = embedded.as_map().expect("embedded_attestation is a sub-map");

    // The embedded sub-map MUST carry the AttestationData fields.
    let has_attesting = embedded_map.iter().any(|(k, _)| k.as_text() == Some("attesting"));
    let has_attested = embedded_map.iter().any(|(k, _)| k.as_text() == Some("attested"));
    let has_properties = embedded_map.iter().any(|(k, _)| k.as_text() == Some("properties"));
    assert!(has_attesting, "embedded_attestation MUST carry `attesting`");
    assert!(has_attested, "embedded_attestation MUST carry `attested`");
    assert!(has_properties, "embedded_attestation MUST carry `properties`");

    // R-6: `attestation_hash` MUST be absent (Go's omitempty contract;
    // hash presence is the "bound in tree" wire signal).
    assert!(
        result_map.iter().all(|(k, _)| k.as_text() != Some("attestation_hash")),
        "R-6: embedded mode MUST omit attestation_hash"
    );
    // `storage_path` MUST also be absent (no tree binding).
    assert!(
        result_map.iter().all(|(k, _)| k.as_text() != Some("storage_path")),
        "R-6: embedded mode MUST omit storage_path"
    );
}

/// R-6 round-trip: the inline `embedded_attestation` payload must be
/// byte-identical to the canonical `AttestationData::to_entity().data`
/// — i.e., re-decoding the inline map yields a CBOR Value equivalent to
/// the canonical encoding. This pins the contract that callers can
/// embed the inline payload directly into a cap envelope without
/// re-encoding.
#[tokio::test]
async fn create_attestation_embedded_inline_matches_canonical_encoding() {
    let mut h = Harness::new();
    h.add_peer("ctrl", 20);
    h.add_peer("agent", 30);
    let handler = h.handler();
    let ctrl = h.peer("ctrl");
    let agent = h.peer("agent");

    let params = to_ecf(&Value::Map(vec![
        (text("attested"), Value::Bytes(agent.to_bytes().to_vec())),
        (text("attesting"), Value::Bytes(ctrl.to_bytes().to_vec())),
        (
            text("properties"),
            Value::Map(vec![
                (text("function"), text("agent")),
                (text("kind"), text(KIND_IDENTITY_CERT)),
                (text("mode"), text("embedded")),
            ]),
        ),
    ]));
    let ctx = build_ctx(&handler, "create_attestation", None, params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_eq!(result.status, STATUS_OK);

    // Re-encode the canonical AttestationData (matches what the handler built).
    let canonical_props = vec![
        (text("function"), text("agent")),
        (text("kind"), text(KIND_IDENTITY_CERT)),
        (text("mode"), text("embedded")),
    ];
    let canonical_att = AttestationData {
        attesting: ctrl,
        attested: agent,
        properties: canonical_props,
        supersedes: None,
        not_before: None,
        expires_at: None,
    };
    let canonical_entity = canonical_att.to_entity().expect("canonical encode");
    let canonical_value: ciborium::Value =
        ciborium::from_reader(canonical_entity.data.as_slice()).expect("decode canonical");

    // Extract the embedded sub-map from the result.
    let result_value: ciborium::Value =
        ciborium::from_reader(result.result.data.as_slice()).expect("CBOR result decodes");
    let result_map = result_value.as_map().expect("result is a CBOR map");
    let embedded = result_map
        .iter()
        .find_map(|(k, v)| if k.as_text() == Some("embedded_attestation") { Some(v.clone()) } else { None })
        .expect("embedded_attestation present");

    assert_eq!(
        embedded, canonical_value,
        "R-6: inline embedded_attestation MUST match AttestationData canonical encoding"
    );
}

/// R-7 (cross-impl spec): `:configure` MUST issue one
/// local-peer→controller cap per live top-level controller-cert anchored
/// under `trusts_quorum`. Pre-R-7 Rust iterated `bindings` only and
/// returned 200 with empty caps when the controller-cert was created
/// via `:create_attestation` ahead of `:configure` without bindings.
/// Algorithm follows Go's `enumerateLiveControllerCerts`: walk by
/// `attesting=trusts_quorum` filtered by `identity_confers_function(controller)`,
/// then liveness-filter and verify each.
#[tokio::test]
async fn pr7_configure_issues_cap_per_live_controller_under_quorum() {
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    h.add_peer("k3", 12);
    h.add_peer("ctrl", 20);

    // Quorum + controller-cert (signed K-of-N). Cert is bound +
    // attestation-index-populated by `add_identity_cert`.
    let q_hash = h.add_quorum(&["k1", "k2", "k3"], 2);
    h.identity_hashes.insert("quorum".into(), q_hash);
    h.keypairs.insert("quorum".into(), Keypair::from_seed([99u8; 32]));
    let cert_hash = h.add_identity_cert(
        "quorum",
        "ctrl",
        "controller",
        "public",
        &["k1", "k2"],
        None,
    );
    let ctrl_peer = h.peer("ctrl");

    // Dispatch `:configure` with the trusted quorum + wildcard
    // controller_grants. No bindings supplied (R-7 quorum-walk path).
    let handler = h.handler();
    let pc_path = h.qualify(crate::paths::PATH_PEER_CONFIG);
    let wildcard_grant = Value::Map(vec![
        (
            text("handlers"),
            Value::Map(vec![(text("include"), Value::Array(vec![text("*")]))]),
        ),
        (
            text("operations"),
            Value::Map(vec![(text("include"), Value::Array(vec![text("*")]))]),
        ),
        (
            text("resources"),
            Value::Map(vec![(text("include"), Value::Array(vec![text("/*/*")]))]),
        ),
    ]);
    let params = to_ecf(&Value::Map(vec![
        (text("bindings"), Value::Array(vec![])),
        (text("controller_grants"), Value::Array(vec![wildcard_grant])),
        (text("trusts_quorum"), Value::Bytes(q_hash.to_bytes().to_vec())),
    ]));
    let ctx = build_ctx(&handler, "configure", Some(&pc_path), params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_eq!(
        result.status, STATUS_OK,
        "R-7: configure with live controller-cert must succeed; got {}",
        result.status
    );

    // Decode result; expect exactly one cap whose grantee == ctrl_peer.
    let result_value: ciborium::Value =
        ciborium::from_reader(result.result.data.as_slice()).expect("decode result");
    let result_map = result_value.as_map().expect("result is map");
    let caps = result_map
        .iter()
        .find_map(|(k, v)| if k.as_text() == Some("local_peer_to_controller_caps") { v.as_array() } else { None })
        .expect("result MUST carry local_peer_to_controller_caps");
    assert_eq!(
        caps.len(), 1,
        "R-7: one live controller-cert MUST yield exactly one cap"
    );
    let cap_hash_bytes = caps[0].as_bytes().expect("cap is hash bytes");
    let cap_hash = Hash::from_bytes(cap_hash_bytes).expect("decode cap hash");
    let cap_entity = h.content_store.get(&cap_hash).expect("cap in store");
    let cap_token = entity_capability::CapabilityToken::from_entity(&cap_entity).unwrap();
    assert_eq!(
        cap_token.grantee, ctrl_peer,
        "R-7: cap grantee MUST be the controller-cert's `attested` field"
    );
    let _ = cert_hash;
}

/// R-7' (Round-4 reframe — cross-impl spec):
/// Exact-wire reproduction of `acme_14_1_configure_ceremony` mirroring
/// Go's mintAndSignControllerCert + Configure flow. All steps dispatch
/// through the handler (not direct put). Includes Go's `name` field on
/// the quorum (per ext/identity/sdk/client.go::CreateQuorum).
#[tokio::test]
async fn pr7_prime_configure_via_dispatch_full_acme_flow() {
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    h.add_peer("k3", 12);
    h.add_peer("ctrl", 20);

    // Persist founder identity entities in content store (the wire test
    // driver binds these via the connection envelope; the harness binds
    // directly). Without this, resolve_peer can't look them up.
    for n in ["k1", "k2", "k3"] {
        let kp = h.keypair(n);
        let id_entity = kp.peer_entity().unwrap();
        h.content_store.put(id_entity).unwrap();
    }
    let signers = vec![h.peer("k1"), h.peer("k2"), h.peer("k3")];
    let ctrl_peer = h.peer("ctrl");
    let handler = h.handler();

    // Step 1: dispatch :create_quorum with a `name` (mirrors Go's
    // `CreateQuorum(ctx, founderHashes, 2, "acme-founders-...")`).
    let canonical_q = QuorumData {
        signers: signers.clone(),
        threshold: 2,
        signer_resolution: None,
        name: Some("acme-founders-test".into()),
        metadata: None,
    };
    let q_hash = canonical_q.to_entity().unwrap().content_hash;
    let q_path = h.qualify(&path_quorum(&q_hash));
    let q_params = to_ecf(&Value::Map(vec![
        (text("name"), text("acme-founders-test")),
        (
            text("signers"),
            Value::Array(
                signers
                    .iter()
                    .map(|p| Value::Bytes(p.to_bytes().to_vec()))
                    .collect(),
            ),
        ),
        (text("threshold"), entity_ecf::integer(2)),
    ]));
    let r1 = handler
        .handle(&build_ctx(&handler, "create_quorum", Some(&q_path), q_params))
        .await
        .unwrap();
    assert_eq!(r1.status, STATUS_OK, "create_quorum must succeed");

    // Step 2: dispatch :create_attestation building controller-cert.
    let cert_props = vec![
        (text("function"), text("controller")),
        (text("kind"), text(KIND_IDENTITY_CERT)),
        (text("mode"), text("internal")),
    ];
    let canonical_cert = AttestationData {
        attesting: q_hash,
        attested: ctrl_peer,
        properties: cert_props.clone(),
        supersedes: None,
        not_before: None,
        expires_at: None,
    };
    let cert_hash = canonical_cert.to_entity().unwrap().content_hash;
    let cert_path = h.qualify(&path_internal_cert(&cert_hash));
    let cert_params = to_ecf(&Value::Map(vec![
        (text("attested"), Value::Bytes(ctrl_peer.to_bytes().to_vec())),
        (text("attesting"), Value::Bytes(q_hash.to_bytes().to_vec())),
        (text("properties"), Value::Map(cert_props)),
    ]));
    let r2 = handler
        .handle(&build_ctx(
            &handler,
            "create_attestation",
            Some(&cert_path),
            cert_params,
        ))
        .await
        .unwrap();
    assert_eq!(
        r2.status, STATUS_OK,
        "create_attestation must succeed; got {}: {:?}",
        r2.status,
        String::from_utf8_lossy(&r2.result.data)
    );

    // Step 3: bind 2-of-3 founder signatures at V7 §6.5 invariant pointer
    // paths. Wire-form: /{founder_i}/system/signature/{att_hex} (top-level
    // peer namespace, NOT nested under local_peer).
    for n in ["k1", "k2"] {
        let kp = h.keypair(n);
        let signer = h.peer(n);
        let sig_bytes = kp.sign(&cert_hash.to_bytes());
        let sig_data = SignatureData {
            target: cert_hash,
            signer,
            algorithm: "ed25519".into(),
            signature: sig_bytes.to_vec(),
        };
        let sig_entity = sig_data.to_entity().unwrap();
        let sig_hash = sig_entity.content_hash;
        h.content_store.put(sig_entity).unwrap();
        let sig_path = format!(
            "/{}/system/signature/{}",
            entity_attestation::hex_segment(&signer),
            entity_attestation::hex_segment(&cert_hash)
        );
        h.location_index.set(&sig_path, sig_hash);
    }

    // Step 4: dispatch :configure. Expected: 200 with one cap.
    let pc_path = h.qualify(crate::paths::PATH_PEER_CONFIG);
    let cfg_params = to_ecf(&Value::Map(vec![
        (text("bindings"), Value::Array(vec![])),
        (text("controller_grants"), Value::Array(vec![])),
        (text("trusts_quorum"), Value::Bytes(q_hash.to_bytes().to_vec())),
    ]));
    let r4 = handler
        .handle(&build_ctx(&handler, "configure", Some(&pc_path), cfg_params))
        .await
        .unwrap();
    assert_eq!(
        r4.status, STATUS_OK,
        "R-7' (Round-4): configure with dispatch-bound cert must succeed; got status {} body {:?}",
        r4.status,
        String::from_utf8_lossy(&r4.result.data)
    );
}

/// R-13 (cross-impl spec, Round 7): the local-peer→controller
/// cap MUST be tree-bound at the controller-keyed canonical path
/// `system/capability/grants/identity/peer-to-controller/{controller_hex}`
/// per Go's `ext/identity/paths.go::localPeerToControllerCapPath`. Pre-R-13
/// Rust used `system/capability/grants/controller/{hex}` which broke the
/// Acme test driver's tree:get and the multi-controller addressability
/// (§11.6 / `assign_under_controller_cap` blocked).
#[tokio::test]
async fn pr13_peer_to_controller_cap_bound_at_canonical_path() {
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    h.add_peer("k3", 12);
    h.add_peer("ctrl", 20);

    let q_hash = h.add_quorum(&["k1", "k2", "k3"], 2);
    h.identity_hashes.insert("quorum".into(), q_hash);
    h.keypairs.insert("quorum".into(), Keypair::from_seed([99u8; 32]));
    let _ctrl_cert = h.add_identity_cert(
        "quorum",
        "ctrl",
        "controller",
        "public",
        &["k1", "k2"],
        None,
    );
    let ctrl_peer = h.peer("ctrl");

    // Dispatch :configure.
    let handler = h.handler();
    let pc_path = h.qualify(crate::paths::PATH_PEER_CONFIG);
    let wildcard_grant = Value::Map(vec![
        (
            text("handlers"),
            Value::Map(vec![(text("include"), Value::Array(vec![text("*")]))]),
        ),
        (
            text("operations"),
            Value::Map(vec![(text("include"), Value::Array(vec![text("*")]))]),
        ),
        (
            text("resources"),
            Value::Map(vec![(text("include"), Value::Array(vec![text("/*/*")]))]),
        ),
    ]);
    let params = to_ecf(&Value::Map(vec![
        (text("bindings"), Value::Array(vec![])),
        (text("controller_grants"), Value::Array(vec![wildcard_grant])),
        (text("trusts_quorum"), Value::Bytes(q_hash.to_bytes().to_vec())),
    ]));
    let ctx = build_ctx(&handler, "configure", Some(&pc_path), params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_eq!(result.status, STATUS_OK);

    // R-13: cap MUST be readable at the controller-keyed canonical path.
    let canonical_cap_path = h.qualify(&format!(
        "system/capability/grants/identity/peer-to-controller/{}",
        entity_attestation::hex_segment(&ctrl_peer)
    ));
    let bound_cap_hash = h
        .location_index
        .get(&canonical_cap_path)
        .expect("R-13: cap MUST be bound at peer-to-controller/{controller_hex}");

    // Sanity: the bound cap matches the cap returned in the configure result.
    let result_value: ciborium::Value =
        ciborium::from_reader(result.result.data.as_slice()).expect("decode result");
    let result_map = result_value.as_map().expect("map");
    let result_caps = result_map
        .iter()
        .find_map(|(k, v)| if k.as_text() == Some("local_peer_to_controller_caps") { v.as_array() } else { None })
        .expect("local_peer_to_controller_caps");
    assert_eq!(result_caps.len(), 1);
    let returned_hash = Hash::from_bytes(result_caps[0].as_bytes().unwrap()).unwrap();
    assert_eq!(
        bound_cap_hash, returned_hash,
        "R-13: bound cap hash MUST match the hash returned in the configure result"
    );

    // R-13 negative: the OLD divergent path MUST NOT carry the binding.
    let old_divergent_path = h.qualify(&format!(
        "system/capability/grants/controller/{}",
        entity_attestation::hex_segment(&ctrl_peer)
    ));
    assert!(
        h.location_index.get(&old_divergent_path).is_none(),
        "R-13: cap MUST NOT be bound at the pre-Round-7 divergent path"
    );

    // EXTENSION-IDENTITY v3.6 (I-7): the granter's self-signature MUST
    // be bound at the V7 invariant pointer path
    // `/{granter_peer_id}/system/signature/{cap_content_hash_hex}` —
    // NOT the v3.5 PI-10 `{cap_path}/signature` sibling-path convention,
    // which v3.6 removed. Downstream chain validation discovers cap
    // signatures at the invariant pointer via `find_signature_by_signer`.
    let sig_path = format!(
        "/{}/system/signature/{}",
        h.local_peer_id,
        entity_attestation::hex_segment(&bound_cap_hash)
    );
    let sig_hash_bound = h
        .location_index
        .get(&sig_path)
        .expect("v3.6 I-7: cap signature MUST be bound at V7 invariant pointer path");
    let sig_entity = h
        .content_store
        .get(&sig_hash_bound)
        .expect("sig entity in store");
    assert_eq!(
        sig_entity.entity_type, "system/signature",
        "v3.6 I-7: bound entity at invariant pointer path MUST be system/signature"
    );
    // v3.6 I-7: the old sibling path MUST NOT carry the binding.
    let old_sibling_path = format!("{}/signature", canonical_cap_path);
    assert!(
        h.location_index.get(&old_sibling_path).is_none(),
        "v3.6 I-7: cap signature MUST NOT be bound at the v3.5 PI-10 sibling path"
    );
}

/// R-12 (cross-impl spec, Round 7): `:revoke_attestation`
/// MUST create a `kind=revocation` attestation entity (per
/// EXTENSION-ATTESTATION §6.3 + EXTENSION-IDENTITY §6 / Go's
/// `handleRevokeAttestation` ext/identity/ops.go:147–...). Pre-R-12 Rust
/// just removed a tree binding — that's neither the spec wire shape
/// (`{target_hash, reason?}` not `{resource: path}`) nor the right
/// semantics (revocation is an attestation, not a remove).
#[tokio::test]
async fn pr12_revoke_attestation_creates_revocation_entity() {
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    h.add_peer("k3", 12);
    h.add_peer("ctrl", 20);
    let q_hash = h.add_quorum(&["k1", "k2", "k3"], 2);
    h.identity_hashes.insert("quorum".into(), q_hash);
    h.keypairs.insert("quorum".into(), Keypair::from_seed([99u8; 32]));
    let target_cert = h.add_identity_cert(
        "quorum",
        "ctrl",
        "controller",
        "public",
        &["k1", "k2"],
        None,
    );

    // Wire shape: `{target_hash, reason?}`. NO resource target.
    let handler = h.handler();
    let params = to_ecf(&Value::Map(vec![
        (text("reason"), text("test rotation cleanup")),
        (
            text("target_hash"),
            Value::Bytes(target_cert.to_bytes().to_vec()),
        ),
    ]));
    let ctx = build_ctx(&handler, "revoke_attestation", None, params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_eq!(
        result.status, STATUS_OK,
        "R-12: revoke_attestation must succeed with target_hash + reason; got {}: {}",
        result.status,
        String::from_utf8_lossy(&result.result.data)
    );

    // R-12: a `kind=revocation` attestation MUST be in the index targeting
    // the original cert (attesting=quorum, attested=target_hash).
    let rev_hashes = h.attestation_index.lookup_by_attested(&target_cert);
    let (rev_hash_in_index, rev) = rev_hashes
        .iter()
        .find_map(|rh| {
            let r = h.attestation_index.get(rh)?;
            if r.kind() == Some("revocation") {
                Some((*rh, r))
            } else {
                None
            }
        })
        .expect("R-12: revocation attestation MUST exist in the index");
    assert_eq!(rev.attesting, q_hash, "R-12: revocation.attesting MUST be quorum_id");
    assert_eq!(rev.attested, target_cert, "R-12: revocation.attested MUST be target_hash");

    // R-12' (cross-impl spec, Round 8): the result entity
    // MUST carry a non-zero `revocation_hash` field equal to the minted
    // revocation entity's content_hash. Pre-R-12' Rust returned `{}`
    // (empty map), which broke Go's test assertion on `revResult.RevocationHash`.
    let result_value: ciborium::Value =
        ciborium::from_reader(result.result.data.as_slice()).expect("decode result");
    let result_map = result_value.as_map().expect("result is a map");
    let result_rev_hash_bytes = result_map
        .iter()
        .find_map(|(k, v)| if k.as_text() == Some("revocation_hash") { v.as_bytes() } else { None })
        .expect("R-12': result MUST carry `revocation_hash` field");
    let result_rev_hash =
        Hash::from_bytes(result_rev_hash_bytes).expect("decode revocation_hash");
    assert_eq!(
        result_rev_hash, rev_hash_in_index,
        "R-12': result.revocation_hash MUST equal the indexed revocation entity's hash"
    );
}

/// R-12 negative: revoke with target_hash that's not in the index returns
/// 404 target_not_found.
#[tokio::test]
async fn pr12_revoke_attestation_404_when_target_missing() {
    let mut h = Harness::new();
    h.add_peer("ctrl", 20);
    let phantom = Hash::compute("test", b"phantom-target");
    let handler = h.handler();
    let params = to_ecf(&Value::Map(vec![
        (text("target_hash"), Value::Bytes(phantom.to_bytes().to_vec())),
    ]));
    let ctx = build_ctx(&handler, "revoke_attestation", None, params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_eq!(
        result.status, 404,
        "R-12: revoke with unknown target MUST 404"
    );
}

/// R-7 negative: `:configure` with no live controller-cert under the
/// trusted quorum MUST return 404 `no_live_controller`. Locks in the
/// spec line 880 contract for post-revocation re-runs (and the freshly-
/// configured-with-no-cert edge case).
#[tokio::test]
async fn pr7_configure_404_when_no_live_controller_under_quorum() {
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    let q_hash = h.add_quorum(&["k1", "k2"], 2);
    h.identity_hashes.insert("quorum".into(), q_hash);

    // No controller-cert created — bare quorum.
    let handler = h.handler();
    let pc_path = h.qualify(crate::paths::PATH_PEER_CONFIG);
    let params = to_ecf(&Value::Map(vec![
        (text("bindings"), Value::Array(vec![])),
        (text("controller_grants"), Value::Array(vec![])),
        (text("trusts_quorum"), Value::Bytes(q_hash.to_bytes().to_vec())),
    ]));
    let ctx = build_ctx(&handler, "configure", Some(&pc_path), params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_eq!(
        result.status, 404,
        "R-7: zero live controllers MUST return 404 no_live_controller"
    );
}

/// R-10 (cross-impl spec): `:configure` with bindings
/// MUST validate per spec §6.1 / PR-8.4. Three error subcodes:
/// - 400 `binding_missing_handle_cert` / `binding_missing_agent_cert` for zero hash
/// - 404 `binding_cert_not_found` for unresolvable hash
/// - 400 `binding_cert_wrong_kind` for resolved entity with wrong kind/function
/// Happy-path: handle_cert (function=controller) + agent_cert (function=agent),
/// both signed and live → 200 with caps.
#[tokio::test]
async fn pr10_configure_with_bindings_happy_path() {
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    h.add_peer("k3", 12);
    h.add_peer("ctrl", 20);
    h.add_peer("agent", 30);

    let q_hash = h.add_quorum(&["k1", "k2", "k3"], 2);
    h.identity_hashes.insert("quorum".into(), q_hash);
    h.keypairs.insert("quorum".into(), Keypair::from_seed([99u8; 32]));
    let ctrl_cert = h.add_identity_cert("quorum", "ctrl", "controller", "public", &["k1", "k2"], None);
    let agent_cert = h.add_identity_cert("ctrl", "agent", "agent", "internal", &["ctrl"], None);

    let handler = h.handler();
    let pc_path = h.qualify(crate::paths::PATH_PEER_CONFIG);
    let binding = Value::Map(vec![
        (text("agent_cert"), Value::Bytes(agent_cert.to_bytes().to_vec())),
        (text("handle_cert"), Value::Bytes(ctrl_cert.to_bytes().to_vec())),
    ]);
    let params = to_ecf(&Value::Map(vec![
        (text("bindings"), Value::Array(vec![binding])),
        (text("controller_grants"), Value::Array(vec![])),
        (text("trusts_quorum"), Value::Bytes(q_hash.to_bytes().to_vec())),
    ]));
    let ctx = build_ctx(&handler, "configure", Some(&pc_path), params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_eq!(
        result.status, STATUS_OK,
        "R-10: bindings happy path must succeed; got {}",
        result.status
    );
}

/// PI-2 (PROPOSAL-IDENTITY-COMPOSITION-CLEANUP §PI-2, Rev 3): binding
/// referencing a non-live controller is a phase-2 hard error
/// (`400 binding_controller_not_live`). Builds a valid live-controller
/// scenario, then revokes the controller cert before configure runs;
/// the binding's agent_cert.attesting now references a no-longer-live
/// controller's identity → reject.
#[tokio::test]
async fn pi2_binding_controller_not_live_returns_400() {
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    h.add_peer("ctrl", 20);
    h.add_peer("agent", 30);
    h.add_peer("orphan", 40);

    let q_hash = h.add_quorum(&["k1", "k2"], 2);
    h.identity_hashes.insert("quorum".into(), q_hash);
    h.keypairs.insert("quorum".into(), Keypair::from_seed([99u8; 32]));

    // Live controller cert under the trusted quorum.
    let ctrl_cert = h.add_identity_cert("quorum", "ctrl", "controller", "public", &["k1", "k2"], None);
    // Agent cert chains under a DIFFERENT (non-live) identity — `orphan`
    // is a peer with no controller cert under the trusted quorum.
    // Manually-constructed AttestationData since add_identity_cert would
    // chain it through `ctrl` (live).
    let orphan = h.peer("orphan");
    let agent = h.peer("agent");
    let agent_cert_data = AttestationData {
        attesting: orphan,
        attested: agent,
        properties: vec![
            (text("function"), text("agent")),
            (text("kind"), text(KIND_IDENTITY_CERT)),
            (text("mode"), text("internal")),
        ],
        supersedes: None,
        not_before: None,
        expires_at: None,
    };
    let agent_cert_entity = agent_cert_data.to_entity().unwrap();
    let agent_cert = agent_cert_entity.content_hash;
    h.content_store.put(agent_cert_entity).unwrap();
    h.attestation_index.insert(agent_cert, agent_cert_data);
    let agent_cert_path = h.qualify(&path_internal_cert(&agent_cert));
    h.location_index.set(&agent_cert_path, agent_cert);
    h.sign_with(&agent_cert, &["orphan"]);

    let handler = h.handler();
    let pc_path = h.qualify(crate::paths::PATH_PEER_CONFIG);
    let binding = Value::Map(vec![
        (text("agent_cert"), Value::Bytes(agent_cert.to_bytes().to_vec())),
        (text("handle_cert"), Value::Bytes(ctrl_cert.to_bytes().to_vec())),
    ]);
    let params = to_ecf(&Value::Map(vec![
        (text("bindings"), Value::Array(vec![binding])),
        (text("controller_grants"), Value::Array(vec![])),
        (text("trusts_quorum"), Value::Bytes(q_hash.to_bytes().to_vec())),
    ]));
    let ctx = build_ctx(&handler, "configure", Some(&pc_path), params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_eq!(result.status, 400, "PI-2: non-live controller binding MUST 400");

    // Verify the error code is `binding_controller_not_live`.
    let result_value: ciborium::Value =
        ciborium::from_reader(result.result.data.as_slice()).expect("decode result");
    let result_map = result_value.as_map().expect("error map");
    let code = result_map
        .iter()
        .find_map(|(k, v)| if k.as_text() == Some("code") { v.as_text() } else { None })
        .unwrap_or("");
    assert_eq!(
        code, "binding_controller_not_live",
        "PI-2: error code MUST be `binding_controller_not_live`"
    );
}

/// R-10 negative: zero handle_cert hash → 400 `binding_missing_handle_cert`.
#[tokio::test]
async fn pr10_binding_zero_handle_cert_returns_400_missing() {
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    h.add_peer("ctrl", 20);
    h.add_peer("agent", 30);
    let q_hash = h.add_quorum(&["k1", "k2"], 2);
    h.identity_hashes.insert("quorum".into(), q_hash);
    h.keypairs.insert("quorum".into(), Keypair::from_seed([99u8; 32]));
    let _ = h.add_identity_cert("quorum", "ctrl", "controller", "public", &["k1", "k2"], None);
    let agent_cert = h.add_identity_cert("ctrl", "agent", "agent", "internal", &["ctrl"], None);

    let handler = h.handler();
    let pc_path = h.qualify(crate::paths::PATH_PEER_CONFIG);
    let binding = Value::Map(vec![
        (text("agent_cert"), Value::Bytes(agent_cert.to_bytes().to_vec())),
        (
            text("handle_cert"),
            Value::Bytes(Hash::zero().to_bytes().to_vec()),
        ),
    ]);
    let params = to_ecf(&Value::Map(vec![
        (text("bindings"), Value::Array(vec![binding])),
        (text("controller_grants"), Value::Array(vec![])),
        (text("trusts_quorum"), Value::Bytes(q_hash.to_bytes().to_vec())),
    ]));
    let ctx = build_ctx(&handler, "configure", Some(&pc_path), params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_eq!(result.status, 400, "R-10: zero handle_cert MUST return 400");
}

/// R-10 negative: handle_cert hash that doesn't resolve → 404 `binding_cert_not_found`.
#[tokio::test]
async fn pr10_binding_unresolvable_handle_cert_returns_404() {
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    h.add_peer("ctrl", 20);
    h.add_peer("agent", 30);
    let q_hash = h.add_quorum(&["k1", "k2"], 2);
    h.identity_hashes.insert("quorum".into(), q_hash);
    h.keypairs.insert("quorum".into(), Keypair::from_seed([99u8; 32]));
    let _ = h.add_identity_cert("quorum", "ctrl", "controller", "public", &["k1", "k2"], None);
    let agent_cert = h.add_identity_cert("ctrl", "agent", "agent", "internal", &["ctrl"], None);

    let phantom = Hash::compute("test", b"phantom-handle-cert-not-in-store");
    let handler = h.handler();
    let pc_path = h.qualify(crate::paths::PATH_PEER_CONFIG);
    let binding = Value::Map(vec![
        (text("agent_cert"), Value::Bytes(agent_cert.to_bytes().to_vec())),
        (text("handle_cert"), Value::Bytes(phantom.to_bytes().to_vec())),
    ]);
    let params = to_ecf(&Value::Map(vec![
        (text("bindings"), Value::Array(vec![binding])),
        (text("controller_grants"), Value::Array(vec![])),
        (text("trusts_quorum"), Value::Bytes(q_hash.to_bytes().to_vec())),
    ]));
    let ctx = build_ctx(&handler, "configure", Some(&pc_path), params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_eq!(
        result.status, 404,
        "R-10: unresolvable handle_cert MUST return 404 binding_cert_not_found"
    );
}

/// R-10 negative: handle_cert resolves but is wrong function (e.g., agent
/// instead of controller/identifier) → 400 `binding_cert_wrong_kind`.
#[tokio::test]
async fn pr10_binding_wrong_function_returns_400_wrong_kind() {
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    h.add_peer("ctrl", 20);
    h.add_peer("agent", 30);
    h.add_peer("agent2", 31);
    let q_hash = h.add_quorum(&["k1", "k2"], 2);
    h.identity_hashes.insert("quorum".into(), q_hash);
    h.keypairs.insert("quorum".into(), Keypair::from_seed([99u8; 32]));
    let _ = h.add_identity_cert("quorum", "ctrl", "controller", "public", &["k1", "k2"], None);
    // Two agent certs; we'll put an agent cert in the handle_cert slot
    // (wrong function — handle_cert should be controller or identifier).
    let agent_cert_a = h.add_identity_cert("ctrl", "agent", "agent", "internal", &["ctrl"], None);
    let agent_cert_b = h.add_identity_cert("ctrl", "agent2", "agent", "internal", &["ctrl"], None);

    let handler = h.handler();
    let pc_path = h.qualify(crate::paths::PATH_PEER_CONFIG);
    let binding = Value::Map(vec![
        (text("agent_cert"), Value::Bytes(agent_cert_a.to_bytes().to_vec())),
        (text("handle_cert"), Value::Bytes(agent_cert_b.to_bytes().to_vec())),
    ]);
    let params = to_ecf(&Value::Map(vec![
        (text("bindings"), Value::Array(vec![binding])),
        (text("controller_grants"), Value::Array(vec![])),
        (text("trusts_quorum"), Value::Bytes(q_hash.to_bytes().to_vec())),
    ]));
    let ctx = build_ctx(&handler, "configure", Some(&pc_path), params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_eq!(
        result.status, 400,
        "R-10: wrong-function handle_cert MUST return 400 binding_cert_wrong_kind"
    );
}

/// R-8 (cross-impl spec): `:supersede_attestation` aligns
/// with EXTENSION-ATTESTATION §6.1 flat AttestationData wire shape (Go's
/// reference impl). Pre-R-8 Rust expected `{previous_hash, ...}` (per §6.2's
/// inconsistent pseudo-spec), causing 400 invalid_params on Go-sent requests.
/// Wire shape: `{attesting, attested, supersedes, properties?, not_before?,
/// expires_at?}` where `supersedes` references the predecessor.
#[tokio::test]
async fn pr8_supersede_attestation_succeeds_with_attestation_data_shape() {
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    h.add_peer("k3", 12);
    h.add_peer("ctrl", 20);
    let q_hash = h.add_quorum(&["k1", "k2", "k3"], 2);
    h.identity_hashes.insert("quorum".into(), q_hash);
    h.keypairs.insert("quorum".into(), Keypair::from_seed([99u8; 32]));
    let ctrl_cert = h.add_identity_cert("quorum", "ctrl", "controller", "public", &["k1", "k2"], None);
    let predecessor = h.attestation_index.get(&ctrl_cert).unwrap();

    let handler = h.handler();
    let params = to_ecf(&Value::Map(vec![
        (text("attested"), Value::Bytes(predecessor.attested.to_bytes().to_vec())),
        (text("attesting"), Value::Bytes(predecessor.attesting.to_bytes().to_vec())),
        (text("supersedes"), Value::Bytes(ctrl_cert.to_bytes().to_vec())),
    ]));
    let ctx = build_ctx(&handler, "supersede_attestation", None, params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_eq!(
        result.status, STATUS_OK,
        "R-8: supersede with §6.1 AttestationData shape MUST succeed; got {}",
        result.status
    );
    assert_eq!(
        result.result.entity_type,
        "system/identity/supersede-attestation-result"
    );
}

/// R-8' (Round-6 reframe): identity supersede MUST allow `attested` to
/// change (controller rotation legitimately points the cert at a new key).
/// Pre-R-8' Rust enforced strict §6.2 attested-match, which made
/// controller_rotation impossible. Go's `handleSupersedeAttestation`
/// validates only KIND match, not attesting/attested.
#[tokio::test]
async fn pr8_prime_supersede_allows_attested_change_for_rotation() {
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    h.add_peer("k3", 12);
    h.add_peer("ctrl_old", 20);
    h.add_peer("ctrl_new", 21);
    let q_hash = h.add_quorum(&["k1", "k2", "k3"], 2);
    h.identity_hashes.insert("quorum".into(), q_hash);
    h.keypairs.insert("quorum".into(), Keypair::from_seed([99u8; 32]));

    // OLD controller cert, K-of-N signed.
    let old_cert = h.add_identity_cert(
        "quorum",
        "ctrl_old",
        "controller",
        "public",
        &["k1", "k2"],
        None,
    );
    let predecessor = h.attestation_index.get(&old_cert).unwrap();
    let new_ctrl = h.peer("ctrl_new");

    // Supersede with NEW attested (controller rotation). Properties retain
    // the same kind=identity-cert, function=controller, mode=public.
    let handler = h.handler();
    let new_props = Value::Map(vec![
        (text("function"), text("controller")),
        (text("kind"), text(KIND_IDENTITY_CERT)),
        (text("mode"), text("public")),
    ]);
    let params = to_ecf(&Value::Map(vec![
        (text("attested"), Value::Bytes(new_ctrl.to_bytes().to_vec())),
        (text("attesting"), Value::Bytes(predecessor.attesting.to_bytes().to_vec())),
        (text("properties"), new_props),
        (text("supersedes"), Value::Bytes(old_cert.to_bytes().to_vec())),
    ]));
    let ctx = build_ctx(&handler, "supersede_attestation", None, params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_eq!(
        result.status, STATUS_OK,
        "R-8': supersede MUST allow attested-change for controller rotation; got {}: {}",
        result.status,
        String::from_utf8_lossy(&result.result.data)
    );
}

/// R-8' kind-match: predecessor and successor MUST share `properties.kind`.
/// Crossing kinds via supersede is a structural error (e.g., identity-cert
/// can't supersede an identity-rotation-recovery).
#[tokio::test]
async fn pr8_prime_supersede_rejects_kind_mismatch() {
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    h.add_peer("ctrl", 20);
    let q_hash = h.add_quorum(&["k1", "k2"], 2);
    h.identity_hashes.insert("quorum".into(), q_hash);
    h.keypairs.insert("quorum".into(), Keypair::from_seed([99u8; 32]));
    let ctrl_cert = h.add_identity_cert("quorum", "ctrl", "controller", "public", &["k1", "k2"], None);
    let predecessor = h.attestation_index.get(&ctrl_cert).unwrap();

    let handler = h.handler();
    // Supersede with a different kind (rotation-recovery) — should reject.
    let bad_props = Value::Map(vec![
        (text("kind"), text(crate::kinds::KIND_IDENTITY_ROTATION_RECOVERY)),
    ]);
    let params = to_ecf(&Value::Map(vec![
        (text("attested"), Value::Bytes(predecessor.attested.to_bytes().to_vec())),
        (text("attesting"), Value::Bytes(predecessor.attesting.to_bytes().to_vec())),
        (text("properties"), bad_props),
        (text("supersedes"), Value::Bytes(ctrl_cert.to_bytes().to_vec())),
    ]));
    let ctx = build_ctx(&handler, "supersede_attestation", None, params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_eq!(result.status, 400, "R-8': kind mismatch MUST 400");
}

/// PI-1 (PROPOSAL-IDENTITY-COMPOSITION-CLEANUP §PI-1, Rev 3):
/// `:supersede_attestation` for non-REBIND_KINDS preserves predecessor's
/// attesting/attested per substrate `:supersede` semantics. Caller-supplied
/// attesting/attested fields are IGNORED (the new attestation inherits
/// from the predecessor). Only properties + bounds may change.
///
/// Test scenario: kind=identity-rotation-recovery (NOT in REBIND_KINDS).
/// Caller passes bogus attesting/attested; the new attestation MUST keep
/// the predecessor's fields.
#[tokio::test]
async fn pi1_supersede_non_rebind_kind_preserves_attesting_attested() {
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    h.add_peer("ctrl", 20);
    h.add_peer("new_ctrl", 21);
    h.add_peer("other", 30);
    let q_hash = h.add_quorum(&["k1", "k2"], 2);
    h.identity_hashes.insert("quorum".into(), q_hash);
    h.keypairs.insert("quorum".into(), Keypair::from_seed([99u8; 32]));

    // Pre-build a controller cert (target of the rotation) and a
    // rotation-recovery predecessor pointing to it.
    let target_cert = h.add_identity_cert(
        "quorum", "ctrl", "controller", "public", &["k1", "k2"], None,
    );
    let new_ctrl = h.peer("new_ctrl");
    let old_handle = h.peer("ctrl");
    let (prev_hash, prev_data) = h.add_rotation_recovery(
        q_hash, new_ctrl, target_cert, old_handle, &["k1", "k2"],
    );

    let handler = h.handler();

    // Supersede with bogus attesting/attested. Per PI-1 non-rebind path,
    // these caller-supplied values MUST be ignored.
    let bogus = h.peer("other");
    let new_props = Value::Map(vec![
        (text("kind"), text(crate::kinds::KIND_IDENTITY_ROTATION_RECOVERY)),
        (text("old_handle"), Value::Bytes(old_handle.to_bytes().to_vec())),
        (text("target_cert"), Value::Bytes(target_cert.to_bytes().to_vec())),
    ]);
    let params = to_ecf(&Value::Map(vec![
        (text("attested"), Value::Bytes(bogus.to_bytes().to_vec())),
        (text("attesting"), Value::Bytes(bogus.to_bytes().to_vec())),
        (text("properties"), new_props),
        (text("supersedes"), Value::Bytes(prev_hash.to_bytes().to_vec())),
    ]));
    let ctx = build_ctx(&handler, "supersede_attestation", None, params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_eq!(
        result.status, 200,
        "PI-1: non-rebind supersede must succeed (got status {})",
        result.status
    );

    // Decode result; resolve the new entity; verify attesting/attested
    // came from the predecessor, NOT the caller-supplied bogus fields.
    let result_value: ciborium::Value =
        ciborium::from_reader(result.result.data.as_slice()).expect("decode result");
    let result_map = result_value.as_map().expect("result map");
    let new_hash_bytes = result_map
        .iter()
        .find_map(|(k, v)| if k.as_text() == Some("attestation_hash") { v.as_bytes() } else { None })
        .expect("attestation_hash");
    let new_hash = Hash::from_bytes(new_hash_bytes).expect("hash bytes");
    let new_att = h.attestation_index.get(&new_hash).expect("new attestation");
    assert_eq!(
        new_att.attesting, prev_data.attesting,
        "PI-1: non-rebind kind MUST preserve attesting from predecessor"
    );
    assert_eq!(
        new_att.attested, prev_data.attested,
        "PI-1: non-rebind kind MUST preserve attested from predecessor"
    );
}

/// R-11 (cross-impl spec, Round 6): `:publish_attestation`
/// is a path-MOVE, not a duplicate. After `:publish_attestation` from
/// internal → public, the OLD internal-cert path MUST be unbound. Pre-R-11
/// Rust left the old binding in place, violating the audience-separation
/// invariant (internal cert discoverable at the internal path post-publish).
#[tokio::test]
async fn pr11_publish_attestation_moves_does_not_duplicate() {
    let mut h = Harness::new();
    h.add_peer("ctrl", 20);
    h.add_peer("agent", 30);
    let handler = h.handler();
    let _ = h.peer("ctrl");
    let _ = h.peer("agent");

    // Pre-bind an internal-mode agent cert.
    let cert_hash = h.add_identity_cert("ctrl", "agent", "agent", "internal", &["ctrl"], None);

    // Verify the cert is bound at the internal path.
    let internal_path = h.qualify(&crate::paths::path_internal_cert(&cert_hash));
    assert!(
        h.location_index.get(&internal_path).is_some(),
        "precondition: cert bound at internal path"
    );

    // Dispatch :publish_attestation to promote internal → public.
    let params = to_ecf(&Value::Map(vec![
        (
            text("attestation_hash"),
            Value::Bytes(cert_hash.to_bytes().to_vec()),
        ),
        (text("new_mode"), text("public")),
    ]));
    let ctx = build_ctx(&handler, "publish_attestation", None, params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_eq!(result.status, STATUS_OK);

    // Cert is bound at the new public path.
    let public_path = h.qualify(&crate::paths::path_public_cert(&cert_hash));
    assert!(
        h.location_index.get(&public_path).is_some(),
        "R-11: cert MUST be bound at the new public path"
    );

    // R-11: cert MUST be UNBOUND at the old internal path (move semantics).
    assert!(
        h.location_index.get(&internal_path).is_none(),
        "R-11: cert MUST be unbound at the old internal path post-publish (move, not copy)"
    );
}

/// R-9 (cross-impl spec): `:publish_attestation` result
/// field name is `new_path`, NOT `storage_path`. Pre-R-9 Rust emitted
/// `storage_path`, causing Go's `IdentityPublishAttestationResultData.NewPath`
/// to decode to empty string. The publish op is the path-move primitive;
/// `new_path` is the post-move canonical destination.
#[tokio::test]
async fn publish_attestation_result_uses_new_path_field() {
    let mut h = Harness::new();
    h.add_peer("ctrl", 20);
    h.add_peer("agent", 30);
    let handler = h.handler();
    let ctrl = h.peer("ctrl");
    let agent = h.peer("agent");

    // Pre-bind an internal-mode agent cert. (publish promotes/demotes
    // between modes; agent function is the only kind allowed to publish
    // per §6 — the publish gate filters at function=agent.)
    let cert_hash = h.add_identity_cert("ctrl", "agent", "agent", "internal", &["ctrl"], None);
    let _ = ctrl;
    let _ = agent;

    // Dispatch :publish_attestation to promote internal → public.
    let params = to_ecf(&Value::Map(vec![
        (
            text("attestation_hash"),
            Value::Bytes(cert_hash.to_bytes().to_vec()),
        ),
        (text("new_mode"), text("public")),
    ]));
    let ctx = build_ctx(&handler, "publish_attestation", None, params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_eq!(result.status, STATUS_OK, "publish_attestation must succeed");
    assert_eq!(
        result.result.entity_type,
        "system/identity/publish-attestation-result"
    );

    // Decode result and confirm `new_path` is populated, `storage_path` absent.
    let result_value: ciborium::Value =
        ciborium::from_reader(result.result.data.as_slice()).expect("decode result");
    let result_map = result_value.as_map().expect("result map");
    let new_path = result_map
        .iter()
        .find_map(|(k, v)| if k.as_text() == Some("new_path") { v.as_text() } else { None })
        .expect("R-9: result MUST carry `new_path` field");
    assert!(
        new_path.contains("system/identity/public/cert/"),
        "R-9: new_path must be the canonical post-move path, got {}",
        new_path
    );
    assert!(
        result_map.iter().all(|(k, _)| k.as_text() != Some("storage_path")),
        "R-9: result MUST NOT carry `storage_path` (renamed to `new_path`)"
    );
}

/// R-1 negative: pre-R-1 Rust silently accepted top-level `kind`. Lock in
/// the new strict behavior — kind at top level (instead of nested under
/// `properties`) MUST return 400 invalid_params for clarity.
#[tokio::test]
async fn create_attestation_rejects_flat_top_level_kind() {
    let mut h = Harness::new();
    h.add_peer("ctrl", 20);
    h.add_peer("agent", 30);
    let handler = h.handler();
    let ctrl = h.peer("ctrl");
    let agent = h.peer("agent");
    let params = to_ecf(&Value::Map(vec![
        (text("attested"), Value::Bytes(agent.to_bytes().to_vec())),
        (text("attesting"), Value::Bytes(ctrl.to_bytes().to_vec())),
        // kind / function / mode at TOP level — pre-R-1 shape, now invalid.
        (text("function"), text("agent")),
        (text("kind"), text(KIND_IDENTITY_CERT)),
        (text("mode"), text("internal")),
    ]));
    let ctx = build_ctx(&handler, "create_attestation", None, params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_eq!(
        result.status, 400,
        "R-1: flat top-level kind/mode/function MUST be rejected"
    );
}

#[tokio::test]
async fn process_attestation_validates_then_succeeds() {
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    h.add_peer("k3", 12);
    h.add_peer("ctrl", 20);
    let q_hash = h.add_quorum(&["k1", "k2", "k3"], 2);
    h.identity_hashes.insert("quorum".into(), q_hash);
    h.keypairs.insert("quorum".into(), Keypair::from_seed([99u8; 32]));
    let cert_hash = h.add_identity_cert(
        "quorum",
        "ctrl",
        "controller",
        "public",
        &["k1", "k2"],
        None,
    );
    let handler = h.handler();
    let params = to_ecf(&Value::Map(vec![(
        text("attestation_hash"),
        Value::Bytes(cert_hash.to_bytes().to_vec()),
    )]));
    let ctx = build_ctx(&handler, "process_attestation", None, params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_eq!(result.status, STATUS_OK, "process_attestation should succeed");
}

// ===========================================================================
// §9.4 fail-closed compromise-recovery
// ===========================================================================

#[tokio::test]
async fn rotation_recovery_fails_closed_without_cached_quorum_publish() {
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    h.add_peer("k3", 12);
    h.add_peer("ctrl_old", 20);
    h.add_peer("ctrl_new", 21);
    let q_hash = h.add_quorum(&["k1", "k2", "k3"], 2);
    h.identity_hashes.insert("quorum".into(), q_hash);
    h.keypairs.insert("quorum".into(), Keypair::from_seed([99u8; 32]));
    let target_cert = h.add_identity_cert(
        "quorum",
        "ctrl_old",
        "controller",
        "public",
        &["k1", "k2"],
        None,
    );
    let old_handle = h.peer("ctrl_old");
    let new_key = h.peer("ctrl_new");
    let (recovery_hash, _) =
        h.add_rotation_recovery(q_hash, new_key, target_cert, old_handle, &["k1", "k2"]);
    let handler = h.handler();
    let params = to_ecf(&Value::Map(vec![(
        text("attestation_hash"),
        Value::Bytes(recovery_hash.to_bytes().to_vec()),
    )]));
    let ctx = build_ctx(&handler, "process_attestation", None, params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_ne!(
        result.status, STATUS_OK,
        "recovery without cached quorum-publish must fail-closed (§9.4)"
    );
}

#[tokio::test]
async fn rotation_recovery_succeeds_with_cached_quorum_publish() {
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    h.add_peer("k3", 12);
    h.add_peer("ctrl_old", 20);
    h.add_peer("ctrl_new", 21);
    let q_hash = h.add_quorum(&["k1", "k2", "k3"], 2);
    h.identity_hashes.insert("quorum".into(), q_hash);
    h.keypairs.insert("quorum".into(), Keypair::from_seed([99u8; 32]));
    let target_cert = h.add_identity_cert(
        "quorum",
        "ctrl_old",
        "controller",
        "public",
        &["k1", "k2"],
        None,
    );
    let old_handle = h.peer("ctrl_old");
    // Seed the contact-quorum cache with a quorum-publish.
    h.add_quorum_publish_cache(q_hash, &["k1", "k2", "k3"], 2, old_handle, &["k1", "k2"]);
    let new_key = h.peer("ctrl_new");
    let (recovery_hash, _) =
        h.add_rotation_recovery(q_hash, new_key, target_cert, old_handle, &["k1", "k2"]);
    let handler = h.handler();
    let params = to_ecf(&Value::Map(vec![(
        text("attestation_hash"),
        Value::Bytes(recovery_hash.to_bytes().to_vec()),
    )]));
    let ctx = build_ctx(&handler, "process_attestation", None, params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_eq!(
        result.status, STATUS_OK,
        "recovery with cached quorum-publish should succeed"
    );
}

// ===========================================================================
// PI-5 (PROPOSAL-IDENTITY-COMPOSITION-CLEANUP §PI-5, Rev 3): controller-
// events stream. v2 scope = failure-only emission. When a phase-2 handler
// fails (e.g., retirement with target_cert pointing to a missing entity),
// a `system/identity/event` entity MUST be bound at
// `system/identity/events/{ts}/{handler_id}/{att_hash}/{event_hash}`
// with `event_subkind = "failure_observation"`.
// ===========================================================================

#[tokio::test]
async fn pi5_process_attestation_emits_failure_observation_on_handler_failure() {
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    h.add_peer("ctrl", 20);
    h.add_peer("retired", 21);
    let q_hash = h.add_quorum(&["k1", "k2"], 2);
    h.identity_hashes.insert("quorum".into(), q_hash);
    h.keypairs.insert("quorum".into(), Keypair::from_seed([99u8; 32]));

    // Build a retirement attestation pointing at a target_cert hash that
    // is NOT in the attestation index — handler will emit a
    // failure-observation event.
    let bogus_target = Hash::compute("test/missing", b"target");
    let _ctrl_cert = h.add_identity_cert("quorum", "ctrl", "controller", "public", &["k1", "k2"], None);

    let retirement = AttestationData {
        attesting: q_hash,
        attested: h.peer("retired"),
        properties: {
            let mut p: Vec<(Value, Value)> = vec![
                (text("kind"), text(crate::kinds::KIND_IDENTITY_RETIREMENT)),
                (text("target_cert"), Value::Bytes(bogus_target.to_bytes().to_vec())),
            ];
            p.sort_by(|a, b| a.0.as_text().unwrap_or("").cmp(b.0.as_text().unwrap_or("")));
            p
        },
        supersedes: None,
        not_before: None,
        expires_at: None,
    };
    let entity = retirement.to_entity().unwrap();
    let retirement_hash = entity.content_hash;
    h.content_store.put(entity).unwrap();
    h.attestation_index.insert(retirement_hash, retirement);
    h.sign_with(&retirement_hash, &["k1", "k2"]);

    // Snapshot event-stream count before dispatch.
    let events_prefix = h.qualify("system/identity/events/");
    let before: Vec<String> = h.location_index
        .list(&events_prefix)
        .into_iter()
        .map(|e| e.path)
        .collect();

    let handler = h.handler();
    let params = to_ecf(&Value::Map(vec![(
        text("attestation_hash"),
        Value::Bytes(retirement_hash.to_bytes().to_vec()),
    )]));
    let ctx = build_ctx(&handler, "process_attestation", None, params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    // Phase 1 (validate) passes for retirement (kind-only sig check); the
    // failure happens in Phase 2 (target_cert lookup), which doesn't
    // propagate to the response status. v2 scope: phase-2 failures emit
    // events, return ok at the dispatch level.
    assert_eq!(result.status, STATUS_OK, "process_attestation phase-2 failures emit events; status stays OK");

    // Check the events stream picked up an entry for this retirement.
    let after = h.location_index.list(&events_prefix);
    let new_entries: Vec<&entity_store::LocationEntry> = after
        .iter()
        .filter(|e| !before.contains(&e.path))
        .collect();
    assert!(
        !new_entries.is_empty(),
        "PI-5: phase-2 handler failure MUST emit a controller-event"
    );
    let event_entry = new_entries[0];
    assert!(
        event_entry.path.contains("/revoke_local_caps_for_attested/"),
        "PI-5: event path should embed the handler_id; got {}",
        event_entry.path
    );

    // Read the event entity and check event_subkind = "failure_observation".
    let event_entity = h.content_store.get(&event_entry.hash).expect("event entity in store");
    assert_eq!(event_entity.entity_type, entity_types::TYPE_IDENTITY_EVENT);
    let value: ciborium::Value =
        ciborium::from_reader(event_entity.data.as_slice()).expect("decode event");
    let event_map = value.as_map().expect("event is map");
    let subkind = event_map
        .iter()
        .find_map(|(k, v)| if k.as_text() == Some("event_subkind") { v.as_text() } else { None })
        .unwrap_or("");
    assert_eq!(
        subkind, "failure_observation",
        "PI-5: phase-2 handler failures MUST be tagged failure_observation"
    );
}

// ===========================================================================
// PI-13 (PROPOSAL-IDENTITY-COMPOSITION-CLEANUP §PI-13, Rev 3): revoke
// cascade-by-default. When :revoke_attestation succeeds against a
// controller cert, the implementation MUST cascade cap cleanup:
// walk `system/capability/grants/identity/peer-to-controller/*` and
// unbind caps whose grantee matches the revoked controller's `attested`,
// AND unbind their cap signatures at the V7 invariant pointer path
// (EXTENSION-IDENTITY v3.6, I-7).
// ===========================================================================

#[tokio::test]
async fn pi13_revoke_attestation_cascades_cap_and_signature() {
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    h.add_peer("ctrl", 20);
    let q_hash = h.add_quorum(&["k1", "k2"], 2);
    h.identity_hashes.insert("quorum".into(), q_hash);
    h.keypairs.insert("quorum".into(), Keypair::from_seed([99u8; 32]));

    // Build live controller cert + run :configure to issue + bind cap.
    let _ctrl_cert = h.add_identity_cert(
        "quorum", "ctrl", "controller", "public", &["k1", "k2"], None,
    );
    let handler = h.handler();
    let pc_path = h.qualify(crate::paths::PATH_PEER_CONFIG);
    let configure_params = to_ecf(&Value::Map(vec![
        (text("bindings"), Value::Array(vec![])),
        (text("controller_grants"), Value::Array(vec![])),
        (text("trusts_quorum"), Value::Bytes(q_hash.to_bytes().to_vec())),
    ]));
    let configure_ctx = build_ctx(&handler, "configure", Some(&pc_path), configure_params);
    let configure_result = handler.handle(&configure_ctx).await.expect("configure ok");
    assert_eq!(configure_result.status, STATUS_OK, "configure must succeed");

    // Sanity: cap + signature are bound at canonical paths.
    let ctrl_peer = h.peer("ctrl");
    let cap_path = h.qualify(&format!(
        "system/capability/grants/identity/peer-to-controller/{}",
        entity_attestation::hex_segment(&ctrl_peer)
    ));
    let cap_hash = h.location_index.get(&cap_path).expect("cap bound pre-revoke");
    // v3.6 I-7: signature at invariant pointer path, not sibling.
    let sig_path = format!(
        "/{}/system/signature/{}",
        h.local_peer_id,
        entity_attestation::hex_segment(&cap_hash)
    );
    assert!(h.location_index.get(&sig_path).is_some(), "signature bound at invariant pointer pre-revoke");

    // Locate the controller cert hash for revoke.
    let ctrl_cert = _ctrl_cert;
    // Revoke the controller cert.
    let revoke_params = to_ecf(&Value::Map(vec![
        (text("reason"), text("PI-13 cascade test")),
        (text("target_hash"), Value::Bytes(ctrl_cert.to_bytes().to_vec())),
    ]));
    let revoke_ctx = build_ctx(&handler, "revoke_attestation", None, revoke_params);
    let revoke_result = handler.handle(&revoke_ctx).await.expect("revoke ok");
    assert_eq!(revoke_result.status, STATUS_OK, "revoke must succeed");

    // PI-13: cap entity AND signature MUST be unbound.
    assert!(
        h.location_index.get(&cap_path).is_none(),
        "PI-13: revoke MUST cascade-unbind the cap entity"
    );
    assert!(
        h.location_index.get(&sig_path).is_none(),
        "PI-13: revoke MUST cascade-unbind the cap signature at the invariant pointer path"
    );
}

// ===========================================================================
// PI-11 (PROPOSAL-IDENTITY-COMPOSITION-CLEANUP §PI-11): per-function
// valid-modes enforcement at :create_attestation. Reject (function, mode)
// combinations the §4.2 table doesn't permit with `400
// invalid_mode_for_function`. Error envelope MUST carry `function`,
// `attempted_mode`, and `valid_modes_for_function` (array).
// ===========================================================================

#[tokio::test]
async fn pi11_create_attestation_rejects_identifier_public() {
    // function=identifier MUST be mode=internal only.
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    h.add_peer("ident", 20);
    let q_hash = h.add_quorum(&["k1", "k2"], 2);
    h.identity_hashes.insert("quorum".into(), q_hash);
    h.keypairs.insert("quorum".into(), Keypair::from_seed([99u8; 32]));
    let ident_peer = h.peer("ident");

    let handler = h.handler();
    let props = Value::Map(vec![
        (text("function"), text("identifier")),
        (text("kind"), text(KIND_IDENTITY_CERT)),
        (text("mode"), text("public")),
    ]);
    let params = to_ecf(&Value::Map(vec![
        (text("attested"), Value::Bytes(ident_peer.to_bytes().to_vec())),
        (text("attesting"), Value::Bytes(q_hash.to_bytes().to_vec())),
        (text("properties"), props),
    ]));
    // Resource path doesn't matter — phase 1 should reject.
    let bogus_path = h.qualify("system/identity/public/cert/00");
    let ctx = build_ctx(&handler, "create_attestation", Some(&bogus_path), params);
    let result = handler.handle(&ctx).await.expect("handle ok");
    assert_eq!(
        result.status, 400,
        "PI-11: identifier+public MUST 400 invalid_mode_for_function"
    );

    // Verify error envelope shape.
    let value: ciborium::Value =
        ciborium::from_reader(result.result.data.as_slice()).expect("decode result");
    let map = value.as_map().expect("error map");
    let code = map
        .iter()
        .find_map(|(k, v)| if k.as_text() == Some("code") { v.as_text() } else { None })
        .unwrap_or("");
    assert_eq!(code, "invalid_mode_for_function", "PI-11: error code");

    let function_field = map
        .iter()
        .find_map(|(k, v)| if k.as_text() == Some("function") { v.as_text() } else { None })
        .unwrap_or("");
    assert_eq!(function_field, "identifier", "PI-11: error MUST carry function");

    let attempted = map
        .iter()
        .find_map(|(k, v)| if k.as_text() == Some("attempted_mode") { v.as_text() } else { None })
        .unwrap_or("");
    assert_eq!(attempted, "public", "PI-11: error MUST carry attempted_mode");

    let valid = map
        .iter()
        .find_map(|(k, v)| {
            if k.as_text() == Some("valid_modes_for_function") {
                v.as_array()
            } else {
                None
            }
        })
        .expect("PI-11: error MUST carry valid_modes_for_function array");
    assert_eq!(valid.len(), 1, "identifier has only one valid mode");
    assert_eq!(valid[0].as_text(), Some("internal"));
}

#[tokio::test]
async fn pi11_create_attestation_accepts_valid_combinations() {
    // function=controller, mode=public is valid (top-level controller).
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    h.add_peer("ctrl", 20);
    let q_hash = h.add_quorum(&["k1", "k2"], 2);
    h.identity_hashes.insert("quorum".into(), q_hash);
    h.keypairs.insert("quorum".into(), Keypair::from_seed([99u8; 32]));

    // add_identity_cert internally calls :create_attestation; if PI-11
    // were over-aggressive this would fail.
    let cert_hash = h.add_identity_cert("quorum", "ctrl", "controller", "public", &["k1", "k2"], None);
    assert!(
        h.attestation_index.get(&cert_hash).is_some(),
        "PI-11: controller+public MUST be accepted"
    );
}

// ===========================================================================
// AttestationStore — finds live agent cert
// ===========================================================================

#[test]
fn attestation_store_finds_live_agent_cert() {
    use entity_handler::{AttestationStatus, AttestationStore};

    let mut h = Harness::new();
    h.add_peer("ctrl", 20);
    h.add_peer("agent", 30);
    let cert = h.add_identity_cert("ctrl", "agent", "agent", "internal", &["ctrl"], None);
    let store = crate::IdentityAttestationStore::new(
        h.attestation_index.clone(),
        h.content_store.clone(),
        h.location_index.clone(),
    );
    let agent_hash = h.peer("agent");
    let ctrl_hash = h.peer("ctrl");
    match store.lookup(&agent_hash) {
        AttestationStatus::Attested {
            public_identity,
            attestation_hash,
        } => {
            assert_eq!(public_identity, ctrl_hash, "issuer is the controller");
            assert_eq!(attestation_hash, cert);
        }
        AttestationStatus::NotAttested => panic!("expected Attested"),
    }
}

#[test]
fn attestation_store_returns_not_attested_for_unknown_peer() {
    use entity_handler::{AttestationStatus, AttestationStore};

    let h = Harness::new();
    let store = crate::IdentityAttestationStore::new(
        h.attestation_index.clone(),
        h.content_store.clone(),
        h.location_index.clone(),
    );
    let unknown = Hash::zero();
    assert_eq!(store.lookup(&unknown), AttestationStatus::NotAttested);
}

// ===========================================================================
// peer-config codec round-trip
// ===========================================================================

#[test]
fn peer_config_codec_roundtrip() {
    use crate::data::PeerConfigData;
    let pc = PeerConfigData {
        trusts_quorum: Hash::zero(),
        controller_grants: wildcard_handler_grant(),
        bindings: vec![],
    };
    let entity = pc.to_entity().unwrap();
    let decoded = PeerConfigData::from_entity(&entity).unwrap();
    assert_eq!(decoded.trusts_quorum, Hash::zero());
    assert_eq!(decoded.controller_grants.len(), 1);
}

// SI-11 envelope.included signature ingestion moved to dispatcher
// (V7 v7.37 §6.5). Tests live at `core/peer/src/ingest.rs`.

// ===========================================================================
// SI-1 / TV-I-A8 — consumer-layer signature validation rejection
// ===========================================================================

#[test]
fn tv_i_a8_identity_verify_cert_rejects_invalid_signature() {
    // The substrate is signature-agnostic (TV-A8 amended). The consumer
    // layer (identity_verify_cert) MUST reject when the topology-dispatched
    // signature check fails.
    let mut h = Harness::new();
    h.add_peer("ctrl", 70);
    h.add_peer("agent", 71);
    let ctrl = h.peer("ctrl");
    let agent = h.peer("agent");
    // Build an identity-cert(function=agent) with NO signature attached.
    let mut props: Vec<(ciborium::Value, ciborium::Value)> = vec![
        (text("function"), text("agent")),
        (text("kind"), text(KIND_IDENTITY_CERT)),
        (text("mode"), text("internal")),
    ];
    props.sort_by(|a, b| a.0.as_text().unwrap_or("").cmp(b.0.as_text().unwrap_or("")));
    let att = AttestationData {
        attesting: ctrl,
        attested: agent,
        properties: props,
        supersedes: None,
        not_before: None,
        expires_at: None,
    };
    let entity = att.to_entity().unwrap();
    let att_hash = entity.content_hash;
    h.content_store.put(entity).unwrap();
    h.attestation_index.insert(att_hash, att.clone());
    let result = identity_verify_cert(&att_hash, &att, &h.ictx());
    assert!(result.is_err(), "consumer-layer must reject invalid sig");
    match result.unwrap_err() {
        crate::VerifyCertError::InvalidSignature => {}
        other => panic!("expected InvalidSignature, got {:?}", other),
    }
}

// ===========================================================================
// SI-23 / TV-I-V23 — top-level controller cert validates K-of-N
//                    (not via single-sig at quorum_id path)
// ===========================================================================

#[test]
fn tv_i_v23_top_level_controller_cert_validates_via_k_of_n() {
    // Top-level controller cert: att.attesting = quorum_id (no peer keypair).
    // Per spec v3.3 amendment (SI-23): topology-first dispatch validates
    // via K-of-N path, NOT via the substrate's verify_attestation_signature
    // (which would fail because there's no signature at /quorum_id/system/signature/...).
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    h.add_peer("k3", 12);
    h.add_peer("ctrl", 20);
    let q_hash = h.add_quorum(&["k1", "k2", "k3"], 2);
    h.identity_hashes.insert("quorum".into(), q_hash);
    h.keypairs.insert("quorum".into(), Keypair::from_seed([99u8; 32]));
    let cert_hash = h.add_identity_cert(
        "quorum",
        "ctrl",
        "controller",
        "public",
        &["k1", "k2"], // K=2 of N=3
        None,
    );
    let cert = h.attestation_index.get(&cert_hash).unwrap();
    // Confirm there is NO signature at /quorum_id/system/signature/{cert_hash}.
    let bogus_path = format!(
        "/test/{}/system/signature/{}",
        entity_attestation::hex_segment(&q_hash),
        entity_attestation::hex_segment(&cert_hash),
    );
    assert!(
        h.location_index.get(&bogus_path).is_none(),
        "no quorum-as-signer path should exist"
    );
    // identity_verify_cert MUST validate via K-of-N dispatch.
    identity_verify_cert(&cert_hash, &cert, &h.ictx())
        .expect("top-level controller cert validates via K-of-N (not single-sig)");
}

// ===========================================================================
// SI-13 / TV-I-V13a — handoff cert is chain-walkable as controller
// ===========================================================================

#[test]
fn tv_i_v13a_identity_confers_function_via_handoff() {
    // identity_confers_function returns true for a handoff whose target
    // is an identity-cert(function=controller).
    use crate::validation::identity_confers_function;
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    h.add_peer("k3", 12);
    h.add_peer("ctrl_old", 20);
    h.add_peer("ctrl_new", 21);
    let q_hash = h.add_quorum(&["k1", "k2", "k3"], 2);
    h.identity_hashes.insert("quorum".into(), q_hash);
    h.keypairs.insert("quorum".into(), Keypair::from_seed([99u8; 32]));
    let ctrl_cert = h.add_identity_cert(
        "quorum",
        "ctrl_old",
        "controller",
        "public",
        &["k1", "k2"],
        None,
    );
    // Build a handoff attestation targeting ctrl_cert.
    let ctrl_old = h.peer("ctrl_old");
    let ctrl_new = h.peer("ctrl_new");
    let mut handoff_props: Vec<(ciborium::Value, ciborium::Value)> = vec![
        (text("kind"), text(crate::kinds::KIND_IDENTITY_ROTATION_HANDOFF)),
        (
            text("target_cert"),
            ciborium::Value::Bytes(ctrl_cert.to_bytes().to_vec()),
        ),
    ];
    handoff_props.sort_by(|a, b| a.0.as_text().unwrap_or("").cmp(b.0.as_text().unwrap_or("")));
    let handoff = AttestationData {
        attesting: ctrl_old,
        attested: ctrl_new,
        properties: handoff_props,
        supersedes: None,
        not_before: None,
        expires_at: None,
    };
    let handoff_entity = handoff.to_entity().unwrap();
    let handoff_hash = handoff_entity.content_hash;
    h.content_store.put(handoff_entity).unwrap();
    h.attestation_index.insert(handoff_hash, handoff.clone());
    // identity_confers_function for a handoff should resolve to the target
    // cert's function.
    assert!(
        identity_confers_function(&handoff, "controller", &h.ictx()),
        "handoff inherits controller function from target_cert"
    );
    assert!(
        !identity_confers_function(&handoff, "agent", &h.ictx()),
        "handoff does not confer agent"
    );
}

// ===========================================================================
// SI-13 / TV-I-V13b — identity-retirement terminates dead
// ===========================================================================

#[test]
fn tv_i_v13b_identity_retirement_does_not_confer_function() {
    use crate::validation::identity_confers_function;
    let mut h = Harness::new();
    h.add_peer("k1", 10);
    h.add_peer("k2", 11);
    h.add_peer("ctrl", 20);
    let q_hash = h.add_quorum(&["k1", "k2"], 2);
    h.identity_hashes.insert("quorum".into(), q_hash);
    h.keypairs.insert("quorum".into(), Keypair::from_seed([99u8; 32]));
    let ctrl_cert = h.add_identity_cert(
        "quorum",
        "ctrl",
        "controller",
        "public",
        &["k1", "k2"],
        None,
    );
    // Build an identity-retirement targeting ctrl_cert.
    let ctrl = h.peer("ctrl");
    let mut props: Vec<(ciborium::Value, ciborium::Value)> = vec![
        (text("kind"), text(crate::kinds::KIND_IDENTITY_RETIREMENT)),
        (
            text("target_cert"),
            ciborium::Value::Bytes(ctrl_cert.to_bytes().to_vec()),
        ),
    ];
    props.sort_by(|a, b| a.0.as_text().unwrap_or("").cmp(b.0.as_text().unwrap_or("")));
    let retirement = AttestationData {
        attesting: q_hash,
        attested: ctrl,
        properties: props,
        supersedes: None,
        not_before: None,
        expires_at: None,
    };
    let entity = retirement.to_entity().unwrap();
    let r_hash = entity.content_hash;
    h.content_store.put(entity).unwrap();
    h.attestation_index.insert(r_hash, retirement.clone());
    assert!(
        !identity_confers_function(&retirement, "controller", &h.ictx()),
        "retirement does NOT confer controller (terminates dead)"
    );
}
