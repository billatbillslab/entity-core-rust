//! Cross-impl test vectors for EXTENSION-QUORUM v1.0.
//!
//! - TV-Q1 through TV-Q5 — pluggable signer-resolution fail-closed (§5.3.1)
//! - TV-Q6 through TV-Q9 — `is_quorum_id` (§4.3)
//! - TV-QF12 through TV-QF15 — `current_signer_set` cache invalidation (§4.2.1)

use std::collections::HashMap;
use std::sync::Arc;

use entity_attestation::{AttestationData, AttestationIndex};
use entity_crypto::Keypair;
use entity_ecf::{text, Value};
use entity_entity::Entity;
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex, MemoryContentStore, MemoryLocationIndex};
use entity_types::SignatureData;

use crate::cache::SignerSetCache;
use crate::data::{hex_segment, path_quorum, path_quorum_event, QuorumData};
use crate::helpers::{current_signer_set, is_quorum_id, verify_k_of_n_signatures, QuorumCtx};
use crate::resolver::ResolverRegistry;
use crate::{KIND_QUORUM_UPDATE, RESOLUTION_CONCRETE};

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

struct Harness {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    attestation_index: Arc<AttestationIndex>,
    resolver_registry: ResolverRegistry,
    signer_set_cache: Arc<SignerSetCache>,
    keypairs: HashMap<String, Keypair>,
    identity_hashes: HashMap<String, Hash>,
    included: HashMap<Hash, Entity>,
}

impl Harness {
    fn new() -> Self {
        Self {
            content_store: Arc::new(MemoryContentStore::new()),
            location_index: Arc::new(MemoryLocationIndex::new()),
            attestation_index: Arc::new(AttestationIndex::new()),
            resolver_registry: ResolverRegistry::new(),
            signer_set_cache: Arc::new(SignerSetCache::new()),
            keypairs: HashMap::new(),
            identity_hashes: HashMap::new(),
            included: HashMap::new(),
        }
    }

    fn add_peer(&mut self, name: &str) -> Hash {
        let kp = Keypair::generate();
        let id_entity = kp.peer_entity().unwrap();
        let id_hash = id_entity.content_hash;
        self.content_store.put(id_entity).unwrap();
        self.identity_hashes.insert(name.to_string(), id_hash);
        self.keypairs.insert(name.to_string(), kp);
        id_hash
    }

    fn peer(&self, name: &str) -> Hash {
        *self.identity_hashes.get(name).unwrap()
    }

    /// Persist a `system/quorum` entity at canonical path.
    fn add_quorum(
        &mut self,
        signer_names: &[&str],
        threshold: u64,
        resolution: Option<&str>,
    ) -> Hash {
        let signers: Vec<Hash> = signer_names.iter().map(|n| self.peer(n)).collect();
        let q = QuorumData {
            signers,
            threshold,
            signer_resolution: resolution.map(|s| s.to_string()),
            name: None,
            metadata: None,
        };
        let entity = q.to_entity().unwrap();
        let q_hash = entity.content_hash;
        self.content_store.put(entity).unwrap();
        let path = format!("/test/{}", path_quorum(&q_hash));
        self.location_index.set(&path, q_hash);
        q_hash
    }

    /// Sign `target_hash` with each named signer's keypair, persist each
    /// signature entity, and bind at the V7 invariant pointer path.
    fn sign_with(&mut self, target_hash: &Hash, signer_names: &[&str]) {
        for name in signer_names {
            let kp = self.keypairs.get(*name).unwrap();
            let signer = self.peer(name);
            let sig_bytes = kp.sign(&target_hash.to_bytes());
            let sig_data = SignatureData {
                target: *target_hash,
                signer,
                algorithm: "ed25519".into(),
                signature: sig_bytes.to_vec(),
            };
            let sig_entity = sig_data.to_entity().unwrap();
            let sig_hash = sig_entity.content_hash;
            self.content_store.put(sig_entity).unwrap();
            let path = format!(
                "/test/{}/system/signature/{}",
                hex_segment(&signer),
                hex_segment(target_hash),
            );
            self.location_index.set(&path, sig_hash);
        }
    }

    /// Build, sign, persist, and index a `quorum-update` attestation.
    /// Signs K-of-N with the named signers (caller chooses the right K).
    #[allow(clippy::too_many_arguments)]
    fn add_quorum_update(
        &mut self,
        quorum_id: Hash,
        new_signer_names: &[&str],
        new_threshold: u64,
        supersedes: Option<Hash>,
        sign_with: &[&str],
    ) -> Hash {
        let new_signers: Vec<Hash> = new_signer_names.iter().map(|n| self.peer(n)).collect();
        let mut props: Vec<(ciborium::Value, ciborium::Value)> = vec![
            (text("kind"), text(KIND_QUORUM_UPDATE)),
            (
                text("new_signers"),
                Value::Array(
                    new_signers
                        .iter()
                        .map(|h| Value::Bytes(h.to_bytes().to_vec()))
                        .collect(),
                ),
            ),
            (
                text("new_threshold"),
                entity_ecf::integer(new_threshold as i64),
            ),
        ];
        props.sort_by(|a, b| {
            a.0.as_text()
                .unwrap_or("")
                .cmp(b.0.as_text().unwrap_or(""))
        });
        let att = AttestationData {
            attesting: quorum_id,
            attested: quorum_id,
            properties: props,
            supersedes,
            not_before: None,
            expires_at: None,
        };
        let entity = att.to_entity().unwrap();
        let att_hash = entity.content_hash;
        self.content_store.put(entity).unwrap();
        let path = format!("/test/{}", path_quorum_event(&quorum_id, &att_hash));
        self.location_index.set(&path, att_hash);
        self.attestation_index.insert(att_hash, att);
        self.sign_with(&att_hash, sign_with);
        att_hash
    }

    fn ctx(&self) -> QuorumCtx<'_> {
        QuorumCtx {
            attestation_index: &self.attestation_index,
            content_store: &self.content_store,
            location_index: &self.location_index,
            included: &self.included,
            resolver_registry: &self.resolver_registry,
            signer_set_cache: &self.signer_set_cache,
        }
    }
}

// ===========================================================================
// Codec round-trip
// ===========================================================================

/// R-7' (cross-impl ACME ruling, Round-6): `load_quorum` must
/// tolerate type-collisions on its `ends_with`-based path scan. The history
/// engine writes transitions at `/{peer}/system/history/head{event.path}`
/// — when event.path is `/{peer}/system/quorum/{q_hex}`, the resulting
/// transition path ends with `system/quorum/{q_hex}` and (since BTreeMap
/// iteration is alphabetical, h < q) shadows the actual quorum binding.
/// Pre-fix Rust's `current_signer_set` returned Err on the type-mismatch,
/// surfacing as `topology_dispatch_failed` in `:configure`.
#[test]
fn r7_prime_load_quorum_tolerates_history_transition_path_collision() {
    let mut h = Harness::new();
    h.add_peer("k1");
    h.add_peer("k2");
    h.add_peer("k3");

    // Bind the actual quorum at its canonical path.
    let q_hash = h.add_quorum(&["k1", "k2", "k3"], 2, None);

    // Synthesize a `system/history/transition` entity bound at a path
    // that ends with `system/quorum/{q_hex}` — exactly what the history
    // engine produces when it observes a tree write to the quorum's
    // canonical path. Sort-order: `system/history/...` precedes
    // `system/quorum/...` in BTreeMap iteration so this entry is hit
    // FIRST by load_quorum's scan.
    let transition_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (text("event"), text("created")),
        (text("path"), text(&format!("/test/{}", path_quorum(&q_hash)))),
    ]));
    let transition = Entity::new(
        entity_types::TYPE_HISTORY_TRANSITION,
        transition_data,
    )
    .unwrap();
    let transition_hash = transition.content_hash;
    h.content_store.put(transition).unwrap();
    let history_head_path = format!(
        "/test/system/history/head/test/{}",
        path_quorum(&q_hash)
    );
    h.location_index.set(&history_head_path, transition_hash);

    // Sanity: the history-head path sorts BEFORE the quorum path.
    assert!(history_head_path < format!("/test/{}", path_quorum(&q_hash)));

    // load_quorum must skip the history transition and return the actual
    // quorum. Pre-fix this returned Err with "expected system/quorum, got
    // system/history/transition".
    let result = current_signer_set(&q_hash, &h.ctx());
    assert!(
        result.is_ok(),
        "R-7': load_quorum must tolerate path-suffix collision with system/history/transition; got {:?}",
        result.err()
    );
    let signer_set = result.unwrap();
    assert_eq!(signer_set.signers.len(), 3);
    assert_eq!(signer_set.threshold, 2);
}

#[test]
fn quorum_codec_roundtrip() {
    let mut h = Harness::new();
    h.add_peer("a");
    h.add_peer("b");
    h.add_peer("c");
    let q = QuorumData {
        signers: vec![h.peer("a"), h.peer("b"), h.peer("c")],
        threshold: 2,
        signer_resolution: Some("identity-resolved".into()),
        name: Some("test".into()),
        metadata: None,
    };
    let entity = q.to_entity().unwrap();
    let decoded = QuorumData::from_entity(&entity).unwrap();
    assert_eq!(decoded.signers.len(), 3);
    assert_eq!(decoded.threshold, 2);
    assert_eq!(decoded.resolution_mode(), "identity-resolved");
    assert_eq!(decoded.name.as_deref(), Some("test"));
}

// ===========================================================================
// is_quorum_id (§4.3) — TV-Q6..TV-Q9
// ===========================================================================

#[test]
fn tv_q6_known_quorum_returns_true() {
    let mut h = Harness::new();
    h.add_peer("a");
    h.add_peer("b");
    let q_hash = h.add_quorum(&["a", "b"], 2, None);
    assert!(is_quorum_id(&q_hash, &h.ctx()));
}

#[test]
fn tv_q7_no_entity_returns_false() {
    let h = Harness::new();
    let bogus = Hash::zero();
    assert!(!is_quorum_id(&bogus, &h.ctx()));
}

#[test]
fn tv_q8_wrong_type_at_path_returns_false() {
    // Bind a non-quorum entity at a quorum path; is_quorum_id rejects.
    let mut h = Harness::new();
    let alice = h.add_peer("alice");
    // alice's identity entity at the canonical quorum path for some hash
    let path = format!("/test/{}", path_quorum(&alice));
    h.location_index.set(&path, alice);
    assert!(!is_quorum_id(&alice, &h.ctx()));
}

#[test]
fn tv_q9_quorum_visible_after_write() {
    let mut h = Harness::new();
    h.add_peer("a");
    h.add_peer("b");
    let bogus = Hash::zero();
    assert!(!is_quorum_id(&bogus, &h.ctx()));
    let q_hash = h.add_quorum(&["a", "b"], 2, None);
    // Subsequent re-evaluation sees it.
    assert!(is_quorum_id(&q_hash, &h.ctx()));
}

// ===========================================================================
// Pluggable signer resolution (§5.3.1) — TV-Q1..TV-Q5
// ===========================================================================

#[test]
fn tv_q1_concrete_mode_validates_normally() {
    let mut h = Harness::new();
    h.add_peer("a");
    h.add_peer("b");
    h.add_peer("c");
    let q_hash = h.add_quorum(&["a", "b", "c"], 2, Some(RESOLUTION_CONCRETE));
    let set = current_signer_set(&q_hash, &h.ctx()).unwrap();
    assert_eq!(set.threshold, 2);
    assert_eq!(set.signers.len(), 3);
}

#[test]
fn tv_q2_identity_resolved_with_resolver_succeeds() {
    let mut h = Harness::new();
    h.add_peer("a");
    h.add_peer("resolved");
    let q_hash = h.add_quorum(&["a"], 1, Some("identity-resolved"));
    let resolved_hash = h.peer("resolved");
    h.resolver_registry
        .register(
            "identity-resolved",
            Arc::new(move |_input, _rctx| Ok(resolved_hash)),
        );
    let set = current_signer_set(&q_hash, &h.ctx()).unwrap();
    assert_eq!(set.signers, vec![resolved_hash]);
}

#[test]
fn tv_q3_identity_resolved_no_resolver_fails_closed() {
    let mut h = Harness::new();
    h.add_peer("a");
    let q_hash = h.add_quorum(&["a"], 1, Some("identity-resolved"));
    let err = current_signer_set(&q_hash, &h.ctx()).unwrap_err();
    match err {
        crate::QuorumError::ResolverUnavailable {
            mode_name,
            available_modes,
            ..
        } => {
            assert_eq!(mode_name, "identity-resolved");
            assert!(available_modes.contains(&"concrete".to_string()));
        }
        other => panic!("expected ResolverUnavailable, got {:?}", other),
    }
}

#[test]
fn tv_q4_unknown_mode_fails_closed() {
    let mut h = Harness::new();
    h.add_peer("a");
    let q_hash = h.add_quorum(&["a"], 1, Some("future-mode-xyz"));
    let err = current_signer_set(&q_hash, &h.ctx()).unwrap_err();
    assert!(matches!(
        err,
        crate::QuorumError::ResolverUnavailable { .. }
    ));
}

#[test]
fn tv_q5_resolver_registered_after_initial_call_works() {
    let mut h = Harness::new();
    h.add_peer("a");
    h.add_peer("resolved");
    let q_hash = h.add_quorum(&["a"], 1, Some("identity-resolved"));
    // First call fails (no resolver).
    assert!(current_signer_set(&q_hash, &h.ctx()).is_err());
    // Register late.
    let resolved_hash = h.peer("resolved");
    h.resolver_registry
        .register(
            "identity-resolved",
            Arc::new(move |_input, _rctx| Ok(resolved_hash)),
        );
    // Spec §4.3: MUST NOT cache "not a quorum"/"resolver missing" status —
    // re-evaluates fresh. Our impl doesn't cache the failure either.
    let set = current_signer_set(&q_hash, &h.ctx()).unwrap();
    assert_eq!(set.signers, vec![resolved_hash]);
}

// ===========================================================================
// Cache invalidation (§4.2.1) — TV-QF12..TV-QF15
// ===========================================================================

#[test]
fn tv_qf12_local_update_invalidates_cache() {
    let mut h = Harness::new();
    h.add_peer("a");
    h.add_peer("b");
    h.add_peer("c");
    let q_hash = h.add_quorum(&["a", "b"], 2, None);
    let _set = current_signer_set(&q_hash, &h.ctx()).unwrap();
    assert_eq!(h.signer_set_cache.len(), 1);
    // Simulate the handler invalidation that `:update` performs.
    h.signer_set_cache.invalidate(&q_hash);
    assert_eq!(h.signer_set_cache.len(), 0);
}

#[test]
fn tv_qf13_validated_attestation_arrival_invalidates() {
    // Cross-peer sync delivers a validated quorum-update attestation —
    // the SyncTreeHook (Phase 6) calls invalidate() on validate-accept.
    // Direct test: invalidate after manual insertion.
    let mut h = Harness::new();
    h.add_peer("a");
    h.add_peer("b");
    h.add_peer("c");
    let q_hash = h.add_quorum(&["a", "b"], 2, None);
    let set_before = current_signer_set(&q_hash, &h.ctx()).unwrap();
    assert_eq!(set_before.signers.len(), 2);
    // Add a quorum-update changing membership.
    let _u1 = h.add_quorum_update(q_hash, &["a", "b", "c"], 2, None, &["a", "b"]);
    // Cache returns stale value until invalidated.
    let stale = current_signer_set(&q_hash, &h.ctx()).unwrap();
    assert_eq!(stale.signers.len(), 2);
    h.signer_set_cache.invalidate(&q_hash);
    let fresh = current_signer_set(&q_hash, &h.ctx()).unwrap();
    assert_eq!(fresh.signers.len(), 3);
}

#[test]
fn tv_qf14_failed_validation_does_not_invalidate() {
    // The cache invalidation is gated on the SyncTreeHook firing AFTER
    // K-of-N validation passes. Failed validations don't reach the
    // invalidation point. Direct test: confirm the invalidate API is
    // separate from the index insert (the invalidate isn't auto-fired by
    // index inserts — handler explicitly calls it).
    let mut h = Harness::new();
    h.add_peer("a");
    let q_hash = h.add_quorum(&["a"], 1, None);
    let set = current_signer_set(&q_hash, &h.ctx()).unwrap();
    assert_eq!(set.signers.len(), 1);
    // Insert a quorum-update directly (simulating raw tree write that
    // bypassed validation). Cache stays populated.
    let _u = h.add_quorum_update(q_hash, &["a"], 1, None, &[]); // unsigned
    let still_cached = h.signer_set_cache.get(&q_hash);
    assert!(still_cached.is_some(), "raw write must not invalidate cache");
}

#[test]
fn tv_qf15_per_quorum_scope() {
    let mut h = Harness::new();
    h.add_peer("a");
    h.add_peer("b");
    let qa_hash = h.add_quorum(&["a"], 1, None);
    let qb_hash = h.add_quorum(&["b"], 1, None);
    let _ = current_signer_set(&qa_hash, &h.ctx()).unwrap();
    let _ = current_signer_set(&qb_hash, &h.ctx()).unwrap();
    assert_eq!(h.signer_set_cache.len(), 2);
    h.signer_set_cache.invalidate(&qa_hash);
    assert!(h.signer_set_cache.get(&qa_hash).is_none());
    assert!(h.signer_set_cache.get(&qb_hash).is_some());
}

// ===========================================================================
// K-of-N validation
// ===========================================================================

#[test]
fn k_of_n_validates_threshold_signatures() {
    let mut h = Harness::new();
    h.add_peer("a");
    h.add_peer("b");
    h.add_peer("c");
    let target = Hash::zero();
    h.sign_with(&target, &["a", "b"]);
    let signers = vec![h.peer("a"), h.peer("b"), h.peer("c")];
    assert!(verify_k_of_n_signatures(&target, &signers, 2, &h.ctx()));
}

#[test]
fn k_of_n_fails_below_threshold() {
    let mut h = Harness::new();
    h.add_peer("a");
    h.add_peer("b");
    h.add_peer("c");
    let target = Hash::zero();
    h.sign_with(&target, &["a"]); // only one
    let signers = vec![h.peer("a"), h.peer("b"), h.peer("c")];
    assert!(!verify_k_of_n_signatures(&target, &signers, 2, &h.ctx()));
}

#[test]
fn k_of_n_threshold_zero_is_trivially_true() {
    let h = Harness::new();
    let signers: Vec<Hash> = vec![];
    assert!(verify_k_of_n_signatures(&Hash::zero(), &signers, 0, &h.ctx()));
}

// ===========================================================================
// current_signer_set — quorum-update chain
// ===========================================================================

#[test]
fn signer_set_tracks_quorum_update_chain() {
    let mut h = Harness::new();
    h.add_peer("a");
    h.add_peer("b");
    h.add_peer("c");
    h.add_peer("d");
    let q_hash = h.add_quorum(&["a", "b"], 2, None);
    let set0 = current_signer_set(&q_hash, &h.ctx()).unwrap();
    assert_eq!(set0.signers.len(), 2);
    h.signer_set_cache.invalidate(&q_hash);

    let u1 = h.add_quorum_update(q_hash, &["a", "b", "c"], 2, None, &["a", "b"]);
    let set1 = current_signer_set(&q_hash, &h.ctx()).unwrap();
    assert_eq!(set1.signers.len(), 3);
    h.signer_set_cache.invalidate(&q_hash);

    let _u2 = h.add_quorum_update(q_hash, &["a", "c", "d"], 2, Some(u1), &["a", "b", "c"]);
    let set2 = current_signer_set(&q_hash, &h.ctx()).unwrap();
    assert_eq!(set2.signers.len(), 3);
    let signer_hashes: Vec<Hash> = set2.signers.clone();
    assert!(signer_hashes.contains(&h.peer("a")));
    assert!(signer_hashes.contains(&h.peer("c")));
    assert!(signer_hashes.contains(&h.peer("d")));
    assert!(!signer_hashes.contains(&h.peer("b")));
}

// ===========================================================================
// SI-16 — `as_of` parameter on current_signer_set
// ===========================================================================

use crate::helpers::current_signer_set_as_of;

/// Build a quorum-update with explicit `not_before`. Variant of
/// `add_quorum_update` for as_of testing.
fn add_quorum_update_at(
    h: &mut Harness,
    quorum_id: Hash,
    new_signer_names: &[&str],
    new_threshold: u64,
    supersedes: Option<Hash>,
    not_before: Option<u64>,
    sign_with: &[&str],
) -> Hash {
    let new_signers: Vec<Hash> = new_signer_names.iter().map(|n| h.peer(n)).collect();
    let mut props: Vec<(ciborium::Value, ciborium::Value)> = vec![
        (text("kind"), text(KIND_QUORUM_UPDATE)),
        (
            text("new_signers"),
            Value::Array(
                new_signers
                    .iter()
                    .map(|hh| Value::Bytes(hh.to_bytes().to_vec()))
                    .collect(),
            ),
        ),
        (
            text("new_threshold"),
            entity_ecf::integer(new_threshold as i64),
        ),
    ];
    props.sort_by(|a, b| {
        a.0.as_text()
            .unwrap_or("")
            .cmp(b.0.as_text().unwrap_or(""))
    });
    let att = AttestationData {
        attesting: quorum_id,
        attested: quorum_id,
        properties: props,
        supersedes,
        not_before,
        expires_at: None,
    };
    let entity = att.to_entity().unwrap();
    let att_hash = entity.content_hash;
    h.content_store.put(entity).unwrap();
    let path = format!("/test/{}", path_quorum_event(&quorum_id, &att_hash));
    h.location_index.set(&path, att_hash);
    h.attestation_index.insert(att_hash, att);
    h.sign_with(&att_hash, sign_with);
    att_hash
}

#[test]
fn tv_q_v16a_as_of_before_u2_returns_s1() {
    // Quorum Q with quorum-update u1 (not_before=t1, signers=S1) and
    // u2 (not_before=t2 > t1, signers=S2; supersedes u1);
    // current_signer_set(Q, as_of=t1.5) → S1
    let mut h = Harness::new();
    h.add_peer("a");
    h.add_peer("b");
    h.add_peer("c");
    h.add_peer("d");
    let q_hash = h.add_quorum(&["a", "b"], 2, None);
    let u1 = add_quorum_update_at(
        &mut h,
        q_hash,
        &["a", "b", "c"], // S1
        2,
        None,
        Some(1_000_000), // t1
        &["a", "b"],
    );
    let _u2 = add_quorum_update_at(
        &mut h,
        q_hash,
        &["a", "c", "d"], // S2
        2,
        Some(u1),
        Some(2_000_000), // t2
        &["a", "b", "c"],
    );
    // as_of = t1.5 (between t1 and t2)
    let set = current_signer_set_as_of(&q_hash, Some(1_500_000), &h.ctx()).unwrap();
    assert_eq!(set.signers.len(), 3);
    assert!(set.signers.contains(&h.peer("a")));
    assert!(set.signers.contains(&h.peer("b")));
    assert!(set.signers.contains(&h.peer("c")));
    assert!(!set.signers.contains(&h.peer("d")));
}

#[test]
fn tv_q_v16b_as_of_after_u2_returns_s2() {
    let mut h = Harness::new();
    h.add_peer("a");
    h.add_peer("b");
    h.add_peer("c");
    h.add_peer("d");
    let q_hash = h.add_quorum(&["a", "b"], 2, None);
    let u1 = add_quorum_update_at(
        &mut h,
        q_hash,
        &["a", "b", "c"],
        2,
        None,
        Some(1_000_000),
        &["a", "b"],
    );
    let _u2 = add_quorum_update_at(
        &mut h,
        q_hash,
        &["a", "c", "d"],
        2,
        Some(u1),
        Some(2_000_000),
        &["a", "b", "c"],
    );
    // as_of = t2 + 1 (after both updates)
    let set = current_signer_set_as_of(&q_hash, Some(2_000_001), &h.ctx()).unwrap();
    assert!(set.signers.contains(&h.peer("a")));
    assert!(set.signers.contains(&h.peer("c")));
    assert!(set.signers.contains(&h.peer("d")));
    assert!(!set.signers.contains(&h.peer("b")));
}

// ===========================================================================
// IDENTITY-2 — Resolver max_depth + cycle detection
// ===========================================================================

#[test]
fn tv_q_v_identity_2_resolver_max_depth_exceeded() {
    // Resolver that always recurses (always returns "enter" further)
    // — depth bound trips at MAX_RESOLVER_DEPTH.
    let mut h = Harness::new();
    h.add_peer("a");
    let q_hash = h.add_quorum(&["a"], 1, Some("recursive-mode"));
    // Resolver that recursively enters MAX_RESOLVER_DEPTH+1 times.
    h.resolver_registry.register(
        "recursive-mode",
        Arc::new(|input, rctx| {
            // Synthesize fresh hashes by hashing repeatedly so each enter()
            // sees a distinct ref and never trips the cycle path.
            let mut next = *input;
            loop {
                let mut bytes = next.to_bytes().to_vec();
                bytes.push(0xAA);
                let entity = entity_entity::Entity::new("test/recurse", bytes).unwrap();
                next = entity.content_hash;
                rctx.enter(next)?;
            }
        }),
    ).unwrap();
    let err = current_signer_set(&q_hash, &h.ctx()).unwrap_err();
    assert!(
        matches!(err, crate::QuorumError::ResolverDepthExceeded { .. }),
        "expected ResolverDepthExceeded, got {:?}",
        err
    );
}

#[test]
fn tv_q_v_identity_2_resolver_cycle() {
    // Resolver that revisits the same identity ref → cycle error.
    let mut h = Harness::new();
    h.add_peer("a");
    let q_hash = h.add_quorum(&["a"], 1, Some("cyclic-mode"));
    h.resolver_registry.register(
        "cyclic-mode",
        Arc::new(|input, rctx| {
            // Enter once, then re-enter with the same ref → cycle.
            rctx.enter(*input)?;
            rctx.enter(*input)?;
            Ok(*input)
        }),
    ).unwrap();
    let err = current_signer_set(&q_hash, &h.ctx()).unwrap_err();
    assert!(
        matches!(err, crate::QuorumError::ResolverCycle { .. }),
        "expected ResolverCycle, got {:?}",
        err
    );
}

// PR-6 (PROPOSAL-SYSTEM-PEER-RENAME §PR-6): resolver_already_registered.
// Re-registering a `mode_name` with a DIFFERENT handler MUST be rejected;
// re-registering the SAME handler (Arc::ptr_eq) is a no-op success for
// hot-reload scenarios. No silent replacement; no stacking.
#[test]
fn pr6_register_already_registered_different_handler() {
    let registry = crate::ResolverRegistry::new();
    let r1: crate::ResolverFn = Arc::new(|_input, _rctx| Ok(Hash::zero()));
    let r2: crate::ResolverFn = Arc::new(|_input, _rctx| Ok(Hash::zero()));

    // First registration succeeds.
    registry.register("test-mode", r1).unwrap();

    // Re-registration with a different handler is rejected.
    let err = registry.register("test-mode", r2).unwrap_err();
    assert!(
        matches!(err, crate::RegisterError::AlreadyRegistered(ref m) if m == "test-mode"),
        "expected AlreadyRegistered(\"test-mode\"), got {:?}",
        err
    );
}

#[test]
fn pr6_register_idempotent_same_arc() {
    let registry = crate::ResolverRegistry::new();
    let r: crate::ResolverFn = Arc::new(|_input, _rctx| Ok(Hash::zero()));

    // First and second registration with the SAME Arc both succeed (no-op).
    registry.register("test-mode", r.clone()).unwrap();
    registry.register("test-mode", r).unwrap();
}
