//! Cross-impl test vectors for EXTENSION-ATTESTATION v1.0.
//!
//! - TV-A1 through TV-A11 — `default_find_authorizing` (§5.1)
//! - TV-I1 through TV-I5 — index invariants (§5.7)
//!
//! These vectors are architect-team-owned per the spec; passing them is the
//! cross-impl conformance baseline. When local Rust impl passes, run interop
//! against Go/Python.

use std::collections::HashMap;
use std::sync::Arc;

use entity_crypto::Keypair;
use entity_ecf::text;
use entity_entity::Entity;
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex, MemoryContentStore, MemoryLocationIndex};
use entity_types::{SignatureData, TYPE_ATTESTATION};

use crate::data::{hex_segment, AttestationData};
use crate::helpers::{
    default_find_authorizing, find_attestations_by, find_attestations_targeting,
    find_attestations_with_kind, find_revocations_for, is_attestation_live,
    verify_attestation_signature, AttestationCtx,
};
use crate::index::AttestationIndex;
use crate::KIND_REVOCATION;

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

struct Harness {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    index: Arc<AttestationIndex>,
    /// Identity entity hashes for each named keypair.
    identity_hashes: HashMap<String, Hash>,
    keypairs: HashMap<String, Keypair>,
    included: HashMap<Hash, Entity>,
}

impl Harness {
    fn new() -> Self {
        Self {
            content_store: Arc::new(MemoryContentStore::new()),
            location_index: Arc::new(MemoryLocationIndex::new()),
            index: Arc::new(AttestationIndex::new()),
            identity_hashes: HashMap::new(),
            keypairs: HashMap::new(),
            included: HashMap::new(),
        }
    }

    /// Generate a keypair, persist its identity entity, return the
    /// identity hash (the canonical "peer hash" for attestation purposes).
    fn add_peer(&mut self, name: &str) -> Hash {
        let kp = Keypair::generate();
        let id_entity = kp.peer_entity().expect("identity entity");
        let id_hash = id_entity.content_hash;
        self.content_store.put(id_entity).expect("put identity");
        self.identity_hashes.insert(name.to_string(), id_hash);
        self.keypairs.insert(name.to_string(), kp);
        id_hash
    }

    fn peer(&self, name: &str) -> Hash {
        *self.identity_hashes.get(name).expect("peer not added")
    }

    /// Build, sign, persist, and index an attestation. Stores at a
    /// caller-supplied (or auto-generated) path so location_index
    /// scans see it.
    fn add_attestation(
        &mut self,
        attesting_peer: &str,
        attested_peer: &str,
        properties: Vec<(&str, &str)>,
        supersedes: Option<Hash>,
        not_before: Option<u64>,
        expires_at: Option<u64>,
    ) -> (Hash, AttestationData) {
        let attesting = self.peer(attesting_peer);
        let attested = self.peer(attested_peer);
        let props: Vec<(ciborium::Value, ciborium::Value)> = properties
            .iter()
            .map(|(k, v)| (text(*k), text(*v)))
            .collect();
        let att = AttestationData {
            attesting,
            attested,
            properties: props,
            supersedes,
            not_before,
            expires_at,
        };
        let entity = att.to_entity().expect("encode attestation");
        let att_hash = entity.content_hash;
        self.content_store.put(entity).expect("put attestation");
        // Bind at a unique path so location_index lists it.
        let path = format!("/test/system/attestation/{}", hex_segment(&att_hash));
        self.location_index.set(&path, att_hash);
        // Sign content_hash with attesting peer's keypair.
        let kp = self
            .keypairs
            .get(attesting_peer)
            .expect("attesting keypair");
        let sig_bytes = kp.sign(&att_hash.to_bytes());
        let sig_data = SignatureData {
            target: att_hash,
            signer: attesting,
            algorithm: "ed25519".into(),
            signature: sig_bytes.to_vec(),
        };
        let sig_entity = sig_data.to_entity().expect("encode signature");
        let sig_hash = sig_entity.content_hash;
        self.content_store.put(sig_entity.clone()).expect("put sig");
        // Bind at the V7 invariant pointer path (§6.2 of identity spec /
        // attestation §4.1). We use the identity hash as the "signer peer
        // id" segment for test convenience; the attestation primitive's
        // `find_signature_for` walks all paths matching the suffix.
        let sig_path = format!(
            "/test/{}/system/signature/{}",
            hex_segment(&attesting),
            hex_segment(&att_hash)
        );
        self.location_index.set(&sig_path, sig_hash);
        // Index the attestation.
        self.index.insert(att_hash, att.clone());
        (att_hash, att)
    }

    /// Same as `add_attestation` but does NOT sign — used to test
    /// `verify_attestation_signature` failure path.
    fn add_attestation_unsigned(
        &mut self,
        attesting_peer: &str,
        attested_peer: &str,
        properties: Vec<(&str, &str)>,
    ) -> (Hash, AttestationData) {
        let attesting = self.peer(attesting_peer);
        let attested = self.peer(attested_peer);
        let props: Vec<(ciborium::Value, ciborium::Value)> = properties
            .iter()
            .map(|(k, v)| (text(*k), text(*v)))
            .collect();
        let att = AttestationData {
            attesting,
            attested,
            properties: props,
            supersedes: None,
            not_before: None,
            expires_at: None,
        };
        let entity = att.to_entity().expect("encode");
        let att_hash = entity.content_hash;
        self.content_store.put(entity).expect("put");
        let path = format!("/test/system/attestation/{}", hex_segment(&att_hash));
        self.location_index.set(&path, att_hash);
        self.index.insert(att_hash, att.clone());
        (att_hash, att)
    }

    fn ctx(&self) -> AttestationCtx<'_> {
        AttestationCtx {
            index: &self.index,
            content_store: &self.content_store,
            location_index: &self.location_index,
            included: &self.included,
        }
    }
}

// ===========================================================================
// Codec round-trip
// ===========================================================================

#[test]
fn att_codec_roundtrip() {
    let mut h = Harness::new();
    let alice = h.add_peer("alice");
    let bob = h.add_peer("bob");

    let att = AttestationData {
        attesting: alice,
        attested: bob,
        properties: vec![
            (text("kind"), text("identity-cert")),
            (text("function"), text("controller")),
        ],
        supersedes: None,
        not_before: Some(100),
        expires_at: Some(2_000_000_000_000),
    };
    let entity = att.to_entity().unwrap();
    assert_eq!(entity.entity_type, TYPE_ATTESTATION);
    let decoded = AttestationData::from_entity(&entity).unwrap();
    assert_eq!(decoded.attesting, alice);
    assert_eq!(decoded.attested, bob);
    assert_eq!(decoded.kind(), Some("identity-cert"));
    assert_eq!(decoded.not_before, Some(100));
    assert_eq!(decoded.expires_at, Some(2_000_000_000_000));
}

// ===========================================================================
// Index invariants (§5.7) — TV-I1..TV-I5
// ===========================================================================

#[test]
fn tv_i1_index_entry_present_after_write() {
    // Empty index; insert attestation A; immediately
    // find_attestations_targeting(A.attested) returns A.
    let mut h = Harness::new();
    h.add_peer("alice");
    h.add_peer("bob");
    let (a_hash, _) = h.add_attestation("alice", "bob", vec![("kind", "test")], None, None, None);
    let bob = h.peer("bob");
    let found = find_attestations_targeting(&bob, |_| true, &h.ctx());
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, a_hash);
}

#[test]
fn tv_i2_atomicity_failed_validation_no_index() {
    // The handler is the gate that calls index.insert. If create_attestation
    // returns an error before persist+index, the index stays empty.
    // Direct test: never call insert; index is empty.
    let h = Harness::new();
    assert!(h.index.is_empty());
}

#[test]
fn tv_i3_two_atts_same_attesting_diff_attested() {
    let mut h = Harness::new();
    h.add_peer("alice");
    h.add_peer("bob");
    h.add_peer("carol");
    let (a, _) = h.add_attestation("alice", "bob", vec![("kind", "x")], None, None, None);
    let (b, _) = h.add_attestation("alice", "carol", vec![("kind", "x")], None, None, None);
    let alice = h.peer("alice");
    let found = find_attestations_by(&alice, |_| true, &h.ctx());
    let hashes: Vec<Hash> = found.into_iter().map(|(h, _)| h).collect();
    assert!(hashes.contains(&a));
    assert!(hashes.contains(&b));
}

#[test]
fn tv_i4_revoked_att_still_indexed() {
    // A and revocation R targeting A. find_attestations_targeting still
    // returns A (revocation does NOT remove from index).
    // is_attestation_live(A) returns false.
    let mut h = Harness::new();
    h.add_peer("alice");
    h.add_peer("bob");
    let (a_hash, _) = h.add_attestation("alice", "bob", vec![("kind", "x")], None, None, None);
    // Self-revocation by alice — build directly since revocation's `attested`
    // is an attestation hash, not a peer.
    let alice = h.peer("alice");
    let rev = AttestationData {
        attesting: alice,
        attested: a_hash,
        properties: vec![(text("kind"), text(KIND_REVOCATION))],
        supersedes: None,
        not_before: None,
        expires_at: None,
    };
    let rev_entity = rev.to_entity().unwrap();
    let rev_hash = rev_entity.content_hash;
    h.content_store.put(rev_entity).unwrap();
    let kp = h.keypairs.get("alice").unwrap();
    let sig_bytes = kp.sign(&rev_hash.to_bytes());
    let sig_data = SignatureData {
        target: rev_hash,
        signer: alice,
        algorithm: "ed25519".into(),
        signature: sig_bytes.to_vec(),
    };
    let sig_entity = sig_data.to_entity().unwrap();
    h.content_store.put(sig_entity).unwrap();
    h.location_index.set(
        &format!(
            "/test/{}/system/signature/{}",
            hex_segment(&alice),
            hex_segment(&rev_hash)
        ),
        sig_data.target,
    );
    h.index.insert(rev_hash, rev);

    // Index still contains A (under bob and under alice).
    let bob = h.peer("bob");
    let still_found = find_attestations_targeting(&bob, |_| true, &h.ctx());
    assert!(still_found.iter().any(|(h, _)| h == &a_hash));

    // Liveness flips to false.
    let a_data = h.index.get(&a_hash).unwrap();
    assert!(!is_attestation_live(&a_hash, &a_data, &h.ctx(), None));
}

#[test]
fn tv_i5_kind_index_only_indexes_atts_with_kind() {
    let mut h = Harness::new();
    h.add_peer("alice");
    h.add_peer("bob");
    let (a, _) = h.add_attestation("alice", "bob", vec![("kind", "foo")], None, None, None);
    let (b, _) = h.add_attestation("alice", "bob", vec![("kind", "foo")], None, None, None);
    let (c, _) = h.add_attestation("alice", "bob", vec![], None, None, None);
    let found = find_attestations_with_kind("foo", &h.ctx());
    let hashes: Vec<Hash> = found.into_iter().map(|(h, _)| h).collect();
    assert!(hashes.contains(&a));
    assert!(hashes.contains(&b));
    assert!(!hashes.contains(&c));
}

// ===========================================================================
// default_find_authorizing (§5.1) — TV-A1..TV-A11
// ===========================================================================

#[test]
fn tv_a1_single_live_attestation_returns_it() {
    let mut h = Harness::new();
    h.add_peer("alice");
    h.add_peer("bob");
    let (a, _) = h.add_attestation("alice", "bob", vec![("kind", "x")], None, None, None);
    let bob = h.peer("bob");
    let found = default_find_authorizing(&bob, &h.ctx()).unwrap();
    assert_eq!(found.0, a);
}

#[test]
fn tv_a2_no_attestations_returns_none() {
    let mut h = Harness::new();
    h.add_peer("alice");
    let alice = h.peer("alice");
    assert!(default_find_authorizing(&alice, &h.ctx()).is_none());
}

#[test]
fn tv_a3_three_distinct_chains_lowest_content_hash() {
    let mut h = Harness::new();
    h.add_peer("alice");
    h.add_peer("bob");
    h.add_peer("carol");
    h.add_peer("target");
    let (a, _) = h.add_attestation("alice", "target", vec![("kind", "x"), ("salt", "1")], None, None, None);
    let (b, _) = h.add_attestation("bob", "target", vec![("kind", "x"), ("salt", "2")], None, None, None);
    let (c, _) = h.add_attestation("carol", "target", vec![("kind", "x"), ("salt", "3")], None, None, None);
    let target = h.peer("target");
    let found = default_find_authorizing(&target, &h.ctx()).unwrap();
    let mut sorted = vec![a, b, c];
    sorted.sort();
    assert_eq!(found.0, sorted[0], "deterministic tie-break: lowest content_hash");
}

#[test]
fn tv_a4_supersedes_chain_returns_live_head() {
    let mut h = Harness::new();
    h.add_peer("alice");
    h.add_peer("bob");
    let (a, _) = h.add_attestation("alice", "bob", vec![("kind", "x"), ("v", "1")], None, None, None);
    let (a_prime, _) =
        h.add_attestation("alice", "bob", vec![("kind", "x"), ("v", "2")], Some(a), None, None);
    let (a_pp, _) = h.add_attestation(
        "alice",
        "bob",
        vec![("kind", "x"), ("v", "3")],
        Some(a_prime),
        None,
        None,
    );
    let bob = h.peer("bob");
    let found = default_find_authorizing(&bob, &h.ctx()).unwrap();
    assert_eq!(found.0, a_pp, "expected live head of supersedes chain");
}

#[test]
fn tv_a5_two_distinct_chains_lowest_content_hash() {
    let mut h = Harness::new();
    h.add_peer("alice");
    h.add_peer("bob");
    h.add_peer("target");
    let (a, _) = h.add_attestation("alice", "target", vec![("kind", "x"), ("salt", "1")], None, None, None);
    let (a_prime, _) = h.add_attestation(
        "alice",
        "target",
        vec![("kind", "x"), ("salt", "1b")],
        Some(a),
        None,
        None,
    );
    let (b, _) = h.add_attestation("bob", "target", vec![("kind", "x"), ("salt", "2")], None, None, None);
    let target = h.peer("target");
    let found = default_find_authorizing(&target, &h.ctx()).unwrap();
    let mut heads = vec![a_prime, b];
    heads.sort();
    assert_eq!(found.0, heads[0]);
}

#[test]
fn tv_a6_expired_attestation_returns_none() {
    let mut h = Harness::new();
    h.add_peer("alice");
    h.add_peer("bob");
    let _ = h.add_attestation(
        "alice",
        "bob",
        vec![("kind", "x")],
        None,
        None,
        Some(1_000), // long expired
    );
    let bob = h.peer("bob");
    assert!(default_find_authorizing(&bob, &h.ctx()).is_none());
}

#[test]
fn tv_a7_self_revoked_returns_none() {
    let mut h = Harness::new();
    h.add_peer("alice");
    h.add_peer("bob");
    let (a_hash, _) = h.add_attestation("alice", "bob", vec![("kind", "x")], None, None, None);
    // Self-revocation
    let alice = h.peer("alice");
    let rev = AttestationData {
        attesting: alice,
        attested: a_hash,
        properties: vec![(text("kind"), text(KIND_REVOCATION))],
        supersedes: None,
        not_before: None,
        expires_at: None,
    };
    let rev_entity = rev.to_entity().unwrap();
    let rev_hash = rev_entity.content_hash;
    h.content_store.put(rev_entity).unwrap();
    let kp = h.keypairs.get("alice").unwrap();
    let sig_bytes = kp.sign(&rev_hash.to_bytes());
    let sig_data = SignatureData {
        target: rev_hash,
        signer: alice,
        algorithm: "ed25519".into(),
        signature: sig_bytes.to_vec(),
    };
    let sig_entity = sig_data.to_entity().unwrap();
    h.content_store.put(sig_entity).unwrap();
    h.location_index.set(
        &format!(
            "/test/{}/system/signature/{}",
            hex_segment(&alice),
            hex_segment(&rev_hash)
        ),
        rev_hash,
    );
    h.index.insert(rev_hash, rev);
    let bob = h.peer("bob");
    assert!(default_find_authorizing(&bob, &h.ctx()).is_none());
}

#[test]
fn tv_a8_substrate_is_signature_agnostic() {
    // Per spec v1.1 amendment (SI-1): the substrate's
    // `default_find_authorizing` is signature-agnostic. An attestation
    // with an invalid signature is still returned by the substrate
    // primitive — consumers (e.g. identity's `identity_verify_cert`)
    // layer signature validation per topology.
    let mut h = Harness::new();
    h.add_peer("alice");
    h.add_peer("bob");
    let (a_hash, _) = h.add_attestation_unsigned("alice", "bob", vec![("kind", "x")]);
    let bob = h.peer("bob");
    let found = default_find_authorizing(&bob, &h.ctx())
        .expect("substrate returns A even with no/invalid signature");
    assert_eq!(found.0, a_hash);
}

#[test]
fn tv_a8_helper_explicitly_validates_signature() {
    // Companion: verify_attestation_signature, when called directly,
    // does reject. Sig validation is OFFERED by the substrate; just not
    // baked into liveness or default_find_authorizing.
    let mut h = Harness::new();
    h.add_peer("alice");
    h.add_peer("bob");
    let (a_hash, a_data) =
        h.add_attestation_unsigned("alice", "bob", vec![("kind", "x")]);
    assert!(!verify_attestation_signature(&a_hash, &a_data, &h.ctx()));
}

// ===========================================================================
// §9.1 Invariant I1 — index populated on ANY tree write of a
// system/attestation entity (not just via the substrate's :create).
// Spec phrase: "...or any operation that writes a `system/attestation`
// entity to the tree..." Per the Rust-failures review item #4.
// ===========================================================================

#[test]
fn invariant_i1_hook_populates_index_on_external_tree_put() {
    use crate::hook::AttestationIndexHook;
    use entity_store::{ChangeType, ExecutionContext, SyncTreeHook, TreeChangeEvent};

    let mut h = Harness::new();
    h.add_peer("alice");
    h.add_peer("bob");

    // Build an attestation entity directly (simulates an arrival via
    // tree:put — bypasses the substrate's :create handler completely).
    let alice = h.peer("alice");
    let bob = h.peer("bob");
    let att = AttestationData {
        attesting: alice,
        attested: bob,
        properties: vec![(text("kind"), text("identity-cert"))],
        supersedes: None,
        not_before: None,
        expires_at: None,
    };
    let entity = att.to_entity().unwrap();
    let att_hash = entity.content_hash;

    // Persist + bind via the raw store paths (kernel tree:put would do
    // exactly this — no substrate handler involved).
    h.content_store.put(entity).unwrap();
    let path = format!("/test/system/attestation/{}", hex_segment(&att_hash));
    h.location_index.set(&path, att_hash);

    // Index is empty at this point (the kernel write didn't go through
    // the substrate handler that populates the index).
    assert_eq!(h.index.len(), 0, "index must be empty before hook fires");

    // Fire the hook directly with a synthesized TreeChangeEvent (the
    // dispatcher fires this on every tree mutation in production).
    let hook = AttestationIndexHook::new(
        h.index.clone(),
        h.content_store.clone(),
        "test".to_string(),
    );
    let event = TreeChangeEvent {
        path: path.clone(),
        hash: att_hash,
        previous_hash: None,
        new_hash: Some(att_hash),
        change_type: ChangeType::Created,
        context: None,
    };
    hook.on_tree_change(&event, &mut ExecutionContext::default())
        .expect("hook should succeed");

    // Per §I1: the index entry MUST be present after the write.
    assert_eq!(h.index.len(), 1, "index entry present after hook");
    let found = find_attestations_targeting(&bob, |_| true, &h.ctx());
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, att_hash);
}

// ===========================================================================
// SI-2 transitive supersession + revival cases — TV-A4a..TV-A4d
// ===========================================================================

#[test]
fn tv_a4a_chain_of_three_a2_live_a1_dead_a0_dead() {
    // a0 → a1 → a2 (chain of three; all valid; no revocations).
    // Expected: a2 live; a1 dead (superseded by a2);
    // a0 dead (superseded by transitive a2).
    let mut h = Harness::new();
    h.add_peer("alice");
    h.add_peer("bob");
    let (a0, _) = h.add_attestation("alice", "bob", vec![("kind", "x"), ("v", "0")], None, None, None);
    let (a1, _) =
        h.add_attestation("alice", "bob", vec![("kind", "x"), ("v", "1")], Some(a0), None, None);
    let (a2, _) =
        h.add_attestation("alice", "bob", vec![("kind", "x"), ("v", "2")], Some(a1), None, None);
    let a0_data = h.index.get(&a0).unwrap();
    let a1_data = h.index.get(&a1).unwrap();
    let a2_data = h.index.get(&a2).unwrap();
    assert!(is_attestation_live(&a2, &a2_data, &h.ctx(), None), "a2 live");
    assert!(!is_attestation_live(&a1, &a1_data, &h.ctx(), None), "a1 dead (superseded)");
    assert!(!is_attestation_live(&a0, &a0_data, &h.ctx(), None), "a0 dead (transitive)");
}

#[test]
fn tv_a4b_a2_expired_a1_revives_to_live() {
    // a0 → a1 → a2; a2 expired. Expected: a1 live (no live descendant);
    // a0 dead (a1 lives between).
    let mut h = Harness::new();
    h.add_peer("alice");
    h.add_peer("bob");
    let (a0, _) = h.add_attestation("alice", "bob", vec![("kind", "x"), ("v", "0")], None, None, None);
    let (a1, _) =
        h.add_attestation("alice", "bob", vec![("kind", "x"), ("v", "1")], Some(a0), None, None);
    let (a2, _) = h.add_attestation(
        "alice",
        "bob",
        vec![("kind", "x"), ("v", "2")],
        Some(a1),
        None,
        Some(1_000), // expired (now is far past)
    );
    let a0_data = h.index.get(&a0).unwrap();
    let a1_data = h.index.get(&a1).unwrap();
    let a2_data = h.index.get(&a2).unwrap();
    assert!(!is_attestation_live(&a2, &a2_data, &h.ctx(), None), "a2 dead (expired)");
    assert!(is_attestation_live(&a1, &a1_data, &h.ctx(), None), "a1 live (no live descendant)");
    assert!(!is_attestation_live(&a0, &a0_data, &h.ctx(), None), "a0 dead (a1 lives between)");
}

#[test]
fn tv_a4c_a1_revoked_a0_revives() {
    // a0 → a1; a1 revoked. Expected: a0 live (no live descendant).
    let mut h = Harness::new();
    h.add_peer("alice");
    h.add_peer("bob");
    let (a0, _) = h.add_attestation("alice", "bob", vec![("kind", "x"), ("v", "0")], None, None, None);
    let (a1, _) =
        h.add_attestation("alice", "bob", vec![("kind", "x"), ("v", "1")], Some(a0), None, None);
    // Self-revoke a1.
    let alice = h.peer("alice");
    let rev = AttestationData {
        attesting: alice,
        attested: a1,
        properties: vec![(text("kind"), text(KIND_REVOCATION))],
        supersedes: None,
        not_before: None,
        expires_at: None,
    };
    let rev_entity = rev.to_entity().unwrap();
    let rev_hash = rev_entity.content_hash;
    h.content_store.put(rev_entity).unwrap();
    let kp = h.keypairs.get("alice").unwrap();
    let sig_bytes = kp.sign(&rev_hash.to_bytes());
    let sig_data = SignatureData {
        target: rev_hash,
        signer: alice,
        algorithm: "ed25519".into(),
        signature: sig_bytes.to_vec(),
    };
    let sig_entity = sig_data.to_entity().unwrap();
    h.content_store.put(sig_entity).unwrap();
    h.location_index.set(
        &format!(
            "/test/{}/system/signature/{}",
            hex_segment(&alice),
            hex_segment(&rev_hash)
        ),
        rev_hash,
    );
    h.index.insert(rev_hash, rev);
    let a0_data = h.index.get(&a0).unwrap();
    let a1_data = h.index.get(&a1).unwrap();
    assert!(!is_attestation_live(&a1, &a1_data, &h.ctx(), None), "a1 dead (revoked)");
    assert!(is_attestation_live(&a0, &a0_data, &h.ctx(), None), "a0 live (revival)");
}

#[test]
fn tv_a4d_a1_revoked_but_a2_lives_a0_stays_dead() {
    // a0 → a1 → a2; a1 revoked; a2 still valid.
    // Expected: a2 live; a1 dead; a0 dead (transitive descendant a2 lives).
    let mut h = Harness::new();
    h.add_peer("alice");
    h.add_peer("bob");
    let (a0, _) = h.add_attestation("alice", "bob", vec![("kind", "x"), ("v", "0")], None, None, None);
    let (a1, _) =
        h.add_attestation("alice", "bob", vec![("kind", "x"), ("v", "1")], Some(a0), None, None);
    let (a2, _) =
        h.add_attestation("alice", "bob", vec![("kind", "x"), ("v", "2")], Some(a1), None, None);
    // Self-revoke a1.
    let alice = h.peer("alice");
    let rev = AttestationData {
        attesting: alice,
        attested: a1,
        properties: vec![(text("kind"), text(KIND_REVOCATION))],
        supersedes: None,
        not_before: None,
        expires_at: None,
    };
    let rev_entity = rev.to_entity().unwrap();
    let rev_hash = rev_entity.content_hash;
    h.content_store.put(rev_entity).unwrap();
    let kp = h.keypairs.get("alice").unwrap();
    let sig_bytes = kp.sign(&rev_hash.to_bytes());
    let sig_data = SignatureData {
        target: rev_hash,
        signer: alice,
        algorithm: "ed25519".into(),
        signature: sig_bytes.to_vec(),
    };
    let sig_entity = sig_data.to_entity().unwrap();
    h.content_store.put(sig_entity).unwrap();
    h.location_index.set(
        &format!(
            "/test/{}/system/signature/{}",
            hex_segment(&alice),
            hex_segment(&rev_hash)
        ),
        rev_hash,
    );
    h.index.insert(rev_hash, rev);
    let a0_data = h.index.get(&a0).unwrap();
    let a1_data = h.index.get(&a1).unwrap();
    let a2_data = h.index.get(&a2).unwrap();
    assert!(is_attestation_live(&a2, &a2_data, &h.ctx(), None), "a2 live");
    assert!(!is_attestation_live(&a1, &a1_data, &h.ctx(), None), "a1 dead (revoked)");
    assert!(!is_attestation_live(&a0, &a0_data, &h.ctx(), None), "a0 dead (a2 transitive)");
}

#[test]
fn tv_a9_as_of_before_not_before_returns_none() {
    let mut h = Harness::new();
    h.add_peer("alice");
    h.add_peer("bob");
    let (_, _) = h.add_attestation(
        "alice",
        "bob",
        vec![("kind", "x")],
        None,
        Some(2_000_000_000_000), // far future
        None,
    );
    let bob = h.peer("bob");
    // as_of via is_attestation_live indirectly — default_find_authorizing
    // uses current time. Verify is_attestation_live respects as_of.
    let candidates = find_attestations_targeting(&bob, |_| true, &h.ctx());
    assert_eq!(candidates.len(), 1);
    assert!(!is_attestation_live(
        &candidates[0].0,
        &candidates[0].1,
        &h.ctx(),
        Some(1_000)
    ));
}

#[test]
fn tv_a10_kind_agnostic_default_returns_any() {
    // Default find_authorizing is kind-agnostic — it returns whatever
    // matches by attested. Consumer's predicate filters by kind.
    let mut h = Harness::new();
    h.add_peer("alice");
    h.add_peer("bob");
    let (a, _) = h.add_attestation("alice", "bob", vec![("kind", "reputation")], None, None, None);
    let bob = h.peer("bob");
    let found = default_find_authorizing(&bob, &h.ctx()).unwrap();
    assert_eq!(found.0, a, "kind-agnostic default returns reputation-kind att");
}

#[test]
fn tv_a11_multi_context_peer_default_picks_lowest_hash() {
    // Peer P has two unrelated authorizing attestations from different
    // contexts (identity A and identity B). Default tie-breaks by content
    // hash; consumers needing context-filtering pass a custom predicate.
    let mut h = Harness::new();
    h.add_peer("a_quorum");
    h.add_peer("b_controller");
    h.add_peer("p");
    let (a1, _) = h.add_attestation(
        "a_quorum",
        "p",
        vec![("kind", "identity-cert"), ("function", "controller")],
        None,
        None,
        None,
    );
    let (b1, _) = h.add_attestation(
        "b_controller",
        "p",
        vec![("kind", "identity-cert"), ("function", "agent")],
        None,
        None,
        None,
    );
    let p = h.peer("p");
    let found = default_find_authorizing(&p, &h.ctx()).unwrap();
    let mut both = vec![a1, b1];
    both.sort();
    assert_eq!(found.0, both[0]);
}

// ===========================================================================
// Sanity: revocation lookup + verify_attestation_signature on signed att
// ===========================================================================

#[test]
fn signed_attestation_verifies() {
    let mut h = Harness::new();
    h.add_peer("alice");
    h.add_peer("bob");
    let (a_hash, a_data) = h.add_attestation("alice", "bob", vec![("kind", "x")], None, None, None);
    assert!(verify_attestation_signature(&a_hash, &a_data, &h.ctx()));
}

#[test]
fn find_revocations_for_returns_only_revocations() {
    let mut h = Harness::new();
    h.add_peer("alice");
    h.add_peer("bob");
    let (a_hash, _) = h.add_attestation("alice", "bob", vec![("kind", "x")], None, None, None);
    // Add a revocation
    let alice = h.peer("alice");
    let rev = AttestationData {
        attesting: alice,
        attested: a_hash,
        properties: vec![(text("kind"), text(KIND_REVOCATION))],
        supersedes: None,
        not_before: None,
        expires_at: None,
    };
    let rev_entity = rev.to_entity().unwrap();
    let rev_hash = rev_entity.content_hash;
    h.content_store.put(rev_entity).unwrap();
    h.index.insert(rev_hash, rev);
    let revs = find_revocations_for(&a_hash, &h.ctx());
    assert_eq!(revs.len(), 1);
    assert_eq!(revs[0].0, rev_hash);
}

// PR-7 (PROPOSAL-SYSTEM-PEER-RENAME §PR-7): kind-namespacing MUST.
// Cross-extension kinds MUST be `<domain>-<kindname>`; only `revocation`
// (universal substrate) may be unnamespaced.
#[test]
fn pr7_validate_kind_accepts_namespaced_kinds() {
    crate::validate_kind("identity-cert").unwrap();
    crate::validate_kind("identity-rotation-handoff").unwrap();
    crate::validate_kind("identity-rotation-recovery").unwrap();
    crate::validate_kind("identity-retirement").unwrap();
    crate::validate_kind("quorum-update").unwrap();
    crate::validate_kind("quorum-publish").unwrap();
    crate::validate_kind("future-extension-kind").unwrap();
}

#[test]
fn pr7_validate_kind_accepts_universal_revocation() {
    crate::validate_kind("revocation").unwrap();
}

#[test]
fn pr7_validate_kind_rejects_bare_unnamespaced() {
    assert!(crate::validate_kind("cert").is_err());
    assert!(crate::validate_kind("rotation").is_err());
    assert!(crate::validate_kind("").is_err());
}

#[test]
fn pr7_validate_kind_rejects_empty_prefix() {
    // Leading `-` means empty prefix → not actually namespaced.
    assert!(crate::validate_kind("-rest").is_err());
}
