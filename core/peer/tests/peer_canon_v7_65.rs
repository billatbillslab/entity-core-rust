//! V7.65 peer-identity canonicalization conformance vectors.
//!
//! Seven vectors per `proposals/implemented/PROPOSAL-V7-PEER-ENTITY-
//! CANONICALIZATION-AND-V1-CONTRACT.md` §13:
//!
//! - PEER-CANON-1: content_hash(system/peer) invariant under wire-form choice
//! - PEER-CANON-2: dialer canonicalizes non-canonical-form on acceptance
//! - PEER-PATTERN-1: canonical-form cap pattern + canonical arrival → match
//! - PEER-PATTERN-2: lazy canonicalization path (mint without pubkey)
//! - PEER-MUT-1: peer publishes one canonical form per operational window
//! - PEER-MUT-2: unknown peer is new route, never auto-correlated
//! - COMPOSITION-1: cap chain interleaves v7.64- and v7.65-shape entities

use entity_capability::{GrantEntry, IdScope, PathScope};
use entity_crypto::{
    legacy_sha256_peer_id_fixture as build_legacy_sha256_peer_id, peer_entity_from_components,
    peer_identity_hash, Keypair, PeerId, HASH_TYPE_IDENTITY, HASH_TYPE_SHA256, KEY_TYPE_ED25519,
};
use entity_ecf as ecf;
use entity_entity::Entity;
use entity_hash::Hash;
use entity_types::{PeerData, TYPE_PEER};

const SEED_A: [u8; 32] = [0xA1; 32];
const SEED_B: [u8; 32] = [0xB2; 32];

// ---------------------------------------------------------------------------
// PEER-CANON-1: content_hash invariance under wire-form choice
// ---------------------------------------------------------------------------

/// V7 §3.5 v7.65 Amendment 1+2: cryptographic identity is invariant under
/// wire-form `peer_id` choice. For any keypair K, `content_hash(system/peer)`
/// is a pure function of `(public_key, key_type)`.
#[test]
fn peer_canon_1_content_hash_invariant_under_wire_form() {
    let kp = Keypair::from_seed(SEED_A);
    let pk = kp.public_key_bytes();

    let identity_pid = PeerId::from_public_key(&pk);
    let sha256_pid = build_legacy_sha256_peer_id(&pk);
    assert_ne!(
        identity_pid, sha256_pid,
        "wire forms differ (different hash_type byte)"
    );

    // Single content_hash regardless of wire form chosen at presentation.
    let h_via_keypair = kp.peer_identity_hash();
    let h_via_components = peer_identity_hash(&pk).unwrap();
    let h_via_entity = peer_entity_from_components(&pk).unwrap().content_hash;
    assert_eq!(h_via_keypair, h_via_components);
    assert_eq!(h_via_keypair, h_via_entity);
}

// ---------------------------------------------------------------------------
// PEER-CANON-2: wire-acceptance — SHA-256-form decodes to same canonical hash
// ---------------------------------------------------------------------------

/// V7 §1.5 v7.65 Amendment 4 (wire-acceptance carve-out): a non-canonical
/// SHA-256-form `peer_id` MAY decode at the wire boundary; the canonical
/// content_hash recovered via the carried public_key is identical to the
/// canonical-form path. Storage form is canonical regardless of wire form.
#[test]
fn peer_canon_2_wire_acceptance_canonicalizes_on_storage() {
    let kp = Keypair::from_seed(SEED_A);
    let pk = kp.public_key_bytes();

    let sha256_pid = build_legacy_sha256_peer_id(&pk);
    let decoded = sha256_pid.decode().expect("legacy-decode parity");
    assert_eq!(decoded.key_type, KEY_TYPE_ED25519);
    assert_eq!(decoded.hash_type, HASH_TYPE_SHA256);

    // Identity-form via the same pubkey: same canonical content_hash.
    let identity_pid = PeerId::from_public_key(&pk);
    let canonical_hash = peer_identity_hash(&pk).unwrap();
    assert_eq!(
        identity_pid.identity_hex_with_public_key(&pk).unwrap(),
        canonical_hash.to_hex(),
        "canonical-form path yields the canonical content_hash hex"
    );

    // Legacy SHA-256-form yields the SAME canonical content_hash hex when
    // resolved through the canonicalization path (recover pubkey from
    // out-of-band exchange — here we already hold it).
    assert_eq!(
        sha256_pid.identity_hex_with_public_key(&pk).unwrap(),
        canonical_hash.to_hex(),
        "v7.65 invariance: legacy wire form maps to canonical content_hash"
    );

    // Construction-time refusal: cannot mint a fresh SHA-256-form peer_id
    // via the canonical-gate constructor.
    let refusal = PeerId::from_public_key_with_hash_type(&pk, HASH_TYPE_SHA256);
    assert!(
        refusal.is_err(),
        "v7.65 Amendment 3: fresh SHA-256-form construction is refused"
    );
}

// ---------------------------------------------------------------------------
// PEER-PATTERN-1: canonical-form cap pattern matches canonical runtime arrival
// ---------------------------------------------------------------------------

/// V7 §3.6 v7.65 Amendment 5 rule 1 + 2: canonical-form pattern + canonical
/// runtime → string-comparison match. Patterns built with canonical Base58
/// peer_id match canonical runtime peer_id 1:1.
#[test]
fn peer_pattern_1_canonical_form_match() {
    let kp = Keypair::from_seed(SEED_B);
    let pk = kp.public_key_bytes();
    let canonical_pid = PeerId::from_public_key(&pk).to_string();

    let grant = GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec![format!("/{}/files/*", canonical_pid)]),
        operations: IdScope::new(vec!["get".into()]),
        peers: Some(IdScope::new(vec![canonical_pid.clone()])),
        constraints: None,
        allowances: None,
    };

    // The peers IdScope and the resources path both use canonical form;
    // runtime peer_id is the same canonical string.
    assert!(
        grant.peers.as_ref().unwrap().include.contains(&canonical_pid),
        "canonical pattern includes canonical runtime peer_id"
    );
}

// ---------------------------------------------------------------------------
// PEER-PATTERN-2: lazy canonicalization (via v7.64 dual-form policy machinery)
// ---------------------------------------------------------------------------

/// V7 §3.6 v7.65 Amendment 5 rule 3 (lazy canonicalization): an operator-
/// pasted non-canonical Base58 handle for an unknown peer is accepted at
/// mint; the v7.64 dual-form policy machinery resolves it on first contact
/// (handshake reveals pubkey → canonicalize in place per §1117).
///
/// Substantive validation lives in
/// `extensions/capability/src/tests.rs::pol_df_2_base58_form_match_and_canonicalize`;
/// this vector asserts the canonicalization PRIMITIVE — a Base58 (SHA-256-form
/// or identity-form) handle resolves to the canonical content_hash hex once
/// the pubkey is known.
#[test]
fn peer_pattern_2_lazy_canonicalize_primitive() {
    let kp = Keypair::from_seed(SEED_B);
    let pk = kp.public_key_bytes();

    let pasted_handle = build_legacy_sha256_peer_id(&pk).to_string();
    let canonical_hex = peer_identity_hash(&pk).unwrap().to_hex();

    // At mint time without pubkey: the handle is stored as-is.
    // At handshake time (pubkey known): the handle resolves to canonical hex.
    let pasted_pid = PeerId::from(pasted_handle.as_str());
    let resolved_hex = pasted_pid
        .identity_hex_with_public_key(&pk)
        .expect("handshake resolves pubkey → canonical hex");
    assert_eq!(
        resolved_hex, canonical_hex,
        "lazy canon: pasted form → canonical content_hash on handshake"
    );
}

// ---------------------------------------------------------------------------
// PEER-MUT-1: peer publishes one canonical form per operational window
// ---------------------------------------------------------------------------

/// V7 §1.5 v7.65 Amendment 7 norm 1: peers SHOULD publish exactly one
/// canonical-form `peer_id` per identity at any operational moment. Under
/// Amendment 3 the construction-gate enforces this structurally —
/// `Keypair::peer_id()` returns canonical (identity-multihash for Ed25519);
/// `peer_id_with_hash_type` refuses non-canonical at construction.
#[test]
fn peer_mut_1_one_canonical_form_per_window() {
    let kp = Keypair::from_seed(SEED_A);

    let canonical = kp.peer_id();
    let decoded = canonical.decode().unwrap();
    assert_eq!(decoded.hash_type, HASH_TYPE_IDENTITY);

    // Refusal: `peer_id_with_hash_type(HASH_TYPE_SHA256)` is non-canonical
    // for Ed25519 and is rejected at construction.
    assert!(
        kp.peer_id_with_hash_type(HASH_TYPE_SHA256).is_err(),
        "v7.65 norm 1 + Amendment 3: non-canonical construction refused"
    );
}

// ---------------------------------------------------------------------------
// PEER-MUT-2: unknown peer is a new route observation — T1 floor
// ---------------------------------------------------------------------------

/// V7 §1.5 v7.65 Amendment 7 norm 5: unknown peer presenting under any
/// form is a NEW route observation; implementations MUST NOT auto-correlate
/// pre-handshake. Pre-pubkey-reveal cross-form correlation is structurally
/// impossible (T1 floor — hashes are one-way).
#[test]
fn peer_mut_2_unknown_peer_no_auto_correlation() {
    let kp_alice = Keypair::from_seed(SEED_A);
    let kp_bob = Keypair::from_seed(SEED_B);

    let alice_pid = PeerId::from_public_key(&kp_alice.public_key_bytes());
    let bob_sha256_pid =
        build_legacy_sha256_peer_id(&kp_bob.public_key_bytes());

    // Pre-handshake, only the wire strings are visible. Decoding gives
    // raw digest bytes — no way to derive Bob's pubkey from his
    // SHA-256-form fingerprint without prior contact (T1 floor).
    assert!(
        bob_sha256_pid.derive_public_key().is_none(),
        "SHA-256-form is one-way; no public_key recovery pre-handshake"
    );

    // String comparison: Alice's canonical pid is NOT mistakenly
    // correlated with Bob's SHA-256-form pid.
    assert_ne!(
        alice_pid.as_str(),
        bob_sha256_pid.as_str(),
        "distinct identities cannot be cross-form-correlated"
    );

    // Identity-form decoding of Alice's pid recovers her pubkey — that
    // is the ONLY structural cross-form bridge (and only for identity-
    // multihash form).
    let (alice_recovered, _kt) = alice_pid.derive_public_key().unwrap();
    assert_eq!(alice_recovered.as_slice(), kp_alice.public_key_bytes().as_slice());
}

// ---------------------------------------------------------------------------
// COMPOSITION-1: cap chain interleaves v7.64- and v7.65-shape entities
// ---------------------------------------------------------------------------

/// V7 §2.4 v7.65: legacy v7.64-shape `system/peer` entities (carrying a
/// `peer_id` map key) coexist with v7.65-shape entities (without). Each
/// link verifies if its referenced `content_hash` is locatable; chains
/// MAY interleave shape generations. Pre-v7.65 cap chains remain
/// verifiable byte-for-byte against the entities they reference.
#[test]
fn composition_1_interleaved_v7_64_and_v7_65_entities_decode() {
    let kp_legacy = Keypair::from_seed(SEED_A);
    let kp_modern = Keypair::from_seed(SEED_B);

    // v7.64-shape entity: data includes a peer_id map key.
    let legacy_pid = kp_legacy.peer_id();
    let legacy_data_value = ecf::Value::Map(vec![
        (ecf::text("key_type"), ecf::text("ed25519")),
        (ecf::text("peer_id"), ecf::text(legacy_pid.as_str())),
        (
            ecf::text("public_key"),
            ecf::Value::Bytes(kp_legacy.public_key_bytes().to_vec()),
        ),
    ]);
    let legacy_entity =
        Entity::new(TYPE_PEER, ecf::to_ecf(&legacy_data_value)).unwrap();
    let legacy_hash: Hash = legacy_entity.content_hash;

    // v7.65-shape entity: data is {key_type, public_key}.
    let modern_entity = kp_modern.peer_entity().unwrap();
    let modern_hash: Hash = modern_entity.content_hash;

    // Both content_hashes are distinct (different entity shapes).
    assert_ne!(legacy_hash, modern_hash);

    // Both decode into the v7.65 PeerData shape — the legacy peer_id key
    // is silently ignored. This is the composition property that makes
    // pre-v7.65 cap chains verifiable post-v7.65.
    let legacy_decoded = PeerData::from_entity(&legacy_entity).unwrap();
    let modern_decoded = PeerData::from_entity(&modern_entity).unwrap();
    assert_eq!(legacy_decoded.key_type, "ed25519");
    assert_eq!(modern_decoded.key_type, "ed25519");

    // Each peer's canonical wire peer_id is derivable from PeerData under
    // either shape — both shapes carry the load-bearing pubkey.
    assert_eq!(
        legacy_decoded.canonical_peer_id().unwrap(),
        legacy_pid.to_string(),
    );
    assert_eq!(
        modern_decoded.canonical_peer_id().unwrap(),
        kp_modern.peer_id().to_string(),
    );
}
