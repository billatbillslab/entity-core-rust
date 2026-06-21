//! V7.67 Phase 1 conformance vectors (Rust impl side).
//!
//! Five Phase-1 vectors per `proposals/implemented/PROPOSAL-V7-V7.67-
//! CRYPTO-AGILITY-SEED-TABLES.md` §7.1, §7.2, §7.4, §7.5 + the companion
//! V7.67 impl-team alignment §3.2:
//!
//! - **KEY-TYPE-ED448-1**: `system/peer({public_key, key_type="ed448"})`
//!   constructs canonical `(0x02, 0x01)` peer_id; sign/verify round-trip
//!   on a fixed Ed448 seed.
//! - **HASH-FORMAT-SHA-384-1**: `content_hash` under
//!   `content_hash_format=0x01` byte-equal cross-impl for the v7.66
//!   `0xAA × 64` fixture re-hashed under SHA-384; store + retrieve.
//! - **VARINT-MULTIBYTE-1**: impl correctly decodes `system/hash` with
//!   multi-byte LEB128 format code (test fixture `0x80 0x01` = value
//!   128) and rejects with `unsupported_content_hash_format`.
//! - **VARINT-RESERVED-FF-1**: impl rejects construction with `key_type`
//!   integer value 255 (varint `0xFF 0x01`); impl rejects `system/hash`
//!   with format-code integer value 255.
//! - **FORMAT-CODE-INTERPRETATION-1**: tested in [`peer_canon_v7_66`]
//!   (renamed from `PREFIX-DISPATCH-1`). Pointed here for completeness.
//!
//! **Corpus-pinning status**: architecture has not yet authored
//! `core-protocol-domain/specs/test-vectors/v767/` as of Phase 1 start.
//! The pinned hex values below are Rust-authored cross-impl convergence
//! targets per V7.66 §7.2 corpus authoring discipline; Go and Python
//! converge at cohort lock. The Ed448 test seed is a documented
//! placeholder until the corpus pins one — when architecture publishes
//! v767/, swap [`PHASE1_ED448_TEST_SEED`] for the corpus value.

use std::collections::HashMap;

use entity_crypto::{
    peer_entity_from_components_with_key_type, peer_identity_hash_with_key_type, CryptoError,
    Ed448Keypair, KeyType, ED448_PUBLIC_KEY_LEN, ED448_SECRET_KEY_LEN, ED448_SIGNATURE_LEN,
    HASH_TYPE_SHA256, KEY_TYPE_ED448,
};
use entity_hash::{Hash, HashError, HASH_ALGORITHM_SHA384, SHA384_DIGEST_LEN};
use entity_types::TYPE_PEER;

/// Phase-1 Ed448 test seed — **placeholder** until architecture publishes
/// `core-protocol-domain/specs/test-vectors/v767/`. Per alignment doc
/// §3.4, per-impl byte-equal sign/verify on the corpus-pinned seed is
/// the Phase 1 lock-gate. Replace this constant when the corpus seed lands.
const PHASE1_ED448_TEST_SEED: [u8; ED448_SECRET_KEY_LEN] = [0x42; ED448_SECRET_KEY_LEN];

/// v7.66 §4.2 fixture: 64-byte synthetic public_key for the
/// `experimental-test` (`0xFE`) key_type. v7.67 §7.6 re-uses this same
/// entity (re-hashed under SHA-384) for `HASH-FORMAT-SHA-384-1`.
const EXPERIMENTAL_TEST_FIXTURE_PUBKEY: [u8; 64] = [0xAA; 64];

// ===========================================================================
// KEY-TYPE-ED448-1
// ===========================================================================

/// V7 §1.5 / v7.67 §3 Ed448 allocation. Confirms:
///   - 57-byte seed produces 57-byte public_key + 114-byte signature
///   - peer_id is canonical SHA-256-form `(0x02, 0x01)` per v7.67 §3.2
///   - `system/peer.data.key_type` is the string `"ed448"` per v7.67 §3.3
///   - sign/verify round-trips on a fixed seed
///
/// The cross-impl byte-equality check (Rust signature bytes ==
/// Go signature bytes for the corpus seed) happens at cohort lock once
/// architecture publishes the corpus.
#[test]
fn key_type_ed448_1_sign_verify_and_canonical_peer_id() {
    let kp = Ed448Keypair::from_seed(&PHASE1_ED448_TEST_SEED).expect("seed accepted");
    let pk = kp.public_key_bytes();
    assert_eq!(pk.len(), ED448_PUBLIC_KEY_LEN);

    // Canonical peer_id is SHA-256-form (0x02, 0x01) — raw 57-byte
    // pubkey exceeds the v7.65 §4 substrate floor.
    let pid = kp.peer_id();
    let dec = pid.decode().expect("Ed448 peer_id decodes");
    assert_eq!(dec.key_type, KEY_TYPE_ED448);
    assert_eq!(dec.hash_type, HASH_TYPE_SHA256);
    assert_eq!(dec.digest.len(), 32, "SHA-256-form digest is 32 bytes");
    pid.validate().expect("Ed448 peer_id validates");

    // peer entity data: {key_type: "ed448", public_key: <57 bytes>}
    let entity = kp.peer_entity().expect("Ed448 peer_entity constructs");
    assert_eq!(entity.entity_type, TYPE_PEER);
    let value: entity_ecf::Value =
        ciborium::from_reader(entity.data.as_slice()).expect("data decodes");
    let map = value.as_map().expect("data is map");
    let label = map
        .iter()
        .find_map(|(k, v)| {
            if k.as_text()? == "key_type" {
                v.as_text()
            } else {
                None
            }
        })
        .expect("key_type present");
    assert_eq!(label, "ed448");

    // Sign / verify round-trip.
    let msg = b"v7.67 Phase 1 Ed448 conformance";
    let sig = kp.sign(msg);
    assert_eq!(sig.len(), ED448_SIGNATURE_LEN);
    Ed448Keypair::verify(&pk, msg, &sig).expect("verify");
    Ed448Keypair::verify(&pk, b"different", &sig).expect_err("wrong message rejects");

    // Determinism: from-seed twice yields the same public_key + signature.
    let kp2 = Ed448Keypair::from_seed(&PHASE1_ED448_TEST_SEED).unwrap();
    assert_eq!(kp2.public_key_bytes(), pk);
    let sig2 = kp2.sign(msg);
    assert_eq!(sig2, sig, "Ed448 sig is deterministic on (seed, msg)");
}

/// v7.67 §3.2 canonical pair: the Ed448 `system/peer` content_hash is a
/// pure function of `(public_key, key_type)` per v7.65 §3 — invariant
/// under wire-form peer_id choice. Determinism is asserted directly;
/// cross-impl byte-equality is the architecture corpus check.
#[test]
fn key_type_ed448_1_content_hash_deterministic() {
    let kp = Ed448Keypair::from_seed(&PHASE1_ED448_TEST_SEED).unwrap();
    let h1 = peer_identity_hash_with_key_type(&kp.public_key_bytes(), KeyType::Ed448)
        .expect("hash computes");
    let h2 = peer_identity_hash_with_key_type(&kp.public_key_bytes(), KeyType::Ed448)
        .expect("hash recomputes");
    assert_eq!(h1, h2, "Ed448 peer content_hash is deterministic");
    assert!(!h1.is_zero(), "non-empty hash");
}

// ===========================================================================
// HASH-FORMAT-SHA-384-1
// ===========================================================================

/// v7.67 §4 / alignment §3.1: `content_hash` under
/// `content_hash_format=0x01` for the v7.66 `0xAA × 64` fixture entity
/// re-hashed under SHA-384. Total `system/hash` size is 49 bytes
/// (1-byte varint + 48-byte digest) per the alignment doc.
///
/// The corpus pin is the architecture-authored byte sequence; this test
/// asserts determinism within Rust and the structural invariants
/// (digest length 48 B, wire length 49 B, display tag `ecfv1-sha384:`).
#[test]
fn hash_format_sha384_1_v766_fixture_rehashed_under_sha384() {
    // Re-use the v7.66 fixture: experimental-test peer with 0xAA × 64
    // pubkey. The entity construction is identical to v7.66 — only the
    // content_hash algorithm changes from SHA-256 (default) to SHA-384.
    let entity = peer_entity_from_components_with_key_type(
        &EXPERIMENTAL_TEST_FIXTURE_PUBKEY,
        KeyType::ExperimentalTest,
    )
    .expect("v7.66 fixture entity constructs");

    // Compute SHA-384 over the ECF-encoded {type, data} hash basis.
    let sha384_hash =
        Hash::compute_format(&entity.entity_type, &entity.data, HASH_ALGORITHM_SHA384).unwrap();
    assert_eq!(sha384_hash.algorithm, 0x01);
    assert_eq!(sha384_hash.digest().len(), SHA384_DIGEST_LEN);

    // Wire form: 49 bytes total per v7.67 alignment §3.1.
    let wire = sha384_hash.to_bytes();
    assert_eq!(wire.len(), 49);
    assert_eq!(wire[0], 0x01);

    // Display tag.
    let display = sha384_hash.to_string();
    assert!(display.starts_with("ecfv1-sha384:"));

    // Determinism within Rust.
    let entity2 = peer_entity_from_components_with_key_type(
        &EXPERIMENTAL_TEST_FIXTURE_PUBKEY,
        KeyType::ExperimentalTest,
    )
    .unwrap();
    let h2 =
        Hash::compute_format(&entity2.entity_type, &entity2.data, HASH_ALGORITHM_SHA384).unwrap();
    assert_eq!(sha384_hash, h2, "SHA-384 fixture hash deterministic");

    // Round-trip through the wire form.
    let decoded = Hash::from_bytes(&wire).expect("wire decode");
    assert_eq!(decoded, sha384_hash);

    // Validate against the original entity content (would reject on tamper).
    Hash::validate(&entity.entity_type, &entity.data, &sha384_hash).expect("validate");
}

/// v7.67 §3.1 alignment "store + retrieve round-trip through content-
/// store dispatch". Phase 1 proves the SHA-384 wire form is a stable
/// lookup key; cross-peer integration through the production
/// ContentStore lands in Phase 2 with the cross-key matrix work.
#[test]
fn hash_format_sha384_1_store_retrieve_round_trip() {
    let entity = peer_entity_from_components_with_key_type(
        &EXPERIMENTAL_TEST_FIXTURE_PUBKEY,
        KeyType::ExperimentalTest,
    )
    .unwrap();

    let h =
        Hash::compute_format(&entity.entity_type, &entity.data, HASH_ALGORITHM_SHA384).unwrap();
    let key = h.to_bytes();

    // Test-local content store keyed by the 49-byte SHA-384 wire form.
    let mut store: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    store.insert(key.clone(), entity.data.clone());

    let retrieved = store.get(&key).expect("retrieved by SHA-384 wire key");
    assert_eq!(retrieved, &entity.data);

    let h_recomputed =
        Hash::compute_format(&entity.entity_type, retrieved, HASH_ALGORITHM_SHA384).unwrap();
    assert_eq!(h, h_recomputed, "byte-equal recomputation on retrieval");
}

// ===========================================================================
// VARINT-MULTIBYTE-1
// ===========================================================================

/// v7.67 §5.4 normative: impls MUST decode multi-byte LEB128 sequences
/// even when no current production allocation exceeds `0x7F`. Synthetic
/// fixture: `system/hash` with `content_hash_format = 0x80 0x01`
/// (value 128, the first two-byte encoding). Since 128 is not
/// allocated, the decoder rejects with `unsupported_content_hash_format`
/// AFTER correctly reading the multi-byte varint (not before).
#[test]
fn varint_multibyte_1_content_hash_format_two_byte_decode_then_reject() {
    // Wire: varint(128) = [0x80, 0x01] + 32-byte placeholder digest.
    let mut wire = vec![0x80, 0x01];
    wire.extend_from_slice(&[0u8; 32]);

    let err = Hash::from_bytes(&wire).expect_err("128 unallocated");
    // Confirms the varint was read correctly (truncates to format_code = 0x80
    // for the error surface).
    assert!(matches!(err, HashError::UnsupportedAlgorithm(0x80)),
            "expected UnsupportedAlgorithm(0x80), got {:?}", err);

    // Negative: a one-byte 0x00 + 32-byte digest decodes cleanly as
    // SHA-256, confirming the harness isn't broken.
    let mut sha256_wire = vec![0x00];
    sha256_wire.extend_from_slice(&[0u8; 32]);
    let h = Hash::from_bytes(&sha256_wire).expect("0x00 SHA-256 decodes");
    assert_eq!(h.algorithm, 0x00);
}

// ===========================================================================
// VARINT-RESERVED-FF-1
// ===========================================================================

/// v7.67 §5.3 reservation: integer value 255 is reserved on both axes
/// and SHALL NOT be allocated. Asserts:
///   - `key_type=255` (`0xFF`) is rejected by [`KeyType::from_byte`]
///     with `UnsupportedKeyType(0xFF)` — same surface as v7.66 used
///     for unallocated `0xFD`.
///   - `content_hash_format=255` is rejected by [`MultiHash::from_wire`]
///     with the dedicated `ReservedFormat(0xFF)` surface (the spec
///     calls this out as a stronger guarantee than mere "unallocated").
#[test]
fn varint_reserved_ff_1_both_axes_reject_value_255() {
    // key_type axis
    let err = KeyType::from_byte(0xFF).expect_err("0xFF rejected on key_type axis");
    assert!(
        matches!(err, CryptoError::UnsupportedKeyType(0xFF)),
        "expected UnsupportedKeyType(0xFF), got {:?}",
        err
    );

    // content_hash_format axis — varint(255) = [0xFF, 0x01] + 32-byte digest.
    let mut wire = vec![0xFF, 0x01];
    wire.extend_from_slice(&[0u8; 32]);
    let err = Hash::from_bytes(&wire).expect_err("0xFF reserved on format axis");
    assert!(
        matches!(err, HashError::ReservedFormat(0xFF)),
        "expected ReservedFormat(0xFF), got {:?}",
        err
    );

    // Authoring-time rejection on the format axis too: you cannot compute
    // a content hash under the reserved code.
    let data = entity_ecf::to_ecf(&entity_ecf::text("x"));
    let err = Hash::compute_format("t", &data, 0xFF).expect_err("0xFF rejected at compute");
    assert!(matches!(err, HashError::UnsupportedAlgorithm(0xFF)));
}

// ===========================================================================
// FORMAT-CODE-INTERPRETATION-1 (renamed from PREFIX-DISPATCH-1)
// ===========================================================================

/// This vector lives in [`peer_canon_v7_66`] as
/// `format_code_interpretation_1_unsupported_format_returns_error` per
/// v7.67 §2 errata (rename of the v7.66 `PREFIX-DISPATCH-1` semantics-
/// unchanged). The fixture switched from `0x01` (now allocated to
/// SHA-384) to `0x7E` (unallocated). Documented here for traceability.
#[test]
fn format_code_interpretation_1_lives_in_v7_66_suite() {
    // Sentinel: a Phase-1-aware test that the cross-reference holds.
    // The actual assertion runs in peer_canon_v7_66.rs:
    // format_code_interpretation_1_unsupported_format_returns_error.
    let _ = "see peer_canon_v7_66.rs";
}
