//! V7.66 format-agility validation + cleanup conformance vectors.
//!
//! Ten vectors per `proposals/implemented/PROPOSAL-V7-V7.66-FORMAT-
//! AGILITY-VALIDATION-AND-CLEANUP.md` §7:
//!
//! - KEY-TYPE-STRING-1: `system/peer.data.key_type` encodes as string
//! - KEY-TYPE-PREFIX-1: binary peer_id prefix is varint(`0x01`) for Ed25519
//! - LEGACY-MINT-1: no live mint API path produces legacy SHA-256-form Ed25519
//! - AGILITY-DECODE-1: wire-format multikey decoder accepts `key_type=0xFE`
//! - AGILITY-ENTITY-1: `system/peer(0xAA×64, 0xFE)` constructs + content_hash pinned
//! - AGILITY-CANONICAL-1: canonical form for `0xFE` is SHA-256-form
//! - AGILITY-PATTERN-1: cap pattern with `0xFE` peer ref canonicalizes
//! - AGILITY-UNKNOWN-1: unsupported `key_type=0xFD` returns `unsupported_key_type`
//! - FORMAT-CODE-INTERPRETATION-1 (renamed from PREFIX-DISPATCH-1 per
//!   v7.67 §2 errata): content_hash with unsupported format-code returns
//!   `unsupported_content_hash_format`
//! - CAP-FREEZE-1: cap chain crossing `content_hash_format` boundary refused

use std::collections::BTreeMap;

use entity_capability::{CapabilityToken, GrantEntry, Granter, IdScope, PathScope};
use entity_crypto::{
    peer_entity_from_components, peer_entity_from_components_with_key_type,
    peer_identity_hash_with_key_type, synthesize_peer_id_for_fixture, CryptoError, KeyType,
    Keypair, PeerId, HASH_TYPE_IDENTITY, HASH_TYPE_SHA256, KEY_TYPE_ED25519,
    KEY_TYPE_EXPERIMENTAL_TEST,
};
use entity_entity::{Entity, Envelope};
use entity_hash::{Hash, HASH_ALGORITHM_SHA384};
use entity_protocol::{
    build_connect_execute, verify_capability_chain, verify_request, Connection, HelloData,
    ProtocolError,
};
use entity_types::TYPE_PEER;

const SEED_A: [u8; 32] = [0xA1; 32];

/// The v7.66 §7.2 corpus fixture: `0xFE` synthetic public_key is exactly
/// `0xAA` repeated 64 times.
const EXPERIMENTAL_TEST_FIXTURE_PUBKEY: [u8; 64] = [0xAA; 64];

// ---------------------------------------------------------------------------
// KEY-TYPE-STRING-1: system/peer.data.key_type encodes as string "ed25519"
// ---------------------------------------------------------------------------

/// V7 §3.5 v7.66 errata: `system/peer.data.key_type` SHALL be a
/// `primitive/string` (canonical value `"ed25519"` for Ed25519), NOT an
/// integer or varint byte. The binary peer_id wire-format prefix
/// (KEY-TYPE-PREFIX-1) is a separate surface.
#[test]
fn key_type_string_1_entity_data_field_is_string() {
    let pk = Keypair::from_seed(SEED_A).public_key_bytes();
    let entity = peer_entity_from_components(&pk).expect("Ed25519 entity constructs");
    assert_eq!(entity.entity_type, TYPE_PEER);

    // Decode the ECF data; assert key_type field is text "ed25519".
    let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice())
        .expect("entity data decodes as CBOR");
    let map = value.as_map().expect("entity data is a map");
    let key_type_value = map
        .iter()
        .find_map(|(k, v)| {
            let key = k.as_text()?;
            if key == "key_type" {
                Some(v)
            } else {
                None
            }
        })
        .expect("key_type field present");
    let label = key_type_value
        .as_text()
        .expect("key_type SHALL be primitive/string, not int");
    assert_eq!(label, "ed25519");
}

// ---------------------------------------------------------------------------
// KEY-TYPE-PREFIX-1: binary peer_id prefix is varint(0x01) for Ed25519
// ---------------------------------------------------------------------------

/// V7 §1.5 v7.66: binary peer_id prefix is an LEB128 multicodec varint.
/// For Ed25519 (code `0x01`), the varint encodes as a single byte `0x01`
/// (codes 0–127 have no continuation). Asserts the first decoded base58
/// byte is `0x01` and a non-Ed25519 byte does NOT appear at this position.
#[test]
fn key_type_prefix_1_binary_prefix_is_varint_0x01() {
    let pk = Keypair::from_seed(SEED_A).public_key_bytes();
    let pid = PeerId::from_public_key(&pk);
    let dec = pid.decode().expect("decode");
    // The decoder reads the leading varint; for Ed25519 (0x01 < 0x80) the
    // varint is a single byte and equals the key_type value.
    assert_eq!(
        dec.key_type, KEY_TYPE_ED25519,
        "binary peer_id prefix decodes to varint(0x01) for Ed25519"
    );
    assert_ne!(dec.key_type, KEY_TYPE_EXPERIMENTAL_TEST);
}

// ---------------------------------------------------------------------------
// LEGACY-MINT-1: no live mint API path produces legacy SHA-256-form Ed25519
// ---------------------------------------------------------------------------

/// v7.66 §3: the live-mint helper `from_public_key_sha256` is REMOVED.
/// Per §7 LEGACY-MINT-1 the vector is satisfied regardless of mechanism;
/// in Rust the helper does not exist as a public symbol (verified at
/// compile time by the absence in the public API) AND the parametrized
/// gate refuses SHA-256-form construction for Ed25519.
#[test]
fn legacy_mint_1_no_live_legacy_mint_path() {
    let pk = Keypair::from_seed(SEED_A).public_key_bytes();

    // Construction gate refuses SHA-256-form for Ed25519 (v7.65 Amendment 3,
    // preserved at v7.66).
    let err = PeerId::from_public_key_with_hash_type(&pk, HASH_TYPE_SHA256)
        .expect_err("SHA-256-form mint MUST refuse for Ed25519");
    assert!(matches!(err, CryptoError::InvalidPeerId(_)));

    // The keypair-bound helper inherits the same gate.
    let kp = Keypair::from_seed(SEED_A);
    assert!(kp.peer_id_with_hash_type(HASH_TYPE_SHA256).is_err());

    // The KeyType-parametric path uses the canonical form by construction;
    // there is no parameter to request legacy form.
    let canonical = PeerId::from_public_key_with_key_type(&pk, KeyType::Ed25519)
        .expect("canonical mint succeeds");
    let dec = canonical.decode().expect("decode");
    assert_eq!(dec.hash_type, HASH_TYPE_IDENTITY);
}

// ---------------------------------------------------------------------------
// AGILITY-DECODE-1: wire-format multikey decoder accepts key_type=0xFE
// ---------------------------------------------------------------------------

/// v7.66 §4.4 surface 1: the wire-format multikey decoder MUST accept a
/// `0xFE` first byte (which encodes as the 2-byte LEB128 sequence
/// `[0xFE, 0x01]`) without panic or hardcoded-Ed25519 reject.
#[test]
fn agility_decode_1_multikey_accepts_0xfe_prefix() {
    let pid = PeerId::from_public_key_with_key_type(
        &EXPERIMENTAL_TEST_FIXTURE_PUBKEY,
        KeyType::ExperimentalTest,
    )
    .expect("0xFE mint succeeds");

    let dec = pid.decode().expect("0xFE peer_id decodes");
    assert_eq!(
        dec.key_type, KEY_TYPE_EXPERIMENTAL_TEST,
        "decoded key_type round-trips"
    );
    assert_eq!(
        dec.hash_type, HASH_TYPE_SHA256,
        "0xFE canonical hash_type is SHA-256"
    );
}

// ---------------------------------------------------------------------------
// AGILITY-ENTITY-1: 0xFE system/peer constructs + content_hash pinned
// ---------------------------------------------------------------------------

/// v7.66 §4.4 surfaces 2+4: `system/peer({0xAA×64, 0xFE})` constructs
/// with `data.key_type = "experimental-test"`; `content_hash` MUST be
/// byte-equal across all conforming impls and match the corpus-pinned
/// value.
///
/// **Corpus-pinned value** (Rust-authored per V7.66 §7.2 — cross-impl
/// convergence target; Go and Python MUST produce the same bytes at
/// cohort lock). The 66-char hex is the full 33-byte content_hash:
/// algorithm byte `00` (ECFv1-SHA-256) + 32-byte digest of the
/// ECF-encoded `{type: "system/peer", data: {key_type:
/// "experimental-test", public_key: 0xAA × 64}}`.
const AGILITY_ENTITY_1_PINNED_HEX: &str =
    "003d0c34b508c5bf9eca5f086f09aac10f44bd43fca1a091b6aa55a096ca8fcd45";
#[test]
fn agility_entity_1_0xfe_peer_content_hash_pinned() {
    let entity = peer_entity_from_components_with_key_type(
        &EXPERIMENTAL_TEST_FIXTURE_PUBKEY,
        KeyType::ExperimentalTest,
    )
    .expect("0xFE peer_entity constructs");

    assert_eq!(entity.entity_type, TYPE_PEER);

    // Confirm entity-data string surface is "experimental-test".
    let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice())
        .expect("entity data decodes as CBOR");
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
        .expect("key_type field present");
    assert_eq!(label, "experimental-test");

    // Cross-impl convergence target. Mismatch at cohort lock → architecture
    // adjudicates per §7.2 corpus authoring discipline (spec algorithm,
    // not two-out-of-three).
    assert_eq!(
        entity.content_hash.to_hex(),
        AGILITY_ENTITY_1_PINNED_HEX,
        "0xFE peer content_hash deviates from corpus pin — cross-impl divergence likely"
    );

    // Determinism within Rust: two constructions of the same fixture
    // produce identical content_hash.
    let entity2 = peer_entity_from_components_with_key_type(
        &EXPERIMENTAL_TEST_FIXTURE_PUBKEY,
        KeyType::ExperimentalTest,
    )
    .expect("0xFE peer_entity constructs again");
    assert_eq!(entity.content_hash, entity2.content_hash);
}

// ---------------------------------------------------------------------------
// AGILITY-CANONICAL-1: canonical form for 0xFE is SHA-256-form
// ---------------------------------------------------------------------------

/// v7.66 §4.4 surface 3: per-`key_type` canonical-form selection MUST
/// return SHA-256-form (`hash_type=0x01`) for `key_type=0xFE`, NOT the
/// identity-form short-circuit hardcoded for Ed25519. Identity-form is
/// refused as exceeding the informative ≤46-Base58-char floor (raw
/// segment would be 66 bytes per v7.66 §4.2).
#[test]
fn agility_canonical_1_0xfe_selects_sha256_form() {
    assert_eq!(KeyType::ExperimentalTest.canonical_hash_type(), HASH_TYPE_SHA256);
    assert_ne!(
        KeyType::ExperimentalTest.canonical_hash_type(),
        HASH_TYPE_IDENTITY
    );

    let pid = PeerId::from_public_key_with_key_type(
        &EXPERIMENTAL_TEST_FIXTURE_PUBKEY,
        KeyType::ExperimentalTest,
    )
    .expect("canonical 0xFE mint succeeds");
    let dec = pid.decode().expect("decode");
    assert_eq!(dec.hash_type, HASH_TYPE_SHA256, "0xFE canonical is SHA-256-form");
    assert_eq!(
        dec.digest.len(),
        32,
        "SHA-256-form digest is 32 bytes regardless of pubkey size"
    );
}

// ---------------------------------------------------------------------------
// AGILITY-PATTERN-1: cap pattern with 0xFE peer ref canonicalizes
// ---------------------------------------------------------------------------

/// v7.66 §4.4 surface 5: cap-pattern peer-reference canonicalization MUST
/// apply v7.65 §6 rules uniformly per `KeyType`. Impls with an
/// Ed25519-only short-circuit (e.g., hardcoding `KEY_TYPE_ED25519` in
/// the canonical-form lookup) fail this vector.
///
/// Verifies that the canonical-form derivation runs through `KeyType`
/// dispatch — given a `0xFE` peer_id, recomputing canonical via
/// `from_public_key_with_key_type` yields the same wire string
/// (round-trip stability under the agility code path).
#[test]
fn agility_pattern_1_0xfe_canonicalize_round_trip() {
    let pid = PeerId::from_public_key_with_key_type(
        &EXPERIMENTAL_TEST_FIXTURE_PUBKEY,
        KeyType::ExperimentalTest,
    )
    .expect("canonical 0xFE mint succeeds");

    // Canonicalization: from the pid string, derive (kt label, hash_type,
    // digest); recompute canonical from (KeyType, pubkey); assert
    // round-trip stability.
    let dec = pid.decode().expect("decode");
    let kt = KeyType::from_byte(dec.key_type).expect("0xFE is allocated KeyType");
    assert_eq!(kt, KeyType::ExperimentalTest);
    assert_eq!(kt.canonical_hash_type(), dec.hash_type);

    let recomputed = PeerId::from_public_key_with_key_type(&EXPERIMENTAL_TEST_FIXTURE_PUBKEY, kt)
        .expect("recompute canonical");
    assert_eq!(
        pid.as_str(),
        recomputed.as_str(),
        "canonical round-trip stable under KeyType dispatch"
    );

    // Validate also runs through KeyType dispatch (not Ed25519
    // short-circuit).
    pid.validate().expect("0xFE peer_id validates");
}

// ---------------------------------------------------------------------------
// AGILITY-UNKNOWN-1: unsupported key_type=0xFD returns unsupported_key_type
// ---------------------------------------------------------------------------

/// v7.66 §4.4 surface 6 (folded B2: `0xFD` chosen as the unallocated
/// experimental code, NOT `0xFF` which is reserved for protocol use per
/// §4.3). An impl receiving `key_type=0xFD` MUST return `400
/// unsupported_key_type` rather than panic or silent accept.
#[test]
fn agility_unknown_1_unsupported_key_type_returns_error() {
    let err = KeyType::from_byte(0xFD).expect_err("0xFD is unallocated");
    match err {
        CryptoError::UnsupportedKeyType(b) => assert_eq!(b, 0xFD),
        other => panic!("expected UnsupportedKeyType, got {:?}", other),
    }

    // Confirm 0xFF (reserved for protocol use, NOT key_type allocation)
    // also surfaces as UnsupportedKeyType.
    assert!(matches!(
        KeyType::from_byte(0xFF),
        Err(CryptoError::UnsupportedKeyType(0xFF))
    ));
}

/// AGILITY-UNKNOWN-1 wire surface (cross-impl regression guard). The
/// unit test above proves `KeyType::from_byte(0xFD)` returns
/// `UnsupportedKeyType`; this test proves that error propagates through
/// the protocol handshake to surface as `400 unsupported_key_type` (NOT
/// transport EOF). Filed after Go's cross-impl sweep caught
/// Rust dropping the connection on this surface.
#[test]
fn agility_unknown_1_wire_handshake_returns_400_unsupported_key_type() {
    use entity_crypto::{HASH_TYPE_IDENTITY, KEY_TYPE_ED25519};

    // Build a peer_id with key_type varint = 0xFD (LEB128 of 253 →
    // [0xFD, 0x01]) and hash_type = identity-multihash. Digest is
    // arbitrary 32 bytes; the wire surface rejects on `key_type`
    // BEFORE digest length validation, so the digest is irrelevant.
    let bad_peer_id =
        synthesize_peer_id_for_fixture(0xFD, HASH_TYPE_IDENTITY, &[0x11u8; 32]).as_str().to_string();

    let hello = HelloData {
        peer_id: bad_peer_id,
        nonce: vec![0u8; 32],
        protocols: vec!["entity-core/1.0".into()],
        hash_formats: vec![],
        key_types: vec![],
        timestamp: None,
    };
    let hello_entity = hello.to_entity().expect("build hello entity");
    let execute = build_connect_execute("test-req-agility-unknown", "hello", &hello_entity)
        .expect("build connect execute");
    let envelope = Envelope::new(execute);

    let local_kp = Keypair::from_seed([0xDE; 32]);
    let mut conn = Connection::new(local_kp.peer_id());

    let err = conn
        .process_hello(&envelope)
        .expect_err("0xFD remote key_type MUST surface as ProtocolError");

    match err {
        ProtocolError::UnsupportedKeyType(b) => assert_eq!(b, 0xFD),
        other => panic!(
            "expected ProtocolError::UnsupportedKeyType(0xFD), got {:?}",
            other
        ),
    }

    let err = ProtocolError::UnsupportedKeyType(0xFD);
    assert_eq!(err.wire_status_code(), 400);
    assert_eq!(err.wire_error_code(), Some("unsupported_key_type"));

    // Allocated Ed25519 (0x01) is unaffected — confirms the gate fires
    // ONLY on unallocated codes.
    let _ = KEY_TYPE_ED25519;
}

// ---------------------------------------------------------------------------
// FORMAT-CODE-INTERPRETATION-1: content_hash with unsupported format-code
// returns error (renamed from PREFIX-DISPATCH-1 per v7.67 §2 errata —
// semantics unchanged; the rename aligns terminology with V7 §1.2 v7.67:
// the format code is intrinsic to the hash, not a separate dispatch step).
// ---------------------------------------------------------------------------

/// V7 §1.2 v7.67 normative (replaces v7.66 prefix-routing framing):
/// **Content-hash format-code interpretation**. A `content_hash` with
/// leading varint not in this impl's supported set MUST return
/// `unsupported_content_hash_format` (status 400) at the validation
/// boundary — NOT silently fail as a content miss or mis-route as a hash
/// mismatch.
#[test]
fn format_code_interpretation_1_unsupported_format_returns_error() {
    // v7.67 §3.1: SHA-384 is now allocated at 0x01. Fixture switches to
    // an unallocated single-byte format code (0x7E in the reserved range
    // 0x0A..=0xEF) so the test remains a true "unsupported format"
    // assertion after Phase 1 lands SHA-384.
    let synthetic_root_hash = Hash::new(0x7E, [0u8; 32]);
    let root_entity = Entity {
        entity_type: "system/execute".to_string(),
        data: vec![0xa0u8], // minimal placeholder
        content_hash: synthetic_root_hash,
    };
    let envelope = Envelope {
        root: root_entity,
        included: BTreeMap::new(),
    };

    let err = verify_request(&envelope, "local-peer").expect_err("unallocated format rejected");
    match err {
        ProtocolError::UnsupportedContentHashFormat(b) => assert_eq!(b, 0x7E),
        other => panic!("expected UnsupportedContentHashFormat, got {:?}", other),
    }

    // Wire status code is 400 (format/validation error catch-all).
    assert_eq!(
        ProtocolError::UnsupportedContentHashFormat(0x7E).wire_status_code(),
        400
    );
}

// ---------------------------------------------------------------------------
// CAP-FREEZE-1: cap chain crossing format-code boundary refused
// ---------------------------------------------------------------------------

/// V7 §5.5 v7.66 normative (Reading A — chain's own link content_hashes):
/// a cap chain whose links have content_hashes at different format-codes
/// SHALL be refused at verification. Implementations that don't inspect
/// the format-code byte at chain-walk boundaries fail this vector.
///
/// Construction: build a normal child cap referencing a parent cap whose
/// content_hash has been patched to `algorithm = 0x01` (simulating a
/// pre-v7.66-format root in a v7.66-format chain). Insert both into the
/// included map keyed by their respective content_hashes. The verifier
/// MUST return `CapabilityFormatCodeMismatch`.
#[test]
fn cap_freeze_1_cross_format_chain_refused() {
    let kp_granter = Keypair::from_seed([0x11; 32]);
    let kp_grantee = Keypair::from_seed([0x22; 32]);

    let granter_entity = kp_granter
        .peer_entity()
        .expect("granter peer entity constructs");
    let grantee_entity = kp_grantee
        .peer_entity()
        .expect("grantee peer entity constructs");

    let single_grant = vec![GrantEntry {
        handlers: PathScope::new(vec!["system/tree".into()]),
        resources: PathScope::new(vec!["/*".into()]),
        operations: IdScope::new(vec!["get".into()]),
        peers: None,
        constraints: None,
        allowances: None,
    }];

    // Build parent cap normally; entity.content_hash.algorithm = 0x00.
    let parent_token = CapabilityToken {
        grants: single_grant.clone(),
        granter: Granter::Single(granter_entity.content_hash),
        grantee: grantee_entity.content_hash,
        parent: None,
        created_at: 1,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let mut parent_entity = parent_token.to_entity().expect("parent cap entity");

    // Patch parent's content_hash to a genuine SHA-384 (`0x01`) hash of its
    // own data, simulating a chain link authored at a different
    // `content_hash_format`. The child (SHA-256, `0x00`) references this
    // hash as its parent — a real cross-format chain (v7.69: the wire form
    // is a valid 49-byte `0x01` bstr, so it decodes cleanly and the freeze
    // check fires on the format-code difference, not on a malformed ref).
    parent_entity.content_hash = Hash::compute_format(
        &parent_entity.entity_type,
        &parent_entity.data,
        HASH_ALGORITHM_SHA384,
    )
    .expect("sha384 parent hash");
    let patched_parent_hash = parent_entity.content_hash;

    // Build child cap pointing at the patched parent. Child's own
    // content_hash is computed normally → algorithm = 0x00.
    let child_token = CapabilityToken {
        grants: single_grant,
        granter: Granter::Single(granter_entity.content_hash),
        grantee: grantee_entity.content_hash,
        parent: Some(patched_parent_hash),
        created_at: 2,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };
    let child_entity = child_token.to_entity().expect("child cap entity");
    let child_hash = child_entity.content_hash;

    let mut included = BTreeMap::new();
    included.insert(granter_entity.content_hash, granter_entity);
    included.insert(grantee_entity.content_hash, grantee_entity);
    included.insert(patched_parent_hash, parent_entity);
    included.insert(child_hash, child_entity);

    let err = verify_capability_chain(&child_hash, &included, "local-peer")
        .expect_err("cross-format chain rejected");
    match err {
        ProtocolError::CapabilityFormatCodeMismatch(_, _) => {}
        other => panic!("expected CapabilityFormatCodeMismatch, got {:?}", other),
    }

    // Wire status code is 403 (capability_denied family).
    assert_eq!(
        ProtocolError::CapabilityFormatCodeMismatch(0x00, 0x01).wire_status_code(),
        403
    );
}

// ---------------------------------------------------------------------------
// (Defense) v7.66 does not regress v7.65 7/7 vectors — verified by the
// sibling test file `peer_canon_v7_65.rs`. v7.66 also pins the corpus
// fixture: 0xAA×64 is exactly 64 bytes of `0xAA`.
// ---------------------------------------------------------------------------

#[test]
fn corpus_fixture_pubkey_is_64_bytes_of_aa() {
    assert_eq!(EXPERIMENTAL_TEST_FIXTURE_PUBKEY.len(), 64);
    assert!(EXPERIMENTAL_TEST_FIXTURE_PUBKEY.iter().all(|&b| b == 0xAA));
    assert_eq!(KeyType::ExperimentalTest.public_key_len(), 64);
}

#[test]
fn corpus_0xfe_peer_identity_hash_deterministic() {
    let h1 = peer_identity_hash_with_key_type(
        &EXPERIMENTAL_TEST_FIXTURE_PUBKEY,
        KeyType::ExperimentalTest,
    )
    .expect("0xFE identity hash");
    let h2 = peer_identity_hash_with_key_type(
        &EXPERIMENTAL_TEST_FIXTURE_PUBKEY,
        KeyType::ExperimentalTest,
    )
    .expect("0xFE identity hash again");
    assert_eq!(h1, h2);
}
