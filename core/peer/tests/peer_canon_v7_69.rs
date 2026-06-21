//! V7 v7.69 `content_hash_format` negotiation conformance vectors + the
//! MATRIX-M3 cross-format handshake proof.
//!
//! Mirrors the cohort `negotiation` validate-peer category (Go reference
//! `cmd/internal/validate/negotiation.go`) plus the end-to-end seam v7.69
//! exists to close: a peer authoring under SHA-384 (`0x01`) and a peer
//! authoring under SHA-256 (`0x00`) **negotiate to a common active format**
//! and complete the handshake, rather than failing `403 capability_denied`
//! on a cross-format `grantee != author` byte-compare.
//!
//! Vectors:
//! - `NEGOTIATE-FORMAT-1`:
//!   - `format_advertised` — responder hello advertises a non-empty
//!     `hash_formats` including the `ecfv1-sha256` floor (§4.5).
//!   - `format_disjoint_reject` — an initiator advertising a disjoint
//!     `hash_formats` set is rejected `400 incompatible_hash_format` (§4.7).
//! - `NEGOTIATE-KEYTYPE-1`:
//!   - `keytype_advertised` — responder hello advertises a non-empty
//!     `key_types` accept-set including `ed25519`.
//!   - `keytype_disjoint_reject` — an initiator whose advertised
//!     `key_types` omits the responder's own key_type is rejected
//!     `400 unsupported_key_type` (mutual-verifiability, §4.5).
//! - `NEGOTIATE-ACTIVE-SHA256` / `NEGOTIATE-ACTIVE-SHA384` — the active
//!   format is the first match in the **initiator's** order; a SHA-384
//!   home peer negotiates **down** to SHA-256 with a SHA-256-only peer
//!   and **up** to SHA-384 with a SHA-384 peer (§4.5/§4.5a).
//! - `M3-CROSS-FORMAT-HANDSHAKE` — a full hello→authenticate handshake
//!   between a SHA-384 responder and a SHA-256 initiator completes, and a
//!   SHA-384↔SHA-384 handshake authors every transmitted entity under
//!   SHA-384 (§4.5a) with the §1.8 authored-signer captured as grantee.

use entity_crypto::{IdentityKeypair, Keypair, KeyType};
use entity_entity::{Envelope, TYPE_SIGNATURE};
use entity_hash::{HASH_ALGORITHM_SHA256, HASH_ALGORITHM_SHA384};
use entity_protocol::{
    build_authenticate_envelope, build_connect_execute, default_advertised_hash_formats,
    default_advertised_key_types, negotiate_active_format, Connection, HelloData, ProtocolError,
};

/// Build a hello EXECUTE envelope from explicit advertised sets (the
/// low-level construction the disjoint-reject vectors need).
fn hello_envelope(
    peer_id: &str,
    nonce: Vec<u8>,
    hash_formats: Vec<String>,
    key_types: Vec<String>,
) -> Envelope {
    let hello = HelloData {
        peer_id: peer_id.to_string(),
        nonce,
        protocols: vec!["entity-core/1.0".to_string()],
        hash_formats,
        key_types,
        timestamp: None,
    };
    let hello_entity = hello.to_entity().expect("hello entity");
    let exec = build_connect_execute("nego-hello", "hello", &hello_entity).expect("connect execute");
    Envelope::new(exec)
}

/// A responder `Connection` configured for the given home format.
fn responder(home_format: u8) -> Connection {
    let local = Keypair::from_seed([0x11; 32]);
    let mut conn = Connection::new(local.peer_id());
    conn.set_local_advertisement(home_format, KeyType::Ed25519.label());
    conn
}

// ===========================================================================
// NEGOTIATE-FORMAT-1
// ===========================================================================

/// `format_advertised`: the responder's hello response carries a non-empty
/// `hash_formats` including the `ecfv1-sha256` floor (§4.5 default floor).
#[test]
fn negotiate_format_1_format_advertised() {
    let mut conn = responder(HASH_ALGORITHM_SHA256);
    let remote = Keypair::from_seed([0x22; 32]);
    let env = hello_envelope(
        remote.peer_id().as_str(),
        vec![3u8; 32],
        vec!["ecfv1-sha256".to_string()],
        vec!["ed25519".to_string()],
    );
    let (response, _req) = conn.process_hello(&env).expect("hello negotiates");
    assert!(!response.hash_formats.is_empty(), "responder advertises hash_formats");
    assert!(
        response.hash_formats.iter().any(|f| f == "ecfv1-sha256"),
        "responder advertises the ecfv1-sha256 floor"
    );
}

/// `format_disjoint_reject`: an initiator advertising only a
/// disjoint/unknown `hash_formats` value is rejected with
/// `incompatible_hash_format` (400).
#[test]
fn negotiate_format_1_disjoint_reject() {
    let mut conn = responder(HASH_ALGORITHM_SHA256);
    let remote = Keypair::from_seed([0x22; 32]);
    let env = hello_envelope(
        remote.peer_id().as_str(),
        vec![3u8; 32],
        vec!["ecfv1-fake-disjoint-format".to_string()],
        vec!["ed25519".to_string()],
    );
    let err = conn.process_hello(&env).expect_err("disjoint hash_formats rejected");
    assert!(
        matches!(err, ProtocolError::IncompatibleHashFormat),
        "expected IncompatibleHashFormat, got {:?}",
        err
    );
    assert_eq!(err.wire_error_code(), Some("incompatible_hash_format"));
    assert_eq!(err.wire_status_code(), 400);
}

// ===========================================================================
// NEGOTIATE-KEYTYPE-1
// ===========================================================================

/// `keytype_advertised`: the responder's hello response carries a non-empty
/// `key_types` accept-set including `ed25519` (floor).
#[test]
fn negotiate_keytype_1_keytype_advertised() {
    let mut conn = responder(HASH_ALGORITHM_SHA256);
    let remote = Keypair::from_seed([0x22; 32]);
    let env = hello_envelope(
        remote.peer_id().as_str(),
        vec![3u8; 32],
        vec!["ecfv1-sha256".to_string()],
        vec!["ed25519".to_string(), "ed448".to_string()],
    );
    let (response, _req) = conn.process_hello(&env).expect("hello negotiates");
    assert!(!response.key_types.is_empty(), "responder advertises key_types");
    assert!(
        response.key_types.iter().any(|k| k == "ed25519"),
        "responder advertises the ed25519 floor"
    );
}

/// `keytype_disjoint_reject`: an initiator whose advertised `key_types`
/// omits the responder's own key_type (`ed25519`) is rejected with
/// `unsupported_key_type` (400) — mutual-verifiability gate (§4.5).
#[test]
fn negotiate_keytype_1_disjoint_reject() {
    let mut conn = responder(HASH_ALGORITHM_SHA256);
    let remote = Keypair::from_seed([0x22; 32]);
    let env = hello_envelope(
        remote.peer_id().as_str(),
        vec![3u8; 32],
        vec!["ecfv1-sha256".to_string()],
        vec!["fake-disjoint-key-type".to_string()],
    );
    let err = conn.process_hello(&env).expect_err("disjoint key_types rejected");
    assert!(
        matches!(err, ProtocolError::UnsupportedKeyType(_)),
        "expected UnsupportedKeyType, got {:?}",
        err
    );
    assert_eq!(err.wire_error_code(), Some("unsupported_key_type"));
    assert_eq!(err.wire_status_code(), 400);
}

// ===========================================================================
// NEGOTIATE-ACTIVE: single-active-value, first-match-in-initiator-order
// ===========================================================================

/// A SHA-384 home peer negotiates **down** to SHA-256 against a
/// SHA-256-only initiator (§4.5a: the active format is a property of the
/// connection, not the peer). Both sides converge on `0x00`.
#[test]
fn negotiate_active_sha384_responder_down_to_sha256() {
    let mut conn = responder(HASH_ALGORITHM_SHA384);
    let remote = Keypair::from_seed([0x22; 32]);
    let initiator_formats = default_advertised_hash_formats(HASH_ALGORITHM_SHA256);
    let env = hello_envelope(
        remote.peer_id().as_str(),
        vec![3u8; 32],
        initiator_formats.clone(),
        default_advertised_key_types(),
    );
    let (response, _req) = conn.process_hello(&env).expect("negotiates down");
    assert_eq!(
        conn.active_hash_format, HASH_ALGORITHM_SHA256,
        "active format negotiates down to the SHA-256 floor"
    );
    // Initiator re-derives the same active value from the response.
    let initiator_active = negotiate_active_format(&initiator_formats, &response.hash_formats)
        .expect("initiator derives active");
    assert_eq!(initiator_active, HASH_ALGORITHM_SHA256, "both sides converge");
}

/// Two SHA-384 peers negotiate **up** to SHA-384 (first match in the
/// initiator's order is `ecfv1-sha384`).
#[test]
fn negotiate_active_sha384_both_sha384() {
    let mut conn = responder(HASH_ALGORITHM_SHA384);
    let remote = Keypair::from_seed([0x22; 32]);
    let initiator_formats = default_advertised_hash_formats(HASH_ALGORITHM_SHA384);
    let env = hello_envelope(
        remote.peer_id().as_str(),
        vec![3u8; 32],
        initiator_formats.clone(),
        default_advertised_key_types(),
    );
    conn.process_hello(&env).expect("negotiates up");
    assert_eq!(
        conn.active_hash_format, HASH_ALGORITHM_SHA384,
        "active format negotiates up to SHA-384 when both support it"
    );
}

// ===========================================================================
// M3-CROSS-FORMAT-HANDSHAKE
// ===========================================================================

/// Drive a full hello → authenticate handshake at the `Connection` layer
/// for a given (responder_home, initiator_home) pair. Returns the
/// responder's resolved active format and the captured §1.8 grantee hash.
fn run_handshake(responder_home: u8, initiator_home: u8) -> (u8, entity_hash::Hash) {
    let responder_kp = Keypair::from_seed([0x11; 32]);
    let initiator_kp = IdentityKeypair::Ed25519(Keypair::from_seed([0x22; 32]));

    let mut conn = Connection::new(responder_kp.peer_id());
    conn.set_local_advertisement(responder_home, KeyType::Ed25519.label());

    // Initiator → responder: hello.
    let initiator_formats = default_advertised_hash_formats(initiator_home);
    let hello_env = hello_envelope(
        initiator_kp.peer_id().as_str(),
        vec![7u8; 32],
        initiator_formats.clone(),
        default_advertised_key_types(),
    );
    let (response_hello, _req) = conn.process_hello(&hello_env).expect("hello negotiates");

    // Initiator derives the active format from the response and authors
    // its authenticate under it (§4.5a). The responder's issued nonce is
    // carried in its hello response.
    let active = negotiate_active_format(&initiator_formats, &response_hello.hash_formats)
        .expect("initiator derives active");
    assert_eq!(
        active, conn.active_hash_format,
        "initiator and responder converge on the active format"
    );

    let auth_env = build_authenticate_envelope(&initiator_kp, &response_hello.nonce, active)
        .expect("initiator authors authenticate under active format");

    // §4.5a: every entity the initiator authored on this connection is
    // under the active format.
    assert_eq!(
        auth_env.root.content_hash.algorithm, HASH_ALGORITHM_SHA256,
        "EXECUTE root stays SHA-256 (process default; per-entity self-describing)"
    );
    for (_h, e) in auth_env.included.iter() {
        if e.entity_type == TYPE_SIGNATURE || e.entity_type == entity_types::TYPE_PEER {
            assert_eq!(
                e.content_hash.algorithm, active,
                "identity-bound entity {} authored under active format",
                e.entity_type
            );
        }
    }

    // Responder → process authenticate. Must succeed (signature verifies
    // against the active-format authenticate hash) and capture the §1.8
    // authored signer as the grantee reference.
    let (_pid, _req) = conn
        .process_authenticate(&auth_env)
        .expect("authenticate verifies; M3 no longer cap-denies on cross-format");
    let grantee = conn
        .remote_identity_hash
        .expect("§1.8 authored signer captured");
    assert_eq!(
        grantee.algorithm, active,
        "grantee (authored signer, §1.8) is under the connection active format"
    );
    (conn.active_hash_format, grantee)
}

/// MATRIX-M3: a SHA-384 responder and a SHA-256 initiator complete the
/// handshake by negotiating to the common SHA-256 floor — the
/// cross-format `cap_denied` failure class is eliminated.
#[test]
fn m3_cross_format_handshake_sha384_responder_sha256_initiator() {
    let (active, grantee) = run_handshake(HASH_ALGORITHM_SHA384, HASH_ALGORITHM_SHA256);
    assert_eq!(active, HASH_ALGORITHM_SHA256);
    assert_eq!(grantee.algorithm, HASH_ALGORITHM_SHA256);
}

/// MATRIX-M3: the symmetric case — SHA-256 responder, SHA-384 initiator —
/// also lands on the common SHA-256 floor.
#[test]
fn m3_cross_format_handshake_sha256_responder_sha384_initiator() {
    let (active, _grantee) = run_handshake(HASH_ALGORITHM_SHA256, HASH_ALGORITHM_SHA384);
    assert_eq!(active, HASH_ALGORITHM_SHA256);
}

/// Two SHA-384 peers complete the handshake authoring every identity-bound
/// entity under SHA-384 (`0x01`) — the native-SHA-384 path the v7.67
/// Phase-2 MATRIX-M3 deferral left unreachable, now live.
#[test]
fn m3_cross_format_handshake_both_sha384_authors_sha384() {
    let (active, grantee) = run_handshake(HASH_ALGORITHM_SHA384, HASH_ALGORITHM_SHA384);
    assert_eq!(active, HASH_ALGORITHM_SHA384);
    assert_eq!(grantee.algorithm, HASH_ALGORITHM_SHA384);
    assert_eq!(grantee.digest().len(), 48, "SHA-384 grantee digest is 48 bytes");
}
