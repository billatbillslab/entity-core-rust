//! ENC-CERT-LIFECYCLE-1 (Tier A) + §9.2 Tier-2 key-backup round-trip.

use entity_encryption::ecdh::x25519_public;
use entity_encryption::lifecycle::{EncryptionHandoffData, EncryptionRevocationData, TierAView};
use entity_encryption::{
    unwrap_private_key, wrap_private_key, EncryptionError, EncryptionPubkeyData, KdfParams,
};

fn pubkey_hash(seed: u8) -> entity_hash::Hash {
    let pubkey = x25519_public(&vec![seed; 32]).unwrap();
    EncryptionPubkeyData {
        enc_key_type: 0x01,
        public_key: pubkey.to_vec(),
        supported_aead_ids: vec![0x01],
        supported_kdf_ids: vec![0x01],
        created: 0,
        expires: None,
    }
    .content_hash()
}

/// ENC-CERT-LIFECYCLE-1 (Tier A): publish A → rotate A→B → revoke B → resolving
/// from A walks to B and rejects with `encryption_key_revoked`; encrypting
/// directly to revoked B is also rejected.
#[test]
fn enc_cert_lifecycle_1_tier_a() {
    let a = pubkey_hash(0x50);
    let b = pubkey_hash(0x51);

    // Publish A; rotate A→B.
    let mut view = TierAView {
        pubkeys: vec![a, b],
        handoffs: vec![EncryptionHandoffData { previous_pubkey: a, next_pubkey: b, created: 100 }],
        revocations: vec![],
    };

    // Before revocation: resolving from A follows the handoff to current B.
    assert_eq!(view.resolve_current(&a).unwrap(), b);
    assert_eq!(view.walk_to_terminal(&a), b);
    view.check_encryptable(&b).unwrap();

    // Revoke B.
    view.revocations.push(EncryptionRevocationData {
        revokes: b,
        reason: Some("key compromise".into()),
        created: 200,
    });

    // Resolving from A still walks to B, but B is now revoked → reject.
    let err = view.resolve_current(&a).unwrap_err();
    assert!(matches!(err, EncryptionError::KeyRevoked(_)), "got {err:?}");
    assert_eq!(err.code(), "encryption_key_revoked");
    assert_eq!(err.status(), 403);

    // Sending directly to revoked B is likewise rejected.
    assert!(view.is_revoked(&b));
    assert!(matches!(view.check_encryptable(&b).unwrap_err(), EncryptionError::KeyRevoked(_)));
}

/// Multi-hop handoff chain resolves to the terminal pubkey (most-recent wins).
#[test]
fn handoff_chain_walks_to_terminal() {
    let (a, b, c) = (pubkey_hash(0x50), pubkey_hash(0x51), pubkey_hash(0x52));
    let view = TierAView {
        pubkeys: vec![a, b, c],
        handoffs: vec![
            EncryptionHandoffData { previous_pubkey: a, next_pubkey: b, created: 100 },
            EncryptionHandoffData { previous_pubkey: b, next_pubkey: c, created: 200 },
        ],
        revocations: vec![],
    };
    assert_eq!(view.walk_to_terminal(&a), c);
    assert_eq!(view.resolve_current(&a).unwrap(), c);
}

/// §11 "revocation supersedes everything": resolving from a revoked pubkey is
/// refused with `encryption_key_revoked` even when a live handoff successor
/// exists — a sender does NOT silently redirect to the successor (Go's
/// `ResolveCurrentRecipient` semantics). `next_in_handoff_chain` still reports
/// the single-occupant successor.
#[test]
fn revoked_initial_refused_no_silent_redirect() {
    let (a, b) = (pubkey_hash(0x50), pubkey_hash(0x51));
    let view = TierAView {
        pubkeys: vec![a, b],
        handoffs: vec![EncryptionHandoffData { previous_pubkey: a, next_pubkey: b, created: 100 }],
        revocations: vec![EncryptionRevocationData { revokes: a, reason: None, created: 200 }],
    };

    // The granular §10 primitive sees the successor…
    assert_eq!(view.next_in_handoff_chain(&a), Some(b));
    // …but resolution refuses the dead key rather than redirecting to B.
    let err = view.resolve_current(&a).unwrap_err();
    assert!(matches!(err, EncryptionError::KeyRevoked(_)), "got {err:?}");
    assert_eq!(err.code(), "encryption_key_revoked");
}

/// §9.2 Tier-2 backup round-trip: wrap a private key under a passphrase, then
/// recover it; a wrong passphrase fails with `encryption_aead_failed`.
#[test]
fn key_backup_roundtrip() {
    let pubkey_ref = pubkey_hash(0x50);
    let private_key = vec![0xABu8; 32]; // the X25519 private to protect
    let backup = wrap_private_key(
        b"my backup passphrase",
        pubkey_ref,
        &private_key,
        vec![0x43; 16],
        vec![0x42; 24],
        KdfParams::default(),
    )
    .unwrap();

    assert_eq!(unwrap_private_key(b"my backup passphrase", &backup).unwrap(), private_key);

    let err = unwrap_private_key(b"wrong passphrase", &backup).unwrap_err();
    assert!(matches!(err, EncryptionError::AeadFailed(_)), "got {err:?}");
}
