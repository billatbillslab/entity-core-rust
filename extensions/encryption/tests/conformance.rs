//! §16 conformance vectors that don't need publishing/lifecycle plumbing:
//! ENC-AAD-1 (per-key AAD tamper), ENC-TIER-INTEROP-1 (uniform pubkey-hash
//! binding + the F2-3 re-mint trap), ENC-ROUNDTRIP-FORMAT-1 (cross
//! content-hash-format recipient_key).

use entity_encryption::aead::{xchacha_decrypt, xchacha_encrypt, AEAD_KEY_SIZE, AEAD_NONCE_SIZE};
use entity_encryption::ecdh::x25519_public;
use entity_encryption::{
    aad, peer_decrypt, peer_encrypt, EncryptionError, EncryptionPubkeyData, PeerEncryptInput,
};
use entity_hash::Hash;

fn kat_pubkey(public_key: Vec<u8>) -> EncryptionPubkeyData {
    EncryptionPubkeyData {
        enc_key_type: 0x01,
        public_key,
        supported_aead_ids: vec![0x01],
        supported_kdf_ids: vec![0x01],
        created: 0,
        expires: None,
    }
}

/// ENC-AAD-1 — tampering with ANY key in the §5.2 peer-mode 7-key AAD set MUST
/// fail decryption with `encryption_aead_failed`. Exercised at the AEAD layer
/// with a fixed key so the failure is attributable purely to the AAD binding.
#[test]
fn enc_aad_1_peer_per_key_tamper() {
    let key = [0x11u8; AEAD_KEY_SIZE];
    let nonce = [0x22u8; AEAD_NONCE_SIZE];
    let recipient_key = Hash::new(0x00, [0x33u8; 32]);
    let ephemeral_key = [0x44u8; 32];
    let plaintext = b"bind me";

    let good_aad = aad::peer_aad(0x01, 0x01, 0x01, &nonce, &recipient_key, &ephemeral_key);
    let ct = xchacha_encrypt(&key, &nonce, &good_aad, plaintext).unwrap();
    // Sanity: the untampered AAD opens.
    assert_eq!(xchacha_decrypt(&key, &nonce, &good_aad, &ct).unwrap(), plaintext);

    // One tampered AAD per key in the set; each MUST fail.
    let other_hash = Hash::new(0x00, [0x99u8; 32]);
    let tampered: Vec<Vec<u8>> = vec![
        aad::self_aad(0x01, 0x01, &nonce, &[0x00; 16], entity_encryption::KdfParams::default().to_ecf_value()), // mode flip (self vs peer)
        aad::peer_aad(0x02, 0x01, 0x01, &nonce, &recipient_key, &ephemeral_key), // enc_key_type
        aad::peer_aad(0x01, 0x02, 0x01, &nonce, &recipient_key, &ephemeral_key), // aead_id
        aad::peer_aad(0x01, 0x01, 0x02, &nonce, &recipient_key, &ephemeral_key), // kdf_id
        aad::peer_aad(0x01, 0x01, 0x01, &[0x23; 24], &recipient_key, &ephemeral_key), // nonce
        aad::peer_aad(0x01, 0x01, 0x01, &nonce, &other_hash, &ephemeral_key),    // recipient_key
        aad::peer_aad(0x01, 0x01, 0x01, &nonce, &recipient_key, &[0x45; 32]),    // ephemeral_key
    ];
    for (i, bad) in tampered.iter().enumerate() {
        let err = xchacha_decrypt(&key, &nonce, bad, &ct).unwrap_err();
        assert!(
            matches!(err, EncryptionError::AeadFailed(_)),
            "tampered AAD #{i} should fail with aead_failed, got {err:?}"
        );
    }
}

/// ENC-TIER-INTEROP-1 — the `recipient_key` is the inner pubkey-entity
/// content_hash, identical at every tier (F-GO-1). A round-trip succeeds when
/// the SAME authored entity is bound; the F2-3 trap (a re-minted equivalent at
/// a different `created`) yields a DIFFERENT hash and would break interop.
#[test]
fn enc_tier_interop_1_uniform_binding() {
    let recipient_seed = vec![0x45u8; 32];
    let recipient_pub = x25519_public(&recipient_seed).unwrap();

    // One authored inner entity, shared across tiers.
    let authored = kat_pubkey(recipient_pub.to_vec());
    let hash_a = authored.content_hash();
    // Re-publishing the byte-identical authored entity → same hash.
    let hash_a_again = kat_pubkey(recipient_pub.to_vec()).content_hash();
    assert_eq!(hash_a, hash_a_again, "same authored entity must hash equal");

    // F2-3 trap: a re-minted equivalent at a different `created` → different
    // hash → would derive a different key → interop fails.
    let reminted = EncryptionPubkeyData { created: 1, ..kat_pubkey(recipient_pub.to_vec()) };
    assert_ne!(hash_a, reminted.content_hash(), "re-minted entity must differ");

    // Cross-tier round-trip binds the one authored hash.
    let ed = peer_encrypt(PeerEncryptInput {
        recipient_pubkey: recipient_pub.to_vec(),
        recipient_pubkey_hash: Some(hash_a),
        plaintext: b"cross-tier".to_vec(),
        nonce: None,
        ephemeral_private_seed: None,
    })
    .unwrap();
    assert_eq!(ed.recipient_key.unwrap(), hash_a);
    assert_eq!(peer_decrypt(&ed, &recipient_seed).unwrap(), b"cross-tier");
}

/// ENC-ROUNDTRIP-FORMAT-1 — when the recipient's home content_hash_format is
/// SHA-384 (`0x01`), `recipient_key` is the 49-byte authored hash under that
/// format; the peer-mode round-trip still succeeds because the HKDF `info`
/// binds whatever wire bytes the hash carries (§7.6 / v7.69 §4.5a).
#[test]
fn enc_roundtrip_format_1_sha384_recipient_key() {
    let recipient_seed = vec![0x45u8; 32];
    let recipient_pub = x25519_public(&recipient_seed).unwrap();
    let pubkey = kat_pubkey(recipient_pub.to_vec());

    let hash_384 = pubkey.content_hash_format(0x01).expect("SHA-384 supported");
    assert_eq!(hash_384.algorithm, 0x01);
    assert_eq!(hash_384.to_bytes().len(), 1 + 48, "format byte + SHA-384 digest");

    let ed = peer_encrypt(PeerEncryptInput {
        recipient_pubkey: recipient_pub.to_vec(),
        recipient_pubkey_hash: Some(hash_384),
        plaintext: b"sha-384 recipient".to_vec(),
        nonce: None,
        ephemeral_private_seed: None,
    })
    .unwrap();
    assert_eq!(ed.recipient_key.unwrap().algorithm, 0x01);
    assert_eq!(peer_decrypt(&ed, &recipient_seed).unwrap(), b"sha-384 recipient");
}
