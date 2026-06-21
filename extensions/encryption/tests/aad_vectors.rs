//! §16 AAD reference-byte authoring (BLOCK-0).
//!
//! These tests produce the `expected_AAD_hex` reference bytes for the §16
//! conformance vectors from the pinned inputs. Self-mode and group-outer AAD
//! are fully pinned (no key material needed), so they are authored here in
//! step 1; peer-mode and group-wrap AAD bind a derived `recipient_key`
//! (`content_hash(system/encryption-pubkey)`), so their real reference hex is
//! authored once X25519 lands (steps 3–4). The fixed-hash cases below lock the
//! builder *shape* in the meantime.
//!
//! Run `cargo test -p entity-encryption -- --nocapture` to print the hex for
//! the 3-way cohort byte-compare against Go + arch.

use entity_encryption::aad;
use entity_encryption::types::KdfParams;
use entity_hash::Hash;
use sha2::{Digest, Sha256};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// §16.2 ENC-SELF-KAT-1 self-mode 8-key AAD, fully pinned inputs.
#[test]
fn enc_self_kat_1_aad() {
    let nonce = [0x42u8; 24];
    let kdf_salt = [0x43u8; 16];
    let params = KdfParams::default(); // §6.2 baseline: 0x13 / 65536 / 3 / 1 / 32

    let got = aad::self_aad(0x01, 0x01, &nonce, &kdf_salt, params.to_ecf_value());
    eprintln!("ENC-SELF-KAT-1 expected_AAD_hex = {}", hex(&got));

    // Authored Rust reference (BLOCK-0). Length-first key order (§16.2):
    // mode(4) < nonce(5) < kdf_id(6) < aead_id(7) < kdf_salt(8) <
    // kdf_params(10) < enc_key_type(12) < recipient_key(13); 8-key header 0xa8;
    // kdf_params nested map ordered time_cost<output_len<memory_cost<
    // parallelism<argon2_version. PENDING 3-way byte-equal with Go + arch.
    const ENC_SELF_KAT_1_AAD: &str = "a8646d6f64656473656c66656e6f6e63655818424242424242424242424242424242424242424242424242666b64665f69640167616561645f696401686b64665f73616c7450434343434343434343434343434343436a6b64665f706172616d73a56974696d655f636f7374036a6f75747075745f6c656e18206b6d656d6f72795f636f73741a000100006b706172616c6c656c69736d016e6172676f6e325f76657273696f6e136c656e635f6b65795f74797065006d726563697069656e745f6b657940";
    assert_eq!(hex(&got), ENC_SELF_KAT_1_AAD);
}

/// §16.4 ENC-GROUP-KAT-1 group-outer 7-key AAD. group_aead_key is pinned
/// (32 bytes of 0x54) so the commitment = SHA-256(group_aead_key) is
/// reproducible; outer nonce = 24 bytes of 0x53.
#[test]
fn enc_group_kat_1_outer_aad() {
    let nonce = [0x53u8; 24];
    let group_aead_key = [0x54u8; 32];
    let commitment = Sha256::digest(group_aead_key);

    let got = aad::group_outer_aad(0x01, 0x01, &nonce, &commitment);
    eprintln!("ENC-GROUP-KAT-1 outer expected_AAD_hex = {}", hex(&got));
    eprintln!("ENC-GROUP-KAT-1 commitment = {}", hex(&commitment));

    // commitment = SHA-256(0x54 × 32), F2-1 key-commitment.
    assert_eq!(
        hex(&commitment),
        "784ad05e9d7a6aeaca70c0acc22d65d14d9dbbc383ee442a3e15484bf7a594e6"
    );
    // Authored Rust reference (BLOCK-0). 7-key header 0xa7; key order
    // mode<nonce<kdf_id<aead_id<commitment<enc_key_type<recipient_key(∅).
    // PENDING 3-way byte-equal with Go + arch.
    const ENC_GROUP_KAT_1_OUTER_AAD: &str = "a7646d6f64656567726f7570656e6f6e63655818535353535353535353535353535353535353535353535353666b64665f69640167616561645f6964016a636f6d6d69746d656e745820784ad05e9d7a6aeaca70c0acc22d65d14d9dbbc383ee442a3e15484bf7a594e66c656e635f6b65795f74797065006d726563697069656e745f6b657940";
    assert_eq!(hex(&got), ENC_GROUP_KAT_1_OUTER_AAD);
}

/// Peer-mode AAD builder shape lock (NOT the real ENC-PEER-KAT-1 reference —
/// that binds the derived X25519 pubkey hash, authored in step 3). Uses a
/// fixed SHA-256-shaped hash so the wire shape (33-byte bstr recipient_key) is
/// exercised deterministically.
#[test]
fn peer_aad_shape() {
    let nonce = [0x44u8; 24];
    let recipient_key = Hash::new(0x00, [0xabu8; 32]);
    let ephemeral_key = [0xcdu8; 32];

    let got = aad::peer_aad(0x01, 0x01, 0x01, &nonce, &recipient_key, &ephemeral_key);
    eprintln!("peer_aad (fixed-hash shape) = {}", hex(&got));

    assert_eq!(got[0], 0xa7, "7-key map header");
    // recipient_key is a 33-byte bstr (0x58 0x21 = bstr len 33), value
    // 0x00 || digest.
    assert!(hex(&got).contains("582100"), "33-byte hash bstr present");
}

/// Group-per-wrap AAD builder shape lock (domain-separated mode="group-wrap").
#[test]
fn group_wrap_aad_shape() {
    let wrap_nonce = [0x60u8; 24];
    let member_key = Hash::new(0x00, [0xefu8; 32]);
    let ephemeral_key = [0x12u8; 32];

    let got = aad::group_wrap_aad(0x01, 0x01, 0x01, &wrap_nonce, &member_key, &ephemeral_key);
    eprintln!("group_wrap_aad (fixed-hash shape) = {}", hex(&got));

    assert_eq!(got[0], 0xa7, "7-key map header");
    // mode value is the 10-byte text "group-wrap" (0x6a 67726f75702d77726170).
    assert!(
        hex(&got).contains("6a67726f75702d77726170"),
        "group-wrap mode label present"
    );
}
