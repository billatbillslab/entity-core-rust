//! Round-trip correctness + §16 KAT ciphertext authoring (BLOCK-0) for the
//! three modes, plus ENC-GROUP-COMMIT-1 and ENC-RESOURCE-BOUNDS-1.
//!
//! KAT `expected_ciphertext_hex` values are authored against the §16.2–§16.4
//! pinned inputs. The inner-entity plaintext framing for the KATs is still
//! "TBD by cohort+arch joint authoring" (§16.2), so these use the literal
//! placeholder bytes the spec lists and are marked PENDING the 3-way lock; the
//! round-trip tests are the unconditional correctness guarantee.

use entity_encryption::{
    enc_kat_inner_plaintext, group_add_member, group_decrypt, group_encrypt, group_rekey,
    peer_decrypt, peer_encrypt, self_decrypt, self_encrypt, EncryptionError, EncryptionPubkeyData,
    GroupDecryptInput, GroupEncryptInput, GroupMember, PeerEncryptInput, SelfEncryptParams,
};
use entity_encryption::ecdh::x25519_public;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Build the §16 pinned recipient pubkey entity for an X25519 public key:
/// suite [0x01]/[0x01], created 0, expires absent.
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

// ---------------------------------------------------------------------------
// self mode
// ---------------------------------------------------------------------------

#[test]
fn self_roundtrip() {
    let passphrase = b"correct horse battery staple";
    let ed = self_encrypt(passphrase, "user-passphrase", b"secret at rest", SelfEncryptParams::default())
        .unwrap();
    let pt = self_decrypt(passphrase, &ed).unwrap();
    assert_eq!(pt, b"secret at rest");
}

#[test]
fn self_wrong_passphrase_fails_aead() {
    let ed = self_encrypt(b"right", "k", b"data", SelfEncryptParams::default()).unwrap();
    let err = self_decrypt(b"wrong", &ed).unwrap_err();
    assert!(matches!(err, EncryptionError::AeadFailed(_)), "got {err:?}");
}

#[test]
fn enc_self_kat_1_ciphertext() {
    // §16.2 pinned inputs; plaintext = ENC-KAT-INNER ECF (R3).
    let passphrase = "entity-core/test/self-kat-1".as_bytes();
    let key_id = "test-key-1";
    let plaintext = enc_kat_inner_plaintext();
    let p = SelfEncryptParams {
        nonce: Some(vec![0x42; 24]),
        kdf_salt: Some(vec![0x43; 16]),
        params: None, // baseline §6.2
    };
    let ed = self_encrypt(passphrase, key_id, &plaintext, p).unwrap();
    // §16.5 byte-pin — byte-equal to Go + Python (95 B = 79 plaintext + 16 tag).
    assert_eq!(
        hex(&ed.ciphertext),
        "1988938ebb6be64ce283683ed6278a0bcc105df639b6474dc807ee4210e65a0e\
354749aafa85f8d5502f3ebbe2697cb7aaa5922efe863a1b2bd6d4e44c3b8d0a\
e3fdd2d30ff02160055dc3687cac148e0013eb25b361b70b949a7b17fa02e7"
    );

    // Round-trips under the pinned passphrase.
    assert_eq!(self_decrypt(passphrase, &ed).unwrap(), plaintext);
    // Determinism: pinned inputs → identical ciphertext.
    let p2 = SelfEncryptParams {
        nonce: Some(vec![0x42; 24]),
        kdf_salt: Some(vec![0x43; 16]),
        params: None,
    };
    let ed2 = self_encrypt(passphrase, key_id, &plaintext, p2).unwrap();
    assert_eq!(ed.ciphertext, ed2.ciphertext);
}

// ---------------------------------------------------------------------------
// peer mode
// ---------------------------------------------------------------------------

#[test]
fn peer_roundtrip() {
    let recipient_seed = vec![7u8; 32];
    let recipient_pub = x25519_public(&recipient_seed).unwrap();
    let pubkey = kat_pubkey(recipient_pub.to_vec());
    let hash = pubkey.content_hash();

    let ed = peer_encrypt(PeerEncryptInput {
        recipient_pubkey: recipient_pub.to_vec(),
        recipient_pubkey_hash: Some(hash),
        plaintext: b"hello peer".to_vec(),
        nonce: None,
        ephemeral_private_seed: None,
    })
    .unwrap();

    let pt = peer_decrypt(&ed, &recipient_seed).unwrap();
    assert_eq!(pt, b"hello peer");
}

#[test]
fn enc_peer_kat_1_ciphertext() {
    // §16.3 pinned inputs.
    let recipient_seed = vec![0x45u8; 32];
    let sender_eph_seed = vec![0x46u8; 32];
    let recipient_pub = x25519_public(&recipient_seed).unwrap();
    let pubkey = kat_pubkey(recipient_pub.to_vec());
    let recipient_hash = pubkey.content_hash();
    eprintln!("ENC-PEER-KAT-1 recipient_pubkey = {}", hex(&recipient_pub));
    eprintln!("ENC-PEER-KAT-1 recipient_pubkey_hash = {}", hex(&recipient_hash.to_bytes()));

    let plaintext = enc_kat_inner_plaintext();
    let ed = peer_encrypt(PeerEncryptInput {
        recipient_pubkey: recipient_pub.to_vec(),
        recipient_pubkey_hash: Some(recipient_hash),
        plaintext: plaintext.clone(), // ENC-KAT-INNER ECF (R3)
        nonce: Some(vec![0x44; 24]),
        ephemeral_private_seed: Some(sender_eph_seed),
    })
    .unwrap();
    // ephemeral_key is plaintext-independent.
    assert_eq!(
        hex(ed.ephemeral_key.as_ref().unwrap()),
        "a28a7c44ede257d664fbf156affa7da8abb3ae74b9fee8d7a2078543504e1a75"
    );
    // §16.5 byte-pin — byte-equal to Go + Python (95 B).
    assert_eq!(
        hex(&ed.ciphertext),
        "ec0a370301e686a6eb7055617b5af228dfa59a01c2c5ee54d6e0a0b14d304700\
b522396763d5e0cb60a90065c35ace3c4fa77707c835745dfb07987c7eb394aa\
b2ab23f7e415f27d4067f5258d8627a9c6f8c045727d41d466b61f87352a1f"
    );

    assert_eq!(peer_decrypt(&ed, &recipient_seed).unwrap(), plaintext);
}

// ---------------------------------------------------------------------------
// group mode
// ---------------------------------------------------------------------------

fn kat_member(seed: u8, wrap_nonce_byte: u8, eph_seed_byte: u8) -> (GroupMember, Vec<u8>) {
    let priv_seed = vec![seed; 32];
    let pubkey = x25519_public(&priv_seed).unwrap();
    let hash = kat_pubkey(pubkey.to_vec()).content_hash();
    let m = GroupMember {
        pubkey: pubkey.to_vec(),
        pubkey_hash: Some(hash),
        ephemeral_private_seed: Some(vec![eph_seed_byte; 32]),
        wrap_nonce: Some(vec![wrap_nonce_byte; 24]),
    };
    (m, priv_seed)
}

#[test]
fn group_roundtrip_all_members() {
    let (m0, p0) = kat_member(0x50, 0x60, 0x70);
    let (m1, p1) = kat_member(0x51, 0x61, 0x71);
    let (m2, p2) = kat_member(0x52, 0x62, 0x72);
    let members = vec![m0.clone(), m1.clone(), m2.clone()];

    let plaintext = enc_kat_inner_plaintext();
    let ed = group_encrypt(GroupEncryptInput {
        members,
        plaintext: plaintext.clone(),
        outer_nonce: Some(vec![0x53; 24]),
        group_aead_key: Some(vec![0x54; 32]),
    })
    .unwrap();
    assert_eq!(ed.wrapped_keys.len(), 3);

    for (m, priv_seed) in [(&m0, &p0), (&m1, &p1), (&m2, &p2)] {
        let pt = group_decrypt(GroupDecryptInput {
            wrapper: &ed,
            my_pubkey_hash: m.pubkey_hash.unwrap(),
            my_priv: priv_seed.clone(),
        })
        .unwrap();
        assert_eq!(pt, plaintext);
    }
}

#[test]
fn enc_group_kat_1_ciphertext() {
    // §16.4 pinned inputs: member seeds 0x50/0x51/0x52, outer nonce 0x53,
    // per-wrap nonces 0x60+i, group_aead_key 0x54.
    let (m0, _) = kat_member(0x50, 0x60, 0x70);
    let (m1, _) = kat_member(0x51, 0x61, 0x71);
    let (m2, _) = kat_member(0x52, 0x62, 0x72);

    let ed = group_encrypt(GroupEncryptInput {
        members: vec![m0, m1, m2],
        plaintext: enc_kat_inner_plaintext(), // ENC-KAT-INNER ECF (R3)
        outer_nonce: Some(vec![0x53; 24]),
        group_aead_key: Some(vec![0x54; 32]),
    })
    .unwrap();
    // §16.5 byte-pins — byte-equal to Go + Python. Outer ct moves with R3;
    // commitment + all 3 wraps are R3-invariant (wraps encrypt group_aead_key).
    assert_eq!(
        hex(&ed.ciphertext),
        "f048ed1f905803cb97f08ea4b6a7bc531016cbea5b9846c0495f6d805f386098\
5373f9ef5845c21715ebab4d29ad4f1f49cb4d2f1a5398b9d2261e18520dd427\
0754642b769542d262648df1c542fd1ccc8d6f1bf1c1d29c103dc6d3c0d35e"
    );
    let want_wraps = [
        (
            "a49eb492bf3c39ee123c3aa7c7a8da3fd51ac9ad058a69a25ee0f72ea1efd176",
            "e2d2776997ee7b8d1c40a8b89c1c6ffdcc630e73d8bd965c9a93f12ffb5007a8f5236b1c15667088f185fb1bcb2e9c64",
        ),
        (
            "ab4f197998fcc56cc6ed68c1d931af9bb522ec00743e181f7330915df4aa3176",
            "2245832d6416dd3b8b5ad93b425f416e111ac8bef5cf7e45f74d9dd40c776766b9804eaa10471c975aced737ba6e6475",
        ),
        (
            "cd48d0681ea73f09a00f83859bd10880df56822019cda3c883e0d1514e35b106",
            "c1d0cee812d8196a3626c9da108256735d9661d0669aa90071c6db809b82849b5a1d2a4910c7ba783a991b54829a2317",
        ),
    ];
    assert_eq!(ed.wrapped_keys.len(), 3);
    for (i, (eph, wrapped)) in want_wraps.iter().enumerate() {
        assert_eq!(hex(&ed.wrapped_keys[i].ephemeral_key), *eph, "wrap[{i}] eph");
        assert_eq!(hex(&ed.wrapped_keys[i].wrapped_aead_key), *wrapped, "wrap[{i}] wrapped");
    }
}

/// ENC-GROUP-COMMIT-1: a member handed a wrap to a DIFFERENT group_aead_key
/// than the one the outer ciphertext was sealed under must be rejected — the
/// reconstructed-AAD AEAD.Open fails rather than yielding a divergent
/// plaintext. F2-1 key-commitment.
#[test]
fn enc_group_commit_1_equivocation_rejected() {
    // Honest group: one member, key A, outer sealed under commitment(A).
    let (m_honest, _) = kat_member(0x50, 0x60, 0x70);
    let (m_victim, victim_priv) = kat_member(0x51, 0x61, 0x71);

    let mut ed = group_encrypt(GroupEncryptInput {
        members: vec![m_honest],
        plaintext: b"the real message".to_vec(),
        outer_nonce: Some(vec![0x53; 24]),
        group_aead_key: Some(vec![0xAA; 32]), // key A
    })
    .unwrap();

    // Malicious author splices in a wrap of a DIFFERENT key (B) to the victim.
    let forged = group_encrypt(GroupEncryptInput {
        members: vec![m_victim.clone()],
        plaintext: b"x".to_vec(),
        outer_nonce: Some(vec![0x53; 24]),
        group_aead_key: Some(vec![0xBB; 32]), // key B != A
    })
    .unwrap();
    ed.wrapped_keys.push(forged.wrapped_keys.into_iter().next().unwrap());

    // Victim recovers B, reconstructs outer AAD with commitment(B) != the bound
    // commitment(A), so AEAD.Open fails — equivocation rejected.
    let err = group_decrypt(GroupDecryptInput {
        wrapper: &ed,
        my_pubkey_hash: m_victim.pubkey_hash.unwrap(),
        my_priv: victim_priv,
    })
    .unwrap_err();
    assert!(matches!(err, EncryptionError::AeadFailed(_)), "got {err:?}");
}

/// §8.5 group lifecycle (B1-3): add a member (same key, wrap appended — every
/// member still decrypts) then re-key (fresh key, removed member rejected on
/// the new wrapper but still opens the old one; F2-1 commitment changes).
#[test]
fn group_add_and_rekey() {
    let group_key = vec![0x54u8; 32];
    let pt = enc_kat_inner_plaintext();

    // Start: group of {A}.
    let (a, a_priv) = kat_member(0x50, 0x60, 0x70);
    let (b, b_priv) = kat_member(0x51, 0x61, 0x71);
    let ed_a = group_encrypt(GroupEncryptInput {
        members: vec![a.clone()],
        plaintext: pt.clone(),
        outer_nonce: Some(vec![0x53; 24]),
        group_aead_key: Some(group_key.clone()),
    })
    .unwrap();

    // Add B: same key, wrap appended; outer ciphertext unchanged.
    let ed_ab = group_add_member(&ed_a, &group_key, &b).unwrap();
    assert_eq!(ed_ab.wrapped_keys.len(), 2);
    assert_eq!(ed_ab.ciphertext, ed_a.ciphertext, "add reuses the outer ciphertext");
    for (m, priv_seed) in [(&a, &a_priv), (&b, &b_priv)] {
        let got = group_decrypt(GroupDecryptInput {
            wrapper: &ed_ab,
            my_pubkey_hash: m.pubkey_hash.unwrap(),
            my_priv: priv_seed.clone(),
        })
        .unwrap();
        assert_eq!(got, pt);
    }

    // Re-key to remove B: fresh key, remaining member {A} only.
    let new_key = vec![0xCCu8; 32];
    let ed_rekey = group_rekey(
        pt.clone(),
        vec![a.clone()],
        Some(new_key.clone()),
        Some(vec![0x55; 24]),
    )
    .unwrap();
    assert_ne!(new_key, group_key);
    assert_eq!(ed_rekey.wrapped_keys.len(), 1);

    // A (retained) opens the new wrapper.
    assert_eq!(
        group_decrypt(GroupDecryptInput {
            wrapper: &ed_rekey,
            my_pubkey_hash: a.pubkey_hash.unwrap(),
            my_priv: a_priv.clone(),
        })
        .unwrap(),
        pt
    );
    // B (removed) has no wrap in the new wrapper → recipient_unknown.
    let err = group_decrypt(GroupDecryptInput {
        wrapper: &ed_rekey,
        my_pubkey_hash: b.pubkey_hash.unwrap(),
        my_priv: b_priv.clone(),
    })
    .unwrap_err();
    assert!(matches!(err, EncryptionError::RecipientUnknown(_)), "got {err:?}");
    // …but B still opens the OLD wrapper (group-snapshot forward secrecy, §8.5).
    assert_eq!(
        group_decrypt(GroupDecryptInput {
            wrapper: &ed_ab,
            my_pubkey_hash: b.pubkey_hash.unwrap(),
            my_priv: b_priv,
        })
        .unwrap(),
        pt
    );
}

/// ENC-RESOURCE-BOUNDS-1: oversized wrapped_keys → encryption_wrapped_keys_too_many.
#[test]
fn enc_resource_bounds_1_wrapped_keys_ceiling() {
    let (m, _) = kat_member(0x50, 0x60, 0x70);
    let members = vec![m; 257]; // > §8.6 default ceiling of 256
    let err = group_encrypt(GroupEncryptInput {
        members,
        plaintext: b"x".to_vec(),
        outer_nonce: Some(vec![0x53; 24]),
        group_aead_key: Some(vec![0x54; 32]),
    })
    .unwrap_err();
    assert_eq!(err.code(), "encryption_wrapped_keys_too_many");
    assert_eq!(err.status(), 413);
}
