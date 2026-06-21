//! §8 mode=group — static key-wrap for a fixed member set (≤256 default).
//! BEST-EFFORT in v1.0.
//!
//! Construction (§8.3):
//! ```text
//! group_aead_key := random 32 bytes
//! commitment     := SHA-256(group_aead_key)                         (F2-1)
//! outer_AAD      := group_outer_aad(... commitment ...)             (§5.2 7-key)
//! ciphertext     := AEAD(group_aead_key, outer_nonce, outer_AAD, inner)
//! for each member M:
//!     fresh per-wrap ephemeral keypair + per-wrap nonce
//!     wrap_AAD       := group_wrap_aad(... M.pubkey_hash ... ephem ...)  (mode="group-wrap" — F2-2)
//!     wrap_aead_key  := HKDF(ECDH(eph_priv, M.pubkey), wrap_nonce, "entity-core/peer/"||M.pubkey_hash)
//!     wrapped_aead_key := AEAD(wrap_aead_key, wrap_nonce, wrap_AAD, group_aead_key)
//! ```
//!
//! Per-wrap derivation reuses the §7.3 peer-mode HKDF info exactly; only the
//! AAD label differs (`group-wrap`), domain-separating a lifted wrap from a
//! replayable peer-mode message. F2-1 key-commitment makes author equivocation
//! (invisible-salamanders) structurally impossible.

use entity_hash::Hash;
use sha2::{Digest, Sha256};

use crate::aead::{random_key, random_nonce, xchacha_decrypt, xchacha_encrypt, AEAD_KEY_SIZE, AEAD_NONCE_SIZE};
use crate::ecdh::{generate_or_load_x25519, x25519_shared, X25519_PRIVATE_SIZE, X25519_PUBLIC_SIZE};
use crate::peer::derive_aead_key;
use crate::registry::{
    group_mode_suite_allowed, AEAD_ID_XCHACHA20_POLY1305, ENC_KEY_TYPE_X25519, KDF_ID_HKDF_SHA256,
};
use crate::types::{EncryptionError, MODE_GROUP, WRAPPED_KEYS_DEFAULT_CEILING};
use crate::wrapper::{EncryptedData, WrappedKey};
use crate::aad;

/// SHA-256(`group_aead_key`) — the F2-1 binding emitted into the §5.2
/// group-outer AAD.
pub fn commitment(group_aead_key: &[u8]) -> [u8; 32] {
    Sha256::digest(group_aead_key).into()
}

/// Per-member encryption target (KAT determinism via the optional seeds).
#[derive(Debug, Default, Clone)]
pub struct GroupMember {
    pub pubkey: Vec<u8>,
    pub pubkey_hash: Option<Hash>,
    pub ephemeral_private_seed: Option<Vec<u8>>,
    pub wrap_nonce: Option<Vec<u8>>,
}

/// Per-encryption inputs (KAT determinism). `None`/empty → freshly random.
#[derive(Debug, Default, Clone)]
pub struct GroupEncryptInput {
    pub members: Vec<GroupMember>,
    pub plaintext: Vec<u8>,
    pub outer_nonce: Option<Vec<u8>>,
    pub group_aead_key: Option<Vec<u8>>,
}

/// §8.3 group-mode encryption. Sender authentication (§7.4 single signature
/// over the outer entity) is the handler layer's job.
pub fn group_encrypt(input: GroupEncryptInput) -> Result<EncryptedData, EncryptionError> {
    if input.members.is_empty() {
        return Err(EncryptionError::InvalidWrapper(
            "group encrypt requires at least one member".into(),
        ));
    }
    if input.members.len() > WRAPPED_KEYS_DEFAULT_CEILING {
        return Err(EncryptionError::WrappedKeysTooMany(format!(
            "group has {} members, ceiling {} (§8.6)",
            input.members.len(),
            WRAPPED_KEYS_DEFAULT_CEILING
        )));
    }

    let aead_id = AEAD_ID_XCHACHA20_POLY1305;
    let kdf_id = KDF_ID_HKDF_SHA256;
    group_mode_suite_allowed(aead_id, kdf_id)?;

    let group_key = match input.group_aead_key {
        Some(k) => k,
        None => random_key().to_vec(),
    };
    if group_key.len() != AEAD_KEY_SIZE {
        return Err(EncryptionError::InvalidWrapper(format!(
            "group_aead_key must be {AEAD_KEY_SIZE} bytes, got {}",
            group_key.len()
        )));
    }
    let outer_nonce = match input.outer_nonce {
        Some(n) => n,
        None => random_nonce().to_vec(),
    };
    if outer_nonce.len() != AEAD_NONCE_SIZE {
        return Err(EncryptionError::InvalidWrapper(format!(
            "group outer nonce must be {AEAD_NONCE_SIZE} bytes, got {}",
            outer_nonce.len()
        )));
    }

    let commit = commitment(&group_key);
    let outer_aad = aad::group_outer_aad(aead_id, kdf_id, &outer_nonce, &commit);
    let outer_ct = xchacha_encrypt(&group_key, &outer_nonce, &outer_aad, &input.plaintext)?;

    let mut wraps = Vec::with_capacity(input.members.len());
    for (i, m) in input.members.iter().enumerate() {
        let w = wrap_for_member(m, &group_key, aead_id, kdf_id)
            .map_err(|e| EncryptionError::InvalidWrapper(format!("wrap for member[{i}]: {e}")))?;
        wraps.push(w);
    }

    let mut ed = EncryptedData::common(MODE_GROUP, 0, aead_id, kdf_id, outer_nonce, outer_ct);
    ed.wrapped_keys = wraps;
    Ok(ed)
}

/// §8.5 group lifecycle — add a member. Produces a new `system/encrypted` that
/// extends `existing` with one additional member wrap. The `group_aead_key`
/// does NOT change (the caller, an existing member, recovered it by unwrapping
/// their own slot; this primitive does not re-derive it) — existing members
/// are unaffected and the outer ciphertext/nonce are reused verbatim. Only
/// `wrapped_keys` grows by one, so the new entity's content_hash differs from
/// `existing` solely in the wrap list. At the handler layer the new wrapper
/// supersedes the old via EXTENSION-REVISION.
pub fn group_add_member(
    existing: &EncryptedData,
    group_aead_key: &[u8],
    new_member: &GroupMember,
) -> Result<EncryptedData, EncryptionError> {
    if existing.mode != MODE_GROUP {
        return Err(EncryptionError::InvalidWrapper(format!(
            "group_add_member requires mode=group, got {:?}",
            existing.mode
        )));
    }
    if group_aead_key.len() != AEAD_KEY_SIZE {
        return Err(EncryptionError::InvalidWrapper(format!(
            "group_aead_key must be {AEAD_KEY_SIZE} bytes, got {}",
            group_aead_key.len()
        )));
    }
    if existing.wrapped_keys.len() + 1 > WRAPPED_KEYS_DEFAULT_CEILING {
        return Err(EncryptionError::WrappedKeysTooMany(format!(
            "adding a member would exceed §8.6 ceiling {WRAPPED_KEYS_DEFAULT_CEILING}"
        )));
    }
    group_mode_suite_allowed(existing.aead_id, existing.kdf_id)?;

    let wrap = wrap_for_member(new_member, group_aead_key, existing.aead_id, existing.kdf_id)
        .map_err(|e| EncryptionError::InvalidWrapper(format!("wrap for new member: {e}")))?;

    let mut out = existing.clone();
    out.wrapped_keys.push(wrap);
    Ok(out)
}

/// §8.5 group lifecycle — remove a member (re-key). Produces a fresh
/// `system/encrypted` for `members` over `plaintext` under a NEW
/// `group_aead_key`: the caller passes the remaining-member list (the removed
/// member absent), the plaintext is re-encrypted, and the F2-1 commitment is
/// recomputed against the new key. There is no continuity with the prior outer
/// ciphertext — the removed member keeps the OLD key and can still open OLD
/// entities (group-snapshot forward secrecy, not message-level, per §8.5).
/// Pin `new_group_aead_key` / `new_outer_nonce` for KAT determinism.
pub fn group_rekey(
    plaintext: Vec<u8>,
    members: Vec<GroupMember>,
    new_group_aead_key: Option<Vec<u8>>,
    new_outer_nonce: Option<Vec<u8>>,
) -> Result<EncryptedData, EncryptionError> {
    group_encrypt(GroupEncryptInput {
        members,
        plaintext,
        outer_nonce: new_outer_nonce,
        group_aead_key: new_group_aead_key,
    })
}

/// Per-decryption inputs.
pub struct GroupDecryptInput<'a> {
    pub wrapper: &'a EncryptedData,
    /// Receiver's own pubkey-entity content_hash (locates the wrap entry).
    pub my_pubkey_hash: Hash,
    /// Receiver's 32-byte X25519 private corresponding to `my_pubkey_hash`.
    pub my_priv: Vec<u8>,
}

/// §8.4 group-mode decryption. Recovers `group_aead_key` from the receiver's
/// wrap, reconstructs the outer AAD with `commitment = SHA-256(group_aead_key)`
/// (F2-1), and AEAD-decrypts the outer ciphertext. An equivocating author's
/// reconstructed-AAD AEAD.Open fails with `encryption_aead_failed`.
pub fn group_decrypt(input: GroupDecryptInput) -> Result<Vec<u8>, EncryptionError> {
    let w = input.wrapper;
    if w.mode != MODE_GROUP {
        return Err(EncryptionError::InvalidWrapper(format!(
            "wrapper mode {:?} is not group",
            w.mode
        )));
    }
    if input.my_priv.len() != X25519_PRIVATE_SIZE {
        return Err(EncryptionError::InvalidWrapper(format!(
            "X25519 priv must be {X25519_PRIVATE_SIZE} bytes, got {}",
            input.my_priv.len()
        )));
    }
    group_mode_suite_allowed(w.aead_id, w.kdf_id)?;

    let mut group_key: Option<Vec<u8>> = None;
    for wk in &w.wrapped_keys {
        if wk.recipient_key != input.my_pubkey_hash {
            continue;
        }
        group_key = Some(unwrap_member(wk, &input.my_priv, w.aead_id, w.kdf_id)?);
        break;
    }
    let group_key = group_key.ok_or_else(|| {
        EncryptionError::RecipientUnknown("no wrapped_keys entry matches my pubkey_hash".into())
    })?;

    let commit = commitment(&group_key);
    let outer_aad = aad::group_outer_aad(w.aead_id, w.kdf_id, &w.nonce, &commit);
    xchacha_decrypt(&group_key, &w.nonce, &outer_aad, &w.ciphertext)
}

/// §8.3 step-5 per-member wrap — peer-shaped hybrid encryption of the group
/// key, AAD domain-separated by the `group-wrap` label.
fn wrap_for_member(
    m: &GroupMember,
    group_key: &[u8],
    aead_id: u8,
    kdf_id: u8,
) -> Result<WrappedKey, EncryptionError> {
    if m.pubkey.len() != X25519_PUBLIC_SIZE {
        return Err(EncryptionError::InvalidWrapper(format!(
            "member X25519 pubkey must be {X25519_PUBLIC_SIZE} bytes, got {}",
            m.pubkey.len()
        )));
    }
    let member_hash = m.pubkey_hash.ok_or_else(|| {
        EncryptionError::InvalidWrapper("member pubkey_hash required".into())
    })?;

    let eph_seed = m.ephemeral_private_seed.clone().unwrap_or_default();
    let (eph_seed, eph_pub) = generate_or_load_x25519(&eph_seed)?;
    let wrap_nonce = match &m.wrap_nonce {
        Some(n) => n.clone(),
        None => random_nonce().to_vec(),
    };
    if wrap_nonce.len() != AEAD_NONCE_SIZE {
        return Err(EncryptionError::InvalidWrapper(format!(
            "wrap_nonce must be {AEAD_NONCE_SIZE} bytes, got {}",
            wrap_nonce.len()
        )));
    }

    let shared = x25519_shared(&eph_seed, &m.pubkey)?;
    let wrap_key = derive_aead_key(&shared, &wrap_nonce, &member_hash)?;
    let aad = aad::group_wrap_aad(ENC_KEY_TYPE_X25519, aead_id, kdf_id, &wrap_nonce, &member_hash, &eph_pub);
    let wrapped = xchacha_encrypt(&wrap_key, &wrap_nonce, &aad, group_key)?;

    Ok(WrappedKey {
        recipient_key: member_hash,
        enc_key_type: ENC_KEY_TYPE_X25519,
        ephemeral_key: eph_pub.to_vec(),
        wrapped_aead_key: wrapped,
        wrap_nonce,
    })
}

/// §8.4 step-3 inverse — recover `group_aead_key` from a wrap the receiver owns.
fn unwrap_member(
    wk: &WrappedKey,
    my_priv: &[u8],
    aead_id: u8,
    kdf_id: u8,
) -> Result<Vec<u8>, EncryptionError> {
    let shared = x25519_shared(my_priv, &wk.ephemeral_key)?;
    let wrap_key = derive_aead_key(&shared, &wk.wrap_nonce, &wk.recipient_key)?;
    let aad = aad::group_wrap_aad(
        wk.enc_key_type,
        aead_id,
        kdf_id,
        &wk.wrap_nonce,
        &wk.recipient_key,
        &wk.ephemeral_key,
    );
    xchacha_decrypt(&wrap_key, &wk.wrap_nonce, &aad, &wk.wrapped_aead_key)
}
