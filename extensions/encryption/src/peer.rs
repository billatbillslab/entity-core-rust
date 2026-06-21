//! §7 mode=peer — non-interactive single-shot hybrid encryption to one
//! recipient. PRIMARY in v1.0. Structurally equivalent to age / NaCl
//! `crypto_box` / libsodium sealed-box (with sender auth layered on top).
//!
//! Provides receiver authentication + sender ephemerality. Sender
//! authentication (§7.4 `system/signature` at the invariant pointer) is a
//! SEPARATE handler-layer step performed once the wrapper's `content_hash` is
//! known — NOT a field on the entity (F-GO-3). Does NOT provide forward secrecy
//! against recipient-key compromise (no ratchet); that's the deferred session
//! sibling.

use entity_hash::Hash;

use crate::aead::{random_nonce, xchacha_decrypt, xchacha_encrypt, AEAD_KEY_SIZE, AEAD_NONCE_SIZE};
use crate::ecdh::{generate_or_load_x25519, x25519_shared, X25519_PRIVATE_SIZE, X25519_PUBLIC_SIZE};
use crate::kdf::hkdf_sha256;
use crate::registry::{
    peer_mode_suite_allowed, AEAD_ID_XCHACHA20_POLY1305, ENC_KEY_TYPE_X25519, KDF_ID_HKDF_SHA256,
};
use crate::types::{EncryptionError, MODE_PEER};
use crate::wrapper::EncryptedData;
use crate::aad;

/// §7.3 step-4 ASCII HKDF-info prefix. The bound context is the F-GO-1
/// uniform-across-tiers `recipient_pubkey_hash` wire bytes (33 bytes for
/// SHA-256: algorithm byte || digest), so Tier-A and Tier-C decryptors derive
/// identical keys.
const PEER_INFO_PREFIX: &str = "entity-core/peer/";

/// Per-encryption inputs (KAT determinism). `None`/empty → freshly random.
#[derive(Debug, Default, Clone)]
pub struct PeerEncryptInput {
    /// Recipient's 32-byte X25519 public key, as published in their
    /// `system/encryption-pubkey.public_key`.
    pub recipient_pubkey: Vec<u8>,
    /// `content_hash(system/encryption-pubkey)` — the F-GO-1 binding. The
    /// caller resolves this from the recipient namespace per §4.4.
    pub recipient_pubkey_hash: Option<Hash>,
    pub plaintext: Vec<u8>,
    /// Pins the AEAD nonce; `None` → random 24 bytes.
    pub nonce: Option<Vec<u8>>,
    /// Pins the sender ephemeral X25519 private seed; `None` → random.
    pub ephemeral_private_seed: Option<Vec<u8>>,
}

/// §7.3 peer-mode encryption.
pub fn peer_encrypt(input: PeerEncryptInput) -> Result<EncryptedData, EncryptionError> {
    if input.recipient_pubkey.len() != X25519_PUBLIC_SIZE {
        return Err(EncryptionError::InvalidWrapper(format!(
            "X25519 recipient pubkey must be {X25519_PUBLIC_SIZE} bytes, got {}",
            input.recipient_pubkey.len()
        )));
    }
    let recipient_hash = input.recipient_pubkey_hash.ok_or_else(|| {
        EncryptionError::InvalidWrapper("recipient_key hash required".into())
    })?;

    let enc_key_type = ENC_KEY_TYPE_X25519;
    let aead_id = AEAD_ID_XCHACHA20_POLY1305;
    let kdf_id = KDF_ID_HKDF_SHA256;
    peer_mode_suite_allowed(enc_key_type, aead_id, kdf_id)?;

    let nonce = match input.nonce {
        Some(n) => n,
        None => random_nonce().to_vec(),
    };
    if nonce.len() != AEAD_NONCE_SIZE {
        return Err(EncryptionError::InvalidWrapper(format!(
            "peer-mode nonce must be {AEAD_NONCE_SIZE} bytes, got {}",
            nonce.len()
        )));
    }

    let eph_seed = input.ephemeral_private_seed.unwrap_or_default();
    let (eph_seed, eph_pub) = generate_or_load_x25519(&eph_seed)?;
    let shared = x25519_shared(&eph_seed, &input.recipient_pubkey)?;

    let aead_key = derive_aead_key(&shared, &nonce, &recipient_hash)?;
    let aad = aad::peer_aad(enc_key_type, aead_id, kdf_id, &nonce, &recipient_hash, &eph_pub);
    let ct = xchacha_encrypt(&aead_key, &nonce, &aad, &input.plaintext)?;

    let mut ed = EncryptedData::common(MODE_PEER, enc_key_type, aead_id, kdf_id, nonce, ct);
    ed.ephemeral_key = Some(eph_pub.to_vec());
    ed.recipient_key = Some(recipient_hash);
    Ok(ed)
}

/// §7.5 peer-mode decryption. The caller matches `ed.recipient_key` against
/// locally-held pubkey entities to select `recipient_priv`; sender-signature
/// verification (§7.4) is a separate handler-layer step.
pub fn peer_decrypt(ed: &EncryptedData, recipient_priv: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    if ed.mode != MODE_PEER {
        return Err(EncryptionError::InvalidWrapper(format!(
            "wrapper mode {:?} is not peer",
            ed.mode
        )));
    }
    peer_mode_suite_allowed(ed.enc_key_type, ed.aead_id, ed.kdf_id)?;
    if recipient_priv.len() != X25519_PRIVATE_SIZE {
        return Err(EncryptionError::InvalidWrapper(format!(
            "X25519 recipient priv must be {X25519_PRIVATE_SIZE} bytes, got {}",
            recipient_priv.len()
        )));
    }
    let eph_pub = ed.ephemeral_key.as_deref().ok_or_else(|| {
        EncryptionError::InvalidWrapper("peer-mode wrapper missing ephemeral_key".into())
    })?;
    let recipient_hash = ed.recipient_key.ok_or_else(|| {
        EncryptionError::InvalidWrapper("peer-mode wrapper missing recipient_key".into())
    })?;

    let shared = x25519_shared(recipient_priv, eph_pub)?;
    let aead_key = derive_aead_key(&shared, &ed.nonce, &recipient_hash)?;
    let aad = aad::peer_aad(ed.enc_key_type, ed.aead_id, ed.kdf_id, &ed.nonce, &recipient_hash, eph_pub);
    xchacha_decrypt(&aead_key, &ed.nonce, &aad, &ed.ciphertext)
}

/// §7.3 step-4 HKDF: `info = "entity-core/peer/" || recipient_pubkey_hash`.
/// Shared by group per-wrap derivation (§8.3). Exposed in-crate so group mode
/// reuses the exact peer key schedule.
pub(crate) fn derive_aead_key(
    shared_secret: &[u8],
    nonce: &[u8],
    recipient_pubkey_hash: &Hash,
) -> Result<Vec<u8>, EncryptionError> {
    let mut info = PEER_INFO_PREFIX.as_bytes().to_vec();
    info.extend_from_slice(&recipient_pubkey_hash.to_bytes());
    hkdf_sha256(shared_secret, nonce, &info, AEAD_KEY_SIZE)
}
