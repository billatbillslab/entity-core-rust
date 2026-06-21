//! §6 mode=self — at-rest storage encryption with a key derived from a local
//! secret (passphrase / keyfile / keychain). PRIMARY in v1.0. No public-key
//! crypto.
//!
//! Derivation (§6.2):
//! ```text
//! kek      = Argon2id(passphrase, kdf_salt, v=0x13, m, t, p, out=32)
//! aead_key = HKDF-SHA-256(ikm=kek, salt=nonce, info="entity-core/self/"||key_id, L=32)
//! ```

use crate::aead::{random_nonce, xchacha_decrypt, xchacha_encrypt, AEAD_KEY_SIZE, AEAD_NONCE_SIZE};
use crate::kdf::{argon2id_key, hkdf_sha256, random_salt};
use crate::registry::{self_mode_suite_allowed, AEAD_ID_XCHACHA20_POLY1305, KDF_ID_HKDF_SHA256};
use crate::types::{EncryptionError, KdfParams, MODE_SELF};
use crate::wrapper::EncryptedData;
use crate::aad;

/// §6.2 ASCII HKDF-info prefix — no separator, no NUL before `key_id` (F-GO-9).
const SELF_INFO_PREFIX: &str = "entity-core/self/";

/// Per-encryption inputs the spec marks random (§6.3) but that callers pin for
/// KAT determinism. `None` → freshly generated.
#[derive(Debug, Default, Clone)]
pub struct SelfEncryptParams {
    pub nonce: Option<Vec<u8>>,
    pub kdf_salt: Option<Vec<u8>>,
    pub params: Option<KdfParams>,
}

/// §6.3 self-mode encryption. `plaintext` is the raw bytes to encrypt
/// (typically an inner entity's ECF; the caller chooses the framing).
pub fn self_encrypt(
    passphrase: &[u8],
    key_id: &str,
    plaintext: &[u8],
    p: SelfEncryptParams,
) -> Result<EncryptedData, EncryptionError> {
    if key_id.is_empty() {
        return Err(EncryptionError::InvalidWrapper(
            "self-mode key_id required".into(),
        ));
    }
    let params = p.params.unwrap_or_default();
    let nonce = match p.nonce {
        Some(n) => n,
        None => random_nonce().to_vec(),
    };
    if nonce.len() != AEAD_NONCE_SIZE {
        return Err(EncryptionError::InvalidWrapper(format!(
            "self-mode nonce must be {AEAD_NONCE_SIZE} bytes, got {}",
            nonce.len()
        )));
    }
    let kdf_salt = match p.kdf_salt {
        Some(s) => s,
        None => random_salt().to_vec(),
    };

    // v1 floor suite.
    let aead_id = AEAD_ID_XCHACHA20_POLY1305;
    let kdf_id = KDF_ID_HKDF_SHA256;
    self_mode_suite_allowed(aead_id, kdf_id)?;

    let aead_key = derive_aead_key(passphrase, key_id, &nonce, &kdf_salt, params)?;
    let aad = aad::self_aad(aead_id, kdf_id, &nonce, &kdf_salt, params.to_ecf_value());
    let ct = xchacha_encrypt(&aead_key, &nonce, &aad, plaintext)?;

    let mut ed = EncryptedData::common(MODE_SELF, 0, aead_id, kdf_id, nonce, ct);
    ed.key_id = Some(key_id.to_string());
    ed.kdf_salt = Some(kdf_salt);
    ed.kdf_params = Some(params);
    Ok(ed)
}

/// §6.4 self-mode decryption. `passphrase` is resolved by the caller from
/// `ed.key_id`; this primitive consumes it.
pub fn self_decrypt(passphrase: &[u8], ed: &EncryptedData) -> Result<Vec<u8>, EncryptionError> {
    if ed.mode != MODE_SELF {
        return Err(EncryptionError::InvalidWrapper(format!(
            "wrapper mode {:?} is not self",
            ed.mode
        )));
    }
    let params = ed.kdf_params.ok_or_else(|| {
        EncryptionError::InvalidWrapper("self-mode wrapper missing kdf_params".into())
    })?;
    let key_id = ed.key_id.as_deref().ok_or_else(|| {
        EncryptionError::InvalidWrapper("self-mode wrapper missing key_id".into())
    })?;
    let kdf_salt = ed.kdf_salt.as_deref().ok_or_else(|| {
        EncryptionError::InvalidWrapper("self-mode wrapper missing kdf_salt".into())
    })?;
    self_mode_suite_allowed(ed.aead_id, ed.kdf_id)?;

    let aead_key = derive_aead_key(passphrase, key_id, &ed.nonce, kdf_salt, params)?;
    let aad = aad::self_aad(ed.aead_id, ed.kdf_id, &ed.nonce, kdf_salt, params.to_ecf_value());
    xchacha_decrypt(&aead_key, &ed.nonce, &aad, &ed.ciphertext)
}

/// §6.2 derivation chain: passphrase → Argon2id → HKDF-SHA-256 → 32-byte key.
fn derive_aead_key(
    passphrase: &[u8],
    key_id: &str,
    nonce: &[u8],
    kdf_salt: &[u8],
    params: KdfParams,
) -> Result<Vec<u8>, EncryptionError> {
    let kek = argon2id_key(passphrase, kdf_salt, params)?;
    let mut info = SELF_INFO_PREFIX.as_bytes().to_vec();
    info.extend_from_slice(key_id.as_bytes());
    hkdf_sha256(&kek, nonce, &info, AEAD_KEY_SIZE)
}
