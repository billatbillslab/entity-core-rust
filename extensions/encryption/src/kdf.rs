//! §6.2 / §9.2 key derivation: Argon2id (passphrase → KEK) + HKDF-SHA-256
//! (KEK / shared-secret → per-entity AEAD key).

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

use crate::registry::ARGON2ID_VERSION;
use crate::types::{EncryptionError, KdfParams, KDF_SALT_MIN_BYTES};

/// §6.2 Argon2id derivation. Version is pinned to `0x13` (v1.3 / v19); a
/// `kdf_params.argon2_version` mismatch fails loudly so a backup authored
/// under a different version is rejected rather than silently mis-derived.
pub fn argon2id_key(
    passphrase: &[u8],
    salt: &[u8],
    params: KdfParams,
) -> Result<Vec<u8>, EncryptionError> {
    if params.argon2_version != ARGON2ID_VERSION {
        return Err(EncryptionError::UnsupportedSuite(format!(
            "argon2_version 0x{:02x} != pinned 0x{:02x}",
            params.argon2_version, ARGON2ID_VERSION
        )));
    }
    if salt.len() < KDF_SALT_MIN_BYTES {
        return Err(EncryptionError::InvalidWrapper(format!(
            "kdf_salt {} bytes < {} minimum",
            salt.len(),
            KDF_SALT_MIN_BYTES
        )));
    }
    if params.output_len == 0 {
        return Err(EncryptionError::InvalidWrapper(
            "kdf_params.output_len must be > 0".into(),
        ));
    }
    if params.parallelism == 0 {
        return Err(EncryptionError::InvalidWrapper(
            "kdf_params.parallelism must be > 0".into(),
        ));
    }

    let p = Params::new(
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        Some(params.output_len as usize),
    )
    .map_err(|e| EncryptionError::InvalidWrapper(format!("argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = vec![0u8; params.output_len as usize];
    argon
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|e| EncryptionError::InvalidWrapper(format!("argon2id derive: {e}")))?;
    Ok(out)
}

/// HKDF-SHA-256 expand per RFC 5869 (`kdf_id` `0x01`, v1 floor). `salt` is the
/// per-message salt (the AEAD nonce in self/peer modes); `info` is the
/// domain-separated ASCII prefix concatenated with any bound context bytes (no
/// separator, no NUL — F-GO-9).
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, EncryptionError> {
    if length == 0 {
        return Err(EncryptionError::InvalidWrapper(
            "HKDF length must be positive".into(),
        ));
    }
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .map_err(|e| EncryptionError::InvalidWrapper(format!("HKDF-SHA-256 expand: {e}")))?;
    Ok(okm)
}

/// A fresh random `kdf_salt` of the §6.1 floor length (16 bytes).
pub fn random_salt() -> [u8; KDF_SALT_MIN_BYTES] {
    let mut b = [0u8; KDF_SALT_MIN_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}
