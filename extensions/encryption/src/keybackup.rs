//! §9.2 Tier-2 passphrase-wrapped key backup (Tier A/B path —
//! `system/encryption/key-backup`).
//!
//! Derivation (§9.2):
//! ```text
//! kek         = Argon2id(passphrase, kdf_salt, v=0x13, m, t, p, out=32)
//! wrap_key    = HKDF-SHA-256(ikm=kek, salt=wrap_nonce, info="entity-core/key-backup/"||pubkey_ref, L=32)
//! backup_AAD  = ECF{pubkey_ref, argon2_version, memory_cost, time_cost, parallelism, output_len}
//! wrapped_key = XChaCha20-Poly1305(wrap_key, wrap_nonce, AAD=backup_AAD, private_key_bytes)
//! ```

use entity_ecf::{to_ecf, Value};
use entity_hash::Hash;

use crate::aead::{xchacha_decrypt, xchacha_encrypt, AEAD_KEY_SIZE, AEAD_NONCE_SIZE};
use crate::kdf::{argon2id_key, hkdf_sha256};
use crate::types::{EncryptionError, KdfParams};

/// §9.2 ASCII HKDF-info prefix — binds the backup to the specific key.
const BACKUP_INFO_PREFIX: &str = "entity-core/key-backup/";

/// §9.2 backup entity. At Tier C the equivalent shape uses `cert_ref` under
/// `system/identity/internal/key-backup` (handled when IDENTITY is wired).
#[derive(Debug, Clone)]
pub struct EncryptionKeyBackupData {
    pub pubkey_ref: Hash,
    pub kdf_salt: Vec<u8>,
    pub kdf_params: KdfParams,
    pub wrap_nonce: Vec<u8>,
    pub wrapped_key: Vec<u8>,
}

/// §9.2 `backup_AAD` — 6-key ECF binding the key reference + derivation params.
/// Keys sort length-first (`time_cost` < `output_len` < `pubkey_ref` <
/// `memory_cost` < `parallelism` < `argon2_version`).
pub fn backup_aad(pubkey_ref: &Hash, params: KdfParams) -> Vec<u8> {
    let m = Value::Map(vec![
        (Value::Text("pubkey_ref".into()), Value::Bytes(pubkey_ref.to_bytes())),
        (Value::Text("argon2_version".into()), Value::Integer(params.argon2_version.into())),
        (Value::Text("memory_cost".into()), Value::Integer(params.memory_cost.into())),
        (Value::Text("time_cost".into()), Value::Integer(params.time_cost.into())),
        (Value::Text("parallelism".into()), Value::Integer(params.parallelism.into())),
        (Value::Text("output_len".into()), Value::Integer(params.output_len.into())),
    ]);
    to_ecf(&m)
}

/// §9.2 wrap: passphrase-encrypt `private_key_bytes` into a backup entity.
pub fn wrap_private_key(
    passphrase: &[u8],
    pubkey_ref: Hash,
    private_key_bytes: &[u8],
    kdf_salt: Vec<u8>,
    wrap_nonce: Vec<u8>,
    params: KdfParams,
) -> Result<EncryptionKeyBackupData, EncryptionError> {
    if wrap_nonce.len() != AEAD_NONCE_SIZE {
        return Err(EncryptionError::InvalidWrapper(format!(
            "wrap_nonce must be {AEAD_NONCE_SIZE} bytes, got {}",
            wrap_nonce.len()
        )));
    }
    let wrap_key = derive_wrap_key(passphrase, &pubkey_ref, &kdf_salt, &wrap_nonce, params)?;
    let aad = backup_aad(&pubkey_ref, params);
    let wrapped_key = xchacha_encrypt(&wrap_key, &wrap_nonce, &aad, private_key_bytes)?;
    Ok(EncryptionKeyBackupData {
        pubkey_ref,
        kdf_salt,
        kdf_params: params,
        wrap_nonce,
        wrapped_key,
    })
}

/// §9.2 unwrap: passphrase-recover the private key from a backup entity.
pub fn unwrap_private_key(
    passphrase: &[u8],
    backup: &EncryptionKeyBackupData,
) -> Result<Vec<u8>, EncryptionError> {
    let wrap_key = derive_wrap_key(
        passphrase,
        &backup.pubkey_ref,
        &backup.kdf_salt,
        &backup.wrap_nonce,
        backup.kdf_params,
    )?;
    let aad = backup_aad(&backup.pubkey_ref, backup.kdf_params);
    xchacha_decrypt(&wrap_key, &backup.wrap_nonce, &aad, &backup.wrapped_key)
}

fn derive_wrap_key(
    passphrase: &[u8],
    pubkey_ref: &Hash,
    kdf_salt: &[u8],
    wrap_nonce: &[u8],
    params: KdfParams,
) -> Result<Vec<u8>, EncryptionError> {
    let kek = argon2id_key(passphrase, kdf_salt, params)?;
    let mut info = BACKUP_INFO_PREFIX.as_bytes().to_vec();
    info.extend_from_slice(&pubkey_ref.to_bytes());
    hkdf_sha256(&kek, wrap_nonce, &info, AEAD_KEY_SIZE)
}
