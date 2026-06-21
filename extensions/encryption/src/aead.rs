//! §3.2 entry `0x01` — XChaCha20-Poly1305 AEAD (v1 floor).
//!
//! 256-bit key, 192-bit nonce, 128-bit tag (RFC 8439 + XSalsa20 nonce
//! extension). Safe under random nonces — collision probability ≈ 2⁻⁹⁶ after
//! 2⁴⁸ messages per key (§5.3 birthday bound).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;

use crate::types::EncryptionError;

/// XChaCha20-Poly1305 key length in bytes.
pub const AEAD_KEY_SIZE: usize = 32;
/// XChaCha20-Poly1305 nonce length in bytes.
pub const AEAD_NONCE_SIZE: usize = 24;
/// Poly1305 tag length appended to ciphertext.
pub const AEAD_OVERHEAD: usize = 16;

/// Produce `ciphertext || tag` for `key`+`nonce`+`aad` over `plaintext`.
pub fn xchacha_encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    check_lengths(key, nonce)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|e| {
            EncryptionError::UnsupportedSuite(format!("XChaCha20-Poly1305 encrypt: {e}"))
        })
}

/// Verify + decrypt `ciphertext || tag`. On tag failure returns
/// [`EncryptionError::AeadFailed`] (§15 `encryption_aead_failed`).
pub fn xchacha_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    check_lengths(key, nonce)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| EncryptionError::AeadFailed("AEAD tag verification failed".into()))
}

fn check_lengths(key: &[u8], nonce: &[u8]) -> Result<(), EncryptionError> {
    if key.len() != AEAD_KEY_SIZE {
        return Err(EncryptionError::UnsupportedSuite(format!(
            "XChaCha20-Poly1305 requires {AEAD_KEY_SIZE}-byte key, got {}",
            key.len()
        )));
    }
    if nonce.len() != AEAD_NONCE_SIZE {
        return Err(EncryptionError::UnsupportedSuite(format!(
            "XChaCha20-Poly1305 requires {AEAD_NONCE_SIZE}-byte nonce, got {}",
            nonce.len()
        )));
    }
    Ok(())
}

/// A fresh random 24-byte XChaCha20-Poly1305 nonce.
pub fn random_nonce() -> [u8; AEAD_NONCE_SIZE] {
    let mut b = [0u8; AEAD_NONCE_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

/// A fresh random 32-byte key (group mode mints one `group_aead_key` per
/// encrypted entity).
pub fn random_key() -> [u8; AEAD_KEY_SIZE] {
    let mut b = [0u8; AEAD_KEY_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}
