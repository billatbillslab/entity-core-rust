//! §7.3 X25519 ECDH (`enc_key_type` `0x01`, v1 floor) per RFC 7748.
//!
//! `x25519-dalek` and Go's `crypto/ecdh` both implement RFC 7748 with the
//! standard scalar clamping, so a given 32-byte seed yields the same public
//! key and the same shared secret in both — the basis for byte-equal peer/group
//! KATs.

use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::types::EncryptionError;

/// X25519 private-key seed length (32 bytes per RFC 7748).
pub const X25519_PRIVATE_SIZE: usize = 32;
/// X25519 public-key length.
pub const X25519_PUBLIC_SIZE: usize = 32;

fn array32(bytes: &[u8], what: &str) -> Result<[u8; 32], EncryptionError> {
    bytes.try_into().map_err(|_| {
        EncryptionError::InvalidWrapper(format!(
            "{what} must be {X25519_PRIVATE_SIZE} bytes, got {}",
            bytes.len()
        ))
    })
}

/// Derive the X25519 public key for a 32-byte private seed.
pub fn x25519_public(seed: &[u8]) -> Result<[u8; X25519_PUBLIC_SIZE], EncryptionError> {
    let s = StaticSecret::from(array32(seed, "X25519 priv seed")?);
    Ok(PublicKey::from(&s).to_bytes())
}

/// Compute the X25519 shared secret between a local private seed and a peer
/// public key.
pub fn x25519_shared(my_seed: &[u8], their_pub: &[u8]) -> Result<[u8; 32], EncryptionError> {
    let s = StaticSecret::from(array32(my_seed, "X25519 priv seed")?);
    let p = PublicKey::from(array32(their_pub, "X25519 pubkey")?);
    Ok(s.diffie_hellman(&p).to_bytes())
}

/// Generate a fresh random X25519 keypair, returning `(private_seed, public)`.
pub fn generate_x25519() -> ([u8; X25519_PRIVATE_SIZE], [u8; X25519_PUBLIC_SIZE]) {
    let mut seed = [0u8; X25519_PRIVATE_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let s = StaticSecret::from(seed);
    (seed, PublicKey::from(&s).to_bytes())
}

/// Generate fresh bytes if `seed` is empty, else validate + return it, paired
/// with the derived public key. Mirrors Go's `generateOrLoadX25519`.
pub fn generate_or_load_x25519(
    seed: &[u8],
) -> Result<([u8; X25519_PRIVATE_SIZE], [u8; X25519_PUBLIC_SIZE]), EncryptionError> {
    if seed.is_empty() {
        return Ok(generate_x25519());
    }
    let arr = array32(seed, "X25519 priv seed")?;
    let s = StaticSecret::from(arr);
    Ok((arr, PublicKey::from(&s).to_bytes()))
}
