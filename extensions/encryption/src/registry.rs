//! §3 algorithm-byte registries (`enc_key_type` / `aead_id` / `kdf_id`) plus
//! the §5.3 / §3.4 suite-admissibility checks.
//!
//! Each algorithm choice is a varint-encoded byte under a documented registry,
//! per the v7.65–v7.69 multikey-style discipline. The constants below are the
//! wire bytes; the `*_name` helpers are debug/log labels only.

use crate::types::EncryptionError;

// §3.1 enc_key_type — encryption keypair algorithm.
pub const ENC_KEY_TYPE_RESERVED: u8 = 0x00;
pub const ENC_KEY_TYPE_X25519: u8 = 0x01; // v1 floor
pub const ENC_KEY_TYPE_X448: u8 = 0x02; // reserved (pairs with Ed448 validate slot)
pub const ENC_KEY_TYPE_MLKEM768: u8 = 0x03; // reserved PQ KEM
pub const ENC_KEY_TYPE_X25519_MLKEM768_HYBRID: u8 = 0x04; // reserved hybrid (PQ upgrade)
pub const ENC_KEY_TYPE_MLKEM512: u8 = 0x05;
pub const ENC_KEY_TYPE_MLKEM1024: u8 = 0x06;
pub const ENC_KEY_TYPE_TEST_ONLY: u8 = 0xFE;

// §3.2 aead_id — symmetric AEAD.
pub const AEAD_ID_RESERVED: u8 = 0x00;
pub const AEAD_ID_XCHACHA20_POLY1305: u8 = 0x01; // v1 floor
pub const AEAD_ID_AES256_GCM: u8 = 0x02; // peer-mode only in v1
pub const AEAD_ID_CHACHA20_POLY1305_IETF: u8 = 0x03; // peer-mode only in v1
pub const AEAD_ID_AEGIS256: u8 = 0x04;

// §3.3 kdf_id — key derivation.
pub const KDF_ID_RESERVED: u8 = 0x00;
pub const KDF_ID_HKDF_SHA256: u8 = 0x01; // v1 floor
pub const KDF_ID_HKDF_SHA512: u8 = 0x02;
pub const KDF_ID_HKDF_SHA384: u8 = 0x03;
pub const KDF_ID_ARGON2ID: u8 = 0x04;

/// Argon2 version pinned by §6.2 / §9.2 (v1.3 / v19).
pub const ARGON2ID_VERSION: u32 = 0x13;

/// Human label for an `enc_key_type` registry byte (`unknown(0xNN)` otherwise).
pub fn enc_key_type_name(b: u8) -> String {
    match b {
        ENC_KEY_TYPE_RESERVED => "reserved".into(),
        ENC_KEY_TYPE_X25519 => "X25519".into(),
        ENC_KEY_TYPE_X448 => "X448".into(),
        ENC_KEY_TYPE_MLKEM768 => "ML-KEM-768".into(),
        ENC_KEY_TYPE_X25519_MLKEM768_HYBRID => "X25519+ML-KEM-768".into(),
        ENC_KEY_TYPE_MLKEM512 => "ML-KEM-512".into(),
        ENC_KEY_TYPE_MLKEM1024 => "ML-KEM-1024".into(),
        ENC_KEY_TYPE_TEST_ONLY => "test-only".into(),
        other => format!("unknown(0x{other:02x})"),
    }
}

/// Human label for an `aead_id` registry byte.
pub fn aead_id_name(b: u8) -> String {
    match b {
        AEAD_ID_RESERVED => "reserved".into(),
        AEAD_ID_XCHACHA20_POLY1305 => "XChaCha20-Poly1305".into(),
        AEAD_ID_AES256_GCM => "AES-256-GCM".into(),
        AEAD_ID_CHACHA20_POLY1305_IETF => "ChaCha20-Poly1305-IETF".into(),
        AEAD_ID_AEGIS256 => "AEGIS-256".into(),
        other => format!("unknown(0x{other:02x})"),
    }
}

/// Human label for a `kdf_id` registry byte.
pub fn kdf_id_name(b: u8) -> String {
    match b {
        KDF_ID_RESERVED => "reserved".into(),
        KDF_ID_HKDF_SHA256 => "HKDF-SHA-256".into(),
        KDF_ID_HKDF_SHA512 => "HKDF-SHA-512".into(),
        KDF_ID_HKDF_SHA384 => "HKDF-SHA-384".into(),
        KDF_ID_ARGON2ID => "Argon2id".into(),
        other => format!("unknown(0x{other:02x})"),
    }
}

/// §5.3 self-mode suite admissibility. AEADs with 96-bit nonces are forbidden
/// in self/group for v1 (a stable key + random 96-bit nonce risks collision);
/// only XChaCha20-Poly1305 (192-bit nonce) + HKDF-SHA-256 are allowed.
pub fn self_mode_suite_allowed(aead_id: u8, kdf_id: u8) -> Result<(), EncryptionError> {
    match aead_id {
        AEAD_ID_XCHACHA20_POLY1305 => {}
        AEAD_ID_AES256_GCM | AEAD_ID_CHACHA20_POLY1305_IETF => {
            return Err(EncryptionError::UnsupportedSuite(format!(
                "AEAD 0x{aead_id:02x} forbidden in self mode (96-bit nonce + stable key risks collision)"
            )));
        }
        other => {
            return Err(EncryptionError::UnsupportedSuite(format!(
                "AEAD 0x{other:02x} not allowed in self mode for v1"
            )));
        }
    }
    match kdf_id {
        KDF_ID_HKDF_SHA256 => Ok(()),
        other => Err(EncryptionError::UnsupportedSuite(format!(
            "KDF 0x{other:02x} not allowed in self mode for v1"
        ))),
    }
}

/// §5.3 group-mode suite admissibility — identical to self mode (the outer key
/// is a stable random `group_aead_key` for the entity's lifetime, so the
/// nonce-reuse hazard applies the same way).
pub fn group_mode_suite_allowed(aead_id: u8, kdf_id: u8) -> Result<(), EncryptionError> {
    self_mode_suite_allowed(aead_id, kdf_id)
}

/// §3.4 / §5.3 peer-mode suite admissibility for v1. XChaCha20-Poly1305 +
/// HKDF-SHA-256 + X25519 is the v1 floor (AES-GCM / IETF-ChaCha20 are
/// spec-allowed in peer mode but not v1-impl-required here).
pub fn peer_mode_suite_allowed(
    enc_key_type: u8,
    aead_id: u8,
    kdf_id: u8,
) -> Result<(), EncryptionError> {
    match enc_key_type {
        ENC_KEY_TYPE_X25519 => {}
        other => {
            return Err(EncryptionError::UnsupportedSuite(format!(
                "enc_key_type 0x{other:02x} not supported in peer mode for v1"
            )));
        }
    }
    match aead_id {
        AEAD_ID_XCHACHA20_POLY1305 => {}
        other => {
            return Err(EncryptionError::UnsupportedSuite(format!(
                "AEAD 0x{other:02x} not supported in peer mode for v1"
            )));
        }
    }
    match kdf_id {
        KDF_ID_HKDF_SHA256 => Ok(()),
        other => Err(EncryptionError::UnsupportedSuite(format!(
            "KDF 0x{other:02x} not supported in peer mode for v1"
        ))),
    }
}

/// §3.4 cipher-suite negotiation. Picks the first `(aead_id, kdf_id)` pair the
/// recipient advertises that the sender also supports — the recipient drives
/// the preference order. Returns [`EncryptionError::NoCommonSuite`] if empty.
pub fn intersect_suite(
    recipient_aead: &[u32],
    recipient_kdf: &[u32],
    sender_aead: &[u32],
    sender_kdf: &[u32],
) -> Result<(u8, u8), EncryptionError> {
    for &a in recipient_aead {
        if !sender_aead.contains(&a) {
            continue;
        }
        for &k in recipient_kdf {
            if sender_kdf.contains(&k) {
                return Ok((a as u8, k as u8));
            }
        }
    }
    Err(EncryptionError::NoCommonSuite(
        "no common (aead_id, kdf_id) in recipient and sender advertised suites".into(),
    ))
}
