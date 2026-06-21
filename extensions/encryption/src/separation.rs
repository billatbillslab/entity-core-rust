//! §2 / §9.4 / §16 ENC-KEY-SEPARATION-1 (arch v2.5 ruling R6) — the normative
//! key-separation MUST: an encryption keypair MUST NOT be derived from the
//! peer's identity (Ed25519) key.
//!
//! Two checks an impl MUST enforce when an encryption keypair is generated or
//! an encryption-pubkey is accepted for a peer whose identity key is known:
//!
//!   1. `encryption_pk != identity_pk` — the X25519 pubkey is not the raw
//!      Ed25519 pubkey bytes.
//!   2. `encryption_pk != birational(identity_pk)` — the X25519 pubkey is not
//!      the well-known Ed25519→X25519 image of the identity key (the
//!      libsodium `crypto_sign_ed25519_pk_to_curve25519` transform,
//!      `u = (1+y)/(1-y) mod 2^255-19`).
//!
//! This is a BLOCK-1 vector against real key generation; it cannot be observed
//! from the pinned-seed KATs. Mirrors Go's `ext/encryption/separation.go`
//! (`BirationalEdToX25519` / `ValidateKeySeparation`); the birational map is
//! computed via curve25519-dalek's `EdwardsPoint::to_montgomery`, which is the
//! same y-only transform.

use curve25519_dalek::edwards::CompressedEdwardsY;

use crate::types::EncryptionError;

/// Map a 32-byte Ed25519 (Edwards-compressed) public key to the corresponding
/// 32-byte Curve25519 (Montgomery-u) public key via the birational equivalence
/// `u = (1 + y) / (1 - y) (mod 2^255 - 19)`. Matches libsodium's
/// `crypto_sign_ed25519_pk_to_curve25519`.
///
/// Returns `None` when the Ed25519 bytes do not decompress to a valid Edwards
/// point (degenerate input — no birational image to collide with), mirroring
/// Go's `(1-y) not invertible` path.
pub fn birational_ed25519_to_x25519(identity_ed25519_pk: &[u8; 32]) -> Option<[u8; 32]> {
    let point = CompressedEdwardsY(*identity_ed25519_pk).decompress()?;
    Some(point.to_montgomery().to_bytes())
}

/// Constant-time equality over two 32-byte public keys. The operands are
/// public, so this is for parity with Go's `subtle.ConstantTimeCompare` intent
/// rather than secret-protection.
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Enforce the R6 MUST: returns [`EncryptionError::KeyDerivedFromIdentity`]
/// when the X25519 encryption pubkey equals the raw Ed25519 identity pubkey
/// bytes, OR equals the birational X25519 image of the identity key. The
/// caller MUST run this for every published / accepted encryption-pubkey whose
/// owner has a known identity key.
pub fn validate_key_separation(
    identity_ed25519_pk: &[u8; 32],
    encryption_x25519_pk: &[u8; 32],
) -> Result<(), EncryptionError> {
    if ct_eq(identity_ed25519_pk, encryption_x25519_pk) {
        return Err(EncryptionError::KeyDerivedFromIdentity(
            "encryption_pk == identity_pk bytes".into(),
        ));
    }
    // A degenerate identity key with no birational image cannot collide; treat
    // separation as satisfied by construction (Go returns nil here too).
    if let Some(birational) = birational_ed25519_to_x25519(identity_ed25519_pk) {
        if ct_eq(&birational, encryption_x25519_pk) {
            return Err(EncryptionError::KeyDerivedFromIdentity(
                "encryption_pk == birational(identity_pk) (Ed25519→X25519 map forbidden)".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecdh::x25519_public;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;

    /// A deterministic valid Ed25519 public key for the test: `s · B` for a
    /// fixed scalar `s`. (Real identity keys are produced by core/crypto; this
    /// only needs to be a decompressible Edwards point.)
    fn identity_ed25519_pk(s: u8) -> [u8; 32] {
        let scalar = Scalar::from(s as u64) + Scalar::ONE; // avoid 0
        (scalar * ED25519_BASEPOINT_POINT).compress().to_bytes()
    }

    /// ENC-KEY-SEPARATION-1 (R6): the X25519 encryption pubkey MUST NOT be the
    /// identity key bytes NOR its birational image; an independent X25519 key
    /// is accepted.
    #[test]
    fn enc_key_separation_1() {
        let identity = identity_ed25519_pk(7);

        // (1) encryption_pk == identity_pk bytes → rejected.
        let err = validate_key_separation(&identity, &identity).unwrap_err();
        assert_eq!(err.code(), "encryption_key_derived_from_identity");

        // (2) encryption_pk == birational(identity_pk) → rejected.
        let birational = birational_ed25519_to_x25519(&identity).expect("valid point");
        let err = validate_key_separation(&identity, &birational).unwrap_err();
        assert_eq!(err.code(), "encryption_key_derived_from_identity");

        // (3) an independent X25519 key → accepted.
        let independent = x25519_public(&vec![0x99u8; 32]).unwrap();
        assert_ne!(independent, birational, "test key must be independent");
        validate_key_separation(&identity, &independent).unwrap();
    }

    /// The birational map agrees with libsodium's transform: for the Ed25519
    /// basepoint, `to_montgomery` yields the Curve25519 basepoint u = 9.
    #[test]
    fn birational_basepoint_is_nine() {
        let ed_basepoint = ED25519_BASEPOINT_POINT.compress().to_bytes();
        let u = birational_ed25519_to_x25519(&ed_basepoint).expect("valid point");
        let mut expected = [0u8; 32];
        expected[0] = 9;
        assert_eq!(u, expected, "Ed25519 basepoint → Montgomery u=9");
    }
}
