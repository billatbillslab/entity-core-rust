//! §5.2 AAD builders (normative).
//!
//! All four shapes are deterministic ECF (RFC 8949 §4.2 length-first) maps with
//! FIXED key sets per mode — the all-keys-present discipline. Keys not
//! applicable to a mode are emitted as empty byte strings (`0x40`), NEVER
//! omitted and NEVER null; omission-vs-present-empty is the v7.67 Phase-2
//! byte-pin trap. Cohort byte-equality across Go + Rust + Python depends on
//! this exact shape — these mirror Go's `ext/encryption/aad.go`.
//!
//! Map-key ordering is handled by [`entity_ecf::to_ecf`] (length-first then
//! lexicographic), so the literal insertion order below is irrelevant to the
//! output bytes; it is written spec-order for readability.

use entity_ecf::{to_ecf, Value};
use entity_hash::Hash;

use crate::types::{AAD_MODE_GROUP_WRAP, MODE_GROUP, MODE_PEER, MODE_SELF};

/// A `system/hash` reference encodes as a CBOR byte string of
/// `varint(algorithm) || digest` (33 bytes for SHA-256) — matching Go's
/// `hash.Hash` `MarshalCBOR`. `Hash::to_bytes()` yields those inner bytes;
/// wrapping in [`Value::Bytes`] emits the bstr.
fn hash_value(h: &Hash) -> Value {
    Value::Bytes(h.to_bytes())
}

fn uint(v: u8) -> Value {
    Value::Integer(v.into())
}

/// §5.2 self-mode **8-key** AAD:
/// `{mode, enc_key_type=0, aead_id, kdf_id, nonce, kdf_salt, kdf_params, recipient_key=∅}`.
///
/// v2.4 F2-4 expanded this from 6 to 8 keys by binding `kdf_salt` +
/// `kdf_params` (mirroring the §9.2 backup path); Go's v2.3 6-key prototype hex
/// is superseded. `enc_key_type` is always 0; `recipient_key` is empty bytes
/// (no recipient in self mode). `kdf_params` is the nested §6.1 sub-map.
pub fn self_aad(aead_id: u8, kdf_id: u8, nonce: &[u8], kdf_salt: &[u8], kdf_params: Value) -> Vec<u8> {
    let m = Value::Map(vec![
        (Value::Text("mode".into()), Value::Text(MODE_SELF.into())),
        (Value::Text("enc_key_type".into()), uint(0)),
        (Value::Text("aead_id".into()), uint(aead_id)),
        (Value::Text("kdf_id".into()), uint(kdf_id)),
        (Value::Text("nonce".into()), Value::Bytes(nonce.to_vec())),
        (Value::Text("kdf_salt".into()), Value::Bytes(kdf_salt.to_vec())),
        (Value::Text("kdf_params".into()), kdf_params),
        (Value::Text("recipient_key".into()), Value::Bytes(Vec::new())),
    ]);
    to_ecf(&m)
}

/// §5.2 peer-mode **7-key** AAD:
/// `{mode, enc_key_type, aead_id, kdf_id, nonce, recipient_key, ephemeral_key}`.
///
/// `recipient_key` is the inner `system/encryption-pubkey` content_hash —
/// uniform at every tier per F-GO-1.
pub fn peer_aad(
    enc_key_type: u8,
    aead_id: u8,
    kdf_id: u8,
    nonce: &[u8],
    recipient_key: &Hash,
    ephemeral_key: &[u8],
) -> Vec<u8> {
    let m = Value::Map(vec![
        (Value::Text("mode".into()), Value::Text(MODE_PEER.into())),
        (Value::Text("enc_key_type".into()), uint(enc_key_type)),
        (Value::Text("aead_id".into()), uint(aead_id)),
        (Value::Text("kdf_id".into()), uint(kdf_id)),
        (Value::Text("nonce".into()), Value::Bytes(nonce.to_vec())),
        (Value::Text("recipient_key".into()), hash_value(recipient_key)),
        (Value::Text("ephemeral_key".into()), Value::Bytes(ephemeral_key.to_vec())),
    ]);
    to_ecf(&m)
}

/// §5.2 group-outer **7-key** AAD (self-shape + key-commitment):
/// `{mode, enc_key_type=0, aead_id, kdf_id, nonce, commitment, recipient_key=∅}`.
///
/// `commitment` = `SHA-256(group_aead_key)` (F2-1) — the key-commitment that
/// closes the invisible-salamanders class: only the single committed key opens
/// the outer ciphertext, so a malicious author cannot equivocate. The caller
/// computes the commitment (the group logic owns the SHA-256) and passes its
/// 32 bytes here; the receiver recomputes it from the recovered
/// `group_aead_key` (§8.4) and binds it identically.
pub fn group_outer_aad(aead_id: u8, kdf_id: u8, nonce: &[u8], commitment: &[u8]) -> Vec<u8> {
    let m = Value::Map(vec![
        (Value::Text("mode".into()), Value::Text(MODE_GROUP.into())),
        (Value::Text("enc_key_type".into()), uint(0)),
        (Value::Text("aead_id".into()), uint(aead_id)),
        (Value::Text("kdf_id".into()), uint(kdf_id)),
        (Value::Text("nonce".into()), Value::Bytes(nonce.to_vec())),
        (Value::Text("commitment".into()), Value::Bytes(commitment.to_vec())),
        (Value::Text("recipient_key".into()), Value::Bytes(Vec::new())),
    ]);
    to_ecf(&m)
}

/// §5.2 group-per-wrap **7-key** AAD (peer-shaped, one per member),
/// domain-separated via `mode:"group-wrap"` (F2-2):
/// `{mode="group-wrap", enc_key_type, aead_id, kdf_id, nonce, recipient_key, ephemeral_key}`.
///
/// The distinct `"group-wrap"` label makes a lifted wrap blob fail to verify as
/// a standalone peer-mode message, closing the replay-as-peer-message gap. The
/// `nonce` is that wrap's `wrap_nonce`; `recipient_key` is that member's
/// pubkey-entity content_hash.
pub fn group_wrap_aad(
    enc_key_type: u8,
    aead_id: u8,
    kdf_id: u8,
    wrap_nonce: &[u8],
    member_key: &Hash,
    ephemeral_key: &[u8],
) -> Vec<u8> {
    let m = Value::Map(vec![
        (Value::Text("mode".into()), Value::Text(AAD_MODE_GROUP_WRAP.into())),
        (Value::Text("enc_key_type".into()), uint(enc_key_type)),
        (Value::Text("aead_id".into()), uint(aead_id)),
        (Value::Text("kdf_id".into()), uint(kdf_id)),
        (Value::Text("nonce".into()), Value::Bytes(wrap_nonce.to_vec())),
        (Value::Text("recipient_key".into()), hash_value(member_key)),
        (Value::Text("ephemeral_key".into()), Value::Bytes(ephemeral_key.to_vec())),
    ]);
    to_ecf(&m)
}
