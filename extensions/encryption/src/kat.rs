//! §16 ENC-KAT-INNER (arch v2.5 ruling R3) — the canonical fixed
//! inner entity used as the plaintext for ENC-SELF-KAT-1 / ENC-PEER-KAT-1 /
//! ENC-GROUP-KAT-1.
//!
//! Pinned shape:
//! ```text
//! system/note {
//!   body:    "entity-core encryption KAT inner entity"
//!   created: 0
//! }
//! ```
//!
//! The KAT plaintext is the ECF of this entity in the hashable `{data, type}`
//! 2-key form (per ENTITY-CBOR-ENCODING §4.2 — identical to what content_hash
//! is computed over), NOT a bare UTF-8 string. This gives decrypt-and-reinject
//! (§13.3) a real typed entity to re-author and pins the true ciphertext
//! length (79-byte plaintext → 95-byte AEAD output). Mirrors Go's
//! `ext/encryption/kat_inner.go` (`EncKATInnerPlaintext`).

use entity_ecf::{to_ecf, Value};

/// ENC-KAT-INNER entity type name.
pub const ENC_KAT_INNER_TYPE: &str = "system/note";
/// ENC-KAT-INNER pinned `body` field.
pub const ENC_KAT_INNER_BODY: &str = "entity-core encryption KAT inner entity";
/// ENC-KAT-INNER pinned `created` field.
pub const ENC_KAT_INNER_CREATED: u64 = 0;

/// The §16 KAT plaintext: ECF bytes of ENC-KAT-INNER in the hashable
/// `{data, type}` 2-key form. Fed into self/peer/group encrypt for the §16.2–
/// §16.4 byte-pin vectors. Deterministic — the ECF encoder sorts map keys
/// length-first then lexicographically (`data` < `type`; `body` < `created`).
pub fn enc_kat_inner_plaintext() -> Vec<u8> {
    let data = Value::Map(vec![
        (
            Value::Text("body".into()),
            Value::Text(ENC_KAT_INNER_BODY.into()),
        ),
        (
            Value::Text("created".into()),
            Value::Integer(ENC_KAT_INNER_CREATED.into()),
        ),
    ]);
    let hashable = Value::Map(vec![
        (Value::Text("data".into()), data),
        (
            Value::Text("type".into()),
            Value::Text(ENC_KAT_INNER_TYPE.into()),
        ),
    ]);
    to_ecf(&hashable)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The plaintext is byte-pinned to the cohort's 79-byte ECF (Go ↔ Python ↔
    /// Rust). If this drifts, every ENC-*-KAT-1 ciphertext drifts with it.
    #[test]
    fn enc_kat_inner_plaintext_is_pinned() {
        let pt = enc_kat_inner_plaintext();
        let hex: String = pt.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "a26464617461a264626f64797827656e746974792d636f726520656e6372797074696f6e204b\
415420696e6e657220656e7469747967637265617465640064747970656b73797374656d2f6e6f7465"
        );
        assert_eq!(pt.len(), 79);
    }
}
