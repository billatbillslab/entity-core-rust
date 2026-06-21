//! §5.1 outer wrapper (`system/encrypted`), unioned across modes, plus the
//! §4.1 inner pubkey entity (`system/encryption-pubkey`).
//!
//! Per-mode fields are optional so the wire shape matches §6.1 (self adds
//! `key_id` + `kdf_salt` + `kdf_params`), §7.2 (peer adds `ephemeral_key` +
//! `recipient_key`), and §8.2 (group adds `wrapped_keys`). The full
//! outer-entity ECF serialization (for `content_hash` + tree storage) is wired
//! when the handler lands; this struct is the in-memory result of the mode
//! primitives and the carrier for the §16 KAT byte outputs.

use entity_ecf::{to_ecf, Value};
use entity_hash::Hash;

use crate::types::KdfParams;

/// §8.2 per-member wrap entry — structurally a peer-mode encryption of the
/// random `group_aead_key` to that member, AAD-domain-separated by the
/// `"group-wrap"` label (F2-2).
#[derive(Debug, Clone)]
pub struct WrappedKey {
    pub recipient_key: Hash,
    pub enc_key_type: u8,
    pub ephemeral_key: Vec<u8>,
    pub wrapped_aead_key: Vec<u8>,
    pub wrap_nonce: Vec<u8>,
}

/// §5.1 outer wrapper. `Mode` discriminates which per-mode fields are set.
#[derive(Debug, Clone)]
pub struct EncryptedData {
    pub mode: String,
    pub enc_key_type: u8,
    pub aead_id: u8,
    pub kdf_id: u8,
    pub nonce: Vec<u8>,
    /// AEAD output (`ciphertext || tag`).
    pub ciphertext: Vec<u8>,

    // Self-mode additions (§6.1).
    pub key_id: Option<String>,
    pub kdf_salt: Option<Vec<u8>>,
    pub kdf_params: Option<KdfParams>,

    // Peer-mode additions (§7.2). recipient_key is the inner pubkey-entity
    // content_hash (uniform at every tier per F-GO-1).
    pub ephemeral_key: Option<Vec<u8>>,
    pub recipient_key: Option<Hash>,

    // Group-mode additions (§8.2).
    pub wrapped_keys: Vec<WrappedKey>,
}

impl EncryptedData {
    /// Empty base wrapper carrying only the §5.1 common fields.
    pub(crate) fn common(
        mode: &str,
        enc_key_type: u8,
        aead_id: u8,
        kdf_id: u8,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            mode: mode.to_string(),
            enc_key_type,
            aead_id,
            kdf_id,
            nonce,
            ciphertext,
            key_id: None,
            kdf_salt: None,
            kdf_params: None,
            ephemeral_key: None,
            recipient_key: None,
            wrapped_keys: Vec::new(),
        }
    }
}

/// §4.1 inner pubkey entity. `content_hash` is a pure function of
/// `(enc_key_type, public_key, supported_aead_ids, supported_kdf_ids, created,
/// expires)`; cross-tier interop binds the SAME authored inner entity (F2-3).
#[derive(Debug, Clone)]
pub struct EncryptionPubkeyData {
    pub enc_key_type: u8,
    pub public_key: Vec<u8>,
    pub supported_aead_ids: Vec<u32>,
    pub supported_kdf_ids: Vec<u32>,
    pub created: u64,
    pub expires: Option<u64>,
}

impl EncryptionPubkeyData {
    /// ECF [`Value`] of the data field. `expires` is omitted when absent
    /// (SHOULD-be-absent optional, matching Go's `omitempty`); the encoder
    /// sorts the keys length-first then lexicographic.
    pub fn to_ecf_value(&self) -> Value {
        let mut entries = vec![
            (
                Value::Text("enc_key_type".into()),
                Value::Integer(self.enc_key_type.into()),
            ),
            (
                Value::Text("public_key".into()),
                Value::Bytes(self.public_key.clone()),
            ),
            (
                Value::Text("supported_aead_ids".into()),
                Value::Array(
                    self.supported_aead_ids
                        .iter()
                        .map(|&v| Value::Integer(v.into()))
                        .collect(),
                ),
            ),
            (
                Value::Text("supported_kdf_ids".into()),
                Value::Array(
                    self.supported_kdf_ids
                        .iter()
                        .map(|&v| Value::Integer(v.into()))
                        .collect(),
                ),
            ),
            (
                Value::Text("created".into()),
                Value::Integer(self.created.into()),
            ),
        ];
        if let Some(exp) = self.expires {
            entries.push((Value::Text("expires".into()), Value::Integer(exp.into())));
        }
        Value::Map(entries)
    }

    /// `content_hash(system/encryption-pubkey)` under the SHA-256 floor — the
    /// uniform-across-tiers `recipient_key` value (F-GO-1). Mirrors Go's
    /// `ComputePubkeyHash`.
    pub fn content_hash(&self) -> Hash {
        let data = to_ecf(&self.to_ecf_value());
        Hash::compute(crate::types::TYPE_ENCRYPTION_PUBKEY, &data)
    }

    /// `content_hash` under an explicit `content_hash_format` (`0x00` SHA-256,
    /// `0x01` SHA-384) per V7 §1.8 / v7.69 §4.5a. `recipient_key` is bound as
    /// the recipient's *authored* hash under their home format
    /// (`ENC-ROUNDTRIP-FORMAT-1`); the sender MUST NOT re-derive it under a
    /// different format (§7.6).
    pub fn content_hash_format(&self, format: u8) -> Result<Hash, entity_hash::HashError> {
        let data = to_ecf(&self.to_ecf_value());
        Hash::compute_format(crate::types::TYPE_ENCRYPTION_PUBKEY, &data, format)
    }
}
