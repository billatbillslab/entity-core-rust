//! Entity-type names, mode discriminators, the §15 error-code domain, and the
//! §6.1 `kdf_params` shape. Per the Rust DAG these live in the extension (not
//! `core/types`): each extension owns its own type defs.

use entity_ecf::Value;

use crate::registry::{
    ARGON2ID_VERSION, KDF_ID_ARGON2ID, // re-exported for callers; kept explicit
};

// §4–§11 entity-type names.

/// §4.1 inner pubkey entity (content-addressed at every tier).
pub const TYPE_ENCRYPTION_PUBKEY: &str = "system/encryption-pubkey";
/// §5.1 outer wrapper (per-mode additional fields per §6.1/§7.2/§8.2).
pub const TYPE_ENCRYPTED: &str = "system/encrypted";
/// §10.1 Tier-A rotation handoff.
pub const TYPE_ENCRYPTION_HANDOFF: &str = "system/encryption/handoff";
/// §11.1 Tier-A revocation.
pub const TYPE_ENCRYPTION_REVOCATION: &str = "system/encryption/revocation";
/// §9.2 Tier-2 passphrase-wrapped key backup (Tier A/B path).
pub const TYPE_ENCRYPTION_KEY_BACKUP: &str = "system/encryption/key-backup";

// §5.1 mode discriminator values.
pub const MODE_SELF: &str = "self";
pub const MODE_PEER: &str = "peer";
pub const MODE_GROUP: &str = "group";

/// §5.2 F2-2 AAD-only mode label for the group per-wrap AAD. NEVER an outer
/// entity `mode` value — it appears only inside per-wrap AAD bytes, domain-
/// separating a wrap so a lifted wrap blob fails to verify as a standalone
/// peer-mode ciphertext.
pub const AAD_MODE_GROUP_WRAP: &str = "group-wrap";

/// §6.2 baseline Argon2id parameters (pinned for v1; configurable per impl up).
pub const ARGON2ID_BASELINE_MEMORY_COST: u32 = 65536; // 64 MiB (KiB units, RFC 9106 §3.1)
pub const ARGON2ID_BASELINE_TIME_COST: u32 = 3;
pub const ARGON2ID_BASELINE_PARALLELISM: u32 = 1;
pub const ARGON2ID_BASELINE_OUTPUT_LEN: u32 = 32;
/// §6.1 minimum random salt length.
pub const KDF_SALT_MIN_BYTES: usize = 16;

/// §8.6 default ceiling on group-mode `wrapped_keys` per entity.
pub const WRAPPED_KEYS_DEFAULT_CEILING: usize = 256;

/// §6.1 / §9.2 normative Argon2id parameter shape. Field names are normative
/// for ECF byte-equality (F-GO-9): full words, not `m`/`t`/`p` abbreviations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub argon2_version: u32,
    pub memory_cost: u32, // KiB per RFC 9106 §3.1
    pub time_cost: u32,
    pub parallelism: u32,
    pub output_len: u32, // bytes
}

impl Default for KdfParams {
    /// §6.2 baseline (pinned for v1; matches the Go/Python/Rust Argon2id
    /// library defaults).
    fn default() -> Self {
        Self {
            argon2_version: ARGON2ID_VERSION,
            memory_cost: ARGON2ID_BASELINE_MEMORY_COST,
            time_cost: ARGON2ID_BASELINE_TIME_COST,
            parallelism: ARGON2ID_BASELINE_PARALLELISM,
            output_len: ARGON2ID_BASELINE_OUTPUT_LEN,
        }
    }
}

impl KdfParams {
    /// ECF [`Value`] form of the `kdf_params` sub-map. The 5 keys are emitted
    /// as a CBOR map; the encoder sorts them length-first then lexicographic
    /// (`time_cost` < `output_len` < `memory_cost` < `parallelism` <
    /// `argon2_version`), matching Go's `ecf.Encode` over `types.KDFParams`.
    pub fn to_ecf_value(self) -> Value {
        Value::Map(vec![
            (
                Value::Text("argon2_version".into()),
                Value::Integer(self.argon2_version.into()),
            ),
            (
                Value::Text("memory_cost".into()),
                Value::Integer(self.memory_cost.into()),
            ),
            (
                Value::Text("time_cost".into()),
                Value::Integer(self.time_cost.into()),
            ),
            (
                Value::Text("parallelism".into()),
                Value::Integer(self.parallelism.into()),
            ),
            (
                Value::Text("output_len".into()),
                Value::Integer(self.output_len.into()),
            ),
        ])
    }
}

// Keep the Argon2id kdf_id reachable as a doc anchor for §3.3 (self mode uses
// Argon2id for passphrase→master, then HKDF for the per-entity key).
const _: u8 = KDF_ID_ARGON2ID;

/// §15 error-code domain (encryption owns its codes per V7 §3.3). Each variant
/// maps to a status code via [`EncryptionError::status`] and a stable string
/// code via [`EncryptionError::code`].
#[derive(Debug, Clone, thiserror::Error)]
pub enum EncryptionError {
    #[error("encryption_aead_failed: {0}")]
    AeadFailed(String),
    #[error("encryption_unsupported_suite: {0}")]
    UnsupportedSuite(String),
    #[error("encryption_no_common_suite: {0}")]
    NoCommonSuite(String),
    #[error("encryption_kdf_params_excessive: {0}")]
    KdfParamsExcessive(String),
    #[error("encryption_invalid_wrapper: {0}")]
    InvalidWrapper(String),
    #[error("encryption_recipient_unknown: {0}")]
    RecipientUnknown(String),
    #[error("encryption_key_unavailable: {0}")]
    KeyUnavailable(String),
    #[error("encryption_key_revoked: {0}")]
    KeyRevoked(String),
    #[error("encryption_signature_invalid: {0}")]
    SignatureInvalid(String),
    #[error("encryption_unsigned_sender: {0}")]
    UnsignedSender(String),
    #[error("encryption_wrapped_keys_too_many: {0}")]
    WrappedKeysTooMany(String),
    /// §2/§9.4 R6 key-separation MUST violation: an encryption pubkey derived
    /// from (equal to, or the birational image of) the identity key.
    #[error("encryption_key_derived_from_identity: {0}")]
    KeyDerivedFromIdentity(String),
}

impl EncryptionError {
    /// The §15 stable error-code string.
    pub fn code(&self) -> &'static str {
        match self {
            Self::AeadFailed(_) => "encryption_aead_failed",
            Self::UnsupportedSuite(_) => "encryption_unsupported_suite",
            Self::NoCommonSuite(_) => "encryption_no_common_suite",
            Self::KdfParamsExcessive(_) => "encryption_kdf_params_excessive",
            Self::InvalidWrapper(_) => "encryption_invalid_wrapper",
            Self::RecipientUnknown(_) => "encryption_recipient_unknown",
            Self::KeyUnavailable(_) => "encryption_key_unavailable",
            Self::KeyRevoked(_) => "encryption_key_revoked",
            Self::SignatureInvalid(_) => "encryption_signature_invalid",
            Self::UnsignedSender(_) => "encryption_unsigned_sender",
            Self::WrappedKeysTooMany(_) => "encryption_wrapped_keys_too_many",
            Self::KeyDerivedFromIdentity(_) => "encryption_key_derived_from_identity",
        }
    }

    /// The §15 HTTP-style status code.
    pub fn status(&self) -> u16 {
        match self {
            Self::AeadFailed(_)
            | Self::UnsupportedSuite(_)
            | Self::NoCommonSuite(_)
            | Self::KdfParamsExcessive(_)
            | Self::InvalidWrapper(_)
            | Self::KeyDerivedFromIdentity(_) => 400,
            Self::RecipientUnknown(_)
            | Self::KeyUnavailable(_)
            | Self::KeyRevoked(_)
            | Self::SignatureInvalid(_)
            | Self::UnsignedSender(_) => 403,
            Self::WrappedKeysTooMany(_) => 413,
        }
    }
}
