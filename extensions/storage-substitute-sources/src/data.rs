//! Typed-struct decoder for the `system/substitute/source` entity (§2.1).
//!
//! Per the bare-CBOR-map convention for typed-struct field shapes
//! (`feedback_typed_struct_field_wire_convention`): the `endpoint` and
//! `refs.type_specific` fields are bare `ciborium::Value` maps — they are
//! NOT wrapped in `{type, data, content_hash}`. Only `core/entity`
//! `result`/`params` carry the wrapper.

use ciborium::Value;
use entity_entity::Entity;
use entity_hash::Hash;
use thiserror::Error;

use crate::TYPE_SUBSTITUTE_SOURCE;

/// Decoded `system/substitute/source` entry.
///
/// Field shape follows §2.1 of the proposal. Optional fields use `None`
/// when absent; `endpoint` and `type_specific_refs` are kept as raw
/// `ciborium::Value` so convention extensions can decode their own
/// type-specific structure without an additional pass through this crate.
#[derive(Debug, Clone)]
pub struct SubstituteSourceData {
    /// Human-readable label (`name`).
    pub name: String,
    /// Convention discriminator (`substitute_type`), e.g. `"static-cdn"`.
    /// Selects which `system/substitute/<type>` handler the substrate
    /// dispatches to.
    pub substitute_type: String,
    /// Identity of the peer whose authority this entry claims.
    pub source_peer_id: Hash,
    /// Convention-specific endpoint payload — raw CBOR; the convention
    /// handler decodes its own shape (per §2.1: "each substitute_type's
    /// convention extension defines the structured endpoint shape it
    /// expects").
    pub endpoint: Option<Value>,
    /// Legacy URL template (`fetch_template`); deprecated for new
    /// entries (§2.1). Carried verbatim so convention handlers MAY
    /// honor it as a fallback when `endpoint` is absent.
    pub fetch_template: Option<String>,
    /// Chain priority. Lower = consulted first.
    pub priority: i64,
    /// Whether the entry is currently usable.
    pub enabled: bool,
    /// Optional expiry (epoch ms). The substrate drops entries whose
    /// `expires_at <= now()` at enumeration time.
    pub expires_at: Option<u64>,
    /// Optional supersedes pointer (§2.1; per ATTESTATION-§5 chain).
    pub supersedes: Option<Hash>,
}

/// Decode errors from a `system/substitute/source` entity.
#[derive(Debug, Error)]
pub enum SubstituteSourceDecodeError {
    /// Entity type didn't match.
    #[error("expected entity_type {expected}, got {got}")]
    UnexpectedType {
        /// The required entity type.
        expected: &'static str,
        /// The type carried on the supplied entity.
        got: String,
    },
    /// CBOR decode failed.
    #[error("cbor decode: {0}")]
    Cbor(String),
    /// A required field was missing.
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    /// A required field had the wrong CBOR shape.
    #[error("field {field} has wrong shape: {detail}")]
    BadFieldShape {
        /// The field name.
        field: &'static str,
        /// Diagnostic detail.
        detail: String,
    },
}

/// Decode a `system/substitute/source` entity.
pub fn decode_substitute_source(
    entity: &Entity,
) -> Result<SubstituteSourceData, SubstituteSourceDecodeError> {
    if entity.entity_type != TYPE_SUBSTITUTE_SOURCE {
        return Err(SubstituteSourceDecodeError::UnexpectedType {
            expected: TYPE_SUBSTITUTE_SOURCE,
            got: entity.entity_type.clone(),
        });
    }
    let value: Value = ciborium::from_reader(entity.data.as_slice())
        .map_err(|e| SubstituteSourceDecodeError::Cbor(e.to_string()))?;
    let map = value
        .as_map()
        .ok_or(SubstituteSourceDecodeError::BadFieldShape {
            field: "<root>",
            detail: "expected a CBOR map".to_string(),
        })?;

    let name = field_text(map, "name").ok_or(SubstituteSourceDecodeError::MissingField("name"))?;
    let substitute_type = field_text(map, "substitute_type")
        .ok_or(SubstituteSourceDecodeError::MissingField("substitute_type"))?;
    let source_peer_id = field_hash(map, "source_peer_id")
        .ok_or(SubstituteSourceDecodeError::MissingField("source_peer_id"))?;
    let priority = field_int(map, "priority")
        .ok_or(SubstituteSourceDecodeError::MissingField("priority"))?;
    let enabled = field_bool(map, "enabled")
        .ok_or(SubstituteSourceDecodeError::MissingField("enabled"))?;

    let endpoint = lookup(map, "endpoint").cloned();
    let fetch_template = field_text(map, "fetch_template");
    let expires_at = field_uint(map, "expires_at");
    let supersedes = field_hash(map, "supersedes");

    Ok(SubstituteSourceData {
        name,
        substitute_type,
        source_peer_id,
        endpoint,
        fetch_template,
        priority,
        enabled,
        expires_at,
        supersedes,
    })
}

// ----- Map-access helpers --------------------------------------------------

fn lookup<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter().find_map(|(k, v)| match k {
        Value::Text(t) if t == key => Some(v),
        _ => None,
    })
}

fn field_text(map: &[(Value, Value)], key: &str) -> Option<String> {
    lookup(map, key)
        .and_then(|v| v.as_text())
        .map(|s| s.to_string())
}

fn field_bool(map: &[(Value, Value)], key: &str) -> Option<bool> {
    lookup(map, key).and_then(|v| match v {
        Value::Bool(b) => Some(*b),
        _ => None,
    })
}

fn field_int(map: &[(Value, Value)], key: &str) -> Option<i64> {
    lookup(map, key).and_then(|v| match v {
        Value::Integer(i) => i64::try_from(*i).ok(),
        _ => None,
    })
}

fn field_uint(map: &[(Value, Value)], key: &str) -> Option<u64> {
    lookup(map, key).and_then(|v| match v {
        Value::Integer(i) => u64::try_from(*i).ok(),
        _ => None,
    })
}

fn field_hash(map: &[(Value, Value)], key: &str) -> Option<Hash> {
    let bytes = lookup(map, key).and_then(|v| v.as_bytes())?;
    Hash::from_bytes(bytes.as_slice()).ok()
}
