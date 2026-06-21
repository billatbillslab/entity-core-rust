//! `system/attestation` entity codec (EXTENSION-ATTESTATION v1.0 §3.1).
//!
//! ECF-deterministic CBOR encoding. Field order (sorted): attested,
//! attesting, expires_at, not_before, properties, supersedes.

use entity_ecf::{text, to_ecf, Value};
use entity_entity::Entity;
use entity_hash::Hash;
use entity_types::TYPE_ATTESTATION;

use crate::AttestationError;

/// Decoded `system/attestation` entity (per §3.1).
///
/// `properties` is the raw consumer-defined map. Consumer extensions
/// interpret keys per their own conventions; the substrate primitive does
/// not introspect (except for the universal `kind == "revocation"` case).
#[derive(Debug, Clone)]
pub struct AttestationData {
    pub attesting: Hash,
    pub attested: Hash,
    pub properties: Vec<(ciborium::Value, ciborium::Value)>,
    pub supersedes: Option<Hash>,
    pub not_before: Option<u64>,
    pub expires_at: Option<u64>,
}

impl AttestationData {
    pub fn from_entity(entity: &Entity) -> Result<Self, AttestationError> {
        if entity.entity_type != TYPE_ATTESTATION {
            return Err(AttestationError::Decode(format!(
                "expected {}, got {}",
                TYPE_ATTESTATION, entity.entity_type
            )));
        }
        let map = decode_map(&entity.data)?;
        Ok(Self {
            attesting: field_hash(&map, "attesting")?,
            attested: field_hash(&map, "attested")?,
            properties: match get_field(&map, "properties") {
                None | Some(ciborium::Value::Null) => Vec::new(),
                Some(v) => v
                    .as_map()
                    .ok_or_else(|| AttestationError::Decode("properties must be CBOR map".into()))?
                    .clone(),
            },
            supersedes: field_hash_opt(&map, "supersedes")?,
            not_before: field_u64_opt(&map, "not_before")?,
            expires_at: field_u64_opt(&map, "expires_at")?,
        })
    }

    pub fn to_entity(&self) -> Result<Entity, AttestationError> {
        let mut fields: Vec<(Value, Value)> = Vec::new();
        fields.push((text("attested"), Value::Bytes(self.attested.to_bytes().to_vec())));
        fields.push((text("attesting"), Value::Bytes(self.attesting.to_bytes().to_vec())));
        if let Some(v) = self.expires_at {
            fields.push((text("expires_at"), entity_ecf::integer(v as i64)));
        }
        if let Some(v) = self.not_before {
            fields.push((text("not_before"), entity_ecf::integer(v as i64)));
        }
        if !self.properties.is_empty() {
            fields.push((text("properties"), Value::Map(self.properties.clone())));
        }
        if let Some(s) = &self.supersedes {
            fields.push((text("supersedes"), Value::Bytes(s.to_bytes().to_vec())));
        }
        let data = to_ecf(&Value::Map(fields));
        Entity::new(TYPE_ATTESTATION, data).map_err(|e| AttestationError::Encode(e.to_string()))
    }

    /// Convenience: extract `properties.kind` if present (per §3.2 convention).
    pub fn kind(&self) -> Option<&str> {
        get_field(&self.properties, "kind").and_then(|v| v.as_text())
    }
}

// ---------------------------------------------------------------------------
// CBOR helpers
// ---------------------------------------------------------------------------

pub(crate) fn decode_map(
    data: &[u8],
) -> Result<Vec<(ciborium::Value, ciborium::Value)>, AttestationError> {
    let value: ciborium::Value =
        ciborium::from_reader(data).map_err(|e| AttestationError::Decode(e.to_string()))?;
    value
        .into_map()
        .map_err(|_| AttestationError::Decode("expected CBOR map".into()))
}

pub(crate) fn get_field<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<&'a ciborium::Value> {
    map.iter()
        .find_map(|(k, v)| if k.as_text() == Some(key) { Some(v) } else { None })
}

pub(crate) fn field_hash(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<Hash, AttestationError> {
    let v = get_field(map, key)
        .ok_or_else(|| AttestationError::Decode(format!("missing {} field", key)))?;
    let bytes = v
        .as_bytes()
        .ok_or_else(|| AttestationError::Decode(format!("{} must be byte string", key)))?;
    Hash::from_bytes(bytes).map_err(|e| AttestationError::Decode(e.to_string()))
}

pub(crate) fn field_hash_opt(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<Option<Hash>, AttestationError> {
    match get_field(map, key) {
        None | Some(ciborium::Value::Null) => Ok(None),
        Some(v) => {
            let bytes = v
                .as_bytes()
                .ok_or_else(|| AttestationError::Decode(format!("{} must be byte string", key)))?;
            Hash::from_bytes(bytes)
                .map(Some)
                .map_err(|e| AttestationError::Decode(e.to_string()))
        }
    }
}

pub(crate) fn field_u64_opt(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<Option<u64>, AttestationError> {
    match get_field(map, key) {
        None | Some(ciborium::Value::Null) => Ok(None),
        Some(v) => {
            let i = v
                .as_integer()
                .ok_or_else(|| AttestationError::Decode(format!("{} must be integer", key)))?;
            let n: i128 = i.into();
            if n < 0 {
                return Err(AttestationError::Decode(format!(
                    "{} must be non-negative",
                    key
                )));
            }
            Ok(Some(n as u64))
        }
    }
}

/// Hex-encode a `system/hash` for path segments. Lowercase, full byte
/// sequence (algorithm prefix + digest). Same convention as identity
/// extension v3.2 §5.3.
pub fn hex_segment(h: &Hash) -> String {
    let bytes = h.to_bytes();
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in &bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}
