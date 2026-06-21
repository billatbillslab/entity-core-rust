//! `system/quorum` entity codec (EXTENSION-QUORUM v1.0 §3.1).
//!
//! ECF-deterministic CBOR. Field order (sorted): metadata, name,
//! signer_resolution, signers, threshold.

use entity_ecf::{text, to_ecf, Value};
use entity_entity::Entity;
use entity_hash::Hash;
use entity_types::TYPE_QUORUM;

use crate::QuorumError;

#[derive(Debug, Clone)]
pub struct QuorumData {
    pub signers: Vec<Hash>,
    pub threshold: u64,
    /// Resolver mode identifier. `None` defaults to `"concrete"` (§5.1).
    pub signer_resolution: Option<String>,
    pub name: Option<String>,
    /// Free-form caller-supplied metadata (`primitive/any` map per §3.1).
    /// Stored as a raw CBOR map to preserve byte fidelity through the
    /// content-hash. R-4 (cross-impl ACME ruling): if dropped
    /// during decode/encode, the recomputed canonical path diverges from
    /// the caller's locally-computed path → resource_target_mismatch.
    pub metadata: Option<Vec<(ciborium::Value, ciborium::Value)>>,
}

impl QuorumData {
    pub fn from_entity(entity: &Entity) -> Result<Self, QuorumError> {
        if entity.entity_type != TYPE_QUORUM {
            return Err(QuorumError::Decode(format!(
                "expected {}, got {}",
                TYPE_QUORUM, entity.entity_type
            )));
        }
        let map = decode_map(&entity.data)?;
        Ok(Self {
            signers: field_hash_array(&map, "signers")?,
            threshold: field_u64(&map, "threshold")?,
            signer_resolution: field_string_opt(&map, "signer_resolution")?,
            name: field_string_opt(&map, "name")?,
            metadata: field_map_opt(&map, "metadata")?,
        })
    }

    pub fn to_entity(&self) -> Result<Entity, QuorumError> {
        // ECF-sorted: metadata, name, signer_resolution, signers, threshold.
        // Per §3.1 + R-4 fidelity contract.
        let mut fields: Vec<(Value, Value)> = Vec::new();
        if let Some(m) = &self.metadata {
            fields.push((text("metadata"), Value::Map(m.clone())));
        }
        if let Some(n) = &self.name {
            fields.push((text("name"), text(n.as_str())));
        }
        if let Some(r) = &self.signer_resolution {
            fields.push((text("signer_resolution"), text(r.as_str())));
        }
        fields.push((
            text("signers"),
            Value::Array(
                self.signers
                    .iter()
                    .map(|h| Value::Bytes(h.to_bytes().to_vec()))
                    .collect(),
            ),
        ));
        fields.push((text("threshold"), entity_ecf::integer(self.threshold as i64)));
        let data = to_ecf(&Value::Map(fields));
        Entity::new(TYPE_QUORUM, data).map_err(|e| QuorumError::Encode(e.to_string()))
    }

    /// Returns the effective resolution mode (`"concrete"` if absent).
    pub fn resolution_mode(&self) -> &str {
        self.signer_resolution
            .as_deref()
            .unwrap_or(crate::RESOLUTION_CONCRETE)
    }
}

// ---------------------------------------------------------------------------
// CBOR helpers (lightweight; reuse identity-attestation patterns)
// ---------------------------------------------------------------------------

pub(crate) fn decode_map(
    data: &[u8],
) -> Result<Vec<(ciborium::Value, ciborium::Value)>, QuorumError> {
    let value: ciborium::Value =
        ciborium::from_reader(data).map_err(|e| QuorumError::Decode(e.to_string()))?;
    value
        .into_map()
        .map_err(|_| QuorumError::Decode("expected CBOR map".into()))
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
) -> Result<Hash, QuorumError> {
    let v = get_field(map, key)
        .ok_or_else(|| QuorumError::Decode(format!("missing {}", key)))?;
    let bytes = v
        .as_bytes()
        .ok_or_else(|| QuorumError::Decode(format!("{} must be bytes", key)))?;
    Hash::from_bytes(bytes).map_err(|e| QuorumError::Decode(e.to_string()))
}

pub(crate) fn field_hash_opt(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<Option<Hash>, QuorumError> {
    match get_field(map, key) {
        None | Some(ciborium::Value::Null) => Ok(None),
        Some(v) => {
            let bytes = v
                .as_bytes()
                .ok_or_else(|| QuorumError::Decode(format!("{} must be bytes", key)))?;
            Hash::from_bytes(bytes)
                .map(Some)
                .map_err(|e| QuorumError::Decode(e.to_string()))
        }
    }
}

pub(crate) fn field_hash_array(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<Vec<Hash>, QuorumError> {
    let v = get_field(map, key)
        .ok_or_else(|| QuorumError::Decode(format!("missing {}", key)))?;
    let arr = v
        .as_array()
        .ok_or_else(|| QuorumError::Decode(format!("{} must be array", key)))?;
    let mut hs = Vec::with_capacity(arr.len());
    for item in arr {
        let bytes = item
            .as_bytes()
            .ok_or_else(|| QuorumError::Decode(format!("{} entry must be bytes", key)))?;
        hs.push(Hash::from_bytes(bytes).map_err(|e| QuorumError::Decode(e.to_string()))?);
    }
    Ok(hs)
}

pub(crate) fn field_u64(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<u64, QuorumError> {
    let v = get_field(map, key)
        .ok_or_else(|| QuorumError::Decode(format!("missing {}", key)))?;
    let i = v
        .as_integer()
        .ok_or_else(|| QuorumError::Decode(format!("{} must be integer", key)))?;
    let n: i128 = i.into();
    if n < 0 {
        return Err(QuorumError::Decode(format!("{} must be non-negative", key)));
    }
    Ok(n as u64)
}

#[allow(dead_code)] // used by future supersede flows
pub(crate) fn field_u64_opt(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<Option<u64>, QuorumError> {
    match get_field(map, key) {
        None | Some(ciborium::Value::Null) => Ok(None),
        Some(v) => {
            let i = v
                .as_integer()
                .ok_or_else(|| QuorumError::Decode(format!("{} must be integer", key)))?;
            let n: i128 = i.into();
            if n < 0 {
                return Err(QuorumError::Decode(format!(
                    "{} must be non-negative",
                    key
                )));
            }
            Ok(Some(n as u64))
        }
    }
}

pub(crate) fn field_string_opt(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<Option<String>, QuorumError> {
    match get_field(map, key) {
        None | Some(ciborium::Value::Null) => Ok(None),
        Some(v) => v
            .as_text()
            .map(|s| Some(s.to_string()))
            .ok_or_else(|| QuorumError::Decode(format!("{} must be text", key))),
    }
}

/// Decode an optional CBOR map sub-field. Used by `metadata` (§3.1
/// `primitive/any` map) and other free-form map fields. Returns `None`
/// for absent/null. Returns the raw CBOR map so byte-fidelity round-trips
/// preserve the entity's content hash.
pub(crate) fn field_map_opt(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<Option<Vec<(ciborium::Value, ciborium::Value)>>, QuorumError> {
    match get_field(map, key) {
        None | Some(ciborium::Value::Null) => Ok(None),
        Some(ciborium::Value::Map(m)) => Ok(Some(m.clone())),
        Some(_) => Err(QuorumError::Decode(format!("{} must be a map", key))),
    }
}

/// Hex-encode a `system/hash` for path segments. Lowercase, full byte
/// sequence (algorithm prefix + digest). Same convention as
/// EXTENSION-ATTESTATION.
pub fn hex_segment(h: &Hash) -> String {
    let bytes = h.to_bytes();
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in &bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// Path for a quorum entity — `system/quorum/{hex(quorum_id)}`.
pub fn path_quorum(quorum_id: &Hash) -> String {
    format!("{}{}", crate::QUORUM_STORAGE_PREFIX, hex_segment(quorum_id))
}

/// Path for a quorum self-event attestation —
/// `system/quorum/{hex(q)}/event/{hex(att)}`.
pub fn path_quorum_event(quorum_id: &Hash, att_hash: &Hash) -> String {
    format!(
        "{}{}{}{}",
        crate::QUORUM_STORAGE_PREFIX,
        hex_segment(quorum_id),
        crate::QUORUM_EVENT_SEGMENT,
        hex_segment(att_hash),
    )
}
