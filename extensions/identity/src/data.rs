//! Codecs for `system/identity/peer-config` (§3.2) and
//! `system/identity/identity-binding` (§3.4).

use entity_capability::{decode_grant_entry, encode_grant_entry, GrantEntry};
use entity_ecf::{text, to_ecf, Value};
use entity_entity::Entity;
use entity_hash::Hash;
use entity_types::{TYPE_IDENTITY_PEER_CONFIG, TYPE_IDENTITY_IDENTITY_BINDING};

use crate::IdentityError;

// ---------------------------------------------------------------------------
// 3.2 peer-config
// ---------------------------------------------------------------------------

/// `system/identity/peer-config` (§3.2). Per-agent local state, never
/// shared across identities.
#[derive(Debug, Clone)]
pub struct PeerConfigData {
    pub trusts_quorum: Hash,
    /// What the *top-level* controller's keypair is authorized to do on
    /// this peer. Used to issue the local peer→controller cap.
    /// Sub-controllers do NOT inherit this scope (per §3.2 normative
    /// resolution rule).
    pub controller_grants: Vec<GrantEntry>,
    pub bindings: Vec<IdentityBindingData>,
}

impl PeerConfigData {
    pub fn from_entity(entity: &Entity) -> Result<Self, IdentityError> {
        if entity.entity_type != TYPE_IDENTITY_PEER_CONFIG {
            return Err(IdentityError::Decode(format!(
                "expected {}, got {}",
                TYPE_IDENTITY_PEER_CONFIG, entity.entity_type
            )));
        }
        let map = decode_map(&entity.data)?;
        let trusts_quorum = field_hash(&map, "trusts_quorum")?;
        let controller_grants = decode_grants(get_field(&map, "controller_grants"))?;
        let bindings = decode_bindings(get_field(&map, "bindings"))?;
        Ok(Self {
            trusts_quorum,
            controller_grants,
            bindings,
        })
    }

    pub fn to_entity(&self) -> Result<Entity, IdentityError> {
        // ECF-sorted keys: bindings, controller_grants, trusts_quorum.
        let mut fields: Vec<(Value, Value)> = Vec::new();
        if !self.bindings.is_empty() {
            fields.push((
                text("bindings"),
                Value::Array(self.bindings.iter().map(IdentityBindingData::to_value).collect()),
            ));
        }
        fields.push((
            text("controller_grants"),
            Value::Array(self.controller_grants.iter().map(grant_to_value).collect()),
        ));
        fields.push((
            text("trusts_quorum"),
            Value::Bytes(self.trusts_quorum.to_bytes().to_vec()),
        ));
        let data = to_ecf(&Value::Map(fields));
        Entity::new(TYPE_IDENTITY_PEER_CONFIG, data)
            .map_err(|e| IdentityError::Encode(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// 3.4 identity-binding (inner type)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct IdentityBindingData {
    /// Hash of the cert that pins this identity's contact-side handle.
    /// 3-key default: a controller cert (`mode="public"`).
    /// 4-key advanced: an identifier cert.
    pub handle_cert: Hash,
    /// Hash of the `identity-cert(function="agent")` for this peer.
    pub agent_cert: Hash,
    pub label: Option<String>,
}

impl IdentityBindingData {
    pub fn from_value(value: &ciborium::Value) -> Result<Self, IdentityError> {
        let map = value
            .as_map()
            .ok_or_else(|| IdentityError::Decode("binding must be CBOR map".into()))?
            .clone();
        Ok(Self {
            agent_cert: field_hash(&map, "agent_cert")?,
            handle_cert: field_hash(&map, "handle_cert")?,
            label: field_string_opt(&map, "label")?,
        })
    }

    pub fn to_value(&self) -> Value {
        // ECF sorted: agent_cert, handle_cert, label
        let mut fields: Vec<(Value, Value)> = Vec::new();
        fields.push((
            text("agent_cert"),
            Value::Bytes(self.agent_cert.to_bytes().to_vec()),
        ));
        fields.push((
            text("handle_cert"),
            Value::Bytes(self.handle_cert.to_bytes().to_vec()),
        ));
        if let Some(s) = &self.label {
            fields.push((text("label"), text(s.as_str())));
        }
        Value::Map(fields)
    }

    pub fn to_entity(&self) -> Result<Entity, IdentityError> {
        let data = to_ecf(&self.to_value());
        Entity::new(TYPE_IDENTITY_IDENTITY_BINDING, data)
            .map_err(|e| IdentityError::Encode(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// CBOR helpers
// ---------------------------------------------------------------------------

pub(crate) fn decode_map(
    data: &[u8],
) -> Result<Vec<(ciborium::Value, ciborium::Value)>, IdentityError> {
    let value: ciborium::Value =
        ciborium::from_reader(data).map_err(|e| IdentityError::Decode(e.to_string()))?;
    value
        .into_map()
        .map_err(|_| IdentityError::Decode("expected CBOR map".into()))
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
) -> Result<Hash, IdentityError> {
    let v = get_field(map, key)
        .ok_or_else(|| IdentityError::Decode(format!("missing {}", key)))?;
    let bytes = v
        .as_bytes()
        .ok_or_else(|| IdentityError::Decode(format!("{} must be bytes", key)))?;
    Hash::from_bytes(bytes).map_err(|e| IdentityError::Decode(e.to_string()))
}

pub(crate) fn field_hash_opt(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<Option<Hash>, IdentityError> {
    match get_field(map, key) {
        None | Some(ciborium::Value::Null) => Ok(None),
        Some(v) => {
            let bytes = v
                .as_bytes()
                .ok_or_else(|| IdentityError::Decode(format!("{} must be bytes", key)))?;
            Hash::from_bytes(bytes)
                .map(Some)
                .map_err(|e| IdentityError::Decode(e.to_string()))
        }
    }
}

pub(crate) fn field_hash_array(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<Vec<Hash>, IdentityError> {
    let v = get_field(map, key)
        .ok_or_else(|| IdentityError::Decode(format!("missing {}", key)))?;
    let arr = v
        .as_array()
        .ok_or_else(|| IdentityError::Decode(format!("{} must be array", key)))?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let bytes = item
            .as_bytes()
            .ok_or_else(|| IdentityError::Decode(format!("{} entry must be bytes", key)))?;
        out.push(Hash::from_bytes(bytes).map_err(|e| IdentityError::Decode(e.to_string()))?);
    }
    Ok(out)
}

pub(crate) fn field_u64(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<u64, IdentityError> {
    let v = get_field(map, key)
        .ok_or_else(|| IdentityError::Decode(format!("missing {}", key)))?;
    let i = v
        .as_integer()
        .ok_or_else(|| IdentityError::Decode(format!("{} must be integer", key)))?;
    let n: i128 = i.into();
    if n < 0 {
        return Err(IdentityError::Decode(format!("{} must be non-negative", key)));
    }
    Ok(n as u64)
}

pub(crate) fn field_u64_opt(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<Option<u64>, IdentityError> {
    match get_field(map, key) {
        None | Some(ciborium::Value::Null) => Ok(None),
        Some(v) => {
            let i = v
                .as_integer()
                .ok_or_else(|| IdentityError::Decode(format!("{} must be integer", key)))?;
            let n: i128 = i.into();
            if n < 0 {
                return Err(IdentityError::Decode(format!("{} must be non-negative", key)));
            }
            Ok(Some(n as u64))
        }
    }
}

pub(crate) fn field_string(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<String, IdentityError> {
    field_string_opt(map, key)?.ok_or_else(|| IdentityError::Decode(format!("missing {}", key)))
}

pub(crate) fn field_string_opt(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<Option<String>, IdentityError> {
    match get_field(map, key) {
        None | Some(ciborium::Value::Null) => Ok(None),
        Some(v) => v
            .as_text()
            .map(|s| Some(s.to_string()))
            .ok_or_else(|| IdentityError::Decode(format!("{} must be text", key))),
    }
}

/// Decode a CBOR map from a sub-field. Returns `None` for an absent or
/// null field. Used by `:create_attestation` / `:supersede_attestation` to
/// read the spec-required `properties` sub-map per EXTENSION-ATTESTATION
/// §6.1 + EXTENSION-IDENTITY §6 (cross-impl conformance — the substrate
/// requires `properties` as a single map field, not flat top-level fields).
pub(crate) fn field_map_opt(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<Option<Vec<(ciborium::Value, ciborium::Value)>>, IdentityError> {
    match get_field(map, key) {
        None | Some(ciborium::Value::Null) => Ok(None),
        Some(ciborium::Value::Map(m)) => Ok(Some(m.clone())),
        Some(_) => Err(IdentityError::Decode(format!("{} must be a map", key))),
    }
}

pub(crate) fn field_map(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<Vec<(ciborium::Value, ciborium::Value)>, IdentityError> {
    field_map_opt(map, key)?.ok_or_else(|| IdentityError::Decode(format!("missing {}", key)))
}

// ---------------------------------------------------------------------------
// Grant en/decode (matches the shape used by other identity flows)
// ---------------------------------------------------------------------------

pub(crate) fn decode_grants(
    field: Option<&ciborium::Value>,
) -> Result<Vec<GrantEntry>, IdentityError> {
    let arr = match field {
        None | Some(ciborium::Value::Null) => return Ok(Vec::new()),
        Some(v) => v
            .as_array()
            .ok_or_else(|| IdentityError::Decode("controller_grants must be array".into()))?,
    };
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        out.push(decode_grant_entry(item).map_err(|e| IdentityError::Decode(e.to_string()))?);
    }
    Ok(out)
}

fn grant_to_value(g: &GrantEntry) -> Value {
    encode_grant_entry(g)
}

pub(crate) fn decode_bindings(
    field: Option<&ciborium::Value>,
) -> Result<Vec<IdentityBindingData>, IdentityError> {
    let arr = match field {
        None | Some(ciborium::Value::Null) => return Ok(Vec::new()),
        Some(v) => v
            .as_array()
            .ok_or_else(|| IdentityError::Decode("bindings must be array".into()))?,
    };
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        out.push(IdentityBindingData::from_value(item)?);
    }
    Ok(out)
}
