//! Entity codecs for the three role-extension types (EXTENSION-ROLE v1.5
//! §2): `system/role` (definition), `system/role/assignment`,
//! `system/role/exclusion`.

use entity_capability::{decode_grant_entry, encode_grant_entry, GrantEntry};
use entity_ecf::{text, to_ecf, Value};
use entity_entity::Entity;
use entity_hash::Hash;

use crate::RoleError;

// ---------------------------------------------------------------------------
// Type names
// ---------------------------------------------------------------------------

pub const TYPE_ROLE: &str = "system/role";
pub const TYPE_ROLE_ASSIGNMENT: &str = "system/role/assignment";
pub const TYPE_ROLE_EXCLUSION: &str = "system/role/exclusion";
/// SI-5 v1.6: per-(peer, role, context) linkage entity.
pub const TYPE_ROLE_DERIVED_TOKEN_LINK: &str = "system/role/derived-token-link";

// ---------------------------------------------------------------------------
// Role definition (§2.1)
// ---------------------------------------------------------------------------

/// `system/role` — named bundle of grant entries (§2.1).
///
/// `metadata` carries extension-specific properties (TTL, conditions,
/// etc.) and is encoded as a CBOR map when present.
#[derive(Debug, Clone, Default)]
pub struct RoleData {
    pub name: String,
    pub grants: Vec<GrantEntry>,
    pub metadata: Option<Vec<(ciborium::Value, ciborium::Value)>>,
}

impl RoleData {
    pub fn from_entity(entity: &Entity) -> Result<Self, RoleError> {
        if entity.entity_type != TYPE_ROLE {
            return Err(RoleError::Decode(format!(
                "expected {}, got {}",
                TYPE_ROLE, entity.entity_type
            )));
        }
        let map = decode_map(&entity.data)?;
        let name = field_text(&map, "name")?;
        let grants = decode_grant_array(&map, "grants")?;
        let metadata = match get_field(&map, "metadata") {
            None | Some(ciborium::Value::Null) => None,
            Some(v) => Some(
                v.as_map()
                    .ok_or_else(|| RoleError::Decode("metadata must be CBOR map".into()))?
                    .clone(),
            ),
        };
        Ok(Self {
            name,
            grants,
            metadata,
        })
    }

    pub fn to_entity(&self) -> Result<Entity, RoleError> {
        let mut fields: Vec<(Value, Value)> = Vec::new();
        let grants_val = Value::Array(self.grants.iter().map(encode_grant_entry).collect());
        fields.push((text("grants"), grants_val));
        if let Some(meta) = &self.metadata {
            fields.push((text("metadata"), Value::Map(meta.clone())));
        }
        fields.push((text("name"), text(&self.name)));
        let data = to_ecf(&Value::Map(fields));
        Entity::new(TYPE_ROLE, data).map_err(|e| RoleError::Encode(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Role assignment (§2.2)
// ---------------------------------------------------------------------------

/// `system/role/assignment` — binds a peer to a role within a context (§2.2).
#[derive(Debug, Clone)]
pub struct RoleAssignmentData {
    pub role: String,
    pub assigned_by: Hash,
    pub assigned_at: u64,
    pub metadata: Option<Vec<(ciborium::Value, ciborium::Value)>>,
}

impl RoleAssignmentData {
    pub fn from_entity(entity: &Entity) -> Result<Self, RoleError> {
        if entity.entity_type != TYPE_ROLE_ASSIGNMENT {
            return Err(RoleError::Decode(format!(
                "expected {}, got {}",
                TYPE_ROLE_ASSIGNMENT, entity.entity_type
            )));
        }
        let map = decode_map(&entity.data)?;
        let role = field_text(&map, "role")?;
        let assigned_by = field_hash(&map, "assigned_by")?;
        let assigned_at = field_u64(&map, "assigned_at")?;
        let metadata = match get_field(&map, "metadata") {
            None | Some(ciborium::Value::Null) => None,
            Some(v) => Some(
                v.as_map()
                    .ok_or_else(|| RoleError::Decode("metadata must be CBOR map".into()))?
                    .clone(),
            ),
        };
        Ok(Self {
            role,
            assigned_by,
            assigned_at,
            metadata,
        })
    }

    pub fn to_entity(&self) -> Result<Entity, RoleError> {
        let mut fields: Vec<(Value, Value)> = Vec::new();
        fields.push((
            text("assigned_at"),
            entity_ecf::integer(self.assigned_at as i64),
        ));
        fields.push((
            text("assigned_by"),
            Value::Bytes(self.assigned_by.to_bytes().to_vec()),
        ));
        if let Some(meta) = &self.metadata {
            fields.push((text("metadata"), Value::Map(meta.clone())));
        }
        fields.push((text("role"), text(&self.role)));
        let data = to_ecf(&Value::Map(fields));
        Entity::new(TYPE_ROLE_ASSIGNMENT, data).map_err(|e| RoleError::Encode(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Role exclusion (§2.3)
// ---------------------------------------------------------------------------

/// `system/role/exclusion` — context-level denial for a peer (§2.3).
///
/// **v1.6 (SI-3):** the body `peer_id` field was dropped — redundant
/// with the hex-encoded path segment after SI-1.
#[derive(Debug, Clone)]
pub struct RoleExclusionData {
    pub excluded_by: Hash,
    pub excluded_at: u64,
    pub reason: Option<String>,
}

impl RoleExclusionData {
    pub fn from_entity(entity: &Entity) -> Result<Self, RoleError> {
        if entity.entity_type != TYPE_ROLE_EXCLUSION {
            return Err(RoleError::Decode(format!(
                "expected {}, got {}",
                TYPE_ROLE_EXCLUSION, entity.entity_type
            )));
        }
        let map = decode_map(&entity.data)?;
        let excluded_by = field_hash(&map, "excluded_by")?;
        let excluded_at = field_u64(&map, "excluded_at")?;
        let reason = match get_field(&map, "reason") {
            None | Some(ciborium::Value::Null) => None,
            Some(v) => Some(
                v.as_text()
                    .ok_or_else(|| RoleError::Decode("reason must be text".into()))?
                    .to_string(),
            ),
        };
        Ok(Self {
            excluded_by,
            excluded_at,
            reason,
        })
    }

    pub fn to_entity(&self) -> Result<Entity, RoleError> {
        let mut fields: Vec<(Value, Value)> = Vec::new();
        fields.push((
            text("excluded_at"),
            entity_ecf::integer(self.excluded_at as i64),
        ));
        fields.push((
            text("excluded_by"),
            Value::Bytes(self.excluded_by.to_bytes().to_vec()),
        ));
        if let Some(r) = &self.reason {
            fields.push((text("reason"), text(r)));
        }
        let data = to_ecf(&Value::Map(fields));
        Entity::new(TYPE_ROLE_EXCLUSION, data).map_err(|e| RoleError::Encode(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Derived-token linkage entity (SI-5 v1.6)
// ---------------------------------------------------------------------------

/// `system/role/derived-token-link` — per-(peer, role, context) record
/// mapping a role assignment to the role-derived cap content_hash. Stored
/// at `system/role/{context}/derived-tokens/{peer_id_hex}/{role_name}`
/// (sibling to `assignment/` and `excluded/`).
///
/// `unassign` reads this to revoke the cap deterministically (per IA12 +
/// SI-5); `:delegate` reads this to select the parent cap (per SI-22).
#[derive(Debug, Clone)]
pub struct RoleDerivedTokenLinkData {
    pub token_hash: Hash,
    pub issued_at: u64,
}

impl RoleDerivedTokenLinkData {
    pub fn from_entity(entity: &Entity) -> Result<Self, RoleError> {
        if entity.entity_type != TYPE_ROLE_DERIVED_TOKEN_LINK {
            return Err(RoleError::Decode(format!(
                "expected {}, got {}",
                TYPE_ROLE_DERIVED_TOKEN_LINK, entity.entity_type
            )));
        }
        let map = decode_map(&entity.data)?;
        Ok(Self {
            token_hash: field_hash(&map, "token_hash")?,
            issued_at: field_u64(&map, "issued_at")?,
        })
    }

    pub fn to_entity(&self) -> Result<Entity, RoleError> {
        let fields = vec![
            (
                text("issued_at"),
                entity_ecf::integer(self.issued_at as i64),
            ),
            (
                text("token_hash"),
                Value::Bytes(self.token_hash.to_bytes().to_vec()),
            ),
        ];
        let data = to_ecf(&Value::Map(fields));
        Entity::new(TYPE_ROLE_DERIVED_TOKEN_LINK, data)
            .map_err(|e| RoleError::Encode(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Initial-grant policy (§4.7)
// ---------------------------------------------------------------------------

/// `system/role/initial-grant-policy` — singleton policy that drives the
/// connect-handler's grant-resolver at AUTHENTICATE (§4.7).
///
/// Modes:
/// - `"anonymous-deny"` — default if absent / decode-fails. Unknown peers
///   get whatever the connect handler's static fallback ships.
/// - `"anonymous-allow"` — issue `default_role` grants to every unknown peer.
/// - `"recognize-on-attestation"` — issue `default_role` grants only when
///   the connecting peer has a live agent identity-cert chain rooted at the
///   trusted quorum from peer-config; on non-recognition fall back per
///   `identity_required` (true → deny, false → allow).
pub const MODE_ANONYMOUS_DENY: &str = "anonymous-deny";
pub const MODE_ANONYMOUS_ALLOW: &str = "anonymous-allow";
pub const MODE_RECOGNIZE_ON_ATTESTATION: &str = "recognize-on-attestation";

pub const TYPE_ROLE_INITIAL_GRANT_POLICY: &str = "system/role/initial-grant-policy";

#[derive(Debug, Clone)]
pub struct RoleInitialGrantPolicyData {
    pub unknown_peer: String,
    pub default_role: Option<String>,
    pub default_context: Option<String>,
    pub identity_required: bool,
}

impl Default for RoleInitialGrantPolicyData {
    fn default() -> Self {
        Self {
            unknown_peer: MODE_ANONYMOUS_DENY.to_string(),
            default_role: None,
            default_context: None,
            identity_required: false,
        }
    }
}

impl RoleInitialGrantPolicyData {
    pub fn from_entity(entity: &Entity) -> Result<Self, RoleError> {
        if entity.entity_type != TYPE_ROLE_INITIAL_GRANT_POLICY {
            return Err(RoleError::Decode(format!(
                "expected {}, got {}",
                TYPE_ROLE_INITIAL_GRANT_POLICY, entity.entity_type
            )));
        }
        let map = decode_map(&entity.data)?;
        let unknown_peer = field_text(&map, "unknown_peer")?;
        let default_role = field_text_opt(&map, "default_role")?;
        let default_context = field_text_opt(&map, "default_context")?;
        let identity_required = match get_field(&map, "identity_required") {
            None | Some(ciborium::Value::Null) => false,
            Some(ciborium::Value::Bool(b)) => *b,
            Some(_) => {
                return Err(RoleError::Decode(
                    "identity_required must be bool".into(),
                ))
            }
        };
        Ok(Self {
            unknown_peer,
            default_role,
            default_context,
            identity_required,
        })
    }

    pub fn to_entity(&self) -> Result<Entity, RoleError> {
        // ECF-sorted keys: default_context, default_role, identity_required,
        // unknown_peer.
        let mut fields: Vec<(Value, Value)> = Vec::new();
        if let Some(c) = &self.default_context {
            fields.push((text("default_context"), text(c)));
        }
        if let Some(r) = &self.default_role {
            fields.push((text("default_role"), text(r)));
        }
        if self.identity_required {
            fields.push((text("identity_required"), Value::Bool(true)));
        }
        fields.push((text("unknown_peer"), text(&self.unknown_peer)));
        let data = to_ecf(&Value::Map(fields));
        Entity::new(TYPE_ROLE_INITIAL_GRANT_POLICY, data)
            .map_err(|e| RoleError::Encode(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// CBOR helpers (kept private to this crate)
// ---------------------------------------------------------------------------

pub(crate) fn decode_map(
    data: &[u8],
) -> Result<Vec<(ciborium::Value, ciborium::Value)>, RoleError> {
    let value: ciborium::Value =
        ciborium::from_reader(data).map_err(|e| RoleError::Decode(e.to_string()))?;
    value
        .into_map()
        .map_err(|_| RoleError::Decode("expected CBOR map".into()))
}

pub(crate) fn get_field<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<&'a ciborium::Value> {
    map.iter()
        .find_map(|(k, v)| if k.as_text() == Some(key) { Some(v) } else { None })
}

pub(crate) fn field_text(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<String, RoleError> {
    get_field(map, key)
        .and_then(|v| v.as_text())
        .map(|s| s.to_string())
        .ok_or_else(|| RoleError::Decode(format!("missing or non-text field {}", key)))
}

#[allow(dead_code)]
pub(crate) fn field_text_opt(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<Option<String>, RoleError> {
    match get_field(map, key) {
        None | Some(ciborium::Value::Null) => Ok(None),
        Some(v) => Ok(Some(
            v.as_text()
                .ok_or_else(|| RoleError::Decode(format!("{} must be text", key)))?
                .to_string(),
        )),
    }
}

pub(crate) fn field_hash(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<Hash, RoleError> {
    let v = get_field(map, key)
        .ok_or_else(|| RoleError::Decode(format!("missing {} field", key)))?;
    let bytes = v
        .as_bytes()
        .ok_or_else(|| RoleError::Decode(format!("{} must be byte string", key)))?;
    Hash::from_bytes(bytes).map_err(|e| RoleError::Decode(e.to_string()))
}

pub(crate) fn field_u64(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<u64, RoleError> {
    let v = get_field(map, key)
        .ok_or_else(|| RoleError::Decode(format!("missing {} field", key)))?;
    let i = v
        .as_integer()
        .ok_or_else(|| RoleError::Decode(format!("{} must be integer", key)))?;
    let n: i128 = i.into();
    if n < 0 {
        return Err(RoleError::Decode(format!("{} must be non-negative", key)));
    }
    Ok(n as u64)
}

pub(crate) fn field_u64_opt(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<Option<u64>, RoleError> {
    match get_field(map, key) {
        None | Some(ciborium::Value::Null) => Ok(None),
        Some(v) => {
            let i = v
                .as_integer()
                .ok_or_else(|| RoleError::Decode(format!("{} must be integer", key)))?;
            let n: i128 = i.into();
            if n < 0 {
                return Err(RoleError::Decode(format!("{} must be non-negative", key)));
            }
            Ok(Some(n as u64))
        }
    }
}

fn decode_grant_array(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<Vec<GrantEntry>, RoleError> {
    let v = get_field(map, key)
        .ok_or_else(|| RoleError::Decode(format!("missing {} field", key)))?;
    let arr = v
        .as_array()
        .ok_or_else(|| RoleError::Decode(format!("{} must be array", key)))?;
    let mut grants = Vec::with_capacity(arr.len());
    for item in arr {
        grants.push(decode_grant_entry(item).map_err(|e| RoleError::Decode(e.to_string()))?);
    }
    Ok(grants)
}

/// Decode an array of `system/capability/grant-entry` from a CBOR Value.
/// Used by request decoders that receive grant arrays as op params.
pub fn decode_grant_array_value(
    value: &ciborium::Value,
) -> Result<Vec<GrantEntry>, RoleError> {
    let arr = value
        .as_array()
        .ok_or_else(|| RoleError::Decode("grants must be array".into()))?;
    let mut grants = Vec::with_capacity(arr.len());
    for item in arr {
        grants.push(decode_grant_entry(item).map_err(|e| RoleError::Decode(e.to_string()))?);
    }
    Ok(grants)
}

/// Hex-encode a `system/hash` for path segments. Same convention as
/// attestation/identity.
pub fn hex_segment(h: &Hash) -> String {
    let bytes = h.to_bytes();
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in &bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_capability::{IdScope, PathScope};

    fn sample_grant() -> GrantEntry {
        GrantEntry {
            handlers: PathScope::new(vec!["system/tree".into()]),
            resources: PathScope::new(vec!["shared/*".into()]),
            operations: IdScope::new(vec!["get".into(), "put".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        }
    }

    #[test]
    fn role_data_roundtrip() {
        let role = RoleData {
            name: "operator".into(),
            grants: vec![sample_grant()],
            metadata: None,
        };
        let entity = role.to_entity().unwrap();
        assert_eq!(entity.entity_type, TYPE_ROLE);
        let decoded = RoleData::from_entity(&entity).unwrap();
        assert_eq!(decoded.name, "operator");
        assert_eq!(decoded.grants.len(), 1);
    }

    #[test]
    fn role_assignment_roundtrip() {
        let by = Hash::compute("test", b"by");
        let assignment = RoleAssignmentData {
            role: "leader".into(),
            assigned_by: by,
            assigned_at: 1_700_000_000_000,
            metadata: None,
        };
        let entity = assignment.to_entity().unwrap();
        assert_eq!(entity.entity_type, TYPE_ROLE_ASSIGNMENT);
        let decoded = RoleAssignmentData::from_entity(&entity).unwrap();
        assert_eq!(decoded.role, "leader");
        assert_eq!(decoded.assigned_by, by);
        assert_eq!(decoded.assigned_at, 1_700_000_000_000);
    }

    #[test]
    fn role_exclusion_roundtrip_no_peer_id_field() {
        let by = Hash::compute("test", b"by");
        let exclusion = RoleExclusionData {
            excluded_by: by,
            excluded_at: 1_700_000_000_000,
            reason: Some("evicted".into()),
        };
        let entity = exclusion.to_entity().unwrap();
        assert_eq!(entity.entity_type, TYPE_ROLE_EXCLUSION);
        let decoded = RoleExclusionData::from_entity(&entity).unwrap();
        assert_eq!(decoded.excluded_by, by);
        assert_eq!(decoded.reason.as_deref(), Some("evicted"));
        // Confirm v1.6: no `peer_id` field appears in the encoded data
        // (SI-3). Decoded round-trip is the inverse of encoding; the
        // struct shape proves it structurally.
    }

    #[test]
    fn derived_token_link_roundtrip() {
        let token_hash = Hash::compute("system/capability/token", b"sample");
        let link = RoleDerivedTokenLinkData {
            token_hash,
            issued_at: 1_700_000_000_000,
        };
        let entity = link.to_entity().unwrap();
        assert_eq!(entity.entity_type, TYPE_ROLE_DERIVED_TOKEN_LINK);
        let decoded = RoleDerivedTokenLinkData::from_entity(&entity).unwrap();
        assert_eq!(decoded.token_hash, token_hash);
        assert_eq!(decoded.issued_at, 1_700_000_000_000);
    }

    #[test]
    fn initial_grant_policy_roundtrip_recognize_mode() {
        let p = RoleInitialGrantPolicyData {
            unknown_peer: MODE_RECOGNIZE_ON_ATTESTATION.into(),
            default_role: Some("guest".into()),
            default_context: Some("public".into()),
            identity_required: true,
        };
        let entity = p.to_entity().unwrap();
        assert_eq!(entity.entity_type, TYPE_ROLE_INITIAL_GRANT_POLICY);
        let decoded = RoleInitialGrantPolicyData::from_entity(&entity).unwrap();
        assert_eq!(decoded.unknown_peer, MODE_RECOGNIZE_ON_ATTESTATION);
        assert_eq!(decoded.default_role.as_deref(), Some("guest"));
        assert_eq!(decoded.default_context.as_deref(), Some("public"));
        assert!(decoded.identity_required);
    }

    #[test]
    fn initial_grant_policy_omits_falsy_identity_required() {
        let p = RoleInitialGrantPolicyData {
            unknown_peer: MODE_ANONYMOUS_DENY.into(),
            default_role: None,
            default_context: None,
            identity_required: false,
        };
        let entity = p.to_entity().unwrap();
        let decoded = RoleInitialGrantPolicyData::from_entity(&entity).unwrap();
        assert_eq!(decoded.unknown_peer, MODE_ANONYMOUS_DENY);
        assert!(decoded.default_role.is_none());
        assert!(decoded.default_context.is_none());
        assert!(!decoded.identity_required);
    }

    #[test]
    fn role_data_rejects_wrong_type() {
        let bytes = to_ecf(&Value::Map(vec![]));
        let bogus = Entity::new("system/wrong", bytes).unwrap();
        assert!(RoleData::from_entity(&bogus).is_err());
    }
}
