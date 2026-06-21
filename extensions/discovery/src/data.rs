//! EXTENSION-DISCOVERY v1.0 entity codecs (§2.1, §2.2.1) + `:scan` envelope (§3).
//!
//! ECF-deterministic CBOR (`to_ecf` canonicalizes key order, so field
//! insertion order below is for readability only). Optional fields are encoded
//! **absent** (key not present) when `None`, per the interop "optional SHOULD
//! be absent" rule — decode tolerates both absent and explicit `null`. All
//! bare-hash fields (`identity_hint`, `supersedes`, `candidate`, `grant`) are
//! 33-byte `system/hash` byte strings, never wrapped under `{type,data}`.
//! `peer_id` is a Base58 peer-id string (V7 §1.5), NOT a hash.
//!
//! All timestamps are milliseconds since Unix epoch (UTC, signed int64) per
//! §2.1 — encoded as canonical CBOR integers.

use entity_ecf::{integer, text, to_ecf, Value};
use entity_entity::Entity;
use entity_hash::Hash;
use entity_types::{
    TYPE_DISCOVERY_CANDIDATE, TYPE_DISCOVERY_DECISION, TYPE_DISCOVERY_IDENTITY_CLAIM,
};

use crate::DiscoveryError;

// ---------------------------------------------------------------------------
// system/discovery/candidate (§2.1)
// ---------------------------------------------------------------------------

/// A peer presence surfaced by a backend. `peer_id` is `None` (encoded absent)
/// until IDENTIFY completes — a successor candidate carries the populated
/// `peer_id` + `supersedes` per the §2.2 immutable-entity successor pattern;
/// the original remains as the observation record.
#[derive(Debug, Clone, PartialEq)]
pub struct CandidateData {
    /// Base58 peer-id (V7 §1.5); `None` until IDENTIFY completes (§2.2).
    pub peer_id: Option<String>,
    /// Backend discriminator: `"mdns"`, `"qr"`, … (§2.1).
    pub backend: String,
    /// Observation time, ms-since-epoch (§2.1).
    pub observed_at: i64,
    /// Opaque dial hint — LAN address+port, QR payload, etc. (§2.1).
    pub endpoint_hint: Value,
    /// Bare `system/hash` of an [`IdentityClaimData`]; `None` = TOFU (§2.2.1).
    pub identity_hint: Option<Hash>,
    /// Bare `system/hash` of the candidate this one supersedes (§2.2).
    pub supersedes: Option<Hash>,
}

impl CandidateData {
    pub fn from_entity(entity: &Entity) -> Result<Self, DiscoveryError> {
        if entity.entity_type != TYPE_DISCOVERY_CANDIDATE {
            return Err(DiscoveryError::Decode(format!(
                "expected {}, got {}",
                TYPE_DISCOVERY_CANDIDATE, entity.entity_type
            )));
        }
        let map = decode_map(&entity.data)?;
        Ok(Self {
            peer_id: field_text_opt(&map, "peer_id"),
            backend: field_text(&map, "backend")?,
            observed_at: field_i64(&map, "observed_at")?,
            endpoint_hint: get_field(&map, "endpoint_hint")
                .cloned()
                .ok_or_else(|| DiscoveryError::Decode("missing endpoint_hint field".into()))?,
            identity_hint: field_hash_opt(&map, "identity_hint")?,
            supersedes: field_hash_opt(&map, "supersedes")?,
        })
    }

    pub fn to_entity(&self) -> Result<Entity, DiscoveryError> {
        let mut fields: Vec<(Value, Value)> = vec![
            (text("backend"), text(&self.backend)),
            (text("endpoint_hint"), self.endpoint_hint.clone()),
            (text("observed_at"), integer(self.observed_at)),
        ];
        // peer_id null-until-IDENTIFY: encode **absent** when None, per the
        // project-wide "optional SHOULD be absent" convention. This is a
        // cross-impl byte-equality convergence point — see
        // docs/SPEC-AMBIGUITIES.md (DISCOVERY candidate.peer_id null-vs-absent).
        if let Some(p) = &self.peer_id {
            fields.push((text("peer_id"), text(p)));
        }
        if let Some(h) = &self.identity_hint {
            fields.push((text("identity_hint"), bytes(h)));
        }
        if let Some(s) = &self.supersedes {
            fields.push((text("supersedes"), bytes(s)));
        }
        encode(TYPE_DISCOVERY_CANDIDATE, fields)
    }
}

// ---------------------------------------------------------------------------
// system/discovery/decision (§2.1)
// ---------------------------------------------------------------------------

/// The user's admission choice for a candidate. `grant` is the bare
/// `system/hash` of a `system/capability/grant` entity (V7 §6.2) for
/// `grant-limited` / `grant-more`; `None` for `ignore` / `track`. The grant is
/// referenced by target-matching (V7 §5.2), NOT via a `refs:` block (§2.1).
#[derive(Debug, Clone, PartialEq)]
pub struct DecisionData {
    /// Bare `system/hash` of the candidate-chain head (§2.2).
    pub candidate: Hash,
    /// One of `ignore` / `track` / `grant-limited` / `grant-more` (§2.1).
    pub outcome: String,
    /// Bare `system/hash` of the `system/capability/grant`; `None` for
    /// ignore/track (§2.1).
    pub grant: Option<Hash>,
    /// Decision time, ms-since-epoch (§2.1).
    pub decided_at: i64,
}

impl DecisionData {
    pub fn from_entity(entity: &Entity) -> Result<Self, DiscoveryError> {
        if entity.entity_type != TYPE_DISCOVERY_DECISION {
            return Err(DiscoveryError::Decode(format!(
                "expected {}, got {}",
                TYPE_DISCOVERY_DECISION, entity.entity_type
            )));
        }
        let map = decode_map(&entity.data)?;
        Ok(Self {
            candidate: field_hash(&map, "candidate")?,
            outcome: field_text(&map, "outcome")?,
            grant: field_hash_opt(&map, "grant")?,
            decided_at: field_i64(&map, "decided_at")?,
        })
    }

    pub fn to_entity(&self) -> Result<Entity, DiscoveryError> {
        let mut fields: Vec<(Value, Value)> = vec![
            (text("candidate"), bytes(&self.candidate)),
            (text("decided_at"), integer(self.decided_at)),
            (text("outcome"), text(&self.outcome)),
        ];
        if let Some(g) = &self.grant {
            fields.push((text("grant"), bytes(g)));
        }
        encode(TYPE_DISCOVERY_DECISION, fields)
    }
}

// ---------------------------------------------------------------------------
// system/discovery/identity-claim (§2.2.1)
// ---------------------------------------------------------------------------

/// A backend's identity claim for a candidate. When a candidate's
/// `identity_hint` is non-null it is the bare `system/hash` of this entity.
/// Post-IDENTIFY the receiver reconstructs an `IdentityClaimData` from the
/// actual IDENTIFY result, recomputes its `content_hash`, and admission MUST
/// fail closed if it does not equal the advertised `identity_hint` (§2.2.1).
#[derive(Debug, Clone, PartialEq)]
pub struct IdentityClaimData {
    /// Claimed Base58 peer-id (V7 §1.5).
    pub peer_id: String,
    /// V7 §1.5 key-type byte.
    pub key_type: u64,
    /// V7 §1.5 hash-type byte.
    pub hash_type: u64,
    /// V7 §1.5 public-key digest.
    pub public_key_digest: Vec<u8>,
}

impl IdentityClaimData {
    pub fn from_entity(entity: &Entity) -> Result<Self, DiscoveryError> {
        if entity.entity_type != TYPE_DISCOVERY_IDENTITY_CLAIM {
            return Err(DiscoveryError::Decode(format!(
                "expected {}, got {}",
                TYPE_DISCOVERY_IDENTITY_CLAIM, entity.entity_type
            )));
        }
        let map = decode_map(&entity.data)?;
        Ok(Self {
            peer_id: field_text(&map, "peer_id")?,
            key_type: field_u64(&map, "key_type")?,
            hash_type: field_u64(&map, "hash_type")?,
            public_key_digest: field_bytes(&map, "public_key_digest")?,
        })
    }

    pub fn to_entity(&self) -> Result<Entity, DiscoveryError> {
        let fields: Vec<(Value, Value)> = vec![
            (text("hash_type"), integer(self.hash_type as i64)),
            (text("key_type"), integer(self.key_type as i64)),
            (text("peer_id"), text(&self.peer_id)),
            (
                text("public_key_digest"),
                Value::Bytes(self.public_key_digest.clone()),
            ),
        ];
        encode(TYPE_DISCOVERY_IDENTITY_CLAIM, fields)
    }

    /// Content hash of this claim — the value a candidate's `identity_hint`
    /// references and the value reconstructed-and-compared post-IDENTIFY
    /// (§2.2.1). Equality of this hash IS the fail-closed admission gate.
    pub fn content_hash(&self) -> Result<Hash, DiscoveryError> {
        Ok(self.to_entity()?.content_hash)
    }
}

// ---------------------------------------------------------------------------
// ScanResult (§3) — `:scan` return payload (not a stored entity type)
// ---------------------------------------------------------------------------

/// Immediate snapshot returned by `system/discovery:scan` (§3). The same call
/// also establishes/refreshes the watchable `system/discovery/candidate/{backend}/*`
/// browse session (the hybrid shape, §3.0) — that surface is the handler's
/// concern, landing with the mDNS backend post-cohort-convergence.
///
/// Over-bound scans MUST set `truncated: true` + `code:
/// "discovery_scan_overflow"` (503) — NOT silent truncation (§3.1, §8.4).
#[derive(Debug, Clone, PartialEq)]
pub struct ScanResult {
    /// Bare `system/hash`es of `system/discovery/candidate` entities (§3).
    pub candidates: Vec<Hash>,
    /// `true` if the per-scan candidate-count ceiling was exceeded (§3.1).
    pub truncated: bool,
    /// `None` normally; `"discovery_scan_overflow"` when truncated (§3.1).
    pub code: Option<String>,
}

impl ScanResult {
    /// A complete, in-bound snapshot.
    pub fn ok(candidates: Vec<Hash>) -> Self {
        Self {
            candidates,
            truncated: false,
            code: None,
        }
    }

    /// An over-ceiling snapshot — the remaining candidates were dropped from
    /// this scan; surfaces the overflow signal per §3.1 (NOT silent).
    pub fn overflow(candidates: Vec<Hash>) -> Self {
        Self {
            candidates,
            truncated: true,
            code: Some(crate::CODE_SCAN_OVERFLOW.to_string()),
        }
    }

    /// The flat `{candidates, truncated, code}` envelope fields (§3).
    pub fn to_fields(&self) -> Vec<(Value, Value)> {
        let mut fields: Vec<(Value, Value)> = vec![
            (
                text("candidates"),
                Value::Array(self.candidates.iter().map(bytes).collect()),
            ),
            (text("truncated"), Value::Bool(self.truncated)),
        ];
        if let Some(c) = &self.code {
            fields.push((text("code"), text(c)));
        }
        fields
    }

    /// Encode the flat `{candidates, truncated, code}` envelope (§3).
    pub fn to_value(&self) -> Value {
        Value::Map(self.to_fields())
    }

    pub fn from_value(value: &Value) -> Result<Self, DiscoveryError> {
        let map = value
            .as_map()
            .ok_or_else(|| DiscoveryError::Decode("ScanResult: expected CBOR map".into()))?;
        let candidates = field_array(map, "candidates")
            .iter()
            .map(|v| {
                v.as_bytes()
                    .ok_or_else(|| DiscoveryError::Decode("candidate must be byte string".into()))
                    .and_then(|b| {
                        Hash::from_bytes(b).map_err(|e| DiscoveryError::Decode(e.to_string()))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            candidates,
            truncated: field_bool_opt(map, "truncated").unwrap_or(false),
            code: field_text_opt(map, "code"),
        })
    }
}

// ---------------------------------------------------------------------------
// CBOR helpers (shape mirrors extensions/registry/src/data.rs)
// ---------------------------------------------------------------------------

fn bytes(h: &Hash) -> Value {
    Value::Bytes(h.to_bytes().to_vec())
}

fn encode(entity_type: &str, fields: Vec<(Value, Value)>) -> Result<Entity, DiscoveryError> {
    let data = to_ecf(&Value::Map(fields));
    Entity::new(entity_type, data).map_err(|e| DiscoveryError::Encode(e.to_string()))
}

fn decode_map(data: &[u8]) -> Result<Vec<(Value, Value)>, DiscoveryError> {
    let value: Value =
        ciborium::from_reader(data).map_err(|e| DiscoveryError::Decode(e.to_string()))?;
    value
        .into_map()
        .map_err(|_| DiscoveryError::Decode("expected CBOR map".into()))
}

fn get_field<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find_map(|(k, v)| if k.as_text() == Some(key) { Some(v) } else { None })
}

fn field_text(map: &[(Value, Value)], key: &str) -> Result<String, DiscoveryError> {
    get_field(map, key)
        .and_then(|v| v.as_text())
        .map(|s| s.to_string())
        .ok_or_else(|| DiscoveryError::Decode(format!("missing/invalid text field {}", key)))
}

fn field_text_opt(map: &[(Value, Value)], key: &str) -> Option<String> {
    get_field(map, key)
        .and_then(|v| v.as_text())
        .map(|s| s.to_string())
}

fn field_i64(map: &[(Value, Value)], key: &str) -> Result<i64, DiscoveryError> {
    get_field(map, key)
        .and_then(|v| v.as_integer())
        .and_then(|i| i64::try_from(i).ok())
        .ok_or_else(|| DiscoveryError::Decode(format!("missing/invalid int field {}", key)))
}

fn field_u64(map: &[(Value, Value)], key: &str) -> Result<u64, DiscoveryError> {
    get_field(map, key)
        .and_then(|v| v.as_integer())
        .and_then(|i| u64::try_from(i).ok())
        .ok_or_else(|| DiscoveryError::Decode(format!("missing/invalid uint field {}", key)))
}

fn field_bytes(map: &[(Value, Value)], key: &str) -> Result<Vec<u8>, DiscoveryError> {
    get_field(map, key)
        .and_then(|v| v.as_bytes())
        .map(|b| b.to_vec())
        .ok_or_else(|| DiscoveryError::Decode(format!("missing/invalid bytes field {}", key)))
}

fn field_bool_opt(map: &[(Value, Value)], key: &str) -> Option<bool> {
    get_field(map, key).and_then(|v| match v {
        Value::Bool(b) => Some(*b),
        _ => None,
    })
}

fn field_array(map: &[(Value, Value)], key: &str) -> Vec<Value> {
    get_field(map, key)
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

fn field_hash(map: &[(Value, Value)], key: &str) -> Result<Hash, DiscoveryError> {
    let v = get_field(map, key)
        .ok_or_else(|| DiscoveryError::Decode(format!("missing {} field", key)))?;
    let b = v
        .as_bytes()
        .ok_or_else(|| DiscoveryError::Decode(format!("{} must be byte string", key)))?;
    Hash::from_bytes(b).map_err(|e| DiscoveryError::Decode(e.to_string()))
}

fn field_hash_opt(map: &[(Value, Value)], key: &str) -> Result<Option<Hash>, DiscoveryError> {
    match get_field(map, key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => {
            let b = v
                .as_bytes()
                .ok_or_else(|| DiscoveryError::Decode(format!("{} must be byte string", key)))?;
            Ok(Some(
                Hash::from_bytes(b).map_err(|e| DiscoveryError::Decode(e.to_string()))?,
            ))
        }
    }
}
