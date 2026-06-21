//! EXTENSION-REGISTRY v1.0 entity codecs (§3, §3.1, §4, §6.4, §11.2).
//!
//! ECF-deterministic CBOR. Optional fields are encoded absent (key not
//! present) when `None`/empty per the interop "optional SHOULD be absent"
//! rule. All bare-hash fields (`supersedes`, `issuer_attestation`, `revokes`,
//! `binding`) are 33-byte `system/hash` byte strings, never wrapped.
//! `target_peer_id` is a Base58 peer-id string (V7 §1.5), NOT a hash.

use entity_ecf::{integer, text, to_ecf, Value};
use entity_entity::Entity;
use entity_hash::Hash;
use entity_types::{
    TYPE_REGISTRY_BINDING, TYPE_REGISTRY_ISSUER_POLICY, TYPE_REGISTRY_LOCAL_NAME_CONFIG,
    TYPE_REGISTRY_REGISTER_REQUEST, TYPE_REGISTRY_RESOLUTION_LOG, TYPE_REGISTRY_RESOLVER_CONFIG,
    TYPE_REGISTRY_REVOCATION,
};
use unicode_normalization::UnicodeNormalization;

use crate::RegistryError;

// Vocabulary (§2.4.1) — binding kinds (hyphen-spelled).
pub const KIND_SELF_CERTIFYING: &str = "self-certifying";
pub const KIND_LOCAL_NAME: &str = "local-name";
/// Peer-issued binding kind (PROPOSAL-PEER-ISSUED §3.2 — signed by a registry).
pub const KIND_PEER_ISSUED: &str = "peer-issued";

// Trust-anchor discriminators (§2.4 — underscore-spelled per V7 enum form).
pub const TRUST_LOCAL_NAME: &str = "local_name";
pub const TRUST_SELF_CERTIFYING: &str = "self_certifying";
pub const TRUST_OUT_OF_BAND: &str = "out_of_band";
/// Peer-issued trust anchor is parametric: `peer_issued:{registry_peer_id}`
/// (PROPOSAL-PEER-ISSUED §2.1 step 3). This is the prefix; the registry's
/// Base58 peer-id is appended.
pub const TRUST_PEER_ISSUED_PREFIX: &str = "peer_issued:";

// ResolutionResult statuses (§2.1).
pub const STATUS_RESOLVED: &str = "resolved";
pub const STATUS_NOT_FOUND: &str = "not_found";
pub const STATUS_CHAIN_EXHAUSTED: &str = "chain_exhausted";

// ---------------------------------------------------------------------------
// system/registry/binding (§3 / §6.3)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct BindingData {
    pub name: String,
    pub kind: String,
    /// Base58 peer-id (V7 §1.5) — an identity, NOT a content-hash.
    pub target_peer_id: String,
    /// Opaque endpoint descriptors per NETWORK §6.5 (substrate passes through).
    pub transports: Vec<Value>,
    pub issued_at: u64,
    pub ttl: Option<u64>,
    pub supersedes: Option<Hash>,
    pub issuer_attestation: Option<Hash>,
    pub metadata: Option<Value>,
}

impl BindingData {
    pub fn from_entity(entity: &Entity) -> Result<Self, RegistryError> {
        if entity.entity_type != TYPE_REGISTRY_BINDING {
            return Err(RegistryError::Decode(format!(
                "expected {}, got {}",
                TYPE_REGISTRY_BINDING, entity.entity_type
            )));
        }
        let map = decode_map(&entity.data)?;
        Ok(Self {
            name: field_text(&map, "name")?,
            kind: field_text(&map, "kind")?,
            target_peer_id: field_text(&map, "target_peer_id")?,
            transports: field_array(&map, "transports"),
            issued_at: field_u64(&map, "issued_at")?,
            ttl: field_u64_opt(&map, "ttl")?,
            supersedes: field_hash_opt(&map, "supersedes")?,
            issuer_attestation: field_hash_opt(&map, "issuer_attestation")?,
            metadata: get_field(&map, "metadata")
                .filter(|v| !matches!(v, Value::Null))
                .cloned(),
        })
    }

    pub fn to_entity(&self) -> Result<Entity, RegistryError> {
        let mut fields: Vec<(Value, Value)> = vec![
            (text("issued_at"), integer(self.issued_at as i64)),
            (text("kind"), text(&self.kind)),
            (text("name"), text(&self.name)),
            (text("target_peer_id"), text(&self.target_peer_id)),
        ];
        if let Some(att) = &self.issuer_attestation {
            fields.push((text("issuer_attestation"), bytes(att)));
        }
        if let Some(m) = &self.metadata {
            fields.push((text("metadata"), m.clone()));
        }
        if let Some(s) = &self.supersedes {
            fields.push((text("supersedes"), bytes(s)));
        }
        if !self.transports.is_empty() {
            fields.push((text("transports"), Value::Array(self.transports.clone())));
        }
        if let Some(t) = self.ttl {
            fields.push((text("ttl"), integer(t as i64)));
        }
        encode(TYPE_REGISTRY_BINDING, fields)
    }
}

// ---------------------------------------------------------------------------
// system/registry/revocation (§3.1)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct RevocationData {
    pub revokes: Hash,
    pub revoked_at: u64,
    pub reason: Option<String>,
}

impl RevocationData {
    pub fn from_entity(entity: &Entity) -> Result<Self, RegistryError> {
        if entity.entity_type != TYPE_REGISTRY_REVOCATION {
            return Err(RegistryError::Decode(format!(
                "expected {}, got {}",
                TYPE_REGISTRY_REVOCATION, entity.entity_type
            )));
        }
        let map = decode_map(&entity.data)?;
        Ok(Self {
            revokes: field_hash(&map, "revokes")?,
            revoked_at: field_u64(&map, "revoked_at")?,
            reason: field_text_opt(&map, "reason"),
        })
    }

    pub fn to_entity(&self) -> Result<Entity, RegistryError> {
        let mut fields: Vec<(Value, Value)> = vec![
            (text("revoked_at"), integer(self.revoked_at as i64)),
            (text("revokes"), bytes(&self.revokes)),
        ];
        if let Some(r) = &self.reason {
            fields.push((text("reason"), text(r)));
        }
        encode(TYPE_REGISTRY_REVOCATION, fields)
    }
}

// ---------------------------------------------------------------------------
// system/registry/register-request (§6a.9) — peer-issued live registration
// ---------------------------------------------------------------------------

/// A publisher's self-signed claim to bind `name → target_peer_id` on a live
/// registry. The entity's `content_hash` is what `target_peer_id` signs
/// (layer-1 ownership proof, §6a.9); `nonce` + `issued_at` back the registry's
/// replay defense.
#[derive(Debug, Clone, PartialEq)]
pub struct RegisterRequestData {
    pub name: String,
    /// Base58 peer-id the name resolves to AND whose key must sign the request.
    pub target_peer_id: String,
    pub transports: Vec<Value>,
    pub requested_ttl: Option<u64>,
    pub nonce: Vec<u8>,
    pub issued_at: u64,
}

impl RegisterRequestData {
    pub fn from_entity(entity: &Entity) -> Result<Self, RegistryError> {
        if entity.entity_type != TYPE_REGISTRY_REGISTER_REQUEST {
            return Err(RegistryError::Decode(format!(
                "expected {}, got {}",
                TYPE_REGISTRY_REGISTER_REQUEST, entity.entity_type
            )));
        }
        let map = decode_map(&entity.data)?;
        Ok(Self {
            name: field_text(&map, "name")?,
            target_peer_id: field_text(&map, "target_peer_id")?,
            transports: field_array(&map, "transports"),
            requested_ttl: field_u64_opt(&map, "requested_ttl")?,
            nonce: field_bytes(&map, "nonce")?,
            issued_at: field_u64(&map, "issued_at")?,
        })
    }

    pub fn to_entity(&self) -> Result<Entity, RegistryError> {
        let mut fields: Vec<(Value, Value)> = vec![
            (text("issued_at"), integer(self.issued_at as i64)),
            (text("name"), text(&self.name)),
            (text("nonce"), Value::Bytes(self.nonce.clone())),
            (text("target_peer_id"), text(&self.target_peer_id)),
        ];
        if let Some(t) = self.requested_ttl {
            fields.push((text("requested_ttl"), integer(t as i64)));
        }
        if !self.transports.is_empty() {
            fields.push((text("transports"), Value::Array(self.transports.clone())));
        }
        encode(TYPE_REGISTRY_REGISTER_REQUEST, fields)
    }
}

// ---------------------------------------------------------------------------
// system/registry/issuer-policy (§6a.9.1) — registry-local admission knob
// ---------------------------------------------------------------------------

// Issuer-policy modes (§6a.9.1). `domain-control` is DEFERRED (the DNS-proof
// challenge format co-designs with the web-native backends, §6a.10).
pub const MODE_OPEN: &str = "open";
pub const MODE_ALLOWLIST: &str = "allowlist";
pub const MODE_MANUAL: &str = "manual";
pub const MODE_DOMAIN_CONTROL: &str = "domain-control";

#[derive(Debug, Clone, PartialEq)]
pub struct IssuerPolicyData {
    pub mode: String,
    /// Allow-listed `target_peer_id`s (allowlist mode). `None` = no allowlist.
    pub allowlist: Option<Vec<String>>,
    /// Optional glob (§4.1 shell-glob) bounding which names may be issued.
    pub name_constraints: Option<String>,
    pub default_ttl: Option<u64>,
}

impl Default for IssuerPolicyData {
    /// A registry that runs the handler but has no policy entity defaults to
    /// `manual` — the conservative posture: requests queue for operator review
    /// rather than auto-issue. The operator opts into `open`/`allowlist`
    /// explicitly (spec-problems doc; §6a.9.1 names no default).
    fn default() -> Self {
        Self {
            mode: MODE_MANUAL.into(),
            allowlist: None,
            name_constraints: None,
            default_ttl: None,
        }
    }
}

impl IssuerPolicyData {
    pub fn from_entity(entity: &Entity) -> Result<Self, RegistryError> {
        if entity.entity_type != TYPE_REGISTRY_ISSUER_POLICY {
            return Err(RegistryError::Decode(format!(
                "expected {}, got {}",
                TYPE_REGISTRY_ISSUER_POLICY, entity.entity_type
            )));
        }
        let map = decode_map(&entity.data)?;
        let allowlist = get_field(&map, "allowlist")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_text().map(|s| s.to_string()))
                    .collect()
            });
        Ok(Self {
            mode: field_text(&map, "mode")?,
            allowlist,
            name_constraints: field_text_opt(&map, "name_constraints"),
            default_ttl: field_u64_opt(&map, "default_ttl")?,
        })
    }

    pub fn to_entity(&self) -> Result<Entity, RegistryError> {
        let mut fields: Vec<(Value, Value)> = vec![(text("mode"), text(&self.mode))];
        if let Some(a) = &self.allowlist {
            fields.push((text("allowlist"), Value::Array(a.iter().map(text).collect())));
        }
        if let Some(t) = self.default_ttl {
            fields.push((text("default_ttl"), integer(t as i64)));
        }
        if let Some(c) = &self.name_constraints {
            fields.push((text("name_constraints"), text(c)));
        }
        encode(TYPE_REGISTRY_ISSUER_POLICY, fields)
    }
}

// ---------------------------------------------------------------------------
// system/registry/resolver-config (§4)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct ResolverChainEntry {
    pub backend_kind: String,
    pub backend_id: String,
    pub priority: u32,
    pub accepted_trust_anchors: Vec<String>,
    pub hints: Option<Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PinnedBinding {
    pub name: String,
    pub target_peer_id: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DispatchRule {
    pub pattern: String,
    pub backend_kinds: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolverConfigData {
    pub resolver_chain: Vec<ResolverChainEntry>,
    pub pinned_bindings: Vec<PinnedBinding>,
    pub name_format_dispatch: Vec<DispatchRule>,
    pub log_cache_hits: bool,
    pub resolution_log_capacity: u64,
}

impl Default for ResolverConfigData {
    fn default() -> Self {
        Self {
            resolver_chain: Vec::new(),
            pinned_bindings: Vec::new(),
            name_format_dispatch: Vec::new(),
            log_cache_hits: false,
            resolution_log_capacity: 1024,
        }
    }
}

impl ResolverConfigData {
    pub fn from_entity(entity: &Entity) -> Result<Self, RegistryError> {
        if entity.entity_type != TYPE_REGISTRY_RESOLVER_CONFIG {
            return Err(RegistryError::Decode(format!(
                "expected {}, got {}",
                TYPE_REGISTRY_RESOLVER_CONFIG, entity.entity_type
            )));
        }
        let map = decode_map(&entity.data)?;
        let resolver_chain = field_array(&map, "resolver_chain")
            .iter()
            .filter_map(decode_chain_entry)
            .collect();
        let pinned_bindings = field_array(&map, "pinned_bindings")
            .iter()
            .filter_map(decode_pinned)
            .collect();
        let name_format_dispatch = field_array(&map, "name_format_dispatch")
            .iter()
            .filter_map(decode_dispatch_rule)
            .collect();
        Ok(Self {
            resolver_chain,
            pinned_bindings,
            name_format_dispatch,
            log_cache_hits: field_bool_opt(&map, "log_cache_hits").unwrap_or(false),
            resolution_log_capacity: field_u64_opt(&map, "resolution_log_capacity")?
                .unwrap_or(1024),
        })
    }

    pub fn to_entity(&self) -> Result<Entity, RegistryError> {
        let chain: Vec<Value> = self
            .resolver_chain
            .iter()
            .map(|e| {
                let mut m = vec![
                    (text("backend_id"), text(&e.backend_id)),
                    (text("backend_kind"), text(&e.backend_kind)),
                    (text("priority"), integer(e.priority as i64)),
                ];
                if !e.accepted_trust_anchors.is_empty() {
                    m.push((
                        text("accepted_trust_anchors"),
                        Value::Array(
                            e.accepted_trust_anchors.iter().map(text).collect(),
                        ),
                    ));
                }
                if let Some(h) = &e.hints {
                    m.push((text("hints"), h.clone()));
                }
                Value::Map(m)
            })
            .collect();
        let pinned: Vec<Value> = self
            .pinned_bindings
            .iter()
            .map(|p| {
                let mut m = vec![
                    (text("name"), text(&p.name)),
                    (text("target_peer_id"), text(&p.target_peer_id)),
                ];
                if let Some(r) = &p.reason {
                    m.push((text("reason"), text(r)));
                }
                Value::Map(m)
            })
            .collect();
        let dispatch: Vec<Value> = self
            .name_format_dispatch
            .iter()
            .map(|d| {
                Value::Map(vec![
                    (
                        text("backend_kinds"),
                        Value::Array(d.backend_kinds.iter().map(text).collect()),
                    ),
                    (text("pattern"), text(&d.pattern)),
                ])
            })
            .collect();

        let mut fields: Vec<(Value, Value)> = vec![
            (text("log_cache_hits"), Value::Bool(self.log_cache_hits)),
            (
                text("resolution_log_capacity"),
                integer(self.resolution_log_capacity as i64),
            ),
        ];
        if !chain.is_empty() {
            fields.push((text("resolver_chain"), Value::Array(chain)));
        }
        if !pinned.is_empty() {
            fields.push((text("pinned_bindings"), Value::Array(pinned)));
        }
        if !dispatch.is_empty() {
            fields.push((text("name_format_dispatch"), Value::Array(dispatch)));
        }
        encode(TYPE_REGISTRY_RESOLVER_CONFIG, fields)
    }
}

fn decode_chain_entry(v: &Value) -> Option<ResolverChainEntry> {
    let m = v.as_map()?;
    Some(ResolverChainEntry {
        backend_kind: field_text(m, "backend_kind").ok()?,
        backend_id: field_text(m, "backend_id").unwrap_or_default(),
        priority: field_u64(m, "priority").unwrap_or(100) as u32,
        accepted_trust_anchors: field_array(m, "accepted_trust_anchors")
            .iter()
            .filter_map(|v| v.as_text().map(|s| s.to_string()))
            .collect(),
        hints: get_field(m, "hints")
            .filter(|v| !matches!(v, Value::Null))
            .cloned(),
    })
}

fn decode_pinned(v: &Value) -> Option<PinnedBinding> {
    let m = v.as_map()?;
    Some(PinnedBinding {
        name: field_text(m, "name").ok()?,
        target_peer_id: field_text(m, "target_peer_id").ok()?,
        reason: field_text_opt(m, "reason"),
    })
}

fn decode_dispatch_rule(v: &Value) -> Option<DispatchRule> {
    let m = v.as_map()?;
    Some(DispatchRule {
        pattern: field_text(m, "pattern").ok()?,
        backend_kinds: field_array(m, "backend_kinds")
            .iter()
            .filter_map(|v| v.as_text().map(|s| s.to_string()))
            .collect(),
    })
}

// ---------------------------------------------------------------------------
// system/registry/local-name-config (§6.4)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct LocalNameConfigData {
    pub default_pinned: bool,
    pub allow_supersede: bool,
    pub case_normalization: String,
}

impl Default for LocalNameConfigData {
    fn default() -> Self {
        Self {
            default_pinned: true,
            allow_supersede: true,
            case_normalization: "none".into(),
        }
    }
}

impl LocalNameConfigData {
    pub fn from_entity(entity: &Entity) -> Result<Self, RegistryError> {
        if entity.entity_type != TYPE_REGISTRY_LOCAL_NAME_CONFIG {
            return Err(RegistryError::Decode(format!(
                "expected {}, got {}",
                TYPE_REGISTRY_LOCAL_NAME_CONFIG, entity.entity_type
            )));
        }
        let map = decode_map(&entity.data)?;
        Ok(Self {
            default_pinned: field_bool_opt(&map, "default_pinned").unwrap_or(true),
            allow_supersede: field_bool_opt(&map, "allow_supersede").unwrap_or(true),
            case_normalization: field_text_opt(&map, "case_normalization")
                .unwrap_or_else(|| "none".into()),
        })
    }

    pub fn to_entity(&self) -> Result<Entity, RegistryError> {
        let fields = vec![
            (text("allow_supersede"), Value::Bool(self.allow_supersede)),
            (
                text("case_normalization"),
                text(&self.case_normalization),
            ),
            (text("default_pinned"), Value::Bool(self.default_pinned)),
        ];
        encode(TYPE_REGISTRY_LOCAL_NAME_CONFIG, fields)
    }
}

// ---------------------------------------------------------------------------
// system/registry/resolution-log (§11.2)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct ResolutionLogData {
    pub seq: u64,
    pub name: String,
    pub backend_id: Option<String>,
    pub status: String,
    pub reason: Option<String>,
    pub binding: Option<Hash>,
    pub attempted_at: u64,
    pub is_fallback_reresolve: bool,
}

impl ResolutionLogData {
    pub fn from_entity(entity: &Entity) -> Result<Self, RegistryError> {
        if entity.entity_type != TYPE_REGISTRY_RESOLUTION_LOG {
            return Err(RegistryError::Decode(format!(
                "expected {}, got {}",
                TYPE_REGISTRY_RESOLUTION_LOG, entity.entity_type
            )));
        }
        let map = decode_map(&entity.data)?;
        Ok(Self {
            seq: field_u64(&map, "seq")?,
            name: field_text(&map, "name")?,
            backend_id: field_text_opt(&map, "backend_id"),
            status: field_text(&map, "status")?,
            reason: field_text_opt(&map, "reason"),
            binding: field_hash_opt(&map, "binding")?,
            attempted_at: field_u64(&map, "attempted_at")?,
            is_fallback_reresolve: field_bool_opt(&map, "is_fallback_reresolve")
                .unwrap_or(false),
        })
    }

    pub fn to_entity(&self) -> Result<Entity, RegistryError> {
        let mut fields: Vec<(Value, Value)> = vec![
            (text("attempted_at"), integer(self.attempted_at as i64)),
            (
                text("is_fallback_reresolve"),
                Value::Bool(self.is_fallback_reresolve),
            ),
            (text("name"), text(&self.name)),
            (text("seq"), integer(self.seq as i64)),
            (text("status"), text(&self.status)),
        ];
        if let Some(b) = &self.backend_id {
            fields.push((text("backend_id"), text(b)));
        }
        if let Some(b) = &self.binding {
            fields.push((text("binding"), bytes(b)));
        }
        if let Some(r) = &self.reason {
            fields.push((text("reason"), text(r)));
        }
        encode(TYPE_REGISTRY_RESOLUTION_LOG, fields)
    }
}

// ---------------------------------------------------------------------------
// ResolutionResult (§2.1) — handler return payload (not a stored entity type)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct ResolutionResult {
    pub status: String,
    pub binding: Option<Hash>,
    pub peer_id: Option<String>,
    pub transports: Vec<Value>,
    pub attestations: Vec<Hash>,
    pub trust_anchor: Option<String>,
    pub ttl: Option<u64>,
    pub neg_ttl: Option<u64>,
    pub backend_id: Option<String>,
}

impl ResolutionResult {
    pub fn not_found(neg_ttl: Option<u64>) -> Self {
        Self {
            status: STATUS_NOT_FOUND.into(),
            binding: None,
            peer_id: None,
            transports: Vec::new(),
            attestations: Vec::new(),
            trust_anchor: None,
            ttl: None,
            neg_ttl,
            backend_id: None,
        }
    }

    pub fn chain_exhausted() -> Self {
        Self {
            status: STATUS_CHAIN_EXHAUSTED.into(),
            binding: None,
            peer_id: None,
            transports: Vec::new(),
            attestations: Vec::new(),
            trust_anchor: None,
            ttl: None,
            neg_ttl: None,
            backend_id: None,
        }
    }

    pub fn is_resolved(&self) -> bool {
        self.status == STATUS_RESOLVED
    }

    /// Encode the flat field map (§2.1). Carried directly under `data` of the
    /// `system/registry/resolution-result` entity — see [`Self::to_entity`].
    pub fn to_result_value(&self) -> Value {
        let mut fields: Vec<(Value, Value)> = vec![
            (text("status"), text(&self.status)),
            (
                text("transports"),
                Value::Array(self.transports.clone()),
            ),
            (
                text("attestations"),
                Value::Array(self.attestations.iter().map(bytes).collect()),
            ),
        ];
        if let Some(b) = &self.binding {
            fields.push((text("binding"), bytes(b)));
        }
        if let Some(p) = &self.peer_id {
            fields.push((text("peer_id"), text(p)));
        }
        if let Some(t) = &self.trust_anchor {
            fields.push((text("trust_anchor"), text(t)));
        }
        if let Some(t) = self.ttl {
            fields.push((text("ttl"), integer(t as i64)));
        }
        if let Some(t) = self.neg_ttl {
            fields.push((text("neg_ttl"), integer(t as i64)));
        }
        if let Some(b) = &self.backend_id {
            fields.push((text("backend_id"), text(b)));
        }
        Value::Map(fields)
    }

    /// Build the on-wire `:resolve` return entity (§2.1, Ruling-3): entity type
    /// `system/registry/resolution-result` with the fields carried **flat**
    /// under `data` — NOT wrapped under `system/protocol/status`.
    pub fn to_entity(&self) -> Entity {
        Entity::new(
            crate::TYPE_REGISTRY_RESOLUTION_RESULT,
            to_ecf(&self.to_result_value()),
        )
        .expect("resolution-result entity")
    }
}

// ---------------------------------------------------------------------------
// Name normalization + path safety (§6.3)
// ---------------------------------------------------------------------------

/// Apply NFC normalization + optional case-fold (per `local-name-config`). The
/// normalized form is the storage key; `:bind` and `:resolve` MUST agree.
pub fn normalize_name(name: &str, case_normalization: &str) -> String {
    let nfc: String = name.nfc().collect();
    if case_normalization == "lower" {
        nfc.to_lowercase()
    } else {
        nfc
    }
}

/// Validate a local-name against §6.3 name-path safety. Returns `Err` with the
/// `bind_invalid_name` reason string when the name is unsafe.
///
/// MUST NOT contain `/` (path ambiguity) or control chars U+0000–U+0020 / U+007F
/// (C0 + DEL). MUST already be NFC (callers normalize first; an empty name is
/// also rejected).
pub fn validate_name_safety(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("name must not be empty".into());
    }
    if name.contains('/') {
        return Err("name must not contain '/'".into());
    }
    for c in name.chars() {
        if c <= '\u{20}' || c == '\u{7f}' {
            return Err(format!(
                "name must not contain control char U+{:04X}",
                c as u32
            ));
        }
    }
    // NFC idempotence check — reject names that are not already NFC.
    let nfc: String = name.nfc().collect();
    if nfc != name {
        return Err("name must be Unicode-NFC normalized".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CBOR helpers
// ---------------------------------------------------------------------------

fn bytes(h: &Hash) -> Value {
    Value::Bytes(h.to_bytes().to_vec())
}

fn encode(entity_type: &str, fields: Vec<(Value, Value)>) -> Result<Entity, RegistryError> {
    let data = to_ecf(&Value::Map(fields));
    Entity::new(entity_type, data).map_err(|e| RegistryError::Encode(e.to_string()))
}

pub(crate) fn decode_map(data: &[u8]) -> Result<Vec<(Value, Value)>, RegistryError> {
    let value: Value =
        ciborium::from_reader(data).map_err(|e| RegistryError::Decode(e.to_string()))?;
    value
        .into_map()
        .map_err(|_| RegistryError::Decode("expected CBOR map".into()))
}

pub(crate) fn get_field<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find_map(|(k, v)| if k.as_text() == Some(key) { Some(v) } else { None })
}

fn field_text(map: &[(Value, Value)], key: &str) -> Result<String, RegistryError> {
    get_field(map, key)
        .and_then(|v| v.as_text())
        .map(|s| s.to_string())
        .ok_or_else(|| RegistryError::Decode(format!("missing/invalid text field {}", key)))
}

fn field_text_opt(map: &[(Value, Value)], key: &str) -> Option<String> {
    get_field(map, key).and_then(|v| v.as_text()).map(|s| s.to_string())
}

fn field_u64(map: &[(Value, Value)], key: &str) -> Result<u64, RegistryError> {
    get_field(map, key)
        .and_then(|v| v.as_integer())
        .and_then(|i| u64::try_from(i).ok())
        .ok_or_else(|| RegistryError::Decode(format!("missing/invalid uint field {}", key)))
}

fn field_u64_opt(map: &[(Value, Value)], key: &str) -> Result<Option<u64>, RegistryError> {
    match get_field(map, key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_integer()
            .and_then(|i| u64::try_from(i).ok())
            .map(Some)
            .ok_or_else(|| RegistryError::Decode(format!("invalid uint field {}", key))),
    }
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

fn field_bytes(map: &[(Value, Value)], key: &str) -> Result<Vec<u8>, RegistryError> {
    get_field(map, key)
        .and_then(|v| v.as_bytes())
        .map(|b| b.to_vec())
        .ok_or_else(|| RegistryError::Decode(format!("missing/invalid byte field {}", key)))
}

fn field_hash(map: &[(Value, Value)], key: &str) -> Result<Hash, RegistryError> {
    let v = get_field(map, key)
        .ok_or_else(|| RegistryError::Decode(format!("missing {} field", key)))?;
    let b = v
        .as_bytes()
        .ok_or_else(|| RegistryError::Decode(format!("{} must be byte string", key)))?;
    Hash::from_bytes(b).map_err(|e| RegistryError::Decode(e.to_string()))
}

fn field_hash_opt(map: &[(Value, Value)], key: &str) -> Result<Option<Hash>, RegistryError> {
    match get_field(map, key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => {
            let b = v
                .as_bytes()
                .ok_or_else(|| RegistryError::Decode(format!("{} must be byte string", key)))?;
            Ok(Some(
                Hash::from_bytes(b).map_err(|e| RegistryError::Decode(e.to_string()))?,
            ))
        }
    }
}
