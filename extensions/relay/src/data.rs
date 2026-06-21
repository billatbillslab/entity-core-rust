//! EXTENSION-RELAY v1.0 entity + result codecs (§3, §4.1, §4.2).
//!
//! ECF-deterministic CBOR (`to_ecf` canonicalizes key order, so field
//! insertion order below is for readability only). Conventions per §3.0 +
//! the cohort discipline pins:
//!
//! - **`peer_id` fields** (`destination`, `next_hop`, `put_by`) are Base58
//!   peer-id strings (V7 §1.5), **never** a bare `system/hash`. Routing keyed
//!   on the wrong representation fails silently — the REGISTRY/DISCOVERY trap.
//! - **`envelope_inner`** is the content-addressed pointer to the opaque inner
//!   envelope — a bare 33-byte `system/hash` byte string (§3.0). The spec
//!   writes it under a `refs:` heading; this codebase's `Entity` is `{type,
//!   data, content_hash}` with the hash taken over `{data, type}` only, so a
//!   field must live in `data` to be part of the content hash. `envelope_inner`
//!   is therefore encoded as a `data` field (bare hash). If Go places it in a
//!   separate top-level `refs` map the content hashes diverge — flagged in
//!   `docs/SPEC-AMBIGUITIES.md` as a cohort-convergence pin.
//! - **No `refs: { signature }` blocks** — all relay entities use V7 §5.2
//!   target-matching; the signature is reachable at
//!   `system/signature/{hex(content_hash)}`.
//! - **Timestamps** are integer milliseconds since the Unix epoch.
//! - **Optional fields** are encoded **absent** (key not present) when `None`,
//!   per the project "optional SHOULD be absent" rule; decode tolerates both
//!   absent and explicit `null`.
//! - **Result types are flat** (`forward-result` / `put-result` /
//!   `poll-result`), their own pinned entity types — never wrapped in
//!   `system/protocol/status` (handoff §3).

use entity_ecf::{integer, text, to_ecf, Value};
use entity_entity::Entity;
use entity_hash::Hash;
use entity_types::{
    TYPE_PEER_INBOX_RELAY, TYPE_RELAY_ADVERTISE, TYPE_RELAY_FORWARD_REQUEST,
    TYPE_RELAY_FORWARD_RESULT, TYPE_RELAY_POLL_REQUEST, TYPE_RELAY_POLL_RESULT, TYPE_RELAY_PUT_RESULT,
    TYPE_RELAY_STORE_ENTRY,
};

use crate::RelayError;

// ---------------------------------------------------------------------------
// §3.1 — Mode F forward-request
// ---------------------------------------------------------------------------

/// Mode F routing envelope (§3.1). Decoded by the relay to read its outer
/// routing fields; the carried inner envelope (`envelope_inner`) stays opaque.
#[derive(Debug, Clone, PartialEq)]
pub struct ForwardRequest {
    /// Terminal recipient — Base58 peer-id (§3.0).
    pub destination: String,
    /// **v1.1 source route** (§3.1) — the remaining relay hops in order, ending
    /// at `destination`; the originator's dictated path. `None`/empty → single-hop
    /// (use `next_hop`) or table-routed (§3.1.1). **omitempty:** absent when
    /// `None`/empty, so a v1.0 single-hop request encodes byte-identically.
    pub route: Option<Vec<String>>,
    /// Single-hop shorthand / route-table output — Base58 peer-id (§3.1). When
    /// `route` is present and non-empty, `next_hop` is advisory and MUST equal
    /// `route[0]` if set (else `invalid_request`/400 pre-dispatch, §3.1.1).
    pub next_hop: Option<String>,
    /// Relay-transport hop budget; decremented per hop, reject at 0 (§3.1).
    pub ttl_hops: u32,
    /// Content-addressed pointer to the opaque inner envelope (§3.1, bare hash).
    pub envelope_inner: Hash,
}

impl ForwardRequest {
    pub fn from_entity(entity: &Entity) -> Result<Self, RelayError> {
        expect_type(entity, TYPE_RELAY_FORWARD_REQUEST)?;
        Self::from_params(&entity.data)
    }

    /// Decode from raw params CBOR (the `:forward` request IS a forward-request,
    /// §4.2 — it arrives as the EXECUTE params, not always as a stored entity).
    pub fn from_params(data: &[u8]) -> Result<Self, RelayError> {
        let map = decode_map(data)?;
        // omitempty: an absent `route` is the v1.0 single-hop shape; an empty
        // array decodes to `None` too so it behaves identically to absent.
        let route = field_text_array_opt(&map, "route").filter(|r| !r.is_empty());
        Ok(Self {
            destination: field_text(&map, "destination")?,
            route,
            next_hop: field_text_opt(&map, "next_hop"),
            ttl_hops: field_u64(&map, "ttl_hops")? as u32,
            envelope_inner: field_hash(&map, "envelope_inner")?,
        })
    }

    pub fn to_entity(&self) -> Result<Entity, RelayError> {
        encode(TYPE_RELAY_FORWARD_REQUEST, self.to_fields())
    }

    pub fn to_fields(&self) -> Vec<(Value, Value)> {
        let mut fields = vec![
            (text("destination"), text(&self.destination)),
            (text("envelope_inner"), bytes(&self.envelope_inner)),
            (text("ttl_hops"), integer(self.ttl_hops as i64)),
        ];
        if let Some(nh) = &self.next_hop {
            fields.push((text("next_hop"), text(nh)));
        }
        // omitempty: drop `route` entirely when None/empty so a single-hop
        // request stays byte-identical to v1.0 (§3.1).
        if let Some(route) = self.route.as_ref().filter(|r| !r.is_empty()) {
            fields.push((text("route"), Value::Array(route.iter().map(text).collect())));
        }
        fields
    }
}

// ---------------------------------------------------------------------------
// §3.2 — Mode S store-entry
// ---------------------------------------------------------------------------

/// Mode S stored entry (§3.2). `put_by` is **placement-identity** (verified ==
/// authenticated caller on `:put`, §3.2), NOT authorship — authorship is the
/// inner envelope's signature, which the relay cannot read.
#[derive(Debug, Clone, PartialEq)]
pub struct StoreEntry {
    /// Where the receiver polls (§3.2, path).
    pub namespace: String,
    /// ms-since-epoch; standard cap-style expiry; `None` = no expiry (§3.2).
    pub expires_at: Option<i64>,
    /// Who placed this entry — Base58 peer-id (§3.0/§3.2).
    pub put_by: String,
    /// Content-addressed pointer to the opaque inner envelope (§3.2, bare hash).
    pub envelope_inner: Hash,
}

impl StoreEntry {
    pub fn from_entity(entity: &Entity) -> Result<Self, RelayError> {
        expect_type(entity, TYPE_RELAY_STORE_ENTRY)?;
        Self::from_params(&entity.data)
    }

    pub fn from_params(data: &[u8]) -> Result<Self, RelayError> {
        let map = decode_map(data)?;
        Ok(Self {
            namespace: field_text(&map, "namespace")?,
            expires_at: field_i64_opt(&map, "expires_at"),
            put_by: field_text(&map, "put_by")?,
            envelope_inner: field_hash(&map, "envelope_inner")?,
        })
    }

    pub fn to_entity(&self) -> Result<Entity, RelayError> {
        encode(TYPE_RELAY_STORE_ENTRY, self.to_fields())
    }

    pub fn to_fields(&self) -> Vec<(Value, Value)> {
        let mut fields = vec![
            (text("envelope_inner"), bytes(&self.envelope_inner)),
            (text("namespace"), text(&self.namespace)),
            (text("put_by"), text(&self.put_by)),
        ];
        if let Some(e) = self.expires_at {
            fields.push((text("expires_at"), integer(e)));
        }
        fields
    }
}

// ---------------------------------------------------------------------------
// §4.1 — advertise entity
// ---------------------------------------------------------------------------

/// Advertised per-mode limits (§4.1). All optional; absent = unbounded/off.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AdvertiseLimits {
    pub max_envelope_size: Option<u64>,
    pub max_storage_bytes: Option<u64>,
    pub forward_rate_limit: Option<u32>,
}

impl AdvertiseLimits {
    fn to_value(&self) -> Value {
        let mut fields: Vec<(Value, Value)> = Vec::new();
        if let Some(v) = self.forward_rate_limit {
            fields.push((text("forward_rate_limit"), integer(v as i64)));
        }
        if let Some(v) = self.max_envelope_size {
            fields.push((text("max_envelope_size"), integer(v as i64)));
        }
        if let Some(v) = self.max_storage_bytes {
            fields.push((text("max_storage_bytes"), integer(v as i64)));
        }
        Value::Map(fields)
    }

    fn from_value(v: &Value) -> Self {
        let map = v.as_map().cloned().unwrap_or_default();
        Self {
            max_envelope_size: field_u64_opt(&map, "max_envelope_size"),
            max_storage_bytes: field_u64_opt(&map, "max_storage_bytes"),
            forward_rate_limit: field_u64_opt(&map, "forward_rate_limit").map(|v| v as u32),
        }
    }
}

/// The relay's published capability announcement (§4.1). Signed by
/// `relay_peer_id` per V7 §5.2 (no `refs:` block); consumers fetch it to see
/// what modes/limits/caps the relay offers.
#[derive(Debug, Clone, PartialEq)]
pub struct AdvertiseData {
    /// v1 mode ids — `"F"` / `"S"` (§4.1).
    pub modes: Vec<String>,
    /// Dial-able endpoints per NETWORK §6.5 (opaque to this codec, §4.1).
    pub endpoints: Vec<Value>,
    /// Advertised limits (§4.1).
    pub limits: AdvertiseLimits,
    /// Cap paths a consumer needs to use this relay (§4.1).
    pub caps_required: Vec<String>,
    /// ms-since-epoch; `None` = no expiry (§4.1).
    pub expires_at: Option<i64>,
}

impl AdvertiseData {
    pub fn from_entity(entity: &Entity) -> Result<Self, RelayError> {
        expect_type(entity, TYPE_RELAY_ADVERTISE)?;
        let map = decode_map(&entity.data)?;
        Ok(Self {
            modes: field_text_array(&map, "modes"),
            endpoints: field_array(&map, "endpoints"),
            limits: get_field(&map, "limits")
                .map(AdvertiseLimits::from_value)
                .unwrap_or_default(),
            caps_required: field_text_array(&map, "caps_required"),
            expires_at: field_i64_opt(&map, "expires_at"),
        })
    }

    pub fn to_entity(&self) -> Result<Entity, RelayError> {
        let mut fields: Vec<(Value, Value)> = vec![
            (
                text("caps_required"),
                Value::Array(self.caps_required.iter().map(text).collect()),
            ),
            (text("endpoints"), Value::Array(self.endpoints.clone())),
            (text("limits"), self.limits.to_value()),
            (
                text("modes"),
                Value::Array(self.modes.iter().map(text).collect()),
            ),
        ];
        if let Some(e) = self.expires_at {
            fields.push((text("expires_at"), integer(e)));
        }
        encode(TYPE_RELAY_ADVERTISE, fields)
    }
}

// ---------------------------------------------------------------------------
// §3.5 — system/peer/inbox-relay (the MX-equivalent declaration)
// ---------------------------------------------------------------------------

/// One declared inbox-relay (an MX record line). `priority` is MX-style —
/// **lower = preferred**; backups carry higher numbers (§3.5).
#[derive(Debug, Clone, PartialEq)]
pub struct InboxRelayEntry {
    /// The relay peer holding this peer's mail — Base58 peer-id (§3.5).
    pub relay: String,
    /// Where to put it (default convention: the declaring peer's own peer_id,
    /// §6.2.1) (§3.5, path).
    pub namespace: String,
    /// MX-priority analog; lower = preferred (§3.5).
    pub priority: u32,
}

impl InboxRelayEntry {
    fn to_value(&self) -> Value {
        // ECF canonicalizes; written length-first for readability (relay,
        // priority, namespace = 5, 8, 9).
        Value::Map(vec![
            (text("relay"), text(&self.relay)),
            (text("priority"), integer(self.priority as i64)),
            (text("namespace"), text(&self.namespace)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, RelayError> {
        let map = v
            .as_map()
            .ok_or_else(|| RelayError::Decode("inbox-relay entry: expected map".into()))?;
        Ok(Self {
            relay: field_text(map, "relay")?,
            namespace: field_text(map, "namespace")?,
            priority: field_u64(map, "priority")? as u32,
        })
    }
}

/// `system/peer/inbox-relay` (§3.5) — a peer's signed, self-certifying
/// declaration of where its mail should be stored when it is unreachable.
/// Authored + signed by the declaring peer (V7 §5.2; no `refs:` block); served
/// always-on by REGISTRY. Superseded by a newer signed entity.
#[derive(Debug, Clone, PartialEq)]
pub struct InboxRelayData {
    /// One or more relays, in any order; the resolver sorts by priority (§3.5).
    pub relays: Vec<InboxRelayEntry>,
    /// ms-since-epoch; `None` = until superseded (§3.5).
    pub expires_at: Option<i64>,
}

impl InboxRelayData {
    pub fn from_entity(entity: &Entity) -> Result<Self, RelayError> {
        expect_type(entity, TYPE_PEER_INBOX_RELAY)?;
        let map = decode_map(&entity.data)?;
        let relays = field_array(&map, "relays")
            .iter()
            .map(InboxRelayEntry::from_value)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            relays,
            expires_at: field_i64_opt(&map, "expires_at"),
        })
    }

    pub fn to_entity(&self) -> Result<Entity, RelayError> {
        let mut fields: Vec<(Value, Value)> = vec![(
            text("relays"),
            Value::Array(self.relays.iter().map(InboxRelayEntry::to_value).collect()),
        )];
        if let Some(e) = self.expires_at {
            fields.push((text("expires_at"), integer(e)));
        }
        encode(TYPE_PEER_INBOX_RELAY, fields)
    }

    /// Resolve the namespace this relay should store at for `destination`, per
    /// the §3.5 resolution rule from the *relay's* side: among the declared
    /// entries that target `this_relay`, the highest-priority (lowest number)
    /// wins. Returns `None` when no entry targets this relay (caller then
    /// considers the default convention or `no_inbox_relay`).
    pub fn namespace_for_relay(&self, this_relay: &str) -> Option<String> {
        self.relays
            .iter()
            .filter(|e| e.relay == this_relay)
            .min_by_key(|e| e.priority)
            .map(|e| e.namespace.clone())
    }
}

// ---------------------------------------------------------------------------
// §4.2 — flat result types
// ---------------------------------------------------------------------------

/// `system/relay/forward-result` (§4.2). Flat; the relay-level result is only
/// the immediate ack — any async response rides inside the inner envelope.
#[derive(Debug, Clone, PartialEq)]
pub struct ForwardResult {
    /// `forwarded` | `queued-fallback` | `rejected` (§4.2).
    pub status: String,
    /// Hop actually used, if forwarded (§4.2).
    pub next_hop: Option<String>,
    /// Namespace, if `queued-fallback` (§6.2.1).
    pub stored_at: Option<String>,
}

impl ForwardResult {
    pub fn to_entity(&self) -> Result<Entity, RelayError> {
        let mut fields = vec![(text("status"), text(&self.status))];
        if let Some(nh) = &self.next_hop {
            fields.push((text("next_hop"), text(nh)));
        }
        if let Some(sa) = &self.stored_at {
            fields.push((text("stored_at"), text(sa)));
        }
        encode(TYPE_RELAY_FORWARD_RESULT, fields)
    }
}

/// `system/relay/put-result` (§4.2).
#[derive(Debug, Clone, PartialEq)]
pub struct PutResult {
    pub stored_at: String,
    pub entry_hash: Hash,
    pub expires_at: Option<i64>,
}

impl PutResult {
    pub fn to_entity(&self) -> Result<Entity, RelayError> {
        let mut fields = vec![
            (text("entry_hash"), bytes(&self.entry_hash)),
            (text("status"), text("stored")),
            (text("stored_at"), text(&self.stored_at)),
        ];
        if let Some(e) = self.expires_at {
            fields.push((text("expires_at"), integer(e)));
        }
        encode(TYPE_RELAY_PUT_RESULT, fields)
    }
}

/// `system/relay/poll-request` (§4.2). The poll cursor (`since`) is opaque and
/// relay-owned; absent = from start. Encoded as an 8-byte big-endian seq bstr
/// (the relay's own format; cross-impl tests do not byte-compare cursors).
#[derive(Debug, Clone, PartialEq)]
pub struct PollRequest {
    pub namespace: String,
    pub since: Option<Vec<u8>>,
    pub limit: Option<u64>,
}

impl PollRequest {
    pub fn from_params(data: &[u8]) -> Result<Self, RelayError> {
        let map = decode_map(data)?;
        Ok(Self {
            namespace: field_text(&map, "namespace")?,
            since: get_field(&map, "since").and_then(|v| v.as_bytes()).map(|b| b.to_vec()),
            limit: field_u64_opt(&map, "limit"),
        })
    }

    pub fn to_entity(&self) -> Result<Entity, RelayError> {
        let mut fields = vec![(text("namespace"), text(&self.namespace))];
        if let Some(l) = self.limit {
            fields.push((text("limit"), integer(l as i64)));
        }
        if let Some(s) = &self.since {
            fields.push((text("since"), Value::Bytes(s.clone())));
        }
        encode(TYPE_RELAY_POLL_REQUEST, fields)
    }
}

/// `system/relay/poll-result` (§4.2). `entries` are store-entry **hashes**
/// (pointers), not inline bytes — the receiver does a content get per entry.
#[derive(Debug, Clone, PartialEq)]
pub struct PollResult {
    pub entries: Vec<Hash>,
    /// Opaque relay-owned cursor (8-byte big-endian seq); pass back as `since`
    /// to continue (§4.2).
    pub cursor: Vec<u8>,
    pub has_more: bool,
}

impl PollResult {
    /// Build from a store cursor seq (encodes it 8-byte big-endian).
    pub fn new(entries: Vec<Hash>, cursor_seq: u64, has_more: bool) -> Self {
        Self {
            entries,
            cursor: cursor_seq.to_be_bytes().to_vec(),
            has_more,
        }
    }

    pub fn to_entity(&self) -> Result<Entity, RelayError> {
        let fields = vec![
            (text("cursor"), Value::Bytes(self.cursor.clone())),
            (
                text("entries"),
                Value::Array(self.entries.iter().map(bytes).collect()),
            ),
            (text("has_more"), Value::Bool(self.has_more)),
        ];
        encode(TYPE_RELAY_POLL_RESULT, fields)
    }
}

/// Parse an 8-byte big-endian cursor seq; tolerant of shorter/empty (→ 0) and
/// over-length (uses the low 8 bytes). The cursor is the relay's own, so a
/// malformed value safely restarts from the beginning.
pub fn parse_cursor(since: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let n = since.len().min(8);
    buf[8 - n..].copy_from_slice(&since[since.len() - n..]);
    u64::from_be_bytes(buf)
}

// ---------------------------------------------------------------------------
// CBOR helpers (shape mirrors extensions/discovery/src/data.rs)
// ---------------------------------------------------------------------------

fn bytes(h: &Hash) -> Value {
    Value::Bytes(h.to_bytes().to_vec())
}

fn expect_type(entity: &Entity, want: &str) -> Result<(), RelayError> {
    if entity.entity_type != want {
        return Err(RelayError::Decode(format!(
            "expected {}, got {}",
            want, entity.entity_type
        )));
    }
    Ok(())
}

fn encode(entity_type: &str, fields: Vec<(Value, Value)>) -> Result<Entity, RelayError> {
    let data = to_ecf(&Value::Map(fields));
    Entity::new(entity_type, data).map_err(|e| RelayError::Encode(e.to_string()))
}

fn decode_map(data: &[u8]) -> Result<Vec<(Value, Value)>, RelayError> {
    let value: Value = ciborium::from_reader(data).map_err(|e| RelayError::Decode(e.to_string()))?;
    value
        .into_map()
        .map_err(|_| RelayError::Decode("expected CBOR map".into()))
}

fn get_field<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find_map(|(k, v)| if k.as_text() == Some(key) { Some(v) } else { None })
}

fn field_text(map: &[(Value, Value)], key: &str) -> Result<String, RelayError> {
    get_field(map, key)
        .and_then(|v| v.as_text())
        .map(|s| s.to_string())
        .ok_or_else(|| RelayError::Decode(format!("missing/invalid text field {}", key)))
}

fn field_text_opt(map: &[(Value, Value)], key: &str) -> Option<String> {
    get_field(map, key).and_then(|v| v.as_text()).map(|s| s.to_string())
}

fn field_u64(map: &[(Value, Value)], key: &str) -> Result<u64, RelayError> {
    get_field(map, key)
        .and_then(|v| v.as_integer())
        .and_then(|i| u64::try_from(i).ok())
        .ok_or_else(|| RelayError::Decode(format!("missing/invalid uint field {}", key)))
}

fn field_u64_opt(map: &[(Value, Value)], key: &str) -> Option<u64> {
    get_field(map, key)
        .and_then(|v| v.as_integer())
        .and_then(|i| u64::try_from(i).ok())
}

fn field_i64_opt(map: &[(Value, Value)], key: &str) -> Option<i64> {
    get_field(map, key)
        .and_then(|v| v.as_integer())
        .and_then(|i| i64::try_from(i).ok())
}

fn field_array(map: &[(Value, Value)], key: &str) -> Vec<Value> {
    get_field(map, key)
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

fn field_text_array(map: &[(Value, Value)], key: &str) -> Vec<String> {
    field_array(map, key)
        .iter()
        .filter_map(|v| v.as_text().map(|s| s.to_string()))
        .collect()
}

/// Like [`field_text_array`] but distinguishes an absent key (`None`) from a
/// present-but-empty array (`Some(vec![])`) — needed so `route` omitempty is
/// faithful: absent ⇒ single-hop, present ⇒ source-routed.
fn field_text_array_opt(map: &[(Value, Value)], key: &str) -> Option<Vec<String>> {
    get_field(map, key).and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_text().map(|s| s.to_string()))
            .collect()
    })
}

fn field_hash(map: &[(Value, Value)], key: &str) -> Result<Hash, RelayError> {
    let v = get_field(map, key)
        .ok_or_else(|| RelayError::Decode(format!("missing {} field", key)))?;
    let b = v
        .as_bytes()
        .ok_or_else(|| RelayError::Decode(format!("{} must be byte string", key)))?;
    Hash::from_bytes(b).map_err(|e| RelayError::Decode(e.to_string()))
}
