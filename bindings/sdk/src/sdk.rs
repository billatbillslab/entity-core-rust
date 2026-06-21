//! EntitySDK — multi-peer container and PeerContext per-peer handle.
//!
//! Provides the developer-facing API for entity-native applications.
//! EntitySDK manages multiple PeerContext instances, each wrapping an
//! entity-core-rust Peer with identity, tree, and handler registry.
//!
//! All tree operations are synchronous (Level 0 direct store access)
//! for render-loop compatibility. The implementation can migrate to
//! protocol-correct routing through execute() (Level 1) later without
//! changing the API surface.
//!
//! Peers are defined by configuration, not type labels. A peer's
//! identity comes from its handlers, capability grants, tree contents,
//! and Ed25519 keypair. See GUIDE-PEER-CONCERNS-AND-NAMESPACES.md
//! for the concern matrix and archetype patterns.
//!
//! See `docs/architecture/specs/ENTITY-SDK-API.md` for the full design.

// SDK modules define public API surface for external consumers. Many
// items are intentionally unused by this binary but remain part of the
// SDK contract — don't prune them based on local usage alone.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use entity_crypto::Keypair;
use entity_entity::Entity;
use entity_hash::Hash;
use entity_peer::{DispatchEvent, Peer, PeerBuilder, PeerConfig, PeerShared, WireEvent};
// Re-export tree change types for subscribers.
pub use entity_store::{TreeChangeEvent, ChangeType, LocationEntry};
// Re-export inspectability event types so SDK consumers don't reach
// into `entity_peer` (GUIDE-INSPECTABILITY v1.2 §2.1).
pub use entity_peer::{DispatchEvent as InspectDispatchEvent, WireEvent as InspectWireEvent, WireDirection as InspectWireDirection};

/// Entry from a dispatched tree listing (L1).
///
/// Represents one immediate child in a tree listing result.
#[derive(Debug, Clone)]
pub struct ListingEntry {
    /// Child name (relative to the listing prefix).
    pub name: String,
    /// Content hash if this child has a direct entity binding.
    pub hash: Option<Hash>,
    /// Whether this child has nested children.
    pub has_children: bool,
}

/// Type alias for the wake function stored in EntitySDK.
type WakeFn = Arc<Mutex<Option<Arc<dyn Fn() + Send + Sync>>>>;

/// Discovered handler information from a peer's tree.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct HandlerInfo {
    /// The handler's URI pattern (e.g., "system/tree").
    pub pattern: String,
    /// Human-readable name.
    pub name: String,
    /// Available operations.
    pub operations: Vec<String>,
}

impl HandlerInfo {
    /// Parse a handler interface entity into HandlerInfo.
    fn from_entity(entity: &Entity) -> Option<Self> {
        let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).ok()?;
        let map = match &value {
            ciborium::Value::Map(m) => m,
            _ => return None,
        };

        let mut name = String::new();
        let mut pattern = String::new();
        let mut operations = Vec::new();

        for (k, v) in map {
            let key = match k {
                ciborium::Value::Text(s) => s.as_str(),
                _ => continue,
            };
            match key {
                "name" => {
                    if let ciborium::Value::Text(s) = v {
                        name = s.clone();
                    }
                }
                "pattern" => {
                    if let ciborium::Value::Text(s) = v {
                        pattern = s.clone();
                    }
                }
                "operations" => {
                    if let ciborium::Value::Map(ops) = v {
                        for (op_key, _) in ops {
                            if let ciborium::Value::Text(op_name) = op_key {
                                operations.push(op_name.clone());
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        if pattern.is_empty() {
            return None;
        }

        operations.sort();
        Some(HandlerInfo { pattern, name, operations })
    }
}

/// Discovered type information from a peer's tree (SDK-OPERATIONS §9.2).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TypeInfo {
    /// The type's full name / path (e.g., "system/handler", "primitive/string").
    pub type_path: String,
    /// Field specifications for this type, sorted by field name.
    pub fields: Vec<FieldInfo>,
}

/// One field within a type definition (SDK-OPERATIONS §9.2).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FieldInfo {
    pub name: String,
    /// Reference to another type (e.g., "primitive/string"). For complex
    /// shapes (`array_of`, `map_of`, `union_of`) the SDK synthesizes a
    /// readable form: `array<elem_type>`, `map<value_type>`, `union<N>`.
    /// Empty if the underlying field-spec carried no usable type info.
    pub type_ref: String,
    pub optional: bool,
}

impl TypeInfo {
    /// Parse a `system/type` entity into TypeInfo.
    fn from_entity(entity: &Entity) -> Option<Self> {
        let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).ok()?;
        let map = match &value {
            ciborium::Value::Map(m) => m,
            _ => return None,
        };

        let mut name = String::new();
        let mut fields_raw: Option<&Vec<(ciborium::Value, ciborium::Value)>> = None;

        for (k, v) in map {
            let key = match k {
                ciborium::Value::Text(s) => s.as_str(),
                _ => continue,
            };
            match key {
                "name" => {
                    if let ciborium::Value::Text(s) = v {
                        name = s.clone();
                    }
                }
                "fields" => {
                    if let ciborium::Value::Map(m) = v {
                        fields_raw = Some(m);
                    }
                }
                _ => {}
            }
        }

        if name.is_empty() {
            return None;
        }

        let mut fields = Vec::new();
        if let Some(fmap) = fields_raw {
            for (fk, fv) in fmap {
                let field_name = match fk {
                    ciborium::Value::Text(s) => s.clone(),
                    _ => continue,
                };
                let spec_map = match fv {
                    ciborium::Value::Map(m) => m,
                    _ => continue,
                };
                fields.push(FieldInfo::from_spec_map(field_name, spec_map));
            }
        }

        fields.sort_by(|a, b| a.name.cmp(&b.name));
        Some(TypeInfo { type_path: name, fields })
    }
}

impl FieldInfo {
    fn from_spec_map(
        name: String,
        spec: &Vec<(ciborium::Value, ciborium::Value)>,
    ) -> Self {
        let mut type_ref = String::new();
        let mut optional = false;
        let mut array_inner: Option<String> = None;
        let mut map_inner: Option<String> = None;
        let mut union_count = 0usize;

        for (k, v) in spec {
            let key = match k {
                ciborium::Value::Text(s) => s.as_str(),
                _ => continue,
            };
            match key {
                "type_ref" => {
                    if let ciborium::Value::Text(s) = v {
                        type_ref = s.clone();
                    }
                }
                "optional" => {
                    if let ciborium::Value::Bool(b) = v {
                        optional = *b;
                    }
                }
                "array_of" => {
                    if let ciborium::Value::Map(inner) = v {
                        array_inner = inner_type_ref(inner);
                    }
                }
                "map_of" => {
                    if let ciborium::Value::Map(inner) = v {
                        map_inner = inner_type_ref(inner);
                    }
                }
                "union_of" => {
                    if let ciborium::Value::Array(arr) = v {
                        union_count = arr.len();
                    }
                }
                _ => {}
            }
        }

        if type_ref.is_empty() {
            if let Some(inner) = array_inner {
                type_ref = format!("array<{}>", inner);
            } else if let Some(inner) = map_inner {
                type_ref = format!("map<{}>", inner);
            } else if union_count > 0 {
                type_ref = format!("union<{}>", union_count);
            }
        }

        FieldInfo { name, type_ref, optional }
    }
}

fn inner_type_ref(spec: &Vec<(ciborium::Value, ciborium::Value)>) -> Option<String> {
    for (k, v) in spec {
        if let (ciborium::Value::Text(key), ciborium::Value::Text(val)) = (k, v) {
            if key == "type_ref" {
                return Some(val.clone());
            }
        }
    }
    None
}

/// Result of an L1 query (SDK-OPERATIONS §5.1).
///
/// Wraps the spec's `[Result]` return with the pagination metadata the
/// `system/query` handler also publishes (`has_more`, `total`, optional
/// `cursor`). The spec's `Result` shape is exposed as [`QueryMatch`].
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct QueryResults {
    /// Matched entries on this page, sorted ascending by path.
    pub matches: Vec<QueryMatch>,
    /// True when more pages remain — pass `cursor` to the next call.
    pub has_more: bool,
    /// Total matching entries across all pages.
    pub total: u64,
    /// Continuation cursor when `has_more` is true.
    pub cursor: Option<String>,
}

/// One match from an L1 query (the spec's `Result` type, plus the
/// match's `entity_type` which the query handler always includes).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct QueryMatch {
    pub path: String,
    pub content_hash: Hash,
    /// Type label of the entity at `path` (e.g. `"system/handler"`).
    pub entity_type: String,
    /// Populated when the query expression set `include_entities: true`
    /// and the entity appeared in the envelope's `included` map.
    pub entity: Option<Entity>,
}

/// Parse the `system/query` `find` result entity into [`QueryResults`].
///
/// Handles both shapes the handler emits: bare `system/query/result`
/// (when `include_entities = false`) and `system/envelope` wrapping a
/// query result plus an `included` map (when `include_entities = true`).
fn parse_query_result(result: &Entity) -> Result<QueryResults, SdkError> {
    let value: ciborium::Value = ciborium::from_reader(result.data.as_slice())
        .map_err(|e| SdkError::HandlerError(format!("query result decode: {}", e)))?;

    let (root_value, included) = if result.entity_type == entity_types::TYPE_ENVELOPE {
        let map = match &value {
            ciborium::Value::Map(m) => m,
            _ => return Err(SdkError::HandlerError("envelope: expected map".into())),
        };
        let mut root: Option<ciborium::Value> = None;
        let mut included: Vec<(ciborium::Value, ciborium::Value)> = Vec::new();
        for (k, v) in map {
            let key = match k {
                ciborium::Value::Text(s) => s.as_str(),
                _ => continue,
            };
            match key {
                "root" => root = Some(v.clone()),
                "included" => {
                    if let ciborium::Value::Map(m) = v {
                        included = m.clone();
                    }
                }
                _ => {}
            }
        }
        let root = root.ok_or_else(|| {
            SdkError::HandlerError("envelope: missing `root` field".into())
        })?;
        let root_decoded = decode_inline_entity_data(&root)?;
        (root_decoded, included)
    } else {
        (value, Vec::new())
    };

    let map = match &root_value {
        ciborium::Value::Map(m) => m,
        _ => return Err(SdkError::HandlerError("query result: expected map".into())),
    };

    let mut matches_raw: Option<&Vec<ciborium::Value>> = None;
    let mut has_more = false;
    let mut total: u64 = 0;
    let mut cursor: Option<String> = None;

    for (k, v) in map {
        let key = match k {
            ciborium::Value::Text(s) => s.as_str(),
            _ => continue,
        };
        match key {
            "matches" => {
                if let ciborium::Value::Array(arr) = v {
                    matches_raw = Some(arr);
                }
            }
            "has_more" => {
                if let ciborium::Value::Bool(b) = v {
                    has_more = *b;
                }
            }
            "total" => {
                if let ciborium::Value::Integer(i) = v {
                    let signed: i128 = (*i).into();
                    if signed >= 0 {
                        total = signed as u64;
                    }
                }
            }
            "cursor" => {
                if let ciborium::Value::Text(s) = v {
                    cursor = Some(s.clone());
                }
            }
            _ => {}
        }
    }

    let mut matches = Vec::new();
    if let Some(arr) = matches_raw {
        for entry in arr {
            if let Some(qm) = parse_query_match(entry, &included) {
                matches.push(qm);
            }
        }
    }

    Ok(QueryResults { matches, has_more, total, cursor })
}

fn parse_query_match(
    entry: &ciborium::Value,
    included: &[(ciborium::Value, ciborium::Value)],
) -> Option<QueryMatch> {
    let map = match entry {
        ciborium::Value::Map(m) => m,
        _ => return None,
    };
    let mut path = String::new();
    let mut entity_type = String::new();
    let mut hash_bytes: Option<Vec<u8>> = None;
    for (k, v) in map {
        let key = match k {
            ciborium::Value::Text(s) => s.as_str(),
            _ => continue,
        };
        match key {
            "path" => {
                if let ciborium::Value::Text(s) = v {
                    path = s.clone();
                }
            }
            "type" => {
                if let ciborium::Value::Text(s) = v {
                    entity_type = s.clone();
                }
            }
            "hash" => {
                if let ciborium::Value::Bytes(b) = v {
                    hash_bytes = Some(b.clone());
                }
            }
            _ => {}
        }
    }
    let content_hash = Hash::from_bytes(&hash_bytes?).ok()?;

    let entity = lookup_included_entity(&content_hash, included);

    Some(QueryMatch { path, content_hash, entity_type, entity })
}

fn lookup_included_entity(
    hash: &Hash,
    included: &[(ciborium::Value, ciborium::Value)],
) -> Option<Entity> {
    let want = hash.to_bytes();
    for (k, v) in included {
        if let ciborium::Value::Bytes(b) = k {
            if b.as_slice() == want.as_slice() {
                return decode_inline_entity(v);
            }
        }
    }
    None
}

/// Decode an inline-entity value `{type, data}` into a real Entity.
fn decode_inline_entity(v: &ciborium::Value) -> Option<Entity> {
    let map = match v {
        ciborium::Value::Map(m) => m,
        _ => return None,
    };
    let mut entity_type = String::new();
    let mut data: Option<Vec<u8>> = None;
    for (k, val) in map {
        let key = match k {
            ciborium::Value::Text(s) => s.as_str(),
            _ => continue,
        };
        match key {
            "type" => {
                if let ciborium::Value::Text(s) = val {
                    entity_type = s.clone();
                }
            }
            "data" => match val {
                ciborium::Value::Bytes(b) => data = Some(b.clone()),
                other => {
                    // Inline-entity `data` is the raw entity bytes; if the
                    // handler encoded it as something other than bytes,
                    // re-serialize it to recover ECF-equivalent bytes.
                    let mut buf = Vec::new();
                    if ciborium::into_writer(other, &mut buf).is_ok() {
                        data = Some(buf);
                    }
                }
            },
            _ => {}
        }
    }
    if entity_type.is_empty() {
        return None;
    }
    Entity::new(&entity_type, data?).ok()
}

/// One transition in a path's history (SDK-EXTENSION-OPERATIONS §5).
/// Mirrors the spec's `HistoryResult.transitions[]` entry.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct HistoryTransition {
    /// Content hash bound to the path at this transition.
    pub hash: Option<Hash>,
    /// Hash this transition replaced (`None` for the path's first put).
    pub previous_hash: Option<Hash>,
    /// Transition event tag from the engine — `"created"`, `"updated"`,
    /// or `"deleted"` (the spec phrases this as "put | remove" — the
    /// engine refines into the three sub-cases).
    pub event: String,
    pub timestamp: u64,
}

/// Filter set for `history_query` per `EXTENSION-HISTORY` and the
/// kernel handler's `QueryParams` shape (`extensions/history/src/lib.rs:291`).
///
/// All fields optional — `HistoryQueryOptions::default()` reads the
/// full audit trail from the most recent transition backward. Use
/// `..Default::default()` to set one field at a time.
///
/// Filter semantics (handler-side at `extensions/history/src/lib.rs:133-154`):
/// - `since`: **a transition-entity hash** (matches against the chain
///   anchor at handler line 122-138, not the path content_hash inside
///   the transition). Walk stops on hit, exclusive — `since` itself is
///   NOT recorded. The only consumer-reachable transition-entity hash
///   in the current SDK shape is [`HistoryQueryResult::head`]
///   (most-recent transition); deeper paging anchors aren't surfaced
///   today. Pass `Some(prev_query.head.unwrap())` to bound a follow-up
///   walk to "older than what I just saw."
/// - `before`: skip transitions whose `timestamp >= before`.
///   Timestamps are **milliseconds since the Unix epoch**
///   (`extensions/history/src/engine.rs:283-286`).
/// - `events`: keep only transitions whose event tag is in the set.
///   Spec values: `"created"`, `"updated"`, `"deleted"`.
/// - `limit`: cap the result count; missing → engine default (50).
#[derive(Debug, Clone, Default)]
pub struct HistoryQueryOptions {
    pub limit: Option<u64>,
    pub since: Option<Hash>,
    pub before: Option<u64>,
    pub events: Option<Vec<String>>,
}

/// Result of `history_query` (SDK-EXTENSION-OPERATIONS §5).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct HistoryQueryResult {
    /// The canonicalized path the history is for.
    pub path: String,
    /// Current head hash (most recent transition's content hash).
    /// `None` when the path has no history.
    pub head: Option<Hash>,
    /// Transitions newest-to-oldest.
    pub transitions: Vec<HistoryTransition>,
    /// True if more transitions remain past the limit.
    pub has_more: bool,
}

fn parse_history_query_result(result: &Entity) -> Result<HistoryQueryResult, SdkError> {
    let value: ciborium::Value = ciborium::from_reader(result.data.as_slice())
        .map_err(|e| SdkError::HandlerError(format!("history result decode: {}", e)))?;

    // The handler always wraps in `system/envelope`; unwrap to get the
    // history-query-result map.
    let root_value = if result.entity_type == entity_types::TYPE_ENVELOPE {
        let map = match &value {
            ciborium::Value::Map(m) => m,
            _ => return Err(SdkError::HandlerError("history envelope: expected map".into())),
        };
        let mut root: Option<ciborium::Value> = None;
        for (k, v) in map {
            if let ciborium::Value::Text(key) = k {
                if key == "root" {
                    root = Some(v.clone());
                    break;
                }
            }
        }
        let root = root.ok_or_else(|| {
            SdkError::HandlerError("history envelope: missing `root`".into())
        })?;
        decode_inline_entity_data(&root)?
    } else {
        value
    };

    let map = match &root_value {
        ciborium::Value::Map(m) => m,
        _ => return Err(SdkError::HandlerError("history result: expected map".into())),
    };

    let mut path = String::new();
    let mut head: Option<Hash> = None;
    let mut transitions: Vec<HistoryTransition> = Vec::new();
    let mut has_more = false;

    for (k, v) in map {
        let key = match k {
            ciborium::Value::Text(s) => s.as_str(),
            _ => continue,
        };
        match key {
            "path" => {
                if let ciborium::Value::Text(s) = v {
                    path = s.clone();
                }
            }
            "head" => {
                if let ciborium::Value::Bytes(b) = v {
                    head = Hash::from_bytes(b).ok();
                }
            }
            "has_more" => {
                if let ciborium::Value::Bool(b) = v {
                    has_more = *b;
                }
            }
            "transitions" => {
                if let ciborium::Value::Array(arr) = v {
                    for entry in arr {
                        if let Some(t) = parse_history_transition(entry) {
                            transitions.push(t);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    Ok(HistoryQueryResult { path, head, transitions, has_more })
}

fn parse_history_transition(v: &ciborium::Value) -> Option<HistoryTransition> {
    let map = match v {
        ciborium::Value::Map(m) => m,
        _ => return None,
    };
    let mut event = String::new();
    let mut hash: Option<Hash> = None;
    let mut previous_hash: Option<Hash> = None;
    let mut timestamp: u64 = 0;

    for (k, val) in map {
        let key = match k {
            ciborium::Value::Text(s) => s.as_str(),
            _ => continue,
        };
        match key {
            "event" => {
                if let ciborium::Value::Text(s) = val {
                    event = s.clone();
                }
            }
            "hash" => {
                if let ciborium::Value::Bytes(b) = val {
                    hash = Hash::from_bytes(b).ok();
                }
            }
            "previous_hash" => {
                if let ciborium::Value::Bytes(b) = val {
                    previous_hash = Hash::from_bytes(b).ok();
                }
            }
            "timestamp" => {
                if let ciborium::Value::Integer(i) = val {
                    let signed: i128 = (*i).into();
                    if signed >= 0 {
                        timestamp = signed as u64;
                    }
                }
            }
            _ => {}
        }
    }

    Some(HistoryTransition { hash, previous_hash, event, timestamp })
}

fn build_history_query_params(
    path: String,
    options: &HistoryQueryOptions,
) -> Result<Entity, SdkError> {
    let mut fields: Vec<(ciborium::Value, ciborium::Value)> = vec![(
        entity_ecf::text("path"),
        entity_ecf::text(&path),
    )];
    if let Some(n) = options.limit {
        fields.push((entity_ecf::text("limit"), entity_ecf::integer(n as i64)));
    }
    if let Some(ref since) = options.since {
        fields.push((
            entity_ecf::text("since"),
            ciborium::Value::Bytes(since.to_bytes().to_vec()),
        ));
    }
    if let Some(before) = options.before {
        fields.push((entity_ecf::text("before"), entity_ecf::integer(before as i64)));
    }
    if let Some(ref events) = options.events {
        let arr: Vec<ciborium::Value> = events.iter().map(|s| entity_ecf::text(s)).collect();
        fields.push((entity_ecf::text("events"), ciborium::Value::Array(arr)));
    }
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(fields));
    Entity::new("system/history/query-params", data)
        .map_err(|e| SdkError::HandlerError(format!("build history query params: {}", e)))
}

fn build_history_rollback_params(path: String, target_hash: Hash) -> Result<Entity, SdkError> {
    let fields: Vec<(ciborium::Value, ciborium::Value)> = vec![
        (entity_ecf::text("path"), entity_ecf::text(&path)),
        (
            entity_ecf::text("target_hash"),
            ciborium::Value::Bytes(target_hash.to_bytes().to_vec()),
        ),
    ];
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(fields));
    Entity::new("system/history/rollback-params", data)
        .map_err(|e| SdkError::HandlerError(format!("build history rollback params: {}", e)))
}

/// Dispatch a handler operation owned by `shared`, returning the typed
/// `HandlerResult` on transport success. Used by helpers (`history_query`,
/// `history_rollback`) that build params asynchronously and so can't
/// reuse the `execute()` owning-future pattern directly.
async fn dispatch_execute(
    shared: Arc<PeerShared>,
    handler: &'static str,
    operation: &'static str,
    params: Entity,
) -> Result<entity_handler::HandlerResult, SdkError> {
    let local_identity = shared.identity_hash;
    let execute_fn = entity_peer::connection::make_execute_fn(
        shared,
        Some(local_identity),
        std::collections::HashMap::new(),
        None,
        None,
    );
    execute_fn(
        handler.into(),
        operation.into(),
        params,
        entity_handler::ExecuteOptions::default(),
    )
    .await
    .map_err(|e| SdkError::HandlerError(e.to_string()))
}

/// Parse the `primitive/uint` entity returned by `system/query count`
/// into a u64. Negative values (which shouldn't appear) are clamped to
/// 0 with an error.
fn parse_count_result(result: &Entity) -> Result<u64, SdkError> {
    let value: ciborium::Value = ciborium::from_reader(result.data.as_slice())
        .map_err(|e| SdkError::HandlerError(format!("count result decode: {}", e)))?;
    match value {
        ciborium::Value::Integer(i) => {
            let signed: i128 = i.into();
            if signed < 0 {
                Err(SdkError::HandlerError(format!(
                    "count: negative value {}",
                    signed
                )))
            } else {
                Ok(signed as u64)
            }
        }
        _ => Err(SdkError::HandlerError("count: expected integer".into())),
    }
}

/// Decode the inner `data` payload of an inline entity to a CBOR Value
/// for further parsing (used to crack open the envelope's `root`).
fn decode_inline_entity_data(v: &ciborium::Value) -> Result<ciborium::Value, SdkError> {
    let map = match v {
        ciborium::Value::Map(m) => m,
        _ => return Err(SdkError::HandlerError("inline entity: expected map".into())),
    };
    for (k, val) in map {
        if let ciborium::Value::Text(key) = k {
            if key == "data" {
                if let ciborium::Value::Bytes(bytes) = val {
                    return ciborium::from_reader(bytes.as_slice())
                        .map_err(|e| SdkError::HandlerError(format!("inline data decode: {}", e)));
                }
                // Non-bytes form: pass through as-is.
                return Ok(val.clone());
            }
        }
    }
    Err(SdkError::HandlerError("inline entity: missing `data`".into()))
}

// ---------------------------------------------------------------------------
// Error model — SDK-OPERATIONS.md §12
// ---------------------------------------------------------------------------

/// Status codes per SDK-OPERATIONS.md §12.
///
/// HTTP-like codes used by handlers and SDK operations.
pub mod status {
    pub const OK: u32 = 200;
    pub const ACCEPTED: u32 = 202;
    pub const PARTIAL: u32 = 207;
    pub const REDIRECT: u32 = 303;
    pub const BAD_REQUEST: u32 = 400;
    pub const FORBIDDEN: u32 = 403;
    pub const NOT_FOUND: u32 = 404;
    pub const CONFLICT: u32 = 409;
    pub const RATE_LIMITED: u32 = 429;
    pub const INTERNAL: u32 = 500;
    pub const NOT_SUPPORTED: u32 = 501;
}

/// Errors from SDK operations, categorized per SDK-OPERATIONS.md §12.
#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    // -- Setup errors --
    #[error("no keypair provided — call keypair() or generate_keypair()")]
    NoKeypair,
    #[error("peer build failed: {0}")]
    PeerBuild(String),
    #[error("unknown peer: {0}")]
    UnknownPeer(String),

    // -- Operation errors (mapped to status codes) --
    //
    // 4xx/5xx variants carry the substrate's structured `code` (per
    // `system/protocol/error` body — see `entity_handler::decode_error_entity`)
    // alongside `message`. Consumers MUST NOT substring-match `message` to
    // identify the failure class; switch on `code` instead. The field is
    // `Option<String>` because some transports (e.g., remote dispatch
    // truncation, unstructured status-only setups) cannot supply one — in
    // those cases `code` is `None` and `message` carries SDK-side context.
    #[error("tree operation failed: {0}")]
    TreeError(String),
    #[error("handler dispatch failed: {0}")]
    HandlerError(String),
    #[error("bad request ({status}{}): {message}", code.as_deref().map(|c| format!(", {}", c)).unwrap_or_default())]
    BadRequest { status: u32, code: Option<String>, message: String },
    #[error("forbidden ({status}{}): {message}", code.as_deref().map(|c| format!(", {}", c)).unwrap_or_default())]
    Forbidden { status: u32, code: Option<String>, message: String },
    #[error("not found ({status}{}): {message}", code.as_deref().map(|c| format!(", {}", c)).unwrap_or_default())]
    NotFound { status: u32, code: Option<String>, message: String },
    #[error("conflict ({status}{}): {message}", code.as_deref().map(|c| format!(", {}", c)).unwrap_or_default())]
    Conflict { status: u32, code: Option<String>, message: String },
    #[error("internal error ({status}{}): {message}", code.as_deref().map(|c| format!(", {}", c)).unwrap_or_default())]
    Internal { status: u32, code: Option<String>, message: String },
    #[error("not supported ({status}{}): {message}", code.as_deref().map(|c| format!(", {}", c)).unwrap_or_default())]
    NotSupported { status: u32, code: Option<String>, message: String },
}

impl SdkError {
    /// Map a handler status code + optional substrate `code` + message into an SdkError.
    /// Returns None for success codes (2xx, 3xx).
    ///
    /// Prefer [`SdkError::from_handler_result`] when the caller already has
    /// the full `HandlerResult`: it decodes the substrate's `system/protocol/error`
    /// body to extract `code` and `message` for free, rather than the caller
    /// having to do it.
    pub fn from_status(
        status: u32,
        code: Option<String>,
        message: impl Into<String>,
    ) -> Option<Self> {
        let message = message.into();
        match status {
            0..=399 => None, // Success / redirect — not an error.
            400 => Some(SdkError::BadRequest { status, code, message }),
            403 => Some(SdkError::Forbidden { status, code, message }),
            404 => Some(SdkError::NotFound { status, code, message }),
            409 => Some(SdkError::Conflict { status, code, message }),
            429 => Some(SdkError::BadRequest { status, code, message }),
            500 => Some(SdkError::Internal { status, code, message }),
            501 => Some(SdkError::NotSupported { status, code, message }),
            _ => Some(SdkError::Internal { status, code, message }),
        }
    }

    /// Map a substrate `HandlerResult` into an SdkError, preserving the
    /// `code` + `message` from the result entity when it is a
    /// `system/protocol/error` body. Falls back to `fallback_context` for
    /// the message when the body has no `message` field (or the entity is
    /// not the canonical error type).
    ///
    /// Returns `None` for 2xx/3xx status — the caller is responsible for
    /// the success path. This is the single canonical mapping site for
    /// "handler returned, but with non-success status"; callers MUST NOT
    /// substring-match the substrate's `code` away by passing only `status`
    /// + their own context.
    pub fn from_handler_result(
        result: &entity_handler::HandlerResult,
        fallback_context: impl Into<String>,
    ) -> Option<Self> {
        if result.status < 400 {
            return None;
        }
        let (code, message) = match entity_handler::decode_error_entity(&result.result) {
            Some((c, Some(m))) => (c, m),
            Some((c, None)) => (c, fallback_context.into()),
            None => (None, fallback_context.into()),
        };
        Self::from_status(result.status, code, message)
    }

    /// The HTTP-like status code for this error, or 500 for setup errors.
    pub fn status_code(&self) -> u32 {
        match self {
            SdkError::NoKeypair | SdkError::PeerBuild(_) => status::INTERNAL,
            SdkError::UnknownPeer(_) => status::NOT_FOUND,
            SdkError::TreeError(_) | SdkError::HandlerError(_) => status::INTERNAL,
            SdkError::BadRequest { status, .. }
            | SdkError::Forbidden { status, .. }
            | SdkError::NotFound { status, .. }
            | SdkError::Conflict { status, .. }
            | SdkError::Internal { status, .. }
            | SdkError::NotSupported { status, .. } => *status,
        }
    }

    /// Whether this is a client error (4xx).
    pub fn is_client_error(&self) -> bool {
        let code = self.status_code();
        (400..500).contains(&code)
    }

    /// Whether this is an authorization error (403).
    pub fn is_auth_error(&self) -> bool {
        self.status_code() == status::FORBIDDEN
    }

    /// Whether this is a system/server error (5xx).
    pub fn is_system_error(&self) -> bool {
        let code = self.status_code();
        code >= 500
    }
}

/// Builder for PeerContext.
pub struct PeerContextBuilder {
    keypair: Option<Keypair>,
    config: Option<PeerConfig>,
    connector: Option<Arc<dyn entity_peer::transport::Connector>>,
    grants: Option<GrantScope>,
    /// Path to a SQLite database file backing this peer's tree. When set,
    /// `build()` calls `PeerBuilder::sqlite(path)` instead of falling
    /// through to the default in-memory store. Per `GUIDE-PERSISTENCE.md`
    /// the path is typically `~/.entity/peers/{name}/store.db`.
    #[cfg(all(not(target_arch = "wasm32"), feature = "sqlite"))]
    sqlite_path: Option<std::path::PathBuf>,
    /// When `Some(root)`, the peer's content store + location index are
    /// backed by OPFS journals under that subdirectory (WASM worker only).
    /// `root` is a slash-separated path under the OPFS root; empty string
    /// uses the OPFS root directly. Requires `build_async()` — sync
    /// `build()` errors if this is set.
    #[cfg(all(target_arch = "wasm32", feature = "wasm-persist"))]
    opfs_root: Option<String>,
    /// When `Some(name)`, the peer's content store + location index are
    /// backed by a write-behind IndexedDB journal under that database
    /// name (WASM main thread or worker). Unlike OPFS, IDB works on the
    /// **main thread** — this is the durable backend for the Direct arm /
    /// Tauri WebView / the persistent system peer. Requires `build_async()`
    /// — sync `build()` errors if this is set. See `core/store/src/idb.rs`.
    #[cfg(all(target_arch = "wasm32", feature = "wasm-idb-persist"))]
    idb_name: Option<String>,
    /// Observe-only dispatch-event hooks per `GUIDE-INSPECTABILITY` v1.2
    /// §2.1 #3 (path tap surface). Forwarded to
    /// `PeerBuilder::with_dispatch_hook` at build time. Type-erased
    /// via `Arc<dyn Fn>` so the builder can hold many heterogeneous
    /// closures.
    dispatch_hooks: Vec<(String, Arc<dyn Fn(&DispatchEvent) + Send + Sync>)>,
    /// Observe-only wire-event hooks per `GUIDE-INSPECTABILITY` v1.2 §2.1 #5.
    /// **Security (audit §2.1):** events carry the full envelope bytes
    /// including capability tokens, signatures, and identity material.
    /// Consumer hooks retaining `frame_bytes` maintain a cap-token corpus
    /// and MUST be operator-controlled.
    wire_hooks: Vec<(String, Arc<dyn Fn(&WireEvent) + Send + Sync>)>,
    /// Observe-only binding-event hooks per `GUIDE-INSPECTABILITY` v1.2 §2.1 #2.
    binding_hooks: Vec<(String, Arc<dyn Fn(&TreeChangeEvent) + Send + Sync>)>,
    /// When set via [`PeerContextBuilder::with_inspect_routing`], the
    /// build path installs three demuxer hooks that marshal substrate
    /// events into `InspectFact` and fan out to sinks registered on
    /// the resulting `PeerContext`. Default-off: an unset registry
    /// pays zero cost. See `inspect.rs` + the inspect-worker-arm design
    /// memo.
    inspect_registry: Option<crate::inspect::InspectSinkRegistry>,
    /// When set via [`PeerContextBuilder::with_grant_resolver`], the
    /// build path installs it on the underlying `Peer` via
    /// `set_grant_resolver`. The resolver is consulted by the connect
    /// handler (EXTENSION-ROLE §4.7) to decide which connection grants
    /// to confer on an authenticated remote peer; returning `None`
    /// falls through to `default_connection_grants` (or whatever the
    /// connect handler's static fallback is). Without this hook,
    /// compositions that don't include the `role` extension have no
    /// way to install custom grant policy — they're stuck on the
    /// static fallback.
    grant_resolver: Option<entity_peer::GrantResolver>,
}

impl PeerContextBuilder {
    pub fn new() -> Self {
        Self {
            keypair: None,
            config: None,
            connector: None,
            grants: None,
            #[cfg(all(not(target_arch = "wasm32"), feature = "sqlite"))]
            sqlite_path: None,
            #[cfg(all(target_arch = "wasm32", feature = "wasm-persist"))]
            opfs_root: None,
            #[cfg(all(target_arch = "wasm32", feature = "wasm-idb-persist"))]
            idb_name: None,
            dispatch_hooks: Vec::new(),
            wire_hooks: Vec::new(),
            binding_hooks: Vec::new(),
            inspect_registry: None,
            grant_resolver: None,
        }
    }

    /// Install a connect-handler grant resolver
    /// (EXTENSION-ROLE §4.7 mechanism, but not role-specific).
    ///
    /// On every successful AUTHENTICATE the connect handler asks the
    /// resolver what grants to confer on the remote peer. Returning
    /// `Some(grants)` confers them; `None` falls through to the
    /// connect handler's static fallback
    /// (`default_connection_grants` or `debug_open_grants` per
    /// `PeerConfig`).
    ///
    /// **Closure signature:** `Fn(&PeerId, &Hash) -> Option<Vec<GrantEntry>>`
    /// where `PeerId` is the remote's `entity_crypto::PeerId` (V7 §1.4
    /// SHA-256 digest of the public key) and `Hash` is the freshly-computed
    /// `system/peer` content hash (the form by which role / identity
    /// tree state is keyed). Use the second arg for role / identity
    /// lookups; use the first when only the cryptographic identity
    /// matters.
    ///
    /// Mirrors the `with_inspect_routing` shape — fluent, idempotent
    /// at construction, type-erased internally so consumers don't see
    /// the `Arc<dyn ...>` plumbing.
    ///
    /// **Without this hook,** non-role compositions (peers built
    /// without the role extension wired in) have no programmatic way
    /// to install custom connection-grant policy and are stuck on the
    /// static fallback. The `role` extension uses
    /// `set_grant_resolver` internally via its `build_policy_resolver`
    /// helper; this method exposes the same seam directly.
    ///
    /// Per Godot ask D2.
    pub fn with_grant_resolver<F>(mut self, resolver: F) -> Self
    where
        F: Fn(&entity_crypto::PeerId, &Hash) -> Option<Vec<entity_capability::GrantEntry>>
            + Send
            + Sync
            + 'static,
    {
        self.grant_resolver = Some(Arc::new(resolver));
        self
    }

    /// Enable consumer-side inspect-sink routing for this peer. After
    /// build, call [`PeerContext::install_inspect_sink`] to attach
    /// per-peer callbacks that receive marshalled `InspectFact` values.
    ///
    /// Costs nothing when no sinks are attached (the demuxer hooks
    /// check the empty registry and early-return before marshalling).
    /// Idempotent: calling more than once reuses the same registry.
    ///
    /// Per the inspect-worker-arm design memo /
    /// `feedback_sdk_is_the_substrate`.
    pub fn with_inspect_routing(mut self) -> Self {
        if self.inspect_registry.is_none() {
            self.inspect_registry = Some(crate::inspect::InspectSinkRegistry::new());
        }
        self
    }

    /// Register an observe-only dispatch hook per `GUIDE-INSPECTABILITY`
    /// v1.2 §2.1 #3 / §2.2 "Path tap". Hook fires twice per dispatch
    /// (entry + exit) at the dispatcher↔handler boundary. Pass-through
    /// to `PeerBuilder::with_dispatch_hook`.
    ///
    /// **Security (audit §2.1):** events carry `params_hash` only, not
    /// the full params body. Hook fns that need the body fetch it via
    /// `ctx.store().get(hash)`. Rust's borrow checker structurally
    /// enforces audit §2's no-retain invariant on `&DispatchEvent`.
    ///
    /// Multiple hooks fire in registration order.
    pub fn with_dispatch_hook<F>(
        mut self,
        name: impl Into<String>,
        f: F,
    ) -> Self
    where
        F: Fn(&DispatchEvent) + Send + Sync + 'static,
    {
        self.dispatch_hooks.push((name.into(), Arc::new(f)));
        self
    }

    /// Register an observe-only wire-event hook per `GUIDE-INSPECTABILITY`
    /// v1.2 §2.1 #5 / §2.2 "Wire recorder". Pass-through to
    /// `PeerBuilder::with_wire_hook`.
    ///
    /// **SECURITY (audit §2.1, §6):** wire events carry the full CBOR
    /// envelope including capability tokens, signatures, and identity
    /// material. Hooks retaining `frame_bytes` maintain a cap-token
    /// corpus and MUST be operator-controlled. Production consumers
    /// SHOULD enforce a retention-volume cap-scope axis (audit §4).
    pub fn with_wire_hook<F>(
        mut self,
        name: impl Into<String>,
        f: F,
    ) -> Self
    where
        F: Fn(&WireEvent) + Send + Sync + 'static,
    {
        self.wire_hooks.push((name.into(), Arc::new(f)));
        self
    }

    /// Register an observe-only binding-event hook per
    /// `GUIDE-INSPECTABILITY` v1.2 §2.1 #2 / §2.2 "Binding stream".
    /// Pass-through to `PeerBuilder::with_binding_hook`.
    ///
    /// Fires on every path bind / rebind / unbind, with
    /// `kind ∈ {Created, Modified, Deleted}` and optional
    /// `cascade_depth`. Observer-only — cannot halt cascades.
    pub fn with_binding_hook<F>(
        mut self,
        name: impl Into<String>,
        f: F,
    ) -> Self
    where
        F: Fn(&TreeChangeEvent) + Send + Sync + 'static,
    {
        self.binding_hooks.push((name.into(), Arc::new(f)));
        self
    }

    /// Use an existing keypair.
    #[allow(dead_code)]
    pub fn keypair(mut self, keypair: Keypair) -> Self {
        self.keypair = Some(keypair);
        self
    }

    /// Generate a new random keypair.
    pub fn generate_keypair(mut self) -> Self {
        self.keypair = Some(Keypair::generate());
        self
    }

    /// Set peer configuration (passed through to entity-peer's PeerConfig).
    pub fn config(mut self, config: PeerConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Set the transport connector for outbound connections.
    pub fn connector(mut self, connector: Arc<dyn entity_peer::transport::Connector>) -> Self {
        self.connector = Some(connector);
        self
    }

    /// Configure SQLite as this peer's storage backend. When set,
    /// `build()` opens (or creates) a SQLite database at `path` for the
    /// content store, location index, and query indexes.
    ///
    /// Path convention per `GUIDE-PERSISTENCE.md` §1.1:
    /// `~/.entity/peers/{name}/store.db`. Apps own the directory walk;
    /// this method is a thin pass-through to `PeerBuilder::sqlite`.
    #[cfg(all(not(target_arch = "wasm32"), feature = "sqlite"))]
    pub fn sqlite(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.sqlite_path = Some(path.into());
        self
    }

    /// Enable OPFS-backed durable storage for this peer (WASM worker only).
    ///
    /// `root` is the OPFS subdirectory to host this peer's journals;
    /// multiple OPFS-backed peers in the same origin MUST use distinct
    /// roots (the underlying `createSyncAccessHandle` is exclusive per
    /// file). Empty string uses the OPFS root directly. Handle
    /// acquisition is async, so callers MUST use `build_async()` instead
    /// of `build()` after setting this — `build()` errors otherwise.
    #[cfg(all(target_arch = "wasm32", feature = "wasm-persist"))]
    pub fn opfs(mut self, root: impl Into<String>) -> Self {
        self.opfs_root = Some(root.into());
        self
    }

    /// Enable IndexedDB-backed durable storage for this peer (WASM main
    /// thread or worker).
    ///
    /// Unlike [`opfs`](Self::opfs) (worker-only, synchronous flush), IDB
    /// works on the **main thread** with a write-behind journal — this is
    /// the durable backend for the Direct arm, the Tauri WebView, and the
    /// persistent system peer. `name` is the IndexedDB database name;
    /// multiple IDB-backed peers in the same origin MUST use distinct
    /// names (concurrent writers to one database race, last-writer-wins —
    /// gate them with the app's single-writer Web Lock). Handle acquisition
    /// + the initial replay are async, so callers MUST use `build_async()`
    /// instead of `build()` after setting this — `build()` errors otherwise.
    ///
    /// Identity/destructive ops (create-peer, delete-peer, config commit)
    /// that cannot tolerate write-behind loss must await
    /// [`PeerContext::idb_checkpoint`]`().checkpoint()` before acknowledging.
    #[cfg(all(target_arch = "wasm32", feature = "wasm-idb-persist"))]
    pub fn idb(mut self, name: impl Into<String>) -> Self {
        self.idb_name = Some(name.into());
        self
    }

    /// Set the default grant scope for this peer (SDK-OPERATIONS.md §11.2).
    ///
    /// This field is plumbed through the SDK but not yet enforced — capability
    /// checking runs in "open grants" mode today. When the capability handler
    /// in entity-core-rust supports grant creation, this scope will be the
    /// default passed into `create_grant` operations for the peer.
    #[allow(dead_code)]
    pub fn grants(mut self, grants: GrantScope) -> Self {
        self.grants = Some(grants);
        self
    }

    /// Build the PeerContext instance.
    ///
    /// **OPFS callers:** if you called `.opfs()`, you MUST use
    /// [`build_async`](Self::build_async) instead — OPFS handle
    /// acquisition is async, and this method has no opportunity to
    /// await. Sync `build()` returns an error in that case.
    pub fn build(self) -> Result<PeerContext, SdkError> {
        #[cfg(all(target_arch = "wasm32", feature = "wasm-persist"))]
        if self.opfs_root.is_some() {
            return Err(SdkError::PeerBuild(
                "opfs() was set; call build_async() instead of build()".into(),
            ));
        }
        #[cfg(all(target_arch = "wasm32", feature = "wasm-idb-persist"))]
        if self.idb_name.is_some() {
            return Err(SdkError::PeerBuild(
                "idb() was set; call build_async() instead of build()".into(),
            ));
        }
        self.build_inner()
    }

    /// Build the PeerContext, awaiting any async backend setup (OPFS).
    ///
    /// Available on wasm32. Always callable on wasm32 (alias of `build`
    /// when no async work is needed) so worker host code can do
    /// `builder.build_async().await` unconditionally without feature
    /// gating its call site.
    #[cfg(target_arch = "wasm32")]
    pub async fn build_async(self) -> Result<PeerContext, SdkError> {
        let keypair = self.keypair.ok_or(SdkError::NoKeypair)?;
        let peer_id_string = keypair.peer_id().to_string();
        let config = self.config.unwrap_or_default();

        let mut builder = PeerBuilder::new().keypair(keypair).config(config);

        if let Some(connector) = self.connector {
            builder = builder.connector(connector);
        }

        // Track storage backend for `PeerContext::storage_kind()`. OPFS
        // and IDB are the async backends and are mutually exclusive per
        // peer; absent both the wasm path is in-memory (same as the native
        // default). The features are independent, so default to "memory"
        // and let whichever backend the caller selected override it.
        #[allow(unused_mut, unused_assignments)]
        let mut storage_kind: &'static str = "memory";
        #[cfg(feature = "wasm-persist")]
        if let Some(root) = self.opfs_root.as_deref() {
            builder = builder
                .opfs(root)
                .await
                .map_err(|e| SdkError::PeerBuild(e.to_string()))?;
            storage_kind = "opfs";
        }
        #[cfg(feature = "wasm-idb-persist")]
        if let Some(name) = self.idb_name.as_deref() {
            builder = builder
                .idb(name)
                .await
                .map_err(|e| SdkError::PeerBuild(e.to_string()))?;
            storage_kind = "idb";
        }

        // Apply registered inspectability hooks (GUIDE-INSPECTABILITY v1.2
        // §2.1). Each Arc clone shares the closure with the substrate's
        // hook registry; the closure runs there.
        for (name, hook) in self.dispatch_hooks {
            let hook = hook.clone();
            builder = builder.with_dispatch_hook(name, move |event| hook(event));
        }
        for (name, hook) in self.wire_hooks {
            let hook = hook.clone();
            builder = builder.with_wire_hook(name, move |event| hook(event));
        }
        for (name, hook) in self.binding_hooks {
            let hook = hook.clone();
            builder = builder.with_binding_hook(name, move |event| hook(event));
        }

        // Inspect-routing demuxer hooks (see `build_inner` for rationale).
        if let Some(registry) = self.inspect_registry.as_ref() {
            let dr = registry.clone();
            builder = builder.with_dispatch_hook("sdk/inspect-route", move |ev| {
                if dr.is_empty() {
                    return;
                }
                dr.fire(&crate::inspect::marshal_dispatch(ev));
            });
            let wr = registry.clone();
            builder = builder.with_wire_hook("sdk/inspect-route", move |ev| {
                if wr.is_empty() {
                    return;
                }
                wr.fire(&crate::inspect::marshal_wire(ev));
            });
            let br = registry.clone();
            builder = builder.with_binding_hook("sdk/inspect-route", move |ev| {
                if br.is_empty() {
                    return;
                }
                br.fire(&crate::inspect::marshal_binding(ev));
            });
        }

        let mut peer = builder
            .build()
            .map_err(|e| SdkError::PeerBuild(e.to_string()))?;
        // Install grant resolver before any `shared()` snapshot — each
        // `PeerShared` clone captures the resolver at clone time
        // (`core/peer/src/lib.rs:260`), so resolver must land first.
        if let Some(resolver) = self.grant_resolver {
            peer.set_grant_resolver(resolver);
        }
        let shared = peer.shared();

        let (owner_self_cap, owner_capability_hash) = mint_owner_self_cap(
            shared
                .keypair
                .as_ed25519()
                .expect("entity-sdk peers are Ed25519-only (Ed448 backends use core PeerBuilder)"),
            shared.identity_hash,
            shared.content_store.as_ref(),
        )?;

        Ok(PeerContext {
            peer,
            shared,
            peer_id_string,
            generation: Arc::new(AtomicU64::new(0)),
            wake_fn: Arc::new(Mutex::new(None)),
            grants: self.grants,
            owner_self_cap,
            owner_capability_hash,
            storage_kind,
            inspect_registry: self.inspect_registry,
        })
    }

    /// Shared body used by sync `build()` (and historically by tests).
    /// Always builds an in-memory or SQLite-backed peer; OPFS is OFF here
    /// because it requires async.
    fn build_inner(self) -> Result<PeerContext, SdkError> {
        let keypair = self.keypair.ok_or(SdkError::NoKeypair)?;
        let peer_id_string = keypair.peer_id().to_string();

        let config = self.config.unwrap_or_default();

        let mut builder = PeerBuilder::new().keypair(keypair).config(config);

        if let Some(connector) = self.connector {
            builder = builder.connector(connector);
        }

        // Track storage backend choice before the path is consumed by
        // the PeerBuilder. Defaults to "memory"; flipped to "sqlite"
        // when the SQLite path is set + feature is on.
        let storage_kind: &'static str;
        #[cfg(all(not(target_arch = "wasm32"), feature = "sqlite"))]
        {
            if let Some(path) = self.sqlite_path {
                builder = builder
                    .sqlite(&path)
                    .map_err(|e| SdkError::PeerBuild(e.to_string()))?;
                storage_kind = "sqlite";
            } else {
                storage_kind = "memory";
            }
        }
        #[cfg(not(all(not(target_arch = "wasm32"), feature = "sqlite")))]
        {
            storage_kind = "memory";
        }

        // Apply registered inspectability hooks (GUIDE-INSPECTABILITY v1.2
        // §2.1).
        for (name, hook) in self.dispatch_hooks {
            let hook = hook.clone();
            builder = builder.with_dispatch_hook(name, move |event| hook(event));
        }
        for (name, hook) in self.wire_hooks {
            let hook = hook.clone();
            builder = builder.with_wire_hook(name, move |event| hook(event));
        }
        for (name, hook) in self.binding_hooks {
            let hook = hook.clone();
            builder = builder.with_binding_hook(name, move |event| hook(event));
        }

        // Install demuxer hooks if inspect routing is enabled. Each hook
        // marshals the in-process event into an InspectFact and fans
        // out to sinks registered on the resulting PeerContext.
        // Empty registry → marshal-and-fire is a quick early-return.
        if let Some(registry) = self.inspect_registry.as_ref() {
            let dr = registry.clone();
            builder = builder.with_dispatch_hook("sdk/inspect-route", move |ev| {
                if dr.is_empty() {
                    return;
                }
                dr.fire(&crate::inspect::marshal_dispatch(ev));
            });
            let wr = registry.clone();
            builder = builder.with_wire_hook("sdk/inspect-route", move |ev| {
                if wr.is_empty() {
                    return;
                }
                wr.fire(&crate::inspect::marshal_wire(ev));
            });
            let br = registry.clone();
            builder = builder.with_binding_hook("sdk/inspect-route", move |ev| {
                if br.is_empty() {
                    return;
                }
                br.fire(&crate::inspect::marshal_binding(ev));
            });
        }

        let mut peer = builder
            .build()
            .map_err(|e| SdkError::PeerBuild(e.to_string()))?;
        // Install grant resolver before any `shared()` snapshot — each
        // `PeerShared` clone captures the resolver at clone time
        // (`core/peer/src/lib.rs:260`), so resolver must land first.
        if let Some(resolver) = self.grant_resolver {
            peer.set_grant_resolver(resolver);
        }

        // Create shared state ONCE — never call peer.shared() again.
        let shared = peer.shared();

        // SDK-level owner self-cap (SDK-OPERATIONS §11.2A — open-grants
        // mode equivalent). Wildcard self-grant minted from the local
        // peer's own keypair; persisted with its signature so chain
        // validators can resolve them. Stamped onto every local L1
        // dispatch as caller_capability so handlers that voluntarily
        // gate on a caller-specified-path cap (e.g., role's RL2) treat
        // the SDK caller as fully authorized. Matches Go's
        // mintOwnerSelfCap (workbench-go entitysdk/app.go:782).
        let (owner_self_cap, owner_capability_hash) = mint_owner_self_cap(
            shared
                .keypair
                .as_ed25519()
                .expect("entity-sdk peers are Ed25519-only (Ed448 backends use core PeerBuilder)"),
            shared.identity_hash,
            shared.content_store.as_ref(),
        )?;

        Ok(PeerContext {
            peer,
            shared,
            peer_id_string,
            generation: Arc::new(AtomicU64::new(0)),
            wake_fn: Arc::new(Mutex::new(None)),
            grants: self.grants,
            owner_self_cap,
            owner_capability_hash,
            storage_kind,
            inspect_registry: self.inspect_registry,
        })
    }
}

/// Mint a wildcard owner self-cap for the local peer per the SDK
/// open-grants progression (SDK-OPERATIONS §11.2A). granter == grantee
/// == local identity hash; wildcards on all four scope dimensions.
/// Persists the cap entity and signature in the content store so
/// `is_attenuated` chain walkers can resolve them.
///
/// V7 §6.5 says "for autonomous operations, the caller capability is
/// absent"; the SDK chooses to materialize it instead so handlers
/// that gate on caller-specified-path authorization (role:define,
/// role:assign, role:re-derive, role:delegate, identity / quorum
/// mint paths) work uniformly across local L1 dispatch and remote
/// connection-cap-bearing dispatch. This is the Rust analog of Go's
/// `mintOwnerSelfCap`.
fn mint_owner_self_cap(
    keypair: &Keypair,
    identity_hash: Hash,
    content_store: &dyn entity_store::ContentStore,
) -> Result<(entity_capability::CapabilityToken, Hash), SdkError> {
    let now_ms = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // Base: the handler-level wildcard self-grant (§6.9). Its resources are the
    // bare `*`, which `canonicalize` resolves to `/{me}/*` — own-namespace only.
    let mut grants = entity_capability::wildcard_handler_grant();

    // Owner-of-the-store READ authority across namespaces. A peer's store can
    // legitimately hold OTHER peers' subtrees at their natural universal paths
    // (V7 §1.4 Category A — e.g. a cached foreign content site at
    // `/{them}/sites/...`). The wildcard grant above does NOT cover those (its
    // `*` → `/{me}/*`), so a peer's own `system/query find` / dispatched `get`
    // over its store is filtered to its own namespace and cannot see the
    // content it cached. The owner of a store may read everything IN it, so
    // grant cross-namespace READ via the explicit `/*/*` peer-wildcard form —
    // the same shape `debug_open_grants` uses for this exact reason
    // (`core/capability/src/lib.rs:153`), and deliberately NOT the bare `*` the
    // `test_resource_wildcard_local_vs_cross_namespace` pin reserves for
    // own-namespace. Reads only (get/find/count): cross-namespace WRITES go
    // through local dispatch, which is not capability-gated, so no write grant
    // is needed. This is what lets `content_site::list_all_sites` enumerate
    // owned + cached site manifests in one type query.
    grants.push(entity_capability::GrantEntry {
        handlers: entity_capability::PathScope::new(vec![
            "system/tree".into(),
            "system/query".into(),
        ]),
        resources: entity_capability::PathScope::new(vec!["/*/*".into()]),
        operations: entity_capability::IdScope::new(vec![
            "get".into(),
            "find".into(),
            "count".into(),
        ]),
        peers: Some(entity_capability::IdScope::all()),
        constraints: None,
        allowances: None,
    });

    let token = entity_capability::CapabilityToken {
        grants,
        granter: entity_capability::Granter::Single(identity_hash),
        grantee: identity_hash,
        parent: None,
        created_at: now_ms,
        expires_at: None,
        not_before: None,
        delegation_caveats: None,
    };

    let cap_entity = token
        .to_entity()
        .map_err(|e| SdkError::PeerBuild(format!("encode owner self-cap: {}", e)))?;
    content_store
        .put(cap_entity.clone())
        .map_err(|e| SdkError::PeerBuild(format!("persist owner self-cap: {}", e)))?;

    // Sign the cap entity's content hash and persist the signature
    // so chain walkers that resolve granter signatures find them.
    let sig_bytes = keypair.sign(&cap_entity.content_hash.to_bytes());
    let sig_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (entity_ecf::text("algorithm"), entity_ecf::text("ed25519")),
        (
            entity_ecf::text("signature"),
            entity_ecf::Value::Bytes(sig_bytes.to_vec()),
        ),
        (
            entity_ecf::text("signer"),
            entity_ecf::Value::Bytes(identity_hash.to_bytes().to_vec()),
        ),
        (
            entity_ecf::text("target"),
            entity_ecf::Value::Bytes(cap_entity.content_hash.to_bytes().to_vec()),
        ),
    ]));
    let sig_entity = entity_entity::Entity::new(entity_entity::TYPE_SIGNATURE, sig_data)
        .map_err(|e| SdkError::PeerBuild(format!("encode owner self-cap signature: {}", e)))?;
    let cap_hash = cap_entity.content_hash;
    content_store
        .put(sig_entity)
        .map_err(|e| SdkError::PeerBuild(format!("persist owner self-cap signature: {}", e)))?;

    Ok((token, cap_hash))
}

/// Outcome of a binding-safe content-store reclaim
/// ([`PeerContext::content_remove`] / [`content_remove_if_unbound`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentRemoveOutcome {
    /// The blob was unreferenced and has been removed from the store.
    Removed,
    /// Refused: a live path in the location index still binds this hash,
    /// so reaping it would strand that binding. No change.
    StillBound,
    /// The hash was already absent from the content store. No change.
    Absent,
}

/// Remove `hash` from `content_store` **iff** no path in `location_index`
/// currently binds it. The one safe app-level content-store reclaim
/// primitive (GUIDE-GC §3.1): it never reaps a hash with a live tree
/// binding, so a deduped blob shared by another path survives. It does
/// NOT consider the `refs` graph or version history — callers must own a
/// provably single-version slice (e.g. save-state) or defer to kernel GC.
///
/// The binding scan is `O(paths)` (no reverse hash→path index); keep it
/// off hot paths.
pub fn content_remove_if_unbound(
    content_store: &dyn entity_store::ContentStore,
    location_index: &dyn entity_store::LocationIndex,
    hash: &Hash,
) -> ContentRemoveOutcome {
    if location_index.list("").iter().any(|e| &e.hash == hash) {
        return ContentRemoveOutcome::StillBound;
    }
    if content_store.remove(hash) {
        ContentRemoveOutcome::Removed
    } else {
        ContentRemoveOutcome::Absent
    }
}

/// Per-peer handle for entity-native application development.
///
/// Wraps an entity-core-rust Peer with ergonomic methods for tree
/// operations, subscriptions, connections, and handler management.
pub struct PeerContext {
    peer: Peer,
    pub(crate) shared: Arc<PeerShared>,
    peer_id_string: String,
    /// Shared with the event bridge so remote mutations also increment it.
    generation: Arc<AtomicU64>,
    #[allow(dead_code)] // Used by event_bridge; the field read warning is spurious
    wake_fn: WakeFn,
    /// Default grant scope applied to this peer's capability operations.
    /// Not yet enforced — open-grants mode until the capability handler
    /// wires it through. See SDK-OPERATIONS.md §11.2.
    #[allow(dead_code)]
    grants: Option<GrantScope>,
    /// Wildcard owner self-cap stamped onto every local L1 dispatch
    /// as `caller_capability` (SDK-OPERATIONS §11.2A open-grants
    /// progression; matches Go SDK's `mintOwnerSelfCap` pattern).
    /// Constructed once at build time.
    pub(crate) owner_self_cap: entity_capability::CapabilityToken,
    /// Content hash of [`owner_self_cap`] as persisted in the
    /// content-addressable store. Exposed via
    /// [`PeerContext::owner_capability_hash`] for consumers that need
    /// to embed it as a `dispatch_capability` reference (e.g., forward
    /// continuations installed on the local peer). Cross-impl parity
    /// with Go SDK `AppPeer.OwnerCapability()` (Go returns the full
    /// `entity.Entity`; the Rust SDK returns just the hash since that
    /// is what consumers immediately need). Cached at build time to
    /// avoid re-encoding the token on every accessor call.
    pub(crate) owner_capability_hash: Hash,
    /// Storage backend kind recorded at construction. One of
    /// `"sqlite"` / `"memory"` / `"opfs"`. Determined by which builder
    /// path was used: `.sqlite(path)` → "sqlite"; `.opfs(root)` +
    /// `build_async()` (wasm32 + `wasm-persist`) → "opfs"; nothing →
    /// "memory".
    storage_kind: &'static str,
    /// `Some(_)` when `.with_inspect_routing()` was called at build
    /// time; `install_inspect_sink` consults this. `None` → consumer
    /// must opt in before sinks can be attached.
    inspect_registry: Option<crate::inspect::InspectSinkRegistry>,
}

/// Cancels an L0 subscription when dropped.
///
/// Returned by [`StoreAccess::subscribe`]. Hold onto it for the lifetime
/// you want notifications; drop it to stop receiving them. Cancellation
/// is observed by the subscription task on its next loop iteration (when
/// the next event arrives or the broadcast channel signals).
#[must_use = "dropping this handle cancels the subscription immediately"]
#[derive(Debug)]
pub struct SubscriptionHandle {
    cancelled: Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for SubscriptionHandle {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

// L1 subscription types — dispatched via system/subscription + inbox —
// live in `src/subscription.rs`. `PeerContext::subscribe(pattern, cb)` is
// implemented there via an additional impl block.


// ---------------------------------------------------------------------------
// ChangeStream — pull-based watch API (SDK-OPERATIONS.md §6.1)
// ---------------------------------------------------------------------------

/// A single change event delivered by [`ChangeStream`].
#[derive(Debug, Clone)]
pub struct ChangeEvent {
    /// The type of change (put, remove).
    pub event_type: ChangeType,
    /// Absolute path that changed.
    pub path: String,
    /// New content hash (present for puts, absent for removes).
    pub new_hash: Option<Hash>,
}

/// Pull-based stream of tree change events filtered by pattern.
///
/// Created by [`PeerContext::watch()`]. Cancels automatically when dropped.
/// Use [`recv()`](ChangeStream::recv) to await the next matching event.
///
/// Pattern matching: exact path match or prefix with trailing `/*`.
///
/// ```ignore
/// let mut stream = ctx.store().watch("app/browser/*");
/// while let Some(event) = stream.recv().await {
///     println!("changed: {} ({:?})", event.path, event.event_type);
/// }
/// ```
///
/// On WASM, use [`StoreAccess::generation`] for polling-based change
/// detection instead — `watch` requires a tokio runtime.
#[cfg(not(target_arch = "wasm32"))]
pub struct ChangeStream {
    rx: tokio::sync::mpsc::UnboundedReceiver<ChangeEvent>,
    _cancel: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(not(target_arch = "wasm32"))]
impl ChangeStream {
    /// Receive the next change event, or `None` if the stream is closed.
    pub async fn recv(&mut self) -> Option<ChangeEvent> {
        self.rx.recv().await
    }

    /// Try to receive without blocking. Returns `None` if no event is ready.
    pub fn try_recv(&mut self) -> Option<ChangeEvent> {
        self.rx.try_recv().ok()
    }

    /// Cancel the watch explicitly (also happens on drop).
    pub fn cancel(&self) {
        self._cancel.store(true, Ordering::Relaxed);
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Drop for ChangeStream {
    fn drop(&mut self) {
        self._cancel.store(true, Ordering::Relaxed);
    }
}

/// Check if a path matches a watch pattern.
/// Patterns: exact match, or prefix with trailing `/*` for subtree.
fn watch_pattern_matches(pattern: &str, path: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/*") {
        path.starts_with(prefix)
    } else {
        path == pattern
    }
}

// ---------------------------------------------------------------------------
// Peer metadata — SDK-observable configuration only
// ---------------------------------------------------------------------------
//
// Per GUIDE-PEER-CONCERNS-AND-NAMESPACES.md: a peer is defined by its
// handlers, capability grants, tree contents, and identity. The SDK
// carries only facts it directly knows — label, persistence, listen
// addresses. Display classifications (Primary/Local/Remote) and
// app-policy flags (deletable) belong to the application layer, which
// can derive them from SDK facts plus its own policy. See
// `src/peer_display.rs`.

/// SDK-observable metadata describing a peer's configuration.
#[derive(Debug, Clone, Default)]
pub struct PeerMetadata {
    /// Human-readable label for UI display.
    pub label: Option<String>,
    /// Whether this peer's keypair is persisted to disk.
    pub persisted: bool,
    /// Listen addresses this peer serves on (e.g., "ws://127.0.0.1:4042").
    /// Non-empty means the peer accepts inbound connections.
    pub listen_addresses: Vec<String>,
}

// ---------------------------------------------------------------------------
// Capability types — SDK-OPERATIONS.md §11
// ---------------------------------------------------------------------------

/// A single include/exclude filter dimension for grant scoping.
#[derive(Debug, Clone, Default)]
pub struct ScopeFilter {
    /// Patterns to include (e.g., `["system/tree", "system/query"]` or `["*"]`).
    pub include: Vec<String>,
    /// Patterns to exclude (applied after include).
    pub exclude: Vec<String>,
}

/// Grant scope with four dimensions per SDK-OPERATIONS.md §11.2.
///
/// Each dimension specifies include/exclude patterns. Wildcard `"*"` matches
/// everything in that dimension. An empty include list matches nothing.
#[derive(Debug, Clone, Default)]
pub struct GrantScope {
    /// Which handler patterns this grant covers.
    pub handlers: ScopeFilter,
    /// Which operations this grant covers.
    pub operations: ScopeFilter,
    /// Which resource paths this grant covers.
    pub resources: ScopeFilter,
    /// Which peer identities this grant covers.
    pub peers: ScopeFilter,
}

impl GrantScope {
    /// A wildcard grant scope that matches everything (development/debug).
    pub fn wildcard() -> Self {
        let star = ScopeFilter { include: vec!["*".into()], exclude: vec![] };
        Self {
            handlers: star.clone(),
            operations: star.clone(),
            resources: star.clone(),
            peers: star,
        }
    }
}

/// Information about an active grant.
#[derive(Debug, Clone)]
pub struct GrantInfo {
    /// The scope of this grant.
    pub scope: GrantScope,
    /// The peer identity this grant was issued to, if scoped.
    pub grantee: Option<String>,
}

// ---------------------------------------------------------------------------
// EntitySDK — multi-peer container
// ---------------------------------------------------------------------------

/// Multi-peer container managing a collection of PeerContext handles.
///
/// One EntitySDK instance per application. Peers are resources within it.
///
/// `PeerContext`s are stored behind `Arc` so consumers (gdext nodes, egui
/// panel state, future hosts) can extract a shareable handle that
/// outlives a `&self` borrow. `PeerContext` itself is internally
/// `Arc<PeerShared>`-based so this wrap is cheap; `Peer` is not Clone
/// (holds an `AtomicBool` for engine-start gating), so `Arc` is the
/// only way to share. The existing `&PeerContext`-returning surface
/// is preserved via `Arc::as_ref`; the parallel `*_arc` getters are
/// for callers that need the owned handle (Tier 2 multi-peer
/// hosting).
pub struct EntitySDK {
    peers: BTreeMap<String, Arc<PeerContext>>,
    metadata: BTreeMap<String, PeerMetadata>,
    default_peer_id: String,
}

impl EntitySDK {
    /// Create a builder for constructing an EntitySDK instance with a default peer.
    pub fn builder() -> EntitySDKBuilder {
        EntitySDKBuilder::new()
    }

    // -- Peer lifecycle --

    /// Add a new local peer with the given keypair. Returns its peer_id.
    ///
    /// The peer gets a default empty `PeerMetadata`. Call `set_metadata()`
    /// afterward to set a label, persistence flag, or listen addresses.
    pub fn create_peer(
        &mut self,
        keypair: Keypair,
        config: PeerConfig,
        connector: Option<Arc<dyn entity_peer::transport::Connector>>,
    ) -> Result<String, SdkError> {
        self.create_peer_inner(keypair, config, connector, None)
    }

    /// Create a peer with an explicit SQLite-backed tree.
    /// Same as [`create_peer`](Self::create_peer) but the tree is opened
    /// (or created) at `sqlite_path` per `GUIDE-PERSISTENCE.md` §1.
    #[cfg(all(not(target_arch = "wasm32"), feature = "sqlite"))]
    pub fn create_peer_with_sqlite(
        &mut self,
        keypair: Keypair,
        config: PeerConfig,
        connector: Option<Arc<dyn entity_peer::transport::Connector>>,
        sqlite_path: impl Into<std::path::PathBuf>,
    ) -> Result<String, SdkError> {
        self.create_peer_inner(keypair, config, connector, Some(sqlite_path.into()))
    }

    fn create_peer_inner(
        &mut self,
        keypair: Keypair,
        config: PeerConfig,
        connector: Option<Arc<dyn entity_peer::transport::Connector>>,
        #[allow(unused_variables)] sqlite_path: Option<std::path::PathBuf>,
    ) -> Result<String, SdkError> {
        let mut builder = PeerContextBuilder::new().keypair(keypair).config(config);
        if let Some(c) = connector {
            builder = builder.connector(c);
        }
        #[cfg(all(not(target_arch = "wasm32"), feature = "sqlite"))]
        if let Some(p) = sqlite_path {
            builder = builder.sqlite(p);
        }
        let ctx = builder.build()?;
        let id = ctx.peer_id().to_string();
        self.peers.insert(id.clone(), Arc::new(ctx));
        if !self.metadata.contains_key(&id) {
            self.metadata.insert(id.clone(), PeerMetadata::default());
        }
        Ok(id)
    }

    /// Insert a pre-built `PeerContext` into the SDK's peer registry.
    ///
    /// Use this when `PeerContextBuilder` customization (inspectability
    /// hooks per `GUIDE-INSPECTABILITY` v1.2, future builder methods)
    /// exceeds what [`create_peer`](Self::create_peer)'s fixed-parameter
    /// signature exposes. The SDK owns registry + metadata + lifecycle;
    /// the consumer owns construction.
    ///
    /// Default empty [`PeerMetadata`] is installed if no entry exists
    /// for the peer's id. Returns the peer's id on success, or
    /// [`SdkError::Conflict`] with `code = "peer_already_exists"` if a
    /// peer with this id is already registered.
    ///
    /// **Use cases:**
    /// - Multi-peer hosts installing per-peer inspectability hooks
    ///   (Godot's `EntityPeer::start` flow, post-fix)
    /// - Any consumer needing builder configuration beyond `create_peer`'s
    ///   keypair + config + connector triple
    ///
    /// **Coherence note:** the SDK does NOT enforce construction-time
    /// invariants on `PeerContext` today — `create_peer` and
    /// `insert_peer` produce registry-equivalent results modulo the
    /// builder customization the latter permits. If construction
    /// invariants land later, both paths must enforce them.
    pub fn insert_peer(&mut self, ctx: PeerContext) -> Result<String, SdkError> {
        let id = ctx.peer_id().to_string();
        if self.peers.contains_key(&id) {
            return Err(SdkError::Conflict {
                status: status::CONFLICT,
                code: Some("peer_already_exists".into()),
                message: format!("peer with id {} is already registered", id),
            });
        }
        self.peers.insert(id.clone(), Arc::new(ctx));
        self.metadata
            .entry(id.clone())
            .or_insert_with(PeerMetadata::default);
        Ok(id)
    }

    /// Same as [`insert_peer`](Self::insert_peer) but installs caller-
    /// supplied [`PeerMetadata`] instead of the default. The metadata
    /// overrides any existing entry for this peer (rare — only relevant
    /// when a backend-peer registration preceded the local context).
    pub fn insert_peer_with_metadata(
        &mut self,
        ctx: PeerContext,
        metadata: PeerMetadata,
    ) -> Result<String, SdkError> {
        let id = ctx.peer_id().to_string();
        if self.peers.contains_key(&id) {
            return Err(SdkError::Conflict {
                status: status::CONFLICT,
                code: Some("peer_already_exists".into()),
                message: format!("peer with id {} is already registered", id),
            });
        }
        self.peers.insert(id.clone(), Arc::new(ctx));
        self.metadata.insert(id.clone(), metadata);
        Ok(id)
    }

    /// Look up a peer by ID. Returns a borrow tied to `&self`. For
    /// consumers that need an owned shareable handle (e.g., gdext
    /// classes holding a peer across an async boundary), use
    /// [`peer_arc`](Self::peer_arc) instead.
    pub fn peer(&self, peer_id: &str) -> Option<&PeerContext> {
        self.peers.get(peer_id).map(Arc::as_ref)
    }

    /// Look up a peer by ID, returning an owned `Arc<PeerContext>`.
    /// Used by Tier 2 multi-peer-hosting consumers — gdext classes
    /// that need to hold a peer beyond a `&self` borrow.
    pub fn peer_arc(&self, peer_id: &str) -> Option<Arc<PeerContext>> {
        self.peers.get(peer_id).cloned()
    }

    /// Register a remote peer (no local PeerContext — accessed via protocol).
    /// The peer is tracked by metadata only. Returns false if the peer_id
    /// already exists (as a local peer or another remote peer).
    pub fn register_backend_peer(&mut self, peer_id: String, metadata: PeerMetadata) -> bool {
        if self.peers.contains_key(&peer_id) || self.metadata.contains_key(&peer_id) {
            return false;
        }
        self.metadata.insert(peer_id, metadata);
        true
    }

    /// Remove a peer by ID. Returns false if the peer doesn't exist or
    /// is the SDK's default peer (which must always be present).
    ///
    /// The SDK gates only its own invariant (default peer exists); any
    /// user-facing deletion policy (e.g., "the user can't delete their
    /// primary identity") is the application's responsibility — see
    /// `peer_display::is_user_deletable`.
    pub fn remove_peer(&mut self, peer_id: &str) -> bool {
        if peer_id == self.default_peer_id {
            return false;
        }
        let had_metadata = self.metadata.remove(peer_id).is_some();
        self.peers.remove(peer_id);
        had_metadata
    }

    /// List all managed peer IDs — both local (PeerContext) and backend
    /// (metadata-only). Sorted deterministically (BTreeMap keys).
    pub fn peer_ids(&self) -> Vec<&str> {
        // metadata is the superset: local peers have entries in both
        // peers + metadata, backend peers only in metadata.
        let mut ids: Vec<&str> = self.metadata.keys().map(|s| s.as_str()).collect();
        // Also include any peers that might not have metadata yet
        // (defensive — shouldn't happen in normal operation).
        for k in self.peers.keys() {
            if !self.metadata.contains_key(k) {
                ids.push(k.as_str());
            }
        }
        ids.sort();
        ids.dedup();
        ids
    }

    /// Whether this peer has a local PeerContext (vs being a protocol-only
    /// backend peer). Use this to decide if direct tree access is available.
    pub fn has_peer_context(&self, peer_id: &str) -> bool {
        self.peers.contains_key(peer_id)
    }

    /// Get metadata for a peer.
    pub fn peer_metadata(&self, peer_id: &str) -> Option<&PeerMetadata> {
        self.metadata.get(peer_id)
    }

    /// Set metadata for a peer.
    pub fn set_metadata(&mut self, peer_id: &str, meta: PeerMetadata) {
        self.metadata.insert(peer_id.to_string(), meta);
    }

    /// Update only the `label` field of `peer_id`'s metadata,
    /// preserving `persisted` and `listen_addresses`. Composes with
    /// the rename-action UX (peer-management panel) without forcing
    /// callers through a read-modify-write dance that loses atomicity
    /// if anything else mutates the metadata between steps.
    ///
    /// Creates a metadata entry with the label set if `peer_id` doesn't
    /// have one yet — matches the "treat unknown as fresh write" shape
    /// of [`set_metadata`]. Caller can preflight with
    /// [`peer_metadata`] if "no-op on unknown" semantics are wanted.
    pub fn set_peer_label(&mut self, peer_id: &str, label: Option<String>) {
        if let Some(meta) = self.metadata.get_mut(peer_id) {
            meta.label = label;
        } else {
            self.metadata.insert(
                peer_id.to_string(),
                PeerMetadata {
                    label,
                    ..PeerMetadata::default()
                },
            );
        }
    }

    /// The default (first-created) peer.
    pub fn default_peer(&self) -> &PeerContext {
        self.peers.get(&self.default_peer_id)
            .map(Arc::as_ref)
            .expect("default peer must exist")
    }

    /// The default (first-created) peer as an owned `Arc<PeerContext>`.
    /// Mirrors [`peer_arc`](Self::peer_arc) for the default case.
    pub fn default_peer_arc(&self) -> Arc<PeerContext> {
        self.peers
            .get(&self.default_peer_id)
            .cloned()
            .expect("default peer must exist")
    }

    /// The default peer's ID.
    pub fn default_peer_id(&self) -> &str {
        &self.default_peer_id
    }

    /// Aggregated generation counter across all peers.
    pub fn generation(&self) -> u64 {
        self.peers.values().map(|ctx| ctx.store().generation()).sum()
    }

    // -- Flat per-peer surface (mirrors WorkerProxy's shape) --
    //
    // These delegate to the resolved `PeerContext`. They exist so the
    // Direct arm presents the SAME call shape as `WorkerProxy`: flat,
    // `peer_id`-first, uniformly `async`, unknown-peer → typed error
    // (never a silent default-to-primary). Consumers hosting both arms
    // can hold one abstraction and stop branching on the arm.
    //
    // Type parity is intentional only at the *shape* level — the Direct
    // arm keeps native `Entity` / `SdkError`; the Worker arm keeps
    // `WireEntity` / `ProxyError`. Bridging native↔wire stays the
    // consumer's job; bridging handle↔string-key no longer is.
    //
    // Op set tracks `L1_WORKER_MIRRORED_SURFACE`. Subscribe/Unsubscribe
    // are deferred: the L1 dispatched-subscription signature is heavy and
    // consumer prefix observation already has cross-arm parity via
    // `StoreAccess::on_prefix_change[_seeded]` / `WorkerProxy::observe[_with_events]`.

    /// Resolve a peer by id or fail loudly. The deliberate replacement
    /// for "look up, fall back to primary on miss" — an unknown peer is
    /// a typed error the caller must handle, not a silent misroute.
    fn peer_or_err(&self, peer_id: &str) -> Result<&PeerContext, SdkError> {
        self.peers
            .get(peer_id)
            .map(Arc::as_ref)
            .ok_or_else(|| SdkError::UnknownPeer(peer_id.to_string()))
    }

    // -- Detached-future ops (own everything; no `&self` borrow escapes) --
    //
    // These are `fn -> impl Future + 'static`, NOT `async fn(&self)`. An
    // `async fn(&self)` future borrows `&self` for its whole life, so it
    // cannot be boxed into the `Pin<Box<dyn Future + 'static>>` a
    // consumer's detached/spawned per-peer boundary needs. We resolve the
    // peer synchronously, hand the resolution `Result` into the returned
    // future, and delegate to `PeerContext`'s already-owning futures
    // (`put`/`execute`/`query`/`count` clone the `shared` Arc and never
    // touch `&self.peer`). Mirrors `PeerContext::execute` (sdk.rs ~1566).
    // Send-ness flows through `impl Trait` automatically: native callers
    // get a `Send` future (the delegated PeerContext future is `Send`),
    // wasm callers don't need it.

    /// Put `entity` at `path` on `peer_id`'s tree. Returns the content
    /// hash. Detached: the returned future owns its state.
    pub fn put(
        &self,
        peer_id: &str,
        path: &str,
        entity: Entity,
    ) -> impl std::future::Future<Output = Result<Hash, SdkError>> + 'static {
        let resolved = self
            .peer_or_err(peer_id)
            .map(|pc| pc.put(path.to_string(), entity));
        async move { resolved?.await }
    }

    /// Dispatch `handler`/`operation` on `peer_id`. Raw `HandlerResult`;
    /// caller maps status. Detached.
    pub fn execute(
        &self,
        peer_id: &str,
        handler: impl Into<String>,
        operation: impl Into<String>,
        params: Entity,
        opts: entity_handler::ExecuteOptions,
    ) -> impl std::future::Future<Output = Result<entity_handler::HandlerResult, SdkError>> + 'static
    {
        let resolved = self
            .peer_or_err(peer_id)
            .map(|pc| pc.execute(handler, operation, params, opts));
        async move { resolved?.await }
    }

    /// L1 query against `peer_id` (`system/query` `find`). Detached.
    pub fn query(
        &self,
        peer_id: &str,
        expression: Entity,
    ) -> impl std::future::Future<Output = Result<QueryResults, SdkError>> + 'static {
        let resolved = self.peer_or_err(peer_id).map(|pc| pc.query(expression));
        async move { resolved?.await }
    }

    /// L1 count against `peer_id` (`system/query` `count`). Detached.
    pub fn count(
        &self,
        peer_id: &str,
        expression: Entity,
    ) -> impl std::future::Future<Output = Result<u64, SdkError>> + 'static {
        let resolved = self.peer_or_err(peer_id).map(|pc| pc.count(expression));
        async move { resolved?.await }
    }

    /// Handlers registered on `peer_id`. Sync underneath; returned as a
    /// detached ready future for cross-arm shape parity.
    pub fn discover_handlers(
        &self,
        peer_id: &str,
    ) -> impl std::future::Future<Output = Result<Vec<HandlerInfo>, SdkError>> + 'static {
        let r = self.peer_or_err(peer_id).map(|pc| pc.discover_handlers());
        async move { r }
    }

    /// Types registered on `peer_id`. Sync underneath; detached ready
    /// future for parity.
    pub fn discover_types(
        &self,
        peer_id: &str,
    ) -> impl std::future::Future<Output = Result<Vec<TypeInfo>, SdkError>> + 'static {
        let r = self.peer_or_err(peer_id).map(|pc| pc.discover_types());
        async move { r }
    }

    /// Total entities in `peer_id`'s content store. Sync + O(1); detached
    /// ready future for parity.
    pub fn entity_count(
        &self,
        peer_id: &str,
    ) -> impl std::future::Future<Output = Result<usize, SdkError>> + 'static {
        let r = self.peer_or_err(peer_id).map(|pc| pc.entity_count());
        async move { r }
    }

    /// Total paths in `peer_id`'s location index. Sync + O(1); detached
    /// ready future for parity.
    pub fn path_count(
        &self,
        peer_id: &str,
    ) -> impl std::future::Future<Output = Result<usize, SdkError>> + 'static {
        let r = self.peer_or_err(peer_id).map(|pc| pc.path_count());
        async move { r }
    }

    /// Pending inbox entries on `peer_id` (SDK-EXTENSION-OPERATIONS §7).
    /// Sync underneath; detached ready future for parity.
    pub fn inbox_list(
        &self,
        peer_id: &str,
    ) -> impl std::future::Future<Output = Result<Vec<LocationEntry>, SdkError>> + 'static {
        let r = self.peer_or_err(peer_id).map(|pc| pc.inbox_list());
        async move { r }
    }

    /// Read a specific inbox delivery on `peer_id` by path relative to
    /// `system/inbox/`. Sync underneath; detached ready future for parity.
    pub fn inbox_get(
        &self,
        peer_id: &str,
        relative_path: &str,
    ) -> impl std::future::Future<Output = Result<Option<Entity>, SdkError>> + 'static {
        let r = self
            .peer_or_err(peer_id)
            .map(|pc| pc.inbox_get(relative_path));
        async move { r }
    }

    /// Storage backend kind for `peer_id`'s PeerContext — one of
    /// `"sqlite"` / `"memory"` / `"opfs"`. See
    /// [`PeerContext::storage_kind`]. Returns `None` if `peer_id` isn't
    /// known to this SDK.
    pub fn storage_kind(&self, peer_id: &str) -> Option<&'static str> {
        self.peers.get(peer_id).map(|pc| pc.storage_kind())
    }

    /// Substrate-bridge extensions installed on `peer_id`. See
    /// [`PeerContext::installed_extensions`]. Returns `None` if
    /// `peer_id` isn't known to this SDK.
    ///
    /// Today every PeerContext returns the same list; per-peer subsets
    /// are Tier 2. Callers wanting "what could be enabled at all" can
    /// reach [`crate::installed_extensions`] directly without a peer.
    pub fn installed_extensions(&self, peer_id: &str) -> Option<Vec<&'static str>> {
        self.peers.get(peer_id).map(|pc| pc.installed_extensions())
    }

    /// Deliver `params` to the inbox at `target_path` via `peer_id`'s
    /// PeerContext. See [`PeerContext::inbox_send`]. Detached.
    pub fn inbox_send(
        &self,
        peer_id: &str,
        target_path: impl Into<String>,
        params: Entity,
        request_id: Option<String>,
    ) -> impl std::future::Future<Output = Result<String, SdkError>> + 'static {
        let target_path = target_path.into();
        let resolved = self
            .peer_or_err(peer_id)
            .map(|pc| pc.inbox_send(target_path, params, request_id));
        async move { resolved?.await }
    }

    // -- Borrowing data ops (NOT detached) --
    //
    // `get`/`list`/`remove`/`has`/`put_cas` delegate to `PeerContext`
    // methods that are themselves `async fn(&self)` (they use
    // `self.peer.execute_with_options(...)` directly — `Peer` is not
    // `Clone`). They cannot become owning `'static` futures without
    // first reworking those `PeerContext` methods to route through
    // `make_execute_fn(shared)` like `put` does. That is a larger,
    // separate change and is NOT in the consumer's scoped §4.1b ask
    // (which is execute/query/count/put/discover). Left as `async fn`
    // deliberately; if a consumer needs these detached too, that is a
    // follow-up with the PeerContext-rework scope acknowledged.

    /// Get entity at `path` on `peer_id`'s tree. `Ok(None)` = no binding.
    /// Borrows `&self` across the await — not detachable (see note above).
    pub async fn get(&self, peer_id: &str, path: &str) -> Result<Option<Entity>, SdkError> {
        self.peer_or_err(peer_id)?.get(path).await
    }

    /// Compare-and-swap put (SDK-OPERATIONS §3.2). Borrows `&self`.
    pub async fn put_cas(
        &self,
        peer_id: &str,
        path: &str,
        entity: Entity,
        expected: Option<Hash>,
    ) -> Result<Hash, SdkError> {
        self.peer_or_err(peer_id)?.put_cas(path, entity, expected).await
    }

    /// List immediate children under `prefix` on `peer_id`'s tree.
    /// Borrows `&self`.
    pub async fn list(
        &self,
        peer_id: &str,
        prefix: &str,
    ) -> Result<Vec<ListingEntry>, SdkError> {
        self.peer_or_err(peer_id)?.list(prefix).await
    }

    /// Remove the binding at `path` on `peer_id`'s tree. `Ok(false)` if
    /// nothing was bound. Borrows `&self`.
    pub async fn remove(&self, peer_id: &str, path: &str) -> Result<bool, SdkError> {
        self.peer_or_err(peer_id)?.remove(path).await
    }

    /// Whether `path` has a binding on `peer_id`'s tree. Borrows `&self`.
    pub async fn has(&self, peer_id: &str, path: &str) -> Result<bool, SdkError> {
        self.peer_or_err(peer_id)?.has(path).await
    }
}

/// Builder for EntitySDK (creates the container with one default peer).
pub struct EntitySDKBuilder {
    keypair: Option<Keypair>,
    config: Option<PeerConfig>,
    connector: Option<Arc<dyn entity_peer::transport::Connector>>,
    grants: Option<GrantScope>,
    #[cfg(all(target_arch = "wasm32", feature = "wasm-persist"))]
    opfs_root: Option<String>,
    /// IndexedDB database name for a write-behind durable default peer
    /// (WASM main thread or worker). Mirrors `PeerContextBuilder::idb`.
    /// Requires `build_async()`.
    #[cfg(all(target_arch = "wasm32", feature = "wasm-idb-persist"))]
    idb_name: Option<String>,
    /// Inspectability hooks (GUIDE-INSPECTABILITY v1.2 §2.1) registered
    /// for the default peer. Pass-through to `PeerContextBuilder`'s
    /// equivalent setters at build time. Multi-peer hosts that want to
    /// install hooks on additional peers use `PeerContextBuilder` +
    /// `EntitySDK::insert_peer` directly — only the default peer flows
    /// through this builder.
    dispatch_hooks: Vec<(String, Arc<dyn Fn(&DispatchEvent) + Send + Sync>)>,
    wire_hooks: Vec<(String, Arc<dyn Fn(&WireEvent) + Send + Sync>)>,
    binding_hooks: Vec<(String, Arc<dyn Fn(&TreeChangeEvent) + Send + Sync>)>,
    /// Enables consumer-side `InspectSink` routing on the default peer.
    /// Forwarded to `PeerContextBuilder::with_inspect_routing` at build
    /// time.
    inspect_routing: bool,
    /// Connect-handler grant resolver for the default peer
    /// (EXTENSION-ROLE §4.7 mechanism). Forwarded to
    /// `PeerContextBuilder::with_grant_resolver` at build time. Per
    /// Godot ask D2.
    grant_resolver: Option<entity_peer::GrantResolver>,
}

impl EntitySDKBuilder {
    pub fn new() -> Self {
        Self {
            keypair: None,
            config: None,
            connector: None,
            grants: None,
            #[cfg(all(target_arch = "wasm32", feature = "wasm-persist"))]
            opfs_root: None,
            #[cfg(all(target_arch = "wasm32", feature = "wasm-idb-persist"))]
            idb_name: None,
            dispatch_hooks: Vec::new(),
            wire_hooks: Vec::new(),
            binding_hooks: Vec::new(),
            inspect_routing: false,
            grant_resolver: None,
        }
    }

    /// Enable inspect-sink routing for the default peer. Forwarded to
    /// [`PeerContextBuilder::with_inspect_routing`]. See that method for
    /// cost semantics (zero when no sinks attached).
    pub fn with_inspect_routing(mut self) -> Self {
        self.inspect_routing = true;
        self
    }

    /// Install a connect-handler grant resolver for the default peer.
    /// Forwarded to [`PeerContextBuilder::with_grant_resolver`] at
    /// build time. See that method for the closure signature and
    /// fallback semantics.
    pub fn with_grant_resolver<F>(mut self, resolver: F) -> Self
    where
        F: Fn(&entity_crypto::PeerId, &Hash) -> Option<Vec<entity_capability::GrantEntry>>
            + Send
            + Sync
            + 'static,
    {
        self.grant_resolver = Some(Arc::new(resolver));
        self
    }

    /// Register an observe-only dispatch hook for the default peer
    /// (GUIDE-INSPECTABILITY v1.2 §2.1 #3). Forwarded to
    /// `PeerContextBuilder::with_dispatch_hook` at build time.
    pub fn with_dispatch_hook<F>(mut self, name: impl Into<String>, f: F) -> Self
    where
        F: Fn(&DispatchEvent) + Send + Sync + 'static,
    {
        self.dispatch_hooks.push((name.into(), Arc::new(f)));
        self
    }

    /// Register an observe-only wire hook for the default peer
    /// (GUIDE-INSPECTABILITY v1.2 §2.1 #5). Forwarded to
    /// `PeerContextBuilder::with_wire_hook` at build time.
    pub fn with_wire_hook<F>(mut self, name: impl Into<String>, f: F) -> Self
    where
        F: Fn(&WireEvent) + Send + Sync + 'static,
    {
        self.wire_hooks.push((name.into(), Arc::new(f)));
        self
    }

    /// Register an observe-only binding hook for the default peer
    /// (GUIDE-INSPECTABILITY v1.2 §2.1 #2). Forwarded to
    /// `PeerContextBuilder::with_binding_hook` at build time.
    pub fn with_binding_hook<F>(mut self, name: impl Into<String>, f: F) -> Self
    where
        F: Fn(&TreeChangeEvent) + Send + Sync + 'static,
    {
        self.binding_hooks.push((name.into(), Arc::new(f)));
        self
    }

    /// Use an existing keypair for the default peer.
    #[allow(dead_code)]
    pub fn keypair(mut self, keypair: Keypair) -> Self {
        self.keypair = Some(keypair);
        self
    }

    /// Generate a new random keypair for the default peer.
    pub fn generate_keypair(mut self) -> Self {
        self.keypair = Some(Keypair::generate());
        self
    }

    /// Set peer configuration for the default peer.
    pub fn config(mut self, config: PeerConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Set the transport connector.
    pub fn connector(mut self, connector: Arc<dyn entity_peer::transport::Connector>) -> Self {
        self.connector = Some(connector);
        self
    }

    /// Set the default grant scope for the default peer
    /// (SDK-OPERATIONS.md §11.2). Not yet enforced.
    #[allow(dead_code)]
    pub fn grants(mut self, grants: GrantScope) -> Self {
        self.grants = Some(grants);
        self
    }

    /// Enable OPFS-backed durable storage for the default peer (WASM
    /// worker only). `root` is the OPFS subdirectory hosting the
    /// journals; multiple OPFS-backed peers in the same origin MUST use
    /// distinct roots. Requires `build_async()`; sync `build()` errors if
    /// this is set. Mirrors `PeerContextBuilder::opfs`.
    #[cfg(all(target_arch = "wasm32", feature = "wasm-persist"))]
    pub fn opfs(mut self, root: impl Into<String>) -> Self {
        self.opfs_root = Some(root.into());
        self
    }

    /// Enable IndexedDB-backed durable storage for the default peer (WASM
    /// main thread or worker). `name` is the IndexedDB database name;
    /// multiple IDB-backed peers in the same origin MUST use distinct
    /// names. Requires `build_async()`; sync `build()` errors if this is
    /// set. Mirrors `PeerContextBuilder::idb`.
    #[cfg(all(target_arch = "wasm32", feature = "wasm-idb-persist"))]
    pub fn idb(mut self, name: impl Into<String>) -> Self {
        self.idb_name = Some(name.into());
        self
    }

    /// Build the EntitySDK with one default PeerContext.
    ///
    /// **OPFS/IDB callers:** if you called `.opfs()` or `.idb()`, use
    /// `build_async()`.
    pub fn build(self) -> Result<EntitySDK, SdkError> {
        #[cfg(all(target_arch = "wasm32", feature = "wasm-persist"))]
        if self.opfs_root.is_some() {
            return Err(SdkError::PeerBuild(
                "opfs() was set; call build_async() instead of build()".into(),
            ));
        }
        #[cfg(all(target_arch = "wasm32", feature = "wasm-idb-persist"))]
        if self.idb_name.is_some() {
            return Err(SdkError::PeerBuild(
                "idb() was set; call build_async() instead of build()".into(),
            ));
        }
        let ctx_builder = self.make_context_builder()?;
        let ctx = ctx_builder.build()?;
        Self::finalize(ctx)
    }

    /// Async-aware variant. Available on wasm32; always callable so the
    /// worker host can `.build_async().await` unconditionally. Calls
    /// `PeerContextBuilder::build_async()` internally, which awaits OPFS
    /// handle acquisition when `.opfs()` was set.
    #[cfg(target_arch = "wasm32")]
    pub async fn build_async(self) -> Result<EntitySDK, SdkError> {
        let ctx_builder = self.make_context_builder()?;
        let ctx = ctx_builder.build_async().await?;
        Self::finalize(ctx)
    }

    fn make_context_builder(self) -> Result<PeerContextBuilder, SdkError> {
        let mut b = PeerContextBuilder::new();
        if let Some(kp) = self.keypair {
            b = b.keypair(kp);
        } else {
            return Err(SdkError::NoKeypair);
        }
        if let Some(config) = self.config {
            b = b.config(config);
        }
        if let Some(connector) = self.connector {
            b = b.connector(connector);
        }
        if let Some(grants) = self.grants {
            b = b.grants(grants);
        }
        #[cfg(all(target_arch = "wasm32", feature = "wasm-persist"))]
        if let Some(root) = self.opfs_root {
            b = b.opfs(root);
        }
        #[cfg(all(target_arch = "wasm32", feature = "wasm-idb-persist"))]
        if let Some(name) = self.idb_name {
            b = b.idb(name);
        }
        for (name, hook) in self.dispatch_hooks {
            let hook = hook.clone();
            b = b.with_dispatch_hook(name, move |event| hook(event));
        }
        for (name, hook) in self.wire_hooks {
            let hook = hook.clone();
            b = b.with_wire_hook(name, move |event| hook(event));
        }
        for (name, hook) in self.binding_hooks {
            let hook = hook.clone();
            b = b.with_binding_hook(name, move |event| hook(event));
        }
        if self.inspect_routing {
            b = b.with_inspect_routing();
        }
        if let Some(resolver) = self.grant_resolver {
            // Forward the already-Arc-ed resolver into the lower
            // builder. The closure adapter just calls through.
            b = b.with_grant_resolver(move |pid, hash| resolver(pid, hash));
        }
        Ok(b)
    }

    fn finalize(ctx: PeerContext) -> Result<EntitySDK, SdkError> {
        let default_peer_id = ctx.peer_id().to_string();
        let mut peers = BTreeMap::new();
        peers.insert(default_peer_id.clone(), Arc::new(ctx));
        let mut metadata = BTreeMap::new();
        metadata.insert(default_peer_id.clone(), PeerMetadata::default());
        Ok(EntitySDK {
            peers,
            metadata,
            default_peer_id,
        })
    }
}

impl PeerContext {
    /// Create a builder for constructing a PeerContext instance.
    pub fn builder() -> PeerContextBuilder {
        PeerContextBuilder::new()
    }

    // -- Identity --

    /// This peer's ID as a string.
    pub fn peer_id(&self) -> &str {
        &self.peer_id_string
    }

    /// This peer's identity-entity content hash (V7 §3.6 grantee form
    /// — 33-byte `system/hash`). Use for capability `grantee` fields,
    /// role-extension peer segments, attestation `subject` fields, and
    /// any other surface that names this peer in hash form rather than
    /// peer-id-string form.
    pub fn identity_hash(&self) -> entity_hash::Hash {
        self.shared.identity_hash
    }

    /// Content hash of this peer's SDK-minted owner capability — the
    /// wildcard self-cap stamped onto every local L1 dispatch as
    /// `caller_capability` (SDK-OPERATIONS §11.2A open-grants
    /// progression).
    ///
    /// Use for surfaces that embed a `dispatch_capability` hash
    /// referencing the writer's authority — most commonly forward
    /// continuations installed locally, where the natural fit is the
    /// owner capability (wildcard authority that walks to self).
    /// Without this accessor consumers can't construct a single-peer
    /// continuation entity without round-tripping through capability
    /// minting.
    ///
    /// Cross-impl parity: Go SDK exposes `AppPeer.OwnerCapability()
    /// entity.Entity` (entity-workbench-go entitysdk/app.go:97). The
    /// Rust SDK returns just the hash since that is what every Godot
    /// consumer immediately extracts; if a future consumer needs the
    /// full capability entity, fetch it back via
    /// `ctx.store().get(hash)` or add a sibling `owner_capability()
    /// -> Entity` accessor.
    ///
    /// Cached at build time — the cap is minted, persisted, and its
    /// hash captured once in `PeerContextBuilder::build`. Constant-time
    /// read; no allocation.
    pub fn owner_capability_hash(&self) -> Hash {
        self.owner_capability_hash
    }

    /// Substrate-bridge extensions installed on this peer. Delegates
    /// to [`crate::installed_extensions`] today — every PeerContext
    /// built in the same process sees the same compile-time-fixed set.
    /// Kept as a `&self` method for Tier 2 forward-compat (when
    /// per-peer `Config.extensions` lets spawned peers carry distinct
    /// subsets).
    pub fn installed_extensions(&self) -> Vec<&'static str> {
        crate::installed_extensions()
    }

    /// Storage backend kind chosen at construction. One of:
    /// - `"sqlite"` — `PeerContextBuilder::sqlite(path)` (native +
    ///   `feature = "sqlite"`).
    /// - `"opfs"` — `PeerContextBuilder::opfs(root)` + `build_async()`
    ///   (wasm32 + `feature = "wasm-persist"`).
    /// - `"memory"` — the default path (no `.sqlite()` / `.opfs()`
    ///   call), or any platform where the feature gating that exposes
    ///   the persistent backend isn't compiled in.
    ///
    /// Fixed at build time; reads are sync and cheap. Callers should
    /// treat the return as an opaque token suitable for UI display +
    /// roster persistence — additional backends (e.g. redb, sled) may
    /// appear here in the future, so `match` arms should keep a
    /// catch-all rather than panicking on unknown.
    pub fn storage_kind(&self) -> &'static str {
        self.storage_kind
    }

    /// The IndexedDB checkpoint handle, when this peer was built with
    /// [`PeerContextBuilder::idb`]. `None` for every other backend
    /// (memory / sqlite / opfs).
    ///
    /// Identity/destructive ops that cannot tolerate write-behind loss
    /// (create-peer, delete-peer, config commit) `await` `checkpoint()`
    /// on this handle before acknowledging, so durability does not depend
    /// on the debounce timer. Incidental writes ride the write-behind
    /// debounce and need not call it. See `core/store/src/idb.rs`.
    #[cfg(all(target_arch = "wasm32", feature = "wasm-idb-persist"))]
    pub fn idb_checkpoint(&self) -> Option<&entity_store::idb::IdbCheckpoint> {
        self.peer.idb_checkpoint()
    }

    /// The default grant scope configured for this peer, if any.
    ///
    /// Not yet enforced — open-grants mode today. The slot exists so
    /// callers can write against it before enforcement lands.
    #[allow(dead_code)]
    pub fn grants(&self) -> Option<&GrantScope> {
        self.grants.as_ref()
    }

    /// Register an observe-only callback receiving marshalled
    /// `InspectFact` values for this peer. Both arms of the consumer
    /// router (Direct here, Worker via
    /// `entity_wasm_worker_proxy::WorkerProxy::install_inspect_sink`)
    /// produce the same shape.
    ///
    /// **Requires** `PeerContextBuilder::with_inspect_routing()` (or
    /// `EntitySDKBuilder::with_inspect_routing()`) at build time —
    /// otherwise returns `Err(SdkError::PeerBuild)`.
    ///
    /// Dropping the returned handle detaches the sink synchronously.
    /// First sink attached / last sink detached are no-ops on the
    /// Direct arm (the demuxer hooks are always installed when routing
    /// is enabled); they're cheap because an empty registry early-returns.
    pub fn install_inspect_sink<F>(&self, sink: F) -> Result<crate::inspect::InspectSinkHandle, SdkError>
    where
        F: Fn(&crate::inspect::InspectFact) + Send + Sync + 'static,
    {
        let registry = self.inspect_registry.as_ref().ok_or_else(|| {
            SdkError::PeerBuild(
                "install_inspect_sink requires .with_inspect_routing() at build time".into(),
            )
        })?;
        let id = registry.register(Arc::new(sink));
        Ok(crate::inspect::InspectSinkHandle::new(registry.clone(), id))
    }

    /// Mint a single-sig self-capability scoped to `grants` and
    /// persist the cap entity + its signature in the local content
    /// store. Returns the cap entity; its `content_hash` is suitable
    /// as the `dispatch_capability` on continuations the local peer
    /// installs.
    ///
    /// **Why not use the owner self-cap?** That cap is wildcard
    /// across all four grant dimensions. Using it as
    /// `dispatch_capability` on a chain means any step in the chain
    /// — and any peer participating in cross-peer delivery — can
    /// act with the full peer's authority. That's drastic overreach
    /// for a chain that only needs scoped access. Owner-cap is fine
    /// for development; chains in real deployments need scoped caps
    /// (the substrate is exercised the way prod peers depend on it).
    ///
    /// **Granter / grantee shape.** Self-cap: granter == grantee ==
    /// local peer's identity hash. The chain installer's identity
    /// (also local) appears in the cap's authority chain by
    /// construction, so the R1 creator-authorization check at
    /// continuation install time (EXTENSION-CONTINUATION §3.2 step 4)
    /// passes.
    ///
    /// **Persistence and revocation.** The cap is content-addressed
    /// + content-store-persisted; its signature lands as a sibling
    /// entity. This helper does **not** bind the cap at a tree path
    /// — use [`mint_chain_capability_bound`](Self::mint_chain_capability_bound)
    /// when you need V7 §5.1 `is_revoked` walks to find the root.
    ///
    /// Returns `Err(SdkError::HandlerError(...))` for an empty
    /// `grants` list or any encode/persist failure.
    ///
    /// Matches Go SDK's `AppPeer.MintChainCapability` in
    /// `workbench-go/entitysdk/capability_mint.go:56`.
    pub fn mint_chain_capability(
        &self,
        grants: Vec<entity_capability::GrantEntry>,
    ) -> Result<Entity, SdkError> {
        if grants.is_empty() {
            return Err(SdkError::HandlerError(
                "mint_chain_capability requires at least one grant".into(),
            ));
        }
        let identity_hash = self.shared.identity_hash;
        let now_ms = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let token = entity_capability::CapabilityToken {
            grants,
            granter: entity_capability::Granter::Single(identity_hash),
            grantee: identity_hash,
            parent: None,
            created_at: now_ms,
            expires_at: None,
            not_before: None,
            delegation_caveats: None,
        };

        let cap_entity = token
            .to_entity()
            .map_err(|e| SdkError::HandlerError(format!("encode chain cap: {}", e)))?;
        self.shared
            .content_store
            .put(cap_entity.clone())
            .map_err(|e| SdkError::HandlerError(format!("persist chain cap: {}", e)))?;

        // Sign the cap's content hash and persist the signature so
        // chain-walk validators (V7 §5.5) can resolve the sibling
        // signature reference.
        let sig_bytes = self.shared.keypair.sign(&cap_entity.content_hash.to_bytes());
        let sig_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("algorithm"), entity_ecf::text("ed25519")),
            (
                entity_ecf::text("signature"),
                entity_ecf::Value::Bytes(sig_bytes.to_vec()),
            ),
            (
                entity_ecf::text("signer"),
                entity_ecf::Value::Bytes(identity_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("target"),
                entity_ecf::Value::Bytes(cap_entity.content_hash.to_bytes().to_vec()),
            ),
        ]));
        let sig_entity = Entity::new(entity_entity::TYPE_SIGNATURE, sig_data)
            .map_err(|e| SdkError::HandlerError(format!("encode chain cap signature: {}", e)))?;
        self.shared
            .content_store
            .put(sig_entity)
            .map_err(|e| SdkError::HandlerError(format!("persist chain cap signature: {}", e)))?;

        Ok(cap_entity)
    }

    /// Bound variant of [`mint_chain_capability`](Self::mint_chain_capability):
    /// mints the cap and binds it at `tree_path` so V7 §5.1
    /// `is_revoked` walks can find the root. Use for chains whose
    /// dispatch caps are long-lived.
    ///
    /// Convention: `system/capability/grants/chain/{chain-id}` keeps
    /// chain caps under a discoverable subtree. The path is opaque
    /// to the capability system itself (V7 §5.1 calls it
    /// implementation-defined for non-handler-grant capabilities).
    ///
    /// Matches Go SDK's `AppPeer.MintChainCapabilityBound` in
    /// `workbench-go/entitysdk/capability_mint.go:110`.
    pub fn mint_chain_capability_bound(
        &self,
        grants: Vec<entity_capability::GrantEntry>,
        tree_path: impl Into<String>,
    ) -> Result<Entity, SdkError> {
        let tree_path = tree_path.into();
        if tree_path.is_empty() {
            return Err(SdkError::HandlerError(
                "mint_chain_capability_bound requires a non-empty tree path".into(),
            ));
        }
        let cap_entity = self.mint_chain_capability(grants)?;
        self.shared
            .location_index
            .set(&tree_path, cap_entity.content_hash);
        Ok(cap_entity)
    }

    // -- Typed extension wrappers --
    //
    // Per SDK-EXTENSION-OPERATIONS.md §1 (v0.7): typed, discoverable
    // wrappers around `execute()`. One accessor per extension that
    // owns a normative L1 surface; the accessor returns a scope handle
    // whose methods translate typed args into `execute()` calls.

    /// Typed accessor for `system/attestation` operations (create /
    /// supersede / revoke / verify). See
    /// [`crate::attestation::AttestationOps`]. Available only when
    /// the `attestation` feature is enabled.
    #[cfg(feature = "attestation")]
    pub fn attestation(&self) -> crate::attestation::AttestationOps<'_> {
        crate::attestation::AttestationOps::new(self)
    }

    /// Typed accessor for `system/clock` operations (now / compare).
    /// See [`crate::clock::ClockOps`]. Available only when the `clock`
    /// feature is enabled.
    #[cfg(feature = "clock")]
    pub fn clock(&self) -> crate::clock::ClockOps<'_> {
        crate::clock::ClockOps::new(self)
    }

    /// Typed accessor for `system/continuation` operations
    /// (install/advance/resume/abandon). See
    /// [`crate::continuation::ContinuationOps`]. Available only when
    /// the `continuation` feature is enabled.
    #[cfg(feature = "continuation")]
    pub fn continuation(&self) -> crate::continuation::ContinuationOps<'_> {
        crate::continuation::ContinuationOps::new(self)
    }

    /// Typed accessor for `system/identity` operations
    /// (create_quorum / create_attestation / supersede_attestation /
    /// revoke_attestation / publish_attestation). See
    /// [`crate::identity::IdentityOps`]. Available only when the
    /// `identity` feature is enabled.
    #[cfg(feature = "identity")]
    pub fn identity(&self) -> crate::identity::IdentityOps<'_> {
        crate::identity::IdentityOps::new(self)
    }

    /// Typed accessor for `system/quorum` operations (create /
    /// update / publish / verify). See
    /// [`crate::quorum::QuorumOps`]. Available only when the
    /// `quorum` feature is enabled.
    #[cfg(feature = "quorum")]
    pub fn quorum(&self) -> crate::quorum::QuorumOps<'_> {
        crate::quorum::QuorumOps::new(self)
    }

    /// Typed accessor for `system/revision` operations
    /// (commit / status / etc.). See
    /// [`crate::revision::RevisionOps`]. Available only when the
    /// `revision` feature is enabled.
    #[cfg(feature = "revision")]
    pub fn revision(&self) -> crate::revision::RevisionOps<'_> {
        crate::revision::RevisionOps::new(self)
    }

    /// Typed accessor for `system/compute` operations
    /// (eval / install / uninstall, plus SDK-side `list` / `show`
    /// helpers over the install tree path). See
    /// [`crate::compute::ComputeOps`]. Available only when the
    /// `compute` feature is enabled.
    #[cfg(feature = "compute")]
    pub fn compute(&self) -> crate::compute::ComputeOps<'_> {
        crate::compute::ComputeOps::new(self)
    }

    /// Typed accessor for `system/role` operations (define / assign /
    /// unassign / exclude / unexclude / re-derive / delegate). See
    /// [`crate::role::RoleOps`]. Available only when the `role`
    /// feature is enabled.
    #[cfg(feature = "role")]
    pub fn role(&self) -> crate::role::RoleOps<'_> {
        crate::role::RoleOps::new(self)
    }

    // -- Tree operations --
    //
    // Two access levels per SDK-OPERATIONS.md §2.7:
    //
    //   L1 — Dispatched (default): async methods that route through
    //         execute("system/tree", ...). Capability-checked, full
    //         emit pathway with execution context.
    //
    //   L0 — Direct store (escape hatch): sync methods via store().
    //         Bypasses dispatch and capability checks. Use only when
    //         you are the peer owner and need sync access (render
    //         loops, bootstrapping).
    //
    // The security boundary MUST be visible in the code. Dispatched
    // operations are the top-level async methods. Direct store access
    // requires explicitly calling store(). See spec §2.7.

    // -- L1: Generic handler dispatch --

    /// Execute a handler operation — the L1 dispatch primitive.
    ///
    /// This is the generic form that tree ops, query, subscription
    /// wrappers, and custom-handler invocations are built on. Routes
    /// through the peer's execute pipeline with capability checks and
    /// the full emit pathway.
    ///
    /// Returns an **owning** future so it can be spawned from sync
    /// contexts (`rt_handle.spawn(ctx.execute(...))`) as well as awaited
    /// directly from async code.
    ///
    /// On transport success, the future resolves to the handler's
    /// `HandlerResult { status, result, included }` verbatim. The caller
    /// decides how to interpret the status code — callers wanting typed
    /// status mapping should prefer the semantic wrappers (`get`, `put`,
    /// `query`, etc.). Transport-level failures (channel closed,
    /// serialization errors) come back as `Err(SdkError::HandlerError)`.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn execute(
        &self,
        handler: impl Into<String>,
        operation: impl Into<String>,
        params: Entity,
        opts: entity_handler::ExecuteOptions,
    ) -> impl std::future::Future<Output = Result<entity_handler::HandlerResult, SdkError>> + Send + 'static
    {
        let shared = self.shared.clone();
        let owner_cap = self.owner_self_cap.clone();
        let handler = handler.into();
        let operation = operation.into();
        async move {
            let local_identity = shared.identity_hash;
            let execute_fn = entity_peer::connection::make_execute_fn(
                shared,
                Some(local_identity),
                std::collections::HashMap::new(),
                None,
                Some(owner_cap),
            );
            execute_fn(handler, operation, params, opts)
                .await
                .map_err(|e| SdkError::HandlerError(e.to_string()))
        }
    }

    /// WASM variant — no `Send` bound required for `spawn_local`.
    #[cfg(target_arch = "wasm32")]
    pub fn execute(
        &self,
        handler: impl Into<String>,
        operation: impl Into<String>,
        params: Entity,
        opts: entity_handler::ExecuteOptions,
    ) -> impl std::future::Future<Output = Result<entity_handler::HandlerResult, SdkError>> + 'static
    {
        let shared = self.shared.clone();
        let owner_cap = self.owner_self_cap.clone();
        let handler = handler.into();
        let operation = operation.into();
        async move {
            let local_identity = shared.identity_hash;
            let execute_fn = entity_peer::connection::make_execute_fn(
                shared,
                Some(local_identity),
                std::collections::HashMap::new(),
                None,
                Some(owner_cap),
            );
            execute_fn(handler, operation, params, opts)
                .await
                .map_err(|e| SdkError::HandlerError(e.to_string()))
        }
    }

    // -- L1: Dispatched tree operations (async, capability-checked) --
}

/// `PeerContext` as the outer-caller / cross-peer side of the
/// [`entity_handler::Dispatcher`] contract (SDK-EXTENSION-OPERATIONS §11
/// Amendment A). Lets SDK-level sequencers like
/// `entity_content::ensure_closure` take `&dyn Dispatcher` and accept
/// either a peer (outer call) or a `HandlerContext`-derived dispatcher
/// (handler-internal) uniformly.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl entity_handler::Dispatcher for PeerContext {
    async fn execute(
        &self,
        handler: &str,
        operation: &str,
        params: Entity,
        opts: entity_handler::ExecuteOptions,
    ) -> Result<entity_handler::HandlerResult, entity_handler::HandlerError> {
        PeerContext::execute(self, handler, operation, params, opts)
            .await
            .map_err(|e| entity_handler::HandlerError::Internal(e.to_string()))
    }
}

impl PeerContext {

    /// Whether `cap_hash` is operator-class for `target_pattern` per
    /// `GUIDE-CAPABILITIES.md` §10 (v1.2.1 Ruling 1). A capability chain
    /// is operator-class iff (1) it roots at this peer's L0 bootstrap
    /// identity, AND (2) every link's `resources` field explicitly
    /// enumerates the target as a literal pattern (wildcards never
    /// count, regardless of match).
    ///
    /// **App-tier defense-in-depth.** The substrate enforces refusal at
    /// the extension layer (subscription handler refuses sensitive
    /// prefixes for non-operator scopes). App code consults this method
    /// to surface "this operation will fail" UX *before* dispatching,
    /// without re-implementing the chain walk.
    ///
    /// Returns `false` on any chain-walk failure (unreachable parent,
    /// malformed cap entity, multi-sig root). Fails closed — never
    /// returns `true` on uncertainty.
    ///
    /// Per Dom feedback (Ask (c)). Thin pass-through to
    /// `entity_protocol::is_operator_class_for`; the SDK boundary is
    /// the right place to consult it so app code doesn't reach into
    /// `entity_protocol` directly.
    pub fn is_operator_class_for(&self, cap_hash: &Hash, target_pattern: &str) -> bool {
        let content_store = self.shared.content_store.clone();
        entity_protocol::is_operator_class_for(
            cap_hash,
            target_pattern,
            &self.shared.identity_hash,
            |h| content_store.get(h),
        )
    }

    /// Get entity at path — dispatched through system/tree handler.
    ///
    /// Returns `Ok(None)` if the path has no binding (404).
    /// Returns `Err` for capability violations (403) or system errors.
    pub async fn get(&self, path: &str) -> Result<Option<Entity>, SdkError> {
        let opts = entity_handler::ExecuteOptions {
            resource: Some(entity_capability::ResourceTarget {
                targets: vec![path.into()],
                exclude: vec![],
            }),
            ..Default::default()
        };
        let params = empty_params();
        match self.peer.execute_with_options("system/tree", "get", params, opts).await {
            Ok(result) if result.status == 200 => Ok(Some(result.result)),
            Ok(result) if result.status == 404 => Ok(None),
            Ok(result) => Err(SdkError::from_handler_result(&result, format!("tree get: {}", path))
                .unwrap_or_else(|| SdkError::TreeError(format!("unexpected status {}", result.status)))),
            Err(e) => Err(SdkError::TreeError(e.to_string())),
        }
    }

    /// Store entity at path — dispatched through system/tree handler.
    ///
    /// Returns the content hash on success. Increments generation counter.
    ///
    /// Returns an **owning** future so it can be spawned from sync contexts
    /// (`rt.spawn(ctx.put(...))`) as well as awaited directly. Same pattern
    /// as [`execute`](Self::execute).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn put(
        &self,
        path: impl Into<String>,
        entity: Entity,
    ) -> impl std::future::Future<Output = Result<Hash, SdkError>> + Send + 'static {
        let shared = self.shared.clone();
        let generation = self.generation.clone();
        let path: String = path.into();
        async move {
            let opts = entity_handler::ExecuteOptions {
                resource: Some(entity_capability::ResourceTarget {
                    targets: vec![path.clone()],
                    exclude: vec![],
                }),
                ..Default::default()
            };
            let params = build_put_params(&entity)?;
            let local_identity = shared.identity_hash;
            let execute_fn = entity_peer::connection::make_execute_fn(
                shared, Some(local_identity), std::collections::HashMap::new(), None, None,
            );
            match execute_fn("system/tree".into(), "put".into(), params, opts).await {
                Ok(result) if result.status == 200 => {
                    generation.fetch_add(1, Ordering::Relaxed);
                    parse_content_hash(&result.result)
                }
                Ok(result) => Err(SdkError::from_handler_result(&result, format!("tree put: {}", path))
                    .unwrap_or_else(|| SdkError::TreeError(format!("unexpected status {}", result.status)))),
                Err(e) => Err(SdkError::TreeError(e.to_string())),
            }
        }
    }

    /// L1 query (SDK-OPERATIONS §5.1). Dispatches `execute("system/query",
    /// "find", expression, default opts)` and parses the typed envelope.
    ///
    /// Returns an **owning** future so it can be spawned from sync contexts.
    /// On a non-200 status the future resolves to `Err(SdkError)` mapped
    /// from the status code.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn query(
        &self,
        expression: Entity,
    ) -> impl std::future::Future<Output = Result<QueryResults, SdkError>> + Send + 'static {
        let exec = self.execute(
            "system/query",
            "find",
            expression,
            entity_handler::ExecuteOptions::default(),
        );
        async move {
            let result = exec.await?;
            if result.status != 200 {
                return Err(SdkError::from_handler_result(&result, "query")
                    .unwrap_or_else(|| {
                        SdkError::HandlerError(format!("query: unexpected status {}", result.status))
                    }));
            }
            parse_query_result(&result.result)
        }
    }

    /// WASM variant — no `Send` bound required for `spawn_local`.
    #[cfg(target_arch = "wasm32")]
    pub fn query(
        &self,
        expression: Entity,
    ) -> impl std::future::Future<Output = Result<QueryResults, SdkError>> + 'static {
        let exec = self.execute(
            "system/query",
            "find",
            expression,
            entity_handler::ExecuteOptions::default(),
        );
        async move {
            let result = exec.await?;
            if result.status != 200 {
                return Err(SdkError::from_handler_result(&result, "query")
                    .unwrap_or_else(|| {
                        SdkError::HandlerError(format!("query: unexpected status {}", result.status))
                    }));
            }
            parse_query_result(&result.result)
        }
    }

    /// L1 count (SDK-EXTENSION-OPERATIONS §6, `count` op). Dispatches
    /// `execute("system/query", "count", expression, default opts)` and
    /// unwraps the `primitive/uint` result entity.
    ///
    /// Returns an **owning** future so it can be spawned from sync contexts.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn count(
        &self,
        expression: Entity,
    ) -> impl std::future::Future<Output = Result<u64, SdkError>> + Send + 'static {
        let exec = self.execute(
            "system/query",
            "count",
            expression,
            entity_handler::ExecuteOptions::default(),
        );
        async move {
            let result = exec.await?;
            if result.status != 200 {
                return Err(SdkError::from_handler_result(&result, "count")
                    .unwrap_or_else(|| {
                        SdkError::HandlerError(format!("count: unexpected status {}", result.status))
                    }));
            }
            parse_count_result(&result.result)
        }
    }

    /// WASM variant — no `Send` bound required for `spawn_local`.
    #[cfg(target_arch = "wasm32")]
    pub fn count(
        &self,
        expression: Entity,
    ) -> impl std::future::Future<Output = Result<u64, SdkError>> + 'static {
        let exec = self.execute(
            "system/query",
            "count",
            expression,
            entity_handler::ExecuteOptions::default(),
        );
        async move {
            let result = exec.await?;
            if result.status != 200 {
                return Err(SdkError::from_handler_result(&result, "count")
                    .unwrap_or_else(|| {
                        SdkError::HandlerError(format!("count: unexpected status {}", result.status))
                    }));
            }
            parse_count_result(&result.result)
        }
    }

    /// L1 history query (SDK-EXTENSION-OPERATIONS §5).
    /// Dispatches `execute("system/history", "query", ...)` for `path`
    /// (optionally bounded by `limit`) and parses the typed envelope.
    ///
    /// Returns an **owning** future so it can be spawned from sync contexts.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn history_query(
        &self,
        path: impl Into<String>,
        options: HistoryQueryOptions,
    ) -> impl std::future::Future<Output = Result<HistoryQueryResult, SdkError>> + Send + 'static
    {
        let path = path.into();
        let shared = self.shared.clone();
        async move {
            let params = build_history_query_params(path, &options)?;
            let result = dispatch_execute(shared, "system/history", "query", params).await?;
            if result.status != 200 {
                return Err(SdkError::from_handler_result(&result, "history query")
                    .unwrap_or_else(|| {
                        SdkError::HandlerError(format!("history query: unexpected status {}", result.status))
                    }));
            }
            parse_history_query_result(&result.result)
        }
    }

    /// WASM variant — no `Send` bound required for `spawn_local`.
    #[cfg(target_arch = "wasm32")]
    pub fn history_query(
        &self,
        path: impl Into<String>,
        options: HistoryQueryOptions,
    ) -> impl std::future::Future<Output = Result<HistoryQueryResult, SdkError>> + 'static {
        let path = path.into();
        let shared = self.shared.clone();
        async move {
            let params = build_history_query_params(path, &options)?;
            let result = dispatch_execute(shared, "system/history", "query", params).await?;
            if result.status != 200 {
                return Err(SdkError::from_handler_result(&result, "history query")
                    .unwrap_or_else(|| {
                        SdkError::HandlerError(format!("history query: unexpected status {}", result.status))
                    }));
            }
            parse_history_query_result(&result.result)
        }
    }

    /// L1 history rollback. Restores `path` to `target_hash` (which must
    /// exist in the path's history chain). The rollback itself is
    /// recorded as a new transition (per spec §5).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn history_rollback(
        &self,
        path: impl Into<String>,
        target_hash: Hash,
    ) -> impl std::future::Future<Output = Result<(), SdkError>> + Send + 'static {
        let path = path.into();
        let shared = self.shared.clone();
        async move {
            let params = build_history_rollback_params(path, target_hash)?;
            let result = dispatch_execute(shared, "system/history", "rollback", params).await?;
            if result.status == 200 {
                Ok(())
            } else {
                Err(SdkError::from_handler_result(&result, "history rollback")
                    .unwrap_or_else(|| {
                        SdkError::HandlerError(format!("history rollback: unexpected status {}", result.status))
                    }))
            }
        }
    }

    /// WASM variant — no `Send` bound required for `spawn_local`.
    #[cfg(target_arch = "wasm32")]
    pub fn history_rollback(
        &self,
        path: impl Into<String>,
        target_hash: Hash,
    ) -> impl std::future::Future<Output = Result<(), SdkError>> + 'static {
        let path = path.into();
        let shared = self.shared.clone();
        async move {
            let params = build_history_rollback_params(path, target_hash)?;
            let result = dispatch_execute(shared, "system/history", "rollback", params).await?;
            if result.status == 200 {
                Ok(())
            } else {
                Err(SdkError::from_handler_result(&result, "history rollback")
                    .unwrap_or_else(|| {
                        SdkError::HandlerError(format!("history rollback: unexpected status {}", result.status))
                    }))
            }
        }
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    pub fn put(
        &self,
        path: impl Into<String>,
        entity: Entity,
    ) -> impl std::future::Future<Output = Result<Hash, SdkError>> + 'static {
        let shared = self.shared.clone();
        let generation = self.generation.clone();
        let path: String = path.into();
        async move {
            let opts = entity_handler::ExecuteOptions {
                resource: Some(entity_capability::ResourceTarget {
                    targets: vec![path.clone()],
                    exclude: vec![],
                }),
                ..Default::default()
            };
            let params = build_put_params(&entity)?;
            let local_identity = shared.identity_hash;
            let execute_fn = entity_peer::connection::make_execute_fn(
                shared, Some(local_identity), std::collections::HashMap::new(), None, None,
            );
            match execute_fn("system/tree".into(), "put".into(), params, opts).await {
                Ok(result) if result.status == 200 => {
                    generation.fetch_add(1, Ordering::Relaxed);
                    parse_content_hash(&result.result)
                }
                Ok(result) => Err(SdkError::from_handler_result(&result, format!("tree put: {}", path))
                    .unwrap_or_else(|| SdkError::TreeError(format!("unexpected status {}", result.status)))),
                Err(e) => Err(SdkError::TreeError(e.to_string())),
            }
        }
    }

    /// Compare-and-swap put. Per SDK-OPERATIONS.md §3.2 (SHOULD).
    ///
    /// `expected` semantics:
    /// - `None` — succeed only if nothing is bound at `path` (insert-only).
    /// - `Some(h)` — succeed only if the current binding's hash equals `h`.
    ///
    /// Returns [`SdkError::Conflict`] (status 409) when the expectation
    /// doesn't match; the caller can re-read and retry.
    ///
    /// **Atomicity caveat**: entity-core-rust's `system/tree` handler does
    /// not yet support native CAS via `expected_hash` in the put params.
    /// Today this is implemented as a best-effort get-then-compare-then-put
    /// at the SDK layer. For a single local writer (the common case today),
    /// dispatch serialization inside the handler makes this effectively
    /// atomic — but a second concurrent writer on the same path can race.
    /// When the core handler gains native CAS, this will become atomic
    /// without a signature change.
    pub async fn put_cas(
        &self,
        path: &str,
        entity: Entity,
        expected: Option<Hash>,
    ) -> Result<Hash, SdkError> {
        let current = self.get(path).await?.map(|e| e.content_hash);
        if current != expected {
            return Err(SdkError::Conflict {
                status: status::CONFLICT,
                code: Some("cas_mismatch".into()),
                message: format!(
                    "tree put_cas: expected {:?}, found {:?}",
                    expected, current
                ),
            });
        }
        self.put(path, entity).await
    }

    /// List children under prefix — dispatched through system/tree handler.
    ///
    /// Returns entries for immediate children at the prefix level.
    pub async fn list(&self, prefix: &str) -> Result<Vec<ListingEntry>, SdkError> {
        let listing_path = if prefix.ends_with('/') || prefix.is_empty() {
            prefix.to_string()
        } else {
            format!("{}/", prefix)
        };
        let opts = entity_handler::ExecuteOptions {
            resource: Some(entity_capability::ResourceTarget {
                targets: vec![listing_path],
                exclude: vec![],
            }),
            ..Default::default()
        };
        let params = empty_params();
        match self.peer.execute_with_options("system/tree", "get", params, opts).await {
            Ok(result) if result.status == 200 => parse_listing_result(&result.result),
            Ok(result) => Err(SdkError::from_handler_result(&result, format!("tree list: {}", prefix))
                .unwrap_or_else(|| SdkError::TreeError(format!("unexpected status {}", result.status)))),
            Err(e) => Err(SdkError::TreeError(e.to_string())),
        }
    }

    /// Remove binding at path — dispatched through system/tree handler.
    ///
    /// Returns `Ok(true)` if something was removed, `Ok(false)` if path wasn't bound.
    pub async fn remove(&self, path: &str) -> Result<bool, SdkError> {
        let opts = entity_handler::ExecuteOptions {
            resource: Some(entity_capability::ResourceTarget {
                targets: vec![path.into()],
                exclude: vec![],
            }),
            ..Default::default()
        };
        let params = build_remove_params()?;
        match self.peer.execute_with_options("system/tree", "put", params, opts).await {
            Ok(result) if result.status == 200 => {
                self.generation.fetch_add(1, Ordering::Relaxed);
                Ok(true)
            }
            Ok(result) if result.status == 404 => Ok(false),
            Ok(result) => Err(SdkError::from_handler_result(&result, format!("tree remove: {}", path))
                .unwrap_or_else(|| SdkError::TreeError(format!("unexpected status {}", result.status)))),
            Err(e) => Err(SdkError::TreeError(e.to_string())),
        }
    }

    /// Check if path has a binding — dispatched through system/tree handler.
    pub async fn has(&self, path: &str) -> Result<bool, SdkError> {
        Ok(self.get(path).await?.is_some())
    }

    // -- L0: Direct store access (sync, escape hatch) --

    /// Direct store access (Level 0) — bypasses handler dispatch and
    /// capability checks.
    ///
    /// Use this when you are the peer owner and need **synchronous** access:
    /// render loops, bootstrapping, diagnostics. The security boundary is
    /// visible in the code — every `store()` call is an explicit opt-out
    /// from dispatch and capability enforcement.
    ///
    /// For dispatched operations with capability checking, use the async
    /// methods directly on PeerContext: [`get()`], [`put()`], [`list()`].
    pub fn store(&self) -> StoreAccess<'_> {
        StoreAccess { peer_ctx: self }
    }

    /// Bump the generation counter. Called by mutation paths that write
    /// directly to the tree without going through `put` (e.g., the dynamic
    /// handler registration primitive) so snapshot-based watchers observe
    /// the change.
    pub(crate) fn bump_generation(&self) {
        self.generation.fetch_add(1, Ordering::Relaxed);
    }

    /// Total entities in the content store.
    pub fn entity_count(&self) -> usize {
        self.peer.content_store().len()
    }

    /// Total paths in the location index. O(1) on all current backends.
    pub fn path_count(&self) -> usize {
        self.peer.location_index().len_prefix("")
    }

    /// Binding-safe content-store reclaim (L0). Removes the blob `hash`
    /// from the content store **only if no live path in the location
    /// index still binds it** — so it can never strand a live `get` or a
    /// deduped reference (GUIDE-GC §3.1, pitfall #1: never reap a hash
    /// with a live tree binding).
    ///
    /// This is the deliberate, visible opt-out from the path-level API,
    /// for app-level retention policies (e.g. bounded save-state) that
    /// own a provably single-version slice of the tree and want to
    /// reclaim the superseded blobs the append-only content store would
    /// otherwise keep forever. It is **not** general reachability GC — it
    /// does not walk the `refs` graph or version history (that is the
    /// kernel's job, GUIDE-GC §2/§3.2); it guarantees only "no live path
    /// binding". The binding scan is O(paths); call it off the hot path
    /// (e.g. behind a debounce), not per keystroke.
    pub fn content_remove(&self, hash: &Hash) -> ContentRemoveOutcome {
        content_remove_if_unbound(
            self.peer.content_store().as_ref(),
            self.peer.location_index().as_ref(),
            hash,
        )
    }

    // -- Handler discovery --

    /// Discover handlers registered on this peer by reading system/handler/* entities.
    ///
    /// Uses L0 store access (handler registry is peer-internal metadata).
    pub fn discover_handlers(&self) -> Vec<HandlerInfo> {
        let store = self.store();
        let prefix = format!("/{}/system/handler/", self.peer_id_string);
        let entries = store.list(&prefix);
        let mut handlers = Vec::new();

        for entry in entries {
            let entity = match store.get(&entry.path) {
                Some(e) => e,
                None => continue,
            };
            if let Some(info) = HandlerInfo::from_entity(&entity) {
                handlers.push(info);
            }
        }

        handlers.sort_by(|a, b| a.pattern.cmp(&b.pattern));
        handlers
    }

    // -- Inbox introspection (SDK-EXTENSION-OPERATIONS §7) --

    /// List pending inbox entries — paths and content hashes under
    /// `/{peer_id}/system/inbox/`. Uses L0 store access (the inbox is a
    /// peer-local subtree).
    ///
    /// The inbox is primarily populated by other extensions (subscription
    /// notifications, continuation results); these helpers expose its
    /// contents for inspection per the spec note in §7.
    pub fn inbox_list(&self) -> Vec<LocationEntry> {
        let prefix = format!("/{}/system/inbox/", self.peer_id_string);
        self.store().list(&prefix)
    }

    /// Read a specific inbox delivery by its path relative to
    /// `system/inbox/`. e.g. `inbox_get("sub-1/event-42")` reads the
    /// fully qualified path `/{pid}/system/inbox/sub-1/event-42`.
    ///
    /// Returns `None` if no entity is bound at that path.
    pub fn inbox_get(&self, relative_path: &str) -> Option<Entity> {
        let path = format!(
            "/{}/system/inbox/{}",
            self.peer_id_string,
            relative_path.trim_start_matches('/')
        );
        self.store().get(&path)
    }

    /// Deliver `params` into the inbox at `target_path`. Wraps
    /// `system/inbox:receive` with the correct `resource_target` shape
    /// per `extensions/inbox/src/lib.rs:75-104`.
    ///
    /// `target_path` form: `/{receiver_pid}/system/inbox/{channel}`. The
    /// message is stored at `{target_path}/{request_id}`; `request_id`
    /// MUST be unique per logical message (V7 §6.8 — inbox handler line
    /// 99-103 keys storage by `ctx.request_id`).
    ///
    /// Pass `None` for `request_id` to have the SDK mint a fresh nonce.
    /// Explicit IDs let the caller dedupe (idempotent send): a second
    /// call with the same `request_id` overwrites the stored entity at
    /// the same storage key.
    ///
    /// Self-dispatch today (target_path's `{receiver_pid}` is this peer
    /// or the local kernel routes it). Cross-peer dispatch routes
    /// through the connection layer automatically when targeting a
    /// remote peer URI — no special call shape needed once Tier 2
    /// multi-peer hosting lands.
    ///
    /// Returns the storage path of the delivered message on success.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn inbox_send(
        &self,
        target_path: impl Into<String>,
        params: Entity,
        request_id: Option<String>,
    ) -> impl std::future::Future<Output = Result<String, SdkError>> + Send + 'static {
        let target_path = target_path.into();
        let rid = request_id.unwrap_or_else(|| mint_inbox_nonce(&self.peer_id_string));
        let storage_path = format!("{}/{}", target_path, rid);
        let fut = self.execute(
            "system/inbox",
            "receive",
            params,
            entity_handler::ExecuteOptions {
                resource: Some(entity_capability::ResourceTarget {
                    targets: vec![target_path],
                    exclude: Vec::new(),
                }),
                request_id: Some(rid),
                ..entity_handler::ExecuteOptions::default()
            },
        );
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/inbox:receive") {
                return Err(err);
            }
            Ok(storage_path)
        }
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    pub fn inbox_send(
        &self,
        target_path: impl Into<String>,
        params: Entity,
        request_id: Option<String>,
    ) -> impl std::future::Future<Output = Result<String, SdkError>> + 'static {
        let target_path = target_path.into();
        let rid = request_id.unwrap_or_else(|| mint_inbox_nonce(&self.peer_id_string));
        let storage_path = format!("{}/{}", target_path, rid);
        let fut = self.execute(
            "system/inbox",
            "receive",
            params,
            entity_handler::ExecuteOptions {
                resource: Some(entity_capability::ResourceTarget {
                    targets: vec![target_path],
                    exclude: Vec::new(),
                }),
                request_id: Some(rid),
                ..entity_handler::ExecuteOptions::default()
            },
        );
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/inbox:receive") {
                return Err(err);
            }
            Ok(storage_path)
        }
    }

    /// Discover type definitions registered on this peer by reading
    /// `system/type/*` entities. Mirrors [`discover_handlers`]; see
    /// SDK-OPERATIONS §9.2.
    ///
    /// Uses L0 store access (type registry is peer-internal metadata).
    pub fn discover_types(&self) -> Vec<TypeInfo> {
        let store = self.store();
        let prefix = format!("/{}/system/type/", self.peer_id_string);
        let entries = store.list(&prefix);
        let mut types = Vec::new();

        for entry in entries {
            let entity = match store.get(&entry.path) {
                Some(e) => e,
                None => continue,
            };
            if let Some(info) = TypeInfo::from_entity(&entity) {
                types.push(info);
            }
        }

        types.sort_by(|a, b| a.type_path.cmp(&b.type_path));
        types
    }


    // -- Wake signal --

    /// Set the wake function called when tree state changes.
    /// Typically `ctx.request_repaint()` for egui, or equivalent
    /// for other renderers.
    pub fn set_wake_fn(&self, f: impl Fn() + Send + Sync + 'static) {
        *self.wake_fn.lock().unwrap() = Some(Arc::new(f));
    }

    /// Create a future that bridges tree change events to the wake function.
    /// Calls request_repaint (via wake_fn) when tree state changes.
    /// Does NOT increment generation — generation is only incremented by
    /// explicit tree_put calls. Internal engine writes (clock, revision)
    /// fire events but shouldn't force DOM rebuilds.
    /// Spawn this on the appropriate runtime (tokio::spawn or spawn_local).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn event_bridge(&self) -> impl std::future::Future<Output = ()> + Send {
        let mut events = self.peer.subscribe_events();
        let wake_fn = self.wake_fn.clone();
        async move {
            loop {
                match events.recv().await {
                    Ok(_evt) => {
                        tracing::trace!("event_bridge: tree change, requesting repaint");
                        if let Ok(guard) = wake_fn.lock() {
                            if let Some(f) = guard.as_ref() { f(); }
                        }
                    }
                    Err(e) if e.to_string().contains("closed") => {
                        tracing::debug!("event_bridge: channel closed, stopping");
                        break;
                    }
                    Err(e) => {
                        tracing::debug!("event_bridge: recv error: {}", e);
                    }
                }
            }
        }
    }

    /// WASM version — same logic, no Send bound required for spawn_local.
    ///
    /// Like the native version, this does **not** increment generation
    /// on every event. Generation is only incremented by explicit
    /// tree_put calls through PeerContext (user-initiated writes).
    /// Internal engine writes (clock, revision, etc.) fire events
    /// here too, but they shouldn't force DOM rebuilds — that would
    /// make legacy windows (which use generation as their fallback
    /// hash) thrash on every clock tick.
    ///
    /// External tree changes (e.g., from a remote peer that the
    /// model has subscribed to) reach the model via its own
    /// path-pattern subscription, which calls model setters
    /// directly. The wake_fn here just causes the renderer to run,
    /// at which point the per-window content_hash check decides
    /// whether anything actually needs rebuilding.
    #[cfg(target_arch = "wasm32")]
    pub fn event_bridge(&self) -> impl std::future::Future<Output = ()> {
        let mut events = self.peer.subscribe_events();
        let wake_fn = self.wake_fn.clone();
        async move {
            tracing::info!("event_bridge: started (WASM)");
            let mut event_count: u64 = 0;
            let mut error_count: u64 = 0;
            let mut burst_count: u64 = 0;
            let mut last_burst_log: f64 = 0.0;
            loop {
                match events.recv().await {
                    Ok(evt) => {
                        event_count += 1;
                        tracing::trace!(
                            path = %evt.path,
                            count = event_count,
                            "event_bridge: tree change"
                        );
                        // Burst detection: warn if >50 events in 1 second.
                        burst_count += 1;
                        let now = js_sys::Date::now();
                        if now - last_burst_log > 1000.0 {
                            if burst_count > 50 {
                                tracing::warn!(
                                    burst = burst_count,
                                    total = event_count,
                                    last_path = %evt.path,
                                    "event_bridge: HIGH EVENT RATE — {} events/sec",
                                    burst_count,
                                );
                            }
                            burst_count = 0;
                            last_burst_log = now;
                        }
                        if let Ok(guard) = wake_fn.lock() {
                            if let Some(f) = guard.as_ref() { f(); }
                        }
                    }
                    Err(e) if e.to_string().contains("closed") => {
                        tracing::info!("event_bridge: channel closed after {} events, {} errors", event_count, error_count);
                        break;
                    }
                    Err(e) => {
                        error_count += 1;
                        tracing::warn!(
                            error = %e,
                            error_count = error_count,
                            "event_bridge: recv error, yielding"
                        );
                        // Yield to prevent busy-loop on WASM's single-threaded runtime.
                        wasm_bindgen_futures::JsFuture::from(js_sys::Promise::new(
                            &mut |resolve, _| { let _ = resolve.call0(&wasm_bindgen::JsValue::NULL); },
                        ))
                        .await
                        .ok();
                    }
                }
            }
        }
    }

    // -- Escape hatches --

    /// Access the underlying kernel Peer directly.
    pub fn peer(&self) -> &Peer {
        &self.peer
    }

    /// Access the cached PeerShared state.
    pub fn peer_shared(&self) -> Arc<PeerShared> {
        self.shared.clone()
    }

    /// Open a connection to a remote peer at `addr` and pool the
    /// resulting `RemoteConnection` so subsequent
    /// `execute("entity://{remote_pid}/...")` calls reuse it.
    ///
    /// Returns the remote peer's id on success.
    ///
    /// **Why this lives on `PeerContext` and not on `Peer`:** the kernel's
    /// `Peer::connect_to` constructs a new `Arc<PeerShared>` via
    /// `Peer::shared()` and inserts the connection into THAT throwaway
    /// shared's pool — which is dropped when the call returns. Cross-peer
    /// dispatch (`PeerContext::execute` against `entity://` URIs) reads
    /// from `PeerContext.shared.remote`, the persistent pool. The two
    /// pools are different `Arc<PeerShared>` instances.
    ///
    /// This method dials + handshakes against the **persistent** shared,
    /// so the resulting `RemoteConnection` lands in the pool that
    /// `make_execute_fn` actually reads from. Bypasses the substrate
    /// `Peer::connect_to` bug around peer-shared and transport; once
    /// that's fixed at source (Shape A — `Peer::shared` returns a long-lived
    /// `Arc<PeerShared>` field), this method becomes a 1-line forward
    /// to `self.peer.connect_to(addr)`.
    ///
    /// Mirrors `PeerContext::execute`'s architectural position:
    /// connection setup + cross-peer dispatch belong at the same layer.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect_to(&self, addr: &str) -> Result<String, SdkError> {
        let conn = self.shared.connector.connect(addr).await.map_err(|e| {
            SdkError::HandlerError(format!("connect_to({addr}): connector failed: {e}"))
        })?;
        // The SDK authors under the SHA-256 floor by design (Ed25519-only
        // surface); negotiation collapses to a common format with the peer.
        let remote = entity_peer::remote::perform_connect_with_dispatch(
            conn,
            &self.shared.keypair,
            entity_hash::HASH_ALGORITHM_SHA256,
            // §6.11(b): receive deliveries the remote pushes back over
            // this connection (we may run no listener it could dial).
            Some(self.shared.clone()),
            )
        .await
        .map_err(|e| SdkError::HandlerError(format!("connect_to({addr}): handshake: {e}")))?;
        let remote_pid = remote.remote_peer_id.clone();
        self.shared.remote.insert(&remote_pid, remote);
        Ok(remote_pid)
    }

    /// WASM variant — same shape, no `Send` bound on the returned
    /// future (matches the cfg-gated pattern used by every other async
    /// method on `PeerContext`).
    #[cfg(target_arch = "wasm32")]
    pub async fn connect_to(&self, addr: &str) -> Result<String, SdkError> {
        let conn = self.shared.connector.connect(addr).await.map_err(|e| {
            SdkError::HandlerError(format!("connect_to({addr}): connector failed: {e}"))
        })?;
        // The SDK authors under the SHA-256 floor by design (Ed25519-only
        // surface); negotiation collapses to a common format with the peer.
        let remote = entity_peer::remote::perform_connect_with_dispatch(
            conn,
            &self.shared.keypair,
            entity_hash::HASH_ALGORITHM_SHA256,
            // §6.11(b): receive deliveries the remote pushes back over
            // this connection (we may run no listener it could dial).
            Some(self.shared.clone()),
            )
        .await
        .map_err(|e| SdkError::HandlerError(format!("connect_to({addr}): handshake: {e}")))?;
        let remote_pid = remote.remote_peer_id.clone();
        self.shared.remote.insert(&remote_pid, remote);
        Ok(remote_pid)
    }

    // -- Scoped handles --

    /// Create a scoped handle bound to a tree prefix.
    ///
    /// All operations on the returned [`Scope`] are relative to the prefix,
    /// which is canonicalized to `/{peer_id}/{prefix}`. This isolates callers
    /// from manual path construction and ensures peer-namespacing.
    ///
    /// ```ignore
    /// let ws = ctx.scope("app/myapp/workspace");
    /// ws.put("windows/1/state", entity)?;  // → /{peer_id}/app/myapp/workspace/windows/1/state
    /// let e = ws.get("windows/1/state");   // relative lookup
    /// ```
    pub fn scope(&self, prefix: &str) -> Scope<'_> {
        let canonical = format!("/{}/{}", self.peer_id_string, prefix.trim_start_matches('/'));
        Scope { peer_ctx: self, prefix: canonical }
    }
}

// ---------------------------------------------------------------------------
// Scope — prefix-bound handle for tree operations (L2 pattern)
// ---------------------------------------------------------------------------

/// A scoped handle that binds a [`PeerContext`] to a tree prefix.
///
/// All operations are relative to the prefix. Paths are canonicalized to
/// `/{peer_id}/{prefix}/{relative_path}`. This is the primary ergonomic
/// pattern for application code per the SDK domain spec (GUIDE-SDK-PATTERNS.md).
pub struct Scope<'a> {
    peer_ctx: &'a PeerContext,
    prefix: String,
}

impl<'a> Scope<'a> {
    /// The canonical prefix this scope is bound to.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Resolve a relative path to its canonical absolute form.
    pub fn resolve(&self, relative: &str) -> String {
        if relative.is_empty() {
            self.prefix.clone()
        } else {
            format!("{}/{}", self.prefix, relative.trim_start_matches('/'))
        }
    }

    /// Get the entity at a relative path (L0 — direct store access).
    ///
    /// Note: Scope will migrate to async L1 dispatch in a future release.
    /// For now, operations route through store() for sync compatibility.
    pub fn get(&self, relative: &str) -> Option<Entity> {
        self.peer_ctx.store().get(&self.resolve(relative))
    }

    /// Store an entity at a relative path (L0 — direct store access).
    pub fn put(&self, relative: &str, entity: Entity) -> Result<Hash, SdkError> {
        self.peer_ctx.store().put(&self.resolve(relative), entity)
    }

    /// List entries under a relative prefix (L0 — direct store access).
    pub fn list(&self, relative: &str) -> Vec<LocationEntry> {
        self.peer_ctx.store().list(&self.resolve(relative))
    }

    /// Check if a path has an entity (L0 — direct store access).
    pub fn has(&self, relative: &str) -> bool {
        self.peer_ctx.store().has(&self.resolve(relative))
    }

    /// Remove an entity at a relative path (L0 — direct store access).
    pub fn remove(&self, relative: &str) -> bool {
        self.peer_ctx.store().remove(&self.resolve(relative))
    }

    /// Create a sub-scope with an additional prefix segment.
    pub fn scope(&self, sub_prefix: &str) -> Scope<'a> {
        Scope {
            peer_ctx: self.peer_ctx,
            prefix: format!("{}/{}", self.prefix, sub_prefix.trim_start_matches('/')),
        }
    }
}

// ---------------------------------------------------------------------------
// L1 dispatch helpers — params construction and result parsing
// ---------------------------------------------------------------------------

/// Build an empty params entity for tree get operations.
/// Per-process monotonic counter feeding `mint_inbox_nonce`. Combined
/// with millis-since-epoch and a peer-id prefix, gives a stable-unique
/// `request_id` for `inbox_send` callers that don't supply their own.
static INBOX_SEND_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Mint a fresh `request_id` for `PeerContext::inbox_send` when the
/// caller passes `None`. Format: `inbox-{peer_short}-{ms}-{n}`. Unique
/// within this process; combined with the peer-id prefix it's unique
/// across processes too (collision requires two peers with the same
/// peer_id, which Ed25519 already prevents).
fn mint_inbox_nonce(peer_id: &str) -> String {
    let ts = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let n = INBOX_SEND_COUNTER.fetch_add(1, Ordering::Relaxed);
    let short = if peer_id.len() >= 8 { &peer_id[..8] } else { peer_id };
    format!("inbox-{}-{}-{}", short, ts, n)
}

fn empty_params() -> Entity {
    Entity::new("system/empty", entity_ecf::to_ecf(&entity_ecf::Value::Null)).unwrap()
}

/// Build put params: `{"entity": {"type": ..., "data": ...}}`.
fn build_put_params(entity: &Entity) -> Result<Entity, SdkError> {
    // The `data` field must be sent as a decoded ciborium Value, NOT
    // wrapped as Value::Bytes. entity-core-rust's `system/tree` put
    // handler re-encodes whatever Value it extracts — if we send
    // Value::Bytes(raw), the handler produces `byte_string_header + raw`
    // which double-wraps the CBOR and corrupts subsequent reads.
    // Decoding `entity.data` back to Value and sending that round-trips
    // cleanly because the handler's re-encode produces equivalent bytes.
    let data_value: entity_ecf::Value = ciborium::from_reader(entity.data.as_slice())
        .map_err(|e| SdkError::TreeError(format!("decode entity.data for put: {}", e)))?;
    let entity_cbor = entity_ecf::Value::Map(vec![
        (entity_ecf::text("type"), entity_ecf::text(&entity.entity_type)),
        (entity_ecf::text("data"), data_value),
    ]);
    let params_map = entity_ecf::Value::Map(vec![
        (entity_ecf::text("entity"), entity_cbor),
    ]);
    Entity::new("system/tree/put/params", entity_ecf::to_ecf(&params_map))
        .map_err(|e| SdkError::TreeError(format!("build put params: {}", e)))
}

/// Build remove params: `{"entity": null}` (null entity signals removal).
fn build_remove_params() -> Result<Entity, SdkError> {
    let params_map = entity_ecf::Value::Map(vec![
        (entity_ecf::text("entity"), entity_ecf::Value::Null),
    ]);
    Entity::new("system/tree/put/params", entity_ecf::to_ecf(&params_map))
        .map_err(|e| SdkError::TreeError(format!("build remove params: {}", e)))
}

/// Parse content hash from a tree put result: `{"content_hash": <bytes>}`.
fn parse_content_hash(result: &Entity) -> Result<Hash, SdkError> {
    let value: ciborium::Value = ciborium::from_reader(result.data.as_slice())
        .map_err(|e| SdkError::TreeError(format!("parse put result: {}", e)))?;
    let map = match &value {
        ciborium::Value::Map(m) => m,
        _ => return Err(SdkError::TreeError("put result is not a map".into())),
    };
    for (k, v) in map {
        if let ciborium::Value::Text(key) = k {
            if key == "content_hash" {
                if let ciborium::Value::Bytes(bytes) = v {
                    return Hash::from_bytes(bytes)
                        .map_err(|e| SdkError::TreeError(format!("invalid hash: {}", e)));
                }
            }
        }
    }
    Err(SdkError::TreeError("put result missing content_hash".into()))
}

/// Parse a tree listing result into ListingEntry items.
fn parse_listing_result(result: &Entity) -> Result<Vec<ListingEntry>, SdkError> {
    let value: ciborium::Value = ciborium::from_reader(result.data.as_slice())
        .map_err(|e| SdkError::TreeError(format!("parse listing: {}", e)))?;
    let map = match &value {
        ciborium::Value::Map(m) => m,
        _ => return Err(SdkError::TreeError("listing result is not a map".into())),
    };

    let entries_value = map.iter()
        .find(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == "entries"))
        .map(|(_, v)| v);

    let entries_map = match entries_value {
        Some(ciborium::Value::Map(m)) => m,
        _ => return Ok(vec![]),
    };

    let mut entries = Vec::new();
    for (k, v) in entries_map {
        let name = match k {
            ciborium::Value::Text(s) => s.clone(),
            _ => continue,
        };
        let (hash, has_children) = match v {
            ciborium::Value::Map(m) => {
                let h = m.iter()
                    .find(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == "hash"))
                    .and_then(|(_, v)| match v {
                        ciborium::Value::Bytes(b) => Hash::from_bytes(b).ok(),
                        _ => None,
                    });
                let hc = m.iter()
                    .find(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == "has_children"))
                    .and_then(|(_, v)| match v {
                        ciborium::Value::Bool(b) => Some(*b),
                        _ => None,
                    })
                    .unwrap_or(false);
                (h, hc)
            }
            _ => (None, false),
        };
        entries.push(ListingEntry { name, hash, has_children });
    }
    Ok(entries)
}

// ---------------------------------------------------------------------------
// ContentLookup — clone-friendly hash→Entity lookup handle
// ---------------------------------------------------------------------------

/// Owned content-store handle for hash-keyed entity lookups.
///
/// Obtained via [`StoreAccess::content_lookup`]. Cloneable and `'static`,
/// so it can be moved into subscription callbacks or spawned tasks that
/// outlive the originating `StoreAccess` borrow.
#[derive(Clone)]
pub struct ContentLookup {
    store: Arc<dyn entity_store::ContentStore>,
}

impl ContentLookup {
    /// Look up an entity by its content hash.
    pub fn get_by_hash(&self, hash: &Hash) -> Option<Entity> {
        self.store.get(hash)
    }
}

impl std::fmt::Debug for ContentLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContentLookup").finish()
    }
}

// ---------------------------------------------------------------------------
// StoreAccess — explicit Level 0 direct store access
// ---------------------------------------------------------------------------

/// Direct store access handle (Level 0).
///
/// Provides synchronous tree operations that bypass handler dispatch and
/// capability checks. Use this when you need explicit L0 access — e.g.,
/// in render loops where async dispatch isn't possible.
///
/// Obtained via [`PeerContext::store()`].
pub struct StoreAccess<'a> {
    peer_ctx: &'a PeerContext,
}

impl<'a> StoreAccess<'a> {
    /// Get the entity at an absolute path.
    pub fn get(&self, path: &str) -> Option<Entity> {
        self.peer_ctx.peer.tree().get(path)
    }

    /// Get an entity directly by its content hash, bypassing the path index.
    ///
    /// Primary use case: subscription callbacks that receive a
    /// [`TreeChangeEvent`] with a `new_hash` — looking the entity up by
    /// hash avoids a second path→hash round-trip through the location
    /// index and skips the race where the path has moved on to a newer
    /// hash by the time the callback runs.
    ///
    /// Returns `None` if the content store has no entity for this hash
    /// (e.g., the hash was from a deletion event, or the entity has
    /// been garbage-collected).
    pub fn get_by_hash(&self, hash: &Hash) -> Option<Entity> {
        self.peer_ctx.peer.content_store().get(hash)
    }

    /// Clone-friendly content lookup handle suitable for spawned tasks
    /// and subscription callbacks.
    ///
    /// `StoreAccess` borrows `PeerContext`, so it can't be moved into a
    /// `'static` closure. [`ContentLookup`] is owned — clone it into the
    /// callback and call `get_by_hash` there. This replaces reaching
    /// into `Arc<PeerShared>` from app code; the SDK keeps the kernel
    /// type private while still enabling long-lived hash lookups.
    pub fn content_lookup(&self) -> ContentLookup {
        ContentLookup {
            store: self.peer_ctx.peer.content_store().clone(),
        }
    }

    /// Store an entity at an absolute path.
    pub fn put(&self, path: &str, entity: Entity) -> Result<Hash, SdkError> {
        let hash = self.peer_ctx.peer.tree().put(path, entity)
            .map_err(|e| SdkError::TreeError(e.to_string()))?;
        self.peer_ctx.generation.fetch_add(1, Ordering::Relaxed);
        Ok(hash)
    }

    /// List entries under a prefix.
    pub fn list(&self, prefix: &str) -> Vec<LocationEntry> {
        self.peer_ctx.peer.location_index().list(prefix)
    }

    /// List every (path, entity) pair under a prefix.
    ///
    /// Sync, L0. Pairs the flat location-index scan with content-store
    /// lookups for each binding. Entries whose hash isn't present in the
    /// content store are silently dropped (defensive — shouldn't happen
    /// in normal operation since writes go through `put` which stores
    /// both).
    ///
    /// Primary use case: snapshotting a subtree as live entities — the
    /// worker-host's `Event::Snapshot.entries` payload, or any native
    /// consumer that wants "the current state of this subtree" without
    /// doing the two-step itself.
    pub fn list_entities(&self, prefix: &str) -> Vec<(String, Entity)> {
        let lookup = self.content_lookup();
        self.list(prefix)
            .into_iter()
            .filter_map(|entry| {
                lookup
                    .get_by_hash(&entry.hash)
                    .map(|entity| (entry.path, entity))
            })
            .collect()
    }

    /// Check if a path has an entity.
    pub fn has(&self, path: &str) -> bool {
        self.peer_ctx.peer.tree().get(path).is_some()
    }

    /// Remove an entity at a path.
    pub fn remove(&self, path: &str) -> bool {
        let removed = self.peer_ctx.peer.location_index().remove(path);
        if removed.is_some() {
            self.peer_ctx.generation.fetch_add(1, Ordering::Relaxed);
        }
        removed.is_some()
    }

    // -- Reactive observation (L0 — bypasses dispatch) --

    /// State generation counter. Incremented on every local write and
    /// by the event bridge on remote mutations. Used for snapshot-based
    /// DOM change detection. L0 — diagnostic/observation only.
    #[allow(dead_code)]
    pub fn generation(&self) -> u64 {
        self.peer_ctx.generation.load(Ordering::Relaxed)
    }

    /// Subscribe to the raw tree change event stream (L0).
    ///
    /// Returns a broadcast receiver for all tree mutations. The caller
    /// gets every event — no capability filtering. For an L1 subscription
    /// that routes through `system/subscription` with cap-checked delivery,
    /// use [`PeerContext::subscribe`] (when available).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<TreeChangeEvent> {
        self.peer_ctx.peer.subscribe_events()
    }

    /// Subscribe to tree changes whose path begins with `prefix` (L0,
    /// client-side filtered, push/callback-based).
    ///
    /// The callback is invoked once for every matching change event.
    /// Returns a [`SubscriptionHandle`] that cancels the subscription
    /// when dropped — store it on the consumer for as long as you
    /// want notifications.
    ///
    /// On native, the filtering task runs on tokio. On WASM, it runs
    /// in `spawn_local`. The callback must not block the runtime.
    ///
    /// This is a software-filtered L0 subscription — it consumes the
    /// per-peer broadcast and matches by prefix in-process. There's no
    /// capability check: every event the peer sees is delivered to the
    /// callback. Use [`PeerContext::subscribe`] for a dispatched L1
    /// subscription that routes through `system/subscription` with
    /// capability-checked delivery.
    ///
    /// Cross-impl convention: mirrors `OnPrefixChange` in the Go
    /// reference.
    #[allow(dead_code)]
    pub fn on_prefix_change<F>(
        &self,
        prefix: impl Into<String>,
        callback: F,
    ) -> SubscriptionHandle
    where
        F: Fn(&TreeChangeEvent) + Send + Sync + 'static,
    {
        self.spawn_prefix_watch(prefix.into(), Arc::new(callback), None)
    }

    /// Like [`on_prefix_change`](Self::on_prefix_change), but synthesizes
    /// `ChangeType::Created` events for every path currently under `prefix`
    /// before forwarding live changes. Closes the Direct-vs-Worker parity
    /// gap: `WorkerProxy::observe` delivers an initial snapshot followed
    /// by live deltas, and consumers wanted the same shape in Direct mode
    /// so panel code is portable.
    ///
    /// **Callback contract: idempotent.** The implementation subscribes to
    /// live events *before* taking the snapshot. If an event arrives
    /// between subscribe and snapshot for a path that's also in the
    /// snapshot, the consumer sees the change twice (synth `Created`
    /// followed by the live event). Removes for paths not in the snapshot
    /// are delivered as-is. Treat both put-shaped and remove-shaped events
    /// as idempotent state transitions and you'll be fine.
    ///
    /// Synth event fields: `path` and `hash` from the listing,
    /// `new_hash = Some(hash)`, `previous_hash = None`, `change_type =
    /// Created`, `context = None`. Down-stream consumers that branch on
    /// `previous_hash` must accept `None` as the seeded-snapshot signal.
    #[allow(dead_code)]
    pub fn on_prefix_change_seeded<F>(
        &self,
        prefix: impl Into<String>,
        callback: F,
    ) -> SubscriptionHandle
    where
        F: Fn(&TreeChangeEvent) + Send + Sync + 'static,
    {
        let prefix = prefix.into();
        let callback = Arc::new(callback);
        // Snapshot AFTER subscribing — see contract above. The
        // `subscribe_events` call inside `spawn_prefix_watch` happens
        // synchronously here, so by the time we call `list`, the receiver
        // is already buffering any concurrent events.
        let snapshot = self.peer_ctx.peer.location_index().list(&prefix);
        self.spawn_prefix_watch(prefix, callback, Some(snapshot))
    }

    /// Shared body for [`on_prefix_change`] and [`on_prefix_change_seeded`].
    /// `seed` is the optional initial-state snapshot — when `Some`, synth
    /// `Created` events fire before the live-event loop starts.
    fn spawn_prefix_watch(
        &self,
        prefix: String,
        callback: Arc<dyn Fn(&TreeChangeEvent) + Send + Sync + 'static>,
        seed: Option<Vec<entity_store::LocationEntry>>,
    ) -> SubscriptionHandle {
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancelled_for_task = cancelled.clone();
        let mut events = self.peer_ctx.peer.subscribe_events();

        let task = async move {
            tracing::debug!(prefix = %prefix, seeded = seed.is_some(), "subscription: started");

            if let Some(entries) = seed {
                for entry in entries {
                    if cancelled_for_task.load(Ordering::Relaxed) {
                        return;
                    }
                    let synth = TreeChangeEvent {
                        path: entry.path,
                        hash: entry.hash,
                        previous_hash: None,
                        new_hash: Some(entry.hash),
                        change_type: ChangeType::Created,
                        context: None,
                    };
                    (callback)(&synth);
                }
            }

            loop {
                if cancelled_for_task.load(Ordering::Relaxed) {
                    tracing::debug!(prefix = %prefix, "subscription: cancelled");
                    break;
                }
                match events.recv().await {
                    Ok(event) => {
                        if event.path.starts_with(&prefix) {
                            (callback)(&event);
                        }
                    }
                    Err(e) if e.to_string().contains("closed") => {
                        tracing::debug!(prefix = %prefix, "subscription: channel closed, stopping");
                        break;
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "subscription: recv error");
                    }
                }
            }
        };

        #[cfg(not(target_arch = "wasm32"))]
        {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(task);
            } else {
                tracing::debug!(
                    "on_prefix_change: no tokio runtime active, subscription will not deliver events"
                );
            }
        }
        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(task);

        SubscriptionHandle { cancelled }
    }

    /// Watch for tree changes matching a pattern (L0 pull-based stream).
    ///
    /// Returns a [`ChangeStream`] that delivers [`ChangeEvent`] values for
    /// paths matching the pattern. The stream cancels automatically when
    /// dropped.
    ///
    /// **Patterns**: exact path match, or prefix with trailing `/*` for
    /// subtree matching (e.g., `"app/browser/*"` matches all paths under
    /// `app/browser/`).
    ///
    /// This is the pull-based alternative to [`subscribe`](Self::subscribe)
    /// (push/callback-based). Same L0 escape-hatch posture — no capability
    /// check, all matching events on the peer's broadcast are delivered.
    /// For a dispatched, capability-checked subscription, use
    /// [`PeerContext::subscribe`] instead.
    ///
    /// Native only — on WASM, use [`generation()`](Self::generation) for
    /// polling-based change detection.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn watch(&self, pattern: impl Into<String>) -> ChangeStream {
        let pattern = pattern.into();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancelled_for_task = cancelled.clone();
        let mut events = self.peer_ctx.peer.subscribe_events();

        let task = async move {
            tracing::debug!(pattern = %pattern, "watch: started");
            loop {
                if cancelled_for_task.load(Ordering::Relaxed) {
                    tracing::debug!(pattern = %pattern, "watch: cancelled");
                    break;
                }
                match events.recv().await {
                    Ok(event) => {
                        if watch_pattern_matches(&pattern, &event.path) {
                            let change = ChangeEvent {
                                event_type: event.change_type,
                                path: event.path,
                                new_hash: event.new_hash,
                            };
                            if tx.send(change).is_err() {
                                // Receiver dropped.
                                break;
                            }
                        }
                    }
                    Err(e) if e.to_string().contains("closed") => {
                        tracing::debug!(pattern = %pattern, "watch: channel closed");
                        break;
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "watch: recv error");
                    }
                }
            }
        };

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(task);
        } else {
            tracing::debug!("watch: no tokio runtime, stream will not deliver events");
        }

        ChangeStream { rx, _cancel: cancelled }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_ecf::{text, to_ecf};

    fn make_entity(entity_type: &str, content: &str) -> Entity {
        let data = to_ecf(&text(content));
        Entity::new(entity_type, data).unwrap()
    }

    fn make_peer_context() -> PeerContext {
        PeerContextBuilder::new()
            .generate_keypair()
            .build()
            .expect("PeerContext build should succeed")
    }

    /// Seed a `system/history/config/*` entity that enables transition
    /// recording for paths matching `pattern`. The history engine's emit
    /// hook checks the cached config table on every tree change.
    #[cfg(not(target_arch = "wasm32"))]
    fn seed_history_config(ctx: &PeerContext, pattern: &str) {
        use entity_ecf::Value;
        let pid = ctx.peer_id();
        let cfg_path = format!("/{}/system/history/config/test-cfg", pid);
        let data = entity_ecf::to_ecf(&Value::Map(vec![
            (entity_ecf::text("enabled"), entity_ecf::bool_val(true)),
            (entity_ecf::text("pattern"), entity_ecf::text(pattern)),
        ]));
        let cfg_entity = Entity::new("system/history/config", data).unwrap();
        ctx.store().put(&cfg_path, cfg_entity).unwrap();
    }

    fn make_sdk() -> EntitySDK {
        EntitySDK::builder()
            .generate_keypair()
            .build()
            .expect("SDK build should succeed")
    }

    #[test]
    fn builder_creates_sdk() {
        let sdk = make_sdk();
        assert!(!sdk.default_peer().peer_id().is_empty());
    }

    #[test]
    fn builder_with_keypair() {
        let keypair = Keypair::generate();
        let expected_pid = keypair.peer_id().to_string();
        let sdk = EntitySDK::builder()
            .keypair(keypair)
            .build()
            .expect("build with keypair should succeed");
        assert_eq!(sdk.default_peer().peer_id(), expected_pid);
    }

    #[test]
    fn builder_no_keypair_errors() {
        let result = EntitySDK::builder().build();
        assert!(result.is_err());
    }

    #[test]
    fn insert_peer_round_trips_a_hook_bearing_context() {
        // Verifies the seam Godot's REQUEST-SDK-PEER-CONTAINER-COHERENCE
        // §3.1 asked for: a consumer constructs a PeerContext with a
        // hook installed on PeerContextBuilder, then inserts it into
        // EntitySDK. Lookup + metadata + container ownership all work.
        let mut sdk = make_sdk();
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter_clone = counter.clone();

        let ctx = PeerContextBuilder::new()
            .keypair(Keypair::generate())
            .config(PeerConfig::default())
            .with_binding_hook("test_observer", move |_evt| {
                counter_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
            .build()
            .expect("PeerContext build");
        let expected_id = ctx.peer_id().to_string();

        let id = sdk
            .insert_peer(ctx)
            .expect("insert_peer of a fresh peer should succeed");
        assert_eq!(id, expected_id);
        assert!(sdk.peer(&id).is_some(), "registry lookup works");
        assert!(sdk.peer_metadata(&id).is_some(), "default metadata installed");
        assert_eq!(
            sdk.peer_metadata(&id).unwrap().label,
            None,
            "default metadata has empty label"
        );
    }

    #[test]
    fn insert_peer_rejects_duplicate_id() {
        let mut sdk = make_sdk();
        let seed = Keypair::generate().secret_key_bytes();
        let ctx1 = PeerContextBuilder::new()
            .keypair(Keypair::from_seed(seed))
            .config(PeerConfig::default())
            .build()
            .unwrap();
        let ctx2 = PeerContextBuilder::new()
            .keypair(Keypair::from_seed(seed))
            .config(PeerConfig::default())
            .build()
            .unwrap();
        sdk.insert_peer(ctx1).expect("first insert succeeds");
        let err = sdk
            .insert_peer(ctx2)
            .expect_err("second insert with same id must fail");
        match err {
            SdkError::Conflict {
                status,
                code,
                message,
            } => {
                assert_eq!(status, 409);
                assert_eq!(code.as_deref(), Some("peer_already_exists"));
                assert!(message.contains("already registered"));
            }
            other => panic!("expected Conflict, got {:?}", other),
        }
    }

    /// EntitySDKBuilder's hook setters forward to PeerContextBuilder for
    /// the default peer. Regression guard for the worker-arm inspect-hook
    /// plumbing — the worker host installs its three default-off inspect
    /// hooks via these
    /// setters before calling `build_async()`.
    #[tokio::test]
    async fn builder_hooks_fire_on_default_peer_writes() {
        use std::sync::atomic::{AtomicUsize, Ordering as O};
        let dispatch_count = std::sync::Arc::new(AtomicUsize::new(0));
        let binding_count = std::sync::Arc::new(AtomicUsize::new(0));
        let dispatch_clone = dispatch_count.clone();
        let binding_clone = binding_count.clone();

        let sdk = EntitySDK::builder()
            .generate_keypair()
            .with_dispatch_hook("test/dispatch", move |_ev| {
                dispatch_clone.fetch_add(1, O::SeqCst);
            })
            .with_binding_hook("test/binding", move |_ev| {
                binding_clone.fetch_add(1, O::SeqCst);
            })
            .with_wire_hook("test/wire", |_ev| {
                // No remote peer in this test, so this never fires — but
                // installing it proves the type bound + builder threading.
            })
            .build()
            .expect("SDK build with hooks should succeed");

        let pid = sdk.default_peer_id().to_string();
        let ent = make_entity("test/doc", "body");
        let path = format!("/{pid}/app/state");
        let _ = sdk
            .put(&pid, &path, ent)
            .await
            .expect("put should succeed");

        assert!(
            dispatch_count.load(O::SeqCst) >= 2,
            "dispatch hook fires at entry + exit per dispatch (≥2 for one put)"
        );
        assert!(
            binding_count.load(O::SeqCst) >= 1,
            "binding hook fires for the new path bind"
        );
    }

    #[test]
    fn insert_peer_with_metadata_installs_caller_supplied_metadata() {
        let mut sdk = make_sdk();
        let ctx = PeerContextBuilder::new()
            .keypair(Keypair::generate())
            .config(PeerConfig::default())
            .build()
            .unwrap();
        let metadata = PeerMetadata {
            label: Some("god-mode operator".into()),
            persisted: true,
            ..PeerMetadata::default()
        };
        let id = sdk
            .insert_peer_with_metadata(ctx, metadata.clone())
            .expect("insert_peer_with_metadata succeeds");
        let stored = sdk
            .peer_metadata(&id)
            .expect("metadata stored under the inserted peer's id");
        assert_eq!(stored.label.as_deref(), Some("god-mode operator"));
        assert!(stored.persisted);
    }

    /// Proves the detached-future contract the consumer's `Peers`
    /// boundary depends on: `EntitySDK::{put,execute,query,count,...}`
    /// return `impl Future + 'static`, so they box into
    /// `Pin<Box<dyn Future + 'static>>` *without* borrowing the SDK.
    /// If anyone regresses these back to `async fn(&self)`, this fails
    /// to compile (the box outlives the `&sdk` borrow). This is the
    /// regression guard for §4.1b — keep it.
    #[tokio::test]
    async fn detached_futures_are_static_boxable() {
        use std::future::Future;
        use std::pin::Pin;

        let sdk = make_sdk();
        let pid = sdk.default_peer_id().to_string();

        // Construct each detached future, box it as 'static, then drop
        // the SDK borrow scope. If any of these were `async fn(&self)`
        // the boxed future would borrow `sdk` and this would not compile.
        let expr = make_entity("system/query/expression", "{}");
        let ent = make_entity("test/doc", "body");

        let boxed: Vec<Pin<Box<dyn Future<Output = ()> + 'static>>> = vec![
            Box::pin({
                let f = sdk.put(&pid, "/x", ent.clone());
                async move { let _ = f.await; }
            }),
            Box::pin({
                let f = sdk.query(&pid, expr.clone());
                async move { let _ = f.await; }
            }),
            Box::pin({
                let f = sdk.count(&pid, expr.clone());
                async move { let _ = f.await; }
            }),
            Box::pin({
                let f = sdk.execute(
                    &pid,
                    "system/tree",
                    "get",
                    ent.clone(),
                    entity_handler::ExecuteOptions::default(),
                );
                async move { let _ = f.await; }
            }),
            Box::pin({
                let f = sdk.discover_handlers(&pid);
                async move { let _ = f.await; }
            }),
            Box::pin({
                let f = sdk.path_count(&pid);
                async move { let _ = f.await; }
            }),
        ];
        // The futures outlive the borrow used to build them.
        assert_eq!(boxed.len(), 6);

        // Unknown peer resolves to a typed error inside the future,
        // never a silent default-to-primary.
        let got = sdk.path_count("no-such-peer").await;
        assert!(matches!(got, Err(SdkError::UnknownPeer(_))));
    }

    // -- PeerContext tests (per-peer API) --

    #[test]
    fn tree_get_bootstrapped() {
        let ctx = make_peer_context();
        let path = format!("/{}/system/tree", ctx.peer_id());
        assert!(ctx.store().get(&path).is_some(), "system/tree should exist");
    }

    #[test]
    fn tree_get_missing_returns_none() {
        let ctx = make_peer_context();
        assert!(ctx.store().get("nonexistent/path").is_none());
    }

    #[test]
    fn tree_has_works() {
        let ctx = make_peer_context();
        let path = format!("/{}/system/tree", ctx.peer_id());
        assert!(ctx.store().has(&path));
        assert!(!ctx.store().has("nonexistent/path"));
    }

    #[test]
    fn tree_list_returns_qualified_paths() {
        let ctx = make_peer_context();
        let path = format!("/{}/docs/readme", ctx.peer_id());
        ctx.store().put(&path, make_entity("test/t", "hello")).unwrap();
        let entries = ctx.store().list(&format!("/{}/docs/", ctx.peer_id()));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, path);
    }

    #[test]
    fn tree_list_includes_system_paths() {
        let ctx = make_peer_context();
        let prefix = format!("/{}/system/", ctx.peer_id());
        let entries = ctx.store().list(&prefix);
        assert!(!entries.is_empty(), "should have bootstrapped system entries");
    }

    #[test]
    fn entity_count_includes_bootstrap() {
        let ctx = make_peer_context();
        assert!(ctx.entity_count() > 0);
    }

    #[test]
    fn path_count_includes_bootstrap() {
        let ctx = make_peer_context();
        assert!(ctx.path_count() > 0);
    }

    #[test]
    fn content_remove_refuses_bound_and_reaps_unbound() {
        use entity_entity::Entity;
        let ctx = make_peer_context();
        let store = ctx.store();
        let p = format!("/{}/app/test/save", ctx.peer_id());

        // A value bound at a path is in the content store.
        let e1 = Entity::new("app/test/save", b"v1".to_vec()).unwrap();
        let h1 = e1.content_hash;
        store.put(&p, e1).unwrap();
        // Refused while the path still binds it (pitfall #1).
        assert_eq!(ctx.content_remove(&h1), ContentRemoveOutcome::StillBound);

        // Overwrite the path → h1 is now superseded / unbound.
        let e2 = Entity::new("app/test/save", b"v2".to_vec()).unwrap();
        let h2 = e2.content_hash;
        store.put(&p, e2).unwrap();
        assert_ne!(h1, h2);

        // h1 is now reclaimable; h2 (the live binding) is still refused.
        assert_eq!(ctx.content_remove(&h1), ContentRemoveOutcome::Removed);
        assert_eq!(ctx.content_remove(&h2), ContentRemoveOutcome::StillBound);
        // A second reclaim of h1 is now a no-op (already gone).
        assert_eq!(ctx.content_remove(&h1), ContentRemoveOutcome::Absent);
    }

    #[test]
    fn content_remove_keeps_a_deduped_blob_shared_by_another_path() {
        use entity_entity::Entity;
        let ctx = make_peer_context();
        let store = ctx.store();
        let pa = format!("/{}/app/test/a", ctx.peer_id());
        let pb = format!("/{}/app/test/b", ctx.peer_id());

        // Two paths bind the SAME bytes → one deduped blob, one hash.
        let a = Entity::new("app/test/save", b"shared".to_vec()).unwrap();
        let h = a.content_hash;
        store.put(&pa, a).unwrap();
        let b = Entity::new("app/test/save", b"shared".to_vec()).unwrap();
        assert_eq!(b.content_hash, h);
        store.put(&pb, b).unwrap();

        // Unbind /…/a; /…/b still binds the shared hash → must NOT reap.
        store.remove(&pa);
        assert_eq!(ctx.content_remove(&h), ContentRemoveOutcome::StillBound);

        // Unbind /…/b too → now safely reclaimable.
        store.remove(&pb);
        assert_eq!(ctx.content_remove(&h), ContentRemoveOutcome::Removed);
    }

    #[test]
    fn generation_starts_at_zero() {
        let ctx = make_peer_context();
        assert_eq!(ctx.store().generation(), 0);
    }

    #[test]
    fn tree_put_increments_generation() {
        let ctx = make_peer_context();
        let p1 = format!("/{}/test/a", ctx.peer_id());
        let p2 = format!("/{}/test/b", ctx.peer_id());
        ctx.store().put(&p1, make_entity("t", "1")).unwrap();
        assert_eq!(ctx.store().generation(), 1);
        ctx.store().put(&p2, make_entity("t", "2")).unwrap();
        assert_eq!(ctx.store().generation(), 2);
    }

    #[test]
    fn discover_handlers_finds_system_tree() {
        let ctx = make_peer_context();
        let handlers = ctx.discover_handlers();
        assert!(!handlers.is_empty(), "should discover bootstrapped handlers");
        let tree = handlers.iter().find(|h| h.pattern == "system/tree");
        assert!(tree.is_some(), "system/tree handler should be found");
        let tree = tree.unwrap();
        assert!(!tree.name.is_empty());
        assert!(!tree.operations.is_empty());
    }

    #[test]
    fn discover_handlers_sorted() {
        let ctx = make_peer_context();
        let handlers = ctx.discover_handlers();
        for pair in handlers.windows(2) {
            assert!(pair[0].pattern <= pair[1].pattern, "handlers should be sorted");
        }
    }

    #[test]
    fn discover_types_finds_bootstrapped() {
        let ctx = make_peer_context();
        let types = ctx.discover_types();
        assert!(!types.is_empty(), "should discover bootstrapped type definitions");
    }

    #[test]
    fn discover_types_sorted() {
        let ctx = make_peer_context();
        let types = ctx.discover_types();
        for pair in types.windows(2) {
            assert!(pair[0].type_path <= pair[1].type_path, "types should be sorted by type_path");
        }
    }

    #[test]
    fn parse_query_result_handles_bare_form() {
        use entity_ecf::Value;
        // Synthesize a bare system/query/result entity with one match.
        // Hash wire format is 33 bytes (1 algorithm byte + 32 digest bytes).
        let hash_bytes: Vec<u8> = vec![0u8; 33];
        let result_entity = Entity::new(
            "system/query/result",
            to_ecf(&Value::Map(vec![
                (text("has_more"), entity_ecf::bool_val(false)),
                (text("matches"), Value::Array(vec![Value::Map(vec![
                    (text("hash"), Value::Bytes(hash_bytes.clone())),
                    (text("path"), text("/peer/x/foo")),
                    (text("type"), text("test/foo")),
                ])])),
                (text("total"), entity_ecf::integer(1)),
            ])),
        ).unwrap();

        let parsed = parse_query_result(&result_entity).expect("should parse");
        assert!(!parsed.has_more);
        assert_eq!(parsed.total, 1);
        assert!(parsed.cursor.is_none());
        assert_eq!(parsed.matches.len(), 1);
        let m = &parsed.matches[0];
        assert_eq!(m.path, "/peer/x/foo");
        assert_eq!(m.entity_type, "test/foo");
        assert!(m.entity.is_none(), "bare form: no included entity");
    }

    #[test]
    fn parse_query_result_handles_envelope_with_included() {
        use entity_ecf::Value;
        // Build a real entity to seed both the match (via its hash) and the
        // envelope's `included` map.
        let inner = make_entity("test/inner", "payload");
        let inner_hash_bytes = inner.content_hash.to_bytes().to_vec();

        // Build the inner query-result map (root payload of the envelope).
        let result_inner = to_ecf(&Value::Map(vec![
            (text("has_more"), entity_ecf::bool_val(false)),
            (text("matches"), Value::Array(vec![Value::Map(vec![
                (text("hash"), Value::Bytes(inner_hash_bytes.clone())),
                (text("path"), text("/peer/x/foo")),
                (text("type"), text("test/inner")),
            ])])),
            (text("total"), entity_ecf::integer(1)),
        ]));

        // Build the envelope: { root: {type, data}, included: {hash → {type, data}} }.
        let envelope_data = to_ecf(&Value::Map(vec![
            (text("root"), Value::Map(vec![
                (text("type"), text("system/query/result")),
                (text("data"), Value::Bytes(result_inner)),
            ])),
            (text("included"), Value::Map(vec![
                (Value::Bytes(inner_hash_bytes), Value::Map(vec![
                    (text("type"), text(&inner.entity_type)),
                    (text("data"), Value::Bytes(inner.data.clone())),
                ])),
            ])),
        ]));
        let envelope = Entity::new("system/envelope", envelope_data).unwrap();

        let parsed = parse_query_result(&envelope).expect("should parse envelope");
        assert_eq!(parsed.matches.len(), 1);
        let m = &parsed.matches[0];
        assert_eq!(m.path, "/peer/x/foo");
        let included = m.entity.as_ref().expect("envelope: included entity attached");
        assert_eq!(included.entity_type, "test/inner");
        assert_eq!(included.data, inner.data);
    }

    #[test]
    fn storage_kind_defaults_to_memory() {
        let ctx = make_peer_context();
        assert_eq!(ctx.storage_kind(), "memory");
    }

    #[test]
    fn entity_sdk_peer_arc_returns_owned_shareable_handle() {
        // The Tier 2 multi-peer hosting path needs Arc<PeerContext>
        // handles that outlive a `&self` borrow. Verifies the two
        // accessors round-trip and share storage with `peer()` /
        // `default_peer()`.
        let sdk = EntitySDK::builder()
            .generate_keypair()
            .build()
            .expect("build sdk with one peer");

        let pid = sdk.default_peer_id().to_string();

        let arc = sdk.peer_arc(&pid).expect("peer_arc resolves");
        // Owned handle: addresses match between &PeerContext (borrow)
        // and Arc::as_ref (deref through Arc).
        assert_eq!(
            arc.as_ref() as *const PeerContext,
            sdk.peer(&pid).expect("peer borrow") as *const PeerContext
        );
        // Strong count ≥ 2 (the map + our clone).
        assert!(Arc::strong_count(&arc) >= 2);

        let default_arc = sdk.default_peer_arc();
        assert_eq!(
            default_arc.as_ref() as *const PeerContext,
            arc.as_ref() as *const PeerContext
        );

        assert!(sdk.peer_arc("nonexistent").is_none());
    }

    #[test]
    fn installed_extensions_lists_default_feature_set() {
        // The SDK's default feature set in Cargo.toml is:
        //   inbox, continuation, subscription, clock, revision, query,
        //   history, sqlite
        // The free fn enumerates ALL enabled features in the substrate-
        // bridge set (it doesn't list sqlite — that's a storage backend,
        // not an extension). With `cargo test -p entity-sdk` running
        // under default features, these seven extensions must all
        // appear.
        let exts = crate::installed_extensions();
        for required in &[
            "inbox",
            "continuation",
            "subscription",
            "clock",
            "revision",
            "query",
            "history",
        ] {
            assert!(
                exts.contains(required),
                "default-feature run must list {} — got {:?}",
                required,
                exts
            );
        }
        // PeerContext mirror returns the same list today (Tier 2 may
        // diverge per-peer; not relevant pre-Tier-2).
        let ctx = make_peer_context();
        assert_eq!(ctx.installed_extensions(), exts);
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "sqlite"))]
    #[test]
    fn storage_kind_is_sqlite_when_builder_sets_sqlite_path() {
        let unique = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let db_path = std::env::temp_dir().join(format!("entity-sdk-storage-kind-{}.db", unique));
        let _cleanup = TempPath(db_path.clone());

        let kp = Keypair::from_seed([9u8; 32]);
        let ctx = PeerContextBuilder::new()
            .keypair(kp)
            .sqlite(&db_path)
            .build()
            .expect("sqlite build");
        assert_eq!(ctx.storage_kind(), "sqlite");
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "sqlite"))]
    #[test]
    fn sqlite_backed_peer_persists_tree_across_restarts() {
        // First session: build a peer with a sqlite-backed tree, write
        // an entity, drop. Second session: rebuild over the same path
        // with the same seed, confirm the entity is still there.
        let unique = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let db_path = std::env::temp_dir().join(format!("entity-sdk-test-{}.db", unique));
        let _cleanup = TempPath(db_path.clone());

        // Reproducible identity across both sessions.
        let seed = [7u8; 32];
        let kp1 = Keypair::from_seed(seed);
        let pid = kp1.peer_id().to_string();
        let target = format!("/{}/app/test/persisted", pid);

        {
            let ctx = PeerContextBuilder::new()
                .keypair(kp1)
                .sqlite(&db_path)
                .build()
                .expect("first-session sqlite build");
            ctx.store().put(&target, make_entity("test/v", "hello")).unwrap();
        }

        let kp2 = Keypair::from_seed(seed);
        let ctx2 = PeerContextBuilder::new()
            .keypair(kp2)
            .sqlite(&db_path)
            .build()
            .expect("second-session sqlite build");
        let restored = ctx2.store().get(&target).expect("entity should persist across restarts");
        assert_eq!(restored.entity_type, "test/v");
    }

    /// Cleans up a temp file when dropped. Used by the sqlite restart
    /// test to avoid leaving DB files in the system temp dir.
    #[cfg(all(not(target_arch = "wasm32"), feature = "sqlite"))]
    struct TempPath(std::path::PathBuf);

    #[cfg(all(not(target_arch = "wasm32"), feature = "sqlite"))]
    impl Drop for TempPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            // SQLite WAL files: best-effort cleanup.
            let mut wal = self.0.clone();
            wal.set_extension("db-wal");
            let _ = std::fs::remove_file(&wal);
            let mut shm = self.0.clone();
            shm.set_extension("db-shm");
            let _ = std::fs::remove_file(&shm);
        }
    }

    #[test]
    fn inbox_list_empty_on_fresh_peer() {
        let ctx = make_peer_context();
        assert!(ctx.inbox_list().is_empty(), "fresh peer's inbox should be empty");
    }

    #[test]
    fn inbox_list_finds_seeded_delivery() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let path = format!("/{}/system/inbox/test-delivery", pid);
        ctx.store().put(&path, make_entity("test/delivery", "payload")).unwrap();

        let entries = ctx.inbox_list();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, path);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "current_thread")]
    async fn inbox_send_stores_message_at_request_id_path() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let target = format!("/{}/system/inbox/note-channel", pid);

        let msg = make_entity("test/message", "hello-inbox");
        let storage_path = ctx
            .inbox_send(target.clone(), msg, Some("rid-42".into()))
            .await
            .expect("inbox_send should succeed");

        // Storage path == {target}/{request_id} per handler at
        // extensions/inbox/src/lib.rs:104.
        assert_eq!(storage_path, format!("{}/rid-42", target));

        // Round-trip through inbox_get with the relative form.
        let got = ctx
            .inbox_get("note-channel/rid-42")
            .expect("inbox_get should resolve");
        assert_eq!(got.entity_type, "test/message");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "current_thread")]
    async fn inbox_send_mints_distinct_nonces_when_request_id_is_none() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let target = format!("/{}/system/inbox/auto-channel", pid);

        let p1 = ctx
            .inbox_send(target.clone(), make_entity("test/m", "a"), None)
            .await
            .expect("first send");
        let p2 = ctx
            .inbox_send(target.clone(), make_entity("test/m", "b"), None)
            .await
            .expect("second send");

        assert_ne!(p1, p2, "SDK-minted nonces must be unique per call");
        assert!(p1.starts_with(&target));
        assert!(p2.starts_with(&target));
        // Both deliveries are listed.
        assert_eq!(ctx.inbox_list().len(), 2);
    }

    #[test]
    fn inbox_get_round_trips_seeded_delivery() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let path = format!("/{}/system/inbox/sub-1/event-42", pid);
        ctx.store().put(&path, make_entity("test/delivery", "hello")).unwrap();

        let got = ctx.inbox_get("sub-1/event-42").expect("delivery should be found");
        assert_eq!(got.entity_type, "test/delivery");

        // Leading-slash form also resolves correctly.
        let got2 = ctx.inbox_get("/sub-1/event-42");
        assert!(got2.is_some(), "leading slash should be tolerated");

        // Missing path → None.
        assert!(ctx.inbox_get("nonexistent").is_none());
    }

    /// PEER-GENERAL SITE CACHE — §4a verification (do-it-right probe).
    ///
    /// The peer-general site cache (Category A) write-through
    /// stores fetched foreign content at its NATURAL universal path
    /// `/{foreign}/sites/...` in MY store — a cross-namespace L1 write. The P1
    /// handoff predicted that write succeeds "ONLY because every peer is built
    /// `debug_open_grants:true`" and would start failing (silently) when that
    /// deprecated flag is removed in v7.75.
    ///
    /// That prediction was a STATIC read of `check_permission` in isolation.
    /// The LIVE local-dispatch path that `ctx.put` takes
    /// (`connection.rs` `make_execute_fn` local branch) carries NO capability
    /// constraint ("matching_grant intentionally absent"); the tree handler
    /// `handle_put` validates only path shape, not the caller's namespace; and
    /// `debug_open_grants` feeds only the *remote* AUTHENTICATE grants
    /// (`connection.rs:395`), never a local put. So the cross-namespace cache
    /// write is not capability-gated at all.
    ///
    /// This test pins that: `make_peer_context()` builds with
    /// `PeerConfig::default()` (debug_open_grants == FALSE), and an L1 put to a
    /// REAL foreign peer-id lands and reads back. If a future revision adds
    /// capability enforcement to local dispatch, THIS test breaks — which is
    /// exactly the loud signal §4a wanted instead of a silent cache stall.
    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "current_thread")]
    async fn cross_namespace_site_cache_put_lands_with_open_grants_off() {
        let ctx = make_peer_context();
        // Sanity: the flag the handoff feared is OFF on this peer.
        assert!(
            !ctx.shared.config.debug_open_grants,
            "make_peer_context must build with debug_open_grants == false"
        );

        // A REAL foreign peer-id (§4b: tree.put validates the peer segment is
        // ~46-char Base58; a fake id is silently dropped on the write path).
        let foreign_pid = Keypair::generate().peer_id().to_string();
        let manifest_path = format!("/{}/sites/blog/manifest", foreign_pid);
        let page_path = format!("/{}/sites/blog/pages/post-3", foreign_pid);

        // Write-through: cache foreign content at its natural universal path.
        ctx.put(&manifest_path, make_entity("site/manifest", "m"))
            .await
            .expect("cross-namespace cache write of the manifest must land");
        ctx.put(&page_path, make_entity("site/page", "body"))
            .await
            .expect("cross-namespace cache write of a deep page must land");

        // Reads from MY store with the universal foreign path (resolver §2 fix).
        assert!(
            ctx.get(&manifest_path).await.expect("get manifest").is_some(),
            "cached foreign manifest must read back from my store"
        );
        assert!(
            ctx.get(&page_path).await.expect("get page").is_some(),
            "cached foreign page must read back from my store"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "current_thread")]
    async fn history_query_returns_transitions_after_writes() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let path = format!("/{}/app/test/history-target", pid);

        seed_history_config(&ctx, &format!("/{}/app/test/*", pid));

        // L1 put — goes through dispatch + emit pathway, which is what
        // the history engine hooks. L0 store().put() bypasses the hook.
        ctx.put(&path, make_entity("test/v", "v1")).await.unwrap();
        ctx.put(&path, make_entity("test/v", "v2")).await.unwrap();

        let result = ctx.history_query(&path, HistoryQueryOptions::default()).await.expect("history query should succeed");
        assert_eq!(result.path, path);
        assert!(
            result.transitions.len() >= 2,
            "expected ≥2 transitions, got {}",
            result.transitions.len()
        );
        assert!(result.head.is_some(), "head should be set after writes");
        assert!(
            result.transitions
                .iter()
                .any(|t| matches!(t.event.as_str(), "created" | "updated")),
            "transitions should include at least one create/update event, got: {:?}",
            result.transitions.iter().map(|t| t.event.as_str()).collect::<Vec<_>>()
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "current_thread")]
    async fn history_query_events_filter_narrows_to_named_kinds() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let path = format!("/{}/app/test/events-filter", pid);

        seed_history_config(&ctx, &format!("/{}/app/test/*", pid));

        ctx.put(&path, make_entity("test/v", "v1")).await.unwrap();
        ctx.put(&path, make_entity("test/v", "v2")).await.unwrap();
        ctx.remove(&path).await.unwrap();

        // Unfiltered: at least one created + one deleted exists.
        let unfiltered = ctx
            .history_query(&path, HistoryQueryOptions::default())
            .await
            .expect("unfiltered query");
        let events_seen: std::collections::HashSet<_> = unfiltered
            .transitions
            .iter()
            .map(|t| t.event.clone())
            .collect();
        assert!(
            events_seen.contains("deleted"),
            "expected a deleted transition; got {:?}",
            events_seen
        );

        // Filter to just deleted — every transition must be tagged deleted.
        let filtered = ctx
            .history_query(
                &path,
                HistoryQueryOptions {
                    events: Some(vec!["deleted".into()]),
                    ..Default::default()
                },
            )
            .await
            .expect("filtered query");
        assert!(!filtered.transitions.is_empty(), "expected ≥1 deleted transition");
        for t in &filtered.transitions {
            assert_eq!(t.event, "deleted", "events filter must drop non-matching transitions");
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "current_thread")]
    async fn history_query_before_filter_drops_transitions_at_or_after_timestamp() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let path = format!("/{}/app/test/before-filter", pid);

        seed_history_config(&ctx, &format!("/{}/app/test/*", pid));

        ctx.put(&path, make_entity("test/v", "early")).await.unwrap();
        // Capture a timestamp between the two writes.
        let cutoff_ms = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .expect("clock")
            .as_millis() as u64;
        // Sleep enough to put the second transition strictly after cutoff.
        // Engine timestamps come from `web_time::SystemTime::now()` at
        // `extensions/history/src/engine.rs:283-286`. 5ms is safe with
        // millisecond precision.
        std::thread::sleep(std::time::Duration::from_millis(5));
        ctx.put(&path, make_entity("test/v", "late")).await.unwrap();

        let r = ctx
            .history_query(
                &path,
                HistoryQueryOptions {
                    before: Some(cutoff_ms),
                    ..Default::default()
                },
            )
            .await
            .expect("before-filtered query");

        // Handler check at extensions/history/src/lib.rs:142 is
        // `transition_data.timestamp >= before` → skip. So we keep
        // only transitions with timestamp < cutoff (the "early" one).
        for t in &r.transitions {
            assert!(
                t.timestamp < cutoff_ms,
                "before-filter must drop timestamp={} (cutoff={})",
                t.timestamp,
                cutoff_ms
            );
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "current_thread")]
    async fn history_query_since_filter_stops_walk_at_hash() {
        // IMPORTANT consumer note (verified against handler line 119+):
        // `since` is matched against the TRANSITION ENTITY hash being
        // walked — i.e. `HistoryQueryResult.head` (the most recent
        // transition entity hash). It is NOT the path content_hash
        // surfaced as `HistoryTransition.hash`. Consumers paginate by
        // capturing `head` from query N and passing it as `since` in
        // query N+1 to "give me everything older than the head I
        // already saw" — though today only the head is surfaced, so
        // arbitrary mid-walk anchors aren't reachable via the public
        // SDK shape (separate ask if paging beyond one window is
        // needed).
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let path = format!("/{}/app/test/since-filter", pid);

        seed_history_config(&ctx, &format!("/{}/app/test/*", pid));
        ctx.put(&path, make_entity("test/v", "v1")).await.unwrap();
        ctx.put(&path, make_entity("test/v", "v2")).await.unwrap();
        ctx.put(&path, make_entity("test/v", "v3")).await.unwrap();

        let unbounded = ctx
            .history_query(&path, HistoryQueryOptions::default())
            .await
            .expect("unbounded");
        let head = unbounded.head.expect("head present after writes");
        assert!(unbounded.transitions.len() >= 3);

        // since == head: walk hits the anchor on iteration 1 and breaks
        // before recording → zero transitions returned.
        let bounded = ctx
            .history_query(
                &path,
                HistoryQueryOptions {
                    since: Some(head),
                    ..Default::default()
                },
            )
            .await
            .expect("bounded");
        assert!(
            bounded.transitions.is_empty(),
            "since=head must stop the walk before any transition is recorded; \
             got {} transitions",
            bounded.transitions.len()
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "current_thread")]
    async fn history_query_filters_compose() {
        // Combined: limit + events. Asserts both apply.
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let path = format!("/{}/app/test/combined-filter", pid);
        seed_history_config(&ctx, &format!("/{}/app/test/*", pid));

        // Mix of created + updated; 4 writes total.
        ctx.put(&path, make_entity("test/v", "a")).await.unwrap();
        ctx.put(&path, make_entity("test/v", "b")).await.unwrap();
        ctx.put(&path, make_entity("test/v", "c")).await.unwrap();
        ctx.put(&path, make_entity("test/v", "d")).await.unwrap();

        let r = ctx
            .history_query(
                &path,
                HistoryQueryOptions {
                    limit: Some(2),
                    events: Some(vec!["updated".into()]),
                    ..Default::default()
                },
            )
            .await
            .expect("combined query");
        assert!(r.transitions.len() <= 2, "limit must cap the result");
        for t in &r.transitions {
            assert_eq!(t.event, "updated");
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "current_thread")]
    async fn history_query_empty_for_untouched_path() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let path = format!("/{}/app/test/never-written", pid);

        let result = ctx.history_query(&path, HistoryQueryOptions::default()).await.expect("history query should succeed");
        assert!(result.transitions.is_empty());
        assert!(result.head.is_none());
        assert!(!result.has_more);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "current_thread")]
    async fn history_rollback_restores_previous_value() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let path = format!("/{}/app/test/rollback-target", pid);

        seed_history_config(&ctx, &format!("/{}/app/test/*", pid));

        let v1 = make_entity("test/v", "v1");
        let v1_hash = v1.content_hash;
        // L1 put so the history engine records the transition.
        ctx.put(&path, v1).await.unwrap();
        ctx.put(&path, make_entity("test/v", "v2")).await.unwrap();

        ctx.history_rollback(&path, v1_hash)
            .await
            .expect("rollback should succeed");

        let restored = ctx.store().get(&path).expect("path should still resolve after rollback");
        assert_eq!(restored.content_hash, v1_hash);
    }

    #[test]
    fn parse_count_result_extracts_uint() {
        use entity_ecf::{integer, to_ecf};
        let entity = Entity::new("primitive/uint", to_ecf(&integer(42))).unwrap();
        assert_eq!(parse_count_result(&entity).unwrap(), 42);
    }

    #[test]
    fn parse_count_result_rejects_negative() {
        use entity_ecf::{integer, to_ecf};
        let entity = Entity::new("primitive/uint", to_ecf(&integer(-1))).unwrap();
        assert!(parse_count_result(&entity).is_err());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "current_thread")]
    async fn count_matches_seeded_entities() {
        use entity_ecf::Value;
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();

        for i in 0..3 {
            ctx.store().put(
                &format!("/{}/app/test/article-{}", pid, i),
                Entity::new("test/article", to_ecf(&text("body"))).unwrap(),
            ).unwrap();
        }
        ctx.store().put(
            &format!("/{}/app/test/note-1", pid),
            Entity::new("test/note", to_ecf(&text("note"))).unwrap(),
        ).unwrap();

        let expr = Entity::new(
            "system/query/expression",
            to_ecf(&Value::Map(vec![(text("type_filter"), text("test/article"))])),
        ).unwrap();
        let n = ctx.count(expr).await.expect("count should succeed");
        assert_eq!(n, 3);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "current_thread")]
    async fn query_finds_seeded_entity() {
        use entity_ecf::Value;
        // Bootstrap a peer, seed two entities of distinct types, then run a
        // query filtered by type — verify it round-trips through dispatch.
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();

        let target = format!("/{}/app/test/article-1", pid);
        ctx.store().put(&target, Entity::new("test/article", to_ecf(&text("hi"))).unwrap()).unwrap();
        ctx.store().put(
            &format!("/{}/app/test/note-1", pid),
            Entity::new("test/note", to_ecf(&text("hello"))).unwrap(),
        ).unwrap();

        let expr = Entity::new(
            "system/query/expression",
            to_ecf(&Value::Map(vec![(text("type_filter"), text("test/article"))])),
        ).unwrap();

        let results = ctx.query(expr).await.expect("query should succeed");
        assert!(
            results.matches.iter().any(|m| m.path == target && m.entity_type == "test/article"),
            "query should find seeded test/article entity, got: {:?}",
            results.matches.iter().map(|m| (m.path.as_str(), m.entity_type.as_str())).collect::<Vec<_>>()
        );
        assert!(
            !results.matches.iter().any(|m| m.entity_type == "test/note"),
            "query with type_filter should not match other types"
        );
    }

    #[test]
    fn discover_types_includes_handler_definition() {
        // Every peer bootstraps `system/handler` and `system/type` themselves
        // as type entities; either one is enough to prove the read path works.
        let ctx = make_peer_context();
        let types = ctx.discover_types();
        let names: Vec<&str> = types.iter().map(|t| t.type_path.as_str()).collect();
        assert!(
            names.iter().any(|n| *n == "system/handler" || *n == "system/type"),
            "expected core type definitions in discover_types output, got {:?}",
            names
        );
    }

    #[test]
    fn peer_escape_hatch() {
        let ctx = make_peer_context();
        assert!(!ctx.peer().peer_id().to_string().is_empty());
    }

    #[test]
    fn peer_shared_escape_hatch() {
        let ctx = make_peer_context();
        let shared = ctx.peer_shared();
        assert!(!shared.peer_id.to_string().is_empty());
    }

    /// Regression gate for the `Peer::shared` throwaway bug —
    /// `PeerContext::connect_to` must insert the new `RemoteConnection`
    /// into the **persistent** `PeerContext.shared.remote` pool that
    /// cross-peer dispatch reads from. (`Peer::connect_to` inserts into
    /// a fresh `Arc<PeerShared>` returned by `Peer::shared()` that's
    /// dropped on return; the pool is empty afterwards.)
    ///
    /// This routes around the substrate's peer-shared and transport
    /// bug. Once `Peer::shared` ships Shape A (long-lived Arc),
    /// this test still passes — the implementation collapses to a
    /// `self.peer.connect_to(addr)` forward but the post-condition
    /// (`peer_shared().remote.get(pid).is_some()`) remains.
    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_to_populates_persistent_remote_pool() {
        use entity_peer::transport::{
            MemoryConnector, MemoryListener, MemoryTransportRegistry,
        };
        use std::sync::Arc;

        let reg = MemoryTransportRegistry::new();

        // Peer A — the dialer. Uses MemoryConnector against `reg`.
        let ctx_a = PeerContextBuilder::new()
            .generate_keypair()
            .connector(Arc::new(MemoryConnector::new(reg.clone())))
            .build()
            .expect("ctx_a build");

        // Peer B — the listener. Same registry; bind under its
        // peer-id so `memory://{b_pid}` resolves.
        let ctx_b = PeerContextBuilder::new()
            .generate_keypair()
            .connector(Arc::new(MemoryConnector::new(reg.clone())))
            .build()
            .expect("ctx_b build");
        let b_pid = ctx_b.peer_id().to_string();
        let listener = MemoryListener::bind(b_pid.clone(), reg.clone())
            .expect("bind MemoryListener");

        // Spawn B's accept loop (multi_thread flavor → tokio::spawn).
        // Drop the JoinHandle at test end to abort cleanly.
        let b_shared = ctx_b.peer_shared();
        let server_task = tokio::spawn(async move {
            let _ = entity_peer::server::run(listener, b_shared).await;
        });

        // Dial.
        let returned_pid = ctx_a
            .connect_to(&format!("memory://{b_pid}"))
            .await
            .expect("connect_to should succeed against a live MemoryListener");
        assert_eq!(
            returned_pid, b_pid,
            "connect_to must return the peer-id from the handshake"
        );

        // THE LOAD-BEARING ASSERTION: the connection lives in the
        // pool A's cross-peer dispatch will actually read from.
        // If we routed through the substrate `Peer::connect_to` bug,
        // this `get` would be None and cross-peer execute would fall
        // through to `resolve_transport_address` and fail.
        let pooled = ctx_a.peer_shared().remote.get(&b_pid);
        assert!(
            pooled.is_some(),
            "PeerContext::connect_to must insert into the PERSISTENT \
             pool (PeerContext.shared.remote). Got None — the §1 fix \
             regressed."
        );

        server_task.abort();
    }

    #[test]
    fn set_wake_fn_callable() {
        let ctx = make_peer_context();
        ctx.set_wake_fn(|| {});
        let guard = ctx.wake_fn.lock().unwrap();
        assert!(guard.is_some());
    }

    #[test]
    fn tree_list_from_root_shows_peer_namespace() {
        let ctx = make_peer_context();
        let entries = ctx.store().list("");
        assert!(!entries.is_empty());
        let prefix = format!("/{}", ctx.peer_id());
        for entry in &entries {
            assert!(
                entry.path.starts_with(&prefix),
                "path {} should start with /{}",
                entry.path,
                ctx.peer_id()
            );
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn subscribe_events_returns_receiver() {
        let ctx = make_peer_context();
        let _rx = ctx.store().subscribe_events();
        let _rx2 = ctx.store().subscribe_events();
    }

    // -- EntitySDK container tests --

    #[test]
    fn multi_peer_create_and_lookup() {
        let mut sdk = make_sdk();
        let default_id = sdk.default_peer_id().to_string();
        assert_eq!(sdk.peer_ids().len(), 1);

        let kp = Keypair::generate();
        let new_id = sdk.create_peer(kp, PeerConfig::default(), None).unwrap();
        assert_ne!(new_id, default_id);
        assert_eq!(sdk.peer_ids().len(), 2);
        assert!(sdk.peer(&new_id).is_some());
        assert!(sdk.peer(&default_id).is_some());
        assert!(sdk.peer("nonexistent").is_none());
    }

    #[test]
    fn multi_peer_generation_aggregates() {
        let mut sdk = make_sdk();
        let kp = Keypair::generate();
        let peer2_id = sdk.create_peer(kp, PeerConfig::default(), None).unwrap();

        assert_eq!(sdk.generation(), 0);
        sdk.default_peer().store().put("/{}/test/a", make_entity("t", "1")).ok();
        assert_eq!(sdk.generation(), 1);
        sdk.peer(&peer2_id).unwrap().store().put("/{}/test/b", make_entity("t", "2")).ok();
        assert_eq!(sdk.generation(), 2);
    }

    // -- Backend peer (metadata-only) tests --

    #[test]
    fn register_backend_peer_appears_in_peer_ids() {
        let mut sdk = make_sdk();
        let default_id = sdk.default_peer_id().to_string();
        assert_eq!(sdk.peer_ids().len(), 1);

        let backend_pid = "2KBackendPeerFakeId12345".to_string();
        let ok = sdk.register_backend_peer(backend_pid.clone(), PeerMetadata {
            label: Some("test-backend".into()),
            listen_addresses: vec!["ws://127.0.0.1:4042".into()],
            ..PeerMetadata::default()
        });
        assert!(ok);
        assert_eq!(sdk.peer_ids().len(), 2);
        assert!(sdk.peer_ids().contains(&backend_pid.as_str()));
        assert!(sdk.peer_ids().contains(&default_id.as_str()));
    }

    #[test]
    fn set_peer_label_preserves_other_metadata_fields() {
        let mut sdk = make_sdk();
        let default_id = sdk.default_peer_id().to_string();

        // Seed metadata with non-default `persisted` + `listen_addresses`.
        sdk.set_metadata(
            &default_id,
            PeerMetadata {
                label: Some("old-name".into()),
                persisted: true,
                listen_addresses: vec!["ws://127.0.0.1:5555".into()],
            },
        );

        // Focused rename — must NOT touch persisted/listen_addresses.
        sdk.set_peer_label(&default_id, Some("new-name".into()));
        let meta = sdk.peer_metadata(&default_id).expect("metadata present");
        assert_eq!(meta.label.as_deref(), Some("new-name"));
        assert!(meta.persisted, "persisted MUST survive a label-only update");
        assert_eq!(
            meta.listen_addresses,
            vec!["ws://127.0.0.1:5555".to_string()],
            "listen_addresses MUST survive a label-only update"
        );

        // Clear the label (None) — sibling fields still untouched.
        sdk.set_peer_label(&default_id, None);
        let meta = sdk.peer_metadata(&default_id).expect("metadata present");
        assert!(meta.label.is_none(), "None label clears the field");
        assert!(meta.persisted);
        assert_eq!(meta.listen_addresses.len(), 1);
    }

    #[test]
    fn set_peer_label_touches_backend_hosted_peer() {
        // Driver per request §6: backend-hosted peers (no PeerContext;
        // metadata-only registration) must be addressable by the helper.
        let mut sdk = make_sdk();
        let backend_pid = "2KBackendPeerLabelTest".to_string();
        sdk.register_backend_peer(
            backend_pid.clone(),
            PeerMetadata {
                label: Some("backend-orig".into()),
                listen_addresses: vec!["ws://remote:4042".into()],
                ..PeerMetadata::default()
            },
        );

        sdk.set_peer_label(&backend_pid, Some("backend-renamed".into()));
        let meta = sdk.peer_metadata(&backend_pid).expect("backend metadata present");
        assert_eq!(meta.label.as_deref(), Some("backend-renamed"));
        assert_eq!(
            meta.listen_addresses,
            vec!["ws://remote:4042".to_string()],
            "backend listen_addresses MUST survive label update"
        );
        // Backend peers have no PeerContext — verify is_backend_hosted
        // composition (per request §3 reclassification) still works.
        assert!(sdk.peer_metadata(&backend_pid).is_some());
        assert!(!sdk.has_peer_context(&backend_pid));
    }

    #[test]
    fn set_peer_label_creates_metadata_for_unknown_peer() {
        // Matches set_metadata's "treat unknown as fresh write" shape
        // documented in set_peer_label's doc-comment.
        let mut sdk = make_sdk();
        let unknown_pid = "2KUnknownPeerForLabelInit".to_string();
        assert!(sdk.peer_metadata(&unknown_pid).is_none());

        sdk.set_peer_label(&unknown_pid, Some("first-name".into()));
        let meta = sdk.peer_metadata(&unknown_pid).expect("entry now exists");
        assert_eq!(meta.label.as_deref(), Some("first-name"));
        assert!(!meta.persisted, "default field");
        assert!(meta.listen_addresses.is_empty(), "default field");
    }

    #[test]
    fn backend_peer_has_no_peer_context() {
        let mut sdk = make_sdk();
        let backend_pid = "2KBackendPeerFakeId67890".to_string();
        sdk.register_backend_peer(backend_pid.clone(), PeerMetadata::default());

        // No PeerContext for backend peers.
        assert!(!sdk.has_peer_context(&backend_pid));
        assert!(sdk.peer(&backend_pid).is_none());

        // Default peer has PeerContext.
        assert!(sdk.has_peer_context(sdk.default_peer_id()));
    }

    #[test]
    fn backend_peer_metadata_accessible() {
        let mut sdk = make_sdk();
        let backend_pid = "2KBackendMeta123".to_string();
        sdk.register_backend_peer(backend_pid.clone(), PeerMetadata {
            label: Some("my-backend".into()),
            listen_addresses: vec!["ws://127.0.0.1:9999".into(), "tcp://0.0.0.0:4040".into()],
            ..PeerMetadata::default()
        });

        let meta = sdk.peer_metadata(&backend_pid).unwrap();
        assert_eq!(meta.label.as_deref(), Some("my-backend"));
        assert_eq!(meta.listen_addresses.len(), 2);
    }

    #[test]
    fn remove_backend_peer() {
        let mut sdk = make_sdk();
        let backend_pid = "2KBackendRemove123".to_string();
        sdk.register_backend_peer(backend_pid.clone(), PeerMetadata::default());
        assert_eq!(sdk.peer_ids().len(), 2);

        assert!(sdk.remove_peer(&backend_pid));
        assert_eq!(sdk.peer_ids().len(), 1);
        assert!(sdk.peer_metadata(&backend_pid).is_none());
    }

    #[test]
    fn register_duplicate_backend_peer_fails() {
        let mut sdk = make_sdk();
        let backend_pid = "2KBackendDup123".to_string();
        assert!(sdk.register_backend_peer(backend_pid.clone(), PeerMetadata::default()));
        assert!(!sdk.register_backend_peer(backend_pid, PeerMetadata::default()));
    }

    #[test]
    fn register_backend_peer_with_existing_local_id_fails() {
        let mut sdk = make_sdk();
        let default_id = sdk.default_peer_id().to_string();
        // Try to register a backend peer with the same ID as the system peer.
        assert!(!sdk.register_backend_peer(default_id, PeerMetadata::default()));
    }

    // -- StoreAccess (L0) tests --

    #[test]
    fn store_access_put_and_get() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let store = ctx.store();
        let path = format!("/{}/test/store_access", pid);
        store.put(&path, make_entity("t", "hello")).unwrap();
        let entity = store.get(&path);
        assert!(entity.is_some());
    }

    #[test]
    fn store_access_list_has_remove() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let store = ctx.store();
        let path = format!("/{}/test/l0/item", pid);
        store.put(&path, make_entity("t", "x")).unwrap();
        assert!(store.has(&path));
        let entries = store.list(&format!("/{}/test/l0/", pid));
        assert_eq!(entries.len(), 1);
        assert!(store.remove(&path));
        assert!(!store.has(&path));
    }

    #[test]
    fn store_access_increments_generation() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let store = ctx.store();
        assert_eq!(ctx.store().generation(), 0);
        store.put(&format!("/{}/test/gen", pid), make_entity("t", "1")).unwrap();
        assert_eq!(ctx.store().generation(), 1);
    }

    #[test]
    fn store_access_get_by_hash_round_trips_put_hash() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let store = ctx.store();
        let entity = make_entity("app/state/test", "payload");
        let hash = store.put(&format!("/{}/test/by_hash", pid), entity.clone()).unwrap();
        let looked_up = store.get_by_hash(&hash).expect("entity resolvable by hash");
        assert_eq!(looked_up.entity_type, entity.entity_type);
        assert_eq!(looked_up.data, entity.data);
    }

    #[test]
    fn store_access_get_by_hash_missing_returns_none() {
        let ctx = make_peer_context();
        // A hash that doesn't correspond to any stored entity.
        let bogus = Hash::new(0, [0xab; 32]);
        assert!(ctx.store().get_by_hash(&bogus).is_none());
    }

    #[test]
    fn content_lookup_clone_resolves_after_original_dropped() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let hash = ctx
            .store()
            .put(&format!("/{}/test/cl", pid), make_entity("t", "x"))
            .unwrap();
        // Take a handle, drop the StoreAccess borrow, and confirm the
        // clone still resolves the entity — proves the handle is
        // callback-safe (no borrow of PeerContext retained).
        let lookup = ctx.store().content_lookup();
        drop(ctx.store());
        assert!(lookup.get_by_hash(&hash).is_some());
    }

    // -- Scope tests --

    #[test]
    fn scope_resolve_builds_absolute_path() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let scope = ctx.scope("app/browser/workspace");
        assert_eq!(scope.resolve("windows/1/state"), format!("/{}/app/browser/workspace/windows/1/state", pid));
    }

    #[test]
    fn scope_resolve_empty_returns_prefix() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let scope = ctx.scope("app/browser");
        assert_eq!(scope.resolve(""), format!("/{}/app/browser", pid));
    }

    #[test]
    fn scope_put_and_get() {
        let ctx = make_peer_context();
        let scope = ctx.scope("app/test");
        scope.put("settings", make_entity("app/state/setting", "dark")).unwrap();
        let entity = scope.get("settings");
        assert!(entity.is_some());
        assert_eq!(entity.unwrap().entity_type, "app/state/setting");
    }

    #[test]
    fn scope_list() {
        let ctx = make_peer_context();
        let scope = ctx.scope("app/test/items");
        scope.put("a", make_entity("t", "1")).unwrap();
        scope.put("b", make_entity("t", "2")).unwrap();
        let entries = scope.list("");
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn scope_has_and_remove() {
        let ctx = make_peer_context();
        let scope = ctx.scope("app/test");
        scope.put("temp", make_entity("t", "x")).unwrap();
        assert!(scope.has("temp"));
        assert!(scope.remove("temp"));
        assert!(!scope.has("temp"));
    }

    #[test]
    fn scope_sub_scope() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let ws = ctx.scope("app/browser/workspace");
        let win = ws.scope("windows/1");
        assert_eq!(win.resolve("state"), format!("/{}/app/browser/workspace/windows/1/state", pid));

        // Put via sub-scope, read via parent scope.
        win.put("state", make_entity("t", "hello")).unwrap();
        assert!(ws.has("windows/1/state"));
    }

    #[test]
    fn scope_increments_generation() {
        let ctx = make_peer_context();
        let scope = ctx.scope("app/test");
        assert_eq!(ctx.store().generation(), 0);
        scope.put("x", make_entity("t", "1")).unwrap();
        assert_eq!(ctx.store().generation(), 1);
        scope.remove("x");
        assert_eq!(ctx.store().generation(), 2);
    }

    // -- Error model tests --

    #[test]
    fn sdk_error_from_status_success_is_none() {
        assert!(SdkError::from_status(200, None, "ok").is_none());
        assert!(SdkError::from_status(202, None, "accepted").is_none());
        assert!(SdkError::from_status(303, None, "redirect").is_none());
    }

    #[test]
    fn sdk_error_from_status_client_errors() {
        let err = SdkError::from_status(400, None, "bad input").unwrap();
        assert!(err.is_client_error());
        assert!(!err.is_auth_error());
        assert_eq!(err.status_code(), 400);

        let err = SdkError::from_status(403, None, "denied").unwrap();
        assert!(err.is_auth_error());
        assert!(err.is_client_error());

        let err = SdkError::from_status(404, None, "missing").unwrap();
        assert!(err.is_client_error());
        assert_eq!(err.status_code(), 404);

        let err = SdkError::from_status(409, None, "conflict").unwrap();
        assert!(err.is_client_error());
    }

    #[test]
    fn sdk_error_from_status_system_errors() {
        let err = SdkError::from_status(500, None, "crash").unwrap();
        assert!(err.is_system_error());
        assert!(!err.is_client_error());

        let err = SdkError::from_status(501, None, "nope").unwrap();
        assert!(err.is_system_error());
    }

    #[test]
    fn sdk_error_tree_error_is_system() {
        let err = SdkError::TreeError("boom".into());
        assert!(err.is_system_error());
        assert_eq!(err.status_code(), status::INTERNAL);
    }

    // -- Ask (d) regression: substrate code + message propagation --
    //
    // The SDK boundary MUST preserve the substrate's `code` field from
    // `system/protocol/error` result entities, not stringify it away.
    // Without these tests an
    // opportunistic refactor of `from_handler_result` could silently
    // re-introduce the flattening that Dom's validation pass caught.

    fn sample_error_result(status: u32, code: &str, message: &str) -> entity_handler::HandlerResult {
        entity_handler::HandlerResult::error(
            status,
            entity_handler::error_entity(code, message),
        )
    }

    #[test]
    fn from_handler_result_preserves_substrate_code_on_forbidden() {
        let result = sample_error_result(
            403,
            "sensitive_path",
            "subscriptions to system/capability/, system/runtime/, or system/continuation/ require operator-class authority",
        );
        let err = SdkError::from_handler_result(&result, "subscribe: system/capability/grants/*")
            .expect("403 must map to Some(SdkError)");
        match err {
            SdkError::Forbidden { status, code, message } => {
                assert_eq!(status, 403);
                assert_eq!(
                    code.as_deref(),
                    Some("sensitive_path"),
                    "Ruling 1 reason code MUST reach the consumer — see B2 in inspectability cycle"
                );
                assert!(
                    message.contains("operator-class"),
                    "substrate message MUST reach the consumer, not synthetic fallback context; got: {message}"
                );
            }
            other => panic!("expected Forbidden, got {other:?}"),
        }
    }

    #[test]
    fn from_handler_result_preserves_substrate_code_on_not_found() {
        let result = sample_error_result(
            404,
            "handler_not_found",
            "no handler for path: definitely/no/handler/here",
        );
        let err = SdkError::from_handler_result(&result, "execute: definitely/no/handler/here")
            .expect("404 must map to Some(SdkError)");
        match err {
            SdkError::NotFound { status, code, message } => {
                assert_eq!(status, 404);
                assert_eq!(code.as_deref(), Some("handler_not_found"), "R2 must surface handler_not_found code");
                assert!(message.contains("definitely/no/handler/here"));
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn from_handler_result_falls_back_to_context_when_body_is_not_error_entity() {
        // Result entity is not `system/protocol/error` — caller's
        // fallback message MUST be used, and `code` MUST be None
        // (no claim about a code we did not decode).
        let entity = Entity::new(
            "primitive/null",
            entity_ecf::to_ecf(&entity_ecf::Value::Null),
        )
        .unwrap();
        let result = entity_handler::HandlerResult::error(500, entity);
        let err = SdkError::from_handler_result(&result, "internal: catastrophic decode failure")
            .expect("500 must map to Some(SdkError)");
        match err {
            SdkError::Internal { status, code, message } => {
                assert_eq!(status, 500);
                assert!(code.is_none(), "code MUST be None when result isn't system/protocol/error");
                assert_eq!(message, "internal: catastrophic decode failure");
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn from_handler_result_returns_none_for_success_status() {
        let entity = Entity::new(
            "primitive/null",
            entity_ecf::to_ecf(&entity_ecf::Value::Null),
        )
        .unwrap();
        let result = entity_handler::HandlerResult::ok(entity);
        assert!(SdkError::from_handler_result(&result, "should not be called").is_none());
    }

    #[test]
    fn grant_scope_default_is_empty() {
        let scope = GrantScope::default();
        assert!(scope.handlers.include.is_empty());
        assert!(scope.operations.include.is_empty());
        assert!(scope.resources.include.is_empty());
        assert!(scope.peers.include.is_empty());
    }

    #[test]
    fn grant_scope_wildcard() {
        let scope = GrantScope::wildcard();
        assert_eq!(scope.handlers.include, vec!["*"]);
        assert_eq!(scope.operations.include, vec!["*"]);
        assert_eq!(scope.resources.include, vec!["*"]);
        assert_eq!(scope.peers.include, vec!["*"]);
    }

    // -- D1: owner_capability_hash accessor (Godot ask) --

    #[test]
    fn owner_capability_hash_is_stable_per_peer() {
        // Same peer → same hash across reads (cached at build time).
        let ctx = make_peer_context();
        let h1 = ctx.owner_capability_hash();
        let h2 = ctx.owner_capability_hash();
        assert_eq!(h1, h2, "owner_capability_hash must be stable for one peer");
    }

    #[test]
    fn owner_capability_hash_matches_persisted_entity() {
        // The accessor must return the content hash of the cap entity
        // that mint_owner_self_cap put into the content store. This
        // pins the post-condition: consumers can use the hash to fetch
        // the cap entity back from the store (which is what continuation
        // installers do via dispatch_capability).
        let ctx = make_peer_context();
        let hash = ctx.owner_capability_hash();
        let fetched = ctx
            .shared
            .content_store
            .get(&hash)
            .expect("owner capability entity must be persisted at build time");
        assert_eq!(
            fetched.content_hash, hash,
            "round-trip: store-fetched entity hash must match accessor"
        );
    }

    #[test]
    fn owner_capability_hash_differs_across_peers() {
        // Different peers (different identities) mint distinct caps —
        // hashes must differ. Prevents accidental aliasing in the
        // accessor.
        let a = make_peer_context();
        let b = make_peer_context();
        assert_ne!(
            a.owner_capability_hash(),
            b.owner_capability_hash(),
            "two peers with distinct identities must have distinct cap hashes"
        );
    }

    // -- D2: with_grant_resolver builder hook (Godot ask) --

    #[test]
    fn with_grant_resolver_installs_on_shared() {
        // Builder hook must result in `PeerShared.grant_resolver` being
        // Some — that's the seam the connect handler reads at
        // AUTHENTICATE time (`core/peer/src/connection.rs:267`).
        // Without the install, compositions without the role extension
        // can't override the static fallback grants.
        use std::sync::atomic::{AtomicUsize, Ordering};
        let call_count = Arc::new(AtomicUsize::new(0));
        let count_clone = call_count.clone();

        let ctx = PeerContextBuilder::new()
            .generate_keypair()
            .with_grant_resolver(move |_pid, _hash| {
                count_clone.fetch_add(1, Ordering::SeqCst);
                // Return None — fall through to static fallback.
                None
            })
            .build()
            .expect("build with resolver should succeed");

        assert!(
            ctx.shared.grant_resolver.is_some(),
            "resolver should be installed on PeerShared after build"
        );

        // Invoke the resolver directly to prove it round-trips.
        let resolver = ctx.shared.grant_resolver.as_ref().unwrap();
        let dummy_pid = ctx.shared.peer_id.clone();
        let dummy_hash = ctx.shared.identity_hash;
        let result = resolver(&dummy_pid, &dummy_hash);
        assert!(result.is_none(), "resolver returned None as configured");
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "resolver closure must have run exactly once"
        );
    }

    #[test]
    fn no_grant_resolver_default_surfaces_no_custom_grants() {
        // Default path (no `.with_grant_resolver`): the connect handler must
        // fall through to its static fallback — no *custom* grants surface.
        //
        // Two feature-dependent shapes satisfy that invariant:
        //   - Without role+attestation: `grant_resolver` stays None.
        //   - With both (EXTENSION-ROLE §4.7 auto-wire): it is Some, but the
        //     policy resolver defaults to anonymous-deny — it returns None
        //     when no initial-grant-policy entity is bound, which is the case
        //     for a freshly built peer.
        // Assert the behavior (deny / absent), not the presence, so the test
        // holds under every feature combination including `--all-features`.
        let ctx = make_peer_context();
        if let Some(resolver) = ctx.shared.grant_resolver.as_ref() {
            let pid = ctx.shared.peer_id.clone();
            let hash = ctx.shared.identity_hash;
            assert!(
                resolver(&pid, &hash).is_none(),
                "auto-wired §4.7 policy resolver must deny when no policy entity is bound"
            );
        }
    }

    #[test]
    fn grant_resolver_can_return_custom_grants() {
        // The closure can construct a Vec<GrantEntry> and have it
        // surface to the connect handler. Round-trip the constructed
        // grants through the resolver to prove the type and the data
        // flow.
        use entity_capability::{GrantEntry, IdScope, PathScope};
        let ctx = PeerContextBuilder::new()
            .generate_keypair()
            .with_grant_resolver(|_pid, _hash| {
                Some(vec![GrantEntry {
                    handlers: PathScope::new(vec!["custom/handler".into()]),
                    resources: PathScope::new(vec!["/p".into()]),
                    operations: IdScope::new(vec!["op".into()]),
                    peers: None,
                    constraints: None,
                    allowances: None,
                }])
            })
            .build()
            .expect("build with resolver should succeed");

        let resolver = ctx.shared.grant_resolver.as_ref().unwrap();
        let dummy_pid = ctx.shared.peer_id.clone();
        let dummy_hash = ctx.shared.identity_hash;
        let grants = resolver(&dummy_pid, &dummy_hash).expect("resolver returned Some");
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].handlers.include, vec!["custom/handler"]);
    }

    // -- Watch pattern matching tests --

    #[test]
    fn watch_pattern_exact_match() {
        assert!(watch_pattern_matches("a/b/c", "a/b/c"));
        assert!(!watch_pattern_matches("a/b/c", "a/b/c/d"));
        assert!(!watch_pattern_matches("a/b/c", "a/b"));
    }

    #[test]
    fn watch_pattern_prefix_wildcard() {
        assert!(watch_pattern_matches("a/b/*", "a/b/c"));
        assert!(watch_pattern_matches("a/b/*", "a/b/c/d"));
        assert!(watch_pattern_matches("a/b/*", "a/b/"));
        assert!(!watch_pattern_matches("a/b/*", "a/x/c"));
    }

    // Watch stream tests require a tokio runtime.
    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn watch_delivers_matching_events() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let mut stream = ctx.store().watch(format!("/{}/app/test/*", pid));

        // Write a matching path.
        ctx.store().put(
            &format!("/{}/app/test/item", pid),
            make_entity("t", "hello"),
        ).unwrap();

        // Should receive the event.
        let event = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            stream.recv(),
        ).await;
        assert!(event.is_ok(), "should receive event within timeout");
        let event = event.unwrap().unwrap();
        assert!(event.path.contains("app/test/item"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn watch_filters_non_matching_events() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let mut stream = ctx.store().watch(format!("/{}/app/test/*", pid));

        // Write to a non-matching path.
        ctx.store().put(
            &format!("/{}/other/path", pid),
            make_entity("t", "hello"),
        ).unwrap();

        // Write to a matching path.
        ctx.store().put(
            &format!("/{}/app/test/item", pid),
            make_entity("t", "world"),
        ).unwrap();

        // First received event should be the matching one.
        let event = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            stream.recv(),
        ).await.unwrap().unwrap();
        assert!(event.path.contains("app/test/item"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn watch_cancel_on_drop() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        {
            let _stream = ctx.store().watch(format!("/{}/app/test/*", pid));
            // Stream dropped here — task should cancel.
        }
        // Ensure no panic and cleanup happened.
        ctx.store().put(
            &format!("/{}/app/test/after_drop", pid),
            make_entity("t", "ok"),
        ).unwrap();
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn watch_try_recv() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let mut stream = ctx.store().watch(format!("/{}/app/test/*", pid));

        // Nothing written yet — try_recv should return None.
        assert!(stream.try_recv().is_none());

        // Write and give the background task a moment to process.
        ctx.store().put(
            &format!("/{}/app/test/item", pid),
            make_entity("t", "x"),
        ).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let event = stream.try_recv();
        assert!(event.is_some());
    }

    // -- put_cas tests --

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn put_cas_insert_only_succeeds_when_missing() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let path = format!("/{}/app/test/cas_new", pid);
        let hash = ctx.put_cas(&path, make_entity("test/t", "first"), None).await;
        assert!(hash.is_ok(), "put_cas with None should succeed when path empty");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn put_cas_insert_only_conflicts_when_present() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let path = format!("/{}/app/test/cas_exists", pid);
        ctx.put(&path, make_entity("test/t", "first")).await.unwrap();
        let err = ctx.put_cas(&path, make_entity("test/t", "second"), None).await;
        assert!(
            matches!(err, Err(SdkError::Conflict { .. })),
            "put_cas with None should conflict when path has a binding"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn put_cas_with_matching_hash_succeeds() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let path = format!("/{}/app/test/cas_match", pid);
        let first_hash = ctx.put(&path, make_entity("test/t", "v1")).await.unwrap();
        let result = ctx.put_cas(&path, make_entity("test/t", "v2"), Some(first_hash)).await;
        assert!(result.is_ok(), "put_cas with matching expected hash should succeed");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn put_cas_with_wrong_hash_conflicts() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let path = format!("/{}/app/test/cas_mismatch", pid);
        ctx.put(&path, make_entity("test/t", "v1")).await.unwrap();
        let bogus = Hash::compute("test/t", b"bogus");
        let err = ctx.put_cas(&path, make_entity("test/t", "v2"), Some(bogus)).await;
        assert!(
            matches!(err, Err(SdkError::Conflict { .. })),
            "put_cas with wrong expected hash should conflict"
        );
    }

    /// `mint_chain_capability` rejects an empty grants list rather
    /// than silently producing an unusable cap. Matches Go's 400
    /// invalid_grants.
    #[test]
    fn mint_chain_capability_empty_grants_rejects() {
        let ctx = make_peer_context();
        let r = ctx.mint_chain_capability(vec![]);
        assert!(
            matches!(r, Err(SdkError::HandlerError(_))),
            "empty grants must produce an error, got {:?}",
            r.as_ref().map(|e| &e.entity_type)
        );
    }

    /// Mints a scoped self-cap, persists it + signature, returns the
    /// cap entity. Probes: cap entity is content-addressed, granter
    /// == grantee == local identity_hash, signature lookup at the
    /// signed-content-hash succeeds.
    #[test]
    fn mint_chain_capability_self_cap_round_trips() {
        let ctx = make_peer_context();
        let me = ctx.identity_hash();
        // Narrow scope: tree:get on app/* only.
        let grants = vec![entity_capability::GrantEntry {
            handlers: entity_capability::PathScope::new(vec!["system/tree".into()]),
            resources: entity_capability::PathScope::new(vec!["app/*".into()]),
            operations: entity_capability::IdScope::new(vec!["get".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        }];
        let cap_entity = ctx
            .mint_chain_capability(grants)
            .expect("mint should succeed with non-empty grants");

        // Cap entity is in the content store at its content_hash.
        let fetched = ctx
            .store()
            .get_by_hash(&cap_entity.content_hash)
            .expect("cap entity should be persisted");
        assert_eq!(fetched.entity_type, "system/capability/token");

        // Decode the token and verify shape.
        let token = entity_capability::CapabilityToken::from_entity(&cap_entity)
            .expect("cap entity should decode as CapabilityToken");
        match token.granter {
            entity_capability::Granter::Single(h) => assert_eq!(h, me),
            _ => panic!("chain cap should be single-sig"),
        }
        assert_eq!(token.grantee, me, "self-cap: grantee == granter");
        assert_eq!(token.grants.len(), 1, "exactly the grant the caller supplied");
        assert!(token.parent.is_none(), "self-cap has no parent");
    }

    /// Bound variant additionally binds the cap entity at the given
    /// tree path, making it discoverable via location_index for
    /// V7 §5.1 is_revoked walks.
    #[tokio::test(flavor = "current_thread")]
    async fn mint_chain_capability_bound_writes_at_tree_path() {
        let ctx = make_peer_context();
        let pid = ctx.peer_id().to_string();
        let tree_path = format!("/{}/system/capability/grants/chain/test-chain-1", pid);
        let grants = vec![entity_capability::GrantEntry {
            handlers: entity_capability::PathScope::new(vec!["system/tree".into()]),
            resources: entity_capability::PathScope::new(vec!["app/*".into()]),
            operations: entity_capability::IdScope::new(vec!["get".into()]),
            peers: None,
            constraints: None,
            allowances: None,
        }];
        let cap_entity = ctx
            .mint_chain_capability_bound(grants, tree_path.clone())
            .expect("bound mint should succeed");

        // Tree path now binds to the cap entity's hash.
        let bound = ctx
            .store()
            .get(&tree_path)
            .expect("tree path should resolve");
        assert_eq!(bound.content_hash, cap_entity.content_hash);
    }

    /// Empty tree path on the bound variant produces an error rather
    /// than binding at the empty string.
    #[test]
    fn mint_chain_capability_bound_empty_path_rejects() {
        let ctx = make_peer_context();
        let grants = vec![entity_capability::GrantEntry {
            handlers: entity_capability::PathScope::all(),
            resources: entity_capability::PathScope::all(),
            operations: entity_capability::IdScope::all(),
            peers: None,
            constraints: None,
            allowances: None,
        }];
        let r = ctx.mint_chain_capability_bound(grants, "");
        assert!(matches!(r, Err(SdkError::HandlerError(_))));
    }
}
