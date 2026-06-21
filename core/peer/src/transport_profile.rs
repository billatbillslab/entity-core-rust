//! Transport-profile entity vocabulary + types (EXTENSION-NETWORK §6.5,
//! v1.4 Amendment 2).
//!
//! Closed-enum constants for the `supported_ops` field on
//! `system/peer/transport/<profile>` entities (D-13), plus the §6.5.2a
//! `tcp` profile entity type with ECF encode/decode (Chunk C).
//!
//! **Tree placement.** Per §6.5 ¶721-723, profile entities live at
//! `system/peer/transport/{peer_id}/{profile-id}` where `{profile-id}`
//! is a per-peer-unique identifier (e.g. `primary`, `cdn-mirror`,
//! `backup-relay`). A peer MAY have multiple profiles of the same type
//! (e.g. two HTTP mirror URLs for redundancy).
//!
//! **Entity type.** The entity's `type` field is the profile transport-
//! type — `system/peer/transport/tcp`, `system/peer/transport/http-poll`,
//! etc. — NOT the tree path.
//!
//! **Semantic reminder.** `supported_ops` is descriptive — what the
//! wire/server can *physically* carry. It is **NOT** an authorization
//! grant. Capability checks happen via the standard 4-axis grant model
//! (V7 §5.2 `check_permission`), never by reading `supported_ops`.

// ===========================================================================
// supported_ops closed enum (D-13)
// ===========================================================================

/// Full EXECUTE request/response — duplex socket or HTTP POST. Live
/// transports advertise `[EXECUTE]`. Carries server-push on duplex
/// transports (TCP, WebSocket); HTTP is half-duplex POST-only.
pub const OP_EXECUTE: &str = "EXECUTE";

/// Passive tree-binding lookup → bound hash. Verification anchor =
/// hash-chain-from-signed-root. Static publishers MAY advertise this.
pub const OP_TREE_GET: &str = "TREE_GET";

/// Passive content-addressed byte lookup. Verification anchor = the
/// content hash itself. Content-only mirrors advertise `[CONTENT_GET]`.
pub const OP_CONTENT_GET: &str = "CONTENT_GET";

/// Passive signed-root / pointer lookup. Verification anchor =
/// signature on `system/peer/published-root` (target entity defined in
/// PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE — next layer). Manifest-only
/// registries advertise `[MANIFEST_GET]`.
pub const OP_MANIFEST_GET: &str = "MANIFEST_GET";

/// Reserved-for-future — currently push-capability is implicit in
/// transport duplexity (TCP/WebSocket carry push; HTTP does not).
/// Promote to a real `supported_ops` value only when a future transport
/// needs field-level push discrimination. Reserved here so impls
/// surface a clear "not yet" if it appears on wire.
pub const OP_SUBSCRIBE_RESERVED: &str = "SUBSCRIBE";

/// All non-reserved values, in spec-declared order. Useful for
/// validation passes that reject unknown strings.
pub const SUPPORTED_OPS_VALID: &[&str] = &[
    OP_EXECUTE,
    OP_TREE_GET,
    OP_CONTENT_GET,
    OP_MANIFEST_GET,
];

/// Returns `true` if `op` is a currently-valid `supported_ops` value
/// (i.e., one of the four non-reserved strings). `SUBSCRIBE` returns
/// `false` — reserved values are not valid as a published op.
pub fn is_valid_supported_op(op: &str) -> bool {
    SUPPORTED_OPS_VALID.iter().any(|v| *v == op)
}

// ===========================================================================
// Transport-type names (§6.5 entity-type suffix)
// ===========================================================================

/// `system/peer/transport/tcp` — the actual default live transport (all
/// three impls run TCP by default). Endpoint shape: `{url: "tcp://host:port"}`.
/// Built in Chunk C; the constant is here so vocabulary lands together.
pub const TRANSPORT_TCP: &str = "tcp";

/// `system/peer/transport/websocket` — duplex browser-capable transport
/// (Rust has native+WASM; Go/Py do not). Endpoint shape:
/// `{url: "wss://.../ws"}`.
pub const TRANSPORT_WEBSOCKET: &str = "websocket";

/// `system/peer/transport/http` — live EXECUTE over HTTP POST. The
/// **wrapper**, NOT BRIDGE-HTTP. Half-duplex, no server-push v1. Built
/// in Chunk D. Endpoint shape: `{url: "https://.../entity"}`.
pub const TRANSPORT_HTTP: &str = "http";

/// `system/peer/transport/http-poll` — passive lookup-only static HTTP
/// origin (Mechanism A). Endpoint carries the two-prefix URL space
/// (`tree_url_prefix` + `content_url_prefix` + `content_layout` +
/// `tree_leaf_suffix`).
pub const TRANSPORT_HTTP_POLL: &str = "http-poll";

/// `system/peer/transport/quic` — aspirational; zero impls today.
/// Profile shape retained in spec for when an impl ships it.
pub const TRANSPORT_QUIC: &str = "quic";

/// `freshness: "live"` — peer/server is online; lookups are point-in-time
/// against a running peer.
pub const FRESHNESS_LIVE: &str = "live";

/// `freshness: "static-immutable+signed-pointer"` — published representation
/// behind a signed mutable pointer (the published-root anchor).
pub const FRESHNESS_STATIC_SIGNED_POINTER: &str = "static-immutable+signed-pointer";

/// `freshness: "async"` — store-and-forward; not used in v1.
pub const FRESHNESS_ASYNC: &str = "async";

// ===========================================================================
// TCP profile entity (§6.5.2a)
// ===========================================================================

/// Entity-type string for the `system/peer/transport/tcp` profile (§6.5.2a).
/// Builds on the existing `"tcp"` transport-value + framing (V7 §3.13/§1.6);
/// this is the discoverable profile entity. All three reference impls
/// default to TCP, so this is the load-bearing live transport.
pub const TYPE_PEER_TRANSPORT_TCP: &str = "system/peer/transport/tcp";

/// `cap_flow: "both"` — transport carries caps in both request + response
/// directions (default for live transports).
pub const CAP_FLOW_BOTH: &str = "both";

/// `cap_flow: "request"` — caps flow only in the connector → listener
/// direction (e.g., a half-duplex client to a push-less server).
pub const CAP_FLOW_REQUEST: &str = "request";

/// Decoded `system/peer/transport/tcp` profile entity (§6.5.2a fields).
///
/// All fields are required per §6.5 ¶727 (the MUST list).
/// `poll_interval_ms` + `signed_pointer` are required only on `async` /
/// `static-immutable+signed-pointer` freshness — not applicable to `tcp`
/// (which is always `freshness: "live"`), so they're not on this struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpProfileData {
    /// Owner peer's identity (the peer this profile advertises). Pin
    /// canonical Base58 string form — same shape as elsewhere in the
    /// codebase (matches what's on the tree path).
    pub peer_id: String,
    /// `transport_type: "tcp"` — kept as a field for downstream code
    /// that hands the profile-data around without the wrapping entity.
    pub transport_type: String,
    /// Endpoint URL — for `tcp` this is `"tcp://host:port"` per D-14.
    pub endpoint_url: String,
    /// `supported_ops` — `["EXECUTE"]` for `tcp` (full duplex; carries
    /// server-push). Carried verbatim so future profiles with subsets
    /// can reuse the struct shape.
    pub supported_ops: Vec<String>,
    /// `freshness` — `"live"` for `tcp`.
    pub freshness: String,
    /// `nonce_required` — true for live transports (replay protection).
    pub nonce_required: bool,
    /// `cap_flow` — `"both"` for tcp.
    pub cap_flow: String,
    /// `advertised_at` — OPTIONAL wall-clock epoch ms when this profile
    /// was published. **Informational only — judged against the
    /// consumer's own local clock for advisory staleness.** Per D3
    /// (transport-family Chunk C amendments §1.3):
    /// this is **NOT a selection key** (skew-prone wall-clock would
    /// make selection non-deterministic across impls), there is no
    /// logical clock in v1, and it must NEVER feed a correctness
    /// decision. The selection rule lives in D1.
    ///
    /// **Q6 (ratified,
    /// transport-family live-reachability §8.2 / §8.9).**
    /// Optional, not required — resolves the §6.5.1 vs §6.5.1a D-3
    /// spec contradiction (MUST-list vs advisory). `None` on decode
    /// when the field is absent or the wrong CBOR major type. Emitted
    /// `omitempty` (absent from the CBOR map entirely when `None`).
    pub advertised_at: Option<u64>,
    /// `priority` — OPTIONAL DNS-SRV-style selection priority (Q1,
    /// ratified, PROPOSAL §8.1 / §8.9). **Lower = more
    /// preferred.** Selection sorts by `(priority asc, profile-id
    /// lex)`. Effective priority when this field is `None`:
    /// - profile-id `"primary"` ⇒ `0` (preserves the existing
    ///   primary-first convention byte-for-byte).
    /// - any other profile-id ⇒ `100` (the spec default).
    /// Explicit `priority` is always authoritative — set it, name
    /// the profile-id freely. Emitted `omitempty`.
    pub priority: Option<u32>,
}

/// Errors decoding a `system/peer/transport/tcp` profile entity.
#[derive(Debug, thiserror::Error)]
pub enum TcpProfileDecodeError {
    /// Entity type didn't match `system/peer/transport/tcp`.
    #[error("expected entity_type {TYPE_PEER_TRANSPORT_TCP}, got {0}")]
    UnexpectedType(String),
    /// CBOR decode failed.
    #[error("cbor decode: {0}")]
    Cbor(String),
    /// Data root wasn't a CBOR map.
    #[error("profile data is not a CBOR map")]
    NotAMap,
    /// A required field was missing.
    #[error("profile missing required field: {0}")]
    MissingField(&'static str),
    /// A required field had the wrong CBOR shape.
    #[error("profile field {field} has wrong shape: {detail}")]
    BadFieldShape {
        /// The field name.
        field: &'static str,
        /// Diagnostic detail.
        detail: String,
    },
    /// `data.transport_type` does not match the entity-type suffix (D5).
    #[error("transport_type field mismatch: expected '{expected}', got '{got}'")]
    TransportTypeMismatch {
        /// Expected transport-type string (the entity-type suffix).
        expected: &'static str,
        /// Actual value carried in `data.transport_type`.
        got: String,
    },
}

impl TcpProfileData {
    /// Convenience constructor for the canonical local-listener case.
    ///
    /// `now_epoch_ms()` is passed in so callers control time-source
    /// (per CLAUDE.md no-Date::now in hot paths; supports replay-safe
    /// fixed timestamps in tests).
    pub fn for_local_listener(
        peer_id: impl Into<String>,
        endpoint_url: impl Into<String>,
        advertised_at: u64,
    ) -> Self {
        Self {
            peer_id: peer_id.into(),
            transport_type: TRANSPORT_TCP.into(),
            endpoint_url: endpoint_url.into(),
            supported_ops: vec![OP_EXECUTE.into()],
            freshness: FRESHNESS_LIVE.into(),
            nonce_required: true,
            cap_flow: CAP_FLOW_BOTH.into(),
            // Q6 ratified optional; existing callers passing a `u64`
            // get it round-tripped through `Some(...)`. Passing `0`
            // (the common "I don't have a clock" sentinel pre-Q6) is
            // still valid but encodes as `Some(0)` not as omitted —
            // use the explicit `None` constructor below for that.
            advertised_at: Some(advertised_at),
            priority: None,
        }
    }

    /// Constructor for the canonical local-listener case with no
    /// `advertised_at` (Q6: field is OPTIONAL per arch §8.2 / §8.9).
    /// Use when the publisher has no usable wall-clock (browser peer,
    /// embedded environment) or when explicitly omitting the field is
    /// preferred over publishing a zero timestamp.
    pub fn for_local_listener_no_clock(
        peer_id: impl Into<String>,
        endpoint_url: impl Into<String>,
    ) -> Self {
        Self {
            peer_id: peer_id.into(),
            transport_type: TRANSPORT_TCP.into(),
            endpoint_url: endpoint_url.into(),
            supported_ops: vec![OP_EXECUTE.into()],
            freshness: FRESHNESS_LIVE.into(),
            nonce_required: true,
            cap_flow: CAP_FLOW_BOTH.into(),
            advertised_at: None,
            priority: None,
        }
    }

    /// Encode to a `system/peer/transport/tcp` `Entity` per the §6.5.2a
    /// shape. Used by the local listener publishing its own profile,
    /// and by interop tests / sync code that mirrors a discovered
    /// peer's profile into the local tree.
    pub fn to_entity(&self) -> entity_entity::Entity {
        let supported_ops_arr = entity_ecf::Value::Array(
            self.supported_ops
                .iter()
                .map(|s| entity_ecf::text(s))
                .collect(),
        );
        let endpoint_map = entity_ecf::Value::Map(vec![(
            entity_ecf::text("url"),
            entity_ecf::text(&self.endpoint_url),
        )]);
        let mut fields = vec![
            (entity_ecf::text("peer_id"), entity_ecf::text(&self.peer_id)),
            (
                entity_ecf::text("transport_type"),
                entity_ecf::text(&self.transport_type),
            ),
            (entity_ecf::text("endpoint"), endpoint_map),
            (entity_ecf::text("supported_ops"), supported_ops_arr),
            (
                entity_ecf::text("freshness"),
                entity_ecf::text(&self.freshness),
            ),
            (
                entity_ecf::text("nonce_required"),
                entity_ecf::Value::Bool(self.nonce_required),
            ),
            (
                entity_ecf::text("cap_flow"),
                entity_ecf::text(&self.cap_flow),
            ),
        ];
        // Q6 omitempty — only emit advertised_at when present.
        if let Some(ts) = self.advertised_at {
            fields.push((
                entity_ecf::text("advertised_at"),
                entity_ecf::Value::Integer(ts.into()),
            ));
        }
        // Q1 omitempty — only emit priority when explicitly set.
        // Absent priority is interpreted per the resolver's
        // `effective_priority` rule (primary → 0, others → 100).
        if let Some(p) = self.priority {
            fields.push((
                entity_ecf::text("priority"),
                entity_ecf::Value::Integer(p.into()),
            ));
        }
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
        entity_entity::Entity::new(TYPE_PEER_TRANSPORT_TCP, data)
            .expect("entity construction for system/peer/transport/tcp")
    }

    /// Decode a `system/peer/transport/tcp` `Entity`.
    ///
    /// **D5 — `transport_type` MUST match entity-type suffix.** Per
    /// the transport-family Chunk C amendments §2.1
    /// (D5), a profile entity whose `data.transport_type` does not equal
    /// the entity-type suffix (`tcp` here) is invalid and MUST be
    /// rejected fail-closed. Returns
    /// [`TcpProfileDecodeError::TransportTypeMismatch`] for that case.
    pub fn from_entity(
        entity: &entity_entity::Entity,
    ) -> Result<Self, TcpProfileDecodeError> {
        if entity.entity_type != TYPE_PEER_TRANSPORT_TCP {
            return Err(TcpProfileDecodeError::UnexpectedType(
                entity.entity_type.clone(),
            ));
        }
        let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice())
            .map_err(|e| TcpProfileDecodeError::Cbor(e.to_string()))?;
        let map = match value {
            ciborium::Value::Map(m) => m,
            _ => return Err(TcpProfileDecodeError::NotAMap),
        };
        let peer_id = field_text(&map, "peer_id")
            .ok_or(TcpProfileDecodeError::MissingField("peer_id"))?;
        let transport_type = field_text(&map, "transport_type")
            .ok_or(TcpProfileDecodeError::MissingField("transport_type"))?;
        // D5 — MUST match entity-type suffix; fail closed.
        if transport_type != TRANSPORT_TCP {
            return Err(TcpProfileDecodeError::TransportTypeMismatch {
                expected: TRANSPORT_TCP,
                got: transport_type,
            });
        }
        let endpoint_url = match field_lookup(&map, "endpoint") {
            Some(ciborium::Value::Map(m)) => field_text(m, "url").ok_or(
                TcpProfileDecodeError::BadFieldShape {
                    field: "endpoint.url",
                    detail: "missing or non-text url field".into(),
                },
            )?,
            Some(_) => {
                return Err(TcpProfileDecodeError::BadFieldShape {
                    field: "endpoint",
                    detail: "expected CBOR map".into(),
                })
            }
            None => return Err(TcpProfileDecodeError::MissingField("endpoint")),
        };
        let supported_ops = match field_lookup(&map, "supported_ops") {
            Some(ciborium::Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| match v {
                    ciborium::Value::Text(s) => Some(s.clone()),
                    _ => None,
                })
                .collect(),
            Some(_) => {
                return Err(TcpProfileDecodeError::BadFieldShape {
                    field: "supported_ops",
                    detail: "expected CBOR array".into(),
                })
            }
            None => return Err(TcpProfileDecodeError::MissingField("supported_ops")),
        };
        let freshness = field_text(&map, "freshness")
            .ok_or(TcpProfileDecodeError::MissingField("freshness"))?;
        let nonce_required = match field_lookup(&map, "nonce_required") {
            Some(ciborium::Value::Bool(b)) => *b,
            Some(_) => {
                return Err(TcpProfileDecodeError::BadFieldShape {
                    field: "nonce_required",
                    detail: "expected CBOR bool".into(),
                })
            }
            None => return Err(TcpProfileDecodeError::MissingField("nonce_required")),
        };
        let cap_flow = field_text(&map, "cap_flow")
            .ok_or(TcpProfileDecodeError::MissingField("cap_flow"))?;
        // Q6 (ratified §8.9): `advertised_at` is OPTIONAL. Absent ⇒
        // None. Present-but-wrong-type ⇒ also None — the field is
        // advisory (D-3) so a malformed advisory is harmless, and
        // tolerating it absorbs the exact cross-impl string-vs-uint
        // class bug arch Gap A flags (the Go pre-fix emitted `string`;
        // Rust pre-Q6 would hard-reject the whole profile entity).
        // The ECF type-vector sweep is what catches THAT in advance;
        // Rust's posture here is to not weaponize a malformed
        // advisory field against a structurally-valid profile.
        let advertised_at = match field_lookup(&map, "advertised_at") {
            Some(ciborium::Value::Integer(i)) => u64::try_from(*i).ok(),
            _ => None,
        };
        // Q1 — OPTIONAL `priority` (uint). Absent or wrong-type ⇒ None;
        // the resolver applies `effective_priority` (primary unset → 0,
        // others unset → 100) so absence here is meaningful, not an
        // error. Same Gap-A class tolerance as advertised_at.
        let priority = match field_lookup(&map, "priority") {
            Some(ciborium::Value::Integer(i)) => u32::try_from(*i).ok(),
            _ => None,
        };
        Ok(TcpProfileData {
            peer_id,
            transport_type,
            endpoint_url,
            supported_ops,
            freshness,
            nonce_required,
            cap_flow,
            advertised_at,
            priority,
        })
    }
}

// ===========================================================================
// HTTP live profile entity (§6.5.2c — Chunk D)
// ===========================================================================

/// Entity-type string for the `system/peer/transport/http` profile
/// (§6.5.2c). Live EXECUTE/EXECUTE-RESPONSE over HTTP POST. **Wrapper,
/// NOT BRIDGE-HTTP** — the bytes on the wire ARE entity envelopes
/// (Mechanism A); BRIDGE-HTTP (Mechanism B) is a structurally-distinct
/// surface for foreign content. POST-only, half-duplex, no server-push
/// in v1. The browser linchpin (a browser can POST but has no raw socket).
pub const TYPE_PEER_TRANSPORT_HTTP: &str = "system/peer/transport/http";

/// Decoded `system/peer/transport/http` profile entity (§6.5.2c).
///
/// Same shape family as [`TcpProfileData`] — D4 pins all live transports
/// to the shared `endpoint: { url: "<scheme>://..." }` shape. The single
/// `url` field is scheme-prefixed (`https://host/path`); per-profile
/// variant shapes are banned.
///
/// `supported_ops` is `["EXECUTE"]` (request/response only; no
/// server-push in v1 — would require a duplex transport).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpProfileData {
    /// Owner peer's identity (the peer this profile advertises).
    pub peer_id: String,
    /// `transport_type: "http"`.
    pub transport_type: String,
    /// Endpoint URL — `"https://host/path"` per D-14. The path is
    /// operator choice (advertised via this URL) and may be anything
    /// from `/` to `/v1/entity` — consumers POST EXECUTE envelopes to
    /// this URL as-is. (G1 — operator choice, advertised in profile.)
    pub endpoint_url: String,
    /// `supported_ops` — `["EXECUTE"]` for `http` (half-duplex; no
    /// server-push v1). Carried verbatim so subsets are expressible.
    pub supported_ops: Vec<String>,
    /// `freshness` — `"live"` for `http`.
    pub freshness: String,
    /// `nonce_required` — true (replay protection; same as tcp/ws).
    pub nonce_required: bool,
    /// `cap_flow` — `"both"`.
    pub cap_flow: String,
    /// `advertised_at` — OPTIONAL (Q6 ratified §8.9); informational
    /// only (D3); NEVER a selection key. See `TcpProfileData::advertised_at`
    /// for the full disposition; HTTP follows the same rule.
    pub advertised_at: Option<u64>,
    /// `priority` — OPTIONAL DNS-SRV-style selection priority (Q1
    /// ratified §8.9). Lower = more preferred; see
    /// [`TcpProfileData::priority`] for the full disposition. HTTP
    /// profiles in particular benefit from this — pre-Q1, the G1
    /// `primary-http` profile-id was a naming compensation for the
    /// absent selection mechanism; with `priority` set explicitly,
    /// the profile-id can be anything.
    pub priority: Option<u32>,
}

impl HttpProfileData {
    /// Convenience constructor for the canonical local-listener case.
    /// Wraps a `u64` timestamp into `Some(_)` for back-compat; use
    /// [`Self::for_local_listener_no_clock`] for explicitly omitted.
    pub fn for_local_listener(
        peer_id: impl Into<String>,
        endpoint_url: impl Into<String>,
        advertised_at: u64,
    ) -> Self {
        Self {
            peer_id: peer_id.into(),
            transport_type: TRANSPORT_HTTP.into(),
            endpoint_url: endpoint_url.into(),
            supported_ops: vec![OP_EXECUTE.into()],
            freshness: FRESHNESS_LIVE.into(),
            nonce_required: true,
            cap_flow: CAP_FLOW_BOTH.into(),
            advertised_at: Some(advertised_at),
            priority: None,
        }
    }

    /// Constructor with no `advertised_at` (Q6 OPTIONAL). For
    /// publishers with no wall-clock or those preferring explicit
    /// omission over a sentinel zero.
    pub fn for_local_listener_no_clock(
        peer_id: impl Into<String>,
        endpoint_url: impl Into<String>,
    ) -> Self {
        Self {
            peer_id: peer_id.into(),
            transport_type: TRANSPORT_HTTP.into(),
            endpoint_url: endpoint_url.into(),
            supported_ops: vec![OP_EXECUTE.into()],
            freshness: FRESHNESS_LIVE.into(),
            nonce_required: true,
            cap_flow: CAP_FLOW_BOTH.into(),
            advertised_at: None,
            priority: None,
        }
    }

    /// Encode to a `system/peer/transport/http` `Entity`.
    pub fn to_entity(&self) -> entity_entity::Entity {
        let supported_ops_arr = entity_ecf::Value::Array(
            self.supported_ops
                .iter()
                .map(|s| entity_ecf::text(s))
                .collect(),
        );
        let endpoint_map = entity_ecf::Value::Map(vec![(
            entity_ecf::text("url"),
            entity_ecf::text(&self.endpoint_url),
        )]);
        let mut fields = vec![
            (entity_ecf::text("peer_id"), entity_ecf::text(&self.peer_id)),
            (
                entity_ecf::text("transport_type"),
                entity_ecf::text(&self.transport_type),
            ),
            (entity_ecf::text("endpoint"), endpoint_map),
            (entity_ecf::text("supported_ops"), supported_ops_arr),
            (
                entity_ecf::text("freshness"),
                entity_ecf::text(&self.freshness),
            ),
            (
                entity_ecf::text("nonce_required"),
                entity_ecf::Value::Bool(self.nonce_required),
            ),
            (
                entity_ecf::text("cap_flow"),
                entity_ecf::text(&self.cap_flow),
            ),
        ];
        // Q6 omitempty — only emit advertised_at when present.
        if let Some(ts) = self.advertised_at {
            fields.push((
                entity_ecf::text("advertised_at"),
                entity_ecf::Value::Integer(ts.into()),
            ));
        }
        // Q1 omitempty — only emit priority when explicitly set.
        // Absent priority is interpreted per the resolver's
        // `effective_priority` rule (primary → 0, others → 100).
        if let Some(p) = self.priority {
            fields.push((
                entity_ecf::text("priority"),
                entity_ecf::Value::Integer(p.into()),
            ));
        }
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
        entity_entity::Entity::new(TYPE_PEER_TRANSPORT_HTTP, data)
            .expect("entity construction for system/peer/transport/http")
    }

    /// Decode a `system/peer/transport/http` `Entity`. D5: `transport_type`
    /// MUST equal `"http"` — mismatch is fail-closed.
    pub fn from_entity(
        entity: &entity_entity::Entity,
    ) -> Result<Self, TcpProfileDecodeError> {
        if entity.entity_type != TYPE_PEER_TRANSPORT_HTTP {
            return Err(TcpProfileDecodeError::UnexpectedType(
                entity.entity_type.clone(),
            ));
        }
        let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice())
            .map_err(|e| TcpProfileDecodeError::Cbor(e.to_string()))?;
        let map = match value {
            ciborium::Value::Map(m) => m,
            _ => return Err(TcpProfileDecodeError::NotAMap),
        };
        let peer_id = field_text(&map, "peer_id")
            .ok_or(TcpProfileDecodeError::MissingField("peer_id"))?;
        let transport_type = field_text(&map, "transport_type")
            .ok_or(TcpProfileDecodeError::MissingField("transport_type"))?;
        if transport_type != TRANSPORT_HTTP {
            return Err(TcpProfileDecodeError::TransportTypeMismatch {
                expected: TRANSPORT_HTTP,
                got: transport_type,
            });
        }
        let endpoint_url = match field_lookup(&map, "endpoint") {
            Some(ciborium::Value::Map(m)) => field_text(m, "url").ok_or(
                TcpProfileDecodeError::BadFieldShape {
                    field: "endpoint.url",
                    detail: "missing or non-text url field".into(),
                },
            )?,
            Some(_) => {
                return Err(TcpProfileDecodeError::BadFieldShape {
                    field: "endpoint",
                    detail: "expected CBOR map".into(),
                })
            }
            None => return Err(TcpProfileDecodeError::MissingField("endpoint")),
        };
        let supported_ops = match field_lookup(&map, "supported_ops") {
            Some(ciborium::Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| match v {
                    ciborium::Value::Text(s) => Some(s.clone()),
                    _ => None,
                })
                .collect(),
            Some(_) => {
                return Err(TcpProfileDecodeError::BadFieldShape {
                    field: "supported_ops",
                    detail: "expected CBOR array".into(),
                })
            }
            None => return Err(TcpProfileDecodeError::MissingField("supported_ops")),
        };
        let freshness = field_text(&map, "freshness")
            .ok_or(TcpProfileDecodeError::MissingField("freshness"))?;
        let nonce_required = match field_lookup(&map, "nonce_required") {
            Some(ciborium::Value::Bool(b)) => *b,
            Some(_) => {
                return Err(TcpProfileDecodeError::BadFieldShape {
                    field: "nonce_required",
                    detail: "expected CBOR bool".into(),
                })
            }
            None => return Err(TcpProfileDecodeError::MissingField("nonce_required")),
        };
        let cap_flow = field_text(&map, "cap_flow")
            .ok_or(TcpProfileDecodeError::MissingField("cap_flow"))?;
        // Q6 ratified §8.9 — OPTIONAL; absent or wrong-type ⇒ None.
        // See TcpProfileData::from_entity for the full disposition.
        let advertised_at = match field_lookup(&map, "advertised_at") {
            Some(ciborium::Value::Integer(i)) => u64::try_from(*i).ok(),
            _ => None,
        };
        // Q1 — OPTIONAL `priority` (uint). Absent or wrong-type ⇒ None;
        // the resolver applies `effective_priority` (primary unset → 0,
        // others unset → 100) so absence here is meaningful, not an
        // error. Same Gap-A class tolerance as advertised_at.
        let priority = match field_lookup(&map, "priority") {
            Some(ciborium::Value::Integer(i)) => u32::try_from(*i).ok(),
            _ => None,
        };
        Ok(HttpProfileData {
            peer_id,
            transport_type,
            endpoint_url,
            supported_ops,
            freshness,
            nonce_required,
            cap_flow,
            advertised_at,
            priority,
        })
    }
}

fn field_lookup<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<&'a ciborium::Value> {
    map.iter().find_map(|(k, v)| match k {
        ciborium::Value::Text(t) if t == key => Some(v),
        _ => None,
    })
}

fn field_text(map: &[(ciborium::Value, ciborium::Value)], key: &str) -> Option<String> {
    field_lookup(map, key).and_then(|v| match v {
        ciborium::Value::Text(s) => Some(s.clone()),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_ops_closed_enum() {
        assert!(is_valid_supported_op(OP_EXECUTE));
        assert!(is_valid_supported_op(OP_TREE_GET));
        assert!(is_valid_supported_op(OP_CONTENT_GET));
        assert!(is_valid_supported_op(OP_MANIFEST_GET));
        assert!(!is_valid_supported_op(OP_SUBSCRIBE_RESERVED));
        assert!(!is_valid_supported_op("GET"));
        assert!(!is_valid_supported_op("execute"));
        assert!(!is_valid_supported_op(""));
    }

    #[test]
    fn transport_names_match_spec_strings() {
        // Pinned wire strings — changing these is a breaking change.
        assert_eq!(TRANSPORT_TCP, "tcp");
        assert_eq!(TRANSPORT_WEBSOCKET, "websocket");
        assert_eq!(TRANSPORT_HTTP, "http");
        assert_eq!(TRANSPORT_HTTP_POLL, "http-poll");
        assert_eq!(TRANSPORT_QUIC, "quic");
    }

    #[test]
    fn tcp_profile_round_trip() {
        let profile = TcpProfileData::for_local_listener(
            "peer-A",
            "tcp://127.0.0.1:4040",
            1_700_000_000_000,
        );
        let entity = profile.to_entity();
        assert_eq!(entity.entity_type, TYPE_PEER_TRANSPORT_TCP);
        let decoded = TcpProfileData::from_entity(&entity).expect("decode");
        assert_eq!(decoded, profile);
        assert_eq!(decoded.endpoint_url, "tcp://127.0.0.1:4040");
        assert_eq!(decoded.supported_ops, vec!["EXECUTE".to_string()]);
        assert_eq!(decoded.freshness, "live");
        assert!(decoded.nonce_required);
        assert_eq!(decoded.cap_flow, "both");
    }

    #[test]
    fn tcp_profile_rejects_wrong_entity_type() {
        // A profile entity of a different transport type should NOT decode
        // as tcp — guards against mis-routing.
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![]));
        let wrong = entity_entity::Entity::new("system/peer/transport/websocket", data)
            .expect("entity ok");
        match TcpProfileData::from_entity(&wrong) {
            Err(TcpProfileDecodeError::UnexpectedType(s)) => {
                assert_eq!(s, "system/peer/transport/websocket");
            }
            other => panic!("expected UnexpectedType, got {:?}", other),
        }
    }

    #[test]
    fn tcp_profile_rejects_transport_type_mismatch() {
        // D5: data.transport_type MUST equal the entity-type suffix.
        // A `system/peer/transport/tcp` entity claiming transport_type
        // "websocket" inside its data is invalid — fail closed.
        let bad_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("peer_id"),
                entity_ecf::text("peer-A"),
            ),
            (
                entity_ecf::text("transport_type"),
                entity_ecf::text("websocket"), // <-- mismatch
            ),
            (
                entity_ecf::text("endpoint"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("url"),
                    entity_ecf::text("wss://example.com/"),
                )]),
            ),
            (
                entity_ecf::text("supported_ops"),
                entity_ecf::Value::Array(vec![entity_ecf::text("EXECUTE")]),
            ),
            (
                entity_ecf::text("freshness"),
                entity_ecf::text("live"),
            ),
            (
                entity_ecf::text("nonce_required"),
                entity_ecf::Value::Bool(true),
            ),
            (
                entity_ecf::text("cap_flow"),
                entity_ecf::text("both"),
            ),
            (
                entity_ecf::text("advertised_at"),
                entity_ecf::Value::Integer(0u64.into()),
            ),
        ]));
        let entity = entity_entity::Entity::new(TYPE_PEER_TRANSPORT_TCP, bad_data)
            .expect("entity ok");
        match TcpProfileData::from_entity(&entity) {
            Err(TcpProfileDecodeError::TransportTypeMismatch { expected, got }) => {
                assert_eq!(expected, "tcp");
                assert_eq!(got, "websocket");
            }
            other => panic!("expected TransportTypeMismatch, got {:?}", other),
        }
    }

    // ---------- HTTP profile (Chunk D) ----------

    #[test]
    fn http_profile_round_trip() {
        let profile = HttpProfileData::for_local_listener(
            "peer-A",
            "https://my-peer.example/entity",
            1_700_000_000_000,
        );
        let entity = profile.to_entity();
        assert_eq!(entity.entity_type, TYPE_PEER_TRANSPORT_HTTP);
        let decoded = HttpProfileData::from_entity(&entity).expect("decode");
        assert_eq!(decoded, profile);
        assert_eq!(decoded.endpoint_url, "https://my-peer.example/entity");
        assert_eq!(decoded.supported_ops, vec!["EXECUTE".to_string()]);
        assert_eq!(decoded.freshness, "live");
        assert!(decoded.nonce_required);
    }

    #[test]
    fn http_profile_rejects_wrong_entity_type() {
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![]));
        let wrong =
            entity_entity::Entity::new("system/peer/transport/tcp", data).expect("entity ok");
        match HttpProfileData::from_entity(&wrong) {
            Err(TcpProfileDecodeError::UnexpectedType(s)) => {
                assert_eq!(s, "system/peer/transport/tcp");
            }
            other => panic!("expected UnexpectedType, got {:?}", other),
        }
    }

    #[test]
    fn http_profile_rejects_transport_type_mismatch() {
        // D5: data.transport_type MUST equal the entity-type suffix.
        let bad_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("peer_id"),
                entity_ecf::text("peer-A"),
            ),
            (
                entity_ecf::text("transport_type"),
                entity_ecf::text("tcp"), // <-- mismatch on http profile
            ),
            (
                entity_ecf::text("endpoint"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("url"),
                    entity_ecf::text("https://example.com/"),
                )]),
            ),
            (
                entity_ecf::text("supported_ops"),
                entity_ecf::Value::Array(vec![entity_ecf::text("EXECUTE")]),
            ),
            (entity_ecf::text("freshness"), entity_ecf::text("live")),
            (
                entity_ecf::text("nonce_required"),
                entity_ecf::Value::Bool(true),
            ),
            (entity_ecf::text("cap_flow"), entity_ecf::text("both")),
            (
                entity_ecf::text("advertised_at"),
                entity_ecf::Value::Integer(0u64.into()),
            ),
        ]));
        let entity = entity_entity::Entity::new(TYPE_PEER_TRANSPORT_HTTP, bad_data)
            .expect("entity ok");
        match HttpProfileData::from_entity(&entity) {
            Err(TcpProfileDecodeError::TransportTypeMismatch { expected, got }) => {
                assert_eq!(expected, "http");
                assert_eq!(got, "tcp");
            }
            other => panic!("expected TransportTypeMismatch, got {:?}", other),
        }
    }

    #[test]
    fn http_profile_rejects_flat_address_shape() {
        // Defense in depth — a legacy {address}-field payload at the
        // http type must NOT decode (fails on missing required fields).
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("address"),
            entity_ecf::text("https://example.com/"),
        )]));
        let flat =
            entity_entity::Entity::new(TYPE_PEER_TRANSPORT_HTTP, data).expect("entity ok");
        match HttpProfileData::from_entity(&flat) {
            Err(TcpProfileDecodeError::MissingField(_)) => {}
            other => panic!(
                "expected MissingField on legacy flat shape, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn tcp_profile_rejects_flat_address_shape() {
        // The retired flat shape (`{address}` field only) MUST NOT
        // decode as a tcp profile — fail fast with clear "missing
        // required field" errors. No migration cruft per ruling §6.
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("address"),
            entity_ecf::text("127.0.0.1:4040"),
        )]));
        let flat = entity_entity::Entity::new(TYPE_PEER_TRANSPORT_TCP, data)
            .expect("entity ok");
        match TcpProfileData::from_entity(&flat) {
            Err(TcpProfileDecodeError::MissingField(_)) => {}
            other => panic!("expected MissingField on legacy flat shape, got {:?}", other),
        }
    }

    // ============================================================
    // Q6 — `advertised_at` OPTIONAL (PROPOSAL §8.2 / §8.9, ratified).
    // Field is OPTIONAL; absent or wrong-CBOR-type
    // resolves to `None`. omitempty on encode. Round-trip both ways.
    // ============================================================

    #[test]
    fn q6_tcp_profile_omits_advertised_at_when_none() {
        let profile = TcpProfileData::for_local_listener_no_clock(
            "peer-X",
            "tcp://127.0.0.1:5050",
        );
        assert_eq!(profile.advertised_at, None);
        let entity = profile.to_entity();
        // Decode and confirm round-trips as None.
        let decoded = TcpProfileData::from_entity(&entity).expect("decode");
        assert_eq!(decoded, profile);
        assert_eq!(decoded.advertised_at, None);
        // CBOR-level proof: walk the entity's data map and assert
        // `advertised_at` is absent — not present-with-zero.
        let val: ciborium::Value =
            ciborium::from_reader(entity.data.as_slice()).expect("cbor");
        let map = match val {
            ciborium::Value::Map(m) => m,
            _ => panic!("data not a map"),
        };
        let present = map
            .iter()
            .any(|(k, _)| k.as_text() == Some("advertised_at"));
        assert!(
            !present,
            "omitempty violation: advertised_at MUST be absent from CBOR map when None"
        );
    }

    #[test]
    fn q6_tcp_profile_absent_advertised_at_decodes_as_none() {
        // Hand-build a profile entity that omits advertised_at (the
        // pre-fix Rust decoder would have rejected this with a
        // `MissingField("advertised_at")` error; post-Q6 it must
        // decode cleanly with `advertised_at: None`).
        let endpoint = entity_ecf::Value::Map(vec![(
            entity_ecf::text("url"),
            entity_ecf::text("tcp://10.0.0.1:9000"),
        )]);
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("peer_id"), entity_ecf::text("peer-Y")),
            (entity_ecf::text("transport_type"), entity_ecf::text("tcp")),
            (entity_ecf::text("endpoint"), endpoint),
            (
                entity_ecf::text("supported_ops"),
                entity_ecf::Value::Array(vec![entity_ecf::text("EXECUTE")]),
            ),
            (entity_ecf::text("freshness"), entity_ecf::text("live")),
            (
                entity_ecf::text("nonce_required"),
                entity_ecf::Value::Bool(true),
            ),
            (entity_ecf::text("cap_flow"), entity_ecf::text("both")),
            // Note: NO advertised_at field.
        ]));
        let entity = entity_entity::Entity::new(TYPE_PEER_TRANSPORT_TCP, data).unwrap();
        let decoded = TcpProfileData::from_entity(&entity).expect("Q6 decode");
        assert_eq!(decoded.advertised_at, None);
    }

    #[test]
    fn q6_tcp_profile_wrong_type_advertised_at_decodes_as_none() {
        // Gap-A class — Go's pre-fix emitted advertised_at as `string`
        // (epoch-ms-as-text) which Rust pre-Q6 hard-rejected on the
        // wrong-type guard. Post-Q6 we tolerate wrong-type as None
        // because the field is advisory (D-3). Validates the
        // tolerance posture documented in the decoder.
        let endpoint = entity_ecf::Value::Map(vec![(
            entity_ecf::text("url"),
            entity_ecf::text("tcp://10.0.0.2:9001"),
        )]);
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("peer_id"), entity_ecf::text("peer-Z")),
            (entity_ecf::text("transport_type"), entity_ecf::text("tcp")),
            (entity_ecf::text("endpoint"), endpoint),
            (
                entity_ecf::text("supported_ops"),
                entity_ecf::Value::Array(vec![entity_ecf::text("EXECUTE")]),
            ),
            (entity_ecf::text("freshness"), entity_ecf::text("live")),
            (
                entity_ecf::text("nonce_required"),
                entity_ecf::Value::Bool(true),
            ),
            (entity_ecf::text("cap_flow"), entity_ecf::text("both")),
            // Wrong-type: string instead of uint (the Gap-A class).
            (
                entity_ecf::text("advertised_at"),
                entity_ecf::text("1700000000000"),
            ),
        ]));
        let entity = entity_entity::Entity::new(TYPE_PEER_TRANSPORT_TCP, data).unwrap();
        let decoded = TcpProfileData::from_entity(&entity).expect(
            "Q6 tolerance: wrong-type advisory field MUST NOT reject a structurally-valid profile",
        );
        assert_eq!(decoded.advertised_at, None);
    }

    #[test]
    fn q6_http_profile_omits_advertised_at_when_none() {
        let profile = HttpProfileData::for_local_listener_no_clock(
            "peer-X",
            "http://127.0.0.1:8080/entity",
        );
        assert_eq!(profile.advertised_at, None);
        let entity = profile.to_entity();
        let decoded = HttpProfileData::from_entity(&entity).expect("decode");
        assert_eq!(decoded, profile);
        let val: ciborium::Value =
            ciborium::from_reader(entity.data.as_slice()).expect("cbor");
        let map = match val {
            ciborium::Value::Map(m) => m,
            _ => panic!("data not a map"),
        };
        let present = map
            .iter()
            .any(|(k, _)| k.as_text() == Some("advertised_at"));
        assert!(
            !present,
            "omitempty violation on HttpProfileData: advertised_at MUST be absent when None"
        );
    }
}
