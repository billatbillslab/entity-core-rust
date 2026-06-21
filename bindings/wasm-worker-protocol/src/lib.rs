#![cfg(target_arch = "wasm32")]
//! Wire protocol shared between `wasm-worker-host` (worker side) and
//! `wasm-worker-proxy` (main-thread side).
//!
//! # Boundary rule (normative for contributors)
//!
//! This crate's enums (`Request`, `Response`, `Event`) are a **serializable
//! shadow of the SDK's L1 method signatures, nothing more**. Adding a variant
//! means a corresponding SDK method already exists (or is being added in
//! lock-step). Cross-cutting concerns — auth, retry, idempotency, batching,
//! caching semantics — belong in the SDK (so in-process consumers get them
//! too) or in the proxy/host pair (so they are transport-specific). They
//! **MUST NOT** be added in this crate. This crate exists to ferry typed
//! messages, not to define semantics.
//!
//! **Typed enums for discriminants are within bounds.** `WireErrorKind` and
//! `CasFailureKind` shadow `SdkError`'s and `CasError`'s discriminants — that
//! is mirroring the SDK signature faithfully, not adding cross-cutting
//! behavior. Stringly-typed `kind: String` was an earlier draft; reverted
//! after Phase 1 protocol review per egui-team push-back.
//!
//! See the worker-migration design notes for the boundary rule rationale
//! and the Phase 1 protocol review for the resolution of Q1-S3.
//!
//! # Versioning (R1)
//!
//! [`PROTOCOL_VERSION`] is bumped whenever the wire shape of any variant
//! changes. The worker posts `Response::Ready { protocol_version, sdk_version }`
//! on init; the proxy verifies match and fails fast on mismatch. The proxy
//! and host ship together.
//!
//! # Multi-peer addressing
//!
//! Every peer-scoped `Request` carries an explicit `peer_id: String` field
//! (per S1 — Option C: one worker hosts multiple peers via the existing
//! `EntitySDK` BTreeMap). Subscriptions are prefix-qualified so peer is
//! inferred from the prefix and no separate field is needed there.

use serde::{Deserialize, Serialize};

#[cfg(feature = "conversions")]
pub mod conversions;

/// Wire-protocol version. Bumped on any wire-shape change.
///
/// **v9:** Inspect-hook plumbing per the upstream inspect-worker-arm design.
/// Adds `Event::Inspect { peer_id, fact }` carrying the marshalled
/// `InspectFact` (Dispatch / Wire / Binding variants) and
/// `Request::SetInspectEnabled { peer_id, enabled }` (+ matching
/// `Response::SetInspectEnabled`) so consumers can flip per-peer
/// marshalling on/off. Default off per §9 q1 — peers with no attached
/// sink pay zero marshal cost. Wire and binding facts carry frame
/// length + path metadata only; body retrieval is a deferred follow-on
/// (§9 q2). The new request is NOT in `REQUEST_VARIANT_NAMES` — it has
/// no SDK L1 counterpart (a worker-side toggle, not an SDK method).
///
/// **v8:** `Response::Ready` gains
/// `actual_capabilities: Option<WireCaps>` so the proxy gets an affirmative
/// "OPFS came up" signal rather than inferring it through retry gymnastics.
/// `WireCaps.opfs_active = true` iff `InitParams.opfs_root` was `Some` and
/// `build_async()` succeeded — note the host does NOT do silent
/// OPFS-to-memory fallback; OPFS init failure surfaces via
/// `Response::Init { result: Some(err) }` and `Ready` is never posted in
/// that path. The new field uses `#[serde(default)]` so v7 hosts that
/// don't emit it deserialize as `None`; the version handshake catches the
/// mismatch fail-fast anyway. Stage 3 UI on the consumer side reads this
/// to surface requested-vs-actual peer mode. See the upstream asks (Ask 1).
///
/// **v7:** `InitParams.enable_opfs: bool` replaced with
/// `InitParams.opfs_root: Option<String>` — clean break so multiple
/// OPFS-backed workers can coexist in one origin under distinct
/// subdirectories. `None` = no OPFS; `Some("")` = OPFS root (single-
/// instance legacy); `Some("peer-…")` = per-instance subdir.
/// `createSyncAccessHandle` is exclusive per file, so two stores rooted
/// at the same directory collide on `entities.log` — the new field exists
/// precisely to give each worker its own root. v6 proxies fail fast via
/// the version handshake. See the worker-migration design notes
/// (Appendix D) for the landed history.
///
/// **v6:** `Request::Subscribe` gains explicit `peer_id`.
/// The host previously hardcoded `default_peer_id` regardless of which
/// peer the subscription targeted, so any non-primary-peer window saw
/// the initial Snapshot (built from the shared store) but never any
/// Change events (registered on the wrong peer's L1 engine). v5→v6
/// `#[serde(default)]` lets old proxies be detected via empty peer_id;
/// the version handshake catches it cleanly anyway. See the
/// subscribe peer-scoping design notes.
///
/// **v5:** Wire-surface closeout — `Request::SetMetadata`
/// (Parity-C) and `Request::ConnectPeer` (Parity-D-narrow). SetMetadata
/// reuses `WirePeerMetadata` from v4. ConnectPeer adds `ConnectPeerOk
/// { remote_peer_id }` and wraps `Peer::connect_to(addr)`. After this,
/// the worker-mode wire surface fully mirrors what `PeerContext` exposes
/// in Direct mode. See the wire-surface closeout design notes.
///
/// **v4:** Worker-mode peer management parity. Adds
/// `Request::{CreatePeer, DeletePeer}` + `Response::{CreatePeer, DeletePeer}`
/// with the `CreatePeerOk { peer_id, keypair_seed, metadata }` shape —
/// generated seed round-trips to the consumer for localStorage
/// persistence. `WireQueryResults` gains `total` + `cursor`;
/// `WireQueryMatch` gains `entity_type`. All new fields use
/// `#[serde(default)]` for v3→v4 backcompat. See the Phase 3
/// worker-parity remainder design notes.
///
/// **v3:** `InitParams` gained `enable_opfs: bool`. When
/// `true`, the worker host builds its SDK with OPFS-backed durable
/// storage (`PeerBuilder::opfs().await`); default `false` preserves
/// the prior in-memory behavior. See the Phase 2 OPFS-wiring design notes.
///
/// **v2:** `Response::{Init, RegisterBackendPeer, Subscribe,
/// Unsubscribe}` changed from `result: Result<(), WireError>` to
/// `result: Option<WireError>`. Reason: ciborium's deserializer for
/// `()` from CBOR `null` is asymmetric — serde's encoder produces
/// `{ "Ok": null }`, the decoder rejects it. `Option<WireError>` round-trips
/// cleanly (None = success, Some = failure). Documented in the Phase 3
/// pilot status notes (§#1) with full hex evidence.
pub const PROTOCOL_VERSION: u32 = 9;

/// `Request` variants that mirror an L1 SDK method. Ordering must match
/// `entity_sdk::L1_WORKER_MIRRORED_SURFACE` — the [coverage check](crate)
/// fires a compile-time assertion if they diverge.
///
/// **What belongs in this list:** any `Request` variant that exists to
/// shadow a public `entity_sdk` L1 method (`Get`, `Put`, `Query`, etc.,
/// plus `Subscribe` / `Unsubscribe`).
///
/// **What does not belong:** wire-only primitives that have no SDK
/// counterpart (`Init`, `RegisterBackendPeer`). These exist solely on the
/// wire and are not part of the mirrored L1 surface; they are exempt from
/// the coverage check. See `CONTRIBUTING.md` boundary cases.
pub const REQUEST_VARIANT_NAMES: &[&str] = &[
    "Get",
    "Put",
    "PutCas",
    "List",
    "Remove",
    "Has",
    "Execute",
    "Query",
    "Count",
    "EntityCount",
    "PathCount",
    "InboxList",
    "InboxGet",
    "DiscoverHandlers",
    "DiscoverTypes",
    "Subscribe",
    "Unsubscribe",
];

// ---------------------------------------------------------------------------
// Drift-protection: compile-time coverage assertion
//
// This fires on `cargo check --target wasm32-unknown-unknown -p
// entity-wasm-worker-protocol`. If the SDK's declared worker-mirrored
// surface drifts from this crate's Request variant list, the build fails
// with the const-eval message — naming both lists and pointing to
// CONTRIBUTING.md.
//
// What this catches:
//   - Variant added to one list but not the other (most common drift).
//   - Lists same length but contents differ (typo, ordering drift).
//
// What this does NOT catch:
//   - SDK method added without anyone updating L1_WORKER_MIRRORED_SURFACE.
//     The CONTRIBUTING.md checklist is the cultural mechanism for that
//     gap. Reviewers checking SDK-modifying PRs should verify the four
//     sites were all updated.
// ---------------------------------------------------------------------------

// Used by the const _COVERAGE_CHECK_… assertion below. Rust's dead-code
// analysis doesn't trace through `const _` items, so allow the warning.
#[allow(dead_code)]
const fn str_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[allow(dead_code)]
const fn arrays_match(a: &[&str], b: &[&str]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if !str_eq(a[i], b[i]) {
            return false;
        }
        i += 1;
    }
    true
}

const _COVERAGE_CHECK_L1_SURFACE_MATCHES_PROTOCOL: () = assert!(
    arrays_match(entity_sdk::L1_WORKER_MIRRORED_SURFACE, REQUEST_VARIANT_NAMES),
    "wasm-worker-protocol Request variants do not match entity_sdk::L1_WORKER_MIRRORED_SURFACE. \
     See bindings/wasm-worker-protocol/CONTRIBUTING.md for the four-site checklist."
);

/// Correlation ID for matching a `Response` to its originating `Request`.
pub type RequestId = u64;

/// Subscription ID for routing `Event`s on the main thread back to the
/// originating subscriber's channel.
pub type SubId = u64;

// ---------------------------------------------------------------------------
// Wire types
//
// Phase 1 status: shapes finalized per protocol-review convergence (Q1, Q2,
// Q3, S1, S2). Payload bodies for not-yet-mirrored methods are still
// placeholders pending the broader L1 surface scaffolding (count,
// history_query, history_rollback, etc.) — added incrementally as their
// proxy_method! invocations land.
// ---------------------------------------------------------------------------

/// Content hash on the wire: algorithm byte + 32-byte digest, fixed 33 bytes.
/// Same layout as `entity_hash::Hash::to_bytes()`. Sent as a CBOR byte string
/// via `serde_bytes` to avoid array-of-int encoding bloat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireHash(#[serde(with = "serde_bytes")] pub Vec<u8>);

/// Q1 resolution (per protocol-review): keep `content_hash` on the wire. The
/// host has it for free (the SDK computes it on every dispatch return); the
/// consumer uses it directly in dedup / change-detection paths. Forcing
/// SHA-256 recomputation on every cache update is per-frame CPU work for a
/// 32-byte wire saving — not worth it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireEntity {
    pub entity_type: String,
    /// Raw CBOR-encoded body. Byte-string on the wire (serde_bytes), not an
    /// array of u8 ints — important for size on burst-traffic snapshots.
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    /// Worker-computed content hash. Consumer trusts this for routine reads;
    /// hash verification (if a consumer wants it) is opt-in and recomputes.
    pub content_hash: WireHash,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WireExecuteOptions {
    pub resource_targets: Vec<String>,
    pub resource_exclude: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireHandlerResult {
    pub status: u32,
    pub result: WireEntity,
    /// Envelope `included` entities, if any. Keyed by content hash.
    pub included: Vec<(WireHash, WireEntity)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireQueryResults {
    pub matches: Vec<WireQueryMatch>,
    pub has_more: bool,
    /// Total number of matches in the underlying index (pre-pagination).
    /// `#[serde(default)]` for v3→v4 backcompat — older hosts ship 0.
    #[serde(default)]
    pub total: u64,
    /// Opaque pagination cursor; pass to a follow-up query to resume.
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireQueryMatch {
    pub path: String,
    pub content_hash: WireHash,
    pub entity: Option<WireEntity>,
    /// Entity type of the match (e.g. `"app/article"`). Mirrors
    /// `entity_sdk::QueryMatch.entity_type`. `#[serde(default)]` for
    /// v3→v4 backcompat — older hosts ship an empty string.
    #[serde(default)]
    pub entity_type: String,
}

// ---------------------------------------------------------------------------
// Error types — Q2/Q3 resolution: typed discriminants, not stringly-typed.
//
// Shadows SdkError's variant set without dragging in SdkError's internal
// payloads. New SdkError variant → parallel WireErrorKind variant + protocol
// version bump. Same discipline as the rest of the wire protocol.
// ---------------------------------------------------------------------------

/// Discriminant for `WireError`. Mirrors `entity_sdk::SdkError` variant kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireErrorKind {
    NotFound,
    CapabilityDenied,
    TreeError,
    HandlerError,
    Cas,
    InvalidParams,
    /// Forward-compat slot for SDK variants the protocol version doesn't yet
    /// model. Should be rare given the version handshake catches mismatches
    /// at boot, but useful for SDK-internal "unexpected" errors that the
    /// worker can't classify.
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireError {
    pub kind: WireErrorKind,
    /// Human-readable; not load-bearing for control flow. For logging /
    /// surfacing to the user.
    pub message: String,
    /// Optional kind-specific structured carry. CBOR `Value` so any
    /// serializable payload survives the wire. Most variants leave this
    /// `None`; `Cas` uses it (alternatively via `CasFailure`, see Q3).
    pub detail: Option<ciborium::Value>,
}

/// Discriminant for CAS failures. Q3 resolution: typed enum, not strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CasFailureKind {
    Mismatch,
    NotFound,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CasFailure {
    pub kind: CasFailureKind,
    /// Present on `Mismatch` with the actual current hash. Absent for `NotFound`.
    pub actual: Option<WireHash>,
}

// ---------------------------------------------------------------------------
// Init / handshake (S2)
//
// Worker boots, awaits `Request::Init`, applies params, posts
// `Response::Ready`. Subsequent Requests are accepted only after Ready.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedPeer {
    pub peer_id: String,
    /// 32-byte Ed25519 keypair seed. Stays main-thread-derived; passed to
    /// worker via init message per R10b ("pass-on-init").
    #[serde(with = "serde_bytes")]
    pub keypair_seed: Vec<u8>,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlerSpec {
    /// Handler URI pattern (e.g. "system/tree", "system/inbox"). The worker
    /// host's binary statically wires handler bodies; this list selects
    /// which compiled-in handlers to register.
    pub pattern: String,
}

/// Peer metadata on the wire. Mirrors `entity_sdk::PeerMetadata`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WirePeerMetadata {
    pub label: Option<String>,
    pub persisted: bool,
    pub listen_addresses: Vec<String>,
}

/// Success payload for `Request::CreatePeer`.
///
/// `keypair_seed` is the freshly-generated 32-byte Ed25519 secret —
/// returned so the consumer can persist it (e.g. localStorage) for
/// reload survival. The host does not retain it server-side; the
/// peer is reconstructed from the seed on the next `Init`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePeerOk {
    pub peer_id: String,
    #[serde(with = "serde_bytes")]
    pub keypair_seed: Vec<u8>,
    pub metadata: WirePeerMetadata,
}

/// Success payload for `Request::ConnectPeer`. Carries the remote peer's
/// identifier (derived from the entity-protocol handshake during
/// `Peer::connect_to`), which the consumer uses to construct
/// `entity://{remote_peer_id}/...` URIs for subsequent dispatches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectPeerOk {
    pub remote_peer_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitParams {
    pub primary_peer: PersistedPeer,
    pub additional_peers: Vec<PersistedPeer>,
    /// Handler set to register at boot. Per R7: handlers are baked into the
    /// worker-host binary; this list selects which of the compiled-in
    /// handlers to actually register for this consumer instance.
    pub handlers: Vec<HandlerSpec>,
    /// When `Some(root)`, the worker host backs its SDK with OPFS-backed
    /// durable storage rooted at the named OPFS subdirectory. Empty string
    /// uses the OPFS root directly (single-instance legacy). Multiple
    /// OPFS-backed workers in the same origin MUST use distinct roots —
    /// `createSyncAccessHandle` is exclusive per file. The host's build
    /// must enable `entity-sdk/wasm-persist`; otherwise it's a build-time
    /// configuration mismatch that the host detects at init.
    ///
    /// `#[serde(default)]` so v6 proxies (which don't know about this
    /// field) still deserialize; they'll be rejected by the
    /// PROTOCOL_VERSION handshake before any field is consulted.
    #[serde(default)]
    pub opfs_root: Option<String>,
}

/// Reports which optional kernel features actually wired up inside the
/// worker. Carried on `Response::Ready`. Reaching the Ready branch means
/// `build_async()` succeeded; the booleans then say which of the
/// optional capabilities the consumer requested came up.
///
/// **No silent fallback.** If the consumer asked for a capability and
/// the worker couldn't provide it, the host returns
/// `Response::Init { result: Some(err) }` and Ready is never posted.
/// `WireCaps` exists to give the consumer an affirmative "I have this"
/// signal in the success path so they don't have to infer it via retry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireCaps {
    /// `true` iff `InitParams.opfs_root` was `Some` and the SDK build
    /// completed (which implies OPFS handle acquisition succeeded —
    /// failure would have produced `Response::Init` with an error).
    pub opfs_active: bool,
}

// ---------------------------------------------------------------------------
// Request / Response / Event
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum Request {
    /// Worker initialization. Must be the first Request after spawn; worker
    /// rejects other Requests until Init completes and Ready has been posted.
    Init {
        request_id: RequestId,
        params: InitParams,
    },
    /// Register a peer the worker should treat as accessible at the given
    /// addresses (today's Tauri-backend-peer flow). Metadata-only — no local
    /// PeerContext is created; the SDK's connection pool reaches the peer
    /// via the listed addresses on demand. See `bindings/sdk/src/peer_manager.rs:188-206`.
    RegisterBackendPeer {
        request_id: RequestId,
        peer_id: String,
        label: Option<String>,
        listen_addresses: Vec<String>,
    },

    /// Create a new peer with a freshly-generated keypair. The worker
    /// host calls `Keypair::generate()` (browser `getrandom` works in
    /// the worker), constructs the peer via the SDK, and returns the
    /// seed inline so the consumer can persist it for reload survival.
    CreatePeer {
        request_id: RequestId,
        label: Option<String>,
    },

    /// Delete a peer by id. Returns false-equivalent (in `Response::DeletePeer.result`)
    /// if the id doesn't exist or is the primary peer (per SDK semantics).
    DeletePeer {
        request_id: RequestId,
        peer_id: String,
    },

    /// Update an existing peer's metadata (label, listen_addresses,
    /// persisted flag). Wraps `EntitySDK::set_metadata`. v5+.
    SetMetadata {
        request_id: RequestId,
        peer_id: String,
        metadata: WirePeerMetadata,
    },

    /// Open an outgoing connection from `peer_id` (local) to a remote
    /// peer at `address` (typically `ws://...` or `wss://...` in browser
    /// worker mode) and perform the entity-protocol handshake. Returns
    /// the remote peer's identifier on success. v5+.
    ///
    /// The connection is pooled inside the worker; subsequent
    /// `execute()` calls against `entity://{remote_peer_id}/...` URIs
    /// reuse it.
    ConnectPeer {
        request_id: RequestId,
        peer_id: String,
        address: String,
    },

    // -- Tree dispatched (S1: peer_id on every variant) --
    Get {
        request_id: RequestId,
        peer_id: String,
        path: String,
    },
    Put {
        request_id: RequestId,
        peer_id: String,
        path: String,
        entity: WireEntity,
    },
    PutCas {
        request_id: RequestId,
        peer_id: String,
        path: String,
        entity: WireEntity,
        expected: WireHash,
    },
    List {
        request_id: RequestId,
        peer_id: String,
        prefix: String,
    },
    Remove {
        request_id: RequestId,
        peer_id: String,
        path: String,
    },
    Has {
        request_id: RequestId,
        peer_id: String,
        path: String,
    },

    // -- Generic dispatch --
    Execute {
        request_id: RequestId,
        peer_id: String,
        handler: String,
        operation: String,
        params: WireEntity,
        opts: WireExecuteOptions,
    },

    // -- Query --
    Query {
        request_id: RequestId,
        peer_id: String,
        expression: WireEntity,
    },
    Count {
        request_id: RequestId,
        peer_id: String,
        expression: WireEntity,
    },

    // -- Metadata --
    EntityCount {
        request_id: RequestId,
        peer_id: String,
    },
    PathCount {
        request_id: RequestId,
        peer_id: String,
    },

    // -- Inbox --
    InboxList {
        request_id: RequestId,
        peer_id: String,
    },
    InboxGet {
        request_id: RequestId,
        peer_id: String,
        relative_path: String,
    },

    // -- Discovery --
    DiscoverHandlers {
        request_id: RequestId,
        peer_id: String,
    },
    DiscoverTypes {
        request_id: RequestId,
        peer_id: String,
    },

    // -- Inspect (v9+) --
    //
    // Flips whether the worker host marshals inspect facts for `peer_id`.
    // Default-off — peers with no attached sink pay zero marshal cost.
    // The consumer (via the SDK) sends this when it installs the first
    // inspect sink for a peer, and again with `enabled: false` when the
    // last sink detaches. Unknown peer ids return an error.
    SetInspectEnabled {
        request_id: RequestId,
        peer_id: String,
        enabled: bool,
    },

    // -- Subscriptions --
    //
    // `peer_id` (v6+): the local peer whose dispatch engine the callback
    // is registered against. Writes through *other* peers fire their own
    // engines independently; a subscription is bound to exactly one peer.
    // (#[serde(default)] for v5→v6 backcompat: empty string falls back to
    // SDK default_peer_id with a tracing warning at the host.)
    //
    // `prefix` semantics (Unix-style):
    //   - trailing slash → subtree match. `/peer/app/` fires for any write
    //     to a path starting with `/peer/app/`.
    //   - no trailing slash → exact-path match. `/peer/app/state` fires
    //     only for writes to that exact path.
    //   - already `/*`-terminated or the universal `*` → passed through.
    //
    // The host translates this into the SDK's pattern syntax; see
    // `wasm-worker-host::prefix_to_pattern`.
    Subscribe {
        request_id: RequestId,
        sub_id: SubId,
        #[serde(default)]
        peer_id: String,
        prefix: String,
    },
    Unsubscribe {
        request_id: RequestId,
        sub_id: SubId,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum Response {
    /// Posted by worker after `Request::Init` completes. Carries the
    /// protocol-version handshake (R1). Proxy verifies version match; on
    /// mismatch, fails fast.
    ///
    /// `actual_capabilities` (v8+) reports which optional kernel features
    /// actually wired up inside the worker. `None` means an older host
    /// (v7) is sending Ready without this field — the version handshake
    /// will reject before the field is consulted, so a real consumer
    /// only sees `Some` in practice.
    Ready {
        request_id: RequestId,
        protocol_version: u32,
        sdk_version: String,
        #[serde(default)]
        actual_capabilities: Option<WireCaps>,
    },
    /// Init outcome. `None` = success (worker fully initialized; `Ready`
    /// is the success-success signal). `Some(err)` = init failed.
    ///
    /// Was `Result<(), WireError>` in PROTOCOL_VERSION=1; changed to
    /// `Option<WireError>` to work around ciborium's unit-from-null
    /// asymmetry. See `PROTOCOL_VERSION` doc.
    Init {
        request_id: RequestId,
        result: Option<WireError>,
    },
    RegisterBackendPeer {
        request_id: RequestId,
        result: Option<WireError>,
    },

    CreatePeer {
        request_id: RequestId,
        result: Result<CreatePeerOk, WireError>,
    },

    DeletePeer {
        request_id: RequestId,
        /// `None` on success (peer removed). `Some(err)` on failure
        /// (peer didn't exist, or was the primary peer — per SDK).
        result: Option<WireError>,
    },

    SetMetadata {
        request_id: RequestId,
        /// `None` on success. `Some(err)` on unknown peer_id or
        /// other SDK rejection.
        result: Option<WireError>,
    },

    ConnectPeer {
        request_id: RequestId,
        result: Result<ConnectPeerOk, WireError>,
    },

    Get {
        request_id: RequestId,
        result: Result<Option<WireEntity>, WireError>,
    },
    Put {
        request_id: RequestId,
        result: Result<WireHash, WireError>,
    },
    PutCas {
        request_id: RequestId,
        /// Inner `Result` distinguishes CAS failure (typed via `CasFailure`)
        /// from generic error (everything else, via `WireError`).
        result: Result<Result<WireHash, CasFailure>, WireError>,
    },
    List {
        request_id: RequestId,
        result: Result<Vec<WireListingEntry>, WireError>,
    },
    Remove {
        request_id: RequestId,
        result: Result<bool, WireError>,
    },
    Has {
        request_id: RequestId,
        result: Result<bool, WireError>,
    },

    Execute {
        request_id: RequestId,
        result: Result<WireHandlerResult, WireError>,
    },

    Query {
        request_id: RequestId,
        result: Result<WireQueryResults, WireError>,
    },
    Count {
        request_id: RequestId,
        result: Result<u64, WireError>,
    },

    EntityCount {
        request_id: RequestId,
        result: Result<u64, WireError>,
    },
    PathCount {
        request_id: RequestId,
        result: Result<u64, WireError>,
    },

    InboxList {
        request_id: RequestId,
        result: Result<Vec<WireListingEntry>, WireError>,
    },
    InboxGet {
        request_id: RequestId,
        result: Result<Option<WireEntity>, WireError>,
    },

    DiscoverHandlers {
        request_id: RequestId,
        result: Result<Vec<WireHandlerInfo>, WireError>,
    },
    DiscoverTypes {
        request_id: RequestId,
        result: Result<Vec<WireTypeInfo>, WireError>,
    },

    Subscribe {
        request_id: RequestId,
        result: Option<WireError>,
    },
    Unsubscribe {
        request_id: RequestId,
        result: Option<WireError>,
    },

    /// `None` on success. `Some(err)` when the peer id is unknown.
    SetInspectEnabled {
        request_id: RequestId,
        result: Option<WireError>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireListingEntry {
    pub path: String,
    pub content_hash: WireHash,
}

// ---------------------------------------------------------------------------
// Discovery wire types — mirrors of entity_sdk::HandlerInfo / TypeInfo /
// FieldInfo. These are descriptive metadata the SDK already collects from
// the peer's tree (SDK-OPERATIONS §9.1, §9.2); the wire shape just carries
// them across.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireHandlerInfo {
    pub pattern: String,
    pub name: String,
    pub operations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireTypeInfo {
    pub type_path: String,
    pub fields: Vec<WireFieldInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireFieldInfo {
    pub name: String,
    pub type_ref: String,
    pub optional: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Event {
    /// Initial state delivered when a subscription is established. Per the
    /// cache invariants documented in `wasm-worker-proxy`, this MUST arrive
    /// over the same channel before any `Change` event for the same `sub_id`.
    Snapshot {
        sub_id: SubId,
        entries: Vec<(String, WireEntity)>,
    },
    /// Incremental change for an entity within a subscribed prefix.
    ///
    /// **Lossless on the wire** — every change generates one `Change` event.
    /// The proxy applies each one to the cache mirror losslessly; the
    /// per-subscription **notification channel** separately coalesces with
    /// newest-wins semantics (see Q4 / invariant #6 in `wasm-worker-proxy`
    /// crate docs).
    Change {
        sub_id: SubId,
        path: String,
        new_entity: Option<WireEntity>,
    },
    /// Worker → main signal that the proxy's subscription is gone (worker
    /// restart, transport drop). Proxy responds by invalidating cache and
    /// re-establishing subscriptions.
    SubscriptionLost {
        sub_id: SubId,
        reason: String,
    },

    /// Worker → main marshalled substrate hook fact for `peer_id` (v9+).
    /// Routed by the proxy to inspect sinks registered on that peer.
    /// Default-off per peer; consumers flip it on via
    /// `Request::SetInspectEnabled` when the first sink attaches.
    ///
    /// Backpressure: shares the existing event channel; no per-Inspect
    /// flow control (§9 q4 — same regime as `Snapshot`/`Change`). Under
    /// sustained load consumers SHOULD detach the sink (which flips
    /// marshalling off) or filter inside `InspectSink::on_inspect`.
    Inspect {
        peer_id: String,
        fact: InspectFact,
    },
}

// ---------------------------------------------------------------------------
// InspectFact — marshalled equivalent of the in-process substrate hook
// events. See the upstream inspect-worker-arm design notes (§4.2)
// for field provenance.
//
// The marshal site in wasm-worker-host is the absorption layer per §9 q5:
// substrate field churn lands here only, not in consumer code.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "fact")]
pub enum InspectFact {
    /// From substrate `DispatchEvent` (`PeerBuilder::with_dispatch_hook`).
    /// Fires twice per dispatch — once at handler entry, once at exit.
    /// On entry, `status` is 0 and `response_hash`-derived fields are
    /// absent. On exit, `status` carries the V7 §8.3 status code.
    Dispatch {
        request_id: String,
        handler_uri: String,
        operation: String,
        /// V7 §8.3 status. `0` on entry (no outcome yet), nonzero on exit.
        status: u32,
        /// Wall-clock elapsed entry→exit; only meaningful on exit.
        /// `None` in v9 — substrate doesn't track this without state.
        /// Marshal site may begin filling this in once the substrate
        /// exposes it. See §9 q5.
        elapsed_micros: Option<u64>,
        /// Cascade `chain_id` from `ExecutionContext`. `None` in v9 —
        /// not surfaced on `DispatchEvent` today.
        chain_id: Option<String>,
    },
    /// From substrate `WireEvent` (`PeerBuilder::with_wire_hook`). Fires
    /// at the post-handshake frame boundary in both directions. Frame
    /// body is NOT carried — only the length — to keep wire chatter
    /// bounded (§9 q2 / §4.3). Body fetch is a deferred follow-on.
    Wire {
        direction: WireDirection,
        /// Remote peer's identity (base58 peer id) when known. Empty
        /// `peer_address` on the substrate event becomes `None`.
        peer_remote: Option<String>,
        /// Frame kind. V7.9 only ships EXECUTE / EXECUTE_RESPONSE on
        /// the wire post-handshake; marshal derives a label from
        /// `direction` ("execute" Recv, "execute_response" Send) until
        /// substrate exposes a richer discriminant.
        frame_kind: String,
        /// Length of the framed envelope in bytes.
        bytes: u32,
        /// Envelope `request_id`. `None` when the substrate event
        /// carries the empty string (pre-auth handshake leftovers in
        /// v1.0 substrate scope; rare post-fix).
        request_id: Option<String>,
    },
    /// From substrate `TreeChangeEvent` (`PeerBuilder::with_binding_hook`).
    /// Fires synchronously on every tree write at the binding-observer
    /// position.
    Binding {
        kind: BindingKind,
        path: String,
        /// Entity type, when the marshal site has it for free. `None`
        /// in v9 — would require a content-store lookup, deliberately
        /// skipped (§4.3 wire chatter discipline).
        entity_type: Option<String>,
        /// 66-char `Hash::to_hex` (33-byte wire form). `None` on
        /// `Deleted` (no new hash).
        content_hash: Option<String>,
        /// `true` for `ChangeType::Created`, `false` for
        /// `Modified`/`Deleted`.
        is_new: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireDirection {
    /// Frame received from the remote peer (substrate `WireDirection::Recv`).
    Inbound,
    /// Frame being sent to the remote peer (substrate `WireDirection::Send`).
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BindingKind {
    /// Created or Modified (`ChangeType::Created`/`Modified`). Distinguish
    /// via `InspectFact::Binding::is_new`.
    Put,
    /// `ChangeType::Deleted`.
    Remove,
    /// Snapshot / cache invalidate (reserved). The substrate hook surface
    /// (v1.0) does not emit these; included for forward compatibility
    /// with cache-layer marshal sites.
    Snapshot,
    CacheInvalidate,
}
