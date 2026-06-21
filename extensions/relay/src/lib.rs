//! EXTENSION-RELAY v1.0 — the opaque-envelope transport substrate.
//!
//! A relay carries opaque, signed, capability-bearing envelopes between two
//! endpoints. The origin's capability chain passes through **unchanged**; the
//! relay is transport, never authority (`ANALYSIS-RELAY-CAPABILITY-CHAIN.md`).
//! There is no V7 amendment and no new substrate primitive — RELAY composes
//! from existing dispatch, signature-verify, and capability machinery.
//!
//! v1 ships two of the four named modes (§1):
//! - **Mode F — Forward** (`:forward`): active forwarding toward a destination,
//!   with a relay-transport `ttl_hops` budget and the §3.1.1 terminal-vs-
//!   intermediate dispatch shape. Unreachable destinations fall back to Mode S
//!   (§6.2.1).
//! - **Mode S — Store-and-poll** (`:put` / `:poll`): passive intermediary;
//!   sender PUTs an entry at a namespace, receiver polls. Relay-owned cursor
//!   and ordering (NOT INBOX's — §6.1).
//!
//! Both modes plus `:advertise` are part of the v1 conformance floor (§10.1);
//! a *deployment* MAY enable any subset, but the *implementation* must support
//! both.
//!
//! **The central transport invariant (§9):** the carried *inner envelope* is
//! held as opaque content-addressed bytes and is **never decoded, re-encoded,
//! or substituted** in the forward/store path. Only the *relay envelope*
//! (`forward-request` / `store-entry`) is decoded — that is how the relay reads
//! its outer routing fields. See [`handler`] for how this is preserved through
//! the Rust dispatch layer (the inner rides as an `Entity` whose `data` the
//! wire codec preserves byte-for-byte).
//!
//! Spec: `../entity-core-architecture/docs/architecture/v7.0-core-revision/core-protocol-domain/specs/extensions/network-peer-extensions/EXTENSION-RELAY.md`

pub mod data;
pub mod forwarder;
pub mod handler;
pub mod resolver;
pub(crate) mod result;
pub mod store;

#[cfg(test)]
mod tests;

pub use data::{
    AdvertiseData, ForwardRequest, ForwardResult, InboxRelayData, InboxRelayEntry, PollRequest,
    PollResult, PutResult, StoreEntry,
};
pub use forwarder::{ForwardOutcome, RelayForwarder};
pub use handler::RelayHandler;
pub use resolver::{InboxRelayResolver, NopInboxRelayResolver, TreeInboxRelayResolver};
pub use store::{ModeStore, StoredEntry};

use thiserror::Error;

// ---------------------------------------------------------------------------
// Modes (§1 / §2)
// ---------------------------------------------------------------------------

/// Mode F — active forwarding peer (§1).
pub const MODE_FORWARD: &str = "F";
/// Mode S — passive store-and-poll intermediary (§1).
pub const MODE_STORE: &str = "S";

// ---------------------------------------------------------------------------
// Capability surface (§5.2) — ordinary handler caps, each rooting at the relay.
// ---------------------------------------------------------------------------

/// Mode F — may forward envelopes through this relay (§5.2).
pub const CAP_RELAY_FORWARD: &str = "system/capability/relay-forward";
/// Mode S — may put entries at a namespace (§5.2).
pub const CAP_RELAY_PUT: &str = "system/capability/relay-put";
/// Mode S — may poll a namespace (§5.2).
pub const CAP_RELAY_POLL: &str = "system/capability/relay-poll";
/// All — may publish the advertise entity (typically operator-only) (§5.2).
pub const CAP_RELAY_ADVERTISE: &str = "system/capability/relay-advertise";

/// Operator-side caps a peer running a relay seeds for itself on first install
/// so it can drive its own relay (put/poll/forward/advertise on its own peer).
/// This is the local-operator floor; the cross-peer **self-poll default grant**
/// (§5.5 — every requesting peer P may poll namespace = P) is a separate,
/// per-caller grant installed at the relay wiring layer.
pub const RELAY_SEED_CAPS: &[&str] = &[
    CAP_RELAY_FORWARD,
    CAP_RELAY_PUT,
    CAP_RELAY_POLL,
    CAP_RELAY_ADVERTISE,
];

// ---------------------------------------------------------------------------
// Error taxonomy (§4.3) — RELAY's own code domain (V7 §3.3). Statuses reuse
// the V7 floor where one exists; relay-owned codes cover conditions V7 has no
// floor for. All ops are fail-closed: on any error the op performs no partial
// effect (no forward, no store, no dequeue).
// ---------------------------------------------------------------------------

/// `ttl_hops` reached 0 on receipt — 400, forward (§4.3).
pub const CODE_TTL_EXHAUSTED: &str = "ttl_exhausted";
/// No source route, no `next_hop`, and no route-table match / destination not
/// directly reachable — 502, forward (§3.1.1 / §4.3).
pub const CODE_NO_ROUTE: &str = "no_route";
/// `route` and `next_hop` both set but `next_hop ≠ route[0]` — 400, forward,
/// rejected **pre-dispatch** before any hop (§3.1.1 / §4.3).
pub const CODE_INVALID_REQUEST: &str = "invalid_request";
/// Exceeds advertised `forward_rate_limit` — 429, forward (§4.3, SHOULD).
pub const CODE_RATE_LIMITED: &str = "rate_limited";
/// Malformed namespace path — 400, put/poll (§4.3).
pub const CODE_NAMESPACE_INVALID: &str = "namespace_invalid";
/// Namespace not provisioned — 404, poll (provisioning deployments only;
/// empty ≠ not-found, §4.2) (§4.3).
pub const CODE_NAMESPACE_NOT_FOUND: &str = "namespace_not_found";
/// Exceeds advertised `max_storage_bytes` — 507, put (§4.3).
pub const CODE_STORAGE_FULL: &str = "storage_full";
/// `expires_at` already past at put time — 400 (creation-side dead-on-arrival,
/// NOT 410 Gone — §4.3 rationale), put.
pub const CODE_EXPIRED_ON_ARRIVAL: &str = "expired_on_arrival";
/// `store-entry.put_by` ≠ authenticated caller — 400, put (§3.2 / §4.3).
pub const CODE_PUT_BY_MISMATCH: &str = "put_by_mismatch";
/// Destination unreachable AND declared no inbox-relay AND the default
/// convention is not usable — 502, forward (§3.5 / §4.3 / §9.5). Fail-closed;
/// only the explicit "MX-required" posture (default-fallback disabled) returns
/// this. Never a silent drop.
pub const CODE_NO_INBOX_RELAY: &str = "no_inbox_relay";
/// Standard malformed-request code for relay request decode failures.
pub const CODE_INVALID_PARAMS: &str = "invalid_params";
/// Unknown relay operation.
pub const CODE_UNKNOWN_OPERATION: &str = "unknown_operation";

// ---------------------------------------------------------------------------
// Forward-result status strings (§4.2)
// ---------------------------------------------------------------------------

/// The envelope was forwarded toward the destination (§4.2).
pub const FORWARD_STATUS_FORWARDED: &str = "forwarded";
/// The destination had no live session; the relay fell back to Mode S and
/// stored the entry at the destination's peer-id namespace (§6.2.1).
pub const FORWARD_STATUS_QUEUED_FALLBACK: &str = "queued-fallback";
/// The forward was rejected (e.g. policy) without a fallback (§4.2).
pub const FORWARD_STATUS_REJECTED: &str = "rejected";

// ---------------------------------------------------------------------------
// Storage paths
// ---------------------------------------------------------------------------

/// The Mode-S store subtree for a namespace (§3.2 / §6.1):
/// `system/relay/store/{namespace}/`. The relay owns this subtree; `:poll` is
/// a relay-owned enumeration over it.
pub fn store_prefix(peer_id: &str, namespace: &str) -> String {
    format!("/{}/system/relay/store/{}/", peer_id, namespace)
}

/// Tree path for a single stored entry (§3.2):
/// `system/relay/store/{namespace}/{hash}`.
pub fn store_entry_path(peer_id: &str, namespace: &str, entry_hash_hex: &str) -> String {
    format!(
        "/{}/system/relay/store/{}/{}",
        peer_id, namespace, entry_hash_hex
    )
}

/// Tree path for the opaque inner envelope (§3.2, per the relay
/// receive-side fetch-surface ruling):
/// `system/relay/store/{namespace}/inner/{inner_hash}`. Nested under the **same**
/// namespace subtree as the store-entry so a single namespace-scoped tree-read
/// cap (§5) governs both post-poll fetches. `system/content` is NOT a relay
/// receive-side dependency: the receiver reads the inner with `tree:get` on this
/// path. Tree-binding is path→hash (PRIMER #1); the inner's bytes live once in
/// the content store, so two namespaces pointing at the same inner is dedup, not
/// duplication. Mirrors Go's `RelayInnerPath`.
pub fn inner_store_path(peer_id: &str, namespace: &str, inner_hash_hex: &str) -> String {
    format!(
        "/{}/system/relay/store/{}/inner/{}",
        peer_id, namespace, inner_hash_hex
    )
}

/// The advertise entity path (§4.1): `system/relay/advertise/{relay_peer_id}`.
pub fn advertise_path(peer_id: &str, relay_peer_id: &str) -> String {
    format!("/{}/system/relay/advertise/{}", peer_id, relay_peer_id)
}

/// The §3.5 inbox-relay declaration path for a peer:
/// `system/peer/inbox-relay/{peer_id}`. Mirrors Go's `InboxRelayStoragePath`.
/// Returned as the bare logical path (the universal-namespace form REGISTRY and
/// any always-on holder serve); a local tree stores it under
/// `/{local_pid}/system/peer/inbox-relay/{peer_id}`.
pub fn inbox_relay_path(peer_id: &str) -> String {
    format!("system/peer/inbox-relay/{}", peer_id)
}

// ---------------------------------------------------------------------------
// Namespace validation (§4.3 `namespace_invalid`)
// ---------------------------------------------------------------------------

/// A namespace MUST be a non-empty path segment sequence with no leading/
/// trailing slash, no empty segments, and no `.`/`..` traversal — it is
/// interpolated directly into the store subtree path (§3.2), so a malformed
/// value would escape the relay's namespace addressing. The destination
/// peer-id used as a fallback rendezvous namespace (§6.2.1) is a Base58 string
/// and passes trivially.
pub fn is_valid_namespace(ns: &str) -> bool {
    if ns.is_empty() || ns.starts_with('/') || ns.ends_with('/') {
        return false;
    }
    ns.split('/').all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("relay entity decode failed: {0}")]
    Decode(String),
    #[error("relay entity encode failed: {0}")]
    Encode(String),
    #[error("invalid relay request: {0}")]
    Invalid(String),
}
