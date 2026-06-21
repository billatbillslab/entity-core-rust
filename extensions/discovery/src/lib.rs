//! EXTENSION-DISCOVERY v1.0 — the find-and-prompt substrate.
//!
//! REGISTRY (sibling [`entity_registry`]) answers "given a name, where is this
//! peer?". Discovery answers the complementary question — "what peers are out
//! there that I don't already know?" — and mediates the human decision to admit
//! them. Discovery never silently connects you to strangers: a backend
//! *surfaces a candidate*, the substrate *prompts*, and the user *decides*
//! (ignore / track / grant-limited / grant-more, §2). Admission is ordinary
//! capability machinery; discovery is the *initiator* of the grant, never the
//! *authority*.
//!
//! **This crate's current surface is the entity layer (§2.1 / §2.2.1):** the
//! `candidate`, `decision`, and `identity-claim` codecs plus the `:scan`
//! [`ScanResult`](data::ScanResult) envelope (§3). The mDNS v1 backend
//! (`:scan` / `:announce` / `:announce-stop`, the watchable
//! `system/discovery/candidate/{backend}/*` prefix, and the §3.0.1 reap rule)
//! follows once the cohort converges on Go's reference handler — the §3.2
//! DNS-SD wire constants pinned below are the cross-impl-divergence point that
//! gating closes.
//!
//! Spec: `../entity-core-architecture/docs/architecture/v7.0-core-revision/core-protocol-domain/specs/extensions/network-peer-extensions/EXTENSION-DISCOVERY.md`

pub mod backend;
pub mod data;
pub mod handler;
pub(crate) mod result;

/// The mDNS v1 backend — native-only (browsers cannot speak multicast UDP, §3.4).
#[cfg(not(target_arch = "wasm32"))]
pub mod mdns;

#[cfg(test)]
mod tests;

pub use backend::{AnnounceParams, BackendEvent, DiscoveryBackend, Observation};
pub use data::{CandidateData, DecisionData, IdentityClaimData, ScanResult};
pub use handler::DiscoveryHandler;

#[cfg(not(target_arch = "wasm32"))]
pub use mdns::MdnsBackend;

use entity_hash::Hash;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Capability surface (§4)
// ---------------------------------------------------------------------------

/// Who may run discovery scans on this peer (§4).
pub const CAP_DISCOVERY_SCAN: &str = "system/capability/discovery-scan";
/// Who may `:announce` / `:announce-stop` on this peer (§4).
pub const CAP_DISCOVERY_ANNOUNCE: &str = "system/capability/discovery-announce";

/// The two caps the seed-policy grants the local peer on first install (§4.1):
/// without them the user cannot scan their own network or announce themselves.
/// There is by construction **no** "discovery grants access" cap — admission is
/// the §2 user decision only.
pub const DISCOVERY_SEED_CAPS: &[&str] = &[CAP_DISCOVERY_SCAN, CAP_DISCOVERY_ANNOUNCE];

// ---------------------------------------------------------------------------
// Outcome vocabulary (§2 / §2.1 decision.outcome)
// ---------------------------------------------------------------------------

/// Discard the candidate: no connection, no tracking. Default-safe (§2).
pub const OUTCOME_IGNORE: &str = "ignore";
/// Remember the peer exists; no grant, no connection authority yet (§2).
pub const OUTCOME_TRACK: &str = "track";
/// Admit with a narrow, explicit capability (§2).
pub const OUTCOME_GRANT_LIMITED: &str = "grant-limited";
/// Later, deliberately widen the grant (§2).
pub const OUTCOME_GRANT_MORE: &str = "grant-more";

// ---------------------------------------------------------------------------
// Backends (§3 / §6)
// ---------------------------------------------------------------------------

/// The first and only v1 backend — mDNS / zero-config multicast (§3).
pub const BACKEND_MDNS: &str = "mdns";

// ---------------------------------------------------------------------------
// Resource-bound code (§3.1) — DISCOVERY's own code domain (V7 §3.3)
// ---------------------------------------------------------------------------

/// `:scan` per-call candidate-count ceiling exceeded (§3.1). Surfaced in
/// [`ScanResult`](data::ScanResult) as `truncated: true` + this code; HTTP-status
/// 503. NOT a V7 §4.10 floor code — per-scan-count ceilings are an
/// application-layer concern, so this lives in DISCOVERY's own code domain.
pub const CODE_SCAN_OVERFLOW: &str = "discovery_scan_overflow";

/// Default per-scan candidate-count ceiling (§3.1, informative). Deployments
/// configure per network size.
pub const DEFAULT_SCAN_CEILING: usize = 1024;

// ---------------------------------------------------------------------------
// mDNS DNS-SD wire-interop pins (§3.2) — cohort-convergence point
// ---------------------------------------------------------------------------
//
// These constants are normative per §3.2: the cross-impl-divergence class that
// fails *silently* (Go and Rust never see each other on the LAN if they
// differ; no error to catch). Pinned here as the shared reference so the mDNS
// backend (post-cohort-convergence) and any binding speak identical wire.

/// DNS-SD service-type for entity-core mDNS discovery (§3.2, RFC 6763 §7).
pub const MDNS_SERVICE_TYPE: &str = "_entity-core._udp.local.";

/// MUST-present TXT key: DISCOVERY major version (§3.2). Value is `"1"`.
pub const TXT_KEY_VERSION: &str = "version";
/// Current DISCOVERY major version advertised in the `version` TXT key.
pub const MDNS_VERSION: &str = "1";
/// MUST-present TXT key: the advertising peer's Base58 peer-id (§3.2). MAY be
/// omitted when announcing anonymous-pre-IDENTIFY.
pub const TXT_KEY_PEER_ID_HINT: &str = "peer_id_hint";
/// MUST-present TXT key: the transport profile-id to dial, per NETWORK §6.5
/// `system/peer/transport/{peer}/{profile-id}` namespace (§3.2).
pub const TXT_KEY_PROFILE_REF: &str = "profile_ref";
/// OPTIONAL TXT key: advertised transport-types, comma-list (§3.2).
pub const TXT_KEY_PROTO: &str = "proto";
/// OPTIONAL TXT key: user-facing label hint, UTF-8 (§3.2).
pub const TXT_KEY_DISPLAY_NAME: &str = "display_name";

// ---------------------------------------------------------------------------
// Storage paths
// ---------------------------------------------------------------------------

/// Live watchable candidate surface for a backend (§3.0): handlers write/remove
/// `system/discovery/candidate/{backend}/{candidate_id}` here as peers arrive
/// and depart; live consumers subscribe to this prefix for add/remove events.
pub fn candidate_prefix(peer_id: &str, backend: &str) -> String {
    format!("/{}/system/discovery/candidate/{}/", peer_id, backend)
}

/// Tree path for a single live candidate (§3.0). `candidate_id` is the
/// backend's stable per-candidate identifier (the candidate entity's content
/// hash hex in practice).
pub fn candidate_path(peer_id: &str, backend: &str, candidate_id: &str) -> String {
    format!(
        "/{}/system/discovery/candidate/{}/{}",
        peer_id, backend, candidate_id
    )
}

/// Durable decision-audit path (§7): `system/discovery/decision/{hex}`.
pub fn decision_path(peer_id: &str, hash: &Hash) -> String {
    format!("/{}/system/discovery/decision/{}", peer_id, hash.to_hex())
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("discovery entity decode failed: {0}")]
    Decode(String),
    #[error("discovery entity encode failed: {0}")]
    Encode(String),
    #[error("invalid discovery request: {0}")]
    Invalid(String),
    /// Backend / transport failure (e.g. mDNS daemon error).
    #[error("discovery backend error: {0}")]
    Backend(String),
    /// No backend registered for the requested `backend` discriminator — e.g.
    /// `:scan(backend=mdns)` on wasm32 where multicast is unavailable (§3.4).
    #[error("unsupported discovery backend: {0}")]
    UnsupportedBackend(String),
}
