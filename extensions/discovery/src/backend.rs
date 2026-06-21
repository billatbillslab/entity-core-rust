//! The pluggable-backend seam (§1). A backend's only job is to *surface
//! observations* (and, for streaming backends, arrivals/departures) and to
//! *advertise self*. It knows nothing about candidates, decisions, grants, or
//! the tree — the [`DiscoveryHandler`](crate::handler::DiscoveryHandler) turns
//! raw [`Observation`]s into `system/discovery/candidate` entities (§2.1) and
//! mediates the §2 grant-prompt flow. v1 ships exactly one backend: mDNS
//! ([`crate::mdns`], native-only).

use entity_ecf::Value;

use crate::DiscoveryError;

/// A raw peer presence surfaced by a backend. The handler maps this to a
/// `CandidateData` (§2.1): `peer_id` may be `None` (null-until-IDENTIFY, §2.2),
/// `endpoint_hint` is the opaque dial info the backend assembled.
#[derive(Debug, Clone, PartialEq)]
pub struct Observation {
    /// A stable per-observation key (e.g. the mDNS service fullname). Used for
    /// the watchable tree path's `{candidate_id}` slot and for arrival/
    /// departure correlation. NOT part of the candidate entity.
    pub key: String,
    /// The peer's Base58 peer-id if the backend advertised one (mDNS
    /// `peer_id_hint` TXT key); `None` → TOFU null-until-IDENTIFY (§2.2).
    pub peer_id: Option<String>,
    /// Opaque dial hint assembled by the backend — for mDNS the resolved
    /// host/port + relevant TXT keys (§2.1 / §3.2).
    pub endpoint_hint: Value,
}

/// Streaming-backend signal for the watchable surface (§3.0): a candidate
/// arrived or departed. Snapshot-only backends never emit `Departed`.
#[derive(Debug, Clone, PartialEq)]
pub enum BackendEvent {
    Arrived(Observation),
    /// Departed — mDNS goodbye (TTL=0) or TTL-expiry reap (§3.0.1). Carries the
    /// observation `key` so the handler can remove the matching candidate.
    Departed { key: String },
}

/// What a peer advertises when it `:announce`s itself (§3). The backend maps
/// these semantic fields onto its wire form (for mDNS, the §3.2 TXT keys) —
/// DNS-SD specifics stay inside the backend.
#[derive(Debug, Clone)]
pub struct AnnounceParams {
    /// Transport profile-id to dial, per NETWORK §6.5 (§3.2 `profile_ref`,
    /// MUST-present). The handler also uses it as the announce-session key.
    pub profile_ref: String,
    /// The advertising peer's Base58 peer-id (§3.2 `peer_id_hint`); `None` when
    /// announcing anonymous-pre-IDENTIFY.
    pub peer_id: Option<String>,
    /// Advertised transport-types, comma-list (§3.2 optional `proto`).
    pub proto: Option<String>,
    /// User-facing label hint (§3.2 optional `display_name`).
    pub display_name: Option<String>,
    /// Port to advertise in the SRV record (§3.2). Backends without a port
    /// concept ignore it.
    pub port: u16,
}

/// A discovery backend (§1). Async because real backends do network I/O; the
/// wasm variant is `?Send` per the project's WASM handler discipline.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait DiscoveryBackend: Send + Sync {
    /// Backend discriminator — `"mdns"`, `"qr"`, … (matches `candidate.backend`).
    fn name(&self) -> &str;

    /// Time-boxed snapshot browse (§3.0 snapshot half). Returns the peers
    /// currently observed. Backends MUST NOT silently return empty on an
    /// unparseable `filter` — surface an error (§3.3); a genuinely empty
    /// network returns `Ok(vec![])`.
    async fn scan(&self, filter: Option<Value>) -> Result<Vec<Observation>, DiscoveryError>;

    /// Advertise self on the backend medium (§3 `:announce`). `profile_ref`
    /// keys the session for `:announce-stop`.
    async fn announce(&self, params: &AnnounceParams) -> Result<(), DiscoveryError>;

    /// End an announce session (§3 `:announce-stop`).
    async fn announce_stop(&self, profile_ref: &str) -> Result<(), DiscoveryError>;
}
