//! Mode F outbound-delivery seam (§3.1.1, §6.2.1).
//!
//! The [`RelayHandler`](crate::RelayHandler) owns the relay *logic* — `ttl_hops`
//! decrement and reject-at-zero, the terminal-vs-intermediate decision,
//! envelope opacity, and the Mode-S fallback — but actual network delivery is
//! delegated to an injected [`RelayForwarder`]. This keeps the relay extension
//! depending only on `core/*` (DAG discipline): the concrete forwarder that
//! touches the connection pool is wired in `core/peer`, where transport lives.
//!
//! **Envelope opacity is a hard contract on this seam (§9 / §10.4).** The
//! forwarder receives the inner envelope as an opaque [`Entity`] whose `data`
//! the wire codec preserves byte-for-byte. The forwarder MUST NOT decode,
//! re-encode, or substitute those bytes:
//! - **Intermediate hop:** carry the (ttl-decremented) `forward-request` to
//!   `next_hop` with the *same* inner entity in the outbound `included` set.
//! - **Terminal hop:** deliver the **bare inner envelope** to the destination
//!   as a normal inbound EXECUTE — exactly the bytes a direct connection would
//!   have carried. The destination needs no RELAY extension to receive it.
//!
//! When no forwarder is injected, the handler treats every destination as
//! unreachable and takes the §6.2.1 Mode-S fallback — the fully-local floor
//! that needs no live transport (and exercises the fallback conformance
//! vector).

use entity_entity::Entity;

/// The outcome of an attempted Mode-F delivery.
#[derive(Debug, Clone, PartialEq)]
pub enum ForwardOutcome {
    /// Delivered toward the destination via `next_hop` (terminal hop:
    /// `next_hop == destination`). Maps to `forward-result {status: forwarded}`.
    Forwarded { next_hop: String },
    /// No live session/route to the destination. The handler stores the inner
    /// envelope via the Mode-S fallback at the destination's peer-id namespace
    /// and returns `forward-result {status: queued-fallback}` (§6.2.1).
    Unreachable,
}

/// What the forwarder needs to deliver one hop. The inner envelope is opaque.
///
/// The handler is the single place that determines routing (the §3.1.1 per-hop
/// algorithm — source route / `next_hop` / route table); the forwarder only
/// transmits the determined hop. For an **intermediate** hop the handler hands
/// over the already-popped onward path in [`ForwardCtx::onward_route`] so the
/// forwarder re-encodes the outbound `forward-request` without re-deriving any
/// routing decision.
pub struct ForwardCtx<'a> {
    /// Terminal recipient — Base58 peer-id (§3.0).
    pub destination: &'a str,
    /// Resolved next hop to dial — Base58 peer-id (the handler computed it).
    pub next_hop: &'a str,
    /// True when `next_hop` resolves to `destination` itself — deliver the bare
    /// inner envelope (§3.1.1). False → forward a `forward-request` onward.
    pub is_terminal: bool,
    /// The `ttl_hops` value to carry onward (already decremented for this hop).
    pub ttl_hops: u32,
    /// **v1.1 source route, head already popped** (§3.1.1): the `route'` slice
    /// the intermediate-hop `forward-request` MUST carry (`route[1:]`). Empty for
    /// a single-hop / `next_hop`-only / table-routed hop. The forwarder sets the
    /// outbound `route` to this and `next_hop'` to its first element (or none),
    /// so a downstream receiver that reads `next_hop` first still resolves
    /// (cross-impl trap #3). Ignored on the terminal hop.
    pub onward_route: &'a [String],
    /// The opaque inner envelope — `data` is the raw inner bytes; MUST NOT be
    /// decoded/re-encoded (§9).
    pub inner: &'a Entity,
}

/// Pluggable outbound delivery for Mode F. Implemented in `core/peer` over the
/// connection pool; absent → handler falls back to Mode S (§6.2.1).
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait RelayForwarder: Send + Sync {
    async fn forward(&self, ctx: ForwardCtx<'_>) -> ForwardOutcome;
}
