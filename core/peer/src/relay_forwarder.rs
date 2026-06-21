//! `PeerRelayForwarder` — the live wiring of EXTENSION-RELAY's `RelayForwarder`
//! seam (§3.1.1, §6.2.1) over `core/peer`'s outbound connection pool.
//!
//! The RELAY handler owns the relay *logic* (ttl decrement, terminal-vs-
//! intermediate decision, §6.2.1 fallback); this type is the injected
//! transport that actually delivers a hop. Installing it flips the relay from
//! the conservative Mode-S-only posture (every destination "unreachable" →
//! fallback) to live Mode-F delivery, falling back only when the next hop
//! genuinely can't be reached.
//!
//! **§3.1.1 raw-frame is the central invariant.** At the terminal hop the
//! relay writes the opaque inner envelope's bytes **verbatim** into the
//! destination's inbound frame — exactly the bytes a direct connection would
//! have carried. We never decode-then-re-encode the inner: a decode/re-encode
//! round-trip is byte-identical only for ECF-canonical inputs and §3.1.1
//! promises *exactness*, and the inner MAY be opaque-to-us (e.g. encrypted).
//! The destination verifies the inner envelope's own signature + capability
//! chain (§5.1) and needs no RELAY extension installed merely to receive — so
//! the relay must NOT re-sign or re-wrap. We read just the inner's embedded
//! `request_id` (to demux the destination's EXECUTE_RESPONSE), never its
//! payload, and we send `inner.data` byte-for-byte.
//!
//! This deliberately diverges from the decode-then-redispatch model the Go
//! reference + shared validator still implement (the relay re-signs the inner
//! under its own identity). §3.1.1 ratified raw-frame as correct and resolved
//! the divergence in raw-frame's favor; see `docs/SPEC-AMBIGUITIES.md`
//! (RELAY §3.1.1 terminal-hop).

use std::collections::HashMap;
use std::sync::Arc;

use entity_crypto::IdentityKeypair;
use entity_ecf::Value;
use entity_entity::Entity;
use entity_relay::data::ForwardRequest;
use entity_relay::forwarder::{ForwardCtx, ForwardOutcome, RelayForwarder};
use entity_store::{ContentStore, LocationIndex};
use entity_wire::decode_envelope;

use crate::remote::{get_or_connect, send_execute, RemoteState};
use crate::transport::Connector;

/// Live Mode-F delivery over the peer's connection pool. Holds its own
/// outbound pool (the peer mints a fresh `RemoteState` per `shared()`
/// snapshot, so there is no single canonical pool to borrow) and the
/// resolution surface `get_or_connect` needs — the same content store /
/// location index the peer uses, so published transport profiles
/// (`system/peer/transport/...`) resolve identically.
pub struct PeerRelayForwarder {
    pool: RemoteState,
    keypair: IdentityKeypair,
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    connector: Arc<dyn Connector>,
    local_peer_id: String,
    home_format: u8,
}

impl PeerRelayForwarder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        keypair: IdentityKeypair,
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        connector: Arc<dyn Connector>,
        local_peer_id: String,
        home_format: u8,
    ) -> Self {
        Self {
            pool: RemoteState::new(),
            keypair,
            content_store,
            location_index,
            connector,
            local_peer_id,
            home_format,
        }
    }
}

/// Read the `request_id` embedded in the inner envelope's root EXECUTE — the
/// demux key for the destination's EXECUTE_RESPONSE. Reads only this routing
/// field; the inner bytes are still delivered verbatim (§3.1.1). Returns
/// `None` if the inner is not a decodable `{root, included}` envelope whose
/// root carries a `request_id` (e.g. malformed, or opaque/encrypted to us).
fn extract_request_id(inner: &Entity) -> Option<String> {
    let env = decode_envelope(&inner.data).ok()?;
    let v: Value = ciborium::from_reader(env.root.data.as_slice()).ok()?;
    let map = v.as_map()?;
    map.iter().find_map(|(k, val)| {
        if k.as_text() == Some("request_id") {
            val.as_text().map(|s| s.to_string())
        } else {
            None
        }
    })
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl RelayForwarder for PeerRelayForwarder {
    async fn forward(&self, ctx: ForwardCtx<'_>) -> ForwardOutcome {
        // Resolve a connection to the next hop. Terminal hop: next_hop ==
        // destination, so this is a connection to the destination itself.
        // Intermediate hop: next_hop is the next RELAY peer. A connect/dial
        // failure is exactly the §6.2.1 "unreachable" trigger.
        let conn = match get_or_connect(
            &self.pool,
            ctx.next_hop,
            &self.keypair,
            self.content_store.as_ref(),
            self.location_index.as_ref(),
            &self.local_peer_id,
            self.connector.as_ref(),
            self.home_format,
            // The relay forwarder holds no local dispatch stack (it carries
            // RemoteState pieces, not a PeerShared) and never acts as a
            // reentry delivery target — next-hop connections are pure
            // request/response forwards. Response-only reader is correct.
            None,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(
                    next_hop = %ctx.next_hop,
                    error = %e,
                    "relay forward: next hop unreachable; taking §6.2.1 fallback"
                );
                return ForwardOutcome::Unreachable;
            }
        };

        if ctx.is_terminal {
            // §3.1.1 terminal hop — raw-frame. Write the inner envelope's
            // bytes verbatim as a normal inbound EXECUTE to the destination.
            let Some(request_id) = extract_request_id(ctx.inner) else {
                // No correlatable request_id → we can't demux the response,
                // and an inner we can't even read the routing of is not a
                // deliverable v1 envelope. Fall back rather than blindly
                // writing bytes we can't confirm landed.
                tracing::warn!(
                    destination = %ctx.destination,
                    "relay terminal hop: inner envelope has no readable request_id; \
                     taking §6.2.1 fallback"
                );
                return ForwardOutcome::Unreachable;
            };

            match conn.dispatch_raw(request_id, ctx.inner.data.clone()).await {
                // Any EXECUTE_RESPONSE — even an error status from the
                // destination — means the bytes landed and were processed.
                // The relay does not interpret the inner response (§5.1
                // transparency): an auth/permission rejection at the
                // destination is between author and destination, not a relay
                // concern. Only a transport failure is "unreachable".
                Ok(_resp) => ForwardOutcome::Forwarded {
                    next_hop: ctx.next_hop.to_string(),
                },
                Err(e) => {
                    self.pool.remove(ctx.next_hop);
                    tracing::debug!(
                        destination = %ctx.destination,
                        error = %e,
                        "relay terminal delivery failed mid-flight; taking §6.2.1 fallback"
                    );
                    ForwardOutcome::Unreachable
                }
            }
        } else {
            // Intermediate hop (§3.1.1) — forward the (ttl-decremented)
            // forward-request to `next`'s RELAY, carrying the opaque inner
            // verbatim in the outbound `included` set so the next relay can
            // address + forward it. The handler already popped the source-route
            // head into `ctx.onward_route` (= route[1:]); we set `route' =
            // onward_route` and `next_hop' = onward_route[0]` (or None). When
            // `onward_route` is empty (a bare `next_hop` hop, or a table-routed
            // forward), both drop via omitempty and the next relay resolves
            // afresh from its own next_hop/table — exactly the cohort's pop-head
            // shape (cross-impl trap #3: next_hop' MUST be populated so a
            // downstream receiver reading next_hop first still resolves).
            let onward_route = ctx.onward_route.to_vec();
            let next_hop_prime = onward_route.first().cloned();
            let fr = ForwardRequest {
                destination: ctx.destination.to_string(),
                route: (!onward_route.is_empty()).then_some(onward_route),
                next_hop: next_hop_prime,
                ttl_hops: ctx.ttl_hops,
                envelope_inner: ctx.inner.content_hash,
            };
            let fr_entity = match fr.to_entity() {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(error = %e, "relay intermediate hop: encode forward-request failed");
                    return ForwardOutcome::Unreachable;
                }
            };
            let uri = format!("/{}/system/relay", ctx.next_hop);
            let mut included = HashMap::new();
            included.insert(ctx.inner.content_hash, ctx.inner.clone());

            match send_execute(
                conn.as_ref(),
                &self.keypair,
                &uri,
                "forward",
                &fr_entity,
                None,
                None,
                None,
                &included,
            )
            .await
            {
                Ok(_resp) => ForwardOutcome::Forwarded {
                    next_hop: ctx.next_hop.to_string(),
                },
                Err(e) => {
                    self.pool.remove(ctx.next_hop);
                    tracing::debug!(
                        next_hop = %ctx.next_hop,
                        error = %e,
                        "relay intermediate forward failed; taking §6.2.1 fallback"
                    );
                    ForwardOutcome::Unreachable
                }
            }
        }
    }
}
