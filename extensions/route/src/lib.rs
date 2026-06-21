//! EXTENSION-ROUTE v1.0 — the routing-table **storage plane**.
//!
//! ROUTE holds a peer's routing table — a set of `system/route` entities saying
//! *"to reach destination D, the next hop is N (or D is direct)."* That is the
//! whole job. ROUTE **stores** routes (the [`RouteData`] entity, tree-bound at
//! [`route_path`]) and defines how the table is **read** (the [`resolve`] match,
//! §3); it does **not** compute routes, does **not** decide how the table is
//! populated, and owns **no** resolver registry (§1).
//!
//! Three clean roles along seams that already exist:
//! - **Store** — this crate (the `system/route` entities; cap-scoped via the
//!   tree handler; signed per V7 §5.2).
//! - **Consume** — `EXTENSION-RELAY` (`entity_relay`): when a `forward-request`
//!   has no source route and no `next_hop`, the relay reads the local table and
//!   applies [`resolve`] to pick the next hop (RELAY §3.1.1 source 3).
//! - **Produce** — the peer / DISCOVERY / GOSSIP. Out of scope here. ROUTE
//!   accepts cap-gated writes (the [`CAP_ROUTE_CONFIGURE`] cap) and stops there.
//!
//! There is no `system/route` *handler* in v1 — writes go through the standard
//! `tree:put` (cap-scoped per path), and reads are the relay's substrate-internal
//! local-tree enumeration. The runtime surface this crate exposes is therefore
//! the entity codec + path helpers + the pure [`resolve`] match function the
//! relay calls; no operations, no dispatch.
//!
//! **Deferred (named, not built, §4):** route *production* (DHT/gossip/link-state)
//! and the *computed-routing* `resolve_next_hop` escape hatch. A static stored
//! table cannot express a computed next-hop; that — and only that — is where a
//! pluggable in-process resolver would earn its place. v1 ships the stored table
//! only (LAN/VPN/gateway need nothing more).
//!
//! Spec: `../entity-core-architecture/docs/architecture/v7.0-core-revision/core-protocol-domain/specs/extensions/network-peer-extensions/EXTENSION-ROUTE.md`

use entity_ecf::{integer, text, to_ecf, Value};
use entity_entity::Entity;
use entity_hash::Hash;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Constants (§2, §3, §5)
// ---------------------------------------------------------------------------

/// The `system/route` entity type slug (§2).
pub const TYPE_ROUTE: &str = "system/route";

/// `action = "deliver"` — terminal hop; deliver locally (the local relay IS the
/// terminal). `via` MUST be empty (§2).
pub const ROUTE_ACTION_DELIVER: &str = "deliver";
/// `action = "forward"` — one-hop intermediate; forward to `via` (§2). `via` is
/// REQUIRED.
pub const ROUTE_ACTION_FORWARD: &str = "forward";

/// The default-route `match` token (§2/§3). The literal string `"*"` —
/// `primitive/string`, **NOT** a peer-id (cross-impl trap: do not decode it as
/// one). Exact `match` outranks this default on ties (§3).
pub const ROUTE_MATCH_DEFAULT: &str = "*";

/// `route-configure` (§5) — the only cap ROUTE defines; guards who may write/
/// expire `system/route/*` entities. Reads need no extra caller cap (the relay's
/// local-tree read is substrate-internal; the per-hop `relay-forward` cap is the
/// network-level authority bound). Full V7 capability-pattern form.
pub const CAP_ROUTE_CONFIGURE: &str = "system/capability/route-configure";

/// The route subtree listing prefix the relay enumerates, relative to a peer
/// root. Combined with the peer prefix by the consumer:
/// `/{peer_id}/system/route/`. Trailing slash matches `LocationIndex::list`
/// (returns every leaf under the prefix).
pub const ROUTE_PREFIX: &str = "system/route/";

// ---------------------------------------------------------------------------
// §2 — the route entity
// ---------------------------------------------------------------------------

/// A single routing-table entry (`system/route`, §2). Tree-bound at
/// [`route_path`]; signed by the configuring authority per V7 §5.2 (signature at
/// the invariant pointer; no `refs:` block).
///
/// **Cross-field invariant** (§2): `action == "forward"` REQUIRES a non-empty
/// `via`; `action == "deliver"` REQUIRES an empty `via`. A route violating this
/// is silently skipped by [`resolve`] (it never matches).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteData {
    /// The destination this route covers — a Base58 peer-id, or
    /// [`ROUTE_MATCH_DEFAULT`] (`"*"`) for the default route (§2).
    pub match_dest: String,
    /// `"deliver"` | `"forward"` (§2).
    pub action: String,
    /// REQUIRED iff `action == "forward"` — the next-hop peer-id (Base58).
    /// `None`/empty == absent (§2).
    pub via: Option<String>,
    /// Lower wins on ties when multiple routes match. `0` == null/unspecified
    /// (§2 "null = 0").
    pub metric: u32,
    /// ms since epoch; `0` == null (until superseded). A route already past at
    /// match time is skipped (§3). Held as `i64` to compare against `now_ms`.
    pub expires_at: i64,
}

impl RouteData {
    pub fn from_entity(entity: &Entity) -> Result<Self, RouteError> {
        if entity.entity_type != TYPE_ROUTE {
            return Err(RouteError::Decode(format!(
                "expected {}, got {}",
                TYPE_ROUTE, entity.entity_type
            )));
        }
        Self::from_params(&entity.data)
    }

    pub fn from_params(data: &[u8]) -> Result<Self, RouteError> {
        let map = decode_map(data)?;
        Ok(Self {
            match_dest: field_text(&map, "match")?,
            action: field_text(&map, "action")?,
            via: field_text_opt(&map, "via").filter(|s| !s.is_empty()),
            metric: field_u64_opt(&map, "metric").unwrap_or(0) as u32,
            expires_at: field_i64_opt(&map, "expires_at").unwrap_or(0),
        })
    }

    pub fn to_entity(&self) -> Result<Entity, RouteError> {
        // ECF canonicalizes key order, so insertion order is for readability.
        let mut fields = vec![
            (text("action"), text(&self.action)),
            (text("match"), text(&self.match_dest)),
        ];
        // omitempty: drop `via`/`metric`/`expires_at` when empty/zero so a route
        // round-trips byte-identically to the minimal authored form.
        if let Some(via) = self.via.as_deref().filter(|s| !s.is_empty()) {
            fields.push((text("via"), text(via)));
        }
        if self.metric != 0 {
            fields.push((text("metric"), integer(self.metric as i64)));
        }
        if self.expires_at != 0 {
            fields.push((text("expires_at"), integer(self.expires_at)));
        }
        let data = to_ecf(&Value::Map(fields));
        Entity::new(TYPE_ROUTE, data).map_err(|e| RouteError::Encode(e.to_string()))
    }
}

/// Canonical tree path for a route entity (§2): `system/route/{content_hash_hex}`.
/// The id segment is the lowercase hex of the route entity's **canonical** hash
/// bytes (algorithm byte + effective digest) via [`Hash::to_hex`] — NOT a
/// fixed-width padded digest, which would produce a non-canonical 130-char path
/// with trailing zeros under SHA-256 (cross-impl trap #1). Returned as the bare
/// logical path; a local tree stores it under `/{peer_id}/system/route/{hex}`.
pub fn route_path(route_hash: &Hash) -> String {
    format!("{}/{}", TYPE_ROUTE, route_hash.to_hex())
}

// ---------------------------------------------------------------------------
// §3 — how relay reads the table (the match + precedence)
// ---------------------------------------------------------------------------

/// The outcome of a successful table match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteResolution {
    /// `action = "deliver"` — terminal at this relay (`next == destination`).
    Deliver,
    /// `action = "forward"` — forward one hop to this peer-id (`via`).
    Forward(String),
}

/// Apply the §3 documented match over an already-decoded set of route entities,
/// for `destination` at time `now_ms`. ROUTE defines the semantics; the relay
/// performs the read (enumerate the local subtree, decode each `system/route`,
/// then call this). Returns `None` on no match → the relay surfaces
/// `no_route`/502 (or its §6.2.1 Mode-S fallback first).
///
/// Match (§3):
/// 1. Gather routes whose `match` is exactly `destination` or `"*"`, not expired.
/// 2. A `forward` route with no `via`, or a `deliver` route with a `via`, is
///    skipped (the §2 cross-field invariant; an invalid route never matches).
/// 3. **Exact `match` outranks the `"*"` default** (longest-match-wins,
///    degenerate over a flat peer-id space); within the same cohort, **lowest
///    `metric` wins** (`metric: 0` = unspecified).
/// 4. `deliver` → [`RouteResolution::Deliver`]; `forward` → `Forward(via)`.
pub fn resolve(routes: &[RouteData], destination: &str, now_ms: i64) -> Option<RouteResolution> {
    let mut best: Option<&RouteData> = None;
    let mut best_exact = false;

    for rd in routes {
        let exact = rd.match_dest == destination;
        let default = rd.match_dest == ROUTE_MATCH_DEFAULT;
        if !exact && !default {
            continue;
        }
        // Skip expired (0 == null per omitempty).
        if rd.expires_at != 0 && rd.expires_at <= now_ms {
            continue;
        }
        // §2 cross-field invariant — an invalid route never matches.
        let has_via = rd.via.as_deref().is_some_and(|v| !v.is_empty());
        match rd.action.as_str() {
            ROUTE_ACTION_FORWARD if !has_via => continue,
            ROUTE_ACTION_DELIVER if has_via => continue,
            ROUTE_ACTION_DELIVER | ROUTE_ACTION_FORWARD => {}
            _ => continue, // unknown action — skip
        }

        match best {
            None => {
                best = Some(rd);
                best_exact = exact;
            }
            Some(b) => {
                // Exact unconditionally outranks the default; within the same
                // exactness cohort, lower metric wins (matches the cohort's Go
                // reference selection — route7_exact_beats_default,
                // route4_metric_tiebreak).
                if exact && !best_exact {
                    best = Some(rd);
                    best_exact = true;
                } else if exact == best_exact && rd.metric < b.metric {
                    best = Some(rd);
                }
            }
        }
    }

    let best = best?;
    match best.action.as_str() {
        ROUTE_ACTION_DELIVER => Some(RouteResolution::Deliver),
        ROUTE_ACTION_FORWARD => best.via.clone().map(RouteResolution::Forward),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// CBOR helpers (shape mirrors extensions/relay/src/data.rs)
// ---------------------------------------------------------------------------

fn decode_map(data: &[u8]) -> Result<Vec<(Value, Value)>, RouteError> {
    let value: Value = ciborium::from_reader(data).map_err(|e| RouteError::Decode(e.to_string()))?;
    value
        .into_map()
        .map_err(|_| RouteError::Decode("expected CBOR map".into()))
}

fn get_field<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find_map(|(k, v)| if k.as_text() == Some(key) { Some(v) } else { None })
}

fn field_text(map: &[(Value, Value)], key: &str) -> Result<String, RouteError> {
    get_field(map, key)
        .and_then(|v| v.as_text())
        .map(|s| s.to_string())
        .ok_or_else(|| RouteError::Decode(format!("missing/invalid text field {}", key)))
}

fn field_text_opt(map: &[(Value, Value)], key: &str) -> Option<String> {
    get_field(map, key).and_then(|v| v.as_text()).map(|s| s.to_string())
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

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum RouteError {
    #[error("route entity decode failed: {0}")]
    Decode(String),
    #[error("route entity encode failed: {0}")]
    Encode(String),
}

#[cfg(test)]
mod tests;
