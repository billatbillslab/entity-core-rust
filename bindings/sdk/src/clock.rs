//! Typed wrapper for `system/clock` extension operations.
//!
//! Per `SDK-EXTENSION-OPERATIONS.md §10` and `EXTENSION-CLOCK.md §3`.
//! Reached via [`PeerContext::clock`].
//!
//! ## Scope
//!
//! The clock handler exposes three operations per `EXTENSION-CLOCK §3`:
//! `now` (§3.2), `compare` (§3.3), and `tick` (§3.4). This module wraps
//! the first two as typed scope-handle methods.
//!
//! `tick` is intentionally not wrapped here — per §3.4, it's a
//! convenience that creates a subscription on `system/clock/tick/latest`
//! through the subscription extension. The Rust handler at
//! `extensions/clock/src/lib.rs:51` returns an error result for direct
//! `tick` dispatch; callers wanting periodic clock events subscribe
//! directly via [`PeerContext::subscribe`]. Matches the deliberate
//! omission in the Go reference (`workbench-go/entitysdk/clock.go`).
//!
//! There is **no `advance` operation**. `EXTENSION-CLOCK §4.2` (Clock
//! Advancement Algorithm) is an autonomous internal process that runs
//! on the emit pathway, not a handler op — clock state writes are
//! authored by the local peer identity per §9.
//!
//! ## Feature gating
//!
//! Available only when `entity-sdk` is built with the `clock`
//! feature enabled.

use std::collections::HashMap;

use crate::sdk::{PeerContext, SdkError};
use entity_entity::Entity;
use entity_handler::ExecuteOptions;
use entity_hash::Hash;

/// Decoded result of `system/clock:now`. Mode is always present;
/// the per-mode fields populate per `EXTENSION-CLOCK §2.6` and the
/// handler's mode-driven assembly (`extensions/clock/src/lib.rs:144`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockState {
    /// Configured clock mode — `"wall"`, `"logical"`, `"vector"`, or
    /// `"hlc"`. Per `EXTENSION-CLOCK §2.5`.
    pub mode: String,
    /// Wall-clock timestamp in milliseconds since the Unix epoch.
    /// Present when mode is `"wall"` or when `wall_clock = true` in
    /// `system/clock/config` (`extensions/clock/src/lib.rs:255`).
    pub timestamp_ms: Option<u64>,
    /// Lamport counter. Present in `logical` / `vector` / `hlc` modes.
    pub logical: Option<u64>,
    /// Vector-clock entries (`peer_id → counter`). Present in `vector`
    /// mode.
    pub vector: Option<HashMap<String, u64>>,
    /// HLC state. Present in `hlc` mode.
    pub hlc: Option<HlcState>,
}

/// Hybrid-logical-clock components per `EXTENSION-CLOCK §2.4`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HlcState {
    /// Wall-clock component in milliseconds.
    pub physical: u64,
    /// Logical counter that breaks ties when `physical` matches.
    pub logical: u64,
    /// Peer that authored the HLC observation. Carried as a
    /// `system/hash` (content hash of the identity entity).
    pub peer: Hash,
}

/// A clock value suitable for `system/clock:compare`. One of the four
/// shapes per `EXTENSION-CLOCK §6.4` — the handler detects the kind
/// from CBOR map keys and rejects mismatched kinds with
/// `400 invalid_params`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClockValue {
    /// Wall-clock timestamp (milliseconds since the Unix epoch).
    Timestamp(u64),
    /// Lamport counter.
    Logical(u64),
    /// Vector-clock entries keyed by peer-id.
    Vector(HashMap<String, u64>),
    /// HLC observation.
    Hlc(HlcState),
}

/// Result of `system/clock:compare` per `EXTENSION-CLOCK §6.4`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockOrder {
    /// `a` is strictly before `b`.
    Before,
    /// `a` is strictly after `b`.
    After,
    /// `a` and `b` are equal.
    Equal,
    /// `a` and `b` are concurrent — only produced for vector clocks.
    Concurrent,
}

/// Typed accessor for `system/clock` operations.
///
/// Created via [`PeerContext::clock`]. Borrows from the `PeerContext`;
/// futures returned by methods are `'static`.
pub struct ClockOps<'a> {
    ctx: &'a PeerContext,
}

impl<'a> ClockOps<'a> {
    pub(crate) fn new(ctx: &'a PeerContext) -> Self {
        Self { ctx }
    }

    /// Read the current clock state per the peer's configured mode
    /// (`system/clock/config`). Per `EXTENSION-CLOCK §3.2`.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn now(
        &self,
    ) -> impl std::future::Future<Output = Result<ClockState, SdkError>> + Send + 'static {
        let fut = self
            .ctx
            .execute("system/clock", "now", empty_params(), ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/clock:now") {
                return Err(err);
            }
            decode_clock_state(&result.result)
        }
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    pub fn now(
        &self,
    ) -> impl std::future::Future<Output = Result<ClockState, SdkError>> + 'static {
        let fut = self
            .ctx
            .execute("system/clock", "now", empty_params(), ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/clock:now") {
                return Err(err);
            }
            decode_clock_state(&result.result)
        }
    }

    /// Order two clock values per `EXTENSION-CLOCK §6.4`. `a` and `b`
    /// must be the same kind; mismatched kinds yield
    /// `Err(SdkError::HandlerError)` from the handler's
    /// `400 invalid_params`.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn compare(
        &self,
        a: ClockValue,
        b: ClockValue,
    ) -> impl std::future::Future<Output = Result<ClockOrder, SdkError>> + Send + 'static {
        let params = build_compare_params(a, b);
        let fut = self
            .ctx
            .execute("system/clock", "compare", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/clock:compare") {
                return Err(err);
            }
            decode_clock_order(&result.result)
        }
    }

    /// WASM variant — no `Send` bound.
    #[cfg(target_arch = "wasm32")]
    pub fn compare(
        &self,
        a: ClockValue,
        b: ClockValue,
    ) -> impl std::future::Future<Output = Result<ClockOrder, SdkError>> + 'static {
        let params = build_compare_params(a, b);
        let fut = self
            .ctx
            .execute("system/clock", "compare", params, ExecuteOptions::default());
        async move {
            let result = fut.await?;
            if let Some(err) = SdkError::from_handler_result(&result, "system/clock:compare") {
                return Err(err);
            }
            decode_clock_order(&result.result)
        }
    }
}

// ---------------------------------------------------------------------------
// Encoders
// ---------------------------------------------------------------------------

fn empty_params() -> Entity {
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(Vec::new()));
    Entity::new("primitive/any", data)
        .expect("empty primitive/any entity construction is infallible")
}

fn build_compare_params(a: ClockValue, b: ClockValue) -> Entity {
    let map = vec![
        (entity_ecf::text("a"), clock_value_to_cbor(a)),
        (entity_ecf::text("b"), clock_value_to_cbor(b)),
    ];
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(map));
    Entity::new("system/clock/compare-params", data)
        .expect("compare-params entity construction is infallible")
}

fn clock_value_to_cbor(v: ClockValue) -> ciborium::Value {
    match v {
        ClockValue::Timestamp(ms) => ciborium::Value::Map(vec![(
            entity_ecf::text("ms"),
            entity_ecf::integer(ms as i64),
        )]),
        ClockValue::Logical(counter) => ciborium::Value::Map(vec![(
            entity_ecf::text("counter"),
            entity_ecf::integer(counter as i64),
        )]),
        ClockValue::Vector(entries) => {
            // Sort entries by peer-id for deterministic encoding —
            // ECF requires sorted map keys (RFC 8949 §4.2). Without
            // this, two equivalent vector values can hash-mismatch.
            let mut pairs: Vec<_> = entries.into_iter().collect();
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            let entry_pairs: Vec<_> = pairs
                .into_iter()
                .map(|(k, c)| (entity_ecf::text(&k), entity_ecf::integer(c as i64)))
                .collect();
            ciborium::Value::Map(vec![(
                entity_ecf::text("entries"),
                ciborium::Value::Map(entry_pairs),
            )])
        }
        ClockValue::Hlc(hlc) => ciborium::Value::Map(vec![
            (
                entity_ecf::text("logical"),
                entity_ecf::integer(hlc.logical as i64),
            ),
            (
                entity_ecf::text("peer"),
                ciborium::Value::Bytes(hlc.peer.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("physical"),
                entity_ecf::integer(hlc.physical as i64),
            ),
        ]),
    }
}

// ---------------------------------------------------------------------------
// Decoders
// ---------------------------------------------------------------------------

fn decode_clock_state(entity: &Entity) -> Result<ClockState, SdkError> {
    let val: ciborium::Value = ciborium::de::from_reader(entity.data.as_slice())
        .map_err(|e| SdkError::HandlerError(format!("decode clock state: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| SdkError::HandlerError("clock state not a map".into()))?;

    let mut mode: Option<String> = None;
    let mut timestamp_ms: Option<u64> = None;
    let mut logical: Option<u64> = None;
    let mut vector: Option<HashMap<String, u64>> = None;
    let mut hlc: Option<HlcState> = None;

    for (k, v) in map {
        match k.as_text() {
            Some("mode") => {
                mode = v.as_text().map(|s| s.to_string());
            }
            Some("timestamp") => {
                timestamp_ms = v.as_map().and_then(|m| {
                    m.iter().find_map(|(kk, vv)| {
                        if kk.as_text() == Some("ms") {
                            decode_u64(vv)
                        } else {
                            None
                        }
                    })
                });
            }
            Some("logical") => {
                logical = v.as_map().and_then(|m| {
                    m.iter().find_map(|(kk, vv)| {
                        if kk.as_text() == Some("counter") {
                            decode_u64(vv)
                        } else {
                            None
                        }
                    })
                });
            }
            Some("vector") => {
                vector = v.as_map().and_then(|m| {
                    m.iter().find_map(|(kk, vv)| {
                        if kk.as_text() == Some("entries") {
                            vv.as_map().map(|entries| {
                                let mut out = HashMap::new();
                                for (ek, ev) in entries {
                                    if let (Some(name), Some(count)) =
                                        (ek.as_text(), decode_u64(ev))
                                    {
                                        out.insert(name.to_string(), count);
                                    }
                                }
                                out
                            })
                        } else {
                            None
                        }
                    })
                });
            }
            Some("hlc") => {
                hlc = v.as_map().and_then(|m| decode_hlc_fields(m));
            }
            _ => {}
        }
    }

    Ok(ClockState {
        mode: mode.ok_or_else(|| SdkError::HandlerError("clock state missing `mode`".into()))?,
        timestamp_ms,
        logical,
        vector,
        hlc,
    })
}

fn decode_hlc_fields(map: &Vec<(ciborium::Value, ciborium::Value)>) -> Option<HlcState> {
    let mut physical = None;
    let mut logical = None;
    let mut peer = None;
    for (k, v) in map {
        match k.as_text() {
            Some("physical") => physical = decode_u64(v),
            Some("logical") => logical = decode_u64(v),
            Some("peer") => {
                if let ciborium::Value::Bytes(b) = v {
                    peer = Hash::from_bytes(b).ok();
                }
            }
            _ => {}
        }
    }
    Some(HlcState {
        physical: physical?,
        logical: logical?,
        peer: peer?,
    })
}

fn decode_clock_order(entity: &Entity) -> Result<ClockOrder, SdkError> {
    let val: ciborium::Value = ciborium::de::from_reader(entity.data.as_slice())
        .map_err(|e| SdkError::HandlerError(format!("decode compare result: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| SdkError::HandlerError("compare result not a map".into()))?;

    for (k, v) in map {
        if k.as_text() == Some("order") {
            return match v.as_text() {
                Some("before") => Ok(ClockOrder::Before),
                Some("after") => Ok(ClockOrder::After),
                Some("equal") => Ok(ClockOrder::Equal),
                Some("concurrent") => Ok(ClockOrder::Concurrent),
                Some(other) => Err(SdkError::HandlerError(format!(
                    "unknown clock order `{}`",
                    other
                ))),
                None => Err(SdkError::HandlerError("`order` is not text".into())),
            };
        }
    }
    Err(SdkError::HandlerError("compare result missing `order`".into()))
}

fn decode_u64(v: &ciborium::Value) -> Option<u64> {
    if let ciborium::Value::Integer(i) = v {
        let signed: i128 = (*i).into();
        if signed >= 0 {
            return Some(signed as u64);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::PeerContextBuilder;

    fn make_ctx() -> PeerContext {
        PeerContextBuilder::new()
            .generate_keypair()
            .build()
            .expect("PeerContext build should succeed")
    }

    /// `now` on a fresh peer returns wall-mode state. Default config
    /// per `EXTENSION-CLOCK §8` is `"wall"`, so timestamp populates
    /// and the per-mode-non-wall fields stay `None`.
    #[tokio::test(flavor = "current_thread")]
    async fn now_fresh_peer_returns_wall_state() {
        let ctx = make_ctx();
        let state = ctx.clock().now().await.expect("now should dispatch");

        assert_eq!(state.mode, "wall", "default clock mode is `wall`");
        assert!(
            state.timestamp_ms.is_some(),
            "wall mode populates timestamp"
        );
        assert!(state.logical.is_none(), "wall mode does not set logical");
        assert!(state.vector.is_none(), "wall mode does not set vector");
        assert!(state.hlc.is_none(), "wall mode does not set hlc");
    }

    /// `compare` orders two timestamps. Proves: ClockValue encodes
    /// correctly, params reach the handler, result decodes to a
    /// typed `ClockOrder`.
    #[tokio::test(flavor = "current_thread")]
    async fn compare_timestamps_orders_earlier_before_later() {
        let ctx = make_ctx();
        let order = ctx
            .clock()
            .compare(ClockValue::Timestamp(1_000), ClockValue::Timestamp(2_000))
            .await
            .expect("compare should dispatch");
        assert_eq!(order, ClockOrder::Before);

        let order = ctx
            .clock()
            .compare(ClockValue::Timestamp(2_000), ClockValue::Timestamp(1_000))
            .await
            .expect("compare should dispatch");
        assert_eq!(order, ClockOrder::After);

        let order = ctx
            .clock()
            .compare(ClockValue::Timestamp(1_000), ClockValue::Timestamp(1_000))
            .await
            .expect("compare should dispatch");
        assert_eq!(order, ClockOrder::Equal);
    }

    /// `compare` with concurrent vector clocks yields `Concurrent`.
    /// Proves: vector encoding round-trips through deterministic
    /// sort, handler detects concurrency per §6.4.
    #[tokio::test(flavor = "current_thread")]
    async fn compare_vector_concurrent() {
        let ctx = make_ctx();
        let mut a = HashMap::new();
        a.insert("peer-a".to_string(), 2);
        a.insert("peer-b".to_string(), 1);
        let mut b = HashMap::new();
        b.insert("peer-a".to_string(), 1);
        b.insert("peer-b".to_string(), 2);

        let order = ctx
            .clock()
            .compare(ClockValue::Vector(a), ClockValue::Vector(b))
            .await
            .expect("compare should dispatch");
        assert_eq!(order, ClockOrder::Concurrent);
    }
}
