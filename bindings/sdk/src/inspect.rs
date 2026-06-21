//! Inspect-sink routing — consumer-facing surface for the substrate's
//! `dispatch` / `wire` / `binding` hooks (`GUIDE-INSPECTABILITY` v1.2 §2.1).
//!
//! Both arms produce the same wire-shape `InspectFact` (defined in
//! `entity-wasm-worker-protocol`, landing #1 of the inspect-worker-arm
//! design memo):
//!
//! - **Direct arm** (this module): the SDK installs three demuxer hooks on
//!   the `PeerContextBuilder` when `with_inspect_routing()` is called.
//!   Each hook marshals the in-process substrate event into an
//!   `InspectFact` and dispatches to every sink the consumer registered
//!   via `PeerContext::install_inspect_sink`. Empty registry → early
//!   return. No work for peers without an attached sink.
//!
//! - **Worker arm** (in `wasm-worker-host` for the install side +
//!   `wasm-worker-proxy::WorkerProxy::install_inspect_sink` for the
//!   consumer side): worker-host installs default-off hooks that post
//!   `Event::Inspect { peer_id, fact }` back to main; the proxy demuxes
//!   by `peer_id` and calls registered callbacks.
//!
//! The marshal functions here mirror `wasm-worker-host::marshal_*`
//! deliberately — both ends absorb substrate field churn at the marshal
//! site (§9 q5 of the design memo). Drift between the two is caught by
//! E2E tests that exercise both arms.

use std::sync::{Arc, Mutex};

use entity_peer::{DispatchEvent, DispatchPhase, WireEvent};
use entity_store::TreeChangeEvent;

use crate::ChangeType;

// ---------------------------------------------------------------------------
// `InspectFact` + helpers — SDK-side mirror of the wire-shape types in
// `entity-wasm-worker-protocol`. Defined here (not re-exported from the
// protocol crate) to avoid a cyclic crate dep: the protocol crate already
// depends on entity-sdk for `L1_WORKER_MIRRORED_SURFACE` (gated by the
// `conversions` feature) and `From` impls between SDK types and wire types.
//
// The shapes match the protocol crate's exactly. The Worker-arm proxy's
// `install_inspect_sink` performs a one-line `.into()` at the boundary
// (`wasm_worker_protocol::InspectFact -> entity_sdk::InspectFact`), so
// the consumer-facing surface is unified at this type.
//
// Drift between this and the wire shape is caught by the conversion
// `From` impls — if either side changes, the conversion stops compiling.
// ---------------------------------------------------------------------------

/// Direction of a wire frame relative to the local peer. Mirrors
/// `entity_wasm_worker_protocol::WireDirection`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectWireFrameDirection {
    Inbound,
    Outbound,
}

/// Kind tag for binding-event facts. Mirrors
/// `entity_wasm_worker_protocol::BindingKind`. `Put` covers both
/// `Created` and `Modified` — distinguish via `is_new`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectBindingKind {
    Put,
    Remove,
    Snapshot,
    CacheInvalidate,
}

/// Marshalled fact delivered to `InspectSinkFn`. Both arms produce the
/// same shape: Direct arm marshals here (`crate::inspect::marshal_*`);
/// Worker arm receives `wasm_worker_protocol::InspectFact` over the
/// wire and converts via `From`.
///
/// Field-level provenance + nullability rationale: see design memo §4.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InspectFact {
    Dispatch {
        request_id: String,
        handler_uri: String,
        operation: String,
        status: u32,
        elapsed_micros: Option<u64>,
        chain_id: Option<String>,
    },
    Wire {
        direction: InspectWireFrameDirection,
        peer_remote: Option<String>,
        frame_kind: String,
        bytes: u32,
        request_id: Option<String>,
    },
    Binding {
        kind: InspectBindingKind,
        path: String,
        entity_type: Option<String>,
        content_hash: Option<String>,
        is_new: bool,
    },
}

/// Synchronous, observe-only callback. Both arms produce the same
/// `InspectFact` shape. Single-threaded WASM-friendly: WASM consumers
/// can capture `Rc<RefCell<_>>` via the `Send + Sync` bound being
/// vacuously satisfied on `wasm32`. Native callers must produce an
/// honest `Send + Sync` closure (we run inside substrate hook fire
/// which is `Send + Sync`).
pub type InspectSinkFn = Arc<dyn Fn(&InspectFact) + Send + Sync>;

/// Per-peer registry of attached sinks. One per peer; held by the
/// peer's `PeerContext` and captured-by-clone in the demuxer hook
/// closures.
///
/// Empty registry → hook closures early-return without marshalling.
/// First sink attached → all events flow.
#[derive(Clone, Default)]
pub struct InspectSinkRegistry {
    inner: Arc<Mutex<Vec<(u64, InspectSinkFn)>>>,
    next_id: Arc<Mutex<u64>>,
}

impl InspectSinkRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a sink. Returns the id used to unregister.
    pub fn register(&self, sink: InspectSinkFn) -> u64 {
        let id = {
            let mut next = self.next_id.lock().unwrap();
            *next = next.wrapping_add(1);
            *next
        };
        self.inner.lock().unwrap().push((id, sink));
        id
    }

    /// Remove a previously-registered sink. Idempotent.
    pub fn unregister(&self, id: u64) {
        self.inner.lock().unwrap().retain(|(i, _)| *i != id);
    }

    /// True when no sinks are attached. Demuxer hooks consult this
    /// before marshalling to keep idle peers zero-cost.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().is_empty()
    }

    /// Fan-out a marshalled fact to every attached sink. Errors in
    /// individual sinks do not propagate — observe-only.
    pub fn fire(&self, fact: &InspectFact) {
        // Clone the sink list to release the lock before invoking
        // user callbacks (a sink calling back into install/uninstall
        // would otherwise deadlock).
        let sinks: Vec<InspectSinkFn> = {
            self.inner
                .lock()
                .unwrap()
                .iter()
                .map(|(_, f)| f.clone())
                .collect()
        };
        for sink in sinks {
            sink(fact);
        }
    }
}

/// Handle returned from `PeerContext::install_inspect_sink`. Drop
/// unregisters the sink. Holding the handle keeps the sink attached.
#[must_use = "dropping the InspectSinkHandle immediately detaches the sink"]
pub struct InspectSinkHandle {
    registry: InspectSinkRegistry,
    id: u64,
}

impl InspectSinkHandle {
    pub(crate) fn new(registry: InspectSinkRegistry, id: u64) -> Self {
        Self { registry, id }
    }
}

impl Drop for InspectSinkHandle {
    fn drop(&mut self) {
        self.registry.unregister(self.id);
    }
}

// ---------------------------------------------------------------------------
// Marshal: substrate hook events → wire `InspectFact`. Mirrors
// `wasm-worker-host::marshal_*` so Direct + Worker arms produce identical
// facts; field churn is absorbed here per §9 q5.
// ---------------------------------------------------------------------------

pub(crate) fn marshal_dispatch(ev: &DispatchEvent) -> InspectFact {
    let status = match &ev.phase {
        DispatchPhase::Entry => 0,
        DispatchPhase::Exit { status, .. } => *status,
    };
    InspectFact::Dispatch {
        request_id: ev.request_id.clone(),
        handler_uri: ev.target_uri.clone(),
        operation: ev.operation.clone(),
        status,
        elapsed_micros: None,
        chain_id: None,
    }
}

pub(crate) fn marshal_wire(ev: &WireEvent) -> InspectFact {
    let direction = match ev.direction {
        entity_peer::WireDirection::Recv => InspectWireFrameDirection::Inbound,
        entity_peer::WireDirection::Send => InspectWireFrameDirection::Outbound,
    };
    let frame_kind = match direction {
        InspectWireFrameDirection::Inbound => "execute".to_string(),
        InspectWireFrameDirection::Outbound => "execute_response".to_string(),
    };
    InspectFact::Wire {
        direction,
        peer_remote: if ev.peer_address.is_empty() {
            None
        } else {
            Some(ev.peer_address.clone())
        },
        frame_kind,
        bytes: ev.frame_bytes.len() as u32,
        request_id: if ev.request_id.is_empty() {
            None
        } else {
            Some(ev.request_id.clone())
        },
    }
}

pub(crate) fn marshal_binding(ev: &TreeChangeEvent) -> InspectFact {
    let kind = match ev.change_type {
        ChangeType::Created | ChangeType::Modified => InspectBindingKind::Put,
        ChangeType::Deleted => InspectBindingKind::Remove,
    };
    InspectFact::Binding {
        kind,
        path: ev.path.clone(),
        entity_type: None,
        content_hash: ev.new_hash.as_ref().map(|h| h.to_hex()),
        is_new: matches!(ev.change_type, ChangeType::Created),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn empty_registry_is_empty_and_fires_to_no_one() {
        let reg = InspectSinkRegistry::new();
        assert!(reg.is_empty());
        reg.fire(&InspectFact::Dispatch {
            request_id: "r1".into(),
            handler_uri: "x/y".into(),
            operation: "z".into(),
            status: 200,
            elapsed_micros: None,
            chain_id: None,
        });
    }

    #[test]
    fn register_then_fire_calls_sink() {
        let reg = InspectSinkRegistry::new();
        let count = Arc::new(AtomicUsize::new(0));
        let count2 = count.clone();
        let id = reg.register(Arc::new(move |_| {
            count2.fetch_add(1, Ordering::Relaxed);
        }));
        assert!(!reg.is_empty());
        reg.fire(&InspectFact::Dispatch {
            request_id: "r1".into(),
            handler_uri: "x/y".into(),
            operation: "z".into(),
            status: 200,
            elapsed_micros: None,
            chain_id: None,
        });
        assert_eq!(count.load(Ordering::Relaxed), 1);
        reg.unregister(id);
        assert!(reg.is_empty());
    }

    #[test]
    fn handle_drop_unregisters() {
        let reg = InspectSinkRegistry::new();
        let count = Arc::new(AtomicUsize::new(0));
        let count2 = count.clone();
        {
            let id = reg.register(Arc::new(move |_| {
                count2.fetch_add(1, Ordering::Relaxed);
            }));
            let _handle = InspectSinkHandle::new(reg.clone(), id);
            assert!(!reg.is_empty());
        }
        assert!(reg.is_empty());
    }

    #[test]
    fn fire_clones_then_invokes_so_sink_can_mutate_registry() {
        // Regression guard for the "sink registers another sink" deadlock —
        // fire() must release the lock before invoking sinks.
        let reg = InspectSinkRegistry::new();
        let reg2 = reg.clone();
        let count = Arc::new(AtomicUsize::new(0));
        let count2 = count.clone();
        reg.register(Arc::new(move |_| {
            // Re-entrant call into the registry — would deadlock if
            // fire() held the inner mutex across the user callback.
            let _ = reg2.is_empty();
            count2.fetch_add(1, Ordering::Relaxed);
        }));
        reg.fire(&InspectFact::Dispatch {
            request_id: "r".into(),
            handler_uri: "x".into(),
            operation: "y".into(),
            status: 200,
            elapsed_micros: None,
            chain_id: None,
        });
        assert_eq!(count.load(Ordering::Relaxed), 1);
    }
}
