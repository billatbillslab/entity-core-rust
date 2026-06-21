#![cfg(target_arch = "wasm32")]
//! Main-thread proxy for an entity-core peer hosted in a dedicated Web Worker.
//!
//! # Responsibilities
//!
//! - Mirror the SDK's L1 async surface as `WorkerProxy` methods.
//! - Correlate requests with responses by `RequestId`.
//! - Demultiplex `Event`s by `SubId` to the right subscriber channel.
//! - Maintain an in-process cache (per-subscription `BTreeMap` mirror) fed
//!   by subscription events. State lives inside `WorkerProxy`; consumers
//!   read it synchronously via [`WorkerProxy::cache_get`] / [`WorkerProxy::cache_list`]
//!   at render time, and wake on the channel-based [`NotifyChannel`]
//!   returned from [`WorkerProxy::observe`].
//!
//! # L0 prohibition
//!
//! This crate exposes the spec's L1 surface. For L0 access (direct
//! `ContentStore` / `LocationIndex` / `Peer` escape hatches), link
//! `entity-sdk` directly — those paths assume same-thread, same-memory
//! peer access and cannot cross the worker boundary.
//!
//! # Subscribe vs observe — naming note
//!
//! Today's `entity-sdk` exposes `subscribe(prefix, callback)` (closure-based).
//! This crate renames the equivalent to [`WorkerProxy::observe`] to make the
//! return-channel-based shape obvious — and to flag the semantic difference
//! (closures don't cross the postMessage boundary; channels are the
//! structured-clone-safe equivalent). Phase 3 consumer migration replaces
//! `subscribe` call sites with `observe`.
//!
//! # Cache invariants (consumer contract)
//!
//! 1. **Initial-snapshot race avoidance.** When a consumer calls
//!    `proxy.observe(prefix)`, the returned `NotifyChannel` MUST receive
//!    the initial snapshot delivery before any incremental change event for
//!    the same subscription. Consumers may safely subscribe-then-read.
//! 2. **Drop semantics.** Dropping a `SubHandle` cancels the worker-side
//!    subscription; queued events for that sub already in transit are
//!    discarded by the proxy on receipt.
//! 3. **Reconnect / restart.** If the worker terminates and restarts, the
//!    proxy invalidates affected cache regions, surfaces a
//!    `Event::SubscriptionLost` to observers, and (in v1) requires the
//!    consumer to re-subscribe. Auto-resubscribe is a future enhancement.
//! 4. **Write/read coherence — events, not writes-in-flight.** The cache
//!    is updated from the subscription-event channel, NOT from `put`/
//!    `execute` response payloads. So after `proxy.put(p, e).await?`
//!    returns, `cache.get(p)` may still return the old value for as long
//!    as it takes the event to propagate (sub-ms in practice, but not
//!    zero). This is correct: the cache reflects what events have
//!    arrived, not what writes have been issued. The right pattern is
//!    "write, return, let the next render cycle (after the dirty flag
//!    fires) pick up the new value." Do not write-then-immediately-read
//!    against the cache. For state-machine flows that genuinely need to
//!    await cache reflection, use [`WorkerProxy::put_and_wait_for_cache`]
//!    (S3 ergonomic helper).
//! 5. **Bounded scope.** v1 mirrors are unbounded. Bounded-LRU per prefix
//!    becomes required (Phase 4) for deployments where any mirrored
//!    prefix is expected to exceed ~50k entities or ~100 MB main-thread
//!    memory. Below those thresholds, unbounded is acceptable.
//! 6. **Cache updates are lossless; notifications are lossy.** Every
//!    `Event::Change` from the worker applies to the cache mirror exactly
//!    once — the mirror cannot diverge from the worker's view. The
//!    per-subscription **notification channel** (bounded mpsc, capacity 1,
//!    newest-wins) separately coalesces consumer wake-ups. Coalescing
//!    affects when consumers learn that *something* changed in a prefix;
//!    it does not affect what the cache reflects when they read. Overflow
//!    recovery, when needed (not in v1 — Phase 0c traffic is far below
//!    capacity), is "drop subscription → resubscribe → fresh snapshot,"
//!    not "drop cache updates." Q4 of the Phase 1 protocol review.

mod broker;
mod web_transport;
pub use broker::MessagePortBroker;
pub use web_transport::WebTransport;

use entity_wasm_worker_protocol::{
    CasFailure, ConnectPeerOk, CreatePeerOk, Event, InitParams, Request, RequestId, Response,
    SubId, WireEntity, WireExecuteOptions, WireHandlerInfo, WireHandlerResult, WireHash,
    WireListingEntry, WirePeerMetadata, WireQueryResults, WireTypeInfo, PROTOCOL_VERSION,
};
use futures::channel::{mpsc, oneshot};
use futures::StreamExt;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("transport: {0}")]
    Transport(String),
    #[error("worker error ({kind:?}): {message}")]
    Worker {
        kind: entity_wasm_worker_protocol::WireErrorKind,
        message: String,
    },
    #[error("unexpected response variant: {0}")]
    UnexpectedResponse(String),
    #[error("worker dropped response channel")]
    Cancelled,
    #[error(
        "protocol version mismatch: proxy expects {expected}, worker reported {actual}. \
         Proxy and host must ship together — rebuild both from the same revision."
    )]
    VersionMismatch { expected: u32, actual: u32 },
    #[error("worker spawn failed: {0}")]
    WorkerSpawn(String),
    #[error("init handshake failed: {0}")]
    InitFailed(String),
    #[error("worker terminated; no further requests will be accepted")]
    Terminated,
}

impl From<entity_wasm_worker_protocol::WireError> for ProxyError {
    fn from(e: entity_wasm_worker_protocol::WireError) -> Self {
        ProxyError::Worker { kind: e.kind, message: e.message }
    }
}

/// Transport abstraction. The real `WebTransport` (wasm-bindgen) wraps a
/// `web_sys::Worker` and routes postMessage I/O. Test code uses a mock
/// implementor.
///
/// Two responsibilities:
/// - `send_request` ships a `Request` and returns a oneshot receiver for
///   the matching `Response` (correlated by `RequestId`).
/// - `take_event_stream` hands the proxy ownership of the inbound `Event`
///   stream exactly once at init time. Subsequent calls return `None`.
///   The proxy spawns a demultiplexer task that drains this stream and
///   routes events to subscription channels by `SubId`.
pub trait Transport {
    fn send_request(&self, req: Request) -> oneshot::Receiver<Response>;

    /// Take the event stream. The contract is "exactly once" — the first
    /// caller gets `Some(receiver)`; later calls return `None`. The proxy
    /// calls this from `WorkerProxy::new` and spawns the demultiplexer.
    fn take_event_stream(&self) -> Option<mpsc::UnboundedReceiver<Event>>;

    /// Tear down the transport: terminate the underlying worker and drop
    /// any pending request senders. Awaiters of in-flight requests
    /// observe `ProxyError::Cancelled` (their oneshot receivers see the
    /// sender drop). Idempotent — default impl is a no-op so non-worker
    /// transports (e.g., test mocks) don't have to implement it.
    fn terminate(&self) {}
}

/// Per-subscription cache state. The mirror is updated **losslessly** from
/// every `Event::Change`; the notify channel is updated **lossily** (newest-
/// wins, bounded capacity 1) — see invariant #6.
struct SubscriptionEntry {
    /// Prefix the subscription covers. Used to resolve `cache_get` /
    /// `cache_list` queries to the right mirror.
    #[allow(dead_code)]
    prefix: String,
    /// The mirror itself. Path → entity. Updated by the demultiplexer; read
    /// synchronously by `cache_get` / `cache_list`.
    mirror: BTreeMap<String, WireEntity>,
    /// Notification sink. The demultiplexer pushes `()` after applying each
    /// event. Capacity-1 bounded channel: if a `()` is already queued and
    /// unread, the sender returns `Err(_)` from `try_send` — we drop the
    /// extra, achieving newest-wins coalescing.
    notify_tx: mpsc::Sender<()>,
    /// Optional per-event sink for `observe_with_events` consumers. When
    /// `Some`, the demultiplexer fans out a `ChangeEvent` here in addition
    /// to poking `notify_tx`. Bounded mpsc(64); overflow is tallied and a
    /// `ChangeEvent::Lagged { count }` is delivered when the channel
    /// drains. None for plain `observe()` to keep that path zero-cost.
    event_tx: Option<mpsc::Sender<ChangeEvent>>,
    /// Pending lag counter — events dropped because `event_tx` was full.
    /// Flushed as `ChangeEvent::Lagged` on the first successful send after
    /// overflow stops. Only meaningful when `event_tx.is_some()`.
    pending_lag: u64,
    /// Invariant #1 gate. The demultiplexer ignores `Change` events for
    /// this subscription until the initial `Snapshot` arrives — otherwise
    /// the mirror could observe paths in an order the worker never sent.
    snapshot_received: bool,
}

/// Per-event delivery for [`WorkerProxy::observe_with_events`]. Shape
/// mirrors the Direct-mode `entity_sdk::TreeChangeEvent` so consumer code
/// looks the same on both arms.
///
/// `Lagged` is delivered when bounded-channel overflow caused events to
/// be dropped. After a `Lagged`, the consumer's view of the per-event
/// stream has gaps — typical recovery is `cache_list(prefix)` to resync
/// then resume consuming live events.
#[derive(Debug, Clone)]
pub enum ChangeEvent {
    Created {
        path: String,
        new_hash: entity_wasm_worker_protocol::WireHash,
    },
    Updated {
        path: String,
        previous_hash: entity_wasm_worker_protocol::WireHash,
        new_hash: entity_wasm_worker_protocol::WireHash,
    },
    Removed {
        path: String,
        previous_hash: entity_wasm_worker_protocol::WireHash,
    },
    /// Consumer missed `count` events because the event channel was
    /// full. Mirror state in the proxy is still authoritative — resync
    /// via `cache_list` and continue consuming.
    Lagged {
        count: u64,
    },
}

const EVENT_CHANNEL_CAPACITY: usize = 64;

/// Subscription registry. Shared between `WorkerProxy` (which inserts
/// entries from `observe`), the demultiplexer task (which mutates mirrors),
/// and `SubHandle::drop` (which removes entries on cancellation).
#[derive(Default)]
struct SubscriptionRegistry {
    entries: HashMap<SubId, SubscriptionEntry>,
}

/// Main-thread proxy. Generic over `Transport` for testability; the
/// production wiring uses `WebTransport` (real `web_sys::Worker`), and
/// tests use a mock implementor of `Transport`.
pub struct WorkerProxy<T: Transport> {
    transport: Rc<T>,
    /// `Rc<Cell<_>>` rather than `Cell<_>` so `SubHandle::drop` can allocate
    /// a `request_id` for the unsubscribe fire-and-forget.
    next_request_id: Rc<Cell<RequestId>>,
    next_sub_id: Rc<Cell<SubId>>,
    subscriptions: Rc<RefCell<SubscriptionRegistry>>,
    /// Per-peer inspect-sink callbacks. Key is the `peer_id` carried on
    /// `Event::Inspect { peer_id, fact }`. Empty map → demultiplexer
    /// silently drops Inspect events (default-off matches worker-side
    /// per-peer enable flag — see PROTOCOL_VERSION=9 design memo).
    ///
    /// Stored as a `Vec<(u64, callback)>` per peer so multiple sinks
    /// can attach (e.g. one window per fact kind). The id is returned
    /// in the `InspectSinkHandle` so drop can unregister precisely.
    inspect_routes: Rc<RefCell<InspectRouteRegistry>>,
    /// Set by [`WorkerProxy::terminate`]. Once true, the proxy refuses to
    /// dispatch further requests — they short-circuit with
    /// [`ProxyError::Terminated`] without touching the (already-dead)
    /// worker. `Rc<Cell<_>>` so `SubHandle::drop`'s fire-and-forget
    /// unsubscribe path can read it cheaply.
    terminated: Rc<Cell<bool>>,
}

/// Per-peer registry of inspect-sink callbacks. WASM-only =
/// single-threaded; uses `Rc<RefCell<_>>` for interior mutability.
#[derive(Default)]
pub struct InspectRouteRegistry {
    by_peer: HashMap<String, Vec<(u64, InspectCallback)>>,
    next_id: u64,
}

type InspectCallback =
    std::rc::Rc<dyn Fn(&entity_wasm_worker_protocol::InspectFact)>;

/// Returned by [`WorkerProxy::install_inspect_sink`]. Drop unregisters
/// the sink and, if it was the last sink for that peer, posts
/// `Request::SetInspectEnabled { enabled: false }` to the worker so
/// marshalling stops.
#[must_use = "dropping the InspectSinkHandle detaches the sink immediately"]
pub struct InspectSinkHandle<T: Transport + 'static> {
    proxy_transport: Rc<T>,
    inspect_routes: Rc<RefCell<InspectRouteRegistry>>,
    next_request_id: Rc<Cell<RequestId>>,
    terminated: Rc<Cell<bool>>,
    peer_id: String,
    sink_id: u64,
}

impl<T: Transport + 'static> Drop for InspectSinkHandle<T> {
    fn drop(&mut self) {
        let mut routes = self.inspect_routes.borrow_mut();
        let last_for_peer = if let Some(list) = routes.by_peer.get_mut(&self.peer_id) {
            list.retain(|(id, _)| *id != self.sink_id);
            list.is_empty()
        } else {
            false
        };
        if last_for_peer {
            routes.by_peer.remove(&self.peer_id);
        }
        drop(routes);
        // Fire-and-forget SetInspectEnabled(false) for the last drop on
        // that peer. Skip if the proxy is terminated (no reachable worker).
        if last_for_peer && !self.terminated.get() {
            let rid = self.next_request_id.get();
            self.next_request_id.set(rid.wrapping_add(1));
            let req = Request::SetInspectEnabled {
                request_id: rid,
                peer_id: self.peer_id.clone(),
                enabled: false,
            };
            // Don't await — drop must be sync.
            let _ = self.proxy_transport.send_request(req);
        }
    }
}

impl<T: Transport + 'static> WorkerProxy<T> {
    /// Construct a proxy and perform the init handshake.
    ///
    /// 1. Send `Request::Init { params }`.
    /// 2. Await `Response::Ready { protocol_version, sdk_version }`.
    /// 3. Verify protocol_version matches the proxy's `PROTOCOL_VERSION`
    ///    constant — on mismatch, fail fast with [`ProxyError::VersionMismatch`].
    /// 4. Take ownership of the event stream and spawn the demultiplexer
    ///    task. From this point on, every `Event` posted by the worker is
    ///    routed to the right `SubscriptionEntry` losslessly, and the
    ///    corresponding `NotifyChannel` is poked lossy-coalesced.
    ///
    /// Returns the proxy ready for normal `Request`/`Response` flow.
    pub async fn new(transport: T, init: InitParams) -> Result<Self, ProxyError> {
        let proxy = Self {
            transport: Rc::new(transport),
            next_request_id: Rc::new(Cell::new(1)),
            next_sub_id: Rc::new(Cell::new(1)),
            subscriptions: Rc::new(RefCell::new(SubscriptionRegistry::default())),
            inspect_routes: Rc::new(RefCell::new(InspectRouteRegistry::default())),
            terminated: Rc::new(Cell::new(false)),
        };

        // Init handshake.
        let request_id = proxy.alloc_request_id();
        let init_request = Request::Init { request_id, params: init };
        let rx = proxy.transport.send_request(init_request);
        match rx.await {
            Ok(Response::Ready {
                request_id: _,
                protocol_version,
                sdk_version: _,
                actual_capabilities: _,
            }) => {
                if protocol_version != PROTOCOL_VERSION {
                    return Err(ProxyError::VersionMismatch {
                        expected: PROTOCOL_VERSION,
                        actual: protocol_version,
                    });
                }
            }
            Ok(Response::Init {
                request_id: _,
                result: Some(e),
            }) => {
                return Err(ProxyError::InitFailed(e.message));
            }
            Ok(Response::Init {
                request_id: _,
                result: None,
            }) => {
                // Worker reported Init success via Response::Init { None }
                // instead of Response::Ready. Treat as success but flag the
                // anomaly — the worker should always send Ready on init OK.
                web_sys::console::warn_1(&wasm_bindgen::JsValue::from_str(
                    "wasm-worker-proxy: Init returned Ok but no Ready was posted — \
                     worker is reachable but did not include protocol_version. \
                     Treating as success at PROTOCOL_VERSION (best-effort).",
                ));
            }
            Ok(other) => {
                return Err(ProxyError::UnexpectedResponse(format!(
                    "init expected Ready, got {:?}",
                    other
                )));
            }
            Err(_) => return Err(ProxyError::Cancelled),
        }

        // Take the event stream and spawn the demultiplexer. From here on,
        // events arriving over postMessage are routed by sub_id into the
        // registry. The task captures `Rc<RefCell<SubscriptionRegistry>>`
        // by clone and runs until the event stream closes (worker death).
        if let Some(events) = proxy.transport.take_event_stream() {
            let subscriptions = proxy.subscriptions.clone();
            let inspect_routes = proxy.inspect_routes.clone();
            wasm_bindgen_futures::spawn_local(demultiplex(events, subscriptions, inspect_routes));
        }

        Ok(proxy)
    }

    /// Register a callback that receives every `Event::Inspect` for
    /// `peer_id` once `SetInspectEnabled(peer_id, true)` round-trips.
    ///
    /// Multiple callbacks may attach to the same peer; each is called
    /// in registration order. The returned handle's drop unregisters
    /// the callback and (if it was the last for that peer) posts
    /// `SetInspectEnabled(false)` to halt marshalling.
    ///
    /// Per design memo §6 / PROTOCOL_VERSION=9 §4.1.
    pub fn install_inspect_sink<F>(
        &self,
        peer_id: impl Into<String>,
        callback: F,
    ) -> InspectSinkHandle<T>
    where
        F: Fn(&entity_wasm_worker_protocol::InspectFact) + 'static,
    {
        let peer_id = peer_id.into();
        let cb: InspectCallback = std::rc::Rc::new(callback);
        let (sink_id, was_first_for_peer) = {
            let mut routes = self.inspect_routes.borrow_mut();
            routes.next_id = routes.next_id.wrapping_add(1);
            let id = routes.next_id;
            let list = routes.by_peer.entry(peer_id.clone()).or_default();
            let was_first = list.is_empty();
            list.push((id, cb));
            (id, was_first)
        };
        // Fire-and-forget enable on first-attach. If the request errors
        // (worker terminated, transport down), the next Event::Inspect
        // simply won't arrive — the sink is no-op but harmless.
        if was_first_for_peer && !self.terminated.get() {
            let rid = self.alloc_request_id();
            let req = Request::SetInspectEnabled {
                request_id: rid,
                peer_id: peer_id.clone(),
                enabled: true,
            };
            let _ = self.transport.send_request(req);
        }
        InspectSinkHandle {
            proxy_transport: self.transport.clone(),
            inspect_routes: self.inspect_routes.clone(),
            next_request_id: self.next_request_id.clone(),
            terminated: self.terminated.clone(),
            peer_id,
            sink_id,
        }
    }

    fn alloc_request_id(&self) -> RequestId {
        let id = self.next_request_id.get();
        self.next_request_id.set(id.wrapping_add(1));
        id
    }

    fn alloc_sub_id(&self) -> SubId {
        let id = self.next_sub_id.get();
        self.next_sub_id.set(id.wrapping_add(1));
        id
    }
}

// Backwards-compat alias for the macro and hand-rolled methods that
// reference `self.alloc_id()`. Keeps the macro body unchanged.
impl<T: Transport> WorkerProxy<T> {
    fn alloc_id(&self) -> RequestId {
        let id = self.next_request_id.get();
        self.next_request_id.set(id.wrapping_add(1));
        id
    }
}

/// Demultiplexer task: drains the event stream and applies each event to
/// the right `SubscriptionEntry`. Spawned once per proxy in `new`.
///
/// **Lossless cache update** (invariant #6): every `Event::Change` is
/// applied to its sub's mirror. The notification channel is poked via
/// `try_send` — if its capacity-1 slot is full, the send fails and we
/// drop the redundant wake. The cache mirror is the source of truth;
/// notifications are just "consumer, you may want to re-render."
///
/// **Snapshot ordering** (invariant #1): a `Change` event for a sub whose
/// `snapshot_received == false` is ignored. The worker is contracted to
/// send `Snapshot` first; until it does, the mirror stays empty.
///
/// **Lost subscription** (invariant #3): `Event::SubscriptionLost` removes
/// the registry entry, which drops the `notify_tx` — the consumer's
/// `NotifyChannel::next()` returns `None`, signalling the subscription is
/// gone. The consumer should resubscribe in v1.
/// Fan an event out to the per-event channel, handling the bounded-channel
/// overflow protocol: if a prior overflow tallied `pending_lag > 0`, try
/// to flush a `Lagged { count }` first; if either send hits `try_send`
/// full, bump `pending_lag` and drop. Caller has already checked
/// `entry.event_tx.is_some()`.
fn try_send_event(entry: &mut SubscriptionEntry, ev: ChangeEvent) {
    let tx = match entry.event_tx.as_mut() {
        Some(tx) => tx,
        None => return,
    };
    // Flush pending lag before the new event so consumers learn about
    // the gap in the right order.
    if entry.pending_lag > 0 {
        let lagged = ChangeEvent::Lagged { count: entry.pending_lag };
        if tx.try_send(lagged).is_err() {
            // Still full — the new event also can't go through; tally
            // it and bail. `pending_lag` stays set.
            entry.pending_lag += 1;
            return;
        }
        entry.pending_lag = 0;
    }
    if tx.try_send(ev).is_err() {
        entry.pending_lag += 1;
    }
}

async fn demultiplex(
    mut events: mpsc::UnboundedReceiver<Event>,
    subscriptions: Rc<RefCell<SubscriptionRegistry>>,
    inspect_routes: Rc<RefCell<InspectRouteRegistry>>,
) {
    while let Some(event) = events.next().await {
        let mut reg = subscriptions.borrow_mut();
        match event {
            Event::Snapshot { sub_id, entries } => {
                if let Some(entry) = reg.entries.get_mut(&sub_id) {
                    entry.mirror.clear();
                    for (path, e) in entries {
                        // Fan out a synth `Created` to the event channel
                        // (if any) BEFORE inserting into the mirror, so the
                        // order observed by event-channel consumers matches
                        // a freshly-built world.
                        if entry.event_tx.is_some() {
                            let ev = ChangeEvent::Created {
                                path: path.clone(),
                                new_hash: e.content_hash.clone(),
                            };
                            try_send_event(entry, ev);
                        }
                        entry.mirror.insert(path, e);
                    }
                    entry.snapshot_received = true;
                    let _ = entry.notify_tx.try_send(());
                }
                // sub_id unknown → registry entry was removed (SubHandle
                // dropped, or SubscriptionLost arrived earlier). Drop event.
            }
            Event::Change { sub_id, path, new_entity } => {
                if let Some(entry) = reg.entries.get_mut(&sub_id) {
                    if !entry.snapshot_received {
                        // Invariant #1: snapshot must arrive first.
                        continue;
                    }
                    // Compute the previous_hash BEFORE mutating the mirror
                    // so we can derive Created/Updated/Removed correctly
                    // for the event channel.
                    let previous_hash = entry.mirror.get(&path).map(|e| e.content_hash.clone());
                    match (previous_hash.as_ref(), new_entity.as_ref()) {
                        (_, Some(e)) if entry.event_tx.is_some() => {
                            let new_hash = e.content_hash.clone();
                            let ev = match &previous_hash {
                                Some(prev) => ChangeEvent::Updated {
                                    path: path.clone(),
                                    previous_hash: prev.clone(),
                                    new_hash,
                                },
                                None => ChangeEvent::Created {
                                    path: path.clone(),
                                    new_hash,
                                },
                            };
                            try_send_event(entry, ev);
                        }
                        (Some(prev), None) if entry.event_tx.is_some() => {
                            let ev = ChangeEvent::Removed {
                                path: path.clone(),
                                previous_hash: prev.clone(),
                            };
                            try_send_event(entry, ev);
                        }
                        _ => {}
                    }
                    match new_entity {
                        Some(e) => {
                            entry.mirror.insert(path, e);
                        }
                        None => {
                            entry.mirror.remove(&path);
                        }
                    }
                    let _ = entry.notify_tx.try_send(());
                }
            }
            Event::SubscriptionLost { sub_id, reason: _ } => {
                // Invariant #3: invalidate. Removing the entry drops
                // notify_tx → consumer's NotifyChannel observes channel
                // close on next poll.
                reg.entries.remove(&sub_id);
            }
            Event::Inspect { peer_id, fact } => {
                // PROTOCOL v9 inspect-hook routing. Clone the per-peer
                // callback list before invoking (a sink calling back
                // into `install_inspect_sink` would otherwise re-borrow
                // the RefCell). Empty / absent peer entry = silent drop,
                // which is the correct shape for a marshal that raced
                // the last sink's drop + SetInspectEnabled(false).
                let cbs: Vec<InspectCallback> = {
                    let routes = inspect_routes.borrow();
                    routes
                        .by_peer
                        .get(&peer_id)
                        .map(|list| list.iter().map(|(_, cb)| cb.clone()).collect())
                        .unwrap_or_default()
                };
                for cb in cbs {
                    cb(&fact);
                }
            }
        }
    }
    // Event stream closed (worker died / transport dropped). All
    // subscriptions are implicitly lost; consumers see their NotifyChannels
    // close when the registry's senders are eventually dropped via the
    // proxy itself being dropped. (We don't proactively clear the registry
    // here because the consumer may still be reading the last cached state.)
}

// ---------------------------------------------------------------------------
// proxy_method! macro — Phase 0b spike, extended Phase 1 protocol-review
//
// Each invocation generates one async method on `WorkerProxy<T>`. The macro
// captures:
//   - method name
//   - argument list (name : type)
//   - the matching Request variant (just the variant ident — the macro
//     constructs the struct-literal init from the arg list, requiring
//     argument names to match the Request variant's field names)
//   - the matching Response variant
//   - the success payload type returned to the caller
//
// All peer-scoped methods take `peer_id: String` as the first argument
// after `request_id` (S1 resolution: explicit field on every relevant
// Request variant).
//
// The generated body:
//   1. Allocates a fresh RequestId.
//   2. Builds the Request variant struct-literal (request_id + args).
//   3. Sends via transport, awaits the response.
//   4. Pattern-matches: success → unwrap the `Result<T, WireError>` and
//      map to ProxyError; wrong variant → UnexpectedResponse error;
//      channel dropped → Cancelled.
// ---------------------------------------------------------------------------

/// Generate an inherent async method on `WorkerProxy<T>` that proxies one
/// L1 SDK call over the postMessage transport.
///
/// Each invocation expands to an `impl<TR: Transport> WorkerProxy<TR>`
/// block adding one method. The macro captures:
///   - method name
///   - argument list (name : type) — names must match the corresponding
///     `Request` variant's field names; the macro uses struct-literal
///     shorthand to build the variant.
///   - the success-return type
///   - the matching `Request` and `Response` variant idents
///
/// Generated body:
///   1. Allocate a fresh `RequestId`.
///   2. Build the `Request` variant struct-literal (request_id + args).
///   3. Send via transport, await the response.
///   4. Pattern-match: success → unwrap the `Result<T, WireError>` and
///      map to `ProxyError`; wrong variant → `UnexpectedResponse`;
///      channel dropped → `Cancelled`.
///
/// `as` separator: `$ret:ty` can only be followed by a specific set of
/// tokens in `macro_rules!` (rustc tells you the list). `as` is among
/// them, `via` is not. The phrasing reads as "fn returning T `as` a
/// Request::X matched by Response::Y."
///
/// **Methods that don't fit this shape** (e.g., `put_cas` with its
/// nested `Result<Result<_, CasFailure>, _>`) are hand-rolled below.
macro_rules! proxy_method {
    (
        $(#[$attr:meta])*
        fn $name:ident ( $( $arg:ident : $argty:ty ),* $(,)? )
            -> $ret:ty
            as $req_variant:ident => $resp_variant:ident
    ) => {
        impl<TR: Transport> WorkerProxy<TR> {
            $(#[$attr])*
            pub async fn $name(
                &self,
                $( $arg : $argty , )*
            ) -> Result<$ret, ProxyError> {
                if self.terminated.get() {
                    return Err(ProxyError::Terminated);
                }
                let request_id = self.alloc_id();
                let request = Request::$req_variant { request_id, $( $arg ),* };
                let rx = self.transport.send_request(request);
                match rx.await {
                    Ok(Response::$resp_variant { request_id: _, result }) => {
                        result.map_err(ProxyError::from)
                    }
                    Ok(other) => Err(ProxyError::UnexpectedResponse(format!("{:?}", other))),
                    Err(_) => Err(ProxyError::Cancelled),
                }
            }
        }
    };
}

// ---------------------------------------------------------------------------
// L1 method mirroring — one proxy_method! per Request variant.
//
// Order matches `entity_wasm_worker_protocol::REQUEST_VARIANT_NAMES`.
// `put_cas` is hand-rolled below the macro block; everything else fits.
// ---------------------------------------------------------------------------

proxy_method! {
    /// Get entity at `path` on `peer_id`'s tree. Returns `Ok(None)` for a
    /// missing binding (404).
    fn get(peer_id: String, path: String) -> Option<WireEntity>
        as Get => Get
}

proxy_method! {
    /// Put entity at `path` on `peer_id`'s tree. Returns the resulting
    /// content hash on success.
    fn put(peer_id: String, path: String, entity: WireEntity) -> WireHash
        as Put => Put
}

proxy_method! {
    /// List bindings under `prefix` on `peer_id`'s tree.
    fn list(peer_id: String, prefix: String) -> Vec<WireListingEntry>
        as List => List
}

proxy_method! {
    /// Remove the binding at `path` on `peer_id`'s tree. Returns true if a
    /// binding existed and was removed.
    fn remove(peer_id: String, path: String) -> bool
        as Remove => Remove
}

proxy_method! {
    /// Check whether a binding exists at `path` on `peer_id`'s tree.
    fn has(peer_id: String, path: String) -> bool
        as Has => Has
}

proxy_method! {
    /// Generic EXECUTE — dispatches `(handler, operation, params, opts)` to
    /// the worker's SDK against the named peer. Returns the handler's
    /// `HandlerResult` verbatim.
    fn execute(
        peer_id: String,
        handler: String,
        operation: String,
        params: WireEntity,
        opts: WireExecuteOptions,
    ) -> WireHandlerResult
        as Execute => Execute
}

proxy_method! {
    /// L1 query (SDK-OPERATIONS §5.1) — `execute("system/query", "find", ...)`
    /// with the typed-envelope parse already done worker-side.
    fn query(peer_id: String, expression: WireEntity) -> WireQueryResults
        as Query => Query
}

proxy_method! {
    /// L1 count — `execute("system/query", "count", expression, ...)`.
    /// Returns the number of matches for the query expression.
    fn count(peer_id: String, expression: WireEntity) -> u64
        as Count => Count
}

proxy_method! {
    /// Total number of entities stored on `peer_id`'s content store.
    fn entity_count(peer_id: String) -> u64
        as EntityCount => EntityCount
}

proxy_method! {
    /// Total number of bound paths in `peer_id`'s tree.
    fn path_count(peer_id: String) -> u64
        as PathCount => PathCount
}

proxy_method! {
    /// List inbox bindings for `peer_id`. Returns entries under
    /// `system/inbox/...`.
    fn inbox_list(peer_id: String) -> Vec<WireListingEntry>
        as InboxList => InboxList
}

proxy_method! {
    /// Get an inbox entry by its path relative to the inbox root.
    fn inbox_get(peer_id: String, relative_path: String) -> Option<WireEntity>
        as InboxGet => InboxGet
}

proxy_method! {
    /// Discover registered handlers on `peer_id` (SDK-OPERATIONS §9.1).
    fn discover_handlers(peer_id: String) -> Vec<WireHandlerInfo>
        as DiscoverHandlers => DiscoverHandlers
}

proxy_method! {
    /// Discover registered types on `peer_id` (SDK-OPERATIONS §9.2).
    fn discover_types(peer_id: String) -> Vec<WireTypeInfo>
        as DiscoverTypes => DiscoverTypes
}

// ---------------------------------------------------------------------------
// Hand-rolled methods — don't fit the proxy_method! shape.
// ---------------------------------------------------------------------------

impl<T: Transport> WorkerProxy<T> {
    /// Compare-and-swap put on `peer_id`'s tree at `path`. If the path's
    /// current binding equals `expected`, replaces it with `entity` and
    /// returns the resulting hash. Otherwise returns `CasFailure`:
    ///
    /// - `Mismatch { actual: Some(_) }` — a binding exists but its hash
    ///   differs from `expected`.
    /// - `NotFound { actual: None }` — no binding exists at `path`.
    ///
    /// Returns `Err(ProxyError::Worker { .. })` for non-CAS transport or
    /// dispatch failures (capability denied, internal error, etc.).
    ///
    /// Hand-rolled because the nested `Result<Result<_, CasFailure>, _>`
    /// doesn't fit the `proxy_method!` macro shape: the outer Result is
    /// the generic worker-error wrap; the inner is the typed CAS outcome.
    pub async fn put_cas(
        &self,
        peer_id: String,
        path: String,
        entity: WireEntity,
        expected: WireHash,
    ) -> Result<Result<WireHash, CasFailure>, ProxyError> {
        if self.terminated.get() {
            return Err(ProxyError::Terminated);
        }
        let request_id = self.alloc_id();
        let request = Request::PutCas { request_id, peer_id, path, entity, expected };
        let rx = self.transport.send_request(request);
        match rx.await {
            Ok(Response::PutCas { request_id: _, result }) => result.map_err(ProxyError::from),
            Ok(other) => Err(ProxyError::UnexpectedResponse(format!("{:?}", other))),
            Err(_) => Err(ProxyError::Cancelled),
        }
    }

    /// Create a new peer inside the worker. Returns the new peer's id,
    /// the freshly-generated keypair seed (32 bytes), and the metadata
    /// the worker installed. The seed is the consumer's responsibility
    /// to persist (typically via localStorage) for reload survival —
    /// the host does NOT retain it server-side.
    pub async fn create_peer(
        &self,
        label: Option<String>,
    ) -> Result<CreatePeerOk, ProxyError> {
        if self.terminated.get() {
            return Err(ProxyError::Terminated);
        }
        let request_id = self.alloc_id();
        let request = Request::CreatePeer { request_id, label };
        let rx = self.transport.send_request(request);
        match rx.await {
            Ok(Response::CreatePeer { request_id: _, result }) => result.map_err(ProxyError::from),
            Ok(other) => Err(ProxyError::UnexpectedResponse(format!("{:?}", other))),
            Err(_) => Err(ProxyError::Cancelled),
        }
    }

    /// Delete a peer by id. Errors if the id is unknown to the worker
    /// or refers to the primary peer (which the SDK refuses to remove).
    pub async fn delete_peer(&self, peer_id: String) -> Result<(), ProxyError> {
        if self.terminated.get() {
            return Err(ProxyError::Terminated);
        }
        let request_id = self.alloc_id();
        let request = Request::DeletePeer { request_id, peer_id };
        let rx = self.transport.send_request(request);
        match rx.await {
            Ok(Response::DeletePeer { request_id: _, result }) => match result {
                None => Ok(()),
                Some(e) => Err(ProxyError::from(e)),
            },
            Ok(other) => Err(ProxyError::UnexpectedResponse(format!("{:?}", other))),
            Err(_) => Err(ProxyError::Cancelled),
        }
    }

    /// Update an existing peer's metadata (label / listen_addresses /
    /// persisted flag). Returns an error if `peer_id` is unknown to the
    /// worker. Wraps `EntitySDK::set_metadata`.
    pub async fn set_metadata(
        &self,
        peer_id: String,
        metadata: WirePeerMetadata,
    ) -> Result<(), ProxyError> {
        if self.terminated.get() {
            return Err(ProxyError::Terminated);
        }
        let request_id = self.alloc_id();
        let request = Request::SetMetadata { request_id, peer_id, metadata };
        let rx = self.transport.send_request(request);
        match rx.await {
            Ok(Response::SetMetadata { request_id: _, result }) => match result {
                None => Ok(()),
                Some(e) => Err(ProxyError::from(e)),
            },
            Ok(other) => Err(ProxyError::UnexpectedResponse(format!("{:?}", other))),
            Err(_) => Err(ProxyError::Cancelled),
        }
    }

    /// Open an outgoing connection from a local peer to a remote peer at
    /// `address` (`ws://...` or `wss://...` in browser worker mode) and
    /// run the entity-protocol handshake. Returns the remote peer's id
    /// so the consumer can dispatch to `entity://{remote_peer_id}/...`
    /// URIs through the proxy's `execute()`.
    pub async fn connect_peer(
        &self,
        peer_id: String,
        address: String,
    ) -> Result<ConnectPeerOk, ProxyError> {
        if self.terminated.get() {
            return Err(ProxyError::Terminated);
        }
        let request_id = self.alloc_id();
        let request = Request::ConnectPeer { request_id, peer_id, address };
        let rx = self.transport.send_request(request);
        match rx.await {
            Ok(Response::ConnectPeer { request_id: _, result }) => result.map_err(ProxyError::from),
            Ok(other) => Err(ProxyError::UnexpectedResponse(format!("{:?}", other))),
            Err(_) => Err(ProxyError::Cancelled),
        }
    }
}

// `Subscribe` / `Unsubscribe` are wire variants but NOT macro-generated —
// they don't return a single response; they establish a stream. Implemented
// alongside the cache layer with the bespoke channel-returning shape.

// ---------------------------------------------------------------------------
// S3 — put_and_wait_for_cache ergonomic helper (Phase 1 body)
// ---------------------------------------------------------------------------

impl<T: Transport> WorkerProxy<T> {
    /// Ergonomic helper for state-machine flows that genuinely need to await
    /// cache reflection before continuing. Equivalent to:
    ///
    /// 1. Issue `put(peer_id, path, entity)`.
    /// 2. Wait for one `Event::Change` for this path on the relevant
    ///    subscription.
    /// 3. Return.
    ///
    /// **Not load-bearing.** Most consumers should use plain `put` and let
    /// the next render cycle (driven by the cache's notification channel)
    /// pick up the new value — that is the canonical event-driven pattern
    /// and avoids the synchronization overhead of this helper. This method
    /// exists for cases where a multi-step state machine genuinely needs to
    /// proceed only after the cache reflects the write — typically tests,
    /// migration scripts, or sequential setup flows.
    ///
    /// Returns `ProxyError::Transport` with a timeout-flavored message if
    /// the change event does not arrive within `timeout_ms` (500 ms is a
    /// reasonable default; events propagate sub-ms in practice).
    ///
    /// **Implementation**: polls the cache at 5 ms intervals after the
    /// put completes, checking whether `cache_get(path)` returns an entity
    /// whose hash matches the put's resulting hash. If no active
    /// subscription covers `path`, returns the hash immediately (degenerate
    /// to plain `put` — there's nothing for the cache to reflect to).
    ///
    /// 5 ms polling is a deliberate choice over coordinating a temporary
    /// listener on the live subscription's `NotifyChannel`: each
    /// subscription has exactly one channel and one consumer, so we'd
    /// need a fan-out scheme to add a temporary watcher. Polling is
    /// trivially correct and burns negligible CPU for a helper that's
    /// only used in setup/state-machine flows, not per-frame.
    pub async fn put_and_wait_for_cache(
        &self,
        peer_id: String,
        path: String,
        entity: WireEntity,
        timeout_ms: u32,
    ) -> Result<WireHash, ProxyError> {
        // Issue the put first. If it fails, no point waiting.
        let hash = self.put(peer_id, path.clone(), entity).await?;

        // Check if any active subscription's prefix covers this path.
        // If not, we have no way to observe cache updates for it — return
        // the put's hash and let the caller decide (the usual interpretation
        // is "caller should subscribe before relying on cache reflection").
        let covered = {
            let reg = self.subscriptions.borrow();
            reg.entries
                .values()
                .any(|e| prefix_covers(&e.prefix, &path))
        };
        if !covered {
            return Ok(hash);
        }

        // Poll the cache. The demultiplexer is updating mirrors as Change
        // events arrive over the wire; we just need to see the matching
        // hash show up.
        const POLL_INTERVAL_MS: u32 = 5;
        let max_polls = (timeout_ms / POLL_INTERVAL_MS).max(1);
        for _ in 0..max_polls {
            if let Some(cached) = self.cache_get(&path) {
                if cached.content_hash.0 == hash.0 {
                    return Ok(hash);
                }
            }
            gloo_timers::future::TimeoutFuture::new(POLL_INTERVAL_MS).await;
        }

        // One final check — the cache may have updated in the last poll
        // interval after our last read.
        if let Some(cached) = self.cache_get(&path) {
            if cached.content_hash.0 == hash.0 {
                return Ok(hash);
            }
        }

        Err(ProxyError::Transport(format!(
            "put_and_wait_for_cache: timeout after {timeout_ms}ms; cache did not reflect new hash at {path}. \
             A `put` succeeded but no matching `Event::Change` was observed within the timeout. \
             Either the worker is unhealthy, or no subscription's prefix covers this path."
        )))
    }
}

// ---------------------------------------------------------------------------
// Cache + Subscriptions: observe / cache_get / cache_list / SubHandle / NotifyChannel
// ---------------------------------------------------------------------------

/// Handle to a live subscription. Dropping it:
///
/// 1. Removes the registry entry, so any in-flight events for this sub_id
///    are dropped on receipt by the demultiplexer (invariant #2).
/// 2. Posts a fire-and-forget `Request::Unsubscribe` to the worker so it
///    stops emitting events for this sub_id. The response is discarded —
///    we don't await it.
///
/// Holding the handle keeps the per-prefix mirror alive; dropping it
/// reclaims the memory and tells the worker.
pub struct SubHandle<T: Transport> {
    sub_id: SubId,
    transport: Rc<T>,
    next_request_id: Rc<Cell<RequestId>>,
    subscriptions: Rc<RefCell<SubscriptionRegistry>>,
    terminated: Rc<Cell<bool>>,
}

impl<T: Transport> Drop for SubHandle<T> {
    fn drop(&mut self) {
        // (1) Local removal first — protects against an Event::Change
        // arriving after the Unsubscribe is in flight but before the worker
        // honors it.
        self.subscriptions.borrow_mut().entries.remove(&self.sub_id);

        // (2) Fire-and-forget Unsubscribe. Skip when the proxy has been
        // terminated — the worker is dead, postMessage would be a no-op,
        // and we don't want to burn a request_id on a dead channel.
        if self.terminated.get() {
            return;
        }
        let request_id = self.next_request_id.get();
        self.next_request_id.set(request_id.wrapping_add(1));
        let req = Request::Unsubscribe { request_id, sub_id: self.sub_id };
        let _ = self.transport.send_request(req);
    }
}

/// Notification channel: wake-up signal for "something changed in this
/// subscription's prefix; re-read the cache."
///
/// Bounded mpsc, capacity 1, newest-wins (R2). Consumers typically wire
/// this to a per-window dirty flag and re-render on the next frame.
pub struct NotifyChannel {
    rx: mpsc::Receiver<()>,
}

/// Per-event delivery channel for [`WorkerProxy::observe_with_events`].
/// Each `ChangeEvent` corresponds to one entity-tree mutation under the
/// subscribed prefix; consumers can drive incremental data structures
/// (e.g., the workbench `EntityTreeModel`) in O(depth) per event instead
/// of O(N) per notify-tick.
///
/// Bounded mpsc, capacity 64. On overflow, dropped events are tallied
/// and surfaced as `ChangeEvent::Lagged { count }` once the channel
/// drains — consumers seeing `Lagged` should resync via
/// [`WorkerProxy::cache_list`] and continue consuming. The proxy's
/// internal mirror is never affected by event-channel overflow; the
/// channel is purely a notification surface.
pub struct EventChannel {
    rx: mpsc::Receiver<ChangeEvent>,
}

impl EventChannel {
    /// Await the next event. Returns `None` if the subscription has
    /// closed (worker death, `Event::SubscriptionLost`, or `SubHandle`
    /// dropped).
    pub async fn next(&mut self) -> Option<ChangeEvent> {
        self.rx.next().await
    }

    /// Non-blocking poll. `Some(event)` means one was pending and has
    /// been consumed; `None` means either nothing was waiting or the
    /// channel has closed.
    pub fn try_next(&mut self) -> Option<ChangeEvent> {
        self.rx.try_recv().ok()
    }
}

impl NotifyChannel {
    /// Await the next notification. Returns `None` if the subscription has
    /// closed (worker death, `Event::SubscriptionLost`, or `SubHandle`
    /// dropped). Consumers seeing `None` should treat the cache as stale
    /// and either resubscribe or surface the loss to the user.
    pub async fn next(&mut self) -> Option<()> {
        self.rx.next().await
    }

    /// Non-blocking poll. `Some(())` means a notification was pending and
    /// has been consumed; `None` means either nothing was waiting or the
    /// channel has closed. Distinguish by calling [`Self::next`] — if the
    /// channel is closed, `next().await` returns `None` immediately.
    pub fn try_next(&mut self) -> Option<()> {
        // `try_recv` returns `Result<(), TryRecvError>` — the discriminant
        // IS the "anything there?" answer. `.ok()` converts to Option<()>.
        self.rx.try_recv().ok()
    }
}

impl<T: Transport + 'static> WorkerProxy<T> {
    /// Establish a subscription on `peer_id` / `prefix`. Returns a
    /// [`SubHandle`] (drop to cancel) and a [`NotifyChannel`] (await to
    /// wake when the subscription's mirror has updated).
    ///
    /// `peer_id` selects the local peer whose L1 dispatch engine the
    /// callback is registered against. Each peer has its own engine; a
    /// subscription is bound to exactly one peer. Pass the SDK's
    /// `default_peer_id()` explicitly if you want the primary peer.
    ///
    /// **Invariant #1 honored:** the registry entry is created *before*
    /// the `Request::Subscribe` is sent, so any `Event` arriving for this
    /// sub_id between request and response is already routable. The
    /// initial `Event::Snapshot` is guaranteed to arrive before any
    /// `Event::Change` for the same sub_id (worker-side contract); the
    /// demultiplexer enforces this by ignoring `Change` events until
    /// `snapshot_received` is true.
    pub async fn observe(
        &self,
        peer_id: String,
        prefix: String,
    ) -> Result<(SubHandle<T>, NotifyChannel), ProxyError> {
        if self.terminated.get() {
            return Err(ProxyError::Terminated);
        }
        let sub_id = self.alloc_sub_id();

        // Insert the registry entry BEFORE the subscribe request goes out.
        // This is invariant #1 in action: we must be ready to receive
        // events as soon as the worker starts emitting them.
        let (notify_tx, notify_rx) = mpsc::channel(1);
        {
            let mut reg = self.subscriptions.borrow_mut();
            reg.entries.insert(
                sub_id,
                SubscriptionEntry {
                    prefix: prefix.clone(),
                    mirror: BTreeMap::new(),
                    notify_tx,
                    event_tx: None,
                    pending_lag: 0,
                    snapshot_received: false,
                },
            );
        }

        // Send the subscribe request. On failure, roll back the registry
        // entry so we don't leak a phantom subscription.
        let request_id = self.alloc_id();
        let request = Request::Subscribe { request_id, sub_id, peer_id, prefix };
        let rx = self.transport.send_request(request);
        let response = rx.await;
        match response {
            Ok(Response::Subscribe { request_id: _, result }) => {
                if let Some(e) = result {
                    self.subscriptions.borrow_mut().entries.remove(&sub_id);
                    return Err(ProxyError::from(e));
                }
            }
            Ok(other) => {
                self.subscriptions.borrow_mut().entries.remove(&sub_id);
                return Err(ProxyError::UnexpectedResponse(format!("{:?}", other)));
            }
            Err(_) => {
                self.subscriptions.borrow_mut().entries.remove(&sub_id);
                return Err(ProxyError::Cancelled);
            }
        }

        let handle = SubHandle {
            sub_id,
            transport: self.transport.clone(),
            next_request_id: self.next_request_id.clone(),
            subscriptions: self.subscriptions.clone(),
            terminated: self.terminated.clone(),
        };
        Ok((handle, NotifyChannel { rx: notify_rx }))
    }

    /// Like [`observe`](Self::observe) but delivers per-event
    /// [`ChangeEvent`]s instead of unit notifications, so consumers can
    /// drive incremental data structures in O(depth) per write rather
    /// than O(N) per dirty tick.
    ///
    /// Mirrors the Direct-arm `entity_sdk::PeerContext::on_prefix_change_seeded`
    /// shape so consumer code is portable across deployment modes.
    /// **Seed phase:** the proxy synthesizes one `ChangeEvent::Created`
    /// per path in the initial snapshot before forwarding live changes.
    /// **Live phase:** each `Event::Change` from the worker becomes one
    /// `ChangeEvent::{Created, Updated, Removed}`, derived from the
    /// pre-mutation mirror state for `previous_hash`. Consumers can't
    /// distinguish seed events from live by anything other than
    /// arrival order — which is fine, the contract is idempotent.
    ///
    /// **Overflow:** the event channel is bounded mpsc(64). Dropped
    /// events are tallied and surfaced as `ChangeEvent::Lagged { count }`
    /// on the next successful send. The mirror is unaffected; consumers
    /// recover via `cache_list(prefix)`.
    ///
    /// **Both channels delivered.** This call returns the same
    /// `NotifyChannel` as [`observe`] *and* an `EventChannel`. Consumers
    /// can ignore the notify channel if they only want per-event
    /// delivery, but it's there for free if they want both.
    pub async fn observe_with_events(
        &self,
        peer_id: String,
        prefix: String,
    ) -> Result<(SubHandle<T>, NotifyChannel, EventChannel), ProxyError> {
        if self.terminated.get() {
            return Err(ProxyError::Terminated);
        }
        let sub_id = self.alloc_sub_id();

        let (notify_tx, notify_rx) = mpsc::channel(1);
        let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        {
            let mut reg = self.subscriptions.borrow_mut();
            reg.entries.insert(
                sub_id,
                SubscriptionEntry {
                    prefix: prefix.clone(),
                    mirror: BTreeMap::new(),
                    notify_tx,
                    event_tx: Some(event_tx),
                    pending_lag: 0,
                    snapshot_received: false,
                },
            );
        }

        let request_id = self.alloc_id();
        let request = Request::Subscribe { request_id, sub_id, peer_id, prefix };
        let rx = self.transport.send_request(request);
        let response = rx.await;
        match response {
            Ok(Response::Subscribe { request_id: _, result }) => {
                if let Some(e) = result {
                    self.subscriptions.borrow_mut().entries.remove(&sub_id);
                    return Err(ProxyError::from(e));
                }
            }
            Ok(other) => {
                self.subscriptions.borrow_mut().entries.remove(&sub_id);
                return Err(ProxyError::UnexpectedResponse(format!("{:?}", other)));
            }
            Err(_) => {
                self.subscriptions.borrow_mut().entries.remove(&sub_id);
                return Err(ProxyError::Cancelled);
            }
        }

        let handle = SubHandle {
            sub_id,
            transport: self.transport.clone(),
            next_request_id: self.next_request_id.clone(),
            subscriptions: self.subscriptions.clone(),
            terminated: self.terminated.clone(),
        };
        Ok((handle, NotifyChannel { rx: notify_rx }, EventChannel { rx: event_rx }))
    }

    /// Tear down the worker.
    ///
    /// Flips the proxy's `terminated` flag (subsequent L1 calls return
    /// [`ProxyError::Terminated`]) and invokes `Transport::terminate()`,
    /// which on the real `WebTransport` calls `Worker.terminate()` on the
    /// JS handle and drops every pending request sender. In-flight
    /// awaiters observe [`ProxyError::Cancelled`] (their oneshot
    /// receivers see the sender drop). Active subscriptions remain in
    /// the registry — drop the corresponding [`SubHandle`]s to reclaim
    /// memory; the unsubscribe postMessage is skipped post-terminate.
    /// Idempotent.
    ///
    /// **OPFS durability:** safe. Every committed write through
    /// `OpfsContentStore::put` and `OpfsLocationIndex::set/remove` does
    /// `append_and_flush` synchronously before the call returns, so the
    /// browser's abrupt `Worker.terminate()` cannot lose acknowledged
    /// writes. No worker-side shutdown handler is required.
    pub fn terminate(&self) {
        if self.terminated.get() {
            return;
        }
        self.terminated.set(true);
        self.transport.terminate();
    }
}

/// Does the live subscription registered with wire `prefix` deliver
/// `Event::Change` for `path`?
///
/// This is the EXACT composition of the two authoritative functions that
/// govern live delivery on the worker side, replicated here because the
/// proxy can't call into the worker:
///
///   `entity_subscription::engine::pattern_matches(`
///       `wasm_worker_host::prefix_to_pattern(prefix), path)`
///
/// Keep this byte-for-byte equivalent to those two functions. If either
/// changes, change this. Inlined composition:
///
/// `prefix_to_pattern`: `"*"` or `".../*"` → unchanged; trailing `'/'`
///   → append `"*"`; else → unchanged.
/// `pattern_matches`: `"*"` → all; `pat.strip_suffix("/*")` = `stem`
///   → `path.starts_with(stem) && path.len() > stem.len()` (note: NO
///   path-segment-boundary requirement — `/a/b/*` matches `/a/bc`); else
///   → `pattern == path` (exact).
///
/// NOTE: this governs LIVE delivery only. The initial `Event::Snapshot`
/// is built host-side from a raw `list_entities(prefix)` prefix scan,
/// which is BROADER than this for non-subtree prefixes (an exact-match
/// wire prefix `/a/b/state` snapshots `/a/b/state2` too, but never live-
/// updates it). Gating reads by this predicate is deliberate: it hides
/// snapshot-only siblings that will never receive a `Change`, so a
/// `cache_get` never returns a value the worker won't keep current. See
/// `docs/SPEC-AMBIGUITIES.md` "worker snapshot/live mirror-population
/// asymmetry".
fn prefix_covers(prefix: &str, path: &str) -> bool {
    if prefix == "*" {
        return true;
    }
    // prefix_to_pattern then pattern_matches, fused. A wire prefix that
    // already ends "/*" and one that ends "/" both become pattern ".../*"
    // → same stem (the part before the trailing "/" or "/*").
    let stem = prefix
        .strip_suffix("/*")
        .or_else(|| prefix.strip_suffix('/'));
    match stem {
        // Subtree pattern: starts_with(stem) AND strictly longer. No
        // segment boundary — mirrors pattern_matches exactly.
        Some(stem) => path.starts_with(stem) && path.len() > stem.len(),
        // No trailing "/" or "/*" → exact pattern, literal equality.
        None => path == prefix,
    }
}

impl<T: Transport> WorkerProxy<T> {
    /// Synchronous cache read. Returns the cached entity at `path` if any
    /// active subscription's prefix covers it.
    ///
    /// **Invariant #4 reminder:** this reflects the most recent
    /// `Event::Change` applied to the mirror — NOT the result of any
    /// in-flight `put`. Don't write-then-immediately-read this. The right
    /// pattern is "write, return, let the next render cycle pick up the
    /// new value."
    ///
    /// **Invariant #6 reminder:** this read is always consistent with the
    /// worker's view as of the most recent `Event::Change` *that has been
    /// processed by the demultiplexer*. Notifications can lag (capacity-1
    /// mpsc), but the mirror cannot.
    pub fn cache_get(&self, path: &str) -> Option<WireEntity> {
        let reg = self.subscriptions.borrow();
        for entry in reg.entries.values() {
            if prefix_covers(&entry.prefix, path) {
                if let Some(e) = entry.mirror.get(path) {
                    return Some(e.clone());
                }
            }
        }
        None
    }

    /// Synchronous prefix scan over the cache. Returns all `(path, entity)`
    /// pairs whose path starts with the caller's query `prefix`, sorted by
    /// path, with duplicates from overlapping subscriptions collapsed
    /// (first occurrence wins — which, since they're sorted, is alphabetic
    /// first).
    ///
    /// A mirror entry is only included if its owning subscription actually
    /// live-covers it (`prefix_covers`). Without this gate, snapshot-only
    /// siblings of an exact-match subscription (see `prefix_covers` doc and
    /// `docs/SPEC-AMBIGUITIES.md` "worker snapshot/live mirror-population
    /// asymmetry") would leak into results as values the worker never keeps
    /// current. The caller's `prefix` is a separate, plain string filter
    /// over what's covered — it is NOT subscription-pattern syntax.
    pub fn cache_list(&self, prefix: &str) -> Vec<(String, WireEntity)> {
        let reg = self.subscriptions.borrow();
        let mut results: Vec<(String, WireEntity)> = Vec::new();
        for entry in reg.entries.values() {
            for (path, entity) in &entry.mirror {
                if path.starts_with(prefix) && prefix_covers(&entry.prefix, path) {
                    results.push((path.clone(), entity.clone()));
                }
            }
        }
        results.sort_by(|a, b| a.0.cmp(&b.0));
        results.dedup_by(|a, b| a.0 == b.0);
        results
    }
}
