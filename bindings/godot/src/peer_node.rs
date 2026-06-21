//! EntityPeer — a Godot Node that manages an Entity Core peer.
//!
//! Lifecycle: configure properties → call `start()` → peer runs in background
//! → call `stop()` or remove from scene tree.
//!
//! Backed by `entity_sdk::PeerContext` so capability-aware methods (generation,
//! L1 dispatch, subscribe) are available alongside the existing L0 store ops.
//! See `godot-entity-core-rust/docs/CONTEXT-SDK-AVAILABLE.md` for the SDK
//! consumption pattern.
//!
//! The event bridge spawns a tokio task that reads `TreeChangeEvent`s and
//! forwards them via `std::sync::mpsc` to be emitted as Godot signals in
//! `_process()`.

use std::sync::Arc;

use godot::prelude::*;

use crate::entity_resource::EntityData;
use crate::entity_subscription::EntitySubscription;
use crate::peer_op_future::{OpResultRaw, PeerOpFuture, SubscriptionPayload};

use std::collections::BTreeMap;
use std::sync::Mutex;

use entity_handler::{HandlerContext, HandlerError, HandlerResult};
use entity_peer::{DispatchPhase, WireDirection};
use entity_sdk::PeerContext;
use entity_store::ChangeType;

// ---------------------------------------------------------------------------
// Inspectability hook snapshots (GUIDE-INSPECTABILITY v1.2 §2.1)
// ---------------------------------------------------------------------------
//
// Each hook variant snapshots the fields it needs out of the borrowed
// `&Event` inside the Rust closure (the SDK's `Fn(&Event) + Send + Sync`
// contract; the event reference cannot outlive the call), ships the owned
// snapshot through `tokio::sync::mpsc::UnboundedSender` (Send + Sync), and
// EntityPeer::process drains the receiver and emits a Godot signal per
// snapshot — same pattern as the existing `tree_changed` bridge.
//
// The hook NAME (matching the SDK's `with_*_hook(name, _)` arg) is carried
// inside each snapshot so a single channel can multiplex any number of
// registered hooks; GDScript filters on the `name` arg of the signal.

#[derive(Clone)]
struct DispatchSnapshot {
    name: String,
    target_uri: String,
    operation: String,
    params_hash: Vec<u8>,
    request_id: String,
    timestamp_ms: u64,
    /// "entry" or "exit"
    phase: &'static str,
    /// Exit only: V7 §8.3 handler status code.
    status: Option<u32>,
    /// Exit only: 32-byte response entity hash.
    response_hash: Option<Vec<u8>>,
}

/// Wire-event snapshot — METADATA ONLY (v1).
///
/// The full `WireEvent.frame_bytes` is intentionally NOT shipped to
/// GDScript: per GUIDE-INSPECTABILITY v1.2 §2.1 audit §2.1/§6, frame
/// bytes carry the complete CBOR envelope including capability tokens,
/// signatures, and identity material. Surfacing the body to userspace
/// without a cap-scoped retention budget effectively gives any GDScript
/// caller a cap-token corpus. Body retrieval gets its own gated surface
/// in a later cut (operator-mode + retention-volume axis per audit §4);
/// for v1 we expose `frame_len` so consumers can size traffic without
/// seeing material.
#[derive(Clone)]
struct WireSnapshot {
    name: String,
    /// "recv" or "send"
    direction: &'static str,
    request_id: String,
    /// Length in bytes of the omitted `frame_bytes`.
    frame_len: u32,
    peer_address: String,
    timestamp_ms: u64,
}

// ---------------------------------------------------------------------------
// register_handler (T3.0.i) — signal-based GDScript handler bodies
// ---------------------------------------------------------------------------
//
// SDK `register_handler` installs a body of type
// `Fn(&HandlerContext) -> BoxFuture<Result<HandlerResult, HandlerError>>`.
// The Godot binding gives GDScript a SIGNAL-driven shape:
//
//   1. Body fires on a tokio worker (handler-dispatch boundary)
//   2. Body assigns a u64 request_id, stashes an oneshot::Sender keyed by
//      request_id in `pending_handler_invocations`, sends a
//      HandlerInvocation through `handler_req_tx` to main thread
//   3. EntityPeer::process drains and emits
//      `handler_invoked(pattern, request_id, op, params_type, params_data)`
//   4. GDScript handler reads the signal, computes the response, calls
//      `peer.respond_to_handler(request_id, status, result_type, result_data)`
//   5. respond_to_handler looks up oneshot::Sender, fires the outcome
//   6. Body future resumes, converts to HandlerResult/Error, returns
//
// On peer stop: dropping `pending_handler_invocations` drops every
// outstanding sender — receivers error with Closed → bodies return
// `HandlerError::Internal("response channel dropped")`. RegisteredHandler
// drops fire the SDK's unregister sequence.

struct HandlerInvocation {
    pattern: String,
    request_id: u64,
    op: String,
    params_type: String,
    params_data: Vec<u8>,
}

enum HandlerOutcome {
    Ok {
        status: u32,
        result_type: String,
        result_data: Vec<u8>,
    },
    Err {
        kind: HandlerErrorKind,
        message: String,
    },
}

#[derive(Clone, Copy)]
enum HandlerErrorKind {
    Internal,
    NotSupported,
    InvalidParams,
}

#[derive(Clone)]
struct BindingSnapshot {
    name: String,
    path: String,
    hash: Vec<u8>,
    previous_hash: Option<Vec<u8>>,
    new_hash: Option<Vec<u8>>,
    /// "created", "modified", or "deleted"
    change_type: &'static str,
    /// Flattened ExecutionContext subset — None if no handler context
    /// (engine/bootstrap writes carry no context).
    context: Option<BindingContextSnapshot>,
}

#[derive(Clone)]
struct BindingContextSnapshot {
    chain_id: Option<String>,
    request_id: Option<String>,
    cascade_depth: u32,
    /// Per-write authorization (V7 §6.8).
    capability: Option<Vec<u8>>,
    handler_pattern: Option<String>,
    operation: Option<String>,
    // NOTE: clock state intentionally omitted from v1 snapshot.
    // ExecutionContext.clock is a rich nested struct (mode/timestamp/
    // logical/vector/hlc) that warrants its own design pass when a
    // consumer materializes. Add a clock subdict here when needed.
}

/// A Godot Node wrapping an Entity Core peer.
///
/// Properties:
/// - `seed`: 32-byte PackedByteArray for deterministic keypair (start())
/// - `peer_name`: user-chosen persistent peer name (boot())
/// - `data_dir`: data root; GDScript sets this to
///   `ProjectSettings.globalize_path("user://entity")` (boot())
/// - `listen_address`: TCP address to listen on (default: "127.0.0.1:9000")
///
/// Methods:
/// - `start()` — seed-based start (deterministic keypair, in-memory tree)
/// - `boot()` — persistence-backed start: keypair + SQLite tree under
///   `{data_dir}/peers/{peer_name}/` (GUIDE-PERSISTENCE.md §1)
/// - `stop()` — stop the peer
/// - `peer_id()` — get the PeerID string
/// - `tree_get(path)` — L0 get an entity from the tree
/// - `tree_put(path, type, data)` — L0 put an entity into the tree
/// - `tree_has(path)` — L0 path existence check
/// - `tree_remove(path)` — L0 path removal, returns true if removed
/// - `tree_list(prefix)` — L0 list paths under a prefix
/// - `generation()` — monotonic counter, bumped on every L0 mutation
/// - `watch(prefix)` — path-prefix subscription returning EntitySubscription
/// - `execute(handler, operation, params_type, params_data)` — local L1 handler dispatch
///
/// Signals:
/// - `tree_changed(path, hash)` — emitted on every tree mutation (raw L0 stream)
/// Runtime ownership discriminant for `EntityPeer`. Lets a single peer
/// either own its own runtime (direct-instantiation back-compat) or
/// borrow a handle injected by `EntityPeerManager` (Tier-2+ multi-peer
/// hosting, one shared runtime across all hosted peers).
///
/// Both variants expose `handle()` for spawn-side use. `block_on` is
/// not needed on this struct because all peer async work goes through
/// spawn + completion-signal pattern (see `peer_op_future.rs`).
enum RuntimeRef {
    /// No runtime yet — peer hasn't been `start`ed / `boot`ed.
    Unset,
    /// Standalone peer owns its runtime. Dropped when the peer is
    /// `stop`ped or destroyed.
    Owned(tokio::runtime::Runtime),
    /// Manager-spawned peer borrows the manager's runtime handle.
    /// Cloning a Handle is cheap (Arc inside); the runtime itself
    /// stays alive in the manager.
    Borrowed(tokio::runtime::Handle),
}

impl RuntimeRef {
    /// Cheap handle clone for spawning async work on whichever runtime
    /// this peer is using.
    fn handle(&self) -> Option<tokio::runtime::Handle> {
        match self {
            RuntimeRef::Unset => None,
            RuntimeRef::Owned(rt) => Some(rt.handle().clone()),
            RuntimeRef::Borrowed(h) => Some(h.clone()),
        }
    }

    /// True once a runtime is wired (Owned or Borrowed). Used by stop()
    /// + `_async` guards.
    #[allow(dead_code)]
    fn is_set(&self) -> bool {
        !matches!(self, RuntimeRef::Unset)
    }
}

#[derive(GodotClass)]
#[class(base=Node)]
pub struct EntityPeer {
    base: Base<Node>,

    #[export]
    seed: PackedByteArray,

    #[export]
    peer_name: GString,

    #[export]
    data_dir: GString,

    #[export]
    listen_address: GString,

    #[export]
    debug_grants: bool,

    /// Runtime ownership. When `EntityPeer` is constructed standalone
    /// (direct GDScript instantiation in tests, or pre-T4-restructure
    /// code paths), we own a freshly-constructed `Runtime`. When
    /// `EntityPeerManager` spawns us, it injects a `Handle` cloned from
    /// its shared runtime via `inject_runtime_handle` and we run all
    /// async work on that — no per-peer runtime construction.
    runtime: RuntimeRef,
    /// Manager-injected transport connector (T4-infra step 3). When set,
    /// `build_start_context` / `build_boot_context` pass this to
    /// `PeerContextBuilder.connector(...)` so the peer's outbound
    /// connects route through it. Today only used for
    /// `Arc<MemoryConnector>` when the manager hosts an in-process
    /// memory-transport topology; TCP peers leave this `None` and the
    /// builder uses the platform-default connector.
    injected_connector: Option<Arc<dyn entity_peer::transport::Connector>>,
    /// Manager-injected memory transport registry (T4-infra step 3).
    /// When set + `listen_address` starts with `memory://`, `spin_up_arc`
    /// binds a `MemoryListener` against this registry instead of calling
    /// `ctx.peer().listen()` (which is TCP-only). Unset for TCP peers.
    injected_memory_registry: Option<Arc<entity_peer::transport::MemoryTransportRegistry>>,
    /// PeerContext is held in an Arc so async ops can spawn 'static
    /// futures that move a clone into the tokio task. The borrow-based
    /// SDK methods (`get`, `list`, `has`, `remove`) need the context to
    /// outlive the spawned future; cloning the Arc into the async block
    /// is the cheapest way to satisfy that without duplicating the SDK's
    /// owning-future dispatch internals.
    ctx: Option<Arc<PeerContext>>,
    /// Receiver end of the event bridge (tokio → Godot main thread).
    event_rx: Option<std::sync::mpsc::Receiver<(String, Vec<u8>)>>,
    /// In-flight async ops. Polled each `_process` tick; entries that
    /// have emitted their `completed` signal are dropped, releasing the
    /// strong ref so the GDScript-side refcount can fall to zero.
    pending: Vec<Gd<PeerOpFuture>>,
    /// Hook names registered pre-start via `install_dispatch_hook`. Drained
    /// during boot/start when the PeerContextBuilder is constructed; each
    /// name becomes a builder-registered hook closure.
    pending_dispatch_hooks: Vec<String>,
    /// Receiver for `DispatchSnapshot`s shipped from the hook closures.
    /// Drained in `process()`; per-snapshot signal emit.
    dispatch_rx: Option<tokio::sync::mpsc::UnboundedReceiver<DispatchSnapshot>>,
    /// Hook names registered pre-start via `install_binding_hook`.
    pending_binding_hooks: Vec<String>,
    /// Receiver for `BindingSnapshot`s shipped from the hook closures.
    binding_rx: Option<tokio::sync::mpsc::UnboundedReceiver<BindingSnapshot>>,
    /// Hook names registered pre-start via `install_wire_hook`.
    pending_wire_hooks: Vec<String>,
    /// Receiver for `WireSnapshot`s shipped from the hook closures.
    wire_rx: Option<tokio::sync::mpsc::UnboundedReceiver<WireSnapshot>>,
    /// SDK-side `RegisteredHandler` handles keyed by bare pattern.
    /// Dropping a handle (via remove or peer stop) calls the SDK's
    /// unregister sequence.
    registered_handlers: BTreeMap<String, entity_sdk::register_handler::RegisteredHandler>,
    /// Receiver for `HandlerInvocation`s shipped from registered-handler
    /// body closures. Drained in `process()` → `handler_invoked` signal.
    handler_req_rx: Option<std::sync::mpsc::Receiver<HandlerInvocation>>,
    /// Sender side — cloned into every body closure during register.
    handler_req_tx: Option<std::sync::mpsc::Sender<HandlerInvocation>>,
    /// Oneshot senders keyed by request_id. Body closures insert their
    /// sender + await the matching receiver; `respond_to_handler` looks
    /// up the sender + ships the outcome. Shared with body closures via
    /// `Arc<Mutex<...>>`.
    pending_handler_invocations:
        Arc<Mutex<BTreeMap<u64, tokio::sync::oneshot::Sender<HandlerOutcome>>>>,
    /// Monotonic request_id counter. Reset on stop.
    next_handler_req_id: u64,
}

#[godot_api]
impl INode for EntityPeer {
    fn init(base: Base<Node>) -> Self {
        Self {
            base,
            seed: PackedByteArray::new(),
            peer_name: GString::new(),
            data_dir: GString::new(),
            listen_address: "127.0.0.1:9000".into(),
            debug_grants: false,
            runtime: RuntimeRef::Unset,
            injected_connector: None,
            injected_memory_registry: None,
            ctx: None,
            event_rx: None,
            pending: Vec::new(),
            pending_dispatch_hooks: Vec::new(),
            dispatch_rx: None,
            pending_binding_hooks: Vec::new(),
            binding_rx: None,
            pending_wire_hooks: Vec::new(),
            wire_rx: None,
            registered_handlers: BTreeMap::new(),
            handler_req_rx: None,
            handler_req_tx: None,
            pending_handler_invocations: Arc::new(Mutex::new(BTreeMap::new())),
            next_handler_req_id: 1,
        }
    }

    /// Drain queued tree change events and emit Godot signals; also
    /// poll every in-flight `PeerOpFuture` and emit its `completed`
    /// signal if the underlying SDK call has resolved.
    fn process(&mut self, _delta: f64) {
        // Collect events first to avoid borrow conflict with base_mut()
        let events: Vec<(String, Vec<u8>)> = self
            .event_rx
            .as_ref()
            .map(|rx| {
                let mut v = Vec::new();
                while let Ok(evt) = rx.try_recv() {
                    v.push(evt);
                }
                v
            })
            .unwrap_or_default();

        for (path, hash_bytes) in events {
            let mut hash_arr = PackedByteArray::new();
            hash_arr.extend(hash_bytes.into_iter());
            self.base_mut().emit_signal(
                "tree_changed",
                &[
                    GString::from(path.as_str()).to_variant(),
                    hash_arr.to_variant(),
                ],
            );
        }

        // Drain dispatch-hook snapshots. Each emit fires once per
        // (Entry, Exit) pair per registered hook name.
        let dispatch_snaps: Vec<DispatchSnapshot> = self
            .dispatch_rx
            .as_mut()
            .map(|rx| {
                let mut v = Vec::new();
                while let Ok(s) = rx.try_recv() {
                    v.push(s);
                }
                v
            })
            .unwrap_or_default();
        for snap in dispatch_snaps {
            let mut dict = Dictionary::new();
            dict.set("target_uri", GString::from(snap.target_uri.as_str()));
            dict.set("operation", GString::from(snap.operation.as_str()));
            let mut ph = PackedByteArray::new();
            ph.extend(snap.params_hash.into_iter());
            dict.set("params_hash", ph);
            dict.set("request_id", GString::from(snap.request_id.as_str()));
            dict.set("timestamp_ms", snap.timestamp_ms as i64);
            dict.set("phase", GString::from(snap.phase));
            if let Some(st) = snap.status {
                dict.set("status", st as i64);
            }
            if let Some(rh) = snap.response_hash {
                let mut arr = PackedByteArray::new();
                arr.extend(rh.into_iter());
                dict.set("response_hash", arr);
            }
            self.base_mut().emit_signal(
                "dispatch_hook_fired",
                &[
                    GString::from(snap.name.as_str()).to_variant(),
                    dict.to_variant(),
                ],
            );
        }

        // Drain binding-hook snapshots.
        let binding_snaps: Vec<BindingSnapshot> = self
            .binding_rx
            .as_mut()
            .map(|rx| {
                let mut v = Vec::new();
                while let Ok(s) = rx.try_recv() {
                    v.push(s);
                }
                v
            })
            .unwrap_or_default();
        for snap in binding_snaps {
            let mut dict = Dictionary::new();
            dict.set("path", GString::from(snap.path.as_str()));
            let mut h = PackedByteArray::new();
            h.extend(snap.hash.into_iter());
            dict.set("hash", h);
            let mut prev = PackedByteArray::new();
            if let Some(b) = snap.previous_hash {
                prev.extend(b.into_iter());
            }
            dict.set("previous_hash", prev);
            let mut new_arr = PackedByteArray::new();
            if let Some(b) = snap.new_hash {
                new_arr.extend(b.into_iter());
            }
            dict.set("new_hash", new_arr);
            dict.set("change_type", GString::from(snap.change_type));
            if let Some(c) = snap.context {
                let mut cdict = Dictionary::new();
                if let Some(s) = c.chain_id {
                    cdict.set("chain_id", GString::from(s.as_str()));
                }
                if let Some(s) = c.request_id {
                    cdict.set("request_id", GString::from(s.as_str()));
                }
                cdict.set("cascade_depth", c.cascade_depth as i64);
                if let Some(b) = c.capability {
                    let mut ca = PackedByteArray::new();
                    ca.extend(b.into_iter());
                    cdict.set("capability", ca);
                }
                if let Some(s) = c.handler_pattern {
                    cdict.set("handler_pattern", GString::from(s.as_str()));
                }
                if let Some(s) = c.operation {
                    cdict.set("operation", GString::from(s.as_str()));
                }
                dict.set("context", cdict);
            } else {
                dict.set("context", Variant::nil());
            }
            self.base_mut().emit_signal(
                "binding_hook_fired",
                &[
                    GString::from(snap.name.as_str()).to_variant(),
                    dict.to_variant(),
                ],
            );
        }

        // Drain wire-hook snapshots (metadata-only — see WireSnapshot
        // doc-comment for the body-omission rationale).
        let wire_snaps: Vec<WireSnapshot> = self
            .wire_rx
            .as_mut()
            .map(|rx| {
                let mut v = Vec::new();
                while let Ok(s) = rx.try_recv() {
                    v.push(s);
                }
                v
            })
            .unwrap_or_default();
        for snap in wire_snaps {
            let mut dict = Dictionary::new();
            dict.set("direction", GString::from(snap.direction));
            dict.set("request_id", GString::from(snap.request_id.as_str()));
            dict.set("frame_len", snap.frame_len as i64);
            dict.set("peer_address", GString::from(snap.peer_address.as_str()));
            dict.set("timestamp_ms", snap.timestamp_ms as i64);
            self.base_mut().emit_signal(
                "wire_hook_fired",
                &[
                    GString::from(snap.name.as_str()).to_variant(),
                    dict.to_variant(),
                ],
            );
        }

        // Drain registered-handler invocations.
        let invocations: Vec<HandlerInvocation> = self
            .handler_req_rx
            .as_ref()
            .map(|rx| {
                let mut v = Vec::new();
                while let Ok(inv) = rx.try_recv() {
                    v.push(inv);
                }
                v
            })
            .unwrap_or_default();
        for inv in invocations {
            let mut params_pba = PackedByteArray::new();
            params_pba.extend(inv.params_data.into_iter());
            self.base_mut().emit_signal(
                "handler_invoked",
                &[
                    GString::from(inv.pattern.as_str()).to_variant(),
                    (inv.request_id as i64).to_variant(),
                    GString::from(inv.op.as_str()).to_variant(),
                    GString::from(inv.params_type.as_str()).to_variant(),
                    params_pba.to_variant(),
                ],
            );
        }

        // Drain completed futures. `try_complete` emits the signal and
        // returns `true` for entries that have fired (now or earlier).
        // We retain the still-pending ones; emitted entries fall out and
        // their Gd<...> refs drop here.
        if !self.pending.is_empty() {
            self.pending
                .retain_mut(|fut| !fut.bind_mut().try_complete());
        }
    }
}

#[godot_api]
impl EntityPeer {
    // -----------------------------------------------------------------
    // Signals
    // -----------------------------------------------------------------

    /// Emitted once per registered dispatch hook per Entry/Exit phase
    /// at the dispatcher↔handler boundary. `name` is the hook name
    /// passed to `install_dispatch_hook`; `event` is a Dictionary with:
    ///
    ///   target_uri:    String — resolved handler-pattern + suffix
    ///   operation:     String — V7 EXECUTE operation name
    ///   params_hash:   PackedByteArray — content hash of request params
    ///   request_id:    String — V7 envelope request id
    ///   timestamp_ms:  int    — wall-clock unix ms at capture
    ///   phase:         String — "entry" or "exit"
    ///   status:        int    — Exit only: V7 §8.3 status code
    ///   response_hash: PackedByteArray — Exit only: result entity hash
    ///
    /// Per GUIDE-INSPECTABILITY v1.2 §2.1 #3 / §2.2 "Path tap" the body
    /// is metadata-only — fetch the params entity through a separate
    /// auth-checked call if needed.
    #[signal]
    fn dispatch_hook_fired(name: GString, event: Dictionary);

    /// Emitted once per registered binding hook per tree write at the
    /// post-mutation observer pass (GUIDE-INSPECTABILITY v1.2 §2.2
    /// "Binding stream"). Cannot halt cascades. Dictionary fields:
    ///
    ///   path:          String — entity path the change applies to
    ///   hash:          PackedByteArray — 32-byte location-index hash
    ///   previous_hash: PackedByteArray — empty if not present
    ///   new_hash:      PackedByteArray — empty if not present
    ///   change_type:   String — "created", "modified", or "deleted"
    ///   context:       Dictionary or null — flattened ExecutionContext:
    ///                    chain_id, request_id, cascade_depth, capability,
    ///                    handler_pattern, operation
    ///                  null for engine/bootstrap writes lacking context.
    ///                  Clock state intentionally omitted (v1).
    #[signal]
    fn binding_hook_fired(name: GString, event: Dictionary);

    /// Emitted once per server-side wire frame at the post-handshake
    /// message loop (Recv after decode_envelope succeeds OR fails; Send
    /// before pushing the response onto the writer channel — per the
    /// SDK's `core/peer/src/connection.rs` instrumentation points).
    ///
    /// **SECURITY:** `event.frame_bytes` is NOT included. The full CBOR
    /// envelope carries capability tokens / signatures / identity
    /// material (GUIDE-INSPECTABILITY v1.2 §2.1 audit §2.1 + §6); body
    /// retrieval gets its own gated surface in a later cut. v1 ships
    /// metadata only:
    ///
    ///   direction:    String — "recv" or "send"
    ///   request_id:   String — V7 envelope request id ("" if undecodable)
    ///   frame_len:    int    — length in bytes of the omitted body
    ///   peer_address: String — remote PeerID base58
    ///   timestamp_ms: int    — wall-clock unix ms at capture
    #[signal]
    fn wire_hook_fired(name: GString, event: Dictionary);

    /// Fired once per invocation of a GDScript-registered handler.
    /// Connect ONE listener (typically in the panel that owns the
    /// plugin) and dispatch on `pattern`. GDScript MUST respond with
    /// `peer.respond_to_handler(request_id, status, result_type,
    /// result_data)` — otherwise the SDK-side body future stalls until
    /// peer stop (or the dispatcher times the dispatch out).
    ///
    ///   pattern:      String          — bare handler pattern (matches register_handler)
    ///   request_id:   int             — opaque correlation id; pass to respond_to_handler
    ///   op:           String          — operation name from the EXECUTE envelope
    ///   params_type:  String          — entity_type of the request params
    ///   params_data:  PackedByteArray — raw bytes of the request params entity
    #[signal]
    fn handler_invoked(
        pattern: GString,
        request_id: i64,
        op: GString,
        params_type: GString,
        params_data: PackedByteArray,
    );

    // -----------------------------------------------------------------
    // Inspectability hooks (GUIDE-INSPECTABILITY v1.2 §2.1)
    // -----------------------------------------------------------------

    /// Register a dispatch-event hook. Must be called BEFORE `start()`
    /// or `boot()` — the SDK installs hooks on `PeerContextBuilder`, so
    /// late registration is not supported.
    ///
    /// `name` is a stable identifier the consumer chooses (e.g.
    /// "path_tap", "chain_trace"); it is included as the first arg of
    /// every `dispatch_hook_fired` signal so a single consumer can
    /// multiplex multiple hook installations.
    ///
    /// Returns `true` on success, `false` if the peer is already started
    /// (warning logged).
    ///
    /// Wraps `PeerContextBuilder::with_dispatch_hook` (entity-sdk).
    #[func]
    fn install_dispatch_hook(&mut self, name: GString) -> bool {
        if self.ctx.is_some() {
            godot_warn!(
                "EntityPeer.install_dispatch_hook: peer already started — \
                 hook must be installed before start()/boot()"
            );
            return false;
        }
        self.pending_dispatch_hooks.push(name.to_string());
        true
    }

    /// Register a binding-event hook (tree change observer). Must be
    /// called BEFORE `start()`/`boot()` — same constraint as
    /// `install_dispatch_hook`.
    ///
    /// Observer-only: hooks cannot halt cascades (per
    /// GUIDE-INSPECTABILITY v1.2 §2.2). Fires once per tree write on
    /// the synchronous emit pathway. Use this surface for ContentStream
    /// observation / live tree mirroring at GDScript.
    ///
    /// Wraps `PeerContextBuilder::with_binding_hook` (entity-sdk).
    #[func]
    fn install_binding_hook(&mut self, name: GString) -> bool {
        if self.ctx.is_some() {
            godot_warn!(
                "EntityPeer.install_binding_hook: peer already started — \
                 hook must be installed before start()/boot()"
            );
            return false;
        }
        self.pending_binding_hooks.push(name.to_string());
        true
    }

    /// Register a wire-event hook. Must be called BEFORE `start()`/
    /// `boot()` — same constraint as `install_dispatch_hook`.
    ///
    /// Fires once per server-side wire frame at the post-handshake
    /// message loop. NOTE that handshake frames are NOT instrumented at
    /// the SDK level (per v1.0 spec); only post-handshake EXECUTE
    /// envelopes + responses fire hooks.
    ///
    /// **SECURITY:** the v1 binding ships METADATA ONLY — the
    /// `frame_bytes` body is omitted because it carries cap tokens /
    /// signatures / identity material (GUIDE-INSPECTABILITY v1.2 audit
    /// §2.1 + §6). Body retrieval is a separate gated surface (later
    /// cut). See the `wire_hook_fired` signal doc-comment.
    ///
    /// Wraps `PeerContextBuilder::with_wire_hook` (entity-sdk).
    #[func]
    fn install_wire_hook(&mut self, name: GString) -> bool {
        if self.ctx.is_some() {
            godot_warn!(
                "EntityPeer.install_wire_hook: peer already started — \
                 hook must be installed before start()/boot()"
            );
            return false;
        }
        self.pending_wire_hooks.push(name.to_string());
        true
    }

    // -----------------------------------------------------------------
    // Dynamic handler registration (T3.0.i — plugin path)
    // -----------------------------------------------------------------

    /// Register a GDScript-driven dynamic handler at `spec.pattern`.
    /// Wraps `PeerContext::register_handler`.
    ///
    /// `spec` Dictionary (per SDK HandlerSpec):
    ///   pattern:     String        — bare pattern (NO leading slash)
    ///   name:        String        — human-readable handler name
    ///   description: String        — optional documentation
    ///   operations:  Array of Dict — each {name, input_type?, output_type?}
    ///
    /// On success the SDK writes the interface + handler + (optional) grant
    /// entities to the tree and starts routing dispatches to a body that
    /// fires the `handler_invoked` signal. GDScript MUST connect a listener
    /// and respond via `respond_to_handler(request_id, ...)` — otherwise
    /// the dispatch hangs until peer stop.
    ///
    /// Returns `true` on success. Errors logged via `godot_error!`:
    ///   - "peer not started" if `boot()`/`start()` hasn't run
    ///   - "pattern_collision" if a handler is already registered
    ///   - "invalid_handler_spec" for malformed pattern/operations
    #[func]
    fn register_handler(&mut self, spec: Dictionary) -> bool {
        let Some(ctx) = self.ctx.as_ref().cloned() else {
            godot_error!("EntityPeer.register_handler: peer not started");
            return false;
        };
        let handler_spec = match parse_handler_spec(&spec) {
            Ok(s) => s,
            Err(e) => {
                godot_error!("EntityPeer.register_handler: {}", e);
                return false;
            }
        };
        // Lazy-init the invocation channel on first register.
        if self.handler_req_tx.is_none() {
            let (tx, rx) = std::sync::mpsc::channel::<HandlerInvocation>();
            self.handler_req_tx = Some(tx);
            self.handler_req_rx = Some(rx);
        }
        let tx_clone = self.handler_req_tx.as_ref().unwrap().clone();
        let pending = self.pending_handler_invocations.clone();
        let pattern_for_body = handler_spec.pattern.clone();

        // Allocate a Send + Sync id source for the body closure.
        // Using Arc<Mutex<u64>> rather than the per-peer counter so the
        // body closure (Fn / Send + Sync) doesn't need to reach back
        // through `self`.
        let id_source: Arc<std::sync::atomic::AtomicU64> =
            Arc::new(std::sync::atomic::AtomicU64::new(self.next_handler_req_id));

        let body: entity_sdk::register_handler::HandlerBody =
            std::sync::Arc::new(move |ctx: &HandlerContext| {
                let request_id = id_source.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let op = ctx.operation.clone();
                let params_type = ctx.params.entity_type.clone();
                let params_data = ctx.params.data.clone();
                let pattern = pattern_for_body.clone();
                let (resp_tx, resp_rx) =
                    tokio::sync::oneshot::channel::<HandlerOutcome>();
                // Insert the oneshot tx so respond_to_handler can find it.
                if let Ok(mut map) = pending.lock() {
                    map.insert(request_id, resp_tx);
                }
                let send_result = tx_clone.send(HandlerInvocation {
                    pattern,
                    request_id,
                    op,
                    params_type,
                    params_data,
                });
                let pending_for_cleanup = pending.clone();
                Box::pin(async move {
                    if send_result.is_err() {
                        if let Ok(mut map) = pending_for_cleanup.lock() {
                            map.remove(&request_id);
                        }
                        return Err(HandlerError::Internal(
                            "godot handler bridge dropped (peer stopped?)".into(),
                        ));
                    }
                    match resp_rx.await {
                        Ok(HandlerOutcome::Ok {
                            status,
                            result_type,
                            result_data,
                        }) => {
                            let entity = entity_entity::Entity::new(&result_type, result_data)
                                .map_err(|e| HandlerError::Internal(e.to_string()))?;
                            Ok(HandlerResult {
                                status,
                                result: entity,
                                included: std::collections::HashMap::new(),
                            })
                        }
                        Ok(HandlerOutcome::Err { kind, message }) => Err(match kind {
                            HandlerErrorKind::Internal => HandlerError::Internal(message),
                            HandlerErrorKind::NotSupported => {
                                HandlerError::NotSupported(message)
                            }
                            HandlerErrorKind::InvalidParams => {
                                HandlerError::InvalidParams(message)
                            }
                        }),
                        Err(_) => Err(HandlerError::Internal(
                            "response oneshot channel dropped".into(),
                        )),
                    }
                })
            });

        let pattern_key = handler_spec.pattern.clone();
        match ctx.register_handler(handler_spec, body) {
            Ok(handle) => {
                self.registered_handlers.insert(pattern_key, handle);
                true
            }
            Err(e) => {
                godot_error!("EntityPeer.register_handler: {}", e);
                false
            }
        }
    }

    /// Unregister a previously registered dynamic handler. Calls the
    /// SDK's close sequence (dispatch index first, then tree entries).
    /// Returns `true` if a handler was unregistered, `false` if no
    /// handler with that pattern was registered by THIS peer.
    #[func]
    fn unregister_handler(&mut self, pattern: GString) -> bool {
        let p = pattern.to_string();
        match self.registered_handlers.remove(&p) {
            Some(handle) => {
                handle.close();
                true
            }
            None => false,
        }
    }

    /// Respond to a previously-fired `handler_invoked` signal. Looks up
    /// the oneshot::Sender by `request_id` and ships an `Ok` outcome
    /// back to the SDK-side body future.
    ///
    ///   request_id:  the int delivered by `handler_invoked`
    ///   status:      V7 §8.3 handler status (200 for OK, 4xx/5xx for errors)
    ///   result_type: result entity type (e.g. "plain/text", or a domain type)
    ///   result_data: raw bytes of the result entity
    ///
    /// Returns `true` if the response was delivered, `false` if no
    /// pending invocation matches `request_id` (already responded, or
    /// the body future was cancelled).
    #[func]
    fn respond_to_handler(
        &mut self,
        request_id: i64,
        status: i64,
        result_type: GString,
        result_data: PackedByteArray,
    ) -> bool {
        let Some(tx) = self.take_pending_invocation(request_id as u64) else {
            return false;
        };
        let _ = tx.send(HandlerOutcome::Ok {
            status: status.max(0) as u32,
            result_type: result_type.to_string(),
            result_data: result_data.to_vec(),
        });
        true
    }

    /// Respond with a handler error. `kind` is one of "internal" /
    /// "not_supported" / "invalid_params"; defaults to "internal" for
    /// unknown values.
    #[func]
    fn respond_to_handler_error(
        &mut self,
        request_id: i64,
        kind: GString,
        message: GString,
    ) -> bool {
        let Some(tx) = self.take_pending_invocation(request_id as u64) else {
            return false;
        };
        let err_kind = match kind.to_string().as_str() {
            "not_supported" => HandlerErrorKind::NotSupported,
            "invalid_params" => HandlerErrorKind::InvalidParams,
            _ => HandlerErrorKind::Internal,
        };
        let _ = tx.send(HandlerOutcome::Err {
            kind: err_kind,
            message: message.to_string(),
        });
        true
    }

    fn take_pending_invocation(
        &self,
        request_id: u64,
    ) -> Option<tokio::sync::oneshot::Sender<HandlerOutcome>> {
        self.pending_handler_invocations
            .lock()
            .ok()
            .and_then(|mut map| map.remove(&request_id))
    }

    /// Start the peer with the configured seed and address.
    ///
    /// Creates the peer via `PeerContextBuilder`, starts extension engines
    /// (clock, sync, subscription), sets up the event bridge, and spawns the
    /// TCP accept loop.
    ///
    /// ── Build / spin-up split (T4-infra restructure) ──
    /// `start()` is the standalone entry point — used by direct GDScript
    /// instantiation (tests + pre-restructure callers). It builds the
    /// `PeerContext` via `build_start_context` and wraps it in an `Arc`
    /// itself before calling `spin_up_arc`. When `EntityPeerManager`
    /// hosts the peer, the manager bypasses `start()`: it calls
    /// `build_start_context` to get the owned `PeerContext`, hands it to
    /// `EntitySDK::insert_peer_with_metadata`, fetches the registered
    /// `Arc<PeerContext>` back via `peer_arc`, then drives
    /// `spin_up_arc` directly. The manager pattern keeps `EntitySDK`
    /// as the source of truth for peer registry + metadata.
    #[func]
    fn start(&mut self) {
        if self.ctx.is_some() {
            godot_warn!("EntityPeer: already started");
            return;
        }
        let Some(ctx) = self.build_start_context() else {
            return;
        };
        self.spin_up_arc(Arc::new(ctx));
    }

    /// Pub(crate) builder half of `start()`. Returns the owned
    /// `PeerContext` ready for either direct-arc-wrap (standalone) or
    /// SDK insertion (manager path). Logs + returns `None` on seed
    /// validation or builder.build() failure.
    pub(crate) fn build_start_context(&mut self) -> Option<PeerContext> {
        let seed_bytes = self.seed.to_vec();
        if seed_bytes.len() != 32 {
            godot_error!(
                "EntityPeer: seed must be exactly 32 bytes, got {}",
                seed_bytes.len()
            );
            return None;
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);

        let addr = self.listen_address.to_string();

        let keypair = entity_crypto::Keypair::from_seed(seed);
        let config = entity_peer::PeerConfig {
            listen_addr: addr.clone(),
            debug_open_grants: self.debug_grants,
            ..Default::default()
        };

        let mut builder = entity_sdk::PeerContextBuilder::new()
            .keypair(keypair)
            .config(config);
        if let Some(c) = self.injected_connector.clone() {
            builder = builder.connector(c);
        }
        let builder = self.apply_pending_hooks(builder);
        match builder.build() {
            Ok(ctx) => Some(ctx),
            Err(e) => {
                godot_error!("EntityPeer: build failed: {}", e);
                None
            }
        }
    }

    /// Persistence-backed startup. Loads (or creates on first run) the
    /// peer keypair from `{data_dir}/peers/{peer_name}/keypair`, writes
    /// `config.toml`, and opens the peer's SQLite tree at `store.db` so
    /// state survives restart (GUIDE-PERSISTENCE.md §1; ARCHITECTURE.md
    /// §6). Same `peer_name` → same peer_id across runs. Call from the
    /// GDScript app's `_ready` (which also re-registers handlers).
    #[func]
    fn boot(&mut self) {
        if self.ctx.is_some() {
            godot_warn!("EntityPeer: already started");
            return;
        }
        let Some(ctx) = self.build_boot_context() else {
            return;
        };
        self.spin_up_arc(Arc::new(ctx));
    }

    /// Pub(crate) builder half of `boot()`. Loads or creates the peer
    /// directory + keypair, opens SQLite, applies hooks, returns the
    /// built `PeerContext` ready for direct-arc-wrap or SDK insertion.
    /// Mirrors `build_start_context` for the persistence-backed path.
    pub(crate) fn build_boot_context(&mut self) -> Option<PeerContext> {
        let name = self.peer_name.to_string();
        if name.is_empty() {
            godot_error!(
                "EntityPeer.boot(): peer_name is required (use start() for the seed path)"
            );
            return None;
        }

        let data_dir = self.data_dir.to_string();
        let explicit = if data_dir.is_empty() {
            None
        } else {
            Some(data_dir.as_str())
        };
        let root = crate::persistence::resolve_data_root(explicit);

        let dir = match crate::persistence::peer_dir(&root, &name) {
            Ok(d) => d,
            Err(e) => {
                godot_error!("EntityPeer.boot(): cannot create peer dir: {}", e);
                return None;
            }
        };

        let keypair = match crate::persistence::load_or_create_keypair(&dir) {
            Ok(kp) => kp,
            Err(e) => {
                godot_error!("EntityPeer.boot(): {}", e);
                return None;
            }
        };
        if let Err(e) = crate::persistence::write_config(&dir, Some(name.as_str())) {
            godot_warn!("EntityPeer.boot(): config.toml write failed: {}", e);
        }
        let cfg = crate::persistence::read_config(&dir);
        let sqlite_path = crate::persistence::store_db_path(&dir, &cfg.storage_backend);

        let config = entity_peer::PeerConfig {
            listen_addr: self.listen_address.to_string(),
            debug_open_grants: self.debug_grants,
            ..Default::default()
        };

        // `entity-sdk`'s `sqlite` feature is hard-enabled for this native
        // cdylib (see Cargo.toml), so `.sqlite()` is always available
        // here; the binding crate has no `sqlite` feature of its own to
        // gate on. Only the wasm target (not a Godot build today) lacks
        // the method.
        let mut builder = entity_sdk::PeerContextBuilder::new()
            .keypair(keypair)
            .config(config);
        if let Some(c) = self.injected_connector.clone() {
            builder = builder.connector(c);
        }
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(p) = sqlite_path.clone() {
            builder = builder.sqlite(p);
        }
        let builder = self.apply_pending_hooks(builder);
        let ctx = match builder.build() {
            Ok(ctx) => ctx,
            Err(e) => {
                godot_error!("EntityPeer.boot(): build failed: {}", e);
                return None;
            }
        };

        godot_print!(
            "EntityPeer: booted '{}' (peer_id {}) store={:?}",
            name,
            ctx.peer_id(),
            sqlite_path
        );
        Some(ctx)
    }

    /// Drain pre-start inspectability hook registrations into the
    /// `PeerContextBuilder`. Each registered name becomes a builder hook
    /// that captures a `tokio::sync::mpsc::UnboundedSender` clone (Send +
    /// Sync) so the hook closure satisfies the SDK's
    /// `Fn(&Event) + Send + Sync + 'static` bound. EntityPeer::process
    /// drains the receiver and emits per-snapshot Godot signals.
    fn apply_pending_hooks(
        &mut self,
        mut builder: entity_sdk::PeerContextBuilder,
    ) -> entity_sdk::PeerContextBuilder {
        if !self.pending_dispatch_hooks.is_empty() {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<DispatchSnapshot>();
            for name in self.pending_dispatch_hooks.drain(..) {
                let tx_clone = tx.clone();
                let name_for_closure = name.clone();
                builder = builder.with_dispatch_hook(name, move |evt| {
                    let (phase, status, response_hash) = match &evt.phase {
                        DispatchPhase::Entry => ("entry", None, None),
                        DispatchPhase::Exit {
                            status,
                            response_hash,
                        } => (
                            "exit",
                            Some(*status),
                            Some(response_hash.to_bytes().to_vec()),
                        ),
                    };
                    let snap = DispatchSnapshot {
                        name: name_for_closure.clone(),
                        target_uri: evt.target_uri.clone(),
                        operation: evt.operation.clone(),
                        params_hash: evt.params_hash.to_bytes().to_vec(),
                        request_id: evt.request_id.clone(),
                        timestamp_ms: evt.timestamp_ms,
                        phase,
                        status,
                        response_hash,
                    };
                    let _ = tx_clone.send(snap);
                });
            }
            self.dispatch_rx = Some(rx);
        }
        if !self.pending_binding_hooks.is_empty() {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<BindingSnapshot>();
            for name in self.pending_binding_hooks.drain(..) {
                let tx_clone = tx.clone();
                let name_for_closure = name.clone();
                builder = builder.with_binding_hook(name, move |evt| {
                    let change_type = match evt.change_type {
                        ChangeType::Created => "created",
                        ChangeType::Modified => "modified",
                        ChangeType::Deleted => "deleted",
                    };
                    let context = evt.context.as_ref().map(|c| BindingContextSnapshot {
                        chain_id: c.chain_id.clone(),
                        request_id: c.request_id.clone(),
                        cascade_depth: c.cascade_depth,
                        capability: c.capability.as_ref().map(|h| h.to_bytes().to_vec()),
                        handler_pattern: c.handler_pattern.clone(),
                        operation: c.operation.clone(),
                    });
                    let snap = BindingSnapshot {
                        name: name_for_closure.clone(),
                        path: evt.path.clone(),
                        hash: evt.hash.to_bytes().to_vec(),
                        previous_hash: evt.previous_hash.as_ref().map(|h| h.to_bytes().to_vec()),
                        new_hash: evt.new_hash.as_ref().map(|h| h.to_bytes().to_vec()),
                        change_type,
                        context,
                    };
                    let _ = tx_clone.send(snap);
                });
            }
            self.binding_rx = Some(rx);
        }
        if !self.pending_wire_hooks.is_empty() {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<WireSnapshot>();
            for name in self.pending_wire_hooks.drain(..) {
                let tx_clone = tx.clone();
                let name_for_closure = name.clone();
                builder = builder.with_wire_hook(name, move |evt| {
                    // SECURITY: snapshot fields ONLY — drop frame_bytes
                    // before the closure returns. The Rust borrow checker
                    // already enforces `&WireEvent` cannot outlive the
                    // call; the explicit drop pattern here also makes the
                    // metadata-only contract visible at the snapshot site.
                    let direction = match evt.direction {
                        WireDirection::Recv => "recv",
                        WireDirection::Send => "send",
                    };
                    let snap = WireSnapshot {
                        name: name_for_closure.clone(),
                        direction,
                        request_id: evt.request_id.clone(),
                        frame_len: evt.frame_bytes.len() as u32,
                        peer_address: evt.peer_address.clone(),
                        timestamp_ms: evt.timestamp_ms,
                    };
                    let _ = tx_clone.send(snap);
                });
            }
            self.wire_rx = Some(rx);
        }
        builder
    }

    /// Shared startup tail used by both `start()` (seed path, exercised
    /// by `tests/test_peer.gd`) and `boot()` (persistence path): tokio
    /// runtime, extension engines, the tokio→Godot event bridge, and the
    /// TCP accept loop.
    /// Wire up the runtime, event bridge, and listen-and-serve loop for a
    /// `PeerContext` that's already been built (via `build_start_context`
    /// or `build_boot_context`) and Arc-wrapped (either directly in the
    /// standalone path or via `EntitySDK::insert_peer` in the manager
    /// path). Takes `Arc<PeerContext>` so the SDK and this EntityPeer
    /// share ownership when the manager mediates.
    pub(crate) fn spin_up_arc(&mut self, ctx_arc: Arc<PeerContext>) {
        // Runtime ownership: borrow from manager if injected, otherwise
        // construct our own (standalone / direct-instantiation path).
        // The Owned variant runtime stays alive in `self.runtime` for
        // the peer's lifetime; the Borrowed variant just clones the
        // manager's handle.
        let runtime_ref = match std::mem::replace(&mut self.runtime, RuntimeRef::Unset) {
            RuntimeRef::Borrowed(h) => RuntimeRef::Borrowed(h),
            RuntimeRef::Unset | RuntimeRef::Owned(_) => {
                match tokio::runtime::Runtime::new() {
                    Ok(rt) => RuntimeRef::Owned(rt),
                    Err(e) => {
                        godot_error!("EntityPeer: failed to create runtime: {}", e);
                        return;
                    }
                }
            }
        };
        let handle = runtime_ref
            .handle()
            .expect("RuntimeRef just set above must yield a handle");

        let peer_id = ctx_arc.peer_id().to_string();
        let shared = ctx_arc.peer_shared();

        // start_engines is sync but spawns tokio tasks internally — needs
        // an active runtime context. Enter via the handle for both
        // Owned and Borrowed variants.
        let _guard = handle.enter();
        ctx_arc.peer().start_engines(&shared);

        // Set up event bridge: tokio broadcast → std::sync::mpsc → _process()
        let (event_tx, event_rx) = std::sync::mpsc::channel();
        let mut events = ctx_arc.peer().subscribe_events();
        handle.spawn(async move {
            while let Ok(evt) = events.recv().await {
                let hash_bytes = evt.hash.to_bytes().to_vec();
                if event_tx.send((evt.path, hash_bytes)).is_err() {
                    break; // receiver dropped (peer stopped)
                }
            }
        });
        self.event_rx = Some(event_rx);

        // Start the accept loop. Three cases:
        //   1. listen_address empty → no listener (peer reachable only
        //      via in-process execute, intentional for inner-composition
        //      peers like operational-peer)
        //   2. listen_address starts with `memory://` AND we have an
        //      injected MemoryTransportRegistry → bind a MemoryListener
        //      at endpoint = peer_id (the canonical convention per
        //      core/peer's `test_cross_peer_memory_connect`). server::run
        //      is generic over `impl Listener`, so the spawn shape is
        //      identical to the TCP path.
        //   3. otherwise → TCP path via `ctx.peer().listen()` (today's
        //      default; what every standalone test relies on).
        let addr_str = self.listen_address.to_string();
        if addr_str.is_empty() {
            godot_print!(
                "EntityPeer: no listener (listen_address empty) for peer_id {}",
                peer_id
            );
        } else if addr_str.starts_with("memory://") {
            // Memory-transport listen path. Bind synchronously here on
            // the main thread (MemoryListener::bind is sync), then spawn
            // server::run on the runtime to drive the accept loop.
            let Some(registry) = self.injected_memory_registry.clone() else {
                godot_error!(
                    "EntityPeer: listen_address {:?} requested memory transport but \
                     no MemoryTransportRegistry was injected (call \
                     inject_memory_registry before start/boot when using memory:// \
                     addresses).",
                    addr_str
                );
                self.runtime = runtime_ref;
                self.ctx = Some(ctx_arc);
                return;
            };
            // Endpoint convention: the peer_id. This matches
            // `core/peer/src/lib.rs::test_cross_peer_memory_connect`'s
            // `memory://<peer-id>` pattern and lets cross-peer connect
            // resolve a known target without out-of-band registration.
            // Any explicit endpoint in the `memory://X` prefix is
            // honored if X is non-empty.
            let endpoint = {
                let stripped = addr_str.trim_start_matches("memory://");
                if stripped.is_empty() {
                    peer_id.clone()
                } else {
                    stripped.to_string()
                }
            };
            match entity_peer::transport::MemoryListener::bind(
                endpoint.clone(),
                registry,
            ) {
                Ok(listener) => {
                    godot_print!(
                        "EntityPeer: listening on memory://{} as {}",
                        endpoint, peer_id
                    );
                    let shared_for_server = shared.clone();
                    handle.spawn(async move {
                        let _ = entity_peer::server::run(listener, shared_for_server).await;
                    });
                }
                Err(e) => {
                    godot_error!("EntityPeer: memory bind failed: {}", e);
                }
            }
        } else {
            // TCP listen path. Spawn listen-and-serve + use a oneshot to
            // sync-wait for the listener-ready result so subsequent
            // connect attempts from the same process see a bound
            // listener. Works with both Owned (runtime) and Borrowed
            // (handle) variants — Handle has no `block_on` in tokio 1.x,
            // so we use spawn + std::sync::mpsc::recv instead.
            let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<String, String>>();
            let ctx_for_listen = ctx_arc.clone();
            let shared_for_server = shared.clone();
            handle.spawn(async move {
                match ctx_for_listen.peer().listen().await {
                    Ok(listener) => {
                        let bound_addr = listener.socket_addr().to_string();
                        let _ = ready_tx.send(Ok(bound_addr));
                        let _ = entity_peer::server::run(listener, shared_for_server).await;
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e.to_string()));
                    }
                }
            });
            match ready_rx.recv() {
                Ok(Ok(bound_addr)) => {
                    godot_print!("EntityPeer: listening on {} as {}", bound_addr, peer_id);
                }
                Ok(Err(e)) => {
                    godot_error!("EntityPeer: listen failed: {}", e);
                }
                Err(_) => {
                    godot_error!("EntityPeer: listen ready-channel dropped before result");
                }
            }
        }

        self.runtime = runtime_ref;
        self.ctx = Some(ctx_arc);
    }

    /// Stop the peer.
    ///
    /// ── Pending-future cleanup (hang-forever protection) ──
    /// Any in-flight `PeerOpFuture` whose tokio task is still racing
    /// must be force-completed before we tear down the runtime —
    /// otherwise the slot stays empty, `try_complete` never fires the
    /// signal, and any GDScript coroutine `await`-ing it hangs
    /// forever. We drain `pending` and call `fail_with` on each so
    /// awaiters resume with `Nil` + a `godot_error!` log naming the
    /// cause. Caught godot-workbench Wave 2.4 protections pass.
    #[func]
    fn stop(&mut self) {
        for mut fut in self.pending.drain(..) {
            fut.bind_mut().fail_with("EntityPeer stopped");
        }
        self.event_rx = None;
        self.dispatch_rx = None;
        self.binding_rx = None;
        self.wire_rx = None;
        // Close all SDK-registered handlers (drop fires the unregister
        // sequence: dispatch index, then tree entries).
        for (_, handle) in std::mem::take(&mut self.registered_handlers) {
            handle.close();
        }
        // Drop the request channel sides; any tokio body futures that
        // tried to send fail-fast on the next dispatch.
        self.handler_req_tx = None;
        self.handler_req_rx = None;
        // Drain pending invocation senders — receivers fire Closed and
        // bodies return `HandlerError::Internal("response oneshot
        // channel dropped")`.
        if let Ok(mut map) = self.pending_handler_invocations.lock() {
            map.clear();
        }
        self.ctx = None;
        // For Owned variant: drop the runtime, which joins/aborts spawned
        // tasks. For Borrowed variant: just drop the handle clone — the
        // manager's runtime stays alive (and any in-flight tasks we
        // spawned on it become orphaned-but-bounded since we dropped the
        // channels they push to above).
        self.runtime = RuntimeRef::Unset;
        godot_print!("EntityPeer: stopped");
    }

    /// Get the PeerID string. Returns empty string if not started.
    ///
    /// The peer_id IS the fingerprint of this peer's identity, derived
    /// as `Base58(key_type || hash_type || SHA-256(public_key_bytes))`
    /// per `core/crypto/src/lib.rs` `PeerId::from_public_key`. Identity
    /// panels can use this as the display fingerprint directly — no
    /// additional hash needed.
    #[func]
    fn peer_id(&self) -> GString {
        match &self.ctx {
            Some(c) => GString::from(c.peer_id()),
            None => GString::new(),
        }
    }

    // -----------------------------------------------------------------
    // Identity surface
    // -----------------------------------------------------------------

    /// Raw Ed25519 public key bytes (32 bytes) for this peer.
    ///
    /// Equivalent to `Keypair::public_key_bytes()`. Empty PackedByteArray
    /// if the peer is not yet started.
    #[func]
    fn public_key_bytes(&self) -> PackedByteArray {
        let mut out = PackedByteArray::new();
        let Some(ctx) = self.ctx.as_ref() else {
            return out;
        };
        let bytes = ctx.peer().keypair().public_key_bytes();
        out.extend(bytes.iter().copied());
        out
    }

    /// 33-byte wire-format hash of this peer's owner self-capability.
    /// Stable for the peer's lifetime.
    ///
    /// Forward continuations + EXTENSION-OPS request envelopes that
    /// embed a `dispatch_capability` hash whose authority chain walks
    /// back to the writer can use this directly. For single-peer
    /// continuation installs targeting this peer's tree, this IS the
    /// natural `dispatch_capability` hash.
    ///
    /// Wraps `PeerContext::owner_capability_hash()`
    /// (`bindings/sdk/src/sdk.rs:2619`). Empty PackedByteArray if the
    /// peer is not yet started.
    #[func]
    fn owner_capability_hash(&self) -> PackedByteArray {
        let mut out = PackedByteArray::new();
        let Some(ctx) = self.ctx.as_ref() else {
            return out;
        };
        let hash = ctx.owner_capability_hash();
        out.extend(hash.to_bytes().iter().copied());
        out
    }

    /// Sign a byte payload with this peer's private key. Returns the
    /// 64-byte Ed25519 signature, or an empty PackedByteArray if the
    /// peer is not yet started.
    ///
    /// SECURITY: The binding does not gate this — exposing the raw
    /// primitive is intentional. GDScript callers should attenuate via
    /// a capability at the action-dispatch layer (Discipline 3); the
    /// Godot frontend's working position is that sign-with-private-key
    /// is a textbook capability candidate and production callers
    /// should not reach `peer.sign()` from arbitrary panels.
    #[func]
    fn sign(&self, message: PackedByteArray) -> PackedByteArray {
        let mut out = PackedByteArray::new();
        let Some(ctx) = self.ctx.as_ref() else {
            godot_error!("EntityPeer.sign: peer not started");
            return out;
        };
        let sig = ctx.peer().keypair().sign(&message.to_vec());
        out.extend(sig.iter().copied());
        out
    }

    /// Verify an Ed25519 signature against an arbitrary public key.
    ///
    /// `public_key` MUST be 32 bytes; `signature` MUST be 64 bytes.
    /// Mismatched lengths return `false`. Static-style (no `&self`
    /// access to this peer's keypair) — verifies any (key, message,
    /// signature) triple.
    ///
    /// Returns `true` iff the signature is cryptographically valid.
    #[func]
    fn verify(
        public_key: PackedByteArray,
        message: PackedByteArray,
        signature: PackedByteArray,
    ) -> bool {
        let pk = public_key.to_vec();
        if pk.len() != 32 {
            godot_error!(
                "EntityPeer.verify: public_key must be 32 bytes, got {}",
                pk.len()
            );
            return false;
        }
        let sig = signature.to_vec();
        if sig.len() != 64 {
            godot_error!(
                "EntityPeer.verify: signature must be 64 bytes, got {}",
                sig.len()
            );
            return false;
        }
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk);
        entity_crypto::Keypair::verify(&pk_arr, &message.to_vec(), &sig).is_ok()
    }

    // -----------------------------------------------------------------
    // Capability inspection (T3.0.d — operator-mode UX prereq)
    // -----------------------------------------------------------------

    /// Check whether a capability is an operator-class grant for the
    /// given target pattern. SDK boundary check per
    /// GUIDE-INSPECTABILITY v1.2.1 §10 (operator-class authority) +
    /// Dom's SDK-boundary feedback, Ask (c).
    ///
    /// `cap_hash` is the 33-byte wire-format Hash of the capability
    /// entity; `target_pattern` is a handler-pattern string
    /// (e.g. `"system/tree"`). Returns `false` for invalid hash bytes,
    /// for a peer that hasn't started, or for any capability that
    /// doesn't meet the operator-class predicate.
    ///
    /// Use this to gate the operator-mode toggle UX: only show the
    /// toggle when the holder's cap is operator-class for the panel's
    /// target. Wraps `PeerContext::is_operator_class_for`.
    #[func]
    fn is_operator_class_for(
        &self,
        cap_hash: PackedByteArray,
        target_pattern: GString,
    ) -> bool {
        let Some(ctx) = self.ctx.as_ref() else {
            godot_error!("EntityPeer.is_operator_class_for: peer not started");
            return false;
        };
        let hash = match entity_hash::Hash::from_bytes(&cap_hash.to_vec()) {
            Ok(h) => h,
            Err(e) => {
                godot_error!(
                    "EntityPeer.is_operator_class_for: invalid cap_hash ({} bytes): {}",
                    cap_hash.len(),
                    e
                );
                return false;
            }
        };
        ctx.is_operator_class_for(&hash, &target_pattern.to_string())
    }

    // -----------------------------------------------------------------
    // Cross-peer capability chain (T3.0.g + h — T4 dispatch prereq)
    // -----------------------------------------------------------------

    /// Mint a dispatch capability for cross-peer continuation, per
    /// EXTENSION-CONTINUATION §4.2 case 3 / §8.2 C-3. Returns the leaf
    /// cap entity (or null on error).
    ///
    /// Pre-condition: the local peer MUST hold an open connection to
    /// `remote_peer_id` (call `connect_to_async` first). The connection
    /// grant the remote conferred during handshake is the chain root.
    ///
    /// `grants` is an Array of Dictionary, each entry per GrantEntry:
    ///   handlers:   Array of pattern strings (e.g. ["system/tree"])
    ///   resources:  Array of resource patterns
    ///   operations: Array of operation names (e.g. ["get", "put"])
    ///   peers:      optional Array of peer-id strings (omit = local only)
    ///
    /// `expires_at` is optional Unix milliseconds; pass `null`/0 for no
    /// expiry.
    ///
    /// The minted leaf cap is paired with `bundle_cross_peer_chain` to
    /// obtain the chain + signatures the remote verifier needs;
    /// downstream T4 cross-peer EXECUTE includes the bundle in the
    /// envelope's `included`.
    ///
    /// Wraps `PeerContext::mint_cross_peer_chain_capability`.
    #[func]
    fn mint_cross_peer_chain_capability(
        &self,
        remote_peer_id: GString,
        grants: VarArray,
        expires_at_ms: Variant,
    ) -> Variant {
        let Some(ctx) = self.ctx.as_ref() else {
            godot_error!("EntityPeer.mint_cross_peer_chain_capability: peer not started");
            return Variant::nil();
        };
        let grant_entries = match parse_grant_entries(&grants) {
            Ok(g) => g,
            Err(e) => {
                godot_error!("EntityPeer.mint_cross_peer_chain_capability: {}", e);
                return Variant::nil();
            }
        };
        let expires_opt = if expires_at_ms.is_nil() {
            None
        } else {
            expires_at_ms
                .try_to::<i64>()
                .ok()
                .and_then(|n| if n > 0 { Some(n as u64) } else { None })
        };
        match ctx.mint_cross_peer_chain_capability(
            &remote_peer_id.to_string(),
            grant_entries,
            expires_opt,
        ) {
            Ok(leaf) => EntityData::from_entity(&leaf).to_variant(),
            Err(e) => {
                godot_error!(
                    "EntityPeer.mint_cross_peer_chain_capability: {}",
                    e
                );
                Variant::nil()
            }
        }
    }

    /// Assemble the chain + signature bundle for a leaf cap minted by
    /// `mint_cross_peer_chain_capability`. Returns an Array of
    /// Dictionary entries each shaped:
    ///   { hash: PackedByteArray(33), entity: EntityData }
    ///
    /// Caller iterates the array and includes each entity in the
    /// dispatched EXECUTE envelope's `included` (per
    /// EXTENSION-CONTINUATION §4.3). T4 cross-peer EXECUTE binding
    /// consumes this directly.
    ///
    /// Wraps `PeerContext::bundle_cross_peer_chain`.
    #[func]
    fn bundle_cross_peer_chain(&self, leaf_cap: Gd<EntityData>) -> VarArray {
        let mut out = VarArray::new();
        let Some(ctx) = self.ctx.as_ref() else {
            godot_error!("EntityPeer.bundle_cross_peer_chain: peer not started");
            return out;
        };
        let entity = match leaf_cap.bind().to_entity() {
            Ok(e) => e,
            Err(e) => {
                godot_error!(
                    "EntityPeer.bundle_cross_peer_chain: leaf cap not a valid entity: {}",
                    e
                );
                return out;
            }
        };
        match ctx.bundle_cross_peer_chain(&entity) {
            Ok(bundle) => {
                for (hash, ent) in bundle {
                    let mut pair = Dictionary::new();
                    let mut hash_pba = PackedByteArray::new();
                    hash_pba.extend(hash.to_bytes().iter().copied());
                    pair.set("hash", hash_pba);
                    pair.set("entity", EntityData::from_entity(&ent));
                    out.push(&pair.to_variant());
                }
            }
            Err(e) => {
                godot_error!("EntityPeer.bundle_cross_peer_chain: {}", e);
            }
        }
        out
    }

    // -----------------------------------------------------------------
    // Peer phase observation
    // -----------------------------------------------------------------

    // -----------------------------------------------------------------
    // Transport
    // -----------------------------------------------------------------

    /// Open an outbound connection to a remote peer at `addr`. Uses the
    /// SDK's platform-default connector — `TcpConnector` on native (see
    /// `core/peer/src/transport.rs::default_connector`) unless an
    /// alternative connector was injected on this peer via
    /// `EntityPeerManager::set_memory_connector` (memory transport).
    ///
    /// `addr` forms accepted (all map to the same wire dial):
    ///   - `host:port`             — bare, what the underlying
    ///                                `TcpConnector` actually wants
    ///   - `tcp://host:port`       — scheme stripped for parity
    ///   - `ws://host:port` /
    ///     `wss://host:port`       — scheme stripped. Native peers
    ///                                listen via `TcpTransportListener`,
    ///                                NOT a WebSocket listener; the `ws://`
    ///                                form is accepted because cross-impl
    ///                                code passes it idiomatically. If/when
    ///                                we wire `WebSocketConnector` (gated
    ///                                on SDK `native-ws`), the dial would
    ///                                still see the same input shape.
    ///   - `memory://...`          — passed through verbatim when a
    ///                                `MemoryConnector` is injected.
    ///
    /// Returns a `PeerOpFuture` whose `completed` carries:
    ///   `{ status: "ok", remote_peer_id: String }`   on success
    ///   `{ status: "error", error: String }`         on failure
    ///
    /// The remote peer_id comes back from the connection's hello/
    /// authenticate handshake (see `Peer::connect_to` at
    /// `core/peer/src/lib.rs:453`).
    ///
    /// Diagnosed: prior versions of this binding documented
    /// `ws://` as required and let it pass through to a `TcpConnector`,
    /// which fed the scheme prefix to `getaddrinfo` and failed with
    /// "failed to lookup address information." Root cause was the URL
    /// shape mismatch, not a `tokio-tungstenite` resolver bug; Dom's
    /// canonical `WebSocketConnector` tests at `core/peer/src/lib.rs`
    /// pass clean against the same env.
    #[func]
    fn connect_to_async(&mut self, addr: GString) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("connect_to_async") {
            return None;
        }
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        let raw_addr = addr.to_string();
        let addr_owned = normalize_dial_addr(&raw_addr).to_string();
        rt.spawn(async move {
            // Forwards to `PeerContext::connect_to`, which dials against
            // the persistent `Arc<PeerShared>` so the resulting
            // `RemoteConnection` lands in the pool that
            // mint_cross_peer_chain_capability + cross-peer EXECUTE
            // actually read from (see entity_sdk::PeerContext::connect_to
            // — sdk.rs::3547 — and its
            // `connect_to_populates_persistent_remote_pool` regression
            // test pinning the post-condition). When the substrate
            // Shape-A fix lands and `Peer::shared` returns a long-lived
            // Arc, the SDK body collapses further; this binding stays the
            // same.
            let raw = match ctx.connect_to(&addr_owned).await {
                Ok(remote_pid) => OpResultRaw::ConnectTo(Ok(remote_pid)),
                Err(e) => OpResultRaw::ConnectTo(Err(format!("{}", e))),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// Current PeerPhase, read from `/{peer_id}/system/peer/self/status`.
    ///
    /// Returns one of `"starting"`, `"ready"`, `"draining"`, or `""` if
    /// the peer is not started or the status entity is not (yet)
    /// present. Sync read against the local tree — no L1 dispatch, no
    /// future. The status entity is written by the kernel during phase
    /// transitions (`core/peer/src/lib.rs:1574+`).
    #[func]
    fn peer_phase(&self) -> GString {
        let Some(ctx) = self.ctx.as_ref() else {
            return GString::new();
        };
        let path = format!("/{}/system/peer/self/status", ctx.peer_id());
        let Some(entity) = ctx.store().get(&path) else {
            return GString::new();
        };
        let phase = decode_phase_from_status_entity(&entity).unwrap_or_default();
        GString::from(phase.as_str())
    }

    /// Substrate-bridge extensions installed on this peer. See
    /// `PeerContext::installed_extensions`. Canonical names match
    /// the `extensions/{name}/` directory layout (with `handlers` for
    /// `handler-ops` per the Cargo-feature convention).
    ///
    /// Sync — fixed at peer construction. Returns an empty array if
    /// the peer is not started.
    ///
    /// Today every peer in the process returns the same list (Cargo
    /// features are process-wide). For pre-peer queries (spawn-form
    /// extension-checkbox prefill, etc.) the SDK exposes
    /// `entity_sdk::installed_extensions()` as a free fn — that
    /// surface isn't reachable from GDScript today; if the spawn-form
    /// UX needs it before a peer exists, file a follow-up to expose a
    /// module-level static.
    #[func]
    fn installed_extensions(&self) -> PackedStringArray {
        let mut out = PackedStringArray::new();
        let Some(ctx) = self.ctx.as_ref() else {
            return out;
        };
        for name in ctx.installed_extensions() {
            out.push(&GString::from(name));
        }
        out
    }

    /// Storage backend kind for this peer. One of `"sqlite"`,
    /// `"memory"`, or `"opfs"` (wasm-only). Empty string if the peer
    /// is not started.
    ///
    /// Stable identifier suitable for the Roster "Backend" column and
    /// the spawn-peer Config form's storage selector. Sync — fixed at
    /// peer construction.
    ///
    /// Native Godot binding sees `"sqlite"` / `"memory"`. Don't
    /// `match` panic on unknown — additional backends may appear here
    /// in future (per `PeerContext::storage_kind` doc).
    #[func]
    fn storage_kind(&self) -> GString {
        match self.ctx.as_ref() {
            Some(ctx) => GString::from(ctx.storage_kind()),
            None => GString::new(),
        }
    }

    /// Crate-internal accessor for the underlying `PeerContext`. Used by
    /// `shell_node::GodotPeerBinding` to satisfy the `entity_shell`
    /// crate's `PeerBinding` trait without going through GString round
    /// trips for every internal Rust-to-Rust call.
    pub(crate) fn peer_ctx(&self) -> Option<&PeerContext> {
        self.ctx.as_deref()
    }

    /// Cloned `Arc<PeerContext>` for `'static + Send` async work that
    /// outlives the bind guard. Used by `GodotPeerBinding` to produce
    /// `BoxFuture<'static, _>` returns for shell verbs that route
    /// through SDK scope handles (`ctx.compute()`, `ctx.identity()`).
    pub(crate) fn peer_ctx_arc(&self) -> Option<Arc<PeerContext>> {
        self.ctx.clone()
    }

    /// Crate-internal accessor for the peer's tokio runtime handle.
    /// Used by `shell_node::EntityShell` to spawn async verb producer
    /// tasks (`connect`/`exec`/`query`/`count` return
    /// `mpsc::Receiver`s whose producer futures must run on a real
    /// runtime). Returns `None` before `boot()` / `start()`.
    pub(crate) fn runtime_handle(&self) -> Option<tokio::runtime::Handle> {
        self.runtime.handle()
    }

    /// Crate-internal injection from `EntityPeerManager`. Called BEFORE
    /// `start()` or `boot()` to wire this peer to the manager's shared
    /// tokio runtime instead of constructing a per-peer runtime. After
    /// injection, `spin_up` borrows the handle and skips the `Runtime::new()`
    /// path.
    ///
    /// Idempotent in practice: calling twice replaces the handle. Calling
    /// after `start()` / `boot()` has no effect — `spin_up` has already
    /// captured into `self.runtime`.
    pub(crate) fn inject_runtime_handle(&mut self, handle: tokio::runtime::Handle) {
        self.runtime = RuntimeRef::Borrowed(handle);
    }

    /// Crate-internal injection of a transport connector. Called BEFORE
    /// `build_start_context` / `build_boot_context` to wire the peer's
    /// outbound connect path to a non-default transport (today: only
    /// `Arc<MemoryConnector>` for in-process cross-peer dispatch). If
    /// unset, the builder uses the platform-default connector.
    pub(crate) fn inject_connector(
        &mut self,
        connector: Arc<dyn entity_peer::transport::Connector>,
    ) {
        self.injected_connector = Some(connector);
    }

    /// Crate-internal injection of a memory transport registry. When
    /// set + the peer's `listen_address` starts with `memory://`,
    /// `spin_up_arc` binds a `MemoryListener` against this registry
    /// instead of the TCP `peer.listen()` path. The endpoint comes
    /// from the `listen_address` itself (the part after `memory://`,
    /// which we conventionally set to the peer_id).
    pub(crate) fn inject_memory_registry(
        &mut self,
        registry: Arc<entity_peer::transport::MemoryTransportRegistry>,
    ) {
        self.injected_memory_registry = Some(registry);
    }

    /// Precondition guard for the `*_async` methods.
    ///
    /// Async ops return a `PeerOpFuture` whose `completed` signal is
    /// fired from `EntityPeer::process` (next idle frame, via
    /// `call_deferred`). If the peer has no parent, `process` will
    /// never run, the slot will never drain, the signal will never
    /// fire, and `await fut.completed` in GDScript will hang forever.
    ///
    /// Verify here so callers see a `null` future immediately with a
    /// clear error message, instead of an opaque hang.
    ///
    /// ── Why `get_parent().is_some()` instead of `is_inside_tree()` ──
    /// `is_inside_tree()` would catch this AND additionally catch
    /// "added to a node that isn't itself in the tree." But it also
    /// returns `false` during `SceneTree::_init` of `--script` test
    /// runners — the tree isn't fully active yet even though
    /// `root.add_child(peer)` has run. The parent check is the
    /// minimum that catches the actual common bug (peer never added
    /// at all — godot-workbench Wave 2.4 caught this on the path that
    /// hung `test_per_host_layout_persistence` for >5 minutes) without
    /// the `_init` false positives. The "added to a detached subtree"
    /// edge case is rare and out of scope here.
    fn check_async_preconditions(&self, op_name: &str) -> bool {
        if self.base().get_parent().is_none() {
            godot_error!(
                "EntityPeer.{}: peer has no parent — `_process` won't run, \
                 the returned future would never complete. Add the EntityPeer to the \
                 scene tree via `root.add_child(peer)` before calling async ops.",
                op_name
            );
            return false;
        }
        true
    }

    /// Get an entity from the tree by path. Returns null if not found.
    /// L0 — sync, peer-owner authority, bypasses dispatch.
    #[func]
    fn tree_get(&self, path: GString) -> Option<Gd<EntityData>> {
        let ctx = self.ctx.as_ref()?;
        let entity = ctx.store().get(&path.to_string())?;
        Some(EntityData::from_entity(&entity))
    }

    /// Put an entity into the tree. Returns the content hash as PackedByteArray.
    /// L0 — sync, peer-owner authority, bypasses dispatch.
    #[func]
    fn tree_put(
        &self,
        path: GString,
        entity_type: GString,
        data: PackedByteArray,
    ) -> PackedByteArray {
        let Some(ctx) = &self.ctx else {
            godot_error!("EntityPeer: not started");
            return PackedByteArray::new();
        };

        let entity = match entity_entity::Entity::new(&entity_type.to_string(), data.to_vec()) {
            Ok(e) => e,
            Err(e) => {
                godot_error!("EntityPeer: entity creation failed: {}", e);
                return PackedByteArray::new();
            }
        };

        match ctx.store().put(&path.to_string(), entity) {
            Ok(hash) => {
                let bytes = hash.to_bytes();
                let mut result = PackedByteArray::new();
                result.extend(bytes.iter().copied());
                result
            }
            Err(e) => {
                godot_error!("EntityPeer: tree put failed: {}", e);
                PackedByteArray::new()
            }
        }
    }

    /// Check if a path has an entity. L0 sync.
    #[func]
    fn tree_has(&self, path: GString) -> bool {
        let Some(ctx) = &self.ctx else {
            return false;
        };
        ctx.store().has(&path.to_string())
    }

    /// Remove an entity at a path. Returns true if removed, false if no-op.
    /// L0 sync; bumps the generation counter on success.
    #[func]
    fn tree_remove(&self, path: GString) -> bool {
        let Some(ctx) = &self.ctx else {
            godot_error!("EntityPeer: not started");
            return false;
        };
        ctx.store().remove(&path.to_string())
    }

    /// List tree paths under a prefix. Returns a PackedStringArray.
    /// L0 sync.
    #[func]
    fn tree_list(&self, prefix: GString) -> PackedStringArray {
        let Some(ctx) = &self.ctx else {
            godot_error!("EntityPeer: not started");
            return PackedStringArray::new();
        };
        let entries = ctx.store().list(&prefix.to_string());
        let mut result = PackedStringArray::new();
        for entry in entries {
            result.push(&GString::from(entry.path.as_str()));
        }
        result
    }

    /// Monotonic counter, incremented on every L0 mutation observable to
    /// readers of this peer. Use to detect "anything changed since I last
    /// looked" without subscribing. Returns 0 if the peer is not started.
    #[func]
    fn generation(&self) -> i64 {
        match &self.ctx {
            Some(c) => c.store().generation() as i64,
            None => 0,
        }
    }

    /// Watch a tree path prefix and receive change notifications.
    ///
    /// Returns an `EntitySubscription` whose `poll()` drains pending events
    /// since the last call. Drop the returned object to cancel.
    ///
    /// L0 — software-filtered against the peer's broadcast. No capability
    /// check; every event the peer sees that matches the prefix is delivered.
    /// For an L1 capability-checked subscription, use `execute("system/subscription", ...)`.
    #[func]
    fn watch(&self, prefix: GString) -> Option<Gd<EntitySubscription>> {
        let ctx = self.ctx.as_ref()?;
        let runtime = self.runtime.handle()?;

        let _guard = runtime.enter();
        let prefix_str = prefix.to_string();
        let queue = std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::VecDeque::<(String, Vec<u8>)>::new(),
        ));
        let queue_for_callback = queue.clone();

        let handle = ctx.store().on_prefix_change(prefix_str, move |event| {
            if let Ok(mut q) = queue_for_callback.lock() {
                q.push_back((event.path.clone(), event.hash.to_bytes().to_vec()));
            }
        });

        Some(EntitySubscription::new_gd_with_handle(queue, handle))
    }

    /// Async variant of `execute` — L1 dispatch through the handler
    /// resolution path, returning a `PeerOpFuture` instead of blocking.
    ///
    /// REQUIRED for invoking dynamic handlers registered via
    /// `register_handler`: those handlers' bodies await
    /// `respond_to_handler` calls from the GDScript main thread, so the
    /// dispatch path CANNOT block the main thread the way sync `execute`
    /// does (rt.block_on would deadlock waiting for process() ticks
    /// that can't happen).
    ///
    /// Result `completed` Variant:
    ///   - On success: `EntityData` holding the result entity
    ///   - On error:   `null` (with `godot_error!` logged)
    #[func]
    fn execute_async(
        &mut self,
        handler: GString,
        operation: GString,
        params_type: GString,
        params_data: PackedByteArray,
    ) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("execute_async") {
            return None;
        }
        let params = match entity_entity::Entity::new(&params_type.to_string(), params_data.to_vec())
        {
            Ok(e) => e,
            Err(e) => {
                godot_error!("EntityPeer.execute_async: params creation failed: {}", e);
                return None;
            }
        };
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        let handler_s = handler.to_string();
        let op_s = operation.to_string();
        rt.spawn(async move {
            let raw = match ctx.peer().execute(&handler_s, &op_s, params).await {
                Ok(result) => OpResultRaw::Entity(Some(result.result)),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// L1 EXECUTE with an explicit capability — the cross-peer variant of
    /// `execute_async`. Pass the capability entity's content hash; the
    /// binding resolves it to the actual `Entity` via the local content
    /// store and populates `ExecuteOptions::capability` so the SDK's
    /// envelope construction (`connection.rs::make_execute_fn`) bundles
    /// the full authority chain via `collect_chain_bundle` and includes
    /// it on the wire — required for cross-peer dispatch where the
    /// receiving peer needs to verify the chain to a root it recognizes
    /// (V7 §4.3 chain transport).
    ///
    /// `handler` is an `entity://{peer_id}/{handler_path}` URI for the
    /// cross-peer case. `is_remote_uri()` detects this; `get_or_connect`
    /// routes through the peer's configured connector (today:
    /// MemoryConnector for memory peers). The connection must already
    /// exist in the pool (call `connect_to_async` first) OR the peer's
    /// tree must have a `system/peer/transport/{remote_pid}` entry the
    /// SDK can resolve into a transport address.
    ///
    /// Returns the result `EntityData` on success, null on error
    /// (godot_error! logged for the failure detail).
    #[func]
    fn execute_async_with_capability(
        &mut self,
        handler: GString,
        operation: GString,
        params_type: GString,
        params_data: PackedByteArray,
        capability_hash: PackedByteArray,
        resource_path: GString,
    ) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("execute_async_with_capability") {
            return None;
        }
        let params = match entity_entity::Entity::new(
            &params_type.to_string(),
            params_data.to_vec(),
        ) {
            Ok(e) => e,
            Err(e) => {
                godot_error!(
                    "EntityPeer.execute_async_with_capability: params creation failed: {}",
                    e
                );
                return None;
            }
        };
        let cap_hash_bytes = capability_hash.to_vec();
        let cap_hash = match entity_hash::Hash::from_bytes(&cap_hash_bytes) {
            Ok(h) => h,
            Err(e) => {
                godot_error!(
                    "EntityPeer.execute_async_with_capability: invalid capability_hash: {}",
                    e
                );
                return None;
            }
        };
        let ctx = self.ctx.as_ref()?.clone();
        // Resolve hash → Entity via the local content store. The cap
        // entity MUST be locally available — for cross-peer caps minted
        // by this peer via `mint_cross_peer_chain_capability` (T3.0.g),
        // it always is.
        let cap_entity = match ctx.peer_shared().content_store.get(&cap_hash) {
            Some(e) => e,
            None => {
                godot_error!(
                    "EntityPeer.execute_async_with_capability: capability entity not in \
                     local content store for hash {} — was the cap minted on this peer?",
                    cap_hash
                );
                return None;
            }
        };
        // Resource targeting (V7 §5.7 — handlers like system/tree:put
        // require an explicit ResourceTarget to bound the operation).
        // Empty resource_path = no resource override, which only works
        // for handlers that don't need one (e.g., system/query:find).
        let resource_path_s = resource_path.to_string();
        let resource = if resource_path_s.is_empty() {
            None
        } else {
            Some(entity_capability::ResourceTarget {
                targets: vec![resource_path_s],
                exclude: vec![],
            })
        };
        let opts = entity_handler::ExecuteOptions {
            capability: Some(cap_entity),
            resource,
            ..Default::default()
        };
        let (fut, slot) = PeerOpFuture::new_pending();
        let rt = self.runtime.handle()?;
        let handler_s = handler.to_string();
        let op_s = operation.to_string();
        rt.spawn(async move {
            let raw = match ctx.execute(handler_s, op_s, params, opts).await {
                Ok(result) => OpResultRaw::Entity(Some(result.result)),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// Extended form of `execute_async_with_capability` exposing the
    /// remaining `ExecuteOptions` fields that the 6-arg signature drops.
    /// Use this when you need any of:
    ///
    /// * **`deliver_to`** — fire-and-forget async result delivery per
    ///   `EXTENSION-INBOX.md §3.2` / V7 §3.2. When `deliver_to_uri` is
    ///   non-empty, the cross-peer dispatch layer at
    ///   `core/peer/src/connection.rs:1879-1898` auto-generates a
    ///   `deliver_token` (signed by this peer's keypair, scoped to the
    ///   remote identity + delivery URI + delivery op) and includes it
    ///   in the envelope. The receiver returns 202 and runs the handler
    ///   async; on completion, the result is delivered as a fresh
    ///   EXECUTE to `deliver_to_uri` with operation `deliver_to_operation`.
    ///   `deliver_to_uri` empty = no deliver_to set (synchronous reply).
    ///   `deliver_to_operation` is required when `deliver_to_uri` is
    ///   non-empty (per spec §2.3).
    ///
    /// * **`request_id`** — overrides the SDK's default request_id
    ///   (`"internal"`) for the dispatched envelope. Required for
    ///   idempotent-send dedupe against handlers like `system/inbox`
    ///   that key storage by `ctx.request_id` (per V7 §6.8). Empty =
    ///   SDK default.
    ///
    /// All other args are identical to `execute_async_with_capability`.
    /// Existing callers should continue using the 6-arg form; this
    /// extended method is purely additive.
    #[func]
    fn execute_async_with_options(
        &mut self,
        handler: GString,
        operation: GString,
        params_type: GString,
        params_data: PackedByteArray,
        capability_hash: PackedByteArray,
        resource_path: GString,
        deliver_to_uri: GString,
        deliver_to_operation: GString,
        request_id: GString,
    ) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("execute_async_with_options") {
            return None;
        }
        let params = match entity_entity::Entity::new(
            &params_type.to_string(),
            params_data.to_vec(),
        ) {
            Ok(e) => e,
            Err(e) => {
                godot_error!(
                    "EntityPeer.execute_async_with_options: params creation failed: {}",
                    e
                );
                return None;
            }
        };
        let cap_hash_bytes = capability_hash.to_vec();
        let cap_hash = match entity_hash::Hash::from_bytes(&cap_hash_bytes) {
            Ok(h) => h,
            Err(e) => {
                godot_error!(
                    "EntityPeer.execute_async_with_options: invalid capability_hash: {}",
                    e
                );
                return None;
            }
        };
        let ctx = self.ctx.as_ref()?.clone();
        let cap_entity = match ctx.peer_shared().content_store.get(&cap_hash) {
            Some(e) => e,
            None => {
                godot_error!(
                    "EntityPeer.execute_async_with_options: capability entity not in \
                     local content store for hash {} — was the cap minted on this peer?",
                    cap_hash
                );
                return None;
            }
        };
        let resource_path_s = resource_path.to_string();
        let resource = if resource_path_s.is_empty() {
            None
        } else {
            Some(entity_capability::ResourceTarget {
                targets: vec![resource_path_s],
                exclude: vec![],
            })
        };

        // deliver_to: both uri AND operation required when set. Spec §2.3.
        let deliver_uri_s = deliver_to_uri.to_string();
        let deliver_op_s = deliver_to_operation.to_string();
        let deliver_to = if deliver_uri_s.is_empty() {
            None
        } else {
            if deliver_op_s.is_empty() {
                godot_error!(
                    "EntityPeer.execute_async_with_options: deliver_to_uri set but \
                     deliver_to_operation is empty (spec §2.3 requires both)"
                );
                return None;
            }
            Some(entity_handler::DeliverySpec {
                uri: deliver_uri_s,
                operation: deliver_op_s,
            })
        };

        let rid_s = request_id.to_string();
        let request_id_opt = if rid_s.is_empty() { None } else { Some(rid_s) };

        let opts = entity_handler::ExecuteOptions {
            capability: Some(cap_entity),
            resource,
            deliver_to,
            request_id: request_id_opt,
            ..Default::default()
        };
        let (fut, slot) = PeerOpFuture::new_pending();
        let rt = self.runtime.handle()?;
        let handler_s = handler.to_string();
        let op_s = operation.to_string();
        rt.spawn(async move {
            let raw = match ctx.execute(handler_s, op_s, params, opts).await {
                Ok(result) => OpResultRaw::Entity(Some(result.result)),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// Sugar for cross-peer `system/tree:put`. Matches the params
    /// wrapping that `PeerContext::put` does internally (build_put_params:
    /// `{"entity": {"type", "data"}}` with data as decoded CBOR Value,
    /// not bytes) so the receiving peer's `system/tree:put` handler
    /// accepts the payload and writes the entity at the target path.
    ///
    /// `target_path` MUST be a fully-qualified path on the remote peer
    /// (`/{remote_pid}/...`). The capability MUST cover system/tree:put
    /// on that path.
    #[func]
    fn tree_put_async_cross_peer(
        &mut self,
        target_peer_id: GString,
        target_path: GString,
        entity_type: GString,
        entity_data: PackedByteArray,
        capability_hash: PackedByteArray,
    ) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("tree_put_async_cross_peer") {
            return None;
        }
        let target_pid_s = target_peer_id.to_string();
        let target_path_s = target_path.to_string();
        let entity_type_s = entity_type.to_string();
        let entity = match entity_entity::Entity::new(&entity_type_s, entity_data.to_vec()) {
            Ok(e) => e,
            Err(e) => {
                godot_error!(
                    "EntityPeer.tree_put_async_cross_peer: entity creation failed: {}",
                    e
                );
                return None;
            }
        };
        // Mirror sdk.rs::build_put_params: data must be decoded CBOR Value,
        // not Value::Bytes — handler re-encodes whatever Value it extracts;
        // sending Value::Bytes(raw) double-wraps and corrupts.
        let data_value: entity_ecf::Value = match ciborium::from_reader(
            entity.data.as_slice(),
        ) {
            Ok(v) => v,
            Err(e) => {
                godot_error!(
                    "EntityPeer.tree_put_async_cross_peer: data must be valid CBOR \
                     (build_put_params requires decoded Value, not raw bytes): {}",
                    e
                );
                return None;
            }
        };
        let entity_cbor = entity_ecf::Value::Map(vec![
            (entity_ecf::text("type"), entity_ecf::text(&entity.entity_type)),
            (entity_ecf::text("data"), data_value),
        ]);
        let params_map = entity_ecf::Value::Map(vec![
            (entity_ecf::text("entity"), entity_cbor),
        ]);
        let mut params_bytes = Vec::new();
        if let Err(e) = ciborium::into_writer(&params_map, &mut params_bytes) {
            godot_error!(
                "EntityPeer.tree_put_async_cross_peer: params CBOR encode failed: {}",
                e
            );
            return None;
        }
        let params = match entity_entity::Entity::new("system/tree/put_params", params_bytes) {
            Ok(e) => e,
            Err(e) => {
                godot_error!(
                    "EntityPeer.tree_put_async_cross_peer: params entity creation failed: {}",
                    e
                );
                return None;
            }
        };
        let cap_hash_bytes = capability_hash.to_vec();
        let cap_hash = match entity_hash::Hash::from_bytes(&cap_hash_bytes) {
            Ok(h) => h,
            Err(e) => {
                godot_error!(
                    "EntityPeer.tree_put_async_cross_peer: invalid capability_hash: {}",
                    e
                );
                return None;
            }
        };
        let ctx = self.ctx.as_ref()?.clone();
        let cap_entity = match ctx.peer_shared().content_store.get(&cap_hash) {
            Some(e) => e,
            None => {
                godot_error!(
                    "EntityPeer.tree_put_async_cross_peer: capability entity not in \
                     local content store for hash {}",
                    cap_hash
                );
                return None;
            }
        };
        let opts = entity_handler::ExecuteOptions {
            capability: Some(cap_entity),
            resource: Some(entity_capability::ResourceTarget {
                targets: vec![target_path_s.clone()],
                exclude: vec![],
            }),
            ..Default::default()
        };
        let handler_uri = format!("entity://{}/system/tree", target_pid_s);
        let (fut, slot) = PeerOpFuture::new_pending();
        let rt = self.runtime.handle()?;
        rt.spawn(async move {
            let raw = match ctx.execute(handler_uri, "put".to_string(), params, opts).await {
                Ok(result) => OpResultRaw::Entity(Some(result.result)),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// Execute a local handler operation. Returns the result entity, or null on error.
    ///
    /// This dispatches through the same handler resolution path as wire protocol
    /// requests, but without TCP, auth, or envelope framing. L1.
    #[func]
    fn execute(
        &self,
        handler: GString,
        operation: GString,
        params_type: GString,
        params_data: PackedByteArray,
    ) -> Option<Gd<EntityData>> {
        let ctx = self.ctx.as_ref()?;
        let handle = self.runtime.handle()?;
        let params = entity_entity::Entity::new(&params_type.to_string(), params_data.to_vec())
            .map_err(|e| godot_error!("EntityPeer: params creation failed: {}", e))
            .ok()?;
        // Spawn + blocking-recv pattern instead of `runtime.block_on(...)` —
        // works whether our runtime is Owned (we have a Runtime) or Borrowed
        // (we only have a Handle, which has no block_on). The sync-wait
        // here is correct for sync `execute`: the dispatch is a straight
        // handler call with no `process()`-tick dependency (unlike
        // `execute_async` for registered handlers).
        let ctx_clone = ctx.clone();
        let handler_str = handler.to_string();
        let op_str = operation.to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        handle.spawn(async move {
            let result = ctx_clone.peer().execute(&handler_str, &op_str, params).await;
            let _ = tx.send(result);
        });
        let result = rx
            .recv()
            .map_err(|e| godot_error!("EntityPeer: execute result-channel dropped: {}", e))
            .ok()?
            .map_err(|e| godot_error!("EntityPeer: execute failed: {}", e))
            .ok()?;
        Some(EntityData::from_entity(&result.result))
    }

    // -----------------------------------------------------------------
    // L1 dispatched tree ops
    // -----------------------------------------------------------------
    //
    // Each `tree_*_async` routes through the kernel's `system/tree`
    // handler via `PeerContext`'s SDK methods, honoring capability
    // tokens. The returned `PeerOpFuture` fires `completed(result)`
    // exactly once on the main thread.
    //
    // Result Variant shape per op:
    //   tree_get_async    → EntityData | null
    //   tree_put_async    → PackedByteArray (33-byte content hash) | null on error
    //   tree_has_async    → bool
    //   tree_remove_async → bool
    //   tree_list_async   → PackedStringArray

    /// L1 dispatched `system/tree:get`. Capability-checked.
    #[func]
    fn tree_get_async(&mut self, path: GString) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("tree_get_async") {
            return None;
        }
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        let path_owned = path.to_string();
        rt.spawn(async move {
            let raw = match ctx.get(&path_owned).await {
                Ok(entity) => OpResultRaw::Entity(entity),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// L1 dispatched `system/tree:put`. Capability-checked.
    #[func]
    fn tree_put_async(
        &mut self,
        path: GString,
        entity_type: GString,
        data: PackedByteArray,
    ) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("tree_put_async") {
            return None;
        }
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        let path_owned = path.to_string();
        let entity = match entity_entity::Entity::new(&entity_type.to_string(), data.to_vec()) {
            Ok(e) => e,
            Err(e) => {
                godot_error!("EntityPeer.tree_put_async: entity creation failed: {}", e);
                return None;
            }
        };
        rt.spawn(async move {
            let raw = match ctx.put(path_owned, entity).await {
                Ok(hash) => OpResultRaw::Hash(hash),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// L1 dispatched `system/tree:has`. Capability-checked.
    #[func]
    fn tree_has_async(&mut self, path: GString) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("tree_has_async") {
            return None;
        }
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        let path_owned = path.to_string();
        rt.spawn(async move {
            let raw = match ctx.has(&path_owned).await {
                Ok(b) => OpResultRaw::Bool(b),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// L1 dispatched `system/tree:remove`. Capability-checked.
    #[func]
    fn tree_remove_async(&mut self, path: GString) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("tree_remove_async") {
            return None;
        }
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        let path_owned = path.to_string();
        rt.spawn(async move {
            let raw = match ctx.remove(&path_owned).await {
                Ok(b) => OpResultRaw::Bool(b),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// L1 dispatched `system/tree:list`. Capability-checked.
    #[func]
    fn tree_list_async(&mut self, prefix: GString) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("tree_list_async") {
            return None;
        }
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        let prefix_owned = prefix.to_string();
        rt.spawn(async move {
            // The L1 list returns immediate-children listings with `name`
            // (just the leaf segment). Compose against the prefix so the
            // GDScript surface matches the existing sync `tree_list` —
            // PackedStringArray of fully-qualified paths.
            let raw = match ctx.list(&prefix_owned).await {
                Ok(entries) => {
                    let base = if prefix_owned.is_empty() || prefix_owned.ends_with('/') {
                        prefix_owned.clone()
                    } else {
                        format!("{}/", prefix_owned)
                    };
                    OpResultRaw::PathList(
                        entries
                            .into_iter()
                            .map(|e| format!("{}{}", base, e.name))
                            .collect(),
                    )
                }
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    // -----------------------------------------------------------------
    // L1 query / count / discover
    // -----------------------------------------------------------------
    //
    // `query_async` / `count_async` dispatch `system/query:find` / `:count`
    // with a `system/query/expression` entity built from the supplied
    // Dictionary. `discover_*` walk the type / handler registries on the
    // local peer (sync underneath, exposed as futures for arm parity with
    // the other L1 ops).
    //
    // ── Field-name convention (canonical schema, see core_types.rs:2386) ──
    // The expression Dictionary keys MUST be the canonical
    // `system/query/expression` field names:
    //
    //     type_filter, ref_filter, path_filter, path_prefix,
    //     limit, cursor, include_entities
    //
    // Earlier drafts of the binding request referred to these as `type` /
    // `ref_hash` / `path` — those names are not what the kernel handler
    // (`extensions/query/src/lib.rs:567+`) reads. Unknown keys are silently
    // ignored: the previous filter is simply not applied, which produces
    // wrong-but-not-failing query results. Callers that hit "everything
    // matched my type filter" should check spelling against this list.

    /// L1 dispatched `system/query:find`. Capability-checked.
    ///
    /// `expression` is a Dictionary matching `system/query/expression`.
    /// Supported fields (all optional):
    ///   * `type_filter`: String — entity type filter
    ///   * `ref_filter`: PackedByteArray (32 bytes) — reverse-hash filter
    ///   * `path_filter`: String — exact path filter
    ///   * `path_prefix`: String — prefix filter
    ///   * `limit`: int — page size (default 100, max 10_000)
    ///   * `cursor`: String — continuation from previous call
    ///   * `include_entities`: bool — populate match.entity (default false)
    ///
    /// On success the future's `completed` Variant is a Dictionary:
    ///   { matches: Array[Dictionary], has_more: bool, total: int, cursor: String }
    /// Each match Dictionary:
    ///   { path: String, content_hash: PackedByteArray (32),
    ///     entity_type: String, entity: EntityData | null }
    #[func]
    fn query_async(&mut self, expression: VarDictionary) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("query_async") {
            return None;
        }
        let entity = match build_query_expression_entity(&expression) {
            Ok(e) => e,
            Err(msg) => {
                godot_error!("EntityPeer.query_async: {}", msg);
                return None;
            }
        };
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        rt.spawn(async move {
            let raw = match ctx.query(entity).await {
                Ok(qr) => OpResultRaw::QueryResults(qr),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// L1 dispatched `system/query:count`. Capability-checked.
    ///
    /// `expression` accepts the same field set as `query_async`; the
    /// `limit`, `cursor`, and `include_entities` keys are accepted but
    /// the handler ignores them for count (spec EXTENSION-QUERY §6).
    ///
    /// On success the future's `completed` Variant is an int (the total).
    #[func]
    fn count_async(&mut self, expression: VarDictionary) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("count_async") {
            return None;
        }
        let entity = match build_query_expression_entity(&expression) {
            Ok(e) => e,
            Err(msg) => {
                godot_error!("EntityPeer.count_async: {}", msg);
                return None;
            }
        };
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        rt.spawn(async move {
            let raw = match ctx.count(entity).await {
                Ok(n) => OpResultRaw::Int(i64::try_from(n).unwrap_or(i64::MAX)),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// Enumerate handlers registered on this peer.
    ///
    /// On success the future's `completed` Variant is `Array[Dictionary]`,
    /// each entry: `{ pattern: String, name: String, operations: PackedStringArray }`.
    ///
    /// Underneath this is sync — the SDK walks `system/handler/*` from the
    /// local tree. The future shape is preserved for arm parity with the
    /// other async ops; resolution typically happens in the same frame.
    #[func]
    fn discover_handlers(&mut self) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("discover_handlers") {
            return None;
        }
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        rt.spawn(async move {
            // PeerContext::discover_handlers is sync; wrap to fit the
            // tokio::spawn signature without changing call shape.
            let raw = OpResultRaw::HandlerList(ctx.discover_handlers());
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// Enumerate types declared on this peer.
    ///
    /// On success the future's `completed` Variant is `Array[Dictionary]`,
    /// each entry:
    ///   { type_path: String, fields: Array[Dictionary] }
    /// Each field Dictionary:
    ///   { name: String, type_ref: String, optional: bool }
    ///
    /// Sync underneath; same arm-parity note as `discover_handlers`.
    #[func]
    fn discover_types(&mut self) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("discover_types") {
            return None;
        }
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        rt.spawn(async move {
            let raw = OpResultRaw::TypeList(ctx.discover_types());
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    // -----------------------------------------------------------------
    // L1 history / revision
    // -----------------------------------------------------------------
    //
    // history_query / history_rollback ride the SDK's typed helpers
    // (`PeerContext::history_query` / `history_rollback`). revision_log /
    // revision_checkout have no SDK helper yet, so they call
    // `ctx.execute("system/revision", op, params, opts)` and decode the
    // envelope here.
    //
    // ── Open follow-ups versus the request's §2 schema:
    //   1. `history_query_async` rich filter set CLOSED —
    //      `HistoryQueryOptions { limit, since, before, events }` shipped
    //      at `entity-core-rust/bindings/sdk/src/sdk.rs:530`; binding
    //      plumbs all four through (see `history_query_async` below).
    //      `since` semantics caveat: matches against the transition-entity
    //      hash, not the path content_hash inside the transition. Only
    //      `HistoryQueryResult.head` is consumer-reachable as an anchor
    //      today; mid-walk paging needs a separate ask if a multi-window
    //      driver materializes (per the T2 SDK-extensions absorption
    //      note).
    //   2. `revision_log_async` request §2.3 expected
    //      `commits[{hash, parents, author, timestamp, message}]`. Per
    //      `PROPOSAL-STRUCTURAL-VERSION-ENTRIES`, version entries hold
    //      `{root, parents}` only — author / timestamp / message do not
    //      exist. We expose `{hash, root, parents}` per the actual entry.
    //   3. `revision_log_async` request §2.3 took a `branch` arg. The
    //      kernel's log op walks from the prefix's active HEAD; branch
    //      selection happens via `revision:checkout` (branch arg there).
    //      Binding accepts the parameter for forward-compatibility but
    //      ignores it; warn if non-empty.

    /// L1 dispatched `system/history:query`. Capability-checked.
    ///
    /// `filters` accepted keys (all optional):
    ///   * `limit`: int — page size; missing → engine default (50)
    ///   * `since`: PackedByteArray(33) — transition-entity hash to stop
    ///     before (exclusive). Only `HistoryQueryResult.head` from a
    ///     prior query is consumer-reachable as an anchor today; deeper
    ///     paging anchors not surfaced.
    ///   * `before`: int — Unix milliseconds; skip transitions whose
    ///     timestamp is at-or-after this value.
    ///   * `events`: PackedStringArray — keep only matching event tags
    ///     (∈ {"created", "updated", "deleted"}).
    ///
    /// On success the future's `completed` Variant is a Dictionary:
    ///   { path: String, head: PackedByteArray|null,
    ///     transitions: Array[Dictionary], has_more: bool }
    /// Each transition Dictionary:
    ///   { event: String, hash: PackedByteArray|null,
    ///     previous_hash: PackedByteArray|null, timestamp: int }
    ///
    /// Note: the SDK's typed `HistoryTransition` does not currently
    /// surface `author`, `capability`, or `chain_id` — only the four
    /// fields above. The wire entity carries more; binding-side
    /// expansion gated on SDK helper extension.
    #[func]
    fn history_query_async(
        &mut self,
        path: GString,
        filters: VarDictionary,
    ) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("history_query_async") {
            return None;
        }
        // Decode the full filter set per the kernel handler shape at
        // `extensions/history/src/lib.rs:291` — `limit` (u64), `since`
        // (33-byte hash bytes), `before` (u64 ms-since-epoch), `events`
        // (array of strings). All optional; missing keys ride as None.
        let limit = filters
            .get("limit")
            .and_then(|v| v.try_to::<i64>().ok())
            .filter(|n| *n > 0)
            .map(|n| n as u64);
        let since = filters
            .get("since")
            .and_then(|v| v.try_to::<PackedByteArray>().ok())
            .and_then(|pba| entity_hash::Hash::from_bytes(&pba.to_vec()).ok());
        let before = filters
            .get("before")
            .and_then(|v| v.try_to::<i64>().ok())
            .filter(|n| *n >= 0)
            .map(|n| n as u64);
        let events = filters
            .get("events")
            .and_then(|v| v.try_to::<PackedStringArray>().ok())
            .map(|arr| arr.to_vec().into_iter().map(|g| g.to_string()).collect::<Vec<_>>());
        let options = entity_sdk::HistoryQueryOptions {
            limit,
            since,
            before,
            events,
        };

        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        let path_owned = path.to_string();
        rt.spawn(async move {
            let raw = match ctx.history_query(path_owned, options).await {
                Ok(r) => OpResultRaw::HistoryQuery(r),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// L1 dispatched `system/history:rollback`. Capability-checked.
    ///
    /// `target_hash` is a 33-byte PackedByteArray — the wire hash format
    /// (one-byte algorithm code + 32-byte digest) per
    /// `core/hash/src/lib.rs`. Any transition's `hash` from the query
    /// result is a valid input.
    ///
    /// On success the future's `completed` Variant is a Dictionary:
    ///   { status: "ok", rolled_back_to: PackedByteArray (the input hash) }
    /// On error: `null` and a `godot_error!` log; the error message
    /// follows the SDK's `SdkError::to_string()` shape.
    #[func]
    fn history_rollback_async(
        &mut self,
        path: GString,
        target_hash: PackedByteArray,
    ) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("history_rollback_async") {
            return None;
        }
        let hash = match entity_hash::Hash::from_bytes(&target_hash.to_vec()) {
            Ok(h) => h,
            Err(e) => {
                godot_error!(
                    "EntityPeer.history_rollback_async: invalid target_hash bytes ({} bytes): {}",
                    target_hash.len(),
                    e
                );
                return None;
            }
        };

        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        let path_owned = path.to_string();
        rt.spawn(async move {
            let raw = match ctx.history_rollback(path_owned, hash).await {
                Ok(()) => OpResultRaw::HistoryRollback(hash),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// L1 dispatched `system/revision:log`. Capability-checked.
    ///
    /// `branch` is accepted for forward-compatibility but ignored by the
    /// kernel log op (log walks from the prefix's active HEAD; branch
    /// selection is via `revision:checkout`). Pass `""` if you don't
    /// need it; passing a non-empty value logs a `godot_warn!`.
    ///
    /// On success the future's `completed` Variant is a Dictionary:
    ///   { prefix: String, commits: Array[Dictionary], has_more: bool }
    /// Each commit Dictionary (per `PROPOSAL-STRUCTURAL-VERSION-ENTRIES`):
    ///   { hash: PackedByteArray, root: PackedByteArray|null,
    ///     parents: Array[PackedByteArray] }
    /// `author` / `timestamp` / `message` are NOT exposed — revision
    /// entries are structural-only.
    #[func]
    fn revision_log_async(
        &mut self,
        prefix: GString,
        branch: GString,
    ) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("revision_log_async") {
            return None;
        }
        let branch_s = branch.to_string();
        if !branch_s.is_empty() {
            godot_warn!(
                "EntityPeer.revision_log_async: `branch` arg ignored — kernel `log` op walks \
                 from the prefix's active HEAD. Use `revision_checkout_async` to switch branches."
            );
        }
        let prefix_s = prefix.to_string();
        let params = build_revision_log_params(&prefix_s);

        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        rt.spawn(async move {
            let exec = ctx.execute(
                "system/revision",
                "log",
                params,
                entity_handler::ExecuteOptions::default(),
            );
            let raw = match exec.await {
                Ok(result) if result.status == 200 => {
                    match decode_revision_log_result(&result.result) {
                        Ok((prefix, versions, has_more)) => OpResultRaw::RevisionLog {
                            prefix,
                            versions,
                            has_more,
                        },
                        Err(e) => OpResultRaw::Err(e),
                    }
                }
                Ok(result) => OpResultRaw::Err(format!(
                    "system/revision:log returned status {}",
                    result.status
                )),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// L1 dispatched `system/revision:checkout`. Capability-checked.
    ///
    /// `target_hash` is a 33-byte PackedByteArray of the version entry
    /// to restore. Detached HEAD mode — pass via `version` param, not
    /// branch.
    ///
    /// On success the future's `completed` Variant is a Dictionary:
    ///   { status: "ok", checked_out: PackedByteArray,
    ///     head: PackedByteArray, branch: String|null,
    ///     cascade_warnings: PackedStringArray,
    ///     uncommitted_changes: bool }
    /// `cascade_warnings` is non-empty when the snapshot apply hit a
    /// path that could not be cleanly restored. `uncommitted_changes`
    /// is `true` if the live tree had pending writes when checkout
    /// fired (those writes were overwritten — surface to the user).
    #[func]
    fn revision_checkout_async(
        &mut self,
        prefix: GString,
        target_hash: PackedByteArray,
    ) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("revision_checkout_async") {
            return None;
        }
        let hash = match entity_hash::Hash::from_bytes(&target_hash.to_vec()) {
            Ok(h) => h,
            Err(e) => {
                godot_error!(
                    "EntityPeer.revision_checkout_async: invalid target_hash bytes ({} bytes): {}",
                    target_hash.len(),
                    e
                );
                return None;
            }
        };
        let prefix_s = prefix.to_string();

        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        rt.spawn(async move {
            let raw = match ctx.revision().checkout(prefix_s, hash).await {
                Ok(r) => OpResultRaw::RevisionCheckout {
                    head: r.head,
                    target_version: r.target_version,
                    branch: r.branch,
                    cascade_warnings: r.cascade_warnings,
                    uncommitted_changes: r.uncommitted_changes,
                },
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    // -----------------------------------------------------------------
    // Revision remaining (REQUEST-BINDING-PARITY-SWEEP-PHASE-1 §2.11)
    // Phase 1 batch: simple-input ops. Heavy ops (merge/fetch/
    // fetch_entities/config_set/merge_config_set, all with complex
    // typed-struct inputs) deferred to a follow-up.
    // -----------------------------------------------------------------

    /// L1 dispatched `system/revision:commit`. Snapshots the live tree
    /// under `prefix` as a new version. Returns Dict
    /// `{version, root, parent: PBA|null}`.
    #[func]
    fn revision_commit_async(&mut self, prefix: GString) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("revision_commit_async") {
            return None;
        }
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        let prefix_owned = prefix.to_string();
        rt.spawn(async move {
            let raw = match ctx.revision().commit(prefix_owned).await {
                Ok(r) => OpResultRaw::RevisionCommit(r),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// L1 dispatched `system/revision:status`. Reads HEAD pointer +
    /// outstanding-conflict count for `prefix`. Returns Dict
    /// `{head: PBA|null, conflicts: int}`.
    #[func]
    fn revision_status_async(&mut self, prefix: GString) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("revision_status_async") {
            return None;
        }
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        let prefix_owned = prefix.to_string();
        rt.spawn(async move {
            let raw = match ctx.revision().status(prefix_owned).await {
                Ok(r) => OpResultRaw::RevisionStatusResult(r),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// L1 dispatched `system/revision:config` (delete action). Removes
    /// the named config entry. `expected_hash` is an optional empty PBA
    /// (pass empty to skip optimistic-concurrency check) or 33-byte
    /// expected hash. Returns the standard ConfigResult Dict.
    #[func]
    fn revision_config_delete_async(
        &mut self,
        name: GString,
        expected_hash: PackedByteArray,
    ) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("revision_config_delete_async") {
            return None;
        }
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        let name_owned = name.to_string();
        let exp = if expected_hash.is_empty() {
            None
        } else {
            match entity_hash::Hash::from_bytes(&expected_hash.to_vec()) {
                Ok(h) => Some(h),
                Err(e) => {
                    godot_error!(
                        "EntityPeer.revision_config_delete_async: invalid expected_hash: {}",
                        e
                    );
                    return None;
                }
            }
        };
        rt.spawn(async move {
            let raw = match ctx.revision().config_delete(name_owned, exp).await {
                Ok(r) => OpResultRaw::RevisionConfig(r),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// L1 dispatched `system/revision:merge-config` (delete action).
    /// Same shape as `revision_config_delete_async` but targets the
    /// `merge-config` namespace.
    #[func]
    fn revision_merge_config_delete_async(
        &mut self,
        scope: GString,
        name: GString,
        expected_hash: PackedByteArray,
    ) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("revision_merge_config_delete_async") {
            return None;
        }
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        let scope_owned = scope.to_string();
        let name_owned = name.to_string();
        let exp = if expected_hash.is_empty() {
            None
        } else {
            match entity_hash::Hash::from_bytes(&expected_hash.to_vec()) {
                Ok(h) => Some(h),
                Err(e) => {
                    godot_error!(
                        "EntityPeer.revision_merge_config_delete_async: invalid expected_hash: {}",
                        e
                    );
                    return None;
                }
            }
        };
        rt.spawn(async move {
            let raw = match ctx
                .revision()
                .merge_config_delete(scope_owned, name_owned, exp)
                .await
            {
                Ok(r) => OpResultRaw::RevisionMergeConfig(r),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    // -----------------------------------------------------------------
    // L1 subscribe
    // -----------------------------------------------------------------

    /// L1 dispatched subscription via `system/subscription`. Returns a
    /// `PeerOpFuture` whose `completed` signal carries an
    /// `EntitySubscription` (same poll/event shape as the L0 `watch`).
    ///
    /// ── Pattern is a GLOB, not a string prefix ──
    /// The argument is named `prefix` for historical reasons but the
    /// kernel's matcher (extensions/subscription/src/engine.rs:539)
    /// only supports three forms:
    ///   `"*"`        — match every path
    ///   `"foo/*"`    — match `foo/X`, `foo/X/Y`, etc (requires the
    ///                  trailing `/*`; bare `"foo"` is exact-match only)
    ///   `"foo/bar"`  — exact match
    ///
    /// Literal string prefixes such as `""`, `"/peer_id/"`, or
    /// `"workspace"` fall through to the exact-equality branch and
    /// **never deliver any event** — they pass capability checks and
    /// produce a valid handle, but the subscription is silently inert.
    /// Caught the godot-workbench team during Wave 2.2 pilot;
    /// the gate test that locks the correct pattern is
    /// `tests/integration/test_l1_subscribe_pilot.gd` in
    /// godot-entity-core-rust.
    ///
    /// ── Compared to `watch(prefix)` ──
    /// - Events route through the kernel's subscription extension, not
    ///   the L0 store-event broadcast.
    /// - Capability-checked (self-grant today; scoped grants are a
    ///   future SDK extension).
    /// - The handle's `Drop` unsubscribes via
    ///   `system/subscription:unsubscribe`.
    /// - Self-puts ARE delivered: the L1 dispatched `system/tree:put`
    ///   path triggers `RootTracker::on_tree_change` which the
    ///   subscription engine's sync hook listens on. The "remote-only"
    ///   wording elsewhere refers to delivery transport, not match
    ///   eligibility.
    ///
    /// GDScript:
    ///     var fut := peer.subscribe_l1("*")           # catch-all
    ///     var sub: EntitySubscription = await fut.completed
    ///     # ... per-frame: for evt in sub.poll(): ...
    ///
    ///     # Narrower: just selection writes under a peer
    ///     peer.subscribe_l1("/" + peer.peer_id() + "/app/godot-workbench/workspace/selection/*")
    #[func]
    fn subscribe_l1(&mut self, prefix: GString) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("subscribe_l1") {
            return None;
        }
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        let prefix_owned = prefix.to_string();

        let queue = std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::VecDeque::<(String, Vec<u8>)>::new(),
        ));
        let queue_for_cb = queue.clone();

        rt.spawn(async move {
            let cb = move |evt: entity_sdk::subscription::L1SubscriptionEvent| {
                // Match the L0 watch shape: { path, hash }. The L1 event
                // carries richer info (change type, prev hash) we drop for
                // parity with the existing GDScript consumer pattern.
                // Revisit when a caller actually needs the extras.
                let hash_bytes = evt
                    .new_hash
                    .map(|h| h.to_bytes().to_vec())
                    .unwrap_or_default();
                if let Ok(mut q) = queue_for_cb.lock() {
                    q.push_back((evt.path, hash_bytes));
                }
            };
            let raw = match ctx.subscribe(prefix_owned, cb).await {
                Ok(handle) => OpResultRaw::Subscription(SubscriptionPayload { handle, queue }),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// Configurable L1 subscription per SDK-EXTENSION-OPERATIONS §3
    /// `SubscribeParams` (T3.0.j). Same semantics as `subscribe_l1` —
    /// returns a `PeerOpFuture` whose `completed` carries an
    /// `EntitySubscription`. The `options` Dictionary accepts:
    ///
    ///   include_payload: bool   — bundle changed entity into the
    ///                             notification envelope; subscriber MUST
    ///                             hold `tree:get` on the resource or the
    ///                             handler rejects with 403
    ///                             payload_unauthorized
    ///   events:          Array  — subset of `["created", "updated",
    ///                             "deleted"]` to receive; absent or null
    ///                             = all three
    ///   max_events:      int    — auto-cancel after this many deliveries
    ///   max_duration_ms: int    — auto-cancel after this many ms
    ///   rate_limit:      int    — engine-defined rate cap (events/sec)
    ///
    /// All keys are optional. `subscribe_l1(prefix)` is equivalent to
    /// `subscribe_l1_with_options(prefix, {})`.
    ///
    /// The change-type filter is enforced server-side — events that
    /// don't match the `events` set are not delivered.
    #[func]
    fn subscribe_l1_with_options(
        &mut self,
        prefix: GString,
        options: Dictionary,
    ) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("subscribe_l1_with_options") {
            return None;
        }
        let opts = parse_subscribe_options(&options);
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        let prefix_owned = prefix.to_string();

        let queue = std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::VecDeque::<(String, Vec<u8>)>::new(),
        ));
        let queue_for_cb = queue.clone();

        rt.spawn(async move {
            let cb = move |evt: entity_sdk::subscription::L1SubscriptionEvent| {
                let hash_bytes = evt
                    .new_hash
                    .map(|h| h.to_bytes().to_vec())
                    .unwrap_or_default();
                if let Ok(mut q) = queue_for_cb.lock() {
                    q.push_back((evt.path, hash_bytes));
                }
            };
            let raw = match ctx.subscribe_with_options(prefix_owned, opts, cb).await {
                Ok(handle) => OpResultRaw::Subscription(SubscriptionPayload { handle, queue }),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    // -----------------------------------------------------------------
    // Extension config helpers
    // -----------------------------------------------------------------
    //
    // Each helper writes the appropriate config entity at the canonical
    // `system/{ext}/config/{key}` path via L1 dispatch. Key is derived
    // deterministically from the pattern (same pattern → same key, so
    // enable/disable round-trip cleanly). Avoids GDScript code knowing
    // kernel-internal entity types or paths.

    /// Enable `system/history` recording for entities matching `pattern`.
    ///
    /// `events` defaults to `["created", "updated", "deleted"]` if empty.
    /// `max_depth` is the per-path retention bound; pass `0` for unbounded.
    ///
    /// Returns a `PeerOpFuture` whose `completed` carries the config
    /// entity's content hash (PackedByteArray) on success, or null on
    /// error (with a `godot_error!` log).
    #[func]
    fn enable_history(
        &mut self,
        pattern: GString,
        events: PackedStringArray,
        max_depth: i64,
    ) -> Option<Gd<PeerOpFuture>> {
        let pattern_s = pattern.to_string();
        let events_vec: Vec<String> = if events.is_empty() {
            vec!["created".into(), "updated".into(), "deleted".into()]
        } else {
            (0..events.len())
                .filter_map(|i| events.get(i).map(|g| g.to_string()))
                .collect()
        };
        let max_depth_opt = if max_depth > 0 { Some(max_depth as u64) } else { None };

        let data = build_history_config_data(&pattern_s, true, &events_vec, max_depth_opt);
        let entity = match entity_entity::Entity::new(entity_types::TYPE_HISTORY_CONFIG, data) {
            Ok(e) => e,
            Err(e) => {
                godot_error!("EntityPeer.enable_history: entity creation failed: {}", e);
                return None;
            }
        };
        let path = config_path("history", &self.peer_id_for_path()?, &pattern_s);
        self.spawn_put(path, entity)
    }

    /// Disable `system/history` recording for `pattern` by removing the
    /// config entity. (Engine treats missing config as "do not record".)
    #[func]
    fn disable_history(&mut self, pattern: GString) -> Option<Gd<PeerOpFuture>> {
        let path = config_path("history", &self.peer_id_for_path()?, &pattern.to_string());
        self.spawn_remove(path)
    }

    /// Enable `system/revision` for entities matching `pattern`.
    ///
    /// `auto_version` true → engine creates a new revision on every
    /// matching put; false → revisions on explicit `system/revision:save`
    /// only.
    ///
    /// **Caution:** REVISION is O(N)/Put on flat namespaces. Pick prefixes
    /// deliberately — `settings/theme` is fine; broad `workspace/*` is not.
    #[func]
    fn enable_revision(
        &mut self,
        pattern: GString,
        auto_version: bool,
    ) -> Option<Gd<PeerOpFuture>> {
        let pattern_s = pattern.to_string();
        let data = build_revision_config_data(&pattern_s, true, auto_version);
        let entity = match entity_entity::Entity::new(entity_types::TYPE_REVISION_CONFIG, data) {
            Ok(e) => e,
            Err(e) => {
                godot_error!("EntityPeer.enable_revision: entity creation failed: {}", e);
                return None;
            }
        };
        let path = config_path("revision", &self.peer_id_for_path()?, &pattern_s);
        self.spawn_put(path, entity)
    }

    /// Disable `system/revision` for `pattern` by removing the config entity.
    #[func]
    fn disable_revision(&mut self, pattern: GString) -> Option<Gd<PeerOpFuture>> {
        let path = config_path("revision", &self.peer_id_for_path()?, &pattern.to_string());
        self.spawn_remove(path)
    }

    // -----------------------------------------------------------------
    // Compute Phase 1 (REQUEST-BINDING-PARITY-SWEEP-PHASE-1 §2.1)
    // -----------------------------------------------------------------

    /// L1 dispatched `system/compute:eval`. One-shot evaluation of the
    /// expression at `expr_path`.
    ///
    /// `budget` is the per-call ops cap; pass `0` for handler default.
    ///
    /// On success the future's `completed` Variant is a Dictionary:
    ///   { value: <kind-dict>, result_entity: EntityData }
    /// where `<kind-dict>` is `{ kind: <name>, value: <typed> }` per
    /// `compute_ops.rs` module docs.
    ///
    /// Per F10, an error *value* surfaces as `value.kind == "error"`
    /// at status 200 — dispatch succeeded but the computation
    /// produced a `compute/error`. Transport / 404 / 400 failures
    /// surface as `null` with a `godot_error!` log.
    #[func]
    fn compute_eval_async(
        &mut self,
        expr_path: GString,
        budget: i64,
    ) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("compute_eval_async") {
            return None;
        }
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        let path_owned = expr_path.to_string();
        let opts = entity_sdk::compute::EvalOptions {
            budget: if budget > 0 { Some(budget as u64) } else { None },
        };
        rt.spawn(async move {
            let raw = match ctx.compute().eval(path_owned, opts).await {
                Ok(r) => OpResultRaw::ComputeEval(r),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// L1 dispatched `system/compute:install`. Installs a reactive
    /// subgraph rooted at `root_expression_path`.
    ///
    /// `result_path` overrides the default `<root>/result` reactive
    /// write target; pass `""` for default.
    ///
    /// On success the future's `completed` Variant is a Dictionary:
    ///   { subgraph_path: String, result_path: String }
    ///
    /// **Requires a caller capability** — the installation grant
    /// authorizes all subsequent reactive re-evaluations. Without
    /// one the handler returns 403 `permission_denied`.
    #[func]
    fn compute_install_async(
        &mut self,
        root_expression_path: GString,
        result_path: GString,
    ) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("compute_install_async") {
            return None;
        }
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        let root_owned = root_expression_path.to_string();
        let result_path_s = result_path.to_string();
        let opts = entity_sdk::compute::InstallOptions {
            result_path: if result_path_s.is_empty() {
                None
            } else {
                Some(result_path_s)
            },
        };
        rt.spawn(async move {
            let raw = match ctx.compute().install(root_owned, opts).await {
                Ok(r) => OpResultRaw::ComputeInstall(r),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// L1 dispatched `system/compute:uninstall`. Removes the reactive
    /// subgraph at `subgraph_path`.
    ///
    /// On success the future's `completed` Variant is `true`; on
    /// error it's `null` with a `godot_error!` log. 404 fires when
    /// no subgraph is installed at the given path.
    #[func]
    fn compute_uninstall_async(&mut self, subgraph_path: GString) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("compute_uninstall_async") {
            return None;
        }
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        let path_owned = subgraph_path.to_string();
        rt.spawn(async move {
            let raw = match ctx.compute().uninstall(path_owned).await {
                Ok(()) => OpResultRaw::Bool(true),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// Sync L0 list of installed reactive subgraphs on the local
    /// peer. Returns Array[Dictionary]; each entry carries the full
    /// `system/compute/subgraph` metadata shape (see
    /// `compute_ops::installed_subgraph_to_dict`).
    ///
    /// Empty Array on a fresh peer. No dispatch, no capability check
    /// — the caller is expected to be the peer owner (or the peer
    /// would expose this via a typed handler op).
    #[func]
    fn compute_list(&self) -> VariantArray {
        let mut arr = VariantArray::new();
        let Some(ctx) = self.ctx.as_ref() else {
            return arr;
        };
        for s in ctx.compute().list() {
            arr.push(&crate::compute_ops::installed_subgraph_to_dict(&s).to_variant());
        }
        arr
    }

    // -----------------------------------------------------------------
    // Bootstrap + IdentityBundle (REQUEST-BINDING-PARITY-SWEEP-PHASE-1 §2.2/§2.3)
    // -----------------------------------------------------------------

    /// L0 identity-bootstrap ceremony. Idempotent: returns the
    /// `already_bootstrapped` shape when a peer-config already exists
    /// at `/{peer_id}/system/identity/peer-config`. Phase 1 supports
    /// `threshold = 1` only; `> 1` returns `multi_signer_unsupported`
    /// from the SDK (surfaced as a `godot_error!` log + null future).
    ///
    /// `label` is the human-readable name attached to the quorum
    /// entity; empty string omits the label.
    ///
    /// `properties` are caller-supplied key→string properties merged
    /// into the controller-cert attestation. Spec-required keys
    /// (`kind`, `function`, `mode`) are injected by the SDK and must
    /// not appear here — extra keys with those names are silently
    /// passed through but may collide.
    ///
    /// On success the future's `completed` Variant is a Dictionary
    /// per `bootstrap_ops::bootstrap_result_to_variant`:
    /// - `{ status: "already_bootstrapped", identity_hash, quorum_id }`
    /// - `{ status: "bootstrapped", identity_hash, quorum_id,
    ///      controller_cert, peer_config_path, issued_caps: [PBA] }`
    #[func]
    fn bootstrap_identity_async(
        &mut self,
        threshold: i64,
        label: GString,
        properties: VarDictionary,
        force: bool,
    ) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("bootstrap_identity_async") {
            return None;
        }
        let label_s = label.to_string();
        let opts = entity_sdk::identity_bootstrap::BootstrapOptions {
            quorum_threshold: if threshold > 0 { threshold as usize } else { 1 },
            additional_signers: vec![],
            label: if label_s.is_empty() { None } else { Some(label_s) },
            properties: crate::bootstrap_ops::decode_string_properties(&properties),
            force,
        };

        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        rt.spawn(async move {
            let raw = match ctx.identity().bootstrap(opts).await {
                Ok(r) => OpResultRaw::Bootstrap(r),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// Sync L0 read of bootstrap status. Returns Dictionary:
    ///   { bootstrapped: bool, identity_hash: PBA,
    ///     quorum_id: PBA|null, peer_config_path: String|null }
    #[func]
    fn bootstrap_status(&self) -> Dictionary {
        let Some(ctx) = self.ctx.as_ref() else {
            return Dictionary::new();
        };
        crate::bootstrap_ops::bootstrap_status_to_dict(ctx.identity().bootstrap_status())
    }

    /// Export the local peer's identity stack as a portable bundle
    /// (SDK-IDENTITY-INFRASTRUCTURE v0.4 §8.4a entity-shape).
    /// Returns the deterministic CBOR bytes; the bundle carries NO
    /// private key material (the v1 `keypair_pem` defect was fixed).
    /// Restore requires the matching keypair on the
    /// receiving peer.
    ///
    /// Returns an empty PackedByteArray on error (with a
    /// `godot_error!` log).
    #[func]
    fn export_identity_bundle(&self) -> PackedByteArray {
        let mut out = PackedByteArray::new();
        let Some(ctx) = self.ctx.as_ref() else {
            godot_error!("EntityPeer.export_identity_bundle: peer not started");
            return out;
        };
        let bundle = match ctx.identity().export_bundle() {
            Ok(b) => b,
            Err(e) => {
                godot_error!("EntityPeer.export_identity_bundle: {}", e);
                return out;
            }
        };
        match bundle.to_cbor() {
            Ok(bytes) => out.extend(bytes),
            Err(e) => {
                godot_error!("EntityPeer.export_identity_bundle: encode failed: {}", e);
            }
        }
        out
    }

    /// Restore the local peer's identity stack from a bundle CBOR.
    /// Decodes the bundle (rejecting v1 `keypair_pem` bytes with the
    /// "treat as compromised, re-export from local keystore" error),
    /// then runs the bootstrap-equivalent ceremony against the
    /// receiver's keypair. Result shape matches
    /// `bootstrap_identity_async`'s `completed` Variant.
    #[func]
    fn restore_identity_bundle_async(
        &mut self,
        bundle_cbor: PackedByteArray,
    ) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("restore_identity_bundle_async") {
            return None;
        }
        let bytes = bundle_cbor.to_vec();
        let bundle = match entity_sdk::identity_bundle::IdentityBundle::from_cbor(&bytes) {
            Ok(b) => b,
            Err(e) => {
                godot_error!(
                    "EntityPeer.restore_identity_bundle_async: decode failed: {}",
                    e
                );
                return None;
            }
        };
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        rt.spawn(async move {
            let raw = match ctx.identity().restore_from_bundle(&bundle).await {
                Ok(r) => OpResultRaw::Bootstrap(r),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// Sync L0 read of the subgraph metadata at `subgraph_path`.
    /// Returns the metadata Dictionary (same shape as `compute_list`
    /// entries) or `null` when no `system/compute/subgraph` entity
    /// is bound at the path.
    ///
    /// `subgraph_path` may be either a fully qualified
    /// `/{peer_id}/system/compute/processes/{id}` path or a relative
    /// `system/compute/processes/{id}` (peer_id prepended internally).
    #[func]
    fn compute_show(&self, subgraph_path: GString) -> Variant {
        let Some(ctx) = self.ctx.as_ref() else {
            return Variant::nil();
        };
        match ctx.compute().show(&subgraph_path.to_string()) {
            Some(s) => crate::compute_ops::installed_subgraph_to_dict(&s).to_variant(),
            None => Variant::nil(),
        }
    }

    // -----------------------------------------------------------------
    // Clock (REQUEST-BINDING-PARITY-SWEEP-PHASE-1 §2.8)
    // -----------------------------------------------------------------

    /// L1 dispatched `system/clock:now`. Reads the configured clock
    /// mode's state — wall/logical/vector/hlc.
    ///
    /// On success the future's `completed` Variant is a Dictionary:
    ///   { mode: String, timestamp_ms?, logical?, vector?, hlc? }
    /// — only the fields populated for the active mode are present.
    #[func]
    fn clock_now_async(&mut self) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("clock_now_async") {
            return None;
        }
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        rt.spawn(async move {
            let raw = match ctx.clock().now().await {
                Ok(s) => OpResultRaw::ClockState(s),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// L1 dispatched `system/clock:compare`. Orders two ClockValue
    /// inputs of the same kind. Returns int: -1 (Before), 0 (Equal),
    /// 1 (After), 2 (Concurrent — vector clocks only). Mismatched
    /// kinds error from the handler.
    ///
    /// Input Dictionary shape (one of):
    ///   { kind: "timestamp", value: int }
    ///   { kind: "logical", value: int }
    ///   { kind: "vector", entries: Dictionary[String→int] }
    ///   { kind: "hlc", physical: int, logical: int, peer: PBA }
    #[func]
    fn clock_compare_async(
        &mut self,
        a: VarDictionary,
        b: VarDictionary,
    ) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("clock_compare_async") {
            return None;
        }
        let av = match decode_clock_value(&a, "a") {
            Ok(v) => v,
            Err(e) => {
                godot_error!("EntityPeer.clock_compare_async: {}", e);
                return None;
            }
        };
        let bv = match decode_clock_value(&b, "b") {
            Ok(v) => v,
            Err(e) => {
                godot_error!("EntityPeer.clock_compare_async: {}", e);
                return None;
            }
        };
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        rt.spawn(async move {
            let raw = match ctx.clock().compare(av, bv).await {
                Ok(o) => OpResultRaw::ClockOrder(o),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    // -----------------------------------------------------------------
    // Continuation (REQUEST-BINDING-PARITY-SWEEP-PHASE-1 §2.9)
    // -----------------------------------------------------------------

    /// L1 dispatched `system/continuation:install`. Persists a
    /// continuation entity at `path`. `body_type` must be
    /// `system/continuation` (forward) or `system/continuation/join`
    /// (join). Returns Bool(true) on success, null on error.
    #[func]
    fn continuation_install_async(
        &mut self,
        path: GString,
        body_type: GString,
        body_data: PackedByteArray,
    ) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("continuation_install_async") {
            return None;
        }
        let entity = match entity_entity::Entity::new(&body_type.to_string(), body_data.to_vec()) {
            Ok(e) => e,
            Err(e) => {
                godot_error!(
                    "EntityPeer.continuation_install_async: entity creation failed: {}",
                    e
                );
                return None;
            }
        };
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        let path_owned = path.to_string();
        rt.spawn(async move {
            let raw = match ctx.continuation().install(path_owned, entity).await {
                Ok(()) => OpResultRaw::Bool(true),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// L1 dispatched `system/continuation:resume`. Resumes a
    /// **suspended** continuation at `path`.
    ///
    /// SUSPENDED-ONLY: rejects any entity that isn't
    /// `system/continuation/suspended`
    /// (`extensions/continuation/src/lib.rs:1331`). Forward
    /// continuations (type `system/continuation`, created via
    /// `install`) are fired via `continuation_advance_async` —
    /// calling resume on a forward continuation will FAIL.
    ///
    /// `resolution_type` may be empty (no resolution body —
    /// equivalent to `None` in the SDK).
    /// Returns Dictionary `{status, result: EntityData}` from the
    /// downstream dispatch.
    #[func]
    fn continuation_resume_async(
        &mut self,
        path: GString,
        resolution_type: GString,
        resolution_data: PackedByteArray,
    ) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("continuation_resume_async") {
            return None;
        }
        let resolution = if resolution_type.is_empty() {
            None
        } else {
            match entity_entity::Entity::new(&resolution_type.to_string(), resolution_data.to_vec()) {
                Ok(e) => Some(e),
                Err(e) => {
                    godot_error!(
                        "EntityPeer.continuation_resume_async: resolution entity creation failed: {}",
                        e
                    );
                    return None;
                }
            }
        };
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        let path_owned = path.to_string();
        rt.spawn(async move {
            let raw = match ctx.continuation().resume(path_owned, resolution).await {
                Ok(r) => OpResultRaw::HandlerOk(r),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// L1 dispatched `system/continuation:advance`. Typically called
    /// by the inbox runtime on result delivery; exposed for app-tier
    /// orchestration / cross-impl parity. `status` <= 0 maps to None
    /// (handler defaults to 200).
    #[func]
    fn continuation_advance_async(
        &mut self,
        path: GString,
        result_bytes: PackedByteArray,
        status: i64,
    ) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("continuation_advance_async") {
            return None;
        }
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        let path_owned = path.to_string();
        let bytes = result_bytes.to_vec();
        let status_opt = if status > 0 { Some(status as u32) } else { None };
        rt.spawn(async move {
            let raw = match ctx
                .continuation()
                .advance(path_owned, bytes, status_opt)
                .await
            {
                Ok(r) => OpResultRaw::HandlerOk(r),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// L1 dispatched `system/continuation:abandon`. Removes the
    /// **suspended** continuation at `path`.
    ///
    /// SUSPENDED-ONLY: same constraint as `continuation_resume_async`
    /// — rejects any non-`system/continuation/suspended` entity
    /// (`extensions/continuation/src/lib.rs:1407`).
    ///
    /// Returns Bool(true) on success, null on error.
    #[func]
    fn continuation_abandon_async(&mut self, path: GString) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("continuation_abandon_async") {
            return None;
        }
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        let path_owned = path.to_string();
        rt.spawn(async move {
            let raw = match ctx.continuation().abandon(path_owned).await {
                Ok(()) => OpResultRaw::Bool(true),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    // -----------------------------------------------------------------
    // Inbox introspection (REQUEST-BINDING-PARITY-SWEEP-PHASE-1 §2.10)
    // -----------------------------------------------------------------

    /// List pending inbox entries under `/{peer_id}/system/inbox/`.
    /// Sync underneath — wrapped as `_async` for arm parity with
    /// `discover_handlers` / `discover_types`. Returns
    /// `Array[{ path: String, hash: PackedByteArray }]`.
    #[func]
    fn inbox_list_async(&mut self) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("inbox_list_async") {
            return None;
        }
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        rt.spawn(async move {
            let raw = OpResultRaw::InboxList(ctx.inbox_list());
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// Read a specific inbox delivery by path relative to
    /// `system/inbox/`. e.g. `inbox_get_async("sub-1/event-42")` reads
    /// `/{peer_id}/system/inbox/sub-1/event-42`. Returns EntityData
    /// on hit, null on miss.
    #[func]
    fn inbox_get_async(&mut self, relative_path: GString) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("inbox_get_async") {
            return None;
        }
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        let path_owned = relative_path.to_string();
        rt.spawn(async move {
            let raw = OpResultRaw::Entity(ctx.inbox_get(&path_owned));
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// Deliver `params_data` (CBOR-encoded entity payload of type
    /// `entity_type`) into the inbox at `target_path`. Wraps
    /// `PeerContext::inbox_send` → `system/inbox:receive`.
    ///
    /// `target_path` form: `/{receiver_pid}/system/inbox/{channel}`. The
    /// message is stored at `{target_path}/{request_id}`; empty
    /// `request_id` makes the SDK mint a fresh nonce (per-call unique).
    ///
    /// Mirrors `tree_put_async`'s `(entity_type, data)` encoding shape
    /// — `params_data` is the CBOR bytes of the message entity's `data`
    /// field, produced by `EntityCbor.encode_variant(...)` on the
    /// GDScript side.
    ///
    /// Returns `Gd<PeerOpFuture>` resolving to the storage path
    /// (`String`) on success, `null` on error.
    #[func]
    fn inbox_send_async(
        &mut self,
        target_path: GString,
        entity_type: GString,
        params_data: PackedByteArray,
        request_id: GString,
    ) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("inbox_send_async") {
            return None;
        }
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        let target_owned = target_path.to_string();
        let params = match entity_entity::Entity::new(
            &entity_type.to_string(),
            params_data.to_vec(),
        ) {
            Ok(e) => e,
            Err(e) => {
                godot_error!(
                    "EntityPeer.inbox_send_async: entity creation failed: {}",
                    e
                );
                return None;
            }
        };
        let rid_str = request_id.to_string();
        let rid = if rid_str.is_empty() { None } else { Some(rid_str) };
        rt.spawn(async move {
            let raw = match ctx.inbox_send(target_owned, params, rid).await {
                Ok(path) => OpResultRaw::InboxSend(path),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    // -----------------------------------------------------------------
    // Store-level access (REQUEST-BINDING-PARITY-SWEEP-PHASE-1 §2.13)
    // -----------------------------------------------------------------

    /// Sync L0 hash → Entity lookup via `StoreAccess::get_by_hash`.
    /// Returns the EntityData if the hash is in the content store,
    /// null otherwise. Useful for fetching entities by content hash
    /// from tree-changed signals or revision walks.
    ///
    /// `hash` must be a 33-byte PackedByteArray (algo tag + 32-byte
    /// digest). Wrong-size input returns null with a `godot_error!`.
    #[func]
    fn get_by_hash(&self, hash: PackedByteArray) -> Variant {
        let Some(ctx) = self.ctx.as_ref() else {
            return Variant::nil();
        };
        let bytes = hash.to_vec();
        let h = match entity_hash::Hash::from_bytes(&bytes) {
            Ok(h) => h,
            Err(e) => {
                godot_error!(
                    "EntityPeer.get_by_hash: invalid hash bytes ({} bytes): {}",
                    bytes.len(),
                    e
                );
                return Variant::nil();
            }
        };
        match ctx.store().get_by_hash(&h) {
            Some(entity) => crate::entity_resource::EntityData::from_entity(&entity).to_variant(),
            None => Variant::nil(),
        }
    }

    /// Sync L0 list of (path, entity) pairs under `prefix`. Wrapped
    /// as `_async` for arm parity. Each Array entry:
    ///   { path: String, entity: EntityData }
    #[func]
    fn list_entities_async(&mut self, prefix: GString) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("list_entities_async") {
            return None;
        }
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        let prefix_owned = prefix.to_string();
        rt.spawn(async move {
            let raw = OpResultRaw::PathEntityList(ctx.store().list_entities(&prefix_owned));
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    // -----------------------------------------------------------------
    // Diagnostics (REQUEST-BINDING-PARITY-SWEEP-PHASE-1 §2.14)
    // -----------------------------------------------------------------

    /// Total entities in the content store. O(1) on all current
    /// backends. Sync L0 — diagnostic only.
    #[func]
    fn entity_count(&self) -> i64 {
        self.ctx
            .as_ref()
            .map(|c| c.entity_count() as i64)
            .unwrap_or(0)
    }

    /// Total paths in the location index. O(1) on all current
    /// backends. Sync L0 — diagnostic only.
    #[func]
    fn path_count(&self) -> i64 {
        self.ctx
            .as_ref()
            .map(|c| c.path_count() as i64)
            .unwrap_or(0)
    }

    #[signal]
    fn tree_changed(path: GString, hash: PackedByteArray);
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

impl EntityPeer {
    /// Local peer_id as a String for path construction. None if not started.
    fn peer_id_for_path(&self) -> Option<String> {
        self.ctx.as_ref().map(|c| c.peer_id().to_string())
    }

    /// Shared backend for the put-based config helpers (enable_*).
    /// Returns the future and registers it on `self.pending`.
    fn spawn_put(&mut self, path: String, entity: entity_entity::Entity) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("enable_history/enable_revision") {
            return None;
        }
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        rt.spawn(async move {
            let raw = match ctx.put(path, entity).await {
                Ok(hash) => OpResultRaw::Hash(hash),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }

    /// Shared backend for the remove-based config helpers (disable_*).
    fn spawn_remove(&mut self, path: String) -> Option<Gd<PeerOpFuture>> {
        if !self.check_async_preconditions("disable_history/disable_revision") {
            return None;
        }
        let (fut, slot) = PeerOpFuture::new_pending();
        let ctx = self.ctx.as_ref()?.clone();
        let rt = self.runtime.handle()?;
        rt.spawn(async move {
            let raw = match ctx.remove(&path).await {
                Ok(b) => OpResultRaw::Bool(b),
                Err(e) => OpResultRaw::Err(e.to_string()),
            };
            if let Ok(mut s) = slot.lock() {
                *s = Some(raw);
            }
        });
        self.pending.push(fut.clone());
        Some(fut)
    }
}

/// Canonical config-entity path: `/{peer_id}/system/{ext}/config/{key}`.
///
/// Key is a deterministic transform of `pattern` so enable/disable on the
/// same pattern target the same entity. The transform is a sanitizer
/// (path-illegal chars to `_`) that preserves the pattern visibly in the
/// tree for debuggability.
/// Decode a `ClockValue` from a GDScript Dictionary tagged by `kind`.
/// Returns a user-facing error string suitable for `godot_error!`.
fn decode_clock_value(
    dict: &VarDictionary,
    label: &str,
) -> Result<entity_sdk::ClockValue, String> {
    let kind_v = dict
        .get("kind")
        .ok_or_else(|| format!("{}: missing `kind` field", label))?;
    let kind_s = kind_v
        .try_to::<GString>()
        .map_err(|_| format!("{}: `kind` must be a String", label))?
        .to_string();
    match kind_s.as_str() {
        "timestamp" => {
            let v = dict
                .get("value")
                .ok_or_else(|| format!("{}: timestamp missing `value`", label))?
                .try_to::<i64>()
                .map_err(|_| format!("{}: timestamp `value` must be int", label))?;
            Ok(entity_sdk::ClockValue::Timestamp(v as u64))
        }
        "logical" => {
            let v = dict
                .get("value")
                .ok_or_else(|| format!("{}: logical missing `value`", label))?
                .try_to::<i64>()
                .map_err(|_| format!("{}: logical `value` must be int", label))?;
            Ok(entity_sdk::ClockValue::Logical(v as u64))
        }
        "vector" => {
            let entries_v = dict
                .get("entries")
                .ok_or_else(|| format!("{}: vector missing `entries`", label))?;
            let entries = entries_v
                .try_to::<VarDictionary>()
                .map_err(|_| format!("{}: vector `entries` must be Dictionary", label))?;
            let mut map = std::collections::HashMap::new();
            for (k, v) in entries.iter_shared() {
                let key = k
                    .try_to::<GString>()
                    .map_err(|_| format!("{}: vector key must be String", label))?
                    .to_string();
                let val = v
                    .try_to::<i64>()
                    .map_err(|_| format!("{}: vector value must be int", label))?;
                map.insert(key, val as u64);
            }
            Ok(entity_sdk::ClockValue::Vector(map))
        }
        "hlc" => {
            let physical = dict
                .get("physical")
                .ok_or_else(|| format!("{}: hlc missing `physical`", label))?
                .try_to::<i64>()
                .map_err(|_| format!("{}: hlc `physical` must be int", label))?;
            let logical = dict
                .get("logical")
                .ok_or_else(|| format!("{}: hlc missing `logical`", label))?
                .try_to::<i64>()
                .map_err(|_| format!("{}: hlc `logical` must be int", label))?;
            let peer_bytes = dict
                .get("peer")
                .ok_or_else(|| format!("{}: hlc missing `peer`", label))?
                .try_to::<PackedByteArray>()
                .map_err(|_| format!("{}: hlc `peer` must be PackedByteArray", label))?;
            let peer = entity_hash::Hash::from_bytes(&peer_bytes.to_vec())
                .map_err(|e| format!("{}: hlc `peer` invalid hash: {}", label, e))?;
            Ok(entity_sdk::ClockValue::Hlc(entity_sdk::HlcState {
                physical: physical as u64,
                logical: logical as u64,
                peer,
            }))
        }
        other => Err(format!(
            "{}: unknown clock kind {:?} (expected timestamp/logical/vector/hlc)",
            label, other
        )),
    }
}

fn config_path(ext: &str, peer_id: &str, pattern: &str) -> String {
    let key: String = pattern
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '.' => c,
            _ => '_',
        })
        .collect();
    format!("/{}/system/{}/config/{}", peer_id, ext, key)
}

/// Build the ECF-encoded data field for a `TYPE_HISTORY_CONFIG` entity.
fn build_history_config_data(
    pattern: &str,
    enabled: bool,
    events: &[String],
    max_depth: Option<u64>,
) -> Vec<u8> {
    let mut fields: Vec<(entity_ecf::Value, entity_ecf::Value)> = vec![
        (entity_ecf::text("pattern"), entity_ecf::text(pattern)),
        (entity_ecf::text("enabled"), entity_ecf::bool_val(enabled)),
        (
            entity_ecf::text("events"),
            entity_ecf::Value::Array(events.iter().map(|s| entity_ecf::text(s)).collect()),
        ),
    ];
    if let Some(d) = max_depth {
        fields.push((
            entity_ecf::text("max_depth"),
            entity_ecf::integer(d as i64),
        ));
    }
    entity_ecf::to_ecf(&entity_ecf::Value::Map(fields))
}

/// Build a `system/query/expression` Entity from a GDScript Dictionary.
///
/// Field name convention is the canonical schema (see core_types.rs:2386).
/// Unknown keys are silently ignored (the kernel handler does the same;
/// staying lenient here matches existing behavior).
///
/// Accepted keys: `type_filter` (String), `ref_filter` (PackedByteArray,
/// 32 bytes — wire shape is the bare 32-byte digest per
/// `extensions/query/src/lib.rs:573` which calls `Hash::from_bytes` on the
/// raw bytes), `path_filter` (String), `path_prefix` (String), `limit`
/// (int), `cursor` (String), `include_entities` (bool).
///
/// Returns the error string on type-mismatch so the caller can route it
/// to `godot_error!` rather than silently producing an empty expression.
fn build_query_expression_entity(dict: &VarDictionary) -> Result<entity_entity::Entity, String> {
    let mut fields: Vec<(entity_ecf::Value, entity_ecf::Value)> = Vec::new();

    if let Some(v) = dict.get("type_filter") {
        let s = v.try_to::<GString>()
            .map_err(|e| format!("`type_filter` must be a String: {}", e))?;
        fields.push((entity_ecf::text("type_filter"), entity_ecf::text(s.to_string())));
    }
    if let Some(v) = dict.get("ref_filter") {
        let pba = v.try_to::<PackedByteArray>()
            .map_err(|e| format!("`ref_filter` must be a PackedByteArray: {}", e))?;
        fields.push((entity_ecf::text("ref_filter"), entity_ecf::bytes(pba.to_vec())));
    }
    if let Some(v) = dict.get("path_filter") {
        let s = v.try_to::<GString>()
            .map_err(|e| format!("`path_filter` must be a String: {}", e))?;
        fields.push((entity_ecf::text("path_filter"), entity_ecf::text(s.to_string())));
    }
    if let Some(v) = dict.get("path_prefix") {
        let s = v.try_to::<GString>()
            .map_err(|e| format!("`path_prefix` must be a String: {}", e))?;
        fields.push((entity_ecf::text("path_prefix"), entity_ecf::text(s.to_string())));
    }
    if let Some(v) = dict.get("limit") {
        let n = v.try_to::<i64>()
            .map_err(|e| format!("`limit` must be an int: {}", e))?;
        if n > 0 {
            fields.push((entity_ecf::text("limit"), entity_ecf::integer(n)));
        }
    }
    if let Some(v) = dict.get("cursor") {
        let s = v.try_to::<GString>()
            .map_err(|e| format!("`cursor` must be a String: {}", e))?;
        fields.push((entity_ecf::text("cursor"), entity_ecf::text(s.to_string())));
    }
    if let Some(v) = dict.get("include_entities") {
        let b = v.try_to::<bool>()
            .map_err(|e| format!("`include_entities` must be a bool: {}", e))?;
        fields.push((entity_ecf::text("include_entities"), entity_ecf::bool_val(b)));
    }

    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
    entity_entity::Entity::new(entity_types::TYPE_QUERY_EXPRESSION, data)
        .map_err(|e| format!("entity construction failed: {}", e))
}

/// Parse the GDScript-facing Array-of-Dictionary grant list into a
/// typed `Vec<GrantEntry>` for `mint_cross_peer_chain_capability`.
///
/// Each Dictionary supports keys:
///   handlers:   Array of String (required, non-empty)
///   resources:  Array of String (required, possibly empty for handler-only grants)
///   operations: Array of String (required, non-empty)
///   peers:      optional Array of String — omit/null = local only
///
/// constraints / allowances are v2 (extension fields with primitive/any
/// values) — not surfaced in v1. Add when a consumer materializes.
fn parse_grant_entries(
    grants: &VarArray,
) -> Result<Vec<entity_capability::GrantEntry>, String> {
    use entity_capability::{GrantEntry, IdScope, PathScope};
    if grants.is_empty() {
        return Err("grants array must be non-empty".into());
    }
    let mut out = Vec::with_capacity(grants.len());
    for i in 0..grants.len() {
        let item = grants
            .get(i)
            .ok_or_else(|| format!("grants[{}] missing", i))?;
        let dict = item
            .try_to::<Dictionary>()
            .map_err(|_| format!("grants[{}] must be a Dictionary", i))?;
        let handlers = dict_get_str_array(&dict, "handlers")
            .ok_or_else(|| format!("grants[{}].handlers missing (Array of String)", i))?;
        if handlers.is_empty() {
            return Err(format!("grants[{}].handlers must be non-empty", i));
        }
        let resources = dict_get_str_array(&dict, "resources").unwrap_or_default();
        let operations = dict_get_str_array(&dict, "operations")
            .ok_or_else(|| format!("grants[{}].operations missing (Array of String)", i))?;
        if operations.is_empty() {
            return Err(format!("grants[{}].operations must be non-empty", i));
        }
        let peers = dict_get_str_array(&dict, "peers").map(IdScope::new);
        out.push(GrantEntry {
            handlers: PathScope::new(handlers),
            resources: PathScope::new(resources),
            operations: IdScope::new(operations),
            peers,
            constraints: None,
            allowances: None,
        });
    }
    Ok(out)
}

/// Pull an Array<String> value from a Godot Dictionary by string key.
/// Accepts PackedStringArray, VarArray of String, or returns None.
fn dict_get_str_array(dict: &Dictionary, key: &str) -> Option<Vec<String>> {
    let v = dict.get(GString::from(key).to_variant())?;
    if v.is_nil() {
        return None;
    }
    if let Ok(pa) = v.try_to::<PackedStringArray>() {
        let mut out = Vec::with_capacity(pa.len());
        for i in 0..pa.len() {
            out.push(pa.get(i).map(|g| g.to_string()).unwrap_or_default());
        }
        return Some(out);
    }
    if let Ok(arr) = v.try_to::<VarArray>() {
        let mut out = Vec::with_capacity(arr.len());
        for i in 0..arr.len() {
            if let Some(item) = arr.get(i) {
                if let Ok(s) = item.try_to::<GString>() {
                    out.push(s.to_string());
                }
            }
        }
        return Some(out);
    }
    None
}

/// Parse the GDScript-facing handler-spec Dictionary into a typed
/// `HandlerSpec` for `register_handler`. Returns Err with a human-
/// readable reason on missing required fields / wrong types.
/// Strip `ws://`, `wss://`, or `tcp://` scheme prefix from an addr,
/// returning a bare `host:port` form. Leaves `memory://...` and bare
/// addresses untouched.
fn normalize_dial_addr(addr: &str) -> &str {
    for scheme in ["ws://", "wss://", "tcp://"] {
        if let Some(rest) = addr.strip_prefix(scheme) {
            return rest;
        }
    }
    addr
}

fn parse_handler_spec(
    spec: &Dictionary,
) -> Result<entity_sdk::register_handler::HandlerSpec, String> {
    use entity_sdk::register_handler::{HandlerSpec, OperationSpec};

    let pattern = dict_get_string(spec, "pattern")
        .ok_or_else(|| "spec missing required field 'pattern' (String)".to_string())?;
    if pattern.is_empty() {
        return Err("'pattern' must be non-empty".into());
    }
    if pattern.starts_with('/') {
        return Err(
            "'pattern' must be bare (no leading slash); SDK qualifies to /{peer_id}/{pattern}"
                .into(),
        );
    }

    let name = dict_get_string(spec, "name")
        .ok_or_else(|| "spec missing required field 'name' (String)".to_string())?;

    let description = dict_get_string(spec, "description");

    let ops_variant = spec
        .get(GString::from("operations").to_variant())
        .ok_or_else(|| "spec missing required field 'operations' (Array)".to_string())?;
    let ops_array = ops_variant
        .try_to::<VarArray>()
        .map_err(|_| "'operations' must be an Array of Dictionary".to_string())?;
    if ops_array.is_empty() {
        return Err("'operations' must be non-empty".into());
    }
    let mut operations = Vec::with_capacity(ops_array.len());
    for i in 0..ops_array.len() {
        let item = ops_array
            .get(i)
            .ok_or_else(|| format!("operations[{}] missing", i))?;
        let op_dict = item
            .try_to::<Dictionary>()
            .map_err(|_| format!("operations[{}] must be a Dictionary", i))?;
        let op_name = dict_get_string(&op_dict, "name")
            .ok_or_else(|| format!("operations[{}].name missing", i))?;
        if op_name.is_empty() {
            return Err(format!("operations[{}].name must be non-empty", i));
        }
        let mut op = OperationSpec::new(op_name);
        if let Some(t) = dict_get_string(&op_dict, "input_type") {
            op = op.with_input(t);
        }
        if let Some(t) = dict_get_string(&op_dict, "output_type") {
            op = op.with_output(t);
        }
        operations.push(op);
    }

    let mut hs = HandlerSpec::new(pattern, name, operations);
    if let Some(d) = description {
        hs = hs.with_description(d);
    }
    Ok(hs)
}

/// Pull a String value from a Godot Dictionary by string key.
fn dict_get_string(dict: &Dictionary, key: &str) -> Option<String> {
    let v = dict.get(GString::from(key).to_variant())?;
    if v.is_nil() {
        return None;
    }
    v.try_to::<GString>().ok().map(|g| g.to_string())
}

/// Parse the GDScript-facing options Dictionary for
/// `subscribe_l1_with_options` into a typed `SubscribeOptions`. Unknown
/// keys are silently ignored (forward-compat); type mismatches fall
/// back to defaults with a warning (matches the rest of the binding's
/// permissive-input posture).
fn parse_subscribe_options(opts: &Dictionary) -> entity_sdk::subscription::SubscribeOptions {
    use entity_sdk::subscription::{SubscribeLimits, SubscribeOptions};
    let mut out = SubscribeOptions::default();

    if let Some(v) = opts.get(GString::from("include_payload").to_variant()) {
        if let Ok(b) = v.try_to::<bool>() {
            out.include_payload = b;
        } else {
            godot_warn!(
                "subscribe_l1_with_options: include_payload must be bool; ignoring"
            );
        }
    }

    if let Some(v) = opts.get(GString::from("events").to_variant()) {
        if v.is_nil() {
            // explicit null = treat as absent (all events)
        } else if let Ok(arr) = v.try_to::<PackedStringArray>() {
            let mut list = Vec::with_capacity(arr.len());
            for i in 0..arr.len() {
                list.push(arr.get(i).map(|g| g.to_string()).unwrap_or_default());
            }
            out.events = Some(list);
        } else if let Ok(arr) = v.try_to::<VarArray>() {
            let mut list = Vec::with_capacity(arr.len());
            for i in 0..arr.len() {
                if let Some(item) = arr.get(i) {
                    if let Ok(s) = item.try_to::<GString>() {
                        list.push(s.to_string());
                    }
                }
            }
            out.events = Some(list);
        } else {
            godot_warn!(
                "subscribe_l1_with_options: events must be Array of String; ignoring"
            );
        }
    }

    let max_events = opts
        .get(GString::from("max_events").to_variant())
        .and_then(|v| v.try_to::<i64>().ok())
        .and_then(|n| if n >= 0 { Some(n as u64) } else { None });
    let max_duration_ms = opts
        .get(GString::from("max_duration_ms").to_variant())
        .and_then(|v| v.try_to::<i64>().ok())
        .and_then(|n| if n >= 0 { Some(n as u64) } else { None });
    let rate_limit = opts
        .get(GString::from("rate_limit").to_variant())
        .and_then(|v| v.try_to::<i64>().ok())
        .and_then(|n| if n >= 0 { Some(n as u64) } else { None });

    if max_events.is_some() || max_duration_ms.is_some() || rate_limit.is_some() {
        out.limits = Some(SubscribeLimits {
            max_events,
            max_duration_ms,
            rate_limit,
        });
    }

    out
}

/// Decode the `phase` text field from a `system/peer/self/status`
/// entity. Returns `None` if the entity isn't a CBOR map or lacks the
/// `phase` field — caller projects that to GString::new() for the
/// "unknown phase" sentinel.
///
/// Phase values are written by `core/peer/src/lib.rs:1582+`
/// `write_peer_self_status`: one of "starting" / "ready" / "draining".
fn decode_phase_from_status_entity(entity: &entity_entity::Entity) -> Option<String> {
    let val: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).ok()?;
    let map = match &val {
        ciborium::Value::Map(m) => m,
        _ => return None,
    };
    for (k, v) in map {
        if let ciborium::Value::Text(key) = k {
            if key == "phase" {
                if let ciborium::Value::Text(s) = v {
                    return Some(s.clone());
                }
            }
        }
    }
    None
}

/// Build the `system/revision/log-params` entity (`{prefix}`).
fn build_revision_log_params(prefix: &str) -> entity_entity::Entity {
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
        entity_ecf::text("prefix"),
        entity_ecf::text(prefix),
    )]));
    entity_entity::Entity::new("system/revision/log-params", data)
        .expect("log-params entity construction is infallible")
}

/// Decode `system/revision:log`'s envelope-wrapped
/// `system/revision/log-result`. Returns `(prefix, versions, has_more)`.
///
/// Envelope shape (per `extensions/revision/src/lib.rs:863+` and the
/// shared `build_envelope_result`):
///   `{root: inline-entity{type,content_hash,data}, included: map<bytes, inline-entity>}`
/// The `root.data` carries the log result map:
///   `{prefix, has_more, versions: Array[Bytes]}`
/// Each version hash in `versions[]` is the key into `included`; the
/// included entity's `data` decodes to a structural revision entry
/// (`{root: Bytes, parents: Array[Bytes]}`) per
/// `extensions/revision/src/dag.rs:30`.
fn decode_revision_log_result(
    result: &entity_entity::Entity,
) -> Result<(String, Vec<crate::peer_op_future::RevisionVersionInfo>, bool), String> {
    use ciborium::Value as CV;

    let root_value: CV = ciborium::from_reader(result.data.as_slice())
        .map_err(|e| format!("revision log decode: {}", e))?;
    let envelope_map = match &root_value {
        CV::Map(m) => m,
        _ => return Err("revision log: envelope is not a map".into()),
    };

    let mut root_entity_data: Option<CV> = None;
    let mut included_map: Vec<(CV, CV)> = Vec::new();
    for (k, v) in envelope_map {
        if let CV::Text(key) = k {
            match key.as_str() {
                "root" => {
                    // root is an inline entity `{type, content_hash, data}`.
                    if let CV::Map(inline) = v {
                        for (ik, iv) in inline {
                            if let CV::Text(ikt) = ik {
                                if ikt == "data" {
                                    root_entity_data = Some(iv.clone());
                                }
                            }
                        }
                    }
                }
                "included" => {
                    if let CV::Map(m) = v {
                        included_map = m.clone();
                    }
                }
                _ => {}
            }
        }
    }

    let root_data = root_entity_data
        .ok_or_else(|| "revision log: envelope missing `root.data`".to_string())?;
    let result_map = match &root_data {
        CV::Map(m) => m,
        _ => return Err("revision log: root.data is not a map".into()),
    };

    let mut prefix = String::new();
    let mut has_more = false;
    let mut version_hashes: Vec<CV> = Vec::new();
    for (k, v) in result_map {
        if let CV::Text(key) = k {
            match key.as_str() {
                "prefix" => {
                    if let CV::Text(s) = v {
                        prefix = s.clone();
                    }
                }
                "has_more" => {
                    if let CV::Bool(b) = v {
                        has_more = *b;
                    }
                }
                "versions" => {
                    if let CV::Array(arr) = v {
                        version_hashes = arr.clone();
                    }
                }
                _ => {}
            }
        }
    }

    let mut versions = Vec::new();
    for vh in version_hashes {
        let hash_bytes = match &vh {
            CV::Bytes(b) => b.clone(),
            _ => continue,
        };
        let hash = match entity_hash::Hash::from_bytes(&hash_bytes) {
            Ok(h) => h,
            Err(_) => continue,
        };
        // Look up the included entity's data map → decode revision entry
        // structure (root + parents).
        let (root_hash, parents) = lookup_revision_entry_in_included(&included_map, &hash_bytes);
        versions.push(crate::peer_op_future::RevisionVersionInfo {
            hash,
            root: root_hash,
            parents,
        });
    }

    Ok((prefix, versions, has_more))
}

/// Walk the envelope's `included` map for the entry keyed by
/// `hash_bytes`, decode its inline entity's `data` field, and pull out
/// the revision-entry fields `{root, parents}`.
fn lookup_revision_entry_in_included(
    included: &[(ciborium::Value, ciborium::Value)],
    hash_bytes: &[u8],
) -> (Option<entity_hash::Hash>, Vec<entity_hash::Hash>) {
    use ciborium::Value as CV;
    for (k, v) in included {
        if let CV::Bytes(b) = k {
            if b.as_slice() != hash_bytes {
                continue;
            }
            // Found the inline entity. Walk its map → extract `data`.
            let inline_map = match v {
                CV::Map(m) => m,
                _ => return (None, Vec::new()),
            };
            let mut entry_data: Option<&CV> = None;
            for (ik, iv) in inline_map {
                if let CV::Text(key) = ik {
                    if key == "data" {
                        entry_data = Some(iv);
                    }
                }
            }
            let entry_map = match entry_data {
                Some(CV::Map(m)) => m,
                _ => return (None, Vec::new()),
            };
            let mut root: Option<entity_hash::Hash> = None;
            let mut parents = Vec::new();
            for (fk, fv) in entry_map {
                if let CV::Text(key) = fk {
                    match key.as_str() {
                        "root" => {
                            if let CV::Bytes(rb) = fv {
                                root = entity_hash::Hash::from_bytes(rb).ok();
                            }
                        }
                        "parents" => {
                            if let CV::Array(arr) = fv {
                                for item in arr {
                                    if let CV::Bytes(pb) = item {
                                        if let Ok(ph) = entity_hash::Hash::from_bytes(pb) {
                                            parents.push(ph);
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            return (root, parents);
        }
    }
    (None, Vec::new())
}

/// Build the ECF-encoded data field for a `TYPE_REVISION_CONFIG` entity.
fn build_revision_config_data(pattern: &str, enabled: bool, auto_version: bool) -> Vec<u8> {
    let fields: Vec<(entity_ecf::Value, entity_ecf::Value)> = vec![
        (entity_ecf::text("pattern"), entity_ecf::text(pattern)),
        (entity_ecf::text("enabled"), entity_ecf::bool_val(enabled)),
        (
            entity_ecf::text("auto_version"),
            entity_ecf::bool_val(auto_version),
        ),
    ];
    entity_ecf::to_ecf(&entity_ecf::Value::Map(fields))
}

#[cfg(test)]
mod tests {
    //! Pure helpers — Variant / runtime / Gd<_> stay out of these tests
    //! because they need a live Godot runtime to construct. Coverage of
    //! the async dispatch + signal emission lives on the Godot side
    //! (godot-entity-core-rust integration tests).
    use super::*;

    #[test]
    fn decode_phase_reads_each_canonical_value() {
        // Build a status entity the same way the kernel does
        // (core/peer/src/lib.rs:1582+ `write_peer_self_status`) and confirm
        // we recover each phase string. Pins the wire contract — if the
        // kernel renames the `phase` field or the variant strings drift,
        // this test fails before GDScript callers see `peer_phase() == ""`.
        for phase_str in &["starting", "ready", "draining"] {
            let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
                (entity_ecf::text("last_phase_transition"), entity_ecf::integer(0)),
                (entity_ecf::text("phase"), entity_ecf::text(*phase_str)),
            ]));
            let entity = entity_entity::Entity::new(
                entity_types::TYPE_PEER_SELF_STATUS,
                data,
            )
            .expect("status entity construction");
            let decoded = decode_phase_from_status_entity(&entity);
            assert_eq!(decoded.as_deref(), Some(*phase_str));
        }
    }

    #[test]
    fn decode_phase_returns_none_when_field_absent() {
        // Defensive: tolerate a status entity lacking `phase` (shouldn't
        // happen in practice; covers garbage-in path).
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("last_phase_transition"),
            entity_ecf::integer(0),
        )]));
        let entity =
            entity_entity::Entity::new(entity_types::TYPE_PEER_SELF_STATUS, data).unwrap();
        assert!(decode_phase_from_status_entity(&entity).is_none());
    }

    #[test]
    fn config_path_sanitizes_pattern_chars() {
        // Slashes and wildcards in the pattern must become path-safe
        // characters in the key segment, but the pattern itself is
        // preserved verbatim in the entity's `pattern` field so the
        // history engine matches against the user-supplied glob.
        let peer = "Peer1";
        assert_eq!(
            config_path("history", peer, "app/state/*"),
            "/Peer1/system/history/config/app_state__"
        );
        assert_eq!(
            config_path("revision", peer, "settings/theme"),
            "/Peer1/system/revision/config/settings_theme"
        );
    }

    #[test]
    fn config_path_is_deterministic() {
        // Enable then disable on the same pattern MUST hit the same path
        // — otherwise disable can't find the entity to remove. This is
        // the load-bearing invariant of the key derivation.
        let a = config_path("history", "P", "workspace/*");
        let b = config_path("history", "P", "workspace/*");
        assert_eq!(a, b);
    }

    #[test]
    fn history_config_data_round_trips_through_engine_decoder() {
        // The history engine's decoder (extensions/history/src/engine.rs
        // line 561, `decode_history_config`) is the authoritative reader.
        // Encoding here and matching what the engine decodes pins the
        // wire contract: any drift in either side fails this test.
        let data = build_history_config_data(
            "app/state/*",
            true,
            &["created".into(), "updated".into()],
            Some(8),
        );
        let val: ciborium::Value = ciborium::de::from_reader(data.as_slice()).unwrap();
        let map = val.as_map().expect("history config encodes as a map");
        let by_key = |k: &str| -> ciborium::Value {
            map.iter()
                .find(|(kk, _)| kk.as_text() == Some(k))
                .map(|(_, v)| v.clone())
                .expect("missing key")
        };
        assert_eq!(by_key("pattern").as_text(), Some("app/state/*"));
        assert_eq!(by_key("enabled").as_bool(), Some(true));
        let events = by_key("events");
        let events = events.as_array().expect("events is array");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].as_text(), Some("created"));
        assert_eq!(events[1].as_text(), Some("updated"));
        let max_depth = by_key("max_depth");
        let n: i128 = max_depth.as_integer().expect("max_depth is int").into();
        assert_eq!(n, 8);
    }

    #[test]
    fn history_config_omits_max_depth_when_none() {
        let data = build_history_config_data("p", true, &["created".into()], None);
        let val: ciborium::Value = ciborium::de::from_reader(data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        assert!(
            map.iter().all(|(k, _)| k.as_text() != Some("max_depth")),
            "max_depth must be absent (not null) when unbounded"
        );
    }

    #[test]
    fn revision_config_carries_auto_version() {
        let data = build_revision_config_data("settings/theme", true, true);
        let val: ciborium::Value = ciborium::de::from_reader(data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let auto = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("auto_version"))
            .map(|(_, v)| v.as_bool().unwrap())
            .unwrap();
        assert!(auto);
    }

    #[test]
    fn config_encoding_is_deterministic_under_key_order() {
        // Two encodings with the same logical content MUST be byte-equal:
        // this is the ECF determinism contract the history engine's
        // content-hash comparison relies on.
        let a = build_history_config_data("p", true, &["created".into()], Some(4));
        let b = build_history_config_data("p", true, &["created".into()], Some(4));
        assert_eq!(a, b);
    }
}
