#![cfg(target_arch = "wasm32")]
//! Library that hosts an entity-core peer SDK inside a dedicated Web Worker.
//!
//! # Usage
//!
//! Consumers ship a tiny wasm binary that depends on this crate and calls
//! [`run_worker`] with the set of handler factories compiled into their
//! binary:
//!
//! ```ignore
//! // consumer's wasm binary main entry (wasm-bindgen):
//! #[wasm_bindgen(start)]
//! pub fn worker_main() {
//!     entity_wasm_worker_host::run_worker(my_app::handler_factories());
//! }
//! ```
//!
//! Init parameters (persisted keypairs, primary peer id, handler selection)
//! arrive over the wire via `Request::Init`, not as `run_worker` args.
//! The worker boots, awaits the first postMessage, applies `InitParams`,
//! posts `Response::Ready`. Subsequent Requests are accepted only after
//! Ready.
//!
//! # What to pass for `handler_factories` (Phase 3.0 pilots)
//!
//! **Most consumers should pass `Vec::new()`.** The SDK's bootstrap
//! handlers — `system/tree`, `system/handler`, `system/protocol/connect`,
//! `system/type`, `system/capability` — are registered automatically by
//! `EntitySDK::builder().build()`. The factory list is only needed when
//! a consumer wants to expose a *custom* handler beyond the bootstrap set.
//!
//! For Phase 3.0 (Settings + Event Log pilots) and Phase 3.1, no custom
//! handlers are needed. Pass an empty Vec and an empty `init.handlers`;
//! validation passes trivially. See the internal design notes for the full
//! rationale and the planned Phase 1.x extension to the factory shape.
//!
//! # Phase 1 implementation status
//!
//! The dispatch loop, init handshake, and the most-used L1 arms
//! (`Get`, `Put`, `List`, `Has`, `Remove`) are fully implemented. The
//! remaining arms return `WireError { kind: Unknown, message: "<op> not yet
//! wired in Phase 1" }` — the wire works, but actual SDK dispatch is
//! TODO. The egui Phase 3 integration + Phase 1 checkpoint validation
//! surface which arms need to ship next.
//!
//! Subscriptions are sketched: a `Request::Subscribe` registers an L1
//! callback with the SDK that re-emits events as `Event::Change`. The
//! initial `Event::Snapshot` derivation (list+fetch under the prefix) is
//! TODO — Phase 1 ships an empty initial snapshot, which exercises the
//! proxy's `snapshot_received` gate without requiring a fully populated
//! prefix.
//!
//! # Library, not binary
//!
//! Consumers do not fork this crate. They supply only the handler
//! factories their app needs; the dispatch logic stays here.

use entity_crypto::Keypair;
use entity_peer::{DispatchEvent, DispatchPhase, PeerConfig, WireEvent};
use entity_sdk::{ChangeType, EntitySDK, PeerContextBuilder, PeerMetadata, TreeChangeEvent};
use entity_wasm_worker_protocol::{
    conversions::ConversionError, BindingKind, CasFailure, CasFailureKind, ConnectPeerOk,
    CreatePeerOk, Event, InitParams, InspectFact, PROTOCOL_VERSION, Request, RequestId, Response,
    SubId, WireCaps, WireDirection, WireEntity, WireError, WireErrorKind, WireExecuteOptions,
    WireHandlerInfo, WireHandlerResult, WireHash, WireListingEntry, WirePeerMetadata,
    WireQueryResults, WireTypeInfo,
};
use js_sys::Uint8Array;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{DedicatedWorkerGlobalScope, MessageEvent, MessagePort};

// ---------------------------------------------------------------------------
// Public API surface
// ---------------------------------------------------------------------------

/// Handler factory the consumer supplies at worker init. Phase 1 ships
/// only the pattern name — actual handler-trait-object wiring is left to
/// each consumer because the handler types live in their crate. The
/// `Init` flow matches `init.handlers` names against the factory list;
/// missing factories fail Init with an actionable error.
///
/// Phase 1.x extends this with `build: Box<dyn Fn(&HandlerSpec) -> Box<dyn Handler>>`
/// once we've validated the design against a real consumer.
pub struct HandlerFactory {
    pub pattern: String,
}

/// Library entry point. Consumer's wasm binary calls this from its
/// `#[wasm_bindgen(start)]` function.
///
/// Returns once the `onmessage` handler is installed. The JS event loop
/// keeps the worker alive — Rust ownership of the closures lives in the
/// `WorkerState` we leak into the handler.
pub fn run_worker(factories: Vec<HandlerFactory>) {
    let factory_map: HashMap<String, HandlerFactory> = factories
        .into_iter()
        .map(|f| (f.pattern.clone(), f))
        .collect();

    let state = Rc::new(RefCell::new(WorkerState {
        sdk: None,
        factories: factory_map,
        subscriptions: HashMap::new(),
        pending_control_port: None,
        control_client: None,
        inspect_enabled: HashMap::new(),
    }));

    let global = js_sys::global()
        .dyn_into::<DedicatedWorkerGlobalScope>()
        .expect("run_worker must be called from a DedicatedWorkerGlobalScope context");

    install_onmessage(state, global);
}

// ---------------------------------------------------------------------------
// Worker state
// ---------------------------------------------------------------------------

struct WorkerState {
    /// `None` until `Request::Init` completes; `Some` thereafter.
    sdk: Option<EntitySDK>,
    /// Consumer-supplied factory map. Currently only the pattern names are
    /// used (matched against `InitParams::handlers` for validation);
    /// actual handler-trait wiring is Phase 1.x.
    #[allow(dead_code)]
    factories: HashMap<String, HandlerFactory>,
    /// Live L1 subscriptions keyed by our protocol's `SubId`. Dropping the
    /// `L1SubscriptionHandle` cancels the SDK-side subscription; we drop
    /// it when `Request::Unsubscribe` arrives.
    subscriptions: HashMap<SubId, entity_sdk::subscription::L1SubscriptionHandle>,
    /// Control port for cross-Worker MessagePort transport, captured
    /// from the FIRST inbound message's `event.ports()` (delivered
    /// alongside the Init request by `WebTransport::with_control_port`).
    /// `handle_init` reads-and-clears this to wire the
    /// `MessagePortConnector` + `MessagePortListener` for the SDK.
    /// `None` means the Worker boots without cross-Worker transport
    /// (legacy path — WS-only connector).
    pending_control_port: Option<MessagePort>,
    /// `ControlPortClient` retained after Init, so `handle_create_peer`
    /// can bind a `MessagePortListener` and build a per-peer connector
    /// for dynamically-created peers. `None` when the Worker boots
    /// without a control port.
    control_client: Option<std::rc::Rc<entity_peer::transport::ControlPortClient>>,
    /// Per-peer marshal-on-off flag for the inspect-hook plumbing
    /// (PROTOCOL v9, inspect-worker-arm design §4.3).
    /// Default-off — installed alongside each peer's substrate hooks so
    /// the closure can early-return when no sink is attached on the
    /// main-thread side. Consumers flip it via `Request::SetInspectEnabled`.
    /// Keys are local peer ids (primary + additional + dynamic).
    inspect_enabled: HashMap<String, Arc<AtomicBool>>,
}

// ---------------------------------------------------------------------------
// onmessage plumbing
// ---------------------------------------------------------------------------

fn install_onmessage(state: Rc<RefCell<WorkerState>>, global: DedicatedWorkerGlobalScope) {
    let onmessage = {
        let state = state.clone();
        let global = global.clone();
        Closure::wrap(Box::new(move |evt: MessageEvent| {
            // Cross-Worker transport: the main-thread proxy may transfer
            // a control port alongside the Init message. Capture it
            // before dispatching the request body so handle_init can
            // pick it up.
            if let Ok(port) = evt.ports().get(0).dyn_into::<MessagePort>() {
                state.borrow_mut().pending_control_port = Some(port);
            }

            let bytes = match evt.data().dyn_into::<Uint8Array>() {
                Ok(arr) => arr.to_vec(),
                Err(_) => {
                    web_sys::console::warn_1(&JsValue::from_str(
                        "wasm-worker-host: ignoring non-Uint8Array message from main thread",
                    ));
                    return;
                }
            };
            let request: Request = match ciborium::from_reader(bytes.as_slice()) {
                Ok(r) => r,
                Err(e) => {
                    web_sys::console::error_1(&JsValue::from_str(&format!(
                        "wasm-worker-host: failed to decode Request: {e}"
                    )));
                    return;
                }
            };
            let state = state.clone();
            let global = global.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let response = dispatch(state, request, &global).await;
                send_response(&global, &response);
            });
        }) as Box<dyn FnMut(MessageEvent)>)
    };
    global.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
    // The closure must outlive the function — `forget` leaks it to JS-land.
    // The worker tab dies when the closure dies anyway (no other Rust
    // ownership keeps it alive).
    onmessage.forget();
}

fn send_response(global: &DedicatedWorkerGlobalScope, response: &Response) {
    let mut buf = Vec::new();
    if let Err(e) = ciborium::into_writer(response, &mut buf) {
        web_sys::console::error_1(&JsValue::from_str(&format!(
            "wasm-worker-host: CBOR encode of Response failed: {e}"
        )));
        return;
    }
    let arr = Uint8Array::new_with_length(buf.len() as u32);
    arr.copy_from(&buf);
    if let Err(e) = global.post_message(&arr) {
        web_sys::console::error_1(&JsValue::from_str(&format!(
            "wasm-worker-host: postMessage(response) failed: {e:?}"
        )));
    }
}

fn send_event(global: &DedicatedWorkerGlobalScope, event: &Event) {
    let mut buf = Vec::new();
    if let Err(e) = ciborium::into_writer(event, &mut buf) {
        web_sys::console::error_1(&JsValue::from_str(&format!(
            "wasm-worker-host: CBOR encode of Event failed: {e}"
        )));
        return;
    }
    let arr = Uint8Array::new_with_length(buf.len() as u32);
    arr.copy_from(&buf);
    if let Err(e) = global.post_message(&arr) {
        web_sys::console::error_1(&JsValue::from_str(&format!(
            "wasm-worker-host: postMessage(event) failed: {e:?}"
        )));
    }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

async fn dispatch(
    state: Rc<RefCell<WorkerState>>,
    request: Request,
    global: &DedicatedWorkerGlobalScope,
) -> Response {
    match request {
        Request::Init { request_id, params } => handle_init(state, request_id, params).await,
        Request::Get { request_id, peer_id, path } => handle_get(state, request_id, peer_id, path).await,
        Request::Put { request_id, peer_id, path, entity } => {
            handle_put(state, request_id, peer_id, path, entity).await
        }
        Request::List { request_id, peer_id, prefix } => handle_list(state, request_id, peer_id, prefix).await,
        Request::Has { request_id, peer_id, path } => handle_has(state, request_id, peer_id, path).await,
        Request::Remove { request_id, peer_id, path } => handle_remove(state, request_id, peer_id, path).await,
        Request::Subscribe { request_id, sub_id, peer_id, prefix } => {
            handle_subscribe(state, request_id, sub_id, peer_id, prefix, global.clone()).await
        }
        Request::Unsubscribe { request_id, sub_id } => handle_unsubscribe(state, request_id, sub_id),

        // Phase 1.x — the wire format is in place; SDK dispatch is TODO.
        // Returning a typed error keeps the proxy's `proxy_method!` happy
        // (it expects Response::<Op> { result: Result<_, WireError> }).
        Request::PutCas { request_id, .. } => Response::PutCas {
            request_id,
            result: Err(not_yet_wired("put_cas")),
        },
        Request::Execute { request_id, peer_id, handler, operation, params, opts } => {
            handle_execute(state, request_id, peer_id, handler, operation, params, opts).await
        }
        Request::Query { request_id, peer_id, expression } => {
            handle_query(state, request_id, peer_id, expression).await
        }
        Request::Count { request_id, peer_id, expression } => {
            handle_count(state, request_id, peer_id, expression).await
        }
        Request::EntityCount { request_id, peer_id } => {
            handle_entity_count(state, request_id, peer_id)
        }
        Request::PathCount { request_id, peer_id } => {
            handle_path_count(state, request_id, peer_id)
        }
        Request::InboxList { request_id, .. } => Response::InboxList {
            request_id,
            result: Err(not_yet_wired("inbox_list")),
        },
        Request::InboxGet { request_id, .. } => Response::InboxGet {
            request_id,
            result: Err(not_yet_wired("inbox_get")),
        },
        Request::DiscoverHandlers { request_id, peer_id } => {
            handle_discover_handlers(state, request_id, peer_id)
        }
        Request::DiscoverTypes { request_id, peer_id } => {
            handle_discover_types(state, request_id, peer_id)
        }
        Request::RegisterBackendPeer { request_id, peer_id, label, listen_addresses } => {
            handle_register_backend_peer(state, request_id, peer_id, label, listen_addresses)
        }
        Request::CreatePeer { request_id, label } => {
            handle_create_peer(state, request_id, label)
        }
        Request::DeletePeer { request_id, peer_id } => {
            handle_delete_peer(state, request_id, peer_id)
        }
        Request::SetMetadata { request_id, peer_id, metadata } => {
            handle_set_metadata(state, request_id, peer_id, metadata)
        }
        Request::ConnectPeer { request_id, peer_id, address } => {
            handle_connect_peer(state, request_id, peer_id, address).await
        }
        Request::SetInspectEnabled { request_id, peer_id, enabled } => {
            handle_set_inspect_enabled(state, request_id, peer_id, enabled)
        }
    }
}

fn not_yet_wired(op: &str) -> WireError {
    WireError {
        kind: WireErrorKind::Unknown,
        message: format!(
            "wasm-worker-host: '{op}' not yet wired in Phase 1. Implement in dispatch(). See \
             bindings/wasm-worker-host/src/lib.rs."
        ),
        detail: None,
    }
}

// ---------------------------------------------------------------------------
// Inspect-hook marshal layer (PROTOCOL v9)
//
// The closures below convert in-process substrate hook
// events (DispatchEvent / WireEvent / TreeChangeEvent) into the
// `InspectFact` wire shape, gate on the per-peer enabled flag, and
// post `Event::Inspect { peer_id, fact }` back to main.
//
// Why captured-`global` works on wasm32 despite the Send + Sync bound on
// hook fns: wasm-bindgen flags JsValue (and the web_sys wrappers
// erected on top of it) as Send + Sync on wasm32-unknown-unknown — the
// target has no real threads, so the bound is vacuously satisfied.
// Same trick `handle_subscribe` already uses for its `Event::Change`
// callback.
// ---------------------------------------------------------------------------

fn marshal_dispatch(ev: &DispatchEvent) -> InspectFact {
    let status = match &ev.phase {
        DispatchPhase::Entry => 0,
        DispatchPhase::Exit { status, .. } => *status,
    };
    InspectFact::Dispatch {
        request_id: ev.request_id.clone(),
        handler_uri: ev.target_uri.clone(),
        operation: ev.operation.clone(),
        status,
        // Substrate doesn't track entry→exit elapsed without state, and
        // the chain_id isn't surfaced on DispatchEvent. v9 ships None
        // for both; marshal layer absorbs any field churn here.
        elapsed_micros: None,
        chain_id: None,
    }
}

fn marshal_wire(ev: &WireEvent) -> InspectFact {
    let direction = match ev.direction {
        entity_peer::WireDirection::Recv => WireDirection::Inbound,
        entity_peer::WireDirection::Send => WireDirection::Outbound,
    };
    let frame_kind = match direction {
        // V7.9 post-handshake frames are EXECUTE / EXECUTE_RESPONSE only.
        WireDirection::Inbound => "execute".to_string(),
        WireDirection::Outbound => "execute_response".to_string(),
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

fn marshal_binding(ev: &TreeChangeEvent) -> InspectFact {
    let kind = match ev.change_type {
        ChangeType::Created | ChangeType::Modified => BindingKind::Put,
        ChangeType::Deleted => BindingKind::Remove,
    };
    InspectFact::Binding {
        kind,
        path: ev.path.clone(),
        // entity_type would require a content-store lookup; intentionally
        // skipped per design §4.3 wire-chatter discipline.
        entity_type: None,
        content_hash: ev.new_hash.as_ref().map(|h| h.to_hex()),
        is_new: matches!(ev.change_type, ChangeType::Created),
    }
}

/// Install the three default-off inspect hooks on a PeerContextBuilder.
/// The closures capture `peer_id`, the enabled flag, and the worker's
/// global handle; they early-return when disabled to keep idle peers
/// zero-cost.
///
/// Returns the builder for chaining. The caller is responsible for
/// stashing `enabled` in `WorkerState::inspect_enabled` keyed by the
/// peer_id so `handle_set_inspect_enabled` can toggle it later.
fn install_inspect_hooks_on_builder(
    builder: PeerContextBuilder,
    peer_id: String,
    enabled: Arc<AtomicBool>,
    global: web_sys::DedicatedWorkerGlobalScope,
) -> PeerContextBuilder {
    let dispatch_pid = peer_id.clone();
    let dispatch_flag = enabled.clone();
    let dispatch_global = global.clone();
    let wire_pid = peer_id.clone();
    let wire_flag = enabled.clone();
    let wire_global = global.clone();
    let binding_pid = peer_id;
    let binding_flag = enabled;
    let binding_global = global;

    builder
        .with_dispatch_hook("worker/inspect-default", move |ev| {
            if !dispatch_flag.load(Ordering::Relaxed) {
                return;
            }
            send_event(
                &dispatch_global,
                &Event::Inspect {
                    peer_id: dispatch_pid.clone(),
                    fact: marshal_dispatch(ev),
                },
            );
        })
        .with_wire_hook("worker/inspect-default", move |ev| {
            if !wire_flag.load(Ordering::Relaxed) {
                return;
            }
            send_event(
                &wire_global,
                &Event::Inspect {
                    peer_id: wire_pid.clone(),
                    fact: marshal_wire(ev),
                },
            );
        })
        .with_binding_hook("worker/inspect-default", move |ev| {
            if !binding_flag.load(Ordering::Relaxed) {
                return;
            }
            send_event(
                &binding_global,
                &Event::Inspect {
                    peer_id: binding_pid.clone(),
                    fact: marshal_binding(ev),
                },
            );
        })
}

// ---------------------------------------------------------------------------
// Cross-Worker connector + listener binding (shared by handle_init + handle_create_peer)
// ---------------------------------------------------------------------------

/// Build the outbound `Connector` for a peer hosted in this Worker.
/// Each peer gets its own connector so its `MessagePortConnector`
/// can carry the source peer-id on `OpenChannel` (lets the broker
/// install one handler per port instead of per peer — see
/// `wasm-worker-proxy/src/broker.rs` lifecycle notes).
///
/// - If a control client is present: `MultiConnector` with
///   `xworker://` (per-peer `MessagePortConnector`) +
///   `ws://`/`wss://` (shared `BrowserWebSocketConnector`).
/// - Otherwise: plain `BrowserWebSocketConnector` (legacy path).
fn build_per_peer_connector(
    control_client: Option<&std::rc::Rc<entity_peer::transport::ControlPortClient>>,
    source_peer_id: &str,
) -> Arc<dyn entity_peer::transport::Connector> {
    match control_client {
        Some(client) => {
            let xworker: Arc<dyn entity_peer::transport::Connector> =
                Arc::new(entity_peer::transport::MessagePortConnector::new(
                    client.clone(),
                    source_peer_id,
                ));
            let ws: Arc<dyn entity_peer::transport::Connector> =
                Arc::new(entity_peer::transport::BrowserWebSocketConnector);
            let multi = entity_peer::transport::MultiConnector::new()
                .with("xworker", xworker)
                .with("ws", ws.clone())
                .with("wss", ws);
            Arc::new(multi)
        }
        None => Arc::new(entity_peer::transport::BrowserWebSocketConnector),
    }
}

/// Bind a `MessagePortListener` for `peer_id` against the given
/// control client, start the peer's engines, and spawn its accept
/// loop. No-op if the peer is missing from the SDK. Engines start is
/// idempotent.
fn bind_xworker_listener(
    sdk: &EntitySDK,
    peer_id: &str,
    control: std::rc::Rc<entity_peer::transport::ControlPortClient>,
) {
    let shared = match sdk.peer(peer_id).map(|ctx| ctx.peer_shared()) {
        Some(s) => s,
        None => {
            web_sys::console::warn_1(&JsValue::from_str(&format!(
                "wasm-worker-host: bind_xworker_listener: no peer {} in SDK",
                peer_id
            )));
            return;
        }
    };
    if let Some(ctx) = sdk.peer(peer_id) {
        ctx.peer().start_engines(&shared);
    }
    let listener = entity_peer::transport::MessagePortListener::bind(peer_id.to_string(), control);
    let pid_for_log = peer_id.to_string();
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = entity_peer::server::run(listener, shared).await {
            web_sys::console::error_1(&JsValue::from_str(&format!(
                "wasm-worker-host: xworker accept loop for {} exited: {e}",
                pid_for_log
            )));
        }
    });
}

// ---------------------------------------------------------------------------
// handle_init
// ---------------------------------------------------------------------------

async fn handle_init(
    state: Rc<RefCell<WorkerState>>,
    request_id: RequestId,
    params: InitParams,
) -> Response {
    // Inspect-hook plumbing (PROTOCOL v9): every peer this Worker hosts
    // gets a default-off enabled flag stashed in state under its peer id;
    // the substrate hooks installed below capture the flag and the
    // worker's global handle so they can post `Event::Inspect` once
    // marshalling is flipped on via `Request::SetInspectEnabled`.
    let global_for_hooks = match js_sys::global().dyn_into::<web_sys::DedicatedWorkerGlobalScope>() {
        Ok(g) => g,
        Err(_) => {
            return Response::Init {
                request_id,
                result: Some(WireError {
                    kind: WireErrorKind::Unknown,
                    message: "handle_init called outside DedicatedWorkerGlobalScope".into(),
                    detail: None,
                }),
            };
        }
    };
    // Reject double-init.
    if state.borrow().sdk.is_some() {
        return Response::Init {
            request_id,
            result: Some(WireError {
                kind: WireErrorKind::InvalidParams,
                message: "Init can only be called once; SDK already constructed".into(),
                detail: None,
            }),
        };
    }

    // Validate keypair seed length on primary peer.
    let primary_seed: [u8; 32] = match params.primary_peer.keypair_seed.clone().try_into() {
        Ok(s) => s,
        Err(_) => {
            return Response::Init {
                request_id,
                result: Some(WireError {
                    kind: WireErrorKind::InvalidParams,
                    message: "primary_peer.keypair_seed must be 32 bytes".into(),
                    detail: None,
                }),
            };
        }
    };
    let primary_keypair = Keypair::from_seed(primary_seed);
    // Derive the primary's peer-id pre-build so we can wire its
    // per-peer connector (which needs the source peer-id baked in for
    // OpenChannel.from_peer).
    let primary_pid = primary_keypair.peer_id().to_string();

    // Cross-Worker control plane:
    // - If the main thread transferred a control port alongside this
    //   Init message, build a shared `ControlPortClient` that backs a
    //   PER-PEER `MessagePortConnector` for each local peer. Each peer
    //   also binds a `MessagePortListener` for inbound demux.
    // - Otherwise the Worker boots WS-only (legacy path).
    let control_port = state.borrow_mut().pending_control_port.take();
    let control_client: Option<std::rc::Rc<entity_peer::transport::ControlPortClient>> =
        control_port.map(entity_peer::transport::ControlPortClient::new);

    let primary_connector = build_per_peer_connector(control_client.as_ref(), &primary_pid);

    // Build the SDK with the primary peer's keypair. Apply `.opfs(root)` if
    // the consumer requested durable storage; build_async() awaits OPFS
    // handle acquisition when applicable and is a sync passthrough when
    // not — safe to call unconditionally on wasm32.
    //
    // The connector MUST be wired here — Request::ConnectPeer dispatches
    // through the primary peer's PeerShared.connector, which is None by
    // default. Additional peers get it via `create_peer` below; the
    // primary peer used to silently default to None, surfacing as
    // "no connector configured" from `Peer::connect_to` (the bug fixed
    // here).
    let primary_inspect_enabled = Arc::new(AtomicBool::new(false));
    let primary_inspect_enabled_for_hooks = primary_inspect_enabled.clone();
    let primary_pid_for_hooks = primary_pid.clone();
    let global_for_primary_hooks = global_for_hooks.clone();

    let mut builder = EntitySDK::builder()
        .keypair(primary_keypair)
        .config(PeerConfig {
            debug_open_grants: true,
            ..PeerConfig::default()
        })
        .connector(primary_connector)
        .with_dispatch_hook("worker/inspect-default", move |ev| {
            if !primary_inspect_enabled_for_hooks.load(Ordering::Relaxed) {
                return;
            }
            send_event(
                &global_for_primary_hooks,
                &Event::Inspect {
                    peer_id: primary_pid_for_hooks.clone(),
                    fact: marshal_dispatch(ev),
                },
            );
        });
    {
        let flag = primary_inspect_enabled.clone();
        let pid = primary_pid.clone();
        let global = global_for_hooks.clone();
        builder = builder.with_wire_hook("worker/inspect-default", move |ev| {
            if !flag.load(Ordering::Relaxed) {
                return;
            }
            send_event(
                &global,
                &Event::Inspect {
                    peer_id: pid.clone(),
                    fact: marshal_wire(ev),
                },
            );
        });
    }
    {
        let flag = primary_inspect_enabled.clone();
        let pid = primary_pid.clone();
        let global = global_for_hooks.clone();
        builder = builder.with_binding_hook("worker/inspect-default", move |ev| {
            if !flag.load(Ordering::Relaxed) {
                return;
            }
            send_event(
                &global,
                &Event::Inspect {
                    peer_id: pid.clone(),
                    fact: marshal_binding(ev),
                },
            );
        });
    }
    if let Some(root) = params.opfs_root.as_deref() {
        builder = builder.opfs(root);
    }
    let mut sdk = match builder.build_async().await {
        Ok(sdk) => sdk,
        Err(e) => {
            return Response::Init {
                request_id,
                result: Some(WireError {
                    kind: WireErrorKind::Unknown,
                    message: format!("SDK build failed: {e}"),
                    detail: None,
                }),
            };
        }
    };

    // Sanity check that the derived primary_pid matches what the SDK
    // ended up using — if they ever diverge the per-peer connector's
    // source-id is wrong. Should be impossible (PeerId derivation is
    // deterministic from the keypair) but cheap insurance.
    debug_assert_eq!(primary_pid, sdk.default_peer_id());

    // Set primary peer metadata.
    sdk.set_metadata(
        &primary_pid,
        PeerMetadata {
            label: params.primary_peer.label.clone(),
            persisted: true,
            ..PeerMetadata::default()
        },
    );

    // Track the primary peer's inspect flag so SetInspectEnabled can
    // toggle it later. (Stashed in state after additional peers are
    // built — a single borrow_mut covers both.)
    let mut new_inspect_flags: HashMap<String, Arc<AtomicBool>> = HashMap::new();
    new_inspect_flags.insert(primary_pid.clone(), primary_inspect_enabled);

    // Add additional peers — each with its own per-peer connector so
    // the `MessagePortConnector` carries that peer's source id on
    // `OpenChannel.from_peer`. We build via PeerContextBuilder so we
    // can install the per-peer inspect hooks before `insert_peer`
    // takes ownership (per the SDK doc on insert_peer's intended use
    // case — multi-peer hosts wanting builder customization).
    let mut additional_peer_ids: Vec<String> = Vec::new();
    for pp in params.additional_peers {
        let seed: [u8; 32] = match pp.keypair_seed.try_into() {
            Ok(s) => s,
            Err(_) => {
                return Response::Init {
                    request_id,
                    result: Some(WireError {
                        kind: WireErrorKind::InvalidParams,
                        message: format!(
                            "additional peer '{}' keypair_seed must be 32 bytes",
                            pp.peer_id
                        ),
                        detail: None,
                    }),
                };
            }
        };
        let kp = Keypair::from_seed(seed);
        let pp_pid = kp.peer_id().to_string();
        let pp_connector = build_per_peer_connector(control_client.as_ref(), &pp_pid);
        let pp_flag = Arc::new(AtomicBool::new(false));
        let pp_builder = PeerContextBuilder::new()
            .keypair(kp)
            .config(PeerConfig {
                debug_open_grants: true,
                ..PeerConfig::default()
            })
            .connector(pp_connector);
        let pp_builder = install_inspect_hooks_on_builder(
            pp_builder,
            pp_pid.clone(),
            pp_flag.clone(),
            global_for_hooks.clone(),
        );
        let ctx = match pp_builder.build() {
            Ok(c) => c,
            Err(e) => {
                return Response::Init {
                    request_id,
                    result: Some(WireError {
                        kind: WireErrorKind::Unknown,
                        message: format!("additional peer '{}' build failed: {e}", pp.peer_id),
                        detail: None,
                    }),
                };
            }
        };
        let metadata = PeerMetadata {
            label: pp.label,
            persisted: true,
            ..PeerMetadata::default()
        };
        match sdk.insert_peer_with_metadata(ctx, metadata) {
            Ok(pid) => {
                debug_assert_eq!(pid, pp_pid);
                new_inspect_flags.insert(pid.clone(), pp_flag);
                additional_peer_ids.push(pid);
            }
            Err(e) => {
                return Response::Init {
                    request_id,
                    result: Some(WireError {
                        kind: WireErrorKind::Unknown,
                        message: format!("additional peer '{}' insert failed: {e}", pp.peer_id),
                        detail: None,
                    }),
                };
            }
        }
    }

    // Cross-Worker transport: if a control port was wired above, bind
    // a `MessagePortListener` for EACH peer hosted in this Worker
    // (primary + additional). The shared `ControlPortClient` demuxes
    // incoming channels by `to_peer` to the matching listener, so
    // every peer is independently reachable via `xworker://<peer-id>`.
    //
    // Engines are started per peer before the accept loop spawns;
    // `start_engines` is idempotent. Connection-handler tasks live
    // for the lifetime of the Worker (no abort handle on
    // `spawn_local` — Worker termination owns task lifecycle).
    if let Some(control) = control_client.as_ref() {
        let mut pids_to_bind: Vec<String> = Vec::with_capacity(1 + additional_peer_ids.len());
        pids_to_bind.push(primary_pid.clone());
        pids_to_bind.extend(additional_peer_ids.iter().cloned());
        for pid in pids_to_bind {
            bind_xworker_listener(&sdk, &pid, control.clone());
        }
    }

    // Stash the control client on state so `handle_create_peer` can
    // build a per-peer connector + xworker listener for dynamically-
    // created peers. Also seed the per-peer inspect flags (primary +
    // additionals) so `handle_set_inspect_enabled` can toggle them.
    {
        let mut st = state.borrow_mut();
        st.control_client = control_client.clone();
        st.inspect_enabled.extend(new_inspect_flags);
    }

    // Handler registration — Phase 1.x.
    //
    // The protocol carries `params.handlers: Vec<HandlerSpec>` listing
    // patterns the consumer wants registered. The factory map (passed to
    // run_worker) has the actual handler-trait implementations. Phase 1
    // ships the validation that requested patterns exist in factories,
    // but does NOT actually register handlers — that needs a
    // factory-to-Handler trait-object wiring we haven't designed yet
    // (the consumer's handler types live in their crate; we'd need either
    // a generic over the handler types, or a trait object the factory
    // returns). Phase 1.x: extend HandlerFactory with
    // `build: Box<dyn Fn(&HandlerSpec) -> Box<dyn Handler>>` and wire
    // here.
    let st_borrow = state.borrow();
    for requested in &params.handlers {
        if !st_borrow.factories.contains_key(&requested.pattern) {
            drop(st_borrow);
            return Response::Init {
                request_id,
                result: Some(WireError {
                    kind: WireErrorKind::InvalidParams,
                    message: format!(
                        "requested handler '{}' has no factory in this worker binary",
                        requested.pattern
                    ),
                    detail: None,
                }),
            };
        }
    }
    drop(st_borrow);

    // Commit the SDK to state.
    state.borrow_mut().sdk = Some(sdk);

    // Post Ready. Per the protocol-version handshake (R1), the proxy
    // verifies PROTOCOL_VERSION matches; we always report our own.
    // `actual_capabilities` reports which optional kernel features
    // actually came up — reaching this branch means build_async()
    // succeeded, so if `opfs_root` was requested it is wired (failure
    // would have returned Response::Init with an error and never
    // reached here). See PROTOCOL_VERSION v8 docstring.
    Response::Ready {
        request_id,
        protocol_version: PROTOCOL_VERSION,
        sdk_version: env!("CARGO_PKG_VERSION").to_string(),
        actual_capabilities: Some(WireCaps {
            opfs_active: params.opfs_root.is_some(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Per-method handlers
// ---------------------------------------------------------------------------
//
// Each handler:
//   1. Looks up the peer_context by peer_id (returns NotFound error if missing).
//   2. Calls the corresponding SDK method.
//   3. Maps the SDK result to the protocol Response variant via the
//      `conversions` feature on `wasm-worker-protocol`.
//
// The `dispatch_borrow!` shape (manual today; macro-able if it shows up
// >5 times) carefully manages the RefCell borrow: extract the owning
// future while holding the borrow, drop the borrow, then await. This
// avoids RefMut-across-await issues.

async fn handle_get(
    state: Rc<RefCell<WorkerState>>,
    request_id: RequestId,
    peer_id: String,
    path: String,
) -> Response {
    let result = {
        let st = state.borrow();
        let sdk = match st.sdk.as_ref() {
            Some(s) => s,
            None => return Response::Get { request_id, result: Err(sdk_not_initialized()) },
        };
        let peer_ctx = match sdk.peer(&peer_id) {
            Some(p) => p,
            None => return Response::Get { request_id, result: Err(peer_not_found(&peer_id)) },
        };
        // SDK's get is `pub async fn get(&self, path: &str)` — the
        // returned future borrows the PeerContext. We must await before
        // dropping the borrow. spawn_local doesn't need Send, so this is
        // safe; we just can't yield to another borrow_mut while we await.
        peer_ctx.get(&path).await
    };
    match result {
        Ok(opt) => Response::Get {
            request_id,
            result: Ok(opt.map(WireEntity::from)),
        },
        Err(e) => Response::Get {
            request_id,
            result: Err(WireError::from(e)),
        },
    }
}

async fn handle_put(
    state: Rc<RefCell<WorkerState>>,
    request_id: RequestId,
    peer_id: String,
    path: String,
    entity: WireEntity,
) -> Response {
    // Convert wire entity → SDK entity at the boundary.
    let sdk_entity = match entity_entity::Entity::try_from(entity) {
        Ok(e) => e,
        Err(e) => return Response::Put { request_id, result: Err(conversion_error("put.entity", &e)) },
    };

    let result = {
        let st = state.borrow();
        let sdk = match st.sdk.as_ref() {
            Some(s) => s,
            None => return Response::Put { request_id, result: Err(sdk_not_initialized()) },
        };
        let peer_ctx = match sdk.peer(&peer_id) {
            Some(p) => p,
            None => return Response::Put { request_id, result: Err(peer_not_found(&peer_id)) },
        };
        // SDK's put returns `impl Future + 'static`. We can extract and drop the borrow.
        let fut = peer_ctx.put(path, sdk_entity);
        drop(st);
        fut.await
    };
    match result {
        Ok(hash) => Response::Put {
            request_id,
            result: Ok(WireHash::from(hash)),
        },
        Err(e) => Response::Put {
            request_id,
            result: Err(WireError::from(e)),
        },
    }
}

async fn handle_list(
    state: Rc<RefCell<WorkerState>>,
    request_id: RequestId,
    peer_id: String,
    prefix: String,
) -> Response {
    let result = {
        let st = state.borrow();
        let sdk = match st.sdk.as_ref() {
            Some(s) => s,
            None => return Response::List { request_id, result: Err(sdk_not_initialized()) },
        };
        let peer_ctx = match sdk.peer(&peer_id) {
            Some(p) => p,
            None => return Response::List { request_id, result: Err(peer_not_found(&peer_id)) },
        };
        peer_ctx.list(&prefix).await
    };
    match result {
        Ok(entries) => Response::List {
            request_id,
            // SDK's ListingEntry is `{ name, hash: Option<Hash> }`. Wire's
            // `WireListingEntry` requires a content_hash, so we filter out
            // hashless entries (directory-shaped listings). The proxy
            // wants the rooted path, so prepend the prefix.
            // Phase 1.x: extend WireListingEntry to mirror the SDK's
            // optional-hash shape exactly, with a PROTOCOL_VERSION bump.
            result: Ok(entries
                .into_iter()
                .filter_map(|e| {
                    e.hash.map(|h| {
                        let full = if prefix.ends_with('/') {
                            format!("{prefix}{}", e.name)
                        } else {
                            format!("{prefix}/{}", e.name)
                        };
                        WireListingEntry {
                            path: full,
                            content_hash: WireHash::from(h),
                        }
                    })
                })
                .collect()),
        },
        Err(e) => Response::List {
            request_id,
            result: Err(WireError::from(e)),
        },
    }
}

async fn handle_has(
    state: Rc<RefCell<WorkerState>>,
    request_id: RequestId,
    peer_id: String,
    path: String,
) -> Response {
    let result = {
        let st = state.borrow();
        let sdk = match st.sdk.as_ref() {
            Some(s) => s,
            None => return Response::Has { request_id, result: Err(sdk_not_initialized()) },
        };
        let peer_ctx = match sdk.peer(&peer_id) {
            Some(p) => p,
            None => return Response::Has { request_id, result: Err(peer_not_found(&peer_id)) },
        };
        peer_ctx.has(&path).await
    };
    match result {
        Ok(b) => Response::Has { request_id, result: Ok(b) },
        Err(e) => Response::Has { request_id, result: Err(WireError::from(e)) },
    }
}

async fn handle_remove(
    state: Rc<RefCell<WorkerState>>,
    request_id: RequestId,
    peer_id: String,
    path: String,
) -> Response {
    let result = {
        let st = state.borrow();
        let sdk = match st.sdk.as_ref() {
            Some(s) => s,
            None => return Response::Remove { request_id, result: Err(sdk_not_initialized()) },
        };
        let peer_ctx = match sdk.peer(&peer_id) {
            Some(p) => p,
            None => return Response::Remove { request_id, result: Err(peer_not_found(&peer_id)) },
        };
        peer_ctx.remove(&path).await
    };
    match result {
        Ok(b) => Response::Remove { request_id, result: Ok(b) },
        Err(e) => Response::Remove { request_id, result: Err(WireError::from(e)) },
    }
}

async fn handle_execute(
    state: Rc<RefCell<WorkerState>>,
    request_id: RequestId,
    peer_id: String,
    handler: String,
    operation: String,
    params: WireEntity,
    opts: WireExecuteOptions,
) -> Response {
    // The egui audit confirmed all
    // consumer call sites use only resource_targets/resource_exclude — the
    // other ExecuteOptions fields (capability, deliver_to, request_id,
    // bounds) are never touched. So the lossy v1 WireExecuteOptions → SDK
    // ExecuteOptions conversion is sufficient; no PROTOCOL_VERSION bump.
    let sdk_params = match entity_entity::Entity::try_from(params) {
        Ok(e) => e,
        Err(e) => {
            return Response::Execute {
                request_id,
                result: Err(conversion_error("execute.params", &e)),
            };
        }
    };
    let sdk_opts = entity_handler::ExecuteOptions::from(opts);

    let result = {
        let st = state.borrow();
        let sdk = match st.sdk.as_ref() {
            Some(s) => s,
            None => return Response::Execute { request_id, result: Err(sdk_not_initialized()) },
        };
        let peer_ctx = match sdk.peer(&peer_id) {
            Some(p) => p,
            None => return Response::Execute { request_id, result: Err(peer_not_found(&peer_id)) },
        };
        // PeerContext::execute returns an owning future; extract and drop the
        // borrow before awaiting (matches handle_put's pattern).
        let fut = peer_ctx.execute(handler, operation, sdk_params, sdk_opts);
        drop(st);
        fut.await
    };
    match result {
        Ok(hr) => Response::Execute {
            request_id,
            result: Ok(WireHandlerResult::from(hr)),
        },
        Err(e) => Response::Execute {
            request_id,
            result: Err(WireError::from(e)),
        },
    }
}

async fn handle_query(
    state: Rc<RefCell<WorkerState>>,
    request_id: RequestId,
    peer_id: String,
    expression: WireEntity,
) -> Response {
    let sdk_expression = match entity_entity::Entity::try_from(expression) {
        Ok(e) => e,
        Err(e) => {
            return Response::Query {
                request_id,
                result: Err(conversion_error("query.expression", &e)),
            };
        }
    };
    let result = {
        let st = state.borrow();
        let sdk = match st.sdk.as_ref() {
            Some(s) => s,
            None => return Response::Query { request_id, result: Err(sdk_not_initialized()) },
        };
        let peer_ctx = match sdk.peer(&peer_id) {
            Some(p) => p,
            None => return Response::Query { request_id, result: Err(peer_not_found(&peer_id)) },
        };
        let fut = peer_ctx.query(sdk_expression);
        drop(st);
        fut.await
    };
    match result {
        Ok(q) => Response::Query {
            request_id,
            result: Ok(WireQueryResults::from(q)),
        },
        Err(e) => Response::Query {
            request_id,
            result: Err(WireError::from(e)),
        },
    }
}

async fn handle_count(
    state: Rc<RefCell<WorkerState>>,
    request_id: RequestId,
    peer_id: String,
    expression: WireEntity,
) -> Response {
    let sdk_expression = match entity_entity::Entity::try_from(expression) {
        Ok(e) => e,
        Err(e) => {
            return Response::Count {
                request_id,
                result: Err(conversion_error("count.expression", &e)),
            };
        }
    };
    let result = {
        let st = state.borrow();
        let sdk = match st.sdk.as_ref() {
            Some(s) => s,
            None => return Response::Count { request_id, result: Err(sdk_not_initialized()) },
        };
        let peer_ctx = match sdk.peer(&peer_id) {
            Some(p) => p,
            None => return Response::Count { request_id, result: Err(peer_not_found(&peer_id)) },
        };
        let fut = peer_ctx.count(sdk_expression);
        drop(st);
        fut.await
    };
    match result {
        Ok(n) => Response::Count { request_id, result: Ok(n) },
        Err(e) => Response::Count { request_id, result: Err(WireError::from(e)) },
    }
}

fn handle_discover_handlers(
    state: Rc<RefCell<WorkerState>>,
    request_id: RequestId,
    peer_id: String,
) -> Response {
    let st = state.borrow();
    let sdk = match st.sdk.as_ref() {
        Some(s) => s,
        None => return Response::DiscoverHandlers { request_id, result: Err(sdk_not_initialized()) },
    };
    let peer_ctx = match sdk.peer(&peer_id) {
        Some(p) => p,
        None => return Response::DiscoverHandlers { request_id, result: Err(peer_not_found(&peer_id)) },
    };
    let wire: Vec<WireHandlerInfo> = peer_ctx
        .discover_handlers()
        .into_iter()
        .map(WireHandlerInfo::from)
        .collect();
    Response::DiscoverHandlers { request_id, result: Ok(wire) }
}

fn handle_discover_types(
    state: Rc<RefCell<WorkerState>>,
    request_id: RequestId,
    peer_id: String,
) -> Response {
    let st = state.borrow();
    let sdk = match st.sdk.as_ref() {
        Some(s) => s,
        None => return Response::DiscoverTypes { request_id, result: Err(sdk_not_initialized()) },
    };
    let peer_ctx = match sdk.peer(&peer_id) {
        Some(p) => p,
        None => return Response::DiscoverTypes { request_id, result: Err(peer_not_found(&peer_id)) },
    };
    let wire: Vec<WireTypeInfo> = peer_ctx
        .discover_types()
        .into_iter()
        .map(WireTypeInfo::from)
        .collect();
    Response::DiscoverTypes { request_id, result: Ok(wire) }
}

fn handle_entity_count(
    state: Rc<RefCell<WorkerState>>,
    request_id: RequestId,
    peer_id: String,
) -> Response {
    let st = state.borrow();
    let sdk = match st.sdk.as_ref() {
        Some(s) => s,
        None => return Response::EntityCount { request_id, result: Err(sdk_not_initialized()) },
    };
    let peer_ctx = match sdk.peer(&peer_id) {
        Some(p) => p,
        None => return Response::EntityCount { request_id, result: Err(peer_not_found(&peer_id)) },
    };
    Response::EntityCount {
        request_id,
        result: Ok(peer_ctx.entity_count() as u64),
    }
}

fn handle_path_count(
    state: Rc<RefCell<WorkerState>>,
    request_id: RequestId,
    peer_id: String,
) -> Response {
    let st = state.borrow();
    let sdk = match st.sdk.as_ref() {
        Some(s) => s,
        None => return Response::PathCount { request_id, result: Err(sdk_not_initialized()) },
    };
    let peer_ctx = match sdk.peer(&peer_id) {
        Some(p) => p,
        None => return Response::PathCount { request_id, result: Err(peer_not_found(&peer_id)) },
    };
    Response::PathCount {
        request_id,
        result: Ok(peer_ctx.path_count() as u64),
    }
}

fn handle_create_peer(
    state: Rc<RefCell<WorkerState>>,
    request_id: RequestId,
    label: Option<String>,
) -> Response {
    // Generate keypair inside the worker — `getrandom`'s `js` feature
    // is enabled, so this works in the browser. Seed bytes round-trip to
    // the consumer for localStorage persistence (the host doesn't keep
    // them; the peer rebuilds from the seed on next Init).
    let keypair = Keypair::generate();
    let seed = keypair.secret_key_bytes();
    // Derive peer-id pre-create so we can bake it into the per-peer
    // MessagePortConnector (OpenChannel.from_peer needs the source id).
    let new_pid = keypair.peer_id().to_string();

    let config = PeerConfig {
        debug_open_grants: true,
        ..PeerConfig::default()
    };

    let control_client = state.borrow().control_client.clone();
    let connector = build_per_peer_connector(control_client.as_ref(), &new_pid);

    // Inspect-hook plumbing — default-off flag installed alongside the
    // new peer's substrate hooks (PROTOCOL v9). Built via
    // PeerContextBuilder + insert_peer so the per-peer hooks are wired
    // before SDK ownership.
    let global_for_hooks = match js_sys::global().dyn_into::<web_sys::DedicatedWorkerGlobalScope>() {
        Ok(g) => g,
        Err(_) => {
            return Response::CreatePeer {
                request_id,
                result: Err(WireError {
                    kind: WireErrorKind::Unknown,
                    message: "handle_create_peer called outside DedicatedWorkerGlobalScope".into(),
                    detail: None,
                }),
            };
        }
    };
    let flag = Arc::new(AtomicBool::new(false));
    let builder = PeerContextBuilder::new()
        .keypair(keypair)
        .config(config)
        .connector(connector);
    let builder = install_inspect_hooks_on_builder(
        builder,
        new_pid.clone(),
        flag.clone(),
        global_for_hooks,
    );
    let ctx = match builder.build() {
        Ok(c) => c,
        Err(e) => {
            return Response::CreatePeer {
                request_id,
                result: Err(WireError {
                    kind: WireErrorKind::Unknown,
                    message: format!("create_peer build failed: {e}"),
                    detail: None,
                }),
            };
        }
    };

    let metadata = PeerMetadata {
        label: label.clone(),
        persisted: true,
        ..PeerMetadata::default()
    };

    let peer_id = {
        let mut st = state.borrow_mut();
        let sdk = match st.sdk.as_mut() {
            Some(s) => s,
            None => {
                return Response::CreatePeer {
                    request_id,
                    result: Err(sdk_not_initialized()),
                };
            }
        };

        let pid = match sdk.insert_peer_with_metadata(ctx, metadata.clone()) {
            Ok(id) => id,
            Err(e) => {
                return Response::CreatePeer {
                    request_id,
                    result: Err(WireError {
                        kind: WireErrorKind::Unknown,
                        message: format!("create_peer insert failed: {e}"),
                        detail: None,
                    }),
                };
            }
        };
        debug_assert_eq!(pid, new_pid);

        // Bind an xworker listener for the new peer if we have a control
        // client. Reuses the same `ControlPortClient`/port handler as the
        // primary — no new port-handler installation, no risk of the
        // shared-port-lifecycle bug from the earlier per-peer-closure
        // shape.
        if let Some(control) = control_client {
            bind_xworker_listener(sdk, &pid, control);
        }
        pid
    };
    state
        .borrow_mut()
        .inspect_enabled
        .insert(peer_id.clone(), flag);

    Response::CreatePeer {
        request_id,
        result: Ok(CreatePeerOk {
            peer_id,
            keypair_seed: seed.to_vec(),
            metadata: WirePeerMetadata::from(metadata),
        }),
    }
}

fn handle_delete_peer(
    state: Rc<RefCell<WorkerState>>,
    request_id: RequestId,
    peer_id: String,
) -> Response {
    // Snapshot control_client before borrowing mut for sdk access —
    // need it after remove_peer to unregister the listener.
    let control = state.borrow().control_client.clone();

    let mut st = state.borrow_mut();
    let sdk = match st.sdk.as_mut() {
        Some(s) => s,
        None => return Response::DeletePeer { request_id, result: Some(sdk_not_initialized()) },
    };
    let removed = sdk.remove_peer(&peer_id);

    // Unregister the xworker listener ONLY if remove_peer succeeded.
    // remove_peer returns false for "not found" (no listener to clean
    // up anyway) or "is the primary peer" (peer is still alive and
    // must remain xworker-reachable). Doing this in either order has
    // tradeoffs:
    // - unregister-then-remove risks silently killing the primary's
    //   reachability on a failed delete (the primary stays alive but
    //   stops accepting xworker connections).
    // - remove-then-unregister means a racing inbound channel for the
    //   peer arrives at a listener whose SDK side is already gone, so
    //   handle_connection fails the handshake — but that's a clean,
    //   observable failure (remote sees error) rather than silent
    //   capability loss for an unrelated peer.
    if removed {
        if let Some(c) = control {
            c.unregister_listener(&peer_id);
        }
        st.inspect_enabled.remove(&peer_id);
    }

    Response::DeletePeer {
        request_id,
        result: if removed {
            None
        } else {
            Some(WireError {
                kind: WireErrorKind::NotFound,
                message: format!(
                    "delete_peer: '{peer_id}' not found or is the primary peer"
                ),
                detail: None,
            })
        },
    }
}

fn handle_set_metadata(
    state: Rc<RefCell<WorkerState>>,
    request_id: RequestId,
    peer_id: String,
    metadata: WirePeerMetadata,
) -> Response {
    let mut st = state.borrow_mut();
    let sdk = match st.sdk.as_mut() {
        Some(s) => s,
        None => return Response::SetMetadata { request_id, result: Some(sdk_not_initialized()) },
    };
    if sdk.peer(&peer_id).is_none() {
        return Response::SetMetadata {
            request_id,
            result: Some(peer_not_found(&peer_id)),
        };
    }
    sdk.set_metadata(&peer_id, PeerMetadata::from(metadata));
    Response::SetMetadata { request_id, result: None }
}

async fn handle_connect_peer(
    state: Rc<RefCell<WorkerState>>,
    request_id: RequestId,
    peer_id: String,
    address: String,
) -> Response {
    // Get an owned `Arc<PeerShared>` so the borrow on WorkerState can
    // drop before we await on the network. The shared handle carries
    // everything `Peer::connect_to` needs (connector, keypair, remote
    // pool). Inlined here rather than calling `Peer::connect_to(&self)`
    // to avoid holding a `&Peer` borrow across the await.
    let shared = {
        let st = state.borrow();
        let sdk = match st.sdk.as_ref() {
            Some(s) => s,
            None => {
                return Response::ConnectPeer {
                    request_id,
                    result: Err(sdk_not_initialized()),
                };
            }
        };
        let peer_ctx = match sdk.peer(&peer_id) {
            Some(p) => p,
            None => {
                return Response::ConnectPeer {
                    request_id,
                    result: Err(peer_not_found(&peer_id)),
                };
            }
        };
        peer_ctx.peer_shared()
    };

    // Mirrors `Peer::connect_to` (core/peer/src/lib.rs:391) — same four
    // steps. Kept inline to avoid a `&self` borrow across the await.
    let conn = match shared.connector.connect(&address).await {
        Ok(c) => c,
        Err(e) => {
            return Response::ConnectPeer {
                request_id,
                result: Err(WireError {
                    kind: WireErrorKind::Unknown,
                    message: format!("connect to {address}: {e}"),
                    detail: None,
                }),
            };
        }
    };
    let remote = match entity_peer::remote::perform_connect(conn, &shared.keypair, shared.config.home_hash_format).await {
        Ok(r) => r,
        Err(e) => {
            return Response::ConnectPeer {
                request_id,
                result: Err(WireError {
                    kind: WireErrorKind::Unknown,
                    message: format!("handshake with {address}: {e}"),
                    detail: None,
                }),
            };
        }
    };
    let remote_peer_id = remote.remote_peer_id.clone();
    shared.remote.insert(&remote_peer_id, remote);

    Response::ConnectPeer {
        request_id,
        result: Ok(ConnectPeerOk { remote_peer_id }),
    }
}

fn handle_set_inspect_enabled(
    state: Rc<RefCell<WorkerState>>,
    request_id: RequestId,
    peer_id: String,
    enabled: bool,
) -> Response {
    let st = state.borrow();
    match st.inspect_enabled.get(&peer_id) {
        Some(flag) => {
            flag.store(enabled, Ordering::Relaxed);
            Response::SetInspectEnabled {
                request_id,
                result: None,
            }
        }
        None => Response::SetInspectEnabled {
            request_id,
            result: Some(peer_not_found(&peer_id)),
        },
    }
}

fn handle_register_backend_peer(
    state: Rc<RefCell<WorkerState>>,
    request_id: RequestId,
    peer_id: String,
    label: Option<String>,
    listen_addresses: Vec<String>,
) -> Response {
    let mut st = state.borrow_mut();
    let sdk = match st.sdk.as_mut() {
        Some(s) => s,
        None => return Response::RegisterBackendPeer { request_id, result: Some(sdk_not_initialized()) },
    };
    let ok = sdk.register_backend_peer(
        peer_id,
        PeerMetadata {
            listen_addresses,
            label,
            ..PeerMetadata::default()
        },
    );
    Response::RegisterBackendPeer {
        request_id,
        result: if ok {
            None
        } else {
            Some(WireError {
                kind: WireErrorKind::InvalidParams,
                message: "peer_id already exists".into(),
                detail: None,
            })
        },
    }
}

// ---------------------------------------------------------------------------
// Subscriptions
// ---------------------------------------------------------------------------

async fn handle_subscribe(
    state: Rc<RefCell<WorkerState>>,
    request_id: RequestId,
    sub_id: SubId,
    peer_id: String,
    prefix: String,
    global: DedicatedWorkerGlobalScope,
) -> Response {
    // Each peer has its own L1 subscription engine — a callback registered
    // on peer A only fires for writes through peer A's dispatch. The
    // wire's `peer_id` (v6+) selects the target peer; v5 proxies sending
    // an empty string fall back to default_peer_id with a tracing warning.
    //
    // Change events carry the post-write entity. L1SubscriptionEvent.new_hash
    // is Some on create/update, None on delete. L0 store access is sync;
    // ContentLookup is the documented clone-friendly handle for this exact
    // use case (see StoreAccess::content_lookup docs). Look up by hash, not
    // path — avoids the path→hash race where the path may have moved on by
    // the time the callback runs.

    // Resolve peer + start the subscribe future. Borrow released before await.
    let (subscribe_future, target_peer_id) = {
        let st = state.borrow();
        let sdk = match st.sdk.as_ref() {
            Some(s) => s,
            None => return Response::Subscribe { request_id, result: Some(sdk_not_initialized()) },
        };
        // v5→v6 backcompat: empty peer_id from old proxy → default peer.
        // The version handshake (R1) catches this at boot, but the
        // fall-through here keeps us robust if the handshake is bypassed.
        let target_peer_id = if peer_id.is_empty() {
            web_sys::console::warn_1(&JsValue::from_str(
                "wasm-worker-host: Subscribe received without peer_id (pre-v6 proxy?); \
                 falling back to default_peer_id",
            ));
            sdk.default_peer_id().to_string()
        } else {
            peer_id
        };
        let peer_ctx = match sdk.peer(&target_peer_id) {
            Some(p) => p,
            None => return Response::Subscribe { request_id, result: Some(peer_not_found(&target_peer_id)) },
        };

        let global_for_cb = global.clone();
        let lookup = peer_ctx.store().content_lookup();
        let callback = move |evt: entity_sdk::subscription::L1SubscriptionEvent| {
            let new_entity = evt
                .new_hash
                .as_ref()
                .and_then(|h| lookup.get_by_hash(h))
                .map(WireEntity::from);
            if evt.new_hash.is_some() && new_entity.is_none() {
                // The cascade just stored this hash; lookup miss is unexpected.
                // Ship None as the safest fallback and warn — the proxy will
                // treat it as a delete, which is wrong but bounded.
                web_sys::console::warn_1(&JsValue::from_str(&format!(
                    "wasm-worker-host: subscription callback could not resolve new_hash for path '{}'",
                    evt.path
                )));
            }
            let event = Event::Change {
                sub_id,
                path: evt.path,
                new_entity,
            };
            send_event(&global_for_cb, &event);
        };

        // Wire `prefix` (descendant intent) → SDK `pattern` (wildcard).
        // The SDK's `subscribe(pattern, ...)` exact-matches the literal
        // pattern unless it ends in `/*` (see extensions/subscription/src/
        // engine.rs:pattern_matches). A wire prefix like `/peer/` would
        // only fire on writes to that exact path — never on descendants.
        // Convert here so descendant intent is honored.
        let pattern = prefix_to_pattern(&prefix);
        let fut = peer_ctx.subscribe(pattern, callback);
        (fut, target_peer_id)
    };

    // Resolve the subscribe future BEFORE snapshotting — seeded ordering
    // (`on_prefix_change_seeded`).
    //
    // Mechanism (verified against bindings/sdk/src/subscription.rs):
    // `peer_ctx.subscribe()` installs the delivery handler synchronously
    // when the future is *created* (the prologue's `register_handler`),
    // but the subscription engine only starts ROUTING tree-change events
    // to it once the `system/subscription:subscribe` EXECUTE — which runs
    // inside this awaited future — completes. So events can begin flowing
    // partway through this await.
    //
    // Why snapshot-after-await has no lost-write window: any write the
    // engine routes (necessarily at/after the moment routing turns on,
    // which is during this await) is also visible to the
    // `build_initial_snapshot` list scan below, because that scan runs
    // strictly after the await resolves. So every such write is in the
    // snapshot; the duplicate live `Change` for it arrives before the
    // `Snapshot` and is dropped by the proxy (snapshot_received==false,
    // proxy lib.rs:416) — harmless, the snapshot carries the value, and
    // the callback contract is idempotent. The OLD order (snapshot before
    // await) lost writes that landed after the pre-await scan but before
    // routing turned on: in neither the snapshot nor the (not-yet-routed)
    // event stream.
    let handle = match subscribe_future.await {
        Ok(h) => h,
        Err(e) => return Response::Subscribe { request_id, result: Some(WireError::from(e)) },
    };

    state.borrow_mut().subscriptions.insert(sub_id, handle);

    // Snapshot uses the L0 store scan over the raw prefix (no /* needed).
    // No await between here and the Snapshot send below, so no write can
    // interleave into the gap.
    let snapshot_entries = build_initial_snapshot(state.clone(), &target_peer_id, &prefix);

    // Ship Snapshot first (invariant #1: snapshot before any Change).
    // Then ack the Subscribe Request. The proxy unblocks when it sees the
    // Response, but the demultiplexer will have already routed the
    // Snapshot Event by then because both messages travel the same
    // postMessage channel in order.
    send_event(&global, &Event::Snapshot {
        sub_id,
        entries: snapshot_entries,
    });

    Response::Subscribe { request_id, result: None }
}

/// Build the initial snapshot for a subscription. Thin wrapper around
/// `StoreAccess::list_entities` — the SDK owns the "snapshot a subtree"
/// primitive (see decision §4.4 in WORKER-MODE-LIVING-DOC.md).
fn build_initial_snapshot(
    state: Rc<RefCell<WorkerState>>,
    peer_id: &str,
    prefix: &str,
) -> Vec<(String, WireEntity)> {
    let st = state.borrow();
    let sdk = match st.sdk.as_ref() {
        Some(s) => s,
        None => return Vec::new(),
    };
    let peer_ctx = match sdk.peer(peer_id) {
        Some(p) => p,
        None => return Vec::new(),
    };
    peer_ctx
        .store()
        .list_entities(prefix)
        .into_iter()
        .map(|(path, e)| (path, WireEntity::from(e)))
        .collect()
}

fn handle_unsubscribe(
    state: Rc<RefCell<WorkerState>>,
    request_id: RequestId,
    sub_id: SubId,
) -> Response {
    // Removing the handle from the map drops it, which cancels the
    // SDK-side subscription.
    state.borrow_mut().subscriptions.remove(&sub_id);
    Response::Unsubscribe { request_id, result: None }
}

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

/// Translate a wire-protocol subscription `prefix` into the SDK's
/// pattern syntax. The SDK matches patterns literally unless they end
/// in `/*` (descendant match) or are the universal `*`.
///
/// Convention (Unix-style):
///   - trailing slash → "watch everything under this subtree"
///     `/peer/foo/` → `/peer/foo/*` (descendants)
///   - no trailing slash → "watch this exact path"
///     `/peer/foo/state` → `/peer/foo/state` (literal)
///
/// This matters because the descendant pattern `/peer/foo/state/*`
/// matches only things under that path — never writes to the path
/// itself. Leaf-entity subscriptions (e.g. a window watching its own
/// state record) need exact-match semantics or they silently miss
/// every notification.
///
/// Idempotent on already-wildcarded inputs (`/*` suffix or universal `*`).
fn prefix_to_pattern(prefix: &str) -> String {
    if prefix == "*" || prefix.ends_with("/*") {
        return prefix.to_string();
    }
    if prefix.ends_with('/') {
        format!("{prefix}*")
    } else {
        prefix.to_string()
    }
}

fn sdk_not_initialized() -> WireError {
    WireError {
        kind: WireErrorKind::InvalidParams,
        message: "Request received before Init completed — proxy/host out of sync".into(),
        detail: None,
    }
}

fn peer_not_found(peer_id: &str) -> WireError {
    WireError {
        kind: WireErrorKind::NotFound,
        message: format!("no peer with id '{peer_id}' in this worker's SDK"),
        detail: None,
    }
}

fn conversion_error(field: &str, e: &ConversionError) -> WireError {
    WireError {
        kind: WireErrorKind::InvalidParams,
        message: format!("wire conversion failed for {field}: {e}"),
        detail: None,
    }
}

// CasFailure is constructed by the host when put_cas finds a conflict.
// Phase 1.x: actually wire CAS through `peer_ctx.put_cas`.
#[allow(dead_code)]
fn _cas_failure_placeholder() -> CasFailure {
    CasFailure {
        kind: CasFailureKind::NotFound,
        actual: None,
    }
}
