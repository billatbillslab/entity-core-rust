//! Real `Transport` implementation backed by `web_sys::Worker`.
//!
//! # Wire format
//!
//! Messages cross postMessage as **CBOR-encoded byte buffers** rather than
//! structured JS objects. This keeps the wire format identical to what
//! would cross a network socket (relevant if a future deployment routes
//! the same protocol over WebSocket / WebRTC / Tauri IPC) and avoids
//! pulling all of serde's JS-value adapter machinery into the wasm bundle.
//! `ciborium` handles encode/decode on both sides.
//!
//! # Demultiplexing
//!
//! Inbound messages are either:
//! - **`Response`** — routed to the matching `oneshot::Sender` registered
//!   in `pending_requests` by `request_id`. The `request_id` is extracted
//!   from the deserialized `Response` variant; if no pending entry exists
//!   (worker sent us an unsolicited response), the message is dropped
//!   with a `tracing::warn!`.
//! - **`Event`** — pushed onto `event_tx`. The proxy's demultiplexer task
//!   (Step 5) drains `event_rx` and routes events by `sub_id`.
//!
//! Init handshake's `Response::Ready` is just another response — routed by
//! its `request_id` to whoever's awaiting `Request::Init`.
//!
//! # Lifecycle
//!
//! `WebTransport` holds a `Worker` handle and an `_onmessage` closure
//! reference (must outlive the transport — JS-side callback). Dropping the
//! transport drops the closure and the worker; the worker is then
//! garbage-collected by the browser.

use entity_wasm_worker_protocol::{Event, Request, Response, RequestId};
use futures::channel::{mpsc, oneshot};
use js_sys::Uint8Array;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{MessageEvent, MessagePort, Worker};

use crate::{ProxyError, Transport};

type PendingMap = Rc<RefCell<HashMap<RequestId, oneshot::Sender<Response>>>>;

pub struct WebTransport {
    worker: Worker,
    pending: PendingMap,
    /// Outbound channel — the onmessage closure pushes Events here; the
    /// proxy's demultiplexer drains the receiver. Wrapped in `RefCell<Option<_>>`
    /// so `take_event_stream` can hand it off once.
    event_rx: RefCell<Option<mpsc::UnboundedReceiver<Event>>>,
    /// Kept alive for the lifetime of the transport — dropping invalidates
    /// the JS onmessage handler. `_onmessage` is intentionally unused; the
    /// closure is leaked into the Worker via `set_onmessage` and we hold
    /// the Rust handle so it doesn't drop while the worker still references
    /// it.
    _onmessage: Closure<dyn FnMut(MessageEvent)>,
    /// Optional control port to transfer on the FIRST outbound
    /// postMessage (the Init request). Consumes itself on first use —
    /// subsequent posts go through the plain path. Set via
    /// `with_control_port`; `new` leaves this empty.
    pending_transfer: RefCell<Option<MessagePort>>,
}

impl WebTransport {
    /// Wrap an already-constructed `Worker`. The transport installs the
    /// `onmessage` handler immediately; the worker should not have any
    /// messages in flight before this is called.
    pub fn new(worker: Worker) -> Self {
        let pending: PendingMap = Rc::new(RefCell::new(HashMap::new()));
        let (event_tx, event_rx) = mpsc::unbounded::<Event>();

        let onmessage = {
            let pending = pending.clone();
            Closure::wrap(Box::new(move |evt: MessageEvent| {
                let data = evt.data();
                // The worker is contracted to send Uint8Array payloads (CBOR
                // bytes). Anything else is a protocol violation — log and
                // drop. We don't want to panic on a malformed message and
                // bring down the page.
                let bytes = match data.dyn_into::<Uint8Array>() {
                    Ok(arr) => arr.to_vec(),
                    Err(orig) => {
                        // `orig` was the original JsValue. Surface it via
                        // tracing if available; for now just stderr-ish.
                        web_sys::console::warn_1(&JsValue::from_str(
                            "wasm-worker-proxy: ignoring non-Uint8Array message from worker",
                        ));
                        drop(orig);
                        return;
                    }
                };
                // Try Response first, then Event. They're tagged separately
                // by serde, so attempting both is unambiguous.
                if let Ok(resp) = ciborium::from_reader::<Response, _>(bytes.as_slice()) {
                    let request_id = response_request_id(&resp);
                    if let Some(tx) = pending.borrow_mut().remove(&request_id) {
                        // Send may fail if the awaiter dropped the receiver;
                        // that's fine — request was abandoned. Ignore.
                        let _ = tx.send(resp);
                    } else {
                        web_sys::console::warn_1(&JsValue::from_str(&format!(
                            "wasm-worker-proxy: unmatched response for request_id={request_id}"
                        )));
                    }
                    return;
                }
                if let Ok(event) = ciborium::from_reader::<Event, _>(bytes.as_slice()) {
                    // Unbounded send only fails if the receiver was dropped.
                    // That means the proxy was dropped while the worker is
                    // still alive — also fine; events stop flowing.
                    let _ = event_tx.unbounded_send(event);
                    return;
                }
                web_sys::console::warn_1(&JsValue::from_str(
                    "wasm-worker-proxy: failed to decode worker message as Response or Event",
                ));
            }) as Box<dyn FnMut(MessageEvent)>)
        };
        worker.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));

        Self {
            worker,
            pending,
            event_rx: RefCell::new(Some(event_rx)),
            _onmessage: onmessage,
            pending_transfer: RefCell::new(None),
        }
    }

    /// Wrap a Worker and arrange for the given control port to be
    /// transferred to it on the FIRST outbound postMessage (the Init
    /// request). The Worker's host detects "control port present" by
    /// `event.ports().length() > 0` on the Init message and wires it
    /// to its `ControlPortClient`.
    pub fn with_control_port(worker: Worker, control_port: MessagePort) -> Self {
        let t = Self::new(worker);
        *t.pending_transfer.borrow_mut() = Some(control_port);
        t
    }

    fn post(&self, bytes: &[u8]) -> Result<(), JsValue> {
        // postMessage takes Transferable / structured-cloneable JsValue.
        // A Uint8Array view of our buffer is the cheapest way across.
        let arr = Uint8Array::new_with_length(bytes.len() as u32);
        arr.copy_from(bytes);
        // First outbound message consumes any pending control-port
        // transfer; subsequent messages use the plain path.
        if let Some(port) = self.pending_transfer.borrow_mut().take() {
            let transfer = js_sys::Array::new();
            transfer.push(&port);
            self.worker.post_message_with_transfer(&arr, &transfer)
        } else {
            self.worker.post_message(&arr)
        }
    }
}

impl Transport for WebTransport {
    fn send_request(&self, req: Request) -> oneshot::Receiver<Response> {
        let request_id = request_request_id(&req);
        let (tx, rx) = oneshot::channel();
        self.pending.borrow_mut().insert(request_id, tx);

        let mut buf = Vec::new();
        if let Err(e) = ciborium::into_writer(&req, &mut buf) {
            // Encoding failed — drop the pending entry and resolve the
            // receiver immediately with a synthesized error via a dropped
            // sender (the receiver will see `Cancelled` in the proxy).
            self.pending.borrow_mut().remove(&request_id);
            web_sys::console::error_1(&JsValue::from_str(&format!(
                "wasm-worker-proxy: CBOR encode failed for request_id={request_id}: {e}"
            )));
            return rx; // sender has been dropped; awaiter gets Err
        }

        if let Err(js_err) = self.post(&buf) {
            self.pending.borrow_mut().remove(&request_id);
            web_sys::console::error_1(&JsValue::from_str(&format!(
                "wasm-worker-proxy: postMessage failed for request_id={request_id}: {js_err:?}"
            )));
            // Same: dropping the pending entry drops the sender; awaiter
            // sees Cancelled.
        }

        rx
    }

    fn take_event_stream(&self) -> Option<mpsc::UnboundedReceiver<Event>> {
        self.event_rx.borrow_mut().take()
    }

    /// Terminate the worker and drop all pending request senders.
    ///
    /// `Worker.terminate()` is abrupt — the worker is killed immediately
    /// with no chance to flush. That's safe for `OpfsStore` because every
    /// committed write is `append_and_flush`-ed synchronously before the
    /// op returns. Pending senders are dropped *before* terminate so that
    /// in-flight awaiters resolve via the dropped-sender path (the proxy
    /// surfaces this as `ProxyError::Cancelled`).
    ///
    /// Idempotent: a second call after `worker.terminate()` is a no-op on
    /// the JS side (per the HTML Living Standard) and finds the pending
    /// map already empty.
    fn terminate(&self) {
        self.pending.borrow_mut().clear();
        self.worker.terminate();
    }
}

/// Extract the `request_id` from a `Request` variant. Every variant carries
/// one; this is just match boilerplate. Co-located here rather than as a
/// method on `Request` because adding it to the protocol crate would
/// require keeping it in lock-step with variant additions — and the
/// coverage check + macro pattern in this crate's `proxy_method!` already
/// ensures every variant has the field.
fn request_request_id(req: &Request) -> RequestId {
    match req {
        Request::Init { request_id, .. }
        | Request::RegisterBackendPeer { request_id, .. }
        | Request::CreatePeer { request_id, .. }
        | Request::DeletePeer { request_id, .. }
        | Request::SetMetadata { request_id, .. }
        | Request::ConnectPeer { request_id, .. }
        | Request::Get { request_id, .. }
        | Request::Put { request_id, .. }
        | Request::PutCas { request_id, .. }
        | Request::List { request_id, .. }
        | Request::Remove { request_id, .. }
        | Request::Has { request_id, .. }
        | Request::Execute { request_id, .. }
        | Request::Query { request_id, .. }
        | Request::Count { request_id, .. }
        | Request::EntityCount { request_id, .. }
        | Request::PathCount { request_id, .. }
        | Request::InboxList { request_id, .. }
        | Request::InboxGet { request_id, .. }
        | Request::DiscoverHandlers { request_id, .. }
        | Request::DiscoverTypes { request_id, .. }
        | Request::Subscribe { request_id, .. }
        | Request::Unsubscribe { request_id, .. }
        | Request::SetInspectEnabled { request_id, .. } => *request_id,
    }
}

fn response_request_id(resp: &Response) -> RequestId {
    match resp {
        Response::Ready { request_id, .. }
        | Response::Init { request_id, .. }
        | Response::RegisterBackendPeer { request_id, .. }
        | Response::CreatePeer { request_id, .. }
        | Response::DeletePeer { request_id, .. }
        | Response::SetMetadata { request_id, .. }
        | Response::ConnectPeer { request_id, .. }
        | Response::Get { request_id, .. }
        | Response::Put { request_id, .. }
        | Response::PutCas { request_id, .. }
        | Response::List { request_id, .. }
        | Response::Remove { request_id, .. }
        | Response::Has { request_id, .. }
        | Response::Execute { request_id, .. }
        | Response::Query { request_id, .. }
        | Response::Count { request_id, .. }
        | Response::EntityCount { request_id, .. }
        | Response::PathCount { request_id, .. }
        | Response::InboxList { request_id, .. }
        | Response::InboxGet { request_id, .. }
        | Response::DiscoverHandlers { request_id, .. }
        | Response::DiscoverTypes { request_id, .. }
        | Response::Subscribe { request_id, .. }
        | Response::Unsubscribe { request_id, .. }
        | Response::SetInspectEnabled { request_id, .. } => *request_id,
    }
}

// ---------------------------------------------------------------------------
// WorkerProxy::spawn convenience
// ---------------------------------------------------------------------------

use entity_wasm_worker_protocol::InitParams;
use crate::WorkerProxy;

impl WorkerProxy<WebTransport> {
    /// Convenience wrapper: spawn a `Worker` from `worker_url` and run the
    /// init handshake. Equivalent to:
    ///
    /// ```ignore
    /// let worker = web_sys::Worker::new(worker_url)?;
    /// WorkerProxy::new(WebTransport::new(worker), init).await?
    /// ```
    ///
    /// Drop down to that two-step form when you need
    /// `Worker::new_with_options` (e.g., `type: "module"` for ESM workers)
    /// or want to share a single `Worker` across multiple consumers.
    pub async fn spawn(worker_url: &str, init: InitParams) -> Result<Self, ProxyError> {
        let worker = Worker::new(worker_url)
            .map_err(|e| ProxyError::WorkerSpawn(format!("{e:?}")))?;
        Self::new(WebTransport::new(worker), init).await
    }
}
