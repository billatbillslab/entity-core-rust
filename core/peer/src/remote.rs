//! Outbound connections and remote execute.
//!
//! Provides client-side connection management: resolve transport address from tree,
//! connect via configured transport, perform hello/authenticate handshake, send
//! authenticated EXECUTE, and cache connections for reuse.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use entity_crypto::IdentityKeypair;
use entity_entity::{Entity, EntityUri, Envelope};
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};
use entity_wire::{decode_envelope, encode_envelope, read_frame, write_frame, DEFAULT_MAX_FRAME_SIZE};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;

use crate::transport::Connector;
use crate::PeerError;

// ---------------------------------------------------------------------------
// Platform shims for the multiplexed reader task (Class G / F-WB28).
// Native: tokio::spawn + JoinHandle (abortable on Drop) + tokio::time::timeout.
// WASM:  wasm_bindgen_futures::spawn_local (no abort; rely on stream EOF) +
//        gloo_timers TimeoutFuture for per-request deadlines.
// ---------------------------------------------------------------------------

#[cfg(not(target_arch = "wasm32"))]
type ReaderTaskHandle = tokio::task::JoinHandle<()>;
#[cfg(target_arch = "wasm32")]
type ReaderTaskHandle = ();

#[cfg(not(target_arch = "wasm32"))]
fn spawn_reader_task<F>(f: F) -> ReaderTaskHandle
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(f)
}

#[cfg(target_arch = "wasm32")]
fn spawn_reader_task<F>(f: F) -> ReaderTaskHandle
where
    F: std::future::Future<Output = ()> + 'static,
{
    wasm_bindgen_futures::spawn_local(f);
}

/// Await `fut` with a per-request deadline. Returns `Err(())` on timeout.
#[cfg(not(target_arch = "wasm32"))]
async fn request_timeout<T>(
    dur: Duration,
    fut: oneshot::Receiver<T>,
) -> Result<Result<T, oneshot::error::RecvError>, ()> {
    tokio::time::timeout(dur, fut).await.map_err(|_| ())
}

#[cfg(target_arch = "wasm32")]
async fn request_timeout<T>(
    dur: Duration,
    fut: oneshot::Receiver<T>,
) -> Result<Result<T, oneshot::error::RecvError>, ()> {
    use futures::future::{select, Either};
    let ms = dur.as_millis() as u32;
    let timer = gloo_timers::future::TimeoutFuture::new(ms);
    futures::pin_mut!(timer);
    futures::pin_mut!(fut);
    match select(timer, fut).await {
        Either::Left(_) => Err(()),
        Either::Right((res, _)) => Ok(res),
    }
}

/// Default per-request response deadline. Independent of the connection-
/// establishment timeout. Per-request, NOT per-connection — concurrent
/// requests on the same connection each have their own clock per V7 §6
/// transport-reentry contract point (c).
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// RemoteEndpoint — outbound-pool abstraction across stream + request/response
// transports (PROPOSAL-TRANSPORT-FAMILY-LIVE-REACHABILITY §7.3, R1).
// ---------------------------------------------------------------------------
//
// The `Connector` trait returns a `Connection { reader, writer }` —
// fits TCP / WS / Memory / MessagePort, all stream-style full-duplex
// transports. HTTP is request/response per POST (half-duplex per
// connection) and CANNOT be expressed as AsyncRead/AsyncWrite halves
// without lying about boundaries.
//
// `RemoteEndpoint` is the sibling abstraction at the *pool* layer:
// any outbound endpoint that's gone through the handshake and holds a
// connection-grant cap can implement it. The pool holds
// `Arc<dyn RemoteEndpoint>`, and `send_execute` takes `&dyn RemoteEndpoint`
// — both `RemoteConnection` (stream multiplexed) and `HttpConnection`
// (POST-per-request, future) fit.
//
// Trait design:
// - Accessors (`remote_peer_id`, `remote_identity_hash`, `capability`,
//   `auth_included`) expose what `send_execute` needs to build a signed
//   EXECUTE envelope.
// - `next_request_id()` lets each transport own its sequencing (the
//   multiplexed stream uses atomic-counter `req-N`; HTTP needs its own).
// - `dispatch_envelope(envelope)` is the transport primitive: "send
//   this envelope, return the parsed response." For the stream
//   transport it registers a pending oneshot, writes the frame, awaits.
//   For HTTP it does a POST round-trip.
// - `transport_type()` for diagnostics.
//
// Pinned-`Future`-as-return-type rather than `async fn in trait` so the
// trait stays object-safe across native (Send) and WASM (?Send) builds
// via the existing `async_trait` cfg pattern used elsewhere in this
// crate.

/// Boxed future returned by `RemoteEndpoint::dispatch_envelope`.
#[cfg(not(target_arch = "wasm32"))]
pub type DispatchFuture<'a> = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Result<entity_protocol::ParsedResponse, PeerError>>
            + Send
            + 'a,
    >,
>;
#[cfg(target_arch = "wasm32")]
pub type DispatchFuture<'a> = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Result<entity_protocol::ParsedResponse, PeerError>>
            + 'a,
    >,
>;

/// Outbound endpoint trait — implemented by `RemoteConnection` (stream)
/// and `HttpConnection` (POST). Pool holds `Arc<dyn RemoteEndpoint>`.
///
/// `Send + Sync` are required on both native and WASM: the pool stores
/// `Arc<dyn _>` (Arc requires Sync on its contents to be Send) and
/// `RemoteConnection`/`HttpConnection` are both already Send+Sync by
/// construction (their underlying writers are `Box<dyn AsyncWrite +
/// Unpin + Send>` even on WASM; Mutex + Box give Sync). The
/// **futures returned by `dispatch_envelope`** are the only piece
/// that differs by platform — see [`DispatchFuture`].
pub trait RemoteEndpoint: Send + Sync {
    fn remote_peer_id(&self) -> &str;
    fn remote_identity_hash(&self) -> Hash;
    fn capability(&self) -> &Entity;
    fn auth_included(&self) -> &HashMap<Hash, Entity>;
    fn next_request_id(&self) -> String;
    fn transport_type(&self) -> &'static str;
    /// Send one already-encoded EXECUTE **frame** (the wire CBOR bytes)
    /// verbatim and return the parsed response, demuxed by `request_id`.
    ///
    /// This is the byte-exact send path the RELAY terminal hop (§3.1.1)
    /// requires: the relay writes an opaque inner envelope's raw bytes into
    /// the destination's inbound frame *without decoding or re-encoding them*
    /// — exactly the bytes a direct connection would have carried. The
    /// `request_id` MUST equal the one embedded in `frame` (the demux key the
    /// caller extracted from the inner envelope, or `next_request_id()` for
    /// locally-built frames).
    fn dispatch_raw<'a>(&'a self, request_id: String, frame: Vec<u8>) -> DispatchFuture<'a>;

    /// Send one EXECUTE envelope; return the parsed response. Convenience
    /// wrapper over [`dispatch_raw`](Self::dispatch_raw) that encodes the
    /// envelope to a frame. The `request_id` MUST match the one embedded in
    /// the envelope (and is what `next_request_id()` returned); we pass it
    /// separately so stream transports can register their demux entry without
    /// re-parsing the envelope they were just handed.
    fn dispatch_envelope<'a>(
        &'a self,
        request_id: String,
        envelope: Envelope,
    ) -> DispatchFuture<'a> {
        let frame = encode_envelope(&envelope);
        self.dispatch_raw(request_id, frame)
    }
}

/// Pending response demultiplexer table — keyed by `request_id`.
///
/// Public so the accept-side message loop can share one table with an
/// [`InboundReentryEndpoint`] (§6.11(b)): the loop routes inbound
/// EXECUTE_RESPONSE frames in, the endpoint registers awaiters.
pub type Pending = Arc<Mutex<HashMap<String, oneshot::Sender<entity_protocol::ParsedResponse>>>>;

/// Construct an empty [`Pending`] demux table.
pub fn new_pending() -> Pending {
    Arc::new(Mutex::new(HashMap::new()))
}

/// A cached outbound connection to a remote peer.
///
/// Class G / F-WB28: multiplexed transport (Option A). A reader task owns
/// the read half and demuxes inbound EXECUTE_RESPONSE frames by
/// `request_id` into per-request oneshot channels. The write half lives
/// behind a short `tokio::sync::Mutex` that's held only across the
/// `write_frame` call — never across await on a response. This satisfies
/// the V7 §6.x transport reentry contract (multiple in-flight EXECUTEs
/// per pooled connection; response routing by request_id; per-request
/// deadlines at the request layer).
pub struct RemoteConnection {
    /// Write half — Mutex held only briefly during `write_frame`. Wrapped
    /// in `Arc` so the reader task can share it: on the §6.11(b) dialer-side
    /// reentry path the reader dispatches an inbound EXECUTE and writes the
    /// EXECUTE_RESPONSE back over this same write half (serialized with
    /// outbound request frames by the inner `Mutex`).
    writer: Arc<tokio::sync::Mutex<Box<dyn AsyncWrite + Unpin + Send>>>,
    /// Demux table for in-flight requests. When the reader task ends
    /// (connection broken), all senders are dropped; awaiters see a
    /// `RecvError` and translate it to a connection error.
    pending: Pending,
    /// Capability token received during handshake (grants us access on the remote peer).
    pub capability: Entity,
    /// All entities from the authenticate response's included map.
    /// Needed for capability chain verification on subsequent requests.
    pub auth_included: HashMap<Hash, Entity>,
    /// Remote peer ID (verified during handshake).
    pub remote_peer_id: String,
    /// Remote peer's identity entity hash (content hash of their system/peer entity).
    pub remote_identity_hash: Hash,
    /// Monotonic request counter — atomic so concurrent `send_execute`
    /// calls on the same connection get distinct IDs.
    request_seq: AtomicU64,
    /// Reader-task handle. On native, a `tokio::task::JoinHandle<()>`
    /// aborted on `Drop`. On WASM, `()` — there's no abort primitive for
    /// `wasm_bindgen_futures::spawn_local`; the reader loop terminates
    /// naturally when `read_frame` errors (the duplex closes when the
    /// write half is dropped).
    #[allow(dead_code)]
    reader_task: ReaderTaskHandle,
}

#[cfg(not(target_arch = "wasm32"))]
impl Drop for RemoteConnection {
    fn drop(&mut self) {
        self.reader_task.abort();
    }
}

impl RemoteEndpoint for RemoteConnection {
    fn remote_peer_id(&self) -> &str {
        &self.remote_peer_id
    }
    fn remote_identity_hash(&self) -> Hash {
        self.remote_identity_hash
    }
    fn capability(&self) -> &Entity {
        &self.capability
    }
    fn auth_included(&self) -> &HashMap<Hash, Entity> {
        &self.auth_included
    }
    fn next_request_id(&self) -> String {
        let seq = self.request_seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        format!("req-{}", seq)
    }
    fn transport_type(&self) -> &'static str {
        "stream"
    }
    fn dispatch_raw<'a>(
        &'a self,
        request_id: String,
        frame: Vec<u8>,
    ) -> DispatchFuture<'a> {
        Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            {
                let mut p = self.pending.lock().unwrap();
                p.insert(request_id.clone(), tx);
            }

            let write_res = {
                let mut writer = self.writer.lock().await;
                write_frame(&mut *writer, &frame).await
            };
            if let Err(e) = write_res {
                self.pending.lock().unwrap().remove(&request_id);
                return Err(PeerError::ConnectionError(format!("send execute: {}", e)));
            }

            match request_timeout(DEFAULT_REQUEST_TIMEOUT, rx).await {
                Ok(Ok(r)) => Ok(r),
                Ok(Err(_)) => {
                    self.pending.lock().unwrap().remove(&request_id);
                    Err(PeerError::ConnectionError(
                        "reader task terminated before response".to_string(),
                    ))
                }
                Err(_) => {
                    self.pending.lock().unwrap().remove(&request_id);
                    Err(PeerError::ConnectionError(format!(
                        "request {} timed out after {:?}",
                        request_id, DEFAULT_REQUEST_TIMEOUT
                    )))
                }
            }
        })
    }
}

/// A bidirectional endpoint over an **accepted** (server-side) connection,
/// for GUIDE-CONFORMANCE §7a / V7 §6.11(b) reentry: a handler dispatching
/// back to the peer that dialed *us* must reuse the same socket, because
/// that peer may have no listener of its own (the validator's B-role-no-
/// listener case).
///
/// Unlike [`RemoteConnection`], this type does NOT own a reader task — the
/// accept-side message loop (`connection::handle_connection`) already owns
/// the read half, multiplexing inbound EXECUTEs (dispatched as requests)
/// and inbound EXECUTE_RESPONSEs (routed to the shared `pending` table).
/// This endpoint only owns the *send* side: it encodes an outbound EXECUTE
/// frame, registers a oneshot in `pending`, and pushes the frame onto the
/// same writer channel the message loop drains.
pub struct InboundReentryEndpoint {
    /// Shared writer channel — the accept loop's serial frame writer.
    writer_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    /// Shared demux table — the accept read loop delivers EXECUTE_RESPONSE
    /// frames here, keyed by `request_id`.
    pending: Pending,
    /// The peer that dialed us (verified at handshake).
    remote_peer_id: String,
    /// That peer's authored identity content_hash.
    remote_identity_hash: Hash,
    /// Placeholder connection grant. The reentry dispatch path always passes
    /// an explicit `dispatch_cap` (the in-band reentry capability, §7a.2a),
    /// so `send_execute` never reads this — it exists only to satisfy the
    /// trait. Holds the capability we minted for the remote at handshake.
    capability: Entity,
    /// Empty — the reentry authority chain rides via `chain_bundle`
    /// (`extra_included`), not the connection's auth set.
    auth_included: HashMap<Hash, Entity>,
    /// Monotonic counter in a distinct `reentry-N` namespace so these IDs
    /// never collide with the inbound EXECUTE `request_id`s the remote chose
    /// (which we never place in `pending`).
    request_seq: AtomicU64,
}

impl InboundReentryEndpoint {
    pub fn new(
        remote_peer_id: String,
        remote_identity_hash: Hash,
        capability: Entity,
        writer_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
        pending: Pending,
    ) -> Self {
        Self {
            writer_tx,
            pending,
            remote_peer_id,
            remote_identity_hash,
            capability,
            auth_included: HashMap::new(),
            request_seq: AtomicU64::new(0),
        }
    }
}

impl RemoteEndpoint for InboundReentryEndpoint {
    fn remote_peer_id(&self) -> &str {
        &self.remote_peer_id
    }
    fn remote_identity_hash(&self) -> Hash {
        self.remote_identity_hash
    }
    fn capability(&self) -> &Entity {
        &self.capability
    }
    fn auth_included(&self) -> &HashMap<Hash, Entity> {
        &self.auth_included
    }
    fn next_request_id(&self) -> String {
        let seq = self.request_seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        format!("reentry-{}", seq)
    }
    fn transport_type(&self) -> &'static str {
        "inbound-reentry"
    }
    fn dispatch_raw<'a>(
        &'a self,
        request_id: String,
        frame: Vec<u8>,
    ) -> DispatchFuture<'a> {
        Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            {
                let mut p = self.pending.lock().unwrap();
                p.insert(request_id.clone(), tx);
            }

            // Push the outbound EXECUTE frame onto the accept loop's serial
            // writer channel. The accept-side read loop will route the
            // matching EXECUTE_RESPONSE back into `pending`.
            if self.writer_tx.send(frame).is_err() {
                self.pending.lock().unwrap().remove(&request_id);
                return Err(PeerError::ConnectionError(
                    "reentry: accept-side writer channel closed".to_string(),
                ));
            }

            match request_timeout(DEFAULT_REQUEST_TIMEOUT, rx).await {
                Ok(Ok(r)) => Ok(r),
                Ok(Err(_)) => {
                    self.pending.lock().unwrap().remove(&request_id);
                    Err(PeerError::ConnectionError(
                        "reentry: connection closed before response".to_string(),
                    ))
                }
                Err(_) => {
                    self.pending.lock().unwrap().remove(&request_id);
                    Err(PeerError::ConnectionError(format!(
                        "reentry request {} timed out after {:?}",
                        request_id, DEFAULT_REQUEST_TIMEOUT
                    )))
                }
            }
        })
    }
}

/// Connection pool for outbound connections, keyed by peer_id.
///
/// Pool holds `Arc<dyn RemoteEndpoint>` so it can store both
/// `RemoteConnection` (stream-multiplexed: TCP/WS/Memory/MessagePort)
/// and `HttpConnection` (POST-per-request) under one map (R1 — the
/// Go-style polymorphic remote-pool refactor).
///
/// `inbound` is a separate registry of [`InboundReentryEndpoint`]s for
/// accepted connections (§6.11(b)). It is kept distinct from `conns` so
/// that an outbound dispatch to a peer that IS independently dialable still
/// prefers a fresh dial / pooled outbound connection; the inbound endpoint
/// is consulted only as a fallback when transport resolution misses.
pub struct RemoteState {
    conns: Mutex<HashMap<String, Arc<dyn RemoteEndpoint>>>,
    inbound: Mutex<HashMap<String, Arc<dyn RemoteEndpoint>>>,
}

impl Default for RemoteState {
    fn default() -> Self {
        Self {
            conns: Mutex::new(HashMap::new()),
            inbound: Mutex::new(HashMap::new()),
        }
    }
}

impl RemoteState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get an existing pooled endpoint, or None.
    pub fn get(&self, peer_id: &str) -> Option<Arc<dyn RemoteEndpoint>> {
        self.conns.lock().unwrap().get(peer_id).cloned()
    }

    /// Insert a `RemoteConnection` (stream transport) into the pool.
    /// Returns the existing entry if another task connected in the
    /// meantime (race resolution).
    pub fn insert(&self, peer_id: &str, conn: RemoteConnection) -> Arc<dyn RemoteEndpoint> {
        self.insert_endpoint(peer_id, Arc::new(conn))
    }

    /// Insert any `RemoteEndpoint` impl into the pool (used by HTTP
    /// outbound which produces an `HttpConnection` rather than a
    /// `RemoteConnection`).
    pub fn insert_endpoint(
        &self,
        peer_id: &str,
        endpoint: Arc<dyn RemoteEndpoint>,
    ) -> Arc<dyn RemoteEndpoint> {
        let mut conns = self.conns.lock().unwrap();
        if let Some(existing) = conns.get(peer_id) {
            return existing.clone();
        }
        conns.insert(peer_id.to_string(), endpoint.clone());
        endpoint
    }

    /// Remove an endpoint from the pool (e.g., on error). The dropped
    /// `Arc` may keep the endpoint alive for any in-flight callers;
    /// transport-specific resources (e.g., the stream's reader task)
    /// are released when the last `Arc` drops.
    pub fn remove(&self, peer_id: &str) {
        self.conns.lock().unwrap().remove(peer_id);
    }

    /// Register a bidirectional endpoint over an accepted (inbound)
    /// connection for §6.11(b) reentry, keyed by the dialer's peer_id.
    /// Distinct from the outbound `conns` pool — see [`RemoteState`].
    pub fn register_inbound(&self, peer_id: &str, endpoint: Arc<dyn RemoteEndpoint>) {
        self.inbound
            .lock()
            .unwrap()
            .insert(peer_id.to_string(), endpoint);
    }

    /// Look up a reentry endpoint for an accepted connection from `peer_id`.
    pub fn get_inbound(&self, peer_id: &str) -> Option<Arc<dyn RemoteEndpoint>> {
        self.inbound.lock().unwrap().get(peer_id).cloned()
    }

    /// Drop the reentry endpoint for `peer_id` (accept loop exited / closed),
    /// but only if the currently-registered endpoint IS `endpoint`.
    ///
    /// The identity check (`Arc::ptr_eq`) makes teardown safe when the same
    /// peer holds more than one inbound connection: a second connection
    /// overwrites the map entry via `register_inbound`, and when the first
    /// (older) connection later closes it MUST NOT clobber the second's live
    /// endpoint. Each connection removes only the endpoint it registered.
    pub fn remove_inbound(&self, peer_id: &str, endpoint: &Arc<dyn RemoteEndpoint>) {
        let mut map = self.inbound.lock().unwrap();
        if let Some(existing) = map.get(peer_id) {
            if Arc::ptr_eq(existing, endpoint) {
                map.remove(peer_id);
            }
        }
    }
}

/// Get or create a pooled connection to a remote peer.
///
/// Returns a mutex-guarded connection. The caller must lock it for the
/// duration of their request-response exchange.
///
/// On connection failure, the pool entry is NOT created.
/// On send/recv failure, the caller should call `pool.remove(peer_id)`.
#[allow(clippy::too_many_arguments)]
pub async fn get_or_connect(
    pool: &RemoteState,
    peer_id: &str,
    keypair: &IdentityKeypair,
    content_store: &dyn ContentStore,
    location_index: &dyn LocationIndex,
    local_peer_id: &str,
    connector: &dyn Connector,
    home_format: u8,
    reentry: Option<Arc<crate::PeerShared>>,
) -> Result<Arc<dyn RemoteEndpoint>, PeerError> {
    // Check pool first
    if let Some(conn) = pool.get(peer_id) {
        tracing::debug!(remote_peer = %peer_id, "reusing pooled connection");
        return Ok(conn);
    }

    // Resolve address and connect.
    //
    // §6.11(b) reentry fallback: if this peer has no dialable transport
    // address (e.g. a validator / browser peer that dialed us but runs no
    // listener), reuse an accepted inbound connection from it — dispatch
    // back over the same socket. Consulted ONLY on resolution miss, so
    // peers that ARE independently dialable keep the normal dial path
    // (matches Go's "inbound fallback fires only when transport-profile
    // resolution misses" ruling).
    let addr = match resolve_transport_address(peer_id, content_store, location_index, local_peer_id)
    {
        Ok(a) => a,
        Err(e) => {
            if let Some(inbound) = pool.get_inbound(peer_id) {
                tracing::debug!(
                    remote_peer = %peer_id,
                    "reentry: no transport address; dispatching over accepted inbound connection"
                );
                return Ok(inbound);
            }
            return Err(e);
        }
    };

    tracing::debug!(remote_peer = %peer_id, addr = %addr, transport = connector.transport_type(), "connecting to remote peer");

    // R1 (PROPOSAL-TRANSPORT-FAMILY-LIVE-REACHABILITY §7.3): branch
    // by URL scheme. `http://` / `https://` use the request/response
    // HttpConnection path (POST per EXECUTE, X-Entity-Session
    // correlation); everything else (`tcp://` / `ws://` / `wss://` /
    // `memory://` / `xworker://` / future schemes the user wired
    // through MultiConnector) goes through the stream-transport
    // Connector + perform_connect.
    #[cfg(all(feature = "http-live", not(target_arch = "wasm32")))]
    {
        if addr.starts_with("http://") || addr.starts_with("https://") {
            let http = crate::http_connection::HttpConnection::connect(&addr, keypair, home_format)
                .await
                .map_err(|e| {
                    PeerError::ConnectionError(format!(
                        "http connect to {} at {}: {}",
                        peer_id, addr, e
                    ))
                })?;
            return Ok(pool.insert_endpoint(peer_id, Arc::new(http)));
        }
    }

    let transport_conn = connector.connect(&addr).await.map_err(|e| {
        PeerError::ConnectionError(format!("connect to {} at {}: {}", peer_id, addr, e))
    })?;

    let conn = perform_connect_with_dispatch(transport_conn, keypair, home_format, reentry)
        .await
        .map_err(|e| {
            PeerError::ConnectionError(format!("handshake with {}: {}", peer_id, e))
        })?;

    // R6 (PROPOSAL §9 rulings) — write the dialer-side
    // `held_capability` on `/{local_peer_id}/system/peer/session/
    // {remote_peer_id}`. Preserves any pre-existing
    // `minted_capability` from a prior inbound dial from this peer
    // (§9.1 R6-a — one entity per peer, two cap fields).
    write_held_session_entity(content_store, location_index, local_peer_id, &conn);

    // Insert into pool (handles race if another task connected simultaneously)
    Ok(pool.insert(peer_id, conn))
}

/// R6 dialer-side write: record the cap received from remote at handshake
/// as `held_capability` on the local session entity at
/// `/{local_peer_id}/system/peer/session/{remote_peer_id}`. Preserves
/// any pre-existing `minted_capability` (granter-side bookkeeping from
/// a prior inbound dial). Errors are logged + ignored — a failure
/// here forces the next dial to re-write, no correctness loss.
pub(crate) fn write_held_session_entity(
    content_store: &dyn ContentStore,
    location_index: &dyn LocationIndex,
    local_peer_id: &str,
    conn: &RemoteConnection,
) {
    // v7.64 §1.4: path-segment is hex of remote's `system/peer` content_hash.
    let path = format!(
        "/{}/{}",
        local_peer_id,
        crate::session_entity::PeerSession::relative_path(&conn.remote_identity_hash)
    );
    let now_ms = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // Decode the cap-token to extract expires_at; tolerate failure.
    let expires_at = entity_capability::CapabilityToken::from_entity(&conn.capability)
        .ok()
        .and_then(|t| t.expires_at);

    // Cap is handshake-minted root cap ⇒ chain length 1. Delegated
    // caps would walk back via `parent`; not in R6 minimum.
    let held = crate::session_entity::CapabilityRef {
        hash: conn.capability.content_hash,
        chain: vec![conn.capability.content_hash],
    };

    // R6-g: remote_public_key is optional. Try to extract from the
    // identity entity in auth_included; None if absent or undecodable.
    let remote_public_key = conn
        .auth_included
        .values()
        .find(|e| e.entity_type == entity_crypto::TYPE_PEER)
        .and_then(|peer_entity| extract_pubkey_from_peer_entity(peer_entity));

    // Read existing session entity (if any) and merge, preserving
    // any pre-existing minted_capability.
    let existing = location_index
        .get(&path)
        .and_then(|h| content_store.get(&h))
        .and_then(|e| crate::session_entity::PeerSession::from_entity(&e).ok());

    let session_to_write = match existing {
        Some(prior) => prior.with_held(held, now_ms),
        None => crate::session_entity::PeerSession::new_held(
            conn.remote_peer_id.clone(),
            conn.remote_identity_hash,
            remote_public_key,
            held,
            now_ms,
            expires_at,
        ),
    };

    // Persist cap entity + session entity. Tolerate put failure.
    if let Err(e) = content_store.put(conn.capability.clone()) {
        tracing::warn!(
            error = %e,
            "R6 dialer: content_store.put(cap_entity) failed; session entity will reference unresolvable hash"
        );
    }
    match content_store.put(session_to_write.to_entity()) {
        Ok(session_hash) => {
            location_index.set(&path, session_hash);
            tracing::debug!(
                path = %path,
                "R6 dialer: wrote held_capability to session entity"
            );
        }
        Err(e) => {
            tracing::warn!(
                path = %path,
                error = %e,
                "R6 dialer: content_store.put(session_entity) failed"
            );
        }
    }
}

/// Extract the 32-byte ed25519 public key from a `system/peer` identity
/// entity's CBOR `data` field. Returns None on any decode/shape error
/// (tolerated — `remote_public_key` is optional per R6-g).
fn extract_pubkey_from_peer_entity(entity: &Entity) -> Option<Vec<u8>> {
    let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).ok()?;
    let map = match value {
        ciborium::Value::Map(m) => m,
        _ => return None,
    };
    map.into_iter().find_map(|(k, v)| match (k, v) {
        (ciborium::Value::Text(s), ciborium::Value::Bytes(b)) if s == "public_key" => Some(b),
        _ => None,
    })
}

/// Reserved profile-id that takes precedence in the D1 selection rule.
/// A peer publishing more than one profile of the same transport-type
/// uses this id for the canonical / preferred entry.
pub const PROFILE_ID_PRIMARY: &str = "primary";

/// Recommended profile-id for the canonical HTTP profile when a peer
/// also publishes a TCP `primary` profile (PROPOSAL-TRANSPORT-FAMILY-
/// LIVE-REACHABILITY §7.3 G1). Publishing both TCP and HTTP under the
/// same `primary` profile-id silently overwrites the first
/// (location-index `set` replaces the hash at that path) — the
/// "mix and match" target peer becomes single-transport. Conventional
/// avoidance: TCP uses `primary` (carries D1 precedence as before);
/// HTTP uses `primary-http`. Operators publishing multiple HTTP
/// endpoints continue with their own profile-ids (`cdn-mirror`, etc.).
pub const PROFILE_ID_PRIMARY_HTTP: &str = "primary-http";

/// Derive a remote peer's `{peer_id_hex}` — the lowercase hex of its
/// `system/peer` entity content_hash, used as the path segment for
/// `system/peer/transport/{peer_id_hex}/...` and `system/peer/session/...`
/// (V7 §1.4 v7.64).
///
/// Identity-multihash-form PeerIDs (`hash_type = 0x00`, e.g. canonical
/// Ed25519) recover the public key from the PID itself and compute the
/// hash locally — zero lookup. SHA-256-form PeerIDs (`hash_type = 0x01`,
/// the canonical form for Ed448 and any key exceeding the v7.65 §4
/// substrate floor) cannot recover the public key from the digest alone;
/// the hash is instead read from the cached `system/peer/session/{hex}`
/// entity written at handshake, which records `remote_peer_id` (Base58)
/// → `remote_identity_hash`. Returns `None` only when neither path
/// resolves (identity-form derivation impossible AND no cached session).
///
/// This is the outbound-dial analogue of the inbound `canonical_peer_id`
/// root-check fix (commit 1e1c817): both make the Ed448 SHA-256-form PID
/// resolvable against state the peer already holds.
pub(crate) fn resolve_peer_id_hex(
    peer_id: &str,
    content_store: &dyn ContentStore,
    location_index: &dyn LocationIndex,
    local_peer_id: &str,
) -> Option<String> {
    // Fast path: identity-form PIDs derive locally with no lookup.
    if let Some(hex) = entity_crypto::PeerId::from(peer_id).identity_hex_local() {
        return Some(hex);
    }
    // SHA-256-form, source 1: the cached session entity learned at
    // handshake. The session is keyed by the remote's identity-hash hex,
    // so we scan the local session slot and match the stored Base58
    // `remote_peer_id`. Available once a connection has been established.
    let session_prefix = format!("/{}/system/peer/session/", local_peer_id);
    for entry in location_index.list(&session_prefix) {
        let Some(entity) = content_store.get(&entry.hash) else {
            continue;
        };
        let Ok(session) = crate::session_entity::PeerSession::from_entity(&entity) else {
            continue;
        };
        if session.remote_peer_id == peer_id {
            return Some(session.remote_identity_hash.to_hex());
        }
    }

    // SHA-256-form, source 2: a published transport profile. Profiles are
    // self-describing — the entity embeds the remote's Base58 `peer_id`
    // and lives at `.../transport/{peer_id_hex}/{profile-id}`. This is the
    // path that fires on a *first* outbound dispatch (continuation rexec /
    // forward), where no session exists yet but the dispatching peer was
    // handed the remote's transport profile (EXTENSION-NETWORK §6.5). Match
    // on the embedded `peer_id`, then recover `{peer_id_hex}` from the path.
    let transport_prefix = format!("/{}/system/peer/transport/", local_peer_id);
    for entry in location_index.list(&transport_prefix) {
        let Some(entity) = content_store.get(&entry.hash) else {
            continue;
        };
        let profile_peer_id = match entity.entity_type.as_str() {
            crate::transport_profile::TYPE_PEER_TRANSPORT_TCP => {
                crate::transport_profile::TcpProfileData::from_entity(&entity)
                    .ok()
                    .map(|p| p.peer_id)
            }
            crate::transport_profile::TYPE_PEER_TRANSPORT_HTTP => {
                crate::transport_profile::HttpProfileData::from_entity(&entity)
                    .ok()
                    .map(|p| p.peer_id)
            }
            _ => None,
        };
        if profile_peer_id.as_deref() == Some(peer_id) {
            // `entry.path` is `/{local}/system/peer/transport/{hex}/{id}`.
            // The hex is the first segment after `transport_prefix`.
            if let Some(rest) = entry.path.strip_prefix(&transport_prefix) {
                if let Some(hex) = rest.split('/').next() {
                    if !hex.is_empty() {
                        return Some(hex.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Resolve a peer's transport address from the tree.
///
/// **Wire shape (EXTENSION-NETWORK §6.5, v1.4 Amendment 2).** Profile
/// entities live at `system/peer/transport/{peer_id}/{profile-id}` —
/// the path carries an extra per-peer profile identifier (`primary`,
/// `cdn-mirror`, etc.) so a peer MAY advertise multiple profiles of
/// the same type (e.g., redundant tcp endpoints). The entity TYPE is
/// the transport name (`system/peer/transport/tcp` per §6.5.2a) and
/// the entity DATA is the full §4.1 profile shape.
///
/// **Selection algorithm (D1 — transport-family Chunk C
/// amendments §1.1).** Deterministic ordered candidate list:
/// 1. The reserved profile-id `primary` first, if present.
/// 2. Then the remaining live profiles **sorted lexicographically by
///    profile-id**.
/// Try each in order; return the first profile whose `endpoint.url` is
/// non-empty and decodes cleanly. `advertised_at` is **NOT** a selection
/// key (D3 — wall-clock, skew-prone). Malformed siblings logged into
/// diagnostics but do NOT abort the walk.
///
/// **Supported live-transport profiles (Chunk C + D).** Both
/// `system/peer/transport/tcp` and `system/peer/transport/http` profiles
/// are decoded; their shared `endpoint.url` shape (D4) is returned with
/// its scheme prefix (`tcp://`, `https://`, etc.). The outbound
/// connector dispatcher (MultiConnector) routes by scheme.
///
/// **Legacy flat shape retired (Chunk C, BREAKING).** The pre-Amendment-2
/// shape `system/peer/transport/{peer_id}` with `{address}` field is
/// no longer accepted; callers that wrote the flat shape MUST republish
/// as `system/peer/transport/tcp` profiles per §6.5.2a.
pub fn resolve_transport_address(
    peer_id: &str,
    content_store: &dyn ContentStore,
    location_index: &dyn LocationIndex,
    local_peer_id: &str,
) -> Result<String, PeerError> {
    // v7.64 §1.4: path-segment is `{peer_id_hex}` (hex of remote's
    // `system/peer` content_hash), not Base58. Identity-form PIDs derive
    // locally; SHA-256-form (the canonical form for Ed448 and other keys
    // exceeding the v7.65 §4 substrate floor) recovers the hex from the
    // cached session entity written at handshake (v7.67 Phase 2).
    let peer_hex = resolve_peer_id_hex(peer_id, content_store, location_index, local_peer_id)
        .ok_or_else(|| {
            PeerError::ConnectionError(format!(
                "cannot derive {{peer_id_hex}} for PeerID {} (identity-form derivation failed and no cached system/peer/session entity found)",
                peer_id
            ))
        })?;
    let prefix = format!("/{}/system/peer/transport/{}/", local_peer_id, peer_hex);
    let entries = location_index.list(&prefix);
    if entries.is_empty() {
        return Err(PeerError::ConnectionError(format!(
            "no transport profile for peer {} (checked prefix {})",
            peer_id, prefix
        )));
    }

    // D1 (Q1 ratified §8.9) — selection by
    // `(effective_priority asc, profile-id lex)`. Effective priority:
    //   - explicit `priority` on the profile entity wins (DNS-SRV
    //     semantics, lower = more preferred).
    //   - profile-id "primary" with no explicit priority defaults to
    //     `0` (preserves the pre-Q1 primary-first convention).
    //   - any other profile-id with no explicit priority defaults to
    //     `100` (spec default).
    // Reading `priority` requires materializing each entity, so we
    // build a `(priority, profile_id, entry)` triple eagerly. Profile
    // entities are tiny; in practice the candidate list is ≤5 for any
    // peer, so this is cheap. Entries whose entity can't be fetched
    // from the store are treated as low-priority fallbacks via the
    // default; the inner loop's decode will then surface them as
    // diagnostics.
    let mut triples: Vec<(u32, &str, &entity_store::LocationEntry)> = Vec::with_capacity(entries.len());
    for e in entries.iter() {
        let profile_id = profile_id_from_path(&e.path, &prefix);
        let explicit_priority = content_store
            .get(&e.hash)
            .and_then(|ent| extract_priority_from_entity(&ent));
        let effective = explicit_priority.unwrap_or_else(|| {
            if profile_id == PROFILE_ID_PRIMARY { 0 } else { 100 }
        });
        triples.push((effective, profile_id, e));
    }
    triples.sort_by(|a, b| match a.0.cmp(&b.0) {
        std::cmp::Ordering::Equal => a.1.cmp(b.1),
        ord => ord,
    });
    let ordered: Vec<&entity_store::LocationEntry> =
        triples.into_iter().map(|(_, _, e)| e).collect();

    let mut diagnostics: Vec<String> = Vec::new();
    for entry in ordered {
        let entity = match content_store.get(&entry.hash) {
            Some(e) => e,
            None => {
                diagnostics.push(format!("{}: entity not in store", entry.path));
                continue;
            }
        };
        // Accept both tcp (§6.5.2a) and http (§6.5.2c) live profiles —
        // the endpoint.url shape is shared (D4 — `{url: "scheme://..."}`),
        // so we extract the URL uniformly and hand it to the outbound
        // dispatcher which routes by scheme (tcp://, ws://, wss://,
        // http://, https://) via MultiConnector.
        let endpoint_url = match entity.entity_type.as_str() {
            crate::transport_profile::TYPE_PEER_TRANSPORT_TCP => {
                match crate::transport_profile::TcpProfileData::from_entity(&entity) {
                    Ok(profile) => profile.endpoint_url,
                    Err(e) => {
                        diagnostics.push(format!("{}: tcp decode failed: {}", entry.path, e));
                        continue;
                    }
                }
            }
            crate::transport_profile::TYPE_PEER_TRANSPORT_HTTP => {
                match crate::transport_profile::HttpProfileData::from_entity(&entity) {
                    Ok(profile) => profile.endpoint_url,
                    Err(e) => {
                        diagnostics.push(format!("{}: http decode failed: {}", entry.path, e));
                        continue;
                    }
                }
            }
            other => {
                diagnostics.push(format!(
                    "{}: entity_type {} not a supported live profile",
                    entry.path, other
                ));
                continue;
            }
        };
        if endpoint_url.is_empty() {
            diagnostics.push(format!("{}: empty endpoint.url", entry.path));
            continue;
        }
        return Ok(endpoint_url);
    }

    Err(PeerError::ConnectionError(format!(
        "no usable live profile for peer {} (tried {} profile entries: {})",
        peer_id,
        entries.len(),
        diagnostics.join("; ")
    )))
}

/// Read the optional `priority` field from a transport profile
/// entity's CBOR map without committing to a specific profile-type
/// decoder. Returns `None` on absence, wrong-type, or any decode
/// error — same Gap-A tolerance posture as `advertised_at`.
fn extract_priority_from_entity(entity: &entity_entity::Entity) -> Option<u32> {
    let v: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).ok()?;
    let map = match v {
        ciborium::Value::Map(m) => m,
        _ => return None,
    };
    for (k, val) in &map {
        if k.as_text() == Some("priority") {
            if let ciborium::Value::Integer(i) = val {
                return u32::try_from(*i).ok();
            }
            return None;
        }
    }
    None
}

/// Extract the profile-id from a transport profile binding path.
///
/// Per arch ruling §8.4: **profile-id is the final path
/// segment**, independent of whether the location-index layer presents
/// relative or absolute paths. We do two things to land on that:
///
/// 1. Strip the per-peer prefix when it matches (the common case —
///    `list(prefix)` returns paths that start with `prefix`, so this
///    always strips for well-formed entries).
/// 2. From whatever tail remains, take everything after the final
///    `/`. This makes nested-segment paths (`mirror/east`) and
///    relative paths (`primary` with no leading slash) both resolve
///    to the same id; it also makes the result invariant against
///    the Go-side prefix-trim class bug (`PRIMER-ENTITY-MODEL.md`
///    path-double-qualify family) — there's nothing for a stale
///    prefix to misalign against once we're operating on the tail.
///
/// Returns the empty string only if `path` itself is empty.
fn profile_id_from_path<'a>(path: &'a str, prefix: &str) -> &'a str {
    let tail = path.strip_prefix(prefix).unwrap_or(path);
    match tail.rfind('/') {
        Some(idx) => &tail[idx + 1..],
        None => tail,
    }
}

/// Perform client-side handshake: send hello, receive hello response,
/// send authenticate, receive authenticate response with capability grant.
///
/// Returns the RemoteConnection ready for sending EXECUTE messages.
pub async fn perform_connect(
    conn: crate::transport::Connection,
    keypair: &IdentityKeypair,
    home_format: u8,
) -> Result<RemoteConnection, PeerError> {
    perform_connect_with_dispatch(conn, keypair, home_format, None).await
}

/// As [`perform_connect`], but with an optional dialer-side §6.11(b) reentry
/// dispatch context. When `reentry` is `Some(shared)`, the reader task
/// dispatches inbound EXECUTE *requests* (deliveries the remote pushes back
/// over the connection we dialed, because we run no listener it could dial)
/// through `shared`'s handler stack and writes the EXECUTE_RESPONSE back over
/// this connection. `None` keeps the response-only reader (relay forwarder,
/// tests, and any caller with no local dispatch stack) — inbound EXECUTEs are
/// dropped with a warning, the pre-fix behavior.
pub async fn perform_connect_with_dispatch(
    conn: crate::transport::Connection,
    keypair: &IdentityKeypair,
    home_format: u8,
    reentry: Option<Arc<crate::PeerShared>>,
) -> Result<RemoteConnection, PeerError> {
    let (mut reader, mut writer) = (conn.reader, conn.writer);

    // --- Phase 1: Send our hello EXECUTE ---
    let mut nonce = vec![0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);

    // §4.5: advertise our negotiation surface (preference-ordered formats
    // from our home format; full key_type accept-set).
    let local_hash_formats = entity_protocol::default_advertised_hash_formats(home_format);
    let hello = entity_protocol::HelloData {
        peer_id: keypair.peer_id().to_string(),
        nonce: nonce.clone(),
        protocols: vec!["entity-core/1.0".to_string()],
        hash_formats: local_hash_formats.clone(),
        key_types: entity_protocol::default_advertised_key_types(),
        timestamp: None,
    };
    let hello_entity = hello
        .to_entity()
        .map_err(|e| PeerError::ConnectionError(format!("build hello: {}", e)))?;
    let hello_execute = entity_protocol::build_connect_execute("connect-hello", "hello", &hello_entity)
        .map_err(|e| PeerError::ConnectionError(format!("build hello execute: {}", e)))?;
    let hello_envelope = Envelope::new(hello_execute);

    let frame = encode_envelope(&hello_envelope);
    write_frame(&mut writer, &frame)
        .await
        .map_err(|e| PeerError::ConnectionError(format!("send hello: {}", e)))?;

    tracing::debug!("outbound: sent hello");

    // --- Phase 2: Receive hello EXECUTE_RESPONSE ---
    let resp_frame = read_frame(&mut reader, DEFAULT_MAX_FRAME_SIZE)
        .await
        .map_err(|e| PeerError::ConnectionError(format!("read hello response: {}", e)))?;
    let resp_envelope = decode_envelope(&resp_frame)
        .map_err(|e| PeerError::ConnectionError(format!("decode hello response: {}", e)))?;

    // Parse the hello response to get remote nonce
    let resp = entity_protocol::parse_execute_response(&resp_envelope)
        .map_err(|e| PeerError::ConnectionError(format!("parse hello response: {}", e)))?;

    if resp.status != 200 {
        return Err(PeerError::ConnectionError(format!(
            "hello response status: {}",
            resp.status
        )));
    }

    // Extract remote nonce and peer_id from the hello result entity
    let remote_hello = entity_protocol::HelloData::from_entity(&resp.result)
        .map_err(|e| PeerError::ConnectionError(format!("parse remote hello: {}", e)))?;

    // §4.5 initiator-side negotiation: derive the connection's active
    // `content_hash_format` from the responder's advertised set, using our
    // own preference order (converges on the value the responder computed).
    // Empty intersection → the responder shares no format we support.
    let active_format = entity_protocol::negotiate_active_format(
        &local_hash_formats,
        &remote_hello.hash_formats,
    )
    .ok_or_else(|| {
        PeerError::ConnectionError("no common content_hash_format with remote peer".into())
    })?;

    let remote_nonce = remote_hello.nonce;
    let remote_peer_id = remote_hello.peer_id;

    tracing::debug!(
        remote_peer = %remote_peer_id,
        active_format,
        "outbound: received hello response; negotiated active content_hash_format"
    );

    // --- Phase 3: Send authenticate EXECUTE (authored under §4.5a active format) ---
    let auth_envelope =
        entity_protocol::build_authenticate_envelope(keypair, &remote_nonce, active_format)
            .map_err(|e| PeerError::ConnectionError(format!("build authenticate: {}", e)))?;
    let auth_frame = encode_envelope(&auth_envelope);
    write_frame(&mut writer, &auth_frame)
        .await
        .map_err(|e| PeerError::ConnectionError(format!("send authenticate: {}", e)))?;

    tracing::debug!("outbound: sent authenticate");

    // --- Phase 4: Receive authenticate EXECUTE_RESPONSE ---
    let auth_resp_frame = read_frame(&mut reader, DEFAULT_MAX_FRAME_SIZE)
        .await
        .map_err(|e| PeerError::ConnectionError(format!("read auth response: {}", e)))?;
    let auth_resp_envelope = decode_envelope(&auth_resp_frame)
        .map_err(|e| PeerError::ConnectionError(format!("decode auth response: {}", e)))?;

    let auth_resp = entity_protocol::parse_execute_response(&auth_resp_envelope)
        .map_err(|e| PeerError::ConnectionError(format!("parse auth response: {}", e)))?;

    if auth_resp.status != 200 {
        return Err(PeerError::ConnectionError(format!(
            "authenticate response status: {}",
            auth_resp.status
        )));
    }

    // Extract capability token hash from the grant result
    let grant_data: ciborium::Value = ciborium::from_reader(auth_resp.result.data.as_slice())
        .map_err(|e| PeerError::ConnectionError(format!("decode grant: {}", e)))?;
    let grant_map = grant_data
        .as_map()
        .ok_or_else(|| PeerError::ConnectionError("grant data not a map".into()))?;

    let mut cap_hash = None;
    for (k, v) in grant_map {
        if k.as_text() == Some("token") {
            if let Some(bytes) = v.as_bytes() {
                cap_hash = Hash::from_bytes(bytes).ok();
            }
        }
    }

    let cap_hash = cap_hash.ok_or_else(|| {
        PeerError::ConnectionError("no token hash in authenticate response grant".into())
    })?;

    // Find the capability token entity in included
    let capability = auth_resp_envelope
        .find_included(&cap_hash)
        .cloned()
        .ok_or_else(|| {
            PeerError::ConnectionError("capability token entity not in auth response included".into())
        })?;

    // Collect all included entities for chain verification on subsequent requests
    let auth_included: HashMap<Hash, Entity> = auth_resp_envelope
        .included
        .iter()
        .map(|(h, e)| (*h, e.clone()))
        .collect();

    // Extract remote peer's identity hash from the capability token's granter field,
    // or find the system/peer entity in included.
    let remote_identity_hash = auth_included
        .values()
        .find(|e| e.entity_type == entity_crypto::TYPE_PEER)
        .map(|e| e.content_hash)
        .unwrap_or(Hash::zero());

    tracing::info!(remote_peer = %remote_peer_id, "outbound: handshake complete");

    // Spawn the reader task — it owns the read half from here on,
    // demuxing inbound frames into per-request oneshot channels.
    // The connection's `Drop` aborts this task; explicit pool removal
    // also drops the `Arc`, which (when no callers hold the conn)
    // triggers the same path.
    let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
    let writer = Arc::new(tokio::sync::Mutex::new(writer));
    // §6.11(b) dialer-side reentry: hand the reader a write handle + dispatch
    // context so it can answer inbound EXECUTEs over this same connection.
    let reentry_ctx = reentry.map(|shared| (shared, writer.clone()));
    let reader_task =
        spawn_reader_loop(reader, pending.clone(), remote_peer_id.clone(), reentry_ctx);

    Ok(RemoteConnection {
        writer,
        pending,
        capability,
        auth_included,
        remote_peer_id,
        remote_identity_hash,
        request_seq: AtomicU64::new(0),
        reader_task,
    })
}

/// Reader task body. Loops reading frames off the connection's read half,
/// decoding them as EXECUTE_RESPONSE, and routing each response to the
/// awaiting caller via its `request_id` oneshot. Frames that don't match
/// a pending entry are logged + dropped.
///
/// Exits on first read error or decode failure — terminating the task
/// drops the `Pending` map's senders, so all in-flight callers' awaits
/// resolve with `RecvError` (translated to a connection error).
#[allow(clippy::type_complexity)]
fn spawn_reader_loop(
    mut reader: Box<dyn AsyncRead + Unpin + Send>,
    pending: Pending,
    remote_peer_id: String,
    reentry: Option<(
        Arc<crate::PeerShared>,
        Arc<tokio::sync::Mutex<Box<dyn AsyncWrite + Unpin + Send>>>,
    )>,
) -> ReaderTaskHandle {
    spawn_reader_task(async move {
        loop {
            let frame = match read_frame(&mut reader, DEFAULT_MAX_FRAME_SIZE).await {
                Ok(f) => f,
                Err(e) => {
                    tracing::debug!(
                        remote_peer = %remote_peer_id,
                        error = %e,
                        "reader: read_frame failed, terminating reader task"
                    );
                    break;
                }
            };
            let envelope = match decode_envelope(&frame) {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(
                        remote_peer = %remote_peer_id,
                        error = %e,
                        "reader: decode_envelope failed, terminating reader task"
                    );
                    break;
                }
            };
            // §6.11(b) dialer-side reentry: an inbound EXECUTE (not a
            // RESPONSE) on the connection WE dialed is a delivery the remote
            // is pushing back to us — a subscription notification, a
            // continuation join, etc. — because we run no listener it could
            // dial independently. Dispatch it through our handler stack and
            // write the EXECUTE_RESPONSE back over this same write half. The
            // accept-side loop already does the symmetric thing (it routes
            // inbound EXECUTE_RESPONSEs to its reentry demux); without this,
            // a Rust peer acting as a no-listener subscriber silently drops
            // every reentry delivery.
            if envelope.root.entity_type != entity_types::TYPE_EXECUTE_RESPONSE {
                match &reentry {
                    Some((shared, writer)) => {
                        let shared = shared.clone();
                        let writer = writer.clone();
                        let peer = remote_peer_id.clone();
                        // Spawn so the reader keeps draining: the dispatched
                        // handler may itself send a request back over THIS
                        // connection and await its response on this very
                        // reader (mirrors the accept loop's spawned dispatch).
                        crate::runtime::spawn(async move {
                            let response = crate::connection::dispatch_request(
                                &envelope,
                                shared,
                                Some(peer.as_str()),
                            )
                            .await;
                            let resp_frame = encode_envelope(&response);
                            let mut w = writer.lock().await;
                            if let Err(e) = write_frame(&mut *w, &resp_frame).await {
                                tracing::debug!(
                                    remote_peer = %peer,
                                    error = %e,
                                    "reentry: failed to write EXECUTE_RESPONSE over dialed connection"
                                );
                            }
                        });
                    }
                    None => {
                        tracing::warn!(
                            remote_peer = %remote_peer_id,
                            "reader: inbound EXECUTE with no reentry dispatch context — dropped"
                        );
                    }
                }
                continue;
            }
            let resp = match entity_protocol::parse_execute_response(&envelope) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        remote_peer = %remote_peer_id,
                        error = %e,
                        "reader: parse_execute_response failed, dropping frame"
                    );
                    continue;
                }
            };
            let request_id = resp.request_id.clone();
            // Pop the pending entry and deliver. `lock().unwrap()` is fine —
            // never held across await.
            let sender = pending.lock().unwrap().remove(&request_id);
            match sender {
                Some(tx) => {
                    // The receiver may have been dropped (e.g., timeout
                    // raced ahead of the response). Best-effort send.
                    let _ = tx.send(resp);
                }
                None => {
                    tracing::warn!(
                        remote_peer = %remote_peer_id,
                        request_id = %request_id,
                        "reader: response with no pending entry — dropped (likely timed-out caller)"
                    );
                }
            }
        }
        // On exit, drop the pending senders so any remaining awaiters
        // resolve immediately with a connection-broken error.
        let mut p = pending.lock().unwrap();
        p.clear();
    })
}

/// Build an authenticated EXECUTE envelope for sending to a remote peer.
///
/// Per spec §5.2: author + capability + signature in the envelope.
/// When `deliver_to_params` is provided, includes deliver_to + deliver_token
/// on the EXECUTE per CONTINUATION §3.5 + INBOX §4.5.
///
/// `capability` is the **effective** EXECUTE capability — for an ordinary
/// internal/remote dispatch it is the connection grant; for a cross-peer
/// continuation dispatch the caller passes the continuation's scoped
/// `dispatch_capability` instead (EXTENSION-CONTINUATION §3.6 step 5 / §4.2
/// case 3 — the cap MUST NOT silently fall back to the connection grant,
/// V7 §6.8). `extra_included` carries the **full authority chain** of that
/// cap (EXTENSION-CONTINUATION §4.3 chain transport: the general V7
/// §3.1/§3.2 rule places only the leaf cap; the transitive parent/granter
/// chain is referenced from *within* the cap entities and MUST be bundled
/// explicitly). Empty `extra_included` + connection `capability` is
/// byte-identical to the pre-G2 behavior — every existing caller is
/// unaffected.
#[allow(clippy::too_many_arguments)]
pub fn build_authenticated_execute(
    keypair: &IdentityKeypair,
    capability: &Entity,
    auth_included: &HashMap<Hash, Entity>,
    extra_included: &HashMap<Hash, Entity>,
    request_id: &str,
    uri: &str,
    operation: &str,
    params: &Entity,
    resource: Option<&entity_capability::ResourceTarget>,
    deliver_to_params: Option<&DeliverToParams>,
) -> Result<Envelope, PeerError> {
    let identity = keypair
        .peer_entity()
        .map_err(|e| PeerError::ConnectionError(format!("build identity: {}", e)))?;

    // Build EXECUTE data
    let mut fields = vec![
        (entity_ecf::text("author"), entity_ecf::Value::Bytes(identity.content_hash.to_bytes().to_vec())),
        (entity_ecf::text("capability"), entity_ecf::Value::Bytes(capability.content_hash.to_bytes().to_vec())),
        (entity_ecf::text("operation"), entity_ecf::text(operation)),
        (entity_ecf::text("request_id"), entity_ecf::text(request_id)),
        (entity_ecf::text("uri"), entity_ecf::text(uri)),
    ];

    if let Some(rt) = resource {
        let targets_arr: Vec<entity_ecf::Value> = rt.targets.iter().map(entity_ecf::text).collect();
        let mut resource_fields = vec![(
            entity_ecf::text("targets"),
            entity_ecf::Value::Array(targets_arr),
        )];
        if !rt.exclude.is_empty() {
            let exclude_arr: Vec<entity_ecf::Value> = rt.exclude.iter().map(entity_ecf::text).collect();
            resource_fields.push((
                entity_ecf::text("exclude"),
                entity_ecf::Value::Array(exclude_arr),
            ));
        }
        fields.push((
            entity_ecf::text("resource"),
            entity_ecf::Value::Map(resource_fields),
        ));
    }

    // Build params as inline entity map (matching wire format §3.4)
    let params_data_val: entity_ecf::Value =
        ciborium::from_reader(params.data.as_slice())
            .unwrap_or(entity_ecf::Value::Null);
    let params_entity_val = entity_ecf::Value::Map(vec![
        (entity_ecf::text("content_hash"), entity_ecf::Value::Bytes(params.content_hash.to_bytes().to_vec())),
        (entity_ecf::text("data"), params_data_val),
        (entity_ecf::text("type"), entity_ecf::text(&params.entity_type)),
    ]);
    fields.push((entity_ecf::text("params"), params_entity_val));

    // Include deliver_to + deliver_token per CONTINUATION §3.5 step 4
    if let Some(dt) = deliver_to_params {
        fields.push((
            entity_ecf::text("deliver_to"),
            entity_ecf::Value::Map(vec![
                (entity_ecf::text("operation"), entity_ecf::text(&dt.deliver_to_operation)),
                (entity_ecf::text("uri"), entity_ecf::text(&dt.deliver_to_uri)),
            ]),
        ));
        fields.push((
            entity_ecf::text("deliver_token"),
            entity_ecf::Value::Bytes(dt.deliver_token.content_hash.to_bytes().to_vec()),
        ));
    }

    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
    let execute = Entity::new(entity_types::TYPE_EXECUTE, data)
        .map_err(|e| PeerError::ConnectionError(format!("build execute: {}", e)))?;

    // Sign the EXECUTE entity
    let sig_bytes = keypair.sign(&execute.content_hash.to_bytes());
    let sig_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (entity_ecf::text("algorithm"), entity_ecf::text(keypair.key_type().label())),
        (entity_ecf::text("signature"), entity_ecf::Value::Bytes(sig_bytes)),
        (entity_ecf::text("signer"), entity_ecf::Value::Bytes(identity.content_hash.to_bytes().to_vec())),
        (entity_ecf::text("target"), entity_ecf::Value::Bytes(execute.content_hash.to_bytes().to_vec())),
    ]));
    let sig_entity = Entity::new(entity_entity::TYPE_SIGNATURE, sig_data)
        .map_err(|e| PeerError::ConnectionError(format!("build signature: {}", e)))?;

    // Build envelope
    let mut envelope = Envelope::new(execute);
    envelope.include(identity);
    envelope.include(capability.clone());
    envelope.include(sig_entity);

    // Include auth chain entities (granter identity, capability signatures, etc.)
    for (h, ent) in auth_included {
        if envelope.find_included(h).is_none() {
            envelope.include(ent.clone());
        }
    }

    // EXTENSION-CONTINUATION §4.3 chain transport: bundle the full authority
    // chain of the (scoped) EXECUTE capability — parent/granter caps, granter
    // identities, and the per-link bound signatures — so the verifying peer
    // can validate the chain to a root it recognizes. Over-inclusion is free
    // (content-addressed dedup); empty for ordinary connection-grant dispatch.
    for (h, ent) in extra_included {
        if envelope.find_included(h).is_none() {
            envelope.include(ent.clone());
        }
    }

    // Include deliver_token entities for async delivery chain verification
    if let Some(dt) = deliver_to_params {
        envelope.include(dt.deliver_token.clone());
        envelope.include(dt.deliver_token_sig.clone());
        // Include the granter identity (already in envelope as our identity,
        // but ensure it's there for chain verification)
        if envelope.find_included(&dt.local_identity.content_hash).is_none() {
            envelope.include(dt.local_identity.clone());
        }
    }

    Ok(envelope)
}

/// Send an authenticated EXECUTE to a remote peer over an established connection.
///
/// Returns the parsed response.
///
/// **Concurrency (Class G / F-WB28, Option A — multiplexed transport).**
/// Multiple `send_execute` calls on the same `RemoteConnection` proceed
/// concurrently per V7 §6.x transport-reentry contract: each gets a
/// unique `request_id`; the writer mutex is held only across the brief
/// `write_frame`; the response is awaited via a per-request oneshot
/// channel that the reader task delivers into.
///
/// `dispatch_cap`, when `Some`, is the scoped capability that authorizes
/// *this* EXECUTE (a continuation's `dispatch_capability`); it replaces the
/// connection grant as the EXECUTE capability and MUST NOT fall back to it
/// (EXTENSION-CONTINUATION §3.6 step 5 / §4.2 case 3; V7 §6.8). `chain_bundle`
/// is its full authority chain for envelope transport (§4.3). `None` + empty
/// bundle ⇒ ordinary connection-grant dispatch, unchanged.
#[allow(clippy::too_many_arguments)]
pub async fn send_execute(
    conn: &dyn RemoteEndpoint,
    keypair: &IdentityKeypair,
    uri: &str,
    operation: &str,
    params: &Entity,
    resource: Option<&entity_capability::ResourceTarget>,
    deliver_to_params: Option<&DeliverToParams>,
    dispatch_cap: Option<&Entity>,
    chain_bundle: &HashMap<Hash, Entity>,
) -> Result<entity_protocol::ParsedResponse, PeerError> {
    let request_id = conn.next_request_id();

    // §3.6 step 5: the dispatched EXECUTE's capability is the continuation's
    // scoped dispatch_capability when present — never a silent fallback to
    // the broad connection grant (V7 §6.8). Ordinary dispatches pass None.
    let effective_cap = dispatch_cap.unwrap_or_else(|| conn.capability());

    let envelope = build_authenticated_execute(
        keypair,
        effective_cap,
        conn.auth_included(),
        chain_bundle,
        &request_id,
        uri,
        operation,
        params,
        resource,
        deliver_to_params,
    )?;

    tracing::debug!(
        remote_peer = %conn.remote_peer_id(),
        request_id = %request_id,
        uri = %uri,
        operation = %operation,
        transport = conn.transport_type(),
        "remote: sending EXECUTE"
    );

    let resp = conn.dispatch_envelope(request_id.clone(), envelope).await?;

    tracing::debug!(
        remote_peer = %conn.remote_peer_id(),
        request_id = %request_id,
        status = resp.status,
        "remote: received response"
    );

    Ok(resp)
}

/// Parameters for including deliver_to on an outbound EXECUTE.
pub struct DeliverToParams {
    /// The deliver_to delivery spec URI.
    pub deliver_to_uri: String,
    /// The deliver_to operation (default "receive").
    pub deliver_to_operation: String,
    /// The deliver_token capability entity (included in envelope).
    pub deliver_token: Entity,
    /// Signature for the deliver_token (included in envelope).
    pub deliver_token_sig: Entity,
    /// Local identity entity as granter (included in envelope).
    pub local_identity: Entity,
}

/// Generate a deliver_token per INBOX §5.1 + CONTINUATION §3.5 step 4.
///
/// Creates a scoped capability token authorizing the remote peer to deliver
/// to the specified inbox URI. The token is signed by the local keypair.
///
/// Per INBOX §5.1:
///   - handlers: system/inbox
///   - resources: the inbox URI
///   - operations: receive
///   - grantee: remote peer identity
///   - delegation_caveats: no_delegation (§5.2)
pub fn generate_deliver_token(
    keypair: &IdentityKeypair,
    remote_identity_hash: Hash,
    deliver_to_uri: &str,
    deliver_to_operation: &str,
) -> Result<DeliverToParams, PeerError> {
    let identity = keypair
        .peer_entity()
        .map_err(|e| PeerError::ConnectionError(format!("build identity: {}", e)))?;

    let now_ms = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let token = entity_capability::CapabilityToken {
        grants: vec![entity_capability::GrantEntry {
            handlers: entity_capability::PathScope::new(
                vec!["system/inbox".to_string(), "system/inbox/*".to_string()],
            ),
            operations: entity_capability::IdScope::new(
                vec!["receive".to_string()],
            ),
            resources: entity_capability::PathScope::new(
                vec![deliver_to_uri.to_string()],
            ),
            peers: Some(entity_capability::IdScope::new(
                vec!["*".to_string()],
            )),
            constraints: None,
            allowances: None,
        }],
        granter: entity_capability::Granter::Single(identity.content_hash),
        grantee: remote_identity_hash,
        parent: None,
        created_at: now_ms,
        expires_at: None,
        not_before: None,
        delegation_caveats: Some(entity_capability::DelegationCaveats {
            max_delegation_depth: Some(0), // no delegation per INBOX §5.2
            max_delegation_ttl: None,
            no_delegation: Some(true),
        }),
    };

    let token_entity = token
        .to_entity()
        .map_err(|e| PeerError::ConnectionError(format!("build deliver token: {}", e)))?;

    // Sign the token
    let sig_bytes = keypair.sign(&token_entity.content_hash.to_bytes());
    let sig_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (entity_ecf::text("algorithm"), entity_ecf::text(keypair.key_type().label())),
        (entity_ecf::text("signature"), entity_ecf::Value::Bytes(sig_bytes)),
        (entity_ecf::text("signer"), entity_ecf::Value::Bytes(identity.content_hash.to_bytes().to_vec())),
        (entity_ecf::text("target"), entity_ecf::Value::Bytes(token_entity.content_hash.to_bytes().to_vec())),
    ]));
    let sig_entity = Entity::new(entity_entity::TYPE_SIGNATURE, sig_data)
        .map_err(|e| PeerError::ConnectionError(format!("build token sig: {}", e)))?;

    Ok(DeliverToParams {
        deliver_to_uri: deliver_to_uri.to_string(),
        deliver_to_operation: deliver_to_operation.to_string(),
        deliver_token: token_entity,
        deliver_token_sig: sig_entity,
        local_identity: identity,
    })
}

/// Check if a URI targets a remote peer (different from local_peer_id).
pub fn is_remote_uri(uri: &str, local_peer_id: &str) -> bool {
    // Extract peer_id from URI
    let path = EntityUri::extract_handler_path(uri);
    // Strip leading slash if present
    let path = path.strip_prefix('/').unwrap_or(path);
    if EntityUri::is_peer_id(path) {
        return false; // bare peer_id, not a path
    }
    // Check if the first segment is a peer_id and differs from ours
    if let Some(slash_pos) = path.find('/') {
        let first_segment = &path[..slash_pos];
        if EntityUri::is_peer_id(first_segment) && first_segment != local_peer_id {
            return true;
        }
    }
    // Check entity:// URI format
    if uri.starts_with("entity://") {
        if let Ok(parsed) = entity_entity::EntityUri::parse(uri) {
            if !parsed.peer_id.is_empty() && parsed.peer_id != local_peer_id {
                return true;
            }
        }
    }
    false
}

/// Extract the peer_id from a URI that targets a remote peer.
pub fn extract_peer_id_from_uri(uri: &str) -> Option<String> {
    // Try entity:// format first
    if uri.starts_with("entity://") {
        if let Ok(parsed) = entity_entity::EntityUri::parse(uri) {
            if !parsed.peer_id.is_empty() {
                return Some(parsed.peer_id);
            }
        }
    }
    // Try qualified path: /{peer_id}/rest/of/path or {peer_id}/rest/of/path
    let path = EntityUri::extract_handler_path(uri);
    let path = path.strip_prefix('/').unwrap_or(path);
    if let Some(slash_pos) = path.find('/') {
        let first_segment = &path[..slash_pos];
        if EntityUri::is_peer_id(first_segment) {
            return Some(first_segment.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_crypto::Keypair;
    use crate::transport_profile::TcpProfileData;
    use entity_store::{MemoryContentStore, MemoryLocationIndex};

    fn test_peer_id() -> String {
        entity_crypto::Keypair::from_seed([42u8; 32]).peer_id().to_string()
    }

    /// v7.64 §1.4: convert a Base58 PeerID (identity-form) to its
    /// `{peer_id_hex}` form — the lowercase hex of the peer's `system/peer`
    /// entity content_hash. All test peers are identity-form by default.
    fn b58_to_hex(b58: &str) -> String {
        entity_crypto::PeerId::from(b58)
            .identity_hex_local()
            .expect("test peers are identity-form; derive_public_key must succeed")
    }

    fn write_tcp_profile_at(
        content_store: &MemoryContentStore,
        location_index: &MemoryLocationIndex,
        path: &str,
        profile: &TcpProfileData,
    ) {
        let entity = profile.to_entity();
        let hash = content_store.put(entity).expect("put profile entity");
        location_index.set(path, hash);
    }

    // ---------- resolve_transport_address (Chunk C — §6.5 shape) ----------

    #[test]
    fn resolve_returns_endpoint_url_from_tcp_profile() {
        let local = test_peer_id();
        let remote = entity_crypto::Keypair::from_seed([99u8; 32])
            .peer_id()
            .to_string();
        let store = MemoryContentStore::default();
        let index = MemoryLocationIndex::default();

        let profile =
            TcpProfileData::for_local_listener(&remote, "tcp://127.0.0.1:4040", 1_000);
        write_tcp_profile_at(
            &store,
            &index,
            &format!("/{}/system/peer/transport/{}/primary", local, b58_to_hex(&remote)),
            &profile,
        );

        let addr = resolve_transport_address(&remote, &store, &index, &local)
            .expect("resolve succeeds");
        assert_eq!(addr, "tcp://127.0.0.1:4040");
    }

    /// v7.67 Phase 2 outbound gap: an Ed448 remote's canonical PeerID is
    /// SHA-256-form, so `identity_hex_local()` returns None and the
    /// `{peer_id_hex}` can't be derived from the PID alone. The hex must
    /// be recovered from the cached `system/peer/session/{hex}` entity
    /// written at handshake (maps Base58 peer_id → identity hash). Before
    /// the fix, `resolve_transport_address` errored out here and the
    /// outbound EXECUTE never left — the real root cause of the rs-48
    /// cross-peer matrix failures (verify_request was never reached).
    #[test]
    fn resolve_sha256_form_ed448_peer_via_session_cache() {
        let local = test_peer_id();
        let ed448 = entity_crypto::Ed448Keypair::from_seed(&[55u8; 57]).unwrap();
        let remote_b58 = ed448.peer_id().to_string();
        let remote_hash = ed448.peer_identity_hash();
        let remote_hex = remote_hash.to_hex();
        let store = MemoryContentStore::default();
        let index = MemoryLocationIndex::default();

        // SHA-256-form: cannot derive {peer_id_hex} from the PID alone.
        assert!(
            entity_crypto::PeerId::from(remote_b58.as_str())
                .identity_hex_local()
                .is_none(),
            "Ed448 canonical PID is SHA-256-form"
        );

        // Session entity cached at handshake: Base58 peer_id → identity hash.
        let session = crate::session_entity::PeerSession::new_minted(
            remote_b58.clone(),
            remote_hash,
            Some(ed448.public_key_bytes().to_vec()),
            crate::session_entity::CapabilityRef {
                hash: remote_hash,
                chain: vec![remote_hash],
            },
            0,
            None,
        );
        let session_path = format!("/{}/{}", local, session.path_for());
        let sh = store.put(session.to_entity()).unwrap();
        index.set(&session_path, sh);

        // Transport profile stored under the canonical identity hex.
        let profile =
            TcpProfileData::for_local_listener(&remote_b58, "tcp://127.0.0.1:9999", 1_000);
        write_tcp_profile_at(
            &store,
            &index,
            &format!("/{}/system/peer/transport/{}/primary", local, remote_hex),
            &profile,
        );

        let addr = resolve_transport_address(&remote_b58, &store, &index, &local)
            .expect("resolve must succeed for SHA-256-form Ed448 peer via session cache");
        assert_eq!(addr, "tcp://127.0.0.1:9999");
    }

    /// The first-dispatch case: a continuation rexec/forward dials a
    /// SHA-256-form (Ed448) peer the dispatcher has NEVER handshaked, so
    /// there is no session entity — only the published transport profile.
    /// The profile self-describes (`peer_id` field + `{hex}` path segment),
    /// which is what makes the outbound dial resolvable. This is the exact
    /// shape that fails the cross-peer convergence `rexec_delivered` gate.
    #[test]
    fn resolve_sha256_form_ed448_peer_via_profile_only_no_session() {
        let local = test_peer_id();
        let ed448 = entity_crypto::Ed448Keypair::from_seed(&[66u8; 57]).unwrap();
        let remote_b58 = ed448.peer_id().to_string();
        let remote_hex = ed448.peer_identity_hash().to_hex();
        let store = MemoryContentStore::default();
        let index = MemoryLocationIndex::default();

        assert!(entity_crypto::PeerId::from(remote_b58.as_str())
            .identity_hex_local()
            .is_none());

        // ONLY a transport profile — no session entity at all.
        let profile =
            TcpProfileData::for_local_listener(&remote_b58, "tcp://127.0.0.1:8888", 1_000);
        write_tcp_profile_at(
            &store,
            &index,
            &format!("/{}/system/peer/transport/{}/primary", local, remote_hex),
            &profile,
        );

        let addr = resolve_transport_address(&remote_b58, &store, &index, &local)
            .expect("resolve must succeed via self-describing transport profile");
        assert_eq!(addr, "tcp://127.0.0.1:8888");
    }

    #[test]
    fn resolve_walks_multiple_profile_ids_until_usable() {
        // Multiple profile-ids under the same peer-id slot. v1 picks
        // the first usable tcp profile encountered. Confirms the walk
        // tolerates non-tcp / malformed siblings without aborting.
        let local = test_peer_id();
        let remote = entity_crypto::Keypair::from_seed([77u8; 32])
            .peer_id()
            .to_string();
        let store = MemoryContentStore::default();
        let index = MemoryLocationIndex::default();

        // Sibling slot 1: malformed (missing endpoint field). Should be
        // skipped, NOT abort the walk.
        let bad_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("peer_id"),
            entity_ecf::text(&remote),
        )]));
        let bad_entity = Entity::new(
            crate::transport_profile::TYPE_PEER_TRANSPORT_TCP,
            bad_data,
        )
        .unwrap();
        let bad_hash = store.put(bad_entity).unwrap();
        index.set(
            &format!("/{}/system/peer/transport/{}/broken", local, b58_to_hex(&remote)),
            bad_hash,
        );

        // Sibling slot 2: a real, usable profile.
        let profile =
            TcpProfileData::for_local_listener(&remote, "tcp://10.0.0.5:9000", 5_000);
        write_tcp_profile_at(
            &store,
            &index,
            &format!("/{}/system/peer/transport/{}/secondary", local, b58_to_hex(&remote)),
            &profile,
        );

        let addr = resolve_transport_address(&remote, &store, &index, &local)
            .expect("resolve picks the usable profile");
        assert_eq!(addr, "tcp://10.0.0.5:9000");
    }

    #[test]
    fn resolve_errors_when_no_profile_published() {
        let local = test_peer_id();
        let remote = entity_crypto::Keypair::from_seed([55u8; 32])
            .peer_id()
            .to_string();
        let store = MemoryContentStore::default();
        let index = MemoryLocationIndex::default();

        let err = resolve_transport_address(&remote, &store, &index, &local)
            .expect_err("empty prefix → error");
        let msg = format!("{}", err);
        assert!(
            msg.contains("no transport profile"),
            "msg should explain empty prefix; got: {}",
            msg
        );
        assert!(msg.contains(&remote));
    }

    #[test]
    fn resolve_rejects_legacy_flat_shape() {
        // Chunk C is BREAKING: a legacy flat-shape entity bound at the
        // old path `system/peer/transport/{peer_id}` (NOT the new
        // per-peer subpath) must NOT be picked up by the new resolver.
        let local = test_peer_id();
        let remote = entity_crypto::Keypair::from_seed([33u8; 32])
            .peer_id()
            .to_string();
        let store = MemoryContentStore::default();
        let index = MemoryLocationIndex::default();

        let flat_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("address"),
            entity_ecf::text("127.0.0.1:4040"),
        )]));
        let flat_entity = Entity::new(
            crate::transport_profile::TYPE_PEER_TRANSPORT_TCP,
            flat_data,
        )
        .unwrap();
        let flat_hash = store.put(flat_entity).unwrap();
        // Legacy path was `/{local}/system/peer/transport/{remote}`
        // (no trailing /<profile-id>). New prefix `…/{remote}/` MUST
        // miss this entirely — no migration cruft.
        index.set(
            &format!("/{}/system/peer/transport/{}", local, b58_to_hex(&remote)),
            flat_hash,
        );

        let err = resolve_transport_address(&remote, &store, &index, &local)
            .expect_err("legacy flat path must not resolve");
        assert!(format!("{}", err).contains("no transport profile"));
    }

    // ---------- Chunk D: http profile resolution ----------

    #[test]
    fn resolve_returns_endpoint_url_from_http_profile() {
        // Chunk D: resolve also accepts system/peer/transport/http
        // profiles; returns the https:// URL with scheme prefix.
        let local = test_peer_id();
        let remote = entity_crypto::Keypair::from_seed([110u8; 32])
            .peer_id()
            .to_string();
        let store = MemoryContentStore::default();
        let index = MemoryLocationIndex::default();

        let profile = crate::transport_profile::HttpProfileData::for_local_listener(
            &remote,
            "https://my-peer.example/entity",
            1_000,
        );
        let entity = profile.to_entity();
        let hash = store.put(entity).expect("put http profile");
        index.set(
            &format!("/{}/system/peer/transport/{}/primary", local, b58_to_hex(&remote)),
            hash,
        );

        let addr = resolve_transport_address(&remote, &store, &index, &local)
            .expect("http profile resolves");
        assert_eq!(addr, "https://my-peer.example/entity");
    }

    #[test]
    fn resolve_picks_primary_across_tcp_and_http() {
        // Mixed profile types under the same peer: `primary` MUST win
        // regardless of transport type. Confirms D1 selection rule
        // composes correctly across the heterogeneous candidate set.
        let local = test_peer_id();
        let remote = entity_crypto::Keypair::from_seed([111u8; 32])
            .peer_id()
            .to_string();
        let store = MemoryContentStore::default();
        let index = MemoryLocationIndex::default();

        // tcp at "alpha" (sorts before "primary" lex)
        let tcp = TcpProfileData::for_local_listener(&remote, "tcp://alpha:1111", 1_000);
        write_tcp_profile_at(
            &store,
            &index,
            &format!("/{}/system/peer/transport/{}/alpha", local, b58_to_hex(&remote)),
            &tcp,
        );

        // http at "primary" — should be picked first per D1.
        let http = crate::transport_profile::HttpProfileData::for_local_listener(
            &remote,
            "https://example.com/entity",
            2_000,
        );
        let hash = store.put(http.to_entity()).unwrap();
        index.set(
            &format!("/{}/system/peer/transport/{}/primary", local, b58_to_hex(&remote)),
            hash,
        );

        let addr = resolve_transport_address(&remote, &store, &index, &local)
            .expect("resolve succeeds");
        assert_eq!(addr, "https://example.com/entity");
    }

    // ---------- D1 selection-rule tests (primary first, then lex) ----------

    #[test]
    fn resolve_picks_primary_profile_first() {
        // D1: when a `primary` profile is present alongside other
        // siblings, it MUST be tried first. Sibling profile-ids that
        // would sort before `primary` lexicographically MUST NOT win.
        let local = test_peer_id();
        let remote = entity_crypto::Keypair::from_seed([100u8; 32])
            .peer_id()
            .to_string();
        let store = MemoryContentStore::default();
        let index = MemoryLocationIndex::default();

        // "alpha" sorts before "primary" lexicographically — proves
        // the rule isn't just "first lexicographically."
        let alpha =
            TcpProfileData::for_local_listener(&remote, "tcp://alpha:1111", 1_000);
        write_tcp_profile_at(
            &store,
            &index,
            &format!("/{}/system/peer/transport/{}/alpha", local, b58_to_hex(&remote)),
            &alpha,
        );

        let primary =
            TcpProfileData::for_local_listener(&remote, "tcp://primary:4040", 2_000);
        write_tcp_profile_at(
            &store,
            &index,
            &format!("/{}/system/peer/transport/{}/primary", local, b58_to_hex(&remote)),
            &primary,
        );

        let addr = resolve_transport_address(&remote, &store, &index, &local)
            .expect("resolve succeeds");
        assert_eq!(addr, "tcp://primary:4040", "primary MUST win over alpha");
    }

    #[test]
    fn resolve_lex_orders_when_no_primary() {
        // D1: with no `primary` profile, fall back to lexicographic
        // by profile-id. "alpha" beats "beta" beats "gamma".
        let local = test_peer_id();
        let remote = entity_crypto::Keypair::from_seed([101u8; 32])
            .peer_id()
            .to_string();
        let store = MemoryContentStore::default();
        let index = MemoryLocationIndex::default();

        // Insert in non-lex order to confirm sorting is happening.
        let gamma =
            TcpProfileData::for_local_listener(&remote, "tcp://gamma:3333", 3_000);
        write_tcp_profile_at(
            &store,
            &index,
            &format!("/{}/system/peer/transport/{}/gamma", local, b58_to_hex(&remote)),
            &gamma,
        );
        let alpha =
            TcpProfileData::for_local_listener(&remote, "tcp://alpha:1111", 1_000);
        write_tcp_profile_at(
            &store,
            &index,
            &format!("/{}/system/peer/transport/{}/alpha", local, b58_to_hex(&remote)),
            &alpha,
        );
        let beta =
            TcpProfileData::for_local_listener(&remote, "tcp://beta:2222", 2_000);
        write_tcp_profile_at(
            &store,
            &index,
            &format!("/{}/system/peer/transport/{}/beta", local, b58_to_hex(&remote)),
            &beta,
        );

        let addr = resolve_transport_address(&remote, &store, &index, &local)
            .expect("resolve succeeds");
        assert_eq!(addr, "tcp://alpha:1111", "alpha should beat beta+gamma");
    }

    #[test]
    fn resolve_falls_through_failed_primary_to_lex_order() {
        // D1: if `primary` is unusable (malformed), the walk falls
        // through to the next in lex order. Confirms ordering is a
        // CANDIDATE LIST, not single-pick.
        let local = test_peer_id();
        let remote = entity_crypto::Keypair::from_seed([102u8; 32])
            .peer_id()
            .to_string();
        let store = MemoryContentStore::default();
        let index = MemoryLocationIndex::default();

        // Primary is malformed (missing endpoint field) — won't decode.
        let bad_primary_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("peer_id"),
            entity_ecf::text(&remote),
        )]));
        let bad_primary = Entity::new(
            crate::transport_profile::TYPE_PEER_TRANSPORT_TCP,
            bad_primary_data,
        )
        .unwrap();
        let bad_hash = store.put(bad_primary).unwrap();
        index.set(
            &format!("/{}/system/peer/transport/{}/primary", local, b58_to_hex(&remote)),
            bad_hash,
        );

        // Secondary is usable.
        let secondary =
            TcpProfileData::for_local_listener(&remote, "tcp://backup:9999", 5_000);
        write_tcp_profile_at(
            &store,
            &index,
            &format!("/{}/system/peer/transport/{}/zzz-backup", local, b58_to_hex(&remote)),
            &secondary,
        );

        let addr = resolve_transport_address(&remote, &store, &index, &local)
            .expect("falls through primary to backup");
        assert_eq!(addr, "tcp://backup:9999");
    }

    // ---------- Q1 — explicit `priority` field (§8.9) ----------
    //
    // Selection rule: sort candidates by `(effective_priority asc,
    // profile_id lex)`. Effective priority:
    //   - explicit priority on profile entity wins,
    //   - profile-id "primary" with no explicit priority → 0,
    //   - any other profile-id with no explicit priority → 100.
    // Back-compat: existing single-`primary`-or-lex deployments behave
    // byte-for-byte identically (covered by earlier resolve_* tests).
    // What's new is gated below.

    /// Helper: build a TCP profile with an explicit priority value.
    fn tcp_profile_with_priority(
        remote: &str,
        url: &str,
        priority: Option<u32>,
    ) -> TcpProfileData {
        let mut p = TcpProfileData::for_local_listener(remote, url, 1_000);
        p.priority = priority;
        p
    }

    #[test]
    fn q1_explicit_priority_overrides_lex_order() {
        // Two profiles `alpha` and `beta`. With no priority, lex says
        // alpha wins. Set beta.priority = 50 (lower = preferred) and
        // beta MUST win — explicit priority is authoritative over the
        // profile-id lex fallback.
        let local = test_peer_id();
        let remote = entity_crypto::Keypair::from_seed([200u8; 32])
            .peer_id()
            .to_string();
        let store = MemoryContentStore::default();
        let index = MemoryLocationIndex::default();

        let alpha = tcp_profile_with_priority(&remote, "tcp://alpha:1111", None);
        write_tcp_profile_at(
            &store,
            &index,
            &format!("/{}/system/peer/transport/{}/alpha", local, b58_to_hex(&remote)),
            &alpha,
        );
        let beta = tcp_profile_with_priority(&remote, "tcp://beta:2222", Some(50));
        write_tcp_profile_at(
            &store,
            &index,
            &format!("/{}/system/peer/transport/{}/beta", local, b58_to_hex(&remote)),
            &beta,
        );

        let addr = resolve_transport_address(&remote, &store, &index, &local)
            .expect("resolve succeeds");
        assert_eq!(
            addr, "tcp://beta:2222",
            "Q1: explicit priority=50 MUST beat default-100 lex winner"
        );
    }

    #[test]
    fn q1_priority_ties_break_by_profile_id_lex() {
        // Two profiles both at priority=10. Lex tie-break: `aaa` <
        // `zzz`, so `aaa` wins.
        let local = test_peer_id();
        let remote = entity_crypto::Keypair::from_seed([201u8; 32])
            .peer_id()
            .to_string();
        let store = MemoryContentStore::default();
        let index = MemoryLocationIndex::default();

        let aaa = tcp_profile_with_priority(&remote, "tcp://aaa:1111", Some(10));
        write_tcp_profile_at(
            &store,
            &index,
            &format!("/{}/system/peer/transport/{}/aaa", local, b58_to_hex(&remote)),
            &aaa,
        );
        let zzz = tcp_profile_with_priority(&remote, "tcp://zzz:2222", Some(10));
        write_tcp_profile_at(
            &store,
            &index,
            &format!("/{}/system/peer/transport/{}/zzz", local, b58_to_hex(&remote)),
            &zzz,
        );

        let addr = resolve_transport_address(&remote, &store, &index, &local)
            .expect("resolve succeeds");
        assert_eq!(
            addr, "tcp://aaa:1111",
            "Q1: equal priorities MUST tie-break by profile-id lex"
        );
    }

    #[test]
    fn q1_primary_unset_priority_defaults_to_zero() {
        // The pre-Q1 "primary-first" convention is preserved by
        // defaulting unset-`primary` to priority=0. A non-primary
        // profile with no priority gets default=100 → primary wins.
        let local = test_peer_id();
        let remote = entity_crypto::Keypair::from_seed([202u8; 32])
            .peer_id()
            .to_string();
        let store = MemoryContentStore::default();
        let index = MemoryLocationIndex::default();

        let primary = tcp_profile_with_priority(&remote, "tcp://primary:4040", None);
        write_tcp_profile_at(
            &store,
            &index,
            &format!("/{}/system/peer/transport/{}/primary", local, b58_to_hex(&remote)),
            &primary,
        );
        let zeta = tcp_profile_with_priority(&remote, "tcp://zeta:9999", None);
        write_tcp_profile_at(
            &store,
            &index,
            &format!("/{}/system/peer/transport/{}/zeta", local, b58_to_hex(&remote)),
            &zeta,
        );

        let addr = resolve_transport_address(&remote, &store, &index, &local)
            .expect("resolve succeeds");
        assert_eq!(
            addr, "tcp://primary:4040",
            "Q1: unset `primary` defaults to priority 0, beats unset non-primary (100)"
        );
    }

    #[test]
    fn q1_explicit_priority_on_non_primary_beats_primary() {
        // A non-`primary` profile-id with an EXPLICIT lower priority
        // (e.g., 0 or any value < 0... well, 0 is the floor) beats
        // an unset `primary` (which defaults to 0 — so we need to
        // outrank it via a tie-break or explicitly outrank). Test the
        // case where unset-primary (0) ties with explicit 0 — then
        // lex tie-break decides. profile-id "aaaa" < "primary" lex,
        // so aaaa wins.
        let local = test_peer_id();
        let remote = entity_crypto::Keypair::from_seed([203u8; 32])
            .peer_id()
            .to_string();
        let store = MemoryContentStore::default();
        let index = MemoryLocationIndex::default();

        let primary = tcp_profile_with_priority(&remote, "tcp://primary:4040", None);
        write_tcp_profile_at(
            &store,
            &index,
            &format!("/{}/system/peer/transport/{}/primary", local, b58_to_hex(&remote)),
            &primary,
        );
        let aaaa = tcp_profile_with_priority(&remote, "tcp://aaaa:1111", Some(0));
        write_tcp_profile_at(
            &store,
            &index,
            &format!("/{}/system/peer/transport/{}/aaaa", local, b58_to_hex(&remote)),
            &aaaa,
        );

        let addr = resolve_transport_address(&remote, &store, &index, &local)
            .expect("resolve succeeds");
        assert_eq!(
            addr, "tcp://aaaa:1111",
            "Q1: explicit priority=0 + lex-before-primary wins the tie-break"
        );
    }

    /// Read the `capability` hash off the built EXECUTE envelope root.
    fn execute_capability_hash(env: &Envelope) -> Hash {
        let v: ciborium::Value =
            ciborium::from_reader(env.root.data.as_slice()).unwrap();
        for (k, val) in v.as_map().unwrap() {
            if k.as_text() == Some("capability") {
                return Hash::from_bytes(val.as_bytes().unwrap()).unwrap();
            }
        }
        panic!("EXECUTE has no capability field");
    }

    /// G2 (EXTENSION-CONTINUATION §3.6 step 5 / §4.2 case 3 / §4.3): when a
    /// scoped dispatch_capability is passed, the dispatched EXECUTE's
    /// `capability` MUST be that cap (never a silent fallback to the
    /// connection grant — V7 §6.8) and its full authority chain MUST travel
    /// in the envelope `included`. With the connection grant + empty bundle
    /// the wire shape is byte-for-byte the pre-G2 behavior.
    #[test]
    fn test_scoped_dispatch_cap_and_chain_transport() {
        let kp = IdentityKeypair::Ed25519(Keypair::generate());
        let conn_cap = Entity::new("system/capability", vec![0xC0]).unwrap();
        let dispatch_cap = Entity::new("system/capability", vec![0xD1]).unwrap();
        let parent_cap = Entity::new("system/capability", vec![0xD2]).unwrap();
        let granter_id = Entity::new(entity_crypto::TYPE_PEER, vec![0xAA]).unwrap();
        let cap_sig = Entity::new(entity_entity::TYPE_SIGNATURE, vec![0xBB]).unwrap();
        let params =
            Entity::new("primitive/any", entity_ecf::to_ecf(&entity_ecf::Value::Null)).unwrap();
        let auth: HashMap<Hash, Entity> = HashMap::new();

        // The bundle collect_chain_bundle would produce for the scoped cap.
        let chain: [&Entity; 4] = [&dispatch_cap, &parent_cap, &granter_id, &cap_sig];
        let mut bundle: HashMap<Hash, Entity> = HashMap::new();
        for e in chain {
            bundle.insert(e.content_hash, e.clone());
        }

        // (1) scoped cap + chain bundle.
        let env = build_authenticated_execute(
            &kp,
            &dispatch_cap,
            &auth,
            &bundle,
            "req-1",
            "entity://peerB/system/inbox",
            "receive",
            &params,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            execute_capability_hash(&env),
            dispatch_cap.content_hash,
            "EXECUTE capability MUST be the scoped dispatch_capability, \
             not the connection grant (§3.6 step 5, V7 §6.8)"
        );
        for e in chain {
            assert!(
                env.find_included(&e.content_hash).is_some(),
                "full authority chain MUST travel in envelope included (§4.3)"
            );
        }

        // (2) connection grant + empty bundle → unchanged.
        let empty: HashMap<Hash, Entity> = HashMap::new();
        let env2 = build_authenticated_execute(
            &kp,
            &conn_cap,
            &auth,
            &empty,
            "req-2",
            "entity://peerB/system/tree",
            "get",
            &params,
            None,
            None,
        )
        .unwrap();
        assert_eq!(execute_capability_hash(&env2), conn_cap.content_hash);
        assert!(env2.find_included(&parent_cap.content_hash).is_none());
        assert!(env2.find_included(&dispatch_cap.content_hash).is_none());
    }

    /// V7 §3.3 v7.51 — request-side envelope-`included` preservation.
    /// `build_authenticated_execute`'s `extra_included` parameter is the
    /// wire-shape carrier for forwarding a parent envelope's `included` map
    /// across a remote dispatch surface (the dispatch-side fix at
    /// `connection.rs` sub-dispatch-remote branch merges parent included
    /// entries into the bundle passed here). This test locks in the contract
    /// that arbitrary entries in `extra_included` arrive in `envelope.included`
    /// so the receiver-side handler / continuation can resolve them.
    #[test]
    fn test_build_authenticated_execute_forwards_parent_included() {
        let kp = IdentityKeypair::Ed25519(Keypair::generate());
        let conn_cap = Entity::new("system/capability", vec![0xC0]).unwrap();
        let params =
            Entity::new("primitive/any", entity_ecf::to_ecf(&entity_ecf::Value::Null)).unwrap();
        let auth: HashMap<Hash, Entity> = HashMap::new();

        // Simulate a parent envelope's `included`: one bundled application
        // entity (e.g. an `include_payload`-delivered changed entity) plus a
        // signature. Neither is a capability-chain entry — what we're locking
        // in is that arbitrary parent-included content survives the wire.
        let bundled_entity =
            Entity::new("app/mirror/payload", b"v7.51 round-trip carrier".to_vec()).unwrap();
        let bundled_sig =
            Entity::new(entity_entity::TYPE_SIGNATURE, vec![0x51, 0x51]).unwrap();
        let mut parent_included: HashMap<Hash, Entity> = HashMap::new();
        parent_included.insert(bundled_entity.content_hash, bundled_entity.clone());
        parent_included.insert(bundled_sig.content_hash, bundled_sig.clone());

        let env = build_authenticated_execute(
            &kp,
            &conn_cap,
            &auth,
            &parent_included,
            "req-included-fwd",
            "entity://peerB/system/tree",
            "put",
            &params,
            None,
            None,
        )
        .unwrap();

        assert!(
            env.find_included(&bundled_entity.content_hash).is_some(),
            "parent envelope's bundled application entity MUST survive forwarding (V7 §3.3 v7.51)"
        );
        assert!(
            env.find_included(&bundled_sig.content_hash).is_some(),
            "parent envelope's bundled signature MUST survive forwarding (V7 §3.3 v7.51)"
        );
    }

    fn other_peer_id() -> String {
        entity_crypto::Keypair::from_seed([99u8; 32]).peer_id().to_string()
    }

    #[test]
    fn test_is_remote_uri_absolute_local() {
        let local = test_peer_id();
        let path = format!("/{}/system/tree", local);
        assert!(!is_remote_uri(&path, &local));
    }

    #[test]
    fn test_is_remote_uri_absolute_remote() {
        let local = test_peer_id();
        let remote = other_peer_id();
        let path = format!("/{}/system/tree", remote);
        assert!(is_remote_uri(&path, &local));
    }

    #[test]
    fn test_is_remote_uri_entity_scheme() {
        let local = test_peer_id();
        let remote = other_peer_id();
        let uri = format!("entity://{}/system/tree", remote);
        assert!(is_remote_uri(&uri, &local));
    }

    #[test]
    fn test_is_remote_uri_bare_path() {
        let local = test_peer_id();
        // Bare path (no peer prefix) is local
        assert!(!is_remote_uri("system/tree", &local));
    }

    #[test]
    fn test_extract_peer_id_absolute() {
        let remote = other_peer_id();
        let path = format!("/{}/system/tree", remote);
        assert_eq!(extract_peer_id_from_uri(&path), Some(remote));
    }

    #[test]
    fn test_extract_peer_id_entity_scheme() {
        let remote = other_peer_id();
        let uri = format!("entity://{}/system/tree", remote);
        assert_eq!(extract_peer_id_from_uri(&uri), Some(remote));
    }

    #[test]
    fn test_extract_peer_id_bare_path() {
        assert_eq!(extract_peer_id_from_uri("system/tree"), None);
    }

    // ---------------------------------------------------------------------
    // F-WB28 / Class G pin tests (Stage 4 round 2)
    //
    // These exercise the multiplexed-transport contract laid out in the
    // PROPOSAL-STAGE-4-TRANSPORT-AND-OBSERVABILITY proposal §1.1:
    //
    //   - multiple in-flight EXECUTEs per pooled connection MUST proceed
    //     concurrently (point a)
    //   - response routing MUST tolerate out-of-order replies, demuxing
    //     by `request_id` (point b)
    //
    // Pre-fix shape (single-pending-per-pooled-connection + per-conn lock
    // held across send+recv) would either deadlock or serialize. Post-fix
    // (Option A: reader task + per-request oneshot demux) handles both
    // structurally.
    // ---------------------------------------------------------------------

    /// Build a `RemoteConnection` directly from a pair of duplex IO halves,
    /// bypassing the handshake. Pin-test-only — production code path is
    /// `perform_connect`.
    fn make_test_remote_connection(
        client_read: Box<dyn AsyncRead + Unpin + Send>,
        client_write: Box<dyn AsyncWrite + Unpin + Send>,
    ) -> RemoteConnection {
        // Use valid ECF (CBOR null) — single-byte invalid CBOR like vec![0xC0]
        // confuses the cbor_item_end recursion through the wire codec.
        let cap = Entity::new(
            "system/capability",
            entity_ecf::to_ecf(&entity_ecf::Value::Null),
        )
        .unwrap();
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let reader_task =
            spawn_reader_loop(client_read, pending.clone(), "memory:test".to_string(), None);
        RemoteConnection {
            writer: Arc::new(tokio::sync::Mutex::new(client_write)),
            pending,
            capability: cap,
            auth_included: HashMap::new(),
            remote_peer_id: "memory:test".to_string(),
            remote_identity_hash: Hash::zero(),
            request_seq: AtomicU64::new(0),
            reader_task,
        }
    }

    /// Run a fake server on the server end of the duplex pipe. Reads N
    /// inbound EXECUTE frames, then writes N EXECUTE_RESPONSE frames in
    /// **reverse order** of arrival — exercising the demux-by-request_id
    /// path (FIFO routing would lose this assertion).
    async fn fake_server_reverse_order(
        mut reader: tokio::io::ReadHalf<tokio::io::DuplexStream>,
        mut writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
        n: usize,
    ) {
        let mut request_ids: Vec<String> = Vec::with_capacity(n);
        for _ in 0..n {
            let frame = read_frame(&mut reader, DEFAULT_MAX_FRAME_SIZE).await.unwrap();
            let env = decode_envelope(&frame).unwrap();
            // Extract request_id from the EXECUTE root entity's data.
            let v: ciborium::Value = ciborium::from_reader(env.root.data.as_slice()).unwrap();
            let map = v.as_map().unwrap();
            let request_id = map
                .iter()
                .find(|(k, _)| k.as_text() == Some("request_id"))
                .and_then(|(_, val)| val.as_text())
                .unwrap()
                .to_string();
            request_ids.push(request_id);
        }
        // Respond in reverse order — the demux must still route each
        // response to the correct caller.
        for request_id in request_ids.into_iter().rev() {
            let result = Entity::new(
                "primitive/any",
                entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                    entity_ecf::text("echo"),
                    entity_ecf::text(&request_id),
                )])),
            )
            .unwrap();
            let env = entity_protocol::build_execute_response(&request_id, 200, result).unwrap();
            let frame = encode_envelope(&env);
            write_frame(&mut writer, &frame).await.unwrap();
        }
    }

    /// F-WB28 Class G pin test (point a + point b).
    ///
    /// Eight concurrent `send_execute` calls on the same `RemoteConnection`
    /// complete within a budget that's much smaller than the serialized
    /// cost would be. The fake server responds in **reverse order** of
    /// arrival, so a FIFO-routing transport would deliver every response
    /// to the wrong caller (or the first send_execute would hang).
    #[tokio::test]
    async fn test_concurrent_executes_are_multiplexed() {
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (server_read, server_write) = tokio::io::split(server_stream);

        let conn = Arc::new(make_test_remote_connection(
            Box::new(client_read),
            Box::new(client_write),
        ));

        const N: usize = 8;
        let server = tokio::spawn(fake_server_reverse_order(server_read, server_write, N));

        let kp = Arc::new(IdentityKeypair::Ed25519(Keypair::generate()));
        let params =
            Entity::new("primitive/any", entity_ecf::to_ecf(&entity_ecf::Value::Null)).unwrap();
        let no_chain: HashMap<Hash, Entity> = HashMap::new();

        // Spawn N concurrent send_execute calls.
        let mut handles = Vec::with_capacity(N);
        for _i in 0..N {
            let conn = conn.clone();
            let kp = kp.clone();
            let params = params.clone();
            let no_chain = no_chain.clone();
            handles.push(tokio::spawn(async move {
                send_execute(
                    conn.as_ref() as &dyn RemoteEndpoint,
                    &kp,
                    "entity://peerB/test/handler",
                    "noop",
                    &params,
                    None,
                    None,
                    None,
                    &no_chain,
                )
                .await
            }));
        }

        // Total wall-clock budget — well under the per-request 30s
        // default and well under N × any serialized cost.
        let budget = Duration::from_secs(5);
        let started = std::time::Instant::now();
        for h in handles {
            let res = tokio::time::timeout(budget, h).await.expect("F-WB28: \
                concurrent send_execute exceeded budget — multiplexing \
                is not in place (would be the deadlock symptom)");
            let send_res = res.expect("task panicked").expect("send_execute failed");
            assert_eq!(send_res.status, 200, "F-WB28: response status mismatch");
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed < budget,
            "F-WB28: total elapsed {:?} exceeded budget {:?}",
            elapsed, budget
        );

        server.await.unwrap();
    }

    /// Lighter sibling — N=2 in the exact bidirectional-symmetric shape
    /// workbench-go's WB-28 reproducer exercises (the canonical F-WB28
    /// deadlock window). Two concurrent dispatches on the same connection
    /// must both complete. Pre-fix this would deadlock; post-fix it
    /// completes well within budget.
    #[tokio::test]
    async fn test_reentrant_dispatch_does_not_deadlock() {
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (server_read, server_write) = tokio::io::split(server_stream);

        let conn = Arc::new(make_test_remote_connection(
            Box::new(client_read),
            Box::new(client_write),
        ));
        let server = tokio::spawn(fake_server_reverse_order(server_read, server_write, 2));

        let kp = Arc::new(IdentityKeypair::Ed25519(Keypair::generate()));
        let params =
            Entity::new("primitive/any", entity_ecf::to_ecf(&entity_ecf::Value::Null)).unwrap();
        let no_chain: HashMap<Hash, Entity> = HashMap::new();

        let h1 = {
            let conn = conn.clone();
            let kp = kp.clone();
            let params = params.clone();
            let no_chain = no_chain.clone();
            tokio::spawn(async move {
                send_execute(
                    conn.as_ref() as &dyn RemoteEndpoint,
                    &kp, "entity://peerB/h1", "op", &params, None, None, None, &no_chain,
                )
                .await
            })
        };
        let h2 = {
            let conn = conn.clone();
            let kp = kp.clone();
            let params = params.clone();
            let no_chain = no_chain.clone();
            tokio::spawn(async move {
                send_execute(
                    conn.as_ref() as &dyn RemoteEndpoint,
                    &kp, "entity://peerB/h2", "op", &params, None, None, None, &no_chain,
                )
                .await
            })
        };

        let budget = Duration::from_secs(3);
        let r1 = tokio::time::timeout(budget, h1)
            .await
            .expect("F-WB28: send 1 exceeded budget — deadlock");
        let r2 = tokio::time::timeout(budget, h2)
            .await
            .expect("F-WB28: send 2 exceeded budget — deadlock");
        assert_eq!(r1.unwrap().unwrap().status, 200);
        assert_eq!(r2.unwrap().unwrap().status, 200);

        server.await.unwrap();
    }
}
