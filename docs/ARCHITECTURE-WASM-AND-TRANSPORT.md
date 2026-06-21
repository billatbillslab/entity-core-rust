# Architecture: Transport Abstraction & WASM Peer

**Status:** Implemented — transport abstraction (TCP / WebSocket / HTTP) and the
wasm32 peer are in the tree; this is the durable design reference.
**Scope:** Transport-agnostic networking, WASM peer, entity-browser-rust integration path
**Depends:** ENTITY-CORE-PROTOCOL-V7.md (v7.9), EXTENSION-NETWORK.md

---

## 1. Problem Statement

entity-core-rust currently hardcodes TCP as its only transport. Three forces demand transport abstraction:

1. **Browser peers** — The entity-browser-rust Entity Browser needs to be a full peer, not a static data viewer. Browsers cannot use TCP. WebSocket is the only viable browser-to-server transport.

2. **Native WebSocket listener** — If browser peers connect via WebSocket, native/TCP peers must *accept* WebSocket connections. A TCP-only peer cannot serve browser clients.

3. **Protocol design** — The spec already anticipates this. Section 1.6: *"Other transports (QUIC, shared memory, etc.) define their own framing and limits."* Section 3.13 defines `system/transport` entities with protocol field accepting "tcp", "quic", "udp", "bluetooth". WebSocket is a natural addition to this list.

The goal is not to support every transport today — it's to introduce the abstraction boundary so that TCP, WebSocket, and future transports (QUIC, shared memory, WebRTC) share the same peer infrastructure.

---

## 2. Current State

### 2.1 Where TCP Lives

TCP is concentrated in 3 files in the peer crate:

| File | LOC | Responsibility | TCP Coupling |
|------|-----|---------------|-------------|
| `server.rs` | 41 | Bind + accept loop | `TcpListener`, `tokio::spawn` per connection |
| `connection.rs` | 1114 | Handshake + message loop + dispatch | `TcpStream` split into `ReadHalf`/`WriteHalf` |
| `remote.rs` | 642 | Outbound connections + connection pool | `TcpStream::connect()`, connection cache |

Everything else in the peer crate (PeerBuilder, handlers, dispatch, extensions) is transport-agnostic.

### 2.2 Wire Crate — Already Abstracted

The wire crate uses trait bounds, not concrete types:

```rust
pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, payload: &[u8]) -> Result<(), WireError>
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R, max_frame_size: u32) -> Result<Vec<u8>, WireError>
```

Any `AsyncRead`/`AsyncWrite` implementation works — TCP streams, WebSocket streams, in-memory pipes, test harnesses. **The wire codec needs no changes.**

### 2.3 Framing Differences

| Transport | Framing | Implication |
|-----------|---------|-------------|
| **TCP** | 4-byte big-endian length prefix + CBOR payload | `wire::read_frame`/`write_frame` implement this |
| **WebSocket** | Messages are already framed by the WebSocket protocol | Length prefix is redundant — could use bare CBOR payloads per WS message |
| **QUIC** | Stream-based (like TCP) or datagram-based | Stream mode: same as TCP. Datagram: per-message framing |
| **Shared memory** | Implementation-defined | Ring buffer, length-prefixed, etc. |

**Design decision needed:** Should WebSocket connections use the same 4-byte length-prefixed framing inside WS messages (simpler, reuses `read_frame`/`write_frame` unchanged), or should they use bare CBOR payloads per WS message (more efficient, eliminates redundant framing)? See §8.1.

### 2.4 tokio Dependencies Inventory

Six `tokio::spawn` call sites and the broadcast channel are the only runtime-specific code:

| Location | Usage | WASM Replacement |
|----------|-------|-----------------|
| `peer/lib.rs:332` | `broadcast::channel(256)` | **Works in WASM as-is** — `tokio::sync` is executor-independent |
| `server.rs:33` | `tokio::spawn` — accept loop | Not needed in browser (no inbound connections) |
| `connection.rs:459` | `tokio::spawn` — async delivery | `spawn_local()` on WASM |
| `inbox.rs:129` | `tokio::spawn` — advance continuation | `spawn_local()` on WASM |
| `subscription/engine.rs:161` | `tokio::spawn` — event loop | `spawn_local()` on WASM |
| `clock/engine.rs:64` | `tokio::spawn` — event loop | `spawn_local()` on WASM |
| `revision/engine.rs:40` | `tokio::spawn` — event loop | `spawn_local()` on WASM |

Additional: `tokio::sync::Mutex` in continuation (join locks) and revision (prefix locks) — **works in WASM as-is**.

---

## 3. Transport Abstraction Design

### 3.1 Core Traits

The abstraction splits into three concerns: reading, writing, and connection establishment.

```rust
// core/peer/src/transport.rs (new file)

use tokio::io::{AsyncRead, AsyncWrite};

/// A single connection's read half.
/// Wraps any transport that can deliver ordered bytes.
pub trait TransportRead: AsyncRead + Unpin + Send {}
impl<T: AsyncRead + Unpin + Send> TransportRead for T {}

/// A single connection's write half.
/// Wraps any transport that can accept ordered bytes.
pub trait TransportWrite: AsyncWrite + Unpin + Send {}
impl<T: AsyncWrite + Unpin + Send> TransportWrite for T {}

/// A connection accepted by a listener or established by a client.
pub struct Connection {
    pub reader: Box<dyn TransportRead>,
    pub writer: Box<dyn TransportWrite>,
    pub remote_addr: String,
    pub transport_type: &'static str,  // "tcp", "websocket", "quic", ...
}

/// Server-side: accepts inbound connections.
#[async_trait]
pub trait Listener: Send + Sync {
    /// Accept the next inbound connection.
    async fn accept(&self) -> Result<Connection, TransportError>;

    /// The local address this listener is bound to.
    fn local_addr(&self) -> String;

    /// Transport identifier (e.g., "tcp", "websocket").
    fn transport_type(&self) -> &'static str;
}

/// Client-side: establishes outbound connections.
#[async_trait]
pub trait Connector: Send + Sync {
    /// Connect to a remote peer at the given address.
    async fn connect(&self, addr: &str) -> Result<Connection, TransportError>;

    /// Transport identifier.
    fn transport_type(&self) -> &'static str;
}
```

### 3.2 Why AsyncRead/AsyncWrite (Not Message-Based)

The wire crate already uses `AsyncRead`/`AsyncWrite`. The length-prefixed framing in `read_frame`/`write_frame` works over any byte stream. Even WebSocket can be adapted to this interface — `ws_stream_wasm` and `tokio-tungstenite` both provide `AsyncRead`/`AsyncWrite` adapters over WebSocket connections.

This means **zero changes to the wire crate, connection handshake, or message dispatch**. The transport abstraction sits below the wire codec:

```
┌─────────────────────────────────────────────┐
│  Handler dispatch, auth, capability check    │  ← unchanged
├─────────────────────────────────────────────┤
│  Wire codec: read_frame / write_frame        │  ← unchanged (uses AsyncRead/Write)
├─────────────────────────────────────────────┤
│  Connection: handshake, message loop         │  ← change: accept Connection instead of TcpStream
├─────────────────────────────────────────────┤
│  Transport: Listener / Connector traits      │  ← NEW abstraction boundary
├──────────┬──────────┬───────────┬───────────┤
│   TCP    │ WebSocket│   QUIC    │  Memory   │  ← implementations
└──────────┴──────────┴───────────┴───────────┘
```

### 3.3 Transport Implementations

#### TCP (existing behavior, wrapped)

```rust
pub struct TcpTransport;

#[async_trait]
impl Listener for TcpListener {
    // wraps tokio::net::TcpListener::accept()
    // splits TcpStream into ReadHalf + WriteHalf
}

#[async_trait]
impl Connector for TcpTransport {
    // wraps TcpStream::connect()
}
```

#### WebSocket (new — both server and client)

**Server side** (native peer accepting browser connections):
```rust
pub struct WebSocketListener {
    inner: TcpListener,  // WS runs over TCP
    // or: tokio_tungstenite upgrade from HTTP
}

#[async_trait]
impl Listener for WebSocketListener {
    async fn accept(&self) -> Result<Connection, TransportError> {
        let (stream, addr) = self.inner.accept().await?;
        let ws_stream = tokio_tungstenite::accept_async(stream).await?;
        let (write, read) = ws_stream.split();
        // Adapt to AsyncRead/AsyncWrite via ws_stream's compat layer
        Ok(Connection { reader: Box::new(read), writer: Box::new(write), ... })
    }
}
```

**Client side — native** (connecting to another peer's WS endpoint):
```rust
pub struct WebSocketConnector;

#[async_trait]
impl Connector for WebSocketConnector {
    async fn connect(&self, addr: &str) -> Result<Connection, TransportError> {
        let (ws_stream, _) = tokio_tungstenite::connect_async(addr).await?;
        // ...
    }
}
```

**Client side — WASM** (browser connecting to native peer):
```rust
// Only compiled for wasm32
pub struct BrowserWebSocketConnector;

#[async_trait]
impl Connector for BrowserWebSocketConnector {
    async fn connect(&self, addr: &str) -> Result<Connection, TransportError> {
        let ws = ws_stream_wasm::WsMeta::connect(addr, None).await?;
        let (read, write) = ws.into_io().split();
        // ws_stream_wasm provides AsyncRead/AsyncWrite
        Ok(Connection { reader: Box::new(read), writer: Box::new(write), ... })
    }
}
```

#### In-Memory (for testing)

```rust
pub struct MemoryTransport {
    // Paired in-memory streams (tokio::io::duplex or similar)
}
```

Enables integration tests without networking — two peers connected via in-memory pipes.

### 3.4 Impact on Peer API

Current:
```rust
impl Peer {
    pub async fn listen(&self) -> Result<(TcpListener, SocketAddr), PeerError>;
    pub async fn run(&self, listener: TcpListener) -> Result<(), PeerError>;
}
```

Proposed:
```rust
impl Peer {
    /// Run the peer with the given listeners and connector.
    /// Accepts connections from all listeners concurrently.
    pub async fn run(
        &self,
        listeners: Vec<Box<dyn Listener>>,
        connector: Arc<dyn Connector>,
    ) -> Result<(), PeerError>;

    /// Convenience: run with TCP only (backwards compatible).
    pub async fn run_tcp(&self, addr: &str) -> Result<(), PeerError> {
        let tcp = TcpListenerImpl::bind(addr).await?;
        self.run(vec![Box::new(tcp)], Arc::new(TcpTransport)).await
    }

    /// Run with both TCP and WebSocket listeners.
    pub async fn run_multi(
        &self,
        tcp_addr: &str,
        ws_addr: &str,
    ) -> Result<(), PeerError> {
        let tcp = TcpListenerImpl::bind(tcp_addr).await?;
        let ws = WebSocketListener::bind(ws_addr).await?;
        self.run(
            vec![Box::new(tcp), Box::new(ws)],
            Arc::new(TcpTransport),
        ).await
    }

    /// Local-only peer (no networking). For WASM or embedded use.
    /// Only uses execute() for local handler dispatch.
    pub fn local_only(&self) -> Result<(), PeerError> {
        self.start_engines(&self.shared()?)?;
        Ok(())
    }
}
```

### 3.5 Impact on Remote Connections

`remote.rs` currently pools TCP connections. The refactored version pools `Connection` objects:

```rust
pub struct RemoteConnection {
    reader: Box<dyn TransportRead>,
    writer: Box<dyn TransportWrite>,
    pub capability: Entity,
    pub auth_included: HashMap<Hash, Entity>,
    pub remote_peer_id: String,
    pub remote_identity_hash: Hash,
    pub request_seq: u64,
}

pub struct RemoteState {
    conns: Mutex<HashMap<String, Arc<tokio::sync::Mutex<RemoteConnection>>>>,
    connector: Arc<dyn Connector>,
}
```

The `get_or_connect()` method uses the `Connector` trait instead of `TcpStream::connect()`.

### 3.6 Transport Resolution

When a peer needs to connect to a remote peer, it looks up the remote's transport address in the tree at `system/peer/transport/{peer_id}/{protocol}` (spec §3.13). The protocol field determines which `Connector` to use:

```rust
fn resolve_connector(protocol: &str, connectors: &HashMap<String, Arc<dyn Connector>>)
    -> Option<Arc<dyn Connector>>
{
    connectors.get(protocol).cloned()
}
```

A native peer would register connectors for both "tcp" and "websocket". A browser peer would register only "websocket".

---

## 4. WASM Peer Architecture

### 4.1 What Works in WASM Today (No Changes Needed)

| Component | Why It Works |
|-----------|-------------|
| All Tier 0 crates (ecf, hash, entity, crypto, types, store, capability) | Pure Rust, no platform deps |
| Handler trait + registry | `async-trait` only, no runtime |
| Wire codec (`read_frame`, `write_frame`) | Generic over `AsyncRead`/`AsyncWrite` |
| `tokio::sync::broadcast` | Executor-independent (tokio CI-tested on wasm32) |
| `tokio::sync::Mutex`, `mpsc`, `oneshot` | Executor-independent |
| `PeerBuilder::build()` | Only uses broadcast + std sync internally |
| `Peer::execute()` | Direct handler dispatch, no networking |
| All handlers (tree, connect, inbox, continuation, subscription, clock, revision) | `async-trait`, no runtime deps in handler logic |

### 4.2 What Needs a WASM Shim

#### Spawn Abstraction

```rust
// core/peer/src/runtime.rs (new file)

/// Spawn a future as a concurrent task.
/// On native: tokio::spawn (Send required).
/// On WASM: wasm_bindgen_futures::spawn_local (no Send required).
#[cfg(not(target_arch = "wasm32"))]
pub fn spawn<F>(future: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(future);
}

#[cfg(target_arch = "wasm32")]
pub fn spawn<F>(future: F)
where
    F: std::future::Future<Output = ()> + 'static,
{
    wasm_bindgen_futures::spawn_local(future);
}
```

**The `Send` bound difference:** `tokio::spawn` requires `Send` because it may run the future on any thread. `spawn_local` does not — WASM is single-threaded. This means futures that capture non-Send types (e.g., `Rc`, raw pointers) work in WASM but not native. For entity-core, all spawned futures currently capture `Arc` types, which are `Send`. No code changes needed beyond the shim.

**Call site changes:** Replace 6 `tokio::spawn(...)` calls with `runtime::spawn(...)`.

#### Timer Abstraction

Extension engines use timing for rate limits and expiry checks:

```rust
// core/peer/src/runtime.rs (addition)

/// Sleep for the given duration.
#[cfg(not(target_arch = "wasm32"))]
pub async fn sleep(duration: std::time::Duration) {
    tokio::time::sleep(duration).await;
}

#[cfg(target_arch = "wasm32")]
pub async fn sleep(duration: std::time::Duration) {
    gloo_timers::future::sleep(duration).await;
}

/// Get current timestamp in milliseconds.
#[cfg(not(target_arch = "wasm32"))]
pub fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[cfg(target_arch = "wasm32")]
pub fn now_millis() -> u64 {
    js_sys::Date::now() as u64
}
```

### 4.3 WASM Peer Lifecycle

A browser peer has a fundamentally different lifecycle than a native peer:

```
Native Peer:                         Browser Peer:
┌─────────────┐                     ┌─────────────┐
│ PeerBuilder  │                     │ PeerBuilder  │
│  .build()    │                     │  .build()    │
└──────┬───────┘                     └──────┬───────┘
       │                                    │
       ▼                                    ▼
┌──────────────┐                    ┌──────────────────┐
│ peer.run()   │                    │ peer.local_only() │
│  - TCP listen │                    │  - start engines  │
│  - WS listen  │                    │  - no listeners   │
│  - accept loop│                    └──────┬───────────┘
└──────────────┘                           │
                                           ▼
                                   ┌──────────────────┐
                                   │ peer.connect_to() │
                                   │  - WS to host     │
                                   │  - handshake      │
                                   │  - message loop   │
                                   └──────────────────┘
```

**Key difference:** Native peers listen and accept. Browser peers initiate outbound WebSocket connections only. A browser peer calls `peer.local_only()` to start engines, then `peer.connect_to(ws_url)` to establish a remote connection.

### 4.4 WASM Cargo Configuration

```toml
# core/peer/Cargo.toml additions

[dependencies]
tokio = { workspace = true, features = ["sync"] }  # sync always needed

[target.'cfg(not(target_arch = "wasm32"))'.dependencies]
tokio = { workspace = true, features = ["rt", "net", "time", "sync", "macros", "io-util"] }
tokio-tungstenite = "0.24"  # native WebSocket

[target.'cfg(target_arch = "wasm32")'.dependencies]
wasm-bindgen-futures = "0.4"
ws_stream_wasm = "0.7"      # browser WebSocket → AsyncRead/AsyncWrite
gloo-timers = "0.3"          # setTimeout-based sleep
js-sys = "0.3"               # Date.now() for timestamps

[features]
# Transport features
tcp = []            # TCP listener + connector (native only)
websocket = []      # WebSocket listener (native) + connector (native + WASM)
default = ["tcp", "websocket"]
```

### 4.5 Feature-Gated TCP

TCP-specific code compiles only on native:

```rust
// server.rs
#[cfg(not(target_arch = "wasm32"))]
pub mod tcp_listener { ... }

// remote.rs — TcpConnector
#[cfg(not(target_arch = "wasm32"))]
pub struct TcpConnector;
```

WebSocket client code compiles on both native and WASM (different implementations):

```rust
// websocket.rs
#[cfg(not(target_arch = "wasm32"))]
pub struct NativeWebSocketConnector;  // tokio-tungstenite

#[cfg(target_arch = "wasm32")]
pub struct BrowserWebSocketConnector;  // ws_stream_wasm
```

---

## 5. Native WebSocket Listener

### 5.1 Why It's Required

If browser peers connect via WebSocket, the native peer they connect *to* must accept WebSocket connections. This is not optional — it's the other side of the browser peer story.

### 5.2 Architecture

A WebSocket listener is a TCP listener that performs the HTTP Upgrade handshake before entering the entity protocol:

```
Browser                              Native Peer
   │                                     │
   ├── HTTP GET /ws (Upgrade: websocket) │
   │                                     │  ← tokio-tungstenite::accept_async()
   │◄── HTTP 101 Switching Protocols ────┤
   │                                     │
   │    WebSocket connection established  │
   │                                     │
   ├── WS message: EXECUTE hello ───────►│  ← now same as TCP: wire framing + handshake
   │◄── WS message: EXECUTE_RESPONSE ───┤
   │    ...                              │
```

After the WebSocket upgrade, the connection is a bidirectional byte stream. The entity protocol handshake (hello/authenticate) proceeds identically to TCP. The `handle_connection()` function in `connection.rs` doesn't need to know whether the underlying stream is TCP or WebSocket — it uses `AsyncRead`/`AsyncWrite`.

### 5.3 Multi-Listener Server

The native peer runs both TCP and WebSocket listeners concurrently:

```rust
pub async fn run_multi_transport(
    listeners: Vec<Box<dyn Listener>>,
    shared: Arc<PeerShared>,
) -> Result<(), PeerError> {
    let mut handles = Vec::new();

    for listener in listeners {
        let shared = shared.clone();
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok(conn) => {
                        let shared = shared.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(conn, shared).await {
                                tracing::warn!("{} connection from {} closed: {}",
                                    conn.transport_type, conn.remote_addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("accept error: {}", e);
                    }
                }
            }
        });
        handles.push(handle);
    }

    // Wait for all listener loops (they run forever unless error)
    futures::future::try_join_all(handles).await?;
    Ok(())
}
```

### 5.4 Transport Entity Registration

Per spec §3.13, the peer stores its transport descriptors in the tree:

```
system/transport/tcp → {protocol: "tcp", addresses: ["0.0.0.0:4040"], status: "listening"}
system/transport/websocket → {protocol: "websocket", addresses: ["0.0.0.0:4041"], status: "listening"}
```

Remote peers discover available transports by reading these entities. A browser peer would look for `system/transport/websocket` when resolving connection addresses.

### 5.5 CLI Configuration

```bash
# TCP only (current default)
entity-peer --listen 0.0.0.0:4040

# TCP + WebSocket
entity-peer --listen 0.0.0.0:4040 --ws-listen 0.0.0.0:4041

# WebSocket only (e.g., behind a reverse proxy)
entity-peer --ws-listen 0.0.0.0:4041
```

---

## 6. entity-browser-rust Integration Path

### 6.1 Current State

The entity-browser-rust Entity Browser is a static data viewer with placeholder UI for peer connections and handler execution. It depends only on Tier 0 crates (ecf, hash, entity, store, types). No peer, no networking, no handler dispatch.

### 6.2 Integration Phases

#### Phase 1: Local Peer (No Networking)

Add `entity-peer` dependency (with `default-features = false` for WASM). Construct a peer at startup. Use `peer.execute()` for local handler dispatch. All tree operations go through the peer instead of direct store access.

```rust
// entity-browser-rust state.rs — after integration
pub struct EntityState {
    peer: Peer,  // replaces raw ContentStore + LocationIndex
}

impl EntityState {
    pub fn new() -> Self {
        let kp = Keypair::generate();
        let peer = PeerBuilder::new().keypair(kp).build().unwrap();
        peer.local_only().unwrap();  // start engines, no networking
        Self { peer }
    }

    pub async fn tree_get(&self, path: &str) -> Option<Entity> {
        self.peer.execute("system/tree", "get", params).await.ok()
    }
}
```

**What this enables:**
- Execute console works (dispatches to real handlers)
- Tree operations go through the handler layer (capability checking, event emission)
- Extensions work (clock advances, revision tracks changes, subscriptions fire)
- All local — no networking, no WASM blockers

#### Phase 2: Remote Connection via WebSocket

Add `BrowserWebSocketConnector`. Connect to a native peer on startup (or via UI). Sync entities over the wire.

```rust
// After Phase 2
let connector = Arc::new(BrowserWebSocketConnector);
let peer = PeerBuilder::new()
    .keypair(kp)
    .connector(connector)
    .build()?;
peer.local_only()?;
peer.connect_to("ws://host:4041").await?;
```

**What this enables:**
- Browser peer connects to native peer
- Full handshake (hello/authenticate)
- Remote handler execution
- Entity sync (tree get/put against remote peer's tree)
- Subscription delivery from remote peer

#### Phase 3: Full Browser Peer

Multi-peer connections, peer discovery, subscription restoration, offline-first with pending delivery queue.

### 6.3 WASM Build Configuration

```toml
# entity-browser-rust/Cargo.toml additions

[dependencies]
entity-peer = { path = "../entity-core-rust/core/peer", default-features = false }

[target.'cfg(target_arch = "wasm32")'.dependencies]
entity-peer = { path = "../entity-core-rust/core/peer", default-features = false, features = ["websocket"] }
```

### 6.4 Async in egui/eframe

eframe (the egui framework) runs on a single-threaded event loop in the browser. Async operations cannot block `update()`. Two patterns for async integration:

**Pattern A: Channel-based (recommended)**
```rust
// Spawn async work via spawn_local, send results through mpsc
let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

wasm_bindgen_futures::spawn_local(async move {
    let result = peer.execute("system/tree", "get", params).await;
    tx.send(result).unwrap();
});

// In update(), poll the channel
fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
    while let Ok(result) = self.rx.try_recv() {
        self.apply_result(result);
    }
    // ... render UI ...
}
```

**Pattern B: Shared state with Mutex**
```rust
// Peer operations write to Arc<Mutex<State>>, UI reads from it
let state = Arc::new(std::sync::Mutex::new(AppState::default()));
```

Pattern A is simpler and avoids contention. egui's `ctx.request_repaint()` can be called from the channel send callback to trigger a repaint when results arrive.

---

## 7. Spawn and Timer Abstraction

### 7.1 The runtime Module

A new `runtime` module in the peer crate provides platform-abstracted primitives:

```rust
// core/peer/src/runtime.rs

/// Spawn a concurrent task.
#[cfg(not(target_arch = "wasm32"))]
pub fn spawn<F: Future<Output = ()> + Send + 'static>(f: F) {
    tokio::spawn(f);
}

#[cfg(target_arch = "wasm32")]
pub fn spawn<F: Future<Output = ()> + 'static>(f: F) {
    wasm_bindgen_futures::spawn_local(f);
}

/// Sleep for a duration.
#[cfg(not(target_arch = "wasm32"))]
pub async fn sleep(d: Duration) { tokio::time::sleep(d).await }

#[cfg(target_arch = "wasm32")]
pub async fn sleep(d: Duration) { gloo_timers::future::sleep(d).await }

/// Current time in milliseconds since epoch.
#[cfg(not(target_arch = "wasm32"))]
pub fn now_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

#[cfg(target_arch = "wasm32")]
pub fn now_millis() -> u64 { js_sys::Date::now() as u64 }
```

### 7.2 Call Site Migration

| File | Current | After |
|------|---------|-------|
| `server.rs:33` | `tokio::spawn(...)` | `runtime::spawn(...)` (or TCP-only, feature-gated) |
| `connection.rs:459` | `tokio::spawn(...)` | `runtime::spawn(...)` |
| `inbox.rs:129` | `tokio::spawn(...)` | `runtime::spawn(...)` |
| `subscription/engine.rs:161` | `tokio::spawn(...)` | `runtime::spawn(...)` |
| `clock/engine.rs:64` | `tokio::spawn(...)` | `runtime::spawn(...)` |
| `revision/engine.rs:40` | `tokio::spawn(...)` | `runtime::spawn(...)` |

### 7.3 The Send Bound Question

On native, `tokio::spawn` requires futures to be `Send`. On WASM, `spawn_local` does not. The `runtime::spawn` shim needs to handle this difference.

Two approaches:

**Approach A: Require `Send` always** — All spawned futures must be `Send`. This works because entity-core uses `Arc` everywhere (not `Rc`). Keeps the codebase identical across platforms. The WASM `spawn_local` accepts `Send` futures even though it doesn't require them.

**Approach B: Conditional `Send` bound** — Use a trait alias or macro to conditionally require `Send`. More complex, but allows WASM-only code to use non-Send types.

**Recommendation: Approach A.** Entity-core's futures are already `Send`. Don't introduce complexity for a flexibility we don't need.

```rust
// Approach A — works everywhere
pub fn spawn<F: Future<Output = ()> + Send + 'static>(f: F) {
    #[cfg(not(target_arch = "wasm32"))]
    { tokio::spawn(f); }

    #[cfg(target_arch = "wasm32")]
    { wasm_bindgen_futures::spawn_local(f); }
}
```

---

## 8. Architecture Team Review Items

These decisions have cross-implementation implications (Go, Python, future implementations) and should be reviewed by the architecture team before Rust implementation proceeds.

### 8.1 WebSocket Framing: Length-Prefixed or Bare?

**Option A: Length-prefixed inside WS messages.** Each WebSocket message contains a 4-byte length prefix + CBOR payload, identical to TCP framing. Simple — reuses `read_frame`/`write_frame` unchanged. Wastes 4 bytes per message.

**Option B: Bare CBOR per WS message.** Each WebSocket message IS one CBOR payload, no length prefix. More efficient. Requires a different code path for WebSocket framing (skip length prefix, read entire WS message as payload).

**Option C: Length-prefixed for binary WS, bare for text WS.** Binary WebSocket messages use length-prefixed framing (compatible with existing code). Text messages (if ever used for diagnostic/debug) use bare payloads.

**Recommendation:** Option A (length-prefixed). The 4-byte overhead is trivial. It means the connection handler doesn't need to know what transport it's running on — `handle_connection()` always uses `read_frame`/`write_frame`. This keeps the transport abstraction clean.

**Impact on other implementations:** If this is standardized, Go and Python need to know whether to length-prefix WebSocket messages. All implementations should agree.

### 8.2 Transport Type Registry

The spec's `system/transport` entity has a `protocol` field. Current values: "tcp", "quic", "udp", "bluetooth". Should "websocket" be added to the spec's known transport types?

**Recommendation:** Yes. WebSocket is the standard browser-to-server transport. It should be a recognized protocol value.

### 8.3 WebSocket Endpoint Path

What URL path should the WebSocket listener use? Options:
- `ws://host:port/` — root path (simple, but conflicts if HTTP is served on same port)
- `ws://host:port/ws` — dedicated path (conventional)
- `ws://host:port/entity` — protocol-specific path
- Separate port entirely — `tcp:4040`, `ws:4041`

**Recommendation:** Separate port. Avoids HTTP routing complexity. The transport entity's `addresses` field carries the full address including port. For environments where only one port is available (cloud hosting), a reverse proxy can route `/ws` to the WebSocket port.

### 8.4 Transport Negotiation During Hello

The hello message (§4.4) includes capability arrays (`protocols`, `hash_formats`, `key_types`, `compression`, `encryption`). Should transport-level preferences be negotiated here too?

**No.** Transport selection happens *before* the hello handshake — you must already be connected to send hello. Transport selection is a connection establishment concern, not a protocol negotiation concern. The `system/transport` entities in the tree provide discovery; the client chooses which transport to use based on what's available.

### 8.5 Network Extension Interaction

EXTENSION-NETWORK.md defines session management, keepalive, reconnection, and graceful close. These should be transport-agnostic. Review needed:

- **Keepalive:** TCP keepalive is OS-level. WebSocket has its own ping/pong. The network extension's keepalive should layer on top of both (protocol-level ping, not transport-level).
- **Reconnection:** When reconnecting, the transport may change (TCP → WebSocket or vice versa). Session continuity should survive transport changes.
- **Graceful close:** The close message (network extension) should be transport-independent. WebSocket has its own close frame — the entity protocol close should happen *before* the WebSocket close.

### 8.6 Browser Peer Identity

Should browser peers use persistent or ephemeral keypairs?

- **Persistent:** Browser generates keypair once, stores in localStorage/IndexedDB. Same peer_id across sessions. Enables persistent capability grants.
- **Ephemeral:** New keypair per session. Simpler. No storage needed. But grants don't survive page reload.

**Recommendation for architecture team:** Define both modes. Browser peers SHOULD support persistent keypairs (stored in IndexedDB), with ephemeral as fallback. The Rust implementation exposes `PeerBuilder::keypair()` — the entity-browser-rust integration layer decides where the keypair comes from.

---

## 9. Implementation Plan

### Phase 0: Prerequisites (before transport work)

- [ ] **Fix tree merge regression** — 4 failing tests from `8ceb61d`
- [ ] **Verify WASM compilation** of Tier 0/1 crates: `cargo build --target wasm32-unknown-unknown -p entity-store -p entity-hash -p entity-ecf -p entity-entity -p entity-crypto -p entity-types -p entity-capability -p entity-handler`

### Phase 1: Transport Abstraction (Rust-only, no WASM yet)

- [ ] Add `transport.rs` with `Listener`, `Connector`, `Connection` traits
- [ ] Add `runtime.rs` with `spawn`, `sleep`, `now_millis` shims
- [ ] Wrap existing TCP code as `TcpListener` impl + `TcpConnector` impl
- [ ] Refactor `server.rs` → `run_multi_transport(listeners, shared)`
- [ ] Refactor `connection.rs` → accept `Connection` instead of `TcpStream`
- [ ] Refactor `remote.rs` → use `Connector` trait instead of `TcpStream::connect()`
- [ ] Replace 6 `tokio::spawn` calls with `runtime::spawn`
- [ ] Add `MemoryTransport` for integration testing
- [ ] All existing tests pass (TCP path unchanged)

### Phase 2: WebSocket Listener (native)

- [ ] Add `tokio-tungstenite` dependency (feature-gated)
- [ ] Implement `WebSocketListener` (HTTP upgrade → WS → AsyncRead/AsyncWrite)
- [ ] CLI flag `--ws-listen` for WebSocket address
- [ ] Bootstrap `system/transport/websocket` entity in tree
- [ ] Integration test: TCP peer ↔ WebSocket peer

### Phase 3: WASM Peer Core

- [ ] Add `wasm32` target configuration to peer crate Cargo.toml
- [ ] Feature-gate TCP code behind `#[cfg(not(target_arch = "wasm32"))]`
- [ ] Implement `BrowserWebSocketConnector` using `ws_stream_wasm`
- [ ] Implement `Peer::local_only()` (start engines, no listeners)
- [ ] Timer shim: `gloo-timers` for WASM sleep
- [ ] Verify: `cargo build --target wasm32-unknown-unknown -p entity-peer --no-default-features --features websocket`

### Phase 4: entity-browser-rust Integration

- [ ] Add `entity-peer` dependency to entity-browser-rust
- [ ] Replace raw `MemoryContentStore`/`MemoryLocationIndex` with `Peer`
- [ ] Wire execute console to `peer.execute()`
- [ ] Wire peer connections window to `peer.connect_to()`
- [ ] Tree change events → UI updates via channel bridge
- [ ] Verify WASM build: `trunk build`

### Phase 5: Architecture Team Review Items

- [ ] WebSocket framing decision (§8.1) — cross-implementation
- [ ] Transport type registry update (§8.2) — spec change
- [ ] WebSocket endpoint path convention (§8.3) — operational
- [ ] Network extension transport-agnosticism review (§8.5) — spec review
- [ ] Browser peer identity model (§8.6) — cross-implementation

---

## 10. Dependency Map

```
                                    New Dependencies
                                    ────────────────
Native:
  tokio-tungstenite = "0.24"        # WebSocket server + client (native)

WASM:
  wasm-bindgen-futures = "0.4"      # spawn_local() executor
  ws_stream_wasm = "0.7"            # WebSocket → AsyncRead/AsyncWrite
  gloo-timers = "0.3"               # setTimeout-based sleep
  js-sys = "0.3"                    # Date.now()

Testing:
  (none — MemoryTransport uses tokio::io::duplex, already available)
```

No new dependencies for the transport abstraction itself — only for specific transport implementations.

---

## 11. Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| `ws_stream_wasm` AsyncRead/Write impl doesn't match wire codec expectations | Blocks WASM networking | Test with simple echo server first; fallback: write own adapter |
| `Send` bound difference causes compilation failures on WASM | Blocks WASM build | Approach A (require Send everywhere) avoids this; audit all spawn sites |
| WebSocket framing decision not aligned across implementations | Interop failure | Decide in Phase 5 before Go/Python implement WebSocket |
| egui async integration conflicts with eframe event loop | Blocks UI integration | Channel-based pattern (§6.4) is proven in eframe WASM apps |
| Extension engine event loops don't work without tokio runtime | Extensions broken in WASM | `tokio::sync::broadcast` is executor-independent; `spawn_local` drives the loop |
| Performance regression from trait dispatch (Box<dyn Listener>) | Negligible | Accept loop is not hot path; connection handling dominates |

---

## 12. Summary

The transport abstraction is a focused refactoring, not an architectural overhaul. The wire codec is already abstracted. The store and handler layers are transport-unaware. The work concentrates in three files (`server.rs`, `connection.rs`, `remote.rs`) plus a new `transport.rs` module.

The WASM peer story is viable because `tokio::sync` works in the browser. The extension engines (subscription, clock, revision) run unchanged — their event loops are driven by broadcast channels and `spawn_local` instead of `tokio::spawn`.

The critical cross-implementation decisions (WebSocket framing, transport registry, network extension review) should go to the architecture team before Phase 2. Phase 1 (transport abstraction) and Phase 3 (WASM peer core) are Rust-internal changes that don't affect the protocol spec.
