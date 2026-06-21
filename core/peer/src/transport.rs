//! Transport abstraction for pluggable network transports.
//!
//! Defines traits for accepting inbound connections (Listener), establishing
//! outbound connections (Connector), and representing established connections
//! (Connection). TCP is the default implementation; WebSocket, QUIC, and
//! in-memory transports can be added without changing any code above this layer.
//!
//! The wire codec (read_frame/write_frame) works over any AsyncRead/AsyncWrite,
//! so all transports share the same handshake, message loop, and dispatch logic.

use async_trait::async_trait;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::PeerError;

/// Errors from transport operations.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("bind failed: {0}")]
    BindError(String),
    #[error("accept failed: {0}")]
    AcceptError(String),
    #[error("connect failed: {0}")]
    ConnectError(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<TransportError> for PeerError {
    fn from(e: TransportError) -> Self {
        PeerError::ConnectionError(e.to_string())
    }
}

/// An established bidirectional connection.
///
/// Wraps any transport's read/write halves behind boxed trait objects.
/// The connection handler uses `read_frame`/`write_frame` over these —
/// it never knows whether the underlying stream is TCP, WebSocket, or memory.
///
/// Reader/writer require Send on all platforms. On WASM (single-threaded),
/// browser types that are !Send are wrapped with SendWrapper (see wasm_websocket module).
pub struct Connection {
    pub reader: Box<dyn AsyncRead + Unpin + Send>,
    pub writer: Box<dyn AsyncWrite + Unpin + Send>,
    /// Human-readable description of the remote endpoint (e.g., "192.168.1.42:4040").
    pub remote_addr: String,
    /// Transport identifier (e.g., "tcp", "websocket", "memory").
    pub transport_type: &'static str,
}

/// Server-side transport: accepts inbound connections.
///
/// Native: standard `Send + Sync` trait. The TCP/WebSocket listeners
/// fit here; the cross-thread accept loop in `server::run` requires it.
///
/// WASM: `?Send` variant for browser environments. Workers cannot accept
/// inbound network connections (browser sandbox), but they CAN accept
/// cross-Worker MessagePort connections via a main-thread broker — see
/// `MessagePortListener`. The accept future is !Send because
/// `web_sys::MessagePort` is !Send; the trait object is Send+Sync only
/// because the underlying types are wrapped in `SendWrapper`.
#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
pub trait Listener: Send + Sync {
    /// Accept the next inbound connection.
    async fn accept(&self) -> Result<Connection, TransportError>;

    /// The local address this listener is bound to.
    fn local_addr(&self) -> String;

    /// Transport identifier (e.g., "tcp", "websocket").
    fn transport_type(&self) -> &'static str;
}

#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
pub trait Listener: Send + Sync {
    /// Accept the next inbound connection.
    async fn accept(&self) -> Result<Connection, TransportError>;

    /// The local address this listener is bound to.
    fn local_addr(&self) -> String;

    /// Transport identifier.
    fn transport_type(&self) -> &'static str;
}

/// Client-side transport: establishes outbound connections.
#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
pub trait Connector: Send + Sync {
    /// Connect to a remote peer at the given address.
    async fn connect(&self, addr: &str) -> Result<Connection, TransportError>;

    /// Transport identifier.
    fn transport_type(&self) -> &'static str;
}

/// Client-side transport: establishes outbound connections (WASM).
/// Futures are !Send (single-threaded), but trait object is Send+Sync
/// (stateless unit structs, stored in Arc).
#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
pub trait Connector: Send + Sync {
    /// Connect to a remote peer at the given address.
    async fn connect(&self, addr: &str) -> Result<Connection, TransportError>;

    /// Transport identifier.
    fn transport_type(&self) -> &'static str;
}

/// Returns the default connector for the current platform.
/// Native: TcpConnector. WASM: NoConnector (outbound connections not supported without explicit setup).
pub fn default_connector() -> std::sync::Arc<dyn Connector> {
    #[cfg(not(target_arch = "wasm32"))]
    { std::sync::Arc::new(TcpConnector) }

    #[cfg(target_arch = "wasm32")]
    { std::sync::Arc::new(NoConnector) }
}

/// Stub connector for WASM — outbound connections require explicit WebSocket setup.
#[cfg(target_arch = "wasm32")]
pub struct NoConnector;

#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
impl Connector for NoConnector {
    async fn connect(&self, addr: &str) -> Result<Connection, TransportError> {
        Err(TransportError::ConnectError(format!(
            "no connector configured (tried to connect to {})", addr
        )))
    }
    fn transport_type(&self) -> &'static str { "none" }
}

// ---------------------------------------------------------------------------
// TCP implementation (native only — no TCP in WASM)
// ---------------------------------------------------------------------------

#[cfg(not(target_arch = "wasm32"))]
mod tcp {
    use super::*;
    use std::net::SocketAddr;
    use tokio::net::TcpStream;

/// TCP listener wrapping `tokio::net::TcpListener`.
pub struct TcpTransportListener {
    inner: tokio::net::TcpListener,
    local_addr: SocketAddr,
}

impl TcpTransportListener {
    /// Bind a TCP listener on the given address.
    pub async fn bind(addr: &str) -> Result<Self, TransportError> {
        let inner = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| TransportError::BindError(format!("{}: {}", addr, e)))?;
        let local_addr = inner
            .local_addr()
            .map_err(|e| TransportError::BindError(format!("local_addr: {}", e)))?;
        Ok(Self { inner, local_addr })
    }

    /// The actual `SocketAddr` bound to (useful for port-0 auto-assignment).
    pub fn socket_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

#[async_trait]
impl Listener for TcpTransportListener {
    async fn accept(&self) -> Result<Connection, TransportError> {
        let (stream, remote_addr) = self
            .inner
            .accept()
            .await
            .map_err(|e| TransportError::AcceptError(e.to_string()))?;

        // Disable Nagle for request/response RPC. Without TCP_NODELAY, small
        // writes interact with the peer's delayed-ACK timer to add ~40 ms per
        // round-trip on localhost. Non-fatal if it fails.
        if let Err(e) = stream.set_nodelay(true) {
            tracing::warn!(remote = %remote_addr, error = %e, "tcp accept: set_nodelay failed");
        }

        let (reader, writer) = tokio::io::split(stream);
        Ok(Connection {
            reader: Box::new(reader),
            writer: Box::new(writer),
            remote_addr: remote_addr.to_string(),
            transport_type: "tcp",
        })
    }

    fn local_addr(&self) -> String {
        self.local_addr.to_string()
    }

    fn transport_type(&self) -> &'static str {
        "tcp"
    }
}

/// TCP connector for outbound connections.
pub struct TcpConnector;

#[async_trait]
impl Connector for TcpConnector {
    async fn connect(&self, addr: &str) -> Result<Connection, TransportError> {
        // `tokio::net::TcpStream::connect` resolves via getaddrinfo and
        // does not know about URL schemes — passing `tcp://host:port`
        // makes it try to resolve `tcp://host` as a hostname, which
        // fails with "Name or service not known". Accept both bare
        // `host:port` (legacy direct callers, in-process tests) and
        // the D-14 wire shape `tcp://host:port` published in
        // TcpProfileData.endpoint_url.
        let host_port = addr.strip_prefix("tcp://").unwrap_or(addr);
        let stream = TcpStream::connect(host_port)
            .await
            .map_err(|e| TransportError::ConnectError(format!("{}: {}", addr, e)))?;

        // Disable Nagle (see TcpTransportListener::accept for rationale).
        if let Err(e) = stream.set_nodelay(true) {
            tracing::warn!(addr = %addr, error = %e, "tcp connect: set_nodelay failed");
        }

        let remote_addr = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| addr.to_string());

        let (reader, writer) = tokio::io::split(stream);
        Ok(Connection {
            reader: Box::new(reader),
            writer: Box::new(writer),
            remote_addr,
            transport_type: "tcp",
        })
    }

    fn transport_type(&self) -> &'static str {
        "tcp"
    }
}

} // mod tcp

#[cfg(not(target_arch = "wasm32"))]
pub use tcp::{TcpConnector, TcpTransportListener};

// ---------------------------------------------------------------------------
// WebSocket implementation (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(all(feature = "websocket", not(target_arch = "wasm32")))]
mod websocket {
    use super::*;
    use futures_util::{Sink, Stream, StreamExt};
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio_tungstenite::tungstenite::Error as WsError;
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::WebSocketStream;

    fn ws_err(e: WsError) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::BrokenPipe, format!("{}", e))
    }

    /// Adapts a `WebSocketStream` split into read/write halves that implement
    /// `AsyncRead`/`AsyncWrite`. Ensures one length-prefixed frame per WS message
    /// per spec W2.
    ///
    /// Write side: buffers bytes until `flush()`, then sends the buffer as a
    /// single binary WebSocket message. This guarantees `write_frame`'s
    /// write_all(len) + write_all(payload) + flush() produces exactly one message.
    ///
    /// Read side: receives one WS message at a time and serves its bytes through
    /// `AsyncRead`. When the current message is exhausted, receives the next.
    pub struct WsReader<S> {
        inner: futures_util::stream::SplitStream<WebSocketStream<S>>,
        buf: Vec<u8>,
        pos: usize,
    }

    pub struct WsWriter<S> {
        inner: futures_util::stream::SplitSink<WebSocketStream<S>, Message>,
        buf: Vec<u8>,
    }

    impl<S: AsyncRead + AsyncWrite + Unpin> WsReader<S> {
        pub fn new(stream: futures_util::stream::SplitStream<WebSocketStream<S>>) -> Self {
            Self {
                inner: stream,
                buf: Vec::new(),
                pos: 0,
            }
        }
    }

    impl<S: AsyncRead + AsyncWrite + Unpin> WsWriter<S> {
        pub fn new(sink: futures_util::stream::SplitSink<WebSocketStream<S>, Message>) -> Self {
            Self {
                inner: sink,
                buf: Vec::new(),
            }
        }
    }

    impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsReader<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            // If we have buffered data from a previous message, serve it
            if self.pos < self.buf.len() {
                let remaining = &self.buf[self.pos..];
                let n = remaining.len().min(buf.remaining());
                buf.put_slice(&remaining[..n]);
                self.pos += n;
                if self.pos >= self.buf.len() {
                    self.buf.clear();
                    self.pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // Read next WS message, skipping control frames (ping/pong)
            loop {
                match Stream::poll_next(Pin::new(&mut self.inner), cx) {
                    Poll::Ready(Some(Ok(msg))) => match msg {
                        Message::Binary(data) => {
                            let n = data.len().min(buf.remaining());
                            buf.put_slice(&data[..n]);
                            if n < data.len() {
                                // Buffer the remainder
                                self.buf = data.into();
                                self.pos = n;
                            }
                            return Poll::Ready(Ok(()));
                        }
                        Message::Close(_) => return Poll::Ready(Ok(())), // EOF
                        Message::Ping(_) | Message::Pong(_) => {
                            // Control frames — skip and poll again
                            continue;
                        }
                        _ => {
                            // Text or other — protocol violation per W2
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "received non-binary WebSocket message",
                            )));
                        }
                    },
                    Poll::Ready(Some(Err(e))) => {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionReset,
                            format!("{}", e),
                        )));
                    }
                    Poll::Ready(None) => return Poll::Ready(Ok(())), // Stream ended = EOF
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
    }

    impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsWriter<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            // Buffer the data — it will be sent as one WS message on flush()
            self.buf.extend_from_slice(data);
            Poll::Ready(Ok(data.len()))
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            if !self.buf.is_empty() {
                let data = std::mem::take(&mut self.buf);
                let msg = Message::Binary(data.into());
                // Check sink readiness
                let sink = Pin::new(&mut self.inner);
                match Sink::<Message>::poll_ready(sink, cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(ws_err(e))),
                    Poll::Pending => {
                        // Put data back and wait
                        if let Message::Binary(d) = msg {
                            self.buf = d.into();
                        }
                        return Poll::Pending;
                    }
                }
                // Send the buffered bytes as a single binary WS message
                let sink = Pin::new(&mut self.inner);
                if let Err(e) = Sink::<Message>::start_send(sink, msg) {
                    return Poll::Ready(Err(ws_err(e)));
                }
            }
            // Flush the underlying sink
            let sink = Pin::new(&mut self.inner);
            Sink::<Message>::poll_flush(sink, cx).map_err(ws_err)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            let sink = Pin::new(&mut self.inner);
            Sink::<Message>::poll_close(sink, cx).map_err(ws_err)
        }
    }

    /// Split a WebSocketStream into Connection-compatible read/write halves.
    pub fn split_ws<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        ws: WebSocketStream<S>,
        remote_addr: String,
    ) -> Connection {
        let (sink, stream) = ws.split();
        Connection {
            reader: Box::new(WsReader::new(stream)),
            writer: Box::new(WsWriter::new(sink)),
            remote_addr,
            transport_type: "websocket",
        }
    }

    // --- Listener ---

    /// WebSocket listener: accepts TCP connections, performs HTTP upgrade,
    /// then wraps the WebSocket stream as a Connection.
    pub struct WebSocketListener {
        inner: tokio::net::TcpListener,
        local_addr: SocketAddr,
    }

    impl WebSocketListener {
        /// Bind a WebSocket listener on the given address.
        pub async fn bind(addr: &str) -> Result<Self, TransportError> {
            let inner = tokio::net::TcpListener::bind(addr)
                .await
                .map_err(|e| TransportError::BindError(format!("{}: {}", addr, e)))?;
            let local_addr = inner
                .local_addr()
                .map_err(|e| TransportError::BindError(format!("local_addr: {}", e)))?;
            Ok(Self { inner, local_addr })
        }

        /// The actual `SocketAddr` bound to.
        pub fn socket_addr(&self) -> SocketAddr {
            self.local_addr
        }
    }

    #[async_trait]
    impl Listener for WebSocketListener {
        async fn accept(&self) -> Result<Connection, TransportError> {
            let (stream, remote_addr) = self
                .inner
                .accept()
                .await
                .map_err(|e| TransportError::AcceptError(e.to_string()))?;

            // Disable Nagle on the underlying TCP stream before the WS upgrade.
            if let Err(e) = stream.set_nodelay(true) {
                tracing::warn!(remote = %remote_addr, error = %e, "ws accept: set_nodelay failed");
            }

            let ws_stream = tokio_tungstenite::accept_async(stream)
                .await
                .map_err(|e| TransportError::AcceptError(format!("ws upgrade: {}", e)))?;

            Ok(split_ws(ws_stream, remote_addr.to_string()))
        }

        fn local_addr(&self) -> String {
            format!("ws://{}", self.local_addr)
        }

        fn transport_type(&self) -> &'static str {
            "websocket"
        }
    }

    // --- Connector ---

    /// WebSocket connector for outbound connections.
    pub struct WebSocketConnector;

    #[async_trait]
    impl Connector for WebSocketConnector {
        async fn connect(&self, addr: &str) -> Result<Connection, TransportError> {
            let (ws_stream, _response) = tokio_tungstenite::connect_async(addr)
                .await
                .map_err(|e| TransportError::ConnectError(format!("{}: {}", addr, e)))?;

            Ok(split_ws(ws_stream, addr.to_string()))
        }

        fn transport_type(&self) -> &'static str {
            "websocket"
        }
    }
}

#[cfg(all(feature = "websocket", not(target_arch = "wasm32")))]
pub use websocket::{WebSocketConnector, WebSocketListener};

// ---------------------------------------------------------------------------
// Browser WebSocket connector (WASM only)
// ---------------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
mod wasm_websocket {
    use super::*;
    use futures_util::{Sink, Stream, StreamExt};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use ws_stream_wasm::{WsMessage, WsStream};

    /// Wrapper that implements Send for !Send types on WASM.
    ///
    /// SAFETY: WASM (wasm32-unknown-unknown) is single-threaded. There are no
    /// other threads to send data to. The Send bound is vacuously satisfied.
    /// This is the standard pattern used by gloo, leptos, dioxus, and other
    /// Rust WASM frameworks.
    struct SendWrapper<T>(T);

    // SAFETY: WASM is single-threaded — Send is vacuously satisfied.
    unsafe impl<T> Send for SendWrapper<T> {}
    // SAFETY: WASM is single-threaded — Sync is vacuously satisfied.
    unsafe impl<T> Sync for SendWrapper<T> {}

    impl<T> SendWrapper<T> {
        fn inner_mut(&mut self) -> &mut T { &mut self.0 }
    }

    fn ws_err(e: ws_stream_wasm::WsErr) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::BrokenPipe, format!("{}", e))
    }

    /// Adapts WsStream (message-level) to AsyncRead.
    /// Inner stream wrapped in SendWrapper for WASM Send compatibility.
    struct BrowserWsReader {
        inner: SendWrapper<futures_util::stream::SplitStream<WsStream>>,
        buf: Vec<u8>,
        pos: usize,
    }

    /// Adapts WsStream (message-level) to AsyncWrite.
    /// Buffers until flush, sends as single binary WS message.
    struct BrowserWsWriter {
        inner: SendWrapper<futures_util::stream::SplitSink<WsStream, WsMessage>>,
        buf: Vec<u8>,
    }

    impl AsyncRead for BrowserWsReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.pos < self.buf.len() {
                let remaining = &self.buf[self.pos..];
                let n = remaining.len().min(buf.remaining());
                buf.put_slice(&remaining[..n]);
                self.pos += n;
                if self.pos >= self.buf.len() {
                    self.buf.clear();
                    self.pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            loop {
                match Stream::poll_next(Pin::new(self.inner.inner_mut()), cx) {
                    Poll::Ready(Some(WsMessage::Binary(data))) => {
                        let n = data.len().min(buf.remaining());
                        buf.put_slice(&data[..n]);
                        if n < data.len() {
                            self.buf = data;
                            self.pos = n;
                        }
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Some(WsMessage::Text(_))) => {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "received text WebSocket message",
                        )));
                    }
                    Poll::Ready(None) => return Poll::Ready(Ok(())),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
    }

    impl AsyncWrite for BrowserWsWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.buf.extend_from_slice(data);
            Poll::Ready(Ok(data.len()))
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            if !self.buf.is_empty() {
                let data = std::mem::take(&mut self.buf);
                let msg = WsMessage::Binary(data);
                match Sink::<WsMessage>::poll_ready(Pin::new(self.inner.inner_mut()), cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(ws_err(e))),
                    Poll::Pending => {
                        if let WsMessage::Binary(d) = msg {
                            self.buf = d;
                        }
                        return Poll::Pending;
                    }
                }
                if let Err(e) = Sink::<WsMessage>::start_send(Pin::new(self.inner.inner_mut()), msg) {
                    return Poll::Ready(Err(ws_err(e)));
                }
            }
            Sink::<WsMessage>::poll_flush(Pin::new(self.inner.inner_mut()), cx).map_err(ws_err)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Sink::<WsMessage>::poll_close(Pin::new(self.inner.inner_mut()), cx).map_err(ws_err)
        }
    }

    /// Browser WebSocket connector using ws_stream_wasm.
    ///
    /// Connects to a WebSocket URL (ws:// or wss://) from the browser.
    pub struct BrowserWebSocketConnector;

    #[async_trait(?Send)]
    impl Connector for BrowserWebSocketConnector {
        async fn connect(&self, addr: &str) -> Result<Connection, TransportError> {
            let (_ws_meta, ws_stream) = ws_stream_wasm::WsMeta::connect(addr, None)
                .await
                .map_err(|e| TransportError::ConnectError(format!("ws connect: {}", e)))?;

            let (sink, stream) = ws_stream.split();

            Ok(Connection {
                reader: Box::new(BrowserWsReader { inner: SendWrapper(stream), buf: Vec::new(), pos: 0 }),
                writer: Box::new(BrowserWsWriter { inner: SendWrapper(sink), buf: Vec::new() }),
                remote_addr: addr.to_string(),
                transport_type: "websocket",
            })
        }

        fn transport_type(&self) -> &'static str {
            "websocket"
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use wasm_websocket::BrowserWebSocketConnector;

// ---------------------------------------------------------------------------
// Memory transport (in-process Connector + Listener)
// ---------------------------------------------------------------------------

/// Create a pair of in-memory connections.
///
/// Returns (client_connection, server_connection) — two ends of a
/// bidirectional pipe. No networking involved. Used as the building
/// block for `MemoryConnector` / `MemoryListener`; also exposed for
/// callers that want a one-shot pair without a registry.
#[cfg(not(target_arch = "wasm32"))]
pub fn memory_transport_pair() -> (Connection, Connection) {
    let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, server_write) = tokio::io::split(server_stream);

    let client = Connection {
        reader: Box::new(client_read),
        writer: Box::new(client_write),
        remote_addr: "memory:server".to_string(),
        transport_type: "memory",
    };
    let server = Connection {
        reader: Box::new(server_read),
        writer: Box::new(server_write),
        remote_addr: "memory:client".to_string(),
        transport_type: "memory",
    };
    (client, server)
}

#[cfg(not(target_arch = "wasm32"))]
mod memory {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};
    use tokio::sync::mpsc;

    /// In-process listener registry. `MemoryConnector` resolves
    /// `memory://<endpoint>` addresses by looking up the registered
    /// `MemoryListener`'s incoming-connection channel here and pushing
    /// the server end of a `memory_transport_pair()` into it.
    ///
    /// Construct one explicitly with `MemoryTransportRegistry::new()`
    /// and pass the `Arc` to every `MemoryConnector` / `MemoryListener`
    /// that should be mutually reachable. Use `process_global()` when
    /// "all in-process peers should be reachable" is the desired
    /// default — e.g., single-process shells, Tauri backends, test
    /// harnesses that don't need isolation.
    ///
    /// Endpoint strings are application-defined; the canonical convention
    /// is the listening peer's Base58 PeerID (matching the
    /// `memory://<peer-id>` URL form).
    pub struct MemoryTransportRegistry {
        listeners: Mutex<HashMap<String, mpsc::Sender<Connection>>>,
    }

    impl MemoryTransportRegistry {
        pub fn new() -> Arc<Self> {
            Arc::new(Self {
                listeners: Mutex::new(HashMap::new()),
            })
        }

        /// Returns the process-global shared registry. Lazily
        /// initialized on first call. Convenient default; prefer
        /// `new()` in tests that need isolation.
        pub fn process_global() -> Arc<Self> {
            static GLOBAL: OnceLock<Arc<MemoryTransportRegistry>> = OnceLock::new();
            GLOBAL.get_or_init(MemoryTransportRegistry::new).clone()
        }

        /// Number of currently-registered endpoints (for tests / debug).
        pub fn len(&self) -> usize {
            self.listeners.lock().unwrap().len()
        }

        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }
    }

    impl Default for MemoryTransportRegistry {
        fn default() -> Self {
            Self {
                listeners: Mutex::new(HashMap::new()),
            }
        }
    }

    /// In-process server endpoint. Registers itself under `endpoint`
    /// in the registry on construction; unregisters on drop. Connections
    /// pushed by a `MemoryConnector` arrive via `accept()`.
    pub struct MemoryListener {
        endpoint: String,
        // tokio::sync::Mutex because `Listener::accept(&self)` takes
        // `&self` but `mpsc::Receiver::recv` requires `&mut self` —
        // need async-aware interior mutability.
        rx: tokio::sync::Mutex<mpsc::Receiver<Connection>>,
        registry: Arc<MemoryTransportRegistry>,
    }

    impl MemoryListener {
        /// Bind a listener for `endpoint` against `registry`. Fails if
        /// another listener for the same endpoint is already registered.
        ///
        /// Channel capacity defaults to 16 — enough for any realistic
        /// burst of concurrent inbound connects; backpressure on the
        /// connector side is fine.
        pub fn bind(
            endpoint: impl Into<String>,
            registry: Arc<MemoryTransportRegistry>,
        ) -> Result<Self, TransportError> {
            let endpoint = endpoint.into();
            let (tx, rx) = mpsc::channel(16);
            {
                let mut listeners = registry.listeners.lock().unwrap();
                if listeners.contains_key(&endpoint) {
                    return Err(TransportError::BindError(format!(
                        "memory endpoint already bound: {}",
                        endpoint
                    )));
                }
                listeners.insert(endpoint.clone(), tx);
            }
            Ok(Self {
                endpoint,
                rx: tokio::sync::Mutex::new(rx),
                registry,
            })
        }
    }

    impl Drop for MemoryListener {
        fn drop(&mut self) {
            // Remove ourselves so subsequent connects to this endpoint
            // fail with a clean ConnectError rather than handing out
            // connections to a closed receiver.
            let _ = self.registry.listeners.lock().unwrap().remove(&self.endpoint);
        }
    }

    #[async_trait]
    impl Listener for MemoryListener {
        async fn accept(&self) -> Result<Connection, TransportError> {
            self.rx
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| TransportError::AcceptError("memory listener closed".into()))
        }

        fn local_addr(&self) -> String {
            format!("memory://{}", self.endpoint)
        }

        fn transport_type(&self) -> &'static str {
            "memory"
        }
    }

    /// In-process client connector. `.connect("memory://<endpoint>")`
    /// looks up the registered `MemoryListener` for `<endpoint>` and
    /// hands back a duplex `Connection`. Returns `ConnectError` if no
    /// listener is registered for the endpoint.
    pub struct MemoryConnector {
        registry: Arc<MemoryTransportRegistry>,
    }

    impl MemoryConnector {
        pub fn new(registry: Arc<MemoryTransportRegistry>) -> Self {
            Self { registry }
        }
    }

    #[async_trait]
    impl Connector for MemoryConnector {
        async fn connect(&self, addr: &str) -> Result<Connection, TransportError> {
            let endpoint = addr.strip_prefix("memory://").ok_or_else(|| {
                TransportError::ConnectError(format!(
                    "MemoryConnector: expected memory:// scheme, got {}",
                    addr
                ))
            })?;
            let tx = {
                let listeners = self.registry.listeners.lock().unwrap();
                listeners.get(endpoint).cloned()
            };
            let tx = tx.ok_or_else(|| {
                TransportError::ConnectError(format!(
                    "MemoryConnector: no listener registered for {}",
                    endpoint
                ))
            })?;
            let (client_conn, server_conn) = memory_transport_pair();
            tx.send(server_conn).await.map_err(|_| {
                TransportError::ConnectError(format!(
                    "MemoryConnector: listener for {} dropped before accept",
                    endpoint
                ))
            })?;
            Ok(client_conn)
        }

        fn transport_type(&self) -> &'static str {
            "memory"
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use memory::{MemoryConnector, MemoryListener, MemoryTransportRegistry};

// ---------------------------------------------------------------------------
// MultiConnector — scheme-routed composition of multiple Connectors
// ---------------------------------------------------------------------------
//
// Each peer holds exactly one `Arc<dyn Connector>`. Workers/peers that
// need to reach multiple address schemes (e.g., a backend Worker
// syncing with sibling Workers via `xworker://` AND with external
// relays via `ws://`/`wss://`) need a composition layer.
//
// `MultiConnector` is a thin dispatcher that picks the underlying
// connector by the address's URL scheme (the part before `://`).
// Schemes are matched **exactly**, not by prefix — registering
// `"ws"` and `"wss"` is unambiguous regardless of insertion order
// (in contrast to `starts_with`-based matching, where `"wss://x"`
// also matches `"ws://"` and order becomes load-bearing).
//
// Native and WASM share the same struct and constructors; the only
// difference is the `Connector` impl block's `async_trait` attribute
// (full Send vs `?Send`). Both impls are otherwise identical.

/// Compose multiple connectors and dispatch `connect` by URL scheme.
///
/// Build with [`MultiConnector::new`] and [`MultiConnector::with`]:
///
/// ```ignore
/// let connector: Arc<dyn Connector> = Arc::new(
///     MultiConnector::new()
///         .with("xworker", Arc::new(MessagePortConnector::new(control)))
///         .with("ws",      Arc::new(BrowserWebSocketConnector))
///         .with("wss",     Arc::new(BrowserWebSocketConnector))
/// );
/// ```
///
/// The scheme is the substring before `"://"` in the address. If no
/// registered scheme matches, `connect` returns
/// `TransportError::ConnectError` listing the registered schemes.
pub struct MultiConnector {
    by_scheme: Vec<(&'static str, std::sync::Arc<dyn Connector>)>,
}

impl MultiConnector {
    pub fn new() -> Self {
        Self {
            by_scheme: Vec::new(),
        }
    }

    /// Register `connector` to handle addresses whose scheme equals
    /// `scheme` (the part before `"://"`). First registration wins
    /// if the same scheme is registered twice.
    pub fn with(mut self, scheme: &'static str, connector: std::sync::Arc<dyn Connector>) -> Self {
        // Strip a trailing `://` if the caller included it — accept
        // both `"ws"` and `"ws://"` to avoid quiet mismatch with the
        // exact-scheme lookup logic.
        let normalized = scheme.strip_suffix("://").unwrap_or(scheme);
        self.by_scheme.push((normalized, connector));
        self
    }

    /// True if any registered scheme would match `addr`.
    pub fn handles(&self, addr: &str) -> bool {
        scheme_of(addr)
            .map(|s| self.by_scheme.iter().any(|(scheme, _)| *scheme == s))
            .unwrap_or(false)
    }

    fn lookup(&self, addr: &str) -> Result<&std::sync::Arc<dyn Connector>, TransportError> {
        let scheme = scheme_of(addr).ok_or_else(|| {
            TransportError::ConnectError(format!(
                "MultiConnector: address has no scheme (expected '<scheme>://...'): {}",
                addr
            ))
        })?;
        self.by_scheme
            .iter()
            .find(|(s, _)| *s == scheme)
            .map(|(_, c)| c)
            .ok_or_else(|| {
                let known: Vec<&str> = self.by_scheme.iter().map(|(s, _)| *s).collect();
                TransportError::ConnectError(format!(
                    "MultiConnector: no connector for scheme '{}' (registered: [{}])",
                    scheme,
                    known.join(", ")
                ))
            })
    }
}

impl Default for MultiConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn scheme_of(addr: &str) -> Option<&str> {
    addr.find("://").map(|i| &addr[..i])
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl Connector for MultiConnector {
    async fn connect(&self, addr: &str) -> Result<Connection, TransportError> {
        let c = self.lookup(addr)?;
        // The pre-connect trace at `remote.rs:113` logs
        // `transport = connector.transport_type()` — which for
        // MultiConnector is the static "multi". Emit a trace here
        // naming the matched underlying connector so observers can
        // see the actual dispatch target without grepping the
        // registration site.
        tracing::trace!(
            addr = %addr,
            inner_transport = c.transport_type(),
            "MultiConnector: dispatching to underlying connector"
        );
        c.connect(addr).await
    }

    fn transport_type(&self) -> &'static str {
        // Forced to `&'static str` by the trait. Inspect
        // Connection.transport_type after connect() for the actual
        // transport, or look at the trace emitted in connect().
        "multi"
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
impl Connector for MultiConnector {
    async fn connect(&self, addr: &str) -> Result<Connection, TransportError> {
        let c = self.lookup(addr)?;
        tracing::trace!(
            addr = %addr,
            inner_transport = c.transport_type(),
            "MultiConnector: dispatching to underlying connector"
        );
        c.connect(addr).await
    }

    fn transport_type(&self) -> &'static str {
        "multi"
    }
}

// ---------------------------------------------------------------------------
// MessagePort transport (browser WASM cross-Worker)
// ---------------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
mod message_port {
    use super::*;
    use futures::channel::{mpsc, oneshot};
    use futures::stream::StreamExt;
    use js_sys::Uint8Array;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::pin::Pin;
    use std::rc::Rc;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen::JsCast;
    use web_sys::{MessageEvent, MessagePort};

    /// Wrapper that makes !Send/!Sync types satisfy the Send/Sync bounds
    /// expected by the Connection trait objects. WASM is single-threaded,
    /// so the bound is vacuously satisfied.
    struct SendWrapper<T>(T);
    unsafe impl<T> Send for SendWrapper<T> {}
    unsafe impl<T> Sync for SendWrapper<T> {}
    impl<T> SendWrapper<T> {
        fn get(&self) -> &T {
            &self.0
        }
        fn get_mut(&mut self) -> &mut T {
            &mut self.0
        }
    }

    /// Inbound message queue + retained onmessage closure. Dropping
    /// this drops the closure, which stops further dispatch from the
    /// port.
    struct PortReader {
        rx: SendWrapper<mpsc::UnboundedReceiver<Vec<u8>>>,
        // Retained for lifetime — when dropped, port stops dispatching.
        _on_message: SendWrapper<Closure<dyn FnMut(MessageEvent)>>,
        leftover: Vec<u8>,
        pos: usize,
    }

    impl AsyncRead for PortReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            // Drain leftover bytes from a previous oversized message first.
            if self.pos < self.leftover.len() {
                let remaining = &self.leftover[self.pos..];
                let n = remaining.len().min(buf.remaining());
                buf.put_slice(&remaining[..n]);
                self.pos += n;
                if self.pos >= self.leftover.len() {
                    self.leftover.clear();
                    self.pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            match self.rx.get_mut().poll_next_unpin(cx) {
                Poll::Ready(Some(data)) => {
                    // Zero-length frame is the close sentinel — surface as EOF.
                    if data.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    let n = data.len().min(buf.remaining());
                    buf.put_slice(&data[..n]);
                    if n < data.len() {
                        self.leftover = data;
                        self.pos = n;
                    }
                    Poll::Ready(Ok(()))
                }
                // Channel closed = other side dropped its port.
                Poll::Ready(None) => Poll::Ready(Ok(())),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    /// Writer side. Buffers writes until flush, then sends the
    /// accumulated buffer as a single Uint8Array postMessage. This
    /// matches `read_frame`/`write_frame`'s "one frame per flush"
    /// contract, identical to `BrowserWsWriter`.
    struct PortWriter {
        port: SendWrapper<MessagePort>,
        buf: Vec<u8>,
    }

    impl AsyncWrite for PortWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.buf.extend_from_slice(data);
            Poll::Ready(Ok(data.len()))
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.buf.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let arr = Uint8Array::new_with_length(self.buf.len() as u32);
            arr.copy_from(&self.buf);
            match self.port.get().post_message(&arr) {
                Ok(()) => {
                    self.buf.clear();
                    Poll::Ready(Ok(()))
                }
                Err(e) => Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    format!("MessagePort postMessage failed: {:?}", e),
                ))),
            }
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            // Flush remaining buffered bytes first.
            match self.as_mut().poll_flush(cx) {
                Poll::Ready(Ok(())) => {}
                other => return other,
            }
            // Send a zero-length frame as the close sentinel — the
            // peer's `PortReader` surfaces it as EOF. MessagePort has
            // no explicit close, so this is how we signal half-close
            // before the writer drops.
            let empty = Uint8Array::new_with_length(0);
            match self.port.get().post_message(&empty) {
                // Sentinel send failure is non-fatal — peer can still
                // discover the close via subsequent write failures.
                Ok(()) | Err(_) => Poll::Ready(Ok(())),
            }
        }
    }

    /// Wrap a single MessagePort as a Connection. Installs an
    /// onmessage handler that forwards binary payloads into a queue
    /// drained by the reader. The same port is used for outbound
    /// writes (MessagePort is bidirectional).
    pub fn connection_from_port(port: MessagePort, remote_addr: String) -> Connection {
        let (tx, rx) = mpsc::unbounded::<Vec<u8>>();

        let tx_for_closure = tx.clone();
        let on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let data = event.data();
            // Expect a Uint8Array (matches our Writer encoding). If
            // anything else arrives, drop it — the wire codec doesn't
            // accept text/structured payloads on this transport.
            if let Ok(arr) = data.dyn_into::<Uint8Array>() {
                let bytes = arr.to_vec();
                let _ = tx_for_closure.unbounded_send(bytes);
            }
        });

        port.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
        // `start()` is only required when the port was created via
        // `addEventListener`; with `onmessage` assignment it auto-starts.
        // Call it anyway to be defensive against ports that arrive
        // without their queue running.
        port.start();

        // Drop sender held inside reader path — keep only the closure-bound
        // copy so closing the port (closure dropped) closes the channel.
        drop(tx);

        let reader = PortReader {
            rx: SendWrapper(rx),
            _on_message: SendWrapper(on_message),
            leftover: Vec::new(),
            pos: 0,
        };
        let writer = PortWriter {
            port: SendWrapper(port),
            buf: Vec::new(),
        };

        Connection {
            reader: Box::new(reader),
            writer: Box::new(writer),
            remote_addr,
            transport_type: "xworker",
        }
    }

    // -----------------------------------------------------------------
    // Control plane — shared between MessagePortConnector / Listener
    // -----------------------------------------------------------------

    /// Wire format on the control port. CBOR-encoded as a Uint8Array
    /// alongside any transferred MessagePort in MessageEvent.ports().
    ///
    /// `OpenChannel.from_peer` and `IncomingChannel.to_peer` are
    /// symmetric: the source identifies itself on the way out, and
    /// the destination is named on the way in. The broker uses
    /// `from_peer` instead of closure-captured state — one handler
    /// per port, regardless of how many local peers share it. The
    /// destination Worker uses `to_peer` to demux the incoming
    /// channel to the right local listener.
    #[derive(serde::Serialize, serde::Deserialize, Debug)]
    #[serde(tag = "op")]
    pub enum ControlMessage {
        /// Connector → broker: "give me a port to peer_id, I'm
        /// from_peer." `from_peer` lets the broker source-route
        /// ChannelDenied responses back without needing a per-peer
        /// closure to capture the source identity.
        OpenChannel {
            request_id: u64,
            peer_id: String,
            from_peer: String,
        },
        /// Broker → connector: response to OpenChannel. The granted
        /// MessagePort arrives via MessageEvent::ports().
        ChannelGranted { request_id: u64 },
        /// Broker → connector: open failed.
        ChannelDenied { request_id: u64, reason: String },
        /// Broker → listener: "an incoming connection arrived". The
        /// MessagePort arrives via MessageEvent::ports(). `to_peer`
        /// identifies which local peer the connection is for so the
        /// receiving `ControlPortClient` can dispatch it to the right
        /// `MessagePortListener`.
        IncomingChannel { from_peer: String, to_peer: String },
    }

    /// Per-Worker control-port handler shared by the connector and
    /// listener. Multiplexes outbound OpenChannel requests via a
    /// pending-map, demultiplexes inbound IncomingChannel notifications
    /// into the listener's accept queue.
    pub struct ControlPortClient {
        port: SendWrapper<MessagePort>,
        next_request_id: RefCell<u64>,
        pending: Rc<RefCell<HashMap<u64, oneshot::Sender<Result<MessagePort, String>>>>>,
        /// Map of locally-bound listeners keyed by their endpoint
        /// (peer id). `MessagePortListener::bind` inserts; Drop
        /// removes. The onmessage closure looks up `to_peer` here on
        /// each `IncomingChannel` and routes the resulting Connection
        /// to the matching listener's accept queue.
        listeners: Rc<RefCell<HashMap<String, mpsc::UnboundedSender<Connection>>>>,
        _on_message: SendWrapper<Closure<dyn FnMut(MessageEvent)>>,
    }

    impl ControlPortClient {
        pub fn new(port: MessagePort) -> Rc<Self> {
            let pending: Rc<RefCell<HashMap<u64, oneshot::Sender<Result<MessagePort, String>>>>> =
                Rc::new(RefCell::new(HashMap::new()));
            let listeners: Rc<RefCell<HashMap<String, mpsc::UnboundedSender<Connection>>>> =
                Rc::new(RefCell::new(HashMap::new()));

            let pending_for_closure = pending.clone();
            let listeners_for_closure = listeners.clone();
            let on_message =
                Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
                    let data = event.data();
                    let bytes = match data.dyn_into::<Uint8Array>() {
                        Ok(arr) => arr.to_vec(),
                        Err(_) => return,
                    };
                    let msg: ControlMessage = match ciborium::from_reader(bytes.as_slice()) {
                        Ok(m) => m,
                        Err(_) => return,
                    };
                    match msg {
                        ControlMessage::ChannelGranted { request_id } => {
                            // The granted port is the first transferred port on the event.
                            let port = event
                                .ports()
                                .get(0)
                                .dyn_into::<MessagePort>()
                                .ok();
                            if let Some(tx) =
                                pending_for_closure.borrow_mut().remove(&request_id)
                            {
                                if let Some(p) = port {
                                    let _ = tx.send(Ok(p));
                                } else {
                                    let _ = tx.send(Err(
                                        "ChannelGranted with no transferred port".into(),
                                    ));
                                }
                            }
                        }
                        ControlMessage::ChannelDenied { request_id, reason } => {
                            if let Some(tx) =
                                pending_for_closure.borrow_mut().remove(&request_id)
                            {
                                let _ = tx.send(Err(reason));
                            }
                        }
                        ControlMessage::IncomingChannel { from_peer, to_peer } => {
                            let port = match event.ports().get(0).dyn_into::<MessagePort>() {
                                Ok(p) => p,
                                Err(_) => return,
                            };
                            let conn =
                                connection_from_port(port, format!("xworker://{}", from_peer));
                            match listeners_for_closure.borrow().get(&to_peer) {
                                Some(tx) => {
                                    let _ = tx.unbounded_send(conn);
                                }
                                None => {
                                    web_sys::console::warn_1(&wasm_bindgen::JsValue::from_str(
                                        &format!(
                                            "ControlPortClient: no listener bound for to_peer={} (from {}); dropping incoming channel",
                                            to_peer, from_peer
                                        ),
                                    ));
                                    // `port` drops here; remote sees handshake failure / EOF.
                                }
                            }
                        }
                        // Connectors don't receive OpenChannel — only the broker does.
                        ControlMessage::OpenChannel { .. } => {}
                    }
                });

            port.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
            port.start();

            Rc::new(Self {
                port: SendWrapper(port),
                next_request_id: RefCell::new(1),
                pending,
                listeners,
                _on_message: SendWrapper(on_message),
            })
        }

        /// Register a listener's inbound-connection sink under the
        /// given endpoint (typically the local peer's PeerID).
        /// Inserts into the demux map; replaces silently if the same
        /// endpoint is re-bound (paired with Drop in
        /// `MessagePortListener`).
        pub fn register_listener(
            &self,
            endpoint: String,
            sink: mpsc::UnboundedSender<Connection>,
        ) {
            self.listeners.borrow_mut().insert(endpoint, sink);
        }

        /// Remove a listener's endpoint from the demux map. Called by
        /// `MessagePortListener::Drop` so a dropped listener stops
        /// receiving incoming channels (subsequent traffic to that
        /// endpoint logs a warning and drops the port).
        pub fn unregister_listener(&self, endpoint: &str) {
            self.listeners.borrow_mut().remove(endpoint);
        }

        /// Maximum time `open_channel` waits for the broker to respond
        /// with `ChannelGranted` / `ChannelDenied`. If the broker or
        /// target Worker disappears mid-flight, the awaiter would
        /// otherwise hang forever; this caps the wait. 30 seconds is
        /// generous for legitimate round-trips (broker hop is sub-ms
        /// in practice) and short enough that a hung peer surfaces
        /// quickly. Hardcoded for now — callers don't currently need
        /// per-connect tuning.
        const OPEN_CHANNEL_TIMEOUT_MS: u32 = 30_000;

        /// Request a fresh transport channel to `peer_id` via the
        /// broker, identifying ourselves as `from_peer`. The broker
        /// echoes `from_peer` into the resulting `IncomingChannel`
        /// notification on the target side.
        ///
        /// Returns `TransportError::ConnectError("timeout …")` if the
        /// broker doesn't respond within `Self::OPEN_CHANNEL_TIMEOUT_MS`.
        /// The pending entry is removed from the map on timeout so a
        /// late response is dropped silently (rather than fed to an
        /// awaiter that no longer exists).
        pub async fn open_channel(
            &self,
            from_peer: &str,
            peer_id: &str,
        ) -> Result<MessagePort, TransportError> {
            let request_id = {
                let mut id = self.next_request_id.borrow_mut();
                let v = *id;
                // wrapping_add — pure paranoia (u64), but matches the
                // wasm-worker-proxy request-id allocator's pattern.
                *id = id.wrapping_add(1);
                v
            };
            let (tx, rx) = oneshot::channel();
            self.pending.borrow_mut().insert(request_id, tx);

            let msg = ControlMessage::OpenChannel {
                request_id,
                peer_id: peer_id.to_string(),
                from_peer: from_peer.to_string(),
            };
            let mut buf = Vec::new();
            ciborium::into_writer(&msg, &mut buf).map_err(|e| {
                TransportError::ConnectError(format!("control-port CBOR encode failed: {}", e))
            })?;
            let arr = Uint8Array::new_with_length(buf.len() as u32);
            arr.copy_from(&buf);
            self.port.get().post_message(&arr).map_err(|e| {
                self.pending.borrow_mut().remove(&request_id);
                TransportError::ConnectError(format!(
                    "control-port postMessage failed: {:?}",
                    e
                ))
            })?;

            // Race the broker response against a timeout. If the
            // broker / target Worker disappears mid-flight, this is
            // what bounds the wait. We clean up the pending entry on
            // timeout so a late response doesn't try to write to a
            // dead receiver (and so the map doesn't leak).
            use futures::future::{select, Either};
            let timeout = gloo_timers::future::TimeoutFuture::new(Self::OPEN_CHANNEL_TIMEOUT_MS);
            futures::pin_mut!(timeout);
            futures::pin_mut!(rx);
            match select(rx, timeout).await {
                Either::Left((Ok(Ok(port)), _)) => Ok(port),
                Either::Left((Ok(Err(reason)), _)) => {
                    Err(TransportError::ConnectError(reason))
                }
                Either::Left((Err(_), _)) => Err(TransportError::ConnectError(
                    "control-port response channel cancelled".into(),
                )),
                Either::Right((_, _)) => {
                    // Timeout fired. Drop the pending entry so a late
                    // ChannelGranted / ChannelDenied is ignored.
                    self.pending.borrow_mut().remove(&request_id);
                    Err(TransportError::ConnectError(format!(
                        "open_channel({}) timed out after {} ms",
                        peer_id, Self::OPEN_CHANNEL_TIMEOUT_MS
                    )))
                }
            }
        }
    }

    // -----------------------------------------------------------------
    // Connector + Listener
    // -----------------------------------------------------------------

    /// Worker-side outbound connector for cross-Worker peer connections.
    /// `connect("xworker://<peer-id>")` routes through the main-thread
    /// broker via the shared control port.
    ///
    /// **Per-peer.** Each local peer hosted in a Worker gets its own
    /// `MessagePortConnector` instance with its `source_peer_id` baked
    /// in at construction. The `ControlPortClient` is still shared
    /// across all peers in the Worker (one control port per Worker);
    /// it's the source-peer identity that varies. This is what lets
    /// the broker install one handler per port instead of per peer —
    /// `from_peer` rides the wire instead of being closure-captured.
    ///
    /// The `Connector` trait requires `Send + Sync` on the type even
    /// under `#[async_trait(?Send)]` (only the future relaxes Send).
    /// `Rc` is !Send/!Sync; SendWrapper makes the bound vacuously
    /// satisfied on single-threaded WASM.
    pub struct MessagePortConnector {
        control: SendWrapper<Rc<ControlPortClient>>,
        source_peer_id: String,
    }

    impl MessagePortConnector {
        pub fn new(control: Rc<ControlPortClient>, source_peer_id: impl Into<String>) -> Self {
            Self {
                control: SendWrapper(control),
                source_peer_id: source_peer_id.into(),
            }
        }
    }

    #[async_trait(?Send)]
    impl Connector for MessagePortConnector {
        async fn connect(&self, addr: &str) -> Result<Connection, TransportError> {
            let peer_id = addr.strip_prefix("xworker://").ok_or_else(|| {
                TransportError::ConnectError(format!(
                    "MessagePortConnector: expected xworker:// scheme, got {}",
                    addr
                ))
            })?;
            let port = self
                .control
                .get()
                .open_channel(&self.source_peer_id, peer_id)
                .await?;
            Ok(connection_from_port(port, format!("xworker://{}", peer_id)))
        }

        fn transport_type(&self) -> &'static str {
            "xworker"
        }
    }

    /// Worker-side listener that accepts cross-Worker connections
    /// pushed by the broker via the shared control port.
    ///
    /// Multiple listeners may share a single `ControlPortClient`; each
    /// registers itself under its `local_endpoint` (typically the
    /// local peer's PeerID) and receives only those `IncomingChannel`
    /// messages whose `to_peer` matches. Drop unregisters cleanly.
    pub struct MessagePortListener {
        local_endpoint: String,
        rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<Connection>>,
        // Retain a reference so the control port outlives the listener,
        // and so Drop can unregister this endpoint.
        control: SendWrapper<Rc<ControlPortClient>>,
    }

    impl MessagePortListener {
        /// Bind the listener against a `ControlPortClient` for the
        /// given local endpoint. Inbound channels whose `to_peer`
        /// matches `local_endpoint` arrive at this listener's
        /// `accept`. Re-binding the same endpoint silently replaces
        /// the prior sink (Drop on the prior listener removes it).
        pub fn bind(
            local_endpoint: impl Into<String>,
            control: Rc<ControlPortClient>,
        ) -> Self {
            let local_endpoint = local_endpoint.into();
            let (tx, rx) = mpsc::unbounded::<Connection>();
            control.register_listener(local_endpoint.clone(), tx);
            Self {
                local_endpoint,
                rx: tokio::sync::Mutex::new(rx),
                control: SendWrapper(control),
            }
        }
    }

    impl Drop for MessagePortListener {
        fn drop(&mut self) {
            self.control.get().unregister_listener(&self.local_endpoint);
        }
    }

    #[async_trait(?Send)]
    impl Listener for MessagePortListener {
        async fn accept(&self) -> Result<Connection, TransportError> {
            let conn = self.rx.lock().await.next().await.ok_or_else(|| {
                TransportError::AcceptError("MessagePortListener closed".into())
            })?;
            Ok(conn)
        }

        fn local_addr(&self) -> String {
            format!("xworker://{}", self.local_endpoint)
        }

        fn transport_type(&self) -> &'static str {
            "xworker"
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use message_port::{
    connection_from_port, ControlMessage, ControlPortClient, MessagePortConnector,
    MessagePortListener,
};
