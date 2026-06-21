//! Accept loop for transport listeners.
//!
//! Accepts connections from one or more Listeners (TCP, WebSocket,
//! MessagePort, etc.) and spawns a connection handler task for each.
//!
//! Native: spawned tasks are tracked so the accept loop can abort them
//! on cancellation. WASM: `wasm_bindgen_futures::spawn_local` returns no
//! handle — task lifetime is tied to the Worker's lifetime, which is
//! controlled by the consumer (drop the proxy / terminate the Worker
//! to stop everything). The WASM path therefore omits abort tracking.

use std::sync::Arc;

use crate::connection::handle_connection;
#[cfg(not(target_arch = "wasm32"))]
use crate::transport::TcpTransportListener;
use crate::transport::{Listener, TransportError};
use crate::{runtime, PeerError, PeerShared};

/// Bind a TCP listener on the given address (convenience wrapper).
#[cfg(not(target_arch = "wasm32"))]
pub async fn listen(addr: &str) -> Result<TcpTransportListener, PeerError> {
    TcpTransportListener::bind(addr)
        .await
        .map_err(|e| PeerError::ConnectionError(e.to_string()))
}

/// Aborts all tracked connection tasks on drop. Native-only — WASM
/// uses `spawn_local` (no handle) and relies on Worker termination.
#[cfg(not(target_arch = "wasm32"))]
struct ConnectionGuard {
    handles: Vec<tokio::task::JoinHandle<()>>,
}

#[cfg(not(target_arch = "wasm32"))]
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let active = self.handles.iter().filter(|h| !h.is_finished()).count();
        for handle in &self.handles {
            handle.abort();
        }
        if active > 0 {
            tracing::info!(active, "server stopped, connection tasks aborted");
        }
    }
}

/// Accept loop for a single listener: spawn a task per connection.
///
/// Native: tracks spawned tasks via a drop guard; aborts all active
/// tasks when the loop exits (listener error, task cancellation).
/// WASM: spawns via `runtime::spawn` (no tracking); tasks live until
/// Worker termination.
#[cfg(not(target_arch = "wasm32"))]
pub async fn run(
    listener: impl Listener,
    shared: Arc<PeerShared>,
) -> Result<(), PeerError> {
    let mut guard = ConnectionGuard { handles: Vec::new() };

    loop {
        let conn = listener
            .accept()
            .await
            .map_err(|e: TransportError| PeerError::ConnectionError(e.to_string()))?;

        tracing::info!(
            transport = conn.transport_type,
            remote = %conn.remote_addr,
            "accepted connection"
        );

        // Clean up finished handles periodically.
        guard.handles.retain(|h| !h.is_finished());

        let shared = shared.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) = handle_connection(conn, shared).await {
                tracing::warn!("connection closed with error: {}", e);
            } else {
                tracing::info!("connection closed normally");
            }
        });
        guard.handles.push(handle);
    }
}

/// Accept loop for a single listener (WASM). No JoinHandle tracking
/// because `spawn_local` doesn't return one; connection-task lifetime
/// is tied to the Worker.
#[cfg(target_arch = "wasm32")]
pub async fn run(
    listener: impl Listener,
    shared: Arc<PeerShared>,
) -> Result<(), PeerError> {
    loop {
        let conn = listener
            .accept()
            .await
            .map_err(|e: TransportError| PeerError::ConnectionError(e.to_string()))?;

        tracing::info!(
            transport = conn.transport_type,
            remote = %conn.remote_addr,
            "accepted connection"
        );

        let shared = shared.clone();
        runtime::spawn(async move {
            if let Err(e) = handle_connection(conn, shared).await {
                tracing::warn!("connection closed with error: {}", e);
            } else {
                tracing::info!("connection closed normally");
            }
        });
    }
}

/// Accept loop for multiple listeners concurrently (native).
#[cfg(not(target_arch = "wasm32"))]
pub async fn run_multi(
    listeners: Vec<Box<dyn Listener>>,
    shared: Arc<PeerShared>,
) -> Result<(), PeerError> {
    if listeners.is_empty() {
        return Err(PeerError::BuildError("no listeners provided".into()));
    }

    let mut handles = Vec::new();
    for listener in listeners {
        let shared = shared.clone();
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok(conn) => {
                        tracing::info!(
                            transport = conn.transport_type,
                            remote = %conn.remote_addr,
                            "accepted connection"
                        );
                        let shared = shared.clone();
                        runtime::spawn(async move {
                            if let Err(e) = handle_connection(conn, shared).await {
                                tracing::warn!("connection closed with error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("accept error: {}", e);
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle
            .await
            .map_err(|e| PeerError::ConnectionError(format!("listener task panicked: {}", e)))?;
    }
    Ok(())
}
