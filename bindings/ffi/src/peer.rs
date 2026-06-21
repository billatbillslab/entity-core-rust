//! Tier 4: Peer lifecycle — create, start, stop, tree get/put, execute, events.

use crate::entity::ENTITIES;
use crate::error::set_last_error;
use crate::handles::HandleMap;
use crate::types::{EntityCoreBuffer, EntityCoreError, Handle};

use std::sync::LazyLock;

/// A running peer with its own tokio runtime.
pub(crate) struct FfiPeer {
    pub runtime: tokio::runtime::Runtime,
    pub peer: entity_peer::Peer,
}

static PEERS: LazyLock<HandleMap<FfiPeer>> = LazyLock::new(HandleMap::new);

/// An event subscription — receives tree change events from a peer.
/// Wrapped in Mutex because std::sync::mpsc::Receiver is !Sync.
pub(crate) struct FfiSubscription {
    rx: std::sync::Mutex<std::sync::mpsc::Receiver<(String, Vec<u8>)>>,
}

static SUBSCRIPTIONS: LazyLock<HandleMap<FfiSubscription>> = LazyLock::new(HandleMap::new);

/// Global tokio runtime for FFI operations (created at init, dropped at shutdown).
static RUNTIME: LazyLock<std::sync::Mutex<Option<tokio::runtime::Runtime>>> =
    LazyLock::new(|| std::sync::Mutex::new(None));

/// Initialize the FFI runtime. Must be called before any peer operations.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn entity_core_init() -> i32 {
    ffi_fn!({
        match tokio::runtime::Runtime::new() {
            Ok(rt) => {
                *RUNTIME.lock().unwrap() = Some(rt);
                0
            }
            Err(e) => {
                set_last_error(&format!("runtime init failed: {}", e));
                -1
            }
        }
    }, -1)
}

/// Shutdown the FFI runtime. Call when done with the library.
#[no_mangle]
pub extern "C" fn entity_core_shutdown() {
    let _ = RUNTIME.lock().unwrap().take();
}

/// Get the library version string.
#[no_mangle]
pub extern "C" fn entity_core_version() -> EntityCoreBuffer {
    ffi_fn!({
        EntityCoreBuffer::from_vec(b"entity-core-ffi/0.1.0".to_vec())
    })
}

/// Create a new peer from a 32-byte seed. Returns a handle, or 0 on error.
///
/// Uses the global runtime created by `entity_core_init()`.
///
/// # Safety
/// `seed_ptr` must point to 32 bytes. `addr_ptr`/`addr_len` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn entity_core_peer_create(
    seed_ptr: *const u8,
    addr_ptr: *const u8,
    addr_len: usize,
) -> Handle {
    ffi_fn!({
        let seed = unsafe { std::slice::from_raw_parts(seed_ptr, 32) };
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(seed);

        let addr = match unsafe {
            std::str::from_utf8(std::slice::from_raw_parts(addr_ptr, addr_len))
        } {
            Ok(s) => s,
            Err(e) => {
                set_last_error(&format!("invalid UTF-8 address: {}", e));
                return 0;
            }
        };

        let runtime = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                set_last_error(&format!("runtime creation failed: {}", e));
                return 0;
            }
        };

        let keypair = entity_crypto::Keypair::from_seed(seed_arr);
        match entity_peer::PeerBuilder::new()
            .keypair(keypair)
            .listen_addr(addr)
            .build()
        {
            Ok(peer) => PEERS.insert(FfiPeer { runtime, peer }),
            Err(e) => {
                set_last_error(&format!("peer build failed: {}", e));
                0
            }
        }
    })
}

/// Free a peer handle (stops the peer if running).
#[no_mangle]
pub extern "C" fn entity_core_peer_free(handle: Handle) {
    let _ = PEERS.remove(handle);
}

/// Get the peer's PeerID string.
#[no_mangle]
pub extern "C" fn entity_core_peer_id(handle: Handle) -> EntityCoreBuffer {
    ffi_fn!({
        match PEERS.with(handle, |p| p.peer.peer_id().to_string()) {
            Some(pid) => EntityCoreBuffer::from_vec(pid.into_bytes()),
            None => {
                set_last_error("invalid peer handle");
                EntityCoreBuffer::null()
            }
        }
    })
}

/// Start the peer listening (non-blocking — spawns in background).
///
/// Starts extension engines (clock, sync, subscription) and the TCP accept loop.
/// Returns 0 on success.
#[no_mangle]
pub extern "C" fn entity_core_peer_start(handle: Handle) -> EntityCoreError {
    ffi_fn!({
        match PEERS.with(handle, |p| {
            let listener = p.runtime.block_on(p.peer.listen());
            match listener {
                Ok(listener) => {
                    let shared = p.peer.shared();
                    let _guard = p.runtime.enter();
                    p.peer.start_engines(&shared);
                    p.runtime.spawn(async move {
                        let _ = entity_peer::server::run(listener, shared).await;
                    });
                    EntityCoreError::Ok
                }
                Err(e) => {
                    set_last_error(&format!("listen failed: {}", e));
                    EntityCoreError::NetworkError
                }
            }
        }) {
            Some(e) => e,
            None => {
                set_last_error("invalid peer handle");
                EntityCoreError::InvalidArgument
            }
        }
    }, EntityCoreError::InternalError)
}

/// Execute a local handler operation. Returns an entity handle for the result, or 0 on error.
///
/// `params_entity` is consumed (freed) by this call.
///
/// # Safety
/// `handler_ptr`/`handler_len` and `operation_ptr`/`operation_len` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn entity_core_execute(
    peer_handle: Handle,
    handler_ptr: *const u8,
    handler_len: usize,
    operation_ptr: *const u8,
    operation_len: usize,
    params_entity: Handle,
) -> Handle {
    ffi_fn!({
        let handler = match unsafe {
            std::str::from_utf8(std::slice::from_raw_parts(handler_ptr, handler_len))
        } {
            Ok(s) => s,
            Err(e) => {
                set_last_error(&format!("invalid UTF-8 handler: {}", e));
                return 0;
            }
        };
        let operation = match unsafe {
            std::str::from_utf8(std::slice::from_raw_parts(operation_ptr, operation_len))
        } {
            Ok(s) => s,
            Err(e) => {
                set_last_error(&format!("invalid UTF-8 operation: {}", e));
                return 0;
            }
        };

        let params = match ENTITIES.remove(params_entity) {
            Some(e) => e,
            None => {
                set_last_error("invalid params entity handle");
                return 0;
            }
        };

        match PEERS.with(peer_handle, |p| {
            p.runtime.block_on(p.peer.execute(handler, operation, params))
        }) {
            Some(Ok(result)) => ENTITIES.insert(result.result),
            Some(Err(e)) => {
                set_last_error(&format!("execute failed: {}", e));
                0
            }
            None => {
                set_last_error("invalid peer handle");
                0
            }
        }
    })
}

/// Subscribe to tree change events for a peer.
/// Returns a subscription handle, or 0 on error.
///
/// Use `entity_core_poll_event()` to poll events and
/// `entity_core_unsubscribe()` to free the subscription.
#[no_mangle]
pub extern "C" fn entity_core_subscribe(peer_handle: Handle) -> Handle {
    ffi_fn!({
        match PEERS.with(peer_handle, |p| {
            let (tx, rx) = std::sync::mpsc::channel();
            let mut events = p.peer.subscribe_events();
            p.runtime.spawn(async move {
                while let Ok(evt) = events.recv().await {
                    let hash_bytes = evt.hash.to_bytes().to_vec();
                    if tx.send((evt.path, hash_bytes)).is_err() {
                        break;
                    }
                }
            });
            SUBSCRIPTIONS.insert(FfiSubscription { rx: std::sync::Mutex::new(rx) })
        }) {
            Some(handle) => handle,
            None => {
                set_last_error("invalid peer handle");
                0
            }
        }
    })
}

/// Poll for the next event from a subscription (non-blocking).
///
/// Returns a buffer containing `path\0hash_bytes` (path as UTF-8, null byte separator,
/// then 33 hash bytes). Returns a null buffer if no events are pending.
#[no_mangle]
pub extern "C" fn entity_core_poll_event(sub_handle: Handle) -> EntityCoreBuffer {
    ffi_fn!({
        match SUBSCRIPTIONS.with(sub_handle, |s| s.rx.lock().unwrap().try_recv().ok()) {
            Some(Some((path, hash_bytes))) => {
                let mut buf = path.into_bytes();
                buf.push(0); // null separator
                buf.extend_from_slice(&hash_bytes);
                EntityCoreBuffer::from_vec(buf)
            }
            _ => EntityCoreBuffer::null(),
        }
    })
}

/// Free a subscription handle.
#[no_mangle]
pub extern "C" fn entity_core_unsubscribe(sub_handle: Handle) {
    let _ = SUBSCRIPTIONS.remove(sub_handle);
}

/// Get an entity from the tree by path.
///
/// # Safety
/// `path_ptr`/`path_len` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn entity_core_tree_get(
    handle: Handle,
    path_ptr: *const u8,
    path_len: usize,
) -> Handle {
    ffi_fn!({
        let path = match unsafe {
            std::str::from_utf8(std::slice::from_raw_parts(path_ptr, path_len))
        } {
            Ok(s) => s,
            Err(e) => {
                set_last_error(&format!("invalid UTF-8 path: {}", e));
                return 0;
            }
        };
        match PEERS.with(handle, |p| p.peer.tree().get(path)) {
            Some(Some(entity)) => ENTITIES.insert(entity),
            Some(None) => {
                set_last_error("not found");
                0
            }
            None => {
                set_last_error("invalid peer handle");
                0
            }
        }
    })
}

/// Put an entity into the tree at a path. Returns the 33-byte content hash.
///
/// # Safety
/// `path_ptr`/`path_len` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn entity_core_tree_put(
    peer_handle: Handle,
    path_ptr: *const u8,
    path_len: usize,
    entity_handle: Handle,
) -> EntityCoreBuffer {
    ffi_fn!({
        let path = match unsafe {
            std::str::from_utf8(std::slice::from_raw_parts(path_ptr, path_len))
        } {
            Ok(s) => s,
            Err(e) => {
                set_last_error(&format!("invalid UTF-8 path: {}", e));
                return EntityCoreBuffer::null();
            }
        };

        let entity = match ENTITIES.remove(entity_handle) {
            Some(e) => e,
            None => {
                set_last_error("invalid entity handle");
                return EntityCoreBuffer::null();
            }
        };

        match PEERS.with(peer_handle, |p| p.peer.tree().put(path, entity)) {
            Some(Ok(hash)) => EntityCoreBuffer::from_vec(hash.to_bytes().to_vec()),
            Some(Err(e)) => {
                set_last_error(&format!("put failed: {}", e));
                EntityCoreBuffer::null()
            }
            None => {
                set_last_error("invalid peer handle");
                EntityCoreBuffer::null()
            }
        }
    })
}

/// List paths under a prefix. Returns a null-separated list of path strings.
///
/// # Safety
/// `prefix_ptr`/`prefix_len` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn entity_core_tree_list(
    handle: Handle,
    prefix_ptr: *const u8,
    prefix_len: usize,
) -> EntityCoreBuffer {
    ffi_fn!({
        let prefix = match unsafe {
            std::str::from_utf8(std::slice::from_raw_parts(prefix_ptr, prefix_len))
        } {
            Ok(s) => s,
            Err(e) => {
                set_last_error(&format!("invalid UTF-8 prefix: {}", e));
                return EntityCoreBuffer::null();
            }
        };
        match PEERS.with(handle, |p| p.peer.tree().list(prefix)) {
            Some(entries) => {
                let joined = entries
                    .iter()
                    .map(|entry| entry.path.as_str())
                    .collect::<Vec<_>>()
                    .join("\0");
                EntityCoreBuffer::from_vec(joined.into_bytes())
            }
            None => {
                set_last_error("invalid peer handle");
                EntityCoreBuffer::null()
            }
        }
    })
}
