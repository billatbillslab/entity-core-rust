//! Runtime-agnostic future + spawn primitives.
//!
//! The crate intentionally does not depend on any specific async
//! runtime (tokio, smol, wasm-bindgen-futures). Async verbs accept a
//! consumer-supplied spawner closure that drives the producer task
//! until completion; the verb constructs the `mpsc::Receiver` half
//! synchronously and hands it back inside `VerbOutput::Lines` /
//! `VerbOutput::Dispatch`.
//!
//! The `Send` bound on `BoxFuture` is cfg-gated — WASM single-threaded
//! environments produce non-Send futures (e.g., from
//! `wasm_bindgen_futures`), while native runtimes (tokio multi-threaded)
//! typically require Send. Embedding `Spawn` impls match the host
//! runtime's bound.

use std::future::Future;
use std::pin::Pin;

/// Boxed future used by async `PeerBinding` methods and by the
/// spawner closure consumers pass to streaming verbs. Native builds
/// require `Send` so the future can move into a multi-threaded
/// runtime; WASM builds drop the bound because `wasm_bindgen_futures`
/// produces non-Send futures.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;
