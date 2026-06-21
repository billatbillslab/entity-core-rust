//! Platform-abstracted runtime primitives.
//!
//! Provides spawn and time functions that work on both native (tokio)
//! and WASM (wasm-bindgen-futures) targets.
//!
//! All spawned futures must be Send + 'static on native (tokio::spawn requires it).
//! On WASM, Send is not required but entity-core futures are Send anyway (Arc everywhere).

/// Spawn a future as a concurrent task.
#[cfg(not(target_arch = "wasm32"))]
pub fn spawn<F>(future: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(future);
}

/// Spawn a future as a concurrent task (WASM — runs on browser event loop).
#[cfg(target_arch = "wasm32")]
pub fn spawn<F>(future: F)
where
    F: std::future::Future<Output = ()> + 'static,
{
    wasm_bindgen_futures::spawn_local(future);
}
