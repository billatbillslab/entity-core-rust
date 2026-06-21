#![cfg(target_arch = "wasm32")]
//! Reference wasm binary that hosts an entity-core peer inside a Web Worker.
//!
//! This is the smallest crate that compiles + boots a worker. Real
//! consumers will adapt this skeleton — typically by:
//!
//! - Installing a panic hook (`console_error_panic_hook::set_once()`) so
//!   worker-side panics surface legibly in DevTools rather than as opaque
//!   `RuntimeError` strings.
//! - Passing a non-empty handler-factory Vec when their app exposes
//!   custom handlers beyond the SDK's bootstrap set (`system/tree`,
//!   `system/handler`, `system/protocol/connect`, `system/type`,
//!   `system/capability` — registered automatically by
//!   `EntitySDK::builder().build()` so most apps don't need anything more).
//! - Wiring their own trunk / wasm-bindgen / wasm-pack build configuration.
//!
//! See `README.md` in this directory for the trunk integration recipe.

use wasm_bindgen::prelude::*;

/// Worker entry point. wasm-bindgen calls this when the JS shim
/// instantiates the module.
///
/// Calls `run_worker(Vec::new())` — no custom handlers. SDK bootstrap
/// handlers cover the L1 surface for typical apps. The worker is then
/// driven entirely by postMessages from the main thread's `WorkerProxy`.
#[wasm_bindgen(start)]
pub fn worker_main() {
    entity_wasm_worker_host::run_worker(Vec::new());
}
