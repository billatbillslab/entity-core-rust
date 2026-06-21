# entity-wasm-worker-example

Reference wasm binary showing how to host an entity-core peer inside a Web Worker. The smallest thing that compiles + boots.

## What this is

A skeleton consumers can copy. The whole crate is one `#[wasm_bindgen(start)]` function calling `entity_wasm_worker_host::run_worker(Vec::new())`. Worker-side dispatch, init handshake, SDK construction, and subscription bridging all live in `entity-wasm-worker-host`; this crate just wires the wasm entry point.

## What this is NOT

A production worker binary. You'll typically want:

- A panic hook (`console_error_panic_hook`) so worker-side panics surface in DevTools instead of becoming opaque `RuntimeError` strings.
- A non-empty `Vec<HandlerFactory>` if your app exposes custom handlers beyond the SDK bootstrap set. (Phase 1.x — factory shape TBD; for Phase 3.0 pilots, `Vec::new()` is correct.)
- Your own trunk / wasm-bindgen build configuration matched to your project layout.

## Building (Rust side)

Compile-only check that the example links against `wasm-worker-host` cleanly:

```bash
cargo check --target wasm32-unknown-unknown -p entity-wasm-worker-example
```

To actually produce a runnable worker, you need a JS shim. The two common paths are trunk and wasm-pack. We don't run either ourselves — but here's what your consumer build needs to do.

## Path 1 — trunk (recommended for most apps)

In your consumer app's `index.html` (or wherever your trunk-rooted page lives):

```html
<link
  data-trunk
  rel="rust"
  data-bin="entity-wasm-worker-example"
  data-type="worker" />
```

Trunk emits to `dist/`:

- `entity-wasm-worker-example.js` — JS shim that `WebAssembly.instantiate`s the module and exposes `worker_main`
- `entity-wasm-worker-example_bg.wasm` — the WASM module itself

On the main thread, spawn the worker:

```rust
use entity_wasm_worker_proxy::WorkerProxy;
use entity_wasm_worker_protocol::{InitParams, PersistedPeer};

let init = InitParams {
    primary_peer: PersistedPeer {
        peer_id: your_peer_id,
        keypair_seed: your_32_byte_seed.to_vec(),
        label: Some("primary".into()),
    },
    additional_peers: vec![],
    handlers: vec![],   // empty for Phase 3.0 — SDK bootstrap covers basics
};

let proxy = WorkerProxy::spawn("/entity-wasm-worker-example.js", init).await?;
// proxy is ready; call proxy.get(peer_id, path).await, etc.
```

If your trunk config emits the worker at a different URL (some configs use hashed filenames), substitute that path.

### ESM workers

If your trunk JS shim uses `import` statements, the worker must be spawned as a module:

```rust
use web_sys::{Worker, WorkerOptions, WorkerType};

let mut opts = WorkerOptions::new();
opts.type_(WorkerType::Module);
let worker = Worker::new_with_options("/entity-wasm-worker-example.js", &opts)?;
let proxy = WorkerProxy::new(
    entity_wasm_worker_proxy::WebTransport::new(worker),
    init,
).await?;
```

`WorkerProxy::spawn` only handles classic-script workers; for modules, drop down to `new` + manual `Worker::new_with_options`.

## Path 2 — wasm-pack

```bash
wasm-pack build --target web bindings/wasm-worker-example
```

Emits a `pkg/` directory with the JS shim + wasm. Less integrated with a larger frontend build than trunk, but works if you're not using trunk.

Then in your consumer's main thread:

```js
import init, { worker_main } from "./pkg/entity_wasm_worker_example.js";
// ... see wasm-pack-as-worker patterns for the rest
```

## Customizing — adding a panic hook

Add to your fork's `Cargo.toml`:

```toml
[dependencies]
console_error_panic_hook = "0.1"
```

And to `lib.rs`:

```rust
#[wasm_bindgen(start)]
pub fn worker_main() {
    console_error_panic_hook::set_once();
    entity_wasm_worker_host::run_worker(Vec::new());
}
```

Strongly recommended. Without it, worker panics show up in DevTools as `RuntimeError: unreachable executed` with no stack trace.

## Customizing — adding custom handlers

This is Phase 1.x — the `HandlerFactory` shape isn't finalized yet. For Phase 3.0 pilots (Settings + Event Log) and most other windows, pass an empty Vec. The SDK's bootstrap handlers cover `system/tree`, `system/handler`, `system/protocol/connect`, `system/type`, and `system/capability` automatically.

When the factory shape lands in Phase 1.x, this README updates with the wiring pattern. Watch for changes in `entity-wasm-worker-host` crate docs.

## References

- `bindings/wasm-worker-host/src/lib.rs` — the library this example wraps. See its crate docs for the full `run_worker` contract.
- `bindings/wasm-worker-proxy/src/lib.rs` — main-thread side; `WorkerProxy::spawn` and `WorkerProxy::new` are the entry points.
- The worker-migration design context (internal design notes).
- The `HandlerFactory` Phase 1 / Phase 1.x split (internal design notes).
