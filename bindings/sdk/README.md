# entity-sdk

Application SDK for entity-core-rust. The Rust-native consumption surface
for entity-core: `EntitySDK`, `PeerContext`, scope handles, subscription
helpers, handler registration. Frontend bindings (egui, Godot, Tauri, etc.)
depend on this crate; they do not depend on the kernel crates directly.

## Discipline

This crate is intentionally narrow. Things that belong here:

- `EntitySDK` (multi-peer container) and `PeerContext` (per-peer access).
- Tree access via L0 (`store()`) and L1 (`get`/`put`/`list`/`has`/`remove`).
- Generic `execute()` and handler discovery.
- `register_handler` helpers for tree-paired handler lifecycle.
- L1 `subscription` primitives (subscribe / unsubscribe wrapping
  `system/subscription`).
- `peer_manager` multi-peer container with `PersistedPeer` value type.
- Change-event broadcast.

Things that do **not** belong here, even when an app needs them:

- App-flavored namespace constants (`app/entity-browser/...`,
  `app/{app-id}/workspace/...`). Apps own their path conventions in
  app-side code (e.g. egui's `app_paths.rs`).
- Persistence I/O. The SDK accepts `Vec<PersistedPeer>` via
  `PeerManager::load_persisted`; apps own where keys live (filesystem,
  localStorage, SQLite, platform key store, Godot data dir).
- Renderer or runtime types. No `eframe`, `web-sys`, `gdext`, `raylib`,
  `tview`, etc. — transitively. CI builds the crate standalone with no
  extra deps to verify this.
- App-layer wrappers for binding ergonomics. Godot's GDExtension wraps
  SDK types in gdext-friendly classes inside `bindings/godot/`; the
  wrapping doesn't leak back here.

## Cargo features

Pass-through to `entity-peer` extension flags 1:1:

| Feature | Enables |
|---|---|
| `inbox`, `continuation`, `subscription`, `clock`, `revision`, `query` | Default extension set |
| `history`, `compute`, `handlers` | Optional extensions |
| `attestation`, `quorum`, `identity`, `role` | Identity stack |
| `native-ws` | Native-only WebSocket transport (excluded on WASM) |

WASM consumers must NOT enable `native-ws` — entity-peer's `websocket`
feature pulls in `tokio-tungstenite` which doesn't compile on wasm32.
WASM peers use the always-available `BrowserWebSocketConnector` without
any feature flag.

## API stability

`0.1.0` — pre-1.0, but the core consumption surface is **shape-stable**.
SemVer commitments land at T2 graduation (cross-impl schema alignment;
see the joint convention doc in entity-workbench-go). Until then,
breaks are possible but the items below are unlikely to change in
shape — name, signature, semantics — without coordination across
consumers.

### Consume freely (shape-stable)

These are the methods Godot, egui, and other consumers can wrap or call
directly without expecting churn:

- **`EntitySDK`**: `new`, `peers`, `peer_context`, `peer_context_or_default`,
  `peer_ids`, `primary`, `has_peer`, `register_peer`, `deregister_peer`.
- **`PeerContext`** L0 access: `store()` (direct `ContentStore` /
  `LocationIndex` — explicit security-boundary opt-out, that property
  is invariant).
- **`PeerContext`** L1 dispatched ops: `get`, `put`, `has`, `remove`,
  `list` — all route through `system/tree` and respect capabilities.
- **`PeerContext`** dispatch + discovery: `execute`,
  `execute_with_options`, `discover_handlers`.
- **`PeerContext`** identity / state: `peer_id()`, `shared()`,
  `generation()`.
- **Change events**: `subscribe_changes` (broadcast receiver of tree
  changes — drives snapshot-rebuild patterns).
- **`PeerManager`**: `load_persisted`, `peer_shared`, change-event wiring.
- **`PersistedPeer`** value type.
- **`SdkError`** variants.
- **Path semantics**: full qualified paths with leading slash and
  `peer_id` prefix (`/{peer_id}/...`). The SDK does not strip or rewrite.

### Coordinate before relying on (in flux)

- **`register_handler`** helpers — tree-paired handler lifecycle is
  stable, but the **identity-roles refactor in flight upstream** (see
  `entity-core-rust` commits touching handler grants) may reshape the
  grant-issuance side. Wrap behind your binding's interface rather than
  exposing 1:1.
- **L1 `subscription`** primitives (`subscribe` / `unsubscribe`) — the
  delivery path and token chain are stable; the params shape may grow
  filter affordances during T3.
- **`PeerContext::scope(prefix)`** — generic prefix-bound helper. Stable
  shape; potential additions to the returned handle's method set during
  T3.
- **Compare-and-swap put** and advanced tree ops — surface may grow.
- **Schema types** for content-categories (`tree-browser`,
  `entity-detail`, `execute-console`, `event-log`) may land as exports
  here at T2; coordinate before re-deriving.

### Active normalization

Daily "SDK Norm update" commits in egui-entity-core-rust through
April-May 2026 reflect signature polish (trait bounds, `Send` /
`'static` discipline, error variants). Behavior is unchanged; binding
wrappers may need recompilation but not redesign.

## Consumers

- `egui-entity-core-rust` — eframe / WASM / Tauri (path dep across
  workspace boundary).
- `bindings/godot` — Godot 4 GDExtension via gdext (workspace dep).
- `bindings/ffi` — C ABI (likely consumer; current usage TBD).

## Origin

Lifted from `egui-entity-core-rust/src/{sdk,register_handler,subscription,peer_manager}.rs`
per `godot-entity-core-rust/docs/PROPOSAL-SDK-EXTRACTION.md`.
