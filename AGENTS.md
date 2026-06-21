
# entity-core-rust

Read **AGENTS-STANDARD.md** first. This file adds entity-core-rust specifics.

## Overview

Rust implementation of Entity Core Protocol v7.9 — a clean rewrite replacing
`entity-core-rs`. This repo **implements** the spec; it does not design protocol.
Three deployment roles from one codebase: data toolkit, embedded peer, standalone
server. The crate DAG and design rationale live in `docs/ARCHITECTURE.md`; WASM
compatibility and the worker stack live in `docs/ARCHITECTURE-WASM-AND-TRANSPORT.md`
— this file does not repeat them.

## Setup / environment

- **Cargo workspace.** Build via `make` over podman (host needs only `make` + podman);
  see `Makefile` for the verb set — `make test` / `make clippy` / `make fmt` / `make wasm`.
- **Edition / MSRV:** edition 2021; toolchain pinned to **1.94.1** via `rust-toolchain.toml`
  (ships `clippy`, `rustfmt`, and the `wasm32-unknown-unknown` target).
- Cross-compile target for browser builds: `wasm32-unknown-unknown`.
- Idioms: `tokio` (async, base `features = ["sync"]`), `ciborium` (CBOR),
  `thiserror` (per-crate typed errors), `async-trait`. Godot binding: `gdext 0.4`;
  FFI: `cdylib` + `cbindgen`.

## Build & test

```bash
make test                      # full suite (cargo build + cargo test all)
make clippy                    # lint
make fmt                       # format
cargo test -p entity-core      # single crate (use -p <crate> for any other)
make wasm                      # wasm32 CI build (see below)
```

WASM CI build excludes `websocket` (tokio-tungstenite doesn't compile for wasm32):

```bash
cargo build --target wasm32-unknown-unknown -p entity-peer --no-default-features \
  --features "inbox,continuation,subscription,clock,revision,query,history,compute,handlers,identity,role,registry,discovery,type-system,content"
```

Add `-p entity-wasm-worker-host -p entity-wasm-worker-proxy -p entity-wasm-worker-protocol`
when touching the worker crates. `attestation`/`quorum` are transitive via `identity`
(list only when testing without identity). `local-files` MAY be enabled on wasm32 but is
conventionally left out for clarity. Check WASM only for changes to async/await, time,
networking, or spawn.

## Code style

- **Spec-first, minimal-diff.** Every decision traces to a spec section; read the passage
  before coding. No opportunistic refactors; closeout-tier tasks ship ~the proposed LOC.
- Errors: `thiserror` enums per crate, no string errors. Wire: **CBOR only** (no JSON).
  Concurrency: `tokio` + `Arc<RwLock<>>`.
- **WASM handler impls** use cfg-gated `async_trait`; use `web_time` not `std::time`. See
  `docs/ARCHITECTURE-WASM-AND-TRANSPORT.md` for the exact pattern and the worker-boundary rules.
- **Hot paths:** `SyncTreeHook`/`on_tree_change` engines MUST cache their decoded config in
  `RwLock<...>` and refresh only on events under their own config subtree — never
  `location_index.list()` + `content_store.get()` + decode per put (that was a 100×+
  regression). Canary: `core/peer/src/lib.rs::perf_treeput_1100` (`--release`).
- **SDK '`static` futures:** any `pub async fn(&self, ...)` on borrowed accessors
  (`IdentityOps`/`ComputeOps`/…) plumbed through a `BoxFuture<'static>` consumer trait must
  instead return `impl Future + Send + 'static` (drop `Send` on wasm32): capture Arcs/owned
  state up front, run in `async move`. `PeerContext` is not `Clone`. Retrofitting is a large
  refactor — reach for this shape from the start.

## Project structure

The strict crate DAG (a crate may import only crates above it; never introduce cycles)
is documented in `docs/ARCHITECTURE.md`. Two invariants that govern where changes may
land: only four extension-to-extension substrate edges are permitted (`quorum→attestation`,
`role→attestation`, `identity→attestation+quorum`, `relay→route`) — no others; and entity
storage (bootstrap, handler emit, tree put) goes through the single `emit()` path, never a
direct `store.put()`. Other key facts:

- `entity-core` is the facade crate re-exporting `core/*` as namespaced modules.
- `bindings/wasm-worker-*` crates are **wasm32-only** (`#![cfg(target_arch = "wasm32")]`).
- Naming: the L3 frontend team is **"Dom"**, not "EGUI".

## Boundaries — do NOT modify

- **No protocol design.** No new primitives, wire messages, or handler operations not in the
  spec; no pluggable validator registries / new hook types / new context fields to paper over
  a gap. Log ambiguities to `docs/SPEC-AMBIGUITIES.md` (exact passage + ambiguity + interim
  choice) and route upstream — don't invent a mechanism.
- `../entity-core-rs/` (old Rust impl) — **reference only**; do not replicate its patterns.
  `../entity-core-go/` and `../entity-core-py/` — interop context only; do not copy structure.
- **wasm-worker-\* crates must not affect native bindings.** Godot/FFI/CLI stay unaffected by
  worker changes (the crates are wasm32-only at lib root).
- **Private keys** belong only in the per-peer keystore (PEM on disk / OPFS / app config) or
  in a live in-memory `Keypair`. Never into bundles/exports/"portable" structs, capability or
  delegation chains, wire messages, logs, or anything `Serialize`/`Debug`-derived. When
  porting a Go field, confirm the Rust shape actually needs it (Bundle v1 shipped a vestigial
  `keypair_pem` — Go's ceremony-rerun shape needed it, Rust's entity-shape didn't).

## Protocol / interop invariants agents get wrong

Cross-impl wire fidelity. Same-side round-trip tests pass with the **wrong** shape too
(encoder + decoder agree); only a cross-impl validator catches these. Run
`validate-peer -category <touched>` on any wire-shape change.

- **Byte fidelity:** entity `data` must be preserved as-is — never decode+re-encode.
- **ECF is deterministic:** sorted keys, minimal integers, definite lengths (RFC 8949 §4.2).
- **Hash input is only `{type, data}`** — never the `content_hash` itself.
- **`system/hash` is always a 33-byte CBOR bstr** (`algorithm || digest`, 0x00 + 32-byte
  digest) — as a single field, array element, or map key. NOT a flat `{format_code, digest}`
  record and NOT a CBOR map. (§4.5 bstr-extension overrides §2.8's named-type→record rule.)
- **Typed-struct fields are bare CBOR maps**, not entity wrappers. Only fields typed
  `core/entity` (`result`, `params`) get the `{type, data, content_hash}` wrapper; fields
  typed as a specific struct (`deliver_to`, `bounds`, `durability`/`durability_request`) are
  bare maps. Reference: `core/peer/src/durability.rs::to_cbor` (encoder),
  `connection.rs::extract_deliver_to` (parser).
- **Optional fields SHOULD be absent** (key not present), not null (null is valid).
- **Signature signer field = `system/hash`** (content hash of the identity entity), not a
  `peer_id` string.
- **Capability `delegation_caveats` = flat struct**, not an array of objects.
- **Worker peer-scoping:** every peer-targeted `Request` variant MUST carry an explicit
  `peer_id: String` — never let "defaults to primary" be silent (see the v6 Subscribe fix).
  New fields on existing variants use `#[serde(default)]`; bump `PROTOCOL_VERSION` on any
  wire-shape change.
