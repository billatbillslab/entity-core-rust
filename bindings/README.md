# Entity Core Bindings

Language bindings for embedding Entity Core Protocol peers in non-Rust applications.

| Binding | Target | Library Type | Docs |
|---------|--------|-------------|------|
| [C FFI](ffi/) | C, C++, Python (ctypes), any FFI-capable language | cdylib + C header | [ffi/README.md](ffi/README.md) |
| [Godot](godot/) | Godot 4.2+ (GDScript, C#) | GDExtension | [godot/README.md](godot/README.md) |

## Building

Both bindings are workspace members but not default members, so they don't
build with `cargo build`. Build them explicitly:

```bash
# FFI (produces .so/.dylib/.dll + auto-generated C header)
cargo build -p entity-core-ffi --release

# Godot (produces .so/.dylib/.dll for GDExtension)
cargo build -p entity-core-godot --release
```

Core crate tests still work unchanged:

```bash
cargo test     # runs all core + extension tests (not bindings)
cargo clippy   # lints core + extensions
```

## What You Get

Both bindings provide a **fully functional peer** — not just tree read/write,
but the complete protocol stack:

- **Identity** — Ed25519 keypair, PeerID
- **Storage** — content-addressed entity store + location index
- **Tree** — get, put, list (path-to-hash mapping)
- **Handlers** — all bootstrap handlers (tree, connect, types, etc.)
- **Extension engines** — clock, revision, subscription (auto-started)
- **TCP server** — accepts incoming protocol connections
- **Local execution** — dispatch to handlers without wire protocol
- **Event subscription** — receive tree change notifications

## Extension Features

The peer crate has optional features for extension handlers. All are enabled
by default:

```bash
# Build with all extensions (default)
cargo build -p entity-core-ffi --release

# Build core-only (no clock, revision, subscription, inbox, continuation)
cargo build -p entity-core-ffi --release --no-default-features
```

| Feature | Handler | Engine |
|---------|---------|--------|
| `inbox` | system/inbox | - |
| `continuation` | system/continuation | - |
| `subscription` | system/subscription | Subscription delivery |
| `clock` | system/clock | Clock advancement on writes |
| `revision` | system/revision | Auto-versioning on writes |

## Core Peer API

Both bindings use these `Peer` methods from the `entity-peer` crate:

```rust
let peer = PeerBuilder::new()
    .keypair(keypair)
    .listen_addr("127.0.0.1:9000")
    .build()?;

// Composable startup (used by bindings)
let shared = peer.shared();              // Arc<PeerShared>
peer.start_engines(&shared);             // clock, revision, subscription
let (listener, addr) = peer.listen().await?;
tokio::spawn(server::run(listener, shared));

// Local dispatch
let result = peer.execute("system/tree", "get", params).await?;
let result = peer.execute_with_options("system/tree", "put", params, opts).await?;

// Events
let mut rx = peer.subscribe_events();
while let Ok(evt) = rx.recv().await {
    println!("{}: {:?}", evt.path, evt.hash);
}

// Or all-in-one (blocks forever)
peer.run(listener).await?;
```

`start_engines()` is idempotent — safe to call multiple times.
