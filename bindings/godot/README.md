# Entity Core Godot — GDExtension Bindings

GDExtension plugin for Godot 4.2+ providing Entity Core Protocol primitives
as native Godot classes.

## Building

```bash
cargo build -p entity-core-godot --release
```

Output: `target/release/libentity_core_godot.{so,dylib,dll}`

## Installation

1. Copy the built library to your Godot project (e.g., `addons/entity_core/`).
2. Copy `entity_core.gdextension` alongside it.
3. Update the library paths in `.gdextension` to match your layout.
4. Reload the Godot project.

The `.gdextension` manifest declares:
- **Compatibility:** Godot 4.2+
- **Entry symbol:** `gdext_rust_init`
- **Reloadable:** yes

## Quick Start (GDScript)

```gdscript
extends Node

@onready var peer: EntityPeer = $EntityPeer

func _ready():
    # Configure and start
    peer.seed = PackedByteArray(range(32))  # 32-byte seed
    peer.listen_address = "127.0.0.1:9000"
    peer.start()
    print("PeerID: ", peer.peer_id())

    # Connect to tree change events
    peer.tree_changed.connect(_on_tree_changed)

    # Put an entity
    var data = EntityCbor.encode_text("hello world")
    var hash = peer.tree_put("my/path", "test/greeting", data)
    print("Stored hash: ", hash.hex_encode())

    # Get it back
    var entity: EntityData = peer.tree_get("my/path")
    print("Type: ", entity.entity_type)
    print("Data: ", EntityCbor.to_diag(entity.data))
    print("Valid: ", entity.validate())

    # Execute a handler directly
    var params_data = EntityCbor.encode_text("query")
    var result: EntityData = peer.execute(
        "system/tree", "get",
        "system/tree/get/params", params_data)
    if result:
        print("Result type: ", result.entity_type)

    # List tree paths
    var paths: PackedStringArray = peer.tree_list("my/")
    for p in paths:
        print("  ", p)

func _on_tree_changed(path: String, hash: PackedByteArray):
    print("Changed: ", path, " -> ", hash.hex_encode())

func _exit_tree():
    peer.stop()
```

## Classes

### EntityPeer (Node)

The main entry point. Manages a full Entity Core peer with identity, storage,
handlers, extension engines (clock, revision, subscription), and a TCP server.

Lifecycle: set properties, call `start()`, use tree/execute methods,
connect to signals, call `stop()` or remove from scene tree.

#### Properties

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `seed` | `PackedByteArray` | empty | 32-byte seed for deterministic Ed25519 keypair |
| `listen_address` | `String` | `"127.0.0.1:9000"` | TCP listen address for incoming connections |

#### Methods

**start() -> void**

Build the peer, start extension engines (clock, revision, subscription), set up
the event bridge, and spawn the TCP accept loop in the background.

- Requires `seed` to be exactly 32 bytes.
- Engines are started automatically (clock, revision, subscription if compiled with those features).
- Safe to call only once per lifecycle. Call `stop()` first to restart.

**stop() -> void**

Stop the peer and release all resources. The runtime and background tasks are dropped.

**peer_id() -> String**

Returns the Base58-encoded PeerID. Empty string if not started.

**tree_get(path: String) -> EntityData?**

Get an entity from the tree by path. Returns `null` if the path doesn't exist
or the peer isn't started.

**tree_put(path: String, entity_type: String, data: PackedByteArray) -> PackedByteArray**

Put an entity into the tree. `data` must be valid CBOR bytes.
Returns the 33-byte content hash, or an empty array on error.

**tree_list(prefix: String) -> PackedStringArray**

List all paths under a prefix. Returns a `PackedStringArray` of full paths.

**execute(handler: String, operation: String, params_type: String, params_data: PackedByteArray) -> EntityData?**

Execute a local handler operation. This dispatches through the same handler
resolution path as wire protocol requests, but without TCP, authentication,
or envelope framing.

Parameters:
- `handler` — handler path, e.g. `"system/tree"`
- `operation` — operation name, e.g. `"get"`
- `params_type` — entity type for the params, e.g. `"system/tree/get/params"`
- `params_data` — CBOR-encoded params data

Returns the result `EntityData`, or `null` on error.

Note: this blocks the main thread until the handler returns.
Fine for fast handlers (tree get/put), avoid for slow operations.

#### Signals

**tree_changed(path: String, hash: PackedByteArray)**

Emitted during `_process()` when a tree path changes. Events are buffered
from the async runtime and drained each frame, so there's no threading concern
in the signal handler.

- `path` — the full qualified path that changed
- `hash` — 33-byte content hash of the new entity (or the removed hash)

---

### EntityData (Resource)

A Godot Resource wrapping an entity's type, data, and content hash.
Returned by `EntityPeer.tree_get()` and `EntityPeer.execute()`.

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `entity_type` | `String` | Entity type (e.g. `"system/handler"`) |
| `data` | `PackedByteArray` | Raw CBOR data bytes |
| `content_hash` | `PackedByteArray` | 33-byte content hash |

#### Methods

**validate() -> bool**

Verify the content hash matches the entity type and data.
Returns `false` if the hash is wrong length or doesn't match.

---

### EntityCbor (RefCounted)

CBOR utility class. All methods are static — instantiate with
`EntityCbor.new()` or call directly if Godot supports static dispatch.

#### Methods

**to_diag(data: PackedByteArray) -> String**

Convert CBOR bytes to human-readable diagnostic notation (RFC 8949 Section 8).

```gdscript
var diag = EntityCbor.to_diag(entity.data)
# e.g.: {"name": "tree", "pattern": "system/tree"}
```

**from_diag(diag: String) -> PackedByteArray**

Parse CBOR diagnostic notation back into bytes.

```gdscript
var bytes = EntityCbor.from_diag('{"key": "value"}')
```

**encode_text(text: String) -> PackedByteArray**

Encode a text string as deterministic CBOR (ECF).

```gdscript
var data = EntityCbor.encode_text("hello")
peer.tree_put("my/path", "test/type", data)
```

**compute_hash(entity_type: String, data: PackedByteArray) -> PackedByteArray**

Compute the 33-byte content hash for a type + data pair without creating an entity.

## Architecture Notes

### Event Bridge

Tree change events originate in the async tokio runtime (background threads).
The event bridge forwards them to the Godot main thread:

```
tokio broadcast channel
    → tokio task (recv loop)
        → std::sync::mpsc channel
            → EntityPeer._process() (drain + emit signal)
```

This means:
- Signals are emitted during `_process()`, not at the instant of change.
- Multiple events may batch into a single frame.
- If the game is paused (`_process` not running), events queue up.

### Peer-Qualified Paths

All tree paths are internally qualified with the PeerID:
`{peer_id}/system/tree`, not just `system/tree`.

When using `tree_get`/`tree_put`/`tree_list`, you can pass either:
- Bare paths: `"system/tree"` (auto-qualified internally by handlers)
- Qualified paths: `"{peer_id}/system/tree"` (used as-is)

The `tree_changed` signal always emits fully qualified paths.

### Extension Engines

If compiled with default features (the default), the peer includes:
- **Clock engine** — advances logical/vector/HLC clocks on tree writes
- **Sync engine** — auto-versions tree writes for configured prefixes
- **Subscription engine** — delivers notifications for subscribed patterns

These start automatically in `start()`. No additional configuration needed
for basic use.
