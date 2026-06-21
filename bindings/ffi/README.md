# Entity Core FFI — C Bindings

C-compatible shared library (`.so` / `.dylib` / `.dll`) for the Entity Core Protocol.
Auto-generates a C header via cbindgen.

## Building

```bash
cargo build -p entity-core-ffi --release
```

Output:
- **Library:** `target/release/libentity_core_ffi.{so,dylib,dll}`
- **Header:** `bindings/ffi/include/entity_core_ffi.h` (auto-generated on build)

Link with `-lentity_core_ffi` and include the header.

## Quick Start

```c
#include "entity_core_ffi.h"
#include <stdio.h>
#include <string.h>

int main() {
    // 1. Initialize runtime
    entity_core_init();

    // 2. Create a peer
    uint8_t seed[32] = {0};  // deterministic seed
    const char *addr = "127.0.0.1:9000";
    EntityCoreHandle peer = entity_core_peer_create(
        seed, (const uint8_t *)addr, strlen(addr));

    // 3. Get PeerID
    EntityCoreBuffer pid = entity_core_peer_id(peer);
    printf("PeerID: %.*s\n", (int)pid.len, pid.data);
    entity_core_buffer_free(pid);

    // 4. Start listening + engines
    entity_core_peer_start(peer);

    // 5. Put an entity into the tree
    const char *type = "test/greeting";
    uint8_t cbor_hello[] = {0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f}; // "hello"
    EntityCoreHandle entity = entity_new(
        (const uint8_t *)type, strlen(type),
        cbor_hello, sizeof(cbor_hello));

    const char *path = "my/greeting";
    EntityCoreBuffer hash = entity_core_tree_put(
        peer,
        (const uint8_t *)path, strlen(path),
        entity);  // entity handle is consumed
    entity_core_buffer_free(hash);

    // 6. Get it back
    EntityCoreHandle got = entity_core_tree_get(
        peer, (const uint8_t *)path, strlen(path));
    EntityCoreBuffer data = entity_get_data(got);
    printf("Data: %zu bytes\n", data.len);
    entity_core_buffer_free(data);
    entity_free(got);

    // 7. Execute a handler
    const char *handler = "system/tree";
    const char *operation = "get";
    // Build params entity with path
    EntityCoreHandle params = entity_new(
        (const uint8_t *)"system/tree/get/params", 22,
        cbor_hello, sizeof(cbor_hello));  // simplified
    EntityCoreHandle result = entity_core_execute(
        peer,
        (const uint8_t *)handler, strlen(handler),
        (const uint8_t *)operation, strlen(operation),
        params);  // params consumed
    if (result) entity_free(result);

    // 8. Subscribe to events
    EntityCoreHandle sub = entity_core_subscribe(peer);
    // In your event loop:
    EntityCoreBuffer evt = entity_core_poll_event(sub);
    if (evt.data) {
        // evt.data = "path\0<33 hash bytes>"
        entity_core_buffer_free(evt);
    }
    entity_core_unsubscribe(sub);

    // 9. Cleanup
    entity_core_peer_free(peer);
    entity_core_shutdown();
    return 0;
}
```

## API Reference

### Conventions

- **Handles** (`EntityCoreHandle` = `uint64_t`): opaque references to Rust objects. `0` means error/null.
- **Buffers** (`EntityCoreBuffer`): owned byte arrays. Caller **must** free with `entity_core_buffer_free()`.
- **Errors**: functions return `EntityCoreError` or `0`-handle on failure. Call `entity_core_last_error()` for details.
- **Consuming**: some functions consume (free) input handles — noted below.
- **Safety**: all `const uint8_t *` / `uintptr_t len` pairs must point to valid memory. String pointers must be valid UTF-8.

### Error Handling

```c
const char *entity_core_last_error(void);
```
Thread-local error message from the last failed call. Returns `NULL` if no error. Valid until the next FFI call on the same thread.

```c
void entity_core_buffer_free(EntityCoreBuffer buf);
```
Free a buffer returned by any FFI function. Call exactly once.

### EntityCoreError Codes

| Code | Name | Value |
|------|------|-------|
| Ok | Success | 0 |
| InvalidArgument | Bad input | 1 |
| NotFound | Not found | 2 |
| PermissionDenied | Auth failure | 3 |
| StorageError | Store failure | 4 |
| NetworkError | Network failure | 5 |
| EncodingError | CBOR/ECF error | 6 |
| CryptoError | Crypto failure | 7 |
| InternalError | Unexpected | 99 |

---

### Tier 0: ECF (Deterministic CBOR)

Build CBOR values, encode to deterministic ECF bytes, decode back.

#### Value Builders

All return `EntityCoreHandle` (0 on error). Free with `ecf_value_free()` or pass to `ecf_encode()` (which consumes).

```c
EntityCoreHandle ecf_value_text(const uint8_t *ptr, uintptr_t len);
EntityCoreHandle ecf_value_bytes(const uint8_t *ptr, uintptr_t len);
EntityCoreHandle ecf_value_integer(int64_t val);
EntityCoreHandle ecf_value_bool(bool val);
EntityCoreHandle ecf_value_null(void);
EntityCoreHandle ecf_value_float(double val);
EntityCoreHandle ecf_value_array(const EntityCoreHandle *handles, uintptr_t count);
EntityCoreHandle ecf_value_map_new(void);
```

#### Map Operations

```c
// Insert key-value pair. Consumes key and value handles.
EntityCoreError ecf_value_map_insert(EntityCoreHandle map,
                                     EntityCoreHandle key,
                                     EntityCoreHandle value);
```

#### Encoding & Decoding

```c
void             ecf_value_free(EntityCoreHandle handle);
EntityCoreBuffer ecf_encode(EntityCoreHandle handle);      // consumes handle
EntityCoreHandle ecf_decode(const uint8_t *ptr, uintptr_t len);
EntityCoreBuffer ecf_to_diag(const uint8_t *ptr, uintptr_t len);   // CBOR → diagnostic string
EntityCoreBuffer ecf_from_diag(const uint8_t *ptr, uintptr_t len); // diagnostic → CBOR bytes
```

---

### Tier 1: Hashing

```c
// Compute content hash (33 bytes: 0x00 + SHA-256)
EntityCoreBuffer entity_hash_compute(
    const uint8_t *type_ptr, uintptr_t type_len,
    const uint8_t *data_ptr, uintptr_t data_len);

// Validate hash matches type + data
EntityCoreError entity_hash_validate(
    const uint8_t *type_ptr, uintptr_t type_len,
    const uint8_t *data_ptr, uintptr_t data_len,
    const uint8_t *hash_ptr);  // 33 bytes

// Display formats
EntityCoreBuffer entity_hash_to_hex(const uint8_t *hash_ptr);      // → 66-char hex
EntityCoreBuffer entity_hash_from_hex(const uint8_t *hex_ptr, uintptr_t hex_len);
EntityCoreBuffer entity_hash_to_display(const uint8_t *hash_ptr);   // → "ecfv1-sha256:..."
```

---

### Tier 2: Cryptography (Ed25519)

```c
// Keypair lifecycle
EntityCoreHandle entity_keypair_generate(void);                     // random
EntityCoreHandle entity_keypair_from_seed(const uint8_t *seed_ptr); // deterministic, 32 bytes
void             entity_keypair_free(EntityCoreHandle handle);

// Accessors
EntityCoreBuffer entity_keypair_public_key(EntityCoreHandle handle); // 32 bytes
EntityCoreBuffer entity_keypair_peer_id(EntityCoreHandle handle);    // Base58 string

// Sign (64-byte Ed25519 signature)
EntityCoreBuffer entity_sign(EntityCoreHandle keypair,
                             const uint8_t *msg_ptr, uintptr_t msg_len);

// Verify (pubkey_ptr=32 bytes, sig_ptr=64 bytes)
EntityCoreError entity_verify(
    const uint8_t *pubkey_ptr,
    const uint8_t *msg_ptr, uintptr_t msg_len,
    const uint8_t *sig_ptr, uintptr_t sig_len);
```

---

### Tier 3: Entities

```c
// Create entity (computes content hash)
EntityCoreHandle entity_new(
    const uint8_t *type_ptr, uintptr_t type_len,
    const uint8_t *data_ptr, uintptr_t data_len);

void             entity_free(EntityCoreHandle handle);
EntityCoreBuffer entity_get_type(EntityCoreHandle handle);
EntityCoreBuffer entity_get_data(EntityCoreHandle handle);
EntityCoreBuffer entity_get_hash(EntityCoreHandle handle);  // 33 bytes
EntityCoreError  entity_validate(EntityCoreHandle handle);   // verify hash
```

### Wire Codec

```c
EntityCoreBuffer entity_encode(EntityCoreHandle handle);  // → wire CBOR (does NOT consume)
EntityCoreHandle entity_decode(const uint8_t *ptr, uintptr_t len);
```

---

### Tier 4: Peer

#### Lifecycle

```c
int32_t entity_core_init(void);       // init global runtime (0=ok, -1=error)
void    entity_core_shutdown(void);    // shutdown runtime
EntityCoreBuffer entity_core_version(void);

EntityCoreHandle entity_core_peer_create(
    const uint8_t *seed_ptr,           // 32 bytes
    const uint8_t *addr_ptr,           // listen address (UTF-8)
    uintptr_t addr_len);

void entity_core_peer_free(EntityCoreHandle handle);
EntityCoreBuffer entity_core_peer_id(EntityCoreHandle handle);

// Start engines + TCP accept loop (non-blocking)
EntityCoreError entity_core_peer_start(EntityCoreHandle handle);
```

#### Handler Execution

```c
// Dispatch to a local handler. params_entity is CONSUMED.
EntityCoreHandle entity_core_execute(
    EntityCoreHandle peer_handle,
    const uint8_t *handler_ptr, uintptr_t handler_len,     // e.g. "system/tree"
    const uint8_t *operation_ptr, uintptr_t operation_len,  // e.g. "get"
    EntityCoreHandle params_entity);                         // consumed
```

Returns entity handle for the result, or 0 on error.

#### Tree Operations

```c
// Get entity by path
EntityCoreHandle entity_core_tree_get(
    EntityCoreHandle peer, const uint8_t *path, uintptr_t path_len);

// Put entity at path (entity_handle consumed). Returns 33-byte hash.
EntityCoreBuffer entity_core_tree_put(
    EntityCoreHandle peer, const uint8_t *path, uintptr_t path_len,
    EntityCoreHandle entity_handle);

// List paths under prefix. Returns null-separated UTF-8 path strings.
EntityCoreBuffer entity_core_tree_list(
    EntityCoreHandle peer, const uint8_t *prefix, uintptr_t prefix_len);
```

#### Event Subscription

```c
// Subscribe to tree change events
EntityCoreHandle entity_core_subscribe(EntityCoreHandle peer);

// Poll next event (non-blocking).
// Returns: path (UTF-8) + \0 + hash (33 bytes), or null buffer if empty.
EntityCoreBuffer entity_core_poll_event(EntityCoreHandle sub);

void entity_core_unsubscribe(EntityCoreHandle sub);
```

## Memory Management Rules

1. Every `EntityCoreBuffer` returned by the library must be freed with `entity_core_buffer_free()`.
2. Every handle created by `*_new()` / `*_generate()` / `*_create()` must be freed with the matching `*_free()`.
3. Functions that **consume** handles (noted in docs) free them internally — do not double-free.
4. `entity_core_last_error()` returns a pointer valid only until the next FFI call on the same thread.

## Thread Safety

- All functions are panic-safe (panics are caught and converted to error codes).
- Handle tables use `RwLock` — safe to call from multiple threads.
- Error messages are thread-local — each thread has its own last error.
- The global runtime (`entity_core_init`) should be initialized once from the main thread.
