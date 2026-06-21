# Entity Core Rust — Architecture Plan

## 1. Overview

This is a clean rewrite of the Rust implementation of Entity Core Protocol v7.9. The previous implementation (entity-core-rs) accumulated ~34K LOC with significant architectural debt. This rewrite targets:

- **Parity with Go** — Same clean architecture, same interop compliance
- **Modularity** — Fine-grained crate DAG enforced at compile time
- **Changeability** — Small, focused crates that can be modified independently
- **Spec fidelity** — Every implementation decision traces to a spec section

## 2. Lessons from Previous Implementation

The old Rust postmortem identified five root causes of complexity:

| Problem | Root Cause | This Time |
|---------|-----------|-----------|
| HandlerContext: 15+ fields, 1263 LOC | Features added to context instead of services | Max 8 fields, services are separate types |
| 4+ storage pathways | Bootstrap used different paths than runtime | One `emit()` function for everything |
| 0 interop issues found by tests | 152 tests validated Rust-to-Rust only | Interop tests from phase 1 |
| Extensions coupled to core internals | No clear public API boundary | Extensions depend only on facade crate traits |
| 34K LOC (4x Go/Python) | Monolithic entity-core crate, premature features | 14 focused crates, core protocol first |

## 3. Crate Architecture

### 3.1 Dependency DAG

Modeled directly on Go's 14-package structure. Each crate has a single responsibility and a strict position in the dependency order:

```
                                    ┌─────────┐
                                    │   ecf   │ (leaf)
                                    └────┬────┘
                                         │
                                    ┌────┴────┐
                                    │  hash   │
                                    └────┬────┘
                                    ┌────┴────┐
                              ┌─────┤ entity  ├─────┐
                              │     └────┬────┘     │
                         ┌────┴────┐     │     ┌────┴────┐
                         │ crypto  │     │     │  store  │
                         └────┬────┘     │     └────┬────┘
                              │     ┌────┴────┐     │
                              │     │  types  │     │
                              │     └────┬────┘     │
                         ┌────┴─────────┴───────────┴────┐
                         │         capability            │
                         └────────────┬──────────────────┘
                              ┌───────┤
                         ┌────┴────┐  │  ┌─────────┐
                         │ handler │  │  │  wire   │
                         └────┬────┘  │  └────┬────┘
                         ┌────┴───────┴───────┴────┐
                         │        protocol         │
                         └────────────┬────────────┘
                                 ┌────┴────┐
                                 │  tree   │
                                 └────┬────┘
                                 ┌────┴────┐
                                 │  peer   │
                                 └─────────┘
```

### 3.2 Crate Responsibilities

| Crate | Responsibility | Key Types | Approx Size |
|-------|---------------|-----------|-------------|
| `ecf` | Deterministic CBOR encoding per RFC 8949 §4.2 | `ecf_encode()`, `ecf_decode()`, `EncMode` | ~200 LOC |
| `hash` | Content hash computation and validation | `Hash`, `content_hash()`, `validate_hash()` | ~300 LOC |
| `entity` | Core entity data structures | `Entity`, `Envelope` | ~300 LOC |
| `crypto` | Ed25519 identity, signing, verification | `Keypair`, `PeerId`, `sign()`, `verify()` | ~300 LOC |
| `store` | Storage traits and in-memory implementations | `ContentStore`, `LocationIndex`, `MemoryStore`, `MemoryIndex` | ~400 LOC |
| `types` | Protocol type definitions, TypeRegistry | `TypeDef`, `FieldSpec`, `TypeRegistry`, protocol message types | ~800 LOC |
| `capability` | Capability tokens, grants, scope checking | `CapabilityToken`, `Grant`, `check_permission()`, `verify_chain()` | ~600 LOC |
| `wire` | Wire framing and envelope codec | `read_envelope()`, `write_envelope()`, `Frame` | ~200 LOC |
| `handler` | Handler trait, registry, context | `Handler`, `HandlerRegistry`, `HandlerContext`, `Request`, `Response` | ~500 LOC |
| `protocol` | EXECUTE dispatch, auth verification, connection handler | `Dispatcher`, `ConnectHandler`, `verify_request()` | ~800 LOC |
| `tree` | system/tree handler (get, put, listing) | `TreeHandler`, `check_path_permission()` | ~400 LOC |
| `peer` | Peer lifecycle, connection management | `Peer`, `PeerBuilder`, `Connection` | ~600 LOC |
| `entity-core` | Facade: re-exports all public types | (re-exports only) | ~50 LOC |

**Estimated total: ~5,500 LOC** — targeting 60-70% of Go's size, well under old Rust's 34K.

### 3.3 Public API Boundary

The `entity-core` facade crate re-exports all public types. External consumers (extensions, CLI, tests) import only `entity-core`. Internal crate dependencies use direct imports.

```rust
// External consumer
use entity_core::{Entity, Hash, Peer, PeerBuilder, Handler, ContentStore};

// Internal crate (e.g., protocol depends on handler)
use entity_handler::{Handler, HandlerContext, Request, Response};
```

## 4. Core Type Design

### 4.1 Entity

```rust
/// The fundamental data unit. Content-addressed via SHA-256.
pub struct Entity {
    pub entity_type: String,
    pub data: RawCbor,           // Preserves byte fidelity
    pub content_hash: Hash,
}
```

**Critical:** `data` must be raw CBOR bytes, never a deserialized structure that gets re-serialized. This preserves byte fidelity for hash verification (spec §1.8).

### 4.2 Hash

```rust
/// Content-addressed identity. 33 bytes on wire.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash {
    pub algorithm: u8,
    pub digest: [u8; 32],
}
```

- Fixed size, stack-allocated, usable as HashMap key
- Wire format: CBOR bstr of 33 bytes (algorithm || digest)
- Display format: `ecfv1-sha256:hex(digest)` (UI only)

### 4.3 Envelope

```rust
/// Wire transport container.
pub struct Envelope {
    pub root: Entity,
    pub included: HashMap<Hash, Entity>,
}
```

### 4.4 HandlerContext

```rust
/// Minimal execution context for handlers.
pub struct HandlerContext {
    pub local_peer_id: PeerId,
    pub remote_peer_id: PeerId,
    pub caller_capability: CapabilityToken,
    pub handler_grant: CapabilityToken,
    pub handler_pattern: String,
    pub request_id: String,
    pub store: Arc<dyn ContentStore>,
    pub location_index: Arc<dyn LocationIndex>,
}
```

**8 fields.** No optional builder methods. No session management. No connection pools. Services that handlers need (like sub-request dispatch) are injected as closures or trait objects on the context, not as accumulated fields.

### 4.5 Handler Trait

```rust
#[async_trait]
pub trait Handler: Send + Sync {
    async fn handle(&self, ctx: &HandlerContext, req: &Request) -> Result<Response>;
    fn name(&self) -> &str;
    fn manifest(&self) -> HandlerManifest;
}
```

Handlers receive a Request (parsed from EXECUTE) and return a Response. No raw entity decoding in handlers.

## 5. Storage Design

### 5.1 Single Pathway

All entity storage — bootstrap, handler emit, tree put — goes through one function:

```rust
pub fn store_entity(
    store: &dyn ContentStore,
    index: &dyn LocationIndex,
    entity: Entity,
    path: Option<&str>,
) -> Result<Hash> {
    let hash = store.put(&entity)?;
    if let Some(path) = path {
        index.set(path, hash);
    }
    Ok(hash)
}
```

Bootstrap uses this same function. No separate `emit_entity()`, `emit_type_entity()`, or direct `store.put()` in builder code.

### 5.2 Traits

```rust
pub trait ContentStore: Send + Sync {
    fn put(&self, entity: &Entity) -> Result<Hash>;
    fn get(&self, hash: &Hash) -> Option<Entity>;
    fn has(&self, hash: &Hash) -> bool;
    fn remove(&self, hash: &Hash) -> bool;
}

pub trait LocationIndex: Send + Sync {
    fn set(&self, path: &str, hash: Hash);
    fn get(&self, path: &str) -> Option<Hash>;
    fn has(&self, path: &str) -> bool;
    fn remove(&self, path: &str) -> Option<Hash>;
    fn list(&self, prefix: &str) -> Vec<LocationEntry>;
}

pub struct LocationEntry {
    pub name: String,
    pub hash: Option<Hash>,
    pub has_children: bool,
}
```

## 6. Implementation Phases

### Phase 0: Project Setup
- Initialize Cargo workspace with all crate stubs
- Set up CI (build, test, clippy, fmt)
- CLAUDE.md and ARCHITECTURE.md (this document)

### Phase 1: Foundation Crates (ecf → hash → entity → crypto)
- ECF deterministic CBOR encoding
- Hash computation and validation (NORMATIVE algorithms §7.1, §7.2)
- Entity creation with automatic hash computation
- Ed25519 keypair, PeerId derivation (§7.4), sign/verify (§7.3)
- **Milestone:** Cross-implementation hash compatibility test with Go/Python

### Phase 2: Storage + Types (store, types)
- ContentStore and LocationIndex traits + in-memory implementations
- Protocol type definitions (all types from spec §3)
- TypeRegistry for bootstrap type population
- **Milestone:** Type definitions match Go's bootstrap types byte-for-byte

### Phase 3: Capability + Wire (capability, wire)
- Capability token structure, grant entries, scope types
- Pattern matching (§5.4), scope checking (§5.2)
- Delegation chain verification (§5.5), attenuation (§5.6)
- Wire framing (4-byte length prefix + CBOR)
- Envelope codec (read/write)
- **Milestone:** Capability verification passes Go's test vectors

### Phase 4: Handler + Protocol (handler, protocol)
- Handler trait, registry, context
- Request/Response types
- EXECUTE dispatch chain (§6.5)
- Request verification (§5.2 verify_request)
- Connection handler (hello + authenticate, §4)
- **Milestone:** Successful handshake with Go peer

### Phase 5: Tree + Peer (tree, peer)
- Tree handler: get, put, listing with capability filtering (§6.3)
- Peer lifecycle: PeerBuilder, listen, accept, connect
- Bootstrap sequence (§6.9): install types, handlers, grants
- Handler dispatch via tree walk (§6.6)
- **Milestone:** Full interop — connect to Go peer, exchange tree operations

### Phase 6: Facade + Extensions
- entity-core facade crate
- Extension crate structure (inbox, subscription, continuation)
- CLI binary
- **Milestone:** Feature parity with Go implementation

## 7. Testing Strategy

### 7.1 Unit Tests
- Each crate has its own tests
- Focus on NORMATIVE algorithms (hash, signature, peer ID)
- Test edge cases in capability pattern matching

### 7.2 Integration Tests
- Two-peer tests (Rust client ↔ Rust server)
- Full connection + tree operation flow

### 7.3 Interop Tests (Critical)
- Connect to Go peer on port 9002, validate:
  - Hash byte equality for same entities
  - Connection handshake completion
  - Tree get/put round-trip
  - Capability verification
- Connect to Python peer on port 9001, same validation
- **These tests are NOT optional.** They catch the spec divergences that internal tests miss.

### 7.4 Test Vectors
- Known-good hash values for specific entities (shared with Go/Python)
- Known-good signatures for specific messages
- Known-good PeerIDs for specific public keys

## 8. CBOR Library Choice

Options:
- **ciborium** — Pure Rust, widely used, supports deterministic mode
- **cbor4ii** — Performance-focused
- **minicbor** — Zero-alloc, but less flexible

Recommendation: **ciborium** — it supports `CoreDetEncOptions` equivalent for deterministic encoding, has good serde integration, and is battle-tested. The Go impl uses `fxamacker/cbor/v2` with `CoreDetEncOptions()`, and ciborium has the equivalent capability.

The critical requirement is deterministic encoding (ECF): sorted map keys by encoded length then lexicographically, minimal integer encoding, definite lengths only. Whichever library we choose must support this or we implement it ourselves.

## 9. Dependency Budget

Minimal external dependencies:

| Dependency | Purpose |
|-----------|---------|
| `ciborium` | CBOR encoding/decoding with deterministic mode |
| `ed25519-dalek` | Ed25519 signing and verification |
| `sha2` | SHA-256 hashing |
| `bs58` | Base58 encoding for PeerID |
| `tokio` | Async runtime |
| `thiserror` | Error type derivation |
| `async-trait` | Async trait support |
| `rand` | Nonce generation |

No web frameworks, no ORM, no logging frameworks in core crates. Logging and CLI dependencies only in cmd/ crates.
