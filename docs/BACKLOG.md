# Entity Core Rust — Backlog

Tracked items for future work. Ordered roughly by priority within each category.

---

## Capability & Authorization

### Per-write capability selection in handlers
Handlers currently pass the caller's capability for all writes via EmitContext. The spec (V7 §6.8, PROPOSAL-WRITE-AUTHORIZATION-MODEL W1) requires handlers to select the right capability per-write: caller capability for caller-specified paths, handler grant for handler-managed paths. The infrastructure is in place (handler_grant and handler_grant_hash on HandlerContext), but individual handlers need domain-specific logic.

**Affected handlers:** revision (mixed mode — binding writes vs metadata writes), inbox, continuation, subscription (all handler-authorized), clock engine, history engine (autonomous writes).

**Tree handler:** Already correct — pure caller-authorized, all writes to caller-specified paths.

### Handler-specific internal_scope declarations
All handlers currently get wildcard grants (all handlers, all resources, all operations). The `internal_scope()` default method exists on the Handler trait. Handlers should declare their actual needs for security hardening. Example: inbox handler should declare `{handlers: ["system/tree"], resources: ["system/inbox/*"], operations: ["get", "put"]}`.

**Reference:** Go's `local/files` handler declares specific scope in `Manifest().InternalScope`.

### system/capability handler
Not bootstrapped. Spec §6.9 lists it as a bootstrap handler. Needed for remote peers to request broader grants after connection. Operations: request, delegate, revoke. Low urgency while using `--debug-grants` for development.

### system/handler register operation with grant creation
Currently handler registration is bootstrap-only (PeerBuilder). The `system/handler` handler exists as a manifest but doesn't implement register/unregister with grant creation. Needed for dynamic handler registration over the wire.

### Connection grant storage
Connection grants are ephemeral (in handshake response only). Spec §8.2 mentions storage at `system/capability/grants/connection/{peer_id}`. Not implemented in Go either. Low priority.

### R-3 broader path-as-resource enforcement on identity ops
PROPOSAL-CROSS-IMPL-ACME-RUST R-3 / V7 §3.2 + EXTENSION-IDENTITY §6: all identity ops MUST require a resource target. `handle_create_quorum` was tightened (strict `path_required` + canonical-path validation). `handle_create_attestation`, `handle_supersede_attestation`, `handle_publish_attestation` still accept `(None, computed_canonical)` as a fallback. Tightening them to strict `path_required` requires updating existing harness tests that don't pre-compute the canonical attestation path. Defensive — does not affect cross-impl wire conformance because Go's SDK now always supplies the canonical path. Candidate to land alongside the next round of identity TVs.

### Loom-based concurrency permutation testing for SEC-2 race
PR-2 (PROPOSAL-ROLE-V2.0-PRODUCTION-READINESS §3) landed `pr2_tv_rd_race_ae_assign_vs_exclude_atomicity` in `extensions/role/src/tests.rs` as a multi-thread tokio iteration soak test (100 iterations × 4 worker threads). Verified 10/10 reliable detection of regressions. Per the proposal §3.3 race-detector guidance, the canonical guarantee shape is exhaustive thread-interleaving search — `loom` would explore the (`is_excluded`, `tree:put`) interleavings deterministically. Migration is a non-trivial dev-dep (loom requires the test harness to use `loom::sync::*` instead of `std::sync::*`); revisit when the substrate stabilizes.

**Reference:** Go's `TestSEC2_AssignExcludeRace` runs under `go test -race` (1000 race opportunities, 0 leaks); Rust's analogue is loom.

---

## Tree Handler

### ~~Snapshot returns flat bindings instead of trie root~~ DONE
Resolved — tree:snapshot at `core/tree/src/lib.rs:697-731` returns
`{root}` carrying the trie root hash (per EXTENSION-TREE v3.2 §3 +
I3 amendment that dropped `prefix` from the snapshot envelope).
`trie::build_trie` is invoked at handler-level; the fast path also
reads tracked roots from `system/tree/root/{prefix}` per §3.4.1.
Backlog entry retained as a historical pointer.

### mode:hash for hash-only reads
Tree get with `mode: "hash"` should return just the hash without fetching the entity from content store.

### Pagination
Tree listing should support offset/limit for large subtrees.

---

## Protocol Gaps

### Mutual authentication (6-message handshake)
Current handshake is 3+3 (hello+authenticate one direction). Full mutual auth needs both sides to authenticate. Validator doesn't test this yet.

### ~~On-receipt hash validation~~ DONE
Resolved in commit b9ad914 — `verify_request` now iterates
`envelope.included` after the root validation and calls `.validate()` on
each entity. Forging an included entity via envelope manipulation fails
the same way forging the root does (`ProtocolError::HashMismatch`).
PROPOSAL-CROSS-IMPL-STANDARDIZATION-CATCHUP §4 partial.

### Post-connect 409 (duplicate connection)
No duplicate connection detection.

---

## Extensions

### Revision Phase 2 — recursive trie diff/merge
Current approach flattens tries for diff/merge (O(total_paths)). Phase 2 would use recursive descent with subtree skipping (O(changes x depth)). Functionally correct now, just slower for large trees with small diffs.

### History accessed events (audit mode)
Spec §5.2 (MAY). Tree handler get would need to fire events for read audit. Adds a write per read on audited paths — only for security-sensitive paths.

### History config caching
`find_history_config()` scans all configs on every tree event. An in-memory cache invalidated on `system/history/config/*` changes would improve high-frequency write performance.

### Identity §9.2 op-key confinement enforcement
EXTENSION-IDENTITY v2.2 §9.2 MUST: reject `public/` attestations carrying signatures from any currently-live operational peer of the trusted quorum. Current handler does NOT enforce. Subtle interpretation in three-key default (op = contact-face by structural collapse) — likely scope is "enforce only when a `contact-face` attestation exists" (4-key shape). Wire as a check inside `process_attestation_inner` for `public/`-bound kinds.

### Identity live-Op cache (per §5.4)
Informative SHOULD. To avoid repeated subtree scans during §9.2 enforcement and `find_live_attestations` calls, maintain an impl-private cache of `quorum_id → live_certification_paths`, invalidated by `process_attestation` on `kind="certification"` insert and `kind="retirement"` removal.

### Identity SyncTreeHook for tree-write boundary
EXTENSION-IDENTITY v2.2 §6.8 sync-hook contract. Local writes through `create_attestation`/`supersede_attestation` already fire `process_attestation` post-persist (the explicit-invocation route the spec accepts). L0 direct writes to the named subtrees and future Sync extension arrivals do NOT yet trigger `process_attestation`. Add an `IdentityEngine` (SyncTreeHook) that observes writes to `system/identity/{public,internal,relationships}/attestation/`, `system/identity/quorum/*/attestation/` and runs the post-state side effects (cache seed, cap mgmt). Note: signature re-validation requires access to in-flight signatures, which are not in `TreeChangeEvent` — Sync-extension integration will need to plumb that.

### Identity AttestationStore enforcement at verify_request
The `AttestationStore` trait is wired into `PeerBuilder` and exposed via `Peer::lookup_attestation()`, but `core/protocol/src/verify.rs` does NOT yet consult it. Wiring the consultation requires picking a default cache-miss policy (§10.1: `fetch-on-demand`, `reject-and-escalate`, or `embedded-only`) and a `cache_miss_policy` config option on `PeerConfig` so deployments can opt in.

---

## Performance

Closed during the per-put perf regression sweep. Per-put cost dropped from
66.4 ms → 0.72 ms (debug, peer-manager `--debug`) — ~92× total. Items below were
considered and deferred because the wins shrank to single-digit µs once the
big-rock fixes (NODELAY + sync-hook caches + dev-profile crypto/CBOR opt
override) landed. Pick up only if a future profile shows `verify_request`
back on the hot path.

### Optimization B — defer full `CapabilityToken::from_entity` to permission check
`verify_request` decodes the entire token (grants, delegation_caveats, etc.)
just to read `grantee` / `expires_at` / `not_before`. Could extend
`decode_capability_chain_fields` with the two time fields and defer the full
decode until permission check. Saves one CBOR decode per RPC. Marginal at
current `verify_request` size (~57 µs release); revisit if the token grows.

### Optimization C — pre-index signatures by `target_hash` on envelope decode
`find_signature_for_target` is an O(n) scan + per-sig CBOR decode of every
`system/signature` entity in `included`. For a 1-hop chain (validator's case)
it fires twice per RPC; for deeper chains it scales per link. Build a
`HashMap<Hash, &Entity>` once at envelope decode time. No-op for 1-hop, useful
for chain depth ≥ 2.

### Optimization D — pass decoded tokens through `is_attenuated`
`is_attenuated` re-decodes both child and parent `CapabilityToken` per
non-root link (`verify.rs:336–339`). Decode once during chain collection and
pass through. 0 calls saved for 1-hop, 2 per non-root link otherwise.

### Optimization E — `Hash::to_bytes` allocation in Ed25519 path
`Keypair::verify` is called with `&content_hash.to_bytes()` which heap-allocs
a `Vec<u8>` per call. `Hash` already holds a `[u8; 32]` internally — exposing
it as `&[u8; 32]` (via Deref or `as_bytes`) makes the input borrowed. ~2
allocs/RPC saved. Sub-µs win in absolute terms.

### Capability validation cache (per-peer, by `capability_hash`)
Considered during the regression sweep, deferred as security-sensitive. The
validator reuses one capability hash for all 1101 puts → cache hit rate
~99.9%. A peer-wide cache keyed by `capability_hash` storing the validated
`CapabilityToken` would skip the chain Ed25519 verify on hit. Skipping *any*
signature work is the kind of optimization that needs an explicit security
review (replay safety, revocation invalidation, time-bound checks on cached
entries). Don't reach for this without one.

### `verify_request` microbench
`tests::verify_request_perf` in `core/protocol/src/lib.rs` (`#[ignore]`'d, run
with `cargo test -p entity-protocol verify_request_perf -- --ignored
--nocapture`). 1000 iterations on the validator's reuse pattern. Use to catch
future regressions on this hot path.

---

## Bindings & SDK Surface

Parked from the upstream-asks + peer-arm-architecture arc. Each has an
explicit fire trigger — none are active now.

### `PeerSurface` trait — formal arm-unification
`EntitySDK` and `WorkerProxy` ship two un-unified per-peer surfaces over
the same 17-op `L1_WORKER_MIRRORED_SURFACE`; the compile-time string
equality check (`L1_WORKER_MIRRORED_SURFACE ≡ REQUEST_VARIANT_NAMES`) is
a hand-rolled stand-in for a trait. The additive flat `EntitySDK` shape
pre-aligns the consumer-side collapse; the principled
end state is one async trait over the 17 ops, Direct wrapping sync L0 in
`ready()` futures. **Trigger:** the second mixed-mode consumer (Godot or
Python binding needing Direct+Worker hosting). Not before — one consumer
hand-rolling it is acceptable; lifting for one is premature.

### Detached-future rework for `get`/`list`/`remove`/`has`/`put_cas`
The flat `EntitySDK` ops `put`/`execute`/`query`/`count`/`discover`/
introspection are `fn -> impl Future + 'static` (owning). `get`/`list`/
`remove`/`has`/`put_cas` are still `async fn(&self)` (they delegate to
`PeerContext` methods that touch `self.peer.execute_with_options` — `Peer`
is not `Clone`). Making them owning futures requires reworking those
`PeerContext` methods to route through `make_execute_fn(shared)` like
`put` already does. **Trigger:** a consumer detaches those ops through a
`Pin<Box<dyn Future + 'static>>` boundary (regression guard:
`detached_futures_are_static_boxable` in `bindings/sdk/src/sdk.rs`).

### Storage-concurrency posture docs + SQLite pool-split
cross-impl Ask 3. `SqliteContentStore`/`SqliteLocationIndex` use
`Arc<Mutex<Connection>>` — all reads serialize against all writes,
non-compliant with the cross-impl "reads must not block writes"
convention. Memory + OPFS hold the property naturally. Needs a
one-paragraph-per-backend concurrency doc in `core/store/`, and the
SQLite construction site to expose `busy_timeout`/`journal_mode`/
`read_pool_size` (mirroring Go's pool split). **Trigger:** src-tauri
SQLite persistence goes to production (per `PEER-IDENTITY-MODEL.md`).

### `Batch` / `Transaction` primitive
cross-impl Ask 4. Today every `PeerContext::put` is autocommit. A batch
guard accumulating N writes into one commit gives ~5× on SQLite (one
fsync vs N) and a real win on OPFS (one journal flush vs N). Emit
semantics (per-put vs post-commit cascade) is the open design question.
**Trigger:** the cross-impl `Batch`/`Transaction` shape design PR — adopt
and add the OPFS-flush amortization then.

---

## Code Cleanup

### Duplicate helpers across extensions
`error_result()` is identical in 4 extension crates (continuation, subscription, clock, revision). `spawn_task()` is identical in 3 crates (inbox, subscription/engine, clock/engine). Consider extracting to entity_handler.

### Dead code fields
Several handlers store `local_peer_id` but never use it (tree, inbox, continuation). QueryHandler stores `location_index` unused. All suppressed with `#[allow(dead_code)]`.

### Legacy snapshot format handling
`core/tree/src/lib.rs` handles 2 legacy snapshot formats alongside the current trie format. Removable if no persisted data uses old formats.

### persist feature in entity-store
`persist` feature and module are deprecated in favor of SQLite (`SqliteStore`). Module marked `#[deprecated(since = "0.2.0")]`. Remove when no external users remain.

---

## Completed

| Item | Notes |
|------|-------|
| Handler normalization (N1-N8) | Three-type architecture: manifest/handler/interface |
| Bounds + cascade_depth | cascade_depth field added per spec §3.11 |
| Path-as-resource hygiene | PROPOSAL-PATH-AS-RESOURCE-HYGIENE: compute (eval/install/uninstall) + continuation (install) + system/handler (register/unregister) read paths from `ctx.resource_target`; eliminated `system/compute/uninstall-request`, `system/handler/unregister-request`, `system/continuation/install-request` wrappers; `manifest.pattern` mismatch policy added. Role extension still pending. |
| EmitContext on TreeChangeEvent | author, capability_hash, handler_pattern, operation, request_id |
| History handler + engine | query/rollback ops, config-based recording, dual capability check |
| Peer-qualified paths | All LocationIndex keys are `{peer_id}/path` |
| Library bindings (C FFI + Godot) | cdylib + cbindgen, gdext 0.4 GDExtension |
| Bounds & chain_id infrastructure | Bounds struct, TTL decrement, chain_id propagation |
| Handler grants at bootstrap | create_handler_grant(), self-grants, wildcard scope |
| Execute closure on HandlerContext | make_execute_fn() in connection.rs |
| NotifyingLocationIndex + events | Callback-based, broadcast channel in PeerBuilder |
| All 7 extension handlers | inbox, continuation, subscription, clock, revision, history, query |
| WASM compatibility | 67 cfg annotations, all crates compile for wasm32 |
| Revision v3.0 path restructuring | Hash-addressed prefix subtrees, always-absolute prefixes |
| Cascade semantics | SyncTreeHook returns Result, 207 Multi-Status |
| Revision auto-version v2.5 | Per-write SyncTreeHook, tracking-config coordination |
| Continuation WASM fix | std::sync::Mutex → tokio::sync::Mutex |
| Per-put perf regression sweep | NODELAY + sync-hook caches + dev-profile crypto opt override + chain-fields decoded once. 66.4 → 0.72 ms/put debug (~92×). |
| Role extension v1.0 → v2.0 | EXTENSION-ROLE v1.0..v1.7 then PROPOSAL-ROLE-V2.0 PR-1/2/3/6 landed. 62 lib tests + 2 peer integration tests + 3 PR-3 protocol tests. Root-cap shape (PR-1), SEC-2 atomicity (PR-2), bearer-cap rejection (PR-3 / V7 v7.39 §3.6 + §5.5 / new `unresolvable_grantee` 401). |
