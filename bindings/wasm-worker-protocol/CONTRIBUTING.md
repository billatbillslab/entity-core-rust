# Contributing to `wasm-worker-protocol`

This crate is the wire-format contract between `wasm-worker-host` (the Web
Worker hosting the SDK) and `wasm-worker-proxy` (the main-thread proxy that
mirrors the SDK's L1 surface to consumers).

## Boundary rule (normative)

This crate's enums (`Request`, `Response`, `Event`) are a **serializable
shadow of the SDK's L1 method signatures, nothing more**. Adding a variant
means a corresponding SDK method already exists (or is being added in
lock-step). Cross-cutting concerns — auth, retry, idempotency, batching,
caching semantics — belong in the SDK (so in-process consumers get them
too) or in the proxy/host pair (so they are transport-specific). They
**MUST NOT** be added in this crate.

See the worker-migration design notes (§4.1a) for full rationale.

## When you add a new L1 SDK method, you must update FOUR places

The drift-protection CI lane (see below) catches most omissions at PR
time, but here's the full checklist:

1. **Add the method to `entity-sdk`** (the SDK itself — its surface is the
   source of truth).
2. **Append the variant name to `entity_sdk::L1_WORKER_MIRRORED_SURFACE`**
   in `bindings/sdk/src/lib.rs`. PascalCase, matching the future `Request`
   variant name (e.g., the SDK method `put_cas` becomes `"PutCas"` in the
   list). Order must match the order in `wasm-worker-protocol`'s
   `REQUEST_VARIANT_NAMES`.
3. **Add `Request::YourMethod` and `Response::YourMethod` variants** to
   `bindings/wasm-worker-protocol/src/lib.rs`. Peer-scoped methods take an
   explicit `peer_id: String` field (S1).
4. **Append the variant name to `REQUEST_VARIANT_NAMES`** in
   `bindings/wasm-worker-protocol/src/lib.rs`. Order must match
   `L1_WORKER_MIRRORED_SURFACE`.
5. **Add `proxy_method! { ... }` invocation** to
   `bindings/wasm-worker-proxy/src/lib.rs`. The argument names in the
   invocation must match the field names in the corresponding `Request`
   variant — the macro relies on this convention.
6. **Add the host dispatch arm** to `bindings/wasm-worker-host/src/lib.rs`
   so the worker can actually serve the new method.
7. **Bump `PROTOCOL_VERSION`** in `wasm-worker-protocol` only if the new
   variant's shape differs structurally from existing ones (new argument
   *types* like a never-before-seen wire type, not just new variant
   *names*). Variant additions are forward-compat as long as the proxy and
   host ship together; the version bump is for "wire-shape evolved
   incompatibly."

## Drift protection (CI lane + compile-time check)

A compile-time assertion in `wasm-worker-protocol` enforces that
`REQUEST_VARIANT_NAMES` matches `entity_sdk::L1_WORKER_MIRRORED_SURFACE`
exactly. The build fails if:

- An entry is in `L1_WORKER_MIRRORED_SURFACE` but missing from
  `REQUEST_VARIANT_NAMES` (you added an SDK method, forgot the wire variant).
- An entry is in `REQUEST_VARIANT_NAMES` but missing from
  `L1_WORKER_MIRRORED_SURFACE` (you added a wire variant but didn't
  declare it on the SDK side).
- The lists have the same length but contents differ (typo, ordering
  drift).

The check fires on `cargo check --target wasm32-unknown-unknown -p
entity-wasm-worker-protocol`, which is one of the CI lanes per R11.

**This check does NOT catch** an SDK method added without ever being added
to `L1_WORKER_MIRRORED_SURFACE`. That's the gap the checklist above
addresses — when reviewing PRs that add SDK methods, check that the four
sites were all updated.

## Boundary cases

- **L0 escape hatches** (`store()`, `Scope`, `peer()`, `peer_shared()`):
  intentionally not in `L1_WORKER_MIRRORED_SURFACE`. These don't cross the
  worker boundary. The §4.4 L0-prohibition contract documents this.
- **Subscriptions:** `Subscribe`/`Unsubscribe` Request variants are wire
  primitives but aren't `proxy_method!`-generated — they're bespoke
  because the channel-returning shape doesn't fit the macro. They DO have
  entries in `REQUEST_VARIANT_NAMES`. The SDK side has `subscribe()` /
  `unsubscribe()` methods; their entries in
  `L1_WORKER_MIRRORED_SURFACE` are `"Subscribe"` and `"Unsubscribe"`.
- **`Init` / `RegisterBackendPeer`** are worker-host-scoped, not L1
  SDK methods. They have no entries in `L1_WORKER_MIRRORED_SURFACE` —
  these are protocol-only primitives, exempt from the coverage check.
  The check's domain is L1 SDK mirroring; these are init / lifecycle
  concerns that exist solely on the wire.

If you're confused whether something belongs in
`L1_WORKER_MIRRORED_SURFACE`, the test is: **is there a corresponding
public `pub async fn` (or `pub fn` returning a future) on `PeerContext`
in `entity-sdk`?** If yes, it goes in the list. If no (it's a wire-only
primitive, a worker-internal helper, or an L0 escape hatch), it doesn't.

## References

- The worker-migration design notes (the plan)
- The Phase 1 protocol review (the protocol-shape convergence; Q1–Q6 and
  S1–S3 resolutions)
- The worker-migration design notes, §10.2 (the maintenance-cost analysis
  that motivated this checklist + check)
