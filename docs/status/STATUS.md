# entity-core-rust — status

_Updated: 2026-06-30 · public: v0.8.0 (master)_

## Where it is

entity-core-rust is the Rust reference implementation of the Entity Core
Protocol (v7.9) — a clean, ground-up implementation, one of three independent
references alongside the Go (oracle) and Python peers. Downstream, the
entity-browser and Godot apps consume it via a Cargo **git dependency pinned to
a release tag**, so a lone clone builds standalone (no sibling checkouts
required).

The workspace is a strict, cycle-free crate DAG — `core/*` (ECF deterministic
CBOR → hash → entity → crypto/store/types → capability/wire/handler →
protocol/tree/peer, with `entity-core` as the facade re-export) — plus opt-in
protocol extensions (`extensions/*`), language/runtime bindings (`bindings/*`:
C FFI, Godot GDExtension, a higher-level SDK, and the wasm-worker stack), and
CLI tools (`entity`, `wire-conformance`, `fetch-published-fixture`). One
codebase serves three deployment roles: data toolkit, embedded peer, and
standalone server.

**Maturity: public research-preview, tagged v0.8.0.** Broad feature coverage —
all seven base extension handlers (inbox, continuation, subscription, clock,
revision, history, query), the identity/role/quorum/attestation trust stack,
the messaging/transport extensions (relay, route, discovery, registry),
encryption, compute, type-system, and WASM compatibility across every crate.
Crypto agility (Ed25519 + Ed448 keys, SHA-256 + SHA-384 hashes) is a
runtime/connection property negotiated in the handshake, not a build flag.
Known gaps are tracked in `docs/BACKLOG.md`; spec under-specifications found
while implementing are logged in `docs/SPEC-AMBIGUITIES.md` and routed upstream.
The protocol is **not** locked at 1.0, but the core wire format, capabilities,
and tree semantics are interop-validated against the Go and Python peers, not
just self-tested.

## Where we left off

Stable at the v0.8.0 research-preview line; no code or protocol changes are in
flight. Next substantive work is cross-peer subscription delivery to a Rust
subscriber.

The most recent substantive engineering thread before the release was
**cross-peer subscription delivery** (see Done recently / Waiting on): the
reported publisher-side bug is fixed and
the substrate completed, but the Rust-*subscriber* side of cross-peer delivery
remains a diagnosed-but-unlanded stack, bottoming out on a cross-impl
capability-canonicalization question logged in `docs/SPEC-AMBIGUITIES.md`.

## Backlog

From `docs/BACKLOG.md` (see it for full detail and fire-triggers):

- **Capability / authorization:** per-write capability selection in handlers
  (caller vs handler grant — infrastructure is in place on `HandlerContext`,
  individual handlers need domain logic); handler-specific `internal_scope()`
  declarations (currently wildcard grants); bootstrap a `system/capability`
  handler (request/delegate/revoke); `system/handler` register/unregister with
  grant creation; R-3 strict `path_required` on the remaining identity ops
  (`create`/`supersede`/`publish` attestation still accept a computed-canonical
  fallback).
- **Tree handler:** `mode:hash` hash-only reads; pagination (offset/limit) for
  large subtrees.
- **Protocol gaps:** full 6-message mutual-auth handshake (currently 3+3, one
  direction; validator does not test the mutual path yet); post-connect 409
  duplicate-connection detection.
- **Extensions:** revision Phase 2 (recursive trie diff/merge, vs today's
  flatten-and-diff); history accessed-events audit mode + config caching;
  identity §9.2 op-key confinement enforcement, a live-Op cache, a SyncTreeHook
  for the tree-write boundary, and `AttestationStore` consultation at
  `verify_request` (needs a cache-miss policy choice).
- **Bindings / SDK:** a `PeerSurface` trait to unify the SDK/WorkerProxy arms
  (gated on a second mixed-mode consumer); detached-`'static`-future rework for
  `get`/`list`/`remove`/`has`/`put_cas`; SQLite pool-split + a
  storage-concurrency posture doc; a `Batch`/`Transaction` primitive (gated on
  the cross-impl shape design).
- **Cleanup:** dedupe `error_result()`/`spawn_task()` helpers across extensions;
  remove dead `local_peer_id` fields; drop legacy snapshot-format handling and
  the deprecated `persist` feature; loom-based permutation testing for the SEC-2
  race (today covered by a multi-thread soak test).

Performance items from the per-put regression sweep are deferred (the remaining
candidates shrank to single-digit µs once the big-rock fixes landed) — pick them
up only if a future profile shows `verify_request` back on the hot path.

## Waiting on

- **Protocol spec (upstream):** this repo implements the landed spec and does
  not define it. Several backlog items (mutual-auth test coverage, the cross-impl
  `Batch`/`Transaction` shape) are gated on upstream design landing.
- **Cross-impl coordination on `entity://` capability-scope canonicalization
  (the structural blocker for Rust-subscriber cross-peer delivery).** The spec
  uses the `entity://peer/path` URI form for a cross-peer `deliver_uri`, so a
  `deliver_token`'s `resources` scope carries that form; but
  `core/capability::canonicalize` does not recognize the `entity://` scheme and
  mangles it so it can never match the normalized delivery-time request target →
  403 "operation permission denied". This bites even the spec-model inbox
  delivery. Whether `canonicalize` MUST strip `entity://` (treating
  `entity://{p}/x` ≡ `/{p}/x` as addresses, as dispatch routing already does) is
  a cross-implementation question — logged in `docs/SPEC-AMBIGUITIES.md`, not
  patched unilaterally, pending Go/Python alignment.
- **Cross-impl coordination on SDK-surface items** (`PeerSurface` trait, SQLite
  pool split mirroring the Go peer) waits on those consumers/decisions.

## Done recently

- **Initial public research-preview release tagged v0.8.0.** Clone-fresh gate
  green from a no-siblings checkout (`make build` → release runtime image with
  the `entity` binary; `make wasm` → wasm32 cross-compile of the canonical
  feature set; `make test`). `make` over podman is the build door (bare host
  needs only `make` + podman); `compose.yaml` is demoted to an explicit
  developer convenience. All workspace crates carry the 0.8.0 version, licensed
  **Apache-2.0**.
- **Cross-peer subscription delivery — reported bug fixed + substrate completed
  (subscriber side still open):**
  - The publisher now presents the subscriber-granted `deliver_token` (and
    bundles its delegation chain) as the delivery EXECUTE's capability for
    cross-peer delivery, instead of falling back to the connection grant — which
    on the reentry path is a publisher-authored placeholder the subscriber can't
    root (EXTENSION-SUBSCRIPTION §4.2). This unblocks the Rust-publisher →
    Go-subscriber direction.
  - Completed the dialer-side reentry receive path: a pooled outbound connection
    now dispatches inbound EXECUTE requests through the local handler stack and
    writes the response back over the same connection (previously the dialer
    reader handled only EXECUTE_RESPONSE and silently dropped reentry
    deliveries).
  - The remaining Rust-*subscriber*-side stack is diagnosed but unlanded:
    SDK-level `deliver_token` grantee/signature/handler-scope mismatches
    (`bindings/sdk/src/subscription.rs`, `extensions/subscription/src/lib.rs`),
    and the core `entity://` canonicalization gap above.
- **Trust stack — Role extension v1.0 → v2.0:** root-cap shape, SEC-2
  assign/exclude atomicity, and bearer-cap rejection (the new
  `unresolvable_grantee` 401).
- **Capability hardening:** granter-aware canonicalization at the dispatch
  boundary, per-link granter frame at chain-walk, grant-signature convergence,
  and a self-owner seed cap at bootstrap.
- **Transport / interop extensions:** relay v1.0 (opaque-envelope transport,
  exercised live Go↔Rust), route (routing table), discovery v1.0 (mDNS
  find-and-prompt) + registry v1.0 (petname→local-name) and the published-root
  flow with cohort absorption. Live cross-impl publish→fetch verified
  (Go-publish → Rust-consume).
- **Encryption extension v1.0:** group/self AEAD modes, key-separation, and the
  associated entity-type registrations.
- **Storage:** an IndexedDB main-thread durable backend (Phase 1) for the
  browser peer, with the SDK builder/checkpoint reach to drive it; a
  multi-tab `versionchange` deadlock guard.
- **Wire-fidelity:** on-receipt hash validation in `verify_request` (a forged
  *included* entity now fails the same as a forged root); §1.2 host-bytes-
  distrust (recompute content hashes, never trust the wire `content_hash`).
- **Performance:** per-put cost ~66.4 ms → ~0.72 ms in debug (~92×) via TCP
  NODELAY, sync-hook config caches, a dev-profile crypto/CBOR optimization
  override, and decoding chain fields once.
- **WASM:** compatibility across all crates (wasm32-unknown-unknown build check
  via `make wasm`).

## Next

1. **Cross-peer subscription delivery to a Rust subscriber** is the highest-
   value in-flight thread: take the `entity://` canonicalization question to the
   architecture team (Go/Python alignment), then land the SDK-side
   grantee/signature/handler-scope fixes behind it.
2. Otherwise, pick up a spec-load-bearing backlog item — per-write capability
   selection in handlers (caller vs handler grant) is the most central open one.
3. Keep the green gate (`make check` = lint + test) and `make wasm` passing on
   any change; run `validate-peer` / `wire-conformance` on any wire-shape touch.
