# Spec Ambiguities (Rust implementation)

Questions and under-specified areas encountered during implementation that
should go back to the architecture team. Each entry names the spec, the
passage, what is unclear, and the interim implementation choice (if any).

---

## CAPABILITY §5.5 / SUBSCRIPTION §4.2 — `entity://` deliver_uri vs capability-scope canonicalization

**Spec:** ENTITY-CORE-PROTOCOL-V7 §5.4/§5.5 (capability resource scoping +
canonicalization) ⨯ EXTENSION-SUBSCRIPTION §4.2 / §1.2 (cross-peer
`deliver_token` + `deliver_uri`).

**Passage.** EXTENSION-SUBSCRIPTION uses the `entity://` URI form for a
cross-peer `deliver_uri` (example § line 715:
`deliver_uri: "entity://peer_c/system/inbox/sensor-data"`). The cross-peer
`deliver_token` (§4.2) authorizes delivery to that URI, so its `resources` scope
naturally carries the `entity://` form. At **delivery time** the receiver checks
the delivery EXECUTE's resource against that scope via the §5.4/§5.5 path,
which runs `canonicalize` on both the request target and the grant's resource
patterns.

**Ambiguity.** `core/capability::canonicalize` does not recognize the
`entity://` scheme. An `entity://{A}/path` resource pattern is neither absolute
(`/…`) nor bare-wildcard, so it is treated as a **bare relative path** and
becomes `/{A}/entity://{A}/path` — which can never match the normalized request
target `/{A}/path`. The result is a 403 "operation permission denied" on any
cross-peer delivery whose `deliver_token` resource scope uses the spec's
`entity://` deliver_uri form. This bites **even the spec-model inbox delivery**,
not just custom delivery handlers.

The spec does not state whether `entity://{p}/x` and `/{p}/x` are
interchangeable *addresses* for the purpose of capability-scope canonicalization
(i.e. whether `canonicalize` MUST strip the `entity://` scheme). The two forms
ARE treated interchangeably for **dispatch routing** (`is_remote_uri` /
`extract_peer_id_from_uri` accept both), which makes the scoping divergence
easy to miss.

**Interim choice.** None — not patched. Stripping `entity://` in `canonicalize`
is shared, cross-implementation capability semantics; doing it unilaterally
risks diverging from Go/Python. Needs an architecture ruling: either (a)
`canonicalize` MUST treat `entity://{p}/x` ≡ `/{p}/x`, or (b) capability
`resources` scopes MUST be authored in `/{p}/x` form even when the
corresponding `deliver_uri` is `entity://`. There are four other layers that
gate Rust-as-subscriber cross-peer delivery.

---

## CONTENT §5.3 — descriptor path hex convention under-stated inline; Go diverges

> **Rust is conformant; no Rust change.** The Go validate-peer check
> `local_files.v3_descriptor_publish_exercised` FAILs Rust, but the FAIL is a
> **Go bug**, not a Rust gap. Routing correction: this routes to **Go +
> architecture**, NOT the Rust team (contra the cohort handoff note that called
> it "Rust descriptor write not landing").

**Spec:** EXTENSION-CONTENT v3.6 §5.3 (descriptor path convention) + V7 §3.5
(invariant-pointer hex convention).

**Passage.** §5.3 binds a descriptor at
`/{publisher_peer_id}/system/content/descriptor/{B_hex}/{D_hex}` and defines
`B_hex` = "hex encoding of the blob's entity hash", `D_hex` = "hex encoding of
the descriptor's own entity hash" — *without restating whether the format-code
byte is included*. But §5.3 explicitly calls this an **invariant-pointer path**
("the invariant-pointer path at which descriptors are bound", §5.3 intro) and
draws the normative parallel to the capability-signature invariant path
`/{signer}/system/signature/{target_hex}`. V7 §3.5 governs all such paths:

> **Hex encoding convention.** Content hashes in invariant pointer paths use hex
> encoding (lowercase, format code included). … a stable format code prefix
> (`00` = ECFv1-SHA-256). *(V7 §3.5)*

and V7 §3.5 on `target_hex`: "the hex-encoded content hash of the entity that
was signed (**including the format code byte**). For ECFv1-SHA-256, this is 66
hex characters starting with `00`." CONTENT §6.4.2 (sibling namespace path
`{namespace}/{hex(H)}`) *does* restate this explicitly: "format-code byte
included, 66 chars beginning `00` … NOT the 64-char digest-only form."

**The determinate reading.** A §5.3 descriptor path is an invariant-pointer
path ⇒ V7 §3.5 hex convention applies ⇒ `B_hex`/`D_hex` are **format-code-byte-
included** (66 chars for SHA-256, `00`-prefixed). This is unambiguous when §5.3
is read against V7 §3.5; the only defect is that §5.3 does not restate the rule
*inline* the way §6.4.2 does, which let an implementer drift.

**Cross-impl state (verified):**

| Impl | `B_hex`/`D_hex` derivation | Form | Conformant |
|------|---------------------------|------|------------|
| Rust | `Hash::to_hex()` (`core/hash`) | `00`+digest (66ch) | ✅ |
| Python | `blob_hash.hex()`; `Hash = [algo]+digest` bytes | `00`+digest (66ch) | ✅ |
| Go | `hash.EffectiveDigest()` (`ext/content/descriptor.go:55-56,120`) | digest-only (64ch) | ❌ |

Go is also *internally inconsistent*: its §6.4.2 namespace binding uses
`h.Bytes()` (format-byte-included, `ext/content/handler.go:495`) but its §5.3
descriptor path uses `EffectiveDigest()`. The Go validator
(`cmd/internal/validate/local_files.go:961`) lists
`system/content/descriptor/{EffectiveDigest_hex}/` — Go's own wrong convention —
so it cannot see Rust's correctly-bound `…/{00+digest}/` leaf and reports a
FAIL. The check asserts against Go's bug, not the spec.

**Interim Rust choice:** none — Rust stays on `to_hex()` (spec-correct, and
byte-compatible with Python). Changing Rust to match Go would (a) violate V7
§3.5, (b) break Rust↔Python descriptor interop (Python agrees with Rust), and
(c) re-introduce Go's internal namespace-vs-descriptor inconsistency on the Rust
side.

**Recommended resolution (Go + arch):**
1. **Go:** switch `DescriptorPath` + `LookupDescriptors` (`descriptor.go`) and
   the validator listing (`local_files.go`) from `EffectiveDigest()` to
   `Bytes()` (format-byte-included). 2-of-3 impls already agree; this is the
   spec-correct convergence.
2. **Arch:** add an explicit one-sentence restatement to §5.3 mirroring §6.4.2
   line ~1051 ("`B_hex`/`D_hex` follow the V7 §3.5 invariant-path hex
   convention — format-code byte included, NOT the digest-only form") so no
   implementer drifts again.

---

## PHASE P — publish-path root selection + trie key convention

> **PARTIALLY RESOLVED (arch ratification `24a4a97`, Amendment 10 +
> Go cohort handoff).** NETWORK §6.5.6 Amendment 10 pinned the serving floor:
> when `signed_pointer` is advertised, the served set MUST cover the transitive
> trie-node closure of `published-root.root_hash` (root + interior nodes +
> leaf-bound content + published-root + signature). Rust now ships
> `ClosureScope` (`core/peer/src/http_live/scope.rs`) + `collect_node_closure`
> (`core/tree/src/trie.rs`); `--publish-root` selects it and publishes even an
> empty subtree (the canonical empty CHAMP root is a real served node). This
> closes validate-peer published_root **v4** (MANIFEST_GET served) and **v7**
> (CONTENT_GET(root_hash) → trie node). **Still open:** (2) cross-impl trie
> **key convention** byte-match (Rust keys peer-prefix-stripped; Go uses
> RootTracker/`PrefixForLocalPeer`) and (3) auto-republish-on-change (Rust is
> still static one-time publish). Both reconcile at the live validate-peer run.

**Spec:** STRATEGY-REGISTRY-DISCOVERY-IMPL §0.5 P1/P2 +
`PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE.md` §1.1/§4.

**Context:** the publisher commits to a tree `root_hash`; the consumer walks the
HAMT from it by `relative_key`. Three cross-impl coordination points are NOT
pinned in the locked spec (they'll be pinned by Go's P4 conformance vectors):

1. **Which root.** `--publish-root` publishes the trie root over the
   `--serve-namespace` subtree (one root per served namespace). A peer tracking
   multiple prefixes has multiple roots; the published-root carries exactly one
   `root_hash`. Rust assumes the single-served-namespace case.
2. **Trie key convention.** Rust keys the published trie by **peer-prefix-
   stripped paths** (a binding at `/{peer}/system/content/public/x` keys as
   `system/content/public/x`), matching the root_tracker convention. The
   consumer's `resolve(relative_key)` must use the same key. Cross-impl, the key
   must byte-match Go/Python for a dial to resolve — the http_poll_outbound
   vector will pin it.
3. **Re-publish on tree change.** P1 says "on tree-root change, sign + write a
   new published-root." Rust ships a **static one-time** publish (the coral-reef
   §7.4 case: build once, serve). Auto-republish-on-change is a clean follow-up
   once the multi-prefix→single-root selection (point 1) is pinned.

**Interim choice:** Rust implements the publisher engine + verify/walk consumer
(both self-consistent + threat-model-tested) and a one-time `--publish-root`
startup publish over `--serve-namespace`, bare-path-keyed. The
`peer.publish_root(root_hash)` programmatic primitive is unambiguous (caller
picks the root). Cross-impl byte alignment on these three points reconciles at
the validate-peer reconvene (P5/P7).

---

## REGISTRY — revocation discovery path is impl-defined

> **RESOLVED (cohort convergence — Go `RevocationStoragePath`,
> validate-peer registry v6).** The cohort stores revocation entities at
> `system/registry/revocation/{hex(revocation_entity.content_hash)}` — keyed by
> the **revocation's own hash**, not the binding it revokes. Rust originally did
> an O(1) lookup keyed by the binding hash, which missed the cohort's path and
> let a revoked local-petname binding still resolve (the bug was masked
> pre-R3: the `system/protocol/status` wrap returned empty data so the v6
> "binding NOT resolved" assertion passed vacuously; fixing R3 exposed it).
> Rust now **scans** `/{peer}/system/registry/revocation/` and matches on the
> `revokes:` field (`is_revoked` in `extensions/registry/src/resolver.rs`) —
> path-convention-agnostic. Local-petname bindings are excluded on presence of
> any type-valid revocation (§6.3 carve-out: the local store is the trust
> source, no signature needed); signed kinds still require a same-authority
> signed revocation. Same fix shape Python shipped at `fb71b16`.

**Spec:** `EXTENSION-REGISTRY.md` §3.1 + §6.6 + §11.1.

**Passage:** "`:resolve` MUST check for a `system/registry/revocation` targeting a
candidate binding before returning `status: resolved`." The spec pins the
revocation **entity type** and its **signature carriage** (invariant-pointer at
`system/signature/{hex(revocation.content_hash)}`) but does NOT pin **where a
revocation entity is stored / how `:resolve` discovers one** targeting a given
binding.

**Interim choice:** Rust stores/looks up revocations at the keyed convention
`system/registry/revocation/{hex(revokes_binding_hash)}` (O(1) lookup by the
binding they revoke), plus an `included`-envelope scan. A present, type-valid
revocation excludes a petname binding unconditionally (petname has no issuing
authority to verify against); signed kinds would additionally verify the
revocation signature against the same authority as the binding.

**For architecture / cohort:** the R5 `meta_resolver_revocation_honored` vector
tests *behavior* (revoked binding excluded, chain advances), not the storage
path — so this is converged at the behavior level. But if a revocation entity
must be **cross-peer discoverable** (e.g. arriving via sync for a peer-issued
binding), the cohort should pin a canonical revocation path the way petname
two-layer storage is pinned. Flag for the validate-peer reconvene.

---

## PHASE P — `system/peer/published-root.peer_id` wire shape

> **RESOLVED (arch ratification `24a4a97`, Ruling-1).** §4 erratum
> changed `peer_id: <hash>` → `peer_id: <Base58 peer-id per V7 §1.5>`, and
> dropped any `refs:` carriage in favor of the §5.2 invariant-pointer
> `system/signature/{hex(published_root.content_hash)}`. Rust's interim Base58
> choice was ratified verbatim — no code change; the type-def comment in
> `core/types/src/core_types.rs` now cites the ratification. The Go cohort
> handoff lists Rust v1/v2/v3/v6 as PASS, confirming the byte shape.

**Spec:** `PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE.md` §4 (NORMATIVE-LOCKED).

**Passage:** §4 defines the entity as:
```
type: "system/peer/published-root"
data: {
  peer_id:     <hash>          ; whose root this is
  root_hash:   <hash>          ; the current tree root the publisher commits to
  ...
}
```

**Ambiguity:** `peer_id` is typed `<hash>`. But (a) the Go coordinator's P1
build target (STRATEGY-REGISTRY-DISCOVERY-IMPL §0.5) writes
`peer_id: <Base58 peer-id per V7 §1.5>`; (b) the closest sibling entity,
`system/peer/transport/http-poll`, carries `peer_id` as the Base58 id
`system/peer-id` per NETWORK errata `bdfb545` (cross-impl F1) precisely because
it must match the `{peer_id}` path segment, not a content hash; (c) REGISTRY
§3/§4.4 pinned `target_peer_id` as Base58 (V7 §1.5) over the same "this is an
identity, not a content-hash" reasoning. The §4 `<hash>` shorthand appears
inherited from the manifest's `source_peer_id` lineage (which IS a hash), but
`published-root.peer_id` is consumed as a self-identifying label cross-checked
against a pinned Base58 identity in the §7.4 ESR flow.

**Interim choice:** Rust encodes `peer_id` as a **Base58 peer-id string**
(`system/peer-id`), matching the cohort convergence target (Go P1 + http-poll
sibling + REGISTRY precedent). `root_hash` and `predecessor` remain bare
`system/hash`. This is the byte-level shape Rust will present at the validate-peer
reconvene.

**For architecture:** amend §4's `peer_id: <hash>` to `peer_id: <Base58 peer-id
per V7 §1.5>` to match the cohort, OR — if a content-hash was genuinely intended
— flag it so Go/Python/Rust converge before the P7 three-peer byte-equality
fixture is pinned. The two encodings are not wire-compatible.

---

## V7.64 PEER-IDENTITY BUNDLE — Rust pickup findings

Five findings surfaced during Rust impl of the v7.64 three-proposal
bundle (identity-multihash + path-encoding-alignment + policy-dual-form).
None block ratification; all are heads-ups / cross-impl coordination
items for architecture + Go/Python peers.

### F1. `system/peer` entity stores `key_type` as text `"ed25519"`, not the uint code

**Passage:** `PROPOSAL-V7-PEER-ID-IDENTITY-MULTIHASH.md` §2.7 talks about
`key_type` in the §1.5 uint sense (`KEY_TYPE_ED25519 = 0x01`). The Rust
`system/peer` entity (and the Go reference, last we checked) encodes
the `key_type` field as the **text literal `"ed25519"`** in the entity's
ECF map — not as the uint code.

**Ambiguity:** v7.64 doesn't address the encoding of the `key_type`
**field** in the entity body — only the `key_type` **byte** in the
PeerID's varint framing. v7.65 sketch §1.1 then specifies
`key_type: uint` for the proposed slim entity, implying a future
encoding switch.

**Interim choice:** Rust v7.64 keeps the text form (no change). This
matches Go's existing entity shape and avoids touching the entity's
content_hash for an unrelated reason.

**For architecture:** is it intentional that v7.64 leaves the entity's
`key_type` field encoding alone, and v7.65 switches it from text to
uint together with the `peer_id`-field drop? If so, the v7.65 proposal
should say so explicitly when drafted.

### F2. Rust does not support SHA-256-form remotes for `system/peer/transport/**` or `system/revision/.../remotes/**`

**Passage:** `PROPOSAL-V7-PEER-ID-PATH-ENCODING-ALIGNMENT.md` §2.5
acknowledges the API-break at dial / session / transport-profile
resolver sites and says: for SHA-256-form remotes, the impl needs the
peer's `system/peer` entity from a cached lookup; the dialer pattern
"works unchanged."

**Rust state:** `resolve_transport_address` (core/peer/remote.rs:550)
and `peer_remote_hex` (extensions/revision/src/lib.rs:90) currently
fail-fast for SHA-256-form PeerIDs with a clear error citing v7.64
§1.4. No cached-`system/peer` lookup is threaded through these sites.

**Interim choice:** Rust = identity-form-only for these two surfaces.
Per v7.64 §2.1 every new peer defaults to identity-form, and Rust has
no deployed cohort with SHA-256-form peers; this is operationally
fine for now. The error message points at the spec.

**For architecture / Go+Python:** worth confirming the **policy on
SHA-256-form remote support at non-policy surfaces.** Policy-dual-form
covers the policy surface explicitly. The other path families (session,
transport, revision remotes) are not enumerated for dual-form support
— but legacy SHA-256-form peers in the wild will hit these paths.
Should the spec mandate that impls thread a cached-`system/peer`
lookup at these sites, or is fail-fast acceptable (operator must
migrate their peer to identity-form before they can dial / push)?

### F3. No migration tool shipped for Rust

**Passage:** `PROPOSAL-V7-PEER-ID-PATH-ENCODING-ALIGNMENT.md` §2.5
("MUST migrate; dual-read fallback is prohibited") + §3 ("each impl
ships its own one-shot migration tool").

**Rust state:** No migration tool. Rust is a clean-rewrite implementation
with no deployed cohort holding Base58-segment paths on disk. The
test fixtures use freshly-generated identity-form peers; production
deployments do not yet exist.

**Interim choice:** No migration binary, no orphan-recovery loop.
The v7.64 path-rewrite is purely a code change — no on-disk data
needed migrating because no on-disk data exists.

**For architecture:** acceptable, or does the proposal want a
placeholder + exit-code convention even for impls without a cohort?
Recommend the proposal explicitly allow this clean-slate skip in §2.5.

### F4. Stability rule (§2.6) not enforced at Keypair layer

**Passage:** `PROPOSAL-V7-PEER-ID-IDENTITY-MULTIHASH.md` §2.6 — impls
MUST NOT silently change a running peer's `hash_type` across upgrades.
Satisfied by (a) persisting `hash_type` alongside the keypair, (b)
persisting the full Base58 PeerID, or (c) explicit operator opt-in.

**Rust state:** `Keypair` PEM file persists only the 32-byte seed.
The `.pub` sidecar carries the derived Base58 PeerID + base64 pubkey,
but `Keypair::load_from_file` reads only the seed and re-derives the
PeerID using the current default (identity-form, post-v7.64). No
hash_type persistence; no .pub-sidecar consultation at load time.

**Interim choice:** Rust pre-v7.64 had no deployed Keypair PEMs with
SHA-256-form PeerIDs that callers depend on. Post-v7.64 every
freshly-derived Keypair produces identity-form. The stability rule
is **trivially satisfied** in practice (the implementation never
changes the form for a given Keypair instance in-process), but is
**not structurally enforced** at the file-format boundary.

**For architecture:** is structural enforcement at the keypair-load
boundary a MUST for impls that already have deployed cohorts, or is
"current default forever" acceptable when no migration burden exists?
Go/Python may need to weigh this against their deployed bases.

### F5. POL-DF-4 conformance vector collapsed into POL-DF-2

**Passage:** `PROPOSAL-V7-POLICY-DUAL-FORM-PRE-CONFIGURATION.md` §2.7
enumerates POL-DF-1..POL-DF-6, with POL-DF-4 specifically covering
canonicalization mechanics ("write Base58-form entry; peer connects;
verify (a) policy applies, (b) impl that canonicalizes per §2.3
produces a hex-form entry and deletes the Base58 entry").

**Rust state:** The Rust suite has POL-DF-1, POL-DF-2, POL-DF-3,
POL-DF-5, POL-DF-6. POL-DF-2 asserts both behaviors that POL-DF-4
enumerates separately: policy applies AND canonicalization writes
hex / removes Base58 (in one test). No separate POL-DF-4 test exists.

**Interim choice:** Rust canonicalizes by default (it doesn't carry
the "MAY skip" branch), so the two vectors collapse to one. The
spec says canonicalization is SHOULD-tier; impls that skip it would
need POL-DF-4 split out to assert non-canonicalization behavior.

**For architecture / Go+Python:** if Go's vector authoring keeps
POL-DF-4 split, Rust can add a separate test that just asserts the
canonicalized state (redundant with POL-DF-2 but matches the vector
naming). Worth a quick alignment on whether the proposal's
"canonicalize / not canonicalize" split is normative or naming-only.

---

## ~~PROPOSAL-REVISION-AUTO-VERSION-FIX §6D.4 — "reject at config-write time at the handler boundary"~~ RESOLVED

**Resolution:** PROPOSAL-CASCADE-SEMANTICS-AND-STATE-MANAGEMENT (adopted)
§7.2 resolved this: revision adds a `config` handler operation
that validates before writing. The `revision/config` op validates against
required-exclude rules, writes the config entity, and coordinates the
tracking-config — all within one handler invocation. Direct tree.put to
`system/revision/config/**` is guarded by capability (only the revision
handler's self-grant can write there).

Defense-in-depth: `ConfigCoordinationHook` remains as a Phase 1 emit
consumer that halts the cascade on invalid config writes that bypass the
handler op (§7.2 MAY).

---

## EXTENSION-REVISION §2.1 vs Go impl: config storage path

**Spec passage (§2.1):** "Stored at `system/revision/config/prefixes/{name}`."

**Go implementation:** writes configs at `system/revision/config/{prefix}`
(no `/prefixes/` segment). See
`entity-core-go/ext/revision/handler.go:186`:
`return "system/revision/config/" + prefix`.

**Validator:** the Go `validate-peer -category auto_version` tool follows
Go's convention, so cross-impl validation runs against
`system/revision/config/{prefix}` regardless of what the spec says.

**Rust interim:** listens on the broader `system/revision/config/` prefix
and filters by entity type (`system/revision/config`) so both conventions
resolve correctly. Writes configs at `system/revision/config/{prefix}` to
match the validator and interop with Go.

**Question for architecture team:** reconcile §2.1 with Go's convention.
Either amend the spec to match the de-facto path, or ask Go to move. The
type-filtered listing is an interim tolerant reader — resolution would let
us narrow it.

---

## ~~Implementation gap: SyncTreeHook cannot halt the emit cascade~~ RESOLVED

**Resolution:** `SyncTreeHook::on_tree_change` now returns
`Result<(), CascadeHalt>`. `NotifyingLocationIndex::dispatch_event` short-
circuits the hook loop on `Err`, collects completed/halted/skipped consumer
names into `CascadeResult`, and skips the Phase 2 broadcast on halt.
`TreeHandler::handle_put` translates an incomplete `CascadeResult` into a
207 Multi-Status response with a `system/tree/partial-result` entity.

All six hooks updated. `RevisionEngine` (auto-version) now returns
`Err(CascadeHalt)` when the tracking-config invariant is violated,
satisfying §6D.5's MUST-halt.

---

## EXTENSION-IDENTITY v1.2 — five gaps surfaced during Phase A implementation

The identity extension was implemented in a Phase A scope (handler ops,
entity codecs, `verify_k_of_n_signatures` at the entity level). Five
spec gaps surfaced that the implementation had to choose conventions for.
None block Phase A from working end-to-end on a single peer; all need
architect attention before Phase B (cross-peer interop) lands.

### IDENTITY-1 — "signature entity" structure not pinned

**Spec passage (§3.10):** the `verify_k_of_n_signatures` pseudocode says
`find_signature where target = entity_hash, signer = candidate`. The
operation is treated abstractly. The spec never names the type of these
signature entities, where they live in transit, or where they live at rest.

**What's unclear:** Are these the existing V7 `system/signature` entities
(used for cap envelopes) reused for identity attestations, or a distinct
`system/identity/signature` type? Where are they discoverable from? In
transit (`included` map of the EXECUTE), at rest under a tree path, or
both?

**Rust interim choice:** reuse `system/signature` entities (same shape as
V7 cap signatures, `entity_types::SignatureData`); scan only the request's
`included` map at validation time. Async signature gathering (§7) is not
yet wired — when it lands it will need a tree-path convention for
persisted in-flight signatures (Phase A defers).

**Why it matters:** §7's async signature gathering (SHOULD) requires a
durable signature path; without one, K-of-N can only be assembled in a
single transaction. Affects compromise-recovery ergonomics (collecting
quorum signatures across devices).

### IDENTITY-2 — `signer_resolution: "identity-resolved"` recursion bound

**Spec passage (§3.1):** identity-resolved mode "resolves through its
identity layer to its current operator-delegation; the signature is
verified against the current Op for that public identity." Cross-refs
`EXTENSION-GROUP §G3.7` for group quorum semantics.

**What's unclear:** Recursion termination. If constituent A is
identity-resolved to Public_A whose own quorum is identity-resolved with
constituent B, and B's quorum references A, the resolution is cyclic. The
spec doesn't specify a bound, a cycle-detection rule, or a max depth.

**Rust interim choice:** Phase A returns
`ValidationError::IdentityResolvedUnimplemented` for any identity-resolved
quorum. Single-identity deployments use `concrete` exclusively (the
overwhelmingly-default per §3.1 prose). Group quorums are
`EXTENSION-GROUP` territory anyway.

**Why it matters:** Will block Group extension implementation when it
lands. Architect call: pick a bound (depth N, cycle detection that fails
closed), or specify the resolution as iterative-not-recursive (resolve
each constituent once, no transitive walk).

### IDENTITY-3 — live-operator-delegation enumeration convention

**Spec passage (§5.2 step 2 / §5.3 step 4):** "enumerate all live
operator-delegations under this quorum"; "find_current_operator_delegation_for(ctx, quorum, operator)".
Per IA1, the supersedes chain is per-(quorum, operator).

**What's unclear:** No tree-path convention for tracking which delegations
are "live" vs. superseded. Implementations have to scan
`system/identity/quorum/{q}/operator-delegation/` and apply supersedes
chains per-operator. Or maintain a per-operator current-pointer subtree.
The spec doesn't pick.

**Rust interim choice:** maintain a per-operator current pointer at
`system/identity/quorum/{q}/current-operator-delegation/{operator}` →
delegation hash. `process_delegation` updates the pointer; `retire_operator`
removes it. `find_live_operator_delegations` walks the subtree.

**Why it matters:** Cross-impl interop (Go peer reading Rust's tree, vice
versa). If Go uses a different convention, neither can enumerate the
other's live set. Architect call: pin a convention, or specify each
implementation MUST scan the operator-delegation subtree itself and apply
supersedes (slower but no shared state).

### IDENTITY-4 — TOFU PQA cache storage convention

**Spec passage (§3.6 / §5.8):** "Bob's peer caches this at TOFU (first
contact with Public_alice). ... When Bob's peer processes a rotation
entity with `quorum_recovery: true`, it MUST validate the K-of-N
signatures against the cached `public-quorum-attestation` for Public_alice.
... MUST reject if no `public-quorum-attestation` is cached (fail-closed)."

**What's unclear:** Storage location of Bob's cache. The spec mandates
the cache exists; doesn't specify where Bob's peer keeps it. Multiple
public_identities, multiple supersedes chains.

**Rust interim choice (Phase B planning):** suggested path
`system/identity/contacts/{contact_public_identity}/public-quorum-attestation`
(see `attestation::path_contact_pqa_cache`). Not yet wired into a
Bob-side verifier (Phase B work).

**Why it matters:** compromise-recovery interop depends on this.
Different impls will diverge unless pinned.

### IDENTITY-5 — verifier cache-miss policy `fetch-on-demand` registry protocol

**Spec passage (§10.1 / §10G.4 of PROPOSAL-IDENTITY-RECOVERY-VALIDATION):**
"implementations MUST expose a deployment-level configuration for
verifier behavior on missing per-peer `runtime-peer-attestation`:
`fetch-on-demand` (default for online deployments; resolves through the
grantee's registry), `reject-and-escalate` (fail-closed), or
`embedded-only` (rejects unless the cap envelope embeds the attestation)."

**What's unclear:** `fetch-on-demand` requires a registry/discovery
protocol that the spec doesn't define. What request is sent, what
response shape, against what endpoint, with what auth? `EXTENSION-NETWORK`
references `PLAN-REGISTRY-AND-DISCOVERY-LANDSCAPE` but the protocol is
not yet pinned.

**Rust interim choice:** Phase A handler doesn't enforce the policy at
the cap-verifier level (cap-chain hook is Phase B work). Phase B will
ship `embedded-only` and `reject-and-escalate` first; `fetch-on-demand`
gates on the registry protocol landing.

**Why it matters:** the rotation-recovery surface across runtime peers
(§9.4 long-lived cap survival, §3.5 mode promotion) depends on this for
production deployments. `embedded-only` works for short-TTL flows;
long-lived flows need `fetch-on-demand`.

### Cross-cutting (Phase B work, not gaps): cap-chain attestation hook

§12.3 documents that "cap-chain verification consults attestation state
for grantee identity-binding lookup" but the implementation seam between
`verify_capability_chain` (in `core/capability`) and the identity
extension's attestation cache is undefined. Phase B will pin a
`AttestationStore` trait or similar and inject it into the verifier;
needs cross-team agreement on the interface shape.


---

## EXTENSION-IDENTITY v1.2 — Phase A self-review log

After Phase A landed (handler + 27 tests), self-review against the spec
surfaced four implementation bugs (B1-B4) and four spec ambiguities (A1-A5).
Bug fixes land in Phase B. Ambiguities go back to the architecture team.

### Bugs in Phase A (fix in Phase B)

**B1 — `handle_rotate_pi_recovery` validates against wrong quorum.**
§10.1 MUST: "validate K-of-N signatures against the cached
`public-quorum-attestation` for Public_alice." Current code validates
against the local peer's `cfg.trusts_quorum`, which is correct only for
the case of the local peer rotating its OWN public identity. For the more
general case (a peer processing a contact's recovery rotation), the
validation must look up the cached PQA for `rot.old_identity` and use ITS
signers/threshold. Fail-closed if no PQA cached for that identity.

**B2 — `handle_revoke_peer` doesn't revoke caps to the revoked peer.**
§5.9 scope=internal/all: "delete attestation; revoke local caps from this
peer to the runtime peer being revoked; remove peer-config bindings."
Current code does the attestation delete and binding removal but doesn't
touch any caps. Need to walk cap bindings whose grantee == runtime_peer
and remove them from the tree.

**B3 — `rotate_quorum` doesn't update `peer-config.trusts_quorum`.**
After rotate_quorum, a NEW quorum entity exists at a new content_hash.
`peer-config.trusts_quorum` still points at the OLD hash. Future calls to
`process_delegation` with `del.quorum = new_quorum_hash` will fail the
`del.quorum != cfg.trusts_quorum` mismatch check, even though the new
delegation legitimately follows the rotation. §5.7 says "future
operator-delegations and quorum-updates validate against the new
constituent set" — peer-config must move to the new quorum hash atomically
with rotate_quorum.

**B4 — `rotate_quorum` validates new PQA against new_signers, but spec
ambiguously says previous quorum signs.** §3.6: "the supersedes chain
[on PQA] is signed by the previous quorum so updates are validated against
cached state." Current code validates the new PQA against `qu.new_signers`
(the new quorum's constituents). §5.7 says PQA is "K-of-N signed by
quorum constituents themselves" — which constituents? If the new ones,
contacts with cached PQA-v1 can't validate the chain (they don't trust the
new signer set yet). If the old ones, they can. See A4 below for the
ambiguity; B4 is the impl bug if A4 resolves to "previous quorum signs."

### Spec ambiguities (architecture team)

**A1 — §13.2 example contradicts IA1.** §13.2 step 2 has Cold1+Cold2 sign
"a new operator-delegation: `{quorum: ..., operator: Op_v2_id,
supersedes: hash(previous_delegation)}`." Per IA1 (v1.2), supersedes is
per-(quorum, operator); a delegation cannot supersede a delegation for a
DIFFERENT operator. The §13.2 flow predates IA1 and is incompatible with
v1.2's handler logic. The IA1-correct flow is: (a) add Op_v2 with
`supersedes: null`, (b) `retire_operator(Op_v1)`. §13.2 should be
rewritten for v1.2.

**A2 — How does the contact-PQA cache get populated?** §3.6 / §5.8 / §10.1
mandate the cache exists ("Bob's peer caches this at TOFU"), but the spec
doesn't pin the mechanism. Three plausible candidates: (a) sync extension
delivers PQAs from contacts' `system/identity/public/`, peer auto-caches;
(b) explicit `register_public_identity` call carries the contact's PQA
in `included` and writes it to the cache; (c) manual `tree:put` to the
cache path. Without pinning the mechanism, cross-impl interop on the
recovery flow is undefined.

**A3 — §5.6 `rotate_operator` prose contradicts IA1.** §5.6: "The handler
issues a quorum-signed operator-delegation naming `new_operator` with
`supersedes: <old_operator's current delegation hash>`." Per IA1, supersedes
is per-(quorum, operator) — you can't supersede a different operator's
delegation. Either the §5.6 prose needs updating, or rotate_operator
should be redefined as a compound op (add new + retire old) rather than a
single supersedes step. The data structures already support multi-Op (per
§6.3 Pattern B step 2 / §11.7); only the §5.6 prose is stale.

**A4 — §3.6 vs §5.7 — who signs the new PQA on rotate_quorum?** §3.6:
"the supersedes chain is signed by the previous quorum so updates are
validated against cached state." §5.7: "K-of-N signed by quorum
constituents themselves." If "themselves" means the new constituents,
contacts with a cached previous PQA cannot validate the chain (they don't
trust the new signers yet — that's circular). If it means the previous
constituents, the chain is verifiable against cache. §3.6's TOFU-and-chain
model only makes sense with previous-quorum signing. §5.7 prose appears
ambiguous and possibly wrong. Architect call: confirm previous-quorum
signing for PQA updates, or define how contacts validate against a chain
of "self-signed" PQAs.

**A5 — §5.5 publish_runtime_peer_attestation: signature-only
authorization.** §5.5: "This operation is authorized by access to
Public_alice's keypair ... Public_alice's signature on the attestation
entity is what makes it valid." Phase A interpreted this as "signature
alone authorizes" — the handler doesn't check that Public_alice is one
of the local peer-config's bound public identities. This means anyone
with Public_alice's keypair can publish attestations on any peer. That's
likely intended (the keypair access IS the auth model), but worth
confirming. If a peer-config-binding check is also required, the handler
needs to add it.

### Methodological note (also a feedback loop)

In an earlier pass on Phase B planning I framed the work as building
"Bob's identity engine" — a SyncTreeHook that watches tree writes for
attestations. This was invented infrastructure; the spec does not specify
or require an engine. The actual shape of the spec's MUST is much
narrower: a single rule about how the recovery handler does its lookup
(§10.1 MUST against cached PQA). Caught and corrected before any code
landed; logged here as a guardrail for future identity work — match the
spec's surface area; do not invent infrastructure.


### Status update (post-Phase B fixes)

**B1, B2, B3 fixed.** B4 deferred pending A4 resolution.

- **B1:** `handle_rotate_pi_recovery` now looks up cached PQA for
  `rot.old_identity` and validates K-of-N against its signers/threshold.
  Fail-closed if no PQA cached. Cache populated by `configure` (when
  `publish_quorum_attestation: true`) and by `rotate_quorum`. Two new tests
  cover the fail-closed path and a two-peer cross-recovery scenario.
- **B2:** `handle_revoke_peer` (scope=internal/all) now also revokes the
  peer→Op cap if the revoked runtime_peer is one of the live operators.
  Broader cap-grantee revocation (caps issued by other extensions to the
  revoked peer) is out of scope for the identity handler — would need a
  cap-grantee index, logged as future work.
- **B3:** `rotate_quorum` now updates `peer-config.trusts_quorum` to the
  new quorum's hash atomically with the rotation. Future delegations
  validate against the new constituent set per §5.7.
- **B4:** `rotate_quorum` still validates new PQA against `qu.new_signers`.
  Per §3.6's TOFU-and-chain semantics, this should be against the previous
  quorum's signers (so contacts with cached PQA-v1 can validate the chain
  to PQA-v2). §5.7 prose reads ambiguously; deferred until A4 resolves.

**Two-peer integration test landed** exercising §13.5 across two real
`IdentityHandler` instances with a manual TOFU step (sync extension not
yet implemented). Validates both the happy-path and insufficient-signature
rejection.


---

## ATT-1: `is_attestation_live` direct vs transitive supersedes walk

**Spec:** EXTENSION-ATTESTATION v1.0 §4.3 (`is_attestation_live`) vs §5.7 TV-A4
**Status:** Implementation chose transitive walk (TV-A4 intent); awaiting architect confirmation

**Passage:**
```
; Supersession check
; If a later attestation in this chain supersedes att and is itself live,
; att is not the current live state.
later = find_attestations_with_supersedes(att.content_hash, ctx)
for l in later:
  if is_attestation_live(l, ctx, as_of=now):
    return false
```

**Ambiguity:** `find_attestations_with_supersedes` returns DIRECT supersedes
successors only (per §5.6a). Recursion through `is_attestation_live` produces a
counter-intuitive result for chains of length ≥ 3:

Setup: `A → A' → A''`, all signed and not expired.
- `is_attestation_live(A'')`: no successors → live
- `is_attestation_live(A')`: A'' is direct successor and live → DEAD ✓
- `is_attestation_live(A)`: A' is direct successor but A' is DEAD → A keeps
  searching, finds no live successor → A is LIVE

But TV-A4's normative result requires `A''` to be the live head when starting
from A's `attested` peer. With A also "live" per the strict reading,
`default_find_authorizing` produces `live = [A, A'']` (two distinct heads),
tie-broken by content_hash — non-deterministically A or A''.

**Interim choice:** Implemented transitive forward walk. `is_attestation_live`
returns `false` if ANY transitively-reachable supersedes-descendant is
self-valid (not expired/not_before, not self-revoked). `find_live_head` walks
through dead intermediates to surface the deepest live link. Both choices
needed to satisfy TV-A4.

**Impact:** TV-A4 passes. Single-link chains and the other 10 TV-A vectors
behave identically under both interpretations.

**Action requested:** Architect to confirm whether the spec text in §4.3
should be amended to reflect transitive semantics (matching TV-A4 intent), or
TV-A4 should be amended to match the strict direct-only reading.

---

## ATT-2: `identity_verify_cert` signature-validation order

**Spec:** EXTENSION-IDENTITY v3.2 §3.6 `identity_verify_cert` pseudocode
**Status:** Implementation reordered to dispatch-on-topology first; awaiting architect confirmation

**Passage:**
```
identity_verify_cert(att, ctx) → bool
  ; ...
  # Generic signature validation (single-sig default; topology may require more)
  if not ATTESTATION.verify_attestation_signature(att, ctx):
    return error("invalid_signature")
  # Liveness check (generic)
  if not ATTESTATION.is_attestation_live(att, ctx):
    return error("not_live")
  # Authority-revocation check (identity-specific authority rules)
  ...
  # Topology dispatch + validation
  topology = identity_topology_for(att, ctx)
  match topology.mode:
    "k-of-n":
      if not QUORUM.verify_k_of_n_signatures(...):
        return error("k_of_n_failed")
```

**Ambiguity:** The pseudo runs `verify_attestation_signature` (single-sig
from `att.attesting`) BEFORE topology dispatch. For top-level controller
certs, `att.attesting = quorum_id` — and a quorum_id is a structural entity
hash, NOT a peer with a keypair. So the single-sig check necessarily
fails ("no signature found from quorum_id as a single signer"), and
control never reaches the K-of-N topology dispatch which could actually
validate the cert.

**Interim choice:** Reordered `identity_verify_cert` to dispatch on
topology first. Signature validation runs in the topology-appropriate
variant: `Single` calls `verify_attestation_signature`; `Dual` calls
`verify_specific_signer` for each signer; `KofN` calls
`verify_k_of_n_signatures`. The spec's stated invariants
(signature must be valid; cert must be live; chain must terminate at
quorum) are all preserved; only the phase ordering changes.

**Impact:** Three-key default ceremony validates correctly (top-level
controller cert + agent cert chain). Without the reorder, no top-level
controller cert can ever validate.

**Action requested:** Architect to amend §3.6 pseudocode to dispatch on
topology before signature validation, OR introduce a separate
`is_quorum_signed` predicate that the pseudo checks before calling
`verify_attestation_signature`.

---

## RATIFIED: ATT-1 and ATT-2

Both ambiguities ratified by `PROPOSAL-IDENTITY-V3.2-MIGRATION-FIXES.md`
in the architecture-team's cross-impl-feedback batch:

- **ATT-1 → SI-2.** Architecture-team confirms the transitive walk
  (the impl behavior). Spec text in EXTENSION-ATTESTATION v1.1 §4.3
  rewritten to specify `has_live_transitive_descendant` explicitly.
  Predecessor-revival side effect documented as intentional.
  **Rust impl is conforming.** New TV-A4a–TV-A4d test vectors all pass
  (verified: 24 attestation tests, 0 fails).

- **ATT-2 → SI-23.** Architecture-team confirms topology-first dispatch
  (the impl behavior). Spec pseudocode in EXTENSION-IDENTITY v3.3 §3.6
  rewritten to dispatch on topology before signature validation.
  **Rust impl is conforming.** New TV-I-V23 test vector covers top-level
  controller cert validation via K-of-N path (verified: 17
  identity tests, 0 fails).

Both ratifications shipped without wire-format change; the existing impl
behavior was correct. Other items from the proposal landed: SI-7 (path_required
error code), SI-10 (process_attestation fail-closed unbind), SI-13
(identity_confers_function for lifecycle-kind chain walks), SI-16 (`as_of`
historical resolution on current_signer_set), SI-17 (resolve_peer_pubkey
vocabulary), IDENTITY-2 (resolver max_depth=8 + cycle detection).

Workspace: 853 tests pass, 0 fail.

---

## SPEC-24 — Op request/result type-name convention not pinned

**Specs:** EXTENSION-ATTESTATION v1.1 §6, EXTENSION-QUORUM v1.1 §6, EXTENSION-IDENTITY v3.3 §6
**Status:** Implementation adopting V7 precedent; awaiting architect ratification

**Passage:** Each handler op section defines the params and result *shapes*
inline:
```
### 6.1 `system/attestation:create`
**Params:** `{attesting: hash, attested: hash, properties: map, ...}`
**Result:** `{attestation_hash: hash}`
```
…but never says "register this params shape as a type at
`system/type/system/attestation/create-request`." The shapes are defined
but the registered type-names are not specified.

**Ambiguity:** The wire-conformance validator (Go's `validate-peer`)
verifies type registrations at canonical names like
`system/attestation/create-request`, `create-result`, `supersede-request`,
`supersede-result`, `revoke-request`, `revoke-result`, `verify-request`,
`verify-result` (and the same for quorum + the missing identity result
types). Cross-impl convergence depends on all impls registering the same
names. The spec does not enumerate them.

**Interim choice:** Adopt V7's existing precedent in `core/types`:
- `TYPE_TREE_GET_REQ = "system/tree/get-request"`
- `TYPE_TREE_PUT_REQ = "system/tree/put-request"`
- `TYPE_HANDLER_REGISTER_REQ = "system/handler/register-request"`

The pattern is `{handler-namespace-path}/{op-name}-request` and
`{handler-namespace-path}/{op-name}-result`. The Rust impl now registers
all 21 substrate + identity result types under this convention. Field
shapes follow the spec §6 inline definitions verbatim.

**Action requested:** Architect to either (a) explicitly normatively
define the convention in each spec's §6 (or in a shared editorial
section), or (b) ratify the existing impl convergence by listing canonical
type-names in the spec text.

---

## SI-11 envelope.included signature ingestion — IMPLEMENTED

Per spec EXTENSION-IDENTITY v3.3 §6.2 (sharpened SI-11 ruling). Rust impl
landed at `extensions/identity/src/ingest.rs` with helper
`ingest_signatures_from_included(included, content_store, location_index)`,
called at the top of the identity handler's `handle()` before any op
dispatch. Mechanism:

- Phase 1: persist any `system/identity` entities in `included` first
  (so signature ingestion can resolve `signer` → peer_id).
- Phase 2: persist + bind each `system/signature` entity at
  `/{signer_peer_id}/system/signature/{target_hash_hex}`.
- Idempotent on hash collision; fail-closed on path conflict
  (`signature_path_conflict` error).

Tests: `si11_ingestion_persists_and_binds_signature_at_v7_path`,
`si11_ingestion_fail_closed_on_path_conflict`,
`si11_ingestion_includes_referenced_identity_entities`.

This closes the prior `IDENTITY-1` Rust ambiguity entry around the
ingestion mechanism — the spec amendment (SI-11) defined the canonical
path + conflict semantics, and the impl follows.

---

## RUST-FAILURES — Cross-impl validator gap report (Go team)

**Source:** the Go team's cross-impl validator gap report on Rust.

**Items closed (M1 + M2, multi-sig primitive):**

- **§M1 polymorphic `granter`** — `system/capability/token.granter` was
  registered as `system/hash`; spec mandates
  `union_of(system/hash, system/capability/multi-granter)`. Fixed: added
  `FieldSpec::union(...)` constructor in `core/types/lib.rs`, updated
  `system_capability_token` registration. CBOR major-type discrimination
  per §M8 (bstr vs map) handled by existing union_of infrastructure.
- **§M2 `system/capability/multi-granter`** — type was unregistered.
  Added `system_capability_multi_granter()` per spec §3.2:
  `{signers: array_of(system/hash), threshold: primitive/uint}`.
  Constant `TYPE_CAP_MULTI_GRANTER` exposed in `core/types/lib.rs`.
- New regression test `test_multisig_primitive_types_registered` asserts
  both items.

**Items deferred (local/files):**

- 31 cascading failures from missing `local/files` handler. Spec
  `DOMAIN-LOCAL-FILES.md` (v1.1, 890 lines, status "Draft — prototype
  domain for sync milestone validation") is unimplemented in Rust. This
  is NOT a v3.3 substrate gap — it's an unimplemented prototype domain
  extension covering filesystem mapping, file watcher, reverse-write
  subscription, two-entity model. Go report itself notes the cleaner
  fix may be on the validator side: "Go's peer-manager passes `--files`
  only when the user specifies it. ... The same skip pattern should
  apply on Rust if the extension exists but isn't enabled." Logged as
  scoped-elsewhere; awaiting user direction on whether to implement.

**Items not actionable (origination):** Requires `-reference-peer`
flag; not a Rust gap.

---

## Failure #4 (RUST-FAILURES update) — TV-A4a/b/c/d behavioral failures CLOSED

**Symptom:** All four TV-A4 behavioral tests over the wire returned
`reason=attestation_not_indexed` from `system/attestation:verify`.

**Root cause:** The `AttestationIndexHook` (SyncTreeHook adapter) was
*defined* in `extensions/attestation/src/hook.rs` but never *registered*
with `core/peer`'s `emit_dispatcher`. So the index was only populated
when an attestation entered the tree via the substrate's `:create` op
(handler-side direct insertion); writes via `tree:put` (the kernel op)
bypassed it.

**Spec source:** EXTENSION-ATTESTATION v1.1 §9.1 invariant I1 — "When
`system/attestation:create` (or `:supersede`, `:revoke`, **or any
operation that writes a `system/attestation` entity to the tree**)
completes successfully, the entity MUST appear in the [...] indexes."

**Fix:** Register `AttestationIndexHook` with `emit_dispatcher` inside
the `#[cfg(feature = "attestation")]` block of `core/peer/src/lib.rs`,
right after the substrate handler is wired. The hook fires on every
tree mutation; if the written entity is `system/attestation` it
populates the index regardless of which op produced the write.

Registration position: early in the cascade (before downstream hooks
that might call `find_attestations_*`). Hook name: `attestation/index-maintainer`.

**Test:** `invariant_i1_hook_populates_index_on_external_tree_put` in
`extensions/attestation/src/tests.rs` exercises the kernel-write path
directly (synthesizes a TreeChangeEvent without going through the
substrate handler) and asserts the index gets populated.

---

## V7 v7.37 Amendment 1 — SPEC-25 closure (dispatcher-level ingestion)

**Spec source:** ENTITY-CORE-PROTOCOL-V7 v7.37 §6.5 (replaces SI-11
in EXTENSION-IDENTITY §6.2; original §6.2 is now a one-paragraph
pointer at V7 §6.5).

**Reading divergence resolved:** Go/Python (Reading A — dispatcher
level) vs Rust (Reading B — IdentityHandler entry). Architecture team
ratified Reading A. Per spec §6.5: "Ingestion runs once per envelope
at the dispatcher's envelope-unwrap step, before any handler is
selected. It applies uniformly to ALL handler ops: kernel ops
(`system/tree:put`), substrate ops (`system/attestation:verify`,
`system/quorum:verify`, etc.), identity ops, and any extension's
handler ops."

**Rust changes landed:**

1. **Helper moved.** `ingest_signatures_from_included` (in
   `extensions/identity/src/ingest.rs`) → `ingest_envelope_signatures`
   in **`core/peer/src/ingest.rs`**. No extension dependency; uses
   only core/store + core/crypto + core/types.

2. **Dispatch wiring.** `core/peer/src/connection.rs::dispatch_request`
   calls `ingest_envelope_signatures(&envelope.included, ...)` AFTER
   `verify_request` succeeds and BEFORE handler resolution. Failure
   semantics per §6.5: 400 `signature_path_conflict` on path conflict;
   500 `ingest_io_error` on transient I/O. Either short-circuits
   dispatch.

3. **IdentityHandler::handle()** no longer ingests; comment notes the
   dispatcher already did it. Substrate `find_signature_by_signer`
   reads pre-bound signatures from the tree.

4. **Tests.** Removed three `si11_*` tests from
   `extensions/identity/src/tests.rs` (the helper isn't in identity
   anymore). Added four equivalent tests in `core/peer/src/ingest.rs`
   tests module covering: persists+binds at canonical path; idempotent
   re-run; picks up identity entity from envelope; fail-closed on
   path conflict.

**Workspace status:** 859 tests pass, 0 fail. The behavioral_v33 4/0/0
gap on Rust should now flip to 4/4/4 because TV-A4a/b/c/d harness sends
attestations + signatures via envelope.included → tree:put; the
dispatcher now binds the signatures at canonical V7 paths before
`tree:put` runs; the attestation index hook (Failure #4 fix) populates
the attestation index on the same write; substrate `:verify` finds
both via tree lookup.

**SPEC-24 status:** ratified at V7 §3.7 per Amendment 1 (handler-op
input/output type-registration convention). Rust impl already adopted
this convention; no code change required, just a doc pointer update
(deferred — cosmetic).

## Rust-side implementation gap: OPFS LocationIndex durable-write failure is unreportable

**Type:** Rust infrastructure limitation (NOT a spec ambiguity — logged
here per CLAUDE.md "note Rust-side implementation gaps ... separately").
**Severity:** correctness (durability divergence on I/O error; bounded
by OPFS reliability — OPFS rarely fails mid-session).

**The MUST.** The protocol treats a storage write failure as a normal
error condition that produces an error *response* to the caller (the
peer keeps running) — same shape as `ContentStore::put` failing, which
propagates `StoreError` → `TreeError::StoreError` → handler error → wire
error response.

**The gap.** The Rust `LocationIndex` trait cannot express this for the
durable `locations.log` write:

- `LocationIndex::set` / `set_with_context` / `remove` /
  `remove_with_context` return `()` / `Option<Hash>` / `CascadeResult` —
  **no error channel.** The common (non-CAS) tree:put binding write goes
  through `set_with_context` (`core/tree/src/lib.rs:613`).
- `compare_and_swap` / `compare_and_remove` return `Result<_, CasError>`,
  but `CasError` is a closed enum spec-pinned to 409 `hash_mismatch`
  (`Mismatch(Hash)` | `NotFound`, `core/store/src/lib.rs:866`). A journal
  I/O failure is not a 409; overloading `CasError` with an `Io` variant
  would be semantically wrong and is a core-trait + cross-impl change
  (Go/Python share the trait shape).

So when `OpfsLocationIndex`'s `entities.log` mirror write succeeds but
the `locations.log` append fails, the in-memory index is ahead of the
durable journal and the binding is **lost on the next restart**, silently
breaking restart equivalence — and there is no trait path to surface it
as the spec-required error response.

**Interim choice.** `log_swallowed_journal_failure()` in
`core/store/src/opfs.rs` logs the failure loudly at `tracing::error!`
(op, path, error, "lost on restart") and continues. This matches the
codebase's existing accepted behavior for the trait's infallible-`set`
contract (`MemoryLocationIndex`/`SqliteLocationIndex` also assume `set`
cannot fail). It is NOT a chosen "swallow" policy — it is the only thing
this layer can do without a trait-shape change. (An earlier patch made
this `panic!` to halt the peer; reverted — panicking takes down the
whole worker, including all co-hosted peers under the single-worker
topology, for what the spec says is a returnable error. Disproportionate
and not spec-compliant.)

**Proper fix (architect's call — cross-cutting, cross-impl).** Give the
`LocationIndex` write methods a fallible signature (e.g. `set` →
`Result<CascadeResult, IndexError>`, and an I/O-distinct error on the CAS
methods) so the tree handler can map a durable-write failure to a
spec-compliant error response. Affects every backend
(Memory/Sqlite/Opfs/Notifying/Journaled/Indexing) and must stay in
lock-step with the Go/Python `LocationIndex` equivalents. Not undertaken
unilaterally.

## Rust-side implementation gap: worker snapshot/live mirror-population asymmetry

**Type:** Rust worker-host design inconsistency (not a spec issue).
**Severity:** correctness (stale cache entries for non-subtree
subscriptions); contained by the proxy's `prefix_covers` read gate.

**The asymmetry.** A `WorkerProxy::observe(prefix)` subscription's
main-thread mirror is populated from two sources that use *different*
path-matching rules:

- **Initial `Event::Snapshot`** — host `build_initial_snapshot` →
  `PeerContext::list_entities(prefix)` → `LocationIndex::list(prefix)`,
  a **raw `path.starts_with(prefix)` prefix scan** with the wire prefix
  verbatim.
- **Live `Event::Change`** — host registers the SDK subscription with
  `prefix_to_pattern(prefix)` and the engine delivers per
  `entity_subscription::engine::pattern_matches` (`"*"` → all;
  `pat.strip_suffix("/*")` → `starts_with(stem) && longer`; else exact).

For a **subtree** wire prefix (`/a/b/` or `/a/b/*`) the two roughly
agree. For an **exact-match** wire prefix (`/a/b/state`, no trailing
slash) they diverge: the snapshot scan pulls in every string-prefix
sibling (`/a/b/state2`, `/a/b/state/child`) but live delivery only ever
updates the exact path `/a/b/state`. The mirror is born over-populated
with siblings the worker will never keep current.

**Interim handling (proxy-side, landed).** `wasm-worker-proxy`'s
`prefix_covers(prefix, path)` is the exact composition of
`pattern_matches(prefix_to_pattern(prefix), path)`, and `cache_get` /
`cache_list` / `put_and_wait_for_cache` all gate reads through it. This
makes reads return only live-maintained entries — the stale snapshot
siblings are present in the `BTreeMap` but never surfaced. Correct for
consumers, but the mirror still wastes memory holding entries that can
never be read or updated, and it means an exact-match subscription's
snapshot does work (fetch + ship siblings) that is then unreachable.

**Proper fix (worker-host side, architect's call).** Make the snapshot
scan honor the same `prefix_to_pattern` semantics as live delivery —
i.e. for an exact-match prefix the snapshot should contain at most the
single exact path, not a `starts_with` sibling set. Small host-side
change (filter `build_initial_snapshot`'s `list_entities` result through
the resolved pattern), but it changes the `Event::Snapshot` wire payload
shape for exact-match subscriptions, so it wants cross-team sign-off
with the browser app (the Dom frontend) before landing. Logged rather than silently
patched: the proxy gate makes it safe, not correct.

## Spec under-specification: EXTENSION-CONTINUATION §3.4 A.1 lost-error marker — `step_index` and marker entity type


**Spec:** EXTENSION-CONTINUATION v1.9 §3.4 (A.1), §8.2 SHOULD.
**Type:** Spec names a path component / entity it does not fully define.
**Severity:** low (A.1 is a SHOULD; the marker is an observation sink with
no reactive behavior). Implemented in Rust with the interim choices below.

§3.4 specifies the lost-error marker is bound at
`system/runtime/chain-errors/lost/{chain_id}/{step_index}` capturing
"the original error code and status, the on_error delivery URI that
failed, the original request ID, a timestamp." Two gaps:

1. **`{step_index}` is undefined.** No continuation type (§2.1–§2.7) nor
   any handler-context field carries a per-chain step counter, and §3.4
   does not say how a continuation determines its own step index. The
   `chain_id` correlates the chain (§6.2) but the step ordinal is
   nowhere defined.
   - **Interim choice (Rust):** `step_index` = the dispatch-layer
     `Bounds.cascade_depth` (monotonic per chain, already threaded, no
     new entity field). Defensible — it is *a* monotonic per-chain
     ordinal — but not necessarily the "step index" a cross-impl
     conformance test would expect; Go/Python may pick differently,
     producing different marker paths for the same logical failure.
   - **Architect ask:** pin `step_index`'s source (a chain-step counter
     in `Bounds`/`EmitContext`? the continuation entity? `cascade_depth`
     ratified as the definition?) so the marker path is cross-impl
     stable.

2. **Marker entity type name is not pinned.** §3.4 describes the payload
   fields but names no `type_ref`. Rust uses `system/runtime/chain-error`
   (unregistered — markers are informational, not schema-validated).
   Cross-impl marker readers/aggregators need an agreed type string.
   - **Architect ask:** pin the marker entity type (and whether it
     registers in the type system) so aggregators are cross-impl.

Both are logged rather than silently chosen because the marker path and
type are observable cross-impl surface; A.1 being a SHOULD made shipping
the interim acceptable, but the conformance contract needs the pins.

## Rust-side sequenced work item: EXTENSION-CONTINUATION §4.2 case 3 / §8.1 — cross-peer continuation dispatch threading (G2)


**Spec:** EXTENSION-CONTINUATION v1.9 §4.2 case 3, §4.3, §8.1 (G2).
**Type:** Rust impl threading **not yet wired** — extension-layer
composition. **NOT a core-protocol change; zero new protocol primitives.**
**Conformance status:** **No present conformance failure.** §4.2 case 3
specifies advance-time `VerifyChain` failure as the *conformant interim*
where the remote target is resolved only at advance. The cross-peer §8.1
bullet is the required *shape* **when an impl performs cross-peer
continuation (L2) dispatch**; an impl that does not yet do so is **not
non-conformant**. Local/system continuations are wholly unaffected (chain
resolves from the install-persisted local store; in-chain ⇔
rooted-at-installer locally).

**Layer (architecture-team review — agreed).** G2 adds no
new protocol primitives. It composes primitives already normative in V7
and already shipped in Rust: capability authority chains +
`check_creator_authority` (V7 §5.5), `VerifyChain` at the verifying peer
(V7 §5.2), envelope `included` for hash-referenced entities (V7
§3.1/§3.2), content-addressed dedup on ingest. It specifies how a
continuation *composes* these for the cross-peer case — the same shape
EXTENSION-SUBSCRIPTION §1.2/§1.3 already specifies (B-rooted caller cap +
A-rooted deliver_token). **Relocating G2 to core would be wrong** — it
would re-open shipped core primitives to express something the extension
layer already has the vocabulary for. What is genuinely first-of-kind in
Rust is **L2 (continuation chains) working cross-peer at all** — that is
extension + SDK + impl scope, not core, and is explicitly sequenced
(below), not a present conformance gap.

**One honest impl note (verified, not inferred).** The arch-team framing
"do for continuation what subscription already does" is correct at the
*spec/primitive* layer. At the Rust *impl-threading* layer there is no
shipped cross-peer scoped-cap dispatch to copy: the continuation remote
path is not wired (evidence below), and the subscription cross-peer
caller-cap *dispatch threading* in Rust was not confirmed during this
review (only the install-time deliver_token chain check, SB1, is
confirmed shipped). So C-3 + the dispatch threading are first-of-kind in
Rust — which *reinforces* the sequenced, careful approach the spec
prescribes; it does not contradict the arch-team conclusion.

**Spec requirement (§4.2 case 3 / §4.3 / §8.1).** For a continuation
step whose `target` is a remote peer B, the continuation's
`dispatch_capability` MUST be the EXECUTE's capability, and the **full**
authority chain (leaf → B-recognized root) MUST travel in the dispatched
envelope's `included` map (the leaf-only V7 §3.1/§3.2 reading is
insufficient cross-peer).

**What Rust actually does (verified, file:line).** The continuation
handler resolves `dispatch_capability` and passes it as
`ExecuteOptions.capability` (`extensions/continuation/src/lib.rs`
`advance_forward`). But on the remote path that value is **dropped**:

- `core/peer/src/connection.rs:1322-1406` (`make_execute_fn`, remote
  branch) calls `remote::send_execute(conn, keypair, uri, op, params,
  resource, deliver_to)` — `opts.capability` is **not a parameter** and
  is never forwarded.
- `core/peer/src/remote.rs:451` `send_execute` →
  `build_authenticated_execute(keypair, &conn.capability,
  &conn.auth_included, …)` — uses the **connection-level** capability
  from the authenticate handshake.
- `core/peer/src/remote.rs:348` sets EXECUTE `capability` =
  `conn.capability.content_hash`; lines 417/421-425 bundle that
  connection cap + `auth_included` into `included`. The continuation's
  `dispatch_capability` and its authority chain are never on the wire.

So cross-peer continuation dispatch currently authorizes with the
caller's *connection* grant, not the continuation's scoped
`dispatch_capability` — and §4.2 case 3's chain-transport MUST cannot be
met by any handler-side change alone.

**Why this is logged + sequenced (not patched in this pass).** This is
not "scary infrastructure deferred" — logging + sequencing is exactly
what the spec's own ordering prescribes. The work: thread
`opts.capability` through `make_execute_fn`'s remote branch →
`send_execute` → `build_authenticated_execute`, use it as the EXECUTE
capability for continuation dispatch, bundle `collect_authority_chain
(leaf)` into the envelope `included`. Its end-to-end correctness is
**only verifiable cross-peer**, and the proposal/guide explicitly scope
that proof as workbench-owned and the T2-closure gate — with
advance-time-fail as the *specified conformant interim* until then
(so nothing is being deferred *below* its required conformance level):

- `PROPOSAL-CONTINUATION-CROSS-PEER-AND-TRANSFORM-OPS.md`: "Remaining
  (post-merge, not spec-side): V-1 — Phase C (G2) … owned by
  workbench-go; T2 is 'done' on that proof, not on this landing."
- `GUIDE-CONTINUATION-IMPLEMENTATION.md`: the §8.2 SHOULD re-attenuation
  **mint helper (C-3)** — B-rooted cap, installer as leaf granter — is a
  prerequisite, and "Phase C … proves G2 after the SDK mint helper
  exists."

Landing a large speculative rewrite of the remote dispatch path with no
cross-peer harness to validate it would be unverified infrastructure —
the failure mode this repo's recent review lessons explicitly call out.

**Scoped plan to close (coordinated, not unilateral).**
1. Add `ExecuteOptions.included: HashMap<Hash, Entity>` (backward-compat;
   existing `..Default::default()` callers unaffected).
2. Continuation `advance_forward`: when `dispatch_capability` resolves,
   `collect_authority_chain(cap_hash, resolve)` and put every chain
   entity into `opts.included`.
3. `make_execute_fn` remote branch + `send_execute` +
   `build_authenticated_execute`: accept the dispatch capability +
   `included`, set EXECUTE `capability` to the dispatch cap for
   continuation dispatch, bundle the full chain into envelope `included`
   (dedup by hash — content-addressing makes over-inclusion free, §4.2
   "Chain transport").
4. Validate against workbench Phase C with the C-3 mint helper.

Until (4) exists this stays advance-time behavior (B's `VerifyChain`
rejects a non-conformant chain — which the spec §4.2 case 3 explicitly
accepts as "current behavior" where the remote target is only known at
advance). Local and system-created continuations are unaffected
(in-chain ⇔ rooted-at-installer locally; chain resolves from the local
store the install step persisted).

**Update — C-3 SDK helpers LANDED (the prerequisite, not the
threading).** The two §8.2 SHOULD helpers proposal §9.1 assigns to
entity-core-rust are implemented + unit-tested, mirroring the Go
reference shape (`MintReattenuated` / `CollectChainBundle`) but written
from spec:

- `entity_capability::mint_reattenuated` (`core/capability/src/mint.rs`)
  — produces the §4.2 case-3 shape: leaf cap `granter = grantee =
  installer`, `parent = the B-conferred cap`, so the chain is rooted at
  B's conferred authority with the installer in-chain as the
  re-attenuation leaf granter. Rejects zero-hash parent / empty grants.
  Returns `(cap_entity, sig_entity)` (canonical 4-field sig, same shape
  as `generate_deliver_token` / envelope ingest expects). 2 tests
  (shape + bad-input).
- `entity_protocol::collect_chain_bundle`
  (`core/protocol/src/verify.rs`, next to `collect_authority_chain`) —
  generic over content + location resolver closures (the verify.rs
  idiom; no store-trait dep). Walks the chain, bundles every cap + each
  link's granter `system/peer` identity + the granter's signature
  resolved from the V7 invariant pointer path
  `/{peer_id}/system/signature/{hex33(target)}` (byte-identical to
  `core/peer::ingest`'s `hex_segment`). Best-effort per link;
  over-inclusion free (content-addressed dedup). 2 tests (full bundle
  verifiable from the bundle alone via `check_creator_authority` +
  best-effort omission). Both re-exported via the `entity-core` facade.

This closes the **C-3 prerequisite** the proposal/guide gate Phase C on.
Steps **1–3 (the actual remote-dispatch wire threading)** and step 4
(workbench Phase C end-to-end proof) remain exactly as scoped above:
sequenced, coordination-gated, advance-time-fail is the specified
conformant interim until workbench validates them. No present
conformance gap; nothing in this update changes wire behavior.

**Update — Amendment 2 (spec v1.11): mint helper grantee
pin LANDED.** The v1.9 §4.2 case 3 model pinned chain *root* (B-rooted)
and *granter* (installer in-chain) but was **silent on the grantee** —
an incomplete port of the EXTENSION-SUBSCRIPTION §1.2/§1.3 caller-cap
analog (which is B-rooted *and* grantee-determinate). entity-core-go
proved by wire trace, with each impl as originator, that **none of
Go/Rust/Python conform**: the cross-peer dispatched EXECUTE is authored
by the **host peer** (the continuation handler signs with that peer's
keypair — the only key it holds), so B's `grantee == author` check (V7
§5.2) rejects a cap self-wielded to the installer. Go silently escalated
onto the connection cap (the *unsafe* failure — V7 §6.8 leak); Rust
failed closed. Arch resolved it as Amendment 2 → **spec v1.11 §4.2 case
3 (iii)**: `grantee` MUST be the dispatching host peer (the EXECUTE
author); installer unchanged as in-chain leaf granter; chain still
B-rooted. (Amendment 3 / V7 §5.2 v7.43 names the general *three-slot
model* — root = resource owner, grantee = EXECUTE author, in-chain
granters = attenuators incl. installer — that collapses only locally;
clarification, no Rust action.)

My prior `mint_reattenuated` set `grantee = signer_identity.content_hash`
(self-wielded to the installer) — **was non-conformant per v1.11**.
Fixed: `mint_reattenuated` now takes an explicit `grantee: Hash`
parameter (positioned after `signer_identity`, mirroring Go's
`MintReattenuated` arg order for cross-impl review) = the dispatching
host peer; new `MintError::MissingGrantee` zero-check; module/fn docs
rewritten to the three-slot (i)/(ii)/(iii) model; tests assert
`leaf.grantee == host_peer && != installer`. 2 capability tests green;
workspace `--all-features` 0 failed; no other callers (only the facade
re-export — the dispatch consumer is still unwired = step 2). This is
proposal §10.1's entity-core-rust deliverable ("explicit grantee
parameter… solo, unit-testable. **Prerequisite for everything
below**"), now done.

**The remaining Rust work is unchanged in scope but better-equipped.**
The G2-dispatch-grantee continuation note
§RESOLUTION gives a proven 4-step conformance recipe; for Rust the
mapping is: **step 1 (explicit-grantee mint) = DONE** (above); **steps
2–4 = the steps 1–3 dispatch threading scoped above** (authorize the
cross-peer dispatch with the scoped `dispatch_capability` not the
connection cap — V7 §6.8; full chain staged at install + bundled at
advance via `collect_chain_bundle`; subtree-scope prefix ops). What is
*new and changes the calculus*: there is now (a) a Go-proven
end-to-end recipe and (b) a **portable conformance harness** —
`entity-core-go validate-peer -peers <rustPeer>,<goPeer> -category
convergence` with Rust as originator (`clients[0]`); green on
`c3_scope_setup` / `c3_inscope_lands` / `c3_outofscope_denied` ⇒
conformant. So steps 2–4 are no longer "only verifiable cross-peer with
no harness" — the harness exists and pinpoints which step is missing
(failure-mode decoder in the peer doc §RESOLUTION). Still sequenced
(workbench Phase C owns the gate) and still the larger core/peer
wire-path change, but the unverifiability objection that justified
deferring it is now resolved; it is a deliberate next work item, not a
blocked one.

**Update — G2 dispatch threading IMPLEMENTED + PROVEN
CONFORMANT (cross-impl, Rust as originator).** Recipe steps 2–3 landed:

- `core/peer/src/remote.rs` — `build_authenticated_execute` +
  `send_execute` take an optional dispatch-cap override + a
  chain-bundle map. The override (the continuation's scoped
  `dispatch_capability`) becomes the dispatched EXECUTE's `capability`
  instead of the connection grant; the bundle is included (dedup via
  `find_included`). `None` + empty bundle ⇒ byte-identical to pre-G2
  (every existing caller — async inbox delivery, etc. — unaffected;
  passes `None, &empty`).
- `core/peer/src/connection.rs` — `make_execute_fn` remote branch: when
  `opts.capability` is `Some` (a continuation dispatch), it calls
  `entity_protocol::collect_chain_bundle(&cap.hash,
  content_store.get, location_index.get)` (the C-3 helper) and threads
  cap + full chain into `send_execute`. The chain is resolvable because
  continuation install already persists it (§3.2 step 5, verified
  `extensions/continuation/src/lib.rs:927-935`). `collect_chain_bundle`
  `Err` ⇒ send the scoped leaf cap only and warn — B fails closed on
  its `VerifyChain`; that is safe and conformant, **never** a fallback
  to the connection grant, so no V7 §6.8 escalation.
- Unit test `core/peer/src/remote.rs::test_scoped_dispatch_cap_and_chain_transport`
  locks the wire shape (override cap referenced as EXECUTE
  `capability`; every chain entity in envelope `included`; `None`/empty
  byte-identical). Workspace `--all-features` 1003 pass / 0 fail; zero
  new clippy warnings (pre-existing-only, unrelated files).

**Proven conformant by the canonical portable harness.** Ran
`entity-core-go validate-peer -peers <rustA>,<goB> -identity
framework-admin -category convergence` with **Rust as originator
(clients[0])** against a Go reference verifier (B), via
`peer-manager` (rebuilds `entity-cli` from this tree). Result:
`c3_scope_setup` **PASS**, `c3_inscope_lands` **PASS**,
`c3_outofscope_denied` **PASS** (the negative control: an out-of-scope
cross-peer dispatch is *denied* — proves the scoped cap is enforced and
there is no §6.8 silent escalation to the connection grant). Per the
the G2-dispatch-grantee continuation note
§RESOLUTION: "Green on all three c3 checks ⇒ conformant." `rexec_*`,
`chain_*`, `cache_extract_merge/verify`, `bisync_*` also green
(unblocked by this). **The cross-peer continuation G2 work is therefore
no longer a sequenced/interim item — it is implemented and proven; the
SPEC-AMBIGUITIES "advance-time-fail interim" no longer applies to
Rust.**

*Method note (verify, don't infer — recorded because it nearly produced
a false finding).* A first harness run **without** `-identity
framework-admin` failed at continuation `install` with 403
`embedded_cap_unauthorized`. Root cause: `validate-peer`'s
`NewPeerClient` calls `crypto.Generate()` **per address**, so each
PeerClient gets a distinct keypair; the scoped cap was minted
granted-from the B-connection identity but the install was authored by
the A-connection identity → Rust's §3.1a in-chain check **correctly**
rejected (the install author genuinely was not a granter in the
chain). This is **Rust behaving per spec**, not a bug — the
convergence harness is *designed* to run under one shared operator
identity (`-identity framework-admin`, `crypto.LoadIdentity`), as
`scripts/test-cross-peer.sh:80` does and the peer doc's
"Distinct-identity provenance" second-order finding documents
("c3/rexec/chain/bisync are genuinely green under this model"). Rust's
strict §3.1a enforcement was *not* weakened to chase a misconfigured
run — the run was corrected. The remaining convergence reds
(`psync_all_synced`/`psync_path_usable`/`psync_query_namespace`,
`cache_hop2_verify`, `filesync_synced`) are the Go-side
legacy-validator-cap second-path residual + the unimplemented Rust
local-files extension — neither continuation/Amendment-2 nor caused by
this change.

---

## Durability Contract (EXTENSION-DURABILITY v0.1) implementation notes

**Update — architecture extraction.** The §10 durability material
was extracted from EXTENSION-INBOX into a new standalone
`EXTENSION-DURABILITY.md` (v0.1, **EXPLORATORY / OPTIONAL / NOT ACTIVELY
DEVELOPED**). V7 was reverted v7.47 → v7.46 (no durability
material in core); EXTENSION-INBOX restored to v5.6 surface (stamped v5.9);
`PROPOSAL-DELIVERY-AND-DURABILITY` marked RETRACTED. **Wire shape and
behavior unchanged** — the Rust impl below is still correct against the
new file; only spec references shifted (`§10.x → §x`; `V7 §3.2/§3.3
silent-ignore / 412 reservation → EXTENSION-DURABILITY §5/§8`). The 412 /
durability-use-of-202 reservations no longer live in V7's core status
table — they exist only within the surface of a peer that installs
EXTENSION-DURABILITY. EXTENSION-INBOX §7.1's 202 (inbox-ack) is unchanged.
Handoff: the Go team's durability-extraction handoff.

**Status: spec clean (against EXTENSION-DURABILITY v0.1), no ambiguity in
the surface that landed.** The new file is self-consistent and explicitly
implementation-defined where it leaves room (§7 illustrative strength
vocabulary; §4/§8 implementation-defined policy + replication topology).
The §5 verdict table maps cleanly onto a small reconcile function gated on
(a) `requested.self_determinable() && requested.rank() ≤ policy.max`,
(b) `must_have`, (c) async pathway presence (`deliver_to`).

**Implementation choices worth surfacing** (none require architect input,
but worth noting for cross-impl alignment):

1. **Strength vocabulary chosen for this peer:** `none` / `stored` /
   `replicated`. Unknown strings parse to a separate `Unknown(String)`
   variant whose rank is `u8::MAX` — never self-certifiable, so required
   unknown → 412, best-effort unknown → take less observably. Reason code
   spellings pinned at `core/peer/src/durability.rs`:
   `REASON_NO_DURABLE_STORE = "no_durable_store"`,
   `REASON_REQUIRED_UNMET = "durability_required_unmet"`.

2. **Policy → store mapping:** `MemoryContentStore` → `None`;
   `.sqlite()` / `.opfs()` builders auto-set `Stored`. `Replicated` is
   never set automatically — this peer is **not configured for any
   replication topology**, so per §5 row 4 ("not configured for the
   required topology") a *required* replication request is refused with
   412; a best-effort one takes less, observably. This is faithful, not
   a gap; replication topology config is explicitly implementation-defined
   per §8.

3. **Async pathway = `deliver_to`:** the inbox write completes
   asynchronously, so at the moment of the 202 response nothing is
   physically in place yet — `applied` is always `"none"` on the async
   branch (faithful to §5 "never claim durability you don't have"),
   and the achievable strength is carried in `committed` (gated to 202)
   only when the store is durable.

4. **§6 handle = the existing inbox storage key.** The Rust inbox
   handler already stores delivered messages at
   `{deliver_to.uri}/{request_id}` (`extensions/inbox/src/lib.rs` ~L99–104).
   The `(author, request_id)` uniqueness scope (V7 §3.2/§3.3) is satisfied
   when the deliver_to URI is author-scoped at the recipient (the
   prevailing convention); a shared inbox URI with non-UUID request_ids
   could in principle collide across authors. V7 §3.3 RECOMMENDS UUIDs,
   making collisions statistically negligible — flagging for cross-impl
   awareness, not a Rust-side fix.

5. **§3 advertise (SHOULD) deferred.** The receiver's supported
   durability levels are not yet exposed via a discovery surface
   (system/peer/self/status or hello result). The MUST contract is
   complete; advertisement is a follow-up.

6. **Pre-acceptance error responses do not carry a `durability` field.**
   Per §4 reconcile is gated on *accepting* the request; auth /
   path / handler-resolution failures (401/403/404) return before
   acceptance and their explicit status is itself the observable answer
   — not a silent discard. Durability field appears only on the
   post-acceptance response (sync 200/err, deliver_to 202, and the 412
   refusal at acceptance).

**Cross-impl interop:**

- Wire field added to `system/protocol/execute`: `durability_request`
  (optional inline map `{level, must_have}`), same convention as
  `deliver_to`.
- Wire field added to `system/protocol/execute/response`: `durability`
  (optional inline `system/durability-result` entity).
- ECF key ordering on EXECUTE_RESPONSE with durability:
  `result(7) < status(7) < durability(11) < request_id(11)`. Wire
  round-trip test at `core/protocol/src/lib.rs::test_durability_field_wire_roundtrip`
  asserts well-formedness + the bare-map field shape.
- **Wire shape lesson (durability-1 fix; pre-extraction):** the `durability` field
  is typed `system/durability-result` (a specific struct), NOT `core/entity`,
  so the wire value is a **bare CBOR map** of `{requested, applied,
  committed?, max_available?, reason?}` — same convention as `deliver_to`
  (typed `system/delivery-spec`) and `bounds` (typed `system/bounds`).
  The first Rust pass wrapped the field as `{type, data, content_hash}`
  (the `core/entity` convention used for `result`/`params`); the cross-impl
  validator decoded it as a flat struct and reported all fields blank.
  Self-round-trip tests missed it because both encoder + decoder shared the
  same wrong shape. Resolved by replacing `DurabilityResult::to_entity()`
  with `to_cbor()` and threading raw CBOR bytes through
  `build_execute_response_full` / `build_202_response`.

- **§6 preservation (durability-2 fix; pre-extraction):** the §5 invariant
  "applied = physically in place at response time" is honest only if the
  receiver actually writes the originating EXECUTE into a `(author,
  request_id)`-addressable slot when it claims `applied: stored`. Rust's
  first sync-path pass returned `applied: stored` without preserving
  anything — the strengthened `durable_entry_preserved` validator caught
  it. Resolved by `connection.rs::preserve_durable_request`: when the
  verdict's `applied` rank ≥ Stored AND `deliver_to` is absent, the
  dispatcher write-aheads `env.root` to the content store and binds the
  hash at `/{local_peer}/system/inbox/{request_id}` BEFORE handler
  dispatch. On store failure, the verdict downgrades to
  `applied:none, reason:no_durable_store` (observable downgrade — never
  overclaim). The deliver_to path's inbox handler already preserves via
  its existing write-ahead (`extensions/inbox/src/lib.rs::handle_receive`
  L99–104), so dispatcher-level preservation only fires on the no-
  deliver_to path — no double-write. Mirrors Go's `preserveDurableRequest`
  in `core/protocol/durability.go`.

**Post-fix cross-impl status:**

- Single-peer durability category: 13 PASS / 1 WARN / 0 FAIL (sqlite
  backend). Remaining WARN is `advertisement_present` — §3 SHOULD,
  the absence of which "does not change the response contract".
- Scenario 5 (companion peer as outbox), Rust↔Go both directions:
  **5 / 5 PASS each way** — Rust now works both as preserver and as
  durable host of another peer's inbox namespace.
- Status codes: `STATUS_ACCEPTED = 202`, `STATUS_PRECONDITION_FAILED = 412`
  added to `core/handler/src/lib.rs`.


---

## IMPL-TEAM-CHANGELOG absorption

Spec source: the architecture team's impl-team changelog.
Cross-impl items A.2 / A.3 / A.4 / A.8 / I-7 / I-8 all landed on this
branch.

### Background — spec-issue taxonomy

Three categories of spec issue exist; this file tracks all three so the
architecture team has one place to look:

- **Spec ambiguity** — spec is right but ambiguous; multiple valid reads;
  impls diverge without anyone being wrong. Fix is more text.
- **Spec failure / missing spec** — a MUST whose mechanism isn't
  enumerated, missing op in the manifest, missing field definition,
  internally inconsistent rules. Fix is amending the spec.
- **Spec bug** — wrong pseudocode, broken cross-references, inconsistent
  field types. Fix is correcting the spec.

All three are surface-able here; the architecture team categorizes on
intake. (Prior versions of this doc conflated "ambiguity" with "spec
issue I worked around" — that posture was wrong; spec failures get
flagged, not absorbed silently.)

### RESOLVED — landed in REVISION v3.3 / CONTINUATION v1.14 same-day

All four spec issues raised below were resolved in same-day architecture
amendments (the architecture team's impl-team changelog addendum; canonical reference =
REVISION v3.3 + CONTINUATION v1.14).

- ~~**Spec failure: merge-config canonical write path**~~ — EXTENSION-
  REVISION v3.1 §2.3 mandated config-write-time rejection of `lww` /
  `keep-both` but §4.1 op manifest had no merge-config op. Landed in
  **REVISION v3.3 §4.4.18** (`merge-config` op + result type with
  `status: "set" | "deleted" | "no_change"`; §2.3 "Handler-owned
  namespace" declaration). Rust diff: result-shape rewrite + idempotency
  + CAS code rename + bootstrap manifest entry. See `core/peer/src/
  lib.rs:803`, `extensions/revision/src/lib.rs:488`.

- ~~**Spec ambiguity: `chain-error-lost.step_index` for v1.13**~~ —
  CONTINUATION §3.4 v1.13 named `{step_index}` but didn't pin it for the
  v1.13 case; Rust drifted to `cascade_depth`, Go used `RequestID`.
  Landed in **CONTINUATION v1.14 §3.4** ("MUST be the original request
  ID … identical to the A.1 convention"). Rust diff: `ChainErr.step_index`
  field changed `u64 → String`, populated from `ctx.request_id`. See
  `extensions/continuation/src/lib.rs:30,139`.

- ~~**Spec ambiguity: `deterministic` tie-break direction**~~ — §2.3
  table named the strategy but not the direction. Landed in **REVISION
  v3.3 D2** ("the **lower** of `entity_hash` and
  `CANONICAL_DELETION_MARKER_HASH` under byte-wise lexicographic
  comparison wins"). Rust was already lower-hash-wins; no diff needed.

- ~~**Spec ambiguity: §6.1 marker-augmentation vs §6.2 dedup ordering**~~
  — §6.1 didn't enumerate ordering vs the dedup-against-prior-head
  check. Landed in **REVISION v3.3 D3** ("augmentation MUST precede
  dedup"). Rust's `perform_commit` was already in this order; comment
  refreshed to cite v3.3 D3.

### Cross-impl validator FAIL absorbed (impl-side, not spec)

Per `entity-core-go/docs/archive/validation/peer-tracking/RUST-CHANGELOG-2026-
05-20-VALIDATION.md`:

- `revision.revert_file_removed` — Rust's revert built its own trie via
  the shared merge classifier but didn't augment V_target's bindings
  with markers at paths V_revert added. Under v3.1 absence-is-preserve
  the classifier kept the local entity instead of unbinding. Fixed by:
  (a) extracting `augment_bindings_with_markers` as a shared helper used
  by `perform_commit` and `handle_revert`; (b) correcting the merge
  classifier's marker-vs-entity branch to consult `base_hash` first —
  if `base == one side`, it's clean three-way (take the other side),
  not "both changed differently" (which is what `deletion_resolution`
  is for). Test: `revert_unbinds_file_added_by_target_version` in
  `extensions/revision/src/lib.rs:4067`.

  This was a genuine impl bug (not a spec issue): the spec was clear,
  the classifier had a path-by-path logic error I'd introduced when
  rewriting for v3.1 semantics. Mentioning here because the validator
  surfaced it via the same cross-impl absorption pass.

## revision:pull §4.4.8 landed (was stubbed → 501)

**Status:** landed. No arch flag.

`revision:pull` was previously dispatched to `handle_remote_stub` (501
not_implemented) and was not even advertised in `operations()`. Closed
per workbench-go handoff: implemented per EXTENSION-REVISION §4.4.8.

  - `extensions/revision/src/lib.rs::handle_pull`: outbound fetch
    against `entity://{remote}/system/revision` (via `ctx.execute_fn`),
    ingest envelope.included → local store, decode `head` from
    fetch-result, walk the remote's trie locally + iteratively
    fetch-entities (max 32 rounds, matches Go's `pullMaxRounds`), local
    merge against the freshly-fetched remote head.

  - `decode_fetch_params`: new decoder for `system/revision/fetch-params`
    that picks up the `remote` + `remote_prefix` fields (Rust's prior
    `decode_log_params` silently dropped them; pull plumbing now
    threads them end-to-end).

  - Helpers: `build_fetch_params_entity`, `build_fetch_entities_params_entity`,
    `decode_envelope` (entity-revision-local; reuse of `entity_wire::decode_envelope`
    would have required a new crate dep, ~20 LoC inline preferred),
    `inline_to_entity`, `decode_fetch_result_head`,
    `collect_missing_pull_hashes` (mirrors Go), `clone_ctx_with`
    (synthetic ctx for the inner merge invocation).

  - `STATUS_BAD_GATEWAY = 502` added to `core/handler/src/lib.rs` for
    the `remote_fetch_failed` error class.

**Op-list parity survey (Rust vs Go):**

  - revision: now full parity (19/19 ops). `pull` was the only gap.
  - clock: `tick` is a 501 stub in Rust (Go has it); other ops parity.
  - Every other extension: dispatch parity. Field-level audits (like
    the `remote`-on-fetch-params miss this fixed) would require
    per-op param-struct diffing against Go's typed structs and are
    not yet done as a pass. Worth a follow-up sweep, but the
    cross-impl probe is the authoritative source of truth — fields
    that don't surface in conformance probes are unobservable.

## v1.16 / v3.4 / v3.15 landing pass

**Status:** landed. Tracking entry only — no architect attention needed
unless the cross-impl probe flags a divergence.

Three coordinated landings absorbed in this session per
the workbench-go cross-impl fetch/diff/merge-mode handoff:

  1. **EXTENSION-TREE v3.15 (withdrawal).** Removed `tree:extract` since-
     mode in `core/tree/src/lib.rs` — the `since` param handling,
     `handle_extract_since`, the revision-head deref helpers
     (`resolve_revision_head`, `decode_version_root`,
     `decode_version_parents`, `since_appears_in_revision_chain`,
     `extract_peer_segment`, `prefix_hash_hex`,
     `materialize_current_root_from_bindings`), `collect_branch_nodes`,
     `make_included_pair`/`build_envelope`, and all the since-mode tests.
     Per the spec deletion + the "no backward-compat shims" rule.
     Supersedes the older "since-mode diff cost" and "scope-validation
     mechanism" entries below (kept for historical context).

  2. **EXTENSION-REVISION v3.4 (`revision:fetch-diff`).** New op in
     `extensions/revision/src/lib.rs::handle_fetch_diff`. Shape B
     (single-dynamic-field, chain-expressible): `(prefix, base)` — target
     is implicit (handler peer's current head). Calls
     `trie::collect_reachable_hashes` and `trie::collect_trie_entities_except`
     downward into `core/tree/src/trie.rs` (new public primitives modeled
     on the Go reference). Error codes pinned to the workbench probe:
     `400 invalid_params`, `404 no_local_state`, `404 base_not_found`,
     `400 base_not_a_version`, `500 internal_error`. Cap-denied surfaces
     at the dispatch layer (handler-internal cap check is not how the
     Rust revision crate is structured — none of its existing ops do
     in-handler cap checks).

  3. **EXTENSION-CONTINUATION v1.16 (`result_merge` + per-reason marker
     path).** Added `result_merge: bool` to `ContinuationData` with
     encode/decode + omitempty round-trip. Install-time mutex check
     against `result_field` returns `400 invalid_continuation` per §3.2.
     New `assemble_params_merge` helper for §3.6 Step 2 Merge dispatch-
     mode: shallow-union of post-transform map into static params, result
     keys win on collision. Non-map post-transform value degrades to
     static-only params and fires the `merge_value_not_map` lost-error
     marker. `write_lost_error_marker`'s path moved from
     `.../{chain_id}/{step_index}` to
     `.../{chain_id}/{step_index}/{reason}` per §3.4.

**Bug found and fixed: error entities used wrong type name (cross-impl R-1, R-2).** The cross-impl probe at
the workbench-go cross-impl fetch/diff/merge-mode validation note
flagged Rust's `revision:fetch-diff` returning `code="not_found" msg="status 404"` instead of the spec-pinned
`base_not_found` / `no_local_state`. Root cause: 10 extension `error_result` helpers were constructing the
error entity with type `"system/error"` instead of the canonical `"system/protocol/error"`. Go's SDK
(`entitysdk/errors.go::ErrorFromResponse`) only reads `{code, message}` from the result entity when its type
matches `TypeError` (= `"system/protocol/error"`); otherwise it falls back to status-default codes, masking
the handler's actual code+message. Rust's type-registry constant `entity_types::TYPE_ERROR` was already
correct — the helpers just hardcoded the wrong string. Swept all 10 sites (revision, clock, handlers, inbox,
quorum, role, attestation, subscription, query, identity); workspace tests green. Not an arch flag — pure
Rust absorption miss across the extensions.

**Bug found and fixed: tree:extract envelope-type was wrong.** Noticed
while wiring fetch-diff: Rust's `tree:extract` was returning
`system/protocol/envelope` (a protocol-message type for EXECUTE-wrapped
data) instead of `system/envelope` (a data-bundle type). Spec is
unambiguous — `EXTENSION-TREE.md` §6 pins `output_type: "system/envelope"`
on the extract signature row, and
`PROPOSAL-CONTINUATION-TRANSFORM-AND-ENVELOPE-AMENDMENTS.md` S3 is the
landed amendment that explicitly renamed it (Rust just never absorbed
S3). Fixed in this commit: `core/tree/src/lib.rs::handle_extract` now
emits `entity_types::TYPE_ENVELOPE` (`system/envelope`), matching Go,
Python, query, history, and the new `revision:fetch-diff`. Not an arch
flag — a Rust-side absorption miss.

## Rust-side implementation note: EXTENSION-TREE v3.14 §6.2b — scope-validation mechanism — SUPERSEDED by v3.15 withdrawal

**Status:** impl note, not a spec ambiguity. §6.2b is explicit that the
validation **mechanism is impl-defined** (the rejection contract is the
normative part). This entry documents the Rust impl's choice for future
readers; it is NOT a flag for architect attention.

The earlier draft of this entry called this a spec ambiguity. That was
overclaiming — the spec deliberately left the mechanism flexible, and
"the spec's example mechanisms don't fit my model perfectly" is not the
same as "the spec is ambiguous." The spec did exactly what it intended.

**Spec passage** (EXTENSION-TREE.md §6.2b, v3.14):

> The validation mechanism is impl-defined (e.g., walking the trie's
> structural metadata, looking up the snapshot entity that wrapped it);
> the rejection contract is normative.

**Rust's mechanism choice.** `core/tree/src/lib.rs::handle_extract_since`
layers two checks:

  1. **Structural.** `since` MUST resolve to a structurally-valid
     `system/tree/snapshot/node` (correct type + decodable as
     `SnapshotNodeData`). Catches obvious misuse — a non-trie hash like
     a data entity or a snapshot wrapper.
  2. **Revision DAG-walk** (revision-tracked prefixes only). `since`
     MUST appear as a `root` somewhere in this prefix's revision chain,
     walking parents from `head`. Catches the genuine cross-scope case:
     a valid trie root from a *different* prefix's DAG. This is what the
     Go cross-impl validator's R-3 probe exercises.

For non-revision-tracked prefixes there is no chain to walk; only the
structural check fires. That mirrors the spec's MAY-reject/MAY-
materialize stance for non-revision-tracked since-mode (§6.2a) — the
scope guarantees are weakest where the underlying tracking is weakest.

**Cross-impl posture.** Python and Rust have converged on rejecting the
cross-scope case the Go probe exercises. The probe is one
acceptable-subset conformance vector; whether to lift it to a normative
SHOULD/MUST cross-impl test is a workflow question for the conformance-
suite owners, not a spec change.

**Workbench-go acknowledgment.** The workbench-go signoff review noted
"POC did not exercise cross-scope rejection" — added on the arch
edge-case sweep, per PROPOSAL-TREE-EXTRACT-SINCE.md §2.3b. That punt to
"cross-impl conformance vectors at ratification" is now closeable on the
mechanism Rust + Python both implement.

## Rust-side implementation note: EXTENSION-TREE v3.14 since-mode diff cost — SUPERSEDED by v3.15 withdrawal

**Status:** known — not a spec ambiguity; honest accounting.

The Rust `handle_extract_since` resolves the current trie root via the
revision head when the prefix is revision-tracked (per spec §6.2a) —
O(1). The subsequent "diff between since_root and current_root" step does
NOT use the content-addressed subtree-skipping `compute_trie_diff`
algorithm described in `EXTENSION-TREE.md` §4.3. It collects all bindings
from both tries (`trie::collect_all_bindings`) and compares the binding
sets directly.

For the bundling step (trie nodes on changed branches), the impl walks
the current trie from root following each changed path, collecting
visited nodes via `collect_branch_nodes` — that part is O(diff × depth)
as the spec wants.

Combined cost: O(workspace) for the diff classification, O(diff × depth)
for the bundling — NOT the pure O(diff × depth) total the spec's scale
claim implies.

For the canonical workbench-go-POC workload (50-leaf workspace, 1-leaf
change) this is irrelevant. For workspaces in the 10K-100K range it
becomes load-bearing.

Lift when needed: port the `compute_trie_diff` algorithm from
`EXTENSION-TREE.md` §4.3 (recursive trie walk with content-addressed
subtree skip) into `core/tree/src/trie.rs`; call it from both
`handle_extract_since` and the existing `handle_diff` (the latter has
the same shortcut today). Estimated ~100 LoC + tests. Currently NOT a
blocker — the incremental-sync envelope is still materially smaller
than full extract regardless of how the diff is computed server-side.

---

EXTENSION-COMPUTE v3.14 findings live in their own file:
`docs/archive/COMPUTE-V314-FINDINGS.md`. That document carries the categorized
record (spec issues / spec ambiguities / architecture feedback / impl
notes) for the v3.14 cross-impl convergence work and is the artifact
fed back to the architecture team.

---

## ~~EXTENSION-IDENTITY §12.3 — when does the IdentityBindingChecker hook fire on cap-chain grantees?~~ RESOLVED

**Resolution (EXTENSION-IDENTITY v3.8, arch commit c7e51b1).**
Spec now explicitly **excludes cross-peer dispatch-cap grantees** from
the IdentityBindingChecker hook's scope — strict and permissive impls
interoperate. Rust's interim (permissive — no hook installed) is
conformant; no impl change required. Go relaxes its strict policy at
`ext/identity/binding.go` + `core/protocol/auth.go:130` to match. This
unblocks the four failing directions of the cross-impl
`convergent_mirror` matrix.

Original ambiguity (preserved below for the round-trip trail):



**Spec passage (§12.3):**
> "Cap-chain verification MAY read attestation state via the
> `IdentityBindingChecker` hook (read-only; for grantee-binding lookup);
> cap-chain verification MUST NOT validate attestations as caps."

**Surfaced by:** cross-impl `convergent_mirror` validate-peer matrix
(memo at
the Go cross-impl convergent-mirror matrix).
Of 6 directional A→B pairs, only the 3 with Go-as-source pass cleanly;
all 3 with Go-as-B (or Go in the path) reject installs and subscribes
with **403 authentication_failed** carrying server-side log:

```
execute: auth failed: identity binding checker: no live identity-cert
binding found for grantee ecf-sha256:a357c0b438e1b19af102781c833e366d0260854a603178aeb45177ac97750eaf
```

Go-side reproducer: `core/protocol/auth.go:110`
(`VerifyRequestWithBinding`) runs on every wire-EXECUTE's cap grantee
unless the grantee is local self; checker at
`ext/identity/binding.go:64-95` requires a live `identity-cert`
(`function=agent` or `controller`) bound to the grantee on the local
tree; policy wired unconditionally at `cmd/entity-peer/main.go:347-348`
as `PolicyAllowAnyAttestedAgent`.

**The ambiguity.** §12.3 says the hook **MAY** read attestation state.
It does not pin **when** the hook fires:

| Reading | Implication | Behavior |
|---|---|---|
| Strict (Go's): hook fires on every cap-chain grantee, cross-peer included | Cross-peer grantees MUST have a live local `identity-cert` binding | The receiving peer must have pre-synced or accepted (e.g., TOFU per §12.4) an agent-cert for the remote peer's identity before any cap whose grantee is that identity will validate |
| Permissive (Rust/Python's de-facto): hook is optional; cross-peer grantees out of scope; the connect handshake's verified peer-identity is sufficient | A cap-chain grantee that is a foreign peer's identity hash validates without a local identity-cert binding | The receiver trusts that the wire authentication verified the EXECUTE author; cap-chain checks the cap's authority chain, not the grantee's identity provenance |

The spec gives no normative discriminator. §12.4 (TOFU + supersedes for
cross-peer attestations) suggests cross-peer identity provenance is
something receivers establish over time — which lines up with the
strict reading IF the strict reading is the intent — but doesn't pin
this hook firing on cap chains specifically. §1185-1284 talks about
agent-keys signing caps and revocation cascading on agent retirement,
which also fits either reading.

**Rust's interim choice: permissive (no IdentityBindingChecker installed).**
A `grep` across `core/` and `extensions/` finds **no**
`IdentityBindingChecker` hook, no `binding_checker`, no
`PolicyAllowAnyAttestedAgent` analog wired in cap-chain verification.
`verify_capability_chain` in `core/protocol` walks per-link signatures
and granter resolvability; it does not consult attestation state to
verify grantee identity-binding. Cross-peer caps whose grantee is a
foreign peer's identity hash validate as long as the chain itself
verifies. This matches Python's de-facto behavior and matches the 3
passing convergent_mirror directions where Go isn't the strict party.

**Impact if §12.3 is meant to be strict.** Rust currently fails closed
on the wrong side: rather than rejecting unbound-grantee cross-peer
caps, it accepts them. Adopting the strict reading is mechanical —
factor an `IdentityBindingChecker` trait, wire it through
`verify_capability_chain`, and install a policy in `core/peer`'s
default setup that resolves grantees against
`system/identity/identity-cert` attestations on the local tree. The
EXTENSION-IDENTITY substrate (3-key default; controller+agent certs)
is fully implemented in `extensions/identity` already; the missing
piece is the cap-chain-side hook.

**Impact if §12.3 is meant to be permissive.** Then Go is enforcing a
policy beyond what the spec requires, and Go's pass should relax to
make the cross-impl matrix symmetric. The wire authentication (peer
identity verified at connect, EXECUTE signature verified per
request) already attests that the foreign peer is who it claims to be;
cap-chain just verifies the authority delegation chain on top of
that.

**Question for the architecture team.** Which reading is normative?
The answer determines whether Rust (and Python) needs to wire the
hook, or whether Go should relax `auth.go:110`'s default policy.
Until settled, the cross-impl `convergent_mirror` gate stays asymmetric
on cap-chain handling. The four failing directions in the cross-impl
matrix all collapse to this one root cause; landing it cleanly unblocks
the gate.

**Note:** The convergent-mirroring spec arc itself (CAS-create v7.50,
include_payload v3.13/v3.14, deref_included v1.17, request-side
included preservation v7.51) is fully implemented and verified in Rust;
this ambiguity is upstream of the mirror recipe — about which peer
identities are even allowed to **dispatch** a cross-peer continuation
or subscribe.


---

## EXTENSION-TYPE v1.1

### type_pattern narrowing — "more specific" not algorithmically pinned

**Location.** §6.2 narrowing table, `type_pattern` row:
> Child pattern is more specific (longer prefix or exact match)

**Ambiguity.** The spec defines `pattern` and `format` narrowing as
**equal-only** with the explicit rationale that sub-pattern
recognition is undecidable / interop-unsafe. `type_pattern` is then
given a more permissive narrowing rule ("longer prefix or exact
match") without pinning the recognition algorithm — when does
`system/capability/grant-entry` qualify as "more specific than"
`system/capability/*`? Different glob comparators may answer
differently for non-trivial patterns (consider `a/**/foo` vs
`a/x/foo` — is the latter "more specific" or are they incomparable?).

**Interim choice (Rust v1.1 baseline).** Equal-only, mirroring
`pattern` and `format`. Logged in
`extensions/type-system/src/narrowing.rs` module doc. Deployments
wanting richer narrowing layer it explicitly per the §6.2 framing.

**Question for architecture team.** Pin the algorithm (e.g., child
pattern's literal prefix ≥ parent's literal prefix and child does
not weaken any wildcard), or formally adopt equal-only.

### ENTITY-NATIVE-TYPE-SYSTEM structural validator absent (Rust impl gap)

**Status.** Rust impl gap, not a spec ambiguity. Logged here because
EXTENSION-TYPE §2.3 Phase 1 says "structural validation first
(delegated to ENTITY-NATIVE-TYPE-SYSTEM core)". Rust has
`TypeDefinition` / `FieldSpec` / `TypeRegistry` but no general
structural validator — no `validate(entity, type_def)` that checks
CBOR major-type compatibility against `type_ref`, union dispatch,
generic-type resolution, etc.

**Interim Rust impl.** `extensions/type-system/src/validate.rs`'s
Phase 1 covers `entity.type == type_def.name` and required-field
presence. Deep CBOR-type coercion is **not checked** in Rust today.
Constraint dispatch (Phase 2) is fully implemented.

**Cross-impl risk.** Conformance vectors that depend on Phase 1
catching structural violations (e.g., a string supplied where an
integer is required) will silently pass on Rust today. The
`type` category in `validate-peer` will surface this at the
cross-impl run.

**Resolution path.** Implement
ENTITY-NATIVE-TYPE-SYSTEM v4.2.0 §7 structural validation in
`core/types`. Independent of EXTENSION-TYPE; once landed, Phase 1
delegates to it. Not blocking the type extension MUST gate, but
required for the SHOULD "constraint validation at system boundaries"
to be meaningful.


---

## EXTENSION-CONTENT v3.5

### system/content:ingest envelope-mode with null root + empty included (edge case)

**Location.** §6.3 ingest algorithm.

**Ambiguity.** The pseudocode for envelope-mode says `if envelope.root
is not null: ctx.content_store.put(envelope.root); count += 1`, then
iterates `included`. It returns `root_hash = content_hash(envelope.root)`
unconditionally. If a caller passes `envelope.root: null` and an empty
`included`, `content_hash(null)` is undefined — the spec doesn't pin
the return shape for this corner.

**Interim choice (Rust impl).** When `envelope.root` is absent/null,
`result.root_hash` is the all-zero hash (`format_code=0`,
`digest=[0u8; 32]`). `result.root` is absent (the §11.1 MUST applies
only when `envelope.root` is non-null). `ingested_count` is the
count of `included` entries actually stored. This matches the spirit
of the §6.3 algorithm (don't put what isn't there) without inventing
a new error shape — the caller can observe `root` absent +
`ingested_count == |included|` and infer the no-root path.

**Question for architecture team.** Either (a) confirm zero-hash +
absent-root is fine; (b) pin a different sentinel; or (c) reject the
shape outright as `missing_input` (no root, no included = ambiguous).
Not blocking — pre-v3.5 callers don't exercise this; flag only so the
behavior across impls converges before any consumer relies on it.


---

## ~~Local self-execute `caller_capability` synthesis~~ RESOLVED

**Resolution (same session as discovery).** Adopted SDK-OPERATIONS
§11.2A open-grants posture matching the Go SDK convergence target.
`PeerContextBuilder` mints a wildcard owner self-cap (granter ==
grantee == local identity hash; wildcards on all four scope
dimensions) at peer build time, persists the cap entity + signature
in the content store, and stamps it onto every local L1 dispatch as
`caller_capability` (see `bindings/sdk/src/sdk.rs::mint_owner_self_cap`
and the `Some(owner_cap)` argument on both `PeerContext::execute`
variants). Rust analog of Go's `mintOwnerSelfCap`
(`workbench-go/entitysdk/app.go:782`) + `Executor.SetCallerCapability`
(`executor.go:132`).

V7 §6.5 says "for autonomous operations the caller capability is
absent"; the SDK chooses to materialize the local peer's authority
instead so handlers that voluntarily gate on caller-specified-path
authorization (role:define/assign/re-derive/delegate; identity /
quorum mint paths) work uniformly across local L1 and remote-
connection-cap-bearing dispatch. When kernel-side §11 grant
enforcement lands (Cut 2+), the owner cap becomes opt-in /
overridable rather than the default.

Wrapper docstrings reference §11.2A so consumers know the posture is
intentional and time-bounded, not a permanent papering-over.

---

Original analysis below preserved for traceability:

**Spec passages:**
- `EXTENSION-ROLE §4.3` and §4.2 — define/assign/re-derive/delegate
  enforce RL2 via `is_attenuated(hypothetical, caller_cap, peer_id)`.
  Missing `caller_capability` → `403 missing_caller_capability`.
- V7 §6.5 — "For autonomous operations (no external caller), the
  author is the local peer identity and the caller capability is
  absent."
- V7 §6.8 — "Propagated caller capability is not a dispatch gate
  (normative)" — caller_capability is for (a) voluntary caller-path
  checks the handler performs and (b) history attribution only.

**Discovery path:** RoleOps tests failed 403 on define/assign/
re-derive/delegate. Initial read framed it as a deferrable gap; on
closer reading of V7 §6.5/§6.8 + workbench-go (the blessed
convergence reference), the answer was a tiny SDK
layer addition. The role wrapper's behavior was correct; the SDK
was missing one piece.

---

## EXTENSION-REVISION fetch-diff D4: Rust rejects cross-peer; Go SDK Reconcile requires it

**Spec passage** (PROPOSAL-CONVERGENT-MIRRORING §2.3 D4, also surfaced
in `extensions/revision/src/lib.rs:2484` rationale):
> "this op reads receiver-local state (self.local_peer_id's head);
> if invoked cross-peer it would return the executor's diff, not the
> caller's — the trap that sank the original
> PROPOSAL-REVISION-DIFF-SINCE-LOCAL-HEAD POC. Reject inbound wire
> dispatch with `400 invalid_dispatch`."

**Rust impl:** the handler rejects any `ctx.is_external` invocation
with 400 `invalid_dispatch`. Local internal sub-dispatch is fine
(SDK's `PeerContext::execute` doesn't set is_external, so the
wrapper added in commit c0508e5 works for local fetch-diff).

**Go SDK collision (workbench-go reconcile.go:79):**
`ReconcileSinceLastSeen` wraps the documented `revision:fetch-diff +
tree:merge` chain — and **requires** cross-peer fetch-diff to do its
job:

```go
envEnt, err := a.RevisionAt(remotePeerID).FetchDiff(ctx, types.RevisionFetchDiffParamsData{
    Prefix: prefix,
    Base:   lastSeen,
})
```

A is asking B for B's diff so A can merge into its local prefix. Under
the Rust D4 rule this call returns `400 invalid_dispatch` from B,
making `ReconcileSinceLastSeen` unimplementable in Rust as Go shaped
it.

**Tension:**
- The Rust rule's stated reason (returning the executor's diff when
  the caller expected their own) is real for the **naive** cross-peer
  use — but Reconcile is the **intentional** opposite: the caller
  explicitly wants B's perspective so they can apply B's state.
- The D4 prose forbids "cross-peer dispatch" categorically when the
  legitimate use case is "cross-peer dispatch from a caller who
  understands the receiver-local-state semantics."

**Interim choice (Rust SDK):** the `RevisionOps::fetch_diff` wrapper
landed in c0508e5 is local-only (matches the handler's current
behavior). `ReconcileSinceLastSeen` is **deferred** from Ask 4 until
this tension resolves. Three plausible resolutions:

1. **Relax D4 to allow cross-peer fetch-diff** when the caller
   passes an explicit `target_peer_id` field (signals "I know I'm
   asking for receiver-local state on purpose"). Matches Go's
   current behavior.
2. **Replace fetch-diff with a different op for Reconcile** — e.g.,
   `fetch-since` whose contract is "the executor's perspective is
   what you want." Go's reconcile call site updates; D4 stays.
3. **Compose at a higher layer** — fetch-diff stays local-only;
   Reconcile becomes `(remote.commit_log_walk + fetch_entities)` or
   similar. Substantial spec redesign.

Cross-impl conformance currently diverges silently: Go reconcile
works against Go peers; against a Rust peer the call would 400.
Worth pinning before two-impl prod deployments rely on it.

---

## RestorePriorSubscriptions depends on missing SubscribeAt (cross-peer subscribe wrapper)

**Status (during Ask 4 push):** Go SDK has both pieces
(`workbench-go/entitysdk/subscription_restore.go:109` enumerates +
re-issues; `SubscribeAt` is the cross-peer wrapper it composes on).
Rust SDK has only the local subscribe surface
(`bindings/sdk/src/subscription.rs::subscribe_with_options`); there
is no cross-peer subscribe wrapper, no tracking-sidecar write on
subscribe-success, no tracking-sidecar removal on unsubscribe.

**Why this is a non-trivial follow-up:** RestorePriorSubscriptions is
the thin enumerate-and-re-issue layer (~150 LOC), but it requires
~300+ LOC of prerequisite work first:

1. **SubscribeAt** — cross-peer subscribe wrapper. The existing
   `subscribe_internal` does (a) register a local delivery handler,
   (b) mint a delivery grant, (c) dispatch the subscribe op locally.
   The cross-peer variant routes (c) to
   `entity://{remote_peer_id}/system/subscription:subscribe` and
   ensures the delivery grant + return path is reachable from the
   remote.
2. **Tracking sidecar** — on cross-peer subscribe success, write
   `sdk/subscription-tracking/{id}` capturing `{remote_peer,
   pattern, events, include_payload}`. Not part of the V7 protocol
   surface — workbench-side state per Go's
   `subscriptionTrackingPrefix = "sdk/subscription-tracking/"`. On
   subscription handle drop / explicit unsubscribe, remove the
   sidecar so explicit cancellations don't auto-restore.
3. **RestorePriorSubscriptions** — list the prefix, decode each
   sidecar, re-issue via SubscribeAt, swap the old sidecar path
   for the new id (new SubscribeAt writes a fresh tracking entry).

**Spec authority:** EXTENSION-SUBSCRIPTION v3.15 §5.7 places
"subscriber-side restoration" at the application/SDK layer, not in
the substrate. So the Rust SDK needs to provide this as a wrapper
chain — there's no handler-side help coming. Matches Go's design.

**Not blocking:** the entity-browser-rust consumer-side validation doesn't drive
RestorePriorSubscriptions today (Gap 5 is the persistence concern,
not the restore concern). When subscription-restoration becomes a
real consumer requirement, the implementation order is SubscribeAt
→ tracking → restore, and the substrate boundary stays exactly
where Go put it.

---

## IdentityBundle: Go filesystem-shape vs entity-browser-rust entity-shape cross-impl divergence

**Discovery context:** Implementing Ask 4 IdentityBundle per
the entity-browser-rust IdentityBundle position paper.

The two implementations have fundamentally different abstractions
for what an IdentityBundle is, and the entity-browser-rust position paper
explicitly asks core-Rust to "coordinate with workbench-go on the
field set so their existing bundles can round-trip." The two shapes
do not currently round-trip.

### Go shape (filesystem-oriented)

`entity-workbench-go/entitysdk/identity_bundle.go::IdentityBundle`
contains:
- `SchemaVersion`, `Name`, `CreatedAt`, `QuorumName` (metadata)
- `QuorumID`, `ControllerCertHash`, `Threshold` (verification pins)
- `ControllerKeypair` (the local peer's keypair)
- `QuorumMembers []Keypair` (the quorum constituent keypairs)

**Reload model:** `ApplyIdentityBundle` re-runs
`runBootstrapCeremony` with the loaded keypairs to **re-mint** all
entities (quorum, controller-cert, signatures, peer-config) from
scratch. Ed25519 is deterministic per RFC 8032, so the recomputed
content hashes match the manifest's pinned hashes — that's the
integrity check. The bundle ships only *keypairs + a manifest*; the
entities themselves never travel.

### entity-browser-rust position-paper shape (entity-oriented)

The entity-browser-rust IdentityBundle position paper proposes:
- `identity_hash: Hash`
- `keypair_pem: String` (caller's keypair)
- `identity_entity: Entity`
- `quorums: Vec<Entity>`
- `attestations: Vec<Entity>`
- `signatures: Vec<Entity>`
- `label`, `properties`

**Reload model:** `restore_from_bundle` writes the entities
directly into the content store + binds them at canonical paths,
then dispatches configure to issue the local-peer cap. No ceremony
re-run — the entities themselves are the portable artifact.

### Why this matters

The entity-browser-rust side wants entity-oriented because:
1. Browser WASM consumers don't have filesystems for keypair
   directories — they store one CBOR blob in OPFS/IndexedDB.
2. Quorum members on different peers can't have their keypairs
   shipped (custody concern §8.2); the entity-oriented bundle
   carries the *signatures* instead, which is what the verifier
   actually needs.
3. Multi-signer quorums where the SDK never had the member
   keypairs (signatures came from other peers) can still be
   exported.

The Go side has the filesystem layout because:
1. Workbench is a desktop daemon — filesystem is native.
2. Deterministic re-mint is a clean integrity check (any drift
   in the bootstrap code = hash mismatch caught at load).
3. Reloading the same keypair into a fresh peer literally re-
   creates the same identity, which is the spec's intent.

Both shapes are internally coherent; they're optimized for
different constraints.

### Cross-impl portability gap

Bundle bytes produced on one side cannot currently round-trip to
the other:
- A Go-produced bundle (keypairs only) can't be loaded into a
  Rust SDK using the entity-shape — the Rust side would need to
  re-run the ceremony with the keypairs to reconstruct entities,
  which is what Go does internally. So the Rust SDK would need
  *both* an "entity bundle" path *and* a "keypair bundle ceremony
  re-run" path to be truly cross-impl.
- A Rust-produced bundle (entities only) can't be loaded into the
  Go SDK at all without a Go-side adapter that writes the entities
  to the content store directly, bypassing `ApplyIdentityBundle`.

### Interim implementation choice

**Ship the entity-shaped bundle per the entity-browser-rust position paper.**
Reasons:
1. The consumer (entity-browser-rust) explicitly drove this surface and is
   committed to consuming whatever lands.
2. The entity-shape covers the multi-signer custody case that
   Go's keypair-shape cannot.
3. Per the position paper §"Coordination": "If workbench-go can't
   easily refactor their existing layout, fine — the abstract
   Bundle ships independently; workbench-go's existing filesystem
   layout becomes 'the workbench-go consumer's storage helper'
   wrapping the same abstract Bundle bytes." Backwards-compatible
   on the Go side; Go can add an entity-bundle adapter later.

**Cross-impl deferral:** the Rust SDK ships entity-bundle CBOR
serde + `IdentityOps::export_bundle()` + `restore_from_bundle()`
now. Cross-impl round-trip with workbench-go is **not** claimed
until Go adds the corresponding entity-bundle path.

**Open for architecture decision:** is "entity-shape" or
"keypair+ceremony-shape" the canonical cross-impl bundle? The
spec (`SDK-IDENTITY-INFRASTRUCTURE` §8.4 covers the filesystem
layout but is silent on the cross-impl portable wire shape) needs
to pin one or the other.


---

## CONTENT-SUBSTITUTE-SOURCES §2.5 consult-cap on the 4D grant axis

`PROPOSAL-CONTENT-SUBSTITUTE-SOURCES.md` §2.5 specifies
`system/capability/content-substitute-consult` as an in-process cheap
pre-flight cap gating whether the substitute chain is consulted at all
(MUST). The cap path is a substrate-level identifier under the
`system/capability/*` namespace.

V7's 4D `GrantEntry` model has axes `{ handlers, resources, operations,
peers, ... }`. None of these axes is "capability path." Two faithful
readings:

1. **Handlers-axis encoding.** A grant that includes the path
   `system/capability/content-substitute-consult` in its `handlers`
   include list is treated as conveying the cap. Misuse of axis intent
   (handlers is for dispatch patterns, not cap path).
2. **New `caps` axis.** Extend `GrantEntry` with a `caps: PathScope`
   field whose values are cap paths. Clean axis-of-intent but a wire
   shape change.

The proposal doesn't say. core-go's substrate review of the W2 proposals
flagged the analogous question for REGISTRY's `registry-resolve` cap.

### Rust interim choice

**v1 ships with default-permit posture.** The substitute miss-hook is
offered to the resolver only when the caller has any capability token at
all; absence of a token denies. Strict per-cap enforcement deferred until
arch pins the axis. Logged so the cap surface doesn't silently land as
permissive-forever.

Source surface: `extensions/content/src/handler.rs::caller_has_consult_cap`.

### RESOLVED — named-capability-mapping ruling

Arch closed both faithful readings with a third: **named caps reduce to
the existing 4-axis grant model.** No new mechanism; no fifth `caps`
axis; the cap-path string is impl shorthand only. Concretely, every
`system/capability/{name}` gate maps to a `(handler, operation)` pair
checked by V7 §5.2 `check_permission`; per-cap narrowing lives in the
grant's `constraints` map (byte-equal under delegation per V7 §5.6);
**absent or non-matching grant → deny (fail closed)**.

Worked mapping for this cap:

| named cap | handler | operation | constraints |
|---|---|---|---|
| `content-substitute-consult` | `system/substitute/sources` | `consult` | `source_peer_id?`, `substitute_types?` |

Rust impl landed in transport-family Chunk B: the substrate
(`ChainConsultHook::consult`) now calls `entity_capability::
check_permission(consult, /{local}/system/substitute/sources, local,
resource_target, caller_cap, local)`. CONTENT no longer carries a
permissive `is_some()` helper; it plumbs through
`ctx.caller_capability` + `ctx.resource_target`. Tests cover
absent-token / wrong-handler / wrong-op / resource-outside-scope each
denying. The same mapping applies to `registry-resolve` →
`(system/registry, resolve)` and (erratum-tier) `bridge-http-fetch` →
`(system/bridge/http, get)` per ruling §4 — neither is on Rust's v1
critical path.

---

## V7 §6.2 capability handler — A1..A5

**Trigger.** Implementing `extensions/capability/` (Resolution B per
the capability-handler advertisement ruling) surfaces the same
five under-specified surfaces Go logged in
`entity-core-go/docs/archive/validation/spec-issues/
the capability-handler ambiguities log. Our impl picks match Go's
for cross-impl interop; each entry below names our position so the
record is on both sides.

### A1 — SHOULD vs default-grant tension

**Spec passage (V7 §6.2:2516):**

> Implementations MUST provide the tree, handlers, and connection
> handlers. Implementations SHOULD provide the capability handler.

**But** V7 §4.4 puts `system/capability:request` in
`default_connection_grants`. Advertising a grant for a SHOULD handler
turns the advertisement into a contract callers will exercise — exactly
the defect Godot caught.

**Our impl choice (Resolution B).** Register the handler at
`system/capability` and keep the grant in `default_connection_grants`.
This satisfies V7 §6.2 SHOULD and the ruling's discipline pin
("advertised SHALL only reference registered") in a single config; the
two stay in lockstep via the `capability-handler` feature in core/peer.

**For arch.** Three viable resolutions; pick one:
- **A1.a — Promote §6.2 to MUST.** Reflects what §4.4 already implies
  in practice. Cleanest. Matches Go's stated preference.
- **A1.b — Keep SHOULD; drop from default grants.** Make the
  advertisement conditional on registration. Matches Rust's pre-impl
  posture and the ruling's *recommended* Resolution A.
- **A1.c — Codify the discipline pin into the spec.** "An advertised
  grant SHALL only reference handlers registered on this peer at
  connection time." Pins discipline general-case; leaves §6.2 SHOULD;
  consistent with both impl postures.

Rust's lean: **A1.a** for cross-impl interop simplicity. Once the
handler is normative MUST, validate-peer harnesses (Go's
`expectedHandlers`) can assert presence unconditionally without the
adverse-conditional-skip the current SHOULD framing requires.

### A2 — `request` default policy

**Spec passage (V7 §6.2:985):** "evaluates the request against the
peer's configured policy and returns a `system/capability/grant`".
"Configured policy" is undefined; no default.

**Our impl choice.** Same as Go: **attenuate from the caller's
authenticated grant.** The request handler verifies
`is_attenuated(child={request.grants, …}, parent=caller_capability)`
using the existing §5.2 `matches_scope` machinery. Cannot widen.

**For arch.** Pin in §6.2: "Absent a configured policy, `request` MUST
return a token whose grants are a subset (per `matches_scope`, §5.2) of
the caller's authenticated capability." This is the only
privilege-escalation-safe default and composes cleanly with
EXTENSION-ROLE policies (which can deny / narrow further on top).

### A3 — revocation storage path

**Spec passage (V7 §6.2):** "MAY write to a revocation list at
`system/capability/revocations/*` (implementation-specific)."

**Our impl choice.** Same as Go:
`system/capability/revocations/{token-hash-hex}`, entity type
`system/capability/revocation` carrying `{token, reason?, revoked_at}`.
Path is *peer-qualified* on the wire
(`/{peer_id}/system/capability/revocations/{hex}`) per V7 §6.5
invariant-pointer semantics; the bare form in spec text is shorthand
for the per-peer namespace.

**For arch.** Pin the path scheme as normative. Cross-peer chain
validation that needs to walk revocations otherwise breaks on impls
that pick different schemes — the substrate primitive is only useful
if the path shape is identical across peers.

### A4 — `delegate` input shape

**Spec passage (V7 §6.2:2503-2509):** `delegate: { input_type:
"system/capability/token", output_type: "system/capability/grant" }`.
"Input is the parent token" — but the caller needs a slot for the
*attenuated child scope* and the spec defines none.

**Our impl choice.** Same as Go (interpretation D3-ish): on the wire
the manifest's `input_type` is the canonical `system/capability/token`
for forward compatibility, but the params we actually accept are a
`system/capability/request` (same shape as `request`) carrying the
desired child grants, and the **parent hash rides in the
`resource_target`** as `system/capability/grants/{parent-hash-hex}`.
Handler walks: load parent from store, verify type, verify peer-issued
(`granter == identity_hash`), validate attenuation, mint child with
`parent: Some(parent_hash)`.

**For arch.** Two viable fixes:
- Define a richer dedicated type: `system/capability/delegate-request
  := { parent: hash, grants: [grant-entry], ttl_ms?: uint }` and pin
  it as `input_type`.
- Or document the convention used here (request shape in params +
  parent in resource) as normative.

Either is fine; the current spec doesn't even tell a reader where the
attenuation lives, which is the actionable gap.

### A5 — `request`/`delegate` result envelope

**Spec language:** `output_type: system/capability/grant`,
`grant := { token: hash }`.

**Gap.** Result is a 1-field wrapper. Where does the actual token
entity live so the caller can use it?

**Our impl choice.** Same as Go: **`included`-map (E1).** The
handler emits `system/capability/grant {token: <hash>}` as `result`
and the response envelope's `included` carries the token entity, its
signature entity, and the granter identity entity (so cross-peer chain
verification can resolve all three without follow-up tree:get calls).
No tree writes from `request`/`delegate` (matches V7 §6.2:2544
"returns tokens inline").

**For arch.** Pin in §6.2: "The result envelope's `included` MUST
carry the issued token entity and its signature; MAY carry the
granter identity entity." Without this pin, callers can't safely
distinguish "token doesn't exist locally because the issuer hasn't
mirrored it yet" from "this impl wrote it to the tree and you need to
fetch it" — two completely different recovery paths.

### Cross-refs

- Architecture ruling that triggered Resolution B:
  the architecture team's capability-handler advertisement ruling.
- Go's parallel log (identical findings, picks aligned):
  the Go team's capability-handler ambiguities log.
- Our impl: `extensions/capability/src/lib.rs` (8/8 unit tests cover
  attenuation, delegation, revocation, and the negative cases for
  scope/parent/granter mismatch).

**RESOLVED — V7 v7.62 amendment landed (arch commit 4b82043).**
All five A1..A5 ambiguities resolved by `PROPOSAL-V7-CAPABILITY-HANDLER-
AMENDMENT.md`:

- **A1 → A1.a**: §6.2 promoted to MUST (capability handler is now a
  conformance MUST). Removes the SHOULD-vs-advertisement tension entirely.
- **A2 → spec-pinned**: §6.2 "Evaluation contract for `request`" pins the
  subset-validation against BOTH caller's auth cap AND matched policy
  entry; pure-attenuation flow works without policy entry by skipping
  the policy ceiling.
- **A3 → spec-pinned**: §3.6 + §6.2 universal-revocation-entry-point. The
  marker entity (`system/capability/revocation`) is **distinct from the
  input type** (`system/capability/revoke-request`) — input is `{token,
  reason?}`, marker is `{token, reason?, revoked_at}`. Path is
  normatively `system/capability/revocations/{cap_hash_hex}` (peer-
  qualified locally per §6.5 invariant-pointer semantics).
- **A4 → A4.a (richer dedicated type)**: §3.6 pins
  `system/capability/delegate-request := {parent, grants, ttl_ms?}` as
  input_type — parent moves off the resource_target and into params.
  Self-attenuation only: `grantee = caller's authenticated identity
  always`. Auth check is `parent.grantee == caller's authenticated
  identity` (direct hold, not chain-walk).
- **A5 → spec-pinned**: §6.2 result-envelope MUST carry the issued token
  entity + its signature entity + the granter identity entity; MAY carry
  the full authority-chain bundle for cross-peer use; SDKs targeting
  cross-peer dispatch SHOULD include the chain by default.

**New surfaces in v7.62 also implemented this pass:**

- **`configure` operation** (V7 §6.2 manifest): accepts
  `system/capability/policy-entry`; writes at
  `system/capability/policy/{peer_pattern}` where `{peer_pattern}` is the
  literal `default` (closeout F8 — see below) or a 66-hex peer-identity
  hash (partial prefixes MUST be rejected — done).
- **501 unsupported_operation**: distinct from 404/403 per §6.2 status-code
  table. Rust returns 501 for unknown ops on registered handler.
- **§4.4 union**: at authenticate-response, the connect handler unions
  the SHOULD floor with any matched `system/capability/policy/{peer_hex}`
  entry (fallback to `default`). Conditional on capability handler being
  registered.

### v7.62 closeout amendments landed (F1, F2, F8)

`PROPOSAL-V7-CAPABILITY-HANDLER-CLOSEOUT-AMENDMENTS.md` (awaiting arch
ratification). Rust implements all three;
Rust-seat concur memo filed at
the Rust V7 capability-handler closeout response.

- **F1 — `delegate` scoped to same-peer-only.** The C1 chain-link gap
  (logged previously: cross-peer self-attenuation produces a chain
  `parent.grantee = remote ↔ child.granter = local` that fails §5.5
  verification because the handler signs with the local keypair) is
  resolved by scoping: v1 enforces `caller == local_peer` and returns
  **501 unsupported_operation** for cross-peer callers. Implemented at
  `extensions/capability/src/lib.rs::handle_delegate` (the first branch).
  Cross-peer self-attenuation moves to the client (construct + sign the
  child locally). The closeout proposal §2.5 flags an open question on
  whether `delegate` earns its keep as a wire op at all (deferred,
  follow-up cycle).

- **F2 — `is_revoked` wired into `verify_request` (MUST when
  `supports_revocation = true`).** v7.62's marker mechanism is
  operationally inert unless verify reads it. Rust now ships a
  `VerifyContext { local_peer_id, supports_revocation }` + a
  `verify_request_with_ctx` variant that runs §5.2 Step 4 on every
  capability presented for verification. `core/peer/src/connection.rs`
  uses `supports_revocation = true` (Rust ships the full marker
  mechanism). Closures are: store-first-then-included `resolve`,
  location-index `locate`, and `capability_path_for_scan` over the
  location index (Rust uses the §5.1 MAY-level scan fallback; a future
  reverse-index optimization is straightforward). Surfaces as new
  `ProtocolError::CapabilityRevoked → 403` (matches Go's
  `revoked_cap_denied_on_use` matrix vector; same family as
  `CapabilityExpired`, NOT `UnresolvableGrantee`/401 — initial Rust
  pick was 401 on faulty analogy; corrected after Go
  matrix flagged the divergence).

- **F8 — `system/capability/policy/{peer_pattern}` fallback segment
  renamed from `*` to `default`.** In v7.62 the literal segment was `*`,
  which collided with `*`-as-glob everywhere else in V7 (resource
  patterns, grant-entry wildcards, free-text path globs). Renamed to
  `default` — unambiguous, cannot collide with a 66-hex peer-ID. Single
  source of truth at `entity_capability::POLICY_FALLBACK_SEGMENT` (re-
  exported from the handler crate); used at the handler's `configure`
  validation, the handler's policy-lookup fallback, and `core/peer`'s
  §4.4 connection-time policy reader.

## `system/revision/commit-result` field names: protocol spec vs SDK spec contradict

**Type:** spec-vs-spec contradiction (two architecture documents disagree on a
wire shape). Surfaced by the cross-impl validate-peer matrix
(the Go cross-impl conformance matrix
§2.3, `commit_version_nonzero` + ~62 cascade failures).

**The two passages.**

- **Protocol domain — EXTENSION-REVISION §4.3.1 (line 699):**
  ```
  return {type: "system/revision/commit-result",
          data: {version: version_hash, root: trie_root_hash}}
  ```
  Field **names** are `version` and `root` (values are the version-entry hash
  and the trie-root hash). The merge-result is consistent: §4.3.4 line 863
  returns `{status: ..., version: ...}`.

- **SDK domain — SDK-EXTENSION-OPERATIONS §4 (lines 276-277, 314):**
  ```
  version_hash: hash    ; Hash of the new version entry
  trie_root:    hash    ; Root of the snapshot trie
  ```
  Field names are `version_hash` and `trie_root`; merge there also uses
  `version_hash`.

**Impact.** Go and the conformance oracle decode per the protocol-domain spec
(`version`/`root`). Our prior "G5" change (commit `2dacb9c`) re-shaped the Rust
emitter to the SDK-domain names `{version_hash, trie_root, parent?}` — which
made every Rust commit read as a *zero* version hash on the oracle (absent
`version` key), and because the whole revision suite gates downstream checks on
a successful commit (`v1_hash` is only stored on commit pass), this single
field-name divergence cascaded to ~62 revision failures. Note the values were
always computed correctly — this was purely a wire-key-name regression, not a
logic bug.

**Our interim choice (this commit).** Reverted the Rust commit-result to the
protocol-domain names `{version, root}` — emitter, SDK decoder, the
`system/revision/commit-result` type schema, and three unit tests. Rationale:
EXTENSION-REVISION is the **handler's own wire spec** and is authoritative for
the result-entity shape; SDK-EXTENSION-OPERATIONS is an SDK-domain *descriptive*
document and its `_hash`/`_root` suffixes read as prose labels, not wire keys.
This also restores cross-impl conformance with Go + the oracle. Also dropped the
G5 `parent` field — §4.3.1 does not define it (extra, undefined wire key).

**For arch (the actionable ask).** Reconcile the two documents so a peer author
reading either lands on the same wire shape. Recommended: correct
SDK-EXTENSION-OPERATIONS §4 to `version`/`root` to match EXTENSION-REVISION
§4.3.1, OR (if the intent really is to migrate the wire to `version_hash`/
`trie_root`) amend EXTENSION-REVISION + the oracle + Go together and re-issue as
a coordinated wire break. The current state — protocol spec and SDK spec naming
the same wire field differently — will keep biting every new peer generated from
these docs, which is exactly the "what's spec vs impl" risk the conformance
program exists to catch.

**Cross-refs.**
- Authoritative: EXTENSION-REVISION §4.3.1 (line 699), §4.3.4 (line 863).
- Contradicting: SDK-EXTENSION-OPERATIONS §4 (lines 276-277, 314).
- Regression introduced: commit `2dacb9c` ("G5"); reverted here.
- Our impl: `extensions/revision/src/lib.rs` (commit emitter),
  `bindings/sdk/src/revision.rs` (`decode_commit_result`),
  `core/types/src/core_types.rs` (`system_revision_commit_result`).

## ~~9 conformance-tested type defs: 3 field disputes resolve per spec; 3 types live only in proposals~~ CLOSED (arch ruling `e748be4` R1+R2; conformance green, no impl change)

**Type:** (a) cross-impl field-type disputes the spec actually settles, plus
(b) a process gap — the conformance suite tests types that are not yet in a
ratified spec. Surfaced by validate-peer matrix §2.1. Rust is missing all 9
type definitions (404 on fetch); this entry is the arch-facing analysis, not a
registration (see disposition).

**The 9 types and where they're DEFINED:**

| Type | Defining doc | Ratified? |
|---|---|---|
| `system/peer/transport/http-poll` | EXTENSION-NETWORK §6.5.3 (L895-925) | ✅ published spec |
| `system/type/{adopt,converge,reconcile}-request`, `reconcile-result` | EXTENSION-TYPE §7.4-7.6 (L879-982) | ✅ published spec |
| `system/substitute/endpoint` | RULINGS-STORAGE-SUBSTITUTE (R1) + PROPOSAL-…-HTTP | ⚠️ proposal/ruling only |
| `system/substitute/snapshot-manifest` | PROPOSAL-…-STORAGE-SUBSTITUTE-HTTP L78-92 | ⚠️ proposal only |
| `system/substitute/source` | PROPOSAL-…-STORAGE-SUBSTITUTE-SOURCES §2.1 | ⚠️ proposal only |
| `system/substitute/try-request` | PROPOSAL-…-SOURCES §2.3 + RULINGS R2 | ⚠️ proposal/ruling only |

**The 3 disputed fields — the spec settles all three (do NOT "match Go"):**

1. **`http-poll.peer_id`** → `system/peer-id` (EXTENSION-NETWORK §6.1 L69),
   not `primitive/string` and not `system/hash`. Python's `primitive/string`
   is wrong.
2. **`substitute/source.priority`** → `primitive/int` (SOURCES §2.1 L59:
   "ascending; lower = consulted first"). NETWORK Amendment 8's `uint` (L729)
   is for **live transport profiles**, a *different* entity type — it does not
   reach `substitute/source`. Python's `uint` is wrong **unless** arch
   deliberately extends Amendment 8 to substitute sources (open question →
   arch).
3. **`substitute/try-request.entry`** → the **full** `system/substitute/source`
   entity (`core/entity`), per SOURCES §2.3 L131 + RULINGS R2 ("the full
   source entity, NOT its hash"). Python's `primitive/any` is too loose;
   `core/entity` is the precise type.

**The process gap (the part that matters for "what belongs in the spec").**
Four of the nine types the conformance suite gates on
(`substitute/{endpoint,snapshot-manifest,source,try-request}`) are defined
**only in proposals + a cross-impl ruling**, never lifted into a published,
ratified spec. The suite is therefore asserting conformance against
pre-ratification shapes. This is exactly the failure mode the conformance
program exists to prevent: a "MUST register type X" with shape Y, where Y has
never been pinned anywhere a peer author would look. It is also why the cohort
disagrees on `priority`/`entry` — each impl read a different proposal draft.

**Disposition (Rust).** **Not registering these 9 in Rust this session.**
Registering proposal-stage shapes would (a) bake in a shape arch may revise on
ratification and (b) risk minting a *fourth* divergence on the disputed fields.
Per impl-role boundaries, type-definition field shapes are protocol-design
decisions, and the matrix itself routes §2.1 "to arch first to confirm the
canonical field types." This entry is that confirmation request.

**For arch (actionable).**
1. Ratify the `system/substitute/*` family into a published spec (lift from
   PROPOSAL-…-STORAGE-SUBSTITUTE-{HTTP,SOURCES} + the cross-impl rulings), with
   the three disputed fields pinned as resolved above — OR scope these four
   types out of the conformance suite until ratified.
2. Confirm `substitute/source.priority` signedness: `int` (per SOURCES §2.1, my
   reading) vs `uint` (if Amendment 8 is meant to generalize). One line in the
   ratified spec closes it.
3. Once ratified, Rust registers all 9 (substitute family in
   `extensions/storage-substitute-*`, type-analysis family in
   `extensions/type-system`, http-poll in the network/types layer) in one pass.

**Cross-refs.** Matrix §2.1; EXTENSION-NETWORK §6.5.3/§6.1; EXTENSION-TYPE
§7.4-7.6; PROPOSAL-EXTENSION-STORAGE-SUBSTITUTE-{HTTP,SOURCES};
the cross-impl storage-substitute rulings (R1, R2).

**RESOLUTION (later same day) — registered.** The two gating
rulings landed, so the prior "not registering this session" disposition is
superseded: A-F1 via arch errata `bdfb545` ("NETWORK §6.5.1 profile peer_id
Hash→system/peer-id") pins `http-poll.peer_id = system/peer-id`; A-F2 via
RULINGS R2 pins `try-request.entry = system/substitute/source` (the **full
source entity**, NOT the looser `core/entity` my earlier reading above
proposed — Go converged to the precise type in `1034f82` and is the validator
reference). All 9 types are now registered in `core/types/src/core_types.rs`
(centralized, matching Go's single `RegisterCoreTypes` pathway — the existing
`system_revision_*` extension types already live there). Field shapes match
Go's converged registration, verified field-by-field and **proven over the
wire**: `validate-peer -category type_system` against a live Rust peer →
291 pass / 5 warn (all pre-existing open-type-tolerable) / **0 fail**, all 18
new-type checks (9 × fetch+match) PASS, `types_all_present` PASS. Disputed
fields landed as: `peer_id=system/peer-id`, `source.priority=primitive/int`,
`try-request.entry=system/substitute/source`, `source_peer_id=system/hash`.

**~~Still open for arch (the substantive asks survive registration):~~ CLOSED — both asks ruled.**
Architecture ruled both asks in the cycle-closeout-0.3 ruling (arch
commit `e748be4`, ratified — ancestor of arch master). Verified against the
ruling text; no Rust impl change required (both already converged):

- **Ask #1 — substitute family: R1 DESCOPE (do not ratify this cycle).** The
  family stays proposal-stage by design — ratification is W3 CDN-corridor
  release work on its own track, deliberately not folded into a peer-cleanup
  cycle (same discipline that keeps the capability amendment separate). The
  cohort **keeps** its implementations (all three converged on the ruled shapes,
  so eventual ratification is mechanical, not wasted); `validate-peer` substitute
  categories are **marked provisional / proposal-stage — NOT part of the
  ratified-core conformance floor** (V7 §2.11 / GUIDE-CONFORMANCE §7). The ruling
  explicitly names this as resolving "Rust's process-gap finding": answer is
  *descope + mark-provisional*, not *ratify-mid-cycle*. **Rust action: none** —
  the four `system_substitute_*` builders stay registered to the ruled shapes;
  if the CDN-corridor track revises a shape on ratification they update in one
  pass (carries its own conformance regen).
- **Ask #2 — `source.priority`: R2 `int` confirmed (no change).** SOURCES §2.1
  L59 pins `priority: int` ("ascending; lower = consulted first"); Python's
  earlier `uint` was the divergence and has converged to `int`. NETWORK
  Amendment 8's `priority: uint` (§6.5.1 L729) is a *different field on a
  different entity* (live transport profiles) and does not generalize. Rust
  registered `primitive/int` (`core_types.rs` `system_substitute_source`) →
  **correct, confirmed.** (Zero wire impact — all real priorities ≥ 0, so
  canonical bytes are identical either way; this was a type-declaration
  confirmation only.)

**Net: this entry is fully closed.** Conformance green (291/5-warn/0-fail), impl
matches the ratified rulings, and the two arch asks are adjudicated. No further
action on either side.


---

## V7.67 PHASE-2 BYTE-PIN COHORT — empty scope `include` encodes as `[]` not `null`

> **RESOLVED — RULED in Rust's favor.** Architecture ruling
> the empty-scope-include ruling: an unconstrained scope
> dimension is **present-with-empty-`include`** (`{include: []}` → `0x80`), NOT
> `{include: null}` (`0xf6`) and NOT absent. No spec change — both halves were
> already bound by existing normative text (ENTITY-CBOR-ENCODING §232 forbids
> field drop; V7 §3.6 `list_of(pattern)` typing excludes `null`). This answers
> BOTH questions below: (1) `[]` is the canonical form (Go's `null` was an
> fxamacker `[]string(nil)` artifact, fixed at `core/types/system.go`
> `3cfb353`); (2) present-with-empty, never absent. 3-way green: Go `3cfb353` ×
> Rust `d38d1f8` × Python `a2463be`, byte-equal on all 7 gates × M2/M3/M6 ×
> `.cbor` sha256. Rust's `0x80` was correct from the start — no impl change. The
> stale `.cbor` was regenerated from the folded `.diag` at F16 close
> (`8e7c5232…f31f982e`). Original surfacing report retained below.

Surfaced running the Phase-2 matrix byte-pin round-trip (SEEDS.md §5 step 3)
in `core/peer/tests/cohort_compare_v767_phase2.rs` against the Go cohort pins
(the V7.67 phase-2 byte-pins cohort record).

**§7 gates 1–4 (peer-identity layer) converge byte-for-byte Rust ↔ Go** on all
three vectors (pubkey, peer_id, `system/peer.data` CBOR, home-format
content_hash — including the SHA-384 home cases M3-A / M6-A). **Gates 5–7
diverge** (cap-token CBOR → content_hash → signature), isolated to one cause
repeated across M2/M3/M6.

**Passage / shapes:** the matrix cap's `GrantEntry` (SEEDS.md §2.3) constrains
only `resources`; `handlers` and `operations` are unconstrained. Their
`include` (a `list_of: pattern` field, V7 §3.6) is a zero-element list.
- Rust emits `{include: []}` → `a1 67696e636c756465 80`.
- Go's pins emit `{include: null}` → `a1 67696e636c756465 f6`.

**Why Rust holds (not arbitrary):** the locked v1 ECF corpus pins these as
DISTINCT canonical forms — `length.1` empty array → `h'80'`, `primitive.1`
null → `h'f6'` (`ecf-conformance/conformance-vectors-v1.diag`), and
ENTITY-CBOR-ENCODING §232 forbids dropping fields. An empty `list_of` value is
`0x80`; `0xf6` (null) is a different value. Go's `f6` is a
`[]string(nil) → CBOR null` serialization artifact of its `GrantEntry`, not a
spec mandate. SEEDS.md §7 names the spec/SEEDS the arbiter, not Go.

**Why it stayed latent:** handshake caps are each self-signed by the minting
peer and verified against received bytes (byte-fidelity, never re-encoded
cross-impl). The byte-pin round-trip is the first surface forcing independent
re-derivation of the same logical cap by two impls. `default_connection_grants`
in Rust already emits `resources: {include: []}` today — interop never broke
because nobody re-encodes a peer's self-signed cap.

**Interim choice:** Rust keeps `0x80`. The Phase-2 test pins Rust's
spec-correct cap-token CBOR / content_hash / signature (peer-layer constants
remain Go's verbatim — they match). Full cap-layer convergence + corpus lock
wait on Go regenerating its pins with `0x80`.

**For architecture (decision needed before the Phase-2 `.diag` fold, SEEDS §5
step 4):**
1. Confirm empty scope `include` canonicalizes to `[]` (`0x80`), making Go's
   `null` pins the ones to regenerate. (Rust + the locked corpus say yes.)
2. SECONDARY (non-blocking, neither impl exercises it today): should a fully
   unconstrained scope dimension be ABSENT entirely (`handlers`/`operations`
   keys omitted, grant = `{resources: {…}}`) per the §1.8 "optional fields
   SHOULD be absent" guidance, rather than present-with-empty-`include`? If so
   that is a third encoding distinct from both impls and a wire-affecting
   GrantEntry canonicalization change across all three SDKs — wants an explicit
   ruling, not silent per-impl drift.

---

## V7.72 CORE-PROFILE COHORT CLOSEOUT — §1.4 path control-char rejection: spec text says "null bytes", cohort floor rejects all C0+DEL

**Passage:** V7 §1.4 (line 370): *"All other UTF-8 characters are valid in path
segments. Paths MUST NOT contain null bytes. Paths MUST NOT contain empty
segments (consecutive `/` separators)."* And §9.5a `CORE-TREE-PATH-FLEX-1`:
*"reject null byte (400)"* — singular.

**Ambiguity:** The normative text mandates rejecting **only** null bytes, and
explicitly says "All other UTF-8 characters are valid." A C0 control byte
(`0x01`–`0x1F`) or DEL (`0x7F`) is, by the letter of §1.4, a valid path-segment
character. But the Go reference's v7.72 fix added `ValidatePathChars` rejecting
the full `0x00`–`0x1F` + `0x7F` range, and the cohort punch list
(`IMPL-TEAM-ALIGNMENT-V7.72-CLOSEOUT-PEER-FIXES`, Class A1) instructs Rust +
Python to reject "NUL/C0/DEL". The conformance vector only *tests* a NUL byte,
so either policy passes the oracle — but the impls now reject a superset of what
§1.4's text forbids.

**Interim choice:** Rust rejects the full C0 range + DEL (`first_illegal_path_byte`
in `core/tree/src/lib.rs`), matching the Go reference and the punch list, so a
path one peer binds is bindable on every peer in the shared tree. This is
stricter than §1.4's literal text.

**For architecture:** tighten §1.4 to say control characters (the C0 range +
DEL), not just "null bytes" — so the normative text matches what all three
impls now enforce. Otherwise the spec permits paths the conformant cohort
rejects, and a future impl reading §1.4 literally would accept C0-control paths
and silently diverge from the shared-tree address space. (Cosmetic: §9.5a
`CORE-TREE-PATH-FLEX-1`'s "reject null byte" bullet could note the broader set.)

## V7.75 RESOURCE-BOUNDS COHORT — `chain_depth_exceeded`/400 is settled for the EXECUTE auth path, but the install-time creator-authority walk still maps too-deep → 404 `chain_unreachable`

**Passage:** V7 §4.10(b) (v7.75, folded RESERVED → §9.1 floor MUST at arch
`414b892`): *"the peer MUST reject a presented chain exceeding its configured
maximum depth with `400 chain_depth_exceeded` rather than walking an
attacker-controlled chain unboundedly... The status is 400, not 403 — a
too-deep chain is a client-correctable structural excess, not an authorization
denial."* The bound is justified by §5.5 cost: *"Capability-chain verification
(§5.5) costs O(depth) signature verifications."*

**Ambiguity:** §4.10(b) names "a presented capability chain" verified under
§5.5. Rust runs the **same** `collect_authority_chain` walk (with the same
`MAX_CHAIN_DEPTH = 64` ceiling) on two boundaries:
- the **EXECUTE auth path** (`verify_capability_chain`) — now correctly maps
  `ChainWalkError::TooDeep` → `ProtocolError::ChainTooDeep` → **400
  `chain_depth_exceeded`** (this turn, against §4.10(b)).
- the **install-time creator-authority path** (`check_creator_authority`, used
  by continuation install / subscription subscribe / compute install audit) —
  documented to map both `Unreachable` *and* `TooDeep` → **404
  `chain_unreachable`** (`core/protocol/src/verify.rs:688`).

The install path incurs the identical O(depth) DoS surface §4.10(b) is written
to bound, but §4.10 scopes itself to "inbound EXECUTE" / "presented chain" and
does not mention the install-time creator check. So it is unclear whether
§4.10(b)'s 400/`chain_depth_exceeded` rule reaches the install boundary, or
whether that boundary keeps its own 404/`chain_unreachable` surface (where
too-deep is folded into unreachable because the walk never reaches root).

**Interim choice:** Rust leaves the install-time path mapping `TooDeep` → 404
`chain_unreachable` unchanged. Only the EXECUTE auth path was remapped, matching
the `resource_bounds` gate's r2 probe (which exercises the EXECUTE path only).
The `resource_bounds` category does not test the install boundary, so either
mapping passes the oracle today.

**For architecture:** clarify whether §4.10(b)'s `chain_depth_exceeded`/400 is a
property of the **§5.5 chain-walk primitive itself** (and therefore applies
everywhere a chain is walked, including install-time creator checks) or only of
the **inbound-EXECUTE auth boundary**. If the former, the install path's
too-deep case should split out from `chain_unreachable`/404 to
`chain_depth_exceeded`/400 across the cohort; if the latter, the spec should say
so, since the install walk shares the same O(depth) cost that motivates the
bound.

## ~~EXTENSION-DISCOVERY §2.1/§2.2 — `candidate.peer_id` null-until-IDENTIFY: explicit-null vs absent~~ RESOLVED (arch Ruling-6, commit 7626026 — ruled **absent**, Rust's interim choice; pinned spec-wide for every `<X | null>` field; Python re-pins F2 fixture, Go+Rust unchanged; cross-impl byte-equal on `candidate_0.content_hash` is the D6/D7 gate)

**Passage:** §2.1 declares `candidate.peer_id: <Base58 peer-id per V7 §1.5 | null>`
with the inline comment *"null until IDENTIFY completes"*; §2.2 reinforces:
*"A candidate's `peer_id` field is **null** when the candidate is first surfaced
by a backend."* The successor pattern (§2.2) then derives a new candidate whose
`content_hash` is referenced by `supersedes` and by `decision.candidate`.

**Ambiguity:** the spec says `peer_id` is **null** pre-IDENTIFY, but the
project-wide interop convention (V7 "Optional fields: SHOULD be absent (key not
present), not null" — also [[feedback_typed_struct_field_wire_convention]]) says
an unknown optional is encoded **absent**. These produce **different CBOR** and
therefore **different `content_hash`** for `candidate_0` — which is exactly the
hash that `supersedes` / `decision.candidate` pin. If Go emits an explicit
`peer_id: null` and Rust omits the key, the two impls compute different
candidate hashes and the §2.2 supersedes-chain / §2.1 decision references
silently fail to match across impls. This is the same silent-divergence class
§3.2 was written to close for the mDNS wire — but on the entity layer.

**Interim choice:** Rust encodes `peer_id: None` as **absent** (key not present),
per the project-wide convention, and decodes both absent and explicit `null` as
`None` (tolerant read). This is the unblocked, convention-consistent choice. The
TOFU-candidate byte-equal fixture pin (`extensions/discovery/src/tests.rs`,
`fixture_candidate_tofu_hash` →
`00b613881ab1f301c47d1b567ba639d59c82a782df2ddaca0a1b0919da573fd1a4`) is computed
under the **absent** encoding.

**For architecture / cohort:** confirm the candidate `peer_id`-pre-IDENTIFY
encoding is **absent**, not explicit-null, and pin it in §2.1 (one sentence) so
Go's D5 handler and Python converge on the same `candidate_0` `content_hash`.
The TOFU fixture above is the convergence anchor — if Go/Py disagree, this is
the field. (Same question technically applies to `identity_hint` /
`supersedes` / `decision.grant`, but those are already `<... | null>` optionals
that Rust encodes absent-when-None with no semantic "is null meaningful?"
tension; `peer_id` is the one the spec prose explicitly calls "null".)

---

## EXTENSION-RELAY v1.0 — `envelope_inner` `refs:` placement (cohort-convergence pin)

**Status:** ✅ RESOLVED — Go's R5 cohort handoff
§4.1 confirms `envelope_inner` lives **in the data field** (not a refs block), the
same reading Rust shipped. Proven byte-equal: Rust's F1/F2/S1/S2 fixtures reproduce
Go's pinned content_hashes exactly (`extensions/relay/src/tests.rs::fixture_*`). The
secondary `stored_at` pin is likewise resolved — Go's R5 amend 1 corrected to bare
namespace (Rust's catch); Rust's R2 fixture matches Go's pin (`beb909b6…047e801c`).
Original concern kept below for the record.
**Spec:** `EXTENSION-RELAY.md` §3.1 / §3.2 / §3.0.

**Passage.** The `forward-request` (§3.1) and `store-entry` (§3.2) entity
schemas list the inner-envelope pointer under a separate `refs:` heading:

```
type: "system/relay/forward-request"
data: { destination, next_hop, ttl_hops }
refs:
  envelope_inner: <system/hash>
```

**Ambiguity.** This Rust codebase's `Entity` is `{type, data, content_hash}`
with `content_hash = SHA-256(ECF({data, type}))` — there is **no** wire-level
`refs` field, and `refs` is **not** part of the hashable basis. So a `refs`
block can only be represented one of two ways, which produce **different
`content_hash`** for the same logical entity:
1. `envelope_inner` is a field **inside `data`** (a bare 33-byte `system/hash`)
   — the only placement where it contributes to the entity's content hash in
   this model. **This is what Rust does.**
2. `envelope_inner` is a top-level sibling map `refs: {envelope_inner: <hash>}`
   that some impl folds into the hashable basis as `{data, refs, type}`.

If Go encodes (2) while Rust encodes (1), the `forward-request` / `store-entry`
content hashes diverge, and any cross-impl reference to a stored entry by hash
(poll → `entry_hash`, fallback rendezvous) silently fails to match. Same
silent-divergence class as the DISCOVERY `candidate.peer_id` pin above.

**Interim choice.** Rust encodes `envelope_inner` as a **`data` field**, bare
33-byte `system/hash` bstr (`extensions/relay/src/data.rs`). This matches the
project-wide typed-struct-field convention
([[feedback_typed_struct_field_wire_convention]]) and the only hashable model
the codebase has. Decode reads it from `data`.

**For architecture / cohort.** Confirm at R5/R8 whether Go places
`envelope_inner` in `data` (matching Rust) or in a distinct `refs` map that
participates in the content hash. If the latter, the spec's `refs:` heading is
load-bearing on the hashable basis and §3.0 needs one sentence pinning how
`refs` serializes + hashes. The `forward-request` / `store-entry` content hashes
are the convergence anchors.

**Secondary (minor):** `forward-result.stored_at` is typed `<path | null>` but
its §4.2 comment + §6.2.1 say "namespace, if queued-fallback." Rust returns the
bare **namespace** (= destination `peer_id`), since that is what the destination
passes to `:poll`. Confirm Go returns the same (namespace, not the full
`system/relay/store/{ns}/{hash}` path) at R8.

---

## EXTENSION-RELAY v1.0 — §3.1.1 terminal hop: spec mandates raw-frame, Go reference + shared validator implement decode-then-redispatch

**Status:** ✅ RESOLVED (same day) — Rust's
raw-frame reading was correct and is now the cohort-settled interpretation. The
cohort gap turned out to be a **validator-shape bug, not a Rust dispatcher bug**:
the prior validator sent an unsigned `ExecuteData` inner, which Rust's
already-correct raw-frame dispatcher refused. Once the validator was fixed to
send a fully-signed `system/envelope` (Go `validate-peer` HEAD `c28dad1`,
`CreateAuthenticatedExecute`), **Go migrated its dispatcher to raw-frame**
(`DeliverInner` → `SendRawFrame`/`SendRawFrameTo`, `c28dad1`) and **Python landed
the same** (`b8034d5`). `relay_multi_peer` mp1–mp4 are now **3-way GREEN**
(Go/Rust/Python self + Python→Go→Rust mixed); §5.1 author-transparency enforced
end-to-end in three impls. Rust needed **no code change** — `PeerRelayForwarder`
was already raw-frame. Close record: the Go relay-R8 cohort-close;
Rust response memo: the relay-R8 raw-frame Rust response.
**Spec:** `EXTENSION-RELAY.md` §3.1 / §3.1.1 / §9 / §5.1.

_Original finding (retained as the record of the divergence and its resolution):_

**Passage (§3.1.1, "Terminal hop — raw-frame forwarding (§2.1 ruling)").**

> The relay **writes the inner envelope's raw bytes verbatim into the
> destination's inbound frame** and dispatches them as a normal inbound message
> — exactly the bytes the destination would have received on a direct
> connection. The relay **MUST NOT decode-then-re-encode** the inner envelope …
> Raw-frame (not decode-then-redispatch) is required to deliver true
> byte-identity-to-direct … **This resolves the Rust (raw-frame) vs Python
> (decode-then-redispatch) divergence in favor of raw-frame** … the destination
> verifies the inner envelope's signature + capability chain *exactly as on a
> direct connection*, and therefore **MUST NOT need the RELAY extension
> installed merely to receive** a forwarded message.

§3.1 likewise pins the inner as **a full materialized `system/envelope`
`{root, included}`** carrying its own signatures/caps, "so the terminal hop
delivers a self-contained, independently-verifiable message; a bare root would
arrive unverifiable."

**The conflict.** The Go reference dispatcher
(`ext/relay/peerwiring/dispatcher.go::DeliverInner`) and the shared cross-impl
validator (`cmd/internal/validate/relay_multipeer.go`) implement the **opposite**
of the ratified ruling:

1. The validator's `buildInnerExecute` constructs the inner as a **bare,
   unsigned `system/protocol/execute` ExecuteData entity** (`execData.ToEntity()`)
   — *not* a `{root, included}` envelope and *not* signed.
2. `DeliverInner` **decodes** that ExecuteData and **re-dispatches** it via
   `peer.RemoteExecute` — i.e. the relay **re-signs the EXECUTE under its own
   identity** to the destination.

These two facts make the two models mutually exclusive, decisively:

- True raw-frame of the validator's inner is **undeliverable**: the destination
  runs `decode_envelope`, finds no `root`/`included` (it's an ExecuteData map),
  and rejects the frame; and even structurally, an **unsigned** EXECUTE fails the
  destination's mandatory non-connect auth (V7 §5.2). Raw-frame **requires** the
  source to build a fully-signed `system/envelope` the destination can verify
  standalone — which the validator does not do.
- Go's decode-then-redispatch "works" only because (a) it re-signs at the relay
  (defeating §5.1 author-transparency — the destination sees the *relay* as
  author, not the source) and (b) ECF round-trips are *usually* (not guaranteed)
  byte-identical (defeating §3.1.1's exactness promise).

So no impl currently realizes §3.1.1, and the validator **cannot** test it (its
inner is the wrong shape). The cohort is mid-migration: §3.1.1 ratified raw-frame
but Go + the validator predate it.

**Interim choice (Rust).** Rust implements **§3.1.1 literally**:
`core/peer/src/relay_forwarder.rs::PeerRelayForwarder` writes the opaque inner
envelope's bytes **verbatim** into the destination's inbound frame
(`RemoteEndpoint::dispatch_raw`, a byte-exact send added alongside the
convenience `dispatch_envelope`), never decoding/re-encoding/re-signing. It reads
only the inner's embedded `request_id` (to demux the destination's
EXECUTE_RESPONSE), never the payload. The destination verifies the source's own
signature + capability chain; the session peer (the relay) is decoupled from the
EXECUTE author (already true in Rust — `verify_request` does not bind author to
session peer). Proven end-to-end by
`core/peer/src/lib.rs::tests::test_relay_terminal_raw_frame_delivery` (live
3-peer TCP: A's signed inner delivered byte-for-byte through relay B to C, C's
tree payload `content_hash`-identical to source). **Consequence:** Rust's
same-impl `relay_multipeer` mp2 vector will **FAIL against the current Go
validator** (validator builds an undeliverable unsigned ExecuteData inner). This
is expected and correct — the red is the validator's, not Rust's.

**For Go / cohort (owed, user-directed).** Go should migrate to raw-frame to
match the §3.1.1 ruling:
1. `DeliverInner` → write `inner.Data` verbatim into the destination's inbound
   frame (no decode/re-encode, no re-sign).
2. `buildInnerExecute` (validator) → build a **fully-signed `system/envelope`
   `{root, included}`** inner (the source authors + signs the EXECUTE and bundles
   its cap chain), so mp2 actually exercises raw-frame + standalone verification
   at the destination.
3. mp2's assertion stays "payload byte-equal at C's tree," but now also implies
   "C verified the *source's* signature, not the relay's."

Until Go migrates, Go-as-relay (decode-redispatch) and Rust-as-relay (raw-frame)
disagree on the wire for the *terminal hop only*: Go re-signs as the relay, Rust
preserves the source's envelope. Mixed rotations with Go-as-B will still observe
a payload at C (Go re-signs a valid EXECUTE), but the **author identity at C
differs** (relay vs source) — a §5.1 transparency divergence, not just an
encoding one. Python is in the same pre-migration state (decode-redispatch).

---

## EXTENSION-RELAY v1.1 source-routed multi-hop + EXTENSION-ROUTE v1.0 — landed Rust-side

**Status:** ✅ IMPLEMENTED (Rust), awaiting cross-impl
validate-peer. No ambiguity — the specs landed clean (arch fold `32ae3e3`; Go
build-test `8ae1c9b`, `relay_source_route` 6/6 + `route` 8/8 self-GREEN, **no
spec deltas**). Logged here as the implementation record + the cross-impl pins to
watch. **Specs:** `EXTENSION-RELAY.md` v1.1 §3.1 / §3.1.1 / §5.4 / §6.8;
`EXTENSION-ROUTE.md` v1.0. **Cohort handoff:**
the Go relay v1.1 cohort-close handoff.

**What landed (Rust):**
- **`route: [peer_id]` on `forward-request`** (`extensions/relay/src/data.rs`),
  CBOR-omitempty: a v1.0 single-hop request (no `route`) encodes byte-identically
  (fixtures F1/F2 digests unchanged — proven in `tests.rs`).
- **§3.1.1 per-hop algorithm** (`extensions/relay/src/handler.rs::handle_forward`):
  precedence **source route > `next_hop` > route table > no_route**. Cross-field
  invariant `next_hop == route[0]` (when both set) → `invalid_request`/400
  **pre-dispatch**. Terminal iff `next == destination`. Intermediate pops the head:
  `route' = route[1:]`, `next_hop' = route'[0]` (or none), `ttl_hops − 1`
  (`core/peer/src/relay_forwarder.rs`).
- **EXTENSION-ROUTE v1.0** as a new sibling crate (`extensions/route`): the
  `system/route` entity codec, canonical `route_path` (= `hex(hash.to_bytes())`,
  the `Hash.Bytes()`-equivalent form — avoids cross-impl trap #1's padded 130-char
  path), the `route-configure` cap, and the pure §3 `resolve` match (exact > `*`
  default, lowest metric, expiry-skip, cross-field-invalid skip). RELAY consumes it
  (`relay → route` edge, documented in `CLAUDE.md`); RELAY does the local-tree read,
  ROUTE owns the match semantics. No `system/route` handler in v1 (writes via
  `tree:put`; reads are relay-internal).

**Architectural call (Rust-side, owned per the no-punt discipline).** ROUTE is a
**separate crate**, not folded into relay. The spec defines ROUTE as a sibling
extension (storage plane; store/consume/produce role separation is "the whole
point", ROUTE §1). The Go reference put `RouteData` in `core/types` for expedience;
Rust implements from spec → a dedicated `entity-route` crate with the documented
`relay → route` composition edge (RELAY §6.8 / ROUTE §6), added to `CLAUDE.md`'s
permitted-edges list alongside `quorum→attestation` etc.

**Cross-impl pins to watch on the next validate-peer (from handoff §6 traps):**
1. Canonical route path uses `hash.to_hex()` (66 hex chars SHA-256), not a padded
   digest — verified by `entity-route` unit test `canonical_path_is_hex_of_canonical_bytes`.
2. `next_hop ≠ route[0]` rejects pre-dispatch — `source_route_next_hop_mismatch_rejected_pre_dispatch`.
3. Intermediate sets `next_hop' = route'[0]` — `source_route_intermediate_pops_head`
   + live `test_relay_source_route_three_hop` (A→B→C→D over real TCP, inner
   byte-identical across both hops).
4. §9 opacity holds across intermediate + terminal — same live 3-hop test
   (`content_hash` identical at D).
5. Route table consulted **only** when both `route` and `next_hop` absent
   (precedence) — `source_route_takes_precedence_over_table`.
6. `"*"` is a string token, not a peer-id — `entity-route` treats it as a literal
   `match` string (never decoded as a peer-id).

**Test evidence:** `entity-route` 12/12, `entity-relay` 41/41 (incl. 8 new
source-route + route-table tests), `entity-peer` (relay) 146/146 (incl. the live
3-hop test). Full workspace builds; route + relay compile for wasm32; standard CI
wasm build green. **Next:** Go `validate-peer -category relay_source_route` +
`-category route` against a Rust peer for 3-way close.

## Rust impl gap — `published_root::verify_content` / `verify_signed_root` are incompatible with the live CONTENT_GET wire form AND trust the wire hash (§1.2 hole)

**Status. RESOLVED** — fix landed (see *Resolution* below). Was: Rust impl
gap, NOT a spec ambiguity. Arch reclassified Gap B to a **v1-release blocker for Rust**
(the architecture network/relay-cycle closeout §3; the Go cohort
relay-v1 pre-tag checklist §3.1) — an
authentication bypass in shipped consumer code, the exact v6 host-bytes-distrust threat.
Surfaced while implementing the Tier-1 `publish_fetch_http_poll` cohort gate (Thread B,
the Go publish-fetch-http-poll cohort handoff).
The Thread B self-PASS itself was GREEN (`core/peer/tests/publish_fetch_http_poll.rs`,
6/6) because that test drives a *correct* Mechanism-A consumer; this note recorded the
defect in the shipped consumer helpers that the test had to route around.

**The two gaps (same root cause).** The live http-poll CONTENT_GET route serves
`ecf_for_hash(type, data)` — the **2-key `{data, type}` form, NO `content_hash`**
(`core/peer/src/http_live.rs:791`, arch ruling 1b5c125 §1: the consumer is
contractually required to *re-hash*). But the consumer helpers in
`core/peer/src/published_root.rs` were written against the 3-key `encode_entity` form:

- **Gap A (live-wire incompatibility).** `verify_content` (`published_root.rs:175`)
  and `verify_signed_root` (`:193`) both call `entity_wire::decode_entity`, which
  **requires** a `content_hash` field (`core/wire/src/lib.rs:144`, errors "missing
  'content_hash' field"). On a real CONTENT_GET body (2-key) this fails outright. It
  hits both the content path *and* the signature path (the `system/signature` entity
  is fetched via CONTENT_GET → 2-key → undecodable). So `HttpPollFetcher` +
  `PublishedRootClient` cannot drive the live route end-to-end — consistent with the
  `HttpPollFetcher` doc-comment flagging live wiring as deferred "Phase P P7."

- **Gap B (§1.2 host-bytes-distrust hole).** Even on the 3-key form, `verify_content`
  compares a **wire-provided** `content_hash` to `expected` (`:178`) instead of
  recomputing `Hash::compute(type, data)`. A host serving
  `{type, data:<evil>, content_hash:<expected>}` passes the check. The unit test
  `consumer_rejects_tampered_content` only catches the naive attacker (whose served
  entity carries its *own* honest hash ≠ expected); a hash-lying host is not caught.
  This is a §1.1/§1.2 Mechanism-A trust-gate violation. (Go's `httplive.Outbound.
  FetchContent` re-hashes the body — handoff Trap 5 — so this is a Rust-only hole.)

**Why the in-tree unit tests don't catch it.** The `StoreFetcher` in
`published_root.rs` tests serves `encode_entity(e)` (3-key, honest content_hash) —
NOT the `ecf_for_hash` form the real server emits. So the tests are green while the
live path is broken on both counts.

**Fix sketch (deferred — not in the Thread B scope; flagged for a follow-up).** Make
the consumer verification content-addressed and form-agnostic: decode `(type, data)`
tolerating presence/absence of `content_hash` (extract `data` as raw bytes for
fidelity, never re-encode), **always** recompute `Hash::compute(type, data)`, and
trust iff it equals the requested hash. A `wire::decode_entity_rehash` primitive
(wire already depends on `entity_hash`) would serve `verify_content`,
`verify_signed_root`, and the `VerifyingFetchStore` walk; the existing 3-key
`StoreFetcher` unit tests stay green (type+data extracted, recompute matches, the
extra wire `content_hash` ignored). This has cross-impl surface (it changes how Rust
verifies published roots) so it warrants a cohort note rather than a silent patch.

**Test evidence / interim:** `core/peer/tests/publish_fetch_http_poll.rs` 6/6 GREEN
(real wire, correct re-hash consumer). The broken helpers are untouched pending the
fix decision.

**Resolution.** Fixed per the blessed sketch.
- New `core/wire::decode_entity_parts(bytes) -> (type, data)` — form-agnostic: tolerates
  both the 3-key authored form and the 2-key `CONTENT_GET` form, and **ignores any wire
  `content_hash`** (it captures `data` as the raw on-wire slice for byte fidelity).
- `published_root::verify_content` now decodes via `decode_entity_parts` and **recomputes**
  `Entity::new_with_format(type, data, expected.algorithm)` (recompute under the requested
  hash's own format, §1.8), trusting iff it equals `expected`. Closes Gap A (2-key decodes)
  + Gap B (hash-lying host rejected). `VerifyingFetchStore::get` inherits the fix (it calls
  `verify_content`), so the trie walk re-hashes every node.
- `published_root::verify_signed_root`: the manifest (3-key per the §6.5.3.1 MANIFEST_GET
  "wire entity" contract) now passes `Hash::validate(type, data, content_hash)` before its
  `content_hash` is used as `root_hash` — defeats a data-swap that keeps a publisher-signed
  outer hash. The signature entity decodes form-agnostically (`decode_entity_parts`); its
  trust is the Ed25519 verify against the pinned key, not its self-hash.
- New unit tests: `verify_content_accepts_2key_content_get_form`,
  `verify_content_rejects_hash_lying_host`. The 3-key `StoreFetcher` tests stay green.
- **§3.2 cohort audit catch (same class, also fixed):**
  `extensions/storage-substitute-http/src/handler.rs` fetched content from an **untrusted
  HTTP origin** and compared the *wire-provided* `content_hash` to `target_hash` — its
  comments falsely claimed a `Hash::compute(type,data)==target_hash` recompute that did not
  exist. Now decodes form-agnostically and recomputes under `target_hash.algorithm`,
  rejecting bytes that do not re-hash. (No integration coverage exists for that fetch path —
  pre-existing; the recompute primitive is the same as the unit-tested `verify_content`.)
- Verified: published_root 10/10, publish_fetch_http_poll 6/6, http_live 43/43, peer suite
  148/0, storage-substitute-http 12/12, wire 15/15, clippy clean on touched files.

---

## EXTENSION-RELAY §3.1 — `forward-request.route` element type: `[<peer_id>]` notation vs Go's `array_of(primitive/string)`

**Passage (EXTENSION-RELAY §3.1):** the source-route field is written `route: [<peer_id>]`
— a list whose elements are peer-ids.

**Ambiguity / divergence.** The spec notation implies each hop is a `system/peer-id`-typed
value. The Go reference, however, reflects `ForwardRequestData.Route []string` to
`array_of(primitive/string)` with **no** `OverrideField` pin to `system/peer-id` — unlike
`destination`, `next_hop`, `put_by`, and `forward-result.next_hop`, which Go *does* pin. So
the `route` element type is `primitive/string` in the type-definition entity Go advertises.

**Interim choice (Rust, F1 cohort).** Rust registers `forward-request.route` as
`opt_arr(t("primitive/string"))` to byte-match the Go reference (the validate-peer oracle):
the `system/relay/forward-request` type-definition entity must hash-equal Go's or the
cohort type_system check FAILs. Confirmed OK via `compare-types` (3-way hash match). Pinning
`route` to `system/peer-id` Rust-side would diverge from Go and break green.

**Routes to:** architecture + Go — decide whether `route` hops should be pinned to
`system/peer-id` (matching the spec notation and the other peer-id surfaces) in *all* impls
together, or whether the spec notation should be read as informal and `primitive/string`
ratified. Either way it is a cohort-wide one-line change, not a Rust-local one. Not gating
release-green (current state is internally consistent across the cohort).

**RESOLVED (arch Q5).** Arch ratified the cohort pin as
`array_of(primitive/string)?` (the spec `[<peer_id>]` notation is read as informal prose for
"peer-ids carried as strings," NOT a `system/peer-id` *type* pin). Rust's interim choice
(`opt_arr(t("primitive/string"))`) already matches, so no Rust change is required — this was
the Q5 cohort decision and Rust conformed at F1. Cross-impl `compare-types` 3-way hash match
stands. Anchored in the cohort handoff Rust punch list item R2.

---

## EXTENSION-TYPE §7.4/§7.5/§7.6 — `converge` / `adopt` / `reconcile` ops unimplemented (ACCEPTED)

**Passage (EXTENSION-TYPE §7, §10 conformance table line 688).** The type-analysis
operations `converge` (§7.4), `adopt` (§7.5), and `reconcile` (§7.6) are **MAY** — the §10
conformance table marks all of §7 "Reference," and the operation set a `system/type` handler
*must* serve is `validate` + `compare` + `compatible` (§7.1–§7.3). The three merge/adoption
ops are optional.

**Rust state.** `extensions/type-system/src/validate.rs` (`TypeHandler::operations()` →
`["validate", "compare", "compatible"]`) serves the three required ops and returns a clean
`400 unknown_operation` for `converge` / `adopt` / `reconcile` (the `other =>` arm). This is
the conformant response for an unimplemented MAY op — the handler advertises its op set and
fail-closes on anything outside it, identical to the existing `unknown_operation` posture for
the constraint handler.

**Decision: ACCEPT (do not implement for v1).** The validate-peer gates
`type.op_{converge,adopt,reconcile}_roundtrip` exercise these ops and observe the 400. Per
arch Bucket B dispatch (cohort handoff R4), these are MAY ops not required for v1 conformance,
so the 400 is correct-by-design, not a failure. No infrastructure invented to satisfy a
non-MUST. If a deployment later needs cross-peer type convergence, `converge`/`adopt`/
`reconcile` become a scoped follow-on against §7.4–§7.6 (their result entities —
`compatibility-report`, `reconcile-result`, etc. — are already registered as core types, so
only the op handlers would be new). Anchored in the cohort handoff Rust punch list item R4.

---

## ENCRYPTION §16.4 — ENC-GROUP-KAT-1 does not pin the per-wrap ephemeral seeds

**Spec:** EXTENSION-ENCRYPTION v1.0 §16.4 (ENC-GROUP-KAT-1 pinned inputs).

**Passage.** §16.4 pins: 3 members with X25519 seeds `0x50`/`0x51`/`0x52`,
outer nonce `0x53×24`, per-wrap nonces `0x60+i`, and `group_aead_key = 0x54×32`.
It does **not** pin the per-wrap *ephemeral* X25519 private seeds. But each
`wrapped_keys[i]` is a peer-mode hybrid encryption (§8.3 step 5) whose
`ephemeral_key` and `wrapped_aead_key` bytes are a function of that fresh
per-wrap ephemeral keypair. Without a pinned wrap-ephemeral seed, the wrap
ciphertexts are non-deterministic and cannot be byte-pinned across impls — the
outer ciphertext locks (it depends only on group_aead_key + outer nonce + outer
AAD, all pinned), but the per-wrap blobs do not.

**Impact.** The outer-ciphertext byte-pin and the commitment are lockable now;
the per-wrap `wrapped_aead_key`/`ephemeral_key` byte-pins are not until §16.4
adds wrap-ephemeral seed pins (suggest `0x70+i`, the value the Rust seat used).
Group-mode round-trip + ENC-GROUP-COMMIT-1 + ENC-RESOURCE-BOUNDS-1 are fully
exercised regardless (they don't depend on a fixed wrap-ephemeral seed).

**Interim Rust choice.** Per-wrap ephemeral seed `0x70+i` (member i). Recorded
in `docs/archive/ENCRYPTION-BYTE-PINS-RUST.md`. Surfaced, NOT self-folded (per the
cohort handoff §4 discipline). Routes to **architecture** to pin in §16.4
alongside Go/Python so the wrap byte-pins lock 3-way.

**Secondary (§16.2/§16.3/§16.4 plaintext framing).** All three KATs mark the
inner-entity plaintext as "TBD by cohort+arch joint authoring (a fixed test
entity)". Until that lands, the `expected_ciphertext_hex` values are provisional
on the placeholder plaintexts the spec text lists (`"hello world"` etc.); the
AAD hex + pubkey-hash derivation are firm regardless.

> **Update: Go independently chose the same `0x70+i`.** `go test
> ./ext/encryption -v` emits wrap ephemerals/ciphertexts byte-identical to
> Rust's, so Go's `group_test.go` also pins wrap-ephemeral seed `0x70+i`. The
> value is already de-facto cohort-converged; the gap is only that §16.4 prose
> doesn't state it — write it in so Python + Keystone don't reverse-engineer it.

> **RESOLVED (arch v2.5, `entity-core-architecture` @ `8b7ac3b`).**
> **R1** pins the per-wrap ephemeral seed at `0x70+i` (Rust's interim choice
> ratified). **R3** pins the §16.2/§16.3/§16.4 KAT plaintext as ENC-KAT-INNER —
> the ECF of a real `system/note{body, created:0}` entity, not a bare string —
> closing the "plaintext framing TBD" secondary. **R4** blesses Go's named
> sub-shapes `system/encryption/kdf-params` + `system/encryption/wrapped-key`,
> resolving the deferred inline-`{fields:…}` modeling call: the 5 encryption
> entity types + 2 sub-shapes (+ `system/note`) are now registered in
> `core/types/core_types.rs` (clears the 5 `validate-peer` type-registration
> FAILs from `e5bd49a`). The §16 `expected_*_hex` re-derivation against the R3
> ENC-KAT-INNER plaintext is **DONE** — `kat::enc_kat_inner_plaintext()` is
> byte-pinned to the 79-byte ECF and `tests/modes.rs` asserts the 95-byte
> self/peer/group ciphertexts byte-equal to Go + Python (3-way §16.5 lock). R6
> key-separation (`separation.rs`), §10/§11 sender resolution, and §8.5 group
> lifecycle primitives also landed. No spec gap remains here.
