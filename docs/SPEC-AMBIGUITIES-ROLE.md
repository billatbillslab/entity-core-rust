# Spec Ambiguities — EXTENSION-ROLE.md

**Status:** all 10 entries are RESOLVED by `PROPOSAL-ROLE-V1.5-SPEC-FIXES`
(EXTENSION-ROLE v1.5 → v1.6). The Rust impl landed the v1.6 wire shapes.
This file is kept for traceability — every RA-N entry below points to the
SI-N item that resolved it.

Spec target: EXTENSION-ROLE v1.6.

---

## ~~RA-1 — `{peer_id}` encoding asymmetry: identity hash vs. canonical Base58~~ RESOLVED

**Resolution (SI-1).** Pin **lowercase hex of `system/hash` of the
assignee's identity entity** for *all* non-root path segments. Base58
PeerID is reserved for the universal-root segment per V7 §1.4 and the
`peer_id` field of `system/identity` entities per V7 §3.5; everywhere
else uses hex of `system/hash`. v1.5 §3.2's "Base58 for non-root
segments" was a spec error; v1.6 corrects it to align with identity
v3.3 / quorum v1.1 / V7 invariant pointers (all hex throughout).

Rust impl status: landed via `peer_segment_from_hash(h: &Hash)` in
`paths.rs`; the handler reads the path segment as raw bytes via
`hash_from_peer_segment(seg) -> Option<Hash>` and uses that for the
cap's `grantee` field directly (SI-8).

---

## ~~RA-2 — `re-derive` cascade scope: per-role vs. per-context~~ RESOLVED

**Resolution (SI-6).** Per-role. Matches the request shape (`role`
selector) and §4.2 path decomposition. Whole-context re-derive is a
caller-side loop. v1.6 prose updates §4.5 / §5.5 to remove the
"context" framing.

Rust impl status: already per-role — no code change needed.

---

## ~~RA-3 — Delegation cap parent (IA22) when delegator holds multiple role caps~~ RESOLVED

**Resolution (SI-22).** Parent is the cap referenced by the SI-5
linkage entity at
`system/role/{context}/derived-tokens/{delegator_peer_id_hex}/{role}`.
If the rare grace-window overlap leaves multiple linkage entities for
the same (peer, role) tuple, tie-break by `issued_at` descending.

Rust impl status: `handle_delegate` now reads the linkage entity to
recover the parent token hash, removing the `created_at`-walk over
role-derived caps that v1.5 used.

---

## ~~RA-4 — Delegation request `delegator` field redundancy~~ RESOLVED

**Resolution (SI-21).** Drop the `delegator` field entirely.
`ctx.execute.data.author` is authoritative; on-behalf-of delegation
isn't supported (SI-19 pins locality).

Rust impl status: type registry no longer declares `delegator`;
`handle_delegate` reads `ctx.author` and validates against the local
peer's identity (SI-19).

---

## ~~RA-5 — Delivery mechanism for re-derived tokens (IA9 MUST)~~ RESOLVED

**Resolution (SI-16, closed in v1.5 §5.5).** Pull-via-subscription is
the DEFAULT; inbox push is opt-in for deployments with
`EXTENSION-INBOX`. Already pinned in v1.5; v1.6 re-confirms.

Rust impl status: re-derive writes new tokens to sync-visible tree
paths; assignees pull via subscription. No additional code needed.

---

## ~~RA-6 — Layer-2 bootstrap exclusion check needs out-of-band exclusion subtree~~ WITHDRAWN

**Note.** Self-resolved during initial implementation: the helper is a
single tree-get and works correctly regardless of bootstrap ordering.
The spec proposal's §9 confirms: "self-resolved in the Rust source
note ('not actually an ambiguity once the cases are enumerated'). No
action."

---

## ~~RA-7 — Reactive sweep (IA8) — "issued tokens" identification~~ RESOLVED

**Resolution (SI-7).** **Broad sweep.** Every cap at the
role-derived/{ctx}/{peer}/* prefix on this peer is removed regardless
of which fleet peer originally issued it. V7 `is_revoked` is
local-tree-binding-based; the only mechanism that makes fleet-wide
exclusion work is for every peer's local view to be cleaned on
exclusion arrival. Caps that should NOT be swept on context exclusion
must live elsewhere (peer-private grants outside role's lifecycle,
application-specific subtrees) — that's a deployment / extension-
design choice.

Rust impl status: `RoleExclusionSweepHook` already does broad sweep —
no code change needed. Doc-comment updated to reference SI-7 / SI-17
(idempotent-hook pattern).

---

## ~~RA-8 — `system/role/define-result.role_path` field semantics~~ RESOLVED

**Resolution (SI-27).** Echo `EXECUTE.resource.targets[0]` as
received. Matches V7's canonicalization-on-input model: the caller
chose the form, the handler preserves it.

Rust impl status: already echoes the input form — no code change
needed.

---

## ~~RA-9 — Role definition existence check on assignment~~ WITHDRAWN

**Note.** §2.2 (data-layer permissiveness for stale assignments) and
§4.3 (handler-entry strictness for new assignments) are consistent on
close reading. No conflict; no action.

---

## ~~RA-10 — `delegate-request.context` / `.role` declared as `system/hash` but used as path strings~~ RESOLVED

**Resolution (SI-4).** Patch schema: both fields are
`primitive/string` (matching `assign-request.role`). The
hash-with-lookup interpretation has no compelling use case and breaks
symmetry.

Rust impl status: type registry updated; `handle_delegate` decodes
both as text via `field_text`.

---

## v1.6 SI items NOT raised by Rust (for reference)

The full PROPOSAL-ROLE-V1.5-SPEC-FIXES batch contains 28 items — the
10 above were Rust-raised. The other 18 came from Go/Python or were
authored by the architecture team. Cross-reference in the proposal
itself for: SI-2 (token-hash hex pinning), SI-5 (linkage entity), SI-9
(exclude-result schema), SI-10 (drop the kernel-rejection framing),
SI-11–SI-15 (concurrent-ops semantics, RL2-fail-closed mid-cascade),
SI-17 (handler-write vs sync-write discrimination), SI-18 (multi-role
token selection), SI-19/SI-20 (delegation locality + literal scope),
SI-23–SI-28 (lifecycle, editorial, terminology rename).

The Rust impl landed all relevant SI items in the same cycle:
- **SI-2** confirmed (`hex_segment` already produces full-byte hex).
- **SI-5** added `RoleDerivedTokenLinkData` + `path_role_derived_link`.
- **SI-15** added `skipped_grantees` to `re-derive-result`.
- **SI-17** documented the idempotent-hook pattern in `hook.rs`.
- **SI-19** locality invariant in `handle_delegate` (400, not 403).
- **SI-20** `scope_contains_template` rejects 400.
- **SI-26** reserved `PATH_INITIAL_GRANT_POLICY`.
- **SI-28** renamed `bootstrap.rs` → `startup.rs`,
  `bootstrap_role_*` → `startup_role_*`, `BootstrapError` →
  `StartupError`, `BootstrapAssignmentResult` →
  `StartupAssignmentResult`.

SI-24 (operations literal-vs-pattern) does not apply — the Rust impl's
`scope_subset_id` already calls `matches_pattern`.
