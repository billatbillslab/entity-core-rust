//! `system/capability` handler — V7 §6.2 (`request` / `delegate` / `revoke`).
//!
//! ## Operations
//!
//! - **`request`** — attenuate from the caller's authenticated capability.
//!   The peer mints a new token rooted at the local peer identity granting
//!   any subset of what the caller already holds. Cannot widen.
//! - **`delegate`** — given a peer-issued parent token (granter ==
//!   local peer identity) plus a desired attenuation, mint a child token
//!   with `parent` set to the parent's hash. Caller-to-caller delegation
//!   is not handled here — the caller signs that locally.
//! - **`revoke`** — write a revocation marker at
//!   `system/capability/revocations/{token-hash}`. Only the granter of
//!   the token (i.e. the local peer for tokens it issued) may revoke.
//!
//! Several aspects of V7 §6.2 are under-specified; the interim picks
//! match Go's `ext/capability` for cross-impl interop and are logged in
//! `docs/SPEC-AMBIGUITIES.md` (entries V7-6.2-A1..A5).

use std::sync::Arc;

use async_trait::async_trait;
use entity_capability::{decode_grant_entry, is_attenuated, CapabilityToken, GrantEntry, Granter};
use entity_crypto::IdentityKeypair;
use entity_entity::{Entity, TYPE_SIGNATURE};
use entity_handler::{
    error_entity, Handler, HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST,
    STATUS_FORBIDDEN, STATUS_NOT_FOUND, STATUS_NOT_SUPPORTED,
};
use entity_hash::{invariant_signature_path, Hash};
use entity_store::{ContentStore, LocationIndex};
use entity_types::{
    PeerData, TYPE_CAP_GRANT, TYPE_CAP_POLICY_ENTRY, TYPE_CAP_REVOCATION, TYPE_CAP_TOKEN, TYPE_PEER,
};

const STATUS_UNAUTHENTICATED: u32 = 401;
const STATUS_INTERNAL: u32 = 500;

/// Policy-table fallback segment (V7.62 §6.2 closeout F8) — re-exported
/// from `core/capability` so callers can reference the constant via the
/// handler crate they already depend on.
pub use entity_capability::POLICY_FALLBACK_SEGMENT;

/// `system/capability` handler implementing request / delegate / revoke.
pub struct CapabilityHandler {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    local_peer_id: String,
    qualified_pattern: String,
    /// Hash of the local peer's `system/peer` identity entity. The
    /// granter on every token minted here.
    identity_hash: Hash,
    /// Cached identity entity, re-emitted with each grant in `included`
    /// so the caller's chain verifier can resolve the granter without a
    /// follow-up `tree:get`.
    identity_entity: Entity,
    /// Local peer keypair — signs every minted token. Polymorphic over
    /// key_type (v7.67 Phase 2) so an Ed448 peer signs with Ed448.
    keypair: IdentityKeypair,
}

impl CapabilityHandler {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
        identity_hash: Hash,
        identity_entity: Entity,
        keypair: IdentityKeypair,
    ) -> Self {
        let qualified_pattern = format!("/{}/system/capability", local_peer_id);
        Self {
            content_store,
            location_index,
            local_peer_id,
            qualified_pattern,
            identity_hash,
            identity_entity,
            keypair,
        }
    }

    fn handle_request(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        let caller_cap = match ctx.caller_capability.as_ref() {
            Some(c) => c,
            None => {
                return Ok(HandlerResult::error(
                    STATUS_UNAUTHENTICATED,
                    error_entity(
                        "unauthenticated",
                        "request requires an authenticated caller capability",
                    ),
                ))
            }
        };
        let author = match ctx.author {
            Some(h) => h,
            None => {
                return Ok(HandlerResult::error(
                    STATUS_UNAUTHENTICATED,
                    error_entity(
                        "unauthenticated",
                        "request requires an EXECUTE author identity",
                    ),
                ))
            }
        };

        let req = match decode_capability_request(&ctx.params) {
            Ok(r) => r,
            Err(msg) => {
                return Ok(HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity("invalid_params", &msg),
                ));
            }
        };
        if req.grants.is_empty() {
            return Ok(HandlerResult::error(
                STATUS_BAD_REQUEST,
                error_entity(
                    "invalid_params",
                    "capability-request must specify at least one grant entry",
                ),
            ));
        }

        let child = CapabilityToken {
            grants: req.grants.clone(),
            granter: Granter::single(self.identity_hash),
            grantee: author,
            parent: None,
            created_at: 0,
            expires_at: None,
            not_before: None,
            delegation_caveats: None,
        };
        // V7.62 §6.2 evaluation contract for `request` step 3: validate the
        // request grants as a subset of BOTH the caller's authenticated cap
        // (attenuation floor) AND the matched policy entry (per-peer
        // ceiling), if a policy entry exists. Pure-attenuation flow works
        // without a policy entry by skipping the policy ceiling.
        if !is_attenuated(&child, caller_cap, &self.local_peer_id) {
            return Ok(HandlerResult::error(
                STATUS_FORBIDDEN,
                error_entity(
                    "scope_exceeds_authority",
                    "requested scope is not an attenuation of the caller's authenticated capability",
                ),
            ));
        }
        if let Some(policy_grants) = self.lookup_policy_grants(&author) {
            let policy_token = CapabilityToken {
                grants: policy_grants,
                granter: Granter::single(self.identity_hash),
                grantee: self.identity_hash,
                parent: None,
                created_at: 0,
                expires_at: None,
                not_before: None,
                delegation_caveats: None,
            };
            if !is_attenuated(&child, &policy_token, &self.local_peer_id) {
                return Ok(HandlerResult::error(
                    STATUS_FORBIDDEN,
                    error_entity(
                        "scope_exceeds_authority",
                        "requested scope exceeds the matched policy entry's grants",
                    ),
                ));
            }
        }

        let created_at = now_ms();
        let expires_at = req.ttl_ms.and_then(|t| created_at.checked_add(t));

        self.mint_and_return(req.grants, author, None, created_at, expires_at)
    }

    /// V7 §6.2 v7.64 dual-form policy resolution. Walks the lookup
    /// order: (1) hex form, (2) Base58 form, (3) `default`. Returns
    /// the first matching entry's `grants` array, or `None` if no
    /// entry exists at any of the three paths.
    ///
    /// Hex is canonical; Base58 is the pre-configuration affordance
    /// (operator pasted the handle before knowing the public_key).
    /// When a Base58 entry matches, the handler MAY canonicalize it
    /// (write the hex form, delete the Base58 form — §2.3 SHOULD,
    /// self-healing idempotent pair). This impl canonicalizes; if a
    /// concurrent handshake races the write the worst case is a
    /// transient overlap with hex winning on next read.
    ///
    /// The caller's canonical Base58 PeerID is derived from their
    /// `system/peer` entity at `&Hash` per V7 §1.5 v7.65 — pure function
    /// of `(public_key, key_type)`. This dual-form policy mechanism is
    /// the v7.65 §6 lazy-canonicalization machinery: operator may write
    /// a pre-configured Base58-form entry before having the public_key;
    /// on first match (post-handshake) it canonicalizes in place.
    fn lookup_policy_grants(&self, author: &Hash) -> Option<Vec<GrantEntry>> {
        let author_hex = hex_of(author);
        let by_hex = format!(
            "/{}/system/capability/policy/{}",
            self.local_peer_id, author_hex
        );
        if let Some(grants) = self.read_policy_grants(&by_hex) {
            return Some(grants);
        }

        // Try the Base58 form (pre-configured "pending-canonicalization"
        // entry per V7 §3.6 v7.65). The peer's canonical Base58 is derived
        // from `(public_key, key_type)` in their content-addressed
        // `system/peer` entity. Absent or unreadable → skip to default.
        if let Some(author_b58) = self.lookup_peer_canonical_base58(author) {
            let by_b58 = format!(
                "/{}/system/capability/policy/{}",
                self.local_peer_id, author_b58
            );
            if let Some(grants) = self.read_policy_grants(&by_b58) {
                // V7 §3.6 v7.65 lazy-canonicalization event: pubkey is now
                // known (this codepath only fires post-resolve); rebind the
                // policy entry under the canonical hex form and clear the
                // Base58 entry. Idempotent + self-healing.
                self.canonicalize_policy_entry(&by_b58, &by_hex);
                return Some(grants);
            }
        }

        let by_default = format!(
            "/{}/system/capability/policy/{}",
            self.local_peer_id, POLICY_FALLBACK_SEGMENT
        );
        self.read_policy_grants(&by_default)
    }

    /// Derive the canonical wire PeerID (Base58) for the peer at
    /// `identity_hash` by decoding their `system/peer` entity and applying
    /// V7 §1.5 v7.65 canonical-form-per-`key_type` (Ed25519 → identity-
    /// multihash). Returns `None` for non-peer entities or malformed data.
    fn lookup_peer_canonical_base58(&self, identity_hash: &Hash) -> Option<String> {
        let entity = self.content_store.get(identity_hash)?;
        if entity.entity_type != entity_crypto::TYPE_PEER {
            return None;
        }
        let data = PeerData::from_entity(&entity).ok()?;
        data.canonical_peer_id()
    }

    /// V7 §6.2 v7.64 §2.3 canonicalization. Two independent idempotent
    /// operations: copy entity from Base58 path to hex path, then delete
    /// Base58 path. Errors are logged + tolerated — the next match-and-
    /// canonicalize cycle re-runs the delete; the system converges.
    fn canonicalize_policy_entry(&self, b58_path: &str, hex_path: &str) {
        let h = match self.location_index.get(b58_path) {
            Some(h) => h,
            None => return, // raced — already gone, nothing to canonicalize
        };
        // Write hex (idempotent — overwriting with same bytes is a no-op).
        self.location_index.set(hex_path, h);
        // Delete Base58 (idempotent — absent is a no-op).
        self.location_index.remove(b58_path);
        tracing::debug!(
            from = %b58_path,
            to = %hex_path,
            "V7 §6.2 v7.64: canonicalized Base58-form policy entry to hex form"
        );
    }

    fn read_policy_grants(&self, path: &str) -> Option<Vec<GrantEntry>> {
        let h = self.location_index.get(path)?;
        let entity = self.content_store.get(&h)?;
        if entity.entity_type != TYPE_CAP_POLICY_ENTRY {
            return None;
        }
        let val: ciborium::Value = ciborium::de::from_reader(entity.data.as_slice()).ok()?;
        let map = val.as_map()?;
        for (k, v) in map {
            if k.as_text() == Some("grants") {
                let arr = v.as_array()?;
                let mut out = Vec::with_capacity(arr.len());
                for entry in arr {
                    let g = decode_grant_entry(entry).ok()?;
                    out.push(g);
                }
                return Some(out);
            }
        }
        None
    }

    fn handle_delegate(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        let author = match ctx.author {
            Some(h) => h,
            None => {
                return Ok(HandlerResult::error(
                    STATUS_UNAUTHENTICATED,
                    error_entity(
                        "unauthenticated",
                        "delegate requires an EXECUTE author identity",
                    ),
                ))
            }
        };

        // V7.62 closeout F1 (same-peer-only): v1 enforces `caller ==
        // local_peer`. Cross-peer self-attenuation is structurally
        // underspecified (V7 §5.5 requires `child.granter` to sign, but
        // the handler runs on the issuer peer and does not hold a remote
        // caller's keypair — so the resulting chain `hash_equals(parent.
        // grantee = remote, child.granter = local)` fails verification).
        // Return 501 (not 403): this is a missing-mechanism case, not a
        // missing-authority case; the caller should self-attenuate
        // client-side rather than re-request with a wider cap. Spec edit
        // pending (PROPOSAL-V7-CAPABILITY-HANDLER-CLOSEOUT-AMENDMENTS).
        if author != self.identity_hash {
            return Ok(HandlerResult::error(
                STATUS_NOT_SUPPORTED,
                error_entity(
                    "unsupported_operation",
                    "delegate is same-peer-only in v1: cross-peer self-attenuation is performed client-side (construct + sign the child cap locally from the parent)",
                ),
            ));
        }

        // V7.62 §3.6 amended: input is `system/capability/delegate-request`
        // = {parent, grants, ttl_ms?}. Parent moved off the resource_target
        // (where v7.60-era impl read it) and into params.
        let req = match decode_delegate_request(&ctx.params) {
            Ok(r) => r,
            Err(msg) => {
                return Ok(HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity("invalid_params", &msg),
                ));
            }
        };
        let parent_hash = req.parent;
        if req.grants.is_empty() {
            return Ok(HandlerResult::error(
                STATUS_BAD_REQUEST,
                error_entity(
                    "invalid_params",
                    "delegate-request must specify at least one grant entry",
                ),
            ));
        }

        let parent_entity = match self.content_store.get(&parent_hash) {
            Some(e) => e,
            None => {
                return Ok(HandlerResult::error(
                    STATUS_NOT_FOUND,
                    error_entity(
                        "parent_not_found",
                        &format!(
                            "delegate parent token not in store: {}",
                            hex_of(&parent_hash)
                        ),
                    ),
                ));
            }
        };
        if parent_entity.entity_type != TYPE_CAP_TOKEN {
            return Ok(HandlerResult::error(
                STATUS_BAD_REQUEST,
                error_entity(
                    "invalid_parent",
                    &format!(
                        "delegate parent must be {TYPE_CAP_TOKEN}, got: {}",
                        parent_entity.entity_type
                    ),
                ),
            ));
        }
        let parent_token = match CapabilityToken::from_entity(&parent_entity) {
            Ok(t) => t,
            Err(e) => {
                return Ok(HandlerResult::error(
                    STATUS_INTERNAL,
                    error_entity("internal", &format!("failed to decode parent token: {e}")),
                ));
            }
        };
        // V7.62 §6.2: "Handler checks parent.grantee == caller's
        // authenticated identity (direct hold, not chain-walk)." This is
        // the v1 self-attenuation auth model. The v7.60-era granter check
        // is replaced.
        if parent_token.grantee != author {
            return Ok(HandlerResult::error(
                STATUS_FORBIDDEN,
                error_entity(
                    "scope_exceeds_authority",
                    "delegate requires caller to directly hold the parent (parent.grantee == caller); chain-walked indirection is not in v1",
                ),
            ));
        }

        let child = CapabilityToken {
            grants: req.grants.clone(),
            granter: Granter::single(self.identity_hash),
            grantee: author,
            parent: Some(parent_hash),
            created_at: 0,
            expires_at: parent_token.expires_at,
            not_before: None,
            delegation_caveats: None,
        };
        if !is_attenuated(&child, &parent_token, &self.local_peer_id) {
            return Ok(HandlerResult::error(
                STATUS_FORBIDDEN,
                error_entity(
                    "scope_exceeds_authority",
                    "delegated scope is not an attenuation of the parent capability",
                ),
            ));
        }

        let created_at = now_ms();
        let mut expires_at = req.ttl_ms.and_then(|t| created_at.checked_add(t));
        if let Some(parent_exp) = parent_token.expires_at {
            expires_at = Some(match expires_at {
                Some(e) => e.min(parent_exp),
                None => parent_exp,
            });
        }

        self.mint_and_return(
            req.grants,
            author,
            Some(parent_hash),
            created_at,
            expires_at,
        )
    }

    fn handle_configure(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        // V7.62 §6.2 baseline policy surface: write a policy entry at
        // `system/capability/policy/{peer_pattern}`. Auth on the caller's
        // cap is already enforced by the dispatcher (standard handler-op
        // cap check); this handler manages its own namespace (§6.2
        // self-namespace authorization) and the tree write is
        // handler-authorized.
        if ctx.params.entity_type != TYPE_CAP_POLICY_ENTRY {
            return Ok(HandlerResult::error(
                STATUS_BAD_REQUEST,
                error_entity(
                    "invalid_params",
                    &format!(
                        "configure params must be {TYPE_CAP_POLICY_ENTRY}, got: {}",
                        ctx.params.entity_type
                    ),
                ),
            ));
        }
        let peer_pattern = match decode_policy_peer_pattern(&ctx.params) {
            Ok(p) => p,
            Err(msg) => {
                return Ok(HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity("invalid_params", &msg),
                ));
            }
        };
        if !is_valid_peer_pattern(&peer_pattern) {
            return Ok(HandlerResult::error(
                STATUS_BAD_REQUEST,
                error_entity(
                    "invalid_peer_pattern",
                    &format!(
                        "peer_pattern must be the literal `{POLICY_FALLBACK_SEGMENT}`, a §3.5 invariant-pointer peer hash (format-relative hex: 66 chars SHA-256, 98 chars SHA-384), or a Base58 PeerID; got: {peer_pattern:?}"
                    ),
                ),
            ));
        }

        // Persist the policy entity as-is. Per §6.2 the cross-cutting
        // timestamp convention doesn't apply to policy-entry (no
        // server-set timestamps on this shape).
        let entry_hash = match self.content_store.put(ctx.params.clone()) {
            Ok(h) => h,
            Err(e) => {
                return Ok(HandlerResult::error(
                    STATUS_INTERNAL,
                    error_entity("internal", &format!("failed to store policy entry: {e}")),
                ));
            }
        };
        let path = format!(
            "/{}/system/capability/policy/{}",
            self.local_peer_id, peer_pattern
        );
        self.location_index.set(&path, entry_hash);

        Ok(HandlerResult::ok(ctx.params.clone()))
    }

    fn handle_revoke(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        // V7.62 §6.2: revoke is the universal entry point. Authz model is
        // "caller MUST hold a cap covering system/capability:revoke" —
        // the standard dispatcher check, NO granter-identity carve-out.
        // The v7.60-era "only the granter may revoke" branch is removed.
        // Behavior is path-agnostic and uniform across all caps:
        //   - path-bound caps: tree-unbind the entry AND write the marker
        //     (defense-in-depth — covers both is_revoked checks)
        //   - wire-only caps: write the marker only
        let rv = match decode_capability_revocation(&ctx.params) {
            Ok(r) => r,
            Err(msg) => {
                return Ok(HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity("invalid_params", &msg),
                ));
            }
        };
        if rv.token.is_zero() {
            return Ok(HandlerResult::error(
                STATUS_BAD_REQUEST,
                error_entity(
                    "invalid_params",
                    "revoke-request must specify a non-zero token hash",
                ),
            ));
        }

        // Tree-unbind if the cap has a known storage path. Currently the
        // handler knows only its own marker namespace + system-handler
        // grants — extending `capability_path_for` to user-issued caps is
        // tracked under the §5.1 reverse-index work. Marker is written
        // unconditionally per the universal-entry-point contract.
        if let Some(path) = self.capability_path_for(&rv.token) {
            self.location_index.remove(&path);
        }

        let revoked_at = now_ms();
        let rev_entity = match build_revocation_entity(&rv, revoked_at) {
            Ok(e) => e,
            Err(msg) => {
                return Ok(HandlerResult::error(
                    STATUS_INTERNAL,
                    error_entity("internal", &msg),
                ));
            }
        };
        let rev_hash = match self.content_store.put(rev_entity.clone()) {
            Ok(h) => h,
            Err(e) => {
                return Ok(HandlerResult::error(
                    STATUS_INTERNAL,
                    error_entity("internal", &format!("failed to store revocation: {e}")),
                ));
            }
        };
        let rev_path = format!(
            "/{}/system/capability/revocations/{}",
            self.local_peer_id,
            hex_of(&rv.token)
        );
        self.location_index.set(&rev_path, rev_hash);

        Ok(HandlerResult::ok(rev_entity))
    }

    /// V7.62 §5.1 `capability_path_for(hash)` — return the canonical
    /// storage path for the cap if known, else None. Core protocol
    /// defines the convention for handler grants
    /// (`system/capability/grants/{pattern}`). Scan-based fallback per
    /// §5.1 MAY clause. Implementations SHOULD upgrade to a persistent
    /// reverse index when issuing caps — tracked as follow-up.
    fn capability_path_for(&self, cap_hash: &Hash) -> Option<String> {
        let prefix = format!("/{}/system/capability/grants/", self.local_peer_id);
        for entry in self.location_index.list(&prefix) {
            if &entry.hash == cap_hash {
                return Some(entry.path);
            }
        }
        None
    }

    fn mint_and_return(
        &self,
        grants: Vec<GrantEntry>,
        grantee: Hash,
        parent: Option<Hash>,
        created_at: u64,
        expires_at: Option<u64>,
    ) -> Result<HandlerResult, HandlerError> {
        let token = CapabilityToken {
            grants,
            granter: Granter::single(self.identity_hash),
            grantee,
            parent,
            created_at,
            expires_at,
            not_before: None,
            delegation_caveats: None,
        };
        let cap_entity = match token.to_entity() {
            Ok(e) => e,
            Err(e) => {
                return Ok(HandlerResult::error(
                    STATUS_INTERNAL,
                    error_entity("internal", &format!("failed to build token entity: {e}")),
                ));
            }
        };
        let sig_bytes = self.keypair.sign(&cap_entity.content_hash.to_bytes());
        let sig_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("algorithm"),
                entity_ecf::text(self.keypair.key_type().label()),
            ),
            (
                entity_ecf::text("signature"),
                entity_ecf::Value::Bytes(sig_bytes),
            ),
            (
                entity_ecf::text("signer"),
                entity_ecf::Value::Bytes(self.identity_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("target"),
                entity_ecf::Value::Bytes(cap_entity.content_hash.to_bytes().to_vec()),
            ),
        ]));
        let sig_entity = match Entity::new(TYPE_SIGNATURE, sig_data) {
            Ok(e) => e,
            Err(e) => {
                return Ok(HandlerResult::error(
                    STATUS_INTERNAL,
                    error_entity(
                        "internal",
                        &format!("failed to build signature entity: {e}"),
                    ),
                ));
            }
        };

        let cap_hash = cap_entity.content_hash;
        let sig_hash = sig_entity.content_hash;

        if let Err(e) = self.content_store.put(self.identity_entity.clone()) {
            return Ok(HandlerResult::error(
                STATUS_INTERNAL,
                error_entity(
                    "internal",
                    &format!("failed to store granter identity: {e}"),
                ),
            ));
        }
        if let Err(e) = self.content_store.put(cap_entity.clone()) {
            return Ok(HandlerResult::error(
                STATUS_INTERNAL,
                error_entity("internal", &format!("failed to store token entity: {e}")),
            ));
        }
        if let Err(e) = self.content_store.put(sig_entity.clone()) {
            return Ok(HandlerResult::error(
                STATUS_INTERNAL,
                error_entity(
                    "internal",
                    &format!("failed to store signature entity: {e}"),
                ),
            ));
        }
        // V7 §3.5 v7.44: "an extension that locally mints a chain-
        // participating capability MUST bind its signature here." Bind at
        // the invariant pointer path so verifiers (and the parent-chain
        // bundler below) can resolve it deterministically.
        let sig_path = invariant_signature_path(&self.local_peer_id, &cap_hash);
        self.location_index.set(&sig_path, sig_hash);

        let grant_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("token"),
            entity_ecf::Value::Bytes(cap_hash.to_bytes().to_vec()),
        )]));
        let grant_entity = match Entity::new(TYPE_CAP_GRANT, grant_data) {
            Ok(e) => e,
            Err(e) => {
                return Ok(HandlerResult::error(
                    STATUS_INTERNAL,
                    error_entity("internal", &format!("failed to build grant entity: {e}")),
                ));
            }
        };

        // V7.62 §6.2 result-envelope: MUST carry leaf token + leaf sig +
        // leaf granter identity (the three below). MAY carry the full
        // parent chain. SDKs targeting cross-peer dispatch SHOULD include
        // the chain by default — this handler does so by walking parents
        // up to root, best-effort (a missing parent / sig is omitted, not
        // an error).
        let mut included = std::collections::HashMap::new();
        included.insert(cap_hash, cap_entity);
        included.insert(sig_hash, sig_entity);
        included.insert(self.identity_hash, self.identity_entity.clone());
        if let Some(parent_hash) = parent {
            self.bundle_parent_chain(parent_hash, &mut included);
        }

        Ok(HandlerResult::ok_with_included(grant_entity, included))
    }

    /// V7.62 §6.2 parent-chain bundling. Walks the parent chain via the
    /// content store, surfacing each parent's token + signature (at the
    /// §3.5 invariant pointer path) + granter identity. Best-effort: a
    /// hop whose pieces don't resolve is omitted, not an error. Cycle-
    /// safe via a visited set.
    fn bundle_parent_chain(
        &self,
        leaf_parent: Hash,
        bundle: &mut std::collections::HashMap<Hash, Entity>,
    ) {
        let mut current = leaf_parent;
        let mut visited = std::collections::HashSet::new();
        loop {
            if !visited.insert(current) {
                return; // cycle — stop
            }
            let cap_entity = match self.content_store.get(&current) {
                Some(e) if e.entity_type == TYPE_CAP_TOKEN => e,
                _ => return,
            };
            let token = match CapabilityToken::from_entity(&cap_entity) {
                Ok(t) => t,
                Err(_) => return,
            };
            bundle.insert(current, cap_entity);

            let signers: Vec<Hash> = match &token.granter {
                Granter::Single(h) => vec![*h],
                Granter::Multi(m) => m.signers.clone(),
            };
            for signer_hash in &signers {
                if let Some(id_entity) = self.content_store.get(signer_hash) {
                    if id_entity.entity_type == TYPE_PEER {
                        // V7 §1.5 v7.65: derive canonical wire peer_id from
                        // (public_key, key_type); the entity no longer
                        // carries peer_id as a hashable field.
                        let peer_id = match PeerData::from_entity(&id_entity) {
                            Ok(d) => match d.canonical_peer_id() {
                                Some(p) => p,
                                None => continue,
                            },
                            Err(_) => {
                                continue;
                            }
                        };
                        bundle.insert(id_entity.content_hash, id_entity);
                        let sig_path = invariant_signature_path(&peer_id, &current);
                        if let Some(sig_hash) = self.location_index.get(&sig_path) {
                            if let Some(sig_entity) = self.content_store.get(&sig_hash) {
                                if sig_entity.entity_type == TYPE_SIGNATURE {
                                    bundle.insert(sig_entity.content_hash, sig_entity);
                                }
                            }
                        }
                    }
                }
            }

            match token.parent {
                Some(next) => current = next,
                None => return,
            }
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for CapabilityHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            "request" => self.handle_request(ctx),
            "delegate" => self.handle_delegate(ctx),
            "revoke" => self.handle_revoke(ctx),
            "configure" => self.handle_configure(ctx),
            other => Ok(HandlerResult::error(
                // V7 §6.2 capability-handler operation status codes: 501
                // when the handler is registered but does not implement
                // the named operation. Distinct from 404 (handler not
                // registered at all) and 403 (registered + supported but
                // caller's authority insufficient).
                STATUS_NOT_SUPPORTED,
                error_entity(
                    "unsupported_operation",
                    &format!("system/capability does not implement operation: {other}"),
                ),
            )),
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "capability"
    }

    fn operations(&self) -> &[&str] {
        &["request", "delegate", "revoke", "configure"]
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

struct CapabilityRequest {
    grants: Vec<GrantEntry>,
    ttl_ms: Option<u64>,
}

struct DelegateRequest {
    parent: Hash,
    grants: Vec<GrantEntry>,
    ttl_ms: Option<u64>,
}

struct CapabilityRevocation {
    token: Hash,
    reason: Option<String>,
}

fn decode_delegate_request(params: &Entity) -> Result<DelegateRequest, String> {
    let val: ciborium::Value = ciborium::de::from_reader(params.data.as_slice())
        .map_err(|e| format!("decode delegate-request: {e}"))?;
    let map = val
        .as_map()
        .ok_or_else(|| "delegate-request data must be a map".to_string())?;

    let mut parent: Option<Hash> = None;
    let mut grants: Vec<GrantEntry> = Vec::new();
    let mut ttl_ms: Option<u64> = None;
    for (k, v) in map {
        match k.as_text() {
            Some("parent") => {
                if let ciborium::Value::Bytes(b) = v {
                    parent =
                        Some(Hash::from_bytes(b).map_err(|e| format!("decode parent hash: {e}"))?);
                }
            }
            Some("grants") => {
                let arr = v
                    .as_array()
                    .ok_or_else(|| "grants must be an array".to_string())?;
                for entry in arr {
                    let g = decode_grant_entry(entry)
                        .map_err(|e| format!("decode grant entry: {e}"))?;
                    grants.push(g);
                }
            }
            Some("ttl_ms") => {
                if let ciborium::Value::Integer(i) = v {
                    let n: i128 = (*i).into();
                    if n >= 0 {
                        ttl_ms = Some(n as u64);
                    }
                }
            }
            _ => {}
        }
    }
    let parent = parent.ok_or_else(|| "delegate-request missing `parent`".to_string())?;
    Ok(DelegateRequest {
        parent,
        grants,
        ttl_ms,
    })
}

fn decode_capability_request(params: &Entity) -> Result<CapabilityRequest, String> {
    let val: ciborium::Value = ciborium::de::from_reader(params.data.as_slice())
        .map_err(|e| format!("decode capability-request: {e}"))?;
    let map = val
        .as_map()
        .ok_or_else(|| "capability-request data must be a map".to_string())?;

    let mut grants: Vec<GrantEntry> = Vec::new();
    let mut ttl_ms: Option<u64> = None;
    for (k, v) in map {
        match k.as_text() {
            Some("grants") => {
                let arr = v
                    .as_array()
                    .ok_or_else(|| "grants must be an array".to_string())?;
                for entry in arr {
                    let g = decode_grant_entry(entry)
                        .map_err(|e| format!("decode grant entry: {e}"))?;
                    grants.push(g);
                }
            }
            Some("ttl_ms") => {
                if let ciborium::Value::Integer(i) = v {
                    let n: i128 = (*i).into();
                    if n >= 0 {
                        ttl_ms = Some(n as u64);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(CapabilityRequest { grants, ttl_ms })
}

fn decode_capability_revocation(params: &Entity) -> Result<CapabilityRevocation, String> {
    let val: ciborium::Value = ciborium::de::from_reader(params.data.as_slice())
        .map_err(|e| format!("decode capability-revocation: {e}"))?;
    let map = val
        .as_map()
        .ok_or_else(|| "capability-revocation data must be a map".to_string())?;

    let mut token = Hash::zero();
    let mut reason: Option<String> = None;
    for (k, v) in map {
        match k.as_text() {
            Some("token") => {
                if let ciborium::Value::Bytes(b) = v {
                    token = Hash::from_bytes(b).map_err(|e| format!("decode token hash: {e}"))?;
                }
            }
            Some("reason") => {
                reason = v.as_text().map(|s| s.to_string());
            }
            _ => {}
        }
    }
    Ok(CapabilityRevocation { token, reason })
}

fn decode_policy_peer_pattern(params: &Entity) -> Result<String, String> {
    let val: ciborium::Value = ciborium::de::from_reader(params.data.as_slice())
        .map_err(|e| format!("decode policy-entry: {e}"))?;
    let map = val
        .as_map()
        .ok_or_else(|| "policy-entry data must be a map".to_string())?;
    for (k, v) in map {
        if k.as_text() == Some("peer_pattern") {
            return v
                .as_text()
                .map(|s| s.to_string())
                .ok_or_else(|| "peer_pattern must be a text string".to_string());
        }
    }
    Err("policy-entry missing `peer_pattern`".to_string())
}

/// V7 §6.2 v7.64 dual-form: `{peer_pattern}` MUST be exactly one of:
/// - the literal fallback segment [`POLICY_FALLBACK_SEGMENT`] (`default`)
/// - a §3.5 invariant-pointer hex form — lowercase hex of the full wire
///   hash (leading format-code byte + digest). The width is
///   **format-relative** per v7.70 §1.2: 66 chars for SHA-256, 98 for
///   SHA-384, and so on for any allocated format (the format byte is part
///   of the address, V7 §1.2; see also v7.64 §2.4)
/// - a Base58 PeerID per V7 §1.5 (the pre-configuration affordance —
///   operator pastes the handle without yet having the public_key, and the
///   handler resolves at handshake time)
///
/// The three forms are unambiguously distinguishable: `default` is the
/// exact 7-char string, hex form is all-hex with a format-valid width, and
/// any well-formed PeerID decodes via [`entity_crypto::PeerId::validate`].
///
/// V7 §6.2 v7.64 strengthened SHOULD → MUST: arbitrary garbage in
/// `peer_pattern` makes the resolver behave undefined for that entry,
/// so the handler MUST reject it at `configure` time with `400
/// invalid_peer_pattern`.
fn is_valid_peer_pattern(s: &str) -> bool {
    if s == POLICY_FALLBACK_SEGMENT {
        return true;
    }
    if is_invariant_pointer_hex(s) {
        return true;
    }
    // Base58 PeerID form: decodes and the (key_type, hash_type) pair is
    // one we recognize. Length is bounded by the existing decoder.
    entity_crypto::PeerId::from(s).validate().is_ok()
}

/// Whether `s` is a §3.5 invariant-pointer hex form: lowercase hex of the
/// full wire hash (leading format-code byte + digest). Rather than
/// hardcoding per-format widths, we read the format byte and check the
/// total length against the format registry ([`digest_len_for_format`]) —
/// so SHA-256 (66 chars), SHA-384 (98 chars), and any future allocated
/// format are all accepted, while a width that doesn't match its declared
/// format byte is rejected. v7.70 §1.2.
///
/// Single-byte format codes only: every allocated format (SHA-256/`0x00`,
/// SHA-384/`0x01`) encodes its code in one varint byte. A multi-byte
/// format code (none allocated, v7.67 §5.4) would need the full LEB128
/// decode here.
fn is_invariant_pointer_hex(s: &str) -> bool {
    if s.len() < 2
        || !s.len().is_multiple_of(2)
        || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return false;
    }
    let format_code = match u8::from_str_radix(&s[..2], 16) {
        Ok(c) => c,
        Err(_) => return false,
    };
    match entity_hash::digest_len_for_format(format_code) {
        Some(digest_len) => s.len() == 2 * (1 + digest_len),
        None => false,
    }
}

fn build_revocation_entity(rv: &CapabilityRevocation, revoked_at: u64) -> Result<Entity, String> {
    let mut fields: Vec<(entity_ecf::Value, entity_ecf::Value)> = Vec::with_capacity(3);
    fields.push((
        entity_ecf::text("token"),
        entity_ecf::Value::Bytes(rv.token.to_bytes().to_vec()),
    ));
    if let Some(reason) = rv.reason.as_deref() {
        fields.push((entity_ecf::text("reason"), entity_ecf::text(reason)));
    }
    fields.push((
        entity_ecf::text("revoked_at"),
        entity_ecf::Value::Integer(ciborium::value::Integer::from(revoked_at)),
    ));
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
    Entity::new(TYPE_CAP_REVOCATION, data).map_err(|e| e.to_string())
}

fn hex_of(h: &Hash) -> String {
    let bytes = h.to_bytes();
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes.iter() {
        s.push(hex_char(b >> 4));
        s.push(hex_char(b & 0x0f));
    }
    s
}

fn hex_char(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => '0',
    }
}

fn now_ms() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests;
