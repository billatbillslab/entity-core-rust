//! Request verification (§5.2).

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use entity_capability::{CapabilityToken, Granter};
use entity_crypto::{verify_for_key_type, KeyType};
use entity_entity::{Entity, Envelope};
use entity_hash::{invariant_signature_path, Hash};
use entity_types::{PeerData, SignatureData, TYPE_CAP_TOKEN, TYPE_PEER};
use thiserror::Error;

use crate::ProtocolError;

/// Max capability chain depth (§5.5).
pub const MAX_CHAIN_DEPTH: u64 = 64;

/// Verify a signature against a signer's `system/peer` data, dispatching the
/// algorithm on the signer's `key_type` (v7.67 Phase 2 — MATRIX-M2). Returns
/// `true` iff the `key_type` is allocated, the public-key length matches the
/// scheme, and the signature checks out. Used by the chain-walk sites that
/// `continue` on failure.
fn peer_data_sig_ok(id: &PeerData, message: &[u8], signature: &[u8]) -> bool {
    match KeyType::from_label(&id.key_type) {
        Ok(kt) => verify_for_key_type(kt, &id.public_key, message, signature).is_ok(),
        Err(_) => false,
    }
}

/// Strict variant of [`peer_data_sig_ok`] for sites that propagate a typed
/// error rather than skipping. Maps an unallocated `key_type` to
/// [`ProtocolError::Invalid`] and a bad signature to
/// [`ProtocolError::InvalidSignature`].
fn verify_peer_data_sig(
    id: &PeerData,
    message: &[u8],
    signature: &[u8],
) -> Result<(), ProtocolError> {
    let kt = KeyType::from_label(&id.key_type)
        .map_err(|e| ProtocolError::Invalid(e.to_string()))?;
    verify_for_key_type(kt, &id.public_key, message, signature)
        .map_err(|_| ProtocolError::InvalidSignature)
}

/// Verified request data extracted during verification.
#[derive(Debug)]
pub struct VerifiedRequest {
    pub author_hash: Hash,
    pub capability_hash: Hash,
    /// Decoded capability token for permission checking in dispatch.
    pub capability: CapabilityToken,
    pub request_id: String,
    pub uri: String,
    pub operation: String,
}

/// Verify an EXECUTE request's integrity (§5.2).
///
/// Checks: content hash, signature, author identity, capability chain.
/// Does NOT check permission (that requires handler resolution first).
#[tracing::instrument(level = "debug", skip_all, fields(included = envelope.included.len()))]
pub fn verify_request(
    envelope: &Envelope,
    local_peer_id: &str,
) -> Result<VerifiedRequest, ProtocolError> {
    let execute = &envelope.root;

    // 1. V7 §1.2 v7.66 format-code dispatch precedes hash validation.
    //    An unsupported `content_hash_format` byte at this boundary
    //    surfaces as `400 unsupported_content_hash_format` (per §4.7
    //    normative status table) rather than masquerading as
    //    `HashMismatch` (which would mis-signal as a presentation error
    //    when the impl simply doesn't speak the format). The check fires
    //    on the EXECUTE root and on every `envelope.included` entity
    //    BEFORE their per-entity hash recompute (validate()).
    if !execute.content_hash.is_supported_format() {
        return Err(ProtocolError::UnsupportedContentHashFormat(
            execute.content_hash.algorithm,
        ));
    }
    for entity in envelope.included.values() {
        if !entity.content_hash.is_supported_format() {
            return Err(ProtocolError::UnsupportedContentHashFormat(
                entity.content_hash.algorithm,
            ));
        }
    }

    // 2. Validate content hash on the EXECUTE root.
    execute
        .validate()
        .map_err(|_| ProtocolError::HashMismatch)?;

    // 2b. Validate content hash on every envelope.included entity.
    //
    // PROPOSAL-CROSS-IMPL-STANDARDIZATION-CATCHUP §4 / MACHINE-SPEC §1.8:
    // an entity's claimed hash MUST be verified before trust. Prior to this
    // pass only the root was checked; included caps, identities, signatures,
    // and chain entities reached downstream consumers with their claimed
    // hashes unverified — a forgery surface where a peer could substitute
    // an entity for a known hash via envelope manipulation (downstream
    // hash-keyed lookups like `included[h]` would index the substitute under
    // h, even though h ≠ recomputed(substitute.bytes)).
    for entity in envelope.included.values() {
        entity.validate().map_err(|_| ProtocolError::HashMismatch)?;
    }

    // 2. Extract author and capability hashes from execute data
    let execute_data = decode_execute_fields(&execute.data)?;

    let author_hash = execute_data
        .author
        .ok_or(ProtocolError::AuthenticationFailed("missing author"))?;
    let capability_hash = execute_data
        .capability
        .ok_or(ProtocolError::MissingCapability)?;

    // 3. Find and verify signature. §5.2 step-2 is authentication (401),
    //    distinct from the step-3+ capability-chain signature checks (403).
    let sig_entity = envelope
        .find_signature_for(&execute.content_hash)
        .ok_or(ProtocolError::AuthenticationFailed("missing execute signature"))?;

    let sig_data = SignatureData::from_entity(sig_entity)
        .map_err(|e| ProtocolError::Invalid(e.to_string()))?;

    // Signer must match author
    if sig_data.signer != author_hash {
        return Err(ProtocolError::AuthenticationFailed(
            "execute signer does not match author",
        ));
    }

    // 4. Verify author identity exists and signature is valid
    let author_entity = envelope
        .find_included(&author_hash)
        .ok_or(ProtocolError::AuthenticationFailed(
            "author identity not in included",
        ))?;

    if author_entity.entity_type != TYPE_PEER {
        return Err(ProtocolError::Invalid("author is not system/peer".into()));
    }

    let author_identity = PeerData::from_entity(author_entity)
        .map_err(|e| ProtocolError::Invalid(e.to_string()))?;

    verify_peer_data_sig(
        &author_identity,
        &execute.content_hash.to_bytes(),
        &sig_data.signature,
    )
    .map_err(|e| match e {
        // §5.2 step-2 EXECUTE-signature failure is authentication (401).
        // An unallocated key_type stays `Invalid` (→400, malformed).
        ProtocolError::InvalidSignature => {
            ProtocolError::AuthenticationFailed("invalid execute signature")
        }
        other => other,
    })?;

    // 5. Verify capability
    let cap_entity = envelope
        .find_included(&capability_hash)
        .ok_or(ProtocolError::MissingCapabilityEntity)?;

    if cap_entity.entity_type != TYPE_CAP_TOKEN {
        return Err(ProtocolError::Invalid(
            "capability is not system/capability/token".into(),
        ));
    }

    // Decode full capability token
    let cap_token = CapabilityToken::from_entity(cap_entity)
        .map_err(|e| ProtocolError::Invalid(format!("capability decode: {}", e)))?;

    // Resolve the leaf cap's grantee to a present `system/peer` entity BEFORE
    // the grantee==author equality check (PR-3 / V7 §3.6 + §5.2 single-401
    // carve-out). A grantee that does not resolve is the `unresolvable_grantee`
    // case (401) — it MUST NOT collapse into the 403 GranteeMismatch or the
    // `verification_failed` catch-all. A grantee that resolves but differs from
    // the author is the genuine 403 GranteeMismatch. `verify_capability_chain`
    // re-checks every chain link's grantee (step 2a); this leaf check only
    // fixes the ordering so resolution precedes equality. The cohort oracle's
    // `grantee_author_mismatch` deliberately includes the grantee identity so
    // resolution passes and the mismatch fires as the cause of the 403.
    match envelope.find_included(&cap_token.grantee) {
        Some(g) if g.entity_type == TYPE_PEER => {}
        _ => return Err(ProtocolError::UnresolvableGrantee),
    }

    // Check grantee matches author
    if cap_token.grantee != author_hash {
        return Err(ProtocolError::GranteeMismatch);
    }

    // Check time-based validity
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    if let Some(expires_at) = cap_token.expires_at {
        if now_ms >= expires_at {
            return Err(ProtocolError::CapabilityExpired);
        }
    }

    if let Some(not_before) = cap_token.not_before {
        if now_ms < not_before {
            return Err(ProtocolError::CapabilityNotYetValid);
        }
    }

    // 6. Verify capability chain
    verify_capability_chain(&capability_hash, &envelope.included, local_peer_id)?;

    Ok(VerifiedRequest {
        author_hash,
        capability_hash,
        capability: cap_token,
        request_id: execute_data.request_id,
        uri: execute_data.uri,
        operation: execute_data.operation,
    })
}

/// V7 §5.2 verify_request context (V7.62 closeout F2).
///
/// Carries the impl's revocation-support advertisement plus the
/// `local_peer_id` that `verify_request` already needed. When
/// `supports_revocation == true`, callers MUST use
/// [`verify_request_with_ctx`] (which runs §5.2 Step 4 `is_revoked`) — the
/// no-context [`verify_request`] omits the marker check and is suitable
/// only for impls that advertise `supports_revocation = false`.
#[derive(Debug, Clone, Copy)]
pub struct VerifyContext<'a> {
    pub local_peer_id: &'a str,
    /// V7 §5.1 / V7.62 closeout F2: when true, `verify_request_with_ctx`
    /// MUST run `is_revoked` Step 4 and MUST reject revoked caps. Wire-
    /// only caps depend on this — the §5.1 marker mechanism is operative
    /// only when `verify_request` reads the marker.
    pub supports_revocation: bool,
}

impl<'a> VerifyContext<'a> {
    pub fn new(local_peer_id: &'a str) -> Self {
        Self { local_peer_id, supports_revocation: false }
    }

    pub fn with_revocation(mut self, on: bool) -> Self {
        self.supports_revocation = on;
        self
    }
}

/// V7 §5.2 verify_request with V7.62 closeout F2 revocation wire-in.
///
/// Runs the same Steps 1-6 as [`verify_request`] and then, when
/// `ctx.supports_revocation` is true, executes Step 4 — invokes
/// [`is_revoked`] over the verified capability chain and rejects with
/// [`ProtocolError::CapabilityRevoked`] on a hit. Closeout F2 promoted
/// this wire-in from SHOULD to MUST: v7.62 introduced the marker
/// mechanism precisely so wire-only caps could be revoked, but the
/// marker is operationally inert unless `verify_request` reads it.
///
/// `resolve` / `locate` / `capability_path_for` are the same closures
/// [`is_revoked`] takes. Convention: `resolve` is store-first then
/// included; `locate` is the location index; `capability_path_for` is
/// either an O(1) reverse index or the scan fallback
/// ([`capability_path_for_scan`]).
pub fn verify_request_with_ctx<R, L, P>(
    envelope: &Envelope,
    ctx: &VerifyContext<'_>,
    resolve: R,
    locate: L,
    capability_path_for: P,
) -> Result<VerifiedRequest, ProtocolError>
where
    R: Fn(&Hash) -> Option<Entity>,
    L: Fn(&str) -> Option<Hash>,
    P: Fn(&Hash) -> Option<String>,
{
    let verified = verify_request(envelope, ctx.local_peer_id)?;
    if ctx.supports_revocation
        && is_revoked(
            &verified.capability_hash,
            ctx.local_peer_id,
            resolve,
            locate,
            capability_path_for,
        )
    {
        return Err(ProtocolError::CapabilityRevoked);
    }
    Ok(verified)
}

/// Errors from `collect_authority_chain` and downstream consumers.
///
/// Distinct from `ProtocolError` because the chain-walk primitive is a
/// pre-validation step used by both dispatch-time verification and
/// install-time creator checks — surfacing as either 404 `chain_unreachable`
/// (when callers map at the protocol boundary) or `DENY` (dispatch-time).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ChainWalkError {
    #[error("chain unreachable: parent reference cannot be resolved")]
    Unreachable,
    #[error("chain too deep: exceeded MAX_CHAIN_DEPTH ({MAX_CHAIN_DEPTH})")]
    TooDeep,
}

/// Walk a capability's authority chain from leaf to root and return the
/// collected entities **paired with their decoded chain fields** (V7 §5.5
/// `collect_authority_chain`, PROPOSAL-UNIFIED-CHAIN-WALK-PRIMITIVE).
///
/// This is the **shared** chain-walk primitive — every other walker
/// (`verify_capability_chain`, `check_creator_authority`, `is_revoked` if
/// implemented) MUST call this rather than reimplementing parent traversal.
/// Centralizing the walk eliminates the class of bugs where independent
/// implementations short-circuit, miss reachability checks, or diverge on
/// edge cases.
///
/// **Always walks to root.** No early return on any condition. If any
/// `resolve(parent)` returns `None`, returns `ChainWalkError::Unreachable`
/// before any consumer-specific check runs. Reachability is enforced by
/// construction.
///
/// **Resolution source is parameterized.** `resolve` looks up an entity by
/// hash from whatever sources the caller composes. By convention:
/// - dispatch-time: `included[hash]` only (chain must travel in envelope)
/// - install-time: `included[hash] ?? content_store.get(hash)`
/// - revocation: `content_store.get(hash) ?? included[hash]` (store-first)
///
/// The returned vector is leaf-to-root (`[leaf, ..., root]`); the root has
/// `parent = None`. Each element is `(entity, fields)`; `fields` are the
/// already-decoded `granter` / `grantee` / `parent` so per-level callers
/// don't need to re-decode the same CBOR.
pub fn collect_authority_chain<F>(
    leaf_hash: &Hash,
    resolve: F,
) -> Result<Vec<(Entity, CapabilityChainFields)>, ChainWalkError>
where
    F: Fn(&Hash) -> Option<Entity>,
{
    let mut chain = Vec::new();
    let mut current_hash = *leaf_hash;
    let mut depth: u64 = 0;

    loop {
        if depth > MAX_CHAIN_DEPTH {
            return Err(ChainWalkError::TooDeep);
        }
        let entity = match resolve(&current_hash) {
            Some(e) => e,
            None => return Err(ChainWalkError::Unreachable),
        };
        let fields = match decode_capability_chain_fields(&entity.data) {
            Ok(f) => f,
            // Malformed cap entity at any chain level is treated as a
            // reachability failure: we couldn't resolve a usable cap there.
            Err(_) => return Err(ChainWalkError::Unreachable),
        };
        let parent_hash = fields.parent;
        chain.push((entity, fields));
        match parent_hash {
            None => return Ok(chain),
            Some(p) => {
                current_hash = p;
                depth += 1;
            }
        }
    }
}


/// Determine whether a capability chain is **operator-class** with respect
/// to a target path family per GUIDE-CAPABILITIES §10 (v1.2.1 Ruling 1).
///
/// A chain is operator-class iff:
/// 1. It walks to a root (`parent: None`) whose `granter` is the supplied
///    `root_identity_hash` (the L0 bootstrap identity for single-sig roots).
/// 2. Every link's `grants[*].resources.include` carries at least one
///    entry that **explicitly enumerates** `target_pattern` — meaning the
///    entry contains no wildcard character (`*`) and is either equal to
///    `target_pattern` or a literal path-segment prefix of it. Wildcard
///    matches do NOT count even when they would match the target.
///
/// Used by extensions that gate sensitive prefix families (CAPABILITY §10
/// for `system/capability/**`; INSPECTABILITY §3.4.1 for
/// `system/runtime/**` and `system/continuation/**`). Returns `false` on
/// any chain-walk failure (unreachable / too deep / malformed cap entity)
/// so the gate fails closed.
///
/// `resolve` is the content resolver — typically `|h| content_store.get(h)`.
/// Multi-sig roots are NOT operator-class via this primitive — they would
/// satisfy criterion 1 only if explicitly extended to compare against a
/// multi-sig root identity, which v1.2.1 does not specify.
pub fn is_operator_class_for<F>(
    leaf_hash: &Hash,
    target_pattern: &str,
    root_identity_hash: &Hash,
    resolve: F,
) -> bool
where
    F: Fn(&Hash) -> Option<Entity>,
{
    let chain = match collect_authority_chain(leaf_hash, &resolve) {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Criterion 1: chain roots at L0 bootstrap.
    let root_fields = match chain.last() {
        Some((_, f)) => f,
        None => return false,
    };
    if root_fields.parent.is_some() {
        return false;
    }
    let root_granter_hash = match &root_fields.granter {
        Granter::Single(h) => h,
        // Multi-sig roots are not single-identity-rooted; v1.2.1 does not
        // extend operator-class to multi-sig. Fail closed.
        Granter::Multi(_) => return false,
    };
    if root_granter_hash != root_identity_hash {
        return false;
    }

    // Criterion 2: every link explicitly enumerates target.
    for (entity, _fields) in &chain {
        let token = match CapabilityToken::from_entity(entity) {
            Ok(t) => t,
            Err(_) => return false,
        };
        if !token
            .grants
            .iter()
            .any(|grant| {
                grant
                    .resources
                    .include
                    .iter()
                    .any(|pat| explicitly_enumerates(pat, target_pattern))
            })
        {
            return false;
        }
    }

    true
}

/// Whether a `resources` pattern literally enumerates `target` per Ruling 1.
/// Wildcards never count.
fn explicitly_enumerates(resource_pattern: &str, target: &str) -> bool {
    if resource_pattern.contains('*') {
        return false;
    }
    if resource_pattern == target {
        return true;
    }
    // Literal-prefix match: pattern is a path-segment prefix of target.
    let prefix = if resource_pattern.ends_with('/') {
        resource_pattern.to_string()
    } else {
        format!("{}/", resource_pattern)
    };
    target.starts_with(&prefix)
}

/// Gather the full set of entities a remote verifier needs to validate
/// `leaf_hash`'s authority chain — EXTENSION-CONTINUATION §4.3 / §8.2 C-3,
/// the **dispatch chain-walk + bundle helper**.
///
/// For a cross-peer continuation step whose `target` is a remote peer B,
/// §4.2 "Chain transport" makes the *dispatching* peer responsible for
/// placing the **transitive** authority chain in the dispatched EXECUTE
/// envelope's `included`. The general V7 §3.1/§3.2 rule only carries the
/// leaf cap (it alone is referenced from EXECUTE `data`); each parent /
/// granter cap is referenced from *within* a cap entity and would otherwise
/// be missing at B, failing B's `VerifyChain` (V7 §5.2).
///
/// Returns, keyed by content hash: every capability from the leaf up to its
/// root, plus — best-effort per link — each link's granter `system/peer`
/// identity entity and the granter's signature over that link (resolved from
/// the V7 invariant pointer path
/// `/{signer_peer_id}/system/signature/{target_hex}` that envelope ingest
/// binds, so the bundle matches what B's signature resolver expects).
///
/// **Over-inclusion is intentional and free.** Content-addressing dedups any
/// entity B already holds, eliminating the "B GC'd a parent → `VerifyChain`
/// fails" failure mode at zero correctness cost (§4.2). **Best-effort per
/// link** — a link whose identity or bound signature is not resolvable is
/// simply omitted; B fails closed later if it actually needed it.
///
/// `resolve` is the content resolver (by convention the installer's content
/// store — §3.2 step 5 persisted the full chain there at install). `locate`
/// resolves a tree path to a content hash (the location index), used only
/// for the signature invariant-pointer path. Generic over closures to match
/// the [`collect_authority_chain`] idiom — no store-trait dependency.
///
/// Propagates [`ChainWalkError`] from the underlying walk (an unreachable or
/// over-deep chain is a real failure, not a best-effort omission — the leaf
/// chain itself must resolve).
pub fn collect_chain_bundle<R, L>(
    leaf_hash: &Hash,
    resolve: R,
    locate: L,
) -> Result<std::collections::HashMap<Hash, Entity>, ChainWalkError>
where
    R: Fn(&Hash) -> Option<Entity>,
    L: Fn(&str) -> Option<Hash>,
{
    let chain = collect_authority_chain(leaf_hash, &resolve)?;
    let mut bundle: std::collections::HashMap<Hash, Entity> =
        std::collections::HashMap::with_capacity(chain.len() * 3);

    for (cap_entity, fields) in chain {
        let cap_hash = cap_entity.content_hash;
        bundle.insert(cap_hash, cap_entity);

        // Granter identities for this link — single-sig: one; multi-sig:
        // every constituent signer.
        let signers: Vec<Hash> = match &fields.granter {
            Granter::Single(h) => vec![*h],
            Granter::Multi(m) => m.signers.clone(),
        };
        for signer in signers {
            let id_entity = match resolve(&signer) {
                Some(e) if e.entity_type == TYPE_PEER => e,
                // best-effort: identity not locally resolvable → omit
                _ => continue,
            };
            let peer_id = match PeerData::from_entity(&id_entity) {
                // V7 §1.5 v7.65: derive canonical wire peer_id from
                // (public_key, key_type). The entity no longer carries
                // peer_id as a hashable field.
                Ok(d) => match d.canonical_peer_id() {
                    Some(p) => p,
                    None => continue,
                },
                Err(_) => continue,
            };
            bundle.insert(id_entity.content_hash, id_entity);

            let sig_path = invariant_signature_path(&peer_id, &cap_hash);
            if let Some(sig_hash) = locate(&sig_path) {
                if let Some(sig_entity) = resolve(&sig_hash) {
                    if sig_entity.entity_type == entity_entity::TYPE_SIGNATURE {
                        bundle.insert(sig_entity.content_hash, sig_entity);
                    }
                }
            }
        }
    }
    Ok(bundle)
}

/// V7.62 §5.1 `is_revoked` — check whether a capability is revoked.
///
/// Walks the delegation chain to the root, then checks two mechanisms in
/// sequence:
/// 1. **Path-binding**: if `capability_path_for(root_hash)` returns a
///    path, the root tree entry MUST be present AND its content_hash MUST
///    equal `root_hash`. Mismatch or absence ⇒ revoked.
/// 2. **Marker check**: `system/capability/revocations/{root_hash_hex}`
///    is consulted regardless of path-binding outcome. Presence ⇒ revoked.
///    (Defense-in-depth — covers both wire-only caps with no known
///    storage path, and provides a second signal for path-bound caps.)
///
/// Returns `true` (revoked) on any chain-walk failure — fail-closed per
/// §1.11 / §5.1 (an unresolvable parent is treated as revoked, never
/// fail-open). Same posture as `is_operator_class_for`.
///
/// **Closures:**
/// - `resolve(hash)` — content lookup. By V7 §5.1 convention for
///   revocation, store-first then `included` fallback.
/// - `locate(path)` — location index lookup.
/// - `capability_path_for(hash)` — returns the canonical storage path of
///   the cap if known, else `None` for wire-only caps. The core protocol
///   pins the convention for handler grants
///   (`system/capability/grants/{pattern}`); application-issued caps are
///   application-defined and SHOULD maintain a reverse index.
/// - `local_peer_id` — used to qualify the marker path. Bare-path
///   semantics in §5.1 pseudocode map to `/{local_peer_id}/system/...`
///   in our location-indexed storage.
pub fn is_revoked<R, L, P>(
    leaf_hash: &Hash,
    local_peer_id: &str,
    resolve: R,
    locate: L,
    capability_path_for: P,
) -> bool
where
    R: Fn(&Hash) -> Option<Entity>,
    L: Fn(&str) -> Option<Hash>,
    P: Fn(&Hash) -> Option<String>,
{
    let chain = match collect_authority_chain(leaf_hash, &resolve) {
        Ok(c) => c,
        Err(_) => return true,
    };
    let root_hash = chain
        .last()
        .map(|(e, _)| e.content_hash)
        .expect("collect_authority_chain returns non-empty chain on Ok");

    // 1. Path-binding check (applies only when the cap has a known
    //    storage path — wire-only caps fall through to marker check).
    if let Some(root_path) = capability_path_for(&root_hash) {
        match locate(&root_path) {
            None => return true,
            Some(bound) if bound != root_hash => return true,
            _ => {}
        }
    }

    // 2. Explicit revocation marker check (defense-in-depth; also the
    //    only revocation signal for wire-only caps).
    let marker_path = format!(
        "/{}/system/capability/revocations/{}",
        local_peer_id,
        root_hash.to_hex()
    );
    locate(&marker_path).is_some()
}

/// V7.62 §5.1 `capability_path_for` — scan-based fallback.
///
/// Returns the canonical storage path for `cap_hash` if it is bound under
/// a known capability-storage prefix, else `None` (wire-only / unknown).
///
/// Spec-defined prefix the core protocol always knows: handler grants at
/// `system/capability/grants/{pattern}`. Application-issued caps live
/// under application-defined prefixes — implementations SHOULD maintain a
/// reverse index for O(1) lookup; this scan is the MAY-level fallback per
/// §5.1.
///
/// `list_by_prefix(prefix)` returns every `(path, hash)` pair the
/// LocationIndex has under the given prefix; the caller provides this
/// without a hard store-trait dependency on `core/protocol`.
pub fn capability_path_for_scan<F>(
    cap_hash: &Hash,
    local_peer_id: &str,
    list_by_prefix: F,
) -> Option<String>
where
    F: Fn(&str) -> Vec<(String, Hash)>,
{
    let prefix = format!("/{}/system/capability/grants/", local_peer_id);
    for (path, h) in list_by_prefix(&prefix) {
        if h == *cap_hash {
            return Some(path);
        }
    }
    None
}

/// Result of the R1 creator-authority check.
///
/// The collected `chain` is returned alongside `found` so callers can persist
/// it without re-walking — coherent-cap §2 chain-entity persistence becomes a
/// loop over this slice rather than a third independent walk.
///
/// **Persist only when `found == true`.** Rejected requests must not
/// contribute caps to the local store.
#[derive(Debug, Clone)]
pub struct CreatorAuthorityResult {
    pub found: bool,
    pub chain: Vec<Entity>,
}

/// R1 creator-authorization check (V7 §5.5 `check_creator_authority`,
/// PROPOSAL-UNIFIED-CHAIN-WALK-PRIMITIVE §3.2). Replaces the retired
/// `identity_in_authority_chain` helper.
///
/// Used by extensions that embed capability references for later dispatch
/// (continuation install, subscription subscribe, compute install audit).
/// Returns `Ok(CreatorAuthorityResult)` when the chain is fully reachable
/// (regardless of whether the identity matched), or
/// `Err(ChainWalkError::Unreachable)` when any parent is missing —
/// reachability errors take precedence over identity match by virtue of
/// `collect_authority_chain` always walking to root before returning.
///
/// Caller mapping at protocol boundary:
/// - `Err(Unreachable)` or `Err(TooDeep)` → 404 `chain_unreachable`
/// - `Ok({found: false, ..})` → 403 `embedded_cap_unauthorized`
/// - `Ok({found: true, chain})` → 200 + persist `chain` to content store
pub fn check_creator_authority<F>(
    cap_hash: &Hash,
    identity: &Hash,
    included: &std::collections::HashMap<Hash, Entity>,
    resolve: F,
) -> Result<CreatorAuthorityResult, ChainWalkError>
where
    F: Fn(&Hash) -> Option<Entity>,
{
    let chain = collect_authority_chain(cap_hash, &resolve)?;
    let mut found = false;
    for (entity, fields) in &chain {
        match &fields.granter {
            // Single-sig: writer matches the granter hash.
            Granter::Single(granter_id) => {
                if granter_id == identity {
                    found = true;
                    break;
                }
            }
            // Multi-sig (M7 strict-with-signature): writer must be in `signers`
            // AND have actually signed at this link. A peer listed but never
            // signing did not participate.
            //
            // Identity-entity lookup uses `resolve` (which by convention encodes
            // `ctx.included[h] ?? ctx.content_store.get(h)` per V7 §5.5 line
            // 1986–1988). Signature lookup is scoped to envelope `included`
            // only — signatures are wire artifacts, not persistent state.
            Granter::Multi(multi) => {
                if !multi.signers.iter().any(|s| s == identity) {
                    continue;
                }
                let sig = match entity_entity::find_signature_by_signer(
                    included.values(),
                    &entity.content_hash,
                    identity,
                ) {
                    Some(s) => s,
                    None => continue,
                };
                let sig_data = match SignatureData::from_entity(sig) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let writer_identity_entity = match resolve(identity) {
                    Some(e) => e,
                    None => continue,
                };
                let writer_identity = match PeerData::from_entity(&writer_identity_entity) {
                    Ok(i) => i,
                    Err(_) => continue,
                };
                if peer_data_sig_ok(
                    &writer_identity,
                    &entity.content_hash.to_bytes(),
                    &sig_data.signature,
                ) {
                    found = true;
                    break;
                }
            }
        }
    }
    // Strip fields for the public result — preserves the existing
    // `CreatorAuthorityResult.chain: Vec<Entity>` shape used by extensions.
    let chain_entities = chain.into_iter().map(|(e, _)| e).collect();
    Ok(CreatorAuthorityResult { found, chain: chain_entities })
}

/// Verify a capability chain back to a root capability (§5.5).
///
/// Restructured under PROPOSAL-UNIFIED-CHAIN-WALK-PRIMITIVE: walk the chain
/// once via `collect_authority_chain`, then validate per-level. Behaviorally
/// identical to the prior inline walk for valid chains; for compound failures
/// (e.g., bad signature at level 0 AND unreachable parent at level 1), chain
/// reachability now takes precedence — both fail closed, the difference is
/// which error code surfaces. Implementations sharing one walker prevents the
/// short-circuit / divergence bugs that arose when each consumer rolled its
/// own loop.
pub fn verify_capability_chain(
    capability_hash: &Hash,
    included: &BTreeMap<Hash, Entity>,
    local_peer_id: &str,
) -> Result<(), ProtocolError> {
    // 1. Collect the full chain. Reachability errors fire here, before any
    //    per-level validation runs. Fields are decoded once during the walk.
    let chain = collect_authority_chain(capability_hash, |h| included.get(h).cloned())
        .map_err(|e| match e {
            ChainWalkError::TooDeep => ProtocolError::ChainTooDeep,
            ChainWalkError::Unreachable => ProtocolError::MissingEntity("capability in chain"),
        })?;

    // 1b. V7 §5.5 v7.66 cap-chain format-code freeze (Reading A). All
    //     chain links MUST share the same `content_hash_format` for the
    //     entities' own `content_hash`es; a cross-format chain without a
    //     continuous re-signing event is rejected. Reading A scope:
    //     chain's own link content_hashes, NOT signed targets (signed
    //     targets are resolved via §1.2 prefix-routing dispatch — the
    //     `is_supported_format()` check at the validation boundary
    //     above). Today only `0x00` is in production use; this check is
    //     structurally inert until a second format is allocated.
    if let Some(((first_entity, _), _)) = chain.split_first() {
        let baseline = first_entity.content_hash.algorithm;
        for (entity, _) in chain.iter().skip(1) {
            let alg = entity.content_hash.algorithm;
            if alg != baseline {
                return Err(ProtocolError::CapabilityFormatCodeMismatch(baseline, alg));
            }
        }
    }

    // 2a. Per-link grantee resolution (PROPOSAL-ROLE-V2.0-PRODUCTION-READINESS
    //     PR-3 / V7 v7.39 §3.6 + §5.5). Every cap in the chain MUST have a
    //     `grantee` that resolves to a present `system/peer` entity in
    //     `included` — same lookup table as granter resolution per §5.5.
    //     Self-caps (grantee == granter) satisfy naturally because granter
    //     resolution at step 3 will already require the entity to be present.
    //     Bearer caps (zero-hash grantee, or any other unresolvable hash) are
    //     rejected with `UnresolvableGrantee` → 401. Runs before per-link
    //     signature work so structurally invalid caps are surfaced cheaply.
    for (_entity, fields) in chain.iter() {
        let grantee_entity = included
            .get(&fields.grantee)
            .ok_or(ProtocolError::UnresolvableGrantee)?;
        if grantee_entity.entity_type != TYPE_PEER {
            return Err(ProtocolError::UnresolvableGrantee);
        }
    }

    // 2c. Per-link temporal validity (V7 §5.5, pseudocode lines 2280-2283).
    //     Every cap in the chain — not just the leaf — MUST be temporally
    //     valid at verification time. A chain with a not-yet-valid or
    //     expired intermediate link is denied NOW, even if the leaf itself
    //     is currently valid. Mirrors the leaf check in `verify_request`.
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    for (_entity, fields) in chain.iter() {
        if let Some(expires_at) = fields.expires_at {
            if now_ms >= expires_at {
                return Err(ProtocolError::CapabilityExpired);
            }
        }
        if let Some(not_before) = fields.not_before {
            if now_ms < not_before {
                return Err(ProtocolError::CapabilityNotYetValid);
            }
        }
    }

    // 2b. M3 validity pass (PROPOSAL-MULTISIG-CORE-PRIMITIVE §3.3 MUST level).
    //    Multi-sig caps MUST have parent: None; signers/threshold must be
    //    well-formed. Run before any per-link signature work so malformed
    //    caps are rejected up front (within-cap precedence rule,
    //    follow-up #4: M3 fires before signature verification on the same cap).
    //
    //    Errors surface as `CapabilityInvalid` → `403 capability_denied` per
    //    the §3.3 status-normalization rule, NOT as generic `Invalid` → 400.
    for (i, (_entity, fields)) in chain.iter().enumerate() {
        if let Granter::Multi(multi) = &fields.granter {
            if fields.parent.is_some() {
                return Err(ProtocolError::CapabilityInvalid(
                    "multi-sig capability must have parent: null (M3)".into(),
                ));
            }
            // Multi-sig must be at chain root (== chain.len()-1) — implied by
            // parent: None plus chain-walk shape, but assert defensively.
            if i + 1 != chain.len() {
                return Err(ProtocolError::CapabilityInvalid(
                    "multi-sig capability appeared at non-root chain position (M3)".into(),
                ));
            }
            multi
                .validate()
                .map_err(|e| ProtocolError::CapabilityInvalid(e.to_string()))?;
        }
    }

    // 3. Per-level validation.
    for i in 0..chain.len() {
        let (entity, fields) = &chain[i];
        let current_hash = entity.content_hash;

        match &fields.granter {
            // ---------- Single-sig path (V7 §5.5, unchanged) ----------
            Granter::Single(granter_id) => {
                let sig = entity_entity::find_signature_for_target(included.values(), &current_hash)
                    .ok_or(ProtocolError::MissingSignature)?;
                let sig_data = SignatureData::from_entity(sig)
                    .map_err(|e| ProtocolError::Invalid(e.to_string()))?;
                if sig_data.signer != *granter_id {
                    return Err(ProtocolError::SignerMismatch);
                }

                let granter_entity = included
                    .get(granter_id)
                    .ok_or(ProtocolError::MissingEntity("granter identity"))?;
                let granter_identity = PeerData::from_entity(granter_entity)
                    .map_err(|e| ProtocolError::Invalid(e.to_string()))?;
                verify_peer_data_sig(
                    &granter_identity,
                    &current_hash.to_bytes(),
                    &sig_data.signature,
                )?;

                if i + 1 < chain.len() {
                    let (parent_entity, parent_fields) = &chain[i + 1];
                    if parent_fields.grantee != *granter_id {
                        return Err(ProtocolError::GranteeMismatch);
                    }
                    let child_token = CapabilityToken::from_entity(entity)
                        .map_err(|e| ProtocolError::Invalid(format!("child cap decode: {e}")))?;
                    let parent_token = CapabilityToken::from_entity(parent_entity)
                        .map_err(|e| ProtocolError::Invalid(format!("parent cap decode: {e}")))?;

                    // V7 §5.5a / §PR-8 (chain-walk surface): each link's
                    // resource patterns canonicalize against ITS OWN granter's
                    // peer_id, not the verifier's. Conflating with
                    // `local_peer_id` lets a foreign-granted bare `*` (which
                    // MUST canon to `/{granter}/*`) silently canon to
                    // `/{verifier}/*` and pass attenuation — the V1'
                    // authority-escalation the cohort triple-confirmed. The
                    // child's granter identity is already loaded + sig-verified
                    // above; resolve the parent's from `included`. Multi-sig
                    // granter (root-only per M3) is locally-rooted → local frame.
                    let child_granter_peer_id = granter_identity
                        .canonical_peer_id()
                        .unwrap_or_else(|| local_peer_id.to_string());
                    let parent_granter_peer_id = match &parent_fields.granter {
                        Granter::Single(parent_granter_id) => {
                            let pe = included.get(parent_granter_id).ok_or(
                                ProtocolError::MissingEntity("parent granter identity"),
                            )?;
                            PeerData::from_entity(pe)
                                .map_err(|e| ProtocolError::Invalid(e.to_string()))?
                                .canonical_peer_id()
                                .unwrap_or_else(|| local_peer_id.to_string())
                        }
                        Granter::Multi(_) => local_peer_id.to_string(),
                    };

                    if !entity_capability::is_attenuated_framed(
                        &child_token,
                        &parent_token,
                        &child_granter_peer_id,
                        &parent_granter_peer_id,
                        local_peer_id,
                    ) {
                        return Err(ProtocolError::AttenuationViolation);
                    }
                    // Delegation caveats (V7 §5.7, pseudocode line 2290):
                    // enforce the parent's no_delegation / max_delegation_depth
                    // / max_delegation_ttl against this direct child. `depth`
                    // is the child's leaf-distance index `i`, matching the
                    // spec's `check_delegation_caveats(parent, current, i)`.
                    if !entity_capability::check_delegation_caveats(
                        &parent_token,
                        &child_token,
                        i as u64,
                    ) {
                        return Err(ProtocolError::CapabilityInvalid(
                            "delegation caveat violated".into(),
                        ));
                    }
                } else {
                    // Single-sig root: granter must be local peer (V7 §5.5).
                    // V7 §1.5 v7.65: derive canonical peer_id from
                    // (public_key, key_type) — entity no longer carries it.
                    let granter_peer_id = match granter_identity.canonical_peer_id() {
                        Some(p) => p,
                        None => return Err(ProtocolError::NotLocalPeer),
                    };
                    if granter_peer_id != local_peer_id {
                        return Err(ProtocolError::NotLocalPeer);
                    }
                }
            }

            // ---------- Multi-sig path (M4 + M6) ----------
            //
            // By the M3 pass above, multi-sig only appears at the root
            // (i == chain.len() - 1, parent: None). M4 and M6 collapse here:
            // both fire at the same chain position and share the same scan
            // over `signers`. The loop verifies K signatures (M4) and tracks
            // whether the local peer was among the validated signers (M6).
            //
            // Identity-hash-based, not identity-status-based (M11): we consult
            // only included signatures and the cap's `signers` identity hashes.
            // Constituent revocation status is NOT checked at the core layer.
            Granter::Multi(multi) => {
                let mut seen: Vec<Hash> = Vec::with_capacity(multi.signers.len());
                let mut valid: u64 = 0;
                let mut local_peer_signed = false;
                for candidate in &multi.signers {
                    if seen.iter().any(|h| h == candidate) {
                        continue; // defensive: dedupe (M3 already rejected dupes)
                    }
                    seen.push(*candidate);

                    let candidate_identity_entity = match included.get(candidate) {
                        Some(e) => e,
                        None => continue,
                    };
                    let candidate_identity = match PeerData::from_entity(
                        candidate_identity_entity,
                    ) {
                        Ok(i) => i,
                        Err(_) => continue,
                    };
                    let sig = match entity_entity::find_signature_by_signer(
                        included.values(),
                        &current_hash,
                        candidate,
                    ) {
                        Some(s) => s,
                        None => continue,
                    };
                    let sig_data = match SignatureData::from_entity(sig) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    if !peer_data_sig_ok(
                        &candidate_identity,
                        &current_hash.to_bytes(),
                        &sig_data.signature,
                    ) {
                        continue;
                    }
                    valid += 1;
                    // V7 §1.5 v7.65: derive canonical peer_id for local-
                    // peer-signed comparison; entity no longer carries it.
                    if candidate_identity
                        .canonical_peer_id()
                        .as_deref()
                        == Some(local_peer_id)
                    {
                        local_peer_signed = true;
                    }
                }
                if valid < multi.threshold {
                    return Err(ProtocolError::InvalidSignature);
                }
                // M6 root-trust: local peer must be in `signers` AND have signed.
                if !local_peer_signed {
                    return Err(ProtocolError::NotLocalPeer);
                }
                // Multi-sig is root-only (M3) — no chain-linkage check at this
                // position.
            }
        }
    }

    Ok(())
}


// ---------------------------------------------------------------------------
// EXECUTE field decoding
// ---------------------------------------------------------------------------

pub(crate) struct ExecuteFields {
    pub request_id: String,
    pub uri: String,
    pub operation: String,
    pub author: Option<Hash>,
    pub capability: Option<Hash>,
}

pub(crate) fn decode_execute_fields(data: &[u8]) -> Result<ExecuteFields, ProtocolError> {
    let value: ciborium::Value =
        ciborium::from_reader(data).map_err(|e| ProtocolError::Invalid(e.to_string()))?;
    let map = value
        .as_map()
        .ok_or_else(|| ProtocolError::Invalid("execute data must be a map".into()))?;

    let mut request_id = None;
    let mut uri = None;
    let mut operation = None;
    let mut author = None;
    let mut capability = None;

    for (k, v) in map {
        match k.as_text() {
            Some("request_id") => request_id = v.as_text().map(|s| s.to_string()),
            Some("uri") => uri = v.as_text().map(|s| s.to_string()),
            Some("operation") => operation = v.as_text().map(|s| s.to_string()),
            Some("author") => {
                if let Some(b) = v.as_bytes() {
                    author = Hash::from_bytes(b).ok();
                }
            }
            Some("capability") => {
                if let Some(b) = v.as_bytes() {
                    capability = Hash::from_bytes(b).ok();
                }
            }
            _ => {}
        }
    }

    Ok(ExecuteFields {
        request_id: request_id
            .ok_or(ProtocolError::MissingField("request_id"))?,
        uri: uri.ok_or(ProtocolError::MissingField("uri"))?,
        operation: operation
            .ok_or(ProtocolError::MissingField("operation"))?,
        author,
        capability,
    })
}

/// Lightweight projection of a capability entity — the three fields needed
/// for chain-walk reachability and per-link delegation checks. Decoded once
/// during `collect_authority_chain` and threaded through to consumers so we
/// don't re-decode the same CBOR map twice (or N+1 times for an N-link chain).
///
/// `granter` is polymorphic per PROPOSAL-MULTISIG-CORE-PRIMITIVE M1: either a
/// single identity hash or a multi-sig granter struct.
#[derive(Debug, Clone)]
pub struct CapabilityChainFields {
    pub granter: Granter,
    pub grantee: Hash,
    pub parent: Option<Hash>,
    /// Temporal validity bounds, decoded per-link so the chain walk can
    /// enforce them on every cap (V7 §5.5), not just the leaf.
    pub not_before: Option<u64>,
    pub expires_at: Option<u64>,
}

pub(crate) fn decode_capability_chain_fields(data: &[u8]) -> Result<CapabilityChainFields, ProtocolError> {
    let value: ciborium::Value =
        ciborium::from_reader(data).map_err(|e| ProtocolError::Invalid(e.to_string()))?;
    let map = value
        .as_map()
        .ok_or_else(|| ProtocolError::Invalid("capability data must be a map".into()))?;

    let mut granter = None;
    let mut grantee = None;
    let mut parent = None;
    let mut not_before = None;
    let mut expires_at = None;

    for (k, v) in map {
        match k.as_text() {
            Some("granter") => {
                granter = Some(
                    entity_capability::decode_granter(v)
                        .map_err(|e| ProtocolError::Invalid(e.to_string()))?,
                );
            }
            Some("grantee") => {
                if let Some(b) = v.as_bytes() {
                    grantee = Hash::from_bytes(b).ok();
                }
            }
            Some("parent") => {
                if let Some(b) = v.as_bytes() {
                    parent = Hash::from_bytes(b).ok();
                }
            }
            Some("not_before") => {
                not_before = v.as_integer().and_then(|i| u64::try_from(i).ok());
            }
            Some("expires_at") => {
                expires_at = v.as_integer().and_then(|i| u64::try_from(i).ok());
            }
            _ => {}
        }
    }

    Ok(CapabilityChainFields {
        granter: granter
            .ok_or(ProtocolError::MissingField("granter"))?,
        grantee: grantee
            .ok_or(ProtocolError::MissingField("grantee"))?,
        parent,
        not_before,
        expires_at,
    })
}
