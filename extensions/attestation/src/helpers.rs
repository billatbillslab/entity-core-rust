//! Validation helpers + graph operations
//! (EXTENSION-ATTESTATION v1.0 §4, §5).
//!
//! All helpers are pure functions taking `&AttestationCtx`. The substrate
//! primitive does not maintain state beyond the in-memory `AttestationIndex`.

use std::collections::HashMap;
use std::sync::Arc;

use entity_crypto::Keypair;
use entity_entity::{find_signature_by_signer, Entity, TYPE_SIGNATURE};
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};
use entity_types::SignatureData;

use crate::data::{hex_segment, AttestationData};
use crate::index::AttestationIndex;
use crate::{KIND_REVOCATION, DEFAULT_MAX_DEPTH};

/// Context for attestation helpers (§4 / §5 `ctx` parameter).
///
/// Carries the in-memory index + the underlying content/location stores
/// for signature and identity resolution. `included` is the in-flight
/// envelope-bundled entity map (per V7 envelope semantics) — checked in
/// addition to tree-resident signatures so single-peer ceremonies and
/// cross-peer sync arrivals produce identical post-state (per
/// EXTENSION-IDENTITY §6.2).
pub struct AttestationCtx<'a> {
    pub index: &'a AttestationIndex,
    pub content_store: &'a Arc<dyn ContentStore>,
    pub location_index: &'a Arc<dyn LocationIndex>,
    pub included: &'a HashMap<Hash, Entity>,
}

// ===========================================================================
// §4.1 verify_attestation_signature — single-sig validation
// ===========================================================================

/// Validate that `att` is signed by `att.attesting` (default single-sig
/// validator per §4.1). Returns `false` if the signature is missing,
/// malformed, or invalid.
pub fn verify_attestation_signature(
    att_hash: &Hash,
    att: &AttestationData,
    ctx: &AttestationCtx,
) -> bool {
    verify_specific_signer(att_hash, att, &att.attesting, ctx)
}

// ===========================================================================
// §4.2 verify_specific_signer — verify a named signer signed
// ===========================================================================

/// Verify `att` carries a valid signature from `expected_signer` specifically
/// (per §4.2). Used by consumers composing multi-sig topologies on top of the
/// primitive (e.g., identity dual-sig, quorum K-of-N).
pub fn verify_specific_signer(
    att_hash: &Hash,
    _att: &AttestationData,
    expected_signer: &Hash,
    ctx: &AttestationCtx,
) -> bool {
    let sig = match find_signature_for(att_hash, expected_signer, ctx) {
        Some(s) => s,
        None => return false,
    };
    let public_key = match resolve_peer(expected_signer, ctx.content_store) {
        Some(pk) => pk,
        None => return false,
    };
    Keypair::verify(&public_key, &att_hash.to_bytes(), &sig.signature).is_ok()
}

/// Locate a signature targeting `target` from `signer`. Two-phase lookup:
/// (1) `included` map (in-flight via envelope, per EXTENSION-IDENTITY §6.2);
/// (2) tree-resident at the V7 invariant pointer path
/// `{signer_peer_id}/system/signature/{target_hex}`.
fn find_signature_for(
    target: &Hash,
    signer: &Hash,
    ctx: &AttestationCtx,
) -> Option<SignatureData> {
    if let Some(entity) = find_signature_by_signer(ctx.included.values(), target, signer) {
        if let Ok(sig) = SignatureData::from_entity(entity) {
            return Some(sig);
        }
    }
    // Tree-resident lookup at the invariant pointer path.
    // Identity hash format: the `signer` peer ID is derived from the identity
    // entity hash; its tree paths are keyed by the Base58 `peer_id` string
    // (see EntityUri). We don't have the identity→peer_id mapping at this
    // layer; instead, scan all signature entities targeting `target` and
    // match by signer field in the SignatureData. This is functionally
    // equivalent and avoids cross-crate dependencies on the protocol layer.
    let prefix_suffix = format!("system/signature/{}", hex_segment(target));
    for entry in ctx.location_index.list("/") {
        if !entry.path.ends_with(&prefix_suffix) {
            continue;
        }
        let entity = match ctx.content_store.get(&entry.hash) {
            Some(e) => e,
            None => continue,
        };
        if entity.entity_type != TYPE_SIGNATURE {
            continue;
        }
        let sig = match SignatureData::from_entity(&entity) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if &sig.target == target && &sig.signer == signer {
            return Some(sig);
        }
    }
    None
}

/// PR-2 (PROPOSAL-SYSTEM-PEER-RENAME): renamed from `resolve_peer_pubkey`.
/// Spec contract `resolve_peer(peer_hash, ctx) → peer_entity` is at the
/// substrate level (EXTENSION-ATTESTATION §4.0). This is a private helper
/// that fuses entity lookup + pubkey extraction.
fn resolve_peer(
    peer_hash: &Hash,
    content_store: &Arc<dyn ContentStore>,
) -> Option<[u8; 32]> {
    let entity = content_store.get(peer_hash)?;
    if entity.entity_type != entity_crypto::TYPE_PEER {
        return None;
    }
    let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).ok()?;
    let map = value.as_map()?;
    let pk_bytes = map.iter().find_map(|(k, v)| {
        if k.as_text() == Some("public_key") {
            v.as_bytes()
        } else {
            None
        }
    })?;
    pk_bytes.as_slice().try_into().ok()
}

// ===========================================================================
// §4.3 is_attestation_live — composite liveness
// ===========================================================================

/// Composite liveness check (§4.3): not expired; not superseded; not
/// self-revoked. `as_of` defaults to current epoch ms.
///
/// **Spec ambiguity (logged in `docs/SPEC-AMBIGUITIES.md`).** §4.3's
/// pseudocode reads only DIRECT supersedes successors, but TV-A4 requires
/// transitive walking (otherwise A stays "live" when A' is dead even
/// though A'' is alive further down the chain). This impl walks the
/// supersedes chain forward transitively to satisfy TV-A4's intent —
/// "all live ... → A'' (live head)" demands transitive semantics.
///
/// Note (§4.3): self-revocation only — authority-revocation (where a
/// non-self peer revokes) is consumer-specific and applied via
/// `find_revocations_for` plus the consumer's authority predicate.
pub fn is_attestation_live(
    att_hash: &Hash,
    att: &AttestationData,
    ctx: &AttestationCtx,
    as_of: Option<u64>,
) -> bool {
    let now = as_of.unwrap_or_else(now_epoch_ms);
    if !is_self_valid_basic(att, now) {
        return false;
    }
    // Self-revocation check (recursive, but each rev has its own chain)
    let revs = find_revocations_for(att_hash, ctx);
    for (r_hash, r) in &revs {
        if r.attesting == att.attesting && is_attestation_live(r_hash, r, ctx, Some(now)) {
            return false;
        }
    }
    // Forward supersedes walk — transitive (per TV-A4 intent).
    if has_valid_descendant(att_hash, ctx, now) {
        return false;
    }
    true
}

/// Self-validity check WITHOUT recursing into supersedes-chain. Used by
/// the transitive forward-walk to avoid recursion blow-up.
fn is_self_valid_basic(att: &AttestationData, now: u64) -> bool {
    if let Some(exp) = att.expires_at {
        if now >= exp {
            return false;
        }
    }
    if let Some(nb) = att.not_before {
        if now < nb {
            return false;
        }
    }
    true
}

/// Walk forward through the supersedes graph from `att_hash`. Return true
/// iff any reachable descendant is self-valid AND not self-revoked.
///
/// "Self-revoked" check uses the full `is_attestation_live` recursion on
/// the revocation entry — fine because revocations don't normally form
/// chains.
fn has_valid_descendant(att_hash: &Hash, ctx: &AttestationCtx, now: u64) -> bool {
    use std::collections::HashSet;
    let mut stack: Vec<Hash> = vec![*att_hash];
    let mut visited: HashSet<Hash> = HashSet::new();
    while let Some(h) = stack.pop() {
        if !visited.insert(h) {
            continue;
        }
        for (dh, d) in find_attestations_with_supersedes(&h, ctx) {
            if is_self_valid_basic(&d, now) {
                let revs = find_revocations_for(&dh, ctx);
                let revoked = revs.iter().any(|(rh, r)| {
                    r.attesting == d.attesting
                        && is_attestation_live(rh, r, ctx, Some(now))
                });
                if !revoked {
                    return true;
                }
            }
            stack.push(dh);
        }
    }
    false
}

fn now_epoch_ms() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ===========================================================================
// §5 graph operations
// ===========================================================================

/// §5.2 — Walk supersedes chain back to the original (oldest) attestation.
/// Returns `[start, prev, prev_prev, ..., original]`. Broken chains return
/// what was found.
pub fn walk_supersedes_chain(
    start_hash: &Hash,
    start: &AttestationData,
    ctx: &AttestationCtx,
) -> Vec<(Hash, AttestationData)> {
    let mut chain = vec![(*start_hash, start.clone())];
    let mut current_super = start.supersedes;
    while let Some(prev) = current_super {
        let Some(prev_att) = ctx.index.get(&prev) else {
            break;
        };
        current_super = prev_att.supersedes;
        chain.push((prev, prev_att));
    }
    chain
}

/// §5.3 — Walk supersedes chain FORWARD to find the current live head.
/// Returns the live head of the chain, or `None` if no link in the chain
/// (including `start` itself) is live.
///
/// Walks ALL successors (live or dead) — intermediate dead links are
/// transparent. This matches TV-A4's intent that find_live_head from any
/// link in the chain reaches the head, even if intermediates are
/// superseded.
pub fn find_live_head(
    start_hash: &Hash,
    start: &AttestationData,
    ctx: &AttestationCtx,
) -> Option<(Hash, AttestationData)> {
    use std::collections::HashSet;
    let mut visited: HashSet<Hash> = HashSet::new();
    let mut best: Option<(Hash, AttestationData)> = None;
    let mut stack: Vec<(Hash, AttestationData)> = vec![(*start_hash, start.clone())];
    while let Some((h, a)) = stack.pop() {
        if !visited.insert(h) {
            continue;
        }
        if is_attestation_live(&h, &a, ctx, None) {
            best = match best {
                None => Some((h, a.clone())),
                Some((bh, ba)) => {
                    // Tie-break: prefer higher not_before, then lower
                    // content_hash for determinism.
                    let cmp = a
                        .not_before
                        .unwrap_or(0)
                        .cmp(&ba.not_before.unwrap_or(0))
                        .then_with(|| bh.cmp(&h));
                    if cmp.is_gt() {
                        Some((h, a.clone()))
                    } else {
                        Some((bh, ba))
                    }
                }
            };
        }
        for (dh, d) in find_attestations_with_supersedes(&h, ctx) {
            stack.push((dh, d));
        }
    }
    best
}

/// §5.4 — All attestations targeting `entity_hash`, filtered by `predicate`.
pub fn find_attestations_targeting<F>(
    entity_hash: &Hash,
    predicate: F,
    ctx: &AttestationCtx,
) -> Vec<(Hash, AttestationData)>
where
    F: Fn(&AttestationData) -> bool,
{
    let hashes = ctx.index.lookup_by_attested(entity_hash);
    hashes
        .into_iter()
        .filter_map(|h| ctx.index.get(&h).map(|a| (h, a)))
        .filter(|(_, a)| predicate(a))
        .collect()
}

/// §5.5 — All attestations whose `attesting` equals `peer_hash`.
pub fn find_attestations_by<F>(
    peer_hash: &Hash,
    predicate: F,
    ctx: &AttestationCtx,
) -> Vec<(Hash, AttestationData)>
where
    F: Fn(&AttestationData) -> bool,
{
    let hashes = ctx.index.lookup_by_attesting(peer_hash);
    hashes
        .into_iter()
        .filter_map(|h| ctx.index.get(&h).map(|a| (h, a)))
        .filter(|(_, a)| predicate(a))
        .collect()
}

/// §5.6 — All revocation attestations targeting `attestation_hash`.
/// Convenience over `find_attestations_targeting` for the common case.
pub fn find_revocations_for(
    attestation_hash: &Hash,
    ctx: &AttestationCtx,
) -> Vec<(Hash, AttestationData)> {
    find_attestations_targeting(
        attestation_hash,
        |a| a.kind() == Some(KIND_REVOCATION),
        ctx,
    )
}

/// §5.6a — All attestations whose `supersedes` field equals `predecessor`.
pub fn find_attestations_with_supersedes(
    predecessor: &Hash,
    ctx: &AttestationCtx,
) -> Vec<(Hash, AttestationData)> {
    ctx.index
        .lookup_by_supersedes(predecessor)
        .into_iter()
        .filter_map(|h| ctx.index.get(&h).map(|a| (h, a)))
        .collect()
}

/// §5.6b — All attestations with `properties.kind == kind_value`.
pub fn find_attestations_with_kind(
    kind_value: &str,
    ctx: &AttestationCtx,
) -> Vec<(Hash, AttestationData)> {
    ctx.index
        .lookup_by_kind(kind_value)
        .into_iter()
        .filter_map(|h| ctx.index.get(&h).map(|a| (h, a)))
        .collect()
}

// ===========================================================================
// §5.1 default_find_authorizing — normative algorithm
// ===========================================================================

/// Normative `default_find_authorizing` per §5.1. Implementations MUST
/// produce identical results across impls (TV-A1 through TV-A11).
///
/// Algorithm:
/// 1. Find all attestations where `attested == peer_hash`.
/// 2. Filter to live (per `is_attestation_live`).
/// 3. Resolve each to its live head (per `find_live_head`).
/// 4. Single live head → return it.
/// 5. Multiple distinct live heads → tie-break by lowest `content_hash`.
pub fn default_find_authorizing(
    peer_hash: &Hash,
    ctx: &AttestationCtx,
) -> Option<(Hash, AttestationData)> {
    let candidates = find_attestations_targeting(peer_hash, |_| true, ctx);
    let live: Vec<_> = candidates
        .into_iter()
        .filter(|(h, a)| is_attestation_live(h, a, ctx, None))
        .collect();
    if live.is_empty() {
        return None;
    }
    let mut heads: Vec<(Hash, AttestationData)> = Vec::new();
    for (h, a) in &live {
        if let Some(head) = find_live_head(h, a, ctx) {
            if !heads.iter().any(|(hh, _)| hh == &head.0) {
                heads.push(head);
            }
        }
    }
    if heads.is_empty() {
        return None;
    }
    if heads.len() == 1 {
        return heads.into_iter().next();
    }
    heads.into_iter().min_by_key(|(h, _)| *h)
}

// ===========================================================================
// §5.1 walk_attesting_chain — parameterized chain walk
// ===========================================================================

/// Walk attesting back to the first attestation matching `terminate`. Returns
/// `Some(chain)` (start → ... → terminating link) or `None` if no chain
/// terminates within `max_depth`.
///
/// Default `find_authorizing` is `default_find_authorizing` (per §5.1
/// normative). Consumers MAY supply their own for non-standard graphs
/// (e.g., per the multi-context-peers note).
pub fn walk_attesting_chain<T, A>(
    start_hash: &Hash,
    start: &AttestationData,
    terminate: T,
    find_authorizing: Option<A>,
    max_depth: usize,
    ctx: &AttestationCtx,
) -> Option<Vec<(Hash, AttestationData)>>
where
    T: Fn(&AttestationData, &AttestationCtx) -> bool,
    A: Fn(&Hash, &AttestationCtx) -> Option<(Hash, AttestationData)>,
{
    let mut chain: Vec<(Hash, AttestationData)> = vec![(*start_hash, start.clone())];
    let mut current = start.clone();
    let mut depth = 0;
    while depth < max_depth {
        if terminate(&current, ctx) {
            return Some(chain);
        }
        let parent_opt = match &find_authorizing {
            Some(f) => f(&current.attesting, ctx),
            None => default_find_authorizing(&current.attesting, ctx),
        };
        let (p_hash, p) = parent_opt?;
        chain.push((p_hash, p.clone()));
        current = p;
        depth += 1;
    }
    None
}

/// Convenience: max_depth defaults to `DEFAULT_MAX_DEPTH` (32) and
/// `find_authorizing` defaults to `default_find_authorizing`.
pub fn walk_attesting_chain_default<T>(
    start_hash: &Hash,
    start: &AttestationData,
    terminate: T,
    ctx: &AttestationCtx,
) -> Option<Vec<(Hash, AttestationData)>>
where
    T: Fn(&AttestationData, &AttestationCtx) -> bool,
{
    walk_attesting_chain::<T, fn(&Hash, &AttestationCtx) -> Option<(Hash, AttestationData)>>(
        start_hash,
        start,
        terminate,
        None,
        DEFAULT_MAX_DEPTH,
        ctx,
    )
}
