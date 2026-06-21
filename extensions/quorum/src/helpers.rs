//! K-of-N validation + signer-set resolution + `is_quorum_id`
//! (EXTENSION-QUORUM v1.0 §4).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use entity_attestation::{
    find_attestations_targeting, find_live_head, AttestationCtx, AttestationData,
    AttestationIndex,
};
use entity_crypto::Keypair;
use entity_entity::{find_signature_by_signer, Entity, TYPE_SIGNATURE};
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};
use entity_types::{SignatureData, TYPE_QUORUM};

use crate::cache::{SignerSet, SignerSetCache};
use crate::data::{hex_segment, path_quorum, QuorumData};
use crate::resolver::{ResolverContext, ResolverError, ResolverRegistry, MAX_RESOLVER_DEPTH};
use crate::{QuorumError, KIND_QUORUM_UPDATE, RESOLUTION_CONCRETE};

/// Quorum-helper context bundle. Wraps the attestation primitive's
/// context plus quorum-specific dependencies (resolver registry, signer
/// set cache).
pub struct QuorumCtx<'a> {
    pub attestation_index: &'a AttestationIndex,
    pub content_store: &'a Arc<dyn ContentStore>,
    pub location_index: &'a Arc<dyn LocationIndex>,
    pub included: &'a HashMap<Hash, Entity>,
    pub resolver_registry: &'a ResolverRegistry,
    pub signer_set_cache: &'a SignerSetCache,
}

impl<'a> QuorumCtx<'a> {
    pub fn attestation_ctx(&self) -> AttestationCtx<'a> {
        AttestationCtx {
            index: self.attestation_index,
            content_store: self.content_store,
            location_index: self.location_index,
            included: self.included,
        }
    }
}

// ===========================================================================
// §4.3 is_quorum_id — path-based lookup
// ===========================================================================

/// Returns `true` iff `hash` refers to a `system/quorum` entity at the
/// canonical path `system/quorum/{hex(hash)}` on the local tree (per §4.3).
///
/// The lookup is path-based (not content-store-only): a quorum is "known"
/// only when bound at its canonical path. Stateless — re-evaluates per
/// call (per §4.3 race semantics during bootstrap / sync catch-up).
pub fn is_quorum_id(hash: &Hash, ctx: &QuorumCtx) -> bool {
    // Path is peer-relative per spec. Caller's tree convention may include
    // a `/{peer_id}/` prefix; we walk all paths matching the peer-relative
    // suffix to satisfy the local-peer scope.
    let suffix = path_quorum(hash);
    for entry in ctx.location_index.list("/") {
        if entry.path.ends_with(&suffix) || entry.path == suffix {
            let entity = match ctx.content_store.get(&entry.hash) {
                Some(e) => e,
                None => continue,
            };
            if entity.entity_type == TYPE_QUORUM {
                return true;
            }
        }
    }
    false
}

// ===========================================================================
// §4.2 current_signer_set — walk quorum-update chain
// ===========================================================================

/// Walk the live `quorum-update` chain for `quorum_id` and return the
/// effective `(signers, threshold)`. Cached per §4.2.1.
///
/// Per spec v1.1 §4.2 (SI-16): `as_of` = `None` returns current state;
/// `as_of = Some(t)` returns the historical state live at `t`.
///
/// Cache is keyed only on `quorum_id`; historical (`as_of`) lookups
/// bypass the cache.
pub fn current_signer_set(
    quorum_id: &Hash,
    ctx: &QuorumCtx,
) -> Result<SignerSet, QuorumError> {
    current_signer_set_as_of(quorum_id, None, ctx)
}

/// `current_signer_set` with an explicit `as_of` parameter for
/// historical-state resolution (per spec v1.1 §4.2 / SI-16).
pub fn current_signer_set_as_of(
    quorum_id: &Hash,
    as_of: Option<u64>,
    ctx: &QuorumCtx,
) -> Result<SignerSet, QuorumError> {
    // Cache hit → return immediately (only for current state, NOT for as_of).
    if as_of.is_none() {
        if let Some(cached) = ctx.signer_set_cache.get(quorum_id) {
            return Ok(cached);
        }
    }

    // Load the quorum entity.
    let quorum = load_quorum(quorum_id, ctx)?;

    // Walk for the live (per as_of) head of the quorum-update chain.
    let (mut signers, mut threshold) = (quorum.signers.clone(), quorum.threshold);
    let actx = ctx.attestation_ctx();
    let updates = find_attestations_targeting(
        quorum_id,
        |a| a.kind() == Some(KIND_QUORUM_UPDATE),
        &actx,
    );
    if !updates.is_empty() {
        let supersedes_set: HashSet<Hash> =
            updates.iter().filter_map(|(_, a)| a.supersedes).collect();
        let chain_heads: Vec<&(Hash, AttestationData)> = updates
            .iter()
            .filter(|(h, _)| !supersedes_set.contains(h))
            .collect();
        // Among chain heads, pick the live one (per find_live_head with as_of).
        for (h, a) in &chain_heads {
            // Walk forward through the chain to find the head live at as_of.
            // find_live_head doesn't currently take as_of (that's a follow-up
            // amendment), so we walk the chain ourselves filtering by not_before
            // <= as_of when as_of is set.
            if let Some(head) = find_quorum_update_head_at(h, a, as_of, &actx) {
                if let Some(new_signers) = quorum_update_signers(&head) {
                    signers = new_signers;
                }
                if let Some(new_threshold) = quorum_update_threshold(&head) {
                    threshold = new_threshold;
                }
                break;
            }
        }
    }

    // Resolution-mode dispatch (§5).
    let mode = quorum.resolution_mode();
    if mode != RESOLUTION_CONCRETE {
        let resolver = ctx.resolver_registry.lookup(mode).ok_or_else(|| {
            QuorumError::ResolverUnavailable {
                quorum_id_hex: hex_segment(quorum_id),
                mode_name: mode.to_string(),
                available_modes: ctx.resolver_registry.available_modes(),
            }
        })?;
        let mut visited: HashSet<Hash> = HashSet::new();
        let mut resolved = Vec::with_capacity(signers.len());
        for s in &signers {
            let mut rctx = ResolverContext {
                content_store: ctx.content_store,
                location_index: ctx.location_index,
                as_of,
                depth: 0,
                visited: &mut visited,
            };
            match resolver(s, &mut rctx) {
                Ok(r) => resolved.push(r),
                Err(ResolverError::MaxDepthExceeded(_)) => {
                    return Err(QuorumError::ResolverDepthExceeded {
                        quorum_id_hex: hex_segment(quorum_id),
                        max_depth: MAX_RESOLVER_DEPTH,
                    });
                }
                Err(ResolverError::Cycle(h)) => {
                    return Err(QuorumError::ResolverCycle {
                        quorum_id_hex: hex_segment(quorum_id),
                        cycle_at_hex: hex_segment(&h),
                    });
                }
                Err(ResolverError::Unresolved) => {
                    return Err(QuorumError::ResolverUnavailable {
                        quorum_id_hex: hex_segment(quorum_id),
                        mode_name: format!("{} (resolver returned unresolved for signer)", mode),
                        available_modes: ctx.resolver_registry.available_modes(),
                    });
                }
            }
        }
        signers = resolved;
    }

    let set = SignerSet { signers, threshold };
    if as_of.is_none() {
        ctx.signer_set_cache.put(*quorum_id, set.clone());
    }
    Ok(set)
}

/// Walk the supersedes chain backward from `start` (chain head) to find
/// the head that is live at `as_of` (or now). For `as_of = None`,
/// delegates to substrate's `find_live_head`. For `as_of = Some(t)`,
/// finds the entry whose `not_before <= t` and whose direct supersedes
/// successor is NOT also live at `t` — i.e., the live head from t's
/// perspective.
fn find_quorum_update_head_at(
    start_hash: &Hash,
    start: &AttestationData,
    as_of: Option<u64>,
    actx: &entity_attestation::AttestationCtx,
) -> Option<AttestationData> {
    if as_of.is_none() {
        // Current-state head — delegate to substrate.
        return find_live_head(start_hash, start, actx).map(|(_, a)| a);
    }
    let t = as_of.unwrap();
    // Walk backward from the chain head (`start`) following `supersedes`.
    // The first entry whose `not_before <= t` is the live head at `t`.
    let _ = start_hash;
    let mut current = start.clone();
    loop {
        let nb_ok = current.not_before.map(|nb| nb <= t).unwrap_or(true);
        let exp_ok = current.expires_at.map(|exp| t < exp).unwrap_or(true);
        if nb_ok && exp_ok {
            return Some(current);
        }
        // Walk back via supersedes pointer.
        let prev_hash = match current.supersedes {
            Some(h) => h,
            None => return None, // ran off the start; no entry valid at t
        };
        let prev = match actx.index.get(&prev_hash) {
            Some(p) => p,
            None => return None,
        };
        current = prev;
    }
}

fn quorum_update_signers(att: &AttestationData) -> Option<Vec<Hash>> {
    // properties: { kind: "quorum-update", new_signers: [..], new_threshold: K }
    let v = att.properties.iter().find_map(|(k, v)| {
        if k.as_text() == Some("new_signers") {
            Some(v)
        } else {
            None
        }
    })?;
    let arr = v.as_array()?;
    let mut hs = Vec::with_capacity(arr.len());
    for item in arr {
        let bytes = item.as_bytes()?;
        hs.push(Hash::from_bytes(bytes).ok()?);
    }
    Some(hs)
}

fn quorum_update_threshold(att: &AttestationData) -> Option<u64> {
    let v = att.properties.iter().find_map(|(k, v)| {
        if k.as_text() == Some("new_threshold") {
            Some(v)
        } else {
            None
        }
    })?;
    let i = v.as_integer()?;
    let n: i128 = i.into();
    if n < 0 {
        return None;
    }
    Some(n as u64)
}

fn load_quorum(quorum_id: &Hash, ctx: &QuorumCtx) -> Result<QuorumData, QuorumError> {
    // Per the cross-impl ACME ruling R-7' (Round-6): we walk all paths
    // matching the suffix and CONTINUE on type mismatch / decode failure
    // instead of returning the first hit. The history engine writes
    // transitions at `/{peer}/system/history/head{event.path}` — when
    // event.path is `/{peer}/system/quorum/{q_hex}`, the resulting
    // transition path ends with `system/quorum/{q_hex}` and shadows the
    // real quorum binding (BTreeMap sort order: h < q). Tolerating type
    // mismatch on intermediate matches restores the lookup. Same pattern
    // already used by `is_quorum_id` (line 55) and the substrate's
    // `find_signature*` lookups; `load_quorum` was the only remaining
    // first-hit-or-bust scan.
    let suffix = path_quorum(quorum_id);
    for entry in ctx.location_index.list("/") {
        if !(entry.path.ends_with(&suffix) || entry.path == suffix) {
            continue;
        }
        let entity = match ctx.content_store.get(&entry.hash) {
            Some(e) => e,
            None => continue, // dangling — skip
        };
        if entity.entity_type != TYPE_QUORUM {
            continue; // sibling/parent path coincidence (e.g., history transition)
        }
        return QuorumData::from_entity(&entity);
    }
    Err(QuorumError::Invalid(format!(
        "quorum_not_found: {}",
        hex_segment(quorum_id)
    )))
}

// ===========================================================================
// §4.1 verify_k_of_n_signatures
// ===========================================================================

/// K-of-N validation over an entity. Returns `true` once `threshold` valid
/// signatures by distinct signers in `signer_set` are counted.
pub fn verify_k_of_n_signatures(
    entity_hash: &Hash,
    signer_set: &[Hash],
    threshold: u64,
    ctx: &QuorumCtx,
) -> bool {
    if threshold == 0 {
        return true;
    }
    let mut signed: HashSet<Hash> = HashSet::new();
    for candidate in signer_set {
        if signed.contains(candidate) {
            continue;
        }
        let sig = match find_signature(entity_hash, candidate, ctx) {
            Some(s) => s,
            None => continue,
        };
        let public_key = match resolve_peer(candidate, ctx.content_store) {
            Some(pk) => pk,
            None => continue,
        };
        if Keypair::verify(&public_key, &entity_hash.to_bytes(), &sig.signature).is_ok() {
            signed.insert(*candidate);
            if signed.len() as u64 >= threshold {
                return true;
            }
        }
    }
    signed.len() as u64 >= threshold
}

fn find_signature(target: &Hash, signer: &Hash, ctx: &QuorumCtx) -> Option<SignatureData> {
    if let Some(entity) = find_signature_by_signer(ctx.included.values(), target, signer) {
        if let Ok(sig) = SignatureData::from_entity(entity) {
            return Some(sig);
        }
    }
    let suffix = format!("system/signature/{}", hex_segment(target));
    for entry in ctx.location_index.list("/") {
        if !entry.path.ends_with(&suffix) {
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
