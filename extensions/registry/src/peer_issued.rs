//! Peer-issued backend (PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND).
//!
//! The twin of [`crate::local_name`], with a different **trust source**: a
//! pinned *remote* registry key instead of *local* authority. The backend is
//! **pure trust logic over transport-agnostic reads** — it reads a registry
//! peer's bindings with the ordinary `tree:get` / `content:get` machinery and
//! **does not know or care** whether that peer is reached over http-poll (a
//! static coral-reef) or a live socket (NETWORK §6.5 decides the wire).
//!
//! For the v1 demo the reads resolve against the **local store** — the
//! offline / precede path (proposal §2.2): the registry's bindings are cached
//! locally (shipped or pre-fetched), stored under the *registry's* namespace
//! `/{registry}/system/registry/binding/…`. The live remote-read seam (fetch
//! the registry peer's tree on a cache miss) is a `core/peer`/SDK concern that
//! populates this store; it is not part of the extension (see
//! `docs/archive/SPEC-PROBLEMS-PEER-ISSUED-REGISTRY.md`).
//!
//! The only registry-specific substance is step 3 of [`resolve_one`]:
//! signature-verify the binding against the **pinned** registry key
//! (`pinned_key_of(registry)` — materialized per spec-problems doc **P1**:
//! the signer's identity entity must derive to the configured registry peer-id).

use std::sync::Arc;

use entity_ecf::Value;
use entity_store::{ContentStore, LocationIndex};
use entity_hash::Hash;
use entity_types::SignatureData;

use crate::data::{
    normalize_name, BindingData, ResolutionResult, RevocationData, STATUS_RESOLVED,
    TRUST_PEER_ISSUED_PREFIX,
};
use crate::log::now_ms;
use crate::resolver::resolve_peer_pubkey;
use crate::{
    by_name_pointer_path, revocation_prefix, signature_pointer_path, ResolverChainEntry,
};

/// Backend resolve (proposal §2.1) — invoked by the meta-resolver for
/// `peer-issued` chain entries. `entry.backend_id` is the registry's Base58
/// peer-id (the pinned trust root + the namespace its bindings live under).
///
/// Returns:
/// - `Some(resolved)` on a verified, unrevoked, unexpired binding;
/// - `Some(not_found)` when the by-name pointer is absent (proposal §2.1 step 1;
///   spec-problems **P2** — backend-level not_found, distinct from chain-exhausted);
/// - `None` on any verify / revocation / expiry failure → the chain advances,
///   **never** silently downgrading to a pin (fail-closed, proposal §5).
pub fn resolve_one(
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    entry: &ResolverChainEntry,
    name: &str,
) -> Option<ResolutionResult> {
    let registry = entry.backend_id.as_str();
    if registry.is_empty() {
        return None;
    }
    // NFC-only normalization (proposal §2.1 `nfc_normalize`); case-folding is a
    // local-name-config knob on the *local* store, not a peer-issued concern.
    let norm = normalize_name(name, "none");

    // 1. by-name index → binding hash (transport-agnostic read; local store for
    //    the precede path).
    let binding_hash = match location_index.get(&by_name_pointer_path(registry, &norm)) {
        Some(h) => h,
        None => return Some(ResolutionResult::not_found(neg_ttl_from_hints(&entry.hints))),
    };

    // 2. binding hash → binding body (content is self-verifying by hash).
    let body = content_store.get(&binding_hash)?;
    let binding = BindingData::from_entity(&body).ok()?;

    // 3. VERIFY — the only registry-specific logic. Signature at the
    //    invariant-pointer, signed by the *pinned* registry key.
    if !verify_signed_by_registry(content_store, location_index, registry, &binding_hash) {
        return None;
    }

    // Revocation (proposal §2.3): a registry-signed revocation targeting the
    // binding excludes it and advances the chain.
    if is_revoked(content_store, location_index, registry, &binding_hash) {
        return None;
    }

    // TTL (proposal §2.1): `issued_at + ttl > now`, or ttl null (no expiry).
    if let Some(ttl) = binding.ttl {
        if binding.issued_at.saturating_add(ttl) <= now_ms() {
            return None;
        }
    }

    // 4. surface.
    Some(ResolutionResult {
        status: STATUS_RESOLVED.into(),
        binding: Some(binding_hash),
        peer_id: Some(binding.target_peer_id),
        transports: binding.transports,
        attestations: Vec::new(),
        trust_anchor: Some(format!("{}{}", TRUST_PEER_ISSUED_PREFIX, registry)),
        ttl: binding.ttl,
        neg_ttl: None,
        backend_id: Some(registry.to_string()),
    })
}

/// Verify a `system/signature` at the invariant-pointer `/{registry}/system/
/// signature/{hex(target)}` proves `target` was signed by the **pinned**
/// registry key. The pin (spec-problems **P1**): the signer's identity entity,
/// resolved from `sig.signer`, must derive to the peer-id `registry`. Ed25519
/// only (spec-problems **P5**).
fn verify_signed_by_registry(
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    registry: &str,
    target: &Hash,
) -> bool {
    let sig_hash = match location_index.get(&signature_pointer_path(registry, target)) {
        Some(h) => h,
        None => return false,
    };
    let sig = match content_store
        .get(&sig_hash)
        .and_then(|e| SignatureData::from_entity(&e).ok())
    {
        Some(s) => s,
        None => return false,
    };
    if &sig.target != target {
        return false;
    }
    let pubkey = match resolve_peer_pubkey(&sig.signer, content_store) {
        Some(pk) => pk,
        None => return false,
    };
    // The pin: the signer's key must derive to the configured registry peer-id.
    if entity_crypto::PeerId::from_public_key(&pubkey).as_str() != registry {
        return false;
    }
    entity_crypto::Keypair::verify(&pubkey, &target.to_bytes(), &sig.signature).is_ok()
}

/// True if a registry-signed `system/registry/revocation` in the registry's
/// subtree targets `binding_hash` (proposal §2.3). Unlike local-name (where the
/// local store is itself the trust source, §6.3 carve-out), a peer-issued
/// revocation MUST verify against the registry key — otherwise anyone serving
/// the registry's tree could censor a binding.
fn is_revoked(
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    registry: &str,
    binding_hash: &Hash,
) -> bool {
    location_index
        .list(&revocation_prefix(registry))
        .into_iter()
        .any(|entry| {
            let targets = content_store
                .get(&entry.hash)
                .and_then(|e| RevocationData::from_entity(&e).ok())
                .map(|rev| &rev.revokes == binding_hash)
                .unwrap_or(false);
            targets && verify_signed_by_registry(content_store, location_index, registry, &entry.hash)
        })
}

/// Read `neg_ttl` (uint ms) from the chain entry's free-form `hints` map
/// (spec-problems **P3** — no first-class config field yet).
fn neg_ttl_from_hints(hints: &Option<Value>) -> Option<u64> {
    let map = hints.as_ref()?.as_map()?;
    map.iter().find_map(|(k, v)| {
        if k.as_text() == Some("neg_ttl") {
            v.as_integer().and_then(|i| u64::try_from(i).ok())
        } else {
            None
        }
    })
}
