//! Envelope.included signature ingestion at dispatcher level
//! (ENTITY-CORE-PROTOCOL-V7 v7.37 §6.5).
//!
//! At envelope unwrap, after `verify_request` and before handler
//! resolution, the dispatcher MUST:
//!
//! 1. Iterate `envelope.included` for `system/signature` entities.
//! 2. Persist each into the content store (idempotent on hash collision).
//! 3. Bind at the V7 invariant pointer path
//!    `/{signer_peer_id}/system/signature/{target_hash_hex}` where
//!    `signer_peer_id` is recovered from the `system/peer` entity at
//!    `signature.signer` (loaded from content store; may itself have
//!    arrived in `included`).
//! 4. On path conflict (existing binding with different content_hash),
//!    return `IngestError::SignaturePathConflict` (rejects the envelope
//!    with status 400, no handler dispatch).
//!
//! Universal: applies to ALL handler ops (kernel, substrate, identity,
//! extensions). Substrate handlers (`system/attestation:verify`,
//! `system/quorum:verify`) and `tree:put` of attestation entities can
//! rely on signatures arriving via `envelope.included` being bound at
//! V7 invariant paths by the time they run.

use std::collections::BTreeMap;
use std::sync::Arc;

use entity_crypto::TYPE_PEER;
use entity_entity::{Entity, TYPE_SIGNATURE};
use entity_hash::{invariant_signature_path, Hash};
use entity_store::{ContentStore, LocationIndex};
use entity_types::{PeerData, SignatureData};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IngestError {
    /// V7 §6.5 — path conflict (existing binding has different
    /// content_hash). MUST surface as status 400 and short-circuit
    /// dispatch.
    #[error("signature_path_conflict: path={path} existing={existing_hex} incoming={incoming_hex}")]
    SignaturePathConflict {
        path: String,
        existing_hex: String,
        incoming_hex: String,
    },
    /// V7 §6.5 — transient I/O during content_store.put or entity_tree.put.
    /// MUST surface as status 500 and short-circuit dispatch.
    #[error("ingest_io_error: {0}")]
    Io(String),
}

/// Run §6.5 dispatcher ingestion over `envelope.included`. Idempotent
/// re-run on the same envelope (no-op).
pub fn ingest_envelope_signatures(
    included: &BTreeMap<Hash, Entity>,
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
) -> Result<usize, IngestError> {
    // Phase 1: persist any system/peer entities first, so signature
    // ingestion can resolve `signer` → peer_id. Has-before-put avoids
    // re-storing identities the peer already knows about (H-G3 Layer 2).
    for entity in included.values() {
        if entity.entity_type == TYPE_PEER && !content_store.has(&entity.content_hash) {
            content_store
                .put(entity.clone())
                .map_err(|e| IngestError::Io(e.to_string()))?;
        }
    }

    // Phase 2: persist + bind each signature at its canonical path.
    let mut count = 0;
    for entity in included.values() {
        if entity.entity_type != TYPE_SIGNATURE {
            continue;
        }
        let sig = match SignatureData::from_entity(entity) {
            Ok(s) => s,
            // Malformed signature entity in included — skip silently.
            // verify_request already structurally validated included
            // entities; SignatureData decode failure here means the
            // signer/target encoding is non-standard. Per spec §6.5 the
            // ingestion is best-effort on signature parse; conflict is
            // the only fail-closed condition.
            Err(_) => continue,
        };
        // Resolve signer → peer_id via the identity entity. Try local
        // store first (already-known signers); fall back to envelope.
        let identity_entity = match content_store.get(&sig.signer) {
            Some(e) => e,
            None => match included.get(&sig.signer) {
                Some(e) => {
                    content_store
                        .put(e.clone())
                        .map_err(|err| IngestError::Io(err.to_string()))?;
                    e.clone()
                }
                // Signer identity not findable → cannot bind. Skip per
                // spec §6.5 algorithm ("if signer_identity is null:
                // continue ; cannot bind; skip").
                None => continue,
            },
        };
        if identity_entity.entity_type != TYPE_PEER {
            continue;
        }
        let peer_id = match peer_id_from_identity_entity(&identity_entity) {
            Some(p) => p,
            None => continue,
        };
        let sig_hash = entity.content_hash;
        if !content_store.has(&sig_hash) {
            content_store
                .put(entity.clone())
                .map_err(|e| IngestError::Io(e.to_string()))?;
        }
        let path = invariant_signature_path(&peer_id, &sig.target);
        if let Some(existing) = location_index.get(&path) {
            if existing != sig_hash {
                return Err(IngestError::SignaturePathConflict {
                    path,
                    existing_hex: hex_segment(&existing),
                    incoming_hex: hex_segment(&sig_hash),
                });
            }
            continue;
        }
        location_index.set(&path, sig_hash);
        count += 1;
    }
    Ok(count)
}

/// Lowercase hex of the full `system/hash` byte sequence (algorithm
/// prefix + digest). Thin alias over the single-source `Hash::to_hex`
/// (V7 §3.5 v7.45); retained only for the diagnostic `*_hex` error
/// fields below. Path construction goes through `invariant_signature_path`.
fn hex_segment(h: &Hash) -> String {
    h.to_hex()
}

/// Recover the canonical `peer_id` (Base58 PeerID string) from a
/// `system/peer` entity for signature-path binding.
///
/// Derives `(public_key, key_type)` → canonical PeerID via the SAME
/// [`PeerData::canonical_peer_id`] the verify-side chain-bundle collector
/// uses ([`entity_protocol::collect_chain_bundle`]). Store-side and
/// lookup-side MUST agree on the form, else the bound path and the queried
/// path diverge and the signature is silently dropped from the bundle.
///
/// The pre-v7.67 implementation hand-decoded the entity and fell back to a
/// hardcoded `[u8; 32]` Ed25519 public key, which returned `None` for an
/// Ed448 signer's 57-byte key — so Ed448-granted cap-chain signatures were
/// never bound, and any cross-peer dispatch whose authority chain rooted at
/// an Ed448 peer failed verification with `missing signature`.
fn peer_id_from_identity_entity(entity: &Entity) -> Option<String> {
    PeerData::from_entity(entity).ok()?.canonical_peer_id()
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_crypto::Keypair;
    use entity_ecf::{text, to_ecf, Value};
    use entity_store::{MemoryContentStore, MemoryLocationIndex};

    fn build_signed(target: Hash, kp: &Keypair, signer: Hash) -> Entity {
        let sig_bytes = kp.sign(&target.to_bytes());
        let sig_data = SignatureData {
            target,
            signer,
            algorithm: "ed25519".into(),
            signature: sig_bytes.to_vec(),
        };
        sig_data.to_entity().unwrap()
    }

    #[test]
    fn ingest_persists_and_binds_at_v7_path() {
        let cs: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let kp = Keypair::from_seed([42u8; 32]);
        let id_entity = kp.peer_entity().unwrap();
        let id_hash = id_entity.content_hash;
        cs.put(id_entity).unwrap();
        let target = Hash::zero();
        let sig_entity = build_signed(target, &kp, id_hash);
        let mut included: BTreeMap<Hash, Entity> = BTreeMap::new();
        included.insert(sig_entity.content_hash, sig_entity);
        let n = ingest_envelope_signatures(&included, &cs, &li).unwrap();
        assert_eq!(n, 1);
        let path = format!(
            "/{}/system/signature/{}",
            kp.peer_id(),
            hex_segment(&target)
        );
        assert!(li.get(&path).is_some(), "signature bound at canonical path");
    }

    /// v7.67 Phase 2 regression: an Ed448 signer's `system/peer` entity
    /// carries a 57-byte public key. The signature MUST bind at the
    /// canonical Ed448 PeerID (SHA-256-form) path — the same form
    /// `collect_chain_bundle` queries. Pre-fix, `peer_id_from_identity_entity`
    /// hand-decoded the entity into a `[u8; 32]` and returned `None` for the
    /// 57-byte key, so the signature was silently never bound and any
    /// cross-peer authority chain rooted at an Ed448 peer failed remote
    /// verification with `missing signature`.
    #[test]
    fn ingest_binds_ed448_signer_at_canonical_path() {
        use entity_crypto::Ed448Keypair;
        let cs: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let kp = Ed448Keypair::from_seed(&[7u8; 57]).unwrap();
        let id_entity = kp.peer_entity().unwrap();
        let id_hash = id_entity.content_hash;
        cs.put(id_entity).unwrap();

        let target = Hash::zero();
        let sig = SignatureData {
            target,
            signer: id_hash,
            algorithm: "ed448".into(),
            signature: kp.sign(&target.to_bytes()).to_vec(),
        }
        .to_entity()
        .unwrap();
        let mut included: BTreeMap<Hash, Entity> = BTreeMap::new();
        included.insert(sig.content_hash, sig);

        let n = ingest_envelope_signatures(&included, &cs, &li).unwrap();
        assert_eq!(n, 1, "Ed448 signature MUST bind (was silently dropped pre-fix)");

        // Path uses the canonical SHA-256-form PeerID — the exact form the
        // verify-side chain-bundle collector derives via canonical_peer_id().
        let path = format!(
            "/{}/system/signature/{}",
            kp.peer_id(),
            hex_segment(&target)
        );
        assert!(
            li.get(&path).is_some(),
            "Ed448 signature bound at canonical SHA-256-form path"
        );
    }

    #[test]
    fn ingest_idempotent_on_re_run() {
        let cs: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let kp = Keypair::from_seed([43u8; 32]);
        let id_entity = kp.peer_entity().unwrap();
        let id_hash = id_entity.content_hash;
        cs.put(id_entity).unwrap();
        let sig_entity = build_signed(Hash::zero(), &kp, id_hash);
        let mut included: BTreeMap<Hash, Entity> = BTreeMap::new();
        included.insert(sig_entity.content_hash, sig_entity);
        ingest_envelope_signatures(&included, &cs, &li).unwrap();
        let n2 = ingest_envelope_signatures(&included, &cs, &li).unwrap();
        assert_eq!(n2, 0, "idempotent re-run binds nothing new");
    }

    #[test]
    fn ingest_picks_up_identity_entity_from_envelope() {
        // Identity not pre-loaded; must be picked up from included.
        let cs: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let kp = Keypair::from_seed([44u8; 32]);
        let id_entity = kp.peer_entity().unwrap();
        let id_hash = id_entity.content_hash;
        let sig_entity = build_signed(Hash::zero(), &kp, id_hash);
        let mut included: BTreeMap<Hash, Entity> = BTreeMap::new();
        included.insert(id_hash, id_entity);
        included.insert(sig_entity.content_hash, sig_entity);
        let n = ingest_envelope_signatures(&included, &cs, &li).unwrap();
        assert_eq!(n, 1);
        // Identity entity is now in the content store.
        assert!(cs.get(&id_hash).is_some());
    }

    #[test]
    fn ingest_fails_closed_on_path_conflict() {
        let cs: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let kp = Keypair::from_seed([45u8; 32]);
        let id_entity = kp.peer_entity().unwrap();
        let id_hash = id_entity.content_hash;
        cs.put(id_entity).unwrap();
        let target = Hash::zero();
        let path = format!(
            "/{}/system/signature/{}",
            kp.peer_id(),
            hex_segment(&target)
        );
        // Pre-bind a different hash at the canonical path.
        let bogus = Entity::new("system/error", to_ecf(&Value::Map(vec![(text("x"), text("y"))]))).unwrap();
        let bogus_hash = bogus.content_hash;
        cs.put(bogus).unwrap();
        li.set(&path, bogus_hash);
        // Now ingest the real signature → conflict.
        let sig_entity = build_signed(target, &kp, id_hash);
        let mut included: BTreeMap<Hash, Entity> = BTreeMap::new();
        included.insert(sig_entity.content_hash, sig_entity);
        let err = ingest_envelope_signatures(&included, &cs, &li).unwrap_err();
        assert!(matches!(err, IngestError::SignaturePathConflict { .. }));
    }
}
