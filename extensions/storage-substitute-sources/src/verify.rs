//! Signature + hash verification helpers (§2.4 trust contract).
//!
//! Substitute entries MUST be signed by their `source_peer_id`; unsigned
//! entries are rejected at chain-enumeration time. Hash verification on
//! fetched bytes is the consumer's defense regardless of substrate
//! consultation.

use entity_crypto::Keypair;
use entity_entity::{Entity, TYPE_SIGNATURE};
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};
use entity_types::SignatureData;

/// Verify a substitute entry's signature against its claimed `source_peer_id`.
///
/// Two-phase lookup (mirrors EXTENSION-ATTESTATION §4.1):
/// 1. Walk the location index for `system/signature` entities targeting
///    `entry_hash`; verify with the source peer's published key.
/// 2. (Future: also check an `included` envelope map; the substrate
///    walks tree-resident state only — chain entries are sticky.)
///
/// Returns `true` only when a signature targeting `entry_hash` from
/// `source_peer_id` exists AND the Ed25519 verification passes.
pub fn verify_entry_signature_against(
    entry_hash: &Hash,
    source_peer_id: &Hash,
    content_store: &dyn ContentStore,
    location_index: &dyn LocationIndex,
) -> bool {
    let sig = match find_signature_tree_resident(entry_hash, source_peer_id, content_store, location_index) {
        Some(s) => s,
        None => return false,
    };
    let pubkey = match resolve_peer_pubkey(source_peer_id, content_store) {
        Some(pk) => pk,
        None => return false,
    };
    Keypair::verify(&pubkey, &entry_hash.to_bytes(), &sig.signature).is_ok()
}

/// Verify a fetched entity's computed `(type, data)` hash matches the
/// requested hash.
///
/// Used after a convention handler returns the fetched entity as its
/// `result` — per §2.2 / §5.1 of the proposal, hash-mismatch discards the
/// entity silently (NOT persisted) and advances to the next chain entry.
pub fn entity_hash_matches(expected: &Hash, entity: &Entity) -> bool {
    Hash::compute(&entity.entity_type, &entity.data) == *expected
}

// ---------------------------------------------------------------------------
// Helpers — mirror EXTENSION-ATTESTATION's resolve discipline at substrate
// minimum surface so we don't depend on the attestation crate.
// ---------------------------------------------------------------------------

fn find_signature_tree_resident(
    target: &Hash,
    signer: &Hash,
    content_store: &dyn ContentStore,
    location_index: &dyn LocationIndex,
) -> Option<SignatureData> {
    let prefix_suffix = format!("system/signature/{}", hex_of(target));
    for entry in location_index.list("/") {
        if !entry.path.ends_with(&prefix_suffix) {
            continue;
        }
        let entity = match content_store.get(&entry.hash) {
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

fn resolve_peer_pubkey(peer_hash: &Hash, content_store: &dyn ContentStore) -> Option<[u8; 32]> {
    let entity = content_store.get(peer_hash)?;
    if entity.entity_type != entity_crypto::TYPE_PEER {
        return None;
    }
    let value: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).ok()?;
    let map = match value {
        ciborium::Value::Map(m) => m,
        _ => return None,
    };
    let pk_bytes = map.iter().find_map(|(k, v)| match (k, v) {
        (ciborium::Value::Text(t), ciborium::Value::Bytes(b)) if t == "public_key" => Some(b),
        _ => None,
    })?;
    pk_bytes.as_slice().try_into().ok()
}

fn hex_of(hash: &Hash) -> String {
    let bytes = hash.to_bytes();
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in &bytes {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

