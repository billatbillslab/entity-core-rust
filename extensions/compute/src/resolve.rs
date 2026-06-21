use std::collections::{HashMap, HashSet};

use entity_entity::Entity;
use entity_hash::Hash;
use entity_store::ContentStore;

use crate::types::{is_compute_type, ComputeError, ComputeValue};

/// Three-tier entity resolution per §4.2, with expression-graph scoping (v3.6 D2)
/// and sealed set authorization (v3.7 D5).
///
/// 1. Check envelope included map (pre-authorized).
/// 2. Check encountered-during-read cache (minimum resolution guarantee).
/// 3. Check content store.
///
/// Post-resolution: validate_compute_resolvable — Tier 0/1/2 checks.
pub fn resolve(
    hash: &Hash,
    included: &HashMap<Hash, Entity>,
    encountered: &HashMap<Hash, Entity>,
    content_store: &dyn ContentStore,
    authorized_data_hashes: &HashSet<Hash>,
) -> Option<Entity> {
    if let Some(entity) = included.get(hash) {
        return validate_compute_resolvable(entity.clone(), hash, authorized_data_hashes);
    }

    if let Some(entity) = encountered.get(hash) {
        return validate_compute_resolvable(entity.clone(), hash, authorized_data_hashes);
    }

    let entity = content_store.get(hash)?;
    validate_compute_resolvable(entity, hash, authorized_data_hashes)
}

/// Validate that a resolved entity is authorized for compute access (§4.2 D2/D5).
///
/// Tier 1: compute-type membership (expression subgraph) — always allowed.
/// Tier 2: sealed set from installed subgraph (authorized_data_hashes) — non-compute
///         entities authorized at install time via path-hint validation.
fn validate_compute_resolvable(
    entity: Entity,
    hash: &Hash,
    authorized_data_hashes: &HashSet<Hash>,
) -> Option<Entity> {
    // Tier 1: compute type — expression subgraph membership
    if is_compute_type(&entity) {
        return Some(entity);
    }
    // Tier 2: sealed set — installed subgraph authorized data
    if authorized_data_hashes.contains(hash) {
        return Some(entity);
    }
    None
}

/// Resolve or return a not_found error (§4.1 V31 helper).
pub fn resolve_or_error(
    hash: &Hash,
    included: &HashMap<Hash, Entity>,
    encountered: &HashMap<Hash, Entity>,
    content_store: &dyn ContentStore,
    authorized_data_hashes: &HashSet<Hash>,
    label: &str,
) -> Result<Entity, ComputeValue> {
    match resolve(hash, included, encountered, content_store, authorized_data_hashes) {
        Some(entity) => Ok(entity),
        None => Err(ComputeError::NotFound(format!(
            "Cannot resolve hash for {}: {}",
            label, hash
        ))
        .to_value()),
    }
}
