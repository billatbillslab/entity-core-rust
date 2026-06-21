//! Three-way merge framework — path-by-path merge with configurable strategies.
//!
//! Implements spec §4.3.4 merge algorithm and §5 merge strategy framework.

use std::collections::BTreeMap;

use entity_entity::{canonical_deletion_marker_hash, Entity};
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};

/// EXTENSION-REVISION v3.1 §2.3 Amendment 4 — `merge-config.deletion_resolution`.
/// Applies when the three-way merge classifies a (local, remote) pair as
/// "both changed differently" AND exactly one side is the canonical
/// deletion marker. Default `preserve-on-conflict`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeletionResolution {
    /// Entity supersedes the deletion marker. Edit-loss risk: the delete
    /// signal is silently discarded. Recommended for collaborative edit
    /// workflows. Default.
    #[default]
    PreserveOnConflict,
    /// Deletion marker supersedes the entity. Sticky delete; the edit
    /// signal is silently discarded. Recommended for security-sensitive
    /// workflows (e.g., access-control revocation).
    DeletionWins,
    /// Surface as a conflict entity (same shape as edit-vs-edit).
    ThreeWayFallthrough,
    /// Deterministic: lower-hash wins. The marker hash is canonical so
    /// the outcome is stable across peers.
    Deterministic,
}

impl DeletionResolution {
    /// Parse a `deletion_resolution` string. Returns `None` for any
    /// rejected-at-config-write value (`lww`, `keep-both`) and for
    /// unknown values.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "preserve-on-conflict" => Some(Self::PreserveOnConflict),
            "deletion-wins" => Some(Self::DeletionWins),
            "three-way-fallthrough" => Some(Self::ThreeWayFallthrough),
            "deterministic" => Some(Self::Deterministic),
            _ => None,
        }
    }

    /// Per v3.1 §2.3: `lww` and `keep-both` MUST be rejected at
    /// config-write time. Implementations encountering either return
    /// `invalid_strategy` rather than silently accepting.
    pub fn is_rejected_at_config_write(s: &str) -> bool {
        matches!(s, "lww" | "keep-both")
    }
}

// crate::dag is not directly used here; merge operates on flat bindings.

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Result of merging two snapshots.
#[derive(Debug)]
pub struct MergeResult {
    /// Final merged bindings (relative_path -> entity_hash).
    pub merged_bindings: BTreeMap<String, Hash>,
    /// Paths that should be deleted from the tree.
    pub deletions: Vec<String>,
    /// Conflict descriptions for unresolved paths.
    pub conflicts: Vec<ConflictInfo>,
    /// Additional bindings produced by strategies like KeepBoth (R4).
    pub additional_bindings: Vec<(String, Hash)>,
}

/// Info about a single conflict, used for storage.
#[derive(Debug, Clone)]
pub struct ConflictInfo {
    pub path: String,
    pub base: Option<Hash>,
    pub local: Option<Hash>,
    pub remote: Option<Hash>,
    pub strategy: String,
}

/// Merge strategy (EXTENSION-REVISION §5.1).
///
/// LWW is removed — no timestamps in structural version entries.
#[derive(Debug, Clone, PartialEq)]
pub enum MergeStrategy {
    ThreeWay,
    SourceWins,
    TargetWins,
    Manual,
    KeepBoth,
}

impl MergeStrategy {
    pub fn parse(s: &str) -> Option<MergeStrategy> {
        match s {
            "three-way" => Some(MergeStrategy::ThreeWay),
            "source-wins" => Some(MergeStrategy::SourceWins),
            "target-wins" => Some(MergeStrategy::TargetWins),
            "manual" => Some(MergeStrategy::Manual),
            "keep-both" => Some(MergeStrategy::KeepBoth),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            MergeStrategy::ThreeWay => "three-way",
            MergeStrategy::SourceWins => "source-wins",
            MergeStrategy::TargetWins => "target-wins",
            MergeStrategy::Manual => "manual",
            MergeStrategy::KeepBoth => "keep-both",
        }
    }
}

/// Normalize merge sides for deterministic ordering.
///
/// In "deterministic" mode, the side with the lower hash (by binary comparison)
/// is always "local" and the higher is "remote". This ensures two peers
/// independently merging the same versions produce the same result.
pub fn normalize_merge_sides<'a>(
    local: &'a BTreeMap<String, Hash>,
    remote: &'a BTreeMap<String, Hash>,
    local_version: Hash,
    remote_version: Hash,
    merge_order: &str,
) -> (&'a BTreeMap<String, Hash>, &'a BTreeMap<String, Hash>, Hash, Hash) {
    if merge_order == "deterministic" && remote_version < local_version {
        (remote, local, remote_version, local_version)
    } else {
        (local, remote, local_version, remote_version)
    }
}

// ---------------------------------------------------------------------------
// Merge snapshots (spec §4.3.4)
// ---------------------------------------------------------------------------

/// Merge two snapshots against a common ancestor.
///
/// `ancestor` is `None` when there is no common ancestor (create/create scenario).
/// `local` and `remote` are the two diverged snapshot bindings.
/// `prefix` is used for conflict storage paths.
/// `strategy_override` overrides per-path config lookup.
#[allow(clippy::too_many_arguments)]
pub fn merge_snapshots(
    ancestor: Option<&BTreeMap<String, Hash>>,
    local: &BTreeMap<String, Hash>,
    remote: &BTreeMap<String, Hash>,
    _prefix: &str,
    strategy_override: Option<&str>,
    store: &dyn ContentStore,
    location_index: &dyn LocationIndex,
    _local_version: Hash,
    _remote_version: Hash,
    local_peer_id: &str,
) -> MergeResult {
    let empty = BTreeMap::new();
    let base = ancestor.unwrap_or(&empty);

    // Collect all paths from all three snapshots
    let mut all_paths: Vec<String> = Vec::new();
    for path in base.keys().chain(local.keys()).chain(remote.keys()) {
        if !all_paths.contains(path) {
            all_paths.push(path.clone());
        }
    }
    all_paths.sort();

    let mut merged = BTreeMap::new();
    let mut deletions = Vec::new();
    let mut conflicts = Vec::new();
    let mut additional_bindings: Vec<(String, Hash)> = Vec::new();

    // EXTENSION-REVISION v3.1 §4.4.4 — canonical deletion-marker hash
    // (O(1) equality check; the spec recommends this over content-store
    // lookup). Under v3.1, *absence* preserves from the other side; only
    // an explicit marker is deletion.
    let marker = canonical_deletion_marker_hash();
    let is_marker = |h: &Hash| *h == marker;

    for path in &all_paths {
        let base_hash = base.get(path);
        let local_hash = local.get(path);
        let remote_hash = remote.get(path);

        match (base_hash, local_hash, remote_hash) {
            // Defensive: shouldn't appear in all_paths.
            (None, None, None) => {}

            // Both-absent fallback (v3.1 §4.4.4): preserved-unbound.
            // Cannot arise under post-v3.1 commits (which emit explicit
            // markers); normative for pre-v3.1 trees and non-conforming
            // peers.
            (Some(_), None, None) => {}

            // Same hash on both sides — same real entity OR same marker.
            // Markers are canonical so deletion-vs-deletion is NOT
            // divergent; both branches produce the same merged hash.
            (_, Some(l), Some(r)) if l == r => {
                merged.insert(path.clone(), *l);
            }

            // Local has an opinion, remote does NOT (v3.1: absence = no
            // opinion, not deletion). Preserve from local — whether
            // marker or real entity.
            (_, Some(l), None) => {
                merged.insert(path.clone(), *l);
            }

            // Remote has an opinion, local does NOT. Preserve from remote.
            (_, None, Some(r)) => {
                merged.insert(path.clone(), *r);
            }

            // Both have opinions, l != r.
            (_, Some(l), Some(r)) => {
                let l_marker = is_marker(l);
                let r_marker = is_marker(r);
                if l_marker ^ r_marker {
                    // Marker-vs-entity. Per EXTENSION-REVISION §2.3
                    // Amendment 4, `deletion_resolution` applies only when
                    // the classifier says "both changed differently". If
                    // base equals one side, this is a clean three-way:
                    // take whichever side changed.
                    if base_hash == Some(l) {
                        // Only remote changed from base — take remote.
                        merged.insert(path.clone(), *r);
                        if r_marker {
                            deletions.push(path.clone());
                        }
                    } else if base_hash == Some(r) {
                        // Only local changed from base — take local.
                        merged.insert(path.clone(), *l);
                        if l_marker {
                            deletions.push(path.clone());
                        }
                    } else {
                        // Both changed differently — `deletion_resolution`.
                        let dr = find_deletion_resolution(path, location_index, store, local_peer_id);
                        let entity_side_hash = if l_marker { *r } else { *l };
                        match dr {
                            DeletionResolution::PreserveOnConflict => {
                                // Entity supersedes the marker; delete silently discarded.
                                merged.insert(path.clone(), entity_side_hash);
                            }
                            DeletionResolution::DeletionWins => {
                                // Sticky delete; edit silently discarded.
                                merged.insert(path.clone(), marker);
                                deletions.push(path.clone());
                            }
                            DeletionResolution::ThreeWayFallthrough => {
                                // Surface as conflict (edit-vs-edit shape).
                                conflicts.push(ConflictInfo {
                                    path: path.clone(),
                                    base: base_hash.copied(),
                                    local: Some(*l),
                                    remote: Some(*r),
                                    strategy: "three-way-fallthrough".to_string(),
                                });
                                // Pick local as the placeholder binding (live
                                // tree apply will translate marker → unbind).
                                merged.insert(path.clone(), *l);
                            }
                            DeletionResolution::Deterministic => {
                                // EXTENSION-REVISION v3.3 D2: lower hash
                                // wins under byte-wise lexicographic
                                // comparison. The canonical marker hash
                                // is stable, so the outcome converges
                                // across peers.
                                let winner = if l < r { *l } else { *r };
                                merged.insert(path.clone(), winner);
                                if winner == marker {
                                    deletions.push(path.clone());
                                }
                            }
                        }
                    }
                } else {
                    // Standard edit-vs-edit divergence — both real entities.
                    let strategy = find_merge_strategy(
                        path, strategy_override, location_index, store,
                        Some(l), Some(r), local_peer_id,
                    );
                    match strategy {
                        MergeStrategy::SourceWins => {
                            merged.insert(path.clone(), *r);
                        }
                        MergeStrategy::TargetWins => {
                            merged.insert(path.clone(), *l);
                        }
                        MergeStrategy::ThreeWay => {
                            if base_hash.is_some() && base_hash == Some(l) {
                                merged.insert(path.clone(), *r);
                            } else if base_hash.is_some() && base_hash == Some(r) {
                                merged.insert(path.clone(), *l);
                            } else {
                                conflicts.push(ConflictInfo {
                                    path: path.clone(),
                                    base: base_hash.copied(),
                                    local: Some(*l),
                                    remote: Some(*r),
                                    strategy: "three-way".to_string(),
                                });
                                merged.insert(path.clone(), *l);
                            }
                        }
                        MergeStrategy::KeepBoth => {
                            // R4: KeepBoth only for edit-vs-edit. Local
                            // keeps original path; remote gets alternate.
                            merged.insert(path.clone(), *l);
                            let hash_prefix: String = r.digest()[0..4]
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect();
                            additional_bindings.push((
                                format!("{}.keep-both-{}", path, hash_prefix),
                                *r,
                            ));
                        }
                        MergeStrategy::Manual => {
                            conflicts.push(ConflictInfo {
                                path: path.clone(),
                                base: base_hash.copied(),
                                local: Some(*l),
                                remote: Some(*r),
                                strategy: strategy.as_str().to_string(),
                            });
                            merged.insert(path.clone(), *l);
                        }
                    }
                }
            }
        }
    }

    MergeResult {
        merged_bindings: merged,
        deletions,
        conflicts,
        additional_bindings,
    }
}

/// Look up `deletion_resolution` for a path. Currently scans the
/// global merge-config paths at `system/revision/config/merge/path/*`
/// (same convention as `find_merge_strategy`). Default
/// `preserve-on-conflict` if no matching config or no field.
fn find_deletion_resolution(
    path: &str,
    location_index: &dyn LocationIndex,
    store: &dyn ContentStore,
    local_peer_id: &str,
) -> DeletionResolution {
    let path_config_prefix = format!(
        "/{}/system/revision/config/merge/path/",
        local_peer_id,
    );
    let mut best_match: Option<(usize, DeletionResolution)> = None;
    for entry in location_index.list(&path_config_prefix) {
        if let Some(config_entity) = store.get(&entry.hash) {
            if let Some((pattern, dr)) = decode_deletion_resolution_config(&config_entity.data) {
                if path_pattern_matches(&pattern, path) {
                    let specificity = pattern.len();
                    if best_match.as_ref().is_none_or(|(s, _)| specificity > *s) {
                        best_match = Some((specificity, dr));
                    }
                }
            }
        }
    }
    best_match.map(|(_, dr)| dr).unwrap_or_default()
}

fn decode_deletion_resolution_config(data: &[u8]) -> Option<(String, DeletionResolution)> {
    let val: ciborium::Value = ciborium::from_reader(data).ok()?;
    let map = val.as_map()?;
    let mut pattern = None;
    let mut dr = None;
    for (k, v) in map {
        match k.as_text() {
            Some("pattern") => pattern = v.as_text().map(|s| s.to_string()),
            Some("deletion_resolution") => {
                dr = v.as_text().and_then(DeletionResolution::parse);
            }
            _ => {}
        }
    }
    Some((pattern?, dr?))
}

// ---------------------------------------------------------------------------
// Conflict storage
// ---------------------------------------------------------------------------

/// Store a conflict entity at `/{pid}/system/revision/{prefix_hash}/conflicts/{path}`.
pub fn store_conflict(
    store: &dyn ContentStore,
    location_index: &dyn LocationIndex,
    prefix_hash: &str,
    info: &ConflictInfo,
    local_version: Hash,
    remote_version: Hash,
    local_peer_id: &str,
) -> Result<Hash, String> {
    let conflict_path = format!("/{}/system/revision/{}/conflicts/{}", local_peer_id, prefix_hash, info.path);

    // Check for existing conflict to supersede
    let supersedes = location_index.get(&conflict_path);

    let mut fields = Vec::new();

    if let Some(base) = &info.base {
        fields.push((
            entity_ecf::text("base"),
            entity_ecf::Value::Bytes(base.to_bytes().to_vec()),
        ));
    }
    if let Some(local) = &info.local {
        fields.push((
            entity_ecf::text("local"),
            entity_ecf::Value::Bytes(local.to_bytes().to_vec()),
        ));
    }
    fields.push((
        entity_ecf::text("path"),
        entity_ecf::text(&info.path),
    ));
    if let Some(remote) = &info.remote {
        fields.push((
            entity_ecf::text("remote"),
            entity_ecf::Value::Bytes(remote.to_bytes().to_vec()),
        ));
    }
    fields.push((
        entity_ecf::text("strategy"),
        entity_ecf::text(&info.strategy),
    ));
    if let Some(sup) = supersedes {
        fields.push((
            entity_ecf::text("supersedes"),
            entity_ecf::Value::Bytes(sup.to_bytes().to_vec()),
        ));
    }
    fields.push((
        entity_ecf::text("version_local"),
        entity_ecf::Value::Bytes(local_version.to_bytes().to_vec()),
    ));
    fields.push((
        entity_ecf::text("version_remote"),
        entity_ecf::Value::Bytes(remote_version.to_bytes().to_vec()),
    ));

    // Sort by key for ECF determinism
    fields.sort_by(|(a, _), (b, _)| {
        let a_text = if let entity_ecf::Value::Text(s) = a { s.as_str() } else { "" };
        let b_text = if let entity_ecf::Value::Text(s) = b { s.as_str() } else { "" };
        a_text.len().cmp(&b_text.len()).then_with(|| a_text.cmp(b_text))
    });

    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
    let entity = Entity::new("system/revision/conflict", data).map_err(|e| e.to_string())?;
    let hash = store.put(entity).map_err(|e| e.to_string())?;
    location_index.set(&conflict_path, hash);
    Ok(hash)
}

// ---------------------------------------------------------------------------
// Strategy resolution (spec §5.1)
// ---------------------------------------------------------------------------

/// Find the merge strategy for a given path.
///
/// Priority (§5.1): override > per-type config > per-path config > default (three-way).
/// Global merge configs (not prefix-scoped) stored at:
///   `system/revision/config/merge/type/{type_name}` (per-type)
///   `system/revision/config/merge/path/{name}` (per-path pattern)
pub fn find_merge_strategy(
    path: &str,
    override_strategy: Option<&str>,
    location_index: &dyn LocationIndex,
    store: &dyn ContentStore,
    local_hash: Option<&Hash>,
    remote_hash: Option<&Hash>,
    local_peer_id: &str,
) -> MergeStrategy {
    if let Some(s) = override_strategy {
        if let Some(strategy) = MergeStrategy::parse(s) {
            return strategy;
        }
    }

    // Per-type config: look up entity type, then check config
    let entity_hash = local_hash.or(remote_hash);
    if let Some(h) = entity_hash {
        if let Some(entity) = store.get(h) {
            let type_config_path = format!(
                "/{}/system/revision/config/merge/type/{}",
                local_peer_id, entity.entity_type
            );
            if let Some(config_hash) = location_index.get(&type_config_path) {
                if let Some(config_entity) = store.get(&config_hash) {
                    if let Some((_, strategy)) = decode_path_strategy_config(&config_entity.data) {
                        return strategy;
                    }
                }
            }
        }
    }

    // Per-path config: global at system/revision/config/merge/path/
    let path_config_prefix = format!(
        "/{}/system/revision/config/merge/path/",
        local_peer_id,
    );
    let mut best_match: Option<(usize, MergeStrategy)> = None;
    for entry in location_index.list(&path_config_prefix) {
        if let Some(config_entity) = store.get(&entry.hash) {
            if let Some((pattern, strategy)) = decode_path_strategy_config(&config_entity.data) {
                if path_pattern_matches(&pattern, path) {
                    let specificity = pattern.len();
                    if best_match.as_ref().is_none_or(|(s, _)| specificity > *s) {
                        best_match = Some((specificity, strategy));
                    }
                }
            }
        }
    }
    if let Some((_, strategy)) = best_match {
        return strategy;
    }

    MergeStrategy::ThreeWay
}

fn decode_path_strategy_config(data: &[u8]) -> Option<(String, MergeStrategy)> {
    let val: ciborium::Value = ciborium::from_reader(data).ok()?;
    let map = val.as_map()?;
    let mut pattern = None;
    let mut strategy = None;
    for (k, v) in map {
        match k.as_text() {
            Some("pattern") => pattern = v.as_text().map(|s| s.to_string()),
            Some("strategy") => strategy = v.as_text().and_then(MergeStrategy::parse),
            _ => {}
        }
    }
    Some((pattern?, strategy?))
}

fn path_pattern_matches(pattern: &str, path: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return path.starts_with(prefix) && path.len() > prefix.len();
    }
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return path.starts_with(prefix);
    }
    pattern == path
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_store::{MemoryContentStore, MemoryLocationIndex};

    fn stores() -> (MemoryContentStore, MemoryLocationIndex) {
        (MemoryContentStore::new(), MemoryLocationIndex::new())
    }

    fn put_test_entity(store: &dyn ContentStore, type_str: &str, content: &str) -> Hash {
        let data = entity_ecf::to_ecf(&entity_ecf::text(content));
        let entity = Entity::new(type_str, data).unwrap();
        store.put(entity).unwrap()
    }

    #[test]
    fn test_clean_merge_no_conflicts() {
        let (store, li) = stores();
        let h1 = put_test_entity(&store, "test/type", "file1");
        let h2 = put_test_entity(&store, "test/type", "file2");
        let h3 = put_test_entity(&store, "test/type", "file3");

        let mut base = BTreeMap::new();
        base.insert("a".to_string(), h1);

        let mut local = BTreeMap::new();
        local.insert("a".to_string(), h1); // unchanged
        local.insert("b".to_string(), h2); // local added

        let mut remote = BTreeMap::new();
        remote.insert("a".to_string(), h1); // unchanged
        remote.insert("c".to_string(), h3); // remote added

        let result = merge_snapshots(
            Some(&base), &local, &remote, "data/",
            None, &store, &li, Hash::zero(), Hash::zero(), "test-peer",
        );

        assert!(result.conflicts.is_empty());
        assert!(result.deletions.is_empty());
        assert_eq!(result.merged_bindings.len(), 3);
        assert_eq!(result.merged_bindings["a"], h1);
        assert_eq!(result.merged_bindings["b"], h2);
        assert_eq!(result.merged_bindings["c"], h3);
    }

    #[test]
    fn test_both_changed_same_value() {
        let (store, li) = stores();
        let h1 = put_test_entity(&store, "test/type", "old");
        let h2 = put_test_entity(&store, "test/type", "new");

        let mut base = BTreeMap::new();
        base.insert("a".to_string(), h1);

        let mut local = BTreeMap::new();
        local.insert("a".to_string(), h2);

        let mut remote = BTreeMap::new();
        remote.insert("a".to_string(), h2);

        let result = merge_snapshots(
            Some(&base), &local, &remote, "data/",
            None, &store, &li, Hash::zero(), Hash::zero(), "test-peer",
        );

        assert!(result.conflicts.is_empty());
        assert_eq!(result.merged_bindings["a"], h2);
    }

    #[test]
    fn test_three_way_only_remote_changed() {
        let (store, li) = stores();
        let h1 = put_test_entity(&store, "test/type", "original");
        let h2 = put_test_entity(&store, "test/type", "changed");

        let mut base = BTreeMap::new();
        base.insert("a".to_string(), h1);

        let mut local = BTreeMap::new();
        local.insert("a".to_string(), h1); // unchanged

        let mut remote = BTreeMap::new();
        remote.insert("a".to_string(), h2); // changed

        let result = merge_snapshots(
            Some(&base), &local, &remote, "data/",
            None, &store, &li, Hash::zero(), Hash::zero(), "test-peer",
        );

        assert!(result.conflicts.is_empty());
        assert_eq!(result.merged_bindings["a"], h2); // takes remote
    }

    #[test]
    fn test_conflict_both_changed_differently() {
        let (store, li) = stores();
        let h0 = put_test_entity(&store, "test/type", "base");
        let h1 = put_test_entity(&store, "test/type", "local_change");
        let h2 = put_test_entity(&store, "test/type", "remote_change");

        let mut base = BTreeMap::new();
        base.insert("a".to_string(), h0);

        let mut local = BTreeMap::new();
        local.insert("a".to_string(), h1);

        let mut remote = BTreeMap::new();
        remote.insert("a".to_string(), h2);

        let result = merge_snapshots(
            Some(&base), &local, &remote, "data/",
            None, &store, &li, Hash::zero(), Hash::zero(), "test-peer",
        );

        assert_eq!(result.conflicts.len(), 1);
        assert_eq!(result.conflicts[0].path, "a");
        // Local stays visible
        assert_eq!(result.merged_bindings["a"], h1);
    }

    #[test]
    fn delete_vs_edit_default_preserve_on_conflict() {
        // EXTENSION-REVISION v3.1 §2.3 Amendment 4: delete-vs-edit
        // (deletion marker on one side, real entity on the other) is
        // governed by `deletion_resolution`. Default `preserve-on-conflict`
        // — the entity supersedes the marker; the delete is silently
        // discarded; no conflict entity written.
        let (store, li) = stores();
        let h0 = put_test_entity(&store, "test/type", "base");
        let h1 = put_test_entity(&store, "test/type", "edited");
        let marker = canonical_deletion_marker_hash();

        let mut base = BTreeMap::new();
        base.insert("a".to_string(), h0);

        // Local bound the deletion marker (= explicit delete); remote edited.
        let mut local = BTreeMap::new();
        local.insert("a".to_string(), marker);
        let mut remote = BTreeMap::new();
        remote.insert("a".to_string(), h1);

        let result = merge_snapshots(
            Some(&base), &local, &remote, "data/",
            None, &store, &li, Hash::zero(), Hash::zero(), "test-peer",
        );

        // Default preserve-on-conflict: no conflict; remote entity wins.
        assert_eq!(result.conflicts.len(), 0);
        assert_eq!(result.merged_bindings["a"], h1);
    }

    #[test]
    fn absent_side_preserves_other_side_under_v3_1() {
        // EXTENSION-REVISION v3.1 §4.4.4: absence is "no opinion", not
        // deletion. Pre-v3.1, this case would have been classified as
        // edit-vs-delete; under v3.1, the side with an opinion wins
        // without surfacing a conflict.
        let (store, li) = stores();
        let h0 = put_test_entity(&store, "test/type", "base");
        let h1 = put_test_entity(&store, "test/type", "edited");

        let mut base = BTreeMap::new();
        base.insert("a".to_string(), h0);

        let local = BTreeMap::new();
        let mut remote = BTreeMap::new();
        remote.insert("a".to_string(), h1);

        let result = merge_snapshots(
            Some(&base), &local, &remote, "data/",
            None, &store, &li, Hash::zero(), Hash::zero(), "test-peer",
        );

        assert_eq!(result.conflicts.len(), 0);
        assert_eq!(result.merged_bindings["a"], h1);
    }

    #[test]
    fn test_source_wins_strategy() {
        let (store, li) = stores();
        let h0 = put_test_entity(&store, "test/type", "base");
        let h1 = put_test_entity(&store, "test/type", "local");
        let h2 = put_test_entity(&store, "test/type", "remote");

        let mut base = BTreeMap::new();
        base.insert("a".to_string(), h0);

        let mut local = BTreeMap::new();
        local.insert("a".to_string(), h1);

        let mut remote = BTreeMap::new();
        remote.insert("a".to_string(), h2);

        let result = merge_snapshots(
            Some(&base), &local, &remote, "data/",
            Some("source-wins"), &store, &li, Hash::zero(), Hash::zero(), "test-peer",
        );

        assert!(result.conflicts.is_empty());
        assert_eq!(result.merged_bindings["a"], h2); // remote wins
    }

    #[test]
    fn test_target_wins_strategy() {
        let (store, li) = stores();
        let h0 = put_test_entity(&store, "test/type", "base");
        let h1 = put_test_entity(&store, "test/type", "local");
        let h2 = put_test_entity(&store, "test/type", "remote");

        let mut base = BTreeMap::new();
        base.insert("a".to_string(), h0);

        let mut local = BTreeMap::new();
        local.insert("a".to_string(), h1);

        let mut remote = BTreeMap::new();
        remote.insert("a".to_string(), h2);

        let result = merge_snapshots(
            Some(&base), &local, &remote, "data/",
            Some("target-wins"), &store, &li, Hash::zero(), Hash::zero(), "test-peer",
        );

        assert!(result.conflicts.is_empty());
        assert_eq!(result.merged_bindings["a"], h1); // local wins
    }

    #[test]
    fn test_conflict_storage_with_supersedes() {
        let (store, li) = stores();

        let info = ConflictInfo {
            path: "foo/bar".to_string(),
            base: None,
            local: Some(Hash::zero()),
            remote: Some(Hash::zero()),
            strategy: "three-way".to_string(),
        };

        let ph = crate::prefix_hash(&crate::resolve_prefix("data/", "peer1"));
        let h1 = store_conflict(&store, &li, &ph, &info, Hash::zero(), Hash::zero(), "peer1").unwrap();
        assert!(h1 != Hash::zero());

        // Store again — should supersede
        let h2 = store_conflict(&store, &li, &ph, &info, Hash::zero(), Hash::zero(), "peer1").unwrap();
        assert!(h2 != Hash::zero());

        // The second conflict should have a supersedes field pointing to h1
        let entity = store.get(&h2).unwrap();
        let val: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let has_supersedes = map.iter().any(|(k, _)| k.as_text() == Some("supersedes"));
        assert!(has_supersedes);
    }

    #[test]
    fn test_keep_both_edit_edit() {
        let (store, li) = stores();
        let h0 = put_test_entity(&store, "test/type", "base");
        let h1 = put_test_entity(&store, "test/type", "local_v");
        let h2 = put_test_entity(&store, "test/type", "remote_v");

        let mut base = BTreeMap::new();
        base.insert("a".to_string(), h0);

        let mut local = BTreeMap::new();
        local.insert("a".to_string(), h1);

        let mut remote = BTreeMap::new();
        remote.insert("a".to_string(), h2);

        let result = merge_snapshots(
            Some(&base), &local, &remote, "data/",
            Some("keep-both"), &store, &li, Hash::zero(), Hash::zero(), "test-peer",
        );

        assert!(result.conflicts.is_empty());
        assert_eq!(result.merged_bindings["a"], h1);
        assert_eq!(result.additional_bindings.len(), 1);
        let (ref keep_path, keep_hash) = result.additional_bindings[0];
        assert!(keep_path.starts_with("a.keep-both-"));
        assert_eq!(keep_hash, h2);
        // Hash prefix is 8 hex chars
        let suffix = keep_path.strip_prefix("a.keep-both-").unwrap();
        assert_eq!(suffix.len(), 8);
    }

    #[test]
    fn keep_both_does_not_apply_to_delete_vs_edit() {
        // EXTENSION-REVISION v3.1 §2.3: `keep-both` is rejected for
        // `deletion_resolution` (the path falls through to the default
        // `preserve-on-conflict`). Even if the strategy override is
        // `keep-both`, the delete-vs-edit case is governed by
        // deletion_resolution, NOT merge strategy. With default
        // preserve-on-conflict, no conflict and no additional binding.
        let (store, li) = stores();
        let h0 = put_test_entity(&store, "test/type", "base");
        let h1 = put_test_entity(&store, "test/type", "edited");
        let marker = canonical_deletion_marker_hash();

        let mut base = BTreeMap::new();
        base.insert("a".to_string(), h0);

        // Local bound the deletion marker; remote edited.
        let mut local = BTreeMap::new();
        local.insert("a".to_string(), marker);
        let mut remote = BTreeMap::new();
        remote.insert("a".to_string(), h1);

        let result = merge_snapshots(
            Some(&base), &local, &remote, "data/",
            Some("keep-both"), &store, &li, Hash::zero(), Hash::zero(), "test-peer",
        );

        assert_eq!(result.conflicts.len(), 0);
        assert!(result.additional_bindings.is_empty());
        assert_eq!(result.merged_bindings["a"], h1);
    }

    #[test]
    fn test_merge_config_wildcard_strategy() {
        let (store, li) = stores();

        // Global merge config at system/revision/config/merge/path/{name}
        let cfg_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "pattern" => entity_ecf::text("*"),
            "strategy" => entity_ecf::text("source-wins")
        });
        let cfg_entity = Entity::new("system/revision/merge-config", cfg_data).unwrap();
        let cfg_hash = store.put(cfg_entity).unwrap();
        li.set("/test-peer/system/revision/config/merge/path/all", cfg_hash);

        let h0 = put_test_entity(&store, "test/type", "base");
        let h1 = put_test_entity(&store, "test/type", "local");
        let h2 = put_test_entity(&store, "test/type", "remote");

        let mut base = BTreeMap::new();
        base.insert("a".to_string(), h0);
        let mut local = BTreeMap::new();
        local.insert("a".to_string(), h1);
        let mut remote = BTreeMap::new();
        remote.insert("a".to_string(), h2);

        // No strategy override — should discover from config
        let result = merge_snapshots(
            Some(&base), &local, &remote, "data/",
            None, &store, &li, Hash::zero(), Hash::zero(), "test-peer",
        );

        assert!(result.conflicts.is_empty());
        assert_eq!(result.merged_bindings["a"], h2); // source-wins → remote
    }

    #[test]
    fn test_merge_config_path_pattern() {
        let (store, li) = stores();

        // Global merge config for "docs/*" paths
        let cfg_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "pattern" => entity_ecf::text("docs/*"),
            "strategy" => entity_ecf::text("target-wins")
        });
        let cfg_entity = Entity::new("system/revision/merge-config", cfg_data).unwrap();
        let cfg_hash = store.put(cfg_entity).unwrap();
        li.set("/test-peer/system/revision/config/merge/path/docs-rule", cfg_hash);

        let h0 = put_test_entity(&store, "test/type", "base");
        let h1 = put_test_entity(&store, "test/type", "local");
        let h2 = put_test_entity(&store, "test/type", "remote");

        let mut base = BTreeMap::new();
        base.insert("docs/readme".to_string(), h0);
        let mut local = BTreeMap::new();
        local.insert("docs/readme".to_string(), h1);
        let mut remote = BTreeMap::new();
        remote.insert("docs/readme".to_string(), h2);

        let result = merge_snapshots(
            Some(&base), &local, &remote, "data/",
            None, &store, &li, Hash::zero(), Hash::zero(), "test-peer",
        );

        assert!(result.conflicts.is_empty());
        assert_eq!(result.merged_bindings["docs/readme"], h1); // target-wins → local
    }

    #[test]
    fn test_merge_config_keep_both_via_config() {
        let (store, li) = stores();

        // Global merge config: keep-both for all paths
        let cfg_data = entity_ecf::to_ecf(&entity_ecf::cbor_map! {
            "pattern" => entity_ecf::text("*"),
            "strategy" => entity_ecf::text("keep-both")
        });
        let cfg_entity = Entity::new("system/revision/merge-config", cfg_data).unwrap();
        let cfg_hash = store.put(cfg_entity).unwrap();
        li.set("/test-peer/system/revision/config/merge/path/all", cfg_hash);

        let h0 = put_test_entity(&store, "test/type", "base");
        let h1 = put_test_entity(&store, "test/type", "local_v");
        let h2 = put_test_entity(&store, "test/type", "remote_v");

        let mut base = BTreeMap::new();
        base.insert("shared".to_string(), h0);
        let mut local = BTreeMap::new();
        local.insert("shared".to_string(), h1);
        let mut remote = BTreeMap::new();
        remote.insert("shared".to_string(), h2);

        let result = merge_snapshots(
            Some(&base), &local, &remote, "data/",
            None, &store, &li, Hash::zero(), Hash::zero(), "test-peer",
        );

        assert!(result.conflicts.is_empty(), "keep-both via config should resolve edit-vs-edit");
        assert_eq!(result.merged_bindings["shared"], h1);
        assert_eq!(result.additional_bindings.len(), 1);
        assert!(result.additional_bindings[0].0.starts_with("shared.keep-both-"));
        assert_eq!(result.additional_bindings[0].1, h2);
    }
}
