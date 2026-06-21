//! Revision DAG — history traversal, common ancestor finding, relationship detection.
//!
//! Pure functions on ContentStore — no mutation, highly testable.
//! Implements EXTENSION-REVISION v2.1 §3.

use std::collections::{HashMap, HashSet, VecDeque};

use entity_entity::Entity;
use entity_hash::Hash;
use entity_store::ContentStore;

// ---------------------------------------------------------------------------
// Revision entry data (structural version entry)
// ---------------------------------------------------------------------------

/// Entity type for revision entries.
pub const TYPE_REVISION_ENTRY: &str = "system/revision/entry";

/// Decoded revision entry data (EXTENSION-REVISION §2.1).
///
/// Structural only: root trie hash + sorted parent hashes.
/// No metadata (author, timestamp, message removed per PROPOSAL-STRUCTURAL-VERSION-ENTRIES).
#[derive(Debug, Clone)]
pub struct RevisionEntryData {
    pub root: Hash,
    pub parents: Vec<Hash>,
}

/// Decode a revision entry entity's CBOR data.
pub fn decode_revision_entry(entity: &Entity) -> Option<RevisionEntryData> {
    let val: ciborium::Value = ciborium::from_reader(entity.data.as_slice()).ok()?;
    let map = val.as_map()?;

    let mut root = None;
    let mut parents = None;

    for (k, v) in map {
        match k.as_text()? {
            "root" => {
                if let ciborium::Value::Bytes(b) = v {
                    root = Hash::from_bytes(b).ok();
                }
            }
            "parents" => {
                if let ciborium::Value::Array(arr) = v {
                    let mut p = Vec::new();
                    for item in arr {
                        if let ciborium::Value::Bytes(b) = item {
                            if let Ok(h) = Hash::from_bytes(b) {
                                p.push(h);
                            }
                        }
                    }
                    parents = Some(p);
                }
            }
            _ => {}
        }
    }

    Some(RevisionEntryData {
        root: root?,
        parents: parents?,
    })
}

/// Build a revision entry entity from RevisionEntryData.
/// ECF-encodes with sorted keys. Parents MUST already be sorted.
pub fn build_revision_entry(data: &RevisionEntryData) -> Result<Entity, String> {
    // ECF key ordering: "parents" (7 chars) > "root" (4 chars), so "root" first.
    let fields = vec![
        (
            entity_ecf::text("parents"),
            entity_ecf::Value::Array(
                data.parents
                    .iter()
                    .map(|h| entity_ecf::Value::Bytes(h.to_bytes().to_vec()))
                    .collect(),
            ),
        ),
        (
            entity_ecf::text("root"),
            entity_ecf::Value::Bytes(data.root.to_bytes().to_vec()),
        ),
    ];

    // Keys are already in ECF order: "root" (4) before "parents" (7)
    // Wait — that's wrong. We need length-first: "root" (4) < "parents" (7) in ECF.
    // But the vec above has "parents" first. Let's sort properly.
    let mut sorted_fields = fields;
    sorted_fields.sort_by(|(a, _), (b, _)| {
        let a_text = if let entity_ecf::Value::Text(s) = a { s.as_str() } else { "" };
        let b_text = if let entity_ecf::Value::Text(s) = b { s.as_str() } else { "" };
        a_text.len().cmp(&b_text.len()).then_with(|| a_text.cmp(b_text))
    });

    let ecf_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(sorted_fields));
    Entity::new(TYPE_REVISION_ENTRY, ecf_data).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// DAG traversal (spec §3.2)
// ---------------------------------------------------------------------------

/// Walk version history from `head` via BFS, returning up to `limit` version hashes.
///
/// If `stop_at` is provided, the walk stops when that hash is encountered (exclusive —
/// the stop_at version itself is NOT included in the result).
pub fn walk_history(
    store: &dyn ContentStore,
    head: Hash,
    limit: usize,
    stop_at: Option<Hash>,
) -> Vec<Hash> {
    let mut result = Vec::new();
    let mut queue = VecDeque::new();
    let mut visited = HashSet::new();

    queue.push_back(head);

    while let Some(current) = queue.pop_front() {
        if result.len() >= limit {
            break;
        }
        if !visited.insert(current) {
            continue;
        }
        if stop_at == Some(current) {
            break;
        }

        let entity = match store.get(&current) {
            Some(e) => e,
            None => continue,
        };
        let entry = match decode_revision_entry(&entity) {
            Some(v) => v,
            None => continue,
        };

        result.push(current);

        for parent in &entry.parents {
            if !visited.contains(parent) {
                queue.push_back(*parent);
            }
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Common ancestor (spec §3.3)
// ---------------------------------------------------------------------------

/// Find the lowest common ancestor of two versions via alternating BFS.
pub fn find_common_ancestor(store: &dyn ContentStore, a: Hash, b: Hash) -> Option<Hash> {
    let mut ancestors_a: HashMap<Hash, usize> = HashMap::new();
    let mut ancestors_b: HashMap<Hash, usize> = HashMap::new();

    let mut queue_a: VecDeque<(Hash, usize)> = VecDeque::new();
    let mut queue_b: VecDeque<(Hash, usize)> = VecDeque::new();

    queue_a.push_back((a, 0));
    queue_b.push_back((b, 0));

    while !queue_a.is_empty() || !queue_b.is_empty() {
        // Expand A
        if let Some((current, depth)) = queue_a.pop_front() {
            if ancestors_b.contains_key(&current) {
                return Some(current);
            }
            if let std::collections::hash_map::Entry::Vacant(e) = ancestors_a.entry(current) {
                e.insert(depth);
                if let Some(entity) = store.get(&current) {
                    if let Some(entry) = decode_revision_entry(&entity) {
                        for parent in &entry.parents {
                            queue_a.push_back((*parent, depth + 1));
                        }
                    }
                }
            }
        }

        // Expand B
        if let Some((current, depth)) = queue_b.pop_front() {
            if ancestors_a.contains_key(&current) {
                return Some(current);
            }
            if let std::collections::hash_map::Entry::Vacant(e) = ancestors_b.entry(current) {
                e.insert(depth);
                if let Some(entity) = store.get(&current) {
                    if let Some(entry) = decode_revision_entry(&entity) {
                        for parent in &entry.parents {
                            queue_b.push_back((*parent, depth + 1));
                        }
                    }
                }
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Ancestor check (spec §3.4)
// ---------------------------------------------------------------------------

/// Check if `potential_ancestor` is an ancestor of `descendant` via BFS.
pub fn is_ancestor(store: &dyn ContentStore, potential_ancestor: Hash, descendant: Hash) -> bool {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(descendant);

    while let Some(current) = queue.pop_front() {
        if current == potential_ancestor {
            return true;
        }
        if !visited.insert(current) {
            continue;
        }
        if let Some(entity) = store.get(&current) {
            if let Some(entry) = decode_revision_entry(&entity) {
                for parent in &entry.parents {
                    queue.push_back(*parent);
                }
            }
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Relationship detection (spec §3.4)
// ---------------------------------------------------------------------------

/// Relationship between local and remote heads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relationship {
    InSync,
    Behind,
    Ahead,
    Diverged,
}

impl Relationship {
    pub fn as_str(&self) -> &'static str {
        match self {
            Relationship::InSync => "in_sync",
            Relationship::Behind => "behind",
            Relationship::Ahead => "ahead",
            Relationship::Diverged => "diverged",
        }
    }
}

/// Check the relationship between local and remote heads.
pub fn check_relationship(
    store: &dyn ContentStore,
    local: Hash,
    remote: Hash,
) -> Relationship {
    if local == remote {
        return Relationship::InSync;
    }
    if is_ancestor(store, local, remote) {
        return Relationship::Behind;
    }
    if is_ancestor(store, remote, local) {
        return Relationship::Ahead;
    }
    Relationship::Diverged
}

// ---------------------------------------------------------------------------
// Oscillation detection (EXTENSION-REVISION §4.4.4)
// ---------------------------------------------------------------------------

/// Detect oscillation: check if `proposed_root` appeared in recent ancestry
/// of `head`, up to `depth_limit` versions back. Returns true if oscillation detected.
pub fn detect_oscillation(
    store: &dyn ContentStore,
    proposed_root: Hash,
    head: Hash,
    depth_limit: usize,
) -> bool {
    let versions = walk_history(store, head, depth_limit, None);
    for version_hash in &versions {
        if let Some(entity) = store.get(version_hash) {
            if let Some(entry) = decode_revision_entry(&entity) {
                if entry.root == proposed_root {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use entity_store::MemoryContentStore;
    use entity_tree::trie;

    fn make_store() -> MemoryContentStore {
        MemoryContentStore::new()
    }

    /// Create a revision entry with the given trie root and parents.
    fn make_revision_entry(
        store: &dyn ContentStore,
        root: Hash,
        parents: Vec<Hash>,
    ) -> Hash {
        let mut sorted = parents;
        trie::sorted_parents(&mut sorted);
        let entry = RevisionEntryData { root, parents: sorted };
        let entity = build_revision_entry(&entry).unwrap();
        store.put(entity).unwrap()
    }

    /// Counter for generating unique versions.
    use std::sync::atomic::{AtomicU32, Ordering};
    static VERSION_COUNTER: AtomicU32 = AtomicU32::new(0);

    /// Create a revision entry with a unique trie root (different binding each time).
    fn make_version(store: &dyn ContentStore, parents: Vec<Hash>) -> Hash {
        let n = VERSION_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut bindings = BTreeMap::new();
        // Use a unique key so each version gets a distinct trie root
        bindings.insert(format!("__unique_{}", n), Hash::zero());
        let root = trie::build_trie(store, &bindings).unwrap();
        make_revision_entry(store, root, parents)
    }

    #[test]
    fn test_revision_entry_roundtrip() {
        let store = make_store();
        let root = trie::build_trie(&store, &BTreeMap::new()).unwrap();

        let entry = RevisionEntryData {
            root,
            parents: vec![],
        };
        let entity = build_revision_entry(&entry).unwrap();
        let decoded = decode_revision_entry(&entity).unwrap();

        assert_eq!(decoded.root, root);
        assert!(decoded.parents.is_empty());
    }

    #[test]
    fn test_revision_entry_with_parents() {
        let store = make_store();
        let root = trie::build_trie(&store, &BTreeMap::new()).unwrap();
        let parent1 = make_version(&store, vec![]);
        let parent2 = make_version(&store, vec![]);

        let mut parents = vec![parent2, parent1];
        trie::sorted_parents(&mut parents);

        let entry = RevisionEntryData { root, parents: parents.clone() };
        let entity = build_revision_entry(&entry).unwrap();
        let decoded = decode_revision_entry(&entity).unwrap();

        assert_eq!(decoded.parents, parents);
    }

    #[test]
    fn test_walk_history_linear() {
        let store = make_store();
        let v1 = make_version(&store, vec![]);
        let v2 = make_version(&store, vec![v1]);
        let v3 = make_version(&store, vec![v2]);

        let history = walk_history(&store, v3, 10, None);
        assert_eq!(history.len(), 3);
        assert_eq!(history[0], v3);
        assert_eq!(history[1], v2);
        assert_eq!(history[2], v1);
    }

    #[test]
    fn test_walk_history_with_limit() {
        let store = make_store();
        let v1 = make_version(&store, vec![]);
        let v2 = make_version(&store, vec![v1]);
        let v3 = make_version(&store, vec![v2]);

        let history = walk_history(&store, v3, 2, None);
        assert_eq!(history.len(), 2);
    }

    #[test]
    fn test_walk_history_diamond() {
        let store = make_store();
        let root = make_version(&store, vec![]);
        let left = make_version(&store, vec![root]);
        let right = make_version(&store, vec![root]);
        let merge = make_version(&store, vec![left, right]);

        let history = walk_history(&store, merge, 10, None);
        assert_eq!(history.len(), 4);
    }

    #[test]
    fn test_walk_history_stop_at() {
        let store = make_store();
        let v1 = make_version(&store, vec![]);
        let v2 = make_version(&store, vec![v1]);
        let v3 = make_version(&store, vec![v2]);

        // Stop at v1 — should return only v3 and v2
        let history = walk_history(&store, v3, 10, Some(v1));
        assert_eq!(history.len(), 2);
        assert_eq!(history[0], v3);
        assert_eq!(history[1], v2);
    }

    #[test]
    fn test_find_common_ancestor_linear() {
        let store = make_store();
        let v1 = make_version(&store, vec![]);
        let v2 = make_version(&store, vec![v1]);
        let v3 = make_version(&store, vec![v2]);

        let ancestor = find_common_ancestor(&store, v2, v3);
        assert_eq!(ancestor, Some(v2));
    }

    #[test]
    fn test_find_common_ancestor_diverged() {
        let store = make_store();
        let root = make_version(&store, vec![]);
        let left = make_version(&store, vec![root]);
        let right = make_version(&store, vec![root]);

        let ancestor = find_common_ancestor(&store, left, right);
        assert_eq!(ancestor, Some(root));
    }

    #[test]
    fn test_find_common_ancestor_none() {
        let store = make_store();
        let a = make_version(&store, vec![]);
        let b = make_version(&store, vec![]);

        let ancestor = find_common_ancestor(&store, a, b);
        assert_eq!(ancestor, None);
    }

    #[test]
    fn test_is_ancestor() {
        let store = make_store();
        let v1 = make_version(&store, vec![]);
        let v2 = make_version(&store, vec![v1]);
        let v3 = make_version(&store, vec![v2]);

        assert!(is_ancestor(&store, v1, v3));
        assert!(is_ancestor(&store, v2, v3));
        assert!(!is_ancestor(&store, v3, v1));
    }

    #[test]
    fn test_check_relationship_all_cases() {
        let store = make_store();
        let root = make_version(&store, vec![]);
        let left = make_version(&store, vec![root]);
        let right = make_version(&store, vec![root]);

        assert_eq!(check_relationship(&store, root, root), Relationship::InSync);
        assert_eq!(check_relationship(&store, root, left), Relationship::Behind);
        assert_eq!(check_relationship(&store, left, root), Relationship::Ahead);
        assert_eq!(check_relationship(&store, left, right), Relationship::Diverged);
    }

    #[test]
    fn test_detect_oscillation() {
        let store = make_store();
        let mut bindings = BTreeMap::new();
        bindings.insert("a".to_string(), Hash::zero());
        let root_a = trie::build_trie(&store, &bindings).unwrap();

        let v1 = make_revision_entry(&store, root_a, vec![]);

        // v2 has different root
        let mut bindings2 = BTreeMap::new();
        bindings2.insert("b".to_string(), Hash::zero());
        let root_b = trie::build_trie(&store, &bindings2).unwrap();
        let v2 = make_revision_entry(&store, root_b, vec![v1]);

        // Proposing root_a again should detect oscillation
        assert!(detect_oscillation(&store, root_a, v2, 4));
        // Proposing a novel root should not
        let mut bindings3 = BTreeMap::new();
        bindings3.insert("c".to_string(), Hash::zero());
        let root_c = trie::build_trie(&store, &bindings3).unwrap();
        assert!(!detect_oscillation(&store, root_c, v2, 4));
    }

}
