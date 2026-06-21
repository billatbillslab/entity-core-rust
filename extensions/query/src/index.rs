//! In-memory secondary indexes for the query extension.
//!
//! Three indexes (spec §2):
//! - Type index: type_name → set of {path, hash}
//! - Reverse hash index: referenced_hash → set of {source_path, source_type, field_name}
//! - Path link index: referenced_path → set of {source_path, source_type, field_name}

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::RwLock;

use entity_entity::Entity;
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};
use entity_types::TypeRegistry;

use crate::walker;

// ---------------------------------------------------------------------------
// Index entry types
// ---------------------------------------------------------------------------

/// Entry in the type index.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeIndexEntry {
    pub path: String,
    pub hash: Hash,
}

/// Entry in the reverse hash / path link indexes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefEntry {
    pub source_path: String,
    pub source_type: String,
    pub field_name: String,
}

// ---------------------------------------------------------------------------
// QueryIndexStore trait
// ---------------------------------------------------------------------------

/// Abstraction over query index storage. Implementations may use in-memory
/// data structures (`QueryIndexes`) or a persistent backend
/// (`SqliteQueryIndexes`).
pub trait QueryIndexStore: Send + Sync {
    /// Add index entries for an entity bound at the given path.
    fn add_entries_for_entity(&self, path: &str, entity: &Entity);
    /// Remove all index entries for an entity at the given path.
    fn remove_entries_for_path(&self, path: &str);
    /// Query the type index. Supports exact match and glob (`*`, `prefix/*`).
    fn query_type_index(&self, type_filter: &str) -> Vec<TypeIndexEntry>;
    /// Query the reverse hash index.
    fn query_reverse_index(&self, hash: &Hash) -> Vec<RefEntry>;
    /// Query the path link index.
    fn query_path_link_index(&self, path: &str) -> Vec<RefEntry>;
    /// Rebuild all indexes from a full scan of the tree + content store.
    fn rebuild(&self, location_index: &dyn LocationIndex, content_store: &dyn ContentStore);
    /// Clear all indexes.
    fn clear(&self);
}

// ---------------------------------------------------------------------------
// QueryIndexes — in-memory implementation
// ---------------------------------------------------------------------------

/// In-memory secondary indexes maintained synchronously with tree writes.
pub struct QueryIndexes {
    /// type_name → set of {path, hash}
    type_index: RwLock<BTreeMap<String, BTreeSet<TypeIndexEntry>>>,
    /// referenced_hash → set of referrers
    reverse_hash_index: RwLock<HashMap<Hash, BTreeSet<RefEntry>>>,
    /// referenced_path → set of referrers
    path_link_index: RwLock<BTreeMap<String, BTreeSet<RefEntry>>>,

    // Caches for efficient removal — avoids content store re-lookup on update/delete
    /// path → entity_type
    path_type_cache: RwLock<BTreeMap<String, String>>,
    /// path → [(referenced_hash, field_name)]
    path_hash_refs_cache: RwLock<BTreeMap<String, Vec<(Hash, String)>>>,
    /// path → [(referenced_path, field_name)]
    path_link_refs_cache: RwLock<BTreeMap<String, Vec<(String, String)>>>,

    /// Type registry for path link index (type-aware walking)
    type_registry: TypeRegistry,
}

impl Default for QueryIndexes {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryIndexes {
    pub fn new() -> Self {
        let type_registry = TypeRegistry::new();
        entity_types::register_core_types(&type_registry);
        Self {
            type_index: RwLock::new(BTreeMap::new()),
            reverse_hash_index: RwLock::new(HashMap::new()),
            path_link_index: RwLock::new(BTreeMap::new()),
            path_type_cache: RwLock::new(BTreeMap::new()),
            path_hash_refs_cache: RwLock::new(BTreeMap::new()),
            path_link_refs_cache: RwLock::new(BTreeMap::new()),
            type_registry,
        }
    }
}

impl QueryIndexStore for QueryIndexes {
    fn add_entries_for_entity(&self, path: &str, entity: &Entity) {
        let entity_type = &entity.entity_type;

        // Type index
        {
            let mut idx = self.type_index.write().unwrap();
            idx.entry(entity_type.clone())
                .or_default()
                .insert(TypeIndexEntry {
                    path: path.to_string(),
                    hash: entity.content_hash,
                });
        }

        // Cache type for removal
        self.path_type_cache
            .write()
            .unwrap()
            .insert(path.to_string(), entity_type.clone());

        // Reverse hash index — scan CBOR for hash references
        let hash_refs = walker::extract_hash_refs(&entity.data);
        if !hash_refs.is_empty() {
            let mut idx = self.reverse_hash_index.write().unwrap();
            for (ref_hash, field_name) in &hash_refs {
                idx.entry(*ref_hash).or_default().insert(RefEntry {
                    source_path: path.to_string(),
                    source_type: entity_type.clone(),
                    field_name: field_name.clone(),
                });
            }
        }
        self.path_hash_refs_cache
            .write()
            .unwrap()
            .insert(path.to_string(), hash_refs);

        // Path link index — type-aware walking
        let path_refs =
            walker::extract_path_refs(&entity.data, entity_type, &self.type_registry);
        if !path_refs.is_empty() {
            let mut idx = self.path_link_index.write().unwrap();
            for (ref_path, field_name) in &path_refs {
                idx.entry(ref_path.clone()).or_default().insert(RefEntry {
                    source_path: path.to_string(),
                    source_type: entity_type.clone(),
                    field_name: field_name.clone(),
                });
            }
        }
        self.path_link_refs_cache
            .write()
            .unwrap()
            .insert(path.to_string(), path_refs);
    }

    fn remove_entries_for_path(&self, path: &str) {
        // Remove from type index using cached type
        if let Some(entity_type) = self.path_type_cache.write().unwrap().remove(path) {
            let mut idx = self.type_index.write().unwrap();
            if let Some(entries) = idx.get_mut(&entity_type) {
                entries.retain(|e| e.path != path);
                if entries.is_empty() {
                    idx.remove(&entity_type);
                }
            }
        }

        // Remove from reverse hash index using cached refs
        if let Some(hash_refs) = self.path_hash_refs_cache.write().unwrap().remove(path) {
            let mut idx = self.reverse_hash_index.write().unwrap();
            for (ref_hash, _) in &hash_refs {
                if let Some(entries) = idx.get_mut(ref_hash) {
                    entries.retain(|e| e.source_path != path);
                    if entries.is_empty() {
                        idx.remove(ref_hash);
                    }
                }
            }
        }

        // Remove from path link index using cached refs
        if let Some(link_refs) = self.path_link_refs_cache.write().unwrap().remove(path) {
            let mut idx = self.path_link_index.write().unwrap();
            for (ref_path, _) in &link_refs {
                if let Some(entries) = idx.get_mut(ref_path) {
                    entries.retain(|e| e.source_path != path);
                    if entries.is_empty() {
                        idx.remove(ref_path);
                    }
                }
            }
        }
    }

    fn query_type_index(&self, type_filter: &str) -> Vec<TypeIndexEntry> {
        let idx = self.type_index.read().unwrap();

        if type_filter == "*" {
            // Match all types
            return idx.values().flat_map(|s| s.iter().cloned()).collect();
        }

        if let Some(prefix) = type_filter.strip_suffix("/*") {
            // Prefix glob
            let prefix_with_slash = format!("{}/", prefix);
            return idx
                .range(prefix_with_slash.clone()..)
                .take_while(|(k, _)| k.starts_with(&prefix_with_slash))
                .flat_map(|(_, entries)| entries.iter().cloned())
                .collect();
        }

        // Exact match
        idx.get(type_filter)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    fn query_reverse_index(&self, hash: &Hash) -> Vec<RefEntry> {
        self.reverse_hash_index
            .read()
            .unwrap()
            .get(hash)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    fn query_path_link_index(&self, path: &str) -> Vec<RefEntry> {
        self.path_link_index
            .read()
            .unwrap()
            .get(path)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    fn rebuild(
        &self,
        location_index: &dyn LocationIndex,
        content_store: &dyn ContentStore,
    ) {
        self.clear();
        for entry in location_index.list("") {
            if let Some(entity) = content_store.get(&entry.hash) {
                self.add_entries_for_entity(&entry.path, &entity);
            }
        }
    }

    fn clear(&self) {
        self.type_index.write().unwrap().clear();
        self.reverse_hash_index.write().unwrap().clear();
        self.path_link_index.write().unwrap().clear();
        self.path_type_cache.write().unwrap().clear();
        self.path_hash_refs_cache.write().unwrap().clear();
        self.path_link_refs_cache.write().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_entity::Entity;
    use entity_hash::Hash;

    fn make_entity(type_str: &str, data: entity_ecf::Value) -> Entity {
        Entity::new(type_str, entity_ecf::to_ecf(&data)).unwrap()
    }

    #[test]
    fn test_type_index_add_query() {
        let indexes = QueryIndexes::new();
        let e1 = make_entity("app/user", entity_ecf::cbor_map! { "name" => entity_ecf::text("alice") });
        let e2 = make_entity("app/user", entity_ecf::cbor_map! { "name" => entity_ecf::text("bob") });
        let e3 = make_entity("app/order", entity_ecf::cbor_map! { "id" => entity_ecf::text("o1") });

        indexes.add_entries_for_entity("users/alice", &e1);
        indexes.add_entries_for_entity("users/bob", &e2);
        indexes.add_entries_for_entity("orders/o1", &e3);

        let users = indexes.query_type_index("app/user");
        assert_eq!(users.len(), 2);

        let orders = indexes.query_type_index("app/order");
        assert_eq!(orders.len(), 1);

        let all_app = indexes.query_type_index("app/*");
        assert_eq!(all_app.len(), 3);

        let all = indexes.query_type_index("*");
        assert_eq!(all.len(), 3);

        let none = indexes.query_type_index("other/type");
        assert!(none.is_empty());
    }

    #[test]
    fn test_type_index_remove() {
        let indexes = QueryIndexes::new();
        let entity = make_entity("app/user", entity_ecf::cbor_map! { "name" => entity_ecf::text("alice") });
        indexes.add_entries_for_entity("users/alice", &entity);
        assert_eq!(indexes.query_type_index("app/user").len(), 1);

        indexes.remove_entries_for_path("users/alice");
        assert!(indexes.query_type_index("app/user").is_empty());
    }

    #[test]
    fn test_reverse_hash_index() {
        let indexes = QueryIndexes::new();
        let target_hash = Hash::compute("target", b"some data");
        let entity = make_entity(
            "app/reference",
            entity_ecf::cbor_map! {
                "target" => entity_ecf::Value::Bytes(target_hash.to_bytes().to_vec())
            },
        );
        indexes.add_entries_for_entity("refs/r1", &entity);

        let refs = indexes.query_reverse_index(&target_hash);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].source_path, "refs/r1");
        assert_eq!(refs[0].source_type, "app/reference");
        assert_eq!(refs[0].field_name, "target");
    }

    #[test]
    fn test_reverse_hash_index_remove() {
        let indexes = QueryIndexes::new();
        let target = Hash::compute("target", b"data");
        let entity = make_entity(
            "app/ref",
            entity_ecf::cbor_map! {
                "ref" => entity_ecf::Value::Bytes(target.to_bytes().to_vec())
            },
        );
        indexes.add_entries_for_entity("refs/r1", &entity);
        assert_eq!(indexes.query_reverse_index(&target).len(), 1);

        indexes.remove_entries_for_path("refs/r1");
        assert!(indexes.query_reverse_index(&target).is_empty());
    }

    #[test]
    fn test_update_entity_at_path() {
        let indexes = QueryIndexes::new();
        let e1 = make_entity("app/user", entity_ecf::cbor_map! { "name" => entity_ecf::text("alice") });
        let e2 = make_entity("app/order", entity_ecf::cbor_map! { "id" => entity_ecf::text("o1") });

        indexes.add_entries_for_entity("path/x", &e1);
        assert_eq!(indexes.query_type_index("app/user").len(), 1);

        // Simulate update: remove old, add new
        indexes.remove_entries_for_path("path/x");
        indexes.add_entries_for_entity("path/x", &e2);
        assert!(indexes.query_type_index("app/user").is_empty());
        assert_eq!(indexes.query_type_index("app/order").len(), 1);
    }

    #[test]
    fn test_rebuild() {
        let content_store = entity_store::MemoryContentStore::new();
        let location_index = entity_store::MemoryLocationIndex::new();

        let e1 = make_entity("app/a", entity_ecf::cbor_map! { "x" => entity_ecf::text("1") });
        let h1 = content_store.put(e1).unwrap();
        location_index.set("path/a", h1);

        let e2 = make_entity("app/b", entity_ecf::cbor_map! { "x" => entity_ecf::text("2") });
        let h2 = content_store.put(e2).unwrap();
        location_index.set("path/b", h2);

        let indexes = QueryIndexes::new();
        indexes.rebuild(&location_index, &content_store);

        assert_eq!(indexes.query_type_index("app/a").len(), 1);
        assert_eq!(indexes.query_type_index("app/b").len(), 1);
        assert_eq!(indexes.query_type_index("*").len(), 2);
    }

    #[test]
    fn test_clear() {
        let indexes = QueryIndexes::new();
        let entity = make_entity("app/user", entity_ecf::cbor_map! { "name" => entity_ecf::text("a") });
        indexes.add_entries_for_entity("users/a", &entity);
        assert_eq!(indexes.query_type_index("*").len(), 1);

        indexes.clear();
        assert!(indexes.query_type_index("*").is_empty());
    }
}
