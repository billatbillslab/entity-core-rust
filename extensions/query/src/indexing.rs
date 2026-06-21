//! IndexingLocationIndex — LocationIndex decorator for synchronous index updates.
//!
//! Slots between the base LocationIndex and NotifyingLocationIndex in the
//! PeerBuilder chain. Ensures query indexes are updated inline during every
//! `set()` and `remove()`, satisfying spec §3.3 synchronous consistency.

use std::sync::Arc;

use entity_hash::Hash;
use entity_store::{ContentStore, LocationEntry, LocationIndex};

use crate::index::QueryIndexStore;

/// A LocationIndex decorator that synchronously updates query indexes
/// on every mutation.
pub struct IndexingLocationIndex {
    inner: Arc<dyn LocationIndex>,
    content_store: Arc<dyn ContentStore>,
    indexes: Arc<dyn QueryIndexStore>,
}

impl IndexingLocationIndex {
    pub fn new(
        inner: Arc<dyn LocationIndex>,
        content_store: Arc<dyn ContentStore>,
        indexes: Arc<dyn QueryIndexStore>,
    ) -> Self {
        Self {
            inner,
            content_store,
            indexes,
        }
    }
}

impl LocationIndex for IndexingLocationIndex {
    fn set(&self, path: &str, hash: Hash) {
        let previous = self.inner.get(path);

        // Short-circuit if hash unchanged
        if let Some(prev) = previous {
            if prev == hash {
                self.inner.set(path, hash);
                return;
            }
            // Remove old index entries
            self.indexes.remove_entries_for_path(path);
        }

        // Perform the write
        self.inner.set(path, hash);

        // Add new index entries
        if let Some(entity) = self.content_store.get(&hash) {
            self.indexes.add_entries_for_entity(path, &entity);
        }
    }

    fn get(&self, path: &str) -> Option<Hash> {
        self.inner.get(path)
    }

    fn has(&self, path: &str) -> bool {
        self.inner.has(path)
    }

    fn remove(&self, path: &str) -> Option<Hash> {
        self.indexes.remove_entries_for_path(path);
        self.inner.remove(path)
    }

    fn list(&self, prefix: &str) -> Vec<LocationEntry> {
        self.inner.list(prefix)
    }

    fn len_prefix(&self, prefix: &str) -> usize {
        self.inner.len_prefix(prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::QueryIndexes;
    use entity_entity::Entity;
    use entity_store::{MemoryContentStore, MemoryLocationIndex};

    fn make_entity(type_str: &str, data_str: &str) -> Entity {
        Entity::new(type_str, entity_ecf::to_ecf(&entity_ecf::text(data_str))).unwrap()
    }

    #[test]
    fn test_set_updates_indexes() {
        let content_store = Arc::new(MemoryContentStore::new());
        let base_index = Arc::new(MemoryLocationIndex::new());
        let indexes = Arc::new(QueryIndexes::new());
        let indexing = IndexingLocationIndex::new(
            base_index.clone(),
            content_store.clone(),
            indexes.clone(),
        );

        let entity = make_entity("app/user", "alice");
        let hash = content_store.put(entity).unwrap();
        indexing.set("users/alice", hash);

        // Verify index was updated synchronously
        let results = indexes.query_type_index("app/user");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].path, "users/alice");
    }

    #[test]
    fn test_remove_cleans_indexes() {
        let content_store = Arc::new(MemoryContentStore::new());
        let base_index = Arc::new(MemoryLocationIndex::new());
        let indexes = Arc::new(QueryIndexes::new());
        let indexing = IndexingLocationIndex::new(
            base_index.clone(),
            content_store.clone(),
            indexes.clone(),
        );

        let entity = make_entity("app/user", "alice");
        let hash = content_store.put(entity).unwrap();
        indexing.set("users/alice", hash);
        assert_eq!(indexes.query_type_index("app/user").len(), 1);

        indexing.remove("users/alice");
        assert!(indexes.query_type_index("app/user").is_empty());
    }

    #[test]
    fn test_update_replaces_indexes() {
        let content_store = Arc::new(MemoryContentStore::new());
        let base_index = Arc::new(MemoryLocationIndex::new());
        let indexes = Arc::new(QueryIndexes::new());
        let indexing = IndexingLocationIndex::new(
            base_index.clone(),
            content_store.clone(),
            indexes.clone(),
        );

        let e1 = make_entity("app/user", "alice");
        let h1 = content_store.put(e1).unwrap();
        indexing.set("path/x", h1);
        assert_eq!(indexes.query_type_index("app/user").len(), 1);

        let e2 = make_entity("app/order", "order1");
        let h2 = content_store.put(e2).unwrap();
        indexing.set("path/x", h2);
        assert!(indexes.query_type_index("app/user").is_empty());
        assert_eq!(indexes.query_type_index("app/order").len(), 1);
    }

    #[test]
    fn test_same_hash_no_reindex() {
        let content_store = Arc::new(MemoryContentStore::new());
        let base_index = Arc::new(MemoryLocationIndex::new());
        let indexes = Arc::new(QueryIndexes::new());
        let indexing = IndexingLocationIndex::new(
            base_index.clone(),
            content_store.clone(),
            indexes.clone(),
        );

        let entity = make_entity("app/user", "alice");
        let hash = content_store.put(entity).unwrap();
        indexing.set("users/alice", hash);
        indexing.set("users/alice", hash); // same hash — no-op

        assert_eq!(indexes.query_type_index("app/user").len(), 1);
    }

    #[test]
    fn test_delegates_reads() {
        let content_store = Arc::new(MemoryContentStore::new());
        let base_index = Arc::new(MemoryLocationIndex::new());
        let indexes = Arc::new(QueryIndexes::new());
        let indexing = IndexingLocationIndex::new(
            base_index.clone(),
            content_store.clone(),
            indexes.clone(),
        );

        let entity = make_entity("app/user", "alice");
        let hash = content_store.put(entity).unwrap();
        indexing.set("users/alice", hash);

        assert_eq!(indexing.get("users/alice"), Some(hash));
        assert!(indexing.has("users/alice"));
        assert!(!indexing.has("nonexistent"));

        let entries = indexing.list("users/");
        assert_eq!(entries.len(), 1);
    }
}
