//! SQLite-backed query indexes.
//!
//! Stores type, reverse hash, and path link indexes in SQL tables
//! within the same database as content/locations. No rebuild needed
//! on restart — indexes are persistent.

use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection};

use entity_entity::Entity;
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex, StoreError};
use entity_types::TypeRegistry;

use crate::index::{QueryIndexStore, RefEntry, TypeIndexEntry};
use crate::walker;

/// Query indexes stored in SQLite tables.
///
/// Shares the same database connection as `SqliteContentStore` and
/// `SqliteLocationIndex`. Created via `SqliteStore::connection()`.
pub struct SqliteQueryIndexes {
    conn: Arc<Mutex<Connection>>,
    type_registry: TypeRegistry,
}

impl SqliteQueryIndexes {
    /// Create query index tables in the given database.
    pub fn new(conn: Arc<Mutex<Connection>>) -> Result<Self, StoreError> {
        {
            let db = conn.lock().unwrap();
            db.execute_batch(
                "CREATE TABLE IF NOT EXISTS query_type_index (
                     entity_type TEXT NOT NULL,
                     path        TEXT NOT NULL,
                     hash        BLOB NOT NULL,
                     PRIMARY KEY (path)
                 );
                 CREATE INDEX IF NOT EXISTS idx_query_type ON query_type_index(entity_type);

                 CREATE TABLE IF NOT EXISTS query_reverse_hash (
                     ref_hash    BLOB NOT NULL,
                     source_path TEXT NOT NULL,
                     source_type TEXT NOT NULL,
                     field_name  TEXT NOT NULL,
                     PRIMARY KEY (ref_hash, source_path, field_name)
                 );
                 CREATE INDEX IF NOT EXISTS idx_ref_hash ON query_reverse_hash(ref_hash);

                 CREATE TABLE IF NOT EXISTS query_path_link (
                     ref_path    TEXT NOT NULL,
                     source_path TEXT NOT NULL,
                     source_type TEXT NOT NULL,
                     field_name  TEXT NOT NULL,
                     PRIMARY KEY (ref_path, source_path, field_name)
                 );
                 CREATE INDEX IF NOT EXISTS idx_ref_path ON query_path_link(ref_path);",
            )
            .map_err(|e| StoreError::Internal(format!("query index init: {e}")))?;
        }

        let type_registry = TypeRegistry::new();
        entity_types::register_core_types(&type_registry);

        Ok(Self {
            conn,
            type_registry,
        })
    }
}

impl QueryIndexStore for SqliteQueryIndexes {
    fn add_entries_for_entity(&self, path: &str, entity: &Entity) {
        let conn = self.conn.lock().unwrap();
        let hash_bytes = entity.content_hash.to_bytes();

        // Type index
        conn.execute(
            "INSERT OR REPLACE INTO query_type_index (entity_type, path, hash) VALUES (?1, ?2, ?3)",
            params![entity.entity_type, path, hash_bytes.as_slice()],
        )
        .expect("sqlite query type index insert failed");

        // Reverse hash index
        let hash_refs = walker::extract_hash_refs(&entity.data);
        for (ref_hash, field_name) in &hash_refs {
            let ref_bytes = ref_hash.to_bytes();
            conn.execute(
                "INSERT OR REPLACE INTO query_reverse_hash (ref_hash, source_path, source_type, field_name) VALUES (?1, ?2, ?3, ?4)",
                params![ref_bytes.as_slice(), path, entity.entity_type, field_name],
            )
            .expect("sqlite query reverse hash insert failed");
        }

        // Path link index
        let path_refs =
            walker::extract_path_refs(&entity.data, &entity.entity_type, &self.type_registry);
        for (ref_path, field_name) in &path_refs {
            conn.execute(
                "INSERT OR REPLACE INTO query_path_link (ref_path, source_path, source_type, field_name) VALUES (?1, ?2, ?3, ?4)",
                params![ref_path, path, entity.entity_type, field_name],
            )
            .expect("sqlite query path link insert failed");
        }
    }

    fn remove_entries_for_path(&self, path: &str) {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM query_type_index WHERE path = ?1", params![path])
            .expect("sqlite query type index delete failed");
        conn.execute(
            "DELETE FROM query_reverse_hash WHERE source_path = ?1",
            params![path],
        )
        .expect("sqlite query reverse hash delete failed");
        conn.execute(
            "DELETE FROM query_path_link WHERE source_path = ?1",
            params![path],
        )
        .expect("sqlite query path link delete failed");
    }

    fn query_type_index(&self, type_filter: &str) -> Vec<TypeIndexEntry> {
        let conn = self.conn.lock().unwrap();

        if type_filter == "*" {
            let mut stmt = conn
                .prepare("SELECT path, hash FROM query_type_index ORDER BY path")
                .expect("sqlite query type index select all failed");
            return stmt
                .query_map([], |row| {
                    let path: String = row.get(0)?;
                    let hash_bytes: Vec<u8> = row.get(1)?;
                    Ok((path, hash_bytes))
                })
                .expect("sqlite query type index query failed")
                .filter_map(|r| {
                    let (path, hash_bytes) = r.ok()?;
                    let hash = Hash::from_bytes(&hash_bytes).ok()?;
                    Some(TypeIndexEntry { path, hash })
                })
                .collect();
        }

        if let Some(prefix) = type_filter.strip_suffix("/*") {
            let like_pattern = format!("{}/%%", prefix);
            let mut stmt = conn
                .prepare(
                    "SELECT path, hash FROM query_type_index WHERE entity_type LIKE ?1 ORDER BY path",
                )
                .expect("sqlite query type index select glob failed");
            return stmt
                .query_map(params![like_pattern], |row| {
                    let path: String = row.get(0)?;
                    let hash_bytes: Vec<u8> = row.get(1)?;
                    Ok((path, hash_bytes))
                })
                .expect("sqlite query type index glob failed")
                .filter_map(|r| {
                    let (path, hash_bytes) = r.ok()?;
                    let hash = Hash::from_bytes(&hash_bytes).ok()?;
                    Some(TypeIndexEntry { path, hash })
                })
                .collect();
        }

        // Exact match
        let mut stmt = conn
            .prepare(
                "SELECT path, hash FROM query_type_index WHERE entity_type = ?1 ORDER BY path",
            )
            .expect("sqlite query type index select exact failed");
        stmt.query_map(params![type_filter], |row| {
            let path: String = row.get(0)?;
            let hash_bytes: Vec<u8> = row.get(1)?;
            Ok((path, hash_bytes))
        })
        .expect("sqlite query type index exact failed")
        .filter_map(|r| {
            let (path, hash_bytes) = r.ok()?;
            let hash = Hash::from_bytes(&hash_bytes).ok()?;
            Some(TypeIndexEntry { path, hash })
        })
        .collect()
    }

    fn query_reverse_index(&self, hash: &Hash) -> Vec<RefEntry> {
        let hash_bytes = hash.to_bytes();
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT source_path, source_type, field_name FROM query_reverse_hash WHERE ref_hash = ?1",
            )
            .expect("sqlite query reverse hash select failed");
        stmt.query_map(params![hash_bytes.as_slice()], |row| {
            Ok(RefEntry {
                source_path: row.get(0)?,
                source_type: row.get(1)?,
                field_name: row.get(2)?,
            })
        })
        .expect("sqlite query reverse hash query failed")
        .filter_map(|r| r.ok())
        .collect()
    }

    fn query_path_link_index(&self, path: &str) -> Vec<RefEntry> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT source_path, source_type, field_name FROM query_path_link WHERE ref_path = ?1",
            )
            .expect("sqlite query path link select failed");
        stmt.query_map(params![path], |row| {
            Ok(RefEntry {
                source_path: row.get(0)?,
                source_type: row.get(1)?,
                field_name: row.get(2)?,
            })
        })
        .expect("sqlite query path link query failed")
        .filter_map(|r| r.ok())
        .collect()
    }

    fn rebuild(&self, location_index: &dyn LocationIndex, content_store: &dyn ContentStore) {
        self.clear();
        for entry in location_index.list("") {
            if let Some(entity) = content_store.get(&entry.hash) {
                self.add_entries_for_entity(&entry.path, &entity);
            }
        }
    }

    fn clear(&self) {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM query_type_index", [])
            .expect("sqlite query type index clear failed");
        conn.execute("DELETE FROM query_reverse_hash", [])
            .expect("sqlite query reverse hash clear failed");
        conn.execute("DELETE FROM query_path_link", [])
            .expect("sqlite query path link clear failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_entity::Entity;
    use entity_store::sqlite::SqliteStore;

    fn make_entity(type_str: &str, data: entity_ecf::Value) -> Entity {
        Entity::new(type_str, entity_ecf::to_ecf(&data)).unwrap()
    }

    fn test_indexes() -> SqliteQueryIndexes {
        let store = SqliteStore::open_in_memory().unwrap();
        SqliteQueryIndexes::new(store.connection()).unwrap()
    }

    #[test]
    fn test_type_index_add_query() {
        let idx = test_indexes();
        let e1 = make_entity("app/user", entity_ecf::cbor_map! { "name" => entity_ecf::text("alice") });
        let e2 = make_entity("app/user", entity_ecf::cbor_map! { "name" => entity_ecf::text("bob") });
        let e3 = make_entity("app/order", entity_ecf::cbor_map! { "id" => entity_ecf::text("o1") });

        idx.add_entries_for_entity("users/alice", &e1);
        idx.add_entries_for_entity("users/bob", &e2);
        idx.add_entries_for_entity("orders/o1", &e3);

        assert_eq!(idx.query_type_index("app/user").len(), 2);
        assert_eq!(idx.query_type_index("app/order").len(), 1);
        assert_eq!(idx.query_type_index("app/*").len(), 3);
        assert_eq!(idx.query_type_index("*").len(), 3);
        assert!(idx.query_type_index("other/type").is_empty());
    }

    #[test]
    fn test_type_index_remove() {
        let idx = test_indexes();
        let entity = make_entity("app/user", entity_ecf::cbor_map! { "name" => entity_ecf::text("alice") });
        idx.add_entries_for_entity("users/alice", &entity);
        assert_eq!(idx.query_type_index("app/user").len(), 1);

        idx.remove_entries_for_path("users/alice");
        assert!(idx.query_type_index("app/user").is_empty());
    }

    #[test]
    fn test_reverse_hash_index() {
        let idx = test_indexes();
        let target_hash = Hash::compute("target", b"some data");
        let entity = make_entity(
            "app/reference",
            entity_ecf::cbor_map! {
                "target" => entity_ecf::Value::Bytes(target_hash.to_bytes().to_vec())
            },
        );
        idx.add_entries_for_entity("refs/r1", &entity);

        let refs = idx.query_reverse_index(&target_hash);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].source_path, "refs/r1");
        assert_eq!(refs[0].source_type, "app/reference");
        assert_eq!(refs[0].field_name, "target");
    }

    #[test]
    fn test_reverse_hash_index_remove() {
        let idx = test_indexes();
        let target = Hash::compute("target", b"data");
        let entity = make_entity(
            "app/ref",
            entity_ecf::cbor_map! {
                "ref" => entity_ecf::Value::Bytes(target.to_bytes().to_vec())
            },
        );
        idx.add_entries_for_entity("refs/r1", &entity);
        assert_eq!(idx.query_reverse_index(&target).len(), 1);

        idx.remove_entries_for_path("refs/r1");
        assert!(idx.query_reverse_index(&target).is_empty());
    }

    #[test]
    fn test_update_entity_at_path() {
        let idx = test_indexes();
        let e1 = make_entity("app/user", entity_ecf::cbor_map! { "name" => entity_ecf::text("alice") });
        let e2 = make_entity("app/order", entity_ecf::cbor_map! { "id" => entity_ecf::text("o1") });

        idx.add_entries_for_entity("path/x", &e1);
        assert_eq!(idx.query_type_index("app/user").len(), 1);

        // Simulate update: remove old, add new
        idx.remove_entries_for_path("path/x");
        idx.add_entries_for_entity("path/x", &e2);
        assert!(idx.query_type_index("app/user").is_empty());
        assert_eq!(idx.query_type_index("app/order").len(), 1);
    }

    #[test]
    fn test_clear() {
        let idx = test_indexes();
        let entity = make_entity("app/user", entity_ecf::cbor_map! { "name" => entity_ecf::text("a") });
        idx.add_entries_for_entity("users/a", &entity);
        assert_eq!(idx.query_type_index("*").len(), 1);

        idx.clear();
        assert!(idx.query_type_index("*").is_empty());
    }

    #[test]
    fn test_persistence() {
        // Use a file-backed SQLite to verify indexes survive reconnection
        let dir = std::env::temp_dir().join(format!("entity_query_sqlite_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("test.db");

        {
            let store = SqliteStore::open(&db_path).unwrap();
            let idx = SqliteQueryIndexes::new(store.connection()).unwrap();
            let entity = make_entity("app/user", entity_ecf::cbor_map! { "name" => entity_ecf::text("alice") });
            idx.add_entries_for_entity("users/alice", &entity);
        }

        // Reopen — indexes should persist
        {
            let store = SqliteStore::open(&db_path).unwrap();
            let idx = SqliteQueryIndexes::new(store.connection()).unwrap();
            let results = idx.query_type_index("app/user");
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].path, "users/alice");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
