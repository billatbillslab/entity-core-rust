//! SQLite-backed ContentStore and LocationIndex implementations.
//!
//! Feature-gated behind `sqlite`. Provides durable persistence with
//! WAL mode for concurrent read access.

use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection, OptionalExtension};

use entity_entity::Entity;
use entity_hash::Hash;

use crate::{CasError, ContentStore, LocationEntry, LocationIndex, StoreError};

// ---------------------------------------------------------------------------
// SqliteStore — factory holding a shared connection
// ---------------------------------------------------------------------------

/// Factory that opens a SQLite database and produces both `ContentStore` and
/// `LocationIndex` implementations sharing the same connection.
pub struct SqliteStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteStore {
    /// Open (or create) a SQLite database at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let conn = Connection::open(path)
            .map_err(|e| StoreError::Internal(format!("sqlite open: {e}")))?;
        Self::init(conn)
    }

    /// Create an in-memory SQLite database (useful for tests).
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| StoreError::Internal(format!("sqlite open_in_memory: {e}")))?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self, StoreError> {
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS entities (
                 hash        BLOB PRIMARY KEY,
                 entity_type TEXT NOT NULL,
                 data        BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS locations (
                 path TEXT PRIMARY KEY,
                 hash BLOB NOT NULL
             );",
        )
        .map_err(|e| StoreError::Internal(format!("sqlite init: {e}")))?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Get a clone of the shared database connection.
    ///
    /// Extensions (e.g., query indexes) can use this to create additional
    /// tables in the same database, sharing the connection.
    pub fn connection(&self) -> Arc<Mutex<Connection>> {
        self.conn.clone()
    }

    /// Get a `SqliteContentStore` sharing this database connection.
    pub fn content_store(&self) -> SqliteContentStore {
        SqliteContentStore {
            conn: self.conn.clone(),
        }
    }

    /// Get a `SqliteLocationIndex` sharing this database connection.
    pub fn location_index(&self) -> SqliteLocationIndex {
        SqliteLocationIndex {
            conn: self.conn.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// SqliteContentStore
// ---------------------------------------------------------------------------

/// Content-addressed entity store backed by SQLite.
pub struct SqliteContentStore {
    conn: Arc<Mutex<Connection>>,
}

impl ContentStore for SqliteContentStore {
    fn put(&self, entity: Entity) -> Result<Hash, StoreError> {
        let hash_bytes = entity.content_hash.to_bytes();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO entities (hash, entity_type, data) VALUES (?1, ?2, ?3)",
            params![hash_bytes.as_slice(), entity.entity_type, entity.data],
        )
        .map_err(|e| StoreError::Internal(format!("sqlite put: {e}")))?;
        Ok(entity.content_hash)
    }

    fn get(&self, hash: &Hash) -> Option<Entity> {
        let hash_bytes = hash.to_bytes();
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT entity_type, data FROM entities WHERE hash = ?1",
            params![hash_bytes.as_slice()],
            |row| {
                let entity_type: String = row.get(0)?;
                let data: Vec<u8> = row.get(1)?;
                Ok((entity_type, data))
            },
        )
        .optional()
        .expect("sqlite get query failed")
        .map(|(entity_type, data)| Entity {
            entity_type,
            data,
            content_hash: *hash,
        })
    }

    fn has(&self, hash: &Hash) -> bool {
        let hash_bytes = hash.to_bytes();
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT 1 FROM entities WHERE hash = ?1",
            params![hash_bytes.as_slice()],
            |_| Ok(()),
        )
        .optional()
        .expect("sqlite has query failed")
        .is_some()
    }

    fn remove(&self, hash: &Hash) -> bool {
        let hash_bytes = hash.to_bytes();
        let conn = self.conn.lock().unwrap();
        let count = conn
            .execute(
                "DELETE FROM entities WHERE hash = ?1",
                params![hash_bytes.as_slice()],
            )
            .expect("sqlite remove failed");
        count > 0
    }

    fn len(&self) -> usize {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM entities", [], |row| row.get::<_, i64>(0))
            .expect("sqlite len failed") as usize
    }
}

// ---------------------------------------------------------------------------
// SqliteLocationIndex
// ---------------------------------------------------------------------------

/// Path → hash index backed by SQLite.
pub struct SqliteLocationIndex {
    conn: Arc<Mutex<Connection>>,
}

impl LocationIndex for SqliteLocationIndex {
    fn set(&self, path: &str, hash: Hash) {
        let hash_bytes = hash.to_bytes();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO locations (path, hash) VALUES (?1, ?2)",
            params![path, hash_bytes.as_slice()],
        )
        .expect("sqlite location set failed");
    }

    fn get(&self, path: &str) -> Option<Hash> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT hash FROM locations WHERE path = ?1",
            params![path],
            |row| {
                let bytes: Vec<u8> = row.get(0)?;
                Ok(bytes)
            },
        )
        .optional()
        .expect("sqlite location get query failed")
        .and_then(|bytes| Hash::from_bytes(&bytes).ok())
    }

    fn has(&self, path: &str) -> bool {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT 1 FROM locations WHERE path = ?1",
            params![path],
            |_| Ok(()),
        )
        .optional()
        .expect("sqlite location has query failed")
        .is_some()
    }

    fn remove(&self, path: &str) -> Option<Hash> {
        let conn = self.conn.lock().unwrap();
        // Get the hash before deleting
        let hash = conn
            .query_row(
                "SELECT hash FROM locations WHERE path = ?1",
                params![path],
                |row| {
                    let bytes: Vec<u8> = row.get(0)?;
                    Ok(bytes)
                },
            )
            .optional()
            .expect("sqlite location remove select failed");

        if let Some(hash_bytes) = hash {
            conn.execute("DELETE FROM locations WHERE path = ?1", params![path])
                .expect("sqlite location remove delete failed");
            Hash::from_bytes(&hash_bytes).ok()
        } else {
            None
        }
    }

    fn compare_and_swap(
        &self,
        path: &str,
        expected: Hash,
        new_hash: Hash,
    ) -> Result<(), CasError> {
        let expected_bytes = expected.to_bytes();
        let new_bytes = new_hash.to_bytes();
        let conn = self.conn.lock().unwrap();
        let updated = conn
            .execute(
                "UPDATE locations SET hash = ?1 WHERE path = ?2 AND hash = ?3",
                params![new_bytes.as_slice(), path, expected_bytes.as_slice()],
            )
            .expect("sqlite CAS swap failed");
        if updated == 1 {
            return Ok(());
        }
        match conn
            .query_row(
                "SELECT hash FROM locations WHERE path = ?1",
                params![path],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .expect("sqlite CAS swap lookup failed")
        {
            None => Err(CasError::NotFound),
            Some(bytes) => {
                let actual = Hash::from_bytes(&bytes)
                    .expect("corrupted hash bytes in locations table");
                Err(CasError::Mismatch(actual))
            }
        }
    }

    fn compare_and_remove(&self, path: &str, expected: Hash) -> Result<Hash, CasError> {
        let expected_bytes = expected.to_bytes();
        let conn = self.conn.lock().unwrap();
        let removed = conn
            .execute(
                "DELETE FROM locations WHERE path = ?1 AND hash = ?2",
                params![path, expected_bytes.as_slice()],
            )
            .expect("sqlite CAS remove failed");
        if removed == 1 {
            return Ok(expected);
        }
        match conn
            .query_row(
                "SELECT hash FROM locations WHERE path = ?1",
                params![path],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .expect("sqlite CAS remove lookup failed")
        {
            None => Err(CasError::NotFound),
            Some(bytes) => {
                let actual = Hash::from_bytes(&bytes)
                    .expect("corrupted hash bytes in locations table");
                Err(CasError::Mismatch(actual))
            }
        }
    }

    fn compare_and_create(&self, path: &str, new_hash: Hash) -> Result<(), CasError> {
        // V7 §3.9 v7.50: CAS-create — succeed only if the path is unbound.
        // Atomic via SQLite's INSERT OR IGNORE: insert succeeds iff no row at
        // this path; row count == 1 means we created; == 0 means someone
        // already had a binding (look it up to report Mismatch).
        let new_bytes = new_hash.to_bytes();
        let conn = self.conn.lock().unwrap();
        let inserted = conn
            .execute(
                "INSERT OR IGNORE INTO locations (path, hash) VALUES (?1, ?2)",
                params![path, new_bytes.as_slice()],
            )
            .expect("sqlite CAS create failed");
        if inserted == 1 {
            return Ok(());
        }
        match conn
            .query_row(
                "SELECT hash FROM locations WHERE path = ?1",
                params![path],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .expect("sqlite CAS create lookup failed")
        {
            None => {
                // Insert failed with zero rows but no row present — shouldn't
                // happen under SQLite's serializable model; treat as a benign
                // race (caller retries).
                Err(CasError::NotFound)
            }
            Some(bytes) => {
                let actual = Hash::from_bytes(&bytes)
                    .expect("corrupted hash bytes in locations table");
                Err(CasError::Mismatch(actual))
            }
        }
    }

    fn list(&self, prefix: &str) -> Vec<LocationEntry> {
        let conn = self.conn.lock().unwrap();

        if prefix.is_empty() {
            // List all entries
            let mut stmt = conn
                .prepare("SELECT path, hash FROM locations ORDER BY path")
                .expect("sqlite list prepare failed");
            let entries = stmt
                .query_map([], |row| {
                    let path: String = row.get(0)?;
                    let hash_bytes: Vec<u8> = row.get(1)?;
                    Ok((path, hash_bytes))
                })
                .expect("sqlite list query failed")
                .filter_map(|r| {
                    let (path, hash_bytes) = r.ok()?;
                    let hash = Hash::from_bytes(&hash_bytes).ok()?;
                    Some(LocationEntry { path, hash })
                })
                .collect();
            return entries;
        }

        // Compute exclusive upper bound for prefix range scan.
        // Increment last byte of prefix to form the upper bound.
        let mut upper = prefix.as_bytes().to_vec();
        // Find the last byte that can be incremented without overflow
        while let Some(last) = upper.last_mut() {
            if *last < 0xFF {
                *last += 1;
                break;
            } else {
                upper.pop();
            }
        }

        if upper.is_empty() {
            // prefix is all 0xFF bytes — scan to end
            let mut stmt = conn
                .prepare("SELECT path, hash FROM locations WHERE path >= ?1 ORDER BY path")
                .expect("sqlite list prepare failed");
            stmt.query_map(params![prefix], |row| {
                let path: String = row.get(0)?;
                let hash_bytes: Vec<u8> = row.get(1)?;
                Ok((path, hash_bytes))
            })
            .expect("sqlite list query failed")
            .filter_map(|r| {
                let (path, hash_bytes) = r.ok()?;
                let hash = Hash::from_bytes(&hash_bytes).ok()?;
                Some(LocationEntry { path, hash })
            })
            .collect()
        } else {
            let upper_str =
                String::from_utf8(upper).expect("prefix upper bound is not valid UTF-8");
            let mut stmt = conn
                .prepare(
                    "SELECT path, hash FROM locations WHERE path >= ?1 AND path < ?2 ORDER BY path",
                )
                .expect("sqlite list prepare failed");
            stmt.query_map(params![prefix, upper_str], |row| {
                let path: String = row.get(0)?;
                let hash_bytes: Vec<u8> = row.get(1)?;
                Ok((path, hash_bytes))
            })
            .expect("sqlite list query failed")
            .filter_map(|r| {
                let (path, hash_bytes) = r.ok()?;
                let hash = Hash::from_bytes(&hash_bytes).ok()?;
                Some(LocationEntry { path, hash })
            })
            .collect()
        }
    }

    fn len_prefix(&self, prefix: &str) -> usize {
        let conn = self.conn.lock().unwrap();

        if prefix.is_empty() {
            return conn
                .query_row("SELECT COUNT(*) FROM locations", [], |row| {
                    row.get::<_, i64>(0)
                })
                .map(|n| n as usize)
                .unwrap_or(0);
        }

        // Same prefix-upper-bound trick as `list`.
        let mut upper = prefix.as_bytes().to_vec();
        while let Some(last) = upper.last_mut() {
            if *last < 0xFF {
                *last += 1;
                break;
            } else {
                upper.pop();
            }
        }

        if upper.is_empty() {
            conn.query_row(
                "SELECT COUNT(*) FROM locations WHERE path >= ?1",
                params![prefix],
                |row| row.get::<_, i64>(0),
            )
            .map(|n| n as usize)
            .unwrap_or(0)
        } else {
            let upper_str =
                String::from_utf8(upper).expect("prefix upper bound is not valid UTF-8");
            conn.query_row(
                "SELECT COUNT(*) FROM locations WHERE path >= ?1 AND path < ?2",
                params![prefix, upper_str],
                |row| row.get::<_, i64>(0),
            )
            .map(|n| n as usize)
            .unwrap_or(0)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_suite;

    fn test_store() -> SqliteStore {
        SqliteStore::open_in_memory().unwrap()
    }

    fn make_entity(type_str: &str, data_str: &str) -> Entity {
        let data = entity_ecf::to_ecf(&entity_ecf::text(data_str));
        Entity::new(type_str, data).unwrap()
    }

    // --- ContentStore tests (via shared suite) ---

    #[test]
    fn test_content_store_put_get() { test_suite::test_content_store_put_get(&test_store().content_store()); }
    #[test]
    fn test_content_store_has() { test_suite::test_content_store_has(&test_store().content_store()); }
    #[test]
    fn test_content_store_remove() { test_suite::test_content_store_remove(&test_store().content_store()); }
    #[test]
    fn test_content_store_len() { test_suite::test_content_store_len(&test_store().content_store()); }
    #[test]
    fn test_content_store_get_missing() { test_suite::test_content_store_get_missing(&test_store().content_store()); }
    #[test]
    fn test_content_store_put_overwrite() { test_suite::test_content_store_put_overwrite(&test_store().content_store()); }
    #[test]
    fn test_content_store_multiple_entities() { test_suite::test_content_store_multiple_entities(&test_store().content_store()); }

    // --- SQLite-specific ContentStore tests ---

    #[test]
    fn test_content_store_data_fidelity() {
        let store = test_store();
        let cs = store.content_store();
        let entity = make_entity("test/binary", "some data with special chars");
        let hash = cs.put(entity.clone()).unwrap();
        let retrieved = cs.get(&hash).unwrap();
        assert_eq!(retrieved.data, entity.data);
        assert_eq!(retrieved.entity_type, entity.entity_type);
    }

    // --- LocationIndex tests (via shared suite) ---

    #[test]
    fn test_location_index_set_get() { test_suite::test_location_index_set_get(&test_store().location_index()); }
    #[test]
    fn test_location_index_has() { test_suite::test_location_index_has(&test_store().location_index()); }
    #[test]
    fn test_location_index_remove() { test_suite::test_location_index_remove(&test_store().location_index()); }
    #[test]
    fn test_location_index_get_missing() { test_suite::test_location_index_get_missing(&test_store().location_index()); }
    #[test]
    fn test_location_index_overwrite() { test_suite::test_location_index_overwrite(&test_store().location_index()); }
    #[test]
    fn test_location_index_list_prefix() { test_suite::test_location_index_list_prefix(&test_store().location_index()); }
    #[test]
    fn test_location_index_list_all() { test_suite::test_location_index_list_all(&test_store().location_index()); }
    #[test]
    fn test_location_index_list_empty() { test_suite::test_location_index_list_empty(&test_store().location_index()); }

    #[test]
    fn test_location_index_list_no_match() { test_suite::test_location_index_list_no_match(&test_store().location_index()); }

    #[test]
    fn test_location_index_len_prefix() { test_suite::test_location_index_len_prefix(&test_store().location_index()); }

    // --- CAS tests (sqlite) ---

    #[test]
    fn test_cas_swap_match_succeeds() { test_suite::test_cas_swap_match_succeeds(&test_store().location_index()); }
    #[test]
    fn test_cas_swap_mismatch_returns_actual() { test_suite::test_cas_swap_mismatch_returns_actual(&test_store().location_index()); }
    #[test]
    fn test_cas_swap_missing_returns_not_found() { test_suite::test_cas_swap_missing_returns_not_found(&test_store().location_index()); }
    #[test]
    fn test_cas_remove_match_succeeds() { test_suite::test_cas_remove_match_succeeds(&test_store().location_index()); }
    #[test]
    fn test_cas_remove_mismatch_returns_actual() { test_suite::test_cas_remove_mismatch_returns_actual(&test_store().location_index()); }
    #[test]
    fn test_cas_remove_missing_returns_not_found() { test_suite::test_cas_remove_missing_returns_not_found(&test_store().location_index()); }

    // --- Persistence tests ---

    #[test]
    fn test_persistence_round_trip() {
        let dir = std::env::temp_dir().join(format!("entity_sqlite_test_{}", std::process::id()));
        let db_path = dir.join("test.db");
        std::fs::create_dir_all(&dir).unwrap();

        // Write data
        {
            let store = SqliteStore::open(&db_path).unwrap();
            let cs = store.content_store();
            let li = store.location_index();

            let e1 = make_entity("test/a", "alpha");
            let h1 = cs.put(e1).unwrap();
            li.set("path/a", h1);

            let e2 = make_entity("test/b", "beta");
            let h2 = cs.put(e2).unwrap();
            li.set("path/b", h2);
        }
        // Connection dropped — data should be on disk

        // Reopen and verify
        {
            let store = SqliteStore::open(&db_path).unwrap();
            let cs = store.content_store();
            let li = store.location_index();

            assert_eq!(cs.len(), 2);
            let h_a = li.get("path/a").unwrap();
            let entity_a = cs.get(&h_a).unwrap();
            assert_eq!(entity_a.entity_type, "test/a");

            let h_b = li.get("path/b").unwrap();
            let entity_b = cs.get(&h_b).unwrap();
            assert_eq!(entity_b.entity_type, "test/b");

            let entries = li.list("path/");
            assert_eq!(entries.len(), 2);
        }

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- Shared connection test ---

    #[test]
    fn test_shared_connection() {
        let store = test_store();
        let cs = store.content_store();
        let li = store.location_index();

        // Write via content store, read via location index (same db)
        let entity = make_entity("test/shared", "data");
        let hash = cs.put(entity).unwrap();
        li.set("shared/path", hash);

        // Both see the data
        assert!(cs.has(&hash));
        assert_eq!(li.get("shared/path"), Some(hash));
    }
}
