//! Journaled write-through persistence for memory stores.
//!
//! Feature-gated behind `persist`. Each `put()`/`set()` appends to an
//! append-only journal file, giving immediate durability. Reads come from
//! in-memory BTreeMaps (fast). On startup, replay the journal to rebuild
//! memory state. Periodic compaction rewrites the journal as a clean snapshot.
//!
//! Journal format: CBOR stream of records, each a CBOR array:
//! - `[0, hash_bytes, entity_type, data]` — PUT entity
//! - `[1, hash_bytes]` — REMOVE entity
//! - `[2, path, hash_bytes]` — SET location
//! - `[3, path]` — REMOVE location

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use entity_entity::Entity;
use entity_hash::Hash;
use thiserror::Error;

use crate::{
    ContentStore, LocationEntry, LocationIndex, MemoryContentStore, MemoryLocationIndex,
    StoreError,
};

// Record type tags
const TAG_PUT_ENTITY: u64 = 0;
const TAG_REMOVE_ENTITY: u64 = 1;
const TAG_SET_LOCATION: u64 = 2;
const TAG_REMOVE_LOCATION: u64 = 3;

#[derive(Debug, Error)]
pub enum PersistError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("journal decode error: {0}")]
    Decode(String),
}

// ---------------------------------------------------------------------------
// JournaledContentStore
// ---------------------------------------------------------------------------

/// Content store backed by memory with an append-only journal for durability.
///
/// Every `put()` and `remove()` appends a record to the journal. Reads come
/// from the in-memory BTreeMap. On open, the journal is replayed to rebuild
/// memory state.
///
/// **Deprecated:** Use `SqliteStore` for persistent storage. SQLite provides
/// better crash resilience (WAL), concurrent access, and persistent query
/// indexes. See `PeerBuilder::sqlite()`.
#[deprecated(since = "0.2.0", note = "Use SqliteStore for persistence. See PeerBuilder::sqlite().")]
pub struct JournaledContentStore {
    memory: MemoryContentStore,
    journal: Mutex<BufWriter<File>>,
    path: PathBuf,
}

impl JournaledContentStore {
    /// Open or create a journaled content store at the given path.
    ///
    /// If the file exists, replays the journal to rebuild memory state.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PersistError> {
        let path = path.as_ref().to_path_buf();
        let memory = MemoryContentStore::new();

        // Replay existing journal if present
        if path.exists() {
            replay_content_journal(&path, &memory)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        let journal = Mutex::new(BufWriter::new(file));

        Ok(Self {
            memory,
            journal,
            path,
        })
    }

    /// Compact the journal: rewrite as a clean snapshot of current state.
    ///
    /// This replaces the journal file atomically. After compaction, the
    /// journal contains only the current state with no tombstones or
    /// duplicate entries.
    pub fn compact(&self) -> Result<(), PersistError> {
        let tmp_path = self.path.with_extension("journal.tmp");

        // Write snapshot to temp file
        {
            let file = File::create(&tmp_path)?;
            let mut writer = BufWriter::new(file);
            for (hash, entity) in self.memory.entries() {
                write_put_entity(&mut writer, &hash, &entity)?;
            }
            writer.flush()?;
        }

        // Lock the journal, atomically replace, and reopen
        let mut journal = self.journal.lock().unwrap();
        journal.flush()?;
        fs::rename(&tmp_path, &self.path)?;
        let file = OpenOptions::new().append(true).open(&self.path)?;
        *journal = BufWriter::new(file);

        Ok(())
    }
}

impl ContentStore for JournaledContentStore {
    fn put(&self, entity: Entity) -> Result<Hash, StoreError> {
        let hash = self.memory.put(entity.clone())?;
        let mut journal = self.journal.lock().unwrap();
        write_put_entity(&mut *journal, &hash, &entity)
            .map_err(|e| StoreError::Internal(format!("journal write: {e}")))?;
        journal
            .flush()
            .map_err(|e| StoreError::Internal(format!("journal flush: {e}")))?;
        Ok(hash)
    }

    fn get(&self, hash: &Hash) -> Option<Entity> {
        self.memory.get(hash)
    }

    fn has(&self, hash: &Hash) -> bool {
        self.memory.has(hash)
    }

    fn remove(&self, hash: &Hash) -> bool {
        let existed = self.memory.remove(hash);
        if existed {
            let mut journal = self.journal.lock().unwrap();
            let _ = write_remove_entity(&mut *journal, hash);
            let _ = journal.flush();
        }
        existed
    }

    fn len(&self) -> usize {
        self.memory.len()
    }
}

// ---------------------------------------------------------------------------
// JournaledLocationIndex
// ---------------------------------------------------------------------------

/// Location index backed by memory with an append-only journal for durability.
///
/// **Deprecated:** Use `SqliteStore` for persistent storage.
#[deprecated(since = "0.2.0", note = "Use SqliteStore for persistence. See PeerBuilder::sqlite().")]
pub struct JournaledLocationIndex {
    memory: MemoryLocationIndex,
    journal: Mutex<BufWriter<File>>,
    path: PathBuf,
}

impl JournaledLocationIndex {
    /// Open or create a journaled location index at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PersistError> {
        let path = path.as_ref().to_path_buf();
        let memory = MemoryLocationIndex::new();

        if path.exists() {
            replay_location_journal(&path, &memory)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        let journal = Mutex::new(BufWriter::new(file));

        Ok(Self {
            memory,
            journal,
            path,
        })
    }

    /// Compact the journal: rewrite as a clean snapshot.
    pub fn compact(&self) -> Result<(), PersistError> {
        let tmp_path = self.path.with_extension("journal.tmp");

        {
            let file = File::create(&tmp_path)?;
            let mut writer = BufWriter::new(file);
            for (path, hash) in self.memory.entries() {
                write_set_location(&mut writer, &path, &hash)?;
            }
            writer.flush()?;
        }

        let mut journal = self.journal.lock().unwrap();
        journal.flush()?;
        fs::rename(&tmp_path, &self.path)?;
        let file = OpenOptions::new().append(true).open(&self.path)?;
        *journal = BufWriter::new(file);

        Ok(())
    }
}

impl LocationIndex for JournaledLocationIndex {
    fn set(&self, path: &str, hash: Hash) {
        self.memory.set(path, hash);
        let mut journal = self.journal.lock().unwrap();
        let _ = write_set_location(&mut *journal, path, &hash);
        let _ = journal.flush();
    }

    fn get(&self, path: &str) -> Option<Hash> {
        self.memory.get(path)
    }

    fn has(&self, path: &str) -> bool {
        self.memory.has(path)
    }

    fn remove(&self, path: &str) -> Option<Hash> {
        let removed = self.memory.remove(path);
        if removed.is_some() {
            let mut journal = self.journal.lock().unwrap();
            let _ = write_remove_location(&mut *journal, path);
            let _ = journal.flush();
        }
        removed
    }

    fn list(&self, prefix: &str) -> Vec<LocationEntry> {
        self.memory.list(prefix)
    }

    fn len_prefix(&self, prefix: &str) -> usize {
        self.memory.len_prefix(prefix)
    }
}

// ---------------------------------------------------------------------------
// Journal write helpers
// ---------------------------------------------------------------------------

fn write_put_entity(
    writer: &mut impl Write,
    hash: &Hash,
    entity: &Entity,
) -> Result<(), PersistError> {
    let record = ciborium::Value::Array(vec![
        ciborium::Value::Integer(TAG_PUT_ENTITY.into()),
        ciborium::Value::Bytes(hash.to_bytes().to_vec()),
        ciborium::Value::Text(entity.entity_type.clone()),
        ciborium::Value::Bytes(entity.data.clone()),
    ]);
    ciborium::into_writer(&record, writer)
        .map_err(|e| PersistError::Decode(format!("write put: {e}")))?;
    Ok(())
}

fn write_remove_entity(writer: &mut impl Write, hash: &Hash) -> Result<(), PersistError> {
    let record = ciborium::Value::Array(vec![
        ciborium::Value::Integer(TAG_REMOVE_ENTITY.into()),
        ciborium::Value::Bytes(hash.to_bytes().to_vec()),
    ]);
    ciborium::into_writer(&record, writer)
        .map_err(|e| PersistError::Decode(format!("write remove: {e}")))?;
    Ok(())
}

fn write_set_location(
    writer: &mut impl Write,
    path: &str,
    hash: &Hash,
) -> Result<(), PersistError> {
    let record = ciborium::Value::Array(vec![
        ciborium::Value::Integer(TAG_SET_LOCATION.into()),
        ciborium::Value::Text(path.to_string()),
        ciborium::Value::Bytes(hash.to_bytes().to_vec()),
    ]);
    ciborium::into_writer(&record, writer)
        .map_err(|e| PersistError::Decode(format!("write set: {e}")))?;
    Ok(())
}

fn write_remove_location(writer: &mut impl Write, path: &str) -> Result<(), PersistError> {
    let record = ciborium::Value::Array(vec![
        ciborium::Value::Integer(TAG_REMOVE_LOCATION.into()),
        ciborium::Value::Text(path.to_string()),
    ]);
    ciborium::into_writer(&record, writer)
        .map_err(|e| PersistError::Decode(format!("write remove_loc: {e}")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Journal replay
// ---------------------------------------------------------------------------

fn replay_content_journal(
    path: &Path,
    memory: &MemoryContentStore,
) -> Result<(), PersistError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    loop {
        // Check if we've reached EOF
        if reader.fill_buf()?.is_empty() {
            break;
        }

        let record: ciborium::Value = match ciborium::from_reader(&mut reader) {
            Ok(v) => v,
            Err(_) => {
                // Truncated record at end of journal — skip
                break;
            }
        };

        let arr = match record.as_array() {
            Some(a) => a,
            None => continue, // skip malformed
        };

        let tag = match arr.first().and_then(|v| v.as_integer()) {
            Some(i) => {
                let val: i128 = i.into();
                val as u64
            }
            None => continue,
        };

        match tag {
            TAG_PUT_ENTITY => {
                if arr.len() < 4 {
                    continue;
                }
                let hash_bytes = match arr[1].as_bytes() {
                    Some(b) => b,
                    None => continue,
                };
                let entity_type = match arr[2].as_text() {
                    Some(t) => t.to_string(),
                    None => continue,
                };
                let data = match arr[3].as_bytes() {
                    Some(b) => b.clone(),
                    None => continue,
                };
                let hash = match Hash::from_bytes(hash_bytes) {
                    Ok(h) => h,
                    Err(_) => continue,
                };
                let entity = Entity {
                    entity_type,
                    data,
                    content_hash: hash,
                };
                let _ = memory.put(entity);
            }
            TAG_REMOVE_ENTITY => {
                if arr.len() < 2 {
                    continue;
                }
                let hash_bytes = match arr[1].as_bytes() {
                    Some(b) => b,
                    None => continue,
                };
                if let Ok(hash) = Hash::from_bytes(hash_bytes) {
                    memory.remove(&hash);
                }
            }
            _ => continue,
        }
    }

    Ok(())
}

fn replay_location_journal(
    path: &Path,
    memory: &MemoryLocationIndex,
) -> Result<(), PersistError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    loop {
        if reader.fill_buf()?.is_empty() {
            break;
        }

        let record: ciborium::Value = match ciborium::from_reader(&mut reader) {
            Ok(v) => v,
            Err(_) => break,
        };

        let arr = match record.as_array() {
            Some(a) => a,
            None => continue,
        };

        let tag = match arr.first().and_then(|v| v.as_integer()) {
            Some(i) => {
                let val: i128 = i.into();
                val as u64
            }
            None => continue,
        };

        match tag {
            TAG_SET_LOCATION => {
                if arr.len() < 3 {
                    continue;
                }
                let path_str = match arr[1].as_text() {
                    Some(t) => t.to_string(),
                    None => continue,
                };
                let hash_bytes = match arr[2].as_bytes() {
                    Some(b) => b,
                    None => continue,
                };
                if let Ok(hash) = Hash::from_bytes(hash_bytes) {
                    memory.set(&path_str, hash);
                }
            }
            TAG_REMOVE_LOCATION => {
                if arr.len() < 2 {
                    continue;
                }
                let path_str = match arr[1].as_text() {
                    Some(t) => t.to_string(),
                    None => continue,
                };
                memory.remove(&path_str);
            }
            _ => continue,
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entity(type_str: &str, data_str: &str) -> Entity {
        let data = entity_ecf::to_ecf(&entity_ecf::text(data_str));
        Entity::new(type_str, data).unwrap()
    }

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "entity_persist_test_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    // --- JournaledContentStore tests ---

    #[test]
    fn test_content_put_get() {
        let dir = temp_dir();
        let cs = JournaledContentStore::open(dir.join("content.journal")).unwrap();
        let entity = make_entity("test/type", "hello");
        let hash = cs.put(entity.clone()).unwrap();
        let retrieved = cs.get(&hash).unwrap();
        assert_eq!(retrieved.content_hash, entity.content_hash);
        assert_eq!(retrieved.entity_type, "test/type");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_content_persistence() {
        let dir = temp_dir();
        let journal_path = dir.join("content.journal");

        // Write data
        let hash;
        {
            let cs = JournaledContentStore::open(&journal_path).unwrap();
            let entity = make_entity("test/persist", "durable data");
            hash = cs.put(entity).unwrap();
            assert!(cs.has(&hash));
        }
        // Dropped — no compact

        // Reopen and verify
        {
            let cs = JournaledContentStore::open(&journal_path).unwrap();
            assert!(cs.has(&hash));
            let entity = cs.get(&hash).unwrap();
            assert_eq!(entity.entity_type, "test/persist");
            assert_eq!(cs.len(), 1);
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_content_remove_persistence() {
        let dir = temp_dir();
        let journal_path = dir.join("content.journal");

        let hash;
        {
            let cs = JournaledContentStore::open(&journal_path).unwrap();
            let entity = make_entity("test/rm", "data");
            hash = cs.put(entity).unwrap();
            assert!(cs.remove(&hash));
            assert!(!cs.has(&hash));
        }

        // Reopen — remove should have been replayed
        {
            let cs = JournaledContentStore::open(&journal_path).unwrap();
            assert!(!cs.has(&hash));
            assert_eq!(cs.len(), 0);
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_content_compaction() {
        let dir = temp_dir();
        let journal_path = dir.join("content.journal");

        let hash_b;
        {
            let cs = JournaledContentStore::open(&journal_path).unwrap();
            // Write many, remove some
            let e_a = make_entity("test/a", "alpha");
            let h_a = cs.put(e_a).unwrap();
            let e_b = make_entity("test/b", "beta");
            hash_b = cs.put(e_b).unwrap();
            cs.remove(&h_a);

            // Journal has 3 records (put, put, remove). Compact to 1.
            cs.compact().unwrap();
        }

        // Reopen — should have only entity b
        {
            let cs = JournaledContentStore::open(&journal_path).unwrap();
            assert_eq!(cs.len(), 1);
            assert!(cs.has(&hash_b));
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_content_multiple_sessions() {
        let dir = temp_dir();
        let journal_path = dir.join("content.journal");

        // Session 1
        {
            let cs = JournaledContentStore::open(&journal_path).unwrap();
            cs.put(make_entity("test/a", "alpha")).unwrap();
        }
        // Session 2 — appends to same journal
        {
            let cs = JournaledContentStore::open(&journal_path).unwrap();
            assert_eq!(cs.len(), 1); // replayed session 1
            cs.put(make_entity("test/b", "beta")).unwrap();
        }
        // Session 3 — sees both
        {
            let cs = JournaledContentStore::open(&journal_path).unwrap();
            assert_eq!(cs.len(), 2);
        }

        let _ = fs::remove_dir_all(&dir);
    }

    // --- JournaledLocationIndex tests ---

    #[test]
    fn test_location_set_get() {
        let dir = temp_dir();
        let li = JournaledLocationIndex::open(dir.join("locations.journal")).unwrap();
        let hash = Hash::compute("test", &entity_ecf::to_ecf(&entity_ecf::text("x")));
        li.set("system/tree", hash);
        assert_eq!(li.get("system/tree"), Some(hash));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_location_persistence() {
        let dir = temp_dir();
        let journal_path = dir.join("locations.journal");
        let hash = Hash::compute("test", &entity_ecf::to_ecf(&entity_ecf::text("x")));

        {
            let li = JournaledLocationIndex::open(&journal_path).unwrap();
            li.set("path/a", hash);
        }

        {
            let li = JournaledLocationIndex::open(&journal_path).unwrap();
            assert_eq!(li.get("path/a"), Some(hash));
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_location_remove_persistence() {
        let dir = temp_dir();
        let journal_path = dir.join("locations.journal");
        let hash = Hash::compute("test", &entity_ecf::to_ecf(&entity_ecf::text("x")));

        {
            let li = JournaledLocationIndex::open(&journal_path).unwrap();
            li.set("path/a", hash);
            li.remove("path/a");
        }

        {
            let li = JournaledLocationIndex::open(&journal_path).unwrap();
            assert!(!li.has("path/a"));
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_location_list() {
        let dir = temp_dir();
        let li = JournaledLocationIndex::open(dir.join("locations.journal")).unwrap();
        let h1 = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("1")));
        let h2 = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("2")));
        li.set("system/handler/a", h1);
        li.set("system/handler/b", h2);

        let entries = li.list("system/handler/");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "system/handler/a");
        assert_eq!(entries[1].path, "system/handler/b");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_location_compaction() {
        let dir = temp_dir();
        let journal_path = dir.join("locations.journal");
        let h1 = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("1")));
        let h2 = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("2")));

        {
            let li = JournaledLocationIndex::open(&journal_path).unwrap();
            li.set("path/a", h1);
            li.set("path/b", h2);
            li.remove("path/a");
            // Journal has set, set, remove. Compact to one set.
            li.compact().unwrap();
        }

        {
            let li = JournaledLocationIndex::open(&journal_path).unwrap();
            assert!(!li.has("path/a"));
            assert!(li.has("path/b"));
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_location_overwrite_persistence() {
        let dir = temp_dir();
        let journal_path = dir.join("locations.journal");
        let h1 = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("one")));
        let h2 = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("two")));

        {
            let li = JournaledLocationIndex::open(&journal_path).unwrap();
            li.set("path", h1);
            li.set("path", h2); // overwrite
        }

        {
            let li = JournaledLocationIndex::open(&journal_path).unwrap();
            assert_eq!(li.get("path"), Some(h2)); // should see latest
        }

        let _ = fs::remove_dir_all(&dir);
    }
}
