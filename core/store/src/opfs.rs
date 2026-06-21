//! OPFS-backed ContentStore and LocationIndex for WASM workers.
//!
//! Feature-gated behind `wasm-persist`. Mirrors `persist.rs` structurally:
//! append-only journals on disk, in-memory `BTreeMap` mirrors for reads,
//! replay on open. The I/O layer is OPFS `FileSystemSyncAccessHandle`
//! instead of `std::fs::File`.
//!
//! # Why journal + memory mirror
//!
//! - Phase 0c measured 4,800 reads/frame at peak — per-read OPFS I/O is
//!   unacceptable. Reads come from memory; OPFS only sees writes.
//! - SyncAccessHandle's strongest operation is sync append + flush; that
//!   matches the journal pattern exactly.
//! - Single-writer per file is enforced by OPFS (a second
//!   `createSyncAccessHandle` on the same file throws). Single-threaded
//!   WASM workers satisfy this trivially.
//!
//! # Record framing
//!
//! Each record is `[version:u8] [length:u32 big-endian] [payload]`. The
//! version byte is forward-compat: if we ever change the payload schema,
//! bump version. Older records replay against their version; newer
//! records ignored or upgraded at compaction. Length-prefix makes torn-
//! write recovery cheap — on replay, if remaining bytes < `length`, the
//! file is truncated at the record's start.
//!
//! Custom binary, NOT CBOR. CBOR framing adds parse cost for zero benefit
//! when the writer controls both sides of the wire.
//!
//! ## entities.log payload (record version 1)
//! ```text
//! [hash: 33 bytes]               // algorithm byte + 32-byte digest
//! [entity_type_len: u16 BE]
//! [entity_type: utf-8 bytes]
//! [data: remaining bytes]        // CBOR-encoded entity body
//! ```
//!
//! Entities are immutable in content-addressed storage — `entities.log`
//! grows monotonically. No remove records; orphan GC is deferred until a
//! consumer needs it. `OpfsContentStore::remove` is a memory-only soft
//! delete: the entity is removed from the mirror but stays on disk until
//! the next GC sweep. Replay re-stores it; callers must `remove` again if
//! they want it gone post-restart. (This matches `MemoryContentStore`
//! semantics — both are append-only at the storage layer.)
//!
//! ## locations.log payload (record version 1)
//! ```text
//! [op: u8]                       // 0 = set, 1 = remove
//! [path_len: u16 BE]
//! [path: utf-8 bytes]
//! [hash: 33 bytes]               // only when op == 0
//! ```
//!
//! Locations are mutable — `locations.log` accumulates set/remove
//! records. Compaction (deferred to v1.x) rewrites as a clean snapshot
//! when journal size > 2× live data.
//!
//! # Send / Sync
//!
//! `JsValue` is `!Send + !Sync`. WASM single-threaded execution makes
//! cross-thread access impossible, so we `unsafe impl Send + Sync` to
//! satisfy the `ContentStore + Send + Sync` and `LocationIndex + Send + Sync`
//! trait bounds. See SAFETY notes on each impl.
//!
//! # Testing
//!
//! Unit tests require a browser context with OPFS available
//! (`wasm-bindgen-test` + dedicated worker). v1 ships without — egui's
//! `make e2e-worker` is the integration signal. Adding wasm-bindgen-test
//! infrastructure is tracked in the WORKER-MIGRATION-ANALYSIS doc.

#![cfg(all(target_arch = "wasm32", feature = "wasm-persist"))]

use std::cell::RefCell;
use std::sync::Mutex;

use entity_entity::Entity;
use entity_hash::Hash;
use thiserror::Error;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    FileSystemFileHandle, FileSystemGetDirectoryOptions, FileSystemGetFileOptions,
    FileSystemReadWriteOptions, FileSystemSyncAccessHandle,
};

use crate::{
    CasError, ContentStore, LocationEntry, LocationIndex, MemoryContentStore,
    MemoryLocationIndex, StoreError,
};

// ---------------------------------------------------------------------------
// Record format constants
// ---------------------------------------------------------------------------

/// Current record version. Bumped on payload schema changes.
const RECORD_VERSION: u8 = 1;

/// Location op codes.
const LOC_OP_SET: u8 = 0;
const LOC_OP_REMOVE: u8 = 1;

/// Maximum reasonable record length. Protects replay against absurd values
/// from corrupted length prefixes (e.g., reading random bytes interpreted as
/// a u32). 256 MB ceiling — well above any plausible single entity.
const MAX_RECORD_LEN: u32 = 256 * 1024 * 1024;

const FILENAME_ENTITIES: &str = "entities.log";
const FILENAME_LOCATIONS: &str = "locations.log";

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum OpfsError {
    #[error("OPFS unavailable: {0}")]
    Unavailable(String),
    #[error("OPFS I/O: {0}")]
    Io(String),
    #[error("journal decode: {0}")]
    Decode(String),
}

// ---------------------------------------------------------------------------
// Directory resolution
// ---------------------------------------------------------------------------

/// Resolve `root` to a `FileSystemDirectoryHandle`, walking slash-separated
/// path components and creating any that don't exist. Empty/`"/"`/`"."`
/// returns the OPFS root directly.
async fn resolve_directory(
    root: &str,
) -> Result<web_sys::FileSystemDirectoryHandle, OpfsError> {
    // navigator.storage.getDirectory() works on both window + worker scopes;
    // we deliberately go through js_sys::global to avoid taking a hard
    // dep on a particular scope type.
    let global = js_sys::global();
    let navigator = js_sys::Reflect::get(&global, &"navigator".into())
        .map_err(|e| OpfsError::Unavailable(format!("no navigator: {e:?}")))?;
    let storage = js_sys::Reflect::get(&navigator, &"storage".into())
        .map_err(|e| OpfsError::Unavailable(format!("no navigator.storage: {e:?}")))?;
    let get_dir_fn = js_sys::Reflect::get(&storage, &"getDirectory".into())
        .map_err(|e| OpfsError::Unavailable(format!("no storage.getDirectory: {e:?}")))?;
    let get_dir_fn: js_sys::Function = get_dir_fn
        .dyn_into()
        .map_err(|_| OpfsError::Unavailable("storage.getDirectory not a function".into()))?;
    let dir_promise = get_dir_fn
        .call0(&storage)
        .map_err(|e| OpfsError::Unavailable(format!("getDirectory call failed: {e:?}")))?;
    let dir_js = JsFuture::from(js_sys::Promise::from(dir_promise))
        .await
        .map_err(|e| OpfsError::Unavailable(format!("getDirectory: {e:?}")))?;
    let mut current: web_sys::FileSystemDirectoryHandle = dir_js
        .dyn_into()
        .map_err(|_| OpfsError::Unavailable("getDirectory returned non-directory".into()))?;

    for component in root.split('/').filter(|s| !s.is_empty() && *s != ".") {
        let opts = FileSystemGetDirectoryOptions::new();
        opts.set_create(true);
        let child_promise = current.get_directory_handle_with_options(component, &opts);
        let child_js = JsFuture::from(child_promise)
            .await
            .map_err(|e| OpfsError::Io(format!("get_directory_handle({component}): {e:?}")))?;
        current = child_js
            .dyn_into()
            .map_err(|_| OpfsError::Io("getDirectoryHandle returned non-directory".into()))?;
    }
    Ok(current)
}

// ---------------------------------------------------------------------------
// JournalHandle — sync write+flush wrapper around a SyncAccessHandle
// ---------------------------------------------------------------------------

/// Wraps `FileSystemSyncAccessHandle` with an append-cursor and basic
/// read/write/flush helpers. Single-writer per file is enforced by OPFS.
struct JournalHandle {
    handle: FileSystemSyncAccessHandle,
    /// Append cursor — bytes from end of file at construction, advanced by
    /// every write. Tracked manually so we don't hit the handle for size
    /// on every write.
    size: u64,
}

impl JournalHandle {
    /// Async OPFS open. Acquires (or creates) the file inside `dir` and
    /// obtains the exclusive sync access handle. Caller owns the handle
    /// for its lifetime; drop closes it.
    async fn open_in(
        dir: &web_sys::FileSystemDirectoryHandle,
        filename: &str,
    ) -> Result<Self, OpfsError> {
        let opts = FileSystemGetFileOptions::new();
        opts.set_create(true);
        let file_promise = dir.get_file_handle_with_options(filename, &opts);
        let file_js = JsFuture::from(file_promise)
            .await
            .map_err(|e| OpfsError::Io(format!("get_file_handle({filename}): {e:?}")))?;
        let file_handle: FileSystemFileHandle = file_js
            .dyn_into()
            .map_err(|_| OpfsError::Io("getFileHandle returned non-file".into()))?;

        let sah_promise = file_handle.create_sync_access_handle();
        let sah_js = JsFuture::from(sah_promise)
            .await
            .map_err(|e| OpfsError::Io(format!("createSyncAccessHandle: {e:?}")))?;
        let handle: FileSystemSyncAccessHandle = sah_js
            .dyn_into()
            .map_err(|_| OpfsError::Io("createSyncAccessHandle returned wrong type".into()))?;

        let size = handle.get_size().map_err(|e| OpfsError::Io(format!("getSize: {e:?}")))? as u64;
        Ok(Self { handle, size })
    }

    /// Read the entire file into a Vec<u8>. Used at open time for replay.
    fn read_all(&self) -> Result<Vec<u8>, OpfsError> {
        if self.size == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; self.size as usize];
        let opts = FileSystemReadWriteOptions::new();
        opts.set_at(0.0);
        self.handle
            .read_with_u8_array_and_options(&mut buf, &opts)
            .map_err(|e| OpfsError::Io(format!("read: {e:?}")))?;
        Ok(buf)
    }

    /// Append `bytes` at the current cursor and flush. Updates `self.size`.
    fn append_and_flush(&mut self, bytes: &[u8]) -> Result<(), OpfsError> {
        let opts = FileSystemReadWriteOptions::new();
        opts.set_at(self.size as f64);
        let written = self
            .handle
            .write_with_u8_array_and_options(bytes, &opts)
            .map_err(|e| OpfsError::Io(format!("write: {e:?}")))? as u64;
        if written != bytes.len() as u64 {
            return Err(OpfsError::Io(format!(
                "short write: requested {} got {}",
                bytes.len(),
                written
            )));
        }
        self.size += written;
        self.handle
            .flush()
            .map_err(|e| OpfsError::Io(format!("flush: {e:?}")))?;
        Ok(())
    }

    /// Truncate the file to `new_size`. Used to drop a torn record at the
    /// end of the journal during replay.
    fn truncate(&mut self, new_size: u64) -> Result<(), OpfsError> {
        self.handle
            .truncate_with_f64(new_size as f64)
            .map_err(|e| OpfsError::Io(format!("truncate: {e:?}")))?;
        self.size = new_size;
        self.handle
            .flush()
            .map_err(|e| OpfsError::Io(format!("flush after truncate: {e:?}")))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// OpfsStore — factory holding both handles
// ---------------------------------------------------------------------------

/// Factory that opens both OPFS journal files and exposes the two backing
/// stores. Mirrors `SqliteStore`'s shape.
pub struct OpfsStore {
    content_store: OpfsContentStore,
    location_index: OpfsLocationIndex,
}

impl OpfsStore {
    /// Open (or create) the entity store under the OPFS subdirectory `root`.
    ///
    /// `root` is a slash-separated path under the OPFS root. Empty string
    /// uses the OPFS root directly (single-instance case). Intermediate
    /// directories are created if they don't exist.
    ///
    /// Acquires exclusive `SyncAccessHandle`s for both journal files and
    /// replays them into in-memory mirrors. Async because OPFS handle
    /// acquisition uses Promises; per-op reads/writes after open are sync.
    ///
    /// Multiple `OpfsStore` instances in the same origin must use distinct
    /// `root` paths — `createSyncAccessHandle` is exclusive per file, so two
    /// stores rooted at the same directory will collide on `entities.log`.
    pub async fn open(root: &str) -> Result<Self, OpfsError> {
        let dir = resolve_directory(root).await?;
        let entities_handle = JournalHandle::open_in(&dir, FILENAME_ENTITIES).await?;
        let locations_handle = JournalHandle::open_in(&dir, FILENAME_LOCATIONS).await?;

        let content_store = OpfsContentStore::new(entities_handle)?;
        let location_index = OpfsLocationIndex::new(locations_handle)?;

        Ok(Self {
            content_store,
            location_index,
        })
    }

    pub fn content_store(self) -> OpfsContentStore {
        self.content_store
    }

    pub fn location_index(self) -> OpfsLocationIndex {
        self.location_index
    }

    /// Consume into both pieces. Most callers want this — the factory only
    /// exists to coordinate the async open.
    pub fn into_parts(self) -> (OpfsContentStore, OpfsLocationIndex) {
        (self.content_store, self.location_index)
    }
}

// ---------------------------------------------------------------------------
// OpfsContentStore
// ---------------------------------------------------------------------------

pub struct OpfsContentStore {
    memory: MemoryContentStore,
    journal: Mutex<RefCell<JournalHandle>>,
}

// SAFETY: WASM is single-threaded. The `JsValue` inside `FileSystemSyncAccessHandle`
// is `!Send + !Sync` to prevent cross-thread access in mixed-target code,
// but on wasm32-unknown-unknown there is no other thread. The `Mutex` is
// kept for the trait Send + Sync bound and the API contract (no aliased
// mutable access); on the single thread, lock contention is impossible.
unsafe impl Send for OpfsContentStore {}
unsafe impl Sync for OpfsContentStore {}

impl OpfsContentStore {
    fn new(mut journal: JournalHandle) -> Result<Self, OpfsError> {
        let memory = MemoryContentStore::new();
        let bytes = journal.read_all()?;
        let good_end = replay_entities(&bytes, &memory)?;
        if good_end < bytes.len() as u64 {
            // Torn record at the tail — truncate.
            tracing::warn!(
                journal_size = bytes.len(),
                good_end,
                "entities.log torn at tail, truncating"
            );
            journal.truncate(good_end)?;
        }
        Ok(Self {
            memory,
            journal: Mutex::new(RefCell::new(journal)),
        })
    }
}

impl ContentStore for OpfsContentStore {
    fn put(&self, entity: Entity) -> Result<Hash, StoreError> {
        let hash = self.memory.put(entity.clone())?;
        let bytes = encode_entity_record(&hash, &entity);
        let guard = self
            .journal
            .lock()
            .map_err(|e| StoreError::Internal(format!("opfs journal poisoned: {e}")))?;
        guard
            .borrow_mut()
            .append_and_flush(&bytes)
            .map_err(|e| StoreError::Internal(format!("opfs entities.log: {e}")))?;
        Ok(hash)
    }

    fn get(&self, hash: &Hash) -> Option<Entity> {
        self.memory.get(hash)
    }

    fn has(&self, hash: &Hash) -> bool {
        self.memory.has(hash)
    }

    fn remove(&self, hash: &Hash) -> bool {
        // Memory-only soft remove. entities.log is append-only at the storage
        // layer (entities are content-addressed and immutable); orphan GC is
        // deferred. A future replay will re-store the entity unless GC has
        // swept it. This matches the content-addressed model and the
        // `MemoryContentStore` semantics from which we inherit.
        self.memory.remove(hash)
    }

    fn len(&self) -> usize {
        self.memory.len()
    }
}

// ---------------------------------------------------------------------------
// OpfsLocationIndex
// ---------------------------------------------------------------------------

pub struct OpfsLocationIndex {
    memory: MemoryLocationIndex,
    journal: Mutex<RefCell<JournalHandle>>,
}

// SAFETY: see OpfsContentStore.
unsafe impl Send for OpfsLocationIndex {}
unsafe impl Sync for OpfsLocationIndex {}

impl OpfsLocationIndex {
    fn new(mut journal: JournalHandle) -> Result<Self, OpfsError> {
        let memory = MemoryLocationIndex::new();
        let bytes = journal.read_all()?;
        let good_end = replay_locations(&bytes, &memory)?;
        if good_end < bytes.len() as u64 {
            tracing::warn!(
                journal_size = bytes.len(),
                good_end,
                "locations.log torn at tail, truncating"
            );
            journal.truncate(good_end)?;
        }
        Ok(Self {
            memory,
            journal: Mutex::new(RefCell::new(journal)),
        })
    }

    fn append_set(&self, path: &str, hash: &Hash) -> Result<(), OpfsError> {
        let bytes = encode_location_set(path, hash);
        let guard = self
            .journal
            .lock()
            .map_err(|e| OpfsError::Io(format!("locations.log poisoned: {e}")))?;
        let result = guard.borrow_mut().append_and_flush(&bytes);
        result
    }

    fn append_remove(&self, path: &str) -> Result<(), OpfsError> {
        let bytes = encode_location_remove(path);
        let guard = self
            .journal
            .lock()
            .map_err(|e| OpfsError::Io(format!("locations.log poisoned: {e}")))?;
        let result = guard.borrow_mut().append_and_flush(&bytes);
        result
    }
}

/// Record a swallowed durable `locations.log` write failure.
///
/// The `LocationIndex` trait's `set`/`remove` return `()`/`Option` and
/// `compare_and_swap`/`compare_and_remove` return `CasError` (closed enum,
/// spec-pinned to 409 `hash_mismatch` — no I/O variant). None of them can
/// surface a durable-store write failure as the spec-compliant error
/// *response* the protocol expects (cf. `ContentStore::put` → `StoreError`).
/// So the only thing this layer can do is log loudly and continue with the
/// in-memory mirror ahead of the journal — the binding is lost on restart.
/// This is a known Rust-side trait-shape gap, not a chosen policy: see
/// `docs/SPEC-AMBIGUITIES.md` "OPFS LocationIndex durable-write failure is
/// unreportable". A spec-compliant fix needs a fallible `LocationIndex`
/// write signature (cross-cutting, cross-impl — Go/Python share the trait).
fn log_swallowed_journal_failure(op: &str, path: &str, e: &OpfsError) {
    tracing::error!(
        op,
        path = %path,
        error = %e,
        "opfs locations.log durable write failed; in-memory index is now \
         ahead of the journal — this binding will be lost on restart \
         (LocationIndex write trait cannot return this error; see \
         docs/SPEC-AMBIGUITIES.md)"
    );
}

impl LocationIndex for OpfsLocationIndex {
    fn set(&self, path: &str, hash: Hash) {
        self.memory.set(path, hash);
        if let Err(e) = self.append_set(path, &hash) {
            log_swallowed_journal_failure("set", path, &e);
        }
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
            if let Err(e) = self.append_remove(path) {
                log_swallowed_journal_failure("remove", path, &e);
            }
        }
        removed
    }

    fn list(&self, prefix: &str) -> Vec<LocationEntry> {
        self.memory.list(prefix)
    }

    fn len_prefix(&self, prefix: &str) -> usize {
        self.memory.len_prefix(prefix)
    }

    fn compare_and_swap(
        &self,
        path: &str,
        expected: Hash,
        new_hash: Hash,
    ) -> Result<(), CasError> {
        // Memory CAS first — single-threaded worker means no race window
        // between check and journal append.
        self.memory.compare_and_swap(path, expected, new_hash)?;
        if let Err(e) = self.append_set(path, &new_hash) {
            log_swallowed_journal_failure("compare_and_swap", path, &e);
        }
        Ok(())
    }

    fn compare_and_remove(&self, path: &str, expected: Hash) -> Result<Hash, CasError> {
        let removed = self.memory.compare_and_remove(path, expected)?;
        if let Err(e) = self.append_remove(path) {
            log_swallowed_journal_failure("compare_and_remove", path, &e);
        }
        Ok(removed)
    }

    fn compare_and_create(&self, path: &str, new_hash: Hash) -> Result<(), CasError> {
        // V7 §3.9 v7.50 CAS-create. Single-threaded worker model — memory
        // check serializes the create decision; journal append mirrors.
        self.memory.compare_and_create(path, new_hash)?;
        if let Err(e) = self.append_set(path, &new_hash) {
            log_swallowed_journal_failure("compare_and_create", path, &e);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Record encoding
// ---------------------------------------------------------------------------

/// Wrap a payload with the outer frame: `[version][length: u32 BE][payload]`.
fn frame_record(payload: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(RECORD_VERSION);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

fn encode_entity_record(hash: &Hash, entity: &Entity) -> Vec<u8> {
    let hash_bytes = hash.to_bytes();
    let type_bytes = entity.entity_type.as_bytes();
    let mut payload = Vec::with_capacity(hash_bytes.len() + 2 + type_bytes.len() + entity.data.len());
    payload.extend_from_slice(&hash_bytes);
    payload.extend_from_slice(&(type_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(type_bytes);
    payload.extend_from_slice(&entity.data);
    frame_record(payload)
}

fn encode_location_set(path: &str, hash: &Hash) -> Vec<u8> {
    let path_bytes = path.as_bytes();
    let hash_bytes = hash.to_bytes();
    let mut payload = Vec::with_capacity(1 + 2 + path_bytes.len() + hash_bytes.len());
    payload.push(LOC_OP_SET);
    payload.extend_from_slice(&(path_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(path_bytes);
    payload.extend_from_slice(&hash_bytes);
    frame_record(payload)
}

fn encode_location_remove(path: &str) -> Vec<u8> {
    let path_bytes = path.as_bytes();
    let mut payload = Vec::with_capacity(1 + 2 + path_bytes.len());
    payload.push(LOC_OP_REMOVE);
    payload.extend_from_slice(&(path_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(path_bytes);
    frame_record(payload)
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

/// Walk the journal `bytes`, applying records to `memory`. Returns the
/// byte offset of the first torn / corrupt record (or `bytes.len()` if
/// the journal is clean). Callers truncate the file to this offset.
fn replay_entities(bytes: &[u8], memory: &MemoryContentStore) -> Result<u64, OpfsError> {
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let record_start = cursor;
        let (version, length, payload_start) = match read_frame(bytes, cursor) {
            FrameResult::Ok { version, length, payload_start } => (version, length, payload_start),
            FrameResult::Torn => return Ok(record_start as u64),
            FrameResult::Invalid(msg) => {
                tracing::warn!(at = record_start, reason = %msg, "entities.log frame invalid, truncating");
                return Ok(record_start as u64);
            }
        };
        let payload_end = payload_start + length;
        if payload_end > bytes.len() {
            // Truncated payload at the tail.
            return Ok(record_start as u64);
        }
        let payload = &bytes[payload_start..payload_end];

        if version != RECORD_VERSION {
            // Unknown version — skip (forward-compat). At compaction time we
            // would upgrade or drop.
            tracing::warn!(version, "entities.log unknown record version, skipping");
        } else if let Err(e) = apply_entity_record(payload, memory) {
            tracing::warn!(at = record_start, error = %e, "entities.log record decode failed, skipping");
        }
        cursor = payload_end;
    }
    Ok(bytes.len() as u64)
}

fn replay_locations(bytes: &[u8], memory: &MemoryLocationIndex) -> Result<u64, OpfsError> {
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let record_start = cursor;
        let (version, length, payload_start) = match read_frame(bytes, cursor) {
            FrameResult::Ok { version, length, payload_start } => (version, length, payload_start),
            FrameResult::Torn => return Ok(record_start as u64),
            FrameResult::Invalid(msg) => {
                tracing::warn!(at = record_start, reason = %msg, "locations.log frame invalid, truncating");
                return Ok(record_start as u64);
            }
        };
        let payload_end = payload_start + length;
        if payload_end > bytes.len() {
            return Ok(record_start as u64);
        }
        let payload = &bytes[payload_start..payload_end];

        if version != RECORD_VERSION {
            tracing::warn!(version, "locations.log unknown record version, skipping");
        } else if let Err(e) = apply_location_record(payload, memory) {
            tracing::warn!(at = record_start, error = %e, "locations.log record decode failed, skipping");
        }
        cursor = payload_end;
    }
    Ok(bytes.len() as u64)
}

enum FrameResult {
    Ok { version: u8, length: usize, payload_start: usize },
    /// Frame header itself is truncated (< 5 bytes remaining).
    Torn,
    /// Frame header is present but corrupt (length absurdly large, etc.).
    Invalid(String),
}

fn read_frame(bytes: &[u8], cursor: usize) -> FrameResult {
    if bytes.len() - cursor < 5 {
        return FrameResult::Torn;
    }
    let version = bytes[cursor];
    let length = u32::from_be_bytes([
        bytes[cursor + 1],
        bytes[cursor + 2],
        bytes[cursor + 3],
        bytes[cursor + 4],
    ]);
    if length > MAX_RECORD_LEN {
        return FrameResult::Invalid(format!("record length {length} exceeds max"));
    }
    FrameResult::Ok {
        version,
        length: length as usize,
        payload_start: cursor + 5,
    }
}

fn apply_entity_record(payload: &[u8], memory: &MemoryContentStore) -> Result<(), OpfsError> {
    if payload.len() < 33 + 2 {
        return Err(OpfsError::Decode("entity payload too short".into()));
    }
    let hash = Hash::from_bytes(&payload[0..33])
        .map_err(|e| OpfsError::Decode(format!("hash: {e}")))?;
    let type_len = u16::from_be_bytes([payload[33], payload[34]]) as usize;
    let body_start = 35;
    let body_end = body_start + type_len;
    if body_end > payload.len() {
        return Err(OpfsError::Decode("entity_type truncated".into()));
    }
    let entity_type = std::str::from_utf8(&payload[body_start..body_end])
        .map_err(|e| OpfsError::Decode(format!("entity_type utf-8: {e}")))?
        .to_string();
    let data = payload[body_end..].to_vec();
    let entity = Entity {
        entity_type,
        data,
        content_hash: hash,
    };
    let _ = memory.put(entity);
    Ok(())
}

fn apply_location_record(payload: &[u8], memory: &MemoryLocationIndex) -> Result<(), OpfsError> {
    if payload.is_empty() {
        return Err(OpfsError::Decode("location payload empty".into()));
    }
    let op = payload[0];
    if payload.len() < 3 {
        return Err(OpfsError::Decode("location payload truncated".into()));
    }
    let path_len = u16::from_be_bytes([payload[1], payload[2]]) as usize;
    let path_start = 3;
    let path_end = path_start + path_len;
    if path_end > payload.len() {
        return Err(OpfsError::Decode("location path truncated".into()));
    }
    let path = std::str::from_utf8(&payload[path_start..path_end])
        .map_err(|e| OpfsError::Decode(format!("path utf-8: {e}")))?;
    match op {
        LOC_OP_SET => {
            let hash_start = path_end;
            let hash_end = hash_start + 33;
            if hash_end > payload.len() {
                return Err(OpfsError::Decode("location hash truncated".into()));
            }
            let hash = Hash::from_bytes(&payload[hash_start..hash_end])
                .map_err(|e| OpfsError::Decode(format!("hash: {e}")))?;
            memory.set(path, hash);
            Ok(())
        }
        LOC_OP_REMOVE => {
            memory.remove(path);
            Ok(())
        }
        other => Err(OpfsError::Decode(format!("unknown location op: {other}"))),
    }
}
