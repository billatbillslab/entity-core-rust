//! IndexedDB-backed ContentStore and LocationIndex for WASM (main thread
//! or worker).
//!
//! Feature-gated behind `wasm-idb-persist`. Structurally identical to
//! [`opfs`](crate::opfs): an in-memory `BTreeMap` mirror serves every read
//! synchronously, and a durable shadow is reconciled at `open()`. The *only*
//! thing that differs is the durable substrate's flush timing:
//!
//! - OPFS flushes **synchronously** inside `put()` (a `SyncAccessHandle`
//!   append), so a write is durable the instant `put()` returns.
//! - IndexedDB on the main thread is **async-only** — you cannot block on it.
//!   So writes are **write-behind**: `put()` updates the sync mirror and
//!   *enqueues* the record; a background drain ([`WriteBehind`]) batches dirty
//!   records into one IDB transaction on a short debounce.
//!
//! The sync `ContentStore` / `LocationIndex` traits are **untouched** — this is
//! the load-bearing insight that makes a durable main-thread store possible
//! with no `async_trait` rewrite and no consumer churn. The mirror is runtime
//! truth; IDB is the durable shadow.
//!
//! # The one genuinely new piece — write-behind + checkpoint
//!
//! Because durability is now deferred, callers that cannot tolerate the loss of
//! the last unflushed window (identity/destructive ops: create-peer,
//! delete-peer, config commit) need a way to **await durability**. That is
//! [`IdbCheckpoint::checkpoint`]: it forces an immediate drain and resolves only
//! once the covering IDB transaction has committed. High-frequency incidental
//! writes stay write-behind; identity ops checkpoint before acknowledging.
//!
//! See `docs/SPEC-AMBIGUITIES.md` for the checkpoint-reach decision.
//!
//! # Storage shape — object-store-as-KV
//!
//! Two IDB object stores in one database:
//! - `entities` — key = 33-byte hash, value = `[type_len:u16 BE][type][data]`.
//! - `locations` — key = path string, value = 33-byte hash.
//!
//! `put`/`delete` map directly to IDB `put`/`delete`; boot replay is one
//! `getAll` + `getAllKeys` per store folded into the mirror. No torn-record
//! framing, no compaction — unlike OPFS's append log. This is the natural IDB
//! idiom and the simplest correct thing.
//!
//! # Atomicity
//!
//! A single [`WriteBehind`] is shared by both stores, and each drain opens one
//! readwrite transaction spanning **both** object stores. So a tree write that
//! touches an entity and its location binding commits atomically, and a single
//! `checkpoint()` awaits durability of both.
//!
//! # Send / Sync
//!
//! `JsValue` (and the `Rc`/`RefCell` interior state) is `!Send + !Sync`. WASM
//! single-threaded execution makes cross-thread access impossible, so we
//! `unsafe impl Send + Sync` to satisfy the trait bounds, exactly as OPFS does.

#![cfg(all(target_arch = "wasm32", feature = "wasm-idb-persist"))]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use entity_entity::Entity;
use entity_hash::Hash;
use futures_channel::oneshot;
use gloo_timers::future::TimeoutFuture;
use thiserror::Error;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{spawn_local, JsFuture};
use web_sys::{
    IdbDatabase, IdbFactory, IdbObjectStore, IdbOpenDbRequest, IdbRequest, IdbTransaction,
    IdbTransactionMode,
};

use crate::{
    CasError, ContentStore, LocationEntry, LocationIndex, MemoryContentStore, MemoryLocationIndex,
    StoreError,
};

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

/// Object store holding entities (key = hash bytes).
const STORE_ENTITIES: &str = "entities";
/// Object store holding location bindings (key = path string).
const STORE_LOCATIONS: &str = "locations";

/// Debounce before an incidental (non-checkpoint) write is drained, in ms.
/// A burst of writes inside this window collapses into one transaction.
const DEBOUNCE_MS: u32 = 250;
/// Retry delay after a failed flush transaction, in ms.
const RETRY_MS: u32 = 500;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum IdbError {
    #[error("IndexedDB unavailable: {0}")]
    Unavailable(String),
    #[error("IndexedDB I/O: {0}")]
    Io(String),
    #[error("record decode: {0}")]
    Decode(String),
}

fn io(e: impl std::fmt::Debug) -> IdbError {
    IdbError::Io(format!("{e:?}"))
}

// ---------------------------------------------------------------------------
// Flush health (for the app's durability-honesty surface, §3.3)
// ---------------------------------------------------------------------------

/// A cheap snapshot of the flusher's state, so the app can honestly show
/// "durable / N pending / degraded" instead of silently lying.
#[derive(Debug, Clone, Default)]
pub struct FlushHealth {
    /// Records enqueued but not yet committed to IDB.
    pub pending_count: usize,
    /// Highest enqueue-sequence durably committed.
    pub last_flushed_seq: u64,
    /// The most recent flush error, if the flusher is currently degraded.
    /// Cleared on the next successful flush.
    pub last_error: Option<String>,
}

// ---------------------------------------------------------------------------
// Promise / event bridging helpers
// ---------------------------------------------------------------------------

/// Resolve `indexedDB` off the global scope (works on both window and worker
/// scopes — IndexedDB is exposed on both), avoiding a hard dep on either scope
/// type. Mirrors `opfs::resolve_directory`'s reflection approach.
fn get_factory() -> Result<IdbFactory, IdbError> {
    let global = js_sys::global();
    let idb = js_sys::Reflect::get(&global, &"indexedDB".into())
        .map_err(|e| IdbError::Unavailable(format!("no indexedDB: {e:?}")))?;
    if idb.is_undefined() || idb.is_null() {
        return Err(IdbError::Unavailable("indexedDB is null/undefined".into()));
    }
    idb.dyn_into::<IdbFactory>()
        .map_err(|_| IdbError::Unavailable("indexedDB is not an IDBFactory".into()))
}

/// Await an `IDBRequest`'s `success` (resolving to `request.result`) or `error`.
/// Bridged through a JS `Promise` so we can reuse `JsFuture` rather than
/// hand-rolling a `Future`. The one-shot closures self-manage via
/// `once_into_js` (freed after they fire).
async fn await_request(req: &IdbRequest) -> Result<JsValue, IdbError> {
    let promise = js_sys::Promise::new(&mut |resolve, reject| {
        let req_ok = req.clone();
        let onsuccess = Closure::once_into_js(move |_e: web_sys::Event| {
            let result = req_ok.result().unwrap_or(JsValue::UNDEFINED);
            let _ = resolve.call1(&JsValue::NULL, &result);
        });
        req.set_onsuccess(Some(onsuccess.unchecked_ref()));

        let onerror = Closure::once_into_js(move |_e: web_sys::Event| {
            let _ = reject.call1(&JsValue::NULL, &JsValue::from_str("IDBRequest error"));
        });
        req.set_onerror(Some(onerror.unchecked_ref()));
    });
    JsFuture::from(promise).await.map_err(io)
}

/// Await an `IDBTransaction`'s `complete` (Ok) or `error`/`abort` (Err). A
/// transaction is durable once `complete` fires.
async fn await_txn(txn: &IdbTransaction) -> Result<(), IdbError> {
    let promise = js_sys::Promise::new(&mut |resolve, reject| {
        let oncomplete = Closure::once_into_js(move |_e: web_sys::Event| {
            let _ = resolve.call0(&JsValue::NULL);
        });
        txn.set_oncomplete(Some(oncomplete.unchecked_ref()));

        let reject_err = reject.clone();
        let onerror = Closure::once_into_js(move |_e: web_sys::Event| {
            let _ = reject_err.call1(&JsValue::NULL, &JsValue::from_str("IDBTransaction error"));
        });
        txn.set_onerror(Some(onerror.unchecked_ref()));

        let onabort = Closure::once_into_js(move |_e: web_sys::Event| {
            let _ = reject.call1(&JsValue::NULL, &JsValue::from_str("IDBTransaction abort"));
        });
        txn.set_onabort(Some(onabort.unchecked_ref()));
    });
    JsFuture::from(promise).await.map(|_| ()).map_err(io)
}

/// Open (or create+upgrade) the database `name` and ensure both object stores
/// exist. Async because IDB `open` is request-based.
async fn open_db(name: &str) -> Result<IdbDatabase, IdbError> {
    let factory = get_factory()?;
    let req: IdbOpenDbRequest = factory.open_with_u32(name, 1).map_err(io)?;

    // `upgradeneeded` fires on first open (or version bump) — create the stores.
    let req_upg = req.clone();
    let onupgrade = Closure::once_into_js(move |_e: web_sys::IdbVersionChangeEvent| {
        if let Ok(result) = req_upg.result() {
            if let Ok(db) = result.dyn_into::<IdbDatabase>() {
                // We only ever bump to version 1, so `upgradeneeded` fires once
                // on a fresh database where neither store exists. Creating
                // unconditionally is correct; a spurious failure is non-fatal
                // (the open still succeeds and replay just sees no records).
                let _ = db.create_object_store(STORE_ENTITIES);
                let _ = db.create_object_store(STORE_LOCATIONS);
            }
        }
    });
    req.set_onupgradeneeded(Some(onupgrade.unchecked_ref()));

    let result = await_request(&req).await?;
    let db: IdbDatabase = result
        .dyn_into()
        .map_err(|_| IdbError::Io("open did not yield an IDBDatabase".into()))?;

    // versionchange guard (multi-tab deadlock prevention). If another tab
    // opens this database at a HIGHER version, the browser fires `versionchange`
    // on our open connection. If we keep it open, that tab's `upgradeneeded`
    // transaction BLOCKS indefinitely — and the hang can persist across reloads
    // (Chromium #242115). We only ever open at version 1 today, so this never
    // fires yet; but the day the schema bumps, an un-closed old connection in a
    // second tab would deadlock the upgrade. Closing on `versionchange` is the
    // cheap, correct guard. Reads keep serving from the in-memory sync mirror;
    // the upgrading tab becomes authoritative (a reload-to-recover UX is a
    // later refinement, not needed while the schema is fixed at v1).
    let db_for_close = db.clone();
    let onversionchange = Closure::once_into_js(move |_e: web_sys::IdbVersionChangeEvent| {
        tracing::warn!(
            "IDB versionchange — another tab is upgrading the schema; closing this \
             connection so its upgrade can proceed (avoids a cross-tab deadlock)"
        );
        db_for_close.close();
    });
    db.set_onversionchange(Some(onversionchange.unchecked_ref()));

    Ok(db)
}

// ---------------------------------------------------------------------------
// Record value encoding (object-store-as-KV)
// ---------------------------------------------------------------------------

/// `entities` value: `[type_len:u16 BE][type utf-8][data]`. The key *is* the
/// 33-byte content hash, so the hash is not repeated in the value.
fn encode_entity_value(entity: &Entity) -> Vec<u8> {
    let type_bytes = entity.entity_type.as_bytes();
    let mut v = Vec::with_capacity(2 + type_bytes.len() + entity.data.len());
    v.extend_from_slice(&(type_bytes.len() as u16).to_be_bytes());
    v.extend_from_slice(type_bytes);
    v.extend_from_slice(&entity.data);
    v
}

fn decode_entity(key: &[u8], value: &[u8]) -> Result<Entity, IdbError> {
    let content_hash = Hash::from_bytes(key).map_err(|e| IdbError::Decode(format!("hash: {e}")))?;
    if value.len() < 2 {
        return Err(IdbError::Decode("entity value too short".into()));
    }
    let type_len = u16::from_be_bytes([value[0], value[1]]) as usize;
    let body_start = 2;
    let body_end = body_start + type_len;
    if body_end > value.len() {
        return Err(IdbError::Decode("entity_type truncated".into()));
    }
    let entity_type = std::str::from_utf8(&value[body_start..body_end])
        .map_err(|e| IdbError::Decode(format!("entity_type utf-8: {e}")))?
        .to_string();
    let data = value[body_end..].to_vec();
    Ok(Entity {
        entity_type,
        data,
        content_hash,
    })
}

// ---------------------------------------------------------------------------
// WriteBehind — the batched async drainer + checkpoint, shared by both stores
// ---------------------------------------------------------------------------

/// A pending mutation for a single key: either a put (with the encoded value)
/// or a delete. Coalesced last-write-wins per key.
enum Op {
    Put(Vec<u8>),
    Delete,
}

/// Interior state behind a single `RefCell`. Single-threaded WASM means all
/// access is uncontended; borrows are never held across an `.await`.
struct Inner {
    db: IdbDatabase,
    /// Coalesced dirty entities, keyed by hash bytes.
    entities: BTreeMap<Vec<u8>, Op>,
    /// Coalesced dirty locations, keyed by path.
    locations: BTreeMap<String, Op>,
    /// Monotonically increasing enqueue counter — the checkpoint target axis.
    seq: u64,
    /// Highest `seq` durably committed.
    flushed_seq: u64,
    /// True while the drain pump is running (serializes drains).
    draining: bool,
    /// True while a debounce timer is pending (avoid scheduling duplicates).
    debounce_pending: bool,
    /// Most recent flush error (cleared on the next success).
    last_error: Option<String>,
    /// Checkpoint waiters: `(target_seq, sender)`. Resolved Ok when
    /// `flushed_seq >= target_seq`, or Err if the covering flush failed.
    waiters: Vec<(u64, oneshot::Sender<Result<(), String>>)>,
}

impl Inner {
    fn pending_count(&self) -> usize {
        self.entities.len() + self.locations.len()
    }

    /// Resolve every waiter whose target is now durable.
    fn resolve_durable(&mut self) {
        let flushed = self.flushed_seq;
        let mut i = 0;
        while i < self.waiters.len() {
            if self.waiters[i].0 <= flushed {
                let (_, tx) = self.waiters.swap_remove(i);
                let _ = tx.send(Ok(()));
            } else {
                i += 1;
            }
        }
    }

    /// Fail every waiter whose records were in a batch that just errored, so a
    /// checkpoint surfaces the failure promptly instead of hanging. (Background
    /// retry still re-attempts the records for eventual write-behind durability.)
    fn fail_covered(&mut self, covered_seq: u64, err: &str) {
        let mut i = 0;
        while i < self.waiters.len() {
            if self.waiters[i].0 <= covered_seq {
                let (_, tx) = self.waiters.swap_remove(i);
                let _ = tx.send(Err(err.to_string()));
            } else {
                i += 1;
            }
        }
    }
}

/// The shared, cloneable write-behind flusher + checkpoint handle.
///
/// Cloning is a cheap `Rc` bump; every clone drives the same queue. Both
/// `IdbContentStore` and `IdbLocationIndex` hold a clone, and the peer builder
/// retains one to surface `checkpoint()` to the SDK/app.
#[derive(Clone)]
pub struct WriteBehind(Rc<RefCell<Inner>>);

// Re-exported public alias: the checkpoint *handle* callers reach for. Same
// type as `WriteBehind`; the alias names its role at the SDK/app boundary.
pub type IdbCheckpoint = WriteBehind;

// SAFETY: WASM is single-threaded. `Rc`/`RefCell`/`JsValue` are `!Send + !Sync`
// to prevent cross-thread access in mixed-target code, but on
// wasm32-unknown-unknown there is no other thread. Mirrors `opfs.rs`.
unsafe impl Send for WriteBehind {}
unsafe impl Sync for WriteBehind {}

impl WriteBehind {
    fn new(db: IdbDatabase) -> Self {
        Self(Rc::new(RefCell::new(Inner {
            db,
            entities: BTreeMap::new(),
            locations: BTreeMap::new(),
            seq: 0,
            flushed_seq: 0,
            draining: false,
            debounce_pending: false,
            last_error: None,
            waiters: Vec::new(),
        })))
    }

    /// A cheap snapshot of flush health for the durability-honesty surface.
    pub fn health(&self) -> FlushHealth {
        let inner = self.0.borrow();
        FlushHealth {
            pending_count: inner.pending_count(),
            last_flushed_seq: inner.flushed_seq,
            last_error: inner.last_error.clone(),
        }
    }

    /// ★ Await durability of every write enqueued before this call.
    ///
    /// Forces an immediate drain (bypassing the debounce) and resolves only once
    /// the covering IDB transaction has committed. This is what identity /
    /// destructive ops (create-peer, **delete-peer**, config commit) call before
    /// acknowledging — so delete durability does not depend on the debounce
    /// timer. Returns the flush error if the covering transaction failed.
    pub async fn checkpoint(&self) -> Result<(), IdbError> {
        let rx = {
            let mut inner = self.0.borrow_mut();
            // Fast path: everything already durable.
            if inner.pending_count() == 0 && inner.seq == inner.flushed_seq {
                return Ok(());
            }
            let target = inner.seq;
            let (tx, rx) = oneshot::channel();
            inner.waiters.push((target, tx));
            rx
        };
        // Kick an immediate drain (no debounce wait).
        self.kick_drain();
        match rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(IdbError::Io(e)),
            Err(_canceled) => Err(IdbError::Io("checkpoint dropped before flush".into())),
        }
    }

    // --- enqueue side (called from the sync trait impls) ---

    fn enqueue_entity_put(&self, key: Vec<u8>, value: Vec<u8>) {
        {
            let mut inner = self.0.borrow_mut();
            inner.seq += 1;
            inner.entities.insert(key, Op::Put(value));
        }
        self.schedule_debounced();
    }

    fn enqueue_entity_delete(&self, key: Vec<u8>) {
        {
            let mut inner = self.0.borrow_mut();
            inner.seq += 1;
            inner.entities.insert(key, Op::Delete);
        }
        self.schedule_debounced();
    }

    fn enqueue_location_put(&self, path: String, hash_bytes: Vec<u8>) {
        {
            let mut inner = self.0.borrow_mut();
            inner.seq += 1;
            inner.locations.insert(path, Op::Put(hash_bytes));
        }
        self.schedule_debounced();
    }

    fn enqueue_location_delete(&self, path: String) {
        {
            let mut inner = self.0.borrow_mut();
            inner.seq += 1;
            inner.locations.insert(path, Op::Delete);
        }
        self.schedule_debounced();
    }

    /// Schedule a debounced drain if no timer is already pending.
    fn schedule_debounced(&self) {
        {
            let mut inner = self.0.borrow_mut();
            if inner.debounce_pending {
                return;
            }
            inner.debounce_pending = true;
        }
        let me = self.clone();
        spawn_local(async move {
            TimeoutFuture::new(DEBOUNCE_MS).await;
            me.0.borrow_mut().debounce_pending = false;
            me.drain_pump().await;
        });
    }

    /// Kick an immediate (non-debounced) drain.
    fn kick_drain(&self) {
        let me = self.clone();
        spawn_local(async move {
            me.drain_pump().await;
        });
    }

    /// The single drain pump. Serialized by the `draining` flag so concurrent
    /// kicks (a debounce timer + a checkpoint) collapse into one runner that
    /// loops until the queue is empty, picking up writes enqueued mid-flush.
    /// **Never panics** — a failed transaction restores the dirty entries,
    /// records degraded health, fails covered checkpoint waiters, and schedules
    /// a retry. It must never unwind into the caller or the frame loop.
    async fn drain_pump(&self) {
        {
            let mut inner = self.0.borrow_mut();
            if inner.draining {
                return; // another pump is already running; it will see our work
            }
            inner.draining = true;
        }

        loop {
            // Snapshot a batch (take the dirty maps; record the seq it covers).
            let (entities, locations, covered) = {
                let mut inner = self.0.borrow_mut();
                if inner.entities.is_empty() && inner.locations.is_empty() {
                    // Nothing to write — resolve any already-durable waiters and stop.
                    inner.resolve_durable();
                    inner.draining = false;
                    return;
                }
                let entities = std::mem::take(&mut inner.entities);
                let locations = std::mem::take(&mut inner.locations);
                let covered = inner.seq;
                (entities, locations, covered)
            };

            match self.write_batch(&entities, &locations).await {
                Ok(()) => {
                    let mut inner = self.0.borrow_mut();
                    inner.flushed_seq = inner.flushed_seq.max(covered);
                    inner.last_error = None;
                    inner.resolve_durable();
                    // Loop again to flush anything enqueued during the txn.
                }
                Err(e) => {
                    let msg = e.to_string();
                    let mut inner = self.0.borrow_mut();
                    // Restore taken records, but never clobber a newer write that
                    // landed for the same key during the failed transaction.
                    restore(&mut inner.entities, entities);
                    restore(&mut inner.locations, locations);
                    inner.last_error = Some(msg.clone());
                    inner.fail_covered(covered, &msg);
                    inner.draining = false;
                    // Schedule a retry; the records are still queued.
                    let me = self.clone();
                    spawn_local(async move {
                        TimeoutFuture::new(RETRY_MS).await;
                        me.drain_pump().await;
                    });
                    return;
                }
            }
        }
    }

    /// Open one readwrite transaction spanning both stores, apply every op, and
    /// await the transaction's `complete`. Atomic across entities + locations.
    async fn write_batch(
        &self,
        entities: &BTreeMap<Vec<u8>, Op>,
        locations: &BTreeMap<String, Op>,
    ) -> Result<(), IdbError> {
        // Clone the db handle out so we don't hold the RefCell borrow across .await.
        let db = self.0.borrow().db.clone();

        let store_names = js_sys::Array::of2(&STORE_ENTITIES.into(), &STORE_LOCATIONS.into());
        let txn = db
            .transaction_with_str_sequence_and_mode(&store_names, IdbTransactionMode::Readwrite)
            .map_err(io)?;
        let es: IdbObjectStore = txn.object_store(STORE_ENTITIES).map_err(io)?;
        let ls: IdbObjectStore = txn.object_store(STORE_LOCATIONS).map_err(io)?;

        for (key, op) in entities {
            let key_js: JsValue = js_sys::Uint8Array::from(key.as_slice()).into();
            match op {
                Op::Put(value) => {
                    let val_js: JsValue = js_sys::Uint8Array::from(value.as_slice()).into();
                    es.put_with_key(&val_js, &key_js).map_err(io)?;
                }
                Op::Delete => {
                    es.delete(&key_js).map_err(io)?;
                }
            }
        }
        for (path, op) in locations {
            let key_js = JsValue::from_str(path);
            match op {
                Op::Put(value) => {
                    let val_js: JsValue = js_sys::Uint8Array::from(value.as_slice()).into();
                    ls.put_with_key(&val_js, &key_js).map_err(io)?;
                }
                Op::Delete => {
                    ls.delete(&key_js).map_err(io)?;
                }
            }
        }

        await_txn(&txn).await
    }
}

/// Re-insert `taken` records that failed to flush, without overwriting a newer
/// write for the same key that arrived during the failed transaction.
fn restore<K: Ord>(current: &mut BTreeMap<K, Op>, taken: BTreeMap<K, Op>) {
    for (k, op) in taken {
        current.entry(k).or_insert(op);
    }
}

// ---------------------------------------------------------------------------
// IdbStore — factory holding both stores + the shared flusher
// ---------------------------------------------------------------------------

/// Factory that opens the IDB database, replays it into in-memory mirrors, and
/// exposes the two backing stores plus the shared checkpoint handle. Mirrors
/// `OpfsStore`'s shape so it drops into the existing builder seam.
pub struct IdbStore {
    content_store: IdbContentStore,
    location_index: IdbLocationIndex,
    checkpoint: IdbCheckpoint,
}

impl IdbStore {
    /// Open the IDB database `name`, replay every persisted record into the
    /// in-memory mirrors, and return the sync-facing stores. Async because IDB
    /// `open` + the initial scan are request-based — exactly like
    /// `OpfsStore::open(root).await`.
    ///
    /// Multiple `IdbStore` instances in one origin SHOULD use distinct database
    /// `name`s; concurrent writers to the same database race (last-writer-wins)
    /// and should be gated by the app's single-writer lock (the same Web Lock
    /// that gates the OPFS worker).
    pub async fn open(name: &str) -> Result<Self, IdbError> {
        let db = open_db(name).await?;

        let content_memory = MemoryContentStore::new();
        let location_memory = MemoryLocationIndex::new();
        replay(&db, &content_memory, &location_memory).await?;

        let checkpoint = WriteBehind::new(db);
        let content_store = IdbContentStore {
            memory: content_memory,
            flusher: checkpoint.clone(),
        };
        let location_index = IdbLocationIndex {
            memory: location_memory,
            flusher: checkpoint.clone(),
        };

        Ok(Self {
            content_store,
            location_index,
            checkpoint,
        })
    }

    /// The shared checkpoint handle. Grab this **before** `into_parts()` (which
    /// consumes `self`); the peer builder retains it to surface `checkpoint()`.
    pub fn checkpoint(&self) -> IdbCheckpoint {
        self.checkpoint.clone()
    }

    /// Consume into the two sync stores. The factory only exists to coordinate
    /// the async open + replay.
    pub fn into_parts(self) -> (IdbContentStore, IdbLocationIndex) {
        (self.content_store, self.location_index)
    }
}

/// Replay both object stores into the in-memory mirrors via `getAll` +
/// `getAllKeys` (one request pair per store — no cursor loop).
async fn replay(
    db: &IdbDatabase,
    content: &MemoryContentStore,
    locations: &MemoryLocationIndex,
) -> Result<(), IdbError> {
    let store_names = js_sys::Array::of2(&STORE_ENTITIES.into(), &STORE_LOCATIONS.into());
    let txn = db
        .transaction_with_str_sequence(&store_names)
        .map_err(io)?;

    // entities
    let es = txn.object_store(STORE_ENTITIES).map_err(io)?;
    let keys = js_sys::Array::from(&await_request(&es.get_all_keys().map_err(io)?).await?);
    let values = js_sys::Array::from(&await_request(&es.get_all().map_err(io)?).await?);
    for i in 0..keys.length() {
        let key = js_sys::Uint8Array::new(&keys.get(i)).to_vec();
        let value = js_sys::Uint8Array::new(&values.get(i)).to_vec();
        match decode_entity(&key, &value) {
            Ok(entity) => {
                let _ = content.put(entity);
            }
            Err(e) => {
                tracing::warn!(error = %e, "idb entities record decode failed, skipping");
            }
        }
    }

    // locations
    let ls = txn.object_store(STORE_LOCATIONS).map_err(io)?;
    let keys = js_sys::Array::from(&await_request(&ls.get_all_keys().map_err(io)?).await?);
    let values = js_sys::Array::from(&await_request(&ls.get_all().map_err(io)?).await?);
    for i in 0..keys.length() {
        let path = match keys.get(i).as_string() {
            Some(p) => p,
            None => {
                tracing::warn!("idb locations key is not a string, skipping");
                continue;
            }
        };
        let hash_bytes = js_sys::Uint8Array::new(&values.get(i)).to_vec();
        match Hash::from_bytes(&hash_bytes) {
            Ok(hash) => locations.set(&path, hash),
            Err(e) => tracing::warn!(error = %e, path = %path, "idb location hash decode failed"),
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// IdbContentStore
// ---------------------------------------------------------------------------

/// `ContentStore` whose reads hit the sync mirror and whose writes update the
/// mirror then enqueue to the shared write-behind flusher.
pub struct IdbContentStore {
    memory: MemoryContentStore,
    flusher: WriteBehind,
}

// SAFETY: see `WriteBehind` — single-threaded WASM.
unsafe impl Send for IdbContentStore {}
unsafe impl Sync for IdbContentStore {}

impl ContentStore for IdbContentStore {
    fn put(&self, entity: Entity) -> Result<Hash, StoreError> {
        let hash = self.memory.put(entity.clone())?; // sync mirror update
        self.flusher
            .enqueue_entity_put(hash.to_bytes().to_vec(), encode_entity_value(&entity));
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
            self.flusher.enqueue_entity_delete(hash.to_bytes().to_vec());
        }
        existed
    }

    fn len(&self) -> usize {
        self.memory.len()
    }
}

// ---------------------------------------------------------------------------
// IdbLocationIndex
// ---------------------------------------------------------------------------

/// `LocationIndex` whose reads hit the sync mirror and whose writes update the
/// mirror then enqueue to the shared write-behind flusher. CAS resolves against
/// the sync mirror — single-threaded WASM makes the in-memory check-and-set
/// atomic — then the resulting change is enqueued.
pub struct IdbLocationIndex {
    memory: MemoryLocationIndex,
    flusher: WriteBehind,
}

// SAFETY: see `WriteBehind` — single-threaded WASM.
unsafe impl Send for IdbLocationIndex {}
unsafe impl Sync for IdbLocationIndex {}

impl LocationIndex for IdbLocationIndex {
    fn set(&self, path: &str, hash: Hash) {
        self.memory.set(path, hash);
        self.flusher
            .enqueue_location_put(path.to_string(), hash.to_bytes().to_vec());
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
            self.flusher.enqueue_location_delete(path.to_string());
        }
        removed
    }

    fn list(&self, prefix: &str) -> Vec<LocationEntry> {
        self.memory.list(prefix)
    }

    fn len_prefix(&self, prefix: &str) -> usize {
        self.memory.len_prefix(prefix)
    }

    fn compare_and_swap(&self, path: &str, expected: Hash, new_hash: Hash) -> Result<(), CasError> {
        self.memory.compare_and_swap(path, expected, new_hash)?;
        self.flusher
            .enqueue_location_put(path.to_string(), new_hash.to_bytes().to_vec());
        Ok(())
    }

    fn compare_and_remove(&self, path: &str, expected: Hash) -> Result<Hash, CasError> {
        let removed = self.memory.compare_and_remove(path, expected)?;
        self.flusher.enqueue_location_delete(path.to_string());
        Ok(removed)
    }

    fn compare_and_create(&self, path: &str, new_hash: Hash) -> Result<(), CasError> {
        self.memory.compare_and_create(path, new_hash)?;
        self.flusher
            .enqueue_location_put(path.to_string(), new_hash.to_bytes().to_vec());
        Ok(())
    }
}
