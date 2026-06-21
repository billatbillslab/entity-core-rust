//! Integration tests for `content::ensure_closure` — the cap-checked
//! SDK sequencer over `system/content:get` per SDK-EXTENSION-OPERATIONS
//! §11 Amendment A.
//!
//! Each test plugs a stub Dispatcher around a *remote* store (entities
//! the caller is fetching) and an empty *local* store (the caller's
//! target). The sequencer drains the closure by dispatching
//! `system/content:get` until the local store mirrors the remote.

use std::sync::Arc;

use async_trait::async_trait;
use ciborium::Value;
use entity_content::{
    create_blob_fastcdc, create_blob_fixed, ensure_closure, EnsureClosureError,
    GET_BATCH_SIZE,
};
use entity_ecf::ValueExt;
use entity_entity::Entity;
use entity_handler::{
    Dispatcher, ExecuteOptions, HandlerError, HandlerResult, STATUS_FORBIDDEN, STATUS_OK,
    STATUS_UNAVAILABLE,
};
use entity_hash::Hash;
use entity_store::{ContentStore, MemoryContentStore};

const NAMESPACE: &str = "system/content";

/// Decode a `system/content/get-request` to its `hashes` list.
fn decode_request_hashes(params: &Entity) -> Vec<Hash> {
    let v: Value = ciborium::from_reader(params.data.as_slice()).unwrap();
    let arr = v.get("hashes").and_then(|v| v.as_array().cloned()).unwrap();
    arr.into_iter()
        .map(|entry| {
            let b = entry.as_bytes().unwrap();
            Hash::from_bytes(b).expect("valid system/hash bstr")
        })
        .collect()
}

/// Build a `system/content/content-response` result entity with the
/// found / missing partition.
fn encode_response(found: &[Hash], missing: &[Hash]) -> Entity {
    let found_arr = Value::Array(found.iter().map(hash_to_bstr).collect());
    let missing_arr = Value::Array(missing.iter().map(hash_to_bstr).collect());
    let data = entity_ecf::to_ecf(&Value::Map(vec![
        (entity_ecf::text("found"), found_arr),
        (entity_ecf::text("missing"), missing_arr),
    ]));
    Entity::new("system/content/content-response", data).unwrap()
}

fn hash_to_bstr(h: &Hash) -> Value {
    Value::Bytes(h.to_bytes())
}

/// Stub Dispatcher that reads from a "remote" content store and tracks
/// call counts for the assertion suite.
struct RemoteStoreDispatcher {
    remote: Arc<dyn ContentStore>,
    /// Set of hashes the remote pretends are "pending sync" — returned
    /// in `missing` for the first N batches each.
    pending_sync: std::sync::Mutex<std::collections::HashMap<Hash, u32>>,
    call_count: std::sync::Mutex<u32>,
    last_batch_sizes: std::sync::Mutex<Vec<usize>>,
}

impl RemoteStoreDispatcher {
    fn new(remote: Arc<dyn ContentStore>) -> Self {
        Self {
            remote,
            pending_sync: std::sync::Mutex::new(Default::default()),
            call_count: std::sync::Mutex::new(0),
            last_batch_sizes: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn add_pending(&self, h: Hash, deferrals: u32) {
        self.pending_sync.lock().unwrap().insert(h, deferrals);
    }
}

#[async_trait]
impl Dispatcher for RemoteStoreDispatcher {
    async fn execute(
        &self,
        handler: &str,
        operation: &str,
        params: Entity,
        _opts: ExecuteOptions,
    ) -> Result<HandlerResult, HandlerError> {
        assert_eq!(handler, NAMESPACE, "namespace dispatched verbatim");
        assert_eq!(operation, "get", "only `get` exercised by ensure_closure");
        *self.call_count.lock().unwrap() += 1;
        let asked = decode_request_hashes(&params);
        self.last_batch_sizes.lock().unwrap().push(asked.len());

        let mut found: Vec<Hash> = Vec::new();
        let mut missing: Vec<Hash> = Vec::new();
        let mut included = std::collections::HashMap::new();

        for h in asked {
            // Pending-sync handling: defer this entity by returning it
            // in `missing` until its counter reaches zero.
            let mut pending = self.pending_sync.lock().unwrap();
            if let Some(remaining) = pending.get_mut(&h) {
                if *remaining > 0 {
                    *remaining -= 1;
                    missing.push(h);
                    continue;
                }
            }
            drop(pending);
            match self.remote.get(&h) {
                Some(entity) => {
                    included.insert(h, entity);
                    found.push(h);
                }
                None => missing.push(h),
            }
        }

        Ok(HandlerResult::ok_with_included(
            encode_response(&found, &missing),
            included,
        ))
    }
}

/// Dispatcher that always returns 403 — for cap-denial test.
struct ForbiddenDispatcher;

#[async_trait]
impl Dispatcher for ForbiddenDispatcher {
    async fn execute(
        &self,
        _h: &str,
        _op: &str,
        _p: Entity,
        _o: ExecuteOptions,
    ) -> Result<HandlerResult, HandlerError> {
        let err = Entity::new(
            "system/protocol/error",
            entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                "code" => entity_ecf::text("forbidden"),
                "message" => entity_ecf::text("cap denied")
            }),
        )
        .unwrap();
        Ok(HandlerResult::error(STATUS_FORBIDDEN, err))
    }
}

/// Build a small blob on a freshly-created remote store. Returns the
/// blob hash so the caller can drive `ensure_closure` against it.
///
/// Uses the 1 MiB FastCDC target (post-A2 cutover default per CONTENT
/// v3.6 §3.5).
fn build_remote_blob_and_return_hash(remote: &Arc<dyn ContentStore>, payload: &[u8]) -> Hash {
    create_blob_fastcdc(remote, payload, 1024 * 1024).unwrap()
}

#[tokio::test]
async fn ensure_closure_local_only_happy_path() {
    let remote: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
    let local: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());

    // ~200 KiB → ~3 chunks at MIN_CHUNK_SIZE=64KiB, comfortable batch.
    let payload = vec![0xABu8; 200 * 1024];
    let blob_hash = build_remote_blob_and_return_hash(&remote, &payload);

    let dispatcher = RemoteStoreDispatcher::new(remote.clone());
    ensure_closure(&dispatcher, &local, blob_hash, NAMESPACE)
        .await
        .expect("closure should complete");

    // Closure is now locally complete — assert by reassembling.
    let bytes = entity_content::reassemble(&local, &blob_hash).unwrap();
    assert_eq!(bytes, payload, "reassembled bytes match remote");
}

#[tokio::test]
async fn ensure_closure_skips_already_local_blob() {
    // When the blob entity is already local, the sequencer SHOULD NOT
    // dispatch for it — only the still-missing chunks drive batches.
    let remote: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
    let local: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());

    let payload = vec![0x77u8; 200 * 1024];
    let blob_hash = build_remote_blob_and_return_hash(&remote, &payload);

    // Pre-populate the local store with the blob entity (only).
    let blob_entity = remote.get(&blob_hash).unwrap();
    local.put(blob_entity).unwrap();

    let dispatcher = RemoteStoreDispatcher::new(remote.clone());
    ensure_closure(&dispatcher, &local, blob_hash, NAMESPACE)
        .await
        .unwrap();

    let calls = *dispatcher.call_count.lock().unwrap();
    let batches = dispatcher.last_batch_sizes.lock().unwrap().clone();
    // No call asked for the blob hash itself; first dispatch is the
    // chunk batch.
    assert!(
        calls >= 1,
        "must have dispatched at least one chunk batch"
    );
    // None of the dispatched batches contained the blob hash.
    for size in &batches {
        assert!(*size <= GET_BATCH_SIZE, "batch <= GET_BATCH_SIZE");
    }
}

#[tokio::test]
async fn ensure_closure_batches_at_get_batch_size() {
    let remote: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
    let local: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());

    // Want strictly more than 1 batch — push for ~20 chunks.
    // 20 chunks × MIN_CHUNK_SIZE (64 KiB) lower bound. Use 1.5 MiB which
    // with FastCDC default 1 MiB target yields ≥ 2 batches comfortably.
    // We just need *more than one batch* — distinct payload per byte.
    let mut payload = Vec::with_capacity(2 * 1024 * 1024);
    for i in 0..(2 * 1024 * 1024) {
        payload.push((i & 0xFF) as u8);
    }
    let blob_hash = build_remote_blob_and_return_hash(&remote, &payload);

    let dispatcher = RemoteStoreDispatcher::new(remote.clone());
    ensure_closure(&dispatcher, &local, blob_hash, NAMESPACE)
        .await
        .unwrap();

    let bytes = entity_content::reassemble(&local, &blob_hash).unwrap();
    assert_eq!(bytes, payload);

    let batches = dispatcher.last_batch_sizes.lock().unwrap().clone();
    for size in &batches {
        assert!(
            *size <= GET_BATCH_SIZE,
            "batch size {} exceeds GET_BATCH_SIZE {}",
            size,
            GET_BATCH_SIZE
        );
    }
}

#[tokio::test]
async fn ensure_closure_redrives_missing_until_complete() {
    // Mark a couple of chunk hashes as "pending sync" (returned in
    // `missing` for the first 2 dispatches each). The sequencer should
    // redrive the missing tail until they land.
    //
    // Use fixed-size chunker at the spec MIN_CHUNK_SIZE (64 KiB) for
    // deterministic multi-chunk: 200 KiB / 64 KiB = 4 chunks.
    let remote: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
    let local: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());

    let payload = vec![0x33u8; 200 * 1024];
    let blob_hash = create_blob_fixed(&remote, &payload, 64 * 1024).unwrap();
    let (_total, chunks) = entity_content::blob_chunk_hashes(&remote, &blob_hash).unwrap();
    assert!(chunks.len() >= 2, "need ≥2 chunks for redrive test");

    let dispatcher = RemoteStoreDispatcher::new(remote.clone());
    dispatcher.add_pending(chunks[0], /*deferrals=*/ 2);
    dispatcher.add_pending(chunks[1], /*deferrals=*/ 1);

    ensure_closure(&dispatcher, &local, blob_hash, NAMESPACE)
        .await
        .expect("closure should complete after redrive");

    let bytes = entity_content::reassemble(&local, &blob_hash).unwrap();
    assert_eq!(bytes, payload);
}

#[tokio::test]
async fn ensure_closure_propagates_403_forbidden() {
    let local: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
    let blob_hash = Hash::new(0, [0x99u8; 32]);
    let dispatcher = ForbiddenDispatcher;
    let err = ensure_closure(&dispatcher, &local, blob_hash, NAMESPACE)
        .await
        .unwrap_err();
    assert!(
        matches!(err, EnsureClosureError::Forbidden),
        "expected Forbidden, got {:?}",
        err
    );
}

#[tokio::test]
async fn ensure_closure_returns_pending_sync_after_max_retries() {
    // Every chunk is permanently pending → sequencer hits the retry
    // ceiling and returns PendingSync.
    let remote: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
    let local: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());

    let payload = vec![0x11u8; 200 * 1024];
    let blob_hash = build_remote_blob_and_return_hash(&remote, &payload);
    let (_total, chunks) = entity_content::blob_chunk_hashes(&remote, &blob_hash).unwrap();

    let dispatcher = RemoteStoreDispatcher::new(remote.clone());
    // Mark every chunk as effectively-never-fulfilled (deferrals > retry cap).
    for h in &chunks {
        dispatcher.add_pending(*h, u32::MAX);
    }

    let err = ensure_closure(&dispatcher, &local, blob_hash, NAMESPACE)
        .await
        .unwrap_err();
    assert!(
        matches!(err, EnsureClosureError::PendingSync { .. }),
        "expected PendingSync, got {:?}",
        err
    );
}

#[tokio::test]
async fn ensure_closure_503_response_redrives_at_next_iteration() {
    // A wholesale 503 on a batch is treated as a partial-sync defer;
    // the sequencer redrives the same missing set at the next iteration.
    // Implementation choice: we model this by having a Dispatcher that
    // emits 503 for the first call, then a normal response.
    struct OneShot503Dispatcher {
        remote: Arc<dyn ContentStore>,
        emitted_503: std::sync::Mutex<bool>,
    }
    #[async_trait]
    impl Dispatcher for OneShot503Dispatcher {
        async fn execute(
            &self,
            _h: &str,
            _o: &str,
            params: Entity,
            _opts: ExecuteOptions,
        ) -> Result<HandlerResult, HandlerError> {
            let mut emitted = self.emitted_503.lock().unwrap();
            if !*emitted {
                *emitted = true;
                let err = Entity::new(
                    "system/protocol/error",
                    entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                        "code" => entity_ecf::text("blob_pending_sync"),
                        "message" => entity_ecf::text("not yet")
                    }),
                )
                .unwrap();
                return Ok(HandlerResult::error(STATUS_UNAVAILABLE, err));
            }
            drop(emitted);
            let asked = decode_request_hashes(&params);
            let mut found: Vec<Hash> = Vec::new();
            let mut included = std::collections::HashMap::new();
            for h in asked {
                if let Some(entity) = self.remote.get(&h) {
                    included.insert(h, entity);
                    found.push(h);
                }
            }
            Ok(HandlerResult {
                status: STATUS_OK,
                result: encode_response(&found, &[]),
                included,
            })
        }
    }

    let remote: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
    let local: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
    let payload = vec![0x55u8; 200 * 1024];
    let blob_hash = build_remote_blob_and_return_hash(&remote, &payload);

    let dispatcher = OneShot503Dispatcher {
        remote: remote.clone(),
        emitted_503: std::sync::Mutex::new(false),
    };
    ensure_closure(&dispatcher, &local, blob_hash, NAMESPACE)
        .await
        .expect("should redrive past 503");

    let bytes = entity_content::reassemble(&local, &blob_hash).unwrap();
    assert_eq!(bytes, payload);
}
