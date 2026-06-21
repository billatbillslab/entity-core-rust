//! Closure completion — cap-checked SDK sequencer over `system/content:get`.
//!
//! Per SDK-EXTENSION-OPERATIONS §11 (paired with the content-materialization
//! proposal, Amendment A): [`ensure_closure`] drives `system/content:get` dispatches
//! until the requested blob's closure (blob entity + every chunk it
//! references) is locally present in the content store. Pure cap-checked
//! sequencer — every dispatch goes through the cap-checked `Dispatcher`
//! shape; no privilege amplification beyond what direct `system/content:get`
//! already permits.
//!
//! **Entity-shape end-to-end.** This function returns `()`. Byte extraction
//! is a separate local concern — call [`crate::reassemble`] over the local
//! `ContentStore` once closure-completion succeeds.
//!
//! [`at_peer`] returns a [`PeerAimedDispatcher`] for the
//! handler-cross-peer case (a handler running on B that needs to dispatch
//! `system/content:get` against A's namespace; workbench Stage 3 case 1.5).

use std::sync::Arc;

use ciborium::Value;
use entity_ecf::{cbor_map, to_ecf};
use entity_entity::Entity;
use entity_handler::{
    Dispatcher, ExecuteOptions, HandlerContext, PeerAimedDispatcher, STATUS_FORBIDDEN,
    STATUS_NOT_FOUND, STATUS_OK, STATUS_UNAVAILABLE,
};
use entity_hash::Hash;
use entity_store::ContentStore;
use thiserror::Error;

use crate::verify::{blob_chunk_hashes, VerifyError};

/// Initial `GET_BATCH_SIZE` per CONTENT v3.6 §7.1 streaming wire ingest.
/// Sender-side batching SHOULD (§7.4 transport-aware batching responsibility
/// split, v3.6 Amendment 1) — tunable per deployment.
pub const GET_BATCH_SIZE: usize = 16;

/// Maximum retries on partial-sync `503 blob_pending_sync` per single
/// closure-completion call. Each retry redrives only the still-missing
/// tail. Caller-side adaptive backoff is the caller's concern; this is
/// the local fail-fast bound.
const MAX_PENDING_SYNC_RETRIES: u32 = 8;

#[derive(Debug, Error)]
pub enum EnsureClosureError {
    /// Cap denial — per V7 §5.2. `system/content:get` dispatch was refused.
    #[error("cap denied for system/content:get on namespace")]
    Forbidden,

    /// A requested entity (blob or chunk) is reported absent and not
    /// expected to arrive. Per CONTENT v3.6 §3.4 sync-state-visibility:
    /// the remote signaled the entity is not coming, not just pending.
    #[error("entity not found: {0}")]
    NotFound(Hash),

    /// Closure is partially synced past the policy bound — caller retries
    /// on the next sync event per partial-sync taxonomy (CONTENT v3.6 §3.4).
    /// Carries the unresolved-tail hash for caller telemetry.
    #[error("blob pending sync; closure incomplete after {retries} retries")]
    PendingSync { retries: u32 },

    /// The dispatched handler returned an unexpected status. Carries the
    /// numeric status verbatim so the caller can re-classify.
    #[error("unexpected dispatch status {status}")]
    Dispatch { status: u32 },

    /// Local content store rejected a put (encoding mismatch, hash
    /// mismatch). Indicates a bug in the closure pipeline; surface to the
    /// caller.
    #[error("local store put failed: {0}")]
    Store(String),

    /// Wire-shape decode failed on a dispatch response. Indicates the
    /// remote sent something the protocol shape doesn't allow, OR a
    /// dispatcher-layer bug.
    #[error("decode: {0}")]
    Decode(String),

    /// Verifier rejected the blob shape (e.g., the local store reports a
    /// "blob" whose chunk list is malformed). Wraps the verify error.
    #[error("verify: {0}")]
    Verify(#[from] VerifyError),
}

/// Drive `system/content:get` against the namespace handler until the
/// blob's closure (blob entity + every referenced chunk) is locally
/// present in `store`.
///
/// Per SDK-EXTENSION-OPERATIONS §11 Amendment A. Returns `Ok(())` on
/// closure-complete; surfaces structured errors per
/// [`EnsureClosureError`] for the four spec-named failure modes (403 /
/// 404 / repeated 503 / unexpected).
///
/// **Cap-flow.** Each dispatch is cap-checked at the dispatcher; the
/// caller's grant must cover `system/content:get` on `namespace`. For
/// handler-internal callers, the handler's `internal_scope` is the
/// surface (V7 §6.8 v7.49); for outer callers, the caller's grant
/// applies. Per Scenario A/C/D analysis in the proposal, no privilege
/// amplification.
pub async fn ensure_closure(
    dispatcher: &dyn Dispatcher,
    store: &Arc<dyn ContentStore>,
    blob_hash: Hash,
    namespace: &str,
) -> Result<(), EnsureClosureError> {
    // Step 1 — blob check. If the blob entity isn't local, fetch it.
    // 503 / partial-sync retries apply here too: the remote may not yet
    // have the blob mirrored. Loop with the same ceiling as chunks; if
    // the blob never arrives, surface PendingSync vs NotFound by
    // distinguishing a 404 (NotFound returned by fetch_and_store) from
    // a perpetual `missing` (PendingSync).
    {
        let mut retries: u32 = 0;
        while store.get(&blob_hash).is_none() {
            fetch_and_store(dispatcher, store, &[blob_hash], namespace).await?;
            if store.get(&blob_hash).is_some() {
                break;
            }
            retries += 1;
            if retries > MAX_PENDING_SYNC_RETRIES {
                return Err(EnsureClosureError::PendingSync { retries });
            }
        }
    }

    // Step 2 — enumerate chunks. blob_chunk_hashes validates the entity
    // type and decodes the in-order chunk list.
    let (_total_size, chunk_hashes) = blob_chunk_hashes(store, &blob_hash)?;

    // Step 3/4 — drain missing chunks in GET_BATCH_SIZE windows with
    // partial-sync retries.
    let mut missing_local: Vec<Hash> = chunk_hashes
        .into_iter()
        .filter(|h| store.get(h).is_none())
        .collect();
    let mut retries: u32 = 0;
    while !missing_local.is_empty() {
        for window in missing_local.chunks(GET_BATCH_SIZE) {
            fetch_and_store(dispatcher, store, window, namespace).await?;
        }
        let still_missing: Vec<Hash> = missing_local
            .into_iter()
            .filter(|h| store.get(h).is_none())
            .collect();
        if still_missing.is_empty() {
            return Ok(());
        }
        retries += 1;
        if retries > MAX_PENDING_SYNC_RETRIES {
            return Err(EnsureClosureError::PendingSync { retries });
        }
        missing_local = still_missing;
    }
    Ok(())
}

/// Convenience constructor matching SDK-EXTENSION-OPERATIONS §11
/// `content.AtPeer(handler_ctx, source_peer_id) → Dispatcher`. Returns
/// the peer-aimed Dispatcher that rewrites every dispatched URI to
/// `entity://{source_peer_id}/{handler}`.
///
/// Returns `None` when the `HandlerContext` lacks an `execute_fn`
/// (e.g., a unit-test stub for a non-dispatching handler).
pub fn at_peer<'a>(
    handler_ctx: &'a HandlerContext,
    source_peer_id: &str,
) -> Option<PeerAimedDispatcher<'a>> {
    PeerAimedDispatcher::new(handler_ctx, source_peer_id)
}

/// Single batched fetch — dispatch `system/content:get` for `hashes`,
/// decode the response, store every entity in `included`. Handles the
/// 403 / 404 / 503 / OK classifications per spec.
async fn fetch_and_store(
    dispatcher: &dyn Dispatcher,
    store: &Arc<dyn ContentStore>,
    hashes: &[Hash],
    namespace: &str,
) -> Result<(), EnsureClosureError> {
    let params = build_get_request(hashes);
    let opts = ExecuteOptions {
        resource: Some(entity_capability::ResourceTarget {
            targets: vec![namespace.to_string()],
            exclude: vec![],
        }),
        ..ExecuteOptions::default()
    };
    let result = dispatcher
        .execute(namespace, "get", params, opts)
        .await
        .map_err(|e| EnsureClosureError::Decode(format!("dispatch: {e}")))?;

    match result.status {
        STATUS_OK => {}
        STATUS_FORBIDDEN => return Err(EnsureClosureError::Forbidden),
        STATUS_NOT_FOUND => {
            return Err(EnsureClosureError::NotFound(
                hashes.first().copied().unwrap_or_else(Hash::zero),
            ));
        }
        STATUS_UNAVAILABLE => return Ok(()), // re-drive at next iteration
        other => return Err(EnsureClosureError::Dispatch { status: other }),
    }

    // Store every entity riding in `included`. Each key is the entity's
    // content hash; the put preserves byte fidelity.
    for (_h, entity) in result.included.into_iter() {
        // Validate the put matches the expected key — the local store
        // recomputes the hash on put.
        store
            .put(entity)
            .map_err(|e| EnsureClosureError::Store(e.to_string()))?;
    }
    Ok(())
}

fn build_get_request(hashes: &[Hash]) -> Entity {
    let arr: Vec<Value> = hashes.iter().map(hash_to_bstr).collect();
    let data = to_ecf(&cbor_map! {
        "hashes" => Value::Array(arr)
    });
    Entity::new("system/content/get-request", data)
        .expect("get-request type is valid")
}

fn hash_to_bstr(h: &Hash) -> Value {
    Value::Bytes(h.to_bytes())
}

