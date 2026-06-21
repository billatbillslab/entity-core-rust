//! Reverse write (DOMAIN-LOCAL-FILES §5).
//!
//! Tree → filesystem. Implemented as a consumer of the peer's tree-change
//! broadcast (`TreeChangeEvent`). The §10.1 MUST pins observable behavior
//! (reverse-write fires for tree changes within configured root prefixes),
//! not subscription wiring — the global-event-stream filter form satisfies
//! the MUST per §5.1's flexibility note. The blob-hash circuit breaker
//! (§5.5) prevents the watcher→tree→reverse-write→watcher loop.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use entity_content::{
    blob_chunk_size, create_blob_fastcdc, reassemble, reassemble_stream,
};
use entity_entity::EntityUri;
use entity_hash::Hash;
use entity_store::{ChangeType, ContentStore, TreeChangeEvent};
use tokio::sync::broadcast;

use crate::handler::LocalFilesHandler;
use crate::types::{FileData, TYPE_FILE};

/// v3.6 §3.5 — 1 MiB default per A2 cutover (was 4 MiB in v3.5).
/// Only used as the fallback in current_disk_blob_hash when the
/// incoming blob's chunk_size is unreadable; the §5.5 MUST primary
/// path uses the incoming blob's chunk_size.
const DEFAULT_CHUNK_SIZE: usize = 1 * 1024 * 1024;
const RECENT_WRITE_WINDOW: Duration = Duration::from_secs(5);
/// L4 streaming cutoff per DOMAIN-LOCAL-FILES v1.3 §5.3 (RECOMMENDED 64 MiB).
const STREAMING_THRESHOLD: u64 = 64 * 1024 * 1024;

/// Wire the reverse-write loop. Subscribes to `events`, filters down to
/// changes inside configured root prefixes owned by this peer, and
/// writes the corresponding file to disk.
pub fn start_reverse_write(
    handler: Arc<LocalFilesHandler>,
    events: broadcast::Receiver<TreeChangeEvent>,
) {
    let tracker = Arc::new(ReverseTracker::default());
    tokio::spawn(async move {
        reverse_write_loop(handler, events, tracker).await;
    });
}

async fn reverse_write_loop(
    handler: Arc<LocalFilesHandler>,
    mut events: broadcast::Receiver<TreeChangeEvent>,
    tracker: Arc<ReverseTracker>,
) {
    loop {
        match events.recv().await {
            Ok(evt) => {
                if let Err(e) = process_event(&handler, &evt, &tracker) {
                    tracing::trace!(error = %e, path = %evt.path, "reverse write skipped");
                }
            }
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

fn process_event(
    handler: &LocalFilesHandler,
    evt: &TreeChangeEvent,
    tracker: &ReverseTracker,
) -> Result<(), String> {
    // Only react to changes inside the local peer's namespace.
    let bare = EntityUri::strip_peer_prefix(&evt.path);
    if bare.starts_with("system/") {
        return Ok(());
    }
    let root = match handler.find_root_mapping(bare) {
        Some(r) => r,
        None => return Ok(()),
    };
    if root.read_only {
        return Ok(());
    }
    if tracker.is_recently_written(bare) {
        return Ok(());
    }

    let relative = bare
        .strip_prefix(&root.prefix)
        .ok_or_else(|| "prefix mismatch".to_string())?;

    // v1.3 §8.3 callsite MUST: reverse-write and reverse-delete route
    // through resolve_fs_path_relative, applying both parent-traversal
    // and leaf-symlink defenses. Go's L5 audit (commit `ba21372`) found
    // these paths bypassing the resolver entirely — Rust had the same
    // bug. Reverse-write is the more critical defense surface (input is
    // incoming sync content, not a local user action).
    let fs_path = match crate::config::resolve_fs_path_relative(&root, relative) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(path = %evt.path, error = %e, "reverse write rejected by path defense");
            return Ok(());
        }
    };

    match evt.change_type {
        ChangeType::Deleted => {
            // Reverse-delete also goes through the resolver. NotFound is
            // benign here — sync may have produced a delete for a path
            // we don't have on disk.
            match std::fs::remove_file(&fs_path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    tracing::warn!(path = %fs_path.display(), error = %e, "reverse delete failed");
                }
            }
            handler.stat_cache.forget(&fs_path);
            Ok(())
        }
        ChangeType::Created | ChangeType::Modified => {
            reverse_write_file(handler, &root.fs_root, &fs_path, evt.hash, tracker, bare)
        }
    }
}

fn reverse_write_file(
    handler: &LocalFilesHandler,
    _root_fs: &std::path::Path,
    fs_path: &std::path::Path,
    file_entity_hash: Hash,
    tracker: &ReverseTracker,
    bare_path: &str,
) -> Result<(), String> {
    let entity = match handler.content_store.get(&file_entity_hash) {
        Some(e) => e,
        None => return Ok(()),
    };
    if entity.entity_type != TYPE_FILE {
        return Ok(());
    }
    let file_data = decode_file_data(&entity)?;
    if file_data.content.is_zero() {
        return Ok(());
    }

    // v1.3 Amendment 3 §5.3 + §5.5 MUST — fetch the incoming blob entity
    // EARLY and read its chunk_size for the circuit-breaker recompute.
    // Without this, a peer running a different DEFAULT_CHUNK_SIZE (e.g.,
    // pre-A2 4 MiB vs. post-A2 1 MiB) re-chunks the on-disk file at the
    // wrong size, hashes diverge, and the circuit-breaker spuriously
    // rewrites identical content. Spec §5.5 normative MUST.
    let incoming_blob = match handler.content_store.get(&file_data.content) {
        Some(b) => b,
        None => return Ok(()), // Blob not yet arrived; await next sync delivery.
    };
    let incoming_chunk_size = match blob_chunk_size(&incoming_blob) {
        Ok(size) => size as usize,
        Err(e) => {
            tracing::warn!(error = %e, "incoming blob missing chunk_size; falling back to default");
            DEFAULT_CHUNK_SIZE
        }
    };

    // §5.5 circuit breaker — if the on-disk content already matches the
    // incoming blob hash, the write is a no-op.
    //
    // Fast path: consult the L7 stat-cache first. A cached blob_hash
    // matching the incoming hash skips the rechunk entirely — replaces
    // the full file read + FastCDC scan with a single stat call. This
    // is the hot-path optimization the spec text calls out as
    // performance-critical for sync-driven deployments under edit
    // churn. The recently-written tracker is still in place as a
    // belt-and-suspenders short-circuit ahead of even the cache probe.
    if let Ok(md) = std::fs::symlink_metadata(fs_path) {
        match handler.stat_cache.probe(fs_path, &md) {
            crate::stat_cache::ProbeResult::Hit(cached) if cached == file_data.content => {
                // Cached blob matches incoming — no work to do, skip
                // the rechunk + reassemble path entirely.
                return Ok(());
            }
            crate::stat_cache::ProbeResult::Hit(_) => {
                // Cached blob differs from incoming — definitely a
                // write. Fall through to reassemble + write; the new
                // hash will be cached after the write.
            }
            crate::stat_cache::ProbeResult::Miss
            | crate::stat_cache::ProbeResult::RacyMiss => {
                // Fall back to the legacy rechunk circuit breaker —
                // MUST use the incoming blob's chunk_size, not local
                // default. Otherwise mixed-size peer exchanges
                // spuriously fire the circuit breaker.
                if let Ok(current_hash) =
                    current_disk_blob_hash(&handler.content_store, fs_path, incoming_chunk_size)
                {
                    if current_hash == file_data.content {
                        // Cache the result for next time so we hit fast.
                        handler.stat_cache.record(fs_path, &md, current_hash);
                        return Ok(());
                    }
                }
            }
        }
    }

    // L4 SHOULD: stream reassembly + write for blobs above the 64 MiB
    // threshold. Pulls one chunk at a time from the store and writes
    // through atomic_write_stream, keeping resident memory at one
    // chunk-payload instead of materializing the full blob. The
    // recently-written tracker still serializes the per-path
    // window-suppression.
    if let Some(parent) = fs_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?;
    }
    let total_size = file_data.size;
    if total_size >= STREAMING_THRESHOLD {
        let store = handler.content_store.clone();
        let blob_hash = file_data.content;
        crate::atomic::atomic_write_stream(fs_path, |w| {
            reassemble_stream(&store, &blob_hash, w)
                .map(|_| ())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        })
        .map_err(|e| format!("write (stream): {e}"))?;
    } else {
        let bytes = reassemble(&handler.content_store, &file_data.content)
            .map_err(|e| format!("reassemble: {e}"))?;
        crate::atomic::atomic_write(fs_path, &bytes).map_err(|e| format!("write: {e}"))?;
    }
    tracker.mark_written(bare_path);
    // Update the stat-cache with the post-write state: the next reverse
    // event for this path hits the cache fast-path. Stat after the
    // rename so dev/ino/mtime match what subsequent probes will see.
    if let Ok(md) = std::fs::symlink_metadata(fs_path) {
        handler.stat_cache.record(fs_path, &md, file_data.content);
    }
    Ok(())
}

/// Recompute the on-disk file's blob hash for the §5.5 circuit
/// breaker, using the **incoming blob's** `chunk_size`. v1.3 Amendment 3
/// pinned this as a normative MUST: chunking with the consumer's local
/// default breaks cross-peer dedup whenever producer and consumer run
/// different chunk-size defaults (e.g., during the v3.5 → v3.6 4 MiB →
/// 1 MiB cutover, or any deployment with a non-default chunk size on
/// either side).
fn current_disk_blob_hash(
    store: &Arc<dyn ContentStore>,
    fs_path: &std::path::Path,
    chunk_size: usize,
) -> Result<Hash, String> {
    let raw = std::fs::read(fs_path).map_err(|e| format!("read: {e}"))?;
    create_blob_fastcdc(store, &raw, chunk_size).map_err(|e| format!("blob: {e}"))
}

fn decode_file_data(entity: &entity_entity::Entity) -> Result<FileData, String> {
    use entity_ecf::ValueExt;
    let v: ciborium::Value = ciborium::from_reader(entity.data.as_slice())
        .map_err(|e| format!("cbor: {e}"))?;
    let path = v.get("path").and_then(|x| x.as_text().map(String::from)).unwrap_or_default();
    let size = v.get("size").and_then(|x| match x {
        ciborium::Value::Integer(i) => (*i).try_into().ok(),
        _ => None,
    }).unwrap_or(0u64);
    let modified_at = v.get("modified_at").and_then(|x| match x {
        ciborium::Value::Integer(i) => (*i).try_into().ok(),
        _ => None,
    });
    let content = match v.get("content") {
        Some(c) => crate::types::decode_hash_record(c)?,
        None => Hash::zero(),
    };
    let media_type = v.get("media_type").and_then(|x| x.as_text().map(String::from));
    let written = v.get("written").and_then(|x| x.as_bool()).unwrap_or(false);
    Ok(FileData {
        path,
        size,
        modified_at,
        content,
        media_type,
        written,
    })
}

#[derive(Default)]
struct ReverseTracker {
    written: Mutex<HashMap<String, Instant>>,
}

impl ReverseTracker {
    fn mark_written(&self, path: &str) {
        self.written
            .lock()
            .unwrap()
            .insert(path.to_string(), Instant::now());
    }

    fn is_recently_written(&self, path: &str) -> bool {
        let mut map = self.written.lock().unwrap();
        if let Some(when) = map.get(path) {
            if when.elapsed() <= RECENT_WRITE_WINDOW {
                return true;
            }
            map.remove(path);
        }
        false
    }
}

// keep PathBuf in use (silences lint when only fs::Path is otherwise used)
#[allow(dead_code)]
fn _path_buf_used(_p: PathBuf) {}
