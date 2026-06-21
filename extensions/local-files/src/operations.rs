//! Op handlers — read, write, list, delete, watch
//! (DOMAIN-LOCAL-FILES v1.2 §4).

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::UNIX_EPOCH;

use entity_content::{
    blob_chunk_hashes, create_blob_fastcdc, create_blob_fastcdc_stream, reassemble,
    reassemble_stream,
};
use entity_entity::Entity;
use entity_handler::{HandlerContext, HandlerResult};
use entity_hash::Hash;
use entity_types::CONTENT_MIN_CHUNK_SIZE;

use crate::config::{matches_exclude, matches_include, resolve_fs_path};
use crate::handler::{
    bad_request, forbidden, not_found, resource_bare_path, LocalFilesHandler,
};
use crate::types::{
    DeletedData, DirectoryData, DirectoryEntryData, FileData, WatchRequestData, WatcherConfigData,
    WriteRequestData,
};

/// v3.6 §3.5 — 1 MiB default per A2 cutover (was 4 MiB in v3.5).
const DEFAULT_CHUNK_SIZE: usize = 1 * 1024 * 1024;
/// L4 streaming-vs-buffered cutoff per DOMAIN-LOCAL-FILES v1.3 §4.3 /
/// §5.3 (RECOMMENDED 64 MiB). Files above this size use the streaming
/// chunker / reassembler to keep memory bounded; below, the buffered
/// path stays for lower latency on small files.
const STREAMING_THRESHOLD: u64 = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// read (§4.1)
// ---------------------------------------------------------------------------

pub(crate) async fn handle_read(h: &LocalFilesHandler, ctx: &HandlerContext) -> HandlerResult {
    let tree_path = match resource_bare_path(ctx) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let root = match h.find_root_mapping(&tree_path) {
        Some(r) => r,
        None => return not_found("no_root_mapping", &format!("no root mapping for {tree_path}")),
    };
    let (fs_path, relative) = match resolve_fs_path(&root, &tree_path) {
        Ok(v) => v,
        Err(e) => return forbidden("path_traversal_rejected", &e),
    };

    // v1.3 C-2 — blocking fs + CPU chunker offloaded to tokio's
    // blocking pool so the async worker isn't pinned for the read +
    // FastCDC pass. For a 1 GB file this is the difference between
    // "this worker is unavailable for ~1 second" and "this worker
    // stays available; the heavy work runs on a blocking thread."
    let cs = h.content_store.clone();
    let fs_path_for_blocking = fs_path.clone();
    let blob_and_metadata = tokio::task::spawn_blocking(move || -> Result<(entity_hash::Hash, std::fs::Metadata, u64), (u32, String, String)> {
        let metadata = match std::fs::symlink_metadata(&fs_path_for_blocking) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err((404, "file_not_found".into(), format!("file not found: {}", fs_path_for_blocking.display())))
            }
            Err(e) => return Err((400, "io_error".into(), format!("stat: {e}"))),
        };
        if metadata.is_dir() {
            return Err((400, "use_list_for_directories".into(), "use list operation for directories".into()));
        }
        let size = metadata.len();
        // L4 SHOULD: stream chunks for large files to keep memory bounded.
        // Cross-impl gate (CONTENT v3.5 §3.6.5): the streaming and
        // buffered chunkers produce byte-identical chunks (verified by
        // `fastcdc_stream_produces_byte_identical_chunks_to_buffered`).
        let blob_hash = if size >= STREAMING_THRESHOLD {
            let file = std::fs::File::open(&fs_path_for_blocking)
                .map_err(|e| (400, "io_error".to_string(), format!("open: {e}")))?;
            let reader = std::io::BufReader::with_capacity(1 << 20, file);
            create_blob_fastcdc_stream(&cs, reader, DEFAULT_CHUNK_SIZE)
                .map_err(|e| (400, "internal_error".to_string(), format!("build blob (stream): {e}")))?
        } else {
            let raw = std::fs::read(&fs_path_for_blocking)
                .map_err(|e| (400, "io_error".to_string(), format!("read: {e}")))?;
            create_blob_fastcdc(&cs, &raw, DEFAULT_CHUNK_SIZE)
                .map_err(|e| (400, "internal_error".to_string(), format!("build blob: {e}")))?
        };
        Ok((blob_hash, metadata, size))
    })
    .await
    .map_err(|e| (500, "join_error".to_string(), format!("blocking task: {e}")));

    let (blob_hash, metadata, raw_len) = match blob_and_metadata {
        Ok(Ok(v)) => v,
        Ok(Err((404, code, msg))) => return not_found(&code, &msg),
        Ok(Err((403, code, msg))) => return forbidden(&code, &msg),
        Ok(Err((_status, code, msg))) => return bad_request(&code, &msg),
        Err((_status, code, msg)) => return bad_request(&code, &msg),
    };

    let modified_at = file_mtime_ms(&metadata);
    let media_type = guess_media_type(&relative);
    let file_data = FileData {
        path: relative,
        size: raw_len,
        modified_at,
        content: blob_hash,
        media_type,
        written: false,
    };
    let file_entity = match file_data.to_entity() {
        Ok(e) => e,
        Err(e) => return bad_request("internal_error", &format!("create file entity: {e}")),
    };
    if let Err(e) = persist_file_entity(h, &tree_path, &file_entity) {
        return bad_request("storage_error", &e);
    }
    // Descriptor publication — gated per-root (§2.5) and only when the
    // media-type is known (§4.1). Publishes a `system/content/descriptor`
    // at the canonical dual-level path per CONTENT v3.5 §5.3. Auxiliary to
    // the read result, so a storage hiccup here is logged, not fatal to the
    // read (the file entity + included blob are already persisted).
    if root.publish_descriptors {
        if let Some(media_type) = file_data.media_type.as_deref() {
            if let Err(e) = publish_descriptor(h, blob_hash, media_type) {
                tracing::warn!("descriptor publish failed for {tree_path}: {e}");
            }
        }
    }
    // Cache the post-read state — subsequent reverse-write / watcher
    // events for this path hit the L7 fast-path.
    h.stat_cache.record(&fs_path, &metadata, blob_hash);

    let included = match build_included(h, blob_hash, raw_len) {
        Ok(map) => map,
        Err(e) => return bad_request("internal_error", &e),
    };

    HandlerResult::ok_with_included(file_entity, included)
}

// ---------------------------------------------------------------------------
// write (§4.3)
// ---------------------------------------------------------------------------

pub(crate) async fn handle_write(h: &LocalFilesHandler, ctx: &HandlerContext) -> HandlerResult {
    let tree_path = match resource_bare_path(ctx) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let root = match h.find_root_mapping(&tree_path) {
        Some(r) => r,
        None => return not_found("no_root_mapping", &format!("no root mapping for {tree_path}")),
    };
    if root.read_only {
        return forbidden("read_only_root", "root mapping is read-only");
    }
    let (fs_path, relative) = match resolve_fs_path(&root, &tree_path) {
        Ok(v) => v,
        Err(e) => return forbidden("path_traversal_rejected", &e),
    };

    let params = match WriteRequestData::from_params(&ctx.params) {
        Ok(p) => p,
        Err(e) => return bad_request("invalid_params", &format!("decode: {e}")),
    };
    // §3.2 presence rule: "exactly one of bytes / content MUST be present".
    // Present, not non-empty — an empty `bytes` is the canonical empty-file
    // write. Filed back to architecture as a spec pseudocode bug: §4.3 line
    // 407's `len(params.bytes) > 0` rejects valid empty-file writes.
    let has_bytes = params.bytes.is_some();
    let has_content = params.content.is_some();
    match (has_bytes, has_content) {
        (true, true) => return bad_request("invalid_params", "ambiguous_input: exactly one of bytes / content must be set"),
        (false, false) => return bad_request("invalid_params", "missing_input: exactly one of bytes / content must be set"),
        _ => {}
    }

    // v1.3 C-2 — chunking + reassembly + disk write run in spawn_blocking.
    // The bytes-mode and content-mode branches have different CPU
    // profiles (bytes: chunk new content; content: pull chunks from
    // store + concat), but both end with a synchronous disk write that
    // must not block the async runtime.
    let cs = h.content_store.clone();
    let fs_path_for_blocking = fs_path.clone();
    let create_dirs = params.create_dirs;
    let bytes = params.bytes.clone();
    let content_hash = params.content;

    let result = tokio::task::spawn_blocking(move || -> Result<(entity_hash::Hash, u64), (u32, String, String)> {
        if let Some(raw) = bytes {
            // Bytes-mode: caller already materialized the payload in
            // memory (bounded by transport frame max per spec L1, ~16
            // MiB default). No streaming benefit on chunker side; the
            // disk write goes through atomic_write either way.
            let bh = create_blob_fastcdc(&cs, &raw, DEFAULT_CHUNK_SIZE)
                .map_err(|e| (400, "internal_error".to_string(), format!("build blob: {e}")))?;
            write_bytes_to_disk(&fs_path_for_blocking, &raw, create_dirs)
                .map_err(|e| (400, "io_error".to_string(), e))?;
            let len = raw.len() as u64;
            Ok((bh, len))
        } else {
            let bh = content_hash.unwrap();
            if cs.get(&bh).is_none() {
                return Err((404, "content_not_found".into(), "blob not found in content store".into()));
            }
            // Decode total_size from the blob manifest WITHOUT
            // materializing chunks — pays one blob-decode upfront to
            // route between streaming and buffered reassembly.
            let (total_size, _chunk_hashes) =
                entity_content::blob_chunk_hashes(&cs, &bh)
                    .map_err(|e| (400, "internal_error".to_string(), format!("decode blob: {e}")))?;
            // L4: stream reassembly + write for blobs above the
            // threshold. The streaming reassembler pulls one chunk at
            // a time and writes through, never materializing the full
            // payload. Combined with atomic_write_stream (below), the
            // dedup-mode write path stays bounded at one-chunk-resident
            // for arbitrarily large files.
            if total_size >= STREAMING_THRESHOLD {
                if create_dirs {
                    if let Some(parent) = fs_path_for_blocking.parent() {
                        std::fs::create_dir_all(parent)
                            .map_err(|e| (400, "io_error".to_string(), format!("mkdir: {e}")))?;
                    }
                }
                crate::atomic::atomic_write_stream(&fs_path_for_blocking, |w| {
                    reassemble_stream(&cs, &bh, w)
                        .map(|_| ())
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
                })
                .map_err(|e| (400, "io_error".to_string(), format!("write (stream): {e}")))?;
            } else {
                let raw = reassemble(&cs, &bh)
                    .map_err(|e| (400, "internal_error".to_string(), format!("reassemble: {e}")))?;
                write_bytes_to_disk(&fs_path_for_blocking, &raw, create_dirs)
                    .map_err(|e| (400, "io_error".to_string(), e))?;
            }
            Ok((bh, total_size))
        }
    })
    .await;
    let (blob_hash, raw_bytes_len) = match result {
        Ok(Ok(v)) => v,
        Ok(Err((404, code, msg))) => return not_found(&code, &msg),
        Ok(Err((_status, code, msg))) => return bad_request(&code, &msg),
        Err(e) => return bad_request("join_error", &format!("blocking task: {e}")),
    };

    // Re-stat for the post-write metadata; this stat call is small and
    // tolerable on the async worker.
    let post_metadata = fs::symlink_metadata(&fs_path).ok();
    let (size, modified_at) = match &post_metadata {
        Some(m) => (m.len(), file_mtime_ms(m)),
        None => (raw_bytes_len, None),
    };
    let media_type = params.media_type.clone().or_else(|| guess_media_type(&relative));
    let file_data = FileData {
        path: relative,
        size,
        modified_at,
        content: blob_hash,
        media_type,
        written: true,
    };
    let file_entity = match file_data.to_entity() {
        Ok(e) => e,
        Err(e) => return bad_request("internal_error", &format!("create file entity: {e}")),
    };
    if let Err(e) = persist_file_entity(h, &tree_path, &file_entity) {
        return bad_request("storage_error", &e);
    }
    // L7 cache update: record the post-write state so the watcher
    // event we're about to fire for our own write hits the cache
    // fast-path instead of triggering a redundant rechunk.
    if let Some(md) = &post_metadata {
        h.stat_cache.record(&fs_path, md, blob_hash);
    }

    let included = match build_included(h, blob_hash, size) {
        Ok(map) => map,
        Err(e) => return bad_request("internal_error", &e),
    };

    HandlerResult::ok_with_included(file_entity, included)
}

// ---------------------------------------------------------------------------
// list (§4.2)
// ---------------------------------------------------------------------------

pub(crate) async fn handle_list(h: &LocalFilesHandler, ctx: &HandlerContext) -> HandlerResult {
    let mut tree_path = match resource_bare_path(ctx) {
        Ok(p) => p,
        Err(r) => return r,
    };
    // Normalize: ensure trailing slash so resolve gives an empty relative for
    // root listings ("local/files/shared/" → "").
    if !tree_path.ends_with('/') {
        tree_path.push('/');
    }
    let root = match h.find_root_mapping(&tree_path) {
        Some(r) => r,
        None => return not_found("no_root_mapping", &format!("no root mapping for {tree_path}")),
    };
    let (fs_path, relative) = match resolve_fs_path(&root, &tree_path) {
        Ok(v) => v,
        Err(e) => return forbidden("path_traversal_rejected", &e),
    };
    // v1.3 C-2 — read_dir + per-entry stat run in spawn_blocking.
    // Directory enumeration on a huge dir + per-entry metadata calls
    // add up; offloading keeps the async worker free.
    let fs_path_for_blocking = fs_path.clone();
    let tree_path_for_blocking = tree_path.clone();
    let exclude = root.exclude.clone();
    let include = root.include.clone();
    let listing = tokio::task::spawn_blocking(move || -> Result<Vec<DirectoryEntryData>, (u32, String, String)> {
        let read_dir = std::fs::read_dir(&fs_path_for_blocking).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                (404, "directory_not_found".to_string(), format!("directory not found: {}", fs_path_for_blocking.display()))
            } else {
                (400, "io_error".to_string(), format!("readdir: {e}"))
            }
        })?;
        let mut children: Vec<DirectoryEntryData> = Vec::new();
        for entry in read_dir.flatten() {
            let name = match entry.file_name().into_string() {
                Ok(n) => n,
                Err(_) => continue,
            };
            if matches_exclude(&name, &exclude) {
                continue;
            }
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            let is_dir = file_type.is_dir();
            if !is_dir && !matches_include(&name, &include) {
                continue;
            }
            let metadata = entry.metadata().ok();
            let size = metadata.as_ref().filter(|_| !is_dir).map(|m| m.len());
            let modified_at = metadata.as_ref().and_then(file_mtime_ms);
            let entry_type = if is_dir {
                "directory"
            } else if file_type.is_symlink() {
                "symlink"
            } else {
                "file"
            };
            children.push(DirectoryEntryData {
                name: name.clone(),
                entity_path: format!("{tree_path_for_blocking}{name}"),
                entry_type: entry_type.to_string(),
                size,
                modified_at,
            });
        }
        Ok(children)
    })
    .await;
    let children = match listing {
        Ok(Ok(c)) => c,
        Ok(Err((404, code, msg))) => return not_found(&code, &msg),
        Ok(Err((_status, code, msg))) => return bad_request(&code, &msg),
        Err(e) => return bad_request("join_error", &format!("blocking task: {e}")),
    };

    let dir_data = DirectoryData {
        path: relative,
        children,
        modified_at: None,
    };
    let dir_entity = match dir_data.to_entity() {
        Ok(e) => e,
        Err(e) => return bad_request("internal_error", &format!("create directory entity: {e}")),
    };
    HandlerResult::ok(dir_entity)
}

// ---------------------------------------------------------------------------
// delete (§4.4)
// ---------------------------------------------------------------------------

pub(crate) fn handle_delete(h: &LocalFilesHandler, ctx: &HandlerContext) -> HandlerResult {
    let tree_path = match resource_bare_path(ctx) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let root = match h.find_root_mapping(&tree_path) {
        Some(r) => r,
        None => return not_found("no_root_mapping", &format!("no root mapping for {tree_path}")),
    };
    if root.read_only {
        return forbidden("read_only_root", "root mapping is read-only");
    }
    let (fs_path, relative) = match resolve_fs_path(&root, &tree_path) {
        Ok(v) => v,
        Err(e) => return forbidden("path_traversal_rejected", &e),
    };

    // Single call: collapse exists()→remove_file TOCTOU. Map NotFound to
    // existed=false; any other error surfaces as io_error.
    let existed = match fs::remove_file(&fs_path) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return bad_request("io_error", &format!("delete: {e}")),
    };
    let qualified = h.qualified(&tree_path);
    h.location_index.remove(&qualified);

    let deleted = DeletedData {
        path: relative,
        existed,
    };
    let entity = match deleted.to_entity() {
        Ok(e) => e,
        Err(e) => return bad_request("internal_error", &format!("create deleted entity: {e}")),
    };
    HandlerResult::ok(entity)
}

// ---------------------------------------------------------------------------
// watch (§4.5)
// ---------------------------------------------------------------------------

pub(crate) fn handle_watch(h: &LocalFilesHandler, ctx: &HandlerContext) -> HandlerResult {
    let params = match WatchRequestData::from_params(&ctx.params) {
        Ok(p) => p,
        Err(e) => return bad_request("invalid_params", &format!("decode: {e}")),
    };
    let root_name = params.root_name.clone();
    let action = params.action.as_deref().unwrap_or("start");

    {
        let roots = h.roots.read().unwrap();
        if !roots.contains_key(&root_name) {
            return not_found(
                "root_mapping_not_found",
                &format!("no root mapping named: {root_name}"),
            );
        }
    }

    let watcher_path = format!(
        "/{}/{}{}/{}",
        h.local_peer_id,
        crate::handler::CONFIG_PATH_PREFIX,
        "watch",
        root_name
    );

    if action == "stop" {
        let removed = h.watchers.write().unwrap().remove(&root_name);
        match removed {
            Some(w) => w.stop(),
            None => {
                return not_found(
                    "watcher_not_found",
                    &format!("no active watcher for: {root_name}"),
                )
            }
        }
        let wc = WatcherConfigData {
            root_name: root_name.clone(),
            status: "stopped".into(),
            debounce_ms: None,
            error_message: None,
        };
        let entity = match wc.to_entity() {
            Ok(e) => e,
            Err(e) => return bad_request("internal_error", &format!("create watcher config: {e}")),
        };
        if let Err(e) = persist_at(h, &watcher_path, &entity) {
            return bad_request("storage_error", &e);
        }
        return HandlerResult::ok(entity);
    }

    let debounce_ms = params.debounce_ms.unwrap_or(2000);
    let root = match h.roots.read().unwrap().get(&root_name).cloned() {
        Some(r) => r,
        None => {
            return not_found(
                "root_mapping_not_found",
                &format!("no root mapping named: {root_name}"),
            )
        }
    };
    let watcher_result = crate::watcher::Watcher::start(
        root,
        debounce_ms,
        h.content_store.clone(),
        h.location_index.clone(),
        h.local_peer_id.clone(),
        h.stat_cache.clone(),
    );
    let watcher = match watcher_result {
        Ok(w) => w,
        Err(e) => {
            let err_msg = format!("{e}");
            let wc = WatcherConfigData {
                root_name: root_name.clone(),
                status: "error".into(),
                debounce_ms: None,
                error_message: Some(err_msg.clone()),
            };
            if let Ok(entity) = wc.to_entity() {
                let _ = persist_at(h, &watcher_path, &entity);
            }
            return bad_request("watcher_error", &format!("start watcher: {err_msg}"));
        }
    };
    {
        let mut ws = h.watchers.write().unwrap();
        if let Some(old) = ws.remove(&root_name) {
            old.stop();
        }
        ws.insert(root_name.clone(), watcher);
    }

    let wc = WatcherConfigData {
        root_name: root_name.clone(),
        status: "active".into(),
        debounce_ms: Some(debounce_ms),
        error_message: None,
    };
    let entity = match wc.to_entity() {
        Ok(e) => e,
        Err(e) => return bad_request("internal_error", &format!("create watcher config: {e}")),
    };
    if let Err(e) = persist_at(h, &watcher_path, &entity) {
        return bad_request("storage_error", &e);
    }
    HandlerResult::ok(entity)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn persist_file_entity(
    h: &LocalFilesHandler,
    bare_tree_path: &str,
    entity: &Entity,
) -> Result<(), String> {
    let hash = h
        .content_store
        .put(entity.clone())
        .map_err(|e| format!("store file entity: {e}"))?;
    let qualified = h.qualified(bare_tree_path);
    h.location_index.set(&qualified, hash);
    Ok(())
}

/// Publish a `system/content/descriptor` over `blob_hash` per CONTENT
/// v3.5 §2.4 / §5.3 (DOMAIN-LOCAL-FILES §4.1 `publish_descriptor`). The
/// descriptor body carries `content = blob_hash`; it is bound at the
/// canonical dual-level path
/// `/{local_peer}/system/content/descriptor/{B_hex}/{D_hex}` where `B_hex`
/// is the blob hash and `D_hex` the descriptor's own content hash. The
/// path embeds the blob hash that the body also carries — CONTENT §5.3's
/// MUST integrity check gates the consumer side against path corruption.
fn publish_descriptor(
    h: &LocalFilesHandler,
    blob_hash: Hash,
    media_type: &str,
) -> Result<(), String> {
    use ciborium::Value;
    use entity_ecf::{text, to_ecf};

    let data = to_ecf(&Value::Map(vec![
        (text("content"), crate::types::hash_to_record(&blob_hash)),
        (text("media_type"), text(media_type)),
    ]));
    let descriptor = Entity::new(entity_types::TYPE_CONTENT_DESCRIPTOR, data)
        .map_err(|e| format!("create descriptor entity: {e}"))?;
    let d_hash = h
        .content_store
        .put(descriptor)
        .map_err(|e| format!("store descriptor entity: {e}"))?;
    let path = format!(
        "/{}/system/content/descriptor/{}/{}",
        h.local_peer_id,
        blob_hash.to_hex(),
        d_hash.to_hex()
    );
    h.location_index.set(&path, d_hash);
    Ok(())
}

fn persist_at(h: &LocalFilesHandler, qualified_path: &str, entity: &Entity) -> Result<(), String> {
    let hash = h
        .content_store
        .put(entity.clone())
        .map_err(|e| format!("store entity: {e}"))?;
    h.location_index.set(qualified_path, hash);
    Ok(())
}

fn write_bytes_to_disk(fs_path: &Path, data: &[u8], create_dirs: bool) -> Result<(), String> {
    if create_dirs {
        if let Some(parent) = fs_path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?;
        }
    }
    crate::atomic::atomic_write(fs_path, data).map_err(|e| format!("write: {e}"))
}

fn file_mtime_ms(metadata: &fs::Metadata) -> Option<u64> {
    metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
}

fn guess_media_type(relative_path: &str) -> Option<String> {
    let path = Path::new(relative_path);
    mime_guess::from_path(path)
        .first()
        .map(|m| m.essence_str().to_string())
}

/// Build the `included` map for a read/write response per §4.3:
/// always include the blob; include chunks too when `total_size ≤
/// MIN_CHUNK_SIZE` (64 KiB).
fn build_included(
    h: &LocalFilesHandler,
    blob_hash: Hash,
    total_size: u64,
) -> Result<HashMap<Hash, Entity>, String> {
    let mut included: HashMap<Hash, Entity> = HashMap::new();
    let blob = h
        .content_store
        .get(&blob_hash)
        .ok_or_else(|| "blob missing from store after put".to_string())?;
    included.insert(blob_hash, blob);
    if total_size <= CONTENT_MIN_CHUNK_SIZE {
        let (_size, chunk_hashes) = blob_chunk_hashes(&h.content_store, &blob_hash)
            .map_err(|e| format!("decode blob chunks: {e}"))?;
        for ch in chunk_hashes {
            if let Some(ent) = h.content_store.get(&ch) {
                included.insert(ch, ent);
            }
        }
    }
    Ok(included)
}

