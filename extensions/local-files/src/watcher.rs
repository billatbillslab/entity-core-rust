//! Filesystem watcher (DOMAIN-LOCAL-FILES §6).
//!
//! On startup the watcher performs an initial scan of the watched
//! filesystem root and produces a `fsCreated` event for every regular file
//! found — without this seed, only post-mount edits would reach the tree.
//! Future filesystem changes flow through `notify`-emitted events. All
//! events are coalesced through a debounce window (default 2000 ms) per
//! §6.3 before flushing to the tree.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use entity_content::create_blob_fastcdc;
use entity_store::{ContentStore, LocationIndex};
use notify::{
    event::{CreateKind, ModifyKind, RemoveKind},
    EventKind, RecommendedWatcher, RecursiveMode, Watcher as NotifyWatcher,
};
use thiserror::Error;
use tokio::sync::mpsc;

use crate::config::{file_skipped, matches_exclude, RootMapping};
use crate::types::FileData;

/// v3.6 §3.5 — 1 MiB default per A2 cutover (was 4 MiB in v3.5).
const DEFAULT_CHUNK_SIZE: usize = 1 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum WatcherError {
    #[error("notify error: {0}")]
    Notify(#[from] notify::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Coalesced filesystem event type (per §6.3 table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FsEvent {
    Created,
    Updated,
    Deleted,
}

/// A running watcher. Holds the notify handle and a shutdown signal.
pub struct Watcher {
    _notify: RecommendedWatcher,
    shutdown_tx: mpsc::Sender<()>,
}

impl Watcher {
    /// Start watching `root`. The async event loop runs as a tokio task;
    /// when this `Watcher` is dropped or `stop()` is called the loop exits.
    pub fn start(
        root: RootMapping,
        debounce_ms: u64,
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
        stat_cache: Arc<crate::stat_cache::StatCache>,
    ) -> Result<Self, WatcherError> {
        let (event_tx, mut event_rx) = mpsc::unbounded_channel::<notify::Result<notify::Event>>();
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

        let event_tx_for_cb = event_tx.clone();
        let mut notify_watcher = notify::recommended_watcher(move |res| {
            let _ = event_tx_for_cb.send(res);
        })?;

        // Walk the root and add each subdirectory as a watch target,
        // skipping excluded directories entirely so we never produce
        // events under a pruned subtree.
        walk_and_watch(&mut notify_watcher, &root.fs_root, &root.exclude)?;

        let pending: Arc<Mutex<HashMap<PathBuf, FsEvent>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let debounce = Duration::from_millis(debounce_ms.max(1));

        // Initial scan: seed `Created` events for every existing regular
        // file. Without this, pre-existing content stays invisible to the
        // tree until the file is touched externally.
        seed_initial_scan(&root, &pending);

        let root_for_task = root.clone();
        let pending_for_task = pending.clone();
        let cs_for_task = content_store.clone();
        let li_for_task = location_index.clone();
        let peer_for_task = local_peer_id.clone();
        let cache_for_task = stat_cache.clone();

        tokio::spawn(async move {
            let mut flush_timer: Option<tokio::time::Instant> = None;
            loop {
                let sleep_for = match flush_timer {
                    Some(deadline) => deadline.saturating_duration_since(tokio::time::Instant::now()),
                    None => Duration::from_secs(3600),
                };
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        flush_pending(
                            &root_for_task,
                            &pending_for_task,
                            &cs_for_task,
                            &li_for_task,
                            &peer_for_task,
                            &cache_for_task,
                        );
                        break;
                    }
                    maybe_event = event_rx.recv() => {
                        match maybe_event {
                            Some(Ok(evt)) => {
                                // v1.3 §10.2 L9 — overflow recovery.
                                // notify v6 surfaces inotify
                                // IN_Q_OVERFLOW (and the macOS / Windows
                                // equivalents) as an EventKind::Other
                                // with Flag::Rescan. When the kernel
                                // queue overflows, intervening events
                                // are LOST — there is no recovery via
                                // the event stream itself. We must do a
                                // full rescan of the watched root and
                                // seed Updated events; the stat-cache
                                // (L7, pending) will make the rescan
                                // cheap. Without recovery, on-disk
                                // edits during the overflow window stay
                                // invisible to the tree until something
                                // else touches the path — a sync-
                                // correctness regression.
                                if evt.need_rescan() {
                                    tracing::warn!(
                                        root = ?root_for_task.fs_root,
                                        "watcher overflow detected — rescanning root (v1.3 §10.2 L9)"
                                    );
                                    rescan_after_overflow(&root_for_task, &pending_for_task);
                                } else {
                                    handle_notify_event(evt, &root_for_task, &pending_for_task);
                                }
                                flush_timer = Some(tokio::time::Instant::now() + debounce);
                            }
                            Some(Err(err)) => {
                                tracing::warn!(error = %err, "local-files watcher error");
                            }
                            None => break,
                        }
                    }
                    _ = tokio::time::sleep(sleep_for), if flush_timer.is_some() => {
                        flush_pending(
                            &root_for_task,
                            &pending_for_task,
                            &cs_for_task,
                            &li_for_task,
                            &peer_for_task,
                            &cache_for_task,
                        );
                        flush_timer = None;
                    }
                }
            }
        });

        // Seed-induced state: if the initial scan produced pending entries,
        // schedule an immediate flush via a synthetic event-less timer
        // tick. We do this by sending nothing — instead the spawned loop
        // checks `pending` at startup. To avoid changing the loop shape,
        // arm a flush by sending a no-op event on the channel.
        // Simpler approach: flush synchronously here before returning.
        if !pending.lock().unwrap().is_empty() {
            flush_pending(
                &root,
                &pending,
                &content_store,
                &location_index,
                &local_peer_id,
                &stat_cache,
            );
        }

        Ok(Watcher {
            _notify: notify_watcher,
            shutdown_tx,
        })
    }

    pub fn stop(self) {
        // Best-effort: drop the sender, the loop wakes via channel close.
        let _ = self.shutdown_tx.try_send(());
    }
}

fn walk_and_watch(
    watcher: &mut RecommendedWatcher,
    fs_root: &Path,
    exclude: &[String],
) -> Result<(), notify::Error> {
    if !fs_root.exists() {
        // Watching a nonexistent root is a no-op; the handler may have
        // pre-registered the mapping before the directory exists.
        return Ok(());
    }
    watcher.watch(fs_root, RecursiveMode::NonRecursive)?;
    let mut stack = vec![fs_root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if matches_exclude(&name, exclude) {
                continue;
            }
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if file_type.is_dir() {
                if watcher.watch(&path, RecursiveMode::NonRecursive).is_ok() {
                    stack.push(path);
                }
            }
        }
    }
    Ok(())
}

/// v1.3 §10.2 L9 — overflow recovery rescan.
///
/// Walks the watched root and seeds `Updated` events (not `Created`,
/// since most files probably existed before the overflow). The
/// debounce-flush will re-ingest each file; with the L7 stat-cache the
/// common case (file unchanged) is a single stat per file with no
/// rechunk. Without the cache, every file is re-read and re-chunked —
/// expensive, but still better than silent desync.
fn rescan_after_overflow(
    root: &RootMapping,
    pending: &Arc<Mutex<HashMap<PathBuf, FsEvent>>>,
) {
    let mut stack = vec![root.fs_root.clone()];
    let mut seeded = 0usize;
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if matches_exclude(&name, &root.exclude) {
                continue;
            }
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                if file_skipped(&name, &root.exclude, &root.include) {
                    continue;
                }
                // Use Updated (not Created): existing pending Created
                // events for the same path coalesce per §6.3 (Created +
                // Updated = Created); new entries become Updated.
                let mut map = pending.lock().unwrap();
                let new_event = coalesce(map.get(&path).copied(), FsEvent::Updated);
                if let Some(ev) = new_event {
                    map.insert(path, ev);
                    seeded += 1;
                }
            }
        }
    }
    tracing::info!(seeded, "watcher rescan complete");
}

fn seed_initial_scan(root: &RootMapping, pending: &Arc<Mutex<HashMap<PathBuf, FsEvent>>>) {
    let mut stack = vec![root.fs_root.clone()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if matches_exclude(&name, &root.exclude) {
                continue;
            }
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                if file_skipped(&name, &root.exclude, &root.include) {
                    continue;
                }
                pending.lock().unwrap().insert(path, FsEvent::Created);
            }
        }
    }
}

fn handle_notify_event(
    evt: notify::Event,
    root: &RootMapping,
    pending: &Arc<Mutex<HashMap<PathBuf, FsEvent>>>,
) {
    let event_kind = classify(&evt.kind);
    for path in evt.paths {
        let name = match path.file_name().and_then(|s| s.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if matches_exclude(&name, &root.exclude) {
            continue;
        }

        let is_dir = path.is_dir();
        if is_dir {
            continue;
        }
        if !crate::config::matches_include(&name, &root.include) {
            continue;
        }

        let mut map = pending.lock().unwrap();
        let new_event = match event_kind {
            Some(ev) => coalesce(map.get(&path).copied(), ev),
            None => continue,
        };
        match new_event {
            Some(ev) => {
                map.insert(path, ev);
            }
            None => {
                map.remove(&path);
            }
        }
    }
}

fn classify(kind: &EventKind) -> Option<FsEvent> {
    match kind {
        EventKind::Create(CreateKind::File | CreateKind::Any) => Some(FsEvent::Created),
        EventKind::Modify(ModifyKind::Data(_) | ModifyKind::Any | ModifyKind::Metadata(_)) => {
            Some(FsEvent::Updated)
        }
        EventKind::Modify(ModifyKind::Name(_)) => Some(FsEvent::Deleted),
        EventKind::Remove(RemoveKind::File | RemoveKind::Any) => Some(FsEvent::Deleted),
        _ => None,
    }
}

/// §6.3 coalescing table. Returns `None` when the sequence collapses to
/// a no-op (e.g., created → deleted in the same window).
fn coalesce(prev: Option<FsEvent>, next: FsEvent) -> Option<FsEvent> {
    use FsEvent::*;
    Some(match (prev, next) {
        (None, ev) => ev,
        (Some(Created), Deleted) => return None,
        (Some(Created), Updated) => Created,
        (Some(Created), Created) => Created,
        (Some(Updated), Deleted) => Deleted,
        (Some(Updated), Updated) => Updated,
        (Some(Updated), Created) => Updated,
        (Some(Deleted), Created) => Updated,
        (Some(Deleted), Updated) => Updated,
        (Some(Deleted), Deleted) => Deleted,
    })
}

fn flush_pending(
    root: &RootMapping,
    pending: &Arc<Mutex<HashMap<PathBuf, FsEvent>>>,
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    local_peer_id: &str,
    stat_cache: &Arc<crate::stat_cache::StatCache>,
) {
    let drained: Vec<(PathBuf, FsEvent)> = {
        let mut map = pending.lock().unwrap();
        map.drain().collect()
    };
    if drained.is_empty() {
        return;
    }
    for (fs_path, event) in drained {
        let relative = match fs_path.strip_prefix(&root.fs_root) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => continue,
        };
        // Tree paths use `/`; normalize Windows-style backslashes if any.
        let relative = relative.replace('\\', "/");
        let bare_path = format!("{}{}", root.prefix, relative);
        let qualified = format!("/{}/{}", local_peer_id, bare_path);

        if event == FsEvent::Deleted {
            location_index.remove(&qualified);
            stat_cache.forget(&fs_path);
            continue;
        }

        // v1.3 §8.3 callsite MUST: watcher flush also routes through the
        // resolver. notify gives us in-root paths by construction, but a
        // symlink-at-leaf placed inside the root produces real events
        // for changes to the link's target — we must not silently ingest
        // through that link.
        let resolved = match crate::config::resolve_fs_path_relative(root, &relative) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(path = %fs_path.display(), error = %e, "watcher flush rejected by path defense");
                continue;
            }
        };

        let metadata = match std::fs::symlink_metadata(&resolved) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if metadata.is_dir() {
            continue;
        }
        // Use the resolved path (post-defense) for the rest of the flush.
        let fs_path = resolved;

        // L7 stat-cache fast path: if the cache says the bytes on disk
        // haven't changed since we last ingested this file, skip the
        // rechunk entirely. This is the load-bearing optimization for
        // sync-driven loops — reverse-write writes the file, the
        // watcher fires for our own write, the cache hits, we skip the
        // re-ingest. Note: the in-memory tree binding may not yet
        // reflect the cached hash if the bind hasn't landed — but
        // since the cached entry came from a successful prior
        // ingest/write, the binding will be (or already is) correct.
        if let crate::stat_cache::ProbeResult::Hit(_) =
            stat_cache.probe(&fs_path, &metadata)
        {
            continue;
        }
        let raw = match std::fs::read(&fs_path) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(path = %fs_path.display(), error = %e, "watcher read failed");
                continue;
            }
        };
        let blob_hash = match create_blob_fastcdc(content_store, &raw, DEFAULT_CHUNK_SIZE) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(error = %e, "watcher build blob failed");
                continue;
            }
        };
        let modified_at = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as u64);
        let media_type = mime_guess::from_path(&fs_path)
            .first()
            .map(|m| m.essence_str().to_string());
        let file_data = FileData {
            path: relative.clone(),
            size: metadata.len(),
            modified_at,
            content: blob_hash,
            media_type,
            written: false,
        };
        let file_entity = match file_data.to_entity() {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, "watcher build file entity failed");
                continue;
            }
        };
        let hash = match content_store.put(file_entity) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(error = %e, "watcher put file entity failed");
                continue;
            }
        };
        location_index.set(&qualified, hash);
        // Record the post-ingest state into the stat-cache so the next
        // watcher event for this path hits the fast path (and the
        // reverse-write path that follows from the tree-change emit
        // also hits the fast path via the shared cache).
        stat_cache.record(&fs_path, &metadata, blob_hash);
    }
}
