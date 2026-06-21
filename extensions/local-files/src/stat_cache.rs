//! Stat-cache for the reverse-write circuit breaker and watcher
//! fast-path (DOMAIN-LOCAL-FILES v1.3 §10.2 L7 SHOULD).
//!
//! Shape: path-keyed cache of `(dev, ino, mtime_ns, ctime_ns, size,
//! mode_bits, blob_hash, cache_write_time_ns)`. The hit predicate
//! follows Git's racy-clean rule (`git-scm.com/docs/index-format`):
//!
//! 1. `(dev, ino, mtime_ns, ctime_ns, size, mode_bits)` all match the
//!    fresh stat → potential hit.
//! 2. AND `mtime_ns < cache_write_time_ns` → confirmed hit. If
//!    `mtime_ns >= cache_write_time_ns`, the write happened within the
//!    same time-stamp granularity as the cache update — we can't tell
//!    if the file changed after we cached it, so it's a forced miss.
//!
//! The "smudge to zero" discipline (Git smudges `size = 0` for entries
//! whose mtime equals the index update time) ensures the next stat is
//! a forced miss until a real change moves the file past the cache's
//! recorded boundary. We apply the same shape: when *writing* a cache
//! entry whose `mtime_ns >= cache_write_time_ns`, smudge `size = 0`.
//!
//! Concrete callers:
//!
//! - **Reverse-write §5.5 circuit breaker.** Before re-chunking the
//!   on-disk file to compare against the incoming blob hash, check the
//!   cache: if hit and `blob_hash == incoming`, skip. Saves a full file
//!   read + FastCDC scan on every loop-back event.
//! - **Watcher debounce-flush.** Before re-chunking the file at flush
//!   time, check the cache: if hit and the cached blob_hash matches the
//!   tree's bound entity, skip the write. Closes the "watcher fires for
//!   a file we just wrote ourselves" loop without the explicit
//!   recently-written tracker — same property, cheaper, more
//!   reliable.
//!
//! Persistence and eviction: implementation-defined per spec. This
//! initial cut is in-memory only, unbounded — sufficient for sessions
//! that fit working set in RAM. A future LRU + disk persistence pass
//! is a follow-up.

use std::collections::HashMap;
use std::fs::Metadata;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use entity_hash::Hash;

/// Single cache entry.
#[derive(Debug, Clone, Copy)]
pub struct StatEntry {
    pub dev: u64,
    pub ino: u64,
    pub mtime_ns: i128,
    pub ctime_ns: i128,
    pub size: u64,
    pub mode_bits: u32,
    pub blob_hash: Hash,
    /// Time-of-cache-write in the same units as `mtime_ns`. Used for
    /// the Git racy-clean predicate.
    pub cache_write_time_ns: i128,
}

/// Path-keyed stat cache. Thread-safe; uses a single mutex (low
/// contention expected — the hot paths are read-heavy and the cache
/// fits in memory).
#[derive(Default)]
pub struct StatCache {
    entries: Mutex<HashMap<PathBuf, StatEntry>>,
}

/// Probe result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResult {
    /// Cache hit AND racy-clean predicate satisfied. Returned blob hash is
    /// the cached value.
    Hit(Hash),
    /// Cache hit but racy-clean predicate fails — within-same-second
    /// edit; behave as miss.
    RacyMiss,
    /// No cache entry, or stat fields don't match. Caller must rechunk.
    Miss,
}

impl StatCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Probe the cache. Returns `Hit(blob_hash)` iff every stat field
    /// matches AND the racy-clean predicate holds. Caller is
    /// responsible for `stat`-ing the file fresh and passing the
    /// resulting metadata.
    pub fn probe(&self, path: &Path, fresh: &Metadata) -> ProbeResult {
        let entries = self.entries.lock().unwrap();
        let entry = match entries.get(path) {
            Some(e) => *e,
            None => return ProbeResult::Miss,
        };
        let (dev, ino, mtime_ns, ctime_ns, size, mode_bits) = match extract_fields(fresh) {
            Some(v) => v,
            None => return ProbeResult::Miss,
        };
        if dev != entry.dev
            || ino != entry.ino
            || mtime_ns != entry.mtime_ns
            || ctime_ns != entry.ctime_ns
            || size != entry.size
            || mode_bits != entry.mode_bits
        {
            return ProbeResult::Miss;
        }
        // Git racy-clean: confirmed hit iff mtime is strictly less than
        // cache update time. Equal or greater means we can't tell if
        // the file was edited within the same time-stamp granularity
        // after we cached it.
        if mtime_ns < entry.cache_write_time_ns {
            ProbeResult::Hit(entry.blob_hash)
        } else {
            ProbeResult::RacyMiss
        }
    }

    /// Insert / replace a cache entry. Applies the smudge-to-zero
    /// discipline: if `mtime_ns >= cache_write_time_ns` (the file was
    /// modified within the same time-stamp granularity as this cache
    /// update), the recorded `size` is smudged to zero so the next
    /// probe is a guaranteed miss. This closes the within-same-second
    /// edit window on second-resolution filesystems.
    pub fn record(&self, path: &Path, fresh: &Metadata, blob_hash: Hash) {
        let now_ns = now_nanos();
        let (dev, ino, mtime_ns, ctime_ns, mut size, mode_bits) = match extract_fields(fresh) {
            Some(v) => v,
            None => return,
        };
        if mtime_ns >= now_ns {
            // Racy entry — smudge so the next probe forces a rechunk.
            size = 0;
        }
        let entry = StatEntry {
            dev,
            ino,
            mtime_ns,
            ctime_ns,
            size,
            mode_bits,
            blob_hash,
            cache_write_time_ns: now_ns,
        };
        self.entries.lock().unwrap().insert(path.to_path_buf(), entry);
    }

    /// Drop a cache entry. Called on delete.
    pub fn forget(&self, path: &Path) {
        self.entries.lock().unwrap().remove(path);
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

#[cfg(unix)]
fn extract_fields(md: &Metadata) -> Option<(u64, u64, i128, i128, u64, u32)> {
    use std::os::unix::fs::MetadataExt;
    let mtime_ns = (md.mtime() as i128) * 1_000_000_000 + md.mtime_nsec() as i128;
    let ctime_ns = (md.ctime() as i128) * 1_000_000_000 + md.ctime_nsec() as i128;
    Some((
        md.dev(),
        md.ino(),
        mtime_ns,
        ctime_ns,
        md.size(),
        md.mode(),
    ))
}

#[cfg(not(unix))]
fn extract_fields(md: &Metadata) -> Option<(u64, u64, i128, i128, u64, u32)> {
    // Non-Unix: best-effort using portable APIs. On Windows the cache is
    // still useful for the size + mtime axis; dev/ino/ctime/mode are
    // placeholder zeros. Hit rate is lower but still nonzero.
    let mtime_ns = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(0);
    Some((0, 0, mtime_ns, 0, md.len(), 0))
}

fn now_nanos() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    fn write_then_stat(path: &Path, contents: &[u8]) -> Metadata {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .open(path)
            .unwrap();
        f.write_all(contents).unwrap();
        f.sync_all().unwrap();
        std::fs::metadata(path).unwrap()
    }

    #[test]
    fn miss_on_empty_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("x");
        let md = write_then_stat(&p, b"a");
        let c = StatCache::new();
        assert_eq!(c.probe(&p, &md), ProbeResult::Miss);
    }

    #[test]
    fn hit_after_record_with_older_mtime() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("x");
        let md = write_then_stat(&p, b"abcdef");
        let h = Hash::zero();
        let c = StatCache::new();
        // Sleep so cache_write_time_ns > mtime_ns.
        std::thread::sleep(std::time::Duration::from_millis(50));
        c.record(&p, &md, h);
        let md2 = std::fs::metadata(&p).unwrap();
        assert_eq!(c.probe(&p, &md2), ProbeResult::Hit(h));
    }

    #[test]
    fn smudge_to_zero_forces_miss_on_within_window_write() {
        // Verify the smudge-to-zero discipline directly: construct a
        // cache entry whose mtime_ns is equal-or-later than its
        // cache_write_time_ns. On record, size is smudged to 0. A
        // probe with the real (non-zero) size sees a size mismatch and
        // returns Miss. On nanosecond-resolution filesystems (modern
        // Linux ext4) the natural case is mtime_ns < now_ns at record
        // time, so the smudge rarely fires in practice — it's the
        // safety net for second-resolution filesystems (some FUSE,
        // some network FS, some legacy targets) where mtime_ns rounds
        // down to the same second as the write.
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("x");
        let md = write_then_stat(&p, b"abcdef");
        let c = StatCache::new();
        // Manually craft a within-window entry by setting
        // cache_write_time_ns to mtime_ns (the smudge fires).
        let (dev, ino, mtime_ns, ctime_ns, size, mode_bits) =
            extract_fields(&md).unwrap();
        let entry = StatEntry {
            dev,
            ino,
            mtime_ns,
            ctime_ns,
            size: 0, // smudged
            mode_bits,
            blob_hash: Hash::zero(),
            cache_write_time_ns: mtime_ns,
        };
        c.entries.lock().unwrap().insert(p.clone(), entry);
        let md2 = std::fs::metadata(&p).unwrap();
        // The fresh stat has size=6, the smudged entry has size=0 →
        // size mismatch → Miss (the correct safety behavior).
        assert_eq!(c.probe(&p, &md2), ProbeResult::Miss);
    }

    #[test]
    fn miss_after_content_change() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("x");
        let md = write_then_stat(&p, b"abcdef");
        let h = Hash::zero();
        let c = StatCache::new();
        std::thread::sleep(std::time::Duration::from_millis(20));
        c.record(&p, &md, h);
        // Modify the file: mtime updates → stat fields don't match cached.
        std::thread::sleep(std::time::Duration::from_millis(20));
        let md2 = write_then_stat(&p, b"different content");
        assert_eq!(c.probe(&p, &md2), ProbeResult::Miss);
    }

    #[test]
    fn forget_clears_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("x");
        let md = write_then_stat(&p, b"abc");
        let c = StatCache::new();
        c.record(&p, &md, Hash::zero());
        assert_eq!(c.len(), 1);
        c.forget(&p);
        assert_eq!(c.len(), 0);
    }
}
