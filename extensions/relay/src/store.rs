//! In-memory Mode-S store (§6.1) — the v1 floor backing for `:put` / `:poll`.
//!
//! Mode S is **inbox-shaped but self-contained** (§6.1): it does NOT delegate
//! to the INBOX op. The store is keyed by `(namespace, entry_hash)` and keeps a
//! **relay-owned, monotonically-increasing cursor** per namespace so `:poll`
//! can page in stable insertion order. The cursor is the relay's own concern
//! (NOT INBOX's, §3.2/§6.1); cross-impl tests compare the *entries observed on
//! advance*, never the cursor bytes (handoff Open/TBD #3).
//!
//! Persistence is out of v1 floor scope — in-memory only; restart is not
//! required to preserve entries (handoff Open/TBD #2). A deployment MAY back a
//! namespace with durable storage, out of RELAY v1 scope (§6.1).

use std::collections::HashMap;
use std::sync::Mutex;

use entity_hash::Hash;

/// One stored Mode-S entry: a pointer to the `store-entry` entity plus the
/// relay-owned sequence number that orders it within its namespace.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredEntry {
    /// Hash of the stored `system/relay/store-entry` entity (§4.2 `entry_hash`).
    pub entry_hash: Hash,
    /// Relay-owned monotonic sequence within the namespace (the cursor basis).
    pub seq: u64,
    /// ms-since-epoch expiry; `None` = no expiry. Expired entries are skipped
    /// on poll (and eligible for GC, §8).
    pub expires_at: Option<i64>,
}

#[derive(Default)]
struct NamespaceLog {
    next_seq: u64,
    entries: Vec<StoredEntry>,
}

/// The result of a `:poll` page (§4.2 `poll-result` payload, pre-encode).
#[derive(Debug, Clone, PartialEq)]
pub struct PollPage {
    pub entries: Vec<Hash>,
    /// Opaque relay-owned cursor — the seq to resume strictly after. Encoded on
    /// the wire as 8-byte big-endian (matching Go for free byte-equality; R8
    /// does not byte-compare cursors regardless).
    pub cursor: u64,
    pub has_more: bool,
}

/// Thread-safe in-memory Mode-S store.
#[derive(Default)]
pub struct ModeStore {
    inner: Mutex<HashMap<String, NamespaceLog>>,
}

impl ModeStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an entry to a namespace; returns its assigned relay-owned seq.
    /// Idempotent placement is NOT assumed — re-putting the same `entry_hash`
    /// appends a new seq (content-addressed dedup happens in the content store;
    /// the poll log records each placement).
    pub fn put(&self, namespace: &str, entry_hash: Hash, expires_at: Option<i64>) -> u64 {
        let mut guard = self.inner.lock().expect("relay store mutex");
        let log = guard.entry(namespace.to_string()).or_default();
        let seq = log.next_seq;
        log.next_seq += 1;
        log.entries.push(StoredEntry {
            entry_hash,
            seq,
            expires_at,
        });
        seq
    }

    /// Page the namespace from `since` (exclusive; `None` = from start),
    /// skipping entries expired at `now_ms`, up to `limit` (`None` = the backend
    /// default). An unknown/empty namespace returns an empty page (§4.2 — empty
    /// is NOT `namespace_not_found`; this in-memory floor never requires
    /// provisioning).
    pub fn poll(
        &self,
        namespace: &str,
        since: Option<u64>,
        limit: Option<usize>,
        now_ms: i64,
    ) -> PollPage {
        let guard = self.inner.lock().expect("relay store mutex");
        let after = since.unwrap_or(0).saturating_add(if since.is_some() { 1 } else { 0 });
        // `since` is the last-seen seq → start strictly after it. `None` → seq 0.
        let start = if since.is_some() { after } else { 0 };

        let Some(log) = guard.get(namespace) else {
            // Empty steady state — the freshly-created-inbox case (§4.2).
            return PollPage {
                entries: Vec::new(),
                cursor: since.unwrap_or(0),
                has_more: false,
            };
        };

        let limit = limit.unwrap_or(DEFAULT_POLL_LIMIT).max(1);

        // Live (non-expired) entries with seq >= start, in insertion order.
        let live: Vec<&StoredEntry> = log
            .entries
            .iter()
            .filter(|e| e.seq >= start && !is_expired(e.expires_at, now_ms))
            .collect();

        let has_more = live.len() > limit;
        let page: Vec<&StoredEntry> = live.into_iter().take(limit).collect();

        let cursor = page
            .last()
            .map(|e| e.seq)
            // No entries returned → echo the incoming cursor so the caller can
            // re-poll from the same point (stable cursor, handoff Open/TBD #3).
            .unwrap_or_else(|| since.unwrap_or(0));

        PollPage {
            entries: page.iter().map(|e| e.entry_hash).collect(),
            cursor,
            has_more,
        }
    }
}

/// Backend default page size when `:poll` omits `limit` (§4.2). Conservative;
/// deployments tune per workload.
pub const DEFAULT_POLL_LIMIT: usize = 256;

fn is_expired(expires_at: Option<i64>, now_ms: i64) -> bool {
    matches!(expires_at, Some(e) if e <= now_ms)
}
