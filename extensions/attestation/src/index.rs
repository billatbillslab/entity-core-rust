//! In-memory indexes for `system/attestation` entities
//! (EXTENSION-ATTESTATION v1.0 §5.7, §9.1).
//!
//! The MUST-indexed fields per §9.1: `attesting`, `attested`,
//! `properties.kind`, `supersedes`. The index satisfies invariants I1–I5.
//!
//! The index stores decoded `AttestationData` keyed by attestation
//! content_hash. Lookups by indexed field return content_hashes; callers
//! pull entities back via `get(hash)`.
//!
//! **Population.** Two entry points:
//! - `AttestationHandler` calls `insert` after a local `:create`/`:supersede`/
//!   `:revoke` op writes the entity (Phase 2).
//! - A SyncTreeHook adapter (Phase 6) calls `insert` for cross-peer arrivals.
//!
//! No persistence — the index is rebuilt at peer start by scanning
//! `system/attestation` entities under all `LocationIndex` paths (Phase 6
//! wiring; not implemented in Phase 2).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, RwLock};

use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};
use entity_types::TYPE_ATTESTATION;

use crate::data::AttestationData;

/// In-memory attestation index. Thread-safe; cheap to clone (Arc the index).
pub struct AttestationIndex {
    inner: RwLock<IndexInner>,
}

struct IndexInner {
    /// Decoded attestations keyed by content_hash.
    by_hash: HashMap<Hash, AttestationData>,
    /// `attesting → set of attestation hashes` (§9.1 MUST).
    by_attesting: BTreeMap<Hash, BTreeSet<Hash>>,
    /// `attested → set of attestation hashes` (§9.1 MUST).
    by_attested: BTreeMap<Hash, BTreeSet<Hash>>,
    /// `properties.kind → set of attestation hashes` (§9.1 MUST + §I5: only
    /// attestations with a `kind` key are indexed here).
    by_kind: BTreeMap<String, BTreeSet<Hash>>,
    /// `supersedes → set of attestation hashes` (§9.1 MUST). Only attestations
    /// whose `supersedes` field is `Some` are indexed.
    by_supersedes: BTreeMap<Hash, BTreeSet<Hash>>,
}

impl Default for AttestationIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl AttestationIndex {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(IndexInner {
                by_hash: HashMap::new(),
                by_attesting: BTreeMap::new(),
                by_attested: BTreeMap::new(),
                by_kind: BTreeMap::new(),
                by_supersedes: BTreeMap::new(),
            }),
        }
    }

    /// Insert an attestation. Idempotent: re-inserting the same hash is a no-op.
    /// Atomic per I2 — caller should only call after the entity is durable.
    pub fn insert(&self, hash: Hash, att: AttestationData) {
        let mut inner = self.inner.write().expect("attestation index poisoned");
        if inner.by_hash.contains_key(&hash) {
            return;
        }
        inner.by_attesting.entry(att.attesting).or_default().insert(hash);
        inner.by_attested.entry(att.attested).or_default().insert(hash);
        if let Some(kind) = att.kind() {
            inner
                .by_kind
                .entry(kind.to_string())
                .or_default()
                .insert(hash);
        }
        if let Some(prev) = att.supersedes {
            inner.by_supersedes.entry(prev).or_default().insert(hash);
        }
        inner.by_hash.insert(hash, att);
    }

    /// Remove an attestation from all indexes. Used by tests / future
    /// reorg flows; the spec's index invariants do NOT require removal on
    /// revocation (§I4 — revoked entities stay indexed; consumers filter
    /// via `is_attestation_live`).
    pub fn remove(&self, hash: &Hash) {
        let mut inner = self.inner.write().expect("attestation index poisoned");
        let Some(att) = inner.by_hash.remove(hash) else {
            return;
        };
        if let Some(set) = inner.by_attesting.get_mut(&att.attesting) {
            set.remove(hash);
            if set.is_empty() {
                inner.by_attesting.remove(&att.attesting);
            }
        }
        if let Some(set) = inner.by_attested.get_mut(&att.attested) {
            set.remove(hash);
            if set.is_empty() {
                inner.by_attested.remove(&att.attested);
            }
        }
        if let Some(kind) = att.kind() {
            if let Some(set) = inner.by_kind.get_mut(kind) {
                set.remove(hash);
                if set.is_empty() {
                    let key = kind.to_string();
                    inner.by_kind.remove(&key);
                }
            }
        }
        if let Some(prev) = att.supersedes {
            if let Some(set) = inner.by_supersedes.get_mut(&prev) {
                set.remove(hash);
                if set.is_empty() {
                    inner.by_supersedes.remove(&prev);
                }
            }
        }
    }

    /// Return the decoded attestation for `hash`, if known.
    pub fn get(&self, hash: &Hash) -> Option<AttestationData> {
        self.inner
            .read()
            .expect("attestation index poisoned")
            .by_hash
            .get(hash)
            .cloned()
    }

    /// Return all attestation hashes whose `attested` field equals `hash`
    /// (§5.4 backing index). Order: BTreeSet iteration (deterministic).
    pub fn lookup_by_attested(&self, hash: &Hash) -> Vec<Hash> {
        self.lookup(&self.inner.read().unwrap().by_attested, hash)
    }

    /// Return all attestation hashes whose `attesting` field equals `hash`
    /// (§5.5 backing index).
    pub fn lookup_by_attesting(&self, hash: &Hash) -> Vec<Hash> {
        self.lookup(&self.inner.read().unwrap().by_attesting, hash)
    }

    /// Return all attestation hashes whose `supersedes` field equals
    /// `predecessor` (§5.6a backing index).
    pub fn lookup_by_supersedes(&self, predecessor: &Hash) -> Vec<Hash> {
        self.lookup(&self.inner.read().unwrap().by_supersedes, predecessor)
    }

    /// Return all attestation hashes whose `properties.kind` equals `kind`
    /// (§5.6b backing index).
    pub fn lookup_by_kind(&self, kind: &str) -> Vec<Hash> {
        let inner = self.inner.read().unwrap();
        inner
            .by_kind
            .get(kind)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    fn lookup(&self, map: &BTreeMap<Hash, BTreeSet<Hash>>, key: &Hash) -> Vec<Hash> {
        map.get(key)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Total number of indexed attestations.
    pub fn len(&self) -> usize {
        self.inner.read().unwrap().by_hash.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Rebuild the index from durable tree state. Walks the
    /// `/{local_peer_id}/system/attestation/` prefix via the
    /// backend-agnostic `LocationIndex::list` API, decodes each entity,
    /// and inserts it into the in-memory index.
    ///
    /// Satisfies the EXTENSION-ATTESTATION §5.7 invariant that "index
    /// lookups are consistent with current tree state across process
    /// restarts." Peer-builder calls this once during construction
    /// before serving traffic, so that handlers reading the index see
    /// the same answers a continuously-running peer would.
    ///
    /// Idempotent: re-inserting an already-known hash is a no-op (see
    /// `insert`). Backend-portable — uses only `ContentStore` and
    /// `LocationIndex` trait methods.
    pub fn load(
        &self,
        content_store: &Arc<dyn ContentStore>,
        location_index: &Arc<dyn LocationIndex>,
        local_peer_id: &str,
    ) {
        let prefix = format!("/{}/system/attestation/", local_peer_id);
        let mut loaded = 0usize;
        for entry in location_index.list(&prefix) {
            let Some(entity) = content_store.get(&entry.hash) else {
                continue;
            };
            if entity.entity_type != TYPE_ATTESTATION {
                continue;
            }
            let Ok(att) = AttestationData::from_entity(&entity) else {
                continue;
            };
            self.insert(entry.hash, att);
            loaded += 1;
        }
        tracing::debug!(
            local_peer_id,
            loaded,
            "AttestationIndex rebuilt from tree"
        );
    }
}
