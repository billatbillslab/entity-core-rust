//! Content-addressed trie for snapshots.
//!
//! Implements `system/tree/snapshot/node` entities per EXTENSION-TREE v4.0
//! (Stage 7 substrate fork; PROPOSAL-TREE-NODE-SHAPE-BOUNDED-FANOUT.md v4.3).
//!
//! Node shape per §3.1:
//! ```text
//! system/tree/snapshot/node := {
//!   map:  bytes(4)         ; 32-bit bitmap, LSB-indexed, big-endian
//!   data: array of Entry   ; dense popcount-compressed at occupied positions
//! }
//! Entry := Bucket(array of [key, value_hash]) | Link(bytes 33)
//! ```
//!
//! Algorithm: IPLD HashMap (algorithm reference: go-hamt-ipld v3.4.1).
//! - bitWidth=5 → K=32 buckets per node
//! - bucketSize=3 (max tuples per bucket before split)
//! - hash = SHA-256(UTF-8(canonical-normalize(relative_key)))
//! - CHAMP-equivalent canonical-form: non-root nodes MUST have ≥ bucketSize+1=4
//!   reachable entries; on delete, violating sub-nodes are collapsed and
//!   inlined into the parent's bucket at the position that linked to them.
//!
//! Wire format is ours (ECF + `system/hash`); IPLD HashMap is adopted as
//! algorithm + parameters reference only — not byte-wire-compatible with
//! go-hamt-ipld.

use std::collections::{BTreeMap, HashSet};

use entity_entity::Entity;
use entity_hash::Hash;
use entity_store::ContentStore;
use sha2::{Digest, Sha256};

/// Type name for trie node entities.
pub const TYPE_TREE_SNAPSHOT_NODE: &str = "system/tree/snapshot/node";

/// Bits consumed per level. Combined with K = 2^BIT_WIDTH = 32.
pub const BIT_WIDTH: u32 = 5;

/// Width of each node — number of position slots in the bitmap.
pub const K: u32 = 1 << BIT_WIDTH;

/// Maximum tuples in a single bucket before overflow forces a sub-node.
pub const BUCKET_SIZE: usize = 3;

/// Width of the bitmap in bytes: K / 8.
pub const BITMAP_BYTES: usize = (K as usize) / 8;

/// One entry in a HAMT node's `data` array. Discriminated on the wire by
/// CBOR major type: bucket = array (major type 4), link = byte string
/// (major type 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// Leaf-level storage. Tuples MUST be sorted lex by key. len ≤ BUCKET_SIZE.
    Bucket(Vec<(String, Hash)>),
    /// Reference to a sub-node entity.
    Link(Hash),
}

/// In-memory representation of a `system/tree/snapshot/node` entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotNodeData {
    /// Bitmap of occupied positions (LSB-indexed). bit `p` set ⇔ position `p`
    /// has an entry in `data`.
    pub map: u32,
    /// Dense array of entries at occupied positions, ordered by position.
    /// `len(data) == popcount(map)`.
    pub data: Vec<Entry>,
}

impl SnapshotNodeData {
    /// Empty (canonical empty-root) node.
    pub fn empty() -> Self {
        SnapshotNodeData {
            map: 0,
            data: Vec::new(),
        }
    }

    /// ECF-encode this node to deterministic CBOR bytes.
    ///
    /// Map keys: `"map"` (bytes(4)) and `"data"` (array). ECF orders keys
    /// length-first then lex; `"map"` (text(3), 4 encoded bytes) precedes
    /// `"data"` (text(4), 5 encoded bytes).
    pub fn to_ecf_bytes(&self) -> Vec<u8> {
        let mut bitmap_bytes = vec![0u8; BITMAP_BYTES];
        bitmap_bytes.copy_from_slice(&self.map.to_be_bytes());

        let data_array: Vec<entity_ecf::Value> = self
            .data
            .iter()
            .map(|e| match e {
                Entry::Bucket(tuples) => {
                    let bucket_items: Vec<entity_ecf::Value> = tuples
                        .iter()
                        .map(|(k, h)| {
                            entity_ecf::Value::Array(vec![
                                entity_ecf::text(k),
                                entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
                            ])
                        })
                        .collect();
                    entity_ecf::Value::Array(bucket_items)
                }
                Entry::Link(h) => entity_ecf::Value::Bytes(h.to_bytes().to_vec()),
            })
            .collect();

        let value = entity_ecf::Value::Map(vec![
            (entity_ecf::text("map"), entity_ecf::Value::Bytes(bitmap_bytes)),
            (entity_ecf::text("data"), entity_ecf::Value::Array(data_array)),
        ]);
        entity_ecf::to_ecf(&value)
    }

    /// Decode from raw CBOR data.
    pub fn from_cbor(data: &[u8]) -> Option<Self> {
        let value: ciborium::Value = ciborium::from_reader(data).ok()?;
        let map = value.as_map()?;

        let mut bitmap: Option<u32> = None;
        let mut entries: Option<Vec<Entry>> = None;

        for (k, v) in map {
            match k.as_text()? {
                "map" => {
                    let b = v.as_bytes()?;
                    if b.len() != BITMAP_BYTES {
                        return None;
                    }
                    let mut buf = [0u8; BITMAP_BYTES];
                    buf.copy_from_slice(b);
                    bitmap = Some(u32::from_be_bytes(buf));
                }
                "data" => {
                    let arr = v.as_array()?;
                    let mut out = Vec::with_capacity(arr.len());
                    for item in arr {
                        if let Some(item_arr) = item.as_array() {
                            // Bucket: array of [key, value_hash] 2-arrays
                            let mut tuples = Vec::with_capacity(item_arr.len());
                            for tuple in item_arr {
                                let pair = tuple.as_array()?;
                                if pair.len() != 2 {
                                    return None;
                                }
                                let key = pair[0].as_text()?.to_string();
                                let hash = Hash::from_bytes(pair[1].as_bytes()?).ok()?;
                                tuples.push((key, hash));
                            }
                            out.push(Entry::Bucket(tuples));
                        } else if let Some(b) = item.as_bytes() {
                            let h = Hash::from_bytes(b).ok()?;
                            out.push(Entry::Link(h));
                        } else {
                            return None;
                        }
                    }
                    entries = Some(out);
                }
                _ => {}
            }
        }

        Some(SnapshotNodeData {
            map: bitmap?,
            data: entries?,
        })
    }
}

/// SHA-256 of UTF-8 bytes of the relative key. Canonical-normalize is a
/// pass-through at this layer — callers above already normalize paths.
fn key_hash(key: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    digest
}

/// Extract the 5-bit slice for the given level from the 32-byte hash.
/// MSB-first within each byte: level 0 → bits 0-4 of byte 0 (the top 5 bits).
fn bit_slice_at(hash_bytes: &[u8; 32], level: usize) -> u32 {
    let bit_offset = level * BIT_WIDTH as usize;
    let byte_offset = bit_offset / 8;
    let bit_in_byte = bit_offset % 8;
    debug_assert!(byte_offset < 32);
    let b0 = hash_bytes[byte_offset] as u32;
    let b1 = if byte_offset + 1 < 32 {
        hash_bytes[byte_offset + 1] as u32
    } else {
        0
    };
    let combined = (b0 << 8) | b1;
    let shift = 16 - bit_in_byte - BIT_WIDTH as usize;
    (combined >> shift) & 0x1F
}

/// Returns `(bit_set, data_index)` for position `p` in `map`.
/// `data_index = popcount(map & ((1 << p) - 1))`.
fn position(map: u32, p: u32) -> (bool, usize) {
    let bit_set = (map >> p) & 1 == 1;
    let mask = if p == 0 { 0 } else { (1u32 << p) - 1 };
    let idx = (map & mask).count_ones() as usize;
    (bit_set, idx)
}

/// Count the total number of (key, value_hash) bindings reachable from this
/// node (sum over inline buckets + recursive load of linked sub-nodes).
/// Used during the remove path to enforce the canonical-form invariant.
fn count_entries(store: &dyn ContentStore, node: &SnapshotNodeData) -> Result<usize, String> {
    let mut total = 0usize;
    for entry in &node.data {
        match entry {
            Entry::Bucket(b) => total += b.len(),
            Entry::Link(h) => {
                let sub = load_trie_node(store, *h)
                    .ok_or_else(|| "missing sub-node".to_string())?;
                total += count_entries(store, &sub)?;
            }
        }
    }
    Ok(total)
}

/// Flatten all bindings reachable from this node into a list of tuples.
/// Used for collapse-and-inline on the remove path.
fn flatten_entries(
    store: &dyn ContentStore,
    node: &SnapshotNodeData,
) -> Result<Vec<(String, Hash)>, String> {
    let mut out = Vec::new();
    flatten_entries_into(store, node, &mut out)?;
    Ok(out)
}

fn flatten_entries_into(
    store: &dyn ContentStore,
    node: &SnapshotNodeData,
    out: &mut Vec<(String, Hash)>,
) -> Result<(), String> {
    for entry in &node.data {
        match entry {
            Entry::Bucket(b) => out.extend(b.iter().cloned()),
            Entry::Link(h) => {
                let sub = load_trie_node(store, *h)
                    .ok_or_else(|| "missing sub-node".to_string())?;
                flatten_entries_into(store, &sub, out)?;
            }
        }
    }
    Ok(())
}

/// Build a HAMT from a sorted set of bindings.
///
/// Returns the root node hash. Stores all trie nodes in the content store.
/// Per EXTENSION-TREE v4.0 §3.3: equivalent to incremental insertion via
/// `trie_put` from the empty root.
pub fn build_trie(
    store: &dyn ContentStore,
    bindings: &BTreeMap<String, Hash>,
) -> Result<Hash, String> {
    let mut root = SnapshotNodeData::empty();
    for (k, v) in bindings {
        let hb = key_hash(k);
        root = put_at_node(store, &root, &hb, 0, k, *v)?;
    }
    store_trie_node(store, &root)
}

/// Incrementally update a HAMT: bind `relative_key` to `value_hash`.
/// Returns the new root hash.
pub fn trie_put(
    store: &dyn ContentStore,
    root_hash: Option<Hash>,
    relative_key: &str,
    value_hash: Hash,
) -> Result<Hash, String> {
    let root = load_or_empty(store, root_hash);
    let hb = key_hash(relative_key);
    let new_root = put_at_node(store, &root, &hb, 0, relative_key, value_hash)?;
    store_trie_node(store, &new_root)
}

/// Incrementally update a HAMT: remove the binding at `relative_key`.
/// Returns the new root hash. If the key was absent the root is unchanged.
pub fn trie_remove(
    store: &dyn ContentStore,
    root_hash: Option<Hash>,
    relative_key: &str,
) -> Result<Hash, String> {
    let root = load_or_empty(store, root_hash);
    let hb = key_hash(relative_key);
    match remove_at_node(store, &root, &hb, 0, relative_key, /*is_root=*/ true)? {
        RemoveOutcome::Unchanged => store_trie_node(store, &root),
        RemoveOutcome::Modified(new_root) => store_trie_node(store, &new_root),
        RemoveOutcome::Inline(_) => {
            // Root is exempt from the canonical-form lower bound; inline at
            // root level is impossible since we pass is_root=true.
            unreachable!("root never reports Inline")
        }
    }
}

/// One step of a HAMT lookup at a given node + level. Pure (no I/O), so both
/// the sync [`trie_get`] and an async remote walker (the http-poll outbound
/// connector) can drive the descent off the same primitive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrieStep {
    /// `relative_key` resolved to this value hash in a bucket at this node.
    Found(Hash),
    /// Descend into this sub-node hash at `level + 1`.
    Descend(Hash),
    /// `relative_key` is not present in the trie.
    Absent,
}

/// Compute the next lookup step for `relative_key` at `node` / `level`.
pub fn trie_step(node: &SnapshotNodeData, relative_key: &str, level: usize) -> TrieStep {
    let hb = key_hash(relative_key);
    let p = bit_slice_at(&hb, level);
    let (bit_set, idx) = position(node.map, p);
    if !bit_set {
        return TrieStep::Absent;
    }
    match &node.data[idx] {
        Entry::Bucket(tuples) => tuples
            .iter()
            .find_map(|(k, v)| if k == relative_key { Some(TrieStep::Found(*v)) } else { None })
            .unwrap_or(TrieStep::Absent),
        Entry::Link(sub_hash) => TrieStep::Descend(*sub_hash),
    }
}

/// Resolve `relative_key` to its bound value hash by walking the HAMT from
/// `root_hash`. The read complement to [`trie_put`] / [`trie_remove`].
///
/// Every node is fetched from `store` by hash, so when `store` is a
/// hash-verifying remote fetcher (e.g. the http-poll outbound connector's
/// CONTENT_GET client), this walk binds the resolved path to the signed root
/// cryptographically — a host cannot inject a `path → hash` binding the
/// publisher never committed to (PROPOSAL-PEER-MANIFEST §1.1 threat model).
/// Returns `None` if the key is absent or any node along the path is missing.
pub fn trie_get(
    store: &dyn ContentStore,
    root_hash: Hash,
    relative_key: &str,
) -> Option<Hash> {
    let mut node = load_trie_node(store, root_hash)?;
    let mut level = 0usize;
    loop {
        match trie_step(&node, relative_key, level) {
            TrieStep::Found(h) => return Some(h),
            TrieStep::Absent => return None,
            TrieStep::Descend(sub) => {
                node = load_trie_node(store, sub)?;
                level += 1;
            }
        }
    }
}

fn load_or_empty(store: &dyn ContentStore, root_hash: Option<Hash>) -> SnapshotNodeData {
    match root_hash.and_then(|h| load_trie_node(store, h)) {
        Some(n) => n,
        None => SnapshotNodeData::empty(),
    }
}

/// Recursive HAMT put. Returns the modified node (not the hash); the caller
/// stores it. Sub-nodes created during overflow are stored eagerly.
fn put_at_node(
    store: &dyn ContentStore,
    node: &SnapshotNodeData,
    hash_bytes: &[u8; 32],
    level: usize,
    key: &str,
    value_hash: Hash,
) -> Result<SnapshotNodeData, String> {
    let p = bit_slice_at(hash_bytes, level);
    let (bit_set, idx) = position(node.map, p);

    if !bit_set {
        // Empty position: insert a new single-entry bucket.
        let mut new_data = node.data.clone();
        new_data.insert(idx, Entry::Bucket(vec![(key.to_string(), value_hash)]));
        return Ok(SnapshotNodeData {
            map: node.map | (1u32 << p),
            data: new_data,
        });
    }

    match &node.data[idx] {
        Entry::Bucket(tuples) => {
            if let Some(pos) = tuples.iter().position(|(k, _)| k == key) {
                // Key already present: replace value_hash (bucket-sort intact).
                let mut new_tuples = tuples.clone();
                new_tuples[pos].1 = value_hash;
                let mut new_data = node.data.clone();
                new_data[idx] = Entry::Bucket(new_tuples);
                Ok(SnapshotNodeData {
                    map: node.map,
                    data: new_data,
                })
            } else if tuples.len() < BUCKET_SIZE {
                // Bucket has room: insert with lex sort.
                let mut new_tuples = tuples.clone();
                new_tuples.push((key.to_string(), value_hash));
                new_tuples.sort_by(|a, b| a.0.cmp(&b.0));
                let mut new_data = node.data.clone();
                new_data[idx] = Entry::Bucket(new_tuples);
                Ok(SnapshotNodeData {
                    map: node.map,
                    data: new_data,
                })
            } else {
                // Overflow: convert bucket → sub-node; recurse all 4 entries
                // (existing 3 + new 1) at level+1.
                let mut sub = SnapshotNodeData::empty();
                for (k, v) in tuples {
                    let sub_hb = key_hash(k);
                    sub = put_at_node(store, &sub, &sub_hb, level + 1, k, *v)?;
                }
                sub = put_at_node(store, &sub, hash_bytes, level + 1, key, value_hash)?;
                let sub_hash = store_trie_node(store, &sub)?;
                let mut new_data = node.data.clone();
                new_data[idx] = Entry::Link(sub_hash);
                Ok(SnapshotNodeData {
                    map: node.map,
                    data: new_data,
                })
            }
        }
        Entry::Link(sub_hash) => {
            let sub = load_trie_node(store, *sub_hash)
                .ok_or_else(|| "missing sub-node".to_string())?;
            let new_sub = put_at_node(store, &sub, hash_bytes, level + 1, key, value_hash)?;
            let new_sub_hash = store_trie_node(store, &new_sub)?;
            let mut new_data = node.data.clone();
            new_data[idx] = Entry::Link(new_sub_hash);
            Ok(SnapshotNodeData {
                map: node.map,
                data: new_data,
            })
        }
    }
}

/// Outcome of a recursive remove at a non-root level.
enum RemoveOutcome {
    /// Key was not present in this subtree; node is unchanged.
    Unchanged,
    /// Node was modified; caller relinks via the new node.
    Modified(SnapshotNodeData),
    /// Sub-node violated the canonical-form lower bound after removal.
    /// Caller inlines these tuples into its bucket at the linking position.
    /// `tuples.len() < BUCKET_SIZE + 1 = 4` (so they fit in one bucket).
    Inline(Vec<(String, Hash)>),
}

fn remove_at_node(
    store: &dyn ContentStore,
    node: &SnapshotNodeData,
    hash_bytes: &[u8; 32],
    level: usize,
    key: &str,
    is_root: bool,
) -> Result<RemoveOutcome, String> {
    let p = bit_slice_at(hash_bytes, level);
    let (bit_set, idx) = position(node.map, p);

    if !bit_set {
        return Ok(RemoveOutcome::Unchanged);
    }

    let mut new_map = node.map;
    let mut new_data = node.data.clone();

    match &node.data[idx] {
        Entry::Bucket(tuples) => {
            let Some(pos) = tuples.iter().position(|(k, _)| k == key) else {
                return Ok(RemoveOutcome::Unchanged);
            };
            if tuples.len() == 1 {
                // Empty bucket → drop entry entirely.
                new_map &= !(1u32 << p);
                new_data.remove(idx);
            } else {
                let mut new_tuples = tuples.clone();
                new_tuples.remove(pos);
                new_data[idx] = Entry::Bucket(new_tuples);
            }
        }
        Entry::Link(sub_hash) => {
            let sub = load_trie_node(store, *sub_hash)
                .ok_or_else(|| "missing sub-node".to_string())?;
            match remove_at_node(store, &sub, hash_bytes, level + 1, key, false)? {
                RemoveOutcome::Unchanged => return Ok(RemoveOutcome::Unchanged),
                RemoveOutcome::Modified(new_sub) => {
                    let new_sub_hash = store_trie_node(store, &new_sub)?;
                    new_data[idx] = Entry::Link(new_sub_hash);
                }
                RemoveOutcome::Inline(mut tuples) => {
                    // Collapse: sub-node fell below canonical-form bound; inline
                    // its reachable entries as a bucket at this position.
                    if tuples.is_empty() {
                        // No reachable entries at all — drop the link.
                        new_map &= !(1u32 << p);
                        new_data.remove(idx);
                    } else {
                        tuples.sort_by(|a, b| a.0.cmp(&b.0));
                        debug_assert!(tuples.len() <= BUCKET_SIZE);
                        new_data[idx] = Entry::Bucket(tuples);
                    }
                }
            }
        }
    }

    let result = SnapshotNodeData {
        map: new_map,
        data: new_data,
    };

    if is_root {
        return Ok(RemoveOutcome::Modified(result));
    }

    // Non-root: enforce canonical-form invariant. If branchSize < bucketSize+1,
    // signal collapse-and-inline to the parent.
    let branch = count_entries(store, &result)?;
    if branch < BUCKET_SIZE + 1 {
        let tuples = flatten_entries(store, &result)?;
        Ok(RemoveOutcome::Inline(tuples))
    } else {
        Ok(RemoveOutcome::Modified(result))
    }
}

/// Create a trie node entity and store it in the content store.
pub fn store_trie_node(
    store: &dyn ContentStore,
    node: &SnapshotNodeData,
) -> Result<Hash, String> {
    let data = node.to_ecf_bytes();
    let entity =
        Entity::new(TYPE_TREE_SNAPSHOT_NODE, data).map_err(|e| e.to_string())?;
    store.put(entity).map_err(|e| e.to_string())
}

/// Load a trie node from the content store.
pub fn load_trie_node(store: &dyn ContentStore, hash: Hash) -> Option<SnapshotNodeData> {
    let entity = store.get(&hash)?;
    SnapshotNodeData::from_cbor(&entity.data)
}

/// Collect the transitive content-hash closure of a snapshot trie rooted at
/// `root_hash`: the root node hash, every reachable sub-node hash, and every
/// leaf-bound value hash.
///
/// This is the serving-mode floor for NETWORK §6.5.6 Amendment 10
/// (closure-of-signed-root): a consumer running the PEER-MANIFEST §1.1
/// walk-from-signed-root must be able to `CONTENT_GET` every interior node
/// (hash-linked, not path-bound — V7 §1.7) and every leaf value by hash. The
/// published-root entity + its signature are NOT trie nodes; the caller adds
/// those to the served set.
///
/// Best-effort over what the store actually holds — a missing sub-node simply
/// terminates that branch (its hash is still recorded so the gap is visible to
/// a consumer as a hash-verified 404, never a silent substitution).
pub fn collect_node_closure(store: &dyn ContentStore, root_hash: Hash) -> HashSet<Hash> {
    let mut out = HashSet::new();
    collect_closure_into(store, root_hash, &mut out);
    out
}

fn collect_closure_into(store: &dyn ContentStore, node_hash: Hash, out: &mut HashSet<Hash>) {
    if !out.insert(node_hash) {
        return; // already visited (shared sub-node / cycle guard)
    }
    let node = match load_trie_node(store, node_hash) {
        Some(n) => n,
        None => return,
    };
    for entry in &node.data {
        match entry {
            Entry::Bucket(tuples) => {
                for (_k, value_hash) in tuples {
                    out.insert(*value_hash);
                }
            }
            Entry::Link(sub) => collect_closure_into(store, *sub, out),
        }
    }
}

/// Collect all path→hash bindings reachable from `node_hash`.
///
/// Per EXTENSION-TREE §5.4 `collect_all_bindings(node, _path_prefix_unused)`:
/// under hash-keyed routing the trie stores full relative_key strings in
/// leaf buckets, so the `prefix` argument is unused — preserved for API
/// compatibility. The returned `BTreeMap` is naturally lex-sorted.
pub fn collect_all_bindings(
    store: &dyn ContentStore,
    node_hash: Hash,
    _prefix_unused: &str,
) -> BTreeMap<String, Hash> {
    let mut result = BTreeMap::new();
    if let Some(node) = load_trie_node(store, node_hash) {
        collect_bindings_into(store, &node, &mut result);
    }
    result
}

fn collect_bindings_into(
    store: &dyn ContentStore,
    node: &SnapshotNodeData,
    out: &mut BTreeMap<String, Hash>,
) {
    for entry in &node.data {
        match entry {
            Entry::Bucket(b) => {
                for (k, h) in b {
                    out.insert(k.clone(), *h);
                }
            }
            Entry::Link(h) => {
                if let Some(sub) = load_trie_node(store, *h) {
                    collect_bindings_into(store, &sub, out);
                }
            }
        }
    }
}

/// Collect all hashes reachable from a trie root (node hashes + value hashes).
/// Used by `fetch-entities` to validate requested hashes against the trie.
pub fn collect_all_hashes(
    store: &dyn ContentStore,
    node_hash: Hash,
) -> std::collections::HashSet<Hash> {
    let mut result = std::collections::HashSet::new();
    collect_hashes_recursive(store, node_hash, &mut result);
    result
}

fn collect_hashes_recursive(
    store: &dyn ContentStore,
    node_hash: Hash,
    result: &mut std::collections::HashSet<Hash>,
) {
    if !result.insert(node_hash) {
        return;
    }
    let Some(node) = load_trie_node(store, node_hash) else {
        return;
    };
    for entry in &node.data {
        match entry {
            Entry::Bucket(b) => {
                for (_, h) in b {
                    result.insert(*h);
                }
            }
            Entry::Link(h) => collect_hashes_recursive(store, *h, result),
        }
    }
}

/// Record every trie-node hash AND every value hash reachable from
/// `node_hash` into `collected`. Used by `revision:fetch-diff` to compute
/// the "receiver already has" set rooted at the caller-supplied base
/// version's trie root.
pub fn collect_reachable_hashes(
    store: &dyn ContentStore,
    node_hash: Hash,
    collected: &mut std::collections::HashSet<Hash>,
) {
    if !collected.insert(node_hash) {
        return;
    }
    let Some(node) = load_trie_node(store, node_hash) else {
        return;
    };
    for entry in &node.data {
        match entry {
            Entry::Bucket(b) => {
                for (_, h) in b {
                    collected.insert(*h);
                }
            }
            Entry::Link(h) => collect_reachable_hashes(store, *h, collected),
        }
    }
}

/// Walk the trie at `node_hash` collecting every node + value entity whose
/// hash is NOT in `skip` into `collected`. Content-addressed equality means
/// a subtree whose root hash matches the receiver's is shared verbatim and
/// need not be transmitted; same for any value entity already in the
/// receiver's base closure. Used by `revision:fetch-diff`.
pub fn collect_trie_entities_except(
    store: &dyn ContentStore,
    node_hash: Hash,
    skip: &std::collections::HashSet<Hash>,
    collected: &mut BTreeMap<Hash, Entity>,
) {
    if skip.contains(&node_hash) || collected.contains_key(&node_hash) {
        return;
    }
    let Some(entity) = store.get(&node_hash) else {
        return;
    };
    let Some(node) = SnapshotNodeData::from_cbor(&entity.data) else {
        collected.insert(node_hash, entity);
        return;
    };
    collected.insert(node_hash, entity);
    for entry in &node.data {
        match entry {
            Entry::Bucket(b) => {
                for (_, h) in b {
                    if !skip.contains(h) && !collected.contains_key(h) {
                        if let Some(ent) = store.get(h) {
                            collected.insert(*h, ent);
                        }
                    }
                }
            }
            Entry::Link(h) => collect_trie_entities_except(store, *h, skip, collected),
        }
    }
}

/// Join two path components with "/".
pub fn join_path(prefix: &str, suffix: &str) -> String {
    if prefix.is_empty() {
        suffix.to_string()
    } else if suffix.is_empty() {
        prefix.to_string()
    } else {
        format!("{}/{}", prefix, suffix)
    }
}

/// Sort parents by lexicographic binary comparison of their hash bytes.
/// Used by version entry hashing per EXTENSION-REVISION §2.1.
pub fn sorted_parents(parents: &mut [Hash]) {
    parents.sort();
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_store::MemoryContentStore;

    fn test_store() -> MemoryContentStore {
        MemoryContentStore::new()
    }

    fn make_hash(n: u8) -> Hash {
        let mut digest = [0u8; 32];
        digest[0] = n;
        Hash::new(0x00, digest)
    }

    // ----- Bit-slice + position helpers -----

    #[test]
    fn test_bit_slice_at_level_0() {
        // SHA-256("") = e3 b0 c4 42 ... ; byte 0 = 0xe3 = 0b11100011.
        // Top 5 bits MSB-first = 0b11100 = 28.
        let hb = key_hash("");
        assert_eq!(hb[0], 0xe3);
        assert_eq!(bit_slice_at(&hb, 0), 28);
    }

    #[test]
    fn test_position_lookup() {
        // map = 0b1010 → positions 1, 3 occupied.
        let m = 0b1010u32;
        assert_eq!(position(m, 0), (false, 0));
        assert_eq!(position(m, 1), (true, 0));
        assert_eq!(position(m, 2), (false, 1));
        assert_eq!(position(m, 3), (true, 1));
        assert_eq!(position(m, 4), (false, 2));
    }

    #[test]
    fn test_trie_get_resolves_and_misses() {
        let store = test_store();
        let mut bindings = BTreeMap::new();
        // Enough keys to force bucket overflow → sub-nodes (exercises the
        // Link descent in trie_get, not just a top-level bucket).
        for i in 0u8..20 {
            bindings.insert(format!("system/key/{}", i), make_hash(i + 1));
        }
        let root = build_trie(&store, &bindings).unwrap();
        for i in 0u8..20 {
            let got = trie_get(&store, root, &format!("system/key/{}", i));
            assert_eq!(got, Some(make_hash(i + 1)), "key {} should resolve", i);
        }
        assert_eq!(trie_get(&store, root, "system/key/absent"), None);
    }

    // ----- Conformance fixtures (EXTENSION-TREE §3.1 / §12.1) -----

    /// Conformance fixture #1: empty-root node MUST encode to this exact
    /// byte sequence. Any deviation breaks cross-peer trie root comparison.
    #[test]
    fn test_conformance_empty_root_bytes() {
        let node = SnapshotNodeData::empty();
        let bytes = node.to_ecf_bytes();
        // A2 63 6D6170 44 00000000 64 64617461 80
        let expected: Vec<u8> = vec![
            0xA2, // map(2)
            0x63, 0x6D, 0x61, 0x70, // text(3) "map"
            0x44, 0x00, 0x00, 0x00, 0x00, // bytes(4) bitmap = 0
            0x64, 0x64, 0x61, 0x74, 0x61, // text(4) "data"
            0x80, // array(0)
        ];
        assert_eq!(bytes, expected, "empty-root node bytes diverge from §3.1 fixture");
    }

    /// Conformance fixture #2: single binding at relative_key="" with
    /// value_hash H MUST encode to this exact byte sequence.
    /// SHA-256("") → top 5 bits = 28 → bitmap = 0x10000000 → BE bytes
    /// `10 00 00 00`. Catches SHA-256-input and bitmap-convention drift.
    #[test]
    fn test_conformance_single_binding_at_empty_key_bytes() {
        let store = test_store();
        let value_h = make_hash(0xAB);
        let root_hash = trie_put(&store, None, "", value_h).unwrap();
        let root_node = load_trie_node(&store, root_hash).unwrap();
        let bytes = root_node.to_ecf_bytes();

        let mut expected: Vec<u8> = vec![
            0xA2, // map(2)
            0x63, 0x6D, 0x61, 0x70, // text(3) "map"
            0x44, 0x10, 0x00, 0x00, 0x00, // bytes(4) bitmap = 0x10000000
            0x64, 0x64, 0x61, 0x74, 0x61, // text(4) "data"
            0x81, // array(1)  -- one entry in data
            0x81, // array(1)  -- bucket with one tuple
            0x82, // array(2)  -- [key, value_hash]
            0x60, // text(0)   -- ""
            0x58, 0x21, // bytes(33)
        ];
        expected.extend_from_slice(&value_h.to_bytes());

        assert_eq!(
            bytes, expected,
            "single-binding node bytes diverge from §3.1 fixture"
        );
    }

    // ----- Basic operation tests -----

    #[test]
    fn test_empty_trie_roundtrip() {
        let store = test_store();
        let bindings = BTreeMap::new();
        let root = build_trie(&store, &bindings).unwrap();
        assert_ne!(root, Hash::zero());
        let node = load_trie_node(&store, root).unwrap();
        assert_eq!(node, SnapshotNodeData::empty());
    }

    #[test]
    fn test_single_binding_roundtrip() {
        let store = test_store();
        let mut bindings = BTreeMap::new();
        bindings.insert("a".to_string(), make_hash(1));
        let root = build_trie(&store, &bindings).unwrap();
        let collected = collect_all_bindings(&store, root, "");
        assert_eq!(collected, bindings);
    }

    #[test]
    fn test_multiple_bindings_roundtrip() {
        let store = test_store();
        let mut bindings = BTreeMap::new();
        for i in 0..20u8 {
            bindings.insert(format!("key/{}", i), make_hash(i));
        }
        let root = build_trie(&store, &bindings).unwrap();
        let collected = collect_all_bindings(&store, root, "");
        assert_eq!(collected, bindings);
    }

    #[test]
    fn test_determinism_same_bindings_same_root() {
        let store = test_store();
        let mut bindings = BTreeMap::new();
        bindings.insert("x/y/z".to_string(), make_hash(1));
        bindings.insert("x/y/w".to_string(), make_hash(2));
        bindings.insert("a/b".to_string(), make_hash(3));

        let root1 = build_trie(&store, &bindings).unwrap();
        let root2 = build_trie(&store, &bindings).unwrap();
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_determinism_insertion_order_invariant() {
        // CHAMP canonical-form guarantees same set → same root regardless
        // of insertion history. This is THE invariant Stage 7 adds.
        let store = test_store();
        let pairs: Vec<(&str, u8)> = vec![
            ("a/b/c", 1),
            ("d/e/f", 2),
            ("g/h", 3),
            ("i", 4),
            ("a/b/d", 5),
            ("x/y/z", 6),
        ];

        let mut r1: Option<Hash> = None;
        for (k, v) in &pairs {
            r1 = Some(trie_put(&store, r1, k, make_hash(*v)).unwrap());
        }

        let mut pairs_rev = pairs.clone();
        pairs_rev.reverse();
        let mut r2: Option<Hash> = None;
        for (k, v) in &pairs_rev {
            r2 = Some(trie_put(&store, r2, k, make_hash(*v)).unwrap());
        }

        assert_eq!(r1, r2, "insertion order should not affect root hash");
    }

    // ----- Incremental put / remove equivalence -----

    fn put_sequence_equivalent_to_build(seq: &[(&str, u8)]) {
        let store = test_store();
        let mut incremental: Option<Hash> = None;
        let mut bindings = BTreeMap::new();
        for (path, tag) in seq {
            let hash = make_hash(*tag);
            incremental = Some(trie_put(&store, incremental, path, hash).unwrap());
            bindings.insert(path.to_string(), hash);
        }
        let built = build_trie(&store, &bindings).unwrap();
        assert_eq!(incremental.unwrap(), built, "seq={:?}", seq);
    }

    #[test]
    fn test_trie_put_single() {
        put_sequence_equivalent_to_build(&[("a/b/c", 1)]);
    }

    #[test]
    fn test_trie_put_siblings() {
        put_sequence_equivalent_to_build(&[("a", 1), ("b", 2)]);
    }

    #[test]
    fn test_trie_put_overwrite() {
        let store = test_store();
        let r = trie_put(&store, None, "a/b", make_hash(1)).unwrap();
        let r = trie_put(&store, Some(r), "a/b", make_hash(9)).unwrap();
        let collected = collect_all_bindings(&store, r, "");
        assert_eq!(collected.get("a/b"), Some(&make_hash(9)));
        assert_eq!(collected.len(), 1);
    }

    #[test]
    fn test_trie_put_many_matches_build() {
        put_sequence_equivalent_to_build(&[
            ("project/src/main.rs", 1),
            ("project/src/lib.rs", 2),
            ("project/Cargo.toml", 3),
            ("project/tests/unit.rs", 4),
            ("project/tests/integration.rs", 5),
            ("docs/README.md", 6),
            ("docs/api/overview.md", 7),
            ("a", 8),
        ]);
    }

    fn mixed_sequence_equivalent_to_build(seq: &[(bool, &str, u8)]) {
        let store = test_store();
        let mut incremental: Option<Hash> = None;
        let mut bindings = BTreeMap::new();
        for (is_put, path, tag) in seq {
            if *is_put {
                let hash = make_hash(*tag);
                incremental = Some(trie_put(&store, incremental, path, hash).unwrap());
                bindings.insert(path.to_string(), hash);
            } else {
                incremental = Some(trie_remove(&store, incremental, path).unwrap());
                bindings.remove(*path);
            }
        }
        let built = build_trie(&store, &bindings).unwrap();
        assert_eq!(incremental.unwrap(), built, "seq={:?}", seq);
    }

    #[test]
    fn test_trie_remove_single_binding() {
        mixed_sequence_equivalent_to_build(&[(true, "a/b/c", 1), (false, "a/b/c", 0)]);
    }

    #[test]
    fn test_trie_remove_one_of_many() {
        mixed_sequence_equivalent_to_build(&[
            (true, "a/b", 1),
            (true, "a/c", 2),
            (true, "d", 3),
            (false, "a/c", 0),
        ]);
    }

    #[test]
    fn test_trie_remove_missing_is_noop() {
        let store = test_store();
        let root = trie_put(&store, None, "a/b", make_hash(1)).unwrap();
        let root2 = trie_remove(&store, Some(root), "x/y").unwrap();
        let a = collect_all_bindings(&store, root, "");
        let b = collect_all_bindings(&store, root2, "");
        assert_eq!(a, b);
    }

    #[test]
    fn test_trie_remove_all_matches_empty() {
        mixed_sequence_equivalent_to_build(&[
            (true, "x/y", 1),
            (true, "x/z", 2),
            (false, "x/y", 0),
            (false, "x/z", 0),
        ]);
    }

    #[test]
    fn test_trie_mixed_large_sequence() {
        mixed_sequence_equivalent_to_build(&[
            (true, "project/src/main.rs", 1),
            (true, "project/src/lib.rs", 2),
            (true, "project/Cargo.toml", 3),
            (true, "project/tests/unit.rs", 4),
            (false, "project/src/main.rs", 0),
            (true, "project/src/main.rs", 5),
            (true, "docs/README.md", 6),
            (false, "project/Cargo.toml", 0),
            (true, "project/Cargo.toml", 7),
            (false, "project/tests/unit.rs", 0),
        ]);
    }

    /// CHAMP-on-delete canonical-form fuzzer (§12.1 MUST).
    ///
    /// Random Put/Delete sequences over a small key universe (forces both
    /// bucket overflow and collapse cascades within K=32, bucketSize=3).
    /// Equivalence to build_trie(final_set) is the canonical-form invariant.
    /// Insert-only tests would not exercise collapse-and-inline; this is the
    /// silent-bug class flagged by the spec at §3.4.2.
    #[test]
    fn test_trie_fuzz_put_remove_canonical_form() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash as _, Hasher};

        // 32 keys is enough to push past BUCKET_SIZE=3 at level 0 and force
        // sub-node creation; covers collapse paths when keys are removed.
        let keys: Vec<String> = (0..32u8).map(|i| format!("k/{:02}", i)).collect();

        // 16 seeds × 64 ops each — small enough to be fast, broad enough
        // to exercise the canonical-form invariant under arbitrary history.
        for seed in 0..16u64 {
            let store = test_store();
            let mut incremental: Option<Hash> = None;
            let mut bindings: BTreeMap<String, Hash> = BTreeMap::new();

            let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15);
            let mut rand = || {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                state
            };

            for _ in 0..64 {
                let r = rand();
                let key = &keys[(r as usize) % keys.len()];
                let is_put = (r >> 32) & 1 == 0 || bindings.is_empty();
                if is_put {
                    let h = make_hash((rand() as u8).wrapping_add(1));
                    incremental = Some(trie_put(&store, incremental, key, h).unwrap());
                    bindings.insert(key.clone(), h);
                } else {
                    incremental = Some(trie_remove(&store, incremental, key).unwrap());
                    bindings.remove(key);
                }
            }

            let built = build_trie(&store, &bindings).unwrap();
            let inc = incremental.unwrap();
            assert_eq!(
                inc, built,
                "seed {} diverged: incremental {:?} vs build {:?} (size {})",
                seed,
                inc,
                built,
                bindings.len()
            );

            // Force the Hasher reference to be used (silences unused-import
            // warning on toolchains that don't auto-elide).
            let mut _h = DefaultHasher::new();
            seed.hash(&mut _h);
        }
    }

    /// Force overflow + collapse: build a key set known to share top-5-bit
    /// SHA-256 prefixes, populate to > BUCKET_SIZE at one position, then
    /// remove enough to trigger collapse-and-inline back to the parent.
    #[test]
    fn test_trie_collapse_on_delete() {
        let store = test_store();
        // Insert many keys; with 32 keys at K=32 fanout, some positions will
        // overflow into sub-nodes. Remove the entire set one-by-one; final
        // root MUST byte-equal the canonical empty-root.
        let mut keys: Vec<(String, Hash)> = (0..40u8)
            .map(|i| (format!("path/segment/leaf-{}", i), make_hash(i)))
            .collect();

        let mut root: Option<Hash> = None;
        for (k, v) in &keys {
            root = Some(trie_put(&store, root, k, *v).unwrap());
        }

        // Now remove all in reverse order; final root must be empty-root.
        keys.reverse();
        for (k, _) in &keys {
            root = Some(trie_remove(&store, root, k).unwrap());
        }

        let empty_root = build_trie(&store, &BTreeMap::new()).unwrap();
        assert_eq!(
            root.unwrap(),
            empty_root,
            "after removing all bindings, root should equal canonical empty-root"
        );
    }

    // ----- Reachability helpers -----

    #[test]
    fn test_collect_all_hashes_includes_values() {
        let store = test_store();
        let mut bindings = BTreeMap::new();
        bindings.insert("a".to_string(), make_hash(1));
        bindings.insert("b".to_string(), make_hash(2));
        let root = build_trie(&store, &bindings).unwrap();
        let hashes = collect_all_hashes(&store, root);
        assert!(hashes.contains(&root));
        assert!(hashes.contains(&make_hash(1)));
        assert!(hashes.contains(&make_hash(2)));
    }

    #[test]
    fn test_collect_reachable_hashes_walks_links() {
        let store = test_store();
        // Force at least one sub-node by inserting > BUCKET_SIZE entries at
        // a single top-5-bit position. Approximate via many keys.
        let mut bindings = BTreeMap::new();
        for i in 0..40u8 {
            bindings.insert(format!("k{}", i), make_hash(i));
        }
        let root = build_trie(&store, &bindings).unwrap();

        let mut seen = std::collections::HashSet::new();
        collect_reachable_hashes(&store, root, &mut seen);

        // Must include the root, every value hash, and any sub-node hash.
        assert!(seen.contains(&root));
        for i in 0..40u8 {
            assert!(seen.contains(&make_hash(i)), "missing value hash {}", i);
        }
    }

    // ----- Utility -----

    #[test]
    fn test_sorted_parents() {
        let h1 = make_hash(5);
        let h2 = make_hash(2);
        let h3 = make_hash(8);
        let mut parents = vec![h1, h2, h3];
        sorted_parents(&mut parents);
        assert_eq!(parents, vec![h2, h1, h3]);
    }

    #[test]
    fn test_join_path() {
        assert_eq!(join_path("", "b"), "b");
        assert_eq!(join_path("a", ""), "a");
        assert_eq!(join_path("a", "b"), "a/b");
        assert_eq!(join_path("", ""), "");
    }
}
