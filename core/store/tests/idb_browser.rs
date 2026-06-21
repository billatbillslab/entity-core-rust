//! Real-browser tests for the IndexedDB backend (`wasm-idb-persist`).
//!
//! These CANNOT run on native or in a non-browser WASM context — they need a
//! live IndexedDB. Run with a browser-driving harness, e.g.:
//!
//! ```text
//! wasm-pack test --headless --firefox \
//!     core/store --features wasm-idb-persist --test idb_browser
//! ```
//!
//! (or `--chrome`). Native `cargo test` skips this file entirely — the
//! `#![cfg(...)]` gate compiles it to nothing off-target.
//!
//! Covers the three properties the egui Engine-Proof Gate blocks on:
//! 1. round-trip / survives-reopen,
//! 2. crash-window (only the unflushed writes are lost),
//! 3. checkpoint durability (a checkpointed write survives an immediate reopen,
//!    no debounce elapsed),
//! plus CAS-against-mirror correctness and burst coalescing.

#![cfg(all(target_arch = "wasm32", feature = "wasm-idb-persist"))]

use entity_entity::Entity;
use entity_hash::Hash;
use entity_store::idb::IdbStore;
use entity_store::{ContentStore, LocationIndex};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

// Distinct DB name per test so runs don't contaminate each other. (IndexedDB
// persists across a test session.)
fn db_name(test: &str) -> String {
    format!("entity-idb-test-{test}")
}

fn entity(label: &str) -> Entity {
    Entity::new("test/type", entity_ecf::to_ecf(&entity_ecf::text(label))).unwrap()
}

const PEER: &str = "testPeerAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn path(suffix: &str) -> String {
    format!("/{PEER}/{suffix}")
}

/// 1. Round-trip / survives-reopen: write a spread → checkpoint → drop →
///    reopen the same DB → the mirror replays and every read matches.
#[wasm_bindgen_test]
async fn round_trip_survives_reopen() {
    let name = db_name("round-trip");
    // Fresh start: delete any residue from a prior run by writing a known set.
    let store = IdbStore::open(&name).await.expect("open");
    let cp = store.checkpoint();
    let (cs, li) = store.into_parts();

    let mut hashes = Vec::new();
    for i in 0..16 {
        let e = entity(&format!("entity-{i}"));
        let h = cs.put(e).unwrap();
        li.set(&path(&format!("e/{i}")), h);
        hashes.push(h);
    }
    cp.checkpoint().await.expect("checkpoint");

    // Drop the runtime stores; reopen a fresh handle on the same DB.
    drop(cs);
    drop(li);
    drop(cp);

    let store2 = IdbStore::open(&name).await.expect("reopen");
    let (cs2, li2) = store2.into_parts();
    for (i, h) in hashes.iter().enumerate() {
        let got = cs2.get(h).expect("entity replayed");
        assert_eq!(
            got.data,
            entity(&format!("entity-{i}")).data,
            "entity {i} byte-identical after reopen"
        );
        assert_eq!(
            li2.get(&path(&format!("e/{i}"))),
            Some(*h),
            "location {i} replayed"
        );
    }
}

/// 2. Crash-window: enqueue writes, do NOT checkpoint, and read durable state
///    through a second connection BEFORE the debounce fires → the unflushed
///    writes are the only thing missing, nothing is corrupted. This proves the
///    loss boundary is exactly the unflushed window (an abrupt page kill stops
///    all JS, so the debounce timer never fires — the same state a second
///    connection observes here).
#[wasm_bindgen_test]
async fn crash_window_loses_only_unflushed() {
    let name = db_name("crash-window");

    // Phase 1: a durable, checkpointed baseline.
    let store = IdbStore::open(&name).await.expect("open");
    let cp = store.checkpoint();
    let (cs, li) = store.into_parts();
    let durable = cs.put(entity("durable")).unwrap();
    li.set(&path("durable"), durable);
    cp.checkpoint().await.expect("checkpoint baseline");

    // Phase 2: enqueue more writes but DO NOT checkpoint and DO NOT await the
    // debounce. These are the "in the unflushed window" writes.
    let volatile = cs.put(entity("volatile")).unwrap();
    li.set(&path("volatile"), volatile);
    assert!(cp.health().pending_count > 0, "writes are pending, not durable");

    // Observe durable state via a second connection, immediately (no 250ms wait).
    let store2 = IdbStore::open(&name).await.expect("reopen");
    let (cs2, li2) = store2.into_parts();
    assert!(cs2.has(&durable), "checkpointed entity survived");
    assert_eq!(li2.get(&path("durable")), Some(durable), "checkpointed binding survived");
    assert!(!cs2.has(&volatile), "unflushed entity is the only loss");
    assert_eq!(li2.get(&path("volatile")), None, "unflushed binding is the only loss");
}

/// 3. Checkpoint durability: put → checkpoint().await → immediate reopen (no
///    debounce elapsed) → the write IS present. This is the property
///    delete-correctness rides on: identity-op durability does not depend on the
///    debounce timer.
#[wasm_bindgen_test]
async fn checkpoint_makes_write_durable_without_debounce() {
    let name = db_name("checkpoint");
    let store = IdbStore::open(&name).await.expect("open");
    let cp = store.checkpoint();
    let (cs, li) = store.into_parts();

    let h = cs.put(entity("identity-op")).unwrap();
    li.set(&path("identity"), h);
    cp.checkpoint().await.expect("checkpoint");
    assert_eq!(cp.health().pending_count, 0, "nothing pending after checkpoint");

    // Immediate reopen — far less than the 250ms debounce.
    let store2 = IdbStore::open(&name).await.expect("reopen");
    let (cs2, li2) = store2.into_parts();
    assert!(cs2.has(&h), "checkpointed write durable without waiting for debounce");
    assert_eq!(li2.get(&path("identity")), Some(h));
}

/// Delete durability (the BUG-A shape): a checkpointed delete must NOT come back
/// on reopen.
#[wasm_bindgen_test]
async fn checkpointed_delete_stays_deleted() {
    let name = db_name("delete");
    let store = IdbStore::open(&name).await.expect("open");
    let cp = store.checkpoint();
    let (cs, li) = store.into_parts();

    let h = cs.put(entity("doomed")).unwrap();
    li.set(&path("doomed"), h);
    cp.checkpoint().await.expect("checkpoint create");

    // Delete + checkpoint (the delete-peer discipline).
    assert!(cs.remove(&h));
    assert_eq!(li.remove(&path("doomed")), Some(h));
    cp.checkpoint().await.expect("checkpoint delete");

    let store2 = IdbStore::open(&name).await.expect("reopen");
    let (cs2, li2) = store2.into_parts();
    assert!(!cs2.has(&h), "deleted entity does not resurrect");
    assert_eq!(li2.get(&path("doomed")), None, "deleted binding does not resurrect");
}

/// CAS resolves against the sync mirror and the resulting binding is durable.
#[wasm_bindgen_test]
async fn cas_against_mirror_then_durable() {
    let name = db_name("cas");
    let store = IdbStore::open(&name).await.expect("open");
    let cp = store.checkpoint();
    let (cs, li) = store.into_parts();

    let h1 = cs.put(entity("v1")).unwrap();
    let h2 = cs.put(entity("v2")).unwrap();
    let p = path("cas");

    // create
    li.compare_and_create(&p, h1).expect("create on empty");
    assert!(li.compare_and_create(&p, h2).is_err(), "create on occupied fails");
    // swap with wrong expected
    assert!(li.compare_and_swap(&p, h2, h1).is_err(), "swap mismatch fails");
    // swap with right expected
    li.compare_and_swap(&p, h1, h2).expect("swap match");
    cp.checkpoint().await.expect("checkpoint");

    let store2 = IdbStore::open(&name).await.expect("reopen");
    let (_cs2, li2) = store2.into_parts();
    assert_eq!(li2.get(&p), Some(h2), "final CAS value durable");
}

/// Burst coalescing: many same-key writes collapse to the final value. Observed
/// property: after a burst + checkpoint, the reopened store has exactly one
/// entry for the path and it holds the last write (last-write-wins).
#[wasm_bindgen_test]
async fn burst_coalesces_to_last_write() {
    let name = db_name("coalesce");
    let store = IdbStore::open(&name).await.expect("open");
    let cp = store.checkpoint();
    let (cs, li) = store.into_parts();

    let p = path("hot");
    let mut last = Hash::zero();
    for i in 0..50 {
        let h = cs.put(entity(&format!("rev-{i}"))).unwrap();
        li.set(&p, h);
        last = h;
    }
    cp.checkpoint().await.expect("checkpoint");

    let store2 = IdbStore::open(&name).await.expect("reopen");
    let (_cs2, li2) = store2.into_parts();
    assert_eq!(li2.get(&p), Some(last), "coalesced to last write");
    assert_eq!(li2.len_prefix(&path("hot")), 1, "exactly one binding for the hot path");
}
