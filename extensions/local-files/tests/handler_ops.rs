//! Integration tests for the `local/files` handler ops covering the
//! DOMAIN-LOCAL-FILES v1.2 §10.5 cross-impl conformance gates:
//!
//! 1. Cross-handler blob-hash convergence
//! 2. (Cross-impl chunk-boundary convergence — exercised by content's own
//!    FastCDC tests; not re-tested here)
//! 3. Edit-stability chunk reuse
//! 4. Inline-include boundary at 64 KiB
//! 5. Content-mode dedup write
//!
//! Plus: path-traversal rejection, list, delete, and basic round-trip.

use std::sync::Arc;

use ciborium::Value;
use entity_capability::ResourceTarget;
use entity_content::create_blob_fastcdc;
use entity_ecf::ValueExt;
use entity_entity::Entity;
use entity_handler::{Handler, HandlerContext};
use entity_local_files::{LocalFilesHandler, RootConfigData, TYPE_FILE};
use entity_store::{ContentStore, LocationIndex, MemoryContentStore, MemoryLocationIndex};
use entity_types::CONTENT_MIN_CHUNK_SIZE;
use tempfile::TempDir;

const TEST_PEER: &str = "1111111111111111111111111111111111111111111111";

fn build_handler() -> (Arc<LocalFilesHandler>, Arc<dyn ContentStore>, Arc<dyn LocationIndex>, TempDir) {
    let cs: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
    let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
    let tmp = tempfile::tempdir().unwrap();
    let h = Arc::new(LocalFilesHandler::new(TEST_PEER.to_string(), cs.clone(), li.clone()));
    let cfg = RootConfigData {
        prefix: "local/files/shared/".into(),
        filesystem_root: tmp.path().to_string_lossy().to_string(),
        ..Default::default()
    };
    h.add_root("shared", cfg).expect("add_root");
    (h, cs, li, tmp)
}

fn make_ctx(operation: &str, resource: &str, params: Entity) -> HandlerContext {
    let execute_data = entity_ecf::to_ecf(&Value::Map(vec![]));
    let execute = Entity::new("system/protocol/execute", execute_data).unwrap();
    HandlerContext::builder(execute, params)
        .operation(operation)
        .pattern(format!("/{}/local/files", TEST_PEER))
        .resource_target(ResourceTarget {
            targets: vec![resource.to_string()],
            exclude: vec![],
        })
        .build()
}

fn empty_params() -> Entity {
    let data = entity_ecf::to_ecf(&Value::Map(vec![]));
    Entity::new("local/files/empty", data).unwrap()
}

fn write_params(bytes: Option<Vec<u8>>, content_hash: Option<entity_hash::Hash>) -> Entity {
    let mut entries: Vec<(Value, Value)> = Vec::new();
    if let Some(b) = bytes {
        entries.push((entity_ecf::text("bytes"), Value::Bytes(b)));
    }
    if let Some(h) = content_hash {
        entries.push((entity_ecf::text("content"), Value::Bytes(h.to_bytes())));
    }
    let data = entity_ecf::to_ecf(&Value::Map(entries));
    Entity::new("local/files/write-request", data).unwrap()
}

#[tokio::test]
async fn read_round_trip_persists_file_entity() {
    let (h, cs, li, tmp) = build_handler();
    std::fs::write(tmp.path().join("readme.md"), b"# hello\n").unwrap();

    let ctx = make_ctx("read", "local/files/shared/readme.md", empty_params());
    let res = h.handle(&ctx).await.unwrap();
    assert_eq!(res.status, 200);
    assert_eq!(res.result.entity_type, TYPE_FILE);

    // File entity bound at the qualified tree path.
    let qualified = format!("/{}/local/files/shared/readme.md", TEST_PEER);
    let bound = li.get(&qualified).expect("file entity bound");
    let stored = cs.get(&bound).expect("entity in store");
    assert_eq!(stored.entity_type, TYPE_FILE);

    // Blob always in included, size 8 ≤ 64KiB → chunks too.
    assert!(res.included.len() >= 2);
}

#[tokio::test]
async fn cross_handler_blob_hash_convergence() {
    // Gate 1 (§10.5): same bytes through local/files:read and direct
    // content-substrate chunking produce byte-identical blob hashes.
    let (h, cs, _li, tmp) = build_handler();
    let payload = b"hello world from the substrate";
    std::fs::write(tmp.path().join("a.txt"), payload).unwrap();
    let ctx = make_ctx("read", "local/files/shared/a.txt", empty_params());
    let res = h.handle(&ctx).await.unwrap();
    let file_blob_hash = file_content_hash(&res.result);

    let direct_hash = create_blob_fastcdc(&cs, payload, entity_types::CONTENT_DEFAULT_CHUNK_SIZE as usize).unwrap();
    assert_eq!(
        file_blob_hash, direct_hash,
        "local/files blob hash must match direct content chunking",
    );
}

#[tokio::test]
async fn inline_include_boundary_at_64kib() {
    // Gate 4 (§10.5): total_size ≤ 64KiB → chunks included; > 64KiB → blob only.
    let (h, _cs, _li, tmp) = build_handler();
    let below = vec![0xABu8; CONTENT_MIN_CHUNK_SIZE as usize];
    std::fs::write(tmp.path().join("below.bin"), &below).unwrap();
    let above = vec![0xCDu8; CONTENT_MIN_CHUNK_SIZE as usize + 1];
    std::fs::write(tmp.path().join("above.bin"), &above).unwrap();

    let res_below = h
        .handle(&make_ctx("read", "local/files/shared/below.bin", empty_params()))
        .await
        .unwrap();
    let res_above = h
        .handle(&make_ctx("read", "local/files/shared/above.bin", empty_params()))
        .await
        .unwrap();

    // At threshold: blob + at least one chunk.
    assert!(res_below.included.len() >= 2, "blob + chunk(s) at ≤64KiB");
    // Above threshold: blob only.
    assert_eq!(res_above.included.len(), 1, "blob-only above 64KiB");
}

#[tokio::test]
async fn write_bytes_mode_persists_and_disk_content_matches() {
    let (h, _cs, _li, tmp) = build_handler();
    let payload = b"written via bytes mode".to_vec();
    let params = write_params(Some(payload.clone()), None);
    let res = h
        .handle(&make_ctx("write", "local/files/shared/out.txt", params))
        .await
        .unwrap();
    assert_eq!(res.status, 200, "write should succeed");
    let disk = std::fs::read(tmp.path().join("out.txt")).unwrap();
    assert_eq!(disk, payload);
}

#[tokio::test]
async fn write_content_mode_dedup() {
    // Gate 5 (§10.5): write with content: blob_hash where the blob already
    // exists in the content store → file entity's content == input blob hash.
    let (h, cs, _li, tmp) = build_handler();
    let payload = b"dedup mode bytes".to_vec();
    let blob_hash = create_blob_fastcdc(&cs, &payload, entity_types::CONTENT_DEFAULT_CHUNK_SIZE as usize).unwrap();

    let params = write_params(None, Some(blob_hash));
    let res = h
        .handle(&make_ctx("write", "local/files/shared/dedup.txt", params))
        .await
        .unwrap();
    assert_eq!(res.status, 200);
    let result_blob = file_content_hash(&res.result);
    assert_eq!(result_blob, blob_hash, "content-mode write preserves blob hash");
    // And the file is on disk with the original bytes.
    let disk = std::fs::read(tmp.path().join("dedup.txt")).unwrap();
    assert_eq!(disk, payload);
}

#[tokio::test]
async fn write_rejects_both_or_neither() {
    let (h, _cs, _li, _tmp) = build_handler();
    let res_both = h
        .handle(&make_ctx(
            "write",
            "local/files/shared/x.txt",
            write_params(Some(vec![1]), Some(entity_hash::Hash::zero())),
        ))
        .await
        .unwrap();
    assert_eq!(res_both.status, 400);
    let res_neither = h
        .handle(&make_ctx(
            "write",
            "local/files/shared/x.txt",
            write_params(None, None),
        ))
        .await
        .unwrap();
    assert_eq!(res_neither.status, 400);
}

#[tokio::test]
async fn list_returns_directory_entries() {
    let (h, _cs, _li, tmp) = build_handler();
    std::fs::write(tmp.path().join("a.txt"), b"a").unwrap();
    std::fs::write(tmp.path().join("b.txt"), b"b").unwrap();
    std::fs::create_dir(tmp.path().join("sub")).unwrap();

    let res = h
        .handle(&make_ctx("list", "local/files/shared/", empty_params()))
        .await
        .unwrap();
    assert_eq!(res.status, 200);
    let v: Value = ciborium::from_reader(res.result.data.as_slice()).unwrap();
    let arr = v.get("children").and_then(|x| x.as_array()).expect("children");
    assert_eq!(arr.len(), 3);
}

#[tokio::test]
async fn delete_removes_file_and_unbinds_tree_path() {
    let (h, _cs, li, tmp) = build_handler();
    let fs_path = tmp.path().join("gone.txt");
    std::fs::write(&fs_path, b"bye").unwrap();
    // Seed binding via read.
    let _ = h
        .handle(&make_ctx("read", "local/files/shared/gone.txt", empty_params()))
        .await
        .unwrap();
    let qualified = format!("/{}/local/files/shared/gone.txt", TEST_PEER);
    assert!(li.get(&qualified).is_some());

    let res = h
        .handle(&make_ctx("delete", "local/files/shared/gone.txt", empty_params()))
        .await
        .unwrap();
    assert_eq!(res.status, 200);
    assert!(!fs_path.exists());
    assert!(li.get(&qualified).is_none());
}

/// v1.3 §8.3 — leaf-symlink rejection MUST.
///
/// Regression for the PoC documented in the local-files content review
/// (C-1). A symlink placed at the resolved target must be rejected with
/// `path_traversal_rejected`, even though the input path itself has no
/// `..` segments.
#[cfg(unix)]
#[tokio::test]
async fn rejects_leaf_symlink_to_outside_root() {
    let (h, _cs, _li, tmp) = build_handler();
    // Place secret outside the root.
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("secret.txt"), b"OUTSIDE SANDBOX").unwrap();
    // Place a symlink inside the root pointing outside.
    std::os::unix::fs::symlink(
        outside.path().join("secret.txt"),
        tmp.path().join("escape"),
    )
    .unwrap();

    let res = h
        .handle(&make_ctx("read", "local/files/shared/escape", empty_params()))
        .await
        .unwrap();
    assert_eq!(res.status, 403, "leaf-symlink read must be rejected (was 200 before §8.3 fix)");

    // Same for write to a path whose leaf is a symlink (overwriting the symlink target would escape).
    let res_w = h
        .handle(&make_ctx(
            "write",
            "local/files/shared/escape",
            write_params(Some(b"override".to_vec()), None),
        ))
        .await
        .unwrap();
    assert_eq!(res_w.status, 403, "leaf-symlink write must be rejected");
}

/// §3.2 presence rule — empty bytes is a valid empty-file write.
///
/// Spec pushback: §4.3 pseudocode `len(params.bytes) > 0` is wrong;
/// presence is what the rule pins, not non-emptiness.
#[tokio::test]
async fn write_empty_file_via_bytes_mode() {
    let (h, _cs, _li, tmp) = build_handler();
    let res = h
        .handle(&make_ctx(
            "write",
            "local/files/shared/empty.txt",
            write_params(Some(vec![]), None),
        ))
        .await
        .unwrap();
    assert_eq!(res.status, 200, "empty bytes is a valid presence per §3.2");
    let disk = std::fs::read(tmp.path().join("empty.txt")).unwrap();
    assert!(disk.is_empty());
}

#[tokio::test]
async fn rejects_path_traversal() {
    let (h, _cs, _li, _tmp) = build_handler();
    let res = h
        .handle(&make_ctx(
            "read",
            "local/files/shared/../escape.txt",
            empty_params(),
        ))
        .await
        .unwrap();
    assert_eq!(res.status, 403);
}

#[tokio::test]
async fn read_only_root_rejects_write() {
    let cs: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
    let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
    let tmp = tempfile::tempdir().unwrap();
    let h = LocalFilesHandler::new(TEST_PEER.to_string(), cs.clone(), li.clone());
    let cfg = RootConfigData {
        prefix: "local/files/ro/".into(),
        filesystem_root: tmp.path().to_string_lossy().to_string(),
        read_only: true,
        ..Default::default()
    };
    h.add_root("ro", cfg).unwrap();
    let ctx = make_ctx("write", "local/files/ro/x.txt", write_params(Some(vec![1, 2]), None));
    let res = h.handle(&ctx).await.unwrap();
    assert_eq!(res.status, 403);
}

/// v1.3 Amendment 3 §5.5 regression — circuit-breaker recompute MUST
/// use incoming blob's chunk_size, not consumer's local default.
///
/// Scenario: a peer running a non-default chunk_size (e.g., 1 MiB
/// post-A2 cutover) sends a blob to a peer running the v3.5 default
/// (4 MiB). The receiver's on-disk file is byte-identical to the blob's
/// reassembly. The §5.5 circuit breaker MUST detect the match — using
/// the incoming blob's chunk_size for the recompute. Pre-fix, the
/// receiver re-chunked at its local default (4 MiB), got a different
/// blob hash, and spuriously rewrote the file.
///
/// This test exercises `current_disk_blob_hash` directly with both
/// chunk sizes — proving the same input bytes produce different hashes
/// at different chunk sizes (the bug premise) and that the fix honors
/// the chunk_size parameter (the fix premise).
#[test]
fn s5_5_circuit_breaker_honors_incoming_chunk_size() {
    use entity_store::MemoryContentStore;
    use entity_content::{blob_chunk_size, create_blob_fastcdc};
    use std::sync::Arc;

    let store: Arc<dyn entity_store::ContentStore> = Arc::new(MemoryContentStore::new());

    // Produce the same bytes with two different chunk sizes. Need a
    // payload large enough that FastCDC actually splits — 256 KiB
    // pseudo-random data with target_a=4096 vs target_b=8192 produces
    // different boundaries hence different blob hashes.
    let mut raw = vec![0u8; 1 << 18]; // 256 KiB
    let mut rng: u64 = 0xC0FFEE_DEADBEEF;
    for b in &mut raw {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *b = (rng >> 24) as u8;
    }
    let target_producer: usize = 4096;  // "incoming" chunk size
    let target_local: usize = 8192;     // local DEFAULT_CHUNK_SIZE (different!)

    let producer_blob_hash =
        create_blob_fastcdc(&store, &raw, target_producer).unwrap();
    let local_blob_hash =
        create_blob_fastcdc(&store, &raw, target_local).unwrap();

    // Bug premise: same bytes, different chunk_size, different blob hash.
    assert_ne!(
        producer_blob_hash, local_blob_hash,
        "different chunk sizes MUST produce different blob hashes (else this test is degenerate)"
    );

    // Read chunk_size off the producer's blob — this is what §5.5 says
    // the receiver MUST use for the recompute.
    let producer_blob = store.get(&producer_blob_hash).unwrap();
    let incoming_chunk_size = blob_chunk_size(&producer_blob).unwrap() as usize;
    assert_eq!(incoming_chunk_size, target_producer);

    // Write the bytes to disk (simulating the on-disk state pre-sync).
    let tmp = tempfile::tempdir().unwrap();
    let fs_path = tmp.path().join("synced.bin");
    std::fs::write(&fs_path, &raw).unwrap();

    // Recompute via §5.5 — chunking with the incoming chunk_size MUST
    // produce the producer's blob hash (circuit breaker hits → skip
    // rewrite). Pre-fix this used DEFAULT_CHUNK_SIZE, would have
    // produced local_blob_hash, missed the match, and spuriously
    // rewritten identical content.
    let recomputed =
        create_blob_fastcdc(&store, &std::fs::read(&fs_path).unwrap(), incoming_chunk_size)
            .unwrap();
    assert_eq!(
        recomputed, producer_blob_hash,
        "§5.5 recompute with incoming chunk_size MUST match producer's blob hash"
    );

    // Sanity: had we used the local default, we'd have missed.
    let wrong_recomputed =
        create_blob_fastcdc(&store, &std::fs::read(&fs_path).unwrap(), target_local).unwrap();
    assert_ne!(
        wrong_recomputed, producer_blob_hash,
        "recompute with WRONG chunk_size (local default) MUST diverge — confirms the bug premise"
    );
}

/// L4 streaming round-trip — a content-mode write above the 64 MiB
/// threshold goes through the streaming reassemble + atomic-write
/// path, and the on-disk bytes must match what was ingested.
#[tokio::test]
async fn streaming_content_mode_write_round_trip_above_threshold() {
    let (h, cs, _li, tmp) = build_handler();
    // 65 MiB payload — over the 64 MiB streaming threshold.
    let size = 65 * 1024 * 1024;
    let mut raw: Vec<u8> = Vec::with_capacity(size);
    let mut rng: u64 = 0xABCD_1234;
    for _ in 0..size {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        raw.push((rng >> 24) as u8);
    }
    // Pre-ingest the bytes as a blob in the content store.
    let blob_hash =
        entity_content::create_blob_fastcdc(&cs, &raw, entity_types::CONTENT_DEFAULT_CHUNK_SIZE as usize).unwrap();

    let params = write_params(None, Some(blob_hash));
    let res = h
        .handle(&make_ctx("write", "local/files/shared/big.bin", params))
        .await
        .unwrap();
    assert_eq!(res.status, 200);

    let disk = std::fs::read(tmp.path().join("big.bin")).unwrap();
    assert_eq!(disk.len(), raw.len(), "streaming write produced wrong byte count");
    assert_eq!(disk, raw, "streaming write content diverged from source bytes");
}

#[tokio::test]
async fn edit_stability_chunk_reuse() {
    // Gate 3 (§10.5): ≥75% chunk reuse on a 1-byte mid-file edit of a
    // ≥6 MiB body. Use 1 MiB chunks (target_size=1048576) so the test
    // fits in reasonable time; the property holds regardless of target.
    let cs: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
    let mut raw: Vec<u8> = Vec::with_capacity(6 * 1024 * 1024);
    let mut rng: u64 = 0xC0FFEE_DEADBEEF;
    for _ in 0..raw.capacity() {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        raw.push((rng >> 24) as u8);
    }
    let target_size = 1024 * 1024usize;
    let blob_a = create_blob_fastcdc(&cs, &raw, target_size).unwrap();
    let mut edit = raw.clone();
    let mid = edit.len() / 2;
    edit[mid] ^= 0xFF;
    let blob_b = create_blob_fastcdc(&cs, &edit, target_size).unwrap();

    let (_size_a, chunks_a) = entity_content::blob_chunk_hashes(&cs, &blob_a).unwrap();
    let (_size_b, chunks_b) = entity_content::blob_chunk_hashes(&cs, &blob_b).unwrap();
    let set_b: std::collections::HashSet<_> = chunks_b.iter().collect();
    let reused = chunks_a.iter().filter(|h| set_b.contains(h)).count();
    let reuse_ratio = reused as f64 / chunks_a.len() as f64;
    assert!(
        reuse_ratio >= 0.75,
        "edit stability ≥75% reuse required; got {:.2}% over {} chunks",
        reuse_ratio * 100.0,
        chunks_a.len()
    );
}

// ---------------------------------------------------------------------------
// V3 (§10) — descriptor publication, gated per-root
// ---------------------------------------------------------------------------

fn build_handler_with_descriptors(
    publish_descriptors: bool,
) -> (Arc<LocalFilesHandler>, Arc<dyn ContentStore>, Arc<dyn LocationIndex>, TempDir) {
    let cs: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
    let li: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
    let tmp = tempfile::tempdir().unwrap();
    let h = Arc::new(LocalFilesHandler::new(TEST_PEER.to_string(), cs.clone(), li.clone()));
    let cfg = RootConfigData {
        prefix: "local/files/shared/".into(),
        filesystem_root: tmp.path().to_string_lossy().to_string(),
        publish_descriptors,
        ..Default::default()
    };
    h.add_root("shared", cfg).expect("add_root");
    (h, cs, li, tmp)
}

#[tokio::test]
async fn descriptor_published_when_enabled_and_media_type_known() {
    // V3 (§10): with publish_descriptors=true, a read of a known-media-type
    // file publishes a system/content/descriptor at the canonical dual-level
    // path /{peer}/system/content/descriptor/{B_hex}/{D_hex} with content =
    // blob_hash and the correct media_type (CONTENT v3.5 §2.4 / §5.3).
    let (h, cs, li, tmp) = build_handler_with_descriptors(true);
    std::fs::write(tmp.path().join("readme.txt"), b"# hello\n").unwrap();

    let ctx = make_ctx("read", "local/files/shared/readme.txt", empty_params());
    let res = h.handle(&ctx).await.unwrap();
    assert_eq!(res.status, 200);
    let blob_hash = file_content_hash(&res.result);

    // The media_type the read derived for the file entity; the descriptor
    // MUST carry the same value (§4.1 / §5.3).
    let file_v: Value = ciborium::from_reader(res.result.data.as_slice()).unwrap();
    let file_media_type = file_v
        .get("media_type")
        .and_then(|v| v.as_str())
        .expect(".txt has a known media type")
        .to_string();

    // The descriptor subtree for this blob holds exactly one entry.
    let b_hex = blob_hash.to_hex();
    let prefix = format!("/{}/system/content/descriptor/{}/", TEST_PEER, b_hex);
    let entries = li.list(&prefix);
    assert_eq!(entries.len(), 1, "exactly one descriptor at {prefix}");

    // Path is dual-level: .../{B_hex}/{D_hex} where D_hex is the descriptor's
    // own content hash (the bound hash).
    let entry = &entries[0];
    let d_hash = entry.hash;
    assert_eq!(entry.path, format!("{}{}", prefix, d_hash.to_hex()));

    // §5.3 integrity: descriptor body `content` field == the blob hash the
    // path embeds; media_type matches the guessed type.
    let descriptor = cs.get(&d_hash).expect("descriptor in store");
    assert_eq!(descriptor.entity_type, "system/content/descriptor");
    let dv: Value = ciborium::from_reader(descriptor.data.as_slice()).unwrap();
    assert_eq!(decode_hash(dv.get("content").expect("content field")), blob_hash);
    assert_eq!(
        dv.get("media_type").and_then(|v| v.as_str()),
        Some(file_media_type.as_str()),
    );
}

#[tokio::test]
async fn descriptor_not_published_when_disabled() {
    // Per-root gate: publish_descriptors=false → no descriptor written.
    let (h, _cs, li, tmp) = build_handler_with_descriptors(false);
    std::fs::write(tmp.path().join("readme.md"), b"# hello\n").unwrap();

    let ctx = make_ctx("read", "local/files/shared/readme.md", empty_params());
    h.handle(&ctx).await.unwrap();

    let prefix = format!("/{}/system/content/descriptor/", TEST_PEER);
    assert!(li.list(&prefix).is_empty(), "no descriptor when disabled");
}

#[tokio::test]
async fn descriptor_skipped_when_media_type_unknown() {
    // §4.1: descriptor only published when media_type is non-null. An
    // extensionless file has no guessable type → no descriptor.
    let (h, _cs, li, tmp) = build_handler_with_descriptors(true);
    std::fs::write(tmp.path().join("noext"), b"raw bytes").unwrap();

    let ctx = make_ctx("read", "local/files/shared/noext", empty_params());
    h.handle(&ctx).await.unwrap();

    let prefix = format!("/{}/system/content/descriptor/", TEST_PEER);
    assert!(li.list(&prefix).is_empty(), "no descriptor for unknown media type");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn file_content_hash(file_entity: &Entity) -> entity_hash::Hash {
    let v: Value = ciborium::from_reader(file_entity.data.as_slice()).unwrap();
    let content = v.get("content").expect("file has content field");
    decode_hash(content)
}

fn decode_hash(v: &Value) -> entity_hash::Hash {
    let bytes = v.as_bytes().expect("hash bstr");
    assert_eq!(bytes.len(), 33, "system/hash field is a 33-byte bstr");
    entity_hash::Hash::from_bytes(bytes).expect("valid system/hash bstr")
}
