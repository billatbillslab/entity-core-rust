//! Fixed-size and FastCDC chunkers (EXTENSION-CONTENT §3.2 + §3.6).
//!
//! Both algorithms produce identical entity shapes:
//!
//! - Chunks: `system/content/chunk` with a single `payload: bytes` field.
//! - Blob:   `system/content/blob` with `total_size`, `chunk_size`,
//!   `chunking`, `chunks: [system/hash]`.
//!
//! The `chunking` discriminator is `0` for fixed-size and `1` for
//! FastCDC/NC2 — the §2.1 standardized identifiers. Two implementations
//! using the same algorithm + chunk size produce byte-identical chunks
//! and the same blob hash; this is the cross-impl conformance gate
//! (§3.7 — Conformance classification).

use std::sync::Arc;

use entity_entity::Entity;
use entity_hash::Hash;
use entity_store::{ContentStore, StoreError};
use entity_types::{
    CONTENT_CHUNKING_FASTCDC, CONTENT_CHUNKING_FIXED, TYPE_CONTENT_BLOB, TYPE_CONTENT_CHUNK,
};
use thiserror::Error;

use crate::fastcdc::{find_boundary, CdcParams};

#[derive(Debug, Error)]
pub enum ChunkerError {
    #[error("invalid parameter: {0}")]
    Invalid(&'static str),
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("entity construction failed: {0}")]
    Entity(String),
}

/// Fixed-size chunker (§3.2). Splits `raw` at every `chunk_size` bytes
/// and writes chunk + blob entities into `store`. Returns the blob hash.
///
/// `chunk_size` MUST be > 0. The final chunk MAY be smaller than
/// `chunk_size`; that's the only exception to §10.1's `MIN_CHUNK_SIZE`
/// rule (final-chunk exception).
pub fn create_blob_fixed(
    store: &Arc<dyn ContentStore>,
    raw: &[u8],
    chunk_size: usize,
) -> Result<Hash, ChunkerError> {
    if chunk_size == 0 {
        return Err(ChunkerError::Invalid("chunk_size must be > 0"));
    }
    let mut chunks: Vec<Hash> = Vec::new();
    let mut offset = 0;
    while offset < raw.len() {
        let end = (offset + chunk_size).min(raw.len());
        let chunk_hash = put_chunk(store, &raw[offset..end])?;
        chunks.push(chunk_hash);
        offset = end;
    }
    put_blob(store, raw.len() as u64, chunk_size as u64, CONTENT_CHUNKING_FIXED, &chunks)
}

/// FastCDC/NC2 chunker (§3.6). Derives params from `target_size` via
/// §3.6.2, finds content-defined boundaries via §3.6.3, writes chunks
/// and the manifest blob. Returns the blob hash.
///
/// `target_size` MUST be > 0.
pub fn create_blob_fastcdc(
    store: &Arc<dyn ContentStore>,
    raw: &[u8],
    target_size: usize,
) -> Result<Hash, ChunkerError> {
    let params = CdcParams::from_target(target_size).map_err(ChunkerError::Invalid)?;
    let mut chunks: Vec<Hash> = Vec::new();
    let mut offset = 0;
    while offset < raw.len() {
        let remaining = raw.len() - offset;
        let end = if remaining <= params.min_size {
            // Final piece: too small to split further.
            offset + remaining
        } else {
            find_boundary(raw, offset, &params)
        };
        let chunk_hash = put_chunk(store, &raw[offset..end])?;
        chunks.push(chunk_hash);
        offset = end;
    }
    put_blob(
        store,
        raw.len() as u64,
        target_size as u64,
        CONTENT_CHUNKING_FASTCDC,
        &chunks,
    )
}

/// Streaming FastCDC/NC2 chunker (§3.6 + DOMAIN-LOCAL-FILES v1.3 §4.3 L4 SHOULD).
///
/// Reads from `reader` in `max_size`-sized windows, emits chunks to
/// `store` as they're found. **Produces byte-identical chunk boundaries
/// as `create_blob_fastcdc` on the same input** (cross-impl gate
/// CONTENT v3.5 §3.6.5) — uses the same `find_boundary` function over
/// the same gear-table fingerprint.
///
/// Steady-state memory: `max_size` bytes (2 MiB for the v3.6 1 MiB default
/// target). A 10 GB file streams through this with constant ~8 MiB
/// resident, vs the buffered variant's 10 GB. Closes the C-3 OOM hole
/// while preserving the cross-impl wire shape.
///
/// `target_size` MUST be > 0.
pub fn create_blob_fastcdc_stream<R: std::io::Read>(
    store: &Arc<dyn ContentStore>,
    mut reader: R,
    target_size: usize,
) -> Result<Hash, ChunkerError> {
    let params = CdcParams::from_target(target_size).map_err(ChunkerError::Invalid)?;
    let mut buf: Vec<u8> = Vec::with_capacity(params.max_size);
    let mut chunks: Vec<Hash> = Vec::new();
    let mut total_size: u64 = 0;
    let mut eof = false;

    while !eof || !buf.is_empty() {
        // Fill the buffer up to max_size.
        if !eof && buf.len() < params.max_size {
            let want = params.max_size - buf.len();
            buf.resize(buf.len() + want, 0);
            let head = buf.len() - want;
            let mut filled = 0;
            while filled < want {
                match reader.read(&mut buf[head + filled..]) {
                    Ok(0) => {
                        eof = true;
                        break;
                    }
                    Ok(n) => filled += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(ChunkerError::Entity(format!("read: {e}"))),
                }
            }
            // Truncate any unread tail.
            buf.truncate(head + filled);
        }

        if buf.is_empty() {
            break;
        }

        // Find the next boundary within the current window. Treat
        // offset=0 (we slid the buffer); find_boundary returns an
        // absolute index into `buf`.
        let end = if buf.len() <= params.min_size {
            // Final piece: emit as-is.
            buf.len()
        } else {
            find_boundary(&buf, 0, &params)
        };

        let chunk_hash = put_chunk(store, &buf[..end])?;
        chunks.push(chunk_hash);
        total_size += end as u64;
        buf.drain(..end);

        // If we hit EOF and the buffer is drained, we're done.
        if eof && buf.is_empty() {
            break;
        }
    }

    put_blob(
        store,
        total_size,
        target_size as u64,
        CONTENT_CHUNKING_FASTCDC,
        &chunks,
    )
}

/// Build + store a single `system/content/chunk` entity.
fn put_chunk(store: &Arc<dyn ContentStore>, payload: &[u8]) -> Result<Hash, ChunkerError> {
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(vec![(
        entity_ecf::text("payload"),
        ciborium::Value::Bytes(payload.to_vec()),
    )]));
    let chunk = Entity::new(TYPE_CONTENT_CHUNK, data)
        .map_err(|e| ChunkerError::Entity(e.to_string()))?;
    Ok(store.put(chunk)?)
}

/// Build + store the `system/content/blob` manifest. `chunks` is the
/// ordered list of chunk hashes (each rendered as a flat `system/hash`
/// record per ENTITY-NATIVE-TYPE-SYSTEM §2.8).
fn put_blob(
    store: &Arc<dyn ContentStore>,
    total_size: u64,
    chunk_size: u64,
    chunking: u64,
    chunks: &[Hash],
) -> Result<Hash, ChunkerError> {
    let chunks_arr = ciborium::Value::Array(
        chunks
            .iter()
            .map(|h| hash_to_bstr(h))
            .collect::<Vec<_>>(),
    );
    let data = entity_ecf::to_ecf(&ciborium::Value::Map(vec![
        (entity_ecf::text("total_size"), ciborium::Value::Integer(total_size.into())),
        (entity_ecf::text("chunk_size"), ciborium::Value::Integer(chunk_size.into())),
        (entity_ecf::text("chunking"), ciborium::Value::Integer(chunking.into())),
        (entity_ecf::text("chunks"), chunks_arr),
    ]));
    let blob = Entity::new(TYPE_CONTENT_BLOB, data)
        .map_err(|e| ChunkerError::Entity(e.to_string()))?;
    Ok(store.put(blob)?)
}

/// Render a `Hash` as a 33-byte CBOR bstr (`algorithm || digest`) — the
/// canonical wire form per ENTITY-NATIVE-TYPE-SYSTEM §4.5 (`system/hash`
/// extends `primitive/bytes`). §2.8 "named type → flat record" does NOT
/// apply here because `system/hash` carries the explicit bstr-extension
/// exception. Same shape used inline (`{type: system/hash, data: bstr}`),
/// in single fields (`FileData.content`), and in array elements
/// (`ContentBlobData.chunks`).
fn hash_to_bstr(h: &Hash) -> ciborium::Value {
    ciborium::Value::Bytes(h.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_store::MemoryContentStore;

    fn store() -> Arc<dyn ContentStore> {
        Arc::new(MemoryContentStore::new())
    }

    #[test]
    fn fixed_size_round_trip_single_chunk() {
        let s = store();
        let raw = b"hello world".to_vec();
        let blob_hash = create_blob_fixed(&s, &raw, 1024).unwrap();
        let blob = s.get(&blob_hash).expect("blob present");
        assert_eq!(blob.entity_type, TYPE_CONTENT_BLOB);
    }

    #[test]
    fn fixed_size_multi_chunk_matches_chunk_count() {
        let s = store();
        let raw = vec![0xAB; 10_000];
        let blob_hash = create_blob_fixed(&s, &raw, 4096).unwrap();
        let blob = s.get(&blob_hash).unwrap();
        let v: ciborium::Value = ciborium::from_reader(blob.data.as_slice()).unwrap();
        let m = v.as_map().unwrap();
        let chunks = m
            .iter()
            .find(|(k, _)| k.as_text() == Some("chunks"))
            .map(|(_, v)| v.as_array().unwrap().clone())
            .unwrap();
        // ceil(10000 / 4096) = 3
        assert_eq!(chunks.len(), 3);
    }

    #[test]
    fn fixed_size_dedupes_identical_chunks() {
        let s = store();
        // Two identical 4 KiB blocks back-to-back — should dedupe to a
        // single chunk entity in the store.
        let raw: Vec<u8> = (0..2)
            .flat_map(|_| std::iter::repeat(0xCD).take(4096))
            .collect();
        let before_len = s.len();
        create_blob_fixed(&s, &raw, 4096).unwrap();
        let after_len = s.len();
        // 1 blob + 1 chunk (deduped) = 2 entities added
        assert_eq!(after_len - before_len, 2);
    }

    #[test]
    fn fastcdc_smaller_than_min_produces_single_chunk() {
        let s = store();
        // 4 MiB target → min = 1 MiB. A 1 KiB input falls into the
        // short-final-chunk path immediately.
        let raw = vec![0u8; 1024];
        let blob_hash = create_blob_fastcdc(&s, &raw, 4 * 1024 * 1024).unwrap();
        let blob = s.get(&blob_hash).unwrap();
        let v: ciborium::Value = ciborium::from_reader(blob.data.as_slice()).unwrap();
        let m = v.as_map().unwrap();
        let chunks = m
            .iter()
            .find(|(k, _)| k.as_text() == Some("chunks"))
            .map(|(_, v)| v.as_array().unwrap().clone())
            .unwrap();
        assert_eq!(chunks.len(), 1);
    }

    #[test]
    fn fastcdc_stream_produces_byte_identical_chunks_to_buffered() {
        // L4 cross-impl conformance: the streaming chunker MUST produce
        // byte-identical chunks to the buffered chunker on the same
        // input (DOMAIN-LOCAL-FILES v1.3 L4 + CONTENT v3.5 §3.6.5).
        // If this diverges, blob hashes diverge between large-file
        // writes (which use stream) and small-file writes (which use
        // buffer), breaking cross-handler dedup.
        let mut rng: u64 = 0x1234_5678;
        let mut raw = vec![0u8; 1 << 18]; // 256 KiB
        for b in &mut raw {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *b = (rng >> 24) as u8;
        }
        let target = 4096;

        let s1 = store();
        let buffered_hash = create_blob_fastcdc(&s1, &raw, target).unwrap();

        let s2 = store();
        let stream_hash =
            create_blob_fastcdc_stream(&s2, std::io::Cursor::new(&raw), target).unwrap();

        assert_eq!(
            buffered_hash, stream_hash,
            "stream + buffered chunkers must produce identical blob hashes"
        );

        // Verify chunk-list identity too (paranoia: same hash could
        // hide divergent chunk counts if blob shape were different).
        let blob_buf = s1.get(&buffered_hash).unwrap();
        let blob_stream = s2.get(&stream_hash).unwrap();
        assert_eq!(blob_buf.data, blob_stream.data, "blob data byte-identical");
    }

    #[test]
    fn fastcdc_edit_stability_property() {
        // Inserting a single byte in the middle of a large pseudo-random
        // stream MUST leave most chunks before and after the edit
        // boundary intact (that's the FastCDC value proposition). Use a
        // small target_size so we get multiple chunks from a modest
        // input.
        let s = store();
        let mut rng_state: u64 = 0xDEAD_BEEF;
        let mut raw = vec![0u8; 1 << 17]; // 128 KiB
        for b in &mut raw {
            // Tiny LCG — deterministic, good enough for a test fixture
            rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *b = (rng_state >> 24) as u8;
        }

        let target = 4096;
        let blob_a_hash = create_blob_fastcdc(&s, &raw, target).unwrap();
        let blob_a = s.get(&blob_a_hash).unwrap();
        let chunks_a = chunks_of(&blob_a);

        // Insert one byte in the middle.
        let mut raw_edit = raw.clone();
        raw_edit.insert(raw.len() / 2, 0xFF);
        let blob_b_hash = create_blob_fastcdc(&s, &raw_edit, target).unwrap();
        let blob_b = s.get(&blob_b_hash).unwrap();
        let chunks_b = chunks_of(&blob_b);

        // The first chunk MUST be byte-identical (boundary is content-
        // defined, edit is far past the first chunk's range).
        assert_eq!(
            chunks_a[0], chunks_b[0],
            "FastCDC failed edit-stability for the first chunk"
        );
        // At least one chunk near the end MUST also be byte-identical.
        let last_a = chunks_a.last().unwrap();
        assert!(
            chunks_b.contains(last_a) || chunks_b[chunks_b.len() - 1] == *last_a,
            "FastCDC failed edit-stability — no shared chunk near the end"
        );
    }

    fn chunks_of(blob: &Entity) -> Vec<Vec<u8>> {
        let v: ciborium::Value = ciborium::from_reader(blob.data.as_slice()).unwrap();
        let m = v.as_map().unwrap();
        let arr = m
            .iter()
            .find(|(k, _)| k.as_text() == Some("chunks"))
            .map(|(_, v)| v.as_array().unwrap().clone())
            .unwrap();
        // Each entry is a 33-byte bstr (algorithm || digest); strip the
        // algorithm prefix and return the digest portion.
        arr.iter()
            .map(|entry| {
                let bytes = entry.as_bytes().unwrap();
                bytes[1..].to_vec()
            })
            .collect()
    }
}
