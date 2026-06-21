//! Content verification + reassembly (EXTENSION-CONTENT §3.3 + §3.4).
//!
//! `verify_content` checks blob completeness — every chunk present,
//! non-empty, and total size matches the blob's declaration. Each
//! chunk's entity hash is already verified at receive time per entity
//! fidelity (V7 §1.8), so this is the post-receipt invariant check.
//!
//! `reassemble` concatenates the chunk payloads in blob-declared
//! order. The fast path is `Vec<u8>`; callers streaming to a sink can
//! wrap this and stop allocating.

use std::sync::Arc;

use ciborium::Value;
use entity_ecf::ValueExt;
use entity_entity::Entity;
use entity_hash::Hash;
use entity_store::ContentStore;
use entity_types::TYPE_CONTENT_BLOB;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("blob not in content store: {0}")]
    BlobMissing(Hash),
    #[error("entity is not a system/content/blob")]
    NotABlob,
    #[error("blob decode failed: {0}")]
    BadBlob(String),
    #[error("chunk missing: {0}")]
    ChunkMissing(Hash),
    #[error("chunk has empty payload: {0}")]
    EmptyChunk(Hash),
    #[error("total size mismatch — blob declares {declared}, actual {actual}")]
    SizeMismatch { declared: u64, actual: u64 },
}

/// Verify a blob's chunks are all present, non-empty, and total size
/// matches the manifest's `total_size`. Returns Ok(()) on success.
pub fn verify_content(store: &Arc<dyn ContentStore>, blob_hash: &Hash) -> Result<(), VerifyError> {
    let (declared, chunk_hashes) = decode_blob(store, blob_hash)?;
    let mut actual: u64 = 0;
    for ch in &chunk_hashes {
        let chunk = store.get(ch).ok_or(VerifyError::ChunkMissing(*ch))?;
        let payload_len = chunk_payload_len(&chunk)
            .map_err(|e| VerifyError::BadBlob(format!("chunk decode: {}", e)))?;
        if payload_len == 0 {
            return Err(VerifyError::EmptyChunk(*ch));
        }
        actual = actual.saturating_add(payload_len as u64);
    }
    if actual != declared {
        return Err(VerifyError::SizeMismatch {
            declared,
            actual,
        });
    }
    Ok(())
}

/// Reassemble a blob's content as a contiguous `Vec<u8>` by walking
/// `chunks` in order and appending each chunk's payload. Errors mirror
/// `verify_content`.
///
/// Public reassembly entry point pinned by SDK-EXTENSION-OPERATIONS §11
/// (per-impl Reassemble location pinning) — Rust's pin is
/// this function at `extensions/content/src/lib.rs`. Pure local helper
/// over a complete closure (no protocol surface; cap discipline is
/// guarded by [`crate::ensure_closure`]).
pub fn reassemble(
    store: &Arc<dyn ContentStore>,
    blob_hash: &Hash,
) -> Result<Vec<u8>, VerifyError> {
    let (total_size, chunk_hashes) = decode_blob(store, blob_hash)?;
    let mut out: Vec<u8> = Vec::with_capacity(total_size as usize);
    for ch in &chunk_hashes {
        let chunk = store.get(ch).ok_or(VerifyError::ChunkMissing(*ch))?;
        let payload = chunk_payload_bytes(&chunk)
            .map_err(|e| VerifyError::BadBlob(format!("chunk decode: {}", e)))?;
        out.extend_from_slice(&payload);
    }
    Ok(out)
}

/// Streaming variant of [`reassemble`] per DOMAIN-LOCAL-FILES v1.3 §5.3
/// L4 SHOULD. Walks the chunk list in order, fetching one chunk at a
/// time from the store and writing its payload to the caller's sink.
/// Steady-state memory: one chunk-payload (worst case `max_size`); the
/// full reassembled buffer is never materialized.
///
/// `writer` MUST handle the write durably (e.g., be a temp-file in an
/// atomic-write sequence) — this function does not buffer for atomicity.
pub fn reassemble_stream<W: std::io::Write>(
    store: &Arc<dyn ContentStore>,
    blob_hash: &Hash,
    mut writer: W,
) -> Result<u64, VerifyError> {
    let (_total_size, chunk_hashes) = decode_blob(store, blob_hash)?;
    let mut written: u64 = 0;
    for ch in &chunk_hashes {
        let chunk = store.get(ch).ok_or(VerifyError::ChunkMissing(*ch))?;
        let payload = chunk_payload_bytes(&chunk)
            .map_err(|e| VerifyError::BadBlob(format!("chunk decode: {}", e)))?;
        writer
            .write_all(&payload)
            .map_err(|e| VerifyError::BadBlob(format!("write: {e}")))?;
        written += payload.len() as u64;
    }
    Ok(written)
}

/// Decode a blob entity to `(total_size, chunk_hashes_in_order)` from
/// the content store. Public so downstream handlers (e.g.,
/// `local/files`) can enumerate a blob's chunks for inline-include
/// without re-implementing the wire decode.
pub fn blob_chunk_hashes(
    store: &Arc<dyn ContentStore>,
    blob_hash: &Hash,
) -> Result<(u64, Vec<Hash>), VerifyError> {
    decode_blob(store, blob_hash)
}

/// Read the `chunk_size` field off a `system/content/blob` entity
/// (CONTENT v3.5 §3.5 — recorded per-blob at chunking time).
///
/// Used by consumers that need to chunk additional bytes against the
/// same parameters as the blob — notably the DOMAIN-LOCAL-FILES v1.3
/// §5.5 circuit-breaker recompute, which MUST chunk the on-disk file
/// with the incoming blob's `chunk_size` (not the consumer's local
/// default) to preserve "same bytes ⇒ same blob hash" across peers
/// running different chunk-size defaults.
pub fn blob_chunk_size(blob_entity: &Entity) -> Result<u64, VerifyError> {
    if blob_entity.entity_type != TYPE_CONTENT_BLOB {
        return Err(VerifyError::NotABlob);
    }
    let v: Value = ciborium::from_reader(blob_entity.data.as_slice())
        .map_err(|e| VerifyError::BadBlob(format!("cbor: {}", e)))?;
    v.get("chunk_size")
        .and_then(value_to_u64)
        .ok_or_else(|| VerifyError::BadBlob("missing chunk_size".into()))
}

/// Decode a blob entity to `(total_size, chunk_hashes_in_order)`.
fn decode_blob(
    store: &Arc<dyn ContentStore>,
    blob_hash: &Hash,
) -> Result<(u64, Vec<Hash>), VerifyError> {
    let blob = store.get(blob_hash).ok_or(VerifyError::BlobMissing(*blob_hash))?;
    if blob.entity_type != TYPE_CONTENT_BLOB {
        return Err(VerifyError::NotABlob);
    }
    let v: Value = ciborium::from_reader(blob.data.as_slice())
        .map_err(|e| VerifyError::BadBlob(format!("cbor: {}", e)))?;
    let total_size = v
        .get("total_size")
        .and_then(value_to_u64)
        .ok_or_else(|| VerifyError::BadBlob("missing total_size".into()))?;
    let chunks_arr = v
        .get("chunks")
        .and_then(|v| v.as_array().cloned())
        .ok_or_else(|| VerifyError::BadBlob("missing chunks".into()))?;
    let mut hashes: Vec<Hash> = Vec::with_capacity(chunks_arr.len());
    for entry in &chunks_arr {
        hashes.push(decode_hash_record(entry)?);
    }
    Ok((total_size, hashes))
}

/// Decode a 33-byte `system/hash` bstr (algorithm || digest) per
/// ENTITY-NATIVE-TYPE-SYSTEM §4.5.
fn decode_hash_record(value: &Value) -> Result<Hash, VerifyError> {
    let bytes = value
        .as_bytes()
        .ok_or_else(|| VerifyError::BadBlob("hash entry not a bstr".into()))?;
    Hash::from_bytes(bytes).map_err(|e| VerifyError::BadBlob(e.to_string()))
}

fn chunk_payload_len(chunk: &Entity) -> Result<usize, String> {
    let v: Value = ciborium::from_reader(chunk.data.as_slice())
        .map_err(|e| format!("cbor: {}", e))?;
    Ok(v.get("payload")
        .and_then(|v| v.as_bytes().cloned())
        .map(|b| b.len())
        .unwrap_or(0))
}

fn chunk_payload_bytes(chunk: &Entity) -> Result<Vec<u8>, String> {
    let v: Value = ciborium::from_reader(chunk.data.as_slice())
        .map_err(|e| format!("cbor: {}", e))?;
    Ok(v.get("payload")
        .and_then(|v| v.as_bytes().cloned())
        .unwrap_or_default())
}

fn value_to_u64(v: &Value) -> Option<u64> {
    match v {
        Value::Integer(i) => (*i).try_into().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunker::{create_blob_fastcdc, create_blob_fixed};
    use entity_store::MemoryContentStore;

    fn store() -> Arc<dyn ContentStore> {
        Arc::new(MemoryContentStore::new())
    }

    #[test]
    fn fixed_round_trip_reassembles_to_input() {
        let s = store();
        let raw: Vec<u8> = (0..10_000).map(|i| (i & 0xFF) as u8).collect();
        let h = create_blob_fixed(&s, &raw, 4096).unwrap();
        verify_content(&s, &h).unwrap();
        let back = reassemble(&s, &h).unwrap();
        assert_eq!(back, raw);
    }

    #[test]
    fn fastcdc_round_trip_reassembles_to_input() {
        let s = store();
        let mut rng_state: u64 = 0xC0FFEE;
        let mut raw = vec![0u8; 1 << 16];
        for b in &mut raw {
            rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *b = (rng_state >> 24) as u8;
        }
        let h = create_blob_fastcdc(&s, &raw, 4096).unwrap();
        verify_content(&s, &h).unwrap();
        let back = reassemble(&s, &h).unwrap();
        assert_eq!(back, raw);
    }

    #[test]
    fn blob_chunk_size_reads_field_from_manifest() {
        // v1.3 Amendment 3 §5.5: the circuit-breaker recompute reads
        // chunk_size off the incoming blob entity. Prove the accessor
        // returns the value used at chunking time.
        let s = store();
        let raw = vec![0xAAu8; 32 * 1024]; // 32 KiB
        let target_a: usize = 4096;
        let target_b: usize = 8192;
        let blob_a_hash = crate::chunker::create_blob_fastcdc(&s, &raw, target_a).unwrap();
        let blob_b_hash = crate::chunker::create_blob_fastcdc(&s, &raw, target_b).unwrap();
        let blob_a = s.get(&blob_a_hash).unwrap();
        let blob_b = s.get(&blob_b_hash).unwrap();
        assert_eq!(blob_chunk_size(&blob_a).unwrap() as usize, target_a);
        assert_eq!(blob_chunk_size(&blob_b).unwrap() as usize, target_b);
    }

    #[test]
    fn verify_detects_missing_chunk() {
        let s = store();
        let raw = vec![0xAAu8; 8192];
        let h = create_blob_fixed(&s, &raw, 4096).unwrap();
        // Yank the first chunk back out.
        let blob = s.get(&h).unwrap();
        let v: Value = ciborium::from_reader(blob.data.as_slice()).unwrap();
        let arr = v.get("chunks").unwrap().as_array().unwrap().clone();
        let first_chunk_hash = decode_hash_record(&arr[0]).unwrap();
        s.remove(&first_chunk_hash);
        let err = verify_content(&s, &h).unwrap_err();
        matches!(err, VerifyError::ChunkMissing(_));
    }
}
