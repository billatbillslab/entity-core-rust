//! Length-prefixed framing and envelope codec.
//!
//! Wire format per Entity Core Protocol v7.9 §1.6, §3.1:
//! - Frame: 4-byte big-endian length prefix + CBOR payload
//! - Envelope: `{root: Entity, included: Map<Hash, Entity>}`
//! - Only two message types: EXECUTE and EXECUTE_RESPONSE

use std::collections::BTreeMap;

use entity_entity::{Entity, Envelope};
use entity_hash::Hash;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Default maximum frame size: 16 MiB (spec recommendation).
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Framing (§1.6)
// ---------------------------------------------------------------------------

/// Write a length-prefixed frame.
#[tracing::instrument(level = "debug", skip_all, fields(bytes = payload.len()))]
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<(), WireError> {
    let len = payload.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a length-prefixed frame.
///
/// Returns the payload bytes. Enforces `max_frame_size` to bound memory allocation.
#[tracing::instrument(level = "debug", skip_all, fields(bytes = tracing::field::Empty))]
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_frame_size: u32,
) -> Result<Vec<u8>, WireError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > max_frame_size {
        return Err(WireError::FrameTooLarge {
            size: len,
            max: max_frame_size,
        });
    }
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;
    tracing::Span::current().record("bytes", len);
    Ok(payload)
}

// ---------------------------------------------------------------------------
// Entity codec
// ---------------------------------------------------------------------------

/// Encode an entity to CBOR bytes: `{type, data, content_hash}`.
///
/// The `data` field is embedded as raw CBOR bytes (not re-encoded)
/// to preserve byte fidelity for hash verification.
pub fn encode_entity(entity: &Entity) -> Vec<u8> {
    // Build manually to embed data as raw CBOR bytes (no re-encoding).
    let mut output = Vec::new();

    // Map with 3 items
    output.push(0xA3);

    // ECF key ordering: by encoded key byte length, then lexicographic.
    // "data" (5 encoded bytes) < "type" (5 bytes) lex < "content_hash" (13 bytes)

    // "data" key + raw value
    entity_ecf::encode_cbor_text(&mut output, "data");
    output.extend_from_slice(&entity.data);

    // "type" key + value
    entity_ecf::encode_cbor_text(&mut output, "type");
    entity_ecf::encode_cbor_text(&mut output, &entity.entity_type);

    // "content_hash" key + value (33-byte bstr)
    entity_ecf::encode_cbor_text(&mut output, "content_hash");
    entity_ecf::encode_cbor_bstr(&mut output, &entity.content_hash.to_bytes());

    output
}

/// Decode an entity from CBOR bytes.
///
/// **Byte fidelity (TODO-WIRE-CODEC-FLOAT-FIX, ENTITY-CBOR-ENCODING §4.2).**
/// The `data` field is captured as its **raw on-wire CBOR bytes**, not
/// decoded into a `ciborium::Value` and re-encoded. Any decode+re-encode
/// cycle would route through whichever encoder ciborium ships and risk
/// differing from the sender's canonical (ECF) output on edge cases —
/// notably non-minimal float encodings, multi-sig cap entities, and
/// anywhere an integer/float distinction or map-key ordering matters.
/// The mirrored extraction in `decode_envelope` preserves the same
/// fidelity for the wrapping envelope's root / included entries.
pub fn decode_entity(data: &[u8]) -> Result<Entity, WireError> {
    let (major, count, head_size) = parse_cbor_head(data, 0)?;
    if major != 5 {
        return Err(WireError::CborDecode(format!(
            "expected CBOR map for entity, got major={major}"
        )));
    }

    let mut entity_type: Option<String> = None;
    let mut entity_data: Option<Vec<u8>> = None;
    let mut content_hash: Option<Hash> = None;

    let mut cursor = head_size;
    for _ in 0..count {
        let (key, after_key) = decode_cbor_text(data, cursor)?;
        let value_start = after_key;
        let value_end = cbor_item_end(data, value_start)?;
        match key {
            "type" => {
                let (s, _) = decode_cbor_text(data, value_start)?;
                entity_type = Some(s.to_string());
            }
            "data" => {
                // Raw byte slice — no decode+re-encode round-trip.
                entity_data = Some(data[value_start..value_end].to_vec());
            }
            "content_hash" => {
                let (bytes, _) = decode_cbor_bytes(data, value_start)?;
                content_hash = Some(
                    Hash::from_bytes(bytes)
                        .map_err(|e| WireError::CborDecode(e.to_string()))?,
                );
            }
            _ => {} // unknown keys are tolerated
        }
        cursor = value_end;
    }

    let entity_type =
        entity_type.ok_or_else(|| WireError::CborDecode("missing 'type' field".into()))?;
    let data =
        entity_data.ok_or_else(|| WireError::CborDecode("missing 'data' field".into()))?;
    let content_hash = content_hash
        .ok_or_else(|| WireError::CborDecode("missing 'content_hash' field".into()))?;

    Ok(Entity {
        entity_type,
        data,
        content_hash,
    })
}

/// Decode an entity's `(type, data)` parts **without** requiring (or trusting)
/// a `content_hash` field. Unlike [`decode_entity`], this tolerates both the
/// 3-key authored form `{data, type, content_hash}` and the 2-key
/// hash-addressed form `{data, type}` that `CONTENT_GET` serves
/// (`ecf_for_hash`). Any `content_hash` present on the wire is ignored.
///
/// This is the parse half of host-bytes-distrust (V7 §1.2): a content consumer
/// that fetched bytes by hash MUST recompute `Hash::compute_format(type, data,
/// expected_format)` and compare against the requested hash — never read a
/// host-supplied `content_hash`. The recompute (which needs the expected hash's
/// format code) is the caller's responsibility; this returns the raw material.
/// `data` is captured as its on-wire CBOR slice for byte fidelity.
pub fn decode_entity_parts(data: &[u8]) -> Result<(String, Vec<u8>), WireError> {
    let (major, count, head_size) = parse_cbor_head(data, 0)?;
    if major != 5 {
        return Err(WireError::CborDecode(format!(
            "expected CBOR map for entity, got major={major}"
        )));
    }

    let mut entity_type: Option<String> = None;
    let mut entity_data: Option<Vec<u8>> = None;

    let mut cursor = head_size;
    for _ in 0..count {
        let (key, after_key) = decode_cbor_text(data, cursor)?;
        let value_start = after_key;
        let value_end = cbor_item_end(data, value_start)?;
        match key {
            "type" => {
                let (s, _) = decode_cbor_text(data, value_start)?;
                entity_type = Some(s.to_string());
            }
            "data" => {
                entity_data = Some(data[value_start..value_end].to_vec());
            }
            _ => {} // content_hash and unknown keys are tolerated and ignored
        }
        cursor = value_end;
    }

    let entity_type =
        entity_type.ok_or_else(|| WireError::CborDecode("missing 'type' field".into()))?;
    let entity_data =
        entity_data.ok_or_else(|| WireError::CborDecode("missing 'data' field".into()))?;
    Ok((entity_type, entity_data))
}

// ---------------------------------------------------------------------------
// Envelope codec (§3.1)
// ---------------------------------------------------------------------------

/// Encode an envelope to CBOR bytes.
pub fn encode_envelope(envelope: &Envelope) -> Vec<u8> {
    let mut output = Vec::new();

    if envelope.included.is_empty() {
        // Map with 1 item (root only, omit empty included)
        output.push(0xA1);
    } else {
        // Map with 2 items
        output.push(0xA2);

        // ECF key ordering: "root" (5 encoded bytes) before "included" (9 encoded bytes)
    }

    // "root" key + entity value
    entity_ecf::encode_cbor_text(&mut output, "root");
    let root_bytes = encode_entity(&envelope.root);
    output.extend_from_slice(&root_bytes);

    if !envelope.included.is_empty() {
        // "included" key + map value
        entity_ecf::encode_cbor_text(&mut output, "included");
        entity_ecf::encode_head(&mut output, 5 << 5, envelope.included.len() as u64);

        for (hash, entity) in &envelope.included {
            // Key: hash as CBOR bstr (33 bytes)
            entity_ecf::encode_cbor_bstr(&mut output, &hash.to_bytes());
            // Value: encoded entity
            let entity_bytes = encode_entity(entity);
            output.extend_from_slice(&entity_bytes);
        }
    }

    output
}

/// Decode an envelope from CBOR bytes.
///
/// Uses byte-slice extraction throughout — root and each included entity
/// are passed to `decode_entity` as their on-wire slice, preserving the
/// sender's `data`-field encoding. See `decode_entity` for the rationale.
pub fn decode_envelope(data: &[u8]) -> Result<Envelope, WireError> {
    let (major, count, head_size) = parse_cbor_head(data, 0)?;
    if major != 5 {
        return Err(WireError::CborDecode(format!(
            "expected CBOR map for envelope, got major={major}"
        )));
    }

    let mut root: Option<Entity> = None;
    let mut included: BTreeMap<Hash, Entity> = BTreeMap::new();

    let mut cursor = head_size;
    for _ in 0..count {
        let (key, after_key) = decode_cbor_text(data, cursor)?;
        let value_start = after_key;
        let value_end = cbor_item_end(data, value_start)?;
        match key {
            "root" => {
                root = Some(decode_entity(&data[value_start..value_end])?);
            }
            "included" => {
                let (inc_major, inc_count, inc_head) =
                    parse_cbor_head(data, value_start)?;
                if inc_major != 5 {
                    return Err(WireError::CborDecode(format!(
                        "envelope.included must be a CBOR map, got major={inc_major}"
                    )));
                }
                let mut inc_cursor = value_start + inc_head;
                for _ in 0..inc_count {
                    let (hash_bytes, after_hash) = decode_cbor_bytes(data, inc_cursor)?;
                    let hash = Hash::from_bytes(hash_bytes)
                        .map_err(|e| WireError::CborDecode(e.to_string()))?;
                    let entity_start = after_hash;
                    let entity_end = cbor_item_end(data, entity_start)?;
                    let entity = decode_entity(&data[entity_start..entity_end])?;
                    included.insert(hash, entity);
                    inc_cursor = entity_end;
                }
            }
            _ => {} // unknown keys tolerated
        }
        cursor = value_end;
    }

    let root = root.ok_or_else(|| WireError::CborDecode("missing 'root' field".into()))?;
    Ok(Envelope::with_included(root, included))
}

/// Extract the raw on-wire CBOR byte slice of `key`'s value from a top-level
/// CBOR map, without decoding the value.
///
/// Preserves byte fidelity for nested entities / opaque payloads carried as
/// map fields — e.g. GUIDE-CONFORMANCE §7a.2a in-band cap-passing, where the
/// reentry capability / granter / signature ride as entity-CBOR inside a
/// `primitive/any` params map and MUST round-trip without a decode+re-encode
/// cycle. Returns `None` if `data` is not a definite-length CBOR map, has a
/// non-text key, or does not contain `key`.
pub fn cbor_map_field_raw<'a>(data: &'a [u8], key: &str) -> Option<&'a [u8]> {
    let (major, count, head_size) = parse_cbor_head(data, 0).ok()?;
    if major != 5 {
        return None;
    }
    let mut cursor = head_size;
    for _ in 0..count {
        let (k, after_key) = decode_cbor_text(data, cursor).ok()?;
        let value_start = after_key;
        let value_end = cbor_item_end(data, value_start).ok()?;
        if k == key {
            return Some(&data[value_start..value_end]);
        }
        cursor = value_end;
    }
    None
}

// ---------------------------------------------------------------------------
// CBOR byte-range walker (ENTITY-CBOR-ENCODING §4.2 — definite-length only)
// ---------------------------------------------------------------------------
//
// Minimal CBOR parser whose job is to locate item boundaries without
// decoding values. Lets us preserve raw byte ranges for `data` fields
// (and entity-shaped values inside envelopes) end-to-end. ECF mandates
// definite-length encodings throughout, so indefinite-length / reserved
// argument bytes are spec violations and surface as decode errors.

/// Parse a CBOR head at `offset`. Returns `(major_type, argument_value, head_size)`.
/// Errors on indefinite-length or reserved argument bytes (ECF requires definite).
fn parse_cbor_head(data: &[u8], offset: usize) -> Result<(u8, u64, usize), WireError> {
    if offset >= data.len() {
        return Err(WireError::CborDecode("unexpected EOF parsing CBOR head".into()));
    }
    let first = data[offset];
    let major = first >> 5;
    let ai = first & 0x1F;
    let (value, head_size) = match ai {
        n @ 0..=23 => (n as u64, 1usize),
        24 => {
            if offset + 2 > data.len() {
                return Err(WireError::CborDecode("EOF reading CBOR u8 argument".into()));
            }
            (data[offset + 1] as u64, 2)
        }
        25 => {
            if offset + 3 > data.len() {
                return Err(WireError::CborDecode("EOF reading CBOR u16 argument".into()));
            }
            let mut b = [0u8; 2];
            b.copy_from_slice(&data[offset + 1..offset + 3]);
            (u16::from_be_bytes(b) as u64, 3)
        }
        26 => {
            if offset + 5 > data.len() {
                return Err(WireError::CborDecode("EOF reading CBOR u32 argument".into()));
            }
            let mut b = [0u8; 4];
            b.copy_from_slice(&data[offset + 1..offset + 5]);
            (u32::from_be_bytes(b) as u64, 5)
        }
        27 => {
            if offset + 9 > data.len() {
                return Err(WireError::CborDecode("EOF reading CBOR u64 argument".into()));
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&data[offset + 1..offset + 9]);
            (u64::from_be_bytes(b), 9)
        }
        _ => {
            return Err(WireError::CborDecode(format!(
                "CBOR additional-info {ai} (indefinite-length / reserved); ECF requires \
                 definite-length encoding per ENTITY-CBOR-ENCODING §4.2"
            )));
        }
    };
    Ok((major, value, head_size))
}

/// Return the end offset (exclusive) of the CBOR item starting at `offset`.
fn cbor_item_end(data: &[u8], offset: usize) -> Result<usize, WireError> {
    let (major, value, head_size) = parse_cbor_head(data, offset)?;
    let after_head = offset + head_size;
    match major {
        0 | 1 => Ok(after_head), // uint / negative integer — head only
        2 | 3 => {
            // bytes / text — head + N bytes payload
            let end = after_head.checked_add(value as usize).ok_or_else(|| {
                WireError::CborDecode("CBOR string/bytes length overflow".into())
            })?;
            if end > data.len() {
                return Err(WireError::CborDecode("CBOR string/bytes runs past end".into()));
            }
            Ok(end)
        }
        4 => {
            // array — head + N child items
            let mut cursor = after_head;
            for _ in 0..value {
                cursor = cbor_item_end(data, cursor)?;
            }
            Ok(cursor)
        }
        5 => {
            // map — head + 2N child items
            let mut cursor = after_head;
            for _ in 0..value {
                cursor = cbor_item_end(data, cursor)?; // key
                cursor = cbor_item_end(data, cursor)?; // value
            }
            Ok(cursor)
        }
        6 => {
            // tag — head + exactly one child item
            cbor_item_end(data, after_head)
        }
        7 => {
            // float / simple — head_size already includes the float payload
            // (ai 25 → +2 bytes, ai 26 → +4, ai 27 → +8, ai 0..=23 → 0).
            Ok(after_head)
        }
        _ => Err(WireError::CborDecode(format!("unknown CBOR major type {major}"))),
    }
}

/// Decode a CBOR text item at `offset`. Returns `(borrowed_str, end_offset)`.
fn decode_cbor_text(data: &[u8], offset: usize) -> Result<(&str, usize), WireError> {
    let (major, len, head_size) = parse_cbor_head(data, offset)?;
    if major != 3 {
        return Err(WireError::CborDecode(format!(
            "expected CBOR text, got major={major}"
        )));
    }
    let start = offset + head_size;
    let end = start.checked_add(len as usize).ok_or_else(|| {
        WireError::CborDecode("CBOR text length overflow".into())
    })?;
    if end > data.len() {
        return Err(WireError::CborDecode("CBOR text runs past end".into()));
    }
    let s = std::str::from_utf8(&data[start..end])
        .map_err(|e| WireError::CborDecode(format!("CBOR text invalid utf-8: {e}")))?;
    Ok((s, end))
}

/// Decode a CBOR byte-string item at `offset`. Returns `(borrowed_slice, end_offset)`.
fn decode_cbor_bytes(data: &[u8], offset: usize) -> Result<(&[u8], usize), WireError> {
    let (major, len, head_size) = parse_cbor_head(data, offset)?;
    if major != 2 {
        return Err(WireError::CborDecode(format!(
            "expected CBOR bytes, got major={major}"
        )));
    }
    let start = offset + head_size;
    let end = start.checked_add(len as usize).ok_or_else(|| {
        WireError::CborDecode("CBOR bytes length overflow".into())
    })?;
    if end > data.len() {
        return Err(WireError::CborDecode("CBOR bytes runs past end".into()));
    }
    Ok((&data[start..end], end))
}

#[derive(Debug, Error)]
pub enum WireError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("frame too large: {size} bytes (max {max})")]
    FrameTooLarge { size: u32, max: u32 },

    #[error("CBOR decode error: {0}")]
    CborDecode(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entity(type_str: &str, data_str: &str) -> Entity {
        let data = entity_ecf::to_ecf(&entity_ecf::text(data_str));
        Entity::new(type_str, data).unwrap()
    }

    // --- Framing tests ---

    #[tokio::test]
    async fn test_frame_roundtrip() {
        let payload = b"hello world";
        let mut buf = Vec::new();
        write_frame(&mut buf, payload).await.unwrap();
        assert_eq!(buf.len(), 4 + payload.len());
        // First 4 bytes are big-endian length
        assert_eq!(&buf[..4], &(payload.len() as u32).to_be_bytes());

        let mut cursor = std::io::Cursor::new(buf);
        let read_back = read_frame(&mut cursor, DEFAULT_MAX_FRAME_SIZE)
            .await
            .unwrap();
        assert_eq!(read_back, payload);
    }

    #[tokio::test]
    async fn test_frame_empty_payload() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"").await.unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let read_back = read_frame(&mut cursor, DEFAULT_MAX_FRAME_SIZE)
            .await
            .unwrap();
        assert!(read_back.is_empty());
    }

    #[tokio::test]
    async fn test_frame_too_large() {
        let mut buf = Vec::new();
        let big_payload = vec![0u8; 1000];
        write_frame(&mut buf, &big_payload).await.unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let result = read_frame(&mut cursor, 100).await;
        assert!(matches!(result, Err(WireError::FrameTooLarge { .. })));
    }

    #[tokio::test]
    async fn test_multiple_frames() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"first").await.unwrap();
        write_frame(&mut buf, b"second").await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let f1 = read_frame(&mut cursor, DEFAULT_MAX_FRAME_SIZE)
            .await
            .unwrap();
        let f2 = read_frame(&mut cursor, DEFAULT_MAX_FRAME_SIZE)
            .await
            .unwrap();
        assert_eq!(f1, b"first");
        assert_eq!(f2, b"second");
    }

    // --- Entity codec tests ---

    #[test]
    fn test_entity_encode_decode() {
        let entity = make_entity("test/type", "hello");
        let encoded = encode_entity(&entity);
        let decoded = decode_entity(&encoded).unwrap();
        assert_eq!(decoded.entity_type, entity.entity_type);
        assert_eq!(decoded.content_hash, entity.content_hash);
    }

    #[test]
    fn test_entity_hash_preserved() {
        let entity = make_entity("test/type", "hello");
        let encoded = encode_entity(&entity);
        let decoded = decode_entity(&encoded).unwrap();
        // The decoded entity should validate (hash matches)
        assert!(decoded.validate().is_ok());
    }

    #[test]
    fn test_entity_encode_deterministic() {
        let entity = make_entity("test/type", "hello");
        let e1 = encode_entity(&entity);
        let e2 = encode_entity(&entity);
        assert_eq!(e1, e2);
    }

    // --- Byte-fidelity regression tests (TODO-WIRE-CODEC-FLOAT-FIX) ---
    //
    // These lock in that `decode_entity` / `decode_envelope` preserve the
    // sender's `data`-field bytes exactly — no ciborium round-trip on the
    // hashed payload. The earlier impl decoded `data` to a `ciborium::Value`
    // and re-encoded it, which differs from the ECF canonical form on
    // floats and on any future encoder divergence between Rust and other
    // impls. Cross-impl symptom: hashes computed by Go/Python over their
    // canonical encoding didn't validate after Rust's decode+re-encode.

    #[test]
    fn test_decode_entity_preserves_float_data_bytes() {
        // ECF Rule 4 / 4a (ENTITY-CBOR-ENCODING): shortest float encoding
        // preserving value; ±0.0, ±Inf, NaN canonicalized to float16.
        for v in [
            0.0_f64,
            -0.0,
            1.0,
            1.5,
            65504.0, // f16 max-normal
            1.1,     // not representable in f16/f32 — falls through to f64
            0.333333,
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
        ] {
            let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                entity_ecf::text("v"),
                entity_ecf::Value::Float(v),
            )]));
            let entity = Entity::new("test/float", data).unwrap();
            let encoded = encode_entity(&entity);
            let decoded = decode_entity(&encoded).unwrap();
            assert_eq!(
                decoded.data, entity.data,
                "data bytes must round-trip exactly for float {v}"
            );
            assert!(
                decoded.validate().is_ok(),
                "content_hash must still validate after wire decode for float {v}"
            );
        }
    }

    #[test]
    fn test_decode_envelope_preserves_root_data_bytes() {
        // Same property on the envelope path — root entity's data bytes
        // must arrive untouched through decode_envelope.
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("v"),
            entity_ecf::Value::Float(1.5),
        )]));
        let root = Entity::new("test/float", data).unwrap();
        let envelope = Envelope::new(root.clone());
        let encoded = encode_envelope(&envelope);
        let decoded = decode_envelope(&encoded).unwrap();
        assert_eq!(decoded.root.data, root.data);
        assert!(decoded.root.validate().is_ok());
    }

    #[test]
    fn test_decode_envelope_preserves_included_data_bytes() {
        // Same property for included entries (load-bearing for the
        // cross-peer mirror recipe: include_payload + deref_included).
        let root = make_entity("test/root", "r");
        let payload_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("created_at"), entity_ecf::integer(1_700_000_000)),
            (entity_ecf::text("ratio"), entity_ecf::Value::Float(1.5)),
        ]));
        let payload = Entity::new("test/cap", payload_data).unwrap();
        let payload_hash = payload.content_hash;
        let mut envelope = Envelope::new(root);
        envelope.include(payload.clone());
        let encoded = encode_envelope(&envelope);
        let decoded = decode_envelope(&encoded).unwrap();
        let decoded_payload = decoded
            .included
            .get(&payload_hash)
            .expect("included payload missing after decode");
        assert_eq!(decoded_payload.data, payload.data);
        assert!(decoded_payload.validate().is_ok());
    }

    // --- Envelope codec tests ---

    #[test]
    fn test_envelope_roundtrip_root_only() {
        let root = make_entity("test/root", "root data");
        let envelope = Envelope::new(root.clone());
        let encoded = encode_envelope(&envelope);
        let decoded = decode_envelope(&encoded).unwrap();
        assert_eq!(decoded.root.entity_type, "test/root");
        assert_eq!(decoded.root.content_hash, root.content_hash);
        assert!(decoded.included.is_empty());
    }

    #[test]
    fn test_envelope_roundtrip_with_included() {
        let root = make_entity("test/root", "root");
        let extra = make_entity("test/extra", "extra");
        let extra_hash = extra.content_hash;
        let mut envelope = Envelope::new(root);
        envelope.include(extra);
        let encoded = encode_envelope(&envelope);
        let decoded = decode_envelope(&encoded).unwrap();
        assert!(decoded.included.contains_key(&extra_hash));
        assert_eq!(
            decoded.included[&extra_hash].entity_type,
            "test/extra"
        );
    }

    #[test]
    fn test_execute_response_result_is_inline_entity() {
        // Verify the result field in EXECUTE_RESPONSE data contains an inline
        // entity map, not just a content hash byte string.
        //
        // Build the response data the same way protocol::build_execute_response does:
        // result = inline entity, not hash reference.
        let result_entity = make_entity("system/protocol/connect/hello", "hello");
        let result_encoded = encode_entity(&result_entity);

        // Build response data with inline entity in result field
        let mut data = Vec::new();
        data.push(0xA3); // map(3)
        // "result" (7 encoded bytes) < "status" (7) lex, then "request_id" (11)
        // text(6) "result"
        data.extend_from_slice(&[0x66, b'r', b'e', b's', b'u', b'l', b't']);
        data.extend_from_slice(&result_encoded);
        // text(6) "status"
        data.extend_from_slice(&[0x66, b's', b't', b'a', b't', b'u', b's']);
        data.push(0x18); data.push(200); // uint 200
        // text(10) "request_id"
        data.extend_from_slice(&[0x6A, b'r', b'e', b'q', b'u', b'e', b's', b't', b'_', b'i', b'd']);
        data.extend_from_slice(&[0x65, b'r', b'e', b'q', b'-', b'1']); // text(5) "req-1"

        let resp_entity = Entity::new("system/protocol/execute_response", data).unwrap();
        let mut envelope = Envelope::new(resp_entity);
        envelope.include(result_entity);

        let encoded = encode_envelope(&envelope);

        // Decode and check the result field is an inline entity map
        let v: ciborium::Value = ciborium::from_reader(encoded.as_slice()).unwrap();
        let top_map = v.as_map().expect("envelope must be a map");

        for (k, val) in top_map {
            if k.as_text() == Some("root") {
                let root_map = val.as_map().expect("root must be entity map");
                for (rk, rv) in root_map {
                    if rk.as_text() == Some("data") {
                        let resp_map = rv.as_map().expect("response data must be a map");
                        for (dk, dv) in resp_map {
                            if dk.as_text() == Some("result") {
                                assert!(
                                    dv.as_map().is_some(),
                                    "result must be an inline entity map, got: {:?}", dv
                                );
                                assert!(
                                    dv.as_bytes().is_none(),
                                    "result must NOT be a byte string (hash reference)"
                                );
                                let ent_map = dv.as_map().unwrap();
                                let keys: Vec<_> = ent_map.iter()
                                    .filter_map(|(k, _)| k.as_text()).collect();
                                assert!(keys.contains(&"type"));
                                assert!(keys.contains(&"data"));
                                assert!(keys.contains(&"content_hash"));
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_envelope_validate_after_decode() {
        let root = make_entity("test/root", "root");
        let extra = make_entity("test/extra", "extra");
        let mut envelope = Envelope::new(root);
        envelope.include(extra);
        let encoded = encode_envelope(&envelope);
        let decoded = decode_envelope(&encoded).unwrap();
        assert!(decoded.validate_all().is_ok());
    }

    // --- Full wire roundtrip ---

    #[tokio::test]
    async fn test_full_wire_roundtrip() {
        let root = make_entity("system/protocol/execute", "request");
        let sig = make_entity("system/signature", "sig");
        let mut envelope = Envelope::new(root.clone());
        envelope.include(sig);

        let payload = encode_envelope(&envelope);
        let mut buf = Vec::new();
        write_frame(&mut buf, &payload).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let read_payload = read_frame(&mut cursor, DEFAULT_MAX_FRAME_SIZE)
            .await
            .unwrap();
        let decoded = decode_envelope(&read_payload).unwrap();

        assert_eq!(decoded.root.content_hash, root.content_hash);
        assert_eq!(decoded.included.len(), 1);
        assert!(decoded.validate_all().is_ok());
    }
}
