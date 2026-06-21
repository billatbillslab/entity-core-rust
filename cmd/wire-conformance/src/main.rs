//! ECF wire conformance harness — core-rust side.
//!
//! Implements the `emit-canonical` mode per Appendix E §E.4.
//!
//! Input: a CBOR array of vector maps (the build-fixture output produced
//! by `entity-core-go/cmd/internal/wire-conformance build-fixture`).
//!
//! Output: a single canonical-ECF-encoded CBOR map of the emission shape
//! defined in §1 of the assignment. The diff harness consumes the output
//! as data; this binary prints nothing to stdout.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use ciborium::Value;
use clap::{Parser, Subcommand};
use entity_crypto::Keypair;
use entity_ecf::{to_ecf, Value as EcfValue};
use entity_hash::{HASH_ALGORITHM_SHA256, HASH_DIGEST_LEN};
use sha2::{Digest, Sha256};

/// Encode a u64 as an unsigned-varint (multibase-style LEB128: 7 payload
/// bits per byte, MSB set when more bytes follow). Used for the
/// `format_code` prefix on `content_hash` and the `key_type`/`hash_type`
/// prefixes on `peer_id`. Single-byte codepoints (< 0x80) emit one byte;
/// codepoints ≥ 0x80 emit the multi-byte form required by the spec's
/// forward-compat vectors (content_hash.4, peer_id.3).
///
/// NOTE — production `Hash` (`core/hash`) and `PeerId` (`core/crypto`)
/// still use single-byte prefixes because today's codepoints all fit. The
/// harness implements the spec-defined varint construction directly so
/// forward-compat vectors don't artificially diverge from impls that
/// already support multi-byte codepoints. When a real V7 codepoint goes
/// over 0x7f, broaden the production types — track via SPEC-AMBIGUITIES.
fn encode_unsigned_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

const IMPL_NAME: &str = "core-rust";
const CORPUS_VERSION: &str = "v1";
const SPEC_VERSION: &str = "1.5";

#[derive(Parser)]
#[command(name = "wire-conformance", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Produce a canonical-ECF emission file for the given corpus.
    EmitCanonical {
        /// Path to the canonical-ECF corpus (`conformance-vectors-v{N}.cbor`).
        #[arg(long)]
        input: PathBuf,
        /// Output path for the emission file (canonical-ECF map).
        #[arg(long)]
        out: PathBuf,
        /// Override the impl-version field; defaults to the build-time
        /// `CARGO_PKG_VERSION` (no git sha available without a build.rs).
        #[arg(long)]
        impl_version: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::EmitCanonical { input, out, impl_version } => {
            let impl_version = impl_version.unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
            emit_canonical(&input, &out, &impl_version)
        }
    }
}

fn emit_canonical(input: &PathBuf, out: &PathBuf, impl_version: &str) -> Result<()> {
    let bytes = fs::read(input).with_context(|| format!("read corpus {}", input.display()))?;
    let corpus: Value = ciborium::de::from_reader(bytes.as_slice())
        .with_context(|| format!("CBOR-decode corpus {}", input.display()))?;
    let vectors = corpus
        .as_array()
        .ok_or_else(|| anyhow!("corpus root must be a CBOR array"))?;

    // Use BTreeMaps so key iteration order is stable; we'll re-sort under ECF
    // rules at emission time, but keeping construction deterministic helps
    // debugging.
    let mut encode_results: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut decode_results: BTreeMap<String, bool> = BTreeMap::new();
    let mut errors: BTreeMap<String, String> = BTreeMap::new();

    for vec_val in vectors {
        let vec_map = vec_val
            .as_map()
            .ok_or_else(|| anyhow!("vector must be a CBOR map"))?;

        let id = field_text(vec_map, "id")?.to_string();
        let kind = field_text(vec_map, "kind")?.to_string();

        match kind.as_str() {
            "encode_equal" => {
                let input = field(vec_map, "input").ok_or_else(|| {
                    anyhow!("vector {id}: encode_equal missing 'input' field")
                })?;
                match encode_vector(&id, input) {
                    Ok(bytes) => {
                        encode_results.insert(id, bytes);
                    }
                    Err(EmitError::Other(msg)) => {
                        errors.insert(id, msg);
                    }
                }
            }
            "decode_reject" => {
                let canonical = field(vec_map, "canonical").ok_or_else(|| {
                    anyhow!("vector {id}: decode_reject missing 'canonical' field")
                })?;
                let wire = canonical
                    .as_bytes()
                    .ok_or_else(|| anyhow!("vector {id}: 'canonical' must be a bstr"))?;
                let rejected = !is_canonical_ecf(wire);
                decode_results.insert(id, rejected);
            }
            other => {
                errors.insert(id, format!("unknown kind: {other}"));
            }
        }
    }

    let emission = build_emission(impl_version, encode_results, decode_results, errors);
    let bytes = to_ecf(&emission);
    fs::write(out, &bytes).with_context(|| format!("write emission {}", out.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Per-vector encoding dispatch
// ---------------------------------------------------------------------------

enum EmitError {
    Other(String),
}

fn encode_vector(id: &str, input: &Value) -> Result<Vec<u8>, EmitError> {
    let (category, _) = id
        .split_once('.')
        .ok_or_else(|| EmitError::Other(format!("malformed vector id: {id}")))?;
    match category {
        "float" | "int" | "map_keys" | "length" | "primitive" | "nested" => {
            Ok(to_ecf(input))
        }
        "content_hash" => encode_content_hash(input),
        "peer_id" => encode_peer_id(input),
        "signature" => encode_signature(input),
        "envelope" => Ok(to_ecf(input)),
        other => Err(EmitError::Other(format!("unknown category: {other}"))),
    }
}

fn encode_content_hash(input: &Value) -> Result<Vec<u8>, EmitError> {
    // Input shape: {type, data} plus optional override {format_code: int}.
    let map = input
        .as_map()
        .ok_or_else(|| EmitError::Other("content_hash input must be a map".into()))?;
    let entity_type = field_text(map, "type")
        .map_err(|e| EmitError::Other(e.to_string()))?
        .to_string();
    let data = field(map, "data")
        .ok_or_else(|| EmitError::Other("content_hash input missing 'data'".into()))?;

    let format_code = match field(map, "format_code") {
        Some(v) => v
            .as_integer()
            .ok_or_else(|| EmitError::Other("format_code must be an int".into()))?
            .try_into()
            .map_err(|_| EmitError::Other("format_code out of u64 range".into()))?,
        None => HASH_ALGORITHM_SHA256 as u64,
    };

    let ecf_bytes = entity_ecf::ecf_for_hash_value(&entity_type, data);
    let digest: [u8; HASH_DIGEST_LEN] = Sha256::digest(&ecf_bytes).into();

    let mut out = Vec::with_capacity(2 + HASH_DIGEST_LEN);
    encode_unsigned_varint(format_code, &mut out);
    out.extend_from_slice(&digest);
    Ok(out)
}

fn encode_peer_id(input: &Value) -> Result<Vec<u8>, EmitError> {
    // Input shape: {key_type, hash_type, digest}.
    let map = input
        .as_map()
        .ok_or_else(|| EmitError::Other("peer_id input must be a map".into()))?;
    let key_type: u64 = field(map, "key_type")
        .ok_or_else(|| EmitError::Other("peer_id input missing 'key_type'".into()))?
        .as_integer()
        .ok_or_else(|| EmitError::Other("key_type must be an int".into()))?
        .try_into()
        .map_err(|_| EmitError::Other("key_type out of u64 range".into()))?;
    let hash_type: u64 = field(map, "hash_type")
        .ok_or_else(|| EmitError::Other("peer_id input missing 'hash_type'".into()))?
        .as_integer()
        .ok_or_else(|| EmitError::Other("hash_type must be an int".into()))?
        .try_into()
        .map_err(|_| EmitError::Other("hash_type out of u64 range".into()))?;
    let digest_bytes = field(map, "digest")
        .ok_or_else(|| EmitError::Other("peer_id input missing 'digest'".into()))?
        .as_bytes()
        .ok_or_else(|| EmitError::Other("digest must be a bstr".into()))?;

    let mut raw = Vec::with_capacity(2 + digest_bytes.len());
    encode_unsigned_varint(key_type, &mut raw);
    encode_unsigned_varint(hash_type, &mut raw);
    raw.extend_from_slice(digest_bytes);
    let base58 = bs58::encode(&raw).into_string();

    // Emit the Base58 string ECF-encoded as a CBOR text string so
    // cross-impl comparison is byte-for-byte at the CBOR layer.
    let mut out = Vec::new();
    entity_ecf::encode_cbor_text(&mut out, &base58);
    Ok(out)
}

fn encode_signature(input: &Value) -> Result<Vec<u8>, EmitError> {
    // Input shape: {seed: 32 bstr, entity: {type, data}}.
    let map = input
        .as_map()
        .ok_or_else(|| EmitError::Other("signature input must be a map".into()))?;
    let seed_bytes = field(map, "seed")
        .ok_or_else(|| EmitError::Other("signature input missing 'seed'".into()))?
        .as_bytes()
        .ok_or_else(|| EmitError::Other("seed must be a bstr".into()))?;
    if seed_bytes.len() != 32 {
        return Err(EmitError::Other(format!(
            "seed must be 32 bytes, got {}",
            seed_bytes.len()
        )));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(seed_bytes);

    let entity = field(map, "entity")
        .ok_or_else(|| EmitError::Other("signature input missing 'entity'".into()))?;
    let entity_map = entity
        .as_map()
        .ok_or_else(|| EmitError::Other("entity must be a map".into()))?;
    let entity_type = field_text(entity_map, "type")
        .map_err(|e| EmitError::Other(e.to_string()))?
        .to_string();
    let entity_data = field(entity_map, "data")
        .ok_or_else(|| EmitError::Other("entity missing 'data'".into()))?;

    // Canonical-ECF encoding of the entity = the {data, type} hash-input form.
    let entity_canonical = entity_ecf::ecf_for_hash_value(&entity_type, entity_data);

    let kp = Keypair::from_seed(seed);
    let sig = kp.sign(&entity_canonical);
    Ok(sig.to_vec())
}

// ---------------------------------------------------------------------------
// Canonical-ECF decoder (rejection check for `decode_reject` vectors)
// ---------------------------------------------------------------------------

/// Return true iff the bytes are a valid canonical-ECF item with no
/// trailing data. Used by `decode_reject`: a vector passes when this
/// returns false (i.e. the decoder rejected). v1 enforces:
///   - definite-length only (no 0x5f/0x7f/0x9f/0xbf headers)
///   - no CBOR tags (major 6) at any depth — §6.3 forbids wire tags
///   - minimal integer / length argument encoding (RFC 8949 §4.2.1 Rule 1)
///
/// (Map-key ordering checks are deferred until vectors land that exercise
/// the case; the v1 corpus has no unsorted-map-key decode_reject.)
fn is_canonical_ecf(bytes: &[u8]) -> bool {
    match walk_canonical(bytes, 0) {
        Ok(end) => end == bytes.len(),
        Err(_) => false,
    }
}

#[derive(Debug)]
struct CanonicalErr;

fn walk_canonical(data: &[u8], offset: usize) -> Result<usize, CanonicalErr> {
    if offset >= data.len() {
        return Err(CanonicalErr);
    }
    let first = data[offset];
    let major = first >> 5;
    let ai = first & 0x1F;

    // §6.3 wire tags forbidden.
    if major == 6 {
        return Err(CanonicalErr);
    }

    // Reject indefinite-length (ai 31) and reserved (28..=30).
    if ai >= 28 {
        return Err(CanonicalErr);
    }

    let (arg, head_size) = read_arg(data, offset, ai)?;

    // Minimal encoding check for integer/length arguments (majors 0..5 + 7-only).
    // Major 7 carries floats / simples where the "arg" isn't a quantity; skip.
    if major < 7 && !is_minimal_arg(ai, arg) {
        return Err(CanonicalErr);
    }

    let after_head = offset + head_size;
    match major {
        0 | 1 => Ok(after_head),
        2 | 3 => {
            let end = after_head
                .checked_add(arg as usize)
                .ok_or(CanonicalErr)?;
            if end > data.len() {
                return Err(CanonicalErr);
            }
            Ok(end)
        }
        4 => {
            let mut cursor = after_head;
            for _ in 0..arg {
                cursor = walk_canonical(data, cursor)?;
            }
            Ok(cursor)
        }
        5 => {
            let mut cursor = after_head;
            for _ in 0..arg {
                cursor = walk_canonical(data, cursor)?; // key
                cursor = walk_canonical(data, cursor)?; // value
            }
            Ok(cursor)
        }
        7 => Ok(after_head),
        _ => Err(CanonicalErr),
    }
}

fn read_arg(data: &[u8], offset: usize, ai: u8) -> Result<(u64, usize), CanonicalErr> {
    match ai {
        0..=23 => Ok((ai as u64, 1)),
        24 => {
            if offset + 2 > data.len() {
                return Err(CanonicalErr);
            }
            Ok((data[offset + 1] as u64, 2))
        }
        25 => {
            if offset + 3 > data.len() {
                return Err(CanonicalErr);
            }
            let b = [data[offset + 1], data[offset + 2]];
            Ok((u16::from_be_bytes(b) as u64, 3))
        }
        26 => {
            if offset + 5 > data.len() {
                return Err(CanonicalErr);
            }
            let mut b = [0u8; 4];
            b.copy_from_slice(&data[offset + 1..offset + 5]);
            Ok((u32::from_be_bytes(b) as u64, 5))
        }
        27 => {
            if offset + 9 > data.len() {
                return Err(CanonicalErr);
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&data[offset + 1..offset + 9]);
            Ok((u64::from_be_bytes(b), 9))
        }
        _ => Err(CanonicalErr),
    }
}

fn is_minimal_arg(ai: u8, arg: u64) -> bool {
    match ai {
        0..=23 => true,
        24 => arg >= 24,
        25 => arg > u8::MAX as u64,
        26 => arg > u16::MAX as u64,
        27 => arg > u32::MAX as u64,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Emission map construction
// ---------------------------------------------------------------------------

fn build_emission(
    impl_version: &str,
    encode_results: BTreeMap<String, Vec<u8>>,
    decode_results: BTreeMap<String, bool>,
    errors: BTreeMap<String, String>,
) -> EcfValue {
    let encode_map = EcfValue::Map(
        encode_results
            .into_iter()
            .map(|(k, v)| (EcfValue::Text(k), EcfValue::Bytes(v)))
            .collect(),
    );
    let decode_map = EcfValue::Map(
        decode_results
            .into_iter()
            .map(|(k, v)| (EcfValue::Text(k), EcfValue::Bool(v)))
            .collect(),
    );
    let errors_map = EcfValue::Map(
        errors
            .into_iter()
            .map(|(k, v)| (EcfValue::Text(k), EcfValue::Text(v)))
            .collect(),
    );

    EcfValue::Map(vec![
        (EcfValue::Text("impl".into()), EcfValue::Text(IMPL_NAME.into())),
        (
            EcfValue::Text("impl_version".into()),
            EcfValue::Text(impl_version.into()),
        ),
        (
            EcfValue::Text("corpus_version".into()),
            EcfValue::Text(CORPUS_VERSION.into()),
        ),
        (
            EcfValue::Text("spec_version".into()),
            EcfValue::Text(SPEC_VERSION.into()),
        ),
        (EcfValue::Text("encode_results".into()), encode_map),
        (EcfValue::Text("decode_results".into()), decode_map),
        (EcfValue::Text("errors".into()), errors_map),
    ])
}

// ---------------------------------------------------------------------------
// Small CBOR map helpers (ciborium::Value-side)
// ---------------------------------------------------------------------------

fn field<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Text(s) if s == key))
        .map(|(_, v)| v)
}

fn field_text<'a>(map: &'a [(Value, Value)], key: &str) -> Result<&'a str> {
    field(map, key)
        .ok_or_else(|| anyhow!("missing field {key}"))
        .and_then(|v| {
            v.as_text()
                .ok_or_else(|| anyhow!("field {key} must be a text string"))
        })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use entity_ecf::cbor_map;

    fn build_mini_corpus() -> Vec<Value> {
        // Mirrors a slice of conformance-vectors-v1.diag for round-trip
        // smoke testing the emitter against hand-built input.
        vec![
            // encode_equal — float
            Value::Map(vec![
                (Value::Text("id".into()), Value::Text("float.3".into())),
                (Value::Text("description".into()), Value::Text("f16: 1.0".into())),
                (Value::Text("kind".into()), Value::Text("encode_equal".into())),
                (Value::Text("input".into()), Value::Float(1.0)),
                (Value::Text("canonical".into()), Value::Bytes(vec![])),
            ]),
            // encode_equal — content_hash on empty entity (F5 vector)
            Value::Map(vec![
                (Value::Text("id".into()), Value::Text("content_hash.1".into())),
                (Value::Text("description".into()), Value::Text("empty entity".into())),
                (Value::Text("kind".into()), Value::Text("encode_equal".into())),
                (
                    Value::Text("input".into()),
                    Value::Map(vec![
                        (Value::Text("type".into()), Value::Text("system/empty".into())),
                        (Value::Text("data".into()), Value::Map(vec![])),
                    ]),
                ),
                (Value::Text("canonical".into()), Value::Bytes(vec![])),
            ]),
            // encode_equal — signature with deterministic seed
            Value::Map(vec![
                (Value::Text("id".into()), Value::Text("signature.1".into())),
                (Value::Text("description".into()), Value::Text("deterministic".into())),
                (Value::Text("kind".into()), Value::Text("encode_equal".into())),
                (
                    Value::Text("input".into()),
                    Value::Map(vec![
                        (Value::Text("seed".into()), Value::Bytes(vec![0u8; 32])),
                        (
                            Value::Text("entity".into()),
                            Value::Map(vec![
                                (Value::Text("type".into()), Value::Text("test/v1".into())),
                                (
                                    Value::Text("data".into()),
                                    Value::Map(vec![(Value::Text("x".into()), Value::Integer(1.into()))]),
                                ),
                            ]),
                        ),
                    ]),
                ),
                (Value::Text("canonical".into()), Value::Bytes(vec![])),
            ]),
            // decode_reject — tag-0 in data field
            Value::Map(vec![
                (Value::Text("id".into()), Value::Text("tag_reject.1".into())),
                (
                    Value::Text("description".into()),
                    Value::Text("tag 0 in data".into()),
                ),
                (Value::Text("kind".into()), Value::Text("decode_reject".into())),
                (
                    Value::Text("canonical".into()),
                    // From conformance-vectors-v1.diag.
                    Value::Bytes(
                        hex_to_bytes(
                            "a2647479706567746573742f7631646461746161316274736374\
                             323032362d30362d30365431323a30303a30305a",
                        ),
                    ),
                ),
            ]),
            // decode_reject — empty map (CANONICAL — must NOT be rejected)
            // Sanity check: confirms is_canonical_ecf accepts valid input
            // by negating the expectation in the test below.
        ]
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn emit_round_trip_mini_corpus() {
        let tmp = std::env::temp_dir();
        let input_path = tmp.join("wcv-test-input.cbor");
        let out_path = tmp.join("wcv-test-out.cbor");

        let corpus = Value::Array(build_mini_corpus());
        let mut input_bytes = Vec::new();
        ciborium::ser::into_writer(&corpus, &mut input_bytes).unwrap();
        fs::write(&input_path, &input_bytes).unwrap();

        emit_canonical(&input_path, &out_path, "test-0.0.0").unwrap();

        let out_bytes = fs::read(&out_path).unwrap();
        let parsed: Value = ciborium::de::from_reader(out_bytes.as_slice()).unwrap();
        let map = parsed.as_map().unwrap();

        assert_eq!(field_text(map, "impl").unwrap(), "core-rust");
        assert_eq!(field_text(map, "corpus_version").unwrap(), "v1");
        assert_eq!(field_text(map, "spec_version").unwrap(), "1.5");

        let encode_results = field(map, "encode_results").unwrap().as_map().unwrap();
        let float_bytes = field(encode_results, "float.3").unwrap().as_bytes().unwrap();
        assert_eq!(float_bytes, &[0xF9, 0x3C, 0x00], "f16 1.0 = F9 3C 00");

        let hash_bytes = field(encode_results, "content_hash.1")
            .unwrap()
            .as_bytes()
            .unwrap();
        assert_eq!(hash_bytes.len(), 33);
        assert_eq!(hash_bytes[0], 0x00, "SHA-256 format code");
        // Recompute the expected hash to confirm.
        let expected = {
            let empty_data = entity_ecf::to_ecf(&cbor_map! {});
            let ecf = entity_ecf::ecf_for_hash("system/empty", &empty_data);
            let mut h = vec![0x00];
            h.extend_from_slice(&Sha256::digest(&ecf));
            h
        };
        assert_eq!(hash_bytes, expected.as_slice());

        let sig_bytes = field(encode_results, "signature.1").unwrap().as_bytes().unwrap();
        assert_eq!(sig_bytes.len(), 64, "Ed25519 sig is 64 bytes");

        let decode_results = field(map, "decode_results").unwrap().as_map().unwrap();
        let rejected = matches!(field(decode_results, "tag_reject.1"), Some(Value::Bool(true)));
        assert!(rejected, "tag_reject.1 must be rejected");
    }

    #[test]
    fn is_canonical_ecf_accepts_simple_values() {
        // empty map
        assert!(is_canonical_ecf(&[0xa0]));
        // {"a": 1}
        assert!(is_canonical_ecf(&[0xa1, 0x61, b'a', 0x01]));
        // 1.0 as f16
        assert!(is_canonical_ecf(&[0xf9, 0x3c, 0x00]));
    }

    #[test]
    fn is_canonical_ecf_rejects_tag_wrapper() {
        // tag 55799 (0xd9 0xd9 0xf7) wrapping empty map (0xa0)
        assert!(!is_canonical_ecf(&[0xd9, 0xd9, 0xf7, 0xa0]));
    }

    #[test]
    fn is_canonical_ecf_rejects_nested_tag() {
        // {"k": tag-0("x")} — minimal: a1 61 6b c0 61 78
        let bytes = [0xa1, 0x61, b'k', 0xc0, 0x61, b'x'];
        assert!(!is_canonical_ecf(&bytes));
    }

    #[test]
    fn is_canonical_ecf_rejects_indefinite_length_map() {
        // 0xbf = indefinite-length map start
        assert!(!is_canonical_ecf(&[0xbf, 0xff]));
    }

    #[test]
    fn is_canonical_ecf_rejects_non_minimal_int() {
        // uint(0) encoded as 0x18 0x00 (ai=24 with arg<24 → non-minimal)
        assert!(!is_canonical_ecf(&[0x18, 0x00]));
        // uint(23) encoded as 0x18 0x17 (could be 0x17 alone)
        assert!(!is_canonical_ecf(&[0x18, 0x17]));
    }

    #[test]
    fn is_canonical_ecf_rejects_trailing_bytes() {
        // Valid map followed by garbage.
        assert!(!is_canonical_ecf(&[0xa0, 0x00]));
    }
}
