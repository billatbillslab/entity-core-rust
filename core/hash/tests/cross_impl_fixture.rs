//! Cross-impl ECF byte-equality fixture (Phase 0 probe).
//!
//! Validates that Rust's ECF encoder + hash computation produce
//! byte-identical output to Go's canonical encoding for a reference
//! `system/continuation` payload. Reference fixture lives in
//! `entity-workbench-go/entitysdk/continuation_dispatch_cap_test.go::TestContinuationEntity_DeterministicEncoding`.
//!
//! Status (after kernel fix): `content_hash_of_continuation_data_matches_go`
//! PASSES — Rust's content hash for the reference inputs matches Go's
//! computed digest (`21bb462a57e8b130abf43738003cee8ee283445f64dd36b9a1157184810e8eb3`).
//! Cross-impl content-addressing on continuation entities is confirmed.
//!
//! The two remaining `#[ignore]`'d tests check the *displayed hex string*
//! from Go's fixture, which contains a spurious extra `0x00` byte in the
//! dispatch_capability section (Go publishes 162 bytes; both impls
//! actually encode 161 bytes — Go's hex-printing has an off-by-one in
//! the published fixture, not in the encoding itself). The content-hash
//! test passing despite this is the load-bearing evidence that the
//! encodings actually match. Re-enable once Go republishes the fixture.
//!
//! Prior to the kernel fix, Rust mis-encoded `params` as
//! `Value::Bytes(...)` instead of inline CBOR per
//! ENTITY-CBOR-ENCODING §7.6.1 (`primitive/any` = `any` CBOR data item).
//! See `extensions/continuation/src/lib.rs` encode_continuation /
//! encode_join.

use entity_ecf::{bytes, text, to_ecf, Value};
use entity_hash::Hash;

/// Construct the dispatch_capability hash exactly as Go's
/// `hash.Compute("test/dispatch-cap", cbor.RawMessage{0xa0})` does.
fn reference_dispatch_cap() -> Hash {
    // Empty CBOR map: a single byte 0xa0 (map header, 0 entries).
    Hash::compute("test/dispatch-cap", &[0xa0])
}

/// Construct the reference `system/continuation` data ECF map.
///
/// Mirrors the Go fixture:
///   target    = "system/revision"
///   operation = "merge"
///   params    = CBOR { "prefix": "shared/", "strategy": "auto" }
///   result_field        = "source_envelope"
///   dispatch_capability = <hash of test/dispatch-cap>
fn reference_continuation_data() -> Value {
    let dispatch_cap = reference_dispatch_cap();

    // Params: CBOR map { "prefix": "shared/", "strategy": "auto" }.
    // Canonical key order: length 6 ("prefix") before length 8 ("strategy").
    // Hand-rolled bytes matching the fixture exactly.
    let params_bytes: Vec<u8> = vec![
        0xa2, // map(2)
        0x66, b'p', b'r', b'e', b'f', b'i', b'x', // "prefix"
        0x67, b's', b'h', b'a', b'r', b'e', b'd', b'/', // "shared/"
        0x68, b's', b't', b'r', b'a', b't', b'e', b'g', b'y', // "strategy"
        0x64, b'a', b'u', b't', b'o', // "auto"
    ];

    // `params` is `primitive/any` per EXTENSION-CONTINUATION §2.1, encoded
    // inline per ENTITY-CBOR-ENCODING §7.6.1. Parse the raw bytes to a
    // Value so `to_ecf` re-canonicalizes and splices inline (matches Go's
    // `cbor.RawMessage` semantics). Wrapping in `bytes(...)` would mis-encode
    // params as `primitive/bytes`.
    let params_value: Value = ciborium::from_reader(params_bytes.as_slice())
        .expect("hand-rolled params bytes must round-trip");

    // The hash field is encoded as a CBOR byte string of 33 raw bytes
    // (1 algorithm byte + 32 digest bytes).
    let dispatch_cap_bytes = dispatch_cap.to_bytes().to_vec();

    // Build the map. Field push order does NOT matter — to_ecf sorts
    // keys per RFC 8949 §4.2.3 (length-then-lex).
    Value::Map(vec![
        (text("target"), text("system/revision")),
        (text("operation"), text("merge")),
        (text("params"), params_value),
        (text("result_field"), text("source_envelope")),
        (text("dispatch_capability"), bytes(dispatch_cap_bytes)),
    ])
}

#[test]
#[ignore = "Phase 0 probe — see file-level docs for current divergences"]
fn matches_go_fixture_byte_for_byte() {
    let data = reference_continuation_data();
    let encoded = to_ecf(&data);

    // Expected hex from Go fixture:
    //   a566706172616d73a266707265666978677368617265642f687374726174656779
    //   646175746f667461726765746f73797374656d2f7265766973696f6e696f706572
    //   6174696f6e656d657267656c726573756c745f6669656c646f736f757263655f65
    //   6e76656c6f70657364697370617463685f6361706162696c69747958210000f2ec
    //   441316496afaa32fd75a6271e3fbdc5aae5a6d4379629ca333ca18cdfb06
    let expected_hex = concat!(
        "a566706172616d73a266707265666978677368617265642f687374726174656779",
        "646175746f667461726765746f73797374656d2f7265766973696f6e696f706572",
        "6174696f6e656d657267656c726573756c745f6669656c646f736f757263655f65",
        "6e76656c6f70657364697370617463685f6361706162696c69747958210000f2ec",
        "441316496afaa32fd75a6271e3fbdc5aae5a6d4379629ca333ca18cdfb06",
    );
    let expected = hex_decode(expected_hex);

    if encoded != expected {
        eprintln!("Rust encoded ({} bytes):  {}", encoded.len(), hex_encode(&encoded));
        eprintln!("Go fixture   ({} bytes):  {}", expected.len(), expected_hex);
        // First-diff hint.
        if let Some(i) = (0..encoded.len().min(expected.len())).find(|&i| encoded[i] != expected[i]) {
            eprintln!("First differing byte at offset {}: rust=0x{:02x} go=0x{:02x}", i, encoded[i], expected[i]);
        }
    }
    assert_eq!(encoded.len(), 161, "expected 161 bytes per Go fixture");
    assert_eq!(encoded, expected, "Rust ECF must match Go canonical encoding");
}

#[test]
#[ignore = "Phase 0 probe — see file-level docs for current divergences"]
fn dispatch_cap_hash_matches_go_fixture() {
    let cap = reference_dispatch_cap();
    let wire = cap.to_bytes(); // 33 bytes: 1 algo + 32 digest

    // Go fixture's dispatch_capability bytes (CBOR-decoded, i.e. without the 0x58 0x21 header):
    let expected_hex = "0000f2ec441316496afaa32fd75a6271e3fbdc5aae5a6d4379629ca333ca18cdfb06";
    let expected = hex_decode(expected_hex);

    if &wire[..] != expected.as_slice() {
        eprintln!("Rust dispatch_cap hash: {}", hex_encode(&wire));
        eprintln!("Go   dispatch_cap hash: {}", expected_hex);
    }
    assert_eq!(&wire[..], expected.as_slice());
}

#[test]
fn content_hash_of_continuation_data_matches_go() {
    let data = reference_continuation_data();
    let encoded = to_ecf(&data);
    let content_hash = Hash::compute("system/continuation", &encoded);

    // Go fixture: ecf-sha256:21bb462a57e8b130abf43738003cee8ee283445f64dd36b9a1157184810e8eb3
    let expected_digest_hex = "21bb462a57e8b130abf43738003cee8ee283445f64dd36b9a1157184810e8eb3";
    let actual_digest_hex = hex_encode(content_hash.digest());
    if actual_digest_hex != expected_digest_hex {
        eprintln!("Rust content_hash digest: {}", actual_digest_hex);
        eprintln!("Go   content_hash digest: {}", expected_digest_hex);
    }
    assert_eq!(actual_digest_hex, expected_digest_hex);
}

// ----- helpers -----

fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.trim();
    assert_eq!(s.len() % 2, 0, "odd-length hex");
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        out.push(u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"));
    }
    out
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}
