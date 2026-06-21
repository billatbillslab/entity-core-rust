//! Content hash: `content_hash_format` varint + variable-length digest.
//!
//! Wire format: `varint(format_code) || digest` inside a CBOR byte string.
//! For the active tier (V7 §8.2) the format code is a single byte:
//! `0x00` ECFv1-SHA-256 (32-byte digest, 33-byte wire) and `0x01`
//! ECFv1-SHA-384 (48-byte digest, 49-byte wire). Hash input is
//! ECF-encoded `{data, type}` — only those two fields — identical across
//! formats; only the digest algorithm differs.
//!
//! **v7.69 unification.** [`Hash`] is the single production content-hash
//! type. It is a `Copy` value type backed by a fixed [`HASH_MAX_DIGEST_LEN`]
//! inline buffer with a logical `len`, so it stays usable as a `HashMap`
//! key and is passed by value throughout the crate DAG, the SDK, bindings,
//! and cap chains — while carrying any allocated `content_hash_format`.
//! This replaces the v7.67 Phase-1 split where a parallel fixed-shape
//! SHA-256 `Hash` coexisted with a `Vec`-backed `MultiHash`; the focused
//! migration the `MultiHash` module docstring anticipated (MATRIX-M3) is
//! this change. Per-connection format selection lands at the authoring
//! sites (V7 §4.5a); this type provides the format-aware compute, encode,
//! decode, and equality primitives those sites build on.

use sha2::{Digest, Sha256, Sha384};
use thiserror::Error;

/// ECFv1-SHA-256 `content_hash_format` code (V7 §8.2 — Required floor).
pub const HASH_ALGORITHM_SHA256: u8 = 0x00;

/// ECFv1-SHA-384 `content_hash_format` code (V7 §8.2 — Validated, v7.67).
pub const HASH_ALGORITHM_SHA384: u8 = 0x01;

/// Reserved `content_hash_format` value (v7.67 §5.3): integer 255 (`0xFF`)
/// SHALL NOT be allocated; decoders MUST reject it.
pub const HASH_ALGORITHM_RESERVED_FF: u8 = 0xFF;

/// Process-wide **home** `content_hash_format` — the format a peer authors
/// its own persistent content and substrate under (V7 §1.2 / §1.2a / v7.70).
///
/// This is the single source for "the format I author under when no
/// connection-bound active format applies": stored entities, trie/location
/// nodes, revision entries, handler results, locally-persisted caps, the
/// peer's own identity entity, and the format-relative deletion marker
/// (§4.9). `Entity::new` and the bare `to_entity()` / `peer_entity()`
/// home-authoring helpers route through [`default_hash_format`]; explicit
/// connection authoring (V7 §4.5a active format) keeps using the
/// `*_with_format` variants and is unaffected.
///
/// Defaults to the SHA-256 floor; `PeerBuilder::build()` sets it from the
/// peer's configured `home_hash_format`. A SHA-256 deployment (and every
/// test that never sets a home format) keeps the floor — no behavior
/// change. The per-process model matches Go's `SetDefaultHashAlgorithm`:
/// one home format per process. Running peers with *different* home formats
/// in one process is the experimental cross-format case (V7 §1.5) — the
/// last writer wins this global; document it where you do it.
static DEFAULT_HASH_FORMAT: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(HASH_ALGORITHM_SHA256);

/// The process home `content_hash_format` (see [`DEFAULT_HASH_FORMAT`]).
pub fn default_hash_format() -> u8 {
    DEFAULT_HASH_FORMAT.load(std::sync::atomic::Ordering::Relaxed)
}

/// Set the process home `content_hash_format` (see [`DEFAULT_HASH_FORMAT`]).
/// Call once at peer construction, before any home authoring.
pub fn set_default_hash_format(format_code: u8) {
    DEFAULT_HASH_FORMAT.store(format_code, std::sync::atomic::Ordering::Relaxed);
}

/// SHA-256 digest length (bytes).
pub const SHA256_DIGEST_LEN: usize = 32;

/// SHA-384 digest length (bytes), per FIPS 180-4 / RFC 6234.
pub const SHA384_DIGEST_LEN: usize = 48;

/// SHA-256 digest length — retained name for the many sites that mean
/// "a SHA-256 digest is 32 bytes". Equal to [`SHA256_DIGEST_LEN`].
pub const HASH_DIGEST_LEN: usize = SHA256_DIGEST_LEN;

/// SHA-256 wire length: 1 format byte + 32-byte digest = 33. Retained as
/// the SHA-256 convenience constant; the wire length of a non-SHA-256
/// hash is `1 + digest_len_for_format(code)`.
pub const HASH_WIRE_LEN: usize = 1 + HASH_DIGEST_LEN;

/// Inline digest buffer ceiling. Covers every allocated and reserved
/// format in V7 §8.2 / §1.2: SHA-256 (32), SHA-384 (48), reserved
/// SHA-512 (64), BLAKE3-256 (32). Sized so [`Hash`] stays `Copy` without
/// heap allocation for any digest the spec can name.
pub const HASH_MAX_DIGEST_LEN: usize = 64;

/// Digest length for a supported `content_hash_format` code, or `None`
/// for an unallocated/unsupported code (the call site SHALL surface
/// `400 unsupported_content_hash_format`, V7 §4.7).
pub const fn digest_len_for_format(format_code: u8) -> Option<usize> {
    match format_code {
        HASH_ALGORITHM_SHA256 => Some(SHA256_DIGEST_LEN),
        HASH_ALGORITHM_SHA384 => Some(SHA384_DIGEST_LEN),
        _ => None,
    }
}

/// Map a V7 §8.2 hello `content_hash_format` string to its format code.
/// The hello negotiation (§4.5) exchanges these strings; the wire authors
/// the code. This is the single source for that mapping.
pub fn format_code_for_string(s: &str) -> Option<u8> {
    match s {
        "ecfv1-sha256" => Some(HASH_ALGORITHM_SHA256),
        "ecfv1-sha384" => Some(HASH_ALGORITHM_SHA384),
        _ => None,
    }
}

/// Map a `content_hash_format` code to its V7 §8.2 hello string.
pub fn format_string_for_code(code: u8) -> Option<&'static str> {
    match code {
        HASH_ALGORITHM_SHA256 => Some("ecfv1-sha256"),
        HASH_ALGORITHM_SHA384 => Some("ecfv1-sha384"),
        _ => None,
    }
}

/// Content hash: `content_hash_format` code + variable-length digest over
/// a fixed inline buffer (so the type is `Copy`).
///
/// On the wire this is a CBOR byte string `varint(algorithm) || digest`.
/// Equality, ordering, and hashing are over `(algorithm, digest[..len])` —
/// the unused buffer tail never participates.
#[derive(Clone, Copy)]
pub struct Hash {
    /// `content_hash_format` identifier (`0x00` = SHA-256, `0x01` = SHA-384).
    pub algorithm: u8,
    /// Logical digest length; `digest` bytes beyond this are zero padding.
    len: u8,
    /// Digest bytes, zero-padded past `len`.
    digest: [u8; HASH_MAX_DIGEST_LEN],
}

impl Hash {
    /// Construct from a format code and digest bytes. Low-level: trusts the
    /// caller that `digest` is the correct length for `algorithm`. The wire
    /// decode path ([`Hash::from_bytes`]) enforces length; internal callers
    /// that already hold a known-good digest use this. Digests longer than
    /// [`HASH_MAX_DIGEST_LEN`] are truncated (no allocated format exceeds it).
    pub fn new(algorithm: u8, digest: impl AsRef<[u8]>) -> Self {
        let digest = digest.as_ref();
        let len = digest.len().min(HASH_MAX_DIGEST_LEN);
        let mut buf = [0u8; HASH_MAX_DIGEST_LEN];
        buf[..len].copy_from_slice(&digest[..len]);
        Self {
            algorithm,
            len: len as u8,
            digest: buf,
        }
    }

    /// The logical digest bytes (length determined by the format code).
    pub fn digest(&self) -> &[u8] {
        &self.digest[..self.len as usize]
    }

    /// Whether this hash's `content_hash_format` is one this build supports.
    /// V7 §1.2 (v7.67 format-code interpretation): the leading varint is
    /// intrinsic to the hash. Sites finding an unsupported format MUST
    /// return `unsupported_content_hash_format` (V7 §4.7).
    pub fn is_supported_format(&self) -> bool {
        digest_len_for_format(self.algorithm).is_some()
    }

    /// Compute the content hash under the SHA-256 floor (`0x00`). Infallible.
    /// This is the process default for non-connection-bound authoring
    /// (peer-startup local state); connection-bound authoring selects the
    /// negotiated active format via [`Hash::compute_format`] (V7 §4.5a).
    pub fn compute(entity_type: &str, data: &[u8]) -> Self {
        let ecf_bytes = entity_ecf::ecf_for_hash(entity_type, data);
        let digest: [u8; SHA256_DIGEST_LEN] = Sha256::digest(&ecf_bytes).into();
        Self::new(HASH_ALGORITHM_SHA256, digest)
    }

    /// Compute the content hash under an explicit `content_hash_format`.
    /// Hash input is the same ECF-encoded `{data, type}` as [`Hash::compute`];
    /// only the digest algorithm differs (V7 §1.4). Returns
    /// `UnsupportedAlgorithm` for an unallocated format code.
    pub fn compute_format(
        entity_type: &str,
        data: &[u8],
        format_code: u8,
    ) -> Result<Self, HashError> {
        let ecf_bytes = entity_ecf::ecf_for_hash(entity_type, data);
        let digest: Vec<u8> = match format_code {
            HASH_ALGORITHM_SHA256 => Sha256::digest(&ecf_bytes).to_vec(),
            HASH_ALGORITHM_SHA384 => Sha384::digest(&ecf_bytes).to_vec(),
            other => return Err(HashError::UnsupportedAlgorithm(other)),
        };
        Ok(Self::new(format_code, &digest))
    }

    /// Validate that a claimed hash matches the recomputed hash for the
    /// given entity, recomputing under the claimed hash's own format code
    /// (V7 §1.8 validate-on-receipt). An unsupported claimed format is a
    /// validation failure (`unsupported_content_hash_format`).
    pub fn validate(entity_type: &str, data: &[u8], claimed: &Hash) -> Result<(), HashError> {
        let actual = Self::compute_format(entity_type, data, claimed.algorithm)?;
        if actual != *claimed {
            return Err(HashError::HashMismatch {
                expected: *claimed,
                actual,
            });
        }
        Ok(())
    }

    /// Decode from wire bytes: `varint(format_code) || digest`. Reads the
    /// LEB128 format varint (multi-byte capable per v7.67 §5.4), looks up
    /// the digest length for the format, and is length-strict. Rejects the
    /// `0xFF` reservation and unallocated codes with `UnsupportedAlgorithm`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HashError> {
        let (format_value, consumed) = read_varint_u32(bytes)?;
        if format_value == HASH_ALGORITHM_RESERVED_FF as u32 {
            return Err(HashError::ReservedFormat(HASH_ALGORITHM_RESERVED_FF));
        }
        let algorithm: u8 = format_value
            .try_into()
            .map_err(|_| HashError::UnsupportedAlgorithm(0xFE))?;
        let expected = digest_len_for_format(algorithm)
            .ok_or(HashError::UnsupportedAlgorithm(algorithm))?;
        let total = consumed + expected;
        if bytes.len() != total {
            return Err(HashError::InvalidLength {
                expected: total,
                actual: bytes.len(),
            });
        }
        Ok(Self::new(algorithm, &bytes[consumed..total]))
    }

    /// Encode to wire bytes: `varint(format_code) || digest`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.len as usize);
        push_varint_u32(&mut out, self.algorithm as u32);
        out.extend_from_slice(self.digest());
        out
    }

    /// Encode to a CBOR byte string wrapping the wire form.
    pub fn to_cbor(&self) -> Vec<u8> {
        let wire = self.to_bytes();
        let mut out = Vec::with_capacity(2 + wire.len());
        if wire.len() < 24 {
            out.push(0x40 | wire.len() as u8); // bstr, length in initial byte
        } else {
            out.push(0x58); // bstr, 1-byte length follows
            out.push(wire.len() as u8);
        }
        out.extend_from_slice(&wire);
        out
    }

    /// Decode from a CBOR byte string (the inverse of [`Hash::to_cbor`]).
    pub fn from_cbor(cbor: &[u8]) -> Result<Self, HashError> {
        if cbor.is_empty() {
            return Err(HashError::InvalidFormat("empty CBOR for hash".into()));
        }
        let (content_off, content_len) = match cbor[0] {
            0x58 => {
                if cbor.len() < 2 {
                    return Err(HashError::InvalidFormat("CBOR too short for hash".into()));
                }
                (2usize, cbor[1] as usize)
            }
            b @ 0x40..=0x57 => (1usize, (b - 0x40) as usize),
            other => {
                return Err(HashError::InvalidFormat(format!(
                    "expected CBOR bstr header, got {:02x}",
                    other
                )));
            }
        };
        if cbor.len() != content_off + content_len {
            return Err(HashError::InvalidLength {
                expected: content_off + content_len,
                actual: cbor.len(),
            });
        }
        Self::from_bytes(&cbor[content_off..])
    }

    /// Parse from display format: `"<format-string>:<hex digest>"`, e.g.
    /// `"ecfv1-sha256:<64 hex>"` or `"ecfv1-sha384:<96 hex>"`.
    pub fn from_display(s: &str) -> Result<Self, HashError> {
        let (tag, hex) = s.split_once(':').ok_or_else(|| {
            HashError::InvalidFormat(format!("expected '<format>:<hex>', got {:?}", s))
        })?;
        let algorithm = format_code_for_string(tag)
            .ok_or_else(|| HashError::InvalidFormat(format!("unknown format tag {:?}", tag)))?;
        let expected = digest_len_for_format(algorithm)
            .ok_or(HashError::UnsupportedAlgorithm(algorithm))?;
        if hex.len() != expected * 2 {
            return Err(HashError::InvalidFormat(format!(
                "expected {} hex chars for {}, got {}",
                expected * 2,
                tag,
                hex.len()
            )));
        }
        let mut digest = vec![0u8; expected];
        for i in 0..expected {
            digest[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| {
                HashError::InvalidFormat(format!("invalid hex at position {}", i * 2))
            })?;
        }
        Ok(Self::new(algorithm, &digest))
    }

    /// The SHA-256 zero hash (all-zero 32-byte digest).
    pub fn zero() -> Self {
        Self::new(HASH_ALGORITHM_SHA256, [0u8; SHA256_DIGEST_LEN])
    }

    /// Whether this is the SHA-256 zero hash.
    pub fn is_zero(&self) -> bool {
        self.algorithm == HASH_ALGORITHM_SHA256 && self.digest().iter().all(|&b| b == 0)
    }

    /// Lowercase hex of the full wire form (format varint + digest). This is
    /// the `{content_hash_hex}` segment of the V7 §3.5 invariant pointer
    /// path — 66 chars for SHA-256 (`00`-prefixed), 98 for SHA-384. The
    /// format byte is part of the address (V7 §1.2). Distinct from
    /// [`Display`](Hash#impl-Display), which hexes only the digest.
    pub fn to_hex(&self) -> String {
        hex_str(&self.to_bytes())
    }
}

impl PartialEq for Hash {
    fn eq(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm && self.digest() == other.digest()
    }
}

impl Eq for Hash {}

impl std::hash::Hash for Hash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.algorithm.hash(state);
        self.digest().hash(state);
    }
}

impl PartialOrd for Hash {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Hash {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.algorithm
            .cmp(&other.algorithm)
            .then_with(|| self.digest().cmp(other.digest()))
    }
}

/// The V7 §3.5 invariant signature pointer path:
/// `/{signer_peer_id}/system/signature/{target_hex}`.
///
/// **Single source (V7 §3.5 v7.45 "Discovery locality").** Every site that
/// *binds* or *resolves* a detached signature in the tree MUST construct the
/// path here — bind and resolve cannot drift, and there is exactly one
/// V7-general constructable path (no extension-private scheme). `signer` is
/// the signing peer's base58 peer id; `target` is the content hash of the
/// signed entity. Per V7 §3.5 v7.44, an extension that locally mints a
/// chain-participating capability MUST bind its signature here.
pub fn invariant_signature_path(signer_peer_id: &str, target: &Hash) -> String {
    format!("/{}/system/signature/{}", signer_peer_id, target.to_hex())
}

impl std::fmt::Debug for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hash({})", self)
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tag = format_string_for_code(self.algorithm).unwrap_or("ecfv1-unknown");
        write!(f, "{}:{}", tag, hex_str(self.digest()))
    }
}

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// LEB128 varint encoder for u32 (V7 §7.3 / v7.67 §5.4). Codes `< 0x80`
/// emit a single byte.
fn push_varint_u32(out: &mut Vec<u8>, mut value: u32) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// LEB128 varint decoder for u32 (V7 §7.3 / v7.67 §5.4). Returns
/// `(value, bytes_consumed)`. Multi-byte capable even though no current
/// allocation exceeds `0x7F`.
fn read_varint_u32(bytes: &[u8]) -> Result<(u32, usize), HashError> {
    let mut value: u32 = 0;
    let mut shift: u32 = 0;
    let mut consumed: usize = 0;
    for &b in bytes {
        consumed += 1;
        if shift >= 28 && (b & 0x80) != 0 {
            return Err(HashError::InvalidFormat("varint exceeds u32".into()));
        }
        value |= ((b & 0x7F) as u32) << shift;
        if (b & 0x80) == 0 {
            return Ok((value, consumed));
        }
        shift += 7;
        if consumed >= 5 {
            return Err(HashError::InvalidFormat("varint exceeds 5 bytes".into()));
        }
    }
    Err(HashError::InvalidFormat("truncated varint".into()))
}

#[derive(Debug, Error)]
pub enum HashError {
    #[error("invalid hash length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("unsupported hash algorithm: {0:#04x}")]
    UnsupportedAlgorithm(u8),

    /// v7.67 §5.3: integer value 255 is reserved on the
    /// `content_hash_format` axis and SHALL NOT be allocated. A stronger
    /// guarantee than mere "unallocated" — decoders MUST reject it.
    #[error("content_hash_format {0:#04x} is reserved (v7.67 §5.3)")]
    ReservedFormat(u8),

    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: Hash, actual: Hash },

    #[error("invalid hash format: {0}")]
    InvalidFormat(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_deterministic() {
        let data = entity_ecf::to_ecf(&entity_ecf::text("hello"));
        let h1 = Hash::compute("test/type", &data);
        let h2 = Hash::compute("test/type", &data);
        assert_eq!(h1, h2);
        assert_eq!(h1.algorithm, HASH_ALGORITHM_SHA256);
        assert!(!h1.is_zero());
    }

    #[test]
    fn test_compute_different_type_different_hash() {
        let data = entity_ecf::to_ecf(&entity_ecf::text("hello"));
        let h1 = Hash::compute("type/a", &data);
        let h2 = Hash::compute("type/b", &data);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_compute_different_data_different_hash() {
        let d1 = entity_ecf::to_ecf(&entity_ecf::text("hello"));
        let d2 = entity_ecf::to_ecf(&entity_ecf::text("world"));
        let h1 = Hash::compute("test/type", &d1);
        let h2 = Hash::compute("test/type", &d2);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_validate_success() {
        let data = entity_ecf::to_ecf(&entity_ecf::integer(42));
        let hash = Hash::compute("test/type", &data);
        assert!(Hash::validate("test/type", &data, &hash).is_ok());
    }

    #[test]
    fn test_validate_failure() {
        let data = entity_ecf::to_ecf(&entity_ecf::integer(42));
        let hash = Hash::compute("test/type", &data);
        let other_data = entity_ecf::to_ecf(&entity_ecf::integer(99));
        let result = Hash::validate("test/type", &other_data, &hash);
        assert!(matches!(result, Err(HashError::HashMismatch { .. })));
    }

    #[test]
    fn test_bytes_roundtrip() {
        let data = entity_ecf::to_ecf(&entity_ecf::text("test"));
        let hash = Hash::compute("test/type", &data);
        let bytes = hash.to_bytes();
        assert_eq!(bytes.len(), HASH_WIRE_LEN);
        assert_eq!(bytes[0], HASH_ALGORITHM_SHA256);
        let recovered = Hash::from_bytes(&bytes).unwrap();
        assert_eq!(hash, recovered);
    }

    #[test]
    fn test_from_bytes_wrong_length() {
        // varint 0x00 (SHA-256) wants 32 digest bytes; only 9 follow.
        assert!(matches!(
            Hash::from_bytes(&[0u8; 10]),
            Err(HashError::InvalidLength { expected: 33, actual: 10 })
        ));
    }

    #[test]
    fn test_cbor_roundtrip() {
        let data = entity_ecf::to_ecf(&entity_ecf::text("test"));
        let hash = Hash::compute("test/type", &data);
        let cbor = hash.to_cbor();
        assert_eq!(cbor[0], 0x58);
        assert_eq!(cbor[1], 0x21);
        assert_eq!(cbor.len(), 35); // 2 header + 33 wire
        let recovered = Hash::from_cbor(&cbor).unwrap();
        assert_eq!(hash, recovered);
    }

    #[test]
    fn test_cbor_wire_format() {
        let hash = Hash::zero();
        let cbor = hash.to_cbor();
        assert_eq!(cbor[0], 0x58); // byte string, 1-byte length
        assert_eq!(cbor[1], 0x21); // length = 33
        assert_eq!(cbor[2], 0x00); // algorithm
        assert_eq!(&cbor[3..], &[0u8; 32]); // zero digest
    }

    #[test]
    fn test_from_cbor_invalid_header() {
        assert!(Hash::from_cbor(&[0x24, 0x21]).is_err());
    }

    #[test]
    fn test_display_format() {
        let hash = Hash::zero();
        let s = hash.to_string();
        assert!(s.starts_with("ecfv1-sha256:"));
        assert_eq!(
            s,
            "ecfv1-sha256:0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn test_display_roundtrip() {
        let data = entity_ecf::to_ecf(&entity_ecf::text("roundtrip"));
        let hash = Hash::compute("test/type", &data);
        let s = hash.to_string();
        let recovered = Hash::from_display(&s).unwrap();
        assert_eq!(hash, recovered);
    }

    #[test]
    fn test_from_display_invalid_prefix() {
        assert!(Hash::from_display("sha256:abcd").is_err());
    }

    #[test]
    fn test_from_display_invalid_length() {
        assert!(Hash::from_display("ecfv1-sha256:abcd").is_err());
    }

    #[test]
    fn test_zero_hash() {
        let z = Hash::zero();
        assert!(z.is_zero());
        let data = entity_ecf::to_ecf(&entity_ecf::text("not zero"));
        let h = Hash::compute("test", &data);
        assert!(!h.is_zero());
    }

    #[test]
    fn test_ord_impl() {
        let d1 = entity_ecf::to_ecf(&entity_ecf::text("aaa"));
        let d2 = entity_ecf::to_ecf(&entity_ecf::text("bbb"));
        let h1 = Hash::compute("test", &d1);
        let h2 = Hash::compute("test", &d2);
        let mut hashes = [h2, h1];
        hashes.sort();
        assert_eq!(hashes[0], std::cmp::min(h1, h2));
    }

    #[test]
    fn test_debug_format() {
        let hash = Hash::zero();
        let debug = format!("{:?}", hash);
        assert!(debug.starts_with("Hash(ecfv1-sha256:"));
    }

    // --- v7.69: SHA-384 through the unified Hash type ---

    #[test]
    fn sha384_compute_wire_round_trip() {
        let data = entity_ecf::to_ecf(&entity_ecf::text("hello v7.69"));
        let h = Hash::compute_format("test/type", &data, HASH_ALGORITHM_SHA384).unwrap();
        assert_eq!(h.algorithm, HASH_ALGORITHM_SHA384);
        assert_eq!(h.digest().len(), SHA384_DIGEST_LEN);
        let wire = h.to_bytes();
        assert_eq!(wire.len(), 1 + SHA384_DIGEST_LEN); // 49 bytes
        assert_eq!(wire[0], 0x01);
        let h2 = Hash::from_bytes(&wire).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn sha384_cbor_round_trip() {
        let data = entity_ecf::to_ecf(&entity_ecf::text("cbor 384"));
        let h = Hash::compute_format("test/type", &data, HASH_ALGORITHM_SHA384).unwrap();
        let cbor = h.to_cbor();
        assert_eq!(cbor[0], 0x58);
        assert_eq!(cbor[1], 0x31); // 49
        let h2 = Hash::from_cbor(&cbor).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn sha256_sha384_distinct_under_same_input() {
        let data = entity_ecf::to_ecf(&entity_ecf::text("same input"));
        let a = Hash::compute_format("t", &data, HASH_ALGORITHM_SHA256).unwrap();
        let b = Hash::compute_format("t", &data, HASH_ALGORITHM_SHA384).unwrap();
        assert_ne!(a, b);
        assert_eq!(a, Hash::compute("t", &data)); // SHA-256 parity
    }

    #[test]
    fn sha384_display_round_trip() {
        let data = entity_ecf::to_ecf(&entity_ecf::text("disp 384"));
        let h = Hash::compute_format("t", &data, HASH_ALGORITHM_SHA384).unwrap();
        let s = h.to_string();
        assert!(s.starts_with("ecfv1-sha384:"));
        assert_eq!(s.len(), "ecfv1-sha384:".len() + SHA384_DIGEST_LEN * 2);
        assert_eq!(Hash::from_display(&s).unwrap(), h);
    }

    #[test]
    fn unsupported_format_rejected() {
        let data = entity_ecf::to_ecf(&entity_ecf::text("x"));
        assert!(matches!(
            Hash::compute_format("t", &data, 0x7E),
            Err(HashError::UnsupportedAlgorithm(0x7E))
        ));
    }

    #[test]
    fn from_bytes_multibyte_varint_then_unallocated() {
        // varint(128) = [0x80, 0x01] + 32-byte digest; 128 is unallocated.
        let mut wire = vec![0x80, 0x01];
        wire.extend_from_slice(&[0u8; 32]);
        assert!(matches!(
            Hash::from_bytes(&wire),
            Err(HashError::UnsupportedAlgorithm(0x80))
        ));
    }

    #[test]
    fn from_bytes_reserved_ff_rejected() {
        // varint(255) = [0xFF, 0x01] + digest.
        let mut wire = vec![0xFF, 0x01];
        wire.extend_from_slice(&[0u8; 32]);
        assert!(matches!(
            Hash::from_bytes(&wire),
            Err(HashError::ReservedFormat(0xFF))
        ));
    }

    #[test]
    fn format_string_code_mapping() {
        assert_eq!(format_code_for_string("ecfv1-sha256"), Some(0x00));
        assert_eq!(format_code_for_string("ecfv1-sha384"), Some(0x01));
        assert_eq!(format_code_for_string("ecfv1-bogus"), None);
        assert_eq!(format_string_for_code(0x00), Some("ecfv1-sha256"));
        assert_eq!(format_string_for_code(0x01), Some("ecfv1-sha384"));
    }
}
