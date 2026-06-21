//! Ed25519 keypair, PeerID, sign/verify.
//!
//! Identity is an Ed25519 keypair. PeerID = Base58(varint(key_type) ||
//! varint(hash_type) || digest) per V7 §1.5 / §7.3 (v7.66 LEB128
//! multicodec varint encoding; v7.64 identity-multihash bundle).
//! `hash_type = 0x00` (identity multihash, recommended for Ed25519) makes
//! the PeerID self-resolving: the digest IS the public_key. `hash_type =
//! 0x01` (SHA-256) is the legacy fingerprint form, retained on the
//! wire-acceptance decode side per V7 §1.5 v7.65 Amendment 4 but no longer
//! constructible from raw components per v7.66 §3.
//!
//! **Two-surface `key_type` (v7.66 §2 errata).** `key_type` appears on two
//! structurally distinct surfaces:
//!
//! - **Binary peer_id wire-format prefix** — a multicodec LEB128 varint
//!   per V7 §1.5 / §7.3. For codes 0–127 this is a single byte; for codes
//!   ≥128 (e.g., `0xFE`) it extends to a 2-byte LEB128 sequence. Encoded
//!   via [`PeerId::from_public_key_with_key_type`] / decoded by
//!   [`PeerId::decode`].
//! - **`system/peer.data.key_type` entity-data field** — a primitive
//!   string. Canonical: `"ed25519"` for Ed25519, `"experimental-test"` for
//!   `0xFE`. Encoded via [`peer_entity_from_components_with_key_type`].
//!
//! `content_hash(system/peer)` is a pure function of the entity-data
//! string surface (per v7.65 §3 P×I primitive discipline); the binary
//! varint surface is presentation/routing only. The two MUST NOT be
//! conflated. See [`KeyType`] for the central allocation table.

use std::path::Path;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signer, Verifier};
use entity_entity::Entity;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Key type identifier for Ed25519 (production allocation per V7 §1.5).
pub const KEY_TYPE_ED25519: u8 = 0x01;

/// Key type identifier for Ed448 (V7 §1.5 / v7.67 §3 allocation, Phase 1
/// validation). Classical-stronger same-family successor to Ed25519. Raw
/// 57-byte pubkey exceeds the v7.65 §4 informative substrate floor, so the
/// canonical form is SHA-256-form (`hash_type = 0x01`).
pub const KEY_TYPE_ED448: u8 = 0x02;

/// Key type identifier for the v7.66 §4 experimental-test allocation.
/// **NOT for production use.** Exists solely to exercise the
/// per-`key_type` agility code paths cross-impl. Fixed 64-byte synthetic
/// `public_key` (`0xAA` × 64); canonical form is SHA-256 (`hash_type =
/// 0x01`), forced by size. No sign/verify semantics — impls SHALL refuse
/// signature operations with [`CryptoError::UnsupportedKeyType`].
pub const KEY_TYPE_EXPERIMENTAL_TEST: u8 = 0xFE;

/// Hash type identifier for identity multihash (digest IS the public_key).
/// V7 §1.5 v7.64 recommended default for short key types (Ed25519, secp256k1, X25519).
pub const HASH_TYPE_IDENTITY: u8 = 0x00;

/// Hash type identifier for SHA-256 (fingerprint form). Canonical for
/// `0xFE` per v7.66 §4; legacy-decode-only for Ed25519 per v7.65 §1.5
/// Amendment 4.
pub const HASH_TYPE_SHA256: u8 = 0x01;

/// Raw public key length for Ed25519.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// Raw public key length for Ed448 (RFC 8032). 57 bytes; exceeds the v7.65
/// §4 substrate floor so canonical form is SHA-256-form.
pub const ED448_PUBLIC_KEY_LEN: usize = 57;

/// Raw signature length for Ed448 (RFC 8032). Detached signatures are 114
/// bytes — 2× Ed25519's 64 — relevant for cap-chain size budgets in
/// v7.67 Phase 2's MATRIX-M2/M6 vectors.
pub const ED448_SIGNATURE_LEN: usize = 114;

/// Raw secret seed length for Ed448 (RFC 8032). 57 bytes.
pub const ED448_SECRET_KEY_LEN: usize = 57;

/// Raw public key length for `KEY_TYPE_EXPERIMENTAL_TEST` per v7.66 §4.2.
/// Sized above Ed25519's 32 bytes to force SHA-256-form canonical
/// selection (identity-form would exceed substrate-compatibility floors).
pub const EXPERIMENTAL_TEST_PUBLIC_KEY_LEN: usize = 64;

/// Length of an Ed25519 PeerID's raw bytes (both identity- and SHA-256-form):
/// varint(key_type)=1 byte (Ed25519's 0x01 fits) + varint(hash_type)=1 byte
/// (0x00 and 0x01 both fit) + digest=32 bytes. For codes ≥128 this is
/// 2+2+digest; see [`PeerId::decode`].
pub const PEER_ID_BYTE_LEN: usize = 34;

/// Central allocation table for `key_type` per V7 §1.5 v7.66 reserved-range
/// table. Codifies the two-surface mapping (varint byte / entity-data
/// string), the canonical `hash_type`, the expected `public_key` length,
/// and signature support — eliminating per-callsite hardcoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// Production Ed25519 — V7 §1.5 / canonical `hash_type = 0x00`
    /// identity-multihash per v7.65 §4.
    Ed25519,
    /// v7.67 §3 Ed448 (`0x02`). Phase 1 validation allocation —
    /// classical-stronger same-family successor to Ed25519. Canonical
    /// `hash_type = 0x01` SHA-256-form (57-byte raw pubkey exceeds the
    /// v7.65 §4 substrate floor). 114-byte signatures. Full sign/verify
    /// semantics via [`Ed448Keypair`].
    Ed448,
    /// v7.66 §4 experimental-test (`0xFE`). NOT for production. Canonical
    /// `hash_type = 0x01` SHA-256-form. 64-byte synthetic `public_key`.
    /// No sign/verify semantics.
    ExperimentalTest,
}

impl KeyType {
    /// Binary peer_id wire-format prefix value (decoded from the varint
    /// per V7 §1.5). Single byte 0–255.
    pub const fn byte(self) -> u8 {
        match self {
            Self::Ed25519 => KEY_TYPE_ED25519,
            Self::Ed448 => KEY_TYPE_ED448,
            Self::ExperimentalTest => KEY_TYPE_EXPERIMENTAL_TEST,
        }
    }

    /// Canonical `system/peer.data.key_type` entity-data string per V7
    /// §3.5 (v7.66 pin — no longer "e.g.").
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::Ed448 => "ed448",
            Self::ExperimentalTest => "experimental-test",
        }
    }

    /// Canonical `hash_type` per v7.65 §4 / v7.66 §4.2 / v7.67 §3.2.
    pub const fn canonical_hash_type(self) -> u8 {
        match self {
            Self::Ed25519 => HASH_TYPE_IDENTITY,
            Self::Ed448 => HASH_TYPE_SHA256,
            Self::ExperimentalTest => HASH_TYPE_SHA256,
        }
    }

    /// Expected raw `public_key` byte length.
    pub const fn public_key_len(self) -> usize {
        match self {
            Self::Ed25519 => ED25519_PUBLIC_KEY_LEN,
            Self::Ed448 => ED448_PUBLIC_KEY_LEN,
            Self::ExperimentalTest => EXPERIMENTAL_TEST_PUBLIC_KEY_LEN,
        }
    }

    /// Whether the `key_type` has sign/verify semantics defined. `0xFE`
    /// is wire/path/canonical-form test-only — impls SHALL refuse
    /// signature operations.
    pub const fn supports_signing(self) -> bool {
        match self {
            Self::Ed25519 => true,
            Self::Ed448 => true,
            Self::ExperimentalTest => false,
        }
    }

    /// Decode from the binary prefix byte (post-varint). Returns
    /// [`CryptoError::UnsupportedKeyType`] for unallocated codes — V7
    /// §4.7 `400 unsupported_key_type` surface.
    ///
    /// v7.67 §5 reservation: integer value `255` (`0xFF`) is reserved on
    /// the `key_type` axis and SHALL NOT be allocated to any algorithm.
    /// Falls through to the `UnsupportedKeyType` arm.
    pub fn from_byte(b: u8) -> Result<Self, CryptoError> {
        match b {
            KEY_TYPE_ED25519 => Ok(Self::Ed25519),
            KEY_TYPE_ED448 => Ok(Self::Ed448),
            KEY_TYPE_EXPERIMENTAL_TEST => Ok(Self::ExperimentalTest),
            other => Err(CryptoError::UnsupportedKeyType(other)),
        }
    }

    /// Decode from the `system/peer.data.key_type` entity-data string.
    pub fn from_label(s: &str) -> Result<Self, CryptoError> {
        match s {
            "ed25519" => Ok(Self::Ed25519),
            "ed448" => Ok(Self::Ed448),
            "experimental-test" => Ok(Self::ExperimentalTest),
            other => Err(CryptoError::InvalidPeerId(format!(
                "unknown key_type label: {:?}",
                other
            ))),
        }
    }
}

/// Verify a detached signature, dispatching the algorithm on `key_type`
/// (v7.67 Phase 2 — MATRIX-M2 cross-key handshake). The verifier decodes
/// `key_type` from the signer's `system/peer` entity (`PeerData.key_type`)
/// or peer_id wire-prefix, then routes to the matching scheme. `public_key`
/// length MUST match `key_type.public_key_len()`.
///
/// Returns [`CryptoError::UnsupportedKeyType`] for key_types without
/// sign/verify semantics (e.g. `experimental-test`) — V7 §4.7
/// `400 unsupported_key_type`.
pub fn verify_for_key_type(
    key_type: KeyType,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    match key_type {
        KeyType::Ed25519 => {
            let pk: [u8; ED25519_PUBLIC_KEY_LEN] = public_key
                .try_into()
                .map_err(|_| CryptoError::InvalidPublicKey)?;
            Keypair::verify(&pk, message, signature)
        }
        KeyType::Ed448 => {
            let pk: [u8; ED448_PUBLIC_KEY_LEN] = public_key
                .try_into()
                .map_err(|_| CryptoError::InvalidPublicKey)?;
            Ed448Keypair::verify(&pk, message, signature)
        }
        KeyType::ExperimentalTest => Err(CryptoError::UnsupportedKeyType(key_type.byte())),
    }
}

/// LEB128 multicodec varint encoder for u8 values per V7 §1.5 / §7.3.
/// Values 0–127 encode as a single byte (no continuation); values ≥128
/// encode as 2 bytes (`0x80 | low7`, then `value >> 7`).
fn push_varint_u8(out: &mut Vec<u8>, v: u8) {
    if v < 0x80 {
        out.push(v);
    } else {
        out.push(0x80 | (v & 0x7F));
        out.push(v >> 7);
    }
}

/// LEB128 multicodec varint decoder for u8 values. Returns `(value,
/// bytes_consumed)`. Rejects 3+ byte sequences (overflow beyond u8) and
/// truncated continuations.
fn read_varint_u8(bytes: &[u8]) -> Result<(u8, usize), CryptoError> {
    if bytes.is_empty() {
        return Err(CryptoError::InvalidPeerId("varint: empty input".into()));
    }
    let b0 = bytes[0];
    if b0 < 0x80 {
        return Ok((b0, 1));
    }
    if bytes.len() < 2 {
        return Err(CryptoError::InvalidPeerId(
            "varint: truncated continuation".into(),
        ));
    }
    let b1 = bytes[1];
    if b1 & 0x80 != 0 {
        return Err(CryptoError::InvalidPeerId(
            "varint: value exceeds u8 (3+ byte sequence)".into(),
        ));
    }
    let value = ((b0 & 0x7F) as u16) | ((b1 as u16) << 7);
    if value > 255 {
        return Err(CryptoError::InvalidPeerId(format!(
            "varint: value {} exceeds u8",
            value
        )));
    }
    Ok((value as u8, 2))
}

/// Entity type for peer (keypair) entities. PR-1 (PROPOSAL-SYSTEM-PEER-RENAME):
/// V7 type tag renamed `system/identity` → `system/peer`.
pub const TYPE_PEER: &str = "system/peer";

/// An Ed25519 keypair for signing and identity.
pub struct Keypair {
    inner: ed25519_dalek::SigningKey,
}

impl Keypair {
    /// Generate a new random keypair.
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        Self {
            inner: ed25519_dalek::SigningKey::generate(&mut OsRng),
        }
    }

    /// Create a keypair from a 32-byte seed (deterministic).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            inner: ed25519_dalek::SigningKey::from_bytes(&seed),
        }
    }

    /// Sign a message, returning a 64-byte Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.inner.sign(message).to_bytes()
    }

    /// Verify a signature against a public key (static method).
    pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public_key)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify(message, &sig)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    /// Get the raw 32-byte public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.inner.verifying_key().to_bytes()
    }

    /// The [`KeyType`] this keypair signs under — `Ed25519`. Single source
    /// of truth for the `system/peer` / authenticate `key_type` entity-data
    /// string (v7.67 Phase 2 — no hardcoded `"ed25519"` literal on the wire).
    pub const fn key_type(&self) -> KeyType {
        KeyType::Ed25519
    }

    /// Get the verifying (public) key.
    pub fn public_key(&self) -> ed25519_dalek::VerifyingKey {
        self.inner.verifying_key()
    }

    /// Derive the PeerID for this keypair — canonical form per V7 §1.5
    /// v7.65 (Ed25519 → `hash_type=0x00` identity-multihash).
    pub fn peer_id(&self) -> PeerId {
        PeerId::from_public_key(&self.public_key_bytes())
    }

    /// Derive the PeerID with explicit `hash_type` — Ed25519
    /// construction gate. Under V7 §1.5 v7.65 the only canonical form
    /// for Ed25519 is `HASH_TYPE_IDENTITY`; this method refuses
    /// `HASH_TYPE_SHA256` for fresh construction per Amendment 3
    /// (canonical-form mandate). The legacy live-mint
    /// `from_public_key_sha256` helper was removed in v7.66 §3; tests
    /// that need SHA-256-form fixtures synthesize them via raw varint +
    /// digest assembly (the wire-acceptance decode path remains
    /// permissive — see [`PeerId::decode`]).
    pub fn peer_id_with_hash_type(&self, hash_type: u8) -> Result<PeerId, CryptoError> {
        PeerId::from_public_key_with_hash_type(&self.public_key_bytes(), hash_type)
    }

    /// Get the raw 32-byte secret key (seed).
    ///
    /// **Use sparingly.** This is the single point through which raw
    /// secret bytes leave the type. Every materialization downstream of
    /// this method is auditable as a keystore-boundary surface.
    /// For in-process duplication of a Keypair, prefer
    /// [`Self::clone_inner`] — it clones the internal Ed25519 state
    /// without exposing seed bytes to caller code.
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// Duplicate this keypair in-process without materializing the seed.
    ///
    /// Equivalent to `Keypair::from_seed(self.secret_key_bytes())`
    /// but never exposes a raw `[u8; 32]` to caller code; the secret
    /// material stays inside the `ed25519_dalek::SigningKey` clone.
    /// Use this anywhere a Keypair needs to be moved into a sibling
    /// struct (e.g. building a `PeerShared` from an existing `Peer`).
    ///
    /// `Keypair` deliberately does not implement `Clone` so that
    /// duplication is always an explicit, audit-visible act — see
    /// the audit doc cited on [`Self::secret_key_bytes`].
    pub fn clone_inner(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }

    /// Get the public key as a base64 string.
    pub fn public_key_base64(&self) -> String {
        BASE64.encode(self.public_key_bytes())
    }

    /// Encode the private key as a PEM string. Same format as
    /// [`Self::save_to_file`] but without the IO — used by the SDK's
    /// `IdentityBundle` to ship keypair material as bytes regardless
    /// of consumer storage backend (filesystem / OPFS / IPC / etc.).
    pub fn to_pem(&self) -> String {
        let encoded = BASE64.encode(self.inner.to_bytes());
        format!(
            "-----BEGIN ENTITY PRIVATE KEY-----\n{}\n-----END ENTITY PRIVATE KEY-----\n",
            encoded
        )
    }

    /// Decode a keypair from a PEM string produced by [`Self::to_pem`]
    /// (or by [`Self::save_to_file`]).
    pub fn from_pem(pem: &str) -> Result<Self, CryptoError> {
        let b64 = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        let decoded = BASE64
            .decode(b64.trim())
            .map_err(|e| CryptoError::IoError(format!("base64 decode: {}", e)))?;
        let seed: [u8; 32] = decoded
            .try_into()
            .map_err(|_| CryptoError::IoError("private key must be 32 bytes".into()))?;
        Ok(Self::from_seed(seed))
    }

    /// Save the keypair to a file (PEM-wrapped private key + `.pub` file).
    pub fn save_to_file(&self, path: &Path) -> Result<(), CryptoError> {
        let pem = self.to_pem();
        std::fs::write(path, pem).map_err(|e| CryptoError::IoError(e.to_string()))?;

        // Write public key file
        let pub_path = path.with_extension("pub");
        let pub_line = format!(
            "entity-ed25519 {} {}\n",
            self.public_key_base64(),
            self.peer_id()
        );
        std::fs::write(pub_path, pub_line).map_err(|e| CryptoError::IoError(e.to_string()))?;

        Ok(())
    }

    /// Load a keypair from a PEM-wrapped private key file.
    pub fn load_from_file(path: &Path) -> Result<Self, CryptoError> {
        let contents =
            std::fs::read_to_string(path).map_err(|e| CryptoError::IoError(e.to_string()))?;
        Self::from_pem(&contents)
    }

    /// Check if a keypair file exists at the given path.
    pub fn exists_at(path: &Path) -> bool {
        path.exists()
    }

    /// Create a `system/peer` entity for this keypair.
    ///
    /// V7 §3.5 v7.65: data is ECF-encoded `{key_type, public_key}` only;
    /// `peer_id` is NOT part of the hashable basis (Amendment 1+2 — P×I
    /// primitive discipline). `content_hash(system/peer)` is a pure function
    /// of `(public_key, key_type)` and invariant under wire-form `peer_id`
    /// choice. Pinned `key_type` string is `"ed25519"` per V7 §3.5 v7.66
    /// (no longer "e.g.").
    pub fn peer_entity(&self) -> Result<Entity, CryptoError> {
        peer_entity_from_components(&self.public_key_bytes())
    }

    /// Compute `content_hash(system/peer)` for this keypair — V7 §1.4 path
    /// segment value at non-universal-root positions. Under v7.65 this is
    /// the unique cryptographic identity per `(public_key, key_type)`.
    pub fn peer_identity_hash(&self) -> entity_hash::Hash {
        self.peer_entity()
            .expect("system/peer entity for own keypair is always constructible")
            .content_hash
    }
}

/// Construct a `system/peer` entity for an Ed25519 keypair — V7 §3.5
/// v7.65 / v7.66 §3.5 pin.
///
/// Convenience wrapper around [`peer_entity_from_components_with_key_type`]
/// for the production Ed25519 path. Data is ECF-encoded `{key_type,
/// public_key}` only with `key_type = "ed25519"` (canonical entity-data
/// string per V7 §3.5 v7.66). `peer_id` is NOT a hashable field
/// (v7.65 Amendment 1+2 — P×I primitive discipline). The resulting
/// `content_hash` is a pure function of `(public_key, key_type)` and
/// invariant under wire-form `peer_id` choice; cap chains, signatures,
/// and identity bindings inherit this invariance.
pub fn peer_entity_from_components(public_key: &[u8; 32]) -> Result<Entity, CryptoError> {
    peer_entity_from_components_with_key_type(public_key, KeyType::Ed25519)
}

/// Construct a `system/peer` entity from raw components for any
/// allocated `key_type` per V7 §1.5 v7.66 reserved-range table.
///
/// `public_key` length MUST match `key_type.public_key_len()`. The
/// `key_type` field is encoded as `key_type.label()` (entity-data string
/// surface — distinct from the binary peer_id wire prefix per v7.66 §2
/// errata). Hashable basis: `{key_type, public_key}` only.
pub fn peer_entity_from_components_with_key_type(
    public_key: &[u8],
    key_type: KeyType,
) -> Result<Entity, CryptoError> {
    peer_entity_from_components_with_format(
        public_key,
        key_type,
        entity_hash::default_hash_format(),
    )
}

/// Construct a `system/peer` entity under an explicit `content_hash_format`
/// (V7 §4.5a — author the local identity under the connection's negotiated
/// active format). The hashable basis (`{key_type, public_key}`) is
/// identical across formats; only the `content_hash` digest algorithm
/// differs. Home-format callers use
/// [`peer_entity_from_components_with_key_type`] (process home default).
pub fn peer_entity_from_components_with_format(
    public_key: &[u8],
    key_type: KeyType,
    format_code: u8,
) -> Result<Entity, CryptoError> {
    if public_key.len() != key_type.public_key_len() {
        return Err(CryptoError::InvalidPublicKey);
    }
    let data_value = entity_ecf::Value::Map(vec![
        (entity_ecf::text("key_type"), entity_ecf::text(key_type.label())),
        (
            entity_ecf::text("public_key"),
            entity_ecf::Value::Bytes(public_key.to_vec()),
        ),
    ]);
    let data = entity_ecf::to_ecf(&data_value);
    Entity::new_with_format(TYPE_PEER, data, format_code)
        .map_err(|e| CryptoError::IdentityError(e.to_string()))
}

/// Compute `content_hash(system/peer)` for an Ed25519 peer with known
/// `public_key`. V7 §1.4 v7.65: pure function of `public_key` (and
/// key_type, fixed to Ed25519). Single cryptographic identity per keypair.
pub fn peer_identity_hash(public_key: &[u8; 32]) -> Result<entity_hash::Hash, CryptoError> {
    Ok(peer_entity_from_components(public_key)?.content_hash)
}

/// Compute `content_hash(system/peer)` for any allocated `key_type`.
/// v7.66 §4 / agility-validation surface 4 (P×I primitive discipline
/// applies uniformly).
pub fn peer_identity_hash_with_key_type(
    public_key: &[u8],
    key_type: KeyType,
) -> Result<entity_hash::Hash, CryptoError> {
    Ok(peer_entity_from_components_with_key_type(public_key, key_type)?.content_hash)
}

/// Synthesize a PeerID for a fixture with arbitrary `key_type` /
/// `hash_type` / `digest` bytes. Used to exercise wire-decode paths
/// (AGILITY-UNKNOWN-1 regression guards, length-agnostic decoder tests)
/// where the test deliberately constructs a peer_id with a `key_type`
/// outside the impl's supported set to verify the rejection surface
/// (`400 unsupported_key_type`).
///
/// **Do NOT call from production paths.** Mint paths must derive
/// canonical form via [`PeerId::from_public_key`] /
/// [`PeerId::from_public_key_with_key_type`].
pub fn synthesize_peer_id_for_fixture(key_type: u8, hash_type: u8, digest: &[u8]) -> PeerId {
    let mut raw = Vec::with_capacity(4 + digest.len());
    push_varint_u8(&mut raw, key_type);
    push_varint_u8(&mut raw, hash_type);
    raw.extend_from_slice(digest);
    PeerId(bs58::encode(&raw).into_string())
}

/// Construct a legacy SHA-256-form Ed25519 PeerID **for wire-acceptance
/// decode-parity fixtures only** per v7.66 §3.4. The live-mint path
/// (`from_public_key_sha256`) was removed at v7.66 §3; pre-built
/// SHA-256-form byte strings are still required as opaque corpus
/// fixtures to exercise the §5 wire-acceptance carve-out (decoders MUST
/// continue to accept legacy form + canonicalize on storage).
///
/// **Do NOT call from production mint paths.** This function exists
/// only to keep conformance fixtures shippable; if you find yourself
/// reaching for it outside a test or fixture-corpus utility, you almost
/// certainly want [`PeerId::from_public_key`] instead.
pub fn legacy_sha256_peer_id_fixture(public_key: &[u8; 32]) -> PeerId {
    let digest = Sha256::digest(public_key).to_vec();
    let mut raw = Vec::with_capacity(2 + digest.len());
    push_varint_u8(&mut raw, KEY_TYPE_ED25519);
    push_varint_u8(&mut raw, HASH_TYPE_SHA256);
    raw.extend_from_slice(&digest);
    PeerId(bs58::encode(&raw).into_string())
}

/// A peer identifier: Base58-encoded `key_type || hash_type || digest`
/// per V7 §1.5 v7.64. Two forms are supported indefinitely:
/// - **Identity multihash** (`hash_type = 0x00`, recommended): `digest = public_key`.
///   The PeerID is self-resolving — [`Self::derive_public_key`] returns `Some`.
/// - **SHA-256 fingerprint** (`hash_type = 0x01`, legacy): `digest = SHA-256(public_key)`.
///   The PeerID hides the key until handshake; [`Self::derive_public_key`] returns `None`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerId(String);

/// Decoded components of a PeerID. `digest` length varies by `(key_type,
/// hash_type)`; for Ed25519 + identity it's the 32-byte public_key, for
/// SHA-256 form it's the 32-byte fingerprint. Length-agnostic per V7 §2.8
/// PIM-5 (future key types may use longer digests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPeerId {
    pub key_type: u8,
    pub hash_type: u8,
    pub digest: Vec<u8>,
}

impl PeerId {
    /// Derive a PeerID from a raw 32-byte Ed25519 public key, canonical
    /// identity-multihash form (V7 §1.5 v7.65 canonical-form mandate).
    /// The resulting PeerID embeds the public_key directly:
    /// [`Self::derive_public_key`] returns `Some`.
    pub fn from_public_key(public_key: &[u8; 32]) -> Self {
        // SAFETY: HASH_TYPE_IDENTITY is always supported.
        Self::from_public_key_with_hash_type(public_key, HASH_TYPE_IDENTITY)
            .expect("identity hash_type is always supported")
    }

    /// Derive a PeerID with explicit `hash_type` — Ed25519 construction
    /// gate per V7 §1.5 v7.65 Amendment 3 (canonical-form mandate).
    /// `HASH_TYPE_SHA256` is rejected at fresh construction; the wire-
    /// decode path ([`Self::decode`]) remains permissive per §5
    /// wire-acceptance carve-out. The legacy live-mint helper
    /// `from_public_key_sha256` was removed in v7.66 §3.
    ///
    /// For non-Ed25519 allocations (e.g., `KeyType::ExperimentalTest`),
    /// use [`Self::from_public_key_with_key_type`].
    pub fn from_public_key_with_hash_type(
        public_key: &[u8; 32],
        hash_type: u8,
    ) -> Result<Self, CryptoError> {
        match hash_type {
            HASH_TYPE_IDENTITY => Self::encode_raw(KeyType::Ed25519, hash_type, public_key),
            HASH_TYPE_SHA256 => Err(CryptoError::InvalidPeerId(
                "V7 §1.5 v7.65: SHA-256-form is legacy-decode-only for Ed25519; \
                 canonical form is HASH_TYPE_IDENTITY (Amendment 3)"
                    .into(),
            )),
            other => Err(CryptoError::InvalidPeerId(format!(
                "unsupported hash_type for derivation: {:#04x}",
                other
            ))),
        }
    }

    /// Derive a PeerID in canonical form for any allocated `key_type`.
    /// v7.66 §4 agility-validation surface 1 (multikey wire-format
    /// construction).
    ///
    /// `public_key.len()` MUST equal `key_type.public_key_len()`. The
    /// canonical `hash_type` is selected from `key_type.canonical_hash_type()`:
    /// Ed25519 → identity (digest = public_key); `ExperimentalTest` →
    /// SHA-256 (digest = SHA-256(public_key)).
    pub fn from_public_key_with_key_type(
        public_key: &[u8],
        key_type: KeyType,
    ) -> Result<Self, CryptoError> {
        if public_key.len() != key_type.public_key_len() {
            return Err(CryptoError::InvalidPublicKey);
        }
        Self::encode_raw(key_type, key_type.canonical_hash_type(), public_key)
    }

    /// Shared assembly: digest selection per `hash_type` (identity uses
    /// raw public_key; SHA-256 hashes it), then `varint(key_type) ||
    /// varint(hash_type) || digest` per V7 §1.5 / §7.3, Base58-encoded.
    fn encode_raw(
        key_type: KeyType,
        hash_type: u8,
        public_key: &[u8],
    ) -> Result<Self, CryptoError> {
        let digest: Vec<u8> = match hash_type {
            HASH_TYPE_IDENTITY => public_key.to_vec(),
            HASH_TYPE_SHA256 => Sha256::digest(public_key).to_vec(),
            other => {
                return Err(CryptoError::InvalidPeerId(format!(
                    "unsupported hash_type: {:#04x}",
                    other
                )))
            }
        };
        let mut raw = Vec::with_capacity(4 + digest.len());
        push_varint_u8(&mut raw, key_type.byte());
        push_varint_u8(&mut raw, hash_type);
        raw.extend_from_slice(&digest);
        Ok(Self(bs58::encode(&raw).into_string()))
    }

    /// Derive an identity-multihash-form PeerID from a keypair (default).
    pub fn from_keypair(keypair: &Keypair) -> Self {
        Self::from_public_key(&keypair.public_key_bytes())
    }

    /// Decode the PeerID into its `(key_type, hash_type, digest)` components.
    /// V7 §1.5 v7.66: `key_type` and `hash_type` are LEB128 varints — for
    /// codes 0–127 a single byte each (so v7.65 Ed25519 PeerIDs decode
    /// byte-for-byte identically), for codes ≥128 (e.g., `0xFE`) two
    /// bytes each. Length-agnostic for the digest: any remaining bytes
    /// after the two varints are the digest (PIM-5 forward-compat).
    pub fn decode(&self) -> Result<DecodedPeerId, CryptoError> {
        let raw = bs58::decode(&self.0)
            .into_vec()
            .map_err(|e| CryptoError::InvalidPeerId(format!("base58 decode: {}", e)))?;
        let (key_type, n1) = read_varint_u8(&raw)?;
        let (hash_type, n2) = read_varint_u8(&raw[n1..])?;
        if raw.len() <= n1 + n2 {
            return Err(CryptoError::InvalidPeerId(format!(
                "peer-id too short: {} bytes (need >= {} for varints + 1 digest byte)",
                raw.len(),
                n1 + n2 + 1
            )));
        }
        Ok(DecodedPeerId {
            key_type,
            hash_type,
            digest: raw[n1 + n2..].to_vec(),
        })
    }

    /// Extract `(public_key, key_type)` from an identity-multihash-form PeerID
    /// (V7 §7.4 `derive_peer_from_peer_id` helper). Returns `None` for
    /// SHA-256-form PeerIDs (fingerprint — public_key must come from a
    /// separate exchange), and for length mismatches against the key_type's
    /// expected public_key size.
    ///
    /// The returned `public_key` is the raw key bytes; the caller is
    /// responsible for any per-key-type validity check (e.g. Ed25519 point
    /// decompression) before using it for verification.
    pub fn derive_public_key(&self) -> Option<(Vec<u8>, u8)> {
        let dec = self.decode().ok()?;
        if dec.hash_type != HASH_TYPE_IDENTITY {
            return None;
        }
        let kt = KeyType::from_byte(dec.key_type).ok()?;
        if dec.digest.len() != kt.public_key_len() {
            return None;
        }
        Some((dec.digest, dec.key_type))
    }

    /// Validate that this PeerID has a well-formed shape: Base58-decodable,
    /// supported `key_type`, supported `hash_type`, digest length matches
    /// the `(key_type, hash_type)` pair. Accepts BOTH identity- and
    /// SHA-256-form for Ed25519 (wire-acceptance carve-out per V7 §1.5
    /// v7.65 Amendment 4); for `0xFE` only the canonical SHA-256-form is
    /// accepted (no legacy decode parity to preserve — it's a fresh v7.66
    /// allocation).
    pub fn validate(&self) -> Result<(), CryptoError> {
        let dec = self.decode()?;
        let kt = KeyType::from_byte(dec.key_type)?;
        match (kt, dec.hash_type) {
            (KeyType::Ed25519, HASH_TYPE_IDENTITY) | (KeyType::Ed25519, HASH_TYPE_SHA256) => {
                if dec.digest.len() != 32 {
                    return Err(CryptoError::InvalidPeerId(format!(
                        "Ed25519 digest must be 32 bytes, got {}",
                        dec.digest.len()
                    )));
                }
            }
            (KeyType::Ed448, HASH_TYPE_SHA256) => {
                if dec.digest.len() != 32 {
                    return Err(CryptoError::InvalidPeerId(format!(
                        "Ed448 SHA-256 digest must be 32 bytes, got {}",
                        dec.digest.len()
                    )));
                }
            }
            (KeyType::Ed448, ht) => {
                return Err(CryptoError::InvalidPeerId(format!(
                    "Ed448 (0x02) canonical hash_type is SHA-256 (0x01); got {:#04x}",
                    ht
                )));
            }
            (KeyType::ExperimentalTest, HASH_TYPE_SHA256) => {
                if dec.digest.len() != 32 {
                    return Err(CryptoError::InvalidPeerId(format!(
                        "experimental-test SHA-256 digest must be 32 bytes, got {}",
                        dec.digest.len()
                    )));
                }
            }
            (KeyType::ExperimentalTest, ht) => {
                return Err(CryptoError::InvalidPeerId(format!(
                    "experimental-test (0xFE) canonical hash_type is SHA-256 (0x01); got {:#04x}",
                    ht
                )));
            }
            (_, ht) => {
                return Err(CryptoError::InvalidPeerId(format!(
                    "unsupported hash_type: {:#04x} (only 0x00 identity, 0x01 sha256 allocated)",
                    ht
                )));
            }
        }
        Ok(())
    }

    /// Verify that this PeerID was derived from the given public key,
    /// **under whichever `hash_type` the PeerID declares**. Works for both
    /// identity-form (digest == public_key) and SHA-256-form
    /// (digest == SHA-256(public_key)). Length-agnostic over `public_key`
    /// to admit non-32-byte keys (e.g., `0xFE`'s 64-byte synthetic key).
    pub fn verify_public_key_bytes(&self, public_key: &[u8]) -> bool {
        let dec = match self.decode() {
            Ok(d) => d,
            Err(_) => return false,
        };
        match dec.hash_type {
            HASH_TYPE_IDENTITY => dec.digest.as_slice() == public_key,
            HASH_TYPE_SHA256 => dec.digest.as_slice() == Sha256::digest(public_key).as_slice(),
            _ => false,
        }
    }

    /// Ed25519-specialized public_key verification — the common path.
    /// Delegates to [`Self::verify_public_key_bytes`].
    pub fn verify_public_key(&self, public_key: &[u8; 32]) -> bool {
        self.verify_public_key_bytes(public_key.as_slice())
    }

    /// Compute the `{peer_id_hex}` content_hash for this PeerID without
    /// any external lookup. Works only for identity-multihash form
    /// (`hash_type = 0x00`), where the public_key is recoverable from
    /// the PeerID itself. Returns `None` for SHA-256-form PeerIDs —
    /// callers must use [`Self::identity_hex_with_public_key`] passing a
    /// cached public_key (typically from a prior handshake's `system/peer`
    /// entity).
    ///
    /// The returned hex is 66 lowercase hex chars (33-byte content_hash:
    /// algorithm byte + 32-byte digest), matching the V7 §1.4 v7.64
    /// positional rule for non-root peer-naming path segments.
    pub fn identity_hex_local(&self) -> Option<String> {
        let (pk_vec, _kt) = self.derive_public_key()?;
        let pk_arr: [u8; 32] = pk_vec.as_slice().try_into().ok()?;
        peer_identity_hash(&pk_arr).ok().map(|h| h.to_hex())
    }

    /// Compute `{peer_id_hex}` for this PeerID using a provided `public_key`.
    /// Under V7 §1.5 v7.65 the content_hash is invariant under wire-form
    /// peer_id choice, so this returns the same hex regardless of whether
    /// the PeerID is identity- or SHA-256-form. The provided public_key is
    /// verified against the PeerID's digest as defense against caller mixing
    /// up keys.
    pub fn identity_hex_with_public_key(
        &self,
        public_key: &[u8; 32],
    ) -> Result<String, CryptoError> {
        let dec = self.decode()?;
        let matches = match dec.hash_type {
            HASH_TYPE_IDENTITY => dec.digest.as_slice() == public_key.as_slice(),
            HASH_TYPE_SHA256 => dec.digest.as_slice() == Sha256::digest(public_key).as_slice(),
            _ => false,
        };
        if !matches {
            return Err(CryptoError::InvalidPeerId(
                "provided public_key does not match this PeerID's digest".into(),
            ));
        }
        peer_identity_hash(public_key).map(|h| h.to_hex())
    }

    /// Get the PeerID string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for PeerId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for PeerId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

// ---------------------------------------------------------------------------
// Ed448 (v7.67 §3 / Phase 1 validation allocation)
// ---------------------------------------------------------------------------

/// Ed448 keypair (v7.67 §3 Phase 1 validation allocation per V7 §1.5
/// `key_type=0x02`). Wraps the `ed448-goldilocks` crate's `SigningKey`.
///
/// Sized:
/// - seed (secret): [`ED448_SECRET_KEY_LEN`] = 57 bytes
/// - public_key: [`ED448_PUBLIC_KEY_LEN`] = 57 bytes
/// - signature: [`ED448_SIGNATURE_LEN`] = 114 bytes
///
/// Canonical PeerID form is SHA-256-form `(0x02, 0x01)` per v7.65 §4
/// substrate-floor cutoff (57-byte raw pubkey exceeds the floor).
///
/// **Phase 1 scope (v7.67 §13.7):** sign/verify byte-equality across
/// impls on a corpus-pinned test seed is the lock gate. Cross-peer
/// connection handshake with Ed448 lands in Phase 2 (MATRIX-M2).
pub struct Ed448Keypair {
    inner: ed448_goldilocks::SigningKey,
}

impl Ed448Keypair {
    /// Create an Ed448 keypair from a 57-byte seed (RFC 8032).
    pub fn from_seed(seed: &[u8; ED448_SECRET_KEY_LEN]) -> Result<Self, CryptoError> {
        let inner = ed448_goldilocks::SigningKey::try_from(&seed[..])
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        Ok(Self { inner })
    }

    /// Sign a message (pure Ed448, no context per RFC 8032 §5.4).
    /// Returns the 114-byte detached signature.
    pub fn sign(&self, message: &[u8]) -> [u8; ED448_SIGNATURE_LEN] {
        use ed448_goldilocks::signature::Signer;
        let sig: ed448_goldilocks::Signature = self.inner.sign(message);
        sig.to_bytes()
    }

    /// Verify a 114-byte Ed448 signature against a 57-byte public key.
    pub fn verify(
        public_key: &[u8; ED448_PUBLIC_KEY_LEN],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        use ed448_goldilocks::signature::Verifier;
        let pk = ed448_goldilocks::VerifyingKey::from_bytes(&(*public_key).into())
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        let sig_bytes: [u8; ED448_SIGNATURE_LEN] = signature
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?;
        let sig = ed448_goldilocks::Signature::try_from(&sig_bytes[..])
            .map_err(|_| CryptoError::InvalidSignature)?;
        pk.verify(message, &sig)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    /// Get the raw 57-byte public key bytes.
    pub fn public_key_bytes(&self) -> [u8; ED448_PUBLIC_KEY_LEN] {
        self.inner.verifying_key().to_bytes().into()
    }

    /// Get the raw 57-byte secret seed bytes. See [`Keypair::secret_key_bytes`]
    /// for the audit-boundary discipline that applies to all raw-secret
    /// surfaces.
    pub fn secret_key_bytes(&self) -> [u8; ED448_SECRET_KEY_LEN] {
        self.inner.to_bytes().into()
    }

    /// Derive the canonical Ed448 PeerID — `(0x02, 0x01)` SHA-256-form
    /// per v7.67 §3.2.
    pub fn peer_id(&self) -> PeerId {
        let pk = self.public_key_bytes();
        // SAFETY: SHA-256-form for the 57-byte key is structurally valid.
        PeerId::from_public_key_with_key_type(&pk, KeyType::Ed448)
            .expect("57-byte Ed448 pubkey canonicalizes to SHA-256-form")
    }

    /// Construct the canonical `system/peer` entity for this Ed448 keypair —
    /// `data = {key_type: "ed448", public_key: <57 bytes>}` (v7.66 §2
    /// two-layer pin; v7.67 §3.3 entity-data string).
    pub fn peer_entity(&self) -> Result<Entity, CryptoError> {
        let pk = self.public_key_bytes();
        peer_entity_from_components_with_key_type(&pk, KeyType::Ed448)
    }

    /// The [`KeyType`] this keypair signs under — `Ed448`. Mirrors
    /// [`Keypair::key_type`] so the handshake reads `key_type` off the
    /// signing identity rather than hardcoding it.
    pub const fn key_type(&self) -> KeyType {
        KeyType::Ed448
    }

    /// Compute `content_hash(system/peer)` for this Ed448 keypair — the
    /// canonical cryptographic identity per `(public_key, key_type)`
    /// (v7.65 §3). Mirrors [`Keypair::peer_identity_hash`].
    pub fn peer_identity_hash(&self) -> entity_hash::Hash {
        self.peer_entity()
            .expect("system/peer entity for own Ed448 keypair is always constructible")
            .content_hash
    }

    /// Encode the 57-byte seed as PEM with the Ed448 algorithm-tagged
    /// header per the V7.67 Phase 2 cohort convention
    /// (`-----BEGIN ENTITY ED448 PRIVATE KEY-----`). The untagged
    /// `ENTITY PRIVATE KEY` header stays reserved for Ed25519 so
    /// [`IdentityKeypair::from_pem`] can dispatch on the header tag.
    pub fn to_pem(&self) -> String {
        let encoded = BASE64.encode(self.secret_key_bytes());
        format!(
            "-----BEGIN ENTITY ED448 PRIVATE KEY-----\n{}\n-----END ENTITY ED448 PRIVATE KEY-----\n",
            encoded
        )
    }

    /// Decode an Ed448 keypair from a PEM string produced by [`Self::to_pem`].
    pub fn from_pem(pem: &str) -> Result<Self, CryptoError> {
        let b64 = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        let decoded = BASE64
            .decode(b64.trim())
            .map_err(|e| CryptoError::IoError(format!("base64 decode: {}", e)))?;
        let seed: [u8; ED448_SECRET_KEY_LEN] = decoded
            .try_into()
            .map_err(|_| CryptoError::IoError("Ed448 private key must be 57 bytes".into()))?;
        Self::from_seed(&seed)
    }

    /// Generate a new random Ed448 keypair.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut seed = [0u8; ED448_SECRET_KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self::from_seed(&seed).expect("57 random bytes is a valid Ed448 seed")
    }
}

impl std::fmt::Debug for Ed448Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't leak secret material via Debug.
        f.debug_struct("Ed448Keypair")
            .field("public_key", &hex_short(&self.public_key_bytes()))
            .finish_non_exhaustive()
    }
}

fn hex_short(bytes: &[u8]) -> String {
    let n = bytes.len().min(8);
    let head: String = bytes[..n].iter().map(|b| format!("{:02x}", b)).collect();
    format!("{}..", head)
}

/// A peer's signing identity, polymorphic over the allocated `key_type`
/// (v7.67 Phase 2 — MATRIX-M2 Ed448 peer backend). A peer holds exactly
/// one of these; the wire-signing surface (`sign` / `peer_id` /
/// `peer_entity` / `key_type`) dispatches to the concrete scheme so a peer
/// can run as an Ed25519 *or* Ed448 backend and complete a real-wire
/// handshake with peers of either type.
///
/// Verification of *remote* peers does not go through this enum — it uses
/// the static [`verify_for_key_type`] keyed on the remote's decoded
/// `key_type`, since verification needs only public-key bytes.
// Held once per peer (and cloned per connection task), never in a hot
// collection — the inter-variant size gap is irrelevant here.
#[allow(clippy::large_enum_variant)]
pub enum IdentityKeypair {
    Ed25519(Keypair),
    Ed448(Ed448Keypair),
}

impl IdentityKeypair {
    /// The [`KeyType`] this identity signs under.
    pub const fn key_type(&self) -> KeyType {
        match self {
            Self::Ed25519(_) => KeyType::Ed25519,
            Self::Ed448(_) => KeyType::Ed448,
        }
    }

    /// Sign a message, returning the scheme's detached signature
    /// (64 bytes Ed25519 / 114 bytes Ed448) as a `Vec<u8>`.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Ed25519(kp) => kp.sign(message).to_vec(),
            Self::Ed448(kp) => kp.sign(message).to_vec(),
        }
    }

    /// Canonical PeerID for this identity.
    pub fn peer_id(&self) -> PeerId {
        match self {
            Self::Ed25519(kp) => kp.peer_id(),
            Self::Ed448(kp) => kp.peer_id(),
        }
    }

    /// Raw public-key bytes (32 Ed25519 / 57 Ed448).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(kp) => kp.public_key_bytes().to_vec(),
            Self::Ed448(kp) => kp.public_key_bytes().to_vec(),
        }
    }

    /// Public key as a base64 string (mirrors [`Keypair::public_key_base64`]).
    pub fn public_key_base64(&self) -> String {
        BASE64.encode(self.public_key_bytes())
    }

    /// Construct the canonical `system/peer` entity for this identity under
    /// the process home `content_hash_format`
    /// ([`entity_hash::default_hash_format`] — V7 §1.2). Per-connection
    /// re-derivation under a negotiated active format (§4.5a) uses
    /// [`Keypair::peer_entity_with_format`].
    pub fn peer_entity(&self) -> Result<Entity, CryptoError> {
        self.peer_entity_with_format(entity_hash::default_hash_format())
    }

    /// Construct this identity's `system/peer` entity under an explicit
    /// `content_hash_format` (V7 §4.5a — re-derive the local identity per
    /// connection under the negotiated active format, without mutating
    /// peer-startup state).
    pub fn peer_entity_with_format(&self, format_code: u8) -> Result<Entity, CryptoError> {
        peer_entity_from_components_with_format(
            &self.public_key_bytes(),
            self.key_type(),
            format_code,
        )
    }

    /// `content_hash(system/peer)` — the canonical cryptographic identity.
    pub fn peer_identity_hash(&self) -> entity_hash::Hash {
        match self {
            Self::Ed25519(kp) => kp.peer_identity_hash(),
            Self::Ed448(kp) => kp.peer_identity_hash(),
        }
    }

    /// Borrow the inner Ed25519 keypair, if this identity is Ed25519.
    /// Ed25519-only surfaces (identity-bundle export, raw secret bytes,
    /// PEM-less round-trips in the SDK) reach the concrete type through
    /// this escape hatch; an Ed448 identity returns `None`.
    pub fn as_ed25519(&self) -> Option<&Keypair> {
        match self {
            Self::Ed25519(kp) => Some(kp),
            Self::Ed448(_) => None,
        }
    }

    /// Clone the underlying secret material into a new owned identity.
    /// Mirrors [`Keypair::clone_inner`] — same audit-boundary discipline.
    pub fn clone_identity(&self) -> Self {
        match self {
            Self::Ed25519(kp) => Self::Ed25519(kp.clone_inner()),
            Self::Ed448(kp) => Self::Ed448(
                Ed448Keypair::from_seed(&kp.secret_key_bytes())
                    .expect("round-trip of own Ed448 seed is valid"),
            ),
        }
    }

    /// PEM-encode the private key with the algorithm-tagged header
    /// (`ENTITY PRIVATE KEY` for Ed25519, `ENTITY ED448 PRIVATE KEY` for
    /// Ed448) per the V7.67 Phase 2 cohort convention.
    pub fn to_pem(&self) -> String {
        match self {
            Self::Ed25519(kp) => kp.to_pem(),
            Self::Ed448(kp) => kp.to_pem(),
        }
    }

    /// Decode an identity from a PEM string, dispatching on the header tag.
    /// The untagged `ENTITY PRIVATE KEY` header is Ed25519 (back-compat with
    /// existing identity files); `ENTITY ED448 PRIVATE KEY` is Ed448.
    pub fn from_pem(pem: &str) -> Result<Self, CryptoError> {
        if pem.contains("ENTITY ED448 PRIVATE KEY") {
            Ok(Self::Ed448(Ed448Keypair::from_pem(pem)?))
        } else {
            Ok(Self::Ed25519(Keypair::from_pem(pem)?))
        }
    }

    /// Save the identity to a PEM file plus a `.pub` sidecar.
    pub fn save_to_file(&self, path: &Path) -> Result<(), CryptoError> {
        match self {
            Self::Ed25519(kp) => kp.save_to_file(path),
            Self::Ed448(_) => {
                std::fs::write(path, self.to_pem())
                    .map_err(|e| CryptoError::IoError(e.to_string()))?;
                let pub_path = path.with_extension("pub");
                let pub_line = format!(
                    "entity-{} {} {}\n",
                    self.key_type().label(),
                    self.public_key_base64(),
                    self.peer_id()
                );
                std::fs::write(pub_path, pub_line)
                    .map_err(|e| CryptoError::IoError(e.to_string()))
            }
        }
    }

    /// Load an identity from a PEM file, dispatching on the header tag.
    pub fn load_from_file(path: &Path) -> Result<Self, CryptoError> {
        let contents =
            std::fs::read_to_string(path).map_err(|e| CryptoError::IoError(e.to_string()))?;
        Self::from_pem(&contents)
    }
}

impl From<Keypair> for IdentityKeypair {
    fn from(kp: Keypair) -> Self {
        Self::Ed25519(kp)
    }
}

impl From<Ed448Keypair> for IdentityKeypair {
    fn from(kp: Ed448Keypair) -> Self {
        Self::Ed448(kp)
    }
}

impl std::fmt::Debug for IdentityKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityKeypair")
            .field("key_type", &self.key_type().label())
            .field("public_key", &hex_short(&self.public_key_bytes()))
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid signature")]
    InvalidSignature,

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid peer ID: {0}")]
    InvalidPeerId(String),

    /// V7 §4.7 `400 unsupported_key_type`. The presented `key_type`
    /// (binary varint prefix or label) is not allocated in this impl's
    /// supported set. For `0xFE` (experimental-test, v7.66 §4), impls
    /// participating in agility-validation accept; non-participating
    /// impls return this error.
    #[error("unsupported key_type: {0:#04x}")]
    UnsupportedKeyType(u8),

    #[error("identity entity error: {0}")]
    IdentityError(String),

    #[error("I/O error: {0}")]
    IoError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a SHA-256-form Ed25519 PeerID from raw bytes. v7.66 §3
    /// removed the live-mint helper; the wire-acceptance decode path
    /// (§5 carve-out) is still tested via fixture-layer pre-built bytes
    /// per v7.66 §3.4. Used only by the decode-parity tests in this
    /// module.
    fn build_legacy_sha256_peer_id(public_key: &[u8; 32]) -> PeerId {
        let digest = Sha256::digest(public_key).to_vec();
        let mut raw = Vec::with_capacity(2 + digest.len());
        push_varint_u8(&mut raw, KEY_TYPE_ED25519);
        push_varint_u8(&mut raw, HASH_TYPE_SHA256);
        raw.extend_from_slice(&digest);
        PeerId(bs58::encode(&raw).into_string())
    }

    const TEST_SEED: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32,
    ];

    #[test]
    fn test_from_seed_deterministic() {
        let k1 = Keypair::from_seed(TEST_SEED);
        let k2 = Keypair::from_seed(TEST_SEED);
        assert_eq!(k1.public_key_bytes(), k2.public_key_bytes());
    }

    #[test]
    fn test_from_seed_different_seeds() {
        let k1 = Keypair::from_seed(TEST_SEED);
        let k2 = Keypair::from_seed([0u8; 32]);
        assert_ne!(k1.public_key_bytes(), k2.public_key_bytes());
    }

    #[test]
    fn test_generate_unique() {
        let k1 = Keypair::generate();
        let k2 = Keypair::generate();
        assert_ne!(k1.public_key_bytes(), k2.public_key_bytes());
    }

    #[test]
    fn test_sign_verify() {
        let kp = Keypair::from_seed(TEST_SEED);
        let message = b"hello world";
        let sig = kp.sign(message);
        assert_eq!(sig.len(), 64);
        assert!(Keypair::verify(&kp.public_key_bytes(), message, &sig).is_ok());
    }

    #[test]
    fn test_verify_wrong_message() {
        let kp = Keypair::from_seed(TEST_SEED);
        let sig = kp.sign(b"hello");
        assert!(Keypair::verify(&kp.public_key_bytes(), b"wrong", &sig).is_err());
    }

    #[test]
    fn test_verify_wrong_key() {
        let kp1 = Keypair::from_seed(TEST_SEED);
        let kp2 = Keypair::from_seed([0u8; 32]);
        let sig = kp1.sign(b"hello");
        assert!(Keypair::verify(&kp2.public_key_bytes(), b"hello", &sig).is_err());
    }

    #[test]
    fn test_verify_invalid_signature_length() {
        let kp = Keypair::from_seed(TEST_SEED);
        assert!(Keypair::verify(&kp.public_key_bytes(), b"hello", &[0u8; 10]).is_err());
    }

    #[test]
    fn test_peer_id_from_public_key() {
        let kp = Keypair::from_seed(TEST_SEED);
        let pid = PeerId::from_public_key(&kp.public_key_bytes());
        assert!(!pid.as_str().is_empty());
        assert!(pid.validate().is_ok());
    }

    #[test]
    fn test_peer_id_from_keypair() {
        let kp = Keypair::from_seed(TEST_SEED);
        let pid1 = kp.peer_id();
        let pid2 = PeerId::from_keypair(&kp);
        assert_eq!(pid1, pid2);
    }

    #[test]
    fn test_peer_id_deterministic() {
        let k1 = Keypair::from_seed(TEST_SEED);
        let k2 = Keypair::from_seed(TEST_SEED);
        assert_eq!(k1.peer_id(), k2.peer_id());
    }

    #[test]
    fn test_peer_id_different_keys() {
        let k1 = Keypair::from_seed(TEST_SEED);
        let k2 = Keypair::from_seed([0u8; 32]);
        assert_ne!(k1.peer_id(), k2.peer_id());
    }

    #[test]
    fn test_peer_id_validate_valid() {
        let kp = Keypair::from_seed(TEST_SEED);
        assert!(kp.peer_id().validate().is_ok());
    }

    #[test]
    fn test_peer_id_validate_invalid() {
        let pid = PeerId::from("not-valid-base58!!!");
        assert!(pid.validate().is_err());
    }

    #[test]
    fn test_peer_id_verify_public_key() {
        let kp = Keypair::from_seed(TEST_SEED);
        let pid = kp.peer_id();
        assert!(pid.verify_public_key(&kp.public_key_bytes()));

        let other = Keypair::from_seed([0u8; 32]);
        assert!(!pid.verify_public_key(&other.public_key_bytes()));
    }

    #[test]
    fn test_peer_id_display() {
        let kp = Keypair::from_seed(TEST_SEED);
        let pid = kp.peer_id();
        let s = pid.to_string();
        assert_eq!(s, pid.as_str());
    }

    #[test]
    fn test_peer_entity() {
        let kp = Keypair::from_seed(TEST_SEED);
        let entity = kp.peer_entity().unwrap();
        assert_eq!(entity.entity_type, TYPE_PEER);
        assert!(!entity.content_hash.is_zero());
        assert!(entity.validate().is_ok());
    }

    #[test]
    fn test_peer_entity_deterministic() {
        let k1 = Keypair::from_seed(TEST_SEED);
        let k2 = Keypair::from_seed(TEST_SEED);
        let e1 = k1.peer_entity().unwrap();
        let e2 = k2.peer_entity().unwrap();
        assert_eq!(e1.content_hash, e2.content_hash);
    }

    #[test]
    fn test_peer_entity_contains_fields() {
        // V7 §3.5 v7.65: data = {key_type, public_key}. peer_id is NOT a
        // hashable field — invariance under wire-form peer_id choice.
        let kp = Keypair::from_seed(TEST_SEED);
        let entity = kp.peer_entity().unwrap();
        let value: entity_ecf::Value =
            ciborium::from_reader(entity.data.as_slice()).unwrap();
        let map = value.as_map().unwrap();

        let mut found_key_type = false;
        let mut found_public_key = false;

        for (k, v) in map {
            match k.as_text().unwrap() {
                "key_type" => {
                    assert_eq!(v.as_text().unwrap(), "ed25519");
                    found_key_type = true;
                }
                "public_key" => {
                    assert_eq!(v.as_bytes().unwrap(), &kp.public_key_bytes());
                    found_public_key = true;
                }
                other => panic!("unexpected v7.65 field: {}", other),
            }
        }
        assert!(found_key_type && found_public_key);
    }

    #[test]
    fn test_sign_hash_bytes() {
        // Verify we can sign hash bytes (the typical protocol usage)
        let kp = Keypair::from_seed(TEST_SEED);
        let entity = kp.peer_entity().unwrap();
        let hash_bytes = entity.content_hash.to_bytes();
        let sig = kp.sign(&hash_bytes);
        assert!(Keypair::verify(&kp.public_key_bytes(), &hash_bytes, &sig).is_ok());
    }

    #[test]
    fn test_public_key_base64() {
        let kp = Keypair::from_seed(TEST_SEED);
        let b64 = kp.public_key_base64();
        assert!(!b64.is_empty());
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .unwrap();
        assert_eq!(decoded.len(), 32);
        assert_eq!(decoded.as_slice(), &kp.public_key_bytes());
    }

    #[test]
    fn test_save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("testkey");
        let kp = Keypair::from_seed(TEST_SEED);
        kp.save_to_file(&path).unwrap();

        // Verify files exist
        assert!(path.exists());
        assert!(path.with_extension("pub").exists());

        // Load and verify same key
        let loaded = Keypair::load_from_file(&path).unwrap();
        assert_eq!(loaded.public_key_bytes(), kp.public_key_bytes());
        assert_eq!(loaded.peer_id(), kp.peer_id());
    }

    #[test]
    fn test_save_pem_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("testkey");
        let kp = Keypair::from_seed(TEST_SEED);
        kp.save_to_file(&path).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.starts_with("-----BEGIN ENTITY PRIVATE KEY-----"));
        assert!(contents.contains("-----END ENTITY PRIVATE KEY-----"));
    }

    #[test]
    fn test_save_pub_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("testkey");
        let kp = Keypair::from_seed(TEST_SEED);
        kp.save_to_file(&path).unwrap();

        let pub_contents = std::fs::read_to_string(path.with_extension("pub")).unwrap();
        assert!(pub_contents.starts_with("entity-ed25519 "));
        assert!(pub_contents.contains(kp.peer_id().as_str()));
    }

    #[test]
    fn test_load_nonexistent() {
        let result = Keypair::load_from_file(Path::new("/tmp/nonexistent_key_12345"));
        assert!(result.is_err());
    }

    #[test]
    fn test_exists_at() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("testkey");
        assert!(!Keypair::exists_at(&path));
        let kp = Keypair::from_seed(TEST_SEED);
        kp.save_to_file(&path).unwrap();
        assert!(Keypair::exists_at(&path));
    }

    // ---------------- v7.64 PIM-* conformance vectors ----------------
    // Per V7 §2.8 (`PROPOSAL-V7-PEER-ID-IDENTITY-MULTIHASH.md`). The vector
    // class is `peer-id-form`; vectors are authored by Go per the existing
    // convention but we implement the same shape locally so the Rust suite
    // proves the decoder is length-agnostic + dual-form-aware.

    /// PIM-1: identity-form encode/decode round-trip — extracted public_key
    /// matches input.
    #[test]
    fn pim_1_identity_form_round_trip() {
        let kp = Keypair::from_seed(TEST_SEED);
        let pk = kp.public_key_bytes();
        let pid = PeerId::from_public_key(&pk);

        let dec = pid.decode().expect("identity-form decode");
        assert_eq!(dec.key_type, KEY_TYPE_ED25519);
        assert_eq!(dec.hash_type, HASH_TYPE_IDENTITY);
        assert_eq!(dec.digest.as_slice(), pk.as_slice());

        let (recovered_pk, recovered_kt) =
            pid.derive_public_key().expect("identity-form is self-resolving");
        assert_eq!(recovered_kt, KEY_TYPE_ED25519);
        assert_eq!(recovered_pk.as_slice(), pk.as_slice());

        assert!(pid.validate().is_ok());
        assert!(pid.verify_public_key(&pk));
    }

    /// PIM-2: SHA-256-form encode/decode round-trip — `derive_public_key`
    /// returns `None`, `decode` returns the fingerprint.
    #[test]
    fn pim_2_sha256_form_round_trip() {
        let kp = Keypair::from_seed(TEST_SEED);
        let pk = kp.public_key_bytes();
        let pid = build_legacy_sha256_peer_id(&pk);

        let dec = pid.decode().expect("sha256-form decode");
        assert_eq!(dec.key_type, KEY_TYPE_ED25519);
        assert_eq!(dec.hash_type, HASH_TYPE_SHA256);
        assert_eq!(dec.digest.as_slice(), Sha256::digest(pk).as_slice());

        assert!(
            pid.derive_public_key().is_none(),
            "fingerprint form is not self-resolving"
        );

        assert!(pid.validate().is_ok());
        assert!(pid.verify_public_key(&pk));
    }

    /// PIM-3: both forms decode and verify against the same public_key
    /// (wire-decode parity per V7 §1.5 v7.65 wire-acceptance carve-out).
    /// The two PeerID STRINGS remain distinct (different hash_type byte);
    /// under v7.65 the underlying content_hash(system/peer) is invariant
    /// (see [peer_identity_hash_invariant_under_wire_form]).
    #[test]
    fn pim_3_mixed_form_interop() {
        let kp = Keypair::from_seed(TEST_SEED);
        let pk = kp.public_key_bytes();
        let pid_identity = PeerId::from_public_key(&pk);
        let pid_sha256 = build_legacy_sha256_peer_id(&pk);

        // Same keypair, two distinct PeerID strings.
        assert_ne!(pid_identity, pid_sha256);

        // Both verify against the same public_key.
        assert!(pid_identity.verify_public_key(&pk));
        assert!(pid_sha256.verify_public_key(&pk));

        // Cross-check: identity-form PID does NOT verify against a different
        // public_key, even if the SHA-256 happens to match (it can't, but
        // defensive: the wrong key fails under both forms).
        let other = Keypair::from_seed([0u8; 32]).public_key_bytes();
        assert!(!pid_identity.verify_public_key(&other));
        assert!(!pid_sha256.verify_public_key(&other));
    }

    /// PIM-4: cross-impl PeerID stability — same `(key_type, hash_type)`
    /// produces byte-identical PeerID for the same input. Asserted via
    /// determinism here; the cross-impl byte-level vector is authored by Go.
    #[test]
    fn pim_4_peer_id_stability() {
        let pk = Keypair::from_seed(TEST_SEED).public_key_bytes();
        let a = PeerId::from_public_key(&pk);
        let b = PeerId::from_public_key(&pk);
        assert_eq!(a, b);

        let c = build_legacy_sha256_peer_id(&pk);
        let d = build_legacy_sha256_peer_id(&pk);
        assert_eq!(c, d);
    }

    /// PIM-5: length-agnostic decoder. Construct an identity-form PeerID
    /// with a synthetic unallocated experimental `key_type = 0xF0` (in
    /// the v7.66 §4.3 `0xF0–0xFE` experimental range but not the `0xFE`
    /// real allocation) and a 256-byte digest. The decoder MUST return
    /// the full 256-byte payload; `derive_public_key` MUST return `None`
    /// and `validate` MUST reject because `0xF0` is not in the
    /// supported-`KeyType` set.
    #[test]
    fn pim_5_length_agnostic_decoder() {
        let big_digest: Vec<u8> = (0u16..256).map(|i| (i & 0xff) as u8).collect();
        assert_eq!(big_digest.len(), 256);

        let mut raw = Vec::with_capacity(4 + big_digest.len());
        push_varint_u8(&mut raw, 0xF0); // unallocated experimental
        push_varint_u8(&mut raw, HASH_TYPE_IDENTITY);
        raw.extend_from_slice(&big_digest);
        let pid = PeerId(bs58::encode(&raw).into_string());

        let dec = pid.decode().expect("length-agnostic decode");
        assert_eq!(dec.key_type, 0xF0);
        assert_eq!(dec.hash_type, HASH_TYPE_IDENTITY);
        assert_eq!(dec.digest.len(), 256);
        assert_eq!(dec.digest, big_digest);

        // Helper returns None for unknown key_type (no length validation
        // table entry).
        assert!(pid.derive_public_key().is_none());

        // validate() rejects 0xF0 — unallocated experimental, not in
        // supported KeyType set (Ed25519 0x01, ExperimentalTest 0xFE).
        assert!(pid.validate().is_err());
    }

    /// Backward-compat: pre-v7.64 generators produce SHA-256-form PeerIDs.
    /// New code MUST still decode them and verify against the public key.
    #[test]
    fn legacy_sha256_form_remains_decodable() {
        let pk = Keypair::from_seed(TEST_SEED).public_key_bytes();
        let pid = build_legacy_sha256_peer_id(&pk);
        assert!(pid.validate().is_ok());
        assert!(pid.verify_public_key(&pk));
        assert!(pid.derive_public_key().is_none());
    }

    /// `from_public_key_with_hash_type` rejects unsupported `hash_type`
    /// codes (the second varint, not key_type — function is
    /// Ed25519-only by signature).
    #[test]
    fn explicit_hash_type_rejects_unsupported() {
        let pk = Keypair::from_seed(TEST_SEED).public_key_bytes();
        assert!(PeerId::from_public_key_with_hash_type(&pk, 0x02).is_err());
        assert!(PeerId::from_public_key_with_hash_type(&pk, 0xFE).is_err());
        assert!(PeerId::from_public_key_with_hash_type(&pk, 0xFF).is_err());
    }

    /// Default `Keypair::peer_id()` is identity-form post-v7.64.
    #[test]
    fn keypair_default_is_identity_form() {
        let kp = Keypair::from_seed(TEST_SEED);
        let pid = kp.peer_id();
        let dec = pid.decode().unwrap();
        assert_eq!(dec.hash_type, HASH_TYPE_IDENTITY);
        // Digest IS the public_key — self-resolving.
        assert_eq!(dec.digest.as_slice(), kp.public_key_bytes().as_slice());
    }

    /// `peer_identity_hash` matches `Keypair::peer_identity_hash` matches
    /// `peer_entity().content_hash`. Three aliases over the canonical V7
    /// §1.4 v7.65 computation — pure function of `(public_key, key_type)`.
    #[test]
    fn peer_identity_hash_helpers_agree() {
        let kp = Keypair::from_seed(TEST_SEED);
        let pk = kp.public_key_bytes();

        let from_kp = kp.peer_identity_hash();
        let from_components = peer_identity_hash(&pk).expect("canonical-form");
        let from_entity = kp.peer_entity().unwrap().content_hash;

        assert_eq!(from_kp, from_components);
        assert_eq!(from_kp, from_entity);
    }

    // ---------------------------------------------------------------------
    // Ed448 (v7.67 §3 Phase 1) smoke tests
    // ---------------------------------------------------------------------

    /// v7.67 §3 / Phase 1: Ed448 sign/verify round-trip with the 57-byte
    /// seed. Conformance vector `KEY-TYPE-ED448-1` is the cross-impl
    /// byte-equality version (corpus-pinned seed) and lives in the
    /// wire-conformance harness; this test just confirms the local crate
    /// surface works.
    #[test]
    fn ed448_sign_verify_round_trip() {
        let seed = [0x42u8; ED448_SECRET_KEY_LEN];
        let kp = Ed448Keypair::from_seed(&seed).expect("seed accepted");
        let pk = kp.public_key_bytes();
        assert_eq!(pk.len(), ED448_PUBLIC_KEY_LEN);
        let msg = b"hello entity-core v7.67";
        let sig = kp.sign(msg);
        assert_eq!(sig.len(), ED448_SIGNATURE_LEN);
        Ed448Keypair::verify(&pk, msg, &sig).expect("verify");
        Ed448Keypair::verify(&pk, b"wrong-message", &sig)
            .expect_err("wrong message must reject");
    }

    /// v7.67 §3.2: canonical Ed448 PeerID form is SHA-256-form
    /// `(0x02, 0x01)` — 57-byte raw pubkey exceeds the v7.65 §4
    /// substrate floor.
    #[test]
    fn ed448_peer_id_canonical_form() {
        let seed = [0x42u8; ED448_SECRET_KEY_LEN];
        let kp = Ed448Keypair::from_seed(&seed).unwrap();
        let pid = kp.peer_id();
        let dec = pid.decode().unwrap();
        assert_eq!(dec.key_type, KEY_TYPE_ED448);
        assert_eq!(dec.hash_type, HASH_TYPE_SHA256);
        assert_eq!(dec.digest.len(), 32); // SHA-256 of the 57-byte pubkey
        pid.validate().expect("Ed448 PeerID validates");
    }

    /// v7.67 §3.3: `system/peer.data.key_type` for Ed448 is the canonical
    /// entity-data string `"ed448"`. `content_hash(system/peer)` is a
    /// pure function of `(public_key, key_type)` per v7.65 §3.
    #[test]
    fn ed448_peer_entity_data_shape() {
        let seed = [0x42u8; ED448_SECRET_KEY_LEN];
        let kp = Ed448Keypair::from_seed(&seed).unwrap();
        let entity = kp.peer_entity().unwrap();
        assert_eq!(entity.entity_type, TYPE_PEER);
        let value: entity_ecf::Value =
            ciborium::from_reader(entity.data.as_slice()).unwrap();
        let map = value.as_map().unwrap();
        let mut found_key_type = false;
        let mut found_public_key = false;
        for (k, v) in map {
            match k.as_text().unwrap() {
                "key_type" => {
                    assert_eq!(v.as_text().unwrap(), "ed448");
                    found_key_type = true;
                }
                "public_key" => {
                    assert_eq!(v.as_bytes().unwrap().len(), ED448_PUBLIC_KEY_LEN);
                    found_public_key = true;
                }
                other => panic!("unexpected field: {}", other),
            }
        }
        assert!(found_key_type && found_public_key);
    }

    /// v7.67 §5 reservation: integer value `255` on the `key_type` axis
    /// is reserved and MUST NOT decode to any allocated algorithm.
    #[test]
    fn key_type_0xff_reserved_v7_67_5() {
        assert!(matches!(
            KeyType::from_byte(0xFF),
            Err(CryptoError::UnsupportedKeyType(0xFF))
        ));
    }

    /// v7.67 §3 KeyType seed table label round-trip for Ed448.
    #[test]
    fn ed448_key_type_label_roundtrip() {
        assert_eq!(KeyType::Ed448.label(), "ed448");
        assert_eq!(KeyType::Ed448.byte(), KEY_TYPE_ED448);
        assert!(matches!(
            KeyType::from_label("ed448"),
            Ok(KeyType::Ed448)
        ));
        assert!(matches!(
            KeyType::from_byte(KEY_TYPE_ED448),
            Ok(KeyType::Ed448)
        ));
        assert!(KeyType::Ed448.supports_signing());
        assert_eq!(KeyType::Ed448.canonical_hash_type(), HASH_TYPE_SHA256);
        assert_eq!(KeyType::Ed448.public_key_len(), ED448_PUBLIC_KEY_LEN);
    }

    /// V7 §3.5 v7.65 (Amendment 1+2): cryptographic identity is invariant
    /// under wire-form `peer_id` choice. The same keypair produces ONE
    /// content_hash regardless of which Base58 form was minted at the
    /// wire layer; `peer_id` exits the hashable basis. This test asserts
    /// the post-v7.65 invariance directly via the public surface.
    #[test]
    fn peer_identity_hash_invariant_under_wire_form() {
        let kp = Keypair::from_seed(TEST_SEED);
        let pk = kp.public_key_bytes();

        let h_via_keypair = kp.peer_identity_hash();
        let h_via_components = peer_identity_hash(&pk).unwrap();
        let h_via_entity = kp.peer_entity().unwrap().content_hash;

        assert_eq!(h_via_keypair, h_via_components);
        assert_eq!(h_via_keypair, h_via_entity);
    }
}
