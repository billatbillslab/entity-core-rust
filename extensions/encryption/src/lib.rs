//! EXTENSION-ENCRYPTION v1.0 — per-entity stateless encryption.
//!
//! Implements the **base** (per-entity stateless) half of the base/session
//! split: `self` (at-rest storage, v1 PRIMARY), `peer` (single-shot hybrid
//! send, v1 PRIMARY), `group` (static key-wrap, v1 best-effort). The stateful
//! interactive sibling (`EXTENSION-ENCRYPTED-SESSION`, §20) is deferred
//! post-release and is NOT built here.
//!
//! Spec: `../entity-core-architecture/docs/architecture/v7.0-core-revision/
//! core-protocol-domain/specs/extensions/network-peer-extensions/
//! EXTENSION-ENCRYPTION.md`.
//!
//! # Architecture
//!
//! Crypto primitives (X25519, HKDF, Argon2id, XChaCha20-Poly1305) live *inside*
//! this extension rather than `core/crypto` — `core/crypto` is the peer-identity
//! signing crate (Ed25519/Ed448/PeerID); the encryption primitives are
//! encryption-specific and no other extension needs them. Keeping them here
//! preserves the lean `core` compile + WASM surface. The planned
//! `ENCRYPTED-SESSION` sibling consumes this extension's substrate (§20) via an
//! `session → encryption` edge, mirroring the documented substrate edges
//! (`quorum → attestation`, `identity → attestation`, `relay → route`).
//!
//! # Byte-equality discipline (BLOCK-0)
//!
//! Every §16 conformance vector pins exact byte inputs so all impls produce
//! identical bytes. The AAD builders ([`aad`]) encode deterministic ECF maps
//! (RFC 8949 §4.2 length-first) with fixed, all-keys-present key sets per mode
//! — the all-keys-present discipline (empty bytes, never omitted, never null)
//! closes the v7.67 Phase-2 omitted-vs-present-empty byte-pin trap. Cohort
//! byte-equality across Go + Rust + Python depends on this.

pub mod aad;
pub mod aead;
pub mod ecdh;
pub mod group;
pub mod kat;
pub mod kdf;
pub mod keybackup;
pub mod lifecycle;
pub mod peer;
pub mod registry;
pub mod self_mode;
pub mod separation;
pub mod types;
pub mod wrapper;

pub use group::{
    group_add_member, group_decrypt, group_encrypt, group_rekey, GroupDecryptInput,
    GroupEncryptInput, GroupMember,
};
pub use kat::enc_kat_inner_plaintext;
pub use keybackup::{unwrap_private_key, wrap_private_key, EncryptionKeyBackupData};
pub use lifecycle::{EncryptionHandoffData, EncryptionRevocationData, TierAView};
pub use peer::{peer_decrypt, peer_encrypt, PeerEncryptInput};
pub use separation::{birational_ed25519_to_x25519, validate_key_separation};
pub use registry::{
    group_mode_suite_allowed, intersect_suite, peer_mode_suite_allowed, self_mode_suite_allowed,
};
pub use self_mode::{self_decrypt, self_encrypt, SelfEncryptParams};
pub use types::{EncryptionError, KdfParams};
pub use wrapper::{EncryptedData, EncryptionPubkeyData, WrappedKey};
