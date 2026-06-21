//! EXTENSION-CONTENT v3.5 — content blobs, chunks, descriptors, chunkers
//! and the optional `system/content` handler.
//!
//! Spec: `entity-core-architecture/.../specs/extensions/standard-peer-extensions/EXTENSION-CONTENT.md` v3.5.
//!
//! Surfaces this crate exposes:
//!
//! - [`chunker`] — fixed-size (§3.2) and FastCDC (§3.6) chunkers. Both
//!   write blob + chunk entities into a [`entity_store::ContentStore`]
//!   and return the blob's entity hash.
//! - [`fastcdc`] — gear table derivation and boundary finder (§3.6.1,
//!   §3.6.3). Pure functions; no I/O.
//! - [`verify`] — completeness + total-size verification (§3.3) and
//!   in-order reassembly (§3.4).
//! - [`handler::SystemContentHandler`] — optional handler bound at
//!   `system/content` with `get` (§6.2) + `ingest` (§6.3). Both require
//!   a `resource` field (§6.2/§6.3 v3.5 normative tightening — without
//!   one the handler returns `path_required`).

pub mod chunker;
pub mod closure;
pub mod fastcdc;
pub mod handler;
pub mod miss_hook;
pub mod verify;

pub use chunker::{
    create_blob_fastcdc, create_blob_fastcdc_stream, create_blob_fixed, ChunkerError,
};
pub use closure::{at_peer, ensure_closure, EnsureClosureError, GET_BATCH_SIZE};
pub use handler::SystemContentHandler;
pub use miss_hook::{MissOutcome, MissResolver};
pub use verify::{
    blob_chunk_hashes, blob_chunk_size, reassemble, reassemble_stream, verify_content,
    VerifyError,
};
