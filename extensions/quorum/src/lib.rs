//! `system/quorum` K-of-N node primitive (EXTENSION-QUORUM v1.0).
//!
//! K-of-N consensus over an entity is a primitive authorization pattern, not
//! identity-specific. Provides the K-of-N node entity, K-of-N validator
//! (`verify_k_of_n_signatures`), live signer-set resolver
//! (`current_signer_set`), `is_quorum_id` predicate, and pluggable
//! resolver registry (`concrete` built-in; consumers register others
//! such as `identity-resolved`).
//!
//! Spec: `../entity-core-architecture/docs/architecture/v7.0-core-revision/core-protocol-domain/specs/extensions/EXTENSION-QUORUM.md`

pub mod cache;
pub mod data;
pub mod handler;
pub mod helpers;
pub mod resolver;

#[cfg(test)]
mod tests;

pub use cache::{SignerSet, SignerSetCache};
pub use data::{hex_segment, path_quorum, path_quorum_event, QuorumData};
pub use handler::QuorumHandler;
pub use helpers::{
    current_signer_set, current_signer_set_as_of, is_quorum_id, verify_k_of_n_signatures,
    QuorumCtx,
};
pub use resolver::{
    RegisterError, ResolverContext, ResolverError, ResolverFn, ResolverRegistry,
    MAX_RESOLVER_DEPTH,
};

use thiserror::Error;

/// `properties.kind` values owned by this extension (per §3.2, §3.3).
pub const KIND_QUORUM_UPDATE: &str = "quorum-update";
pub const KIND_QUORUM_PUBLISH: &str = "quorum-publish";

/// Built-in signer-resolution mode (per §5.1).
pub const RESOLUTION_CONCRETE: &str = "concrete";

/// Storage prefix for `system/quorum` entities (per §7).
pub const QUORUM_STORAGE_PREFIX: &str = "system/quorum/";

/// Storage suffix for `quorum-update` / `quorum-publish` events under a quorum (per §7).
pub const QUORUM_EVENT_SEGMENT: &str = "/event/";

#[derive(Debug, Error)]
pub enum QuorumError {
    #[error("quorum entity decode failed: {0}")]
    Decode(String),
    #[error("quorum entity encode failed: {0}")]
    Encode(String),
    #[error("invalid quorum: {0}")]
    Invalid(String),
    /// Per §5.3.1 — a quorum specified a `signer_resolution` mode for which
    /// no resolver is registered. Implementations MUST fail-closed.
    #[error("quorum_resolver_unavailable: mode={mode_name} quorum={quorum_id_hex}")]
    ResolverUnavailable {
        quorum_id_hex: String,
        mode_name: String,
        available_modes: Vec<String>,
    },
    /// Per spec v1.1 IDENTITY-2 — resolver chain exceeded
    /// `MAX_RESOLVER_DEPTH` (default 8).
    #[error("identity_resolver_max_depth_exceeded: max_depth={max_depth} quorum={quorum_id_hex}")]
    ResolverDepthExceeded {
        quorum_id_hex: String,
        max_depth: usize,
    },
    /// Per spec v1.1 IDENTITY-2 — resolver chain revisited an identity
    /// reference (cycle).
    #[error("identity_resolver_cycle: cycle_at={cycle_at_hex} quorum={quorum_id_hex}")]
    ResolverCycle {
        quorum_id_hex: String,
        cycle_at_hex: String,
    },
}
