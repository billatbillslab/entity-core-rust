//! `system/attestation` substrate primitive (EXTENSION-ATTESTATION v1.0).
//!
//! The signed-claim entity type. The edge in the system's signed graph.
//! Generic helpers for signature verification, supersedes-chain walking,
//! liveness checks, and revocation lookup. Consumer extensions
//! (EXTENSION-QUORUM, EXTENSION-IDENTITY, future) layer kind-discriminated
//! semantics on top.
//!
//! Spec: `../entity-core-architecture/docs/architecture/v7.0-core-revision/core-protocol-domain/specs/extensions/EXTENSION-ATTESTATION.md`

pub mod data;
pub mod handler;
pub mod helpers;
pub mod hook;
pub mod index;

#[cfg(test)]
mod tests;

pub use data::{hex_segment, AttestationData};
pub use handler::{persist_attestation, AttestationHandler};
pub use hook::AttestationIndexHook;
pub use helpers::{
    default_find_authorizing, find_attestations_by, find_attestations_targeting,
    find_attestations_with_kind, find_attestations_with_supersedes, find_live_head,
    find_revocations_for, is_attestation_live, verify_attestation_signature,
    verify_specific_signer, walk_attesting_chain, walk_attesting_chain_default,
    walk_supersedes_chain, AttestationCtx,
};
pub use index::AttestationIndex;

use thiserror::Error;

/// Universal `properties.kind` value owned by this primitive (per §3.3).
/// All other kind values belong to consumer extensions.
pub const KIND_REVOCATION: &str = "revocation";

/// Default bound on chain-walk depth (per §5.1).
pub const DEFAULT_MAX_DEPTH: usize = 32;

/// PR-7 (PROPOSAL-SYSTEM-PEER-RENAME §PR-7): cross-extension kinds MUST be
/// namespaced (`<domain>-<kindname>`). The single exception is `revocation`,
/// the universal substrate-owned kind. Within-extension internal kinds (not
/// in the kind-ownership table) MAY use unnamespaced names; this validator
/// enforces the rule for substrate-bound attestations entering the wire.
///
/// Returns `Ok(())` if `kind` is valid; `AttestationError::Invalid` otherwise.
pub fn validate_kind(kind: &str) -> Result<(), AttestationError> {
    if kind == KIND_REVOCATION {
        return Ok(());
    }
    if let Some((prefix, _)) = kind.split_once('-') {
        if !prefix.is_empty() {
            return Ok(());
        }
    }
    Err(AttestationError::Invalid(format!(
        "kind_must_be_namespaced: '{}' lacks domain prefix \
         (use '<domain>-<kind>'); only `revocation` may be unnamespaced",
        kind
    )))
}

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("attestation entity decode failed: {0}")]
    Decode(String),
    #[error("attestation entity encode failed: {0}")]
    Encode(String),
    #[error("invalid attestation: {0}")]
    Invalid(String),
}
