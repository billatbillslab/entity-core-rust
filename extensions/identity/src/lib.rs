//! `system/identity` handler — structured COMPOSITION LAYER over
//! EXTENSION-ATTESTATION and EXTENSION-QUORUM substrates
//! (EXTENSION-IDENTITY v3.4 + PROPOSAL-IDENTITY-COMPOSITION-CLEANUP).
//!
//! PS-1 (PROPOSAL-IDENTITY-COMPOSITION-CLEANUP §PS-1): renamed from
//! "convention layer" to "composition layer." Identity actively
//! registers an `identity-resolved` resolver against EXTENSION-QUORUM,
//! defines validators, owns four `identity-*` properties.kind values,
//! and orchestrates substrate ops + V7 cap-layer ops + sync-hook side
//! effects in single user-visible flows like `:configure` and
//! `:create_attestation`. That's not "convention" — it's composition.
//!
//! Identity adds essentially zero new entity types — just `peer-config`
//! (per-agent local state) and `identity-binding` (helper inner type).
//! The substrate primitives provide the entity types (`system/attestation`
//! / `system/quorum`), validators (signature, K-of-N, liveness,
//! supersedes), and graph operations.
//!
//! Identity contributes:
//! - 4 identity-context `properties.kind` values + `function`/`mode` shape
//! - Topology dispatch (which kind requires K-of-N, dual-sig, single-sig)
//! - Cert-chain walking back to the root quorum
//! - Authority-revocation rules
//! - Storage path conventions (per audience tier)
//! - Identity-resolved signer-resolution mode registration

pub mod attestation_store;
pub mod data;
pub mod handler;
pub mod kinds;
mod ops;
pub mod paths;
pub mod validation;

#[cfg(test)]
mod tests;

pub use attestation_store::IdentityAttestationStore;

pub use data::{IdentityBindingData, PeerConfigData};
pub use handler::IdentityHandler;
pub use kinds::{
    identity_lifecycle_kinds, is_valid_mode_for_function, valid_functions, Function, Mode,
    KIND_IDENTITY_CERT, KIND_IDENTITY_RETIREMENT, KIND_IDENTITY_ROTATION_HANDOFF,
    KIND_IDENTITY_ROTATION_RECOVERY,
};
pub use paths::{
    canonical_cert_path, path_contact_quorum_publish, path_internal_cert, path_public_cert,
    path_relationship_cert, same_tier_path, PATH_PEER_CONFIG,
};
pub use validation::{
    identity_confers_function, identity_is_authorized_revoker, identity_is_quorum_link,
    identity_topology_for, identity_verify_cert, lookup_target_cert,
    walk_cert_chain_to_current_controller, IdentityCtx, Topology, VerifyCertError,
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("decode error: {0}")]
    Decode(String),
    #[error("encode error: {0}")]
    Encode(String),
    #[error("invalid params: {0}")]
    InvalidParam(String),
}
