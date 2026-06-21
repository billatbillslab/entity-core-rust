//! `AttestationStore` impl per EXTENSION-IDENTITY v3.2 §10.1 / §12.3.
//!
//! Looks up live `identity-cert(function="agent")` attestations whose
//! `attested == peer_identity_hash`. Returns the issuing controller as
//! `public_identity` and the cert hash for audit.

use std::sync::Arc;

use entity_attestation::{
    find_attestations_targeting, is_attestation_live, AttestationCtx, AttestationIndex,
};
use entity_handler::{AttestationStatus, AttestationStore};
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};

use crate::kinds::KIND_IDENTITY_CERT;
use crate::validation::read_function;

/// Implementation of `AttestationStore` over the in-memory
/// `AttestationIndex` populated by the attestation primitive's handler
/// (and the SyncTreeHook for cross-peer arrivals).
pub struct IdentityAttestationStore {
    attestation_index: Arc<AttestationIndex>,
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
}

impl IdentityAttestationStore {
    pub fn new(
        attestation_index: Arc<AttestationIndex>,
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
    ) -> Self {
        Self {
            attestation_index,
            content_store,
            location_index,
        }
    }
}

impl AttestationStore for IdentityAttestationStore {
    fn lookup(&self, peer_identity_hash: &Hash) -> AttestationStatus {
        let included = std::collections::HashMap::new();
        let ctx = AttestationCtx {
            index: &self.attestation_index,
            content_store: &self.content_store,
            location_index: &self.location_index,
            included: &included,
        };
        // Find live identity-cert(function=agent) with attested = peer.
        let candidates = find_attestations_targeting(
            peer_identity_hash,
            |a| {
                a.kind() == Some(KIND_IDENTITY_CERT)
                    && read_function(a) == Some("agent")
            },
            &ctx,
        );
        for (h, a) in candidates {
            if is_attestation_live(&h, &a, &ctx, None) {
                return AttestationStatus::Attested {
                    public_identity: a.attesting,
                    attestation_hash: h,
                };
            }
        }
        AttestationStatus::NotAttested
    }
}
