//! Path conventions per EXTENSION-IDENTITY v3.2 §5.
//!
//! All paths returned here are peer-relative (no leading `/{peer_id}/`).
//! Callers qualify with their local peer's namespace.

use entity_attestation::hex_segment;
use entity_hash::Hash;

use crate::kinds::Mode;

pub const PATH_PEER_CONFIG: &str = "system/identity/peer-config";

/// `system/identity/internal/cert/{hash_hex}` — internal-tier cert.
pub fn path_internal_cert(att_hash: &Hash) -> String {
    format!("system/identity/internal/cert/{}", hex_segment(att_hash))
}

/// `system/identity/public/cert/{hash_hex}` — public-tier cert.
pub fn path_public_cert(att_hash: &Hash) -> String {
    format!("system/identity/public/cert/{}", hex_segment(att_hash))
}

/// `system/identity/relationships/{contact_id_hex}/cert/{hash_hex}`.
pub fn path_relationship_cert(contact_id: &Hash, att_hash: &Hash) -> String {
    format!(
        "system/identity/relationships/{}/cert/{}",
        hex_segment(contact_id),
        hex_segment(att_hash)
    )
}

/// `system/identity/contacts/{handle_hex}/quorum-publish` — cached
/// `quorum-publish` attestation (§9.4 trust anchor).
pub fn path_contact_quorum_publish(handle: &Hash) -> String {
    format!(
        "system/identity/contacts/{}/quorum-publish",
        hex_segment(handle)
    )
}

/// `canonical_cert_path` per §5.3 — dispatch by `mode` only. Returns
/// `None` for `Embedded` mode (cert lives inside cap envelopes; no tree
/// path).
pub fn canonical_cert_path(
    mode: Mode,
    contact_id: Option<&Hash>,
    att_hash: &Hash,
) -> Option<String> {
    match mode {
        Mode::Internal => Some(path_internal_cert(att_hash)),
        Mode::Public => Some(path_public_cert(att_hash)),
        Mode::PerRelationship => contact_id.map(|c| path_relationship_cert(c, att_hash)),
        Mode::Embedded => None,
    }
}

/// `same_tier_path` per §5.3 — lifecycle events (rotation/retirement/
/// revocation) co-locate with their target cert. Caller derives `mode`
/// from the target cert's properties and supplies it here.
pub fn same_tier_path(
    target_mode: Mode,
    target_contact_id: Option<&Hash>,
    att_hash: &Hash,
) -> Option<String> {
    canonical_cert_path(target_mode, target_contact_id, att_hash)
}

/// PI-5 (PROPOSAL-IDENTITY-COMPOSITION-CLEANUP §PI-5, Rev 3): controller-
/// events stream path. Emit point for failure-observation +
/// recovery-signal events from `:process_attestation` Phase 2 handlers
/// and from `:publish_attestation` orphan-binding recovery (PI-3).
///
/// `system/identity/events/{ts_ms}/{handler_id}/{att_hash}/{event_hash}`.
/// The trailing `{event_hash}` segment makes the path unique-by-content
/// (any change to the event entity's data produces a distinct hash;
/// identical events at the same instant collapse to the same path —
/// idempotent semantic per Rev 1 spec).
pub fn path_identity_event(
    timestamp_ms: u64,
    handler_id: &str,
    attestation_hash: &Hash,
    event_hash: &Hash,
) -> String {
    format!(
        "system/identity/events/{}/{}/{}/{}",
        timestamp_ms,
        handler_id,
        hex_segment(attestation_hash),
        hex_segment(event_hash),
    )
}
