//! `system/identity:process_attestation` — validates an attestation and
//! dispatches kind-keyed side effects (cap issuance, cap revocation,
//! handle-cache update). Per EXTENSION-IDENTITY §6.3.

use entity_attestation::AttestationData;
use entity_capability::GrantEntry;
use entity_handler::{
    HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST, STATUS_NOT_FOUND,
};
use entity_hash::Hash;

use crate::data::{decode_map, field_hash, PeerConfigData};
use crate::handler::{error, status_ok, IdentityHandler};
use crate::kinds::{KIND_IDENTITY_CERT, KIND_IDENTITY_RETIREMENT, KIND_IDENTITY_ROTATION_RECOVERY};
use crate::paths::{path_contact_quorum_publish, PATH_PEER_CONFIG};
use crate::validation::{identity_verify_cert, read_function};

impl IdentityHandler {
    pub(crate) async fn handle_process_attestation(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        // §6.3 algorithm (per spec v3.3 / SI-10):
        //   Phase 1 — validate via identity_verify_cert
        //   Phase 2a — on validation failure, unbind path (fail-closed)
        //   Phase 2b — on success, dispatch side effects in deterministic order
        //   Phase 3 — quorum-publish cache seeding (separate from kind dispatch)
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let attestation_hash = match field_hash(&map, "attestation_hash") {
            Ok(h) => h,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        // Resource target (when supplied) is the attestation's stored path
        // — used for fail-closed unbind. Optional in v3.3 to keep
        // explicit-call path callable without staging a binding first.
        let bound_path = self.resource_path(ctx);
        let att = match self.attestation_index.get(&attestation_hash) {
            Some(a) => a,
            None => return Ok(error(STATUS_NOT_FOUND, "attestation_not_indexed", "")),
        };
        // For quorum-publish, route to the dedicated cache-seed path
        // (the substrate validates K-of-N for quorum entities itself; we
        // just cache the published_handle for §9.4 compromise-recovery).
        let kind = att.kind().unwrap_or("");
        if kind == entity_quorum::KIND_QUORUM_PUBLISH {
            self.seed_contact_quorum_publish_cache(&att, attestation_hash);
            return Ok(status_ok());
        }

        // Identity-context kinds: Phase 1 — validate via identity_verify_cert.
        let actx = self.ctx(&ctx.included);
        // §9.4 fail-closed: rotation-recovery for handle-bearing certs MUST
        // validate K-of-N against the cached quorum-publish (§9.4 normative).
        if kind == KIND_IDENTITY_ROTATION_RECOVERY {
            if let Some(reason) = self.compromise_recovery_fail_closed(&att) {
                // Phase 2a — fail-closed unbind.
                if let Some(path) = &bound_path {
                    self.location_index.remove(path);
                }
                return Ok(error(STATUS_BAD_REQUEST, "compromise_recovery_rejected", reason));
            }
        }
        if let Err(e) = identity_verify_cert(&attestation_hash, &att, &actx) {
            // Phase 2a — fail-closed unbind per §6.3.
            if let Some(path) = &bound_path {
                self.location_index.remove(path);
            }
            return Ok(error(STATUS_BAD_REQUEST, "verify_failed", &e.to_string()));
        }

        // PI-5 (PROPOSAL-IDENTITY-COMPOSITION-CLEANUP §PI-5, Rev 3):
        // Phase 2 — dispatch side-effect handlers per (kind, function).
        // Each handler runs independently; failures MUST NOT propagate
        // or affect other handlers' execution. Phase-3 emits a
        // failure-observation event for each handler error (v2 scope:
        // failure-only emission — no informational success events).
        match kind {
            KIND_IDENTITY_CERT => {
                if read_function(&att) == Some("controller") {
                    let handler_id = "maybe_issue_local_controller_cap";
                    if let Some(grants) = self.read_peer_config_controller_grants() {
                        if let Err(e) =
                            self.issue_peer_to_controller_cap(&att.attested, &grants)
                        {
                            self.emit_controller_event(
                                "failure_observation",
                                handler_id,
                                &attestation_hash,
                                kind,
                                "cap_issuance_failed",
                                &e,
                            );
                        }
                    }
                }
            }
            KIND_IDENTITY_RETIREMENT => {
                let handler_id = "revoke_local_caps_for_attested";
                let target_hash = att
                    .properties
                    .iter()
                    .find_map(|(k, v)| {
                        if k.as_text() == Some("target_cert") { v.as_bytes() } else { None }
                    })
                    .and_then(|b| Hash::from_bytes(b).ok());
                match target_hash {
                    Some(t) => match self.attestation_index.get(&t) {
                        Some(target) => {
                            if read_function(&target) == Some("controller") {
                                self.revoke_peer_to_controller_cap(&target.attested);
                            }
                        }
                        None => self.emit_controller_event(
                            "failure_observation",
                            handler_id,
                            &attestation_hash,
                            kind,
                            "target_cert_missing",
                            "retirement.target_cert not in attestation index",
                        ),
                    },
                    None => self.emit_controller_event(
                        "failure_observation",
                        handler_id,
                        &attestation_hash,
                        kind,
                        "target_cert_missing",
                        "retirement properties missing target_cert",
                    ),
                }
            }
            KIND_IDENTITY_ROTATION_RECOVERY => {
                // update_handle_cache_on_recovery is best-effort and
                // logs internally; nothing observable to emit on failure
                // at this granularity in v2.
                self.update_handle_cache_on_recovery(&att);
            }
            _ => {}
        }
        Ok(status_ok())
    }

    /// §9.4 fail-closed gate. Returns `Some(reason)` if a handle-bearing
    /// rotation-recovery has no cached `quorum-publish` to validate
    /// against, or the K-of-N signers don't match the cached signer set.
    fn compromise_recovery_fail_closed(&self, att: &AttestationData) -> Option<&'static str> {
        let old_handle = att
            .properties
            .iter()
            .find_map(|(k, v)| if k.as_text() == Some("old_handle") { v.as_bytes() } else { None })
            .and_then(|b| Hash::from_bytes(b).ok());
        let old_handle = match old_handle {
            Some(h) => h,
            // No old_handle in properties → treat as non-handle-bearing
            // (sub-controller / agent recovery). Pass through to standard
            // identity_verify_cert.
            None => return None,
        };
        let cache_path = self.qualify(&path_contact_quorum_publish(&old_handle));
        let cached_hash = match self.location_index.get(&cache_path) {
            Some(h) => h,
            None => return Some("no cached quorum-publish for old_handle (§9.4)"),
        };
        // Read the cached quorum-publish and check that the recovery's
        // K-of-N is signed by the cached signer set. This is the §9.4
        // trust anchor.
        let cached_publish = match self.attestation_index.get(&cached_hash) {
            Some(a) => a,
            None => return Some("cached quorum-publish entity missing"),
        };
        let cached_signers: Vec<Hash> = cached_publish
            .properties
            .iter()
            .find_map(|(k, v)| if k.as_text() == Some("signers") { v.as_array() } else { None })
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_bytes().and_then(|b| Hash::from_bytes(b).ok()))
                    .collect()
            })
            .unwrap_or_default();
        let cached_threshold: u64 = cached_publish
            .properties
            .iter()
            .find_map(|(k, v)| if k.as_text() == Some("threshold") { v.as_integer() } else { None })
            .and_then(|i| {
                let n: i128 = i.into();
                if n < 0 {
                    None
                } else {
                    Some(n as u64)
                }
            })
            .unwrap_or(0);
        if cached_signers.is_empty() || cached_threshold == 0 {
            return Some("cached quorum-publish has empty signer set");
        }
        let included = std::collections::HashMap::new();
        let qctx = entity_quorum::QuorumCtx {
            attestation_index: &self.attestation_index,
            content_store: &self.content_store,
            location_index: &self.location_index,
            included: &included,
            resolver_registry: &self.resolver_registry,
            signer_set_cache: &self.signer_set_cache,
        };
        // Re-derive the recovery's content_hash by re-encoding (cheap
        // round-trip — already in index but we don't have hash here).
        let recovery_hash = match att.to_entity() {
            Ok(e) => e.content_hash,
            Err(_) => return Some("recovery entity encode failed"),
        };
        let valid = entity_quorum::verify_k_of_n_signatures(
            &recovery_hash,
            &cached_signers,
            cached_threshold,
            &qctx,
        );
        if !valid {
            return Some("recovery K-of-N does not satisfy cached quorum-publish signer set");
        }
        None
    }

    fn update_handle_cache_on_recovery(&self, att: &AttestationData) {
        // Recovery's `attested` is the new handle key. Bind a new
        // contact-cache pointer; old cache entry is retained per §5.1
        // "Cache lifetime across rotations" until impl-defined GC.
        let new_handle = att.attested;
        // We don't have the new quorum-publish here — that arrives
        // separately. The cache update happens when the next
        // quorum-publish for the new key fires seed_contact_quorum_publish_cache.
        // No-op slot kept here for the post-rotation indexing if we want
        // to track the rotation event itself.
        let _ = new_handle;
    }

    fn read_peer_config_controller_grants(&self) -> Option<Vec<GrantEntry>> {
        let path = self.qualify(PATH_PEER_CONFIG);
        let pc_hash = self.location_index.get(&path)?;
        let pc_entity = self.content_store.get(&pc_hash)?;
        let pc = PeerConfigData::from_entity(&pc_entity).ok()?;
        Some(pc.controller_grants)
    }

    /// Seed the contact-quorum-publish cache for a published_handle.
    ///
    /// **Convergence assumption (PROPOSAL-CROSS-IMPL-STANDARDIZATION-CATCHUP
    /// §6 latent-hole tracking):** the write at `path` is unconditional — no
    /// CAS anchor, no compare-against-existing. The single-writer assumption
    /// is "for a given `published_handle`, at most one canonical quorum-
    /// publish exists at a time; processing two concurrently from different
    /// sources yields last-write-wins under §9.4 recovery, with the
    /// fail-closed K-of-N gate as the trust anchor that catches divergence".
    /// If/when identity sync becomes a peer-mirroring surface where multiple
    /// concurrent publishers are valid, this path is one of the sites that
    /// the receiver-local CAS/convergent-mirroring primitive (Go track) will
    /// need to anchor.
    fn seed_contact_quorum_publish_cache(
        &self,
        att: &AttestationData,
        att_hash: Hash,
    ) {
        let handle = att
            .properties
            .iter()
            .find_map(|(k, v)| if k.as_text() == Some("published_handle") { v.as_bytes() } else { None })
            .and_then(|b| Hash::from_bytes(b).ok());
        if let Some(h) = handle {
            let path = self.qualify(&path_contact_quorum_publish(&h));
            self.location_index.set(&path, att_hash);
        }
    }
}
