//! `system/identity:configure` — installs per-agent local state (peer-config
//! at `system/identity/peer-config`) and issues local-peer→controller caps
//! per the live controller set under `trusts_quorum`. Per EXTENSION-IDENTITY
//! §6 + PROPOSAL-IDENTITY-COMPOSITION-CLEANUP §PI-2 (5-phase ordering).

use std::collections::HashMap;
use std::sync::Arc;

use entity_attestation::AttestationData;
use entity_entity::Entity;
use entity_handler::{
    HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST, STATUS_FORBIDDEN,
    STATUS_NOT_FOUND,
};
use entity_hash::Hash;
use entity_quorum::path_quorum;

use crate::data::{
    decode_bindings, decode_grants, decode_map, field_hash, get_field, PeerConfigData,
};
use crate::handler::{configure_result, error, require_resource, IdentityHandler};
use crate::kinds::KIND_IDENTITY_CERT;
use crate::paths::PATH_PEER_CONFIG;
use crate::validation;
use crate::validation::{
    identity_confers_function, identity_verify_cert, read_function, IdentityCtx,
};

impl IdentityHandler {
    pub(crate) async fn handle_configure(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        // PI-2 (PROPOSAL-IDENTITY-COMPOSITION-CLEANUP §PI-2, Rev 3):
        // 5-phase ordered pseudocode. Phase 1 is purely structural; the
        // binding-controller-liveness check moved from phase 1 to phase 2
        // post-enumeration (Rev 3 phase-ordering fix). Phases execute in
        // order; failure at phase N short-circuits subsequent phases.
        // Empty bindings is a valid configure shape — phase 1 passes;
        // phases 2-4 still execute; phase 5 persists with bindings: [].

        // Resource MUST be system/identity/peer-config (§6).
        let expected = self.qualify(PATH_PEER_CONFIG);
        if let Err(e) = require_resource(ctx, &expected) {
            return Ok(e);
        }

        // ---------- Phase 1: validate_inputs (structural only) ----------
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let trusts_quorum = match field_hash(&map, "trusts_quorum") {
            Ok(h) => h,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let controller_grants = match decode_grants(get_field(&map, "controller_grants")) {
            Ok(g) => g,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let bindings = match decode_bindings(get_field(&map, "bindings")) {
            Ok(b) => b,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };

        // Quorum existence (structural).
        if !self.quorum_present(&trusts_quorum) {
            return Ok(error(
                STATUS_NOT_FOUND,
                "quorum_not_found",
                "trusts_quorum entity not in tree",
            ));
        }

        // Per §6.1 / §10.1, register `identity-resolved` resolver against
        // the quorum hook on configure.
        self.register_identity_resolved_resolver();

        let actx = self.ctx(&ctx.included);

        // Phase 1: per-binding STRUCTURAL validation only — zero-hash,
        // entity-resolves, kind/function shape, signature/topology. Rev 3:
        // does NOT check binding controller liveness here (phase 2).
        for binding in &bindings {
            if let Err(result) = self.validate_binding_structural(binding, &actx) {
                return Ok(result);
            }
        }

        // ---------- Phase 2: enumerate_live_controller_certs ----------
        // R-7 (cross-impl spec): enumerate live top-level
        // controller-certs anchored under the trusted quorum. Per spec §3.2
        // (resolve_controller_for_grants) + Go reference, the search is by
        // `attesting == trusts_quorum` filtered by
        // `identity_confers_function(controller)` (SI-13 — handles
        // handoff/recovery inheritance; retirement terminates dead).
        let actx_a = actx.attestation_ctx();
        let candidate_certs = entity_attestation::find_attestations_by(
            &trusts_quorum,
            |a| identity_confers_function(a, "controller", &actx),
            &actx_a,
        );
        let mut live_controller_certs: Vec<(Hash, AttestationData)> = Vec::new();
        for (cert_hash, cert) in candidate_certs {
            if entity_attestation::is_attestation_live(&cert_hash, &cert, &actx_a, None) {
                live_controller_certs.push((cert_hash, cert));
            }
        }
        if live_controller_certs.is_empty() {
            return Ok(error(
                STATUS_NOT_FOUND,
                "no_live_controller",
                "no live top-level controller cert under trusts_quorum",
            ));
        }

        // Phase 2 (Rev 3): binding-controller-liveness check FIRST, then
        // binding-cert topology verification. Liveness is the more specific
        // check — if the agent_cert's issuing controller isn't in the live
        // set, surface `binding_controller_not_live` rather than the
        // generic `cert_invalid` topology error.
        for binding in &bindings {
            if let Err(result) =
                self.check_binding_controller_liveness(binding, &live_controller_certs)
            {
                return Ok(result);
            }
            if let Err(result) = self.verify_binding_topology(binding, &actx) {
                return Ok(result);
            }
        }

        // ---------- Phase 3: verify_each_controller_cert ----------
        for (cert_hash, cert) in &live_controller_certs {
            if let Err(e) = identity_verify_cert(cert_hash, cert, &actx) {
                return Ok(error(
                    STATUS_FORBIDDEN,
                    "controller_invalid",
                    &format!("{:?}: {}", cert_hash, e),
                ));
            }
        }

        // ---------- Phase 4: issue_local_caps ----------
        // EXTENSION-IDENTITY v3.7 (A.4): MUST issue one local-peer→
        // controller capability per **distinct verified controller**, not
        // per controller-cert / attestation. Multiple controller-certs may
        // attest the same controller identity; without dedupe, N-1 caps
        // orphan at the same canonical path on every ceremony re-run
        // (PERSISTENCE-FEEDBACK Finding 1 Q1). The dedupe key is
        // `cert.attested` (the controller's identity hash) — the same
        // value used as the per-controller cap-path segment.
        let mut issued: Vec<Hash> = Vec::new();
        let mut seen_controllers: std::collections::HashSet<Hash> =
            std::collections::HashSet::new();
        for (_cert_hash, cert) in &live_controller_certs {
            if !seen_controllers.insert(cert.attested) {
                continue;
            }
            match self.issue_peer_to_controller_cap(&cert.attested, &controller_grants) {
                Ok(h) => issued.push(h),
                Err(e) => {
                    return Ok(error(
                        STATUS_BAD_REQUEST,
                        "cap_issuance_failed",
                        &e,
                    ));
                }
            }
        }

        // ---------- Phase 5: register_bindings (persist peer-config) ----------
        let pc = PeerConfigData {
            trusts_quorum,
            controller_grants: controller_grants.clone(),
            bindings: bindings.clone(),
        };
        let pc_entity = match pc.to_entity() {
            Ok(e) => e,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "encode_failed", &e.to_string())),
        };
        let pc_hash = pc_entity.content_hash;
        if let Err(e) = self.content_store.put(pc_entity) {
            return Ok(error(STATUS_BAD_REQUEST, "store_failed", &e.to_string()));
        }
        self.location_index.set(&expected, pc_hash);

        Ok(configure_result(&expected, &issued))
    }

    /// PI-2 phase 1: PURELY STRUCTURAL binding validation. Checks shape
    /// only (zero-hash, entity-resolves, kind/function). No topology
    /// check — that requires the enumerated live controller set and runs
    /// in phase 2 (Rev 3 phase-ordering fix).
    ///
    /// Errors:
    /// - 400 binding_missing_handle_cert / _agent_cert (zero hash)
    /// - 404 binding_cert_not_found (non-zero hash, no entity)
    /// - 400 binding_cert_wrong_kind (kind/function mismatch)
    fn validate_binding_structural(
        &self,
        binding: &crate::data::IdentityBindingData,
        _actx: &validation::IdentityCtx,
    ) -> Result<(), HandlerResult> {
        if binding.handle_cert == Hash::zero() {
            return Err(error(
                STATUS_BAD_REQUEST,
                "binding_missing_handle_cert",
                "binding.handle_cert is required",
            ));
        }
        if binding.agent_cert == Hash::zero() {
            return Err(error(
                STATUS_BAD_REQUEST,
                "binding_missing_agent_cert",
                "binding.agent_cert is required",
            ));
        }
        // Three-key default: handle_cert.function ∈ {controller, identifier};
        // agent_cert.function == agent. Both kind == identity-cert.
        for (label, cert_hash, expected_functions) in [
            ("handle_cert", &binding.handle_cert, &["controller", "identifier"][..]),
            ("agent_cert", &binding.agent_cert, &["agent"][..]),
        ] {
            let cert = match self.attestation_index.get(cert_hash) {
                Some(c) => c,
                None => {
                    return Err(error(
                        STATUS_NOT_FOUND,
                        "binding_cert_not_found",
                        &format!(
                            "{}: attestation entity not in local store or envelope.included",
                            label
                        ),
                    ));
                }
            };
            if cert.kind() != Some(KIND_IDENTITY_CERT) {
                return Err(error(
                    STATUS_BAD_REQUEST,
                    "binding_cert_wrong_kind",
                    &format!(
                        "{}: expected kind=identity-cert, got {:?}",
                        label,
                        cert.kind()
                    ),
                ));
            }
            let function = read_function(&cert);
            if !expected_functions.iter().any(|f| function == Some(f)) {
                return Err(error(
                    STATUS_BAD_REQUEST,
                    "binding_cert_wrong_kind",
                    &format!(
                        "{}: expected function ∈ {:?}, got {:?}",
                        label, expected_functions, function
                    ),
                ));
            }
        }
        Ok(())
    }

    /// PI-2 phase 2 (Rev 3): binding-cert topology + controller-liveness
    /// verification. Runs AFTER `enumerate_live_controller_certs` so we
    /// can verify each binding cert's authority chain AND check that the
    /// agent_cert chains under a live controller. Phase 1 stays purely
    /// structural; phase 2 does the authority work that needs the live set.
    fn verify_binding_topology(
        &self,
        binding: &crate::data::IdentityBindingData,
        actx: &validation::IdentityCtx,
    ) -> Result<(), HandlerResult> {
        for (label, cert_hash) in [
            ("handle_cert", &binding.handle_cert),
            ("agent_cert", &binding.agent_cert),
        ] {
            let cert = match self.attestation_index.get(cert_hash) {
                Some(c) => c,
                None => {
                    return Err(error(
                        STATUS_BAD_REQUEST,
                        "binding_controller_not_live",
                        &format!("{} disappeared during configure", label),
                    ));
                }
            };
            if let Err(e) = identity_verify_cert(cert_hash, &cert, actx) {
                return Err(error(
                    STATUS_FORBIDDEN,
                    "cert_invalid",
                    &format!("{}: {}", label, e),
                ));
            }
        }
        Ok(())
    }

    /// PI-2 phase 2 (Rev 3): binding-controller-liveness check. The agent
    /// cert's `attesting` field is the issuing controller's peer-identity
    /// hash; that identity MUST be the `attested` of a live controller cert
    /// in `live_controller_certs`. Prevents bindings to retired or
    /// non-existent controllers. Per Go feedback §3.4.
    ///
    /// Error: 400 binding_controller_not_live
    fn check_binding_controller_liveness(
        &self,
        binding: &crate::data::IdentityBindingData,
        live_controller_certs: &[(Hash, AttestationData)],
    ) -> Result<(), HandlerResult> {
        let agent_cert = match self.attestation_index.get(&binding.agent_cert) {
            Some(c) => c,
            // Phase 1 already 404'd this case; here we'd only reach this
            // if the index changed mid-flight. Fail-closed.
            None => {
                return Err(error(
                    STATUS_BAD_REQUEST,
                    "binding_controller_not_live",
                    "agent_cert disappeared from index during configure",
                ));
            }
        };
        let issuer_identity = agent_cert.attesting;
        let live = live_controller_certs
            .iter()
            .any(|(_h, c)| c.attested == issuer_identity);
        if !live {
            return Err(error(
                STATUS_BAD_REQUEST,
                "binding_controller_not_live",
                &format!(
                    "binding.agent_cert.attesting ({:?}) does not resolve to the attested of any live controller cert",
                    issuer_identity
                ),
            ));
        }
        Ok(())
    }

    fn register_identity_resolved_resolver(&self) {
        let attestation_index = self.attestation_index.clone();
        let resolver_registry = self.resolver_registry.clone();
        let signer_set_cache = self.signer_set_cache.clone();
        let resolver: entity_quorum::ResolverFn = Arc::new(move |identity_ref, rctx| {
            // identity_ref is interpreted as a quorum_id (canonical handle
            // for an identity in `identity-resolved` mode per §6.1).
            // Per IDENTITY-2 (spec v1.1): track depth + cycle. The walk
            // here is single-hop (cert chain → controller), so we don't
            // recurse — but we still register entry to support callers
            // composing identity-resolved chains via multiple quorums.
            rctx.enter(*identity_ref)?;
            let included: HashMap<Hash, Entity> = HashMap::new();
            let ctx = IdentityCtx {
                attestation_index: &attestation_index,
                content_store: rctx.content_store,
                location_index: rctx.location_index,
                included: &included,
                resolver_registry: &resolver_registry,
                signer_set_cache: &signer_set_cache,
            };
            crate::validation::walk_cert_chain_to_current_controller(identity_ref, &ctx)
                .map(|(_, cert)| cert.attested)
                .ok_or(entity_quorum::ResolverError::Unresolved)
        });
        // PR-6: register may return RegisterError::AlreadyRegistered if a
        // different resolver was previously registered for `identity-resolved`.
        // Idempotent re-registration of the same Arc is a no-op success.
        // For install-time registration, log+ignore — the only legitimate
        // collision is a second IdentityHandler instance with a fresh resolver
        // closure (in which case the first one stays bound, fail-closed).
        if let Err(e) =
            self.resolver_registry.register("identity-resolved", resolver)
        {
            tracing::warn!("identity-resolved resolver already registered: {}", e);
        }
    }

    fn quorum_present(&self, quorum_id: &Hash) -> bool {
        let path = self.qualify(&path_quorum(quorum_id));
        self.location_index.get(&path).is_some()
    }
}
