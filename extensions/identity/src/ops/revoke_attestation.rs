//! `system/identity:revoke_attestation` — creates a `kind=revocation`
//! attestation entity (attesting=quorum, attested=target_hash) bound at the
//! target's same-tier path, per EXTENSION-IDENTITY §6 + EXTENSION-ATTESTATION
//! §6.3.

use entity_attestation::{
    persist_attestation, walk_attesting_chain_default, AttestationData, KIND_REVOCATION,
};
use entity_ecf::text;
use entity_handler::{
    HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST, STATUS_NOT_FOUND,
};
use entity_hash::Hash;
use entity_quorum::{is_quorum_id, QuorumCtx};

use crate::data::{decode_map, field_hash, field_string_opt};
use crate::handler::{error, revoke_attestation_result, IdentityHandler};
use crate::kinds::Mode;
use crate::validation::{read_function, read_mode};

impl IdentityHandler {
    pub(crate) async fn handle_revoke_attestation(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        // R-12 (cross-impl spec, Round 7): per
        // EXTENSION-IDENTITY §6 + EXTENSION-ATTESTATION §6.3, revoke
        // CREATES a `kind=revocation` attestation entity (attesting=quorum,
        // attested=target_hash) bound at the target's same-tier path.
        // Pre-R-12 Rust just removed a tree binding — that's neither the
        // wire shape nor the spec semantics.
        //
        // Wire shape: `{target_hash: hash, reason?: string}`. NO resource
        // target (Go SDK doesn't supply path-as-resource on revoke; the
        // canonical revocation path is derived from the target cert's
        // mode + contact_id).
        //
        // Algorithm (matches Go's `handleRevokeAttestation`
        // ext/identity/ops.go:147–...):
        //   1. Decode target_hash + optional reason from request.
        //   2. Load target attestation from index.
        //   3. Validate target is identity-context kind.
        //   4. Walk chain from target back to its trusted quorum.
        //   5. Build revocation AttestationData with attesting=quorum_id.
        //   6. Persist at the target's same-tier path.
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let target_hash = match field_hash(&map, "target_hash") {
            Ok(h) => h,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let reason = field_string_opt(&map, "reason").ok().flatten();

        let target = match self.attestation_index.get(&target_hash) {
            Some(t) => t,
            None => {
                return Ok(error(
                    STATUS_NOT_FOUND,
                    "target_not_found",
                    &format!("attestation {:?} not in index", target_hash),
                ));
            }
        };

        // §3.6 chain walk back to the trusted quorum. Identity revoke
        // requires a quorum-rooted target so the revocation entity's
        // `attesting` field is the quorum_id.
        let actx = self.ctx(&ctx.included);
        let attestation_actx = actx.attestation_ctx();
        let resolver_registry = &self.resolver_registry;
        let signer_set_cache = &self.signer_set_cache;
        let chain = walk_attesting_chain_default(
            &target_hash,
            &target,
            |a, c| {
                is_quorum_id(
                    &a.attesting,
                    &QuorumCtx {
                        attestation_index: c.index,
                        content_store: c.content_store,
                        location_index: c.location_index,
                        included: c.included,
                        resolver_registry,
                        signer_set_cache,
                    },
                )
            },
            &attestation_actx,
        );
        let chain = match chain {
            Some(c) if !c.is_empty() => c,
            _ => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "chain_to_quorum_not_found",
                    "target's chain does not terminate at a known quorum",
                ));
            }
        };
        let quorum_id = chain.last().expect("non-empty chain").1.attesting;

        // Build revocation properties (kind=revocation + optional reason),
        // ECF-sorted.
        let mut props: Vec<(ciborium::Value, ciborium::Value)> = Vec::new();
        props.push((text("kind"), text(KIND_REVOCATION)));
        if let Some(r) = &reason {
            props.push((text("reason"), text(r)));
        }
        props.sort_by(|a, b| a.0.as_text().unwrap_or("").cmp(b.0.as_text().unwrap_or("")));
        let rev_att = AttestationData {
            attesting: quorum_id,
            attested: target_hash,
            properties: props,
            supersedes: None,
            not_before: None,
            expires_at: None,
        };
        let rev_entity = match rev_att.to_entity() {
            Ok(e) => e,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "encode_failed", &e.to_string())),
        };
        let rev_hash = rev_entity.content_hash;

        // Same-tier path: revocation co-locates with its target.
        // Determine target's mode + contact_id from target's properties.
        let target_mode_str = read_mode(&target);
        let target_contact_id = target
            .properties
            .iter()
            .find_map(|(k, v)| {
                if k.as_text() == Some("contact_id") {
                    v.as_bytes()
                } else {
                    None
                }
            })
            .and_then(|b| Hash::from_bytes(b).ok());
        let path = match target_mode_str.and_then(|s| Mode::parse(s).ok()) {
            Some(target_mode) => {
                match crate::paths::same_tier_path(
                    target_mode,
                    target_contact_id.as_ref(),
                    &rev_hash,
                ) {
                    Some(bare) => self.qualify(&bare),
                    None => {
                        return Ok(error(
                            STATUS_BAD_REQUEST,
                            "embedded_target_no_revocation_path",
                            "cannot revoke an embedded-mode target (no tree path)",
                        ));
                    }
                }
            }
            None => {
                // Target without mode (e.g., quorum self-events): fall back
                // to a generic attestation tree path.
                self.qualify(&format!(
                    "system/attestation/{}",
                    entity_attestation::hex_segment(&rev_hash)
                ))
            }
        };

        if let Err(e) = persist_attestation(
            &self.content_store,
            &self.location_index,
            &self.attestation_index,
            &path,
            rev_att,
        ) {
            return Ok(error(STATUS_BAD_REQUEST, "store_failed", &e.to_string()));
        }

        // Side effect: if the target was a controller-cert, revoke the
        // local-peer→controller cap so subsequent EXECUTEs under the
        // controller chain fail-closed (per spec §6.4 deployment policy).
        if read_function(&target) == Some("controller") {
            self.revoke_peer_to_controller_cap(&target.attested);
        }

        Ok(revoke_attestation_result(rev_hash))
    }
}
