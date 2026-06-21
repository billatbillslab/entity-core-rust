//! `system/identity:supersede_attestation` — supersedes a prior attestation
//! per EXTENSION-IDENTITY §6 + PI-1 rebind dispatch. For REBIND_KINDS
//! (identity-cert), caller supplies new attesting/attested (controller
//! rotation). For other kinds, predecessor's attesting/attested are
//! preserved (substrate `:supersede` semantics).

use entity_attestation::{persist_attestation, AttestationData};
use entity_handler::{
    HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST, STATUS_NOT_FOUND,
};
use entity_hash::Hash;

use crate::data::{decode_map, field_hash, field_map_opt, field_u64_opt};
use crate::handler::{error, supersede_attestation_result, IdentityHandler};
use crate::kinds::KIND_IDENTITY_CERT;
use crate::validation::read_mode;

impl IdentityHandler {
    pub(crate) async fn handle_supersede_attestation(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        // Per EXTENSION-ATTESTATION §6.1 / §6.2 wire-shape: supersede uses
        // the same flat AttestationData shape as `:create`, with
        // `supersedes` set to the previous attestation's hash. This mirrors
        // Go's `IdentitySupersedeAttestationRequestData` (which embeds
        // `AttestationData`).
        //
        // R-8 (cross-impl spec, Round 1): pre-R-8 Rust
        // expected a distinct `{previous_hash, properties?, ...}` shape per
        // §6.2's pseudo-spec. The §6.1/§6.2 conflict in the spec was
        // resolved by Go's reference impl picking §6.1 (flat). Aligning
        // with Go.
        //
        // R-8' (Round-6 reframe): identity-level supersede does NOT enforce
        // §6.2's attesting/attested-match constraint — that's a substrate-
        // level invariant for use cases like updating cap-token properties
        // without changing the granter/grantee. Identity supersede is the
        // controller/identifier rotation primitive: kind stays the same,
        // but `attested` LEGITIMATELY changes (it's the new key). Go's
        // `handleSupersedeAttestation` enforces only KIND match. Rust
        // matches Go's reading; spec-clarity item logged for the
        // architecture team to pin which §6.2 invariants apply at the
        // identity layer.
        // PI-1 (PROPOSAL-IDENTITY-COMPOSITION-CLEANUP, Rev 3): two paths
        // depending on kind.
        //   REBIND_KINDS (identity-cert): controller rotation legitimately
        //     changes attesting AND attested → call substrate `:create`
        //     with explicit `supersedes` (caller-supplied attesting/attested).
        //   Other kinds (rotation-handoff, rotation-recovery, retirement,
        //     revocation): preserve substrate `:supersede` semantics — copy
        //     predecessor's attesting/attested, accept only properties + bounds.
        // Adding kinds to REBIND_KINDS is a normative spec amendment.
        const REBIND_KINDS: &[&str] = &[KIND_IDENTITY_CERT];

        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let supersedes = match field_hash(&map, "supersedes") {
            Ok(h) => h,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let previous = match self.attestation_index.get(&supersedes) {
            Some(p) => p,
            None => return Ok(error(STATUS_NOT_FOUND, "previous_not_found", "")),
        };
        let prev_kind_str = previous.kind().unwrap_or("").to_string();
        let is_rebind_kind = REBIND_KINDS.iter().any(|k| *k == prev_kind_str);

        // PI-1: caller-supplied attesting/attested only for REBIND_KINDS;
        // non-rebind kinds preserve predecessor fields (substrate :supersede).
        let attesting = if is_rebind_kind {
            match field_hash(&map, "attesting") {
                Ok(h) => h,
                Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
            }
        } else {
            previous.attesting
        };
        let attested = if is_rebind_kind {
            match field_hash(&map, "attested") {
                Ok(h) => h,
                Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
            }
        } else {
            previous.attested
        };
        let new_properties = match field_map_opt(&map, "properties") {
            Ok(v) => v,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let not_before = match field_u64_opt(&map, "not_before") {
            Ok(v) => v.or(previous.not_before),
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let expires_at = match field_u64_opt(&map, "expires_at") {
            Ok(v) => v.or(previous.expires_at),
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };

        // Properties: replace if caller supplied (sorted for ECF
        // determinism); inherit from previous otherwise.
        let properties = match new_properties {
            Some(mut props) => {
                props.sort_by(|a, b| {
                    a.0.as_text().unwrap_or("").cmp(b.0.as_text().unwrap_or(""))
                });
                props
            }
            None => previous.properties.clone(),
        };

        // R-8' kind-match check: predecessor and successor MUST share
        // `properties.kind`. Crossing kinds via supersede is a structural
        // error — identity-cert can't supersede a rotation-recovery, etc.
        // PI-1: orthogonal to the REBIND_KINDS dispatch above; both branches
        // require kind invariance.
        let new_kind = properties
            .iter()
            .find_map(|(k, v)| if k.as_text() == Some("kind") { v.as_text() } else { None })
            .unwrap_or("");
        if prev_kind_str != new_kind {
            return Ok(error(
                STATUS_BAD_REQUEST,
                "kind_mismatch",
                &format!(
                    "supersede crosses kinds: prev={} new={}",
                    prev_kind_str, new_kind
                ),
            ));
        }

        let att = AttestationData {
            attesting,
            attested,
            properties,
            supersedes: Some(supersedes),
            not_before,
            expires_at,
        };

        // Path: same canonical mode/tier as previous.
        let mode_str = read_mode(&previous).map(|s| s.to_string());
        let contact_id = previous
            .properties
            .iter()
            .find_map(|(k, v)| if k.as_text() == Some("contact_id") { v.as_bytes() } else { None })
            .and_then(|b| Hash::from_bytes(b).ok());
        let path = match self.compute_storage_path(&att, &prev_kind_str, mode_str.as_deref(), contact_id.as_ref())? {
            Some(p) => p,
            None => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "embedded_supersede",
                    "cannot supersede an embedded-mode cert at a tree path",
                ));
            }
        };
        let hash = match persist_attestation(
            &self.content_store,
            &self.location_index,
            &self.attestation_index,
            &path,
            att,
        ) {
            Ok(h) => h,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "store_failed", &e.to_string())),
        };
        Ok(supersede_attestation_result(hash, Some(&path)))
    }
}
