//! `system/identity:publish_attestation` — promotes/demotes a
//! `kind="identity-cert" function="agent"` cert to a different mode by
//! rebinding it at the new mode's canonical path. Per EXTENSION-IDENTITY §6
//! + PROPOSAL-IDENTITY-COMPOSITION-CLEANUP §PI-3 (path-MOVE semantics).

use entity_handler::{
    HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST, STATUS_NOT_FOUND,
};
use entity_hash::Hash;

use crate::data::{decode_map, field_hash, field_hash_opt, field_string};
use crate::handler::{error, publish_attestation_result, IdentityHandler};
use crate::kinds::{Function, Mode};
use crate::paths::canonical_cert_path;
use crate::validation::{read_function, read_mode};

impl IdentityHandler {
    pub(crate) async fn handle_publish_attestation(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        // Promote/demote a `kind="identity-cert" function="agent"` cert
        // to a different mode by writing the same logical cert at the new
        // mode's canonical path. Resource = new mode's canonical path.
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let attestation_hash = match field_hash(&map, "attestation_hash") {
            Ok(h) => h,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let new_mode_str = match field_string(&map, "new_mode") {
            Ok(s) => s,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let new_mode = match Mode::parse(&new_mode_str) {
            Ok(m) => m,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_mode", &e.to_string())),
        };
        let contact_id = match field_hash_opt(&map, "contact_id") {
            Ok(v) => v,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let cert = match self.attestation_index.get(&attestation_hash) {
            Some(c) => c,
            None => return Ok(error(STATUS_NOT_FOUND, "cert_not_found", "")),
        };
        let function = read_function(&cert).and_then(Function::parse_optional);
        if !matches!(function, Some(Function::Agent)) {
            return Ok(error(
                STATUS_BAD_REQUEST,
                "publish_only_for_agents",
                "only function=agent certs may be promoted across modes",
            ));
        }
        if matches!(new_mode, Mode::PerRelationship) && contact_id.is_none() {
            return Ok(error(
                STATUS_BAD_REQUEST,
                "missing_contact_id",
                "per-relationship mode requires contact_id",
            ));
        }
        let new_path = match canonical_cert_path(new_mode, contact_id.as_ref(), &attestation_hash)
        {
            Some(p) => self.qualify(&p),
            None => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "embedded_no_path",
                    "embedded mode has no tree path; use envelope ingestion",
                ))
            }
        };

        // PI-3 (PROPOSAL-IDENTITY-COMPOSITION-CLEANUP §PI-3, Rev 3):
        // publish is a path-MOVE per spec §4.2a + Go's reference
        // (`ext/identity/ops.go::handlePublishAttestation`). Tombstone-
        // style recovery via PI-5 events stream:
        //
        //   1. bind(new_path) — do this first
        //   2. unbind(old_path) (if old_path != new_path)
        //
        // If bind(new) fails: old path remains bound; surface error; no
        //   tombstone needed (no inconsistent state).
        // If unbind(old) fails after bind(new) succeeded: retry once;
        //   on retry failure emit `event_subkind="recovery_signal"` event
        //   at `system/identity/events/{ts}/publish_attestation/...`.
        //   Recovery signals MUST NOT be pruned until cleared (Rev 3).
        //
        // Note: this impl's LocationIndex set/remove are infallible
        // (in-memory + journaled-persistence layer). The retry/emit
        // branches activate if a future fallible primitive is wired in;
        // we additionally emit a recovery_signal as a defense-in-depth
        // post-condition check (orphaned old-path binding).
        let cert_mode_str = read_mode(&cert);
        let cert_contact_id = cert
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
        let old_path: Option<String> = cert_mode_str
            .and_then(|s| Mode::parse(s).ok())
            .and_then(|m| canonical_cert_path(m, cert_contact_id.as_ref(), &attestation_hash))
            .map(|bare| self.qualify(&bare));

        // (1) bind new — entity itself is unchanged; only its tree
        // binding moves.
        self.location_index.set(&new_path, attestation_hash);

        // (2) unbind old (if different). Best-effort; retry once on
        // post-condition mismatch; emit recovery_signal on persistent
        // failure.
        if let Some(ref op) = old_path {
            if op != &new_path {
                self.location_index.remove(op);
                // Defense-in-depth: verify the unbind landed.
                if self.location_index.has(op) {
                    // Retry once.
                    self.location_index.remove(op);
                    if self.location_index.has(op) {
                        // Persistent failure: emit recovery_signal so the
                        // controller can investigate / re-issue.
                        self.emit_controller_event(
                            "recovery_signal",
                            "publish_attestation",
                            &attestation_hash,
                            cert.kind().unwrap_or(""),
                            "orphan_old_path_binding",
                            &format!(
                                "publish moved cert to {} but old binding at {} persists",
                                new_path, op
                            ),
                        );
                    }
                }
            }
        }
        Ok(publish_attestation_result(attestation_hash, &new_path))
    }
}
