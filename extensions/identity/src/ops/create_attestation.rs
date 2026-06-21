//! `system/identity:create_attestation` — creates an attestation entity at
//! the canonical path computed from its `properties.mode` / `kind`. Per
//! EXTENSION-IDENTITY §6 + EXTENSION-ATTESTATION §6.1.

use entity_attestation::{persist_attestation, AttestationData};
use entity_ecf::{text, to_ecf, Value};
use entity_entity::Entity;
use entity_handler::{
    HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST,
};
use crate::data::{
    decode_map, field_hash, field_hash_opt, field_map, field_string, field_string_opt, field_u64_opt,
};
use crate::handler::{
    create_attestation_result, create_attestation_result_embedded, error, IdentityHandler,
};
use crate::kinds::{
    is_valid_mode_for_function, valid_modes_for_function, Function, Mode, KIND_IDENTITY_CERT,
    KIND_IDENTITY_RETIREMENT, KIND_IDENTITY_ROTATION_HANDOFF, KIND_IDENTITY_ROTATION_RECOVERY,
};

impl IdentityHandler {
    pub(crate) async fn handle_create_attestation(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        // Per EXTENSION-ATTESTATION §6.1 + EXTENSION-IDENTITY §6 (R-1):
        // request shape is `{attesting, attested, properties: map,
        // supersedes?, not_before?, expires_at?}`. `kind` / `function` /
        // `mode` / `contact_id` / `target_cert` / `old_handle` are NESTED
        // inside `properties`, not flat top-level fields. Pre-R-1 Rust
        // flattened them; that broke wire parity with Go and Python.
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let attesting = match field_hash(&map, "attesting") {
            Ok(h) => h,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let attested = match field_hash(&map, "attested") {
            Ok(h) => h,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let properties_map = match field_map(&map, "properties") {
            Ok(m) => m,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let kind = match field_string(&properties_map, "kind") {
            Ok(k) => k,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let function_str = match field_string_opt(&properties_map, "function") {
            Ok(v) => v,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let mode_str = match field_string_opt(&properties_map, "mode") {
            Ok(v) => v,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let contact_id = match field_hash_opt(&properties_map, "contact_id") {
            Ok(v) => v,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let target_cert = match field_hash_opt(&properties_map, "target_cert") {
            Ok(v) => v,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let old_handle = match field_hash_opt(&properties_map, "old_handle") {
            Ok(v) => v,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let supersedes = match field_hash_opt(&map, "supersedes") {
            Ok(v) => v,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let not_before = match field_u64_opt(&map, "not_before") {
            Ok(v) => v,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let expires_at = match field_u64_opt(&map, "expires_at") {
            Ok(v) => v,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };

        // Per-kind structural validation (§4).
        if kind == KIND_IDENTITY_CERT {
            // function REQUIRED.
            let f = function_str.as_deref().ok_or(()).map_err(|_| ()).ok();
            if f.is_none() {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "missing_function",
                    "identity-cert requires properties.function",
                ));
            }
            // mode REQUIRED on all identity-certs (§4.2).
            if mode_str.is_none() {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "missing_mode",
                    "identity-cert requires properties.mode",
                ));
            }
            // PI-11 (PROPOSAL-IDENTITY-COMPOSITION-CLEANUP §PI-11):
            // per-function valid-modes enforcement at create time.
            // Reject (function, mode) combinations the §4.2 table doesn't
            // permit (e.g., `function=identifier, mode=public`;
            // `function=controller, mode=per-relationship`). Returns
            // `400 invalid_mode_for_function` with structured detail.
            let function_enum = function_str.as_deref().and_then(Function::parse_optional);
            let mode_enum = match Mode::parse(mode_str.as_deref().unwrap_or("internal")) {
                Ok(m) => m,
                Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_mode", &e.to_string())),
            };
            // Sub-controller detection: controller cert whose attesting !=
            // attested AND attesting resolves to another attestation in
            // the index (i.e., chains under another controller cert).
            let sub_controller = matches!(function_enum, Some(Function::Controller))
                && attesting != attested
                && self.attestation_index.get(&attesting).is_some();
            if !is_valid_mode_for_function(function_enum, mode_enum, sub_controller) {
                let valid = valid_modes_for_function(function_enum, sub_controller);
                let valid_array = Value::Array(valid.iter().map(|s| text(*s)).collect());
                let attempted = mode_str.as_deref().unwrap_or("internal");
                let function_label = function_str.as_deref().unwrap_or("");
                let detail = to_ecf(&Value::Map(vec![
                    (text("attempted_mode"), text(attempted)),
                    (text("code"), text("invalid_mode_for_function")),
                    (text("function"), text(function_label)),
                    (
                        text("message"),
                        text(&format!(
                            "mode `{}` not valid for function `{}`",
                            attempted, function_label
                        )),
                    ),
                    (text("valid_modes_for_function"), valid_array),
                ]));
                let entity = Entity::new(entity_types::TYPE_ERROR, detail).unwrap();
                return Ok(HandlerResult::error(STATUS_BAD_REQUEST, entity));
            }
        } else if [
            KIND_IDENTITY_ROTATION_HANDOFF,
            KIND_IDENTITY_ROTATION_RECOVERY,
            KIND_IDENTITY_RETIREMENT,
        ]
        .contains(&kind.as_str())
        {
            // target_cert REQUIRED.
            if target_cert.is_none() {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "missing_target_cert",
                    &format!("{} requires properties.target_cert", kind),
                ));
            }
        }

        // Build properties map (ECF-sorted by key at end).
        let mut props: Vec<(ciborium::Value, ciborium::Value)> = Vec::new();
        props.push((text("kind"), text(kind.as_str())));
        if let Some(f) = function_str.as_deref() {
            props.push((text("function"), text(f)));
        }
        if let Some(m) = mode_str.as_deref() {
            props.push((text("mode"), text(m)));
        }
        if let Some(c) = &contact_id {
            props.push((text("contact_id"), Value::Bytes(c.to_bytes().to_vec())));
        }
        if let Some(t) = &target_cert {
            props.push((text("target_cert"), Value::Bytes(t.to_bytes().to_vec())));
        }
        if let Some(o) = &old_handle {
            props.push((text("old_handle"), Value::Bytes(o.to_bytes().to_vec())));
        }
        props.sort_by(|a, b| a.0.as_text().unwrap_or("").cmp(b.0.as_text().unwrap_or("")));

        let att = AttestationData {
            attesting,
            attested,
            properties: props,
            supersedes,
            not_before,
            expires_at,
        };

        // Resolve storage path.
        let provided_path = self.resource_path(ctx);
        let computed_path = self.compute_storage_path(&att, &kind, mode_str.as_deref(), contact_id.as_ref())?;

        let path = match (provided_path.as_deref(), computed_path.as_deref()) {
            (Some(p), Some(c)) if p == c => p.to_string(),
            (Some(p), Some(c)) => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "resource_target_mismatch",
                    &format!("expected {}, got {}", c, p),
                ));
            }
            (Some(p), None) => {
                // Embedded mode — caller supplied a path but we wouldn't
                // canonicalize one; reject for clarity.
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "embedded_no_path",
                    &format!("embedded mode does not store at tree path; got {}", p),
                ));
            }
            (None, Some(c)) => c.to_string(),
            (None, None) => {
                // Embedded mode (no canonical tree path; no resource target).
                // R-6 (cross-impl spec): return the
                // canonical AttestationData inline under `embedded_attestation`
                // so the caller can embed it in a cap envelope without
                // re-encoding. The entity is still put in the local
                // content store + index for in-process lookup, but no tree
                // binding is created and no `attestation_hash` field is
                // emitted (presence of the hash field signals "bound in
                // tree" per Go's reference shape).
                let entity = att.to_entity().map_err(|e| HandlerError::Internal(e.to_string()))?;
                let hash = entity.content_hash;
                let entity_data = entity.data.clone();
                if let Err(e) = self.content_store.put(entity) {
                    return Ok(error(STATUS_BAD_REQUEST, "store_failed", &e.to_string()));
                }
                self.attestation_index.insert(hash, att);
                return Ok(create_attestation_result_embedded(&entity_data));
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
        Ok(create_attestation_result(hash, Some(&path)))
    }
}
