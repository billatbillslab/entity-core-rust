//! `system/attestation` handler — 4 operations
//! (EXTENSION-ATTESTATION v1.0 §6).
//!
//! Operations: `create`, `supersede`, `revoke`, `verify`. All ops follow
//! path-as-resource per V7 §3.2 (per spec §10.1 cross-extension MUST).
//!
//! Storage paths are consumer-supplied. The substrate primitive does NOT
//! mandate a canonical path (§7) — callers pass the storage path via
//! `resource_target`; the handler writes there.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use entity_ecf::{text, to_ecf, Value};
use entity_entity::Entity;
use entity_handler::{
    Handler, HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST, STATUS_NOT_FOUND,
    STATUS_OK,
};
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};

use crate::data::{decode_map, field_hash, field_hash_opt, field_u64_opt, get_field, AttestationData};
use crate::helpers::{is_attestation_live, verify_attestation_signature, AttestationCtx};
use crate::index::AttestationIndex;
use crate::{AttestationError, KIND_REVOCATION};

/// Public persistence helper for consumer extensions that wrap
/// `system/attestation:create`. Encodes the attestation, persists into
/// the content store, binds at `storage_path`, and inserts into the
/// attestation index. Returns the attestation's content hash.
///
/// Per spec §6 — identity / quorum / future consumers MAY call this
/// directly (instead of dispatching through the substrate handler) when
/// they have already constructed the kind-specific properties shape.
pub fn persist_attestation(
    content_store: &Arc<dyn ContentStore>,
    location_index: &Arc<dyn LocationIndex>,
    index: &AttestationIndex,
    storage_path: &str,
    att: AttestationData,
) -> Result<Hash, AttestationError> {
    let entity = att.to_entity()?;
    let hash = entity.content_hash;
    content_store
        .put(entity)
        .map_err(|e| AttestationError::Encode(e.to_string()))?;
    location_index.set(storage_path, hash);
    index.insert(hash, att);
    Ok(hash)
}

/// `system/attestation` handler.
pub struct AttestationHandler {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    index: Arc<AttestationIndex>,
    qualified_pattern: String,
}

impl AttestationHandler {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        index: Arc<AttestationIndex>,
        local_peer_id: String,
    ) -> Self {
        let qualified_pattern = format!("/{}/system/attestation", local_peer_id);
        Self {
            content_store,
            location_index,
            index,
            qualified_pattern,
        }
    }

    pub fn index(&self) -> Arc<AttestationIndex> {
        self.index.clone()
    }

    fn ctx<'a>(&'a self, included: &'a HashMap<Hash, Entity>) -> AttestationCtx<'a> {
        AttestationCtx {
            index: &self.index,
            content_store: &self.content_store,
            location_index: &self.location_index,
            included,
        }
    }

    fn resource_path(&self, ctx: &HandlerContext) -> Option<String> {
        ctx.resource_target.as_ref().and_then(|rt| rt.targets.first().cloned())
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for AttestationHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            "create" => self.handle_create(ctx).await,
            "supersede" => self.handle_supersede(ctx).await,
            "revoke" => self.handle_revoke(ctx).await,
            "verify" => self.handle_verify(ctx).await,
            other => Ok(error(
                STATUS_BAD_REQUEST,
                "unknown_operation",
                &format!("unknown attestation op: {}", other),
            )),
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "attestation"
    }

    fn operations(&self) -> &[&str] {
        &["create", "supersede", "revoke", "verify"]
    }
}

impl AttestationHandler {
    // -------------------------------------------------------------------
    // §6.1 create
    // -------------------------------------------------------------------

    async fn handle_create(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let resource = match self.resource_path(ctx) {
            Some(r) => r,
            None => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "path_required",
                    "resource.targets[0] required (storage path for new attestation)",
                ))
            }
        };
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
        let properties = match get_field(&map, "properties") {
            None | Some(ciborium::Value::Null) => Vec::new(),
            Some(v) => match v.as_map() {
                Some(m) => m.clone(),
                None => {
                    return Ok(error(
                        STATUS_BAD_REQUEST,
                        "invalid_params",
                        "properties must be CBOR map",
                    ))
                }
            },
        };
        let supersedes = match field_hash_opt(&map, "supersedes") {
            Ok(h) => h,
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

        let att = AttestationData {
            attesting,
            attested,
            properties,
            supersedes,
            not_before,
            expires_at,
        };
        // PR-7: kind-namespacing MUST. Reject unnamespaced kinds (other than
        // the universal `revocation` substrate kind) at substrate-binding
        // time. Within-extension internal kinds bypass `system/attestation:create`
        // and aren't validated here; only kinds entering the wire-bound
        // attestation surface are checked.
        if let Some(kind) = att.kind() {
            if let Err(e) = crate::validate_kind(kind) {
                return Ok(error(STATUS_BAD_REQUEST, "invalid_kind", &e.to_string()));
            }
        }
        let entity = match att.to_entity() {
            Ok(e) => e,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "encode_failed", &e.to_string())),
        };
        self.persist(&resource, entity, &att, ctx)
    }

    // -------------------------------------------------------------------
    // §6.2 supersede
    // -------------------------------------------------------------------

    async fn handle_supersede(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let resource = match self.resource_path(ctx) {
            Some(r) => r,
            None => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "path_required",
                    "resource.targets[0] required",
                ))
            }
        };
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let previous_hash = match field_hash(&map, "previous_hash") {
            Ok(h) => h,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let previous = match self.index.get(&previous_hash) {
            Some(p) => p,
            None => {
                return Ok(error(
                    STATUS_NOT_FOUND,
                    "previous_not_found",
                    "previous_hash not in attestation index",
                ))
            }
        };
        let properties = match get_field(&map, "properties") {
            None | Some(ciborium::Value::Null) => previous.properties.clone(),
            Some(v) => match v.as_map() {
                Some(m) => m.clone(),
                None => {
                    return Ok(error(
                        STATUS_BAD_REQUEST,
                        "invalid_params",
                        "properties must be CBOR map",
                    ))
                }
            },
        };
        let not_before = match field_u64_opt(&map, "not_before") {
            Ok(v) => v.or(previous.not_before),
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let expires_at = match field_u64_opt(&map, "expires_at") {
            Ok(v) => v.or(previous.expires_at),
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };

        let att = AttestationData {
            attesting: previous.attesting,
            attested: previous.attested,
            properties,
            supersedes: Some(previous_hash),
            not_before,
            expires_at,
        };
        let entity = match att.to_entity() {
            Ok(e) => e,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "encode_failed", &e.to_string())),
        };
        self.persist(&resource, entity, &att, ctx)
    }

    // -------------------------------------------------------------------
    // §6.3 revoke (convenience wrapper)
    // -------------------------------------------------------------------

    async fn handle_revoke(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let resource = match self.resource_path(ctx) {
            Some(r) => r,
            None => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "path_required",
                    "resource.targets[0] required",
                ))
            }
        };
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let target_hash = match field_hash(&map, "target_hash") {
            Ok(h) => h,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let attesting = match field_hash(&map, "attesting") {
            Ok(h) => h,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let mut properties: Vec<(ciborium::Value, ciborium::Value)> = Vec::new();
        properties.push((text("kind"), text(KIND_REVOCATION)));
        if let Some(reason) = get_field(&map, "reason").and_then(|v| v.as_text()) {
            properties.push((text("reason"), text(reason)));
        }
        let att = AttestationData {
            attesting,
            attested: target_hash,
            properties,
            supersedes: None,
            not_before: None,
            expires_at: None,
        };
        let entity = match att.to_entity() {
            Ok(e) => e,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "encode_failed", &e.to_string())),
        };
        self.persist(&resource, entity, &att, ctx)
    }

    // -------------------------------------------------------------------
    // §6.4 verify (orchestration helper)
    // -------------------------------------------------------------------

    async fn handle_verify(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let attestation_hash = match field_hash(&map, "attestation_hash") {
            Ok(h) => h,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let as_of = match field_u64_opt(&map, "as_of") {
            Ok(v) => v,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let att = match self.index.get(&attestation_hash) {
            Some(a) => a,
            None => {
                return Ok(verify_result(false, Some("attestation_not_indexed")));
            }
        };
        let actx = self.ctx(&ctx.included);
        if !verify_attestation_signature(&attestation_hash, &att, &actx) {
            return Ok(verify_result(false, Some("invalid_signature")));
        }
        if !is_attestation_live(&attestation_hash, &att, &actx, as_of) {
            return Ok(verify_result(false, Some("not_live")));
        }
        Ok(verify_result(true, None))
    }

    // -------------------------------------------------------------------
    // Persistence + index maintenance
    // -------------------------------------------------------------------

    fn persist(
        &self,
        resource: &str,
        _entity: Entity,
        att: &AttestationData,
        _ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        match persist_attestation(
            &self.content_store,
            &self.location_index,
            &self.index,
            resource,
            att.clone(),
        ) {
            Ok(hash) => Ok(create_result(hash)),
            Err(e) => Ok(error(STATUS_BAD_REQUEST, "store_failed", &e.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// Result + error helpers
// ---------------------------------------------------------------------------

fn make_error_entity(code: &str, message: &str) -> Entity {
    let data = to_ecf(&Value::Map(vec![
        (text("code"), text(code)),
        (text("message"), text(message)),
    ]));
    Entity::new(entity_types::TYPE_ERROR, data).unwrap()
}

fn error(status: u32, code: &str, message: &str) -> HandlerResult {
    HandlerResult::error(status, make_error_entity(code, message))
}

fn create_result(attestation_hash: Hash) -> HandlerResult {
    let result = Entity::new(
        entity_types::TYPE_PROTOCOL_STATUS,
        to_ecf(&Value::Map(vec![(
            text("attestation_hash"),
            Value::Bytes(attestation_hash.to_bytes().to_vec()),
        )])),
    )
    .unwrap();
    HandlerResult {
        status: STATUS_OK,
        result,
        included: HashMap::new(),
    }
}

fn verify_result(valid: bool, reason: Option<&str>) -> HandlerResult {
    let mut fields: Vec<(Value, Value)> = vec![(text("valid"), Value::Bool(valid))];
    if let Some(r) = reason {
        fields.push((text("reason"), text(r)));
    }
    let result = Entity::new(entity_types::TYPE_PROTOCOL_STATUS, to_ecf(&Value::Map(fields)))
        .unwrap();
    HandlerResult {
        status: STATUS_OK,
        result,
        included: HashMap::new(),
    }
}

