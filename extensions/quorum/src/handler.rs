//! `system/quorum` handler — 4 operations
//! (EXTENSION-QUORUM v1.0 §6).
//!
//! `create` / `update` / `publish` / `verify`. All ops follow
//! path-as-resource per V7 §3.2.
//!
//! `update` and `publish` delegate to EXTENSION-ATTESTATION:create with
//! the appropriate properties shape (`kind="quorum-update"` /
//! `kind="quorum-publish"`).

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use entity_attestation::{AttestationData, AttestationIndex};
use entity_ecf::{text, to_ecf, Value};
use entity_entity::Entity;
use entity_handler::{
    error_entity, Handler, HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST,
    STATUS_OK,
};
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};
use entity_types::TYPE_QUORUM;

use crate::cache::SignerSetCache;
use crate::data::{
    decode_map, field_hash, field_hash_array, field_hash_opt, field_map_opt, field_string_opt,
    field_u64, get_field, QuorumData,
};
use crate::helpers::{current_signer_set, verify_k_of_n_signatures, QuorumCtx};
use crate::resolver::ResolverRegistry;
use crate::{KIND_QUORUM_PUBLISH, KIND_QUORUM_UPDATE};

pub struct QuorumHandler {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    attestation_index: Arc<AttestationIndex>,
    resolver_registry: ResolverRegistry,
    signer_set_cache: Arc<SignerSetCache>,
    qualified_pattern: String,
    local_peer_id: String,
}

impl QuorumHandler {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        attestation_index: Arc<AttestationIndex>,
        resolver_registry: ResolverRegistry,
        signer_set_cache: Arc<SignerSetCache>,
        local_peer_id: String,
    ) -> Self {
        let qualified_pattern = format!("/{}/system/quorum", local_peer_id);
        Self {
            content_store,
            location_index,
            attestation_index,
            resolver_registry,
            signer_set_cache,
            qualified_pattern,
            local_peer_id,
        }
    }

    pub fn resolver_registry(&self) -> ResolverRegistry {
        self.resolver_registry.clone()
    }

    pub fn signer_set_cache(&self) -> Arc<SignerSetCache> {
        self.signer_set_cache.clone()
    }

    fn ctx<'a>(&'a self, included: &'a HashMap<Hash, Entity>) -> QuorumCtx<'a> {
        QuorumCtx {
            attestation_index: &self.attestation_index,
            content_store: &self.content_store,
            location_index: &self.location_index,
            included,
            resolver_registry: &self.resolver_registry,
            signer_set_cache: &self.signer_set_cache,
        }
    }

    #[allow(dead_code)]
    fn qualify(&self, bare: &str) -> String {
        format!("/{}/{}", self.local_peer_id, bare)
    }

    fn resource_path(&self, ctx: &HandlerContext) -> Option<String> {
        ctx.resource_target.as_ref().and_then(|rt| rt.targets.first().cloned())
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for QuorumHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            "create" => self.handle_create(ctx).await,
            "update" => self.handle_update(ctx).await,
            "publish" => self.handle_publish(ctx).await,
            "verify" => self.handle_verify(ctx).await,
            other => Ok(error(
                STATUS_BAD_REQUEST,
                "unknown_operation",
                &format!("unknown quorum op: {}", other),
            )),
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "quorum"
    }

    fn operations(&self) -> &[&str] {
        &["create", "update", "publish", "verify"]
    }
}

impl QuorumHandler {
    // -------------------------------------------------------------------
    // §6.1 create
    // -------------------------------------------------------------------

    async fn handle_create(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let signers = match field_hash_array(&map, "signers") {
            Ok(v) => v,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let threshold = match field_u64(&map, "threshold") {
            Ok(v) => v,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        if threshold == 0 || threshold > signers.len() as u64 {
            return Ok(error(
                STATUS_BAD_REQUEST,
                "invalid_threshold",
                "threshold must satisfy 1 ≤ K ≤ |signers|",
            ));
        }
        let signer_resolution = match field_string_opt(&map, "signer_resolution") {
            Ok(v) => v,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let name = match field_string_opt(&map, "name") {
            Ok(v) => v,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        // R-4 (cross-impl ACME ruling): `metadata` is part of
        // §3.1 QuorumData. Dropping it caused recomputed canonical paths
        // to diverge from caller-supplied paths (resource_target_mismatch
        // under R-3 strict). Preserve the raw CBOR map for byte fidelity.
        let metadata = match field_map_opt(&map, "metadata") {
            Ok(v) => v,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let q = QuorumData {
            signers,
            threshold,
            signer_resolution,
            name,
            metadata,
        };
        let entity = match q.to_entity() {
            Ok(e) => e,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "encode_failed", &e.to_string())),
        };
        let q_hash = entity.content_hash;
        // Path-as-resource MUST per V7 §3.2 (architectural-side; spec
        // EXTENSION-QUORUM v1.1 §6 / SI-7/SI-22).
        let path = match self.resource_path(ctx) {
            Some(p) => p,
            None => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "path_required",
                    "system/quorum:create requires resource.targets[0]",
                ))
            }
        };
        if let Err(e) = self.content_store.put(entity) {
            return Ok(error(STATUS_BAD_REQUEST, "store_failed", &e.to_string()));
        }
        self.location_index.set(&path, q_hash);
        Ok(create_result("quorum_id", q_hash))
    }

    // -------------------------------------------------------------------
    // §6.2 update
    // -------------------------------------------------------------------

    async fn handle_update(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let quorum_id = match field_hash(&map, "quorum_id") {
            Ok(h) => h,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let new_signers = match field_hash_array(&map, "new_signers") {
            Ok(v) => v,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let new_threshold = match field_u64(&map, "new_threshold") {
            Ok(v) => v,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        if new_threshold == 0 || new_threshold > new_signers.len() as u64 {
            return Ok(error(
                STATUS_BAD_REQUEST,
                "invalid_threshold",
                "new_threshold must satisfy 1 ≤ K ≤ |new_signers|",
            ));
        }
        let supersedes = match field_hash_opt(&map, "supersedes") {
            Ok(v) => v,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let mut props: Vec<(ciborium::Value, ciborium::Value)> = vec![
            (text("kind"), text(KIND_QUORUM_UPDATE)),
            (
                text("new_signers"),
                Value::Array(
                    new_signers
                        .iter()
                        .map(|h| Value::Bytes(h.to_bytes().to_vec()))
                        .collect(),
                ),
            ),
            (
                text("new_threshold"),
                entity_ecf::integer(new_threshold as i64),
            ),
        ];
        // ECF sort: kind, new_signers, new_threshold (already sorted).
        props.sort_by(|a, b| {
            a.0.as_text()
                .unwrap_or("")
                .cmp(b.0.as_text().unwrap_or(""))
        });
        let att = AttestationData {
            attesting: quorum_id,
            attested: quorum_id,
            properties: props,
            supersedes,
            not_before: None,
            expires_at: None,
        };
        let att_entity = match att.to_entity() {
            Ok(e) => e,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "encode_failed", &e.to_string())),
        };
        let att_hash = att_entity.content_hash;
        // Path-as-resource MUST per spec §6 / SI-7.
        let path = match self.resource_path(ctx) {
            Some(p) => p,
            None => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "path_required",
                    "system/quorum:update requires resource.targets[0]",
                ))
            }
        };
        if let Err(e) = self.content_store.put(att_entity) {
            return Ok(error(STATUS_BAD_REQUEST, "store_failed", &e.to_string()));
        }
        self.location_index.set(&path, att_hash);
        // Index the attestation with the substrate primitive's index.
        self.attestation_index.insert(att_hash, att);
        // Cache invalidation per §4.2.1 trigger 1.
        self.signer_set_cache.invalidate(&quorum_id);
        Ok(create_result("update_hash", att_hash))
    }

    // -------------------------------------------------------------------
    // §6.3 publish
    // -------------------------------------------------------------------

    async fn handle_publish(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let quorum_id = match field_hash(&map, "quorum_id") {
            Ok(h) => h,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let signers = match field_hash_array(&map, "signers") {
            Ok(v) => v,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let threshold = match field_u64(&map, "threshold") {
            Ok(v) => v,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let published_handle = match field_hash_opt(&map, "published_handle") {
            Ok(v) => v,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let supersedes = match field_hash_opt(&map, "supersedes") {
            Ok(v) => v,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        // Merge consumer-supplied `properties` map (per §6.3) into the
        // attestation's properties, alongside the standard quorum-publish
        // fields.
        let mut props: Vec<(ciborium::Value, ciborium::Value)> = vec![
            (text("kind"), text(KIND_QUORUM_PUBLISH)),
            (
                text("signers"),
                Value::Array(
                    signers
                        .iter()
                        .map(|h| Value::Bytes(h.to_bytes().to_vec()))
                        .collect(),
                ),
            ),
            (text("threshold"), entity_ecf::integer(threshold as i64)),
        ];
        if let Some(h) = &published_handle {
            props.push((
                text("published_handle"),
                Value::Bytes(h.to_bytes().to_vec()),
            ));
        }
        if let Some(extra) = get_field(&map, "properties").and_then(|v| v.as_map()) {
            for (k, v) in extra {
                if let Some(ks) = k.as_text() {
                    if !matches!(ks, "kind" | "signers" | "threshold" | "published_handle") {
                        props.push((text(ks), v.clone()));
                    }
                }
            }
        }
        // ECF-sort by key.
        props.sort_by(|a, b| {
            a.0.as_text()
                .unwrap_or("")
                .cmp(b.0.as_text().unwrap_or(""))
        });
        let att = AttestationData {
            attesting: quorum_id,
            attested: quorum_id,
            properties: props,
            supersedes,
            not_before: None,
            expires_at: None,
        };
        let att_entity = match att.to_entity() {
            Ok(e) => e,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "encode_failed", &e.to_string())),
        };
        let att_hash = att_entity.content_hash;
        let path = match self.resource_path(ctx) {
            Some(p) => p,
            None => {
                return Ok(error(
                    STATUS_BAD_REQUEST,
                    "path_required",
                    "system/quorum:publish requires resource.targets[0]",
                ))
            }
        };
        if let Err(e) = self.content_store.put(att_entity) {
            return Ok(error(STATUS_BAD_REQUEST, "store_failed", &e.to_string()));
        }
        self.location_index.set(&path, att_hash);
        self.attestation_index.insert(att_hash, att);
        self.signer_set_cache.invalidate(&quorum_id);
        Ok(create_result("publish_hash", att_hash))
    }

    // -------------------------------------------------------------------
    // §6.4 verify
    // -------------------------------------------------------------------

    async fn handle_verify(
        &self,
        ctx: &HandlerContext,
    ) -> Result<HandlerResult, HandlerError> {
        let map = match decode_map(&ctx.params.data) {
            Ok(m) => m,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let entity_hash = match field_hash(&map, "entity_hash") {
            Ok(h) => h,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let quorum_id = match field_hash(&map, "quorum_id") {
            Ok(h) => h,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "invalid_params", &e.to_string())),
        };
        let qctx = self.ctx(&ctx.included);
        let set = match current_signer_set(&quorum_id, &qctx) {
            Ok(s) => s,
            Err(e) => return Ok(error(STATUS_BAD_REQUEST, "signer_set_failed", &e.to_string())),
        };
        let valid =
            verify_k_of_n_signatures(&entity_hash, &set.signers, set.threshold, &qctx);
        Ok(verify_result(valid))
    }
}

// ---------------------------------------------------------------------------
// Result helpers
// ---------------------------------------------------------------------------

fn error(status: u32, code: &str, message: &str) -> HandlerResult {
    HandlerResult::error(status, error_entity(code, message))
}

fn create_result(field: &str, hash: Hash) -> HandlerResult {
    let result = Entity::new(
        entity_types::TYPE_PROTOCOL_STATUS,
        to_ecf(&Value::Map(vec![(
            text(field),
            Value::Bytes(hash.to_bytes().to_vec()),
        )])),
    )
    .unwrap();
    HandlerResult {
        status: STATUS_OK,
        result,
        included: HashMap::new(),
    }
}

fn verify_result(valid: bool) -> HandlerResult {
    let result = Entity::new(
        entity_types::TYPE_PROTOCOL_STATUS,
        to_ecf(&Value::Map(vec![(text("valid"), Value::Bool(valid))])),
    )
    .unwrap();
    HandlerResult {
        status: STATUS_OK,
        result,
        included: HashMap::new(),
    }
}

// Silence type warnings for unused TYPE_QUORUM import (referenced in docs).
#[allow(dead_code)]
const _: &str = TYPE_QUORUM;
