//! `system/identity` handler — 7 operations
//! (EXTENSION-IDENTITY v3.2 §6).
//!
//! `configure`, `create_quorum`, `create_attestation`,
//! `supersede_attestation`, `revoke_attestation`, `publish_attestation`,
//! `process_attestation`. All ops follow path-as-resource per V7 §3.2.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use entity_attestation::{
    AttestationData, AttestationIndex,
};
use entity_capability::{CapabilityToken, GrantEntry, Granter};
use entity_crypto::IdentityKeypair;
use entity_ecf::{text, to_ecf, Value};
use entity_entity::{Entity, TYPE_SIGNATURE};
use entity_handler::{
    error_entity, Handler, HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST, STATUS_OK,
};
use entity_hash::Hash;
use entity_quorum::{ResolverRegistry, SignerSetCache};
use entity_store::{ContentStore, LocationIndex};

use crate::kinds::{
    is_valid_mode_for_function, Function, Mode, KIND_IDENTITY_CERT,
    KIND_IDENTITY_RETIREMENT, KIND_IDENTITY_ROTATION_HANDOFF,
    KIND_IDENTITY_ROTATION_RECOVERY,
};
use crate::paths::{
    canonical_cert_path, path_identity_event,
};
use crate::validation::{
    lookup_target_cert, read_function, read_mode,
    IdentityCtx,
};

pub struct IdentityHandler {
    pub(crate) content_store: Arc<dyn ContentStore>,
    pub(crate) location_index: Arc<dyn LocationIndex>,
    pub(crate) attestation_index: Arc<AttestationIndex>,
    pub(crate) resolver_registry: ResolverRegistry,
    pub(crate) signer_set_cache: Arc<SignerSetCache>,
    pub(crate) local_peer_id: String,
    pub(crate) qualified_pattern: String,
    /// Local peer's identity entity hash. Used as granter for the
    /// peer→controller cap.
    pub(crate) identity_hash: Hash,
    /// Local keypair for signing peer→controller caps (and identity-cert
    /// agent entries this peer issues to itself in single-agent flows).
    /// Polymorphic over key_type (v7.67 Phase 2).
    pub(crate) keypair: IdentityKeypair,
}

impl IdentityHandler {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        attestation_index: Arc<AttestationIndex>,
        resolver_registry: ResolverRegistry,
        signer_set_cache: Arc<SignerSetCache>,
        local_peer_id: String,
        identity_hash: Hash,
        keypair: IdentityKeypair,
    ) -> Self {
        let qualified_pattern = format!("/{}/system/identity", local_peer_id);
        Self {
            content_store,
            location_index,
            attestation_index,
            resolver_registry,
            signer_set_cache,
            local_peer_id,
            qualified_pattern,
            identity_hash,
            keypair,
        }
    }

    pub(crate) fn ctx<'a>(&'a self, included: &'a HashMap<Hash, Entity>) -> IdentityCtx<'a> {
        IdentityCtx {
            attestation_index: &self.attestation_index,
            content_store: &self.content_store,
            location_index: &self.location_index,
            included,
            resolver_registry: &self.resolver_registry,
            signer_set_cache: &self.signer_set_cache,
        }
    }

    pub(crate) fn qualify(&self, bare: &str) -> String {
        format!("/{}/{}", self.local_peer_id, bare)
    }

    pub(crate) fn resource_path(&self, ctx: &HandlerContext) -> Option<String> {
        ctx.resource_target.as_ref().and_then(|rt| rt.targets.first().cloned())
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for IdentityHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        // V7 v7.37 §6.5: signature ingestion runs at the dispatcher's
        // envelope-unwrap step (in core/peer::ingest), not here. By the
        // time the handler body runs, signatures from envelope.included
        // are already persisted + bound at canonical V7 paths.
        // Substrate find_signature_by_signer reads them via tree lookup.
        match ctx.operation.as_str() {
            "configure" => self.handle_configure(ctx).await,
            "create_quorum" => self.handle_create_quorum(ctx).await,
            "create_attestation" => self.handle_create_attestation(ctx).await,
            "supersede_attestation" => self.handle_supersede_attestation(ctx).await,
            "revoke_attestation" => self.handle_revoke_attestation(ctx).await,
            "publish_attestation" => self.handle_publish_attestation(ctx).await,
            "process_attestation" => self.handle_process_attestation(ctx).await,
            other => Ok(error(
                STATUS_BAD_REQUEST,
                "unknown_operation",
                &format!("unknown identity op: {}", other),
            )),
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "identity"
    }

    fn operations(&self) -> &[&str] {
        &[
            "configure",
            "create_quorum",
            "create_attestation",
            "supersede_attestation",
            "revoke_attestation",
            "publish_attestation",
            "process_attestation",
        ]
    }
}

// §6 — configure — moved to ops/configure.rs


// §6 — create_quorum — moved to ops/create_quorum.rs

// ===========================================================================
// §6 — create_attestation
// ===========================================================================

impl IdentityHandler {
    /// Compute canonical storage path per §5.3 from the attestation's own
    /// properties. Returns `None` for `mode="embedded"`.
    pub(crate) fn compute_storage_path(
        &self,
        att: &AttestationData,
        kind: &str,
        mode_str: Option<&str>,
        contact_id: Option<&Hash>,
    ) -> Result<Option<String>, HandlerError> {
        // Provisional: hash needed for path. Compute by encoding once.
        let entity = att
            .to_entity()
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        let att_hash = entity.content_hash;

        match kind {
            KIND_IDENTITY_CERT => {
                let mode = Mode::parse(mode_str.unwrap_or("internal"))
                    .map_err(|e| HandlerError::Internal(e.to_string()))?;
                // function-mode constraints.
                let function = read_function(att).and_then(Function::parse_optional);
                let sub_controller = matches!(function, Some(Function::Controller))
                    && att.attesting != att.attested
                    && self.attestation_index.get(&att.attesting).is_some();
                if !is_valid_mode_for_function(function, mode, sub_controller) {
                    return Err(HandlerError::Internal(format!(
                        "mode {} not valid for function {:?}",
                        mode.as_str(),
                        function
                    )));
                }
                Ok(canonical_cert_path(mode, contact_id, &att_hash)
                    .map(|bare| self.qualify(&bare)))
            }
            KIND_IDENTITY_ROTATION_HANDOFF
            | KIND_IDENTITY_ROTATION_RECOVERY
            | KIND_IDENTITY_RETIREMENT => {
                // Same audience tier as target cert.
                let target_hash = att
                    .properties
                    .iter()
                    .find_map(|(k, v)| if k.as_text() == Some("target_cert") { v.as_bytes() } else { None })
                    .and_then(|b| Hash::from_bytes(b).ok())
                    .ok_or_else(|| HandlerError::Internal("missing target_cert".into()))?;
                let target = self
                    .attestation_index
                    .get(&target_hash)
                    .ok_or_else(|| HandlerError::Internal("target_cert not indexed".into()))?;
                let target_mode = read_mode(&target)
                    .ok_or_else(|| HandlerError::Internal("target cert missing mode".into()))?;
                let target_mode_enum = Mode::parse(target_mode)
                    .map_err(|e| HandlerError::Internal(e.to_string()))?;
                let target_contact_id = target
                    .properties
                    .iter()
                    .find_map(|(k, v)| if k.as_text() == Some("contact_id") { v.as_bytes() } else { None })
                    .and_then(|b| Hash::from_bytes(b).ok());
                Ok(crate::paths::same_tier_path(
                    target_mode_enum,
                    target_contact_id.as_ref(),
                    &att_hash,
                )
                .map(|bare| self.qualify(&bare)))
            }
            _ => Ok(None),
        }
    }
}

// §6 — supersede_attestation — moved to ops/supersede_attestation.rs

// §6 — revoke_attestation — moved to ops/revoke_attestation.rs

// §6 — publish_attestation — moved to ops/publish_attestation.rs

// §6 — process_attestation — moved to ops/process_attestation.rs

// PI-13 cap-revocation helper (used by revoke_attestation + retirement processing).
impl IdentityHandler {

    /// PI-13 (PROPOSAL-IDENTITY-COMPOSITION-CLEANUP §PI-13, Rev 3):
    /// cascade-by-default cap cleanup on controller revocation. Walks
    /// `system/capability/grants/identity/peer-to-controller/*` and
    /// unbinds any cap whose `grantee` matches the revoked controller's
    /// `attested`. The granter's self-signature at the V7 invariant
    /// pointer path `/{local_peer_id}/system/signature/{cap_hash_hex}`
    /// (EXTENSION-IDENTITY v3.6, I-7) is unbound alongside.
    ///
    /// Convergence framing: this is the local-peer ideal-state cleanup.
    /// Other peers cascade when the revocation arrives via sync. Cap
    /// chains issued by stale peers in the convergence window remain
    /// validatable until propagation; consistent with V7's "caps are
    /// revoked at the cap layer" model.
    pub(crate) fn revoke_peer_to_controller_cap(&self, controller_attested: &Hash) {
        let prefix = self.qualify("system/capability/grants/identity/peer-to-controller/");
        let entries = self.location_index.list(&prefix);
        for entry in entries {
            // Read cap entity; check grantee.
            let cap_entity = match self.content_store.get(&entry.hash) {
                Some(e) => e,
                None => continue,
            };
            // Decode the cap token; if grantee matches the revoked
            // controller's attested identity, unbind cap + signature.
            let token = match entity_capability::CapabilityToken::from_entity(&cap_entity) {
                Ok(t) => t,
                Err(_) => continue,
            };
            if token.grantee != *controller_attested {
                continue;
            }
            self.location_index.remove(&entry.path);
            // Unbind the cap signature at the V7 invariant pointer path.
            let sig_path = format!(
                "/{}/system/signature/{}",
                self.local_peer_id,
                entity_attestation::hex_segment(&entry.hash)
            );
            self.location_index.remove(&sig_path);
        }
    }
}


// ===========================================================================
// PI-5 — Controller-events stream
// ===========================================================================

impl IdentityHandler {
    /// PI-5 (PROPOSAL-IDENTITY-COMPOSITION-CLEANUP §PI-5, Rev 3): emit a
    /// controller-event entity at
    /// `system/identity/events/{ts_ms}/{handler_id}/{att_hash}/{event_hash}`.
    /// `event_subkind` discriminates retention: `"recovery_signal"` events
    /// MUST NOT be pruned until cleared; `"failure_observation"` events
    /// have impl-defined retention.
    ///
    /// Best-effort: emission failures (encode/store/bind) are logged and
    /// silently ignored — the event stream is observability/recovery, not
    /// load-bearing for the dispatching op's success.
    pub(crate) fn emit_controller_event(
        &self,
        event_subkind: &str,
        handler_id: &str,
        attestation_hash: &Hash,
        attestation_kind: &str,
        error_code: &str,
        error_detail: &str,
    ) {
        let timestamp_ms = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let data = to_ecf(&Value::Map(vec![
            (text("attestation_hash"), Value::Bytes(attestation_hash.to_bytes().to_vec())),
            (text("attestation_kind"), text(attestation_kind)),
            (text("error_code"), text(error_code)),
            (text("error_detail"), text(error_detail)),
            (text("event_subkind"), text(event_subkind)),
            (text("handler_id"), text(handler_id)),
            (text("timestamp_ms"), entity_ecf::integer(timestamp_ms as i64)),
        ]));
        let entity = match Entity::new(entity_types::TYPE_IDENTITY_EVENT, data) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("emit_controller_event: encode failed: {}", e);
                return;
            }
        };
        let event_hash = entity.content_hash;
        if let Err(e) = self.content_store.put(entity) {
            tracing::warn!("emit_controller_event: store failed: {}", e);
            return;
        }
        let path = self.qualify(&path_identity_event(
            timestamp_ms,
            handler_id,
            attestation_hash,
            &event_hash,
        ));
        self.location_index.set(&path, event_hash);
    }
}

// ===========================================================================
// Cap issuance helper
// ===========================================================================

impl IdentityHandler {
    pub(crate) fn issue_peer_to_controller_cap(
        &self,
        controller_peer: &Hash,
        grants: &[GrantEntry],
    ) -> Result<Hash, String> {
        let now_ms = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let cap_token = CapabilityToken {
            grants: grants.to_vec(),
            granter: Granter::Single(self.identity_hash),
            grantee: *controller_peer,
            parent: None,
            created_at: now_ms,
            expires_at: None,
            not_before: None,
            delegation_caveats: None,
        };
        let cap_entity = cap_token.to_entity().map_err(|e| e.to_string())?;
        let cap_hash = self
            .content_store
            .put(cap_entity.clone())
            .map_err(|e| e.to_string())?;
        let sig_bytes = self.keypair.sign(&cap_entity.content_hash.to_bytes());
        let sig_data = to_ecf(&Value::Map(vec![
            (text("algorithm"), text(self.keypair.key_type().label())),
            (text("signature"), Value::Bytes(sig_bytes)),
            (text("signer"), Value::Bytes(self.identity_hash.to_bytes().to_vec())),
            (text("target"), Value::Bytes(cap_entity.content_hash.to_bytes().to_vec())),
        ]));
        let sig_entity = Entity::new(TYPE_SIGNATURE, sig_data).map_err(|e| e.to_string())?;
        let sig_hash = self
            .content_store
            .put(sig_entity)
            .map_err(|e| e.to_string())?;
        // R-13 (cross-impl spec, Round 7): bind at the
        // controller-keyed canonical path per Go's
        // `ext/identity/paths.go::localPeerToControllerCapPath`. Pre-R-13
        // Rust used `system/capability/grants/controller/{hex}` — a
        // divergent prefix that broke the Acme test driver's lookup
        // and the multi-controller addressability story (§11.6 deps on
        // per-controller cap-keyed-by-controller-hash for assign-under-cap
        // chains). One cap per live controller, keyed by the controller's
        // identity content_hash (= cert.attested).
        let cap_path = self.qualify(&format!(
            "system/capability/grants/identity/peer-to-controller/{}",
            entity_attestation::hex_segment(controller_peer)
        ));
        self.location_index.set(&cap_path, cap_hash);
        // EXTENSION-IDENTITY v3.6 (I-7) / v3.7 Phase 4 pseudocode
        // companion: bind the granter's self-signature at the V7
        // invariant pointer path `/{granter_peer_id}/system/signature/
        // {cap_content_hash_hex}` (per V7 §3.5 v7.44 + IDENTITY §6.0e
        // v3.6). v3.5 PI-10's `{cap_path}/signature` sibling-path
        // convention was removed by v3.6; downstream chain validation
        // discovers cap signatures at the invariant pointer path via
        // `find_signature_by_signer` (EXTENSION-ATTESTATION §4.0).
        let sig_path = format!(
            "/{}/system/signature/{}",
            self.local_peer_id,
            entity_attestation::hex_segment(&cap_hash)
        );
        self.location_index.set(&sig_path, sig_hash);
        Ok(cap_hash)
    }
}

// ===========================================================================
// Result + error helpers
// ===========================================================================

pub(crate) fn error(status: u32, code: &str, message: &str) -> HandlerResult {
    HandlerResult::error(status, error_entity(code, message))
}

/// Empty-payload result with the spec-pinned `system/protocol/status` envelope
/// type. Used for ops whose result schema is a bare status (e.g.,
/// `revoke_attestation` per EXTENSION-IDENTITY §6 — `revoke-attestation-result`
/// is defined as an empty payload, so the generic `system/protocol/status`
/// is the right envelope type for it).
pub(crate) fn status_ok() -> HandlerResult {
    let result = Entity::new(entity_types::TYPE_PROTOCOL_STATUS, to_ecf(&Value::Map(vec![])))
        .unwrap();
    HandlerResult {
        status: STATUS_OK,
        result,
        included: HashMap::new(),
    }
}

/// Build a typed result entity carrying a single hash field. R-2
/// (cross-impl spec): result envelopes MUST use the
/// spec-pinned per-op result type per V7 §3.4, NOT the generic
/// `system/protocol/status`.
pub(crate) fn typed_single_hash_result(
    result_type: &str,
    field: &str,
    hash: Hash,
) -> HandlerResult {
    let result = Entity::new(
        result_type,
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

/// `system/identity/create-quorum-result` per V7 §3.4.
pub(crate) fn create_quorum_result(quorum_id: Hash) -> HandlerResult {
    typed_single_hash_result(
        entity_types::TYPE_IDENTITY_CREATE_QUORUM_RESULT,
        "quorum_id",
        quorum_id,
    )
}

/// `system/identity/create-attestation-result` per V7 §3.4. Regular shape:
/// `{attestation_hash, storage_path?}`.
pub(crate) fn create_attestation_result(att_hash: Hash, storage_path: Option<&str>) -> HandlerResult {
    let mut fields: Vec<(Value, Value)> = vec![(
        text("attestation_hash"),
        Value::Bytes(att_hash.to_bytes().to_vec()),
    )];
    if let Some(p) = storage_path {
        fields.push((text("storage_path"), text(p)));
    }
    let result = Entity::new(
        entity_types::TYPE_IDENTITY_CREATE_ATTESTATION_RESULT,
        to_ecf(&Value::Map(fields)),
    )
    .unwrap();
    HandlerResult {
        status: STATUS_OK,
        result,
        included: HashMap::new(),
    }
}

/// R-6 (cross-impl spec): embedded-mode result. Returns the
/// AttestationData inline under `embedded_attestation` so the caller can
/// embed it in a cap envelope or otherwise propagate it without
/// re-encoding. Per Go's reference shape (`IdentityCreateAttestationResultData`
/// with `cbor:"omitempty"` on the hash field): `attestation_hash` is omitted
/// in embedded mode — the hash field's presence is the wire signal for
/// "the handler bound this in the tree." `embedded_data` MUST be the bytes
/// produced by `AttestationData::to_entity().data` so the inline payload's
/// byte shape matches the substrate's canonical encoding.
pub(crate) fn create_attestation_result_embedded(embedded_data: &[u8]) -> HandlerResult {
    // Decode the canonical AttestationData ECF bytes into a CBOR Value so
    // the result envelope's `embedded_attestation` field is a sub-map (not
    // a bytes blob). Decoding is faithful to the original encoding because
    // ECF + ciborium round-trip is value-preserving.
    let inline: ciborium::Value =
        ciborium::from_reader(embedded_data).expect("AttestationData ECF must decode");
    let result = Entity::new(
        entity_types::TYPE_IDENTITY_CREATE_ATTESTATION_RESULT,
        to_ecf(&Value::Map(vec![(text("embedded_attestation"), inline)])),
    )
    .unwrap();
    HandlerResult {
        status: STATUS_OK,
        result,
        included: HashMap::new(),
    }
}

/// `system/identity/supersede-attestation-result` per V7 §3.4. Same payload
/// shape as create-attestation-result; distinct type tag for SDK dispatch.
pub(crate) fn supersede_attestation_result(att_hash: Hash, storage_path: Option<&str>) -> HandlerResult {
    let mut fields: Vec<(Value, Value)> = vec![(
        text("attestation_hash"),
        Value::Bytes(att_hash.to_bytes().to_vec()),
    )];
    if let Some(p) = storage_path {
        fields.push((text("storage_path"), text(p)));
    }
    let result = Entity::new(
        entity_types::TYPE_IDENTITY_SUPERSEDE_ATTESTATION_RESULT,
        to_ecf(&Value::Map(fields)),
    )
    .unwrap();
    HandlerResult {
        status: STATUS_OK,
        result,
        included: HashMap::new(),
    }
}

/// `system/identity/publish-attestation-result` per V7 §3.4.
///
/// R-9 (cross-impl spec): the destination-path field is
/// `new_path` (not `storage_path`). Pre-R-9 Rust emitted `storage_path`,
/// causing Go's `IdentityPublishAttestationResultData.NewPath` to decode
/// to empty. The publish op is the path-move primitive; `new_path` is the
/// post-move canonical destination and is the entire return-value point.
pub(crate) fn publish_attestation_result(att_hash: Hash, new_path: &str) -> HandlerResult {
    let result = Entity::new(
        entity_types::TYPE_IDENTITY_PUBLISH_ATTESTATION_RESULT,
        to_ecf(&Value::Map(vec![
            (
                text("attestation_hash"),
                Value::Bytes(att_hash.to_bytes().to_vec()),
            ),
            (text("new_path"), text(new_path)),
        ])),
    )
    .unwrap();
    HandlerResult {
        status: STATUS_OK,
        result,
        included: HashMap::new(),
    }
}

/// `system/identity/revoke-attestation-result` per V7 §3.4 + Go's
/// `core/types/identity.go::IdentityRevokeAttestationResultData`. Carries
/// `revocation_hash` — the content_hash of the newly-minted revocation
/// attestation entity. R-12' (cross-impl spec, Round 8):
/// pre-R-12' Rust returned an empty map `{}`, which broke Go's test
/// (`revResult.RevocationHash.IsZero()`).
pub(crate) fn revoke_attestation_result(revocation_hash: Hash) -> HandlerResult {
    let result = Entity::new(
        entity_types::TYPE_IDENTITY_REVOKE_ATTESTATION_RESULT,
        to_ecf(&Value::Map(vec![(
            text("revocation_hash"),
            Value::Bytes(revocation_hash.to_bytes().to_vec()),
        )])),
    )
    .unwrap();
    HandlerResult {
        status: STATUS_OK,
        result,
        included: HashMap::new(),
    }
}

pub(crate) fn configure_result(peer_config_path: &str, issued: &[Hash]) -> HandlerResult {
    let result = Entity::new(
        entity_types::TYPE_IDENTITY_CONFIGURE_RESULT,
        to_ecf(&Value::Map(vec![
            (text("local_peer_to_controller_caps"),
             Value::Array(issued.iter().map(|h| Value::Bytes(h.to_bytes().to_vec())).collect())),
            (text("peer_config_path"), text(peer_config_path)),
        ])),
    )
    .unwrap();
    HandlerResult {
        status: STATUS_OK,
        result,
        included: HashMap::new(),
    }
}

pub(crate) fn require_resource(ctx: &HandlerContext, expected: &str) -> Result<(), HandlerResult> {
    let path = ctx
        .resource_target
        .as_ref()
        .and_then(|rt| rt.targets.first().cloned());
    match path {
        Some(p) if p == expected => Ok(()),
        Some(p) => Err(error(
            STATUS_BAD_REQUEST,
            "resource_target_mismatch",
            &format!("expected {}, got {}", expected, p),
        )),
        None => Err(error(
            STATUS_BAD_REQUEST,
            "path_required",
            "resource.targets[0] required",
        )),
    }
}

// Silence unused-warning until process_attestation full convergence in Phase 7.
#[allow(dead_code)]
const _: fn(&AttestationData) -> Option<&str> = lookup_target_cert_kind;
pub(crate) fn lookup_target_cert_kind(att: &AttestationData) -> Option<&str> {
    lookup_target_cert as fn(_, _) -> _;
    att.kind()
}
