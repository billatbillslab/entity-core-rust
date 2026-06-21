//! `system/handler` handler — register and unregister operations.
//!
//! Per V7 §3.12, §6.2, this is the dispatch entrance for installing and
//! removing handlers post-bootstrap. Bootstrap handlers (system/tree,
//! system/handler, system/protocol/connect) are pre-loaded during peer
//! initialization (V7 §6.9) without going through register.
//!
//! `register` atomically writes:
//!   1. `system/handler/{pattern}` — the interface entity (public contract).
//!   2. `system/capability/grants/{pattern}` — the new handler's capability grant.
//!   3. `system/signature/{grant_hash}` — Ed25519 signature over the grant
//!      entity's content hash, signed by the local peer, bound at the §3.5
//!      invariant-pointer path keyed by the grant hash (v7.74 §3.4 CONVERGENT
//!      ruling; V7 §6.2 / §S1: handlers handler MUST sign self-issued grants).
//!   4. `{pattern}` — the handler manifest entity (dispatch target).
//!   5. `system/type/{name}` — any type definitions provided in the request.
//!
//! `unregister` removes 1-3 (interface, grant, signature); type definitions
//! are left in place since they may be shared by other handlers.
//!
//! V7 §6.2: `system/*` patterns are reserved — register/unregister return 403.

use std::sync::Arc;

use async_trait::async_trait;
use ciborium::Value;
use entity_crypto::IdentityKeypair;
use entity_ecf::ValueExt;
use entity_entity::Entity;
use entity_handler::{
    Handler, HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST, STATUS_FORBIDDEN,
    STATUS_NOT_FOUND, STATUS_OK,
};
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};

const STATUS_CONFLICT: u32 = 409;
const STATUS_INTERNAL: u32 = 500;

/// `system/handler` handler implementing register and unregister.
pub struct HandlersHandler {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    local_peer_id: String,
    qualified_pattern: String,
    /// Local peer identity hash — used as granter+grantee for self-grants
    /// derived from peer root (V7 §6.8 attenuation chain).
    identity_hash: Hash,
    /// Local peer keypair — needed to sign self-issued handler grants per
    /// V7 §6.2 / spec-gap §S1. Dispatch (`load_local_handler_grant`)
    /// verifies the signature against the local pubkey, so an unsigned
    /// grant would fail-close at the next dispatch. Polymorphic over
    /// key_type (v7.67 Phase 2) so an Ed448 peer signs its own grants.
    keypair: IdentityKeypair,
}

impl HandlersHandler {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
        identity_hash: Hash,
        keypair: IdentityKeypair,
    ) -> Self {
        let qualified_pattern = format!("/{}/system/handler", local_peer_id);
        Self {
            content_store,
            location_index,
            local_peer_id,
            qualified_pattern,
            identity_hash,
            keypair,
        }
    }

    fn handle_register(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        // Path-as-resource (PROPOSAL-PATH-AS-RESOURCE-HYGIENE §3.4, P-V7-1):
        // resource = `system/handler/{pattern}`. Pattern is derived from the
        // resource path; manifest.pattern (if present) MUST agree.
        let qualified_resource = match ctx.resource_target.as_ref() {
            Some(rt) if rt.targets.len() == 1 && rt.exclude.is_empty() => rt.targets[0].clone(),
            _ => {
                return Ok(HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity(
                        "ambiguous_resource",
                        "register requires resource = system/handler/{pattern}",
                    ),
                ))
            }
        };
        let pattern = match parse_handler_resource_pattern(&qualified_resource) {
            Some(p) => p,
            None => {
                return Ok(HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity(
                        "malformed_resource",
                        "resource must be system/handler/{pattern}",
                    ),
                ))
            }
        };

        let params_data = match decode_data(&ctx.params) {
            Some(d) => d,
            None => {
                return Ok(HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity("invalid_params", "cannot decode register-request data"),
                ))
            }
        };

        let manifest = match params_data.get("manifest") {
            Some(m) => m,
            None => {
                return Ok(HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity("invalid_manifest", "register-request missing 'manifest'"),
                ))
            }
        };

        // manifest.pattern policy (proposal §3.4 P-V7-1, normative):
        //   absent  → derive from resource (already done above)
        //   matches → use (no error)
        //   disagrees → 400 manifest_pattern_mismatch
        if let Some(mp) = data_str(manifest, "pattern") {
            if !mp.is_empty() && mp != pattern {
                return Ok(HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity(
                        "manifest_pattern_mismatch",
                        "manifest.pattern does not match resource-derived pattern",
                    ),
                ));
            }
        }

        // V7 §6.2: user-installed handlers MUST NOT register at system/* paths.
        if is_reserved_system_pattern(&pattern) {
            return Ok(HandlerResult::error(
                STATUS_FORBIDDEN,
                error_entity(
                    "forbidden_pattern",
                    &format!(
                        "V7 §6.2: user-installed handlers MUST NOT register at system/* paths: {}",
                        pattern
                    ),
                ),
            ));
        }

        // Refuse to clobber an existing registration. Caller should unregister first.
        let qualified_pattern = self.qualify(&pattern);
        if let Some(existing) = self.location_index.get(&qualified_pattern) {
            if let Some(ent) = self.content_store.get(&existing) {
                if ent.entity_type == "system/handler" {
                    return Ok(HandlerResult::error(
                        STATUS_CONFLICT,
                        error_entity(
                            "already_registered",
                            &format!("handler already registered at pattern: {}", pattern),
                        ),
                    ));
                }
            }
        }

        // Build the grant scope. Prefer explicit `requested_scope`; fall back to
        // manifest.internal_scope. A handler with no declared scope is a contract
        // error — we do NOT fabricate a default (would silently grant wildcard).
        let grant_scope = match decode_grant_entries(
            params_data
                .get("requested_scope")
                .or_else(|| manifest.get("internal_scope")),
        ) {
            Ok(Some(s)) => s,
            Ok(None) => {
                return Ok(HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity(
                        "missing_scope",
                        "register-request must specify requested_scope or manifest.internal_scope (V7 §3.12)",
                    ),
                ))
            }
            Err(msg) => {
                return Ok(HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity("invalid_scope", &format!("decode grant scope: {}", msg)),
                ))
            }
        };

        // Build entities: interface, grant, manifest.
        let interface_path = format!("system/handler/{}", pattern);

        let interface_data = entity_ecf::cbor_map! {
            "name" => entity_ecf::text(data_str(manifest, "name").unwrap_or_default()),
            "operations" => clone_value(manifest.get("operations").unwrap_or(&Value::Map(vec![]))),
            "pattern" => entity_ecf::text(&pattern)
        };
        let interface_entity =
            match Entity::new("system/handler/interface", entity_ecf::to_ecf(&interface_data)) {
                Ok(e) => e,
                Err(err) => {
                    return Ok(HandlerResult::error(
                        STATUS_INTERNAL,
                        error_entity(
                            "internal",
                            &format!("build interface entity: {}", err),
                        ),
                    ))
                }
            };

        let now_ms = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let grant_token = entity_capability::CapabilityToken {
            grants: grant_scope,
            granter: entity_capability::Granter::Single(self.identity_hash),
            grantee: self.identity_hash,
            // V7 §6.8 attenuation chain: link new grant to the handlers handler's
            // own grant — runtime chain verification (§5.5) walks back to peer root.
            parent: ctx.handler_grant_hash,
            created_at: now_ms,
            expires_at: None,
            not_before: None,
            delegation_caveats: None,
        };
        let grant_entity = match grant_token.to_entity() {
            Ok(e) => e,
            Err(err) => {
                return Ok(HandlerResult::error(
                    STATUS_INTERNAL,
                    error_entity("internal", &format!("build grant entity: {}", err)),
                ))
            }
        };

        let mut handler_fields: Vec<(Value, Value)> = vec![(
            Value::Text("interface".into()),
            entity_ecf::text(&interface_path),
        )];
        if let Some(max_scope) = manifest.get("max_scope") {
            handler_fields.push((Value::Text("max_scope".into()), clone_value(max_scope)));
        }
        if let Some(internal_scope) = manifest.get("internal_scope") {
            handler_fields.push((
                Value::Text("internal_scope".into()),
                clone_value(internal_scope),
            ));
        }
        if let Some(expression_path) = manifest.get("expression_path") {
            handler_fields.push((
                Value::Text("expression_path".into()),
                clone_value(expression_path),
            ));
        }
        // ECF canonical key ordering (length, then byte order).
        handler_fields.sort_by(|(a, _), (b, _)| {
            let ab = entity_ecf::to_ecf(a);
            let bb = entity_ecf::to_ecf(b);
            ab.len().cmp(&bb.len()).then(ab.cmp(&bb))
        });
        let manifest_entity = match Entity::new(
            "system/handler",
            entity_ecf::to_ecf(&Value::Map(handler_fields)),
        ) {
            Ok(e) => e,
            Err(err) => {
                return Ok(HandlerResult::error(
                    STATUS_INTERNAL,
                    error_entity(
                        "internal",
                        &format!("build handler manifest entity: {}", err),
                    ),
                ))
            }
        };

        // V7 §6.2 / spec-gap §S1: the handlers handler MUST sign the self-
        // issued grant. Dispatch verifies signatures at load time
        // (`load_local_handler_grant`) — without one, the grant fails closed
        // at the next dispatch and the just-registered handler is unreachable.
        let sig_bytes = self.keypair.sign(&grant_entity.content_hash.to_bytes());
        let sig_data = entity_types::SignatureData {
            target: grant_entity.content_hash,
            signer: self.identity_hash,
            algorithm: self.keypair.key_type().label().to_string(),
            signature: sig_bytes,
        };
        let sig_entity = match sig_data.to_entity() {
            Ok(e) => e,
            Err(err) => {
                return Ok(HandlerResult::error(
                    STATUS_INTERNAL,
                    error_entity(
                        "internal",
                        &format!("build grant signature entity: {}", err),
                    ),
                ))
            }
        };

        // Atomic install: interface → grant → signature → handler entity.
        // Order matters so downstream lookups (handler.interface, dispatch,
        // capability check, signature verification) resolve in dependency
        // order. Signature must be in place before the manifest is published,
        // otherwise a concurrent dispatch could load the manifest, follow it
        // to the unsigned grant, and fail-close.
        let interface_qualified = self.qualify(&interface_path);
        let grant_qualified = self.qualify(&format!("system/capability/grants/{}", pattern));
        // v7.74 §3.4: grant signature at the §3.5 invariant-pointer path
        // system/signature/{grant_hash}, keyed by the grant's content hash.
        let sig_qualified =
            entity_hash::invariant_signature_path(&self.local_peer_id, &grant_entity.content_hash);

        if let Err(e) = self.put_at(&interface_qualified, interface_entity) {
            return Ok(HandlerResult::error(STATUS_INTERNAL, e));
        }
        if let Err(e) = self.put_at(&grant_qualified, grant_entity.clone()) {
            return Ok(HandlerResult::error(STATUS_INTERNAL, e));
        }
        if let Err(e) = self.put_at(&sig_qualified, sig_entity) {
            return Ok(HandlerResult::error(STATUS_INTERNAL, e));
        }
        if let Err(e) = self.put_at(&qualified_pattern, manifest_entity) {
            return Ok(HandlerResult::error(STATUS_INTERNAL, e));
        }

        // Optional: install type definitions provided in the request.
        if let Some(types_map) = params_data.get("types").and_then(|v| v.as_map()) {
            for (k, v) in types_map {
                let type_name = match k.as_text() {
                    Some(s) => s.to_string(),
                    None => continue,
                };
                let type_path = self.qualify(&format!("system/type/{}", type_name));
                let type_entity = match Entity::new("system/type", entity_ecf::to_ecf(&clone_value(v))) {
                    Ok(e) => e,
                    Err(err) => {
                        return Ok(HandlerResult::error(
                            STATUS_INTERNAL,
                            error_entity(
                                "internal",
                                &format!("build type entity for {}: {}", type_name, err),
                            ),
                        ))
                    }
                };
                if let Err(e) = self.put_at(&type_path, type_entity) {
                    return Ok(HandlerResult::error(STATUS_INTERNAL, e));
                }
            }
        }

        let result_data = entity_ecf::cbor_map! {
            "grant" => clone_grant_for_result(&grant_entity),
            "pattern" => entity_ecf::text(&pattern)
        };
        let result_entity = match Entity::new(
            "system/handler/register-result",
            entity_ecf::to_ecf(&result_data),
        ) {
            Ok(e) => e,
            Err(err) => {
                return Ok(HandlerResult::error(
                    STATUS_INTERNAL,
                    error_entity(
                        "internal",
                        &format!("build register-result entity: {}", err),
                    ),
                ))
            }
        };

        tracing::info!(
            pattern = %pattern,
            "handler registered"
        );

        Ok(HandlerResult::ok(result_entity))
    }

    fn handle_unregister(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        // Path-as-resource (PROPOSAL-PATH-AS-RESOURCE-HYGIENE §3.4, P-V7-2):
        // resource = `system/handler/{pattern}`. The
        // `system/handler/unregister-request` wrapper is eliminated; params
        // is the empty-params shape (`primitive/any` with `a0` data) and is
        // ignored here.
        let qualified_resource = match ctx.resource_target.as_ref() {
            Some(rt) if rt.targets.len() == 1 && rt.exclude.is_empty() => rt.targets[0].clone(),
            _ => {
                return Ok(HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity(
                        "ambiguous_resource",
                        "unregister requires resource = system/handler/{pattern}",
                    ),
                ))
            }
        };
        let pattern = match parse_handler_resource_pattern(&qualified_resource) {
            Some(p) => p,
            None => {
                return Ok(HandlerResult::error(
                    STATUS_BAD_REQUEST,
                    error_entity(
                        "malformed_resource",
                        "resource must be system/handler/{pattern}",
                    ),
                ))
            }
        };

        if is_reserved_system_pattern(&pattern) {
            return Ok(HandlerResult::error(
                STATUS_FORBIDDEN,
                error_entity(
                    "forbidden_pattern",
                    &format!(
                        "V7 §6.2: cannot unregister system/* handlers: {}",
                        pattern
                    ),
                ),
            ));
        }

        let qualified_pattern = self.qualify(&pattern);
        let existing = match self.location_index.get(&qualified_pattern) {
            Some(h) => h,
            None => {
                return Ok(HandlerResult::error(
                    STATUS_NOT_FOUND,
                    error_entity(
                        "not_registered",
                        &format!("no handler registered at pattern: {}", pattern),
                    ),
                ))
            }
        };
        let ent = match self.content_store.get(&existing) {
            Some(e) if e.entity_type == "system/handler" => e,
            _ => {
                return Ok(HandlerResult::error(
                    STATUS_NOT_FOUND,
                    error_entity(
                        "not_registered",
                        &format!("no handler entity at pattern: {}", pattern),
                    ),
                ))
            }
        };
        let _ = ent;

        let interface_qualified = self.qualify(&format!("system/handler/{}", pattern));
        let grant_qualified = self.qualify(&format!("system/capability/grants/{}", pattern));
        // v7.74 §3.4: the grant signature is keyed by the grant's content
        // hash at system/signature/{grant_hash} — read the bound grant hash
        // before unbinding the grant so the signature path is derivable.
        if let Some(grant_hash) = self.location_index.get(&grant_qualified) {
            let sig_qualified =
                entity_hash::invariant_signature_path(&self.local_peer_id, &grant_hash);
            self.location_index.remove(&sig_qualified);
        }

        self.location_index.remove(&qualified_pattern);
        self.location_index.remove(&interface_qualified);
        self.location_index.remove(&grant_qualified);

        tracing::info!(pattern = %pattern, "handler unregistered");

        let status_data = entity_ecf::cbor_map! {
            "status" => entity_ecf::integer(STATUS_OK as i64)
        };
        let status_entity = Entity::new("system/protocol/status", entity_ecf::to_ecf(&status_data))
            .expect("status entity");
        Ok(HandlerResult::ok(status_entity))
    }

    fn qualify(&self, path: &str) -> String {
        if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{}/{}", self.local_peer_id, path)
        }
    }

    fn put_at(&self, qualified_path: &str, entity: Entity) -> Result<(), Entity> {
        let h = self
            .content_store
            .put(entity)
            .map_err(|e| error_entity("internal", &format!("content store put: {}", e)))?;
        self.location_index.set(qualified_path, h);
        Ok(())
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for HandlersHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            "register" => self.handle_register(ctx),
            "unregister" => self.handle_unregister(ctx),
            other => Ok(HandlerResult::error(
                STATUS_BAD_REQUEST,
                error_entity(
                    "unknown_operation",
                    &format!("system/handler does not support operation: {}", other),
                ),
            )),
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "handler"
    }

    fn operations(&self) -> &[&str] {
        &["register", "unregister"]
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn decode_data(entity: &Entity) -> Option<Value> {
    ciborium::from_reader(entity.data.as_slice()).ok()
}

fn data_str(data: &Value, key: &str) -> Option<String> {
    data.get(key).and_then(|v| v.as_text()).map(String::from)
}

fn clone_value(v: &Value) -> Value {
    v.clone()
}

/// Decode an optional grant-entries array. Returns:
///   Ok(None) — the field is absent (no `requested_scope` and no `internal_scope`)
///   Ok(Some(vec![])) — present but empty (§S3: pure-functional handler)
///   Ok(Some(_)) — present and well-formed
///   Err(msg) — present but malformed
///
/// Distinguishes "missing scope" (rejected by caller) from "empty scope"
/// (valid pure-functional handler per spec-gap §S3). An earlier version
/// collapsed the latter into the former.
fn decode_grant_entries(
    value: Option<&Value>,
) -> Result<Option<Vec<entity_capability::GrantEntry>>, String> {
    let arr = match value {
        Some(v) => match v.as_array() {
            Some(a) => a,
            None => return Err("expected array".into()),
        },
        None => return Ok(None),
    };
    let mut out = Vec::with_capacity(arr.len());
    for entry in arr {
        let parsed = entity_capability::decode_grant_entry(entry)
            .map_err(|e| format!("decode grant entry: {}", e))?;
        out.push(parsed);
    }
    Ok(Some(out))
}

/// Inline a grant entity for the register-result. The result type expects a
/// `system/capability/token` value; we pass through the grant entity's data
/// as a CBOR map preserving the wire-canonical bytes.
fn clone_grant_for_result(grant_entity: &Entity) -> Value {
    ciborium::from_reader(grant_entity.data.as_slice()).unwrap_or(Value::Null)
}

fn error_entity(code: &str, message: &str) -> Entity {
    let data = entity_ecf::cbor_map! {
        "code" => entity_ecf::text(code),
        "message" => entity_ecf::text(message)
    };
    Entity::new(entity_types::TYPE_ERROR, entity_ecf::to_ecf(&data)).expect("error entity")
}

fn is_reserved_system_pattern(pattern: &str) -> bool {
    pattern == "system" || pattern.starts_with("system/")
}

/// Strip the peer prefix and `system/handler/` to derive the bare pattern from
/// a peer-qualified resource path (`/{peer_id}/system/handler/{pattern}`).
/// Tolerates a leading slash on inputs that don't match the 46-char Base58
/// peer-id heuristic (so synthetic test peer IDs still work).
fn parse_handler_resource_pattern(qualified_resource: &str) -> Option<String> {
    let bare = entity_entity::EntityUri::strip_peer_prefix(qualified_resource);
    let trimmed = bare.trim_start_matches('/');
    // If strip_peer_prefix didn't recognize the leading segment as a peer id,
    // we may still see "{anything}/system/handler/{pattern}" — try to find
    // the marker anywhere from the start.
    let after = match trimmed.strip_prefix("system/handler/") {
        Some(p) => p,
        None => {
            // Scan for "/system/handler/" inside the path.
            let needle = "/system/handler/";
            trimmed.find(needle).map(|i| &trimmed[i + needle.len()..])?
        }
    };
    if after.is_empty() {
        return None;
    }
    Some(after.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use entity_capability::{GrantEntry, IdScope, PathScope};
    use entity_store::{MemoryContentStore, MemoryLocationIndex};
    use std::collections::HashMap;

    const TEST_PID: &str = "testpeer123456789012345678901234567890123456";

    fn test_handler() -> HandlersHandler {
        HandlersHandler::new(
            Arc::new(MemoryContentStore::new()),
            Arc::new(MemoryLocationIndex::new()),
            TEST_PID.to_string(),
            Hash::compute("test", b"identity"),
            IdentityKeypair::Ed25519(entity_crypto::Keypair::from_seed([7u8; 32])),
        )
    }

    fn build_register_request(pattern: &str, with_scope: bool, expression_path: Option<&str>) -> Entity {
        let mut manifest_fields = vec![
            (Value::Text("name".into()), entity_ecf::text("testhandler")),
            (
                Value::Text("operations".into()),
                Value::Map(vec![(
                    entity_ecf::text("run"),
                    Value::Map(vec![(
                        entity_ecf::text("input_type"),
                        entity_ecf::text("primitive/any"),
                    )]),
                )]),
            ),
            (Value::Text("pattern".into()), entity_ecf::text(pattern)),
        ];
        if with_scope {
            // internal_scope: minimal grant covering the pattern itself
            let scope_entry = Value::Map(vec![
                (
                    entity_ecf::text("handlers"),
                    Value::Map(vec![(
                        entity_ecf::text("include"),
                        Value::Array(vec![entity_ecf::text(pattern)]),
                    )]),
                ),
                (
                    entity_ecf::text("operations"),
                    Value::Map(vec![(
                        entity_ecf::text("include"),
                        Value::Array(vec![entity_ecf::text("run")]),
                    )]),
                ),
                (
                    entity_ecf::text("resources"),
                    Value::Map(vec![(
                        entity_ecf::text("include"),
                        Value::Array(vec![entity_ecf::text(&format!("{}/*", pattern))]),
                    )]),
                ),
            ]);
            manifest_fields.push((
                Value::Text("internal_scope".into()),
                Value::Array(vec![scope_entry]),
            ));
        }
        if let Some(p) = expression_path {
            manifest_fields.push((
                Value::Text("expression_path".into()),
                entity_ecf::text(p),
            ));
        }
        manifest_fields.sort_by(|(a, _), (b, _)| {
            let ab = entity_ecf::to_ecf(a);
            let bb = entity_ecf::to_ecf(b);
            ab.len().cmp(&bb.len()).then(ab.cmp(&bb))
        });

        let req_data = entity_ecf::cbor_map! {
            "manifest" => Value::Map(manifest_fields)
        };
        Entity::new(
            "system/handler/register-request",
            entity_ecf::to_ecf(&req_data),
        )
        .unwrap()
    }

    /// PROPOSAL-PATH-AS-RESOURCE-HYGIENE empty-params shape: a `primitive/any`
    /// entity whose data is the canonical CBOR encoding of an empty map (`a0`).
    fn empty_params() -> Entity {
        Entity::new("primitive/any", vec![0xa0]).unwrap()
    }

    fn ctx_with_params(params: Entity, op: &str, target_pattern: &str) -> HandlerContext {
        // Path-as-resource: resource = system/handler/{pattern}, peer-qualified
        // (mirrors what dispatch does for real EXECUTEs).
        let resource_path = format!("/{}/system/handler/{}", TEST_PID, target_pattern);
        HandlerContext {
            handler_grant: None,
            caller_capability: None,
            execute: Entity::new("system/protocol/execute", entity_ecf::to_ecf(&entity_ecf::cbor_map! {
                "operation" => entity_ecf::text(op),
                "uri" => entity_ecf::text("entity://test/system/handler")
            }))
            .unwrap(),
            params,
            pattern: format!("/{}/system/handler", TEST_PID),
            suffix: String::new(),
            resource_target: Some(entity_capability::ResourceTarget {
                targets: vec![resource_path],
                exclude: vec![],
            }),
            author: Some(Hash::compute("test", b"author")),
            request_id: "test-req".to_string(),
            operation: op.to_string(),
            execute_fn: None,
            included: HashMap::new(),
            matching_grant: None,
            capability_hash: None,
            handler_grant_hash: Some(Hash::compute("test", b"hgrant")),
            bounds: None,
            is_external: false,
            session_peer_id: None,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_register_succeeds_for_app_pattern() {
        let handler = test_handler();
        let pattern = "app/echo";
        let req = build_register_request(pattern, true, Some("app/echo/expr"));
        let ctx = ctx_with_params(req, "register", pattern);

        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, 200);
        assert_eq!(result.result.entity_type, "system/handler/register-result");

        // All three locations populated
        let pid = TEST_PID;
        assert!(
            handler.location_index.get(&format!("/{}/{}", pid, pattern)).is_some(),
            "manifest at pattern path"
        );
        assert!(
            handler
                .location_index
                .get(&format!("/{}/system/handler/{}", pid, pattern))
                .is_some(),
            "interface at /system/handler/{pattern}"
        );
        assert!(
            handler
                .location_index
                .get(&format!("/{}/system/capability/grants/{}", pid, pattern))
                .is_some(),
            "grant at /system/capability/grants/{pattern}"
        );

        // Manifest entity is system/handler with expression_path preserved
        let manifest_h = handler
            .location_index
            .get(&format!("/{}/{}", pid, pattern))
            .unwrap();
        let manifest_ent = handler.content_store.get(&manifest_h).unwrap();
        assert_eq!(manifest_ent.entity_type, "system/handler");
        let manifest_data = decode_data(&manifest_ent).unwrap();
        assert_eq!(
            data_str(&manifest_data, "expression_path"),
            Some("app/echo/expr".to_string())
        );
        assert_eq!(
            data_str(&manifest_data, "interface"),
            Some(format!("system/handler/{}", pattern))
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_register_rejects_system_patterns() {
        let handler = test_handler();
        let req = build_register_request("system/foo", true, None);
        let ctx = ctx_with_params(req, "register", "system/foo");

        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_FORBIDDEN);
        let data = decode_data(&result.result).unwrap();
        assert_eq!(data_str(&data, "code"), Some("forbidden_pattern".into()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_register_rejects_missing_scope() {
        let handler = test_handler();
        let req = build_register_request("app/no-scope", false, None);
        let ctx = ctx_with_params(req, "register", "app/no-scope");

        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_BAD_REQUEST);
        let data = decode_data(&result.result).unwrap();
        assert_eq!(data_str(&data, "code"), Some("missing_scope".into()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_register_409_when_already_registered() {
        let handler = test_handler();
        let pattern = "app/twice";

        let req1 = build_register_request(pattern, true, None);
        let ctx1 = ctx_with_params(req1, "register", pattern);
        let r1 = handler.handle(&ctx1).await.unwrap();
        assert_eq!(r1.status, 200);

        let req2 = build_register_request(pattern, true, None);
        let ctx2 = ctx_with_params(req2, "register", pattern);
        let r2 = handler.handle(&ctx2).await.unwrap();
        assert_eq!(r2.status, STATUS_CONFLICT);
        let data = decode_data(&r2.result).unwrap();
        assert_eq!(data_str(&data, "code"), Some("already_registered".into()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_unregister_round_trip() {
        let handler = test_handler();
        let pattern = "app/round-trip";

        let req = build_register_request(pattern, true, None);
        let ctx = ctx_with_params(req, "register", pattern);
        handler.handle(&ctx).await.unwrap();

        let pid = TEST_PID;
        assert!(handler
            .location_index
            .get(&format!("/{}/{}", pid, pattern))
            .is_some());

        // Empty-params for unregister per PROPOSAL-PATH-AS-RESOURCE-HYGIENE.
        let unreg = empty_params();
        let unreg_ctx = ctx_with_params(unreg, "unregister", pattern);
        let result = handler.handle(&unreg_ctx).await.unwrap();
        assert_eq!(result.status, 200);

        // All three locations gone
        assert!(handler
            .location_index
            .get(&format!("/{}/{}", pid, pattern))
            .is_none());
        assert!(handler
            .location_index
            .get(&format!("/{}/system/handler/{}", pid, pattern))
            .is_none());
        assert!(handler
            .location_index
            .get(&format!("/{}/system/capability/grants/{}", pid, pattern))
            .is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_unregister_404_when_not_registered() {
        let handler = test_handler();
        let unreg = empty_params();
        let ctx = ctx_with_params(unreg, "unregister", "app/missing");
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_NOT_FOUND);
        let data = decode_data(&result.result).unwrap();
        assert_eq!(data_str(&data, "code"), Some("not_registered".into()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_register_grant_chains_to_handlers_handler_grant() {
        // V7 §6.8 attenuation chain: new grant.parent = handlers handler grant hash.
        let handler = test_handler();
        let req = build_register_request("app/chain", true, None);
        let mut ctx = ctx_with_params(req, "register", "app/chain");
        let parent = Hash::compute("test", b"parent-grant");
        ctx.handler_grant_hash = Some(parent);

        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, 200);

        let pid = TEST_PID;
        let grant_h = handler
            .location_index
            .get(&format!("/{}/system/capability/grants/app/chain", pid))
            .unwrap();
        let grant_ent = handler.content_store.get(&grant_h).unwrap();
        let token = entity_capability::CapabilityToken::from_entity(&grant_ent).unwrap();
        assert_eq!(token.parent, Some(parent), "grant chains to handlers handler");
    }

    #[test]
    fn test_is_reserved_system_pattern() {
        assert!(is_reserved_system_pattern("system"));
        assert!(is_reserved_system_pattern("system/anything"));
        assert!(is_reserved_system_pattern("system/handler/foo"));
        assert!(!is_reserved_system_pattern("app/foo"));
        assert!(!is_reserved_system_pattern("local/files"));
        assert!(!is_reserved_system_pattern("systemicon")); // false-prefix safety
    }

    // Suppress unused warnings on test-only imports
    #[allow(dead_code)]
    fn _imports_used() {
        let _: Option<GrantEntry> = None;
        let _: Option<PathScope> = None;
        let _: Option<IdScope> = None;
    }
}
